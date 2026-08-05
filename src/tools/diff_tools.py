"""
Patch-diff tools for two analyzed binaries.

Cache-only MCP tooling that pairs functions across two cached Ghidra
contexts (PDB-name -> hash -> callee-set Jaccard) and ranks the modified
set by a "fix-likelihood" score so a Patch-Tuesday triage can surface
the security-relevant deltas without drowning the analyst in cosmetic
renames or compiler reorderings.

Designed to be the bulk counterpart to ``find_similar_functions``:
where that one returns per-pair similarity, this one returns
ADDED / REMOVED / MODIFIED buckets with deltas attached.

Coverage
--------
A diff run is a machine pass, not a reading, so it records on the
*examination* axis of the coverage ledger rather than the review axis --
see ``docs/coverage.md``. Only the MODIFIED entries are recorded, and
only because those are the ones this tool actually analyses per function:
it scores the bounds-check, stack-cookie, caller-count and size deltas
and extracts the first changed line for each. ADDED, REMOVED and the
unchanged pairs get bucket membership and nothing else, so recording
them would be claiming an analysis that never happened -- and on a
Patch-Tuesday-shaped diff of a large DLL, claiming it several thousand
times over.
"""

from __future__ import annotations

import logging
import math
import re
from pathlib import Path

from src.engines.static.ghidra.coverage_store import EXAMINATION_DIFF, auto_examine
from src.tools.function_hash_tools import (
    FunctionHashCache,
    _compute_function_hash,
    _get_capstone_mode,
)

logger = logging.getLogger(__name__)

# Regex for "auto-generated" Ghidra symbol names; PDB-name detection
# rejects anything matching this pattern.
_AUTO_NAME_RE = re.compile(
    r"^(?:FUN_[0-9a-fA-F]+|sub_[0-9a-fA-F]+|thunk_FUN_[0-9a-fA-F]+|"
    r"unnamed_[A-Za-z0-9_]+|func_\d+)$",
    re.IGNORECASE,
)

# Bounds-check signature: ``if (... < <ident>)`` or ``if (... <= <ident>)``.
# The ident requirement filters out ``if (x < 10)`` sized-literal forms,
# which are usually loop bounds, not new safety checks.
_BOUNDS_CHECK_RE = re.compile(r"\bif\s*\([^)]*<=?\s*[A-Za-z_]\w*[^)]*\)")

# Names of stack-cookie helper calls inserted by /GS hardening.
_COOKIE_NAMES = {"__security_check_cookie", "__security_init_cookie"}

# Jaccard threshold + scoring weights. Tuned for Patch-Tuesday-shaped
# diffs (mostly stable, a handful of fixed funcs); not load-bearing.
_CALLEE_JACCARD_THRESHOLD = 0.85

# Report bounds. An unbounded report on a 14000-function pair is 20000 lines
# and ~240K tokens -- it cannot come back through an MCP client, which is what
# drove diff work out into offline scripts. These defaults land around 250
# lines while keeping every bucket count exact, and the untruncated report is
# written to disk whenever they bite.
DEFAULT_TOP_N = 40
DEFAULT_LIST_LIMIT = 20

_BOUNDS_WEIGHT = 5.0
_COOKIE_WEIGHT = 8.0
_CALLER_WEIGHT = 1.0
_SIZE_WEIGHT = 0.05


def _normalize_addr(raw: str | None) -> str:
    if not raw:
        return ""
    return str(raw).lower().replace("0x", "").lstrip("0") or "0"


def _is_hashable_function(func: dict) -> bool:
    return (
        not func.get("is_thunk") and not func.get("is_external") and bool(func.get("basic_blocks"))
    )


def _is_pdb_named(func: dict) -> bool:
    """A function is PDB-named when its name does NOT match the auto
    pattern AND its name_source is not in the auto/unknown bucket."""
    name = func.get("name") or ""
    if not name or _AUTO_NAME_RE.match(name):
        return False
    source = (func.get("name_source") or "").upper()
    if source in {"DEFAULT", "UNKNOWN", ""}:
        return False
    return True


def _bb_count(func: dict) -> int:
    return len(func.get("basic_blocks") or [])


def _size_addresses(func: dict) -> int:
    return sum((b.get("num_addresses") or 0) for b in func.get("basic_blocks") or [])


def _callee_name_set(func: dict) -> frozenset[str]:
    return frozenset(
        (c.get("name") or "") for c in func.get("called_functions") or [] if c.get("name")
    )


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def _xrefs_index(context: dict) -> dict[str, list]:
    idx = context.get("xrefs_to_function")
    return idx if isinstance(idx, dict) else {}


def _caller_count(context: dict, func: dict) -> int:
    idx = _xrefs_index(context)
    return len(idx.get(_normalize_addr(func.get("address")), []))


def _bounds_check_count(text: str) -> int:
    return len(_BOUNDS_CHECK_RE.findall(text or ""))


def _cookie_calls(func: dict) -> int:
    return sum(1 for n in _callee_name_set(func) if n in _COOKIE_NAMES)


def _first_changed_line(old_text: str, new_text: str) -> tuple[int, str, str] | None:
    """Return (1-based line index, old_line, new_line) of first diff, or None."""
    old_lines = (old_text or "").splitlines()
    new_lines = (new_text or "").splitlines()
    for idx in range(max(len(old_lines), len(new_lines))):
        a = old_lines[idx] if idx < len(old_lines) else ""
        b = new_lines[idx] if idx < len(new_lines) else ""
        if a.strip() != b.strip():
            return idx + 1, a.strip(), b.strip()
    return None


def _module_prefix(name: str) -> str:
    """C++ class prefix: ``A::B::method`` -> ``A::B``; bare names -> ``(global)``."""
    if not name or "::" not in name:
        return "(global)"
    parts = name.rsplit("::", 1)
    return parts[0]


def _pair_by_pdb_name(
    old_funcs: list[dict], new_funcs: list[dict]
) -> tuple[list[tuple[dict, dict, str]], list[dict], list[dict]]:
    """Return (pairs, old_residue, new_residue) where pairs is a list of
    (old_func, new_func, kind) with kind in {"unchanged_pending", "modified_pending"}.

    "_pending" suffix means the kind is provisional - Phase 1 cannot
    distinguish unchanged from modified without a hash, so callers will
    confirm with ``_compute_function_hash``.
    """
    old_named = {f.get("name"): f for f in old_funcs if _is_pdb_named(f)}
    new_named = {f.get("name"): f for f in new_funcs if _is_pdb_named(f)}

    pairs: list[tuple[dict, dict, str]] = []
    paired_old_addrs: set[int] = set()
    paired_new_addrs: set[int] = set()

    for name, of in old_named.items():
        nf = new_named.get(name)
        if nf is None:
            continue
        pairs.append((of, nf, "name_match"))
        paired_old_addrs.add(id(of))
        paired_new_addrs.add(id(nf))

    old_residue = [f for f in old_funcs if id(f) not in paired_old_addrs]
    new_residue = [f for f in new_funcs if id(f) not in paired_new_addrs]
    return pairs, old_residue, new_residue


def _new_capstone(cs_arch, cs_mode):
    """One reusable disassembler for a whole bulk pass, or None.

    ``_compute_function_hash`` builds its own when not given one, which is an
    FFI allocation per function -- 14000 of them for an object that never
    varies, about 9% of the hashing cost.

    Returns None rather than raising when the arch/mode pair is rejected.
    This is purely an optimization, so it must not be the thing that decides
    whether a diff runs: on None the per-function path builds its own handle
    and fails exactly where it always did.
    """
    try:
        import capstone

        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = False
        return md
    except Exception as exc:
        logger.debug("shared capstone handle unavailable (%s, %s): %s", cs_arch, cs_mode, exc)
        return None


def _hash_many(reader, cs_arch, cs_mode, funcs, hash_cache) -> dict[int, dict]:
    """Hash ``funcs`` through one reader, consulting ``hash_cache``.

    Returns ``{id(func): result}``. Functions whose hash cannot be computed
    (no basic_blocks, unsupported arch, read failure) are absent.

    The disassembler is built on the first cache miss, not up front, so a
    fully-cached side never allocates one at all.
    """
    md = None
    out: dict[int, dict] = {}
    for func in funcs:
        result = hash_cache.get(func) if hash_cache is not None else None
        if result is None:
            if md is None:
                md = _new_capstone(cs_arch, cs_mode)
            result = _compute_function_hash(reader, cs_arch, cs_mode, func, md=md)
            if result is None:
                continue
            if hash_cache is not None:
                hash_cache.put(func, result)
        out[id(func)] = result
    return out


def _hash_functions(binary_path: str, funcs: list[dict], hash_cache=None) -> dict[str, list[dict]]:
    """Compute opcode hashes for every hashable function in ``funcs``.

    Returns ``{hash: [func, func, ...]}``. Functions whose hash cannot be
    computed (no basic_blocks, unsupported arch, read failure) are
    omitted.
    """
    hashable = [f for f in funcs if _is_hashable_function(f)]
    if not hashable:
        return {}
    mode = _get_capstone_mode(binary_path)
    if mode is None:
        return {}
    cs_arch, cs_mode = mode

    from src.utils.binary_reader import BinaryReader

    out: dict[str, list[dict]] = {}
    with BinaryReader(binary_path) as reader:
        results = _hash_many(reader, cs_arch, cs_mode, hashable, hash_cache)
    for func in hashable:
        result = results.get(id(func))
        if result is not None:
            out.setdefault(result["hash"], []).append(func)
    return out


def _pair_by_hash(
    old_path: str,
    new_path: str,
    old_residue: list[dict],
    new_residue: list[dict],
    old_hash_cache=None,
    new_hash_cache=None,
) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    """Phase 2: pair residue by exact opcode hash."""
    old_hashes = _hash_functions(old_path, old_residue, old_hash_cache)
    new_hashes = _hash_functions(new_path, new_residue, new_hash_cache)

    pairs: list[tuple[dict, dict]] = []
    paired_old_ids: set[int] = set()
    paired_new_ids: set[int] = set()

    for h, old_list in old_hashes.items():
        new_list = new_hashes.get(h)
        if not new_list:
            continue
        for of, nf in zip(old_list, new_list):  # 1:1 in hash-collision order
            pairs.append((of, nf))
            paired_old_ids.add(id(of))
            paired_new_ids.add(id(nf))

    old_remaining = [f for f in old_residue if id(f) not in paired_old_ids]
    new_remaining = [f for f in new_residue if id(f) not in paired_new_ids]
    return pairs, old_remaining, new_remaining


def _probe_prefix_length(size: int) -> int:
    """How many of a set's elements must be probed to find every match.

    Prefix filter, and it is exact rather than a heuristic. If
    ``J(A, B) >= t`` then ``|A & B| >= t * |A | B| >= t * |A|``, so B can miss
    at most ``|A| - ceil(t * |A|)`` of A's elements. Probing one more element
    than that guarantees any qualifying B is found: it cannot miss them all.

    At ``t = 0.85`` a 5-element set probes 1 element, a 20-element set probes
    4. Combined with rarest-first ordering those are the *short* posting
    lists, which is what keeps a ubiquitous callee like ``memcpy`` from
    dragging its entire bucket into the candidate set.
    """
    if size <= 0:
        return 0
    misses = size - math.ceil(_CALLEE_JACCARD_THRESHOLD * size)
    return max(1, min(size, misses + 1))


def _pair_by_callees(
    old_residue: list[dict], new_residue: list[dict]
) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    """Phase 3: pair residue by callee-set Jaccard with same bb count.

    Output is identical to the all-pairs scan this replaces -- same pairs,
    same tie-breaking -- but it does not compare every old function against
    every same-bb candidate. That scan was 98% of ``diff_binaries``' runtime
    on a tquery-sized residue (~6000 unmatched twins per side): 51 of 53
    seconds, two thirds of it rebuilding the *candidate's* callee set inside
    the inner loop, 6.7 million times. That is what put the tool over a 30s
    client timeout and forced diffs out into offline scripts.

    Two changes, neither of which can alter the result:

    1. Callee sets are computed once per function instead of once per
       comparison.
    2. Candidates come from an inverted index on ``(bb_count, callee_name)``
       rather than the whole bucket. A candidate sharing no callee with the
       old function scores 0.0, and the scan below requires ``score >
       best_score`` starting at 0.0 -- so a zero-overlap candidate could
       never be selected and dropping it changes nothing. The prefix filter
       narrowing that further is exact; see :func:`_probe_prefix_length`.
    """
    # Rarest-first ordering, so the elements we probe are the ones with the
    # shortest posting lists. Ties broken by name to keep the walk
    # deterministic across runs.
    frequency: dict[str, int] = {}
    new_sets: list[frozenset[str]] = []
    for func in new_residue:
        callees = _callee_name_set(func)
        new_sets.append(callees)
        for name in callees:
            frequency[name] = frequency.get(name, 0) + 1

    index: dict[tuple[int, str], list[int]] = {}
    for idx, func in enumerate(new_residue):
        callees = new_sets[idx]
        # Functions with zero callees give no Jaccard signal - pairing them
        # via this phase would silently match every leaf to every leaf with
        # the same bb count. Never indexed, so never a candidate.
        if not callees:
            continue
        bb = _bb_count(func)
        for name in callees:
            index.setdefault((bb, name), []).append(idx)

    pairs: list[tuple[dict, dict]] = []
    paired_old_ids: set[int] = set()
    paired_new_idx: set[int] = set()

    for of in old_residue:
        of_set = _callee_name_set(of)
        if not of_set:
            continue
        bb = _bb_count(of)
        probe = sorted(of_set, key=lambda n: (frequency.get(n, 0), n))
        probe = probe[: _probe_prefix_length(len(of_set))]

        candidates: set[int] = set()
        for name in probe:
            candidates.update(index.get((bb, name), ()))
        if not candidates:
            continue

        best = None
        best_score = 0.0
        # Ascending index is the order the old all-pairs scan walked the
        # bucket in, so an exact tie still goes to the earliest candidate.
        for idx in sorted(candidates):
            if idx in paired_new_idx:
                continue
            nf_set = new_sets[idx]
            intersection = len(of_set & nf_set)
            score = intersection / (len(of_set) + len(nf_set) - intersection)
            if score > best_score:
                best_score = score
                best = idx
        if best is not None and best_score >= _CALLEE_JACCARD_THRESHOLD:
            pairs.append((of, new_residue[best]))
            paired_old_ids.add(id(of))
            paired_new_idx.add(best)

    paired_new_ids = {id(new_residue[i]) for i in paired_new_idx}
    old_remaining = [f for f in old_residue if id(f) not in paired_old_ids]
    new_remaining = [f for f in new_residue if id(f) not in paired_new_ids]
    return pairs, old_remaining, new_remaining


def _score_modified(
    old_func: dict, new_func: dict, old_ctx: dict, new_ctx: dict, mode: str
) -> dict:
    """Compute fix-likelihood score and per-delta components."""
    if mode == "security":
        bounds_delta = _bounds_check_count(new_func.get("pseudocode") or "") - (
            _bounds_check_count(old_func.get("pseudocode") or "")
        )
        cookie_delta = _cookie_calls(new_func) - _cookie_calls(old_func)
        caller_delta = _caller_count(new_ctx, new_func) - _caller_count(old_ctx, old_func)
        size_delta = _size_addresses(new_func) - _size_addresses(old_func)
        score = (
            _BOUNDS_WEIGHT * max(bounds_delta, 0)
            + _COOKIE_WEIGHT * max(cookie_delta, 0)
            + _CALLER_WEIGHT * abs(caller_delta)
            + _SIZE_WEIGHT * abs(size_delta)
        )
    else:
        bounds_delta = cookie_delta = caller_delta = size_delta = 0
        score = 0.0

    return {
        "score": score,
        "bounds_delta": bounds_delta,
        "cookie_delta": cookie_delta,
        "caller_delta": caller_delta,
        "size_delta": size_delta,
    }


def _confirm_phase1_buckets(
    pairs: list[tuple[dict, dict, str]],
    old_path: str,
    new_path: str,
    old_hash_cache=None,
    new_hash_cache=None,
) -> tuple[list[tuple[dict, dict]], list[tuple[dict, dict]]]:
    """
    For each PDB-name match, decide unchanged vs modified.

    We hash the paired pseudocode-bearing functions on both sides through
    a single per-binary BinaryReader so we don't open a second one in
    Phase 2. Returns ``(modified_pairs, unchanged_pairs)``.
    """
    if not pairs:
        return [], []

    # Bucket the pairs by side so we open one reader per binary.
    old_funcs = [of for of, _, _ in pairs if _is_hashable_function(of)]
    new_funcs = [nf for _, nf, _ in pairs if _is_hashable_function(nf)]

    old_mode = _get_capstone_mode(old_path)
    new_mode = _get_capstone_mode(new_path)

    if old_mode is None or new_mode is None:
        # Without hashes we can't confirm; fall back to "modified" for
        # safety so the report at least flags the pair.
        return [(of, nf) for of, nf, _ in pairs], []

    from src.utils.binary_reader import BinaryReader

    old_hashes: dict[int, dict] = {}
    new_hashes: dict[int, dict] = {}

    if old_funcs:
        cs_arch, cs_mode = old_mode
        with BinaryReader(old_path) as reader:
            old_hashes = _hash_many(reader, cs_arch, cs_mode, old_funcs, old_hash_cache)
    if new_funcs:
        cs_arch, cs_mode = new_mode
        with BinaryReader(new_path) as reader:
            new_hashes = _hash_many(reader, cs_arch, cs_mode, new_funcs, new_hash_cache)

    modified: list[tuple[dict, dict]] = []
    unchanged: list[tuple[dict, dict]] = []
    for of, nf, _ in pairs:
        oh = (old_hashes.get(id(of)) or {}).get("hash")
        nh = (new_hashes.get(id(nf)) or {}).get("hash")
        if oh and nh and oh == nh:
            unchanged.append((of, nf))
        else:
            modified.append((of, nf))
    return modified, unchanged


def _elide(count: int, shown: int, what: str) -> str:
    """The line that admits a section was cut.

    Every truncation says so, in place, with the number omitted. A section
    that silently stops reads as a complete answer, and on a Patch-Tuesday
    diff "no more added functions" versus "4000 more added functions" is the
    difference between a finished triage and an abandoned one.
    """
    return f"  ... {count - shown} more {what} not shown"


def _sorted_modified(
    modified: list[tuple[dict, dict, str, dict]], mode: str
) -> list[tuple[dict, dict, str, dict]]:
    if mode == "security":
        return sorted(modified, key=lambda m: -m[3]["score"])
    return list(modified)


def _format_report(
    old_path: str,
    new_path: str,
    old_ctx: dict,
    new_ctx: dict,
    added: list[dict],
    removed: list[dict],
    modified: list[tuple[dict, dict, str, dict]],
    unchanged_count: int,
    mode: str,
    group_by: str,
    unchanged_renamed: list[tuple[dict, dict]] | None = None,
    coverage_line: str | None = None,
    top_n: int = 0,
    list_limit: int = 0,
    min_score: float = 0.0,
    full_report_path: str | None = None,
) -> str:
    """Render the diff report; ``modified`` already carries score dicts.

    ``top_n`` / ``list_limit`` / ``min_score`` bound the output; 0 means no
    bound, which is what the on-disk full report is rendered with.
    """
    unchanged_renamed = unchanged_renamed or []

    modified_sorted = _sorted_modified(modified, mode)
    scored_out = 0
    if min_score > 0.0 and mode == "security":
        kept = [m for m in modified_sorted if m[3]["score"] >= min_score]
        scored_out = len(modified_sorted) - len(kept)
        modified_sorted = kept

    shown_modified = modified_sorted if top_n <= 0 else modified_sorted[:top_n]

    lines = [
        "=" * 60,
        "BINARY DIFF",
        "=" * 60,
        f"Old: {Path(old_path).name}  ({len(old_ctx.get('functions', []))} functions)",
        f"New: {Path(new_path).name}  ({len(new_ctx.get('functions', []))} functions)",
        f"Mode: {mode}    group_by={group_by}",
        "",
        "### SUMMARY",
        f"  ADDED     {len(added)}",
        f"  REMOVED   {len(removed)}",
        f"  RENAMED   {len(unchanged_renamed)}  (identical body, different name)",
        f"  MODIFIED  {len(modified)}",
        f"  UNCHANGED {unchanged_count}",
    ]
    if scored_out:
        lines.append(f"  (min_score={min_score:g} filtered out {scored_out} MODIFIED)")
    if coverage_line:
        # In the header, not a footer: even a bounded report is long enough
        # that a footer gets skimmed past.
        lines.append(f"  {coverage_line}")
    if full_report_path:
        lines.append(f"  Full untruncated report: {full_report_path}")
    lines.append("")

    def _name_section(title: str, entries: list[str], total: int, noun: str) -> None:
        shown = entries if list_limit <= 0 else entries[:list_limit]
        suffix = f", showing {len(shown)}" if len(shown) < total else ""
        lines.append(f"### {title} ({total}{suffix})")
        lines.extend(shown)
        if len(shown) < total:
            lines.append(_elide(total, len(shown), noun))
        lines.append("")

    _name_section(
        "ADDED",
        [f"- {f.get('name')} @ {f.get('address')}" for f in added],
        len(added),
        "added function(s)",
    )
    _name_section(
        "REMOVED",
        [f"- {f.get('name')} @ {f.get('address')}" for f in removed],
        len(removed),
        "removed function(s)",
    )
    # Renamed-but-otherwise-unchanged: hash-identical phase-2 pairs whose
    # names differ. Surfaced separately so they don't pollute the MODIFIED
    # bucket (which is meant for actual body changes / security fixes).
    _name_section(
        "Renamed (unchanged body)",
        [
            f"- {of.get('name')} ({of.get('address')})  ->  "
            f"{nf.get('name')} ({nf.get('address')})  [unchanged_renamed]"
            for of, nf in unchanged_renamed
        ],
        len(unchanged_renamed),
        "rename(s)",
    )

    if len(shown_modified) < len(modified_sorted):
        ordering = "by fix-likelihood score" if mode == "security" else "in source order"
        header = (
            f"### MODIFIED ({len(modified_sorted)}, showing top "
            f"{len(shown_modified)} {ordering})"
        )
    else:
        header = f"### MODIFIED ({len(modified_sorted)})"
    lines.append(header)

    if group_by == "module":
        groups: dict[str, list[tuple[dict, dict, str, dict]]] = {}
        for entry in shown_modified:
            old_func, _, _, _ = entry
            groups.setdefault(_module_prefix(old_func.get("name") or ""), []).append(entry)
        for module, entries in sorted(groups.items()):
            lines.append(f"-- module: {module} ({len(entries)})")
            for entry in entries:
                lines.extend(_format_modified_entry(entry, old_ctx, new_ctx))
            lines.append("")
    else:
        for entry in shown_modified:
            lines.extend(_format_modified_entry(entry, old_ctx, new_ctx))

    if len(shown_modified) < len(modified_sorted):
        lines.append(_elide(len(modified_sorted), len(shown_modified), "modified pair(s)"))
        lines.append(
            "  Raise top_n, or set min_score, to see more"
            + (f" -- or read {full_report_path}" if full_report_path else "")
        )

    return "\n".join(lines)


def _format_modified_entry(
    entry: tuple[dict, dict, str, dict],
    old_ctx: dict,
    new_ctx: dict,
) -> list[str]:
    old_func, new_func, kind, deltas = entry
    out = [
        (
            f"- {old_func.get('name')} ({old_func.get('address')})  "
            f"->  {new_func.get('name')} ({new_func.get('address')})  [{kind}]"
        ),
        (
            f"    score={deltas['score']:.1f}  "
            f"bounds_delta={deltas['bounds_delta']:+d}  "
            f"cookies={deltas['cookie_delta']:+d}  "
            f"callers={deltas['caller_delta']:+d}  "
            f"size={deltas['size_delta']:+d}"
        ),
    ]
    diff = _first_changed_line(old_func.get("pseudocode") or "", new_func.get("pseudocode") or "")
    if diff is not None:
        line_no, a, b = diff
        a_short = a[:80] + ("..." if len(a) > 80 else "")
        b_short = b[:80] + ("..." if len(b) > 80 else "")
        out.append(f"    L{line_no}  -  {a_short}")
        out.append(f"    L{line_no}  +  {b_short}")
    return out


def _write_full_report(cache, old_path: str, new_path: str, render) -> str | None:
    """Write the untruncated report beside the analysis caches.

    Truncation is only acceptable if nothing is lost, so whenever the returned
    report is bounded the complete one goes to disk and the header points at
    it. ``render`` is a callable so the full report -- 1.5 MB and 20000 lines
    on a large pair -- is never built when it is not needed.

    The name is derived from both binaries' content hashes, so re-running the
    same diff overwrites rather than accumulating, and two different pairs
    never collide. Returns the path, or None if it could not be written.

    Writes only into a cache directory that already exists, and never creates
    one. ``ProjectCache.__init__`` makes it, so a missing directory means the
    cache root is not what we think it is -- and creating it anyway turns that
    into a tree of files somewhere nobody asked for. A ``MagicMock`` cache is
    the concrete case: ``__fspath__`` hands back a plausible-looking relative
    path rather than raising, so ``mkdir(parents=True)`` silently built
    ``MagicMock/mock.cache_dir/<id>/`` under the working directory during a
    test run. Degrade to "no full report" instead.
    """
    try:
        cache_dir = Path(cache.cache_dir)
        if not cache_dir.is_dir():
            logger.debug("no full diff report: cache dir %s does not exist", cache_dir)
            return None
        old_id = cache._get_binary_hash(old_path)
        new_id = cache._get_binary_hash(new_path)
        target = cache_dir / f"{old_id[:16]}-{new_id[:16]}.diff.txt"
        target.write_text(render(), encoding="utf-8")
        return str(target)
    except Exception as exc:
        # A report we could not persist must not cost the report we can
        # return; the caller falls back to saying so in the header.
        logger.warning("could not write full diff report: %s", exc)
        return None


def _record_examinations(
    cache,
    old_path: str,
    new_path: str,
    old_ctx: dict,
    new_ctx: dict,
    modified: list[tuple[dict, dict, str, dict]],
    enabled: bool,
) -> str:
    """Record the MODIFIED pairs as ``diff`` examinations on both ledgers.

    Each side goes to its own coverage record: the ledger is keyed by the
    sha256 of the file's bytes, so the old binary's addresses belong to the
    old binary's record and cross-writing them would land phantom addresses
    in a ledger they do not exist in.

    Only the MODIFIED bucket. ADDED and REMOVED are single-sided -- there is
    no pair and no delta, only a bucket -- and the unchanged pairs are the
    ones this tool concluded nothing happened to. Recording either would
    inflate the examination axis with functions nothing analysed, which is
    the same dishonesty as inflating the review axis, just one column over.

    Returns the header line for the report.
    """
    if not enabled:
        return "Coverage: not recorded (record_examination=False)"
    if not modified:
        return "Coverage: 0 diff examinations recorded (no MODIFIED entries)"

    old_name = Path(old_path).name
    new_name = Path(new_path).name

    old_written = auto_examine(
        cache,
        old_path,
        [of.get("address") for of, _, _, _ in modified],
        kind=EXAMINATION_DIFF,
        tool="diff_binaries",
        note=f"MODIFIED in diff_binaries against {new_name}",
        context=old_ctx,
    )
    new_written = auto_examine(
        cache,
        new_path,
        [nf.get("address") for _, nf, _, _ in modified],
        kind=EXAMINATION_DIFF,
        tool="diff_binaries",
        note=f"MODIFIED in diff_binaries against {old_name}",
        context=new_ctx,
    )
    return (
        f"Coverage: recorded {old_written} new diff examination(s) on {old_name}, "
        f"{new_written} on {new_name} "
        f"(of {len(modified)} MODIFIED pair(s); examined is not reviewed)"
    )


def register_diff_tools(app, session_manager, cache, runner):
    """
    Register the cross-binary diff tool with the MCP app.

    Args:
        app: FastMCP application instance.
        session_manager: Session manager (unused today; kept for parity).
        cache: ProjectCache instance.
        runner: GhidraRunner (kept for parity; this tool is strictly
            cache-only and never invokes it).
    """
    from src.utils.security import (
        FileSizeError,
        PathTraversalError,
        safe_error_message,
        sanitize_binary_path,
    )

    @app.tool()
    def diff_binaries(
        old_path: str,
        new_path: str,
        group_by: str = "none",
        mode: str = "security",
        record_examination: bool = True,
        top_n: int = DEFAULT_TOP_N,
        list_limit: int = DEFAULT_LIST_LIMIT,
        min_score: float = 0.0,
    ) -> str:
        """
        Diff two analyzed binaries and rank likely security fixes.

        Pairs functions across two cached Ghidra contexts in three phases
        (PDB-name -> opcode hash -> callee-set Jaccard >= 0.85 with matching
        basic-block count) and emits ADDED / REMOVED / MODIFIED buckets.
        In ``mode="security"`` modified entries are ranked by a heuristic
        fix-likelihood score combining bounds-check delta, stack-cookie
        delta, caller-count delta (from Wave 1A's ``xrefs_to_function``
        index) and size delta. ``mode="none"`` returns modified entries
        in source order with the score suppressed.

        Both binaries must already be analyzed; this tool does not invoke
        Ghidra. ``group_by="module"`` groups MODIFIED entries by C++
        class prefix (``A::B::method`` -> ``A::B``); ``"none"`` emits a
        flat list.

        Opcode hashes are cached to a ``<sha256>.fnhash.json`` side-car per
        binary, so re-running a diff of the same pair skips the dominant cost
        of a cold run. The side-car is keyed on the binary's content hash and
        each entry is guarded by its function's basic-block extents, so a
        re-analysis that redraws them recomputes rather than serving a stale
        hash.

        The report is bounded by default. An unbounded one on a large pair
        runs to 20000 lines and cannot come back through an MCP client at
        all, so the buckets are capped and every cut says how much it
        omitted. Nothing is lost: whenever the returned report is truncated
        the complete one is written next to the analysis caches and the
        header carries its path.

        Args:
            old_path: Path to the OLD analyzed binary.
            new_path: Path to the NEW analyzed binary.
            group_by: ``"none"`` (default) or ``"module"``.
            mode: ``"security"`` (default, ranked by fix-likelihood) or
                ``"none"`` (source-order, no scoring).
            record_examination: Record the MODIFIED entries against both
                binaries' coverage ledgers as machine examinations
                (``kind="diff"``). Default on, and safe on: an examination is
                explicitly **not** a review, so this cannot inflate the review
                counts or shorten the worklist -- it makes the diff's leads
                retrievable afterwards through
                ``get_next_unreviewed(only_examined=True)`` instead of
                vanishing when the report scrolls away. Set false for a dry
                run against a ledger you do not want touched.
            top_n: How many MODIFIED entries to print, highest score first in
                ``mode="security"`` and source order otherwise. ``0`` prints
                every one -- use it when writing to a file, not when the
                result has to cross a client.
            list_limit: How many names to print per ADDED / REMOVED / renamed
                bucket. ``0`` prints every one. The counts are always exact
                regardless; this bounds only the listings.
            min_score: Drop MODIFIED entries scoring below this before
                ``top_n`` applies. ``mode="security"`` only -- there is no
                score to filter on otherwise. Use it to widen coverage of
                what actually matters rather than raising ``top_n`` and
                pulling in cosmetic churn.

        Returns:
            Markdown-style report: a SUMMARY block with exact bucket counts,
            then the bounded listings. The header states how many
            examinations were recorded on each side, and the path to the full
            report when one was written.
        """
        try:
            old_path = str(sanitize_binary_path(old_path))
            new_path = str(sanitize_binary_path(new_path))

            if mode not in ("security", "none"):
                return "Error: mode must be 'security' or 'none'."
            if group_by not in ("none", "module"):
                return "Error: group_by must be 'none' or 'module'."
            if top_n < 0 or list_limit < 0:
                return "Error: top_n and list_limit must be >= 0 (0 means no limit)."
            if min_score < 0:
                return "Error: min_score must be >= 0."

            old_ctx = cache.get_cached(old_path)
            if not old_ctx:
                return (
                    f"Error: Old binary {Path(old_path).name} has not been "
                    f"analyzed yet. Run analyze_binary first."
                )
            new_ctx = cache.get_cached(new_path)
            if not new_ctx:
                return (
                    f"Error: New binary {Path(new_path).name} has not been "
                    f"analyzed yet. Run analyze_binary first."
                )

            old_funcs = list(old_ctx.get("functions", []))
            new_funcs = list(new_ctx.get("functions", []))

            # Hashing both sides is the dominant cost of a cold diff (~6s per
            # side for 14000 functions). It is fully determined by the bytes
            # and the block extents, so it is cached to a side-car and a
            # repeat diff of the same pair -- the normal case when iterating
            # on a patch -- skips it.
            old_hash_cache = FunctionHashCache(cache, old_path)
            new_hash_cache = FunctionHashCache(cache, new_path)

            # Phase 1: PDB-name match.
            phase1_pairs, old_residue, new_residue = _pair_by_pdb_name(old_funcs, new_funcs)
            modified_phase1, unchanged_phase1 = _confirm_phase1_buckets(
                phase1_pairs, old_path, new_path, old_hash_cache, new_hash_cache
            )

            # Phase 2: hash match across the residue.
            phase2_pairs, old_residue, new_residue = _pair_by_hash(
                old_path, new_path, old_residue, new_residue,
                old_hash_cache, new_hash_cache,
            )
            old_hash_cache.save()
            new_hash_cache.save()

            # Phase 3: callee-set Jaccard.
            phase3_pairs, old_residue, new_residue = _pair_by_callees(old_residue, new_residue)

            # Build the modified set with kind labels.
            #
            # Phase-2 pairs match by normalized opcode hash - the function
            # bodies are byte-for-byte equivalent after capstone
            # normalization, so these are functionally unchanged. Same-name
            # phase-2 pairs are pure "unchanged" (just bucket-count them);
            # different-name pairs are "unchanged_renamed" and get their
            # own section so reviewers can see the rename without being
            # told to look for a security fix that isn't there.
            modified: list[tuple[dict, dict, str, dict]] = []
            unchanged_renamed: list[tuple[dict, dict]] = []
            unchanged_count = len(unchanged_phase1)
            for of, nf in modified_phase1:
                deltas = _score_modified(of, nf, old_ctx, new_ctx, mode)
                modified.append((of, nf, "modified", deltas))
            for of, nf in phase2_pairs:
                if of.get("name") != nf.get("name"):
                    unchanged_renamed.append((of, nf))
                else:
                    unchanged_count += 1
            for of, nf in phase3_pairs:
                deltas = _score_modified(of, nf, old_ctx, new_ctx, mode)
                modified.append((of, nf, "modified-renamed", deltas))

            coverage_line = _record_examinations(
                cache,
                old_path,
                new_path,
                old_ctx,
                new_ctx,
                modified,
                enabled=record_examination,
            )

            def _render(bounded: bool, full_path: str | None = None) -> str:
                return _format_report(
                    old_path,
                    new_path,
                    old_ctx,
                    new_ctx,
                    added=new_residue,
                    removed=old_residue,
                    modified=modified,
                    unchanged_count=unchanged_count,
                    unchanged_renamed=unchanged_renamed,
                    mode=mode,
                    group_by=group_by,
                    coverage_line=coverage_line,
                    top_n=top_n if bounded else 0,
                    list_limit=list_limit if bounded else 0,
                    min_score=min_score if bounded else 0.0,
                    full_report_path=full_path,
                )

            truncates = (
                (top_n > 0 and len(modified) > top_n)
                or (min_score > 0 and mode == "security")
                or (
                    list_limit > 0
                    and max(len(new_residue), len(old_residue), len(unchanged_renamed))
                    > list_limit
                )
            )
            # Only when something is actually cut, so an ordinary small diff
            # does not litter the cache with a duplicate of its own output.
            full_path = (
                _write_full_report(cache, old_path, new_path, lambda: _render(bounded=False))
                if truncates
                else None
            )
            return _render(bounded=True, full_path=full_path)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("diff_binaries", e)
        except Exception as e:
            logger.exception("diff_binaries failed")
            return safe_error_message("Failed to diff binaries", e)

    logger.info("Registered 1 diff tool")

    return (diff_binaries,)
