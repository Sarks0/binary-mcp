"""
Patch-diff tools for two analyzed binaries.

Cache-only MCP tooling that pairs functions across two cached Ghidra
contexts (PDB-name → hash → callee-set Jaccard) and ranks the modified
set by a "fix-likelihood" score so a Patch-Tuesday triage can surface
the security-relevant deltas without drowning the analyst in cosmetic
renames or compiler reorderings.

Designed to be the bulk counterpart to ``find_similar_functions``:
where that one returns per-pair similarity, this one returns
ADDED / REMOVED / MODIFIED buckets with deltas attached.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from src.tools.function_hash_tools import _compute_function_hash, _get_capstone_mode

logger = logging.getLogger(__name__)

# Regex for "auto-generated" Ghidra symbol names; PDB-name detection
# rejects anything matching this pattern.
_AUTO_NAME_RE = re.compile(
    r"^(?:FUN_[0-9a-fA-F]+|sub_[0-9a-fA-F]+|thunk_FUN_[0-9a-fA-F]+|"
    r"unnamed_[A-Za-z0-9_]+|func_\d+|FUN_.*)$",
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
    """C++ class prefix: ``A::B::method`` → ``A::B``; bare names → ``(global)``."""
    if not name or "::" not in name:
        return "(global)"
    parts = name.rsplit("::", 1)
    return parts[0]


def _pair_by_pdb_name(
    old_funcs: list[dict], new_funcs: list[dict]
) -> tuple[list[tuple[dict, dict, str]], list[dict], list[dict]]:
    """Return (pairs, old_residue, new_residue) where pairs is a list of
    (old_func, new_func, kind) with kind in {"unchanged_pending", "modified_pending"}.

    "_pending" suffix means the kind is provisional — Phase 1 cannot
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


def _hash_functions(binary_path: str, funcs: list[dict]) -> dict[str, list[dict]]:
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
        for func in hashable:
            result = _compute_function_hash(reader, cs_arch, cs_mode, func)
            if result is None:
                continue
            out.setdefault(result["hash"], []).append(func)
    return out


def _pair_by_hash(
    old_path: str,
    new_path: str,
    old_residue: list[dict],
    new_residue: list[dict],
) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    """Phase 2: pair residue by exact opcode hash."""
    old_hashes = _hash_functions(old_path, old_residue)
    new_hashes = _hash_functions(new_path, new_residue)

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


def _pair_by_callees(
    old_residue: list[dict], new_residue: list[dict]
) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    """Phase 3: pair residue by callee-set Jaccard with same bb count."""
    by_bb: dict[int, list[dict]] = {}
    for f in new_residue:
        by_bb.setdefault(_bb_count(f), []).append(f)

    pairs: list[tuple[dict, dict]] = []
    paired_old_ids: set[int] = set()
    paired_new_ids: set[int] = set()

    for of in old_residue:
        candidates = by_bb.get(_bb_count(of), [])
        if not candidates:
            continue
        of_set = _callee_name_set(of)
        # Functions with zero callees give no Jaccard signal — pairing
        # them via this phase would silently match every leaf to every
        # leaf with the same bb count. Skip outright.
        if not of_set:
            continue
        best = None
        best_score = 0.0
        for nf in candidates:
            if id(nf) in paired_new_ids:
                continue
            nf_set = _callee_name_set(nf)
            if not nf_set:
                continue
            score = _jaccard(of_set, nf_set)
            if score > best_score:
                best_score = score
                best = nf
        if best is not None and best_score >= _CALLEE_JACCARD_THRESHOLD:
            pairs.append((of, best))
            paired_old_ids.add(id(of))
            paired_new_ids.add(id(best))

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

    old_hashes: dict[int, str] = {}
    new_hashes: dict[int, str] = {}

    if old_funcs:
        cs_arch, cs_mode = old_mode
        with BinaryReader(old_path) as reader:
            for of in old_funcs:
                result = _compute_function_hash(reader, cs_arch, cs_mode, of)
                if result:
                    old_hashes[id(of)] = result["hash"]
    if new_funcs:
        cs_arch, cs_mode = new_mode
        with BinaryReader(new_path) as reader:
            for nf in new_funcs:
                result = _compute_function_hash(reader, cs_arch, cs_mode, nf)
                if result:
                    new_hashes[id(nf)] = result["hash"]

    modified: list[tuple[dict, dict]] = []
    unchanged: list[tuple[dict, dict]] = []
    for of, nf, _ in pairs:
        oh = old_hashes.get(id(of))
        nh = new_hashes.get(id(nf))
        if oh and nh and oh == nh:
            unchanged.append((of, nf))
        else:
            modified.append((of, nf))
    return modified, unchanged


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
) -> str:
    """Render the diff report; ``modified`` already carries score dicts."""
    lines = [
        "=" * 60,
        "BINARY DIFF",
        "=" * 60,
        f"Old: {Path(old_path).name}  ({len(old_ctx.get('functions', []))} functions)",
        f"New: {Path(new_path).name}  ({len(new_ctx.get('functions', []))} functions)",
        f"Mode: {mode}    group_by={group_by}",
        f"Unchanged pairs: {unchanged_count}",
        "",
    ]

    lines.append(f"### ADDED ({len(added)})")
    for f in added:
        lines.append(f"- {f.get('name')} @ {f.get('address')}")
    lines.append("")

    lines.append(f"### REMOVED ({len(removed)})")
    for f in removed:
        lines.append(f"- {f.get('name')} @ {f.get('address')}")
    lines.append("")

    lines.append(f"### MODIFIED ({len(modified)})")

    if mode == "security":
        modified_sorted = sorted(modified, key=lambda m: -m[3]["score"])
    else:
        modified_sorted = list(modified)

    if group_by == "module":
        groups: dict[str, list[tuple[dict, dict, str, dict]]] = {}
        for entry in modified_sorted:
            old_func, _, _, _ = entry
            groups.setdefault(_module_prefix(old_func.get("name") or ""), []).append(entry)
        for module, entries in sorted(groups.items()):
            lines.append(f"-- module: {module} ({len(entries)})")
            for entry in entries:
                lines.extend(_format_modified_entry(entry, old_ctx, new_ctx))
            lines.append("")
    else:
        for entry in modified_sorted:
            lines.extend(_format_modified_entry(entry, old_ctx, new_ctx))

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
            f"→  {new_func.get('name')} ({new_func.get('address')})  [{kind}]"
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
        a_short = a[:80] + ("…" if len(a) > 80 else "")
        b_short = b[:80] + ("…" if len(b) > 80 else "")
        out.append(f"    L{line_no}  -  {a_short}")
        out.append(f"    L{line_no}  +  {b_short}")
    return out


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
    ) -> str:
        """
        Diff two analyzed binaries and rank likely security fixes.

        Pairs functions across two cached Ghidra contexts in three phases
        (PDB-name → opcode hash → callee-set Jaccard ≥ 0.85 with matching
        basic-block count) and emits ADDED / REMOVED / MODIFIED buckets.
        In ``mode="security"`` modified entries are ranked by a heuristic
        fix-likelihood score combining bounds-check delta, stack-cookie
        delta, caller-count delta (from Wave 1A's ``xrefs_to_function``
        index) and size delta. ``mode="none"`` returns modified entries
        in source order with the score suppressed.

        Both binaries must already be analyzed; this tool does not invoke
        Ghidra. ``group_by="module"`` groups MODIFIED entries by C++
        class prefix (``A::B::method`` → ``A::B``); ``"none"`` emits a
        flat list.

        Args:
            old_path: Path to the OLD analyzed binary.
            new_path: Path to the NEW analyzed binary.
            group_by: ``"none"`` (default) or ``"module"``.
            mode: ``"security"`` (default, ranked by fix-likelihood) or
                ``"none"`` (source-order, no scoring).

        Returns:
            Markdown-style report of ADDED / REMOVED / MODIFIED buckets.
        """
        try:
            old_path = str(sanitize_binary_path(old_path))
            new_path = str(sanitize_binary_path(new_path))

            if mode not in ("security", "none"):
                return "Error: mode must be 'security' or 'none'."
            if group_by not in ("none", "module"):
                return "Error: group_by must be 'none' or 'module'."

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

            # Phase 1: PDB-name match.
            phase1_pairs, old_residue, new_residue = _pair_by_pdb_name(old_funcs, new_funcs)
            modified_phase1, unchanged_phase1 = _confirm_phase1_buckets(
                phase1_pairs, old_path, new_path
            )

            # Phase 2: hash match across the residue.
            phase2_pairs, old_residue, new_residue = _pair_by_hash(
                old_path, new_path, old_residue, new_residue
            )

            # Phase 3: callee-set Jaccard.
            phase3_pairs, old_residue, new_residue = _pair_by_callees(old_residue, new_residue)

            # Build the modified set with kind labels.
            modified: list[tuple[dict, dict, str, dict]] = []
            for of, nf in modified_phase1:
                deltas = _score_modified(of, nf, old_ctx, new_ctx, mode)
                modified.append((of, nf, "modified", deltas))
            for of, nf in phase2_pairs:
                kind = "renamed" if of.get("name") != nf.get("name") else "modified"
                deltas = _score_modified(of, nf, old_ctx, new_ctx, mode)
                modified.append((of, nf, kind, deltas))
            for of, nf in phase3_pairs:
                deltas = _score_modified(of, nf, old_ctx, new_ctx, mode)
                modified.append((of, nf, "modified-renamed", deltas))

            return _format_report(
                old_path,
                new_path,
                old_ctx,
                new_ctx,
                added=new_residue,
                removed=old_residue,
                modified=modified,
                unchanged_count=len(unchanged_phase1),
                mode=mode,
                group_by=group_by,
            )

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("diff_binaries", e)
        except Exception as e:
            logger.error(f"diff_binaries failed: {e}")
            return safe_error_message("Failed to diff binaries", e)

    logger.info("Registered 1 diff tool")

    return (diff_binaries,)
