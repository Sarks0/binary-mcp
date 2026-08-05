"""
Per-binary review-coverage store.

binary-mcp is the single source of truth for the coverage *denominator*: how
many functions a binary has, how many of those are in scope, and how many have
actually been reviewed. Consumers (vr-lab's notes-mcp ledger) mirror the counts
and keep their own campaign semantics (stratum, verdict, finding linkage) on
top; they never recompute a total from their own mark count.

Storage
-------
A ``<sha256>.coverage.json`` side-car beside the existing Ghidra cache, sharing
the same root (``$BINARY_CACHE_DIR`` / ``~/ghidra_mcp_cache``) and the same sha
stem as ``<sha>.json.gz`` / ``<sha>.funcidx.json`` / ``<sha>.notes.json``. This
inherits the cache's eviction and ``clean_cache`` story for free, and needs no
new dependency. Writes are whole-file and atomic (``os.replace``).

Like the notes side-car, coverage survives :meth:`ProjectCache.invalidate` --
re-running Ghidra on the *same bytes* must not destroy a review history, and
because the key is a content hash the addresses cannot shift underneath it.
``clear_all`` still wipes it.

Identity
--------
- binary: lowercase sha256 hexdigest of the file bytes, 64 chars, no prefix --
  exactly what ``ProjectCache._get_binary_hash`` already computes.
- function: canonical lowercase hex with a ``0x`` prefix and no zero padding
  (``0x140006d8c``). The Ghidra cache stores bare, unprefixed hex
  (``140006d8c``); every address crossing this module's boundary is normalized
  through :func:`canon_addr`.

Addresses are Ghidra/loader virtual addresses at the image base as loaded --
not file offsets, not RVAs, not runtime-rebased debugger addresses. The image
base is reported in the status payload so a mismatch is detectable rather than
silent.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# Bump when the on-disk layout changes in a way older readers can't handle.
#
# v2: records carry `dropped_address_count`. A v1 record cannot distinguish
# "no address failed to parse" from "nobody counted", and that difference is
# the whole point of the field, so v1 records are rebuilt rather than trusted.
SCHEMA_VERSION = 2

# Oldest layout this reader can still parse well enough to salvage review marks
# from. Anything in [MIN..SCHEMA_VERSION) is readable but stale -- rebuilt on
# the next status query, marks preserved. Anything outside is refused: a record
# we cannot interpret must report `not_indexed` with null counts, because
# serving it as `ready` would put numbers of unknown provenance in front of a
# closure decision.
MIN_READABLE_SCHEMA_VERSION = 1

# Machine-readable identifier for the reachability method behind `in_scope`.
# Bump on ANY change to how scope is computed -- consumers invalidate their
# mirror when this string changes, and `_ensure_current` rebuilds any record
# still carrying an older one.
#
# v2: cycle members are promoted to roots to a fixpoint. v1 treated "no direct
# caller anywhere" as the only indirect-root signal, so a call cycle reached
# only indirectly was never entered and its entire subtree fell out as
# `excluded:unreachable` -- a shrunken denominator. Leaving the string at v1
# would strand every record built before the fix, because this string IS the
# rebuild trigger.
SCOPE_VERSION = "fwd-bfs-v2"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Cached `decompile_status` value meaning Ghidra deliberately did not
# decompile: a thunk or an external stub. notes-mcp already treats this as a
# skip signal, so scope must agree with it.
_SKIPPED_STATUS = "skipped_thunk_or_external"

STATUS_READY = "ready"
STATUS_NOT_INDEXED = "not_indexed"
STATUS_INDEXING = "indexing"  # reserved: indexing is synchronous today
STATUS_STALE = "stale"


class CoverageError(RuntimeError):
    """Raised when a coverage invariant is violated -- never swallow this."""


# Address normalization


def canon_addr(raw: object) -> str:
    """Return the canonical ``0x`` + lowercase-hex form, or ``""``.

    Accepts an int, a bare hex string (``"140006d8c"``), or a prefixed one
    (``"0x140006D8C"``). Ghidra's ``EXTERNAL:0000005b`` pseudo-addresses and
    anything unparseable return ``""`` so callers can drop them.

    The output survives notes-mcp's ``_normalize_addr`` unchanged, so a naive
    string compare matches on either side of the boundary.
    """
    if raw is None:
        return ""
    if isinstance(raw, int):
        return f"0x{raw:x}"
    text = str(raw).strip().lower()
    if not text or ":" in text:
        return ""
    if text.startswith("0x"):
        text = text[2:]
    try:
        return f"0x{int(text, 16):x}"
    except ValueError:
        return ""


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# Scope computation


def _collect_entry_points(context: dict, by_addr: dict[str, dict]) -> dict[str, str]:
    """Return ``{canonical_address: scope_reason}`` for evidenced entry points.

    Three sources, in priority order (an address keeps the first reason that
    claims it):

    1. ``reachable:export`` -- PE/ELF export table entries, including the
       driver ``entry`` stub and TLS callbacks.
    2. ``reachable:ioctl_dispatch`` -- IOCTL / opcode dispatcher candidates,
       detected with the same predicate ``find_ioctl_handlers`` uses, plus the
       switch-table targets those dispatchers route to.
    3. ``reachable:indirect_root`` -- every function with no direct caller
       anywhere in the binary. These are the registered callbacks, vtable
       members and dispatch-table slots that a forward call-graph walk cannot
       see. Treating them as roots OVER-approximates reachability, which is
       the safe direction: under-counting scope shrinks the denominator and
       manufactures false completion.
    """
    entries: dict[str, str] = {}

    for export in context.get("exports") or []:
        addr = canon_addr(export.get("address"))
        if addr and addr in by_addr:
            entries.setdefault(addr, "reachable:export")

    try:
        from src.tools.dispatch_tools import _is_dispatcher_candidate
    except ImportError:  # pragma: no cover - defensive
        _is_dispatcher_candidate = None

    if _is_dispatcher_candidate is not None:
        # Switch-table targets are keyed by the jump-table source address; a
        # dispatcher's own jump_tables entry carries the target list directly.
        for func in context.get("functions") or []:
            try:
                is_candidate, _hint = _is_dispatcher_candidate(func)
            except Exception:  # pragma: no cover - never let scope break on this
                continue
            if not is_candidate:
                continue
            addr = canon_addr(func.get("address"))
            if addr and addr in by_addr:
                entries.setdefault(addr, "reachable:ioctl_dispatch")
            for table in func.get("jump_tables") or []:
                for target in table.get("targets") or []:
                    t_addr = canon_addr(target)
                    if t_addr and t_addr in by_addr:
                        entries.setdefault(t_addr, "reachable:ioctl_dispatch")

    called: set[str] = set()
    for func in context.get("functions") or []:
        for callee in func.get("called_functions") or []:
            addr = canon_addr(callee.get("address"))
            if addr:
                called.add(addr)

    for addr in by_addr:
        if addr not in called:
            entries.setdefault(addr, "reachable:indirect_root")

    return entries


def _excluded_reason(func: dict) -> str | None:
    """Return a scope-exclusion reason, or None when the function is in scope.

    Only mechanical signals -- nothing name-based. A heuristic that guesses
    "this looks like CRT" would shrink the denominator on a guess, and a
    denominator that shrinks on a guess is how a half-read binary gets called
    hardened.
    """
    if func.get("fid_match"):
        return "excluded:fid_library"
    if func.get("is_external"):
        return "excluded:external"
    if func.get("is_thunk"):
        return "excluded:thunk"
    if func.get("decompile_status") == _SKIPPED_STATUS:
        return "excluded:thunk_or_external"
    return None


def compute_scope(context: dict) -> tuple[dict[str, dict], str]:
    """Forward-BFS reachability over the cached call graph.

    Returns ``({canonical_address: {...}}, scope_description)``. Each record
    carries ``name``, ``size``, ``in_scope`` and ``scope_reason``. Functions
    excluded from scope stay in the map -- they remain retrievable through
    ``scope="all"`` -- with an ``excluded:*`` reason.

    The walk is a pure cache read: ``called_functions`` is already materialized
    per function, so no Ghidra run is involved.
    """
    functions = context.get("functions") or []
    by_addr: dict[str, dict] = {}
    for func in functions:
        addr = canon_addr(func.get("address"))
        if addr:
            by_addr[addr] = func

    entries = _collect_entry_points(context, by_addr)

    # Every evidenced entry point claims its own reason BEFORE any walking, so
    # a dispatcher that also happens to be called from `entry` is still
    # labelled a dispatcher rather than being swallowed as a plain callee.
    # Membership is unaffected either way -- this is provenance only.
    reasons: dict[str, str] = dict(entries)
    for layer in ("reachable:export", "reachable:ioctl_dispatch", "reachable:indirect_root"):
        frontier = [a for a, r in entries.items() if r == layer]
        while frontier:
            addr = frontier.pop()
            func = by_addr.get(addr)
            if func is None:
                continue
            for callee in func.get("called_functions") or []:
                c_addr = canon_addr(callee.get("address"))
                if c_addr and c_addr in by_addr and c_addr not in reasons:
                    reasons[c_addr] = "reachable:callee"
                    frontier.append(c_addr)

    # The layered walk above cannot enter a call cycle that is only reachable
    # indirectly. `reachable:indirect_root` means "no direct caller anywhere",
    # and every member of a cycle has one -- itself, or its partner -- so no
    # cycle member is ever promoted, the walk never enters, and the entire
    # subtree below it drops out as `excluded:unreachable`. That SHRINKS the
    # denominator, the one direction this scope must never move: on the cached
    # corpus it was silently dropping http.sys parsers and the chakra GC.
    #
    # Promote the residual to roots until a fixpoint. Prefer genuine sources --
    # residual functions with no caller inside the residual -- so provenance
    # stays meaningful; a pure cycle with no source is broken at its lowest
    # address, which keeps the result deterministic for a resuming client.
    #
    # When no source exists, promote the WHOLE residual in ascending address
    # order rather than one function per pass. Skipping any address the running
    # BFS already reached makes that sequence identical to repeatedly taking
    # min(residual) -- the same roots, the same `scope_reason` on every
    # function -- because once a pass has no source, no later pass has one
    # either: if x survives a pass it was called by some y in the old residual,
    # and y cannot have been reached (the BFS follows every callee, so it would
    # have taken x with it), so y survives too and still calls x. The loop
    # therefore runs at most twice -- one source pass, one cycle pass -- rather
    # than once per independent cycle, and each pass is linear in the graph.
    #
    # Not a micro-optimization: every fixpoint pass on the 29-binary cached
    # corpus is a no-source pass, so the old code recomputed `residual` and
    # `called_within` over the entire graph once per cycle (chakra: 16 passes
    # over 25026 functions). This sits on `get_analysis_context`'s hot path.
    while True:
        residual = {
            a for a in by_addr
            if a not in reasons and _excluded_reason(by_addr[a]) is None
        }
        if not residual:
            break
        called_within = set()
        for a in residual:
            for callee in by_addr[a].get("called_functions") or []:
                c_addr = canon_addr(callee.get("address"))
                if c_addr and c_addr in residual:
                    called_within.add(c_addr)
        sources = sorted(residual - called_within, key=lambda x: int(x, 16))
        if not sources:
            sources = sorted(residual, key=lambda x: int(x, 16))
        # Termination: `sources` is drawn from `residual`, which is disjoint
        # from `reasons`, so its first element is always promoted and every
        # pass shrinks the residual by at least one.
        for root in sources:
            if root in reasons:
                continue
            reasons[root] = "reachable:cycle_root"
            frontier = [root]
            while frontier:
                addr = frontier.pop()
                func = by_addr.get(addr)
                if func is None:
                    continue
                for callee in func.get("called_functions") or []:
                    c_addr = canon_addr(callee.get("address"))
                    if c_addr and c_addr in by_addr and c_addr not in reasons:
                        reasons[c_addr] = "reachable:callee"
                        frontier.append(c_addr)

    records: dict[str, dict] = {}
    excluded_count = 0
    unreached_count = 0
    entry_counts: dict[str, int] = {}
    for addr, func in by_addr.items():
        excluded = _excluded_reason(func)
        reason = reasons.get(addr)
        if excluded is not None:
            in_scope = False
            scope_reason = excluded
            excluded_count += 1
        elif reason is None:
            # Structurally unreachable, and deliberately kept. The fixpoint
            # above only exits once every non-excluded address has a reason, so
            # nothing can land here -- `in_scope` is now exactly "not
            # mechanically excluded", and the call graph supplies provenance
            # rather than membership. This branch is the tripwire that catches
            # a future change breaking that: it fails toward a smaller
            # denominator, so it must stay visible in the counts and in
            # `scope_description` rather than being silently folded in.
            in_scope = False
            scope_reason = "excluded:unreachable"
            unreached_count += 1
        else:
            in_scope = True
            scope_reason = reason
            if reason != "reachable:callee":
                entry_counts[reason] = entry_counts.get(reason, 0) + 1
        records[addr] = {
            "name": func.get("name") or "",
            "size": int(func.get("size") or 0),
            "in_scope": in_scope,
            "scope_reason": scope_reason,
        }

    description = (
        f"forward BFS over cached called_functions from "
        f"{entry_counts.get('reachable:export', 0)} export(s), "
        f"{entry_counts.get('reachable:ioctl_dispatch', 0)} dispatch entr(ies) and "
        f"{entry_counts.get('reachable:indirect_root', 0)} address-taken root(s) "
        f"with no direct caller"
    )
    if entry_counts.get("reachable:cycle_root"):
        description += (
            f" and {entry_counts['reachable:cycle_root']} cycle root(s) promoted "
            f"after the walk settled"
        )
    description += f"; minus {excluded_count} thunk/external/library function(s)"
    # Only reachable if the fixpoint above stops draining the residual -- see
    # the tripwire comment below. Zero on all 29 cached binaries.
    if unreached_count:
        description += (
            f"; {unreached_count} function(s) still unreachable from any root "
            f"(expected 0 -- a non-zero count here means the fixpoint failed to "
            f"converge and the denominator is under-counted)"
        )
    description += ". Indirect calls are invisible to a forward walk, so scope is "
    description += (
        "over-approximated on purpose: unreached functions are promoted to roots "
        "until nothing is left, and the denominator never shrinks on a guess. "
        "Because that drains the residual entirely, in_scope_total is exactly "
        "total minus the mechanically excluded set -- the walk supplies "
        "scope_reason, not membership."
    )

    return records, description


# Store


class CoverageStore:
    """Reads and writes ``<sha>.coverage.json`` beside the Ghidra cache."""

    def __init__(self, cache):
        """
        Args:
            cache: the shared :class:`ProjectCache`; supplies the cache root,
                the sha256 identity and the analysis context.
        """
        self.cache = cache

    # paths / identity

    @property
    def cache_dir(self) -> Path:
        return self.cache.cache_dir

    def _coverage_path(self, binary_id: str) -> Path:
        return self.cache_dir / f"{binary_id}.coverage.json"

    def binary_id_for_path(self, binary_path: str) -> str:
        return self.cache._get_binary_hash(binary_path)

    def path_for_binary_id(self, binary_id: str) -> str | None:
        """Recover the descriptive binary path from the cache metadata side-car.

        Lets a client that only has the sha256 (vr-lab's ledger key) reach the
        analysis context without knowing where the file lived -- and keeps
        working after the staging directory is cleaned up.
        """
        meta_path = self.cache_dir / f"{binary_id}.meta.json"
        if meta_path.exists():
            try:
                with open(meta_path, encoding="utf-8") as handle:
                    return json.load(handle).get("binary_path")
            except (OSError, ValueError) as exc:
                logger.warning("Unreadable cache metadata for %s: %s", binary_id[:12], exc)
        stored = self.read(binary_id)
        if stored:
            return stored.get("binary_path")
        return None

    def resolve(
        self,
        binary_id: str | None = None,
        binary_path: str | None = None,
        fallback_path: str | None = None,
    ) -> tuple[str | None, str | None]:
        """Resolve ``(binary_id, binary_path)`` from whatever the caller supplied.

        ``fallback_path`` is the active analysis session's binary, used when the
        caller passed neither -- the ``binary_id=None`` case in the contract.
        Returns ``(None, None)`` when nothing resolves.
        """
        if binary_id:
            binary_id = binary_id.strip().lower()
            if not _SHA256_RE.match(binary_id):
                raise ValueError(
                    f"binary_id must be a 64-char lowercase sha256 hexdigest, got {binary_id!r}"
                )
            return binary_id, self.path_for_binary_id(binary_id)

        path = binary_path or fallback_path
        if not path:
            return None, None
        try:
            return self.binary_id_for_path(path), str(path)
        except OSError as exc:
            logger.warning("Could not hash %s: %s", path, exc)
            return None, str(path)

    # persistence

    def read(self, binary_id: str) -> dict | None:
        path = self._coverage_path(binary_id)
        if not path.exists():
            return None
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as exc:
            logger.error("Unreadable coverage side-car %s: %s", path, exc)
            return None
        if not isinstance(data, dict) or "functions" not in data:
            logger.error("Malformed coverage side-car %s: no functions map", path)
            return None
        version = data.get("schema_version")
        if not isinstance(version, int) or isinstance(version, bool):
            logger.error(
                "Coverage side-car %s has no usable schema_version (%r); refusing "
                "to serve counts from a record of unknown provenance",
                path,
                version,
            )
            return None
        if not MIN_READABLE_SCHEMA_VERSION <= version <= SCHEMA_VERSION:
            # A future layout is the dangerous one: fields this reader does not
            # know about may be what make the counts mean what they say, and
            # `bool()`-coercing the entries it does recognize would turn an
            # unread binary into a confidently-reported one. Refuse instead --
            # the caller sees `not_indexed` with null counts, and rebuilds from
            # the analysis cache with everything unreviewed. That loses marks,
            # which is the safe direction: it asks for work to be redone rather
            # than claiming work that was never done.
            logger.error(
                "Coverage side-car %s carries schema_version %d, outside the "
                "readable range %d..%d; treating the binary as not indexed",
                path,
                version,
                MIN_READABLE_SCHEMA_VERSION,
                SCHEMA_VERSION,
            )
            return None
        return data

    def write(self, data: dict) -> bool:
        """Atomically persist a coverage record.

        Whole-file replace via ``os.replace`` so a reader never observes a
        half-written ledger. There is no lock: two MCP clients marking the same
        binary concurrently race read-modify-write in the classic way (later
        write wins). That matches the surrounding cache's contract and vr-lab's
        one-session-per-campaign rule; a lock is the fix if that ever changes.
        """
        binary_id = data.get("binary_id")
        if not binary_id:
            raise CoverageError("cannot write a coverage record without binary_id")
        target = self._coverage_path(binary_id)
        try:
            handle = tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(self.cache_dir),
                prefix=f".{binary_id}.coverage.",
                suffix=".tmp",
                delete=False,
            )
            try:
                with handle:
                    json.dump(data, handle)
                os.replace(handle.name, target)
            except BaseException:
                Path(handle.name).unlink(missing_ok=True)
                raise
            return True
        except OSError as exc:
            logger.error("Failed to write coverage side-car %s: %s", target, exc)
            return False

    # indexing

    def _load_context_by_id(self, binary_id: str) -> dict | None:
        """Read the analysis cache straight off the sha, no file needed.

        ``ProjectCache.get_cached`` re-hashes the binary to find its cache, so
        it fails once the staged file is gone. The ledger key outlives the
        staging tree -- a consumer holding only a sha must still be able to
        index and query -- so resolve ``<sha>.json.gz`` directly instead.
        """
        import gzip

        for path in (
            self.cache_dir / f"{binary_id}.json.gz",
            self.cache_dir / f"{binary_id}.json",
        ):
            if not path.exists():
                continue
            try:
                opener = gzip.open if path.suffix == ".gz" else open
                with opener(path, "rt", encoding="utf-8") as handle:
                    return json.load(handle)
            except (OSError, ValueError) as exc:
                logger.error("Unreadable analysis cache %s: %s", path, exc)
                return None
        return None

    def _load_context(self, binary_path: str | None, binary_id: str | None = None) -> dict | None:
        if binary_id:
            context = self._load_context_by_id(binary_id)
            if context is not None:
                return context
        if not binary_path:
            return None
        try:
            return self.cache.get_cached(binary_path)
        except Exception as exc:  # pragma: no cover - cache already logs
            logger.warning("Could not load analysis cache for %s: %s", binary_path, exc)
            return None

    def _source_function_count(self, binary_id: str) -> int | None:
        """Function count from the tiny ``<sha>.meta.json``.

        Used as the cheap staleness probe so polling ``get_coverage_status``
        never has to decompress a multi-megabyte analysis cache.
        """
        meta_path = self.cache_dir / f"{binary_id}.meta.json"
        if not meta_path.exists():
            return None
        try:
            with open(meta_path, encoding="utf-8") as handle:
                value = json.load(handle).get("function_count")
        except (OSError, ValueError):
            return None
        return int(value) if isinstance(value, int) else None

    def index(
        self,
        binary_id: str,
        binary_path: str | None,
        context: dict | None = None,
    ) -> dict | None:
        """Build (or rebuild) the coverage record for a binary.

        Review marks are preserved across a rebuild: an address that was
        reviewed stays reviewed, keeping its timestamp, marking tool and note.
        Rebuilds happen when the analysis cache grows (an incremental Ghidra
        run) or when the scope algorithm is bumped, and neither is a reason to
        throw away review history.

        Returns the new record, or None when no analysis context is available.
        """
        if context is None:
            context = self._load_context(binary_path, binary_id)
        if not context:
            return None
        functions = context.get("functions") or []
        if not functions:
            return None

        records, description = compute_scope(context)

        # Every function whose address `canon_addr` cannot parse (a Ghidra
        # `EXTERNAL:` pseudo-address, anything malformed) is absent from
        # `records` and therefore absent from `total`. Nothing downstream
        # compares `total` against the source list, and both staleness probes
        # agree with each other, so an under-counted denominator would be
        # served as `ready` forever.
        dropped = len(functions) - len(records)
        if not records:
            # Not one address survived. Reporting `ready` with six zeros here
            # is the documented terminal condition -- a review loop would stop
            # on a binary nobody read. `not_indexed` with null counts is the
            # honest answer.
            logger.error(
                "Coverage index for %s: none of the %d function address(es) in "
                "the analysis cache could be parsed; reporting not_indexed "
                "rather than a denominator of zero",
                binary_id[:12],
                len(functions),
            )
            return None
        if dropped:
            logger.warning(
                "Coverage index for %s: %d of %d function(s) dropped -- their "
                "addresses did not parse, so they are missing from the "
                "denominator",
                binary_id[:12],
                dropped,
                len(functions),
            )
            description += (
                f" WARNING: {dropped} of {len(functions)} function(s) in the "
                f"analysis cache have unparseable addresses and are missing "
                f"from this denominator; total under-counts the binary."
            )

        previous = self.read(binary_id) or {}
        prior_functions = previous.get("functions") or {}
        for addr, record in records.items():
            prior = prior_functions.get(addr)
            if prior and prior.get("reviewed"):
                record["reviewed"] = True
                record["reviewed_at"] = prior.get("reviewed_at")
                record["reviewed_by"] = prior.get("reviewed_by")
                record["findings_note"] = prior.get("findings_note")
            else:
                record["reviewed"] = False
                record["reviewed_at"] = None
                record["reviewed_by"] = None
                record["findings_note"] = prior.get("findings_note") if prior else None

        metadata = context.get("metadata") or {}
        image_base = canon_addr(metadata.get("image_base")) or None
        resolved_path = binary_path or previous.get("binary_path") or metadata.get(
            "executable_path"
        )
        module_name = metadata.get("name") or (
            Path(resolved_path).name if resolved_path else None
        )

        data = {
            "schema_version": SCHEMA_VERSION,
            "binary_id": binary_id,
            "binary_path": resolved_path,
            "module_name": module_name,
            "image_base": image_base,
            "indexed_at": _utc_now(),
            "scope_version": SCOPE_VERSION,
            "scope_description": description,
            "source_function_count": len(functions),
            "dropped_address_count": dropped,
            "functions": records,
        }
        self.write(data)
        return data

    @staticmethod
    def _counts_add_up(record: dict) -> bool:
        """Does the stored denominator account for every source function?

        ``total`` (the size of the function map) plus the addresses that failed
        to parse must equal the function count the analysis cache supplied. The
        two sides come from different places -- one derived at index time, one
        recorded from the source list -- so unlike the count invariants this is
        a real cross-check rather than a restatement of its own arithmetic.

        Returns True when either field is missing: a legacy record has no
        opinion to check, and the schema-version trigger already rebuilds it.
        """
        dropped = record.get("dropped_address_count")
        source_count = record.get("source_function_count")
        if not isinstance(dropped, int) or not isinstance(source_count, int):
            return True
        return len(record.get("functions") or {}) + dropped == source_count

    def has_analysis_cache(self, binary_id: str) -> bool:
        """Is the Ghidra analysis this ledger counts still on disk?

        The rebuild source. Without it a dropped record cannot be reconstructed,
        so callers that are about to destroy a record must check first.
        """
        return (self.cache_dir / f"{binary_id}.json.gz").exists() or (
            self.cache_dir / f"{binary_id}.json"
        ).exists()

    def ensure_indexed(
        self,
        binary_id: str,
        binary_path: str | None,
    ) -> tuple[dict | None, str]:
        """Return ``(record, status)``, indexing on demand when it is cheap.

        - No coverage record and no analysis cache -> ``not_indexed``. Counts
          must be reported as null, never zero: zero reads as "complete" and
          would terminate a review loop on a binary nobody has looked at.
        - No coverage record but an analysis cache exists -> index now. It is a
          pure cache walk, and reporting ``not_indexed`` for a binary that is
          already fully analyzed would strand every previously-cached target.
        - Coverage record whose ``source_function_count``, ``scope_version`` or
          ``schema_version`` no longer matches, or whose own stored numbers do
          not add up -> re-index, preserving review marks.
        - Coverage record with no analysis cache behind it any more -> ``stale``;
          the counts are still returned because they are the last known truth,
          but the consumer is told not to trust them as current.
        """
        record = self.read(binary_id)
        if record is None:
            rebuilt = self.index(binary_id, binary_path)
            if rebuilt is None:
                return None, STATUS_NOT_INDEXED
            return rebuilt, STATUS_READY

        if not self.has_analysis_cache(binary_id):
            # The analysis this ledger counted has been evicted. Return the
            # last known counts -- they are still the best available truth --
            # but flag them as not current so nobody concludes on them.
            return record, STATUS_STALE

        source_count = self._source_function_count(binary_id)
        stale_scope = record.get("scope_version") != SCOPE_VERSION
        stale_count = (
            source_count is not None
            and record.get("source_function_count") is not None
            and source_count != record.get("source_function_count")
        )
        # A record written before drop accounting existed cannot say whether
        # its `total` covers every function or quietly lost some, so rebuild
        # rather than trust it. Deliberately keyed on the schema version and on
        # the record's own arithmetic, NOT on `dropped_address_count != 0`: a
        # binary that genuinely has unparseable addresses would then re-index
        # -- decompressing the whole analysis cache -- on every status poll,
        # forever, and produce the identical record each time.
        stale_schema = record.get("schema_version") != SCHEMA_VERSION
        inconsistent = not self._counts_add_up(record)
        if stale_scope or stale_count or stale_schema or inconsistent:
            if inconsistent:
                logger.warning(
                    "Coverage record for %s does not add up (total=%s + dropped=%s "
                    "!= source_function_count=%s); rebuilding",
                    binary_id[:12],
                    len(record.get("functions") or {}),
                    record.get("dropped_address_count"),
                    record.get("source_function_count"),
                )
            rebuilt = self.index(binary_id, binary_path or record.get("binary_path"))
            if rebuilt is not None:
                return rebuilt, STATUS_READY
            return record, STATUS_STALE

        return record, STATUS_READY

    # counting

    @staticmethod
    def counts(record: dict) -> dict[str, int]:
        """Derive the six count fields and assert the contract invariants."""
        functions = record.get("functions") or {}
        total = len(functions)
        in_scope_total = 0
        reviewed = 0
        reviewed_in_scope = 0
        for entry in functions.values():
            in_scope = bool(entry.get("in_scope"))
            is_reviewed = bool(entry.get("reviewed"))
            if in_scope:
                in_scope_total += 1
            if is_reviewed:
                reviewed += 1
                if in_scope:
                    reviewed_in_scope += 1

        counts = {
            "total": total,
            "in_scope_total": in_scope_total,
            "reviewed": reviewed,
            "reviewed_in_scope": reviewed_in_scope,
            "remaining": total - reviewed,
            "remaining_in_scope": in_scope_total - reviewed_in_scope,
        }
        _assert_invariants(counts, record)
        return counts

    # marking

    def reset_marks(self, binary_id: str) -> int:
        """Clear every review mark, keeping the index and the scope.

        The recovery path for a contaminated ledger -- a scripted sweep, a
        verification run against the wrong file, a pass that was retracted.
        Without it the only remedy is deleting files out of the cache
        directory by hand, and a denominator nobody can correct is worse than
        no denominator: the next campaign reads "fully reviewed" and stops.

        Returns the number of functions whose mark or note was cleared.
        """
        record = self.read(binary_id)
        if record is None:
            return 0
        cleared = 0
        for entry in (record.get("functions") or {}).values():
            if entry.get("reviewed") or entry.get("findings_note"):
                cleared += 1
            entry["reviewed"] = False
            entry["reviewed_at"] = None
            entry["reviewed_by"] = None
            entry["findings_note"] = None
        if cleared:
            self.write(record)
        return cleared

    def drop(self, binary_id: str) -> bool:
        """Delete the coverage record entirely.

        The next status query re-indexes from the analysis cache with every
        function unreviewed. Stronger than :meth:`reset_marks` because it also
        discards the stored scope, so it is the right call when the index
        itself is suspect rather than only the marks.
        """
        path = self._coverage_path(binary_id)
        if not path.exists():
            return False
        try:
            path.unlink()
            return True
        except OSError as exc:
            logger.error("Could not drop coverage side-car %s: %s", path, exc)
            return False

    def mark_reviewed(
        self,
        binary_id: str,
        addresses,
        tool: str,
        note: str | None = None,
        reviewed: bool = True,
    ) -> dict:
        """Mark functions reviewed (idempotent).

        Returns ``{"marked": [...], "already": [...], "unknown": [...]}``.
        Addresses absent from the function map are reported as ``unknown`` and
        never inserted -- a phantom entry would push ``reviewed`` above
        ``total`` and break the invariants the consumer asserts on.
        """
        record = self.read(binary_id)
        if record is None:
            return {"marked": [], "already": [], "unknown": [canon_addr(a) for a in addresses]}

        functions = record.get("functions") or {}
        marked: list[str] = []
        already: list[str] = []
        unknown: list[str] = []

        for raw in addresses:
            addr = canon_addr(raw)
            if not addr or addr not in functions:
                unknown.append(addr or str(raw))
                continue
            entry = functions[addr]
            if note is not None:
                entry["findings_note"] = note
            if bool(entry.get("reviewed")) == reviewed:
                # Idempotent: re-decompiling does not double-count, and does
                # not rewrite the original review timestamp.
                already.append(addr)
                continue
            entry["reviewed"] = reviewed
            entry["reviewed_at"] = _utc_now() if reviewed else None
            entry["reviewed_by"] = tool if reviewed else None
            marked.append(addr)

        if marked or note is not None:
            self.write(record)

        return {"marked": marked, "already": already, "unknown": unknown}


def has_reviewable_body(pseudocode: object) -> bool:
    """Did the decompiler actually return code, as opposed to a remark about it?

    The auto-marking tools use this to decide whether what they handed back
    counts as a review. Non-empty is not enough: Ghidra emits bodies that are
    only a banner comment (``/* WARNING: Globals starting with '_' overlap */``)
    when it declines to decompile, and marking on those advances the
    denominator for a function whose code nobody saw.

    A statement terminator or a brace is the cheapest signal that separates the
    two. Genuine empty stubs still mark -- ``void FUN_140137c58(void) { return; }``
    is real, reviewable code and http.sys has two of them. Across the 18500
    pseudocode bodies in the cached corpus, none lack both characters, so this
    rejects the comment-only case without excluding anything real.
    """
    if not isinstance(pseudocode, str):
        return False
    body = pseudocode.strip()
    return bool(body) and ("{" in body or ";" in body)


def auto_mark(
    cache,
    binary_path: str | None,
    addresses,
    tool: str,
    context: dict | None = None,
) -> None:
    """Best-effort auto-mark hook for the per-function analysis tools.

    Called for its side effect only: coverage must never be able to break an
    analysis tool, so every failure here is logged and swallowed. Callers pass
    the ``context`` they already hold so indexing a not-yet-indexed binary does
    not re-read and decompress the analysis cache on the hot path.

    See ``docs/coverage.md`` for the auto-marking tool set and why the
    whole-binary sweeps are deliberately not in it.
    """
    try:
        addresses = [a for a in (canon_addr(x) for x in addresses) if a]
        if not addresses or not binary_path:
            return
        store = CoverageStore(cache)
        binary_id = store.binary_id_for_path(binary_path)
        if store.read(binary_id) is None:
            if store.index(binary_id, binary_path, context=context) is None:
                return
        store.mark_reviewed(binary_id, addresses, tool=tool)
    except Exception as exc:
        logger.warning("auto-mark (%s) failed for %s: %s", tool, binary_path, exc)


def _assert_invariants(counts: dict[str, int], record: dict | None = None) -> None:
    """Fail loudly on an inconsistent count set.

    The consumer treats an invariant violation as a hard error; producing one
    server-side would be worse than crashing, so this raises rather than logs.

    The count relations below are near-tautological when :meth:`CoverageStore.counts`
    is the caller -- it derives ``remaining`` as ``total - reviewed`` a few lines
    before this asserts they are equal. ``record`` is what gives the check
    something it did not compute itself: ``source_function_count`` was recorded
    from the analysis cache's own function list, so comparing the denominator
    against it catches the one failure the relations cannot see -- a ``total``
    that silently lost functions.
    """
    for key, value in counts.items():
        if not isinstance(value, int) or value < 0:
            raise CoverageError(f"coverage count {key}={value!r} is not a non-negative int")
    if counts["remaining"] != counts["total"] - counts["reviewed"]:
        raise CoverageError("invariant violated: remaining != total - reviewed")
    if counts["remaining_in_scope"] != counts["in_scope_total"] - counts["reviewed_in_scope"]:
        raise CoverageError(
            "invariant violated: remaining_in_scope != in_scope_total - reviewed_in_scope"
        )
    if counts["in_scope_total"] > counts["total"]:
        raise CoverageError("invariant violated: in_scope_total > total")
    if counts["reviewed_in_scope"] > counts["reviewed"]:
        raise CoverageError("invariant violated: reviewed_in_scope > reviewed")
    if record is not None and not CoverageStore._counts_add_up(record):
        raise CoverageError(
            "invariant violated: total + dropped_address_count != "
            f"source_function_count (total={counts['total']}, "
            f"dropped={record.get('dropped_address_count')!r}, "
            f"source={record.get('source_function_count')!r}) -- the "
            "denominator does not account for every function in the binary"
        )
