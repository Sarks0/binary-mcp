"""
Review-coverage MCP tools.

binary-mcp owns the coverage denominator: how many functions a binary has, how
many are in scope, and how many have been reviewed. These tools expose it.
Unlike the rest of the server they return **JSON**, not markdown -- the
consumer (vr-lab's notes-mcp ledger) mirrors the count fields directly and
asserts invariants on them, so a prose report would be the wrong shape.

Tools
-----
``get_coverage_status``  -- the six counts plus scope provenance.
``get_next_unreviewed``  -- deterministic worklist, ascending address.
``coverage_index``       -- explicit (re)index; normally automatic.
``mark_function_reviewed`` -- manual mark / unmark, optional findings note.

Auto-marking
------------
These tools mark a function reviewed as a side effect:

    decompile_function, batch_decompile, get_review_package, get_param_sinks

They are the calls that hand a model the function's actual body or a semantic
per-function analysis of it. Everything else -- ``get_functions``,
``get_imports``, ``get_strings``, ``get_function_callers``,
``analyze_function_completeness``, and the whole-binary ``scan_pseudocode``
sweep -- does NOT auto-mark. Seeing a function in a list is not reviewing it,
and a regex sweep that "reviewed" 3000 functions would manufacture exactly the
false completion this store exists to prevent.
"""

from __future__ import annotations

import json
import logging

from src.engines.static.ghidra.coverage_store import (
    SCOPE_VERSION,
    CoverageStore,
    canon_addr,
)
from src.utils.security import (
    FileSizeError,
    PathTraversalError,
    sanitize_binary_path,
    validate_numeric_range,
)

logger = logging.getLogger(__name__)

# Cap on one worklist batch. Large enough for a real pass, small enough that a
# poll cannot bury the model.
MAX_WORKLIST = 500


def _json(payload: dict) -> str:
    return json.dumps(payload, indent=2)


def _error(message: str, **extra) -> str:
    return _json({"error": message, **extra})


def register_coverage_tools(app, session_manager, cache, runner=None):
    """
    Register the coverage tools with the MCP app.

    Args:
        app: FastMCP instance.
        session_manager: used only to resolve the active session's binary when
            the caller supplies neither ``binary_id`` nor ``binary_path``.
        cache: ProjectCache -- supplies the cache root, the sha256 identity and
            the analysis context.
        runner: accepted for signature parity with the sibling
            ``register_*_tools`` entry points; coverage is strictly cache-only
            and never invokes Ghidra.
    """
    del runner

    store = CoverageStore(cache)

    def _session_binary() -> str | None:
        return getattr(session_manager, "_current_binary_path", None)

    def _resolve(binary_id: str | None, binary_path: str | None):
        """Resolve identity, validating any caller-supplied path."""
        if binary_path:
            binary_path = str(sanitize_binary_path(binary_path))
        return store.resolve(
            binary_id=binary_id,
            binary_path=binary_path,
            fallback_path=_session_binary(),
        )

    @app.tool()
    def get_coverage_status(
        binary_id: str | None = None,
        binary_path: str | None = None,
    ) -> str:
        """
        Report review coverage for one binary: the denominator and what's left.

        Answers "how much of this binary has actually been read?" with numbers
        that survive a restart. binary-mcp owns these counts; a consumer should
        mirror them rather than recompute a total from its own mark count.

        Args:
            binary_id: Lowercase sha256 hexdigest of the binary's bytes (64
                chars). Optional.
            binary_path: Path to the binary. Optional convenience for clients
                that hold a path rather than a hash.
            When both are omitted, resolves the active analysis session's
            binary.

        Returns:
            JSON with ``binary_id``, ``binary_path``, ``module_name``,
            ``image_base``, the six counts (``total``, ``in_scope_total``,
            ``reviewed``, ``reviewed_in_scope``, ``remaining``,
            ``remaining_in_scope``), ``scope_description``, ``scope_version``,
            ``indexed_at`` and ``status``.

            ``status`` is ``ready`` | ``not_indexed`` | ``indexing`` |
            ``stale``. On anything other than ``ready`` **all six counts are
            null, never zero** -- zero would read as "complete" and terminate a
            review loop on a binary nobody has looked at. Treat a non-ready
            status as "cannot conclude", not "done".

            ``remaining_in_scope == 0`` means the in-scope worklist is finished,
            not that the binary is. Indirect calls are invisible to a forward
            call-graph walk, so full closure still consults ``remaining``.
        """
        try:
            resolved_id, resolved_path = _resolve(binary_id, binary_path)
        except ValueError as exc:
            return _error(str(exc))
        except (PathTraversalError, FileSizeError, FileNotFoundError) as exc:
            return _error(f"Invalid binary path: {exc}")

        if not resolved_id:
            return _error(
                "No binary resolved. Pass binary_id or binary_path, or run an "
                "analysis tool first so a session binary exists."
            )

        base = {
            "binary_id": resolved_id,
            "binary_path": resolved_path,
            "module_name": None,
            "image_base": None,
            "total": None,
            "in_scope_total": None,
            "reviewed": None,
            "reviewed_in_scope": None,
            "remaining": None,
            "remaining_in_scope": None,
            "scope_description": None,
            "scope_version": SCOPE_VERSION,
            "indexed_at": None,
            "status": "not_indexed",
        }

        try:
            record, status = store.ensure_indexed(resolved_id, resolved_path)
        except Exception as exc:
            logger.exception("get_coverage_status failed")
            return _error(f"Coverage lookup failed: {exc}", **base)

        if record is None:
            base["status"] = status
            base["scope_description"] = (
                "Binary has not been analyzed. Run analyze_binary first; "
                "coverage indexes automatically from the analysis cache."
            )
            return _json(base)

        payload = dict(base)
        payload.update(
            {
                "binary_path": record.get("binary_path") or resolved_path,
                "module_name": record.get("module_name"),
                "image_base": record.get("image_base"),
                "scope_description": record.get("scope_description"),
                "scope_version": record.get("scope_version"),
                "indexed_at": record.get("indexed_at"),
                "status": status,
            }
        )
        payload.update(store.counts(record))
        return _json(payload)

    @app.tool()
    def get_next_unreviewed(
        binary_id: str | None = None,
        count: int = 20,
        scope: str = "in_scope",
        binary_path: str | None = None,
    ) -> str:
        """
        Return the next batch of functions that have not been reviewed yet.

        Ordering is ascending numeric address -- deterministic and stable, so a
        client that crashes mid-batch and re-calls gets the same head of the
        queue and makes forward progress once those are marked.

        Args:
            binary_id: Lowercase sha256 hexdigest of the binary's bytes.
            count: Batch size (1-500, default 20).
            scope: ``"in_scope"`` (default) for the reachability-filtered
                worklist, or ``"all"`` to include thunk / library / unreachable
                functions. Excluded functions stay retrievable through
                ``"all"`` precisely so an under-counted scope cannot hide work.
            binary_path: Optional path alternative to ``binary_id``.

        Returns:
            JSON with ``binary_id``, ``scope``, ``returned``,
            ``remaining_after`` and a ``functions`` list of
            ``{address, name, size, in_scope, scope_reason}``.

            ``functions: []`` with ``remaining_after: 0`` is the terminal
            condition. A ``status`` other than ``ready`` means the binary is not
            indexed -- do not read an empty list as completion.
        """
        if scope not in ("in_scope", "all"):
            return _error(f"scope must be 'in_scope' or 'all', got {scope!r}")
        try:
            count = validate_numeric_range(count, 1, MAX_WORKLIST, "count")
            resolved_id, resolved_path = _resolve(binary_id, binary_path)
        except ValueError as exc:
            return _error(str(exc))
        except (PathTraversalError, FileSizeError, FileNotFoundError) as exc:
            return _error(f"Invalid binary path: {exc}")

        if not resolved_id:
            return _error(
                "No binary resolved. Pass binary_id or binary_path, or run an "
                "analysis tool first so a session binary exists."
            )

        try:
            record, status = store.ensure_indexed(resolved_id, resolved_path)
        except Exception as exc:
            logger.exception("get_next_unreviewed failed")
            return _error(f"Coverage lookup failed: {exc}")

        if record is None:
            return _json(
                {
                    "binary_id": resolved_id,
                    "scope": scope,
                    "returned": 0,
                    "remaining_after": None,
                    "functions": [],
                    "status": status,
                }
            )

        functions = record.get("functions") or {}
        pending = [
            (int(addr, 16), addr, entry)
            for addr, entry in functions.items()
            if not entry.get("reviewed") and (scope == "all" or entry.get("in_scope"))
        ]
        pending.sort(key=lambda item: item[0])

        batch = pending[:count]
        return _json(
            {
                "binary_id": resolved_id,
                "scope": scope,
                "returned": len(batch),
                "remaining_after": len(pending) - len(batch),
                "functions": [
                    {
                        "address": addr,
                        "name": entry.get("name"),
                        "size": entry.get("size"),
                        "in_scope": bool(entry.get("in_scope")),
                        "scope_reason": entry.get("scope_reason"),
                    }
                    for _, addr, entry in batch
                ],
                "status": status,
            }
        )

    @app.tool()
    def coverage_index(
        binary_path: str,
        force: bool = False,
    ) -> str:
        """
        Build or rebuild the coverage index for an already-analyzed binary.

        Normally unnecessary: coverage indexes itself after ``analyze_binary``
        and on first status query. Use this to force a rebuild after changing
        the scope algorithm, or to pre-warm the ledger.

        Review marks are preserved across a rebuild -- an address that was
        reviewed stays reviewed, with its original timestamp and note.

        Args:
            binary_path: Path to a binary that has already been analyzed.
            force: Rebuild even when a current index exists.

        Returns:
            JSON with the resulting counts, or an error when the binary has no
            analysis cache.
        """
        try:
            path = str(sanitize_binary_path(binary_path))
        except (PathTraversalError, FileSizeError, FileNotFoundError) as exc:
            return _error(f"Invalid binary path: {exc}")

        try:
            binary_id = store.binary_id_for_path(path)
            if force or store.read(binary_id) is None:
                record = store.index(binary_id, path)
            else:
                record, _status = store.ensure_indexed(binary_id, path)
        except Exception as exc:
            logger.exception("coverage_index failed")
            return _error(f"Coverage index failed: {exc}")

        if record is None:
            return _error(
                "Binary has not been analyzed yet. Run analyze_binary first.",
                binary_id=binary_id,
                binary_path=path,
                status="not_indexed",
            )

        payload = {
            "binary_id": binary_id,
            "binary_path": record.get("binary_path"),
            "module_name": record.get("module_name"),
            "image_base": record.get("image_base"),
            "scope_description": record.get("scope_description"),
            "scope_version": record.get("scope_version"),
            "indexed_at": record.get("indexed_at"),
            "status": "ready",
        }
        payload.update(store.counts(record))
        return _json(payload)

    @app.tool()
    def mark_function_reviewed(
        functions: str,
        binary_id: str | None = None,
        binary_path: str | None = None,
        note: str | None = None,
        reviewed: bool = True,
    ) -> str:
        """
        Manually mark functions reviewed (or clear the mark).

        The auto-mark side effect covers functions read through binary-mcp. Use
        this for work done elsewhere -- a Ghidra GUI session, objdump,
        a debugger -- and to attach a findings note to a reviewed function.

        Args:
            functions: Comma-separated addresses (``"0x140006d8c,140001010"``).
                Addresses only -- names are ambiguous across a binary and the
                ledger is keyed by address.
            binary_id: Lowercase sha256 hexdigest of the binary's bytes.
            binary_path: Optional path alternative to ``binary_id``.
            note: Optional findings note stored against every listed function.
            reviewed: Set False to clear the mark (e.g. a pass was retracted).

        Returns:
            JSON with ``marked`` / ``already`` / ``unknown`` address lists and
            the refreshed counts. Marking is idempotent -- re-marking a
            reviewed function does not double-count and does not overwrite its
            original timestamp.
        """
        try:
            resolved_id, resolved_path = _resolve(binary_id, binary_path)
        except ValueError as exc:
            return _error(str(exc))
        except (PathTraversalError, FileSizeError, FileNotFoundError) as exc:
            return _error(f"Invalid binary path: {exc}")

        if not resolved_id:
            return _error("No binary resolved. Pass binary_id or binary_path.")

        requested = [item.strip() for item in (functions or "").split(",") if item.strip()]
        if not requested:
            return _error("No functions specified. Provide comma-separated addresses.")
        if len(requested) > MAX_WORKLIST:
            return _error(
                f"Too many functions ({len(requested)}); maximum is {MAX_WORKLIST} per call."
            )

        malformed = [item for item in requested if not canon_addr(item)]
        if malformed:
            return _error(
                "Not valid hex addresses: " + ", ".join(malformed[:5]),
                hint="Pass addresses like 0x140006d8c, not function names.",
            )

        try:
            record, status = store.ensure_indexed(resolved_id, resolved_path)
            if record is None:
                return _error(
                    "Binary has not been analyzed yet. Run analyze_binary first.",
                    binary_id=resolved_id,
                    status=status,
                )
            result = store.mark_reviewed(
                resolved_id, requested, tool="mark_function_reviewed",
                note=note, reviewed=reviewed,
            )
            refreshed = store.read(resolved_id) or record
        except Exception as exc:
            logger.exception("mark_function_reviewed failed")
            return _error(f"Mark failed: {exc}")

        payload = {"binary_id": resolved_id, "status": status, **result}
        payload.update(store.counts(refreshed))
        return _json(payload)

    logger.info("Registered 4 coverage tools")
