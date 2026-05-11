"""
Dispatch-table recovery tools.

Cache-only MCP tools that reconstruct selector → handler maps from cached
Ghidra analysis output. Today this exposes ``find_ioctl_handlers`` for
Windows kernel-style IOCTL dispatchers (drivers, minifilters,
``win32k.sys``, opcode tables in ``mpengine.dll``-style binaries); future
work could extend the same scaffolding to message-pump WndProcs or RPC
opcode routers.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from src.engines.dynamic.windbg.kernel_types import IOCTLCode

logger = logging.getLogger(__name__)

# Maximum dispatcher records returned in one call; protects the model from
# being buried under noise on enormous binaries.
MAX_DISPATCHERS = 200

# IOCTL transfer methods (METHOD_*) and access masks (FILE_*_ACCESS) keyed
# by their raw 2-bit integer values. DDK conventional names.
_METHOD_NAMES = {
    0: "BUFFERED",
    1: "IN_DIRECT",
    2: "OUT_DIRECT",
    3: "NEITHER",
}

_ACCESS_NAMES = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_ACCESS",
    2: "FILE_WRITE_ACCESS",
    3: "FILE_READ_WRITE_ACCESS",
}

# First-parameter datatypes that suggest the function takes either a PIRP
# (``DriverDispatch`` style) or an unwrapped IOCTL value (opcode router).
_DISPATCHER_PARAM_TYPES = {"ULONG", "DWORD", "ULONG_PTR", "ULONGLONG", "UINT", "UINT32"}

# Substrings (case-insensitive) in a function's symbol name that strongly
# imply dispatch behavior even when the parameter shape is opaque.
_DISPATCHER_NAME_HINTS = ("dispatch", "ioctl", "handlerequest")

# Comparison-style dispatch: ``param_2 == 0x222000``, ``IoControlCode > 0x10``.
# Only real comparison operators are matched — bare ``=`` (assignment) must
# never be treated as a dispatch comparison (``param_2 = 0x222000`` is a
# store, not a branch). The selector uses ``\d+`` so ``param_10`` and beyond
# match in functions with 10+ parameters.
_COMPARE_RE = re.compile(
    r"(?P<sel>\b(?:param_\d+|IoControlCode|ControlCode|IoCtl|IoCtlCode)\b)\s*"
    r"(?:==|!=|<=|>=|<|>)\s*(?P<val>0x[0-9a-fA-F]+)"
)

# Switch-case style: ``case 0x222000:``.
_CASE_RE = re.compile(r"\bcase\s+(?P<val>0x[0-9a-fA-F]+)\s*:")


def _normalize_addr(raw: str | None) -> str:
    """Mirror review_tools._normalize_addr — lowercase, no 0x, no leading zeros."""
    if not raw:
        return ""
    return str(raw).lower().replace("0x", "").lstrip("0") or "0"


def _build_addr_index(functions: list[dict]) -> dict[str, dict]:
    """Forward index: normalized address → function record."""
    index: dict[str, dict] = {}
    for func in functions:
        addr = _normalize_addr(func.get("address"))
        if addr:
            index[addr] = func
    return index


def _build_jump_table_index(functions: list[dict]) -> dict[str, list[str]]:
    """Index: normalized switch source-addr → list of target addresses."""
    index: dict[str, list[str]] = {}
    for func in functions:
        for jt in func.get("jump_tables") or []:
            src = _normalize_addr(jt.get("source_addr"))
            if not src:
                continue
            index[src] = list(jt.get("targets") or [])
    return index


def _decode_ctl_code(value: int) -> dict:
    """Decode an IOCTL value into a dict with DDK-named bit-fields."""
    decoded = IOCTLCode.decode(value)
    return {
        "device": decoded.device_type,
        "function": decoded.function_code,
        "method": _METHOD_NAMES.get(decoded.method, f"METHOD_{decoded.method}"),
        "access": _ACCESS_NAMES.get(decoded.access, f"ACCESS_{decoded.access}"),
        "risk": decoded.risk_level,
    }


def _is_dispatcher_candidate(func: dict) -> tuple[bool, str | None]:
    """
    Return ``(is_candidate, selector_param_hint)``.

    ``selector_param_hint`` is a human-readable label like ``"param_2"`` or
    ``"IoControlCode"``; ``None`` when only name-based detection fired.
    """
    name = (func.get("name") or "").lower()
    if any(hint in name for hint in _DISPATCHER_NAME_HINTS):
        return True, None

    params = func.get("parameters") or []
    if params:
        first_dt = (params[0].get("datatype") or "").upper()
        if "PIRP" in first_dt or first_dt in _DISPATCHER_PARAM_TYPES:
            return True, params[0].get("name") or None

    return False, None


def _extract_constants(pseudocode: str) -> tuple[dict[int, str], str | None]:
    """
    Pull dispatch constants out of pseudocode.

    Returns ``(values_with_origin, selector_label)`` where ``values_with_origin``
    maps integer dispatch values to a human-readable origin (``"case"`` /
    ``"compare"``); ``selector_label`` is the most-frequent comparison-side
    selector (e.g. ``"param_2"``) or ``None`` if only ``case`` matches were
    found.
    """
    values: dict[int, str] = {}
    selector_counts: dict[str, int] = {}

    for m in _COMPARE_RE.finditer(pseudocode):
        try:
            v = int(m.group("val"), 16)
        except ValueError:
            continue
        values.setdefault(v, "compare")
        sel = m.group("sel")
        selector_counts[sel] = selector_counts.get(sel, 0) + 1

    for m in _CASE_RE.finditer(pseudocode):
        try:
            v = int(m.group("val"), 16)
        except ValueError:
            continue
        values.setdefault(v, "case")

    selector = None
    if selector_counts:
        selector = max(selector_counts.items(), key=lambda kv: kv[1])[0]

    return values, selector


def _resolve_target(addr: str, addr_index: dict[str, dict]) -> str | None:
    """Resolve a target address to ``"name @ 0xADDR"`` if known, else None."""
    func = addr_index.get(_normalize_addr(addr))
    if not func:
        return None
    return f"{func.get('name')} @ {func.get('address')}"


def _collect_targets_for_function(
    func: dict,
    jump_table_index: dict[str, list[str]],
) -> list[str]:
    """Concatenate every jump-table target list owned by ``func`` in order."""
    out: list[str] = []
    for jt in func.get("jump_tables") or []:
        src = _normalize_addr(jt.get("source_addr"))
        if not src:
            continue
        out.extend(jump_table_index.get(src, []))
    return out


def _build_dispatcher_record(
    func: dict,
    selector_hint: str | None,
    addr_index: dict[str, dict],
    jump_table_index: dict[str, list[str]],
    inferred_via: str | None = None,
) -> dict | None:
    """Assemble one dispatcher record. Returns None if no constants found."""
    pseudo = func.get("pseudocode") or ""
    values, selector = _extract_constants(pseudo)
    if not values:
        return None

    selector_label = selector or selector_hint or "IoControlCode"

    # Zip targets to constants when this function owns jump-table entries.
    # Only constants that came from `case` arms can plausibly be aligned
    # by ordering; comparison-style values are not tied to a switch table.
    case_values = sorted(v for v, origin in values.items() if origin == "case")
    targets = _collect_targets_for_function(func, jump_table_index)
    target_for_value: dict[int, str | None] = {}
    if case_values and len(targets) == len(case_values):
        for v, t in zip(case_values, targets):
            target_for_value[v] = _resolve_target(t, addr_index)

    cases: list[dict] = []
    for value in sorted(values.keys()):
        case_record = {
            "value": value,
            "value_hex": f"0x{value:x}",
            "ctl_code": _decode_ctl_code(value),
            "origin": values[value],
            "target": target_for_value.get(value),
        }
        if case_record["target"] is None:
            case_record["note"] = "indirect"
        cases.append(case_record)

    record = {
        "function": f"{func.get('name')} @ {func.get('address')}",
        "selector_param": selector_label,
        "case_count": len(cases),
        "cases": cases,
    }
    if inferred_via:
        record["inferred_via"] = inferred_via
    return record


def _try_inlined_recursion(
    func: dict,
    addr_index: dict[str, dict],
    jump_table_index: dict[str, list[str]],
) -> dict | None:
    """
    Walk one level into ``called_functions`` looking for a sub-handler that
    actually contains the constants. Helps with win32k-style tail-call
    dispatchers where the entry function is just a thunk.
    """
    for call in func.get("called_functions") or []:
        callee_addr = _normalize_addr(call.get("address"))
        callee = addr_index.get(callee_addr)
        if not callee:
            continue
        record = _build_dispatcher_record(
            callee,
            selector_hint=None,
            addr_index=addr_index,
            jump_table_index=jump_table_index,
            inferred_via=callee.get("name"),
        )
        if record is not None:
            # Anchor the record on the OUTER dispatcher so the analyst sees
            # the entry point they searched for, not the inlined helper.
            record["function"] = f"{func.get('name')} @ {func.get('address')}"
            return record
    return None


def _format_record(record: dict) -> list[str]:
    """Render one dispatcher record to a markdown-style block."""
    lines = [
        f"### {record['function']}",
        f"  Selector: {record['selector_param']}",
    ]
    if record.get("inferred_via"):
        lines.append(f"  Inferred via callee: {record['inferred_via']}")
    lines.append(f"  Cases: {record['case_count']}")
    for case in record["cases"]:
        ctl = case["ctl_code"]
        target = case.get("target") or "(unresolved)"
        ctl_summary = (
            f"device=0x{ctl['device']:x} func=0x{ctl['function']:x} "
            f"method={ctl['method']} access={ctl['access']} risk={ctl['risk']}"
        )
        note = f" [{case.get('note')}]" if case.get("note") else ""
        lines.append(f"    - {case['value_hex']:>12}  →  {target}{note}    [{ctl_summary}]")
    return lines


def register_dispatch_tools(app, session_manager, cache, runner):
    """
    Register dispatch / IOCTL recovery tools with the MCP app.

    Args:
        app: FastMCP application instance.
        session_manager: Session manager (unused today; kept for signature
            parity with sibling tool modules).
        cache: ProjectCache instance for cached Ghidra context.
        runner: GhidraRunner instance (kept for signature parity; this
            tool is strictly cache-only and never invokes it).
    """
    from src.utils.security import (
        FileSizeError,
        PathTraversalError,
        safe_error_message,
        safe_regex_compile,
        sanitize_binary_path,
    )

    # ``runner`` is accepted for signature parity with sibling
    # register_*_tools entrypoints; find_ioctl_handlers is strictly
    # cache-only and never invokes it. ``del`` makes the intentional
    # non-use explicit to static-analysis tools.
    del runner

    @app.tool()
    def find_ioctl_handlers(
        binary_path: str,
        function_filter: str | None = None,
    ) -> str:
        """
        Recover the IOCTL dispatch map for a kernel driver / opcode router.

        Walks the cached function list, identifies dispatcher candidates by
        their first-parameter datatype (PIRP/ULONG/DWORD-ish) or symbol
        name (Dispatch/Ioctl/HandleRequest, case-insensitive), regex-extracts
        comparison and ``case`` constants from each candidate's pseudocode,
        decodes the IOCTL bit-fields (device / function / method / access),
        and joins switch-table targets back to function names via the
        cached ``jump_tables`` field. For tail-call dispatchers that hold
        no constants in their own body, walks one level into
        ``called_functions`` to find the inlined sub-handler.

        Strict cache-only: the binary must already be analyzed with
        ``analyze_binary``. Does not invoke Ghidra.

        Args:
            binary_path: Path to an already-analyzed binary.
            function_filter: Optional regex filtered against dispatcher
                function names (e.g. ``"DispatchDeviceControl"`` or
                ``"^FltMgr.*"``).

        Returns:
            Markdown-style report listing each dispatcher with its selector
            parameter, decoded IOCTL cases, and resolved handler targets.
        """
        try:
            binary_path = str(sanitize_binary_path(binary_path))

            cached = cache.get_cached(binary_path)
            if not cached:
                return "Error: Binary has not been analyzed yet. Run analyze_binary first."

            cached_depth = cached.get("metadata", {}).get("analysis_depth", "full")
            if cached_depth in ("shallow", "structural"):
                return (
                    f"find_ioctl_handlers requires a full Ghidra cache, but "
                    f"the existing cache for this binary was produced with "
                    f"analysis_depth='{cached_depth}' (no pseudocode).\n\n"
                    f"To fix: analyze_binary(binary_path, force_reanalyze=True)"
                )

            functions = cached.get("functions", [])
            if not functions:
                return f"No functions found in {Path(binary_path).name}."

            if function_filter:
                try:
                    name_re = safe_regex_compile(function_filter, max_length=200)
                except ValueError as e:
                    return f"Error: invalid function_filter regex: {e}"
            else:
                name_re = None

            addr_index = _build_addr_index(functions)
            jump_table_index = _build_jump_table_index(functions)

            records: list[dict] = []
            for func in functions:
                if name_re and not name_re.search(func.get("name") or ""):
                    continue

                is_candidate, selector_hint = _is_dispatcher_candidate(func)
                if not is_candidate:
                    continue

                record = _build_dispatcher_record(func, selector_hint, addr_index, jump_table_index)
                if record is None:
                    record = _try_inlined_recursion(func, addr_index, jump_table_index)
                if record is None:
                    continue

                records.append(record)

                if len(records) >= MAX_DISPATCHERS:
                    break

            records.sort(
                key=lambda r: (
                    -r["case_count"],
                    _normalize_addr(r["function"].rsplit("@", 1)[-1].strip()),
                )
            )

            output = []
            output.append("=" * 60)
            output.append("IOCTL DISPATCH MAP")
            output.append("=" * 60)
            output.append(f"Binary:      {Path(binary_path).name}")
            output.append(f"Functions:   {len(functions)}")
            output.append(f"Dispatchers: {len(records)}")
            total_cases = sum(r["case_count"] for r in records)
            output.append(f"Total cases: {total_cases}")
            if function_filter:
                output.append(f"Filter:      {function_filter!r}")
            output.append("")

            if not records:
                output.append(
                    "No IOCTL dispatchers detected. If this is a kernel "
                    "driver, verify analyze_binary completed with full "
                    "decompilation, then check that handler names contain "
                    "Dispatch/Ioctl/HandleRequest or that the first "
                    "parameter is a PIRP / ULONG / DWORD."
                )
                return "\n".join(output)

            for record in records:
                output.extend(_format_record(record))
                output.append("")

            return "\n".join(output)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("find_ioctl_handlers", e)
        except Exception as e:
            logger.exception("find_ioctl_handlers failed")
            return safe_error_message("Failed to find IOCTL handlers", e)

    logger.info("Registered 1 dispatch tool")
