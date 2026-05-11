"""
Review and caller-analysis tools backed by the cached Ghidra context.

These tools never spawn Ghidra -- they operate purely on the cache populated
by ``analyze_binary``. If a binary has not been analyzed yet, they run it
once through the cache-miss path (mirroring the pattern used by
``control_flow_tools._get_or_run_analysis``).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from src.utils.pseudocode_rules import (
    SINK_HINTS,
    PseudocodeRules,
    _split_statements,
    adjust_confidences,
    scan_text,
)
from src.utils.security import (
    FileSizeError,
    PathTraversalError,
    safe_error_message,
    sanitize_binary_path,
    validate_numeric_range,
)

logger = logging.getLogger(__name__)

# One module-level rules instance -- pattern compilation is non-trivial and
# the rules are stateless.
_RULES = PseudocodeRules()


def _normalize_addr(raw: str | None) -> str:
    """Normalize an address string for comparison: lowercase, no 0x, no leading zeros."""
    if not raw:
        return ""
    return str(raw).lower().replace("0x", "").lstrip("0") or "0"


def _find_function(functions: list[dict], name_or_address: str) -> dict | None:
    """Look up a function by exact name, address, or substring name match."""
    for f in functions:
        if f.get("name") == name_or_address:
            return f

    needle = _normalize_addr(name_or_address)
    for f in functions:
        if _normalize_addr(f.get("address")) == needle:
            return f

    lower = name_or_address.lower()
    for f in functions:
        if lower in (f.get("name") or "").lower():
            return f
    return None


def _build_caller_index(functions: list[dict]) -> dict[str, list[dict]]:
    """
    Invert ``called_functions`` → map of callee-address → list of callers.

    O(N) scan across all functions; at 22K functions × ~10 callees/function
    this is under 5ms.
    """
    index: dict[str, list[dict]] = {}
    for caller in functions:
        caller_meta = {
            "name": caller.get("name"),
            "address": caller.get("address"),
        }
        for call in caller.get("called_functions", []) or []:
            addr = _normalize_addr(call.get("address"))
            if not addr:
                continue
            index.setdefault(addr, []).append(caller_meta)
    return index


def _load_context(binary_path: str, cache, runner):
    """Cache lookup with run-on-miss, mirroring control_flow_tools pattern."""
    import json

    from src.utils.config import get_config_int

    validated = sanitize_binary_path(binary_path)
    bp = str(validated)

    cached = cache.get_cached(bp)
    if cached:
        return cached, bp

    output_path = cache.cache_dir / f"temp_analysis_{Path(bp).stem}.json"
    script_path = Path(__file__).parent.parent / "engines" / "static" / "ghidra" / "scripts"
    timeout = get_config_int("GHIDRA_TIMEOUT", 1800)
    timeout = validate_numeric_range(timeout, 30, 3600, "GHIDRA_TIMEOUT")

    runner.analyze(
        binary_path=bp,
        script_path=str(script_path),
        script_name="core_analysis.py",
        output_path=str(output_path),
        keep_project=True,
        timeout=timeout,
    )
    if not output_path.exists():
        raise RuntimeError("Ghidra did not produce output.")

    with open(output_path, encoding="utf-8") as f:
        context = json.load(f)
    cache.save_cached(bp, context)
    output_path.unlink(missing_ok=True)
    return context, bp


# ---------------------------------------------------------------------------
# get_param_sinks helpers
# ---------------------------------------------------------------------------

# Maximum chain depth for parameter → sink propagation. Findings whose chain
# exceeds this are dropped (per Wave 3B brief), reflecting our honesty about
# how much we can usefully follow before the noise floor swallows the signal.
_PARAM_SINK_MAX_CHAIN = 6

# Bare-identifier scanner for taint propagation; preserved as a single
# pre-compiled object since this is hot in the per-statement sweep.
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# A simple `lhs = rhs` matcher that accepts an identifier or a small dotted
# chain on the LHS (``foo``, ``foo.bar``); rejects ``*p =`` and ``p->x =``
# so we don't fool ourselves into thinking we modeled aliasing.
_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*=\s*(.+)$")

# Pointer/field-indirection markers that demote chain confidence to
# ``indirect`` (the consumer should treat such chains as advisory only).
_INDIRECT_MARKERS = ("*", "->", "[")


def _collect_param_names(func: dict) -> set[str]:
    """Return the set of parameter names that act as taint roots."""
    roots: set[str] = set()
    for idx, p in enumerate(func.get("parameters") or []):
        name = (p.get("name") or "").strip()
        if name:
            roots.add(name)
        else:
            roots.add(f"param_{idx + 1}")
    return roots


def _split_args(text: str, open_paren_idx: int) -> list[str]:
    """
    Split the call's argument list at depth 0.

    ``text[open_paren_idx]`` must be ``'('``; returns the list of comma-
    separated args without the surrounding parens. Robust to nested parens,
    bracket subscripts, and angle-bracket templates.
    """
    args: list[str] = []
    if open_paren_idx >= len(text) or text[open_paren_idx] != "(":
        return args
    depth = 0
    buf: list[str] = []
    for ch in text[open_paren_idx:]:
        if ch == "(":
            depth += 1
            if depth == 1:
                continue
        elif ch == ")":
            depth -= 1
            if depth == 0:
                arg = "".join(buf).strip()
                if arg:
                    args.append(arg)
                return args
        if depth == 1 and ch == ",":
            arg = "".join(buf).strip()
            if arg:
                args.append(arg)
            buf = []
            continue
        buf.append(ch)
    # Unbalanced parens — return whatever we collected so far.
    arg = "".join(buf).strip()
    if arg:
        args.append(arg)
    return args


def _build_taint_aliases(statements, param_names: set[str]) -> dict[str, dict]:
    """
    Forward-sweep alias map.

    Each tainted variable carries: ``root`` (the originating parameter
    name), ``defined_at`` (statement index in ``statements``), and the
    ``expr`` text of the assignment that propagated the taint.

    The map is intentionally simplistic — pure ``lhs = rhs`` propagation,
    no field- / pointer-sensitivity. Dropped statements include anything
    that does not match a bare/dotted ``lhs``, or whose ``rhs`` does not
    contain at least one already-tainted identifier.
    """
    tainted: dict[str, dict] = {}
    # Roots themselves are tainted "for free" so chain walks bottom-out.
    for root in param_names:
        tainted[root] = {"root": root, "defined_at": -1, "expr": ""}

    for idx, stmt in enumerate(statements):
        m = _ASSIGN_RE.match(stmt.text)
        if not m:
            continue
        lhs = m.group(1)
        rhs = m.group(2)
        rhs_idents = set(_IDENT_RE.findall(rhs))
        # Skip self-references (``x = x + 1``) so we don't shadow an
        # earlier root binding.
        propagated = False
        for name in rhs_idents:
            if name == lhs:
                continue
            if name in tainted:
                tainted[lhs] = {
                    "root": tainted[name]["root"],
                    "defined_at": idx,
                    "expr": stmt.text,
                }
                propagated = True
                break
        if not propagated and lhs not in param_names:
            # Reassignment from an expression containing no tainted
            # identifiers (e.g. ``x = 0x100`` after ``x = param_1``) kills
            # the binding. Without this, the stale taint survives and
            # ``get_param_sinks`` reports false-positive findings on
            # ``memcpy(dst, src, x)`` even though ``x`` has been
            # overwritten with a constant. Roots themselves (param_names)
            # are preserved — they are tainted unconditionally.
            tainted.pop(lhs, None)
    return tainted


def _walk_back_chain(
    var_name: str,
    tainted: dict[str, dict],
    statements,
    max_depth: int,
) -> list[dict] | None:
    """
    Reconstruct the propagation chain that made ``var_name`` tainted.

    Returns ``None`` when the chain is longer than ``max_depth`` so the
    caller can suppress the finding (per task brief). A single-step chain
    where ``var_name`` is itself the parameter root produces an empty
    list (the chain is trivial).
    """
    chain: list[dict] = []
    current = var_name
    visited: set[str] = set()
    while current in tainted and current not in visited:
        visited.add(current)
        record = tainted[current]
        if record["defined_at"] < 0:
            # Reached the root — done.
            break
        if len(chain) >= max_depth:
            return None  # signal "chain too long; suppress"
        stmt = statements[record["defined_at"]]
        chain.append({"line": stmt.start_line, "text": stmt.text})
        # Follow back to the root via the rhs identifier that introduced
        # the taint. Pick the FIRST tainted rhs ident matching the
        # propagation that built this entry (re-derive cheaply).
        rhs_idents = set(_IDENT_RE.findall(stmt.text))
        next_var = None
        for name in rhs_idents:
            if name == current:
                continue
            if name in tainted:
                next_var = name
                break
        if next_var is None:
            break
        current = next_var
    return list(reversed(chain))  # oldest first


def _chain_confidence(chain: list[dict], arg_text: str) -> str:
    """``indirect`` if any chain step or the sink arg crosses pointer/field."""
    if any(marker in arg_text for marker in _INDIRECT_MARKERS):
        return "indirect"
    for step in chain:
        if any(marker in step["text"] for marker in _INDIRECT_MARKERS):
            return "indirect"
    return "structural"


def _collect_param_sink_findings(
    statements, tainted: dict[str, dict], param_names: set[str]
) -> list[dict]:
    """Walk statements, emit one finding per (sink, tainted-arg) pair."""
    findings: list[dict] = []
    seen: set[tuple[int, int, str]] = set()

    for idx, stmt in enumerate(statements):
        for sink_match in SINK_HINTS.finditer(stmt.text):
            sink_name = sink_match.group(1)
            # SINK_HINTS regex ends with ``\s*\(`` — the open paren sits
            # at sink_match.end() - 1 in the statement text.
            open_paren_idx = sink_match.end() - 1
            args = _split_args(stmt.text, open_paren_idx)

            for arg_idx, arg in enumerate(args):
                arg_idents = set(_IDENT_RE.findall(arg))
                root = None
                anchor = None
                for name in arg_idents:
                    if name in param_names:
                        root, anchor = name, name
                        break
                if root is None:
                    for name in arg_idents:
                        if name in tainted:
                            root, anchor = tainted[name]["root"], name
                            break
                if root is None:
                    continue

                key = (stmt.start_line, arg_idx, root)
                if key in seen:
                    continue
                seen.add(key)

                chain = _walk_back_chain(anchor, tainted, statements, _PARAM_SINK_MAX_CHAIN)
                if chain is None:
                    # Chain longer than the depth budget — drop per brief.
                    continue

                findings.append(
                    {
                        "sink": sink_name,
                        "sink_line": stmt.start_line,
                        "arg_index": arg_idx,
                        "taint_chain": chain,
                        "parameter_root": root,
                        "confidence": _chain_confidence(chain, arg),
                    }
                )

    findings.sort(key=lambda f: (f["sink_line"], f["arg_index"]))
    return findings


def register_review_tools(app, session_manager, cache, runner, api_patterns=None):
    """
    Register review-oriented MCP tools.

    Args:
        app: FastMCP instance
        session_manager: unused today; kept for signature parity with other
            tool modules in case session-logging is added later
        cache: ProjectCache
        runner: GhidraRunner
        api_patterns: APIPatterns instance (optional) used by
            ``get_review_package`` to enrich the API-usage list
    """

    @app.tool()
    def get_function_callers(
        binary_path: str,
        function_name_or_address: str,
        limit: int = 100,
    ) -> str:
        """
        List the functions that call a given function.

        Inverts the cached ``called_functions`` graph. Useful for impact
        analysis ("where is this handler invoked from?") which the existing
        `get_call_graph` tool does not cover in the reverse direction.

        Args:
            binary_path: Path to analyzed binary
            function_name_or_address: Target function -- exact name, hex
                address (with or without 0x), or unique substring match
            limit: Max callers to return (default 100, max 10000)

        Returns:
            Formatted list of callers with addresses, or a not-found error.
        """
        try:
            limit = validate_numeric_range(limit, 1, 10000, "limit")
            context, _ = _load_context(binary_path, cache, runner)
            functions = context.get("functions", [])

            target = _find_function(functions, function_name_or_address)
            if not target:
                return (
                    f"Function not found: {function_name_or_address}. "
                    f"Try an exact name or address like '0x1800abcd'."
                )

            index = _build_caller_index(functions)
            callers = index.get(_normalize_addr(target.get("address")), [])
            total = len(callers)
            shown = callers[:limit]

            lines = [
                f"**Callers of {target.get('name')} @ {target.get('address')}**",
                f"Total: {total} (showing {len(shown)})",
                "",
            ]
            if not shown:
                lines.append("No callers found in this binary.")
                lines.append(
                    "Note: indirect calls are not represented in the direct "
                    "call graph. Run `find_vtables` to enumerate "
                    'function-pointer tables and `get_xrefs(direction="to", '
                    "...)` for combined direct + indirect candidates."
                )
            else:
                for caller in shown:
                    lines.append(f"- {caller.get('name')} @ {caller.get('address')}")
            return "\n".join(lines)

        except (PathTraversalError, FileSizeError, FileNotFoundError) as e:
            return f"Invalid binary path: {e}"
        except Exception as e:
            logger.exception(f"get_function_callers failed: {e}")
            return f"Error: {e}"

    @app.tool()
    def scan_pseudocode(
        binary_path: str,
        function_filter: str | None = None,
        severity_floor: str = "low",
        rule_ids: list[str] | None = None,
        exclude_rule_ids: list[str] | None = None,
        confidence_floor: int = 0,
        limit: int = 50,
        offset: int = 0,
        mode: str = "findings",
    ) -> str:
        """
        Scan cached pseudocode for CWE / vulnerability patterns.

        Pattern-based triage -- expect false positives. Each finding has a
        confidence score (0-100) derived from rule baseline + per-function
        context (corroboration from other rules, scanner-shape penalty,
        dangerous-sink presence, regex-meta negative pattern).

        Recommended workflow on large binaries (14K+ functions):
          1. ``mode='summary', confidence_floor=60`` to surface top suspects
          2. ``get_review_package(binary, top_function)`` for full context
             so the model can confirm or reject each candidate.

        Modes:
          - "findings" (default): full per-finding report with excerpt and
            recommendation, sorted by severity then confidence desc.
          - "summary": one line per function showing finding count, max
            confidence in that function, and severity breakdown.

        Args:
            binary_path: Path to analyzed binary (must have been analyzed
                without ``skip_decompile=True``)
            function_filter: Optional regex filtered against function names
            severity_floor: "info" | "low" | "medium" | "high" | "critical"
            rule_ids: Restrict scanning to specific rule ids (allowlist)
            exclude_rule_ids: Drop these rule ids (blocklist; e.g. silence
                a rule known to be noisy on this target)
            confidence_floor: Drop findings whose computed confidence falls
                below this value (0-100). Use 60-70 for first-pass triage.
            limit: Max rows to return (default 50, max 5000)
            offset: Skip this many rows before returning ``limit``
            mode: "findings" or "summary"

        Returns:
            Findings or per-function summary, plus pagination footer.
        """
        try:
            import re as _re

            limit = validate_numeric_range(limit, 1, 5000, "limit")
            offset = validate_numeric_range(offset, 0, 1_000_000, "offset")
            confidence_floor = validate_numeric_range(confidence_floor, 0, 100, "confidence_floor")
            mode = mode.lower()
            if mode not in ("findings", "summary"):
                return f"Invalid mode '{mode}'. Use 'findings' or 'summary'."

            context, _ = _load_context(binary_path, cache, runner)

            # scan_pseudocode is meaningless on a shallow/structural cache:
            # there is no decompiled text to match rules against. Surface
            # this explicitly instead of silently scanning zero functions.
            cached_depth = context.get("metadata", {}).get("analysis_depth", "full")
            if cached_depth in ("shallow", "structural"):
                return (
                    f"scan_pseudocode requires a full Ghidra cache, but the "
                    f"existing cache for this binary was produced with "
                    f"analysis_depth='{cached_depth}' (no pseudocode).\n\n"
                    f"To fix: analyze_binary(binary_path, force_reanalyze=True)\n\n"
                    f"For string-only triage that does not need pseudocode, "
                    f"use search_strings or search_bytes."
                )

            functions = context.get("functions", [])

            pattern = _re.compile(function_filter) if function_filter else None
            rules = _RULES.filter(severity_floor=severity_floor, rule_ids=rule_ids)
            if exclude_rule_ids:
                excluded = set(exclude_rule_ids)
                rules = [r for r in rules if r.id not in excluded]
            if not rules:
                return (
                    f"No rules matched severity_floor={severity_floor} / "
                    f"rule_ids={rule_ids} / exclude_rule_ids={exclude_rule_ids}. "
                    f"See PseudocodeRules for available rules."
                )

            severity_order = {
                s: i for i, s in enumerate(("info", "low", "medium", "high", "critical"))
            }

            per_func: dict[str, dict] = {}
            all_findings: list[dict] = []
            scanned = 0
            dropped_by_confidence = 0
            for func in functions:
                if pattern and not pattern.search(func.get("name") or ""):
                    continue
                pseudo = func.get("pseudocode")
                if not pseudo:
                    continue
                scanned += 1
                fname = func.get("name") or "?"
                faddr = func.get("address") or "?"

                func_findings = scan_text(pseudo, rules)
                adjust_confidences(func_findings, pseudo)

                kept: list[dict] = []
                for finding in func_findings:
                    if finding["confidence"] < confidence_floor:
                        dropped_by_confidence += 1
                        continue
                    finding["function"] = fname
                    finding["address"] = faddr
                    kept.append(finding)
                if not kept:
                    continue

                bucket = per_func.setdefault(
                    fname,
                    {
                        "name": fname,
                        "address": faddr,
                        "by_severity": {},
                        "max_severity_idx": -1,
                        "max_confidence": 0,
                        "total": 0,
                    },
                )
                for finding in kept:
                    all_findings.append(finding)
                    sev = finding["severity"]
                    bucket["by_severity"][sev] = bucket["by_severity"].get(sev, 0) + 1
                    bucket["total"] += 1
                    sev_idx = severity_order.get(sev, 0)
                    if sev_idx > bucket["max_severity_idx"]:
                        bucket["max_severity_idx"] = sev_idx
                    if finding["confidence"] > bucket["max_confidence"]:
                        bucket["max_confidence"] = finding["confidence"]

            if not all_findings:
                msg = (
                    f"No findings. Scanned {scanned} functions with "
                    f"{len(rules)} rules at severity_floor='{severity_floor}'"
                )
                if confidence_floor > 0:
                    msg += (
                        f", confidence_floor={confidence_floor} "
                        f"(dropped {dropped_by_confidence} low-confidence hits)"
                    )
                return msg + "."

            all_findings.sort(
                key=lambda f: (
                    -severity_order.get(f["severity"], 0),
                    -f["confidence"],
                    f["rule_id"],
                )
            )

            total_findings = len(all_findings)
            total_funcs_with_findings = len(per_func)

            if mode == "summary":
                summary_rows = sorted(
                    per_func.values(),
                    key=lambda r: (
                        -r["max_severity_idx"],
                        -r["max_confidence"],
                        -r["total"],
                        r["name"],
                    ),
                )
                page = summary_rows[offset : offset + limit]
                header = (
                    f"**Pseudocode scan SUMMARY: {total_findings} finding(s) "
                    f"across {total_funcs_with_findings} function(s) "
                    f"of {scanned} scanned**"
                )
                meta = f"Rules: {len(rules)} | Severity floor: {severity_floor}"
                if confidence_floor > 0:
                    meta += (
                        f" | Confidence floor: {confidence_floor} (dropped {dropped_by_confidence})"
                    )
                lines = [header, meta, ""]
                if not page:
                    lines.append(
                        f"Offset {offset} is beyond the result set "
                        f"({total_funcs_with_findings} functions)."
                    )
                    return "\n".join(lines)

                for row in page:
                    sev_breakdown = " ".join(
                        f"{sev}={row['by_severity'][sev]}"
                        for sev in ("critical", "high", "medium", "low", "info")
                        if row["by_severity"].get(sev)
                    )
                    lines.append(
                        f"- {row['name']} @ {row['address']}  "
                        f"(conf={row['max_confidence']}, {row['total']} total) "
                        f"{sev_breakdown}"
                    )

                next_offset = offset + len(page)
                if next_offset < total_funcs_with_findings:
                    lines.append("")
                    lines.append(
                        f"_Showing {offset + 1}-{next_offset} of "
                        f"{total_funcs_with_findings}. "
                        f"Call again with offset={next_offset} for the next page._"
                    )
                return "\n".join(lines)

            page = all_findings[offset : offset + limit]
            header = (
                f"**Pseudocode scan: {total_findings} finding(s) "
                f"across {total_funcs_with_findings} function(s) "
                f"of {scanned} scanned**"
            )
            meta = f"Rules: {len(rules)} | Severity floor: {severity_floor}"
            if confidence_floor > 0:
                meta += f" | Confidence floor: {confidence_floor} (dropped {dropped_by_confidence})"
            lines = [header, meta, ""]
            if not page:
                lines.append(
                    f"Offset {offset} is beyond the result set ({total_findings} findings)."
                )
                return "\n".join(lines)

            for hit in page:
                lines.append(
                    f"[{hit['severity'].upper()} conf={hit['confidence']}] "
                    f"{hit['rule_id']} ({hit['cwe']}) "
                    f"-- {hit['function']} @ {hit['address']}"
                )
                lines.append(f"    {hit['description']}")
                lines.append(f"    excerpt: {hit['excerpt']}")
                lines.append(f"    → {hit['recommendation']}")
                lines.append("")

            next_offset = offset + len(page)
            if next_offset < total_findings:
                lines.append(
                    f"_Showing {offset + 1}-{next_offset} of "
                    f"{total_findings}. "
                    f"Call again with offset={next_offset} for the next page. "
                    f"Tip: try mode='summary' for a bird's-eye view._"
                )
            return "\n".join(lines)

        except (PathTraversalError, FileSizeError, FileNotFoundError) as e:
            return f"Invalid binary path: {e}"
        except Exception as e:
            logger.exception(f"scan_pseudocode failed: {e}")
            return f"Error: {e}"

    @app.tool()
    def get_review_package(
        binary_path: str,
        function_name_or_address: str,
    ) -> str:
        """
        Assemble a self-contained review bundle for one function.

        Returns pseudocode together with everything needed for semantic
        review in one shot: callers, callees, imported APIs actually used,
        referenced strings, jump tables (if extracted), pseudocode-rule
        findings, and complexity. Hand the output to a model to get a
        meaningful code review without further tool calls.

        Args:
            binary_path: Path to analyzed binary
            function_name_or_address: Function to review

        Returns:
            Structured, multi-section text payload.
        """
        try:
            context, _ = _load_context(binary_path, cache, runner)
            functions = context.get("functions", [])

            target = _find_function(functions, function_name_or_address)
            if not target:
                return f"Function not found: {function_name_or_address}."

            pseudo = target.get("pseudocode") or ""
            signature = target.get("signature") or ""
            params = target.get("parameters") or []
            locals_ = target.get("local_variables") or []
            callees = target.get("called_functions") or []
            basic_blocks = target.get("basic_blocks") or []
            jump_tables = target.get("jump_tables") or []

            caller_index = _build_caller_index(functions)
            callers = caller_index.get(_normalize_addr(target.get("address")), [])

            # APIs actually referenced in pseudocode
            import_names: set[str] = set()
            for imp in context.get("imports", []):
                name = imp.get("name")
                if name:
                    import_names.add(name)
            apis_used: list[str] = []
            if pseudo:
                for api in sorted(import_names):
                    if api in pseudo:
                        apis_used.append(api)

            # Strings referenced at addresses inside this function's body
            # (cheap: each string has xrefs with a "from" address -- compare
            # against the function's basic-block ranges)
            strings_referenced: list[dict] = []
            func_ranges = []
            try:
                for bb in basic_blocks:
                    start = int(str(bb["start"]).replace("0x", ""), 16)
                    end = int(str(bb["end"]).replace("0x", ""), 16)
                    func_ranges.append((start, end))
            except (KeyError, ValueError):
                func_ranges = []

            if func_ranges:
                for s in context.get("strings", []):
                    for xref in s.get("xrefs") or []:
                        try:
                            xa = int(str(xref.get("from", "")).replace("0x", ""), 16)
                        except ValueError:
                            continue
                        if any(a <= xa <= b for a, b in func_ranges):
                            strings_referenced.append(
                                {
                                    "address": s.get("address"),
                                    "value": (s.get("value") or "")[:120],
                                }
                            )
                            break

            # Rule findings for this function only
            findings: list[dict] = []
            if pseudo:
                for f in scan_text(pseudo, _RULES.rules):
                    findings.append(f)

            # Format
            lines = [
                f"# Review Package -- {target.get('name')} @ {target.get('address')}",
                "",
                "## Signature",
                f"`{signature}`",
                "",
                "## Metrics",
                f"- Basic blocks: {len(basic_blocks)}",
                f"- Parameters: {len(params)}",
                f"- Local variables: {len(locals_)}",
                f"- Callers: {len(callers)}",
                f"- Callees: {len(callees)}",
                f"- Jump tables: {len(jump_tables)}",
                "",
                "## Parameters",
            ]
            if params:
                for p in params:
                    lines.append(f"- `{p.get('datatype')} {p.get('name')}`")
            else:
                lines.append("(none)")

            lines.append("")
            lines.append("## Callers")
            if callers:
                for c in callers[:25]:
                    lines.append(f"- {c.get('name')} @ {c.get('address')}")
                if len(callers) > 25:
                    lines.append(f"  … and {len(callers) - 25} more")
            else:
                lines.append("(none -- entry point or unreferenced)")

            lines.append("")
            lines.append("## Callees")
            if callees:
                for c in callees[:25]:
                    lines.append(f"- {c.get('name')} @ {c.get('address')}")
                if len(callees) > 25:
                    lines.append(f"  … and {len(callees) - 25} more")
            else:
                lines.append("(none)")

            lines.append("")
            lines.append("## Imported APIs referenced in pseudocode")
            if apis_used:
                for api in apis_used[:25]:
                    lines.append(f"- {api}")
                if len(apis_used) > 25:
                    lines.append(f"  … and {len(apis_used) - 25} more")
            else:
                lines.append("(none)")

            lines.append("")
            lines.append("## Strings referenced")
            if strings_referenced:
                for s in strings_referenced[:25]:
                    lines.append(f"- `{s['value']}` @ {s['address']}")
                if len(strings_referenced) > 25:
                    lines.append(f"  … and {len(strings_referenced) - 25} more")
            else:
                lines.append("(none)")

            if jump_tables:
                lines.append("")
                lines.append("## Jump tables")
                for jt in jump_tables:
                    targets = jt.get("targets") or []
                    lines.append(f"- switch @ {jt.get('source_addr')} → {len(targets)} cases")

            lines.append("")
            lines.append("## Pseudocode rule findings")
            if findings:
                for hit in findings:
                    lines.append(
                        f"- [{hit['severity'].upper()}] {hit['rule_id']} "
                        f"({hit['cwe']}): {hit['description']}"
                    )
                    lines.append(f"    excerpt: {hit['excerpt']}")
            else:
                lines.append("(no rule-based findings for this function)")

            lines.append("")
            lines.append("## Pseudocode")
            if pseudo:
                lines.append("```c")
                lines.append(pseudo)
                lines.append("```")
            else:
                lines.append(
                    "(no pseudocode -- function was likely analyzed with "
                    "skip_decompile=True or is a thunk/external)"
                )

            return "\n".join(lines)

        except (PathTraversalError, FileSizeError, FileNotFoundError) as e:
            return f"Invalid binary path: {e}"
        except Exception as e:
            logger.exception(f"get_review_package failed: {e}")
            return f"Error: {e}"

    @app.tool()
    def get_switch_tables(
        binary_path: str,
        function_name_or_address: str | None = None,
        limit: int = 200,
    ) -> str:
        """
        List extracted jump / switch tables.

        Reads the ``jump_tables`` field populated by ``core_analysis.py``
        during ``analyze_binary``. Useful for dispatch-heavy binaries
        (e.g. mpengine signal-code dispatchers).

        Args:
            binary_path: Path to analyzed binary
            function_name_or_address: Restrict to one function; if omitted,
                list tables across the whole binary
            limit: Max tables to list (default 200)

        Returns:
            Formatted listing of switch_addr → N cases, or guidance if the
            cache predates the jump_tables extraction.
        """
        try:
            limit = validate_numeric_range(limit, 1, 10000, "limit")
            context, _ = _load_context(binary_path, cache, runner)
            functions = context.get("functions", [])

            if function_name_or_address:
                target = _find_function(functions, function_name_or_address)
                if not target:
                    return f"Function not found: {function_name_or_address}."
                candidates = [target]
            else:
                candidates = functions

            tables: list[tuple[dict, dict]] = []
            any_has_field = False
            for func in candidates:
                if "jump_tables" in func:
                    any_has_field = True
                for jt in func.get("jump_tables") or []:
                    tables.append((func, jt))

            if not any_has_field:
                return (
                    "No jump_tables data in cache -- this cache was produced "
                    "by a version of core_analysis.py that predates jump-table "
                    "extraction. Re-run `analyze_binary(path, force_reanalyze=True)`."
                )

            total = len(tables)
            tables = tables[:limit]

            if not tables:
                return "No jump/switch tables found."

            lines = [f"**Jump tables: {total} total ({len(tables)} shown)**", ""]
            for func, jt in tables:
                targets = jt.get("targets") or []
                lines.append(
                    f"- {func.get('name')} @ {func.get('address')} -- "
                    f"switch @ {jt.get('source_addr')} → {len(targets)} cases"
                )
                for t in targets[:12]:
                    lines.append(f"    → {t}")
                if len(targets) > 12:
                    lines.append(f"    … and {len(targets) - 12} more")
            return "\n".join(lines)

        except (PathTraversalError, FileSizeError, FileNotFoundError) as e:
            return f"Invalid binary path: {e}"
        except Exception as e:
            logger.exception(f"get_switch_tables failed: {e}")
            return f"Error: {e}"

    @app.tool()
    def get_param_sinks(binary_path: str, function: str) -> str:
        """
        Trace untrusted-input → dangerous-sink chains in one function.

        Builds a syntactic taint chain across pseudocode statements: each
        function parameter is treated as a taint root, simple ``lhs = rhs``
        assignments propagate the taint through aliases, and any call to a
        recognised sink (memcpy, RtlCopyMemory, ProbeForRead, etc.) whose
        argument identifiers map back to a parameter is reported.

        IMPORTANT: this is a syntactic chain, not real taint analysis.
        Pure-text propagation drops through pointer indirection (``*p``,
        ``p->field``, ``p[i]``); when a chain crosses any of these the
        confidence is downgraded from ``structural`` to ``indirect`` so the
        consumer can prioritise accordingly.

        Args:
            binary_path: Path to analyzed binary.
            function: Function name or hex address.

        Returns:
            Formatted markdown-style report listing every (sink, arg)
            chain that traces back to a parameter, ordered by sink line.
        """
        try:
            context, _ = _load_context(binary_path, cache, runner)

            cached_depth = context.get("metadata", {}).get("analysis_depth", "full")
            if cached_depth in ("shallow", "structural"):
                return (
                    f"get_param_sinks requires a full Ghidra cache, but the "
                    f"existing cache for this binary was produced with "
                    f"analysis_depth='{cached_depth}' (no pseudocode).\n\n"
                    f"To fix: analyze_binary(binary_path, force_reanalyze=True)"
                )

            functions = context.get("functions", [])
            target = _find_function(functions, function)
            if not target:
                return (
                    f"Function not found: {function}. "
                    f"Try an exact name or address like '0x1800abcd'."
                )

            pseudo = target.get("pseudocode") or ""
            if not pseudo.strip():
                return (
                    f"Function {target.get('name')} @ {target.get('address')} "
                    f"has no pseudocode in the cache. Re-analyze with full "
                    f"decompilation enabled."
                )

            param_names = _collect_param_names(target)
            if not param_names:
                return (
                    f"Function {target.get('name')} @ {target.get('address')} "
                    f"has no parameters in the cache; nothing to trace."
                )

            statements = _split_statements(pseudo)
            tainted = _build_taint_aliases(statements, param_names)
            findings = _collect_param_sink_findings(statements, tainted, param_names)

            lines = [
                f"### Param-sink chains for {target.get('name')} @ {target.get('address')}",
                f"Parameters: {', '.join(sorted(param_names))}",
                f"Findings:   {len(findings)}",
                "",
                "_Syntactic chain only — not real taint analysis. "
                "`indirect` confidence means the chain crossed pointer / "
                "field indirection that pure-text propagation cannot follow._",
                "",
            ]
            if not findings:
                lines.append(
                    "No parameter-derived sink calls detected. Consider "
                    "running scan_pseudocode for unconditional sink hits."
                )
                return "\n".join(lines)

            for f in findings:
                lines.append(
                    f"- {f['sink']}() arg #{f['arg_index']} "
                    f"@ line {f['sink_line']}  "
                    f"[root={f['parameter_root']}, "
                    f"confidence={f['confidence']}]"
                )
                for step in f["taint_chain"]:
                    lines.append(f"    L{step['line']}: {step['text']}")
                lines.append("")

            return "\n".join(lines)

        except (PathTraversalError, FileSizeError, FileNotFoundError) as e:
            return f"Invalid binary path: {e}"
        except Exception as e:
            logger.error(f"get_param_sinks failed: {e}")
            return safe_error_message("Failed to trace parameter sinks", e)

    # Keep a tuple export so the caller can introspect what was registered
    return (
        get_function_callers,
        scan_pseudocode,
        get_review_package,
        get_switch_tables,
        get_param_sinks,
    )
