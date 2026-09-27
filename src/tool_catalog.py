"""
Machine-readable catalog of every MCP tool this server registers.

Why this exists: integrators (e.g. a PreToolUse guard that gates "start
reading this binary in earnest" behind a kill sheet) need to know which
tools decompile, which only list structure, which launch Ghidra, and which
touch the network. Tool names don't encode that -- ``batch_decompile``,
``get_review_package`` and ``scan_pseudocode`` all hand back decompiled
code without ``decompile`` leading their name -- so a caller that guesses a
name list enforces nothing on the tools it missed.

Every registered tool gets exactly one **category** and zero or more
**facets**. Both are applied as FastMCP tags (``category:<name>`` plus the
bare facet names), so they appear on every ``tools/list`` entry under
``_meta._fastmcp.tags``. For consumers that can't call the server (a hook
script), the same data is exported as JSON::

    python -m src.tool_catalog            # manifest for the full roster
    docs/tool-catalog.json                # checked-in copy, kept in sync by tests

Gate on facets, not categories: ``code-output`` is the one to use for
"this call puts decompiled or disassembled code in front of the model".

Tests (tests/test_tool_catalog.py) fail when a registered tool is missing
from the catalog, when a catalog entry names a tool that no longer exists,
and when a tool's source reads pseudocode or launches an engine without
the matching facet. Adding a tool therefore means adding a line here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

CATALOG_VERSION = 1

CATEGORIES: dict[str, str] = {
    "decompile": (
        "Produces decompiled source, pseudocode or IL listings for specific "
        "functions/types. Reading the binary's code in earnest."
    ),
    "review": (
        "Per-function review bundles and pseudocode scans. Built on the "
        "decompiler output; most return excerpts of it."
    ),
    "analysis-run": (
        "Starts or extends an engine analysis of a whole binary (import, "
        "auto-analysis, PDB application)."
    ),
    "census": (
        "Structural listings from the analysis cache: functions, imports, "
        "strings, xrefs, call graph, sections, types. No code bodies."
    ),
    "detection": (
        "Heuristic detectors and metrics over the analysis cache (behaviour, "
        "crypto, anti-analysis, control flow, similarity, diffing)."
    ),
    "triage": (
        "File-level inspection that parses the file directly, without an "
        "analysis engine (PE headers, packers, signatures, carving, "
        "XOR/Base64, Python packers)."
    ),
    "annotation": "Reads or writes user annotations (renames, notes) on the analysis cache.",
    "coverage": "Per-binary review coverage ledger: denominator, worklist, marks.",
    "session": "Analysis-session bookkeeping: start, save, list, replay, delete.",
    "reporting": "Reports, IOC exports and YARA rule generation.",
    "jobs": "Background job control for long-running analysis calls.",
    "admin": "Setup diagnostics and cache maintenance.",
    "threat-intel": "External reputation / sandbox lookups (VirusTotal).",
    "debugger": "Live debugging via x64dbg or WinDbg against a running target or dump.",
}

FACETS: dict[str, str] = {
    "code-output": (
        "The response can contain decompiled code, pseudocode excerpts, C# "
        "source or IL/disassembly listings -- including replays of earlier "
        "tool output. Gate on this to keep code out of the model's context."
    ),
    "pseudocode-derived": (
        "Results are computed from Ghidra's decompiler output, so they "
        "inherit its artifacts (unaff_* values, collapsed variadic args) "
        "and are empty on a structural-only cache."
    ),
    "runs-engine": (
        "May launch Ghidra headless or ILSpy -- by design, or on a cache "
        "miss. Can take minutes on a large binary. A first import of a PE may "
        "also fetch its PDB from the symbol server (BINARY_MCP_AUTO_PDB)."
    ),
    "network": (
        "Always contacts an external service (VirusTotal, a symbol server). "
        "runs-engine tools can too, on a first import, per BINARY_MCP_AUTO_PDB."
    ),
}


@dataclass(frozen=True)
class ToolEntry:
    category: str
    facets: frozenset[str] = frozenset()

    def tags(self) -> set[str]:
        return {f"category:{self.category}", *self.facets}


def _e(category: str, *facets: str) -> ToolEntry:
    return ToolEntry(category, frozenset(facets))


CODE = "code-output"
PSEUDO = "pseudocode-derived"
ENGINE = "runs-engine"
NET = "network"

TOOL_CATALOG: dict[str, ToolEntry] = {
    # decompile
    "decompile_function": _e("decompile", CODE, ENGINE),
    "decompile_functions": _e("decompile", CODE, ENGINE),
    "batch_decompile": _e("decompile", CODE),
    "expand_callgraph": _e("decompile", ENGINE),
    "decompile_dotnet_type": _e("decompile", CODE, ENGINE),
    # Writes C# files to disk and returns their paths, not their contents.
    "decompile_dotnet_assembly": _e("decompile", ENGINE),
    "get_dotnet_il": _e("decompile", CODE, ENGINE),
    # review
    "get_review_package": _e("review", CODE, PSEUDO, ENGINE),
    "scan_pseudocode": _e("review", CODE, PSEUDO, ENGINE),
    "get_param_sinks": _e("review", CODE, PSEUDO, ENGINE),
    "get_function_callers": _e("review", ENGINE),
    "get_switch_tables": _e("review", ENGINE),
    # analysis-run
    "analyze_binary": _e("analysis-run", ENGINE),
    "load_pdb": _e("analysis-run", ENGINE, NET),
    "analyze_dotnet": _e("analysis-run", ENGINE),
    # census
    "get_functions": _e("census", ENGINE),
    "get_imports": _e("census", ENGINE),
    "get_strings": _e("census", ENGINE),
    "get_xrefs": _e("census", PSEUDO, ENGINE),
    "get_call_graph": _e("census", ENGINE),
    "find_api_calls": _e("census", ENGINE),
    "get_memory_map": _e("census", ENGINE),
    "extract_metadata": _e("census", ENGINE),
    "list_data_types": _e("census", ENGINE),
    "search_bytes": _e("census"),
    "find_vtables": _e("census"),
    "fid_match": _e("census"),
    "get_dotnet_types": _e("census", ENGINE),
    "search_dotnet_types": _e("census", ENGINE),
    # detection
    "detect_crypto": _e("detection", ENGINE),
    "generate_iocs": _e("detection", ENGINE),
    "analyze_control_flow": _e("detection", ENGINE),
    "detect_loops": _e("detection", ENGINE),
    "find_dead_code": _e("detection", ENGINE),
    "get_function_complexity": _e("detection", ENGINE),
    "find_ioctl_handlers": _e("detection", PSEUDO),
    "get_function_hash": _e("detection"),
    "find_similar_functions": _e("detection"),
    # Prints each cluster's representative pseudocode.
    "find_inlined_clones": _e("detection", CODE, PSEUDO),
    "analyze_function_completeness": _e("detection"),
    "diff_binaries": _e("detection", PSEUDO),
    "analyze_api_call_chains": _e("detection", ENGINE),
    "detect_dynamic_api_resolution": _e("detection", PSEUDO, ENGINE),
    "detect_malware_behaviors": _e("detection", ENGINE),
    "extract_iocs_with_context": _e("detection", ENGINE),
    "find_anti_analysis": _e("detection", PSEUDO, ENGINE),
    "find_stack_strings": _e("detection", PSEUDO, ENGINE),
    # triage
    "check_binary": _e("triage"),
    "quick_scan": _e("triage"),
    "detect_packers": _e("triage"),
    "extract_iocs": _e("triage"),
    "get_pe_info": _e("triage"),
    "inspect_authenticode": _e("triage"),
    "compute_similarity_hashes": _e("triage"),
    "extract_embedded_binaries": _e("triage"),
    "detect_crypto_patterns": _e("triage"),
    "analyze_xor_encryption": _e("triage"),
    "decrypt_xor": _e("triage"),
    "decode_base64_file": _e("triage"),
    "detect_python_packer": _e("triage"),
    "extract_python_packed": _e("triage"),
    "analyze_pyc_file": _e("triage"),
    "list_python_archive_contents": _e("triage"),
    # annotation
    "rename_function": _e("annotation", ENGINE),
    "add_note": _e("annotation", ENGINE),
    "get_notes": _e("annotation", ENGINE),
    "delete_note": _e("annotation", ENGINE),
    # coverage
    "coverage_index": _e("coverage"),
    "get_coverage_status": _e("coverage"),
    "get_next_unreviewed": _e("coverage"),
    "mark_function_reviewed": _e("coverage"),
    "mark_functions_examined": _e("coverage"),
    "reset_coverage": _e("coverage"),
    # session -- sessions log tool output verbatim, decompiles included, so
    # the two replay tools can hand back code.
    "start_analysis_session": _e("session"),
    "save_session": _e("session"),
    "list_sessions": _e("session"),
    "get_session_summary": _e("session"),
    "load_session_section": _e("session", CODE),
    "load_full_session": _e("session", CODE),
    "delete_session": _e("session"),
    "find_related_sessions": _e("session"),
    "configure_auto_session": _e("session"),
    "get_active_session": _e("session"),
    # reporting
    "generate_report": _e("reporting"),
    "export_iocs": _e("reporting"),
    "generate_yara_rule_from_session": _e("reporting"),
    "generate_yara_rule_from_strings": _e("reporting"),
    # jobs
    "job_status": _e("jobs"),
    "job_result": _e("jobs"),
    "job_list": _e("jobs"),
    "job_cancel": _e("jobs"),
    # admin
    "diagnose_setup": _e("admin"),
    "diagnose_dotnet_setup": _e("admin"),
    "clean_cache": _e("admin"),
    # threat-intel
    "vt_lookup": _e("threat-intel", NET),
    "vt_search": _e("threat-intel", NET),
    "vt_behavior": _e("threat-intel", NET),
    "vt_check_api": _e("threat-intel", NET),
}

# The ~190 debugger tools share one shape; listing each by hand would add
# nothing. Exact entries in TOOL_CATALOG win over these, which is how the
# disassembly tools below pick up ``code-output``.
PREFIX_RULES: dict[str, ToolEntry] = {
    "x64dbg_": _e("debugger"),
    "windbg_": _e("debugger"),
}

DEBUGGER_CODE_OUTPUT = ("x64dbg_disasm", "windbg_disassemble")
for _name in DEBUGGER_CODE_OUTPUT:
    TOOL_CATALOG[_name] = _e("debugger", CODE)


def classify(tool_name: str) -> ToolEntry | None:
    """Return the catalog entry for ``tool_name``, or None if unclassified."""
    entry = TOOL_CATALOG.get(tool_name)
    if entry is not None:
        return entry
    for prefix, rule in PREFIX_RULES.items():
        if tool_name.startswith(prefix):
            return rule
    return None


def apply_catalog(tools: dict) -> list[str]:
    """Tag every tool in ``tools`` (name -> FastMCP Tool) from the catalog.

    Returns the names that have no catalog entry. Those are tagged
    ``category:uncategorized`` rather than left bare, so a consumer that
    fails closed on unknown categories still blocks them.
    """
    missing = []
    for name, tool in tools.items():
        entry = classify(name)
        if entry is None:
            missing.append(name)
            tool.tags = set(tool.tags) | {"category:uncategorized"}
            continue
        tool.tags = set(tool.tags) | entry.tags()
    return sorted(missing)


def build_manifest(tool_names) -> dict:
    """JSON-ready manifest for ``tool_names`` (the live roster)."""
    tools = {}
    for name in sorted(tool_names):
        entry = classify(name)
        tools[name] = (
            {"category": "uncategorized", "facets": []}
            if entry is None
            else {"category": entry.category, "facets": sorted(entry.facets)}
        )
    by_facet = {
        facet: sorted(n for n, t in tools.items() if facet in t["facets"])
        for facet in FACETS
    }
    return {
        "catalog_version": CATALOG_VERSION,
        "categories": CATEGORIES,
        "facets": FACETS,
        "by_facet": by_facet,
        "tools": tools,
    }


def manifest_json(tool_names) -> str:
    return json.dumps(build_manifest(tool_names), indent=2, sort_keys=False) + "\n"


def _main() -> None:
    import asyncio

    from src.server import app, register_all_tools

    register_all_tools()
    tools = asyncio.run(app.get_tools())
    print(manifest_json(tools), end="")


if __name__ == "__main__":
    _main()
