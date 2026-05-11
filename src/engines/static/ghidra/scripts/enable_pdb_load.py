# ruff: noqa: F821
# Pre-script (Jython 2.7, Ghidra headless): allow PdbUniversalAnalyzer to
# load <binary>.pdb adjacent to the imported binary.
#
# Ghidra 10.x+ treats the binary's directory as an "untrusted symbol
# server" and the PdbUniversalAnalyzer's "Search untrusted symbol servers"
# option defaults to False -- so a perfectly-matched PDB sitting next to
# the binary is silently skipped. binary-mcp's load_pdb tool stages the
# PDB exactly there (via runner._stage_pdb), so we need to opt into that
# path before auto-analysis kicks in.
#
# Source of truth for the option name (verified against Ghidra master):
#   PdbAnalyzerCommon.java:
#     OPTION_NAME_SEARCH_UNTRUSTED_LOCATIONS = "Search untrusted symbol servers"
#   PdbUniversalAnalyzer.java:
#     NAME = "PDB Universal"
# Combined: option key is "PDB Universal.Search untrusted symbol servers".
#
# Run as a -preScript before the post-analysis core_analysis.py:
#     analyzeHeadless ... -preScript enable_pdb_load.py -postScript core_analysis.py


def _try_set(option_key, value):
    """Set an analyzer option both via setAnalysisOption (the documented
    GhidraScript helper) and via direct Options access. setAnalysisOption
    is the idiomatic API surface, but on older Ghidra builds the helper
    can be missing -- the direct path is the fallback."""
    ok = False
    str_value = "true" if value else "false"
    try:
        setAnalysisOption(currentProgram, option_key, str_value)
        ok = True
    except Exception as e:
        print("[binary-mcp] setAnalysisOption({!r}) failed: {}".format(option_key, e))
    try:
        options = currentProgram.getOptions("Analyzers")
        options.setBoolean(option_key, value)
        ok = True
    except Exception as e:
        print(
            "[binary-mcp] options.setBoolean({!r}) failed: {}".format(option_key, e)
        )
    if ok:
        print("[binary-mcp] Enabled {}".format(option_key))
    return ok


# Modern analyzer (PdbUniversalAnalyzer, Ghidra 10.x+).
# Verified option name: "PDB Universal.Search untrusted symbol servers".
set_any = _try_set("PDB Universal.Search untrusted symbol servers", True)

# Legacy analyzer (PdbAnalyzer) -- still shipped in some Ghidra builds
# alongside the universal one. PdbAnalyzerCommon constants apply, so the
# leaf name is identical; only the namespace prefix differs.
_try_set("PDB.Search untrusted symbol servers", True)

if not set_any:
    print(
        "[binary-mcp] WARNING: no PDB analyzer option could be set. "
        "PDB symbols will likely NOT load. Check that "
        "'PDB Universal' analyzer is present in this Ghidra version, "
        "or run with logging enabled to see the underlying error."
    )
