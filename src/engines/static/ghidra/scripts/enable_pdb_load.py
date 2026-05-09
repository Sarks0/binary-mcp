# ruff: noqa: F821
# Pre-script (Jython 2.7, Ghidra headless): allow PdbUniversalAnalyzer to
# load <binary>.pdb adjacent to the imported binary.
#
# Ghidra 10.x+ treats the binary's directory as an "untrusted location" and
# the PdbUniversalAnalyzer's "Search untrusted locations" option defaults
# to False -- so a perfectly-matched PDB sitting next to the binary is
# silently skipped. binary-mcp's load_pdb tool stages the PDB exactly there
# (via runner._stage_pdb), so we need to opt into that path before
# auto-analysis kicks in.
#
# Run as a -preScript before the post-analysis core_analysis.py:
#     analyzeHeadless ... -preScript enable_pdb_load.py -postScript core_analysis.py

options = currentProgram.getOptions("Analyzers")

# PdbUniversalAnalyzer is the modern (Ghidra 10.x+) PDB loader. The option
# key is namespaced under the analyzer's display name. The exact name has
# been stable since 10.0; if a future Ghidra renames it, the try/except
# falls through and we log a clear message instead of failing analysis.
def _try_set(option_key, value):
    try:
        options.setBoolean(option_key, value)
        print("[binary-mcp] Enabled %s" % option_key)
        return True
    except Exception as e:
        print("[binary-mcp] Could not set %s: %s" % (option_key, e))
        return False

set_any = False
# Modern analyzer (PdbUniversalAnalyzer)
set_any |= _try_set("PDB Universal.Search untrusted locations", True)
# Legacy analyzer (PdbAnalyzer) -- some Ghidra builds still ship both.
# Setting both is safe; whichever analyzer ends up running picks it up.
_try_set("PDB.Search untrusted locations", True)

if not set_any:
    print(
        "[binary-mcp] WARNING: no PDB analyzer option could be set. "
        "PDB symbols will likely NOT load. Check that "
        "'PDB Universal' analyzer is present in this Ghidra version."
    )
