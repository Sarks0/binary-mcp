# Vulnerability-Research Workflow Enhancements

Plan for two improvements that make binary-mcp more useful when triaging large
binaries (multi-MB DLLs, kernel drivers, browser engines) for vulnerability
research, where the user typically:

- Compares many candidate binaries quickly before committing time to one.
- Cares about a specific function or call site, not whole-program decompilation.
- Wants tools to degrade gracefully when no cache exists, not hard-fail.

Both items are deferred. Filed for future work.

## Context: today's gate

Most static-analysis tools key off the Ghidra cache produced by
`analyze_binary` (`src/engines/static/ghidra/project_cache.py`). The cache is
indexed by SHA-256 of the binary contents and persists function metadata,
disassembly, decompiled pseudocode, and string xrefs. Tools that depend on it:

- `decompile_function`, `list_functions`, `get_functions`
- `extract_iocs_with_context`, `search_pseudocode`
- `x64dbg_resolve_function`, `x64dbg_list_function_mappings`

When the cache is missing, those tools return a structured "No Ghidra analysis
cache found" message pointing at `ghidra_analyze`. The existing two-phase
workflow (`skip_decompile=True` + lazy `decompile_function`) already cuts the
big-binary cost dramatically, but two gaps remain.

## Item 1: shallow-analysis mode (`-noanalysis`)

### Problem

`skip_decompile=True` skips the decompiler but still runs Ghidra's full
auto-analyzer suite: `DataReferenceAnalyzer`, `StackVariableAnalyzer`,
`FunctionStackAnalyzer`, `DemanglerAnalyzer`, `EmbeddedMediaAnalyzer`,
`ScalarOperandAnalyzer`, etc. On a several-hundred-MB driver or browser engine
that's still minutes, not seconds.

For VR triage the user often wants to know in 30 seconds:
- Imports / exports
- Function table (entry points + sizes)
- String table
- Section layout

That's all available from a `-noanalysis` headless run plus Ghidra's
disassembler-only pass.

### Proposed change

Add a new `analysis_depth` parameter to `analyze_binary`:

| Value          | Auto-analyzers | Decompile | Typical cost (10 MB DLL) |
| -------------- | -------------- | --------- | ------------------------ |
| `full`         | all            | yes       | 15-30 min                |
| `structural`   | all            | no        | 1-3 min                  |
| `shallow`      | none           | no        | 15-45 sec                |

Map `shallow` to Ghidra's `-noanalysis` flag in the headless launcher
(`src/engines/static/ghidra/runner.py` or wherever the analyzeHeadless command
line is built). Update `core_analysis.py` to skip the per-function decompile
loop when `analysis_depth=shallow` and to mark the cache entries with a
`coverage="shallow"` tag so callers can detect a thin cache.

Existing `skip_decompile` should map to `analysis_depth="structural"` and stay
backward-compatible (deprecation note in the docstring; remove later).

### Files affected (rough)

- `src/server.py` - `analyze_binary` tool signature + dispatch
- `src/engines/static/ghidra/runner.py` (or equivalent) - command-line
  construction; add `-noanalysis`
- `src/engines/static/ghidra/scripts/core_analysis.py` - branch on env var
  `GHIDRA_ANALYSIS_DEPTH`, skip the analyzer-dependent extraction (xrefs,
  pseudocode, demangled names) for shallow mode
- `src/engines/static/ghidra/project_cache.py` - record coverage tag in
  `.meta.json`; add `is_shallow()` helper
- New tests around `tests/test_ghidra_analysis.py`

### Caveats

- Function boundaries from `-noanalysis` come from PE/ELF symbol tables and
  Ghidra's basic disassembler scan; they will be incomplete for stripped
  binaries. Document that shallow mode can miss functions reachable only via
  indirect calls or runtime resolution.
- Tools that require pseudocode (`search_pseudocode`, `decompile_function`,
  `extract_iocs_with_context` in its current form) must detect a shallow cache
  and either upgrade it on demand or return a clear "shallow cache; run
  analyze_binary(analysis_depth='structural') to upgrade" error.

## Item 2: graceful fallback in IOC and pseudocode-search tools

### Problem

`extract_iocs_with_context` and `search_pseudocode` hard-fail on cache miss.
For early triage the user often wants the strings/imports anyway, even without
the full call-graph context the tools normally surface.

### Proposed change

Add a `cache_required: bool = True` parameter (default-on, preserves current
behaviour) and a degraded path for `cache_required=False`:

**`extract_iocs_with_context`:**
- Fall back to `strings`-style extraction via `pefile` / `pyelftools`
- Use Capstone for a one-pass linear disassembly to find the *immediate caller*
  of each IOC reference (no full xref graph)
- Tag every result with `context_quality: "shallow" | "ghidra"` so callers can
  tell the difference

**`search_pseudocode`:**
- Without a cache, it can't search pseudocode. Either:
  - Return a clear error and suggest `search_strings` / `search_bytes`, or
  - Auto-redirect to `search_strings` when a string-only query is detected
    (no operators, single literal). Quieter UX but risks confusion.

Pick the explicit-error path - VR users want to know which tool is actually
running.

### Files affected (rough)

- `src/tools/static_analysis_tools.py` (or wherever
  `extract_iocs_with_context` lives) - add the `pefile + capstone` fallback
- `src/utils/ioc_extraction.py` (if separate) - factor the fallback as a
  reusable extractor
- `src/tools/static_analysis_tools.py` for `search_pseudocode` - emit explicit
  error referencing alternatives
- Tests covering both modes (cache present, cache missing + fallback)

### Caveats

- Linear disassembly without Ghidra's analyzers will miss switch tables,
  thunks, exception handlers. Document that `context_quality: "shallow"` may
  contain false-negative xrefs.
- Capstone fallback should be size-bounded (`max_disasm_bytes`) to keep the
  shallow mode actually fast on a giant binary.

## Suggested order

1. Item 1 first - it's the smaller change and unblocks the big-binary triage
   workflow that prompted this. Roughly half a day.
2. Item 2 second - bigger because the "context" extraction is what makes
   `extract_iocs_with_context` valuable in the first place. Roughly 1-1.5
   days including tests.

## Out of scope

- Streaming/incremental cache updates (would require restructuring the cache
  format).
- Cross-binary cache sharing (e.g. pre-warmed caches for common Windows DLLs).
  Worth doing eventually but needs a content-addressable distribution story.
- Function-targeted analyze (run Ghidra only on a specific function range).
  Ghidra headless doesn't support this cleanly; would need a custom Jython
  driver and a partial-cache merge strategy.
