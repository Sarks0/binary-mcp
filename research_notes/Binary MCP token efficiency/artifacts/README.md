# Measurement artifacts

The scripts and outputs behind the token counts in the notes in this folder
and in `reports/Binary MCP token efficiency.md`. They were produced on
2026-10-19 in a throwaway cloud session and copied here so the citations keep
working.

- `scripts/` holds the measurement scripts. They still contain the original
  session's scratch paths, so adjust those before running one again.
- `out/` holds the raw `tools/list` capture (`run1_tools.json`; `run2_tools.json`
  is the byte-identical second run), the per-tool breakdown
  (`per_tool_tokens.csv`), the tool-result measurements
  (`results_summary.json`) and the what-if re-renderings (`whatif.json`).
- `out/results/` keeps only the individual tool results the notes cite.
  `results_summary.json` has the numbers for all 95 measured calls.
- `data/` holds the pseudocode, disassembly and listing compaction
  measurements.

Token counts use OpenAI's o200k and cl100k encodings as stand-ins, because
Claude's tokenizer is not public. Treat absolute counts as approximate and
compare percentages. Ghidra, ILSpy and the debuggers were not installed, so
decompile and listing outputs came from a synthetic analysis cache.

Paths that still point at the original scratch folder (the Ghidra stub, the
tokenizer files, the sample PE and the `uv sync` log) were not kept.
