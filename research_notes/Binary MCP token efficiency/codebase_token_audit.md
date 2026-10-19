# binary-mcp codebase token audit: where the tokens go (measured)

Scope: the binary-mcp repo at /home/user/binary-mcp (HEAD f4595aa), FastMCP 2.14.7, mcp 1.30.0, Python 3.13. Token counts are tiktoken **o200k_base** unless a column says otherwise; cl100k_base, chars/4 and a legacy Anthropic tokenizer are given alongside. **Claude's current tokenizer is not public, so every token number here is a proxy for Claude.** There was no `ANTHROPIC_API_KEY` in the environment, so Anthropic's count_tokens endpoint could not be used. "Synthetic" marks outputs of Ghidra-backed tools measured against a synthetic analysis cache; treat those as estimates for real binaries.

Abbreviations used in links: `SP` = /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad (every link target below is the full absolute path).

## How was this measured? (method, environment, artifacts)

### Takeaway
I measured tools/list and tool results on the real wire format: an in-memory `fastmcp.Client(app)`, serialized exactly as the stdio transport does. Ghidra-backed tools ran against a synthetic cache written through the server's own `ProjectCache.save_cached`. Triage tools ran on three benign PE files. Nothing in `samples/` was executed, and the repo is unmodified apart from this notes file and `.venv`.

### Cited Findings
- The server cannot even be imported without a Ghidra install. `runner = GhidraRunner()` runs at import time and raises `FileNotFoundError` when GHIDRA_HOME is invalid and auto-detection fails — [src/server.py:120](/home/user/binary-mcp/src/server.py#L120), [src/engines/static/ghidra/runner.py:159](/home/user/binary-mcp/src/engines/static/ghidra/runner.py#L159), [runner.py:246](/home/user/binary-mcp/src/engines/static/ghidra/runner.py#L246). I used the same workaround the tests use: an empty `support/analyzeHeadless` stub — [tests/test_get_xrefs.py:67-74](/home/user/binary-mcp/tests/test_get_xrefs.py#L67) — at [SP/fake_ghidra/support/analyzeHeadless](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/fake_ghidra/support/analyzeHeadless). The stub is never executed.
- Tools are registered by `register_all_tools()`, not at import. That function also applies the catalog tags — [src/server.py:6314-6390](/home/user/binary-mcp/src/server.py#L6314).
- Wire serialization reproduces the MCP SDK path: `result.model_dump(by_alias=True, mode="json", exclude_none=True)` wrapped in a JSONRPCResponse, then `model_dump_json(by_alias=True, exclude_none=True)`. That is compact JSON with no spaces — [.venv mcp/shared/session.py:346](/home/user/binary-mcp/.venv/lib/python3.13/site-packages/mcp/shared/session.py#L346), [.venv mcp/server/stdio.py:79](/home/user/binary-mcp/.venv/lib/python3.13/site-packages/mcp/server/stdio.py#L79).
- Tokenizers. tiktoken 0.14.0 was installed into the scratchpad. Its normal download host, openaipublic.blob.core.windows.net, was **denied by the proxy (403)** and I did not retry it. The cl100k_base and o200k_base BPE files came instead from the PyPI `litellm` wheel, which bundles them as tiktoken cache files `9b5ad71b…` and `fb374d41…`. The same wheel bundles `anthropic_tokenizer.json`, the pre-Claude-3 tokenizer from the old Anthropic SDK, which I loaded with HF `tokenizers` as a "claude_legacy" column. **That legacy tokenizer is not the current Claude tokenizer.** Files: [SP/pylib_litellm/litellm/litellm_core_utils/tokenizers/](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/pylib_litellm/litellm/litellm_core_utils/tokenizers/).
- Test inputs: three benign PE files copied from local package caches into [SP/pe_samples/](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/pe_samples/):
  - `distlib_t64.exe`: PE32+ console, 108,032 B (distlib launcher)
  - `distlib_w32.exe`: PE32 GUI, 91,648 B
  - `clipboard_x86_64.exe`: PE32+, 331,438 B (clipboardy fallback)
  
  `samples/` contains only `test_malware.c`, which is source code, not a binary — [samples/](/home/user/binary-mcp/samples/).
- File-access setup:
  - `BINARY_MCP_ALLOWED_DIRS` was set to `SP/pe_samples:/home/user/binary-mcp/samples`. When it is unset, analysis is confined to default quarantine dirs — [src/utils/security.py:73-130](/home/user/binary-mcp/src/utils/security.py#L73), [security.py:349-445](/home/user/binary-mcp/src/utils/security.py#L349).
  - All state was redirected into SP via HOME, BINARY_CACHE_DIR, BINARY_MCP_SESSION_DIR and XDG_CACHE_HOME. BINARY_MCP_AUTO_PDB was set to `never`, mirroring [tests/conftest.py:39-45](/home/user/binary-mcp/tests/conftest.py#L39).
  - VT tools make no request without a key — [src/tools/vt_tools.py:45-71](/home/user/binary-mcp/src/tools/vt_tools.py#L45).
- Synthetic Ghidra cache. Field shapes are copied from [core_analysis.py:762-1070](/home/user/binary-mcp/src/engines/static/ghidra/scripts/core_analysis.py#L762). Profile:
  - 600 internal functions plus 60 externals
  - 180 imports across 8 DLLs, 1,200 strings, 7 memory blocks, 40 structs and 15 enums
  - Ghidra-style C pseudocode: 55% of bodies are 12-30 lines, 30% are 31-90, 12% are 91-200 and 3% are 201-500. Every third function carries unaff_/extraout_/in_stack_/variadic/GS artifacts.
  
  The cache is accepted without a Ghidra run because `metadata.analysis_depth="full"` — [src/server.py:642](/home/user/binary-mcp/src/server.py#L642), [server.py:650-697](/home/user/binary-mcp/src/server.py#L650).
- Artifacts (all full paths):
  - Scripts:
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/common.py
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/dump_tools_list.py
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/analyze_tools_list.py
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/synthetic_ctx.py
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/measure_results.py
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/measure_errors.py
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/whatif.py
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/measure_concise.py
  - tools/list wire dumps (run1 = default environment, run2 = altered environment):
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_tools.json
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_init.json
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run2_tools.json
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run2_init.json
  - tools/list analysis:
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis.json
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis_summary.txt
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/per_tool_tokens.csv (all 147 tools)
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/tool_signatures.txt
  - Tool results:
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results/ (raw text of every call)
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results_summary.json
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/measure_results.stdout
  - What-ifs, errors and environment log:
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/whatif.json
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/whatif.stdout
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/errors_summary.txt
    - /tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/uv_sync.log

### Inferences
- chars/4 is a good proxy for tools/list prose: 44,553 versus 43,373 o200k, within 3%. It badly **underestimates code- and hex-heavy results**, where text runs at 2.45-3.12 chars per o200k token:
  - decompile_functions(50): chars/4 gives 28,150, o200k gives 43,471 (−35%)
  - get_functions(100): chars/4 gives 5,069, o200k gives 7,017 (−28%)
  
  Source: [results_summary.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results_summary.json). Any budget the server sets in characters should assume about 2.6 chars/token for pseudocode.
- o200k and cl100k agree within about 2% everywhere. The legacy Anthropic tokenizer runs +7% on tools/list (46,514), −8% to +11% on results.

### Gaps
- Exact Claude token counts were not possible: no API key, and the current tokenizer is unpublished.
- Ghidra (Java 21 is present, Ghidra is not) and ILSpy were unavailable, as were x64dbg and WinDbg (Linux host). Real decompile and listing outputs, .NET decompiles and debugger outputs are therefore estimates from synthetic data or from code.

## Tool-definition footprint (tools/list)

### Takeaway
The full tools/list is **147 tools, 178,213 bytes, about 43.4K o200k tokens**, with no server `instructions`. Descriptions (raw docstrings) are 62% of it. Input schemas are 19%, auto-generated output schemas 10% and `_meta` tags 6%. The 49 debugger tools (x64dbg plus WinDbg) are 32%, and they are registered on every platform regardless of availability.

### Cited Findings
- **Totals**: wire tools/list response = 178,213 bytes. Tokens: 43,373 o200k / 42,489 cl100k / 44,553 chars/4 / 46,514 legacy-Claude. No `nextCursor`, so there is no pagination. The tools array alone is 43,357 o200k — [run1_analysis_summary.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis_summary.txt).
- **Server instructions: none.** `app = FastMCP("binary-mcp")` sets no instructions and no version — [src/server.py:119](/home/user/binary-mcp/src/server.py#L119). The initialize result is 376 bytes / 110 o200k, and `serverInfo.version` is FastMCP's own "2.14.7" — [run1_init.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_init.json).
- **Model-facing projection.** Keeping only `name`, `description` and `input_schema` (the Anthropic tool-definition fields) gives 151,824 bytes / **36,452 o200k** (84% of the wire tokens). Name plus input_schema alone is 37,834 bytes / 9,345 o200k — [run1_analysis.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis.json).
- **Per-component split** (each `"key":value` fragment of every tool, summed). Every tool carries exactly these five keys; there is no `title`, `annotations` or `icons` — [run1_analysis_summary.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis_summary.txt).

  | Component | Bytes | o200k | cl100k | Share of 43,357 |
  |---|---:|---:|---:|---:|
  | description | 113,843 | 27,100 | 26,989 | 62.5% |
  | inputSchema | 33,308 | 8,365 | 7,904 | 19.3% |
  | outputSchema | 17,725 | 4,377 | 4,240 | 10.1% |
  | `_meta` (`_fastmcp.tags`) | 8,473 | 2,518 | 2,514 | 5.8% |
  | name | 3,790 | 978 | 968 | 2.3% |

- **How each part is produced (FastMCP 2.14.7):**
  - description = `inspect.getdoc(fn)`, i.e. the whole Google-style docstring, Args/Returns included — [.venv fastmcp/tools/tool.py:477](/home/user/binary-mcp/.venv/lib/python3.13/site-packages/fastmcp/tools/tool.py#L477), [tool.py:578](/home/user/binary-mcp/.venv/lib/python3.13/site-packages/fastmcp/tools/tool.py#L578)
  - input schema = `compress_schema(..., prune_titles=True, dereference=True)`, so titles are already stripped — [tool.py:499-504](/home/user/binary-mcp/.venv/lib/python3.13/site-packages/fastmcp/tools/tool.py#L499)
  - `_meta._fastmcp.tags` = `sorted(self.tags)`, enabled by default (`include_fastmcp_meta = True`) — [.venv fastmcp/utilities/components.py:91](/home/user/binary-mcp/.venv/lib/python3.13/site-packages/fastmcp/utilities/components.py#L91), [.venv fastmcp/settings.py:355-367](/home/user/binary-mcp/.venv/lib/python3.13/site-packages/fastmcp/settings.py#L355)
  - tags come from the catalog (`category:<x>` plus facets) — [src/tool_catalog.py:101-102](/home/user/binary-mcp/src/tool_catalog.py#L101), [tool_catalog.py:255-270](/home/user/binary-mcp/src/tool_catalog.py#L255)
- **Description length distribution** (raw text, o200k):
  - median 112, mean 169.7, max 1,275 (analyze_binary), min 9 (windbg_pause)
  - 2 tools over 1,000, 7 over 500, 60 under 100
  - Source: [run1_analysis.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis.json)
- **25 heaviest tools** (o200k, whole tool object). Together they total 17,875 tokens, **41% of the list** (17% of the tools) — [run1_analysis_summary.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis_summary.txt):

  | # | Tool | Category | Total | Desc | Input | Out | Meta |
  |---:|---|---|---:|---:|---:|---:|---:|
  | 1 | analyze_binary | analysis-run | 1,643 | 1,333 | 253 | 31 | 19 |
  | 2 | windbg_execute_command | debugger | 1,396 | 1,319 | 22 | 31 | 16 |
  | 3 | diff_binaries | detection | 1,059 | 892 | 109 | 31 | 20 |
  | 4 | x64dbg_breakpoint | debugger | 1,032 | 622 | 354 | 31 | 16 |
  | 5 | load_pdb | analysis-run | 980 | 816 | 105 | 31 | 21 |
  | 6 | x64dbg_trace | debugger | 820 | 382 | 383 | 31 | 16 |
  | 7 | get_coverage_status | coverage | 803 | 715 | 51 | 13 | 15 |
  | 8 | mark_functions_examined | coverage | 788 | 647 | 104 | 13 | 15 |
  | 9 | x64dbg_memory | debugger | 732 | 379 | 298 | 31 | 16 |
  | 10 | scan_pseudocode | review | 615 | 393 | 157 | 31 | 26 |
  | 11 | x64dbg_symbols | debugger | 607 | 323 | 229 | 31 | 16 |
  | 12 | decompile_function | decompile | 593 | 487 | 46 | 31 | 22 |
  | 13 | x64dbg_execution | debugger | 592 | 397 | 140 | 31 | 16 |
  | 14 | reset_coverage | coverage | 579 | 455 | 88 | 13 | 15 |
  | 15 | x64dbg_session | debugger | 572 | 277 | 240 | 31 | 16 |
  | 16 | get_next_unreviewed | coverage | 556 | 432 | 86 | 13 | 15 |
  | 17 | get_xrefs | census | 551 | 392 | 98 | 31 | 23 |
  | 18 | x64dbg_annotate | debugger | 533 | 282 | 194 | 31 | 16 |
  | 19 | decompile_functions | decompile | 519 | 379 | 80 | 31 | 22 |
  | 20 | expand_callgraph | decompile | 502 | 363 | 82 | 31 | 19 |
  | 21 | find_inlined_clones | detection | 493 | 380 | 50 | 31 | 23 |
  | 22 | find_stack_strings | detection | 491 | 381 | 48 | 31 | 23 |
  | 23 | extract_embedded_binaries | triage | 491 | 378 | 57 | 31 | 16 |
  | 24 | x64dbg_types | debugger | 476 | 263 | 158 | 31 | 16 |
  | 25 | x64dbg_state | debugger | 452 | 151 | 246 | 31 | 16 |

- **Totals by catalog category** (o200k, sum of individually tokenized tools = 43,502) — [run1_analysis_summary.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis_summary.txt):

  | Category | Tools | o200k | Bytes | Description o200k | Input o200k |
  |---|---:|---:|---:|---:|---:|
  | debugger | 49 | 14,049 | 56,270 | 7,577 | 3,752 |
  | detection | 18 | 5,653 | 24,046 | 3,910 | 701 |
  | triage | 16 | 3,944 | 15,695 | 2,524 | 544 |
  | coverage | 6 | 3,353 | 13,979 | 2,676 | 457 |
  | census | 14 | 3,233 | 13,211 | 1,712 | 744 |
  | analysis-run | 3 | 2,819 | 11,739 | 2,251 | 394 |
  | decompile | 7 | 2,461 | 10,205 | 1,687 | 357 |
  | session | 10 | 1,782 | 7,479 | 866 | 383 |
  | review | 5 | 1,649 | 6,910 | 1,006 | 336 |
  | reporting | 4 | 1,275 | 5,370 | 855 | 199 |
  | annotation | 4 | 1,048 | 4,292 | 612 | 216 |
  | jobs | 4 | 1,024 | 3,983 | 770 | 113 |
  | threat-intel | 4 | 695 | 2,702 | 367 | 99 |
  | admin | 3 | 517 | 2,140 | 287 | 70 |

  - Facets: runs-engine 41 tools / 12,969 tokens; pseudocode-derived 10 / 4,664; code-output 13 / 4,307; network 5 / 1,675.
  - Tool families: the .NET tools (7) are 1,306 tokens, VT (4) 695, Python-packer (4) 892 — [per_tool_tokens.csv](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/per_tool_tokens.csv).
- **Debugger tools: 49 (33 `windbg_*` = 6,225 tokens; 16 `x64dbg_*` = 7,824 tokens), all registered unconditionally.**
  - `register_dynamic_tools` and `register_windbg_tools` are called with no platform or availability check — [src/server.py:6327-6330](/home/user/binary-mcp/src/server.py#L6327).
  - WinDbg tools check `_is_windows()` inside each tool body (34 call sites) and return `_PLATFORM_MSG` ("WinDbg tools require Windows with Pybag installed…") at call time — [src/tools/windbg_tools.py:41-44](/home/user/binary-mcp/src/tools/windbg_tools.py#L41), [windbg_tools.py:108-109](/home/user/binary-mcp/src/tools/windbg_tools.py#L108), [windbg_tools.py:199-221](/home/user/binary-mcp/src/tools/windbg_tools.py#L199). On this Linux host, `windbg_status` returned that 22-token message — [results/windbg_status__linux.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results/windbg_status__linux.txt).
  - x64dbg is already consolidated: 16 `op`-dispatch tools front **159 operations**. Their descriptions are `_GROUP_DOCS[group] + build_op_catalog(ops[group])` — [src/tools/dynamic_tools.py:10314-10316](/home/user/binary-mcp/src/tools/dynamic_tools.py#L10314) — and the split is pinned by `test_surface_is_16_tools_not_159` — [tests/test_x64dbg_tool_groups.py:76](/home/user/binary-mcp/tests/test_x64dbg_tool_groups.py#L76). `op` is a bare `string` with no `enum`; valid ops are listed only in the description — [run1_tools.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_tools.json).
  - WinDbg (33 tools) is not consolidated.
  - Other engines are also registered regardless of availability. .NET tools return "ILSpyCmd not installed" at call time — [src/tools/dotnet_tools.py:59](/home/user/binary-mcp/src/tools/dotnet_tools.py#L59), [dotnet_tools.py:193](/home/user/binary-mcp/src/tools/dotnet_tools.py#L193). VT tools return "API key not configured" — [vt_tools.py:63-71](/home/user/binary-mcp/src/tools/vt_tools.py#L63).
- **`windbg_execute_command` is disabled by default but always listed**, at 1,396 tokens (3.2% of the list). Its own refusal text says it is "disabled by default" unless `BINARY_MCP_ENABLE_RAW_WINDBG=1` — [results/windbg_execute_command__linux-disabled.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results/windbg_execute_command__linux-disabled.txt). The description is mostly an internal security-model essay ("SECURITY MODEL -- audit finding F-6, second remediation pass", the internal allowlist module path, a long refused-command inventory) — [run1_tools.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_tools.json).
- **Duplication and placement of parameter docs:**
  - 439 schema properties, **0 with a `description`**. 114 tools carry a docstring `Args:` section and have zero schema descriptions, so parameter docs live only in the description text. The reverse (schema duplicating the docstring) never occurs.
  - 17 tools have parameters but no `Args:`; 16 tools take no parameters.
  - Section costs (raw text, o200k):

    | Section | Tools | o200k | Chars |
    |---|---:|---:|---:|
    | Args | 114 | 7,601 | 31,856 |
    | Returns | 112 | 2,949 | 13,172 |
    | Examples | 41 | 1,002 | |
    | Notes | 4 | 278 | |

  - 53 parenthetical "(default …)" restatements (365 tokens) repeat what the schema `default` already says.
  - 50 descriptions use RST double-backticks.
  - Source: [run1_analysis.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis.json)
- **What-if description trims** (whole tools array, o200k; savings exceed raw section tokens because JSON-escaped `\n` and indentation cost extra), from [run1_analysis.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis.json):

  | Trim | Tokens saved | Share of list |
  |---|---:|---:|
  | Strip `Args:` | 8,113 | 18.7% |
  | Strip `Returns:` | 3,189 | 7.4% |
  | Strip both | 11,333 | 26.1% |
  | Strip Args + Returns + Examples + Notes | 12,866 | 29.7% |
  | Keep first paragraph only | 25,160 | 58.0% |

- **Prose provenance.** Several descriptions narrate audit and implementation history rather than usage: 3 mention "audit", 4 cite F-NN finding IDs, 5 say "used to / previously". The CONTRIBUTING template mandates Google-style docstrings with `Args:`/`Returns:` — [CONTRIBUTING.md:144](/home/user/binary-mcp/CONTRIBUTING.md#L144), [CONTRIBUTING.md:226-250](/home/user/binary-mcp/CONTRIBUTING.md#L226). Marker counts: [run1_analysis.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis.json).
- **JSON Schema bloat (input schemas).** Counts:
  - 299 `default` keys, of which 179 are `default: null`
  - 179 `anyOf`, every one a `[X, {"type":"null"}]` Optional
  - 11 `items`, 1 `additionalProperties`, 0 `title` (FastMCP prunes them)
  
  Savings against the 7,780 o200k of bare input schemas, from [run1_analysis.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis.json):

  | Transform | Tokens saved | Share of schemas | Share of list |
  |---|---:|---:|---:|
  | Collapse anyOf-null to X | 1,450 | 18.6% | |
  | Drop `default: null` | 537 | | |
  | Both | **2,165** | 27.8% | 5.0% |
  | Drop all defaults | 998 | | |
  | Drop additionalProperties | 5 | | |

  Example: `x64dbg_breakpoint` has 17 nullable parameters, each `{"anyOf":[{"type":"string"},{"type":"null"}],"default":null}` — [run1_tools.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_tools.json).
- **Removal what-ifs** (whole list): removing every `outputSchema` saves 4,240 o200k (9.8%); removing `_meta` saves 2,528 (5.8%) — [run1_analysis.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis.json).
- A stale comment in the catalog still says "The ~190 debugger tools"; there are 49 — [src/tool_catalog.py:231](/home/user/binary-mcp/src/tool_catalog.py#L231).

### Inferences
- The single biggest lever is description content: about 27K tokens, of which roughly 12.9K is docstring sections. The next is the always-on debugger surface: about 14K tokens, or 6.2K for WinDbg alone on non-Windows hosts. These two overlap, because debugger descriptions also contain docstring sections, so their savings are not additive.
- Moving `Args:` text into `Field(description=...)` would not save tokens by itself; the text just moves. Savings come from rewriting it tersely and deleting the restated defaults, history and security essays.
- Gating `windbg_*` on `platform.system()=="Windows"` at registration, and `windbg_execute_command` on its env flag, would make tools/list differ per host. It stays stable within one deployment, so prompt caching across sessions on the same host is unaffected (see the next section).

### Gaps
- Which fields each client actually forwards to the model (outputSchema? `_meta`?) was not tested here. The 36.5K "projection" figure assumes only name, description and inputSchema reach the model.
- The fixed tool-use system-prompt overhead that Anthropic adds per request is outside this codebase and was not measured.

## Is tools/list deterministic and static (prompt-cache safe)?

### Takeaway
Yes, within a given FastMCP version and code revision. Two processes with different hash seeds and very different environment variables produced **byte-identical** tools/list (sha256 prefix 907bb6244fbd3c3d) and initialize responses. No description or default is computed from the environment.

### Cited Findings
- Run 1 used default settings. Run 2 changed `PYTHONHASHSEED=12345`, `GHIDRA_HOME`, `GHIDRA_TIMEOUT=999`, `X64DBG_PORT=9999`, `X64DBG_HOST=127.0.0.2`, `BINARY_CACHE_DIR`, `HOME`, `VT_API_KEY`, `GHIDRA_MAX_HEAP_MB=8192` and `BINARY_MCP_ALLOWED_DIRS`. `cmp` found the tools and init dumps identical — [run1_tools.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_tools.json), [run2_tools.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run2_tools.json), [dump_tools_list.py](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/dump_tools_list.py).
- Tag order cannot vary with hash randomization: FastMCP emits `sorted(self.tags)` — [.venv fastmcp/utilities/components.py:91](/home/user/binary-mcp/.venv/lib/python3.13/site-packages/fastmcp/utilities/components.py#L91).
- No server `instructions` exist to drift — [src/server.py:119](/home/user/binary-mcp/src/server.py#L119).
- Strings that look environment-specific are static docstring examples:
  - `generate_yara_rule_from_strings("/tmp/samples/malware.exe")`
  - "compiled 2024-01-15" in `analyze_pyc_file`
  - 8 descriptions name env vars as text
  
  Source: [run1_tools.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_tools.json).
- x64dbg descriptions are generated at registration by `build_op_catalog`, but only from the static op table — [src/tools/dynamic_tools.py:10314-10316](/home/user/binary-mcp/src/tools/dynamic_tools.py#L10314).
- Registration has no platform branches; `_is_windows()` is evaluated only inside tool bodies — [src/tools/windbg_tools.py:108-109](/home/user/binary-mcp/src/tools/windbg_tools.py#L108), [src/server.py:6314-6390](/home/user/binary-mcp/src/server.py#L6314).
- `serverInfo.version` is FastMCP's version (2.14.7) because the app sets none — [run1_init.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_init.json).

### Inferences
- tools/list should be identical on Windows too, because nothing at registration is platform-conditional. It will change whenever any docstring, the FastMCP version (schema generation, `x-fastmcp-wrap-result`, `_meta` format) or the tool catalog changes. That is per-release churn, not per-session churn.
- Dynamic or random content does appear in **results**, which does not affect caching of the tool prefix:
  - a random 8-hex "Reference ID" in every error — [src/tools/error_hygiene.py:98-102](/home/user/binary-mcp/src/tools/error_hygiene.py#L98), [src/utils/security.py:1140](/home/user/binary-mcp/src/utils/security.py#L1140)
  - absolute host paths, e.g. `find_stack_strings` prints `Binary: <full path>` — [src/utils/stack_strings.py:594](/home/user/binary-mcp/src/utils/stack_strings.py#L594)
  - `diagnose_setup` output
  - timestamps in coverage JSON

### Gaps
- I did not run on Windows or under a different FastMCP release to confirm byte-equality there.

## Structured output: outputSchema and content/structuredContent duplication

### Takeaway
All 147 tools ship an auto-generated outputSchema: 137 are the `{"result": string}` wrapper and 10 are untyped objects. Every successful call returns the text twice, once in `content[0].text` and again in `structuredContent`. On the wire, results are therefore about **2.16× the size of the text alone**.

### Cited Findings
- FastMCP wraps non-object return types: `output_schema["x-fastmcp-wrap-result"] = True` — [.venv fastmcp/tools/tool.py:554-559](/home/user/binary-mcp/.venv/lib/python3.13/site-packages/fastmcp/tools/tool.py#L554). It then returns `ToolResult(content=..., structured_content={"result": result})` — [tool.py:412-416](/home/user/binary-mcp/.venv/lib/python3.13/site-packages/fastmcp/tools/tool.py#L412). Per-tool opt-out is `output_schema=None` on `@app.tool(...)` — [.venv fastmcp/server/server.py:1927](/home/user/binary-mcp/.venv/lib/python3.13/site-packages/fastmcp/server/server.py#L1927).
- Shapes in tools/list:
  - 137 × `{"properties":{"result":{"type":"string"}},"required":["result"],"type":"object","x-fastmcp-wrap-result":true}`, about 31 tokens per tool
  - 10 × `{"additionalProperties":true,"type":"object"}`, about 13 tokens per tool: the six coverage tools plus `job_status`, `job_result`, `job_list` and `job_cancel`
  
  Source: [run1_analysis.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis.json).
- Measured raw CallToolResults: 86 in-memory calls.
  - In 80, `structuredContent == {"result": <same text>}`.
  - The dict-returning tools (coverage, jobs) put compact JSON of the dict in `content` and the dict itself in `structuredContent`, which is also a duplicate.
  - Totals across all 86: text 235,557 o200k, structuredContent 253,216, full wire 508,975.
  - Example: `get_functions(limit=100)` has 7,017 tokens of text but 15,285 wire tokens (42,106 bytes).
  
  Sources: [results_summary.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results_summary.json), [measure_results.py](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/measure_results.py).
- Errors are returned as ordinary text with `isError: false` (path denials, missing files, unknown functions, bad session IDs). In my run, only FastMCP's own "Unknown tool" came back with `isError: true` — [results_summary.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results_summary.json).
- Dict tools serialize compact JSON (no indentation) but embed long prose fields. Example: `coverage_index`'s `scope_description` (several sentences, ending in "WARNING: 60 of 660 function(s)…") at 430 tokens total — [results/coverage_index__synthetic.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results/coverage_index__synthetic.txt).

### Inferences
- If a client forwards both `content` and `structuredContent` to the model, every result costs about twice its text. If it forwards only one, the duplicate costs bandwidth and logging but no context. Either way, the `{"result": string}` schema adds no information over the text, so `output_schema=None` on the 137 str tools would cut about 4.2K list tokens and halve result wire size (estimate).

### Gaps
- Client behaviour (which of content or structuredContent the model sees) is outside this codebase and was not verified.

## Tool-result footprint (limits, formats, boilerplate, concise modes)

### Takeaway
Results are Markdown prose or lists. The listing tools cost about **70 tokens per function**, **36-40 per string** and **15.5 per import**. A `decompile_functions` call defaults to a 120,000-character budget (≈46K o200k, estimated). Every untrusted body is wrapped in a ≈140-token envelope, and some tools repeat it per item. Several tools have no cap at all. Concise modes exist only for `scan_pseudocode` (`mode="summary"`), `decompile_functions` (`include_bodies`, `max_body_chars`), `get_pe_info` (`detail_level`) and `analyze_binary` (`analysis_depth`).

### Cited Findings
- **Measured outputs, real benign PEs** (text o200k; "t64" = 108 KB, "rust" = 331 KB). Source: [measure_results.stdout](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/measure_results.stdout).

  | Tool | o200k | Envelope tokens |
  |---|---:|---:|
  | get_pe_info, standard (t64 / rust) | 1,632 / 1,977 | 296 |
  | get_pe_info, full (t64 / rust) | 2,091 / 3,400 | 449 |
  | quick_scan (t64 / rust) | 545 / 653 | |
  | extract_iocs (t64 / rust) | 344 / 476 | |
  | check_binary | 297 | 140 |
  | detect_packers | 46 | |
  | inspect_authenticode | 166 | |
  | compute_similarity_hashes | 735 | |
  | detect_crypto_patterns | 289 | |
  | analyze_xor_encryption | 428 | |
  | detect_python_packer | 206 | |
  | search_bytes("48 8B"), default max_results=50 | 1,578 | |
  | find_vtables | 78 | |
  | extract_embedded_binaries (rust) | 391 | |
  | generate_yara_rule_from_strings | 1,076 | |
  | diagnose_setup (includes host paths) | 615 | |
  | diagnose_dotnet_setup | 127 | |

- **Measured outputs, synthetic Ghidra cache (estimates for real binaries).** Source: [measure_results.stdout](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/measure_results.stdout).

  | Tool and call | o200k | Notes |
  |---|---:|---|
  | get_functions (default limit=100) | 7,017 | |
  | get_functions (limit=600) | 42,084 | |
  | get_strings (default limit=100) | 3,998 | |
  | get_strings (limit=1000) | 36,370 | |
  | get_imports (all 180; **no limit parameter**) | 2,928 | |
  | get_memory_map | 391 | |
  | extract_metadata | 274 | |
  | find_api_calls (no limit) | 1,272 | |
  | detect_crypto | 238 | |
  | generate_iocs | 306 | |
  | get_xrefs | 251 | |
  | get_call_graph, depth=2 / depth=4 | 486 / 1,895 | |
  | decompile_function: ≤25 lines | 364 | |
  | decompile_function: 80 lines | 1,270 | |
  | decompile_function: 80 lines with 4 artifact kinds | 1,530 | 64 inline-caveat + 180 caveat-summary tokens |
  | decompile_function: 300 lines | 4,688 | |
  | decompile_functions, 10 functions | 11,133 | |
  | decompile_functions, 50 functions | 43,471 | 112,599 chars, just under the budget |
  | batch_decompile, 10 functions | 12,353 | 10 envelopes = 1,450 tokens |
  | get_review_package: 80 lines with artifacts | 2,232 | 3 envelopes = 431 |
  | get_review_package: 300 lines | 5,528 | |
  | scan_pseudocode (default) | 6,133 | |
  | diff_binaries | 5,037 | |
  | find_stack_strings | 15,740 | 903 XOR-loop candidates |
  | analyze_control_flow (300-line function) | 2,567 | |
  | get_next_unreviewed (count=20) | 1,081 | |
  | coverage_index | 430 | |
  | detect_malware_behaviors | 994 | |
  | find_anti_analysis | 812 | |

  The marginal cost of synthetic pseudocode is about 15.5 tokens per line (300-line versus 80-line function).
- **Existing limits and defaults:**
  - get_functions limit=100 — [src/server.py:2423](/home/user/binary-mcp/src/server.py#L2423)
  - get_strings limit=100, values truncated at 100 chars, at most 5 xref lines per string — [server.py:2552](/home/user/binary-mcp/src/server.py#L2552), [server.py:2595-2604](/home/user/binary-mcp/src/server.py#L2595); the cache itself keeps values up to 1,000 chars and 50 xrefs — [core_analysis.py:901-905](/home/user/binary-mcp/src/engines/static/ghidra/scripts/core_analysis.py#L901)
  - get_xrefs limit=200 — [server.py:2746](/home/user/binary-mcp/src/server.py#L2746)
  - decompile_functions `max_body_chars=120000`, allowed range 1,000 to 1,000,000, with withheld bodies named in a footer — [server.py:3337](/home/user/binary-mcp/src/server.py#L3337), [server.py:3381-3382](/home/user/binary-mcp/src/server.py#L3381), [server.py:3495](/home/user/binary-mcp/src/server.py#L3495)
  - expand_callgraph `max_functions=100`
  - scan_pseudocode limit=50, offset, mode findings/summary — [src/tools/review_tools.py:469-514](/home/user/binary-mcp/src/tools/review_tools.py#L469)
  - get_switch_tables limit=200; fid_match limit=100; get_function_callers limit=100; diff_binaries top_n=40, list_limit=20; get_next_unreviewed count=20; list_sessions limit=20 — [tool_signatures.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/tool_signatures.txt)
  - .NET: get_dotnet_types limit=100, search_dotnet_types limit=50, get_dotnet_il truncated at 50,000 chars — [src/tools/dotnet_tools.py:177](/home/user/binary-mcp/src/tools/dotnet_tools.py#L177), [dotnet_tools.py:320](/home/user/binary-mcp/src/tools/dotnet_tools.py#L320), [dotnet_tools.py:503-509](/home/user/binary-mcp/src/tools/dotnet_tools.py#L503)
  - VirusTotal: names[:5], detections[:20] (15 shown), behaviour lists [:10] each, vt_search limit=10 — [src/tools/vt_tools.py:262-263](/home/user/binary-mcp/src/tools/vt_tools.py#L262), [vt_tools.py:384](/home/user/binary-mcp/src/tools/vt_tools.py#L384), [vt_tools.py:459-526](/home/user/binary-mcp/src/tools/vt_tools.py#L459)
  - Debuggers: x64dbg read_memory 256 B, disassemble 20 instructions, get_trace 100 entries — [src/tools/dynamic_tools.py:1845](/home/user/binary-mcp/src/tools/dynamic_tools.py#L1845), [dynamic_tools.py:1893](/home/user/binary-mcp/src/tools/dynamic_tools.py#L1893), [dynamic_tools.py:2249](/home/user/binary-mcp/src/tools/dynamic_tools.py#L2249); WinDbg read_memory 64 B (max 4096), disassemble 10, get_stack 32 frames — [src/tools/windbg_tools.py:953-958](/home/user/binary-mcp/src/tools/windbg_tools.py#L953), [windbg_tools.py:1014](/home/user/binary-mcp/src/tools/windbg_tools.py#L1014), [windbg_tools.py:563](/home/user/binary-mcp/src/tools/windbg_tools.py#L563)
- **No limit or pagination at all:**
  - get_imports, get_memory_map, find_api_calls, detect_crypto, generate_iocs — [tool_signatures.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/tool_signatures.txt)
  - batch_decompile (comma-separated list, no budget) — [src/tools/function_hash_tools.py:619-698](/home/user/binary-mcp/src/tools/function_hash_tools.py#L619)
  - find_stack_strings: every XOR candidate is listed without cap or dedupe, and the recovered-strings table is uncapped; IOC matches are capped at 20 per type — [src/utils/stack_strings.py:607-633](/home/user/binary-mcp/src/utils/stack_strings.py#L607). `ioc_only=True` did not shrink the output (15,749 tokens) — [results/find_stack_strings__ioc_only.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results/find_stack_strings__ioc_only.txt)
  - load_full_session / load_session_section (see the session replay finding below)
- **Output formats:**
  - get_functions renders **6 Markdown lines per function**: name, Address, a Signature that repeats the name, and counts of Parameters, Local Variables and Calls — [results/get_functions__synthetic-default100.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results/get_functions__synthetic-default100.txt)
  - get_strings: a bold `**[addr]**` line plus one line per xref — [results/get_strings__synthetic-default100.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results/get_strings__synthetic-default100.txt)
  - decompile_function: `**Decompiled: name**`, Address, a `Signature:` line that duplicates the first line of the C body (24 tokens), a fenced block, then the caveat summary — [results/decompile_function__synthetic-80lines-artifacts.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results/decompile_function__synthetic-80lines-artifacts.txt)
  - scan_pseudocode findings: 4 lines each, about 119 tokens per finding, with the rule description and the "->" remediation repeated for every finding of the same rule — [results/scan_pseudocode__synthetic-default.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results/scan_pseudocode__synthetic-default.txt)
  - The memory hexdump is offset + hex + ASCII per 16 bytes — [src/tools/dynamic_tools.py:1866-1873](/home/user/binary-mcp/src/tools/dynamic_tools.py#L1866). Simulated for 256 B, it is 927 tokens including the envelope, versus 299 as plain hex or 240 as base64 (estimate) — [whatif.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/whatif.json)
- **`wrap_untrusted` envelope** = a sentinel-bracketed header line, a fixed 523-char notice ("ATTACKER-CONTROLLED content … cannot close itself early."), the body and a terminator line — [src/utils/formatters.py:152-161](/home/user/binary-mcp/src/utils/formatters.py#L152), [formatters.py:229-268](/home/user/binary-mcp/src/utils/formatters.py#L229).
  - Measured overhead: **140 tokens** ("function list" / "extracted strings"), **145** ("decompiled pseudocode from the sample"). The notice alone is 109 tokens; the `⟦⟧` pair is 6 tokens.
  - A minimal 2-line envelope (`⟦untrusted:function list⟧ … ⟦/untrusted⟧`) would cost 21 — [whatif.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/whatif.json).
  - Across the 86 calls: 69 envelopes = 9,898 tokens (4.2% of all result text). They dominate small results: analyze_binary on a warm cache 139 of 266 tokens, get_xrefs 140 of 251, check_binary 140 of 297 — [results_summary.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results_summary.json).
  - 92 source lines in src/server.py and src/tools/*.py contain `wrap_untrusted(` (`grep -c`, which may include a few comment mentions): 37 in server.py, 14 in dynamic_tools.py, 7 in review_tools.py, 6 in dotnet_tools.py, 5 in function_hash_tools.py, the rest 1-4 each. batch_decompile wraps **each function separately** — [src/tools/function_hash_tools.py:698](/home/user/binary-mcp/src/tools/function_hash_tools.py#L698).
- **Decompiler caveats**: `annotate()` adds inline `/* [caveat] … */` markers and a summary of up to `max_summary=12` bullets, each with a long fixed sentence of meaning, for every rendered function — [src/utils/decompiler_caveats.py:203-240](/home/user/binary-mcp/src/utils/decompiler_caveats.py#L203), [decompiler_caveats.py:243-254](/home/user/binary-mcp/src/utils/decompiler_caveats.py#L243).
  - 4 caveats cost a 180-token summary, versus 47 tokens for a terse `kind:detail@line` form (estimate).
  - Across the measured calls caveats totalled 4,792 tokens; decompile_functions(50) alone carried 860 inline + 2,098 summary tokens — [whatif.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/whatif.json), [measure_results.stdout](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/measure_results.stdout).
- **Concise modes, measured:**
  - scan_pseudocode `mode="summary"`: 1,344 versus 6,133 (−78%); `limit=10`: 1,391
  - decompile_functions `include_bodies=False`: 74 versus 11,133; `max_body_chars=4000`: 2,294 (7 bodies withheld and named)
  - get_functions `limit=20`: 1,437
  
  Source: [measure_concise.py](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/measure_concise.py) and the result files in [SP/out/results/](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results/).
- **What-if re-renderings** of the same data (estimates) — [whatif.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/whatif.json):

  | Change | Before | After | Saving |
  |---|---:|---:|---:|
  | get_functions(100) as TSV with signature | 7,017 | 3,270 | −53% |
  | get_functions(100), address/name/calls only | 7,017 | 1,095 | −84% |
  | get_strings(100) as TSV with xref addresses | 3,998 | 1,910 | −52% |
  | get_strings(100), xref count only | 3,998 | 1,345 | −66% |
  | get_imports(180) grouped as CSV per DLL | 2,928 | 885 | −70% |
  | scan_pseudocode findings grouped by rule | 5,820 | 3,499 | −40% (optimistic: synthetic data had 1 rule) |
  | batch_decompile(10) with one envelope instead of ten | | | −1,305 |

- **Session replay**: every logged call stores its **full** output — [src/engines/session/unified_session.py:362-400](/home/user/binary-mcp/src/engines/session/unified_session.py#L362) — and auto-session is enabled by default — [unified_session.py:135](/home/user/binary-mcp/src/engines/session/unified_session.py#L135). `load_full_session` strips the inner envelopes and re-wraps once, with no limit or offset — [src/server.py:5385-5441](/home/user/binary-mcp/src/server.py#L5385). Measured: 5 calls totalling 20,161 tokens replayed as **20,149**. `get_session_summary` = 342; `generate_report` = 1,071 (it uses only 50-char output excerpts) — [whatif.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/whatif.json), [src/tools/reporting.py:322-334](/home/user/binary-mcp/src/tools/reporting.py#L322).
- The code already knows the envelope is costly: the `strip_untrusted_envelope` docstring says nesting "the ~530-character notice … a 30-call session replays roughly 16 KB of boilerplate" — [src/utils/formatters.py:271-281](/home/user/binary-mcp/src/utils/formatters.py#L271).

### Inferences
- Rough per-session picture:
  - tools/list ≈ 36-43K tokens, paid once per conversation and cacheable
  - a triage call ≈ 0.3-3.4K
  - a listing call ≈ 3-7K at default limits
  - one decompile ≈ 0.4-4.7K
  - one batched decompile ≈ 11-46K
  
  So for decompile-heavy workflows the per-call results, not the tool definitions, dominate after a handful of calls.
- The highest-yield result changes are:
  1. tabular one-line listing formats (about −50% to −84%)
  2. a smaller default `max_body_chars`, since tokens ≈ chars / 2.6 for pseudocode
  3. one short envelope per response instead of a 109-token notice per body
  4. a terse caveat legend
  5. caps or pagination on the uncapped tools
- `find_stack_strings` at 15.7K is inflated by my synthetic line pool, which repeats an XOR loop in most functions. The structural risk (no cap or dedupe) is real; the magnitude is not representative.

### Gaps
- Real Ghidra decompile, xref, call-graph and data-type outputs were not measured. `list_data_types` returned 24 tokens, probably because my synthetic `data_types` shape did not match what the tool reads, so ignore that number.
- x64dbg and WinDbg command output, .NET decompile and VT lookups could not be run. Their sizes come from code defaults only.

## Error responses

### Takeaway
Errors are small, typically **11-125 o200k tokens**, but inconsistent. Structured debugger errors carry 2-4 numbered suggestions (74-125 tokens). Generic failures collapse to an opaque 24-token "Reference ID … contact support" line. A default-confinement denial can reach about 400 tokens because it lists every quarantine directory. All of them are returned with `isError: false`.

### Cited Findings
- Structured errors render as `Error [CODE]: message` + `Reason:` + numbered "Suggested actions" + `Reference ID`, with debug_info dropped — [src/utils/structured_errors.py:95-156](/home/user/binary-mcp/src/utils/structured_errors.py#L95), [src/tools/error_hygiene.py:47-104](/home/user/binary-mcp/src/tools/error_hygiene.py#L47). All 20 `create_*_error` factories measured 74-125 tokens (median 102, mean 98), with 2-4 suggestions each. The largest is `create_windbg_not_found_error` at 125 — [errors_summary.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/errors_summary.txt), [measure_errors.py](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/measure_errors.py).
- `safe_error_message` → "Error: <op>\nReference ID: <id>\nPlease contact support with this reference ID." = 24 tokens — [src/utils/security.py:1104-1140](/home/user/binary-mcp/src/utils/security.py#L1104). Measured on `get_pe_info` with a path outside the allow-list (24 tokens) and a missing file (25 tokens); neither says what was wrong — [results/get_pe_info__err-outside-allowlist.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results/get_pe_info__err-outside-allowlist.txt), [results/get_pe_info__err-missing-file.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results/get_pe_info__err-missing-file.txt).
- `safe_path_error` path guidance strings run 10-92 tokens; the PathTraversalError one is the longest at 92 — [src/tools/error_hygiene.py:144-179](/home/user/binary-mcp/src/tools/error_hygiene.py#L144), [errors_summary.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/errors_summary.txt).
- The default-confinement denial (no `BINARY_MCP_ALLOWED_DIRS`) enumerates every default directory plus setup advice. It was 393 tokens here; the length depends on the paths — [src/utils/security.py:207-246](/home/user/binary-mcp/src/utils/security.py#L207), [errors_summary.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/errors_summary.txt).
- Other measured errors (all `isError: false`) — [measure_results.stdout](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/measure_results.stdout):
  - unknown function: 11 tokens
  - invalid session ID: 35
  - bad job ID: 19 (JSON)
  - not a PE: 13
  - WinDbg on Linux: 22
  - raw-WinDbg disabled: 143 (lists 16 structured tools)
  - x64dbg bad `op`: 57

### Inferences
- Error tokens are not a hotspot. Their problem is informativeness rather than size: the opaque "contact support" lines invite retries, and each retry costs a full call round-trip. A 1-2 line actionable message would cost about the same.

### Gaps
- Live debugger error paths (bridge/API failures through `create_error_from_api_response`) were not exercised.

## Existing related material in docs

### Takeaway
The docs address latency and timeouts thoroughly but **token and output size barely at all**. The one piece of output-size guidance is in docs/opencode-issues.md, and it describes a parameter that no longer exists. There is no token budget guidance in large-binary-decompile.md, jobs.md, configuration.md or CONTRIBUTING.md. The contributor template actively produces the description bloat.

### Cited Findings
- **docs/opencode-issues.md, "Issue 2 - Silent tool-response truncation."** opencode silently cuts large tool results (`tool/truncation.ts`, issue #13770) — [docs/opencode-issues.md:56-71](/home/user/binary-mcp/docs/opencode-issues.md#L56).
  - It cites "PR #114 added pagination + summary mode… `scan_pseudocode(summary_only=True, offset=N, limit=M)`" — [opencode-issues.md:75-80](/home/user/binary-mcp/docs/opencode-issues.md#L75). That is stale: the live parameter is `mode="summary"` — [src/tools/review_tools.py:469](/home/user/binary-mcp/src/tools/review_tools.py#L469).
  - It prescribes that new large-payload tools "surface a `summary_only` flag and `offset`/`limit`" — [opencode-issues.md:82-86](/home/user/binary-mcp/docs/opencode-issues.md#L82).
  - It says "the long-term answer is server-side pagination… not unlimited responses" — [opencode-issues.md:125-128](/home/user/binary-mcp/docs/opencode-issues.md#L125).
- **docs/jobs.md**: deadline-then-degrade. Calls block up to `BINARY_MCP_INLINE_DEADLINE` (default 25 s) and then return a `job_id` — [docs/jobs.md:29-46](/home/user/binary-mcp/docs/jobs.md#L29). It also has a table of Claude Code limits (wall clock, idle, auto-background at 2 min) — [jobs.md:18-24](/home/user/binary-mcp/docs/jobs.md#L18). It contains no token guidance; slow analyses add `job_status`/`job_result` round-trips.
- **docs/large-binary-decompile.md**: purely time and performance (structural first pass, targeted decompiles, `decompile_functions` batching, a cost table in minutes) — [docs/large-binary-decompile.md:81-145](/home/user/binary-mcp/docs/large-binary-decompile.md#L81). It says nothing about `max_body_chars` or result size.
- **docs/configuration.md**: knobs for time and heap (`BINARY_MCP_INLINE_DEADLINE`, `GHIDRA_MAX_FUNCTIONS`, `GHIDRA_MAX_HEAP_MB`) but none for output size — [docs/configuration.md:18-45](/home/user/binary-mcp/docs/configuration.md#L18).
- **docs/claude-code-setup.md**: claims "20+ analysis tools" and lists tools that do not exist (`save_analysis`, `get_analysis`, `list_analyses`, `x64dbg_connect`/`x64dbg_status`/`x64dbg_run`…) — [docs/claude-code-setup.md:122-143](/home/user/binary-mcp/docs/claude-code-setup.md#L122). Calling `x64dbg_status` returns "Unknown tool" — [results/x64dbg_status__no-debugger.txt](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results/x64dbg_status__no-debugger.txt).
- **CONTRIBUTING.md** requires Google-style docstrings and gives a tool template with `Args:`/`Returns:` sections. Those become the tool description verbatim — [CONTRIBUTING.md:144](/home/user/binary-mcp/CONTRIBUTING.md#L144), [CONTRIBUTING.md:226-250](/home/user/binary-mcp/CONTRIBUTING.md#L226). It also requires a catalog entry and a regenerated `docs/tool-catalog.json` — [CONTRIBUTING.md:257-270](/home/user/binary-mcp/CONTRIBUTING.md#L257).
- config/claude_code_config.example.json carries a client-side `metadata.tools` list of 12 tool names, which is informational only — [config/claude_code_config.example.json](/home/user/binary-mcp/config/claude_code_config.example.json).

### Inferences
- Any token-efficiency work should update CONTRIBUTING's template (a short description, parameter docs in `Annotated[..., Field(description=...)]`, no history or audit narration) and fix the stale `summary_only` reference. Without that, new tools will regrow the bloat.

### Gaps
- The README and docs/tools.md were not scanned for token guidance beyond the tool-count pins below.

## Tests that pin tool names, descriptions, the catalog and output text

### Takeaway
Changes to tool names or counts, `_meta` tags, x64dbg grouping, wrapper wording and caveat headers each break specific tests. These have to be updated together.

### Cited Findings
- **tests/test_tool_catalog.py:**
  - every registered tool must be classified — [tests/test_tool_catalog.py:107](/home/user/binary-mcp/tests/test_tool_catalog.py#L107)
  - no stale catalog entries — [test_tool_catalog.py:113](/home/user/binary-mcp/tests/test_tool_catalog.py#L113)
  - **tags must appear in tools/list `_meta._fastmcp.tags`**, so disabling `include_fastmcp_meta` breaks this — [test_tool_catalog.py:125-135](/home/user/binary-mcp/tests/test_tool_catalog.py#L125)
  - `docs/tool-catalog.json` must equal the regenerated manifest — [test_tool_catalog.py:30](/home/user/binary-mcp/tests/test_tool_catalog.py#L30), [test_tool_catalog.py:204-205](/home/user/binary-mcp/tests/test_tool_catalog.py#L204)
  - facet checks read the tool source with the docstring removed (`fn.__doc__`) — [test_tool_catalog.py:97-104](/home/user/binary-mcp/tests/test_tool_catalog.py#L97)
- **tests/test_docs_accuracy.py** pins the registered tool count (147) in four places. Removing or merging tools means editing all four:
  - docs/tools.md — [tests/test_docs_accuracy.py:138-143](/home/user/binary-mcp/tests/test_docs_accuracy.py#L138)
  - README — [test_docs_accuracy.py:146-160](/home/user/binary-mcp/tests/test_docs_accuracy.py#L146)
  - the architecture diagram label — [test_docs_accuracy.py:248-280](/home/user/binary-mcp/tests/test_docs_accuracy.py#L248)
  - the "Provides N tools" line in the server.py docstring — [test_docs_accuracy.py:298-305](/home/user/binary-mcp/tests/test_docs_accuracy.py#L298), [src/server.py:1-22](/home/user/binary-mcp/src/server.py#L1)
  
  It also bans em dashes in files — [test_docs_accuracy.py:201](/home/user/binary-mcp/tests/test_docs_accuracy.py#L201).
- **tests/test_x64dbg_tool_groups.py**: exactly 16 tools fronting 159 ops, every group takes `op`, and `op` is the only required argument — [tests/test_x64dbg_tool_groups.py:72-113](/home/user/binary-mcp/tests/test_x64dbg_tool_groups.py#L72). It also pins group descriptions and the `build_op_catalog` text (e.g. "no arguments") — [test_x64dbg_tool_groups.py:132-150](/home/user/binary-mcp/tests/test_x64dbg_tool_groups.py#L132).
- **Envelope wording:**
  - "ATTACKER-CONTROLLED" must appear in output — [tests/test_untrusted_content.py:67](/home/user/binary-mcp/tests/test_untrusted_content.py#L67)
  - a replay contains the notice exactly once — [tests/test_untrusted_rollout.py:1541](/home/user/binary-mcp/tests/test_untrusted_rollout.py#L1541)
  - a report contains none — [test_untrusted_rollout.py:1611](/home/user/binary-mcp/tests/test_untrusted_rollout.py#L1611)
  - header ordering for "BATCH DECOMPILATION" and "**Decompiled: C**" — [test_untrusted_rollout.py:766](/home/user/binary-mcp/tests/test_untrusted_rollout.py#L766), [test_untrusted_rollout.py:784](/home/user/binary-mcp/tests/test_untrusted_rollout.py#L784), [test_untrusted_rollout.py:1008](/home/user/binary-mcp/tests/test_untrusted_rollout.py#L1008)
  - docstring and notice checks — [test_untrusted_rollout.py:238](/home/user/binary-mcp/tests/test_untrusted_rollout.py#L238), [test_untrusted_rollout.py:1390](/home/user/binary-mcp/tests/test_untrusted_rollout.py#L1390)
  - `strip_untrusted_envelope` requires the exact notice line — [src/utils/formatters.py:315](/home/user/binary-mcp/src/utils/formatters.py#L315)
- **Caveat header** "**Decompiler caveats (N)**" — [tests/test_decompiler_caveats.py:91](/home/user/binary-mcp/tests/test_decompiler_caveats.py#L91), [test_decompiler_caveats.py:110](/home/user/binary-mcp/tests/test_decompiler_caveats.py#L110), [tests/test_review_tools.py:767](/home/user/binary-mcp/tests/test_review_tools.py#L767).
- **Listing-format strings:**
  - "Function calls (N)" — [tests/test_get_xrefs.py:103](/home/user/binary-mcp/tests/test_get_xrefs.py#L103), [test_get_xrefs.py:121](/home/user/binary-mcp/tests/test_get_xrefs.py#L121), [test_get_xrefs.py:232](/home/user/binary-mcp/tests/test_get_xrefs.py#L232), [test_get_xrefs.py:281](/home/user/binary-mcp/tests/test_get_xrefs.py#L281), [test_get_xrefs.py:305](/home/user/binary-mcp/tests/test_get_xrefs.py#L305), [tests/test_indirect_call_tools.py:441](/home/user/binary-mcp/tests/test_indirect_call_tools.py#L441)
  - "Showing 2 of 5" — [tests/test_fid_tools.py:119](/home/user/binary-mcp/tests/test_fid_tools.py#L119)
  - scan_pseudocode paging "Showing 1-10 of 25" — [tests/test_review_tools.py:661-667](/home/user/binary-mcp/tests/test_review_tools.py#L661)
  - `format_function_list` / `format_iocs` assertions — [tests/test_server.py:280-330](/home/user/binary-mcp/tests/test_server.py#L280)

### Inferences
- Shortening the envelope notice needs `strip_untrusted_envelope`'s exact-match check and the rollout tests changed in the same commit. Otherwise previously stored sessions will no longer be stripped and will nest on replay.
- Platform-gating WinDbg registration would make the tool count host-dependent. The four count pins in test_docs_accuracy.py count `main()`'s registry, so they would need a defined counting rule, such as "all tools registered on Windows".

### Gaps
- I did not run the test suite.

## Which hotspots cost the most, and how much could each change save? (ranked)

### Takeaway
For the fixed per-session cost (tools/list ≈ 43.4K o200k), the biggest wins are trimming docstring sections (−12.9K) and gating debugger tools on availability (up to −14.0K, overlapping with the first). For per-call cost, the biggest wins are dropping the duplicate `structuredContent` (≈ −50% of wire), compact listing formats (−50% to −84%), a lower default decompile budget, and a one-line untrusted envelope.

### Cited Findings
All numbers come from the measurements above. Sources: [run1_analysis.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/run1_analysis.json), [results_summary.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/results_summary.json), [whatif.json](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/out/whatif.json).

**Fixed cost, paid once per session in tools/list** (savings in o200k against 43,357; not additive):

| Rank | Hotspot | Where | Measured cost | Estimated saving |
|---:|---|---|---:|---|
| 1 | Docstring `Args:`/`Returns:`/`Examples:`/`Notes:` copied into descriptions; 0/439 params have schema descriptions | FastMCP `inspect.getdoc`; CONTRIBUTING template | 11,830 raw section tokens | −12,866 (29.7%) if stripped; −25,160 (58%) for first paragraph only |
| 2 | Debugger tools registered on every host (49 tools) | server.py:6327-6330; windbg_tools.py:108 | 14,049 (32.4%); WinDbg 6,225, x64dbg 7,824 | up to −6,225 on non-Windows by gating WinDbg; up to −14,049 without a debugger |
| 3 | Auto `outputSchema` `{"result": string}` on 137 tools | tool.py:554-559 | 4,377 | −4,240 (9.8%) with `output_schema=None` |
| 4 | Long prose and audit history in top descriptions: analyze_binary 1,333; windbg_execute_command 1,319; diff_binaries 892; load_pdb 816; get_coverage_status 715; mark_functions_examined 647 | those tools | 5,722 description tokens across the six | an estimated −50% to −70% each by rewriting to usage-only text |
| 5 | `_meta._fastmcp.tags` | components.py:91 | 2,518 | −2,528 (5.8%); but pinned by test_tool_catalog.py:125-135 and used by integrators, and model impact depends on the client |
| 6 | Optional parameters as `anyOf[X,null]` + `default:null` (179 each) | pydantic via FastMCP | 2,165 | −2,165 (5.0%) |
| 7 | `windbg_execute_command` listed while disabled by default | windbg_tools.py | 1,396 | −1,396 (3.2%) by not registering it unless `BINARY_MCP_ENABLE_RAW_WINDBG=1` |
| 8 | "(default …)" restatements | descriptions | 365 | −365 |

**Per call, paid on every result** (estimates where marked):

| Rank | Hotspot | Measured cost | Estimated saving |
|---:|---|---:|---|
| A | `structuredContent` duplicating `content` text (137 str tools and the 10 dict tools) | wire 508,975 vs text 235,557 over 86 calls (2.16×) | ≈ −50% of wire bytes and tokens with `output_schema=None`; model impact depends on the client |
| B | `decompile_functions` default `max_body_chars=120000` (server.py:3337) | ≈46K o200k max per call (estimate, 2.59 chars/token); measured 43,471 for 50 functions | tokens ≈ max_body_chars/2.6, so e.g. 24,000 chars caps a call at about 9K (estimate) |
| C | Verbose listing formats | get_functions ≈70 tokens/row, get_strings ≈36-40, get_imports ≈15.5 | −53%/−84% functions; −52%/−66% strings; −70% imports (synthetic) |
| D | `wrap_untrusted` notice (109 of ≈140-145 tokens per envelope); per item in batch_decompile, 2-3× in get_pe_info, get_review_package and diff_binaries | 9,898 tokens across 69 envelopes in 86 calls; about half of small results | ≈ −120 per envelope (−85%) with a 21-token envelope; −1,305 per 10-function batch_decompile with one envelope |
| E | Uncapped outputs: get_imports, get_memory_map, find_api_calls, detect_crypto, generate_iocs, batch_decompile, find_stack_strings (stack_strings.py:607-624), load_full_session / load_session_section | e.g. find_stack_strings 15,740 (synthetic, inflated); load_full_session ≈100% of all prior outputs (20,149 for 5 calls) | bounded by any limit/offset or budget (size depends on the binary) |
| F | `scan_pseudocode` defaulting to `mode="findings"`, limit 50 | 6,133 | −78% (to 1,344) with summary as the default; −40% by grouping per rule (optimistic) |
| G | Caveat summary sentences repeated for every function | 180 for 4 caveats; 2,958 in decompile_functions(50) | −74% with a terse legend (estimate) |
| H | Duplicated `Signature:` line in decompile output | 24 tokens per function | −24 per function |
| I | Hexdump + ASCII format for memory reads | 927 per 256 B (simulated) | −68% as plain hex (estimate) |
| J | Opaque or verbose errors | 11-125 typical; 393 confinement denial | small; mostly an informativeness fix |

### Inferences
- The best fixed-cost package is: rewrite descriptions without the docstring sections, put parameter docs in schema `description`s, gate WinDbg on Windows plus the raw-command flag, and drop the str outputSchemas. That plausibly takes tools/list from about 43K to about 20-25K o200k tokens (estimate: rows 1+3+6+7 with overlap discounted, before any debugger gating on Linux), without changing the tool count except for the optional WinDbg gating.
- The best per-call package is: drop the str outputSchema (which also drops the duplicate `structuredContent`), add a compact or TSV mode as the default for listings, use a shorter envelope, lower the default decompile budget, and cap the uncapped tools. For decompile-heavy sessions this likely matters more than tools/list, because a single default `decompile_functions` call can exceed the whole tools/list.

### Gaps
- The savings are estimates from synthetic data or re-renderings. Real-binary distributions (string counts, xref fan-out, caveat density) will move the per-call numbers.
- Whether clients send outputSchema, `_meta` or structuredContent to the model decides how much of rows 3, 5 and A is actually model-facing. That needs client-side verification, which belongs to the companion web research.
