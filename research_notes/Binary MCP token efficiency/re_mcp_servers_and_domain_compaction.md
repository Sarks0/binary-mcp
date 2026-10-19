# Reverse-engineering MCP servers and RE-specific output compaction (survey as of 2026-10-19)

Legend used in bullets: **Code** = read from the repository source at the cited commit; **Docs/Claim** = stated by the project or author, not independently verified; **Measured (by project)** = a measurement the project published; **Own measurement** = measured by this researcher on 2026-10-19 with the scripts at `/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/measure.py` and `.../scripts/literals.py`; full output tables are in `.../scratchpad/data/results.md` and `.../scratchpad/data/literals.md`. Star counts come from the GitHub repository-search API on 2026-10-19. Repos were shallow-cloned and read, never built or run. Access limits: arxiv.org, usenix.org, acm.org, ndss-symposium.org, openreview.net, semanticscholar.org, hex-rays.com, binary.ninja and huggingface.co were blocked from this environment. Paper facts therefore come from search-result summaries, the papers' own GitHub repos, or vendor sites that were reachable (cloud.google.com, microsoft.com, platform.claude.com).

## 1. Survey of the most-used RE MCP servers: tool counts, pagination defaults, output caps, formats, explicit token-efficiency design, and context-blowup fixes

### Takeaway
The field has converged on a common toolkit. That means offset/limit or cursor pagination, usually with default page sizes of 25–1,000, plus hard server-side caps, plus some way to shrink the tool surface: profiles, lazy tool groups, meta-tools, or a "code mode" `execute_python` tool. The official Hex-Rays IDA server takes the last idea furthest, shipping only 6 tools. The strongest measured result is blacktop/ida-mcp-rs. Its 28-tool "lean" profile cost 25% less than the 76-tool default with equal correctness, almost entirely from fewer cached input tokens spent on tool schemas. The most-reported output blowups are RE-specific: per-byte `undefined` struct members (~11k tokens for one struct), unpaginated imports/exports and decompilation, and indented JSON. Each was fixed by condensing, paginating or compacting.

### Cited Findings

#### Popularity snapshot (GitHub stars on 2026-10-19)
- **IDA:** mrexodia/ida-pro-mcp has 13,017 stars and P4nda0s/IDA-NO-MCP has 2,061. blacktop/ida-mcp-rs has 872, MeroZemory/ida-multi-mcp 459, Claude-Reverser/IDA-instances-MCP 452 and namename333/idapromcp_333 284. jtsylve/re-mcp (IDA + Ghidra) has 174 — [GitHub search API via repo pages, e.g. mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp); [P4nda0s/IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP); [blacktop/ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs); [jtsylve/re-mcp](https://github.com/jtsylve/re-mcp)
- **Ghidra:** LaurieWired/GhidraMCP has 11,406 stars and bethington/ghidra-mcp 5,788. cyberkaida/reverse-engineering-assistant (ReVa) has 878, symgraph/GhidrAssistMCP 777 and clearbluejar/pyghidra-mcp 446. mrphrazer/ghidra-headless-mcp has 195 and 13bm/GhidraMCP 148 — [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP); [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp); [cyberkaida/reverse-engineering-assistant](https://github.com/cyberkaida/reverse-engineering-assistant); [symgraph/GhidrAssistMCP](https://github.com/symgraph/GhidrAssistMCP); [clearbluejar/pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp)
- **Binary Ninja:** fosdickio/binary_ninja_mcp has 456 stars and mrphrazer/binary-ninja-headless-mcp 259. symgraph/BinAssistMCP has 50 and is archived. akrutsinger/binja-codemode-mcp has 11 — [fosdickio/binary_ninja_mcp](https://github.com/fosdickio/binary_ninja_mcp); [mrphrazer/binary-ninja-headless-mcp](https://github.com/mrphrazer/binary-ninja-headless-mcp); [symgraph/BinAssistMCP](https://github.com/symgraph/BinAssistMCP); [akrutsinger/binja-codemode-mcp](https://github.com/akrutsinger/binja-codemode-mcp)
- **Debuggers:**
  - x64dbg: duty1g/x64dbg-mcp-server has 2,568 stars (Zig, created 2026-08-22) and AgentSmithers/x64DbgMCPServer has 738. Wasdubya/x64dbgMCP has 598, SetsunaYukiOvO/x64dbg-mcp 526, dariushoule/x64dbg-skills 210 and bromoket/x64dbg_mcp 132.
  - WinDbg: svnscha/mcp-windbg has 1,625 stars and NadavLor/windbg-ext-mcp has 119.
  - Sources: [duty1g/x64dbg-mcp-server](https://github.com/duty1g/x64dbg-mcp-server); [AgentSmithers/x64DbgMCPServer](https://github.com/AgentSmithers/x64DbgMCPServer); [Wasdubya/x64dbgMCP](https://github.com/Wasdubya/x64dbgMCP); [svnscha/mcp-windbg](https://github.com/svnscha/mcp-windbg)
- **radare2 / rizin / Cutter:** radareorg/radare2-mcp (r2mcp) has 328 stars and sjkim1127/Reversecore_MCP (radare2-based) has 211. The only rizin-specific servers found were tiny: kd992102/rizin-mcp has 4 stars and drvcvt/radare2-mcp (r2/rizin, "85 tools") has 2. LING71671/open-reverselab (Ghidra/Frida/x64dbg/Rizin, "100+ MCP tools") has 1,282. No Cutter MCP server was found — [radareorg/radare2-mcp](https://github.com/radareorg/radare2-mcp); [kd992102/rizin-mcp](https://github.com/kd992102/rizin-mcp); [LING71671/open-reverselab](https://github.com/LING71671/open-reverselab)
- **Anomaly:** morluto/rea ("Reverse engineer anything with agents") showed 333,150 stars and 84,204 forks for a repo created 2026-04-14. A blog put it at "roughly 145,000 stars … in a matter of days". This pattern suggests star inflation; the repo was not evaluated — [morluto/rea](https://github.com/morluto/rea); [kunalganglani.com write-up](https://www.kunalganglani.com/blog/rea-reverse-engineer-anything-agents)

#### Ghidra servers
- **LaurieWired/GhidraMCP @1e98025 (2026-10-10).** The repo was restructured into a Python FastMCP package (`src/ghidra_mcp/server.py`) with a Java backend, including a headless provider. It has 30 `@mcp.tool` functions (Code).
  - List tools default to `offset=0, limit=100`. `list_strings` defaults to `limit=200` and `disassemble_function` to `limit=500`. `decompile_function` takes no limit parameter (Code).
  - The server-side `Page.MAX_LIMIT = 2000`. Pages return `{items, offset, limit, total, hasMore}`, and the builder "Counts every offered item but only materializes the ones inside the requested window" (Code).
  - Server instructions tell the model to "pass offset/limit and check has_more" and say addresses are hex strings such as "0x401000" (Docs).
  - Sources: [server.py](https://github.com/LaurieWired/GhidraMCP/blob/1e980252087b2479a21b9ca6d82d5829538651a7/src/ghidra_mcp/server.py); [Page.java](https://github.com/LaurieWired/GhidraMCP/blob/1e980252087b2479a21b9ca6d82d5829538651a7/extension/src/main/java/com/lauriewired/ghidramcp/core/Page.java)
- **bethington/ghidra-mcp @cf8b12d (2026-10-14), v7.0.0 line.** This is the largest catalog: "209 tools — 205 served by the GUI plugin, 190 by the headless server, 186 by both". A 2026-10-07 commit says "published counts follow #576 (210 tools, 68 in the default groups)". 7.0.0 is a consolidation release: "The advertised surface went from 272 → 251 in the first consolidation pass", and later passes reached 209 — [CHANGELOG.md](https://github.com/bethington/ghidra-mcp/blob/cf8b12db27eb139b28b90eaa3488306da910d759/CHANGELOG.md); [commit 0041777](https://github.com/bethington/ghidra-mcp/commit/00417774c436097a9555a5f0b1cf0a87f1bbc2ab); [MIGRATION_7.0.0_TOOL_CONSOLIDATION.md](https://github.com/bethington/ghidra-mcp/blob/cf8b12db27eb139b28b90eaa3488306da910d759/docs/project-management/MIGRATION_7.0.0_TOOL_CONSOLIDATION.md)
  - **Consolidation pattern (Docs):** "single/batch → one variadic survivor". For example, `batch_decompile(functions)` was folded into `get_functions(functions="a,b,c", fields="decompiled_code")`, and plate, decompiler and disassembly comment setters became `set_comment(type=…)`. `get_functions` takes "up to 20" functions and a `fields=` selector (`decompiled_code`, `signature`, `callers`, `callees`, `xrefs`, `comments`, …) — [migration guide](https://github.com/bethington/ghidra-mcp/blob/cf8b12db27eb139b28b90eaa3488306da910d759/docs/project-management/MIGRATION_7.0.0_TOOL_CONSOLIDATION.md); [README](https://github.com/bethington/ghidra-mcp/blob/cf8b12db27eb139b28b90eaa3488306da910d759/README.md)
  - **Lazy tool loading is the default (issue #440).** "Advertising all 209 endpoints in a single `tools/list` is over a hard limit for at least one major provider". Gemini rejects the request with `400 INVALID_ARGUMENT … too many states for serving`. The bridge therefore loads only `listing,function,program` ("68 endpoints plus the 8 static tools") on connect and registers the rest on demand.
    - The meta-tools are `search_tools`, `list_tool_groups`, `load_tool_group`/`unload_tool_group` and `check_tools`.
    - `--no-lazy` / `GHIDRA_MCP_LAZY=0` is provided for clients that ignore `tools/list_changed`.
    - Source: [README](https://github.com/bethington/ghidra-mcp/blob/cf8b12db27eb139b28b90eaa3488306da910d759/README.md)
  - **Measured (by project, 2026-06-27, v5.14.1, tiktoken, pre-consolidation 251 tools):**
    - The full catalog cost 12,922 tokens, and the "Full MCP Schema (with inputSchema)" cost 18,385.
    - Dropping descriptions gave 8,998 (−30.4%), and keeping only the top 50 endpoints gave 2,818 (−78.2%).
    - Descriptions averaged 12 tokens per endpoint.
    - The document concluded that "Token count alone is not the limiting factor. **Discoverability** … is the real challenge", citing issue #307 and RAG-MCP's "13.6%" vs "43.1%" tool-selection accuracy.
    - Source: [Context-Window-Analysis.md](https://github.com/bethington/ghidra-mcp/blob/cf8b12db27eb139b28b90eaa3488306da910d759/docs/Context-Window-Analysis.md)
  - **Minimal read-only allowlist (Docs).** Four tools — `get_metadata`, `find_functions` (paginated `offset`/`limit`), `get_entry_points`, `get_functions` — are described as a closed set. The README warns that cutting further makes agents "work around the allowlist by `curl`-ing the HTTP API … directly" — [README](https://github.com/bethington/ghidra-mcp/blob/cf8b12db27eb139b28b90eaa3488306da910d759/README.md)
- **ReVa (cyberkaida/reverse-engineering-assistant) @a05a6b0 (2026-10-13).** Code has 88 unique tool names (`.name("…")` in `src/main`).
  - Philosophy (Docs): ReVa "uses state of the art techniques to limit context rot". Its tools "provide smaller, critical fragments with reinforcement and links to other relevant information to reduce context usage and hallucination". It also reports "additional context like the namespace and cross references along with the decompilation" as "a small nudge" to explore like a human — [README](https://github.com/cyberkaida/reverse-engineering-assistant/blob/a05a6b0a18649efd6d74ec8447bdadf8d468c365/README.md)
  - Pagination uses `startIndex`/`maxCount` (Code) — [SchemaUtil.java](https://github.com/cyberkaida/reverse-engineering-assistant/blob/a05a6b0a18649efd6d74ec8447bdadf8d468c365/src/main/java/reva/util/SchemaUtil.java)
  - `get-decompilation` has a 1-based line `offset` and `limit` defaulting to 50, with the description "Defaults to 50 lines to conserve context. Use smaller chunks (10-20 lines) for initial exploration, then expand as needed". Callers and callees are capped with `callersLimited`/`calleesLimited` flags (Code) — [DecompilerToolProvider.java](https://github.com/cyberkaida/reverse-engineering-assistant/blob/a05a6b0a18649efd6d74ec8447bdadf8d468c365/src/main/java/reva/tools/decompiler/DecompilerToolProvider.java)
  - Other defaults: search results 100, bookmarks 200, memory reads 16 bytes, `DEFAULT_MAX_DECOMPILER_SEARCH_FUNCTIONS = 1000` and `DEFAULT_SCRIPT_OUTPUT_CHAR_LIMIT = 65536` (Code) — [ConfigManager.java](https://github.com/cyberkaida/reverse-engineering-assistant/blob/a05a6b0a18649efd6d74ec8447bdadf8d468c365/src/main/java/reva/plugin/ConfigManager.java)
  - Issue #106 (opened 2025-06-04): "Refactor the decompilation tool to reduce context usage". The proposal was "Use a range and paginate", Claude-Code-style, plus a decompilation search tool. It was closed by PR #122 on 2025-06-07 — [issue #106](https://github.com/cyberkaida/reverse-engineering-assistant/issues/106)
  - Issue #202 (2025-10-20): "get-structure-info result uses up a lot of tokens". A 304-byte struct with 286 components produced one JSON entry per `undefined` byte, and the `cRepresentation` repeated "undefined null;" lines. The client flagged a "Large MCP response (~11.0k tokens)". Commits that "Condense consecutive undefined bytes" in both the field list and the C representation fixed it, and PR #209 closed the issue on 2025-11-08 — [issue #202](https://github.com/cyberkaida/reverse-engineering-assistant/issues/202)
- **GhidrAssistMCP (symgraph, formerly jtang613) @b575acc, v3.0.0 (2026-10-09).** "The public catalog contains 100 explicit tools, 93 enabled by default". The import/export and five script tools are disabled by default (Docs).
  - The modernization review says "The previous 49 registered definitions" (consolidated tools with format/action selectors) were replaced because "Names carry the user's intent instead of requiring the model to discover a format/action selector". "Old consolidated names are no longer exposed". This is a *de-consolidation*, the opposite direction to bethington — [README](https://github.com/symgraph/GhidrAssistMCP/blob/b575acc1412cafcfd4dc9fedb7f99ecf219c68ab/README.md); [docs/modernization-review.md](https://github.com/symgraph/GhidrAssistMCP/blob/b575acc1412cafcfd4dc9fedb7f99ecf219c68ab/docs/modernization-review.md)
  - List tools default to `limit = 100`, and disassembly is cut off with "... (truncated at 500 instructions)". Results are cached in a `McpCache` (`DEFAULT_MAX_ENTRIES = 1000`, `DEFAULT_MAX_AGE_MS = 5 * 60 * 1000`) keyed by program revision (Code/Docs) — [ListFunctionsTool.java](https://github.com/symgraph/GhidrAssistMCP/blob/b575acc1412cafcfd4dc9fedb7f99ecf219c68ab/src/main/java/ghidrassistmcp/tools/ListFunctionsTool.java); [DisassembleAtTool.java](https://github.com/symgraph/GhidrAssistMCP/blob/b575acc1412cafcfd4dc9fedb7f99ecf219c68ab/src/main/java/ghidrassistmcp/tools/DisassembleAtTool.java); [McpCache.java](https://github.com/symgraph/GhidrAssistMCP/blob/b575acc1412cafcfd4dc9fedb7f99ecf219c68ab/src/main/java/ghidrassistmcp/cache/McpCache.java)
  - Commit 1fc74f2 (2026-01-11), "Consolidate repeated undefined bytes into single lines", made the same fix as ReVa #202. Data-type dumps print `-- N undefined bytes at 0x…` instead of one line per byte — [commit 1fc74f2](https://github.com/symgraph/GhidrAssistMCP/commit/1fc74f2d5584eeefb9c57a69eda12ceecdd1912d)
- **pyghidra-mcp (clearbluejar) @42d8f80 (2026-10-09).** It registers 25 tools, five of which are GUI-only and "only exposed when the server is started with `--gui`" (Code/Docs).
  - The README has an "Optimized for Agents" section: "keeps the MCP surface intentionally narrow so agent clients spend fewer tokens on tool discovery". It promises "Short tool descriptions" and "Context discipline: tools return focused structured data instead of dumping whole-program context by default" — [README](https://github.com/clearbluejar/pyghidra-mcp/blob/42d8f80551a765441b1a723f6f1ff45aa3914d5e/README.md); [server.py](https://github.com/clearbluejar/pyghidra-mcp/blob/42d8f80551a765441b1a723f6f1ff45aa3914d5e/src/pyghidra_mcp/server.py)
  - Defaults (Code): symbol search, imports and exports use `limit=25`. `search_code` uses `limit=5`, `search_strings` uses `limit=100` and byte/disassembly reads use `count=20`. `gen_callgraph` emits MermaidJS with `condense_threshold=50, top_layers=3, bottom_layers=3` — [mcp_tools.py](https://github.com/clearbluejar/pyghidra-mcp/blob/42d8f80551a765441b1a723f6f1ff45aa3914d5e/src/pyghidra_mcp/mcp_tools.py)
  - Fix history:
    - 2025-08-15, "fix large context-length for imports and exports": `list_imports` changed from limit 100 to 25, and `list_exports` gained `query/offset/limit` pagination — [commit aa4c060](https://github.com/clearbluejar/pyghidra-mcp/commit/aa4c06023d25f57a51213ecdc7138e51a1874ad0)
    - 2026-04-14, "reduce MCP tool manifest token bloat (~66% reduction)": stripped `Field(description=…)`, trimmed "all 14 tool docstrings to 1-2 sentences, drop Args: sections" and turned enums into `Literal` types — [commit 44ee2c2](https://github.com/clearbluejar/pyghidra-mcp/commit/44ee2c2fd784ce9e4210a101f6a80836c4a1263f)
    - 2026-04-15: merged `search_functions_by_name` into `search_symbols_by_name(functions_only=…)` — [commit 9a6b46e](https://github.com/clearbluejar/pyghidra-mcp/commit/9a6b46e81037338178c87c7ab575bb7695f69c29)
- **GhydraMCP (starsong-consulting) @e944495 (2026-06-18).** Code has 68 `@mcp.tool` functions. `limit` defaults to 100 on 26 tools, with 50 and 2000 on one each; call graphs use `max_depth=3` and dataflow uses `max_steps=50`. Responses carry HATEOAS `self/next/prev` links (e.g. `/functions?offset=50&limit=50`) — [bridge_mcp_hydra.py](https://github.com/starsong-consulting/GhydraMCP/blob/e944495e2b8a9c9252c821fcef8a04cf751328e4/bridge_mcp_hydra.py); [README](https://github.com/starsong-consulting/GhydraMCP/blob/e944495e2b8a9c9252c821fcef8a04cf751328e4/README.md)
- **mrphrazer/ghidra-headless-mcp @307b461 (2026-09-16) and mrphrazer/binary-ninja-headless-mcp @7fafd75 (2026-09-19), by Tim Blazytko.** The READMEs list about 212 and about 181 tools respectively; the Binary Ninja description says "180 tools".
  - `tools/list` itself is paginated when `offset`/`limit` are passed, with "`limit=50` default in paged mode", and supports `prefix`/`query` filtering.
  - Results split into `structuredContent` (the "canonical full payload") and `content[0].text`, "a compact summary string (not full JSON duplication). This split is intentional to keep context usage smaller" (Docs).
  - Sources: [BN README](https://github.com/mrphrazer/binary-ninja-headless-mcp/blob/7fafd7523838fa2627a972869e34815fc461834f/README.md); [Ghidra README](https://github.com/mrphrazer/ghidra-headless-mcp/blob/307b461cdbbedfbafb3771333f21875b745f940e/README.md)

#### IDA servers
- **mrexodia/ida-pro-mcp @c133c38 (2026-09-26).** The README now opens: "**I recommend using the Official Hex-Rays IDA MCP Server instead!**" — [README](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/README.md)
  - Code has 102 `@tool` functions, 11 resources and 25 `@unsafe` tools. The 22 debugger tools sit behind `?ext=dbg` ("Debugger tools are hidden by default").
  - **Profiles** (`--profile` whitelists, Code): `readonly.txt` has 34 tools and `triage.txt` has 9, "Small enough to keep small models on-task" — [profiles/triage.txt](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/profiles/triage.txt); [profiles/readonly.txt](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/profiles/readonly.txt)
  - **Defaults and caps (Code):**
    - `list_funcs` count is 100.
    - Search tools default to `limit=1000` with an "enforced max: 10000 to prevent token overflow", and use cursor pagination `{next: offset}`/`{done: true}`.
    - `decompile(max_lines=500, offset=0)` is clamped to 5000 lines, and since 2026-09-12 it is also capped at `_DECOMPILE_CODE_MAX_CHARS = 30_000`.
    - `disasm(max_instructions=5000)` is clamped to 50000.
    - Sources: [api_analysis.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/api_analysis.py); [api_core.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/api_core.py); [commit b708a8a](https://github.com/mrexodia/ida-pro-mcp/commit/b708a8a62ee5a11f2a5de747ad9685d002ed5153)
  - **Global output cap (Code).** `OUTPUT_LIMIT_MAX_CHARS = 50000`. Larger results become a "schema-preserving preview" (`OUTPUT_LIMIT_PREVIEW_ITEMS = 10`, `…STR_LEN = 4000`, `…MAX_CHARS = 40000`), plus `_meta` saying `output_truncated: True` and a `download_url`. The hint reads "Output truncated. Run: curl -o .ida-mcp/{id}.json {url}", and the full output is cached server-side.
    - Fix 2026-04-15 (#361): "truncation metadata violates output schema".
    - Sources: [rpc.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/rpc.py); [commit 54b0566](https://github.com/mrexodia/ida-pro-mcp/commit/54b0566d1065b77abc8ad4d636db34f10d92dfab)
  - **Token optimization PR #341 (merged 2026-04-06, ZehMatt), "Trim whitespaces on disasm/decompile and json serialization".** A `compact_whitespace()` function collapses "runs of 2+ spaces/tabs to a single space, preserving string literals" in disassembly and pseudocode lines. All `json.dumps(result, indent=2)` calls became `separators=(",", ":")` (Code) — [commit 244d2d3](https://github.com/mrexodia/ida-pro-mcp/commit/244d2d3b665ebdb13ccb622110d665b778f72725); [merge 30774f3](https://github.com/mrexodia/ida-pro-mcp/commit/30774f3ac62825d1f31f16a9b446ed67f072dc77)
  - **Composite and triage tools (Code).**
    - `survey_binary` returns "a compact overview of the binary in one call". It includes the "top 15 strings and functions ranked by xref count", classified as thunk/wrapper/leaf/dispatcher/complex, plus "imports by category, and call graph summary". Its docstring says: "Use this as your FIRST tool call … Do not call list_funcs, imports, or find_regex separately for triage". A `detail_level='minimal'` mode exists "for binaries with >10k functions", and iteration is capped at 10,000 functions and 5,000 strings.
    - `analyze_function` caps decompilation at `_DECOMPILE_LINE_CAP = 100` lines, `_TOP_STRINGS = 10` (deduplicated) and `_TOP_CONSTANTS = 10` ("Drop boring constants").
    - `trace_data_flow` caps at 200 nodes / 500 edges, with depth defaulting to 5 and a maximum of 20.
    - Sources: [api_survey.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/api_survey.py); [api_composite.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/api_composite.py)
  - `py_eval(code)` runs "arbitrary Python code in IDA context" as an unsafe tool. `int_convert` exists because LLMs "struggle with complex mathematical calculations", and the README says to tell the model "NEVER convert number bases yourself" (Docs) — [README](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/README.md)
  - Issue #127 ("Add pagination or offset to disassemble_function", opened 2025-08-27) was closed on 2026-04-16 — [issue #127](https://github.com/mrexodia/ida-pro-mcp/issues/127)
- **Official Hex-Rays IDA MCP (HexRaysSA/ida-mcp) @df6de79 (2026-10-08).** The README calls it the "Official Hex-Rays IDA MCP Server". It requires IDA 9.4+ with idalib and installs via `uvx ida-hcli mcp install` (Docs).
  - Its `tools/list` snapshot contains exactly **6 tools**: `open_database`, `execute_python`, `reference`, `list_databases`, `save_database` and `close_database`.
  - `execute_python` "Run[s] Python (IDAPython and the ida-domain API) … decompile … disassemble … xrefs … rename … patch bytes. Returns the result plus stdout/stderr". `reference(query)` returns "API signatures and usage examples".
  - Descriptions run 117–527 characters each (Code).
  - Sources: [README](https://github.com/HexRaysSA/ida-mcp/blob/df6de7985b534a964c125d5a86e41b26b17b14f6/README.md); [tests/snapshots/mcp_metadata.json](https://github.com/HexRaysSA/ida-mcp/blob/df6de7985b534a964c125d5a86e41b26b17b14f6/tests/snapshots/mcp_metadata.json); [docs/ARCHITECTURE.md](https://github.com/HexRaysSA/ida-mcp/blob/df6de7985b534a964c125d5a86e41b26b17b14f6/docs/ARCHITECTURE.md). The announcement post was not reachable from this environment: [hex-rays.com blog](https://hex-rays.com/blog/hex-rays-ida-mcp-server)
- **blacktop/ida-mcp-rs @15d16ab (2026-10-08), Rust over idalib.** "By default `tools/list` returns 76 tools. The full tool list is roughly 15k tokens, estimated at four characters per token"; 7 more tools are opt-in.
  - Flags: `--profile=lean` (28 tools, "about 26 KB of schemas"), `--toolsets=…` over 12 categories, `--tools=`, `--exclude-tools=` and `--read-only`. `--profile=lean --read-only` gives "21 tools, 21.9 KB".
  - **Measured (by project, 2026-10-03, Claude Code 2.1.288, Sonnet 5.5, 3 trials × 3 tasks):** "Lean cost 25% less than full ($0.275 vs $0.367), used 42 vs 52 tool calls, and recorded 0 vs 1 MCP tool errors; cache-read input fell from 849,325 to 442,166 tokens … The saving is almost all cache-read tokens from the smaller inventory". It also notes that Cursor and Codex defer MCP schemas.
  - `run_script` "returns a trailing expression as JSON and keeps state between calls, so one script can find, filter, and return only what matters" (Docs).
  - Source: [README](https://github.com/blacktop/ida-mcp-rs/blob/15d16aba427bedc8a23c7a54d8adee06d427b740/README.md)
- **jtsylve/re-mcp @7b38aa9 (2026-09-09), IDA + Ghidra.** "To keep token usage manageable, only common analysis tools and management tools are directly visible". The rest are reached through the meta-tools `search_tools`, `get_schema`, `call`, `execute` and `batch`.
  - `execute` is "sandboxed Python that chains multiple `await invoke(name, params)` calls in a single round trip". `batch` handles "up to 50 operations per call".
  - All tools carry MCP annotations, and mutation tools "return old values alongside new values" (Docs).
  - Source: [README](https://github.com/jtsylve/re-mcp/blob/7b38aa92952bd0621e8c964dc859f1515fe26a10/README.md)
- **P4nda0s/IDA-NO-MCP @2a48a91 (2026-07-26).** It is anti-MCP by design: "Say goodbye to the complex, verbose, and laggy interaction mode of IDA MCP … Export IDA decompilation results as source files" for AI IDEs.
  - Its "consolidated" mode exists because the original export of a 100 MB binary was "nearly 1G, more than twenty thousand files" ("token explosion"). In that mode it writes a single `decompiled.c` plus a one-line-per-function `function_list.txt` and a sampled N-hop BFS `callgraph.txt` from entry points and exports.
  - It "skips `memory/` by default (raw hex has low value for AI and costs the most tokens)" and filters short strings. The mode switches automatically above 20,000 functions (Docs; translated from Chinese).
  - Sources: [README](https://github.com/P4nda0s/IDA-NO-MCP/blob/2a48a91da706eb778761bfd47e5bb9dde8b651fb/README.md); [README_EN](https://github.com/P4nda0s/IDA-NO-MCP/blob/2a48a91da706eb778761bfd47e5bb9dde8b651fb/README_EN.md)
- **namename333/idapromcp_333 (v1.5 @dcc334b, 2026-04-06).** This fork of ida-pro-mcp is "focused on removing redundant MCP capabilities, reducing context usage, and saving token overhead". The author felt "the original project has too many tools, which drags it down" (Claim; translated) — [README](https://github.com/namename333/idapromcp_333/blob/dcc334b6c63fdc4e34784ea93aa78b37d77ecdd3/README.md)
- **MxIris-Reverse-Engineering/ida-mcp-server** has been inactive since 2025-05-29 (last commit 74e2eb8) — [repo](https://github.com/MxIris-Reverse-Engineering/ida-mcp-server)

#### Binary Ninja servers
- **Official Vector35 built-in MCP server.** The GUI server is HTTP-only (default `http://127.0.0.1:24642/mcp`). The GUI server is "Included with every GUI edition". The headless `binaryninja_mcp` uses stdio, ships with Commercial/Ultimate on macOS/Linux, and "is not available in Binary Ninja Free or Personal and is not yet available in native Windows packages".
  - Tools use a `bn_` prefix, and "The exact tool list may change". Categories include "a compact triage summary". Memory reads return "hex and base64".
  - "Large lists are paginated with `offset` and `limit`. Responses include `count`, `total`, `nextOffset`, and `truncated`". "Addresses in tool output are formatted as hexadecimal strings".
  - Docs fetched from the dev branch on 2026-10-19 — [docs/guide/mcp.md](https://github.com/Vector35/binaryninja-api/blob/dev/docs/guide/mcp.md)
  - The plugin tool API guidance says "**Return one representation.** Some MCP clients show the model only the structured content, and others only the text. A tool that returns both must put everything the model needs in each". Warnings go in a `warnings` array — [docs/dev/mcp-tools.md](https://github.com/Vector35/binaryninja-api/blob/dev/docs/dev/mcp-tools.md)
- **symgraph/BinAssistMCP @c15fce5 (2026-10-09).** It advertises "45 Consolidated Tools" and carries a notice of "Planned archival … as Binary Ninja introduces a bundled native MCP server" — [README](https://github.com/symgraph/BinAssistMCP/blob/c15fce527d5d17cb005cb9aafeea6b8d53edc729/README.md)
- **fosdickio/binary_ninja_mcp @8c5134e (2026-04-06).** Code has 56 bridge tools with `offset`/`limit` defaults of 100 and `count` defaults of 100/200. It also includes `list_all_strings()`, which has "no pagination; aggregates all pages" (Docs) — [bridge](https://github.com/fosdickio/binary_ninja_mcp/blob/8c5134ee46e2bf44f9a4d846bd971c3e39b3e306/bridge/binja_mcp_bridge.py); [README](https://github.com/fosdickio/binary_ninja_mcp/blob/8c5134ee46e2bf44f9a4d846bd971c3e39b3e306/README.md)
- **akrutsinger/binja-codemode-mcp @928c9fa (2026-09-21).** It "implements Anthropic's Code Execution pattern. Instead of accessing the typical MCP 'tools', the LLM writes Python code that executes directly against Binary Ninja's API … more token-efficient".
  - The API reference "rides in the tool description". `search_api()` and `describe()` cover 31 BN types, and `workspace.write/read` carries results between calls.
  - `skills.save` keeps "Reusable analysis code, saved across sessions" (Docs).
  - Source: [README](https://github.com/akrutsinger/binja-codemode-mcp/blob/928c9fa50b56da4127b7deb15f221b139e69fe58/README.md)

#### radare2 / rizin / Cutter
- **radareorg/radare2-mcp (r2mcp) @562c0cf (2026-10-16), written in C.** `tool_specs[]` has 51 entries (Code).
  - Pagination uses cursor/`page_size` with `R2MCP_DEFAULT_PAGE_SIZE 1000` and `R2MCP_MAX_PAGE_SIZE 10000`. It paginates both JSON arrays and plain text by lines. List tools accept `count` to return only a count and `filter` (Code) — [r2mcp.h](https://github.com/radareorg/radare2-mcp/blob/562c0cf23c42b65b3052f0b294d8778c20facbde/src/r2mcp.h); [tools.c](https://github.com/radareorg/radare2-mcp/blob/562c0cf23c42b65b3052f0b294d8778c20facbde/src/tools.c)
  - Modes: `-m` "expose minimum amount of tools", `-R` read-only, `-r` "permit run_* tools" (`run_command`, `run_javascript`) and sessions. Tool descriptions embed `<think>` hints, e.g. open_file's "Call this tool before any other one".
  - A `sql` tool (via the r2xsql plugin) runs queries like `SELECT name, size FROM funcs WHERE size > 100 ORDER BY size DESC LIMIT 10` (Docs/Code) — [README](https://github.com/radareorg/radare2-mcp/blob/562c0cf23c42b65b3052f0b294d8778c20facbde/README.md)
  - History:
    - 2025-04-14 "Limit screen output to 16KB just in case" (`scr.limit` = 16768) — [commit e338006](https://github.com/radareorg/radare2-mcp/commit/e33800673ef19bee06c37f8bb3bfb80015666d47)
    - 2025-10-08 "Add support for pagination the tool output" — [commit 933a4dc](https://github.com/radareorg/radare2-mcp/commit/933a4dcd68693d7d0f5fdeb3c80ed56375968da5)
    - 2026-04-28 "Add optional count param to 'list_' tools" — [commit 097c9b0](https://github.com/radareorg/radare2-mcp/commit/097c9b0b67d7f89bc0a8702242b046a5e48c4c60)
- **rizin/Cutter:** no maintained, widely used MCP server was found; the largest rizin-specific one has 4 stars — [kd992102/rizin-mcp](https://github.com/kd992102/rizin-mcp)

#### Debugger servers
- **svnscha/mcp-windbg @48e4350 (2026-10-10).** Code has 11 tools: `list_dumps`, `open_cdb_dump`, `open_cdb_remote`, `open_kd_session`, `open_kd_dump`, `run_cdb_command`, `run_kd_command`, `close_cdb_session`, `close_kd_session`, `send_ctrl_break` and `wait_for_break`. Output is raw debugger text returned by command passthrough — [server.py](https://github.com/svnscha/mcp-windbg/blob/48e4350d57c44a38068be4f64e89a0fe60fe5c04/src/mcp_windbg/server.py)
  - Output bounds (Code): `MAX_RETAINED_LINES = 2000`, `MAX_RETAINED_LINE_CHARS = 16384` (" ... line truncated at"), `MAX_PARTIAL_OUTPUT_LINES = 2000` and `MAX_PARTIAL_OUTPUT_CHARS = 64 * 1024`. The changelog says "The output retained for one command is now bounded, by line count and per line, with a notice saying how it was cut" (#130, #139) and "The retained output is capped at 2,000 lines and 64 KiB" (#112, #114) — [debug_session.py](https://github.com/svnscha/mcp-windbg/blob/48e4350d57c44a38068be4f64e89a0fe60fe5c04/src/mcp_windbg/debug_session.py); [CHANGELOG](https://github.com/svnscha/mcp-windbg/blob/48e4350d57c44a38068be4f64e89a0fe60fe5c04/CHANGELOG.md)
  - User filter scripts can define `process_input` and/or `process_output` hooks to transform or redact tool text — [filter_script.py](https://github.com/svnscha/mcp-windbg/blob/48e4350d57c44a38068be4f64e89a0fe60fe5c04/src/mcp_windbg/filter_script.py)
  - The Claude Code plugin ships the tools, 4 skills and a `crash-analyst` agent; "Always-on context cost is about 400 tokens; a skill or agent costs more only when it fires" (Claim) — [CHANGELOG](https://github.com/svnscha/mcp-windbg/blob/48e4350d57c44a38068be4f64e89a0fe60fe5c04/CHANGELOG.md)
- **x64dbg servers:**
  - duty1g's README claims "84 MCP Tools" in its feature list but "72 MCP tools" in its Tools section, an internal inconsistency — [duty1g README @18be30a, 2026-10-12](https://github.com/duty1g/x64dbg-mcp-server/blob/18be30ab417a371fd441de68d7252d2bc1830f11/README.md)
  - Wasdubya has 56 `@mcp.tool` tools (Code):
    - `ExecCommand(cmd, offset=0, limit=100)`, documented as "default: 100, max: 5000".
    - `QuerySymbols(limit=5000)`, "max: 50000".
    - Disassembly `count` "default: 1, max: 100".
    - Its README suggests "If large token count is a concern, try Headroom … a proxy to put in-between the plugin and your LLM".
    - Sources: [x64dbg.py @e7474e5, 2026-06-04](https://github.com/Wasdubya/x64dbgMCP/blob/e7474e57d34aacf533d29e5778361637afef936a/src/x64dbg.py); [README](https://github.com/Wasdubya/x64dbgMCP/blob/e7474e57d34aacf533d29e5778361637afef936a/README.md)
  - bromoket advertises "**23 mega-tools** over **153 REST endpoints**", i.e. consolidation — [README @d8e6cac, 2026-06-09](https://github.com/bromoket/x64dbg_mcp/blob/d8e6cac465128c18f63c51e5de55616d91c09bcf/README.md)
  - AgentSmithers (C#) defines about 42 `[Command(...)]` attributes, a few of them commented out (Code) — [repo @a8303d7, 2026-10-04](https://github.com/AgentSmithers/x64DbgMCPServer/tree/a8303d7ac7bfd251b9da83b80c9d1d4407ddd8df)
  - dariushoule/x64dbg-skills ships Claude Code skills instead of an MCP server — [repo](https://github.com/dariushoule/x64dbg-skills)

#### Cross-server summary of explicit token-efficiency mechanisms (from the findings above)
| Mechanism | Servers (source above) |
|---|---|
| Tool profiles / toolsets / allowlists | ida-pro-mcp (`readonly` 34, `triage` 9); ida-mcp-rs (`lean` 28 of 76, `--toolsets`, `--read-only`); r2mcp (`-m`, `-R`); pyghidra-mcp (GUI tools only with `--gui`); GhidrAssistMCP (7 of 100 disabled by default) |
| Lazy loading / meta-tools / tool search | bethington (default groups + `search_tools`/`load_tool_group`); re-mcp (`search_tools`/`get_schema`/`call`); mrphrazer (paginated, filterable `tools/list`) |
| Consolidation into fewer, parameterized tools | bethington 272→251→209 (`get_functions fields=`); BinAssistMCP "45 Consolidated Tools"; bromoket "23 mega-tools"; pyghidra-mcp merged search tools; **reversed** by GhidrAssistMCP 3.0.0 (49 consolidated → 100 explicit) |
| Code mode / scripting tool | Hex-Rays official (`execute_python` + `reference`, 6 tools total); binja-codemode-mcp; re-mcp `execute`; ida-mcp-rs `run_script`; ida-pro-mcp `py_eval` (unsafe); r2mcp `run_javascript`/`sql`; ReVa script tools (65,536-char output limit) |
| Output caps + truncation hints | ida-pro-mcp 50k chars → preview + download URL; ReVa 50 decompile lines; GhidraMCP MAX_LIMIT 2000; GhidrAssistMCP 500 insns; r2mcp 16 KB screen limit + page size 1000/10000; mcp-windbg 2,000 lines/64 KiB |
| Compact serialization | ida-pro-mcp compact JSON + whitespace collapse; mrphrazer text summary + `structuredContent`; Binary Ninja "Return one representation" |
| Schema/description trimming | pyghidra-mcp ~66% manifest reduction; bethington measured descriptions = 24.1% of catalog tokens |

### Inferences
- Defaults cluster at 100 items per page: GhidraMCP, GhidrAssistMCP, GhydraMCP, fosdickio and ida-pro-mcp's list_funcs all use it. Search-type tools allow far larger pages (1,000 default / 10,000 max in ida-pro-mcp and r2mcp). Decompilation is the least consistently bounded output: GhidraMCP has no cap, ReVa defaults to 50 lines, ida-pro-mcp to 500 lines / 30k chars, and analyze_function to 100 lines. binary-mcp should treat decompile and disassembly as needing explicit line/char budgets, not just list pagination.
- The two directions on consolidation coexist for different reasons. bethington and bromoket consolidate to cut tool count and schema tokens. GhidrAssistMCP de-consolidated because selector parameters hurt the model's tool choice. The defensible middle seems to be "one-or-many" variadic tools with `fields=` selectors (bethington `get_functions`), not action enums.
- The only rigorous cost measurement found (ida-mcp-rs) attributes most of the saving to schema tokens re-sent with every request (cache reads), not to tool outputs. That suggests a 147-tool server like binary-mcp gains most from profiles or lazy loading on clients that don't defer schemas.
- Vendors are moving toward code mode: Hex-Rays ships 6 tools, Binary Ninja has a native server, and BinAssistMCP is being archived in its favour. An `execute_python`-style tool plus an API `reference` tool is now a first-party pattern for IDA.

### Gaps
- The Hex-Rays announcement post (hex-rays.com) and Binary Ninja's rendered docs (binary.ninja) were blocked here. The rationale Hex-Rays gave for a 6-tool design, its release date, and the exact `bn_*` tool count are not captured.
- No server publishes a measured before/after token count for *outputs*, as opposed to schemas. The only quantified output blowup is ReVa #202 (~11.0k tokens). pyghidra-mcp's "~66%" is a commit-message claim with no published method.
- Star counts are a weak proxy for use. Download, telemetry or MCP-registry install numbers were not found, and the morluto/rea count looks inflated.
- The r2mcp mini-mode tool count was not determined precisely. The duty1g x64dbg tool count conflicts within its own README (84 vs 72).
- LaurieWired/GhidraMCP issue search returned no token/context issues. Its 94 open issues were not read individually.

## 2. Catalog of RE-specific ways to compact output, with measured savings

### Takeaway
Measured on 656 real Ghidra outputs, structure-preserving normalization cut o200k tokens by 23.3%: removing indentation, shortening Ghidra auto-names (`param_N`, `local_XX`, `uVarN`) and stripping zero-padding. Adding cast removal (lossy) reached 27.5%. Auto-name shortening alone gave 13.3%. Some "obvious" rewrites cost tokens instead of saving them, notably `undefined8`→`u64` (+0.9%). For listings, the big wins are structural:
- **Disassembly:** dropping the bytes column and 16-digit addresses takes 28.0 tokens per instruction down to 12–14 (−49 to −56%). Labels instead of addresses reach −64%.
- **Imports:** grouping by DLL saves 76%.
- **Call graphs:** an adjacency list with short RVAs saves 67% against an edge list and 87% against indented JSON.
- **Strings:** dedupe plus a length or "wordy" filter cuts tokens by 4–5×.
- **Raw bytes:** base64 or contiguous hex costs 0.7–1.2 o200k tokens per byte on non-zero data, versus 2.1–3.4 for spaced, xxd, `hexdump -C` or WinDbg-style hexdumps.

### Cited Findings

#### Measurement setup (Own measurement, 2026-10-19)
- **Tokenizers:**
  - o200k_base (mapped to `gpt-4o`, `gpt-4.1`, `gpt-4.5-preview`, `gpt-5` in tiktoken's model map) and cl100k_base (`gpt-4`, `gpt-3.5-turbo`), rebuilt from npm `tiktoken@1.0.22`.
  - "claude-legacy" = Anthropic's pre-Claude-3 `tokenizer.json` shipped in PyPI `anthropic==0.34.2`. It is **not** the tokenizer of current Claude models.
  - Qwen `qwen.tiktoken` (PyPI `dashscope` 1.27.8).
  - Mistral Tekken `tekken_240911.json` (PyPI `mistral_common` 1.12.0).
  - Counted with Python tiktoken 0.14.0 / tokenizers 0.23.3 — [measure.py](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/measure.py); [npm tiktoken 1.0.22](https://registry.npmjs.org/tiktoken/-/tiktoken-1.0.22.tgz)
- **Pseudocode corpus:** 656 real Ghidra decompilations (HumanEval-Decompile, gcc x86-64, O0–O3, 164 each) with the original C, from LLM4Decompile's `legacy-test/decompile-eval-executable-gcc-ghidra.json` — [LLM4Decompile @85b364b](https://github.com/albertan017/LLM4Decompile/blob/85b364bf093eb2ee4f3687cfe38a203fca89f23e/legacy-test/decompile-eval-executable-gcc-ghidra.json)
- **PE sample:** `pip/_vendor/distlib/t64.exe` from pip 26.2.1. It is a real MSVC x64 PE (108,032 bytes, SHA-256 81a618f2…6b7; ImageBase 0x140000000; 86 imports from 2 DLLs; 688 unique direct call edges) and was read only, never executed. Disassembled with capstone 5.0.7 and parsed with pefile 2024.8.26 — [measure.py](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts/measure.py)

#### A. Decompiler pseudocode (656 Ghidra functions; totals across corpus) — Own measurement ([results.md](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/data/results.md))
| Transform | o200k | cl100k | claude-legacy | Qwen | Tekken |
|---|---|---|---|---|---|
| raw Ghidra output (288,290 o200k tokens; 722,843 chars) | — | — | — | — | — |
| W1 drop blank lines + trailing ws | −0.2% | −0.2% | −0.2% | −0.2% | −0.4% |
| W2 + collapse internal 2+ space runs (ida-pro-mcp PR #341 rule) | −0.2% | −0.2% | −0.3% | −0.2% | −0.4% |
| W3 indent 1 space/level (Ghidra uses 2) | −3.7% | −3.8% | −0.3% | −3.6% | −3.6% |
| W3t indent 1 tab/level | −0.8% | −0.8% | **+8.7%** | −0.8% | −0.6% |
| W4 no indentation | −9.3% | −9.5% | −0.3% | −8.9% | −8.7% |
| C strip `/* */` comments | −0.3% | −0.3% | −0.3% | −0.3% | −0.3% |
| N1 strip zero padding (`FUN_00101234`→`FUN_101234`) | −0.2% | −0.2% | −0.1% | −0.6% | −0.6% |
| N2 short auto-names (`param_N`→`aN`, `local_x`/`xVarN`→`vN`, collision-free per function) | **−13.3%** | −11.9% | −13.3% | −12.3% | −13.1% |
| N3 `FUN_`→`f_`, `DAT_`→`d_`, `LAB_`→`L_` (+N1) | −0.2% | −0.2% | −0.1% | −0.6% | −0.8% |
| T `undefinedN`/`ulong`/`uint`… → `u64`/`u32`… | **+0.9%** | +0.9% | +0.8% | +1.7% | +1.4% |
| K strip C casts (LOSSY) | −5.1% | −5.4% | −6.1% | −5.1% | −5.4% |
| Combined structure-preserving: W3+C+N1+N2 | −17.6% | −16.3% | −14.0% | −16.8% | −17.7% |
| Combined structure-preserving+: W4+C+N1+N2+N3 | **−23.3%** | −22.1% | −14.1% | −22.3% | −23.1% |
| Combined aggressive: above + T + K | −27.5% | −26.2% | −19.7% | −25.8% | −27.8% |
- **Own measurement, token composition of raw Ghidra output:** whitespace-only tokens are 12.6% (o200k), 12.9% (cl100k) and 9.8% (claude-legacy). Pure-parenthesis tokens are 6.0% (o200k) and 7.4% (claude-legacy); this is an upper bound on what removing redundant parentheses could save. Ghidra emits patterns like `if ((float)(DAT_001020d0 & (uint)(…)) < param_1)` — [results.md](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/data/results.md)
- **Own measurement, literal costs (o200k):** `undefined8` = 2 tokens, `u64` = 2, `uint64_t` = 3, `param_1` = 3 vs `a1` = 2, `local_28` = 3, `uVar1` = 3 vs `v1` = 2, `(undefined8 *)` = 3, `DAT_001020d0` = 6. Type renaming saves characters but not tokens — [literals.md](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/data/literals.md)
- **Own measurement, decompiled vs source and signature vs body (o200k, mean per function):**
  | Opt level | Source | Raw Ghidra | Raw/source | Normalized | Normalized/source | Max raw |
  |---|---|---|---|---|---|---|
  | O0 | 139 | 320 | 2.30× | 246 | 1.77× | — |
  | O1 | 139 | 395 | 2.84× | 300 | 2.16× | — |
  | O2 | 139 | 380 | 2.73× | 290 | 2.08× | — |
  | O3 | 139 | 663 | 4.77× | 512 | 3.68× | 8,886 |

  The signature line alone averages 13.7–14.3 tokens, i.e. a one-line function header is about 2–4% of a body — [results.md](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/data/results.md)
- **Prior art in servers:**
  - ida-pro-mcp collapses runs of 2+ spaces outside string literals and switched to compact JSON separators — [commit 244d2d3](https://github.com/mrexodia/ida-pro-mcp/commit/244d2d3b665ebdb13ccb622110d665b778f72725)
  - ReVa defaults decompilation to 50-line windows — [DecompilerToolProvider.java](https://github.com/cyberkaida/reverse-engineering-assistant/blob/a05a6b0a18649efd6d74ec8447bdadf8d468c365/src/main/java/reva/tools/decompiler/DecompilerToolProvider.java)
  - ida-pro-mcp's composite tool caps pseudocode at 100 lines and the plain decompile at 30,000 chars — [api_composite.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/api_composite.py); [api_analysis.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/api_analysis.py)
  - SK2Decompile normalizes pseudo-code ("R2I standard"), removing comments (`comment_remover`), dropping empty lines (`strip_empty`) and reformatting with clang-format — [sk2decompile/Preprocess/format.py](https://github.com/albertan017/LLM4Decompile/blob/85b364bf093eb2ee4f3687cfe38a203fca89f23e/sk2decompile/Preprocess/format.py); [SK2Decompile README](https://github.com/albertan017/LLM4Decompile/blob/85b364bf093eb2ee4f3687cfe38a203fca89f23e/sk2decompile/README.md)

#### B. Structure/type dumps
- **Undefined-byte runs:** listing every `undefined` member of a 304-byte, 286-component struct cost about 11.0k tokens in ReVa. Condensing consecutive undefined bytes fixed it — [ReVa issue #202](https://github.com/cyberkaida/reverse-engineering-assistant/issues/202). GhidrAssistMCP made the same fix, emitting `-- %d undefined bytes at 0x%04x --` — [commit 1fc74f2](https://github.com/symgraph/GhidrAssistMCP/commit/1fc74f2d5584eeefb9c57a69eda12ceecdd1912d)

#### C. Disassembly (200 real x86-64 instructions from t64.exe's entry point) — Own measurement
| Layout | o200k tok/insn (Δ) | cl100k | claude-legacy | Qwen |
|---|---|---|---|---|
| x64dbg-like `000000014000427C \| 48 83 EC 28 \| sub rsp, 0x28` | 28.0 | 27.8 | 23.5 | 41.7 |
| Ghidra-like `addr bytes MNEMONIC OPS` (padded, uppercase) | 24.9 (−11%) | 24.8 | 22.1 | 34.1 |
| objdump-like `addr:\tbytes\tinsn` | 27.9 (−0%) | 27.6 | 24.4 | 36.9 |
| no bytes, `0x%016x  insn` | 19.7 (−30%) | 19.5 | 18.4 | 30.8 |
| no bytes, `%x insn` | 14.3 (−49%) | 14.1 | 14.4 | 20.8 |
| no bytes, RVA addresses (also in operands) | 12.4 (−56%) | 12.1 | 12.1 | 14.8 |
| no bytes, function-relative `+%x` | 13.2 (−53%) | 13.0 | 13.1 | 15.5 |
| no addresses; labels only on branch targets | 10.2 (−64%) | 9.9 | 10.1 | 11.0 |
| `%x` + compact operands (drop ` ptr`, spaces) | 13.0 (−54%) | 12.9 | 13.8 | 19.6 |
| `%x` + UPPERCASE mnemonic/registers | 14.7 (−47%) | 14.6 | 15.2 | 21.3 |

Source: [results.md](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/data/results.md). Uppercase mnemonics (Ghidra's style) cost about 3% more than lowercase in o200k.
- **Prior art:**
  - LLM4Decompile's assembly preprocessing keeps only the instruction field of `objdump -d` lines (`# remove the binary code`) and drops `#` comments (`# remove the comments`) — [LLM4Decompile README @85b364b](https://github.com/albertan017/LLM4Decompile/blob/85b364bf093eb2ee4f3687cfe38a203fca89f23e/README.md)
  - Nova's normalized assembly replaces addresses with per-instruction special tokens: the test input reads `mov eax , $1<label-1>mov ebx , $2<label-2>…`, with 256 `<label-i>` tokens added to the tokenizer — [nova/test_tokenizer.py @6dfaf43](https://github.com/lt-asset/nova/blob/6dfaf438fb23a8f024d0297653571615631ad8f4/nova/test_tokenizer.py)

#### D. Hexdumps (tokens per byte, 256-byte samples) — Own measurement
| Format | PE header (o200k) | x64 code (o200k) | .rdata strings (o200k) | random (o200k) | zeros (o200k) | random (claude-legacy) | random (Qwen) |
|---|---|---|---|---|---|---|---|
| `hexdump -C` (offset + bytes + \|ASCII\|) | 2.98 | 3.09 | 2.96 | 3.16 | 2.59 | 2.60 | 3.80 |
| WinDbg `db` (backtick addr + bytes + ASCII) | 3.27 | 3.36 | 3.27 | 3.44 | 2.89 | 2.99 | 4.15 |
| `xxd` (offset + 2-byte groups + ASCII) | 2.26 | 2.41 | 2.26 | 2.52 | 1.96 | 2.29 | 3.29 |
| spaced hex, 16/line (no offset/ASCII) | 2.16 | 2.06 | 2.17 | 2.13 | 2.00 | 1.55 | 2.47 |
| contiguous hex, 32 B/line | 1.04 | 0.89 | 0.86 | 1.20 | 0.71 | 1.22 | 1.76 |
| base64 | 0.67 | 0.82 | 0.87 | 0.94 | 0.18 | 0.97 | 0.99 |
| C escapes `\xNN` | 2.19 | 2.11 | 2.17 | 2.27 | 2.00 | 3.11 | 2.61 |
| C array `0xNN, ` | 5.13 | 5.05 | 5.16 | 5.10 | 4.99 | 4.11 | 5.44 |

Uppercase and lowercase hex cost the same in every tokenizer tested — [results.md](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/data/results.md)
- **Practice:** IDA-NO-MCP skips raw memory hexdumps by default as low-value and the most token-hungry — [README](https://github.com/P4nda0s/IDA-NO-MCP/blob/2a48a91da706eb778761bfd47e5bb9dde8b651fb/README.md). Binary Ninja's official server returns memory reads "as hex and base64" — [docs/guide/mcp.md](https://github.com/Vector35/binaryninja-api/blob/dev/docs/guide/mcp.md)

#### E. String listings (t64.exe, ASCII + UTF-16LE) — Own measurement (o200k)
| Filter | # strings | `0x%016x: "s"` | `%x s` (RVA) | values only |
|---|---|---|---|---|
| min len 4 | 1,406 | 21,541 | 10,499 | 6,688 |
| min 4 + dedupe | 865 | 13,430 | 6,644 | 4,334 |
| min 6 + dedupe | 371 | 6,204 | 3,326 | 2,293 |
| min 8 + dedupe | 286 | 4,935 | 2,719 | 1,906 |
| min 4 + dedupe + "wordy" filter (≥85% alnum/space/path chars and a 3-letter run) | 304 | 4,873 | 2,520 | 1,676 |
| min 6 + dedupe + wordy | 267 | 4,366 | 2,303 | 1,556 |

Source: [results.md](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/data/results.md). A full 16-digit `0x` address per string roughly doubles the listing's cost against an RVA.
- **Practice:** ida-pro-mcp's survey returns the "top 15 strings", and analyze_function returns 10 deduplicated strings — [api_survey.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/api_survey.py); [api_composite.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/api_composite.py). IDA-NO-MCP's consolidated mode filters by minimum length (`LARGE_STRING_MIN_LEN`) — [README](https://github.com/P4nda0s/IDA-NO-MCP/blob/2a48a91da706eb778761bfd47e5bb9dde8b651fb/README.md). ReVa's triage skill reads strings "100-200 strings at a time" and lists keyword categories to look for (network, file system, crypto…) — [binary-triage SKILL.md](https://github.com/cyberkaida/reverse-engineering-assistant/blob/a05a6b0a18649efd6d74ec8447bdadf8d468c365/ReVa/skills/binary-triage/SKILL.md)

#### F. Import listings (t64.exe: 86 imports from 2 DLLs) — Own measurement (o200k tokens)
- Address table `0x%016x  DLL  name`: 1,611 tokens.
- Markdown table: 1,798 (+12%).
- JSON `indent=2`: 3,246 (+101%).
- Compact JSON: 2,129 (+32%).
- `DLL!name` per line: 808 (−50%).
- Grouped `DLL (n): a, b, c`: 394 (−76%).
- Grouped, lowercase DLL without `.dll`: 303 (−81%).
- Source: [results.md](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/data/results.md)
- **Practice:** ida-pro-mcp's survey returns "imports by category" (network/file/process etc. via `_classify_import`) — [api_survey.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/api_survey.py)

#### G. Call graphs / xrefs (t64.exe: 688 unique direct-call edges, 173 callers) — Own measurement (o200k tokens)
- Edge list `FUN_x -> FUN_y`: 9,710 tokens.
- Markdown xref table: 13,165 (+36%).
- JSON edges `indent=2`: 24,161 (+149%).
- Compact JSON edges: 15,218 (+57%).
- Mermaid: 10,401 (+7%).
- DOT: 12,468 (+28%).
- Adjacency `FUN_x: FUN_y, FUN_z`: 6,061 (−38%).
- Adjacency with short RVA hex `x: y z`: 3,184 (−67%; −87% vs indented JSON).
- Compact JSON adjacency with RVA: 3,307 (−66%).
- Source: [results.md](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/data/results.md)
- **Practice:**
  - pyghidra-mcp renders call graphs as Mermaid with `condense_threshold=50`, `top_layers=3`, `bottom_layers=3` — [README](https://github.com/clearbluejar/pyghidra-mcp/blob/42d8f80551a765441b1a723f6f1ff45aa3914d5e/README.md)
  - ida-pro-mcp's `trace_data_flow` caps at 200 nodes / 500 edges — [api_composite.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/api_composite.py)
  - IDA-NO-MCP samples the graph by N-hop BFS from entry points and exports — [README](https://github.com/P4nda0s/IDA-NO-MCP/blob/2a48a91da706eb778761bfd47e5bb9dde8b651fb/README.md)
  - The ReVa issue #106 proposal noted Mermaid for graph output "because Claude is trained on it" — [issue #106](https://github.com/cyberkaida/reverse-engineering-assistant/issues/106)

#### H. Debugger register views (18 x64 registers, synthetic values) — Own measurement (o200k tokens)
- WinDbg `r` style: 226 tokens.
- JSON `indent=2` with `0x%016x`: 281 (+24%).
- Compact JSON with `0x%x`: 153 (−32%).
- `k=%x` on one line: 98 (−57%).
- Same, with zero registers omitted plus "(others=0)": 68 (−70%).
- Source: [results.md](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/data/results.md)
- **Practice:** mcp-windbg returns raw debugger text but bounds it by lines, line length and bytes — [debug_session.py](https://github.com/svnscha/mcp-windbg/blob/48e4350d57c44a38068be4f64e89a0fe60fe5c04/src/mcp_windbg/debug_session.py)

#### I. Names and summaries
- **Own measurement, mangled names** (9 examples, o200k): mangled 140 tokens, full demangled (undname/c++filt style) 146, simplified `Namespace::Function` 47 (−66%). Demangling alone saves nothing; simplifying does — [results.md](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/data/results.md)
- **Summary before body:**
  - mrphrazer's servers return a compact text summary in `content[0].text` with the full payload in `structuredContent` — [README](https://github.com/mrphrazer/binary-ninja-headless-mcp/blob/7fafd7523838fa2627a972869e34815fc461834f/README.md)
  - IDA-NO-MCP writes a one-line-per-function `function_list.txt` (`address | name | type | fallback reason`) alongside the code — [README](https://github.com/P4nda0s/IDA-NO-MCP/blob/2a48a91da706eb778761bfd47e5bb9dde8b651fb/README.md)
  - BinAssistMCP embeds "Function signatures and Binary Ninja comments" in code results — [README](https://github.com/symgraph/BinAssistMCP/blob/c15fce527d5d17cb005cb9aafeea6b8d53edc729/README.md)

### Inferences
- binary-mcp's highest-yield output changes are mostly formatting choices with no information loss:
  - drop or shorten addresses and raw bytes in disassembly by default (~2× fewer tokens)
  - print RVA or function-relative offsets with a single image-base line
  - group imports by DLL
  - emit call graphs and xrefs as adjacency lists
  - remove leading indentation and blank lines from pseudocode
  - avoid `indent=2` JSON
  - prefer base64 or contiguous hex for bulk bytes, keeping xxd only for short, human-oriented peeks
- Ghidra auto-name shortening (−13%) is the biggest single pseudocode saving, but it has a cost. `local_28` encodes the stack offset (−0x28), `uVar`/`pcVar` encode type hints and `FUN_<addr>` is a stable address handle. It should be optional, or use a reversible alias table, so renames and xref follow-ups still work.
- Tokenizer behaviour differs enough to change conclusions. Indentation is nearly free in the legacy Claude tokenizer but costs ~9% in o200k, and tabs are much worse in the legacy Claude tokenizer. Any decision for Claude clients should be re-measured with Anthropic's `count_tokens` (see Q4).
- Decompiled output on optimized code (O3) is about 4.8× the source tokens with outliers near 9k tokens for a small function. Per-function line or char budgets, as in ReVa and ida-pro-mcp, matter most for optimized and malware binaries.

### Gaps
- Current Claude tokenizer counts are missing. `count_tokens` needs an API key that was not available here, so all percentages are proxies from other vocabularies.
- The pseudocode corpus is small, benign HumanEval functions compiled by gcc for Linux. Windows/MSVC malware and C++ binaries (more `WARNING` comments, `FUN_`/`DAT_` references, casts and vtable code) will have different savings, and the comment-stripping and zero-padding numbers (−0.2 to −0.3%) are likely understated for them.
- Removing redundant parentheses was not implemented, since it needs a C expression parser. Only the 6–7% upper bound is reported.
- No measured accuracy impact exists for any of these transforms on RE tasks. Q3 lists the closest evidence.
- The register sample was synthetic, and the PE sample is a small launcher stub rather than a typical malware sample.

## 3. Academic and industry research on LLMs for binary analysis that deals with context length or token budgets

### Takeaway
No paper was found that directly measures token savings from normalizing decompiler output. The literature handles context limits in four ways:
- training-time caps of 2,048–4,096 tokens per function (LLM4Decompile, ReSym, Nova)
- input normalization that strips bytes, addresses and comments (LLM4Decompile, Nova, SK2Decompile)
- splitting the work across many queries and re-aggregating (ReSym's Prolog aggregation, MalSight's iterative summaries, Project Ire's per-function summaries)
- avoiding splitting altogether with very long context (Google/Gemini)

Industry reports agree that decompiled C is "5–10 times more concise" than disassembly. The closest accuracy evidence is from non-RE code: removing formatting saved 24.5% of input tokens "with negligible" performance impact (ICSE'26).

### Cited Findings
- **LLM4Decompile (Tan et al., arXiv 2403.05286; EMNLP 2024).**
  - V1.5 "End" models are "trained with a larger dataset (15B tokens) and a maximum token size of 4,096". V2 "Ref" models are "built upon **Ghidra** and trained on 2 billion tokens to **refine** the decompiled pseudo-code from Ghidra".
  - Re-executability on HumanEval-Decompile ranges from 27.3% (1.3B v1.5) and 45.4% (6.7B v1.5) to 52.7% (6.7B v2), 64.9% (9B v2) and 63.6% (22B v2).
  - The example generation uses `max_new_tokens=2048` with "max length to 4096".
  - Sources: [README @85b364b](https://github.com/albertan017/LLM4Decompile/blob/85b364bf093eb2ee4f3687cfe38a203fca89f23e/README.md); [arXiv abstract](https://arxiv.org/abs/2403.05286)
  - Per the abstract as summarized by search, refinement models gain "a further 16.2% improvement over the LLM4Decompile-End" — [arXiv PDF](https://arxiv.org/pdf/2403.05286)
  - Input normalization (Code): objdump lines are reduced to the instruction field ("remove the binary code") and `#` comments are dropped — [README](https://github.com/albertan017/LLM4Decompile/blob/85b364bf093eb2ee4f3687cfe38a203fca89f23e/README.md)
- **SK2Decompile (in the LLM4Decompile repo, 2025).**
  - Approach: two phases. First "Transform binary/pseudo-code into obfuscated intermediate representations" (Skeleton, normalized per the "R2I standard"), then "Generate human-readable source code with meaningful identifiers" (Skin).
  - Results (Claims): "**+21.6%** over GPT-5-mini" re-executability on HumanEval and R2I "**+29.4%** over Idioms". On BringUpBench (505 functions) it reports "42.3% compilation rate and 27.0% re-executability rate".
  - Source: [sk2decompile/README.md](https://github.com/albertan017/LLM4Decompile/blob/85b364bf093eb2ee4f3687cfe38a203fca89f23e/sk2decompile/README.md)
- **DeGPT (Hu, Liang, Chen; NDSS 2024).** It optimizes Ghidra output with three LLM roles (referee, advisor, operator) and a semantic check. It reports "a 24.4% drop in the effort needed to understand decompiled code" and about "63% of the comments" as practically useful (search summary of the NDSS page). The code counts tokens with tiktoken (`num_tokens_from_messages`). No token-saving numbers are reported — [NDSS paper page](https://ndss-symposium.org/ndss-paper/degpt-optimizing-decompiler-output-with-llm); [DeGPT util.py @3660492](https://github.com/QGrain/DeGPT/blob/36604923658ec896727828d68c39756b0ee449f9/degpt/util.py)
- **ReSym (Xie et al.; CCS 2024, Distinguished Paper).** It recovers variable and struct names and types from stripped binaries. A "Prolog-based algorithm … aggregates and cross-checks results from multiple LLM queries", which works around token constraints and suppresses hallucinations (search summary of the abstract). Training uses `max_len=2048` with truncation (StarCoderBase-3B) — [paper PDF](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf); [Purdue news](https://cs.purdue.edu/news/articles/2025/purdue-cs-researchers-develop-an-ai-powered-tool-for-reverse-engineering-stripped-binary-code-earning-acm-ccs-distinguished-paper-award.html); [training_src/dataset.py @437b4ac](https://github.com/lt-asset/resym/blob/437b4acac21a5a60edecf0c4423f7172f991271f/training_src/dataset.py)
  - GENNM (NDSS 2025) notes that ReSym-style per-function fine-tuning "limits the calling context the model can see" (search summary) — [GENNM PDF](https://cs.purdue.edu/homes/lintan/publications/gennm-ndss25.pdf)
- **Nova (Jiang et al.; ICLR 2025).** It uses hierarchical attention "that builds attention summaries" over assembly and claims gains "up to 146.54%" on decompilation and "6.17%" on binary similarity — [arXiv HTML](https://arxiv.org/html/2311.13721v3)
  - Code: training data is capped at `max_len = 2048`, and normalized assembly uses 256 `<label-i>` special tokens in place of addresses — [prepare_lm_dataset.py @6dfaf43](https://github.com/lt-asset/nova/blob/6dfaf438fb23a8f024d0297653571615631ad8f4/nova/prepare_lm_dataset.py); [test_tokenizer.py](https://github.com/lt-asset/nova/blob/6dfaf438fb23a8f024d0297653571615631ad8f4/nova/test_tokenizer.py)
- **BinSum (Jin, Larson, Yang, Lin; arXiv 2312.09601, Dec 2023).** It benchmarks over 557K binary functions and compares assembly with decompiled inputs across ChatGPT, GPT-4, Llama 2 and Code Llama. The study "generates 4 billion inference tokens, incurred a total expense of 11,418 US dollars and 873 NVIDIA A100 GPU hours" — [arXiv](https://arxiv.org/abs/2312.09601v1); [Microsoft Research page](https://www.microsoft.com/en-us/research/?p=1032138)
- **MalSight (Lu et al.; arXiv 2406.18379).** Binary malware summarization proceeds iteratively over a call-graph-ordered function list, feeding annotated functions to MalT5 (0.77B), which is described as comparable to Code-Llama (search summary) — [arXiv](https://arxiv.org/abs/2406.18379v1)
- **Google / VirusTotal, "From Assistant to Analyst: The Power of Gemini 1.5 Pro for Malware Analysis" (2024-04-29, Bernardo Quintero).**
  - Two WannaCry binaries were decompiled with Hex-Rays into C files of "268 KB and … 231 KB … more than 280,000 tokens", analyzed in "34 seconds".
  - medui.exe (833 KB) "was decompiled into 189,080 tokens" and analyzed in 27 s. A "306.50 KB executable binary produces a 1.5 MB assembly file".
  - "the output from a decompiler is five to 10 times more concise than that produced by a disassembler".
  - On earlier chunked analyses: "we were required to divide the code into chunks, which led to vague and non-specific outcomes".
  - Source: [Google Cloud blog](https://cloud.google.com/blog/topics/threat-intelligence/gemini-for-malware-analysis)
- **Google, "Scaling Up Malware Analysis with Gemini 1.5 Flash" (2024-07-15).** The pipeline is Mandiant Backscatter unpacking, then a Hex-Rays cluster (IDA's headless lib), then Gemini 1.5 Flash.
  - Rationale: "decompiled code being 5–10 times more concise than disassembled code, making it a more efficient choice given the token window limitations".
  - Throughput: 12.72 s average per file over 1,000 files, and "4 million tokens per minute".
  - No truncation or pre-filtering strategy is described.
  - Source: [Google Cloud blog](https://cloud.google.com/blog/topics/threat-intelligence/scaling-up-malware-analysis-with-gemini)
- **Microsoft Project Ire (2025-08-05).**
  - Pipeline: triage first, then control-flow reconstruction with angr and Ghidra. The LLM "calls tools through an API to summarize key functions", and each summary goes into a "chain of evidence" that a validator cross-checks.
  - Results: precision 0.98 / recall 0.83 on a public Windows-driver set, and 0.89 / 0.26 on about 4,000 hard targets.
  - Source: [Microsoft Research blog](https://www.microsoft.com/en-us/research/blog/project-ire-autonomously-identifies-malware-at-scale/)
- **Non-RE evidence on formatting removal.**
  - "The Hidden Cost of Readability" (arXiv 2508.13666, accepted to ICSE'26): "LLMs can maintain performance across formatted code and unformatted code, achieving an average input token reduction of 24.5% with negligible output token reductions" (search summary) — [arXiv HTML](https://arxiv.org/html/2508.13666v1)
  - Token Sugar (arXiv 2512.08266): "799 (code pattern, shorthand) pairs can reduce up to 15.1% token count" — [papers.cool listing](https://papers.cool/arxiv/2512.08266)
  - PseudoFix (ASE 2025) improves decompiled-C readability (up to 34% less Halstead effort) but does not measure tokens — [ASE 2025 entry](https://conf.researchr.org/details/ase-2025/ase-2025-papers/152/PseudoFix-Refactoring-Distorted-Structures-in-Decompiled-C-Pseudocode)
- **Industry training:** John McIntosh (author of pyghidra-mcp) teaches "Building Agentic RE: Automating Reverse Engineering & Vulnerability Research with AI" at Recon 2026 and DEF CON training. It covers custom Ghidra MCP servers and multi-binary analysis (course listing; content not reviewed) — [Recon 2026](https://recon.cx/2026/en/trainingBuildingAgenticRE.html); [DEF CON training](https://training.defcon.org/products/agentic-re-automating-reverse-engineering-vulnerability-research-with-ai-john-mcintosh-dctlv2026)

### Inferences
- The research models were trained and evaluated with 2,048–4,096-token windows per function. The 656-function measurement in Q2 shows Ghidra O3 output averaging 663 tokens with outliers near 9k for small HumanEval functions. Real-world functions routinely exceed these windows, which is why every system either paginates, splits or uses huge context.
- Google's "chunking led to vague outcomes" observation argues against blind fixed-size chunking. Splitting along program structure (per function, in call-graph order, with summaries carried forward) is what MalSight and Project Ire do, and it is the defensible alternative when a whole binary doesn't fit.
- SK2Decompile and LLM4Decompile normalize their inputs (no bytes, no comments, anonymized structure) and still get strong accuracy. That is indirect evidence that stripping RE boilerplate does not hurt models, though none of these papers isolates token savings.

### Gaps
- No paper reports measured token savings or accuracy deltas from pseudocode normalization (casts, `undefined` types, parentheses, auto-names) for LLM consumption. The Q2 numbers are the only measurements found.
- Full texts of LLM4Decompile, ReSym, Nova, BinSum, MalSight and the ICSE'26 formatting paper could not be opened (academic hosts blocked). Their quoted figures come from search summaries or repo READMEs and code, and specific tables such as BinSum's assembly-vs-decompiled findings were not verified.
- No REcon, RE//verse, Black Hat or DEF CON 2025–2026 talk with token measurements for RE agents was found. Only the agentic-RE training listings surfaced.

## 4. How hex addresses and typical RE artifacts tokenize in modern LLM tokenizers

### Takeaway
In o200k/cl100k, which group digits in runs of 1–3, the leading `0x` costs about 2 extra tokens per address. Zero padding and full 64-bit virtual addresses cost another 2–4. Image-relative (RVA) or function-relative offsets are 2.5–3.5× cheaper than `0x%016x` VAs:
- `0x0000000140001000` is 8 tokens versus 3 for `140001000` and 2 for `1000`.
- Averaged over random PE addresses: 9.6 → 3.8 → 2.7 tokens.

Tokenizers that split every digit (Qwen, Mistral Tekken) raise these costs by up to roughly 2× (e.g. 18.6 vs 9.6 tokens for `0x%016x`). Anthropic says its current tokenizer (Claude 4.7+) yields about 30% more tokens than earlier Claude models and does not publish it, so Claude numbers must come from `count_tokens`.

### Cited Findings
- **Own measurement, single literals (o200k / cl100k / claude-legacy / Qwen / Tekken):**
  | Literal | o200k | cl100k | claude-legacy | Qwen | Tekken |
  |---|---|---|---|---|---|
  | `0x00401000` | 5 | 5 | 5 | 10 | 10 |
  | `00401000` | 3 | 3 | 3 | 8 | 8 |
  | `0x401000` | 4 | 4 | 4 | 8 | 8 |
  | `401000` | 2 | 2 | 2 | 6 | 6 |
  | `0x1000` | 4 | 4 | 3 | 6 | 6 |
  | `1000` | 2 | 2 | 1 | 4 | 4 |
  | `+0x1a` | 5 | 5 | 5 | 5 | 5 |
  | `+1a` | 3 | 3 | 3 | 3 | 3 |
  | `FUN_00401000` | 5 | 5 | 6 | 10 | 11 |
  | `sub_401000` | 4 | 4 | 4 | 8 | 8 |
  | `0x0000000140001000` | 8 | 8 | 6 | 18 | 18 |
  | `140001000` | 3 | 3 | 3 | 9 | 9 |
  | WinDbg `00000001`40001000` | 7 | 7 | 5 | 17 | 17 |
  | `4d 5a 90 00` | 9 | 9 | 6 | 11 | 11 |
  | `4d5a9000` | 6 | 6 | 5 | 8 | 8 |
  | base64 `TVqQAA==` | 5 | 5 | 5 | 5 | 5 |
  | `\x4d\x5a\x90\x00` | 10 | 10 | 14 | 12 | 12 |

  Source: [literals.md](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/data/literals.md)
- **Own measurement, mean tokens per address** over 1,000 random addresses, measured after a space as inside a listing line (o200k, with Qwen in parentheses):
  - 32-bit `0x%08x`: 7.14 (10.52); `%08x`: 5.14; `0x%x`: 6.61; `%x`: 4.61; decimal: 4.00 (8.00).
  - Ghidra `FUN_%08x`: 6.14; IDA `sub_%X`: 5.63.
  - 64-bit PE `0x%016x`: 9.58 (18.64); `0x%x`: 7.18; `%x`: 5.18; RVA: 3.81 (5.25).
  - 64-bit user-mode `0x%016x`: 11.35; WinDbg backtick form: 10.85; `%x`: 8.35.
  - Function-relative `+%x` (0–0x3ff): 2.72 (3.60); `+0x%x`: 4.62.
  - Source: [results.md](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/data/results.md)
- **Own measurement, why the tokenizers differ (Code):** o200k's pre-tokenizer pattern contains `\p{N}{1,3}`, grouping up to 3 digits, and separates letter runs. Qwen's pattern (`…|\p{N}|…`) and Tekken's (`…|\p{N}|…`) emit each digit as its own token — [npm tiktoken encoders/o200k_base.json](https://registry.npmjs.org/tiktoken/-/tiktoken-1.0.22.tgz); [dashscope qwen_tokenizer.py](https://pypi.org/project/dashscope/); [mistral_common tekken_240911.json](https://pypi.org/project/mistral-common/)
- **Own measurement, hex bytes** (see the Q2 table): random bytes cost 0.94 tokens/B as base64 (o200k), 1.20 as contiguous hex, 2.13 as spaced hex and 2.52 as xxd. Zero-filled data costs 0.18 tokens/B in base64.
- **Published cross-check:** the `unigram` crate docs report "32 bytes of hex average 37.1" tokens under GPT-4 vocabularies and "base64url … 29.9 … for 32 bytes" under GPT-4o (small sample, 64 payloads per size). My random-data figures give about 38 and 30 tokens — [docs.rs unigram 0.3.1](https://docs.rs/crate/unigram/0.3.1)
  - A general guide gives "base64 data at 2.0-2.5 bytes per token" and "random binary at 1.5-2.0" as rules of thumb (low-rigor source) — [speedtesthq guide](https://speedtesthq.com/guides/ai/llm-tokens-bytes-and-bandwidth)
- **Own measurement, mangled names** (o200k, totals over 9 MSVC/Itanium/Rust examples): mangled 140 tokens, full demangled 146, simplified 47. For example, `?push_back@?$vector@HV?$allocator@H@std@@@std@@QEAAXAEBH@Z` is 26 tokens versus 28 fully demangled versus 7 for `std::vector<int>::push_back` — [results.md](/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/data/results.md)
- **Anthropic (docs fetched 2026-10-19):**
  - "Claude 4.7 and later models and Claude Mythos Preview use a newer tokenizer. The same input text produces approximately 30 percent more tokens than on earlier models … Recount prompts against the model you plan to use".
  - "Claude Fable 5.1, Claude Mythos 5.1, Claude Fable 5, and Claude Mythos 5 share the tokenizer introduced with Claude Opus 4.7".
  - "Token counting is **free to use** but subject to requests per minute rate limits".
  - Source: [Claude token counting docs](https://platform.claude.com/docs/en/build-with-claude/token-counting)
- **Third-party claims on the new Claude tokenizer (unverified):** "1.47x" on technical documentation and "1.45x" on code files for Opus 4.7 vs 4.6 — [feedbagel analysis](https://feedbagel.com/post/analysis-claude-opus-47s-new-tokenizer-uses-147x-more-tokens-than-version-46); [aiproductivity.ai](https://aiproductivity.ai/news/claude-opus-47-tokenizer-cost-increase/)
- **How projects estimate tokens:** ida-mcp-rs estimates schema tokens "at four characters per token" — [README](https://github.com/blacktop/ida-mcp-rs/blob/15d16aba427bedc8a23c7a54d8adee06d427b740/README.md). bethington measured with tiktoken and warns that its fallback "characters-divided-by-four estimate … cannot be compared" with tiktoken totals — [Context-Window-Analysis.md](https://github.com/bethington/ghidra-mcp/blob/cf8b12db27eb139b28b90eaa3488306da910d759/docs/Context-Window-Analysis.md)

### Inferences
- Defaults for binary-mcp:
  - print a module's image base once and use RVA (`1bd38`) or function-relative (`+3c`) offsets in listings
  - drop the `0x` prefix and zero padding inside dense tables where the column is known to be hex
  - keep full VAs only where the user must copy them into a debugger
  - for x64dbg/WinDbg live addresses, the backtick form is slightly cheaper than `0x%016x` but still ~10 tokens
- Hex-heavy outputs disproportionately penalize models whose tokenizers split digits. Address compaction gives an even larger relative win for those models than the o200k numbers suggest.
- Because Claude's current tokenizer is unpublished and about 30% "heavier", the reliable method for a Claude-first server is `count_tokens` on a fixed corpus of binary-mcp outputs. The scripts above are ready to swap in a `count_tokens` backend.

### Gaps
- No measurement with the current Claude tokenizer (needs an API key for the free `count_tokens` endpoint).
- No published peer-reviewed measurement of address or hex tokenization was found. The unigram crate figure is a small, self-reported benchmark.
- Gemini and Llama-3 tokenizers were not measured, because Hugging Face downloads were blocked.

## 5. Workflow-level strategies RE agents use to cut tokens

### Takeaway
The servers and research converge on a tiered workflow:
1. a single compact triage call: survey, counts, top-N strings and functions by xref count, imports by category
2. targeted, paginated reads of only the interesting functions, often batched
3. delegation of deep dives to sub-agents that return only a verdict
4. persisting findings back into the database (renames, comments, bookmarks, tags) or into workspace files so later reads are self-describing
5. a code-mode script or an export-to-files path when the tools run out

The research analogues are per-function summaries carried along the call graph (MalSight, Project Ire) and query aggregation (ReSym). The counter-strategy is a single long-context pass (Google), which Google itself notes can hit limits on very large binaries.

### Cited Findings
- **Triage first, in one call:**
  - ida-pro-mcp's `survey_binary` ("Use this as your FIRST tool call … Do not call list_funcs, imports, or find_regex separately for triage") ranks functions by xref count and classifies them (thunk/wrapper/leaf/dispatcher/complex). It marks FLIRT library functions, and its `detail_level='minimal'` mode serves >10k-function binaries — [api_survey.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/api_survey.py)
  - Binary Ninja's official server offers "a compact triage summary" — [docs/guide/mcp.md](https://github.com/Vector35/binaryninja-api/blob/dev/docs/guide/mcp.md)
  - BinAssistMCP exposes a `binassist://{filename}/triage_summary` resource — [README](https://github.com/symgraph/BinAssistMCP/blob/c15fce527d5d17cb005cb9aafeea6b8d53edc729/README.md)
  - re-mcp ships a `survey_binary` prompt that produces "an executive summary" — [README](https://github.com/jtsylve/re-mcp/blob/7b38aa92952bd0621e8c964dc859f1515fe26a10/README.md)
  - Project Ire begins with automated triage of "the file type, its structure, and potential areas of interest" — [Microsoft Research blog](https://www.microsoft.com/en-us/research/blog/project-ire-autonomously-identifies-malware-at-scale/)
- **Counts before contents, small chunks:**
  - ReVa's binary-triage skill calls `get-strings-count`, then pages "100-200 strings at a time". It filters symbols with `filterDefaultNames=true` and ends by creating "a task list of next steps for deeper investigation" — [binary-triage SKILL.md](https://github.com/cyberkaida/reverse-engineering-assistant/blob/a05a6b0a18649efd6d74ec8447bdadf8d468c365/ReVa/skills/binary-triage/SKILL.md)
  - ReVa's deep-analysis skill prescribes "READ - Gather Current Context (1-2 tool calls)" with `get-decompilation (limit=20-50 lines …)` and to "start small, expand as needed" — [deep-analysis SKILL.md](https://github.com/cyberkaida/reverse-engineering-assistant/blob/a05a6b0a18649efd6d74ec8447bdadf8d468c365/ReVa/skills/deep-analysis/SKILL.md)
  - r2mcp list tools take `count` to return just a number — [commit 097c9b0](https://github.com/radareorg/radare2-mcp/commit/097c9b0b67d7f89bc0a8702242b046a5e48c4c60)
- **Batching with field selection:**
  - bethington's `get_functions(functions=…up to 20, fields=…)` — [README](https://github.com/bethington/ghidra-mcp/blob/cf8b12db27eb139b28b90eaa3488306da910d759/README.md)
  - ida-pro-mcp's "Batch-first design: Most operations accept both single items and lists" and `analyze_component` ("per-function summaries, internal call graph, shared data") — [README](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/README.md); [api_composite.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/api_composite.py)
  - re-mcp's `batch` (≤50 ops) and `execute` (chain `await invoke(...)` calls, `asyncio.gather`) — [README](https://github.com/jtsylve/re-mcp/blob/7b38aa92952bd0621e8c964dc859f1515fe26a10/README.md)
- **Sub-agents:**
  - A community prompt in ida-pro-mcp's README instructs "Use sub-agents to perform detailed analysis" and "NEVER convert number bases yourself - use the int_convert MCP tool" — [README](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/README.md)
  - mcp-windbg's `crash-analyst` agent works one dump, "they see only your final message, so it has to stand alone", and has Write/Edit/Bash disallowed — [crash-analyst.md](https://github.com/svnscha/mcp-windbg/blob/48e4350d57c44a38068be4f64e89a0fe60fe5c04/plugins/mcp-windbg-agents/agents/crash-analyst.md)
- **Per-function summarization / map-reduce:**
  - Project Ire records each function summary in a "chain of evidence" that a validator checks — [Microsoft Research blog](https://www.microsoft.com/en-us/research/blog/project-ire-autonomously-identifies-malware-at-scale/)
  - MalSight summarizes iteratively in call-graph order — [arXiv 2406.18379](https://arxiv.org/abs/2406.18379v1)
  - ReSym aggregates multiple LLM queries with Prolog to stay within token constraints — [ReSym PDF](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
  - ida-pro-mcp's `analyze_component` returns per-function summaries for a group — [api_composite.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/api_composite.py)
- **Single long-context pass (alternative):** Gemini 1.5 Pro handled more than 280k tokens of WannaCry pseudocode "in a single pass" and avoided chunking because it "led to vague and non-specific outcomes". The same post warns it "may encounter limitations when handling exceptionally large binaries" — [Google Cloud blog](https://cloud.google.com/blog/topics/threat-intelligence/gemini-for-malware-analysis)
- **Persisting analysis state instead of re-reading:**
  - ida-pro-mcp's suggested strategy is to rename variables and functions, retype, and "add comments with your findings" in the IDB, and to "Create a report.md" — [README](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/README.md)
  - ReVa records findings with `set-bookmark type="Analysis"` — [deep-analysis SKILL.md](https://github.com/cyberkaida/reverse-engineering-assistant/blob/a05a6b0a18649efd6d74ec8447bdadf8d468c365/ReVa/skills/deep-analysis/SKILL.md)
  - bethington has function tags and `analyze_function_completeness` (one-or-many) — [migration guide](https://github.com/bethington/ghidra-mcp/blob/cf8b12db27eb139b28b90eaa3488306da910d759/docs/project-management/MIGRATION_7.0.0_TOOL_CONSOLIDATION.md)
  - binja-codemode-mcp has `workspace.write/read` "for carrying results between calls" and `skills.save` "saved across sessions" — [README](https://github.com/akrutsinger/binja-codemode-mcp/blob/928c9fa50b56da4127b7deb15f221b139e69fe58/README.md)
- **Server-side caches (performance, not LLM memory):**
  - GhidrAssistMCP's response cache (1,000 entries, 5 min, keyed by program revision) — [McpCache.java](https://github.com/symgraph/GhidrAssistMCP/blob/b575acc1412cafcfd4dc9fedb7f99ecf219c68ab/src/main/java/ghidrassistmcp/cache/McpCache.java)
  - GhydraMCP's "cache decompile results" (2026-06-08) — [GhydraMCP repo](https://github.com/starsong-consulting/GhydraMCP)
  - ida-pro-mcp's strings cache "with MD5-based invalidation" — [README](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/README.md)
- **Off-context bulk data:**
  - ida-pro-mcp parks over-limit results behind a download URL fetched with `curl` into `.ida-mcp/` — [rpc.py](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/ida_mcp/rpc.py)
  - IDA-NO-MCP exports pseudocode to files so the agent can use "indexing, parallelism, chunking" in the IDE — [README_EN](https://github.com/P4nda0s/IDA-NO-MCP/blob/2a48a91da706eb778761bfd47e5bb9dde8b651fb/README_EN.md)
- **Deterministic helpers to avoid wasted turns:** ida-pro-mcp's `int_convert` exists because number-base conversion is "especially problematic" for LLMs — [README](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/README.md)

### Inferences
- A practical binary-mcp workflow, assembled from the above:
  - a single `triage`/survey tool with hard top-N caps on strings, functions by xref count, and imports by category
  - count-only modes on every list tool
  - batch decompile with a per-call token or char budget and `fields=` selection
  - summaries returned before bodies
  - a persistent per-binary notes store (renames, comments, "reviewed" tags) so already-reviewed functions are summarized rather than re-decompiled
  - over-limit results spilled to files or resources instead of being truncated silently
- Sub-agent or map-reduce designs trade more total tokens for a smaller orchestrator context. They fit malware triage across many functions. For small binaries, Google's single-pass results suggest a whole-binary dump into a long-context model can beat chunking.

### Gaps
- No public measurement compares these workflows on token cost and accuracy for RE tasks. ida-mcp-rs's profile benchmark is the only controlled cost measurement found, and it covers tool surface, not workflow.
- Microsoft did not publish how Project Ire stores or compresses its chain of evidence, and Google did not describe overflow handling for binaries beyond the context window.
- No server was found that caches *LLM-written* function summaries server-side for reuse across sessions. The closest are database annotations (comments, bookmarks, tags) and binja-codemode's workspace and skills files.
