# Tool definitions and discovery: cutting the fixed per-session token cost of MCP tool definitions

Researched 2026-10-19. Provenance tags used below:
- **[read]**: I read the primary page (all of it or the relevant part).
- **[search-summary]**: the fact comes only from web-search result summaries. This session's egress policy refused these hosts (HTTP 403 on CONNECT): arxiv.org, blog.cloudflare.com, github.blog, speakeasy.com, cursor.com, developers.openai.com, code.visualstudio.com, engineering.block.xyz, philschmid.de, atlassian.com and getunblocked.com. Treat these facts as lower confidence and check them before quoting.
- **[local]**: I checked it myself in one of these places:
  - a shallow clone of github/github-mcp-server (main @ e3809fe, committed 2026-10-15);
  - a sparse clone of microsoft/vscode-copilot-chat (main @ 5863f5a, committed 2026-05-20; this repo may since have been superseded);
  - the installed fastmcp 2.14.7 in `/home/user/binary-mcp/.venv`;
  - the binary-mcp repo itself.
- **[vendor]**: a claim by the party that ships or sells the technique. **[independent]**: a third-party measurement. **[academic]** / **[preprint]**: a research paper.

## 1. How many tokens do MCP tool definitions cost, and how does tool count affect selection accuracy?

### Takeaway
Published counts put MCP tool definitions at roughly 150-1,900 tokens per tool. One large server therefore costs tens of thousands of tokens before the first user turn. Anthropic's reference setup is 58 tools ≈ 55K tokens, and it has seen 134K. The cost is not only money. Anthropic's own docs say Claude's tool selection "degrades once you exceed 30-50 available tools". The tool-count studies (Anthropic's tool-search evals, RAG-MCP) show large accuracy gains when the visible set is cut. Most of those numbers come from vendor-internal evals or synthetic stress tests, and how much accuracy degrades depends on how much the tools overlap.

### Cited Findings
**Size of definitions: Anthropic (primary)**
- Anthropic's five-server setup totals "58 tools" and consumes "approximately 55K tokens" before the conversation starts. The other figures in the same post are in the table below; see [Anthropic, "Introducing advanced tool use on the Claude Developer Platform", 2025-11-24, Bin Wu](https://www.anthropic.com/engineering/advanced-tool-use) [read; vendor]

  | Setup | Tools | Tokens |
  |---|---|---|
  | GitHub | 35 | ≈26K |
  | Slack | 11 | ≈21K |
  | Sentry | 5 | ≈3K |
  | Grafana | 5 | ≈3K |
  | Splunk | 2 | ≈2K |
  | Jira alone | n/a | ≈17K |
  | Adding more servers | n/a | approaches "100K+ token overhead" |
  | Largest seen before optimization | n/a | 134K |
  | Traditional setup | 50+ | ≈72K of definitions, ≈77K total before work begins |

- Agents connected to thousands of tools "need to process hundreds of thousands of tokens before reading a request"; see [Anthropic, "Code execution with MCP", 2025-11-04, Adam Jones & Conor Kelly](https://www.anthropic.com/engineering/code-execution-with-mcp) [read]
- The Claude API wraps tool definitions in a tool-use system prompt that it builds itself ("Here are the functions available in JSONSchema format: {{ TOOL DEFINITIONS IN JSON SCHEMA }}"). Definitions are therefore input tokens on every request; see [Claude API docs, Define tools, undated, accessed 2026-10-19](https://platform.claude.com/docs/en/agents-and-tools/tool-use/define-tools) [read]. Definitions that tool search loads also "count as input tokens like any other tool definition"; see [Claude API docs, Tool search tool, accessed 2026-10-19](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool) [read]

**Size of definitions: GitHub MCP server and others (third-party; versions, toolsets and tokenizers differ)**
- The full GitHub MCP server's definitions measured ≈42,000 tokens; a later count gave ≈55,000 tokens across 93 tool definitions; see [Unblocked blog](https://getunblocked.com/blog/github-mcp-token-cost/) [search-summary; independent]
- 86 GitHub tool definitions ≈ 14,406 tokens; see [PolicyLayer token-cost page](https://policylayer.com/token-cost/github) [search-summary; method unknown]
- 94 GitHub tools ≈ 17.6k tokens; see [Atlassian, "Announcing mcp-compressor"](https://www.atlassian.com/blog/developer/mcp-compression-preventing-tool-bloat-in-ai-agents) [search-summary; vendor of a compression tool]
- The official GitHub (40 tools) and Linear (27 tools) MCP servers together use 17.1K tokens, 8.5% of a 200K window; see [Cyrus, MCP Tool Search guide](https://atcyrus.com/stories/mcp-tool-search-claude-code-context-pollution-guide) [search-summary]
- Secondary guides collected Claude Code `/context` readouts from Dec 2025 to Apr 2026 (mixed versions). They report the GitHub server at 91 tools ≈ 46,000 tokens and Playwright MCP at 22 tools ≈ 14,300 tokens. One user's "MCP tools" row was 82K tokens (41%); other readouts were as low as 907 tokens (0.5%) once deferral applied; see [morphllm](https://www.morphllm.com/claude-code-context-window), [claudelog](https://claudelog.com/faqs/what-is-context-command-in-claude-code), [wmedia](https://wmedia.es/en/tips/claude-code-context-command-token-usage) [search-summary; I could not tell which guide reported which number]
- Speakeasy says a 400-tool server consumes "over 400,000 tokens" before the first query; see [Speakeasy, "100x token reduction with dynamic toolsets", Nov 2025](https://speakeasy.com/blog/100x-token-reduction-dynamic-toolsets) [search-summary; vendor]
- Cloudflare says its API (2,500+ endpoints) exposed as one MCP tool per endpoint would take ≈ 1.17 million tokens, counted with tiktoken; see [Cloudflare, "Code Mode: give agents an entire API in 1,000 tokens", 2026-02-20](https://blog.cloudflare.com/code-mode-mcp/) [search-summary; vendor]
- GitHub's README: "Enabling only the toolsets that you need can help the LLM with tool choice and reduce the context size." See [github/github-mcp-server README, main @ 2026-10-15](https://github.com/github/github-mcp-server) [read]
- OpenCode's docs say an MCP server "adds to the context, and this can quickly add up if you have a lot of tools", and name the GitHub MCP server as a heavy one; see [OpenCode docs, MCP servers](https://opencode.ai/docs/mcp-servers/) [search-summary]

**What Claude Code's `/context` shows**
- `/context` breaks the context window down by category, including system prompt, system tools, "MCP tools", memory files, messages, free space and the autocompact buffer. A secondary guide says it was introduced in v1.0.86; see [claudelog](https://claudelog.com/faqs/what-is-context-command-in-claude-code) [search-summary]
- The current Claude Code docs say: "MCP tool definitions are deferred by default, so only tool names and server instructions enter context until Claude uses a specific tool. Run `/context` to see what's consuming space." CLI tools "are still more context-efficient than MCP servers because they don't add any per-tool listing"; see [Claude Code docs, Manage costs, accessed 2026-10-19](https://code.claude.com/docs/en/costs) [read]

**Accuracy evidence**
- "Claude's ability to pick the right tool degrades once you exceed 30-50 available tools." See [Claude API docs, Tool search tool](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool) [read; vendor]
- Internal MCP evaluations with large tool libraries: Tool Search raised Opus 4 from 49% to 74% and Opus 4.5 from 79.5% to 88.1%; see [Anthropic, 2025-11-24](https://www.anthropic.com/engineering/advanced-tool-use) [read; vendor-internal eval, not public]
- "One of the most common failure modes we see is bloated tool sets that cover too much functionality or lead to ambiguous decision points about which tool to use. If a human engineer can't definitively say which tool should be used in a given situation, an AI agent can't be expected to do better." The same post describes "context rot" and "n² pairwise relationships for n tokens", and says context is "a finite resource with diminishing marginal returns"; see [Anthropic, "Effective context engineering for AI agents", 2025-09-29](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents) [read]
- "More tools don't always lead to better outcomes", and "Too many tools or overlapping tools can also distract agents from pursuing efficient strategies." See [Anthropic, "Writing effective tools for AI agents", 2025-09-11, Ken Aizawa](https://www.anthropic.com/engineering/writing-tools-for-agents) [read]
- RAG-MCP (arXiv 2505.03275, May 2025) ran a needle-in-a-haystack "MCP stress test": N schemas, one correct and N-1 distractors. Tool-selection accuracy was 13.62% with every schema in the prompt and 43.13% with retrieval, and retrieval cut prompt tokens by "over 50%". An alphaXiv summary says 73%; prefer the paper's own figure. The paper also says retrieval precision degrades as the registry grows; see [arXiv 2505.03275](https://arxiv.org/abs/2505.03275), [alphaXiv overview](https://www.alphaxiv.org/overview/2505.03275v1) [search-summary; academic]
- Secondary write-ups disagree on where accuracy breaks down. One says success stays ">90%" only up to about 30 candidate tools; another describes a cliff "past 100", counted in tools in one account and servers in another; see [Writer engineering](https://writer.com/engineering/rag-mcp/), [StackOne](https://www.stackone.com/blog/agent-tool-count-ceiling/) [search-summary; threshold unresolved]
- "How Many Tools Should an LLM Agent See?" (2026 preprint) uses an RL policy to choose how many tools to show per query. With Claude Sonnet 4.6 downstream it scored 93.1%, against 87.1% when the model was always shown 5 tools; see [alphaXiv 2605.24660](https://www.alphaxiv.org/abs/2605.24660) [search-summary; preprint]
- MTU-Bench reports that "as the number of tools increases", both GPT-3.5 and LLaMA3-70B decline notably; see [arXiv 2410.11710](https://arxiv.org/pdf/2410.11710) [search-summary; academic]
- LongFuncEval reportedly found that accuracy fell substantially as the tool catalog grew, depending on the model, cited by [agentpatterns.ai](https://agentpatterns.ai/tool-engineering/consolidate-agent-tools/) [search-summary; secondary]
- Practitioner estimates put noticeable degradation at about 10-20 tools and serious problems above 40-50. These secondary sources also claim that BFCL calendar-task accuracy fell from 43% to 2% as tools went from 4 to 51, and that GPT-5 scored 63.3% choosing among 100 apps on AppSelectBench. I could not trace either claim to a primary source; see [tianpan.co](https://tianpan.co/blog/2026-04-19-over-tooled-agent-problem), [MachineLearningMastery](https://machinelearningmastery.com/the-complete-guide-to-tool-selection-in-ai-agents/) [search-summary; unverified]
- The text of VS Code Copilot Chat's virtual-tools setting warns that "you experience degraded tool calling once the threshold is hit"; see [vscode-copilot-chat package.nls.json @ 2026-05-20](https://github.com/microsoft/vscode-copilot-chat/blob/main/package.nls.json) [local]
- OpenAI's function-calling guide reportedly recommends "fewer than 20 functions available at the start of a turn", as soft guidance; see [Nerd Level Tech summary](https://nerdleveltech.com/how-many-tools-can-an-ai-agent-handle) [search-summary]

**binary-mcp context (local)**
- binary-mcp registers 147 tools. Counts by category, name prefix and facet are in the table below; see [binary-mcp docs/tool-catalog.json](file:///home/user/binary-mcp/docs/tool-catalog.json) [local]

  | Grouping | Counts |
  |---|---|
  | Category | debugger 49, detection 18, triage 16, census 14, session 10, decompile 7, coverage 6, review 5, annotation 4, reporting 4, jobs 4, threat-intel 4, analysis-run 3, admin 3 |
  | Name prefix | `windbg_` 33, `get_` 20, `x64dbg_` 16, `find_` 9, `analyze_` 7, `detect_` 7 |
  | Facet | runs-engine 41, code-output 13, pseudocode-derived 10, network 5 |

- The catalog's own docstring notes that tool names overlap in what they return: "`batch_decompile`, `get_review_package` and `scan_pseudocode` all hand back decompiled code without `decompile` leading their name"; see [binary-mcp src/tool_catalog.py](file:///home/user/binary-mcp/src/tool_catalog.py) [local]

### Inferences
- The figures above imply these per-tool costs: Anthropic's GitHub server ≈ 740 tokens/tool (26K/35), Slack ≈ 1,900/tool, the five-server average ≈ 950/tool, third-party GitHub counts ≈ 155-590/tool and Speakeasy ≈ 1,000/tool. At 147 tools, that puts binary-mcp's full-load cost very roughly at 25K-140K tokens, or about 12-70% of a 200K window. The real figure has to come from the token audit (task #5); this range only shows that the facet matters.
- In current Claude Code, where tool search is on by default, binary-mcp's fixed cost shrinks to 147 prefixed names plus any server instructions. Each full definition is paid for only when that tool is discovered. Clients without deferral still pay the full definition cost on every request; see Q7.
- binary-mcp has many tools that return pseudocode, plus 49 debugger tools (33 `windbg_`, 16 `x64dbg_`). That is the "ambiguous decision points" pattern Anthropic describes, so trimming the visible set should help accuracy as well as cost. There is no binary-mcp-specific evidence of this yet.
- Per the brief, the 49 debugger tools are Windows-only. Not registering them on Linux hosts removes a third of the roster at no cost to capability.
- The brief's "one `x64dbg` tool instead of 40" overstates the x64dbg family, which has 16 tools by prefix. WinDbg is the larger family, with 33.

### Gaps
- There is no published measurement for binary-mcp itself. The task #5 audit should measure it with Anthropic's token-counting endpoint, with and without `outputSchema`.
- The arXiv full texts were blocked, so RAG-MCP's stress-test curve and exact accuracy threshold are unverified, and the 30-tool vs 100-tool threshold dispute remains open.
- I found no independent replication of Anthropic's 49% → 74% and 79.5% → 88.1% results; the eval set is not public.
- I did not retrieve the per-model fixed token overhead of Anthropic's tool-use system prompt, which is published on the pricing page.

## 2. Anthropic's Tool Search Tool and `defer_loading`, and Claude Code's MCP tool search: how they work, what they save, and what makes a server's tools findable

### Takeaway
On the Claude API you still send every definition with each request. Deferred tools stay out of context until a regex or BM25 search, or a custom search returning `tool_reference` blocks, loads the matches (5 by default). Anthropic reports about 85% fewer tokens and higher accuracy, and prompt caching is preserved. In Claude Code (docs accessed Oct 2026), tool search is **on by default and defers every MCP tool**; the old 10% "auto" threshold is now opt-in. A server needs no changes to be deferred. Whether its tools get found depends entirely on text the server supplies:
- server instructions;
- keyword-dense opening sentences within the first 4,096 characters of each description;
- consistent name prefixes;
- `_meta["anthropic/alwaysLoad"]` on the 3-5 tools Claude needs every session.

### Cited Findings
**Claude API tool search (docs accessed 2026-10-19)**
- There are two server-side variants. `tool_search_tool_regex_20251119` has Claude write Python `re.search()` patterns: case-insensitive, at most 200 characters. `tool_search_tool_bm25_20251119` takes natural-language queries of at most 500 characters. Both search "tool names, descriptions, argument names, and argument descriptions"; see [Claude API docs, Tool search tool](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool) [read]
- How it works; see [same page](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool) [read]:
  - You still "send every tool's full definition in the `tools` array on every request". `defer_loading: true` controls only what enters context.
  - At least one tool must stay non-deferred.
  - A search returns `tool_reference` blocks, 5 by default, with a `limit` Claude can set from 1 to 10,000. The API expands them into full definitions.
  - Discovered tools can be reused in later turns without searching again.
  - A request can carry up to 10,000 deferred tools.
- Caching: deferred tools are excluded from the system-prompt prefix, so "prompt caching is preserved". A deferred tool cannot also carry `cache_control`; the API returns a 400; see [same page](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool) [read]
- With the MCP connector, you set `defer_loading` once on the `mcp_toolset`'s `default_config`, or per tool in `configs`. A custom client-side search, for example over embeddings, can return `tool_reference` blocks from any tool. A discovered tool's `input_examples` are expanded along with its definition; see [same page](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool) [read]
- Supported models as of Oct 2026: Opus 4.5+, Sonnet 4.5+ and Haiku 4.5+, including Opus 5.5, Sonnet 5.5 and Haiku 5.5. "Claude Opus 4.1 and earlier models don't support the tool search tool." On Bedrock it is available only through InvokeModel, not Converse; see [same page](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool) [read]
- When to use it: 10 or more tools; definitions over 10k tokens; accuracy dropping as the toolset grows; aggregated MCP servers (200+ tools); a growing library. Standard tool calling fits better with fewer than 10 tools, when every tool is used in every request, or when definitions total under 100 tokens; see [same page](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool) [read]
- Discoverability tips; see [same page](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool) [read]:
  - Keep the 3-5 most-used tools non-deferred.
  - Write clear names and descriptions.
  - Use "consistent namespacing … prefix by service or resource (for example, `github_`, `slack_`) so one search matches the whole group".
  - Use "keywords in descriptions that match how users describe tasks".
  - Add a system-prompt section that lists the tool categories.
  - Monitor which tools Claude discovers.
  - When tools aren't found: "Add common keywords to tool descriptions to improve discoverability."
- Tool search is not metered separately. Loaded definitions are billed as input tokens; see [same page](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool) [read]
- Results and caveats reported at launch (2025-11-24); see [Anthropic, advanced tool use](https://www.anthropic.com/engineering/advanced-tool-use) [read; vendor]:
  - It launched behind the `advanced-tool-use-2025-11-20` beta header.
  - Context fell from ≈77K to ≈8.7K tokens, an "85% reduction"; the chart caption says 191,300 tokens preserved against 122,800.
  - It "adds a search step before tool invocation".
  - It is less useful with fewer than 10 tools, when every tool is used every session, or when definitions are compact.
  - Keep the "three to five most-used tools always loaded".
- The current quick-start request sends only `anthropic-version`, with no beta header; see [Tool search tool docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool) [read]. The launch-era beta header therefore appears to be superseded, though the excerpt I read showed no explicit status label.

**Claude Code MCP tool search (docs accessed 2026-10-19; they cite versions up to v2.1.296)**
- "Tool search keeps MCP context usage low by deferring tool definitions until Claude needs them. Only tool names and server instructions load at session start… Claude Code doesn't impose a fixed per-server tool cap; the practical limit is your context window budget." See [Claude Code docs, MCP](https://code.claude.com/docs/en/mcp) [read]
- `ENABLE_TOOL_SEARCH` values; see [same](https://code.claude.com/docs/en/mcp) [read]:

  | Value | Behaviour |
  |---|---|
  | unset | All MCP tools deferred. Falls back to loading upfront on models earlier than Opus 4 and Sonnet 4, on Agent Platform models earlier than the 4.5 generation, when `ANTHROPIC_BASE_URL` is a non-first-party host, or on Microsoft Foundry hosted on Azure. |
  | `true` | Keeps deferring through non-first-party proxies. Requests fail on proxies that don't support `tool_reference` blocks. |
  | `auto` | Loads tools upfront while their definitions are under 10% of the context window, and defers all of them once they reach 10%. |
  | `auto:N` | The same, with a custom percentage `N` (0-100). |
  | `false` | All MCP tools load upfront, with no deferral. |

- Tool search is also kept off when `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS` is set and in HIPAA-configured sessions. The `ToolSearch` tool can be denied with `permissions.deny`; see [same](https://code.claude.com/docs/en/mcp) [read]
- Claude Code uses tool search on "Claude Opus 4, Claude Sonnet 4, Claude Haiku 4.5, and later models". On earlier models it loads all MCP tools upfront, and `ENABLE_TOOL_SEARCH=true` does not override that; see [same](https://code.claude.com/docs/en/mcp) [read]
- For server authors: "the server instructions field becomes more useful with tool search enabled. Server instructions help Claude understand when to search for your tools." The instructions should explain what category of tasks the tools handle, when Claude should search for them, and the server's key capabilities; see [same](https://code.claude.com/docs/en/mcp) [read]
- Truncation; see [same](https://code.claude.com/docs/en/mcp) [read]:
  - Server instructions, and the descriptions of tools that load upfront, are cut at 4,096 characters.
  - Descriptions of tools loaded through tool search are cut at 16,384 characters.
  - "When tool search matches Claude's query against a tool's description, it reads only the part within the shorter limit, so put the words Claude would search for near the start."
  - Before v2.1.296 the shorter limit was 2,048 characters, and before v2.1.295 it applied to every description.
  - `CLAUDE_CODE_MAX_MCP_DESCRIPTION_LENGTH` (v2.1.280+) replaces both limits.
- Controlling what loads upfront; see [same](https://code.claude.com/docs/en/mcp) [read]:
  - A server author can set `_meta["anthropic/alwaysLoad"]` on a tool. `true` loads that tool upfront.
  - `false` keeps the tool deferred even when the user's server config sets `"alwaysLoad": true`. This needs v2.1.285+ and applies to `--mcp-config`, Agent SDK and plugin servers.
  - A user can set `alwaysLoad: true` on a whole server in their config. Startup then waits for that server, capped at the 5-second connect timeout.
  - Server-level `alwaysLoad: false` defers every tool, including author-marked ones (v2.1.287+).
- If a server connects mid-turn, Claude Code "lists the server's tool names to Claude on its next request in the same turn". `ToolSearch` waits for pending servers; see [same](https://code.claude.com/docs/en/mcp) [read]
- Superseded behaviour: early-2026 guides describe deferral only "when MCP tool descriptions exceed 10% of your context window", via an "MCPSearch" tool; see [Cyrus](https://atcyrus.com/stories/mcp-tool-search-claude-code-context-pollution-guide), [claudelog](https://claudelog.com/faqs/what-is-tool-search-in-claude-code/) [search-summary]. That is now the opt-in `auto` mode; the default defers everything; see [Claude Code docs, MCP](https://code.claude.com/docs/en/mcp) [read]
- A real example of server instructions: the GitHub MCP server builds them from the enabled inventory (`generateInstructions(inv *Inventory)`). They include "Tool selection guidance" and "Context management" ("Use pagination whenever possible with batches of 5-10 items. Use minimal_output parameter set to true if the full information is not needed"); see [github-mcp-server pkg/inventory/instructions.go](https://github.com/github/github-mcp-server/blob/main/pkg/inventory/instructions.go) [local]. GitHub's changelog of 2025-10-29 announced that the server "now comes with server instructions"; see [GitHub changelog](https://github.blog/changelog/2025-10-29-github-mcp-server-now-comes-with-server-instructions-better-tools-and-more) [search-summary]

**Equivalent features in other clients**
- OpenAI's Responses API also has tool search; see [OpenAI docs, Tool search](https://developers.openai.com/api/docs/guides/tools-tool-search) [search-summary]:
  - `defer_loading: true` can be set on functions, on functions inside namespaces, or on an MCP server tool.
  - It runs in a hosted mode or a client-executed mode (`tool_search_call` / `tool_search_output`).
  - OpenAI recommends namespaces or MCP servers because "models have primarily been trained to search those surfaces".
- Cursor's "dynamic context discovery" keeps a compact catalog of servers and tool names in context, and loads a tool's full description and schema only when it is needed; see [Cursor blog](https://cursor.com/blog/dynamic-context-discovery), [Cursor forum staff reply](https://forum.cursor.com/t/what-do-your-attached-mcp-servers-actually-cost-you-in-tokens-per-request-i-measured-it/166405), [Vantaige](https://vantaige.io/blog/cursor-3-3-context-breakdown-what-to-cut-first) [search-summary; vendor]:
  - Cursor reports 46.9% fewer total agent tokens in runs that called an MCP tool, from an A/B test. Vantaige dates the change to 2026-01-06.
  - Staff caveat: attached servers still have a nonzero cost, and definitions once loaded stay in the conversation history.
- VS Code has its own equivalent, "virtual tools"; see Q4.

### Inferences
- binary-mcp needs no server change to be deferred in Claude Code, but its discoverability then rests entirely on text it supplies. It currently supplies no server instructions: `app = FastMCP("binary-mcp")` at src/server.py:119, and grep finds no `instructions` argument anywhere in the file; see [binary-mcp src/server.py](file:///home/user/binary-mcp/src/server.py) [local]. Under Claude Code's default, the highest-leverage change is short instructions (well under 4,096 characters) that cover:
  - what the server does: static RE through Ghidra, ILSpy and pefile, and live debugging through x64dbg and WinDbg on Windows;
  - the entry-point workflow: triage, then analysis job, then census, then decompile;
  - when to search;
  - that samples are never executed.
- Name prefixes matter for regex search: `windbg_` and `x64dbg_` already group well, but Ghidra and .NET tools have no family prefix. A query like "ghidra" matches only tools whose descriptions mention Ghidra. Search returns 5 tools by default, so it cannot load a 33-tool `windbg_` family at once unless Claude raises `limit`. Consolidation (Q5) and tool search therefore complement each other.
- 3-5 entry tools should load upfront via `_meta["anthropic/alwaysLoad"]: true`, for example triage/`analyze_binary`, job status and session list. Whether FastMCP 2.x passes per-tool `meta` through is for task #6 to confirm.
- Each tool's first sentence should be a keyword-dense summary (engine, artefact, action). Only the first 4,096 characters are searchable, and the first sentence is also what discovery ranking reads.
- Deferred definitions sit outside the cached prefix. Tool search therefore also avoids the cache-invalidation cost that runtime tool-list changes impose (Q4).

### Gaps
- I found no independent accuracy measurement of Claude Code's MCP tool search, and no data on how often Claude fails to search for a deferred tool it would have needed. The upfront names list mitigates the second problem.
- I found no accessible source on whether Claude Desktop or claude.ai connectors defer MCP tools; the [search turned up nothing official](https://composio.dev/blog/how-to-better-your-claude-cowork-experience-with-mcps).
- The docs do not say whether Claude Code's `ToolSearch` matches argument descriptions in the same way as the API tool, or how `notifications/tools/list_changed` interacts with deferral.
- **Conflict to resolve:** the API docs say "Claude Opus 4.1 and earlier models don't support the tool search tool" ([Tool search tool](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool)). Claude Code's docs say it uses tool search on "Claude Opus 4, Claude Sonnet 4, Claude Haiku 4.5, and later models" ([Claude Code docs, MCP](https://code.claude.com/docs/en/mcp)). Claude Code may run its own client-side `ToolSearch` that returns `tool_reference` blocks rather than the server-side API tool. That is my inference; the sources don't say.

## 3. "Code execution with MCP", Cloudflare Code Mode and Programmatic Tool Calling: how they work, what they cost, and whether they fit a malware-analysis server

### Takeaway
All three have the model write code against tools. Definitions become an on-demand code API, explored through a filesystem or a search, and intermediate results stay out of context. Reported savings are large:
- Anthropic's 98.7% is an illustrative workflow, not a benchmark;
- Cloudflare's 99.9% is for an API with 2,500 endpoints;
- PTC saves 20-40% typically, and 37-38% in internal evals.

But each needs a sandbox, and each needs a client or API path that implements it. None of them executes the malware sample. They do, however, put model-written code next to attacker-controlled strings (decompiled output). PTC is a Claude Developer Platform feature (Claude API, Claude Platform on AWS, Microsoft Foundry) and cannot call MCP-connector tools. I found no evidence that Claude Code, Claude Desktop or OpenCode expose it for MCP servers. For binary-mcp, the usable lessons are to avoid hosting an arbitrary-code "execute" tool and to get most of the benefit from server-side workflow tools, a CLI path and progressive disclosure, none of which needs a sandbox.

### Cited Findings
**Anthropic, "Code execution with MCP" (2025-11-04)**; see [source](https://www.anthropic.com/engineering/code-execution-with-mcp) [read]
- MCP servers are presented as code APIs on a filesystem, for example `./servers/google-drive/getDocument.ts`. The agent explores the tree and reads only the tool files it needs.
- Alternatively, a `search_tools` tool can return results at a chosen detail level: name only, name and description, or the full definition with schemas.
- It claims token use falls "from 150,000 tokens to 2,000 tokens, a time and cost saving of 98.7%" for a Google Drive → Salesforce transcript workflow. No methodology is given, so treat the figure as illustrative.
- Other benefits it lists:
  - the client can tokenize PII (e.g. "[EMAIL_1]");
  - agents can persist state in files and save code as reusable skills;
  - data can be filtered in code (the example shows five rows of 10,000).
- Costs, quoted: "Running agent-generated code requires a secure execution environment" with "sandboxing, resource limits, and monitoring". "These infrastructure requirements add operational overhead and security considerations that direct tool calls avoid."

**Cloudflare Code Mode**
- "Code Mode: the better way to use MCP" (Kenton Varda & Sunil Pai; a mirror dates it 2025-09-26); see [Cloudflare blog](https://blog.cloudflare.com/code-mode/) [search-summary; vendor]:
  - Method: "Convert the MCP tools into a TypeScript API, and then ask an LLM to write code that calls that API."
  - Claim: agents "handle many more tools, and more complex tools" this way, plausibly because models saw far more real TypeScript than contrived tool-call examples in training. Conclusion: "LLMs are better at writing code to call MCP, than at calling MCP directly."
- "Code Mode: give agents an entire API in 1,000 tokens" (2026-02-20); see [Cloudflare blog](https://blog.cloudflare.com/code-mode-mcp/), [InfoQ, Apr 2026](https://infoq.com/news/2026/04/cloudflare-code-mode-mcp-server), [Cloudflare docs](https://developers.cloudflare.com/agents/model-context-protocol/cloudflare/servers-for-cloudflare/) [search-summary; vendor]:
  - The server has two tools. `search()` runs model-written code against the OpenAPI spec, which stays on the server. `execute()` runs model-written code with an authenticated request function.
  - It uses about 1,000 tokens for more than 2,500 endpoints, against ≈ 1.17M tokens for the same API as native tools: a 99.9% cut, counted with tiktoken.
  - The code runs in an isolated "Dynamic Worker" sandbox.

**Programmatic Tool Calling (PTC): Claude API docs, accessed 2026-10-19**; see [source](https://platform.claude.com/docs/en/agents-and-tools/tool-use/programmatic-tool-calling) [read]
- Status and requirements:
  - The docs mark it GA, and "not-eligible" for ZDR.
  - Platforms: Claude API (GA), Claude Platform on AWS (GA), and Microsoft Foundry only on a "Hosted on Anthropic" deployment.
  - It requires `code_execution_20260120` or a later tool version.
  - Claude Haiku 4.5 accepts that tool version but doesn't support PTC.
- How it works:
  - Tools whose `allowed_callers` include `code_execution_20260120` are exposed to Claude's code as async Python functions.
  - Each call pauses the response with a `tool_use` block whose `caller` names the code-execution run. **Your application** executes the tool and returns the result.
  - "Tool results from programmatic invocations do not count toward your input/output token usage. Only the final code execution result and Claude's response count."
- Restrictions:
  - "Tools provided by an MCP connector" cannot be called programmatically.
  - It is incompatible with `strict: true`, forced `tool_choice` and `disable_parallel_tool_use`.
  - Schemas with a recursive `$ref` are rejected.
- Security:
  - `allowed_callers` "is not a hard API-level block … Do not rely on `allowed_callers` as a security boundary."
  - "Tool results are returned as strings: They can contain any content, including code snippets or executable commands that may be processed by the execution environment … be aware of code injection risks."
- Timing: idle containers are reclaimed after about 5 minutes; a pending programmatic call times out after about 4 minutes with a `TimeoutError`; no container is reused more than 30 days after creation.
- Measured savings, all internal:
  - a 75-tool project-management benchmark: about -38% billed input tokens, "with no change in task accuracy";
  - τ²-bench (one or two sequential calls per turn): scores unchanged, about 8% *more* cost;
  - production traffic with 10-49 tools: typical savings of 20-40%;
  - BrowseComp/DeepSearchQA: +11% performance with 24% fewer input tokens.
- Fit:
  - Strong: fan-out, large filterable results, agentic search.
  - Weak: strictly sequential reasoning between calls, a few small calls, and calls that need user feedback.
- Alternatives the docs compare: client-side direct execution "Executes untrusted code outside of a sandbox"; self-managed sandboxed execution.
- At launch (2025-11-24); see [Anthropic, advanced tool use](https://www.anthropic.com/engineering/advanced-tool-use) [read; vendor-internal]:
  - average tokens fell from 43,588 to 27,297 (37%);
  - internal knowledge retrieval improved from 25.6% to 28.5%, and GIA from 46.5% to 51.2%;
  - a 20+-call workflow "eliminate[s] 19+ inference passes";
  - it is less useful for single calls, or when "Claude should see and reason about all intermediate results".
  - The launch used `code_execution_20250825`, which the 20260120 version requirement has superseded.

**Relevant client and binary-mcp facts**
- Claude Code's guidance: "Prefer CLI tools when available … they don't add any per-tool listing. Claude can run CLI commands directly." See [Claude Code docs, Manage costs](https://code.claude.com/docs/en/costs) [read]
- binary-mcp's security guarantee: "Samples are never executed by this server and never uploaded anywhere: no tool can launch a binary (see docs/security.md)"; see [binary-mcp src/server.py module docstring](file:///home/user/binary-mcp/src/server.py) [local]

### Inferences
- **The sample itself:** none of these patterns runs it; the sandbox runs orchestration code.
- **Injection risk:** output derived from the sample (strings, pseudocode, resource names) is adversary-controlled. Model-written code that parses or evaluates it is a code-injection path, which the PTC docs warn about explicitly. In a Code-Mode-style design, binary-mcp would host an `execute(code)` tool inside the process that holds samples, Ghidra projects and debugger sessions. That is an arbitrary-code primitive, and it contradicts the "no tool can launch a binary" posture unless the code is isolated: a separate container, no network, read-only mounts and resource limits.
- **Duration:** Ghidra analyses can run longer than PTC's ~4-minute pending-call timeout, so PTC-based orchestration would need the existing job-ID pattern.
- **Client reach:** binary-mcp's users are Claude Code, Claude Desktop and OpenCode. None of the sources shows them offering Code Mode for arbitrary MCP servers. PTC is API-only and excludes MCP-connector tools, so it only helps someone building an API agent that re-wraps binary-mcp tools as client tools. The realistic equivalents are:
  1. **Server-side workflow tools** that chain steps internally and return a summary, e.g. triage → analysis job → top-N suspicious functions with short excerpts. This keeps the "intermediate results stay out of context" benefit with no sandbox.
  2. **A CLI entry point** (e.g. `binary-mcp-cli decompile …`) that Claude Code or OpenCode runs through the shell. It has zero per-tool listing cost, but its output still enters context and it loses MCP's structured results and annotations.
  3. **Progressive disclosure** borrowed from Code execution with MCP: a `search_tools` tool with detail levels (Q4), which needs no code execution.
- **Bottom line:** for a malware-analysis server, the code-execution family is a poor fit as a primary technique. Its token wins are mainly about intermediate *results* (task #2's scope) rather than definitions, and Q2's deferral already handles definitions in Claude Code.

### Gaps
- There is no independent replication of the 98.7% or 99.9% figures. The Cloudflare posts were blocked, so their sandbox details (isolation, network policy, startup latency) were not read first-hand.
- I did not retrieve pricing for code-execution containers (the PTC docs defer to the code-execution pricing page).
- I found no evidence on whether Claude Desktop or OpenCode ship any Code Mode adapter as of Oct 2026.

## 4. Dynamic toolsets, meta-tool patterns, tool retrieval, and toolset profiles

### Takeaway
There are three families, compared in the matrix under Inferences:
1. **Static profiles chosen at startup** (GitHub's `--toolsets`, `--tools`, `--exclude-tools`, read-only, env vars, and remote URL paths or headers). Simple, cache-friendly, no extra round trips, and they work in clients with hard caps. GitHub kept and extended this path.
2. **Runtime discovery on the server**, either as enable-toolset meta-tools plus `tools/list_changed` (GitHub's `--dynamic-toolsets` is gone from its code as of Oct 2026), or as search/describe/execute proxies (Speakeasy Gram, Atlassian mcp-compressor, MCP-Zero). Vendors report 90-99% token cuts, at the cost of one or two extra calls, dependence on ranking quality, and the loss of per-tool identity.
3. **Client-side retrieval** (Claude Code and Claude API tool search, Cursor, VS Code virtual tools, OpenAI tool search). This increasingly makes family 2 redundant for capable clients.

The failure modes are extra round trips, missed tools, prompt-cache invalidation when the tool list changes, and clients that ignore `list_changed`.

### Cited Findings
**GitHub MCP server: static profiles (repo main @ 2026-10-15)**
- Configuration options (local: CLI flags or environment variables; remote: headers or URL paths); see [docs/server-configuration.md](https://github.com/github/github-mcp-server/blob/main/docs/server-configuration.md) [local]:

  | Option | Remote server | Local server |
  |---|---|---|
  | Toolsets | `X-MCP-Toolsets` header or `/x/{toolset}` URL path | `--toolsets` / `GITHUB_TOOLSETS` |
  | Individual tools | `X-MCP-Tools` | `--tools` / `GITHUB_TOOLS` |
  | Excluded tools | `X-MCP-Exclude-Tools` | `--exclude-tools` / `GITHUB_EXCLUDE_TOOLS` |
  | Read-only | `X-MCP-Readonly` header or `/readonly` URL suffix | `--read-only` / `GITHUB_READ_ONLY` |
  | Lockdown, Insiders, feature flags | separate headers | separate flags |

  - With no configuration the server loads the default toolsets: `context`, `issues`, `pull_requests`, `repos`, `users`.
  - The options are "composable". Excluded tools take precedence over everything, and read-only takes precedence over explicit requests.
  - The individual-tools option is "Best for: users who know exactly what they need and want to optimize context usage by loading only the tools they will use."
- Every remote toolset has its own URL, e.g. `https://api.githubcopilot.com/mcp/x/all/readonly`; see [docs/remote-server.md](https://github.com/github/github-mcp-server/blob/main/docs/remote-server.md), [server-configuration.md](https://github.com/github/github-mcp-server/blob/main/docs/server-configuration.md) [local]
- GitHub's 2025-12-10 changelog: loading 3-10 of the most-used tools can cut context-window usage by about 60-90% compared with the default toolsets; see [GitHub changelog](https://github.blog/changelog/2025-12-10-the-github-mcp-server-adds-support-for-tool-specific-configuration-and-more) [search-summary; vendor estimate, no token counts]
- The `--dynamic-toolsets` flag named in the brief no longer exists: grep finds "dynamic-toolsets", "DynamicToolsets", `enable_toolset` and `list_available_toolsets` nowhere in `cmd/`, `pkg/`, `internal/`, `docs/` or the README at commit e3809fe (2026-10-15); see [github/github-mcp-server](https://github.com/github/github-mcp-server) [local]. I could not find when or why it was removed.
- GitHub issue #2996 (opened 2026-08-02, still open, no maintainer reply): "Benchmark and improve tool-search ranking with indexed BM25". It concerns ranking "inside the server's existing tool-search implementation", which it says is separate from host-side deferred loading (#1680). A commenter's 49-case replication found the current heuristic at only R@1 0.367 and R@3 0.571; see [GitHub issue #2996](https://github.com/github/github-mcp-server/issues/2996) [read]. The author's prototype results over 49 queries and 115 tools:

  | Ranking | Recall@1 | Recall@3 | MRR@10 | Latency |
  |---|---|---|---|---|
  | Current heuristic | 71.4% | 81.6% | 0.792 | ~2.25 ms |
  | Indexed BM25 | 71.4% | 87.8% | 0.802 | ~34 µs (≈66× faster) |
  | Hybrid RRF | 73.5% | 87.8% | 0.823 | not reported |

- My grep of main found no tool-search tool; the only matches were GitHub content-search tools such as `search_code`; see [github/github-mcp-server](https://github.com/github/github-mcp-server) [local]. Whether the "existing tool-search implementation" lives behind a flag, on a branch or in the remote server is unresolved.

**Server-side meta-tools and proxies**
- Speakeasy Gram "dynamic toolsets": meta-tools let the model discover only what it needs, through a search → describe → execute flow (three meta-tools, including `search_tools`); the docs label it experimental; see [Speakeasy, Nov 2025](https://speakeasy.com/blog/100x-token-reduction-dynamic-toolsets), [Speakeasy v2, 2025-11-18](https://www.speakeasy.com/blog/how-we-reduced-token-usage-by-100x-dynamic-toolsets-v2), [Speakeasy docs](https://www.speakeasy.com/docs/mcp/build/toolsets/dynamic-toolsets) [search-summary; vendor]
  - A 400-tool static server uses more than 400,000 tokens, against "a few thousand" initially with dynamic toolsets.
  - v2 claims up to 160× reduction with 100% task success, and average cuts of 96% in input tokens and 90% in total tokens.
- A third-party guide notes that dynamic discovery adds 1-2 extra tool calls per interaction, but argues total tokens and latency usually still fall; see [mcpservers.org](https://blog.mcpservers.org/posts/reducing-mcp-token-usage-by-100x) / [ChatForest](https://chatforest.com/guides/mcp-cost-optimization/) [search-summary; I could not tell which of the two made this claim]. I found no independent replication of Speakeasy's numbers.
- Atlassian Labs mcp-compressor: an open-source proxy that replaces a server's tool list with two wrappers, `get_tool_schema` and `invoke_tool`, and claims 70-97% less tool-description overhead. Its baseline example is GitHub's 94 tools at ≈ 17.6k tokens; see [Atlassian blog](https://www.atlassian.com/blog/developer/mcp-compression-preventing-tool-bloat-in-ai-agents) [search-summary; vendor]. Compression levels of low, medium, high and max, and "up to 99%", appear only in a third-party listing; see [Glama](https://glama.ai/mcp/servers/h9qylpupcf) [search-summary; unverified]
- A community GitHub-MCP fork reportedly groups 26 tools into 7 "semantic operations" for a 71.5% token cut; see [LobeHub listing](https://lobehub.com/mcp/mcpslim-github-slim) [search-summary; self-reported; attribution uncertain]

**Retrieval research**
- MCP-Zero (arXiv 2506.01056, June 2025; Fei, Zheng & Feng); see [arXiv](https://arxiv.org/abs/2506.01056) [search-summary; academic]:
  - The model itself emits structured tool requests, which go through coarse-to-fine retrieval (server, then tool) in an iterative loop.
  - Prompts shrank by 60-98%; the extreme case on APIBank went from 6,308.2 to 111.0 tokens (-98.24%), "with accuracy kept high".
  - It ships the MCP-tools dataset: 308 servers and 2,797 tools.
- ScaleMCP (arXiv 2505.06416, May 2025; Lumer et al., PwC); see [arXiv](https://arxiv.org/abs/2505.06416) [search-summary; academic]:
  - Agents add tools to their own memory; the MCP servers are the source of truth, kept in sync with CRUD operations.
  - A "Tool Document Weighted Average" (TDWA) embedding weights parts of a tool document, such as its name or synthetic questions.
  - It was evaluated on 5,000 financial-metric MCP servers with 10 LLMs, 5 embedding models and 5 retriever types; I could not retrieve exact gains.
- RAG-MCP (13.62% → 43.13%, >50% fewer tokens) is in Q1. Its retrieval precision "degrade[s] as the tool registry scales"; see [arXiv 2505.03275](https://arxiv.org/abs/2505.03275) [search-summary]

**Client-side grouping and retrieval**
- VS Code Copilot Chat source (main @ 2026-05-20); see [configurationService.ts](https://github.com/microsoft/vscode-copilot-chat/blob/main/src/platform/configuration/common/configurationService.ts), [virtualToolsConstants.ts](https://github.com/microsoft/vscode-copilot-chat/blob/main/src/extension/tools/common/virtualTools/virtualToolsConstants.ts), [virtualToolGrouper.ts](https://github.com/microsoft/vscode-copilot-chat/blob/main/src/extension/tools/common/virtualTools/virtualToolGrouper.ts), [package.json](https://github.com/microsoft/vscode-copilot-chat/blob/main/package.json), [package.nls.json](https://github.com/microsoft/vscode-copilot-chat/blob/main/package.nls.json) [local]:
  - `HARD_TOOL_LIMIT = 128`.
  - `github.copilot.chat.virtualTools.threshold`: number, 0-128, default 128, tagged experimental and experiment-based; 0 disables it.
  - Constants: `START_GROUPING_AFTER_TOOL_COUNT = 64`, `START_BUILTIN_GROUPING_AFTER_TOOL_COUNT = 20`, `TRIM_THRESHOLD = 96`, `GROUP_WITHIN_TOOLSET = 16`, `NUM_EMBED_MATCHED_TOOLS = 10`.
  - Groups are categorized with a `copilot-fast` model. Each group tool's description starts "Call this tool when you need access to a new category of tools…".
  - The setting text: "Virtual tools group similar sets of tools together and they allow the model to activate them on-demand. Certain tool groups will optimistically be pre-activated."
- GitHub Copilot "fewer tools" post; see [GitHub blog](https://github.blog/ai-and-ml/github-copilot/how-were-making-github-copilot-smarter-with-fewer-tools/) [search-summary]:
  - It cut the default 40 built-in tools to 13 core tools, with "embedding-guided tool routing" and adaptive clustering.
  - Secondary coverage reports +2-5 percentage points task success and about -400 ms average latency; unverified against the post; see [Blockchain.News](https://blockchain.news/news/github-copilot-enhances-efficiency-by-streamlining-tool-usage) [search-summary].
  - A June 2026 write-up says client-side embedding-guided tool search added a further 1-4% latency reduction for Anthropic-backed models; see [Let's Data Science](https://letsdatascience.com/news/github-improves-copilot-context-handling-and-model-routing-953d85c3) [search-summary]
- Cursor's dynamic context discovery (46.9%) and OpenAI's tool search are covered in Q2.

**Server mechanics available to binary-mcp (FastMCP 2.14.7, local)**
- `FastMCP(..., include_tags=..., exclude_tags=...)` constructor parameters exist and filter components by tag; see [fastmcp/server/server.py L171-172, L256-260](file:///home/user/binary-mcp/.venv/lib/python3.13/site-packages/fastmcp/server/server.py) [local]
- `Tool.enable()` and `Tool.disable()` call `context._queue_tool_list_changed()`, so toggling at runtime emits `notifications/tools/list_changed`; see [fastmcp/tools/tool.py L151-163](file:///home/user/binary-mcp/.venv/lib/python3.13/site-packages/fastmcp/tools/tool.py) [local]
- binary-mcp's `docs/configuration.md` documents no toolset or profile option today; grep for "toolset" and "profile" found none; see [binary-mcp docs/configuration.md](file:///home/user/binary-mcp/docs/configuration.md) [local]

**Cost of changing the tool list mid-session**
- Claude Code's `/usage` reports cache misses with a "likely cause", for example "likely cause: tool definitions changed" (v2.1.260+); see [Claude Code docs, Manage costs](https://code.claude.com/docs/en/costs) [read]
- Claude API tool search avoids that cost because deferred tools sit outside the cached prefix; see [Tool search tool docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool) [read]
- OpenCode can disable tools by name or glob (e.g. `"my-mcp*": false`) and re-enable them per agent; see [OpenCode docs](https://opencode.ai/docs/mcp-servers/) [search-summary]

### Inferences
- **Lowest-risk win:** a startup profile keyed on binary-mcp's existing `category:` tags, e.g. `BINARY_MCP_TOOLSETS=triage,census,decompile` or `--toolsets`, with `default` and `all`. It is client-agnostic, works under the hard caps in Cursor, Windsurf and VS Code, keeps the prompt cache stable, and needs no extra round trips. FastMCP 2.14.7's `include_tags`/`exclude_tags` already do the filtering. Pair it with platform gating so that the 49 debugger tools are not registered off Windows.
- **Runtime enable-toolset meta-tools are less attractive in 2026:**
  - capable clients already defer and retrieve (Claude Code, Cursor, VS Code);
  - support for `list_changed` varies by client;
  - every change can invalidate the prompt cache in clients that put tools in the prefix;
  - GitHub, the reference implementation, no longer ships the flag.
- **A server-side search/describe/invoke facade** (Speakeasy- or mcp-compressor-style) is worth it only for clients without deferral, and costs binary-mcp something specific. With a single `invoke` tool name, Claude Code's per-tool permission rules, PreToolUse hooks and the `code-output` facet gating that `tool_catalog.py` exists to support all stop working. Read-only and destructive annotations would also be lost. If it is offered at all, make it an opt-in profile, not the default.
- **Ranking is the failure point** for any search-based design: GitHub's own heuristic reached only 81.6% Recall@3 on 115 tools (57.1% in the replication). Good names and first sentences, and BM25 over names plus descriptions, matter more than the mechanism.

**Technique matrix for binary-mcp.** The numbers repeat the sourced findings in Q1-Q6:

| Technique | Reported savings | Accuracy evidence | Server work | Client support | Main trade-offs |
|---|---|---|---|---|---|
| Startup toolset profiles | GitHub: ~60-90% context cut loading 3-10 tools vs defaults ([changelog](https://github.blog/changelog/2025-12-10-the-github-mcp-server-adds-support-for-tool-specific-configuration-and-more), search-summary) | Qualitative ("help the LLM with tool choice", [README](https://github.com/github/github-mcp-server)) | Flag/env → `include_tags`/`exclude_tags`; platform gating | All clients | Hidden tools are unknown to the model; restart to change |
| Client deferral (Claude API / Claude Code tool search) | 77K → 8.7K, -85% ([Anthropic](https://www.anthropic.com/engineering/advanced-tool-use)) | Opus 4 49 → 74%; Opus 4.5 79.5 → 88.1% (internal) | None required; instructions, prefixes, keyword-first descriptions, `alwaysLoad` meta | Claude Code (default), Claude API; Cursor (-46.9% tokens, [blog](https://cursor.com/blog/dynamic-context-discovery), search-summary); OpenAI | Extra search step; tools missed when text lacks keywords; 5 results per search by default |
| VS Code virtual tools | n/a | Setting warns of "degraded tool calling" | None | VS Code (above the threshold) | Groups categorized by a model; activation round trip |
| Server meta-tools (search/describe/execute) | Up to 160×, avg -96% input ([Speakeasy](https://www.speakeasy.com/blog/how-we-reduced-token-usage-by-100x-dynamic-toolsets-v2)); 70-97% ([Atlassian](https://www.atlassian.com/blog/developer/mcp-compression-preventing-tool-bloat-in-ai-agents)); both search-summary | "100% success" (vendor) | Search index + dispatcher + validation | Any client | +1-2 calls; breaks per-tool permissions, hooks and annotations; depends on ranking |
| Runtime enable_toolset + `list_changed` | Not measured | None found | Meta-tool; FastMCP `enable()`/`disable()` | Needs `list_changed` support | Cache invalidation; GitHub dropped the flag |
| Retrieval research (RAG-MCP, MCP-Zero, ScaleMCP) | >50%; 60-98% | 13.62 → 43.13% | Embedding index | Custom agents | Research prototypes; precision falls with scale |
| Code execution / Code Mode / PTC | 98.7% (illustrative); 99.9% (Cloudflare); PTC 20-40%, but +8% cost on τ²-bench | PTC +2.9 / +4.7 pp (internal) | Sandbox (Code Mode) or none (PTC) | PTC: Claude API only, not MCP-connector tools | Code injection from sample-derived strings; ~4-minute call timeout |
| Consolidation (action enums) | 71.5% (community, unverified) | MCP-GRANITE: middle granularity best, monolithic worse (Q5) | Refactor + server-side validation | All clients | Larger schemas; per-action required parameters unenforced; hooks must inspect arguments |
| Description/schema trimming | No published figures for titles or `anyOf` | Descriptions are "by far the most important factor" (Q6) | Docstring/Field edits | All clients | Over-trimming hurts selection and search recall |
| CLI instead of MCP | "no per-tool listing" ([costs](https://code.claude.com/docs/en/costs)) | n/a | CLI entry point | Claude Code, OpenCode (shell) | Output still enters context; no structured results or annotations |

### Gaps
- I did not retrieve Speakeasy's per-task tables, latency or failure rates, and found no independent replication.
- The history and rationale for GitHub removing `--dynamic-toolsets` were not found, and GitHub's "existing tool-search implementation" (issue #2996) was not located in main.
- MCP-Zero and ScaleMCP accuracy details came from abstract-level summaries only.
- How binary-mcp's target clients handle `tools/list_changed` (whether they re-fetch, defer, or invalidate the cache) is task #6's scope.

## 5. Tool consolidation and design guidance: workflow-level tools and multiplexed `action`/`operation` tools

### Takeaway
The guidance converges on fewer, outcome-oriented, non-overlapping tools. Anthropic's API docs now explicitly say to group related operations "into a single tool with an `action` parameter", and GitHub did exactly this in production (`actions_get`/`actions_list`/`actions_run_trigger`, `projects_*`, `issue_read` with a method parameter). The best controlled evidence I found (MCP-GRANITE, 2026, search-summary only) favours moderate consolidation, about 4 tools, over both a fine-grained set and one monolithic tool. So the evidence supports replacing the 16 `x64dbg_*` and 33 `windbg_*` tools with a few intent-grouped tools per debugger. It does not support collapsing a whole engine into one tool. Token savings come from removing per-tool boilerplate. Accuracy then depends on clear per-action documentation and on validating arguments server-side.

### Cited Findings
- "**Consolidate related operations into fewer tools.** Rather than creating a separate tool for every action (`create_pr`, `review_pr`, `merge_pr`), group them into a single tool with an `action` parameter. Fewer, more capable tools reduce selection ambiguity and make your tool surface easier for Claude to navigate." The same page says to use "meaningful namespacing" (`github_list_prs`), "especially important when using tool search"; see [Claude API docs, Define tools, accessed 2026-10-19](https://platform.claude.com/docs/en/agents-and-tools/tool-use/define-tools) [read; vendor guidance, no numbers]
- Anthropic's consolidation examples; see [Anthropic, "Writing effective tools for AI agents", 2025-09-11](https://www.anthropic.com/engineering/writing-tools-for-agents) [read]:
  - `schedule_event` instead of `list_users` + `list_events` + `create_event`;
  - `search_logs` instead of `read_logs`;
  - `get_customer_context` instead of three getters;
  - `search_contacts` rather than `list_contacts`.
  - Namespacing by service and resource (`asana_projects_search`) "has non-trivial effects on our tool-use evaluations", and the effects "vary by LLM"; no numbers are given.
  - The post does not discuss multiplexed `action` parameters.
- GitHub's consolidations, with old names kept as aliases; see [docs/tool-renaming.md](https://github.com/github/github-mcp-server/blob/main/docs/tool-renaming.md) [local]:
  - `actions_get` ← `get_workflow`, `get_workflow_job`, `get_workflow_job_logs`, `get_workflow_run`, `get_workflow_run_logs`, `get_workflow_run_usage`, `download_workflow_run_artifact`;
  - `actions_list` ← four `list_workflow*` tools;
  - `actions_run_trigger` ← `run_workflow`, `rerun_workflow_run`, `rerun_failed_jobs`, `cancel_workflow_run`, `delete_workflow_run_logs`;
  - `projects_get`, `projects_list` and `projects_write` replace nine project tools.
- GitHub's 2025-10-29 changelog: the pull-request review tools merged into one tool "with a method parameter", and four issue tools merged into `issue_read`, to shrink the server's footprint; see [GitHub changelog](https://github.blog/changelog/2025-10-29-github-mcp-server-now-comes-with-server-instructions-better-tools-and-more) [search-summary]. Granular issue tools are still available, but only behind an opt-in `issues_granular` feature flag; see [docs/feature-flags.md](https://github.com/github/github-mcp-server/blob/main/docs/feature-flags.md) [local]
- MCP-GRANITE ("GRANularity Interface TEsting for MCP-Based LLM Agents", arXiv 2609.24161, 2026); see [arXiv PDF](https://arxiv.org/pdf/2609.24161) [search-summary; academic; full text unverified]:
  - A middle granularity level (about 4 tools) beat both the fine-grained and the fully merged settings for 8 of 9 models.
  - Moving from the fine-grained level (L4) to the middle level (L3) raised mean argument accuracy from 0.20 to 0.40.
  - A single monolithic tool degraded results: task completion fell and zero-tool-call rates rose, mainly for weaker models. The authors attribute this to the model having to pick among many action types and fill a larger schema on every call.
- HyperTool (arXiv 2606.13663) argues that step-wise atomic calls inflate context and fragment reasoning, and proposes a hybrid interface: atomic calls plus deterministic multi-tool workflows; see [arXiv PDF](https://arxiv.org/pdf/2606.13663) [search-summary]
- Workato recommends starting with 3-5 core tools and limiting a server to 5-8; see [Workato docs, MCP server design](https://docs.workato.com/mcp/mcp-server-design) [search-summary; vendor]. Boomi recommends exposing a single outcome-oriented tool and running the ordered steps behind the scenes; see [Boomi](https://boomi.com/ja/blog/emerging-patterns-and-practices-for-mcp-servers/) [search-summary; vendor]
- Phil Schmid, "MCP is Not the Problem, It's your Server: Best Practices for Building MCP Servers" (January 2026): servers fail when built as thin REST wrappers, and MCP should be designed as a user interface for agents; see [philschmid.de](https://www.philschmid.de/mcp-best-practices) [search-summary; I could not retrieve the full list of practices]. A CData summary says Schmid calls tool overload a hard bottleneck. A post on X, relayed by an aggregator, suggests loading servers only on an @mention or through subagents; see [CData](https://www.cdata.com/blog/scaling-mcp-architectures-onprem-to-remote-cdata) [search-summary; secondary]
- Arcade has built over 8,000 tools across 100+ integrations. Its central point is that a tool can return correct data and still fail if the agent can't tell when to call it. Its pattern catalog is at arcade.dev/patterns. "Arcade Evals" (Feb 2026) tests whether models pick and fill tools correctly, without executing them; see [Arcade blog](https://arcade.dev/blog/mcp-tool-patterns), [Plushcap summary](https://www.plushcap.com/companies/arcade/blog/summaries/2026/02) [search-summary; vendor]
- Speakeasy says optimizing tool descriptions and names "can have a bigger impact on the quality of your MCP server than the choice of underlying LLM"; see [Speakeasy tool design](https://www.speakeasy.com/mcp/tool-design.md) [search-summary; vendor]
- Claude Code flattens input schemas that have `anyOf`/`oneOf`/`allOf` at the root. For `anyOf`/`oneOf`, "each branch's `required` list is described in the tool description instead of enforced by the schema … keep validating the combination server-side"; see [Claude Code docs, MCP](https://code.claude.com/docs/en/mcp) [read]

### Inferences
- **How to group the debuggers:** the pattern that fits is GitHub's three-way split by intent (get / list / run_trigger) together with MCP-GRANITE's middle granularity. For x64dbg that means about 4-6 tools rather than 1 or 16, e.g. control (run/step/pause), breakpoints (set/clear/list), memory (read/search/dump), inspect (registers/stack/modules/threads). WinDbg would get a similar split.
- **Keep read-only and state-changing actions in separate tools.** MCP annotations (`readOnlyHint`) and Claude Code permission rules apply per tool. GitHub keeps `run_trigger` separate from `get` and `list` for the same reason.
- **Keep the gated facets in their own tools.** binary-mcp's catalog gates on tool name plus facet (`code-output`, `runs-engine`). If a multiplexed tool mixed code-output actions with structural ones, hooks would have to inspect `tool_input.action` and the catalog's guarantees would weaken.
- **Trade-offs of multiplexing:** the schema becomes a union of every action's parameters, mostly optional. Per-action required parameters cannot be enforced, especially once Claude Code flattens root-level combinators. The description has to document each action's arguments, which partly erodes the token savings. Errors must name the valid parameters for the chosen action.
- **Workflow-level tools for common RE sequences** (triage → analysis → census summary) cut both definitions and round trips, in line with Anthropic's `schedule_event` example and Boomi's guidance. Keep the atomic tools behind a profile for experts.

### Gaps
- I could not access Block's "playbook for designing MCP servers" (engineering.block.xyz was blocked), and no search result described its Linear case study, so there are no Block before/after tool counts or measurements.
- I have not read Phil Schmid's full list or Arcade's pattern catalog first-hand.
- There is no evidence specific to debugger tools; MCP-GRANITE's full text and its task domains are unverified.
- I found no measurement of token savings from GitHub's consolidations.

## 6. Writing descriptions and schemas for brevity: what to cut, what to keep, Pydantic schema bloat, and whether tool use examples pay off

### Takeaway
Keep what the tool does, when to use and not use it, what it returns, and its key limits. Put that first: Claude Code truncates upfront descriptions at 4,096 characters, and its tool search only reads that span. Cut duplicated material. In FastMCP 2.14.7 the whole docstring, including any "Args:" block, is sent as the description, while parameter documentation belongs in `Field(description=…)`. FastMCP 2.14.7 already strips Pydantic `title`s and inlines `$defs` in tool input schemas. The remaining Pydantic bloat is `anyOf [T, null]` for Optional parameters, plus defaults. I found no published measurement of what these cost. Tool use examples cost about 20-50 tokens (simple) to 100-200 tokens (complex) each. They are worth it only for a few complex or format-sensitive tools; Anthropic's internal result on complex parameters went from 72% to 90%.

### Cited Findings
- "**Provide extremely detailed descriptions.** This is by far the most important factor in tool performance." A description should cover what the tool does, when to use it and when not to, what each parameter means, and caveats, including "what information the tool does not return". "Aim for at least 3-4 sentences for each tool description, more if the tool is complex." Responses should "return only high-signal information"; see [Claude API docs, Define tools](https://platform.claude.com/docs/en/agents-and-tools/tool-use/define-tools) [read]
- Write descriptions as you would for "a new hire on your team". Use unambiguous parameter names (`user_id`, not `user`). The authors credit "precise refinements to tool descriptions" with Claude Sonnet 3.5's state-of-the-art SWE-bench Verified result, but give no figures; see [Anthropic, Writing effective tools](https://www.anthropic.com/engineering/writing-tools-for-agents) [read]
- `input_examples` (Claude API field); see [Claude API docs, Define tools](https://platform.claude.com/docs/en/agents-and-tools/tool-use/define-tools) [read]:
  - Each example must validate against `input_schema`; an invalid one returns a 400.
  - Not supported on server tools or client toolsets.
  - "Token cost - Examples add to prompt tokens: ~20-50 tokens for simple examples, ~100-200 tokens for complex nested objects".
- Tool use examples at launch; see [Anthropic, advanced tool use](https://www.anthropic.com/engineering/advanced-tool-use) [read; vendor-internal]:
  - Internal testing on complex parameter handling improved from 72% to 90%.
  - Use 1-5 realistic examples per tool, from minimal to full, focused on ambiguity.
  - Less useful for simple single-parameter tools, standard formats such as URLs or emails, or validation that JSON Schema handles better.
- Tool search matches on argument names and argument descriptions as well as names and descriptions; see [Tool search tool docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool) [read]. Claude Code's 4,096 and 16,384 character truncation and its keyword-first advice are in Q2; see [Claude Code docs, MCP](https://code.claude.com/docs/en/mcp) [read]
- FastMCP 2.14.7 description source: `fn_doc = inspect.getdoc(fn)` becomes `ParsedFunction.description`, and the tool uses `description=description or parsed_fn.description`. I found no docstring parser (griffe, docstring_parser) in `fastmcp/tools` or `fastmcp/utilities`. "Args:" sections are therefore sent verbatim as description text and are not turned into per-parameter schema descriptions; see [fastmcp/tools/tool.py L365, L477, L578](file:///home/user/binary-mcp/.venv/lib/python3.13/site-packages/fastmcp/tools/tool.py) [local]
- FastMCP 2.14.7 schema compression; see [fastmcp/tools/tool.py L499-504](file:///home/user/binary-mcp/.venv/lib/python3.13/site-packages/fastmcp/tools/tool.py), [fastmcp/utilities/json_schema.py L387-394](file:///home/user/binary-mcp/.venv/lib/python3.13/site-packages/fastmcp/utilities/json_schema.py) [local]:
  - Tool input schemas go through `compress_schema(input_schema, prune_params=…, prune_titles=True, dereference=True)`.
  - `compress_schema`'s defaults are `prune_defs=True`, `prune_additional_properties=True` and `prune_titles=False`; the tool path overrides titles to `True`.
  - FastMCP also generates an `outputSchema` from return annotations, and it is included in `tools/list`.
- Pydantic emits `Optional[T]` as an `anyOf` of the type and null; see [mcp-use docs, json_schema utils](https://docs.mcp-use.com/python/api-reference/mcp_use_server_utils_json_schema), [Pydantic docs, JSON Schema](https://docs.pydantic.dev/dev/concepts/json_schema) [search-summary]:
  - mcp-use calls this "valid JSON Schema, but not idiomatic MCP" (MCP marks optional fields by leaving them out of `required`).
  - It says the pattern makes some clients, such as the Inspector, fail to render those fields' descriptions.
  - Its `simplify_optional_schema` helper flattens only top-level properties.
- An OpenAI community thread asks whether Pydantic's extra `title` fields are worth stripping, but it contains no measurements; I found no benchmark of token savings from schema minification; see [OpenAI community](https://community.openai.com/t/extended-or-minimal-schemas-for-tool-parameters/578636) [search-summary]
- Claude Code schema handling; see [Claude Code docs, MCP](https://code.claude.com/docs/en/mcp) [read]:
  - A root-level combinator is flattened, and Claude Code *prepends* a sentence to the description, which adds tokens.
  - Top-level property names must be 1-64 characters of `[A-Za-z0-9_.-]`.
  - A schema must validate against JSON Schema draft 2020-12 or the tool is excluded.
  - A tool whose full name (`mcp__<server>__<tool>`) exceeds 128 characters is left out.
- mcp-compressor's 70-97% saving comes from removing descriptions and schemas from the upfront listing and fetching them on demand; see [Atlassian blog](https://www.atlassian.com/blog/developer/mcp-compression-preventing-tool-bloat-in-ai-agents) [search-summary; vendor]

### Inferences
- **What to cut, in order:**
  1. "Args:"/"Returns:" docstring blocks that repeat the schema. Move the parameter text into `Annotated[..., Field(description=…)]`, where tool search also indexes it.
  2. Boilerplate repeated in every tool, such as security caveats and untrusted-data envelopes. Move it to server instructions once, under 4,096 characters.
  3. Long examples and multi-paragraph background. Move them into an MCP resource, prompt or doc tool.
  4. `anyOf`-null wrappers. Use `T` with a default instead of `Optional[T] = None` where `None` only means "not given".
  5. Unhelpful defaults.
- **What to keep:** a keyword-dense first sentence; when to use the tool and when not to, naming the sibling tool to prefer, which is what reduces ambiguity; what it returns and its size limits; and long-running or job semantics.
- **Deferral changes the arithmetic.** With deferral (Claude Code), description length costs tokens only after discovery. Description quality now drives search recall too, so cutting meaning to save tokens is a worse trade than before. Without deferral, every character is paid for on every request.
- **Rough size of the `anyOf`-null overhead:** `{"anyOf":[{"type":"string"},{"type":"null"}],"default":null}` against `{"type":"string"}` is plausibly about 10-20 extra tokens per optional parameter. This is an unmeasured estimate. The token audit should count it with the count-tokens endpoint.
- **Tool use examples for MCP servers:** MCP has no standard `input_examples` field in the sources reviewed, so an MCP server can only carry examples inside descriptions, where they are always paid for. Reserve them for 3-5 complex tools, such as debugger breakpoint-condition syntax, address/RVA formats, YARA rule input and Ghidra address ranges. Do not use them across all 147 tools: at 147 × 3 × ~35 tokens that would be about 15K tokens.

### Gaps
- I found no published measurement of Pydantic `title`/`anyOf`/default bloat, or of savings from removing "Args:" duplication.
- It is unknown whether Claude Code, Claude Desktop or OpenCode include `outputSchema` or annotations in the model prompt. If they do, `outputSchema` is extra fixed cost (task #5 to measure).
- It is unknown whether any MCP client maps examples to Claude's `input_examples`.

## 7. Client hard limits on tool count (as of October 2026)

### Takeaway
A 147-tool server exceeds four hard limits:
- **VS Code Copilot Chat:** 128 tools per request. VS Code only copes by switching to experimental "virtual tools" grouping, whose threshold also defaults to 128.
- **Windsurf Cascade:** a documented 100-tool cap across all servers.
- **Cursor:** a widely reported 40-tool cap (2025). Its status after Cursor's January 2026 dynamic-discovery change is unconfirmed.
- **OpenAI:** a historical cap of 128 entries in the `tools` array, unverified for the current API.

Claude Code has no fixed cap. A profile mechanism is therefore needed for portability, separate from any token argument.

### Cited Findings
- **VS Code:** `export const HARD_TOOL_LIMIT = 128;`. The `chat.virtualTools.threshold` setting is experiment-based, defaults to `HARD_TOOL_LIMIT`, and in `package.json` is limited to 0-128 with a default of 128; see [vscode-copilot-chat configurationService.ts and package.json @ 2026-05-20](https://github.com/microsoft/vscode-copilot-chat/blob/main/src/platform/configuration/common/configurationService.ts) [local]. The VS Code docs say a chat request can have at most 128 tools enabled at a time, with the error "Cannot have more than 128 tools per request". They suggest deselecting tools or servers, or using the virtual-tools threshold; see [VS Code docs, Use tools in chat](https://code.visualstudio.com/docs/copilot/chat/chat-tools) [search-summary]. GitHub says the default VS Code toolset has about 40 built-in tools, which can grow into the hundreds with MCP servers; see [GitHub blog, fewer tools](https://github.blog/ai-and-ml/github-copilot/how-were-making-github-copilot-smarter-with-fewer-tools/) [search-summary]
- **Windsurf:** "Windsurf has a maximum limit of 100 tools that Cascade can access at any given time." The Iterable MCP server "exposes 104 tools, which exceeds this limit". Iterable's PR #19 (merged 2025-11-26) cites [docs.windsurf.com/windsurf/cascade/mcp](https://docs.windsurf.com/windsurf/cascade/mcp); see [Iterable/mcp-server PR #19](https://github.com/Iterable/mcp-server/pull/19/files) [read; secondary quote of official docs]. Guides advise toggling off individual tools; the limit applies across all connected servers; see [fast.io](https://fast.io/resources/windsurf-mcp-setup-guide/), [Grafana docs](https://grafana.com/docs/grafana/v13.2/developer-resources/mcp/clients/windsurf.md) [search-summary]
- **Cursor:** 2025 forum threads say Cursor sends "only the first 40 tools" to the Agent, and tools beyond that are silently unavailable. The workaround is to disable individual tools per server; see [Cursor forum, "Tools limited to 40 total"](https://forum.cursor.com/t/tools-limited-to-40-total/67976), [Cursor forum, 40-tool limit](https://forum.cursor.com/t/mcp-server-40-tool-limit-in-cursor-is-this-frustrating-your-workflow/81627) [search-summary]. A 2026 thread on the limit exists, but I did not read it; see [Cursor forum #153432](https://forum.cursor.com/t/regarding-the-quantity-limit-of-mcp-tools/153432). Cursor's January 2026 dynamic context discovery (Q2) may change how the cap applies, and one unsourced article claims more flexible registration; see [rapidevelopers](https://www.rapidevelopers.com/md/mcp-tutorial/how-to-fix-mcp-tool-not-showing-in-cursor) [search-summary; unverified]
- **OpenAI:** a historical 400 error read "'$.tools' is too long. Maximum length is 128, but got 221 items." (GPT-4-1106-preview era). CAMEL's docs say "a max of 128 functions"; a Vapi support thread reports the same 128 limit. One article says the 128 figure is mostly quoted from the deprecated Assistants API, and that the current guide gives only a soft "fewer than 20" recommendation; see [LlamaIndex community](https://community.llamaindex.ai/badrequesterror-error-code-400-TzmVbvmgXR4L), [Vapi support](https://support.vapi.ai/t/33329099/openai-s-tool-limit-is-128-per-request-exited-400-error-code), [Nerd Level Tech](https://nerdleveltech.com/how-many-tools-can-an-ai-agent-handle) [search-summary; current limit unverified]. OpenAI's tool search with `defer_loading` is described in Q2; see [OpenAI docs](https://developers.openai.com/api/docs/guides/tools-tool-search) [search-summary]
- **Claude Code:** "doesn't impose a fixed per-server tool cap; the practical limit is your context window budget". It drops individual tools whose full names exceed 128 characters or whose schemas are invalid, and it truncates descriptions (Q2); see [Claude Code docs, MCP](https://code.claude.com/docs/en/mcp) [read]
- **Claude API:** tool names must match `^[a-zA-Z0-9_-]{1,128}$`; see [Define tools](https://platform.claude.com/docs/en/agents-and-tools/tool-use/define-tools) [read]. With tool search, a request can carry up to 10,000 deferred tools; see [Tool search tool](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool) [read]
- **OpenCode:** the sources show no documented hard cap, only a context warning plus per-tool, glob and per-agent disabling; see [OpenCode docs](https://opencode.ai/docs/mcp-servers/) [search-summary]

### Inferences
- With 147 tools, binary-mcp is over the VS Code (128), Windsurf (100) and, if it still applies, Cursor (40) limits. In VS Code its tools also compete with about 40 built-ins for the 128 budget, so roughly 88 MCP tools fit before virtual-tools grouping or the error applies. Exactly what VS Code does at 147 + 40 under default settings is an inference, not something I tested.
- Profile sizes from binary-mcp's categories:

  | Profile | Tools | Fits under |
  |---|---|---|
  | All except debugger tools | 98 | Windsurf (100) |
  | Debugger tools only (WinDbg + x64dbg) | 49 | Windsurf, VS Code |
  | analysis-run + decompile + census + triage | 40 | Cursor (40), exactly |

  Combined with platform gating (no debugger tools off Windows), this makes the server portable without relying on client-side deferral.
- Name length is not a problem: `mcp__binary-mcp__` is 17 characters, well under the 128-character full-name limit.

### Gaps
- I could not open the official Cursor, Windsurf and VS Code docs pages (blocked). The VS Code facts come from source code dated May 2026, which may have been superseded if Copilot Chat has since moved into the main VS Code repository.
- OpenAI's current per-request tool limit for the Responses and Chat Completions APIs is unverified.
- Tool limits and deferral behaviour for Claude Desktop and claude.ai connectors, Gemini CLI, Zed, JetBrains AI and Copilot CLI were not established.
