# Session-level context management and caching: what decides the token cost of a long binary-mcp session

Research date: 2026-10-19. Live documentation pages (platform.claude.com, code.claude.com) are undated and were fetched on that date. Claude Code behaviour is version-gated (many statements carry "v2.1.2xx or later") and changes fast, so treat it as current only as of October 2026.

Evidence labels: **[Vendor docs]** = the vendor's own documentation of its product; **[Vendor claim]** = a vendor's own measurement or marketing number (usually internal evals, not independently reproduced); **[Independent]** = peer-reviewed or third-party research; **[Secondary]** = blog or summary of someone else's work; **[via search summary]** = the primary page could not be fetched from this environment, because DNS was blocked for manus.im, trychroma.com, arxiv.org, aclanthology.org, openai.com, modelcontextprotocol.io, medium.com and claude.dev. For those pages the content came from search-engine summaries and secondary write-ups, so the exact wording is not verified.

Local context checked read-only: binary-mcp builds its server as `app = FastMCP("binary-mcp")` (src/server.py:119), with no `instructions=` argument. A grep found no dynamic tool registration (`add_tool`/`remove_tool`/enable/disable) and no use of sampling. Tools carry FastMCP category/facet tags, and src/tool_catalog.py says outright that the tags exist so that "a PreToolUse guard" can gate code-reading tools.

---

## 1. Prompt caching (Anthropic, with OpenAI for comparison): where tool definitions sit, what invalidates the cache, prices, TTLs and minimums, and what this means for an MCP server

### Takeaway
Tool definitions are the first segment of the cached prefix (tools → system → messages). Any byte change to any tool's name, description or schema invalidates the whole cache, including the conversation history behind it. Cache reads now cost 0.1× base input (0.05× on Opus 5.5/Sonnet 5.5, 0.025× on Fable 5.1), so one invalidation costs about 12.5× to 50× what a normal cached turn costs on the same context. In Claude Code the risk is mostly neutralised by default: MCP tools are deferred behind tool search, and the tool list is frozen at the conversation's first request. It comes back in full whenever tool search is off, and on clients that load all tools upfront. A static, deterministic tool list and instructions remain the safe design.

### Cited Findings

**Anthropic API: prefix order and invalidation [Vendor docs]**
- Caching "references the entire prompt: `tools`, `system`, and `messages` (in that order), up to and including the block designated with `cache_control`". The order is a hierarchy, and "changes at each level invalidate that level and all subsequent levels." See [Anthropic prompt caching docs](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)
- Invalidation table:
  - Changing tool definitions ("names, descriptions, or parameters") invalidates the tools, system and messages caches.
  - Toggling web search or citations, or switching `speed`, invalidates system and messages.
  - Changing `tool_choice`, or adding or removing images, invalidates only messages.
  - Thinking-parameter and `effort` changes always invalidate messages, and invalidate tools/system on some models.
  
See [Anthropic prompt caching docs](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)
- Changing `disable_parallel_tool_use` also invalidates the messages cache. See [Tool use with prompt caching](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-use-with-prompt-caching)
- "Cache hits require 100% identical prompt segments." Reordering tools therefore changes the prefix bytes, which is an inference from this exact-match rule; the docs give no separate statement on ordering. See [Anthropic prompt caching docs](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)
- The API offers two cache-preserving escape hatches:
  - A mid-conversation tool-changes beta (`inline-tools-2026-09-15`) "lets you add tools without editing `tools`, so the cache still matches".
  - On supported models, appending a `{"role": "system"}` message to `messages` adds an instruction without invalidating the system or message caches. This is not available on Claude Sonnet 5.
  
  The tool-changes feature is a beta whose header name may change. No beta is mentioned for the system-message form. See [Anthropic prompt caching docs](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)
- Putting `cache_control` on the last tool caches the whole tool-definitions prefix. For MCP-connector toolsets the docs say "You don't control tool order within an MCP toolset, so place the breakpoint on the `mcp_toolset` entry itself." See [Tool use with prompt caching](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-use-with-prompt-caching)
- A request can carry at most 4 breakpoints. Each breakpoint checks "at most 20 positions" backwards, and a run of consecutive `tool_use` blocks or of consecutive `tool_result` blocks counts as one position. Cache writes happen only at breakpoints. See [Anthropic prompt caching docs](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)
- Organisations never share caches. Caches are isolated per workspace on the Claude API, Claude Platform on AWS and Foundry, and per organisation on Bedrock and Google Cloud. See [Anthropic prompt caching docs](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)

**Anthropic API: prices, TTLs, minimum lengths, latency [Vendor docs / Vendor claim]**
- The default lifetime is 5 minutes, "refreshed for no additional cost each time the cached content is used". The lifetime "is measured from the start of the request", so a response that streams for 4 minutes leaves about 1 minute for the next request. An optional 1-hour TTL exists, and longer-TTL entries must come before shorter ones. See [Anthropic prompt caching docs](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)
- Multipliers on base input price: 5-minute write **1.25×**, 1-hour write **2×**, cache read **0.1×**. The read exceptions are **0.05×** on Claude Opus 5.5 and Sonnet 5.5, and **0.025×** on Claude Fable 5.1 and Mythos 5.1. The multipliers "stack with" the Batch discount, long-context pricing and data residency. See [Anthropic prompt caching docs](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)
- Per-model prices in $/MTok (base / 5m write / 1h write / cache read / output):

  | Model | Base | 5m write | 1h write | Cache read | Output |
  |---|---|---|---|---|---|
  | Opus 5.5 | 4 | 5 | 8 | 0.20 | 20 |
  | Sonnet 5.5 | 2 | 2.50 | 4 | 0.10 | 10 |
  | Sonnet 4.6 | 3 | 3.75 | 6 | 0.30 | 15 |
  | Opus 5 / 4.8 / 4.7 / 4.6 / 4.5 | 5 | 6.25 | 10 | 0.50 | 25 |
  | Haiku 5.5 (≤100K tokens) | 0.10 | 0.125 | 0.20 | 0.01 | 0.50 |
  | Fable 5.1 | 10 | 12.50 | 20 | 0.25 | 50 |

See [Anthropic prompt caching docs](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)
- Minimum cacheable prompt length:
  - **512 tokens**: Opus 5.5, Opus 5, Sonnet 5.5, Haiku 5.5, Fable 5/5.1, Mythos 5/5.1.
  - **1,024**: Opus 4.8, Sonnet 5, Sonnet 4.6/4.5, Opus 4.1/4, Sonnet 4.
  - **2,048**: Opus 4.7, Mythos Preview, Haiku 3.5.
  - **4,096**: Opus 4.6/4.5, Haiku 4.5.
  
  Shorter prompts are "processed without caching and no error is returned". See [Anthropic prompt caching docs](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)
- The docs state that cache hits "are not deducted against your rate limit". The statement appears in the 1-hour TTL section. See [Anthropic prompt caching docs](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)
- Latency: "You will generally see improved time-to-first-token for long documents." The 5m and 1h TTLs "behave the same with respect to latency", and caching has "no effect on output token generation". The current page gives no number. See [Anthropic prompt caching docs](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)
- The launch post claims "costs by up to 90% and latency by up to 85% for long prompts" **[Vendor claim, 2024-era models; absolute numbers likely superseded]**. The fetch tool rendered the post as dated 14 Aug 2025, but the page carries a 17 Dec 2024 GA update note, so 14 Aug 2024 is the consistent date. Its table:

  | Use case | Latency (TTFT) | Cost |
  |---|---|---|
  | Chat with a book (100K-token cached prompt) | 11.5 s → 2.4 s (-79%) | -90% |
  | Many-shot prompting (10K tokens) | 1.6 s → 1.1 s (-31%) | -86% |
  | 10-turn chat with a long system prompt | ~10 s → ~2.5 s (-75%) | -53% |

See [Anthropic, "Prompt caching with Claude"](https://claude.com/blog/prompt-caching)

**Tool search / `defer_loading` and caching [Vendor docs / Vendor claim]**
- "Deferred tools are not included in the system-prompt prefix." A discovered tool is "appended inline as a `tool_reference` block in the conversation history. The prefix is untouched, so prompt caching is preserved." The page also says "adding tools dynamically through tool search does not break your cache." See [Tool use with prompt caching](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-use-with-prompt-caching)
- Mechanics of `defer_loading`:
  - "You still send every tool's full definition in the `tools` array on every request, including the deferred ones."
  - At least one tool must be non-deferred.
  - "Keep your 3-5 most frequently used tools non-deferred."
  - A tool with `defer_loading: true` "can't also carry `cache_control`" (the API returns a 400).
  
See [Tool search tool docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool)
- Claims and limits **[Vendor claim]**:
  - A five-server setup "can consume ~55k tokens in definitions"; tool search "typically reduces this by over 85 percent, loading only the 3-5 tools Claude needs".
  - "Claude's ability to pick the right tool degrades once you exceed 30-50 available tools."
  - Recommended when you have ≥10 tools or >10k tokens of definitions.
  - Search covers tool names, descriptions, argument names and argument descriptions, and returns 5 results by default. Up to 10,000 deferred tools are allowed.
  - Consistent name prefixes (for example `github_`) let "one search match the whole group".
  - Discovered definitions "count as input tokens like any other tool definition".
  
See [Tool search tool docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool)
- "Advanced tool use" (24 Nov 2025) **[Vendor claim, internal evals]**:
  - Upfront tool definitions of ~77K tokens fell to ~8.7K with tool search (85% reduction).
  - MCP-eval accuracy rose from 49% to 74% on Opus 4 and from 79.5% to 88.1% on Opus 4.5.
  - Anthropic had seen 134K tokens of tool definitions before optimisation.
  - Deferred tools are "excluded from the initial prompt entirely", so caching is not broken.
  
See [Anthropic, Advanced tool use](https://www.anthropic.com/engineering/advanced-tool-use)

**Claude Code (the main client) [Vendor docs]**
- Claude Code orders each request in three layers: a System prompt layer ("Core instructions, tool definitions", changes when "the set of loaded tool definitions changes"), then Project context (CLAUDE.md, memory), then Conversation. "A change to the system prompt invalidates everything." See [Claude Code: How Claude Code uses prompt caching](https://code.claude.com/docs/en/prompt-caching)
- With tool search deferring MCP tools, which is the default on supported models:
  - "Claude Code keeps the tool list from the conversation's first request for the whole conversation, so a server connecting or disconnecting mid-session doesn't disturb anything already cached."
  - A server that connects late "supplies its tools as deferred definitions".
  
See [Claude Code prompt caching](https://code.claude.com/docs/en/prompt-caching)
- With tools loaded upfront (tool search below its `auto` threshold, disabled, or unavailable, for example behind a non-first-party `ANTHROPIC_BASE_URL` gateway):
  - "A server connects, or a dynamic tool update adds tools" → cache invalidated.
  - Deliberately removing a tool → invalidated.
  - A stdio server that drops out → cache kept; its definitions stay and calls return errors.
  
See [Claude Code prompt caching](https://code.claude.com/docs/en/prompt-caching)
- On a `list_changed` notification, an interactive Claude Code session "fetches the updated list from that server". With `-p` or the Agent SDK it "refreshes only the tool list". If a refresh fails, the previous lists are kept. See [Claude Code MCP docs](https://code.claude.com/docs/en/mcp)
- Tool search is "enabled by default". "Only tool names and server instructions load at session start." `ENABLE_TOOL_SEARCH` accepts:
  - unset (default): defer all;
  - `true`;
  - `auto`: load upfront while the definitions total <10% of the context window, defer once they reach 10%;
  - `auto:N`;
  - `false`.
  
  Tool search is turned off by default when `ANTHROPIC_BASE_URL` points to a non-first-party host. See [Claude Code MCP docs](https://code.claude.com/docs/en/mcp)
- Claude Code cuts "Server instructions, and the description of a tool that loads upfront" at **4,096 characters**, and "the description of a tool that Claude loads through tool search" at **16,384 characters**. Tool-search matching reads only text within the shorter limit, so "put the words Claude would search for near the start too". Before v2.1.296 the shorter limit was 2,048. See [Claude Code MCP docs](https://code.claude.com/docs/en/mcp)
- A server can mark one tool to load upfront with `_meta["anthropic/alwaysLoad"]: true`. Users can set `alwaysLoad` for a whole server in their configuration. See [Claude Code MCP docs](https://code.claude.com/docs/en/mcp)
- The docs tell MCP server authors that server instructions "become more useful with tool search enabled". Instructions should explain "what category of tasks your tools handle", "when Claude should search for your tools", and "key capabilities". See [Claude Code MCP docs](https://code.claude.com/docs/en/mcp)
- Cache TTL in Claude Code:
  - The main conversation gets **1 hour** on a Claude subscription within plan usage, and **5 minutes** on API keys, usage credits and cloud providers.
  - Subagents, compaction and other side requests get 5 minutes by default.
  - Overrides: `promptCacheTtl`/`CLAUDE_CODE_PROMPT_CACHE_TTL`, `subagentPromptCacheTtl`, `FORCE_PROMPT_CACHING_5M`, `ENABLE_PROMPT_CACHING_1H`.
  
See [Claude Code prompt caching](https://code.claude.com/docs/en/prompt-caching)
- "In Claude Code, the cache is effectively scoped to one machine and directory." The system prompt embeds memory paths and the conversation opens with an environment announcement. Parallel sessions in the same directory read each other's cache. See [Claude Code prompt caching](https://code.claude.com/docs/en/prompt-caching)
- Cost mechanics from the costs page:
  - "Claude Code sends your full conversation with every request, and each time Claude uses tools it sends another request carrying that batch of tool results".
  - The first message after a break longer than the TTL "misses the cache and reprocesses your full context".
  - "`/compact` reads the conversation it summarizes".
  
See [Claude Code: Manage costs](https://code.claude.com/docs/en/costs)
- `/usage` prints a "Prompt cache (main)" line. The documented example reads "14 requests · 91% of input tokens from cache · 2 misses … 1 expected rebuild (compaction or tool-result clearing)", and the line can name a likely miss cause such as "tool definitions changed". The example session block shows "1.2k input, 5.3k output, 940.0k cache read, 50.0k cache write". These are illustrative doc examples, not measurements. See [Claude Code costs](https://code.claude.com/docs/en/costs)
- The Claude Code team "runs alerts on the cache hit rate, declaring SEVs when the rate gets too low" **[via search summary; the claude.com/claude.dev post could not be fetched]**. See [Lessons from building Claude Code: Prompt caching is everything](https://claude.com/blog/lessons-from-building-claude-code-prompt-caching-is-everything)

**OpenAI, for comparison [Vendor docs, via search summary]**
- Caching is automatic with "no additional fees" for prompts of ≥1,024 tokens. Hits need exact prefix matches, so static content goes first. `cached_tokens` is reported in usage. OpenAI claims it "can reduce latency by up to 80% and input token costs by up to 90%". See [OpenAI prompt caching guide](https://developers.openai.com/api/docs/guides/prompt-caching)
- Retention: the default in-memory cache lasts 5-10 minutes of inactivity. Extended retention up to 24 hours is set with `prompt_cache_retention: "24h"` on specific models; the snippet says gpt-5.5/gpt-5.5-pro support only 24h. `prompt_cache_key` improves routing, and routing hashes the prompt's initial prefix (the snippet says the first 256 tokens). See [OpenAI prompt caching guide](https://developers.openai.com/api/docs/guides/prompt-caching)
- OpenAI's cookbook reports cached requests are 7% faster at 1,024-token prompts but 67% faster to first token at 150K+ tokens **[Vendor claim]**. See [OpenAI Prompt Caching 201 cookbook](https://developers.openai.com/cookbook/examples/prompt_caching_201)
- "Both the messages array and the list of available tools can be cached" **[Secondary: a gateway's mirror of OpenAI's docs]**. See [Portkey OpenAI prompt caching docs](https://portkey.ai/docs/integrations/llms/openai/prompt-caching-openai)

### Inferences

**Worked arithmetic** (my calculations from the Anthropic price table above)
- **A miss costs 12.5× to 50× a hit.** Rewriting the prefix at the 5m write rate costs 1.25/0.1 = **12.5×** a cached re-read on 0.1× models, 1.25/0.05 = **25×** on Opus 5.5/Sonnet 5.5, and **50×** on Fable 5.1. With 1h writes the ratios are 20×/40×/80×. Cheaper reads therefore make each invalidation relatively more expensive. OpenAI has no write premium, so there a miss costs roughly 10× a hit at a 90% discount.
- **One invalidation at 150K tokens of context:**

  | Model | Cached re-read | Rewrite on miss |
  |---|---|---|
  | Opus 5.5 | $0.030 | $0.75 (5m) / $1.20 (1h) |
  | Sonnet 5.5 | $0.015 | $0.375 |
  | Sonnet 4.6 | $0.045 | $0.56 |
  | Fable 5.1 | $0.0375 | $1.875 |

  Each avoidable `list_changed`, tool add/remove or description change in an upfront-tools client costs this once. The same applies to every resumed turn after a TTL expiry.
- **Upfront tool definitions, hypothetical.** If all 147 definitions loaded upfront at an *assumed* 400 tokens each (~59K tokens), the prefix would cost ~$0.29 to write once and ~$0.012 per request to re-read on Opus 5.5, or ~$3.5 over 300 tool calls. On 200K-window models it would also take ~30% of the window. The real per-tool size should come from the token-footprint audit. Under Claude Code's default deferral, only names plus instructions load, so most of this disappears there.

**Design rules for binary-mcp**
1. **Keep the tool list static and deterministic.**
   - Register all 147 tools unconditionally, in a fixed order, on every start.
   - Never hide or add tools based on whether Ghidra, x64dbg, WinDbg or .NET tooling is available. This is Manus's "mask, don't remove" (section 3). Report unavailability inside the tool result with an actionable next step instead.
   - Claude Code already keeps a dropped stdio server's definitions and returns errors, which is the same pattern.
2. **Put no volatile text in tool descriptions or server instructions.** Volatile means timestamps, engine availability, counts, session IDs, set or dict iteration order, or anything that differs between runs.
   - Machine-constant strings such as `Path.home()` output paths are harmless to caching inside Claude Code, which already scopes its cache per machine and directory, but they still spend tokens.
   - Version strings change the prefix only once per upgrade. Claude Code itself rebuilds its cache after each Claude Code upgrade.
3. **Do not emit `notifications/tools/list_changed` in normal operation.** It costs nothing under Claude Code's default deferral. It costs a full rewrite in any upfront-tools configuration, and the server cannot tell which configuration the client is using.
4. **Add short, static server `instructions`.** Under deferral the model sees only tool names plus instructions, and binary-mcp currently sends no instructions.
   - Keep them under the 4,096-character cut.
   - Put the category map and search keywords first ("decompile", "xrefs", "debug", ".NET", "PE triage").
   - Name the handle/job conventions and the 3-5 entry-point tools.
5. **Mark only 3-5 hot tools `_meta["anthropic/alwaysLoad"]`**, for example triage, decompile and xrefs. Every tool-search call adds a search round-trip and expands definitions as input tokens, so hot tools should not need a search; everything else stays deferred.
   - This assumes FastMCP 2.13 can emit per-tool `_meta`, which the FastMCP research thread should verify.
6. **Put search keywords in the first sentence of each description.** Use consistent group prefixes or keywords (`ghidra_*`, `x64dbg_*` and so on, or equivalent keywords if renaming is too disruptive), because regex/BM25 search and hook matchers both key on them.
7. **For API-based harnesses** (Agent SDK, or the MCP connector), place `cache_control` on the `mcp_toolset` entry and use `defer_loading` at the toolset level, since the server does not control order inside the toolset.

### Gaps
- No primary documentation found on whether **Claude Desktop** or **OpenCode** defer MCP tool definitions, where they place cache breakpoints, or whether they re-send `tools/list` content every turn. One third-party tutorial says Claude Desktop "will load all of them on startup" ([mcpplaygroundonline](https://mcpplaygroundonline.com/blog/how-to-setup-mcp-claude-desktop)). This is unverified and should be measured.
- Not documented: whether a `list_changed` that only *edits* existing descriptions reaches the model in a deferred Claude Code session, given the tool list is frozen at the first request.
- OpenAI details could not be fetched directly: tool-order sensitivity, cache-hit granularity and exact retention per model.
- Anthropic publishes no current-model latency figures for cache hits. The 2024 table is the only quantified source found.
- The Claude Code "prompt caching is everything" blog post could not be fetched (claude.dev DNS block), so its specific design lessons beyond the SEV-on-hit-rate point are unverified here.

---

## 2. Anthropic's context-engineering guidance, context editing and the memory tool, and how Claude Code treats large MCP outputs (auto-compaction, `/compact`, `/context`, subagents)

### Takeaway
Anthropic's guidance has four parts:
- **Just-in-time retrieval:** pass lightweight identifiers, not bodies.
- **Compaction and tool-result clearing:** clearing is called the "lightest touch" form of compaction.
- **Structured notes** kept outside the context window.
- **Sub-agents** that return summaries of 1-2K tokens.

Anthropic reports that context editing cut tokens 84% on a 100-turn eval, a vendor number. In Claude Code, on 1M-context models, auto-compaction by default waits until about 967K tokens. Large MCP results are persisted to disk only beyond 25K tokens or 50K characters, and compaction discards full tool outputs. A long RE session therefore re-reads every decompilation it has received on every later tool call until compaction. Result size and how long a result stays in context, more than description text, drive the bill.

### Cited Findings

**Anthropic, "Effective context engineering for AI agents" (29 Sep 2025) [Vendor guidance]**; see [Anthropic engineering](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents)
- Recall degrades as context grows ("context rot"). LLMs have an "attention budget", and transformers create "n² pairwise relationships for n tokens".
- Guiding principle: "find the smallest set of high-signal tokens that maximize the likelihood of your desired outcome."
- Tools should return "information that is token efficient" and "have minimal overlap in functionality".
- Just-in-time retrieval: agents keep "lightweight identifiers (file paths, stored queries, web links, etc.)" and load data at runtime with tools.
- Hybrid strategy: CLAUDE.md is loaded upfront and glob/grep fetch the rest just in time.
- Compaction should preserve "architectural decisions, unresolved bugs, and implementation details" and carry "the five most recently accessed files". Tune compaction prompts for recall first.
- Tool-result clearing is "one of the safest lightest touch forms of compaction".
- Structured note-taking: notes "persisted to memory outside of the context window", for example a NOTES.md, or the Pokémon agent's running tallies.
- Sub-agents work "with clean context windows". They may use "tens of thousands of tokens or more" but return "a condensed, distilled summary of its work (often 1,000-2,000 tokens)".

**Context editing API [Vendor docs]**; see [Context editing docs](https://platform.claude.com/docs/en/build-with-claude/context-editing)
- Beta header `context-management-2025-06-27`. The `clear_tool_uses_20250919` strategy takes:
  - `trigger`: default 100,000 input tokens, or set as a count of tool uses;
  - `keep`: default the last 3 tool uses;
  - `clear_at_least`;
  - `exclude_tools`;
  - `clear_tool_inputs`: default false, so only results are cleared.
- The oldest results are cleared first, and each is replaced with "placeholder text telling Claude the result was removed".
- Clearing "invalidates cached prefixes when content is cleared". `clear_at_least` exists so each clear removes enough tokens to justify the invalidation.
- Combined with the memory tool, Claude gets "an automatic warning to save important information to memory files before results are cleared".
- Responses report `context_management.applied_edits` with `cleared_input_tokens`.
- The SDK's client-side compaction defaults to a 100,000-token threshold. Its default summary has five sections: Task Overview, Current State, Important Discoveries, Next Steps, Context to Preserve.

**Reported numbers for context editing and the memory tool (29 Sep 2025) [Vendor claim, internal evals]**; see [Claude blog: Managing context on the Claude Developer Platform](https://claude.com/blog/context-management)
- Memory tool plus context editing improved performance by **39%** over baseline on "an internal evaluation set for agentic search". Context editing alone improved it by **29%**.
- On a **100-turn web search evaluation**, context editing "reduced token consumption by **84%**" and let agents finish workflows that would otherwise fail on context exhaustion.
- The memory tool is file-based, runs client-side, and persists across conversations in a directory the developer controls. Launched with Sonnet 4.5 in public beta on the Claude Developer Platform, Bedrock and Vertex AI.

**Compaction API [Vendor docs]**; see [Compaction overview](https://platform.claude.com/docs/en/build-with-claude/compaction)
- Compaction keeps the active context small "because response quality degrades as a conversation grows".
- Two server-side modes exist: compaction at a token threshold, and newer on-demand compaction (beta `compact-2026-09-04`). On-demand compaction supports keeping recent turns verbatim and running in the background.

**Claude Code: when compaction triggers and what survives it [Vendor docs]**
- Without a configured window, Claude Code compacts at the model's context limit:
  - Native-1M models (Fable, Sonnet 5 and later, Haiku 5.5, Opus 4.7 and later, so Opus 5.5 too) compact at "about 967K tokens by default".
  - Sonnet/Opus 4.6 without extended context compact at the 200K boundary.
  - The window is configurable with `/autocompact 500k`, the `autoCompactWindow` setting, `--autocompact`, or `CLAUDE_CODE_AUTO_COMPACT_WINDOW`, in the range 100K-1M.
  
See [Claude Code model configuration](https://code.claude.com/docs/en/model-config)
- The compaction summary keeps "your requests and intent, key technical concepts, files examined or modified with important code snippets, errors and how they were fixed, pending tasks, and current work". "Full tool outputs and intermediate reasoning are gone." Claude Code then:
  - re-reads "up to five of the files modified most recently";
  - re-injects invoked skills, capped at 5,000 tokens per skill;
  - reloads the system prompt, CLAUDE.md, memory and MCP tools;
  - does not reload the skill listing.
  
See [Claude Code: Explore the context window](https://code.claude.com/docs/en/context-window)
- Compaction sends "a separate request with the same system prompt, tools, and history as your conversation, plus a summarization instruction". While the cache is warm it reads the prefix from cache, so "a mid-session `/compact` costs a fraction of what the context size suggests". After a TTL gap it reprocesses the full history uncached. `/rewind` truncates back to an already-cached prefix instead. See [Claude Code prompt caching](https://code.claude.com/docs/en/prompt-caching)
- `/compact Focus on …` takes custom instructions, and a "# Compact instructions" section in CLAUDE.md customises compaction. `/context` shows what is consuming space. "`/clear` costs nothing." See [Claude Code costs](https://code.claude.com/docs/en/costs)
- Hooks can intercept compaction: `PreCompact` (matcher `manual`/`auto`; exit code 2 blocks compaction), `PostCompact`, and `SessionStart` with matcher `compact`, which accepts `additionalContext`. See [Claude Code hooks](https://code.claude.com/docs/en/hooks)

**Claude Code: large MCP outputs [Vendor docs]**; see [Claude Code MCP docs](https://code.claude.com/docs/en/mcp)
- Size limits:
  - A warning appears when "any MCP tool output exceeds 10,000 tokens" (a fixed threshold).
  - Output is limited "to 25,000 tokens by default", changeable with `MAX_MCP_OUTPUT_TOKENS`.
  - A successful non-image result over the limit is saved to a file in the session's `tool-results` directory and replaced "with a message that names the file path, so Claude reads the file when it needs the content".
  - A successful text result longer than **50,000 characters** is saved to a file "whatever its token count".
- A server can raise one tool's threshold with `_meta["anthropic/maxResultSizeChars"]`, up to a hard ceiling of 500,000 characters.
- Error text longer than about 11,000 characters keeps only the first and last 5,000 characters.
- HTTP/SSE responses over 16 MiB fail.
- "A foreground call still running after two minutes moves to a background task, and the result arrives as a task notification when the call settles."
- Image results appear inline (possibly downscaled), and the original bytes are also saved to a file whose path Claude receives.

**Claude Code: subagents [Vendor docs]**; see [Claude Code subagents](https://code.claude.com/docs/en/sub-agents)
- Each subagent has its own context window; "the verbose output stays in the subagent's context while only the relevant summary returns to your main conversation."
- MCP tools are inherited by default. A server defined inline in a subagent's `mcpServers` keeps "its tool descriptions" out of the main conversation: "The subagent gets the tools; the parent conversation doesn't."
- Subagents can run on a cheaper model (`model: haiku`).
- Subagent transcripts are separate files and are unaffected by main-conversation compaction. A warning appears when custom subagent descriptions exceed 15,000 tokens.
- The context-window simulation's example: the subagent "read 6,100 tokens of files. You got a 420-token result". The token counts are illustrative. See [Claude Code: Explore the context window](https://code.claude.com/docs/en/context-window)
- A subagent's first request "doesn't read the parent's cache, because the two prefixes differ", and it gets a 5-minute TTL by default. A fork inherits the parent's prefix and does read the parent's cache. See [Claude Code prompt caching](https://code.claude.com/docs/en/prompt-caching)
- Claude Code's own cost advice is to delegate "running tests, fetching documentation, or processing log files" to subagents. See [Claude Code costs](https://code.claude.com/docs/en/costs)

**Claude Code: automatic tool-result clearing ("micro-compaction")**
- Officially, Claude Code counts an "expected rebuild" when it rewrites the conversation "by compaction or by clearing old tool results from context". See [Claude Code costs](https://code.claude.com/docs/en/costs)
- Thresholds and scope are documented only by third parties **[Secondary, conflicting]**:
  - The clearable set is file reads, shell commands, grep, glob, web fetches and edits, with the most recent results kept.
  - Trigger thresholds are quoted variously as ~60-70% or ~75-80% of the window.
  - A time-based variant fires after roughly an hour idle.
  
See [ClaudeLog: micro-compact](https://claudelog.com/faqs/what-is-micro-compact/); [MorphLLM: Claude Code compact](https://morphllm.com/claude-code-compact)

### Inferences
- **Each tool call re-reads the whole history, and Claude Code's default compaction point on 1M models is very late (~967K).** Per-request history re-read cost on Opus 5.5 at $0.20/MTok:

  | Resident context | Per request | Per 300 requests |
  |---|---|---|
  | 100K | $0.02 | $6 |
  | 200K | $0.04 | $12 |
  | 500K | $0.10 | $30 |
  | 967K | $0.19 | $58 |

  These figures are re-reads only, before any new input or output. The Chroma and Anthropic findings in section 3 also tie larger contexts to lower quality. For RE sessions it is worth documenting a recommended `/autocompact 200k` (or similar). More importantly, keep results small so the context grows slowly.
- **MCP results do not survive compaction.** Only what the summary paraphrases is kept, and Claude Code re-reads modified *files*, not MCP results. Results should therefore carry short, stable handles (a function address plus an artifact ID or content hash) that a summariser is likely to keep, so the model can re-fetch cheaply from binary-mcp's analysis cache afterwards.
- **The coverage ledger is binary-mcp's structured note (NOTES.md/todo.md).** It is stored server-side, so it survives compaction and context editing. A cheap "session state / ledger digest" tool of a few hundred tokens would be the natural thing to call after compaction. A Claude Code `SessionStart(compact)` hook could also inject it automatically (section 6).
- **The server should not rely on Claude Code's 25K-token / 50K-character safety net.**
  - That net turns an oversized result into an opaque "saved to <path>" message, and only in Claude Code.
  - Server-side shaping is portable and can provide a structured summary plus an ID: a header with signature, size, key callees, strings and APIs, and the body on request or in pages.
  - Raising `anthropic/maxResultSizeChars` would *increase* the tokens that stay in context, so it should be used sparingly.
- **Delegating bulk reads to a subagent is the strongest session-level lever for decompile-heavy phases.** The documented example returned 420 tokens from 6,100 tokens read, and Anthropic suggests 1-2K-token summaries. Trade-offs:
  - The subagent pays its own uncached prefix on its first request.
  - If binary-mcp is scoped *only* to the subagent through inline `mcpServers`, the main agent cannot call it.
  - A plugin could ship a "bulk reader" subagent definition that pairs with a cheaper model.
- **Clearing break-even** (my arithmetic). Clearing C tokens whose rewrite region is S tokens costs an extra (S - C)·w - S·r on that request and saves C·r on every later request, where w is the write multiplier and r the read multiplier. With S = 150K and C = 50K, it breaks even after about **22 more requests** at r = 0.1 and about **47** at r = 0.05.
  - Clearing therefore pays off in dollars only in long sessions. Its main justifications are window limits and quality.
  - A server that makes cleared results expensive to restore (a full re-decompile re-sent at full size) erodes the savings. Restorable handles plus memoisation keep re-fetches small.
- **Keep error results short.** Claude Code middle-truncates errors over about 11K characters, and an error repeated over several retries stays resident like any other result.

### Gaps
- No official Claude Code documentation was found on **micro-compaction thresholds**, and in particular on **whether MCP tool results are cleared**. Third parties list only built-in tools. If MCP results are not cleared, binary-mcp results stay resident until full compaction. This matters a lot and should be checked empirically, for example from the `/usage` "expected rebuild" counts or transcripts.
- `/context` output categories and per-category token figures were not retrieved in detail.
- How Claude Desktop and OpenCode handle very large MCP results (truncation, persistence to disk, or neither) is not documented in sources I could reach.
- The current default trigger for threshold-based API compaction was not confirmed on the fetched page. The fetched overview page did not show it.

---

## 3. Lessons from Manus, Chroma's "Context Rot", "Lost in the Middle" and related evidence: concrete design implications for tool outputs

### Takeaway
Independent and vendor evidence agree on direction:
- Model performance becomes less reliable as input grows, even on trivial tasks.
- Plausible distractors and mid-context placement hurt.
- Production agents treat cache hit rate as a first-class metric and keep the context append-only, with the tool list fixed.

For tool outputs this means: lead with the answer, avoid re-sending near-duplicate bodies, make every elision restorable through an identifier, and keep the action space static.

### Cited Findings

**Manus, "Context Engineering for AI Agents: Lessons from Building Manus" (Yichao "Peak" Ji, 18 Jul 2025) [Vendor experience report; via search summary, original not fetched]**; see [Manus blog](https://manus.im/blog/Context-Engineering-for-AI-Agents-Lessons-from-Building-Manus)
- Manus treats KV-cache hit rate as its key production metric. Its average input:output token ratio is around **100:1**. On Claude Sonnet, cached input costs **$0.30/MTok versus $3.00/MTok** uncached, a 10× difference. See [Manus blog](https://manus.im/blog/Context-Engineering-for-AI-Agents-Lessons-from-Building-Manus); [agentic-ai.readthedocs summary](https://agentic-ai.readthedocs.io/en/latest/ContextEngineering/manus/) **[Secondary]**
- "Even a single-token difference can invalidate the cache from that token onward." A timestamp at the start of the system prompt is a common mistake, and non-deterministic JSON key ordering silently breaks caching. See [Manus blog](https://manus.im/blog/Context-Engineering-for-AI-Agents-Lessons-from-Building-Manus) (via search summary)
- "Mask, don't remove": removing tools mid-task changes the early part of the context, which invalidates the cache. Manus keeps tool definitions fixed and uses a context-aware state machine with logit masking to block or force actions. Consistent tool-name prefixes (`browser_*`, `shell_*`) make group-level constraints easy. See [Manus blog](https://manus.im/blog/Context-Engineering-for-AI-Agents-Lessons-from-Building-Manus) (via search summary)
- Secondary write-ups add that without constrained decoding, removing tools tends to cause schema violations or hallucinated actions. See [Manus search summary](https://agentic-ai.readthedocs.io/en/latest/ContextEngineering/manus/) **[Secondary]**
- The file system serves as external context, with **restorable** compression: "a web page's body can be dropped if its URL is kept, and a document's contents can be omitted if its path remains available in the sandbox". See [Manus blog](https://manus.im/blog/Context-Engineering-for-AI-Agents-Lessons-from-Building-Manus) (via search summary)
- Recitation: for complex tasks Manus keeps a `todo.md` and rewrites it as work proceeds, "reciting its objectives into the end of the context". See [Manus blog](https://manus.im/blog/Context-Engineering-for-AI-Agents-Lessons-from-Building-Manus) (via search summary)
- "A typical Manus task requires around 50 tool calls" appears only in a secondary summary. See [agentic-ai.readthedocs](https://agentic-ai.readthedocs.io/en/latest/ContextEngineering/manus/) **[Secondary]**
- A December 2025 follow-up says Manus's harness "has evolved beyond the original post", so details may be superseded. See [Phil Schmid, Context Engineering Part 2](https://www.philschmid.de/context-engineering-part-2) **[Secondary]**

**Chroma, "Context Rot: How Increasing Input Tokens Impacts LLM Performance" (Hong, Troynikov, Huber, 14 Jul 2025) [Independent-ish: research by a retrieval-infrastructure vendor, with open-source reproduction code]**; see [Chroma research](https://trychroma.com/research/context-rot); [code](https://github.com/chroma-core/context-rot)
- The study covered **18 LLMs**, including GPT-4.1, Claude 4, Gemini 2.5 and Qwen3. Its central finding: models "do not use their context uniformly", and performance "grows increasingly unreliable as input length grows". The tasks were deliberately simple (LongMemEval conversational QA, repeated-word copying), to isolate the effect of length. See [Chroma research](https://trychroma.com/research/context-rot) (via search summary)
- "Needle-question similarity, presence of distractors, haystack structure, and semantic relationships" all affect performance non-uniformly as length grows. See [ZenML summary](https://www.zenml.io/llmops-database/context-rot-evaluating-llm-performance-degradation-with-increasing-input-tokens) **[Secondary]**
- Secondary write-ups of the findings:
  - Shuffled haystacks outperformed logically coherent ones across all 18 models.
  - A single plausible distractor reduces accuracy, and four reduce it further.
  - LongMemEval with a focused ~300-token input beat the full ~113K-token history for every model family. The size of the gap varies by write-up (quoted as roughly 30% to 30-60%).
  - Claude models abstain more often when unsure, while GPT models hallucinate more confidently.
  
See [PromptHub](https://www.prompthub.us/blog/why-long-context-windows-still-dont-work); [MorphLLM](https://www.morphllm.com/context-rot) **[Secondary; exact figures unverified]**

**Liu et al., "Lost in the Middle: How Language Models Use Long Contexts" (arXiv July 2023; TACL 2024) [Independent, peer-reviewed]**; see [arXiv 2307.03172](https://arxiv.org/abs/2307.03172); [TACL](https://aclanthology.org/2024.tacl-1.9/)
- "Performance is often highest when relevant information occurs at the beginning or end of the input context, and significantly degrades when models must access relevant information in the middle of long contexts", even for explicitly long-context models. (via search summary of the abstract)
- The tasks were multi-document QA over NaturalQuestions-Open with 10/20/30 documents, and key-value retrieval. Models included GPT-3.5-Turbo, GPT-4, Claude-1.3, MPT-30B and LongChat-13B. Secondary sources put GPT-3.5's best-to-worst-position drop at about 20 points, with inconsistent exact figures. See [aktagon paper summary](https://ai-papers.aktagon.com/papers/lost-middle/); [Liner review](https://liner.com/review/lost-in-middle-how-language-models-use-long-contexts) **[Secondary]**
- The models tested are from 2023, so absolute effects are likely smaller on 2026 models. Chroma's 2025 results suggest the general length sensitivity persists.

**Other evidence**
- Anthropic says tool-selection ability "degrades once you exceed 30-50 available tools" **[Vendor claim]**. See [Tool search docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool)
- Anthropic's compaction docs state that "response quality degrades as a conversation grows" **[Vendor docs]**. See [Compaction overview](https://platform.claude.com/docs/en/build-with-claude/compaction)
- LangChain's framing (2 Jul 2025): context engineering is **write** (save outside the window), **select** (pull in what the step needs), **compress** (keep only needed tokens) and **isolate** (split across sub-agents or state). See [LangChain blog: Context engineering](https://www.langchain.com/blog/context-engineering); [langchain-ai/context_engineering](https://github.com/langchain-ai/context_engineering) **[Vendor guidance]**

### Inferences
Concrete output rules for binary-mcp tools:
1. **Lead with the answer.** Every decompile, listing or debug result should start with a compact header: identity (address, name, signature), size, key callees, imported APIs and strings, a one-line verdict or summary, and an artifact ID or content hash. The body comes after the header or behind the ID. Position effects and summariser behaviour both favour what comes first. Claude Code also middle-truncates long errors, keeping the head and tail.
2. **Do not re-send near-duplicate bodies.** Sibling functions, re-decompiles after renames, and the same function shown in both pseudocode and disassembly are exactly the "plausible distractor" content that Chroma found most harmful. Prefer diffs ("same as FUN_x except lines 12-18"), references to an earlier artifact ID, or opt-in full bodies.
3. **Make every elision restorable.** Each truncated or summarised result should name the ID, path or URI, and the paging parameters, needed to get the rest (Manus's URL/path rule). The memoised analysis cache makes restoration cheap and byte-identical.
4. **Recite briefly.** A short ledger delta, for example "reviewed 37/412 functions; 3 flagged; next candidates…", occasionally appended keeps the goal in recent attention (Manus `todo.md`). It should be a delta of a few lines, not the full ledger on every call.
5. **Keep the action space static** (section 1, rule 1). Express "debugger not attached" or "Ghidra project not loaded" as tool-result state with a next step, not by changing the tool list.
6. **Serialise results deterministically.** Use sorted keys and stable ordering, and leave volatile fields such as `created_at` timestamps out of bodies the model reads. This does not affect caching of the earlier prefix, but it lets content hashes, client-side dedup (for example OpenCode's DCP plugin, section 5) and server-side "unchanged" checks work.

### Gaps
- The parent brief cites Manus's "keep the wrong stuff in" (leave error traces in context) and "don't get few-shotted" (vary structure) lessons. They are not confirmed in any summary I could retrieve and should be checked against the original post.
- Chroma's exact numbers for the LongMemEval gap and the distractor effect could not be verified from the primary page.
- No study was found that measures long-context degradation specifically on **tool-result-heavy agent transcripts**, or on code/disassembly content. The evidence is from documents and chat histories.

---

## 4. Agent Skills (SKILL.md progressive disclosure) and Claude Code plugins: can workflow guidance move out of tool descriptions and server instructions, and what are the token economics?

### Takeaway
Yes, at least for Claude Code, and probably with better economics:
- A skill costs about 100 tokens of always-loaded metadata. Its body, recommended under 5K tokens, loads once when triggered.
- Invoking a skill appends a message, so it does not invalidate the cache.
- In Claude Code, server instructions are cut at 4,096 characters, so long workflow guidance placed there is truncated anyway.
- A plugin can ship the MCP server, skills, hooks and subagents together, and its skill, agent and hook components never invalidate the cache.

The dollar savings from moving static text are modest, because cached text is cheap. The bigger gains are no truncation, loading guidance only for sessions that need it, and a smaller attention load. Portability beyond Claude Code is the main constraint.

### Cited Findings
- Progressive disclosure in Agent Skills **[Vendor docs]**:
  - **Level 1**, metadata (name and description): "~100 tokens per Skill", loaded at startup into the system prompt.
  - **Level 2**, the SKILL.md body: "Under 5k tokens", loaded when triggered.
  - **Level 3+**, bundled files: no cost "until accessed"; "Scripts run through bash, and only their output enters context".
  - Limits: `name` ≤64 characters, `description` ≤1,024 characters.
  
See [Agent Skills overview](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview)
- Where skills are available **[Vendor docs]**:
  - Claude API, which requires the code execution tool.
  - Claude Code: filesystem `~/.claude/skills/` or `.claude/skills/`, "Can also be shared through Claude Code Plugins".
  - claude.ai custom skills: zip upload, on Pro/Max/Team/Enterprise plans with code execution enabled, per user only.
  - "Custom Skills do not sync across surfaces."
  
See [Agent Skills overview](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview)
- In Claude Code **[Vendor docs]**:
  - A skill's description is "always in context", unless `disable-model-invocation: true`.
  - The combined `description` and `when_to_use` text "is truncated at 1,536 characters in the skill listing".
  - The body loads only when used and "stays in context across turns".
  - After compaction, Claude Code "re-attaches the most recent invocation of each skill … keeping the first 5,000 tokens of each", with "a combined budget of 25,000 tokens".
  - "Keep `SKILL.md` under 500 lines", because "every line is a recurring token cost".
  - `context: fork` runs a skill in a subagent.
  - Plugin skills live at `<plugin>/skills/<skill-name>/SKILL.md` and are invoked as `/plugin-name:skill-name`.
  
See [Claude Code skills](https://code.claude.com/docs/en/skills)
- The skill *listing* "is not re-injected after `/compact`. Only skills you actually invoked get preserved." See [Claude Code: Explore the context window](https://code.claude.com/docs/en/context-window)
- Cache effects in Claude Code **[Vendor docs]**:
  - "Skills and commands inject their instructions as user messages at the point of invocation. Nothing earlier in the conversation changes."
  - "Claude Code never invalidates the cache for a plugin's skills, commands, agents, hooks, monitors, or themes."
  - A plugin's MCP servers follow the same rules as connecting or removing an MCP server.
  
See [Claude Code prompt caching](https://code.claude.com/docs/en/prompt-caching)
- Plugin-bundled MCP tools are named `mcp__plugin_<plugin-name>_<server-name>__<tool>` for hook matching. See [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- Claude Code leaves out any MCP tool whose full name exceeds 128 characters. See [Claude Code MCP docs](https://code.claude.com/docs/en/mcp)
- Claude Code's cost guidance:
  - Move specialised workflow instructions from CLAUDE.md into skills, because skills "load on-demand only when invoked". Keep CLAUDE.md under 200 lines.
  - A domain-knowledge skill lets Claude get context "immediately instead of spending tokens reading multiple files".
  
See [Claude Code costs](https://code.claude.com/docs/en/costs)
- Server instructions and upfront tool descriptions are cut at 4,096 characters, and deferred-tool descriptions at 16,384. See [Claude Code MCP docs](https://code.claude.com/docs/en/mcp)
- MCP **prompts** appear in Claude Code as `/mcp__servername__promptname` commands, and "Prompt results are injected directly into the conversation". See [Claude Code MCP docs](https://code.claude.com/docs/en/mcp)
- "Code execution with MCP" (4 Nov 2025) **[Vendor claim]**: presenting tools as files and filtering data in code cut one workflow from "150,000 tokens to 2,000 tokens" (98.7%). Agents can save working code as reusable functions with a SKILL.md, turning it "into a structured skill". See [Anthropic, Code execution with MCP](https://www.anthropic.com/engineering/code-execution-with-mcp)

### Inferences
- **Token economics** (my arithmetic, Opus 5.5 prices; a "request" is one model call, and each tool call adds one):
  - *Guidance in server instructions.* Instructions sit in the prefix every session. Anything past about 4,096 characters (roughly 1,000 tokens at the ~4 chars/token rule of thumb) is silently cut in Claude Code. At 1,000 tokens it costs about $0.0002 per request cached, which is trivial, but it occupies attention in every session, including quick PE-triage sessions that never decompile.
  - *Guidance repeated across tool descriptions.* Under deferral each discovered tool's description expands into context. A 300-token workflow paragraph copied into 20 tools, 10 of which get discovered, means about 3,000 tokens of duplicates. Without deferral, every copy loads upfront.
  - *Guidance as a skill.* About 100 tokens of description always load (≤1,536 characters shown). A 3,000-token body loads once per session that needs it: about $0.015 to write plus 300 × 3,000 × $0.20/MTok ≈ $0.18 of re-reads over 300 requests, so about $0.20 per session. Up to 5,000 tokens are re-attached after compaction.
  - *For comparison*, one 10K-token decompilation that stays resident for 200 requests costs about $0.45 (section 5). Shrinking results matters more in dollars than relocating guidance. Relocating guidance is still worth doing for truncation, relevance and attention reasons.
- **Suggested split for binary-mcp:**
  1. A short static **server-instructions map**, ≤4,096 characters and ideally ≤1,000 tokens: tool categories, when to search, the 3-5 entry-point tools, and the handle/job/ledger conventions.
  2. **Per-workflow skills**, each under 5K tokens with references in separate files: PE/malware triage, static decompile/xref loop, dynamic debugging, .NET. Only the relevant one loads.
  3. Minimal **per-tool descriptions** covering what the tool does, its key parameters, and its output shape with size controls.
  4. A Claude Code **plugin** that bundles the server, the skills, optional hooks (section 6) and possibly a "bulk-reader" subagent on a cheaper model.
- **Portability:**
  - Claude Desktop custom skills need code execution and a per-user upload, and they do not sync from Claude Code.
  - OpenCode support for SKILL.md is unverified.
  - MCP prompts (protocol-native, user-invoked) are the portable fallback for workflow scripts.
  - Instructions and descriptions must therefore still carry the minimal essentials on their own.
- **Plugin naming has a side effect.** The plugin form changes tool names (the `mcp__plugin_…` prefix). That affects users' existing permission rules and hook matchers, and pushes names toward the 128-character cap.

### Gaps
- Whether OpenCode supports Agent Skills/SKILL.md, and how it surfaces MCP prompts, was not verified.
- Whether Claude Desktop combines its skills with local MCP servers in a way that keeps progressive disclosure was not verified.
- No measured comparison (tokens or task success) of skills versus long server instructions or tool descriptions was found. Anthropic's ~100 / <5K token figures are design guidance, not measurements.
- How reliably skills auto-trigger, which is what makes the guidance load when needed, was not quantified in the sources.

---

## 5. Server-side caching, memoisation and dedup; artifacts on disk; job handles; MCP sampling for server-side summarisation

### Takeaway
The server's job is to send less and make what it sends restorable:
- Memoise expensive analysis, which saves latency and compute.
- Return headers and IDs instead of bodies, which saves tokens.
- Offer "unchanged" stubs only when the model asserts it still holds the content.
- Keep large artifacts on disk or behind paged resources, and run long work as jobs with small status payloads.

MCP sampling is not a viable summarisation path in 2026. It is **deprecated** as of protocol revision 2026-07-28, and Claude Code does not support it. Summaries should be deterministic and server-side, or produced by client-side subagents. Where an LLM summary is needed, call a provider API directly, which is the spec's own migration path, and cache the result.

### Cited Findings
- Anthropic's tool-writing guidance (11 Sep 2025) **[Vendor guidance]**:
  - Expose a `response_format` enum (`DETAILED`/`CONCISE`); in its example the detailed response used **206 tokens** and the concise one **72**, and Slack-style concise responses used about one-third of the tokens.
  - Limit size with "pagination, range selection, filtering, and truncation with sensible default values". "Claude Code restricts tool responses to 25,000 tokens by default."
  - When truncating, steer the agent toward narrower, token-efficient follow-ups.
  - Replacing UUIDs with interpretable identifiers improved precision.
  
See [Anthropic, Writing effective tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents)
- Programmatic tool calling cut average tokens on complex research tasks from **43,588 to 27,297 (-37%)**. In a budget example, raw data of 200 KB was reduced to about 1 KB of output **[Vendor claim]**. See [Anthropic, Advanced tool use](https://www.anthropic.com/engineering/advanced-tool-use)
- "Code execution with MCP" **[Vendor claim]**:
  - Intermediate results pass through the model, so "a 2-hour sales meeting transcript could add about 50,000 tokens because it passes through the model twice".
  - Filtering in code means the agent sees five rows instead of 10,000.
  - Agents can persist intermediate results to files.
  - Caveat: code execution "requires a secure execution environment with appropriate sandboxing".
  
See [Anthropic, Code execution with MCP](https://www.anthropic.com/engineering/code-execution-with-mcp)
- Just-in-time retrieval through "lightweight identifiers (file paths, stored queries, web links, etc.)". See [Anthropic, Effective context engineering](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents)
- Manus's restorable compression: keep the URL or path and drop the body. See [Manus blog](https://manus.im/blog/Context-Engineering-for-AI-Agents-Lessons-from-Building-Manus) (via search summary)
- Claude Code already persists large MCP results to disk: over 25K tokens by default, or over 50K characters, results are saved and replaced with a path. Long calls are auto-backgrounded after 2 minutes, with a task notification on completion. See [Claude Code MCP docs](https://code.claude.com/docs/en/mcp)
- Context editing replaces cleared results with a placeholder that tells Claude the result was removed, and Claude can re-fetch from memory. See [Context editing docs](https://platform.claude.com/docs/en/build-with-claude/context-editing)
- Client-side dedup exists in the wild. OpenCode's Dynamic Context Pruning plugin keeps only the most recent output of repeated calls (same tool, same arguments), purges errored-call inputs after 4 turns by default, and swaps pruned content for placeholders before sending **[Secondary/third-party plugin]**. See [Opencode-DCP on GitHub](https://github.com/Opencode-DCP/opencode-dynamic-context-pruning)
- OpenCode V2's built-in compaction: `auto` is on by default. `prune` "is accepted by the V2 schema but currently has no runtime effect", and V2 "does not clear old tool outputs in place". Older OpenCode versions pruned old tool outputs, keeping the most recent ~40K tokens **[Secondary for the older behaviour]**. See [OpenCode V2 compaction docs](https://v2.opencode.ai/compaction); [learnopencode](https://learnopencode.com/en/5-advanced/20-compaction)
- **MCP sampling is deprecated** **[Spec, via search summary; fetch blocked]**:
  - "The Sampling feature is deprecated as of protocol version 2026-07-28 (SEP-2577)".
  - Under the feature lifecycle policy (SEP-2596) it remains "for at least twelve months", and "New implementations SHOULD NOT adopt it".
  - The migration path is to "integrate directly with LLM provider APIs".
  - The `includeContext` values `thisServer`/`allServers` are also deprecated.
  
See [MCP 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog); [noze.it summary](https://www.noze.it/en/insights/mcp-2026-07-28-stateless/) **[Secondary]**
- One MCP SDK's documentation notes that "on modern connections sampling fails because a 2026-07-28 session has no channel to carry one". The search summary did not name the SDK; the results included the Python SDK's deprecated-features page and the Ruby gem's `MCP::ProtocolDeprecations`. See [MCP Python SDK: deprecated features](https://py.sdk.modelcontextprotocol.io/deprecated/) (via search summary; attribution unconfirmed)
- Client support for sampling:
  - **Claude Code**: still lacks sampling. Feature request #1785 has been "open since June 2025 and was still open … in August 2026" **[Secondary]**. The retrieved text of Claude Code's MCP docs covers roots, elicitation (form and URL capabilities declared on 2026-07-28 connections) and protocol revision 2026-07-28 on the v2 runtime, and never mentions sampling.
  - **Claude Desktop**: sources conflict. The newest says it is not supported, while an older comparison claims full support.
  - **VS Code**: supports sampling.
  
See [Developers Digest, MCP client features 2026](https://www.developersdigest.tech/blog/mcp-client-features-explained-2026); [Claude Code MCP docs](https://code.claude.com/docs/en/mcp); conflicting: [Pondero MCP client comparison](https://pondero.ai/mcps/guides/mcp-client-comparison/)

### Inferences
- **Memoisation and token savings are separate concerns.** binary-mcp's analysis cache already avoids re-running Ghidra. Tokens fall only if responses get smaller. The cache key should include the binary hash, function address, engine version and options, so that hashes in results are stable across a session and a restart.
- **"Unchanged since last call" must be asserted by the client.** The server cannot tell whether the model still holds the earlier copy. Context editing, Claude Code's tool-result clearing, compaction, or a new session may have dropped it. A stub returned when the content is gone forces another call and costs more. Suggested design:
  - Every body carries a content hash or ETag in its header.
  - Tools accept an optional `known_hash` / `if_none_match`.
  - The server returns a one-line "unchanged (hash H)" only when the model passes the matching hash; otherwise it returns the body.
  - Context editing's placeholder tells Claude when a result was removed, so the model can omit the hash.
- **Lifetime cost of a resident result** (my arithmetic). An N-token result that stays in context for k more requests costs N·(w + k·r)·base.

  | Result | Model | Write | Re-reads (k = 200) | Total |
  |---|---|---|---|---|
  | 10K-token decompilation | Opus 5.5 | $0.05 | $0.40 | **$0.45** |
  | 10K-token decompilation | Sonnet 4.6 | $0.04 | $0.60 | **$0.64** |
  | 600-token header + handle | Opus 5.5 | | | **≈ $0.027** |

  Re-reads overtake the one-time write after only w/r = 25 requests on Opus 5.5, or 12.5 on 0.1× models. In sessions with hundreds of tool calls, how long a result stays resident is the dominant cost, which is why summaries plus handles beat full bodies even when the full body is needed once.
- **Artifacts on disk or behind resources.**
  - Write large outputs (full listings, multi-function dumps, traces) to the server's output directory and return a header, path or URI, and paging parameters.
  - In Claude Code a path is directly usable with the built-in Read/Grep tools, so the model can grep a 10K-line listing instead of loading it. Other clients may lack filesystem tools, so a paged `get_artifact(id, offset, limit)` tool and/or an MCP resource URI is the portable path.
  - This also avoids Claude Code's generic ">25K tokens / >50K characters saved to file" behaviour, which happens only in Claude Code and carries no summary.
- **Job handles.**
  - They fit just-in-time retrieval. Keep status payloads tiny (state, progress, ETA, result ID).
  - Claude Code also auto-backgrounds MCP calls longer than 2 minutes.
  - Timing interacts with the cache TTL. On API-key or usage-credit Claude Code (5-minute main TTL), if the agent idles more than 5 minutes waiting for a job, the next turn misses the cache: at 150K context on Opus 5.5 that is about $0.75 instead of $0.03.
  - Returning an ETA, and documenting `promptCacheTtl: 1h` for long-job sessions, avoids repeated misses. Subscription users already get a 1-hour TTL by default.
- **Sampling is not worth adopting.** It is deprecated, unsupported in Claude Code (and probably Claude Desktop), and on 2026-07-28 sessions it reportedly cannot be carried.
  - Deterministic summaries are cheaper, reproducible and need no API key: signature, callees/callers, imported APIs, strings, xref counts, loop/complexity metrics.
  - Where natural-language summaries clearly help, call a provider API with a small model directly (the spec's migration path), cache by function hash so each summary is computed once per binary, and treat it as opt-in. Sending binary code to a third-party API is a data-governance issue.
  - Otherwise, let the client's subagents be the summarisers.

### Gaps
- FastMCP's server-side sampling fallback handler (for clients without sampling) could not be checked (gofastmcp.com was not fetched). This matters only if sampling were pursued, which the evidence argues against.
- How each client renders or fetches MCP `resource_link` / embedded-resource content in tool results (token cost when auto-fetched) was not covered here. It belongs to the MCP-spec and client-support thread.
- No measurements were found of how often agents re-request the same function in RE sessions, which sets the real value of dedup. The binary-mcp transcripts or coverage ledger could provide this.
- The official MCP changelog and sampling pages could not be fetched (DNS), so the deprecation text is from search summaries. The SEP numbers (2577 for the deprecation, 2596 for the lifecycle policy) agree across the summaries.

---

## 6. Hooks: can Claude Code hooks (PostToolUse, PreToolUse) rewrite or trim MCP tool output before it enters context, or steer the model to cheaper tools?

### Takeaway
Yes, in Claude Code only, as of October 2026:
- **PostToolUse** `updatedToolOutput` replaces a tool's output "before it is sent to Claude". For MCP tools it is passed through without schema validation.
- **PreToolUse** can rewrite arguments (`updatedInput`) or deny a call with a reason that Claude sees.
- **PostToolBatch**, **SessionStart(compact)** and **PreCompact** add batch-level and compaction-time control.

These make a Claude Code plugin a good place for user-tunable token policy. Server-side shaping remains the portable baseline, since Claude Desktop and OpenCode do not share this hook system.

### Cited Findings
- PostToolUse input includes `tool_input` and `tool_response`, plus `mcp_server` for MCP tools. See [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- `updatedToolOutput`:
  - "Replaces the tool's output with the provided value before it is sent to Claude. The value must match the tool's output shape."
  - "For built-in tools, a value that doesn't match the tool's output schema is ignored … MCP tool output is passed through without schema validation."
  - The older `updatedMCPToolOutput` works for MCP tools only; the docs say to "Prefer `updatedToolOutput`, which works for all tools".
  
See [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- "`updatedToolOutput` only changes what Claude sees. The tool has already run … Telemetry such as OpenTelemetry tool spans … captures the original output." With `decision: "block"`, "Claude still sees the original output; to replace it, use `updatedToolOutput`." See [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- PreToolUse fields:
  - `permissionDecision`: `allow`/`deny`/`ask`/`defer`, with precedence "`deny` > `defer` > `ask` > `allow`".
  - `permissionDecisionReason`: for `deny` it is "shown to Claude".
  - `updatedInput`: "Modifies the tool's input parameters before execution. Replaces the entire input object".
  - `additionalContext`.
  
  The docs do not say Claude will then pick a different tool; they only say the reason is shown to Claude. See [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- `PostToolBatch` "fires exactly once with the full batch" before the next model request. Its input carries the serialised `tool_result` content "the model receives", and its `additionalContext` is "injected once before the next model call". See [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- Hook handler types are `command`, `http`, `mcp_tool` (call an MCP server's tool, with `${path}` substitution from the input), `prompt` and `agent`; agent hooks are experimental. Default timeouts are 600 s for command/http/mcp_tool, 30 s for prompt and 60 s for agent. See [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- MCP matchers use `mcp__<server>__<tool>`; matchers containing regex characters are unanchored JavaScript regexes, for example `mcp__memory__.*`. Plugin servers use `mcp__plugin_<plugin>_<server>__<tool>`. See [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- A hook's `additionalContext`, `systemMessage`, `initialUserMessage` and plain stdout are each "capped at 10,000 characters". Over the cap, Claude Code saves the output to a file and passes "the file path and a preview of up to the first 2,000 characters". See [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- Compaction-related events: `PreCompact` (matcher `manual`/`auto`; exit 2 "Blocks compaction"), `PostCompact`, and `SessionStart` with matcher `compact`, which accepts `additionalContext`. See [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- Claude Code's own cost guide shows a PreToolUse hook that rewrites test commands, through `updatedInput`, to output only failures. It states that hooks can cut a 10,000-line log "from tens of thousands of tokens to hundreds". See [Claude Code costs](https://code.claude.com/docs/en/costs)
- Plugin hooks never invalidate the prompt cache. See [Claude Code prompt caching](https://code.claude.com/docs/en/prompt-caching)
- OpenCode has plugin events `tool.execute.before`/`tool.execute.after`. Whether and how the after-hook can rewrite output is not officially documented in sources I found **[Secondary]**. See [skills.sh: writing OpenCode plugins](https://skills.sh/ian-pascoe/dotfiles/writing-plugins)

### Inferences
- **What a binary-mcp Claude Code plugin's hooks could do:**
  1. **Steer cheap-first (PreToolUse).**
     - On `mcp__…binary-mcp__.*` tools carrying the `code-output` facet, `updatedInput` can inject conservative defaults (line or function caps, concise format) when the model omitted them.
     - `deny` can block bulk code-reading until triage has run, with a reason naming the cheaper tool ("call get_function_summary / triage first").
     - The repo's tool_catalog facets and docs/tool-catalog.json were designed for exactly this gating.
  2. **Externalise oversized results (PostToolUse `updatedToolOutput`).** The hook would replace very large MCP results with header + path + artifact ID. This is better done in the server (no subprocess per call, portable). Hooks suit *user-tunable* policy, such as a per-user cap.
  3. **Rehydrate after compaction (SessionStart `compact`).** The hook injects a ledger and state digest of at most 10,000 characters: loaded binary, functions reviewed, open jobs, flagged items. It could use an `mcp_tool` hook that calls a binary-mcp digest tool, so compaction does not force the model to rediscover state with expensive calls.
  4. **Batch-level recitation (PostToolBatch).** Add one short ledger delta per batch instead of per tool.
- **Hook output still costs tokens.** `additionalContext` and replacement outputs become resident like any tool result. They are appended, so they never invalidate the cache, but they should be terse.
- **A deny-with-reason costs a model round trip**, since Claude reads the reason and re-plans. It is cheaper than a large wrong output, but not free. Prefer `updatedInput` (silently cap) for size policy, and `deny` for workflow ordering.
- **Hooks see the original output first.** Telemetry captures the original, which is useful for measuring how much hooks save.
- **Portability:** Claude Desktop has no equivalent hook system in the sources found. OpenCode's plugin API might allow similar rewriting but is unverified. Server-side defaults (small default limits, concise default format, headers plus handles) therefore remain the baseline that works in every client.

### Gaps
- The official OpenCode plugin documentation on whether `tool.execute.after` can replace tool output could not be retrieved.
- No source confirmed whether Claude Desktop exposes any hook or interception mechanism for MCP results.
- No measurements of hook latency overhead for per-call `command` hooks (process spawn plus jq), which matters with hundreds of tool calls, were found.
- How Claude Code serialises a hook-replaced MCP output (the expected CallToolResult/content-block shape) is not fully specified: the docs say only "passed through without schema validation". A plugin would need to test this.
