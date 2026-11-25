# Designing tools for LLM agents that drive debuggers and RE environments over MCP

Scope: design principles and patterns, with evidence, for binary-mcp's x64dbg tool surface. The current surface is 16 grouped `op` tools, about 175 ops and about 7.4k tokens of descriptions. All sources were fetched or searched on 2026-11-23.

## 1. Vendor guidance on writing tools for agents (Anthropic, OpenAI, MCP spec)

### Takeaway
The vendors broadly agree on these points:
- Build a few well-chosen, workflow-shaped tools rather than thin API wrappers.
- Namespace related tools.
- Return high-signal, token-bounded output with an optional verbosity switch.
- Paginate or truncate, and tell the model how to get more.
- Write actionable errors.
- Use strict, typed schemas with enums.
- Iterate on descriptions against realistic evals.

### Cited Findings
**Consolidation and workflow shape**
- Anthropic advises building "a few thoughtful tools targeting specific high-impact workflows" and warns against tools that "merely wrap existing software functionality or API endpoints." — [Anthropic, Writing effective tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents)
- Anthropic recommends consolidating multi-step work into one call, for example `schedule_event` instead of `list_users`, `list_events` and `create_event`. It prefers search over list (`search_contacts` over `list_contacts`) and `search_logs` over `read_logs`. — [Anthropic](https://www.anthropic.com/engineering/writing-tools-for-agents)
- Anthropic says overlapping or too many tools "can also distract agents from pursuing efficient strategies." — [Anthropic](https://www.anthropic.com/engineering/writing-tools-for-agents)

**Namespacing**
- Anthropic suggests prefixing tools by service or resource (e.g. `asana_search`, `asana_projects_search`), and testing prefix against suffix naming in evals because results vary by model. — [Anthropic](https://www.anthropic.com/engineering/writing-tools-for-agents)

**Response content and size**
- Return high-signal fields and drop low-level identifiers such as uuid and mime_type. Mapping opaque IDs to names or 0-based indexes reduced hallucination. — [Anthropic](https://www.anthropic.com/engineering/writing-tools-for-agents)
- Anthropic suggests a `response_format` enum (`concise` / `detailed`). In its Slack example, concise responses used about one third of the tokens. Detailed mode exposes the IDs that later calls need. — [Anthropic](https://www.anthropic.com/engineering/writing-tools-for-agents)
- Response structure (XML, JSON or Markdown) affects performance, so choose it by eval. — [Anthropic](https://www.anthropic.com/engineering/writing-tools-for-agents)
- For large outputs, use pagination, range selection, filtering or truncation with sensible defaults. Claude Code caps tool responses at 25,000 tokens by default. When truncating, tell the agent how to continue and encourage small targeted queries. — [Anthropic](https://www.anthropic.com/engineering/writing-tools-for-agents)

**Errors**
- Errors should state specific, actionable fixes, not opaque codes or tracebacks. Including examples of valid input helps. — [Anthropic](https://www.anthropic.com/engineering/writing-tools-for-agents)

**Descriptions and parameters**
- Write descriptions as if onboarding a new hire, and make query formats, niche terms and relationships explicit. — [Anthropic](https://www.anthropic.com/engineering/writing-tools-for-agents)
- Use unambiguous parameter names (`user_id`, not `user`) and enforce inputs with strict data models. — [Anthropic](https://www.anthropic.com/engineering/writing-tools-for-agents)
- "Even small refinements to tool descriptions can yield dramatic improvements." Anthropic cites SWE-bench Verified gains from description edits alone. — [Anthropic](https://www.anthropic.com/engineering/writing-tools-for-agents)
- Tool use examples (`input_examples`) raised accuracy on complex parameter handling from 72% to 90% in Anthropic's internal testing. Examples teach formats, how to build nested objects, and which optional parameters go together. Anthropic recommends 1–5 examples per tool, for cases where the schema alone is not obvious. — [Anthropic, Advanced tool use](https://www.anthropic.com/engineering/advanced-tool-use)

**OpenAI guidance**
- Write clear, detailed function names, parameter descriptions and instructions. — [OpenAI function calling guide](https://developers.openai.com/api/docs/guides/function-calling)
- "Use enums and object structure to prevent invalid states." — [OpenAI](https://developers.openai.com/api/docs/guides/function-calling)
- Apply the "intern test": could a new hire use the function from what the model sees alone? — [OpenAI](https://developers.openai.com/api/docs/guides/function-calling)
- Don't ask the model for arguments your code already knows, and combine functions that are always called in sequence. — [OpenAI](https://developers.openai.com/api/docs/guides/function-calling)
- Aim for fewer than 20 functions at the start of a turn (a soft suggestion), and defer large or rarely used parts of the surface with tool search. — [OpenAI](https://developers.openai.com/api/docs/guides/function-calling)
- Group tools by domain namespace. — [OpenAI](https://developers.openai.com/api/docs/guides/function-calling)
- "We recommend always enabling strict mode": `additionalProperties: false`, every property required, and optional fields expressed as nullable. — [OpenAI](https://developers.openai.com/api/docs/guides/function-calling)

**Evaluation**
- Use realistic multi-call tasks with verifiable outcomes, and track accuracy, runtime, call count, tokens and tool errors. — [Anthropic](https://www.anthropic.com/engineering/writing-tools-for-agents)
- Read the transcripts. Many redundant calls point to pagination or limit tuning; many invalid-parameter errors point to unclear descriptions or missing examples. Use held-out test sets. — [Anthropic](https://www.anthropic.com/engineering/writing-tools-for-agents)

**MCP spec**
- Tools declare `inputSchema` (JSON Schema with `required`), an optional `outputSchema`, and optional `annotations`. — [MCP spec 2025-06-18, Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- Servers MUST validate all tool inputs, implement access controls, rate-limit invocations, and sanitize tool outputs. — [MCP spec 2025-06-18, Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- Clients SHOULD implement timeouts and log tool usage. — [MCP spec 2025-06-18, Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- Tool execution errors belong in the result with `isError: true`. Protocol errors (JSON-RPC) cover unknown tools and invalid arguments. — [MCP spec 2025-06-18, Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)

### Inferences
- binary-mcp's op catalogue lists argument names only. That breaks the "strict data model", "intern test" and "enums prevent invalid states" guidance. Each op's parameters need types, required/optional status, enums and an example.
- Near-duplicate ops are the "overlapping tools" anti-pattern; merge them or remove one.
- Free-text outputs and broken ops will show up in eval transcripts as invalid-parameter errors and redundant calls. A small eval harness with real RE tasks is the vendor-recommended way to find them.

### Gaps
- I found no vendor guidance aimed specifically at "one tool with an `op` discriminator" schemas. Section 2 covers this by inference.

## 2. Grouped `op`-style mega-tools vs separate tools; tool count, tool search and progressive disclosure

### Takeaway
Selection accuracy falls as tool count grows, and similar or overlapping tools are the main cause. Vendor-reported mitigations include tool search, deferred loading and namespacing, with large gains. A grouped `op` tool cuts the number of tool names but moves the selection problem into the op parameter. The `op` schema is only safe if it is a strict enum and each op's arguments are properly typed, for example with JSON Schema `oneOf` per op or separate small tools.

### Cited Findings
**Tool search and deferred loading (vendor-reported)**
- Anthropic's Tool Search Tool raised accuracy on its internal MCP evals from 49% to 74% for Opus 4, and from 79.5% to 88.1% for Opus 4.5. — [Anthropic, Advanced tool use](https://www.anthropic.com/engineering/advanced-tool-use)
- Tool definitions dropped from about 77K tokens to about 8.7K (an 85% reduction). — [Anthropic, Advanced tool use](https://www.anthropic.com/engineering/advanced-tool-use)
- Anthropic recommends tool search when definitions exceed 10K tokens, when there are 10 or more tools, or when selection is inaccurate. It is less useful when tools are few and compact. — [Anthropic, Advanced tool use](https://www.anthropic.com/engineering/advanced-tool-use)
- Claude platform docs say selection degrades past roughly 30–50 tools. — [Claude docs, Tool search tool](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool)

**Programmatic tool calling (vendor-reported)**
- Letting the model write code that orchestrates tools keeps intermediate results out of context. Tokens on complex research tasks fell from 43,588 to 27,297. — [Anthropic, Advanced tool use](https://www.anthropic.com/engineering/advanced-tool-use)

**Academic and practitioner evidence on tool count**
- RAG-MCP: retrieving relevant MCP tools first raised selection accuracy from 13.62% to 43.13% and cut prompt tokens by more than 50%. — [arXiv 2505.03275](https://arxiv.org/html/2505.03275v1)
- HumanMCP: accuracy fell about 10 points going from 10 to 100 tools. — [arXiv 2602.23367](https://arxiv.org/pdf/2602.23367)
- MCPVerse: most models degrade as more MCP servers are mounted. — [arXiv 2508.16260](https://arxiv.org/html/2508.16260v2)
- MCP-Atlas: errors cluster around wrong server or tool selection and parameter mistakes. — [arXiv 2602.00933](https://arxiv.org/html/2602.00933v1)
- Informal practitioner tests saw degradation from about 25–50 tools, with ambiguous prompts hit hardest. These are non-peer-reviewed. — [DEV, "We gave LLMs 150 tools"](https://dev.to/craigtracey/we-gave-llms-150-tools-heres-what-broke-2jaj)

**What comparable servers do**
- ida-pro-mcp uses prefix namespacing (`idb_*`, `dbg_*`, `py_eval`). Debugger tools are hidden by default and enabled with `?ext=dbg`, a form of progressive disclosure. — [ida-pro-mcp README](https://github.com/mrexodia/ida-pro-mcp)
- ida-pro-mcp uses strongly typed TypedDict schemas. — [ida-pro-mcp README](https://github.com/mrexodia/ida-pro-mcp)
- MCP supports `notifications/tools/list_changed`, so a server can change its exposed tool set at runtime. — [MCP spec 2025-06-18, Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)

### Inferences
- At about 7.4k tokens, binary-mcp is under Anthropic's 10K threshold, and 16 tools is under OpenAI's ~20 guidance. Grouping therefore achieves the count goal. The open risk is the quality of op selection and argument filling within each group.
- Recommended shape:
  - Make `op` a JSON Schema enum.
  - Express per-op argument sets as a `oneOf` discriminated union, with `required` and enums per branch, or split the hottest 10–15 ops into dedicated, strongly typed tools.
  - Keep rarely used ops behind a `describe_op` / `help` op, or put them in deferred or extension groups (the ida-pro-mcp `?ext=` pattern, plus `list_changed`).
- Merging near-duplicate ops directly removes the "similar tools" failure mode the benchmarks highlight.

### Gaps
- I found no published A/B study of a single `op`-discriminator tool against N separate tools with identical functionality. Grouped-tool accuracy has to be measured with our own evals.
- Whether clients handle large `oneOf` schemas well, including strict-mode compatibility, is unverified.

## 3. Debugger-specific agent research: abstractions used and what improved success

### Takeaway
The successful systems all use these patterns:
- Give the agent an interactive debugger alongside code browsing and scripting.
- Return enriched state, such as stack plus locals plus source context, rather than raw dumps.
- Summarize or truncate long output, with a path back to the full data.
- Report errors that explain exactly what went wrong.
- Provide an explicit "report or verify" endpoint.

Debugger tools help, but agents use them imperfectly. The gains come from letting the model "take the wheel", not from static context alone.

### Cited Findings
**debug-gym (Microsoft)**
- debug-gym gives LLM agents pdb plus tools to view, rewrite, eval and listdir. Agents can set breakpoints, navigate code and print variables. Observations are structured text (e.g. JSON), and code runs in Docker sandboxes. — [Microsoft Research blog](https://www.microsoft.com/en-us/research/blog/debug-gym-an-environment-for-ai-coding-tools-to-learn-how-to-debug-code-like-programmers); [arXiv 2503.21557](https://arxiv.org/pdf/2503.21557)
- Agents with debugging tools beat agents without them across nine LLMs on SWE-bench Lite. Even so, a simple agent "rarely solves more than half" of the issues. The authors attribute the limit to "the scarcity of data representing sequential decision-making behavior" in training data. — [Microsoft Research blog](https://www.microsoft.com/en-us/research/blog/debug-gym-an-environment-for-ai-coding-tools-to-learn-how-to-debug-code-like-programmers)
- debug-gym SWE-bench Lite success rates (mean of 3 runs), rewrite-only vs pdb from the start vs pdb added after the 5th rewrite ("debug(5)"):

  | Model | rewrite | debug | debug(5) |
  |---|---|---|---|
  | Claude 3.7 Sonnet | 37.2 | 48.4 | 52.1 |
  | o1-preview | 10.7 | 30.2 | 30.8 |
  | o3-mini | 8.5 | 22.1 | 19.8 |
  | GPT-4o | 19.1 | 17.2 | 23.6 |

  On Aider, pdb did not help. The authors suspect agents issued pdb commands "without a clear strategy." — [debug-gym, arXiv 2503.21557](https://arxiv.org/html/2503.21557)
- Starting with pdb hurt weaker models (GPT-4o, GPT-4o-mini, Llama-3.3-70B) on SWE-bench but helped stronger ones. Claude over-explored, trying tools that returned nothing useful. — [arXiv 2503.21557](https://arxiv.org/html/2503.21557)
- debug-gym keeps a server-side breakpoint list and restores it when the terminal session restarts. The agent's prompt includes the current breakpoints (file and line) at every step. — [arXiv 2503.21557](https://arxiv.org/html/2503.21557)

**EnIGMA (CTF agent built on SWE-agent)**
- EnIGMA added "Interactive Agent Tools": a gdb session and a pwntools server connection. Commands cover start/stop session, breakpoints, step, continue, and arbitrary commands. — [EnIGMA, arXiv 2409.16165](https://arxiv.org/html/2409.16165)
- Only one interactive session runs at a time, and sessions are non-blocking, so the agent can keep using bash while the session persists. The design generalizes to any REPL-style tool. — [arXiv 2409.16165](https://arxiv.org/html/2409.16165)
- With the interactive tools, solved challenges took 11.5 turns instead of 14.9 (p = 0.019). — [arXiv 2409.16165](https://arxiv.org/html/2409.16165)
- Ablation, pass@1 with Claude 3.5 Sonnet:

  | Configuration | % Solved |
  |---|---|
  | Full EnIGMA | 29.5 |
  | No interactive tools | 27.4 |
  | No summarizer | 28.2 |
  | Simple (save-to-file) summarizer | 26.9 |
  | No demonstrations | 23.3 |

  Removing the interactive tools hurt pwn, rev and crypto. — [arXiv 2409.16165](https://arxiv.org/html/2409.16165)
- Without summarization, long outputs could fill the context window and end the session. Both summarizers attach warnings and instructions for retrieving the full output. — [arXiv 2409.16165](https://arxiv.org/html/2409.16165)
- Failure modes:
  - Agents rarely give up and usually exhaust the budget. Most successes came within 20 steps.
  - "Soliloquizing": Claude 3.5 Sonnet invented tool observations inside one response in 10–48% of trajectories, depending on benchmark. This correlated with about 26% lower success.

  — [arXiv 2409.16165](https://arxiv.org/html/2409.16165)

**Naptime / Big Sleep (Google Project Zero)**
- Naptime's principles:
  - space for reasoning
  - an interactive environment
  - specialised tools (code browser, Python sandbox, debugger, reporter)
  - perfect (automatic) verification
  - sampling many independent trajectories

  The debugger runs the program with inputs, sets breakpoints and evaluates expressions, and captures ASan crash signals. — [Project Zero, Project Naptime](https://projectzero.google/2024/06/project-naptime.html)
- Naptime raised CyberSecEval 2 scores by "up to 20x". Buffer overflow went from 0.05 to 1.00 and advanced memory corruption from 0.24 to 0.76 (GPT-4 Turbo, @20). — [Project Zero](https://projectzero.google/2024/06/project-naptime.html)
- Big Sleep's tools were `debugger_run` (run with input; report crash, breakpoint hits and stderr), `code_browser_source` and `report_success`. The agent recovered from a failed run because the tool reported a specific cause (a missing TCL module). It then reset its breakpoint and found a SQLite stack buffer underflow. — [Project Zero, From Naptime to Big Sleep](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html)

**ChatDBG (FSE'25)**
- The LLM "takes the wheel" through a `debug(command)` function plus domain helpers (`info`, `slice`, `code`, `definition`). — [ChatDBG, arXiv 2403.16354](https://arxiv.org/html/2403.16354v5)
- The initial prompt carries an enriched stack: per-frame variable types and values plus at least 10 source lines. Library frames are elided, aggregates truncated, and recursion depth capped at 3. — [arXiv 2403.16354](https://arxiv.org/html/2403.16354v5)
- Debugger commands are filtered against a whitelist, with an `--unsafe` override. — [arXiv 2403.16354](https://arxiv.org/html/2403.16354v5)
- Results:
  - Python success was 57% with "why?" alone, 67% with a targeted question, and 85% with one follow-up turn.
  - C/C++ produced 36% root-cause fixes and 55% proximate-cause fixes.
  - Taking the wheel gave the large gains, while the enriched stack alone gave smaller ones.
  - Some added features lowered success, possibly because of longer prompts.

  — [arXiv 2403.16354](https://arxiv.org/html/2403.16354v5)

**RE-specific server patterns (ida-pro-mcp)**
- Batch-first design: most ops accept lists and return per-item `{..., error}` results. — [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
- Cursor pagination with a default limit of 1000 and an enforced maximum of 10,000. — [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
- Every call names an explicit `database`, with "no implicit 'current database'." — [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
- A dedicated `int_convert` tool, because "LLMs can sometimes struggle with complex mathematical calculations" and converting between integers and bytes is "especially problematic." — [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)

### Inferences
- A "context snapshot" result (registers, current instruction with a few lines of disassembly around it, stack top, last debug event or exception, module+offset of RIP) mirrors ChatDBG's enriched stack and Big Sleep's `debugger_run` report. It should come back from one tool call, and ideally be attached automatically to every execution-control result (step, run, continue).
- Summarize large outputs such as memory dumps, traces and string lists, with a handle or offset to fetch more (EnIGMA). Plain save-to-file truncation without guidance performed worse.
- Explicit target or session identifiers, batch ops with per-item errors, and server-side number formatting (hex plus decimal, plus symbol+offset) reduce agent arithmetic and addressing errors.
- Results must state clearly when nothing happened, for example "no event; target still running", so that soliloquizing or hallucinated observations are less likely to be mistaken for real state.

### Gaps
- I did not find the exact format of debug-gym's per-command pdb observations (frame or listing) in the parts of the report I read.
- I found no CyberGym or AutoCodeRover details on debugger abstractions within this budget.
- I found no published agent study using a Windows user-mode debugger (x64dbg or WinDbg) specifically.

## 4. Asynchronous execution, long-running operations and accurate state

### Takeaway
Treat execution control as asynchronous:
- Return immediately with a run or session handle, or block only up to an explicit, bounded timeout.
- Always report the authoritative debugger state (running, paused or terminated, plus the reason) in every result.
- Offer non-blocking sessions.

MCP has moved Tasks (call-now, poll-later) from experimental core to an opt-in extension, so a server-level `wait_for_event(timeout)` pattern remains the portable choice.

### Cited Findings
- MCP 2025-11-25 added experimental Tasks:
  - A receiver can return a task handle immediately instead of blocking.
  - Requestors poll with `tasks/get`.
  - Requestors SHOULD respect `pollInterval`.

  — [MCP spec 2025-11-25, Tasks](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks)
- Tasks were later moved out of core into an official extension (`io.modelcontextprotocol/tasks`), which requires opt-in from both client and server. — [MCP latest changelog](https://modelcontextprotocol.io/specification/latest/changelog); [SEP-2663 Tasks extension](https://modelcontextprotocol.io/seps/2663-tasks-extension)
- MCP clients SHOULD implement timeouts for tool calls. — [MCP spec 2025-06-18, Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- EnIGMA's interactive sessions are non-blocking and persist across turns, and the agent can do other work while they stay open. The paper also mentions runtime control for long operations such as brute force (Appendix D, not read). — [arXiv 2409.16165](https://arxiv.org/html/2409.16165)
- Big Sleep's `debugger_run` runs to an outcome and reports crash, breakpoint hit or stderr in one result. — [Project Zero](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html)

### Inferences
- Replace open-ended waits with `run_until(event_types, timeout_ms)`. It should return one of:
  - `{state: paused, reason: breakpoint|exception|singlestep|..., snapshot}`
  - `{state: running, timed_out: true}`, with a hint to call `wait` or `pause`
- Derive `state` from the debugger engine at call time, not from a cached flag. This addresses the "paused while running" bug.
- Include a monotonically increasing `event_seq` or `state_version` in every result, so the model can tell whether state has changed since its last observation.
- Consider the Tasks extension later for long traces or scans, but keep a polling tool for clients that do not support it.

### Gaps
- I found no client-compatibility data for the Tasks extension (which hosts support it as of late 2026).

## 5. Security: prompt injection from binaries, sandboxing, human-in-the-loop, annotations

### Takeaway
Text taken from a binary is attacker-controlled. RE agents have been shown to be vulnerable to prompt injection embedded in binaries. Defence should be layered:
- Fence and label untrusted data.
- Keep the analysis server unable to exfiltrate, which removes one leg of the "lethal trifecta".
- Annotate tools honestly.
- Require human confirmation for state-changing operations.

Annotations are hints only, not enforcement.

### Cited Findings
**Prompt injection via binaries**
- Crawford & McClure (May 2026) show that agentic RE systems are vulnerable to prompt injection hidden in the source of executables, demonstrate detecting injection strings in decompiler output, and study obfuscations and counter-defences. — [arXiv 2605.30677](https://arxiv.org/abs/2605.30677)
- Crawford & McClure's setup was Cline with GhidraMCP and Qwen3-8B. Payloads were compiled into binaries and reached the model through the `list_strings` and `decompile_function` tool outputs. Payloads used fake chat-template tokens such as `<|im_start|>`. — [arXiv 2605.30677 (HTML)](https://arxiv.org/html/2605.30677)
- Attack success fell from 100% to 40% on Qwen3-8B, and from 65% to 50% on OSS-120B, when angle brackets were swapped for square brackets. — [arXiv 2605.30677 (HTML)](https://arxiv.org/html/2605.30677)
- Detection results:

  | Detector | F1 | Recall |
  |---|---|---|
  | Regex on `<...>` | 0.750 | 0.600 |
  | Neural classifier (Qwen3-1.7B backbone) | 0.909 | 1.000 |

  The classifier caught every `list_strings` payload but only 62.5–70.8% of injected functions in decompiler output. — [arXiv 2605.30677 (HTML)](https://arxiv.org/html/2605.30677)
- Obfuscations defeated detection:
  - Non-printing characters such as `\x01` hide the payload from strings extraction.
  - Learned pseudo-system tokens evaded the `list_strings` detector in 20 of 20 programs.

  The authors advise against relying on regex alone and recommend screening both strings and decompiler output before they enter context. — [arXiv 2605.30677 (HTML)](https://arxiv.org/html/2605.30677)
- A practitioner write-up demonstrates weaponized binaries attacking Cline and GhidraMCP-based RE workflows. — [it4sec Substack](https://it4sec.substack.com/p/attacking-ai-based-reverse-engineering)
- The "lethal trifecta" is private data, untrusted content and external communication together. The only reliable defence is to cut one leg, for example making an MCP server read-only. — [Simon Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/); [Supabase MCP example](https://simonwillison.net/2025/Jul/06/supabase-mcp-lethal-trifecta/)

**Tool annotations**
- `readOnlyHint` defaults to false. `destructiveHint` (default true) applies when not read-only. `idempotentHint` defaults to false and `openWorldHint` to true, so the defaults are pessimistic. — [MCP blog, Tool annotations](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/)
- Clients mainly use annotations to skip confirmation for read-only tools and to warn before destructive ones. — [MCP blog, Tool annotations](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/)
- Annotations do not stop prompt injection and are not enforcement. Untrusted servers' annotations must be treated as untrusted. — [MCP blog, Tool annotations](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/); [MCP spec 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- Annotations can let a client tighten approvals after an untrusted-content tool has run. — [MCP blog, Tool annotations](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/)

**Human-in-the-loop, gating and output sanitization**
- The MCP spec says there SHOULD always be a human in the loop able to deny tool calls, and clients SHOULD confirm sensitive operations. Servers MUST sanitize tool outputs. — [MCP spec 2025-06-18, Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- ChatDBG whitelists debugger commands by default and rejects native commands that call functions, with an explicit `--unsafe` flag. It also presents fixes to the human rather than auto-applying them. — [arXiv 2403.16354](https://arxiv.org/html/2403.16354v5)
- ida-pro-mcp hides debugger tools unless explicitly enabled (`?ext=dbg`). — [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
- Naptime and debug-gym run code in sandboxes (a Python sandbox and Docker respectively). — [Project Zero](https://projectzero.google/2024/06/project-naptime.html); [Microsoft Research](https://www.microsoft.com/en-us/research/blog/debug-gym-an-environment-for-ai-coding-tools-to-learn-how-to-debug-code-like-programmers)

### Inferences
- Keep fencing sample-derived text, and also:
  - Put it in dedicated structured fields (e.g. `untrusted: {strings: [...]}`) so it is never mixed into server-authored instructions or error messages.
  - Escape or neutralize fence-closing sequences inside the data.
  - Cap string length.
  - Neutralize chat-template tokens (`<|im_start|>`, `<|...|>`, role markers) and non-printing bytes in strings and labels. Do this before data reaches the model, because these were the payload mechanics in arXiv 2605.30677.
  - Optionally add a lightweight injection classifier. Regex alone had a recall of 0.6.
  - The same channels exist in x64dbg: strings, labels and comments, memory dumps rendered as ASCII, and module or export names.
- Split read-only ops (registers, memory read, disasm, modules) from state-changing ops (memory write, patch, register set, breakpoint changes, run/step). Set `readOnlyHint: true` on the first group. Give memory writes and patching `destructiveHint: true`. Set `openWorldHint: false` on everything, because the server is local and closed-domain.
  - In an op-grouped design, a single tool cannot carry different annotations per op. That is an argument for separating read and write tool groups.
- Add a server-side "allow writes" or "unsafe" flag that defaults off, in the style of ChatDBG and ida-pro-mcp. That makes the guarantee enforced rather than only hinted.
- binary-mcp's "never launches a sample" stance plus the absence of network tools removes the exfiltration leg. Document this as a security property.

### Gaps
- The Crawford & McClure paper is internally inconsistent: §II-I says no benign-classified injection was found across λ values, while §III-C2 reports benign-classified attacks. Treat its obfuscation numbers with caution.
- That paper tested a small open model (Qwen3-8B). I found no published measurement of injection success against frontier models in an RE setting.

## 6. Structured outputs (structuredContent/outputSchema) vs text; resources vs tools for large data — plus final checklist

### Takeaway
Return structured JSON (`structuredContent` with an `outputSchema`) plus a text mirror, and keep the text compact. Put large or browsable data (memory regions, traces, module lists, string tables) behind paginated tools or `resource_link`s rather than inlining it.

### Cited Findings
- `structuredContent` is a JSON object in the result. For backwards compatibility, servers SHOULD also return serialized JSON in a text block. If `outputSchema` is declared, servers MUST conform to it and clients SHOULD validate. — [MCP spec 2025-06-18, Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- Tools may return `resource_link` items (a URI plus name, mimeType and annotations such as `audience: ["assistant"]` and `priority`), or embedded resources. — [MCP spec 2025-06-18, Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- ida-pro-mcp exposes read-only browsable state as resources (`ida://idb/segments`, `ida://struct/{name}`, and paginated, filterable strings) and keeps actions as tools. — [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
- Anthropic: response format (JSON, XML, Markdown) affects accuracy, so evaluate it. Use concise or detailed modes. — [Anthropic](https://www.anthropic.com/engineering/writing-tools-for-agents)
- Programmatic tool calling benefits from predictable, structured tool outputs that code can filter, e.g. 200KB of raw data reduced to 1KB. — [Anthropic, Advanced tool use](https://www.anthropic.com/engineering/advanced-tool-use)

### Inferences — Recommended checklist for binary-mcp (x64dbg)

Each item traces to evidence above.

1. **Typed op schemas.** Make `op` an enum, give each op a `oneOf` branch with types, `required` and enums, and add 1–3 `input_examples` for tricky ops (address expressions, sizes, conditions). (§1, §2)
2. **Context snapshot.** Add a single `context` / `snapshot` op returning: state (running/paused/terminated, from the live engine), stop reason, RIP as module+offset and symbol, ±N disasm lines, GPRs and flags, top ~8 stack qwords with symbolization, last event or exception, and `state_version`. Attach the same snapshot by default to every step/run/continue result. (ChatDBG, Big Sleep; §3)
3. **Bounded waits.** Replace open-ended waits with `run_until(events, timeout_ms)` and `wait(timeout_ms)`, both returning `timed_out` and the live state. Never report paused unless the engine confirms it. (§4)
4. **Merge duplicates and fix or remove broken ops.** Merge or delete near-duplicate ops. Remove broken ops, or make them return `isError: true` with a reason rather than failing silently. Add a regression test per op. (§1, §2)
5. **Actionable errors.** Use `isError: true` with what went wrong, why, and a valid example. Examples: "address 0x… is not mapped; nearest region …", "target is running; call pause first". (§1, Big Sleep)
6. **Structured output.** Declare `outputSchema` per tool and return `structuredContent` plus a compact text mirror. Numbers should come as hex strings plus symbol+offset, so the model never converts bases (ida-pro-mcp `int_convert` lesson). (§3, §6)
7. **Verbosity and pagination.** Add `response_format: concise|detailed`, plus `limit`/`offset` or cursors with enforced maxima, on memory, disasm, strings, modules, threads and breakpoints. Truncation notices should say how to fetch more. (§1)
8. **Large data as resources.** Return dumps, traces and full string tables as `resource_link` handles or paginated reads, with a short summary inline. (§6, EnIGMA)
9. **Split read and write tools; gate writes.** Separate read-only groups from mutating ones and annotate them (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint: false`). Disable writes and patching by default behind a server flag, and expect client confirmation. (§5)
10. **Untrusted-data hygiene.** Keep sample-derived text in dedicated fields, fenced, escaped and length-capped. Never echo it inside server instructions or error text. Document that there is no network or exfiltration capability. (§5)
11. **Progressive disclosure.** Keep the core always loaded (session, context, exec control, breakpoints, memory read, disasm). Put rare ops behind `describe_op` or extension groups toggled via `list_changed`. Keep the total under about 10K tokens. (§2)
12. **Batching.** Accept lists for reads (multiple addresses or expressions) and return per-item errors. (ida-pro-mcp)
13. **Explicit session/target IDs** in calls and results, to avoid acting on a stale target. (ida-pro-mcp)
13a. **Server-owned breakpoint state.** Keep the breakpoint list server-side and include it, compactly, in the snapshot, so the model never has to remember it. (debug-gym; §3)
13b. **Guidance in descriptions.** Tool descriptions should say when to use the debugger and suggest a typical workflow: set a breakpoint on the hypothesis, run_until, inspect the snapshot. debug-gym found that weaker models used pdb "without a clear strategy" and were sometimes hurt by it. (§3)
14. **Evals.** Build 20–50 realistic tasks (e.g. "find the decryption routine's key at runtime", "identify the API resolving loop"), each with a verifiable answer. Track success, calls, tokens and invalid-argument rate, read the transcripts, and iterate on descriptions. (§1)

### Gaps
- I found no empirical comparison of JSON vs text debugger outputs for agent accuracy. Anthropic says format should be chosen by eval.
- MCP client support for `outputSchema`/`structuredContent` and `resource_link` varies, and I did not survey it.
