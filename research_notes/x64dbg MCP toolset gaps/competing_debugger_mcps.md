# Competing Debugger / RE MCP Servers: Tool Catalogue and Gaps vs binary-mcp

Research date: 2026-11-23. Star counts and last-push dates come from `gh search repos` output on that date. Search-result URLs: https://github.com/search?q=x64dbg+mcp&type=repositories (same query pattern for "windbg mcp", "gdb mcp", "lldb mcp", "ida mcp", "ghidra mcp", "binary ninja mcp", "frida mcp", "cheat engine mcp"). Tool lists come from each project's README (raw.githubusercontent.com/<repo>/HEAD/README.md) or the docs file linked below.

## Which x64dbg MCP servers exist and what do they expose?

### Takeaway
At least ten x64dbg MCP servers exist. The most significant are:
- **duty1g/x64dbg-mcp-server**: about 2.9k stars, a native Zig plugin with roughly 72-84 flat tools.
- **Wasdubya/x64dbgMCP**: the original, with SDK-mirroring tools.
- **rison1337/x64dbgMCP**: a Wasdubya fork with around 250 tools. It is the most feature-rich: launch/bind, GUI automation of the debuggee, API/heap traces, IAT repair, IDA evidence hand-off, leases and tool profiles.
- **Akhil-Chaturvedi/x64dbg-MCP**: 36 grouped tools with about 393 operations, plus resources and prompts. Its architecture is closest to binary-mcp's.
- **DNLINYJ/better-x64dbg-mcp**: 22 mega-tools with SSE event push and pause-reason attribution.
- **x64dbg-automate**: by Darius Houle, with about 46 tools and careful response budgeting.

All but one of these can launch a target, which binary-mcp deliberately does not.

### Cited Findings

**duty1g/x64dbg-mcp-server**: https://github.com/duty1g/x64dbg-mcp-server
- Maturity: about 2,861 stars, last push 2026-11-22 (gh search).
- Built as a native Zig plugin with zero dependencies. It builds both x32 and x64 and serves Streamable HTTP plus SSE inside x64dbg's address space. — [README](https://github.com/duty1g/x64dbg-mcp-server)
- The README is inconsistent about its tool count: it says "84 MCP Tools" in Features and "72 MCP tools" in the Tools section. It also lists "22 Event Callbacks". — [README](https://github.com/duty1g/x64dbg-mcp-server)
- Tools:
  - **Session/meta**: GetDebugState, LoadBinary, ExecuteDebuggerCommand, ListCommandsByCategory, GetEventLog, ClearEventLog, EvalExpression, AttachProcess, Echo, WaitForEvent (long-poll for events), WaitForPause, StopDebug, RestartDebug, SaveDatabase.
  - **Execution**: run, StepInto, StepOver, StepOut, PauseDebug, RunToAddress, TraceInto, TraceOver (N steps recording address and disassembly).
  - **Breakpoints**: SetBreakpoint, SetHardwareBreakpoint, SetConditionalBreakpoint (with a log), Enable/Disable/Toggle/Delete/DeleteAll, ResetHitCount, ListBreakpoints, SetMemoryBreakpoint, Set/DeleteExceptionBreakpoint, SetBreakpointCommand, SetBreakpointFastResume.
  - **State**: GetCurrentAddress, GetAllRegisters, SetRegister, GetCallStack, GetThreads, SwitchThread, Suspend/ResumeThread.
  - **Memory**: ReadMemory, GetMemoryMap, GetDumpableRegions, Allocate/FreeMemory, WriteMemToAddress, RestorePatches, GetPatches, FollowPointer (dereferences a pointer chain N levels), WatchExpressions (evaluates many expressions in one call).
  - **Code**: Disassemble, DisassembleFunction, Assemble, GetFunctions, AnalyzeCode, GetReferences, FindPattern (with ?? wildcards), SearchForStrings, GetStrings.
  - **Annotations**: CommentOrLabelAtAddress, Set/Delete/ListBookmarks.
  - **Modules and symbols**: ListModules, GetImports, GetExports, SearchSymbols, ListSymbols.
  - **PE/unpacking**: AnalyzeModule, DetectOEP, DumpMemory, DumpModule.
  - **Windows internals**: GetSEHChain (x32), GetPEB, GetArguments (reads function arguments from the stack or registers).
  - Source: [README](https://github.com/duty1g/x64dbg-mcp-server)
- Security: the README says a Bearer token is mandatory and auto-generated, but the default bind is 0.0.0.0:9094 (x64) and 9095 (x32). — [README](https://github.com/duty1g/x64dbg-mcp-server)
- A write-up assigns CVE-2026-107824 / GHSA-4478-h5jv-647m to this plugin, which exposed every tool unauthenticated on 0.0.0.0 before v1.1. v1.1 added Bearer auth (2026-08-23/24), and v1.2 changed the default bind to 127.0.0.1. The sources disagree on which versions are affected (the GHSA says <1.0, NVD says <1.1). This README still shows 0.0.0.0 defaults, which conflicts with the v1.2 claim. I could not verify the CVE ID independently. — [ThreatFrontier](https://threatfrontier.com/articles/x64dbg-mcp-server-cve-2026-107824-unauthenticated-debugger)
- An editorial covers this project as making reverse engineering "an API". — [heatdrop](https://heatdrop.ai/editorial/duty1g/x64dbg-mcp-server/2026-08-24)

**Wasdubya/x64dbgMCP**: https://github.com/Wasdubya/x64dbgMCP
- A C++ plugin with a Python FastMCP bridge (src/x64dbg.py). It claims "40+ x64dbg SDK tools" and supports x32 and x64. — [README](https://github.com/Wasdubya/x64dbgMCP)
- Tools, from the `@mcp.tool` functions in [src/x64dbg.py](https://github.com/Wasdubya/x64dbgMCP/blob/main/src/x64dbg.py):
  - **Core**: ExecCommand, IsDebugActive, IsDebugging.
  - **Registers and flags**: RegisterGet/Set, GetRegisterDump, FlagGet/Set.
  - **Memory**: MemoryRead/Write, MemoryIsValidPtr, MemoryGetProtect, MemoryBase, SetPageRights, MemoryRemoteAlloc/Free, GetMemoryMap.
  - **Execution**: DebugRun/Pause/Stop/StepIn/StepOver/StepOut, StepInWithDisasm.
  - **Breakpoints**: DebugSetBreakpoint/DeleteBreakpoint, Set/DeleteHardwareBreakpoint, GetBreakpointList.
  - **Assembly and stack**: AssemblerAssemble, AssemblerAssembleMem, StackPop/Push/Peek.
  - **Search and expressions**: PatternFindMem, MiscParseExpression, MiscRemoteGetProcAddress.
  - **Disassembly and xrefs**: DisasmGetInstructionRange, GetBranchDestination, XrefGet, XrefCount, StringGetAt.
  - **Modules, symbols, threads**: GetModuleList, QuerySymbols, GetThreadList, GetTebAddress, GetCallStack.
  - **Annotations**: LabelSet/Get/List, CommentSet/Get.
  - **Patches**: GetPatchList, GetPatchAt.
  - **System**: EnumTcpConnections, EnumHandles.
- Usage tips from the README:
  - Give the model the full exe path so it can restart a hung or crashed target with "init <path>".
  - GetModuleBase is "the best place to start", because x64dbg rejects out-of-range addresses.
  - For token cost, put the Headroom proxy in front. — [README](https://github.com/Wasdubya/x64dbgMCP)

**rison1337/x64dbgMCP**: https://github.com/rison1337/x64dbgMCP
- Maturity: 3 stars, last push 2026-09-16. It is GPL-3.0, based on Wasdubya's project, and has CI. — [README](https://github.com/rison1337/x64dbgMCP)
- Positioning: "guarded control" that makes live debugging a "replayable reverse-engineering workflow". The workflow is to bind the exact process, observe runtime facts, recover artifacts, validate them independently, and hand the evidence to IDA. — [README](https://github.com/rison1337/x64dbgMCP)
- Tool profiles: compact, inspect, standard, automation and full. Responses can also take `detail="full"`. — [TOOL_REFERENCE](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md)
- Tools, about 250 in total, from [docs/TOOL_REFERENCE.md](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md):
  - **Launch and bind**:
    - InitDebuggee (auto-detects x86/x64 and starts the matching debugger), LaunchFileUnderDebugger, LaunchAndOpenDebuggee, AttachToProcess.
    - Session binding: BindSessionTarget, ListDebugSessions, SelectDebugSession.
    - Child processes: FollowChildProcess, WaitForChildProcess, ListChildProcesses.
    - Launch streams: WriteLaunchStdin, ReadLaunchStream.
    - Startup and stops: AdvancePastStartupPause, RunToUserCode, RunUntilModuleLoad, WaitForModuleLoad, WaitForExit, WaitForUserCode.
  - **Waiting and capture**: WaitForBreakpoint, WaitForBreakpointCapture(Structured), WaitForBreakpointDetailed, DebugRunBlocking, SetBreakpointWithCapture, BatchBreakpointsCapture, GetBreakpointCaptureHistory, SetMemoryWatchpointWithCapture, CaptureExecuteAfterWrite, CaptureSymbolicBreakpoint, CaptureStopContextStructured, DumpOnEvent.
  - **Leases and safety**: AcquireBreakpointLease, AcquireMutationLease, Renew/Release*, ListBreakpointLeases, EnsureReady, EnsureDebugger, BridgeHello, RunBridgeSelfCheck, BenchmarkBridge, ExportCapabilityMap.
  - **Tracing**: StartNativeTrace, RunNativeTrace, GetNativeTrace, WaitNativeTrace, StartApiTrace, RunApiTrace, TraceApiCalls, GetApiTraceLog, StartHeapTrace, RunHeapTrace, GetHeapState, TraceInstructionTape, TraceInto/OverConditional, StartRunTraceToFile, RunTraceRecord, GetBasicBlockCoverage, Export/Merge/DiffCoverageArtifacts, SummarizeTraceHistory.
  - **Exceptions**: Get/Set/ClearExceptionPolicy, SetExceptionFilter, GetExceptionHistory, ContinueException.
  - **Time travel**: Checkpoint, Rewind, ReplayToAddress, SaveState, RestoreState, StepWithSnapshot, CaptureMemorySnapshot, CompareMemorySnapshots, WatchMemoryChanges.
  - **Unpacking**: FindOEP, RunUntilOEP, FindIATCandidates, InspectRuntimeIAT, RecoverRuntimeImports, ReconstructImports, ValidateIAT, FixDumpImports.
  - **Dumping**: DumpPeFromMemory, DumpModuleRaw, ScanMemoryForPEImages, ValidateDump, VerifyPEDump, WriteMiniDump, VerifyMiniDump, ExportPatchedFile.
  - **Recovery and analysis**: RecoverComparisonSecret, AnalyzeAntiDebugSurface, AnalyzeExecutablePacking, InspectProcessPayload, LoadLibraryInDebuggee, LoadSymbolsForModule.
  - **ScyllaHide**: EnsureScyllaHideForDebuggee, SetScyllaHideProfile.
  - **Debuggee GUI and console automation**: GetDebuggeeWindows, CaptureDebuggeeWindow, CompareWindowCaptures, ClickControl, ClickDebuggeeWindow, SetControlText, ReadControlText, SendTextToDebuggeeWindow, SendForegroundKeys, SubmitDebuggeeGuiForm, InvokeUiAutomationElement, WaitForDebuggeeWindow, WaitForGuiChange, ReadDebuggeeConsole, SendTextToDebuggeeConsole, AutoRespondToDebuggeeConsole/Gui.
  - **Managed .NET**: GetManagedRuntimeState, InspectManagedAssembly, ResolveManagedJitMethod, ResolveManagedToken, SetManagedMethodBreakpoint, ExportManagedEvidence.
  - **IDA hand-off**: ExportRuntimeEvidence, ImportStaticAnnotations, SyncBreakpoints, ResolveModuleRva, Import/Export/ValidateAnalysisEvidence.
  - **Misc**: EvalBatch, ReadMemoryBatch, DecodeStructuredValue, SetThreadPriority, Suspend/ResumeAllThreads, RemoveProcessDebug, GetRecentLog.
- IDA hand-off design: runtime facts are keyed by **file SHA-256 + module RVA**, not runtime VA. A coordinator validates that the IDA database has the same SHA-256 and architecture before it applies set_name, set_comments, define_func and coverage comments. — [README](https://github.com/rison1337/x64dbgMCP)
- ScyllaHide is opt-in: the default is `use_scyllahide="off"`. The project disables NtContinueHook and KillAntiAttach to avoid a reproduced crash, and it reports these overrides. — [README](https://github.com/rison1337/x64dbgMCP)

**Akhil-Chaturvedi/x64dbg-MCP**: https://github.com/Akhil-Chaturvedi/x64dbg-MCP
- Maturity: 2 stars, last push 2026-07-30. Architecture: a C++23 plugin serving HTTP on 127.0.0.1:27042, with a TypeScript stdio MCP server. It has 36 grouped tools (each takes an `action` parameter), more than 393 operations, 15 resources and 10 prompts. — [README](https://github.com/Akhil-Chaturvedi/x64dbg-MCP)
- Tool groups:
  - **Debugging and commands**: x64dbg_debug (run/pause/step/init/attach/detach/restart/run-to/state), x64dbg_command (commands, expressions, scripts, database).
  - **Core state**: x64dbg_registers (including AVX-512), x64dbg_memory, x64dbg_disassembly, x64dbg_breakpoints, x64dbg_symbols, x64dbg_stack (including SEH chain), x64dbg_threads (create and kill), x64dbg_modules (section, party, imports and exports).
  - **Search and analysis**: x64dbg_search, x64dbg_find_pattern (indirect calls, stack access, API calls, jump tables), x64dbg_analysis (basic blocks, constants, error codes, source locations), x64dbg_database (constants, error codes, structs), x64dbg_address_convert (VA to file offset), x64dbg_control_flow (CFG, loops), x64dbg_function, x64dbg_analyze_module.
  - **Events and tracing**: x64dbg_watchdog, x64dbg_events (subscribe/unsubscribe), x64dbg_tracing.
  - **Dumping and patching**: x64dbg_dumping (PE header, sections, relocations), x64dbg_advanced_dump (PE rebuild), x64dbg_patches (apply, list, revert, export), x64dbg_auto_patch (NOP, JMP, invert conditional, RET, set byte).
  - **Process and system**: x64dbg_antidebug (PEB/TEB, hide, DEP), x64dbg_exceptions (list exception codes), x64dbg_process (command line, elevation), x64dbg_handles (handles, TCP connections, windows, heaps), x64dbg_system (ping, method listing, permissions).
  - **State, scripting, annotation**: x64dbg_context and x64dbg_snapshot_diff (named state snapshots and diffs), x64dbg_script (batch commands, multi-step script engine, conditional workflows with branching), x64dbg_assembler, x64dbg_bookmark, x64dbg_batch_annotate.
  - Source: [README](https://github.com/Akhil-Chaturvedi/x64dbg-MCP)
- Resources: x64dbg://state, registers, modules, threads, memory_map, breakpoints, stack, stack_trace, plus templates such as memory/{address}/{size}, disassembly/{address}/{count}, module/{name}, symbol/{name}, function/{address}, export/{module} and import/{module}. — [README](https://github.com/Akhil-Chaturvedi/x64dbg-MCP)
- Prompts: debug_session, analyze_crash, unpack_binary, trace_function, find_vulnerability, reverse_algorithm, api_monitor, patch_code, hunt_strings, compare_state. — [README](https://github.com/Akhil-Chaturvedi/x64dbg-MCP)
- Resilience: health-polls /api/health every 15 s and waits up to 120 s for the plugin. It retries connection errors with backoff but does not retry 4xx/5xx errors. The timeout defaults to 0 (unbounded) for long traces. — [README](https://github.com/Akhil-Chaturvedi/x64dbg-MCP)

**DNLINYJ/better-x64dbg-mcp**: https://github.com/DNLINYJ/better-x64dbg-mcp
- Maturity: 9 stars, last push 2026-07-30. It rebuilds bromoket/x64dbg_mcp (TypeScript plus C++, 148 REST routes) as a single C++ DLL that serves MCP Streamable HTTP at one /mcp endpoint. It has 22 mega-tools and SSE push for 9 callbacks: breakpoint hit, pause, exception, step complete, debug stop, process create/exit, and DLL load/unload. — [README](https://github.com/DNLINYJ/better-x64dbg-mcp)
- **Pause-reason attribution**: `state` returns `reason` as breakpoint, step, exception or unknown, with a detail object. The breakpoint detail has type, address, name, module, hit_count and log; the exception detail has code, name, address and first_chance. Attribution is conservative: a pause counts as `breakpoint` only if CB_BREAKPOINT fired, the breakpoint has no commandText, and CIP is unchanged. — [README](https://github.com/DNLINYJ/better-x64dbg-mcp)
- **Breakpoint log files**: logging breakpoints write to a file. `x64dbg_log read` pages through it with offset, file_id and continuity_token, so the debuggee does not have to stop. This works around the SDK having no log callback. — [README](https://github.com/DNLINYJ/better-x64dbg-mcp)

**x64dbg-automate MCP (Darius Houle)**: https://dariushoule.github.io/x64dbg-automate-pyclient/mcp-server/
- Tools (about 46):
  - **Session**: list_sessions, start_session, connect_to_session, connect_remote, disconnect, terminate_session.
  - **Execution**: go, pause, step_into, step_over, skip_instruction, run_to_return, get_debugger_status.
  - **Memory**: read_memory, read_memory_many, write_memory, allocate_memory, free_memory, get_memory_map.
  - **Registers**: get_register, set_register, get_all_registers.
  - **Expressions**: eval_expression, execute_command.
  - **Breakpoints**: set_breakpoint, clear_breakpoint, toggle_breakpoint, list_breakpoints.
  - **Assembly**: disassemble, assemble.
  - **Annotations**: set_label, get_label, set_comment, get_comment, get_symbol.
  - **Threads**: create_thread, terminate_thread, pause_resume_thread, switch_thread.
  - **Events**: get_latest_event, wait_for_event.
  - **Settings**: get_setting, set_setting.
  - **GUI**: log_message, get_log, refresh_gui.
  - Source: [docs](https://dariushoule.github.io/x64dbg-automate-pyclient/mcp-server/)
- Response budgeting:
  - read_memory formats: dump (about 5x raw size), hex (about 2x) and base64 (about 1.33x).
  - Per-call caps of roughly 9/24/36 KB for those formats; disassemble is capped at 100 instructions.
  - Oversized requests are refused up front, with the limit named, rather than truncated.
  - `size=0` reads the largest run that fits.
  - read_memory_many shares one budget and reports skipped reads.
  - The memory map filters by type, protection, size and state, and pages with offset/limit.
  - Source: [docs](https://dariushoule.github.io/x64dbg-automate-pyclient/mcp-server/)
- Gotchas it handles:
  - Memory tools check for a live debuggee, because the cached memory map survives detach and would otherwise look valid.
  - `$result` is not cleared between commands, so it uses a sentinel pattern to detect stale values. — [docs](https://dariushoule.github.io/x64dbg-automate-pyclient/mcp-server/)

**AgentSmithers/x64DbgMCPServer**: https://github.com/AgentSmithers/x64DbgMCPServer
- A C# .NET Framework plugin with a self-hosted HttpListener SSE server on port 50300. It needs an STDIO-to-SSE proxy for Claude Desktop. — [README](https://github.com/AgentSmithers/x64DbgMCPServer)
- Notable tools: ExecuteDebuggerCommand, ExecuteDebuggerCommandWithVar, ExecuteDebuggerCommandWithOutput, ReadDismAtAddress, ReadMemAtAddress, WriteMemToAddress, CommentOrLabelAtAddress, GetAllRegisters, GetLabel, GetAllActiveThreads, GetAllModulesFromMemMap, GetCallStack.
  - ExecuteDebuggerCommandWithVar runs a command, then polls a debugger variable such as `$pid` (pollMs, pollTimeoutMs).
  - ExecuteDebuggerCommandWithOutput captures the log text a command produces. — [README](https://github.com/AgentSmithers/x64DbgMCPServer)
- Known issue: ExecuteDebuggerCommand returns true whenever the command was submitted, not whether it succeeded. — [README](https://github.com/AgentSmithers/x64DbgMCPServer)

**Smaller x64dbg MCPs** (low stars; tool lists not reviewed):
- ouonet/x64dbg-mcp: 9 stars, last push 2026-05-30.
- chensiling/x64dbg-mcp: 6 stars, last push 2026-07-22.
- Evelynkaz/x64dbg-mcp: 4 stars, last push 2026-09-01.
- pkuislm/x64Dbg-mcp: 2 stars, last push 2026-08-05.
- abbasdivian/x32DbgMCPServer: 2 stars, last push 2025-10-22.
- Source: [GitHub search](https://github.com/search?q=x64dbg+mcp&type=repositories)

### Inferences
- The x64dbg ecosystem has split into two designs. One is flat SDK mirrors (duty1g, Wasdubya, x64dbg-automate). The other is workflow and evidence servers with grouped or composite tools (rison1337, Akhil, binary-mcp).
- rison1337 is the most direct functional competitor to binary-mcp. Akhil is the closest in architecture (C++ plugin, HTTP bridge, action-grouped tools).
- duty1g has by far the largest audience. Its CVE history shows that auth and localhost binding are expected baseline features.

### Gaps
- I did not verify which x64dbg MCPs are maintained versus abandoned beyond the last-push date.
- The GitHub repo API was blocked in this session, so star counts for Wasdubya, AgentSmithers, mrexodia and svnscha could not be retrieved.

## What do WinDbg, GDB/LLDB, IDA, Ghidra, Binary Ninja, radare2, Frida and Cheat Engine MCP servers expose, especially for dynamic analysis?

### Takeaway
The WinDbg MCPs are the most sophisticated in design:
- **glslang/windbg-mcp** has 89 tools with typed structuredContent, async continue/wait, transactional batches with rollback, TTD, and heap and pool walks.
- **Microsoft's official WinDbg MCP** (Oct 2026) adds secure mode and prompt-injection classification of debugger output.
- **gengstah/windbg-mcp** has breakpoints that auto-capture state into a buffer.

In the static tools (IDA, Ghidra, Binary Ninja), debugger features are small add-ons. Their design patterns (batching, int_convert, pagination, lazy tool loading) are what carry over. Frida's kahlo has the best-documented async job, event and artifact model.

### Cited Findings

**WinDbg**
- **Microsoft WinDbg MCP** (official, WinDbg 1.2610.1001.0, announced 2026-10-06):
  - Architecture: DbgX.Mcp.Proxy.exe speaks stdio to the client and connects over a per-process named pipe to one WinDbg session, one client at a time.
  - Connection tools: list_sessions, connect_session, disconnect_session.
  - Prompts: investigate_symbol_loading_issues, write_extension, create_graph, configure_ttd.
  - **Secure mode** is on by default. It blocks `.shell`, process launches and unsafe file operations, and it cannot be turned off until restart. The docs warn that without secure mode, indirect actions still run, for example a breakpoint command.
  - **Cross-prompt-injection (XPIA) protection** uses MCP sampling to have the client's model classify protected debugger output, and blocks output flagged as unsafe.
  - Officially supported clients are VS Code Copilot and Copilot CLI.
  - Sources: [MS Learn overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/windbg-mcp-overview); [announcement](https://devblogs.microsoft.com/performance-diagnostics/introducing-windbg-mcp-debug-with-natural-language-grounded-in-evidence/)
  - The announcement does not list per-tool names. It says AI-initiated actions are logged and visible in WinDbg. — [announcement](https://devblogs.microsoft.com/performance-diagnostics/introducing-windbg-mcp-debug-with-natural-language-grounded-in-evidence/)
- **svnscha/mcp-windbg**: https://github.com/svnscha/mcp-windbg
  - Python wrapper around cdb/kd, distributed on PyPI and as a signed exe.
  - Tools: list_dumps, open_cdb_dump (with automatic triage: !analyze -v, stacks, modules, threads), open_cdb_remote, open_kd_session, open_kd_dump, run_cdb_command, run_kd_command, close_cdb_session, close_kd_session, send_ctrl_break, wait_for_break.
  - Session IDs; per-call timeouts with CTRL+BREAK resync when a command outruns its timeout.
  - `--filter-script` redacts PII and secrets from both arguments and output.
  - Ships Claude Code skills and a crash-analyst agent; stdio or HTTP transport.
  - Source: [README](https://github.com/svnscha/mcp-windbg)
- **glslang/windbg-mcp**: https://github.com/glslang/windbg-mcp
  - Maturity: 22 stars, v0.24.0, last push 2026-11-23. Written in Rust on DbgEng.
  - Process model: a supervisor plus one engine worker process per session, up to 4 concurrent, with a 32-bit worker for WoW64.
  - 89 tools in 9 `--tools` groups:
    - **Session**: open_dump, open_trace, attach_kernel(_local), attach_process, launch, interrupt, end_session, session_status, server_log.
    - **Inspect**: current_location (IP and PE coordinate), registers, read_memory, backtrace (typed frames with module+RVA), modules (refresh), threads, disassemble (records with encoding and RVA), dx, set_symbol_path, execute.
    - **Crash**: crash_triage, exception_triage (decodes the exception record, C++ thrown object and HRESULT), decode_error_reporting (HRESULT, NTSTATUS or Win32 code to fields and message).
    - **Exec**: go, step_over, step_into, set_breakpoint, breakpoints, clear_breakpoints, run_to_address.
    - **Async**: continue_async (returns a handle), wait_for_stop (running out the wait is a poll, not a failure), break_in.
    - **Batch**: debug_batch, an ordered sequence with assertions and a rollback that runs on every path, including timeout and disconnect.
    - **TTD**: step_back, step_over_back, reverse_go, goto_position, ttd_calls, ttd_memory, ttd_events, index_trace, record_trace.
    - **IOCTL**: decode_ioctl, driver_object, device_object, irp_stack, ioctl_trace, reachable_from_dispatch, driver_hazards, ioctl_map, xrefs_to, device_security, driver_surface.
    - **Allocator**: pool_find_tag, pool_chunk, pool_census, pool_diagnostics, pool_trace, pool_trace_read, heap_list, heap_allocations, heap_chunk, heap_census, heap_diagnostics, walk_memory (lists, arrays and chains where an unreadable node becomes a row instead of ending the walk).
    - **Secure Kernel (opt-in)**: VTL1 capture and live-control tools.
  - Most tools return MCP structuredContent with stable error categories (invalid_argument, debugger, timeout, stale_session).
  - JSONL session transcripts with redaction; HTTP `--listen` with one bearer token per client.
  - A local-model eval grid (model × tool surface × context window) found two defects in the server.
  - Sources: [README](https://github.com/glslang/windbg-mcp); [tool-surface doc](https://github.com/glslang/windbg-mcp/blob/main/docs/tool-surface.md)
- **gengstah/windbg-mcp**: https://github.com/gengstah/windbg-mcp
  - 97 stars, last push 2026-05-03. Python on pybag/DbgEng, 55 tools.
  - **Session**: status, list_processes, create, attach, kernel_attach, load_dump, connect, detach, terminate.
  - **Execution**: go(timeout) returns new_captures; step_into/over/out return rip, instruction and symbol; goto; trace(count).
  - **Breakpoints**: bp and hw_bp take `capture`, `action` ("go" or "break"), `oneshot` and `passcount`; list/remove/enable/disable.
  - **State captures**: with `capture: true` (the default), every hit saves registers, rip, symbol, instruction, stack and context_memory into a buffer, read with get_captures and cleared with clear_captures. capture_state takes an on-demand snapshot.
  - **Memory**: read_mem (hex, formatted and ascii), write_mem, read_ptr, poi, read_str, dump_mem, mem_info, mem_list.
  - **Registers**: get_regs, get_reg, set_reg, get_pc, get_sp.
  - **Symbols**: resolve, find_symbols, addr_to_symbol, disasm, whereami.
  - **Modules**: list_modules, module_info, get_exports, get_imports.
  - **Threads and stack**: list_threads, get_thread, set_thread, get_stack, get_teb, get_peb.
  - **Utility**: get_handles, get_bitness, raw.
  - Source: [README](https://github.com/gengstah/windbg-mcp)
- **memoryforensics1/windbg-mcp**: 47 stars, last push 2026-10-10, C#. Its 29 tools include:
  - **VM control**: vm_start, vm_stop, vm_pause, vm_resume, vm_snapshot_restore, vm_snapshot_list, vm_screenshot, vm_set_target.
  - **Kernel debugging**: kd_connect, kd_disconnect, kd_break, kd_continue, kd_step, kd_execute, kd_wait_for_event ("Always returns").
  - **Guest OS**: guest_run_command, guest_transfer_to_vm/from_vm, guest_list_processes, guest_kill_process.
  - **Meta**: get_system_state ("Always allowed").
  - Source: [README](https://github.com/memoryforensics1/windbg-mcp)
- **kanren3/windbg-mcp-rs**: 57 stars. An in-process WinDbg extension on Streamable HTTP with a compact toolset: catalog search over the **official WinDbg command docs** extracted from debugger.chm, execution-state query, command execution and interrupt. Resources hold the command documentation. — [README](https://github.com/kanren3/windbg-mcp-rs)

**GDB / LLDB**
- **BeaCox/gdb-mcp** (14 stars, last push 2026-11-06): multi-session GDB/MI.
  - **Composite "_and_context" tools**: gdb_run_and_context, continue_and_context, step_and_context, next_and_context. Each returns the frame, backtrace, locals and a summary.
  - **Reverse debugging**: rr record/replay, reverse_continue/step.
  - **pwndbg-style tools**: gdb_pwn_context, binary_summary, vmmap_structured, address_info, rva_info, telescope, nearpc, got, piebase, break_rva, checksec, elf_info.
  - **gdbserver**: connect, launch and status.
  - **Introspection**: capabilities, server_health, command_reference, session_diagnostics.
  - Lazy backend start. "Safety by default": dangerous operations require explicit unsafe mode.
  - Source: [README](https://github.com/BeaCox/gdb-mcp)
- **stass/lldb-mcp** (114 stars, last push 2025-03-26):
  - Sessions: lldb_start, terminate, list_sessions.
  - Loading: load, attach, load_core.
  - Execution: run, continue, step, next, finish, kill.
  - Breakpoints: set_breakpoint, breakpoint_list, breakpoint_delete, watchpoint.
  - Plus inspection tools.
  - Source: [README](https://github.com/stass/lldb-mcp)
- **smadi0x86/MDB-MCP** (74 stars): drives both GDB and LLDB through generic commands. Commands that resume the program wait for it to stop, and the assistant can interrupt or keep waiting. Its security note recommends keeping tool approval on for `debugger_command` because debuggers can run shell commands. — [README](https://github.com/smadi0x86/MDB-MCP)
- **0xeb/lldb-agent** (20 stars, last push 2026-07-17): a single `dbg_exec` tool over MCP or HTTP, bound to 127.0.0.1 by default. — [README](https://github.com/0xeb/lldb-agent)
- **ant4g0nist/lisa.py**: 756 stars, last push 2025-03-29. An LLDB MCP integration with extra commands. — [README](https://github.com/ant4g0nist/lisa.py)

**IDA Pro**
- **mrexodia/ida-pro-mcp**: https://github.com/mrexodia/ida-pro-mcp
  - **Debugger extension**, hidden by default and enabled with `?ext=dbg`:
    - Control: dbg_start, dbg_exit, dbg_continue, dbg_run_to, dbg_step_into, dbg_step_over.
    - Breakpoints: dbg_bps, dbg_add_bp, dbg_delete_bp, dbg_toggle_bp.
    - Registers: dbg_regs, dbg_regs_all, dbg_regs_remote(tids), dbg_gpregs, dbg_regs_named.
    - Stack and memory: dbg_stacktrace, dbg_read(regions), dbg_write(regions).
  - **Static tools**:
    - Lookup and listing: lookup_funcs, int_convert, list_funcs, list_globals, imports.
    - Code: decompile, disasm, xrefs_to, xrefs_to_field, callees, basic_blocks, callgraph, analyze_funcs (decompilation, asm, xrefs, strings, constants and blocks in one call).
    - Search: find_regex, find_bytes, find_insns, find.
    - Types: set_type, infer_types, declare_type, export_funcs.
    - Modification: rename (batch), patch, patch_asm, put_int, set_comments, define_func, define_code, undefine.
    - Reads: get_bytes, get_int, get_string, get_global_value.
    - Stack frames: stack_frame, declare_stack.
    - Scripting: py_eval.
  - Resources: ida://idb/metadata, segments, entrypoints, cursor, types, structs, xrefs.
  - Headless idalib session model: idb_open/list/close/save with --max-workers.
  - Design: batch-first (lists accepted, per-item `{error}`); cursor pagination with a default of 1000 and an enforced maximum of 10000; MD5-invalidated string cache.
  - Source: [README](https://github.com/mrexodia/ida-pro-mcp)
  - Prompting guidance: "NEVER convert number bases yourself. Use the int_convert MCP tool". It also warns that LLMs perform poorly on obfuscated code and recommends deobfuscating first. — [README](https://github.com/mrexodia/ida-pro-mcp)
- **HexRaysSA/ida-mcp**: the official Hex-Rays IDA MCP. 1,672 stars, last push 2026-10-28. Headless idat workers, an `ida-nexus` library for custom tools, and installers for Claude Code, Codex and Copilot CLI. The README does not show its tool list. — [README](https://github.com/HexRaysSA/ida-mcp)
- **blacktop/ida-mcp-rs**: a headless IDA MCP. 912 stars, last push 2026-11-01. Tools not reviewed. — [GitHub search](https://github.com/search?q=ida+mcp&type=repositories)

**Ghidra**
- **LaurieWired/GhidraMCP**: about 12,015 stars, last push 2026-10-10. It decompiles, renames methods and data, and lists methods, classes, imports and exports; it also has a headless mode. — [README](https://github.com/LaurieWired/GhidraMCP)
- **bethington/ghidra-mcp**: https://github.com/bethington/ghidra-mcp
  - About 6,331 stars, last push 2026-11-20, 219 tools.
  - **P-code emulation**: runs a function in isolation, for example to brute-force API hashes.
  - **Live debugger**: 16 /debugger/* endpoints over Ghidra TraceRmi (dbgeng, gdb or lldb): launch, interrupt/resume, step, breakpoints, registers, memory, stack, and ASLR-aware static↔dynamic address translation. It can also proxy 22 `debugger_*` tools to an external debugger server.
  - **Lazy tool loading**: search_tools, list_tool_groups, load_tool_group/unload_tool_group, check_tools.
  - **Convention enforcement**: auto-fix, warn or reject on names and types.
  - **Cross-binary documentation transfer** via SHA-256 function hashing.
  - Atomic transactions; batch ops claimed to cut API calls by 93%.
  - Source: [README](https://github.com/bethington/ghidra-mcp)
- **cyberkaida/ReVa** (reverse-engineering-assistant): a Ghidra MCP with assistant and headless modes, and Claude Code marketplace skills (Binary Triage, Deep Analysis, Cryptography Analysis, CTF guides). — [README](https://github.com/cyberkaida/reverse-engineering-assistant)
- **Other Ghidra MCPs**: clearbluejar/pyghidra-mcp (469 stars) and mrphrazer/ghidra-headless-mcp (200 stars). — [GitHub search](https://github.com/search?q=ghidra+mcp&type=repositories)

**Binary Ninja**
- **fosdickio/binary_ninja_mcp** (462 stars, last push 2026-11-13): decompile_function, get_il (hlil/mlil/llil, with SSA), define_types, declare_c_type, comments, format_value, convert_number and more. It supports multiple open binaries. Its sample prompt also says "NEVER convert number bases yourself". — [README](https://github.com/fosdickio/binary_ninja_mcp)
- **mrphrazer/binary-ninja-headless-mcp**: 264 stars, not reviewed. — [GitHub search](https://github.com/search?q=binary+ninja+mcp&type=repositories)

**radare2**
- **radareorg/radare2-mcp (r2mcp)**: https://github.com/radareorg/radare2-mcp
  - Safety controls: read-only mode (`-R`), sandbox lock and restricted tools.
  - Fine-grained sandbox grains: `socket`, `network`, `exec` (Frida needs both exec and network).
  - `r2mcp yolo on|off` toggles approvals and the "dangerous run tools".
  - HTTP mode needs Bearer auth; `R2MCP_AUTH_TOKEN=random` generates a token.
  - Has an `sql` tool through r2xsql, which is excluded in read-only mode.
  - Source: [README](https://github.com/radareorg/radare2-mcp)

**Frida**
- **FuzzySecurity/kahlo-mcp**: https://github.com/FuzzySecurity/kahlo-mcp
  - 141 stars, last push 2026-02-08, Android.
  - Tools:
    - Introspection: kahlo_mcp_about, which returns the operational contract.
    - Devices and processes: devices_list, devices_get, devices_health, processes_list, adb_command.
    - Targets: targets_ensure (attach or spawn, with gating none/spawn/child and early bootstrap hooks), targets_status, targets_detach.
    - Jobs: jobs_start (oneshot, interactive or daemon, with TTL), jobs_status (heartbeat and metrics), jobs_list, jobs_cancel.
    - Telemetry: events_fetch (cursor-paged, with filters), snapshots_get.
    - Artifacts: artifacts_list, artifacts_get (inline payload when small, a storage reference when large).
  - Source: [README](https://github.com/FuzzySecurity/kahlo-mcp)
  - Design lessons from the author's post:
    - One isolated script per job, so cancelling a job cleans up completely.
    - Per-entity keyed locks instead of a global lock.
    - **Atomic spawn, attach, inject and resume**, killing the process on any failure.
    - **Structured errors** with a stable code, a retryable flag and a suggested next tool.
    - Events kept in a bounded ring buffer, with a `dropped` count reported on overflow.
    - Artifacts stored on disk with SHA-256 and atomic rename, and never dropped.
    - Dense tool descriptions (about 300 words each).
    - A self-description tool to recover from "context rot".
    - Raw frida CLI use by agents failed: blocking jobs, accumulated hooks, and skipped setup steps.
    - Source: [KnifeCoat post](https://knifecoat.com/Posts/Scalable+research+tooling+for+agent+systems)
- **Other Frida MCPs**: dnakov/frida-mcp (470 stars, last push 2025-05-12), 1shin-7/ya-frida-mcp and yfe404/frida-mcp (Frida 17). — [GitHub search](https://github.com/search?q=frida+mcp&type=repositories)

**Cheat Engine**
- **CheatEngineNet/CheatEngine.Mcp** (104 stars, last push 2026-11-09):
  - Value scans and AOB searches; UTF-8 and UTF-16LE string discovery.
  - Typed reads and writes, batches, **sampling values over time**, and compare/copy/hash/snapshot of bounded ranges.
  - **Pointer chains with per-hop evidence**, plus pointer scan and rescan.
  - Structure layouts (define, compare, import, export); freezes; Mono and .NET inspection.
  - **Versioned investigation notes** with observations, confidence and module-relative bindings.
  - Lua; a multi-instance gateway; a call timeout of 5-3600 s.
  - Source: [README](https://github.com/CheatEngineNet/CheatEngine.Mcp)

### Inferences
- Only WinDbg (glslang, Microsoft) and Frida (kahlo) treat agent ergonomics as a first-class design problem: typed results, async handles, transactional batches and error taxonomies. These are the best sources of design ideas, more than of individual operations.
- Debugger tools in the IDA, Ghidra and Binary Ninja MCPs are thin; binary-mcp already exceeds them. Their batching and pagination conventions are worth matching, so that a model using both an IDA MCP and binary-mcp sees consistent semantics.

### Gaps
- The HexRaysSA/ida-mcp tool list, the per-tool names of Microsoft's WinDbg MCP debugger tools, and the r2mcp tool list were not in their READMEs and were not retrieved.
- pwndbg and GEF do not appear to ship first-party MCP servers. A GitHub search for "gdb mcp" found none from those orgs, though BeaCox/gdb-mcp reimplements pwndbg-style views. Not confirmed.

## Which features recur across projects (consensus must-haves) and which are unique?

### Takeaway
Consensus must-haves:
- Attach or launch, run, pause, step and run-to.
- Software, hardware and memory breakpoints.
- Registers, memory read/write, the memory map, the stack and threads.
- Modules with imports and exports, and disassembly.
- A raw command escape hatch, plus expression evaluation.
- Some form of wait-for-stop.

Increasingly standard:
- Session IDs, structured JSON output, localhost binding with bearer auth, and pagination or response caps.

Unique, high-value ideas:
- Breakpoints that auto-capture state.
- Async continue handles.
- Transactional batches with rollback.
- Pause-reason attribution.
- Evidence keyed by SHA-256+RVA.
- XPIA output classification.
- Debuggee GUI automation.
- Leases.

### Cited Findings
- **Wait for stop is universal, with varied mechanisms**:
  - WaitForPause and WaitForEvent long-poll ([duty1g](https://github.com/duty1g/x64dbg-mcp-server)).
  - wait_for_break ([svnscha](https://github.com/svnscha/mcp-windbg)).
  - continue_async plus wait_for_stop, where running out the wait is a poll ([glslang](https://github.com/glslang/windbg-mcp)).
  - wait_for_event ([x64dbg-automate](https://dariushoule.github.io/x64dbg-automate-pyclient/mcp-server/)).
  - kd_wait_for_event, which "always returns" ([memoryforensics1](https://github.com/memoryforensics1/windbg-mcp)).
  - SSE push of events ([DNLINYJ](https://github.com/DNLINYJ/better-x64dbg-mcp)).
- **A raw command escape hatch is universal**: ExecuteDebuggerCommand ([duty1g](https://github.com/duty1g/x64dbg-mcp-server)), ExecCommand ([Wasdubya](https://github.com/Wasdubya/x64dbgMCP)), execute ([glslang](https://github.com/glslang/windbg-mcp)), raw ([gengstah](https://github.com/gengstah/windbg-mcp)), dbg_exec ([0xeb](https://github.com/0xeb/lldb-agent)), py_eval ([ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)).
- **Launching the target is near-universal**: LoadBinary ([duty1g](https://github.com/duty1g/x64dbg-mcp-server)), InitDebuggee ([rison1337](https://github.com/rison1337/x64dbgMCP)), start_session ([x64dbg-automate](https://dariushoule.github.io/x64dbg-automate-pyclient/mcp-server/)), create ([gengstah](https://github.com/gengstah/windbg-mcp)), launch ([glslang](https://github.com/glslang/windbg-mcp)), dbg_start ([ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)). In the other direction, Microsoft's secure mode blocks launching processes ([MS Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/windbg-mcp-overview)), which supports binary-mcp's choice not to launch.
- **Auth and localhost binding are expected**: bearer tokens in duty1g (after the CVE), r2mcp HTTP, glslang `--listen` and Akhil (optional), with 127.0.0.1 defaults in Akhil, 0xeb and DNLINYJ. — [duty1g](https://github.com/duty1g/x64dbg-mcp-server); [r2mcp](https://github.com/radareorg/radare2-mcp); [glslang](https://github.com/glslang/windbg-mcp); [Akhil](https://github.com/Akhil-Chaturvedi/x64dbg-MCP); [ThreatFrontier](https://threatfrontier.com/articles/x64dbg-mcp-server-cve-2026-107824-unauthenticated-debugger)
- **Grouped tools and surface reduction are recurring**:
  - Action-grouped tools in [Akhil](https://github.com/Akhil-Chaturvedi/x64dbg-MCP) and [DNLINYJ](https://github.com/DNLINYJ/better-x64dbg-mcp).
  - `--tools` groups in [glslang](https://github.com/glslang/windbg-mcp).
  - Profiles in [rison1337](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md).
  - Lazy tool groups with search_tools in [bethington](https://github.com/bethington/ghidra-mcp).
  - The debugger extension hidden behind `?ext=dbg` in [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).
- **Batch-first APIs recur**: dbg_read(regions) and batch rename ([ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)), read_memory_many ([x64dbg-automate](https://dariushoule.github.io/x64dbg-automate-pyclient/mcp-server/)), EvalBatch and ReadMemoryBatch ([rison1337](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md)), WatchExpressions ([duty1g](https://github.com/duty1g/x64dbg-mcp-server)), x64dbg_batch_annotate ([Akhil](https://github.com/Akhil-Chaturvedi/x64dbg-MCP)).
- **Unpacking and dumping (OEP, dump, IAT) recur among x64dbg servers**: DetectOEP and DumpModule ([duty1g](https://github.com/duty1g/x64dbg-mcp-server)); FindOEP, RunUntilOEP, FixDumpImports and ValidateDump ([rison1337](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md)); advanced_dump with PE rebuild ([Akhil](https://github.com/Akhil-Chaturvedi/x64dbg-MCP)).
- **Handles, TCP connections and PEB/TEB recur**: EnumHandles and EnumTcpConnections ([Wasdubya](https://github.com/Wasdubya/x64dbgMCP)); x64dbg_handles covering handles, TCP, windows and heaps ([Akhil](https://github.com/Akhil-Chaturvedi/x64dbg-MCP)); get_handles, get_teb and get_peb ([gengstah](https://github.com/gengstah/windbg-mcp)).
- **Unique features**:
  - Breakpoint auto-capture buffer ([gengstah](https://github.com/gengstah/windbg-mcp)).
  - Pause-reason attribution and paged breakpoint log files ([DNLINYJ](https://github.com/DNLINYJ/better-x64dbg-mcp)).
  - debug_batch with rollback; walk_memory; exception_triage; decode_error_reporting ([glslang](https://github.com/glslang/windbg-mcp)).
  - XPIA classification via sampling ([Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/windbg-mcp-overview)).
  - Debuggee GUI and console automation, breakpoint and mutation leases, and SHA-256+RVA evidence hand-off ([rison1337](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md)).
  - "_and_context" composite steps ([BeaCox](https://github.com/BeaCox/gdb-mcp)).
  - A searchable official command-doc catalog ([kanren3](https://github.com/kanren3/windbg-mcp-rs)).
  - VM snapshot, restore and screenshot alongside the debugger ([memoryforensics1](https://github.com/memoryforensics1/windbg-mcp)).
  - Redaction filter script ([svnscha](https://github.com/svnscha/mcp-windbg)).
  - Value sampling over time and per-hop pointer evidence ([CheatEngine.Mcp](https://github.com/CheatEngineNet/CheatEngine.Mcp)).
  - P-code emulation ([bethington](https://github.com/bethington/ghidra-mcp)).

### Inferences
- The field is converging on giving the model compact, structured, evidence-bearing results, and on the server doing multi-step bookkeeping atomically. Examples are kahlo's atomic spawn, glslang's batches and rison's capture tools.
- Raw command passthrough is universal, yet it is the main safety hole. Microsoft and MDB-MCP both warn about indirect execution through breakpoint commands and shell commands. binary-mcp's allowlist is ahead of most projects here.

### Gaps
- There are no quantitative comparisons (for example task success rate by tool design) across projects. Only glslang publishes a local-model eval.

## What do write-ups and talks say about which tools proved most useful or problematic in LLM-driven debugging?

### Takeaway
Practitioners report three main things:
- x64dbg MCPs are the most token-hungry part of an analysis lab, but still worth having.
- Higher-level skills such as snapshot/diff, trace analysis and decompilation beat raw step and read calls.
- Models hallucinate number conversions and API signatures.

Agents also mismanage multi-step setup, so atomic composites, structured errors and self-description tools help.

### Cited Findings
- **G DATA (Karsten Hahn, 2026-03-03)**:
  - x64dbg MCP was "very token hungry", the most token-intensive tool in his lab, but still worthwhile for samples that are easier to debug.
  - Headless Ghidra decompilation "substantially improved analysis" at far lower token cost than disassembly.
  - Sonnet 4.6 failed to extract a runtime-built next-stage URL until steered toward emulation.
  - Pay-per-token analysis cost about €5-20 per sample.
  - He recommends verifying IoCs and using scripts as a feedback loop.
  - Source: [G DATA blog](https://blog.gdatasoftware.com/2026/03/38381-llm-malware-analysis)
- **x64.ooo, "Cooking with x64dbg and MCP" (2026-02-12)**:
  - Uses the x64dbg Automate MCP plus x64dbg-skills: decompile (angr), state snapshot/diff, tracealyze and yara-sigs.
  - Snapshot/diff of memory and registers around a region helps infer what obfuscated routines do.
  - tracealyze deobfuscates strings and API calls from traces.
  - Raw MCP calls on resistant binaries are costly.
  - Without docs, models hallucinate x64dbg API signatures; Context7 helps.
  - Source: [x64.ooo](https://x64.ooo/posts/2026-02-12-cooking-with-x64dbg-and-mcp/)
- **mrexodia/ida-pro-mcp**: LLMs are especially bad at converting between integers and bytes, so use int_convert. LLMs do poorly on obfuscated code. — [README](https://github.com/mrexodia/ida-pro-mcp)
- **KnifeCoat/kahlo**: agents skipped steps in multi-step setup, leaked suspended processes, and needed structured errors that name the next tool. A self-description tool helped them recover from context rot. — [KnifeCoat](https://knifecoat.com/Posts/Scalable+research+tooling+for+agent+systems)
- **Check Point Research (2025)**: in XLoader research, an MCP-connected LLM drove IDA Pro, x64dbg and VMware. Live debugging was still needed to confirm guessed keys and to recover material static analysis missed. I only saw this through a search summary, so check the original. — [Check Point Research](https://research.checkpoint.com/2025/generative-ai-for-reverse-engineering/)
- **Wasdubya/x64dbgMCP**: recommends that models start with GetModuleBase, give the full exe path so the model can restart a crashed target, and use the Headroom proxy to cut tokens. — [README](https://github.com/Wasdubya/x64dbgMCP)
- **AgentSmithers/x64DbgMCPServer**: a raw command "success" result only confirms the command was submitted, not its outcome. — [README](https://github.com/AgentSmithers/x64DbgMCPServer)
- **x64dbg-automate**: `$result` is stale between commands, and a cached memory map survives detach. — [docs](https://dariushoule.github.io/x64dbg-automate-pyclient/mcp-server/)
- **glslang/windbg-mcp**: a local-model eval found two defects in the server. — [README](https://github.com/glslang/windbg-mcp)

### Inferences
- Token cost is the dominant complaint, which favours compact defaults, base64 or hex memory formats, response caps, and composite capture tools over many small calls.
- The most useful dynamic primitive in practice appears to be "run code region X and tell me what changed" (snapshot/diff, captures, traces), not step-by-step stepping.

### Gaps
- I found no REcon, OffensiveCon, Black Hat or DEF CON 2024-2026 talk specifically on LLM-driven debugger MCPs, though some may exist. The search effort here was limited.

## Gaps vs binary-mcp

Source note: these gaps compare against the binary-mcp feature summary in the task brief; I did not audit binary-mcp's code. Items marked (verify) may partly exist under another name.

1. **Breakpoint auto-capture buffer.** Each breakpoint takes `capture` and `action` (go or break), saving registers, stack, nearby memory and the instruction on every hit. Captures are read later in one call, so the model does not need a stop/inspect round-trip per hit. — [gengstah](https://github.com/gengstah/windbg-mcp); [rison1337 SetBreakpointWithCapture, BatchBreakpointsCapture, SetMemoryWatchpointWithCapture, CaptureExecuteAfterWrite](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md)
2. **Pause-reason attribution in status/wait results**: breakpoint (type, hit_count, log), exception (code, name, first_chance), step, or unknown, attributed conservatively. (verify) — [DNLINYJ](https://github.com/DNLINYJ/better-x64dbg-mcp)
3. **Paged log-breakpoint output**: non-stopping logging breakpoints whose output is paged through with continuity tokens. — [DNLINYJ](https://github.com/DNLINYJ/better-x64dbg-mcp)
4. **Async continue handle**, where a wait that runs out is a poll and not an error, plus **server push** (SSE notifications) of debug events. (verify how binary-mcp's `wait` reports timeout) — [glslang](https://github.com/glslang/windbg-mcp); [DNLINYJ](https://github.com/DNLINYJ/better-x64dbg-mcp)
5. **Transactional batch with assertions and guaranteed rollback**, or a scripted multi-step workflow with branching. — [glslang debug_batch](https://github.com/glslang/windbg-mcp); [Akhil x64dbg_script](https://github.com/Akhil-Chaturvedi/x64dbg-MCP)
6. **Composite "step/continue and context" responses**: every execution op returns IP, disassembly, stack and changed registers, which saves follow-up calls. (verify) — [BeaCox](https://github.com/BeaCox/gdb-mcp); [gengstah step tools](https://github.com/gengstah/windbg-mcp)
7. **Structured error taxonomy**: stable categories, a `retryable` flag and a suggested next tool, using MCP `structuredContent`. — [glslang](https://github.com/glslang/windbg-mcp); [KnifeCoat](https://knifecoat.com/Posts/Scalable+research+tooling+for+agent+systems)
8. **Exception and error decoding**: exception_triage (exception record, C++ thrown type, HRESULT) and decode of NTSTATUS, HRESULT and Win32 codes; also exception history and policy. — [glslang](https://github.com/glslang/windbg-mcp); [rison1337 GetExceptionHistory, SetExceptionPolicy](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md); [Akhil x64dbg_exceptions and database error codes](https://github.com/Akhil-Chaturvedi/x64dbg-MCP)
9. **int_convert or number-format helper**, so the model never converts bases or endianness itself. — [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp); [binary_ninja_mcp convert_number](https://github.com/fosdickio/binary_ninja_mcp)
10. **Pointer-chain follow and telescope**: dereferences N levels with per-hop evidence and symbolization. — [duty1g FollowPointer](https://github.com/duty1g/x64dbg-mcp-server); [BeaCox gdb_telescope](https://github.com/BeaCox/gdb-mcp); [CheatEngine.Mcp](https://github.com/CheatEngineNet/CheatEngine.Mcp)
11. **Structure walking**: walks linked lists and arrays, turning unreadable nodes into rows. Pairs with binary-mcp's C types. — [glslang walk_memory](https://github.com/glslang/windbg-mcp)
12. **Batch evaluate and batch read**: many expressions or regions in one call, sharing one response budget. (verify) — [duty1g WatchExpressions](https://github.com/duty1g/x64dbg-mcp-server); [x64dbg-automate read_memory_many](https://dariushoule.github.io/x64dbg-automate-pyclient/mcp-server/); [rison1337 EvalBatch, ReadMemoryBatch](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md)
13. **Response budgeting**: choice of memory format (base64 at about 1.33x), explicit refusal with the limit named, `size=0` meaning the largest read that fits, and compact versus full detail profiles. — [x64dbg-automate](https://dariushoule.github.io/x64dbg-automate-pyclient/mcp-server/); [rison1337 profiles](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md)
14. **Tool-surface control**: profiles or `--tools` groups, lazy tool-group loading and search_tools. — [glslang](https://github.com/glslang/windbg-mcp); [bethington](https://github.com/bethington/ghidra-mcp); [rison1337](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md)
15. **MCP resources and prompts**: state, registers and memory-map resources plus URI templates, and workflow prompts (unpack_binary, analyze_crash, api_monitor, compare_state). A self-describing "about/contract" tool helps recover from context rot. — [Akhil](https://github.com/Akhil-Chaturvedi/x64dbg-MCP); [MS prompts](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/windbg-mcp-overview); [kahlo_mcp_about](https://github.com/FuzzySecurity/kahlo-mcp)
16. **Unpacking and dump repair**:
    - IAT candidate discovery and reconstruction (Scylla-like).
    - FixDumpImports, ValidateDump and VerifyPEDump.
    - PE rebuild.
    - ScanMemoryForPEImages to find injected or manually mapped PEs.
    - RunUntilOEP.
    - ExportPatchedFile, which writes patches back to a file on disk.
    - binary-mcp has trace-to-OEP and module dump, but no IAT fix or validation is listed. — [rison1337](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md); [Akhil x64dbg_advanced_dump, x64dbg_patches export](https://github.com/Akhil-Chaturvedi/x64dbg-MCP)
17. **Patch management and patch idioms**: list, revert and restore patches; export patches; auto-patch (NOP, force JMP, invert conditional, RET); assemble an instruction at an address. (verify) — [duty1g RestorePatches, GetPatches, Assemble](https://github.com/duty1g/x64dbg-mcp-server); [Akhil x64dbg_auto_patch](https://github.com/Akhil-Chaturvedi/x64dbg-MCP); [Wasdubya AssemblerAssembleMem](https://github.com/Wasdubya/x64dbgMCP)
18. **Process environment enumeration**: handles, TCP connections, windows, heaps (and heap walk or heap trace), TEB, PEB fields, SEH chain, process command line and elevation. (verify which exist) — [Wasdubya EnumHandles, EnumTcpConnections, GetTebAddress](https://github.com/Wasdubya/x64dbgMCP); [Akhil x64dbg_handles, x64dbg_process](https://github.com/Akhil-Chaturvedi/x64dbg-MCP); [duty1g GetSEHChain, GetPEB](https://github.com/duty1g/x64dbg-mcp-server); [rison1337 StartHeapTrace, GetHeapState](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md); [glslang heap_*](https://github.com/glslang/windbg-mcp)
19. **Function-argument reader** at a call or breakpoint: reads arguments by calling convention. — [duty1g GetArguments](https://github.com/duty1g/x64dbg-mcp-server); [rison1337 GetFunctionArgs](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md)
20. **Static-identity evidence export and import**: every address also reported as module+RVA, with an exported evidence document keyed by file SHA-256+RVA (coverage, API calls, labels) that the static tool imports after a hash and architecture check. binary-mcp has Ghidra address mapping; check whether all outputs carry RVA and whether runtime findings flow back into Ghidra or IDA. — [rison1337](https://github.com/rison1337/x64dbgMCP); [glslang backtrace and disassemble RVAs](https://github.com/glslang/windbg-mcp); [bethington static↔dynamic translation](https://github.com/bethington/ghidra-mcp)
21. **Coverage artifacts**: export, merge and diff coverage between runs, for example to find the branch where a license check fails. — [rison1337](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md)
22. **Rewind, checkpoint and replay-to-address and TTD-style reverse execution.** binary-mcp has state save and restore; reverse stepping and TTD are absent. — [rison1337 Checkpoint, Rewind, ReplayToAddress](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md); [glslang TTD](https://github.com/glslang/windbg-mcp); [BeaCox rr](https://github.com/BeaCox/gdb-mcp)
23. **Child-process following and multi-session binding**: FollowChildProcess and WaitForChildProcess, with explicit session_id routing for several debuggees. — [rison1337](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md); [glslang sessions](https://github.com/glslang/windbg-mcp)
24. **Debuggee GUI and console interaction**: enumerate windows, screenshot and diff, click controls, set text, submit forms, read and write console stdin and stdout. This is needed to drive a sample past a "click OK" dialog or a password prompt while under the debugger. — [rison1337](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md)
25. **Managed .NET runtime inspection**: JIT method resolution, metadata tokens and managed-method breakpoints. — [rison1337](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md); [CheatEngine.Mcp Mono/.NET](https://github.com/CheatEngineNet/CheatEngine.Mcp)
26. **Breakpoint and mutation leases (ownership)**, so concurrent agents or a human do not clobber each other's breakpoints and patches. A "list only breakpoints I own" view goes with this. — [rison1337](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md)
27. **Output-side safety**:
    - Prompt-injection classification of debuggee-derived strings via MCP sampling.
    - A redaction filter hook.
    - JSONL audit transcripts of every call.
    - binary-mcp has a raw-command allowlist but nothing listed for output-borne prompt injection; malware strings are a direct injection vector.
    - Sources: [MS WinDbg MCP XPIA](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/windbg-mcp-overview); [svnscha filter-script](https://github.com/svnscha/mcp-windbg); [glslang transcripts](https://github.com/glslang/windbg-mcp)
28. **Command-documentation lookup tool**: search x64dbg command and expression docs so the model does not hallucinate syntax for the raw-command path. — [kanren3](https://github.com/kanren3/windbg-mcp-rs); [x64.ooo on hallucinated APIs](https://x64.ooo/posts/2026-02-12-cooking-with-x64dbg-and-mcp/)
29. **Emulation of a function or snippet** without running the sample, for example to resolve API hashes or decode strings. Practitioners needed this when the debugger route was too costly. — [bethington P-code emulation](https://github.com/bethington/ghidra-mcp); [G DATA](https://blog.gdatasoftware.com/2026/03/38381-llm-malware-analysis)
30. **Cheat-Engine-style value scanning**: scan, rescan by value or changed/unchanged, and sample a value over time. Useful for locating state such as counters or flags in memory. — [CheatEngine.Mcp](https://github.com/CheatEngineNet/CheatEngine.Mcp)
31. **VM-level controls** next to the debugger: snapshot restore, screenshot, and guest file transfer. This is outside x64dbg scope but recurs in malware labs. — [memoryforensics1](https://github.com/memoryforensics1/windbg-mcp); [G DATA on VM snapshots](https://blog.gdatasoftware.com/2026/03/38381-llm-malware-analysis)
32. **Bookmarks and batch annotation**: setting many labels, comments and bookmarks in one call. (verify) — [Akhil x64dbg_batch_annotate](https://github.com/Akhil-Chaturvedi/x64dbg-MCP); [duty1g bookmarks](https://github.com/duty1g/x64dbg-mcp-server)
33. **Thread create, kill and suspend/resume-all, and thread priority.** (verify) — [x64dbg-automate create_thread, terminate_thread](https://dariushoule.github.io/x64dbg-automate-pyclient/mcp-server/); [rison1337 SuspendAllThreads, SetThreadPriority](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md)
34. **Remote debug-target helpers**: LoadLibraryInDebuggee, RemoteGetProcAddress and VA↔file-offset conversion. (verify) — [rison1337](https://github.com/rison1337/x64dbgMCP/blob/main/docs/TOOL_REFERENCE.md); [Wasdubya MiscRemoteGetProcAddress](https://github.com/Wasdubya/x64dbgMCP); [Akhil x64dbg_address_convert](https://github.com/Akhil-Chaturvedi/x64dbg-MCP)

Deliberate non-gap: every major competitor exposes a launch tool (LoadBinary, InitDebuggee, start_session, create, launch, dbg_start). binary-mcp's no-launch stance matches Microsoft's secure mode, which blocks process launch. Atomic attach-and-break, as in kahlo's spawn-gating idea, could be offered for an already-suspended process without launching anything. — [MS Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/windbg-mcp-overview); [kahlo](https://github.com/FuzzySecurity/kahlo-mcp)
