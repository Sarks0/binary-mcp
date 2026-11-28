# x64dbg capabilities and what binary-mcp does not expose yet

Method: I pulled the primary sources from GitHub on 2026-11-23. These were the `development` branch headers (`_dbgfunctions.h`, `bridgemain.h`, `_plugins.h`, `_scriptapi_*.h`), the command registration table in `src/dbg/x64dbg.cpp`, the x64dbg/docs markdown, Scylla's `FunctionExport.h`, the ScyllaHide config and the x64dbg-automate client. I also grepped binary-mcp itself (`src/engines/dynamic/x64dbg/plugin/plugin.cpp` and related files) to see what it already uses. The plugin registers CB_CREATEPROCESS/EXITPROCESS/CREATETHREAD/EXITTHREAD/LOADDLL/UNLOADDLL/EXCEPTION/BREAKPOINT/PAUSEDEBUG/RESUMEDEBUG/STEPPED/SYSTEMBREAKPOINT/MENUENTRY. It never calls `DbgFunctions()->...`, and from the Script API it only uses `Script::Module`.

Abbreviated source keys used below. They are given as full URLs in each citation.
- CMDS = https://github.com/x64dbg/x64dbg/blob/development/src/dbg/x64dbg.cpp (the `dbgcmdnew` registration table, lines ~110-519)
- DBGF = https://github.com/x64dbg/x64dbg/blob/development/src/dbg/_dbgfunctions.h
- BRIDGE = https://github.com/x64dbg/x64dbg/blob/development/src/bridge/bridgemain.h
- PLUG = https://github.com/x64dbg/x64dbg/blob/development/src/dbg/_plugins.h

## 1. Command reference: categories, safety and the commands not yet allowlisted

### Takeaway
x64dbg registers about 400 commands. Beyond what binary-mcp already allowlists, the most valuable read-only ones are these:
- `bpcond`/`bplog`/`SetBreakpointFastResume`/`SetBreakpointSilent`/`GetBreakpointHitCount`, plus the hw/mem/dll/exception variants. Strictly these configure breakpoints rather than read state, but they cannot launch anything.
- `imageinfo`, `GetRelocSize`, `getpagerights`, `GetPrivilegeState`, `gpa`, `getcommandline`, `mnemonicbrief`, `printstack`, `symdownload`/`symload`, `virtualmod`, `TraceSetStepFilter`, `RunToParty`, `StartRunTrace`/`StopRunTrace`, and the `function*`/`argument*`/`loop*` list commands.

These commands are dangerous: `loadlib`, `scriptdll`, `scriptload`/`scriptrun`, `plugload`, `createthread`, `init`, `restartadmin`, `setjit`, `chd`, `savedata`, `minidump`, `dbsave`, `RedirectLog`/`SaveLog`, `SetBreakpointLogFile`, `handleclose`, `killthread` and `StartScylla`.

### Cited Findings
**Command categories with names and aliases (all from CMDS: https://github.com/x64dbg/x64dbg/blob/development/src/dbg/x64dbg.cpp)**
- Debug control. Read-only/safe: none (all change state). Dangerous: `InitDebug,init` (launches), `AttachDebugger`, `DetachDebugger`, `StopDebug`. Stepping commands: `run/erun/serun`, `pause`, `StepInto/eStepInto/seStepInto`, `StepOver/...`, `StepOut,rtr`/`eStepOut`, `skip`, `InstrUndo`, `StepUser`, `StepSystem`. `skip` is not in our list.
- Breakpoint control: `bp`/`bpc`/`bpe`/`bpd`, `bph*`, `bpm`/`bpmrange`/`bpmc`/`bpme`/`bpmd`, the `bpdll` family, `SetExceptionBPX`/`Delete`/`Enable`/`DisableExceptionBPX`, `bpgoto`, `bplist`, `SetBPXOptions,bptype`.
- Conditional breakpoint control, repeated for each of the five breakpoint kinds (software, hardware, memory, librarian/DLL, exception): `Set*BreakpointName`, `Set*BreakpointCondition` (`bpcond`/`bphwcond`/`bpmcond`), `Set*BreakpointLog` (`bplog`/`bphwlog`/`bpmlog`), `Set*BreakpointLogCondition`, `Set*BreakpointCommand`, `Set*BreakpointCommandCondition`, `Set*BreakpointLogFile`, `Set*BreakpointFastResume`, `Set*BreakpointSingleshoot`, `Set*BreakpointSilent`, `Get*BreakpointHitCount`, `Reset*BreakpointHitCount`.
- Tracing: `ticnd`/`tocnd`, `tibt`/`tobt`, `tiit`/`toit` ("into trace record"), `RunToParty`, `RunToUserCode,rtu`, `TraceSetLog`, `TraceSetCommand`, `TraceSetLogFile`, `TraceSetStepFilter`, `StartTraceRecording,StartRunTrace,opentrace`, `StopTraceRecording,StopRunTrace,tc`.
- Thread control: `createthread`, `switchthread`, `suspendthread`, `resumethread`, `killthread`, `suspendallthreads`, `resumeallthreads`, `setthreadpriority`, `threadsetname`.
- Memory: `alloc`, `free`, `Fill,memset`, `memcpy`, `getpagerights`, `setpagerights`, `savedata`, `minidump`.
- Operating-system control: `GetPrivilegeState`, `EnablePrivilege`, `DisablePrivilege`, `handleclose`, `EnableWindow`, `DisableWindow`.
- Watch: `AddWatch`, `DelWatch`, `SetWatchdog`, `SetWatchExpression`, `SetWatchName`, `SetWatchType`, `CheckWatchdog`.
- Variables: `var`, `vardel`, `varlist`.
- Searching: `find`, `findall`, `findallmem`, `findasm`, `ref`, `reffindrange`, `refstr`, `reffunctionpointer`, `modcallfind`, `setmaxfindresult`, `findguid`.
  - `reffunctionpointer`, `reffindrange` and `setmaxfindresult` are not on our list.
- User database:
  - Database files: `dbsave`, `dbload`, `dbclear`.
  - Annotations: `commentset/del/list/clear`, `labelset/del/list/clear`, `bookmarkset/...`, `addresscolor*`.
  - Analysis records: `functionadd/del/list/clear`, `argumentadd/...`, `loopadd/...`.
- Analysis: `analyse`, `exanal`, `cfanal`, `analyse_nukem`, `analxrefs`, `analrecur`, `analadv`, `traceexecute`, `virtualmod`, `symdownload`, `symload`, `symunload`, `imageinfo`, `GetRelocSize,grs`, `exhandlers`, `exinfo`, `LabelRuntimeFunctions`.
- Data typing: `DataByte,db` ... `DataAscii,da`, `DataUnicode,du`, `DataCode,dc`, `DataJunk`.
- Types: `AddType`/`AddStruct`/`AddUnion`/`AddMember`/`AddFunction`/`AddArg`, `SizeofType`, `VisitType,DisplayType,dt`, `ClearTypes`, `RemoveType`, `EnumTypes`, `LoadTypes`, `ParseTypes`.
- Plugins: `StartScylla,scylla,imprec`, `plugload`, `plugunload`, `plugreload`.
- Script: `scriptload`, `msg`, `msgyn`, `log`, `htmllog`, `scriptdll`, `scriptcmd`, `scriptrun`, `scriptexec`, `testassert`, `testscript`, `settingset`.
- GUI: `disasm,dis`, `dump`, `sdump`, `memmapdump`, `graph`, `refinit`/`refadd`/`refget`, `EnableLog`/`DisableLog`/`ClearLog`/`SaveLog`/`RedirectLog`, `FoldDisassembly`, `symfollow`, `gototrace`, `AddFavouriteTool`/`AddFavouriteCommand`.
- Misc: `chd`, `zzz`, `HideDebugger`, `loadlib`, `freelib`, `asm`, `gpa`, `setjit`/`getjit`/`getjitauto`/`setjitauto`, `getcommandline`/`setcommandline`, `mnemonichelp`, `mnemonicbrief`, `config`, `restartadmin,runas`, `dprintf`, `setstr`/`getstr`/`copystr`, `zydis`, `visualize`, `meminfo`, `printstack,logstack`, `flushlog`, `dbdecompress`, `DebugFlags`.
- The calculator-style commands (`inc`, `add`, `xor`, `mov,set`, `push`, `pop`, `bswap`, ...) operate on variables, registers and memory.

**What the conditional breakpoint machinery does**
- When a breakpoint is hit, x64dbg sets `$breakpointexceptionaddress` and increments a hit counter (`$breakpointcounter`). It then evaluates the break condition. If fast resume is on and the condition is 0, it resumes immediately and skips plugin callbacks and GUI updates. It also evaluates the log and command conditions, prints the formatted log text, and runs the command text. A command can change `$breakpointcondition` to decide whether to break. An invalid expression always breaks. Numbers are hex by default. - [ConditionalBreakpoint.md](https://github.com/x64dbg/docs/blob/master/introduction/ConditionalBreakpoint.md)
- Example: a break condition of `0` gives a breakpoint that only logs or runs a command. `arg.get(0)==1` filters on the first argument. - [ConditionalBreakpoint.md](https://github.com/x64dbg/docs/blob/master/introduction/ConditionalBreakpoint.md)
- The log format syntax is `{?:expr}`.
  - Basic types: `d`, `u`, `p`, `s`, `x`, `a` (address plus symbol) and `i` (instruction).
  - Floating-point types: `f`/`F`, including XMM/YMM/ZMM registers.
  - Complex types: `{mem;size@addr}`, `{winerror@code}`, `{ntstatus@code}`, `{ascii|ansi|utf8|utf16[;len]@addr}`, `{disasm@}`, `{modname@}`, `{bswap;size@}`, `{label@}`, `{comment@}`.
  - Plugins can add formatters with `_plugin_registerformatfunction`.
  - - [Formatting.md](https://github.com/x64dbg/docs/blob/master/introduction/Formatting.md)
- Conditional tracing follows the same pattern: `$tracecounter` and break/log/command conditions, with `$tracecondition` and `$tracelogcondition`. `{p:cip} {i:cip}` logs every traced instruction. Trace Over does not log or record inside the calls it steps over. - [ConditionalTracing.md](https://github.com/x64dbg/docs/blob/master/introduction/ConditionalTracing.md)
- Expression functions are what conditions, log strings and `eval` can call. All of them are read-only except `arg.set`.
  - Process: `peb()`, `teb()`, `tid()`, `kusd()`.
  - Modules: `mod.party/base/size/hash/entry/system/user/main/rva/offset/isexport/fromname`.
  - Memory: `mem.valid/base/size/iscode/decodepointer`.
  - Disassembly: `dis.*`, for example `dis.iscallsystem`, `dis.match(addr, regex)`, `dis.branchexec`.
  - Trace: `tr.enabled/hitcount/isrecording`.
  - Exceptions: `ex.firstchance/addr/code/flags/info(i)`.
  - Syscalls: `syscall.name(n)` and `syscall.id(name)`.
  - Strings: `utf8/utf16/ansi`, `strstr`, `streq`.
  - Arguments: `arg.get/arg.set`.
  - Other: `func.start/end`, `ref.count/addr`, `rdtsc()`, `GetTickCount()`.
  - - [Expression-functions.md](https://github.com/x64dbg/docs/blob/master/introduction/Expression-functions.md)

**Documented behaviour of individual commands**
- `savedata file, addr, size` writes memory to disk. The name `:memdump:` produces `memdump_pid_addr_size.bin` in the x64dbg directory, and the filename accepts format strings. Risk: it writes files. - [savedata.md](https://github.com/x64dbg/docs/blob/master/commands/memory-operations/savedata.md)
- `minidump file.dmp` writes a full-memory minidump that includes handle information. - [minidump.md](https://github.com/x64dbg/docs/blob/master/commands/memory-operations/minidump.md)
- `HideDebugger/dbh` patches the PEB so that `IsDebuggerPresent()` returns false. It only defeats very simple checks. - [HideDebugger.md](https://github.com/x64dbg/docs/blob/master/commands/misc/HideDebugger.md)
- `handleclose h` closes a handle in the debuggee. It mutates the debuggee and is destructive. - [handleclose.md](https://github.com/x64dbg/docs/blob/master/commands/operating-system-control/handleclose.md)
- `imageinfo [base]` prints the PE Characteristics and DllCharacteristics of a module. It is read-only. - [imageinfo.md](https://github.com/x64dbg/docs/blob/master/commands/analysis/imageinfo.md)
- `RunToParty n` places temporary memory breakpoints on every page of that party (0 = user, 1 = system). `rtu` is the same as `RunToParty 0`. - [RunToParty.md](https://github.com/x64dbg/docs/blob/master/commands/tracing/RunToParty.md), [RunToUserCode.md](https://github.com/x64dbg/docs/blob/master/commands/tracing/RunToUserCode.md)
- `symdownload [module] [storeURL]` downloads symbols from a symbol store, for all modules if none is given. This makes network requests. - [symdownload.md](https://github.com/x64dbg/docs/blob/master/commands/analysis/symdownload.md)
- `virtualmod name, base[, size]` treats a memory range as a module. This is useful for unpacked or manually mapped payloads. - [virtualmod.md](https://github.com/x64dbg/docs/blob/master/commands/analysis/virtualmod.md)
- `SetWatchdog id, changed|unchanged|istrue|isfalse` makes a watch expression act as a tripwire. - [SetWatchdog.md](https://github.com/x64dbg/docs/blob/master/commands/watch-control/SetWatchdog.md)
- `gpa export[, dll]` resolves an export in the debuggee and stores it in `$result`. - [gpa.md](https://github.com/x64dbg/docs/blob/master/commands/misc/gpa.md)
- `traceexecute addr` marks an address as traced in trace coverage. - [traceexecute.md](https://github.com/x64dbg/docs/blob/master/commands/analysis/traceexecute.md)
- `createthread entry[, arg]` creates a thread in the debuggee. It executes code. - [createthread.md](https://github.com/x64dbg/docs/blob/master/commands/thread-control/createthread.md)
- `chd` calls SetCurrentDirectory in the debugger process. - [chd.md](https://github.com/x64dbg/docs/blob/master/commands/misc/chd.md)
- `scriptdll` loads a DLL into **x64dbg itself** and calls its `Start`/`AsyncStart`, then unloads it. It executes arbitrary code in the debugger. - [scriptdll.md](https://github.com/x64dbg/docs/blob/master/commands/script/scriptdll.md)
- `TraceSetStepFilter` and the `rtu` rework are new in the 2026.04.20 release. - [x64dbg releases](https://github.com/x64dbg/x64dbg/releases)

### Inferences
- Several breakpoint commands can be allowlisted safely if we validate their arguments: the `bpcond`, `bplog`, `bplogcondition`, `SetBreakpointFastResume`, `SetBreakpointSilent`, `SetBreakpointSingleshoot` and `Get/ResetBreakpointHitCount` families for all five breakpoint kinds. Together they enable "log every call to X with args, never break", the most useful pattern for an LLM.
- `bpcommand`/`bpcommandcond` should stay restricted, or be limited to commands on the allowlist. A breakpoint command is an arbitrary debugger command, so it could carry `loadlib` or `scriptdll`.
- `bplog` text can execute nothing except expression functions, which are read-only apart from `arg.set`. `SetBreakpointLogFile` writes files and should be blocked or constrained to a sandbox directory.
- `savedata` and `minidump` write files. If they are exposed, binary-mcp should force the path into its own output directory.

### Gaps
- `DebugFlags`, `LabelRuntimeFunctions`, `briefcheck`, `focusinfo` and `visualize` have no documentation pages in x64dbg/docs, and I did not read their implementations.
- The docs moved into the main repo in 2025 according to the [releases](https://github.com/x64dbg/x64dbg/releases) page. The x64dbg/docs master pages I cite may lag slightly behind.

## 2. Plugin SDK: DbgFunctions(), bridge exports, Script API and callbacks

### Takeaway
`DbgFunctions()` contains a large amount of structured, read-only data that binary-mcp does not use at all. It covers:
- call stacks, the SEH chain, handles with names, TCP connections, windows and heaps
- the patch list and patched-file export
- module party and relocations
- page rights and DEP state
- source lines and symbol status
- trace-record hit counts
- a breakpoint-reference API for reading and writing fields
- `StringFormatInline`

The bridge adds TEB/PEB addresses, xrefs, symbol info, the watch list, function/loop/argument records and a control-flow graph.

### Cited Findings
**`DBGFUNCTIONS` members (DBGF: https://github.com/x64dbg/x64dbg/blob/development/src/dbg/_dbgfunctions.h)**
- Patches:
  - `PatchGet`, `PatchGetEx`, `PatchInRange`, `PatchEnum(DBGPATCHINFO*, size_t*)`, `PatchRestore`, `PatchRestoreRange`.
  - `PatchFile(patchlist, count, szFileName, error)` writes the patched file to disk.
  - `MemPatch` writes memory and records it as a patch.
- Assembly: `Assemble`, `AssembleAtEx(addr, instr, error, fillnop)`, `DisasmFast`, `GetMnemonicBrief`.
- Modules:
  - Lookups: `ModNameFromAddr`, `ModBaseFromAddr/Name`, `ModSizeFromAddr`, `ModPathFromAddr/Name`, `SectionFromAddr`.
  - Party: `ModGetParty`/`ModSetParty`.
  - Relocations: `ModRelocationsFromAddr`, `ModRelocationAtAddr`, `ModRelocationsInRange`.
  - Other: `ModSymbolStatus`, `RefreshModuleList`, `ModNameFromHash`.
- Memory: `MemUpdateMap`, `GetPageRights`/`SetPageRights`, `PageRightsToString`, `MemIsCodePage`, `MemBpSize`, `FileOffsetToVa`, `VaToFileOffset`.
- Stacks and exceptions: `GetCallStack`, `GetCallStackEx(cache)`, `GetCallStackByThread(HANDLE)` and `GetSEHChain(DBGSEHCHAIN*)`.
- OS objects: `EnumHandles(ListOf(HANDLEINFO))`, `GetHandleName(handle, name, typeName)`, `EnumTcpConnections`, `EnumWindows(ListOf(WINDOW_INFO))`, `EnumHeaps(ListOf(HEAPINFO))`, `GetProcessList`, `ThreadGetName`.
- Process state: `IsProcessElevated`, `IsDepEnabled`, `GetCmdline`/`SetCmdline`, `GetJit`, `GetJitAuto`, `GetDefJit`.
- Symbols and source: `SymbolDownloadAllSymbols(store)`, `GetAddrFromLine`/`GetAddrFromLineEx`, `GetSourceFromAddr`, `SymAutoComplete`.
- Expressions and formatting: `ValFromString`, `StringFormatInline(format, size, result)`.
- Trace record: `GetTraceRecordHitCount(addr)`, `GetTraceRecordByteType`, `Set/GetTraceRecordType(page)`.
- Debug events and watches: `GetDbgEvents()` returns a count of debug events, and `WatchIsWatchdogTriggered(id)`.
- Constants: `EnumConstants`, `EnumErrorCodes`, `EnumExceptions`.
- Other: `GetUserComment`, `DbGetHash`, `EnumStructs`.
- Breakpoint-reference API: `BpRefList`, `BpRefVa`, `BpRefRva(module, rva)`, `BpRefDll`, `BpRefException`, `BpRefExists`, `BpGet/SetFieldNumber`, `BpGet/SetFieldText`. These give typed access to breakpoint fields such as conditions and logs without building command strings.
- Commands: `CommandEscape(arg)` escapes an argument for safe quoting inside a command. `AnimateCommand`.
- Init scripts: `DbgSetDebuggeeInitScript`/`DbgGetDebuggeeInitScript`.
- Version note: `BpRef*`, `CommandEscape` and `ModNameFromHash` sit at the end of the struct, so they are recent additions. Check that the x64dbg build we target has them before calling.

**Bridge exports (BRIDGE: https://github.com/x64dbg/x64dbg/blob/development/src/bridge/bridgemain.h)**
- Process and thread: `DbgGetPebAddress(pid)`, `DbgGetTebAddress(tid)`, `DbgGetThreadList`, `DbgGetProcessHandle`/`DbgGetThreadHandle`.
- Cross-references: `DbgXrefGet(addr, XREF_INFO*)`, `DbgGetXrefCountAt`, `DbgGetXrefTypeAt`.
- Strings: `DbgGetStringAt`.
- Watches: `DbgGetWatchList`.
- Graph: `DbgAnalyzeFunction(entry, BridgeCFGraphList*)` returns a CFG.
- Symbols: `DbgSymbolEnum`, `DbgSymbolEnumRange`, `DbgSymbolEnumFromCache`, `DbgGetSymbolInfoAt`.
- Database records: `DbgFunctionGet`, `DbgLoopGet`, `DbgArgumentGet`, `DbgGetArgTypeAt`, `DbgGetEncodeTypeAt`.
- Expressions and breakpoints: `DbgIsValidExpression`, `DbgGetBpxTypeAt`, `DbgIsBpDisabled`, `DbgGetBranchDestination`, `DbgIsJumpGoingToExecute`.
- Annotations: `DbgStackCommentGet`, `DbgGetTimeWastedCounter`.
- Scripting: `DbgScriptLoad`/`Run`/`Step`.
- Command execution: `DbgCmdExecDirect`.

**Script API (`Script::` namespaces), from https://github.com/x64dbg/x64dbg/tree/development/src/dbg (`_scriptapi_*.h`)**
- `Debug`: Run/Pause/Stop/StepIn/Over/Out/Wait, plus software and hardware breakpoints.
- `Memory`: Read/Write/RemoteAlloc/RemoteFree/Get/SetProtect/GetBase/GetSize.
- `Module`:
  - Lookups: InfoFromAddr/Name, EntryFromAddr.
  - Sections: SectionListFromAddr/Name.
  - Imports and exports: GetExports/GetImports.
  - Main module: GetMainModule*.
- `Pattern`: Find/FindMem/Write/WriteMem/SearchAndReplaceMem.
- `Assembler`: AssembleMem/AssembleMemEx(fillnop).
- `Misc`: ParseExpression, RemoteGetProcAddress, ResolveLabel.
- `Function`/`Argument`: Add/Get/GetList.
- `Label`/`Comment`: Set/Get/GetList.
- `Symbol`: GetList.
- `Stack`: Pop/Push/Peek.
- `Flag`: get and set ZF/CF/TF...
- `Register`: get and set every register, including DR0-DR7.
- `Gui`: selection, InputLine, Message.

**Plugin callbacks (PLUG: https://github.com/x64dbg/x64dbg/blob/development/src/dbg/_plugins.h)**
- Debug session and process: CB_INITDEBUG, CB_STOPDEBUG, CB_STOPPINGDEBUG, CB_CREATEPROCESS, CB_EXITPROCESS, CB_CREATETHREAD, CB_EXITTHREAD, CB_SYSTEMBREAKPOINT, CB_LOADDLL, CB_UNLOADDLL, **CB_OUTPUTDEBUGSTRING**, CB_EXCEPTION, CB_BREAKPOINT, CB_PAUSEDEBUG, CB_RESUMEDEBUG, CB_STEPPED, CB_ATTACH, CB_DETACH, **CB_DEBUGEVENT** (any raw debug event).
- GUI and database: CB_MENUENTRY, CB_WINEVENT, CB_LOADDB/CB_SAVEDB, CB_FILTERSYMBOL.
- Tracing: **CB_TRACEEXECUTE** (per traced instruction, can change the break decision), CB_STARTTRACE, CB_STOPTRACE.
- Analysis and expressions: CB_ANALYZE, CB_ADDRINFO, CB_VALFROMSTRING, CB_VALTOSTRING.
- Database operations: CB_DBOPERATION, CB_DBLOADOPERATION.
- The StartTrace and StopTrace plugin callbacks arrived in 2026.04.20 - [releases](https://github.com/x64dbg/x64dbg/releases)
- binary-mcp's plugin does **not** register CB_OUTPUTDEBUGSTRING, CB_DEBUGEVENT, CB_ATTACH/DETACH, CB_TRACEEXECUTE or CB_START/STOPTRACE. Source: grep of `src/engines/dynamic/x64dbg/plugin/plugin.cpp` in this repo.

### Inferences
- These functions are pure reads with no side effects: GetCallStack/ByThread, GetSEHChain, EnumHandles+GetHandleName, EnumTcpConnections, EnumWindows, EnumHeaps, PatchEnum, ModGetParty, ModRelocations*, GetPageRights, MemIsCodePage, IsDepEnabled, IsProcessElevated, GetCmdline, GetSourceFromAddr, GetTraceRecordHitCount, DbgGetPeb/TebAddress, DbgXrefGet, DbgAnalyzeFunction, DbgGetWatchList, DbgFunctionGet/LoopGet and StringFormatInline. They are high value and low risk.
- `GetProcessList` reveals what else runs on the analysis host. It is mild information disclosure, so whether to expose it is a policy choice.
- Functions that change state: `SetPageRights`, `MemPatch`, `PatchRestore*`, `ModSetParty`, `SetCmdline`, `AssembleAtEx`.
- `PatchFile` writes files. `SymbolDownloadAllSymbols` uses the network. `DbgSetDebuggeeInitScript` executes a script.
- `StringFormatInline` lets one MCP call evaluate rich templates, such as `{utf16@[esp+8]} {winerror@eax}`, without extra round trips.

### Gaps
- I did not verify the exact layout of `HANDLEINFO`, `TCPCONNECTIONINFO`, `WINDOW_INFO`, `HEAPINFO` or `DBGSEHCHAIN`. They are defined elsewhere in `_dbgfunctions.h` and `bridgemain.h`.
- No VEH enumeration API exists in DbgFunctions. `exhandlers` (already allowlisted) is the only built-in route to VEH/VCH/SEH/unhandled-filter listing, per CMDS.

## 3. Trace recording and the trace file format ("time travel")

### Takeaway
x64dbg can record a run trace to a `.trace32`/`.trace64` file with `StartRunTrace file` and stop it with `StopRunTrace`/`tc`. The tracing itself comes from `ticnd`/`tocnd` and similar commands. The file format is documented, so an MCP server could parse it offline for register and memory deltas per instruction. Trace coverage hit counts are also available live through `tr.hitcount()` and `GetTraceRecordHitCount`.

### Cited Findings
- `StartTraceRecording/StartRunTrace/opentrace file` starts recording and opens the trace view. A tracing command is still needed to produce instructions, and the extension is not added automatically. - [StartRunTrace.md](https://github.com/x64dbg/docs/blob/master/commands/tracing/StartRunTrace.md)
- The `.trace32`/`.trace64` file format:
  - The file opens with the magic `"TRAC"`, then a 4-byte length and a JSON header, then binary blocks. It is little-endian.
  - Block type 0 is one executed instruction. It holds a ThreadId (stored only when it changes), the opcode (up to 15 bytes), register changes as relative indices into `REGDUMP` with new values, and memory accesses with flags, address, old data and new data.
  - - [tracefile.md](https://github.com/x64dbg/docs/blob/master/developers/tracefile.md)
- Recent trace features:
  - 2025.08.19 added best-effort memory and stack reconstruction from traces, and searching for intermodular calls in traces.
  - 2026.04.20 added `TraceSetStepFilter`, user-defined blocks in trace, and StartTrace/StopTrace callbacks.
  - 2026.05.27 fixed a memory fault in the trace reader.
  - - [releases](https://github.com/x64dbg/x64dbg/releases)
- Trace coverage commands and functions: `tibt`/`tobt` (beyond coverage), `tiit`/`toit` (into coverage), `traceexecute`, `tr.hitcount`, `tr.isrecording`. - [CMDS](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/x64dbg.cpp), [Expression-functions.md](https://github.com/x64dbg/docs/blob/master/introduction/Expression-functions.md)
- `GetTraceRecordHitCount`, `GetTraceRecordByteType` and `Set/GetTraceRecordType` are in DbgFunctions. - [DBGF](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/_dbgfunctions.h)

### Inferences
- The best fit is a pair of tools, `trace_record_start(path in sandbox dir)` and `trace_record_stop`, plus a Python-side parser for the trace file. The parser would answer questions like "which instruction last wrote address X", "values of EAX across the loop" or "all memory writes into region R". This gives post-hoc "time travel" queries without re-running malware.
- Recording writes a file, which is why `tracesetlogfile` is blocked today. It is safe if the plugin chooses the path. Trace files grow quickly, so cap them by instruction count with a `ticnd` max-steps argument.

### Gaps
- I did not determine whether an API exists for reading back the trace that is currently open, as opposed to parsing the file.
- The JSON header fields are not fully listed in the excerpt I read.

## 4. Scylla, TitanEngine, anti-anti-debug and other OS-level features

### Takeaway
x64dbg starts Scylla only as a GUI through `StartScylla`, which calls `ScyllaStartGui`. `Scylla.dll`, however, exports headless functions for IAT search, IAT auto-fix, dumping and PE rebuild. A plugin could call them directly to unpack without the GUI. ScyllaHide is far more thorough than our PEB-only hiding.

### Cited Findings
- x64dbg's `StartScylla` runs `LoadLibraryW(L"Scylla.dll")` and calls the `ScyllaStartGui` export. - [cmd-plugins.cpp](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/commands/cmd-plugins.cpp)
- Scylla exports:
  - `ScyllaIatSearch(pid, &iatStart, &iatSize, searchStart, advancedSearch)`
  - `ScyllaIatFixAutoW(iatAddr, iatSize, pid, dumpFile, iatFixFile)`
  - `ScyllaDumpProcessW(pid, fileToDump, imagebase, entrypoint, fileResult)`
  - `ScyllaDumpCurrentProcessW`
  - `ScyllaRebuildFileW(file, removeDosStub, updateChecksum, createBackup)`
  - `ScyllaStartGui`, `ScyllaVersionInformation*`
  - - [FunctionExport.h](https://github.com/NtQuery/Scylla/blob/master/Scylla/FunctionExport.h)
- ScyllaHide is a user-mode anti-anti-debug library that hooks functions to hide the debugger. It ships an x64dbg plugin and an InjectorCLI, and points to TitanHide for ring 0. - [ScyllaHide README](https://github.com/x64dbg/ScyllaHide)
- ScyllaHide profile options:
  - PEB: `PebBeingDebugged`, `PebHeapFlags`, `PebNtGlobalFlag`, `PebStartupInfo`, `PebOsBuildNumber`.
  - Process, thread and object queries: `NtQueryInformationProcessHook`, `NtSetInformationThreadHook`, `NtQueryObjectHook`, `NtQuerySystemInformationHook`, `NtCloseHook`, `NtSetInformationProcessHook`.
  - Thread context and creation: `NtGet/SetContextThreadHook`, `NtContinueHook`, `NtCreateThreadExHook`, `KiUserExceptionDispatcherHook`.
  - Timing: `GetTickCount(64)Hook`, `GetLocal/SystemTimeHook`, `NtQuerySystemTime/PerformanceCounterHook`.
  - Window APIs: `NtUserFindWindowEx/BuildHwndList/QueryWindow/GetForegroundWindow/BlockInputHook`.
  - Debug output and filters: `OutputDebugStringHook`, `NtSetDebugFilterStateHook`.
  - Other: `NtYieldExecutionHook`, `KillAntiAttach`, `RemoveDebugPrivileges`, `PreventThreadCreation`.
  - Each profile is a named INI section, such as a "VMProtect x86/x64" profile.
  - - [scylla_hide.ini](https://github.com/x64dbg/ScyllaHide/blob/master/ConfigCollection/scylla_hide.ini)
- The x64dbg-automate plugin uses ZeroMQ request/reply plus pub/sub events with MessagePack. - [x64dbg-automate](https://github.com/dariushoule/x64dbg-automate)
- Its request set:
  - Debugger control and state: `DBG_CMD_EXEC_DIRECT`, `DBG_EVAL`, `DBG_IS_DEBUGGING`, `DBG_IS_RUNNING`, `DBG_IS_ELEVATED`, `DBG_GET_BITNESS`, `DEBUGGER_PID`, `DEBUGGER_VERSION`, `QUIT`.
  - Memory: `DBG_MEMMAP`, `DBG_READ/WRITE_MEMORY`, `DBG_IS_VALID_READ_PTR`.
  - Registers: `DBG_READ_REGISTERS`.
  - Code: `ASSEMBLE`, `DISASSEMBLE`.
  - Breakpoints and annotations: `GET_BREAKPOINTS`, `GET_COMMENT`, `GET_LABEL`, `GET_SYMBOL`.
  - Log, settings and GUI: `GET_LOG`, `DBG_READ/WRITE_SETTING_SZ/UINT`, `GUI_REFRESH_VIEWS`.
  - - [commands_xauto.py](https://github.com/dariushoule/x64dbg-automate-pyclient/blob/main/x64dbg_automate/commands_xauto.py)
- The 2025.08.19 release notes mention the Automate Python library and an MCP server built on it. The 2026.04.20 notes point to an MCP-based "x64dbg-skills" project built on Automate. - [releases](https://github.com/x64dbg/x64dbg/releases)

### Inferences
- binary-mcp exposes no reading of x64dbg's own log (`GET_LOG`), and none of the settings reads and writes that Automate has.
- TEB/PEB: the plugin can return `DbgGetTebAddress`/`DbgGetPebAddress` and then parse with `parsetypes`/`dt`, or read raw memory. `peb()`/`teb()` already work through `eval`. A dedicated "PEB summary" tool would be the higher-value option, covering BeingDebugged, NtGlobalFlag, ProcessHeap flags, the Ldr module list against the debugger module list for unlinked DLLs, and ProcessParameters.
- Unpacking tools: exposing Scylla headlessly (`iat_search`, `iat_fix_auto`, `dump_pe`) is high value for unpacking. Scylla.dll runs inside the debugger process and writes files, so pin the output paths. Loading `Scylla.dll`, which ships in x64dbg's own directory, is a controlled `LoadLibrary`. It is not user-supplied.
- Anti-anti-debug: binary-mcp's current anti-debug feature covers the PEB only, comparable to `HideDebugger`. A ScyllaHide profile selector, which reads and writes the INI and applies it on attach, would cover NtQueryInformationProcess, ThreadHideFromDebugger, timing, NtClose and window checks.

### Gaps
- I did not confirm a programmatic API in the ScyllaHide x64dbg plugin, such as commands or exports, beyond its INI and GUI.
- I did not confirm x64dbg's settings for child-process debugging or for breaking on OutputDebugString. Child processes are not auto-attached in my knowledge, but I found no citation.
- I did not research TitanHide, HyperHide, SharpOD, xAnalyzer or Multiline Ultimate Assembler beyond the TitanHide pointer in the ScyllaHide README. Their features are unverified.
- I did not investigate TitanEngine internals.

## 4b. Third-party plugins, OutputDebugString and child processes (follow-up pass)

### Takeaway
x64dbg captures OutputDebugString itself. It logs ASCII strings as `DebugString: "..."`, has no Unicode support yet, and hands every string to plugins through CB_OUTPUTDEBUGSTRING. A plugin can therefore capture ODS without the debugger pausing. Of the third-party plugins, xAnalyzer (API argument annotation) and the TitanHide/HyperHide kernel hiders are the most relevant. The kernel hiders need PatchGuard and DSE disabled, so they belong to lab setup rather than MCP tools.

### Cited Findings
- **OutputDebugString handling in the debugger.**
  - `cbOutputDebugString` first calls `plugincbcall(CB_OUTPUTDEBUGSTRING, ...)`.
  - It then reads ASCII strings from debuggee memory and logs them as `DebugString: "..."`. Duplicates are suppressed.
  - Unicode debug strings are marked `//TODO: implement Windows 10 unicode debug string`.
  - It pauses on a debug string only if the `Events/DebugStrings` setting is true. The default is false.
  - - [debugger.cpp](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/debugger.cpp)
- **TitanHide** is a kernel driver that hooks Nt* functions through SSDT hooks. Each hidden process gets a PID plus a set of hide options.
  - Hidden: ProcessDebugFlags, ProcessDebugPort, ProcessDebugObjectHandle, the DebugObject (NtQueryObject), SystemKernelDebuggerInformation and SystemDebugControl.
  - It also covers NtClose exceptions and ThreadHideFromDebugger, and protects DRx against reads and writes through Get/SetContextThread.
  - It requires PatchGuard and DSE to be disabled.
  - - [TitanHide README](https://github.com/mrexodia/TitanHide)
- **HyperHide** has a feature list of more than 30 items, among them:
  - PEB, heap flags, process and thread flags, KUserSharedData and KiExceptionDispatch.
  - Query APIs: NtQueryInformationProcess/Thread/JobObject, NtQueryObject, NtQuerySystemInformation, NtQuerySystemTime/PerformanceCounter.
  - Set and control APIs: NtSetInformationThread/Process, NtSystemDebugControl, NtClose, NtGet/SetContextThread.
  - Creation and open APIs: NtCreateThreadEx/ProcessEx/UserProcess/File, NtOpenProcess/Thread, NtGetNextProcess.
  - Other: NtContinue, NtYieldExecution, NtUserFindWindowEx/GetForegroundWindow.
  - - [HyperHide README](https://github.com/Air14/HyperHide)
- **xAnalyzer** extends function-call analysis using more than 13,000 API definitions from almost 200 DLLs. It recognises functions, arguments and data types, detects loops automatically, and uses user-maintained definition files. - [xAnalyzer README](https://github.com/ThunderCls/xAnalyzer)

### Inferences
- **ODS capture.** Registering CB_OUTPUTDEBUGSTRING in Obsidian and pushing the string into the existing debug-event queue would be cheap and safe. The handler must read Unicode strings itself, because x64dbg does not.
- **Annotation.** xAnalyzer's comments are written into the x64dbg database, so the existing `labels/comments` tools already read them back. The only new piece an MCP needs is "run xAnalyzer on module", which is a plugin command and therefore falls under the plugin-loading block. An optional allowlisted plugin command is the cleanest route.
- **Kernel hiders.** TitanHide and HyperHide should be documented as lab prerequisites. They should not be MCP-controlled.

### Gaps
- **Child processes.** I found no child-process auto-attach option in `debugger.cpp`, and a grep for "Child" gave no hits. x64dbg appears to debug only the launched process. A child must be handled by attaching after a CB_CREATEPROCESS-style notification or by pausing on CreateProcess. This is not confirmed by documentation.
- **Other plugins.** I did not verify the feature lists of SharpOD, Multiline Ultimate Assembler or x64dbgpy within this budget.
- **Scope of the TitanHide note.** The README says "Windows 10" as its newest tested OS. I did not check Windows 11 support.

## 5. Not yet exposed by binary-mcp: ranked candidates

### Takeaway
The best additions are read-only DbgFunctions wrappers plus non-breaking conditional/log breakpoints. Together they cover the main gaps in the stack-and-exception, OS-object, patch and API-tracing views.

### Cited Findings
Ranked by value to malware analysis against risk.

1. **Call stack per thread and SEH chain.** Source: `GetCallStackByThread`, `GetSEHChain` ([DBGF](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/_dbgfunctions.h)). Read-only. It gives "who called this API" and SEH-based anti-debug and control-flow tricks.
2. **Logging/conditional breakpoints with fast resume.** Source: `bpcond`/`bplog`/`bplogcondition`/`SetBreakpointFastResume`/`Silent`/`Singleshoot`/hit counts for all five breakpoint kinds ([CMDS](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/x64dbg.cpp)), or the typed `BpSetFieldText`/`BpGetFieldNumber`. The semantics are in [ConditionalBreakpoint.md](https://github.com/x64dbg/docs/blob/master/introduction/ConditionalBreakpoint.md) and [Formatting.md](https://github.com/x64dbg/docs/blob/master/introduction/Formatting.md). This enables in-debugger API monitors such as `{utf16@[esp+4]}` and `{winerror@eax}`. Block or validate `bpcommand` and `SetBreakpointLogFile`.
3. **Handles, with names and types.** Source: `EnumHandles` and `GetHandleName` ([DBGF](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/_dbgfunctions.h)). Read-only. It shows mutexes, files, registry keys and sections. Keep `handleclose` out.
4. **OutputDebugString and raw debug-event capture.** Source: CB_OUTPUTDEBUGSTRING and CB_DEBUGEVENT, which binary-mcp does not register ([PLUG](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/_plugins.h)). Read-only. Malware often uses ODS for anti-debug or leaks debug strings through it. The x64dbg core does not decode Unicode ODS ([debugger.cpp](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/debugger.cpp)), so the plugin should read the string itself.
5. **Patch list and patched-file export.** Source: `PatchEnum`, `PatchGetEx`, `PatchRestore`, `PatchFile` ([DBGF](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/_dbgfunctions.h)). Reads are safe. `PatchFile` writes a file, so pin its path.
6. **Trace recording and trace-file query.** Source: `StartRunTrace`/`StopRunTrace`, plus a parser for the format in [tracefile.md](https://github.com/x64dbg/docs/blob/master/developers/tracefile.md). It needs a pinned path and a size cap.
7. **Headless Scylla.** Source: `ScyllaIatSearch`, `ScyllaIatFixAutoW`, `ScyllaDumpProcessW`, `ScyllaRebuildFileW` ([FunctionExport.h](https://github.com/NtQuery/Scylla/blob/master/Scylla/FunctionExport.h)). Used for unpacking. It writes files and loads a bundled DLL into the debugger.
8. **TCP connections and windows.** Source: `EnumTcpConnections`, `EnumWindows` ([DBGF](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/_dbgfunctions.h)). Read-only. Shows C2 sockets and hidden windows.
9. **Heaps, page rights, DEP, code pages and module party.** Source: `EnumHeaps`, `GetPageRights`, `MemIsCodePage`, `IsDepEnabled`, `ModGetParty`, `ModRelocations*`, `IsProcessElevated`, `GetCmdline` ([DBGF](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/_dbgfunctions.h)). Read-only.
10. **TEB/PEB addresses, xrefs and the function CFG.** Source: `DbgGetTeb/PebAddress`, `DbgXrefGet`, `DbgAnalyzeFunction`, `DbgGetWatchList`, `DbgFunctionGet`/`DbgLoopGet` ([BRIDGE](https://github.com/x64dbg/x64dbg/blob/development/src/bridge/bridgemain.h)). Read-only.
11. **`StringFormatInline` / an `eval_format` tool.** Source: [DBGF](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/_dbgfunctions.h), [Formatting.md](https://github.com/x64dbg/docs/blob/master/introduction/Formatting.md). Read-only, with one-call rich formatting that includes `syscall.name()` and `ex.*` ([Expression-functions.md](https://github.com/x64dbg/docs/blob/master/introduction/Expression-functions.md)).
12. **Commands that are safe to allowlist.**
    - Read-only: `imageinfo`, `GetRelocSize`, `getpagerights`, `GetPrivilegeState`, `gpa`, `getcommandline`, `mnemonicbrief`, `printstack`, `reffunctionpointer`, `reffindrange`, `functionlist`, `argumentlist`, `looplist`, `commentlist`, `labellist`, `bookmarklist`.
    - Change debugger state but cannot launch or load code: `virtualmod`, `RunToParty`, `TraceSetStepFilter`, `skip`, `SetWatchdog`/`CheckWatchdog`, `symload` with a local path.
    - Network: `symdownload`.
    - Sources: [CMDS](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/x64dbg.cpp), [virtualmod.md](https://github.com/x64dbg/docs/blob/master/commands/analysis/virtualmod.md), [RunToParty.md](https://github.com/x64dbg/docs/blob/master/commands/tracing/RunToParty.md), [SetWatchdog.md](https://github.com/x64dbg/docs/blob/master/commands/watch-control/SetWatchdog.md)
13. **ScyllaHide profile control.** Source: [scylla_hide.ini](https://github.com/x64dbg/ScyllaHide/blob/master/ConfigCollection/scylla_hide.ini). It needs the ScyllaHide plugin installed, and it injects a hook DLL into the debuggee by design.
14. **x64dbg log retrieval and settings read.** These follow the model of Automate's `GET_LOG` and `READ_SETTING` ([commands_xauto.py](https://github.com/dariushoule/x64dbg-automate-pyclient/blob/main/x64dbg_automate/commands_xauto.py)). Exposing the log lets the LLM see `bplog` output and the output of the allowlisted commands.

Keep blocked, all from [CMDS](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/x64dbg.cpp) unless noted:
- Loads or runs code in the debugger: `loadlib`, `freelib`, `scriptdll` ([scriptdll.md](https://github.com/x64dbg/docs/blob/master/commands/script/scriptdll.md)), `scriptload`/`scriptrun`/`scriptcmd`/`scriptexec`, `plug*`.
- Runs code in the debuggee: `createthread` ([createthread.md](https://github.com/x64dbg/docs/blob/master/commands/thread-control/createthread.md)).
- Starts or restarts processes: `init`, `restartadmin`.
- Changes system or debugger configuration: `setjit`/`setjitauto`, `chd` ([chd.md](https://github.com/x64dbg/docs/blob/master/commands/misc/chd.md)), `settingset`/`config`.
- Writes files: `RedirectLog`/`SaveLog`, `dbsave` with a path, `Set*BreakpointLogFile`, `TraceSetLogFile`.
- Breakpoint and trace commands that run arbitrary commands: `Set*BreakpointCommand`, `TraceSetCommand`.
- Destructive to the debuggee: `handleclose`, `killthread`.
- GUI only: `StartScylla`.

### Inferences
- Items 1-4 and 8-11 need only a few `DbgFunctions()` calls in the Obsidian plugin, with no new risk surface, so they offer the best value for the effort.
- Item 2 offers the largest workflow gain for an LLM: it replaces many pause/inspect/resume round trips.

### Gaps
- I did not test whether each DbgFunctions member is present in the specific x64dbg snapshot binary-mcp targets. The struct grows over time, so a version check is advised.
