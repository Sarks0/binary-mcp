# Tool Reference

Every tool this server registers, grouped by engine.

Counts come from the tools actually registered by `src/server.py`, and
`tests/test_docs_accuracy.py` fails if this file and the code disagree.

Every tool also carries a machine-readable category and facets, exported as
FastMCP tags and checked in at [`tool-catalog.json`](tool-catalog.json)
(regenerate with `python -m src.tool_catalog`). Gate on the `code-output` facet
if you need to know which calls put decompiled code in front of the model.

## Capabilities (166 tools)

| Group | Tools |
|-------|-------|
| [Static Analysis (Ghidra)](#static-analysis-ghidra---20-tools) | 20 |
| [Python & Encoding Utilities](#python--encoding-utilities---7-tools) | 7 |
| [Sessions & Server Utilities](#sessions--server-utilities---15-tools) | 15 |
| [Dynamic Analysis (x64dbg)](#dynamic-analysis-x64dbg---16-tools) | 16 |
| [Kernel Debugging (WinDbg)](#kernel-debugging-windbg---33-tools) | 33 |
| [.NET Analysis (ILSpyCmd)](#net-analysis-ilspycmd---7-tools) | 7 |
| [PE Structure (pefile)](#pe-structure-pefile---4-tools) | 4 |
| [Other](#other---45-tools) | 45 |

### Static Analysis (Ghidra) - 20 tools

Analysis, decompilation (single and batch), cross-references, memory maps, byte
pattern search, function renaming, call graphs, API pattern detection (100+
Windows APIs), crypto constant identification, IOC extraction, PDB loading, and
binary compatibility checking.

On large binaries, see [Project reuse and targeted
decompiles](large-binary-decompile.md).

### Python & Encoding Utilities - 7 tools

Python bytecode (`.pyc`) analysis, PyInstaller and py2exe packer detection and
extraction, packed-archive listing, XOR key recovery and decryption, and Base64
file decoding.

### Sessions & Server Utilities - 15 tools

Persistent analysis sessions (create, save, load, list, delete, summarise,
relate), analyst notes, auto-session configuration, cache cleanup, and a setup
diagnostic.

### Dynamic Analysis (x64dbg) - 16 tools

Sixteen grouped operations, each covering a family of x64dbg commands. See
[x64dbg architecture](x64dbg-architecture.md) for how the bridge and plugin fit
together, and [x64dbg error logging](x64dbg-error-logging.md) for diagnostics.

| Area | What it does |
|------|--------------|
| Execution control | Run, pause, step into/over/out, run to user code, instruction undo |
| Breakpoints | Software, hardware, memory, DLL load, exception, and conditional breakpoints with logging |
| Tracing | Conditional tracing (ticnd/tocnd), trace recording, OEP finder for packed binaries |
| Memory | Read, write, dump, allocate, protect, pattern scan, string search, memory watch with diff |
| Registers & stack | Read/write registers, stack trace with raw fallback, expression evaluation |
| Analysis | Control flow analysis, cross-references, function boundaries, disassembly with capstone fallback |
| Type system | Define structs/unions, overlay on memory (VisitType), parse C headers, enumerate types |
| Search | Find assembly patterns, GUIDs, module calls, string references, reference ranges |
| Anti-debug | Detect and bypass anti-debug techniques (PEB, NtGlobalFlag, heap flags) |
| Watch & logging | Watch expressions with watchdog triggers, API call logging, breakpoint hit logging |
| Annotations | Comments, labels, bookmarks, function boundaries, variables |
| Thread control | Switch, suspend, resume threads individually or all at once |
| Process | Attach/detach, minidump creation, module listing with exports |
| Navigation | Navigate disassembly, dump and graph views, generic command execution |

### Kernel Debugging (WinDbg) - 33 tools

Connection (KDNET, named pipe, serial, local kernel, crash dumps), execution
control, software/hardware/conditional breakpoints, register, memory and thread
inspection, structure display (`dt`), disassembly, module and process listing,
symbol path management, and raw WinDbg command execution.

Windows only; every tool returns a platform message elsewhere. See the [WinDbg
and kernel debugging guide](windbg-kernel-debugging.md).

### .NET Analysis (ILSpyCmd) - 7 tools

Type listing, C# decompilation, IL disassembly, type search, full assembly
decompilation, and a setup diagnostic.

### PE Structure (pefile) - 4 tools

PE header, section, import, export, resource, debug, TLS and Rich header
analysis in a single call at three detail levels (basic, standard, full), with
decoded characteristic flags, compiler attribution and malware indicators. Plus
Authenticode signature inspection, embedded-binary carving, and similarity
hashing.

### Other - 64 tools

| Area | Tools | What it covers |
|------|-------|----------------|
| Triage | 3 | File type detection, packer identification, entropy analysis |
| Malware analysis | 6 | Behavior detection, API call chains, dynamic API resolution, anti-analysis detection, stack-string recovery, IOC extraction with context |
| Control flow | 4 | CFG generation, cyclomatic complexity, loop detection, dead code |
| Function hashing | 5 | Cross-binary function matching, similarity scoring, inlined-clone detection, batch decompilation, completeness checks |
| Pseudocode review | 5 | Decompiler-output scanning, caller analysis, parameter sinks, switch tables, review packages |
| Review coverage | 6 | Per-binary review denominator, reachability scope, a deterministic unreviewed worklist, and a separate machine-examination axis so a diff run is recorded without counting as a review ([docs](coverage.md)) |
| Background jobs | 4 | Poll long-running analysis that outlives the MCP client timeout, with one Ghidra run per binary shared across server processes and orphan reaping ([docs](jobs.md)) |
| VirusTotal | 4 | Hash lookups, sandbox behavior reports, Intelligence search, API-key check. Read-only, see [Security model](security.md) |
| MalwareBazaar | 5 | Sample lookup by hash, corpus pivots (tag, family signature, file type, ClamAV signature, imphash, TLSH, telfhash, gimphash, icon dhash, YARA rule), recent uploads, Auth-Key check, and an opt-in sample download. Downloading is off unless `MB_ALLOW_DOWNLOAD=1`, see [Security model](security.md) |
| ThreatFox, URLhaus, YARAify | 9 | IOC-to-malware-family identification, malware distribution history for a URL/host/payload (including the payload hashes served from a host), and public YARA rule matching by hash or by rule name, imphash, TLSH, telfhash, gimphash, icon dhash or ClamAV signature. Shares one abuse.ch Auth-Key with MalwareBazaar |
| MITRE ATT&CK | 5 | Technique, threat-actor group and malware/tool lookups with alias resolution, plus keyword search across the matrix. No API key and no rate limit: the STIX bundle is fetched once from MITRE's public repository, distilled to a compact index, and served from disk thereafter, so these work offline |
| Reporting | 2 | Structured analysis reports, IOC export |
| YARA | 2 | Rule *generation* from session data or extracted strings. The server emits rule text; it does not compile or run rules, so no YARA library is required or installed |
| IOCTL dispatch | 1 | Recover driver IOCTL handlers |
| Binary diff | 1 | Cross-binary patch diffing |
| Indirect calls | 1 | Vtable enumeration |
| Function ID | 1 | Ghidra FID library-match reading |

## Supported Formats

| Format | Engine |
|--------|--------|
| PE (.exe, .dll, .sys) | Ghidra + x64dbg |
| .NET assembly | ILSpyCmd |
| ELF (Linux) | Ghidra |
| Mach-O (macOS) | Ghidra |
| Kernel drivers (.sys) | Ghidra + WinDbg |
| Crash dumps (.dmp) | WinDbg |
| Python bytecode (.pyc) | Built-in analyzer |

## Architecture

```
                    MCP Client (Claude Desktop / Claude Code)
                                    |
                            FastMCP Server (stdio)
                           /        |        \         \
                  Static Analysis  Dynamic    Kernel    .NET
                   /       \       Analysis  Debugging  Analysis
               Ghidra    Python   x64dbg     WinDbg/KD  ILSpyCmd
             (headless)  bytecode (HTTP)    (Pybag COM)
                                    |           |
                               C++ Plugin   DbgEng COM
                                    |           |
                              User Process  Kernel Target
```

## Adding a tool

Adding a tool means updating the counts on this page and `src/tool_catalog.py`.
The docs tests enforce both. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the
registration walkthrough.
