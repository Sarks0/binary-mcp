# Binary MCP Server

An MCP server for reverse engineering. It hands an AI assistant 147 tools for
static analysis, live user-mode debugging, kernel debugging and .NET
decompilation, so the whole workflow happens in the chat window instead of
across four separate GUIs.

| Engine | What it covers | Platform |
|--------|----------------|----------|
| Ghidra (headless) | Analysis, decompilation, xrefs, call graphs, pattern search | Linux, macOS, Windows |
| x64dbg | Live user-mode debugging through a C++ plugin and HTTP bridge | Windows |
| WinDbg / KD | Kernel debugging and crash dumps through Pybag and DbgEng COM | Windows |
| ILSpyCmd | .NET assemblies to C# and IL | Linux, macOS, Windows |
| pefile and built-ins | PE structure, triage, carving, Authenticode, hashing | Linux, macOS, Windows |

## Requirements

- **Python 3.12+** and [uv](https://docs.astral.sh/uv/)
- **Java 21+** for Ghidra (the installer can fetch Ghidra itself)
- **.NET 8 runtime** for ILSpyCmd, only if you want .NET decompilation
- **Windows** for the two debuggers. Static analysis, triage and .NET work
  everywhere; every WinDbg and x64dbg tool returns a platform message on
  Linux and macOS rather than failing obscurely.

**Ghidra 12.1+:** Jython is no longer bundled and analysis needs it. Install it
once from the Ghidra Front End (**File -> Install Extensions -> Jython**), then
restart Ghidra. Ghidra 12.0.x and earlier need no extra setup.

## Quick Start

### Install

Clone, or download the installer and read it before running it. The installers
pull down Ghidra, x64dbg, the Windows debuggers and this project's own x64dbg
plugins, and `install.ps1` requires Administrator.

```bash
# Recommended: clone, then run the installer from the checkout
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp
python3 install.py          # Windows: .\install.ps1  (as Administrator)

# Or just the dependencies, no installer
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp && uv sync
```

Without git, download and inspect first:

```bash
# Linux / macOS
curl -fsSLO https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.py
sha256sum install.py
less install.py
python3 install.py
```

```powershell
# Windows (as Administrator)
Invoke-WebRequest -Uri https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.ps1 -OutFile install.ps1
Get-FileHash .\install.ps1 -Algorithm SHA256
notepad .\install.ps1
.\install.ps1
```

> **No `| iex` or `| python3 -` one-liner is offered on purpose.** Piping a
> fresh download into an interpreter runs whatever the network returned, with
> no copy on disk to inspect, nothing to compare a digest against, and no
> record of what ran. On Windows it runs elevated. The extra command above is
> the whole difference. See
> [INSTALL.md](INSTALL.md#supply-chain-integrity) for what the installers
> verify and how to pin a digest.

### Connect

```bash
claude mcp add binary-analysis -- uv --directory /path/to/binary-mcp run python -m src.server
```

Or add it to your MCP config by hand. Ready-made examples live in
[`config/`](config/) for both Claude Code and Claude Desktop:

```json
{
  "mcpServers": {
    "binary-analysis": {
      "command": "uv",
      "args": ["--directory", "/path/to/binary-mcp", "run", "python", "-m", "src.server"],
      "env": {"GHIDRA_HOME": "/path/to/ghidra"}
    }
  }
}
```

Ask the assistant to run `diagnose_setup` once it is connected. It reports
which engines it found, which are missing, and why.

## What You Can Do

**Static analysis.** Analyze any binary without running it.

```
Analyze the binary at /path/to/malware.exe
Decompile the function at 0x401000
Find all suspicious API calls and crypto constants
```

**Live debugging.** Drive x64dbg from the chat window.

```
Connect to x64dbg and set breakpoints on BCryptEncrypt
Trace execution until EAX contains a decrypted pointer
Find the OEP of this packed binary
```

**Kernel debugging.** Inspect drivers and crash dumps.

```
Connect to the kernel debugger on port 50000
Show the dispatch table for \\Driver\\MyDriver
Analyze the crash dump at C:\Windows\MEMORY.DMP
```

**.NET analysis.** Decompile managed assemblies.

```
Decompile the type MyNamespace.MyClass to C#
```

## Capabilities (147 tools)

Counts below come from the tools actually registered by `src/server.py`, and
`tests/test_docs_accuracy.py` fails if this file and the code disagree.

Every tool also carries a machine-readable category and facets, exported as
FastMCP tags and checked in at [`docs/tool-catalog.json`](docs/tool-catalog.json)
(regenerate with `python -m src.tool_catalog`). Gate on the `code-output` facet
if you need to know which calls put decompiled code in front of the model.

### Static Analysis (Ghidra) - 20 tools

Analysis, decompilation (single and batch), cross-references, memory maps, byte
pattern search, function renaming, call graphs, API pattern detection (100+
Windows APIs), crypto constant identification, IOC extraction, PDB loading, and
binary compatibility checking.

### Python & Encoding Utilities - 7 tools

Python bytecode (`.pyc`) analysis, PyInstaller and py2exe packer detection and
extraction, packed-archive listing, XOR key recovery and decryption, and Base64
file decoding.

### Sessions & Server Utilities - 15 tools

Persistent analysis sessions (create, save, load, list, delete, summarise,
relate), analyst notes, auto-session configuration, cache cleanup, and a setup
diagnostic.

### Dynamic Analysis (x64dbg) - 16 tools

| Category | What it does |
|----------|--------------|
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
symbol path management, and raw WinDbg command execution. Windows only.

### .NET Analysis (ILSpyCmd) - 7 tools

Type listing, C# decompilation, IL disassembly, type search, full assembly
decompilation, and a setup diagnostic.

### PE Structure (pefile) - 4 tools

PE header, section, import, export, resource, debug, TLS and Rich header
analysis in a single call at three detail levels (basic, standard, full), with
decoded characteristic flags, compiler attribution and malware indicators. Plus
Authenticode signature inspection, embedded-binary carving, and similarity
hashing.

### Other - 45 tools

| Area | Tools | What it covers |
|------|-------|----------------|
| Triage | 3 | File type detection, packer identification, entropy analysis |
| Malware analysis | 6 | Behavior detection, API call chains, dynamic API resolution, anti-analysis detection, stack-string recovery, IOC extraction with context |
| Control flow | 4 | CFG generation, cyclomatic complexity, loop detection, dead code |
| Function hashing | 5 | Cross-binary function matching, similarity scoring, inlined-clone detection, batch decompilation, completeness checks |
| Pseudocode review | 5 | Decompiler-output scanning, caller analysis, parameter sinks, switch tables, review packages |
| Review coverage | 6 | Per-binary review denominator, reachability scope, a deterministic unreviewed worklist, and a separate machine-examination axis so a diff run is recorded without counting as a review ([docs](docs/coverage.md)) |
| Background jobs | 4 | Poll long-running analysis that outlives the MCP client timeout, with one Ghidra run per binary shared across server processes and orphan reaping ([docs](docs/jobs.md)) |
| VirusTotal | 4 | Hash lookups, sandbox behavior reports, Intelligence search, API-key check. Read-only, see [Operational safety](#operational-safety) |
| Reporting | 2 | Structured analysis reports, IOC export |
| YARA | 2 | Rule *generation* from session data or extracted strings. The server emits rule text; it does not compile or run rules, so no YARA library is required or installed |
| IOCTL dispatch | 1 | Recover driver IOCTL handlers |
| Binary diff | 1 | Cross-binary patch diffing |
| Indirect calls | 1 | Vtable enumeration |
| Function ID | 1 | Ghidra FID library-match reading |

## Operational Safety

This is a malware-analysis tool. Analyze samples in an isolated VM, on a host
you can revert. Some of that advice is enforced by the code, and it is worth
being precise about which parts.

**No tool can execute a sample.** Nothing in `src/tools/` starts a process from
a file on disk. The x64dbg bridge has a `load_binary()` method and the C++
plugin has a `LOAD_BINARY` handler, but no MCP tool calls either, so neither is
reachable from a client. `x64dbg_attach` attaches to a PID that is *already
running*: you decide what runs, and where.

**Raw debugger commands are filtered, not sandboxed.**
`x64dbg_execute_command` is gated by an allowlist at the tool layer and a
second, authoritative allowlist in the C++ plugin, which fails closed on any
command name it does not recognise. Every `;`-separated segment is validated
independently, at the HTTP chokepoint every bridge method posts through, so a
command chained after an allowed one cannot slip past on the strength of the
first token.

`windbg_execute_command` is **disabled unless the operator sets
`BINARY_MCP_ENABLE_RAW_WINDBG=1`** in the server environment. When enabled it
is gated by a fail-closed allowlist: a subcommand runs only if its command name
appears in a curated read-only inspection list, and anything unrecognised (a
new verb, an extension export, a misspelling) is refused. The gate splits
compound commands on every separator WinDbg honours, recurses into the quoted
and braced command-string arguments of the few carriers it permits, and refuses
a set of unsafe argument forms on commands that are otherwise allowed. Both
tools act on a live target with the debugger's full read access; see each
tool's docstring for the exact rules.

**Samples are never uploaded anywhere.** The VirusTotal integration performs
GET lookups only: hash reports, behavior summaries and Intelligence search.
There is no tool that sends a file, so nothing can leave your host through it,
deliberately or by accident. Sending a hash still tells VirusTotal you have the
sample; sending the file would tell everyone with VT Intelligence access.

**File access is confined by default.** Binary paths go through
`sanitize_binary_path` (`src/utils/security.py`), which checks a symlink's
target for containment before following it, and answers "denied" identically
whether or not the path exists so it cannot be used to probe the filesystem.
With `BINARY_MCP_ALLOWED_DIRS` unset, access defaults to a quarantine
allow-list: the system temp directory, this server's cache root
(`$BINARY_CACHE_DIR` or `~/ghidra_mcp_cache`), and `~/.binary_mcp_cache` or
`~/.cache/binary_mcp`. So `~/.ssh/id_rsa` and `/etc/shadow` are out of reach
without you saying so. Report and rule output is separately confined to
`~/.binary_mcp_output/`.

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

## Configuration

Settings come from the environment or from a `.env` file in the project root;
the environment wins. Copy [`.env.example`](.env.example) to `.env` to start.
The full list of keys and their descriptions lives in `CONFIG_KEYS` in
[`src/utils/config.py`](src/utils/config.py). The ones worth knowing:

| Variable | Description | Default |
|----------|-------------|---------|
| `GHIDRA_HOME` | Ghidra installation path | Auto-detected |
| `GHIDRA_TIMEOUT` | Analysis timeout in seconds (30-3600) | 1800 |
| `GHIDRA_MAX_HEAP_MB` | JVM max heap for the Ghidra subprocess, in MB. Raise to 6144-8192 for multi-MB binaries | 4096 |
| `X64DBG_BRIDGE_URL` | x64dbg HTTP bridge URL | `http://localhost:27042` |
| `WINDBG_PATH` | WinDbg/CDB installation path | Auto-detected |
| `WINDBG_TIMEOUT` | Timeout for a single WinDbg command, in seconds | 30 |
| `BINARY_CACHE_DIR` | Cache root for Ghidra projects and carved output | `~/ghidra_mcp_cache` |
| `BINARY_MCP_INLINE_DEADLINE` | Seconds a Ghidra-invoking tool blocks before handing back a job handle (max 900) | 25 |
| `BINARY_MCP_AUTO_PDB` | Fetch a PDB on first import: `microsoft`, `always` or `never`. A fetch discloses the PDB name and GUID to the symbol server | `microsoft` |
| `VT_API_KEY` | VirusTotal API key (lookups only) | Unset, VT tools report how to configure it |

Security-relevant keys:

| Variable | Description | Default |
|----------|-------------|---------|
| `BINARY_MCP_ALLOWED_DIRS` | Directories analysis is confined to, separated by `:` (POSIX) or `;` (Windows) | Unset, falls back to the quarantine directories under [Operational safety](#operational-safety) |
| `BINARY_MCP_REQUIRE_CONFINEMENT` | Fail closed: refuse to open any binary unless `BINARY_MCP_ALLOWED_DIRS` is set explicitly | Off |
| `BINARY_MCP_ALLOW_ANY_PATH` | Opt out of path confinement entirely. Not recommended: every file this process can read becomes reachable through the server. Warns once per process, and is ignored when `BINARY_MCP_REQUIRE_CONFINEMENT` is set | Off |
| `BINARY_MCP_ENABLE_RAW_WINDBG` | Enable `windbg_execute_command` behind its fail-closed allowlist | Off |
| `BINARY_MCP_SYMBOL_OFFLINE` | Serve symbols only from the local cache, never the upstream server | Off |
| `BINARY_MCP_ALLOW_HTTP_SYMBOLS` | Permit `http://` symbol servers. PDBs are MITM-sensitive | Off |

## Optional Dependencies

```bash
uv sync --extra windbg    # Pybag, for kernel debugging (Windows only)
uv sync --extra dev       # pytest, ruff
```

Fuzzy hashing (`ssdeep`, `python-tlsh`) wraps native libraries with packaging
quirks, so it is deliberately not a project extra. Install it yourself if you
want it:

```bash
pip install ssdeep python-tlsh    # may need: apt install libfuzzy-dev
```

`compute_similarity_hashes` detects their absence and notes it in the output.
Every other similarity hash works without them.

## Development

```bash
uv sync --extra dev        # Install with test and lint tooling
uv run pytest              # Run tests
uv run pytest --cov=src    # With coverage
uv run ruff check src/ tests/
uv run ruff format src/ tests/
```

`make help` lists the same commands plus cache cleanup and the Ghidra
diagnostic. `./quickstart.sh` runs the whole setup end to end: dependencies,
the sample in [`samples/`](samples/), diagnostics and tests.

The x64dbg C++ plugin is built separately, for both x64 and x32. See
[`src/engines/dynamic/x64dbg/plugin/README.md`](src/engines/dynamic/x64dbg/plugin/README.md).
CI compiles it on every pull request with warnings as errors.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the tool-registration walkthrough,
code style and the pattern-database format. Adding a tool means updating the
counts above and `src/tool_catalog.py`; the docs tests enforce both.

## Documentation

**Guides**

- [Installation](INSTALL.md), including supply-chain integrity and release verification
- [Claude Code integration](docs/claude-code-setup.md)
- [Large binaries: project reuse and targeted decompiles](docs/large-binary-decompile.md)
- [Background jobs](docs/jobs.md)
- [Review coverage](docs/coverage.md)
- [WinDbg and kernel debugging](docs/windbg-kernel-debugging.md)
- [x64dbg architecture](docs/x64dbg-architecture.md)
- [x64dbg error logging](docs/x64dbg-error-logging.md)

**Reference and notes**

- [Tool catalog](docs/tool-catalog.json), the machine-readable tool roster
- [Ghidra analysis of Defender binaries](docs/ghidra-mcp-defender-issues.md)
- [opencode known issues and workarounds](docs/opencode-issues.md)
- [Vulnerability-research workflow plans](docs/vr-workflow-enhancements.md)
- [Activity log and real-time tracing (proposed)](docs/activity-log-plan.md)
- [MCP protocol](https://modelcontextprotocol.io/)

## License

Apache 2.0. See [LICENSE](LICENSE).
