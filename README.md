# Binary MCP Server

[![CI](https://github.com/sarks0/binary-mcp/workflows/CI/badge.svg)](https://github.com/sarks0/binary-mcp/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

An MCP server for reverse engineering. It hands an AI assistant 147 tools for
static analysis, live debugging, kernel debugging and .NET decompilation, so
the whole workflow happens in one place instead of across four GUIs.

| Engine | What it covers | Platform |
|--------|----------------|----------|
| Ghidra (headless) | Analysis, decompilation, xrefs, call graphs | Linux, macOS, Windows |
| x64dbg | Live user-mode debugging | Windows |
| WinDbg / KD | Kernel debugging and crash dumps | Windows |
| ILSpyCmd | .NET assemblies to C# and IL | Linux, macOS, Windows |
| pefile and built-ins | PE structure, triage, carving, hashing | Linux, macOS, Windows |

Requires Python 3.12+ and Java 21+ for Ghidra. Both debuggers are Windows only;
everything else runs anywhere.

## Architecture

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/architecture-dark.png">
    <img src="docs/images/architecture.png"
         alt="binary-mcp architecture: an AI assistant talks MCP over stdio to the binary-mcp server, which exposes 147 tools behind path and command guardrails, session, job and cache layers, and drives five engines -- Ghidra, ILSpyCmd, pefile built-ins, x64dbg and WinDbg -- while keeping state in a shared on-disk cache.">
  </picture>
</p>

The client speaks MCP over stdio, so each one gets its own server process. That
is why sessions, jobs and the Ghidra project cache are file-backed in a shared
directory rather than held in memory: two agents analyzing the same binary
attach to one analysis instead of starting two. Every engine runs as a
subprocess the server supervises, and the sample reaches them as bytes only --
nothing in the diagram executes it.

The drawing is editable: open
[`docs/images/architecture.excalidraw`](docs/images/architecture.excalidraw) at
[excalidraw.com](https://excalidraw.com) and re-export the two PNGs.

## Quick Start

```bash
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp
python3 install.py          # Windows: .\install.ps1  (as Administrator)
```

The installer fetches Ghidra, x64dbg and the Windows debuggers. For
dependencies only, run `uv sync` instead. To install without cloning, or to
check a download before you run it, see [INSTALL.md](INSTALL.md).

Then connect it:

```bash
claude mcp add binary-analysis -- uv --directory /path/to/binary-mcp run python -m src.server
```

Config-file examples for Claude Code and Claude Desktop are in
[`config/`](config/). Once connected, ask the assistant to run
`diagnose_setup`: it reports which engines it found and which are missing.

## Usage

Ask for what you want in plain language.

```
Analyze the binary at /path/to/malware.exe
Decompile the function at 0x401000 and find its callers
Connect to x64dbg and break on BCryptEncrypt
Find the OEP of this packed binary
Analyze the crash dump at C:\Windows\MEMORY.DMP
Decompile the type MyNamespace.MyClass to C#
```

## Safety

This is a malware-analysis tool. Analyze samples in an isolated VM, on a host
you can revert.

No tool can execute a sample, samples are never uploaded anywhere, file access
is confined to a quarantine allow-list by default, and raw debugger commands
are gated by fail-closed allowlists. The [security model](docs/security.md)
states each of those precisely and points at the code that enforces it.

## Documentation

- [Installation](INSTALL.md), including supply-chain integrity
- [Tool reference](docs/tools.md), all 147 tools by engine
- [Configuration](docs/configuration.md), environment variables and extras
- [Security model](docs/security.md)
- [All documentation](docs/), including guides for kernel debugging, large
  binaries, background jobs and review coverage

## Development

```bash
uv sync --extra dev
uv run pytest
uv run ruff check src/ tests/
```

`make help` lists the rest. See [CONTRIBUTING.md](CONTRIBUTING.md) to add a
tool.

## License

Apache 2.0. See [LICENSE](LICENSE).
