# Documentation

## Start here

| Document | What it covers |
|----------|----------------|
| [Installation](../INSTALL.md) | Every install path, prerequisites, supply-chain integrity, release verification |
| [Tool reference](tools.md) | All 147 tools by engine, supported formats, architecture |
| [Configuration](configuration.md) | Environment variables, optional dependencies, Jython setup |
| [Security model](security.md) | What the code enforces, and what it does not |

## Guides

| Document | What it covers |
|----------|----------------|
| [Claude Code integration](claude-code-setup.md) | Wiring the server into Claude Code |
| [Remote setup](remote-setup.md) | Two ways to run across machines, with the exact settings for each |
| [Remote access reference](remote-access.md) | The long version: diagrams, every option, troubleshooting |
| [Large binaries](large-binary-decompile.md) | Project reuse and targeted decompiles for multi-MB binaries |
| [Background jobs](jobs.md) | Polling analysis that outlives the client timeout |
| [Review coverage](coverage.md) | The review denominator, worklist and examination axis |
| [WinDbg and kernel debugging](windbg-kernel-debugging.md) | Transports, kernel primitives, crash dumps |
| [x64dbg architecture](x64dbg-architecture.md) | Bridge, C++ plugin and pipe protocol |
| [x64dbg error logging](x64dbg-error-logging.md) | Diagnosing a bridge or plugin failure |

## Reference

| Document | What it covers |
|----------|----------------|
| [`tool-catalog.json`](tool-catalog.json) | Machine-readable tool roster, categories and facets |
| [x64dbg plugin build](../src/engines/dynamic/x64dbg/plugin/README.md) | Building the C++ plugin for x64 and x32 |

Regenerate the catalog with `python -m src.tool_catalog`.

## Notes and known issues

| Document | What it covers |
|----------|----------------|
| [Ghidra analysis of Defender binaries](ghidra-mcp-defender-issues.md) | Why `analyze_binary` fails or appears to fail on Defender PEs |
| [opencode issues](opencode-issues.md) | Two upstream opencode bugs and their workarounds |
| [Vulnerability-research workflow](vr-workflow-enhancements.md) | Planned improvements for triaging large binaries |
| [Activity log and tracing](activity-log-plan.md) | Proposed, not implemented |
| [Remote access plan](remote-access-plan.md) | The design behind [Remote access](remote-access.md), and the phases still outstanding (artifact transfer, WinDbg user-mode remoting) |
