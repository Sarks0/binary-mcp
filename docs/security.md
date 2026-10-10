# Security Model

This is a malware-analysis tool. Analyze samples in an isolated VM, on a host
you can revert.

Some of that advice is enforced by the code, and it is worth being precise
about which parts.

Most of the claims below are pinned against the source by a test, so they
cannot quietly stop being true: the no-execution, never-uploaded,
confinement-default and symbol-policy claims by `tests/test_docs_accuracy.py`,
the command gates by `tests/test_windbg_gate_allowlist.py` and
`tests/test_x64dbg_command_gate.py`, and the installer claims by
`tests/test_installer_integrity.py`.

## No tool can execute a sample

Nothing in `src/tools/` starts a process from a file on disk. The x64dbg bridge
has a `load_binary()` method and the C++ plugin has a `LOAD_BINARY` handler, but
no MCP tool calls either, so neither is reachable from a client.
`x64dbg_attach` attaches to a PID that is *already running*: you decide what
runs, and where.

## Raw debugger commands are filtered, not sandboxed

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
a set of unsafe argument forms on commands that are otherwise allowed.

Both tools act on a live target with the debugger's full read access. See each
tool's docstring for the exact rules.

## Samples are never uploaded anywhere

The VirusTotal integration performs GET lookups only: hash reports, behavior
summaries and Intelligence search. There is no tool that sends a file, so
nothing can leave your host through it, deliberately or by accident.

Sending a hash still tells VirusTotal you have the sample; sending the file
would tell everyone with VT Intelligence access.

The abuse.ch integrations (MalwareBazaar, ThreatFox, URLhaus, YARAify) hold the
same property by a different mechanism, and the difference is worth stating
plainly: those APIs are POST-only, so unlike the VirusTotal tools these calls
do carry a request body. What goes in it is a hash, a tag, a family name or a
rule name, never file content. `mb_lookup(file_path=...)` hashes the file
locally and sends the digest alone. There is no `add_file` call anywhere in
the module, and `tests/test_mb_tools.py` plus `tests/test_integrations_base.py`
pin that every request body is assembled only from scalar fields, so sample
bytes have no path to the wire.

The MITRE ATT&CK tools send nothing at all about the sample: they fetch a
public dataset once and then answer from a local cache.

## Downloading a sample is off by default

`mb_download` is the one tool in this server that writes malware to disk. It
refuses unless the operator sets `MB_ALLOW_DOWNLOAD=1`; it writes only inside
`~/.binary_mcp_output/malwarebazaar/`, via `sanitize_output_path`; and it
stores abuse.ch's **encrypted** zip without ever extracting it, so nothing this
server does leaves a runnable copy on the host. The archive password is the
abuse.ch convention, `infected`. Extract it in your analysis VM, not on the
machine running this server.

## File access is confined by default

Binary paths go through `sanitize_binary_path` (`src/utils/security.py`), which
checks a symlink's target for containment before following it, and answers
"denied" identically whether or not the path exists so it cannot be used to
probe the filesystem.

With `BINARY_MCP_ALLOWED_DIRS` unset, access defaults to a quarantine
allow-list:

- the system temp directory
- this server's cache root (`$BINARY_CACHE_DIR` or `~/ghidra_mcp_cache`)
- `~/.binary_mcp_cache` or `~/.cache/binary_mcp`

So `~/.ssh/id_rsa` and `/etc/shadow` are out of reach without you saying so.
Report and rule output is separately confined to `~/.binary_mcp_output/`.

## Symbol fetches leave the host

A first import of a PE may fetch its PDB from a symbol server, which discloses
the PDB name and GUID. This is controlled by `BINARY_MCP_AUTO_PDB`, which
defaults to `microsoft` (only binaries whose version info names Microsoft). Set
it to `never` for samples you do not want disclosed, or set
`BINARY_MCP_SYMBOL_OFFLINE=1` to serve only from the local cache.

## Tightening the defaults

The keys below are documented in full in [Configuration](configuration.md).

| Variable | Effect |
|----------|--------|
| `BINARY_MCP_ALLOWED_DIRS` | Confine analysis to an explicit directory list |
| `BINARY_MCP_REQUIRE_CONFINEMENT` | Fail closed: refuse any binary unless `BINARY_MCP_ALLOWED_DIRS` is set |
| `BINARY_MCP_ALLOW_ANY_PATH` | Opt out of confinement entirely. Not recommended |
| `BINARY_MCP_ENABLE_RAW_WINDBG` | Enable `windbg_execute_command` behind its allowlist |
| `BINARY_MCP_SYMBOL_OFFLINE` | Never contact the upstream symbol server |
| `BINARY_MCP_AUTO_PDB` | Whether a first import fetches a PDB at all |

## Installer integrity

The installers download Ghidra, x64dbg and the Windows debuggers, and
`install.ps1` runs elevated. No `| iex` or `| python3 -` one-liner is offered
on purpose. See [Supply-Chain
Integrity](../INSTALL.md#supply-chain-integrity) for what the installers verify
and how to pin a digest.

## Reporting a vulnerability

See the security section of [CONTRIBUTING.md](../CONTRIBUTING.md#security). Do
not open a public issue for a vulnerability.
