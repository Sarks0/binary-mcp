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

### Hard links are refused, and that is a different refusal

Containment is a prefix test on the resolved path, and `resolve()` follows
symlinks only. A hard link has no target to follow -- it *is* the inode, under
a second name -- so a link created inside an allowed directory, pointing at an
inode outside it, passes every check above and reads back the outside file.
There is no way to ask the kernel which other names an inode has, so while
confinement is active a regular file with `st_nlink > 1` is refused.

Two things bound the attack, and are worth knowing before you judge how much
the refusal is buying. Hard links cannot cross filesystems, so the target must
live on the same filesystem as the allowed directory -- an `os.link` from
`/etc` into a tmpfs `/tmp` fails with `EXDEV`. And `fs.protected_hardlinks=1`, which stops an
unprivileged user linking to a file they neither own nor can write, is set by
most distributions -- Debian, Ubuntu and Fedora among them -- though the
mainline kernel ships it as 0, so on a minimal or embedded image, or a host
whose `/etc/sysctl.d` has been trimmed, only the same-filesystem constraint
applies. Check `sysctl fs.protected_hardlinks` rather than assuming. What remains is a real
bypass with a narrower reach than "any file on the host": a same-filesystem
file the caller owns or can write, republished under an in-bounds name.

That costs some false positives: a corpus de-duplicated with links (`cp -l`,
`rsync --link-dest`, a content-addressed sample store) is refused even though
it is legitimate. `BINARY_MCP_ALLOW_HARDLINKS=1` re-permits multiply-linked
files and leaves directory confinement untouched -- deliberately a far smaller
hammer than `BINARY_MCP_ALLOW_ANY_PATH`. Nothing this server writes trips the
check; caches, carved output and dumps are all created with one link.
Directories are exempt, and that exemption is doing real work: **every**
directory has `st_nlink >= 2`, not just ones with subdirectories, so without
the regular-file check every directory reaching the test would be refused.

**The check does not run on Windows at all**, and the allow-list should be
treated as advisory there: `mklink /H` is the equivalent of the construction
above, and nothing refuses it. The skip is a deliberate choice not to rely on
`st_nlink` on a platform where this project has not measured what CPython
reports for a file with multiple NTFS links -- but an unmeasured platform
difference is a reason to state the gap, not a reason to call the gap safe. If
you run this server on Windows and the allow-list is load-bearing for you,
confine it at the filesystem instead.

The two refusals report separately. A hard-link refusal raises `HardLinkError`
-- a `PathTraversalError` subclass, so existing handlers still catch it -- and
says the link count was the problem and that widening
`BINARY_MCP_ALLOWED_DIRS` will not help. An out-of-bounds path says the path is
outside the allow-list. They used to be the same sentence, which sent operators
to re-check an allow-list that had already accepted the directory.

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
| `BINARY_MCP_ALLOW_HARDLINKS` | Permit multiply-linked files. Keeps directory confinement in force |
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
