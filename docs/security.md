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
`BINARY_MCP_ENABLE_RAW_WINDBG=1`** in the server environment. Without it the
tool is not even listed, and it still refuses at call time if the variable is
cleared after startup. When enabled it
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

### Crash dumps are deliberately not confined

`windbg_open_dump` is the one path-taking tool that does not consult the
allow-list. A kernel or process dump lives wherever Windows wrote it, and
`C:\Windows\MEMORY.DMP` is this project's own worked example, so confining the
tool would refuse its documented workflow. It does check that the path exists
and names a file -- it used to answer "Opened crash dump" for a missing path or
a directory and enter dump-analysis mode against nothing -- and the reply names
the file rather than echoing the path back.

What that costs: a caller who can reach this server can have WinDbg open any
dump file the server's user can read, wherever it sits. No setting narrows
that; `BINARY_MCP_ALLOWED_DIRS` does not apply to this tool. If that is too
wide for your install, confine it outside the server -- run it as a user with
no read access to the dumps you want withheld.

## Symbol fetches leave the host

A first import of a PE may fetch its PDB from a symbol server, which discloses
the PDB name and GUID. This is controlled by `BINARY_MCP_AUTO_PDB`, which
defaults to `microsoft` (only binaries whose version info names Microsoft). Set
it to `never` for samples you do not want disclosed, or set
`BINARY_MCP_SYMBOL_OFFLINE=1` to serve only from the local cache.

## The HTTP transport

By default this server speaks `stdio`: the MCP client spawns it as a
subprocess and the transport is a pair of pipes. Nothing listens, so nothing on
the network can reach it, and the rest of this page was written for that shape.

`BINARY_MCP_TRANSPORT=http` changes that shape. The server becomes a listener,
and a client that reaches it can drive every tool in the roster: including
debuggee memory writes, register writes and breakpoints. Treat the bearer token
as equivalent to a debugger session on that host.

What the code enforces, pinned by `tests/test_remote_policy.py`:

- **Loopback by default.** `BINARY_MCP_HTTP_HOST` defaults to `127.0.0.1`.
- **A wildcard bind is always refused.** `0.0.0.0`, `::` and `*` are rejected
  outright, with or without the opt-in. "Reachable from every interface" must
  not be something you can arrive at by typo; name the interface instead.
- **A non-loopback bind needs three things, all of them.** The opt-in
  `BINARY_MCP_REMOTE_ALLOW`, a TLS certificate and key
  (`BINARY_MCP_REMOTE_TLS_CERT` / `_KEY`), and an explicitly set
  `BINARY_MCP_HTTP_TOKEN`. Missing any one is a refusal to start, naming the
  variable. The token is required rather than generated because a generated
  token changes on restart and would silently break the client on the other
  host.
- **A token is always required, loopback included**, because any local process
  can reach a loopback listener. On loopback it is generated and logged once
  per start if you do not set one.
- **`Host` and `Origin` are validated** against the bind address plus anything
  in `BINARY_MCP_HTTP_ALLOWED_HOSTS`. This is the DNS-rebinding control: a
  browser on any host that can resolve a name to this address would otherwise
  be able to drive the server through a page you never visited. There is
  deliberately no CORS support: an `Access-Control-Allow-Origin` header here
  would undo the check.
- **Optional client-address allowlist.** `BINARY_MCP_REMOTE_CLIENT_ALLOWLIST`
  takes addresses and CIDRs, checked before authentication, so a client outside
  it never gets to present a credential.
- **Optional mutual TLS.** Setting `BINARY_MCP_REMOTE_TLS_CA` requires a client
  certificate that CA signed, enforced at the TLS layer. This is the control
  worth having on a LAN listener: a stolen token alone is then not enough.

What it does *not* do: there is no rate limiting, no audit log of refused
requests beyond the server log, and no revocation short of restarting with a
new token. The transport also trusts the peer address the socket reports, so
it must not be placed behind a reverse proxy without re-thinking the
allowlist: `X-Forwarded-For` is not consulted.

Path confinement matters *more* in this mode, not less: the server now shares a
filesystem with the sample it is analysing. See
[file access](#file-access-is-confined-by-default) and set
`BINARY_MCP_ALLOWED_DIRS` deliberately.

See [Remote access](remote-access.md) for the setup, and
[Configuration](configuration.md#transport) for every key.

## Reaching x64dbg on another host

The section above is about who may drive this server. This one is about what
this server may drive.

The bridge dials the Obsidian plugin's HTTP API, which grants the same powers
from the other end: memory read and write, registers, breakpoints, threads. The
policy mirrors the listener's, and is enforced in the same module:

- **Loopback by default**, and a loopback endpoint needs no opt-in. This is
  what a tunnel looks like from here, which is why the recommended remote setup
  requires no configuration beyond a token.
- **A non-loopback host needs three things, all of them.**
  `BINARY_MCP_REMOTE_ALLOW`, a CA in `X64DBG_TLS_CA`, and an explicit
  `OBSIDIAN_AUTH_TOKEN`. Missing any one is a refusal to connect, naming the
  variable.
- **There is no plaintext remote path.** The CA is what selects `https`, so a
  non-loopback endpoint is always TLS. `verify` is set to that CA rather than
  `True`: the plugin's certificate is one an analyst issued for a lab host, so
  checking it against the system trust store would be checking the wrong thing.
- **`0.0.0.0` and `::` are refused** as a destination. They mean "every
  interface" to a listener and nothing at all to a client.
- **Optional mutual TLS** via `X64DBG_TLS_CLIENT_CERT` / `_KEY`.
- **The plugin's token file is only read for a loopback endpoint.** It lives in
  `%TEMP%` on the host x64dbg runs on, so for a remote endpoint this machine's
  copy is a different file: reading it would authenticate with the wrong
  token.

Note that `BINARY_MCP_REMOTE_TLS_CA` and `X64DBG_TLS_CA` are deliberately
different variables. The first is the CA whose client certificates this
server's listener accepts; the second is the CA that signs the debugger host's
certificate. Sharing one would make a CA trusted to issue client credentials
also trusted to impersonate the debugger.

### The plugin's own listener

`obsidian_server.exe` enforces the mirror of that policy on its own side,
configured by an `obsidian.ini` beside the plugin. With no ini it binds
`127.0.0.1:8765` in plaintext, exactly as it always has.

- **A wildcard bind is refused outright** (`0.0.0.0`, `::`, `*`) with or
  without TLS.
- **A non-loopback bind requires a server certificate**
  (`tls_cert_thumbprint`), named by SHA-1 thumbprint from a Windows
  certificate store. TLS 1.2 with `SCH_USE_STRONG_CRYPTO`, via Schannel, so the
  binary gains no new runtime dependency.
- **An address the policy cannot classify is refused** rather than passed to
  the OS. `inet_addr` accepts forms the policy does not (`0` is `0.0.0.0`,
  `127.1` is loopback, `0177.0.0.1` is octal), and a classifier that disagrees
  with the thing that performs the bind is one that can be walked past. Both
  now read the same parser.
- **`Host` and `Origin` are validated** against the bind address plus
  `allow_hosts`, before the token is compared. The
  `Access-Control-Allow-Origin: *` header that used to be on every response;
  including the 401: is gone; there is no browser client, so it granted
  nothing legitimate. `OPTIONS` is no longer exempt from authentication,
  because there is no preflight left to serve.
- **An optional client allowlist** (`allow_clients`, addresses or CIDRs) is
  checked at `accept()`: before the TLS handshake, before any HTTP is parsed,
  and before the token is compared.
- **Optional mutual TLS** (`tls_client_ca_thumbprint`). Both halves of this
  are enforced after the handshake, not by it: with `ASC_REQ_MUTUAL_AUTH` set,
  Schannel asks for a certificate but still completes the handshake when the
  client answers with an empty list. The server then requires that a
  certificate was presented *and* that its chain reaches *that* CA: the
  thumbprint pinned in `obsidian.ini`, not anything in the machine's trust
  stores.
- **A malformed `obsidian.ini` is refused whole.** Any value containing a
  character its flag cannot legitimately hold fails the file, rather than one
  setting being quietly dropped: a listener configured differently from how it
  was written is worse than one that does not start.

The decisions above live in `src/engines/dynamic/x64dbg/server/listener_policy.h`,
which is deliberately free of Windows headers so that
`tests/test_cpp_listener_policy.py` can compile and run them. The TLS plumbing
around them (`schannel_tls.h`) can only be compiled, which the `build-plugin`
job in `.github/workflows/ci.yml` does for both architectures with
warnings-as-errors on every pull request.

Two things it does not do: there is no keep-alive (every request is one
connection), and TLS 1.3 is not negotiated: that needs an SSPI credential
structure this code does not use. A TLS terminator in front of a loopback
listener remains supported and is the way to get either.

See [Remote access](remote-access.md#option-2-direct-with-the-plugins-own-tls-listener)
for the setup.

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
| `BINARY_MCP_TRANSPORT` | `stdio` (default, no listener) or `http` |
| `BINARY_MCP_REMOTE_ALLOW` | Required before the HTTP transport may bind off loopback |
| `X64DBG_TLS_CA` | CA verifying the debugger host's certificate. Required for a non-loopback x64dbg endpoint |

## Installer integrity

The installers download Ghidra, x64dbg and the Windows debuggers, and
`install.ps1` runs elevated. No `| iex` or `| python3 -` one-liner is offered
on purpose. See [Supply-Chain
Integrity](../INSTALL.md#supply-chain-integrity) for what the installers verify
and how to pin a digest.

## Reporting a vulnerability

See the security section of [CONTRIBUTING.md](../CONTRIBUTING.md#security). Do
not open a public issue for a vulnerability.
