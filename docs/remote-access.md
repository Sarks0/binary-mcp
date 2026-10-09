# Remote access

Running the MCP client on one host and the analysis tooling on another. The
usual reason: the debugger and the sample belong in a disposable VM, and the
client does not.

Two arrangements are possible, and both work end to end. The one thing still
outstanding is fetching plugin-written artifacts (minidumps, coverage exports)
back from the debugger host; see [the remote access
plan](remote-access-plan.md).

| | What crosses the network | Status |
|---|---|---|
| **Remote MCP server** | The MCP protocol itself. The whole server, Ghidra and x64dbg all live on the debugger host | Implemented |
| **Remote x64dbg bridge** | Only the x64dbg HTTP hop. The server and Ghidra stay with the client | Implemented, with TLS in the plugin's own listener — see [below](#remote-x64dbg) |

Throughout: **Host A** is where the MCP client runs, **Host B** is where
x64dbg, the sample and (for the first arrangement) this server run.

---

## Remote MCP server

```
  HOST A  analyst workstation          HOST B  debugger VM
  ┌─────────────────────────┐          ┌──────────────────────────────┐
  │  MCP client             │          │  binary-mcp  (Python)        │
  │  Claude Code / Desktop  │          │  FastMCP  transport=http     │
  │                         │          │  ┌────────────────────────┐  │
  │                         │ MCP/TLS  │  │ RemoteAccessGate (ASGI)│  │
  │              ───────────┼─────────▶│  └───────────┬────────────┘  │
  │                         │  :8770   │              ▼               │
  │                         │  /mcp    │        tool dispatch         │
  └─────────────────────────┘          │         │           │        │
                                       │         ▼           ▼        │
                                       │      Ghidra    X64DbgBridge  │
                                       │      + cache        │        │
                                       │                     ▼ 8765   │
                                       │  x64dbg + obsidian.dp64      │
                                       │  + the sample + all dumps    │
                                       └──────────────────────────────┘
```

Everything the server touches — the sample, the Ghidra cache, memory dumps,
trace logs — is on one filesystem, so no artifact ends up on the wrong host.
The bridge hop inside Host B stays on loopback, so none of the x64dbg-side
remote configuration applies. Cost: Ghidra runs inside the malware VM.

### Option 1: over an SSH tunnel (recommended)

The server keeps its default loopback bind and SSH carries the traffic. SSH
provides the encryption and the host authentication, so no certificates are
needed and no opt-in is required.

**On Host B**, start the server:

```bash
BINARY_MCP_TRANSPORT=http \
BINARY_MCP_HTTP_TOKEN=$(openssl rand -hex 32) \
uv run python -m src.server
```

Keep the token you generated — you need it on Host A. (Leave
`BINARY_MCP_HTTP_TOKEN` unset and the server mints one and logs it at startup,
but it changes on every restart.)

**On Host A**, forward the port and register the server:

```bash
ssh -N -L 8770:127.0.0.1:8770 analyst@host-b &

claude mcp add --transport http binary-mcp http://127.0.0.1:8770/mcp \
  --header "Authorization: Bearer <the token>"
```

The `Host` header a client sends for `127.0.0.1:8770` is accepted, because a
loopback bind accepts `localhost`, `127.0.0.1` and `::1`.

### Option 2: directly on the LAN, with TLS

Use this when a tunnel is impractical. The server refuses to bind a
non-loopback address unless all three of the following are set, and refuses a
wildcard address (`0.0.0.0`, `::`, `*`) under any configuration — name the
interface.

```bash
BINARY_MCP_TRANSPORT=http \
BINARY_MCP_HTTP_HOST=192.168.1.50 \
BINARY_MCP_REMOTE_ALLOW=1 \
BINARY_MCP_REMOTE_TLS_CERT=/etc/binary-mcp/server.crt \
BINARY_MCP_REMOTE_TLS_KEY=/etc/binary-mcp/server.key \
BINARY_MCP_HTTP_TOKEN=<64 hex characters> \
BINARY_MCP_REMOTE_CLIENT_ALLOWLIST=192.168.1.10 \
uv run python -m src.server
```

On Host A:

```bash
claude mcp add --transport http binary-mcp https://192.168.1.50:8770/mcp \
  --header "Authorization: Bearer <the token>"
```

If clients dial a DNS name rather than the address, add it to
`BINARY_MCP_HTTP_ALLOWED_HOSTS` — otherwise the request is refused as a
possible rebinding attempt:

```bash
BINARY_MCP_HTTP_ALLOWED_HOSTS=analysis.lan
```

**Add mutual TLS.** A bearer token is a single secret that travels with every
request. Requiring a client certificate as well means a captured token is not
enough on its own:

```bash
BINARY_MCP_REMOTE_TLS_CA=/etc/binary-mcp/clients-ca.pem
```

A client without a certificate that CA signed now fails the TLS handshake,
before the token is ever read.

### What the listener exposes

A client that authenticates can call every tool: decompile, dump memory, write
debuggee memory, set breakpoints, resume threads. Treat the token as equivalent
to a debugger session on Host B. [Security
model](security.md#the-http-transport) has the full list of what is and is not
enforced; [Configuration](configuration.md#transport) has every key.

Two things worth knowing before you expose it:

- The transport trusts the peer address the socket reports and does not consult
  `X-Forwarded-For`, so `BINARY_MCP_REMOTE_CLIENT_ALLOWLIST` is meaningless
  behind a reverse proxy.
- Path confinement matters more here, not less: the server now shares a
  filesystem with the sample. Set `BINARY_MCP_ALLOWED_DIRS` deliberately.

### Troubleshooting

| Symptom | Cause |
|---|---|
| `Refusing to start: BINARY_MCP_HTTP_HOST=...` | The policy refused the bind. The message names the variable to set; see [Configuration](configuration.md#transport) |
| `401` with `WWW-Authenticate: Bearer` | No token, a malformed `Authorization` header, or the wrong token |
| `400 {"error":"Host not allowed"}` | The client dialed a name the server does not answer for. Add it to `BINARY_MCP_HTTP_ALLOWED_HOSTS` |
| `400 {"error":"Origin not allowed"}` | A cross-origin request, usually a browser. Not served by design |
| `403 {"error":"Client address not permitted"}` | The peer is outside `BINARY_MCP_REMOTE_CLIENT_ALLOWLIST` |

Every refusal above is logged at WARNING with the client address and the
reason, so it is already visible at the default log level — there is no need to
raise `BINARY_MCP_LOG_LEVEL` to see why a request was turned away. Raise it to
`DEBUG` only for the successful path (which endpoint was resolved, where the
token came from).

---

## Remote x64dbg

The other arrangement — this server and Ghidra on Host A, only the x64dbg hop
crossing the network. Use it when the analysis brain should stay outside the
malware VM, or when Ghidra wants a bigger machine than the VM.

```
  HOST A  analyst workstation          HOST B  debugger VM
  ┌─────────────────────────┐          ┌──────────────────────────────┐
  │  MCP client             │          │  obsidian_server.exe         │
  │       │ stdio           │          │   listener_policy.h          │
  │       ▼                 │          │   + Schannel TLS 1.2         │
  │  binary-mcp (Python)    │  HTTPS   │        ▲                     │
  │   ├─ Ghidra + cache     │ ────────▶│        │ named pipe          │
  │   └─ X64DbgBridge ──────┼─ :8765   │        ▼ \\.\pipe\x64dbg_mcp │
  │        verify= $X64DBG_ │          │  x64dbg.exe                  │
  │                 TLS_CA  │          │   └─ obsidian.dp64           │
  │                         │          │       spawns the server,     │
  │  sample copy, dumps     │          │       reads obsidian.ini     │
  └─────────────────────────┘          └──────────────────────────────┘
```

The endpoint policy mirrors the listener's: loopback needs no opt-in, and a
non-loopback host needs `BINARY_MCP_REMOTE_ALLOW`, a CA and an explicit token,
all three. See [Security model](security.md#reaching-x64dbg-on-another-host).

### Option 1: over an SSH tunnel (recommended)

The plugin keeps its loopback bind and SSH carries the traffic. Nothing new
listens on the LAN, and no certificates are involved.

**On Host B**, with x64dbg running and the plugin loaded, read the token:

```powershell
Get-Content "$env:TEMP\x64dbg_mcp_token.txt"
```

**On Host A**, forward the port and point the server at the local end:

```bash
ssh -N -L 8765:127.0.0.1:8765 analyst@host-b &

export OBSIDIAN_AUTH_TOKEN=<the token from Host B>
export X64DBG_HOST=127.0.0.1
export X64DBG_PORT=8765
```

The bridge sees a loopback endpoint, so the policy asks for nothing else. The
token has to be set explicitly because the plugin's `%TEMP%` token file is on
Host B; the bridge reads that file only for a loopback endpoint, and here the
loopback end is a tunnel, not the plugin.

### Option 2: direct, with the plugin's own TLS listener

`obsidian_server.exe` serves TLS itself. The listener is configured by an
`obsidian.ini` beside the plugin; with no ini it binds `127.0.0.1:8765` in
plaintext exactly as it always has.

The policy it enforces (`server/listener_policy.h`, exercised by
`tests/test_cpp_listener_policy.py`) mirrors the Python side:

- a wildcard bind — `0.0.0.0`, `::`, `*` — is refused outright, with or without
  TLS;
- a non-loopback bind without `tls_cert_thumbprint` is refused;
- an address the policy cannot classify as a dotted quad is refused rather than
  handed to the OS;
- `Host` and `Origin` are validated against the bind address, so a browser that
  resolves a name to this machine cannot drive the debugger.

#### On Host B (where x64dbg runs)

**1. Make a certificate for the address Host A will dial.** No admin needed —
`CurrentUser\My` is the store the server process reads, because x64dbg spawns
it as that user.

```powershell
$cert = New-SelfSignedCertificate `
  -Type SSLServerAuthentication `
  -Subject "CN=192.168.1.50" `
  -TextExtension @("2.5.29.17={text}IPAddress=192.168.1.50") `
  -CertStoreLocation Cert:\CurrentUser\My `
  -NotAfter (Get-Date).AddYears(1)

$cert.Thumbprint
```

The `TextExtension` line is the subject alternative name. Without it the
certificate has no SAN for the address and Host A's verification fails — which
is the correct failure, but a confusing one to debug.

**2. Export the public certificate** so Host A has something to verify
against. It is self-signed, so the certificate *is* the CA:

```powershell
$pem = "-----BEGIN CERTIFICATE-----`n" +
       [Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks') +
       "`n-----END CERTIFICATE-----`n"
Set-Content -Path "$HOME\obsidian-debugger.pem" -Value $pem -Encoding ascii
```

`Set-Content` prints nothing on success, so "it did nothing" and "it worked"
look identical. Check it:

```powershell
Get-Content "$HOME\obsidian-debugger.pem"
```

`$cert` only exists in the session that ran step 1. In a new window, fetch the
certificate by thumbprint first and the export above works unchanged:

```powershell
$cert = Get-Item "Cert:\CurrentUser\My\<THUMBPRINT>"
```

Copy that file to Host A. It contains no private key. Worth confirming the SAN
survived before going further, because a missing one fails much later and the
error does not name it:

```bash
openssl x509 -in obsidian-debugger.pem -noout -subject -ext subjectAltName
```

**3. Write `obsidian.ini`** next to `obsidian.dp64` and
`obsidian_server.exe` — ASCII, no BOM, and no spaces around `=`:

```ini
[listener]
bind=192.168.1.50
port=8765
tls_cert_thumbprint=A1B2C3D4E5F60718293A4B5C6D7E8F9012345678
allow_clients=192.168.1.10
```

`allow_clients` takes addresses or CIDRs, comma-separated, and is checked at
`accept()` — before the TLS handshake, before any HTTP is parsed, and before
the token is compared. `allow_hosts` does the same for `Host` header values
when clients dial a DNS name. Any value containing a character a flag cannot
legitimately hold causes the whole file to be refused, rather than one setting
being quietly dropped.

A CIDR must be written as its network address: `10.0.0.0/24`, not
`10.0.0.5/24`. The second is refused rather than read as the first, because
someone writing a host address with a prefix means that host, and silently
admitting 254 more would be the wrong way to resolve the ambiguity — write
`10.0.0.5` on its own for a single client. The same rule applies to
`BINARY_MCP_REMOTE_CLIENT_ALLOWLIST` on the Python listener. An entry in
`allow_hosts` may carry a port or not (`analysis.lan` and
`analysis.lan:8765` behave identically); the port is stripped before
comparing, as it is on every incoming `Host`.

**4. Add a firewall rule, scoped to the client** — not to `Any`. This is the
one step that needs an elevated prompt.

Needed even on a network that is already open to this traffic: Windows
Defender Firewall is per-host and independent of any VLAN or switch policy, it
blocks unsolicited inbound by default on every profile, and
`obsidian_server.exe` is spawned without a window so it never gets the
first-run allow prompt a GUI application would. `Get-NetFirewallProfile |
Select-Object Name, Enabled` says whether it is on. The symptom when it blocks
is a timeout, which is also the symptom of a wrong `allow_clients` — so rule
this out first:

```powershell
New-NetFirewallRule -DisplayName "Obsidian x64dbg bridge" `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8765 `
  -RemoteAddress 192.168.1.10 -Profile Private
```

**5. Restart x64dbg.** The plugin logs the listener it spawned, so check the
log shows the address you expect:

```
[Obsidian] Listener options from obsidian.ini: --bind 192.168.1.50 ...
[Obsidian] NOTE: this listener is configured for 192.168.1.50 -- it may be
           reachable from the network.
```

If the server refuses its configuration it exits with code 2 and the plugin
says so; the reason is in `obsidian_server.log` beside the executable.

#### On Host A

Put these in a `.env` beside the server rather than exporting them. The server
searches upwards for one, so a file in the repository root is found without
any shell involvement — and a shell that loses its exports (a new terminal, a
restarted service) is otherwise indistinguishable from a broken endpoint:
`$X64DBG_TLS_CA` unset makes curl report `the file '' provided to --cacert
does not exist`, and an unset token gets you a 401.

```ini
BINARY_MCP_REMOTE_ALLOW=1
X64DBG_HOST=192.168.1.50
X64DBG_PORT=8765
X64DBG_TLS_CA=/path/to/obsidian-debugger.pem
OBSIDIAN_AUTH_TOKEN=<the token from Host B>
```

`chmod 600` it: that last line drives a debugger. Note that `os.environ` wins
over `.env`, so a stale value still exported in the shell you launch from
silently overrides the file.

Shell exports of the same five names work too, and are what `curl` needs since
it does not read `.env`:

```bash
set -a; . ./.env; set +a
```

**The token changes every time x64dbg restarts.** The plugin generates one on
load and deletes the file on unload, so every restart of the debugger means
re-reading `%TEMP%\x64dbg_mcp_token.txt` and updating that line. This is the
single most common reason a working setup starts answering 401.

#### Adding mutual TLS

A bearer token is a single secret that travels with every request. Requiring a
client certificate as well means a captured token is not enough on its own.

On Host B, make a CA and a client certificate, then hand the client certificate
to Host A:

```powershell
$ca = New-SelfSignedCertificate -Type Custom -KeyUsage CertSign `
  -Subject "CN=obsidian-client-ca" `
  -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(1)

$client = New-SelfSignedCertificate -Type Custom -Signer $ca `
  -Subject "CN=analyst-workstation" `
  -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") `
  -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(1)

$ca.Thumbprint     # goes in obsidian.ini
Export-PfxCertificate -Cert $client -FilePath "$HOME\analyst.pfx" `
  -Password (Read-Host -AsSecureString "PFX password")
```

**Import the CA into a trust store.** This step is easy to miss and nothing
works without it: the server validates the client's chain in full before
applying the thumbprint pin, so a CA that sits only in `My` produces
`CERT_TRUST_IS_UNTRUSTED_ROOT` and every client is refused.

```powershell
$store = Get-Item Cert:\CurrentUser\Root
$store.Open('ReadWrite'); $store.Add($ca); $store.Close()
```

`CurrentUser\Root`, not `LocalMachine\Root`: that scopes the trust to the one
account x64dbg runs as, on a VM you revert. It is still real trust — that CA
can now vouch for any host to that account — which is the cost of pinning on
top of chain validation rather than instead of it. If that trade is wrong for
your setup, use the SSH tunnel instead and skip certificates entirely.

Add the CA thumbprint to the ini:

```ini
tls_client_ca_thumbprint=0011223344556677889900AABBCCDDEEFF001122
```

Schannel then fails the handshake for a client without a certificate, and the
server additionally checks two things the chain alone does not: that the
certificate is valid **for client authentication** (a server certificate from
the same CA is refused), and that the pinned CA appears in its chain — so a
different CA in the same trust store cannot vouch for a client here.

On Host A, split the PFX into a PEM certificate and key (`openssl pkcs12
-in analyst.pfx -clcerts -nokeys -out analyst.crt` and `openssl pkcs12 -in
analyst.pfx -nocerts -nodes -out analyst.key`), then:

```bash
export X64DBG_TLS_CLIENT_CERT=/path/to/analyst.crt
export X64DBG_TLS_CLIENT_KEY=/path/to/analyst.key
```

#### Still works: a TLS terminator

Putting stunnel, nginx or Caddy on Host B in front of a loopback
`obsidian_server.exe` also works and always did — Host A's side is identical,
since it verifies whatever certificate the thing it dials presents. Use it if
you already run one, or if you want TLS 1.3 (the plugin's listener negotiates
TLS 1.2 with strong cipher suites; TLS 1.3 needs a Schannel API this does not
use yet).

### What works, and what does not

Either option gives you every x64dbg tool: memory read and write, breakpoints,
stepping, events, coverage, and `x64dbg_dump_module` — which streams bytes over
the API and writes the file on Host A, where the static tools can reach it.

Two limitations remain, both from the same cause: some artifacts are written by
the plugin, on Host B.

- `x64dbg_create_minidump`, `x64dbg_dump_memory` and the coverage export land
  in `%TEMP%\obsidian_x64dbg\output\` on Host B. There is no tool to fetch
  them back yet.
- The static side needs the sample on Host A. The Ghidra cache is keyed on the
  SHA-256 of the file's contents, so a copy of the same bytes lines up with
  analysis done on either host.

Phase 4 of [the plan](remote-access-plan.md) covers the artifact transfer that
removes the first.

### Troubleshooting

| Symptom | Cause |
|---|---|
| `X64DBG_HOST=... is not a loopback address` | The endpoint needs `BINARY_MCP_REMOTE_ALLOW`. A tunnel needs no opt-in and is simpler |
| `... so TLS is required: set X64DBG_TLS_CA` | No CA configured for a remote host. Point it at the certificate exported from Host B |
| Server log says `Invalid token (wrong length)` | The presented token is not 64 characters — a truncated paste, or a `\r` picked up from the Windows file. `printf '%s' "$OBSIDIAN_AUTH_TOKEN" \| wc -c` should print 64 |
| Server log says `Invalid token (mismatch)` | 64 characters but the wrong value, which means the token rotated: x64dbg has been restarted since you read it |
| `OBSIDIAN_AUTH_TOKEN must be set for a non-loopback endpoint` | The plugin's token file is on Host B. Read it there |
| `OBSIDIAN_AUTH_TOKEN is not set, and this bridge points at ...` | Same cause, hit at request time rather than construction |
| `SSLError` / certificate verify failed | The certificate Host B serves is not the one in `X64DBG_TLS_CA`, or its subject alternative name does not cover `X64DBG_HOST` (the `TextExtension` line) |
| Plugin log says `Server refused its listener configuration (exit 2)` | The flags built from `obsidian.ini` were rejected. The reason is in `obsidian_server.log`; deleting the ini restores the loopback default |
| Plugin log says `obsidian.ini is malformed` | A value contains a character a flag cannot hold — usually a stray space or quote. The whole file is refused rather than one setting dropped |
| Server log says `client certificate chain is not trusted (status 0x00000020)` | `CERT_TRUST_IS_UNTRUSTED_ROOT`: the client CA is not in a trust store the server can read. Import it into `Cert:\CurrentUser\Root` |
| Server log says `was not issued under the CA named by --tls-client-ca-thumbprint` | The certificate is trusted but came from a different CA than the pinned one |
| Nothing listens, and the server log says `no certificate with that thumbprint` | The thumbprint is from a different store. `--machine-store` / `machine_store=1` selects `LocalMachine\My`; the default is `CurrentUser\My`, which is what x64dbg's own user can read |
| Connection reset, or a timeout, reaching a host that is clearly up | `HTTPS_PROXY` is set in the server's environment and `requests` is routing the debugger connection through it. Add the debugger host to `no_proxy` |
| A client denied by `allow_clients` sees a connection reset, not a 403 | Expected. The check runs before the TLS handshake, so there is no channel to answer on; `obsidian_server.log` records the peer address |
| `entry '10.0.0.5/24' is not an address or CIDR: ... has host bits set` | Write the network address (`10.0.0.0/24`) or drop the prefix for one host (`10.0.0.5`) |
| `host=... is not the configured debugger endpoint` | `x64dbg_connect` may restate the configured endpoint but not replace it. Set `X64DBG_HOST` / `X64DBG_PORT` and reconnect |

---

## What the gates check

Both listeners apply the same checks in the same order: cheapest and least
secret-dependent first, so a denial never depends on comparing a token the
caller was never going to get right.

The chain below is `obsidian_server.exe`. The Python gate
(`RemoteAccessGate` in `src/utils/remote.py`) runs steps 1 and 4–7; steps 2
and 3 are uvicorn's.

Step 1 is the one asymmetry between the two. `obsidian_server.exe` closes the
socket and sends nothing — the check runs before the TLS handshake, so there
is no channel to send a status over — so a client denied by `allow_clients`
sees a connection reset, not a 403. The Python gate, which sits behind a
handshake that has already completed, does answer 403. If an `allow_clients`
entry is wrong, expect the port to look firewalled; `obsidian_server.log`
records the refusal with the peer address.

```
  connection ──▶ ┌────────────────────────────────────────────┐
                 │  accept()                                  │
                 ├────────────────────────────────────────────┤
                 │ 1  client address   allow_clients   close  │ ◀─ before TLS,
                 ├────────────────────────────────────────────┤    before any
                 │ 2  TLS handshake    + mTLS chain pin       │    parsing
                 ├────────────────────────────────────────────┤
                 │ 3  read request     16 KiB headers         │
                 │                     1 MiB body             │
                 │                     15 s deadline          │
                 ├────────────────────────────────────────────┤
                 │ 4  duplicate Host or Origin?          400  │
                 ├────────────────────────────────────────────┤
                 │ 5  Host    == bind / allow_hosts      400  │ ◀─ DNS
                 ├────────────────────────────────────────────┤    rebinding
                 │ 6  Origin  == bind / allow_hosts      400  │
                 ├────────────────────────────────────────────┤
                 │ 7  Bearer token     constant-time     401  │
                 ├────────────────────────────────────────────┤
                 │ 8  dispatch ──▶ pipe ──▶ plugin ──▶ x64dbg │
                 └────────────────────────────────────────────┘
```

A duplicate `Host` is refused rather than resolved (step 4) because a gate
deciding on the first value while a proxy in front decided on the last is a
gate that can be walked past — and a TLS terminator in front of a loopback
listener is a supported deployment.

## What the policy demands

One rule, enforced identically by `resolve_debugger_endpoint` and
`resolve_transport_config` on the Python side and `ParseOptions` on the C++
side:

```
                 is it loopback?
                        │
            ┌───────────┴────────────┐
           yes                       no
            │                         │
   no opt-in needed          ┌────────┴───────────────────────┐
   TLS optional              │  REMOTE_ALLOW=1                │  all three,
   token still required      │  + a certificate / CA          │  or refuse
   (%TEMP% file fallback)    │  + an explicit token           │  to start
                             └────────────────────────────────┘

   0.0.0.0   ::   *   ──▶  refused always, opt-in or not
   an address the parser cannot classify  ──▶  refused, never given to the OS
```

That last line is the one worth remembering. Each of these is a form
`inet_addr` accepts and this parser refuses: `0` as the wildcard `0.0.0.0`,
`127.1` as loopback, `0177.0.0.1` as octal. A classifier that disagrees with
the thing performing the bind is one that can be walked past, so both read the
same strict dotted-quad parser. The decisions in that diagram are compiled and
executed by `tests/test_cpp_listener_policy.py` and
`tests/test_remote_policy.py`.
