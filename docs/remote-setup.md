# Remote setup

Two ways to run this across machines. Pick one.

| | Setup A | Setup B |
|---|---|---|
| **What moves** | The whole server runs on the analysis box | Only the x64dbg connection crosses the network |
| **You get** | Every tool, Ghidra included | Live debugging only; Ghidra runs locally |
| **Set up on** | The analysis box | Both machines |
| **Status** | Works, not yet tested on real hardware | Tested on two hosts |

Both refuse to go off-loopback without TLS and a token. Neither changes
anything if you set nothing: the default is still local stdio.

The full reference, with diagrams and a troubleshooting table, is
[remote-access.md](remote-access.md).

---

## Setup A: whole server remote

Use this when the heavy machine should do the work: Ghidra, the cache, the
samples. Your laptop just talks to it.

### 1. Certificate (on the analysis box)

```bash
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout server-key.pem -out server-cert.pem \
  -subj "/CN=binary-mcp" \
  -addext "subjectAltName=IP:10.0.0.50"
```

Use the box's real IP. The IP must be in `subjectAltName` or the client
refuses the certificate.

### 2. Token (on the analysis box)

```bash
openssl rand -hex 32
```

### 3. `.env` (on the analysis box)

```bash
BINARY_MCP_TRANSPORT=http
BINARY_MCP_HTTP_HOST=10.0.0.50
BINARY_MCP_REMOTE_ALLOW=1
BINARY_MCP_REMOTE_TLS_CERT=/path/to/server-cert.pem
BINARY_MCP_REMOTE_TLS_KEY=/path/to/server-key.pem
BINARY_MCP_HTTP_TOKEN=<the token from step 2>
BINARY_MCP_ALLOWED_DIRS=/srv/samples
```

`chmod 600 .env`. Samples live on **this** machine now, inside
`BINARY_MCP_ALLOWED_DIRS`: nothing copies them there for you.

Optional, worth setting:

```bash
BINARY_MCP_REMOTE_CLIENT_ALLOWLIST=10.0.0.0/24   # who may even reach it
BINARY_MCP_HTTP_ALLOWED_HOSTS=analysis.lab       # if you dial it by name
```

### 4. Start it

```bash
uv run python -m src.server
```

### 5. Connect (from your machine)

Copy `server-cert.pem` over, then point the client at
`https://10.0.0.50:8770/mcp` with the token as a bearer header and that PEM
as the CA.

---

## Setup B: x64dbg remote only

Use this when the server stays local and only the debugger is elsewhere.

### On the Windows box

Get the certificate thumbprint:

```powershell
Get-ChildItem Cert:\CurrentUser\My | Select-Object Thumbprint, Subject
```

Create `obsidian.ini` next to the plugin (same folder as `obsidian.dp64`):

```ini
[listener]
bind=10.0.0.25
port=8765
tls_cert_thumbprint=AABBCC...
token=<64 hex characters>
allow_clients=10.0.0.24
```

Restart x64dbg. The log should say:

```
[MCP] Authentication token ready (pinned in obsidian.ini, 64 chars)
```

Without `token=` the plugin generates a new one every start, which breaks
the other machine on every restart. Pin it.

Export the certificate and copy it to the server box as a `.pem`.

### On the server box

```bash
X64DBG_HOST=10.0.0.25
X64DBG_PORT=8765
X64DBG_TLS_CA=/path/to/obsidian-cert.pem
OBSIDIAN_AUTH_TOKEN=<the same token>
```

The token must match the ini exactly. A length mismatch logs
`Invalid token (wrong length)` on the Windows side.

### Check it

```bash
curl --cacert /path/to/obsidian-cert.pem \
  -H "Authorization: Bearer $OBSIDIAN_AUTH_TOKEN" \
  https://10.0.0.25:8765/health
```

Expect `{"status":"ok","message":"Obsidian server running"}`.

---

## When it will not start

| Symptom | Cause |
|---|---|
| wildcard bind refused | `0.0.0.0` is never allowed. Name the real address. |
| remote access not enabled | Missing `BINARY_MCP_REMOTE_ALLOW=1` |
| TLS required / token required | Off-loopback needs both. No exceptions. |
| 401 | Token mismatch, or it rotated because `token=` is not pinned |
| 403 | Client address is not in the allowlist |
| 400 | `Host` header is not the bind address; add it to `BINARY_MCP_HTTP_ALLOWED_HOSTS` |
| certificate verify failed | The IP or name you dial is not in the cert's `subjectAltName` |

## Mutual TLS

Both setups can require a client certificate as well. Setup A:
`BINARY_MCP_REMOTE_TLS_CA`. Setup B: `tls_client_ca_thumbprint` in the ini,
plus `X64DBG_TLS_CLIENT_CERT` and `X64DBG_TLS_CLIENT_KEY` on the server.

This path has never been run. Use it expecting to debug it.
