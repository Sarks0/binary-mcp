# Quick Reference: Remote MCP Access

## One-Page Setup Guide

### 1. Setup VM (Analysis Machine)

```bash
# SSH to VM
ssh user@192.168.1.100

# Clone and setup
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp
git checkout feature/secure-remote-mcp-access
uv sync

# Generate token
python scripts/generate_token.py
# Copy the generated token
```

### 2. Configure VM

Create `.env`:
```bash
cat > .env << 'EOF'
MCP_TRANSPORT=sse
MCP_HOST=0.0.0.0
MCP_PORT=3000
MCP_ALLOW_REMOTE=true
MCP_AUTH_TOKEN=YOUR_TOKEN_HERE
MCP_TLS_MODE=self_signed
MCP_ALLOWED_IPS=192.168.1.0/24
EOF

chmod 600 .env
```

### 3. Start Server on VM

```bash
python -m src.server

# Look for:
# [INFO] SSE server listening on https://0.0.0.0:3000
```

### 4. Configure Host (Claude Desktop)

**Option A: Native SSE (if supported):**
```json
{
  "mcpServers": {
    "vm-analysis": {
      "url": "https://192.168.1.100:3000/sse",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      }
    }
  }
}
```

**Option B: Bridge script (if stdio only):**
```bash
# Save as bridge.py, then reference in Claude config:
# "command": "python3", "args": ["/path/to/bridge.py"]
```

See `docs/remote-usage-guide.md` for bridge script.

---

## Key Differences from stdio

| Aspect | stdio (Local) | SSE (Remote) |
|--------|---------------|--------------|
| **Config** | None | `.env` file |
| **Security** | None | Token + TLS |
| **Start** | Claude starts it | You start it |
| **Port** | N/A | 3000 (default) |
| **Auth** | N/A | Bearer token |

---

## Common Commands

```bash
# Generate new token
python scripts/generate_token.py

# Validate existing token
python scripts/generate_token.py --validate YOUR_TOKEN

# Check audit logs
tail -f ~/.binary_mcp_output/audit/audit-*.log

# View certificate fingerprint
python -c "
from src.utils.tls import get_certificate_fingerprint
from pathlib import Path
print(get_certificate_fingerprint(Path.home() / '.binary_mcp_output' / 'tls' / 'server.crt'))
"

# Test server is running
curl -k -H "Authorization: Bearer YOUR_TOKEN" \
  https://192.168.1.100:3000/sse
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| "Auth required" | No token | Set `MCP_AUTH_TOKEN` |
| "TLS required" | No encryption | Set `MCP_TLS_MODE=self_signed` |
| "IP not allowed" | Wrong network | Update `MCP_ALLOWED_IPS` |
| "Port in use" | Conflict | Change `MCP_PORT` |
| "Cert error" | Self-signed | Use `-k` in curl, or proper cert |

---

## Security Quick-Check

```bash
# Before enabling remote, verify:
✓ Token generated: python scripts/generate_token.py
✓ Token in .env: grep MCP_AUTH_TOKEN .env
✓ TLS enabled: grep MCP_TLS_MODE .env
✓ File permissions: chmod 600 .env
✓ IP restricted: grep MCP_ALLOWED_IPS .env
✓ Firewall active: VM only allows port 3000
```

---

## Files Reference

| File | Purpose |
|------|---------|
| `.env` | Configuration (keep secret!) |
| `scripts/generate_token.py` | Create auth tokens |
| `docs/remote-usage-guide.md` | Full documentation |
| `docs/security.md` | Security architecture |
| `~/.binary_mcp_output/audit/` | Audit logs |
| `~/.binary_mcp_output/tls/` | Certificates |

---

## Minimal .env for Testing

```bash
MCP_TRANSPORT=sse
MCP_HOST=0.0.0.0
MCP_ALLOW_REMOTE=true
MCP_AUTH_TOKEN=$(python scripts/generate_token.py 2>/dev/null | grep "^  " | head -1 | xargs)
MCP_TLS_MODE=self_signed
```

**Production requires more hardening** - see `docs/security.md`.
