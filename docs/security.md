# Binary MCP Security Guide

## Overview

This guide covers securing remote access to the Binary MCP server. By default, the server runs in **stdio mode** (local only), which is the most secure configuration. When enabling remote access for VM/host setups, proper security configuration is **mandatory**.

## Quick Start (Secure VM Setup)

### On the VM (Windows/Linux with analysis tools):

```bash
# 1. Install binary-mcp
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp
uv sync

# 2. Generate secure token
python scripts/generate_token.py
# Copy the generated token

# 3. Configure .env
cat > .env << 'EOF'
MCP_TRANSPORT=sse
MCP_HOST=0.0.0.0
MCP_PORT=3000
MCP_ALLOW_REMOTE=true
MCP_AUTH_TOKEN=your-generated-token-here
MCP_TLS_MODE=self_signed
MCP_ALLOWED_IPS=192.168.1.0/24
EOF

# 4. Set restrictive permissions
chmod 600 .env

# 5. Start server
python -m src.server
```

### On the Host (Claude Desktop):

```json
{
  "mcpServers": {
    "binary-analysis": {
      "url": "https://192.168.1.100:3000/sse",
      "headers": {
        "Authorization": "Bearer your-generated-token-here"
      }
    }
  }
}
```

**Note**: With self-signed certificates, you'll need to configure your client to trust the certificate or bypass verification for this specific host (depending on your client's capabilities).

---

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────┐
│  Layer 1: Network Security              │
│  - Interface binding control             │
│  - IP allowlisting                       │
│  - Firewall integration                  │
├─────────────────────────────────────────┤
│  Layer 2: Transport Security              │
│  - TLS 1.2+ (mandatory for remote)       │
│  - Certificate validation                │
│  - No unencrypted fallback               │
├─────────────────────────────────────────┤
│  Layer 3: Authentication                │
│  - Bearer token (min 256-bit entropy)  │
│  - Session management                    │
│  - Rate limiting on auth                 │
├─────────────────────────────────────────┤
│  Layer 4: Application Security            │
│  - Input validation (path, regex)        │
│  - Rate limiting per session            │
│  - Tool-level permissions               │
├─────────────────────────────────────────┤
│  Layer 5: Audit & Monitoring              │
│  - Immutable audit logs                  │
│  - Security event logging                │
│  - Log integrity verification           │
└─────────────────────────────────────────┘
```

---

## Security Requirements

### For Remote Access (VM Setup)

Remote access requires **both** authentication and TLS:

| Requirement | Configuration | Why |
|-------------|---------------|-----|
| Authentication | `MCP_AUTH_TOKEN` | Prevents unauthorized access |
| TLS | `MCP_TLS_MODE` | Prevents MITM attacks |
| Rate Limiting | `MCP_RATE_LIMIT_*` | Prevents brute force & DoS |
| Audit Logging | `MCP_AUDIT_LOG_*` | Forensics and monitoring |

### For Local Access (stdio)

Local access has no mandatory requirements but optional security is available:

- Authentication can still be enabled
- TLS not needed (local communication)
- Audit logging still recommended

---

## Configuration Reference

### Transport Configuration

```bash
# Transport type
MCP_TRANSPORT=stdio      # Local only (default, most secure)
MCP_TRANSPORT=sse        # HTTP with SSE (allows remote)

# Network binding
MCP_HOST=127.0.0.1       # Local only (default, secure)
MCP_HOST=0.0.0.0         # All interfaces (allows remote access)
MCP_PORT=3000            # HTTP/S port

# Remote access control
MCP_ALLOW_REMOTE=false   # Don't allow non-localhost binds (default)
MCP_ALLOW_REMOTE=true    # Allow binding to 0.0.0.0

# IP allowlist (CIDR notation)
MCP_ALLOWED_IPS=         # Empty = allow all (if auth enabled)
MCP_ALLOWED_IPS=192.168.1.0/24,10.0.0.0/8  # Only these networks
```

### Authentication

```bash
# Bearer token (REQUIRED for remote)
MCP_AUTH_TOKEN=your-secure-token-here-min-32-chars

# Generate with:
python scripts/generate_token.py

# Token expiration (seconds)
MCP_TOKEN_EXPIRY=3600    # 1 hour
MCP_TOKEN_EXPIRY=0       # Never expire (not recommended)
```

**Token Requirements:**
- Minimum 32 characters
- High entropy (no dictionary words, high randomness)
- URL-safe characters (A-Z, a-z, 0-9, -, _)
- Generate with provided script for best security

### TLS Configuration

```bash
# TLS mode
MCP_TLS_MODE=disabled      # No TLS (INSECURE for remote)
MCP_TLS_MODE=self_signed   # Auto-generated certificate
MCP_TLS_MODE=cert_file     # User-provided certificate

# Certificate paths (for cert_file mode)
MCP_TLS_CERT_PATH=/path/to/server.crt
MCP_TLS_KEY_PATH=/path/to/server.key

# Require TLS for remote (default: true)
MCP_TLS_REQUIRED_FOR_REMOTE=true
```

**Certificate Requirements:**
- RSA 2048+ bit or ECDSA P-256+
- SHA-256 or better signature
- Valid for the server's hostname/IP
- Private key permissions: 600 (owner read/write only)

### Rate Limiting

```bash
# Authentication attempts
MCP_RATE_LIMIT_AUTH=5          # 5 attempts per window
MCP_RATE_LIMIT_REQUESTS=100    # 100 requests per window
MCP_RATE_LIMIT_WINDOW=60       # 60 second window
MCP_MAX_CONNECTIONS=10         # 10 concurrent connections
```

### Audit Logging

```bash
# Audit log directory
MCP_AUDIT_LOG_PATH=/var/log/binary-mcp/audit

# Retention
MCP_AUDIT_LOG_RETENTION_DAYS=90
MCP_AUDIT_LOG_ROTATE_SIZE_MB=100
```

---

## Deployment Scenarios

### Scenario 1: Secure VM (Recommended)

**Use case**: Analyze malware on isolated VM, control from host

**VM (192.168.1.100)**:
```bash
# .env
MCP_TRANSPORT=sse
MCP_HOST=0.0.0.0
MCP_PORT=3000
MCP_ALLOW_REMOTE=true
MCP_AUTH_TOKEN=<48-char-random-token>
MCP_TLS_MODE=self_signed
MCP_ALLOWED_IPS=192.168.1.0/24
MCP_TLS_REQUIRED_FOR_REMOTE=true

# Set permissions
chmod 600 .env

# Run
python -m src.server
```

**Security features:**
- ✅ Authentication required
- ✅ TLS encryption
- ✅ IP restricted to LAN
- ✅ Audit logging enabled

### Scenario 2: Development (Local Only)

**Use case**: Local development, no remote needed

```bash
# .env
MCP_TRANSPORT=stdio
MCP_LOG_LEVEL=DEBUG

# No auth/TLS needed - local only
```

### Scenario 3: Production Server

**Use case**: Dedicated analysis server in data center

```bash
# .env
MCP_TRANSPORT=sse
MCP_HOST=0.0.0.0
MCP_PORT=3000
MCP_ALLOW_REMOTE=true
MCP_AUTH_TOKEN=<strong-token>
MCP_TLS_MODE=cert_file
MCP_TLS_CERT_PATH=/etc/ssl/certs/binary-mcp.crt
MCP_TLS_KEY_PATH=/etc/ssl/private/binary-mcp.key
MCP_ALLOWED_IPS=10.0.0.0/8
MCP_RATE_LIMIT_AUTH=3
MCP_RATE_LIMIT_REQUESTS=50
MCP_AUDIT_LOG_PATH=/var/log/binary-mcp/audit
MCP_AUDIT_LOG_RETENTION_DAYS=365
```

**Additional hardening:**
- Use proper PKI certificate (not self-signed)
- Restrictive IP allowlist
- Strict rate limits
- Long audit retention
- Run as non-root user
- Firewall rules at network level

---

## Security Checklist

Before enabling remote access:

- [ ] Generated strong authentication token (`python scripts/generate_token.py`)
- [ ] Set `MCP_AUTH_TOKEN` with token value
- [ ] Enabled TLS (`MCP_TLS_MODE=self_signed` minimum)
- [ ] Configured IP allowlist if applicable
- [ ] Set restrictive file permissions on `.env` (`chmod 600`)
- [ ] Tested connection with client
- [ ] Verified audit logs are writing
- [ ] Have incident response plan

After enabling remote access:

- [ ] Monitor audit logs regularly
- [ ] Rotate authentication token periodically
- [ ] Review rate limit logs for abuse
- [ ] Keep system and dependencies updated
- [ ] Test certificate expiration handling

---

## Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| **Unauthorized Access** | Mandatory authentication + TLS |
| **MITM Attack** | TLS 1.2+ with strong ciphers |
| **Brute Force** | Rate limiting on authentication |
| **Token Theft** | Token expiration, session management |
| **Replay Attack** | Session-based auth, timestamp validation |
| **DoS** | Connection and rate limiting |
| **Path Traversal** | Input validation (existing) |
| **Command Injection** | Input validation (existing) |
| **Privilege Escalation** | Run as non-root, restricted file access |

---

## Audit Log Format

Audit logs are JSON Lines format:

```json
{"timestamp":"2024-01-15T10:30:00+00:00","sequence":1,"event_id":"uuid","event_type":"security","event_subtype":"auth:authentication","outcome":"success","session_id":"abc123","client_ip":"192.168.1.50","action":"authentication","resource":null,"resource_type":null,"auth_method":"bearer_token","mfa_used":null,"details":{},"prev_hash":null,"event_hash":"abc123"}
```

Fields:
- `timestamp`: ISO 8601 with timezone
- `sequence`: Monotonic counter (detect deletions)
- `event_id`: Unique UUID
- `event_type`: Category (auth, access, tool_call, etc.)
- `outcome`: success/failure/denied/error
- `session_id`: Session identifier
- `client_ip`: Source IP
- `event_hash`: Integrity verification
- `prev_hash`: Chain verification

**Log integrity verification:**
```python
from src.utils.audit_log import get_audit_logger
result = get_audit_logger().verify_integrity()
print(f"Valid: {result['all_valid']}")
```

---

## Troubleshooting

### "Authentication required" error
- Ensure `MCP_AUTH_TOKEN` is set
- Verify client sends `Authorization: Bearer <token>` header

### "TLS required" error
- Set `MCP_TLS_MODE=self_signed` or provide certificate
- Or explicitly disable (INSECURE): `MCP_TLS_REQUIRED_FOR_REMOTE=false`

### "IP not in allowlist" error
- Check `MCP_ALLOWED_IPS` includes client's network
- Check for proxy/NAT issues (client sees different IP)

### Certificate verification fails
- With self-signed: client must trust or bypass verification
- With cert_file: verify certificate chain and hostname

### Rate limit exceeded
- Wait for window to reset
- Adjust `MCP_RATE_LIMIT_*` if legitimate use

---

## Incident Response

If you suspect unauthorized access:

### Session Revocation

To revoke all sessions and block a compromised token:

1. Generate a new token:
   ```bash
   python scripts/generate_token.py
   ```

2. Update your `.env` file with the new `MCP_AUTH_TOKEN`

3. Restart the server -- all existing sessions are invalidated immediately

### Post-Incident Investigation

1. **Review audit logs:**
   ```bash
   cat ~/.binary_mcp_output/audit/audit-*.log | grep "192.168.1.x"
   ```

2. **Check for data access:**
   Review tool calls in logs for unauthorized binary analysis

---

## Contact & Support

Security issues: Please report via GitHub Security Advisory
Documentation: https://github.com/Sarks0/binary-mcp/blob/main/docs/security.md
