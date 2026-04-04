# Remote MCP Access Usage Guide

This guide explains how to use the Binary MCP server remotely (e.g., VM with analysis tools → Host with Claude Desktop).

## Quick Comparison

| Feature | Local (stdio) | Remote (SSE) |
|---------|---------------|--------------|
| **Transport** | Standard input/output | HTTP + Server-Sent Events |
| **Location** | Same machine | Different machines/network |
| **Security** | Process isolation | TLS + Authentication required |
| **Configuration** | None (default) | `.env` file setup |
| **Use case** | Local development | VM analysis, remote servers |

---

## Current Setup (stdio - What You Have Now)

### Configuration

**No configuration needed** - this is the default:

```bash
# Just run the server
python -m src.server
```

### Claude Desktop Config

```json
{
  "mcpServers": {
    "binary-mcp": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/binary-mcp",
        "run",
        "python",
        "-m",
        "src.server"
      ]
    }
  }
}
```

### How It Works

```
┌─────────────────┐        ┌─────────────────┐
│  Claude Desktop │◄──────►│  MCP Server     │
│  (stdio client) │ pipes  │  (stdio server) │
└─────────────────┘        └─────────────────┘
        Host                        Host
        (Same machine)              (Same machine)
```

1. Claude Desktop spawns the MCP server as a subprocess
2. Communication over stdin/stdout pipes
3. Server terminates when Claude closes
4. **Limitation**: Must be on same machine

---

## New Remote Setup (SSE - For VM/Remote)

### Step-by-Step Setup

#### Step 1: VM Setup (Where Analysis Tools Run)

```bash
# SSH into your Windows/Linux VM with Ghidra/x64dbg
ssh user@192.168.1.100

# Navigate to binary-mcp
cd binary-mcp

# Switch to the feature branch
git checkout feature/secure-remote-mcp-access

# Install new dependency (cryptography for TLS)
uv sync

# Generate authentication token
python scripts/generate_token.py

# The script outputs something like:
# Token: aB3dEfGhIjKlMnOpQrStUvWxYz... (48 chars)
# Length: 48 chars
# Entropy: 286 bits
#
# CONFIGURATION
# Add this to your .env file:
# MCP_TRANSPORT=sse
# MCP_HOST=0.0.0.0
# MCP_ALLOW_REMOTE=true
# MCP_AUTH_TOKEN=aB3dEfGhIjKlMnOpQrStUvWxYz...
```

#### Step 2: Create .env File on VM

```bash
# Create the .env file
cat > .env << 'EOF'
# Network Configuration
MCP_TRANSPORT=sse
MCP_HOST=0.0.0.0
MCP_PORT=3000
MCP_ALLOW_REMOTE=true

# Authentication (REQUIRED for remote)
MCP_AUTH_TOKEN=your-generated-token-here

# TLS (REQUIRED for remote - auto-generate self-signed cert)
MCP_TLS_MODE=self_signed

# Optional: Restrict to your local network
MCP_ALLOWED_IPS=192.168.1.0/24

# Optional: Rate limiting
MCP_RATE_LIMIT_AUTH=5
MCP_RATE_LIMIT_REQUESTS=100

# Optional: Audit logging
MCP_AUDIT_LOG_RETENTION_DAYS=90
EOF

# Secure the file
chmod 600 .env
```

#### Step 3: Start Server on VM

```bash
# On the VM
python -m src.server

# You'll see output like:
# [INFO] Starting Binary MCP Server...
# [INFO] Transport: sse
# [INFO] Bind: 0.0.0.0:3000
# [INFO] TLS Mode: self_signed
# [INFO] Authentication: enabled
# 
# SECURITY WARNING: Remote Access Enabled
# ============================================================
# ℹ️  Using self-signed certificate.
#    Clients must verify certificate fingerprint out-of-band.
#    Vulnerable to MITM if fingerprint not verified.
#
#    Listening on: 0.0.0.0:3000
#    TLS Mode: self_signed
#
#    Authentication: Bearer token required
# ============================================================
#
# [INFO] SSE server listening on https://0.0.0.0:3000
```

**Note**: With `MCP_TLS_MODE=self_signed`, the server generates a certificate on first run. You'll need the fingerprint to verify on the client.

#### Step 4: Get Certificate Fingerprint (for client verification)

```bash
# On the VM - get the fingerprint
python -c "
from src.utils.tls import get_certificate_fingerprint
from pathlib import Path
cert = Path.home() / '.binary_mcp_output' / 'tls' / 'server.crt'
print(f'Certificate fingerprint: {get_certificate_fingerprint(cert)}')
"
```

Output:
```
Certificate fingerprint: a1b2c3d4e5f6... (SHA-256 hex)
```

#### Step 5: Host Setup (Claude Desktop)

```json
{
  "mcpServers": {
    "binary-analysis-vm": {
      "url": "https://192.168.1.100:3000/sse",
      "headers": {
        "Authorization": "Bearer your-generated-token-here"
      }
    }
  }
}
```

**Important**: The exact configuration depends on your MCP client:

**For Claude Desktop (current stable):**
- Claude Desktop may not yet support the `url` field in stable release
- You may need a **bridge** (see Alternative Setup below)

**For Claude Code or other MCP clients:**
- Direct SSE URL support varies by client

### Alternative: Using a Local Bridge

If your MCP client doesn't support SSE directly, use the stdio bridge pattern:

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Claude     │    │   Bridge     │    │   MCP Server │
│   Desktop    │───►│   (stdio     │───►│   (VM, SSE)  │
│              │    │   → HTTP)    │    │              │
└──────────────┘    └──────────────┘    └──────────────┘
     Host                 Host              VM
```

**Bridge implementation** (save as `mcp_bridge.py` on host):

```python
#!/usr/bin/env python3
"""Bridge stdio to SSE for MCP clients without native SSE support."""

import json
import sys
import requests
import urllib3

# Disable SSL warnings for self-signed cert (verify fingerprint separately!)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
SERVER_URL = "https://192.168.1.100:3000"
AUTH_TOKEN = "your-generated-token-here"
VERIFY_CERT = False  # Set to True if using proper CA cert

def main():
    headers = {
        "Authorization": f"Bearer {AUTH_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # Connect to SSE endpoint
    session = requests.Session()
    
    # Read requests from stdin (from Claude)
    for line in sys.stdin:
        try:
            request = json.loads(line)
            
            # Forward to server
            response = session.post(
                f"{SERVER_URL}/message",
                headers=headers,
                json=request,
                verify=VERIFY_CERT,
                timeout=30
            )
            
            if response.status_code == 200:
                # Write response to stdout (to Claude)
                print(json.dumps(response.json()), flush=True)
            else:
                error = {
                    "error": f"Server error: {response.status_code}",
                    "message": response.text
                }
                print(json.dumps(error), flush=True)
                
        except json.JSONDecodeError:
            continue
        except Exception as e:
            error = {"error": str(e)}
            print(json.dumps(error), flush=True)

if __name__ == "__main__":
    main()
```

**Claude Desktop config with bridge:**

```json
{
  "mcpServers": {
    "binary-analysis-vm": {
      "command": "python3",
      "args": ["/path/to/mcp_bridge.py"]
    }
  }
}
```

---

## Architecture Comparison

### Current: stdio (Local Only)

```
┌─────────────────────────────────────────────────────┐
│                      HOST                            │
│  ┌──────────────┐      ┌──────────────────────────┐  │
│  │              │      │  MCP Server Process      │  │
│  │   Claude     │◄────►│                          │  │
│  │   Desktop    │stdio │  • Ghidra analysis       │  │
│  │              │      │  • x64dbg debugging      │  │
│  └──────────────┘      │  • PE parsing            │  │
│                        └──────────────────────────┘  │
└─────────────────────────────────────────────────────┘

Pros:
✓ Simple, no configuration
✓ Automatic process management
✓ Works out of the box

Cons:
✗ Analysis tools must be on same machine
✗ Clutters host with heavy tools (Ghidra, x64dbg)
✗ Security concerns analyzing malware on main machine
```

### New: SSE (VM/Remote)

```
┌─────────────────────────┐         ┌─────────────────────────────────────┐
│         HOST            │         │              VM                      │
│  ┌──────────────────┐   │  HTTPS  │  ┌─────────────────────────────────┐ │
│  │                │   │  + Auth │  │                                 │ │
│  │  Claude        │   │────────►│  │  MCP Server                     │ │
│  │  Desktop       │   │  SSE    │  │  • Ghidra (static analysis)     │ │
│  │                │   │         │  │  • x64dbg (dynamic debugging)   │ │
│  │  [Bridge if    │   │◄────────│  │  • WinDbg (kernel debugging)    │ │
│  │   needed]      │   │         │  │                                 │ │
│  └──────────────────┘   │         │  │  Isolated from host:            │ │
│                         │         │  │  • Malware runs in sandbox    │ │
│  Clean environment      │         │  │  • Heavy tools off host         │ │
│  • No Ghidra install    │         │  │  • Snapshots for safety         │ │
│  • No x64dbg install    │         │  └─────────────────────────────────┘ │
│  • No Java/JRE needed   │         │                                     │
└─────────────────────────┘         └─────────────────────────────────────┘

Pros:
✓ Host stays clean (no heavy tools)
✓ Malware analysis isolated in VM
✓ Cross-platform (macOS/Linux host, Windows VM)
✓ Multiple clients can connect
✓ Remote analysis servers possible

Cons:
✓ Requires network configuration
✓ TLS + Authentication setup
✓ May need bridge for some MCP clients
✓ Slightly more latency (network vs pipes)
```

---

## Common Workflows

### Workflow 1: Analyzing Malware Safely

**Before (stdio):**
1. Install Ghidra, x64dbg on your Mac/PC
2. Run malware sample on main machine (risky!)
3. Analyze directly

**After (SSE with VM):**
1. VM has Ghidra, x64dbg pre-installed
2. Transfer sample to VM (shared folder, scp, etc.)
3. Run sample in isolated VM
4. Analyze remotely from clean host
5. Rollback VM snapshot after analysis

**Commands:**

```bash
# On VM - prepare analysis
mkdir -p ~/analysis
cd ~/analysis

# Copy malware sample (from host or download)
scp host:~/suspected_malware.exe .

# Start MCP server (already running as service, or start now)
python -m src.server

# On Host - in Claude Desktop
# Just use normally, all analysis happens on VM
```

**Claude conversation:**

```
User: Analyze this suspected malware: C:\analysis\suspected_malware.exe

Claude (via remote MCP): I'll analyze this on the VM for safety.

[Calls x64dbg_run on VM]
[Calls ghidra_decompile_function on VM]  
[Results returned to host]

Analysis complete. The sample appears to be...
```

### Workflow 2: Cross-Platform Analysis

**Scenario**: macOS host analyzing Windows PE files

**VM Setup (Windows):**
```powershell
# On Windows VM
# Install binary-mcp with Windows tools
python install.py

# Set up environment
$env:MCP_TRANSPORT = "sse"
$env:MCP_HOST = "0.0.0.0"
$env:MCP_AUTH_TOKEN = "your-token"
$env:MCP_TLS_MODE = "self_signed"

# Run server
python -m src.server
```

**Host (macOS):**
```json
{
  "mcpServers": {
    "windows-analysis": {
      "url": "https://windows-vm.local:3000/sse",
      "headers": {
        "Authorization": "Bearer your-token"
      }
    }
  }
}
```

Now you can analyze Windows PE files from macOS without needing Windows emulation.

### Workflow 3: Shared Analysis Server

**Scenario**: Team shares powerful analysis workstation

**Server Setup:**
```bash
# On powerful workstation
MCP_HOST=0.0.0.0
MCP_PORT=3000
MCP_AUTH_TOKEN=<strong-team-token>
MCP_TLS_MODE=cert_file
MCP_TLS_CERT_PATH=/etc/ssl/certs/analysis-server.crt
MCP_TLS_KEY_PATH=/etc/ssl/private/analysis-server.key
MCP_ALLOWED_IPS=10.0.0.0/8
MCP_RATE_LIMIT_REQUESTS=200
```

**Team members:**
```json
{
  "mcpServers": {
    "team-analysis": {
      "url": "https://analysis-server.company.internal:3000/sse",
      "headers": {
        "Authorization": "Bearer team-shared-token"
      }
    }
  }
}
```

---

## Security Checklist

When using remote access, verify:

- [ ] **Generated strong token**: `python scripts/generate_token.py`
- [ ] **Set in .env**: `MCP_AUTH_TOKEN=<token>`
- [ ] **Secured .env**: `chmod 600 .env`
- [ ] **TLS enabled**: `MCP_TLS_MODE=self_signed` (or cert_file)
- [ ] **IP restricted**: `MCP_ALLOWED_IPS=your.network/24`
- [ ] **Firewall rules**: VM only exposes port 3000 to LAN
- [ ] **Audit logging**: Check `~/.binary_mcp_output/audit/`
- [ ] **Token rotation**: Plan to rotate tokens periodically
- [ ] **VM snapshots**: For malware analysis, use snapshot + rollback

---

## Troubleshooting

### "Authentication required" Error

**Cause**: Token missing or invalid

**Fix**:
```bash
# On VM - check token is set
grep MCP_AUTH_TOKEN .env

# Should show: MCP_AUTH_TOKEN=your-token-here
# If not set, generate and add it
python scripts/generate_token.py
```

### "TLS required" Error

**Cause**: Remote access without TLS

**Fix**:
```bash
# Add to .env
MCP_TLS_MODE=self_signed
```

### "IP not in allowlist" Error

**Cause**: Client IP not in `MCP_ALLOWED_IPS`

**Fix**:
```bash
# Check client IP
# On host: curl ifconfig.me
# Or: ipconfig (Windows), ifconfig (macOS/Linux)

# Update .env on VM
MCP_ALLOWED_IPS=192.168.1.0/24,10.0.0.50/32
```

### Certificate Verification Fails

**Cause**: Self-signed cert not trusted by client

**Solutions**:

1. **Option A**: Use proper certificate (Let's Encrypt or internal CA)
2. **Option B**: Configure client to skip verification (development only)
3. **Option C**: Trust the certificate fingerprint out-of-band

For bridge script (development):
```python
VERIFY_CERT = False  # Only for development!
```

### Server Won't Start - "Port in use"

**Cause**: Another service using port 3000

**Fix**:
```bash
# Change port in .env
MCP_PORT=3001
```

---

## Configuration Reference

### Minimal Remote Config (Development)

```bash
MCP_TRANSPORT=sse
MCP_HOST=0.0.0.0
MCP_ALLOW_REMOTE=true
MCP_AUTH_TOKEN=<your-token>
MCP_TLS_MODE=self_signed
```

### Secure Production Config

```bash
# Network
MCP_TRANSPORT=sse
MCP_HOST=0.0.0.0
MCP_PORT=3000
MCP_ALLOW_REMOTE=true
MCP_ALLOWED_IPS=10.0.0.0/8,192.168.1.0/24

# Authentication
MCP_AUTH_TOKEN=<48-char-high-entropy-token>
MCP_TOKEN_EXPIRY=3600

# TLS with proper certificate
MCP_TLS_MODE=cert_file
MCP_TLS_CERT_PATH=/etc/ssl/certs/mcp-server.crt
MCP_TLS_KEY_PATH=/etc/ssl/private/mcp-server.key
MCP_TLS_REQUIRED_FOR_REMOTE=true

# Rate limiting
MCP_RATE_LIMIT_AUTH=3
MCP_RATE_LIMIT_REQUESTS=50
MCP_RATE_LIMIT_WINDOW=60
MCP_MAX_CONNECTIONS=5

# Audit logging
MCP_AUDIT_LOG_PATH=/var/log/binary-mcp/audit
MCP_AUDIT_LOG_RETENTION_DAYS=365
```

---

## Migration from stdio to SSE

If you currently use stdio and want to switch to remote:

### 1. Clone Current Setup to VM

```bash
# On VM
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp
git checkout feature/secure-remote-mcp-access
uv sync
```

### 2. Verify VM Has Analysis Tools

```bash
# Check Ghidra
ls $GHIDRA_HOME/support/analyzeHeadless

# Check x64dbg (Windows)
ls $X64DBG_HOME/x64dbg.exe
```

### 3. Configure and Start Server on VM

```bash
# Generate token
python scripts/generate_token.py >> .env

# Add other settings
cat >> .env << 'EOF'
MCP_TRANSPORT=sse
MCP_HOST=0.0.0.0
MCP_ALLOW_REMOTE=true
MCP_TLS_MODE=self_signed
EOF

# Start
python -m src.server
```

### 4. Update Claude Desktop Config on Host

**From:**
```json
{
  "mcpServers": {
    "binary-mcp": {
      "command": "uv",
      "args": ["..."]
    }
  }
}
```

**To:**
```json
{
  "mcpServers": {
    "binary-analysis-vm": {
      "url": "https://192.168.1.100:3000/sse",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

Or use the bridge script if your client doesn't support SSE directly.

### 5. Test

```
In Claude Desktop:
"What binary analysis tools are available?"

Expected: Same response as before, but tools now run on VM
```

---

## Summary

| What You Do | stdio (Current) | SSE (New Remote) |
|-------------|-----------------|------------------|
| **Install** | Everything on host | Tools on VM, client on host |
| **Configure** | Nothing | `.env` with token + TLS |
| **Start** | Claude auto-starts | Manually start on VM first |
| **Security** | Process isolation | TLS + Auth + IP filtering |
| **Use** | Ask Claude normally | Ask Claude normally |
| **Speed** | Fast (pipes) | Fast (local network) |

**Key insight**: From Claude's perspective, nothing changes. You ask the same questions. The difference is where the heavy lifting happens (host vs VM).
