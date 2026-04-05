# 🌐 Remote MCP Access - Quick Start Guide

> **TL;DR:** Run heavy analysis tools (Ghidra, x64dbg) on a VM, control them from your main machine via secure network connection.

---

## 📋 Before You Start

**What you need:**
- 🖥️ A VM or second computer with analysis tools (Ghidra, x64dbg, WinDbg)
- 🔐 The ability to generate a secure password (we'll do this for you)
- 🌐 Both machines on the same network (or accessible via IP)

**What this solves:**
- ✅ Keep your main computer clean (no Java, no heavy tools)
- ✅ Analyze malware safely in an isolated VM
- ✅ macOS/Linux can control Windows analysis tools
- ✅ Multiple people can share one powerful analysis workstation

---

## 🚀 Quick Setup (5 Minutes)

### Step 1: Prepare Your VM (Analysis Machine)

SSH into your VM or open a terminal on your second computer:

```bash
# 1. Navigate to your binary-mcp installation
cd binary-mcp

# 2. Install dependencies
uv sync
```

### Step 2: Generate Your Security Token

Think of this like creating a password for your server:

```bash
python scripts/generate_token.py
```

**You'll see output like:**
```
============================================================
BINARY MCP - SECURE TOKEN GENERATOR
============================================================

Generated Token:
  aB3dEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEf
  Length: 48 chars
  Entropy: 286 bits

CONFIGURATION
============================================================

Add this to your .env file:

MCP_TRANSPORT=sse
MCP_HOST=0.0.0.0
MCP_ALLOW_REMOTE=true
MCP_AUTH_TOKEN=aB3dEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEf
```

**💡 Copy that token** (the long string) - you'll need it twice.

### Step 3: Create the Configuration File

Still on your VM, create the `.env` file:

```bash
# Create the config file (replace YOUR_TOKEN with the actual token)
cat > .env << 'EOF'
MCP_TRANSPORT=sse
MCP_HOST=0.0.0.0
MCP_PORT=3000
MCP_ALLOW_REMOTE=true
MCP_AUTH_TOKEN=YOUR_TOKEN_HERE
MCP_TLS_MODE=self_signed
EOF

# Secure the file (only you can read it)
chmod 600 .env
```

**📝 What these settings mean:**
- `MCP_TRANSPORT=sse` - Use network instead of local pipes
- `MCP_HOST=0.0.0.0` - Accept connections from any IP
- `MCP_AUTH_TOKEN` - Your secret password from Step 2
- `MCP_TLS_MODE=self_signed` - Encrypt connections (auto-generated certificate)

### Step 4: Start the Server

```bash
python -m src.server
```

**You should see:**
```
[INFO] Starting Binary MCP Server...
[INFO] Transport: sse
[INFO] Bind: 0.0.0.0:3000
[INFO] Authentication: enabled

SECURITY WARNING: Remote Access Enabled
============================================================
ℹ️  Using self-signed certificate.
   Clients must verify certificate fingerprint out-of-band.

[INFO] SSE server listening on https://0.0.0.0:3000
```

**✅ Success!** Your VM is now listening for connections.

**🔒 Important:** This server will only accept connections that:
1. Have the correct token
2. Come from the allowed network
3. Use encrypted connections

---

## 💻 Step 5: Connect Your Host Computer

### Find Your VM's IP Address

On the VM, run:
```bash
# Linux/macOS:
ip addr show | grep "inet " | head -2

# Windows (PowerShell):
Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"} | Select IPAddress
```

Look for an IP like `192.168.1.100` or `10.0.0.50`.

### Configure Claude Desktop

Edit your Claude Desktop configuration:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows:** `%APPDATA%/Claude/claude_desktop_config.json`

**Linux:** `~/.config/claude/claude_desktop_config.json`


**Add this** (replace `192.168.1.100` with your VM's IP, and `YOUR_TOKEN` with your token):

```json
{
  "mcpServers": {
    "binary-analysis-vm": {
      "url": "https://192.168.1.100:3000/sse",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      }
    }
  }
}
```

**⚠️ Note:** Claude Desktop's SSE support varies by version. If this doesn't work, see the Bridge Script section below.

### Restart Claude Desktop

1. Quit Claude Desktop completely
2. Restart it
3. Open a new conversation
4. Test with: "What analysis tools are available?"

You should see your tools listed - this means you're connected!

---

## 🔧 Bridge Script (If Claude Desktop Doesn't Support SSE Directly)

Some versions of Claude Desktop only support `stdio` (local) connections. Use this bridge script to forward to your remote server:

### 1. Create the Bridge File

Save this as `mcp_bridge.py` on your **host** computer:

```python
#!/usr/bin/env python3
"""Bridge from stdio to remote SSE MCP server."""

import json
import sys
import requests
import urllib3

# 🔧 CONFIGURATION - EDIT THESE
SERVER_URL = "https://192.168.1.100:3000"  # Your VM's IP
AUTH_TOKEN = "YOUR_TOKEN_HERE"             # Token from Step 2
VERIFY_SSL = False  # True if using proper certificate

# Disable SSL warnings for self-signed certs (verify fingerprint separately!)
urllib3.disable_warnings()

def main():
    headers = {
        "Authorization": f"Bearer {AUTH_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # Read from stdin (Claude), forward to server
    for line in sys.stdin:
        try:
            request = json.loads(line)
            
            response = requests.post(
                f"{SERVER_URL}/message",
                headers=headers,
                json=request,
                verify=VERIFY_SSL,
                timeout=30
            )
            
            if response.status_code == 200:
                print(json.dumps(response.json()), flush=True)
            else:
                error = {"error": f"Server error: {response.status_code}"}
                print(json.dumps(error), flush=True)
                
        except Exception as e:
            print(json.dumps({"error": str(e)}), flush=True)

if __name__ == "__main__":
    main()
```

**Edit the file** and set:
- `SERVER_URL` to your VM's IP address
- `AUTH_TOKEN` to your generated token

### 2. Use Bridge in Claude Config

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

## 🆘 Troubleshooting

### "Authentication required" Error

**What happened:** Your token is missing or wrong.

**Fix:**
1. Check your `.env` file on the VM: `grep MCP_AUTH_TOKEN .env`
2. Make sure the token in Claude config matches exactly
3. If unsure, generate a new token: `python scripts/generate_token.py`

---

### "TLS required" Error

**What happened:** Trying to use remote without encryption.

**Fix on VM:**
```bash
# Edit .env and add:
echo "MCP_TLS_MODE=self_signed" >> .env

# Restart the server
python -m src.server
```

---

### "IP not in allowlist" Error

**What happened:** Your host computer's IP isn't allowed.

**Fix on VM:**
```bash
# Check your host IP (on host computer):
# macOS/Linux: ip addr show
# Windows: ipconfig

# Then add it to .env on VM:
echo "MCP_ALLOWED_IPS=192.168.1.0/24" >> .env
# (Replace with your actual network, or remove line to allow all)
```

---

### "Port in use" Error

**What happened:** Another program is using port 3000.

**Fix:**
```bash
# Use a different port in .env:
echo "MCP_PORT=3001" >> .env

# Then update Claude config to use :3001
```

---

### "Certificate verify failed" Error

**What happened:** Self-signed certificates aren't trusted by default.

**Quick fix (development only):**
- With bridge script: Set `VERIFY_SSL = False`
- With direct SSE: Client needs to skip verification (depends on client)

**Proper fix:**
Use a real certificate (Let's Encrypt or internal CA).

---

## 🧪 Testing Your Setup

### Test from Host to VM

```bash
# Replace with your VM's IP and token
curl -k -H "Authorization: Bearer YOUR_TOKEN" \
  https://192.168.1.100:3000/sse

# Should connect and show SSE stream (Ctrl+C to stop)
```

### Check Server is Running

On the VM:
```bash
# See if process is listening on port 3000
netstat -tlnp | grep 3000
# or
ss -tlnp | grep 3000
```

### Check Logs

On the VM:
```bash
# Server logs show connections
# Audit logs show who connected
tail -f ~/.binary_mcp_output/audit/audit-*.log
```

---

## 📊 Architecture Overview

```
┌─────────────────────────┐         ┌─────────────────────────────────────┐
│    💻 YOUR COMPUTER      │         │      🖥️ VM (Analysis Server)        │
│                          │         │                                     │
│  ┌───────────────────┐   │  🔒 TLS │  ┌─────────────────────────────┐  │
│  │                   │   │   +     │  │                             │  │
│  │  Claude Desktop   │◄──┼──Auth──┼──┼►│  Binary MCP Server          │  │
│  │                   │   │         │  │                             │  │
│  └───────────────────┘   │         │  │  • Ghidra                   │  │
│                          │         │  │  • x64dbg                   │  │
│  Clean Environment       │         │  │  • WinDbg                   │  │
│  ✓ No Java needed        │         │  │  • PE analysis tools          │  │
│  ✓ No heavy tools        │         │  │                             │  │
│  ✓ No malware risk       │         │  │  Isolated & Safe            │  │
│                          │         │  │  ✓ Malware in sandbox       │  │
│                          │         │  │  ✓ Snapshot before/after    │  │
└─────────────────────────┘         │  └─────────────────────────────┘  │
                                    └─────────────────────────────────────┘

You ask Claude:                    Server executes:
"Analyze this malware"      →     Ghidra decompiles in VM
"Set breakpoint at X"       →     x64dbg pauses in VM
"Dump memory region"        →     VM extracts, returns data
```

---

## 📁 Important Files

| File | Location | What it's for |
|------|----------|---------------|
| `.env` | On VM | Your secrets (token, settings) - **keep secure!** |
| `~/.binary_mcp_output/tls/` | On VM | Auto-generated certificates |
| `~/.binary_mcp_output/audit/` | On VM | Connection logs |
| `claude_desktop_config.json` | On Host | Claude's connection settings |
| `mcp_bridge.py` | On Host | If using bridge script |

---

## ⚡ Quick Commands Cheat Sheet

```bash
# Generate new token
python scripts/generate_token.py

# Validate token strength
python scripts/generate_token.py --validate YOUR_TOKEN

# View certificate fingerprint (for verification)
python -c "from src.utils.tls import get_certificate_fingerprint
from pathlib import Path
print(get_certificate_fingerprint(Path.home() / '.binary_mcp_output' / 'tls' / 'server.crt'))"

# Check recent connections
tail -f ~/.binary_mcp_output/audit/audit-*.log

# Test server from host
curl -k -H "Authorization: Bearer TOKEN" https://VM_IP:3000/sse
```

---

## 🔒 Security Checklist

Before using in production:

- [ ] **Regenerated token** - Don't use example/demo tokens
- [ ] **Secured .env file** - Run `chmod 600 .env`
- [ ] **Restricted IP access** - Set `MCP_ALLOWED_IPS` to your network
- [ ] **Firewall rules** - VM only allows port 3000 from your network
- [ ] **Audit logging enabled** - Check `~/.binary_mcp_output/audit/`
- [ ] **VM snapshot created** - Before analyzing any malware
- [ ] **Token backed up safely** - You'll need it for all clients

---

## ❓ Still Stuck?

1. **Check the full guide:** `docs/remote-usage-guide.md`
2. **Check security docs:** `docs/security.md`
3. **Check server logs:** Look at output from `python -m src.server`
4. **Check audit logs:** `tail -f ~/.binary_mcp_output/audit/*.log`

**Common issues:**
- Token mismatch between VM and host
- Firewall blocking port 3000
- Wrong IP address in Claude config
- Using `http://` instead of `https://`

---

**🎉 Once working, using remote analysis feels exactly like local - just ask Claude!**
