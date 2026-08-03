# Binary MCP Server - Installation Guide

Complete automated installation guide for Windows, Linux, and macOS.

## Quick Start

### Method 1: Clone & Run (Recommended)

**Linux / macOS:**
```bash
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp
python3 install.py
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp
.\install.ps1
```

### Method 2: Direct Download

Download the installer, look at it, then run it. This is the recommended form
of Method 2 — see [Supply-Chain Integrity](#supply-chain-integrity) for why the
one-line `curl | python3 -` / `irm | iex` variants are worth avoiding.

**Linux / macOS:**
```bash
curl -fsSLO https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.py

# Record what you actually received, and read it before running it
sha256sum install.py
less install.py

chmod +x install.py
python3 install.py
```

**Windows (PowerShell):**
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Sarks0/binary-mcp/main/install.ps1" -OutFile "install.ps1"

# Record what you actually received, and read it before running it
Get-FileHash .\install.ps1 -Algorithm SHA256
notepad .\install.ps1

.\install.ps1
```

Compare the digest against the one for the same commit in the repository
(`git show <commit>:install.ps1 | sha256sum`, or the checksums published with a
release) if you want to confirm you got the file the project published.

**Note:** If you get a 404 error, GitHub's CDN may still be updating. Use Method 1 instead.

---

## Supply-Chain Integrity

The installers download third-party tooling (uv, Ghidra, x64dbg, the Windows
SDK debuggers) and this project's own x64dbg bridge plugins, and `install.ps1`
requires Administrator. It is worth knowing exactly what that trusts.

### Why `curl … | sh` and `irm … | iex` are worth avoiding

Both installers are fetched over HTTPS, and both force TLS 1.2+ for their own
downloads. TLS establishes *who served* the bytes; it does not establish *which*
bytes were served. Piping a URL straight into an interpreter executes whatever
came back immediately — there is no copy on disk to inspect, nothing to compare
a digest against, and no record afterwards of what ran. A tampered mirror or
release asset, or an interception proxy whose root certificate the machine
already trusts, is enough for that to be attacker-chosen code. On Windows it
would run elevated.

The download-inspect-then-run flow above costs one extra command and removes
that whole class of problem. The same applies to any vendor one-liner, including
uv's:

```bash
# Instead of: curl -LsSf https://astral.sh/uv/install.sh | sh
curl -LsSf -o uv-install.sh https://astral.sh/uv/install.sh
sha256sum uv-install.sh          # record it; compare across machines/runs
less uv-install.sh
sh uv-install.sh
```

```powershell
# Instead of: irm https://astral.sh/uv/install.ps1 | iex
Invoke-WebRequest -Uri https://astral.sh/uv/install.ps1 -OutFile uv-install.ps1 -UseBasicParsing
Get-FileHash .\uv-install.ps1 -Algorithm SHA256
notepad .\uv-install.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\uv-install.ps1
```

The installers in this repository do exactly that internally: they never pipe a
downloaded script into an interpreter.

### What the installers verify

> **Status — what is and is not actually checked.** `.github/workflows/release.yml`
> now generates a `SHA256SUMS` manifest in the same job that uploads the release
> assets, and publishes it as a release asset. `install.ps1` reads that manifest
> and verifies `obsidian.dp64`, `obsidian.dp32` and `obsidian_server.exe`
> against it before copying anything into the x64dbg plugins directory; if the
> manifest is present but does not list an asset, the plugin install **aborts**
> rather than falling back to installing it unchecked.
>
> Two limits are worth stating plainly:
>
> - **Releases published before that workflow change carry no `SHA256SUMS`.**
>   Installing plugins from one of those releases still prints the loud
>   unverified-download warning and installs them without a trusted digest. Pin
>   the digests yourself (see "Pinning a hash") or build the plugins from source
>   if you need assurance on an older release.
> - **A manifest published in the same release as the assets does not survive a
>   takeover of the release itself.** It defeats tampering with an individual
>   asset or its CDN copy. Only a pinned digest — one you obtained out of band —
>   defends against a compromised release.
>
> The plugin binaries are also **not code-signed**, so the Authenticode check on
> them is informational (see the note under the table).

| Artifact | How it is verified |
|---|---|
| binary-mcp release assets (`obsidian.dp64`, `obsidian.dp32`, `obsidian_server.exe`) | SHA-256 against the `SHA256SUMS` manifest published with the GitHub release, or an operator-pinned hash. Fails closed if the manifest exists but omits the asset. Releases predating the manifest are installed unverified, with a warning |
| Ghidra release zip | SHA-256 from the checksum published with the Ghidra release, or an operator-pinned hash |
| x64dbg snapshot zip | Operator-pinned hash (the `snapshot` tag is a rolling build with no fixed digest) |
| uv / .NET install scripts | Operator-pinned hash only — astral.sh and dot.net publish no stable digest. Without a pin the script is written to disk, flagged loudly as unverified, and then run (refused under strict mode); it is never piped into an interpreter. On Windows its Mark-of-the-Web is left intact unless the hash verified |
| Windows SDK bootstrapper | Authenticode signature, required to be valid and issued to Microsoft Corporation. A bad or missing signature **aborts** — the bootstrapper is otherwise run with Administrator rights. An operator-pinned hash is optional and additional |
| `main` branch source zip | Cannot be verified — a branch archive changes with every push. Prefer the `git clone` path, which the installer already uses when git is present |

Anything that cannot be verified produces a loud, explicit warning naming the
artifact, the URL, and the SHA-256 that was actually downloaded — the installer
does not skip the check quietly.

**About the Authenticode check on the plugins.** `install.ps1` runs
`Get-AuthenticodeSignature` over each staged plugin binary, but Windows
dispatches signature checks by file *extension* and does not recognise
`.dp64`/`.dp32`, so it reports `UnknownError` — "cannot evaluate", not "bad
signature". The installer treats that (and a plain unsigned `.exe`) as *no
signature information*, and does not fail on it. **The plugins' integrity rests
entirely on the SHA-256 check**, which is why the `SHA256SUMS` manifest matters.

### Verifying a release yourself

Releases built by the current workflow publish a `SHA256SUMS` asset covering the
three plugin binaries and the release zip. (Releases predating that change do
not have one — check the asset list.)

```bash
# download SHA256SUMS plus the assets you want, into the same directory
sha256sum -c SHA256SUMS
```

```powershell
Get-FileHash .\obsidian.dp64 -Algorithm SHA256    # compare against SHA256SUMS
```

### Pinning a hash

Set `BINARY_MCP_SHA256_<KEY>` before running the installer to require an exact
digest for an artifact, overriding whatever the publisher's manifest says. The
warning printed for an unverified download tells you the variable name and the
digest to use. The full set:

| Artifact | Environment variable | Installer |
|---|---|---|
| `obsidian.dp64` (x64dbg plugin) | `BINARY_MCP_SHA256_BINARY_MCP_OBSIDIAN_DP64` | `install.ps1` |
| `obsidian.dp32` (x64dbg plugin) | `BINARY_MCP_SHA256_BINARY_MCP_OBSIDIAN_DP32` | `install.ps1` |
| `obsidian_server.exe` | `BINARY_MCP_SHA256_BINARY_MCP_OBSIDIAN_SERVER_EXE` | `install.ps1` |
| Ghidra release zip | `BINARY_MCP_SHA256_GHIDRA_ZIP` | both |
| x64dbg snapshot zip | `BINARY_MCP_SHA256_X64DBG_SNAPSHOT` | `install.ps1` |
| uv installer (`install.ps1` flavour) | `BINARY_MCP_SHA256_UV_INSTALLER_PS1` | `install.ps1` |
| uv installer (`install.sh` flavour) | `BINARY_MCP_SHA256_UV_INSTALLER_SH` | `install.py` |
| .NET install script | `BINARY_MCP_SHA256_DOTNET_INSTALLER_SH` | `install.py` |
| Windows SDK bootstrapper | `BINARY_MCP_SHA256_WINDOWS_SDK_SETUP` | `install.ps1` |
| `main` branch source zip | `BINARY_MCP_SHA256_REPO_ZIP` | both |

The three `obsidian` entries are the only pins that override this project's own
published `SHA256SUMS`. Use them when you want a digest you obtained out of band
to win over the release — that is the only thing that survives a takeover of the
release itself.

**Linux / macOS:**
```bash
export BINARY_MCP_SHA256_GHIDRA_ZIP=<64-hex-digest>
export BINARY_MCP_SHA256_UV_INSTALLER_SH=<64-hex-digest>
python3 install.py
```

**Windows (PowerShell):**
```powershell
$env:BINARY_MCP_SHA256_GHIDRA_ZIP = "<64-hex-digest>"
$env:BINARY_MCP_SHA256_X64DBG_SNAPSHOT = "<64-hex-digest>"
$env:BINARY_MCP_SHA256_BINARY_MCP_OBSIDIAN_DP64 = "<64-hex-digest>"
.\install.ps1
```

If a digest does not match, the downloaded file is deleted and the installer
stops with the expected and actual values.

### Strict mode

To refuse anything that cannot be verified, rather than warn about it:

```powershell
.\install.ps1 -StrictIntegrity
```

```bash
python3 install.py --strict-integrity
# or: BINARY_MCP_STRICT_INTEGRITY=1 python3 install.py
```

In strict mode an unverifiable download aborts the affected component. Expect to
need pins for the rolling artifacts (x64dbg snapshot, the uv/.NET install
scripts) for a strict install to complete.

---

## What Gets Installed

### Core Components (All Platforms)
- [OK] **Python 3.12+** (verified, not installed by script)
- [OK] **uv** - Fast Python package manager
- [OK] **Binary MCP Server** - The main server with all dependencies
- [OK] **Claude Desktop Integration** - Automatic MCP configuration

### Platform-Specific Tools

#### Windows
- [OK] **Ghidra** - Static analysis (NSA reverse engineering framework)
- [OK] **x64dbg** - Dynamic analysis (debugger for Windows binaries)
- [OK] **Java 17+** (required for Ghidra, verified only)

#### Linux / macOS
- [OK] **Ghidra** - Static analysis
- [OK] **Java 17+** (required for Ghidra, verified only)

---

## Installation Options

### Windows PowerShell Options

```powershell
# Custom installation directory
.\install.ps1 -InstallDir "C:\Tools\binary-mcp"

# Custom Ghidra location
.\install.ps1 -GhidraDir "C:\Tools\ghidra"

# Skip Ghidra installation
.\install.ps1 -SkipGhidra

# Skip x64dbg installation
.\install.ps1 -SkipX64Dbg

# Don't configure Claude Desktop
.\install.ps1 -NoClaudeConfig

# Refuse any download that cannot be integrity-checked (see Supply-Chain Integrity)
.\install.ps1 -StrictIntegrity

# Combine options
.\install.ps1 -InstallDir "C:\binary-mcp" -SkipX64Dbg
```

### Linux/macOS Python Options

```bash
# Custom installation directory
python3 install.py --install-dir ~/my-binary-mcp

# Skip Ghidra installation
python3 install.py --skip-ghidra

# Don't configure Claude Desktop
python3 install.py --no-claude-config

# Combine options
python3 install.py --install-dir /opt/binary-mcp --skip-ghidra
```

---

## Prerequisites

### All Platforms
- **Python 3.12+** - [Download here](https://www.python.org/downloads/)
- **Internet connection** - For downloading components
- **~2 GB disk space** - For all tools and dependencies

### Windows Specific
- **PowerShell 5.1+** - Built into Windows 10/11
- **Administrator privileges** - For system-wide installation
- **.NET Framework 4.8+** - Usually pre-installed

### Linux/macOS Specific
- **curl** - Usually pre-installed
- **build-essential** (Linux) / **Xcode Command Line Tools** (macOS)

---

## Manual Installation Steps

If you prefer manual installation or the automated scripts fail:

### 1. Install Python 3.12+

**Windows:**
```powershell
winget install Python.Python.3.12
```

**macOS:**
```bash
brew install python@3.12
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install python3.12 python3-pip
```

### 2. Install uv Package Manager

**All Platforms:**
```bash
curl -LsSf -o uv-install.sh https://astral.sh/uv/install.sh
sha256sum uv-install.sh    # record/compare before running
sh uv-install.sh
```

**Windows (PowerShell):**
```powershell
Invoke-WebRequest -Uri https://astral.sh/uv/install.ps1 -OutFile uv-install.ps1 -UseBasicParsing
Get-FileHash .\uv-install.ps1 -Algorithm SHA256    # record/compare before running
powershell -NoProfile -ExecutionPolicy Bypass -File .\uv-install.ps1
```

The vendor's documented one-liners (`curl … | sh`, `irm … | iex`) do the same
thing without the inspection step — see [Supply-Chain
Integrity](#supply-chain-integrity).

### 3. Clone Repository

```bash
git clone https://github.com/Sarks0/binary-mcp.git
cd binary-mcp
```

### 4. Install Dependencies

```bash
uv sync --extra dev
```

### 5. Install Ghidra (Optional)

**Download:** https://github.com/NationalSecurityAgency/ghidra/releases/latest

Extract to your preferred location and set environment variable:

**Windows:**
```powershell
$env:GHIDRA_HOME = "C:\path\to\ghidra"
```

**Linux/macOS:**
```bash
export GHIDRA_HOME=/path/to/ghidra
```

#### Ghidra 12.1+: Activate the Jython Extension

Ghidra 12.1 unbundled Jython, which binary-mcp uses for its analysis scripts. The installer scripts do this automatically. If you installed Ghidra manually, activate the bundled Jython extension before first use — either via the Ghidra Front End (**File → Install Extensions → check Jython → restart**), or by extracting the bundled zip directly:

The bundled archive ships under `Extensions/Ghidra/` and is extracted into the install-tree extensions dir `Ghidra/Extensions/`:

**Windows:**
```powershell
Expand-Archive -Path "$env:GHIDRA_HOME\Extensions\Ghidra\*Jython*.zip" -DestinationPath "$env:GHIDRA_HOME\Ghidra\Extensions\"
```

**Linux/macOS:**
```bash
unzip "$GHIDRA_HOME"/Extensions/Ghidra/*Jython*.zip -d "$GHIDRA_HOME"/Ghidra/Extensions/
```

Ghidra 12.0.x and earlier ship with Jython built in — no extra step needed.

### 6. Install x64dbg (Windows Only, Optional)

**Download:** https://github.com/x64dbg/x64dbg/releases/latest

Extract to your preferred location and set environment variable:

```powershell
$env:X64DBG_HOME = "C:\path\to\x64dbg"
```

### 7. Configure Claude Desktop

**Location:**
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux:** `~/.config/claude/claude_desktop_config.json`

**Configuration:**
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

---

## Verification

After installation, verify everything works:

### 1. Test the Server

```bash
cd ~/binary-mcp
uv run python -m src.server
```

You should see:
```
[INFO] Starting Binary MCP Server...
[INFO] Ghidra detected: /path/to/ghidra
[INFO] Server ready
```

Press `Ctrl+C` to stop.

### 2. Test Ghidra Integration

```bash
cd ~/binary-mcp
uv run python -c "from src.engines.static.ghidra.runner import GhidraRunner; r = GhidraRunner(); print(r.diagnose())"
```

### 3. Test in Claude Desktop

1. **Restart Claude Desktop**
2. Open a new conversation
3. Try: "What binary analysis tools are available?"
4. The server should respond with available tools

---

## Troubleshooting

### Windows Issues

**"Execution policy" error:**
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

**"uv not found" after installation:**
- Restart PowerShell/Terminal
- Or manually add to PATH: `C:\Users\<YourName>\.local\bin`

**x64dbg plugin build fails:**
- Install Visual Studio 2022 with C++ tools
- Or skip dynamic analysis: `.\install.ps1 -SkipX64Dbg`

### Linux/macOS Issues

**"Permission denied" error:**
```bash
chmod +x install.py
```

**Python version too old:**
```bash
# Ubuntu/Debian
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.12

# macOS
brew install python@3.12
```

**Ghidra won't start:**
- Ensure Java 17+ is installed: `java -version`
- Install from: https://adoptium.net/

### Common Issues

**"Claude Desktop config not found":**
- Install Claude Desktop first
- The config file is created on first launch
- Manually create the config file in the correct location

**"Port already in use":**
- Another MCP server might be running
- Change port in the configuration
- Or stop conflicting services

**Git clone fails:**
- The installer will automatically fall back to ZIP download
- Or manually download: https://github.com/Sarks0/binary-mcp/archive/main.zip

---

## Uninstallation

### Windows

```powershell
# Remove installation
Remove-Item -Recurse -Force "$env:USERPROFILE\binary-mcp"
Remove-Item -Recurse -Force "$env:USERPROFILE\ghidra"
Remove-Item -Recurse -Force "$env:USERPROFILE\x64dbg"

# Remove from Claude Desktop config
# Edit: %APPDATA%\Claude\claude_desktop_config.json
# Remove the "binary-mcp" entry from "mcpServers"
```

### Linux/macOS

```bash
# Remove installation
rm -rf ~/binary-mcp
rm -rf ~/ghidra

# Remove from Claude Desktop config
# Edit: ~/.config/claude/claude_desktop_config.json (Linux)
#   or: ~/Library/Application Support/Claude/claude_desktop_config.json (macOS)
# Remove the "binary-mcp" entry from "mcpServers"
```

---

## Upgrading

To update to the latest version:

### Windows
```powershell
cd $env:USERPROFILE\binary-mcp
git pull
uv sync --extra dev
```

### Linux/macOS
```bash
cd ~/binary-mcp
git pull
uv sync --extra dev
```

Or simply re-run the installer - it will update existing installations.

---

## Advanced Configuration

### Custom Environment Variables

**Windows:**
```powershell
# Persistent environment variables
[System.Environment]::SetEnvironmentVariable("GHIDRA_HOME", "C:\custom\ghidra", "User")
[System.Environment]::SetEnvironmentVariable("X64DBG_HOME", "C:\custom\x64dbg", "User")
```

**Linux/macOS:**
```bash
# Add to ~/.bashrc or ~/.zshrc
export GHIDRA_HOME="/custom/path/ghidra"
```

### MCP Server Configuration

The server can be configured via environment variables:

```bash
# Custom cache directory
export GHIDRA_MCP_CACHE="$HOME/custom-cache"

# Enable debug logging
export MCP_LOG_LEVEL="DEBUG"
```

### Running Multiple Instances

You can install multiple copies with different configurations:

```bash
# Production instance
python3 install.py --install-dir ~/binary-mcp-prod

# Development instance with custom Ghidra
python3 install.py --install-dir ~/binary-mcp-dev --ghidra-dir ~/ghidra-dev
```

---

## Getting Help

- **Documentation:** https://github.com/Sarks0/binary-mcp
- **Issues:** https://github.com/Sarks0/binary-mcp/issues
- **Discussions:** https://github.com/Sarks0/binary-mcp/discussions

---

## License

See [LICENSE](LICENSE) file for details.
