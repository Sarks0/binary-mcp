# Binary MCP Server - Windows Installer
# Automated installation script for Windows with Ghidra and x64dbg support

#Requires -RunAsAdministrator

param(
    [string]$InstallDir = "$env:USERPROFILE\binary-mcp",
    [string]$GhidraDir = "$env:USERPROFILE\ghidra",
    [string]$X64DbgDir = "$env:USERPROFILE\x64dbg",
    [switch]$SkipGhidra,
    [switch]$SkipX64Dbg,
    [switch]$NoClaudeConfig
)

$ErrorActionPreference = "Stop"

# Colors for output
function Write-Success { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "[i] $msg" -ForegroundColor Cyan }
function Write-Warning { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Error { param($msg) Write-Host "[X] $msg" -ForegroundColor Red }

function Test-Command {
    param($CommandName)
    return $null -ne (Get-Command $CommandName -ErrorAction SilentlyContinue)
}

function Get-LatestGitHubRelease {
    param($Repo)

    try {
        $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
        return $release
    } catch {
        Write-Error "Failed to fetch latest release for $Repo"
        throw
    }
}

# Banner
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      Binary MCP Server - Automated Installer              ║" -ForegroundColor Cyan
Write-Host "║      Static (Ghidra) + Dynamic (x64dbg) Analysis          ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check prerequisites
Write-Info "Checking prerequisites..."

# Check Python
if (Test-Command python) {
    $pythonVersion = python --version 2>&1 | Select-String -Pattern "(\d+\.\d+)"
    $version = [version]$pythonVersion.Matches.Groups[1].Value
    if ($version -ge [version]"3.12") {
        Write-Success "Python $version found"
    } else {
        Write-Warning "Python $version found, but 3.12+ recommended"
        Write-Info "Download Python 3.12+ from: https://www.python.org/downloads/"
        $continue = Read-Host "Continue anyway? (y/n)"
        if ($continue -ne "y") { exit 1 }
    }
} else {
    Write-Error "Python not found!"
    Write-Info "Please install Python 3.12+ from: https://www.python.org/downloads/"
    Write-Info "Make sure to check 'Add Python to PATH' during installation"
    exit 1
}

# Check/Install uv
Write-Info "Checking uv package manager..."
if (Test-Command uv) {
    Write-Success "uv already installed"
} else {
    Write-Info "Installing uv..."
    try {
        Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","User") + ";" + [System.Environment]::GetEnvironmentVariable("Path","Machine")
        Write-Success "uv installed successfully"
    } catch {
        Write-Error "Failed to install uv: $_"
        exit 1
    }
}

# Check Java (required for Ghidra)
if (-not $SkipGhidra) {
    Write-Info "Checking Java..."
    if (Test-Command java) {
        $javaVersion = java -version 2>&1 | Select-String -Pattern "version"
        Write-Success "Java found: $javaVersion"
    } else {
        Write-Warning "Java not found - required for Ghidra"
        Write-Info "Download Java 17+ from: https://adoptium.net/"
        $installJava = Read-Host "Skip Ghidra installation? (y/n)"
        if ($installJava -eq "y") {
            $SkipGhidra = $true
        } else {
            Write-Error "Please install Java and run this script again"
            exit 1
        }
    }
}

# Install Ghidra
if (-not $SkipGhidra) {
    Write-Info "Installing Ghidra..."

    if (Test-Path $GhidraDir) {
        Write-Warning "Ghidra directory already exists: $GhidraDir"
        $reinstall = Read-Host "Reinstall Ghidra? (y/n)"
        if ($reinstall -ne "y") {
            Write-Info "Skipping Ghidra installation"
        } else {
            Remove-Item -Recurse -Force $GhidraDir
        }
    }

    if (-not (Test-Path $GhidraDir)) {
        Write-Info "Fetching latest Ghidra release..."

        # Ghidra releases are on GitHub
        $ghidraRelease = Get-LatestGitHubRelease "NationalSecurityAgency/ghidra"
        $ghidraAsset = $ghidraRelease.assets | Where-Object { $_.name -match ".*\.zip$" -and $_.name -notmatch "DEV" } | Select-Object -First 1

        if ($null -eq $ghidraAsset) {
            Write-Error "Could not find Ghidra release asset"
            $SkipGhidra = $true
        } else {
            Write-Info "Downloading Ghidra $($ghidraRelease.tag_name)..."
            $ghidraZip = "$env:TEMP\ghidra.zip"

            try {
                Invoke-WebRequest -Uri $ghidraAsset.browser_download_url -OutFile $ghidraZip -UseBasicParsing
                Write-Success "Downloaded Ghidra"

                Write-Info "Extracting Ghidra..."
                Expand-Archive -Path $ghidraZip -DestinationPath "$env:USERPROFILE" -Force

                # Find extracted directory (format: ghidra_x.x.x_PUBLIC_YYYYMMDD)
                $extractedDir = Get-ChildItem "$env:USERPROFILE" -Directory | Where-Object { $_.Name -match "^ghidra_.*_PUBLIC" } | Select-Object -First 1

                if ($extractedDir) {
                    Rename-Item $extractedDir.FullName $GhidraDir
                    Write-Success "Ghidra installed to: $GhidraDir"

                    # Set environment variable
                    [System.Environment]::SetEnvironmentVariable("GHIDRA_HOME", $GhidraDir, "User")
                    $env:GHIDRA_HOME = $GhidraDir
                } else {
                    Write-Error "Could not find extracted Ghidra directory"
                }

                Remove-Item $ghidraZip -ErrorAction SilentlyContinue
            } catch {
                Write-Error "Failed to install Ghidra: $_"
                $SkipGhidra = $true
            }
        }
    }
}

# Install x64dbg
if (-not $SkipX64Dbg) {
    Write-Info "Installing x64dbg..."

    if (Test-Path $X64DbgDir) {
        Write-Warning "x64dbg directory already exists: $X64DbgDir"
        $reinstall = Read-Host "Reinstall x64dbg? (y/n)"
        if ($reinstall -ne "y") {
            Write-Info "Skipping x64dbg installation"
        } else {
            Remove-Item -Recurse -Force $X64DbgDir
        }
    }

    if (-not (Test-Path $X64DbgDir)) {
        Write-Info "Fetching latest x64dbg snapshot..."

        try {
            $x64dbgUrl = "https://github.com/x64dbg/x64dbg/releases/download/snapshot/snapshot_latest.zip"
            $x64dbgZip = "$env:TEMP\x64dbg.zip"

            Write-Info "Downloading x64dbg..."
            Invoke-WebRequest -Uri $x64dbgUrl -OutFile $x64dbgZip -UseBasicParsing
            Write-Success "Downloaded x64dbg"

            Write-Info "Extracting x64dbg..."
            Expand-Archive -Path $x64dbgZip -DestinationPath $X64DbgDir -Force
            Write-Success "x64dbg installed to: $X64DbgDir"

            # Set environment variable
            [System.Environment]::SetEnvironmentVariable("X64DBG_HOME", $X64DbgDir, "User")
            $env:X64DBG_HOME = $X64DbgDir

            Remove-Item $x64dbgZip -ErrorAction SilentlyContinue
        } catch {
            Write-Error "Failed to install x64dbg: $_"
            $SkipX64Dbg = $true
        }
    }
}

# Clone/Setup project
Write-Info "Setting up Binary MCP Server..."

if (Test-Path $InstallDir) {
    Write-Warning "Installation directory already exists: $InstallDir"
    $continue = Read-Host "Continue and update? (y/n)"
    if ($continue -ne "y") {
        Write-Info "Installation cancelled"
        exit 0
    }
} else {
    Write-Info "Creating installation directory..."
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

Push-Location $InstallDir

# Check if git repo exists
if (Test-Path ".git") {
    Write-Info "Updating existing repository..."
    git pull
} else {
    Write-Info "Cloning repository..."
    if (Test-Command git) {
        git clone https://github.com/Sarks0/binary-mcp.git .
    } else {
        Write-Warning "Git not found. Downloading as ZIP..."
        $zipUrl = "https://github.com/Sarks0/binary-mcp/archive/refs/heads/main.zip"
        $zipFile = "$env:TEMP\binary-mcp.zip"
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing
        Expand-Archive -Path $zipFile -DestinationPath $InstallDir -Force
        Move-Item "$InstallDir\binary-mcp-main\*" $InstallDir -Force
        Remove-Item "$InstallDir\binary-mcp-main" -Recurse -Force
        Remove-Item $zipFile -ErrorAction SilentlyContinue
    }
}

Write-Success "Repository ready"

# Install Python dependencies
Write-Info "Installing Python dependencies..."
try {
    uv sync --extra dev
    Write-Success "Dependencies installed"
} catch {
    Write-Error "Failed to install dependencies: $_"
    exit 1
}

# Configure Claude Desktop
if (-not $NoClaudeConfig) {
    Write-Info "Configuring Claude Desktop..."

    $claudeConfigDir = "$env:APPDATA\Claude"
    $claudeConfigFile = "$claudeConfigDir\claude_desktop_config.json"

    if (Test-Path $claudeConfigFile) {
        Write-Info "Claude Desktop config found"

        try {
            $config = Get-Content $claudeConfigFile -Raw | ConvertFrom-Json

            if (-not $config.mcpServers) {
                $config | Add-Member -MemberType NoteProperty -Name "mcpServers" -Value @{} -Force
            }

            # Add binary-mcp server
            $config.mcpServers | Add-Member -MemberType NoteProperty -Name "binary-mcp" -Value @{
                command = "uv"
                args = @("--directory", $InstallDir, "run", "python", "-m", "src.server")
            } -Force

            # Backup existing config
            Copy-Item $claudeConfigFile "$claudeConfigFile.backup" -Force

            # Save new config
            $config | ConvertTo-Json -Depth 10 | Set-Content $claudeConfigFile

            Write-Success "Claude Desktop configured"
            Write-Info "Backup saved to: $claudeConfigFile.backup"
        } catch {
            Write-Warning "Failed to configure Claude Desktop: $_"
            Write-Info "You can manually configure it later"
        }
    } else {
        Write-Warning "Claude Desktop config not found"
        Write-Info "Expected location: $claudeConfigFile"
        Write-Info "You'll need to manually configure Claude Desktop after installation"
    }
}

Pop-Location

# Verify installation
Write-Info "Verifying installation..."

$allGood = $true

if (-not (Test-Path $InstallDir)) {
    Write-Error "Installation directory not found"
    $allGood = $false
}

if (-not $SkipGhidra -and -not (Test-Path $GhidraDir)) {
    Write-Warning "Ghidra not installed"
}

if (-not $SkipX64Dbg -and -not (Test-Path $X64DbgDir)) {
    Write-Warning "x64dbg not installed"
}

# Summary
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              Installation Complete!                       ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

Write-Success "Binary MCP Server installed to: $InstallDir"

if (-not $SkipGhidra) {
    Write-Success "Ghidra installed to: $GhidraDir"
}

if (-not $SkipX64Dbg) {
    Write-Success "x64dbg installed to: $X64DbgDir"
}

Write-Host ""
Write-Info "Next steps:"
Write-Host "  1. Restart Claude Desktop to load the MCP server" -ForegroundColor White
Write-Host "  2. Test the server: " -ForegroundColor White -NoNewline
Write-Host "cd $InstallDir && uv run python -m src.server" -ForegroundColor Yellow
Write-Host "  3. Use binary analysis tools in Claude conversations!" -ForegroundColor White
Write-Host ""

if (-not $NoClaudeConfig) {
    Write-Info "Configuration added to Claude Desktop"
    Write-Info "Restart Claude Desktop to activate the MCP server"
}

Write-Host ""
Write-Success "Installation finished successfully!"
Write-Host ""
