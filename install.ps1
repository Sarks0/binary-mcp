# Binary MCP Server - Windows Installer
# Interactive installation script with component selection

#Requires -RunAsAdministrator

param(
    [string]$InstallDir = "$env:USERPROFILE\binary-mcp",
    [string]$GhidraDir = "$env:USERPROFILE\ghidra",
    [string]$X64DbgDir = "$env:USERPROFILE\x64dbg",
    [ValidateSet("", "full", "static", "dynamic", "custom", "repair")]
    [string]$InstallProfile = "",  # full, static, dynamic, custom, repair
    [switch]$Unattended
)

$ErrorActionPreference = "Stop"

# Helper Functions

function Write-Success { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "[i] $msg" -ForegroundColor Cyan }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[X] $msg" -ForegroundColor Red }

function Test-Command {
    param($CommandName)
    return $null -ne (Get-Command $CommandName -ErrorAction SilentlyContinue)
}

function Test-WingetAvailable {
    return (Test-Command winget)
}

function Install-WithWinget {
    param(
        [string]$PackageId,
        [string]$PackageName
    )

    if (-not (Test-WingetAvailable)) {
        Write-Err "winget is not available. Please install manually."
        return $false
    }

    Write-Info "Installing $PackageName via winget..."
    try {
        $result = winget install --id $PackageId --accept-source-agreements --accept-package-agreements 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "$PackageName installed successfully"
            # Refresh PATH
            $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
            $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
            $env:Path = "$machinePath;$userPath"
            return $true
        } else {
            Write-Warn "winget returned: $result"
            return $false
        }
    } catch {
        Write-Err "Failed to install $PackageName : $_"
        return $false
    }
}

function Install-Python {
    Write-Info "Installing Python 3.12..."
    return Install-WithWinget -PackageId "Python.Python.3.12" -PackageName "Python 3.12"
}

function Install-Java {
    Write-Info "Installing Eclipse Temurin JDK 21 (Java)..."
    return Install-WithWinget -PackageId "EclipseAdoptium.Temurin.21.JDK" -PackageName "Eclipse Temurin JDK 21"
}

function Install-DotNetSDK {
    Write-Info "Installing .NET SDK 8.0..."
    return Install-WithWinget -PackageId "Microsoft.DotNet.SDK.8" -PackageName ".NET SDK 8.0"
}

function Install-DotNetRuntime {
    Write-Info "Installing .NET Runtime 8.0 (required for ILSpyCmd)..."
    return Install-WithWinget -PackageId "Microsoft.DotNet.Runtime.8" -PackageName ".NET Runtime 8.0"
}

function Install-Git {
    Write-Info "Installing Git..."
    return Install-WithWinget -PackageId "Git.Git" -PackageName "Git"
}

function Get-LatestGitHubRelease {
    param($Repo)
    try {
        $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
        return $release
    } catch {
        Write-Err "Failed to fetch latest release for $Repo"
        throw
    }
}

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ____  _                          __  __  ____ ____  " -ForegroundColor Magenta
    Write-Host " | __ )(_)_ __   __ _ _ __ _   _  |  \/  |/ ___|  _ \ " -ForegroundColor Magenta
    Write-Host " |  _ \| | '_ \ / _`` | '__| | | | | |\/| | |   | |_) |" -ForegroundColor Magenta
    Write-Host " | |_) | | | | | (_| | |  | |_| | | |  | | |___|  __/ " -ForegroundColor Magenta
    Write-Host " |____/|_|_| |_|\__,_|_|   \__, | |_|  |_|\____|_|    " -ForegroundColor Magenta
    Write-Host "                           |___/                      " -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  Binary Analysis MCP Server - Automated Installer" -ForegroundColor White
    Write-Host "  https://github.com/Sarks0/binary-mcp" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ================================================" -ForegroundColor DarkGray
    Write-Host ""
}

function Get-ComponentStatus {
    $status = @{
        Winget = @{ Installed = $false; Version = ""; Path = "" }
        Python = @{ Installed = $false; Version = ""; Path = "" }
        Java = @{ Installed = $false; Version = ""; Path = "" }
        DotNet = @{ Installed = $false; Version = ""; Path = "" }
        DotNet8Runtime = @{ Installed = $false; Version = ""; Path = "" }
        Git = @{ Installed = $false; Version = ""; Path = "" }
        UV = @{ Installed = $false; Version = ""; Path = "" }
        Ghidra = @{ Installed = $false; Version = ""; Path = $GhidraDir }
        ILSpyCmd = @{ Installed = $false; Version = ""; Path = "" }
        X64Dbg = @{ Installed = $false; Version = ""; Path = $X64DbgDir }
        BinaryMCP = @{ Installed = $false; Version = ""; Path = $InstallDir }
    }

    # Check winget
    if (Test-Command winget) {
        $status.Winget.Installed = $true
        try {
            $status.Winget.Version = (winget --version 2>&1).Trim()
        } catch {}
    }

    # Check Git
    if (Test-Command git) {
        $status.Git.Installed = $true
        try {
            $status.Git.Version = (git --version 2>&1).Trim()
            $status.Git.Path = (Get-Command git).Source
        } catch {}
    }

    # Check Python
    if (Test-Command python) {
        $status.Python.Installed = $true
        try {
            $pyVer = python --version 2>&1
            $status.Python.Version = ($pyVer -replace "Python ", "").Trim()
            $status.Python.Path = (Get-Command python).Source
        } catch {}
    }

    # Check Java
    if (Test-Command java) {
        $status.Java.Installed = $true
        try {
            $javaOutput = java -version 2>&1
            $status.Java.Version = (($javaOutput | Out-String) -split "`n" | Select-Object -First 1).Trim()
            $status.Java.Path = (Get-Command java).Source
        } catch {}
    }

    # Check .NET SDK
    if (Test-Command dotnet) {
        $status.DotNet.Installed = $true
        try {
            $status.DotNet.Version = (dotnet --version 2>&1).Trim()
            $status.DotNet.Path = (Get-Command dotnet).Source
        } catch {}

        # Check for .NET 8 runtime specifically (required for ILSpyCmd)
        try {
            $runtimes = dotnet --list-runtimes 2>&1
            if ($runtimes -match "Microsoft\.NETCore\.App 8\.") {
                $status.DotNet8Runtime.Installed = $true
                $runtime8 = ($runtimes | Select-String "Microsoft\.NETCore\.App 8\." | Select-Object -First 1).ToString()
                if ($runtime8 -match "(\d+\.\d+\.\d+)") {
                    $status.DotNet8Runtime.Version = $Matches[1]
                }
            }
        } catch {}
    }

    # Check uv
    if (Test-Command uv) {
        $status.UV.Installed = $true
        try {
            $status.UV.Version = (uv --version 2>&1).Trim()
            $status.UV.Path = (Get-Command uv).Source
        } catch {}
    }

    # Check Ghidra
    if (Test-Path $GhidraDir) {
        $status.Ghidra.Installed = $true
        $status.Ghidra.Path = $GhidraDir
    }

    # Check ILSpyCmd
    $ilspyPath = "$env:USERPROFILE\.dotnet\tools\ilspycmd.exe"
    if (Test-Path $ilspyPath) {
        $status.ILSpyCmd.Installed = $true
        $status.ILSpyCmd.Path = $ilspyPath
    } elseif (Test-Command ilspycmd) {
        $status.ILSpyCmd.Installed = $true
        $status.ILSpyCmd.Path = (Get-Command ilspycmd).Source
    }

    # Check x64dbg
    if (Test-Path $X64DbgDir) {
        $status.X64Dbg.Installed = $true
        $status.X64Dbg.Path = $X64DbgDir
    }

    # Check Binary MCP
    if (Test-Path "$InstallDir\pyproject.toml") {
        $status.BinaryMCP.Installed = $true
        $status.BinaryMCP.Path = $InstallDir
    }

    return $status
}

function Show-SystemStatus {
    param($Status)

    Write-Host "  SYSTEM STATUS" -ForegroundColor Yellow
    Write-Host "  -------------" -ForegroundColor Yellow
    Write-Host ""

    # Package Manager
    Write-Host "  Package Manager:" -ForegroundColor White
    if ($Status.Winget.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline; Write-Host "] winget $($Status.Winget.Version) (can auto-install prerequisites)"
    } else {
        Write-Host "    [" -NoNewline; Write-Host "--" -ForegroundColor Yellow -NoNewline; Write-Host "] winget (not available - manual install required)"
    }

    Write-Host ""

    # Core Requirements
    Write-Host "  Core Requirements:" -ForegroundColor White

    if ($Status.Python.Installed) {
        try {
            $pyVersionStr = $Status.Python.Version -replace "[^\d.]", ""
            if ($pyVersionStr -match "^(\d+)\.(\d+)") {
                $pyVersion = [version]"$($Matches[1]).$($Matches[2])"
            } else {
                $pyVersion = [version]"0.0"
            }
        } catch {
            $pyVersion = [version]"0.0"
        }
        if ($pyVersion -ge [version]"3.12") {
            Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline; Write-Host "] Python $($Status.Python.Version)"
        } else {
            Write-Host "    [" -NoNewline; Write-Host "!!" -ForegroundColor Yellow -NoNewline; Write-Host "] Python $($Status.Python.Version) (3.12+ recommended)"
        }
    } else {
        Write-Host "    [" -NoNewline; Write-Host "--" -ForegroundColor Red -NoNewline; Write-Host "] Python (not installed)"
    }

    if ($Status.UV.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline; Write-Host "] uv package manager"
    } else {
        Write-Host "    [" -NoNewline; Write-Host "--" -ForegroundColor DarkGray -NoNewline; Write-Host "] uv (will be installed)"
    }

    if ($Status.Git.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline; Write-Host "] Git"
    } else {
        Write-Host "    [" -NoNewline; Write-Host "--" -ForegroundColor DarkGray -NoNewline; Write-Host "] Git (optional, for updates)"
    }

    Write-Host ""
    Write-Host "  Analysis Components:" -ForegroundColor White

    # Ghidra + Java
    if ($Status.Ghidra.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline; Write-Host "] Ghidra (native binary analysis)"
    } else {
        Write-Host "    [" -NoNewline; Write-Host "--" -ForegroundColor DarkGray -NoNewline; Write-Host "] Ghidra (not installed)"
    }

    if ($Status.Java.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline; Write-Host "] Java 21+ (for Ghidra)"
    } else {
        Write-Host "    [" -NoNewline; Write-Host "--" -ForegroundColor DarkGray -NoNewline; Write-Host "] Java 21+ (required for Ghidra)"
    }

    # .NET Tools
    if ($Status.ILSpyCmd.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline; Write-Host "] ILSpyCmd (.NET decompilation)"
    } else {
        Write-Host "    [" -NoNewline; Write-Host "--" -ForegroundColor DarkGray -NoNewline; Write-Host "] ILSpyCmd (not installed)"
    }

    if ($Status.DotNet.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline; Write-Host "] .NET SDK $($Status.DotNet.Version)"
    } else {
        Write-Host "    [" -NoNewline; Write-Host "--" -ForegroundColor DarkGray -NoNewline; Write-Host "] .NET SDK (required for ILSpyCmd)"
    }

    if ($Status.DotNet8Runtime.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline; Write-Host "] .NET 8 Runtime $($Status.DotNet8Runtime.Version)"
    } elseif ($Status.DotNet.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "!!" -ForegroundColor Yellow -NoNewline; Write-Host "] .NET 8 Runtime (required for ILSpyCmd)"
    }

    # x64dbg
    if ($Status.X64Dbg.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline; Write-Host "] x64dbg (dynamic analysis)"
    } else {
        Write-Host "    [" -NoNewline; Write-Host "--" -ForegroundColor DarkGray -NoNewline; Write-Host "] x64dbg (not installed)"
    }

    Write-Host ""
    Write-Host "  Binary MCP Server:" -ForegroundColor White
    if ($Status.BinaryMCP.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline; Write-Host "] Installed at $($Status.BinaryMCP.Path)"
    } else {
        Write-Host "    [" -NoNewline; Write-Host "--" -ForegroundColor DarkGray -NoNewline; Write-Host "] Not installed"
    }

    Write-Host ""
}

function Show-InstallMenu {
    Write-Host "  INSTALLATION OPTIONS" -ForegroundColor Yellow
    Write-Host "  --------------------" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] Full Installation" -ForegroundColor White
    Write-Host "      Everything: Ghidra + .NET Tools + x64dbg + Claude Config" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [2] Static Analysis Only" -ForegroundColor White
    Write-Host "      Ghidra (native) + ILSpyCmd (.NET) - No debugger" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [3] Dynamic Analysis Only" -ForegroundColor White
    Write-Host "      x64dbg with MCP plugins - No static analysis tools" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [4] Custom Installation" -ForegroundColor White
    Write-Host "      Choose individual components to install" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [5] Repair/Update Existing" -ForegroundColor White
    Write-Host "      Reinstall or update specific components" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [Q] Quit" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-CustomMenu {
    param($Status)

    Write-Host "  CUSTOM INSTALLATION" -ForegroundColor Yellow
    Write-Host "  -------------------" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Select components (enter numbers separated by commas, e.g., 1,2,4):" -ForegroundColor White
    Write-Host ""

    $ghidraStatus = if ($Status.Ghidra.Installed) { "[Installed]" } else { "" }
    $javaNote = if (-not $Status.Java.Installed) { "(requires Java 21+)" } else { "" }
    Write-Host "  [1] Ghidra - Native binary analysis $ghidraStatus" -ForegroundColor White
    if ($javaNote) { Write-Host "      $javaNote" -ForegroundColor Yellow }

    $dotnetStatus = if ($Status.ILSpyCmd.Installed) { "[Installed]" } else { "" }
    $dotnetNote = if (-not $Status.DotNet.Installed) { "(requires .NET SDK 6.0+)" } else { "" }
    Write-Host "  [2] .NET Tools (ILSpyCmd) - C#/VB.NET decompilation $dotnetStatus" -ForegroundColor White
    if ($dotnetNote) { Write-Host "      $dotnetNote" -ForegroundColor Yellow }

    $x64dbgStatus = if ($Status.X64Dbg.Installed) { "[Installed]" } else { "" }
    Write-Host "  [3] x64dbg - Dynamic debugging/analysis $x64dbgStatus" -ForegroundColor White

    Write-Host "  [4] Configure Claude Desktop" -ForegroundColor White
    Write-Host "  [5] Configure Claude Code" -ForegroundColor White
    Write-Host ""
    Write-Host "  [A] All components" -ForegroundColor Cyan
    Write-Host "  [B] Back to main menu" -ForegroundColor DarkGray
    Write-Host ""
}

function Get-UserSelection {
    param($Prompt = "Select an option")
    Write-Host "  $Prompt" -ForegroundColor Cyan -NoNewline
    Write-Host ": " -NoNewline
    return Read-Host
}

# Installation Functions

function Install-UV {
    Write-Info "Installing uv package manager..."
    try {
        Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
        # Refresh PATH: Machine PATH first, then User PATH (standard Windows order)
        $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
        $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
        $env:Path = "$machinePath;$userPath"
        Write-Success "uv installed successfully"
        return $true
    } catch {
        Write-Err "Failed to install uv: $_"
        return $false
    }
}

function Install-Ghidra {
    Write-Info "Installing Ghidra..."

    # Check Java first
    if (-not (Test-Command java)) {
        Write-Err "Java 21+ is required for Ghidra"
        if (Test-WingetAvailable) {
            Write-Info "Attempting to install Java 21 via winget..."
            if (-not (Install-Java)) {
                Write-Info "Download manually from: https://adoptium.net/"
                return $false
            }
        } else {
            Write-Info "Download from: https://adoptium.net/"
            return $false
        }
    }

    if (Test-Path $GhidraDir) {
        Write-Warn "Ghidra directory already exists: $GhidraDir"
        if ($Unattended) {
            Write-Info "Skipping Ghidra (already installed, unattended mode)"
            return $true
        }
        $reinstall = Read-Host "  Reinstall? (y/n)"
        if ($reinstall -ne "y") {
            Write-Info "Skipping Ghidra installation"
            return $true
        }
        Remove-Item -Recurse -Force $GhidraDir
    }

    try {
        Write-Info "Fetching latest Ghidra release..."
        $ghidraRelease = Get-LatestGitHubRelease "NationalSecurityAgency/ghidra"
        $ghidraAsset = $ghidraRelease.assets | Where-Object { $_.name -match ".*\.zip$" -and $_.name -notmatch "DEV" } | Select-Object -First 1

        if ($null -eq $ghidraAsset) {
            Write-Err "Could not find Ghidra release asset"
            return $false
        }

        Write-Info "Downloading Ghidra $($ghidraRelease.tag_name)..."
        $ghidraZip = "$env:TEMP\ghidra.zip"
        Invoke-WebRequest -Uri $ghidraAsset.browser_download_url -OutFile $ghidraZip -UseBasicParsing
        Write-Success "Downloaded Ghidra"

        Write-Info "Extracting Ghidra..."
        Expand-Archive -Path $ghidraZip -DestinationPath "$env:USERPROFILE" -Force

        $extractedDir = Get-ChildItem "$env:USERPROFILE" -Directory | Where-Object { $_.Name -match "^ghidra_.*_PUBLIC" } | Select-Object -First 1

        if ($extractedDir) {
            Rename-Item $extractedDir.FullName $GhidraDir
            [System.Environment]::SetEnvironmentVariable("GHIDRA_HOME", $GhidraDir, "User")
            $env:GHIDRA_HOME = $GhidraDir
            Write-Success "Ghidra installed to: $GhidraDir"
        } else {
            Write-Err "Could not find extracted Ghidra directory"
            return $false
        }

        Remove-Item $ghidraZip -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Err "Failed to install Ghidra: $_"
        return $false
    }
}

function Install-DotNetTools {
    Write-Info "Installing .NET analysis tools..."

    # Check .NET SDK
    if (-not (Test-Command dotnet)) {
        Write-Err ".NET SDK is required for ILSpyCmd"
        if (Test-WingetAvailable) {
            Write-Info "Attempting to install .NET SDK 8.0 via winget..."
            if (-not (Install-DotNetSDK)) {
                Write-Info "Download manually from: https://dotnet.microsoft.com/download"
                return $false
            }
        } else {
            Write-Info "Download from: https://dotnet.microsoft.com/download"
            return $false
        }
    }

    # Check for .NET 8 runtime (required by ILSpyCmd)
    $runtimes = dotnet --list-runtimes 2>&1
    if ($runtimes -notmatch "Microsoft\.NETCore\.App 8\.") {
        Write-Warn ".NET 8 Runtime is required for ILSpyCmd but not found"
        if (Test-WingetAvailable) {
            Write-Info "Attempting to install .NET 8 Runtime via winget..."
            if (-not (Install-DotNetRuntime)) {
                Write-Info "Download manually from: https://dotnet.microsoft.com/download/dotnet/8.0"
                return $false
            }
        } else {
            Write-Info "Download .NET 8 Runtime from: https://dotnet.microsoft.com/download/dotnet/8.0"
            return $false
        }
    }

    try {
        Write-Info "Installing ILSpyCmd..."
        $result = dotnet tool install -g ilspycmd 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Success "ILSpyCmd installed successfully"
        } elseif ($result -match "already installed") {
            Write-Info "ILSpyCmd is already installed, updating..."
            dotnet tool update -g ilspycmd
            Write-Success "ILSpyCmd updated"
        } else {
            Write-Warn "ILSpyCmd installation returned: $result"
        }

        # Add to PATH if needed
        $toolsPath = "$env:USERPROFILE\.dotnet\tools"
        $currentUserPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
        if ($currentUserPath -notlike "*$toolsPath*") {
            # Add to current session
            $env:Path = "$toolsPath;$env:Path"
            # Persist to user environment (prepend to avoid duplicates)
            $newUserPath = "$toolsPath;$currentUserPath"
            [System.Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
            Write-Info "Added .NET tools to PATH"
        }

        return $true
    } catch {
        Write-Err "Failed to install ILSpyCmd: $_"
        return $false
    }
}

function Install-X64Dbg {
    Write-Info "Installing x64dbg..."

    if (Test-Path $X64DbgDir) {
        Write-Warn "x64dbg directory already exists: $X64DbgDir"
        if ($Unattended) {
            Write-Info "Skipping x64dbg (already installed, unattended mode)"
            return $true
        }
        $reinstall = Read-Host "  Reinstall? (y/n)"
        if ($reinstall -ne "y") {
            Write-Info "Skipping x64dbg installation"
            return $true
        }
        Remove-Item -Recurse -Force $X64DbgDir
    }

    try {
        $x64dbgUrl = "https://github.com/x64dbg/x64dbg/releases/download/snapshot/snapshot_latest.zip"
        $x64dbgZip = "$env:TEMP\x64dbg.zip"

        Write-Info "Downloading x64dbg..."
        Invoke-WebRequest -Uri $x64dbgUrl -OutFile $x64dbgZip -UseBasicParsing
        Write-Success "Downloaded x64dbg"

        Write-Info "Extracting x64dbg..."
        Expand-Archive -Path $x64dbgZip -DestinationPath $X64DbgDir -Force
        Write-Success "x64dbg installed to: $X64DbgDir"

        [System.Environment]::SetEnvironmentVariable("X64DBG_HOME", $X64DbgDir, "User")
        $env:X64DBG_HOME = $X64DbgDir

        Remove-Item $x64dbgZip -ErrorAction SilentlyContinue

        # Install MCP plugins
        Write-Info "Installing x64dbg MCP plugins..."
        try {
            $pluginRelease = Get-LatestGitHubRelease "Sarks0/binary-mcp"
            $plugin64 = $pluginRelease.assets | Where-Object { $_.name -eq "x64dbg_mcp.dp64" } | Select-Object -First 1
            $plugin32 = $pluginRelease.assets | Where-Object { $_.name -eq "x64dbg_mcp.dp32" } | Select-Object -First 1

            if ($plugin64 -and $plugin32) {
                $plugin64Dir = "$X64DbgDir\release\x64\plugins"
                $plugin32Dir = "$X64DbgDir\release\x32\plugins"
                New-Item -ItemType Directory -Force -Path $plugin64Dir | Out-Null
                New-Item -ItemType Directory -Force -Path $plugin32Dir | Out-Null

                Invoke-WebRequest -Uri $plugin64.browser_download_url -OutFile "$plugin64Dir\x64dbg_mcp.dp64" -UseBasicParsing
                Invoke-WebRequest -Uri $plugin32.browser_download_url -OutFile "$plugin32Dir\x64dbg_mcp.dp32" -UseBasicParsing
                Write-Success "MCP plugins installed"
            } else {
                Write-Warn "Pre-built MCP plugins not found in latest release"
                Write-Info "Build manually: src/engines/dynamic/x64dbg/plugin/README.md"
            }
        } catch {
            Write-Warn "Failed to install MCP plugins: $_"
        }

        return $true
    } catch {
        Write-Err "Failed to install x64dbg: $_"
        return $false
    }
}

function Install-BinaryMCP {
    Write-Info "Setting up Binary MCP Server..."

    if (Test-Path $InstallDir) {
        Write-Warn "Installation directory already exists: $InstallDir"
        if (-not $Unattended) {
            $continue = Read-Host "  Update existing installation? (y/n)"
            if ($continue -ne "y") {
                return $true
            }
        } else {
            Write-Info "Updating existing installation (unattended mode)"
        }
    } else {
        New-Item -ItemType Directory -Path $InstallDir | Out-Null
    }

    Push-Location $InstallDir

    try {
        if (Test-Path ".git") {
            Write-Info "Updating existing repository..."
            git pull
        } else {
            Write-Info "Cloning repository..."
            if (Test-Command git) {
                git clone https://github.com/Sarks0/binary-mcp.git .
            } else {
                Write-Warn "Git not found. Downloading as ZIP..."
                $zipUrl = "https://github.com/Sarks0/binary-mcp/archive/refs/heads/main.zip"
                $zipFile = "$env:TEMP\binary-mcp.zip"
                Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing
                Expand-Archive -Path $zipFile -DestinationPath "$env:TEMP\binary-mcp-extract" -Force
                Move-Item "$env:TEMP\binary-mcp-extract\binary-mcp-main\*" $InstallDir -Force
                Remove-Item "$env:TEMP\binary-mcp-extract" -Recurse -Force
                Remove-Item $zipFile -ErrorAction SilentlyContinue
            }
        }

        Write-Success "Repository ready"

        Write-Info "Installing Python dependencies..."
        uv sync --extra dev
        Write-Success "Dependencies installed"

        Pop-Location
        return $true
    } catch {
        Pop-Location
        Write-Err "Failed to setup Binary MCP: $_"
        return $false
    }
}

function Configure-ClaudeDesktop {
    Write-Info "Configuring Claude Desktop..."

    $claudeConfigDir = "$env:APPDATA\Claude"
    $claudeConfigFile = "$claudeConfigDir\claude_desktop_config.json"

    if (-not (Test-Path $claudeConfigDir)) {
        New-Item -ItemType Directory -Path $claudeConfigDir -Force | Out-Null
    }

    try {
        if (Test-Path $claudeConfigFile) {
            $config = Get-Content $claudeConfigFile -Raw | ConvertFrom-Json
            Copy-Item $claudeConfigFile "$claudeConfigFile.backup" -Force
            Write-Info "Backup saved to: $claudeConfigFile.backup"
        } else {
            $config = [PSCustomObject]@{ mcpServers = @{} }
        }

        if (-not $config.mcpServers) {
            $config | Add-Member -MemberType NoteProperty -Name "mcpServers" -Value @{} -Force
        }

        $config.mcpServers | Add-Member -MemberType NoteProperty -Name "binary-mcp" -Value @{
            command = "uv"
            args = @("--directory", $InstallDir, "run", "python", "-m", "src.server")
        } -Force

        $config | ConvertTo-Json -Depth 10 | Set-Content $claudeConfigFile -Encoding UTF8
        Write-Success "Claude Desktop configured"
        return $true
    } catch {
        Write-Err "Failed to configure Claude Desktop: $_"
        return $false
    }
}

function Configure-ClaudeCode {
    Write-Info "Configuring Claude Code..."

    $claudeCodeConfigDir = "$env:USERPROFILE\.config\claude-code"
    $claudeCodeConfigFile = "$claudeCodeConfigDir\mcp_settings.json"

    if (-not (Test-Path $claudeCodeConfigDir)) {
        New-Item -ItemType Directory -Path $claudeCodeConfigDir -Force | Out-Null
    }

    try {
        if (Test-Path $claudeCodeConfigFile) {
            $config = Get-Content $claudeCodeConfigFile -Raw | ConvertFrom-Json
            Copy-Item $claudeCodeConfigFile "$claudeCodeConfigFile.backup" -Force
            Write-Info "Backup saved to: $claudeCodeConfigFile.backup"
        } else {
            $config = [PSCustomObject]@{ mcpServers = @{} }
        }

        if (-not $config.mcpServers) {
            $config | Add-Member -MemberType NoteProperty -Name "mcpServers" -Value @{} -Force
        }

        $config.mcpServers | Add-Member -MemberType NoteProperty -Name "binary-mcp" -Value @{
            command = "uv"
            args = @("--directory", $InstallDir, "run", "python", "-m", "src.server")
        } -Force

        $config | ConvertTo-Json -Depth 10 | Set-Content $claudeCodeConfigFile -Encoding UTF8
        Write-Success "Claude Code configured"
        return $true
    } catch {
        Write-Err "Failed to configure Claude Code: $_"
        return $false
    }
}

function Show-Summary {
    param($Installed)

    Write-Host ""
    Write-Host "  ================================================" -ForegroundColor Green
    Write-Host "           INSTALLATION COMPLETE!" -ForegroundColor Green
    Write-Host "  ================================================" -ForegroundColor Green
    Write-Host ""

    if ($Installed.BinaryMCP) {
        Write-Success "Binary MCP Server: $InstallDir"
    }
    if ($Installed.Ghidra) {
        Write-Success "Ghidra: $GhidraDir"
    }
    if ($Installed.DotNet) {
        Write-Success "ILSpyCmd: .NET decompilation ready"
    }
    if ($Installed.X64Dbg) {
        Write-Success "x64dbg: $X64DbgDir"
    }
    if ($Installed.ClaudeDesktop) {
        Write-Success "Claude Desktop: Configured"
    }
    if ($Installed.ClaudeCode) {
        Write-Success "Claude Code: Configured"
    }

    Write-Host ""
    Write-Info "Next steps:"
    Write-Host "  1. Restart Claude Desktop/Code to load the MCP server" -ForegroundColor White

    if ($Installed.Ghidra -or $Installed.DotNet) {
        Write-Host "  2. Test static analysis:" -ForegroundColor White
        if ($Installed.Ghidra) {
            Write-Host "     - Native binaries: 'Analyze /path/to/binary.exe'" -ForegroundColor DarkGray
        }
        if ($Installed.DotNet) {
            Write-Host "     - .NET assemblies: 'Analyze the .NET binary at /path/to/app.exe'" -ForegroundColor DarkGray
        }
    }

    if ($Installed.X64Dbg) {
        Write-Host "  3. For dynamic analysis: Launch x64dbg and load a binary" -ForegroundColor White
        Write-Host "     - x64dbg.exe for 64-bit, x32dbg.exe for 32-bit" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  Test the server: " -ForegroundColor White -NoNewline
    Write-Host "cd $InstallDir && uv run python -m src.server" -ForegroundColor Yellow
    Write-Host ""
}

# Main Installation Flow

Show-Banner

# Get initial system status
$status = Get-ComponentStatus

# Check Python first (required)
if (-not $status.Python.Installed) {
    Write-Err "Python is required but not found!"
    if ($status.Winget.Installed) {
        if ($Unattended) {
            Write-Info "Installing Python via winget (unattended mode)..."
            if (Install-Python) {
                $status = Get-ComponentStatus
            } else {
                exit 1
            }
        } else {
            $installPy = Read-Host "  Install Python 3.12 via winget? (y/n)"
            if ($installPy -eq "y") {
                if (Install-Python) {
                    $status = Get-ComponentStatus
                } else {
                    exit 1
                }
            } else {
                Write-Info "Please install Python 3.12+ from: https://www.python.org/downloads/"
                Write-Info "Make sure to check 'Add Python to PATH' during installation"
                exit 1
            }
        }
    } else {
        Write-Info "Please install Python 3.12+ from: https://www.python.org/downloads/"
        Write-Info "Make sure to check 'Add Python to PATH' during installation"
        exit 1
    }
}

Show-SystemStatus $status

# Offer to install missing prerequisites if winget is available
if ($status.Winget.Installed) {
    $missingPrereqs = @()

    if (-not $status.Java.Installed) {
        $missingPrereqs += @{ Name = "Java 21 (Temurin)"; Key = "java"; Installer = { Install-Java } }
    }
    if (-not $status.DotNet.Installed) {
        $missingPrereqs += @{ Name = ".NET SDK 8.0"; Key = "dotnetsdk"; Installer = { Install-DotNetSDK } }
    } elseif (-not $status.DotNet8Runtime.Installed) {
        $missingPrereqs += @{ Name = ".NET 8 Runtime"; Key = "dotnetruntime"; Installer = { Install-DotNetRuntime } }
    }
    if (-not $status.Git.Installed) {
        $missingPrereqs += @{ Name = "Git"; Key = "git"; Installer = { Install-Git } }
    }

    if ($missingPrereqs.Count -gt 0) {
        Write-Host ""
        Write-Host "  MISSING PREREQUISITES" -ForegroundColor Yellow
        Write-Host "  ---------------------" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  The following can be installed automatically via winget:" -ForegroundColor White
        foreach ($prereq in $missingPrereqs) {
            Write-Host "    - $($prereq.Name)" -ForegroundColor DarkGray
        }
        Write-Host ""

        if ($Unattended) {
            Write-Info "Installing all prerequisites (unattended mode)..."
            foreach ($prereq in $missingPrereqs) {
                & $prereq.Installer | Out-Null
            }
            $status = Get-ComponentStatus
        } else {
            $installPrereqs = Read-Host "  Install missing prerequisites? (y/n/select)"
            if ($installPrereqs -eq "y") {
                foreach ($prereq in $missingPrereqs) {
                    & $prereq.Installer | Out-Null
                }
                $status = Get-ComponentStatus
                Write-Host ""
                Show-SystemStatus $status
            } elseif ($installPrereqs -eq "select") {
                Write-Host ""
                foreach ($prereq in $missingPrereqs) {
                    $install = Read-Host "    Install $($prereq.Name)? (y/n)"
                    if ($install -eq "y") {
                        & $prereq.Installer | Out-Null
                    }
                }
                $status = Get-ComponentStatus
                Write-Host ""
                Show-SystemStatus $status
            }
        }
    }
}

# Install uv if needed
if (-not $status.UV.Installed) {
    if ($Unattended) {
        Write-Info "Installing uv (unattended mode)..."
        if (-not (Install-UV)) {
            Write-Err "Cannot proceed without uv"
            exit 1
        }
    } else {
        $installUV = Read-Host "  uv package manager is required. Install now? (y/n)"
        if ($installUV -eq "y") {
            if (-not (Install-UV)) {
                Write-Err "Cannot proceed without uv"
                exit 1
            }
        } else {
            Write-Err "uv is required for Binary MCP"
            exit 1
        }
    }
}

# Tracking what gets installed
$installed = @{
    BinaryMCP = $false
    Ghidra = $false
    DotNet = $false
    X64Dbg = $false
    ClaudeDesktop = $false
    ClaudeCode = $false
}

# Installation profile selection
if ($InstallProfile) {
    # Map profile names to menu numbers
    $selection = switch ($InstallProfile.ToLower()) {
        "full"    { "1" }
        "static"  { "2" }
        "dynamic" { "3" }
        "custom"  { "4" }
        "repair"  { "5" }
        default   { $InstallProfile }
    }
} else {
    Show-InstallMenu
    $selection = Get-UserSelection "Enter choice (1-5, Q to quit)"
}

switch ($selection.ToLower()) {
    { $_ -in "1", "full" } {
        # Full installation
        Write-Host ""
        Write-Info "Starting Full Installation..."
        Write-Host ""

        $installed.BinaryMCP = Install-BinaryMCP

        if ($status.Java.Installed) {
            $installed.Ghidra = Install-Ghidra
        } else {
            Write-Warn "Skipping Ghidra - Java 21+ not installed"
            Write-Info "Install Java from: https://adoptium.net/"
        }

        if ($status.DotNet.Installed) {
            $installed.DotNet = Install-DotNetTools
        } else {
            Write-Warn "Skipping ILSpyCmd - .NET SDK not installed"
            Write-Info "Install .NET SDK from: https://dotnet.microsoft.com/download"
        }

        $installed.X64Dbg = Install-X64Dbg
        $installed.ClaudeDesktop = Configure-ClaudeDesktop
        $installed.ClaudeCode = Configure-ClaudeCode
    }

    { $_ -in "2", "static" } {
        # Static analysis only
        Write-Host ""
        Write-Info "Starting Static Analysis Installation..."
        Write-Host ""

        $installed.BinaryMCP = Install-BinaryMCP

        if ($status.Java.Installed) {
            $installed.Ghidra = Install-Ghidra
        } else {
            Write-Warn "Skipping Ghidra - Java 21+ not installed"
        }

        if ($status.DotNet.Installed) {
            $installed.DotNet = Install-DotNetTools
        } else {
            Write-Warn "Skipping ILSpyCmd - .NET SDK not installed"
        }

        $installed.ClaudeDesktop = Configure-ClaudeDesktop
    }

    { $_ -in "3", "dynamic" } {
        # Dynamic analysis only
        Write-Host ""
        Write-Info "Starting Dynamic Analysis Installation..."
        Write-Host ""

        $installed.BinaryMCP = Install-BinaryMCP
        $installed.X64Dbg = Install-X64Dbg
        $installed.ClaudeDesktop = Configure-ClaudeDesktop
    }

    { $_ -in "4", "custom" } {
        # Custom installation
        Show-CustomMenu $status
        $customSelection = Get-UserSelection "Enter components"

        if ($customSelection.ToLower() -eq "b") {
            Write-Info "Returning to main menu..."
            # Re-run script (quote path in case of spaces)
            & "$($MyInvocation.MyCommand.Path)"
            exit 0
        }

        $components = if ($customSelection.ToLower() -eq "a") {
            @("1", "2", "3", "4", "5")
        } else {
            $customSelection -split "," | ForEach-Object { $_.Trim() }
        }

        Write-Host ""
        Write-Info "Starting Custom Installation..."
        Write-Host ""

        # Always install base
        $installed.BinaryMCP = Install-BinaryMCP

        foreach ($comp in $components) {
            switch ($comp) {
                "1" {
                    if ($status.Java.Installed) {
                        $installed.Ghidra = Install-Ghidra
                    } else {
                        Write-Warn "Cannot install Ghidra - Java 21+ required"
                    }
                }
                "2" {
                    if ($status.DotNet.Installed) {
                        $installed.DotNet = Install-DotNetTools
                    } else {
                        Write-Warn "Cannot install ILSpyCmd - .NET SDK 6.0+ required"
                    }
                }
                "3" { $installed.X64Dbg = Install-X64Dbg }
                "4" { $installed.ClaudeDesktop = Configure-ClaudeDesktop }
                "5" { $installed.ClaudeCode = Configure-ClaudeCode }
            }
        }
    }

    { $_ -in "5", "repair" } {
        # Repair/Update
        Write-Host ""
        Write-Info "Repair/Update Mode"
        Write-Host ""
        Show-CustomMenu $status
        Write-Info "Select components to reinstall/update"
        $repairSelection = Get-UserSelection "Enter components"

        if ($repairSelection.ToLower() -eq "b") {
            & "$($MyInvocation.MyCommand.Path)"
            exit 0
        }

        $components = $repairSelection -split "," | ForEach-Object { $_.Trim() }

        foreach ($comp in $components) {
            switch ($comp) {
                "1" { $installed.Ghidra = Install-Ghidra }
                "2" { $installed.DotNet = Install-DotNetTools }
                "3" { $installed.X64Dbg = Install-X64Dbg }
                "4" { $installed.ClaudeDesktop = Configure-ClaudeDesktop }
                "5" { $installed.ClaudeCode = Configure-ClaudeCode }
            }
        }
    }

    { $_ -in "q", "quit", "exit" } {
        Write-Info "Installation cancelled"
        exit 0
    }

    default {
        Write-Err "Invalid selection: $selection"
        exit 1
    }
}

# Show summary
Show-Summary $installed

Write-Host ""
Write-Success "Installation finished!"
Write-Host ""
