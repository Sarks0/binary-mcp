# Binary MCP Server - Windows Installer
# Interactive installation script with component selection

#Requires -RunAsAdministrator

param(
    [string]$InstallDir = "$env:USERPROFILE\binary-mcp",
    [string]$GhidraDir = "$env:USERPROFILE\ghidra",
    [string]$X64DbgDir = "$env:USERPROFILE\x64dbg",
    [string]$WinDbgDir = "",  # Auto-detected from Windows SDK
    [ValidateSet("", "full", "static", "dynamic", "kernel", "custom", "repair")]
    [string]$InstallProfile = "",  # full, static, dynamic, kernel, custom, repair
    [switch]$Unattended,
    # Turn every "could not verify this download" warning into a hard failure.
    # See the supply-chain integrity section below (audit finding F-3).
    [switch]$StrictIntegrity
)

$ErrorActionPreference = "Stop"

# Force TLS 1.2 for all downloads. Windows PowerShell 5.1 may default to
# TLS 1.0, which GitHub, astral.sh, and Microsoft download endpoints reject -
# resulting in an opaque "Could not create SSL/TLS secure channel" error.
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

# Suppress the progress bar; in PowerShell 5.1 it slows Invoke-WebRequest
# downloads (e.g. Ghidra, x64dbg) by roughly an order of magnitude.
$ProgressPreference = 'SilentlyContinue'

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

# Supply-Chain Integrity Helpers (audit finding F-3)
#
# This installer runs elevated (#Requires -RunAsAdministrator) and drops code
# onto a malware analyst's machine - including obsidian.dp64, which x64dbg
# loads into the same process that debugs live malware. Downloading over TLS
# proves only *who served* the bytes, never *which* bytes were served: a
# tampered CDN copy, a swapped GitHub release asset, or an interception proxy
# whose root the machine trusts all still yield code execution as
# Administrator. So every artifact fetched below is hash-checked before it is
# used, and PE artifacts that ought to be signed also get an Authenticode
# check.
#
# An expected SHA-256 is resolved in this order:
#   1. a checksum manifest published alongside the artifact's GitHub release
#      (SHA256SUMS / <asset>.sha256) - this is what binary-mcp's own release
#      assets should ship, and it is the hash the maintainer actually controls;
#   2. a best-effort scrape of the release notes for a digest next to the asset
#      name (Ghidra publishes checksums this way);
#   3. a value pinned in $script:PinnedSha256 below;
#   4. the BINARY_MCP_SHA256_<KEY> environment variable, so an operator can pin
#      a third-party artifact (Ghidra, the x64dbg snapshot build, the Windows
#      SDK bootstrapper) whose upstream publishes no stable digest we could
#      hard-code here.
#
# Note what each of those does and does not buy: a manifest fetched from the
# same release defeats tampering with an individual asset or its CDN copy, but
# not a takeover of the release itself. A pinned/operator-supplied hash is the
# only thing that defends against that, which is why pinning is offered for
# every artifact rather than only the unusual ones.
#
# When none of those yields a hash the install no longer continues silently as
# it did before this finding: it prints a loud, unmissable warning naming the
# artifact, the URL, and the digest that was actually downloaded, so the
# operator can pin it for next time. -StrictIntegrity (or
# BINARY_MCP_STRICT_INTEGRITY=1) turns those warnings into hard failures.

# Known-good digests. Deliberately empty by default: a wrong pinned hash breaks
# every install, and these upstreams publish new builds faster than this file
# can track them. Populate an entry (or set the matching env var) to pin.
#
# The 'binary-mcp-*' keys are listed for discoverability (F-3, second pass):
# they name the artifacts this project publishes itself, and spell out the
# BINARY_MCP_SHA256_BINARY_MCP_OBSIDIAN_DP64 style env var an operator sets to
# pin one. Their normal source of truth is the SHA256SUMS manifest published
# with each release by .github/workflows/release.yml; a pin here (or in the
# environment) overrides that, and is the only defence against a takeover of
# the release itself.
$script:PinnedSha256 = @{
    'uv-installer-ps1'             = ''
    'ghidra-zip'                   = ''
    'x64dbg-snapshot'              = ''
    'windows-sdk-setup'            = ''
    'repo-zip'                     = ''
    'binary-mcp-obsidian.dp64'     = ''
    'binary-mcp-obsidian.dp32'     = ''
    'binary-mcp-obsidian_server.exe' = ''
}

function Get-IntegrityEnvName {
    param([Parameter(Mandatory = $true)][string]$HashKey)
    return "BINARY_MCP_SHA256_" + (($HashKey -replace '[^A-Za-z0-9]', '_').ToUpperInvariant())
}

function Test-StrictIntegrity {
    if ($StrictIntegrity) { return $true }
    $flag = [System.Environment]::GetEnvironmentVariable("BINARY_MCP_STRICT_INTEGRITY")
    if ($flag -and @('1', 'true', 'yes', 'on') -contains $flag.Trim().ToLowerInvariant()) {
        return $true
    }
    return $false
}

function Get-PinnedSha256 {
    # Operator-supplied env var wins over the in-script table so an analyst can
    # pin today's Ghidra build without editing (and re-signing) the installer.
    param([Parameter(Mandatory = $true)][string]$HashKey)
    $fromEnv = [System.Environment]::GetEnvironmentVariable((Get-IntegrityEnvName $HashKey))
    if ($fromEnv -and $fromEnv.Trim()) { return $fromEnv.Trim() }
    if ($script:PinnedSha256.ContainsKey($HashKey) -and $script:PinnedSha256[$HashKey]) {
        return $script:PinnedSha256[$HashKey].Trim()
    }
    return $null
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Assert-FileHash {
    <#
        Verify a downloaded file against an expected SHA-256, and on mismatch
        DELETE it before throwing. Deleting matters: a rejected artifact left
        in %TEMP% is one retry, one stale path, or one curious double-click
        away from being executed anyway - and this script runs as Administrator.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [string]$Description = "file"
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Integrity check failed: $Description is missing from $Path"
    }

    $expected = $ExpectedSha256.Trim()
    if ($expected -notmatch '^[0-9a-fA-F]{64}$') {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        throw "Integrity check failed: expected SHA-256 for $Description is not a 64-character hex digest (got '$expected')"
    }

    # Get-FileHash returns uppercase; published manifests are usually lowercase.
    # Compare case-insensitively instead of normalising one side and hoping.
    $actual = Get-FileSha256 -Path $Path
    if (-not [string]::Equals($actual, $expected, [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        $message = "SHA-256 mismatch for ${Description}: expected $($expected.ToLowerInvariant()), got $($actual.ToLowerInvariant()). " +
                   "The downloaded file has been deleted. Either the artifact was republished upstream " +
                   "(in which case update the pinned hash) or the download was tampered with - do not " +
                   "install it by hand without establishing which."
        throw $message
    }

    Write-Success "Verified SHA-256 of $Description"
    return $true
}

function Write-UnverifiedArtifactWarning {
    <#
        Reached when no expected digest could be resolved. The old behaviour was
        to install the bytes without comment; the point of this warning is that
        the analyst finds out at the moment it happens, and is handed the exact
        command to pin the artifact next time.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string]$HashKey,
        [string]$Uri = ""
    )

    $actual = (Get-FileSha256 -Path $Path).ToLowerInvariant()
    $envName = Get-IntegrityEnvName $HashKey

    Write-Host ""
    Write-Warn "======================================================================"
    Write-Warn " UNVERIFIED DOWNLOAD - integrity could NOT be checked"
    Write-Warn "======================================================================"
    Write-Warn "  Artifact : $Description"
    if ($Uri) { Write-Warn "  Source   : $Uri" }
    Write-Warn "  SHA-256  : $actual"
    Write-Warn "  No publisher checksum was available and no hash is pinned, so this"
    Write-Warn "  file is trusted purely because TLS said it came from that host."
    Write-Warn "  To pin this exact copy for future installs, run before installing:"
    Write-Warn "      `$env:$envName = '$actual'"
    Write-Warn "  Re-run with -StrictIntegrity to make unverified downloads fatal."
    Write-Warn "======================================================================"
    Write-Host ""

    if (Test-StrictIntegrity) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        throw "StrictIntegrity: refusing to use unverified download '$Description'. Pin it with `$env:$envName = '$actual'."
    }
}

function Invoke-VerifiedDownload {
    <#
        The only place in this script that writes a remote file to disk.
        Downloads, then verifies - or warns loudly when there is nothing to
        verify against. Callers get the same throw-on-failure semantics they
        already handle in their try/catch blocks.

        Returns $true only when the bytes were actually checked against an
        expected digest, and $false when the download completed but nothing
        could be verified. F-3: that distinction matters to callers that do
        something irreversible with the file afterwards - Install-UV must not
        strip the Mark-of-the-Web from a script it never verified - so the
        return value is a verification result, NOT a success flag. A caller that
        ignores it is no worse off than before; a caller that treats $false as
        "verified" is the bug this return value exists to prevent.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string]$HashKey,
        [string]$ExpectedSha256 = ""
    )

    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing

    $expected = $ExpectedSha256
    if (-not $expected) { $expected = Get-PinnedSha256 -HashKey $HashKey }

    if ($expected) {
        Assert-FileHash -Path $OutFile -ExpectedSha256 $expected -Description $Description | Out-Null
        return $true
    }

    Write-UnverifiedArtifactWarning -Path $OutFile -Description $Description -HashKey $HashKey -Uri $Uri
    return $false
}

function Test-VerificationResult {
    <#
        F-3: normalise the result of a verification helper
        (Invoke-VerifiedDownload, Assert-AuthenticodeValid) into a strict
        boolean, failing CLOSED on anything unexpected.

        PowerShell functions return everything left on the output stream, so if
        a future edit inside one of those helpers emits a stray object the
        caller receives an array rather than the boolean it asked for - and
        `if ($array)` is $true for any non-empty array, which would silently
        turn "could not verify" into "verified". Requiring an actual [bool] $true
        means such an edit degrades to "treat as unverified" instead, which is
        the direction a security check should fail in.
    #>
    param($Result)
    return ($Result -is [bool]) -and $Result
}

function Get-ReleaseChecksumMap {
    <#
        Parse a checksum manifest published as a GitHub release asset into
        @{ 'asset-name' = 'sha256' }. Handles both the coreutils layout
        ("<hash>  <name>", '*' for binary mode) and single-digest "<asset>.sha256"
        files. Failures are non-fatal: the caller falls back to a pinned hash or
        to the loud unverified warning.
    #>
    param($Release)

    $map = @{}
    if ($null -eq $Release -or $null -eq $Release.assets) { return $map }

    $sumAssets = @($Release.assets | Where-Object {
        $_.name -match '^(sha256sums?|checksums?)(\.txt)?$' -or $_.name -match '\.sha256$'
    })

    foreach ($sumAsset in $sumAssets) {
        $tempSums = Join-Path $env:TEMP ("binary-mcp-sums-" + [guid]::NewGuid().ToString("N") + ".txt")
        try {
            # Downloaded to disk (not piped) and only ever parsed as text - it is
            # never executed, so it does not need its own integrity check; its
            # authority is that of the release it is published in.
            Invoke-WebRequest -Uri $sumAsset.browser_download_url -OutFile $tempSums -UseBasicParsing
            foreach ($line in (Get-Content -LiteralPath $tempSums)) {
                $trimmed = $line.Trim()
                if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }
                if ($trimmed -match '^([0-9a-fA-F]{64})[\s\*]+(.+)$') {
                    $name = [System.IO.Path]::GetFileName($matches[2].Trim().TrimStart('*'))
                    if ($name) { $map[$name] = $matches[1] }
                } elseif ($trimmed -match '^([0-9a-fA-F]{64})$' -and $sumAsset.name -match '\.sha256$') {
                    $map[($sumAsset.name -replace '\.sha256$', '')] = $matches[1]
                }
            }
        } catch {
            Write-Warn "Could not read checksum manifest $($sumAsset.name): $_"
        } finally {
            Remove-Item -LiteralPath $tempSums -Force -ErrorAction SilentlyContinue
        }
    }

    return $map
}

function Get-ChecksumFromReleaseNotes {
    <#
        Best-effort scrape of a release body for a digest published next to the
        asset name (how Ghidra ships its SHA-256). Only accepts a digest found
        on, or within two lines of, a line naming the asset, so an unrelated
        hash elsewhere in the notes cannot be mistaken for this asset's.
    #>
    param($Release, [Parameter(Mandatory = $true)][string]$AssetName)

    if ($null -eq $Release -or -not $Release.body) { return $null }

    $lines = @($Release.body -split "`r?`n")
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -notmatch [regex]::Escape($AssetName)) { continue }
        $upper = [Math]::Min($i + 2, $lines.Count - 1)
        for ($j = $i; $j -le $upper; $j++) {
            if ($lines[$j] -match '([0-9a-fA-F]{64})') { return $matches[1] }
        }
    }
    return $null
}

function Get-ReleaseAssetChecksum {
    # Convenience wrapper: manifest asset first, release notes second, $null if
    # neither yields a digest for this asset.
    param($Release, [Parameter(Mandatory = $true)][string]$AssetName, $ChecksumMap = $null)

    try {
        if ($null -eq $ChecksumMap) { $ChecksumMap = Get-ReleaseChecksumMap -Release $Release }
        if ($ChecksumMap -and $ChecksumMap.ContainsKey($AssetName)) { return $ChecksumMap[$AssetName] }
        return (Get-ChecksumFromReleaseNotes -Release $Release -AssetName $AssetName)
    } catch {
        Write-Warn "Could not resolve a published checksum for ${AssetName}: $_"
        return $null
    }
}

function Assert-AuthenticodeValid {
    <#
        Authenticode check for PE artifacts. Complements the hash check: a hash
        pins one exact build, a valid signature says the publisher stands behind
        whatever build this is.

        Warning, not fatal, by default - binary-mcp's own release assets are not
        code-signed yet, and failing the install over that would be worse than
        the status quo. -StrictIntegrity escalates a *bad* signature to fatal,
        while -AllowUnsigned keeps a plainly unsigned artifact non-fatal even
        then (unsigned is the expected state for our own assets today; a broken
        or mismatched signature never is).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Description = "file",
        [string]$ExpectedSubjectMatch = "",
        [switch]$AllowUnsigned
    )

    $sig = $null
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
    } catch {
        Write-Warn "Could not read the Authenticode signature of ${Description}: $_"
        return $false
    }

    if ($null -eq $sig) {
        Write-Warn "Could not read the Authenticode signature of $Description"
        return $false
    }

    if ($sig.Status -eq 'Valid') {
        $subject = ""
        if ($sig.SignerCertificate) { $subject = $sig.SignerCertificate.Subject }
        if ($ExpectedSubjectMatch -and ($subject -notmatch [regex]::Escape($ExpectedSubjectMatch))) {
            Write-Warn "$Description carries a VALID signature from an UNEXPECTED publisher:"
            Write-Warn "  signer   : $subject"
            Write-Warn "  expected : subject containing '$ExpectedSubjectMatch'"
            if (Test-StrictIntegrity) {
                Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
                throw "StrictIntegrity: unexpected Authenticode signer for $Description ($subject)"
            }
            return $false
        }
        Write-Success "Authenticode signature valid for $Description"
        return $true
    }

    if ($sig.Status -eq 'NotSigned' -and $AllowUnsigned) {
        Write-Warn "$Description is not Authenticode-signed; its integrity rests on the SHA-256 check alone."
        return $false
    }

    # F-3 (second pass): 'UnknownError' is NOT a bad signature - it is Windows
    # saying "I do not know how to evaluate this file type". WinVerifyTrust
    # dispatches on file EXTENSION, and .dp64/.dp32 (x64dbg's names for plain
    # PE DLLs) are not in the subject-type table, so Get-AuthenticodeSignature
    # returns UnknownError for a perfectly good plugin. Lumping that in with
    # the genuine-failure branch below meant -StrictIntegrity DELETED a
    # legitimate, already hash-verified obsidian.dp64 and aborted the install -
    # a self-inflicted denial of service dressed up as a security control.
    # Treat it as "no signature information available", exactly like NotSigned,
    # but only where the caller has already said unsigned is acceptable
    # (-AllowUnsigned). Callers that require a real signature - the elevated
    # Windows SDK bootstrapper - do not pass it and still fail on UnknownError.
    if ($sig.Status -eq 'UnknownError' -and $AllowUnsigned) {
        Write-Warn "$Description could not be Authenticode-evaluated (status 'UnknownError')."
        Write-Warn "  Windows dispatches signature checks by file extension and does not"
        Write-Warn "  recognise this one, so this is 'unknown', not 'invalid'. Its integrity"
        Write-Warn "  rests on the SHA-256 check alone."
        return $false
    }

    Write-Warn "Authenticode verification FAILED for ${Description}: status '$($sig.Status)'"
    Write-Warn "  This file is about to be installed on a machine that debugs live malware."
    if (Test-StrictIntegrity) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        throw "StrictIntegrity: Authenticode verification failed for $Description (status: $($sig.Status))"
    }
    return $false
}

function Find-WinDbgPath {
    # Returns the directory containing cdb.exe, or $null if not found.
    # Searches in priority order:
    #   1. WINDBG_PATH env var
    #   2. Standard Windows SDK paths
    #   3. WinDbg Preview via Get-AppxPackage (Microsoft Store)
    #   4. WinDbg Preview WindowsApps aliases (Store / winget)
    #   5. WinDbg Preview in Program Files (winget / direct install)
    #   6. cdb.exe on PATH

    # 1. Env var
    if ($env:WINDBG_PATH -and (Test-Path "$env:WINDBG_PATH\cdb.exe")) {
        return $env:WINDBG_PATH
    }

    # 2. Windows SDK paths
    $sdkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64",
        "$env:ProgramFiles\Windows Kits\10\Debuggers\x64",
        "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x86",
        "C:\Debuggers"
    )
    foreach ($p in $sdkPaths) {
        if (Test-Path "$p\cdb.exe") {
            return $p
        }
    }

    # 3. WinDbg Preview via Get-AppxPackage (Microsoft Store)
    try {
        $appx = Get-AppxPackage -Name "Microsoft.WinDbg" -ErrorAction SilentlyContinue
        if ($appx -and $appx.InstallLocation) {
            $appxPath = $appx.InstallLocation
            foreach ($sub in @("amd64", "x64", "")) {
                $candidate = if ($sub) { "$appxPath\$sub" } else { $appxPath }
                if (Test-Path "$candidate\cdb.exe") {
                    return $candidate
                }
            }
        }
    } catch {}

    # 4. WinDbg Preview WindowsApps aliases (Store / winget symlinks)
    try {
        $localApps = "$env:LOCALAPPDATA\Microsoft\WindowsApps"
        if (Test-Path $localApps) {
            $windbgDirs = Get-ChildItem -Path $localApps -Directory -Filter "Microsoft.WinDbg*" -ErrorAction SilentlyContinue
            foreach ($dir in $windbgDirs) {
                foreach ($sub in @("amd64", "x64", "")) {
                    $candidate = if ($sub) { "$($dir.FullName)\$sub" } else { $dir.FullName }
                    if (Test-Path "$candidate\cdb.exe") {
                        return $candidate
                    }
                }
            }
        }
    } catch {}

    # 5. WinDbg Preview in Program Files (winget / direct install)
    foreach ($progDir in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $progDir) { continue }
        $windbgDir = "$progDir\WinDbg"
        if (Test-Path $windbgDir) {
            foreach ($sub in @("amd64", "x64", "")) {
                $candidate = if ($sub) { "$windbgDir\$sub" } else { $windbgDir }
                if (Test-Path "$candidate\cdb.exe") {
                    return $candidate
                }
            }
        }
    }

    # 6. cdb.exe on PATH
    if (Test-Command cdb) {
        return (Get-Command cdb).Source | Split-Path
    }

    return $null
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
        $result = winget install --id $PackageId --source winget --accept-source-agreements --accept-package-agreements 2>&1
        $wingetExit = $LASTEXITCODE
        $resultText = ($result | Out-String)

        # Decide success from winget's exit code, not arbitrary output text:
        # matching phrases like "already installed" in the output would misread
        # a genuine failure (e.g. a conflicting dependency error) as success.
        # These codes are stable winget result constants meaning "nothing to do":
        #   0            = installed
        #   -1978335189  = 0x8A15002B no applicable upgrade found
        #   -1978335212  = 0x8A150014 package already installed
        $benignCodes = @(0, -1978335189, -1978335212)

        # Reboot-required is a *successful* install that completes after restart.
        # winget signals it inconsistently across versions, so detect it from the
        # message (narrowly) and surface it as a warning rather than a failure.
        $rebootRequired = $resultText -match "(?i)(restart your (PC|computer)|reboot[^\n]*required|requires[^\n]*restart)"

        if (($wingetExit -in $benignCodes) -or $rebootRequired) {
            Write-Success "$PackageName installed successfully"
            if ($rebootRequired) {
                Write-Warn "A restart may be required to finish installing $PackageName"
            }
            # Refresh PATH
            $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
            $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
            $env:Path = "$machinePath;$userPath"
            return $true
        } else {
            Write-Warn "winget returned (exit $wingetExit): $resultText"
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
    Write-Info "Installing .NET SDK 10.0..."
    return Install-WithWinget -PackageId "Microsoft.DotNet.SDK.10" -PackageName ".NET SDK 10.0"
}

function Install-DotNetRuntime {
    Write-Info "Installing .NET Runtime 10.0 (required for ILSpyCmd)..."
    return Install-WithWinget -PackageId "Microsoft.DotNet.Runtime.10" -PackageName ".NET Runtime 10.0"
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
        DotNet10Runtime = @{ Installed = $false; Version = ""; Path = "" }
        Git = @{ Installed = $false; Version = ""; Path = "" }
        UV = @{ Installed = $false; Version = ""; Path = "" }
        Ghidra = @{ Installed = $false; Version = ""; Path = $GhidraDir }
        ILSpyCmd = @{ Installed = $false; Version = ""; Path = "" }
        X64Dbg = @{ Installed = $false; Version = ""; Path = $X64DbgDir }
        WinDbg = @{ Installed = $false; Version = ""; Path = "" }
        Pybag  = @{ Installed = $false; Version = ""; Path = "" }
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

        # Check for .NET 10 runtime specifically (required by current ILSpyCmd, which targets net10.0)
        try {
            $runtimes = dotnet --list-runtimes 2>&1
            if ($runtimes -match "Microsoft\.NETCore\.App 10\.") {
                $status.DotNet10Runtime.Installed = $true
                $runtime10 = ($runtimes | Select-String "Microsoft\.NETCore\.App 10\." | Select-Object -First 1).ToString()
                if ($runtime10 -match "(\d+\.\d+\.\d+)") {
                    $status.DotNet10Runtime.Version = $Matches[1]
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

    # Check WinDbg / Debugging Tools for Windows
    $windbgPath = Find-WinDbgPath
    if ($windbgPath) {
        $status.WinDbg.Installed = $true
        $status.WinDbg.Path = $windbgPath
    }

    # Check Pybag (Python package for WinDbg COM API). uv resolves the project
    # from the current directory, so this must run inside $InstallDir or it
    # will always report "not installed" when launched from elsewhere.
    if (Test-Path "$InstallDir\pyproject.toml") {
        Push-Location $InstallDir
        try {
            $pybagCheck = uv run python -c "import pybag; print(pybag.__version__)" 2>&1
            if ($LASTEXITCODE -eq 0) {
                $status.Pybag.Installed = $true
                # 2>&1 can make $pybagCheck a multi-line array (stderr warnings
                # before the version), which has no .Trim(); take the last line.
                $status.Pybag.Version = ($pybagCheck | Select-Object -Last 1).ToString().Trim()
            }
        } catch {}
        Pop-Location
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

    if ($Status.DotNet10Runtime.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline; Write-Host "] .NET 10 Runtime $($Status.DotNet10Runtime.Version)"
    } elseif ($Status.DotNet.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "!!" -ForegroundColor Yellow -NoNewline; Write-Host "] .NET 10 Runtime (required for ILSpyCmd)"
    }

    # x64dbg
    if ($Status.X64Dbg.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline; Write-Host "] x64dbg (dynamic analysis)"
    } else {
        Write-Host "    [" -NoNewline; Write-Host "--" -ForegroundColor DarkGray -NoNewline; Write-Host "] x64dbg (not installed)"
    }

    # WinDbg
    if ($Status.WinDbg.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline
        Write-Host "] WinDbg/CDB (kernel debugging) - $($Status.WinDbg.Path)"
    } else {
        Write-Host "    [" -NoNewline; Write-Host "--" -ForegroundColor DarkGray -NoNewline
        Write-Host "] WinDbg/CDB (not installed)"
    }

    if ($Status.Pybag.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "OK" -ForegroundColor Green -NoNewline
        Write-Host "] Pybag $($Status.Pybag.Version) (WinDbg Python bridge)"
    } elseif ($Status.WinDbg.Installed) {
        Write-Host "    [" -NoNewline; Write-Host "!!" -ForegroundColor Yellow -NoNewline
        Write-Host "] Pybag (not installed - required for WinDbg integration)"
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
    Write-Host "      Everything: Ghidra + .NET Tools + x64dbg + WinDbg + Claude Config" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [2] Static Analysis Only" -ForegroundColor White
    Write-Host "      Ghidra (native) + ILSpyCmd (.NET) - No debugger" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [3] Dynamic Analysis Only" -ForegroundColor White
    Write-Host "      x64dbg with MCP plugins - No static analysis tools" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [4] Kernel Debugging" -ForegroundColor White
    Write-Host "      WinDbg/CDB for kernel driver analysis + crash dumps" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [5] Custom Installation" -ForegroundColor White
    Write-Host "      Choose individual components to install" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [6] Repair/Update Existing" -ForegroundColor White
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
    $dotnetNote = if (-not $Status.DotNet.Installed) { "(requires .NET SDK 10.0+)" } else { "" }
    Write-Host "  [2] .NET Tools (ILSpyCmd) - C#/VB.NET decompilation $dotnetStatus" -ForegroundColor White
    if ($dotnetNote) { Write-Host "      $dotnetNote" -ForegroundColor Yellow }

    $x64dbgStatus = if ($Status.X64Dbg.Installed) { "[Installed]" } else { "" }
    Write-Host "  [3] x64dbg - Dynamic debugging/analysis $x64dbgStatus" -ForegroundColor White

    $windbgStatus = if ($Status.WinDbg.Installed) { "[Installed]" } else { "" }
    Write-Host "  [4] WinDbg - Kernel/user-mode debugging $windbgStatus" -ForegroundColor White

    Write-Host "  [5] Configure Claude Desktop" -ForegroundColor White
    Write-Host "  [6] Configure Claude Code" -ForegroundColor White
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
    $uvInstaller = Join-Path $env:TEMP "uv-install.ps1"
    try {
        # F-3: this used to be `Invoke-RestMethod ... | Invoke-Expression` - a
        # nested curl|iex inside an installer that itself runs as Administrator.
        # Whatever bytes came back from the network were executed immediately,
        # with no copy on disk to inspect and no opportunity to check anything.
        # Download to a file, verify it, then execute the verified copy.
        $uvDownload = Invoke-VerifiedDownload -Uri "https://astral.sh/uv/install.ps1" -OutFile $uvInstaller `
            -Description "uv installer script (astral.sh)" -HashKey "uv-installer-ps1"
        $uvVerified = Test-VerificationResult -Result $uvDownload

        # F-3 (second pass): the Mark-of-the-Web is the record that these bytes
        # came off the internet. Defender/SmartScreen, AMSI and any EDR on the
        # box key off it, and so does anyone doing forensics afterwards.
        # Stripping it from a file whose hash was NEVER checked - which is the
        # default state here, because $script:PinnedSha256['uv-installer-ps1']
        # ships empty and astral.sh publishes no digest - actively destroys
        # evidence about unverified attacker-influenceable content, which is
        # strictly worse than the pre-F-3 code that never touched MotW at all.
        # So: clear it only on the verified path.
        if ($uvVerified) {
            # Verified bytes: clearing MotW here removes a prompt about content
            # we have already proven matches the expected digest.
            Unblock-File -LiteralPath $uvInstaller -ErrorAction SilentlyContinue
        } else {
            Write-Warn "uv installer could not be verified - leaving its Mark-of-the-Web intact"
            Write-Warn "  so Defender/SmartScreen still treat it as downloaded content."
            Write-Warn "  Pin it with `$env:BINARY_MCP_SHA256_UV_INSTALLER_PS1, or re-run with"
            Write-Warn "  -StrictIntegrity to refuse unverified installers outright."
        }

        # Run the verified script in a child PowerShell rather than dot-sourcing
        # it: same effect (uv's installer persists PATH via the user
        # environment, which the refresh below picks up) without the execution
        # policy of this session getting in the way.
        $psExeName = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh' } else { 'powershell' }
        & $psExeName -NoProfile -ExecutionPolicy Bypass -File $uvInstaller
        if ($LASTEXITCODE -ne 0) {
            throw "uv installer exited with code $LASTEXITCODE"
        }

        # Refresh PATH: Machine PATH first, then User PATH (standard Windows order)
        $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
        $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
        $env:Path = "$machinePath;$userPath"
        Write-Success "uv installed successfully"
        return $true
    } catch {
        Write-Err "Failed to install uv: $_"
        return $false
    } finally {
        # F-3 (second pass): the previous code deleted the installer only on the
        # success path, so a hash mismatch, a non-zero exit, or any throw in
        # between left a downloaded - possibly unverified - PowerShell script
        # sitting at a predictable path in %TEMP%. That is one retry or one
        # double-click away from running, on a box that just ran an elevated
        # installer. Clean up on every exit path, including the throwing ones.
        Remove-Item -LiteralPath $uvInstaller -Force -ErrorAction SilentlyContinue
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
        # Ghidra ships a new build far more often than this file can track, so
        # there is no digest to hard-code. Try the checksum published with the
        # release; failing that the operator can pin BINARY_MCP_SHA256_GHIDRA_ZIP,
        # and failing that the download is called out loudly as unverified.
        $ghidraExpected = Get-ReleaseAssetChecksum -Release $ghidraRelease -AssetName $ghidraAsset.name
        Invoke-VerifiedDownload -Uri $ghidraAsset.browser_download_url -OutFile $ghidraZip `
            -Description "Ghidra $($ghidraRelease.tag_name) ($($ghidraAsset.name))" `
            -HashKey "ghidra-zip" -ExpectedSha256 $ghidraExpected | Out-Null
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

        # Ghidra 12.1+ ships Jython as an inert bundled extension zip under
        # Extensions\Ghidra\. Extract it into the install-tree extensions dir
        # (Ghidra\Extensions\) so analyzeHeadless can run our Jython pre-scripts.
        try {
            $installedDir = Join-Path $GhidraDir "Ghidra\Extensions"
            $jythonDir = Join-Path $installedDir "Jython"
            if (Test-Path $jythonDir -PathType Container) {
                Write-Info "Jython extension already activated, skipping"
            } else {
                # Bundled archives live under Extensions\Ghidra\; fall back to
                # the install-tree dir in case a layout drops the zip there.
                $sourceDirs = @((Join-Path $GhidraDir "Extensions\Ghidra"), $installedDir)
                $jythonZip = $null
                foreach ($src in $sourceDirs) {
                    if (Test-Path $src -PathType Container) {
                        $jythonZip = Get-ChildItem -Path $src -Filter "*Jython*.zip" -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($null -ne $jythonZip) { break }
                    }
                }
                if ($null -eq $jythonZip) {
                    Write-Info "No bundled Jython extension found (Ghidra < 12.1)"
                } else {
                    if (-not (Test-Path $installedDir -PathType Container)) {
                        New-Item -ItemType Directory -Path $installedDir -Force | Out-Null
                    }
                    Expand-Archive -Path $jythonZip.FullName -DestinationPath $installedDir -Force
                    Write-Success "Jython extension activated"
                }
            }
        } catch {
            Write-Warn "Failed to activate Jython extension: $_"
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
            Write-Info "Attempting to install .NET SDK 10.0 via winget..."
            if (-not (Install-DotNetSDK)) {
                Write-Info "Download manually from: https://dotnet.microsoft.com/download"
                return $false
            }
        } else {
            Write-Info "Download from: https://dotnet.microsoft.com/download"
            return $false
        }
    }

    # Check for .NET 10 runtime (current ILSpyCmd targets net10.0 and won't run without it)
    $runtimes = dotnet --list-runtimes 2>&1
    if ($runtimes -notmatch "Microsoft\.NETCore\.App 10\.") {
        Write-Warn ".NET 10 Runtime is required for ILSpyCmd but not found"
        if (Test-WingetAvailable) {
            Write-Info "Attempting to install .NET 10 Runtime via winget..."
            if (-not (Install-DotNetRuntime)) {
                Write-Info "Download manually from: https://dotnet.microsoft.com/download/dotnet/10.0"
                return $false
            }
        } else {
            Write-Info "Download .NET 10 Runtime from: https://dotnet.microsoft.com/download/dotnet/10.0"
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
            dotnet tool update -g ilspycmd 2>&1
            Write-Success "ILSpyCmd updated"
        } else {
            Write-Err "ILSpyCmd installation failed: $result"
            return $false
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

        # Verify ILSpyCmd actually runs. A version mismatch between the tool's
        # target framework (currently net10.0) and the installed runtime fails
        # only at launch with "You must install .NET", so a successful install
        # does not guarantee a working tool.
        $ilspyExe = "$toolsPath\ilspycmd.exe"
        $verifyCmd = if (Test-Path $ilspyExe) { $ilspyExe } else { "ilspycmd" }
        $versionOutput = & $verifyCmd --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "ILSpyCmd verified: $(($versionOutput | Select-Object -First 1))"
        } else {
            Write-Err "ILSpyCmd installed but failed to run"
            if ($versionOutput -match "You must install|download the \.NET|Framework.*not found") {
                Write-Warn "This is a .NET runtime mismatch - ILSpyCmd needs the .NET 10 Runtime"
                Write-Info "Install it with: winget install Microsoft.DotNet.Runtime.10"
            } else {
                Write-Warn "ilspycmd --version output: $versionOutput"
            }
            return $false
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

    $x64dbgZip = "$env:TEMP\x64dbg.zip"

    try {
        # Resolve actual snapshot asset name via GitHub API (no longer named snapshot_latest.zip)
        Write-Info "Fetching latest x64dbg snapshot release..."
        $snapshotRelease = Invoke-RestMethod "https://api.github.com/repos/x64dbg/x64dbg/releases/tags/snapshot"
        $snapshotAsset = $snapshotRelease.assets | Where-Object {
            $_.name -match "^snapshot_.*\.zip$" -and $_.name -notmatch "symbols"
        } | Select-Object -First 1

        if ($null -eq $snapshotAsset) {
            Write-Err "Could not find x64dbg snapshot asset in release"
            return $false
        }

        Write-Info "Downloading x64dbg ($($snapshotAsset.name))..."
        # The x64dbg "snapshot" tag is a rolling release: the asset behind it is
        # replaced without warning, so a hard-coded digest here would break every
        # install within days. Use whatever checksum the release publishes, or an
        # operator pin (BINARY_MCP_SHA256_X64DBG_SNAPSHOT), else warn loudly.
        $x64dbgExpected = Get-ReleaseAssetChecksum -Release $snapshotRelease -AssetName $snapshotAsset.name
        Invoke-VerifiedDownload -Uri $snapshotAsset.browser_download_url -OutFile $x64dbgZip `
            -Description "x64dbg snapshot ($($snapshotAsset.name))" `
            -HashKey "x64dbg-snapshot" -ExpectedSha256 $x64dbgExpected | Out-Null
        Write-Success "Downloaded x64dbg"

        Write-Info "Extracting x64dbg..."
        Expand-Archive -Path $x64dbgZip -DestinationPath $X64DbgDir -Force

        # Verify extraction produced expected binaries
        if (-not (Test-Path "$X64DbgDir\release\x64\x64dbg.exe")) {
            Write-Err "Extraction succeeded but x64dbg.exe not found at expected path"
            Write-Info "Expected: $X64DbgDir\release\x64\x64dbg.exe"
            return $false
        }

        Write-Success "x64dbg installed to: $X64DbgDir"

        [System.Environment]::SetEnvironmentVariable("X64DBG_HOME", $X64DbgDir, "User")
        $env:X64DBG_HOME = $X64DbgDir

        Remove-Item $x64dbgZip -ErrorAction SilentlyContinue

        # Install Obsidian MCP bridge plugins
        Write-Info "Installing Obsidian x64dbg plugins..."
        try {
            $pluginRelease = Get-LatestGitHubRelease "Sarks0/binary-mcp"
            $plugin64 = $pluginRelease.assets | Where-Object { $_.name -eq "obsidian.dp64" } | Select-Object -First 1
            $plugin32 = $pluginRelease.assets | Where-Object { $_.name -eq "obsidian.dp32" } | Select-Object -First 1
            $server = $pluginRelease.assets | Where-Object { $_.name -eq "obsidian_server.exe" } | Select-Object -First 1

            if ($plugin64 -and $plugin32 -and $server) {
                $plugin64Dir = "$X64DbgDir\release\x64\plugins"
                $plugin32Dir = "$X64DbgDir\release\x32\plugins"
                New-Item -ItemType Directory -Force -Path $plugin64Dir | Out-Null
                New-Item -ItemType Directory -Force -Path $plugin32Dir | Out-Null

                # F-3, the most load-bearing check in this script: obsidian.dp64
                # is loaded by x64dbg into the process that debugs live malware,
                # on an analyst box, installed by an elevated script. These are
                # OUR release assets, so their digests are ones the maintainer
                # actually controls - publish a SHA256SUMS file with the release
                # and every install verifies against it.
                #
                # Download to a staging directory first and only copy into the
                # x64dbg plugins directory after the checks pass, so an artifact
                # that fails verification is never even momentarily present
                # somewhere x64dbg would load it from.
                #
                # .github/workflows/release.yml now generates SHA256SUMS in the
                # same job that uploads these assets, so for any release built
                # after that change the manifest lookup below resolves a real
                # digest and the verification is no longer inert.
                $checksums = Get-ReleaseChecksumMap -Release $pluginRelease
                if ($checksums.Count -eq 0) {
                    Write-Warn "This binary-mcp release publishes no SHA256SUMS manifest."
                    Write-Warn "  Releases built by .github/workflows/release.yml do publish one, so this is"
                    Write-Warn "  either a release predating that change or a release whose manifest was removed."
                    Write-Warn "  The plugin binaries below cannot be verified against a published digest;"
                    Write-Warn "  pin them with `$env:BINARY_MCP_SHA256_BINARY_MCP_OBSIDIAN_DP64 (and _DP32,"
                    Write-Warn "  _OBSIDIAN_SERVER_EXE), or re-run with -StrictIntegrity to refuse them."
                }

                $stagingDir = Join-Path $env:TEMP ("binary-mcp-plugins-" + [guid]::NewGuid().ToString("N"))
                New-Item -ItemType Directory -Force -Path $stagingDir | Out-Null
                try {
                    $stagedFiles = @{}
                    foreach ($asset in @($plugin64, $plugin32, $server)) {
                        $staged = Join-Path $stagingDir $asset.name
                        $expected = $null
                        $assetHashKey = "binary-mcp-" + $asset.name
                        if ($checksums.ContainsKey($asset.name)) {
                            $expected = $checksums[$asset.name]
                        } elseif (Get-PinnedSha256 -HashKey $assetHashKey) {
                            # An operator pin still wins: it is a stronger claim
                            # than the manifest (it survives a release takeover).
                            $expected = Get-PinnedSha256 -HashKey $assetHashKey
                        } elseif ($checksums.Count -gt 0) {
                            # F-3: fail CLOSED when the manifest exists but does
                            # not cover this asset. release.yml refuses to
                            # publish a partial SHA256SUMS, so a manifest that
                            # lists some assets and not obsidian.dp64 is not a
                            # packaging slip - it is what an asset swapped in
                            # after the manifest was generated looks like.
                            # Falling through to the "unverified" warning here
                            # would let exactly that case install a DLL x64dbg
                            # loads next to live malware.
                            throw ("$($asset.name) is not listed in this release's SHA256SUMS manifest, " +
                                   "but other assets are. Refusing to install an unlisted plugin binary. " +
                                   "Build the plugins from source (src/engines/dynamic/x64dbg/plugin/README.md), " +
                                   "or pin the digest you trust in `$env:$(Get-IntegrityEnvName $assetHashKey).")
                        }

                        Invoke-VerifiedDownload -Uri $asset.browser_download_url -OutFile $staged `
                            -Description "binary-mcp release asset $($asset.name)" `
                            -HashKey ("binary-mcp-" + $asset.name) -ExpectedSha256 $expected | Out-Null

                        # Wired up now so signing the release later needs no
                        # installer change. -AllowUnsigned because the assets are
                        # not code-signed today; a *broken* signature still warns
                        # (and is fatal under -StrictIntegrity).
                        #
                        # For .dp64/.dp32 this always reports 'UnknownError' -
                        # Windows dispatches signature checks by extension and
                        # does not know these - so the result is informational
                        # only and the SHA-256 above is the real control. See the
                        # UnknownError branch in Assert-AuthenticodeValid.
                        Assert-AuthenticodeValid -Path $staged -Description $asset.name -AllowUnsigned | Out-Null

                        $stagedFiles[$asset.name] = $staged
                    }

                    Copy-Item -LiteralPath $stagedFiles[$plugin64.name] -Destination "$plugin64Dir\obsidian.dp64" -Force
                    Copy-Item -LiteralPath $stagedFiles[$server.name] -Destination "$plugin64Dir\obsidian_server.exe" -Force
                    Copy-Item -LiteralPath $stagedFiles[$plugin32.name] -Destination "$plugin32Dir\obsidian.dp32" -Force
                    Copy-Item -LiteralPath $stagedFiles[$server.name] -Destination "$plugin32Dir\obsidian_server.exe" -Force
                    Write-Success "Obsidian plugins installed"
                } finally {
                    Remove-Item -LiteralPath $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            } else {
                Write-Warn "Pre-built Obsidian plugins not found in latest release"
                Write-Info "Build manually: src/engines/dynamic/x64dbg/plugin/README.md"
            }
        } catch {
            # An integrity failure lands here. Not installing the plugins is the
            # safe outcome, but say so unambiguously rather than leaving a
            # one-line warning about a DLL x64dbg would load next to live malware.
            Write-Err "Obsidian plugin installation ABORTED: $_"
            Write-Warn "x64dbg is installed, but the MCP bridge plugins are not."
            Write-Info "Build them from source instead: src/engines/dynamic/x64dbg/plugin/README.md"
        }

        return $true
    } catch {
        Remove-Item $x64dbgZip -ErrorAction SilentlyContinue
        Write-Err "Failed to install x64dbg: $_"
        return $false
    }
}

function Install-WinDbg {
    Write-Info "Setting up WinDbg/Debugging Tools..."

    $existingPath = Find-WinDbgPath

    if ($existingPath) {
        Write-Success "WinDbg/CDB found at: $existingPath"
        [System.Environment]::SetEnvironmentVariable("WINDBG_PATH", $existingPath, "User")
        $env:WINDBG_PATH = $existingPath
    } else {
        $installed = $false

        # Method 1: Windows SDK via winget (includes cdb.exe, kd.exe, windbg.exe)
        if (-not $installed -and (Test-WingetAvailable)) {
            Write-Info "Installing Windows SDK Debugging Tools via winget..."
            $installed = Install-WithWinget -PackageId "Microsoft.WindowsSDK.10.0.26100" -PackageName "Windows SDK"

            # Set default path for SDK debuggers
            if ($installed) {
                $sdkPath = "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64"
                if (Test-Path "$sdkPath\cdb.exe") {
                    [System.Environment]::SetEnvironmentVariable("WINDBG_PATH", $sdkPath, "User")
                    $env:WINDBG_PATH = $sdkPath
                    Write-Success "CDB found at: $sdkPath"
                }
            }
        }

        # Method 2: WinDbg Preview via winget (modern UI, may not include standalone cdb.exe)
        if (-not $installed -and (Test-WingetAvailable)) {
            Write-Info "Trying WinDbg Preview via winget..."
            $installed = Install-WithWinget -PackageId "Microsoft.WinDbg" -PackageName "WinDbg Preview"
        }

        # Method 3: Download Windows SDK installer and install just the debuggers
        if (-not $installed) {
            Write-Info "Attempting Windows SDK Debugging Tools standalone install..."
            # Declared outside the try so the finally below can always clean it
            # up, including when the download or the signature check throws.
            $sdkSetup = "$env:TEMP\winsdksetup.exe"
            try {
                Write-Info "Downloading Windows SDK installer..."
                # A go.microsoft.com fwlink resolves to whatever build Microsoft
                # currently serves, so no digest can be pinned in-tree
                # (BINARY_MCP_SHA256_WINDOWS_SDK_SETUP if an operator wants to).
                # The bootstrapper is Microsoft-signed, though, so Authenticode
                # is the real check here - and it runs elevated moments later.
                Invoke-VerifiedDownload -Uri "https://go.microsoft.com/fwlink/?linkid=2173743" -OutFile $sdkSetup `
                    -Description "Windows SDK bootstrapper (winsdksetup.exe)" -HashKey "windows-sdk-setup" | Out-Null
                # F-3 (second pass): this result used to be piped to Out-Null,
                # which threw away the only thing it computes. A BAD signature -
                # a bootstrapper signed by someone other than Microsoft, or one
                # whose signature does not match its bytes - printed a warning
                # and then fell straight through to the Start-Process below,
                # which runs it with the Administrator token this whole script
                # already holds. An unsigned/mis-signed elevated installer is
                # precisely the outcome the check exists to prevent, so a
                # non-Valid result must abort. Note -AllowUnsigned is
                # deliberately NOT passed here: unlike our own plugin assets,
                # winsdksetup.exe is always Microsoft-signed, so "no signature"
                # is itself a red flag rather than the expected state.
                $sdkSigOk = Assert-AuthenticodeValid -Path $sdkSetup -Description "Windows SDK bootstrapper" `
                    -ExpectedSubjectMatch "Microsoft Corporation"
                if (-not (Test-VerificationResult -Result $sdkSigOk)) {
                    throw ("Refusing to run the Windows SDK bootstrapper: it is not validly " +
                           "Authenticode-signed by Microsoft Corporation. It would have been executed " +
                           "with Administrator rights. Install the debuggers instead with " +
                           "'winget install Microsoft.WindowsSDK.10.0.26100', or download the SDK by hand " +
                           "from https://developer.microsoft.com/windows/downloads/windows-sdk/ and check " +
                           "its signature before running it.")
                }

                Write-Info "Installing Debugging Tools for Windows (silent)..."
                $proc = Start-Process -FilePath $sdkSetup -ArgumentList "/features OptionId.WindowsDesktopDebuggers /quiet" -Wait -PassThru
                if ($proc.ExitCode -eq 0) {
                    Write-Success "Debugging Tools for Windows installed"
                    $installed = $true
                } else {
                    Write-Warn "SDK installer exited with code: $($proc.ExitCode)"
                }
            } catch {
                Write-Warn "Failed to install via SDK: $_"
            } finally {
                # F-3 (second pass): previously deleted only on the success path,
                # so a failed signature check or a throwing download left an
                # unverified elevated-installer .exe at a predictable %TEMP%
                # path. Remove it however this block exits.
                Remove-Item -LiteralPath $sdkSetup -Force -ErrorAction SilentlyContinue
            }
        }

        if (-not $installed) {
            Write-Err "Could not install WinDbg automatically"
            Write-Info "Manual installation options:"
            Write-Info "  1. winget install Microsoft.WindowsSDK.10.0.26100"
            Write-Info "  2. winget install Microsoft.WinDbg"
            Write-Info "  3. Download Windows SDK: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/"
            Write-Info "     Select 'Debugging Tools for Windows' during installation"
            return $false
        }

        # Re-detect path after installation
        $detectedPath = Find-WinDbgPath
        if ($detectedPath) {
            Write-Success "WinDbg detected at: $detectedPath"
            [System.Environment]::SetEnvironmentVariable("WINDBG_PATH", $detectedPath, "User")
            $env:WINDBG_PATH = $detectedPath
        } else {
            Write-Warn "WinDbg installed but could not auto-detect path"
            Write-Info "Set WINDBG_PATH manually if needed"
        }
    }

    # Install Pybag Python package (WinDbg COM API bridge). This needs the
    # Binary MCP project (pyproject.toml) present so uv can resolve the
    # environment; in repair mode WinDbg can be selected without it.
    Write-Info "Installing Pybag (WinDbg Python bridge)..."
    $pybagInstalled = $false

    if (-not (Test-Path "$InstallDir\pyproject.toml")) {
        Write-Warn "Binary MCP not found at $InstallDir - cannot set up Pybag yet"
        Write-Info "Install the Binary MCP server first, then re-run this step"
    } else {
        # Method 1: Try uv sync --extra windbg (requires windbg extra in pyproject.toml)
        Push-Location $InstallDir
        try {
            $syncOutput = & uv sync --extra dev --extra windbg 2>&1
            if ($LASTEXITCODE -eq 0) {
                $pybagInstalled = $true
                Write-Success "Pybag installed successfully via uv sync"
            } else {
                Write-Warn "uv sync --extra windbg failed (exit $LASTEXITCODE)"
            }
        } catch {
            Write-Warn "uv sync --extra windbg error: $_"
        }
        Pop-Location

        # Method 2: Fall back to uv pip install if extra is not defined yet
        if (-not $pybagInstalled) {
            Push-Location $InstallDir
            try {
                Write-Info "Falling back to direct pybag install..."
                $pipOutput = & uv pip install "pybag>=2.2.16" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $pybagInstalled = $true
                    Write-Success "Pybag installed successfully via uv pip"
                } else {
                    Write-Warn "uv pip install failed (exit code $LASTEXITCODE): $pipOutput"
                }
            } catch {
                Write-Warn "Failed to install Pybag: $_"
            }
            Pop-Location
        }

        if (-not $pybagInstalled) {
            Write-Err "Could not install Pybag automatically"
            Write-Info "Install manually: uv pip install pybag"
        }
    }

    # Enable kernel debugging via bcdedit (requires reboot to take effect)
    Write-Info "Checking kernel debug mode..."
    try {
        $bcdeditOutput = bcdedit /enum "{current}" 2>&1 | Out-String
        if ($bcdeditOutput -match "debug\s+Yes") {
            Write-Success "Kernel debug mode is already enabled"
        } else {
            Write-Info "Enabling kernel debug mode (bcdedit -debug on)..."
            $debugResult = bcdedit -debug on 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Kernel debug mode enabled"
                Write-Warn "A reboot is required for kernel debugging to take effect"
                Write-Info "Run: shutdown /r /t 0"
            } else {
                if ($debugResult -match "Secure Boot|secure boot|0xc0000428") {
                    Write-Err "Cannot enable kernel debugging: Secure Boot is enabled"
                    Write-Info "To fix this:"
                    Write-Info "  1. Restart your PC and enter BIOS/UEFI settings"
                    Write-Info "  2. Navigate to Security > Secure Boot"
                    Write-Info "  3. Set Secure Boot to Disabled"
                    Write-Info "  4. Save and exit BIOS"
                    Write-Info "  5. Re-run this installer or manually run: bcdedit -debug on"
                } else {
                    Write-Warn "bcdedit -debug on failed: $debugResult"
                    Write-Info "Try running this installer as Administrator"
                }
            }
        }
    } catch {
        Write-Warn "Could not check/set kernel debug mode: $_"
        Write-Info "Manually run as Administrator: bcdedit -debug on"
    }

    return $true
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
                # A branch archive has no stable digest by construction - it
                # changes with every push, and GitHub does not publish checksums
                # for it. That is exactly why the git clone path above is
                # preferred (it at least verifies commit contents against the
                # remote); this fallback says out loud that it cannot verify.
                Invoke-VerifiedDownload -Uri $zipUrl -OutFile $zipFile `
                    -Description "binary-mcp source archive (main branch)" -HashKey "repo-zip" | Out-Null
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

function Get-McpServerConfig {
    # Build MCP server config with env vars for all detected/installed tools
    $envVars = @{}

    if ($env:GHIDRA_HOME -and (Test-Path $env:GHIDRA_HOME)) {
        $envVars["GHIDRA_HOME"] = $env:GHIDRA_HOME
    } elseif (Test-Path $GhidraDir) {
        $envVars["GHIDRA_HOME"] = $GhidraDir
    }

    if ($env:X64DBG_HOME -and (Test-Path $env:X64DBG_HOME)) {
        $envVars["X64DBG_HOME"] = $env:X64DBG_HOME
    } elseif (Test-Path $X64DbgDir) {
        $envVars["X64DBG_HOME"] = $X64DbgDir
    }

    if ($env:WINDBG_PATH -and (Test-Path "$env:WINDBG_PATH\cdb.exe")) {
        $envVars["WINDBG_PATH"] = $env:WINDBG_PATH
    } else {
        $detectedWinDbg = Find-WinDbgPath
        if ($detectedWinDbg) {
            $envVars["WINDBG_PATH"] = $detectedWinDbg
        }
    }

    $serverConfig = @{
        command = "uv"
        args = @("--directory", $InstallDir, "run", "python", "-m", "src.server")
    }

    if ($envVars.Count -gt 0) {
        $serverConfig["env"] = $envVars
    }

    return $serverConfig
}

function Merge-McpConfig {
    # Merge our binary-mcp server into an existing parsed config and return a
    # plain hashtable ready for ConvertTo-Json.
    #
    # This must use hashtables, not Add-Member on the parsed object: when the
    # config (or its mcpServers) is a Hashtable, ConvertTo-Json serializes only
    # the dictionary entries and silently drops NoteProperties added via
    # Add-Member - which would write an empty "mcpServers": {} on a fresh
    # install. Rebuilding as hashtables also preserves any existing top-level
    # keys (e.g. other entries in Claude Code's settings.json).
    param($ExistingConfig)

    $config = @{}
    if ($ExistingConfig) {
        foreach ($prop in $ExistingConfig.PSObject.Properties) {
            $config[$prop.Name] = $prop.Value
        }
    }

    $servers = @{}
    if ($ExistingConfig -and $ExistingConfig.mcpServers) {
        foreach ($prop in $ExistingConfig.mcpServers.PSObject.Properties) {
            $servers[$prop.Name] = $prop.Value
        }
    }
    $servers["binary-mcp"] = Get-McpServerConfig

    $config["mcpServers"] = $servers
    return $config
}

function Configure-ClaudeDesktop {
    Write-Info "Configuring Claude Desktop..."

    $claudeConfigDir = "$env:APPDATA\Claude"
    $claudeConfigFile = "$claudeConfigDir\claude_desktop_config.json"

    if (-not (Test-Path $claudeConfigDir)) {
        New-Item -ItemType Directory -Path $claudeConfigDir -Force | Out-Null
    }

    try {
        $existingConfig = $null
        if (Test-Path $claudeConfigFile) {
            # Read with UTF-8 encoding to properly handle any existing content
            # Note: -Encoding UTF8 in PS 5.1 handles both with and without BOM
            $existingConfig = Get-Content $claudeConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
            Copy-Item $claudeConfigFile "$claudeConfigFile.backup" -Force
            Write-Info "Backup saved to: $claudeConfigFile.backup"
        }

        $config = Merge-McpConfig $existingConfig

        # Write JSON with UTF-8 encoding WITHOUT BOM (required for Claude Desktop compatibility)
        # Note: PowerShell 5.1's -Encoding UTF8 adds BOM, so we use .NET directly
        $jsonContent = $config | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText($claudeConfigFile, $jsonContent, [System.Text.UTF8Encoding]::new($false))
        Write-Success "Claude Desktop configured at: $claudeConfigFile"
        return $true
    } catch {
        Write-Err "Failed to configure Claude Desktop: $_"
        return $false
    }
}

function Configure-ClaudeCode {
    Write-Info "Configuring Claude Code..."

    # Claude Code reads settings from ~/.claude/settings.json (not ~/.config/claude-code/)
    $claudeCodeConfigDir = "$env:USERPROFILE\.claude"
    $claudeCodeConfigFile = "$claudeCodeConfigDir\settings.json"

    if (-not (Test-Path $claudeCodeConfigDir)) {
        New-Item -ItemType Directory -Path $claudeCodeConfigDir -Force | Out-Null
    }

    try {
        $existingConfig = $null
        if (Test-Path $claudeCodeConfigFile) {
            # Read with UTF-8 encoding to properly handle any existing content
            # Note: -Encoding UTF8 in PS 5.1 handles both with and without BOM
            $existingConfig = Get-Content $claudeCodeConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
            Copy-Item $claudeCodeConfigFile "$claudeCodeConfigFile.backup" -Force
            Write-Info "Backup saved to: $claudeCodeConfigFile.backup"
        }

        # Merge preserves other top-level keys already in settings.json
        $config = Merge-McpConfig $existingConfig

        # Write JSON with UTF-8 encoding WITHOUT BOM (required for compatibility)
        # Note: PowerShell 5.1's -Encoding UTF8 adds BOM, so we use .NET directly
        $jsonContent = $config | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText($claudeCodeConfigFile, $jsonContent, [System.Text.UTF8Encoding]::new($false))
        Write-Success "Claude Code configured at: $claudeCodeConfigFile"
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
    if ($Installed.WinDbg) {
        Write-Success "WinDbg: Kernel debugging ready"
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

    if ($Installed.WinDbg) {
        Write-Host "  4. For kernel debugging:" -ForegroundColor White
        Write-Host "     - Crash dumps: 'Analyze the crash dump at C:\path\to\MEMORY.DMP'" -ForegroundColor DarkGray
        Write-Host "     - Live kernel: 'Connect to kernel debugger on port 50000'" -ForegroundColor DarkGray
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
        $missingPrereqs += @{ Name = ".NET SDK 10.0"; Key = "dotnetsdk"; Installer = { Install-DotNetSDK } }
    } elseif (-not $status.DotNet10Runtime.Installed) {
        $missingPrereqs += @{ Name = ".NET 10 Runtime"; Key = "dotnetruntime"; Installer = { Install-DotNetRuntime } }
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
    WinDbg = $false
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
        "kernel"  { "4" }
        "custom"  { "5" }
        "repair"  { "6" }
        default   { $InstallProfile }
    }
} else {
    Show-InstallMenu
    $selection = Get-UserSelection "Enter choice (1-6, Q to quit)"
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
        $installed.WinDbg = Install-WinDbg
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

    { $_ -in "4", "kernel" } {
        # Kernel debugging
        Write-Host ""
        Write-Info "Starting Kernel Debugging Installation..."
        Write-Host ""

        $installed.BinaryMCP = Install-BinaryMCP
        $installed.WinDbg = Install-WinDbg
        $installed.ClaudeDesktop = Configure-ClaudeDesktop
    }

    { $_ -in "5", "custom" } {
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
            @("1", "2", "3", "4", "5", "6")
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
                        Write-Warn "Cannot install ILSpyCmd - .NET SDK 10.0+ required"
                    }
                }
                "3" { $installed.X64Dbg = Install-X64Dbg }
                "4" { $installed.WinDbg = Install-WinDbg }
                "5" { $installed.ClaudeDesktop = Configure-ClaudeDesktop }
                "6" { $installed.ClaudeCode = Configure-ClaudeCode }
            }
        }
    }

    { $_ -in "6", "repair" } {
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
                "4" { $installed.WinDbg = Install-WinDbg }
                "5" { $installed.ClaudeDesktop = Configure-ClaudeDesktop }
                "6" { $installed.ClaudeCode = Configure-ClaudeCode }
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
