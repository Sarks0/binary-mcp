#!/usr/bin/env python3
"""
Binary MCP Server - Cross-Platform Installer
Interactive installation script for Linux and macOS with full tooling support.
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request


# ============================================================
# Terminal Colors and Output Helpers
# ============================================================

class Colors:
    MAGENTA = '\033[95m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'


def print_success(msg: str) -> None:
    print(f"{Colors.GREEN}[OK]{Colors.RESET} {msg}")


def print_info(msg: str) -> None:
    print(f"{Colors.CYAN}[i]{Colors.RESET} {msg}")


def print_warning(msg: str) -> None:
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")


def print_error(msg: str) -> None:
    print(f"{Colors.RED}[X]{Colors.RESET} {msg}")


def print_banner() -> None:
    """Display ASCII art banner."""
    os.system('clear' if os.name != 'nt' else 'cls')
    print()
    print(f"{Colors.MAGENTA}  ____  _                          __  __  ____ ____  {Colors.RESET}")
    print(f"{Colors.MAGENTA} | __ )(_)_ __   __ _ _ __ _   _  |  \\/  |/ ___|  _ \\ {Colors.RESET}")
    print(f"{Colors.MAGENTA} |  _ \\| | '_ \\ / _` | '__| | | | | |\\/| | |   | |_) |{Colors.RESET}")
    print(f"{Colors.MAGENTA} | |_) | | | | | (_| | |  | |_| | | |  | | |___|  __/ {Colors.RESET}")
    print(f"{Colors.MAGENTA} |____/|_|_| |_|\\__,_|_|   \\__, | |_|  |_|\\____|_|    {Colors.RESET}")
    print(f"{Colors.MAGENTA}                           |___/                      {Colors.RESET}")
    print()
    print(f"  Binary Analysis MCP Server - Automated Installer")
    print(f"{Colors.DIM}  https://github.com/Sarks0/binary-mcp{Colors.RESET}")
    print()
    print(f"{Colors.DIM}  ================================================{Colors.RESET}")
    print()


# ============================================================
# Utility Functions
# ============================================================

def command_exists(cmd: str) -> bool:
    """Check if a command exists in PATH."""
    return shutil.which(cmd) is not None


def get_command_version(cmd: str, version_arg: str = "--version") -> Optional[str]:
    """Get version string from a command."""
    try:
        result = subprocess.run(
            [cmd, version_arg],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout or result.stderr
        return output.strip().split('\n')[0] if output else None
    except Exception:
        return None


def run_command(cmd: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Run a command with proper error handling."""
    try:
        return subprocess.run(
            cmd,
            check=check,
            capture_output=capture,
            text=True
        )
    except subprocess.CalledProcessError as e:
        print_error(f"Command failed: {' '.join(cmd)}")
        if e.stderr:
            print_error(e.stderr)
        raise


def fetch_github_release(repo: str) -> dict:
    """Fetch latest GitHub release information."""
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = Request(url, headers={"User-Agent": "binary-mcp-installer"})

    try:
        with urlopen(req, timeout=15) as response:
            return json.loads(response.read())
    except Exception as e:
        print_error(f"Failed to fetch release for {repo}: {e}")
        raise


def download_file(url: str, dest: Path, description: str = "file") -> bool:
    """Download a file with progress indication."""
    print_info(f"Downloading {description}...")

    try:
        req = Request(url, headers={"User-Agent": "binary-mcp-installer"})

        with urlopen(req, timeout=300) as response:
            total = int(response.headers.get('content-length', 0))
            downloaded = 0

            with open(dest, 'wb') as f:
                while chunk := response.read(8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total > 0:
                        pct = (downloaded / total) * 100
                        print(f"\r  Progress: {pct:.1f}%", end='', flush=True)

            print()

        print_success(f"Downloaded {description}")
        return True
    except Exception as e:
        print_error(f"Download failed: {e}")
        return False


# ============================================================
# System Status Detection
# ============================================================

@dataclass
class ComponentStatus:
    installed: bool = False
    version: str = ""
    path: str = ""


@dataclass
class SystemStatus:
    system: str = ""
    package_manager: str = ""
    python: ComponentStatus = field(default_factory=ComponentStatus)
    java: ComponentStatus = field(default_factory=ComponentStatus)
    dotnet: ComponentStatus = field(default_factory=ComponentStatus)
    dotnet8_runtime: ComponentStatus = field(default_factory=ComponentStatus)
    git: ComponentStatus = field(default_factory=ComponentStatus)
    uv: ComponentStatus = field(default_factory=ComponentStatus)
    ghidra: ComponentStatus = field(default_factory=ComponentStatus)
    ilspycmd: ComponentStatus = field(default_factory=ComponentStatus)
    binary_mcp: ComponentStatus = field(default_factory=ComponentStatus)


def detect_package_manager() -> str:
    """Detect the system's package manager."""
    system = platform.system()

    if system == "Darwin":
        if command_exists("brew"):
            return "brew"
    elif system == "Linux":
        if command_exists("apt"):
            return "apt"
        elif command_exists("dnf"):
            return "dnf"
        elif command_exists("pacman"):
            return "pacman"
        elif command_exists("zypper"):
            return "zypper"
        elif command_exists("apk"):
            return "apk"

    return ""


def get_system_status(install_dir: Path, ghidra_dir: Path) -> SystemStatus:
    """Gather current system status."""
    status = SystemStatus()
    status.system = platform.system()
    status.package_manager = detect_package_manager()

    # Python
    status.python.installed = True  # We're running Python!
    status.python.version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    status.python.path = sys.executable

    # Java
    if command_exists("java"):
        status.java.installed = True
        ver = get_command_version("java", "-version")
        if ver:
            status.java.version = ver
        status.java.path = shutil.which("java") or ""

    # .NET SDK
    if command_exists("dotnet"):
        status.dotnet.installed = True
        status.dotnet.version = get_command_version("dotnet") or ""
        status.dotnet.path = shutil.which("dotnet") or ""

        # Check for .NET 8 runtime
        try:
            result = subprocess.run(
                ["dotnet", "--list-runtimes"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if "Microsoft.NETCore.App 8." in result.stdout:
                status.dotnet8_runtime.installed = True
                for line in result.stdout.split('\n'):
                    if "Microsoft.NETCore.App 8." in line:
                        # Extract version like "8.0.0"
                        parts = line.split()
                        if len(parts) >= 2:
                            status.dotnet8_runtime.version = parts[1]
                        break
        except Exception:
            pass

    # Git
    if command_exists("git"):
        status.git.installed = True
        status.git.version = get_command_version("git") or ""
        status.git.path = shutil.which("git") or ""

    # uv
    if command_exists("uv"):
        status.uv.installed = True
        status.uv.version = get_command_version("uv") or ""
        status.uv.path = shutil.which("uv") or ""

    # Ghidra
    if ghidra_dir.exists():
        status.ghidra.installed = True
        status.ghidra.path = str(ghidra_dir)
    elif os.environ.get("GHIDRA_HOME") and Path(os.environ["GHIDRA_HOME"]).exists():
        status.ghidra.installed = True
        status.ghidra.path = os.environ["GHIDRA_HOME"]

    # ILSpyCmd
    ilspy_path = Path.home() / ".dotnet" / "tools" / "ilspycmd"
    if ilspy_path.exists() or command_exists("ilspycmd"):
        status.ilspycmd.installed = True
        status.ilspycmd.path = str(ilspy_path) if ilspy_path.exists() else shutil.which("ilspycmd") or ""

    # Binary MCP
    if (install_dir / "pyproject.toml").exists():
        status.binary_mcp.installed = True
        status.binary_mcp.path = str(install_dir)

    return status


def show_system_status(status: SystemStatus) -> None:
    """Display current system status."""
    print(f"  {Colors.YELLOW}SYSTEM STATUS{Colors.RESET}")
    print(f"  {Colors.YELLOW}-------------{Colors.RESET}")
    print()

    # Package Manager
    print(f"  Package Manager:")
    if status.package_manager:
        print(f"    [{Colors.GREEN}OK{Colors.RESET}] {status.package_manager} (can auto-install prerequisites)")
    else:
        print(f"    [{Colors.YELLOW}--{Colors.RESET}] No supported package manager found")

    print()
    print(f"  Core Requirements:")

    # Python
    py_ver = tuple(map(int, status.python.version.split('.')[:2]))
    if py_ver >= (3, 12):
        print(f"    [{Colors.GREEN}OK{Colors.RESET}] Python {status.python.version}")
    else:
        print(f"    [{Colors.YELLOW}!!{Colors.RESET}] Python {status.python.version} (3.12+ recommended)")

    # uv
    if status.uv.installed:
        print(f"    [{Colors.GREEN}OK{Colors.RESET}] uv package manager")
    else:
        print(f"    [{Colors.DIM}--{Colors.RESET}] uv (will be installed)")

    # Git
    if status.git.installed:
        print(f"    [{Colors.GREEN}OK{Colors.RESET}] Git")
    else:
        print(f"    [{Colors.DIM}--{Colors.RESET}] Git (optional, for updates)")

    print()
    print(f"  Analysis Components:")

    # Ghidra
    if status.ghidra.installed:
        print(f"    [{Colors.GREEN}OK{Colors.RESET}] Ghidra (native binary analysis)")
    else:
        print(f"    [{Colors.DIM}--{Colors.RESET}] Ghidra (not installed)")

    # Java
    if status.java.installed:
        print(f"    [{Colors.GREEN}OK{Colors.RESET}] Java 21+ (for Ghidra)")
    else:
        print(f"    [{Colors.DIM}--{Colors.RESET}] Java 21+ (required for Ghidra)")

    # ILSpyCmd
    if status.ilspycmd.installed:
        print(f"    [{Colors.GREEN}OK{Colors.RESET}] ILSpyCmd (.NET decompilation)")
    else:
        print(f"    [{Colors.DIM}--{Colors.RESET}] ILSpyCmd (not installed)")

    # .NET SDK
    if status.dotnet.installed:
        print(f"    [{Colors.GREEN}OK{Colors.RESET}] .NET SDK {status.dotnet.version}")
    else:
        print(f"    [{Colors.DIM}--{Colors.RESET}] .NET SDK (required for ILSpyCmd)")

    # .NET 8 Runtime
    if status.dotnet8_runtime.installed:
        print(f"    [{Colors.GREEN}OK{Colors.RESET}] .NET 8 Runtime {status.dotnet8_runtime.version}")
    elif status.dotnet.installed:
        print(f"    [{Colors.YELLOW}!!{Colors.RESET}] .NET 8 Runtime (required for ILSpyCmd)")

    print()
    print(f"  Binary MCP Server:")
    if status.binary_mcp.installed:
        print(f"    [{Colors.GREEN}OK{Colors.RESET}] Installed at {status.binary_mcp.path}")
    else:
        print(f"    [{Colors.DIM}--{Colors.RESET}] Not installed")

    print()


# ============================================================
# Installation Menu
# ============================================================

def show_install_menu() -> None:
    """Display installation options menu."""
    print(f"  {Colors.YELLOW}INSTALLATION OPTIONS{Colors.RESET}")
    print(f"  {Colors.YELLOW}--------------------{Colors.RESET}")
    print()
    print(f"  [1] Full Installation")
    print(f"{Colors.DIM}      Everything: Ghidra + .NET Tools + Claude Config{Colors.RESET}")
    print()
    print(f"  [2] Static Analysis Only")
    print(f"{Colors.DIM}      Ghidra (native) + ILSpyCmd (.NET){Colors.RESET}")
    print()
    print(f"  [3] Minimal Installation")
    print(f"{Colors.DIM}      Just Binary MCP + Claude Config (bring your own tools){Colors.RESET}")
    print()
    print(f"  [4] Custom Installation")
    print(f"{Colors.DIM}      Choose individual components to install{Colors.RESET}")
    print()
    print(f"  [5] Repair/Update Existing")
    print(f"{Colors.DIM}      Reinstall or update specific components{Colors.RESET}")
    print()
    print(f"{Colors.DIM}  [Q] Quit{Colors.RESET}")
    print()


def show_custom_menu(status: SystemStatus) -> None:
    """Display custom component selection menu."""
    print(f"  {Colors.YELLOW}CUSTOM INSTALLATION{Colors.RESET}")
    print(f"  {Colors.YELLOW}-------------------{Colors.RESET}")
    print()
    print(f"  Select components (enter numbers separated by commas, e.g., 1,2,4):")
    print()

    ghidra_status = "[Installed]" if status.ghidra.installed else ""
    java_note = f"{Colors.YELLOW}(requires Java 21+){Colors.RESET}" if not status.java.installed else ""
    print(f"  [1] Ghidra - Native binary analysis {ghidra_status}")
    if java_note:
        print(f"      {java_note}")

    dotnet_status = "[Installed]" if status.ilspycmd.installed else ""
    dotnet_note = f"{Colors.YELLOW}(requires .NET SDK){Colors.RESET}" if not status.dotnet.installed else ""
    print(f"  [2] .NET Tools (ILSpyCmd) - C#/VB.NET decompilation {dotnet_status}")
    if dotnet_note:
        print(f"      {dotnet_note}")

    print(f"  [3] Configure Claude Desktop")
    print(f"  [4] Configure Claude Code")
    print()
    print(f"  [{Colors.CYAN}A{Colors.RESET}] All components")
    print(f"{Colors.DIM}  [B] Back to main menu{Colors.RESET}")
    print()


def get_user_input(prompt: str) -> str:
    """Get user input with colored prompt."""
    print(f"  {Colors.CYAN}{prompt}{Colors.RESET}: ", end='')
    return input().strip()


# ============================================================
# Package Manager Installation Functions
# ============================================================

def get_install_command(pkg_manager: str, package: str) -> list[str]:
    """Get the install command for a package manager."""
    commands = {
        "brew": ["brew", "install", package],
        "apt": ["sudo", "apt", "install", "-y", package],
        "dnf": ["sudo", "dnf", "install", "-y", package],
        "pacman": ["sudo", "pacman", "-S", "--noconfirm", package],
        "zypper": ["sudo", "zypper", "install", "-y", package],
        "apk": ["sudo", "apk", "add", package],
    }
    return commands.get(pkg_manager, [])


def install_with_package_manager(pkg_manager: str, package: str, name: str) -> bool:
    """Install a package using the system package manager."""
    if not pkg_manager:
        print_error(f"No package manager available to install {name}")
        return False

    cmd = get_install_command(pkg_manager, package)
    if not cmd:
        print_error(f"Unknown package manager: {pkg_manager}")
        return False

    print_info(f"Installing {name} via {pkg_manager}...")
    try:
        subprocess.run(cmd, check=True)
        print_success(f"{name} installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install {name}: {e}")
        return False


def install_java(pkg_manager: str) -> bool:
    """Install Java/OpenJDK."""
    packages = {
        "brew": "openjdk@21",
        "apt": "openjdk-21-jdk",
        "dnf": "java-21-openjdk-devel",
        "pacman": "jdk21-openjdk",
        "zypper": "java-21-openjdk-devel",
        "apk": "openjdk21",
    }

    package = packages.get(pkg_manager)
    if not package:
        print_error(f"Don't know how to install Java on {pkg_manager}")
        print_info("Install Java 21+ manually from: https://adoptium.net/")
        return False

    return install_with_package_manager(pkg_manager, package, "Java 21")


def install_dotnet_sdk(pkg_manager: str) -> bool:
    """Install .NET SDK."""
    system = platform.system()

    if pkg_manager == "brew":
        return install_with_package_manager(pkg_manager, "dotnet-sdk", ".NET SDK")

    # For Linux, use Microsoft's packages
    if system == "Linux":
        print_info("Installing .NET SDK...")
        try:
            # Try using the Microsoft install script
            script_url = "https://dot.net/v1/dotnet-install.sh"

            with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
                req = Request(script_url, headers={"User-Agent": "binary-mcp-installer"})
                with urlopen(req, timeout=30) as response:
                    f.write(response.read().decode())
                script_path = f.name

            os.chmod(script_path, 0o755)
            subprocess.run(["bash", script_path, "--channel", "8.0"], check=True)

            # Add to PATH
            dotnet_dir = Path.home() / ".dotnet"
            if str(dotnet_dir) not in os.environ.get("PATH", ""):
                os.environ["PATH"] = f"{dotnet_dir}:{os.environ.get('PATH', '')}"

            os.unlink(script_path)
            print_success(".NET SDK installed successfully")
            return True
        except Exception as e:
            print_error(f"Failed to install .NET SDK: {e}")
            print_info("Install manually from: https://dotnet.microsoft.com/download")
            return False

    return False


def install_git(pkg_manager: str) -> bool:
    """Install Git."""
    packages = {
        "brew": "git",
        "apt": "git",
        "dnf": "git",
        "pacman": "git",
        "zypper": "git",
        "apk": "git",
    }

    package = packages.get(pkg_manager)
    if package:
        return install_with_package_manager(pkg_manager, package, "Git")
    return False


# ============================================================
# Component Installation Functions
# ============================================================

def install_uv() -> bool:
    """Install uv package manager."""
    print_info("Installing uv package manager...")

    try:
        script_url = "https://astral.sh/uv/install.sh"

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.sh', delete=False) as f:
            req = Request(script_url, headers={"User-Agent": "binary-mcp-installer"})
            with urlopen(req, timeout=30) as response:
                f.write(response.read())
            script_path = f.name

        os.chmod(script_path, 0o755)
        subprocess.run(["sh", script_path], check=True)

        # Update PATH
        uv_bin = Path.home() / ".local" / "bin"
        if str(uv_bin) not in os.environ.get("PATH", ""):
            os.environ["PATH"] = f"{uv_bin}:{os.environ.get('PATH', '')}"

        os.unlink(script_path)
        print_success("uv installed successfully")
        return True
    except Exception as e:
        print_error(f"Failed to install uv: {e}")
        return False


def install_ghidra(ghidra_dir: Path, unattended: bool = False) -> bool:
    """Install Ghidra from GitHub releases."""
    print_info("Installing Ghidra...")

    if ghidra_dir.exists():
        print_warning(f"Ghidra directory already exists: {ghidra_dir}")
        if unattended:
            print_info("Skipping Ghidra (already installed, unattended mode)")
            return True
        response = get_user_input("Reinstall? (y/n)")
        if response.lower() != 'y':
            print_info("Skipping Ghidra installation")
            return True
        shutil.rmtree(ghidra_dir)

    try:
        release = fetch_github_release("NationalSecurityAgency/ghidra")

        # Find ZIP asset
        asset = None
        for a in release.get("assets", []):
            if a["name"].endswith(".zip") and "DEV" not in a["name"]:
                asset = a
                break

        if not asset:
            print_error("Could not find Ghidra release asset")
            return False

        version = release.get("tag_name", "unknown")

        # Download
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as f:
            temp_zip = Path(f.name)

        if not download_file(asset["browser_download_url"], temp_zip, f"Ghidra {version}"):
            return False

        # Extract
        print_info("Extracting Ghidra...")
        with zipfile.ZipFile(temp_zip, 'r') as zf:
            zf.extractall(Path.home())

        temp_zip.unlink()

        # Find and rename extracted directory
        extracted = list(Path.home().glob("ghidra_*_PUBLIC_*"))
        if not extracted:
            print_error("Could not find extracted Ghidra directory")
            return False

        extracted[0].rename(ghidra_dir)
        os.environ["GHIDRA_HOME"] = str(ghidra_dir)

        print_success(f"Ghidra installed to: {ghidra_dir}")
        return True
    except Exception as e:
        print_error(f"Failed to install Ghidra: {e}")
        return False


def install_ilspycmd(status: SystemStatus, pkg_manager: str) -> bool:
    """Install ILSpyCmd .NET tool."""
    print_info("Installing .NET analysis tools...")

    # Check .NET SDK
    if not command_exists("dotnet"):
        print_error(".NET SDK is required for ILSpyCmd")
        if pkg_manager:
            print_info("Attempting to install .NET SDK...")
            if not install_dotnet_sdk(pkg_manager):
                return False
        else:
            print_info("Install from: https://dotnet.microsoft.com/download")
            return False

    # Check .NET 8 runtime
    try:
        result = subprocess.run(
            ["dotnet", "--list-runtimes"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if "Microsoft.NETCore.App 8." not in result.stdout:
            print_warning(".NET 8 Runtime is required for ILSpyCmd")
            print_info("ILSpyCmd may fail without .NET 8 Runtime")
            print_info("Install with: dotnet-install.sh --runtime dotnet --channel 8.0")
    except Exception:
        pass

    # Install ILSpyCmd
    try:
        print_info("Installing ILSpyCmd...")
        result = subprocess.run(
            ["dotnet", "tool", "install", "-g", "ilspycmd"],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print_success("ILSpyCmd installed successfully")
        elif "already installed" in result.stderr.lower():
            print_info("ILSpyCmd already installed, updating...")
            subprocess.run(["dotnet", "tool", "update", "-g", "ilspycmd"], check=True)
            print_success("ILSpyCmd updated")
        else:
            print_warning(f"ILSpyCmd installation: {result.stderr}")

        # Add to PATH
        tools_path = Path.home() / ".dotnet" / "tools"
        if str(tools_path) not in os.environ.get("PATH", ""):
            os.environ["PATH"] = f"{tools_path}:{os.environ.get('PATH', '')}"

        return True
    except Exception as e:
        print_error(f"Failed to install ILSpyCmd: {e}")
        return False


def setup_binary_mcp(install_dir: Path, unattended: bool = False) -> bool:
    """Setup Binary MCP Server."""
    print_info("Setting up Binary MCP Server...")

    # Check if running from repo
    current_dir = Path.cwd()
    if (current_dir / "pyproject.toml").exists() and (current_dir / "src" / "server.py").exists():
        print_info("Running from repository directory")
        install_dir = current_dir
    elif install_dir.exists():
        print_warning(f"Installation directory exists: {install_dir}")
        if not unattended:
            response = get_user_input("Update existing installation? (y/n)")
            if response.lower() != 'y':
                return True
        else:
            print_info("Updating existing installation (unattended mode)")
    else:
        install_dir.mkdir(parents=True, exist_ok=True)

    os.chdir(install_dir)

    # Clone or update
    if (install_dir / ".git").exists():
        print_info("Updating repository...")
        try:
            subprocess.run(["git", "pull"], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            print_warning("Git pull failed, continuing...")
    elif command_exists("git"):
        print_info("Cloning repository...")
        try:
            subprocess.run([
                "git", "clone",
                "https://github.com/Sarks0/binary-mcp.git",
                "."
            ], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            print_warning("Git clone failed, downloading as ZIP...")
            download_repo_zip(install_dir)
    else:
        print_warning("Git not found, downloading as ZIP...")
        download_repo_zip(install_dir)

    print_success("Repository ready")

    # Install dependencies
    print_info("Installing Python dependencies...")
    try:
        subprocess.run(["uv", "sync", "--extra", "dev"], check=True)
        print_success("Dependencies installed")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install dependencies: {e}")
        return False


def download_repo_zip(install_dir: Path) -> None:
    """Download repository as ZIP."""
    url = "https://github.com/Sarks0/binary-mcp/archive/refs/heads/main.zip"

    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as f:
        temp_zip = Path(f.name)

    with tempfile.TemporaryDirectory() as temp_dir:
        if download_file(url, temp_zip, "project source"):
            print_info("Extracting...")
            with zipfile.ZipFile(temp_zip, 'r') as zf:
                zf.extractall(temp_dir)

            extracted = Path(temp_dir) / "binary-mcp-main"
            for item in extracted.iterdir():
                shutil.move(str(item), str(install_dir / item.name))

    temp_zip.unlink(missing_ok=True)


def configure_claude_desktop(install_dir: Path) -> bool:
    """Configure Claude Desktop."""
    print_info("Configuring Claude Desktop...")

    system = platform.system()
    if system == "Darwin":
        config_dir = Path.home() / "Library" / "Application Support" / "Claude"
    else:
        config_dir = Path.home() / ".config" / "Claude"

    config_file = config_dir / "claude_desktop_config.json"

    config_dir.mkdir(parents=True, exist_ok=True)

    try:
        if config_file.exists():
            with open(config_file) as f:
                config = json.load(f)
            # Backup
            shutil.copy(config_file, config_file.with_suffix(".json.backup"))
            print_info(f"Backup saved to: {config_file.with_suffix('.json.backup')}")
        else:
            config = {"mcpServers": {}}

        if "mcpServers" not in config:
            config["mcpServers"] = {}

        config["mcpServers"]["binary-mcp"] = {
            "command": "uv",
            "args": ["--directory", str(install_dir), "run", "python", "-m", "src.server"]
        }

        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)

        print_success("Claude Desktop configured")
        return True
    except Exception as e:
        print_error(f"Failed to configure Claude Desktop: {e}")
        return False


def configure_claude_code(install_dir: Path) -> bool:
    """Configure Claude Code."""
    print_info("Configuring Claude Code...")

    config_dir = Path.home() / ".config" / "claude-code"
    config_file = config_dir / "mcp_settings.json"

    config_dir.mkdir(parents=True, exist_ok=True)

    try:
        if config_file.exists():
            with open(config_file) as f:
                config = json.load(f)
            shutil.copy(config_file, config_file.with_suffix(".json.backup"))
        else:
            config = {"mcpServers": {}}

        if "mcpServers" not in config:
            config["mcpServers"] = {}

        config["mcpServers"]["binary-mcp"] = {
            "command": "uv",
            "args": ["--directory", str(install_dir), "run", "python", "-m", "src.server"]
        }

        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)

        print_success("Claude Code configured")
        return True
    except Exception as e:
        print_error(f"Failed to configure Claude Code: {e}")
        return False


# ============================================================
# Summary
# ============================================================

def show_summary(installed: dict, install_dir: Path, ghidra_dir: Path) -> None:
    """Show installation summary."""
    print()
    print(f"  {Colors.GREEN}================================================{Colors.RESET}")
    print(f"  {Colors.GREEN}         INSTALLATION COMPLETE!{Colors.RESET}")
    print(f"  {Colors.GREEN}================================================{Colors.RESET}")
    print()

    if installed.get("binary_mcp"):
        print_success(f"Binary MCP Server: {install_dir}")
    if installed.get("ghidra"):
        print_success(f"Ghidra: {ghidra_dir}")
    if installed.get("ilspycmd"):
        print_success("ILSpyCmd: .NET decompilation ready")
    if installed.get("claude_desktop"):
        print_success("Claude Desktop: Configured")
    if installed.get("claude_code"):
        print_success("Claude Code: Configured")

    print()
    print_info("Next steps:")
    print("  1. Restart Claude Desktop/Code to load the MCP server")

    if installed.get("ghidra") or installed.get("ilspycmd"):
        print("  2. Test static analysis:")
        if installed.get("ghidra"):
            print(f"{Colors.DIM}     - Native binaries: 'Analyze /path/to/binary'{Colors.RESET}")
        if installed.get("ilspycmd"):
            print(f"{Colors.DIM}     - .NET assemblies: 'Analyze the .NET binary at /path/to/app.exe'{Colors.RESET}")

    print()
    print(f"  Test the server: {Colors.YELLOW}cd {install_dir} && uv run python -m src.server{Colors.RESET}")
    print()


# ============================================================
# Main
# ============================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Binary MCP Server - Cross-Platform Installer"
    )
    parser.add_argument(
        "--install-dir",
        type=Path,
        default=Path.home() / "binary-mcp",
        help="Installation directory"
    )
    parser.add_argument(
        "--ghidra-dir",
        type=Path,
        default=Path.home() / "ghidra",
        help="Ghidra installation directory"
    )
    parser.add_argument(
        "--profile",
        choices=["full", "static", "minimal", "custom", "repair"],
        default="",
        help="Installation profile"
    )
    parser.add_argument(
        "--unattended",
        action="store_true",
        help="Run in unattended mode (no prompts)"
    )

    args = parser.parse_args()

    # Check if running from repo
    current_dir = Path.cwd()
    if (current_dir / "pyproject.toml").exists() and (current_dir / "src" / "server.py").exists():
        args.install_dir = current_dir

    print_banner()

    # Get system status
    status = get_system_status(args.install_dir, args.ghidra_dir)
    show_system_status(status)

    # Install uv if needed
    if not status.uv.installed:
        if args.unattended:
            print_info("Installing uv (unattended mode)...")
            if not install_uv():
                return 1
        else:
            response = get_user_input("uv package manager is required. Install now? (y/n)")
            if response.lower() == 'y':
                if not install_uv():
                    return 1
            else:
                print_error("uv is required for Binary MCP")
                return 1
        status = get_system_status(args.install_dir, args.ghidra_dir)

    # Offer to install missing prerequisites
    if status.package_manager:
        missing = []
        if not status.java.installed:
            missing.append(("Java 21", "java", lambda: install_java(status.package_manager)))
        if not status.dotnet.installed:
            missing.append((".NET SDK", "dotnet", lambda: install_dotnet_sdk(status.package_manager)))
        if not status.git.installed:
            missing.append(("Git", "git", lambda: install_git(status.package_manager)))

        if missing and not args.unattended:
            print()
            print(f"  {Colors.YELLOW}MISSING PREREQUISITES{Colors.RESET}")
            print(f"  {Colors.YELLOW}---------------------{Colors.RESET}")
            print()
            print(f"  The following can be installed via {status.package_manager}:")
            for name, _, _ in missing:
                print(f"{Colors.DIM}    - {name}{Colors.RESET}")
            print()

            response = get_user_input("Install missing prerequisites? (y/n/select)")
            if response.lower() == 'y':
                for name, _, installer in missing:
                    installer()
                status = get_system_status(args.install_dir, args.ghidra_dir)
                print()
                show_system_status(status)
            elif response.lower() == 'select':
                for name, _, installer in missing:
                    resp = get_user_input(f"  Install {name}? (y/n)")
                    if resp.lower() == 'y':
                        installer()
                status = get_system_status(args.install_dir, args.ghidra_dir)

    # Track what gets installed
    installed = {
        "binary_mcp": False,
        "ghidra": False,
        "ilspycmd": False,
        "claude_desktop": False,
        "claude_code": False,
    }

    # Profile selection
    if args.profile:
        selection = args.profile
    else:
        show_install_menu()
        selection = get_user_input("Enter choice (1-5, Q to quit)")

    # Map menu numbers to profile names
    profile_map = {"1": "full", "2": "static", "3": "minimal", "4": "custom", "5": "repair"}
    selection = profile_map.get(selection, selection.lower())

    if selection in ('q', 'quit', 'exit'):
        print_info("Installation cancelled")
        return 0

    # Execute selected profile
    if selection == "full":
        print()
        print_info("Starting Full Installation...")
        print()

        installed["binary_mcp"] = setup_binary_mcp(args.install_dir, args.unattended)

        if status.java.installed or install_java(status.package_manager):
            installed["ghidra"] = install_ghidra(args.ghidra_dir, args.unattended)
        else:
            print_warning("Skipping Ghidra - Java not available")

        if status.dotnet.installed or install_dotnet_sdk(status.package_manager):
            installed["ilspycmd"] = install_ilspycmd(status, status.package_manager)
        else:
            print_warning("Skipping ILSpyCmd - .NET SDK not available")

        installed["claude_desktop"] = configure_claude_desktop(args.install_dir)
        installed["claude_code"] = configure_claude_code(args.install_dir)

    elif selection == "static":
        print()
        print_info("Starting Static Analysis Installation...")
        print()

        installed["binary_mcp"] = setup_binary_mcp(args.install_dir, args.unattended)

        if status.java.installed or install_java(status.package_manager):
            installed["ghidra"] = install_ghidra(args.ghidra_dir, args.unattended)

        if status.dotnet.installed or install_dotnet_sdk(status.package_manager):
            installed["ilspycmd"] = install_ilspycmd(status, status.package_manager)

        installed["claude_desktop"] = configure_claude_desktop(args.install_dir)

    elif selection == "minimal":
        print()
        print_info("Starting Minimal Installation...")
        print()

        installed["binary_mcp"] = setup_binary_mcp(args.install_dir, args.unattended)
        installed["claude_desktop"] = configure_claude_desktop(args.install_dir)

    elif selection == "custom":
        show_custom_menu(status)
        custom_sel = get_user_input("Enter components")

        if custom_sel.lower() == 'b':
            return main()  # Restart

        components = ['1', '2', '3', '4'] if custom_sel.lower() == 'a' else [c.strip() for c in custom_sel.split(',')]

        print()
        print_info("Starting Custom Installation...")
        print()

        installed["binary_mcp"] = setup_binary_mcp(args.install_dir, args.unattended)

        for comp in components:
            if comp == '1':
                if status.java.installed or install_java(status.package_manager):
                    installed["ghidra"] = install_ghidra(args.ghidra_dir, args.unattended)
            elif comp == '2':
                if status.dotnet.installed or install_dotnet_sdk(status.package_manager):
                    installed["ilspycmd"] = install_ilspycmd(status, status.package_manager)
            elif comp == '3':
                installed["claude_desktop"] = configure_claude_desktop(args.install_dir)
            elif comp == '4':
                installed["claude_code"] = configure_claude_code(args.install_dir)

    elif selection == "repair":
        print()
        print_info("Repair/Update Mode")
        print()
        show_custom_menu(status)
        repair_sel = get_user_input("Enter components to reinstall/update")

        if repair_sel.lower() == 'b':
            return main()

        components = [c.strip() for c in repair_sel.split(',')]

        for comp in components:
            if comp == '1':
                installed["ghidra"] = install_ghidra(args.ghidra_dir, unattended=False)
            elif comp == '2':
                installed["ilspycmd"] = install_ilspycmd(status, status.package_manager)
            elif comp == '3':
                installed["claude_desktop"] = configure_claude_desktop(args.install_dir)
            elif comp == '4':
                installed["claude_code"] = configure_claude_code(args.install_dir)

    else:
        print_error(f"Invalid selection: {selection}")
        return 1

    show_summary(installed, args.install_dir, args.ghidra_dir)

    print()
    print_success("Installation finished!")
    print()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        print_warning("Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print()
        print_error(f"Installation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
