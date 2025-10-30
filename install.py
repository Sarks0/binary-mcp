#!/usr/bin/env python3
"""
Binary MCP Server - Cross-Platform Installer
Automated installation script for Linux and macOS with Ghidra support
"""

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_success(msg: str) -> None:
    print(f"{Colors.GREEN}[OK]{Colors.RESET} {msg}")

def print_info(msg: str) -> None:
    print(f"{Colors.BLUE}[i]{Colors.RESET} {msg}")

def print_warning(msg: str) -> None:
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")

def print_error(msg: str) -> None:
    print(f"{Colors.RED}[X]{Colors.RESET} {msg}")

def print_banner() -> None:
    print()
    print(f"{Colors.BLUE}╔════════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.BLUE}║      Binary MCP Server - Automated Installer              ║{Colors.RESET}")
    print(f"{Colors.BLUE}║      Static (Ghidra) Analysis + Dynamic Debugging         ║{Colors.RESET}")
    print(f"{Colors.BLUE}╚════════════════════════════════════════════════════════════╝{Colors.RESET}")
    print()

def command_exists(cmd: str) -> bool:
    """Check if a command exists in PATH."""
    return shutil.which(cmd) is not None

def get_python_version() -> tuple[int, int]:
    """Get Python version as (major, minor) tuple."""
    return (sys.version_info.major, sys.version_info.minor)

def fetch_latest_github_release(repo: str) -> dict:
    """Fetch latest GitHub release information."""
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = Request(url)
    req.add_header("User-Agent", "binary-mcp-installer")

    try:
        with urlopen(req, timeout=10) as response:
            return json.loads(response.read())
    except Exception as e:
        print_error(f"Failed to fetch latest release for {repo}: {e}")
        raise

def download_file(url: str, dest: Path, description: str = "file") -> None:
    """Download a file with progress indication."""
    print_info(f"Downloading {description}...")

    try:
        req = Request(url)
        req.add_header("User-Agent", "binary-mcp-installer")

        with urlopen(req, timeout=30) as response:
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            chunk_size = 8192

            with open(dest, 'wb') as f:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)

                    if total_size > 0:
                        progress = (downloaded / total_size) * 100
                        print(f"\r  Progress: {progress:.1f}%", end='', flush=True)

        print()  # New line after progress
        print_success(f"Downloaded {description}")
    except Exception as e:
        print_error(f"Failed to download {description}: {e}")
        raise

def install_uv() -> bool:
    """Install uv package manager."""
    print_info("Installing uv package manager...")

    try:
        # Use the official installer
        cmd = "curl -LsSf https://astral.sh/uv/install.sh | sh"
        subprocess.run(cmd, shell=True, check=True)

        # Update PATH for current session
        uv_bin = Path.home() / ".local" / "bin"
        if str(uv_bin) not in os.environ["PATH"]:
            os.environ["PATH"] = f"{uv_bin}:{os.environ['PATH']}"

        print_success("uv installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install uv: {e}")
        return False

def install_ghidra(install_dir: Path, skip_if_exists: bool = True) -> Optional[Path]:
    """Install latest Ghidra version."""
    print_info("Installing Ghidra...")

    ghidra_dir = Path.home() / "ghidra"

    if ghidra_dir.exists() and skip_if_exists:
        print_warning(f"Ghidra directory already exists: {ghidra_dir}")
        response = input("Reinstall Ghidra? (y/n): ").strip().lower()
        if response != 'y':
            print_info("Skipping Ghidra installation")
            return ghidra_dir

        shutil.rmtree(ghidra_dir)

    try:
        print_info("Fetching latest Ghidra release...")
        release = fetch_latest_github_release("NationalSecurityAgency/ghidra")

        # Find the appropriate asset (ZIP file, not DEV)
        asset = None
        for a in release.get("assets", []):
            if a["name"].endswith(".zip") and "DEV" not in a["name"]:
                asset = a
                break

        if not asset:
            print_error("Could not find Ghidra release asset")
            return None

        version = release.get("tag_name", "unknown")
        print_info(f"Found Ghidra {version}")

        # Download
        temp_zip = Path("/tmp") / "ghidra.zip"
        download_file(asset["browser_download_url"], temp_zip, f"Ghidra {version}")

        # Extract
        print_info("Extracting Ghidra...")
        with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
            zip_ref.extractall(Path.home())

        # Find extracted directory (format: ghidra_x.x.x_PUBLIC_YYYYMMDD)
        extracted_dirs = list(Path.home().glob("ghidra_*_PUBLIC_*"))
        if not extracted_dirs:
            print_error("Could not find extracted Ghidra directory")
            return None

        extracted_dir = extracted_dirs[0]
        extracted_dir.rename(ghidra_dir)

        print_success(f"Ghidra installed to: {ghidra_dir}")

        # Set environment variable
        os.environ["GHIDRA_HOME"] = str(ghidra_dir)

        # Clean up
        temp_zip.unlink(missing_ok=True)

        return ghidra_dir

    except Exception as e:
        print_error(f"Failed to install Ghidra: {e}")
        return None

def setup_project(install_dir: Path) -> bool:
    """Clone/setup the binary-mcp project."""

    # Check if we're already running from within the repo
    current_dir = Path.cwd()
    if (current_dir / ".git").exists() and (current_dir / "install.py").exists():
        print_info("Already running from repository directory")
        print_success("Using current directory for installation")
        # Update install_dir to current directory
        install_dir = current_dir
        os.chdir(install_dir)
        return True

    print_info("Setting up Binary MCP Server...")

    if install_dir.exists():
        print_warning(f"Installation directory already exists: {install_dir}")
        response = input("Continue and update? (y/n): ").strip().lower()
        if response != 'y':
            print_info("Installation cancelled")
            return False
    else:
        print_info("Creating installation directory...")
        install_dir.mkdir(parents=True, exist_ok=True)

    os.chdir(install_dir)

    # Check if git repo exists
    if (install_dir / ".git").exists():
        print_info("Updating existing repository...")
        try:
            subprocess.run(["git", "pull"], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            print_warning("Git pull failed, continuing...")
    else:
        print_info("Cloning repository...")
        if command_exists("git"):
            try:
                subprocess.run([
                    "git", "clone",
                    "https://github.com/Sarks0/binary-mcp.git",
                    str(install_dir)
                ], check=True, capture_output=True)
            except subprocess.CalledProcessError:
                print_warning("Git clone failed, downloading as ZIP...")
                download_as_zip(install_dir)
        else:
            print_warning("Git not found, downloading as ZIP...")
            download_as_zip(install_dir)

    print_success("Repository ready")
    return True

def download_as_zip(install_dir: Path) -> None:
    """Download project as ZIP file."""
    zip_url = "https://github.com/Sarks0/binary-mcp/archive/refs/heads/main.zip"
    temp_zip = Path("/tmp") / "binary-mcp.zip"

    download_file(zip_url, temp_zip, "project source")

    print_info("Extracting...")
    with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
        zip_ref.extractall("/tmp")

    # Move contents
    extracted = Path("/tmp/binary-mcp-main")
    for item in extracted.iterdir():
        shutil.move(str(item), str(install_dir / item.name))

    shutil.rmtree(extracted, ignore_errors=True)
    temp_zip.unlink(missing_ok=True)

def install_dependencies(install_dir: Path) -> bool:
    """Install Python dependencies using uv."""
    print_info("Installing Python dependencies...")

    os.chdir(install_dir)

    try:
        subprocess.run(["uv", "sync", "--extra", "dev"], check=True)
        print_success("Dependencies installed")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install dependencies: {e}")
        return False

def configure_claude_desktop(install_dir: Path) -> bool:
    """Configure Claude Desktop MCP settings."""
    print_info("Configuring Claude Desktop...")

    system = platform.system()

    if system == "Darwin":  # macOS
        config_dir = Path.home() / "Library" / "Application Support" / "Claude"
    else:  # Linux
        config_dir = Path.home() / ".config" / "claude"

    config_file = config_dir / "claude_desktop_config.json"

    if not config_file.exists():
        print_warning(f"Claude Desktop config not found: {config_file}")
        print_info("You'll need to manually configure Claude Desktop after installation")
        return False

    try:
        # Read existing config
        with open(config_file, 'r') as f:
            config = json.load(f)

        # Ensure mcpServers exists
        if "mcpServers" not in config:
            config["mcpServers"] = {}

        # Add binary-mcp server
        config["mcpServers"]["binary-mcp"] = {
            "command": "uv",
            "args": [
                "--directory",
                str(install_dir),
                "run",
                "python",
                "-m",
                "src.server"
            ]
        }

        # Backup existing config
        backup_file = config_file.with_suffix(".json.backup")
        shutil.copy(config_file, backup_file)

        # Save new config
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)

        print_success("Claude Desktop configured")
        print_info(f"Backup saved to: {backup_file}")
        return True

    except Exception as e:
        print_warning(f"Failed to configure Claude Desktop: {e}")
        print_info("You can manually configure it later")
        return False

def verify_installation(install_dir: Path, ghidra_dir: Optional[Path]) -> bool:
    """Verify the installation."""
    print_info("Verifying installation...")

    all_good = True

    if not install_dir.exists():
        print_error("Installation directory not found")
        all_good = False
    else:
        print_success("Project files present")

    if ghidra_dir and ghidra_dir.exists():
        print_success("Ghidra installation verified")
    elif ghidra_dir:
        print_warning("Ghidra not installed")

    if command_exists("uv"):
        print_success("uv package manager available")
    else:
        print_error("uv not found in PATH")
        all_good = False

    return all_good

def main() -> int:
    """Main installer function."""
    print_banner()

    # Parse arguments
    import argparse
    parser = argparse.ArgumentParser(description="Binary MCP Server Installer")
    parser.add_argument("--install-dir", type=Path, default=Path.home() / "binary-mcp",
                        help="Installation directory")
    parser.add_argument("--skip-ghidra", action="store_true",
                        help="Skip Ghidra installation")
    parser.add_argument("--no-claude-config", action="store_true",
                        help="Don't configure Claude Desktop")
    args = parser.parse_args()

    # Check if we're already running from within the repo
    current_dir = Path.cwd()
    if (current_dir / ".git").exists() and (current_dir / "install.py").exists():
        print_info("Detected running from repository directory")
        install_dir = current_dir
        print_success(f"Using current directory: {install_dir}")
    else:
        install_dir = args.install_dir

    # Check prerequisites
    print_info("Checking prerequisites...")

    # Check Python version
    py_major, py_minor = get_python_version()
    if py_major >= 3 and py_minor >= 12:
        print_success(f"Python {py_major}.{py_minor} found")
    else:
        print_warning(f"Python {py_major}.{py_minor} found, but 3.12+ recommended")
        response = input("Continue anyway? (y/n): ").strip().lower()
        if response != 'y':
            return 1

    # Check/Install uv
    print_info("Checking uv package manager...")
    if command_exists("uv"):
        print_success("uv already installed")
    else:
        if not install_uv():
            print_error("Failed to install uv")
            return 1

    # Check Java (for Ghidra)
    if not args.skip_ghidra:
        print_info("Checking Java...")
        if command_exists("java"):
            try:
                result = subprocess.run(["java", "-version"], capture_output=True, text=True)
                version_output = result.stderr.split('\n')[0]
                print_success(f"Java found: {version_output}")
            except Exception:
                print_warning("Could not determine Java version")
        else:
            print_warning("Java not found - required for Ghidra")
            print_info("Install Java 17+ from: https://adoptium.net/")
            response = input("Skip Ghidra installation? (y/n): ").strip().lower()
            if response == 'y':
                args.skip_ghidra = True
            else:
                print_error("Please install Java and run this script again")
                return 1

    # Install Ghidra
    ghidra_dir = None
    if not args.skip_ghidra:
        ghidra_dir = install_ghidra(install_dir)

    # Setup project
    if not setup_project(install_dir):
        return 1

    # Install dependencies
    if not install_dependencies(install_dir):
        return 1

    # Configure Claude Desktop
    if not args.no_claude_config:
        configure_claude_desktop(install_dir)

    # Verify installation
    verify_installation(install_dir, ghidra_dir)

    # Summary
    print()
    print(f"{Colors.GREEN}╔════════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.GREEN}║              Installation Complete!                       ║{Colors.RESET}")
    print(f"{Colors.GREEN}╚════════════════════════════════════════════════════════════╝{Colors.RESET}")
    print()

    print_success(f"Binary MCP Server installed to: {install_dir}")

    if ghidra_dir:
        print_success(f"Ghidra installed to: {ghidra_dir}")

    print()
    print_info("Next steps:")
    print(f"  1. Restart Claude Desktop to load the MCP server")
    print(f"  2. Test the server: {Colors.YELLOW}cd {install_dir} && uv run python -m src.server{Colors.RESET}")
    print(f"  3. Use binary analysis tools in Claude conversations!")
    print()

    if not args.no_claude_config:
        print_info("Configuration added to Claude Desktop")
        print_info("Restart Claude Desktop to activate the MCP server")

    print()
    print_success("Installation finished successfully!")
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
        sys.exit(1)
