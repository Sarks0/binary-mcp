"""
Ghidra headless runner with cross-platform support.
Handles Ghidra installation detection, project management, and script execution.
"""

import logging
import os
import platform
import re
import subprocess  # nosec B404 - Required for Ghidra headless execution
import time
from pathlib import Path

from src.utils.security import validate_parameter_pattern

logger = logging.getLogger(__name__)


class GhidraRunner:
    """Manages Ghidra headless analysis execution."""

    def __init__(self, ghidra_path: str | None = None):
        """
        Initialize Ghidra runner.

        Args:
            ghidra_path: Path to Ghidra installation. If None, checks GHIDRA_HOME
                         environment variable, then auto-detects.
        """
        if ghidra_path:
            self.ghidra_path = Path(ghidra_path)
        else:
            # Check GHIDRA_HOME environment variable first (fast path)
            ghidra_home = os.environ.get("GHIDRA_HOME")
            if ghidra_home:
                ghidra_home_path = Path(ghidra_home)
                if self._is_valid_ghidra_installation(ghidra_home_path):
                    logger.info(f"Using GHIDRA_HOME: {ghidra_home}")
                    self.ghidra_path = ghidra_home_path
                else:
                    logger.warning(
                        f"GHIDRA_HOME set but not a valid Ghidra installation: {ghidra_home}"
                    )
                    self.ghidra_path = self._detect_ghidra()
            else:
                # Fall back to auto-detection (slow path)
                self.ghidra_path = self._detect_ghidra()

        self.system = platform.system()
        logger.info(f"Initialized Ghidra runner: {self.ghidra_path} on {self.system}")

    def _detect_ghidra(self) -> Path:
        """
        Auto-detect Ghidra installation across platforms.

        Returns:
            Path to Ghidra installation directory

        Raises:
            FileNotFoundError: If Ghidra cannot be found
        """
        system = platform.system()
        search_paths = []

        if system == "Darwin":  # macOS
            search_paths = [
                Path.home() / "Downloads" / "ghidra_*",
                Path.home() / "ghidra",
                Path("/Applications/ghidra_*"),
                Path("/opt/ghidra"),
            ]
        elif system == "Linux":
            search_paths = [
                Path("/opt/ghidra"),
                Path.home() / "ghidra",
                Path.home() / "Downloads" / "ghidra_*",
                Path("/usr/local/ghidra"),
            ]
        elif system == "Windows":
            search_paths = [
                Path(os.environ.get("USERPROFILE", "C:\\")) / "Downloads" / "ghidra_*",
                Path("C:\\ghidra"),
                Path("C:\\Program Files\\ghidra"),
                Path(os.environ.get("PROGRAMFILES", "C:\\Program Files")) / "ghidra",
            ]

        # Search for Ghidra installation
        for pattern in search_paths:
            if "*" in str(pattern):
                # Glob pattern - find the latest version
                matches = sorted(pattern.parent.glob(pattern.name), reverse=True)
                if matches:
                    ghidra_dir = matches[0]
                    if (ghidra_dir / "support" / "analyzeHeadless").exists() or \
                       (ghidra_dir / "support" / "analyzeHeadless.bat").exists():
                        logger.info(f"Auto-detected Ghidra: {ghidra_dir}")
                        return ghidra_dir
            else:
                if pattern.exists():
                    if (pattern / "support" / "analyzeHeadless").exists() or \
                       (pattern / "support" / "analyzeHeadless.bat").exists():
                        logger.info(f"Auto-detected Ghidra: {pattern}")
                        return pattern

        raise FileNotFoundError(
            "Ghidra installation not found. Please set GHIDRA_HOME environment variable "
            "or pass ghidra_path explicitly."
        )

    def _is_valid_ghidra_installation(self, path: Path) -> bool:
        """
        Validate that path contains a valid Ghidra installation.

        Checks that the directory exists and contains the analyzeHeadless binary.

        Args:
            path: Path to potential Ghidra installation

        Returns:
            True if path is a valid Ghidra installation, False otherwise
        """
        if not path.exists() or not path.is_dir():
            return False
        # Check for analyzeHeadless binary (Unix or Windows)
        analyze_unix = path / "support" / "analyzeHeadless"
        analyze_win = path / "support" / "analyzeHeadless.bat"
        return analyze_unix.exists() or analyze_win.exists()

    def _get_analyze_headless_cmd(self) -> str:
        """Get the analyzeHeadless command for the current platform."""
        if self.system == "Windows":
            return str(self.ghidra_path / "support" / "analyzeHeadless.bat")
        else:
            return str(self.ghidra_path / "support" / "analyzeHeadless")

    def _normalize_binary_path(self, binary_path: str) -> Path:
        """
        Normalize binary path for the current platform.

        On Windows, adds .exe if missing. On Unix, removes .exe if present.
        """
        path = Path(binary_path)

        if self.system == "Windows":
            if not path.suffix:
                # Check if .exe exists
                exe_path = path.with_suffix(".exe")
                if exe_path.exists():
                    return exe_path
        else:
            # On Unix, prefer no extension
            if path.suffix == ".exe":
                no_ext = path.with_suffix("")
                if no_ext.exists():
                    return no_ext

        return path

    def _stage_pdb(self, binary_path: Path | str, pdb_path: str) -> Path:
        """
        Stage a PDB file next to the binary so Ghidra's PdbUniversalAnalyzer
        auto-locates it. Symlinks on Unix, copies on Windows (where symlinks
        need admin privileges).

        Returns the staged path. Callers should pass it to ``_cleanup_pdb``
        once Ghidra has finished reading the binary.
        """
        import shutil

        src = Path(pdb_path)
        if not src.exists():
            raise FileNotFoundError(f"PDB not found: {pdb_path}")

        binary = Path(binary_path)
        # Ghidra looks for <binary-with-suffix>.pdb adjacent to the binary
        # (e.g. foo.exe → foo.pdb). Use stem to normalise.
        dest = binary.parent / f"{binary.stem}.pdb"

        if dest.exists() and dest.resolve() == src.resolve():
            # Already in the right place
            return dest

        # Remove any prior artefact so staging is idempotent
        if dest.exists() or dest.is_symlink():
            dest.unlink()

        if self.system == "Windows":
            shutil.copy2(src, dest)
        else:
            try:
                dest.symlink_to(src.resolve())
            except OSError:
                # Fallback to copy if symlink isn't allowed
                shutil.copy2(src, dest)
        return dest

    def _cleanup_pdb(self, staged_pdb: Path | None) -> None:
        """Best-effort removal of a PDB staged by ``_stage_pdb``."""
        if staged_pdb is None:
            return
        try:
            if staged_pdb.exists() or staged_pdb.is_symlink():
                staged_pdb.unlink()
        except OSError as e:
            logger.warning(f"Failed to remove staged PDB {staged_pdb}: {e}")

    def _cleanup_project(self, project_dir: Path, project_name: str) -> None:
        """
        Clean up a Ghidra project directory and lock files.

        Called when analysis fails or times out to prevent lock issues.
        """
        import shutil

        project_path = project_dir / f"{project_name}.rep"
        lock_file = project_dir / f"{project_name}.lock"
        gpr_file = project_dir / f"{project_name}.gpr"

        try:
            # Remove lock file
            if lock_file.exists():
                lock_file.unlink()
                logger.debug(f"Removed lock file: {lock_file}")

            # Remove project file
            if gpr_file.exists():
                gpr_file.unlink()
                logger.debug(f"Removed project file: {gpr_file}")

            # Remove project directory
            if project_path.exists():
                shutil.rmtree(project_path, ignore_errors=True)
                logger.debug(f"Removed project directory: {project_path}")

        except Exception as e:
            logger.warning(f"Failed to cleanup project {project_name}: {e}")

    def analyze(
        self,
        binary_path: str,
        script_path: str,
        script_name: str,
        output_path: str,
        project_name: str | None = None,
        keep_project: bool = False,
        timeout: int = 600,
        processor: str | None = None,
        loader: str | None = None,
        function_timeout: int | None = None,
        max_functions: int | None = None,
        skip_decompile: bool = False,
        resume_from_cache: str | None = None,
        resume_manifest: str | None = None,
        start_address: str | None = None,
        end_address: str | None = None,
        pdb_path: str | None = None,
        enable_fid: bool = False,
        max_heap_mb: int | None = None,
    ) -> dict:
        """
        Run Ghidra headless analysis on a binary.

        Args:
            binary_path: Path to binary file to analyze
            script_path: Directory containing Ghidra scripts
            script_name: Name of the Jython script to execute
            output_path: Where to save analysis output
            project_name: Ghidra project name (default: binary basename)
            keep_project: Whether to keep the project after analysis
            timeout: Maximum execution time in seconds (default: 600)
            processor: Optional processor specification (e.g., "x86:LE:64:default")
            loader: Optional loader specification (e.g., "Portable Executable (PE)")
            function_timeout: Per-function decompilation timeout (default: 30s)
            max_functions: Maximum functions to analyze (default: unlimited)
            skip_decompile: Skip decompilation for faster analysis (default: False)
            resume_from_cache: Path to a previous cache JSON (plain or .gz) -- functions
                already present are skipped and their results preserved
            start_address: Hex start address (e.g. "0x61abbc") -- skip functions below
            end_address: Hex end address -- skip functions above
            pdb_path: Optional path to a PDB file. Staged next to the binary so
                Ghidra's PdbUniversalAnalyzer picks it up automatically.
            enable_fid: When True, set GHIDRA_ENABLE_FID=1 so the Jython script
                runs Function ID library matching per function.

        Returns:
            dict with analysis results and metadata

        Raises:
            subprocess.TimeoutExpired: If analysis exceeds timeout
            subprocess.CalledProcessError: If Ghidra analysis fails
            FileNotFoundError: If binary or script not found

        Note:
            For binaries with anti-analysis code that causes decompiler hangs,
            you can:
            1. Reduce function_timeout to skip problematic functions faster
            2. Set max_functions to limit analysis scope
            3. Set skip_decompile=True to skip decompilation entirely
        """
        binary_path = self._normalize_binary_path(binary_path)

        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        if project_name is None:
            project_name = binary_path.stem
        # Sanitize project name to prevent parameter injection
        project_name = re.sub(r'[^a-zA-Z0-9_.\-]', '_', project_name)
        if project_name.startswith('-'):
            project_name = f"proj_{project_name}"

        # Create temporary project directory
        project_dir = Path(output_path).parent / "ghidra_projects"
        project_dir.mkdir(parents=True, exist_ok=True)

        # Set environment variables for output path and analysis options
        env = os.environ.copy()
        env["GHIDRA_CONTEXT_JSON"] = str(output_path)

        # Pass function-level timeout settings to the Ghidra script
        if function_timeout is not None:
            env["GHIDRA_FUNCTION_TIMEOUT"] = str(function_timeout)
        if max_functions is not None and max_functions > 0:
            env["GHIDRA_MAX_FUNCTIONS"] = str(max_functions)
        if skip_decompile:
            env["GHIDRA_SKIP_DECOMPILE"] = "1"
        if resume_from_cache:
            env["GHIDRA_RESUME_CACHE"] = str(resume_from_cache)
        if resume_manifest:
            env["GHIDRA_RESUME_MANIFEST"] = str(resume_manifest)
        if start_address:
            env["GHIDRA_START_ADDRESS"] = str(start_address)
        if end_address:
            env["GHIDRA_END_ADDRESS"] = str(end_address)
        if enable_fid:
            env["GHIDRA_ENABLE_FID"] = "1"
        # Give script a wall-clock budget with margin for JSON serialization
        env["GHIDRA_ANALYSIS_BUDGET"] = str(max(timeout - 60, 60))

        # Bump JVM heap. Loading a multi-GB resume cache or decompiling
        # complex functions on large binaries will OOM Ghidra's default heap.
        # _JAVA_OPTIONS is picked up by every JVM the analyzeHeadless script
        # spawns, including the one running our Jython post-script.
        if max_heap_mb is None:
            try:
                max_heap_mb = int(os.environ.get("GHIDRA_MAX_HEAP_MB", "4096"))
            except ValueError:
                max_heap_mb = 4096
        if max_heap_mb > 0:
            existing = env.get("_JAVA_OPTIONS", "")
            if "-Xmx" not in existing:
                env["_JAVA_OPTIONS"] = (
                    f"{existing} -Xmx{max_heap_mb}m".strip()
                )

        # Stage PDB next to the binary so Ghidra's PdbUniversalAnalyzer finds
        # it. Auto-cleanup on success/failure so we don't leave dangling
        # artefacts.
        staged_pdb = None
        if pdb_path:
            staged_pdb = self._stage_pdb(binary_path, pdb_path)
            logger.info(f"Staged PDB at {staged_pdb}")

        logger.debug(
            f"Analysis settings: function_timeout={function_timeout}, "
            f"max_functions={max_functions}, skip_decompile={skip_decompile}, "
            f"resume_from_cache={resume_from_cache}, "
            f"start_address={start_address}, end_address={end_address}"
        )

        # Build command - processor/loader must come immediately after binary path
        cmd = [
            self._get_analyze_headless_cmd(),
            str(project_dir),
            project_name,
            "-import", str(binary_path),
        ]

        # Add processor/loader if specified (must be before other flags)
        if processor:
            try:
                processor = validate_parameter_pattern(
                    processor, "processor",
                    pattern=r'^[a-zA-Z0-9:_.\-]+$',
                    max_length=100
                )
            except ValueError as e:
                raise ValueError(f"Invalid processor specification: {e}")
            cmd.extend(["-processor", processor])
        if loader:
            try:
                loader = validate_parameter_pattern(
                    loader, "loader",
                    pattern=r'^[a-zA-Z0-9 _.\-()]+$',
                    max_length=200
                )
            except ValueError as e:
                raise ValueError(f"Invalid loader specification: {e}")
            cmd.extend(["-loader", loader])

        # Add remaining flags
        cmd.append("-overwrite")
        cmd.extend([
            "-scriptPath", str(script_path),
            "-postScript", script_name,
        ])

        if not keep_project:
            cmd.append("-deleteProject")

        logger.info(f"Running Ghidra analysis: {' '.join(cmd)}")
        logger.debug(f"Environment: GHIDRA_CONTEXT_JSON={output_path}")

        start_time = time.time()

        try:
            # On Windows, don't use shell=True - it causes path handling issues
            # The .bat file can be executed directly without shell
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                shell=False,  # Changed: shell=False to fix Windows path handling
                check=True,
            )

            elapsed_time = time.time() - start_time

            logger.info(f"Analysis completed in {elapsed_time:.2f}s")
            logger.debug(f"stdout: {result.stdout[:500]}")

            return {
                "success": True,
                "binary": str(binary_path),
                "project_name": project_name,
                "output_path": output_path,
                "elapsed_time": elapsed_time,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        except subprocess.TimeoutExpired as e:
            elapsed_time = time.time() - start_time
            logger.error(f"Analysis timeout after {elapsed_time:.2f}s")

            # Clean up locked project to prevent future lock errors
            self._cleanup_project(project_dir, project_name)

            raise RuntimeError(
                f"Ghidra analysis timed out after {timeout}s. "
                f"Binary may be too large or complex."
            ) from e

        except subprocess.CalledProcessError as e:
            elapsed_time = time.time() - start_time
            logger.error(f"Analysis failed after {elapsed_time:.2f}s")
            logger.error(f"stdout: {e.stdout}")
            logger.error(f"stderr: {e.stderr}")

            # Clean up locked project to prevent future lock errors
            self._cleanup_project(project_dir, project_name)

            stdout_tail = (e.stdout or "")[-2000:]
            raise RuntimeError(
                f"Ghidra analysis failed with exit code {e.returncode}. "
                f"stdout (last 2000 chars): {stdout_tail}"
            ) from e

        finally:
            # Always remove the PDB we staged -- Ghidra has either read it by
            # now or failed outright. Leaving it behind would confuse future
            # analyses with a mismatched PDB.
            self._cleanup_pdb(staged_pdb)

    def diagnose(self) -> dict:
        """
        Run diagnostic checks on Ghidra installation.

        Returns:
            dict with diagnostic information
        """
        diag = {
            "platform": self.system,
            "ghidra_path": str(self.ghidra_path),
            "ghidra_exists": self.ghidra_path.exists(),
        }

        # Check analyzeHeadless
        analyze_cmd = self._get_analyze_headless_cmd()
        diag["analyze_headless"] = analyze_cmd
        diag["analyze_headless_exists"] = Path(analyze_cmd).exists()

        # Check Java
        try:
            java_result = subprocess.run(  # nosec B603 B607 - Safe diagnostic check for Java
                ["java", "-version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            diag["java_installed"] = True
            diag["java_version"] = java_result.stderr.split("\n")[0]
        except (subprocess.SubprocessError, FileNotFoundError):
            diag["java_installed"] = False
            diag["java_version"] = None

        # Check Ghidra version
        version_file = self.ghidra_path / "application.properties"
        if version_file.exists():
            try:
                with open(version_file, encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("application.version"):
                            diag["ghidra_version"] = line.split("=")[1].strip()
                            break
            except Exception as e:
                diag["ghidra_version"] = f"Error reading version: {e}"
        else:
            diag["ghidra_version"] = "Unknown"

        return diag
