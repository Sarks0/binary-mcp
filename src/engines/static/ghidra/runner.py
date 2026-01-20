"""
Ghidra headless runner with cross-platform support.
Handles Ghidra installation detection, project management, and script execution.
"""

import asyncio
import logging
import os
import platform
import subprocess  # nosec B404 - Required for Ghidra headless execution
import time
from pathlib import Path

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

    def _cleanup_project(self, project_dir: Path, project_name: str) -> None:
        """
        Clean up a Ghidra project directory and lock files.

        Called when analysis fails or times out to prevent lock issues.
        """
        import shutil

        project_path = project_dir / f"{project_name}.rep"
        lock_file = project_dir / f"{project_name}.lock"

        try:
            # Remove lock file
            if lock_file.exists():
                lock_file.unlink()
                logger.debug(f"Removed lock file: {lock_file}")

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

        logger.debug(f"Analysis settings: function_timeout={function_timeout}, "
                     f"max_functions={max_functions}, skip_decompile={skip_decompile}")

        # Build command - processor/loader must come immediately after binary path
        cmd = [
            self._get_analyze_headless_cmd(),
            str(project_dir),
            project_name,
            "-import", str(binary_path),
        ]

        # Add processor/loader if specified (must be before other flags)
        if processor:
            cmd.extend(["-processor", processor])
        if loader:
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

            raise RuntimeError(
                f"Ghidra analysis failed with exit code {e.returncode}. "
                f"Check logs for details."
            ) from e

    async def analyze_async(
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
    ) -> dict:
        """
        Run Ghidra headless analysis on a binary asynchronously.

        This is the non-blocking version of analyze() that doesn't block the
        async event loop. Use this for MCP server operations to allow other
        requests to be processed while Ghidra runs.

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

        Returns:
            dict with analysis results and metadata

        Raises:
            RuntimeError: If analysis fails or times out
            FileNotFoundError: If binary or script not found
        """
        binary_path = self._normalize_binary_path(binary_path)

        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        if project_name is None:
            project_name = binary_path.stem

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

        logger.debug(f"Analysis settings: function_timeout={function_timeout}, "
                     f"max_functions={max_functions}, skip_decompile={skip_decompile}")

        # Build command - processor/loader must come immediately after binary path
        cmd = [
            self._get_analyze_headless_cmd(),
            str(project_dir),
            project_name,
            "-import", str(binary_path),
        ]

        # Add processor/loader if specified (must be before other flags)
        if processor:
            cmd.extend(["-processor", processor])
        if loader:
            cmd.extend(["-loader", loader])

        # Add remaining flags
        cmd.append("-overwrite")
        cmd.extend([
            "-scriptPath", str(script_path),
            "-postScript", script_name,
        ])

        if not keep_project:
            cmd.append("-deleteProject")

        logger.info(f"Running async Ghidra analysis: {' '.join(cmd)}")
        logger.debug(f"Environment: GHIDRA_CONTEXT_JSON={output_path}")

        start_time = time.time()

        try:
            # Create async subprocess - this doesn't block the event loop
            process = await asyncio.create_subprocess_exec(
                *cmd,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait for completion with timeout - other async tasks can run during this
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")
            except asyncio.TimeoutError:
                # Kill the process on timeout
                logger.warning(f"Ghidra analysis timed out after {timeout}s, killing process")
                process.kill()
                await process.wait()

                elapsed_time = time.time() - start_time
                logger.error(f"Analysis timeout after {elapsed_time:.2f}s")

                # Clean up locked project to prevent future lock errors
                self._cleanup_project(project_dir, project_name)

                raise RuntimeError(
                    f"Ghidra analysis timed out after {timeout}s. "
                    f"Binary may be too large or complex. "
                    f"Consider increasing GHIDRA_TIMEOUT or using skip_decompile=True."
                )

            elapsed_time = time.time() - start_time

            # Check return code
            if process.returncode != 0:
                logger.error(f"Analysis failed after {elapsed_time:.2f}s")
                logger.error(f"stdout: {stdout}")
                logger.error(f"stderr: {stderr}")

                # Clean up locked project to prevent future lock errors
                self._cleanup_project(project_dir, project_name)

                raise RuntimeError(
                    f"Ghidra analysis failed with exit code {process.returncode}. "
                    f"Check logs for details."
                )

            logger.info(f"Async analysis completed in {elapsed_time:.2f}s")
            logger.debug(f"stdout: {stdout[:500]}")

            return {
                "success": True,
                "binary": str(binary_path),
                "project_name": project_name,
                "output_path": output_path,
                "elapsed_time": elapsed_time,
                "stdout": stdout,
                "stderr": stderr,
            }

        except RuntimeError:
            # Re-raise RuntimeError (timeout or failure) as-is
            raise
        except Exception as e:
            elapsed_time = time.time() - start_time
            logger.error(f"Unexpected error during async analysis after {elapsed_time:.2f}s: {e}")

            # Clean up locked project to prevent future lock errors
            self._cleanup_project(project_dir, project_name)

            raise RuntimeError(f"Ghidra analysis failed unexpectedly: {e}") from e

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
                with open(version_file) as f:
                    for line in f:
                        if line.startswith("application.version"):
                            diag["ghidra_version"] = line.split("=")[1].strip()
                            break
            except Exception as e:
                diag["ghidra_version"] = f"Error reading version: {e}"
        else:
            diag["ghidra_version"] = "Unknown"

        return diag
