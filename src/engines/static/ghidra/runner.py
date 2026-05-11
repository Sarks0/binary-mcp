"""
Ghidra headless runner with cross-platform support.
Handles Ghidra installation detection, project management, and script execution.
"""

import logging
import os
import platform
import re
import signal
import subprocess  # nosec B404 - Required for Ghidra headless execution
import time
from pathlib import Path

from src.utils.security import validate_parameter_pattern

logger = logging.getLogger(__name__)


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """
    Best-effort kill of a subprocess and all of its descendants.

    On Windows, ``proc.kill()`` only terminates the immediate child. Ghidra's
    ``analyzeHeadless.bat`` spawns ``java.exe`` grandchildren that survive
    the .bat's death and keep the captured stdout/stderr pipes open. The
    parent's post-timeout ``communicate()`` then blocks indefinitely. We
    invoke ``taskkill /F /T /PID`` to terminate the whole tree.

    On POSIX, the child is launched with ``start_new_session=True`` so it
    has its own process group, and we send SIGKILL to the group.
    """
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(  # nosec B603 B607 - tear down stuck Ghidra tree
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        else:
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
    except Exception as e:
        logger.warning(f"_kill_process_tree failed for pid {proc.pid}: {e}")
        try:
            proc.kill()
        except Exception:
            pass


# Patterns we look for in Ghidra stdout/stderr to surface actionable failure
# reasons. Ghidra's headless analyzer dumps a lot of noise; these markers are
# what users actually need to see to self-diagnose (cache poisoning, JDK
# mismatch, missing files, OOM, etc.).
_GHIDRA_FAILURE_MARKERS = (
    "ERROR Abort due to",
    "UnsupportedClassVersionError",
    "ClassNotFoundException",
    "NoClassDefFoundError",
    "OutOfMemoryError",
    "Exception in thread",
    "Caused by:",
    "ERROR REPORT",
    "FileNotFoundException",
    "IOException",
)


def _extract_ghidra_diagnostic(stdout: str, stderr: str, max_chars: int = 1500) -> str:
    """
    Pull the actionable bits out of Ghidra's stdout/stderr.

    Ghidra logs the real failure reason (e.g. UnsupportedClassVersionError
    from a poisoned OSGi cache) buried in long output. We grab matching
    lines plus their immediate trailing context so the model/user gets a
    diagnosis instead of a generic "Analysis failed" message.
    """
    matched: list[str] = []
    for stream_name, stream in (("stderr", stderr or ""), ("stdout", stdout or "")):
        if not stream:
            continue
        lines = stream.splitlines()
        for i, line in enumerate(lines):
            if any(marker in line for marker in _GHIDRA_FAILURE_MARKERS):
                # Include up to 4 trailing lines of stack/context per match.
                chunk = "\n".join(lines[i : i + 5])
                matched.append(f"[{stream_name}] {chunk}")

    if matched:
        # Dedupe while preserving order.
        seen: set[str] = set()
        unique = []
        for m in matched:
            if m not in seen:
                seen.add(m)
                unique.append(m)
        diagnostic = "\n---\n".join(unique)
    else:
        # No specific marker found -- fall back to last chunk of each stream.
        diagnostic = ""
        if stderr:
            diagnostic += f"[stderr tail]\n{stderr[-800:]}"
        if stdout:
            if diagnostic:
                diagnostic += "\n---\n"
            diagnostic += f"[stdout tail]\n{stdout[-800:]}"

    if len(diagnostic) > max_chars:
        diagnostic = diagnostic[:max_chars] + f"\n[...truncated, {len(diagnostic) - max_chars} more chars]"
    return diagnostic


class GhidraAnalysisError(RuntimeError):
    """
    Raised when Ghidra's headless analysis fails with a non-zero exit code
    or times out. Carries a user-facing ``diagnostic`` string extracted from
    Ghidra's own output, so callers can surface the real reason (e.g. JDK
    class-version mismatch from a poisoned OSGi cache) instead of a generic
    "Analysis failed" message.
    """

    def __init__(self, message: str, diagnostic: str = "", returncode: int | None = None):
        super().__init__(message)
        self.diagnostic = diagnostic
        self.returncode = returncode


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

        ``pdb_path`` is expected to be pre-validated by the caller -- it MUST
        be a regular file and MUST NOT be a symlink. The staging step symlinks
        ``dest`` to ``src.resolve()``, so accepting a user-supplied symlink
        here would let a caller stage an arbitrary host file (e.g. /etc/shadow)
        adjacent to the binary, which Ghidra then reads. We re-check here as
        a defence-in-depth measure.

        Returns the staged path. Callers should pass it to ``_cleanup_pdb``
        once Ghidra has finished reading the binary.
        """
        import shutil

        src = Path(pdb_path)
        # Reject symlinks BEFORE existence check so a dangling symlink also
        # fails fast with the right error.
        if src.is_symlink():
            raise ValueError(
                f"PDB path must not be a symlink: {pdb_path}"
            )
        if not src.exists():
            raise FileNotFoundError(f"PDB not found: {pdb_path}")
        if not src.is_file():
            raise ValueError(
                f"PDB path must be a regular file: {pdb_path}"
            )

        binary = Path(binary_path)
        # Ghidra looks for <binary-with-suffix>.pdb adjacent to the binary
        # (e.g. foo.exe → foo.pdb). Use stem to normalise.
        dest = binary.parent / f"{binary.stem}.pdb"

        if dest.exists() and dest.resolve() == src.resolve():
            # Already in the right place
            return dest

        # Remove any prior artefact so staging is idempotent. Since we've
        # already rejected symlink-as-source and non-files above, the only
        # path here is intentional re-staging of a new PDB next to the
        # binary; a pre-existing <stem>.pdb adjacent to the binary is
        # replaced. Log it so users can spot accidental clobbers.
        if dest.exists() or dest.is_symlink():
            logger.debug(
                "Replacing existing PDB at %s while staging %s",
                dest, src,
            )
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
        analysis_depth: str = "full",
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
            GhidraAnalysisError: If Ghidra exits non-zero or times out. Carries
                a ``.diagnostic`` string extracted from Ghidra's own output so
                callers can surface the real failure reason.
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
        # Map analysis_depth onto Ghidra flags. Both skip_decompile and
        # analysis_depth coexist; analysis_depth wins when set to a non-default.
        # - full:       all auto-analyzers + decompile (legacy behavior)
        # - structural: all auto-analyzers, skip per-function decompile
        # - shallow:    pass -noanalysis to analyzeHeadless and skip decompile;
        #               function table comes from PE/ELF symbols + basic disasm.
        if analysis_depth not in ("full", "structural", "shallow"):
            raise ValueError(
                f"Invalid analysis_depth {analysis_depth!r}; "
                "expected 'full', 'structural', or 'shallow'"
            )
        if analysis_depth in ("structural", "shallow") or skip_decompile:
            env["GHIDRA_SKIP_DECOMPILE"] = "1"
        env["GHIDRA_ANALYSIS_DEPTH"] = analysis_depth
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
        ])

        # When a PDB is supplied, install a pre-script that enables
        # PdbUniversalAnalyzer.SearchUntrustedLocations before auto-analysis
        # runs. Without it, Ghidra 10.x+ refuses to load the PDB we just
        # staged adjacent to the binary (the binary's directory is treated
        # as untrusted by default), and load_pdb returns "Gain: +0" with
        # no symbols applied. Pre-script must precede -postScript on the
        # command line so analyzeHeadless runs them in the right order.
        if pdb_path:
            cmd.extend(["-preScript", "enable_pdb_load.py"])

        cmd.extend([
            "-postScript", script_name,
        ])

        if analysis_depth == "shallow":
            cmd.append("-noanalysis")

        if not keep_project:
            cmd.append("-deleteProject")

        logger.info(f"Running Ghidra analysis: {' '.join(cmd)}")
        logger.debug(f"Environment: GHIDRA_CONTEXT_JSON={output_path}")

        start_time = time.time()

        # Use Popen + manual lifecycle (instead of subprocess.run) so timeout
        # cleanup can kill Ghidra's whole java.exe grandchild tree. With
        # subprocess.run on Windows, the post-timeout drain blocks
        # indefinitely if Java keeps the pipes open after the .bat dies.
        # Popen sits inside the try so spawn-time failures (missing
        # analyzeHeadless, fd exhaustion, bad argv) still hit the staged-PDB
        # cleanup in finally.
        proc = None
        try:
            proc = subprocess.Popen(  # nosec B603 - cmd built from validated args
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                # POSIX: own process group so SIGKILL can fan out via killpg.
                # Windows ignores start_new_session; we use taskkill /T instead.
                start_new_session=(os.name != "nt"),
            )

            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as e:
                elapsed_time = time.time() - start_time
                logger.error(f"Analysis timeout after {elapsed_time:.2f}s")

                _kill_process_tree(proc)
                try:
                    drain_stdout, drain_stderr = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    # Pipes still held by an unreachable descendant. Close
                    # them so we don't leak fds; partial output captured by
                    # the original TimeoutExpired is still useful.
                    for stream in (proc.stdout, proc.stderr):
                        try:
                            if stream is not None:
                                stream.close()
                        except Exception:
                            pass
                    drain_stdout, drain_stderr = "", ""

                self._cleanup_project(project_dir, project_name)

                partial_stdout = (e.stdout.decode("utf-8", errors="replace")
                                  if isinstance(e.stdout, bytes)
                                  else (e.stdout or "")) or drain_stdout
                partial_stderr = (e.stderr.decode("utf-8", errors="replace")
                                  if isinstance(e.stderr, bytes)
                                  else (e.stderr or "")) or drain_stderr
                diagnostic = _extract_ghidra_diagnostic(
                    partial_stdout, partial_stderr
                )
                raise GhidraAnalysisError(
                    f"Ghidra analysis timed out after {timeout}s. "
                    f"Binary may be too large or complex.",
                    diagnostic=diagnostic,
                ) from e

            elapsed_time = time.time() - start_time

            if proc.returncode != 0:
                logger.error(f"Analysis failed after {elapsed_time:.2f}s")
                logger.error(f"stdout: {stdout}")
                logger.error(f"stderr: {stderr}")

                self._cleanup_project(project_dir, project_name)

                diagnostic = _extract_ghidra_diagnostic(stdout or "", stderr or "")
                raise GhidraAnalysisError(
                    f"Ghidra analysis failed with exit code {proc.returncode}.",
                    diagnostic=diagnostic,
                    returncode=proc.returncode,
                )

            logger.info(f"Analysis completed in {elapsed_time:.2f}s")
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

        finally:
            # Ensure no zombie even on unexpected exception paths. proc may
            # be None if subprocess.Popen itself raised (missing
            # analyzeHeadless, fd exhaustion, bad argv) -- staged-PDB
            # cleanup must still run in that case.
            if proc is not None and proc.poll() is None:
                _kill_process_tree(proc)
                try:
                    proc.communicate(timeout=5)
                except Exception:
                    pass
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
