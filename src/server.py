"""
Binary MCP Server for comprehensive binary analysis.

Provides 245 tools for static and dynamic binary analysis:
- Static analysis via Ghidra (headless mode) for native binaries
- Static analysis via ILSpyCmd for .NET assemblies
- Dynamic analysis via x64dbg (native plugin)
- Control flow analysis (CFG, cyclomatic complexity, loops, dead code)
- Malware behavior detection (10 categories, anti-analysis, API call chains)
- Function hashing and cross-binary matching
"""

import contextlib
import functools
import json
import logging
import os
import re
import struct
import sys
import time
from pathlib import Path

from fastmcp import FastMCP

from src.engines.session import AnalysisType, UnifiedSessionManager
from src.engines.static.ghidra.project_cache import ProjectCache
from src.engines.static.ghidra.runner import GhidraAnalysisError, GhidraRunner
from src.tools.control_flow_tools import register_control_flow_tools
from src.tools.dispatch_tools import register_dispatch_tools
from src.tools.dotnet_tools import register_dotnet_tools
from src.tools.dynamic_tools import register_dynamic_tools
from src.tools.fid_tools import register_fid_tools
from src.tools.function_hash_tools import register_function_hash_tools
from src.tools.indirect_call_tools import register_indirect_call_tools
from src.tools.malware_tools import register_malware_tools
from src.tools.pe_tools import register_pe_tools
from src.tools.reporting import register_reporting_tools
from src.tools.review_tools import register_review_tools
from src.tools.triage_tools import register_triage_tools
from src.tools.vt_tools import register_vt_tools
from src.tools.windbg_tools import register_windbg_tools
from src.tools.yara_tools import register_yara_tools
from src.utils.compatibility import (
    BinaryCompatibilityChecker,
    CompatibilityLevel,
)
from src.utils.config import get_config_int
from src.utils.patterns import APIPatterns, CryptoPatterns
from src.utils.security import (
    FileSizeError,
    PathTraversalError,
    UserFacingError,
    get_allowed_dirs,
    safe_error_message,
    safe_regex_compile,
    sanitize_binary_path,
    sanitize_output_path,
    validate_numeric_range,
)

# Allowed output directory for decrypted/decoded files
CRYPTO_OUTPUT_DIR = Path.home() / ".binary_mcp_output" / "crypto"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize components
app = FastMCP("binary-mcp")
runner = GhidraRunner()
cache = ProjectCache()
session_manager = UnifiedSessionManager()
api_patterns = APIPatterns()
crypto_patterns = CryptoPatterns()
compatibility_checker = BinaryCompatibilityChecker()


# --- Helper Functions ---

def log_to_session(func=None, *, analysis_type: AnalysisType = AnalysisType.STATIC):
    """
    Decorator to automatically log tool calls to session with auto-session support.

    Features:
    - Transparently captures tool name, arguments, and output
    - Auto-starts/resumes session if binary_path is in arguments
    - Tracks analysis type (static/dynamic) for mixed sessions

    Args:
        analysis_type: Type of analysis (STATIC or DYNAMIC)
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # Extract binary_path for auto-session if present
            binary_path = kwargs.get("binary_path")

            # Auto-ensure session if we have a binary path and auto-session is enabled
            if binary_path and session_manager.auto_session_enabled:
                session_manager.ensure_session(
                    binary_path=binary_path,
                    analysis_type=analysis_type
                )

            # Call the original function
            result = fn(*args, **kwargs)

            # Log to active session if one exists
            if session_manager.active_session_id:
                tool_name = fn.__name__
                session_manager.log_tool_call(
                    tool_name=tool_name,
                    arguments=kwargs,
                    output=result,
                    analysis_type=analysis_type
                )

            return result

        return wrapper

    # Handle both @log_to_session and @log_to_session() syntax
    if func is not None:
        return decorator(func)
    return decorator


def _check_ghidra_import_failure(stdout: str, stderr: str) -> tuple[bool, str | None]:
    """
    Check Ghidra output for import failure indicators.

    Ghidra often returns exit code 0 even when import fails, so we need to
    check the output for failure messages.

    Args:
        stdout: Ghidra stdout output
        stderr: Ghidra stderr output

    Returns:
        Tuple of (failed: bool, error_message: str | None)
    """
    combined = (stdout or "") + (stderr or "")

    # Known import failure patterns
    failure_patterns = [
        (r"No load spec found", "Ghidra could not determine the binary format"),
        (r"Unable to create loader", "Ghidra loader initialization failed"),
        (r"Failed to import", "Ghidra import failed"),
        (r"Import failed", "Ghidra import failed"),
        (r"ERROR.*Unable to.*import", "Import error occurred"),
        (r"No language.*found", "Ghidra could not determine processor architecture"),
        (r"Language not found", "Processor/language specification not found"),
        (r"IOException.*reading", "Error reading binary file"),
        (r"InvalidInputException", "Invalid binary format"),
        (r"NOT_FOUND", "Binary format not recognized"),
    ]

    for pattern, message in failure_patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            return True, message

    return False, None


def _validate_analysis_context(
    context: dict,
    binary_path: str,
    ghidra_stdout: str,
    ghidra_stderr: str
) -> tuple[bool, str | None]:
    """
    Validate that Ghidra analysis produced meaningful output.

    This catches cases where Ghidra returns 0 but produces empty/minimal output
    due to import failures.

    Args:
        context: The loaded JSON context
        binary_path: Path to the analyzed binary
        ghidra_stdout: Ghidra stdout for error context
        ghidra_stderr: Ghidra stderr for error context

    Returns:
        Tuple of (is_valid: bool, error_message: str | None)
    """
    metadata = context.get("metadata", {})
    functions = context.get("functions", [])
    memory_map = context.get("memory_map", [])

    # Check if metadata indicates a failed import
    exec_format = metadata.get("executable_format", "")

    # Empty or "Unknown" format often indicates import failure
    if not exec_format or exec_format == "Unknown":
        # Check if this is actually a valid empty binary or a failed import
        if not memory_map and not functions:
            return False, (
                "Ghidra produced no analysis output. This typically means the binary "
                "format was not recognized. Check the debug log for details."
            )

    # Check for suspiciously empty analysis
    if not functions and not context.get("imports", []) and not context.get("strings", []):
        # This could be a data file or failed import
        if memory_map:
            # Has memory map but nothing else - might be a data/resource file
            logger.warning(
                f"Analysis produced memory map but no functions/imports/strings for {binary_path}"
            )
        else:
            return False, (
                "Analysis produced no data. The binary may not have been imported correctly. "
                "Try specifying a processor and loader explicitly."
            )

    # Check Ghidra output for warnings that indicate partial failure
    combined = (ghidra_stdout or "") + (ghidra_stderr or "")
    if "WARN" in combined and "Unable to" in combined:
        logger.warning(f"Ghidra reported warnings during analysis of {binary_path}")

    return True, None


def _get_elf_loader_recommendation(binary_path: str) -> str | None:
    """
    Get ELF-specific loader recommendations based on architecture.

    Args:
        binary_path: Path to ELF binary

    Returns:
        Recommendation string or None if not an ELF
    """
    try:
        with open(binary_path, 'rb') as f:
            magic = f.read(20)

        if magic[:4] != b'\x7fELF':
            return None

        # ELF class: 1 = 32-bit, 2 = 64-bit
        ei_class = magic[4]
        # ELF data encoding: 1 = little-endian, 2 = big-endian
        ei_data = magic[5]
        # Machine type at offset 18-20
        machine = struct.unpack('<H' if ei_data == 1 else '>H', magic[18:20])[0]

        # Map machine type to Ghidra processor spec
        elf_processors = {
            0x03: ("x86:LE:32:default", "x86 32-bit"),
            0x3E: ("x86:LE:64:default", "x86-64"),
            0x28: ("ARM:LE:32:v7" if ei_data == 1 else "ARM:BE:32:v7", "ARM 32-bit"),
            0xB7: ("AARCH64:LE:64:v8A", "ARM64/AArch64"),
            0x08: ("MIPS:BE:32:default" if ei_data == 2 else "MIPS:LE:32:default", "MIPS"),
            0x14: ("PowerPC:BE:32:default", "PowerPC 32-bit"),
            0x15: ("PowerPC:BE:64:default", "PowerPC 64-bit"),
            0xF3: ("RISCV:LE:64:RV64GC" if ei_class == 2 else "RISCV:LE:32:RV32GC", "RISC-V"),
        }

        if machine in elf_processors:
            proc_spec, arch_name = elf_processors[machine]
            return (
                f"ELF detected: {arch_name}\n"
                f"Try: analyze_binary(..., processor=\"{proc_spec}\", loader=\"ElfLoader\")"
            )
        else:
            return (
                f"ELF detected with unknown machine type 0x{machine:x}\n"
                f"Try: analyze_binary(..., loader=\"ElfLoader\") with appropriate processor spec"
            )

    except Exception as e:
        logger.debug(f"Failed to read ELF header: {e}")
        return None


def _write_resume_manifest(
    cache_dir: Path,
    binary_path: str,
    existing_cache: dict,
    skip_decompile: bool,
) -> str | None:
    """
    Write a tiny ``{"complete_addresses": [...]}`` sidecar so the Ghidra
    Jython script can skip already-analyzed functions without loading the
    multi-GB resume JSON (which OOMs the JVM on large binaries).

    "Complete" depends on the upcoming run:
      - ``skip_decompile=True`` -> every cached entry counts as complete
      - ``skip_decompile=False`` -> only entries with pseudocode (or
        thunks/externals that are intentionally never decompiled)

    Writes are atomic (tmp file + os.replace) so a crashed run cannot leave
    a partial JSON that the next run silently trusts.
    """
    try:
        complete = []
        for func in existing_cache.get("functions", []):
            addr = func.get("address")
            if not addr:
                continue
            if skip_decompile:
                complete.append(addr)
                continue
            if func.get("pseudocode"):
                complete.append(addr)
                continue
            if func.get("decompile_status") == "skipped_thunk_or_external":
                complete.append(addr)
                continue
        manifest_path = (
            Path(cache_dir) / f"resume_manifest_{Path(binary_path).stem}.json"
        )
        tmp_path = manifest_path.with_suffix(manifest_path.suffix + ".tmp")
        run_id = f"{os.getpid()}-{time.monotonic_ns()}"
        body = {"complete_addresses": complete, "run_id": run_id}
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(body, f)
        os.replace(tmp_path, manifest_path)
        logger.info(
            f"Wrote resume manifest with {len(complete)} complete addresses "
            f"to {manifest_path} (run_id={run_id})"
        )
        return str(manifest_path)
    except Exception as e:
        logger.warning(f"Failed to write resume manifest: {e}")
        return None


@contextlib.contextmanager
def _delta_run_lock(cache_dir: Path, binary_path: str):
    """
    Cross-platform exclusive lock for incremental Ghidra runs on a binary.

    Two parallel ``analyze_binary(..., incremental=True)`` calls on the same
    binary would race on the manifest, the temp output JSON, and the cache
    file. This advisory lock makes the second caller fail fast with a clear
    message instead of silently corrupting cache state.
    """
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    lock_path = cache_dir / f"delta_run_{Path(binary_path).stem}.lock"
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    locked = False
    try:
        if sys.platform == "win32":
            import msvcrt
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                locked = True
            except OSError:
                raise RuntimeError(
                    f"Another incremental analysis is already running for "
                    f"{binary_path}. Wait for it to finish or remove "
                    f"{lock_path} if you are sure no run is in progress."
                )
        else:
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except (BlockingIOError, OSError):
                raise RuntimeError(
                    f"Another incremental analysis is already running for "
                    f"{binary_path}. Wait for it to finish or remove "
                    f"{lock_path} if you are sure no run is in progress."
                )
        yield
    finally:
        if locked:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    try:
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
            except Exception:
                pass
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            lock_path.unlink(missing_ok=True)
        except OSError:
            pass


def _merge_delta_into_cache(existing: dict, delta: dict) -> dict:
    """
    Merge a delta context (output of an incremental Ghidra run) into the
    existing cached context.

    Top-level fields from the new run replace the old ones (metadata,
    imports, exports, strings, memory_map, data_types, analysis_stats).
    The functions list is merged per-address: delta entries replace old
    entries with the same address; new addresses are appended; addresses
    that the delta did not touch are preserved from the existing cache.
    """
    merged = dict(delta)

    # Index existing functions by address for fast replacement.
    existing_funcs = existing.get("functions", []) or []
    addr_to_idx = {}
    for idx, f in enumerate(existing_funcs):
        a = f.get("address")
        if a:
            addr_to_idx[a] = idx

    merged_funcs = list(existing_funcs)
    for new_func in delta.get("functions", []) or []:
        addr = new_func.get("address")
        if not addr:
            continue
        if addr in addr_to_idx:
            merged_funcs[addr_to_idx[addr]] = new_func
        else:
            merged_funcs.append(new_func)
    merged["functions"] = merged_funcs

    # Preserve previously-extracted skipped_functions list if the delta
    # didn't produce one (rare, but be defensive).
    if not merged.get("skipped_functions") and existing.get("skipped_functions"):
        merged["skipped_functions"] = existing["skipped_functions"]

    return merged


def get_analysis_context(
    binary_path: str,
    force_reanalyze: bool = False,
    processor: str | None = None,
    loader: str | None = None,
    *,
    skip_decompile: bool = False,
    max_functions: int | None = None,
    function_timeout: int | None = None,
    incremental: bool = False,
    start_address: str | None = None,
    end_address: str | None = None,
    pdb_path: str | None = None,
    enable_fid: bool = False,
    analysis_depth: str = "structural",
) -> dict:
    """
    Get or create analysis context for a binary.

    Args:
        binary_path: Path to binary file
        force_reanalyze: Force re-analysis even if cached
        processor: Optional processor specification (e.g., "x86:LE:64:default")
        loader: Optional loader name (e.g., "PeLoader" for Windows PE, "ElfLoader" for Linux ELF)
        skip_decompile: Skip per-function decompilation for a much faster
            structural pass (no pseudocode). Useful for large binaries where
            decompilation dominates wall-clock time.
        max_functions: Cap how many functions the Jython script will process
            this run (useful with ``incremental`` for chunked coverage).
        function_timeout: Per-function decompilation timeout in seconds.
        incremental: When True and a cache already exists, pass it to Ghidra
            as ``resume_from_cache`` so the script skips previously-analyzed
            functions and extends coverage rather than restarting.
        start_address / end_address: Hex bounds used to restrict the run to a
            sub-range (``"0x61abbc"``). Pairs well with ``incremental``.
        pdb_path: Path to a PDB file. Staged next to the binary so Ghidra's
            PdbUniversalAnalyzer picks it up. Forces a fresh analysis if set.
        enable_fid: Run Ghidra's Function ID library matching per function.
        analysis_depth: Cache-acceptance floor. Default ``"structural"`` so
            tools that don't read pseudocode (get_strings, get_imports,
            get_xrefs, etc.) hit a structural cache without forcing a fresh
            full Ghidra run. ``analyze_binary`` keeps ``"full"`` as its
            top-level default. Tools that genuinely need pseudocode either
            request ``"full"`` explicitly or use the peek-and-upgrade
            pattern in ``decompile_function``.

    Returns:
        Analysis context dict

    Raises:
        RuntimeError: If analysis fails
        PathTraversalError: If path is outside allowed directories
        FileSizeError: If file exceeds size limits
    """
    # Validate and sanitize binary path (SECURITY FIX)
    # TODO: Configure allowed_dirs from a config file
    # For now, allow any directory but still validate the path exists and is a file
    try:
        validated_path = sanitize_binary_path(
            binary_path,
            allowed_dirs=get_allowed_dirs(),
            max_size_bytes=500 * 1024 * 1024  # 500MB max
        )
        # Use string representation for consistency with rest of codebase
        binary_path = str(validated_path)
    except (PathTraversalError, FileSizeError, FileNotFoundError, ValueError) as e:
        logger.error(f"Path validation failed: {e}")
        raise RuntimeError(f"Invalid binary path: {e}")

    # Short-circuit to cache unless the caller asked to re-analyze,
    # is overriding the processor/loader, or is extending coverage via
    # incremental/range options. PDB/FID both require a fresh Ghidra run.
    extending = incremental or start_address or end_address
    if not force_reanalyze and not processor and not loader and not extending \
            and not pdb_path and not enable_fid:
        cached_context = cache.get_cached(binary_path)
        if cached_context:
            # If the cache was produced at a shallower depth than the caller
            # asked for, run a fresh analysis instead. shallow < structural < full.
            depth_rank = {"shallow": 0, "structural": 1, "full": 2}
            cached_depth = cached_context.get("metadata", {}).get(
                "analysis_depth", "full"
            )
            if depth_rank.get(cached_depth, 2) >= depth_rank.get(analysis_depth, 2):
                logger.info(
                    "Using cached analysis for %s (cached_depth=%s)",
                    binary_path, cached_depth,
                )
                return cached_context
            logger.info(
                "Cache depth %s is shallower than requested %s; reanalyzing",
                cached_depth, analysis_depth,
            )

    # Run Ghidra analysis
    logger.info(f"Analyzing {binary_path} with Ghidra...")
    if processor or loader:
        logger.info(f"Using explicit loader config - Processor: {processor}, Loader: {loader}")

    output_path = cache.cache_dir / f"temp_analysis_{Path(binary_path).stem}.json"
    script_path = Path(__file__).parent / "engines" / "static" / "ghidra" / "scripts"

    # Resolve resume path if caller wants to extend an existing cache.
    # When the caller passed start_address/end_address but did not also pass
    # incremental=True, auto-promote: a ranged run without resume would
    # overwrite the existing full cache with a tiny range-only result.
    if (start_address or end_address) and not incremental:
        existing = cache.get_cache_path(binary_path)
        if existing is not None:
            logger.info(
                "Address range supplied without incremental=True; auto-promoting "
                "to incremental to avoid overwriting the existing cache."
            )
            incremental = True

    resume_from_cache = None
    resume_manifest_path = None
    existing_cache_data = None
    delta_lock_cm = contextlib.nullcontext()
    if incremental:
        resume_from_cache = cache.get_cache_path(binary_path)
        if resume_from_cache is None:
            logger.info("incremental=True but no cache exists yet; running full analysis")
        else:
            logger.info(f"Resuming analysis from cache: {resume_from_cache}")
            # Acquire an advisory lock so a second concurrent incremental run
            # on the same binary fails fast instead of corrupting the cache.
            delta_lock_cm = _delta_run_lock(cache.cache_dir, binary_path)
            delta_lock_cm.__enter__()
            try:
                existing_cache_data = cache.get_cached(binary_path)
            except Exception as e:
                logger.warning(f"Could not pre-load cache for delta merge: {e}")
                existing_cache_data = None
            if existing_cache_data is not None:
                resume_manifest_path = _write_resume_manifest(
                    cache.cache_dir, binary_path, existing_cache_data,
                    skip_decompile=skip_decompile,
                )

    try:
        # Default bumped to 1800s (30 min) -- large binaries routinely need more
        # than the old 10-minute ceiling. Bounds are still 30s..3600s.
        timeout = get_config_int("GHIDRA_TIMEOUT", 1800)
        timeout = validate_numeric_range(timeout, 30, 3600, "GHIDRA_TIMEOUT")
        result = runner.analyze(
            binary_path=binary_path,
            script_path=str(script_path),
            script_name="core_analysis.py",
            output_path=str(output_path),
            keep_project=True,  # Keep project for incremental analysis
            timeout=timeout,
            processor=processor,
            loader=loader,
            skip_decompile=skip_decompile,
            max_functions=max_functions,
            function_timeout=function_timeout,
            analysis_depth=analysis_depth,
            resume_from_cache=None if resume_manifest_path else (
                str(resume_from_cache) if resume_from_cache else None
            ),
            resume_manifest=resume_manifest_path,
            start_address=start_address,
            end_address=end_address,
            pdb_path=pdb_path,
            enable_fid=enable_fid,
        )

        # Save Ghidra output to debug file for inspection
        debug_file = cache.cache_dir / "ghidra_debug.log"
        try:
            with open(debug_file, 'w', encoding='utf-8', errors='replace') as f:
                f.write("=== GHIDRA ANALYSIS DEBUG LOG ===\n")
                f.write(f"Binary: {binary_path}\n")
                f.write(f"Output Path: {output_path}\n")
                f.write(f"Script Path: {script_path}\n\n")
                f.write("=== STDOUT ===\n")
                f.write(result.get('stdout', 'N/A'))
                f.write("\n\n=== STDERR ===\n")
                f.write(result.get('stderr', 'N/A'))
            print(f"DEBUG: Ghidra output saved to {debug_file}", file=sys.stderr)
        except Exception as e:
            print(f"DEBUG: Failed to write debug log: {e}", file=sys.stderr)

        ghidra_stdout = result.get('stdout', '')
        ghidra_stderr = result.get('stderr', '')

        # Check for import failure in Ghidra output (even with exit code 0)
        import_failed, import_error = _check_ghidra_import_failure(ghidra_stdout, ghidra_stderr)
        if import_failed:
            # Get ELF-specific recommendations if applicable
            elf_recommendation = _get_elf_loader_recommendation(binary_path)

            internal_details = f"Ghidra import failure detected: {import_error}\n"
            internal_details += f"Debug log: {debug_file}\n"
            internal_details += f"Stdout (last 1000 chars): {ghidra_stdout[-1000:]}\n"
            internal_details += f"Stderr (last 1000 chars): {ghidra_stderr[-1000:]}"

            user_message = f"Analysis failed: {import_error}."
            if elf_recommendation:
                user_message += f"\n\n**Recommendation:**\n{elf_recommendation}"
            else:
                user_message += (
                    "\n\nTry specifying processor and loader explicitly. "
                    "See analyze_binary() docstring for examples."
                )

            raise UserFacingError(user_message, internal_details=internal_details)

        # Check if output file was created
        if not output_path.exists():
            # Get ELF-specific recommendations if applicable
            elf_recommendation = _get_elf_loader_recommendation(binary_path)

            internal_details = f"Ghidra did not create output file: {output_path}\n"
            internal_details += f"Debug log: {debug_file}\n"
            internal_details += f"Stdout (last 1000 chars): {ghidra_stdout[-1000:]}\n"
            internal_details += f"Stderr (last 1000 chars): {ghidra_stderr[-1000:]}"

            user_message = "Analysis failed. Ghidra did not produce output."
            if elf_recommendation:
                user_message += f"\n\n**Recommendation:**\n{elf_recommendation}"
            else:
                user_message += " This may be due to an unsupported binary format or corrupted file."

            raise UserFacingError(user_message, internal_details=internal_details)

        # Load analysis results
        with open(output_path, encoding="utf-8") as f:
            context = json.load(f)

        # If the Ghidra script ran in delta mode (manifest-based resume),
        # ``context`` holds only NEW or RE-DECOMPILED functions plus refreshed
        # top-level fields. Merge it into the existing cache before validation
        # so a small delta does not get rejected for having "too few functions".
        is_delta_run = bool(context.get("analysis_stats", {}).get("delta_run"))
        if is_delta_run and existing_cache_data is not None:
            logger.info(
                f"Merging delta ({len(context.get('functions', []))} entries) "
                f"into cache ({len(existing_cache_data.get('functions', []))} entries)"
            )
            context = _merge_delta_into_cache(existing_cache_data, context)

        # Validate the analysis context has meaningful data
        is_valid, validation_error = _validate_analysis_context(
            context, binary_path, ghidra_stdout, ghidra_stderr
        )
        if not is_valid:
            # Get ELF-specific recommendations if applicable
            elf_recommendation = _get_elf_loader_recommendation(binary_path)

            internal_details = f"Validation failed: {validation_error}\n"
            internal_details += f"Debug log: {debug_file}\n"
            internal_details += f"Context keys: {list(context.keys())}\n"
            internal_details += f"Metadata: {context.get('metadata', {})}\n"
            internal_details += f"Functions count: {len(context.get('functions', []))}\n"
            internal_details += f"Stdout (last 500 chars): {ghidra_stdout[-500:]}"

            user_message = validation_error
            if elf_recommendation:
                user_message += f"\n\n**Recommendation:**\n{elf_recommendation}"

            # Don't cache invalid results
            output_path.unlink(missing_ok=True)
            raise UserFacingError(user_message, internal_details=internal_details)

        # Tag the cache with the depth it was produced at so callers can
        # detect a thin shallow/structural cache and upgrade if they need
        # decompiled output. Existing caches without this field count as
        # "full" because that was the only mode prior to PR #116.
        meta = context.setdefault("metadata", {})
        meta["analysis_depth"] = analysis_depth

        # Cache the results
        cache.save_cached(binary_path, context)

        # Replay any user-supplied notes onto the freshly-built cache
        # (the side-car survives invalidate, so this is what makes
        # annotations persist across force_reanalyze / load_pdb). The
        # second save is cheap and keeps the on-disk cache annotated
        # so cache-direct readers see notes too.
        try:
            cache.apply_notes_overlay(binary_path, context)
            cache.save_cached(binary_path, context)
        except Exception as e:
            logger.warning(f"Failed to apply notes overlay after analysis: {e}")

        # Clean up temp file
        output_path.unlink()

        logger.info(f"Analysis complete: {result['elapsed_time']:.2f}s")
        return context

    except (UserFacingError, GhidraAnalysisError, PathTraversalError, FileSizeError):
        # Preserve curated user-facing errors and Ghidra diagnostics so callers
        # like analyze_binary() can surface the real failure reason instead of
        # collapsing every failure into an opaque "Failed to analyze binary" /
        # reference-ID response. See docs/ghidra-mcp-defender-issues.md (Issue 2).
        raise
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise RuntimeError(f"Failed to analyze binary: {e}")
    finally:
        if resume_manifest_path:
            try:
                Path(resume_manifest_path).unlink(missing_ok=True)
            except Exception as e:
                logger.debug(f"Could not clean up resume manifest: {e}")
        try:
            delta_lock_cm.__exit__(None, None, None)
        except Exception as e:
            logger.debug(f"Delta-run lock release failed: {e}")


# --- Phase 1: Core Tools (P0 - Critical) ---

@app.tool()
@log_to_session
def analyze_binary(
    binary_path: str,
    force_reanalyze: bool = False,
    processor: str | None = None,
    loader: str | None = None,
    skip_compatibility_check: bool = False,
    skip_decompile: bool = False,
    max_functions: int | None = None,
    function_timeout: int | None = None,
    incremental: bool = False,
    start_address: str | None = None,
    end_address: str | None = None,
    pdb_path: str | None = None,
    enable_fid: bool = False,
    analysis_depth: str = "full",
) -> str:
    """
    Analyze a binary file with Ghidra headless analyzer.

    This is the foundation tool that must be called before using other analysis tools.
    It loads the binary, runs Ghidra's auto-analysis, and extracts comprehensive data.

    IMPORTANT: This tool automatically checks binary compatibility before analysis.
    For .NET assemblies or packed binaries, it will return recommendations for better tools.
    Use skip_compatibility_check=True to bypass this check if you want to proceed anyway.

    Args:
        binary_path: Path to the binary file to analyze
        force_reanalyze: Force re-analysis even if cached (default: False)
        processor: Optional processor spec when AutoImporter fails (e.g., "x86:LE:64:default")
        loader: Optional loader name when AutoImporter fails (e.g., "PeLoader" for Windows PE)
        skip_compatibility_check: Skip pre-analysis compatibility check (default: False)
        skip_decompile: Skip decompilation for a fast structural pass (no pseudocode).
            Recommended for a first pass on very large binaries -- functions,
            imports, strings, and memory map are still extracted.
        max_functions: Cap how many functions to process this run (pairs with
            ``incremental`` for multi-pass coverage of huge binaries).
        function_timeout: Per-function decompile timeout (seconds). Lower values
            skip anti-analysis code faster.
        incremental: When True, extend an existing cache instead of starting
            fresh. Previously-analyzed functions are skipped and preserved.
        start_address / end_address: Hex bounds to restrict the run to an
            address range (e.g. ``"0x61abbc"``).
        pdb_path: Path to a Windows PDB file. Staged next to the binary so
            Ghidra's PdbUniversalAnalyzer can apply symbolic function names.
        enable_fid: Run Ghidra's Function ID library fingerprinting; matches
            are stored per-function in ``fid_match``. Query via ``fid_match``
            tool after analysis.
        analysis_depth: Analysis tier. ``"full"`` (default) runs all auto-analyzers
            and decompiles every function. ``"structural"`` runs auto-analyzers
            but skips decompilation (equivalent to ``skip_decompile=True``).
            ``"shallow"`` adds Ghidra's ``-noanalysis`` flag for the fastest
            possible pass: function table from PE/ELF symbols + basic disasm,
            no xrefs, no decompile. Use shallow for VR triage on multi-MB
            binaries, then upgrade with ``analysis_depth="structural"`` or
            ``"full"`` once you've narrowed the target.

    Returns:
        Analysis summary with basic statistics, or compatibility warning if issues detected

    Note:
        If Ghidra's AutoImporter fails with "No load spec found", you can manually specify:
        - For x86-64 Windows PE: processor="x86:LE:64:default", loader="PeLoader"
        - For x86-64 Linux ELF: processor="x86:LE:64:default", loader="ElfLoader"
        - For macOS Mach-O: processor="x86:LE:64:default", loader="MachoLoader"

        Common Ghidra loaders: PeLoader, ElfLoader, MachoLoader, BinaryLoader, CoffLoader

        Large-binary workflow (e.g. 17MB+ with 60K+ functions):
        1. First pass: ``analyze_binary(..., skip_decompile=True)`` -- structure only.
        2. Extend: ``analyze_binary(..., incremental=True, max_functions=5000)``
           repeatedly, or target a range with ``start_address``/``end_address``.
    """
    # Store compatibility info for inclusion in output
    compat_warning = None

    try:
        # Pre-analysis compatibility check (unless skipped or using cache)
        if not skip_compatibility_check and not cache.get_cached(binary_path):
            try:
                compat_info = compatibility_checker.check_compatibility(binary_path)

                # For any non-FULL compatibility, capture warning but PROCEED with analysis
                if compat_info.compatibility != CompatibilityLevel.FULL:
                    # Build a concise warning message
                    issues_summary = []
                    for issue in compat_info.issues:
                        issues_summary.append(f"- [{issue.severity.upper()}] {issue.message}")
                        issues_summary.append(f"  → {issue.recommendation}")

                    compat_warning = f"""
**⚠️ Compatibility Notice ({compat_info.compatibility.value.upper()}):**
Format: {compat_info.format.value}
{chr(10).join(issues_summary)}
"""
                    logger.warning(f"Compatibility issues for {binary_path}: {compat_info.compatibility.value}")

            except Exception as e:
                # Don't fail on compatibility check errors, just log and proceed
                logger.warning(f"Compatibility check failed, proceeding with analysis: {e}")

        context = get_analysis_context(
            binary_path,
            force_reanalyze,
            processor,
            loader,
            skip_decompile=skip_decompile,
            max_functions=max_functions,
            function_timeout=function_timeout,
            incremental=incremental,
            start_address=start_address,
            end_address=end_address,
            pdb_path=pdb_path,
            enable_fid=enable_fid,
            analysis_depth=analysis_depth,
        )

        metadata = context.get("metadata", {})
        functions = context.get("functions", [])
        imports = context.get("imports", [])
        strings = context.get("strings", [])

        # Check for analysis quality indicators
        warnings = []

        # .NET/CLR indicator: high structure count + low imports
        structure_count = len(context.get('data_types', {}).get('structures', []))
        if structure_count > 10000 and len(imports) == 0:
            warnings.append("⚠️ High structure count with no imports suggests .NET assembly - consider using dnSpy/ILSpy for better results")

        # Packed indicator: very few imports
        if 0 < len(imports) < 5 and len(functions) > 100:
            warnings.append("⚠️ Very few imports detected - binary may be packed. Consider unpacking first.")

        # Build the summary output
        summary = ""

        # Add compatibility warning at the top if present
        if compat_warning:
            summary += compat_warning + "\n"

        summary += f"""Binary Analysis Complete: {metadata.get('name', 'Unknown')}

**Metadata:**
- Format: {metadata.get('executable_format', 'Unknown')}
- Architecture: {metadata.get('language', 'Unknown')}
- Compiler: {metadata.get('compiler', 'Unknown')}
- Image Base: {metadata.get('image_base', 'Unknown')}
- Entry Point: {metadata.get('min_address', 'Unknown')}

**Statistics:**
- Functions: {len(functions)}
- Imports: {len(imports)}
- Strings: {len(strings)}
- Memory Blocks: {len(context.get('memory_map', []))}
- Structures: {structure_count}
- Enums: {len(context.get('data_types', {}).get('enums', []))}
"""

        if warnings:
            summary += "\n**Analysis Warnings:**\n"
            for warning in warnings:
                summary += f"{warning}\n"

        # Surface incremental / partial-run stats when present
        stats = context.get("analysis_stats", {})
        if (
            stats.get("resumed") or stats.get("partial_results")
            or stats.get("skipped_by_range") or stats.get("redecompiled")
        ):
            summary += "\n**Analysis Run Stats:**\n"
            if stats.get("resumed"):
                summary += (
                    f"- Resumed from prior cache: "
                    f"{stats.get('resumed_from_count', 0)} functions preserved\n"
                )
            summary += f"- Functions processed this run: {stats.get('functions_analyzed', 0)}\n"
            if stats.get("redecompiled"):
                summary += (
                    f"- Re-decompiled (pseudocode added to existing entries): "
                    f"{stats['redecompiled']}\n"
                )
            if stats.get("skipped_by_resume"):
                summary += f"- Skipped (already complete in cache): {stats['skipped_by_resume']}\n"
            if stats.get("skipped_by_range"):
                summary += f"- Skipped (outside address range): {stats['skipped_by_range']}\n"
            if stats.get("partial_results"):
                summary += (
                    "- ⚠️  Partial results -- hit max_functions or wall-clock budget. "
                    "Re-run with `incremental=True` to extend coverage.\n"
                )

        summary += """
Analysis cached for fast subsequent queries.
Use other tools like get_functions, get_imports, decompile_function to explore the binary.
"""
        return summary

    except UserFacingError as e:
        # Return safe error with reference ID
        return str(e)
    except (PathTraversalError, FileSizeError) as e:
        # Security errors - return safe message
        return safe_error_message("Invalid binary file or path", e)
    except GhidraAnalysisError as e:
        # Ghidra itself failed (subprocess error or timeout). The diagnostic
        # is curated from Ghidra's own stdout/stderr -- surface it so users
        # can self-remediate (poisoned OSGi cache, JDK mismatch, OOM, etc.)
        # instead of getting an opaque reference ID.
        logger.error(f"analyze_binary -- Ghidra failure: {e}")
        msg = f"Error: {e}"
        if e.diagnostic:
            msg += f"\n\nGhidra diagnostic:\n{e.diagnostic}"
            msg += (
                "\n\nIf you see UnsupportedClassVersionError or similar class-loading"
                " errors, your Ghidra OSGi cache may be stale (e.g. compiled with a"
                " different JDK than the one currently running). Clearing the"
                " compiled-bundles cache and retrying usually resolves this."
            )
        return msg
    except Exception as e:
        # Unexpected error - log internally, return safe message
        logger.exception(f"analyze_binary failed: {e}")
        return safe_error_message("Analysis failed unexpectedly", e)


@app.tool()
@log_to_session
def load_pdb(
    binary_path: str,
    pdb_path: str | None = None,
    symbol_path: str | None = None,
) -> str:
    """
    Apply a Windows PDB to an analyzed binary.

    Stages the PDB next to the binary (Ghidra's PdbUniversalAnalyzer
    expects ``<binary-stem>.pdb`` adjacency), invalidates any existing
    cache, and re-runs analysis so symbolic function names propagate.

    When ``pdb_path`` is omitted (or set to ``"auto"``), reads the binary's
    CodeView (RSDS) debug record and downloads the matching PDB from the
    Microsoft public symbol server, caching it under
    ``~/.binary_mcp_cache/symbols/``.

    Args:
        binary_path: Path to the binary
        pdb_path: Path to the PDB file, or None / "auto" to fetch from
                  a configured symbol server.
        symbol_path: Optional Windows-style ``_NT_SYMBOL_PATH``
                  (e.g. ``"srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"``).
                  Falls back to the ``BINARY_MCP_SYMBOL_PATH`` /
                  ``_NT_SYMBOL_PATH`` env vars, then to the public
                  Microsoft server. Multiple servers can be chained
                  with ``;``.

    Returns:
        Summary comparing pre/post symbolic-function counts.
    """
    try:
        if pdb_path in (None, "", "auto"):
            from src.utils.pdb_fetcher import fetch_pdb
            try:
                fetched = fetch_pdb(binary_path, symbol_path=symbol_path)
            except ValueError as e:
                return f"Cannot auto-fetch PDB: {e}"
            except RuntimeError as e:
                return f"Symbol server fetch failed: {e}"
            pdb_path = str(fetched)

        # Capture pre-state for before/after comparison
        pre_cached = cache.get_cached(binary_path)
        pre_named = 0
        if pre_cached:
            for f in pre_cached.get("functions", []):
                name = f.get("name", "") or ""
                if name and not name.startswith("FUN_") and not f.get("is_thunk"):
                    pre_named += 1
            cache.invalidate(binary_path)

        context = get_analysis_context(
            binary_path,
            force_reanalyze=True,
            pdb_path=pdb_path,
        )

        post_functions = context.get("functions", [])
        post_named = sum(
            1 for f in post_functions
            if (f.get("name") or "") and not (f.get("name") or "").startswith("FUN_")
            and not f.get("is_thunk")
        )

        lines = [
            f"**PDB applied to {Path(binary_path).name}**",
            f"- PDB: {pdb_path}",
            f"- Functions with symbolic names before: {pre_named}",
            f"- Functions with symbolic names after: {post_named}",
            f"- Gain: +{post_named - pre_named}",
        ]
        if post_named <= pre_named:
            lines.append(
                "\n⚠️  No gain detected. The PDB may not match this binary, "
                "or Ghidra's PdbUniversalAnalyzer did not run. Check the "
                "debug log in the cache directory."
            )
        return "\n".join(lines)

    except FileNotFoundError as e:
        return f"PDB not found: {e}"
    except (PathTraversalError, FileSizeError) as e:
        return safe_error_message("Invalid binary or PDB path", e)
    except Exception as e:
        logger.exception(f"load_pdb failed: {e}")
        return safe_error_message("Failed to apply PDB", e)


@app.tool()
@log_to_session
def get_functions(
    binary_path: str,
    filter_name: str | None = None,
    exclude_external: bool = True,
    limit: int = 100
) -> str:
    """
    List all identified functions in the binary.

    Args:
        binary_path: Path to analyzed binary
        filter_name: Filter functions by name pattern (regex supported)
        exclude_external: Exclude external/thunk functions (default: True)
        limit: Maximum number of functions to return (default: 100)

    Returns:
        Formatted list of functions with addresses and signatures
    """
    try:
        # Validate inputs (SECURITY FIX)
        limit = validate_numeric_range(limit, 1, 10000, "limit")

        context = get_analysis_context(binary_path)
        functions = context.get("functions", [])

        # Apply filters
        if exclude_external:
            functions = [f for f in functions if not f.get('is_external', False)]

        if filter_name:
            # Use safe regex compilation to prevent ReDoS (SECURITY FIX)
            pattern = safe_regex_compile(filter_name, max_length=200)
            functions = [f for f in functions if pattern.search(f.get('name', ''))]

        # Limit results
        total = len(functions)
        functions = functions[:limit]

        # Format output
        result = f"**Functions: {total} total ({len(functions)} shown)**\n\n"

        for func in functions:
            name = func.get('name', 'Unknown')
            addr = func.get('address', 'Unknown')
            sig = func.get('signature', 'Unknown')
            is_thunk = ' [THUNK]' if func.get('is_thunk') else ''

            result += f"- **{name}**{is_thunk}\n"
            result += f"  - Address: `{addr}`\n"
            result += f"  - Signature: `{sig}`\n"
            result += f"  - Parameters: {len(func.get('parameters', []))}\n"
            result += f"  - Local Variables: {len(func.get('local_variables', []))}\n"
            result += f"  - Calls: {len(func.get('called_functions', []))}\n\n"

        if total > limit:
            result += f"\n*Showing {limit} of {total} functions. Use filter_name or increase limit to see more.*"

        return result

    except Exception as e:
        logger.error(f"get_functions failed: {e}")
        return f"Error: {e}"


@app.tool()
@log_to_session
def get_imports(
    binary_path: str,
    filter_library: str | None = None,
    filter_function: str | None = None
) -> str:
    """
    Extract imported functions and libraries.

    Args:
        binary_path: Path to analyzed binary
        filter_library: Filter by library name (regex supported)
        filter_function: Filter by function name (regex supported)

    Returns:
        Formatted list of imports grouped by library
    """
    try:
        context = get_analysis_context(binary_path)
        imports = context.get("imports", [])

        # Apply filters (using safe_regex_compile to prevent ReDoS)
        if filter_library:
            try:
                pattern = safe_regex_compile(filter_library, max_length=200)
                imports = [i for i in imports if pattern.search(i.get('library', ''))]
            except ValueError as e:
                return f"Error: Invalid filter_library pattern: {e}"

        if filter_function:
            try:
                pattern = safe_regex_compile(filter_function, max_length=200)
                imports = [i for i in imports if pattern.search(i.get('name', ''))]
            except ValueError as e:
                return f"Error: Invalid filter_function pattern: {e}"

        # Group by library
        by_library = {}
        for imp in imports:
            lib = imp.get('library', 'Unknown')
            if lib not in by_library:
                by_library[lib] = []
            by_library[lib].append(imp)

        # Format output
        result = f"**Imports: {len(imports)} total from {len(by_library)} libraries**\n\n"

        for lib, funcs in sorted(by_library.items()):
            result += f"### {lib} ({len(funcs)} functions)\n\n"
            for func in sorted(funcs, key=lambda x: x.get('name', '')):
                name = func.get('name', 'Unknown')
                addr = func.get('address', 'N/A')
                result += f"- `{name}` @ {addr}\n"
            result += "\n"

        return result

    except Exception as e:
        logger.error(f"get_imports failed: {e}")
        return f"Error: {e}"


@app.tool()
@log_to_session
def get_strings(
    binary_path: str,
    min_length: int = 4,
    filter_pattern: str | None = None,
    limit: int = 100
) -> str:
    """
    Extract all strings from the binary with cross-references.

    Args:
        binary_path: Path to analyzed binary
        min_length: Minimum string length to include (default: 4)
        filter_pattern: Filter strings by regex pattern
        limit: Maximum number of strings to return (default: 100)

    Returns:
        Formatted list of strings with addresses and xrefs
    """
    try:
        # Validate inputs (SECURITY FIX)
        min_length = validate_numeric_range(min_length, 1, 1000, "min_length")
        limit = validate_numeric_range(limit, 1, 10000, "limit")

        context = get_analysis_context(binary_path)
        strings = context.get("strings", [])

        # Apply filters
        strings = [s for s in strings if s.get('length', 0) >= min_length]

        if filter_pattern:
            # Use safe regex compilation to prevent ReDoS (SECURITY FIX)
            pattern = safe_regex_compile(filter_pattern, max_length=200)
            strings = [s for s in strings if pattern.search(s.get('value', ''))]

        # Limit results
        total = len(strings)
        strings = strings[:limit]

        # Format output
        result = f"**Strings: {total} total ({len(strings)} shown)**\n\n"

        for string in strings:
            value = string.get('value', '').replace('\n', '\\n').replace('\r', '\\r')
            addr = string.get('address', 'Unknown')
            length = string.get('length', 0)
            xrefs = string.get('xrefs', [])

            result += f"**[{addr}]** `{value[:100]}`\n"
            if len(value) > 100:
                result += f"  *(truncated, total length: {length})*\n"

            if xrefs:
                result += f"  Referenced from: {len(xrefs)} locations\n"
                for xref in xrefs[:5]:  # Show first 5 xrefs
                    result += f"    - {xref.get('from')} ({xref.get('type')})\n"
                if len(xrefs) > 5:
                    result += f"    - ...and {len(xrefs) - 5} more\n"
            result += "\n"

        if total > limit:
            result += f"\n*Showing {limit} of {total} strings. Use filter_pattern or increase limit to see more.*"

        return result

    except Exception as e:
        logger.error(f"get_strings failed: {e}")
        return f"Error: {e}"


def _normalize_xref_addr(raw: str | None) -> str:
    """Normalize an address for xref comparison: lowercase, no 0x, no leading zeros."""
    if not raw:
        return ""
    return str(raw).lower().replace("0x", "").lstrip("0") or "0"


def _resolve_function_note_key(
    context: dict, address: str
) -> tuple[dict | None, str | None]:
    """Resolve an address to ``(function_dict, function_key)``.

    The returned key is the function's symbolic name when its
    ``name_source`` is anything other than ``"DEFAULT"``, and
    ``"rva:0xHEX"`` (computed against ``metadata.image_base``) otherwise
    -- the same scheme :class:`ProjectCache` overlay uses, so notes
    written under one rebuild reattach correctly after another.

    Falls back to whichever key form is computable when only one is
    available. Returns ``(None, None)`` if no function in the cache
    contains the supplied address.
    """
    if not address:
        return None, None
    target_norm = _normalize_xref_addr(address)
    functions = context.get("functions") or []
    target_fn: dict | None = None
    for fn in functions:
        if _normalize_xref_addr(fn.get("address")) == target_norm:
            target_fn = fn
            break
    if target_fn is None:
        return None, None

    name = target_fn.get("name") or ""
    name_source = target_fn.get("name_source") or ""
    if name and name_source and name_source != "DEFAULT":
        return target_fn, name

    metadata = context.get("metadata") or {}
    raw_base = metadata.get("image_base") or ""
    try:
        image_base_int = int(str(raw_base).lower().replace("0x", ""), 16)
    except (ValueError, TypeError):
        # No usable image base and no symbolic name -- best effort: use
        # the function's own address. This is only a fallback for
        # synthetic test fixtures; real binaries always carry an
        # image_base in metadata.
        return target_fn, name or target_fn.get("address") or None

    try:
        addr_int = int(
            str(target_fn.get("address") or "").lower().replace("0x", ""), 16
        )
    except (ValueError, TypeError):
        return target_fn, name or target_fn.get("address") or None

    rva = addr_int - image_base_int
    if rva < 0:
        return target_fn, name or target_fn.get("address") or None
    return target_fn, f"rva:0x{rva:x}"


@app.tool()
@log_to_session
def get_xrefs(
    binary_path: str,
    address: str | None = None,
    function_name: str | None = None,
    direction: str = "to",
    limit: int = 200,
) -> str:
    """
    Get cross-references for a function or arbitrary address.

    Derives xrefs from the cached Ghidra context:
      * Function-to-function calls (inverts ``called_functions`` for
        ``direction="to"``, uses the function's own callee list for
        ``direction="from"``).
      * String xrefs (existing per-string ``xrefs`` list).
      * Pseudocode-mention scan as a last resort, surfacing any function
        whose decompiled body references the target address literal.

    Args:
        binary_path: Path to analyzed binary
        address: Hex address to find xrefs for (e.g. "0x401000")
        function_name: Convenience alternative to address - resolves to the
            function's entry point
        direction: "to" (references inbound) or "from" (outbound)
        limit: Max xref rows to list (default 200)

    Returns:
        Structured listing grouped by xref source, or a clear "no xrefs"
        message (never "coming soon").
    """
    try:
        context = get_analysis_context(binary_path)
        functions = context.get("functions", [])

        if function_name:
            function = next(
                (f for f in functions if f.get("name") == function_name), None
            )
            if not function:
                return f"Error: Function '{function_name}' not found"
            address = function.get("address")

        if not address:
            return "Error: Must provide either address or function_name"

        if direction not in ("to", "from"):
            return "Error: direction must be 'to' or 'from'"

        target_norm = _normalize_xref_addr(address)
        target_fn = next(
            (f for f in functions if _normalize_xref_addr(f.get("address")) == target_norm),
            None,
        )

        function_xrefs: list[dict] = []
        string_xrefs: list[dict] = []
        pseudocode_xrefs: list[dict] = []
        indirect_xrefs: list[dict] = []
        vtable_hits: list[dict] = []

        # --- function-to-function xrefs ---------------------------------
        if direction == "to":
            # Prefer the precomputed reverse index (populated by
            # core_analysis.py since Wave 1A): keys are normalized callee
            # addresses, values are lists of caller records carrying the
            # precise call-site PC. Falls back to the legacy linear scan
            # over called_functions for caches built before the index
            # existed.
            xrefs_idx = context.get("xrefs_to_function")
            if isinstance(xrefs_idx, dict):
                for r in xrefs_idx.get(target_norm) or []:
                    function_xrefs.append({
                        "from": r.get("from_func_addr"),
                        "from_name": r.get("from_func_name"),
                        "to": address,
                        "type": "CALL",
                        "call_site": r.get("from_call_site"),
                    })
            else:
                # Legacy cache (no reverse index): scan every function's
                # called_functions list. Lacks call-site precision.
                for caller in functions:
                    for call in caller.get("called_functions") or []:
                        if _normalize_xref_addr(call.get("address")) == target_norm:
                            function_xrefs.append({
                                "from": caller.get("address"),
                                "from_name": caller.get("name"),
                                "to": address,
                                "type": "CALL",
                            })
                            break
        else:  # from
            if target_fn:
                for call in target_fn.get("called_functions") or []:
                    function_xrefs.append({
                        "from": target_fn.get("address"),
                        "from_name": target_fn.get("name"),
                        "to": call.get("address"),
                        "to_name": call.get("name"),
                        "type": "CALL",
                    })

        # --- indirect-call candidates (Wave 2) -------------------------
        # Surfaces vtable slots and indirect-call sites whose static
        # ``loaded_from`` immediate resolves to the target. Indirect
        # calls have no direct caller in the call graph, so this block
        # appears alongside direct callers (not only when direct is
        # empty) -- the LLM should see all evidence.
        if direction == "to":
            iidx = context.get("xrefs_to_function_indirect")
            if isinstance(iidx, dict):
                for r in iidx.get(target_norm) or []:
                    indirect_xrefs.append({
                        "from": r.get("from_func_addr"),
                        "from_name": r.get("from_func_name"),
                        "to": address,
                        "type": "INDIRECT_CALL",
                        "call_site": r.get("from_call_site"),
                        "operand": r.get("operand"),
                    })

            for vt in context.get("vtables") or []:
                for tgt in vt.get("targets") or []:
                    if (
                        _normalize_xref_addr(tgt.get("address"))
                        == target_norm
                    ):
                        vtable_hits.append({
                            "table_address": vt.get("address"),
                            "section": vt.get("section"),
                            "slot": tgt.get("slot"),
                            "tags": vt.get("tags") or [],
                        })

        # --- string xrefs -----------------------------------------------
        for s in context.get("strings", []):
            s_addr_norm = _normalize_xref_addr(s.get("address"))
            if direction == "to":
                # Caller asked "what xrefs point AT <address>?" -- for strings
                # that means: is <address> the location of a string referenced
                # from this function's body?
                if s_addr_norm == target_norm:
                    for xref in s.get("xrefs") or []:
                        string_xrefs.append({
                            "from": xref.get("from"),
                            "to": s.get("address"),
                            "type": f"DATA/{xref.get('type', 'REF')}",
                            "value": (s.get("value") or "")[:80],
                        })
            else:  # from
                # Caller asked "what xrefs originate AT/inside this address?"
                for xref in s.get("xrefs") or []:
                    if _normalize_xref_addr(xref.get("from")) == target_norm:
                        string_xrefs.append({
                            "from": xref.get("from"),
                            "to": s.get("address"),
                            "type": f"DATA/{xref.get('type', 'REF')}",
                            "value": (s.get("value") or "")[:80],
                        })

        # --- pseudocode mention scan (last resort, direction=to only) ---
        if direction == "to" and not function_xrefs and not string_xrefs:
            needle_forms = {f"0x{target_norm}", f"0x{target_norm.zfill(8)}"}
            for caller in functions:
                pseudo = caller.get("pseudocode") or ""
                if any(n in pseudo for n in needle_forms):
                    pseudocode_xrefs.append({
                        "from": caller.get("address"),
                        "from_name": caller.get("name"),
                        "type": "PSEUDOCODE_MENTION",
                    })

        total = (
            len(function_xrefs)
            + len(string_xrefs)
            + len(pseudocode_xrefs)
            + len(indirect_xrefs)
            + len(vtable_hits)
        )
        if total == 0:
            target_label = (
                f"{target_fn.get('name')} @ {address}" if target_fn else address
            )
            return (
                f"**Cross-references {direction} {target_label}:**\n\n"
                f"*No xrefs found. This function may only be reached via "
                f"indirect calls (vtable / function pointer) which are not "
                f"resolved in the current extraction.*"
            )

        # Format output grouped by type
        target_label = f"{target_fn.get('name')} @ {address}" if target_fn else address
        lines = [f"**Cross-references {direction} {target_label}:**", ""]
        lines.append(f"Total: {total}")
        lines.append("")

        shown = 0
        if function_xrefs:
            lines.append(f"### Function calls ({len(function_xrefs)})")
            for x in function_xrefs:
                if shown >= limit:
                    break
                if direction == "to":
                    call_site = x.get("call_site")
                    site_suffix = f" (call site: {call_site})" if call_site else ""
                    lines.append(
                        f"- {x['from_name']} @ {x['from']}{site_suffix}  [{x['type']}]"
                    )
                else:
                    to_name = x.get("to_name") or "?"
                    lines.append(
                        f"- {x['from_name']} @ {x['from']}  ->  "
                        f"{to_name} @ {x['to']}  [{x['type']}]"
                    )
                shown += 1
            lines.append("")
            if direction == "to":
                lines.append(
                    "*Note: indirect calls (vtable / function pointer / "
                    "`CALL [reg+N]`) are not represented in this index; "
                    "results may be incomplete.*"
                )
                lines.append("")

        if string_xrefs and shown < limit:
            lines.append(f"### Data / string refs ({len(string_xrefs)})")
            for x in string_xrefs:
                if shown >= limit:
                    break
                lines.append(
                    f"- {x['from']}  ->  {x['to']}  [{x['type']}]  "
                    f"`{x['value']}`"
                )
                shown += 1
            lines.append("")

        if pseudocode_xrefs and shown < limit:
            lines.append(
                f"### Pseudocode mentions ({len(pseudocode_xrefs)})"
            )
            lines.append(
                "_Function bodies that textually mention this address "
                "(may include indirect-call resolutions)._"
            )
            for x in pseudocode_xrefs:
                if shown >= limit:
                    break
                lines.append(
                    f"- {x['from_name']} @ {x['from']}  [{x['type']}]"
                )
                shown += 1
            lines.append("")

        # --- indirect candidates (Wave 2) ------------------------------
        indirect_total = len(indirect_xrefs) + len(vtable_hits)
        if indirect_total and shown < limit:
            lines.append(
                f"### Indirect call candidates ({indirect_total})"
            )
            lines.append(
                "_Inferred from static MOV/LEA loads and `.rdata`/`.data` "
                "vtable scans. Run `find_vtables` to populate or refresh "
                "the vtable hit list._"
            )
            for x in indirect_xrefs:
                if shown >= limit:
                    break
                operand = x.get("operand") or ""
                operand_text = f", operand: `{operand}`" if operand else ""
                call_site = x.get("call_site") or ""
                site_text = (
                    f" (call site: {call_site}{operand_text})"
                    if call_site
                    else ""
                )
                lines.append(
                    f"- {x['from_name']} @ {x['from']}{site_text}  "
                    f"[{x['type']}]"
                )
                shown += 1
            for vt in vtable_hits:
                if shown >= limit:
                    break
                tag_text = (
                    f" [{', '.join(vt['tags'])}]" if vt.get("tags") else ""
                )
                lines.append(
                    f"- vtable @ {vt['table_address']} ({vt['section']}) "
                    f"slot {vt['slot']}{tag_text}  [VTABLE]"
                )
                shown += 1

        if total > limit:
            lines.append("")
            lines.append(
                f"*Showing {limit} of {total}. Increase `limit` to see more.*"
            )

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"get_xrefs failed: {e}")
        return f"Error: {e}"


@app.tool()
@log_to_session
def decompile_function(
    binary_path: str,
    function_name: str
) -> str:
    """
    Decompile a function to C-like pseudocode.

    If the cache for ``binary_path`` was built with ``skip_decompile=True``
    (or ``analysis_depth="shallow"``/``"structural"``), pseudocode for the
    requested function will be missing. In that case this tool runs a
    targeted incremental decompile for the single function at its known
    address (``max_functions=1``) and merges the result back into the
    cache, so the typical workflow of "fast structural pass → LLM picks
    targets → decompile on demand" just works without an explicit
    re-analyze step.

    Args:
        binary_path: Path to analyzed binary
        function_name: Name of the function to decompile

    Returns:
        Decompiled C pseudocode
    """
    try:
        # Peek at the existing cache first. If it was produced shallow/structural,
        # do NOT trigger get_analysis_context's depth-upgrade path -- that would
        # re-analyze the whole binary. Instead we'll do a targeted single-function
        # decompile below.
        peek = cache.get_cached(binary_path)
        cached_depth = (
            peek.get("metadata", {}).get("analysis_depth", "full") if peek else "full"
        )

        if peek and cached_depth in ("shallow", "structural"):
            context = peek
        else:
            context = get_analysis_context(binary_path)
        functions = context.get("functions", [])

        # Find function by name
        function = next((f for f in functions if f.get('name') == function_name), None)

        if not function:
            # Try fuzzy matching
            matches = [f for f in functions if function_name.lower() in f.get('name', '').lower()]
            if matches:
                suggestions = ", ".join([f.get('name', '') for f in matches[:5]])
                return f"Error: Function '{function_name}' not found. Did you mean: {suggestions}?"
            return f"Error: Function '{function_name}' not found"

        pseudocode = function.get('pseudocode')

        if not pseudocode:
            if function.get('is_thunk'):
                return f"Function '{function_name}' is a thunk and cannot be decompiled."
            if function.get('is_external'):
                return f"Function '{function_name}' is external and cannot be decompiled."

            # Cache was produced shallow/structural -- pseudocode was opted out,
            # not a decompile failure. Run a targeted incremental decompile for
            # just this function and merge the result back into the cache so
            # subsequent calls hit the warm path.
            fn_address = function.get("address")
            if cached_depth in ("shallow", "structural") and fn_address:
                logger.info(
                    "decompile_function: pseudocode missing for %s on %s cache -- "
                    "running targeted incremental decompile at %s",
                    function_name, cached_depth, fn_address,
                )
                try:
                    context = get_analysis_context(
                        binary_path,
                        incremental=True,
                        start_address=fn_address,
                        max_functions=1,
                    )
                    functions = context.get("functions", [])
                    function = next(
                        (f for f in functions if f.get('name') == function_name),
                        function,
                    )
                    pseudocode = function.get("pseudocode")
                except Exception as e:
                    logger.warning(f"On-demand decompile failed for {function_name}: {e}")

            if not pseudocode:
                return (
                    f"Function '{function_name}' could not be decompiled "
                    f"(decompilation may have failed)."
                )

        # Format output
        result = f"**Decompiled: {function_name}**\n\n"
        result += f"Address: `{function.get('address')}`\n"
        result += f"Signature: `{function.get('signature')}`\n\n"
        result += "```c\n"
        result += pseudocode
        result += "\n```\n"

        return result

    except Exception as e:
        logger.error(f"decompile_function failed: {e}")
        return f"Error: {e}"


# --- Phase 2: Enhanced Analysis Tools (P1 - Important) ---

@app.tool()
@log_to_session
def get_call_graph(
    binary_path: str,
    function_name: str,
    depth: int = 2,
    direction: str = "callees"
) -> str:
    """
    Generate function call graph.

    Args:
        binary_path: Path to analyzed binary
        function_name: Starting function name
        depth: How many levels to traverse (default: 2)
        direction: "callees" (functions called) or "callers" (functions calling this)

    Returns:
        Call graph visualization
    """
    try:
        context = get_analysis_context(binary_path)
        functions = context.get("functions", [])

        # Find starting function
        start_func = next((f for f in functions if f.get('name') == function_name), None)
        if not start_func:
            return f"Error: Function '{function_name}' not found"

        # Build call graph
        def build_graph(func_name, current_depth, visited=None):
            if visited is None:
                visited = set()
            if current_depth > depth or func_name in visited:
                return ""

            visited.add(func_name)
            func = next((f for f in functions if f.get('name') == func_name), None)
            if not func:
                return ""

            indent = "  " * current_depth
            result = f"{indent}- {func_name} @ {func.get('address')}\n"

            if direction == "callees":
                called = func.get('called_functions', [])
                for called_func in called:
                    result += build_graph(called_func.get('name'), current_depth + 1, visited)

            return result

        result = f"**Call Graph for {function_name}** (depth={depth}, direction={direction})\n\n"
        result += build_graph(function_name, 0)

        return result

    except Exception as e:
        logger.error(f"get_call_graph failed: {e}")
        return f"Error: {e}"


@app.tool()
@log_to_session
def find_api_calls(
    binary_path: str,
    category: str | None = None,
    suspicious_only: bool = False
) -> str:
    """
    Find Windows API calls categorized by behavior.

    Args:
        binary_path: Path to analyzed binary
        category: Filter by category (process, memory, file, network, registry, crypto, anti-debug)
        suspicious_only: Only return high-risk APIs (default: False)

    Returns:
        Categorized API calls with severity ratings
    """
    try:
        context = get_analysis_context(binary_path)
        imports = context.get("imports", [])
        functions = context.get("functions", [])

        # Analyze API calls
        api_calls = []

        for imp in imports:
            api_name = imp.get('name', '')
            api_info = api_patterns.get_api_info(api_name)

            if api_info:
                if suspicious_only and api_info['severity'] not in ['high', 'critical']:
                    continue

                if category and api_info['category'] != category:
                    continue

                # Find where this API is called
                call_sites = []
                for func in functions:
                    for called in func.get('called_functions', []):
                        if called.get('name') == api_name:
                            call_sites.append(func.get('name'))

                api_calls.append({
                    'name': api_name,
                    'category': api_info['category'],
                    'severity': api_info['severity'],
                    'description': api_info['description'],
                    'call_sites': call_sites
                })

        # Format output
        result = f"**API Calls Analysis: {len(api_calls)} APIs found**\n\n"

        # Group by category
        by_category = {}
        for api in api_calls:
            cat = api['category']
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(api)

        for cat, apis in sorted(by_category.items()):
            result += f"### {cat.upper()} ({len(apis)} APIs)\n\n"

            for api in sorted(apis, key=lambda x: x['severity'], reverse=True):
                severity_icon = {
                    'critical': '[CRITICAL]',
                    'high': '[HIGH]',
                    'medium': '[MEDIUM]',
                    'low': '[LOW]'
                }.get(api['severity'], '[INFO]')

                result += f"- {severity_icon} **{api['name']}** [{api['severity'].upper()}]\n"
                result += f"  {api['description']}\n"
                if api['call_sites']:
                    result += f"  Called from: {', '.join(api['call_sites'][:5])}\n"
                result += "\n"

        return result

    except Exception as e:
        logger.error(f"find_api_calls failed: {e}")
        return f"Error: {e}"


@app.tool()
@log_to_session
def get_memory_map(
    binary_path: str
) -> str:
    """
    Extract memory layout and sections with entropy analysis.

    Args:
        binary_path: Path to analyzed binary

    Returns:
        Memory map with section details and entropy
    """
    try:
        context = get_analysis_context(binary_path)
        memory_blocks = context.get("memory_map", [])

        result = f"**Memory Map: {len(memory_blocks)} sections**\n\n"

        for block in memory_blocks:
            name = block.get('name', 'Unknown')
            start = block.get('start', 'Unknown')
            end = block.get('end', 'Unknown')
            size = block.get('size', 0)
            perms = ""
            if block.get('read'):
                perms += "R"
            if block.get('write'):
                perms += "W"
            if block.get('execute'):
                perms += "X"

            initialized = "YES" if block.get('initialized') else "NO"

            result += f"### {name}\n"
            result += f"- Range: `{start}` - `{end}` ({size} bytes)\n"
            result += f"- Permissions: `{perms}`\n"
            result += f"- Initialized: {initialized}\n"
            if block.get('comment'):
                result += f"- Comment: {block.get('comment')}\n"
            result += "\n"

        return result

    except Exception as e:
        logger.error(f"get_memory_map failed: {e}")
        return f"Error: {e}"


@app.tool()
@log_to_session
def extract_metadata(
    binary_path: str
) -> str:
    """
    Get binary metadata and headers (PE/ELF/Mach-O).

    Args:
        binary_path: Path to analyzed binary

    Returns:
        Comprehensive metadata including format-specific headers
    """
    try:
        context = get_analysis_context(binary_path)
        metadata = context.get("metadata", {})

        result = "**Binary Metadata**\n\n"

        for key, value in sorted(metadata.items()):
            formatted_key = key.replace('_', ' ').title()
            result += f"- **{formatted_key}:** `{value}`\n"

        return result

    except Exception as e:
        logger.error(f"extract_metadata failed: {e}")
        return f"Error: {e}"


def _parse_byte_pattern(pattern: str) -> tuple[bytes, bytes] | None:
    """
    Parse a hex byte pattern, optionally with '?' or '??' wildcards.

    Accepts forms like:
      - "4883EC20"
      - "48 83 EC 20"
      - "48 83 ?? 20"  (single-byte wildcard)
      - "48 83 EC ??"

    Returns (needle_bytes, mask_bytes) where mask byte is 0xFF for fixed
    bytes and 0x00 for wildcards. Returns None if the pattern is invalid.
    """
    cleaned = pattern.replace(" ", "").replace("\t", "").lower()
    if len(cleaned) % 2 != 0 or len(cleaned) == 0:
        return None

    needle = bytearray()
    mask = bytearray()
    for i in range(0, len(cleaned), 2):
        chunk = cleaned[i:i + 2]
        if chunk in ("??", "?."):
            needle.append(0)
            mask.append(0)
            continue
        try:
            needle.append(int(chunk, 16))
            mask.append(0xFF)
        except ValueError:
            return None
    return bytes(needle), bytes(mask)


def _scan_with_mask(data: bytes, needle: bytes, mask: bytes, max_results: int) -> list[int]:
    """Linear masked scan over a bytes buffer; returns list of file offsets."""
    if not needle:
        return []
    has_wildcards = b"\x00" in mask and any(m != 0xFF for m in mask)
    if not has_wildcards:
        offsets: list[int] = []
        start = 0
        while len(offsets) < max_results:
            idx = data.find(needle, start)
            if idx < 0:
                break
            offsets.append(idx)
            start = idx + 1
        return offsets

    offsets = []
    n = len(needle)
    end = len(data) - n
    i = 0
    while i <= end and len(offsets) < max_results:
        match = True
        for j in range(n):
            if mask[j] and data[i + j] != needle[j]:
                match = False
                break
        if match:
            offsets.append(i)
        i += 1
    return offsets


@app.tool()
@log_to_session
def search_bytes(
    binary_path: str,
    pattern: str,
    max_results: int = 50,
) -> str:
    """
    Search for a byte/instruction pattern in the binary.

    Reads the binary directly and reports each match's virtual address.
    When an address falls inside a known function, the function name and
    offset-into-function are surfaced so hits land in context.

    Args:
        binary_path: Path to analyzed binary
        pattern: Hex byte pattern. Spaces optional; '??' (or '?.') marks a
            single-byte wildcard. Examples:
            - "4883EC20"           → exact 4 bytes
            - "48 83 EC 20"        → same, with spaces
            - "48 83 ?? 20"        → wildcard third byte
        max_results: Maximum number of results (default 50, max 1000)

    Returns:
        Listing of matches with VA, function context, and file offset.
    """
    try:
        from src.utils.binary_reader import BinaryReader

        max_results = validate_numeric_range(max_results, 1, 1000, "max_results")

        parsed = _parse_byte_pattern(pattern)
        if parsed is None:
            return (
                f"Error: invalid hex pattern '{pattern}'. Expected pairs of "
                f"hex digits, optionally separated by spaces, with '??' for "
                f"wildcards. Length must be a multiple of 2."
            )
        needle, mask = parsed

        # Don't trigger a Ghidra run just to scan bytes -- if cache is
        # missing, fall back to context-free hits.
        cached = cache.get_cached(binary_path)
        functions = cached.get("functions", []) if cached else []

        with BinaryReader(binary_path) as reader:
            data = reader.read_full()
            offsets = _scan_with_mask(data, needle, mask, max_results + 1)
            hits: list[dict] = []
            for off in offsets:
                va = reader.file_offset_to_va(off)
                hits.append({"file_offset": off, "va": va})

        if functions:
            ranges: list[tuple[int, int, str]] = []
            for f in functions:
                try:
                    start = int(str(f.get("address") or "0").replace("0x", ""), 16)
                except ValueError:
                    continue
                end = start
                for bb in f.get("basic_blocks") or []:
                    try:
                        bb_end = int(str(bb.get("end") or "0").replace("0x", ""), 16)
                        if bb_end > end:
                            end = bb_end
                    except ValueError:
                        continue
                if end <= start:
                    end = start + max(1, f.get("size") or 0)
                ranges.append((start, end, f.get("name") or "?"))
            ranges.sort()

            def _resolve(va: int | None) -> tuple[str, int] | None:
                if va is None:
                    return None
                for s, e, name in ranges:
                    if s <= va <= e:
                        return name, va - s
                return None

            for h in hits:
                ctx = _resolve(h["va"])
                if ctx:
                    h["function"] = ctx[0]
                    h["offset_in_function"] = ctx[1]

        total = len(hits)
        truncated = total > max_results
        hits = hits[:max_results]

        lines = [f"**Byte Pattern Search: `{pattern}`**", ""]
        if total == 0:
            lines.append("No matches found.")
            return "\n".join(lines)

        lines.append(
            f"Found {total} match(es)"
            + (f" (showing first {max_results})" if truncated else "")
        )
        lines.append("")
        for h in hits:
            va_str = f"0x{h['va']:x}" if h["va"] is not None else "(unmapped)"
            line = f"- {va_str}  [file offset 0x{h['file_offset']:x}]"
            if "function" in h:
                line += f"  in `{h['function']}` +0x{h['offset_in_function']:x}"
            lines.append(line)

        return "\n".join(lines)

    except FileNotFoundError as e:
        return f"Binary not found: {e}"
    except (PathTraversalError, FileSizeError) as e:
        return safe_error_message("search_bytes", e)
    except Exception as e:
        logger.error(f"search_bytes failed: {e}")
        return f"Error: {e}"


# --- Phase 3: Advanced Tools (P2 - Nice-To-Have) ---

@app.tool()
@log_to_session
def detect_crypto(
    binary_path: str
) -> str:
    """
    Identify cryptographic constants and algorithms.

    Args:
        binary_path: Path to analyzed binary

    Returns:
        List of detected cryptographic patterns
    """
    try:
        context = get_analysis_context(binary_path)

        result = "**Cryptography Detection**\n\n"

        # Search for crypto constants in functions and strings
        detected = crypto_patterns.detect_in_context(context)

        if detected:
            for crypto in detected:
                result += f"- **{crypto['algorithm']}** detected at {crypto['location']}\n"
                result += f"  Confidence: {crypto['confidence']}\n"
                result += f"  Pattern: {crypto['pattern']}\n\n"
        else:
            result += "No known cryptographic constants detected.\n"

        return result

    except Exception as e:
        logger.error(f"detect_crypto failed: {e}")
        return f"Error: {e}"


@app.tool()
@log_to_session
def generate_iocs(
    binary_path: str
) -> str:
    """
    Generate indicators of compromise (IOCs) from analysis.

    Args:
        binary_path: Path to analyzed binary

    Returns:
        IOCs in structured format (IPs, domains, files, registry keys, etc.)
    """
    try:
        context = get_analysis_context(binary_path)
        strings = context.get("strings", [])

        iocs = {
            'ip_addresses': [],
            'domains': [],
            'urls': [],
            'file_paths': [],
            'registry_keys': [],
            'emails': [],
            'crypto_addresses': []
        }

        # Regex patterns for IOC extraction
        patterns = {
            'ip_addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'domains': r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            'urls': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'file_paths': r'[C-Z]:\\[\\\w\s\-\.]+',
            'registry_keys': r'HKEY_[A-Z_]+\\[\\\w\s\-]+',
        }

        # Extract IOCs from strings
        for string in strings:
            value = string.get('value', '')

            for ioc_type, pattern in patterns.items():
                matches = re.findall(pattern, value, re.IGNORECASE)
                for match in matches:
                    if match not in iocs[ioc_type]:
                        iocs[ioc_type].append(match)

        # Format output
        result = "**Indicators of Compromise (IOCs)**\n\n"

        total_iocs = sum(len(v) for v in iocs.values())
        result += f"Total IOCs found: {total_iocs}\n\n"

        for ioc_type, values in iocs.items():
            if values:
                formatted_type = ioc_type.replace('_', ' ').title()
                result += f"### {formatted_type} ({len(values)})\n\n"
                for value in sorted(set(values))[:20]:  # Limit to 20 per type
                    result += f"- `{value}`\n"
                if len(values) > 20:
                    result += f"\n*...and {len(values) - 20} more*\n"
                result += "\n"

        return result

    except Exception as e:
        logger.error(f"generate_iocs failed: {e}")
        return f"Error: {e}"


@app.tool()
def diagnose_setup() -> str:
    """
    Run diagnostic checks on Ghidra installation and environment.

    Returns:
        Diagnostic information about the setup
    """
    try:
        diag = runner.diagnose()

        result = "**Ghidra MCP Server Diagnostics**\n\n"

        result += f"- Platform: {diag['platform']}\n"
        result += f"- Ghidra Path: `{diag['ghidra_path']}`\n"
        result += f"- Ghidra Exists: {'YES' if diag['ghidra_exists'] else 'NO'}\n"
        result += f"- analyzeHeadless: `{diag['analyze_headless']}`\n"
        result += f"- analyzeHeadless Exists: {'YES' if diag['analyze_headless_exists'] else 'NO'}\n"
        result += f"- Java Installed: {'YES' if diag['java_installed'] else 'NO'}\n"

        if diag['java_version']:
            result += f"- Java Version: {diag['java_version']}\n"

        result += f"- Ghidra Version: {diag.get('ghidra_version', 'Unknown')}\n\n"

        # Cache info
        cached_binaries = cache.list_cached()
        result += "**Cache Information:**\n"
        result += f"- Cached Binaries: {len(cached_binaries)}\n"
        result += f"- Cache Directory: `{cache.cache_dir}`\n"
        result += f"- Cache Size: {cache.get_cache_size() / 1024 / 1024:.2f} MB\n\n"

        # Session info
        session_stats = session_manager.get_stats()
        result += "**Analysis Sessions:**\n"
        result += f"- Stored Sessions: {session_stats['total_sessions']}\n"
        result += f"- Storage Size: {session_stats['total_size_mb']:.2f} MB\n"
        result += f"- Storage Directory: `{session_manager.store_dir}`\n"
        if session_stats['active_session']:
            result += f"- Active Session: `{session_stats['active_session'][:8]}...`\n"
        result += "\n"

        if not diag['ghidra_exists']:
            result += "\n**WARNING:** Ghidra not found! Please install Ghidra or set GHIDRA_HOME environment variable.\n"
        elif not diag['java_installed']:
            result += "\n**WARNING:** Java not found! Ghidra requires Java 21+.\n"
        else:
            result += "\n**Setup looks good!** Ready to analyze binaries.\n"

        return result

    except Exception as e:
        logger.error(f"diagnose_setup failed: {e}")
        return f"Error: {e}"


# --- Additional Tools ---

@app.tool()
def check_binary(binary_path: str) -> str:
    """
    Check binary compatibility BEFORE running Ghidra analysis.

    This is a fast pre-analysis check that examines binary headers to detect:
    - Binary format (PE, ELF, Mach-O, .NET, etc.)
    - Architecture and bitness
    - .NET assemblies (which have limited Ghidra support)
    - Packed/protected binaries
    - Potential analysis issues

    Use this tool FIRST when you're unsure about a binary's format or want to
    avoid long analysis times on incompatible files.

    Args:
        binary_path: Path to the binary file to check

    Returns:
        Detailed compatibility report with recommendations

    Example:
        check_binary("C:/samples/unknown.exe")
        -> Returns format detection, compatibility level, and tool recommendations
    """
    try:
        # Validate path exists
        path = Path(binary_path)
        if not path.exists():
            return f"Error: File not found: {binary_path}"
        if not path.is_file():
            return f"Error: Path is not a file: {binary_path}"

        # Run compatibility check
        info = compatibility_checker.check_compatibility(binary_path)
        report = compatibility_checker.format_report(info)

        # Add guidance based on compatibility level
        guidance = "\n**Next Steps:**\n"

        if info.compatibility == CompatibilityLevel.FULL:
            guidance += "- Binary is fully compatible - proceed with `analyze_binary()`\n"
        elif info.compatibility == CompatibilityLevel.PARTIAL:
            guidance += "- Analysis will work with some limitations\n"
            guidance += "- Proceed with `analyze_binary()` but review warnings above\n"
        elif info.compatibility == CompatibilityLevel.LIMITED:
            if info.is_dotnet:
                guidance += "- **RECOMMENDED:** Use dnSpy or ILSpy for .NET analysis\n"
                guidance += "- If you must use Ghidra: `analyze_binary(binary_path, skip_compatibility_check=True)`\n"
            else:
                guidance += "- Consider alternative analysis tools\n"
                guidance += "- To force Ghidra analysis: `analyze_binary(binary_path, skip_compatibility_check=True)`\n"
        elif info.compatibility == CompatibilityLevel.UNSUPPORTED:
            guidance += "- Binary is NOT recommended for Ghidra analysis\n"
            guidance += "- Use specialized tools for this format\n"

        return report + guidance

    except FileNotFoundError as e:
        return f"Error: {e}"
    except Exception as e:
        logger.error(f"check_binary failed: {e}")
        return f"Error checking binary: {e}"


@app.tool()
@log_to_session
def list_data_types(
    binary_path: str,
    type_filter: str = "all"
) -> str:
    """
    List data types (structures and enums) found in the binary.

    Args:
        binary_path: Path to analyzed binary
        type_filter: Filter by type: "all", "structures", or "enums"

    Returns:
        List of data types with details
    """
    try:
        context = get_analysis_context(binary_path)
        data_types = context.get("data_types", {})

        result = "**Data Types**\n\n"

        if type_filter in ["all", "structures"]:
            structures = data_types.get("structures", [])
            result += f"### Structures ({len(structures)})\n\n"

            for struct in structures[:50]:  # Limit to 50
                result += f"- **{struct.get('name')}** ({struct.get('length')} bytes)\n"
                members = struct.get('members', [])
                for member in members[:10]:  # Show first 10 members
                    result += f"  - +0x{member.get('offset'):x}: {member.get('name')} ({member.get('datatype')})\n"
                if len(members) > 10:
                    result += f"  - ...and {len(members) - 10} more members\n"
                result += "\n"

        if type_filter in ["all", "enums"]:
            enums = data_types.get("enums", [])
            result += f"### Enums ({len(enums)})\n\n"

            for enum in enums[:50]:  # Limit to 50
                result += f"- **{enum.get('name')}**\n"
                values = enum.get('values', [])
                for value in values[:10]:  # Show first 10 values
                    result += f"  - {value.get('name')} = {value.get('value')}\n"
                if len(values) > 10:
                    result += f"  - ...and {len(values) - 10} more values\n"
                result += "\n"

        return result

    except Exception as e:
        logger.error(f"list_data_types failed: {e}")
        return f"Error: {e}"


@app.tool()
@log_to_session
def rename_function(
    binary_path: str,
    new_name: str,
    address: str | None = None,
    old_name: str | None = None
) -> str:
    """
    Rename a function in the analysis cache.

    Use this after analyzing a binary to give meaningful names to functions
    once you understand what they do. The rename is stored in the analysis
    cache and will be reflected in subsequent tool calls.

    Args:
        binary_path: Path to the analyzed binary
        new_name: New name for the function (e.g., "decrypt_string", "init_network")
        address: Hex address of the function to rename (e.g., "0x00401000")
        old_name: Current name of the function (e.g., "FUN_00401000")

    Returns:
        Confirmation of the rename with old and new names

    Note:
        You must provide either address or old_name to identify the function.
        If both are provided, address takes precedence.
    """
    try:
        if not address and not old_name:
            return "Error: Must provide either 'address' or 'old_name' to identify the function"

        if not new_name or not new_name.strip():
            return "Error: 'new_name' cannot be empty"

        # Validate new_name is a valid identifier
        new_name = new_name.strip()
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', new_name):
            return f"Error: '{new_name}' is not a valid function name. Use only letters, numbers, and underscores, starting with a letter or underscore."

        # Get the analysis context (from cache)
        context = get_analysis_context(binary_path)
        functions = context.get("functions", [])

        if not functions:
            return "Error: No functions found in analysis. Run analyze_binary first."

        # Find the function to rename
        target_function = None
        target_index = -1

        if address:
            # Normalize address format (handle with/without 0x prefix)
            addr_normalized = address.lower().replace("0x", "")
            for i, func in enumerate(functions):
                func_addr = func.get('address', '').lower().replace("0x", "")
                if func_addr == addr_normalized or func_addr.endswith(addr_normalized):
                    target_function = func
                    target_index = i
                    break
        elif old_name:
            for i, func in enumerate(functions):
                if func.get('name') == old_name:
                    target_function = func
                    target_index = i
                    break

        if not target_function:
            identifier = address if address else old_name
            # Suggest similar functions
            if old_name:
                matches = [f.get('name', '') for f in functions
                          if old_name.lower() in f.get('name', '').lower()][:5]
                if matches:
                    return f"Error: Function '{old_name}' not found. Similar functions: {', '.join(matches)}"
            return f"Error: Function '{identifier}' not found"

        # Check if new name already exists
        existing = next((f for f in functions if f.get('name') == new_name), None)
        if existing and existing != target_function:
            return f"Error: A function named '{new_name}' already exists at {existing.get('address')}"

        # Store old name for confirmation message
        original_name = target_function.get('name', 'unknown')
        func_address = target_function.get('address', 'unknown')

        # Update the function name
        target_function['name'] = new_name

        # Update the signature if it contains the old name
        old_signature = target_function.get('signature', '')
        if original_name in old_signature:
            target_function['signature'] = old_signature.replace(original_name, new_name, 1)

        # Update the pseudocode if it contains the old name (function definition line)
        pseudocode = target_function.get('pseudocode', '')
        if pseudocode and original_name in pseudocode:
            # Only replace in the function definition, not all occurrences
            # This handles the common case of "void FUN_00401000(void)" -> "void decrypt_string(void)"
            lines = pseudocode.split('\n')
            for i, line in enumerate(lines):
                # Look for function definition pattern
                if original_name in line and ('(' in line or '{' in line):
                    lines[i] = line.replace(original_name, new_name, 1)
                    break
            target_function['pseudocode'] = '\n'.join(lines)

        # Update the function in the context
        context['functions'][target_index] = target_function

        # Save the updated context back to cache
        cache.save_cached(binary_path, context)

        logger.info(f"Renamed function '{original_name}' to '{new_name}' at {func_address}")

        result = "**Function Renamed Successfully**\n\n"
        result += f"- **Address:** `{func_address}`\n"
        result += f"- **Old Name:** `{original_name}`\n"
        result += f"- **New Name:** `{new_name}`\n"
        result += f"- **New Signature:** `{target_function.get('signature', 'N/A')}`\n\n"
        result += "*The rename is saved in the analysis cache and will be reflected in all subsequent tool calls.*"

        return result

    except Exception as e:
        logger.error(f"rename_function failed: {e}")
        return f"Error: {e}"


_NOTE_KIND_VALUES = ("plate", "pre", "post")
_NOTE_TEXT_MAX = 4096


def _matching_note_index(
    notes: list[dict], function_key: str, kind: str, addr: str | None
) -> int | None:
    """Return the index of the existing note row matching the
    ``(function_key, kind, addr)`` triple, or ``None`` if no row matches.
    Used so ``add_note`` overwrites in place and ``delete_note`` knows
    which row to drop.
    """
    norm_addr = (addr or "").lower()
    for idx, row in enumerate(notes):
        if not isinstance(row, dict):
            continue
        if row.get("function_key") != function_key:
            continue
        if row.get("kind") != kind:
            continue
        if kind == "plate":
            if not row.get("addr"):
                return idx
        else:
            row_addr = (row.get("addr") or "").lower()
            if row_addr == norm_addr:
                return idx
    return None


@app.tool()
@log_to_session
def add_note(
    binary_path: str,
    address: str,
    note: str,
    kind: str = "plate",
) -> str:
    """
    Attach a free-text annotation to a function or specific instruction.

    Notes are stored in a side-car file alongside the analysis cache and
    survive ``analyze_binary(force_reanalyze=True)`` and ``load_pdb``. Use
    them to record what a function does, what an instruction means, why
    a branch matters -- anything you want carried forward across
    re-analyses.

    Args:
        binary_path: Path to the analyzed binary
        address: Hex address. For ``kind="plate"`` this is the function's
            entry point. For ``kind="pre"`` / ``kind="post"`` this is the
            instruction the comment is pinned to (the function it
            belongs to is resolved automatically).
        note: Free-text annotation (1..4096 chars)
        kind: ``"plate"`` (function-level), ``"pre"`` (above an
            instruction), or ``"post"`` (below an instruction)

    Returns:
        Confirmation including the resolved function_key.
    """
    try:
        if kind not in _NOTE_KIND_VALUES:
            return (
                f"Error: kind must be one of {', '.join(_NOTE_KIND_VALUES)}; "
                f"got '{kind}'"
            )
        if not address:
            return "Error: 'address' is required"
        text = (note or "").strip()
        if not text:
            return "Error: 'note' cannot be empty"
        if len(text) > _NOTE_TEXT_MAX:
            return (
                f"Error: 'note' exceeds the {_NOTE_TEXT_MAX}-char limit "
                f"({len(text)} given)"
            )

        context = get_analysis_context(binary_path)
        target_fn, function_key = _resolve_function_note_key(context, address)
        if target_fn is None or function_key is None:
            return f"Error: No function contains address {address}"

        notes = cache.read_notes(binary_path)
        note_addr = None if kind == "plate" else address
        existing_idx = _matching_note_index(notes, function_key, kind, note_addr)
        new_row = {
            "function_key": function_key,
            "kind": kind,
            "addr": note_addr,
            "text": text,
            "created_at": time.time(),
        }
        if existing_idx is None:
            notes.append(new_row)
            verb = "Added"
        else:
            notes[existing_idx] = new_row
            verb = "Replaced"

        if not cache.write_notes(binary_path, notes):
            return "Error: Failed to persist notes side-car"

        # Re-overlay so cache reads pick up the new note immediately
        # without waiting for the next analysis run.
        try:
            cache.apply_notes_overlay(binary_path, context)
            cache.save_cached(binary_path, context)
        except Exception as e:
            logger.warning(f"add_note overlay refresh failed: {e}")

        result = "**Note Saved**\n\n"
        result += f"- **Action:** {verb}\n"
        result += f"- **Function key:** `{function_key}`\n"
        result += f"- **Address:** `{address}`\n"
        result += f"- **Kind:** `{kind}`\n"
        result += f"- **Text:** {text}\n\n"
        result += (
            "*Stored in the per-binary side-car. Survives "
            "force_reanalyze and load_pdb.*"
        )
        return result
    except Exception as e:
        logger.error(f"add_note failed: {e}")
        return f"Error: {e}"


@app.tool()
@log_to_session
def get_notes(
    binary_path: str,
    address: str | None = None,
) -> str:
    """
    List user-supplied annotations for a binary.

    With no ``address``, returns every note in the side-car. With an
    ``address`` set, returns notes attached to that function (any kind)
    plus any pre/post notes pinned exactly to that instruction.

    Args:
        binary_path: Path to the analyzed binary
        address: Optional hex address to filter by

    Returns:
        Markdown listing grouped by function_key, or "No notes" when empty.
    """
    try:
        notes = cache.read_notes(binary_path)
        if not notes:
            return f"**Notes for {Path(binary_path).name}:** *(none)*"

        if address:
            context = get_analysis_context(binary_path)
            _target_fn, function_key = _resolve_function_note_key(
                context, address
            )
            target_addr_norm = _normalize_xref_addr(address)
            filtered = []
            for row in notes:
                if not isinstance(row, dict):
                    continue
                if function_key and row.get("function_key") == function_key:
                    filtered.append(row)
                    continue
                row_addr = row.get("addr")
                if row_addr and _normalize_xref_addr(row_addr) == target_addr_norm:
                    filtered.append(row)
            notes = filtered
            if not notes:
                return (
                    f"**Notes for {Path(binary_path).name} @ {address}:** "
                    f"*(none)*"
                )

        # Group by function_key for stable presentation.
        grouped: dict[str, list[dict]] = {}
        for row in notes:
            if not isinstance(row, dict):
                continue
            grouped.setdefault(row.get("function_key") or "<unknown>", []).append(row)

        lines = [f"**Notes for {Path(binary_path).name}:**", ""]
        total = 0
        for key in sorted(grouped):
            rows = grouped[key]
            lines.append(f"### `{key}` ({len(rows)})")
            for row in rows:
                kind = row.get("kind") or "?"
                addr = row.get("addr") or ""
                text = row.get("text") or ""
                if kind == "plate":
                    lines.append(f"- [plate] {text}")
                else:
                    lines.append(f"- [{kind} @ {addr}] {text}")
                total += 1
            lines.append("")
        lines.append(f"_Total: {total}_")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"get_notes failed: {e}")
        return f"Error: {e}"


@app.tool()
@log_to_session
def delete_note(
    binary_path: str,
    address: str,
    kind: str = "plate",
) -> str:
    """
    Remove a user-supplied annotation.

    Args:
        binary_path: Path to the analyzed binary
        address: Hex address used when the note was added (function
            entry for plate, instruction PC for pre/post)
        kind: ``"plate"``, ``"pre"``, or ``"post"`` -- must match the
            kind given to ``add_note``

    Returns:
        Confirmation that the note was dropped, or an error if it was
        not found.
    """
    try:
        if kind not in _NOTE_KIND_VALUES:
            return (
                f"Error: kind must be one of {', '.join(_NOTE_KIND_VALUES)}; "
                f"got '{kind}'"
            )
        if not address:
            return "Error: 'address' is required"

        context = get_analysis_context(binary_path)
        target_fn, function_key = _resolve_function_note_key(context, address)
        if target_fn is None or function_key is None:
            return f"Error: No function contains address {address}"

        notes = cache.read_notes(binary_path)
        note_addr = None if kind == "plate" else address
        existing_idx = _matching_note_index(notes, function_key, kind, note_addr)
        if existing_idx is None:
            return (
                f"Error: No {kind} note for `{function_key}`"
                + (f" at {address}" if note_addr else "")
            )

        removed = notes.pop(existing_idx)
        if not cache.write_notes(binary_path, notes):
            return "Error: Failed to persist notes side-car"

        # Re-overlay onto the in-memory context. Because the deleted
        # note's slot in ``notes[func]`` is no longer rewritten, we
        # also drop it from the cache's func entry directly.
        try:
            target = next(
                (
                    f for f in context.get("functions") or []
                    if f is target_fn
                ),
                None,
            )
            if target is not None and isinstance(target.get("notes"), dict):
                bucket = target["notes"]
                if kind == "plate":
                    bucket["plate"] = ""
                elif note_addr:
                    bucket.get(kind, {}).pop(note_addr, None)
            cache.save_cached(binary_path, context)
        except Exception as e:
            logger.warning(f"delete_note cache refresh failed: {e}")

        result = "**Note Deleted**\n\n"
        result += f"- **Function key:** `{function_key}`\n"
        result += f"- **Address:** `{address}`\n"
        result += f"- **Kind:** `{kind}`\n"
        result += f"- **Text:** {removed.get('text', '')}\n"
        return result
    except Exception as e:
        logger.error(f"delete_note failed: {e}")
        return f"Error: {e}"


# --- Analysis Session Tools ---

@app.tool()
def start_analysis_session(
    binary_path: str,
    name: str,
    tags: str | list[str] | None = None,
    analysis_type: str = "static"
) -> str:
    """
    Start a new analysis session to track all tool outputs.

    Note: Sessions are now started AUTOMATICALLY when you run analysis tools.
    You only need this if you want to set a custom name or tags.

    Args:
        binary_path: Path to the binary file to analyze
        name: Human-readable name for the session (e.g., "Malware Sample XYZ Analysis")
        tags: Optional tags for categorization (e.g., ["malware", "trojan", "ransomware"])
        analysis_type: Type of analysis: "static", "dynamic", or "mixed" (default: "static")

    Returns:
        Session ID and instructions
    """
    try:
        # Handle tags: accept either list or JSON string (for MCP client compatibility)
        parsed_tags: list[str] = []
        if tags:
            if isinstance(tags, str):
                # Parse JSON string to list
                try:
                    parsed_tags = json.loads(tags)
                    if not isinstance(parsed_tags, list):
                        raise ValueError("Tags must be a list")
                except (json.JSONDecodeError, ValueError) as e:
                    logger.warning(f"Failed to parse tags string: {e}. Using as single tag.")
                    parsed_tags = [tags]
            else:
                parsed_tags = tags

        # Parse analysis type
        type_map = {
            "static": AnalysisType.STATIC,
            "dynamic": AnalysisType.DYNAMIC,
            "mixed": AnalysisType.MIXED
        }
        a_type = type_map.get(analysis_type.lower(), AnalysisType.STATIC)

        session_id = session_manager.start_session(
            binary_path=binary_path,
            name=name,
            analysis_type=a_type,
            tags=parsed_tags
        )

        result = "**Analysis Session Started**\n\n"
        result += f"- **Session ID:** `{session_id}`\n"
        result += f"- **Name:** {name}\n"
        result += f"- **Binary:** {Path(binary_path).name}\n"
        result += f"- **Type:** {analysis_type}\n"
        if parsed_tags:
            result += f"- **Tags:** {', '.join(parsed_tags)}\n"
        result += "\n**Status:** All tool calls will now be automatically logged.\n\n"
        result += "**Note:** Sessions auto-start when you run analysis tools.\n"
        result += "Both static (Ghidra) and dynamic (x64dbg) tools are logged to the same session.\n\n"
        result += "**Next Steps:**\n"
        result += "1. Run analysis tools (analyze_binary, x64dbg_*, decompile_function, etc.)\n"
        result += "2. Call `save_session()` when done to persist all outputs\n"
        result += "3. Use the session ID in a new conversation to load the data\n"

        return result

    except Exception as e:
        logger.error(f"start_analysis_session failed: {e}")
        return f"Error: {e}"


@app.tool()
def save_session(session_id: str | None = None) -> str:
    """
    Save the current analysis session to disk.

    Persists all tool call outputs in compressed format for later retrieval.
    Call this periodically during long analysis sessions as a checkpoint.

    Args:
        session_id: Session ID to save. If not provided, saves the active session.

    Returns:
        Success message with session details
    """
    try:
        # Use active session if no ID provided
        if session_id is None:
            if not session_manager.active_session_id:
                return "Error: No active session. Start a session first with start_analysis_session() or run an analysis tool."
            session_id = session_manager.active_session_id

        success = session_manager.save_session(session_id)

        if not success:
            return f"Error: Failed to save session '{session_id}'"

        # Get metadata for confirmation
        metadata = session_manager.get_metadata(session_id)
        if not metadata:
            return "Session saved but metadata unavailable."

        result = "**Session Saved Successfully**\n\n"
        result += f"- **Session ID:** `{session_id}`\n"
        result += f"- **Name:** {metadata.get('name')}\n"
        result += f"- **Type:** {metadata.get('analysis_type', 'unknown')}\n"
        result += f"- **Tools Used:** {metadata.get('tool_count')}\n"

        # Show static/dynamic breakdown if mixed
        static_count = metadata.get('static_tool_count', 0)
        dynamic_count = metadata.get('dynamic_tool_count', 0)
        if static_count > 0 or dynamic_count > 0:
            result += f"  - Static: {static_count}, Dynamic: {dynamic_count}\n"

        result += f"- **Total Output:** {metadata.get('total_output_size', 0) / 1024:.1f} KB\n"
        result += f"- **Compressed Size:** {metadata.get('compressed_size', 0) / 1024:.1f} KB\n"
        result += "\n**To retrieve this session in a new conversation:**\n"
        result += f"```\nget_session_summary('{session_id}')\n```\n"
        result += "\nYou can now safely end this conversation. The session data is persisted.\n"

        return result

    except Exception as e:
        logger.error(f"save_session failed: {e}")
        return f"Error: {e}"


@app.tool()
def list_sessions(
    tag_filter: str | None = None,
    binary_name_filter: str | None = None,
    analysis_type_filter: str | None = None,
    limit: int = 20
) -> str:
    """
    List all saved analysis sessions.

    Args:
        tag_filter: Filter by tag (optional)
        binary_name_filter: Filter by binary name pattern (optional)
        analysis_type_filter: Filter by type: "static", "dynamic", or "mixed" (optional)
        limit: Maximum number of results (default: 20)

    Returns:
        List of sessions with metadata
    """
    try:
        sessions = session_manager.list_sessions(
            tag_filter=tag_filter,
            binary_name_filter=binary_name_filter,
            analysis_type_filter=analysis_type_filter,
            limit=limit
        )

        if not sessions:
            result = "**No Saved Sessions Found**\n\n"
            if tag_filter or binary_name_filter or analysis_type_filter:
                result += "Try removing filters or start a new session.\n"
            else:
                result += "Sessions are created automatically when you run analysis tools.\n"
            return result

        result = f"**Saved Sessions: {len(sessions)} found**\n\n"

        for session in sessions:
            session_id = session.get('session_id', 'Unknown')
            name = session.get('name', 'Unknown')
            updated = time.strftime('%Y-%m-%d %H:%M', time.localtime(session.get('updated_at', 0)))
            binary_name = session.get('binary_name', 'Unknown')
            tags = session.get('tags', [])
            tool_count = session.get('tool_count', 0)
            analysis_type = session.get('analysis_type', 'static')
            size_kb = session.get('compressed_size', 0) / 1024

            # Analysis type indicator
            type_icon = {"static": "[S]", "dynamic": "[D]", "mixed": "[M]"}.get(analysis_type, "[?]")

            result += f"### {type_icon} {name}\n"
            result += f"- **ID:** `{session_id[:8]}...`\n"
            result += f"- **Binary:** {binary_name}\n"
            result += f"- **Type:** {analysis_type}\n"
            result += f"- **Updated:** {updated}\n"
            result += f"- **Tools:** {tool_count}"

            # Show static/dynamic breakdown
            static_count = session.get('static_tool_count', 0)
            dynamic_count = session.get('dynamic_tool_count', 0)
            if static_count > 0 or dynamic_count > 0:
                result += f" (S:{static_count}, D:{dynamic_count})"
            result += "\n"

            result += f"- **Size:** {size_kb:.1f} KB\n"
            if tags:
                # Filter out auto-session tag for cleaner display
                display_tags = [t for t in tags if t != "auto-session"]
                if display_tags:
                    result += f"- **Tags:** {', '.join(display_tags)}\n"
            result += "\n"

        # Show stats
        stats = session_manager.get_stats()
        result += "---\n**Stats:** "
        result += f"{stats['total_sessions']} sessions, {stats['total_size_mb']:.2f} MB"
        type_counts = stats.get('type_counts', {})
        if type_counts:
            result += f" | Static: {type_counts.get('static', 0)}, Dynamic: {type_counts.get('dynamic', 0)}, Mixed: {type_counts.get('mixed', 0)}"
        result += "\n"

        return result

    except Exception as e:
        logger.error(f"list_sessions failed: {e}")
        return f"Error: {e}"


@app.tool()
def get_session_summary(session_id: str) -> str:
    """
    Get a lightweight summary of a session without loading full data.

    Use this first to see what's in a session before loading specific sections.

    Args:
        session_id: UUID of the session

    Returns:
        Session summary with tools used and metadata
    """
    try:
        summary = session_manager.get_section(session_id, "summary")

        if not summary:
            return f"Error: Session '{session_id}' not found. Use list_sessions() to see available sessions."

        metadata = session_manager.get_metadata(session_id)

        analysis_type = metadata.get('analysis_type', 'static')
        type_icon = {"static": "[Static]", "dynamic": "[Dynamic]", "mixed": "[Mixed]"}.get(analysis_type, "")

        result = f"# {type_icon} {metadata.get('name', 'Unknown Session')}\n\n"
        result += f"**Session ID:** `{session_id}`\n"
        result += f"**Binary:** {metadata.get('binary_name')}\n"
        result += f"**Binary Hash:** `{metadata.get('binary_hash', 'N/A')[:16]}...`\n"
        result += f"**Analysis Type:** {analysis_type}\n"
        result += f"**Created:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(metadata.get('created_at', 0)))}\n"
        result += f"**Updated:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(metadata.get('updated_at', 0)))}\n"
        result += f"**Status:** {metadata.get('status', 'unknown')}\n"

        if metadata.get('tags'):
            display_tags = [t for t in metadata.get('tags', []) if t != "auto-session"]
            if display_tags:
                result += f"**Tags:** {', '.join(display_tags)}\n"

        result += "\n**Analysis Summary:**\n"
        result += f"- Total Tools Used: {summary.get('tool_count')}\n"

        # Show static/dynamic breakdown
        static_count = metadata.get('static_tool_count', 0)
        dynamic_count = metadata.get('dynamic_tool_count', 0)
        if static_count > 0 or dynamic_count > 0:
            result += f"  - Static Tools: {static_count}\n"
            result += f"  - Dynamic Tools: {dynamic_count}\n"

        result += f"- Total Output: {metadata.get('total_output_size', 0) / 1024:.1f} KB\n"
        result += f"- Compressed Size: {metadata.get('compressed_size', 0) / 1024:.1f} KB\n"

        # Show static tools
        static_tools = summary.get('static_tools', [])
        dynamic_tools = summary.get('dynamic_tools', [])

        if static_tools:
            result += "\n**Static Analysis Tools:**\n"
            for tool in sorted(static_tools):
                result += f"- {tool}\n"

        if dynamic_tools:
            result += "\n**Dynamic Analysis Tools:**\n"
            for tool in sorted(dynamic_tools):
                result += f"- {tool}\n"

        result += "\n**Load Data:**\n"
        result += f"- Static tools: `load_session_section('{session_id}', 'static_tools')`\n"
        result += f"- Dynamic tools: `load_session_section('{session_id}', 'dynamic_tools')`\n"
        result += f"- Specific tool: `load_session_section('{session_id}', 'tools', 'tool_name')`\n"
        result += f"- All data: `load_full_session('{session_id}')`\n"

        return result

    except Exception as e:
        logger.error(f"get_session_summary failed: {e}")
        return f"Error: {e}"


@app.tool()
def load_session_section(
    session_id: str,
    section: str,
    tool_filter: str | None = None
) -> str:
    """
    Load a specific section of session data (chunked retrieval).

    Use this to load only the data you need, avoiding context overflow.

    Args:
        session_id: UUID of the session
        section: Section to load:
            - "metadata": Session metadata only
            - "summary": Session summary with tool list
            - "tools": All tool calls (optionally filtered by tool_filter)
            - "static_tools": Only static analysis tool calls
            - "dynamic_tools": Only dynamic analysis tool calls
        tool_filter: Optional tool name filter (e.g., "decompile_function", "x64dbg_get_registers")

    Returns:
        Requested section data
    """
    try:
        section_data = session_manager.get_section(
            session_id=session_id,
            section_type=section,
            tool_filter=tool_filter
        )

        if not section_data:
            return f"Error: Could not load section '{section}' from session '{session_id}'"

        if section == "metadata":
            result = "**Session Metadata**\n\n"
            result += f"- Session ID: `{section_data.get('session_id')}`\n"
            result += f"- Name: {section_data.get('name')}\n"
            result += f"- Binary: {section_data.get('binary_name')}\n"
            result += f"- Type: {section_data.get('analysis_type', 'static')}\n"
            result += f"- Tool Count: {section_data.get('tool_count')}\n"
            result += f"- Size: {section_data.get('total_output_size', 0) / 1024:.1f} KB\n"
            return result

        if section == "summary":
            return get_session_summary(session_id)

        if section in ("tools", "static_tools", "dynamic_tools"):
            tool_calls = section_data.get('tool_calls', [])

            if not tool_calls:
                filter_desc = ""
                if tool_filter:
                    filter_desc = f" for tool: {tool_filter}"
                elif section == "static_tools":
                    filter_desc = " (static analysis)"
                elif section == "dynamic_tools":
                    filter_desc = " (dynamic analysis)"
                return f"No tool calls found{filter_desc}"

            # Section header
            section_labels = {
                "tools": "All Tool Outputs",
                "static_tools": "Static Analysis Outputs",
                "dynamic_tools": "Dynamic Analysis Outputs"
            }
            result = f"**{section_labels.get(section, 'Tool Outputs')}** (Session: {session_id[:8]}...)\n"
            if tool_filter:
                result += f"**Filtered by:** {tool_filter}\n"
            result += f"\n**Total Calls:** {len(tool_calls)}\n\n"
            result += "---\n\n"

            for i, call in enumerate(tool_calls, 1):
                tool_name = call.get('tool_name')
                timestamp = call.get('timestamp')
                output = call.get('output', '')
                args = call.get('arguments', {})
                analysis_type = call.get('analysis_type', 'static')

                # Type indicator
                type_icon = "[S]" if analysis_type == "static" else "[D]"

                result += f"## {type_icon} Call #{i}: {tool_name}\n\n"
                result += f"**Time:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}\n"

                if args:
                    result += "**Arguments:** "
                    arg_str = ", ".join(f"{k}={v}" for k, v in args.items())
                    result += f"{arg_str}\n"

                result += f"\n{output}\n\n"
                result += "---\n\n"

            return result

        return f"Error: Unknown section type: {section}. Valid sections: metadata, summary, tools, static_tools, dynamic_tools"

    except Exception as e:
        logger.error(f"load_session_section failed: {e}")
        return f"Error: {e}"


@app.tool()
def load_full_session(session_id: str) -> str:
    """
    Load ALL data from a session (WARNING: may be very large).

    Only use this for small sessions or when you need everything at once.
    For large sessions, use load_session_section() instead.

    Args:
        session_id: UUID of the session

    Returns:
        Complete session data with all tool outputs
    """
    try:
        session_data = session_manager.get_session(session_id)

        if not session_data:
            return f"Error: Session '{session_id}' not found. Use list_sessions() to see available sessions."

        result = f"# {session_data.get('name')}\n\n"
        result += f"**Session ID:** `{session_id}`\n"
        result += f"**Binary:** {session_data.get('binary_name')}\n"
        result += f"**Binary Hash:** `{session_data.get('binary_hash', 'N/A')[:16]}...`\n"
        result += f"**Created:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session_data.get('created_at', 0)))}\n"

        tool_calls = session_data.get('tool_calls', [])
        result += f"**Tool Calls:** {len(tool_calls)}\n\n"
        result += "---\n\n"

        for i, call in enumerate(tool_calls, 1):
            tool_name = call.get('tool_name')
            timestamp = call.get('timestamp')
            output = call.get('output', '')
            args = call.get('arguments', {})

            result += f"## Tool Call #{i}: {tool_name}\n\n"
            result += f"**Time:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}\n"

            if args:
                result += "**Arguments:** "
                arg_str = ", ".join(f"{k}={v}" for k, v in args.items())
                result += f"{arg_str}\n"

            result += f"\n{output}\n\n"
            result += "---\n\n"

        return result

    except Exception as e:
        logger.error(f"load_full_session failed: {e}")
        return f"Error: {e}"


@app.tool()
def delete_session(session_id: str) -> str:
    """
    Delete a saved session.

    Use this to clean up old sessions after you've generated reports and
    no longer need the raw data.

    Args:
        session_id: UUID of the session to delete

    Returns:
        Success/failure message
    """
    try:
        # Get metadata first for confirmation message
        metadata = session_manager.get_metadata(session_id)
        if metadata:
            name = metadata.get('name', 'Unknown')
        else:
            return f"Error: Session '{session_id}' not found."

        # Delete
        success = session_manager.delete_session(session_id)

        if success:
            return f"**Session Deleted**\n\nSuccessfully deleted: {name} (ID: {session_id[:8]}...)"
        else:
            return f"Error: Failed to delete session '{session_id}'"

    except Exception as e:
        logger.error(f"delete_session failed: {e}")
        return f"Error: {e}"


@app.tool()
def find_related_sessions(binary_path: str, limit: int = 10) -> str:
    """
    Find all sessions related to a specific binary.

    Use this to find previous analysis sessions for the same binary,
    allowing you to continue where you left off or compare results.

    The search uses the binary's SHA256 hash, so it works even if:
    - The file was moved to a different location
    - The file was renamed
    - You're in a new conversation

    Args:
        binary_path: Path to the binary file
        limit: Maximum number of sessions to return (default: 10)

    Returns:
        List of related sessions sorted by most recent first
    """
    try:
        sessions = session_manager.find_sessions_for_binary(
            binary_path=binary_path,
            limit=limit
        )

        if not sessions:
            return f"No previous sessions found for: {Path(binary_path).name}"

        result = f"**Related Sessions for {Path(binary_path).name}**\n\n"
        result += f"Found {len(sessions)} session(s) for this binary:\n\n"

        for session in sessions:
            session_id = session.get('session_id', 'Unknown')
            name = session.get('name', 'Unknown')
            updated = time.strftime('%Y-%m-%d %H:%M', time.localtime(session.get('updated_at', 0)))
            analysis_type = session.get('analysis_type', 'static')
            tool_count = session.get('tool_count', 0)

            type_icon = {"static": "[S]", "dynamic": "[D]", "mixed": "[M]"}.get(analysis_type, "[?]")

            result += f"### {type_icon} {name}\n"
            result += f"- **ID:** `{session_id[:8]}...`\n"
            result += f"- **Updated:** {updated}\n"
            result += f"- **Tools:** {tool_count}\n"
            result += f"- **Load:** `get_session_summary('{session_id}')`\n\n"

        return result

    except Exception as e:
        logger.error(f"find_related_sessions failed: {e}")
        return f"Error: {e}"


@app.tool()
def configure_auto_session(enabled: bool = True) -> str:
    """
    Enable or disable automatic session management.

    When enabled (default), sessions are automatically started/resumed when:
    - You run analysis tools with a binary_path
    - A recent session exists for the same binary (within 1 hour)

    Args:
        enabled: True to enable auto-session, False to disable

    Returns:
        Confirmation message
    """
    session_manager.auto_session_enabled = enabled

    if enabled:
        result = "**Auto-Session Enabled**\n\n"
        result += "Sessions will now be automatically created/resumed when running analysis tools.\n"
        result += "Recent sessions (within 1 hour) for the same binary will be resumed automatically.\n"
    else:
        result = "**Auto-Session Disabled**\n\n"
        result += "You must manually call `start_analysis_session()` to create sessions.\n"
        result += "Use `configure_auto_session(True)` to re-enable.\n"

    return result


@app.tool()
def get_active_session() -> str:
    """
    Get information about the currently active session.

    Returns:
        Active session details or message if none active
    """
    if not session_manager.active_session_id:
        return "No active session. Sessions are created automatically when you run analysis tools, or use `start_analysis_session()` to create one manually."

    session_id = session_manager.active_session_id
    data = session_manager.active_session_data

    if not data:
        return f"Active session ID: `{session_id}` (data unavailable)"

    tool_count = len(data.get('tool_calls', []))
    analysis_type = data.get('analysis_type', 'static')

    result = "**Active Session**\n\n"
    result += f"- **ID:** `{session_id}`\n"
    result += f"- **Name:** {data.get('name')}\n"
    result += f"- **Binary:** {data.get('binary_name')}\n"
    result += f"- **Type:** {analysis_type}\n"
    result += f"- **Tools Called:** {tool_count}\n"
    result += f"- **Status:** {data.get('status', 'active')}\n\n"
    result += "**Actions:**\n"
    result += "- Save: `save_session()`\n"
    result += "- End without saving: `session_manager.end_session(save=False)`\n"

    return result


# --- Crypto Analysis Tools ---

@app.tool()
@log_to_session(analysis_type=AnalysisType.STATIC)
def detect_crypto_patterns(binary_path: str) -> str:
    """
    Detect encryption and encoding patterns in a binary file.

    Analyzes the file for common crypto patterns including:
    - XOR encryption (single and multi-byte keys)
    - Base64 encoding
    - High entropy regions (encrypted/compressed)
    - Null byte patterns

    Args:
        binary_path: Path to binary file to analyze

    Returns:
        Detected patterns with confidence scores and details

    Example output:
        Crypto Pattern Analysis:
          File: payload.bin
          Size: 4096 bytes
          Entropy: 7.85 bits/byte (high - likely encrypted)

        Detected Patterns:
          [HIGH] xor_single_byte (confidence: 0.85)
            Key: 0x41
            Sample entropy after decryption: 4.2

          [MEDIUM] high_entropy (confidence: 0.75)
            Entropy: 7.85 bits/byte
            Likely: encrypted or compressed
    """
    try:
        safe_path = sanitize_binary_path(binary_path)

        from src.utils.crypto_analysis import calculate_entropy
        from src.utils.crypto_analysis import detect_crypto_patterns as analyze

        path = Path(safe_path)
        if not path.exists():
            return f"Error: File not found: {binary_path}"

        # Read file, cap at 500KB for crypto analysis (patterns are in headers/early data)
        file_size = path.stat().st_size
        with open(path, "rb") as f:
            data = f.read(min(file_size, 512 * 1024))
        entropy = calculate_entropy(data[:65536] if len(data) > 65536 else data)
        patterns = analyze(data)

        # Build output
        output = [
            "Crypto Pattern Analysis:",
            f"  File: {path.name}",
            f"  Size: {len(data)} bytes",
            f"  Entropy: {entropy:.2f} bits/byte",
        ]

        # Entropy interpretation
        if entropy > 7.5:
            output.append("  Status: HIGH entropy - likely encrypted or compressed")
        elif entropy > 6.0:
            output.append("  Status: MEDIUM entropy - may be obfuscated")
        else:
            output.append("  Status: LOW entropy - likely plaintext or structured data")

        output.append("")

        if patterns:
            output.append("Detected Patterns:")
            output.append("-" * 50)

            for pattern in patterns:
                conf = pattern["confidence"]
                level = "HIGH" if conf > 0.7 else "MEDIUM" if conf > 0.4 else "LOW"
                output.append(f"  [{level}] {pattern['type']} (confidence: {conf:.2f})")

                for key, value in pattern.get("details", {}).items():
                    if isinstance(value, float):
                        output.append(f"    {key}: {value:.2f}")
                    else:
                        output.append(f"    {key}: {value}")
                output.append("")
        else:
            output.append("No significant crypto patterns detected.")

        return "\n".join(output)

    except (PathTraversalError, FileSizeError) as e:
        return safe_error_message("detect_crypto_patterns", e)
    except Exception as e:
        logger.error(f"detect_crypto_patterns failed: {e}")
        return f"Error analyzing file: {e}"


@app.tool()
@log_to_session(analysis_type=AnalysisType.STATIC)
def analyze_xor_encryption(
    binary_path: str,
    min_key_length: int = 1,
    max_key_length: int = 16,
    sample_size: int = 10000
) -> str:
    """
    Analyze potential XOR encryption and find likely keys.

    Uses frequency analysis to detect XOR encryption and find
    the most probable decryption keys.

    Args:
        binary_path: Path to encrypted file
        min_key_length: Minimum key length to try (default: 1)
        max_key_length: Maximum key length to try (default: 16)
        sample_size: Bytes to analyze (default: 10000)

    Returns:
        Top XOR key candidates with confidence scores

    Example:
        analyze_xor_encryption("encrypted.bin", max_key_length=8)
    """
    try:
        safe_path = sanitize_binary_path(binary_path)

        from src.utils.crypto_analysis import analyze_xor

        path = Path(safe_path)
        if not path.exists():
            return f"Error: File not found: {binary_path}"

        data = path.read_bytes()[:sample_size]

        candidates = analyze_xor(
            data,
            key_length_range=(min_key_length, max_key_length),
            top_n=5
        )

        output = [
            "XOR Encryption Analysis:",
            f"  File: {path.name}",
            f"  Sample size: {len(data)} bytes",
            f"  Key length range: {min_key_length}-{max_key_length}",
            ""
        ]

        if candidates:
            output.append("Top Key Candidates:")
            output.append("-" * 50)

            for i, candidate in enumerate(candidates, 1):
                output.append(f"{i}. Key: {candidate['key_hex']}")
                output.append(f"   Length: {candidate['key_length']} bytes")
                output.append(f"   Confidence: {candidate['confidence']:.2f}")
                output.append(f"   Decrypted entropy: {candidate['sample_entropy']:.2f}")

                # Show sample of decrypted text
                sample = candidate["decrypted_sample"]
                try:
                    text_sample = sample.decode('ascii', errors='replace')[:40]
                    output.append(f"   Sample: \"{text_sample}\"")
                except Exception:
                    output.append(f"   Sample: {sample[:20].hex()}")
                output.append("")
        else:
            output.append("No XOR encryption patterns detected.")

        return "\n".join(output)

    except (PathTraversalError, FileSizeError) as e:
        return safe_error_message("analyze_xor_encryption", e)
    except Exception as e:
        logger.error(f"analyze_xor_encryption failed: {e}")
        return f"Error analyzing file: {e}"


@app.tool()
@log_to_session(analysis_type=AnalysisType.STATIC)
def decrypt_xor(
    binary_path: str,
    key: str,
    output_path: str | None = None
) -> str:
    """
    Decrypt a file using XOR with the specified key.

    Args:
        binary_path: Path to encrypted file
        key: XOR key as hex string (e.g., "41", "DEADBEEF")
        output_path: Optional path to save decrypted output

    Returns:
        Decryption result with preview of decrypted content

    Example:
        decrypt_xor("encrypted.bin", key="DEADBEEF", output_path="decrypted.bin")
    """
    try:
        safe_path = sanitize_binary_path(binary_path)

        from src.utils.crypto_analysis import calculate_entropy, xor_decrypt

        path = Path(safe_path)
        if not path.exists():
            return f"Error: File not found: {binary_path}"

        # Parse key
        try:
            key_bytes = bytes.fromhex(key.replace("0x", "").replace(" ", ""))
        except ValueError:
            return f"Error: Invalid hex key: {key}"

        data = path.read_bytes()
        decrypted = xor_decrypt(data, key_bytes)
        entropy = calculate_entropy(decrypted)

        output = [
            "XOR Decryption:",
            f"  Input: {path.name} ({len(data)} bytes)",
            f"  Key: {key_bytes.hex().upper()} ({len(key_bytes)} bytes)",
            f"  Decrypted entropy: {entropy:.2f} bits/byte",
            ""
        ]

        # Check for known file signatures
        if decrypted[:2] == b'MZ':
            output.append("  Signature: PE executable (MZ header)")
        elif decrypted[:4] == b'\x7fELF':
            output.append("  Signature: ELF executable")
        elif decrypted[:3] == b'PK\x03':
            output.append("  Signature: ZIP archive")
        elif decrypted[:8] == b'\x89PNG\r\n\x1a\n':
            output.append("  Signature: PNG image")

        # Show preview
        output.append("")
        output.append("Decrypted preview (first 64 bytes):")
        output.append(f"  Hex: {decrypted[:64].hex().upper()}")
        try:
            text_preview = decrypted[:64].decode('ascii', errors='replace')
            output.append(f"  Text: \"{text_preview}\"")
        except Exception:
            pass

        # Save if output path specified
        if output_path:
            try:
                # Ensure output directory exists
                CRYPTO_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
                # Validate output path to prevent directory traversal
                safe_out_path = sanitize_output_path(Path(output_path), CRYPTO_OUTPUT_DIR)
                safe_out_path.parent.mkdir(parents=True, exist_ok=True)
                safe_out_path.write_bytes(decrypted)
                output.append("")
                output.append(f"Saved to: {safe_out_path}")
            except PathTraversalError:
                output.append("")
                output.append(f"Error: Output path must be within {CRYPTO_OUTPUT_DIR}")

        return "\n".join(output)

    except (PathTraversalError, FileSizeError) as e:
        return safe_error_message("decrypt_xor", e)
    except Exception as e:
        logger.error(f"decrypt_xor failed: {e}")
        return f"Error decrypting file: {e}"


@app.tool()
@log_to_session(analysis_type=AnalysisType.STATIC)
def decode_base64_file(
    binary_path: str,
    output_path: str | None = None
) -> str:
    """
    Decode a Base64 encoded file.

    Args:
        binary_path: Path to Base64 encoded file
        output_path: Optional path to save decoded output

    Returns:
        Decoding result with preview of decoded content

    Example:
        decode_base64_file("encoded.txt", output_path="decoded.bin")
    """
    try:
        safe_path = sanitize_binary_path(binary_path)

        import base64

        from src.utils.crypto_analysis import calculate_entropy

        path = Path(safe_path)
        if not path.exists():
            return f"Error: File not found: {binary_path}"

        data = path.read_bytes()

        # Try to decode
        try:
            text = data.decode('ascii', errors='ignore')
            text = ''.join(text.split())  # Remove whitespace
            decoded = base64.b64decode(text)
        except Exception as e:
            return f"Error: Failed to decode Base64: {e}"

        entropy = calculate_entropy(decoded)

        output = [
            "Base64 Decoding:",
            f"  Input: {path.name} ({len(data)} bytes)",
            f"  Decoded: {len(decoded)} bytes",
            f"  Decoded entropy: {entropy:.2f} bits/byte",
            ""
        ]

        # Check for known file signatures
        if decoded[:2] == b'MZ':
            output.append("  Signature: PE executable (MZ header)")
        elif decoded[:4] == b'\x7fELF':
            output.append("  Signature: ELF executable")
        elif decoded[:3] == b'PK\x03':
            output.append("  Signature: ZIP archive")

        # Show preview
        output.append("")
        output.append("Decoded preview (first 64 bytes):")
        output.append(f"  Hex: {decoded[:64].hex().upper()}")
        try:
            text_preview = decoded[:64].decode('ascii', errors='replace')
            output.append(f"  Text: \"{text_preview}\"")
        except Exception:
            pass

        # Save if output path specified
        if output_path:
            try:
                # Ensure output directory exists
                CRYPTO_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
                # Validate output path to prevent directory traversal
                safe_out_path = sanitize_output_path(Path(output_path), CRYPTO_OUTPUT_DIR)
                safe_out_path.parent.mkdir(parents=True, exist_ok=True)
                safe_out_path.write_bytes(decoded)
                output.append("")
                output.append(f"Saved to: {safe_out_path}")
            except PathTraversalError:
                output.append("")
                output.append(f"Error: Output path must be within {CRYPTO_OUTPUT_DIR}")

        return "\n".join(output)

    except (PathTraversalError, FileSizeError) as e:
        return safe_error_message("decode_base64_file", e)
    except Exception as e:
        logger.error(f"decode_base64_file failed: {e}")
        return f"Error decoding file: {e}"


# --- Python Bytecode Analysis Tools ---


@app.tool()
@log_to_session(analysis_type=AnalysisType.STATIC)
def detect_python_packer(binary_path: str) -> str:
    """
    Detect if a binary is packed with a Python packer.

    Detects py2exe, PyInstaller, cx_Freeze, and Nuitka packed executables.
    Provides confidence scores and indicators found.

    Args:
        binary_path: Path to the binary file to analyze

    Returns:
        Detection result with packer type, confidence, and indicators

    Example:
        detect_python_packer("suspicious.exe")
        # Returns: Packer: pyinstaller, Confidence: 95%, Python: 3.11
    """
    try:
        binary_path = sanitize_binary_path(binary_path)

        from src.engines.static.python.analyzer import PythonPackerAnalyzer
        analyzer = PythonPackerAnalyzer()
        result = analyzer.detect_packer(binary_path)

        output = []
        output.append("=" * 60)
        output.append("PYTHON PACKER DETECTION")
        output.append("=" * 60)
        output.append(f"File: {binary_path}")
        output.append("")

        if result["is_python_packed"]:
            output.append(f"✓ Python packer detected: {result['packer'].upper()}")
            output.append(f"  Confidence: {result['confidence'] * 100:.0f}%")

            if result["python_version"]:
                output.append(f"  Python Version: {result['python_version']}")

            output.append("")
            output.append("Indicators Found:")
            for indicator in result["indicators"]:
                output.append(f"  • {indicator}")

            if result["resources"]:
                output.append("")
                output.append("Embedded Resources:")
                for res in result["resources"][:10]:
                    output.append(f"  • {res}")
                if len(result["resources"]) > 10:
                    output.append(f"  ... and {len(result['resources']) - 10} more")
        else:
            output.append("✗ No Python packer detected")
            if result["indicators"]:
                output.append("")
                output.append("Notes:")
                for indicator in result["indicators"]:
                    output.append(f"  • {indicator}")

        return "\n".join(output)

    except (PathTraversalError, FileSizeError) as e:
        return safe_error_message("detect_python_packer", e)
    except FileNotFoundError as e:
        return f"File not found: {e}"
    except Exception as e:
        logger.error(f"detect_python_packer failed: {e}")
        return f"Error detecting packer: {e}"


@app.tool()
@log_to_session(analysis_type=AnalysisType.STATIC)
def extract_python_packed(
    binary_path: str,
    output_dir: str,
    packer_type: str = "auto"
) -> str:
    """
    Extract files from a Python packed executable.

    Automatically detects the packer type or uses the specified one.
    Extracts embedded .pyc files, libraries, and resources.

    Args:
        binary_path: Path to the packed executable
        output_dir: Directory to extract files to
        packer_type: Packer type (auto, pyinstaller, py2exe) - default: auto

    Returns:
        Extraction result with list of extracted files

    Example:
        extract_python_packed("packed.exe", "/tmp/extracted/")
        extract_python_packed("packed.exe", "/tmp/extracted/", packer_type="py2exe")
    """
    try:
        binary_path = sanitize_binary_path(binary_path)

        from src.engines.static.python.analyzer import PythonPackerAnalyzer
        analyzer = PythonPackerAnalyzer()

        # Auto-detect packer type if needed
        if packer_type == "auto":
            detection = analyzer.detect_packer(binary_path)
            if not detection["is_python_packed"]:
                return "No Python packer detected in this binary"
            packer_type = detection["packer"]

        output = []
        output.append("=" * 60)
        output.append("PYTHON PACKED EXTRACTION")
        output.append("=" * 60)
        output.append(f"File: {binary_path}")
        output.append(f"Packer: {packer_type}")
        output.append(f"Output: {output_dir}")
        output.append("")

        # Extract based on packer type
        if packer_type == "pyinstaller":
            result = analyzer.extract_pyinstaller(binary_path, output_dir)
        elif packer_type == "py2exe":
            result = analyzer.extract_py2exe(binary_path, output_dir)
        else:
            return f"Unsupported packer type for extraction: {packer_type}"

        if result["success"]:
            output.append(f"✓ Successfully extracted {len(result['extracted_files'])} files")
            output.append("")
            output.append("Extracted Files:")
            for f in result["extracted_files"][:20]:
                output.append(f"  • {f}")
            if len(result["extracted_files"]) > 20:
                output.append(f"  ... and {len(result['extracted_files']) - 20} more")
        else:
            output.append("✗ Extraction failed or no files extracted")

        if result["errors"]:
            output.append("")
            output.append("Errors:")
            for err in result["errors"][:10]:
                output.append(f"  • {err}")

        return "\n".join(output)

    except (PathTraversalError, FileSizeError) as e:
        return safe_error_message("extract_python_packed", e)
    except FileNotFoundError as e:
        return f"File not found: {e}"
    except Exception as e:
        logger.error(f"extract_python_packed failed: {e}")
        return f"Error extracting packed binary: {e}"


@app.tool()
@log_to_session(analysis_type=AnalysisType.STATIC)
def analyze_pyc_file(pyc_path: str) -> str:
    """
    Analyze a .pyc (compiled Python bytecode) file.

    Extracts Python version, magic number, timestamp, and metadata.
    Useful for understanding what Python version compiled the bytecode.

    Args:
        pyc_path: Path to the .pyc file

    Returns:
        Analysis result with version info and metadata

    Example:
        analyze_pyc_file("extracted/script.pyc")
        # Returns: Python 3.11, magic 0x7B0D, compiled 2024-01-15
    """
    try:
        pyc_path = sanitize_binary_path(pyc_path)

        from src.engines.static.python.analyzer import PythonPackerAnalyzer
        analyzer = PythonPackerAnalyzer()
        result = analyzer.analyze_pyc(pyc_path)

        output = []
        output.append("=" * 60)
        output.append("PYC FILE ANALYSIS")
        output.append("=" * 60)
        output.append(f"File: {result['file']}")
        output.append(f"Size: {result['size']} bytes")
        output.append("")

        if result["is_valid"]:
            output.append("Header Information:")
            output.append(f"  Magic Number: {result['magic_number']}")
            output.append(f"  Python Version: {result['python_version']}")

            if result["timestamp"]:
                output.append(f"  Compiled: {result['timestamp']}")

            if result["source_size"]:
                output.append(f"  Source Size: {result['source_size']} bytes")

            output.append("")
            output.append("✓ Valid .pyc file")
        else:
            output.append("✗ Invalid or unrecognized .pyc format")
            if result.get("error"):
                output.append(f"  Error: {result['error']}")

        return "\n".join(output)

    except (PathTraversalError, FileSizeError) as e:
        return safe_error_message("analyze_pyc_file", e)
    except FileNotFoundError as e:
        return f"File not found: {e}"
    except Exception as e:
        logger.error(f"analyze_pyc_file failed: {e}")
        return f"Error analyzing .pyc file: {e}"


@app.tool()
@log_to_session(analysis_type=AnalysisType.STATIC)
def list_python_archive_contents(binary_path: str) -> str:
    """
    List contents of a Python packed archive.

    Shows all files embedded in a py2exe or PyInstaller packed executable,
    including .pyc files, DLLs, and other resources.

    Args:
        binary_path: Path to the packed executable

    Returns:
        List of embedded files with sizes

    Example:
        list_python_archive_contents("packed.exe")
        # Returns: 15 files including main.pyc, library.zip, etc.
    """
    try:
        binary_path = sanitize_binary_path(binary_path)

        from src.engines.static.python.analyzer import PythonPackerAnalyzer
        analyzer = PythonPackerAnalyzer()
        result = analyzer.list_archive_contents(binary_path)

        output = []
        output.append("=" * 60)
        output.append("PYTHON ARCHIVE CONTENTS")
        output.append("=" * 60)
        output.append(f"File: {binary_path}")

        if result["packer"]:
            output.append(f"Packer: {result['packer']}")

        output.append(f"Total Files: {result['total_files']}")
        output.append("")

        if result["contents"]:
            # Group by type
            pyc_files = [f for f in result["contents"] if f["is_pyc"]]
            other_files = [f for f in result["contents"] if not f["is_pyc"]]

            if pyc_files:
                output.append(f"Python Bytecode Files ({len(pyc_files)}):")
                for f in pyc_files[:15]:
                    ratio = f["compressed_size"] / f["size"] if f["size"] > 0 else 1
                    output.append(f"  • {f['name']:<40} {f['size']:>8} bytes ({ratio:.0%} compressed)")
                if len(pyc_files) > 15:
                    output.append(f"  ... and {len(pyc_files) - 15} more .pyc files")

            if other_files:
                output.append("")
                output.append(f"Other Files ({len(other_files)}):")
                for f in other_files[:15]:
                    output.append(f"  • {f['name']:<40} {f['size']:>8} bytes")
                if len(other_files) > 15:
                    output.append(f"  ... and {len(other_files) - 15} more files")
        else:
            output.append("No embedded archive found or archive could not be read")

        return "\n".join(output)

    except (PathTraversalError, FileSizeError) as e:
        return safe_error_message("list_python_archive_contents", e)
    except FileNotFoundError as e:
        return f"File not found: {e}"
    except Exception as e:
        logger.error(f"list_python_archive_contents failed: {e}")
        return f"Error listing archive contents: {e}"


def main():
    """Run the MCP server."""
    logger.info("Starting Binary MCP Server...")
    logger.info(f"Ghidra Path: {runner.ghidra_path}")
    logger.info(f"Cache Directory: {cache.cache_dir}")

    # Register .NET analysis tools
    register_dotnet_tools(app)

    # Register dynamic analysis tools (with session logging)
    register_dynamic_tools(app, session_manager)

    # Register WinDbg kernel debugging tools (with session logging)
    register_windbg_tools(app, session_manager)

    # Register VirusTotal tools
    register_vt_tools(app, session_manager)

    # Register triage tools
    register_triage_tools(app, session_manager)

    # Register reporting tools
    register_reporting_tools(app, session_manager)

    # Register Yara tools
    register_yara_tools(app, session_manager)

    # Register control flow analysis tools
    register_control_flow_tools(app, session_manager, cache, runner)

    # Register malware behavior analysis tools
    register_malware_tools(app, session_manager, cache, runner, api_patterns)

    # Register function hash and cross-binary matching tools
    register_function_hash_tools(app, session_manager, cache, runner)

    # Register dispatch / IOCTL recovery tools
    register_dispatch_tools(app, session_manager, cache, runner)

    # Register PE structure analysis tools
    register_pe_tools(app, session_manager)

    # Register indirect-call / vtable enumeration tool (Wave 2)
    register_indirect_call_tools(app, cache, runner)

    # Register pseudocode-review + caller-analysis tools
    register_review_tools(app, session_manager, cache, runner, api_patterns)

    # Register Function ID (FID) library-match reader
    register_fid_tools(app, session_manager, cache, runner)

    logger.info("Registered all analysis tools (static, dynamic, VT, triage, reporting, Yara, control flow, malware, function hash, PE structure, review, fid)")
    logger.info(f"Session Directory: {session_manager.store_dir}")

    # Run the FastMCP server (handles stdio automatically)
    app.run()


if __name__ == "__main__":
    main()
