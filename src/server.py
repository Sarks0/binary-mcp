"""
Binary MCP Server for comprehensive binary analysis.

Provides 40+ tools for static and dynamic binary analysis:
- Static analysis via Ghidra (headless mode) for native binaries
- Static analysis via ILSpyCmd for .NET assemblies
- Dynamic analysis via x64dbg (native plugin)
"""

import functools
import json
import logging
import re
import sys
import time
from pathlib import Path

from fastmcp import FastMCP

from src.engines.session import AnalysisType, UnifiedSessionManager
from src.engines.static.ghidra.project_cache import ProjectCache
from src.engines.static.ghidra.runner import GhidraRunner
from src.tools.dotnet_tools import register_dotnet_tools
from src.tools.dynamic_tools import register_dynamic_tools
from src.tools.reporting import register_reporting_tools
from src.tools.triage_tools import register_triage_tools
from src.tools.vt_tools import register_vt_tools
from src.tools.yara_tools import register_yara_tools
from src.utils.compatibility import (
    BinaryCompatibilityChecker,
    CompatibilityLevel,
)
from src.utils.patterns import APIPatterns, CryptoPatterns
from src.utils.security import (
    FileSizeError,
    PathTraversalError,
    UserFacingError,
    safe_error_message,
    safe_regex_compile,
    sanitize_binary_path,
    validate_numeric_range,
)

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


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

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


def get_analysis_context(
    binary_path: str,
    force_reanalyze: bool = False,
    processor: str | None = None,
    loader: str | None = None
) -> dict:
    """
    Get or create analysis context for a binary.

    Args:
        binary_path: Path to binary file
        force_reanalyze: Force re-analysis even if cached
        processor: Optional processor specification (e.g., "x86:LE:64:default")
        loader: Optional loader name (e.g., "PeLoader" for Windows PE, "ElfLoader" for Linux ELF)

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
            allowed_dirs=None,  # None = allow any directory (can be restricted in production)
            max_size_bytes=500 * 1024 * 1024  # 500MB max
        )
        # Use string representation for consistency with rest of codebase
        binary_path = str(validated_path)
    except (PathTraversalError, FileSizeError, FileNotFoundError, ValueError) as e:
        logger.error(f"Path validation failed: {e}")
        raise RuntimeError(f"Invalid binary path: {e}")

    # Check cache first (skip cache if processor/loader specified)
    if not force_reanalyze and not processor and not loader:
        cached_context = cache.get_cached(binary_path)
        if cached_context:
            logger.info(f"Using cached analysis for {binary_path}")
            return cached_context

    # Run Ghidra analysis
    logger.info(f"Analyzing {binary_path} with Ghidra...")
    if processor or loader:
        logger.info(f"Using explicit loader config - Processor: {processor}, Loader: {loader}")

    output_path = cache.cache_dir / f"temp_analysis_{Path(binary_path).stem}.json"
    script_path = Path(__file__).parent / "engines" / "static" / "ghidra" / "scripts"

    try:
        result = runner.analyze(
            binary_path=binary_path,
            script_path=str(script_path),
            script_name="core_analysis.py",
            output_path=str(output_path),
            keep_project=True,  # Keep project for incremental analysis
            timeout=600,
            processor=processor,
            loader=loader
        )

        # Save Ghidra output to debug file for inspection
        debug_file = cache.cache_dir / "ghidra_debug.log"
        try:
            with open(debug_file, 'w') as f:
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

        # Check if output file was created
        if not output_path.exists():
            # Log detailed error internally
            internal_details = f"Ghidra did not create output file: {output_path}\n"
            internal_details += f"Debug log: {debug_file}\n"
            internal_details += f"Stdout: {result.get('stdout', 'N/A')[-500:]}\n"
            internal_details += f"Stderr: {result.get('stderr', 'N/A')[-500:]}"

            # Return safe user-facing error
            raise UserFacingError(
                "Analysis failed. This may be due to an unsupported binary format or corrupted file.",
                internal_details=internal_details
            )

        # Load analysis results
        with open(output_path) as f:
            context = json.load(f)

        # Cache the results
        cache.save_cached(binary_path, context)

        # Clean up temp file
        output_path.unlink()

        logger.info(f"Analysis complete: {result['elapsed_time']:.2f}s")
        return context

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise RuntimeError(f"Failed to analyze binary: {e}")


# ============================================================================
# PHASE 1: CORE TOOLS (P0 - Critical)
# ============================================================================

@app.tool()
@log_to_session
def analyze_binary(
    binary_path: str,
    force_reanalyze: bool = False,
    processor: str | None = None,
    loader: str | None = None,
    skip_compatibility_check: bool = False
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

    Returns:
        Analysis summary with basic statistics, or compatibility warning if issues detected

    Note:
        If Ghidra's AutoImporter fails with "No load spec found", you can manually specify:
        - For x86-64 Windows PE: processor="x86:LE:64:default", loader="PeLoader"
        - For x86-64 Linux ELF: processor="x86:LE:64:default", loader="ElfLoader"
        - For macOS Mach-O: processor="x86:LE:64:default", loader="MachoLoader"

        Common Ghidra loaders: PeLoader, ElfLoader, MachoLoader, BinaryLoader, CoffLoader
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

        context = get_analysis_context(binary_path, force_reanalyze, processor, loader)

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
    except Exception as e:
        # Unexpected error - log internally, return safe message
        logger.exception(f"analyze_binary failed: {e}")
        return safe_error_message("Analysis failed unexpectedly", e)


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

        # Apply filters
        if filter_library:
            pattern = re.compile(filter_library, re.IGNORECASE)
            imports = [i for i in imports if pattern.search(i.get('library', ''))]

        if filter_function:
            pattern = re.compile(filter_function, re.IGNORECASE)
            imports = [i for i in imports if pattern.search(i.get('name', ''))]

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


@app.tool()
@log_to_session
def get_xrefs(
    binary_path: str,
    address: str | None = None,
    function_name: str | None = None,
    direction: str = "to"
) -> str:
    """
    Get cross-references for an address or function.

    Args:
        binary_path: Path to analyzed binary
        address: Hex address to find xrefs for
        function_name: Function name to find xrefs for
        direction: "to" (references to) or "from" (references from)

    Returns:
        List of cross-references with types
    """
    try:
        context = get_analysis_context(binary_path)

        if function_name:
            # Find function by name
            functions = context.get("functions", [])
            function = next((f for f in functions if f.get('name') == function_name), None)

            if not function:
                return f"Error: Function '{function_name}' not found"

            address = function.get('address')

        if not address:
            return "Error: Must provide either address or function_name"

        # For now, show xrefs from strings
        # Full xref implementation would need additional Ghidra script support
        strings = context.get("strings", [])

        result = f"**Cross-references {direction} {address}:**\n\n"

        found = False
        for string in strings:
            for xref in string.get('xrefs', []):
                if (direction == "to" and xref.get('from') == address) or \
                   (direction == "from" and string.get('address') == address):
                    result += f"- {xref.get('from')} -> {string.get('address')}: {string.get('value', '')[:50]}\n"
                    found = True

        if not found:
            result += "*No cross-references found. Note: Full xref support coming soon.*\n"

        return result

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

    Args:
        binary_path: Path to analyzed binary
        function_name: Name of the function to decompile

    Returns:
        Decompiled C pseudocode
    """
    try:
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
            return f"Function '{function_name}' could not be decompiled (decompilation may have failed)."

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


# ============================================================================
# PHASE 2: ENHANCED ANALYSIS TOOLS (P1 - Important)
# ============================================================================

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


@app.tool()
@log_to_session
def search_bytes(
    binary_path: str,
    pattern: str,
    max_results: int = 50
) -> str:
    """
    Search for byte patterns in the binary.

    Args:
        binary_path: Path to analyzed binary
        pattern: Hex byte pattern (e.g., "4883EC20" or "48 83 EC 20")
        max_results: Maximum number of results (default: 50)

    Returns:
        List of addresses where pattern was found
    """
    try:
        # This would require reading the binary directly
        # For now, search in strings as a simple implementation
        context = get_analysis_context(binary_path)

        # Remove spaces and convert to lowercase
        clean_pattern = pattern.replace(' ', '').lower()

        result = f"**Byte Pattern Search: '{pattern}'**\n\n"
        result += "*Note: Full byte search requires direct binary access. Currently searching in extracted data.*\n\n"

        # Search in string data as a placeholder
        strings = context.get("strings", [])
        found = 0

        for string in strings:
            if clean_pattern in string.get('value', '').lower():
                result += f"- Found in string at {string.get('address')}: {string.get('value')[:100]}\n"
                found += 1
                if found >= max_results:
                    break

        if found == 0:
            result += "No matches found.\n"

        return result

    except Exception as e:
        logger.error(f"search_bytes failed: {e}")
        return f"Error: {e}"


# ============================================================================
# PHASE 3: ADVANCED TOOLS (P2 - Nice-to-have)
# ============================================================================

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


# ============================================================================
# ADDITIONAL TOOLS
# ============================================================================

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


# ============================================================================
# ANALYSIS SESSION TOOLS
# ============================================================================

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


# ============================================================================
# CRYPTO ANALYSIS TOOLS
# ============================================================================

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

        data = path.read_bytes()
        entropy = calculate_entropy(data)
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
            out_path = Path(output_path)
            out_path.write_bytes(decrypted)
            output.append("")
            output.append(f"Saved to: {output_path}")

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
            out_path = Path(output_path)
            out_path.write_bytes(decoded)
            output.append("")
            output.append(f"Saved to: {output_path}")

        return "\n".join(output)

    except (PathTraversalError, FileSizeError) as e:
        return safe_error_message("decode_base64_file", e)
    except Exception as e:
        logger.error(f"decode_base64_file failed: {e}")
        return f"Error decoding file: {e}"


# ============================================================================
# PYTHON BYTECODE ANALYSIS TOOLS
# ============================================================================


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

    # Register VirusTotal tools
    register_vt_tools(app, session_manager)

    # Register triage tools
    register_triage_tools(app, session_manager)

    # Register reporting tools
    register_reporting_tools(app, session_manager)

    # Register Yara tools
    register_yara_tools(app, session_manager)

    logger.info("Registered all analysis tools (static, dynamic, VT, triage, reporting, Yara)")
    logger.info(f"Session Directory: {session_manager.store_dir}")

    # Run the FastMCP server (handles stdio automatically)
    app.run()


if __name__ == "__main__":
    main()
