"""
Binary MCP Server for comprehensive binary analysis.

Provides 30+ tools for static and dynamic binary analysis:
- Static analysis via Ghidra (headless mode)
- Dynamic analysis via x64dbg (native plugin)
"""

import json
import logging
import re
import sys
import time
from pathlib import Path

from fastmcp import FastMCP

from src.engines.static.ghidra.analysis_store import AnalysisStore
from src.engines.static.ghidra.project_cache import ProjectCache
from src.engines.static.ghidra.runner import GhidraRunner
from src.tools.dynamic_tools import register_dynamic_tools
from src.utils.patterns import APIPatterns, CryptoPatterns

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
analysis_store = AnalysisStore()
api_patterns = APIPatterns()
crypto_patterns = CryptoPatterns()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_analysis_context(binary_path: str, force_reanalyze: bool = False) -> dict:
    """
    Get or create analysis context for a binary.

    Args:
        binary_path: Path to binary file
        force_reanalyze: Force re-analysis even if cached

    Returns:
        Analysis context dict

    Raises:
        RuntimeError: If analysis fails
    """
    # Check cache first
    if not force_reanalyze:
        cached_context = cache.get_cached(binary_path)
        if cached_context:
            logger.info(f"Using cached analysis for {binary_path}")
            return cached_context

    # Run Ghidra analysis
    logger.info(f"Analyzing {binary_path} with Ghidra...")

    output_path = cache.cache_dir / f"temp_analysis_{Path(binary_path).stem}.json"
    script_path = Path(__file__).parent / "engines" / "static" / "ghidra" / "scripts"

    try:
        result = runner.analyze(
            binary_path=binary_path,
            script_path=str(script_path),
            script_name="core_analysis.py",
            output_path=str(output_path),
            keep_project=True,  # Keep project for incremental analysis
            timeout=600
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
            error_msg = f"Ghidra did not create output file: {output_path}\n"
            error_msg += f"Check debug log at: {debug_file}\n\n"
            error_msg += f"Ghidra stdout (last 500 chars):\n{result.get('stdout', 'N/A')[-500:]}\n\n"
            error_msg += f"Ghidra stderr:\n{result.get('stderr', 'N/A')[-500:]}"
            print(f"ERROR: {error_msg}", file=sys.stderr)
            raise RuntimeError(error_msg)

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
def analyze_binary(
    binary_path: str,
    force_reanalyze: bool = False
) -> str:
    """
    Analyze a binary file with Ghidra headless analyzer.

    This is the foundation tool that must be called before using other analysis tools.
    It loads the binary, runs Ghidra's auto-analysis, and extracts comprehensive data.

    Args:
        binary_path: Path to the binary file to analyze
        force_reanalyze: Force re-analysis even if cached (default: False)

    Returns:
        Analysis summary with basic statistics
    """
    try:
        context = get_analysis_context(binary_path, force_reanalyze)

        metadata = context.get("metadata", {})
        functions = context.get("functions", [])
        imports = context.get("imports", [])
        strings = context.get("strings", [])

        summary = f"""Binary Analysis Complete: {metadata.get('name', 'Unknown')}

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
- Structures: {len(context.get('data_types', {}).get('structures', []))}
- Enums: {len(context.get('data_types', {}).get('enums', []))}

Analysis cached for fast subsequent queries.
Use other tools like get_functions, get_imports, decompile_function to explore the binary.
"""
        return summary

    except Exception as e:
        logger.error(f"analyze_binary failed: {e}")
        return f"Error: {e}"


@app.tool()
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
        context = get_analysis_context(binary_path)
        functions = context.get("functions", [])

        # Apply filters
        if exclude_external:
            functions = [f for f in functions if not f.get('is_external', False)]

        if filter_name:
            pattern = re.compile(filter_name, re.IGNORECASE)
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
        context = get_analysis_context(binary_path)
        strings = context.get("strings", [])

        # Apply filters
        strings = [s for s in strings if s.get('length', 0) >= min_length]

        if filter_pattern:
            pattern = re.compile(filter_pattern, re.IGNORECASE)
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

        # Analysis store info
        store_stats = analysis_store.get_stats()
        result += "**Analysis Storage:**\n"
        result += f"- Stored Analyses: {store_stats['total_analyses']}\n"
        result += f"- Storage Size: {store_stats['total_size_mb']:.2f} MB\n"
        result += f"- Storage Directory: `{analysis_store.store_dir}`\n"

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


# ============================================================================
# ANALYSIS STORAGE TOOLS
# ============================================================================

@app.tool()
def save_analysis(
    name: str,
    content: str,
    binary_path: str | None = None,
    tags: list[str] | None = None
) -> str:
    """
    Save an analysis report for later retrieval.

    Use this to persist comprehensive analysis reports that can be retrieved
    later, even if the conversation crashes or resets. Each analysis is stored
    with a unique ID.

    Args:
        name: Human-readable name for the analysis (e.g., "Malware Sample XYZ Analysis")
        content: Full analysis content (markdown/text format)
        binary_path: Path to the analyzed binary (optional)
        tags: List of tags for categorization (e.g., ["malware", "trojan", "ransomware"])

    Returns:
        Success message with analysis ID
    """
    try:
        # Get binary hash if path provided
        binary_hash = None
        if binary_path:
            try:
                import hashlib
                sha256 = hashlib.sha256()
                with open(binary_path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        sha256.update(chunk)
                binary_hash = sha256.hexdigest()
            except Exception as e:
                logger.warning(f"Could not hash binary: {e}")

        # Save analysis
        analysis_id = analysis_store.save(
            name=name,
            content=content,
            binary_path=binary_path,
            binary_hash=binary_hash,
            tags=tags or []
        )

        result = "**Analysis Saved Successfully**\n\n"
        result += f"- **Analysis ID:** `{analysis_id}`\n"
        result += f"- **Name:** {name}\n"
        result += f"- **Content Length:** {len(content):,} characters\n"
        if binary_path:
            result += f"- **Binary:** {Path(binary_path).name}\n"
        if tags:
            result += f"- **Tags:** {', '.join(tags)}\n"
        result += "\n**To retrieve this analysis later, use:**\n"
        result += f"```\nget_analysis('{analysis_id}')\n```\n"

        return result

    except Exception as e:
        logger.error(f"save_analysis failed: {e}")
        return f"Error: {e}"


@app.tool()
def get_analysis(analysis_id: str) -> str:
    """
    Retrieve a previously saved analysis report.

    Args:
        analysis_id: UUID of the saved analysis

    Returns:
        The saved analysis content
    """
    try:
        analysis = analysis_store.get(analysis_id)

        if not analysis:
            return f"Error: Analysis '{analysis_id}' not found. Use list_analyses() to see available analyses."

        result = f"# {analysis.get('name', 'Unknown')}\n\n"
        result += f"**Analysis ID:** `{analysis_id}`\n"
        result += f"**Created:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(analysis.get('created_at', 0)))}\n"
        result += f"**Updated:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(analysis.get('updated_at', 0)))}\n"

        if analysis.get('binary_path'):
            result += f"**Binary:** {Path(analysis.get('binary_path')).name}\n"
        if analysis.get('tags'):
            result += f"**Tags:** {', '.join(analysis.get('tags', []))}\n"

        result += "\n---\n\n"
        result += analysis.get('content', '')

        return result

    except Exception as e:
        logger.error(f"get_analysis failed: {e}")
        return f"Error: {e}"


@app.tool()
def list_analyses(
    tag_filter: str | None = None,
    binary_name_filter: str | None = None,
    limit: int = 20
) -> str:
    """
    List all saved analysis reports.

    Args:
        tag_filter: Filter by tag (optional)
        binary_name_filter: Filter by binary name pattern (optional)
        limit: Maximum number of results (default: 20)

    Returns:
        List of saved analyses with metadata
    """
    try:
        analyses = analysis_store.list(
            tag_filter=tag_filter,
            binary_name_filter=binary_name_filter,
            limit=limit
        )

        if not analyses:
            result = "**No Saved Analyses Found**\n\n"
            if tag_filter or binary_name_filter:
                result += "Try removing filters or save a new analysis using save_analysis().\n"
            else:
                result += "Save your first analysis using save_analysis().\n"
            return result

        result = f"**Saved Analyses: {len(analyses)} found**\n\n"

        for analysis in analyses:
            analysis_id = analysis.get('analysis_id', 'Unknown')
            name = analysis.get('name', 'Unknown')
            created = time.strftime('%Y-%m-%d %H:%M', time.localtime(analysis.get('created_at', 0)))
            updated = time.strftime('%Y-%m-%d %H:%M', time.localtime(analysis.get('updated_at', 0)))
            binary_name = analysis.get('binary_name', 'Unknown')
            tags = analysis.get('tags', [])
            size_kb = analysis.get('size_bytes', 0) / 1024

            result += f"### {name}\n"
            result += f"- **ID:** `{analysis_id[:8]}...` (use full ID: `{analysis_id}`)\n"
            result += f"- **Binary:** {binary_name}\n"
            result += f"- **Created:** {created}\n"
            result += f"- **Updated:** {updated}\n"
            result += f"- **Size:** {size_kb:.1f} KB\n"
            if tags:
                result += f"- **Tags:** {', '.join(tags)}\n"
            result += f"\n**Retrieve:** `get_analysis('{analysis_id}')`\n\n"

        # Show stats
        stats = analysis_store.get_stats()
        result += "\n**Storage Stats:**\n"
        result += f"- Total: {stats['total_analyses']} analyses\n"
        result += f"- Size: {stats['total_size_mb']:.2f} MB\n"

        return result

    except Exception as e:
        logger.error(f"list_analyses failed: {e}")
        return f"Error: {e}"


@app.tool()
def delete_analysis(analysis_id: str) -> str:
    """
    Delete a saved analysis report.

    Args:
        analysis_id: UUID of the analysis to delete

    Returns:
        Success/failure message
    """
    try:
        # Get analysis name first
        analysis = analysis_store.get(analysis_id)
        if analysis:
            name = analysis.get('name', 'Unknown')
        else:
            return f"Error: Analysis '{analysis_id}' not found."

        # Delete
        success = analysis_store.delete(analysis_id)

        if success:
            return f"**Analysis Deleted**\n\nSuccessfully deleted: {name} (ID: {analysis_id[:8]}...)"
        else:
            return f"Error: Failed to delete analysis '{analysis_id}'"

    except Exception as e:
        logger.error(f"delete_analysis failed: {e}")
        return f"Error: {e}"


@app.tool()
def append_to_analysis(analysis_id: str, content: str) -> str:
    """
    Append additional content to an existing analysis report.

    Useful for adding follow-up analysis, new findings, or updates to
    previously saved reports.

    Args:
        analysis_id: UUID of the analysis to append to
        content: Content to append

    Returns:
        Success message
    """
    try:
        success = analysis_store.append(analysis_id, content)

        if success:
            analysis = analysis_store.get(analysis_id)
            new_length = analysis.get('content_length', 0) if analysis else 0

            result = "**Content Appended Successfully**\n\n"
            result += f"- **Analysis ID:** `{analysis_id[:8]}...`\n"
            result += f"- **New Length:** {new_length:,} characters\n"
            result += f"- **Added:** {len(content):,} characters\n"
            return result
        else:
            return f"Error: Failed to append to analysis '{analysis_id}'. Analysis may not exist."

    except Exception as e:
        logger.error(f"append_to_analysis failed: {e}")
        return f"Error: {e}"


def main():
    """Run the MCP server."""
    logger.info("Starting Binary MCP Server...")
    logger.info(f"Ghidra Path: {runner.ghidra_path}")
    logger.info(f"Cache Directory: {cache.cache_dir}")

    # Register dynamic analysis tools
    register_dynamic_tools(app)
    logger.info("Registered static + dynamic analysis tools")

    # Run the FastMCP server (handles stdio automatically)
    app.run()


if __name__ == "__main__":
    main()
