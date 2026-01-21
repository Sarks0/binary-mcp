# Ghidra Python 3 script for comprehensive malware analysis extraction
# @runtime PyGhidra
# @category MalwareAnalysis
# @menupath Tools.Binary MCP.Core Analysis
#
# REQUIRES: Ghidra 12.0+ with PyGhidra support
#
# The @runtime PyGhidra directive tells Ghidra to use Python 3 (PyGhidra)
# instead of Jython 2.7, even when called via analyzeHeadless -postScript.
# This allows us to write pure Python 3 code.
#
# ruff: noqa: F821, E402
# Note: currentProgram and other Ghidra globals are provided at runtime

import json
import os
import sys

# Early diagnostic: Print Python version and execution context
# These prints must happen before Ghidra imports to help debug import failures
print(f"[*] Script starting - Python version: {sys.version_info[:3]}")
print(f"[*] Python executable: {sys.executable}")
print("[*] PyGhidra runtime active")

# Ghidra imports (must be after diagnostic prints for debugging)
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SymbolType
from ghidra.util.task import ConsoleTaskMonitor
from java.lang import InterruptedException, Thread
from java.util.concurrent import Callable, Executors, TimeoutException, TimeUnit


def safe_unicode(value):
    """
    Safely convert a value to string, handling non-ASCII characters.

    In Python 3, all strings are Unicode by default. This function ensures
    consistent string handling across different types (Java objects, Python strings, etc).
    """
    if value is None:
        return ""

    # In Python 3, str is already Unicode
    if isinstance(value, str):
        return value

    # For bytes, decode to string
    if isinstance(value, bytes):
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            # If UTF-8 fails, try latin-1 (which accepts all byte values)
            return value.decode('latin-1', 'replace')

    # For other types (Java objects, numbers, etc), convert to str
    try:
        return str(value)
    except Exception:
        return "<encoding_error>"


def safe_format(fmt_string, *args, **kwargs):
    """
    Safely format a string for printing, handling Unicode.

    In Python 3, strings are Unicode by default and print() handles them correctly.
    This function maintains the same API as the Python 2 version for compatibility.

    Returns a formatted string.
    """
    try:
        return fmt_string.format(*args, **kwargs)
    except Exception:
        return "<formatting_error>"


class DecompileCallable(Callable):
    """
    Java Callable wrapper for decompilation with thread-based timeout.

    This allows us to enforce a hard timeout on decompilation that works
    even when Ghidra's internal decompiler timeout fails to trigger
    (which can happen with anti-analysis code that causes infinite loops).
    """

    def __init__(self, decompiler, function, timeout_seconds, monitor):
        """
        Initialize the callable.

        Args:
            decompiler: DecompInterface instance
            function: Ghidra Function to decompile
            timeout_seconds: Timeout in seconds for decompilation
            monitor: TaskMonitor instance
        """
        self.decompiler = decompiler
        self.function = function
        self.timeout_seconds = timeout_seconds
        self.monitor = monitor
        self.result = None
        self.error = None

    def call(self):
        """Execute decompilation - called by executor thread."""
        try:
            # Use the internal timeout as a first line of defense
            self.result = self.decompiler.decompileFunction(
                self.function, self.timeout_seconds, self.monitor
            )
            return self.result
        except Exception as e:
            self.error = e
            return None


def decompile_with_timeout(decompiler, function, timeout_seconds, monitor, executor):
    """
    Decompile a function with a hard thread-based timeout.

    This provides a robust timeout mechanism that works even when Ghidra's
    internal decompiler timeout fails (e.g., due to anti-analysis code).

    Args:
        decompiler: DecompInterface instance
        function: Ghidra Function to decompile
        timeout_seconds: Timeout in seconds
        monitor: TaskMonitor instance
        executor: ExecutorService for running the decompilation

    Returns:
        tuple: (result, status, error_message)
            - result: DecompileResults or None
            - status: "success", "timeout", "error", "interrupted"
            - error_message: Error description or None
    """
    callable_task = DecompileCallable(decompiler, function, timeout_seconds, monitor)

    try:
        # Submit task and wait with timeout
        future = executor.submit(callable_task)

        try:
            # Wait for result with timeout (add 5 seconds buffer for thread overhead)
            result = future.get(timeout_seconds + 5, TimeUnit.SECONDS)

            if callable_task.error:
                return (None, "error", safe_unicode(callable_task.error))

            return (result, "success", None)

        except TimeoutException:
            # Hard timeout - cancel the future and return
            future.cancel(True)  # True = may interrupt if running
            return (None, "timeout", "Thread timeout exceeded")

    except InterruptedException:
        Thread.currentThread().interrupt()
        return (None, "interrupted", "Decompilation interrupted")

    except Exception as e:
        return (None, "error", safe_unicode(e))


def extract_comprehensive_analysis():
    """Extract comprehensive analysis data from the current program."""

    monitor = ConsoleTaskMonitor()
    program = currentProgram
    listing = program.getListing()
    function_manager = program.getFunctionManager()
    symbol_table = program.getSymbolTable()
    memory = program.getMemory()
    reference_manager = program.getReferenceManager()
    data_type_manager = program.getDataTypeManager()

    # Configurable settings from environment variables
    # GHIDRA_FUNCTION_TIMEOUT: Per-function decompilation timeout in seconds (default: 30)
    # GHIDRA_MAX_FUNCTIONS: Maximum number of functions to analyze (default: unlimited)
    # GHIDRA_SKIP_DECOMPILE: Skip decompilation entirely (faster, but no pseudocode)
    function_timeout = int(os.environ.get("GHIDRA_FUNCTION_TIMEOUT", "30"))
    max_functions = int(os.environ.get("GHIDRA_MAX_FUNCTIONS", "0"))  # 0 = unlimited
    skip_decompile = os.environ.get("GHIDRA_SKIP_DECOMPILE", "").lower() in ("1", "true", "yes")

    print("[*] Analysis settings:")
    print(f"    Function timeout: {function_timeout}s")
    print(f"    Max functions: {max_functions if max_functions > 0 else 'unlimited'}")
    print(f"    Skip decompile: {skip_decompile}")

    # Initialize decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(program)

    # Create a single-thread executor for timeout-controlled decompilation
    # Using a cached thread pool allows reuse of threads for better performance
    decompile_executor = Executors.newCachedThreadPool()

    context = {
        "metadata": {},
        "functions": [],
        "imports": [],
        "exports": [],
        "strings": [],
        "memory_map": [],
        "xrefs": {},
        "data_types": {
            "structures": [],
            "enums": []
        },
        "analysis_stats": {
            "functions_analyzed": 0,
            "functions_skipped": 0,
            "decompile_failures": 0,
            "decompile_timeouts": 0,
            "thread_timeouts": 0,  # Hard thread timeouts (anti-analysis code)
            "internal_timeouts": 0,  # Ghidra's internal decompiler timeouts
            "partial_results": False,
            "function_timeout_setting": function_timeout,
            "max_functions_setting": max_functions if max_functions > 0 else None
        },
        "skipped_functions": []  # Track functions that couldn't be analyzed
    }

    # Extract metadata
    print("[*] Extracting metadata...")
    context["metadata"] = {
        "name": safe_unicode(program.getName()),
        "executable_path": safe_unicode(program.getExecutablePath()),
        "executable_format": safe_unicode(program.getExecutableFormat()),
        "language": safe_unicode(program.getLanguage()),
        "compiler": safe_unicode(program.getCompilerSpec()),
        "image_base": safe_unicode(program.getImageBase()),
        "min_address": safe_unicode(program.getMinAddress()),
        "max_address": safe_unicode(program.getMaxAddress()),
        "creation_date": safe_unicode(program.getCreationDate()),
    }

    # Extract memory map
    print("[*] Extracting memory map...")
    for block in memory.getBlocks():
        block_info = {
            "name": safe_unicode(block.getName()),
            "start": safe_unicode(block.getStart()),
            "end": safe_unicode(block.getEnd()),
            "size": block.getSize(),
            "read": block.isRead(),
            "write": block.isWrite(),
            "execute": block.isExecute(),
            "initialized": block.isInitialized(),
            "comment": safe_unicode(block.getComment()) if block.getComment() else ""
        }
        context["memory_map"].append(block_info)

    # Extract imports
    print("[*] Extracting imports...")
    external_manager = program.getExternalManager()
    for external_name in external_manager.getExternalLibraryNames():
        for symbol in symbol_table.getExternalSymbols(external_name):
            if symbol.getSymbolType() == SymbolType.FUNCTION:
                import_info = {
                    "library": safe_unicode(external_name),
                    "name": safe_unicode(symbol.getName()),
                    "address": safe_unicode(symbol.getAddress()) if symbol.getAddress() else None,
                    "ordinal": None  # Ordinals would need additional parsing
                }
                context["imports"].append(import_info)

    # Extract exports
    print("[*] Extracting exports...")
    entry_points = symbol_table.getExternalEntryPointIterator()
    while entry_points.hasNext():
        address = entry_points.next()
        # Get symbols at this address
        symbols = symbol_table.getSymbols(address)
        for symbol in symbols:
            export_info = {
                "name": safe_unicode(symbol.getName()),
                "address": safe_unicode(address),
                "type": safe_unicode(symbol.getSymbolType())
            }
            context["exports"].append(export_info)
            break  # Usually only one export per address

    # Extract strings
    print("[*] Extracting strings...")
    defined_data = listing.getDefinedData(True)
    string_count = 0
    while defined_data.hasNext() and string_count < 10000:  # Limit to prevent memory issues
        data = defined_data.next()
        if data.hasStringValue():
            string_value = data.getValue()
            # Use safe_unicode to handle non-ASCII characters (like copyright symbols)
            unicode_value = safe_unicode(string_value)
            if unicode_value and len(unicode_value) > 0:
                # Get cross-references to this string
                refs = []
                for ref in reference_manager.getReferencesTo(data.getAddress()):
                    refs.append({
                        "from": safe_unicode(ref.getFromAddress()),
                        "type": safe_unicode(ref.getReferenceType())
                    })

                string_info = {
                    "address": safe_unicode(data.getAddress()),
                    "value": unicode_value[:1000],  # Limit string length
                    "length": len(unicode_value),
                    "type": safe_unicode(data.getDataType()),
                    "xrefs": refs[:50]  # Limit xrefs per string
                }
                context["strings"].append(string_info)
                string_count += 1

    # Extract functions
    print("[*] Extracting functions...")
    function_iterator = function_manager.getFunctions(True)
    function_count = 0
    decompile_timeout_count = 0
    decompile_failure_count = 0
    thread_timeout_count = 0  # Hard thread timeouts (likely anti-analysis)
    internal_timeout_count = 0  # Ghidra's internal decompiler timeouts

    while function_iterator.hasNext():
        function = function_iterator.next()
        function_count += 1

        # Check max functions limit
        if max_functions > 0 and function_count > max_functions:
            print(safe_format("[!] Reached max function limit ({}), stopping analysis", max_functions))
            context["analysis_stats"]["partial_results"] = True
            break

        if function_count % 100 == 0:
            print(safe_format("    Processed {} functions ({} timeouts, {} failures)...",
                              function_count, decompile_timeout_count, decompile_failure_count))

        # Get function signature
        signature = function.getSignature()
        entry_point = function.getEntryPoint()

        # Get basic info
        function_info = {
            "name": safe_unicode(function.getName()),
            "address": safe_unicode(entry_point),
            "signature": safe_unicode(signature),
            "is_thunk": function.isThunk(),
            "is_external": function.isExternal(),
            "parameters": [],
            "local_variables": [],
            "called_functions": [],
            "pseudocode": None,
            "basic_blocks": [],
            "decompile_status": "not_attempted"  # Track decompilation status
        }

        # Get parameters
        for param in function.getParameters():
            param_info = {
                "name": safe_unicode(param.getName()),
                "datatype": safe_unicode(param.getDataType()),
                "storage": safe_unicode(param.getVariableStorage()) if param.getVariableStorage() else None
            }
            function_info["parameters"].append(param_info)

        # Get local variables
        for var in function.getLocalVariables():
            var_info = {
                "name": safe_unicode(var.getName()),
                "datatype": safe_unicode(var.getDataType()),
                "storage": safe_unicode(var.getVariableStorage()) if var.getVariableStorage() else None
            }
            function_info["local_variables"].append(var_info)

        # Get called functions (limited to direct calls)
        try:
            called_functions = function.getCalledFunctions(monitor)
            for called in called_functions:
                function_info["called_functions"].append({
                    "name": safe_unicode(called.getName()),
                    "address": safe_unicode(called.getEntryPoint())
                })
        except Exception as e:
            print(safe_format("    Warning: Could not get called functions for {}: {}",
                              safe_unicode(function.getName()), safe_unicode(e)))

        # Get basic blocks
        try:
            body = function.getBody()
            code_block_iterator = listing.getCodeBlocks(body, monitor)
            while code_block_iterator.hasNext():
                block = code_block_iterator.next()
                block_info = {
                    "start": safe_unicode(block.getMinAddress()),
                    "end": safe_unicode(block.getMaxAddress()),
                    "num_instructions": block.getNumAddresses()
                }
                function_info["basic_blocks"].append(block_info)
        except Exception as e:
            print(safe_format("    Warning: Could not extract basic blocks for {}: {}",
                              safe_unicode(function.getName()), safe_unicode(e)))

        # Decompile function (for non-thunk, non-external functions)
        if skip_decompile:
            function_info["decompile_status"] = "skipped"
        elif not function.isThunk() and not function.isExternal():
            # Use thread-based timeout for robust handling of anti-analysis code
            # This catches cases where Ghidra's internal timeout fails
            decompile_result, status, error_msg = decompile_with_timeout(
                decompiler, function, function_timeout, monitor, decompile_executor
            )

            if status == "timeout":
                # Hard thread timeout - function likely has anti-analysis code
                function_info["decompile_status"] = "thread_timeout"
                decompile_timeout_count += 1
                thread_timeout_count += 1
                context["skipped_functions"].append({
                    "name": safe_unicode(function.getName()),
                    "address": safe_unicode(entry_point),
                    "reason": "thread_timeout",
                    "detail": error_msg
                })
                print(safe_format("    [!] TIMEOUT: {} at {} (thread timeout after {}s)",
                                  safe_unicode(function.getName()), safe_unicode(entry_point),
                                  function_timeout))

            elif status == "error":
                function_info["decompile_status"] = "error"
                decompile_failure_count += 1
                context["skipped_functions"].append({
                    "name": safe_unicode(function.getName()),
                    "address": safe_unicode(entry_point),
                    "reason": "decompile_error",
                    "detail": error_msg
                })
                print(safe_format("    [!] Decompile error for {}: {}",
                                  safe_unicode(function.getName()), error_msg))

            elif status == "interrupted":
                function_info["decompile_status"] = "interrupted"
                decompile_failure_count += 1
                context["skipped_functions"].append({
                    "name": safe_unicode(function.getName()),
                    "address": safe_unicode(entry_point),
                    "reason": "interrupted"
                })
                print(safe_format("    [!] Decompilation interrupted for {}",
                                  safe_unicode(function.getName())))

            elif status == "success" and decompile_result:
                # Check if decompilation actually completed
                if decompile_result.decompileCompleted():
                    pseudocode = decompile_result.getDecompiledFunction()
                    if pseudocode:
                        function_info["pseudocode"] = safe_unicode(pseudocode.getC())
                        function_info["decompile_status"] = "success"
                    else:
                        function_info["decompile_status"] = "empty_result"
                        decompile_failure_count += 1
                else:
                    # Ghidra's internal timeout triggered
                    function_info["decompile_status"] = "internal_timeout"
                    decompile_timeout_count += 1
                    internal_timeout_count += 1
                    context["skipped_functions"].append({
                        "name": safe_unicode(function.getName()),
                        "address": safe_unicode(entry_point),
                        "reason": "ghidra_internal_timeout"
                    })
                    print(safe_format("    [!] Decompile timeout (internal) for {} at {}",
                                      safe_unicode(function.getName()), safe_unicode(entry_point)))
            else:
                function_info["decompile_status"] = "no_result"
                decompile_failure_count += 1
        else:
            function_info["decompile_status"] = "skipped_thunk_or_external"

        context["functions"].append(function_info)

    # Update analysis stats
    context["analysis_stats"]["functions_analyzed"] = function_count
    context["analysis_stats"]["decompile_timeouts"] = decompile_timeout_count
    context["analysis_stats"]["thread_timeouts"] = thread_timeout_count
    context["analysis_stats"]["internal_timeouts"] = internal_timeout_count
    context["analysis_stats"]["decompile_failures"] = decompile_failure_count

    # Extract data types (structures)
    print("[*] Extracting data types...")
    for data_type in data_type_manager.getAllDataTypes():
        type_name = str(type(data_type).__name__)

        if "Structure" in type_name:
            struct_info = {
                "name": safe_unicode(data_type.getName()),
                "length": data_type.getLength(),
                "members": []
            }

            # Get structure members
            if hasattr(data_type, 'getComponents'):
                for component in data_type.getComponents():
                    field_name = component.getFieldName() if component.getFieldName() else component.getDefaultFieldName()
                    member_info = {
                        "name": safe_unicode(field_name),
                        "offset": component.getOffset(),
                        "datatype": safe_unicode(component.getDataType()),
                        "length": component.getLength()
                    }
                    struct_info["members"].append(member_info)

            context["data_types"]["structures"].append(struct_info)

        elif "Enum" in type_name:
            enum_info = {
                "name": safe_unicode(data_type.getName()),
                "length": data_type.getLength(),
                "values": []
            }

            # Get enum values
            if hasattr(data_type, 'getNames'):
                for name in data_type.getNames():
                    enum_info["values"].append({
                        "name": safe_unicode(name),
                        "value": data_type.getValue(name)
                    })

            context["data_types"]["enums"].append(enum_info)

    print("[*] Extraction complete!")
    print(f"    Functions: {len(context['functions'])}")
    print(f"    Imports: {len(context['imports'])}")
    print(f"    Exports: {len(context['exports'])}")
    print(f"    Strings: {len(context['strings'])}")
    print(f"    Structures: {len(context['data_types']['structures'])}")
    print(f"    Enums: {len(context['data_types']['enums'])}")

    # Print analysis statistics
    stats = context["analysis_stats"]
    print("[*] Analysis statistics:")
    print(f"    Functions analyzed: {stats['functions_analyzed']}")
    print(f"    Total decompile timeouts: {stats['decompile_timeouts']}")
    if stats["thread_timeouts"] > 0:
        print(f"      - Thread timeouts (anti-analysis): {stats['thread_timeouts']}")
    if stats["internal_timeouts"] > 0:
        print(f"      - Internal timeouts (Ghidra): {stats['internal_timeouts']}")
    print(f"    Decompile failures: {stats['decompile_failures']}")
    if stats["partial_results"]:
        print("    [!] PARTIAL RESULTS: Analysis was limited by max_functions setting")
    if context["skipped_functions"]:
        print(f"    Skipped functions: {len(context['skipped_functions'])}")

    # Cleanup: shutdown the executor service
    print("[*] Shutting down decompile executor...")
    decompile_executor.shutdown()
    try:
        # Wait up to 10 seconds for tasks to complete
        if not decompile_executor.awaitTermination(10, TimeUnit.SECONDS):
            # Force shutdown if tasks don't complete
            decompile_executor.shutdownNow()
            print("    [!] Forced executor shutdown (some tasks may not have completed)")
    except InterruptedException:
        decompile_executor.shutdownNow()
        Thread.currentThread().interrupt()

    return context


def main():
    """Main execution function."""
    print("[*] core_analysis.py main() started")

    try:
        # Get output path from environment variable
        output_path = os.environ.get("GHIDRA_CONTEXT_JSON")
        print(f"[*] GHIDRA_CONTEXT_JSON = {output_path if output_path else '<NOT SET>'}")

        if not output_path:
            print("[!] ERROR: GHIDRA_CONTEXT_JSON environment variable not set")
            print("[!] Available environment variables:")
            for key in sorted(os.environ.keys()):
                if "GHIDRA" in key.upper() or "PATH" in key.upper():
                    print(f"    {key} = {os.environ.get(key, '')}")
            return

        print("[*] Starting comprehensive analysis extraction...")
        print(f"[*] Program: {safe_unicode(currentProgram.getName())}")
        print(f"[*] Output: {output_path}")

        # Extract all analysis data
        context = extract_comprehensive_analysis()

        # Write to JSON file with UTF-8 encoding to handle Unicode characters
        print(f"[*] Writing output to {output_path}...")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(context, f, indent=2, ensure_ascii=False)

        print(f"[+] Analysis complete! Output saved to: {output_path}")

    except Exception as e:
        print(f"[!] ERROR during analysis: {safe_unicode(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
