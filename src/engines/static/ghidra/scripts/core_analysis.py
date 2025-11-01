# Ghidra Jython script for comprehensive malware analysis extraction
# This script runs inside Ghidra's JVM environment
# @category: MalwareAnalysis
# ruff: noqa: F821
# Note: currentProgram and other Ghidra globals are provided at runtime

import codecs
import json
import os

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SymbolType
from ghidra.util.task import ConsoleTaskMonitor


def safe_unicode(value):
    """
    Safely convert a value to unicode string, handling non-ASCII characters.

    In Jython/Python 2, str() fails on unicode strings with non-ASCII characters.
    This function handles both str and unicode types safely.
    """
    if value is None:
        return u""

    # If it's already unicode, return it
    if isinstance(value, unicode):
        return value

    # If it's a regular string (bytes), decode it
    if isinstance(value, str):
        try:
            return value.decode('utf-8')
        except (UnicodeDecodeError, AttributeError):
            # If UTF-8 fails, try latin-1 (which accepts all byte values)
            return value.decode('latin-1', 'replace')

    # For other types (Java objects, numbers, etc), convert to unicode
    try:
        return unicode(value)
    except UnicodeDecodeError:
        # Last resort: convert to str first, then decode
        try:
            return str(value).decode('utf-8', 'replace')
        except (UnicodeDecodeError, AttributeError, TypeError):
            return u"<encoding_error>"


def safe_format(fmt_string, *args, **kwargs):
    """
    Safely format and encode a string for printing, handling Unicode.

    In Python 2/Jython, formatting with Unicode values creates a Unicode string,
    which print() tries to encode with ASCII, causing UnicodeEncodeError.
    This function formats and encodes to UTF-8 in one step.

    Returns a UTF-8 encoded byte string safe for printing.
    """
    try:
        # Format the string (may contain Unicode)
        result = fmt_string.format(*args, **kwargs)
        # If it's Unicode, encode to UTF-8; otherwise return as-is
        if isinstance(result, unicode):
            return result.encode('utf-8', 'replace')
        return result
    except (UnicodeEncodeError, UnicodeDecodeError):
        # Fallback: use ASCII with replacement chars
        try:
            result = fmt_string.format(*args, **kwargs)
            if isinstance(result, unicode):
                return result.encode('ascii', 'replace')
            return result
        except Exception:
            return "<formatting_error>"


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

    # Initialize decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(program)

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
        }
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
            "comment": safe_unicode(block.getComment()) if block.getComment() else u""
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

    while function_iterator.hasNext():
        function = function_iterator.next()
        function_count += 1

        if function_count % 100 == 0:
            print(safe_format("    Processed {} functions...", function_count))

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
            "basic_blocks": []
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
        called_functions = function.getCalledFunctions(monitor)
        for called in called_functions:
            function_info["called_functions"].append({
                "name": safe_unicode(called.getName()),
                "address": safe_unicode(called.getEntryPoint())
            })

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
            print(safe_format("    Warning: Could not extract basic blocks for {}: {}", safe_unicode(function.getName()), safe_unicode(e)))

        # Decompile function (for non-thunk, non-external functions)
        if not function.isThunk() and not function.isExternal():
            try:
                decompile_results = decompiler.decompileFunction(function, 30, monitor)
                if decompile_results and decompile_results.decompileCompleted():
                    pseudocode = decompile_results.getDecompiledFunction()
                    if pseudocode:
                        function_info["pseudocode"] = safe_unicode(pseudocode.getC())
            except Exception as e:
                print(safe_format("    Warning: Could not decompile {}: {}", safe_unicode(function.getName()), safe_unicode(e)))

        context["functions"].append(function_info)

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
    print(safe_format("    Functions: {}", len(context["functions"])))
    print(safe_format("    Imports: {}", len(context["imports"])))
    print(safe_format("    Exports: {}", len(context["exports"])))
    print(safe_format("    Strings: {}", len(context["strings"])))
    print(safe_format("    Structures: {}", len(context["data_types"]["structures"])))
    print(safe_format("    Enums: {}", len(context["data_types"]["enums"])))

    return context


def main():
    """Main execution function."""
    try:
        # Get output path from environment variable
        output_path = os.environ.get("GHIDRA_CONTEXT_JSON")
        if not output_path:
            print("[!] ERROR: GHIDRA_CONTEXT_JSON environment variable not set")
            return

        print("[*] Starting comprehensive analysis extraction...")
        print(safe_format("[*] Program: {}", safe_unicode(currentProgram.getName())))
        print(safe_format("[*] Output: {}", output_path))

        # Extract all analysis data
        context = extract_comprehensive_analysis()

        # Write to JSON file with UTF-8 encoding to handle Unicode characters
        print(safe_format("[*] Writing output to {}...", output_path))
        with codecs.open(output_path, 'w', encoding='utf-8') as f:
            json.dump(context, f, indent=2, ensure_ascii=False)

        print(safe_format("[+] Analysis complete! Output saved to: {}", output_path))

    except Exception as e:
        print(safe_format("[!] ERROR during analysis: {}", safe_unicode(e)))
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
