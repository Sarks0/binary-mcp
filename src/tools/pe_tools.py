"""
PE structure analysis tools.

Provides comprehensive PE file structure parsing using pefile,
returning complete header, section, import, export, resource,
and metadata information in a single fast tool call.
"""

import hashlib
import logging
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# --- Lookup Tables ---

MACHINE_TYPES = {
    0x0: "Unknown",
    0x014C: "x86 (i386)",
    0x0166: "MIPS R4000",
    0x0169: "MIPS R10000",
    0x01A2: "Hitachi SH3",
    0x01A3: "Hitachi SH3 DSP",
    0x01C0: "ARM",
    0x01C4: "ARMv7 (Thumb-2)",
    0x01F0: "PowerPC",
    0x0200: "IA-64 (Itanium)",
    0x0266: "MIPS16",
    0x5032: "RISC-V 32-bit",
    0x5064: "RISC-V 64-bit",
    0x8664: "x64 (AMD64)",
    0xAA64: "ARM64 (AArch64)",
}

SUBSYSTEM_NAMES = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows Console",
    5: "OS/2 Console",
    7: "POSIX Console",
    9: "Windows CE",
    10: "EFI Application",
    11: "EFI Boot Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows Boot",
}

FILE_CHARACTERISTICS = {
    0x0001: "RELOCS_STRIPPED",
    0x0002: "EXECUTABLE_IMAGE",
    0x0004: "LINE_NUMS_STRIPPED",
    0x0008: "LOCAL_SYMS_STRIPPED",
    0x0020: "LARGE_ADDRESS_AWARE",
    0x0100: "32BIT_MACHINE",
    0x0200: "DEBUG_STRIPPED",
    0x0400: "REMOVABLE_RUN_FROM_SWAP",
    0x0800: "NET_RUN_FROM_SWAP",
    0x1000: "SYSTEM",
    0x2000: "DLL",
    0x4000: "UP_SYSTEM_ONLY",
}

DLL_CHARACTERISTICS = {
    0x0020: "HIGH_ENTROPY_VA",
    0x0040: "DYNAMIC_BASE (ASLR)",
    0x0080: "FORCE_INTEGRITY",
    0x0100: "NX_COMPAT (DEP)",
    0x0200: "NO_ISOLATION",
    0x0400: "NO_SEH",
    0x0800: "NO_BIND",
    0x1000: "APPCONTAINER",
    0x2000: "WDM_DRIVER",
    0x4000: "GUARD_CF",
    0x8000: "TERMINAL_SERVER_AWARE",
}

SECTION_CHARACTERISTICS = {
    0x00000020: "CODE",
    0x00000040: "INITIALIZED_DATA",
    0x00000080: "UNINITIALIZED_DATA",
    0x02000000: "DISCARDABLE",
    0x04000000: "NOT_CACHED",
    0x08000000: "NOT_PAGED",
    0x10000000: "SHARED",
    0x20000000: "EXECUTE",
    0x40000000: "READ",
    0x80000000: "WRITE",
}

DATA_DIRECTORY_NAMES = [
    "Export", "Import", "Resource", "Exception",
    "Security", "Relocation", "Debug", "Architecture",
    "GlobalPtr", "TLS", "Load Config", "Bound Import",
    "IAT", "Delay Import", "CLR Runtime", "Reserved",
]

# Known Rich header tool IDs (comp.id >> 16) mapped to compiler/linker names
RICH_TOOL_IDS = {
    0x0001: "Import0",
    0x0004: "Linker",
    0x0006: "CVTOMF",
    0x0007: "Export",
    0x000A: "Assembler (MASM)",
    0x000F: "Linker",
    0x0019: "Import",
    0x001C: "Resource Compiler",
    0x005D: "Utc1310 (VS2003 C/C++)",
    0x006D: "Utc1400 (VS2005 C/C++)",
    0x0078: "Utc1400 (VS2005 C++)",
    0x0083: "Utc1500 (VS2008 C/C++)",
    0x0093: "Utc1600 (VS2010 C/C++)",
    0x00AA: "Utc1700 (VS2012 C/C++)",
    0x00AB: "Utc1700 (VS2012 C++)",
    0x00C7: "Utc1800 (VS2013 C/C++)",
    0x00C8: "Utc1800 (VS2013 C++)",
    0x00D9: "Utc1900 (VS2015 C/C++)",
    0x00DA: "Utc1900 (VS2015 C++)",
    0x00E0: "Resource Compiler (VS2015)",
    0x0104: "Utc1910 (VS2017 C/C++)",
    0x0105: "Utc1910 (VS2017 C++)",
    0x010E: "Linker (VS2017)",
    0x0112: "Utc1920 (VS2019 C/C++)",
    0x0113: "Utc1920 (VS2019 C++)",
    0x0116: "Linker (VS2019)",
    0x0120: "Utc1930 (VS2022 C/C++)",
    0x0121: "Utc1930 (VS2022 C++)",
    0x0124: "Linker (VS2022)",
}


# --- Helper Functions ---

def _format_flags(value: int, flag_map: dict) -> list[str]:
    """Decode a bitfield into a list of human-readable flag names."""
    return [name for bit, name in sorted(flag_map.items()) if value & bit]


def _format_timestamp(timestamp: int) -> str:
    """Convert PE timestamp to readable UTC string."""
    if timestamp == 0:
        return "Not set"
    if timestamp == 0xFFFFFFFF:
        return "Invalid (0xFFFFFFFF)"
    try:
        dt = datetime.fromtimestamp(timestamp, tz=UTC)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, ValueError, OverflowError):
        return f"Invalid (0x{timestamp:08X})"


def _format_size(size_bytes: int) -> str:
    """Format byte count as human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes:,} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes:,} bytes ({size_bytes / 1024:.1f} KB)"
    else:
        return f"{size_bytes:,} bytes ({size_bytes / (1024 * 1024):.1f} MB)"


def _section_table(pe) -> list[str]:
    """Format the section table with entropy and decoded flags."""
    lines = [f"--- Sections ({len(pe.sections)}) ---"]
    lines.append(f"  {'Name':<10} {'VirtAddr':<10} {'VirtSize':<10} {'RawSize':<10} {'Entropy':<8} Flags")
    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
        entropy = section.get_entropy()
        flags = ", ".join(_format_flags(section.Characteristics, SECTION_CHARACTERISTICS))
        lines.append(
            f"  {name:<10} 0x{section.VirtualAddress:<8X} 0x{section.Misc_VirtualSize:<8X} "
            f"0x{section.SizeOfRawData:<8X} {entropy:<8.2f} {flags}"
        )
    return lines


def _parse_imports(pe) -> list[str]:
    """Parse and format the import table."""
    lines = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT") or not pe.DIRECTORY_ENTRY_IMPORT:
        lines.append("--- Imports ---")
        lines.append("No imports")
        return lines

    total_funcs = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
    num_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
    lines.append(f"--- Imports ({num_dlls} DLLs, {total_funcs} functions) ---")

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("utf-8", errors="ignore") if entry.dll else "Unknown"
        func_names = []
        for imp in entry.imports:
            if imp.name:
                func_names.append(imp.name.decode("utf-8", errors="ignore"))
            elif imp.ordinal:
                func_names.append(f"ord({imp.ordinal})")
        lines.append(f"{dll_name} ({len(func_names)}):")
        # Wrap function names at ~80 chars per line
        line = "  "
        for i, name in enumerate(func_names):
            separator = ", " if i > 0 else ""
            if len(line) + len(separator) + len(name) > 100:
                lines.append(line)
                line = "  " + name
            else:
                line += separator + name
        if line.strip():
            lines.append(line)

    return lines


def _parse_exports(pe) -> list[str]:
    """Parse and format the export table."""
    lines = ["--- Exports ---"]
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT") or not pe.DIRECTORY_ENTRY_EXPORT:
        lines.append("No exports")
        return lines

    symbols = pe.DIRECTORY_ENTRY_EXPORT.symbols
    dll_name = ""
    if pe.DIRECTORY_ENTRY_EXPORT.name:
        dll_name = pe.DIRECTORY_ENTRY_EXPORT.name.decode("utf-8", errors="ignore")
        lines.append(f"DLL Name: {dll_name}")
    lines.append(f"Total: {len(symbols)} exports")

    for sym in symbols[:200]:  # Cap at 200 for readability
        name = sym.name.decode("utf-8", errors="ignore") if sym.name else None
        fwd = sym.forwarder.decode("utf-8", errors="ignore") if sym.forwarder else None
        if fwd:
            lines.append(f"  ord({sym.ordinal}) {name or ''} -> {fwd}")
        elif name:
            lines.append(f"  ord({sym.ordinal}) {name} @ 0x{sym.address:X}")
        else:
            lines.append(f"  ord({sym.ordinal}) @ 0x{sym.address:X}")
    if len(symbols) > 200:
        lines.append(f"  ... and {len(symbols) - 200} more")

    return lines


def _parse_resources(pe) -> list[str]:
    """Parse resources: version info strings and resource type summary."""
    lines = ["--- Resources ---"]
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") or not pe.DIRECTORY_ENTRY_RESOURCE:
        lines.append("No resources")
        return lines

    # Version info extraction
    version_info = {}
    if hasattr(pe, "FileInfo"):
        try:
            for file_info_list in pe.FileInfo:
                for entry in file_info_list:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            for key, value in st.entries.items():
                                k = key.decode("utf-8", errors="ignore") if isinstance(key, bytes) else str(key)
                                v = value.decode("utf-8", errors="ignore") if isinstance(value, bytes) else str(value)
                                if v.strip():
                                    version_info[k] = v
        except (AttributeError, TypeError):
            pass

    if version_info:
        lines.append("Version Info:")
        # Show common fields in a logical order
        priority_keys = [
            "CompanyName", "ProductName", "FileDescription",
            "FileVersion", "ProductVersion", "OriginalFilename",
            "InternalName", "LegalCopyright",
        ]
        shown = set()
        for key in priority_keys:
            if key in version_info:
                lines.append(f"  {key}: {version_info[key]}")
                shown.add(key)
        for key, value in version_info.items():
            if key not in shown:
                lines.append(f"  {key}: {value}")

    # Resource type summary
    import pefile as _pefile
    type_counts: dict[str, int] = {}
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id is not None:
            type_name = _pefile.RESOURCE_TYPE.get(entry.id, f"Unknown({entry.id})")
        elif entry.name:
            type_name = str(entry.name)
        else:
            type_name = "Unknown"

        count = 0
        if hasattr(entry, "directory") and entry.directory:
            count = len(entry.directory.entries)
        else:
            count = 1
        type_counts[type_name] = type_counts.get(type_name, 0) + count

    if type_counts:
        summary = ", ".join(f"{name} ({count})" for name, count in sorted(type_counts.items()))
        lines.append(f"Resource Types: {summary}")

    return lines


def _parse_debug_info(pe) -> list[str]:
    """Parse debug directory for PDB path and debug type."""
    lines = ["--- Debug Info ---"]
    if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG") or not pe.DIRECTORY_ENTRY_DEBUG:
        lines.append("No debug info")
        return lines

    debug_type_names = {
        0: "Unknown", 1: "COFF", 2: "CodeView", 3: "FPO",
        4: "Misc", 5: "Exception", 6: "Fixup", 9: "Borland",
        10: "BBT", 11: "Clsid", 12: "VC Feature", 13: "POGO",
        14: "ILTCG", 16: "Repro", 17: "Embedded",
    }

    for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
        dtype = debug_type_names.get(debug_entry.struct.Type, f"Type({debug_entry.struct.Type})")
        lines.append(f"Type: {dtype}")
        lines.append(f"Timestamp: {_format_timestamp(debug_entry.struct.TimeDateStamp)}")

        # Extract PDB path from CodeView entries
        if debug_entry.struct.Type == 2 and hasattr(debug_entry, "entry") and debug_entry.entry:
            entry = debug_entry.entry
            if hasattr(entry, "PdbFileName"):
                pdb = entry.PdbFileName
                if isinstance(pdb, bytes):
                    pdb = pdb.decode("utf-8", errors="ignore").rstrip("\x00")
                lines.append(f"PDB Path: {pdb}")
            if hasattr(entry, "Signature_String"):
                lines.append(f"GUID: {entry.Signature_String}")

    return lines


def _parse_tls(pe) -> list[str]:
    """Parse TLS directory for callback addresses."""
    lines = ["--- TLS ---"]
    if not hasattr(pe, "DIRECTORY_ENTRY_TLS") or not pe.DIRECTORY_ENTRY_TLS:
        lines.append("No TLS directory")
        return lines

    tls = pe.DIRECTORY_ENTRY_TLS.struct
    lines.append(f"Raw Data: 0x{tls.StartAddressOfRawData:X} - 0x{tls.EndAddressOfRawData:X}")
    lines.append(f"Index Address: 0x{tls.AddressOfIndex:X}")
    lines.append(f"Callbacks Address: 0x{tls.AddressOfCallBacks:X}")

    # Read callback table
    if tls.AddressOfCallBacks:
        callbacks = []
        try:
            pointer_size = 8 if pe.OPTIONAL_HEADER.Magic == 0x20B else 4
            callback_rva = tls.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
            for i in range(32):  # Safety limit
                data = pe.get_data(callback_rva + i * pointer_size, pointer_size)
                if pointer_size == 8:
                    addr = int.from_bytes(data, "little")
                else:
                    addr = int.from_bytes(data, "little")
                if addr == 0:
                    break
                callbacks.append(addr)
        except Exception:
            pass

        if callbacks:
            lines.append(f"TLS Callbacks: {len(callbacks)} found (malware indicator!)")
            for addr in callbacks:
                lines.append(f"  0x{addr:X}")
        else:
            lines.append("TLS Callbacks: None")

    return lines


def _parse_rich_header(pe) -> list[str]:
    """Parse Rich header for compiler/linker metadata."""
    lines = ["--- Rich Header ---"]
    if not hasattr(pe, "RICH_HEADER") or not pe.RICH_HEADER:
        lines.append("No Rich header")
        return lines

    lines.append(f"{'Tool':<35} {'Build':<10} Count")
    for comp_id, count in pe.RICH_HEADER.values:
        tool_id = comp_id >> 16
        build = comp_id & 0xFFFF
        tool_name = RICH_TOOL_IDS.get(tool_id, f"Unknown (0x{tool_id:04X})")
        lines.append(f"  {tool_name:<33} {build:<10} {count}")

    return lines


def _parse_relocations(pe) -> list[str]:
    """Parse base relocations (full detail only)."""
    lines = ["--- Relocations ---"]
    if not hasattr(pe, "DIRECTORY_ENTRY_BASERELOC") or not pe.DIRECTORY_ENTRY_BASERELOC:
        lines.append("No relocations")
        return lines

    total = sum(len(block.entries) for block in pe.DIRECTORY_ENTRY_BASERELOC)
    lines.append(f"Total: {total} relocations across {len(pe.DIRECTORY_ENTRY_BASERELOC)} blocks")
    return lines


def _parse_delay_imports(pe) -> list[str]:
    """Parse delay import directory (full detail only)."""
    lines = ["--- Delay Imports ---"]
    if not hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT") or not pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        lines.append("No delay imports")
        return lines

    for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        dll_name = entry.dll.decode("utf-8", errors="ignore") if entry.dll else "Unknown"
        func_count = len(entry.imports)
        func_names = []
        for imp in entry.imports:
            if imp.name:
                func_names.append(imp.name.decode("utf-8", errors="ignore"))
            elif imp.ordinal:
                func_names.append(f"ord({imp.ordinal})")
        lines.append(f"{dll_name} ({func_count}): {', '.join(func_names)}")

    return lines


def _parse_load_config(pe) -> list[str]:
    """Parse load configuration directory (full detail only)."""
    lines = ["--- Load Config ---"]
    if not hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG") or not pe.DIRECTORY_ENTRY_LOAD_CONFIG:
        lines.append("No load config")
        return lines

    lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
    if hasattr(lc, "SecurityCookie"):
        lines.append(f"Security Cookie: 0x{lc.SecurityCookie:X}")
    if hasattr(lc, "GuardCFCheckFunctionPointer") and lc.GuardCFCheckFunctionPointer:
        lines.append(f"Guard CF Check: 0x{lc.GuardCFCheckFunctionPointer:X}")
    if hasattr(lc, "GuardCFFunctionCount"):
        lines.append(f"Guard CF Function Count: {lc.GuardCFFunctionCount}")
    if hasattr(lc, "GuardFlags") and lc.GuardFlags:
        lines.append(f"Guard Flags: 0x{lc.GuardFlags:X}")

    return lines


def _parse_bound_imports(pe) -> list[str]:
    """Parse bound import directory (full detail only)."""
    lines = ["--- Bound Imports ---"]
    if not hasattr(pe, "DIRECTORY_ENTRY_BOUND_IMPORT") or not pe.DIRECTORY_ENTRY_BOUND_IMPORT:
        lines.append("No bound imports")
        return lines

    for entry in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
        name = entry.name.decode("utf-8", errors="ignore") if entry.name else "Unknown"
        ts = _format_timestamp(entry.struct.TimeDateStamp)
        lines.append(f"  {name} (bound: {ts})")

    return lines


def _parse_exceptions(pe) -> list[str]:
    """Parse exception directory -- x64 RUNTIME_FUNCTION entries (full detail only)."""
    lines = ["--- Exception Handlers ---"]
    if not hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION") or not pe.DIRECTORY_ENTRY_EXCEPTION:
        lines.append("No exception directory")
        return lines

    lines.append(f"RUNTIME_FUNCTION entries: {len(pe.DIRECTORY_ENTRY_EXCEPTION)}")
    return lines


def _detect_overlay(pe, file_path: Path, include_hex: bool = False) -> list[str]:
    """Detect overlay data appended after PE structure."""
    lines = ["--- Overlay ---"]
    try:
        offset = pe.get_overlay_data_start_offset()
        if offset is None:
            lines.append("No overlay")
            return lines

        file_size = file_path.stat().st_size
        overlay_size = file_size - offset
        if overlay_size <= 0:
            lines.append("No overlay")
            return lines

        lines.append(f"Offset: 0x{offset:X}")
        lines.append(f"Size: {_format_size(overlay_size)}")

        if include_hex and overlay_size > 0:
            data = file_path.read_bytes()[offset:offset + 256]
            hex_lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i + 16]
                hex_part = " ".join(f"{b:02X}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                hex_lines.append(f"  {offset + i:08X}: {hex_part:<48} {ascii_part}")
            lines.append("First 256 bytes:")
            lines.extend(hex_lines)
    except Exception:
        lines.append("Could not determine overlay")

    return lines


# --- Registration ---

def register_pe_tools(app, session_manager=None):
    """Register PE structure analysis tools with the MCP app."""
    from src.utils.security import (
        FileSizeError,
        PathTraversalError,
        safe_error_message,
        sanitize_binary_path,
    )

    @app.tool()
    def get_pe_info(binary_path: str, detail_level: str = "standard") -> str:
        """
        Get comprehensive PE file structure information.

        Returns complete PE headers, sections, imports, exports, resources,
        debug info, TLS, Rich header, and more -- all from a single fast call
        using pefile (no Ghidra dependency).

        Args:
            binary_path: Path to the PE file to analyze
            detail_level: Level of detail - "basic", "standard", or "full"
                - basic: Headers, sections, data directory summary (~50ms)
                - standard: + imports, exports, resources, debug, TLS,
                  Rich header, imphash, section hashes (~200ms)
                - full: + relocations, delay imports, load config,
                  exceptions, overlay hex dump, PE warnings (~500ms)

        Returns:
            Formatted PE structure analysis

        Example:
            get_pe_info("/path/to/malware.exe")
            get_pe_info("/path/to/sample.dll", detail_level="full")
        """
        try:
            binary_path = sanitize_binary_path(binary_path)
            path = Path(binary_path)

            if detail_level not in ("basic", "standard", "full"):
                return (
                    f"Invalid detail_level '{detail_level}'. "
                    "Must be one of: basic, standard, full"
                )

            import pefile

            try:
                pe = pefile.PE(str(path), fast_load=True)
            except pefile.PEFormatError as e:
                return f"Not a valid PE file: {e}"

            try:
                file_size = path.stat().st_size
                output: list[str] = []

                output.append("PE Structure Analysis")
                output.append(f"File: {path.name}")
                output.append(f"Size: {_format_size(file_size)}")
                output.append(f"Detail: {detail_level}")
                output.append("")

                # --- Headers (always) ---
                output.append("--- Headers ---")
                machine = MACHINE_TYPES.get(
                    pe.FILE_HEADER.Machine,
                    f"Unknown (0x{pe.FILE_HEADER.Machine:04X})",
                )
                output.append(f"Machine: {machine}")
                output.append(f"Sections: {pe.FILE_HEADER.NumberOfSections}")
                output.append(f"Compile Time: {_format_timestamp(pe.FILE_HEADER.TimeDateStamp)}")
                chars = _format_flags(pe.FILE_HEADER.Characteristics, FILE_CHARACTERISTICS)
                output.append(f"Characteristics: {', '.join(chars) if chars else 'None'}")
                magic = "PE32+" if pe.OPTIONAL_HEADER.Magic == 0x20B else "PE32"
                output.append(f"Format: {magic}")
                output.append(f"ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:X}")
                output.append(f"EntryPoint: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
                subsys = SUBSYSTEM_NAMES.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown")
                output.append(f"Subsystem: {subsys}")
                dll_chars = _format_flags(pe.OPTIONAL_HEADER.DllCharacteristics, DLL_CHARACTERISTICS)
                output.append(f"DllCharacteristics: {', '.join(dll_chars) if dll_chars else 'None'}")
                output.append(f"SectionAlignment: 0x{pe.OPTIONAL_HEADER.SectionAlignment:X}")
                output.append(f"FileAlignment: 0x{pe.OPTIONAL_HEADER.FileAlignment:X}")
                output.append(f"SizeOfImage: 0x{pe.OPTIONAL_HEADER.SizeOfImage:X}")
                output.append(f"SizeOfHeaders: 0x{pe.OPTIONAL_HEADER.SizeOfHeaders:X}")

                is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
                is_driver = pe.OPTIONAL_HEADER.Subsystem == 1
                pe_type = "DLL" if is_dll else "Driver" if is_driver else "EXE"
                output.append(f"Type: {pe_type}")
                output.append("")

                # --- Section Table (always) ---
                output.extend(_section_table(pe))
                output.append("")

                # --- Data Directory Summary (always) ---
                output.append("--- Data Directories ---")
                for i, name in enumerate(DATA_DIRECTORY_NAMES):
                    if i < len(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
                        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[i]
                        if dd.VirtualAddress != 0:
                            output.append(f"  {name}: RVA=0x{dd.VirtualAddress:X}, Size=0x{dd.Size:X}")
                output.append("")

                # --- Overlay (always) ---
                output.extend(_detect_overlay(pe, path, include_hex=(detail_level == "full")))
                output.append("")

                # --- Standard + Full: parse data directories ---
                if detail_level in ("standard", "full"):
                    dirs_to_parse = [
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                    ]
                    if detail_level == "full":
                        dirs_to_parse.extend([
                            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"],
                            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
                            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"],
                            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"],
                            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"],
                        ])

                    try:
                        pe.parse_data_directories(directories=dirs_to_parse)
                    except Exception as e:
                        output.append(f"Warning: Partial directory parse failure: {e}")
                        output.append("")

                    output.extend(_parse_imports(pe))
                    output.append("")
                    output.extend(_parse_exports(pe))
                    output.append("")
                    output.extend(_parse_resources(pe))
                    output.append("")
                    output.extend(_parse_debug_info(pe))
                    output.append("")
                    output.extend(_parse_tls(pe))
                    output.append("")
                    output.extend(_parse_rich_header(pe))
                    output.append("")

                    # Section hashes
                    output.append("--- Section Hashes ---")
                    for section in pe.sections:
                        name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                        try:
                            data = section.get_data()
                            md5 = hashlib.md5(data).hexdigest()  # noqa: S324
                            line = f"  {name}: MD5={md5}"
                            if detail_level == "full":
                                sha256 = hashlib.sha256(data).hexdigest()
                                line += f", SHA256={sha256}"
                            output.append(line)
                        except Exception:
                            output.append(f"  {name}: (could not read)")
                    output.append("")

                    # Imphash
                    try:
                        imphash = pe.get_imphash()
                        if imphash:
                            output.append(f"Imphash: {imphash}")
                            output.append("")
                    except Exception:
                        pass

                # --- Full only ---
                if detail_level == "full":
                    output.extend(_parse_relocations(pe))
                    output.append("")
                    output.extend(_parse_delay_imports(pe))
                    output.append("")
                    output.extend(_parse_load_config(pe))
                    output.append("")
                    output.extend(_parse_bound_imports(pe))
                    output.append("")
                    output.extend(_parse_exceptions(pe))
                    output.append("")

                    # Rich header hash
                    if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
                        try:
                            rich_hash = hashlib.md5(pe.RICH_HEADER.raw_data).hexdigest()  # noqa: S324
                            output.append(f"Rich Header Hash: {rich_hash}")
                            output.append("")
                        except Exception:
                            pass

                    # PE parser warnings
                    warnings = pe.get_warnings()
                    if warnings:
                        output.append("--- PE Parser Warnings ---")
                        for w in warnings:
                            output.append(f"  {w}")
                        output.append("")

                return "\n".join(output)

            finally:
                pe.close()

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("get_pe_info", e)
        except Exception as e:
            logger.error(f"get_pe_info failed: {e}")
            return safe_error_message("Failed to analyze PE file", e)

    logger.info("Registered 1 PE structure tools")
