"""
Binary compatibility checker for Ghidra analysis.

Detects binary format, architecture, and potential analysis issues BEFORE
invoking Ghidra to provide fast feedback and prevent timeouts.
"""

import logging
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class BinaryFormat(Enum):
    """Supported binary formats."""
    PE = "Portable Executable (PE)"
    ELF = "ELF (Executable and Linkable Format)"
    MACHO = "Mach-O"
    DOTNET = ".NET Assembly (CLR)"
    JAVA_CLASS = "Java Class File"
    MSIL = "MSIL/CIL Assembly"
    RAW = "Raw Binary"
    UNKNOWN = "Unknown"


class CompatibilityLevel(Enum):
    """Analysis compatibility levels."""
    FULL = "full"           # Fully supported, expect good results
    PARTIAL = "partial"     # Supported but with limitations
    LIMITED = "limited"     # May work but expect issues
    UNSUPPORTED = "unsupported"  # Not recommended for Ghidra


@dataclass
class CompatibilityIssue:
    """Represents a compatibility issue or warning."""
    severity: str  # "error", "warning", "info"
    code: str      # Short code for programmatic handling
    message: str   # Human-readable message
    recommendation: str  # What to do about it


@dataclass
class BinaryInfo:
    """Information about a binary file."""
    path: Path
    size: int
    format: BinaryFormat
    architecture: str = "unknown"
    bitness: int = 0  # 32 or 64
    is_dotnet: bool = False
    is_packed: bool = False
    is_signed: bool = False
    has_debug_info: bool = False
    compiler: str = "unknown"
    subsystem: str = "unknown"
    entry_point: int = 0
    image_base: int = 0
    sections: list = field(default_factory=list)
    imports_count: int = 0
    exports_count: int = 0

    # .NET specific
    dotnet_version: str = ""
    dotnet_flags: int = 0
    is_mixed_mode: bool = False  # Native + .NET

    # Analysis metadata
    compatibility: CompatibilityLevel = CompatibilityLevel.FULL
    issues: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


class BinaryCompatibilityChecker:
    """
    Pre-analysis binary compatibility checker.

    Quickly analyzes binary headers to detect format, architecture,
    and potential issues before invoking Ghidra.
    """

    # Magic bytes for format detection
    MAGIC_PE = b'MZ'
    MAGIC_ELF = b'\x7fELF'
    MAGIC_MACHO_32 = b'\xfe\xed\xfa\xce'  # Big-endian
    MAGIC_MACHO_32_LE = b'\xce\xfa\xed\xfe'  # Little-endian
    MAGIC_MACHO_64 = b'\xfe\xed\xfa\xcf'  # Big-endian
    MAGIC_MACHO_64_LE = b'\xcf\xfa\xed\xfe'  # Little-endian
    MAGIC_MACHO_FAT = b'\xca\xfe\xba\xbe'  # Universal binary
    MAGIC_JAVA_CLASS = b'\xca\xfe\xba\xbe'  # Same as fat Mach-O, need context

    # PE signature offset location
    PE_SIGNATURE_OFFSET = 0x3C
    PE_SIGNATURE = b'PE\x00\x00'

    # .NET CLR header constants
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
    COMIMAGE_FLAGS_ILONLY = 0x00000001
    COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
    COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010

    def __init__(self):
        """Initialize the compatibility checker."""
        self.min_file_size = 64  # Minimum valid binary size

    def check_compatibility(self, binary_path: str | Path) -> BinaryInfo:
        """
        Check binary compatibility for Ghidra analysis.

        Args:
            binary_path: Path to the binary file

        Returns:
            BinaryInfo with format detection and compatibility assessment
        """
        path = Path(binary_path)

        if not path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        if not path.is_file():
            raise ValueError(f"Path is not a file: {binary_path}")

        file_size = path.stat().st_size

        if file_size < self.min_file_size:
            info = BinaryInfo(
                path=path,
                size=file_size,
                format=BinaryFormat.UNKNOWN,
                compatibility=CompatibilityLevel.UNSUPPORTED
            )
            info.issues.append(CompatibilityIssue(
                severity="error",
                code="FILE_TOO_SMALL",
                message=f"File is too small ({file_size} bytes) to be a valid executable",
                recommendation="Verify this is the correct file"
            ))
            return info

        # Read header bytes for analysis
        with open(path, 'rb') as f:
            header = f.read(min(4096, file_size))  # Read first 4KB

        # Detect format
        binary_format = self._detect_format(header)

        # Create base info
        info = BinaryInfo(
            path=path,
            size=file_size,
            format=binary_format
        )

        # Format-specific analysis
        if binary_format == BinaryFormat.PE or binary_format == BinaryFormat.DOTNET:
            self._analyze_pe(path, header, info)
        elif binary_format == BinaryFormat.ELF:
            self._analyze_elf(header, info)
        elif binary_format == BinaryFormat.MACHO:
            self._analyze_macho(header, info)
        elif binary_format == BinaryFormat.JAVA_CLASS:
            info.compatibility = CompatibilityLevel.LIMITED
            info.issues.append(CompatibilityIssue(
                severity="warning",
                code="JAVA_CLASS",
                message="Java class files have limited Ghidra support",
                recommendation="Consider using jadx or JD-GUI for Java decompilation"
            ))
        else:
            info.compatibility = CompatibilityLevel.LIMITED
            info.warnings.append("Unknown format - Ghidra will attempt auto-detection")

        # Assess overall compatibility
        self._assess_compatibility(info)

        return info

    def _detect_format(self, header: bytes) -> BinaryFormat:
        """Detect binary format from header bytes."""
        if len(header) < 4:
            return BinaryFormat.UNKNOWN

        # Check for PE (MZ header)
        if header[:2] == self.MAGIC_PE:
            # Verify PE signature
            if len(header) > 0x40:
                pe_offset = struct.unpack('<I', header[self.PE_SIGNATURE_OFFSET:self.PE_SIGNATURE_OFFSET+4])[0]
                if pe_offset < len(header) - 4:
                    if header[pe_offset:pe_offset+4] == self.PE_SIGNATURE:
                        return BinaryFormat.PE  # Will be refined to DOTNET if CLR header found
            return BinaryFormat.PE

        # Check for ELF
        if header[:4] == self.MAGIC_ELF:
            return BinaryFormat.ELF

        # Check for Mach-O
        if header[:4] in (self.MAGIC_MACHO_32, self.MAGIC_MACHO_32_LE,
                          self.MAGIC_MACHO_64, self.MAGIC_MACHO_64_LE):
            return BinaryFormat.MACHO

        # Check for FAT Mach-O or Java class (same magic)
        if header[:4] == self.MAGIC_MACHO_FAT:
            # Distinguish by checking if it looks like Java class file
            if len(header) >= 8:
                # Java class has version numbers after magic
                # minor_version at offset 4-6, major_version at offset 6-8
                major_version = struct.unpack('>H', header[6:8])[0]
                # Java versions are typically 45-65 for major
                if 45 <= major_version <= 70:
                    return BinaryFormat.JAVA_CLASS
            return BinaryFormat.MACHO

        return BinaryFormat.UNKNOWN

    def _analyze_pe(self, path: Path, header: bytes, info: BinaryInfo) -> None:
        """Analyze PE/COFF format binary."""
        try:
            import pefile
            pe = pefile.PE(str(path), fast_load=True)

            # Basic info
            info.architecture = self._get_pe_architecture(pe)
            info.bitness = 64 if pe.FILE_HEADER.Machine == 0x8664 else 32
            info.image_base = pe.OPTIONAL_HEADER.ImageBase
            info.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            info.subsystem = self._get_pe_subsystem(pe)

            # Check for .NET CLR header
            if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
                info.is_dotnet = True
                info.format = BinaryFormat.DOTNET
                self._analyze_dotnet(pe, info)
            elif self._has_clr_header(pe):
                info.is_dotnet = True
                info.format = BinaryFormat.DOTNET
                self._analyze_dotnet(pe, info)

            # Section analysis
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                info.sections.append({
                    'name': section_name,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': section.Characteristics
                })

            # Import/Export counts
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
            ])

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                info.imports_count = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)

            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                info.exports_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

            # Check for packing indicators
            self._check_pe_packing(pe, info)

            # Check entry point
            if info.entry_point == 0:
                info.warnings.append("Entry point is 0x0 - may indicate .NET or packed binary")

            pe.close()

        except ImportError:
            logger.warning("pefile not installed - using basic PE analysis")
            self._analyze_pe_basic(header, info)
        except Exception as e:
            logger.error(f"PE analysis failed: {e}")
            info.warnings.append(f"PE header parsing error: {str(e)[:100]}")

    def _has_clr_header(self, pe) -> bool:
        """Check if PE has CLR/.NET header."""
        try:
            clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[self.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
            return clr_dir.VirtualAddress != 0 and clr_dir.Size != 0
        except (AttributeError, IndexError):
            return False

    def _analyze_dotnet(self, pe, info: BinaryInfo) -> None:
        """Analyze .NET-specific characteristics."""
        try:
            # Get CLR header info
            clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[self.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]

            if clr_dir.VirtualAddress != 0:
                # Read CLR header
                clr_rva = clr_dir.VirtualAddress
                clr_data = pe.get_data(clr_rva, min(clr_dir.Size, 72))

                if len(clr_data) >= 16:
                    # Parse COR20 header (cb at offset 0-4, runtime version at 4-8)
                    major_runtime = struct.unpack('<H', clr_data[4:6])[0]
                    minor_runtime = struct.unpack('<H', clr_data[6:8])[0]
                    flags = struct.unpack('<I', clr_data[16:20])[0] if len(clr_data) >= 20 else 0

                    info.dotnet_version = f"{major_runtime}.{minor_runtime}"
                    info.dotnet_flags = flags

                    # Check if IL-only or mixed mode
                    if flags & self.COMIMAGE_FLAGS_ILONLY:
                        info.is_mixed_mode = False
                    else:
                        info.is_mixed_mode = True
                        info.warnings.append("Mixed-mode assembly (native + .NET) - analysis may be incomplete")

                    # Check for native entry point (P/Invoke heavy)
                    if flags & self.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT:
                        info.warnings.append("Assembly has native entry point - uses P/Invoke heavily")

            # Add .NET-specific issues with MCP tool recommendation
            info.issues.append(CompatibilityIssue(
                severity="warning",
                code="DOTNET_ASSEMBLY",
                message=".NET assemblies have limited native code analysis in Ghidra",
                recommendation="Use the built-in .NET tools instead: "
                              "analyze_dotnet(), decompile_dotnet_type(), get_dotnet_types(). "
                              "These use ILSpyCmd for proper C# decompilation."
            ))

            # Check for obfuscation indicators
            self._check_dotnet_obfuscation(pe, info)

        except Exception as e:
            logger.debug(f"CLR header analysis failed: {e}")
            info.warnings.append("Could not fully parse .NET metadata")

    def _check_dotnet_obfuscation(self, pe, info: BinaryInfo) -> None:
        """Check for .NET obfuscation indicators."""
        obfuscation_indicators = []

        # Check section names for known obfuscators
        obfuscator_sections = {
            '.netsdk': 'Potential obfuscator detected',
            '.dotfus': 'Dotfuscator obfuscation detected',
            '.cnf': 'ConfuserEx obfuscation possible',
            '.vmp': 'VMProtect detected',
            '.themida': 'Themida protection detected',
        }

        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00').lower()
            for obf_section, msg in obfuscator_sections.items():
                if obf_section in section_name:
                    obfuscation_indicators.append(msg)

        # Check for encrypted/packed sections (high entropy, no data)
        for section in pe.sections:
            if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                obfuscation_indicators.append(f"Section '{section.Name.decode('utf-8', errors='ignore').rstrip(chr(0))}' has no raw data - possible packing")

        if obfuscation_indicators:
            info.is_packed = True
            info.issues.append(CompatibilityIssue(
                severity="warning",
                code="DOTNET_OBFUSCATED",
                message="Obfuscation/protection detected: " + "; ".join(obfuscation_indicators),
                recommendation="Consider using de4dot or other .NET deobfuscators first"
            ))

    def _check_pe_packing(self, pe, info: BinaryInfo) -> None:
        """Check for PE packing indicators."""
        packing_indicators = []

        # Known packer section names
        packer_sections = {
            'upx': 'UPX packer',
            '.aspack': 'ASPack',
            '.adata': 'ASPack',
            '.nsp': 'NsPack',
            '.pec': 'PECompact',
            '.perplex': 'Perplex',
            '.petite': 'Petite',
            '.spack': 'Simple Pack',
            '.svkp': 'SVKP',
            '.taz': 'PESpin',
            '.tsuarch': 'TSULoader',
            '.tsustub': 'TSULoader',
            '.packed': 'Generic packer',
            '.yp': 'Y0da Protector',
            '.y0da': 'Y0da Protector',
            'pebundle': 'PEBundle',
            'pelock': 'PELock',
            '.vmprotect': 'VMProtect',
            '.vmp0': 'VMProtect',
            '.vmp1': 'VMProtect',
            '.themida': 'Themida',
            '.enigma': 'Enigma Protector',
        }

        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00').lower()
            for packer_section, packer_name in packer_sections.items():
                if packer_section in section_name:
                    packing_indicators.append(packer_name)

        # Check for suspicious section characteristics
        for section in pe.sections:
            chars = section.Characteristics
            # Writable + Executable is suspicious
            if (chars & 0x20000000) and (chars & 0x80000000):  # EXECUTE + WRITE
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                if section_name not in ['.text', '.code']:
                    packing_indicators.append(f"RWX section: {section_name}")

        # Import count heuristics - be careful not to flag export-only DLLs
        # DLLs with many exports but few/no imports are common and legitimate
        has_significant_exports = info.exports_count > 10

        if info.imports_count == 0 and not info.is_dotnet:
            # Only flag as suspicious if there are OTHER packing indicators
            # or if the binary has no exports either (unusual for legitimate binaries)
            if packing_indicators:  # Already have other indicators
                packing_indicators.append("No imports detected")
            elif not has_significant_exports:
                # No imports AND no significant exports - more suspicious
                packing_indicators.append("No imports or exports detected - may be packed or unusual binary")
            # else: DLL with many exports but no imports is normal (export-only DLL)
        elif info.imports_count < 5 and info.imports_count > 0:
            # Very few imports combined with other indicators suggests packing
            if packing_indicators:
                packing_indicators.append(f"Very few imports ({info.imports_count})")

        if packing_indicators:
            # Determine severity based on indicator strength
            has_known_packer = any(
                indicator for indicator in packing_indicators
                if any(packer in indicator for packer in ['UPX', 'ASPack', 'VMProtect', 'Themida', 'Enigma'])
            )

            info.is_packed = True
            info.issues.append(CompatibilityIssue(
                severity="warning" if has_known_packer else "info",
                code="PACKED_BINARY",
                message="Possible packing/protection detected: " + "; ".join(set(packing_indicators)),
                recommendation="Analysis will proceed. If results seem incomplete, consider unpacking first."
            ))

    def _analyze_pe_basic(self, header: bytes, info: BinaryInfo) -> None:
        """Basic PE analysis without pefile library."""
        try:
            # Get PE header offset
            pe_offset = struct.unpack('<I', header[self.PE_SIGNATURE_OFFSET:self.PE_SIGNATURE_OFFSET+4])[0]

            if pe_offset + 24 < len(header):
                # Read machine type
                machine = struct.unpack('<H', header[pe_offset+4:pe_offset+6])[0]

                machine_types = {
                    0x014c: ('x86', 32),
                    0x8664: ('x86-64', 64),
                    0x01c0: ('ARM', 32),
                    0xaa64: ('ARM64', 64),
                }

                if machine in machine_types:
                    info.architecture, info.bitness = machine_types[machine]

        except Exception as e:
            logger.debug(f"Basic PE analysis failed: {e}")

    def _analyze_elf(self, header: bytes, info: BinaryInfo) -> None:
        """Analyze ELF format binary with detailed compatibility checking."""
        if len(header) < 52:
            info.issues.append(CompatibilityIssue(
                severity="error",
                code="ELF_HEADER_TRUNCATED",
                message="ELF header is truncated or incomplete",
                recommendation="File may be corrupted or incomplete"
            ))
            return

        # ELF class (32/64 bit)
        ei_class = header[4]
        info.bitness = 64 if ei_class == 2 else 32

        # ELF data encoding (endianness)
        ei_data = header[5]
        is_little_endian = ei_data == 1
        endian_str = "LE" if is_little_endian else "BE"
        unpack_fmt = '<' if is_little_endian else '>'

        # ELF version
        ei_version = header[6]
        if ei_version != 1:
            info.warnings.append(f"Unusual ELF version: {ei_version}")

        # OS/ABI
        ei_osabi = header[7]
        osabi_names = {
            0: "UNIX System V",
            1: "HP-UX",
            2: "NetBSD",
            3: "Linux",
            6: "Solaris",
            7: "AIX",
            8: "IRIX",
            9: "FreeBSD",
            10: "Tru64",
            11: "Novell Modesto",
            12: "OpenBSD",
            64: "ARM EABI",
            97: "ARM",
            255: "Standalone",
        }
        info.compiler = osabi_names.get(ei_osabi, f"Unknown ABI ({ei_osabi})")

        # ELF type (offset 16-18)
        e_type = struct.unpack(f'{unpack_fmt}H', header[16:18])[0]
        elf_types = {
            0: "None",
            1: "Relocatable",
            2: "Executable",
            3: "Shared object",
            4: "Core dump",
        }
        info.subsystem = elf_types.get(e_type, f"Unknown ({e_type})")

        # Check for core dumps
        if e_type == 4:
            info.issues.append(CompatibilityIssue(
                severity="warning",
                code="ELF_CORE_DUMP",
                message="This is a core dump file, not an executable",
                recommendation="Core dumps have limited analysis value in Ghidra"
            ))

        # ELF machine type (offset 18-20)
        machine = struct.unpack(f'{unpack_fmt}H', header[18:20])[0]

        # Extended machine type mapping with Ghidra processor specs
        machine_types = {
            0x00: ('None', None),
            0x02: ('SPARC', 'sparc:BE:32:default'),
            0x03: ('x86', 'x86:LE:32:default'),
            0x08: ('MIPS', f'MIPS:{endian_str}:32:default'),
            0x14: ('PowerPC', 'PowerPC:BE:32:default'),
            0x15: ('PowerPC64', 'PowerPC:BE:64:default'),
            0x16: ('S390', None),  # Limited Ghidra support
            0x28: ('ARM', f'ARM:{endian_str}:32:v7'),
            0x2B: ('SPARC64', 'sparc:BE:64:default'),
            0x32: ('IA-64', None),  # Limited Ghidra support
            0x3E: ('x86-64', 'x86:LE:64:default'),
            0xB7: ('ARM64', 'AARCH64:LE:64:v8A'),
            0xF3: ('RISC-V', f'RISCV:{endian_str}:{info.bitness}:RV{info.bitness}GC'),
            0xF7: ('BPF', None),  # eBPF - limited support
            0x101: ('LoongArch', None),  # Very new, limited support
        }

        arch_info = machine_types.get(machine, (f'unknown (0x{machine:x})', None))
        info.architecture = arch_info[0]

        # Store suggested Ghidra processor spec
        ghidra_processor = arch_info[1]
        if ghidra_processor:
            info.warnings.append(
                f"Suggested Ghidra processor: {ghidra_processor}"
            )

        # Check for architectures with limited Ghidra support
        limited_support_archs = {0x16, 0x32, 0xF7, 0x101}  # S390, IA-64, BPF, LoongArch
        if machine in limited_support_archs:
            info.issues.append(CompatibilityIssue(
                severity="warning",
                code="ELF_LIMITED_ARCH",
                message=f"Architecture '{info.architecture}' has limited Ghidra support",
                recommendation="Analysis may be incomplete or require custom processor modules"
            ))

        # Unknown architecture
        if machine not in machine_types:
            info.issues.append(CompatibilityIssue(
                severity="warning",
                code="ELF_UNKNOWN_ARCH",
                message=f"Unknown ELF machine type: 0x{machine:x}",
                recommendation=(
                    "Ghidra may not auto-detect this architecture. "
                    "Try specifying processor and loader explicitly: "
                    "analyze_binary(..., loader='ElfLoader', processor='<spec>')"
                )
            ))

        # Entry point (varies by bitness)
        if info.bitness == 64 and len(header) >= 32:
            info.entry_point = struct.unpack(f'{unpack_fmt}Q', header[24:32])[0]
        elif len(header) >= 28:
            info.entry_point = struct.unpack(f'{unpack_fmt}I', header[24:28])[0]

        # Check for stripped binary indicators
        # Section header info is at different offsets for 32/64-bit
        if info.bitness == 64 and len(header) >= 64:
            e_shoff = struct.unpack(f'{unpack_fmt}Q', header[40:48])[0]
            e_shnum = struct.unpack(f'{unpack_fmt}H', header[60:62])[0]
            e_shstrndx = struct.unpack(f'{unpack_fmt}H', header[62:64])[0]
        elif len(header) >= 52:
            e_shoff = struct.unpack(f'{unpack_fmt}I', header[32:36])[0]
            e_shnum = struct.unpack(f'{unpack_fmt}H', header[48:50])[0]
            e_shstrndx = struct.unpack(f'{unpack_fmt}H', header[50:52])[0]
        else:
            e_shoff = 0
            e_shnum = 0
            e_shstrndx = 0

        # No section headers often indicates stripped binary
        if e_shnum == 0 or e_shoff == 0:
            info.warnings.append(
                "No section headers - binary may be stripped or statically linked"
            )
            info.has_debug_info = False
        elif e_shstrndx == 0 or e_shstrndx >= e_shnum:
            info.warnings.append(
                "Invalid section string table index - binary may be obfuscated"
            )

        # Default to full compatibility unless issues found
        info.compatibility = CompatibilityLevel.FULL

    def _analyze_macho(self, header: bytes, info: BinaryInfo) -> None:
        """Analyze Mach-O format binary."""
        if len(header) < 8:
            return

        magic = header[:4]

        if magic in (self.MAGIC_MACHO_64, self.MAGIC_MACHO_64_LE):
            info.bitness = 64
        else:
            info.bitness = 32

        # CPU type is at offset 4
        if len(header) >= 8:
            if magic in (self.MAGIC_MACHO_32_LE, self.MAGIC_MACHO_64_LE):
                cpu_type = struct.unpack('<I', header[4:8])[0]
            else:
                cpu_type = struct.unpack('>I', header[4:8])[0]

            cpu_types = {
                0x00000007: 'x86',
                0x01000007: 'x86-64',
                0x0000000C: 'ARM',
                0x0100000C: 'ARM64',
            }

            info.architecture = cpu_types.get(cpu_type, f'unknown (0x{cpu_type:x})')

        info.compatibility = CompatibilityLevel.FULL

    def _get_pe_architecture(self, pe) -> str:
        """Get architecture string from PE machine type."""
        machine_types = {
            0x014c: 'x86',
            0x8664: 'x86-64',
            0x01c0: 'ARM',
            0xaa64: 'ARM64',
            0x01c4: 'ARMv7',
        }
        return machine_types.get(pe.FILE_HEADER.Machine, f'unknown (0x{pe.FILE_HEADER.Machine:x})')

    def _get_pe_subsystem(self, pe) -> str:
        """Get subsystem string from PE optional header."""
        subsystems = {
            0: 'Unknown',
            1: 'Native',
            2: 'Windows GUI',
            3: 'Windows Console',
            5: 'OS/2 Console',
            7: 'POSIX Console',
            9: 'Windows CE',
            10: 'EFI Application',
            11: 'EFI Boot Driver',
            12: 'EFI Runtime Driver',
            13: 'EFI ROM',
            14: 'Xbox',
            16: 'Windows Boot',
        }
        return subsystems.get(pe.OPTIONAL_HEADER.Subsystem, 'Unknown')

    def _assess_compatibility(self, info: BinaryInfo) -> None:
        """Assess overall compatibility based on collected information."""
        # Start with full compatibility
        info.compatibility = CompatibilityLevel.FULL

        # Downgrade based on issues
        has_error = any(issue.severity == "error" for issue in info.issues)
        has_warning = any(issue.severity == "warning" for issue in info.issues)

        if has_error:
            info.compatibility = CompatibilityLevel.UNSUPPORTED
        elif info.is_dotnet and not info.is_mixed_mode:
            # Pure .NET assemblies have limited Ghidra support
            info.compatibility = CompatibilityLevel.LIMITED
        elif info.is_dotnet and info.is_mixed_mode:
            # Mixed-mode has partial support
            info.compatibility = CompatibilityLevel.PARTIAL
        elif info.is_packed:
            info.compatibility = CompatibilityLevel.PARTIAL
        elif has_warning:
            info.compatibility = CompatibilityLevel.PARTIAL
        elif info.format == BinaryFormat.UNKNOWN:
            info.compatibility = CompatibilityLevel.LIMITED

    def format_report(self, info: BinaryInfo) -> str:
        """
        Format compatibility check results as a human-readable report.

        Args:
            info: BinaryInfo from check_compatibility()

        Returns:
            Formatted string report
        """
        lines = []

        # Header
        lines.append("=" * 60)
        lines.append("BINARY COMPATIBILITY CHECK")
        lines.append("=" * 60)
        lines.append("")

        # Compatibility status with clear indicator
        status_icons = {
            CompatibilityLevel.FULL: "[OK]",
            CompatibilityLevel.PARTIAL: "[PARTIAL]",
            CompatibilityLevel.LIMITED: "[LIMITED]",
            CompatibilityLevel.UNSUPPORTED: "[NOT RECOMMENDED]",
        }

        status_icon = status_icons.get(info.compatibility, "[?]")
        lines.append(f"Status: {status_icon} {info.compatibility.value.upper()}")
        lines.append("")

        # Basic info
        lines.append("**Binary Information:**")
        lines.append(f"- File: {info.path.name}")
        lines.append(f"- Size: {info.size:,} bytes ({info.size / 1024 / 1024:.2f} MB)")
        lines.append(f"- Format: {info.format.value}")
        lines.append(f"- Architecture: {info.architecture}")
        lines.append(f"- Bitness: {info.bitness}-bit")

        if info.subsystem != "unknown":
            lines.append(f"- Subsystem: {info.subsystem}")

        if info.image_base:
            lines.append(f"- Image Base: 0x{info.image_base:08X}")

        if info.entry_point:
            lines.append(f"- Entry Point: 0x{info.entry_point:08X}")

        lines.append("")

        # .NET specific info
        if info.is_dotnet:
            lines.append("**.NET Information:**")
            lines.append(f"- Runtime Version: {info.dotnet_version or 'Unknown'}")
            lines.append(f"- Assembly Type: {'Mixed-mode (Native + Managed)' if info.is_mixed_mode else 'IL-only (Pure Managed)'}")
            lines.append("")

        # Statistics
        if info.imports_count or info.exports_count or info.sections:
            lines.append("**Statistics:**")
            if info.imports_count:
                lines.append(f"- Imports: {info.imports_count}")
            if info.exports_count:
                lines.append(f"- Exports: {info.exports_count}")
            if info.sections:
                lines.append(f"- Sections: {len(info.sections)}")
            lines.append("")

        # Flags
        flags = []
        if info.is_dotnet:
            flags.append(".NET Assembly")
        if info.is_packed:
            flags.append("Packed/Protected")
        if info.is_signed:
            flags.append("Signed")

        if flags:
            lines.append(f"**Flags:** {', '.join(flags)}")
            lines.append("")

        # Issues
        if info.issues:
            lines.append("**Issues:**")
            for issue in info.issues:
                severity_prefix = {
                    "error": "[ERROR]",
                    "warning": "[WARNING]",
                    "info": "[INFO]"
                }.get(issue.severity, "[?]")

                lines.append(f"\n{severity_prefix} {issue.code}")
                lines.append(f"  {issue.message}")
                lines.append(f"  → {issue.recommendation}")
            lines.append("")

        # Warnings
        if info.warnings:
            lines.append("**Warnings:**")
            for warning in info.warnings:
                lines.append(f"- {warning}")
            lines.append("")

        # Recommendations
        lines.append("**Recommendations:**")

        if info.compatibility == CompatibilityLevel.FULL:
            lines.append("- Binary is fully compatible with Ghidra analysis")
            lines.append("- Proceed with analyze_binary() for best results")

        elif info.compatibility == CompatibilityLevel.PARTIAL:
            lines.append("- Analysis will work but some features may be limited")
            if info.is_packed:
                lines.append("- Consider unpacking the binary first for better results")
                lines.append("- Use x64dbg dynamic analysis to dump unpacked code")

        elif info.compatibility == CompatibilityLevel.LIMITED:
            if info.is_dotnet:
                lines.append("- This is a .NET assembly - Ghidra has LIMITED .NET support")
                lines.append("- RECOMMENDED: Use dnSpy or ILSpy for .NET decompilation")
                lines.append("- Ghidra will show metadata but may miss managed code details")
                lines.append("- Analysis will be slow due to .NET metadata processing")
            else:
                lines.append("- Binary format has limited support")
                lines.append("- Analysis may produce incomplete results")

        elif info.compatibility == CompatibilityLevel.UNSUPPORTED:
            lines.append("- Binary is NOT recommended for Ghidra analysis")
            lines.append("- Consider alternative tools for this format")

        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)


# Module-level instance for convenience
_checker = None


def get_checker() -> BinaryCompatibilityChecker:
    """Get or create the singleton compatibility checker."""
    global _checker
    if _checker is None:
        _checker = BinaryCompatibilityChecker()
    return _checker


def check_binary_compatibility(binary_path: str | Path) -> BinaryInfo:
    """
    Convenience function to check binary compatibility.

    Args:
        binary_path: Path to binary file

    Returns:
        BinaryInfo with compatibility assessment
    """
    return get_checker().check_compatibility(binary_path)


def format_compatibility_report(binary_path: str | Path) -> str:
    """
    Convenience function to get formatted compatibility report.

    Args:
        binary_path: Path to binary file

    Returns:
        Formatted string report
    """
    checker = get_checker()
    info = checker.check_compatibility(binary_path)
    return checker.format_report(info)
