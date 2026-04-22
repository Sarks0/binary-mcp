"""
Shared binary reader that opens a file once and caches format structures.

Replaces the per-call file opening pattern used in control_flow_tools and
function_hash_tools, eliminating thousands of redundant file opens when
processing large binaries with many basic blocks.
"""

import logging
import struct
from pathlib import Path

logger = logging.getLogger(__name__)


class BinaryReader:
    """
    Context manager that opens a binary file once and provides efficient
    virtual-address-to-bytes translation.

    Supports PE, ELF, and Mach-O formats. Detects format on open and
    caches all segment/section mappings for O(1) lookups.

    Usage::

        with BinaryReader("/path/to/binary") as reader:
            data = reader.read_bytes_at_va(0x401000, 64)
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._file = None
        self._format: str | None = None
        # PE cached state
        self._pe = None
        self._pe_image_base: int = 0
        # ELF/Mach-O cached segments: list of (va_start, va_end, file_offset)
        self._segments: list[tuple[int, int, int]] = []

    def __enter__(self):
        self._open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._close()
        return False

    def _open(self):
        """Detect format and cache all segment mappings."""
        with open(self._path, "rb") as f:
            magic = f.read(4)

        if magic[:2] == b"MZ":
            self._open_pe()
        elif magic[:4] == b"\x7fELF":
            self._open_elf()
        elif magic[:4] in (
            b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
            b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
        ):
            self._open_macho()
        else:
            # Unknown format -- open file for raw reads
            self._format = "raw"
            self._file = open(self._path, "rb")  # noqa: SIM115

    def _open_pe(self):
        """Open PE and cache the pefile object (fast_load)."""
        try:
            import pefile
        except ImportError:
            logger.debug("pefile not available")
            self._format = "raw"
            self._file = open(self._path, "rb")  # noqa: SIM115
            return

        self._pe = pefile.PE(str(self._path), fast_load=True)
        self._pe_image_base = self._pe.OPTIONAL_HEADER.ImageBase
        self._format = "pe"

    def _open_elf(self):
        """Parse ELF PT_LOAD segments into cached tuples."""
        self._format = "elf"
        self._file = open(self._path, "rb")  # noqa: SIM115
        try:
            from elftools.elf.elffile import ELFFile

            elf = ELFFile(self._file)
            for segment in elf.iter_segments():
                if segment.header.p_type != "PT_LOAD":
                    continue
                va_start = segment.header.p_vaddr
                file_size = segment.header.p_filesz
                file_offset = segment.header.p_offset
                if file_size > 0:
                    self._segments.append((va_start, va_start + file_size, file_offset))
        except ImportError:
            logger.debug("pyelftools not available, falling back to raw reads")
            self._format = "raw"
        except Exception as e:
            logger.debug(f"ELF segment parsing failed: {e}")
            self._format = "raw"

    def _open_macho(self):
        """Parse Mach-O LC_SEGMENT/LC_SEGMENT_64 load commands."""
        self._format = "macho"
        self._file = open(self._path, "rb")  # noqa: SIM115

        try:
            self._file.seek(0)
            magic = self._file.read(4)

            if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
                endian = "<"
            else:
                endian = ">"

            is_64 = magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
            header_size = 32 if is_64 else 28

            self._file.seek(0)
            header = self._file.read(header_size)
            if len(header) < header_size:
                self._format = "raw"
                return

            ncmds = struct.unpack(endian + "I", header[16:20])[0]

            offset = header_size
            for _ in range(ncmds):
                self._file.seek(offset)
                cmd_header = self._file.read(8)
                if len(cmd_header) < 8:
                    break
                cmd, cmdsize = struct.unpack(endian + "II", cmd_header)

                # LC_SEGMENT = 1, LC_SEGMENT_64 = 0x19
                if cmd in (1, 0x19):
                    self._file.seek(offset)
                    if is_64:
                        seg_data = self._file.read(72)
                        if len(seg_data) >= 72:
                            seg_vmaddr = struct.unpack(endian + "Q", seg_data[24:32])[0]
                            seg_fileoff = struct.unpack(endian + "Q", seg_data[40:48])[0]
                            seg_filesize = struct.unpack(endian + "Q", seg_data[48:56])[0]
                            if seg_filesize > 0:
                                self._segments.append(
                                    (seg_vmaddr, seg_vmaddr + seg_filesize, seg_fileoff)
                                )
                    else:
                        seg_data = self._file.read(56)
                        if len(seg_data) >= 56:
                            seg_vmaddr = struct.unpack(endian + "I", seg_data[24:28])[0]
                            seg_fileoff = struct.unpack(endian + "I", seg_data[32:36])[0]
                            seg_filesize = struct.unpack(endian + "I", seg_data[36:40])[0]
                            if seg_filesize > 0:
                                self._segments.append(
                                    (seg_vmaddr, seg_vmaddr + seg_filesize, seg_fileoff)
                                )

                offset += cmdsize
        except Exception as e:
            logger.debug(f"Mach-O segment parsing failed: {e}")
            self._format = "raw"

    def _close(self):
        """Release all resources."""
        if self._pe is not None:
            self._pe.close()
            self._pe = None
        if self._file is not None:
            self._file.close()
            self._file = None

    def read_bytes_at_va(self, va: int, size: int) -> bytes | None:
        """
        Read *size* bytes from the binary at virtual address *va*.

        Returns raw bytes, or None if the VA cannot be resolved.
        """
        if self._format == "pe":
            return self._read_pe(va, size)
        if self._format in ("elf", "macho"):
            return self._read_segments(va, size)
        if self._format == "raw" and self._file is not None:
            return self._read_raw(va, size)
        return None

    def _read_pe(self, va: int, size: int) -> bytes | None:
        """Read bytes from PE using cached pefile object."""
        if self._pe is None:
            return None
        try:
            rva = va - self._pe_image_base
            if rva < 0:
                rva = va  # VA might already be an RVA
            self._pe.get_offset_from_rva(rva)  # validates RVA is within a section
            data = self._pe.get_data(rva, size)
            return bytes(data)
        except Exception:
            return None

    def _read_segments(self, va: int, size: int) -> bytes | None:
        """Read bytes using cached ELF/Mach-O segment list."""
        if self._file is None:
            return None
        for seg_start, seg_end, seg_fileoff in self._segments:
            if seg_start <= va < seg_end:
                file_offset = seg_fileoff + (va - seg_start)
                self._file.seek(file_offset)
                return self._file.read(size)
        return None

    def _read_raw(self, va: int, size: int) -> bytes | None:
        """Fallback: treat VA as a file offset."""
        if self._file is None:
            return None
        try:
            self._file.seek(va)
            return self._file.read(size)
        except Exception:
            return None

    @property
    def format(self) -> str | None:
        """Return detected format: 'pe', 'elf', 'macho', 'raw', or None."""
        return self._format
