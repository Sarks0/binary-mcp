"""
Python packer analysis and extraction.

Supports detection and extraction of:
- py2exe packed executables
- PyInstaller packed executables
- cx_Freeze packed executables
- Nuitka compiled binaries
"""

import logging
import struct
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)


def _safe_extract_path(output_dir: Path, entry_name: str) -> Path:
    """
    Safely resolve archive entry path preventing directory traversal (Zip Slip).

    Args:
        output_dir: Base output directory
        entry_name: Archive entry name/path

    Returns:
        Safe path within output_dir

    Raises:
        ValueError: If path traversal attempt detected
    """
    # Normalize the entry name - handle both forward and back slashes
    # Remove any null bytes that could be used for truncation attacks
    safe_name = entry_name.replace("\x00", "").replace("\\", "/")

    # Remove leading slashes and handle .. components
    parts = []
    for part in safe_name.split("/"):
        # Skip empty parts and current directory references
        if not part or part == ".":
            continue
        # Skip parent directory references entirely
        if part == "..":
            continue
        # Skip parts that are only dots (potential bypass attempts)
        if part.strip(".") == "":
            continue
        parts.append(part)

    if not parts:
        # Entry name resolved to empty - use a safe default
        safe_name = "extracted_file"
    else:
        safe_name = "/".join(parts)

    # Construct and resolve the target path
    target = (output_dir / safe_name).resolve()

    # Verify target is within output directory
    try:
        target.relative_to(output_dir.resolve())
    except ValueError:
        raise ValueError(f"Path traversal attempt detected: {entry_name}")

    return target


class PythonPackerAnalyzer:
    """Analyzes and extracts Python packed executables."""

    # Known Python packer signatures
    SIGNATURES = {
        "py2exe": [
            b"PYTHONSCRIPT",
            b"py2exe",
            b"python27.dll",
            b"python37.dll",
            b"python38.dll",
            b"python39.dll",
            b"python310.dll",
            b"python311.dll",
            b"python312.dll",
        ],
        "pyinstaller": [
            b"pyi-",
            b"PyInstaller",
            b"_MEIPASS",
            b"MEI",
            # PyInstaller archive magic
            b"MEI\x0c\x0b\x0a\x0b\x0e",
        ],
        "cx_freeze": [
            b"cx_Freeze",
            b"freezer",
        ],
        "nuitka": [
            b"nuitka",
            b"Nuitka",
            b"NUITKA_PACKAGE",
        ],
    }

    # PyInstaller archive magic (at end of file)
    PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"

    # py2exe overlay marker
    PY2EXE_MARKER = b"PY2EXE"

    def __init__(self):
        """Initialize the analyzer."""
        pass

    def detect_packer(self, binary_path: str) -> dict:
        """
        Detect if a binary is packed with a Python packer.

        Args:
            binary_path: Path to the binary file

        Returns:
            Detection result with packer type and confidence
        """
        path = Path(binary_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {binary_path}")

        data = path.read_bytes()
        results = {
            "is_python_packed": False,
            "packer": None,
            "python_version": None,
            "confidence": 0.0,
            "indicators": [],
            "resources": [],
        }

        # Check for PE file
        if data[:2] != b"MZ":
            results["indicators"].append("Not a PE file")
            return results

        # Search for packer signatures
        data_lower = data.lower()

        for packer, signatures in self.SIGNATURES.items():
            matches = []
            for sig in signatures:
                if sig.lower() in data_lower:
                    matches.append(sig.decode("utf-8", errors="replace"))

            if matches:
                if results["packer"] is None or len(matches) > len(results["indicators"]):
                    results["packer"] = packer
                    results["indicators"] = matches
                    results["confidence"] = min(0.5 + len(matches) * 0.1, 1.0)

        # Additional PyInstaller detection
        if self._check_pyinstaller_archive(data):
            results["packer"] = "pyinstaller"
            results["confidence"] = max(results["confidence"], 0.95)
            results["indicators"].append("PyInstaller archive found")

        # Additional py2exe detection
        py2exe_info = self._check_py2exe(data)
        if py2exe_info:
            results["packer"] = "py2exe"
            results["confidence"] = max(results["confidence"], 0.90)
            results["indicators"].extend(py2exe_info.get("indicators", []))
            results["resources"] = py2exe_info.get("resources", [])

        # Detect Python version from DLL names
        python_version = self._detect_python_version(data)
        if python_version:
            results["python_version"] = python_version

        results["is_python_packed"] = results["packer"] is not None

        return results

    def _check_pyinstaller_archive(self, data: bytes) -> bool:
        """Check for PyInstaller archive at end of file."""
        # PyInstaller appends its archive to the end of the executable
        # The archive ends with MAGIC + cookie_len (4 bytes) + pkg_len (4 bytes) + toc_len (4 bytes)
        # + toc offset (4 bytes) + pyvers (4 bytes) + pylib_name (64 bytes) = 88 bytes before magic

        try:
            # Search for magic in last 4KB
            search_area = data[-4096:]
            if self.PYINSTALLER_MAGIC in search_area:
                return True

            # Alternative: look for "PYZ-" marker
            if b"PYZ-00.pyz" in data or b"PYZ" in data[-8192:]:
                return True

        except Exception as e:
            logger.debug(f"PyInstaller check failed: {e}")

        return False

    def _check_py2exe(self, data: bytes) -> dict | None:
        """Check for py2exe packed executable."""
        result = {"indicators": [], "resources": []}

        # Look for PYTHONSCRIPT resource
        if b"PYTHONSCRIPT" in data:
            result["indicators"].append("PYTHONSCRIPT resource")

        # Look for py2exe specific strings
        if b"py2exe" in data.lower():
            result["indicators"].append("py2exe string")

        # Look for zipfile at end (py2exe often appends a zipfile)
        try:
            # Find ZIP signature (PK\x03\x04)
            zip_start = data.rfind(b"PK\x03\x04")
            if zip_start > 0:
                # Try to read as zipfile
                import io
                zip_data = data[zip_start:]
                try:
                    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                        names = zf.namelist()
                        # Check for .pyc files or library.zip
                        pyc_files = [n for n in names if n.endswith(".pyc")]
                        if pyc_files:
                            result["indicators"].append(f"Found {len(pyc_files)} .pyc files in overlay")
                            result["resources"].extend(pyc_files[:10])  # First 10
                except zipfile.BadZipFile:
                    pass
        except Exception as e:
            logger.debug(f"py2exe ZIP check failed: {e}")

        return result if result["indicators"] else None

    def _detect_python_version(self, data: bytes) -> str | None:
        """Detect Python version from embedded DLL names."""
        # Common Python DLL patterns
        patterns = [
            (b"python312.dll", "3.12"),
            (b"python311.dll", "3.11"),
            (b"python310.dll", "3.10"),
            (b"python39.dll", "3.9"),
            (b"python38.dll", "3.8"),
            (b"python37.dll", "3.7"),
            (b"python36.dll", "3.6"),
            (b"python35.dll", "3.5"),
            (b"python34.dll", "3.4"),
            (b"python27.dll", "2.7"),
            (b"python26.dll", "2.6"),
            (b"PYTHON312.DLL", "3.12"),
            (b"PYTHON311.DLL", "3.11"),
            (b"PYTHON310.DLL", "3.10"),
            (b"PYTHON39.DLL", "3.9"),
            (b"PYTHON38.DLL", "3.8"),
            (b"PYTHON37.DLL", "3.7"),
            (b"PYTHON27.DLL", "2.7"),
        ]

        data_search = data.lower()
        for pattern, version in patterns:
            if pattern.lower() in data_search:
                return version

        return None

    def extract_pyinstaller(self, binary_path: str, output_dir: str) -> dict:
        """
        Extract PyInstaller packed executable.

        Args:
            binary_path: Path to the packed executable
            output_dir: Directory to extract to

        Returns:
            Extraction result
        """
        path = Path(binary_path)
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        data = path.read_bytes()
        result = {
            "success": False,
            "extracted_files": [],
            "errors": [],
        }

        try:
            # Find the archive
            archive_info = self._find_pyinstaller_archive(data)
            if not archive_info:
                result["errors"].append("Could not find PyInstaller archive")
                return result

            archive_data = data[archive_info["offset"]:]

            # PyInstaller uses a custom format, try to extract what we can
            # The format includes a TOC (table of contents) and compressed entries

            # For now, extract any embedded ZIP files
            zip_offsets = self._find_zip_archives(archive_data)

            for i, offset in enumerate(zip_offsets[:5]):  # Limit to 5 archives
                try:
                    import io
                    archive_out_dir = out_path / f"archive_{i}"
                    archive_out_dir.mkdir(parents=True, exist_ok=True)

                    with zipfile.ZipFile(io.BytesIO(archive_data[offset:])) as zf:
                        for name in zf.namelist():
                            try:
                                # Safely resolve path to prevent Zip Slip attacks
                                out_file = _safe_extract_path(archive_out_dir, name)
                                out_file.parent.mkdir(parents=True, exist_ok=True)
                                out_file.write_bytes(zf.read(name))
                                result["extracted_files"].append(str(out_file))
                            except ValueError as e:
                                # Path traversal attempt
                                result["errors"].append(f"Skipped unsafe path {name}: {e}")
                            except Exception as e:
                                result["errors"].append(f"Failed to extract {name}: {e}")
                except zipfile.BadZipFile:
                    continue

            result["success"] = len(result["extracted_files"]) > 0

        except Exception as e:
            result["errors"].append(f"Extraction failed: {e}")

        return result

    def _find_pyinstaller_archive(self, data: bytes) -> dict | None:
        """Find PyInstaller archive in the binary."""
        # Look for the magic from the end
        try:
            # Search in last 1MB for the magic
            search_start = max(0, len(data) - 1024 * 1024)
            search_data = data[search_start:]

            magic_pos = search_data.rfind(self.PYINSTALLER_MAGIC)
            if magic_pos >= 0:
                return {"offset": search_start + magic_pos - 24}  # Cookie is 24 bytes before magic

            # Alternative: look for PYZ marker
            pyz_pos = data.rfind(b"PYZ")
            if pyz_pos > 0:
                return {"offset": pyz_pos}

        except Exception as e:
            logger.debug(f"Failed to find PyInstaller archive: {e}")

        return None

    def _find_zip_archives(self, data: bytes) -> list[int]:
        """Find all ZIP archive offsets in data."""
        offsets = []
        pos = 0
        while True:
            pos = data.find(b"PK\x03\x04", pos)
            if pos < 0:
                break
            offsets.append(pos)
            pos += 1
        return offsets

    def extract_py2exe(self, binary_path: str, output_dir: str) -> dict:
        """
        Extract py2exe packed executable.

        Args:
            binary_path: Path to the packed executable
            output_dir: Directory to extract to

        Returns:
            Extraction result
        """
        path = Path(binary_path)
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        data = path.read_bytes()
        result = {
            "success": False,
            "extracted_files": [],
            "errors": [],
        }

        try:
            # py2exe typically appends a ZIP file to the executable
            zip_offsets = self._find_zip_archives(data)

            for offset in zip_offsets:
                try:
                    import io
                    with zipfile.ZipFile(io.BytesIO(data[offset:])) as zf:
                        for name in zf.namelist():
                            try:
                                # Safely resolve path to prevent Zip Slip attacks
                                out_file = _safe_extract_path(out_path, name)
                                out_file.parent.mkdir(parents=True, exist_ok=True)
                                out_file.write_bytes(zf.read(name))
                                result["extracted_files"].append(str(out_file))
                            except ValueError as e:
                                # Path traversal attempt
                                result["errors"].append(f"Skipped unsafe path {name}: {e}")
                            except Exception as e:
                                result["errors"].append(f"Failed to extract {name}: {e}")
                    # If we successfully extracted from one ZIP, we're done
                    break
                except zipfile.BadZipFile:
                    continue

            result["success"] = len(result["extracted_files"]) > 0

        except Exception as e:
            result["errors"].append(f"Extraction failed: {e}")

        return result

    def analyze_pyc(self, pyc_path: str) -> dict:
        """
        Analyze a .pyc (compiled Python) file.

        Args:
            pyc_path: Path to .pyc file

        Returns:
            Analysis result with version and metadata
        """
        path = Path(pyc_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {pyc_path}")

        data = path.read_bytes()
        result = {
            "file": str(path),
            "size": len(data),
            "python_version": None,
            "magic_number": None,
            "timestamp": None,
            "source_size": None,
            "is_valid": False,
        }

        if len(data) < 16:
            result["error"] = "File too small to be a valid .pyc"
            return result

        # Parse the header
        # .pyc format:
        # - 4 bytes: magic number (identifies Python version)
        # - 4 bytes: bit field (Python 3.7+) or padding
        # - 4 bytes: timestamp
        # - 4 bytes: source size (Python 3.3+)

        magic = struct.unpack("<H", data[:2])[0]
        result["magic_number"] = f"0x{magic:04X}"

        # Map magic numbers to Python versions
        magic_versions = {
            # Python 2.x
            0x7B03: "1.5", 0x7CF1: "1.6", 0x87C6: "2.0", 0x8DF2: "2.1",
            0x959E: "2.2", 0x9E60: "2.3", 0xA622: "2.4", 0xADCE: "2.5",
            0xB66B: "2.6", 0xC66F: "2.7",
            # Python 3.x
            0xBF0C: "3.0", 0xC70C: "3.1", 0xCF0C: "3.2", 0xD70C: "3.3",
            0xDF0D: "3.4", 0xE80D: "3.5", 0xF10D: "3.6",
            0x0D42: "3.7", 0x550D: "3.8", 0x610D: "3.9",
            0x6F0D: "3.10", 0x7B0D: "3.11", 0x870D: "3.12",
        }

        result["python_version"] = magic_versions.get(magic, f"Unknown (magic: 0x{magic:04X})")

        try:
            # Try to get timestamp
            if len(data) >= 8:
                timestamp = struct.unpack("<I", data[4:8])[0]
                if timestamp > 0 and timestamp < 0xFFFFFFFF:
                    import datetime
                    result["timestamp"] = datetime.datetime.fromtimestamp(timestamp).isoformat()

            # Try to get source size
            if len(data) >= 16:
                source_size = struct.unpack("<I", data[12:16])[0]
                if source_size < 100 * 1024 * 1024:  # Less than 100MB
                    result["source_size"] = source_size

            result["is_valid"] = True

        except Exception as e:
            result["error"] = f"Failed to parse header: {e}"

        return result

    def list_archive_contents(self, binary_path: str) -> dict:
        """
        List contents of a Python packed archive.

        Args:
            binary_path: Path to packed executable

        Returns:
            List of files/modules in the archive
        """
        path = Path(binary_path)
        data = path.read_bytes()

        result = {
            "packer": None,
            "contents": [],
            "total_files": 0,
        }

        # Detect packer type first
        detection = self.detect_packer(binary_path)
        result["packer"] = detection.get("packer")

        # Find embedded ZIP files
        zip_offsets = self._find_zip_archives(data)

        for offset in zip_offsets:
            try:
                import io
                with zipfile.ZipFile(io.BytesIO(data[offset:])) as zf:
                    for info in zf.infolist():
                        result["contents"].append({
                            "name": info.filename,
                            "size": info.file_size,
                            "compressed_size": info.compress_size,
                            "is_pyc": info.filename.endswith(".pyc"),
                        })
                    # Usually we only want the first valid archive
                    break
            except zipfile.BadZipFile:
                continue

        result["total_files"] = len(result["contents"])
        return result
