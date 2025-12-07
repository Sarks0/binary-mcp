"""
Malware triage and quick scan tools.

Provides rapid initial assessment of suspicious files:
- File type and format detection
- Packer/protector identification
- Suspicious indicator extraction
- Anti-analysis technique detection
- Recommended analysis approach
"""

import hashlib
import logging
import struct
from pathlib import Path

logger = logging.getLogger(__name__)


def calculate_file_hashes(file_path: str) -> dict:
    """Calculate MD5, SHA1, SHA256 hashes."""
    path = Path(file_path)
    data = path.read_bytes()

    return {
        "md5": hashlib.md5(data).hexdigest(),  # nosec B324
        "sha1": hashlib.sha1(data).hexdigest(),  # nosec B324
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0

    import math
    from collections import Counter

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def detect_file_type(data: bytes) -> dict:
    """Detect file type from magic bytes."""
    result = {
        "type": "unknown",
        "description": "Unknown file type",
        "is_executable": False,
        "architecture": None,
    }

    if len(data) < 4:
        return result

    # PE (Windows executable)
    if data[:2] == b"MZ":
        result["type"] = "pe"
        result["description"] = "Windows PE executable"
        result["is_executable"] = True

        # Check for PE signature
        if len(data) > 0x3C + 4:
            pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
            if len(data) > pe_offset + 6 and data[pe_offset:pe_offset+4] == b"PE\x00\x00":
                machine = struct.unpack("<H", data[pe_offset+4:pe_offset+6])[0]
                if machine == 0x8664:
                    result["architecture"] = "x64"
                    result["description"] = "Windows PE64 executable"
                elif machine == 0x14c:
                    result["architecture"] = "x86"
                    result["description"] = "Windows PE32 executable"

                # Check for DLL
                if len(data) > pe_offset + 22:
                    characteristics = struct.unpack("<H", data[pe_offset+22:pe_offset+24])[0]
                    if characteristics & 0x2000:  # IMAGE_FILE_DLL
                        result["description"] = result["description"].replace("executable", "DLL")

    # ELF (Linux executable)
    elif data[:4] == b"\x7fELF":
        result["type"] = "elf"
        result["is_executable"] = True
        if data[4] == 1:
            result["architecture"] = "x86"
            result["description"] = "Linux ELF32 executable"
        elif data[4] == 2:
            result["architecture"] = "x64"
            result["description"] = "Linux ELF64 executable"

    # Mach-O (macOS executable)
    elif data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                      b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        result["type"] = "macho"
        result["description"] = "macOS Mach-O executable"
        result["is_executable"] = True

    # .NET assembly
    elif data[:2] == b"MZ" and b"_CorExeMain" in data[:4096]:
        result["type"] = "dotnet"
        result["description"] = ".NET assembly"
        result["is_executable"] = True

    # MSI installer
    elif data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        result["type"] = "msi"
        result["description"] = "Windows MSI installer"
        result["is_executable"] = True

    # ZIP archive
    elif data[:4] == b"PK\x03\x04":
        result["type"] = "zip"
        result["description"] = "ZIP archive"

    # PDF
    elif data[:5] == b"%PDF-":
        result["type"] = "pdf"
        result["description"] = "PDF document"

    # Office documents
    elif data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        result["type"] = "ole"
        result["description"] = "OLE document (Office)"

    return result


def detect_packer(data: bytes) -> list[dict]:
    """Detect common packers and protectors."""
    packers = []

    # Common packer signatures
    packer_signatures = {
        "upx": [b"UPX!", b"UPX0", b"UPX1", b"UPX2"],
        "aspack": [b"ASPack", b".aspack"],
        "fsg": [b"FSG!"],
        "petite": [b"petite", b"Petite"],
        "mpress": [b"MPRESS1", b"MPRESS2"],
        "themida": [b"Themida", b".themida"],
        "vmprotect": [b"VMProtect", b".vmp0", b".vmp1"],
        "enigma": [b"Enigma protector", b".enigma"],
        "pyinstaller": [b"PyInstaller", b"pyi-", b"_MEIPASS", b"MEI\x0c\x0b\x0a\x0b\x0e"],
        "py2exe": [b"PYTHONSCRIPT", b"py2exe", b"python27.dll", b"python3"],
        "nuitka": [b"nuitka", b"Nuitka"],
        "dotfuscator": [b"Dotfuscator", b"DotfuscatorAttribute"],
        "confuserex": [b"ConfuserEx", b"Confuser"],
        "dnguard": [b"DNGuard"],
        "nspack": [b"NsPacK", b".nsp0", b".nsp1"],
        "pecompact": [b"PEC2", b"PECompact"],
    }

    data_lower = data.lower()

    for packer, signatures in packer_signatures.items():
        matches = []
        for sig in signatures:
            if sig.lower() in data_lower:
                matches.append(sig.decode("utf-8", errors="replace"))

        if matches:
            confidence = min(0.5 + len(matches) * 0.15, 0.95)
            packers.append({
                "name": packer,
                "confidence": confidence,
                "indicators": matches,
            })

    # Sort by confidence
    packers.sort(key=lambda x: x["confidence"], reverse=True)
    return packers


def extract_suspicious_strings(data: bytes, min_length: int = 6) -> dict:
    """Extract suspicious strings from binary."""
    import re

    result = {
        "urls": [],
        "ips": [],
        "emails": [],
        "file_paths": [],
        "registry_keys": [],
        "commands": [],
        "crypto_strings": [],
        "debug_strings": [],
        "api_names": [],
    }

    # Convert to string, handling encoding
    try:
        # Try UTF-16 LE (common in Windows)
        text_utf16 = data.decode("utf-16-le", errors="ignore")
    except Exception:
        text_utf16 = ""

    text_ascii = data.decode("ascii", errors="ignore")
    combined_text = text_ascii + " " + text_utf16

    # URLs
    url_pattern = rb'https?://[^\s<>"\'}{)(\]\[]{5,200}'
    for match in re.findall(url_pattern, data, re.IGNORECASE):
        url = match.decode("utf-8", errors="replace")
        if url not in result["urls"]:
            result["urls"].append(url)

    # IP addresses
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    for match in re.findall(ip_pattern, combined_text):
        if match not in result["ips"] and not match.startswith(("0.", "127.", "255.")):
            result["ips"].append(match)

    # Email addresses
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    for match in re.findall(email_pattern, combined_text):
        if match not in result["emails"]:
            result["emails"].append(match)

    # Windows file paths
    path_pattern = r'[A-Za-z]:\\[^\s<>"\'*?|]{5,100}'
    for match in re.findall(path_pattern, combined_text):
        if match not in result["file_paths"]:
            result["file_paths"].append(match)

    # Registry keys
    reg_pattern = r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKU|HKCR)\\[^\s<>"\']{5,100}'
    for match in re.findall(reg_pattern, combined_text):
        if match not in result["registry_keys"]:
            result["registry_keys"].append(match)

    # Suspicious commands
    cmd_keywords = [
        "cmd.exe", "powershell", "wscript", "cscript", "mshta",
        "regsvr32", "rundll32", "certutil", "bitsadmin",
        "/c ", "-enc ", "-nop ", "-w hidden", "Invoke-",
        "DownloadString", "DownloadFile", "IEX", "bypass",
    ]
    for keyword in cmd_keywords:
        if keyword.lower() in combined_text.lower():
            result["commands"].append(keyword)

    # Crypto-related strings
    crypto_keywords = [
        "AES", "RSA", "DES", "RC4", "encrypt", "decrypt",
        "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt",
        "BCrypt", "NCrypt", "ransom", "bitcoin", "wallet",
    ]
    for keyword in crypto_keywords:
        if keyword.lower() in combined_text.lower():
            if keyword not in result["crypto_strings"]:
                result["crypto_strings"].append(keyword)

    # Debug/development strings
    debug_keywords = [
        ".pdb", "DEBUG", "RELEASE", "assert", "\\Debug\\",
        "\\Release\\", "Visual Studio", "gcc", "mingw",
    ]
    for keyword in debug_keywords:
        if keyword in combined_text:
            if keyword not in result["debug_strings"]:
                result["debug_strings"].append(keyword)

    # Limit results
    for key in result:
        result[key] = result[key][:20]

    return result


def detect_anti_analysis(data: bytes) -> list[dict]:
    """Detect anti-analysis and anti-debug techniques."""
    techniques = []

    # Anti-debug API patterns
    anti_debug_apis = {
        "IsDebuggerPresent": "Basic debugger detection via PEB",
        "CheckRemoteDebuggerPresent": "Remote debugger detection",
        "NtQueryInformationProcess": "Advanced debugger detection",
        "NtQuerySystemInformation": "System debugger detection",
        "OutputDebugString": "Debugger detection via debug output",
        "GetTickCount": "Timing-based anti-debug",
        "QueryPerformanceCounter": "High-precision timing check",
        "rdtsc": "CPU timing check (rdtsc instruction)",
        "NtSetInformationThread": "Thread hiding from debugger",
        "ZwSetInformationThread": "Thread hiding (Zw variant)",
        "CloseHandle": "Exception-based debugger detection",
        "NtClose": "Exception-based detection (Nt variant)",
        "FindWindow": "Debugger window detection",
        "EnumWindows": "Window enumeration for debugger detection",
    }

    for api, description in anti_debug_apis.items():
        if api.encode() in data:
            techniques.append({
                "type": "anti_debug",
                "technique": api,
                "description": description,
            })

    # Anti-VM patterns
    anti_vm_patterns = {
        b"VMware": "VMware detection",
        b"VBox": "VirtualBox detection",
        b"VBOX": "VirtualBox detection",
        b"Virtual": "Generic VM detection",
        b"Hyper-V": "Hyper-V detection",
        b"QEMU": "QEMU detection",
        b"Xen": "Xen detection",
        b"vmt": "VMware tools detection",
        b"vmtoolsd": "VMware tools daemon detection",
        b"VBoxService": "VirtualBox service detection",
        b"\\REGISTRY\\MACHINE\\SOFTWARE\\VMware": "VMware registry check",
        b"HARDWARE\\DEVICEMAP\\Scsi": "VM SCSI detection",
    }

    for pattern, description in anti_vm_patterns.items():
        if pattern in data:
            techniques.append({
                "type": "anti_vm",
                "technique": pattern.decode("utf-8", errors="replace"),
                "description": description,
            })

    # Anti-sandbox patterns
    anti_sandbox_patterns = {
        b"SbieDll": "Sandboxie detection",
        b"snxhk": "Avast sandbox detection",
        b"cmdvrt": "Comodo sandbox detection",
        b"cuckoomon": "Cuckoo sandbox detection",
        b"pstorec.dll": "Anubis sandbox detection",
        b"dbghelp.dll": "Debug environment detection",
        b"sample": "Sample filename detection",
        b"malware": "Malware filename detection",
        b"virus": "Virus filename detection",
    }

    for pattern, description in anti_sandbox_patterns.items():
        if pattern.lower() in data.lower():
            techniques.append({
                "type": "anti_sandbox",
                "technique": pattern.decode("utf-8", errors="replace"),
                "description": description,
            })

    return techniques


def detect_suspicious_imports(data: bytes) -> list[dict]:
    """Detect suspicious Windows API imports."""
    suspicious_apis = {
        # Process injection
        "VirtualAllocEx": {"category": "injection", "severity": "high"},
        "WriteProcessMemory": {"category": "injection", "severity": "high"},
        "CreateRemoteThread": {"category": "injection", "severity": "high"},
        "NtCreateThreadEx": {"category": "injection", "severity": "high"},
        "QueueUserAPC": {"category": "injection", "severity": "high"},
        "SetThreadContext": {"category": "injection", "severity": "high"},

        # Process hollowing
        "NtUnmapViewOfSection": {"category": "hollowing", "severity": "high"},
        "ZwUnmapViewOfSection": {"category": "hollowing", "severity": "high"},

        # Privilege escalation
        "AdjustTokenPrivileges": {"category": "privilege", "severity": "medium"},
        "OpenProcessToken": {"category": "privilege", "severity": "medium"},
        "LookupPrivilegeValue": {"category": "privilege", "severity": "medium"},

        # Keylogging
        "SetWindowsHookEx": {"category": "keylogger", "severity": "high"},
        "GetAsyncKeyState": {"category": "keylogger", "severity": "medium"},
        "GetKeyState": {"category": "keylogger", "severity": "medium"},

        # Persistence
        "RegSetValueEx": {"category": "persistence", "severity": "medium"},
        "CreateService": {"category": "persistence", "severity": "medium"},

        # Network
        "URLDownloadToFile": {"category": "network", "severity": "medium"},
        "InternetOpen": {"category": "network", "severity": "low"},
        "HttpSendRequest": {"category": "network", "severity": "low"},
        "WinHttpOpen": {"category": "network", "severity": "low"},

        # Crypto (potential ransomware)
        "CryptEncrypt": {"category": "crypto", "severity": "medium"},
        "CryptGenKey": {"category": "crypto", "severity": "medium"},
        "BCryptEncrypt": {"category": "crypto", "severity": "medium"},

        # Evasion
        "VirtualProtect": {"category": "evasion", "severity": "medium"},
        "NtProtectVirtualMemory": {"category": "evasion", "severity": "medium"},
    }

    found = []
    for api, info in suspicious_apis.items():
        if api.encode() in data:
            found.append({
                "api": api,
                "category": info["category"],
                "severity": info["severity"],
            })

    # Sort by severity
    severity_order = {"high": 0, "medium": 1, "low": 2}
    found.sort(key=lambda x: severity_order.get(x["severity"], 99))

    return found


def generate_recommendations(analysis: dict) -> list[str]:
    """Generate analysis recommendations based on findings."""
    recommendations = []

    # Anti-debug detected
    anti_debug = [t for t in analysis.get("anti_analysis", []) if t["type"] == "anti_debug"]
    if anti_debug:
        recommendations.append("⚠ Anti-debug detected: Use hardware breakpoints and PEB hiding")
        recommendations.append("  Consider ScyllaHide or TitanHide plugins")

    # Anti-VM detected
    anti_vm = [t for t in analysis.get("anti_analysis", []) if t["type"] == "anti_vm"]
    if anti_vm:
        recommendations.append("⚠ Anti-VM detected: Run on bare metal or use VM cloaking")

    # Packer detected
    if analysis.get("packers"):
        packer = analysis["packers"][0]["name"]
        if packer in ("upx", "aspack", "fsg", "mpress"):
            recommendations.append(f"• Packed with {packer.upper()}: Can likely be unpacked statically")
        elif packer in ("themida", "vmprotect"):
            recommendations.append(f"• Protected with {packer}: Requires dynamic unpacking")
            recommendations.append("  Set breakpoint at OEP after protection layer")
        elif packer in ("pyinstaller", "py2exe"):
            recommendations.append(f"• Python packed ({packer}): Use extract_python_packed tool")

    # Injection APIs found
    injection_apis = [a for a in analysis.get("suspicious_imports", [])
                      if a["category"] == "injection"]
    if injection_apis:
        recommendations.append("• Process injection detected: Monitor CreateRemoteThread and VirtualAllocEx")
        recommendations.append("  Set breakpoints on WriteProcessMemory to capture injected code")

    # Network activity
    network_apis = [a for a in analysis.get("suspicious_imports", [])
                    if a["category"] == "network"]
    if network_apis or analysis.get("strings", {}).get("urls"):
        recommendations.append("• Network capability detected: Monitor DNS and HTTP traffic")
        recommendations.append("  Use Fakenet-NG or similar for network simulation")

    # Crypto APIs
    crypto_apis = [a for a in analysis.get("suspicious_imports", [])
                   if a["category"] == "crypto"]
    if crypto_apis:
        recommendations.append("• Crypto APIs detected: Possible ransomware or encrypted C2")
        recommendations.append("  Monitor CryptEncrypt/BCryptEncrypt for encryption operations")

    # High entropy
    if analysis.get("entropy", 0) > 7.0:
        recommendations.append("• High entropy: Binary likely encrypted or compressed")
        recommendations.append("  Look for decryption routine before main payload")

    if not recommendations:
        recommendations.append("• No specific evasion techniques detected")
        recommendations.append("• Standard analysis approach should work")

    return recommendations


def register_triage_tools(app, session_manager=None):
    """
    Register triage tools with the MCP app.

    Args:
        app: FastMCP application instance
        session_manager: Optional session manager for logging
    """
    from src.utils.security import (
        PathTraversalError,
        FileSizeError,
        sanitize_binary_path,
        safe_error_message,
    )

    @app.tool()
    def quick_scan(binary_path: str) -> str:
        """
        Perform quick triage scan of a suspicious file.

        Provides comprehensive initial assessment including:
        - File type and format detection
        - Hash calculation (MD5, SHA1, SHA256)
        - Entropy analysis
        - Packer/protector identification
        - Suspicious string extraction
        - Anti-analysis technique detection
        - Suspicious API import analysis
        - Recommended analysis approach

        Args:
            binary_path: Path to suspicious file

        Returns:
            Comprehensive triage report

        Example:
            quick_scan("suspicious.exe")
        """
        try:
            binary_path = sanitize_binary_path(binary_path)
            path = Path(binary_path)

            if not path.exists():
                return f"File not found: {binary_path}"

            data = path.read_bytes()
            file_size = len(data)

            output = []
            output.append("=" * 70)
            output.append("MALWARE TRIAGE SCAN")
            output.append("=" * 70)
            output.append(f"File: {path.name}")
            output.append(f"Path: {binary_path}")
            output.append(f"Size: {file_size:,} bytes ({file_size / 1024:.1f} KB)")
            output.append("")

            # Collect analysis results
            analysis = {}

            # File hashes
            hashes = calculate_file_hashes(binary_path)
            output.append("File Hashes:")
            output.append(f"  MD5:    {hashes['md5']}")
            output.append(f"  SHA1:   {hashes['sha1']}")
            output.append(f"  SHA256: {hashes['sha256']}")
            output.append("")

            # File type
            file_type = detect_file_type(data)
            analysis["file_type"] = file_type
            output.append(f"File Type: {file_type['description']}")
            if file_type["architecture"]:
                output.append(f"Architecture: {file_type['architecture']}")
            output.append("")

            # Entropy
            entropy = calculate_entropy(data)
            analysis["entropy"] = entropy
            entropy_assessment = ""
            if entropy > 7.5:
                entropy_assessment = " (Very high - likely encrypted/compressed)"
            elif entropy > 7.0:
                entropy_assessment = " (High - possibly packed)"
            elif entropy > 6.0:
                entropy_assessment = " (Normal for executables)"
            else:
                entropy_assessment = " (Low - mostly plaintext)"
            output.append(f"Entropy: {entropy:.2f}/8.0{entropy_assessment}")
            output.append("")

            # Packer detection
            packers = detect_packer(data)
            analysis["packers"] = packers
            if packers:
                output.append("Packer/Protector Detection:")
                for p in packers[:3]:
                    output.append(f"  • {p['name'].upper()} ({p['confidence']*100:.0f}% confidence)")
                    output.append(f"    Indicators: {', '.join(p['indicators'][:3])}")
                output.append("")
            else:
                output.append("Packer Detection: None detected")
                output.append("")

            # Anti-analysis techniques
            anti_analysis = detect_anti_analysis(data)
            analysis["anti_analysis"] = anti_analysis
            if anti_analysis:
                output.append(f"Anti-Analysis Techniques ({len(anti_analysis)} found):")

                by_type = {}
                for t in anti_analysis:
                    by_type.setdefault(t["type"], []).append(t)

                for atype, techniques in by_type.items():
                    type_label = atype.replace("_", "-").upper()
                    output.append(f"  [{type_label}]")
                    for t in techniques[:5]:
                        output.append(f"    • {t['technique']}: {t['description']}")
                output.append("")

            # Suspicious imports
            suspicious_imports = detect_suspicious_imports(data)
            analysis["suspicious_imports"] = suspicious_imports
            if suspicious_imports:
                output.append(f"Suspicious API Imports ({len(suspicious_imports)} found):")

                by_category = {}
                for imp in suspicious_imports:
                    by_category.setdefault(imp["category"], []).append(imp)

                for category, apis in by_category.items():
                    severity = apis[0]["severity"]
                    severity_icon = "🔴" if severity == "high" else "🟡" if severity == "medium" else "🟢"
                    output.append(f"  {severity_icon} {category.upper()}:")
                    for api in apis[:5]:
                        output.append(f"      {api['api']}")
                output.append("")

            # Suspicious strings
            strings = extract_suspicious_strings(data)
            analysis["strings"] = strings
            has_strings = any(strings.values())

            if has_strings:
                output.append("Suspicious Strings:")

                if strings["urls"]:
                    output.append(f"  URLs ({len(strings['urls'])}):")
                    for url in strings["urls"][:5]:
                        output.append(f"    • {url[:80]}")

                if strings["ips"]:
                    output.append(f"  IP Addresses ({len(strings['ips'])}):")
                    for ip in strings["ips"][:5]:
                        output.append(f"    • {ip}")

                if strings["file_paths"]:
                    output.append(f"  File Paths ({len(strings['file_paths'])}):")
                    for fp in strings["file_paths"][:5]:
                        output.append(f"    • {fp[:60]}")

                if strings["registry_keys"]:
                    output.append(f"  Registry Keys ({len(strings['registry_keys'])}):")
                    for rk in strings["registry_keys"][:5]:
                        output.append(f"    • {rk[:60]}")

                if strings["commands"]:
                    output.append("  Command Keywords:")
                    output.append(f"    {', '.join(strings['commands'][:10])}")

                if strings["crypto_strings"]:
                    output.append("  Crypto Keywords:")
                    output.append(f"    {', '.join(strings['crypto_strings'][:10])}")

                output.append("")

            # Recommendations
            recommendations = generate_recommendations(analysis)
            output.append("=" * 70)
            output.append("ANALYSIS RECOMMENDATIONS")
            output.append("=" * 70)
            for rec in recommendations:
                output.append(rec)

            return "\n".join(output)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("quick_scan", e)
        except Exception as e:
            logger.error(f"quick_scan failed: {e}")
            return f"Error scanning file: {e}"

    @app.tool()
    def detect_packers(binary_path: str) -> str:
        """
        Detect packers and protectors in a binary.

        Identifies common packers like UPX, Themida, VMProtect,
        as well as Python packers (PyInstaller, py2exe).

        Args:
            binary_path: Path to binary file

        Returns:
            List of detected packers with confidence scores

        Example:
            detect_packers("packed.exe")
        """
        try:
            binary_path = sanitize_binary_path(binary_path)
            path = Path(binary_path)

            if not path.exists():
                return f"File not found: {binary_path}"

            data = path.read_bytes()
            packers = detect_packer(data)

            output = []
            output.append("=" * 60)
            output.append("PACKER DETECTION")
            output.append("=" * 60)
            output.append(f"File: {path.name}")
            output.append("")

            if packers:
                output.append(f"Detected {len(packers)} packer(s):")
                output.append("")

                for p in packers:
                    output.append(f"• {p['name'].upper()}")
                    output.append(f"  Confidence: {p['confidence']*100:.0f}%")
                    output.append(f"  Indicators: {', '.join(p['indicators'])}")
                    output.append("")
            else:
                output.append("No packers detected.")
                output.append("")
                output.append("The binary may be:")
                output.append("  • Unpacked/native")
                output.append("  • Using an unknown/custom packer")
                output.append("  • Using advanced obfuscation")

            return "\n".join(output)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("detect_packers", e)
        except Exception as e:
            logger.error(f"detect_packers failed: {e}")
            return f"Error detecting packers: {e}"

    @app.tool()
    def extract_iocs(binary_path: str) -> str:
        """
        Extract Indicators of Compromise (IOCs) from a binary.

        Extracts URLs, IP addresses, file paths, registry keys,
        and other potential IOCs from the file.

        Args:
            binary_path: Path to binary file

        Returns:
            List of extracted IOCs by category

        Example:
            extract_iocs("malware.exe")
        """
        try:
            binary_path = sanitize_binary_path(binary_path)
            path = Path(binary_path)

            if not path.exists():
                return f"File not found: {binary_path}"

            data = path.read_bytes()
            hashes = calculate_file_hashes(binary_path)
            strings = extract_suspicious_strings(data)

            output = []
            output.append("=" * 60)
            output.append("INDICATORS OF COMPROMISE (IOCs)")
            output.append("=" * 60)
            output.append(f"File: {path.name}")
            output.append("")

            output.append("File Hashes:")
            output.append(f"  MD5:    {hashes['md5']}")
            output.append(f"  SHA1:   {hashes['sha1']}")
            output.append(f"  SHA256: {hashes['sha256']}")
            output.append("")

            total_iocs = sum(len(v) for v in strings.values())

            if total_iocs > 0:
                output.append(f"Extracted {total_iocs} potential IOCs:")
                output.append("")

                if strings["urls"]:
                    output.append(f"URLs ({len(strings['urls'])}):")
                    for url in strings["urls"]:
                        output.append(f"  {url}")
                    output.append("")

                if strings["ips"]:
                    output.append(f"IP Addresses ({len(strings['ips'])}):")
                    for ip in strings["ips"]:
                        output.append(f"  {ip}")
                    output.append("")

                if strings["emails"]:
                    output.append(f"Email Addresses ({len(strings['emails'])}):")
                    for email in strings["emails"]:
                        output.append(f"  {email}")
                    output.append("")

                if strings["file_paths"]:
                    output.append(f"File Paths ({len(strings['file_paths'])}):")
                    for fp in strings["file_paths"]:
                        output.append(f"  {fp}")
                    output.append("")

                if strings["registry_keys"]:
                    output.append(f"Registry Keys ({len(strings['registry_keys'])}):")
                    for rk in strings["registry_keys"]:
                        output.append(f"  {rk}")
                    output.append("")

            else:
                output.append("No IOCs extracted.")
                output.append("The binary may be packed/encrypted.")

            return "\n".join(output)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("extract_iocs", e)
        except Exception as e:
            logger.error(f"extract_iocs failed: {e}")
            return f"Error extracting IOCs: {e}"

    logger.info("Registered 3 triage tools")
