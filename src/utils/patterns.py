"""
Pattern databases for malware API detection and crypto identification.
"""

import json
import re
from pathlib import Path
from typing import Optional, List


class APIPatterns:
    """Database of Windows API patterns for malware analysis."""

    def __init__(self):
        """Initialize API patterns database."""
        self.patterns = self._load_default_patterns()

    def _load_default_patterns(self) -> dict:
        """Load default API patterns."""
        return {
            # Process Manipulation
            "CreateProcess": {
                "category": "process",
                "severity": "medium",
                "description": "Creates a new process"
            },
            "CreateProcessA": {
                "category": "process",
                "severity": "medium",
                "description": "Creates a new process (ANSI)"
            },
            "CreateProcessW": {
                "category": "process",
                "severity": "medium",
                "description": "Creates a new process (Wide)"
            },
            "OpenProcess": {
                "category": "process",
                "severity": "medium",
                "description": "Opens existing process"
            },
            "TerminateProcess": {
                "category": "process",
                "severity": "high",
                "description": "Terminates a process"
            },
            "CreateRemoteThread": {
                "category": "process",
                "severity": "critical",
                "description": "Code injection via remote thread creation"
            },
            "QueueUserAPC": {
                "category": "process",
                "severity": "critical",
                "description": "APC-based code injection"
            },
            "SetThreadContext": {
                "category": "process",
                "severity": "critical",
                "description": "Process hollowing / thread hijacking"
            },

            # Memory Operations
            "VirtualAlloc": {
                "category": "memory",
                "severity": "medium",
                "description": "Allocates virtual memory"
            },
            "VirtualAllocEx": {
                "category": "memory",
                "severity": "high",
                "description": "Allocates memory in another process (injection)"
            },
            "VirtualProtect": {
                "category": "memory",
                "severity": "high",
                "description": "Changes memory protection (shellcode execution)"
            },
            "VirtualProtectEx": {
                "category": "memory",
                "severity": "critical",
                "description": "Changes memory protection in another process"
            },
            "WriteProcessMemory": {
                "category": "memory",
                "severity": "critical",
                "description": "Writes to another process memory (injection)"
            },
            "ReadProcessMemory": {
                "category": "memory",
                "severity": "high",
                "description": "Reads another process memory"
            },
            "HeapCreate": {
                "category": "memory",
                "severity": "low",
                "description": "Creates a heap"
            },

            # File Operations
            "CreateFile": {
                "category": "file",
                "severity": "low",
                "description": "Creates or opens a file"
            },
            "CreateFileA": {
                "category": "file",
                "severity": "low",
                "description": "Creates or opens a file (ANSI)"
            },
            "CreateFileW": {
                "category": "file",
                "severity": "low",
                "description": "Creates or opens a file (Wide)"
            },
            "WriteFile": {
                "category": "file",
                "severity": "medium",
                "description": "Writes data to a file"
            },
            "DeleteFile": {
                "category": "file",
                "severity": "medium",
                "description": "Deletes a file"
            },
            "DeleteFileA": {
                "category": "file",
                "severity": "medium",
                "description": "Deletes a file (ANSI)"
            },
            "DeleteFileW": {
                "category": "file",
                "severity": "medium",
                "description": "Deletes a file (Wide)"
            },
            "MoveFile": {
                "category": "file",
                "severity": "medium",
                "description": "Moves/renames a file"
            },
            "CopyFile": {
                "category": "file",
                "severity": "medium",
                "description": "Copies a file"
            },
            "FindFirstFile": {
                "category": "file",
                "severity": "low",
                "description": "Searches for files"
            },

            # Registry Operations
            "RegCreateKey": {
                "category": "registry",
                "severity": "medium",
                "description": "Creates a registry key"
            },
            "RegCreateKeyEx": {
                "category": "registry",
                "severity": "medium",
                "description": "Creates a registry key with extended options"
            },
            "RegSetValue": {
                "category": "registry",
                "severity": "medium",
                "description": "Sets a registry value"
            },
            "RegSetValueEx": {
                "category": "registry",
                "severity": "medium",
                "description": "Sets a registry value with extended options"
            },
            "RegDeleteKey": {
                "category": "registry",
                "severity": "medium",
                "description": "Deletes a registry key"
            },
            "RegDeleteValue": {
                "category": "registry",
                "severity": "medium",
                "description": "Deletes a registry value"
            },
            "RegOpenKey": {
                "category": "registry",
                "severity": "low",
                "description": "Opens a registry key"
            },
            "RegQueryValue": {
                "category": "registry",
                "severity": "low",
                "description": "Queries a registry value"
            },

            # Network Operations
            "socket": {
                "category": "network",
                "severity": "medium",
                "description": "Creates a socket"
            },
            "connect": {
                "category": "network",
                "severity": "medium",
                "description": "Connects to a remote host"
            },
            "send": {
                "category": "network",
                "severity": "medium",
                "description": "Sends data over a socket"
            },
            "recv": {
                "category": "network",
                "severity": "medium",
                "description": "Receives data from a socket"
            },
            "WSAStartup": {
                "category": "network",
                "severity": "medium",
                "description": "Initializes Winsock"
            },
            "InternetOpen": {
                "category": "network",
                "severity": "medium",
                "description": "Initializes WinINet"
            },
            "InternetOpenA": {
                "category": "network",
                "severity": "medium",
                "description": "Initializes WinINet (ANSI)"
            },
            "InternetOpenW": {
                "category": "network",
                "severity": "medium",
                "description": "Initializes WinINet (Wide)"
            },
            "InternetConnect": {
                "category": "network",
                "severity": "medium",
                "description": "Connects to HTTP/FTP server"
            },
            "HttpSendRequest": {
                "category": "network",
                "severity": "medium",
                "description": "Sends HTTP request"
            },
            "HttpOpenRequest": {
                "category": "network",
                "severity": "medium",
                "description": "Opens HTTP request"
            },
            "URLDownloadToFile": {
                "category": "network",
                "severity": "high",
                "description": "Downloads file from URL"
            },

            # Cryptography
            "CryptAcquireContext": {
                "category": "crypto",
                "severity": "medium",
                "description": "Acquires crypto context"
            },
            "CryptEncrypt": {
                "category": "crypto",
                "severity": "medium",
                "description": "Encrypts data"
            },
            "CryptDecrypt": {
                "category": "crypto",
                "severity": "medium",
                "description": "Decrypts data"
            },
            "CryptCreateHash": {
                "category": "crypto",
                "severity": "low",
                "description": "Creates a hash"
            },
            "CryptHashData": {
                "category": "crypto",
                "severity": "low",
                "description": "Hashes data"
            },
            "CryptGenKey": {
                "category": "crypto",
                "severity": "medium",
                "description": "Generates crypto key"
            },

            # Service Management
            "CreateService": {
                "category": "service",
                "severity": "high",
                "description": "Creates a service (persistence)"
            },
            "CreateServiceA": {
                "category": "service",
                "severity": "high",
                "description": "Creates a service (ANSI)"
            },
            "CreateServiceW": {
                "category": "service",
                "severity": "high",
                "description": "Creates a service (Wide)"
            },
            "StartService": {
                "category": "service",
                "severity": "medium",
                "description": "Starts a service"
            },
            "OpenSCManager": {
                "category": "service",
                "severity": "medium",
                "description": "Opens service control manager"
            },

            # Anti-Debugging
            "IsDebuggerPresent": {
                "category": "anti-debug",
                "severity": "high",
                "description": "Checks for debugger"
            },
            "CheckRemoteDebuggerPresent": {
                "category": "anti-debug",
                "severity": "high",
                "description": "Checks for remote debugger"
            },
            "NtQueryInformationProcess": {
                "category": "anti-debug",
                "severity": "high",
                "description": "Queries process info (often for debugger detection)"
            },
            "OutputDebugString": {
                "category": "anti-debug",
                "severity": "medium",
                "description": "Outputs debug string (anti-debug trick)"
            },
            "GetTickCount": {
                "category": "anti-debug",
                "severity": "low",
                "description": "Gets tick count (timing check for debuggers)"
            },
            "QueryPerformanceCounter": {
                "category": "anti-debug",
                "severity": "low",
                "description": "High-resolution timer (anti-debug timing)"
            },

            # Other Suspicious APIs
            "SetWindowsHookEx": {
                "category": "hooking",
                "severity": "high",
                "description": "Installs hook procedure (keylogger/injection)"
            },
            "GetAsyncKeyState": {
                "category": "keylogging",
                "severity": "high",
                "description": "Gets keyboard state (keylogger)"
            },
            "GetForegroundWindow": {
                "category": "surveillance",
                "severity": "medium",
                "description": "Gets active window (surveillance)"
            },
            "ShellExecute": {
                "category": "execution",
                "severity": "medium",
                "description": "Executes a file/URL"
            },
            "WinExec": {
                "category": "execution",
                "severity": "medium",
                "description": "Executes a program"
            },
            "LoadLibrary": {
                "category": "loading",
                "severity": "low",
                "description": "Loads a DLL"
            },
            "GetProcAddress": {
                "category": "loading",
                "severity": "medium",
                "description": "Gets function address (dynamic API resolution)"
            },
        }

    def get_api_info(self, api_name: str) -> Optional[dict]:
        """
        Get information about an API.

        Args:
            api_name: API function name

        Returns:
            API info dict or None if not found
        """
        return self.patterns.get(api_name)

    def get_by_category(self, category: str) -> List[str]:
        """
        Get all APIs in a category.

        Args:
            category: Category name

        Returns:
            List of API names
        """
        return [api for api, info in self.patterns.items() if info['category'] == category]

    def get_by_severity(self, severity: str) -> List[str]:
        """
        Get all APIs with a severity level.

        Args:
            severity: Severity level (low, medium, high, critical)

        Returns:
            List of API names
        """
        return [api for api, info in self.patterns.items() if info['severity'] == severity]


class CryptoPatterns:
    """Database of cryptographic constants and patterns."""

    def __init__(self):
        """Initialize crypto patterns database."""
        self.patterns = self._load_default_patterns()

    def _load_default_patterns(self) -> dict:
        """Load default crypto patterns."""
        return {
            # AES Constants
            "aes_sbox": {
                "algorithm": "AES",
                "pattern": "637c777bf26b6fc5",
                "description": "AES S-box"
            },
            "aes_rcon": {
                "algorithm": "AES",
                "pattern": "8d01020408102040",
                "description": "AES Round Constants"
            },

            # MD5 Constants
            "md5_init_a": {
                "algorithm": "MD5",
                "pattern": "67452301",
                "description": "MD5 initial value A"
            },
            "md5_init_b": {
                "algorithm": "MD5",
                "pattern": "efcdab89",
                "description": "MD5 initial value B"
            },
            "md5_init_c": {
                "algorithm": "MD5",
                "pattern": "98badcfe",
                "description": "MD5 initial value C"
            },
            "md5_init_d": {
                "algorithm": "MD5",
                "pattern": "10325476",
                "description": "MD5 initial value D"
            },

            # SHA-1 Constants
            "sha1_init_h0": {
                "algorithm": "SHA-1",
                "pattern": "67452301",
                "description": "SHA-1 initial value H0"
            },
            "sha1_init_h1": {
                "algorithm": "SHA-1",
                "pattern": "efcdab89",
                "description": "SHA-1 initial value H1"
            },
            "sha1_init_h2": {
                "algorithm": "SHA-1",
                "pattern": "98badcfe",
                "description": "SHA-1 initial value H2"
            },
            "sha1_init_h3": {
                "algorithm": "SHA-1",
                "pattern": "10325476",
                "description": "SHA-1 initial value H3"
            },
            "sha1_init_h4": {
                "algorithm": "SHA-1",
                "pattern": "c3d2e1f0",
                "description": "SHA-1 initial value H4"
            },

            # SHA-256 Constants
            "sha256_init_h0": {
                "algorithm": "SHA-256",
                "pattern": "6a09e667",
                "description": "SHA-256 initial value H0"
            },
            "sha256_init_h1": {
                "algorithm": "SHA-256",
                "pattern": "bb67ae85",
                "description": "SHA-256 initial value H1"
            },

            # RSA / Big Number
            "rsa_exponent": {
                "algorithm": "RSA",
                "pattern": "00010001",
                "description": "Common RSA public exponent (65537)"
            },

            # RC4
            "rc4_sbox_init": {
                "algorithm": "RC4",
                "pattern": "000102030405060708090a0b0c0d0e0f",
                "description": "RC4 S-box initialization"
            },
        }

    def detect_in_context(self, context: dict) -> List[dict]:
        """
        Detect crypto patterns in analysis context.

        Args:
            context: Analysis context from Ghidra

        Returns:
            List of detected crypto patterns
        """
        detected = []

        # Search in strings
        strings = context.get("strings", [])
        for string in strings:
            value = string.get('value', '').lower().replace(' ', '')

            for pattern_name, pattern_info in self.patterns.items():
                if pattern_info['pattern'].lower() in value:
                    detected.append({
                        'algorithm': pattern_info['algorithm'],
                        'location': string.get('address'),
                        'confidence': 'high',
                        'pattern': pattern_name,
                        'description': pattern_info['description']
                    })

        # Search in function names
        functions = context.get("functions", [])
        crypto_keywords = ['aes', 'md5', 'sha', 'rsa', 'rc4', 'des', 'crypt', 'cipher', 'hash']

        for func in functions:
            func_name = func.get('name', '').lower()
            for keyword in crypto_keywords:
                if keyword in func_name:
                    detected.append({
                        'algorithm': keyword.upper(),
                        'location': func.get('address'),
                        'confidence': 'medium',
                        'pattern': 'function_name',
                        'description': f'Function name contains crypto keyword: {keyword}'
                    })
                    break

        return detected
