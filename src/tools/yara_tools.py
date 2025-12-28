"""
Yara rule generation tools for malware detection.

Generates Yara rules from analysis sessions based on:
- Unique strings
- Import patterns
- Binary signatures
- Behavioral indicators
"""

import hashlib
import logging
import re
from datetime import datetime
from pathlib import Path

from src.utils.security import sanitize_output_path

logger = logging.getLogger(__name__)

# Allowed output directory for Yara rules
YARA_OUTPUT_DIR = Path.home() / ".binary_mcp_output" / "yara"


def sanitize_rule_name(name: str) -> str:
    """Convert a string to a valid Yara rule name."""
    # Remove extension
    name = Path(name).stem

    # Replace invalid characters
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', name)

    # Ensure starts with letter
    if sanitized and not sanitized[0].isalpha():
        sanitized = "rule_" + sanitized

    # Limit length
    return sanitized[:64]


def escape_yara_string(s: str) -> str:
    """Escape a string for use in Yara rules."""
    # Escape backslashes and quotes
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    return s


def is_good_string(s: str) -> bool:
    """Check if a string is suitable for Yara rule."""
    # Skip too short or too long
    if len(s) < 6 or len(s) > 200:
        return False

    # Skip pure whitespace
    if not s.strip():
        return False

    # Skip common/generic strings
    generic = [
        "error", "warning", "success", "failed", "true", "false",
        "null", "undefined", "function", "return", "import",
        "microsoft", "windows", ".dll", ".exe", "kernel32",
        "ntdll", "user32", "version", "copyright",
    ]
    if s.lower() in generic:
        return False

    # Skip strings that are all numbers
    if s.isdigit():
        return False

    # Skip very repetitive strings
    if len(set(s)) < 3:
        return False

    return True


def calculate_string_score(s: str, all_strings: list[str]) -> float:
    """Calculate uniqueness score for a string."""
    score = 0.0

    # Length bonus (prefer 10-50 chars)
    if 10 <= len(s) <= 50:
        score += 0.3
    elif len(s) > 50:
        score += 0.2

    # Uniqueness bonus (appears only once)
    count = all_strings.count(s)
    if count == 1:
        score += 0.3
    elif count <= 3:
        score += 0.1

    # Special character bonus (paths, URLs, etc.)
    if "\\" in s or "/" in s:
        score += 0.2
    if "@" in s or "://" in s:
        score += 0.3

    # Registry path bonus
    if "HKEY" in s or "Software\\" in s:
        score += 0.3

    # Mutex-like string bonus
    if "mutex" in s.lower() or "Global\\" in s:
        score += 0.3

    # C2 indicator bonus
    if any(x in s.lower() for x in ["beacon", "callback", "c2", "cnc", "shell"]):
        score += 0.4

    # PDB path is very unique
    if ".pdb" in s.lower():
        score += 0.5

    return min(score, 1.0)


def generate_yara_rule(
    rule_name: str,
    strings: list[str],
    meta: dict | None = None,
    imports: list[str] | None = None,
    condition: str = "any of them",
    strictness: str = "medium",
) -> str:
    """
    Generate a Yara rule from collected indicators.

    Args:
        rule_name: Name for the rule
        strings: List of strings to include
        meta: Metadata dictionary
        imports: List of imports to check
        condition: Yara condition string
        strictness: Rule strictness (low, medium, high)

    Returns:
        Yara rule as string
    """
    rule_name = sanitize_rule_name(rule_name)

    lines = []
    lines.append(f"rule {rule_name} {{")

    # Meta section
    lines.append("    meta:")
    if meta:
        for key, value in meta.items():
            if isinstance(value, str):
                lines.append(f'        {key} = "{escape_yara_string(value)}"')
            elif isinstance(value, int):
                lines.append(f'        {key} = {value}')
            elif isinstance(value, bool):
                lines.append(f'        {key} = {"true" if value else "false"}')
    else:
        lines.append(f'        description = "Auto-generated rule for {rule_name}"')
        lines.append('        author = "binary-mcp"')
        lines.append(f'        date = "{datetime.now().strftime("%Y-%m-%d")}"')

    # Strings section
    if strings:
        lines.append("")
        lines.append("    strings:")

        # Score and sort strings
        scored_strings = []
        for s in strings:
            if is_good_string(s):
                score = calculate_string_score(s, strings)
                scored_strings.append((s, score))

        scored_strings.sort(key=lambda x: x[1], reverse=True)

        # Select strings based on strictness
        if strictness == "low":
            max_strings = 10
            min_score = 0.1
        elif strictness == "high":
            max_strings = 5
            min_score = 0.4
        else:  # medium
            max_strings = 8
            min_score = 0.2

        selected = [s for s, score in scored_strings if score >= min_score][:max_strings]

        for i, s in enumerate(selected):
            var_name = f"$s{i}"

            # Determine string type
            if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-. /\\:@' for c in s):
                # ASCII string - check if wide
                if "\\" in s or "HKEY" in s:
                    lines.append(f'        {var_name} = "{escape_yara_string(s)}" wide ascii')
                else:
                    lines.append(f'        {var_name} = "{escape_yara_string(s)}" ascii')
            else:
                # Hex encode non-printable
                hex_str = " ".join(f"{ord(c):02x}" for c in s)
                lines.append(f'        {var_name} = {{ {hex_str} }}')

    # Imports section (as strings)
    if imports:
        lines.append("")
        lines.append("        // Suspicious imports")
        for i, imp in enumerate(imports[:5]):
            lines.append(f'        $imp{i} = "{imp}" ascii')

    # Condition section
    lines.append("")
    lines.append("    condition:")

    if strictness == "high":
        # Require PE and multiple matches
        if len(selected) >= 3:
            lines.append("        uint16(0) == 0x5A4D and")
            lines.append(f"        ({len(selected) - 1} of ($s*))")
        else:
            lines.append("        uint16(0) == 0x5A4D and")
            lines.append("        all of them")
    elif strictness == "low":
        # Just require any match
        lines.append("        any of them")
    else:  # medium
        # PE header and some matches
        if len(selected) >= 2:
            lines.append("        uint16(0) == 0x5A4D and")
            lines.append("        (2 of ($s*))")
        else:
            lines.append("        uint16(0) == 0x5A4D and")
            lines.append("        any of them")

    lines.append("}")

    return "\n".join(lines)


def register_yara_tools(app, session_manager):
    """
    Register Yara tools with the MCP app.

    Args:
        app: FastMCP application instance
        session_manager: Session manager for accessing session data
    """
    from src.utils.security import (
        FileSizeError,
        PathTraversalError,
        safe_error_message,
        sanitize_binary_path,
    )

    @app.tool()
    def generate_yara_rule_from_session(
        session_id: str = "",
        rule_name: str = "",
        strictness: str = "medium",
        output_path: str = "",
    ) -> str:
        """
        Generate a Yara rule from analysis session data.

        Creates detection rules based on unique strings, imports,
        and other indicators collected during analysis.

        Args:
            session_id: Session ID (uses active session if empty)
            rule_name: Name for the rule (auto-generated if empty)
            strictness: Rule strictness - "low" (more FPs), "medium", "high" (fewer FPs)
            output_path: Optional path to save rule

        Returns:
            Generated Yara rule

        Example:
            generate_yara_rule_from_session()
            generate_yara_rule_from_session(strictness="high", output_path="rule.yar")
        """
        try:
            # Get session
            if session_id:
                sid = session_id
            elif session_manager.active_session_id:
                sid = session_manager.active_session_id
            else:
                return "No session specified and no active session."

            session = session_manager.get_session(sid)
            if not session:
                return f"Session not found: {sid}"

            # Get binary name for rule
            binary_path = session.get("binary_path", "")
            if not rule_name:
                rule_name = Path(binary_path).stem if binary_path else "malware_detection"

            # Collect strings from session
            all_strings = []
            all_imports = []

            # From IOCs
            iocs = session.get("iocs", {})
            for url in iocs.get("network", {}).get("urls", []):
                all_strings.append(url)
            for fp in iocs.get("files", []):
                all_strings.append(fp)
            for reg in iocs.get("registry", []):
                all_strings.append(reg)

            # From tool outputs
            for call in session.get("tool_calls", []):
                output = call.get("output", "")
                if isinstance(output, str):
                    # Extract potential strings
                    for match in re.findall(r'[A-Za-z0-9_\-\\./:@]{8,100}', output):
                        if is_good_string(match):
                            all_strings.append(match)

            # Build meta
            meta = {
                "description": f"Detects {rule_name} based on analysis",
                "author": "binary-mcp",
                "date": datetime.now().strftime("%Y-%m-%d"),
                "session_id": sid,
            }

            hashes = iocs.get("hashes", {})
            if hashes.get("sha256"):
                meta["hash"] = hashes["sha256"]

            # Generate rule
            rule = generate_yara_rule(
                rule_name=rule_name,
                strings=list(set(all_strings)),
                meta=meta,
                imports=all_imports,
                strictness=strictness,
            )

            # Save if requested
            if output_path:
                try:
                    # Ensure output directory exists
                    YARA_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
                    # Validate output path to prevent directory traversal
                    safe_path = sanitize_output_path(Path(output_path), YARA_OUTPUT_DIR)
                    safe_path.parent.mkdir(parents=True, exist_ok=True)
                    safe_path.write_text(rule)
                    return f"Yara rule saved to: {safe_path}\n\n{rule}"
                except PathTraversalError:
                    return f"Error: Output path must be within {YARA_OUTPUT_DIR}"

            return rule

        except Exception as e:
            logger.error(f"generate_yara_rule_from_session failed: {e}")
            return f"Error generating Yara rule: {e}"

    @app.tool()
    def generate_yara_rule_from_strings(
        binary_path: str,
        rule_name: str = "",
        strictness: str = "medium",
        output_path: str = "",
    ) -> str:
        """
        Generate a Yara rule by extracting strings from a binary.

        Analyzes the binary directly to find unique, high-value strings
        suitable for detection.

        Args:
            binary_path: Path to binary file
            rule_name: Name for the rule (auto-generated if empty)
            strictness: Rule strictness - "low", "medium", "high"
            output_path: Optional path to save rule

        Returns:
            Generated Yara rule

        Example:
            generate_yara_rule_from_strings("malware.exe")
            generate_yara_rule_from_strings("malware.exe", strictness="high")
        """
        try:
            binary_path = sanitize_binary_path(binary_path)
            path = Path(binary_path)

            if not path.exists():
                return f"File not found: {binary_path}"

            data = path.read_bytes()

            # Calculate hash
            sha256 = hashlib.sha256(data).hexdigest()

            # Extract strings (ASCII)
            ascii_strings = []
            current = []
            for b in data:
                if 32 <= b < 127:
                    current.append(chr(b))
                else:
                    if len(current) >= 6:
                        ascii_strings.append("".join(current))
                    current = []

            # Extract strings (UTF-16 LE)
            utf16_strings = []
            i = 0
            while i < len(data) - 1:
                if data[i+1] == 0 and 32 <= data[i] < 127:
                    chars = []
                    while i < len(data) - 1 and data[i+1] == 0 and 32 <= data[i] < 127:
                        chars.append(chr(data[i]))
                        i += 2
                    if len(chars) >= 6:
                        utf16_strings.append("".join(chars))
                else:
                    i += 1

            all_strings = list(set(ascii_strings + utf16_strings))

            if not rule_name:
                rule_name = path.stem

            # Build meta
            meta = {
                "description": f"Detects {rule_name}",
                "author": "binary-mcp",
                "date": datetime.now().strftime("%Y-%m-%d"),
                "hash": sha256,
            }

            # Generate rule
            rule = generate_yara_rule(
                rule_name=rule_name,
                strings=all_strings,
                meta=meta,
                strictness=strictness,
            )

            # Save if requested
            if output_path:
                try:
                    # Ensure output directory exists
                    YARA_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
                    # Validate output path to prevent directory traversal
                    safe_path = sanitize_output_path(Path(output_path), YARA_OUTPUT_DIR)
                    safe_path.parent.mkdir(parents=True, exist_ok=True)
                    safe_path.write_text(rule)
                    return f"Yara rule saved to: {safe_path}\n\n{rule}"
                except PathTraversalError:
                    return f"Error: Output path must be within {YARA_OUTPUT_DIR}"

            return rule

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("generate_yara_rule_from_strings", e)
        except Exception as e:
            logger.error(f"generate_yara_rule_from_strings failed: {e}")
            return f"Error generating Yara rule: {e}"

    logger.info("Registered 2 Yara tools")
