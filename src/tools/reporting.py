"""
Malware analysis report generation tools.

Provides tools for generating structured reports from analysis sessions:
- Markdown reports with IOCs, MITRE ATT&CK mapping
- Executive summaries
- Technical details with timeline
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from src.utils.security import PathTraversalError, sanitize_output_path

logger = logging.getLogger(__name__)

# Allowed output directory for reports
REPORTS_OUTPUT_DIR = Path.home() / ".binary_mcp_output" / "reports"

# MITRE ATT&CK technique mappings for common behaviors
MITRE_MAPPINGS = {
    # Execution
    "CreateProcess": ("T1106", "Execution", "Native API"),
    "CreateRemoteThread": ("T1055", "Defense Evasion", "Process Injection"),
    "WinExec": ("T1106", "Execution", "Native API"),
    "ShellExecute": ("T1106", "Execution", "Native API"),
    "cmd.exe": ("T1059.003", "Execution", "Windows Command Shell"),
    "powershell": ("T1059.001", "Execution", "PowerShell"),

    # Persistence
    "RegSetValueEx": ("T1547.001", "Persistence", "Registry Run Keys"),
    "CreateService": ("T1543.003", "Persistence", "Windows Service"),
    "schtasks": ("T1053.005", "Persistence", "Scheduled Task"),

    # Defense Evasion
    "VirtualAllocEx": ("T1055", "Defense Evasion", "Process Injection"),
    "WriteProcessMemory": ("T1055", "Defense Evasion", "Process Injection"),
    "IsDebuggerPresent": ("T1622", "Defense Evasion", "Debugger Evasion"),
    "VirtualProtect": ("T1055", "Defense Evasion", "Process Injection"),
    "NtUnmapViewOfSection": ("T1055.012", "Defense Evasion", "Process Hollowing"),

    # Credential Access
    "CredRead": ("T1555", "Credential Access", "Credentials from Password Stores"),
    "CryptUnprotectData": ("T1555.004", "Credential Access", "Windows Credential Manager"),

    # Discovery
    "GetComputerName": ("T1082", "Discovery", "System Information Discovery"),
    "GetUserName": ("T1033", "Discovery", "System Owner/User Discovery"),
    "EnumProcesses": ("T1057", "Discovery", "Process Discovery"),
    "GetAdaptersInfo": ("T1016", "Discovery", "System Network Configuration"),

    # Collection
    "GetClipboardData": ("T1115", "Collection", "Clipboard Data"),
    "SetWindowsHookEx": ("T1056.001", "Collection", "Keylogging"),
    "GetAsyncKeyState": ("T1056.001", "Collection", "Keylogging"),

    # Command and Control
    "InternetOpen": ("T1071", "Command and Control", "Application Layer Protocol"),
    "URLDownloadToFile": ("T1105", "Command and Control", "Ingress Tool Transfer"),
    "HttpSendRequest": ("T1071.001", "Command and Control", "Web Protocols"),

    # Exfiltration
    "FtpPutFile": ("T1048", "Exfiltration", "Exfiltration Over Alternative Protocol"),

    # Impact
    "CryptEncrypt": ("T1486", "Impact", "Data Encrypted for Impact"),
    "DeleteFile": ("T1485", "Impact", "Data Destruction"),
}


def map_to_mitre(indicators: list) -> list[dict]:
    """Map indicators to MITRE ATT&CK techniques."""
    techniques = {}

    for indicator in indicators:
        indicator_str = str(indicator)
        for keyword, (technique_id, tactic, technique_name) in MITRE_MAPPINGS.items():
            if keyword.lower() in indicator_str.lower():
                if technique_id not in techniques:
                    techniques[technique_id] = {
                        "technique_id": technique_id,
                        "tactic": tactic,
                        "technique": technique_name,
                        "indicators": [],
                    }
                if indicator_str not in techniques[technique_id]["indicators"]:
                    techniques[technique_id]["indicators"].append(indicator_str)

    return list(techniques.values())


def generate_markdown_report(
    session_data: dict,
    include_sections: list[str] | None = None,
) -> str:
    """
    Generate a Markdown report from session data.

    Args:
        session_data: Analysis session data
        include_sections: Sections to include (default: all)

    Returns:
        Markdown formatted report
    """
    if include_sections is None:
        include_sections = [
            "executive_summary",
            "iocs",
            "mitre_attack",
            "technical_details",
            "timeline",
            "recommendations",
        ]

    sections = []

    # Header
    binary_path = session_data.get("binary_path", "Unknown")
    binary_name = Path(binary_path).name if binary_path else "Unknown"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sections.append(f"# Malware Analysis Report: {binary_name}")
    sections.append("")
    sections.append(f"**Generated:** {timestamp}")
    sections.append(f"**Session ID:** {session_data.get('session_id', 'N/A')}")
    sections.append(f"**Binary:** `{binary_path}`")
    sections.append("")

    # Executive Summary
    if "executive_summary" in include_sections:
        sections.append("## Executive Summary")
        sections.append("")

        tool_calls = session_data.get("tool_calls", [])
        analysis_types = set()
        for call in tool_calls:
            atype = call.get("analysis_type", "unknown")
            analysis_types.add(atype)

        sections.append(f"This report summarizes the analysis of `{binary_name}`.")
        sections.append(f"Analysis included {len(tool_calls)} tool calls ")
        sections.append(f"using {', '.join(analysis_types) or 'various'} analysis methods.")
        sections.append("")

        # Key findings
        findings = session_data.get("findings", {})
        if findings:
            sections.append("### Key Findings")
            sections.append("")
            for category, items in findings.items():
                if items:
                    sections.append(f"- **{category.replace('_', ' ').title()}:** {len(items)} indicators")
            sections.append("")

    # IOCs
    if "iocs" in include_sections:
        sections.append("## Indicators of Compromise (IOCs)")
        sections.append("")

        iocs = session_data.get("iocs", {})
        hashes = iocs.get("hashes", {})

        if hashes:
            sections.append("### File Hashes")
            sections.append("")
            sections.append("| Algorithm | Hash |")
            sections.append("|-----------|------|")
            for algo, value in hashes.items():
                sections.append(f"| {algo.upper()} | `{value}` |")
            sections.append("")

        network_iocs = iocs.get("network", {})
        if network_iocs:
            sections.append("### Network IOCs")
            sections.append("")

            urls = network_iocs.get("urls", [])
            if urls:
                sections.append("**URLs:**")
                for url in urls[:20]:
                    sections.append(f"- `{url}`")
                sections.append("")

            ips = network_iocs.get("ips", [])
            if ips:
                sections.append("**IP Addresses:**")
                for ip in ips[:20]:
                    sections.append(f"- `{ip}`")
                sections.append("")

            domains = network_iocs.get("domains", [])
            if domains:
                sections.append("**Domains:**")
                for domain in domains[:20]:
                    sections.append(f"- `{domain}`")
                sections.append("")

        file_iocs = iocs.get("files", [])
        if file_iocs:
            sections.append("### File IOCs")
            sections.append("")
            for f in file_iocs[:20]:
                sections.append(f"- `{f}`")
            sections.append("")

        registry_iocs = iocs.get("registry", [])
        if registry_iocs:
            sections.append("### Registry IOCs")
            sections.append("")
            for r in registry_iocs[:20]:
                sections.append(f"- `{r}`")
            sections.append("")

    # MITRE ATT&CK
    if "mitre_attack" in include_sections:
        sections.append("## MITRE ATT&CK Mapping")
        sections.append("")

        # Collect all indicators for mapping
        all_indicators = []
        for call in session_data.get("tool_calls", []):
            output = call.get("output", "")
            if isinstance(output, str):
                all_indicators.append(output)

        techniques = map_to_mitre(all_indicators)

        if techniques:
            # Group by tactic
            by_tactic = {}
            for t in techniques:
                by_tactic.setdefault(t["tactic"], []).append(t)

            for tactic, techs in sorted(by_tactic.items()):
                sections.append(f"### {tactic}")
                sections.append("")
                sections.append("| Technique ID | Technique | Evidence |")
                sections.append("|--------------|-----------|----------|")
                for t in techs:
                    evidence = t["indicators"][0][:50] + "..." if t["indicators"] else "N/A"
                    sections.append(f"| {t['technique_id']} | {t['technique']} | {evidence} |")
                sections.append("")
        else:
            sections.append("No MITRE ATT&CK techniques mapped from current indicators.")
            sections.append("")

    # Technical Details
    if "technical_details" in include_sections:
        sections.append("## Technical Details")
        sections.append("")

        tool_calls = session_data.get("tool_calls", [])

        if tool_calls:
            # Group by analysis type
            static_calls = [c for c in tool_calls if c.get("analysis_type") == "static"]
            dynamic_calls = [c for c in tool_calls if c.get("analysis_type") == "dynamic"]

            if static_calls:
                sections.append("### Static Analysis")
                sections.append("")
                sections.append(f"Performed {len(static_calls)} static analysis operations.")
                sections.append("")

                # List unique tools used
                static_tools = set(c.get("tool_name", "unknown") for c in static_calls)
                sections.append("**Tools used:**")
                for tool in sorted(static_tools):
                    sections.append(f"- `{tool}`")
                sections.append("")

            if dynamic_calls:
                sections.append("### Dynamic Analysis")
                sections.append("")
                sections.append(f"Performed {len(dynamic_calls)} dynamic analysis operations.")
                sections.append("")

                dynamic_tools = set(c.get("tool_name", "unknown") for c in dynamic_calls)
                sections.append("**Tools used:**")
                for tool in sorted(dynamic_tools):
                    sections.append(f"- `{tool}`")
                sections.append("")

    # Timeline
    if "timeline" in include_sections:
        sections.append("## Analysis Timeline")
        sections.append("")

        tool_calls = session_data.get("tool_calls", [])

        if tool_calls:
            sections.append("| Time | Tool | Result |")
            sections.append("|------|------|--------|")

            for call in tool_calls[:30]:
                ts = call.get("timestamp", "")
                if ts:
                    try:
                        dt = datetime.fromisoformat(ts)
                        time_str = dt.strftime("%H:%M:%S")
                    except (ValueError, TypeError):
                        time_str = str(ts)[:8]
                else:
                    time_str = "N/A"

                tool = call.get("tool_name", "unknown")
                output = str(call.get("output", ""))[:50]
                if len(output) == 50:
                    output += "..."

                sections.append(f"| {time_str} | `{tool}` | {output} |")

            if len(tool_calls) > 30:
                sections.append(f"| ... | *{len(tool_calls) - 30} more calls* | ... |")

            sections.append("")

    # Recommendations
    if "recommendations" in include_sections:
        sections.append("## Recommendations")
        sections.append("")

        recommendations = session_data.get("recommendations", [])
        if recommendations:
            for rec in recommendations:
                sections.append(f"- {rec}")
        else:
            sections.append("- Continue monitoring for related indicators")
            sections.append("- Block identified network IOCs at perimeter")
            sections.append("- Search for similar files using provided hashes")
            sections.append("- Update detection rules based on identified behaviors")

        sections.append("")

    # Footer
    sections.append("---")
    sections.append("")
    sections.append("*Report generated by Binary MCP*")

    return "\n".join(sections)


def register_reporting_tools(app, session_manager):
    """
    Register reporting tools with the MCP app.

    Args:
        app: FastMCP application instance
        session_manager: Session manager for accessing session data
    """

    @app.tool()
    def generate_report(
        session_id: str = "",
        output_path: str = "",
        format: str = "markdown",
        sections: str = "",
    ) -> str:
        """
        Generate an analysis report from session data.

        Creates a structured report with executive summary, IOCs,
        MITRE ATT&CK mapping, technical details, and recommendations.

        Args:
            session_id: Session ID to generate report for (uses active session if empty)
            output_path: Optional path to save report to file
            format: Report format (currently only "markdown" supported)
            sections: Comma-separated list of sections to include
                      (executive_summary,iocs,mitre_attack,technical_details,timeline,recommendations)

        Returns:
            Generated report content

        Example:
            generate_report()  # Use active session
            generate_report(session_id="abc123", output_path="report.md")
            generate_report(sections="iocs,mitre_attack")
        """
        try:
            # Get session data
            if session_id:
                sid = session_id
            elif session_manager.active_session_id:
                sid = session_manager.active_session_id
            else:
                return "No session specified and no active session. Start a session first or provide session_id."

            session = session_manager.get_session(sid)
            if not session:
                return f"Session not found: {sid}"

            # Parse sections
            include_sections = None
            if sections:
                include_sections = [s.strip() for s in sections.split(",")]

            # Generate report
            if format.lower() == "markdown":
                report = generate_markdown_report(session, include_sections)
            else:
                return f"Unsupported format: {format}. Currently only 'markdown' is supported."

            # Save to file if requested
            if output_path:
                try:
                    # Ensure output directory exists
                    REPORTS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
                    # Validate output path to prevent directory traversal
                    safe_path = sanitize_output_path(Path(output_path), REPORTS_OUTPUT_DIR)
                    safe_path.parent.mkdir(parents=True, exist_ok=True)
                    safe_path.write_text(report)
                    return f"Report saved to: {safe_path}\n\n" + report[:500] + "\n...\n(truncated)"
                except PathTraversalError:
                    return f"Error: Output path must be within {REPORTS_OUTPUT_DIR}"

            return report

        except Exception as e:
            logger.error(f"generate_report failed: {e}")
            return f"Error generating report: {e}"

    @app.tool()
    def export_iocs(
        session_id: str = "",
        format: str = "text",
        output_path: str = "",
    ) -> str:
        """
        Export IOCs from a session in various formats.

        Args:
            session_id: Session ID (uses active session if empty)
            format: Export format (text, csv, json)
            output_path: Optional path to save IOCs

        Returns:
            Exported IOCs

        Example:
            export_iocs(format="csv", output_path="iocs.csv")
        """
        try:
            # Get session data
            if session_id:
                sid = session_id
            elif session_manager.active_session_id:
                sid = session_manager.active_session_id
            else:
                return "No session specified and no active session."

            session = session_manager.get_session(sid)
            if not session:
                return f"Session not found: {sid}"

            iocs = session.get("iocs", {})

            # Flatten IOCs
            all_iocs = []

            hashes = iocs.get("hashes", {})
            for algo, value in hashes.items():
                all_iocs.append({"type": f"hash_{algo}", "value": value})

            for url in iocs.get("network", {}).get("urls", []):
                all_iocs.append({"type": "url", "value": url})

            for ip in iocs.get("network", {}).get("ips", []):
                all_iocs.append({"type": "ip", "value": ip})

            for domain in iocs.get("network", {}).get("domains", []):
                all_iocs.append({"type": "domain", "value": domain})

            for f in iocs.get("files", []):
                all_iocs.append({"type": "file", "value": f})

            for r in iocs.get("registry", []):
                all_iocs.append({"type": "registry", "value": r})

            if not all_iocs:
                return "No IOCs found in session."

            # Format output
            if format.lower() == "json":
                output = json.dumps(all_iocs, indent=2)
            elif format.lower() == "csv":
                lines = ["type,value"]
                for ioc in all_iocs:
                    # Escape commas and quotes
                    value = ioc["value"].replace('"', '""')
                    if "," in value or '"' in value:
                        value = f'"{value}"'
                    lines.append(f"{ioc['type']},{value}")
                output = "\n".join(lines)
            else:  # text
                lines = []
                by_type = {}
                for ioc in all_iocs:
                    by_type.setdefault(ioc["type"], []).append(ioc["value"])

                for ioc_type, values in sorted(by_type.items()):
                    lines.append(f"[{ioc_type.upper()}]")
                    for v in values:
                        lines.append(v)
                    lines.append("")

                output = "\n".join(lines)

            # Save if requested
            if output_path:
                try:
                    # Ensure output directory exists
                    REPORTS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
                    # Validate output path to prevent directory traversal
                    safe_path = sanitize_output_path(Path(output_path), REPORTS_OUTPUT_DIR)
                    safe_path.parent.mkdir(parents=True, exist_ok=True)
                    safe_path.write_text(output)
                    return f"IOCs exported to: {safe_path}\n\nTotal IOCs: {len(all_iocs)}"
                except PathTraversalError:
                    return f"Error: Output path must be within {REPORTS_OUTPUT_DIR}"

            return output

        except Exception as e:
            logger.error(f"export_iocs failed: {e}")
            return f"Error exporting IOCs: {e}"

    logger.info("Registered 2 reporting tools")
