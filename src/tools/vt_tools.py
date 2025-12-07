"""
VirusTotal integration tools for binary analysis.

Provides tools for:
- Hash/file lookup on VirusTotal
- Detection summary and AV results
- Related samples search
- Behavior analysis results

Requires VT_API_KEY environment variable or config.
"""

import hashlib
import json
import logging
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

# VirusTotal API configuration
VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_API_KEY_ENV = "VT_API_KEY"


def _get_api_key() -> str | None:
    """Get VirusTotal API key from .env file or environment."""
    from src.utils.config import get_config
    return get_config(VT_API_KEY_ENV)


def _vt_request(endpoint: str, method: str = "GET", data: bytes | None = None) -> dict:
    """
    Make a request to VirusTotal API.

    Args:
        endpoint: API endpoint (e.g., "/files/{id}")
        method: HTTP method
        data: Request body for POST

    Returns:
        JSON response as dict

    Raises:
        ValueError: If API key not configured
        RuntimeError: If API request fails
    """
    api_key = _get_api_key()
    if not api_key:
        raise ValueError(
            f"VirusTotal API key not configured. "
            f"Set {VT_API_KEY_ENV} environment variable."
        )

    url = f"{VT_API_BASE}{endpoint}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    if data:
        headers["Content-Type"] = "application/json"

    req = Request(url, data=data, headers=headers, method=method)

    try:
        with urlopen(req, timeout=30) as response:  # nosec B310 - VT API URL is hardcoded
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as e:
        if e.code == 404:
            raise RuntimeError("Hash not found in VirusTotal database")
        elif e.code == 401:
            raise RuntimeError("Invalid VirusTotal API key")
        elif e.code == 429:
            raise RuntimeError("VirusTotal API rate limit exceeded. Try again later.")
        else:
            raise RuntimeError(f"VirusTotal API error: {e.code} {e.reason}")
    except URLError as e:
        raise RuntimeError(f"Network error connecting to VirusTotal: {e.reason}")


def calculate_file_hashes(file_path: str) -> dict:
    """
    Calculate MD5, SHA1, and SHA256 hashes of a file.

    Args:
        file_path: Path to file

    Returns:
        Dict with md5, sha1, sha256 keys
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    md5 = hashlib.md5()  # nosec B324 - MD5 used for identification, not security
    sha1 = hashlib.sha1()  # nosec B324 - SHA1 used for identification, not security
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def lookup_hash(file_hash: str) -> dict:
    """
    Look up a hash on VirusTotal.

    Args:
        file_hash: MD5, SHA1, or SHA256 hash

    Returns:
        VirusTotal analysis results
    """
    # Normalize hash
    file_hash = file_hash.lower().strip()

    # Validate hash format
    if len(file_hash) not in (32, 40, 64):
        raise ValueError(
            f"Invalid hash length: {len(file_hash)}. "
            "Expected MD5 (32), SHA1 (40), or SHA256 (64)."
        )

    response = _vt_request(f"/files/{file_hash}")
    return response.get("data", {})


def lookup_file(file_path: str) -> dict:
    """
    Calculate file hash and look it up on VirusTotal.

    Args:
        file_path: Path to file

    Returns:
        VirusTotal analysis results with file hashes
    """
    hashes = calculate_file_hashes(file_path)
    result = lookup_hash(hashes["sha256"])
    result["local_hashes"] = hashes
    return result


def get_behavior_report(file_hash: str) -> dict:
    """
    Get behavior analysis report from VirusTotal sandbox.

    Args:
        file_hash: SHA256 hash of file

    Returns:
        Behavior analysis results
    """
    file_hash = file_hash.lower().strip()
    response = _vt_request(f"/files/{file_hash}/behaviour_summary")
    return response.get("data", {})


def search_files(query: str, limit: int = 10) -> list[dict]:
    """
    Search VirusTotal for files matching query.

    Args:
        query: VT search query (e.g., "content:malware" or "tag:ransomware")
        limit: Maximum results to return

    Returns:
        List of matching files
    """
    # URL encode the query
    from urllib.parse import quote
    encoded_query = quote(query)

    response = _vt_request(f"/intelligence/search?query={encoded_query}&limit={limit}")
    return response.get("data", [])


def format_detection_summary(vt_data: dict) -> dict:
    """
    Format VirusTotal data into a readable summary.

    Args:
        vt_data: Raw VirusTotal API response data

    Returns:
        Formatted summary dict
    """
    attributes = vt_data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    results = attributes.get("last_analysis_results", {})

    # Calculate detection ratio
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0

    # Get top detections
    detections = []
    for engine, result in results.items():
        if result.get("category") in ("malicious", "suspicious"):
            detections.append({
                "engine": engine,
                "result": result.get("result", "Unknown"),
                "category": result.get("category"),
            })

    # Sort by engine name for consistency
    detections.sort(key=lambda x: x["engine"])

    # Extract useful metadata
    summary = {
        "detection_ratio": f"{malicious + suspicious}/{total}",
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": stats.get("undetected", 0),
        "total_engines": total,
        "sha256": attributes.get("sha256"),
        "sha1": attributes.get("sha1"),
        "md5": attributes.get("md5"),
        "file_type": attributes.get("type_description"),
        "file_size": attributes.get("size"),
        "first_seen": attributes.get("first_submission_date"),
        "last_seen": attributes.get("last_submission_date"),
        "last_analysis": attributes.get("last_analysis_date"),
        "tags": attributes.get("tags", []),
        "names": attributes.get("names", [])[:5],  # First 5 names
        "detections": detections[:20],  # Top 20 detections
    }

    # Convert timestamps
    for field in ("first_seen", "last_seen", "last_analysis"):
        if summary[field]:
            try:
                from datetime import datetime
                summary[field] = datetime.fromtimestamp(summary[field]).isoformat()
            except (ValueError, TypeError, OSError):
                pass

    return summary


def register_vt_tools(app, session_manager=None):
    """
    Register VirusTotal tools with the MCP app.

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
    def vt_lookup(
        file_hash: str = "",
        file_path: str = "",
    ) -> str:
        """
        Look up a file on VirusTotal by hash or path.

        Queries VirusTotal for detection results, file metadata, and tags.
        Requires VT_API_KEY environment variable.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash to look up
            file_path: Path to file (will calculate hash automatically)

        Returns:
            Detection summary with AV results

        Example:
            vt_lookup(file_hash="44d88612fea8a8f36de82e1278abb02f")
            vt_lookup(file_path="suspicious.exe")
        """
        try:
            if not file_hash and not file_path:
                return "Error: Provide either file_hash or file_path"

            output = []
            output.append("=" * 60)
            output.append("VIRUSTOTAL LOOKUP")
            output.append("=" * 60)

            # Get VT data
            if file_path:
                file_path = sanitize_binary_path(file_path)
                output.append(f"File: {file_path}")

                # Calculate hashes
                hashes = calculate_file_hashes(file_path)
                output.append(f"MD5:    {hashes['md5']}")
                output.append(f"SHA1:   {hashes['sha1']}")
                output.append(f"SHA256: {hashes['sha256']}")
                output.append("")

                vt_data = lookup_hash(hashes["sha256"])
            else:
                output.append(f"Hash: {file_hash}")
                output.append("")
                vt_data = lookup_hash(file_hash)

            # Format results
            summary = format_detection_summary(vt_data)

            # Detection summary
            if summary["malicious"] > 0:
                output.append(f"⚠ MALICIOUS: {summary['detection_ratio']} engines detected this file")
            elif summary["suspicious"] > 0:
                output.append(f"⚡ SUSPICIOUS: {summary['detection_ratio']} engines flagged this file")
            else:
                output.append(f"✓ CLEAN: {summary['detection_ratio']} - No detections")

            output.append("")
            output.append("File Information:")
            output.append(f"  Type: {summary['file_type'] or 'Unknown'}")
            output.append(f"  Size: {summary['file_size'] or 'Unknown'} bytes")

            if summary["first_seen"]:
                output.append(f"  First Seen: {summary['first_seen']}")
            if summary["last_seen"]:
                output.append(f"  Last Seen: {summary['last_seen']}")

            if summary["tags"]:
                output.append(f"  Tags: {', '.join(summary['tags'][:10])}")

            if summary["names"]:
                output.append(f"  Known Names: {', '.join(summary['names'])}")

            # Show detections
            if summary["detections"]:
                output.append("")
                output.append(f"Detections ({len(summary['detections'])} shown):")
                for det in summary["detections"][:15]:
                    output.append(f"  • {det['engine']}: {det['result']}")
                if len(summary["detections"]) > 15:
                    output.append(f"  ... and {len(summary['detections']) - 15} more")

            # Hashes for reference
            output.append("")
            output.append("Hashes:")
            output.append(f"  MD5:    {summary['md5']}")
            output.append(f"  SHA1:   {summary['sha1']}")
            output.append(f"  SHA256: {summary['sha256']}")

            return "\n".join(output)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("vt_lookup", e)
        except ValueError as e:
            return f"Configuration error: {e}"
        except RuntimeError as e:
            return f"VirusTotal error: {e}"
        except FileNotFoundError as e:
            return f"File not found: {e}"
        except Exception as e:
            logger.error(f"vt_lookup failed: {e}")
            return f"Error looking up file: {e}"

    @app.tool()
    def vt_behavior(file_hash: str) -> str:
        """
        Get VirusTotal sandbox behavior report for a file.

        Shows process activity, file operations, network connections,
        and registry changes observed during sandbox execution.

        Args:
            file_hash: SHA256 hash of file

        Returns:
            Behavior analysis summary

        Example:
            vt_behavior("a1b2c3d4e5f6...")
        """
        try:
            output = []
            output.append("=" * 60)
            output.append("VIRUSTOTAL BEHAVIOR REPORT")
            output.append("=" * 60)
            output.append(f"Hash: {file_hash}")
            output.append("")

            behavior = get_behavior_report(file_hash)

            if not behavior:
                output.append("No behavior data available for this file.")
                output.append("The file may not have been executed in a sandbox.")
                return "\n".join(output)

            # Process activity
            processes = behavior.get("processes_created", [])
            if processes:
                output.append(f"Processes Created ({len(processes)}):")
                for proc in processes[:10]:
                    output.append(f"  • {proc}")
                if len(processes) > 10:
                    output.append(f"  ... and {len(processes) - 10} more")
                output.append("")

            # Files operations
            files_written = behavior.get("files_written", [])
            if files_written:
                output.append(f"Files Written ({len(files_written)}):")
                for f in files_written[:10]:
                    output.append(f"  • {f}")
                if len(files_written) > 10:
                    output.append(f"  ... and {len(files_written) - 10} more")
                output.append("")

            files_deleted = behavior.get("files_deleted", [])
            if files_deleted:
                output.append(f"Files Deleted ({len(files_deleted)}):")
                for f in files_deleted[:10]:
                    output.append(f"  • {f}")
                output.append("")

            # Network activity
            dns = behavior.get("dns_lookups", [])
            if dns:
                output.append(f"DNS Lookups ({len(dns)}):")
                for d in dns[:10]:
                    if isinstance(d, dict):
                        output.append(f"  • {d.get('hostname', d)}")
                    else:
                        output.append(f"  • {d}")
                output.append("")

            http = behavior.get("http_conversations", [])
            if http:
                output.append(f"HTTP Connections ({len(http)}):")
                for h in http[:10]:
                    if isinstance(h, dict):
                        output.append(f"  • {h.get('url', h)}")
                    else:
                        output.append(f"  • {h}")
                output.append("")

            # Registry
            registry = behavior.get("registry_keys_set", [])
            if registry:
                output.append(f"Registry Keys Set ({len(registry)}):")
                for r in registry[:10]:
                    output.append(f"  • {r}")
                if len(registry) > 10:
                    output.append(f"  ... and {len(registry) - 10} more")
                output.append("")

            # Mutexes
            mutexes = behavior.get("mutexes_created", [])
            if mutexes:
                output.append(f"Mutexes Created ({len(mutexes)}):")
                for m in mutexes[:10]:
                    output.append(f"  • {m}")
                output.append("")

            # Command executions
            commands = behavior.get("command_executions", [])
            if commands:
                output.append(f"Commands Executed ({len(commands)}):")
                for c in commands[:10]:
                    output.append(f"  • {c[:100]}...")
                output.append("")

            # Tags/verdicts
            verdicts = behavior.get("verdicts", [])
            if verdicts:
                output.append("Sandbox Verdicts:")
                for v in verdicts:
                    output.append(f"  • {v}")

            if len(output) == 4:  # Only header lines
                output.append("No significant behavior recorded.")

            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except RuntimeError as e:
            return f"VirusTotal error: {e}"
        except Exception as e:
            logger.error(f"vt_behavior failed: {e}")
            return f"Error getting behavior report: {e}"

    @app.tool()
    def vt_search(query: str, limit: int = 10) -> str:
        """
        Search VirusTotal for files matching a query.

        Uses VirusTotal Intelligence search syntax.
        Requires a VirusTotal Premium API key.

        Args:
            query: Search query (e.g., "tag:ransomware", "content:MZ")
            limit: Maximum results (default: 10)

        Returns:
            List of matching files with detection info

        Example:
            vt_search("tag:ransomware")
            vt_search("content:PYTHONSCRIPT")
            vt_search("name:malware.exe")
        """
        try:
            output = []
            output.append("=" * 60)
            output.append("VIRUSTOTAL SEARCH")
            output.append("=" * 60)
            output.append(f"Query: {query}")
            output.append(f"Limit: {limit}")
            output.append("")

            results = search_files(query, limit)

            if not results:
                output.append("No results found.")
                return "\n".join(output)

            output.append(f"Found {len(results)} results:")
            output.append("")

            for i, item in enumerate(results, 1):
                attrs = item.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 0

                sha256 = attrs.get("sha256", "Unknown")
                file_type = attrs.get("type_description", "Unknown")
                names = attrs.get("names", [])
                name = names[0] if names else "Unknown"

                output.append(f"{i}. {name}")
                output.append(f"   SHA256: {sha256}")
                output.append(f"   Type: {file_type}")
                output.append(f"   Detection: {malicious}/{total}")

                tags = attrs.get("tags", [])
                if tags:
                    output.append(f"   Tags: {', '.join(tags[:5])}")

                output.append("")

            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except RuntimeError as e:
            return f"VirusTotal error: {e}"
        except Exception as e:
            logger.error(f"vt_search failed: {e}")
            return f"Error searching VirusTotal: {e}"

    @app.tool()
    def vt_check_api() -> str:
        """
        Check if VirusTotal API is configured and working.

        Verifies the API key is set and can connect to VirusTotal.

        Returns:
            API status and quota information
        """
        try:
            output = []
            output.append("=" * 60)
            output.append("VIRUSTOTAL API STATUS")
            output.append("=" * 60)

            api_key = _get_api_key()
            if not api_key:
                output.append("✗ API key not configured")
                output.append("")
                output.append("Configure your API key using one of these methods:")
                output.append("")
                output.append("1. Create a .env file in the project root:")
                output.append(f"   {VT_API_KEY_ENV}=your_api_key_here")
                output.append("")
                output.append("2. Or set an environment variable:")
                output.append(f"   export {VT_API_KEY_ENV}=your_api_key_here")
                output.append("")
                output.append("Get your API key from: https://www.virustotal.com/gui/my-apikey")
                return "\n".join(output)

            # Mask the API key
            masked_key = api_key[:8] + "..." + api_key[-4:]
            output.append(f"✓ API key configured: {masked_key}")

            # Test with a known hash (EICAR test file)
            test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

            try:
                result = lookup_hash(test_hash)
                output.append("✓ API connection successful")
                output.append("")
                output.append("Test lookup (EICAR test file):")
                summary = format_detection_summary(result)
                output.append(f"  Detection: {summary['detection_ratio']}")
            except RuntimeError as e:
                if "rate limit" in str(e).lower():
                    output.append("⚠ API rate limit reached")
                else:
                    output.append(f"✗ API test failed: {e}")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"vt_check_api failed: {e}")
            return f"Error checking API: {e}"

    logger.info("Registered 4 VirusTotal tools")
