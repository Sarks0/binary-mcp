"""
Function ID (FID) library-match reporting tool.

FID matching happens inside ``core_analysis.py`` when ``enable_fid=True`` is
passed to ``analyze_binary``. This module just formats the results from the
cache. Keeping the reader separate from the analysis step means users can
query matches without re-running Ghidra.
"""

from __future__ import annotations

import logging

from src.utils.security import (
    FileSizeError,
    PathTraversalError,
    sanitize_binary_path,
    validate_numeric_range,
)

logger = logging.getLogger(__name__)


def register_fid_tools(app, session_manager, cache, runner):
    """Register fid_match MCP tool on the given FastMCP app."""

    @app.tool()
    def fid_match(
        binary_path: str,
        filter_unmatched: bool = True,
        limit: int = 100,
    ) -> str:
        """
        List functions identified by Ghidra's Function ID library database.

        Requires a prior run of ``analyze_binary(path, enable_fid=True)``.
        Matches are stored per-function as the ``fid_match`` field in the
        cache. Useful for filtering out stdlib / CRT noise so your review
        focuses on binary-specific code.

        Args:
            binary_path: Path to analyzed binary
            filter_unmatched: When True (default), only list functions that
                actually matched a FID entry
            limit: Max rows returned (default 100, max 10000)

        Returns:
            Formatted table, or guidance to re-run with ``enable_fid=True``.
        """
        try:
            limit = validate_numeric_range(limit, 1, 10000, "limit")
            validated = sanitize_binary_path(binary_path)
            bp = str(validated)

            cached = cache.get_cached(bp)
            if not cached:
                return (
                    "No cached analysis. Run "
                    "`analyze_binary(path, enable_fid=True)` first."
                )

            functions = cached.get("functions", [])
            # Detect whether FID ran at all
            has_fid_field = any("fid_match" in f for f in functions)
            if not has_fid_field:
                return (
                    "Cache has no fid_match data. Re-run "
                    "`analyze_binary(path, force_reanalyze=True, enable_fid=True)` "
                    "to populate Function ID matches."
                )

            rows: list[tuple[dict, dict]] = []
            matched_count = 0
            unmatched_count = 0
            for func in functions:
                m = func.get("fid_match")
                if m:
                    matched_count += 1
                    rows.append((func, m))
                else:
                    unmatched_count += 1
                    if not filter_unmatched:
                        rows.append((func, {}))

            total = len(rows)
            rows = rows[:limit]

            header = [
                f"**FID matches: {matched_count} matched / {unmatched_count} unmatched**",
                f"Showing {len(rows)} of {total}",
                "",
            ]
            if matched_count == 0:
                header.append(
                    "No FID matches found. Either FID databases are not "
                    "installed, the language is unsupported, or the binary "
                    "contains no recognised library functions."
                )
                return "\n".join(header)

            lines = header
            for func, m in rows:
                orig_name = func.get("name") or ""
                addr = func.get("address") or ""
                if m:
                    conf = m.get("confidence")
                    conf_str = f"{conf:.1f}" if isinstance(conf, (int, float)) else "?"
                    lines.append(
                        f"- {addr}  `{orig_name}`  →  "
                        f"{m.get('name', '?')}  [{m.get('library', '?')}, score={conf_str}]"
                    )
                else:
                    lines.append(f"- {addr}  `{orig_name}`  (no match)")
            return "\n".join(lines)

        except (PathTraversalError, FileSizeError, FileNotFoundError) as e:
            return f"Invalid binary path: {e}"
        except Exception as e:
            logger.exception(f"fid_match failed: {e}")
            return f"Error: {e}"

    return (fid_match,)
