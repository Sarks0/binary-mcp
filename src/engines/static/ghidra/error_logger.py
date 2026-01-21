"""
GhidraErrorLogger - Comprehensive error logging and tracking for Ghidra operations.

Stores detailed error information in structured JSON format for debugging and analysis.
Modeled after X64DbgErrorLogger for consistency across the binary-mcp project.
"""

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class GhidraErrorContext:
    """Context information for a Ghidra error."""

    operation: str  # Operation that failed (e.g., "analyze", "import", "decompile")
    binary_path: str | None = None  # Path to binary being analyzed
    binary_size_mb: float | None = None  # Binary file size in MB
    ghidra_version: str | None = None  # Ghidra version
    execution_mode: str | None = None  # "pyghidra" or "analyzeHeadless"
    timeout_seconds: int | None = None  # Configured timeout
    elapsed_seconds: float | None = None  # Time elapsed before error
    processor: str | None = None  # Processor specification
    loader: str | None = None  # Loader specification
    additional: dict[str, Any] = field(default_factory=dict)  # Any other context


@dataclass
class GhidraErrorRecord:
    """Complete error record with all metadata."""

    timestamp: float
    error_id: str
    operation: str
    error_type: str
    error_message: str
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    context: dict[str, Any] = field(default_factory=dict)
    traceback: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class GhidraErrorLogger:
    """
    Error logger for Ghidra operations.

    Stores errors in `~/.ghidra_mcp_cache/ghidra_errors/` with:
    - Individual JSON files per error
    - Manifest file for quick browsing
    - Statistics for error analysis
    - Automatic cleanup of old errors
    """

    def __init__(self, error_dir: Path | None = None, max_errors: int = 500):
        """
        Initialize error logger.

        Args:
            error_dir: Directory for error storage (defaults to ~/.ghidra_mcp_cache/ghidra_errors/)
            max_errors: Maximum number of errors to keep (oldest removed first)
        """
        if error_dir is None:
            cache_dir = Path.home() / ".ghidra_mcp_cache"
            self.error_dir = cache_dir / "ghidra_errors"
        else:
            self.error_dir = Path(error_dir)

        self.max_errors = max_errors
        self.manifest_file = self.error_dir / "manifest.json"
        self.stats_file = self.error_dir / "stats.json"

        # Create directory structure
        self.error_dir.mkdir(parents=True, exist_ok=True)

        # Initialize manifest and stats if they don't exist
        if not self.manifest_file.exists():
            self._save_manifest([])

        if not self.stats_file.exists():
            self._save_stats({})

        logger.debug(f"GhidraErrorLogger initialized: {self.error_dir}")

    def log_error(
        self,
        operation: str,
        error: Exception,
        context: GhidraErrorContext | None = None,
        exit_code: int | None = None,
        stdout: str | None = None,
        stderr: str | None = None,
        traceback_str: str | None = None,
    ) -> GhidraErrorRecord:
        """
        Log an error with full context.

        Args:
            operation: Operation that failed
            error: Exception that occurred
            context: Additional context information
            exit_code: Process exit code if applicable
            stdout: Process stdout if available
            stderr: Process stderr if available
            traceback_str: Full traceback string

        Returns:
            GhidraErrorRecord that was created
        """
        # Generate unique error ID
        error_id = f"ghidra_{uuid.uuid4().hex[:16]}"

        # Build error record
        record = GhidraErrorRecord(
            timestamp=time.time(),
            error_id=error_id,
            operation=operation,
            error_type=type(error).__name__,
            error_message=str(error),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            context=asdict(context) if context else {},
            traceback=traceback_str,
        )

        # Save error record
        self._save_error_record(record)

        # Update manifest
        self._update_manifest(record)

        # Update statistics
        self._update_stats(record)

        # Cleanup old errors if needed
        self._cleanup_old_errors()

        # Log to Python logger with error ID
        logger.error(
            f"[{error_id}] Ghidra {operation} failed: {type(error).__name__}: {str(error)}"
        )

        return record

    def _save_error_record(self, record: GhidraErrorRecord) -> None:
        """Save individual error record to JSON file."""
        # Format: {timestamp}_{operation}_{error_id}.json
        timestamp_str = time.strftime("%Y%m%d_%H%M%S", time.localtime(record.timestamp))
        filename = f"{timestamp_str}_{record.operation}_{record.error_id}.json"
        filepath = self.error_dir / filename

        try:
            with open(filepath, "w") as f:
                json.dump(record.to_dict(), f, indent=2)

            logger.debug(f"Saved Ghidra error record: {filename}")

        except Exception as e:
            logger.error(f"Failed to save Ghidra error record: {e}")

    def _update_manifest(self, record: GhidraErrorRecord) -> None:
        """Update manifest with new error entry."""
        try:
            manifest = self._load_manifest()

            # Add new entry
            manifest_entry = {
                "error_id": record.error_id,
                "timestamp": record.timestamp,
                "operation": record.operation,
                "error_type": record.error_type,
                "error_message": record.error_message[:200],  # Truncate for manifest
                "exit_code": record.exit_code,
            }

            manifest.append(manifest_entry)

            # Sort by timestamp (newest first)
            manifest.sort(key=lambda x: x["timestamp"], reverse=True)

            # Save updated manifest
            self._save_manifest(manifest)

        except Exception as e:
            logger.error(f"Failed to update Ghidra error manifest: {e}")

    def _update_stats(self, record: GhidraErrorRecord) -> None:
        """Update error statistics."""
        try:
            stats = self._load_stats()

            # Update counters
            stats["total_errors"] = stats.get("total_errors", 0) + 1

            # By operation
            by_operation = stats.get("by_operation", {})
            by_operation[record.operation] = by_operation.get(record.operation, 0) + 1
            stats["by_operation"] = by_operation

            # By error type
            by_type = stats.get("by_type", {})
            by_type[record.error_type] = by_type.get(record.error_type, 0) + 1
            stats["by_type"] = by_type

            # By exit code
            if record.exit_code is not None:
                by_exit_code = stats.get("by_exit_code", {})
                exit_key = str(record.exit_code)
                by_exit_code[exit_key] = by_exit_code.get(exit_key, 0) + 1
                stats["by_exit_code"] = by_exit_code

            # Update timestamp
            stats["last_error_timestamp"] = record.timestamp
            stats["last_updated"] = time.time()

            # Save updated stats
            self._save_stats(stats)

        except Exception as e:
            logger.error(f"Failed to update Ghidra error stats: {e}")

    def _cleanup_old_errors(self) -> None:
        """Remove oldest errors if count exceeds max_errors."""
        try:
            manifest = self._load_manifest()

            if len(manifest) <= self.max_errors:
                return

            # Sort by timestamp (oldest first for deletion)
            manifest_sorted = sorted(manifest, key=lambda x: x["timestamp"])

            # Determine how many to delete
            to_delete = len(manifest) - self.max_errors

            # Delete oldest error files
            for entry in manifest_sorted[:to_delete]:
                error_id = entry["error_id"]

                # Find and delete error file
                for error_file in self.error_dir.glob(f"*_{error_id}.json"):
                    try:
                        error_file.unlink()
                        logger.debug(f"Deleted old Ghidra error: {error_file.name}")
                    except Exception as e:
                        logger.warning(f"Failed to delete {error_file}: {e}")

            # Update manifest (keep only recent errors)
            updated_manifest = manifest_sorted[to_delete:]
            self._save_manifest(updated_manifest)

            logger.info(f"Cleaned up {to_delete} old Ghidra error records")

        except Exception as e:
            logger.error(f"Failed to cleanup old Ghidra errors: {e}")

    def _load_manifest(self) -> list[dict[str, Any]]:
        """Load manifest file."""
        try:
            if self.manifest_file.exists():
                with open(self.manifest_file) as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load Ghidra error manifest: {e}")

        return []

    def _save_manifest(self, manifest: list[dict[str, Any]]) -> None:
        """Save manifest file."""
        try:
            with open(self.manifest_file, "w") as f:
                json.dump(manifest, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save Ghidra error manifest: {e}")

    def _load_stats(self) -> dict[str, Any]:
        """Load statistics file."""
        try:
            if self.stats_file.exists():
                with open(self.stats_file) as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load Ghidra error stats: {e}")

        return {}

    def _save_stats(self, stats: dict[str, Any]) -> None:
        """Save statistics file."""
        try:
            with open(self.stats_file, "w") as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save Ghidra error stats: {e}")

    def get_error(self, error_id: str) -> GhidraErrorRecord | None:
        """
        Retrieve error record by ID.

        Args:
            error_id: Error ID to look up

        Returns:
            GhidraErrorRecord if found, None otherwise
        """
        # Find error file
        for error_file in self.error_dir.glob(f"*_{error_id}.json"):
            try:
                with open(error_file) as f:
                    data = json.load(f)
                    return GhidraErrorRecord(**data)
            except Exception as e:
                logger.error(f"Failed to load Ghidra error {error_id}: {e}")

        return None

    def get_recent_errors(self, count: int = 20) -> list[dict[str, Any]]:
        """
        Get recent errors from manifest.

        Args:
            count: Number of recent errors to return

        Returns:
            List of error summaries
        """
        manifest = self._load_manifest()
        return manifest[:count]

    def get_stats(self) -> dict[str, Any]:
        """
        Get error statistics.

        Returns:
            Dictionary with error statistics
        """
        return self._load_stats()

    def get_errors_by_operation(self, operation: str) -> list[GhidraErrorRecord]:
        """
        Get all errors for a specific operation.

        Args:
            operation: Operation name to filter by

        Returns:
            List of GhidraErrorRecords
        """
        errors = []
        manifest = self._load_manifest()

        for entry in manifest:
            if entry["operation"] == operation:
                error = self.get_error(entry["error_id"])
                if error:
                    errors.append(error)

        return errors

    def clear_all_errors(self) -> int:
        """
        Clear all error records.

        Returns:
            Number of errors cleared
        """
        count = 0

        # Delete all error files
        for error_file in self.error_dir.glob("*.json"):
            if error_file.name not in ["manifest.json", "stats.json"]:
                try:
                    error_file.unlink()
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to delete {error_file}: {e}")

        # Reset manifest and stats
        self._save_manifest([])
        self._save_stats({})

        logger.info(f"Cleared {count} Ghidra error records")
        return count

    def format_error_summary(self, count: int = 10) -> str:
        """
        Format recent errors as human-readable summary.

        Args:
            count: Number of recent errors to include

        Returns:
            Formatted string with error summary
        """
        errors = self.get_recent_errors(count)
        stats = self.get_stats()

        if not errors:
            return "No Ghidra errors recorded."

        lines = [
            "=== GHIDRA ERROR SUMMARY ===",
            f"Total errors: {stats.get('total_errors', 0)}",
            "",
            f"Recent {len(errors)} errors:",
            "-" * 40,
        ]

        for entry in errors:
            timestamp = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(entry["timestamp"])
            )
            lines.append(f"[{entry['error_id']}] {timestamp}")
            lines.append(f"  Operation: {entry['operation']}")
            lines.append(f"  Type: {entry['error_type']}")
            lines.append(f"  Message: {entry['error_message'][:100]}")
            if entry.get("exit_code") is not None:
                lines.append(f"  Exit code: {entry['exit_code']}")
            lines.append("")

        # Add stats breakdown
        if stats.get("by_operation"):
            lines.append("Errors by operation:")
            for op, count in stats["by_operation"].items():
                lines.append(f"  {op}: {count}")

        if stats.get("by_type"):
            lines.append("\nErrors by type:")
            for err_type, count in stats["by_type"].items():
                lines.append(f"  {err_type}: {count}")

        return "\n".join(lines)

    def export_errors_log(self, output_file: Path) -> None:
        """
        Export all errors to a single log file for analysis.

        Args:
            output_file: Path to output log file
        """
        try:
            manifest = self._load_manifest()

            with open(output_file, "w") as f:
                f.write("=" * 80 + "\n")
                f.write("GHIDRA ERROR LOG\n")
                f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Errors: {len(manifest)}\n")
                f.write("=" * 80 + "\n\n")

                for entry in manifest:
                    error = self.get_error(entry["error_id"])
                    if not error:
                        continue

                    f.write(f"Error ID: {error.error_id}\n")
                    f.write(
                        f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(error.timestamp))}\n"
                    )
                    f.write(f"Operation: {error.operation}\n")
                    f.write(f"Error Type: {error.error_type}\n")
                    f.write(f"Message: {error.error_message}\n")

                    if error.exit_code is not None:
                        f.write(f"Exit Code: {error.exit_code}\n")

                    if error.context:
                        f.write(f"Context: {json.dumps(error.context, indent=2)}\n")

                    if error.stdout:
                        f.write(f"\nStdout:\n{error.stdout[:2000]}\n")

                    if error.stderr:
                        f.write(f"\nStderr:\n{error.stderr[:2000]}\n")

                    if error.traceback:
                        f.write(f"\nTraceback:\n{error.traceback}\n")

                    f.write("-" * 80 + "\n\n")

            logger.info(f"Exported {len(manifest)} Ghidra errors to {output_file}")

        except Exception as e:
            logger.error(f"Failed to export Ghidra errors: {e}")
