"""
WinDbgErrorLogger - Comprehensive error logging and tracking for WinDbg operations.

Stores detailed error information in structured JSON format for debugging and analysis.
Similar to X64DbgErrorLogger but tailored for WinDbg's DbgEng/Pybag architecture.
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
class ErrorContext:
    """Context information for a WinDbg error."""

    operation: str  # Operation that failed (e.g., "read_msr", "list_drivers")
    address: str | None = None  # Memory address involved
    register: str | None = None  # Register involved
    module: str | None = None  # Module involved
    debugger_state: str | None = None  # Current debugger state
    binary_path: str | None = None  # Binary or dump being debugged
    request_data: dict[str, Any] = field(default_factory=dict)  # Request parameters
    additional: dict[str, Any] = field(default_factory=dict)  # Any other context


@dataclass
class ErrorRecord:
    """Complete error record with all metadata."""

    timestamp: float
    error_id: str
    operation: str
    error_type: str
    error_message: str
    http_status: int | None = None
    api_response: dict[str, Any] | None = None
    endpoint: str | None = None
    duration_ms: int | None = None
    retry_count: int = 0
    context: dict[str, Any] = field(default_factory=dict)
    traceback: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class WinDbgErrorLogger:
    """
    Error logger for WinDbg operations.

    Stores errors in `~/.ghidra_mcp_cache/windbg_errors/` with:
    - Individual JSON files per error
    - Manifest file for quick browsing
    - Statistics for error analysis
    - Automatic cleanup of old errors
    """

    def __init__(self, error_dir: Path | None = None, max_errors: int = 500):
        """
        Initialize error logger.

        Args:
            error_dir: Directory for error storage
                       (defaults to ~/.ghidra_mcp_cache/windbg_errors/)
            max_errors: Maximum number of errors to keep (oldest removed first)
        """
        if error_dir is None:
            cache_dir = Path.home() / ".ghidra_mcp_cache"
            self.error_dir = cache_dir / "windbg_errors"
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

        logger.debug(f"WinDbgErrorLogger initialized: {self.error_dir}")

    def log_error(
        self,
        operation: str,
        error: Exception,
        context: ErrorContext | None = None,
        http_status: int | None = None,
        api_response: dict[str, Any] | None = None,
        endpoint: str | None = None,
        duration_ms: int | None = None,
        traceback_str: str | None = None,
    ) -> ErrorRecord:
        """
        Log an error with full context.

        Args:
            operation: Operation that failed
            error: Exception that occurred
            context: Additional context information
            http_status: HTTP status code if applicable
            api_response: API response if available
            endpoint: API endpoint that was called
            duration_ms: Operation duration in milliseconds
            traceback_str: Full traceback string

        Returns:
            ErrorRecord that was created
        """
        # Generate unique error ID
        error_id = f"windbg_{uuid.uuid4().hex[:16]}"

        # Build error record
        error_type = type(error).__name__
        record = ErrorRecord(
            timestamp=time.time(),
            error_id=error_id,
            operation=operation,
            error_type=error_type,
            error_message=str(error),
            http_status=http_status,
            api_response=api_response,
            endpoint=endpoint,
            duration_ms=duration_ms,
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
        logger.error(f"[{error_id}] {operation} failed: {error_type}: {error}")

        return record

    def _save_error_record(self, record: ErrorRecord) -> None:
        """Save individual error record to JSON file."""
        # Format: {timestamp}_{operation}_{error_id}.json
        timestamp_str = time.strftime("%Y%m%d_%H%M%S", time.localtime(record.timestamp))
        filename = f"{timestamp_str}_{record.operation}_{record.error_id}.json"
        filepath = self.error_dir / filename

        try:
            with open(filepath, "w") as f:
                json.dump(record.to_dict(), f, indent=2)

            logger.debug(f"Saved error record: {filename}")

        except Exception as e:
            logger.error(f"Failed to save error record: {e}")

    def _update_manifest(self, record: ErrorRecord) -> None:
        """Update manifest with new error entry."""
        try:
            manifest = self._load_manifest()

            # Add new entry
            manifest_entry = {
                "error_id": record.error_id,
                "timestamp": record.timestamp,
                "operation": record.operation,
                "error_type": record.error_type,
                "error_message": record.error_message[:100],  # Truncate for manifest
                "http_status": record.http_status,
            }

            manifest.append(manifest_entry)

            # Sort by timestamp (newest first)
            manifest.sort(key=lambda x: x["timestamp"], reverse=True)

            # Save updated manifest
            self._save_manifest(manifest)

        except Exception as e:
            logger.error(f"Failed to update manifest: {e}")

    def _update_stats(self, record: ErrorRecord) -> None:
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

            # By HTTP status
            if record.http_status:
                by_status = stats.get("by_http_status", {})
                status_key = str(record.http_status)
                by_status[status_key] = by_status.get(status_key, 0) + 1
                stats["by_http_status"] = by_status

            # Update timestamp
            stats["last_error_timestamp"] = record.timestamp
            stats["last_updated"] = time.time()

            # Save updated stats
            self._save_stats(stats)

        except Exception as e:
            logger.error(f"Failed to update stats: {e}")

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
                        logger.debug(f"Deleted old error: {error_file.name}")
                    except Exception as e:
                        logger.warning(f"Failed to delete {error_file}: {e}")

            # Update manifest (keep only recent errors)
            updated_manifest = manifest_sorted[to_delete:]
            self._save_manifest(updated_manifest)

            logger.info(f"Cleaned up {to_delete} old error records")

        except Exception as e:
            logger.error(f"Failed to cleanup old errors: {e}")

    def _load_manifest(self) -> list[dict[str, Any]]:
        """Load manifest file."""
        try:
            if self.manifest_file.exists():
                with open(self.manifest_file) as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load manifest: {e}")

        return []

    def _save_manifest(self, manifest: list[dict[str, Any]]) -> None:
        """Save manifest file."""
        try:
            with open(self.manifest_file, "w") as f:
                json.dump(manifest, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save manifest: {e}")

    def _load_stats(self) -> dict[str, Any]:
        """Load statistics file."""
        try:
            if self.stats_file.exists():
                with open(self.stats_file) as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load stats: {e}")

        return {}

    def _save_stats(self, stats: dict[str, Any]) -> None:
        """Save statistics file."""
        try:
            with open(self.stats_file, "w") as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save stats: {e}")

    def get_error(self, error_id: str) -> ErrorRecord | None:
        """
        Retrieve error record by ID.

        Args:
            error_id: Error ID to look up

        Returns:
            ErrorRecord if found, None otherwise
        """
        # Find error file
        for error_file in self.error_dir.glob(f"*_{error_id}.json"):
            try:
                with open(error_file) as f:
                    data = json.load(f)
                    return ErrorRecord(**data)
            except Exception as e:
                logger.error(f"Failed to load error {error_id}: {e}")

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

    def get_errors_by_operation(self, operation: str) -> list[ErrorRecord]:
        """
        Get all errors for a specific operation.

        Args:
            operation: Operation name to filter by

        Returns:
            List of ErrorRecords
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

        logger.info(f"Cleared {count} error records")
        return count

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
                f.write("WINDBG ERROR LOG\n")
                f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Errors: {len(manifest)}\n")
                f.write("=" * 80 + "\n\n")

                for entry in manifest:
                    error = self.get_error(entry["error_id"])
                    if not error:
                        continue

                    f.write(f"Error ID: {error.error_id}\n")
                    timestamp_fmt = time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(error.timestamp)
                    )
                    f.write(f"Timestamp: {timestamp_fmt}\n")
                    f.write(f"Operation: {error.operation}\n")
                    f.write(f"Error Type: {error.error_type}\n")
                    f.write(f"Message: {error.error_message}\n")

                    if error.http_status:
                        f.write(f"HTTP Status: {error.http_status}\n")

                    if error.endpoint:
                        f.write(f"Endpoint: {error.endpoint}\n")

                    if error.duration_ms:
                        f.write(f"Duration: {error.duration_ms}ms\n")

                    if error.context:
                        f.write(f"Context: {json.dumps(error.context, indent=2)}\n")

                    if error.traceback:
                        f.write(f"Traceback:\n{error.traceback}\n")

                    f.write("-" * 80 + "\n\n")

            logger.info(f"Exported {len(manifest)} errors to {output_file}")

        except Exception as e:
            logger.error(f"Failed to export errors: {e}")
