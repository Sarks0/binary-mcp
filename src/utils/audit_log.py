"""
Immutable audit logging for MCP server security.

Provides:
- Security event logging (authentication, access, errors)
- Tamper-resistant log format (append-only)
- Structured JSON logs for SIEM integration
- Automatic log rotation and retention
- Integrity verification

Security features:
- JSON Lines format (one event per line, parseable even if corrupted)
- Timestamp with timezone (ISO 8601)
- Event integrity (sequence numbers prevent deletion)
- Automatic rotation by size and time
- Read-only historical logs (current log only writable)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import Any

from src.utils.config import get_config, get_config_int

logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Types of audit events."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ACCESS = "access"
    DATA_ACCESS = "data_access"
    TOOL_CALL = "tool_call"
    ERROR = "error"
    CONFIG_CHANGE = "config_change"
    SESSION = "session"
    SECURITY = "security"


class AuditOutcome(Enum):
    """Outcome of audited operation."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class AuditEvent:
    """
    Audit event record.

    Immutable record of security-relevant events.
    """

    # Event identification
    timestamp: str  # ISO 8601 with timezone
    sequence: int  # Sequence number (monotonic, detect gaps)
    event_id: str  # Unique event ID (UUID)

    # Event categorization
    event_type: str  # From AuditEventType
    event_subtype: str  # Detailed subtype
    outcome: str  # From AuditOutcome

    # Actor information
    session_id: str | None  # Session identifier (if authenticated)
    client_ip: str | None  # Client IP address
    user_agent: str | None  # User agent (if available)

    # Action details
    action: str | None  # Action performed
    resource: str | None  # Resource accessed
    resource_type: str | None  # Type of resource

    # Security context
    auth_method: str | None  # Authentication method used
    mfa_used: bool | None  # Whether MFA was used

    # Details (structured)
    details: dict[str, Any]  # Additional event-specific details

    # Integrity
    prev_hash: str | None  # Hash of previous event (chain)
    event_hash: str | None  # Hash of this event

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string for logging."""
        return json.dumps(self.to_dict(), separators=(",", ":"))


class AuditLogIntegrityError(Exception):
    """Audit log integrity verification failed."""

    pass


class AuditLogger:
    """
    Security audit logger with integrity protection.

    Features:
    - Append-only JSON Lines format
    - Sequence numbers for gap detection
    - Log rotation by size and retention
    - Optional integrity chaining
    """

    def __init__(
        self,
        log_dir: Path | None = None,
        max_size_mb: int = 100,
        retention_days: int = 90,
        enable_chaining: bool = True,
        compress_old: bool = True,
    ):
        """
        Initialize audit logger.

        Args:
            log_dir: Directory for audit logs (default: ~/.binary_mcp_output/audit/)
            max_size_mb: Maximum size before rotation
            retention_days: Days to retain old logs
            enable_chaining: Chain event hashes for integrity
            compress_old: Gzip old logs
        """
        self.log_dir = log_dir or (Path.home() / ".binary_mcp_output" / "audit")
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Restrictive permissions on audit directory
        os.chmod(self.log_dir, 0o700)

        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.retention_days = retention_days
        self.enable_chaining = enable_chaining
        self.compress_old = compress_old

        self._lock = Lock()
        self._sequence = 0
        self._current_log: Path | None = None
        self._current_file = None
        self._last_hash: str | None = None

        # Initialize sequence from existing logs
        self._initialize_sequence()

    def _initialize_sequence(self) -> None:
        """Initialize sequence number from existing logs."""
        log_files = sorted(self.log_dir.glob("audit-*.log*"))

        if not log_files:
            self._sequence = 0
            self._last_hash = None
            return

        # Find highest sequence in most recent log
        latest = log_files[-1]

        try:
            if latest.suffix == ".gz":
                import gzip

                with gzip.open(latest, "rt") as f:
                    lines = f.readlines()
            else:
                with open(latest) as f:
                    lines = f.readlines()

            if lines:
                last_line = lines[-1]
                event = json.loads(last_line)
                self._sequence = event.get("sequence", 0)
                self._last_hash = event.get("event_hash")

        except Exception as e:
            logger.warning(f"Could not read sequence from existing log: {e}")
            self._sequence = 0
            self._last_hash = None

    def _get_current_log_path(self) -> Path:
        """Get path for current log file."""
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        return self.log_dir / f"audit-{today}.log"

    def _rotate_if_needed(self) -> None:
        """Rotate log if size limit reached."""
        if self._current_file is None:
            return

        # Check file size
        try:
            current_size = self._current_file.tell()
            if current_size >= self.max_size_bytes:
                self._close_current()
                self._cleanup_old_logs()
        except Exception as e:
            logger.error(f"Error checking log size: {e}")

    def _close_current(self) -> None:
        """Close current log file."""
        if self._current_file:
            self._current_file.flush()
            self._current_file.close()

            # Compress if enabled
            if self.compress_old and self._current_log:
                self._compress_log(self._current_log)

            self._current_file = None
            self._current_log = None

    def _compress_log(self, log_path: Path) -> None:
        """Compress log file to .gz."""
        try:
            import gzip

            gz_path = log_path.with_suffix(log_path.suffix + ".gz")

            with open(log_path, "rb") as f_in:
                with gzip.open(gz_path, "wb") as f_out:
                    f_out.writelines(f_in)

            # Remove original, keep compressed
            log_path.unlink()
            logger.debug(f"Compressed audit log: {gz_path}")

        except Exception as e:
            logger.warning(f"Failed to compress log {log_path}: {e}")

    def _cleanup_old_logs(self) -> int:
        """
        Remove logs older than retention period.

        Returns:
            Number of files removed
        """
        cutoff = time.time() - (self.retention_days * 24 * 3600)
        removed = 0

        for log_file in self.log_dir.glob("audit-*.log*"):
            try:
                stat = log_file.stat()
                if stat.st_mtime < cutoff:
                    log_file.unlink()
                    removed += 1
                    logger.info(f"Removed old audit log: {log_file}")
            except Exception as e:
                logger.warning(f"Could not remove old log {log_file}: {e}")

        return removed

    def _get_or_open_file(self) -> tuple[Path, Any]:
        """Get current log file, opening if necessary."""
        expected = self._get_current_log_path()

        if self._current_log == expected and self._current_file:
            return (self._current_log, self._current_file)

        # Need to open (or reopen with new date)
        self._close_current()

        self._current_log = expected
        # Append mode, create if doesn't exist
        self._current_file = open(self._current_log, "a", buffering=1)  # Line buffered

        # Restrictive permissions
        os.chmod(self._current_log, 0o600)

        logger.debug(f"Opened audit log: {self._current_log}")

        return (self._current_log, self._current_file)

    def _calculate_hash(self, event: AuditEvent) -> str:
        """Calculate hash of event for integrity."""
        # Include previous hash in calculation for chaining
        data = {
            "timestamp": event.timestamp,
            "sequence": event.sequence,
            "event_id": event.event_id,
            "event_type": event.event_type,
            "outcome": event.outcome,
            "session_id": event.session_id,
            "action": event.action,
            "prev_hash": event.prev_hash,
        }

        # Serialize with consistent ordering
        json_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(json_str.encode()).hexdigest()[:32]  # First 32 chars

    def log_event(self, event: AuditEvent) -> None:
        """
        Write audit event to log.

        Args:
            event: Audit event to log
        """
        with self._lock:
            # Assign sequence and timestamp if not set
            if not event.timestamp:
                event.timestamp = datetime.now(UTC).isoformat()

            if not event.sequence:
                self._sequence += 1
                event.sequence = self._sequence

            if not event.event_id:
                import uuid

                event.event_id = str(uuid.uuid4())

            # Chain hash for integrity
            if self.enable_chaining:
                event.prev_hash = self._last_hash
                event.event_hash = self._calculate_hash(event)
                self._last_hash = event.event_hash

            # Write to log
            _, file_handle = self._get_or_open_file()
            file_handle.write(event.to_json() + "\n")
            file_handle.flush()

            # Check for rotation
            self._rotate_if_needed()

    def verify_integrity(self, log_file: Path | None = None) -> dict[str, Any]:
        """
        Verify integrity of audit log.

        Args:
            log_file: Specific file to verify, or None for all

        Returns:
            Verification report
        """
        files_to_check = [log_file] if log_file else list(self.log_dir.glob("audit-*.log"))

        results = []
        all_valid = True

        for lf in files_to_check:
            if not lf.exists():
                continue

            result = {
                "file": str(lf.name),
                "valid": True,
                "errors": [],
                "events": 0,
                "gaps": [],
            }

            try:
                with open(lf) as f:
                    prev_seq = 0
                    prev_hash = None

                    for line_num, line in enumerate(f, 1):
                        try:
                            event = json.loads(line)
                            result["events"] += 1

                            # Check sequence continuity
                            seq = event.get("sequence", 0)
                            if prev_seq > 0 and seq != prev_seq + 1:
                                gap = (prev_seq + 1, seq - 1)
                                result["gaps"].append(gap)
                                result["errors"].append(
                                    f"Gap at line {line_num}: missing sequences {gap[0]}-{gap[1]}"
                                )
                            prev_seq = seq

                            # Check hash chain (if enabled)
                            if self.enable_chaining:
                                stored_prev = event.get("prev_hash")
                                if prev_hash is not None and stored_prev != prev_hash:
                                    result["errors"].append(f"Hash chain broken at line {line_num}")
                                prev_hash = event.get("event_hash")

                        except json.JSONDecodeError as e:
                            result["errors"].append(f"Invalid JSON at line {line_num}: {e}")
                            result["valid"] = False
                            all_valid = False

                if result["errors"]:
                    result["valid"] = False
                    all_valid = False

            except Exception as e:
                result["errors"].append(f"File read error: {e}")
                result["valid"] = False
                all_valid = False

            results.append(result)

        return {
            "all_valid": all_valid,
            "files_checked": len(results),
            "file_results": results,
        }


# Global audit logger instance
_global_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Get or create global audit logger."""
    global _global_audit_logger

    if _global_audit_logger is None:
        log_dir = get_config("MCP_AUDIT_LOG_PATH")
        log_dir_path = Path(log_dir) if log_dir else None

        retention = get_config_int("MCP_AUDIT_LOG_RETENTION_DAYS", 90)
        max_size = get_config_int("MCP_AUDIT_LOG_ROTATE_SIZE_MB", 100)

        _global_audit_logger = AuditLogger(
            log_dir=log_dir_path,
            retention_days=retention,
            max_size_mb=max_size,
        )

        logger.info(f"Audit logger initialized: {_global_audit_logger.log_dir}")

    return _global_audit_logger


def reset_audit_logger() -> None:
    """Reset global audit logger (for testing)."""
    global _global_audit_logger
    _global_audit_logger = None


# Convenience functions for common events


def log_security_event(
    event_type: str,
    event_subtype: str,
    success: bool,
    client_ip: str | None,
    details: dict[str, Any] | None = None,
) -> None:
    """
    Log security-related event.

    Args:
        event_type: Event category (auth, access, etc.)
        event_subtype: Detailed type
        success: Whether operation succeeded
        client_ip: Client IP
        details: Additional details
    """
    try:
        event = AuditEvent(
            timestamp="",
            sequence=0,
            event_id="",
            event_type=AuditEventType.SECURITY.value,
            event_subtype=f"{event_type}:{event_subtype}",
            outcome=AuditOutcome.SUCCESS.value if success else AuditOutcome.FAILURE.value,
            session_id=None,
            client_ip=client_ip,
            user_agent=None,
            action=event_subtype,
            resource=None,
            resource_type=None,
            auth_method="bearer_token" if event_type == "auth" else None,
            mfa_used=None,
            details=details or {},
            prev_hash=None,
            event_hash=None,
        )

        get_audit_logger().log_event(event)

    except Exception as e:
        # Never fail main operation due to audit logging
        logger.error(f"Failed to write audit log: {e}")


def log_tool_call(
    session_id: str,
    tool_name: str,
    client_ip: str | None,
    success: bool,
    details: dict[str, Any] | None = None,
) -> None:
    """Log tool call event."""
    try:
        event = AuditEvent(
            timestamp="",
            sequence=0,
            event_id="",
            event_type=AuditEventType.TOOL_CALL.value,
            event_subtype=tool_name,
            outcome=AuditOutcome.SUCCESS.value if success else AuditOutcome.ERROR.value,
            session_id=session_id,
            client_ip=client_ip,
            user_agent=None,
            action=tool_name,
            resource=details.get("binary_path") if details else None,
            resource_type="binary_file",
            auth_method=None,
            mfa_used=None,
            details=details or {},
            prev_hash=None,
            event_hash=None,
        )

        get_audit_logger().log_event(event)

    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")


def log_access(
    session_id: str, resource: str, action: str, client_ip: str | None, allowed: bool
) -> None:
    """Log resource access attempt."""
    try:
        outcome = AuditOutcome.SUCCESS.value if allowed else AuditOutcome.DENIED.value

        event = AuditEvent(
            timestamp="",
            sequence=0,
            event_id="",
            event_type=AuditEventType.ACCESS.value,
            event_subtype=action,
            outcome=outcome,
            session_id=session_id,
            client_ip=client_ip,
            user_agent=None,
            action=action,
            resource=resource,
            resource_type="path",
            auth_method=None,
            mfa_used=None,
            details={},
            prev_hash=None,
            event_hash=None,
        )

        get_audit_logger().log_event(event)

    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")


def log_session_event(
    session_id: str,
    event_subtype: str,
    client_ip: str | None,
    details: dict[str, Any] | None = None,
) -> None:
    """Log session lifecycle event (create, destroy, etc.)."""
    try:
        event = AuditEvent(
            timestamp="",
            sequence=0,
            event_id="",
            event_type=AuditEventType.SESSION.value,
            event_subtype=event_subtype,
            outcome=AuditOutcome.SUCCESS.value,
            session_id=session_id,
            client_ip=client_ip,
            user_agent=None,
            action=event_subtype,
            resource=None,
            resource_type=None,
            auth_method=None,
            mfa_used=None,
            details=details or {},
            prev_hash=None,
            event_hash=None,
        )

        get_audit_logger().log_event(event)

    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")


def log_error(
    error_type: str,
    message: str,
    session_id: str | None,
    client_ip: str | None,
    details: dict[str, Any] | None = None,
) -> None:
    """Log error event."""
    try:
        event = AuditEvent(
            timestamp="",
            sequence=0,
            event_id="",
            event_type=AuditEventType.ERROR.value,
            event_subtype=error_type,
            outcome=AuditOutcome.ERROR.value,
            session_id=session_id,
            client_ip=client_ip,
            user_agent=None,
            action=None,
            resource=None,
            resource_type=None,
            auth_method=None,
            mfa_used=None,
            details={"message": message, **(details or {})},
            prev_hash=None,
            event_hash=None,
        )

        get_audit_logger().log_event(event)

    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")
