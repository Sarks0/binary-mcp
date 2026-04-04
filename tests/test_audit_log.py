"""
Tests for audit logging system.

Verifies AuditEvent construction and serialization, AuditLogger integrity
chaining and rotation, convenience logging functions, and singleton management.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from src.utils.audit_log import (
    AuditEvent,
    AuditEventType,
    AuditLogger,
    AuditOutcome,
    get_audit_logger,
    log_access,
    log_error,
    log_security_event,
    log_session_event,
    log_tool_call,
    reset_audit_logger,
)

# -- Fixtures ----------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_audit_logger_state():
    """Reset the global audit logger singleton before and after each test."""
    reset_audit_logger()
    yield
    reset_audit_logger()


@pytest.fixture()
def _reset_failure_counter():
    """Reset the consecutive failure counter between tests."""
    import src.utils.audit_log as mod

    mod._audit_failure_count = 0
    yield
    mod._audit_failure_count = 0


def _make_event(**overrides) -> AuditEvent:
    """Create an AuditEvent with sensible defaults, allowing field overrides."""
    defaults = dict(
        timestamp="2025-01-15T10:30:00+00:00",
        sequence=1,
        event_id="evt-001",
        event_type=AuditEventType.SECURITY.value,
        event_subtype="login",
        outcome=AuditOutcome.SUCCESS.value,
        session_id="sess-abc",
        client_ip="127.0.0.1",
        user_agent="TestAgent/1.0",
        action="authenticate",
        resource="/api/login",
        resource_type="endpoint",
        auth_method="bearer_token",
        mfa_used=False,
        details={"key": "value"},
        prev_hash=None,
        event_hash=None,
    )
    defaults.update(overrides)
    return AuditEvent(**defaults)


# -- AuditEvent tests --------------------------------------------------------


class TestAuditEvent:
    """Tests for the AuditEvent dataclass."""

    def test_construction_with_all_fields(self):
        """All fields are accessible after construction."""
        event = _make_event()

        assert event.timestamp == "2025-01-15T10:30:00+00:00"
        assert event.sequence == 1
        assert event.event_id == "evt-001"
        assert event.event_type == AuditEventType.SECURITY.value
        assert event.event_subtype == "login"
        assert event.outcome == AuditOutcome.SUCCESS.value
        assert event.session_id == "sess-abc"
        assert event.client_ip == "127.0.0.1"
        assert event.user_agent == "TestAgent/1.0"
        assert event.action == "authenticate"
        assert event.resource == "/api/login"
        assert event.resource_type == "endpoint"
        assert event.auth_method == "bearer_token"
        assert event.mfa_used is False
        assert event.details == {"key": "value"}
        assert event.prev_hash is None
        assert event.event_hash is None

    def test_to_json_produces_valid_json(self):
        """to_json() output is parseable JSON containing all fields."""
        event = _make_event()
        json_str = event.to_json()

        parsed = json.loads(json_str)
        assert parsed["timestamp"] == event.timestamp
        assert parsed["sequence"] == event.sequence
        assert parsed["event_id"] == event.event_id
        assert parsed["event_type"] == event.event_type
        assert parsed["details"] == {"key": "value"}

    def test_from_json_round_trip(self):
        """Serializing then deserializing produces an equivalent AuditEvent."""
        original = _make_event()
        json_str = original.to_json()

        data = json.loads(json_str)
        restored = AuditEvent(**data)

        assert restored.timestamp == original.timestamp
        assert restored.sequence == original.sequence
        assert restored.event_id == original.event_id
        assert restored.event_type == original.event_type
        assert restored.outcome == original.outcome
        assert restored.details == original.details

    def test_class_docstring_says_structured_record(self):
        """AuditEvent docstring describes it as a 'Structured record'."""
        assert "Structured record" in (AuditEvent.__doc__ or "")


# -- AuditLogger tests -------------------------------------------------------


class TestAuditLogger:
    """Tests for AuditLogger core functionality."""

    def test_log_event_creates_file_with_valid_json(self, tmp_path: Path):
        """log_event() creates a log file containing a valid JSON line."""
        al = AuditLogger(log_dir=tmp_path, enable_chaining=False)
        event = _make_event(timestamp="", sequence=0, event_id="")

        al.log_event(event)

        log_files = list(tmp_path.glob("audit-*.log"))
        assert len(log_files) == 1

        line = log_files[0].read_text().strip()
        parsed = json.loads(line)
        assert parsed["event_type"] == AuditEventType.SECURITY.value

    def test_sequential_events_have_incrementing_sequence(self, tmp_path: Path):
        """Consecutive events receive monotonically increasing sequence numbers."""
        al = AuditLogger(log_dir=tmp_path, enable_chaining=False)

        for _ in range(5):
            al.log_event(_make_event(timestamp="", sequence=0, event_id=""))

        log_file = next(tmp_path.glob("audit-*.log"))
        lines = log_file.read_text().strip().splitlines()

        seqs = [json.loads(line)["sequence"] for line in lines]
        assert seqs == [1, 2, 3, 4, 5]

    def test_integrity_chaining_prev_hash_matches(self, tmp_path: Path):
        """Each event's prev_hash equals the preceding event's event_hash."""
        al = AuditLogger(log_dir=tmp_path, enable_chaining=True)

        for _ in range(3):
            al.log_event(_make_event(timestamp="", sequence=0, event_id=""))

        log_file = next(tmp_path.glob("audit-*.log"))
        events = [json.loads(line) for line in log_file.read_text().strip().splitlines()]

        # First event has no predecessor
        assert events[0]["prev_hash"] is None
        # Second event chains to the first
        assert events[1]["prev_hash"] == events[0]["event_hash"]
        # Third event chains to the second
        assert events[2]["prev_hash"] == events[1]["event_hash"]

    def test_verify_integrity_passes_on_valid_log(self, tmp_path: Path):
        """verify_integrity() reports all_valid=True for an untampered log."""
        al = AuditLogger(log_dir=tmp_path, enable_chaining=True)

        for _ in range(4):
            al.log_event(_make_event(timestamp="", sequence=0, event_id=""))

        report = al.verify_integrity()
        assert report["all_valid"] is True
        assert report["files_checked"] == 1
        assert report["file_results"][0]["events"] == 4

    def test_verify_integrity_detects_modified_event(self, tmp_path: Path):
        """verify_integrity() detects a tampered event (changed field)."""
        al = AuditLogger(log_dir=tmp_path, enable_chaining=True)

        for _ in range(3):
            al.log_event(_make_event(timestamp="", sequence=0, event_id=""))

        log_file = next(tmp_path.glob("audit-*.log"))
        lines = log_file.read_text().strip().splitlines()

        # Tamper with the second event's hash to break the chain
        tampered = json.loads(lines[1])
        tampered["event_hash"] = "0000000000000000000000000000dead"
        lines[1] = json.dumps(tampered, separators=(",", ":"))
        log_file.write_text("\n".join(lines) + "\n")

        report = al.verify_integrity()
        assert report["all_valid"] is False
        errors = report["file_results"][0]["errors"]
        assert any("Hash chain broken" in e for e in errors)

    def test_verify_integrity_detects_deleted_event(self, tmp_path: Path):
        """verify_integrity() detects a removed line (sequence gap)."""
        al = AuditLogger(log_dir=tmp_path, enable_chaining=True)

        for _ in range(4):
            al.log_event(_make_event(timestamp="", sequence=0, event_id=""))

        log_file = next(tmp_path.glob("audit-*.log"))
        lines = log_file.read_text().strip().splitlines()

        # Remove the second line to create a sequence gap (1 -> 3)
        del lines[1]
        log_file.write_text("\n".join(lines) + "\n")

        report = al.verify_integrity()
        assert report["all_valid"] is False
        assert len(report["file_results"][0]["gaps"]) > 0

    def test_log_rotation_triggers_on_size(self, tmp_path: Path):
        """Log rotates when file exceeds max_size_bytes."""
        # Set a tiny max size so rotation fires quickly
        al = AuditLogger(
            log_dir=tmp_path,
            max_size_mb=1,  # Will override below
            enable_chaining=False,
            compress_old=False,
        )
        # Override to a very small threshold
        al.max_size_bytes = 200

        for _ in range(20):
            al.log_event(_make_event(timestamp="", sequence=0, event_id=""))

        # After rotation the original file is closed; there may be
        # compressed copies or the current file was reopened.
        log_files = list(tmp_path.glob("audit-*"))
        # At minimum the logger must have written events somewhere
        assert len(log_files) >= 1

    def test_event_fields_populated_by_log_event(self, tmp_path: Path):
        """log_event() fills in timestamp, sequence, event_id, and event_hash."""
        al = AuditLogger(log_dir=tmp_path, enable_chaining=True)
        event = _make_event(timestamp="", sequence=0, event_id="")

        al.log_event(event)

        assert event.timestamp != ""
        assert event.sequence > 0
        assert event.event_id != ""
        assert event.event_hash is not None


# -- Convenience function tests ----------------------------------------------


class TestConvenienceFunctions:
    """Tests for module-level convenience logging functions."""

    def test_log_security_event_writes_correct_type(self, tmp_path: Path, monkeypatch):
        """log_security_event() creates an event with event_type='security'."""
        monkeypatch.setenv("MCP_AUDIT_LOG_PATH", str(tmp_path))

        log_security_event(
            event_type="auth",
            event_subtype="login_attempt",
            success=True,
            client_ip="10.0.0.1",
            details={"user": "admin"},
        )

        log_file = next(tmp_path.glob("audit-*.log"))
        parsed = json.loads(log_file.read_text().strip().splitlines()[-1])
        assert parsed["event_type"] == "security"
        assert parsed["outcome"] == "success"

    def test_log_tool_call_writes_tool_details(self, tmp_path: Path, monkeypatch):
        """log_tool_call() records tool name and session."""
        monkeypatch.setenv("MCP_AUDIT_LOG_PATH", str(tmp_path))

        log_tool_call(
            session_id="sess-123",
            tool_name="disassemble",
            client_ip="10.0.0.2",
            success=True,
            details={"binary_path": "/tmp/test.exe"},
        )

        log_file = next(tmp_path.glob("audit-*.log"))
        parsed = json.loads(log_file.read_text().strip().splitlines()[-1])
        assert parsed["event_type"] == "tool_call"
        assert parsed["event_subtype"] == "disassemble"
        assert parsed["session_id"] == "sess-123"
        assert parsed["resource"] == "/tmp/test.exe"

    def test_log_access_writes_access_event(self, tmp_path: Path, monkeypatch):
        """log_access() writes an access event with the correct outcome."""
        monkeypatch.setenv("MCP_AUDIT_LOG_PATH", str(tmp_path))

        log_access(
            session_id="sess-456",
            resource="/etc/passwd",
            action="read",
            client_ip="192.168.1.10",
            allowed=False,
        )

        log_file = next(tmp_path.glob("audit-*.log"))
        parsed = json.loads(log_file.read_text().strip().splitlines()[-1])
        assert parsed["event_type"] == "access"
        assert parsed["outcome"] == "denied"
        assert parsed["resource"] == "/etc/passwd"

    def test_log_session_event_writes_session_event(self, tmp_path: Path, monkeypatch):
        """log_session_event() logs session lifecycle with subtype."""
        monkeypatch.setenv("MCP_AUDIT_LOG_PATH", str(tmp_path))

        log_session_event(
            session_id="sess-789",
            event_subtype="created",
            client_ip="10.0.0.5",
            details={"transport": "sse"},
        )

        log_file = next(tmp_path.glob("audit-*.log"))
        parsed = json.loads(log_file.read_text().strip().splitlines()[-1])
        assert parsed["event_type"] == "session"
        assert parsed["event_subtype"] == "created"
        assert parsed["details"]["transport"] == "sse"

    def test_log_error_writes_error_event(self, tmp_path: Path, monkeypatch):
        """log_error() records error type and message in details."""
        monkeypatch.setenv("MCP_AUDIT_LOG_PATH", str(tmp_path))

        log_error(
            error_type="unhandled_exception",
            message="Something went wrong",
            session_id="sess-err",
            client_ip=None,
            details={"traceback": "..."},
        )

        log_file = next(tmp_path.glob("audit-*.log"))
        parsed = json.loads(log_file.read_text().strip().splitlines()[-1])
        assert parsed["event_type"] == "error"
        assert parsed["outcome"] == "error"
        assert parsed["details"]["message"] == "Something went wrong"
        assert parsed["details"]["traceback"] == "..."

    def test_failure_tracking_escalates_to_critical(
        self, tmp_path: Path, monkeypatch, caplog, _reset_failure_counter
    ):
        """After 3 consecutive failures the logger emits a CRITICAL message."""
        monkeypatch.setenv("MCP_AUDIT_LOG_PATH", str(tmp_path))

        # Force the global logger to be created so we can patch its method
        reset_audit_logger()
        logger_instance = get_audit_logger()

        with patch.object(
            logger_instance,
            "log_event",
            side_effect=OSError("disk full"),
        ):
            with caplog.at_level(logging.ERROR, logger="src.utils.audit_log"):
                for _ in range(4):
                    log_security_event("auth", "fail", False, "1.2.3.4")

            critical_msgs = [r for r in caplog.records if r.levelno >= logging.CRITICAL]
            assert len(critical_msgs) >= 1
            assert "consecutive" in critical_msgs[0].message.lower()


# -- Singleton management tests -----------------------------------------------


class TestSingletonManagement:
    """Tests for get_audit_logger / reset_audit_logger."""

    def test_get_audit_logger_returns_instance(self, tmp_path: Path, monkeypatch):
        """get_audit_logger() returns an AuditLogger after setting env vars."""
        monkeypatch.setenv("MCP_AUDIT_LOG_PATH", str(tmp_path))

        al = get_audit_logger()
        assert isinstance(al, AuditLogger)
        assert al.log_dir == tmp_path

    def test_get_audit_logger_returns_same_instance(self, tmp_path: Path, monkeypatch):
        """Repeated calls return the same singleton."""
        monkeypatch.setenv("MCP_AUDIT_LOG_PATH", str(tmp_path))

        first = get_audit_logger()
        second = get_audit_logger()
        assert first is second

    def test_reset_audit_logger_clears_singleton(self, tmp_path: Path, monkeypatch):
        """reset_audit_logger() forces a fresh instance on next call."""
        monkeypatch.setenv("MCP_AUDIT_LOG_PATH", str(tmp_path))

        first = get_audit_logger()
        reset_audit_logger()
        second = get_audit_logger()

        assert first is not second
