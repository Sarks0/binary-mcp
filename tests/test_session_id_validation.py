"""
Tests for session-ID validation in the unified session manager (audit finding
F-5, MEDIUM: session_id path traversal).

``_get_session_path`` and ``_get_metadata_path`` interpolated a caller-supplied
``session_id`` straight into a filename under the session store::

    self.store_dir / f"{session_id}.session.json.gz"

so ``session_id='../../../../tmp/pwned'`` resolved to
``/root/.binary_mcp_sessions/../../../../tmp/pwned.session.json.gz``. That path
is then written by ``save_session``, read by ``_load_session_data`` and
``unlink()``-ed by ``delete_session``, all reachable from MCP tools
(save_session, get_session_summary, load_session_section, load_full_session,
delete_session, generate_report(session_id=), export_iocs,
generate_yara_rule_from_session).

Session IDs are minted exclusively by ``uuid.uuid4()``, so pinning them to a
canonical UUIDv4 is lossless. Validation lives at the chokepoint (both path
builders) rather than at each tool entry point.
"""

from __future__ import annotations

import uuid

import pytest

from src.engines.session.unified_session import (
    AnalysisType,
    UnifiedSessionManager,
    _validate_session_id,
)

# Payloads that must never be turned into a filesystem path. Each one either
# escapes the store directory, targets an absolute location, or is simply not a
# session ID this manager could have created.
TRAVERSAL_PAYLOADS = [
    "../../../../tmp/pwned",
    "..",
    "../",
    "../etc/passwd",
    "..\\..\\windows\\system32\\config\\sam",
    "/etc/passwd",
    "/root/.ssh/authorized_keys",
    "C:\\Windows\\Temp\\evil",
    "sub/dir/id",
    "id\x00.session.json.gz",
    "\x00",
    "~/.bashrc",
    "....//....//tmp/x",
    "%2e%2e%2ftmp%2fx",
]

NON_UUID_PAYLOADS = [
    "",
    "   ",
    "abc123",
    "not-a-uuid",
    "session_1",
    # Right length/shape but not hex.
    "zzzzzzzz-zzzz-4zzz-azzz-zzzzzzzzzzzz",
    # Truncated / extended canonical forms.
    "123e4567-e89b-42d3-a456-42661417400",
    "123e4567-e89b-42d3-a456-4266141740000",
    # UUID without dashes: not the canonical form uuid4() emits.
    uuid.uuid4().hex,
    # Trailing junk after a genuine UUID must not be tolerated.
    str(uuid.uuid4()) + "/../../evil",
    str(uuid.uuid4()) + ".session.json.gz",
    # Wrong version nibble (uuid1-shaped) - uuid.uuid4() never produces this.
    "123e4567-e89b-12d3-a456-426614174000",
    # Wrong variant nibble.
    "123e4567-e89b-42d3-c456-426614174000",
]


# ---------------------------------------------------------------------------
# _validate_session_id itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", TRAVERSAL_PAYLOADS)
def test_validate_rejects_traversal_payloads(payload):
    with pytest.raises(ValueError):
        _validate_session_id(payload)


@pytest.mark.parametrize("payload", NON_UUID_PAYLOADS)
def test_validate_rejects_non_uuid(payload):
    with pytest.raises(ValueError):
        _validate_session_id(payload)


@pytest.mark.parametrize("payload", [None, 123, 4.5, b"\x00", ["a"], {"a": 1}])
def test_validate_rejects_non_string(payload):
    with pytest.raises(ValueError):
        _validate_session_id(payload)


def test_validate_accepts_genuine_uuid4():
    sid = str(uuid.uuid4())
    assert _validate_session_id(sid) == sid


def test_validate_normalises_case_and_whitespace():
    """Case-insensitive, normalised to lowercase (matching uuid4() output)."""
    sid = str(uuid.uuid4())
    assert _validate_session_id(sid.upper()) == sid
    assert _validate_session_id(f"  {sid.upper()}  ") == sid


def test_validate_error_is_plain_valueerror():
    """
    The tool layer wraps calls in ``except Exception`` and formats ``f"Error: {e}"``,
    so the message must be a clean sentence, not a traceback artefact.
    """
    with pytest.raises(ValueError) as exc:
        _validate_session_id("../../../../tmp/pwned")
    assert "Invalid session ID format" in str(exc.value)


# ---------------------------------------------------------------------------
# The chokepoint: path builders
# ---------------------------------------------------------------------------


@pytest.fixture
def manager(tmp_path):
    return UnifiedSessionManager(store_dir=str(tmp_path / "sessions"))


@pytest.mark.parametrize("payload", TRAVERSAL_PAYLOADS + NON_UUID_PAYLOADS)
def test_path_builders_reject_bad_ids(manager, payload):
    with pytest.raises(ValueError):
        manager._get_session_path(payload)
    with pytest.raises(ValueError):
        manager._get_metadata_path(payload)


def test_paths_stay_inside_store_dir(manager):
    sid = str(uuid.uuid4())
    store = manager.store_dir.resolve()
    for path in (manager._get_session_path(sid), manager._get_metadata_path(sid)):
        assert path.resolve().parent == store


def test_traversal_does_not_touch_disk(manager, tmp_path):
    """
    End-to-end: the classic payload must not create, read or unlink anything
    outside the store directory.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.meta.json"
    victim.write_text("{}")

    payload = f"../outside/{victim.stem.replace('.meta', '')}"

    # Public API paths all fail closed rather than escaping the store.
    assert manager.save_session(payload) is False
    assert manager.get_metadata(payload) is None
    assert manager.get_session(payload) is None
    assert manager.get_section(payload, "summary") is None
    assert manager.delete_session(payload) is False

    assert victim.exists(), "traversal payload deleted a file outside the store"
    assert list(manager.store_dir.iterdir()) == []


def test_no_stray_files_written_outside_store(manager, tmp_path):
    """save_session with a traversal id must not write a .session.json.gz anywhere."""
    manager.start_session(
        binary_path=str(tmp_path / "missing.exe"),
        name="victim",
        analysis_type=AnalysisType.STATIC,
    )
    before = {p for p in tmp_path.rglob("*") if p.is_file()}

    assert manager.save_session("../../../../tmp/pwned") is False

    after = {p for p in tmp_path.rglob("*") if p.is_file()}
    assert before == after


# ---------------------------------------------------------------------------
# Legitimate flows still work end to end
# ---------------------------------------------------------------------------


def test_full_round_trip_start_save_resume_delete(tmp_path):
    """start -> log -> save -> (new manager) resume -> delete must all work."""
    store = str(tmp_path / "sessions")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)

    mgr = UnifiedSessionManager(store_dir=store)
    session_id = mgr.start_session(
        binary_path=str(binary),
        name="round trip",
        analysis_type=AnalysisType.STATIC,
        tags=["unit-test"],
    )
    # Whatever start_session mints must survive our own validator.
    assert _validate_session_id(session_id) == session_id

    assert mgr.log_tool_call("analyze_binary", {"path": str(binary)}, "output text") is True
    assert mgr.save_session() is True

    # Files landed in the store directory, named after the session ID.
    assert (tmp_path / "sessions" / f"{session_id}.session.json.gz").exists()
    assert (tmp_path / "sessions" / f"{session_id}.meta.json").exists()

    # A fresh manager (new "conversation") can read it all back.
    mgr2 = UnifiedSessionManager(store_dir=store)
    metadata = mgr2.get_metadata(session_id)
    assert metadata is not None
    assert metadata["name"] == "round trip"
    assert metadata["tool_count"] == 1

    data = mgr2.get_session(session_id)
    assert data is not None
    assert data["tool_calls"][0]["tool_name"] == "analyze_binary"

    summary = mgr2.get_section(session_id, "summary")
    assert summary["tool_count"] == 1

    listed = mgr2.list_sessions()
    assert [s["session_id"] for s in listed] == [session_id]

    assert mgr2._resume_session(session_id) is True
    assert mgr2.active_session_id == session_id

    assert mgr2.delete_session(session_id) is True
    assert not (tmp_path / "sessions" / f"{session_id}.session.json.gz").exists()
    assert not (tmp_path / "sessions" / f"{session_id}.meta.json").exists()
    assert mgr2.delete_session(session_id) is False


def test_auto_resume_by_binary_hash_still_works(tmp_path):
    """
    ``_find_recent_session_for_binary`` reads session IDs back out of metadata
    files and feeds them to the (now validating) path builders; genuine IDs must
    still round-trip.
    """
    store = str(tmp_path / "sessions")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 32)

    mgr = UnifiedSessionManager(store_dir=store)
    session_id = mgr.ensure_session(binary_path=str(binary))
    mgr.log_tool_call("decompile_function", {}, "code")
    assert mgr.save_session() is True

    mgr2 = UnifiedSessionManager(store_dir=store)
    binary_hash = mgr2._compute_binary_hash(str(binary))
    assert mgr2._find_recent_session_for_binary(binary_hash) == session_id
    assert mgr2.ensure_session(binary_path=str(binary)) == session_id

    related = mgr2.find_sessions_for_binary(binary_path=str(binary))
    assert [s["session_id"] for s in related] == [session_id]


def test_poisoned_metadata_session_id_is_skipped(tmp_path):
    """
    A metadata file whose ``session_id`` field disagrees with its filename must
    not be able to steer auto-resume at an attacker-chosen path (F-5). The bad
    entry is skipped and a genuine older session is still resumable.
    """
    import json
    import time

    store = tmp_path / "sessions"
    store.mkdir()
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 16)

    mgr = UnifiedSessionManager(store_dir=str(store))
    binary_hash = mgr._compute_binary_hash(str(binary))

    # Genuine, older session.
    good_id = mgr.start_session(str(binary), "good", AnalysisType.STATIC)
    assert mgr.save_session() is True
    good_meta = store / f"{good_id}.meta.json"
    meta = json.loads(good_meta.read_text())
    meta["updated_at"] = time.time() - 60
    good_meta.write_text(json.dumps(meta))

    # Planted, newer, poisoned session.
    (store / "evil.meta.json").write_text(json.dumps({
        "session_id": "../../../../tmp/pwned",
        "binary_hash": binary_hash,
        "updated_at": time.time(),
        "status": "saved",
    }))

    found = UnifiedSessionManager(store_dir=str(store))._find_recent_session_for_binary(binary_hash)
    assert found == good_id


def test_uppercase_session_id_still_loads(tmp_path):
    """Normalisation means an operator pasting an upper-cased UUID still works."""
    store = str(tmp_path / "sessions")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")

    mgr = UnifiedSessionManager(store_dir=store)
    session_id = mgr.start_session(str(binary), "case test", AnalysisType.STATIC)
    assert mgr.save_session() is True

    mgr2 = UnifiedSessionManager(store_dir=store)
    assert mgr2.get_metadata(session_id.upper()) is not None
    assert mgr2.get_session(session_id.upper()) is not None
