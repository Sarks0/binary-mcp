"""
Tests for the cross-process job registry.

The registry exists because binary-mcp runs over stdio -- every client gets its
own server process -- so six agents analyzing one binary are six processes that
can only coordinate through the shared cache directory. The properties that
matter are therefore about what happens *between* processes: exactly one runner
per key, a crashed owner's claim becoming takeable, and a crashed owner's
subprocesses actually getting reaped.

Real process killing is monkeypatched throughout. A test suite that kills pids
is a test suite that eventually kills the wrong one.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time

import pytest

from src.engines import jobs as jobs_mod
from src.engines.jobs import (
    STATE_CANCELLED,
    STATE_FAILED,
    STATE_ORPHANED,
    STATE_RUNNING,
    STATE_SUCCEEDED,
    JobRegistry,
)


@pytest.fixture
def registry(tmp_path):
    return JobRegistry(tmp_path, stale_after=1, heartbeat_interval=1)


@pytest.fixture
def no_killing(monkeypatch):
    """Record kill attempts instead of performing them."""
    killed = []

    def _fake_kill(pid):
        killed.append(pid)
        return True

    monkeypatch.setattr(jobs_mod, "_kill_pid", _fake_kill)
    return killed


def _wait_for(predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


class TestBasicLifecycle:
    def test_successful_job_carries_its_result(self, registry):
        submitted = registry.submit(kind="test", key="k1", fn=lambda ctx: {"n": 42})
        assert submitted["attached"] is False

        assert _wait_for(
            lambda: registry.read(submitted["job_id"])["state"] == STATE_SUCCEEDED
        )
        assert registry.read(submitted["job_id"])["result"] == {"n": 42}

    def test_failed_job_records_why(self, registry):
        def _boom(ctx):
            raise RuntimeError("ghidra fell over")

        submitted = registry.submit(kind="test", key="k1", fn=_boom)
        assert _wait_for(
            lambda: registry.read(submitted["job_id"])["state"] == STATE_FAILED
        )
        assert "ghidra fell over" in registry.read(submitted["job_id"])["error"]

    def test_progress_is_readable_while_running(self, registry):
        release = threading.Event()

        def _slow(ctx):
            ctx.set_progress("halfway")
            release.wait(5)
            return {}

        submitted = registry.submit(kind="test", key="k1", fn=_slow)
        assert _wait_for(
            lambda: registry.read(submitted["job_id"])["progress"] == "halfway"
        )
        release.set()


class TestClaimExclusivity:
    """One runner per key. This is the property that stops six agents from
    starting six Ghidra runs on the same binary."""

    def test_second_submit_attaches_rather_than_starting_a_second_run(self, registry):
        started = []
        release = threading.Event()

        def _work(ctx):
            started.append(1)
            release.wait(5)
            return {}

        first = registry.submit(kind="analyze", key="same", fn=_work)
        assert _wait_for(lambda: len(started) == 1)

        second = registry.submit(kind="analyze", key="same", fn=_work)
        assert second["attached"] is True
        assert second["job_id"] == first["job_id"]

        release.set()
        assert _wait_for(lambda: registry.read(first["job_id"])["state"] == STATE_SUCCEEDED)
        assert started == [1], "the work must have run exactly once"

    def test_different_keys_run_independently(self, registry):
        a = registry.submit(kind="analyze", key="a", fn=lambda ctx: {"which": "a"})
        b = registry.submit(kind="analyze", key="b", fn=lambda ctx: {"which": "b"})
        assert a["job_id"] != b["job_id"]
        assert b["attached"] is False
        assert _wait_for(lambda: registry.read(b["job_id"])["state"] == STATE_SUCCEEDED)

    def test_claim_is_released_when_the_job_finishes(self, registry):
        first = registry.submit(kind="analyze", key="same", fn=lambda ctx: {})
        assert _wait_for(lambda: registry.read(first["job_id"])["state"] == STATE_SUCCEEDED)

        second = registry.submit(kind="analyze", key="same", fn=lambda ctx: {})
        assert second["attached"] is False, "a finished job must not block the next one"
        assert second["job_id"] != first["job_id"]

    def test_claim_creation_is_atomic(self, registry):
        """`O_CREAT|O_EXCL` is the whole cross-process mechanism; if it were
        racy, two agents could both believe they own the run."""
        assert registry._try_claim("k", "job-one") is True
        assert registry._try_claim("k", "job-two") is False


class TestDeadOwners:
    """A crashed owner must not hold a claim forever, and must not leave its
    Ghidra tree running."""

    def _plant_dead_job(self, registry, *, pid=999999, children=(4242,), age=600):
        """Write a job record that looks like it belongs to a dead process."""
        stale = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - age)
        )
        record = {
            "schema_version": jobs_mod.SCHEMA_VERSION,
            "job_id": "deadjob",
            "kind": "analyze_binary",
            "key": "abandoned",
            "state": STATE_RUNNING,
            "owner_pid": pid,
            "created_at": stale,
            "updated_at": stale,
            "heartbeat_at": stale,
            "child_pids": list(children),
            "progress": "running",
            "result": None,
            "error": None,
        }
        registry._write(record)
        registry._try_claim("abandoned", "deadjob")
        return record

    def test_stale_heartbeat_makes_a_job_stale(self, registry):
        record = self._plant_dead_job(registry)
        assert registry.is_stale(record) is True

    def test_a_live_owner_is_never_stale(self, registry, monkeypatch):
        """The dangerous direction: declaring a live owner dead starts the
        second Ghidra this registry exists to prevent."""
        monkeypatch.setattr(jobs_mod, "_pid_alive", lambda pid: True)
        record = self._plant_dead_job(registry, pid=os.getpid(), age=0)
        record["heartbeat_at"] = jobs_mod._utc_now()
        assert registry.is_stale(record) is False

    def test_sweep_orphans_the_job_and_reaps_its_children(self, registry, no_killing):
        self._plant_dead_job(registry, children=(4242, 4343))
        result = registry.sweep()

        assert result["orphaned"] == ["deadjob"]
        assert sorted(no_killing) == [4242, 4343]
        assert registry.read("deadjob")["state"] == STATE_ORPHANED

    def test_a_dead_owners_claim_becomes_takeable(self, registry, no_killing):
        self._plant_dead_job(registry)
        taken = registry.submit(kind="analyze", key="abandoned", fn=lambda ctx: {"ok": 1})

        assert taken["attached"] is False, "a dead owner must not hold the claim"
        assert taken["job_id"] != "deadjob"
        assert _wait_for(lambda: registry.read(taken["job_id"])["state"] == STATE_SUCCEEDED)
        assert registry.read("deadjob")["state"] == STATE_ORPHANED

    def test_sweep_leaves_our_own_running_jobs_alone(self, registry):
        release = threading.Event()
        submitted = registry.submit(kind="test", key="mine", fn=lambda ctx: release.wait(5))
        assert _wait_for(lambda: registry.read(submitted["job_id"]) is not None)

        assert registry.sweep()["orphaned"] == []
        assert registry.read(submitted["job_id"])["state"] == STATE_RUNNING
        release.set()


class TestKillGating:
    """Every cross-process kill is gated on identity, because pids get
    recycled and killing an unrelated process is not recoverable."""

    def test_unidentifiable_process_is_not_killed(self, monkeypatch):
        monkeypatch.setattr(jobs_mod, "_pid_alive", lambda pid: True)
        monkeypatch.setattr(jobs_mod, "_process_command", lambda pid: "")
        assert jobs_mod._kill_pid(4242) is False

    def test_unrelated_process_is_not_killed(self, monkeypatch):
        monkeypatch.setattr(jobs_mod, "_pid_alive", lambda pid: True)
        monkeypatch.setattr(jobs_mod, "_process_command", lambda pid: "/usr/bin/postgres -D /var")
        assert jobs_mod._kill_pid(4242) is False

    def test_a_ghidra_process_is_identified(self, monkeypatch):
        monkeypatch.setattr(jobs_mod, "_pid_alive", lambda pid: True)
        monkeypatch.setattr(
            jobs_mod, "_process_command",
            lambda pid: "/opt/ghidra/support/analyzeHeadless /tmp/proj foo",
        )
        assert jobs_mod._process_matches(4242) is True

    def test_dead_pid_is_not_killed(self, monkeypatch):
        monkeypatch.setattr(jobs_mod, "_pid_alive", lambda pid: False)
        assert jobs_mod._kill_pid(4242) is False


class TestCancellation:
    def test_cancel_kills_children_and_marks_the_job(self, registry, no_killing):
        release = threading.Event()

        def _work(ctx):
            ctx.track_child(5150)
            release.wait(5)
            return {}

        submitted = registry.submit(kind="test", key="k", fn=_work)
        assert _wait_for(
            lambda: (registry.read(submitted["job_id"]).get("child_pids") or []) == [5150]
        )

        result = registry.cancel(submitted["job_id"])
        assert result["cancelled"] is True
        assert result["reaped"] == 1
        assert no_killing == [5150]
        assert registry.read(submitted["job_id"])["state"] == STATE_CANCELLED
        release.set()

    def test_cancelling_a_finished_job_is_not_an_error(self, registry):
        submitted = registry.submit(kind="test", key="k", fn=lambda ctx: {})
        assert _wait_for(
            lambda: registry.read(submitted["job_id"])["state"] == STATE_SUCCEEDED
        )
        result = registry.cancel(submitted["job_id"])
        assert result["cancelled"] is False
        assert result["state"] == STATE_SUCCEEDED

    def test_cancelling_an_unknown_job_reports_it(self, registry):
        assert "error" in registry.cancel("nope")


class TestShutdown:
    def test_shutdown_reaps_our_own_children(self, registry, no_killing):
        """The original failure mode: the server exits mid-analysis and the
        Ghidra tree is left parentless."""
        release = threading.Event()

        def _work(ctx):
            ctx.track_child(7777)
            release.wait(10)
            return {}

        submitted = registry.submit(kind="analyze", key="k", fn=_work)
        assert _wait_for(
            lambda: (registry.read(submitted["job_id"]).get("child_pids") or []) == [7777]
        )

        registry.shutdown()
        assert no_killing == [7777]
        record = registry.read(submitted["job_id"])
        assert record["state"] == STATE_FAILED
        assert "server process exited" in record["error"]
        release.set()


class TestRecordHandling:
    def test_unknown_job_reads_as_none(self, registry):
        assert registry.read("nope") is None

    def test_a_record_from_a_future_schema_is_refused(self, registry):
        path = registry.root / "future.job.json"
        path.write_text(json.dumps({"schema_version": 99, "job_id": "future"}))
        assert registry.read("future") is None

    def test_a_corrupt_record_reads_as_none(self, registry):
        (registry.root / "bad.job.json").write_text("{not json")
        assert registry.read("bad") is None

    def test_a_corrupt_claim_does_not_block_the_key(self, registry):
        registry._claim_path("k").write_text("{not json")
        submitted = registry.submit(kind="test", key="k", fn=lambda ctx: {"ok": 1})
        assert submitted["attached"] is False

    def test_list_filters_by_state(self, registry):
        registry.submit(kind="test", key="a", fn=lambda ctx: {})
        assert _wait_for(lambda: len(registry.list_jobs(state=STATE_SUCCEEDED)) == 1)
        assert registry.list_jobs(state=STATE_ORPHANED) == []

    def test_purge_drops_old_terminal_records_only(self, registry):
        submitted = registry.submit(kind="test", key="a", fn=lambda ctx: {})
        assert _wait_for(
            lambda: registry.read(submitted["job_id"])["state"] == STATE_SUCCEEDED
        )
        assert registry.purge(older_than_seconds=86400) == 0
        assert registry.purge(older_than_seconds=0) == 1
        assert registry.read(submitted["job_id"]) is None


class TestKillBlastRadius:
    """Regression: `_kill_pid` used `killpg` unconditionally. A pid that is not
    its own process-group leader shares a group with whatever spawned it -- and
    during a sweep that can be the sweeping server's own group, so reaping an
    abandoned Ghidra killed the process doing the reaping. Caught by a
    cross-process test exiting 137.
    """

    @pytest.fixture(autouse=True)
    def _identified_and_alive(self, monkeypatch):
        monkeypatch.setattr(jobs_mod, "_pid_alive", lambda pid: True)
        monkeypatch.setattr(jobs_mod, "_process_matches", lambda pid: True)

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="POSIX process-group semantics; Windows kills the tree with taskkill /T",
    )
    def test_non_group_leader_is_killed_alone(self, monkeypatch):
        calls = {"killpg": [], "kill": []}
        monkeypatch.setattr(jobs_mod.os, "getpgid", lambda pid: 4242)
        monkeypatch.setattr(jobs_mod.os, "killpg", lambda g, s: calls["killpg"].append(g))
        monkeypatch.setattr(jobs_mod.os, "kill", lambda p, s: calls["kill"].append(p))

        assert jobs_mod._kill_pid(5150) is True
        assert calls["killpg"] == [], "must not fan out to a group it does not lead"
        assert calls["kill"] == [5150]

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="POSIX process-group semantics; Windows kills the tree with taskkill /T",
    )
    def test_group_leader_takes_its_tree_with_it(self, monkeypatch):
        """Ghidra is spawned with start_new_session, so it leads its own group
        and the whole java tree must go down together."""
        calls = {"killpg": [], "kill": []}
        monkeypatch.setattr(jobs_mod.os, "getpgid", lambda pid: pid)
        monkeypatch.setattr(jobs_mod.os, "killpg", lambda g, s: calls["killpg"].append(g))
        monkeypatch.setattr(jobs_mod.os, "kill", lambda p, s: calls["kill"].append(p))

        assert jobs_mod._kill_pid(5150) is True
        assert calls["killpg"] == [5150]
        assert calls["kill"] == []

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="POSIX process-group semantics; Windows kills the tree with taskkill /T",
    )
    def test_unknown_group_falls_back_to_the_single_pid(self, monkeypatch):
        calls = {"killpg": [], "kill": []}

        def _boom(pid):
            raise PermissionError

        monkeypatch.setattr(jobs_mod.os, "getpgid", _boom)
        monkeypatch.setattr(jobs_mod.os, "killpg", lambda g, s: calls["killpg"].append(g))
        monkeypatch.setattr(jobs_mod.os, "kill", lambda p, s: calls["kill"].append(p))

        assert jobs_mod._kill_pid(5150) is True
        assert calls["killpg"] == []
        assert calls["kill"] == [5150]

    def test_windows_kills_the_tree_by_pid(self, monkeypatch):
        """The Windows branch has no group to over-reach into.

        `taskkill /F /T` is scoped to the pid's own descendants, so the hazard
        the POSIX tests above guard against cannot arise -- but the branch
        still needs to be exercised somewhere, and skipping it on POSIX would
        leave it covered only on one runner.
        """
        monkeypatch.setattr(jobs_mod.sys, "platform", "win32")
        calls = []
        monkeypatch.setattr(
            jobs_mod.subprocess, "run", lambda *args, **kwargs: calls.append(args[0])
        )
        assert jobs_mod._kill_pid(5150) is True
        assert calls == [["taskkill", "/F", "/T", "/PID", "5150"]]
