"""
Cross-process job registry for work that outlives an MCP call.

The problem this solves
-----------------------
binary-mcp runs over stdio, so every client gets its **own server process**.
A Ghidra analysis routinely takes minutes; an MCP client gives up after ~30
seconds. The server keeps going, finishes, and writes its cache -- but the
caller is already gone and never learns the result. Worse, nobody is left
waiting on the subprocess, so ``_kill_process_tree`` never fires and the
``analyzeHeadless`` tree runs on unattended.

Run six agents against the same binary and that compounds: six server
processes, six independent Ghidra trees on the same input, one saturated box,
and cascading timeouts on every subsequent call. An in-process job table
cannot fix that, because the six are not in one process. Coordination has to
live where they actually meet, which is the shared cache directory.

So this registry is file-backed, and it does two things:

1. **Hands back a handle instead of blocking.** ``submit`` returns a job id
   immediately; the caller polls. The work continues in a background thread
   and its result lands in a file any process can read.
2. **Admits one runner per key.** A second process asking for work already
   running *attaches* to the existing job rather than starting a second one.

Liveness, and why heartbeats rather than pids
---------------------------------------------
A claim is only useful if a crashed owner cannot hold it forever. Owners
heartbeat into their job file; a claim is dead when the heartbeat goes stale.

Pid liveness is used only as a fast path, and deliberately never as the sole
signal: pids are recycled, so a dead owner's pid can be reused by something
unrelated and read as alive. That failure mode makes us *wait longer* for the
heartbeat to expire, which is the safe direction. The reverse -- treating a
live owner as dead and starting a competing Ghidra -- is the one that
reproduces the original problem, so nothing here can conclude "dead" from a
pid alone.

Reaping someone else's children
-------------------------------
A job record carries the pids of the subprocesses its owner spawned. When a
sweep finds an orphaned job it can kill those -- but a pid on its own is not
enough to justify ``kill``, for the same recycling reason. Every kill is gated
on verifying the process still looks like what we spawned
(:func:`_process_matches`). If identity cannot be established the pid is
logged and left alone: leaking a process is recoverable, killing an unrelated
one is not.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import subprocess  # nosec B404 - process liveness/identity probes only
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

STATE_RUNNING = "running"
STATE_SUCCEEDED = "succeeded"
STATE_FAILED = "failed"
STATE_CANCELLED = "cancelled"
STATE_ORPHANED = "orphaned"

TERMINAL_STATES = (STATE_SUCCEEDED, STATE_FAILED, STATE_CANCELLED, STATE_ORPHANED)

# How often an owner refreshes its heartbeat, and how long a heartbeat may go
# unrefreshed before other processes may take the claim. The gap between them
# is deliberately wide: a box under Ghidra load can starve a heartbeat thread
# for a while, and declaring a live owner dead starts the second Ghidra this
# registry exists to prevent.
HEARTBEAT_INTERVAL_SECONDS = 15
STALE_AFTER_SECONDS = 120

# Substrings that identify a process as one of ours before we kill it.
_REAPABLE_MARKERS = ("analyzeheadless", "ghidra")


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(text: object) -> float | None:
    if not isinstance(text, str) or not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return None


def _pid_alive(pid: int) -> bool:
    """Is a process with this pid running right now?

    Only ever used to conclude *dead* faster. A recycled pid reads as alive,
    which costs a longer wait for the heartbeat to expire -- never a second
    Ghidra.
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                capture_output=True, text=True, timeout=10,
            )
            return str(pid) in (out.stdout or "")
        except Exception:
            # Cannot tell -> assume alive. Assuming dead would let another
            # process take a live claim.
            return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists, owned by somebody else.
        return True
    except OSError:
        return True


def _process_command(pid: int) -> str:
    """Best-effort command line for a pid, lowercased. Empty when unknown."""
    try:
        if sys.platform == "linux":
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()
            return raw.replace(b"\x00", b" ").decode("utf-8", "replace").lower()
        if sys.platform == "win32":
            out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
                ["wmic", "process", "where", f"ProcessId={pid}", "get", "CommandLine"],
                capture_output=True, text=True, timeout=10,
            )
            return (out.stdout or "").lower()
        out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True, text=True, timeout=10,
        )
        return (out.stdout or "").lower()
    except Exception:
        return ""


def _process_matches(pid: int) -> bool:
    """Does this pid still look like a Ghidra process we spawned?

    The gate on every cross-process kill. Unknown means no: leaking a process
    is recoverable, killing an unrelated one that happens to have inherited
    the pid is not.
    """
    command = _process_command(pid)
    if not command:
        return False
    return any(marker in command for marker in _REAPABLE_MARKERS)


def _kill_pid(pid: int) -> bool:
    """Kill a process tree by pid, only when its identity checks out."""
    if not _pid_alive(pid) or not _process_matches(pid):
        return False
    try:
        if sys.platform == "win32":
            subprocess.run(  # nosec B603 B607 - tear down stuck Ghidra tree
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True, timeout=15,
            )
        else:
            # Only fan out to the process group when the target actually LEADS
            # that group. `runner.analyze` spawns Ghidra with
            # `start_new_session`, so its pid is its own group leader and the
            # whole java tree goes down together -- which is the point.
            #
            # For any other pid, killpg would take out every process that
            # happens to share the group. During a sweep that group can be the
            # sweeping server's own, so an unguarded killpg turns "reap an
            # abandoned Ghidra" into "kill myself". Fall back to the single
            # pid, which is always in scope and never more than was asked for.
            try:
                if os.getpgid(pid) == pid:
                    os.killpg(pid, 9)
                else:
                    os.kill(pid, 9)
            except (ProcessLookupError, PermissionError, OSError):
                os.kill(pid, 9)
        return True
    except Exception as exc:
        logger.warning("could not reap pid %s: %s", pid, exc)
        return False


class JobContext:
    """Handed to the worker so it can report children and progress."""

    def __init__(self, registry: JobRegistry, job_id: str):
        self._registry = registry
        self.job_id = job_id
        self._cancelled = threading.Event()

    def track_child(self, pid: int) -> None:
        """Record a spawned subprocess so a sweep can reap it if we die."""
        self._registry._add_child(self.job_id, pid)

    def set_progress(self, message: str) -> None:
        self._registry._set_progress(self.job_id, message)

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()


class JobRegistry:
    """File-backed job store shared by every server process on a cache root."""

    def __init__(
        self,
        cache_dir,
        stale_after: int = STALE_AFTER_SECONDS,
        heartbeat_interval: int = HEARTBEAT_INTERVAL_SECONDS,
    ):
        self.root = Path(cache_dir) / "jobs"
        self.stale_after = stale_after
        self.heartbeat_interval = heartbeat_interval
        self._lock = threading.RLock()
        self._local: dict[str, JobContext] = {}
        self._stop = threading.Event()
        try:
            self.root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.error("job registry unavailable at %s: %s", self.root, exc)
        atexit.register(self.shutdown)

    # paths

    def _job_path(self, job_id: str) -> Path:
        return self.root / f"{job_id}.job.json"

    def _claim_path(self, key: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in key)[:120]
        return self.root / f"{safe}.claim.json"

    # persistence

    def _write(self, record: dict) -> None:
        path = self._job_path(record["job_id"])
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(record), encoding="utf-8")
            os.replace(tmp, path)
        except OSError as exc:
            logger.error("could not write job %s: %s", record.get("job_id"), exc)
            tmp.unlink(missing_ok=True)

    def read(self, job_id: str) -> dict | None:
        try:
            data = json.loads(self._job_path(job_id).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
            return None
        return data

    def _update(self, job_id: str, **fields) -> dict | None:
        with self._lock:
            record = self.read(job_id)
            if record is None:
                return None
            record.update(fields)
            record["updated_at"] = _utc_now()
            self._write(record)
            return record

    def _add_child(self, job_id: str, pid: int) -> None:
        with self._lock:
            record = self.read(job_id)
            if record is None:
                return
            children = record.get("child_pids") or []
            if pid not in children:
                children.append(pid)
            record["child_pids"] = children
            record["updated_at"] = _utc_now()
            self._write(record)

    def _set_progress(self, job_id: str, message: str) -> None:
        self._update(job_id, progress=message)

    # liveness

    def is_stale(self, record: dict, now: float | None = None) -> bool:
        """Has this job's owner stopped proving it is alive?

        Heartbeat is the authority. A dead pid is accepted as conclusive
        because it can only make us decide *sooner*; a recycled pid reads as
        alive and simply costs another heartbeat window.
        """
        if record.get("state") != STATE_RUNNING:
            return False
        now = time.time() if now is None else now
        beat = _parse_utc(record.get("heartbeat_at")) or _parse_utc(record.get("created_at"))
        if beat is not None and now - beat > self.stale_after:
            return True
        pid = record.get("owner_pid")
        if isinstance(pid, int) and pid != os.getpid() and not _pid_alive(pid):
            return True
        return False

    # claims

    def _read_claim(self, key: str) -> str | None:
        try:
            data = json.loads(self._claim_path(key).read_text(encoding="utf-8"))
            job_id = data.get("job_id")
            return job_id if isinstance(job_id, str) else None
        except (OSError, ValueError):
            return None

    def _try_claim(self, key: str, job_id: str) -> bool:
        """Atomically take the claim for ``key``. False if somebody has it.

        ``O_CREAT | O_EXCL`` is the whole mechanism: it is atomic on a local
        filesystem across unrelated processes, which is exactly the
        coordination this needs and the only kind two stdio servers can share.
        """
        path = self._claim_path(key)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            return False
        except OSError as exc:
            logger.error("could not create claim %s: %s", path, exc)
            return False
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"job_id": job_id, "key": key, "claimed_at": _utc_now()}, handle)
            return True
        except OSError:
            path.unlink(missing_ok=True)
            return False

    def _release_claim(self, key: str) -> None:
        self._claim_path(key).unlink(missing_ok=True)

    # submission

    def submit(
        self,
        *,
        kind: str,
        key: str,
        fn,
        timeout_seconds: int | None = None,
    ) -> dict:
        """Start ``fn`` in the background, or attach to a job already doing it.

        Returns ``{job_id, state, attached, kind, key}``. ``attached`` is True
        when another process (or an earlier call in this one) was already
        running this key -- the caller polls the same job and gets the same
        answer instead of starting a competing run.
        """
        with self._lock:
            existing = self._existing_for_key(key)
            if existing is not None:
                return {
                    "job_id": existing["job_id"],
                    "state": existing.get("state"),
                    "attached": True,
                    "kind": existing.get("kind"),
                    "key": key,
                }

            job_id = uuid.uuid4().hex[:16]
            if not self._try_claim(key, job_id):
                # Lost a race between the check above and the claim. Whoever
                # won is the runner; attach to them.
                existing = self._existing_for_key(key)
                if existing is not None:
                    return {
                        "job_id": existing["job_id"],
                        "state": existing.get("state"),
                        "attached": True,
                        "kind": existing.get("kind"),
                        "key": key,
                    }
                return {"error": f"could not claim job key {key!r}"}

            record = {
                "schema_version": SCHEMA_VERSION,
                "job_id": job_id,
                "kind": kind,
                "key": key,
                "state": STATE_RUNNING,
                "owner_pid": os.getpid(),
                "created_at": _utc_now(),
                "updated_at": _utc_now(),
                "heartbeat_at": _utc_now(),
                "timeout_seconds": timeout_seconds,
                "child_pids": [],
                "progress": "started",
                "result": None,
                "error": None,
            }
            self._write(record)
            context = JobContext(self, job_id)
            self._local[job_id] = context

        thread = threading.Thread(
            target=self._run, args=(job_id, key, fn, context),
            name=f"job-{job_id}", daemon=True,
        )
        thread.start()
        return {"job_id": job_id, "state": STATE_RUNNING, "attached": False,
                "kind": kind, "key": key}

    def _existing_for_key(self, key: str) -> dict | None:
        """The live job for ``key``, breaking the claim if its owner died."""
        job_id = self._read_claim(key)
        if job_id is None:
            # A claim file that exists but cannot be parsed names no owner, so
            # it protects nothing -- and left in place it wedges this key
            # forever, because the exclusive create keeps failing against it.
            # A truncated write from a process killed mid-claim looks exactly
            # like this.
            if self._claim_path(key).exists():
                logger.warning("discarding unreadable claim for key %r", key)
                self._release_claim(key)
            return None
        record = self.read(job_id)
        if record is None:
            self._release_claim(key)
            return None
        if record.get("state") in TERMINAL_STATES:
            # Finished. The claim is spent; the result stays readable by id.
            self._release_claim(key)
            return None
        if self.is_stale(record):
            logger.warning(
                "job %s (%s) owner pid %s stopped heartbeating; breaking claim",
                job_id, record.get("kind"), record.get("owner_pid"),
            )
            self._orphan(record)
            self._release_claim(key)
            return None
        return record

    def _run(self, job_id: str, key: str, fn, context: JobContext) -> None:
        beat = threading.Thread(
            target=self._heartbeat, args=(job_id,), name=f"hb-{job_id}", daemon=True
        )
        beat.start()
        try:
            result = fn(context)
            if context.cancelled:
                self._update(job_id, state=STATE_CANCELLED, progress="cancelled")
            else:
                self._update(job_id, state=STATE_SUCCEEDED, result=result,
                             progress="complete")
        except Exception as exc:
            logger.exception("job %s failed", job_id)
            self._update(job_id, state=STATE_FAILED, error=str(exc), progress="failed")
        finally:
            self._release_claim(key)
            with self._lock:
                self._local.pop(job_id, None)

    def _heartbeat(self, job_id: str) -> None:
        while not self._stop.is_set():
            if self._stop.wait(self.heartbeat_interval):
                return
            with self._lock:
                if job_id not in self._local:
                    return
            record = self.read(job_id)
            if record is None or record.get("state") != STATE_RUNNING:
                return
            self._update(job_id, heartbeat_at=_utc_now())

    # cancellation and reaping

    def _orphan(self, record: dict) -> list[int]:
        """Mark a job orphaned and reap whatever its dead owner left running."""
        reaped = []
        for pid in record.get("child_pids") or []:
            if isinstance(pid, int) and _kill_pid(pid):
                reaped.append(pid)
        self._update(
            record["job_id"],
            state=STATE_ORPHANED,
            progress="owner exited without finishing",
            error=(
                f"owner pid {record.get('owner_pid')} stopped heartbeating; "
                f"reaped {len(reaped)} subprocess(es)"
            ),
        )
        return reaped

    def cancel(self, job_id: str) -> dict:
        record = self.read(job_id)
        if record is None:
            return {"error": f"no such job: {job_id}"}
        if record.get("state") in TERMINAL_STATES:
            return {"job_id": job_id, "state": record["state"], "cancelled": False,
                    "reaped": 0, "note": "already finished"}

        reaped = 0
        for pid in record.get("child_pids") or []:
            if isinstance(pid, int) and _kill_pid(pid):
                reaped += 1
        with self._lock:
            context = self._local.get(job_id)
            if context is not None:
                context._cancelled.set()
        self._update(job_id, state=STATE_CANCELLED, progress="cancelled",
                     error=f"cancelled; reaped {reaped} subprocess(es)")
        self._release_claim(record.get("key") or "")
        return {"job_id": job_id, "state": STATE_CANCELLED, "cancelled": True,
                "reaped": reaped}

    def sweep(self) -> dict:
        """Find jobs whose owner died and reap what they left behind.

        This is the piece that stops a pile-up: a client that abandoned its
        call leaves a Ghidra tree with nobody waiting on it, and without a
        sweep those accumulate until the box is saturated and every later call
        times out from memory pressure rather than from anything it did.
        """
        orphaned, reaped = [], []
        for path in sorted(self.root.glob("*.job.json")):
            record = self.read(path.name.split(".")[0])
            if record is None or record.get("state") != STATE_RUNNING:
                continue
            if record.get("owner_pid") == os.getpid():
                continue
            if not self.is_stale(record):
                continue
            reaped.extend(self._orphan(record))
            orphaned.append(record["job_id"])
            self._release_claim(record.get("key") or "")
        if orphaned:
            logger.warning("swept %d orphaned job(s), reaped %d process(es)",
                           len(orphaned), len(reaped))
        return {"orphaned": orphaned, "reaped_pids": reaped}

    def list_jobs(self, limit: int = 20, state: str | None = None) -> list[dict]:
        out = []
        for path in self.root.glob("*.job.json"):
            record = self.read(path.name.split(".")[0])
            if record is None:
                continue
            if state and record.get("state") != state:
                continue
            out.append(record)
        out.sort(key=lambda r: r.get("created_at") or "", reverse=True)
        return out[:limit]

    def purge(self, older_than_seconds: int = 86400) -> int:
        """Drop terminal job records older than a cutoff."""
        now, removed = time.time(), 0
        for path in list(self.root.glob("*.job.json")):
            record = self.read(path.name.split(".")[0])
            if record is None or record.get("state") == STATE_RUNNING:
                continue
            updated = _parse_utc(record.get("updated_at"))
            if updated is not None and now - updated > older_than_seconds:
                path.unlink(missing_ok=True)
                removed += 1
        return removed

    def shutdown(self) -> None:
        """Reap our own children on the way out.

        Registered with :mod:`atexit`. Without it, a server process that exits
        while Ghidra is mid-run leaves the tree parentless -- which is exactly
        how the orphans accumulated.
        """
        self._stop.set()
        with self._lock:
            job_ids = list(self._local)
        for job_id in job_ids:
            record = self.read(job_id)
            if record is None or record.get("state") != STATE_RUNNING:
                continue
            reaped = 0
            for pid in record.get("child_pids") or []:
                if isinstance(pid, int) and _kill_pid(pid):
                    reaped += 1
            self._update(
                job_id, state=STATE_FAILED, progress="server exited",
                error=f"server process exited before completion; reaped {reaped} subprocess(es)",
            )
            self._release_claim(record.get("key") or "")
