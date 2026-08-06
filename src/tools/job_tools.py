"""
Job-control MCP tools: the poll side of the async transport.

A Ghidra analysis takes minutes; an MCP client gives up in ~30 seconds. These
tools are how a caller gets the answer anyway -- submit returns a handle, and
``job_status`` / ``job_result`` retrieve it whenever it is ready, from any
process sharing the cache root.

Like the coverage tools these return a **flat JSON object** rather than prose:
a client polls them in a loop and branches on ``state``, so the shape has to be
stable and machine-readable.
"""

from __future__ import annotations

import logging

from src.engines.jobs import STATE_RUNNING, TERMINAL_STATES

logger = logging.getLogger(__name__)

MAX_LIST = 100


def _error(message: str, **extra) -> dict:
    return {"error": message, **extra}


def _public(record: dict) -> dict:
    """The client-facing view of a job record."""
    return {
        "job_id": record.get("job_id"),
        "kind": record.get("kind"),
        "state": record.get("state"),
        "progress": record.get("progress"),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
        "heartbeat_at": record.get("heartbeat_at"),
        "owner_pid": record.get("owner_pid"),
        "child_pids": record.get("child_pids") or [],
        "error": record.get("error"),
        "done": record.get("state") in TERMINAL_STATES,
    }


def register_job_tools(app, registry):
    """Register the job-control tools with the MCP app."""

    @app.tool()
    def job_status(job_id: str) -> dict:
        """
        Check on a background job started by a long-running analysis call.

        Heavy calls (a full ``analyze_binary`` on a multi-MB binary) take
        minutes, which no MCP client will wait for. Those return a ``job_id``
        instead of blocking; this is how you find out where it got to.

        Poll this until ``done`` is true, then call ``job_result``. Jobs are
        stored in the shared cache directory, so a job started by one server
        process is visible to every other one on the same cache root -- which
        is also why two agents asking for the same analysis get the same
        ``job_id`` rather than two Ghidra runs.

        Args:
            job_id: The id returned by the call that started the work.

        Returns:
            JSON with ``job_id``, ``kind``, ``state``, ``progress``,
            ``owner_pid``, ``child_pids``, ``error`` and ``done``.

            ``state`` is ``running`` | ``succeeded`` | ``failed`` |
            ``cancelled`` | ``orphaned``. ``orphaned`` means the process that
            owned the job stopped heartbeating before finishing -- its
            subprocesses have been reaped and the work needs restarting. It is
            a distinct outcome from ``failed`` on purpose: nothing went wrong
            with the analysis, the thing running it went away.
        """
        record = registry.read(job_id)
        if record is None:
            return _error(f"No such job: {job_id}", job_id=job_id, done=True)
        # Cheap opportunistic sweep so a caller polling a live job also
        # notices somebody else's abandoned one, instead of the pile-up
        # needing an operator to spot it.
        if record.get("state") == STATE_RUNNING and registry.is_stale(record):
            registry.sweep()
            record = registry.read(job_id) or record
        return _public(record)

    @app.tool()
    def job_result(job_id: str) -> dict:
        """
        Fetch the result of a finished background job.

        Args:
            job_id: The id returned by the call that started the work.

        Returns:
            JSON with ``job_id``, ``state``, ``done`` and ``result`` -- the
            payload the work produced, or null when it did not finish.

            On a job still running this returns ``done: false`` with a null
            result rather than an error, so a polling loop does not have to
            treat "not yet" as a failure. On ``failed`` or ``orphaned`` the
            ``error`` field carries why.
        """
        record = registry.read(job_id)
        if record is None:
            return _error(f"No such job: {job_id}", job_id=job_id, done=True)
        payload = _public(record)
        payload["result"] = record.get("result")
        return payload

    @app.tool()
    def job_list(limit: int = 20, state: str | None = None) -> dict:
        """
        List background jobs on this cache root, newest first.

        Shows jobs from **every** server process sharing the cache, not just
        this one. That is the point: it is how you see that another agent is
        already analyzing the binary you were about to analyze, and how an
        abandoned run becomes visible instead of quietly eating the box.

        Args:
            limit: Maximum jobs to return (1-100, default 20).
            state: Optional filter -- ``running``, ``succeeded``, ``failed``,
                ``cancelled`` or ``orphaned``.

        Returns:
            JSON with ``count``, ``jobs`` and ``swept`` (how many abandoned
            jobs this call reaped as a side effect).
        """
        if limit < 1 or limit > MAX_LIST:
            return _error(f"limit must be between 1 and {MAX_LIST}")
        swept = registry.sweep()
        jobs = [_public(r) for r in registry.list_jobs(limit=limit, state=state)]
        return {
            "count": len(jobs),
            "jobs": jobs,
            "swept": len(swept.get("orphaned") or []),
            "reaped_pids": swept.get("reaped_pids") or [],
        }

    @app.tool()
    def job_cancel(job_id: str) -> dict:
        """
        Cancel a running job and kill the subprocesses it spawned.

        Use when an analysis is not worth waiting for, or when a run is
        holding a claim you need released. Killing is gated on verifying each
        pid still looks like the Ghidra process we started -- pids get
        recycled, and killing an unrelated process that inherited one is worse
        than leaving a stray.

        Args:
            job_id: The id of the job to cancel.

        Returns:
            JSON with ``job_id``, ``state``, ``cancelled`` and ``reaped`` (how
            many subprocesses were killed). Cancelling an already-finished job
            reports ``cancelled: false`` rather than failing.
        """
        return registry.cancel(job_id)

    logger.info("Registered 4 job tools")

    return (job_status, job_result, job_list, job_cancel)
