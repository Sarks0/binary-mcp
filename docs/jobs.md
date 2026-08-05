# Background jobs

A full Ghidra analysis of a multi-MB binary takes minutes. An MCP client gives
up after about 30 seconds. The work carries on server-side, finishes, and
writes its cache — but the caller is already gone and never learns the result.

That is the whole problem this solves, plus the thing it turns into: nobody is
left waiting on the subprocess, so the timeout cleanup never fires and the
`analyzeHeadless` tree runs on unattended. Six agents against one binary means
six abandoned Ghidra trees, a saturated box, and cascading timeouts on every
later call that have nothing to do with what those calls asked for.

## Why it is file-backed

binary-mcp runs over **stdio**, so every client gets its own server process.
Six agents are six processes. An in-process job table would fix "my call timed
out and I can't get the result" and do nothing at all about "six processes each
started their own Ghidra" — they share no memory. The only place they meet is
the cache directory, so that is where coordination lives:

```
$BINARY_CACHE_DIR/jobs/<job_id>.job.json     the job record
$BINARY_CACHE_DIR/jobs/<key>.claim.json      exclusive claim on a key
```

Claims are taken with `O_CREAT | O_EXCL`, which is atomic across unrelated
processes on a local filesystem.

## Tools

| Tool | Purpose |
|---|---|
| `job_status` | where a job got to; poll until `done` |
| `job_result` | the payload, once it finished |
| `job_list` | every job on this cache root, from every server process |
| `job_cancel` | stop a job and kill the subprocesses it spawned |

## Starting one

`analyze_binary(..., wait=False)` returns a `job_id` instead of blocking:

```
analyze_binary("/path/to/tquery.dll", wait=False)
  -> job_id: 4f9c2a10be7d3355
job_status("4f9c2a10be7d3355")   -> {"state": "running", "progress": "..."}
job_status("4f9c2a10be7d3355")   -> {"state": "succeeded", "done": true}
job_result("4f9c2a10be7d3355")   -> {"function_count": 14260, ...}
```

The analysis survives the client timeout, and the result lands in the shared
cache either way — so once the job succeeds the ordinary tools just work.

## `decompile_function(..., wait=False)`

Same shape, but only the Ghidra-invoking path goes async. When the pseudocode
is already cached this returns it immediately regardless of `wait` — there is
nothing to wait for, and making a warm read return a job id would be a worse
tool. A background decompile is only started when the cache was built shallow
or structural and the function's body genuinely has to be produced.

```
decompile_function("/path/to/tquery.dll", "CQuery::Execute", wait=False)
  -> job_id: 91b3d0f5c7a24411
job_status(...)                  -> succeeded
decompile_function("/path/to/tquery.dll", "CQuery::Execute")
  -> the formatted body, from the now-warm cache
```

### It does not mark coverage, on purpose

`docs/coverage.md` says a function is marked reviewed only once its body has
been handed to the caller. A background decompile hands it to nobody: it merges
the pseudocode into the cache and finishes. So the job does not mark, and the
mark lands on the next `decompile_function` call — the one that actually
returns the body.

Collecting the result purely through `job_result` therefore **under-marks**.
That is deliberate and it is the safe direction: under-marking costs a re-mark,
over-marking manufactures the false completion the ledger exists to prevent.

## One runner per key

A job's key is the binary's content hash plus the analysis parameters. A second
process asking for the same analysis **attaches** to the running job instead of
starting a competing one:

```
Attached to an analysis already running for tquery.dll.
job_id: 4f9c2a10be7d3355
```

`force_reanalyze` is part of the key on purpose: a caller explicitly asking to
redo the work must not silently attach to the run it was trying to bypass.

## States

`running` | `succeeded` | `failed` | `cancelled` | `orphaned`

`orphaned` is distinct from `failed` deliberately. It does not mean the
analysis went wrong — it means the process running it went away. Its
subprocesses have been reaped and the work needs restarting.

## Job ids are validated, not trusted

`job_id` arrives as an MCP tool argument, and `root / f"{job_id}.job.json"`
happily accepts `../../x` or an absolute path — either of which leaves the
cache root. Generated ids are `uuid4().hex[:16]`, so `_job_path` requires
lowercase hex and additionally asserts the resolved parent is the jobs
directory. Everything keyed by job id goes through that one function, so
`read`, `_update`, `_write`, `_add_child` and `cancel` are all covered by the
single check rather than four tool entry points that each have to remember.

A rejected id reads as "no such job" rather than an error that would confirm
whether the traversed path exists.

## A claim can change hands

Releasing a claim is guarded by the job that believes it holds it. Without
that guard: process A hangs long enough to look dead, B breaks the claim and
starts a replacement, then A wakes up and finishes — and A's tidy-up deletes
*B's* claim. The next submit sees an unclaimed key and starts a second
concurrent Ghidra run on the same binary, which is the exact failure the
registry exists to prevent, reached through the recovery path.

Terminal states are first-writer-wins for the same reason. A worker that
finishes normally must not overwrite a `cancelled` or `orphaned` state another
process wrote while it was running, or an operator who cancelled a job and was
told so later reads `succeeded`.

`job_cancel` from a process that does not own the job cannot interrupt the
worker directly — it has no `JobContext` to flag. It kills the subprocesses and
writes the state; the owner's heartbeat loop sees the state change on its next
tick and sets the local cancel flag, so the worker reports cancelled rather
than claiming success for work that was stopped out from under it.

## Liveness, and why heartbeats rather than pids

A claim is only useful if a crashed owner cannot hold it forever. Owners
heartbeat into their job file every 15s; a claim is dead once the heartbeat is
120s stale.

Pid liveness is a fast path and never the sole signal. Pids get recycled, so a
dead owner's pid can be reused and read as alive — which makes us wait for the
heartbeat to expire. That is the safe direction. The opposite error, treating a
live owner as dead, starts the second Ghidra this exists to prevent, so nothing
concludes "dead" from a pid alone.

The wide gap between heartbeat interval and staleness is deliberate: a box
under Ghidra load can starve a heartbeat thread for a while.

## Reaping, and its blast radius

A job record carries the pids its owner spawned. A sweep — on server startup,
on `job_list`, and whenever a poll notices a stale job — reaps those for
orphaned jobs. The owning process also reaps its own children via `atexit`.

Two guards, both learned the hard way:

**Identity.** A pid alone never justifies a kill. Every kill verifies the
process still looks like the Ghidra one we spawned. If identity cannot be
established the pid is logged and left alone — leaking a process is
recoverable, killing an unrelated one that inherited the pid is not.

**Group.** `killpg` is only used when the target genuinely *leads* its process
group. `runner.analyze` spawns Ghidra with `start_new_session`, so its pid is
its own group leader and the whole java tree goes down together. For any other
pid, `killpg` would take out everything sharing that group — and during a sweep
that group can be the sweeping server's own. The first cross-process test of
this exited 137: the reaper killed itself. It now falls back to the single pid,
which is never more than was asked for.
