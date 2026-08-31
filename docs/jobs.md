# Background jobs

A full Ghidra analysis of a multi-MB binary takes minutes. Some MCP clients
abandon a call long before that. The work carries on server-side, finishes, and
writes its cache — but the caller is already gone and never learns the result.

That is the whole problem this solves, plus the thing it turns into: nobody is
left waiting on the subprocess, so the timeout cleanup never fires and the
`analyzeHeadless` tree runs on unattended. Six agents against one binary means
six abandoned Ghidra trees, a saturated box, and cascading timeouts on every
later call that have nothing to do with what those calls asked for.

## How long will a client actually wait?

This doc used to assert "about 30 seconds" as a fact. It is not one — it is a
client setting, and the spread is enormous. For **Claude Code over stdio**:

| Limit | Default | Control |
|---|---|---|
| Wall clock per call | ~28 hours when unset | `MCP_TOOL_TIMEOUT`, or a per-server `timeout` (ms) in `.mcp.json` |
| Idle — no response *and* no progress | 30 min (stdio) | `CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT` |
| Auto-background | 2 min, then it becomes a background task and stops blocking the session | `CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS` |

So there is no 30-second wall there at all, and a per-server `timeout` is a
**hard** ceiling that progress notifications do *not* extend. Other clients are
stricter. Since a stdio server cannot know which client it is talking to, it
does not guess — see the deadline below.

## Deadline-then-degrade

Tools that invoke Ghidra do not choose between "block" and "return a handle".
They do both, in that order: submit the work, block up to
`BINARY_MCP_INLINE_DEADLINE` seconds (default **25**), and return a job handle
only if it is still running when that expires.

That is correct against a client that waits 30 seconds and one that waits 28
hours, without either being configured. A fast call reads as an ordinary
synchronous call — no job id anywhere in the answer — and a slow one degrades
to a handle instead of being abandoned mid-run. With project reuse
(see [large-binary-decompile.md](large-binary-decompile.md)) most targeted
decompiles now land inside the deadline.

Raise the deadline if your client is known to be patient; under Claude Code,
where a long call moves to a background task rather than failing, 90–120s
returns more answers inline. `wait=False` still skips the window entirely and
hands back the handle immediately.

A **warm cache never touches the registry at all** — no claim file, no job
record, no thread. A cache hit needs no Ghidra run, so it must not pay for the
machinery that exists to survive one.

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

With `wait=True` (the default) that decompile still runs as a job — it just
blocks on it until the inline deadline first, so a quick one comes back as a
formatted body and a slow one comes back as a handle.

```
decompile_function("/path/to/tquery.dll", "CQuery::Execute", wait=False)
  -> job_id: 91b3d0f5c7a24411
job_status(...)                  -> succeeded
decompile_function("/path/to/tquery.dll", "CQuery::Execute")
  -> the formatted body, from the now-warm cache
```

`decompile_functions(..., wait=False)` submits the same kind of job for a whole
list of targets, running them through a single Ghidra invocation. Its result
carries `decompiled_functions` and `failed` rather than a body — a batch of two
hundred would put megabytes of pseudocode in the on-disk job record, and the
cache is where the bodies are meant to be read from. A single-function job
still carries `pseudocode` as before.

Since [project reuse](large-binary-decompile.md) landed, a targeted decompile
on a binary that has been analyzed once no longer re-imports and re-analyzes
the binary first, so `wait=True` is viable far more often than it used to be.

### A job that produced no body fails

If the targeted decompile comes back with no pseudocode, the job finalizes
`failed` — not `succeeded` with an empty result. That distinction is the whole
value of having a state: an earlier version returned `decompiled: false`
alongside a note claiming the cache had been updated, finalized `succeeded`,
and sent the caller to a `decompile_function` call that answered "could not be
decompiled". Three ways of saying it worked, about work that produced nothing.

The `error` says what to do — normally
`analyze_binary(analysis_depth='full')`.

This generalises to every job. **`submit`'s contract is that `fn` returning
normally means success; failure is raised, never encoded in the returned
payload.** The registry deliberately does not inspect the result, because it
cannot know which of a caller's fields mean failure. If your work function
computes something like a `succeeded` flag into its own result, that is the
signal it should be raising instead.

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
