# Activity Log & Real-Time Tracing — Concept & Plan

Status: **proposed, not implemented.** Captured during a session where
`load_pdb` on `mpengine.dll` ran for 13+ minutes with no visible
output, and the user had to fall back to `Get-Process java` and stat
checks on `ghidra_debug.log` to confirm the process wasn't hung.

## The visibility problem

Long-running binary-mcp operations are opaque from the outside:

- `analyze_binary` on a 17 MB binary can take 60-90 minutes. The MCP
  client sees a single tool call that returns at the end. Until then,
  no progress, no phase markers, no way to tell "is it working?" apart
  from "did it crash?"
- `load_pdb` is internally a 5-step pipeline (fetch PDB → invalidate
  cache → stage adjacent → spawn Ghidra → run analyzers → write
  cache). When it's slow, the user can't tell which step.
- `expand_callgraph` runs N targeted decompiles. If function 73 of 100
  wedges, the user sees a hung tool call but doesn't know it's the
  73rd specific subprocess that's the problem.
- `ghidra_debug.log` only gets written *after* Ghidra returns, so
  it's useless for live monitoring of the longest single phase.

The diagnostic moves we ended up using during this session — `Get-Process
java`, `Get-Item ghidra_debug.log | Select LastWriteTime`, manual CPU
inspection — are all manual proxy signals. We need first-class
observability.

## Goals

1. **Real-time tail-able log** so the user can watch progress from
   another shell while a tool runs. PowerShell `Get-Content -Wait`,
   POSIX `tail -f`.
2. **Phase markers** that bracket logical steps (download, spawn,
   analyse, post-script, cache-write) with timestamps and durations,
   so failures show up at the phase boundary, not buried in
   subprocess output.
3. **In-conversation introspection** via an MCP tool that returns
   recent activity — the model can ask "what was happening 5 minutes
   ago?" without external shell access.
4. **No noise.** Activity log emits one line per logical event, not
   debug-level chatter. Grep-friendly, low-volume.
5. **Never fail the operation it's tracking.** Logging errors must be
   swallowed.

## Non-goals

- Distributed tracing / OpenTelemetry. Overkill for a local tool.
- JSON-lines output. Text is more grep-friendly and the volume is low
  enough that machine parsing isn't the priority. (Easy to add later
  if we want a visualiser.)
- Replacing Python logging. Activity log sits *alongside* logging.
  Logging stays for stack traces and debug-level detail; activity log
  captures the structured high-level phase narrative.

## Layered design — 4 levels, each shippable independently

### Layer 1 — Activity log file with phase markers (highest value, lowest risk)

New module `src/utils/activity_log.py` that exposes:

```python
emit(tool: str, **fields)              # write one line, autoflushed
phase(tool, phase_name, **start_fields) # context manager: start + ok/error + duration
get_activity_log_path() -> Path         # canonical file location
tail(lines=200, filter_tool=None, filter_phase=None) -> list[str]
```

File location:
- Default: `~/.binary_mcp_cache/activity.log` (sibling of analysis cache).
- Overridable: `BINARY_MCP_ACTIVITY_LOG` env var (full path) or
  `BINARY_MCP_CACHE` env var (uses `<cache>/activity.log`).

Format (one event per line):

```
2026-05-09T17:30:12.345Z [load_pdb] phase=fetch_pdb status=start binary=mpengine.dll
2026-05-09T17:30:14.890Z [load_pdb] phase=fetch_pdb status=ok duration_s=2.55 cached=True
2026-05-09T17:30:14.892Z [load_pdb] phase=ghidra_analyze status=start
2026-05-09T17:43:12.001Z [load_pdb] phase=ghidra_analyze status=ok duration_s=777.11
```

Conventions:
- ISO-8601 UTC with millisecond precision, `Z` suffix. Sortable.
- `[tool]` is the MCP tool name (load_pdb, analyze_binary, etc.).
- `phase=` is a short slug for the logical step.
- `status=` is one of `start | ok | error | progress`.
- `duration_s=` on `ok`/`error` events.
- Domain-specific fields appended (`binary=`, `pdb_size=`,
  `function_count=`, etc.). Values containing whitespace get quoted.

Risk: minimal. New file, new module, no behavioural changes to existing
code paths.

### Layer 2 — Phase markers wired into long-running tools

Add `phase()` context managers in:

- `load_pdb` — bracket fetch_pdb / cache.invalidate / stage_pdb /
  ghidra_analyze / cache_write phases.
- `analyze_binary` — bracket cache check / ghidra_analyze / post-script
  / cache_write.
- `expand_callgraph` — bracket each iteration of the BFS, each
  per-function decompile.
- `runner.analyze` — bracket subprocess spawn / wall-clock wait / kill /
  drain phases. Especially valuable: a `phase=ghidra_subprocess`
  marker captures total Ghidra wall-clock independently of any other
  Python overhead.
- `fetch_pdb` — bracket CodeView extract / URL build / per-server
  attempt with HTTP code recorded.

Each `phase()` context manager handles start + end + duration + error
fields automatically. Adding a phase to a function is a 2-line change
(import + with-block).

Risk: low. Additive only. The context manager swallows logging errors,
so a broken activity log can never fail an analysis.

### Layer 3 — Real-time Ghidra stderr streaming (highest value for the actual UX problem, medium risk)

The 13-minute opaque wait the user just hit is *inside* a single Ghidra
subprocess call. Phase markers help frame it ("we're in
ghidra_subprocess for 13 min so far") but don't help diagnose *what
phase of Ghidra* is slow. Ghidra's auto-analysis pipeline emits
progress messages to stderr — Decompiler Switch Analysis, Reference
analyzer, PdbUniversalAnalyzer, etc. — but currently those are buffered
and only flushed when the subprocess exits.

Replace `runner.analyze`'s `proc.communicate(timeout=...)` pattern with
a Popen + manual lifecycle that:

1. Starts two pump threads, one per stdout/stderr stream.
2. Each thread reads line-by-line, appends to a captured list, AND
   writes to `<cache>/ghidra_live.log` autoflushed.
3. Main thread does `proc.wait(timeout=...)` for wall-clock cap.
4. On TimeoutExpired: kill tree + join pump threads (with own
   timeout) + raise.
5. Final captured stdout/stderr still returned exactly as before, so
   `_extract_ghidra_diagnostic` and the `ghidra_debug.log` writer
   keep working unchanged.

Live log lets the user run from another shell:

```powershell
Get-Content ~\.binary_mcp_cache\ghidra_live.log -Wait
```

…and watch `Decompiler Switch Analysis...`, `Reference...`, and the
PdbUniversalAnalyzer's progress messages stream in real-time. Wedge
points become visible: if `Decompiler Switch Analysis` is the last
line for 5 minutes, that's where the analyzer is stuck.

Risk: medium. Touches the subprocess lifecycle in `runner.analyze`,
which is the most load-bearing code in the project. Needs careful
tests around timeout, kill, and stream draining. Worth doing because
this is what would have actually told the user *why* their 13-minute
wait was 13 minutes.

### Layer 4 — `tail_activity` MCP tool (low effort, useful but secondary)

```python
@app.tool()
def tail_activity(lines: int = 200,
                  filter_tool: str | None = None,
                  filter_phase: str | None = None) -> str:
    """Read recent activity log lines from inside the conversation."""
```

Lets the model introspect activity without external shell access. Most
useful when a previous tool call had a partial result and we want to
ask "what got far enough to log before it failed?".

Risk: trivial. Read-only file access.

## Format decisions and rationale

**Why text, not JSON-lines?**
- The volume is low (tens to hundreds of events per analysis, not
  thousands). Compactness doesn't matter.
- Grep + ripgrep + PowerShell `Select-String` work natively on text.
- Humans tail this file. JSON-lines would need `jq` to be readable.
- If we ever need machine parsing, the format is regex-trivial:
  `(\S+) \[(\w+)\] (.*)`.

**Why a separate file, not stdout/stderr of the MCP server?**
- The MCP server's stdout/stderr is owned by the client (Claude Desktop,
  Cursor, etc.) and may not be tail-able from a separate shell.
- A file at a known location is the most universally accessible
  observable.

**Why `~/.binary_mcp_cache/activity.log` (not /tmp, not /var/log)?**
- Sibling to the analysis cache makes it discoverable: if you found
  the cache, you found the log.
- User-writable everywhere; no privilege escalation needed.
- Survives reboots (unlike /tmp on some systems).

**Why no rotation in v1?**
- File grows ~100 bytes/event, a few hundred events per analysis.
  Multiple-MB after a year of heavy use, not GB. Not urgent.
- `clean_cache()` already exists; it should grow to also rotate
  `activity.log` once we have one. Add when needed.

## Concrete implementation steps (when we come back)

1. **Layer 1** (~ 1 hour, ~ 150 lines including tests):
   - Create `src/utils/activity_log.py` with `emit`, `phase`, `tail`,
     `get_activity_log_path`. Pure stdlib (no new deps).
   - `tests/test_activity_log.py` — file write/read, phase context
     manager success path, phase context manager error path,
     `tail()` filtering.
2. **Layer 2** (~ 2 hours, ~ 80 lines across 5 files):
   - Wire `phase()` blocks into `load_pdb`, `analyze_binary`,
     `expand_callgraph`, `runner.analyze`, `fetch_pdb`. One block per
     logical phase. ~ 5-10 phases per tool.
   - Update existing tests where phase-marker emission is observable
     in test logs (most won't need changes).
3. **Layer 3** (~ 4 hours, ~ 100 lines + careful tests):
   - Refactor `runner.analyze` subprocess block to streaming pumps.
   - Hardest test: timeout fires while pumps are mid-flight; kill
     tree; join with own timeout; verify partial stderr is still
     captured.
   - Verify on Windows VM end-to-end (this is where the original
     subprocess-cleanup hangs lived; the streaming change must not
     reintroduce them).
4. **Layer 4** (~ 30 min, ~ 40 lines):
   - `tail_activity` MCP tool wrapping `activity_log.tail()`.
   - Format output as a fenced code block for readability in chat.

Total realistic effort: ~ 8 hours of focused work + careful Windows
verification. Should land as a single PR (`feat(observability):
real-time activity log + Ghidra stderr streaming`) so reviewers see
the complete visibility story.

## Open questions to revisit when we come back

1. **Should `phase()` be auto-instrumented via a decorator** instead of
   manual `with` blocks? `@traced("load_pdb")` would be terser but less
   precise about sub-phases. Lean toward explicit `with` for clarity.
2. **Should we include a session ID** in each event so multiple
   concurrent MCP server processes don't interleave confusingly?
   Probably yes if/when we support concurrent invocations, but a
   single-server install can defer.
3. **How does this relate to the existing UnifiedSessionManager** in
   `src/engines/session.py`? The session manager already logs tool
   invocations. Activity log is finer-grained (per phase, not per
   tool call). Could the session manager *consume* the activity log
   to build session summaries? Worth exploring.
4. **Do we want a `progress` status** for emitting heartbeats during
   long single phases (e.g. core_analysis.py emits "processed 10000
   of 47000 functions" every 30s)? Adds noise but adds the
   highest-value visibility. Probably worth a Layer 3.5.

## What this would have prevented in this session

- The 13-minute opaque `load_pdb` wait would have been live-tail-able:
  the user could see `phase=fetch_pdb status=ok` then
  `phase=ghidra_subprocess status=start` immediately, with Ghidra
  stderr streaming in `ghidra_live.log`. They'd see Decompiler Switch
  Analysis taking minutes and know it was working.
- The earlier 36-minute Windows hang on PR #117 would have shown
  `phase=ghidra_subprocess status=start` and then no further events
  for 36 minutes — instantly diagnostic of "subprocess wedged."
- The 2-hour `Cogitated for 1h 59m 12s` block from the BMEnvVarReceiver
  session would still have been opaque (that's the model thinking,
  not the tool), but every tool call inside it would have left phase
  markers, so the post-mortem would have been "we ran 25 decompile
  calls, here's the timing for each."
