# Ghidra MCP Defender Analysis Issues

Date: 2026-05-05

This note captures the issues found while reviewing why `analyze_binary` failed
or appeared to fail for Defender PE files such as `MpDlp.dll`,
`MpDetours.dll`, and `MpClient.dll`.

The short version: the observed failures are not just "Ghidra cannot analyze
these binaries." There is evidence that Ghidra completed useful analysis for
the Defender-DLP copies, but the MCP server did not promote the temporary JSON
outputs into the normal hash cache and masked the real failure reason behind
generic reference IDs.

## Scope Reviewed

- Current working repo:
  `C:\Users\zerocool\Documents\binary-mcp`
- Live/stale repo apparently used by the running MCP instance:
  `C:\Users\zerocool\binary-mcp`
- Ghidra cache directory:
  `C:\Users\zerocool\.ghidra_mcp_cache`
- Reported failures:
  - `MpDlp.dll`: no cache; explicit `analyze_binary` failed, ref `a06cc1d9`
  - `MpDetours.dll`: explicit analysis failed, ref `ecc51cdf`
  - `MpClient.dll`: explicit analysis failed, ref `fee0342a`

## Issue 1 - Running MCP Uses a Stale Checkout

### Evidence

The latest Ghidra debug log in:

```text
C:\Users\zerocool\.ghidra_mcp_cache\ghidra_debug.log
```

shows the live script path as:

```text
C:\Users\zerocool\binary-mcp\src\engines\static\ghidra\scripts\core_analysis.py
```

But the reviewed repo is:

```text
C:\Users\zerocool\Documents\binary-mcp
```

The stale/live checkout has older code:

- `analyze_binary` does not expose `skip_decompile`, `incremental`,
  `pdb_path`, `enable_fid`, or `analysis_depth`.
- `GhidraRunner` raises plain `RuntimeError`, not `GhidraAnalysisError` with a
  curated diagnostic.
- `GHIDRA_TIMEOUT` defaults to `600`, not the newer `1800`.
- `core_analysis.py` records language as `program.getLanguage()`, yielding
  values like `x86/little/64/default`, instead of the canonical
  `program.getLanguageID().getIdAsString()` form like `x86:LE:64:default`.

### Impact

Fixes in `C:\Users\zerocool\Documents\binary-mcp` will not affect the MCP
server if the client config launches `C:\Users\zerocool\binary-mcp`.

This explains why "fixed" behavior may not appear in tool calls.

### Recommended Work

1. Check the MCP client configuration and confirm which repo path is launched.
2. Point the MCP server at `C:\Users\zerocool\Documents\binary-mcp`, or port the
   current changes into `C:\Users\zerocool\binary-mcp`.
3. Restart the MCP client/server process after updating the path.
4. Re-run `ghidra_diagnose` or a small `analyze_binary` test and confirm the
   debug log references the intended checkout.

## Issue 2 - Ghidra Diagnostics Are Still Masked

### Evidence

In the current repo, `runner.analyze()` can raise `GhidraAnalysisError` with
diagnostic output extracted from Ghidra stdout/stderr.

However, `get_analysis_context()` catches every exception and rethrows:

```python
except Exception as e:
    logger.error(f"Analysis failed: {e}")
    raise RuntimeError(f"Failed to analyze binary: {e}")
```

That strips exception type and custom fields such as `.diagnostic`.

Then `analyze_binary()` catches the resulting generic exception and returns:

```text
Error: Analysis failed unexpectedly
Reference ID: <id>
Please contact support with this reference ID.
```

The same broad catch also masks `UserFacingError`, so import-failure and
validation errors that were designed to produce actionable user messages can
become generic reference-ID failures.

### Impact

The reported refs `a06cc1d9`, `ecc51cdf`, and `fee0342a` are likely generated
by `safe_error_message()` after the useful diagnostic was wrapped away.

This makes backend logs necessary even when Ghidra already emitted the real
cause.

### Recommended Work

1. In `get_analysis_context()`, let `GhidraAnalysisError` and
   `UserFacingError` propagate unchanged.
2. Avoid wrapping all exceptions as plain `RuntimeError` unless the wrapper
   preserves `__cause__` and diagnostic fields.
3. Add tests proving that:
   - a `GhidraAnalysisError(diagnostic="...")` from `runner.analyze()` reaches
     `analyze_binary()` and appears in the returned text;
   - `UserFacingError` still returns its user-facing message rather than a
     generic reference-ID response.

## Issue 3 - Ghidra Produced Temp JSON for the Defender-DLP Binaries

### Evidence

These temp output files exist:

```text
C:\Users\zerocool\.ghidra_mcp_cache\temp_analysis_MpDlp.json
C:\Users\zerocool\.ghidra_mcp_cache\temp_analysis_MpDetours.json
C:\Users\zerocool\.ghidra_mcp_cache\temp_analysis_MpClient.json
```

Observed summary:

| Temp Output | Functions | Imports | Strings | Partial | Thread Timeouts |
| --- | ---: | ---: | ---: | --- | ---: |
| `temp_analysis_MpDlp.json` | 13,143 | 394 | 9,191 | `False` | 1 |
| `temp_analysis_MpDetours.json` | 1,369 | 163 | 1,064 | `False` | 0 |
| `temp_analysis_MpClient.json` | 6,843 | 291 | 3,975 | `False` | 1 |

The latest `ghidra_debug.log` for `MpClient.dll` shows:

```text
[+] Analysis complete! Output saved to:
C:\Users\zerocool\.ghidra_mcp_cache\temp_analysis_MpClient.json
INFO  REPORT: Post-analysis succeeded ...
INFO  REPORT: Import succeeded ...
```

### Impact

The failure mode is probably not "Ghidra cannot analyze these binaries."

More likely failure points:

- the MCP request timed out or was cancelled after Ghidra completed;
- Python stalled or failed while loading a large temp JSON;
- `cache.save_cached()` failed or never ran;
- the live stale server path had older timeout behavior;
- a later exception was masked by the broad catch path described above.

Because the temp files are not promoted into the normal hash cache, subsequent
tools see "no cache" even though useful Ghidra output exists.

### Recommended Work

1. Add logging around:
   - JSON load from `temp_analysis_*.json`;
   - context validation;
   - `cache.save_cached()`;
   - temp-file deletion.
2. Consider a recovery path that can promote a valid `temp_analysis_<stem>.json`
   into the hash cache when the normal save phase was interrupted.
3. Consider writing Ghidra output directly to a unique run file first, then
   atomically promoting it into cache after validation.
4. Ensure client MCP request timeout comfortably exceeds `GHIDRA_TIMEOUT` plus
   JSON load/cache-save time.

## Issue 4 - Temp Output Is Ignored by Cache Lookup

### Evidence

`ProjectCache` indexes by binary SHA256 and checks for:

```text
<sha256>.json.gz
<sha256>.json
```

It does not consider:

```text
temp_analysis_<binary-stem>.json
```

This is correct for normal operation, but it means interrupted successful runs
leave large useful temp files that are invisible to MCP tools.

### Impact

Users can repeatedly pay the full Ghidra cost for the same binary while every
subsequent tool still reports no cache.

### Recommended Work

1. Keep normal hash-cache behavior as the canonical path.
2. Add an explicit admin/debug tool or documented maintenance command to:
   - validate a temp analysis JSON;
   - compute the source binary hash;
   - save it through `ProjectCache.save_cached()`;
   - delete the temp file after successful promotion.
3. Do not silently trust temp files without validating binary path, metadata,
   and context shape.

## Issue 5 - Current Repo Fixes Are Not Fully Covered by Tests

### Evidence

The current repo has tests for:

- gzip cache round-trip;
- function index sidecar;
- analysis-depth env plumbing;
- shallow-cache rejection for pseudocode scanning;
- incremental/delta merge behavior.

The reviewed tests did not show coverage for:

- `GhidraAnalysisError` propagation through `get_analysis_context()` and
  `analyze_binary()`;
- `UserFacingError` propagation through `get_analysis_context()`;
- cache promotion failure after a valid temp JSON is written;
- recovery from existing temp JSON;
- verifying that the live script path matches the intended checkout.

### Impact

The repo can contain the right primitives but still regress to opaque
reference-ID failures.

### Recommended Work

Add focused tests for exception propagation and temp-output promotion before
attempting another large Defender binary run.

## Issue 6 - Documentation Timeout Drift

### Evidence

The current repo code and docs are inconsistent:

- Current code in `src/server.py` uses default `GHIDRA_TIMEOUT=1800`.
- `docs/opencode-issues.md` references a 30-minute default.
- `README.md` and `.env.example` still mention `600`.
- The stale live checkout uses default `600`.

### Impact

It is easy to run with a 10-minute MCP/Ghidra budget while assuming the newer
30-minute workflow is active.

### Recommended Work

1. Align README, `.env.example`, and setup docs around the real default.
2. Document that MCP client request timeout must be larger than
   `GHIDRA_TIMEOUT`.
3. Make `ghidra_diagnose` report effective timeout values and repo/script path.

## Issue 7 - LPAC and MsMpEngCP Proof Work Is Outside This Repo

### Evidence

Searches in both checkouts found no repo material for:

- `Proc207`;
- `LPAC`;
- `Launch App Container`;
- `MsMpEngCP`;
- Defender Sandbox harnessing;
- an RPC proof runner for this scenario.

### Impact

The MCP backend can help with static binary analysis, but it does not currently
contain the proof infrastructure needed for either:

- the fast LPAC eligibility test; or
- the stronger Defender Sandbox / `MsMpEngCP` demonstration.

### Recommended Work

Keep this separate from the MCP backend fix.

For the vulnerability proof path:

1. Fast eligibility check:
   - Run the existing Proc207 PoC from Launch App Container with LPAC.
   - Record whether the RPC endpoint is reachable from restricted context.
   - Record exact HRESULTs and whether the handler body is reached.
2. Stronger Defender-specific proof:
   - Decide whether to execute a harness inside/through `MsMpEngCP`, or
   - trigger a Defender scan/sandbox workflow that naturally invokes the
     vulnerable DLP path with attacker-controlled source path.
3. Keep evidence separate:
   - LPAC proves bounty-scenario reachability.
   - `MsMpEngCP` proves Defender Sandbox context relevance.

## Suggested Fix Order

1. Correct the MCP server launch path so the intended checkout is actually
   running.
2. Preserve `GhidraAnalysisError` and `UserFacingError` through
   `get_analysis_context()`.
3. Add logging and tests around temp JSON load/cache-save.
4. Add a recovery/promote path for valid stranded temp analysis files.
5. Align timeout docs/config and expose effective timeout in diagnostics.
6. Re-run a small PE analysis to confirm diagnostics and cache promotion.
7. Re-run one Defender DLL with `analysis_depth="structural"` or
   `skip_decompile=True` first, then full/incremental only if needed.
8. Work LPAC and `MsMpEngCP` proof separately from MCP backend reliability.

## Useful Current Artifacts

These existing temp files may be recoverable after validation:

```text
C:\Users\zerocool\.ghidra_mcp_cache\temp_analysis_MpDlp.json
C:\Users\zerocool\.ghidra_mcp_cache\temp_analysis_MpDetours.json
C:\Users\zerocool\.ghidra_mcp_cache\temp_analysis_MpClient.json
```

These are not canonical cache files. They should be treated as candidate
analysis outputs, validated, and then promoted through `ProjectCache` if they
match the intended source binaries.

