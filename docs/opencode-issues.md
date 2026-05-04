# opencode + binary-mcp: Known Issues and Workarounds

Notes on two distinct opencode-side issues encountered while driving the
binary-mcp MCP server through opencode. Both are upstream bugs, not
binary-mcp bugs - documented here so the next person hitting them does
not waste time looking on our side.

## Issue 1 - MCP request timeout (`-32001`)

### Symptom

opencode aborts long-running tool calls with:

```
MCP error -32001: Request timed out
```

Most often hit on:

- `analyze_binary` on multi-GB binaries (mpengine-class) where Ghidra
  takes minutes.
- `scan_pseudocode` across tens of thousands of functions before
  pagination/summary mode landed.
- Any tool that legitimately needs more than opencode's stock per-request
  timeout.

### Root cause

opencode's default per-MCP-request timeout is short (single-digit
minutes) and is independent of any timeout the MCP server itself
enforces. binary-mcp's tools - especially Ghidra-backed ones - have
their own internal timeout budget (30 minutes by default for Ghidra)
that exceeds what opencode is willing to wait for.

### Fix

Raise opencode's MCP request timeout in its config. Check the
opencode config file (typically under `~/.config/opencode/` or a
project-local `opencode.json`) for an MCP timeout key and bump it
to comfortably exceed `GHIDRA_TIMEOUT` (30 minutes default in
binary-mcp, configurable via env var).

For binary-mcp's side, the relevant env vars are documented in
`src/utils/config.py`:

- `GHIDRA_TIMEOUT` (seconds, 30-3600, default 1800)
- `GHIDRA_FUNCTION_TIMEOUT` (per-function decompile, default 30)

If you cannot change opencode's timeout, mitigations:

- Use `analyze_binary(skip_decompile=True)` for a much faster structural
  pass.
- Use `analyze_binary(incremental=True, start_address=..., end_address=...)`
  to run in chunks within whatever time budget opencode allows.

## Issue 2 - Silent tool-response truncation

### Symptom

A tool returns a large structured payload (e.g. 60 K functions, full
pseudocode dump). opencode passes a clean cut-off back to the model -
no error, no marker, no indication anything was dropped. The model
then reasons over a partial payload as if it were complete and
silently produces wrong conclusions.

### Root cause

opencode has a hidden truncation step in its tool-result handler
(`tool/truncation.ts`) that cuts payloads above a threshold without
inserting a marker. Tracked upstream in opencode issue #13770. The
model has no way to know the data was truncated.

### Server-side mitigations (already shipped in binary-mcp)

PR #114 added pagination + summary mode to the noisiest tools:

- `scan_pseudocode(summary_only=True, offset=N, limit=M)` returns one
  line per finding instead of full pseudocode excerpts; combine with
  offset/limit to walk the result set without overflowing.
- `analyze_binary(skip_decompile=True)` skips per-function pseudocode
  entirely - large structural metadata only.

When adding new tools that can produce large payloads, follow the same
pattern: surface a `summary_only` flag and `offset`/`limit` for
pagination so the model can drive the cut intentionally rather than
discovering it post-hoc.

### Client-side fix (optional, on opencode itself)

Three escalating options:

1. **Config knob.** Check whether opencode has added a knob since
   #13770 was filed:
   ```
   opencode --help 2>&1 | grep -i 'truncat\|max.*token\|max.*output\|response.*limit'
   ls ~/.config/opencode/ ~/.opencode/ 2>/dev/null
   opencode config 2>&1 | head -40
   ```
   Look for env vars like `OPENCODE_MAX_TOOL_OUTPUT` or config keys
   like `tool.maxOutputTokens` / `truncation.threshold`. If present,
   set it and stop here.

2. **Patch the installed JS.** opencode ships as a compiled bundle.
   Find the truncation site and either bump the threshold (10x), add
   an opt-out env var that short-circuits the function, or at minimum
   make the truncation insert a clear marker
   (`\n\n[truncated: N chars omitted]`) so the model can tell the
   payload was cut. Locate the install:
   ```
   readlink -f $(which opencode)
   grep -rn 'truncation\|truncate.*tool\|maxToolOutput' \
     "$(dirname $(readlink -f $(which opencode)))/.." 2>/dev/null | head
   ```
   The patch is lost on every `npm i -g opencode-ai` / `bun upgrade`.

3. **Make the patch durable.** Either use `patch-package` (if
   project-local install with a `package.json`) or build opencode
   from source: clone the repo, edit `packages/opencode/src/tool/truncation.ts`,
   run their build (`bun run build` / `pnpm build`), point your shell
   at the resulting binary.

### Caveats

- Anthropic's API has its own per-message size cap. Removing
  client-side truncation lets bigger payloads through, but the API
  can still return `request_too_large` / 400 on extreme cases. The
  long-term answer is server-side pagination (option above), not
  unlimited responses.
- Don't disable other safety/length checks that aren't this specific
  silent truncation - prompt-cache logic, conversation compaction,
  per-line rate limits should stay alone.

## Cross-references

- binary-mcp PR #114 (pagination/summary modes for `scan_pseudocode`):
  https://github.com/Sarks0/binary-mcp/pull/114
- opencode issue #13770 (silent truncation in `tool/truncation.ts`):
  upstream tracking issue.
- `src/utils/config.py` - all binary-mcp env-var knobs.
