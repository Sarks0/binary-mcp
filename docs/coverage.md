# Review coverage

binary-mcp is the single source of truth for the **coverage denominator** of a
binary: how many functions it has, how many are in scope, and how many have
actually been reviewed. Consumers mirror the counts; they never recompute a
total from their own mark count.

The problem this solves: a reviewer reads 20 functions of a 5000-function
binary and calls it hardened. Without an external denominator that claim is
unfalsifiable. With one it is arithmetic.

## Tools

| Tool | Purpose |
|---|---|
| `get_coverage_status` | the six counts, plus scope provenance |
| `get_next_unreviewed` | deterministic worklist, ascending address |
| `coverage_index` | explicit (re)index; normally automatic |
| `mark_function_reviewed` | manual mark / unmark, optional findings note |

These four return **JSON**, unlike the rest of the server, because consumers
bind to the field names and assert invariants on the counts.

### `get_coverage_status(binary_id=None, binary_path=None)`

```jsonc
{
  "binary_id": "5d2d84175ed6b7ee855adef804906bd78519aa3d0bd495bed91d449aa8c5a5ca",
  "binary_path": "/…/bindflt-28000.2387.sys",
  "module_name": "bindflt-28000.2387.sys",
  "image_base": "0x140000000",
  "total": 256,
  "in_scope_total": 248,
  "reviewed": 6,
  "reviewed_in_scope": 6,
  "remaining": 250,
  "remaining_in_scope": 242,
  "scope_description": "forward BFS over cached called_functions from …",
  "scope_version": "fwd-bfs-v1",
  "indexed_at": "2026-08-03T21:30:04Z",
  "status": "ready"
}
```

Guaranteed server-side, and enforced by a check that raises rather than
returning bad numbers:

- `remaining == total - reviewed`
- `remaining_in_scope == in_scope_total - reviewed_in_scope`
- `in_scope_total <= total`, `reviewed_in_scope <= reviewed`
- all six counts are non-negative integers

`status` is `ready` | `not_indexed` | `indexing` | `stale`. On anything other
than `ready` **all six counts are null, never zero.** Zero would read as
"complete" and terminate a review loop on a binary nobody has looked at, which
is the precise failure this store exists to prevent. Treat a non-ready status
as "cannot conclude", never as "done". (`indexing` is reserved; indexing is
synchronous today and never returns it.)

There is deliberately no `reviewed_list` on this response — an 885-entry array
on every poll saturates a model's context. Use `get_next_unreviewed`.

### `get_next_unreviewed(binary_id=None, count=20, scope="in_scope", binary_path=None)`

Ordered by ascending numeric address. A client that crashes mid-batch and
re-calls gets the same head of the queue, and makes forward progress once those
are marked. `functions: []` with `remaining_after: 0` is the terminal
condition — but only when `status == "ready"`.

`scope="all"` includes thunk / library / unreachable functions. They stay
retrievable precisely so an under-counted scope cannot hide work.

## Auto-marking

These tools mark a function reviewed as a side effect:

- `decompile_function`
- `batch_decompile` — only functions whose pseudocode actually came back
- `get_review_package`
- `get_param_sinks`

They are the calls that hand the caller a function's actual body or a semantic
per-function analysis of it.

**Everything else does not mark.** In particular `get_functions`,
`get_imports`, `get_strings`, `get_function_callers`, `get_switch_tables`,
`analyze_function_completeness`, and the whole-binary `scan_pseudocode` sweep.
Seeing a function in a list is not reviewing it, and a regex sweep that marked
3000 functions would manufacture exactly the false completion the denominator
is there to prevent. Over-marking is the dangerous direction; under-marking
just means the operator re-marks.

Marking is idempotent: re-decompiling does not double-count and does not
rewrite the original timestamp or the tool that first recorded it.

Use `mark_function_reviewed` for work done outside binary-mcp — a Ghidra GUI
session, objdump, a debugger — and to attach a findings note.

## Scope, and what it cannot see

`in_scope` is real reachability, not a name heuristic: a forward BFS over the
`called_functions` edges already materialized in the analysis cache. No Ghidra
run is involved.

Entry points, in priority order:

| `scope_reason` | Source |
|---|---|
| `reachable:export` | PE/ELF export table, including `entry` and TLS callbacks |
| `reachable:ioctl_dispatch` | dispatcher candidates (same predicate `find_ioctl_handlers` uses) and their switch-table targets |
| `reachable:indirect_root` | any function with no direct caller anywhere in the binary |
| `reachable:callee` | discovered downstream of one of the above |

Exclusions are mechanical only — `excluded:thunk`, `excluded:external`,
`excluded:thunk_or_external` (Ghidra's `decompile_status`), `excluded:fid_library`
(a Function ID library match; requires `analyze_binary(enable_fid=True)`).
Nothing is excluded on a name guess.

**The blind spot, stated plainly.** Indirect calls — vtables, dispatch tables,
registered callbacks — are invisible to a forward call-graph walk. That is why
every function with no direct caller is treated as a root: it over-approximates
reachability, and over-approximating is the safe direction. Under-counting
scope shrinks the denominator and manufactures false completion.

The practical consequence on driver-shaped binaries, where the only export is
`entry`: scope leans almost entirely on the address-taken roots, so
`in_scope_total` lands close to `total` and the only real reduction is the
thunk/library set (bindflt: 248 in scope of 256, 8 thunks excluded). That is
the honest number, not a tighter one obtained by dropping the indirect surface.

`remaining_in_scope == 0` therefore means the in-scope worklist is finished,
**not** that the binary is. Full closure still consults `remaining`.

`scope_version` records the method (`fwd-bfs-v1`). It changes whenever scope
logic changes, and a consumer should invalidate its mirror when it does.

## Storage

A `<sha256>.coverage.json` side-car beside the analysis cache, sharing the same
root (`$BINARY_CACHE_DIR`, else `~/ghidra_mcp_cache`) and the same sha stem as
`<sha>.json.gz` / `<sha>.funcidx.json` / `<sha>.notes.json`.

- **Key** — lowercase sha256 hexdigest of the file bytes. The same key
  `ProjectCache` already uses, so re-analysis of the same file on a different
  host resumes the same coverage row. Queries by `binary_id` work even after
  the staged file is deleted.
- **Addresses** — canonical lowercase hex, `0x` prefix, no zero padding
  (`0x140006d8c`). Note that the analysis cache itself stores them *bare*;
  normalizing is this module's job.
  These are loader virtual addresses at the image base as loaded — not file
  offsets, not RVAs, not runtime-rebased debugger addresses. `image_base` is
  reported so a mismatch is detectable rather than silent.
- **Writes** — whole-file and atomic (`os.replace`). There is no lock: two
  clients marking the same binary concurrently race read-modify-write in the
  classic way, later write wins. That matches the surrounding cache and is
  acceptable at one-session-per-binary usage; a lock is the fix if that changes.
- **Lifecycle** — survives `ProjectCache.invalidate` (so `force_reanalyze` and
  `load_pdb` do not destroy a review history; the key is a content hash, so
  addresses cannot have shifted). Dropped by `clear_all`.

Indexing happens automatically after `analyze_binary`, and on the first status
query for a binary that was analyzed before coverage existed. The index rebuilds
itself when the analysis cache grows (an incremental run) or when
`scope_version` changes — **review marks, timestamps and notes are preserved
across a rebuild.**
