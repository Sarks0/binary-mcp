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
| `mark_functions_examined` | bulk-record a machine pass; never a review |
| `reset_coverage` | clear every mark for a binary, or drop the record entirely |

These six return a **flat JSON object**, unlike the rest of the server, because
consumers bind to the field names and assert invariants on the counts.

They return a `dict`, not a serialized string, and that is load-bearing: FastMCP
puts a `str` return under `structuredContent.result` *as a string*, so a client
that peels one envelope layer lands on a string and its flat-object assumption
breaks. Returning the object keeps every transport path flat —
`structuredContent`, `.data` and `content[0].text` all carry the same object,
with no `result` / `data` / `coverage` wrapper.
`tests/test_coverage_tools.py::TestWireShape` guards this.

Errors use the same flat shape, carrying an `error` key.

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
  "examined": 31,
  "examined_in_scope": 31,
  "examined_unreviewed": 27,
  "examined_by_kind": { "diff": 31, "sweep": 0, "external": 0 },
  "dropped_address_count": 0,
  "scope_description": "forward BFS over cached called_functions from …",
  "scope_version": "fwd-bfs-v2",
  "indexed_at": "2026-08-03T21:30:04Z",
  "status": "ready"
}
```

Guaranteed server-side, and enforced by a check that raises rather than
returning bad numbers:

- `remaining == total - reviewed`
- `remaining_in_scope == in_scope_total - reviewed_in_scope`
- `in_scope_total <= total`, `reviewed_in_scope <= reviewed`
- all counts are non-negative integers
- `total + dropped_address_count == source_function_count` — the only one of
  these that compares the denominator against something it did not derive
  itself; see [`dropped_address_count`](#dropped_address_count)

`status` is `ready` | `not_indexed` | `indexing` | `stale`.

On `not_indexed`, **every count is null, never zero** — the examination counts
included. Zero would read as "complete" and terminate a review loop on a binary
nobody has looked at, which is the precise failure this store exists to prevent. Treat any non-`ready`
status as "cannot conclude", never as "done".

`stale` means the analysis cache this ledger counted has been evicted. It still
returns the last known counts — they are the best available truth and they
satisfy every invariant above — but they are not current, so they must not
settle a closure decision. The rule for a consumer asserting invariants:
assert whenever `total is not None`, not only on `ready`.

`indexing` is reserved; indexing is synchronous today and never returns it.

There is deliberately no `reviewed_list` on this response — an 885-entry array
on every poll saturates a model's context. Use `get_next_unreviewed`.

### `get_next_unreviewed(binary_id=None, count=20, scope="in_scope", binary_path=None, only_examined=False)`

Ordered by ascending numeric address. A client that crashes mid-batch and
re-calls gets the same head of the queue, and makes forward progress once those
are marked. `functions: []` with `remaining_after: 0` is the terminal
condition — but only when `status == "ready"`.

`scope="all"` includes thunk / library / unreachable functions. They stay
retrievable precisely so an under-counted scope cannot hide work.

`only_examined=True` narrows to the machine-flagged leads — see
[the lead queue](#the-lead-queue).

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

The rule, stated for the operator: **a function is marked reviewed only if its
body — or a semantic analysis of that specific function — was returned to the
caller.** Never merely because the server read or produced its pseudocode
internally.

"Body" means code, not merely a non-empty string. Ghidra emits bodies that are
only a banner comment (`/* WARNING: Globals starting with '_' overlap … */`)
when it declines to decompile, and those are still returned to the caller but do
not mark — showing a remark about a function is not showing the function. The
test is a brace or a statement terminator, which keeps genuine empty stubs
marking: `void FUN_140137c58(void) { return; }` is real, reviewable code, and
http.sys has two of them. Across the 18500 pseudocode bodies in the cached
corpus none lack both characters, so nothing real is excluded.

So `analyze_binary` decompiles the whole binary and marks nothing;
`decompile_function` on a structural cache runs a targeted Ghidra decompile
internally and marks only the function you asked for, which is also the one you
get back; `batch_decompile` marks only what it actually printed.

Marking is idempotent: re-decompiling does not double-count, and `reviewed_at`
/ `reviewed_by` record the *first* tool that marked it and are never
overwritten.

Use `mark_function_reviewed` for work done outside binary-mcp — a Ghidra GUI
session, objdump, a debugger — and to attach a findings note.

None of this changes for a machine pass, because a machine pass does not mark
reviewed at all. It records on the separate axis below.

## Examination: the second axis

A machine pass is not a review, and the ledger says so on a separate axis.

| | claim | moves `reviewed` / `remaining` | recorded by |
|---|---|---|---|
| `reviewed` | somebody read this function's body | yes | the four auto-markers, `mark_function_reviewed` |
| `examined` | a machine pass produced a per-function judgement about it | **never** | `diff_binaries`, `mark_functions_examined` |

The two are **orthogonal**, not ordered. A function can be examined and
unreviewed (a lead nobody has read), reviewed and unexamined, both, or neither.
`examined` never enters `reviewed`, never shortens `remaining`, and never
removes a function from `get_next_unreviewed`.

This exists because the alternative was a choice between two lies. A diff that
pairs 5,958 functions has reviewed none of them, so marking them reviewed
inflates the denominator by thousands, silently, at exactly the scale where
nobody can audit it — and marking nothing loses the fact that a pass ran at
all, which is why script-driven diff work used to be invisible here. The honest
answer is a column that says what actually happened.

Three kinds, and the vocabulary is closed:

| `kind` | what it claims |
|---|---|
| `diff` | paired against a twin by a binary-diff run and its delta scored; the body was not necessarily read |
| `sweep` | surfaced by a whole-binary pattern sweep (sink extraction, lock analysis, regex scan) — a hit, not a reading |
| `external` | examined by a machine pass outside binary-mcp — a script driving the caches directly, BinDiff, Diaphora |

An unrecognized `kind` is refused rather than stored. Free-form values let a
caller invent something that reads like a review (`"audited"`, `"cleared"`) and
park it in a field the counts do not police.

### Counts

`examined` and `examined_in_scope` sit beside the six, and are additive: the
six are unchanged, `remaining == total - reviewed` still holds exactly, and a
consumer mirroring only the six keeps working untouched.

`examined_unreviewed` is the number that drives work — the machine found a
reason to look at these and nobody has. `examined_by_kind` breaks the total
down, always carrying every known kind including the zeros, so a consumer
reading `breakdown["diff"]` never has to guard for a key that vanished when its
count dropped.

The invariants are bounds, never subtractions: `examined <= total`,
`examined_in_scope <= min(examined, in_scope_total)`, and
`examined_unreviewed <= remaining`. That last one is the useful tripwire — every
examined-and-unreviewed function is by definition one of the unreviewed ones, so
exceeding `remaining` means the examination set has acquired an address the
ledger does not have.

A binary showing `examined == total` and `reviewed == 0` has been entirely
machine-touched and entirely unread. That is a real and common state after a
diff, and the counts must be able to say it.

### The lead queue

`get_next_unreviewed(only_examined=True)` narrows the worklist to functions a
machine pass already flagged — read it as "what did the diff tell me to look at
that I haven't looked at". It is a **narrowing filter, not a shorter path to
closure**: emptying it means the leads are read, not that the binary is. The
response therefore always carries `remaining_unfiltered` alongside
`remaining_after`, so an empty lead queue cannot be mistaken for a finished
binary the way an empty unfiltered queue legitimately can.

### `diff_binaries`

`diff_binaries` records `kind="diff"` for **the MODIFIED entries only**, on both
binaries' ledgers — each side to its own record, since the ledger is keyed by
the sha256 of the file's bytes and cross-writing would land phantom addresses in
a ledger they do not exist in.

Only MODIFIED, because those are the ones the tool actually analyses per
function: it scores the bounds-check, stack-cookie, caller-count and size deltas
and extracts the first changed line for each. ADDED and REMOVED are single-sided
— a bucket, no pair, no delta — and the unchanged pairs are the ones it
concluded nothing happened to. Recording either would inflate the examination
axis with functions nothing analysed, which is the same dishonesty as inflating
the review axis, one column over.

The report header states what was written. `record_examination=False` gives a
dry run against a ledger you do not want touched, and coverage failure is
swallowed — a broken ledger must never cost you the diff.

### Bulk import

`mark_functions_examined` is the import path for a pass that ran outside the
server: a script driving the Ghidra caches directly, BinDiff, Diaphora, an
external sink extractor.

Its cap is 20000 addresses per call, far above `mark_function_reviewed`'s 500,
because the two are bounded by different things — a worklist batch has to fit in
a model's context, whereas an import is a machine pass reporting what it touched
and is only ever read back as a count. A whole-binary diff of a
14000-function DLL has to fit in one call: sharding it means a partial failure
leaves the ledger half-written with no way to tell.

For the same reason the response reports `requested` / `marked` / `already` /
`unknown` as **counts, not lists**, with up to ten unknown addresses echoed in
`unknown_sample` — enough to diagnose the usual cause (addresses taken from the
wrong side of the diff, or from a rebased image) without making the address dump
the largest thing in the payload.

Set `note` — `"lock/sink candidate from the KB5044273 twin-pair diff"` is what
makes the record auditable six weeks later, and it is carried on
`get_next_unreviewed` entries as `examination_note`.

Marking is idempotent and the first examination wins for `examined_at`,
`examined_by` and `examination_kind`: re-running a diff does not rewrite when a
function was first flagged. An explicit `note` always lands, so a later run can
update why.

## Scope, and what it cannot see

Scope is computed by a forward BFS over the `called_functions` edges already
materialized in the analysis cache. No Ghidra run is involved.

**What the walk actually decides is `scope_reason`, not membership.** Because
unreached functions are promoted to roots until the residual is empty (below),
every function that is not *mechanically* excluded ends up in scope. The
identity holds exactly:

```
in_scope_total == total - (thunks + externals + FID-library matches)
```

Verified on all 29 cached binaries — chakra 25026−78=24948, jscript9
18065−73=17992, http.sys 4422−11=4411, bindflt 256−8=248. So do not read
`in_scope_total` as "the reachable subset": it is "the not-obviously-skippable
subset", and the call graph only explains *why* each function is there.

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

"No direct caller" is not sufficient on its own, and the first implementation
got this wrong. Every member of a call cycle has a direct caller — itself, or
its partner — so a cycle reached only indirectly was never promoted, the walk
could not enter, and the entire subtree below it fell out as
`excluded:unreachable`. That is a shrink. On the cached corpus it was dropping
`HttppParseUtf16Sequence` and `UxDuoParseUnknownFragment` from http.sys and the
whole chakra garbage collector — and 100% of that bucket was a false exclusion,
not one genuine orphan across 10 binaries. After the layered walk settles the
residual is now promoted to roots (`reachable:cycle_root`) until a fixpoint.
Because that fixpoint drains the residual *entirely*, `excluded:unreachable` is
now structurally unreachable rather than merely rare — the loop cannot exit
while any non-excluded function lacks a reason. The branch that produces it is
kept deliberately, as a tripwire: if a future change stops the residual
draining, the failure is toward a **smaller** denominator, so it must surface in
the counts and in `scope_description` instead of being folded in silently.

The practical consequence: scope leans almost entirely on the address-taken
roots, so `in_scope_total` lands close to `total` and the only real reduction is
the thunk/library set. This is not driver-specific — bindflt (one export)
reports 248 of 256, and jscript9 (98 exports) reports 17992 of 18065, the same
~0.4% reduction. That is the honest number, not a tighter one obtained by
dropping the indirect surface.

### `dropped_address_count`

How many functions the analysis cache listed that are **missing from `total`**
because `canon_addr` could not parse their address (Ghidra `EXTERNAL:` pseudo-
addresses, anything malformed). It is `0` on every binary in the cached corpus;
the current extractor does not emit unparseable addresses.

A non-zero value means the denominator under-counts the binary by that much, and
no completion claim should rest on it. `scope_description` carries an explicit
warning too. If *every* address fails to parse the tool reports `not_indexed`
with null counts rather than `ready` with six zeros — six zeros is the
documented terminal condition, and reporting it for a binary nobody read is the
exact failure this store exists to prevent.

The count is also cross-checked: `total + dropped_address_count` must equal
`source_function_count`, which was recorded from the analysis cache's own
function list. A record that fails it is rebuilt. This is the one count check
that is not a restatement of its own arithmetic — the remaining/total/reviewed
relations are derived and asserted a few lines apart, and cannot see a `total`
that silently lost functions.

Note that a genuinely non-zero drop is deliberately **not** a rebuild trigger:
a binary that really does carry unparseable addresses would then re-index —
decompressing the whole analysis cache — on every status poll, forever,
producing the identical record each time.

`remaining_in_scope == 0` therefore means the in-scope worklist is finished,
**not** that the binary is. Full closure still consults `remaining`.

`scope_version` records the method (`fwd-bfs-v2`). It changes whenever scope
logic changes, and a consumer should invalidate its mirror when it does. It
is also the rebuild trigger: a stored record carrying an older string is
re-indexed on the next status query, marks preserved. `v1` is the pre-
fixpoint walk described above, and any record still stamped with it is
carrying that shrunken scope until it is rebuilt.

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
itself when the analysis cache grows (an incremental run), when `scope_version`
changes, when `schema_version` is older than the current one, or when the
record's own numbers do not add up — **review marks, examinations, timestamps
and notes are preserved across a rebuild.**

Examinations survive on their own terms, not the review mark's. The state worth
preserving across an incremental re-analysis is precisely a diff-flagged lead
nobody has read yet, and that is the state where `reviewed` is false.

### Versioning, and what happens to a record we cannot read

Two independent version stamps:

- `schema_version` — the on-disk layout. Validated on read.
- `scope_version` — how scope was computed. Any mismatch rebuilds.

The current `schema_version` is **4**; the minimum readable is 1. A v2 record
cannot say a function was machine-examined, so every function in one reads as
never-examined. That is the safe direction — it under-states the leads rather
than over-stating the reviews — so v2 records are read and rebuilt with an empty
examination set, review marks preserved. A v3 record is rebuilt once to
acquire `source_index_count` — see below.

### The staleness probe compares like with like

`ProjectCache` writes `function_count` into `<sha>.meta.json` as
`len(_build_function_index(data))` — a dict keyed on the raw address, so a
function with a falsy address vanishes and duplicates collapse. The record
stores `source_index_count`, derived exactly the same way, and the probe
compares those two.

It used to compare the meta value against `source_function_count`, which counts
the raw function list. Those are different quantities, and on a binary with a
duplicate address or an address-less function they differ *permanently* — so
the probe read stale on every status poll and re-indexed forever,
decompressing the whole analysis cache each time. `source_function_count`
remains the honest denominator cross-check
([`dropped_address_count`](#dropped_address_count)); it is simply not what the
cheap probe compares.

| Stored value | Behaviour |
|---|---|
| `schema_version` older than current, ≥ the minimum readable | layout is a subset we can still parse, so the record is read and rebuilt, **marks preserved** |
| `schema_version` newer than current, non-integer, or absent | refused. The tool reports `not_indexed` with null counts, and re-indexes from the analysis cache with everything unreviewed |
| `scope_version` different in either direction, future included | rebuilt under current scope semantics and re-stamped with the current string |

Refusing a *future* layout rather than best-effort parsing it is deliberate:
fields this reader does not know about may be what make the counts mean what
they say, and the per-entry coercion (`bool(entry.get("reviewed"))`) would turn
anything unrecognized into a confident `False`. Losing marks is the safe
direction — it asks for work to be redone rather than claiming work that was
never done.

The scope downgrade is silent by design but detectable: the consumer reads
`scope_version` back off the payload, and it will have changed.

## Resetting a contaminated denominator

Marks are preserved aggressively, and auto-marking is silent. Together those
make one accident easy: a scripted sweep, a bulk `mark_function_reviewed`, or a
tool run against the wrong path leaves a binary recorded as reviewed that nobody
read. That record is worse than having none — the next campaign polls it, sees
`remaining_in_scope: 0`, and stops.

`reset_coverage` is the way out. It is deliberately a tool and not a documented
`rm`: a glob delete in the cache directory is unreviewable and takes the
neighbouring binaries with it.

| Call | Effect |
|---|---|
| `reset_coverage(binary_path=...)` | clears every mark on both axes; keeps the stored function list and scope exactly as built. |
| `reset_coverage(binary_path=..., clear_reviewed=False)` | clears only the examinations. |
| `reset_coverage(binary_path=..., clear_examined=False)` | clears only the review marks. |
| `reset_coverage(binary_path=..., drop_index=True)` | deletes the side-car, then rebuilds it from the current analysis cache under current scope logic. **Refused when there is no analysis cache to rebuild from** — see below. |

The two axes get independent flags because they contaminate independently: a
diff pointed at the wrong pair floods the examinations while the reviews stay
honest, and a bad review sweep leaves the examinations perfectly good. Clearing
one must not cost the other. The response reports `cleared` and
`cleared_examined` separately.

With the analysis cache present, both return `status: "ready"` with
`reviewed: 0` and the denominator intact. `drop_index=True` does not leave the
binary unindexed: the record is rebuilt on the spot, and even if it were not,
the next status query re-indexes automatically.

**Without the analysis cache, `drop_index=True` is refused.** That is not a
hypothetical state: `ProjectCache.invalidate` evicts the analysis and
deliberately spares this side-car, which is exactly how a ledger ends up
`stale`. A `stale` record still carries the last known counts — it is the only
surviving account of what was reviewed — and dropping it there is
unrecoverable. The refusal keeps it and points at the two ways forward: re-run
`analyze_binary` to restore the rebuild source, or reset without `drop_index`
to clear the marks while keeping the denominator.

Every `reset_coverage` response carries every count key, null when no record
could be read. An **omitted** key is not a null: a consumer reading
`payload.get("total", 0)` off a response that dropped the key lands on `0`, and
`0` reads as "complete" — the same false completion the null-not-zero rule
exists to prevent, arrived at through the client's default instead of the
server's value.

So the difference is not "how much is deleted", it is **which scope survives**.
The default keeps the scope as it was computed, whenever that was; the drop
recomputes it under the current `scope_version` and the current contents of the
analysis cache. Prefer the default: clearing marks unlearns the claim that
functions were read while keeping the denominator you already trust. Reach for
`drop_index=True` when the index itself is suspect — built under scope logic you
no longer trust, or predating an incremental re-analysis that added functions.

The response reports `cleared` (how many marks were removed) so the operator
sees the size of what was undone. Resetting a binary with no record is an error,
not a silent no-op — it usually means the wrong `binary_id`.
