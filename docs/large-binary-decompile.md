# Large binaries: project reuse and targeted decompiles

The workflow this page is about: analyze a multi-MB DLL `structural` (fast, no
pseudocode), let the model pick targets from the function table, then decompile
those targets on demand.

That workflow used to have a hole in the middle. The structural pass was cheap
as advertised, but **every** targeted decompile that followed cost a full
re-analysis of the binary first — about seven minutes on a 17 MB, ~30K-function
DLL — to produce one function body. Decompiling twenty candidates meant twenty
re-analyses. The cache filled up with function *names* while the code stayed
one Ghidra run away, per function, forever.

## What was actually happening

Every invocation of `analyzeHeadless` was built the same way:

```
analyzeHeadless <projects> <name> -import <binary> -overwrite ... -postScript core_analysis.py
```

`-import ... -overwrite` re-imports the binary and re-runs Ghidra's whole
auto-analyzer suite. `keep_project=True` was already being passed, so the
analyzed project was *kept* — but nothing ever opened it again. The expensive
artifact was produced, saved, and then ignored on the next call.

## Project reuse

Ghidra can open a program that is already in a project:

```
analyzeHeadless <projects> <name> -process <program> -noanalysis -readOnly ... -postScript core_analysis.py
```

That skips the import and the auto-analysis, leaving only the work the script
was called to do. A targeted decompile drops from a re-analysis to one
decompile.

Reuse is not taken on trust. Each project carries an owner record at
`ghidra_projects/<project>.owner.json`, written **only** after a successful
import:

```json
{
  "project_name": "mpengine_1a2b3c4d",
  "binary_hash": "<sha256 of the binary>",
  "program_name": "mpengine.dll",
  "analyzed": true,
  "pdb_applied": false
}
```

A run reuses the project only when the record's `binary_hash` matches the
binary in hand and `analyzed` is true. Reuse is refused — and a normal import
runs — when:

| Condition | Why |
|---|---|
| `force_reanalyze=True` | the caller explicitly asked for the analysis to be redone |
| `processor` / `loader` given | those only take effect at import |
| `pdb_path` given | symbols are applied during import analysis |
| no owner record, or hash mismatch | the project may hold a different binary |
| `analyzed: false` and depth > shallow | the program was imported with `-noanalysis` |
| the reuse run produced no output | fall back to a fresh import, once |

If a reuse run comes back empty (half-deleted `.rep`, a Ghidra upgrade that
cannot open the older database), the owner record is dropped and the run
retries as an import. The worst case is the behaviour that existed before.

### Projects are keyed on content

Project names are now `<stem>_<hash8>` rather than the file stem alone. An old
and a new build of one DLL — the patch-diff case this server exists for — used
to share a single project, so switching sides re-imported every time, and a
project reused across that collision would have decompiled the wrong build.
Separate projects mean both sides stay warm.

Projects created by an older install (stem-named, no owner record) are never
reused; they are still cleaned up by `clean_cache(include_ghidra_projects=True)`.

## Targeted decompiles

Ghidra is now told exactly which entry points to process, via
`GHIDRA_TARGET_ADDRESSES`. In that mode the script:

- looks each address up directly instead of walking every function in the
  program (a 30K-function sweep to reach the one you asked for);
- skips the program-wide extractions — memory map, imports, exports, strings,
  data types — which are re-derived from a whole-program walk and were the
  bulk of what a "targeted" run spent its time on;
- writes no resume manifest, since the address list already *is* the work list.

The result is a delta that the server merges into the cache. The merge keeps
the program-wide fields the run deliberately skipped, and rebuilds the
reverse-xref indices from the merged function list.

> That last part was a real bug, not just an optimisation: the delta's xref
> index described only the function it processed, and the merge adopted
> top-level fields from the delta wholesale. So any targeted decompile replaced
> the binary's whole reverse-xref index with a one-function one, and
> `get_xrefs(direction="to")` answered "no callers" for everything until the
> next full analysis.

## Batching: `decompile_functions`

`decompile_function` is one function per Ghidra run. Even a fast run has fixed
costs (JVM start, project open), so a list of targets pays them repeatedly.

```
decompile_functions("/path/to/mpengine.dll", ["MpContainerOpen", "0x180447d30", "ParseHeader"])
```

The whole list rides one Ghidra invocation. Functions that already have
pseudocode are reported as warm and not re-decompiled, so re-invoking after a
partial run resumes cheaply. `wait=False` returns a `job_id` and runs the batch
in the background (see [jobs.md](jobs.md)).

`expand_callgraph` uses the same batching: each depth's frontier is one Ghidra
run instead of one per callee.

## Backfilling a structural cache

To fill in pseudocode for a whole binary that was analyzed structurally:

```
analyze_binary(path, analysis_depth="full", wait=False)
```

With a warm project this no longer re-imports or re-analyzes — it goes straight
to decompiling. That is still tens of thousands of decompiles on a large DLL,
so run it as a job; the per-function work is the irreducible part.

## Cost, roughly

For a 17 MB DLL with ~30K functions:

| Operation | Before | After |
|---|---|---|
| First `structural` analysis | ~7 min | ~7 min (unchanged — the import must happen) |
| Targeted decompile, 1 function | ~7 min | one decompile on a warm project |
| Targeted decompile, 20 functions | ~20 × 7 min | one run for the batch |
| `expand_callgraph`, frontier of 12 | 12 runs | 1 run |

The first analysis is unchanged by design: something has to import and analyze
the binary once. Everything after it stops paying for that again.
