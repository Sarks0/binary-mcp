# Attaching analysis to an existing Ghidra project

By default `analyze_binary` imports the binary into a throwaway Ghidra project.
That is fine for a cold start, but it throws away anything you did by hand: if
you have been renaming functions and writing comments in the Ghidra GUI, a
fresh import knows none of it.

Attach mode reads *your* project instead. Function names, plate comments,
instruction comments and applied types all come across, so the analysis the
server reasons over is the one you have actually been building.

## Setup

Tell the server where your projects live:

```bash
# Linux / macOS
export GHIDRA_PROJECT_DIR=/home/me/ghidra_projects

# Windows (several directories: separate with ';')
set GHIDRA_PROJECT_DIR=C:\Users\me\ghidra_projects;D:\cases\projects
```

The server's own project directory (`<cache>/ghidra_projects`) is always
searched as well, so if you save GUI projects there you need not set anything.

## Use

```
list_ghidra_projects()
```

```
**Ghidra Projects**

Searched:
- `/home/me/ghidra_mcp_cache/ghidra_projects`
- `/home/me/ghidra_projects`

Found 2 project(s):

### okular.stage2  (user-owned)
- Location: `/home/me/ghidra_projects`
- Modified: 2026-09-07 14:22
- Size: 412.7 MB
- Programs: `/okular.exe`, `/types.gdt` [Data Type Archive]
```

Then analyze against it:

```
analyze_binary(binary_path="/samples/okular.exe", ghidra_project="okular.stage2")
```

```
**Read from Ghidra project 'okular.stage2'** (opened read-only)
- Functions with non-default names: 1183
- Functions carrying comments: 297
```

Every other tool (`decompile_function`, `get_xrefs`, `expand_callgraph`, ...)
reads from the analysis cache, so they all see your names and comments with no
further arguments.

### Picking a program

A project can hold several programs. By default the server processes the one
named after your binary's filename, which is how Ghidra names an imported
program. Override it when they differ:

```
analyze_binary(..., ghidra_project="cases", ghidra_program="okular_patched.exe")
analyze_binary(..., ghidra_project="cases", ghidra_folder="/stage2")
```

`ghidra_program` accepts Ghidra's `*` and `?` wildcards. Omit it (or pass `"*"`)
to take every program in the folder.

## The contract: the project is authoritative

A re-pull replaces what is in the analysis cache. Concretely:

| What | Survives a re-pull? |
|------|---------------------|
| Names and comments in the Ghidra project | Yes — they *are* the new cache |
| Notes from `add_note` | Yes — keyed by address |
| Review/coverage marks | Yes — keyed by address |
| Names from `rename_function` | **No** — replaced by the project's name |

`rename_function` writes only to the analysis cache; nothing writes back into
the `.gpr`. So a name you set through the server is provisional — the next
re-pull overwrites it with whatever the project calls that address. This is
deliberate: with two places to store a name, one has to win, and the project is
the one you can see and edit.

Both directions are reported rather than left to be discovered:

- `analyze_binary` says how many cache-only names it replaced, and names a few.
  Only names set through `rename_function` count -- renaming in the GUI and
  re-pulling changes the name at that address too, and reporting *that* as a
  loss would tell you to go and do what you just did.
- `rename_function` tells you the name is provisional when the cache came from a
  project, and points you at the GUI.

To make a name permanent, rename it in Ghidra and re-pull.

## Your project is never modified

Attach mode opens the project with `-process ... -readOnly -noanalysis`:

- `-readOnly` makes Ghidra discard every change on exit.
- `-noanalysis` skips the auto-analysis pass that would have produced them.

Both matter. Ghidra's `-process` mode re-runs auto-analysis unconditionally and
then *saves* the result back into the project, so without these flags a read
would quietly rewrite your work.

The server also never deletes a project it did not create. The cleanup that runs
on a Ghidra timeout or crash — which removes the `.gpr`, `.lock` and `.rep` — is
gated on the project living in the server's own managed directory.
`clean_cache(include_ghidra_projects=True)` likewise only touches managed
projects.

## Speed

An attach is much faster than an import: no binary import, no auto-analysis,
just JVM startup plus the extraction script. On a large binary that is roughly a
minute rather than the ten to fifteen a full analysis costs — fast enough to
re-pull whenever you have done a batch of annotation in the GUI.

## Troubleshooting

**"project is locked"** — Ghidra permits one holder of a project at a time, and
your GUI has it. Close the project in the Ghidra Front End (the application can
stay open) and retry. `list_ghidra_projects` flags locked projects. If a crash
left a stale lock, the error names the file to remove.

**"project not found"** — run `list_ghidra_projects` to see which directories
are being searched, and set `GHIDRA_PROJECT_DIR` if yours is not among them.

**"is not the same binary"** — the program in the project has a different
SHA256 from the file at `binary_path`. The analysis cache is keyed on the file's
hash, so caching this would file one binary's functions under another's. Either
pass `ghidra_program` to name the right program, or point `binary_path` at the
file the project was actually built from.

**"could not verify"** — the project records no SHA256 for the program, which is
normal for projects made by older Ghidra versions. The analysis is cached
anyway; confirm the program is the right one if anything looks unfamiliar.
