# Linux dynamic analysis via GDB/MI — review of issue #7 and implementation plan

Status: **planning only, nothing implemented.** This document reviews
[issue #7](https://github.com/Sarks0/binary-mcp/issues/7) ("Support Linux
debugging via GDB backend"), records what was verified empirically, and
proposes a phased plan.

Every MI claim below was executed against **GNU gdb 15.1 (Ubuntu
15.1-1ubuntu1~24.04.1)** on x86-64 with purpose-built PIE and non-PIE ELF
targets. Where a claim in the issue was checked and holds, it says so; where
it does not, the correction is given with the observed output.

---

## 1. Verdict

The proposal is sound and the backend choice is right. `gdb
--interpreter=mi2` over stdio is the correct automation surface, the
`Debugger` ABC really is the right seam, and every MI command in the issue's
mapping table exists and behaves as described on GDB 15.1.

Three things need to change before implementation starts:

1. **The scope estimate is off by roughly an order of magnitude.** The issue
   frames this as "implement the `Debugger` ABC + thin platform-dispatch
   additions". The ABC is 14 methods
   (`src/engines/dynamic/base.py:22`); `X64DbgBridge` exposes **159 public
   methods** and `dynamic_tools.py` registers **159 MCP tools** across 9,210
   lines. Implementing the ABC buys parity with about 8% of the Windows
   dynamic tier. That is still worth doing — but it should be planned and
   announced as an MVP, not as parity.
2. **The bridge cannot be request/response.** The x64dbg bridge is
   synchronous HTTP (`src/engines/dynamic/x64dbg/bridge.py`). GDB/MI is not:
   with `mi-async on`, `-exec-interrupt` returns `^done` *immediately* and
   the `*stopped` record arrives later, unsolicited. The GDB bridge needs a
   reader thread and an async-record queue from day one. Retrofitting that
   later means rewriting the bridge.
3. **There is a live RCE surface that the issue treats as a footnote.**
   Verified below: `-interpreter-exec console "shell id"` runs as the MCP
   server user, and `startup-with-shell` is **on by default**, so target
   `args` are shell-expanded. The allowlist is not a nice-to-have.

Recommended framing: **Phase 1 is an MVP that makes Linux ELF triage
possible, not x64dbg parity.**

---

## 2. Corrections to the issue

### 2.1 Platform gating — the stated pattern does not exist for x64dbg

The issue says gating should follow "the existing WinDbg pattern … exactly as
`windbg/bridge.py` does in reverse."

- WinDbg does gate, but at **call time, per tool**: `_is_windows()` at
  `src/tools/windbg_tools.py:37` is checked in each tool body, returning
  `_PLATFORM_MSG` (~9 call sites), plus a bridge-level guard at
  `src/engines/dynamic/windbg/bridge.py:1591`.
- **x64dbg has no platform gate at all.** `grep -n "platform" src/tools/dynamic_tools.py`
  returns only comments about the Windows *ABI*. `register_dynamic_tools` is
  called unconditionally from `src/server.py:5762`.

So today a Linux user is shown 159 `x64dbg_*` tools, every one of which fails
with a connection error rather than a platform error. Adding ~30 `gdb_*`
tools on top means a Linux session advertises ~200 dynamic tools of which
~30 can work, and a Windows session ~180 of which ~30 cannot.

**Recommendation:** make engine registration platform-aware in `server.py`
(one `if` per engine, overridable by a `BINARY_MCP_ENGINES` env var for
remote/cross-platform bridge setups). This is a small change that pays for
itself immediately and is arguably worth doing as a standalone PR before
any GDB work lands.

### 2.2 Drop macOS from the initial scope

The issue proposes gating on "non-Linux/non-macOS". GDB on macOS is
effectively unusable for this purpose — it needs a self-signed
code-signing certificate and taskgated entitlements, and there is no
Apple-Silicon support. `lldb-mi` was unbundled from LLDB and its standalone
repo is unmaintained.

**Recommendation:** gate Phase 1 to **Linux only**. macOS should be a
separate issue targeting the LLDB **Python API** (not MI) behind the same
`Debugger` ABC — the issue's own alternative #2, which is the right call for
macOS but a different piece of work.

### 2.3 `debug_set_breakpoint(address="0x401236")` is a non-PIE assumption

The worked example in the issue passes a raw Ghidra-style address. Verified
on a PIE target: the same breakpoint reports `addr="0x00000000000011d4"`
before `-exec-run` and `addr="0x00005555555551d4"` after — GDB relocates
symbolic breakpoints itself, but `-break-insert *0xADDR` with a static
address does not get that treatment.

Nearly all modern Linux malware is PIE. The existing rebase helper,
`_resolve_function_to_runtime` (`src/tools/dynamic_tools.py:490`), computes
`runtime = static - image_base + module_base` and falls back to Windows image
bases (`0x400000`, `0x10000000` for DLLs) when the Ghidra cache has none.
For ELF the equivalent is: `ET_DYN` → link base 0, load base from
`info proc mappings` or the `=library-loaded` `ranges` field; `ET_EXEC` →
link base is the real base and no rebasing applies.

**Recommendation:** the GDB engine must own ELF-aware rebasing, and every
address-taking tool should accept `"0x401236"` (static, rebased) vs
`"*0x555555555236"` (runtime, literal) with an explicit flag rather than
guessing. `pyelftools` is already a hard dependency, so reading `e_type` and
`p_vaddr` costs nothing.

### 2.4 `trace_syscalls()` is not a thin wrapper

Verified: `catch syscall openat` works and MI reports it in structured form —

```
*stopped,reason="syscall-entry",disp="keep",bkptno="1",syscall-number="257",
  syscall-name="openat",frame={...},thread-id="1",stopped-threads="all"
```

That is better than expected, but four things stand between it and the
strace-like output the issue shows as "expected output":

- **Two stops per syscall.** `syscall-entry` and `syscall-return` are
  separate events that must be paired to produce `openat(...) = 3`.
- **No argument decoding.** The frame args GDB prints are the *libc wrapper's*
  C arguments, and only when symbols are present. Raw syscall args must be
  read from the SysV syscall ABI registers (`rdi, rsi, rdx, r10, r8, r9`;
  `rax` for the return), with string arguments dereferenced by hand.
- **Loader noise.** The run above tripped `openat("/etc/ld.so.cache")` before
  reaching `main`. Filtering pre-`main` dynamic-linker syscalls is required or
  the trace is unreadable.
- **Cost.** Every syscall becomes two ptrace stops.

**Recommendation:** ship a curated decoder for ~25 syscalls of interest
(`execve, openat, read, write, connect, socket, clone, ptrace, mmap,
memfd_create, unlink, chmod, …`) and be explicit in the tool docstring that
it is not strace. A separate `strace -f` shell-out tool is a cheaper way to
get a full, correct trace and is worth considering alongside — it just is not
the same tool.

### 2.5 `~860 x64dbg/WinDbg references` — accurate, but it is the wrong metric

`grep -o "x64dbg" src/tools/dynamic_tools.py | wc -l` → 868, so the number
checks out. But most are the `x64dbg_` tool-name prefix and bridge accessor
calls, not Windows-semantics assumptions. The genuinely Windows-*semantic*
work is much narrower and is listed in §5.3.

### 2.6 Missing from the issue

- **`attach` is not in the plan.** `x64dbg_attach` exists
  (`bridge.py:567`); the GDB equivalent is `-target-attach` and it is
  constrained by `/proc/sys/kernel/yama/ptrace_scope` (commonly `1`, which
  blocks attaching to non-descendants) and, in containers, by
  `CAP_SYS_PTRACE`. Both need a preflight check with an actionable error.
- **No MI parser file.** The proposed file list is
  `{__init__.py, bridge.py, commands.py}`. MI output is a real grammar —
  nested tuples and lists, C-string escaping, four record classes. It needs
  its own module. It is also the one piece that is pure, platform-independent
  and fully unit-testable, which makes it the most valuable thing to build
  first.
- **Env var naming.** The issue proposes `BINARY_MCP_GDB_PATH` /
  `BINARY_MCP_GDB_TIMEOUT`. Existing per-engine keys are unprefixed
  (`GHIDRA_HOME`, `X64DBG_BRIDGE_URL`, `X64DBG_TIMEOUT`, `WINDBG_TIMEOUT`);
  `BINARY_MCP_*` is used for cross-cutting concerns. `GDB_PATH` / `GDB_TIMEOUT`
  matches the engine convention. Either way they must be added to
  `CONFIG_KEYS` in `src/utils/config.py:174` or they will not appear in
  config status output.

---

## 3. Security findings (all verified)

These are the highest-priority items in the whole plan.

| # | Finding | Evidence | Mitigation |
|---|---|---|---|
| S1 | `-interpreter-exec console "shell …"` is arbitrary command execution as the MCP server user | Ran `shell id` → `uid=0(root) gid=0(root)` | Token allowlist modelled on `src/engines/dynamic/windbg/allowlist.py`; deny `shell`, `!`, `python`, `pi`, `source`, `define`, `set logging`, `add-auto-load-safe-path`, `compile`, `guile` |
| S2 | `python` is enabled in stock GDB | Ran `python print(1+1)` → `2` | Same allowlist; also start with `--nx` |
| S3 | `startup-with-shell` is **on by default** — target argv goes through `/bin/sh -c` | `show startup-with-shell` → `Use of shell to start subprocesses is on.` | `-gdb-set startup-with-shell off` in the connect sequence, before any `-exec-run` |
| S4 | Console commands can block on a confirmation prompt | `kill` → `Kill the program being debugged? (y or n) [answered Y; input not from terminal]` | `-gdb-set confirm off`; every MI read must be deadline-bounded regardless |
| S5 | `.gdbinit` / auto-load from the sample's directory | `show auto-load safe-path` → `$debugdir:$datadir/auto-load` (restrictive on this build, **but distro-dependent**) | Launch with `--nx`; explicitly `-gdb-set auto-load off`; never `add-auto-load-safe-path` |
| S6 | **The server executes the malware.** x64dbg is analyst-driven in a GUI; here the MCP server spawns the sample itself | Design-level | Documented isolation requirement (VM/container, no host network), and a `GDB_ALLOW_EXEC` opt-in gate so live execution is never the accidental default |

S6 deserves emphasis. Nothing in the repo today runs an untrusted sample —
Ghidra, pefile and ILSpyCmd are all static, and x64dbg/WinDbg are attached to
a debugger the analyst already started. This feature makes the MCP server a
malware launcher. That is a legitimate thing for this tool to do, but it is a
new posture and should be an explicit, documented, opt-in one. The
`lab-environment` guidance (FlareVM/Kali-style isolation) applies directly.

---

## 4. Verified MI behaviour

Confirmed working exactly as the issue's mapping table describes:
`-file-exec-and-symbols`, `-break-insert` (symbolic and `*0xADDR`),
`-exec-run`, `-exec-continue`, `-data-list-register-values x`,
`-stack-info-frame`, `-data-read-memory-bytes`, `-data-evaluate-expression`,
`-data-disassemble -s $pc -e $pc+16 -- {0,2,3}` (all three modes still work on
15.1 despite modes 2/3 being deprecated in GDB 12), `catch syscall`.

Behaviours that shape the design:

- **Async is mandatory for `pause()`.** With `-gdb-set mi-async on`,
  `-exec-interrupt` returned `^done` while the inferior was still running; the
  `*stopped,reason="signal-received",signal-name="SIGINT"` record arrived on a
  later read. Without `mi-async on`, GDB accepts no commands while running.
  → the bridge needs a reader thread, a correlation map keyed by MI token, and
  a separate async-event queue.
- **A SIGINT pause is indistinguishable from a real target SIGINT** by
  `reason` alone. The bridge must remember that it asked.
- **Registers come back numbered, not named.** `-data-list-register-values x 0`
  → `{number="0",value="0x1"}`. On x86-64: 0=rax, 4=rsi, 5=rdi, 16=rip.
  → cache `-data-list-register-names` once per connect and map.
- **`=library-loaded` carries `ranges={from,to}`** — this is the module list
  source, the analogue of `X64DbgBridge.get_modules()` (`bridge.py:966`), and
  it also supplies the PIE load base for §2.3.
- **GDB disables ASLR by default.** Reproducible addresses (`0x5555…`) —
  helpful for analysis, but worth surfacing in tool output so an analyst does
  not mistake them for a real-world run.

Reproduction scripts used for the above are not committed; they are three
short `subprocess`/`select` drivers against `gdb --interpreter=mi2 -nx -q`
and are trivially reconstructed from the observations here.

---

## 5. Proposed implementation

### 5.1 Module layout

```
src/engines/dynamic/gdb/
    __init__.py
    mi_parser.py      # MI grammar -> dict. Pure, no I/O. Build and test FIRST.
    mi_session.py     # subprocess + reader thread + token correlation + event queue
    allowlist.py      # console-command validator (mirrors windbg/allowlist.py)
    bridge.py         # GdbBridge(Debugger) - the 14 ABC methods + ELF rebasing
    commands.py       # high-level workflows (mirrors x64dbg/commands.py)
    error_logger.py   # subclass of dynamic/base_error_logger.py
src/tools/gdb_tools.py    # MCP tool registrations, gated to Linux
```

**Build `mi_parser.py` first and alone.** It is pure, needs no GDB installed,
is fully testable in CI on all three platforms, and de-risks the rest. The
fixture-driven style of `tests/test_windbg_parser.py` is the model.

**`pygdbmi` (MIT, v0.11.0.0, cs01/pygdbmi) is a viable alternative** to
hand-writing the parser. Trade-off: it removes ~300 lines and a class of
escaping bugs, against a new runtime dependency in a project that currently
keeps them to seven. Its `GdbController` should *not* be used regardless — it
is synchronous and would reintroduce the problem in §2 item 2; only
`pygdbmi.gdbmiparser` is of interest. **Maintainer decision needed.**

### 5.2 Phasing

**Phase 0 — prerequisite, independently useful (small)**
Platform-aware engine registration in `server.py` per §2.1. Ships on its own;
fixes the existing Linux experience whether or not GDB work proceeds.

**Phase 1 — MVP, "can I triage an ELF sample" (the bulk)**
`mi_parser` + `mi_session` + `allowlist` + `GdbBridge` implementing all 14 ABC
methods, plus `attach`/`detach`, `disassemble`, `get_modules`, `step_out`,
`list_breakpoints`, `read_string`. ~18–22 MCP tools named `gdb_*` to match the
`x64dbg_*` / `windbg_*` convention. Security items S1–S6 are in scope for
Phase 1, not deferred.

**Phase 2 — analyst ergonomics**
ELF static↔runtime rebasing wired to the Ghidra cache (the ELF counterpart of
`_resolve_function_to_runtime`), PLT/libc symbol breakpoints (the counterpart
of the Windows API-import mapping), memory search, hardware/watchpoint
breakpoints (`-break-watch`), stack traces via `-stack-list-frames`.

**Phase 3 — syscall tracing**
`catch syscall` with the entry/return pairing and register-ABI decoding of
§2.4. Long traces belong in `src/engines/jobs.py`, as the issue correctly
notes.

**Out of scope, as the issue states:** Linux kernel debugging, pwndbg
integration, rr replay. Add: macOS/LLDB (§2.2).

### 5.3 The Windows assumptions that actually need porting

Not the 868 `x64dbg` string matches — these:

| Windows assumption | Location | Linux equivalent |
|---|---|---|
| x64 MS ABI arg registers `RCX, RDX, R8, R9` | `dynamic_tools.py:1869` | SysV: `RDI, RSI, RDX, RCX, R8, R9` (and `R10` for syscalls, not `RCX`) |
| Windows API → module map for breakpointing | `dynamic_tools.py:1559` | PLT/GOT entries and libc exports; `info functions`, `-symbol-info-functions` |
| Image-base fallbacks `0x400000` / `0x10000000` | `dynamic_tools.py:531-538` | ELF `ET_EXEC` real base vs `ET_DYN` base 0 + runtime load base |
| Privilege enable/disable | `dynamic_tools.py:8443,8477` | POSIX capabilities; realistically a no-op with a clear "not applicable" message |
| UTF-16 string reads for Windows APIs | `dynamic_tools.py:122` | UTF-8 default, UTF-16 opt-in |
| Anti-debug (PEB, NtGlobalFlag, heap flags) | multiple | `ptrace(PTRACE_TRACEME)` self-check, `/proc/self/status:TracerPid`, `LD_PRELOAD` detection, timing checks — a different technique set entirely, and its own follow-up issue |

### 5.4 Testing and CI

CI already runs `ubuntu-latest` (`.github/workflows/ci.yml`), so Linux
coverage is free. `gdb` is **not** preinstalled on the runner image.

- **Unit (all platforms, no GDB):** `mi_parser` against recorded fixtures —
  including the exact records captured in §4; `allowlist` against the S1/S2
  escapes; ELF rebasing against `pyelftools` on a checked-in tiny ELF.
- **Integration (ubuntu only, opt-in):** `apt-get install -y gdb` plus a
  `gcc`-built fixture in a `@pytest.mark.skipif(shutil.which("gdb") is None)`
  suite. Note GitHub runners have no Yama LSM (verified here: no
  `/proc/sys/kernel/yama/ptrace_scope`), so an attach test that passes in CI
  may still fail on a developer host where `ptrace_scope=1`. Test the
  preflight error path explicitly rather than assuming.
- The session-logging decorator pattern (`log_dynamic_tool`,
  `dynamic_tools.py:340`) should wrap the new tools so GDB activity lands in
  `UnifiedSessionManager` with `AnalysisType.DYNAMIC`, same as x64dbg.

---

## 6. Questions for the maintainer

1. **Scope acceptance** — is a ~20-tool MVP (not x64dbg parity) the right
   Phase 1? This is the main thing to settle before code is written.
2. **Phase 0 as its own PR?** Platform-aware registration is independently
   valuable and small.
3. **`pygdbmi` or a hand-written parser?** (§5.1)
4. **Env var naming** — `GDB_PATH`/`GDB_TIMEOUT` (engine convention) or
   `BINARY_MCP_GDB_*` as the issue proposes? (§2.6)
5. **Execution posture** — is opt-in-by-env-var (`GDB_ALLOW_EXEC`) the right
   default for S6, or should launching a sample be unrestricted once the user
   has installed a Linux debugging engine at all?
6. **Tool naming** — `gdb_*` (matches `x64dbg_*`/`windbg_*`) or the neutral
   `debug_*` from the issue's example, which would imply a cross-engine facade
   and a larger refactor?

---

## 7. References

- [Issue #7](https://github.com/Sarks0/binary-mcp/issues/7)
- `src/engines/dynamic/base.py` — the `Debugger` ABC (14 methods)
- `src/engines/dynamic/windbg/allowlist.py` — the model for §3's allowlist
- `src/tools/windbg_tools.py:37` — the existing platform-gate pattern
- `docs/x64dbg-architecture.md` — the analogous engine write-up
- [GDB/MI reference](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI.html)
