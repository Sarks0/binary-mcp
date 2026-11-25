# Exploit-Mitigation & Build-Hardening Flags for an MSVC/CMake x64dbg Plugin DLL and a Localhost TLS Server EXE

Scope: MSVC (VS 2022, toolset v143), Windows 11 / Server 2025 era. Two native x64 (and x86 for the plugin) targets:
1. **Plugin DLL** `obsidian.dp64` / `.dp32` - a renamed `.dll` loaded into the **x64dbg.exe host we do not control**.
2. **Standalone server EXE** `obsidian_server.exe` - static CRT (`/MT`), Winsock + Schannel TLS, parses JSON from localhost.

Both process attacker-adjacent data. Current CMakeLists sets **no** mitigation or optimization flags.

---

## Control Flow Guard `/guard:cf` + `/GUARD:CF` - how it works, cost, DLL-into-host caveats

### Takeaway
CFG is a forward-edge CFI mitigation set **per-image** at build time; it works in a DLL regardless of whether the host EXE is CFG-aware, and it does **not** require x64dbg to opt in. It is safe to enable on the plugin - the only way a host could *reject* a non-CFG DLL is CFG "StrictMode," and x64dbg does not enable it. Enable `/guard:cf` (compiler) **and** `/GUARD:CF` (linker) on both targets.

### Cited Findings
- `/guard:cf` makes the compiler "analyze control flow for indirect call targets at compile time, and inserts code at runtime to verify the targets." It is **off by default** and must be explicitly enabled; disable with `/guard:cf-` (compiler) / `/GUARD:NO` (linker) - [MS Learn /guard](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard)
- Valid indirect-call targets are stored "in extra structures in the headers of your binaries"; a check is injected before every indirect call, and "If the check fails at runtime on a CFG-aware operating system, the operating system closes the program." - [MS Learn /guard](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard)
- To use CFG you must "pass `/guard:cf` to the compiler and `/GUARD:CF` to the linker." A single `cl` invocation forwards it to the linker; separate compile/link steps must set both. **`/GUARD:CF` also requires `/DYNAMICBASE`** (on by default). - [MS Learn /guard](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard)
- VS 2017+ also adds guards for `switch` jump tables. - [MS Learn /guard](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard)
- Cost: "There's a small runtime cost for CFG checks, but the compiler analysis attempts to optimize away the checks on indirect jumps that can be proven to be safe." CFG "doesn't fix the data corruption bugs" - it only makes exploitation harder. - [MS Learn /guard](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard)
- **Incompatible with `/ZI`** (Edit-and-Continue debug info) and `/clr`. - [MS Learn /guard](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard)
- Mixing is fine: "Code compiled by using `/guard:cf` can be linked to libraries and object files that aren't compiled by using the option. Only this code … has CFG protection." Microsoft recommends enabling it on all code you compile. - [MS Learn /guard](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard)
- **DLL into a non-CFG host:** "a mixture of CFG enabled and non-CFG enabled code will execute fine" but gaps in protection result if not all code enables it. CFG is marked per-image via the DLL characteristics flag. - [MS Learn: Control Flow Guard](https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard)
- **Host opt-in only matters for StrictMode:** the process-mitigation policy `PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY` has a `StrictMode` bit - "If TRUE, all DLLs that are loaded must enable CFG. If a DLL does not enable CFG then the image will fail to load." Can be turned on after start via `SetProcessMitigationPolicy`. - [MS Learn: PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_control_flow_guard_policy)
- **x64dbg itself does NOT enable CFG, CET, or ehcont** in its build. A grep of the current x64dbg master build config (`cmake.toml`, `cmake/VSFlags.cmake`, `CMakeLists.txt`) finds no `/guard:cf`, `/GUARD:CF`, `/CETCOMPAT`, or `/guard:ehcont`; release linking sets only `/DEBUG:FULL /INCREMENTAL:NO /OPT:REF /OPT:ICF` and compile sets `/MP /bigobj`. - source: cloned `github.com/x64dbg/x64dbg` `cmake/VSFlags.cmake` and `cmake.toml` (HEAD, Nov 2026). Repo: [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg)
- Verify: `dumpbin /headers /loadconfig` - "CFG-enabled binaries have `Guard` in the list of EXE or DLL characteristics, and Guard Flags include `CF Instrumented` and `FID table present`." - [MS Learn /guard](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard)

### Inferences
- Because x64dbg does **not** set CFG StrictMode, a CFG-enabled plugin DLL will load normally, and a non-CFG plugin would also load - so enabling CFG on the plugin **cannot break loading** into x64dbg. Enabling it is pure upside (it protects indirect calls *within the plugin's own code*, which is where the JSON/pipe parsing lives), independent of the host.
- CFG's protection on the plugin is only as strong as the OS enforcement of the plugin's own FID table; it still functions on a CFG-aware OS even inside a non-CFG host process, because enforcement is per-indirect-call using the target module's metadata.

### Gaps
- No exact published percentage for CFG runtime overhead from Microsoft (described only as "small"); independent figures typically cite low single-digit % but I did not find an authoritative current benchmark.

---

## CET / hardware shadow stack `/CETCOMPAT` - EXE vs DLL, and process-wide requirement

### Takeaway
`/CETCOMPAT` is a **linker** flag (x64 only) that sets a PE bit requesting kernel-maintained shadow stacks (ROP defense). It is appropriate for the **server EXE**. For the **plugin DLL it is governed by the host process's shadow-stack mode**: shadow stacks are a *process* property driven by the EXE. Marking the plugin DLL `/CETCOMPAT` is low-risk but its effect depends entirely on x64dbg - and **x64dbg is not CET-enabled**, so in practice the plugin runs without shadow-stack enforcement regardless. Critically, marking a DLL `/CETCOMPAT` when its code is *not* actually shadow-stack-clean could cause #CP faults if the host ever ran in strict mode - only mark it if the code is compatible.

### Cited Findings
- `/CETCOMPAT` "tells the linker to mark the binary as CET Shadow Stack-compatible"; `/CETCOMPAT:NO` marks it non-compatible; last one on the command line wins. "This switch is currently only applicable to the x64 architecture." Available from VS 2019. No programmatic equivalent. - [MS Learn /CETCOMPAT](https://learn.microsoft.com/en-us/cpp/build/reference/cetcompat)
- The flag "sets a bit in the PE header to request protection from the kernel for the executable"; when set and supported, "the Kernel will maintain shadow stacks throughout the runtime of the program." If the OS/hardware lacks support, "the PE bit is ignored." - [MS Tech Community: Understanding Hardware-enforced Stack Protection](https://techcommunity.microsoft.com/blog/windowsosplatform/understanding-hardware-enforced-stack-protection/1247815)
- Enforcement: "On every CALL instruction, return addresses are pushed onto both the call stack and shadow stack"; on mismatch "the processor issues a control protection (#CP) exception" and the kernel terminates the process. - [MS Tech Community](https://techcommunity.microsoft.com/blog/windowsosplatform/understanding-hardware-enforced-stack-protection/1247815)
- **Mixed modules - compatibility mode:** the user-shadow-stack policy defines a **compatibility mode** in which "only shadow stack violations occurring in modules that are considered compatible with shadow stacks (CETCOMPAT) are fatal." A module is compatible if "compiled with CETCOMPAT for binaries, or marked using `SetProcessDynamicEnforcedCetCompatibleRanges` for dynamic code." - [MS Learn: PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_user_shadow_stack_policy)
- **Strict mode:** "All shadow stack violations are fatal"; and it can "block loading: binaries that are not compiled with CETCOMPAT are blocked from being loaded into the process." Compatibility mode can be upgraded to strict at runtime but HSP cannot be downgraded/disabled via `SetProcessMitigationPolicy`. - [MS Learn: PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_user_shadow_stack_policy)
- A non-CETCOMPAT DLL in compatibility mode is *exempted* from fatal violations rather than disabling process-wide enforcement; the kernel walks the stack for the true return rather than terminating. - [Raymond Chen / The Old New Thing, 2024-10-16](https://devblogs.microsoft.com/oldnewthing/20241016-00/?p=110378)
- .NET's `apphost`/`singlefilehost` are built with `/CETCOMPAT` as an example of EXE adoption. - [MS Learn: CET support (.NET 9)](https://learn.microsoft.com/en-us/dotnet/core/compatibility/interop/9.0/cet-support)
- x64dbg does **not** set `/CETCOMPAT` (see grep result in CFG section). Repo: [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg)

### Inferences
- **For the server EXE:** apply `/CETCOMPAT`. Shadow stacks are a strong ROP mitigation, the EXE owns its process, and the cost is effectively zero where hardware/OS support is absent (bit ignored). Only requirement: don't do non-standard stack manipulation (hand-rolled fibers/unwinding) without shadow-stack-aware handling.
- **For the plugin DLL:** the premise "does it require the whole process to be CET-compatible, so marking is moot/harmful" is *partly* true. Shadow-stack enforcement is driven by the **host EXE's** policy; a DLL cannot enable shadow stacks on its own. Since x64dbg is not CET-enabled, the plugin gets no shadow-stack enforcement no matter how it's marked - so marking it `/CETCOMPAT` is **moot** today. It is **not harmful** as long as the plugin's code is genuinely shadow-stack-clean (standard prologue/epilogue, no custom unwinding), because `/CETCOMPAT` only *opts the module into fatal enforcement* if the host is ever in compatibility/strict mode. Recommendation: mark it `/CETCOMPAT` (honest, future-proof, zero cost while host is non-CET) **only if** the plugin does no unusual stack games; otherwise leave it unmarked.

### Gaps
- No source explicitly states x64dbg's runtime shadow-stack policy; inference is from its build config (no CET markings, dynamic CRT) - it almost certainly runs in the OS default (compatibility mode is opt-in via the EXE, which x64dbg does not request).

---

## ASLR `/DYNAMICBASE`, high-entropy ASLR `/HIGHENTROPYVA`, DEP/NX `/NXCOMPAT` - defaults & explicitness

### Takeaway
All three are enabled by default by the MSVC linker for modern targets, but set them **explicitly** on both DLL and EXE for auditability and to guarantee they are not accidentally lost (e.g. by stripped relocations). `/DYNAMICBASE` is a prerequisite for CFG and high-entropy ASLR.

### Cited Findings
- "By default, `/DYNAMICBASE` is enabled." Disable with `/DYNAMICBASE:NO`. `:NO` is unsupported on ARM/ARM64/ARM64EC. - [MS Learn /DYNAMICBASE](https://learn.microsoft.com/en-us/cpp/build/reference/dynamicbase)
- `/HIGHENTROPYVA` is on by default for 64-bit images and enables high-entropy (≥4 GB) bottom-up ASLR; "The `/DYNAMICBASE` option is required for the `/HIGHENTROPYVA` option to have an effect." Ignored for 32-bit images. - [MS Learn /HIGHENTROPYVA](https://learn.microsoft.com/en-us/cpp/build/reference/highentropyva)
- `/NXCOMPAT` "marks an executable as verified to be compatible with the Windows Data Execution Prevention feature." - [MS Learn: Linker options](https://learn.microsoft.com/en-us/cpp/build/reference/linker-options)
- Setting `/DYNAMICBASE` at build time does not *guarantee* runtime randomization (relocations can be stripped); tools report ASLR separately from the Dynamic Base bit. - [Trail of Bits: winchecksec](https://blog.trailofbits.com/2018/09/26/effortless-security-feature-detection-with-winchecksec/)

### Inferences
- Because these are defaults, the risk is silent loss rather than needing to turn them on. Set `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT` explicitly in `target_link_options` for both targets so BinSkim/winchecksec audits are green and so nothing (e.g. a stray `/FIXED` or stripped relocs) disables them. On x86 plugin builds, `/HIGHENTROPYVA` is ignored (harmless).

### Gaps
- The current `/NXCOMPAT` page did not surface an explicit "on by default" statement in search; MSVC has linked images `/NXCOMPAT` by default since VS 2005-era, but I could not pin a current primary-source sentence for the default. Treat "set it explicitly" as the safe guidance.

---

## Stack/security checks: `/GS`, `/sdl`, `/Qspectre`, `/guard:ehcont`, `/SAFESEH`

### Takeaway
`/GS` is on by default - keep it. Add `/sdl` (superset of stricter `/GS` + init), `/Qspectre` (negligible cost, needs the Spectre-mitigated runtime libs installed), and on **x64** `/guard:ehcont` (back-edge/SEH-continuation hardening that pairs with CFG/CET). `/SAFESEH` is **x86-only** and applies to the 32-bit plugin build only.

### Cited Findings
- `/GS` "detect[s] some buffer overruns that overwrite the return address," is **on by default**, and "does not protect against all buffer overrun security attacks." - [MS Learn /GS](https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check)
- `/GS` performance is workload-dependent: an older MS page calls the effect "negligible," while independent testing (Preshing) found "no effect" in some tests and a commenter reported ~10% in their suite; post-VS2008 heuristics are more extensive and `/GS:partial` can recover some performance. - [Preshing: The Cost of Buffer Security Checks](https://preshing.com/20110807/the-cost-of-buffer-security-checks-in-visual-c/); [Intel docs mirroring /GS behavior](https://www.intel.com/content/www/us/en/docs/fortran-compiler/developer-guide-reference/2025-0/gs-001.html)
- `/sdl` "enables additional security checks" including stricter `/GS` behavior and variable initialization, recommended for production. - [MS Learn: Avoiding Buffer Overruns](https://learn.microsoft.com/en-us/windows/win32/SecBP/avoiding-buffer-overruns)
- `/Qspectre`: using it "also changes the library paths to link the Spectre-mitigated runtime libraries. If these libraries aren't installed … the build system reports warning MSB8040." Mitigated static + DLL runtimes exist for a subset (startup code, vcruntime140, msvcp140, concrt140, vcamp140); MFC/ATL mitigated libs are a separate install. - [MS Learn /Qspectre](https://learn.microsoft.com/en-us/cpp/build/reference/qspectre)
- `/Qspectre` performance impact is "negligible" per the MSVC team; hot code can opt out via `__declspec(spectre(nomitigation))`; it is supported regardless of optimization level since VS2017 15.7 Preview 3. The heavier `/Qspectre-load` "stops speculation of all loads, so the performance impact is high." - [MSVC blog: Spectre mitigations in MSVC](https://devblogs.microsoft.com/cppblog/spectre-mitigations-in-msvc/)
- `/guard:ehcont` "generate[s] a sorted list of the RVAs of all the valid exception handling continuation targets," used at runtime for `NtContinue`/`SetThreadContext` instruction-pointer validation. **Off by default. Supported for 64-bit processes on a 64-bit OS only.** - [MS Learn /guard:ehcont](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-eh-continuation-metadata)
- ehcont relationship to CFG: it must be passed to compiler **and** linker; in a single `cl` build "The compiler also passes the `/guard:cf` option to the linker." It exists specifically to complement CET shadow stacks (the `__except` continuation target "isn't expected to be on the shadow stack"). Linker can emit `LNK2046/LNK2047` fatal errors or `LNK4291` warning if EH metadata can't be generated; `/Gy` (function-level linking / COMDATs) is needed for SEH COMDAT cases. - [MS Learn /guard:ehcont](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-eh-continuation-metadata)
- Verify ehcont: `link /dump /loadconfig` shows "EH Continuation table present" guard flag plus a "Guard EH continuation table" / count. - [MS Learn /guard:ehcont](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-eh-continuation-metadata)

### Inferences
- Practical guidance: enable `/guard:cf` together with `/guard:ehcont` on x64 (both to compiler and linker). On the x86 plugin build, use `/SAFESEH` (x86-only SEH validation) instead of ehcont, which is x64-only. `/Qspectre` is cheap insurance for a network-facing JSON parser; ensure the Spectre-mitigated libs component is installed in CI or the build fails with MSB8040.
- `/sdl` is a strict superset worth enabling on both; it turns some security warnings into errors and forces pointer/member initialization, which is valuable for parser code.

### Gaps
- No single authoritative current %-overhead for `/GS` or `/Qspectre`; sources describe both as "negligible" with workload-dependent exceptions.

---

## Performance/size: `/O2`, `/GL`+`/LTCG`, `/Gy`, `/OPT:REF,ICF`, and interaction with CFG

### Takeaway
Use `/O2` + LTCG (`/GL` compile, `/LTCG` link) and `/Gy` + `/OPT:REF,ICF` for speed/size; in CMake drive LTCG via `INTERPROCEDURAL_OPTIMIZATION` after `check_ipo_supported()`. LTCG is compatible with and actually *improves* CFG (whole-program view tightens the valid-target set); x64dbg itself uses `/OPT:REF /OPT:ICF`.

### Cited Findings
- CMake `check_ipo_supported()` (module `CheckIPOSupported`, CMake 3.9+) tests compiler IPO/LTO support; enable per target with the `INTERPROCEDURAL_OPTIMIZATION` property (or globally with `CMAKE_INTERPROCEDURAL_OPTIMIZATION`). Policy `CMP0069` must be `NEW`. Recommended pattern: check first, then set the property, warn on unsupported. - [CMake: CheckIPOSupported](https://cmake.org/cmake/help/latest/module/CheckIPOSupported.html)
- x64dbg's release link flags include `/OPT:REF` and `/OPT:ICF` (and `/INCREMENTAL:NO`), and compile uses `/MP` (multiprocessor) and `/bigobj`. - source: cloned `cmake/VSFlags.cmake`, [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg)
- CFG analysis "attempts to optimize away the checks on indirect jumps that can be proven to be safe" - i.e. more whole-program information (LTCG) lets more checks be elided. - [MS Learn /guard](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard)

### Inferences
- `INTERPROCEDURAL_OPTIMIZATION TRUE` on an MSVC target maps to `/GL` (compile) + `/LTCG` (link); the CMake IPO module is the portable, supported way to request it rather than hand-adding `/GL`/`/LTCG` (hand-adding `/GL` without `/LTCG` causes linker errors). The CheckIPOSupported page does not literally name the `/GL`/`/LTCG` mapping - treat the mapping as MSVC behavior, gated behind the support check.
- `/Gy` (function-level linking) is required for `/OPT:REF`/`/OPT:ICF` to fold/strip unused functions and is also needed by `/guard:ehcont` for SEH COMDAT cases - enable `/Gy` on both targets. `/O2` implies `/Gy`-friendly codegen but set `/Gy` explicitly.

### Gaps
- No primary source quantifying LTCG speedup for these specific binaries; benefit is standard MSVC whole-program optimization.

---

## Signing / Authenticode, `/INTEGRITYCHECK`, reproducible builds

### Takeaway
Authenticode-sign both binaries (defense-in-depth + user trust for a security tool). `/INTEGRITYCHECK` forces the loader to verify the signature but has real deployment friction (requires Trusted/Azure signing, and a plugin DLL forced-integrity may interact badly with the host) - treat it as **optional / EXE-only and test carefully**, not a default.

### Cited Findings
- `/INTEGRITYCHECK` "sets a flag, `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`, in the PE header … [that] tells the memory manager to check for a digital signature in order to load the image." Off by default. - [MS Learn /INTEGRITYCHECK](https://learn.microsoft.com/en-us/cpp/build/reference/integritycheck-require-signature-check)
- Forced-integrity user-mode PEs "must be signed using Trusted Signing (formerly Azure Code Signing)"; the flag is used for anti-malware/anti-cheat registration with Windows Security Center. - [MS Support KB5022661: Azure Code Signing](https://support.microsoft.com/en-gb/topic/kb5022661-windows-support-for-the-azure-code-signing-program-4b505a31-fa1e-4ea6-85dd-6630229e8ef4)
- Community reports show ordinary signed apps still failing to load under `/INTEGRITYCHECK` (stricter-than-Authenticode behavior) - anecdotal, not documented. - [OSR forum thread](https://community.osr.com/t/how-to-force-authenticode-verification-when-loading-a-user-mode-exe/57523)

### Inferences
- `/INTEGRITYCHECK` on the **plugin DLL** is risky: if forced integrity makes the loader refuse the module (e.g., signing chain not trusted on an analyst's isolated VM), **the plugin silently fails to load into x64dbg** - a hard warning. Prefer plain Authenticode signing (no forced-integrity bit) for the plugin; consider `/INTEGRITYCHECK` only for the EXE and only if you commit to Trusted Signing.
- Reproducible builds: no MSVC-specific primary source was gathered here; standard levers are `/Brepro` (deterministic timestamps) and pinned toolset - flag as a gap for the writer to confirm.

### Gaps
- Did not retrieve a primary source on MSVC `/Brepro` / reproducible-build guidance; note as unverified.

---

## Verification tooling: `dumpbin /loadconfig`, BinSkim, winchecksec

### Takeaway
Verify every mitigation with `dumpbin /headers /loadconfig` plus a scanner (Microsoft **BinSkim** for CI gating, Trail of Bits **winchecksec** for a quick report). Each mitigation maps to a specific header/load-config field.

### Cited Findings
- `dumpbin /headers /loadconfig`: CFG shows `Guard` in characteristics + `CF Instrumented`/`FID table present`; ehcont shows "EH Continuation table present." - [MS Learn /guard](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard); [MS Learn /guard:ehcont](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-eh-continuation-metadata)
- **BinSkim** is Microsoft's PE/ELF static-analysis tool that "validates compiler/linker settings and other security-relevant binary characteristics"; distributed as a NuGet dotnet tool; run `binskim analyze <file>`. Rule families: BA2xxx = PE. Relevant rule IDs: Control Flow Guard **BA2008**, ASLR **BA2009**, Spectre **BA2024**, CET shadow stack **BA2025**. - [microsoft/binskim](https://github.com/microsoft/binskim); [BinSkim User Guide](https://github.com/Microsoft/binskim/blob/master/docs/UserGuide.md); [MS Learn: Use BinSkim](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/binskim-check-binaries)
- **winchecksec** (Trail of Bits) reports, as text labels: Dynamic Base, ASLR, High Entropy VA, Force Integrity, Isolation, NX, SEH, CFG, RFG, SafeSEH, GS, Authenticode, .NET; JSON output uses camelCase keys under `mitigations` (e.g. `dynamicBase` with a `presence` of `Present`/`NotPresent`/`NotApplicable`). It notes `/DYNAMICBASE` at build time ≠ guaranteed runtime ASLR, so it reports both separately. - [trailofbits/winchecksec](https://github.com/trailofbits/winchecksec); [Trail of Bits blog](https://blog.trailofbits.com/2018/09/26/effortless-security-feature-detection-with-winchecksec/)

### Inferences
- CI recipe: build → `binskim analyze` as a gate (fail the pipeline on missing BA2008/BA2009/BA2024/BA2025) → `winchecksec --json` artifact for human review → spot-check `dumpbin /loadconfig` for CFG/ehcont tables.

### Gaps
- Exact BinSkim rule IDs for `/GS`, `/HIGHENTROPYVA`, DEP, SafeSEH were not individually confirmed from the live rule table (only CFG/ASLR/Spectre/CET IDs surfaced); writer should confirm against the current UserGuide rule table.

---

## Static CRT (`/MT`) security tradeoff

### Takeaway
Yes - a `/MT` build bakes in a copy of the CRT and will **not** receive servicing fixes via the VC++ Redistributable / Windows Update; the mitigation is to rebuild and re-release whenever a relevant CRT CVE is fixed and to track the toolset version. For a self-contained security tool shipped on isolated analyst VMs, `/MT` is a defensible convenience tradeoff provided you have a rebuild/update discipline.

### Cited Findings
- `/MT` "Statically links the native CRT startup into your code." - [MS Learn: CRT Library Features](https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-library-features)
- Microsoft "strongly recommend[s] you use the Redistributable package" for central UCRT deployment "for security and ease of updates"; local deployment of the UCRT is "supported, but not recommended for both performance and security reasons." UCRT is serviced by Windows Update independently of the toolset. - [MS Learn: Universal CRT deployment](https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment)
- Precedent that statically linked runtime code needs rebuilds for fixes: MFC bulletin MS11-025 states "customers will be required to rebuild your application every time a security update for MFC is released." - [MSRC MS11-025](https://technet.microsoft.com/security/ms11-025)

### Inferences
- The concrete risk for `obsidian_server.exe` (/MT, parses network JSON) is a CRT-level vulnerability (e.g., in a formatting/allocation routine) that a redist update would fix centrally but a static build would not - you must re-ship. Mitigations: (1) pin and record the exact toolset version in build metadata; (2) subscribe to MSVC CRT advisories; (3) keep the build reproducible so a security rebuild is a one-click re-release; (4) prefer `/MT` only where single-file portability genuinely matters, else `/MD` + ship the redist. Note `/Qspectre` requires the *mitigated* static libs for a `/MT` build.

### Gaps
- No current (post-2015) Microsoft advisory specifically about a static-CRT CVE was found; the servicing argument rests on deployment-guidance pages + the older MFC precedent.

---

## x64dbg-specific guidance: how x64dbg is built, and loader-lock / DllMain constraint

### Takeaway
x64dbg is built with MSVC + CMake (cmkr), **dynamic CRT**, release opts `/OPT:REF /OPT:ICF`, and **no CFG/CET/ehcont markings** - so it does not enforce CFG StrictMode or CET strict mode, and a hardened plugin DLL loads fine. The hard plugin constraint is not a mitigation flag but the Windows **loader lock**: do no heavy work in `DllMain`; do initialization in the exported `pluginit`.

### Cited Findings
- x64dbg build: `cmake.toml` sets `msvc-runtime = "dynamic"`; `CMakeLists.txt` uses `CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"`; `cmake/VSFlags.cmake` sets release `/DEBUG:FULL /INCREMENTAL:NO /OPT:REF /OPT:ICF` and `/MP /bigobj`; no `/guard:cf`, `/CETCOMPAT`, `/guard:ehcont`, or explicit DYNAMICBASE/HIGHENTROPYVA. Optional ASan via `ENABLE_SANITIZERS` (`/fsanitize=address`, static release runtime). - source: cloned `github.com/x64dbg/x64dbg` (HEAD, Nov 2026). Repo: [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg)
- Plugins are "simple dynamic link libraries (.dll files)" renamed to `.dp64`/`.dp32`; they export `pluginit` (registration), `plugsetup`, `plugstop`; cleanup (remove commands/callbacks) happens in `plugstop`. - [x64dbg plugin SDK blog](https://x64dbg.com/blog/2016/07/30/x64dbg-plugin-sdk.html); [x64dbg plugin basics](https://help.x64dbg.com/en/latest/developers/plugins/basics.html)
- Official CMake build: the x64dbg **plugintemplate** uses cmkr/`cmake.toml`, builds a `shared` library of `type = "plugin"`, fetches the x64dbg SDK, and applies `cmake/msvc-static-runtime.cmake` + `cmake/msvc-configurations.cmake`. - [x64dbg/plugintemplate](https://github.com/x64dbg/plugintemplate)

### Inferences
- Because x64dbg uses the **dynamic** CRT while the plugin is specified as `/MT` (static), the two coexist (separate CRT instances) - standard for plugins, but means heap/CRT objects must not be freed across the plugin↔host boundary with mismatched allocators. This is an ABI caution, not a mitigation-flag issue.
- Enabling CFG/ehcont/GS/sdl/Qspectre/ASLR on the plugin is safe to load into x64dbg (host enforces no StrictMode). The loader-lock rule (no LoadLibrary/thread/heavy init in `DllMain`) is the real "could break loading" constraint and is orthogonal to the hardening flags.

### Gaps
- The x64dbg 2016 threading-model blog post was referenced in the task but not directly retrieved; loader-lock guidance here is from the plugin SDK/basics docs and general Windows loader rules, not a quoted x64dbg threading post.

---

## CI bug-finding: `/W4 /WX`, `/analyze`, AddressSanitizer

### Takeaway
For the JSON/pipe/TLS parsers, run `/W4 /WX` (or `/Wall` selectively), `/analyze` (static analysis), and MSVC **AddressSanitizer** (`/fsanitize=address`) in CI - these find bugs rather than mitigate them, and x64dbg's own build already wires up optional ASan.

### Cited Findings
- x64dbg supports `/fsanitize=address` via an `ENABLE_SANITIZERS` option (MSVC and Clang-CL paths), referencing the MSVC ASan docs; ASan requires the static release runtime and `/INCREMENTAL:NO`. - source: cloned `cmake/VSFlags.cmake`, [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg)

### Inferences
- `/WX` (warnings as errors) + `/W4` + `/sdl` catches many parser defects at compile time. `/analyze` adds taint/overrun checks valuable for network-facing code. `/fsanitize=address` is a debug/CI configuration (not for release - it disables some mitigations and adds large overhead) and is the strongest way to shake out memory bugs in the JSON and Schannel-buffer handling before shipping.

### Gaps
- Did not retrieve the primary MSVC `/analyze` or `/fsanitize=address` Learn pages this session; the ASan usage pattern is corroborated by x64dbg's build referencing the MSVC ASan blog. Writer may cite [MSVC ASan docs](https://learn.microsoft.com/en-us/cpp/build/reference/fsanitize) to firm this up.

---

## PRIORITISED CHECKLIST (flag → target → CMake snippet → benefit → cost/risk → verify)

CMake pattern used below (per-target, MSVC-guarded). Define once:
```cmake
# Applies to both the plugin DLL and the server EXE targets
function(harden_target tgt is_exe)
  if(MSVC)
    target_compile_options(${tgt} PRIVATE
      /guard:cf                 # CFG instrumentation
      $<$<CONFIG:Release>:/guard:ehcont>  # x64 only; see note
      /sdl /GS /Qspectre /Gy /W4)
    target_link_options(${tgt} PRIVATE
      /GUARD:CF /guard:ehcont
      /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT
      /OPT:REF /OPT:ICF)
    if(is_exe)
      target_link_options(${tgt} PRIVATE /CETCOMPAT)   # EXE only
    endif()
  endif()
endfunction()
```
LTCG via the portable IPO module:
```cmake
include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_ok OUTPUT ipo_err)
if(ipo_ok)
  set_property(TARGET obsidian_server obsidian_plugin PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()
```

| Priority | Flag | Target | Benefit | Cost / Risk | Verify |
|---|---|---|---|---|---|
| P0 | `/guard:cf` (compile) + `/GUARD:CF` (link) | **Both** | Forward-edge CFI on indirect calls in parser code | Small runtime cost; incompatible with `/ZI`,`/clr`. **No load risk** - x64dbg has no CFG StrictMode | `dumpbin /loadconfig` → `CF Instrumented`,`FID table present`; BinSkim BA2008 |
| P0 | `/DYNAMICBASE` `/HIGHENTROPYVA` `/NXCOMPAT` (link) | **Both** | ASLR + high-entropy ASLR + DEP (prereq for CFG) | Defaults anyway; ~0 cost. HIGHENTROPYVA ignored on x86 | winchecksec Dynamic Base / High Entropy VA / NX = Present; BinSkim BA2009 |
| P0 | `/GS` (compile) | **Both** | Stack-cookie overrun detection | On by default; workload-dependent, ~0-10% | winchecksec GS=Present |
| P0 | `/sdl` (compile) | **Both** | Stricter `/GS`, init, security warnings→errors | Minor; may surface new warnings | build log; code review |
| P1 | `/Qspectre` (compile) | **Both** | Spectre v1 (bounds-check bypass) hardening on net-facing parser | "Negligible"; **needs Spectre-mitigated runtime libs installed or MSB8040** | BinSkim BA2024 |
| P1 | `/guard:ehcont` (compile+link) | **Both (x64)** | Validates SEH continuation targets (back-edge; complements CET) | x64/64-bit OS only; needs `/Gy`; may hit LNK2046/2047 if EH metadata can't form | `dumpbin /loadconfig` → "EH Continuation table present" |
| P1 | `/Gy` (compile) + `/OPT:REF,ICF` (link) | **Both** | Dead-code strip + COMDAT fold (size/speed); required by ehcont | ICF can merge identical funcs (debugging nuance) | smaller binary; map file |
| P1 | `INTERPROCEDURAL_OPTIMIZATION` (`/GL`+`/LTCG`) | **Both** | Whole-program opt; also lets CFG elide more checks | Longer link; gate behind `check_ipo_supported` | `dumpbin /headers` shows LTCG; BinSkim |
| P1 | `/W4 /WX`, `/analyze`, `/fsanitize=address` (CI only) | **Both** | Find real bugs in JSON/pipe/TLS parsers | ASan: big overhead, disables some mitigations → **CI/debug only, not release** | CI job results |
| P2 | `/CETCOMPAT` (link) | **EXE only** | Hardware shadow-stack ROP defense for the server process | **Moot inside x64dbg (host not CET)**; only enable on the plugin if its code is shadow-stack-clean | BinSkim BA2025; `dumpbin` CET bit |
| P2 | `/SAFESEH` (link) | **Plugin x86 build only** | Validates x86 exception handler chain | x86 only; needs SEH-aware objects | winchecksec SafeSEH=Present |
| P3 | Authenticode signing | **Both** | Integrity/trust for a security tool | Requires cert + signing infra | `signtool verify`; winchecksec Authenticode |
| P3 (opt) | `/INTEGRITYCHECK` (link) | **EXE (test first)** | Loader enforces signature | **HARD WARNING: on the plugin DLL, forced integrity can make x64dbg refuse to load it**; needs Trusted/Azure signing | `dumpbin /headers` → Force Integrity |

### Hard warnings (things that can break plugin loading into x64dbg)
1. **`/INTEGRITYCHECK` on the plugin DLL** - if the signing chain isn't trusted on the analyst's machine, the loader can refuse the module and the plugin silently fails to load. Keep forced-integrity off the plugin; plain Authenticode only. - [MS Learn /INTEGRITYCHECK](https://learn.microsoft.com/en-us/cpp/build/reference/integritycheck-require-signature-check)
2. **`/CETCOMPAT` on the plugin when the plugin does non-standard stack manipulation** - marking it compatible opts its code into *fatal* #CP enforcement if the host is ever in CET compatibility/strict mode. Only mark the plugin if its code is shadow-stack-clean. - [MS Learn: USER_SHADOW_STACK_POLICY](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_user_shadow_stack_policy)
3. **Heavy work / `LoadLibrary` / thread creation in `DllMain`** (loader lock) - unrelated to flags but the real load-time failure mode; do init in exported `pluginit`, not `DllMain`. - [x64dbg plugin basics](https://help.x64dbg.com/en/latest/developers/plugins/basics.html)
4. **`/guard:cf` is NOT a load risk** for x64dbg (no StrictMode); CFG/GS/sdl/Qspectre/ASLR/ehcont are all safe to enable on the plugin.
