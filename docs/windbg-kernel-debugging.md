# WinDbg Kernel Debugging

## Overview

The WinDbg kernel debugging integration provides kernel-mode analysis capabilities through the binary-mcp MCP server. It wraps Microsoft's DbgEng COM interfaces via the Pybag library and uses CDB/KD subprocesses as a fallback for extension commands.

This is built for security researchers and reverse engineers working on:

- **Kernel driver vulnerability research** -- analyzing dispatch tables, IOCTL handlers, and driver attack surfaces.
- **Crash dump analysis** -- triaging BSODs with `!analyze -v`, inspecting faulting modules, and walking stack traces.
- **Live kernel inspection** -- reading kernel memory, enumerating loaded modules, dumping structures, and examining kernel objects.

The integration exposes 20 MCP tools across four categories: connection management, execution control, breakpoints, and memory/register inspection.

---

## Prerequisites

- **Windows** with Administrator privileges
- **Windows SDK** (Debugging Tools for Windows) -- provides `cdb.exe` and `kd.exe`
- **Python 3.12+** with `binary-mcp[windbg]` installed (pulls in the Pybag package)
- **`bcdedit -debug on` + reboot** for full local kernel access (memory, registers, processes)

Without debug mode enabled, local kernel connections partially work -- symbol lookups (`lm`, `x`, `dt`, `u`) succeed through KD, but register reads, memory reads, `!process`, and stack walks will fail.

---

## Setup

### Installing Debugging Tools for Windows

The tools require `cdb.exe` and `kd.exe` from the Windows SDK. Three installation methods:

**Method 1: winget (recommended)**

```powershell
winget install Microsoft.WindowsSDK.10.0.26100
```

This installs the full SDK. The debugger binaries land in:

```
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\
```

**Method 2: Windows SDK installer**

Download from [developer.microsoft.com/windows/downloads/windows-sdk](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/). During installation, select **Debugging Tools for Windows** -- you can deselect everything else.

**Method 3: WinDbg Preview**

```powershell
winget install Microsoft.WinDbg
```

This installs the modern WinDbg UI via the Microsoft Store. It includes `cdb.exe` in its install directory, though the path varies by version.

**Setting WINDBG_PATH manually**

If auto-detection fails, set the environment variable to the directory containing `cdb.exe` and `kd.exe`:

```powershell
set WINDBG_PATH=C:\Program Files (x86)\Windows Kits\10\Debuggers\x64
```

Or persist it:

```powershell
[System.Environment]::SetEnvironmentVariable("WINDBG_PATH", "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64", "User")
```

**Auto-detection search order**

When `WINDBG_PATH` is not set, the bridge searches these locations in order:

1. `WINDBG_PATH` environment variable
2. `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`
3. `C:\Program Files\Windows Kits\10\Debuggers\x64`
4. `C:\Program Files (x86)\Windows Kits\10\Debuggers\x86`
5. `C:\Debuggers`
6. WinDbg Preview Store/winget paths (`Microsoft.WinDbg` AppX package)
7. `cdb.exe` / `kd.exe` on system `PATH`

### Enabling Kernel Debug Mode

Full local kernel access requires debug mode to be enabled in the Windows boot configuration:

```powershell
# Run as Administrator
bcdedit -debug on
```

Then reboot:

```powershell
shutdown /r /t 0
```

After rebooting, the MCP server must be run from an elevated (Administrator) terminal.

**Secure Boot note**: If `bcdedit -debug on` fails with error `0xc0000428`, Secure Boot is blocking the change. You must disable Secure Boot in your BIOS/UEFI settings (typically under Security > Secure Boot > Disabled), then retry the `bcdedit` command.

**What works without debug mode vs. with it**

| Capability | Without `bcdedit -debug on` | With `bcdedit -debug on` |
|---|---|---|
| Symbol lookups (`x`, `lm`, `u`) | Yes (via KD) | Yes |
| Structure dumps (`dt`) | Yes (via KD) | Yes |
| Disassembly | Yes (via KD) | Yes |
| Register reads | No | Yes |
| Memory reads (`db`, `dq`) | No | Yes |
| `!process`, `!drvobj` | No | Yes |
| Stack traces (`k`) | No | Yes |

### Installer (install.ps1)

The interactive installer has a dedicated kernel debugging profile:

```powershell
# Run as Administrator
.\install.ps1
```

Select **[4] Kernel Debugging** from the menu. This will:

1. Install the Windows SDK (Debugging Tools) if not detected
2. Install the Pybag Python package (`uv sync --extra windbg`)
3. Run `bcdedit -debug on` (with Secure Boot detection and guidance)
4. Configure Claude Desktop/Code MCP server entries

For unattended installation:

```powershell
.\install.ps1 -InstallProfile kernel -Unattended
```

---

## Connection Modes

### Local Kernel (Inspection Mode)

Local kernel debugging attaches to the running kernel on the same machine. It provides read access to kernel memory, registers, loaded modules, and kernel objects, but no execution control.

**When to use**: Inspecting the live kernel -- enumerating drivers, reading kernel structures, examining loaded module lists, or resolving symbols at runtime addresses.

**What works**:

- Memory reads (`db`, `dq`, `dd`, `dp`)
- Register dump (`r`)
- Loaded module list (`lm`)
- Symbol resolution (`x nt!*`)
- Structure dumps (`dt nt!_EPROCESS`)
- Disassembly (`u`)
- Extension commands (`!process`, `!drvobj`, `!devobj`)

**What does not work**:

- Breakpoints (software or hardware)
- Single-stepping (`t`, `p`)
- Run/pause (`g`, break)
- Memory writes

**Requirements**: `bcdedit -debug on`, reboot, run as Administrator.

**Connect via MCP**:

```
Connect to the local kernel debugger
```

This calls `windbg_connect_kernel()` with no key, which triggers `KernelDbg().attach("local")` through Pybag.

### Remote KDNET

KDNET debugging connects to a separate target machine over the network. This provides full debugging capabilities including breakpoints, stepping, and execution control.

**Setup on target machine** (the machine being debugged):

```powershell
# Run as Administrator on the target
bcdedit /debug on
bcdedit /dbgsettings net hostip:<HOST_IP> port:50000 key:1.2.3.4
shutdown /r /t 0
```

Replace `<HOST_IP>` with the IP address of the machine running the MCP server. The key is an arbitrary dotted-quad value shared between host and target.

**Connect from MCP**:

```
Connect to the kernel debugger on port 50000 with key 1.2.3.4
```

This calls `windbg_connect_kernel(port=50000, key="1.2.3.4")`, which executes `KernelDbg().attach("net:port=50000,key=1.2.3.4")` through Pybag.

**Full capabilities**: breakpoints, stepping, run/pause, memory read/write, register access, all extension commands.

### Crash Dump Analysis

Opens a Windows crash dump file (`.dmp`) for offline analysis. This is a read-only mode -- the dump captures a frozen snapshot of kernel state at the time of the crash.

**Connect via MCP**:

```
Analyze the crash dump at C:\Windows\MEMORY.DMP
```

This calls `windbg_open_dump(dump_path="C:\\Windows\\MEMORY.DMP")`. Dump analysis runs entirely through the CDB subprocess (`cdb.exe -z <dump>`), because Pybag's `OpenDumpFile` COM binding is not implemented.

**What works**: `!analyze -v`, stack traces, register state at crash, module lists, memory reads from the dump, symbol resolution.

**What does not work**: execution control, breakpoints, memory writes (the dump is immutable).

---

## Tool Reference

### Connection Tools (4)

| Tool | Parameters | Description |
|---|---|---|
| `windbg_status` | None | Returns current debugger state, mode (kernel/user/dump), target path, and instruction pointer. |
| `windbg_connect_kernel` | `port: int = 50000`, `key: str = ""` | Connect to kernel target. Empty key = local kernel inspection. Non-empty key = KDNET remote session. |
| `windbg_open_dump` | `dump_path: str` | Open a `.dmp` crash dump for analysis. Requires `cdb.exe`. |
| `windbg_disconnect` | None | Disconnect from the current session. Cleans up Pybag connections and CDB subprocesses. |

**Example -- check status**:

```
What is the current WinDbg debugger status?
```

**Example -- local kernel connection**:

```
Connect to the local kernel debugger
```

**Example -- open crash dump**:

```
Open the crash dump at C:\Windows\Minidump\120625-31234-01.dmp
```

### Execution Control Tools (6)

| Tool | Parameters | Description | Restrictions |
|---|---|---|---|
| `windbg_run` | None | Resume execution (`g`). | Blocked in local kernel and dump modes. |
| `windbg_pause` | None | Break into the debugger. | Blocked in local kernel and dump modes. |
| `windbg_step_into` | None | Single-step into the next instruction (`t`). | Blocked in local kernel and dump modes. |
| `windbg_step_over` | None | Step over the next instruction (`p`). | Blocked in local kernel and dump modes. |
| `windbg_run_and_wait` | `timeout: int = 30` | Resume execution and wait for a break event. Uses `INFINITE` timeout for kernel targets per Microsoft documentation. | Blocked in local kernel and dump modes. |
| `windbg_wait_paused` | `timeout: int = 30` | Wait for the target to reach a paused state. Uses `INFINITE` timeout for kernel targets. | Blocked in local kernel and dump modes. |

All six execution control tools require a remote KDNET connection. In local kernel or dump analysis mode, they return an error explaining why execution control is unavailable.

### Breakpoint Tools (4)

| Tool | Parameters | Description |
|---|---|---|
| `windbg_set_breakpoint` | `address: str` | Set a software breakpoint at a hex address or symbol name. |
| `windbg_delete_breakpoint` | `address: str` | Delete the breakpoint at the given hex address. |
| `windbg_list_breakpoints` | None | List all active breakpoints (runs the `bl` command). |
| `windbg_set_conditional_breakpoint` | `address: str`, `condition: str` | Set a conditional breakpoint. Condition is a WinDbg expression, max 200 characters. |

**Address formats accepted**:

- Hex: `0x401000`, `fffff80579afb8c0`, `` fffff805`79afb8c0 `` (backtick separators allowed)
- Symbol: `nt!NtCreateFile`, `Vgk!DriverEntry`, `module!*`

**Conditional breakpoint syntax**:

The condition parameter uses WinDbg expression syntax. Internally it generates:

```
bp <address> ".if (<condition>) {} .else {gc}"
```

**Examples**:

```
Set a breakpoint at nt!NtDeviceIoControlFile
```

```
Set a conditional breakpoint at 0xfffff80579afb8c0 when rcx==0x100
```

**Condition validation rules**:

- Allowed characters: `a-zA-Z0-9_!=<>&|+-*/()@$.\s,`
- Maximum length: 200 characters
- Blocked substrings: `.shell`, `.create`, `.script`, `!runscript`, `.writemem`

### Inspection Tools (6)

| Tool | Parameters | Description |
|---|---|---|
| `windbg_get_registers` | None | Formatted dump of general-purpose (RAX-RSP, RIP) and extended (R8-R15) registers. |
| `windbg_read_memory` | `address: str`, `size: int = 64` | Read memory at the given address. Default 64 bytes, maximum 4096 bytes. Returns a hex+ASCII dump. |
| `windbg_write_memory` | `address: str`, `data: str` | Write hex bytes to the target address space (e.g. `"90 90 cc"`). Blocked in local kernel and dump modes. |
| `windbg_disassemble` | `address: str`, `count: int = 10` | Disassemble instructions at the address. Uses `u <address> L<count>`. |
| `windbg_get_modules` | None | List all loaded modules/drivers with base address, end address, name, and symbol status. |
| `windbg_execute_command` | `command: str` | Execute any raw WinDbg command. Subject to the security blocklist. Use this for commands not covered by dedicated tools (e.g. `!analyze -v`, `!process 0 0`, `dt nt!_EPROCESS`). |

**Example -- read kernel memory**:

```
Read 256 bytes of memory at fffff80579afb8c0
```

**Example -- disassemble a function**:

```
Disassemble 20 instructions at nt!NtCreateFile
```

**Example -- raw WinDbg command**:

```
Execute the WinDbg command: !process 0 0
```

```
Execute the WinDbg command: dt nt!_EPROCESS fffff805`79c12340
```

---

## Architecture

### Pybag COM API (Primary)

The primary interface wraps Microsoft's DbgEng COM interfaces through the [Pybag](https://github.com/dshikashio/Pybag) Python library. Pybag provides direct access to `IDebugClient`, `IDebugControl`, `IDebugRegisters`, and `IDebugDataSpaces` without spawning subprocesses.

**Used for**: connections (`KernelDbg().attach()`), breakpoints (`bp`/`bc`), memory read/write (`read`/`write`), register access (`reg`), command execution (`cmd()`), and module enumeration (`module_list()`).

**Advantages over subprocess**:

- Structured data (bytes, integers, dicts) instead of text parsing
- Direct HRESULT error codes for precise failure diagnosis
- No startup latency from spawning processes
- Breakpoint callbacks in Python

### CDB/KD Subprocess (Fallback)

When Pybag is unavailable, when a Pybag `cmd()` call fails, or when analyzing crash dumps (Pybag's `OpenDumpFile` is not implemented), the bridge falls back to running commands through a CDB or KD subprocess.

- **`kd.exe`** is used for local kernel debugging (`kd.exe -kl -c "<command>; q"`). CDB does not support the `-kl` flag.
- **`cdb.exe`** is used for crash dump analysis (`cdb.exe -z <dump> -c "<command>; q"`).

Output from the subprocess is automatically filtered to strip:

- CDB/KD startup banner (Microsoft copyright, version, symbol path)
- Debugger Extensions Gallery setup noise
- NatVis load/unload messages
- KD session banner (Connected to, Product, Kernel base, etc.)
- Prompt echoes (`lkd>`, `kd>`)

### Two-Layer Security Model

Command execution passes through two independent security checks.

**Layer 1: Bridge layer** -- 25 blocked WinDbg meta-commands are rejected by substring match before any command reaches DbgEng or the CDB subprocess. This is defense-in-depth applied to every code path, including `execute_command()`, `execute_extension()`, and `_execute_cdb_command()`.

Blocked commands (25):

```
.shell     .create    .abandon   .kill      .restart
.dump      .writemem  .writevirtmem          .logopen
.logclose  .outmask   .script    .scriptrun .scriptload
!runscript .formats   .tlist     .detach    .reboot
.crash     .bugcheck  .load      .loadby    .cordll
.call
```

**Why these are blocked**:

- `.shell`, `.create` -- spawn arbitrary OS processes
- `.load`, `.loadby`, `.cordll` -- load arbitrary DLLs into the debugger
- `.script`, `.scriptrun`, `.scriptload`, `!runscript` -- execute arbitrary scripts
- `.dump`, `.writemem`, `.writevirtmem` -- write to disk or memory outside controlled paths
- `.call` -- call arbitrary functions in the target process
- `.reboot`, `.crash`, `.bugcheck` -- destructive target operations
- `.detach`, `.abandon`, `.kill`, `.restart` -- uncontrolled session management
- `.logopen`, `.logclose`, `.outmask` -- write to arbitrary files
- `.formats`, `.tlist` -- information disclosure outside the debug session

**Layer 2: Tool layer** -- individual tools validate their inputs before passing them to the bridge:

- **Address validation**: `^[0-9a-fA-F`x]+$` for hex addresses, `^[a-zA-Z0-9_!.*+:]+$` for symbols
- **Condition validation**: `^[a-zA-Z0-9_!=<>&|+\-*/()@$.\s,]+$` with max 200 characters and an additional blocklist (`.shell`, `.create`, `.script`, `!runscript`, `.writemem`)
- **Command blocklist**: `windbg_execute_command` re-checks the blocked command list at the tool layer

**What is allowed through `windbg_execute_command`**:

Regular commands (`lm`, `r`, `k`, `u`, `db`, `dq`, `dd`, `dp`, `dt`, `x`, `s`, `!analyze`, `!process`, `!drvobj`, `!devobj`, `!pool`, `!poolfind`, `!poolused`, `!object`, `!irp`, `!handle`, `vertarget`, `bl`, and any other command not on the blocklist).

---

## Workflows

### Analyzing a Kernel Driver

This workflow inspects a loaded kernel driver to understand its dispatch table and IOCTL handler.

**Step 1: Connect to the local kernel**

```
Connect to the local kernel debugger
```

Tool call: `windbg_connect_kernel()` (no key = local)

**Step 2: List loaded drivers**

```
List all loaded kernel modules
```

Tool call: `windbg_get_modules()`

This returns a table of all loaded drivers with base addresses, end addresses, names, and symbol status. Look for the target driver (e.g. `Vgk`, `BEDaisy`, `EasyAntiCheat`).

**Step 3: Get the driver object and dispatch table**

```
Execute the WinDbg command: !drvobj \Driver\Vgk 3
```

Tool call: `windbg_execute_command(command="!drvobj \\Driver\\Vgk 3")`

The `3` verbosity flag dumps the full IRP dispatch table, showing the handler address for each of the 28 IRP_MJ functions.

**Step 4: Disassemble the IOCTL handler**

From the dispatch table output, find the `IRP_MJ_DEVICE_CONTROL` handler address and disassemble it:

```
Disassemble 30 instructions at fffff805`79afb8c0
```

Tool call: `windbg_disassemble(address="fffff805`79afb8c0", count=30)`

**Step 5: Read memory around the handler**

```
Read 256 bytes of memory at fffff805`79afb8c0
```

Tool call: `windbg_read_memory(address="fffff80579afb8c0", size=256)`

### Analyzing a Crash Dump

**Step 1: Open the dump file**

```
Open the crash dump at C:\Windows\MEMORY.DMP
```

Tool call: `windbg_open_dump(dump_path="C:\\Windows\\MEMORY.DMP")`

**Step 2: Run automated crash analysis**

```
Execute the WinDbg command: !analyze -v
```

Tool call: `windbg_execute_command(command="!analyze -v")`

This returns the bugcheck code, faulting module, faulting address, probable cause, and a stack trace.

**Step 3: Check the faulting module and stack**

```
Execute the WinDbg command: lm vm <faulting_module>
```

Tool call: `windbg_execute_command(command="lm vm Vgk")`

This shows the module's version information, timestamp, and image path.

```
Execute the WinDbg command: .ecxr; k
```

Tool call: `windbg_execute_command(command=".ecxr")`

Then: `windbg_execute_command(command="k")`

These restore the exception context record and display the stack trace at the point of the crash.

### Inspecting Kernel Memory

**Step 1: Connect**

```
Connect to the local kernel debugger
```

**Step 2: Dump an EPROCESS structure**

```
Execute the WinDbg command: !process 0 0 lsass.exe
```

Tool call: `windbg_execute_command(command="!process 0 0 lsass.exe")`

This returns the EPROCESS address for the target process.

```
Execute the WinDbg command: dt nt!_EPROCESS fffff805`79c12340
```

Tool call: `windbg_execute_command(command="dt nt!_EPROCESS fffff805`79c12340")`

**Step 3: Read raw memory**

```
Read 64 bytes of memory at fffff805`79c12340
```

Tool call: `windbg_read_memory(address="fffff80579c12340", size=64)`

**Step 4: Examine loaded modules for a specific driver**

```
Execute the WinDbg command: lm vm Vgk
```

```
Execute the WinDbg command: x Vgk!*Dispatch*
```

The `x` command resolves symbols matching the wildcard pattern, helping locate dispatch routines and other key functions.

---

## Debug Logging

Enable trace-level debug logging by setting the `WINDBG_DEBUG` environment variable:

```powershell
set WINDBG_DEBUG=1
```

**Log file**: `~/.ghidra_mcp_cache/windbg_debug.log`

**Log format**: `HH:MM:SS LEVEL message`

**What it logs**:

- `CALL method(args)` -- every bridge method invocation with arguments
- `OK method -> result (Nms)` -- successful returns with timing
- `FAIL method -> ExceptionType: message (Nms)` -- failures with timing

Results longer than 200 characters are truncated in the log. When `WINDBG_DEBUG` is not set, the trace decorator has zero overhead -- it checks for handlers and returns immediately.

**Example output**:

```
14:32:01 DEBUG === WinDbg debug trace started ===
14:32:01 DEBUG CALL  WinDbgBridge.connect_kernel_local()
14:32:02 DEBUG OK    WinDbgBridge.connect_kernel_local -> True  (847.3ms)
14:32:02 DEBUG CALL  WinDbgBridge.get_loaded_drivers()
14:32:03 DEBUG OK    WinDbgBridge.get_loaded_drivers -> [{'start': 'fffff80579800000', 'end'...  (312.1ms)
14:32:05 DEBUG CALL  WinDbgBridge.execute_command('!drvobj \\Driver\\Vgk 3')
14:32:06 DEBUG OK    WinDbgBridge.execute_command -> 'Driver object (fffff80579...'  (1043.7ms)
```

---

## Error Logging

All WinDbg operation failures are automatically persisted as structured JSON error records.

**Storage location**: `~/.ghidra_mcp_cache/windbg_errors/`

**File structure**:

```
windbg_errors/
    manifest.json                                              # Error index (sorted by time)
    stats.json                                                 # Aggregate statistics
    20260217_143012_read_memory_windbg_37496d64b65946dc.json   # Individual error record
    20260217_143015_cdb_command_windbg_84b033248cd44c34.json    # Individual error record
```

**Manifest** (`manifest.json`): An index of all recorded errors, sorted newest-first, with truncated error messages for quick browsing.

**Statistics** (`stats.json`): Aggregate counts by operation, by exception type, and by HTTP status. Updated on every new error.

**Individual records**: Full error context including operation, exception type, message, debugger state, target binary/dump path, address involved, and Python traceback.

**Retention**: The 500 most recent errors are kept. When the count exceeds 500, the oldest records are automatically deleted.

**Error codes** (9 structured codes with actionable suggestions):

| Error Code | Meaning |
|---|---|
| `KERNEL_NOT_CONNECTED` | No active kernel debug session |
| `KERNEL_TARGET_UNAVAILABLE` | Target machine not responding |
| `KERNEL_DUMP_INVALID` | Dump file corrupt or inaccessible |
| `KERNEL_DRIVER_NOT_FOUND` | Driver name not found in loaded modules |
| `KERNEL_IOCTL_INVALID` | Malformed IOCTL code |
| `WINDBG_NOT_FOUND` | `cdb.exe` / `kd.exe` not found on the system |
| `WINDBG_COMMAND_FAILED` | Command execution returned an error |
| `WINDBG_COMMAND_TIMEOUT` | CDB/KD subprocess timed out |
| `WINDBG_PARSE_ERROR` | Failed to parse command output |

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `WINDBG_PATH` | Directory containing `cdb.exe` and `kd.exe` | Auto-detected from Windows SDK |
| `WINDBG_MODE` | Operating mode: `kernel`, `user`, or `dump` | `kernel` |
| `WINDBG_SYMBOL_PATH` | Symbol server path for resolving symbols | `srv*C:\Symbols*https://msdl.microsoft.com/download/symbols` |
| `WINDBG_TIMEOUT` | Command timeout in seconds for CDB subprocess | `30` |
| `WINDBG_DEBUG` | Set to `1` to enable trace logging to file | Disabled |

---

## Troubleshooting

### WinDbg/CDB not found

**Error**: `WINDBG_NOT_FOUND` or `CDB.exe is required but was not found`

**Fix**: Install the Windows SDK Debugging Tools and either add the directory to your `PATH` or set `WINDBG_PATH`:

```powershell
# Install via winget
winget install Microsoft.WindowsSDK.10.0.26100

# Or set the path manually
set WINDBG_PATH=C:\Program Files (x86)\Windows Kits\10\Debuggers\x64
```

### Kernel debugging not enabled

**Error**: `Local kernel debugging is not enabled on this system`

**Fix**: Enable debug mode and reboot:

```powershell
# Run as Administrator
bcdedit -debug on
shutdown /r /t 0
```

After rebooting, run the MCP server from an elevated terminal.

### Secure Boot blocking bcdedit

**Error**: `bcdedit -debug on` fails with error `0xc0000428`

**Fix**: Disable Secure Boot in your BIOS/UEFI settings:

1. Restart and enter BIOS/UEFI (usually Del, F2, or F12 during boot)
2. Navigate to Security > Secure Boot
3. Set Secure Boot to **Disabled**
4. Save and exit BIOS
5. Run `bcdedit -debug on` again, then reboot

### CDB subprocess timeout

**Error**: `CDB/KD timed out after 30s`

**Fix**: Increase the timeout:

```powershell
set WINDBG_TIMEOUT=120
```

This is common when running `!analyze -v` on large crash dumps or when the symbol server is slow on first use. After symbols are cached locally, subsequent runs are faster.

### Pybag import error

**Error**: `Pybag is not installed. Install with: pip install pybag`

**Fix**: Install the `windbg` extra:

```powershell
pip install binary-mcp[windbg]
```

Or with uv:

```powershell
uv sync --extra windbg
```

Pybag requires Windows -- it wraps COM interfaces that do not exist on other platforms.

### Operation not supported in local kernel mode

**Error**: `'run' is not supported in local kernel mode`

**Cause**: Execution control (run, pause, step, breakpoints) is not available when attached to the local kernel. Local kernel mode provides inspection only.

**Fix**: For full debugging capabilities, set up a remote KDNET connection to a separate target machine:

```powershell
# On the TARGET machine:
bcdedit /debug on
bcdedit /dbgsettings net hostip:<HOST_IP> port:50000 key:1.2.3.4
shutdown /r /t 0

# Then connect from the MCP server:
# "Connect to kernel debugger on port 50000 with key 1.2.3.4"
```

### Command blocked for security reasons

**Error**: `Command '.shell' is blocked for security reasons`

**Cause**: The command contains one of the 25 blocked WinDbg meta-commands. These are blocked to prevent command injection through the MCP interface.

**Fix**: Use the allowed alternative. For example, instead of `.dump` to save a dump file, use the Windows Task Manager or `procdump.exe` externally. See the [Security Model](#two-layer-security-model) section for the complete blocklist and rationale.

### Limited data access in local kernel

**Warning**: `Local kernel connected but data access is limited`

**Cause**: `bcdedit -debug on` was not set before the last reboot, or the session is not running as Administrator.

**Fix**:

```powershell
# 1. Enable debug mode
bcdedit -debug on

# 2. Reboot
shutdown /r /t 0

# 3. Run the MCP server as Administrator
```
