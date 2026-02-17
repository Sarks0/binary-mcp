# WinDbg Kernel Debugging Integration Plan

## Context

binary-mcp currently supports Ghidra (static analysis) and x64dbg (dynamic analysis). The goal is to add **WinDbg kernel-level debugging** for vulnerability research in bug bounty programs -- specifically targeting kernel drivers like anti-cheat software (Riot Vanguard, BattlEye, EAC). The user previously found vulnerabilities manually and wants LLM-automated kernel debugging workflows.

**Approach**: Pybag COM API as the primary bridge (wraps Microsoft's `dbgeng.dll` COM interfaces directly), with CDB subprocess as a secondary channel for WinDbg extension commands (`!analyze`, `!pool`, `!drvobj`, etc.) that aren't exposed through COM.

**Why Pybag over CDB subprocess**: Structured data natively (no text parsing), COM API stability (unchanged since Windows XP), breakpoint callbacks in Python, better performance (direct COM calls vs subprocess I/O), programmatic error handling via HRESULT codes.

---

## File Structure

### New Files to Create

```
src/engines/dynamic/windbg/
    __init__.py                  # Module docstring + exports
    bridge.py                    # WinDbgBridge(Debugger) - Pybag COM + CDB fallback
    commands.py                  # WinDbgCommands - high-level kernel workflows
    error_logger.py              # WinDbgErrorLogger - error persistence
    output_parser.py             # Parse CDB text output (for extension commands only)
    kernel_types.py              # Dataclasses: DriverObject, DeviceObject, IOCTLCode, etc.

src/tools/
    windbg_tools.py              # register_windbg_tools(app, session_manager)

tests/
    test_windbg_parser.py        # Unit tests for output parsers
    test_windbg_bridge.py        # Unit tests with mocked Pybag
    test_windbg_tools.py         # Tool registration tests
    test_kernel_types.py         # Dataclass/IOCTL decode tests
    fixtures/windbg_output/      # Captured WinDbg output samples for parser tests
        registers.txt
        lm_modules.txt
        drvobj.txt
        pool_info.txt
        analyze_v.txt
        ioctl_decode.txt
```

### Files to Modify

```
src/engines/dynamic/__init__.py          # Update docstring (already mentions WinDbg as planned)
src/engines/session/unified_session.py   # Add AnalysisType.KERNEL to enum (line 25-29)
src/server.py                            # Add register_windbg_tools() call in main() (line 2866)
src/utils/structured_errors.py           # Add KERNEL_* and WINDBG_* error codes (line 22-78)
pyproject.toml                           # Add [project.optional-dependencies.windbg]
```

---

## Phase 1: Foundation (kernel_types, output_parser, error_logger, structured_errors)

Pure Python modules with zero external dependencies. Fully unit-testable on any platform.

### 1a. `kernel_types.py` -- Kernel Data Classes

```python
@dataclass
class DriverObject:
    name: str                              # e.g., "\\Driver\\Vgk"
    address: str                           # Kernel address
    device_objects: list[str]              # Device object addresses
    dispatch_table: dict[str, str]         # IRP_MJ_* -> handler address
    driver_start: str                      # Image base
    driver_size: int                       # Image size
    driver_extension: str | None

@dataclass
class DeviceObject:
    address: str
    driver_object: str
    device_type: str
    device_name: str | None
    attached_to: str | None
    flags: int

@dataclass
class IOCTLCode:
    raw_code: int
    device_type: int
    function_code: int
    method: str          # METHOD_BUFFERED / METHOD_IN_DIRECT / METHOD_OUT_DIRECT / METHOD_NEITHER
    access: str          # FILE_ANY_ACCESS / FILE_READ_ACCESS / FILE_WRITE_ACCESS
    risk_level: str      # "high" for METHOD_NEITHER + FILE_ANY_ACCESS, etc.

    @staticmethod
    def decode(code: int) -> "IOCTLCode": ...  # Bit-field decomposition

@dataclass
class PoolAllocation:
    address: str
    tag: str
    size: int
    pool_type: str       # "Paged" / "NonPaged"
    owning_component: str | None

@dataclass
class CrashAnalysis:
    bugcheck_code: str
    bugcheck_name: str
    arguments: list[str]
    faulting_module: str
    faulting_address: str
    stack_trace: list[dict]
    probable_cause: str
```

### 1b. `output_parser.py` -- CDB Text Output Parsers

Only used for WinDbg extension commands (`!` commands) that have no COM API equivalent. Each parser takes raw text output and returns structured data.

```python
class WinDbgOutputParser:
    @staticmethod
    def parse_registers(output: str) -> dict[str, str]: ...
    @staticmethod
    def parse_modules(output: str) -> list[dict]: ...
    @staticmethod
    def parse_stack(output: str) -> list[dict]: ...
    @staticmethod
    def parse_disassembly(output: str) -> list[dict]: ...
    @staticmethod
    def parse_memory_dump(output: str) -> bytes: ...
    @staticmethod
    def parse_driver_object(output: str) -> DriverObject: ...
    @staticmethod
    def parse_device_object(output: str) -> DeviceObject: ...
    @staticmethod
    def parse_pool_info(output: str) -> PoolAllocation: ...
    @staticmethod
    def parse_analyze(output: str) -> CrashAnalysis: ...
    @staticmethod
    def parse_ioctl_decode(output: str) -> IOCTLCode: ...
    @staticmethod
    def parse_processes(output: str) -> list[dict]: ...
```

### 1c. `error_logger.py` -- Clone from x64dbg pattern

Reuse the exact pattern from `src/engines/dynamic/x64dbg/error_logger.py`:
- Same `ErrorContext` and `ErrorRecord` dataclasses
- Store in `~/.ghidra_mcp_cache/windbg_errors/`
- Error IDs prefixed `windbg_` instead of `x64_`
- Same manifest.json + stats.json pattern

**Reuse**: Copy `ErrorContext`, `ErrorRecord` dataclass definitions. Rename class to `WinDbgErrorLogger`. Change `error_dir` default to `windbg_errors/`.

### 1d. Modify `structured_errors.py` -- Add error codes

Add to `ErrorCode` enum after line 78:

```python
# Kernel/WinDbg errors
KERNEL_NOT_CONNECTED = "KERNEL_NOT_CONNECTED"
KERNEL_TARGET_UNAVAILABLE = "KERNEL_TARGET_UNAVAILABLE"
KERNEL_DUMP_INVALID = "KERNEL_DUMP_INVALID"
KERNEL_DRIVER_NOT_FOUND = "KERNEL_DRIVER_NOT_FOUND"
KERNEL_IOCTL_INVALID = "KERNEL_IOCTL_INVALID"
WINDBG_NOT_FOUND = "WINDBG_NOT_FOUND"
WINDBG_COMMAND_FAILED = "WINDBG_COMMAND_FAILED"
WINDBG_COMMAND_TIMEOUT = "WINDBG_COMMAND_TIMEOUT"
WINDBG_PARSE_ERROR = "WINDBG_PARSE_ERROR"
```

Add factory functions following the existing pattern (e.g., `create_address_invalid_error` at ~line 200+):

```python
def create_windbg_not_found_error() -> StructuredError: ...
def create_kernel_not_connected_error() -> StructuredError: ...
def create_kernel_driver_not_found_error(driver_name: str) -> StructuredError: ...
```

### 1e. Modify `unified_session.py` -- Add AnalysisType.KERNEL

At line 25-29, add `KERNEL`:

```python
class AnalysisType(Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    KERNEL = "kernel"     # NEW
    MIXED = "mixed"
```

The existing `log_tool_call()` and `ensure_session()` methods work with any `AnalysisType` value -- no other changes needed in this file.

### 1f. Tests for Phase 1

- `tests/test_kernel_types.py`: IOCTLCode.decode() with known IOCTL values, dataclass construction
- `tests/test_windbg_parser.py`: Each parser method tested with captured WinDbg output fixtures
- `tests/fixtures/windbg_output/`: Real WinDbg output samples (captured from actual sessions)

---

## Phase 2: Bridge + Core Tools (20 MCP tools)

### 2a. `bridge.py` -- WinDbgBridge

The core class. Uses Pybag for structured operations, CDB subprocess for extension commands.

```python
class WinDbgMode(Enum):
    USER_MODE = "user"
    KERNEL_MODE = "kernel"
    DUMP_ANALYSIS = "dump"

class WinDbgBridge(Debugger):
    """WinDbg bridge via Pybag COM API + CDB subprocess for extensions."""

    def __init__(
        self,
        mode: WinDbgMode = WinDbgMode.KERNEL_MODE,
        windbg_path: str | None = None,
        symbol_path: str | None = None,
        timeout: int = 30,
    ):
        self.mode = mode
        self.timeout = timeout
        self.symbol_path = symbol_path or "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols"
        self._windbg_path = windbg_path or self._auto_detect_path()
        self._error_logger = WinDbgErrorLogger()
        self.connected = False

        # Pybag instances (lazy init on connect)
        self._dbg = None           # pybag.UserDbg or pybag.KernelDbg
        self._cdb_process = None   # subprocess.Popen for extension commands

    # --- Auto-detection ---
    def _auto_detect_path(self) -> str | None:
        """Find kd.exe/cdb.exe from Windows SDK or WinDbg install."""
        # Search order:
        # 1. WINDBG_PATH env var
        # 2. C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\
        # 3. C:\Program Files\Windows Kits\10\Debuggers\x64\
        # 4. shutil.which("kd.exe")
        ...

    # --- ABC implementations via Pybag COM ---
    def connect(self, timeout: int = 10) -> bool: ...
    def disconnect(self) -> None: ...
    def load_binary(self, binary_path: Path, args: list[str] | None = None) -> bool: ...
    def set_breakpoint(self, address: str) -> bool: ...
    def delete_breakpoint(self, address: str) -> bool: ...
    def run(self) -> DebuggerState: ...
    def pause(self) -> bool: ...
    def step_into(self) -> dict[str, Any]: ...
    def step_over(self) -> dict[str, Any]: ...
    def get_registers(self) -> dict[str, str]: ...
    def read_memory(self, address: str, size: int) -> bytes: ...
    def write_memory(self, address: str, data: bytes) -> bool: ...
    def get_state(self) -> DebuggerState: ...
    def get_current_location(self) -> dict[str, Any]: ...

    # --- Kernel connection variants ---
    def connect_kernel_net(self, port: int, key: str) -> bool:
        """Connect via KDNET: KernelDbg().attach('net:port=X,key=Y')"""
        ...

    def connect_kernel_local(self) -> bool:
        """Local kernel debugging (read-only, no breakpoints)."""
        ...

    def open_dump(self, dump_path: Path) -> bool:
        """Open crash dump for analysis."""
        ...

    # --- CDB subprocess for extension commands ---
    def _ensure_cdb(self) -> subprocess.Popen:
        """Spawn CDB subprocess for ! extension commands."""
        ...

    def execute_extension(self, command: str, timeout: int | None = None) -> str:
        """Execute a WinDbg extension command (e.g., '!analyze -v') via CDB."""
        ...

    def execute_command(self, command: str) -> str:
        """Execute any raw WinDbg command. Routes to Pybag or CDB as appropriate."""
        ...
```

**ABC Method -> Pybag COM mapping:**

| ABC Method | Pybag COM Call |
|---|---|
| `connect()` | `KernelDbg().attach("net:port=X,key=Y")` or `UserDbg().create("binary.exe")` |
| `set_breakpoint(addr)` | `dbg.bp(addr, handler_callback)` |
| `delete_breakpoint(addr)` | `dbg.bc(bp_id)` |
| `run()` | `dbg.go()` |
| `pause()` | `dbg.break_in()` |
| `step_into()` | `dbg.step_into()` |
| `step_over()` | `dbg.step_over()` |
| `get_registers()` | `dbg.regs` dict access |
| `read_memory(addr, size)` | `dbg.read(addr, size)` -> bytes directly |
| `write_memory(addr, data)` | `dbg.write(addr, data)` |
| `get_state()` | `dbg.execution_status` |
| `get_current_location()` | `dbg.reg.rip` + `dbg.disasm(rip, 1)` |

**Extension commands via CDB subprocess** (no COM equivalent):

| Operation | CDB Command |
|---|---|
| `get_driver_object()` | `!drvobj \Driver\Name 3` |
| `get_device_object()` | `!devobj addr` |
| `analyze_pool()` | `!pool addr` |
| `analyze_crash()` | `!analyze -v` |
| `decode_ioctl()` | `!ioctldecode code` |
| `get_object_directory()` | `!object \Device` |

### 2b. `commands.py` -- WinDbgCommands

High-level workflows, mirrors `src/engines/dynamic/x64dbg/commands.py`:

```python
class WinDbgCommands:
    def __init__(self, bridge: WinDbgBridge):
        self.bridge = bridge

    def ensure_connected(self) -> None: ...
    def get_status_summary(self) -> str: ...
    def dump_registers(self) -> str: ...
    def analyze_driver(self, driver_name: str) -> dict: ...
    def find_ioctl_handlers(self, driver_name: str) -> list[dict]: ...
    def analyze_crash_dump(self, dump_path: str) -> dict: ...
    def get_driver_vulnerability_surface(self, driver_name: str) -> dict: ...
```

### 2c. `windbg_tools.py` -- Phase 1 MCP Tools (20 tools)

Follows the exact pattern from `src/tools/dynamic_tools.py`:
- Module-level globals with lazy init (`_windbg_bridge`, `_windbg_commands`, `_session_manager`)
- `get_windbg_bridge()` reads env vars: `WINDBG_MODE`, `WINDBG_PATH`, `WINDBG_SYMBOL_PATH`, `WINDBG_TIMEOUT`
- `log_windbg_tool` decorator logs to session with `AnalysisType.KERNEL`
- `register_windbg_tools(app, session_manager)` registers all tools
- Platform check: tools return clear error on non-Windows

**Phase 2 Tool List (20 tools):**

Connection & Session:
1. `windbg_status` -- Debugger status summary
2. `windbg_connect_kernel` -- Connect via KDNET (port, key params)
3. `windbg_open_dump` -- Open .dmp crash dump
4. `windbg_disconnect` -- Disconnect/quit

Execution Control:
5. `windbg_run` -- Resume execution (`g`)
6. `windbg_pause` -- Break into debugger
7. `windbg_step_into` -- Trace (`t`)
8. `windbg_step_over` -- Step (`p`)
9. `windbg_run_and_wait` -- Run + wait for breakpoint
10. `windbg_wait_paused` -- Wait for debugger to pause

Breakpoints:
11. `windbg_set_breakpoint` -- Set bp (address or symbol)
12. `windbg_delete_breakpoint` -- Delete bp
13. `windbg_list_breakpoints` -- List all bps
14. `windbg_set_conditional_breakpoint` -- Conditional bp with command string

Inspection:
15. `windbg_get_registers` -- Read all registers
16. `windbg_read_memory` -- Read memory at address
17. `windbg_write_memory` -- Write memory
18. `windbg_disassemble` -- Disassemble at address
19. `windbg_get_modules` -- List loaded modules/drivers
20. `windbg_execute_command` -- Execute raw WinDbg command (escape hatch)

### 2d. Modify `server.py` -- Register WinDbg tools

At line 2866 in `main()`, add:

```python
# Register WinDbg kernel debugging tools
from src.tools.windbg_tools import register_windbg_tools
register_windbg_tools(app, session_manager)
```

### 2e. Modify `pyproject.toml` -- Add optional dependency

```toml
[project.optional-dependencies]
windbg = [
    "pybag>=2.2.0; sys_platform == 'win32'",
]
```

Conditional import in `bridge.py`:
```python
try:
    from pybag import UserDbg, KernelDbg, DbgEng
    PYBAG_AVAILABLE = True
except ImportError:
    PYBAG_AVAILABLE = False
```

Tools return `"WinDbg tools require Windows. Install with: pip install binary-mcp[windbg]"` when Pybag unavailable.

### 2f. Tests for Phase 2

- `tests/test_windbg_bridge.py`: Mock Pybag COM calls, test all 13 ABC methods, test auto-detection, test connect_kernel_net
- `tests/test_windbg_tools.py`: Test registration, test platform guard, test error handling

---

## Phase 3: Kernel Analysis Tools (25 tools)

Driver-specific and kernel-object tools for vulnerability research.

### Driver Analysis (7 tools):
21. `windbg_get_driver_object` -- `!drvobj \Driver\Name` -> DriverObject dataclass
22. `windbg_get_dispatch_table` -- `!drvobj \Driver\Name 3` -> IRP_MJ dispatch table
23. `windbg_get_device_object` -- `!devobj addr` -> DeviceObject dataclass
24. `windbg_get_device_stack` -- `!devstack addr`
25. `windbg_get_loaded_drivers` -- `lm k` (kernel modules only)
26. `windbg_analyze_driver` -- Full driver analysis workflow (high-level)
27. `windbg_find_driver_by_name` -- Search loaded drivers by pattern

### IOCTL Analysis (5 tools):
28. `windbg_decode_ioctl` -- Decompose IOCTL code -> IOCTLCode dataclass (with risk rating)
29. `windbg_find_ioctl_handlers` -- Find IRP_MJ_DEVICE_CONTROL handler + decompile
30. `windbg_trace_ioctl` -- Set bp on dispatch, send IOCTL, trace execution
31. `windbg_log_ioctls` -- Monitor all IOCTLs to a driver
32. `windbg_get_ioctl_buffer` -- Read IOCTL input/output buffer at breakpoint

### Pool Memory (5 tools):
33. `windbg_analyze_pool` -- `!pool addr` -> PoolAllocation
34. `windbg_search_pool_tag` -- `!poolfind tag` -> list of allocations
35. `windbg_get_pool_usage` -- `!poolused` -> usage statistics
36. `windbg_validate_pool` -- Check pool integrity around address
37. `windbg_track_pool_tag` -- Monitor alloc/free for specific tag

### Crash Dump Analysis (5 tools):
38. `windbg_analyze_crash` -- `!analyze -v` -> CrashAnalysis dataclass
39. `windbg_get_bugcheck` -- Bugcheck code + arguments
40. `windbg_get_crash_stack` -- Stack trace from crash context
41. `windbg_get_crash_registers` -- Register state at crash
42. `windbg_find_faulting_module` -- Identify faulting driver/module

### System Inspection (3 tools):
43. `windbg_get_processes` -- `!process 0 0` -> kernel process list
44. `windbg_get_system_info` -- `vertarget` -> target system details
45. `windbg_get_object_directory` -- `!object \Device` -> kernel namespace

---

## Phase 4: Advanced & Automated Workflows (15+ tools)

### LLM-Automated Vulnerability Analysis (5 tools):
46. `windbg_auto_analyze_driver` -- Automated vulnerability surface: dispatch table + IOCTL risk + pool usage + input validation gaps
47. `windbg_auto_trace_handler` -- Auto-trace IOCTL handler execution path with annotations
48. `windbg_auto_find_bugs` -- Run common kernel bug pattern checks (missing ProbeForRead, METHOD_NEITHER without validation, etc.)
49. `windbg_compare_dispatch_tables` -- Diff tables between driver versions
50. `windbg_generate_report` -- Generate structured vulnerability report

### Advanced Kernel (5 tools):
51. `windbg_set_hardware_breakpoint` -- Hardware bp (`ba`)
52. `windbg_get_irp` -- IRP inspection (`!irp`)
53. `windbg_get_handle_table` -- Handle table (`!handle`)
54. `windbg_search_kernel_memory` -- Kernel memory search (`s`)
55. `windbg_get_system_callbacks` -- System callbacks (`!callback`)

### Ghidra Cross-Reference (5 tools):
56. `windbg_resolve_static_address` -- Map runtime kernel addr to Ghidra addr (accounting for KASLR)
57. `windbg_set_bp_by_function` -- Set bp by Ghidra function name
58. `windbg_sync_with_ghidra` -- Push comments/annotations to Ghidra cache
59. `windbg_get_runtime_address` -- Resolve Ghidra function -> runtime address
60. `windbg_correlate_crash` -- Map crash address to decompiled source

Reuses existing `ProjectCache` from `src/engines/static/ghidra/project_cache.py` and the `_load_function_mappings` pattern from `src/tools/dynamic_tools.py:4429+`.

---

## Dependency Management

### pyproject.toml addition
```toml
[project.optional-dependencies]
windbg = ["pybag>=2.2.0; sys_platform == 'win32'"]
```

### Conditional imports in bridge.py
```python
import sys
try:
    from pybag import UserDbg, KernelDbg, DbgEng
    PYBAG_AVAILABLE = True
except ImportError:
    PYBAG_AVAILABLE = False

WINDOWS = sys.platform == "win32"
```

### CI strategy
- Parser tests + kernel_types tests run on all platforms (pure Python)
- Bridge tests use mocked Pybag, run on all platforms
- Integration tests marked `@pytest.mark.skipif(not WINDOWS)`, run only on Windows CI

---

## Environment Variables

```bash
WINDBG_PATH          # Path to Windows Debugging Tools (auto-detected)
WINDBG_MODE          # "kernel" | "user" | "dump" (default: "kernel")
WINDBG_SYMBOL_PATH   # Symbol server path (default: Microsoft public symbols)
WINDBG_TIMEOUT       # Command timeout in seconds (default: 30)
WINDBG_KDNET_PORT    # KDNET port (default: 50000)
WINDBG_KDNET_KEY     # KDNET encryption key
```

---

## Verification Plan

### Unit Tests (run on any platform)
```bash
make test  # All existing tests pass (no regressions)
pytest tests/test_kernel_types.py      # IOCTL decode, dataclasses
pytest tests/test_windbg_parser.py     # All output parsers
pytest tests/test_windbg_bridge.py     # Mocked Pybag bridge
pytest tests/test_windbg_tools.py      # Tool registration, platform guard
```

### Integration Tests (Windows with WinDbg only)
```bash
pytest tests/test_windbg_integration.py -m integration  # Real WinDbg
```

### Manual Verification
1. Start binary-mcp server: `uv run binary-mcp`
2. Verify WinDbg tools appear in tool list
3. On non-Windows: verify tools return clear "requires Windows" message
4. On Windows with WinDbg:
   - `windbg_status` returns debugger info
   - `windbg_open_dump("crash.dmp")` opens a dump file
   - `windbg_analyze_crash` returns structured crash analysis
   - `windbg_connect_kernel(port=50000, key="...")` connects to KDNET target
   - `windbg_get_loaded_drivers` lists kernel modules
   - `windbg_get_driver_object("\\Driver\\Vgk")` returns driver info with dispatch table

### Lint
```bash
make lint  # ruff passes on all new files
```

---

## Implementation Order Summary

| Phase | Scope | Files Created | Files Modified | Tools Added |
|-------|-------|---------------|----------------|-------------|
| 1 | Foundation | kernel_types.py, output_parser.py, error_logger.py, 3 test files | structured_errors.py, unified_session.py | 0 |
| 2 | Bridge + Core | bridge.py, commands.py, windbg_tools.py, __init__.py, 2 test files | server.py, pyproject.toml, dynamic/__init__.py | 20 |
| 3 | Kernel Analysis | (expand bridge.py, commands.py, windbg_tools.py) | - | 25 |
| 4 | Automation | (expand windbg_tools.py, commands.py) | - | 15+ |

**Total: ~60 MCP tools across 4 phases, 6 new Python modules, 5 test files**
