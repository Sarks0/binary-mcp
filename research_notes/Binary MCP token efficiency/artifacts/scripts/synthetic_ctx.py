"""Deterministic synthetic Ghidra analysis context (shape copied from
src/engines/static/ghidra/scripts/core_analysis.py:762-1070).

Profile ("medium native sample"): 600 internal functions + 60 external thunks,
180 imports over 8 DLLs, 1200 strings, 7 memory blocks, 40 structs, 15 enums.
Pseudocode is Ghidra-style C generated from a line pool, with known artifacts
(unaff_/extraout_/in_stack_, variadic calls, /GS helpers) sprinkled in so the
caveat renderer has realistic work.
"""
import random

R = random.Random(1337)
BASE = 0x140001000

DLLS = {
    "KERNEL32.DLL": ["CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "GetModuleFileNameW",
                     "VirtualAlloc", "VirtualProtect", "VirtualFree", "LoadLibraryW", "GetProcAddress",
                     "CreateThread", "WaitForSingleObject", "Sleep", "GetTickCount", "CreateProcessW",
                     "OpenProcess", "WriteProcessMemory", "CreateRemoteThread", "GetLastError",
                     "HeapAlloc", "HeapFree", "GetProcessHeap", "IsDebuggerPresent", "FindFirstFileW",
                     "FindNextFileW", "FindClose", "GetTempPathW", "DeleteFileW", "MoveFileExW",
                     "GetComputerNameW", "GetSystemInfo", "QueryPerformanceCounter", "GetCurrentProcessId",
                     "TerminateProcess", "CreateMutexW", "OpenMutexW", "ExitProcess", "GetCommandLineW",
                     "MultiByteToWideChar", "WideCharToMultiByte", "lstrlenW", "lstrcpyW", "SetFilePointer",
                     "GetFileSize", "CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW",
                     "GetEnvironmentVariableW", "ExpandEnvironmentStringsW", "SetLastError"],
    "ADVAPI32.DLL": ["RegOpenKeyExW", "RegSetValueExW", "RegQueryValueExW", "RegCloseKey", "RegCreateKeyExW",
                     "OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueW", "CryptAcquireContextW",
                     "CryptCreateHash", "CryptHashData", "CryptDeriveKey", "CryptDecrypt", "CryptEncrypt",
                     "CryptReleaseContext", "CreateServiceW", "OpenSCManagerW", "StartServiceW", "GetUserNameW",
                     "CloseServiceHandle"],
    "WININET.DLL": ["InternetOpenW", "InternetConnectW", "HttpOpenRequestW", "HttpSendRequestW",
                    "InternetReadFile", "InternetCloseHandle", "InternetSetOptionW", "HttpQueryInfoW",
                    "InternetOpenUrlW", "InternetCrackUrlW"],
    "WS2_32.DLL": ["WSAStartup", "socket", "connect", "send", "recv", "closesocket", "gethostbyname",
                   "inet_addr", "htons", "WSACleanup", "getaddrinfo", "freeaddrinfo"],
    "USER32.DLL": ["MessageBoxW", "GetForegroundWindow", "GetWindowTextW", "SetWindowsHookExW",
                   "GetAsyncKeyState", "FindWindowW", "wsprintfW", "ShowWindow", "GetDesktopWindow",
                   "CallNextHookEx", "UnhookWindowsHookEx", "GetKeyboardState"],
    "SHELL32.DLL": ["ShellExecuteW", "SHGetFolderPathW", "SHGetSpecialFolderPathW", "CommandLineToArgvW"],
    "NTDLL.DLL": ["NtQueryInformationProcess", "RtlGetVersion", "NtUnmapViewOfSection", "RtlDecompressBuffer",
                  "NtQuerySystemInformation", "RtlInitUnicodeString", "LdrLoadDll", "NtAllocateVirtualMemory"],
    "MSVCRT.DLL": [f"crt_fn_{i:02d}" for i in range(64)],
}

STR_POOL = [
    "http://update-check.example.net/gate.php?id=%s&v=%d",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "%APPDATA%\\Microsoft\\svchost.exe", "cmd.exe /c del /f /q \"%s\"", "\\\\.\\pipe\\msupdate_%08x",
    "Global\\{6A3F2C71-9E1B-4C55-8D2E-4F0A1B7C9D33}", "185.220.101.47", "c2.example-cdn.org",
    "POST", "GET", "Content-Type: application/x-www-form-urlencoded", "kernel32.dll", "ntdll.dll",
    "IsDebuggerPresent", "VirtualAllocEx", "Error opening file: %s (code %d)", "Invalid configuration block",
    "Unknown command received", "beacon interval=%u jitter=%u", "SeDebugPrivilege", "vmtoolsd.exe",
    "VBoxService.exe", "wireshark.exe", "procmon.exe", "%s\\%s.tmp", "Software\\Classes\\CLSID\\%s",
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/", "AES-256-CBC", "config.dat",
    "Failed to allocate %zu bytes", "Shutdown requested", "user32.dll", "explorer.exe", "rundll32.exe %s,Start",
]

LINE_POOL = [
    "  local_18 = DAT_14001e040 ^ (ulonglong)auStack_238;",
    "  iVar1 = GetModuleFileNameW((HMODULE)0x0,local_218,0x104);",
    "  if (iVar1 == 0) {",
    "    uVar2 = FUN_{callee}(param_1,0);",
    "    goto LAB_{lab};",
    "  }",
    "  lVar3 = (**(code **)(*param_1 + 0x18))(param_1,param_2,&local_res10);",
    "  for (uVar4 = 0; uVar4 < param_3; uVar4 = uVar4 + 1) {",
    "    *(byte *)(lVar3 + uVar4) = *(byte *)(lVar3 + uVar4) ^ 0x5a;",
    "  }",
    "  hFile = CreateFileW(local_218,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);",
    "  if (hFile == (HANDLE)0xffffffffffffffff) {",
    "    dwErr = GetLastError();",
    "    FUN_{callee}(L\"open failed\",dwErr);",
    "    return 0;",
    "  }",
    "  BVar5 = ReadFile(hFile,pbVar6,local_220,&local_224,(LPOVERLAPPED)0x0);",
    "  memset(local_158,0,0x100);",
    "  uVar7 = *(uint *)(param_1 + 0x10) & 0xfffffff0;",
    "  *(undefined8 *)(param_1 + 0x28) = uVar2;",
    "  local_c8 = (undefined4)((ulonglong)param_2 >> 0x20);",
    "  switch(*(undefined4 *)(param_1 + 8)) {",
    "  case 0:",
    "    uVar2 = FUN_{callee}(param_1);",
    "    break;",
    "  default:",
    "    uVar2 = 0xffffffff;",
    "  }",
    "  CloseHandle(hFile);",
    "  pvVar8 = VirtualAlloc((LPVOID)0x0,(SIZE_T)local_220,0x3000,0x40);",
    "  FUN_{callee}(pvVar8,pbVar6,local_220);",
    "  while (*pwVar9 != L'\\0') {",
    "    pwVar9 = pwVar9 + 1;",
    "  }",
    "  lVar3 = FUN_{callee}(&DAT_14001f2a0,s_SOFTWARE_Microsoft_Windows_Curren_14001c3f0);",
]
ARTIFACT_LINES = [
    "  wsprintfW(local_218,L\"%s\\\\%s\",param_2);",
    "  uVar2 = extraout_RAX;",
    "  *(undefined8 *)(param_1 + 0x30) = in_stack_00000028;",
    "  __security_check_cookie(local_18 ^ (ulonglong)auStack_238);",
    "  (*_guard_dispatch_icall)(lVar3,param_2);",
]


def _addr(i):
    return f"{BASE + i * 0x80:x}"


def pseudocode(name, n_lines, with_artifacts):
    out = [f"undefined8 {name}(longlong *param_1,undefined8 param_2,uint param_3)", "", "{",
           "  int iVar1;", "  undefined8 uVar2;", "  longlong lVar3;", "  ulonglong uVar4;",
           "  HANDLE hFile;", "  DWORD dwErr;", "  undefined auStack_238 [32];",
           "  WCHAR local_218 [264];", "  ulonglong local_18;", "  "]
    k = 0
    while len(out) < n_lines - 2:
        ln = LINE_POOL[k % len(LINE_POOL)]
        ln = ln.replace("{callee}", _addr(R.randrange(600))).replace("{lab}", _addr(R.randrange(600)))
        out.append(ln)
        k += 1
        if with_artifacts and k % 23 == 7:
            out.append(ARTIFACT_LINES[(k // 23) % len(ARTIFACT_LINES)])
    out.append("  return unaff_RBX;" if with_artifacts else "  return uVar2;")
    out.append("}")
    return "\n".join(out) + "\n"


NAMED = ["entry", "main", "parse_config", "send_beacon", "decrypt_buffer", "install_persistence",
         "enum_processes", "inject_payload", "check_vm", "resolve_apis", "keylog_hook", "upload_file",
         "handle_command", "init_crypto", "read_registry", "write_registry", "spawn_shell",
         "download_stage2", "parse_response", "build_request"]


def size_for(i):
    # distribution of body sizes (lines): mostly small, some medium, few large
    if i in (0, 1):
        return 80
    if i == 2:
        return 300
    r = R.random()
    if r < 0.55:
        return R.randint(12, 30)
    if r < 0.85:
        return R.randint(31, 90)
    if r < 0.97:
        return R.randint(91, 200)
    return R.randint(201, 500)


def build(binary_name, n_funcs=600, n_strings=1200):
    imports = []
    ext_funcs = []
    j = 0
    for lib, names in DLLS.items():
        for n in names:
            if len(imports) >= 180:
                break
            imports.append({"library": lib, "name": n, "address": f"EXTERNAL:{j:08x}",
                            "is_function": True, "ordinal": None})
            if len(ext_funcs) < 60:
                ext_funcs.append({"name": n, "address": f"EXTERNAL:{j:08x}"})
            j += 1
    funcs = []
    for i in range(n_funcs):
        name = NAMED[i] if i < len(NAMED) else (f"FUN_{_addr(i)}" if R.random() < 0.8 else f"sub_helper_{i}")
        nl = size_for(i)
        art = (i % 3 == 0)
        callees = [{"name": f"FUN_{_addr(c)}" if c >= len(NAMED) else NAMED[c], "address": _addr(c)}
                   for c in R.sample(range(n_funcs), R.randint(1, 6)) if c != i]
        callees += [{"name": e["name"], "address": e["address"]} for e in R.sample(ext_funcs, R.randint(0, 4))]
        n_bb = max(1, nl // 6)
        funcs.append({
            "name": name, "namespace": "Global", "address": _addr(i), "size": nl * 9,
            "signature": f"undefined8 {name}(longlong * param_1, undefined8 param_2, uint param_3)",
            "is_thunk": False, "is_external": False, "name_source": "DEFAULT" if name.startswith("FUN_") else "USER_DEFINED",
            "parameters": [{"name": "param_1", "datatype": "longlong *", "storage": "RCX:8"},
                           {"name": "param_2", "datatype": "undefined8", "storage": "RDX:8"},
                           {"name": "param_3", "datatype": "uint", "storage": "R8D:4"}],
            "local_variables": [{"name": "local_18", "datatype": "ulonglong", "storage": "Stack[-0x18]:8"},
                                {"name": "local_218", "datatype": "WCHAR[264]", "storage": "Stack[-0x218]:528"}],
            "called_functions": callees,
            "call_sites": [], "indirect_calls": [],
            "pseudocode": pseudocode(name, nl, art),
            "basic_blocks": [{"start": f"{BASE + i * 0x80 + b * 0x10:x}", "end": f"{BASE + i * 0x80 + b * 0x10 + 0xf:x}",
                              "num_addresses": 16} for b in range(n_bb)],
            "jump_tables": [], "fid_match": None, "plate_comment": "", "instruction_comments": [],
            "decompile_status": "success",
        })
    for e in ext_funcs:
        funcs.append({"name": e["name"], "namespace": "KERNEL32.DLL", "address": e["address"], "size": 0,
                      "signature": f"undefined {e['name']}(void)", "is_thunk": False, "is_external": True,
                      "name_source": "IMPORTED", "parameters": [], "local_variables": [], "called_functions": [],
                      "call_sites": [], "indirect_calls": [], "pseudocode": None, "basic_blocks": [],
                      "jump_tables": [], "fid_match": None, "plate_comment": "", "instruction_comments": [],
                      "decompile_status": "skipped_thunk_or_external"})
    strings = []
    for s in range(n_strings):
        if s < len(STR_POOL):
            v = STR_POOL[s]
        else:
            v = R.choice(["Error: %s", "%s=%s", "Initializing module %d", "status_%04x", "Retrying in %u ms",
                          "opt_" + "".join(R.choice("abcdefghijklmnop") for _ in range(R.randint(4, 14))),
                          "".join(R.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(R.randint(4, 9)))])
        strings.append({"address": f"14001{c:04x}".replace("c", "") if False else f"{0x14001c000 + s * 0x20:x}",
                        "value": v, "length": len(v), "type": R.choice(["string", "unicode", "TerminatedCString"]),
                        "xrefs": [{"from": _addr(R.randrange(n_funcs)), "type": "DATA"} for _ in range(R.randint(0, 3))]})
    mm = [{"name": n, "start": f"{0x140000000 + o:x}", "end": f"{0x140000000 + o + sz - 1:x}", "size": sz,
           "read": True, "write": w, "execute": x, "initialized": True, "comment": ""}
          for n, o, sz, w, x in [("Headers", 0, 0x400, False, False), (".text", 0x1000, 0x1a000, False, True),
                                 (".rdata", 0x1b000, 0x8000, False, False), (".data", 0x23000, 0x2000, True, False),
                                 (".pdata", 0x25000, 0x1000, False, False), (".rsrc", 0x26000, 0x3000, False, False),
                                 (".reloc", 0x29000, 0x800, False, False)]]
    structs = [{"name": f"struct_{i}", "size": 8 * (i + 2), "category": "/auto_structs",
                "fields": [{"name": f"field_0x{k * 8:x}", "datatype": "undefined8", "offset": k * 8} for k in range(i % 6 + 2)]}
               for i in range(40)]
    enums = [{"name": f"enum_{i}", "size": 4, "values": {f"VAL_{k}": k for k in range(5)}} for i in range(15)]
    return {
        "metadata": {"name": binary_name, "executable_path": f"/samples/{binary_name}",
                     "executable_format": "Portable Executable (PE)", "language": "x86:LE:64:default",
                     "language_description": "x86/little/64/default", "compiler": "windows",
                     "image_base": "140000000", "min_address": "140000000", "max_address": "140029fff",
                     "creation_date": "Mon Oct 19 12:00:00 UTC 2026", "analysis_depth": "full"},
        "functions": funcs, "imports": imports,
        "exports": [{"name": "entry", "address": _addr(0), "type": "Function"}],
        "strings": strings, "memory_map": mm, "xrefs": {},
        "data_types": {"structures": structs, "enums": enums},
        "analysis_stats": {"functions_analyzed": n_funcs, "functions_skipped": 0, "decompile_failures": 0,
                           "decompile_timeouts": 0, "thread_timeouts": 0, "internal_timeouts": 0,
                           "partial_results": False, "function_timeout_setting": 30,
                           "max_functions_setting": None},
        "skipped_functions": [],
    }
