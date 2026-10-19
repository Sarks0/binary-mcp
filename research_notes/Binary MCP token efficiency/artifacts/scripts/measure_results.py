"""Call tools in memory (fastmcp.Client(app)) and measure raw CallToolResults.

Ghidra-backed tools read a SYNTHETIC analysis cache (synthetic_ctx.py) written
through the server's own ProjectCache.save_cached into the scratchpad cache.
Triage tools read real, benign PE files (pip/distlib launchers) staged in
scratchpad/pe_samples. Nothing in samples/ is executed.

Usage: python -I measure_results.py
Writes out/results/*.txt (content text) and out/results_summary.json.
"""
import asyncio
import json
import os
import re
import sys
import time

sys.path.insert(0, "/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts")
from common import SP, count, jdump, setup_env  # noqa: E402

setup_env({"GHIDRA_HOME": f"{SP}/fake_ghidra", "BINARY_MCP_AUTO_PDB": "never"})
OUT = f"{SP}/out/results"
os.makedirs(OUT, exist_ok=True)

from mcp.types import JSONRPCMessage, JSONRPCResponse  # noqa: E402

import src.server as server  # noqa: E402
from src.utils import formatters  # noqa: E402

server.register_all_tools()
import synthetic_ctx  # noqa: E402
from fastmcp import Client  # noqa: E402

PE64 = f"{SP}/pe_samples/distlib_t64.exe"
PE32 = f"{SP}/pe_samples/distlib_w32.exe"
PERUST = f"{SP}/pe_samples/clipboard_x86_64.exe"
CSRC = "/home/user/binary-mcp/samples/test_malware.c"

ctx64 = synthetic_ctx.build("distlib_t64.exe")
ctx32 = synthetic_ctx.build("distlib_w32.exe", n_funcs=550)
assert server.cache.save_cached(PE64, ctx64)
assert server.cache.save_cached(PE32, ctx32)

fn_by_name = {f["name"]: f for f in ctx64["functions"]}
small = next(f["name"] for f in ctx64["functions"][20:] if f["pseudocode"] and f["pseudocode"].count("\n") <= 25)
medium = "main"          # 80 lines, artifacts (i=1 -> 1%3!=0 -> no artifacts) -- see below
art80 = "entry"           # 80 lines with artifacts (i=0)
large = "parse_config"    # 300 lines (i=2 -> no artifacts)
ten = [f["name"] for f in ctx64["functions"][:10]]
fifty = [f["name"] for f in ctx64["functions"][:50]]

ENV_OPEN = formatters.UNTRUSTED_OPEN_SENTINEL + "BEGIN UNTRUSTED SAMPLE DATA"
NOTICE = formatters._UNTRUSTED_NOTICE
ENV_END = formatters.UNTRUSTED_END_MARKER


def strip_envelopes(text):
    keep = []
    for ln in text.split("\n"):
        if ln.startswith(ENV_OPEN) or ln == NOTICE or ln == ENV_END:
            continue
        keep.append(ln)
    return "\n".join(keep)


CAVEAT_INLINE = re.compile(r"  /\* \[caveat\] .*? \*/")


def caveat_tokens(text):
    inline = "".join(m.group(0) for m in CAVEAT_INLINE.finditer(text))
    summ = []
    on = False
    for ln in text.split("\n"):
        if ln.startswith("**Decompiler caveats"):
            on = True
            summ.append(ln)
            continue
        if on:
            if ln.startswith("- "):
                summ.append(ln)
            else:
                on = False
    return count(inline)["o200k"] if inline else 0, count("\n".join(summ))["o200k"] if summ else 0, len(summ)


CALLS = [
    # ---- admin / no-engine
    ("diagnose_setup", {}, ""),
    ("diagnose_dotnet_setup", {}, ""),
    ("job_list", {}, ""),
    ("list_sessions", {}, ""),
    ("get_active_session", {}, ""),
    ("vt_lookup", {"file_hash": "81a618f21cb87db9076134e70388b6e9cb7c2106739011b6a51772d22cae06b7"}, "no-key"),
    ("vt_check_api", {}, "no-key"),
    # ---- triage on real benign PEs
    ("check_binary", {"binary_path": PE64}, "t64"),
    ("quick_scan", {"binary_path": PE64}, "t64"),
    ("quick_scan", {"binary_path": PERUST}, "rust331k"),
    ("detect_packers", {"binary_path": PE64}, "t64"),
    ("extract_iocs", {"binary_path": PE64}, "t64"),
    ("extract_iocs", {"binary_path": PERUST}, "rust331k"),
    ("get_pe_info", {"binary_path": PE64}, "t64-standard"),
    ("get_pe_info", {"binary_path": PE64, "detail_level": "full"}, "t64-full"),
    ("get_pe_info", {"binary_path": PERUST}, "rust331k-standard"),
    ("get_pe_info", {"binary_path": PERUST, "detail_level": "full"}, "rust331k-full"),
    ("inspect_authenticode", {"binary_path": PE64}, "t64"),
    ("compute_similarity_hashes", {"binary_path": PE64}, "t64"),
    ("detect_crypto_patterns", {"binary_path": PE64}, "t64"),
    ("analyze_xor_encryption", {"binary_path": PE64}, "t64"),
    ("detect_python_packer", {"binary_path": PE64}, "t64"),
    ("search_bytes", {"binary_path": PE64, "pattern": "48 8B"}, "t64-common-pattern"),
    ("find_vtables", {"binary_path": PE64}, "t64"),
    ("extract_embedded_binaries", {"binary_path": PERUST}, "rust331k"),
    ("generate_yara_rule_from_strings", {"binary_path": PE64}, "t64"),
    # ---- Ghidra-backed via synthetic cache
    ("analyze_binary", {"binary_path": PE64}, "synthetic-warm"),
    ("get_functions", {"binary_path": PE64}, "synthetic-default100"),
    ("get_functions", {"binary_path": PE64, "limit": 600}, "synthetic-600"),
    ("get_imports", {"binary_path": PE64}, "synthetic-180"),
    ("get_strings", {"binary_path": PE64}, "synthetic-default100"),
    ("get_strings", {"binary_path": PE64, "limit": 1000}, "synthetic-1000"),
    ("get_memory_map", {"binary_path": PE64}, "synthetic"),
    ("extract_metadata", {"binary_path": PE64}, "synthetic"),
    ("list_data_types", {"binary_path": PE64}, "synthetic"),
    ("find_api_calls", {"binary_path": PE64}, "synthetic"),
    ("detect_crypto", {"binary_path": PE64}, "synthetic"),
    ("generate_iocs", {"binary_path": PE64}, "synthetic"),
    ("get_xrefs", {"binary_path": PE64, "function_name": "FUN_" + synthetic_ctx._addr(25)}, "synthetic"),
    ("get_call_graph", {"binary_path": PE64, "function_name": "main"}, "synthetic-depth2"),
    ("get_call_graph", {"binary_path": PE64, "function_name": "main", "depth": 4}, "synthetic-depth4"),
    ("decompile_function", {"binary_path": PE64, "function_name": small}, "synthetic-small"),
    ("decompile_function", {"binary_path": PE64, "function_name": medium}, "synthetic-80lines"),
    ("decompile_function", {"binary_path": PE64, "function_name": art80}, "synthetic-80lines-artifacts"),
    ("decompile_function", {"binary_path": PE64, "function_name": large}, "synthetic-300lines"),
    ("decompile_functions", {"binary_path": PE64, "function_names": ten}, "synthetic-10"),
    ("decompile_functions", {"binary_path": PE64, "function_names": fifty}, "synthetic-50"),
    ("batch_decompile", {"binary_path": PE64, "functions": ",".join(ten)}, "synthetic-10"),
    ("expand_callgraph", {"binary_path": PE64, "root": "main"}, "synthetic-depth2"),
    ("get_review_package", {"binary_path": PE64, "function_name_or_address": art80}, "synthetic-80lines-artifacts"),
    ("get_review_package", {"binary_path": PE64, "function_name_or_address": large}, "synthetic-300lines"),
    ("scan_pseudocode", {"binary_path": PE64}, "synthetic-default"),
    ("get_function_callers", {"binary_path": PE64, "function_name_or_address": "FUN_" + synthetic_ctx._addr(25)}, "synthetic"),
    ("get_switch_tables", {"binary_path": PE64}, "synthetic"),
    ("get_param_sinks", {"binary_path": PE64, "function": art80}, "synthetic"),
    ("detect_malware_behaviors", {"binary_path": PE64}, "synthetic"),
    ("find_anti_analysis", {"binary_path": PE64}, "synthetic"),
    ("detect_dynamic_api_resolution", {"binary_path": PE64}, "synthetic"),
    ("analyze_api_call_chains", {"binary_path": PE64}, "synthetic"),
    ("extract_iocs_with_context", {"binary_path": PE64}, "synthetic"),
    ("find_stack_strings", {"binary_path": PE64}, "synthetic"),
    ("analyze_control_flow", {"binary_path": PE64, "function_name_or_address": large}, "synthetic-300lines"),
    ("detect_loops", {"binary_path": PE64, "function_name_or_address": large}, "synthetic-300lines"),
    ("find_dead_code", {"binary_path": PE64}, "synthetic"),
    ("get_function_complexity", {"binary_path": PE64, "function_name_or_address": large}, "synthetic"),
    ("get_function_hash", {"binary_path": PE64, "function_name_or_address": large}, "synthetic"),
    ("analyze_function_completeness", {"binary_path": PE64, "function_name_or_address": large}, "synthetic"),
    ("find_similar_functions", {"binary_path": PE64, "target_binary_path": PE32}, "synthetic"),
    ("find_inlined_clones", {"binary_path": PE64}, "synthetic"),
    ("find_ioctl_handlers", {"binary_path": PE64}, "synthetic"),
    ("fid_match", {"binary_path": PE64}, "synthetic"),
    ("diff_binaries", {"old_path": PE32, "new_path": PE64, "record_examination": False}, "synthetic"),
    ("coverage_index", {"binary_path": PE64}, "synthetic"),
    ("get_coverage_status", {"binary_path": PE64}, "synthetic"),
    ("get_next_unreviewed", {"binary_path": PE64}, "synthetic-20"),
    ("get_notes", {"binary_path": PE64}, "synthetic-empty"),
    # ---- debuggers (no debugger available on this Linux host)
    ("x64dbg_status", {}, "no-debugger"),
    ("x64dbg_session", {"op": "nonexistent_op"}, "bad-op"),
    ("windbg_status", {}, "linux"),
    ("windbg_execute_command", {"command": "lm"}, "linux-disabled"),
    # ---- errors
    ("get_pe_info", {"binary_path": "/etc/passwd"}, "err-outside-allowlist"),
    ("get_pe_info", {"binary_path": f"{SP}/pe_samples/does_not_exist.exe"}, "err-missing-file"),
    ("get_pe_info", {"binary_path": CSRC}, "err-not-a-pe"),
    ("decompile_function", {"binary_path": PE64, "function_name": "no_such_function"}, "err-unknown-function"),
    ("job_status", {"job_id": "nope"}, "err-bad-job"),
    ("get_session_summary", {"session_id": "nope"}, "err-bad-session"),
]


def wire(result_model, rid):
    resp = JSONRPCResponse(jsonrpc="2.0", id=rid,
                           result=result_model.model_dump(by_alias=True, mode="json", exclude_none=True))
    return JSONRPCMessage(resp).model_dump_json(by_alias=True, exclude_none=True)


async def main():
    rows = []
    async with Client(app := server.app) as c:  # noqa: F841
        for i, (tool, args, label) in enumerate(CALLS):
            t0 = time.time()
            try:
                res = await asyncio.wait_for(c.call_tool_mcp(tool, args), timeout=180)
            except Exception as e:  # noqa: BLE001
                rows.append({"tool": tool, "label": label, "exception": repr(e)[:300]})
                print(f"{tool:32s} {label:28s} EXC {e!r}"[:200])
                continue
            w = wire(res, i + 10)
            texts = [b.text for b in res.content if getattr(b, "type", "") == "text"]
            text = "\n".join(texts)
            sc = res.structuredContent
            n_env = text.count(ENV_OPEN)
            stripped = strip_envelopes(text)
            ct, cs, cn = caveat_tokens(text)
            row = {
                "tool": tool, "label": label, "isError": res.isError, "secs": round(time.time() - t0, 2),
                "wire": count(w), "text": count(text),
                "structured": count(jdump(sc)) if sc is not None else None,
                "structured_equals_text": (isinstance(sc, dict) and sc.get("result") == text),
                "n_content_blocks": len(res.content),
                "envelopes": n_env,
                "envelope_overhead_o200k": count(text)["o200k"] - count(stripped)["o200k"] if n_env else 0,
                "caveat_inline_o200k": ct, "caveat_summary_o200k": cs, "caveat_summary_lines": cn,
                "lines": text.count("\n") + 1 if text else 0,
            }
            rows.append(row)
            fn = f"{OUT}/{tool}__{label or 'default'}.txt".replace(" ", "_")
            with open(fn, "w") as f:
                f.write(text)
            print(f"{tool:32s} {label:28s} err={str(res.isError)[0]} text_o200k={row['text']['o200k']:6d} "
                  f"wire_o200k={row['wire']['o200k']:6d} bytes={row['wire']['bytes']:7d} env={n_env} "
                  f"envtok={row['envelope_overhead_o200k']:4d} cav={ct}+{cs} dup={row['structured_equals_text']}")
    json.dump(rows, open(f"{SP}/out/results_summary.json", "w"), indent=1)


asyncio.run(main())
