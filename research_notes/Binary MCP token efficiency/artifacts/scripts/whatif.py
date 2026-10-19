"""What-if re-renderings of measured outputs to estimate savings (ESTIMATES),
plus a session-replay experiment and an x64dbg hexdump simulation.

Usage: python -I whatif.py
"""
import asyncio
import json
import os
import random
import re
import sys

sys.path.insert(0, "/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts")
from common import SP, count, setup_env  # noqa: E402

setup_env({"GHIDRA_HOME": f"{SP}/fake_ghidra", "BINARY_MCP_AUTO_PDB": "never"})
RES = f"{SP}/out/results"
T = "o200k"


def tok(s):
    return count(s)[T]


import src.server as server  # noqa: E402
from src.utils import decompiler_caveats as dc  # noqa: E402
from src.utils import formatters as fm  # noqa: E402

server.register_all_tools()
import synthetic_ctx  # noqa: E402
from fastmcp import Client  # noqa: E402

out = {}

# ---------------- 1. envelope overhead
for kind in ("function list", "extracted strings", "decompiled pseudocode from the sample"):
    w = fm.wrap_untrusted("X", kind)
    out[f"envelope_overhead[{kind}]"] = tok(w) - tok("X")
out["notice_alone"] = tok(fm._UNTRUSTED_NOTICE)
out["notice_chars"] = len(fm._UNTRUSTED_NOTICE)
out["sentinel_pair_tokens"] = tok("⟦⟧")
minimal = "⟦untrusted:function list⟧\nX\n⟦/untrusted⟧"
out["minimal_envelope_overhead_example"] = tok(minimal) - tok("X")

# ---------------- 2. get_functions compact
ctx = synthetic_ctx.build("distlib_t64.exe")
funcs = [f for f in ctx["functions"] if not f["is_external"]][:100]
cur = open(f"{RES}/get_functions__synthetic-default100.txt").read()
compact = "address\tname\tsignature\tparams\tlocals\tcalls\n" + "\n".join(
    f"{f['address']}\t{f['name']}\t{f['signature'].split('(', 1)[1].rstrip(')')}\t{len(f['parameters'])}\t{len(f['local_variables'])}\t{len(f['called_functions'])}"
    for f in funcs)
compact_nosig = "address name calls\n" + "\n".join(f"{f['address']} {f['name']} {len(f['called_functions'])}" for f in funcs)
out["get_functions_100_current"] = tok(cur)
out["get_functions_100_tsv_with_sig"] = tok(compact)
out["get_functions_100_minimal_addr_name_calls"] = tok(compact_nosig)

# ---------------- 3. get_strings compact
strings = ctx["strings"][:100]
cur_s = open(f"{RES}/get_strings__synthetic-default100.txt").read()
comp_s = "address\txrefs\tvalue\n" + "\n".join(
    f"{s['address']}\t{','.join(x['from'] for x in s['xrefs'][:5])}\t{s['value'][:100]}" for s in strings)
comp_s2 = "address\tnrefs\tvalue\n" + "\n".join(f"{s['address']}\t{len(s['xrefs'])}\t{s['value'][:100]}" for s in strings)
out["get_strings_100_current"] = tok(cur_s)
out["get_strings_100_tsv_with_xref_addrs"] = tok(comp_s)
out["get_strings_100_tsv_count_only"] = tok(comp_s2)

# ---------------- 4. get_imports grouped
cur_i = open(f"{RES}/get_imports__synthetic-180.txt").read()
by = {}
for imp in ctx["imports"]:
    by.setdefault(imp["library"], []).append(imp["name"])
comp_i = "\n".join(f"{lib} ({len(n)}): {', '.join(sorted(n))}" for lib, n in by.items())
out["get_imports_180_current"] = tok(cur_i)
out["get_imports_180_grouped_csv"] = tok(comp_i)

# ---------------- 5. decompile_function signature dup + caveat summary
cur_d = open(f"{RES}/decompile_function__synthetic-80lines-artifacts.txt").read()
sig_line = re.search(r"^Signature: .*$", cur_d, re.M).group(0)
out["decompile_signature_line_tokens"] = tok(sig_line + "\n")
summ = [ln for ln in cur_d.split("\n") if ln.startswith("**Decompiler caveats") or (ln.startswith("- ") and " -- " in ln)]
cav = dc.find_caveats(fn := synthetic_ctx.build("x")["functions"][0]["pseudocode"])
short = "caveats: " + "; ".join(f"{c.kind}:{c.detail}@{c.line}" for c in cav)
out["caveat_summary_current_tokens"] = tok("\n".join(summ))
out["caveat_summary_short_tokens"] = tok(short)
out["caveat_kinds_in_example"] = len(cav)

# ---------------- 6. scan_pseudocode grouped by rule
cur_sc = open(f"{RES}/scan_pseudocode__synthetic-default.txt").read()
body = fm.strip_untrusted_envelope(cur_sc.split("\n\n_Showing")[0]) if "_Showing" in cur_sc else cur_sc
blocks = [b for b in re.split(r"\n\s*\n", body) if b.strip().startswith("[")]
groups = {}
for b in blocks:
    ls = b.strip().split("\n")
    m = re.match(r"\[(\w+) conf=(\d+)\] (\S+) \(([^)]*)\) -- (.*)$", ls[0])
    if not m:
        continue
    rule = m.group(3)
    g = groups.setdefault(rule, {"hdr": f"{rule} ({m.group(4)}) {m.group(1)}: {ls[1].strip()} | fix: {ls[-1].strip()[3:]}", "items": []})
    exc = next((x.strip()[len("excerpt: "):] for x in ls if x.strip().startswith("excerpt:")), "")
    g["items"].append(f"  {m.group(5)} conf={m.group(2)}: {exc}")
grouped = "\n".join(g["hdr"] + "\n" + "\n".join(g["items"]) for g in groups.values())
grouped_noexc = "\n".join(g["hdr"] + "\n" + "\n".join(i.split(": ", 1)[0] for i in g["items"]) for g in groups.values())
out["scan_pseudocode_50_findings_body_current"] = tok("\n\n".join(blocks))
out["scan_pseudocode_50_grouped_by_rule"] = tok(grouped)
out["scan_pseudocode_50_grouped_no_excerpt"] = tok(grouped_noexc)
out["scan_pseudocode_findings_parsed"] = len(blocks)
out["scan_pseudocode_rules"] = len(groups)

# ---------------- 7. batch_decompile single envelope
cur_b = open(f"{RES}/batch_decompile__synthetic-10.txt").read()
n_env = cur_b.count("BEGIN UNTRUSTED SAMPLE DATA")
per = tok(fm.wrap_untrusted("X", "decompiled pseudocode from the sample")) - tok("X")
out["batch_decompile_10_envelopes"] = n_env
out["batch_decompile_10_envelope_tokens_saved_if_one"] = (n_env - 1) * per

# ---------------- 8. structuredContent duplication totals across the measured calls
rows = json.load(open(f"{SP}/out/results_summary.json"))
tot_wire = sum(r["wire"][T] for r in rows if "wire" in r)
tot_text = sum(r["text"][T] for r in rows if "wire" in r)
tot_struct = sum(r["structured"][T] for r in rows if r.get("structured"))
out["all_calls_wire_o200k"] = tot_wire
out["all_calls_text_o200k"] = tot_text
out["all_calls_structured_o200k"] = tot_struct
out["calls_measured"] = sum(1 for r in rows if "wire" in r)
out["calls_with_structured_equal_to_text"] = sum(1 for r in rows if r.get("structured_equals_text"))
out["all_calls_envelope_overhead_o200k"] = sum(r.get("envelope_overhead_o200k", 0) for r in rows)
out["all_calls_caveat_o200k"] = sum(r.get("caveat_inline_o200k", 0) + r.get("caveat_summary_o200k", 0) for r in rows)

# ---------------- 9. x64dbg hexdump simulation (format copied from dynamic_tools.py:1863-1871)
rnd = random.Random(7)
data = bytes(rnd.randrange(256) for _ in range(256))
dump = []
for i in range(0, len(data), 16):
    chunk = data[i:i + 16]
    hex_str = " ".join(f"{b:02x}" for b in chunk)
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    dump.append(f"{i:08x}: {hex_str:<48}  {ascii_str}")
hd = "\n".join(["Memory at 0x401000 (256 bytes):", "-" * 60, fm.wrap_untrusted("\n".join(dump), kind="raw memory read from the debugged process")])
out["x64dbg_read_memory_256B_simulated_o200k"] = tok(hd)
out["x64dbg_read_memory_256B_hex_only_o200k"] = tok(data.hex())
out["x64dbg_read_memory_256B_base64_o200k"] = tok(__import__("base64").b64encode(data).decode())


# ---------------- 10. session replay experiment
async def replay():
    pe = f"{SP}/pe_samples/distlib_t64.exe"
    res = {}
    async with Client(server.app) as c:
        r = await c.call_tool_mcp("start_analysis_session", {"binary_path": pe, "name": "token-audit"})
        txt = r.content[0].text
        res["start_session_o200k"] = tok(txt)
        sid = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", txt).group(0)
        singles = 0
        for name, args in [("get_functions", {"binary_path": pe}),
                           ("get_strings", {"binary_path": pe}),
                           ("decompile_function", {"binary_path": pe, "function_name": "entry"}),
                           ("decompile_function", {"binary_path": pe, "function_name": "parse_config"}),
                           ("get_imports", {"binary_path": pe})]:
            rr = await c.call_tool_mcp(name, args)
            singles += tok(rr.content[0].text)
        res["sum_of_5_call_outputs_o200k"] = singles
        await c.call_tool_mcp("save_session", {"session_id": sid})
        for name, args in [("get_session_summary", {"session_id": sid}),
                           ("load_full_session", {"session_id": sid}),
                           ("generate_report", {"session_id": sid})]:
            rr = await c.call_tool_mcp(name, args)
            t = rr.content[0].text
            res[f"{name}_o200k"] = tok(t)
            open(f"{RES}/{name}__session.txt", "w").write(t)
        await c.call_tool_mcp("delete_session", {"session_id": sid})
    return res

out.update(asyncio.run(replay()))

for k, v in out.items():
    print(f"{k:60s} {v}")
json.dump(out, open(f"{SP}/out/whatif.json", "w"), indent=1)
