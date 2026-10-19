"""Analyse the dumped tools/list: totals, per-component split, heaviest tools,
per-category totals, docstring-section duplication and JSON-Schema bloat.

Usage: python -I analyze_tools_list.py OUT_PREFIX   (reads OUT_PREFIX_tools.json)
Writes OUT_PREFIX_analysis.json and prints a human summary.
"""
import copy
import json
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, "/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts")
from common import count, jdump  # noqa: E402

prefix = sys.argv[1]
raw = open(f"{prefix}_tools.json").read()
msg = json.loads(raw)
tools = msg["result"]["tools"]
T = "o200k"

report = {}
report["wire_total"] = count(raw)
report["tools_array_only"] = count(jdump(tools))
report["n_tools"] = len(tools)

# ---- keys present
keyset = Counter()
for t in tools:
    keyset.update(t.keys())
report["keys_present"] = dict(keyset)

# ---- per-component split (count each "key":value fragment separately)
COMPONENTS = ["name", "title", "description", "inputSchema", "outputSchema",
              "annotations", "_meta", "execution", "icons"]
comp_tot = defaultdict(lambda: defaultdict(int))
per_tool = []
for t in tools:
    row = {"name": t["name"], "total": count(jdump(t))}
    for k in t:
        frag = jdump({k: t[k]})[1:-1]  # "key":value
        c = count(frag)
        row["name_frag" if k == "name" else k] = c
        for m, v in c.items():
            comp_tot[k][m] += v
    tags = (t.get("_meta") or {}).get("_fastmcp", {}).get("tags", [])
    row["category"] = next((x.split(":", 1)[1] for x in tags if x.startswith("category:")), "?")
    row["facets"] = [x for x in tags if not x.startswith("category:")]
    per_tool.append(row)
report["component_totals"] = {k: dict(v) for k, v in comp_tot.items()}

# ---- model-facing projection: what an Anthropic-API tool definition carries
proj = [{"name": t["name"], "description": t.get("description", ""),
         "input_schema": t["inputSchema"]} for t in tools]
report["projection_name_desc_input"] = count(jdump(proj))
proj_nodesc = [{"name": t["name"], "input_schema": t["inputSchema"]} for t in tools]
report["projection_name_input_only"] = count(jdump(proj_nodesc))

# ---- heaviest tools
per_tool.sort(key=lambda r: -r["total"][T])
report["top25"] = [
    {"name": r["name"], "category": r["category"], "total_o200k": r["total"][T],
     "desc_o200k": r.get("description", {}).get(T, 0),
     "input_o200k": r.get("inputSchema", {}).get(T, 0),
     "output_o200k": r.get("outputSchema", {}).get(T, 0),
     "meta_o200k": r.get("_meta", {}).get(T, 0),
     "bytes": r["total"]["bytes"]}
    for r in per_tool[:25]]
report["top25_share_o200k"] = sum(r["total"][T] for r in per_tool[:25])

# ---- by category
cat = defaultdict(lambda: {"tools": 0, "o200k": 0, "cl100k": 0, "bytes": 0,
                           "desc_o200k": 0, "input_o200k": 0})
for r in per_tool:
    c = cat[r["category"]]
    c["tools"] += 1
    c["o200k"] += r["total"]["o200k"]
    c["cl100k"] += r["total"]["cl100k"]
    c["bytes"] += r["total"]["bytes"]
    c["desc_o200k"] += r.get("description", {}).get("o200k", 0)
    c["input_o200k"] += r.get("inputSchema", {}).get("o200k", 0)
report["by_category"] = dict(sorted(cat.items(), key=lambda kv: -kv[1]["o200k"]))

# ---- debugger tools
x64 = [t["name"] for t in tools if t["name"].startswith("x64dbg_")]
wdb = [t["name"] for t in tools if t["name"].startswith("windbg_")]
dbg_tok = sum(r["total"][T] for r in per_tool if r["name"].startswith(("x64dbg_", "windbg_")))
report["debugger"] = {"x64dbg": len(x64), "windbg": len(wdb), "o200k": dbg_tok,
                      "x64dbg_o200k": sum(r["total"][T] for r in per_tool if r["name"].startswith("x64dbg_")),
                      "windbg_o200k": sum(r["total"][T] for r in per_tool if r["name"].startswith("windbg_"))}

# ---- facets
fac = defaultdict(lambda: {"tools": 0, "o200k": 0})
for r in per_tool:
    for f in r["facets"]:
        fac[f]["tools"] += 1
        fac[f]["o200k"] += r["total"][T]
report["by_facet"] = dict(fac)

# ---- description analysis: docstring sections
SECTION_RE = re.compile(r"^(Args|Arguments|Parameters|Returns|Return|Raises|Example|Examples|Note|Notes|Yields)\s*:\s*$", re.M)
sec_tot = defaultdict(lambda: {"tools": 0, "o200k": 0, "chars": 0})
desc_lens = []
args_tools_no_schema_desc = 0
schema_param_desc = 0
schema_params = 0
for t in tools:
    d = t.get("description", "") or ""
    desc_lens.append((count(d)[T], t["name"]))
    props = (t["inputSchema"] or {}).get("properties", {}) or {}
    schema_params += len(props)
    with_desc = sum(1 for p in props.values() if isinstance(p, dict) and "description" in p)
    schema_param_desc += with_desc
    # split into sections
    matches = list(SECTION_RE.finditer(d))
    has_args = False
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(d)
        body = d[m.start():end]
        name = m.group(1)
        name = {"Arguments": "Args", "Parameters": "Args", "Return": "Returns",
                "Example": "Examples", "Note": "Notes"}.get(name, name)
        sec_tot[name]["tools"] += 1
        sec_tot[name]["o200k"] += count(body)[T]
        sec_tot[name]["chars"] += len(body)
        if name == "Args":
            has_args = True
    if has_args and with_desc == 0 and props:
        args_tools_no_schema_desc += 1
report["doc_sections"] = dict(sec_tot)
report["schema_params_total"] = schema_params
report["schema_params_with_description"] = schema_param_desc
report["tools_with_Args_and_zero_schema_param_desc"] = args_tools_no_schema_desc
desc_lens.sort(reverse=True)
report["desc_o200k_stats"] = {
    "max": desc_lens[0], "min": desc_lens[-1],
    "median": desc_lens[len(desc_lens) // 2][0],
    "mean": round(sum(x for x, _ in desc_lens) / len(desc_lens), 1),
    "over_1000": sum(1 for x, _ in desc_lens if x > 1000),
    "over_500": sum(1 for x, _ in desc_lens if x > 500),
    "under_100": sum(1 for x, _ in desc_lens if x < 100),
}
# Audit-style prose in descriptions (heuristic markers)
markers = {"audit": re.compile(r"\baudit\b", re.I),
           "F-NN finding id": re.compile(r"\bF-\d+\b"),
           "used to / previously": re.compile(r"\b(used to|previously)\b", re.I),
           "docs/ reference": re.compile(r"docs/[\w\-]+\.md")}
report["desc_markers"] = {k: sum(1 for t in tools if rx.search(t.get("description", "") or ""))
                          for k, rx in markers.items()}


# ---- JSON Schema bloat
def walk(node, fn):
    if isinstance(node, dict):
        fn(node)
        for v in node.values():
            walk(v, fn)
    elif isinstance(node, list):
        for v in node:
            walk(v, fn)


stats = Counter()


def tally(n):
    if "title" in n and isinstance(n.get("title"), str):
        stats["title"] += 1
    if "default" in n:
        stats["default"] += 1
        if n["default"] is None:
            stats["default_null"] += 1
    if "anyOf" in n:
        stats["anyOf"] += 1
        if any(isinstance(x, dict) and x.get("type") == "null" for x in n["anyOf"]):
            stats["anyOf_with_null"] += 1
    if "additionalProperties" in n:
        stats["additionalProperties"] += 1
    if "$defs" in n:
        stats["$defs"] += 1
    if "enum" in n:
        stats["enum"] += 1
    if "items" in n:
        stats["items"] += 1


for t in tools:
    walk(t["inputSchema"], tally)
report["input_schema_keyword_counts"] = dict(stats)

out_stats = Counter()
for t in tools:
    os_ = t.get("outputSchema")
    if os_ is None:
        out_stats["none"] += 1
        continue
    if os_.get("x-fastmcp-wrap-result"):
        rt = os_.get("properties", {}).get("result", {})
        out_stats["wrapped:" + jdump(rt)] += 1
    else:
        out_stats["object:" + jdump(os_)[:80]] += 1
report["output_schema_shapes"] = dict(out_stats)


def total_input_tokens(tlist):
    return count(jdump([t["inputSchema"] for t in tlist]))[T]


def tool_tokens(tlist):
    return count(jdump(tlist))[T]


base_tools_tokens = tool_tokens(tools)
base_input = total_input_tokens(tools)


def xform_collapse_anyof_null(n):
    if "anyOf" in n and isinstance(n["anyOf"], list):
        non_null = [x for x in n["anyOf"] if not (isinstance(x, dict) and x.get("type") == "null")]
        if len(non_null) == 1 and len(non_null) < len(n["anyOf"]):
            del n["anyOf"]
            n.update(non_null[0])


def xform_drop_default_null(n):
    if "default" in n and n["default"] is None:
        del n["default"]


def xform_drop_all_defaults(n):
    n.pop("default", None)


def xform_drop_additional(n):
    n.pop("additionalProperties", None)


def apply(tlist, *fns, key="inputSchema"):
    tl = copy.deepcopy(tlist)
    for t in tl:
        if t.get(key) is None:
            continue
        for fn in fns:
            walk(t[key], fn)
    return tl


sav = {}
for label, fns in [
    ("collapse anyOf[X,null] -> X", (xform_collapse_anyof_null,)),
    ("drop default:null", (xform_drop_default_null,)),
    ("collapse anyOf-null + drop default:null", (xform_collapse_anyof_null, xform_drop_default_null)),
    ("drop all defaults", (xform_drop_all_defaults,)),
    ("drop additionalProperties", (xform_drop_additional,)),
]:
    tl = apply(tools, *fns)
    sav[label] = base_input - total_input_tokens(tl)
# outputSchema removal
no_out = copy.deepcopy(tools)
for t in no_out:
    t.pop("outputSchema", None)
sav["remove outputSchema (whole tools/list)"] = base_tools_tokens - tool_tokens(no_out)
no_meta = copy.deepcopy(tools)
for t in no_meta:
    t.pop("_meta", None)
sav["remove _meta (whole tools/list)"] = base_tools_tokens - tool_tokens(no_meta)
report["schema_savings_o200k"] = sav
report["base_tools_array_o200k"] = base_tools_tokens
report["base_input_schemas_o200k"] = base_input

# ---- strip docstring sections from descriptions (what-if)
def strip_sections(d, names):
    lines = d.split("\n")
    out, skip = [], False
    for ln in lines:
        m = SECTION_RE.match(ln.strip()) if ln.strip() else None
        if m and ln == ln.lstrip():  # top-level header
            nm = {"Arguments": "Args", "Parameters": "Args", "Return": "Returns",
                  "Example": "Examples", "Note": "Notes"}.get(m.group(1), m.group(1))
            skip = nm in names
            if skip:
                continue
        elif skip and ln and ln == ln.lstrip():  # dedented line ends section
            skip = False
        if not skip:
            out.append(ln)
    return "\n".join(out).strip()


what_if = {}
for names in (("Args",), ("Returns",), ("Args", "Returns"), ("Args", "Returns", "Examples", "Notes")):
    tl = copy.deepcopy(tools)
    for t in tl:
        t["description"] = strip_sections(t.get("description", "") or "", set(names))
    what_if["strip " + "+".join(names)] = base_tools_tokens - tool_tokens(tl)
# first paragraph only
tl = copy.deepcopy(tools)
for t in tl:
    t["description"] = (t.get("description", "") or "").split("\n\n")[0]
what_if["first paragraph only"] = base_tools_tokens - tool_tokens(tl)
report["description_what_if_savings_o200k"] = what_if

# ---- per-tool full table
report["per_tool"] = [
    {"name": r["name"], "category": r["category"], "facets": r["facets"],
     **{f"{k}_{m}": r[k][m] for k in ("total", "description", "inputSchema", "outputSchema", "_meta")
        if k in r for m in ("bytes", "o200k", "cl100k", "chars_div4")},
     "total_claude_legacy": r["total"].get("claude_legacy")}
    for r in per_tool]

json.dump(report, open(f"{prefix}_analysis.json", "w"), indent=1)

# ---- print summary
print("WIRE TOTAL", report["wire_total"])
print("TOOLS ARRAY", report["tools_array_only"])
print("PROJECTION name+desc+input", report["projection_name_desc_input"])
print("PROJECTION name+input", report["projection_name_input_only"])
print("KEYS", report["keys_present"])
print("COMPONENT TOTALS")
for k, v in report["component_totals"].items():
    print(f"  {k:14s}", v)
print("TOP25 share o200k", report["top25_share_o200k"])
for r in report["top25"]:
    print(f"  {r['name']:38s} {r['category']:13s} tot={r['total_o200k']:5d} desc={r['desc_o200k']:5d} in={r['input_o200k']:4d} out={r['output_o200k']:3d} meta={r['meta_o200k']:3d} bytes={r['bytes']}")
print("BY CATEGORY")
for k, v in report["by_category"].items():
    print(f"  {k:13s}", v)
print("DEBUGGER", report["debugger"])
print("FACETS", report["by_facet"])
print("DOC SECTIONS", report["doc_sections"])
print("schema params", schema_params, "with description", schema_param_desc,
      "tools w/ Args and zero schema desc", args_tools_no_schema_desc)
print("DESC STATS", report["desc_o200k_stats"])
print("DESC MARKERS", report["desc_markers"])
print("INPUT KW COUNTS", report["input_schema_keyword_counts"])
print("OUTPUT SHAPES", report["output_schema_shapes"])
print("SCHEMA SAVINGS", report["schema_savings_o200k"], "base tools", base_tools_tokens, "base input", base_input)
print("DESC WHAT-IF", report["description_what_if_savings_o200k"])
