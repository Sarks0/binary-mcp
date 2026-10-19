#!/usr/bin/env python3
"""Token-cost measurements for reverse-engineering artifacts.

Run with: venv/bin/python -I scripts/measure.py <scratchpad_dir>
Inputs (all local, read-only):
  - tokenizer vocabularies extracted from npm `tiktoken@1.0.22` (o200k_base, cl100k_base),
    PyPI `anthropic==0.34.2` (legacy Claude tokenizer.json), `dashscope` (qwen.tiktoken),
    `mistral_common==1.12.0` (tekken_240911.json)
  - LLM4Decompile legacy-test/decompile-eval-executable-gcc-ghidra.json (656 real Ghidra outputs)
  - pip/_vendor/distlib/t64.exe (real MSVC x64 PE; only its bytes are read, never executed)
"""
import base64, json, math, os, random, re, statistics, sys
from collections import defaultdict, OrderedDict

SP = sys.argv[1]
import tiktoken
from tokenizers import Tokenizer

# ----------------------------------------------------------------------------- tokenizers
def load_npm(name):
    d = json.load(open(f"{SP}/data/npm/tk/package/encoders/{name}.json"))
    ranks = {}
    for line in d["bpe_ranks"].split("\n"):
        if not line:
            continue
        parts = line.split(" ")
        off = int(parts[1])
        for i, t in enumerate(parts[2:]):
            ranks[base64.b64decode(t)] = off + i
    return tiktoken.Encoding(name=name, pat_str=d["pat_str"], mergeable_ranks=ranks,
                             special_tokens=d["special_tokens"])

def load_qwen():
    ranks = {}
    for line in open(f"{SP}/data/tok/dashscope/resources/qwen.tiktoken", "rb"):
        if line.strip():
            t, r = line.split()
            ranks[base64.b64decode(t)] = int(r)
    pat = r"""(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+"""
    return tiktoken.Encoding(name="qwen", pat_str=pat, mergeable_ranks=ranks, special_tokens={})

def load_tekken():
    d = json.load(open(f"{SP}/data/tok/mistral_common/data/tekken_240911.json"))
    cfg = d["config"]
    n = cfg["default_vocab_size"] - cfg["default_num_special_tokens"]
    ranks = {base64.b64decode(t["token_bytes"]): t["rank"] for t in d["vocab"][:n]}
    return tiktoken.Encoding(name="tekken", pat_str=cfg["pattern"], mergeable_ranks=ranks, special_tokens={})

class HF:
    def __init__(self, path):
        self.t = Tokenizer.from_file(path)
    def encode(self, s, **kw):
        return self.t.encode(s, add_special_tokens=False).ids
    def decode_single_token_bytes(self, i):
        return self.t.decode([i]).encode()

TOKS = OrderedDict()
TOKS["o200k"] = load_npm("o200k_base")
TOKS["cl100k"] = load_npm("cl100k_base")
TOKS["claude-legacy"] = HF(f"{SP}/data/tok/anthropic/tokenizer.json")
TOKS["qwen"] = load_qwen()
TOKS["tekken"] = load_tekken()

def n(tok, s):
    if isinstance(tok, HF):
        return len(tok.encode(s))
    return len(tok.encode(s, disallowed_special=()))

def counts(s):
    return {k: n(t, s) for k, t in TOKS.items()}

OUT = []
def emit(s=""):
    OUT.append(s)
    print(s)

def table(title, rows, cols=None, note=None):
    """rows: list of (label, text) -> prints tokens per tokenizer and chars."""
    emit(f"\n### {title}\n")
    if note:
        emit(note + "\n")
    hdr = "| Format | chars | " + " | ".join(TOKS) + " |"
    emit(hdr)
    emit("|" + "---|" * (len(TOKS) + 2))
    base = None
    for label, text in rows:
        c = counts(text)
        if base is None:
            base = c
        cells = []
        for k in TOKS:
            pct = (c[k] - base[k]) / base[k] * 100 if base[k] else 0
            cells.append(f"{c[k]}" + ("" if label == rows[0][0] else f" ({pct:+.0f}%)"))
        emit(f"| {label} | {len(text)} | " + " | ".join(cells) + " |")

# ----------------------------------------------------------------------------- 1. addresses
random.seed(1234)
emit("## 1. Address formats (mean tokens per address over 1,000 random addresses)\n")
emit("| Format | example | " + " | ".join(TOKS) + " |")
emit("|" + "---|" * (len(TOKS) + 2))
a32 = [random.randrange(0x401000, 0x4fffff) for _ in range(1000)]
a64 = [random.randrange(0x140001000, 0x14002ffff) for _ in range(1000)]
a64u = [random.randrange(0x7ff600000000, 0x7ff6ffffffff) for _ in range(1000)]
rel = [random.randrange(0, 0x400) for _ in range(1000)]
fmts = [
    ("32-bit `0x%08x`", a32, lambda a: f"0x{a:08x}"),
    ("32-bit `%08x`", a32, lambda a: f"{a:08x}"),
    ("32-bit `%08X`", a32, lambda a: f"{a:08X}"),
    ("32-bit `0x%x`", a32, lambda a: f"0x{a:x}"),
    ("32-bit `%x`", a32, lambda a: f"{a:x}"),
    ("32-bit decimal", a32, lambda a: f"{a}"),
    ("Ghidra `FUN_%08x`", a32, lambda a: f"FUN_{a:08x}"),
    ("IDA `sub_%X`", a32, lambda a: f"sub_{a:X}"),
    ("RVA `0x%x` (minus 0x400000)", a32, lambda a: f"0x{a-0x400000:x}"),
    ("RVA `%x` (minus 0x400000)", a32, lambda a: f"{a-0x400000:x}"),
    ("64-bit PE `0x%016x`", a64, lambda a: f"0x{a:016x}"),
    ("64-bit PE `0x%x`", a64, lambda a: f"0x{a:x}"),
    ("64-bit PE `%x`", a64, lambda a: f"{a:x}"),
    ("64-bit PE RVA `%x`", a64, lambda a: f"{a-0x140000000:x}"),
    ("64-bit user `0x%016x`", a64u, lambda a: f"0x{a:016x}"),
    ("64-bit user WinDbg `%08x`%08x`", a64u, lambda a: f"{a>>32:08x}`{a & 0xffffffff:08x}"),
    ("64-bit user `0x%x`", a64u, lambda a: f"0x{a:x}"),
    ("64-bit user `%x`", a64u, lambda a: f"{a:x}"),
    ("func-relative `+0x%x` (0-0x3ff)", rel, lambda a: f"+0x{a:x}"),
    ("func-relative `+%x` (0-0x3ff)", rel, lambda a: f"+{a:x}"),
]
for label, vals, f in fmts:
    cells = []
    for k, t in TOKS.items():
        # measure in a realistic context: preceded by a space, as inside a listing line
        m = statistics.mean(n(t, " " + f(v)) for v in vals)
        cells.append(f"{m:.2f}")
    emit(f"| {label} | `{f(vals[0])}` | " + " | ".join(cells) + " |")

# ----------------------------------------------------------------------------- PE helpers
import pefile, capstone
PE_PATH = f"{SP}/venv/lib/python3.13/site-packages/pip/_vendor/distlib/t64.exe"
raw = open(PE_PATH, "rb").read()
pe = pefile.PE(data=raw)
IB = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.startswith(b".text"))
rdata = next((s for s in pe.sections if s.Name.startswith(b".rdata")), None)
text_va = IB + text.VirtualAddress
text_bytes = text.get_data()
ep = IB + pe.OPTIONAL_HEADER.AddressOfEntryPoint
emit(f"\nPE sample: distlib t64.exe, {len(raw)} bytes, ImageBase=0x{IB:x}, .text VA=0x{text_va:x} size={len(text_bytes)}, entry=0x{ep:x}")

# ----------------------------------------------------------------------------- 2. hexdumps
def fmt_xxd(b, base=0):
    out = []
    for i in range(0, len(b), 16):
        ch = b[i:i+16]
        hx = " ".join(ch[j:j+2].hex() for j in range(0, len(ch), 2))
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in ch)
        out.append(f"{base+i:08x}: {hx:<39}  {asc}")
    return "\n".join(out)

def fmt_hexdump_c(b, base=0):
    out = []
    for i in range(0, len(b), 16):
        ch = b[i:i+16]
        h1 = " ".join(f"{x:02x}" for x in ch[:8]); h2 = " ".join(f"{x:02x}" for x in ch[8:])
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in ch)
        out.append(f"{base+i:08x}  {h1:<23}  {h2:<23}  |{asc}|")
    return "\n".join(out)

def fmt_windbg_db(b, base=0x00007ff6a1b20000):
    out = []
    for i in range(0, len(b), 16):
        ch = b[i:i+16]; a = base + i
        h1 = " ".join(f"{x:02x}" for x in ch[:8]); h2 = " ".join(f"{x:02x}" for x in ch[8:])
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in ch)
        out.append(f"{a>>32:08x}`{a&0xffffffff:08x}  {h1}-{h2}  {asc}")
    return "\n".join(out)

def fmt_spaced(b, upper=False):
    f = "{:02X}" if upper else "{:02x}"
    return "\n".join(" ".join(f.format(x) for x in b[i:i+16]) for i in range(0, len(b), 16))

def fmt_contig(b):
    return "\n".join(b[i:i+32].hex() for i in range(0, len(b), 32))

def fmt_b64(b):
    return base64.b64encode(b).decode()

def fmt_cesc(b):
    return "".join(f"\\x{x:02x}" for x in b)

def fmt_carray(b):
    return ", ".join(f"0x{x:02x}" for x in b)

samples = OrderedDict()
samples["PE header (file offset 0, 256 B)"] = raw[:256]
off = text.PointerToRawData + (ep - text_va)
samples[".text code at entry (256 B)"] = raw[off:off+256]
if rdata:
    rd = rdata.get_data()
    # pick a 256-byte window of .rdata with the most printable characters (string-rich region)
    best = max(range(0, max(1, len(rd)-256), 64), key=lambda i: sum(32 <= x < 127 for x in rd[i:i+256]))
    samples[".rdata string-rich (256 B)"] = rd[best:best+256]
rnd = random.Random(7)
samples["random/high-entropy (256 B)"] = bytes(rnd.randrange(256) for _ in range(256))
samples["all zero (256 B)"] = bytes(256)

emit("\n## 2. Hexdump formats (tokens per byte; 256-byte samples)\n")
hfmts = [
    ("xxd (offset + 2-byte groups + ASCII)", fmt_xxd),
    ("hexdump -C (offset + bytes + |ASCII|)", fmt_hexdump_c),
    ("WinDbg db (backtick addr + bytes + ASCII)", fmt_windbg_db),
    ("hex bytes spaced, lowercase, 16/line", fmt_spaced),
    ("hex bytes spaced, UPPERCASE, 16/line", lambda b: fmt_spaced(b, True)),
    ("hex contiguous, 32 B/line", fmt_contig),
    ("base64 (one line)", fmt_b64),
    ("C escapes \\xNN", fmt_cesc),
    ("C array 0xNN, ", fmt_carray),
]
for sname, b in samples.items():
    emit(f"\n**{sname}**\n")
    emit("| Format | chars | " + " | ".join(f"{k} tok (tok/B)" for k in TOKS) + " |")
    emit("|" + "---|" * (len(TOKS) + 2))
    for label, f in hfmts:
        s = f(b)
        cells = [f"{n(t, s)} ({n(t, s)/len(b):.2f})" for t in TOKS.values()]
        emit(f"| {label} | {len(s)} | " + " | ".join(cells) + " |")

# ----------------------------------------------------------------------------- 3. mangled names
emit("\n## 3. Mangled vs demangled C++/Rust names (tokens)\n")
names = [
    ("MSVC", "?GetInstance@CManager@@SAPAV1@XZ",
     "public: static class CManager * __cdecl CManager::GetInstance(void)", "CManager::GetInstance"),
    ("MSVC", "??0CString@@QAE@PBD@Z", "public: __thiscall CString::CString(char const *)", "CString::CString"),
    ("MSVC", "?push_back@?$vector@HV?$allocator@H@std@@@std@@QEAAXAEBH@Z",
     "public: void __cdecl std::vector<int,class std::allocator<int> >::push_back(int const & __ptr64) __ptr64",
     "std::vector<int>::push_back"),
    ("MSVC", "??_7type_info@@6B@", "const type_info::`vftable'", "type_info::vftable"),
    ("MSVC", "?_Xlength_error@std@@YAXPEBD@Z", "void __cdecl std::_Xlength_error(char const * __ptr64)", "std::_Xlength_error"),
    ("Itanium", "_ZNSt6vectorIiSaIiEE9push_backERKi",
     "std::vector<int, std::allocator<int> >::push_back(int const&)", "std::vector<int>::push_back"),
    ("Itanium", "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv",
     "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::c_str() const",
     "std::string::c_str"),
    ("Itanium", "_ZSt4cout", "std::cout", "std::cout"),
    ("Rust legacy", "_ZN4core3fmt5write17h0f5ecb6c3e3a5d9bE", "core::fmt::write::h0f5ecb6c3e3a5d9b", "core::fmt::write"),
]
emit("| Scheme | mangled | " + " | ".join(f"{k} m/d/s" for k in TOKS) + " |")
emit("|" + "---|" * (len(TOKS) + 2))
tot = defaultdict(lambda: [0, 0, 0])
for sch, m, d, s in names:
    cells = []
    for k, t in TOKS.items():
        a, b_, c = n(t, m), n(t, d), n(t, s)
        tot[k][0] += a; tot[k][1] += b_; tot[k][2] += c
        cells.append(f"{a}/{b_}/{c}")
    emit(f"| {sch} | `{m}` | " + " | ".join(cells) + " |")
emit("| **total** | | " + " | ".join(f"{v[0]}/{v[1]}/{v[2]}" for v in tot.values()) + " |")
emit("\n(m = mangled, d = full demangled (undname / c++filt style), s = simplified `Namespace::Function` form)")

# ----------------------------------------------------------------------------- 4. Ghidra pseudocode normalization
G = json.load(open(f"{SP}/papers/albertan017_LLM4Decompile/legacy-test/decompile-eval-executable-gcc-ghidra.json"))
STR_RE = r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\''

def compact_ws_line(line):
    stripped = line.lstrip(" \t")
    if not stripped:
        return line
    lead = line[:len(line) - len(stripped)]
    return lead + re.sub(STR_RE + r"|[ \t]{2,}", lambda m: m.group(0) if m.group(0)[0] in "\"'" else " ", stripped)

def ws_blank(code):
    lines = [l.rstrip() for l in code.split("\n")]
    return "\n".join(l for l in lines if l.strip())

def ws_compact(code):
    return "\n".join(compact_ws_line(l) for l in ws_blank(code).split("\n"))

def ws_indent1(code):
    out = []
    for l in ws_compact(code).split("\n"):
        s = l.lstrip(" "); k = len(l) - len(s)
        out.append(" " * (k // 2) + s)
    return "\n".join(out)

def ws_tabs(code):
    out = []
    for l in ws_compact(code).split("\n"):
        s = l.lstrip(" "); k = len(l) - len(s)
        out.append("\t" * (k // 2) + s)
    return "\n".join(out)

def ws_noindent(code):
    return "\n".join(l.lstrip() for l in ws_compact(code).split("\n"))

def strip_comments(code):
    pat = re.compile(r'//.*?$|/\*.*?\*/|' + STR_RE, re.DOTALL | re.MULTILINE)
    return re.sub(pat, lambda m: "" if m.group(0).startswith("/") else m.group(0), code)

AUTO = re.compile(r"\b(?:param_\d+|local_[0-9a-fA-F]+(?:_[0-9a-fA-F]+)?|[a-z]{1,5}Var\d+|in_[A-Za-z0-9_]+|"
                  r"extraout_[A-Za-z0-9_]+|unaff_[A-Za-z0-9_]+|[a-z]{1,5}Stack_[0-9a-fA-F]+(?:_[0-9a-fA-F]+)?)\b")
IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")

def short_auto_names(code):
    existing = set(IDENT.findall(code))
    mapping = {}
    pi = vi = 0
    for m in AUTO.finditer(code):
        name = m.group(0)
        if name in mapping:
            continue
        if name.startswith("param_"):
            new = "a" + name[6:]
        else:
            new = f"v{vi}"; vi += 1
        while new in existing:
            new = "_" + new
        mapping[name] = new
    return AUTO.sub(lambda m: mapping[m.group(0)], code), mapping

def strip_addr_padding(code):
    # FUN_00101234 -> FUN_101234, DAT_001020d0 -> DAT_1020d0 (lossless: same value)
    return re.sub(r"\b(FUN|DAT|LAB|PTR|SUB|UNK|thunk_FUN|switchD|caseD|s|u)_0+([0-9a-fA-F]+)\b", r"\1_\2", code)

def short_symbol_prefixes(code):
    code = re.sub(r"\bFUN_([0-9a-fA-F]+)\b", r"f_\1", code)
    code = re.sub(r"\bDAT_([0-9a-fA-F]+)\b", r"d_\1", code)
    code = re.sub(r"\bLAB_([0-9a-fA-F]+)\b", r"L_\1", code)
    return code

TYPE_MAP = OrderedDict([("undefined8", "u64"), ("undefined4", "u32"), ("undefined2", "u16"), ("undefined1", "u8"),
                        ("undefined", "u8"), ("ulonglong", "u64"), ("longlong", "i64"), ("ulong", "u64"),
                        ("uint", "u32"), ("ushort", "u16"), ("uchar", "u8"), ("byte", "u8")])
def short_types(code):
    return re.sub(r"\b(" + "|".join(TYPE_MAP) + r")\b", lambda m: TYPE_MAP[m.group(1)], code)

KNOWN_TYPES = ["undefined8", "undefined4", "undefined2", "undefined1", "undefined", "ulonglong", "longlong", "ulong",
               "uint", "ushort", "uchar", "byte", "char", "short", "int", "long", "float", "double", "bool", "void",
               "code", "size_t", "sbyte", "dword", "qword", "word", "float10", "FILE", "u64", "u32", "u16", "u8", "i64"]
CAST = re.compile(r"(?<![A-Za-z0-9_\)\]])\((?:const\s+)?(?:unsigned\s+)?(?:struct\s+)?(?:" + "|".join(KNOWN_TYPES) +
                  r"|[A-Za-z_][A-Za-z0-9_]*\s*\*+)(?:\s*\*+)?\)\s*(?=[A-Za-z0-9_\(\*&\-~!])")
def strip_casts(code):
    prev = None
    while prev != code:
        prev = code
        code = CAST.sub("", code)
    return code

def count_class(tok, s):
    ids = tok.encode(s) if isinstance(tok, HF) else tok.encode(s, disallowed_special=())
    ws = par = 0
    for i in ids:
        try:
            piece = tok.decode_single_token_bytes(i).decode("utf-8", "replace")
        except Exception:
            piece = ""
        if piece.strip() == "":
            ws += 1
        elif set(piece.strip()) <= set("()"):
            par += 1
    return len(ids), ws, par

def src_only(c):
    return "\n".join(l for l in c.split("\n") if not l.startswith("#include")).strip()

steps = OrderedDict()
steps["raw Ghidra output"] = lambda c: c
steps["W1 drop blank lines + trailing ws"] = ws_blank
steps["W2 W1 + collapse internal space runs (ida-pro-mcp PR#341 rule)"] = ws_compact
steps["W3 W2 + indent 1 space/level (Ghidra uses 2)"] = ws_indent1
steps["W3t W2 + indent 1 tab/level"] = ws_tabs
steps["W4 W2 + no indentation"] = ws_noindent
steps["C  strip comments only"] = strip_comments
steps["N1 strip zero-padding in FUN_/DAT_/LAB_ only"] = strip_addr_padding
steps["N2 short auto-names only (param_N->aN, local_x/xVarN->vN)"] = lambda c: short_auto_names(c)[0]
steps["N3 short symbol prefixes (FUN_->f_, DAT_->d_, LAB_->L_) + N1"] = lambda c: short_symbol_prefixes(strip_addr_padding(c))
steps["T  undefinedN/ulong/uint... -> u64/u32/... only"] = short_types
steps["K  strip casts only (LOSSY)"] = strip_casts
steps["COMBO-lossless: W3 + C + N1 + N2"] = lambda c: short_auto_names(strip_addr_padding(strip_comments(ws_indent1(c))))[0]
steps["COMBO-lossless+: W4 + C + N1 + N2 + N3"] = lambda c: short_auto_names(short_symbol_prefixes(strip_addr_padding(strip_comments(ws_noindent(c)))))[0]
steps["COMBO-aggressive: COMBO-lossless+ + T + K"] = lambda c: strip_casts(short_types(short_auto_names(short_symbol_prefixes(strip_addr_padding(strip_comments(ws_noindent(c)))))[0]))

emit(f"\n## 4. Ghidra pseudocode normalization on {len(G)} real Ghidra outputs (LLM4Decompile HumanEval-Decompile, gcc x86-64 O0-O3)\n")
tot_steps = OrderedDict((s, defaultdict(int)) for s in steps)
for rec in G:
    code = rec["input_asm_prompt"]
    for sname, fn in steps.items():
        out = fn(code)
        for k, t in TOKS.items():
            tot_steps[sname][k] += n(t, out)
        tot_steps[sname]["chars"] += len(out)
emit("| Transform | chars | " + " | ".join(f"{k} tokens (Δ vs raw)" for k in TOKS) + " |")
emit("|" + "---|" * (len(TOKS) + 2))
raw_tot = tot_steps["raw Ghidra output"]
for sname, d in tot_steps.items():
    cells = []
    for k in TOKS:
        pct = (d[k] - raw_tot[k]) / raw_tot[k] * 100
        cells.append(f"{d[k]:,}" + ("" if sname.startswith("raw") else f" ({pct:+.1f}%)"))
    emit(f"| {sname} | {d['chars']:,} | " + " | ".join(cells) + " |")

# token class shares in raw output
emit("\nToken-class share in raw Ghidra output (whitespace-only tokens, pure-parenthesis tokens):\n")
emit("| tokenizer | total | whitespace-only | % | parenthesis-only | % |")
emit("|---|---|---|---|---|---|")
for k, t in TOKS.items():
    T = W = P = 0
    for rec in G:
        a, b_, c = count_class(t, rec["input_asm_prompt"])
        T += a; W += b_; P += c
    emit(f"| {k} | {T:,} | {W:,} | {W/T*100:.1f}% | {P:,} | {P/T*100:.1f}% |")

# per optimisation level: Ghidra vs original source; signature-only vs body
emit("\nGhidra pseudocode vs original C source, and signature line vs whole function (o200k tokens):\n")
emit("| opt | n | source tok (mean) | Ghidra raw tok (mean) | ratio raw/src | COMBO-lossless+ (mean) | ratio/src | signature line tok (mean) | max raw tok |")
emit("|---|---|---|---|---|---|---|---|---|")
o2 = TOKS["o200k"]
for opt in ["O0", "O1", "O2", "O3"]:
    recs = [r for r in G if r["type"] == opt]
    s = [n(o2, src_only(r["c_func"])) for r in recs]
    g = [n(o2, r["input_asm_prompt"]) for r in recs]
    cl = [n(o2, steps["COMBO-lossless+: W4 + C + N1 + N2 + N3"](r["input_asm_prompt"])) for r in recs]
    sig = [n(o2, r["input_asm_prompt"].strip().split("\n")[0]) for r in recs]
    emit(f"| {opt} | {len(recs)} | {statistics.mean(s):.0f} | {statistics.mean(g):.0f} | {sum(g)/sum(s):.2f} | {statistics.mean(cl):.0f} | {sum(cl)/sum(s):.2f} | {statistics.mean(sig):.1f} | {max(g)} |")

# show one example before/after
ex = next(r for r in G if r["type"] == "O2" and 250 < len(r["input_asm_prompt"]) < 700)
emit("\nExample (O2) raw:\n```c\n" + ex["input_asm_prompt"].strip() + "\n```")
emit("Example COMBO-lossless+:\n```c\n" + steps["COMBO-lossless+: W4 + C + N1 + N2 + N3"](ex["input_asm_prompt"]).strip() + "\n```")

# ----------------------------------------------------------------------------- 5. disassembly
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = False
start = ep
code_bytes = raw[off:off + 4096]
insns = []
for ins in md.disasm(code_bytes, start):
    insns.append(ins)
    if len(insns) >= 200:
        break
REG = re.compile(r"\b(?:[re]?[abcd]x|[abcd][lh]|[re]?[sd]i|[sd]il|[re]?[sb]p|[sb]pl|r(?:8|9|1[0-5])[dwb]?|[re]?ip|xmm\d+|ymm\d+|[cdefgs]s)\b")
def hexb(b, upper=False):
    return " ".join((f"{x:02X}" if upper else f"{x:02x}") for x in b)
def rva_ops(op):
    return re.sub(r"0x(14[0-9a-f]{7})\b", lambda m: "0x%x" % (int(m.group(1), 16) - IB), op)
targets = {}
for ins in insns:
    if ins.mnemonic.startswith("j") or ins.mnemonic == "call":
        m = re.fullmatch(r"0x([0-9a-f]+)", ins.op_str)
        if m:
            tgt = int(m.group(1), 16)
            if start <= tgt < insns[-1].address + insns[-1].size and ins.mnemonic != "call":
                targets.setdefault(tgt, f"L{len(targets)}")
def labels_fmt():
    out = []
    for ins in insns:
        if ins.address in targets:
            out.append(targets[ins.address] + ":")
        op = ins.op_str
        m = re.fullmatch(r"0x([0-9a-f]+)", op)
        if m and int(m.group(1), 16) in targets and ins.mnemonic != "call":
            op = targets[int(m.group(1), 16)]
        out.append(f"{ins.mnemonic} {op}".strip())
    return "\n".join(out)
def compact_ops(op):
    op = re.sub(r"\b(byte|word|dword|qword|xmmword|tbyte) ptr ", r"\1 ", op)
    op = re.sub(r"\s*([+\-*])\s*", r"\1", op)
    op = op.replace(", ", ",")
    return op
dfmts = [
    ("x64dbg-like `ADDR16 | BYTES | insn`", lambda: "\n".join(f"{i.address:016X} | {hexb(i.bytes, True):<24} | {i.mnemonic} {i.op_str}" for i in insns)),
    ("Ghidra-like `addr bytes MNEMONIC OPS` (padded, uppercase)", lambda: "\n".join(f"{i.address:09x} {hexb(i.bytes):<20} {i.mnemonic.upper():<10} {REG.sub(lambda m: m.group(0).upper(), i.op_str)}" for i in insns)),
    ("objdump-like `addr:\\tbytes\\tinsn`", lambda: "\n".join(f"  {i.address:x}:\t{hexb(i.bytes):<21}\t{i.mnemonic:<6} {i.op_str}" for i in insns)),
    ("no bytes, `0x%016x  insn`", lambda: "\n".join(f"0x{i.address:016x}  {i.mnemonic} {i.op_str}" for i in insns)),
    ("no bytes, `%x insn`", lambda: "\n".join(f"{i.address:x} {i.mnemonic} {i.op_str}" for i in insns)),
    ("no bytes, RVA `%x insn` (+ RVA operands)", lambda: "\n".join(f"{i.address-IB:x} {i.mnemonic} {rva_ops(i.op_str)}" for i in insns)),
    ("no bytes, func-relative `+%x insn`", lambda: "\n".join(f"+{i.address-start:x} {i.mnemonic} {i.op_str}" for i in insns)),
    ("no addresses, labels for branch targets", labels_fmt),
    ("`%x insn`, compact operands (drop ` ptr`, spaces)", lambda: "\n".join(f"{i.address:x} {i.mnemonic} {compact_ops(i.op_str)}" for i in insns)),
    ("`%x INSN` uppercase mnemonic+regs", lambda: "\n".join(f"{i.address:x} {i.mnemonic.upper()} {REG.sub(lambda m: m.group(0).upper(), i.op_str)}" for i in insns)),
]
emit(f"\n## 5. Disassembly listing formats ({len(insns)} real x86-64 instructions from t64.exe entry point, capstone {capstone.__version__})\n")
emit("| Format | chars | " + " | ".join(f"{k} (tok/insn)" for k in TOKS) + " |")
emit("|" + "---|" * (len(TOKS) + 2))
base = None
for label, f in dfmts:
    s = f()
    c = counts(s)
    if base is None:
        base = c
    cells = [f"{c[k]} ({c[k]/len(insns):.1f}, {((c[k]-base[k])/base[k]*100):+.0f}%)" for k in TOKS]
    emit(f"| {label} | {len(s)} | " + " | ".join(cells) + " |")
emit("\nFirst 3 lines of first and last-but-one formats:\n```\n" + "\n".join(dfmts[0][1]().split("\n")[:3]) + "\n...\n" + "\n".join(dfmts[8][1]().split("\n")[:3]) + "\n```")

# ----------------------------------------------------------------------------- 6. imports
imps = []
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in e.imports:
        imps.append((e.dll.decode(), imp.name.decode() if imp.name else f"ord_{imp.ordinal}", imp.address))
bydll = OrderedDict()
for d, nm, a in imps:
    bydll.setdefault(d, []).append(nm)
irows = [
    ("table lines `0x%016x  DLL  name`", "\n".join(f"0x{a:016x}  {d:<14} {nm}" for d, nm, a in imps)),
    ("Markdown table `| addr | dll | name |`", "| Address | DLL | Function |\n|---|---|---|\n" + "\n".join(f"| 0x{a:016x} | {d} | {nm} |" for d, nm, a in imps)),
    ("JSON list, indent=2", json.dumps([{"address": f"0x{a:016x}", "dll": d, "name": nm} for d, nm, a in imps], indent=2)),
    ("JSON list, compact separators", json.dumps([{"address": f"0x{a:016x}", "dll": d, "name": nm} for d, nm, a in imps], separators=(",", ":"))),
    ("`DLL!name` per line (no addresses)", "\n".join(f"{d}!{nm}" for d, nm, a in imps)),
    ("grouped by DLL `DLL (n): a, b, c`", "\n".join(f"{d} ({len(v)}): " + ", ".join(v) for d, v in bydll.items())),
    ("grouped by DLL, lowercase dll w/o .dll", "\n".join(f"{d.lower().removesuffix('.dll')}: " + " ".join(v) for d, v in bydll.items())),
]
table(f"6. Import listing formats (t64.exe: {len(imps)} imports from {len(bydll)} DLLs)", irows)

# ----------------------------------------------------------------------------- 7. strings
def ascii_strings(b, minlen):
    return [(m.start(), m.group().decode()) for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, b)]
def utf16_strings(b, minlen):
    return [(m.start(), m.group().decode("utf-16le")) for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, b)]
def entropy(s):
    from collections import Counter
    c = Counter(s); L = len(s)
    return -sum(v / L * math.log2(v / L) for v in c.values())
def looks_wordy(s):
    al = sum(ch.isalnum() or ch in " ._-/\\:%" for ch in s) / len(s)
    return al >= 0.85 and re.search(r"[A-Za-z]{3,}", s) is not None
emit("\n## 7. String listing (t64.exe, ASCII + UTF-16LE)\n")
emit("| Filter | #strings | o200k tokens, `0x%016x: \"s\"` | o200k tokens, `%x s` (RVA) | o200k tokens, values only |")
emit("|---|---|---|---|---|")
for minlen, dedupe, wordy in [(4, False, False), (4, True, False), (6, True, False), (8, True, False), (4, True, True), (6, True, True)]:
    ss = ascii_strings(raw, minlen) + [(o, s) for o, s in utf16_strings(raw, minlen)]
    if wordy:
        ss = [(o, s) for o, s in ss if looks_wordy(s)]
    if dedupe:
        seen = set(); tmp = []
        for o, s in ss:
            if s not in seen:
                seen.add(s); tmp.append((o, s))
        ss = tmp
    f1 = "\n".join(f'0x{IB+o:016x}: "{s}"' for o, s in ss)
    f2 = "\n".join(f"{o:x} {s}" for o, s in ss)
    f3 = "\n".join(s for o, s in ss)
    label = f"min {minlen}" + (", dedupe" if dedupe else "") + (", 'wordy' filter (>=85% alnum, has 3-letter run)" if wordy else "")
    emit(f"| {label} | {len(ss)} | {n(o2, f1):,} | {n(o2, f2):,} | {n(o2, f3):,} |")

# ----------------------------------------------------------------------------- 8. call graph / xrefs
md2 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md2.skipdata = True
calls = []
for ins in md2.disasm(text_bytes, text_va):
    if ins.mnemonic == "call":
        m = re.fullmatch(r"0x([0-9a-f]+)", ins.op_str)
        if m:
            tgt = int(m.group(1), 16)
            if text_va <= tgt < text_va + len(text_bytes):
                calls.append((ins.address, tgt))
starts = sorted(set([t for _, t in calls] + [ep]))
import bisect
edges = []
seen = set()
for site, tgt in calls:
    i = bisect.bisect_right(starts, site) - 1
    if i < 0:
        continue
    e = (starts[i], tgt)
    if e not in seen:
        seen.add(e); edges.append(e)
adj = OrderedDict()
for a, b_ in edges:
    adj.setdefault(a, []).append(b_)
FN = lambda a: f"FUN_{a:08x}"
crows = [
    ("edge list `FUN_x -> FUN_y`", "\n".join(f"{FN(a)} -> {FN(b_)}" for a, b_ in edges)),
    ("Markdown xref table `| from | to | type |`", "| From | To | Type |\n|---|---|---|\n" + "\n".join(f"| 0x{a:x} | 0x{b_:x} | CALL |" for a, b_ in edges)),
    ("JSON edges, indent=2", json.dumps([{"from": f"0x{a:x}", "to": f"0x{b_:x}", "type": "call"} for a, b_ in edges], indent=2)),
    ("JSON edges, compact", json.dumps([{"from": f"0x{a:x}", "to": f"0x{b_:x}", "type": "call"} for a, b_ in edges], separators=(",", ":"))),
    ("Mermaid `A --> B`", "graph TD\n" + "\n".join(f"  {FN(a)} --> {FN(b_)}" for a, b_ in edges)),
    ("DOT `\"A\" -> \"B\";`", "digraph G {\n" + "\n".join(f'  "{FN(a)}" -> "{FN(b_)}";' for a, b_ in edges) + "\n}"),
    ("adjacency `FUN_x: FUN_y, FUN_z`", "\n".join(f"{FN(a)}: " + ", ".join(FN(b_) for b_ in v) for a, v in adj.items())),
    ("adjacency, RVA hex `x: y z`", "\n".join(f"{a-IB:x}: " + " ".join(f"{b_-IB:x}" for b_ in v) for a, v in adj.items())),
    ("JSON adjacency compact `{\"x\":[y,z]}` RVA", json.dumps({f"{a-IB:x}": [f"{b_-IB:x}" for b_ in v] for a, v in adj.items()}, separators=(",", ":"))),
]
table(f"8. Call-graph formats (t64.exe direct calls: {len(edges)} unique edges, {len(adj)} caller functions)", crows)

# ----------------------------------------------------------------------------- 9. registers / memory view
regs = OrderedDict([("rax", 0x0), ("rbx", 0x14f3a0), ("rcx", 0x7ff6a1b21000), ("rdx", 0x1), ("rsi", 0x0), ("rdi", 0x24ec5a10ab0),
                    ("rbp", 0x0), ("rsp", 0x14fe28), ("r8", 0x14fe18), ("r9", 0x0), ("r10", 0x0), ("r11", 0x246), ("r12", 0x0),
                    ("r13", 0x0), ("r14", 0x0), ("r15", 0x0), ("rip", 0x7ff6a1b2104c), ("rflags", 0x244)])
windbg = []
items = list(regs.items())
for i in range(0, 15, 3):
    windbg.append(" ".join(f"{k}={v:016x}" for k, v in items[i:i+3]))
windbg.append(f"rip={regs['rip']:016x} rsp={regs['rsp']:016x} rbp={regs['rbp']:016x}")
windbg.append("iopl=0         nv up ei pl zr na po nc")
windbg.append("cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000244")
rrows = [
    ("WinDbg `r` style", "\n".join(windbg)),
    ("JSON indent=2, `0x%016x`", json.dumps({k: f"0x{v:016x}" for k, v in regs.items()}, indent=2)),
    ("JSON compact, `0x%x`", json.dumps({k: f"0x{v:x}" for k, v in regs.items()}, separators=(",", ":"))),
    ("text `k=%x` one line", " ".join(f"{k}={v:x}" for k, v in regs.items())),
    ("text `k=%x`, zero registers omitted (+ 'others=0')", " ".join(f"{k}={v:x}" for k, v in regs.items() if v) + " (others=0)"),
]
table("9. Register-view formats (18 x64 registers, synthetic but realistic values)", rrows)

open(f"{SP}/data/results.md", "w").write("\n".join(OUT) + "\n")
