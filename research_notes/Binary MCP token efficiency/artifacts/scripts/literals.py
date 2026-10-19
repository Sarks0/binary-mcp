import sys, runpy
SP = sys.argv[1]
# reuse tokenizer loaders from measure.py without re-running experiments
src = open(f"{SP}/scripts/measure.py").read().split("# ----------------------------------------------------------------------------- 1. addresses")[0]
g = {"__name__": "lit"}; sys.argv = ["x", SP]; exec(compile(src, "measure_head", "exec"), g)
TOKS, n = g["TOKS"], g["n"]
lits = ["0x00401000", "00401000", "0x401000", "401000", "0x1000", "1000", "+0x1a", "+1a", "sub_401000", "FUN_00401000", "FUN_401000",
        "0x0000000140001000", "0x140001000", "140001000", "00000001`40001000", "4d 5a 90 00", "4d5a9000", "TVqQAA==", "\\x4d\\x5a\\x90\\x00",
        "undefined8", "u64", "uint64_t", "param_1", "a1", "local_28", "uVar1", "v1", "(undefined8 *)", "DAT_001020d0"]
print("| literal | " + " | ".join(TOKS) + " |"); print("|" + "---|" * (len(TOKS) + 1))
for s in lits:
    print(f"| `{s}` | " + " | ".join(str(n(t, s)) for t in TOKS.values()) + " |")
