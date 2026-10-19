"""Render every create_*_error factory in src/utils/structured_errors.py with
placeholder arguments and measure the model-facing text produced by
error_hygiene.curated_structured_text (+ the 'Reference ID' line), plus the
path-error guidance strings and the default-confinement denial message."""
import inspect
import sys

sys.path.insert(0, "/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts")
from common import SP, count, setup_env  # noqa: E402

setup_env({"GHIDRA_HOME": f"{SP}/fake_ghidra"})

from src.tools import error_hygiene  # noqa: E402
from src.utils import security, structured_errors as se  # noqa: E402

rows = []
for name, fn in inspect.getmembers(se, inspect.isfunction):
    if not name.startswith("create_") or name == "create_error_from_api_response":
        continue
    kwargs = {}
    for p in inspect.signature(fn).parameters.values():
        if p.default is inspect.Parameter.empty:
            ann = str(p.annotation)
            kwargs[p.name] = 5 if "int" in ann and "str" not in ann else "0x401000"
    try:
        err = fn(**kwargs)
        exc = se.StructuredBaseError(err) if not isinstance(err, se.StructuredBaseError) else err
        text = error_hygiene.curated_structured_text(exc) + "\nReference ID: 1a2b3c4d"
        rows.append((count(text)["o200k"], name, len(err.suggestions), text))
    except Exception as e:  # noqa: BLE001
        rows.append((-1, name, 0, repr(e)))
rows.sort(reverse=True)
tot = [r[0] for r in rows if r[0] > 0]
print(f"factories={len(rows)} o200k min={min(tot)} median={sorted(tot)[len(tot)//2]} max={max(tot)} mean={sum(tot)/len(tot):.0f}")
for r in rows:
    print(f"{r[0]:5d} {r[1]:42s} suggestions={r[2]}")
print("---- largest example ----")
print(rows[0][3])

print("---- safe_error_message example ----")
m = security.safe_error_message("get_pe_info", RuntimeError("boom"))
print(count(m)["o200k"], repr(m))

print("---- path guidance strings ----")
g = getattr(security, "PATH_ERROR_GUIDANCE", None) or getattr(error_hygiene, "PATH_ERROR_GUIDANCE", None)
if isinstance(g, dict):
    for k, v in g.items():
        print(count(str(v))["o200k"], k, "::", str(v)[:160])
else:
    print(type(g), str(g)[:300])

print("---- default confinement denial (no BINARY_MCP_ALLOWED_DIRS) ----")
d = security._default_confinement_denied("/etc/passwd", security.default_quarantine_dirs())
print(count(d)["o200k"], d)
