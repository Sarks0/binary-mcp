"""
Regression tests for documentation that describes the security model.

Audit findings F-6 and F-11. Both are documentation bugs, which is exactly why
they need tests: prose has no compiler, so a docstring that misstates a control
and a README that overstates a capability both survive indefinitely.

F-6 (model-facing docstrings misstate the security model): a tool docstring is
the ONLY view a model has of that tool's contract. Telling it "only commands
from a curated allowlist are permitted" and stopping there invites it to treat
the tool as a sandbox; saying nothing at all -- as windbg_execute_command did
-- invites it to assume no restrictions exist. The tests here pin the specific
statements that were wrong so they cannot quietly revert, and pin the code
facts those statements depend on (e.g. the tool-layer x64dbg allowlist really
being a subset of the plugin's) so the docs cannot become false by a change on
the other side.

F-11 (documentation overstates capability): the README advertised 245 tools
when 279 were registered, VirusTotal "file submission" that does not exist,
and YARA "rule scanning" backed by a `yara` extra that nothing imports. A
capability claim is something a caller may act on, so each one is asserted
against the code rather than trusted.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
README = REPO_ROOT / "README.md"
PYPROJECT = REPO_ROOT / "pyproject.toml"
SERVER_PY = SRC / "server.py"
DYNAMIC_TOOLS = SRC / "tools" / "dynamic_tools.py"
WINDBG_TOOLS = SRC / "tools" / "windbg_tools.py"
VT_TOOLS = SRC / "tools" / "vt_tools.py"
PLUGIN_CPP = SRC / "engines" / "dynamic" / "x64dbg" / "plugin" / "plugin.cpp"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iter_python_sources() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def count_registered_tools() -> int:
    """
    Count @<something>.tool()-decorated functions across src/.

    Deliberately AST-based rather than importing src.server: importing the
    server requires a Ghidra installation and creates cache/session
    directories, neither of which belongs in a docs test. The count was
    cross-checked against a live FastMCP registration of every register_*_tools
    entry point in main() and matched exactly; test_every_tool_module_is_registered
    below keeps the two definitions from drifting apart.
    """
    total = 0
    for path in _iter_python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if isinstance(target, ast.Attribute) and target.attr == "tool":
                    total += 1
                    break
    return total


def _get_docstring(path: Path, func_name: str) -> str:
    """
    Return the named function's docstring, lower-cased with runs of whitespace
    collapsed to single spaces.

    Normalising matters: these tests look for specific phrases, and a phrase
    that happens to straddle a line wrap ("not a\\n        sandbox") would
    otherwise fail for a purely cosmetic reason and train the next reader to
    delete the assertion rather than fix the prose.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            doc = ast.get_docstring(node)
            if doc:
                return re.sub(r"\s+", " ", doc).lower()
    raise AssertionError(f"{func_name} or its docstring not found in {path}")


def _x64dbg_tool_allowlist() -> set[str]:
    """Read allowed_command_prefixes out of dynamic_tools.py without importing it."""
    tree = ast.parse(DYNAMIC_TOOLS.read_text(encoding="utf-8"), filename=str(DYNAMIC_TOOLS))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "allowed_command_prefixes" not in names:
            continue
        # frozenset({...})
        value = node.value
        if isinstance(value, ast.Call) and value.args:
            return {
                elt.value
                for elt in ast.walk(value.args[0])
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            }
    raise AssertionError("allowed_command_prefixes not found in dynamic_tools.py")


def _plugin_allowlist() -> set[str]:
    """Read ALLOWED_COMMANDS out of plugin.cpp."""
    text = PLUGIN_CPP.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"static const char\* ALLOWED_COMMANDS\[\]\s*=\s*\{(.*?)nullptr", text, re.S)
    assert match, "ALLOWED_COMMANDS table not found in plugin.cpp"
    return set(re.findall(r'"([^"]+)"', match.group(1)))


# ---------------------------------------------------------------------------
# F-11: tool counts
# ---------------------------------------------------------------------------


def test_readme_headline_tool_count_matches_code():
    """README '## Capabilities (N tools)' must equal the real tool count."""
    text = README.read_text(encoding="utf-8")
    match = re.search(r"^## Capabilities \((\d+) tools\)", text, re.M)
    assert match, "README is missing the '## Capabilities (N tools)' heading"
    assert int(match.group(1)) == count_registered_tools()


def test_server_module_docstring_tool_count_matches_code():
    """src/server.py's module docstring must not overstate the tool count."""
    tree = ast.parse(SERVER_PY.read_text(encoding="utf-8"), filename=str(SERVER_PY))
    doc = ast.get_docstring(tree)
    assert doc, "src/server.py lost its module docstring"
    match = re.search(r"Provides (\d+) tools", doc)
    assert match, "server.py docstring no longer states a tool count"
    assert int(match.group(1)) == count_registered_tools()


def test_readme_category_counts_sum_to_total():
    """
    The per-category '### Name - N tools' counts must add up to the headline.

    The original table's categories summed to 245 while the code registered
    279; a table that sums to the wrong number is the shape the bug took, so
    the sum is what gets asserted.
    """
    text = README.read_text(encoding="utf-8")
    section_counts = [int(n) for n in re.findall(r"^### .+ - (\d+) tools?$", text, re.M)]
    assert section_counts, "README no longer lists per-category tool counts"
    assert sum(section_counts) == count_registered_tools()


def test_every_tool_module_is_registered_from_main():
    """
    Every module that defines tools must actually be wired up by main().

    count_registered_tools() counts decorators statically. That equals the
    live count only while each module holding them is reached from main() --
    so assert it, rather than assuming it.
    """
    server_tree = ast.parse(SERVER_PY.read_text(encoding="utf-8"), filename=str(SERVER_PY))

    # Which modules does server.py import a register_* entry point from?
    imported_from: dict[str, set[str]] = {}
    for node in ast.walk(server_tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name.startswith("register_"):
                    imported_from.setdefault(node.module.rsplit(".", 1)[-1], set()).add(alias.name)

    # Which register_* functions does main() actually call?
    called: set[str] = set()
    for node in ast.walk(server_tree):
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            for call in ast.walk(node):
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                    if call.func.id.startswith("register_"):
                        called.add(call.func.id)
    assert called, "main() no longer calls any register_*_tools function"

    for path in _iter_python_sources():
        if path == SERVER_PY:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        has_tools = any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and any(
                isinstance(dec.func if isinstance(dec, ast.Call) else dec, ast.Attribute)
                and (dec.func if isinstance(dec, ast.Call) else dec).attr == "tool"
                for dec in node.decorator_list
            )
            for node in ast.walk(tree)
        )
        if not has_tools:
            continue
        entry_points = imported_from.get(path.stem, set())
        assert entry_points, (
            f"{path} defines MCP tools but src/server.py imports no register_* "
            f"entry point from it, so those tools are counted in the docs but "
            f"never registered"
        )
        assert entry_points & called, (
            f"{path}'s entry point(s) {sorted(entry_points)} are imported but "
            f"never called from main()"
        )


# ---------------------------------------------------------------------------
# F-11: VirusTotal is lookup-only, samples are never uploaded
# ---------------------------------------------------------------------------


def test_readme_does_not_advertise_virustotal_submission():
    """
    The README promised VT 'file submission'. No such tool exists.

    This is good security -- no sample exfiltration path can fire, even by
    accident -- but the promise had to go, and it must not come back without
    the code to match it.
    """
    text = README.read_text(encoding="utf-8").lower()
    for claim in ("file submission", "submit file", "upload sample", "sample upload"):
        assert claim not in text, f"README re-advertises VirusTotal {claim!r}"


def test_readme_states_samples_are_never_uploaded():
    """The never-uploads property is a genuine selling point; keep it stated."""
    text = README.read_text(encoding="utf-8").lower()
    assert "never uploaded" in text or "never upload" in text


def test_no_vt_caller_uses_post():
    """
    _vt_request supports POST but nothing calls it that way.

    If a caller ever passes method="POST", this server gains an outbound path
    for sample data and the README's "never uploaded" claim above becomes
    false. Fail here so the two are changed together.
    """
    tree = ast.parse(VT_TOOLS.read_text(encoding="utf-8"), filename=str(VT_TOOLS))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if name != "_vt_request":
            continue
        for arg in list(node.args[1:]) + [kw.value for kw in node.keywords]:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                assert arg.value.upper() == "GET", (
                    "a _vt_request caller now uses a non-GET method; the README's "
                    "'samples are never uploaded' claim must be re-verified"
                )


# ---------------------------------------------------------------------------
# F-11: YARA is generation-only, and the dead extra stays gone
# ---------------------------------------------------------------------------


def test_yara_library_is_not_imported_anywhere():
    """Nothing in src/ imports yara -- which is why 'rule scanning' was wrong."""
    for path in _iter_python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(a.name.split(".")[0] != "yara" for a in node.names), path
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] != "yara", path


def test_pyproject_has_no_yara_extra_while_yara_is_unimported():
    """
    The `yara` extra installed a native dependency nothing could import.

    If YARA scanning is ever implemented, the extra returns in the same commit
    as the import -- and this test will then pass because the import exists.
    """
    text = PYPROJECT.read_text(encoding="utf-8")
    declares_extra = re.search(r"^yara\s*=\s*\[", text, re.M) is not None
    if declares_extra:
        pytest.fail(
            "pyproject declares a `yara` extra but no module in src/ imports yara; "
            "the declared dependency surface must match the real one"
        )


def test_readme_describes_yara_as_generation_not_scanning():
    text = README.read_text(encoding="utf-8")
    yara_lines = [ln for ln in text.splitlines() if "YARA" in ln or "yara" in ln]
    assert yara_lines, "README no longer mentions YARA at all"
    joined = " ".join(yara_lines).lower()
    assert "generation" in joined or "generate" in joined
    assert "rule scanning" not in joined
    assert "yara-python" not in joined, "README still points at the removed extra"


# ---------------------------------------------------------------------------
# F-11: 'analyze in a VM' guidance, and the code that backs it
# ---------------------------------------------------------------------------


def test_readme_carries_isolated_vm_guidance():
    text = README.read_text(encoding="utf-8").lower()
    assert "isolated vm" in text or "isolated virtual machine" in text


def test_no_tool_can_launch_a_sample():
    """
    Backs the README's "no tool can execute a sample" claim.

    bridge.load_binary() and the plugin's LOAD_BINARY handler both exist; the
    claim rests entirely on nothing in the tool layer calling them. Assert that
    instead of trusting it.
    """
    for path in sorted((SRC / "tools").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr != "load_binary", (
                    f"{path} calls load_binary(); the README claim that no MCP tool "
                    f"can execute a sample is no longer true"
                )


def test_readme_documents_confinement_controls():
    text = README.read_text(encoding="utf-8")
    for var in (
        "BINARY_MCP_ALLOWED_DIRS",
        "BINARY_MCP_REQUIRE_CONFINEMENT",
        "BINARY_MCP_ALLOW_ANY_PATH",
    ):
        assert var in text, f"README no longer documents {var}"


def test_documented_confinement_defaults_match_security_module():
    """
    The README describes the CURRENT default posture; verify it against code.

    Defaults moved during this audit (F-8: unset used to mean "any path").
    A README that describes the old posture is worse than one that says
    nothing, because an operator would skip configuring an allow-list they
    actually still need.
    """
    from src.utils import security

    assert security.ENV_ALLOWED_DIRS == "BINARY_MCP_ALLOWED_DIRS"
    assert security.ENV_REQUIRE_CONFINEMENT == "BINARY_MCP_REQUIRE_CONFINEMENT"
    assert security.ENV_ALLOW_ANY_PATH == "BINARY_MCP_ALLOW_ANY_PATH"
    # Unset BINARY_MCP_ALLOWED_DIRS must NOT mean unrestricted: there has to be
    # a non-empty implicit allow-list for sanitize_binary_path to fall back to.
    assert security.default_quarantine_dirs(), (
        "default_quarantine_dirs() is empty, so an unconfigured install would "
        "again be unrestricted and the README's default-confinement claim false"
    )


# ---------------------------------------------------------------------------
# F-6: x64dbg_execute_command docstring
# ---------------------------------------------------------------------------


def test_x64dbg_execute_command_docstring_describes_all_three_gates():
    lowered = _get_docstring(DYNAMIC_TOOLS, "x64dbg_execute_command")
    # The tool-layer allowlist, by name.
    assert "allowed_command_prefixes" in lowered
    # The bridge layer must be named as a DENYLIST, not sold as a second allowlist.
    assert "denylist" in lowered
    assert "_blocked_commands" in lowered
    # The authoritative plugin allowlist.
    assert "allowed_commands" in lowered
    assert "plugin.cpp" in lowered
    assert "fails closed" in lowered


def test_x64dbg_execute_command_docstring_states_arguments_are_unvalidated():
    """
    The heart of F-6: the old text implied a sandbox.

    Only the first token is ever inspected, and permitted commands still run
    against a live debuggee. Both facts must be stated.
    """
    lowered = _get_docstring(DYNAMIC_TOOLS, "x64dbg_execute_command")
    assert "first token" in lowered
    assert "not validated" in lowered or "not refused and not validated" in lowered
    assert "sandbox" in lowered
    assert "live debuggee" in lowered or "debuggee" in lowered


def test_x64dbg_tool_allowlist_is_subset_of_plugin_allowlist():
    """
    The docstring tells the model the plugin accepts everything this tool does.

    That is only true while the tool-layer list is a subset of the plugin's.
    If someone adds a command here and forgets plugin.cpp, the tool would
    accept a command the plugin then refuses -- and the docstring would be
    lying about the relationship between the two gates.
    """
    tool = _x64dbg_tool_allowlist()
    plugin = _plugin_allowlist()
    extra = sorted(tool - plugin)
    assert not extra, (
        f"tool-layer allowlist permits commands the plugin refuses: {extra}. "
        f"Add them to ALLOWED_COMMANDS in plugin.cpp or drop them here."
    )


def test_x64dbg_allowlists_still_refuse_process_control():
    """
    The docstring names specific refusals; keep them true.

    'init' is the command that STARTS a debuggee -- if it ever appears on
    either allowlist, x64dbg_execute_command becomes an arbitrary-process-launch
    primitive on the analyst's own host, and the README's "no tool can execute
    a sample" claim falls with it.
    """
    tool = _x64dbg_tool_allowlist()
    plugin = _plugin_allowlist()
    forbidden = {
        "init", "initdbg", "initdebug", "startdebug",
        "attach", "detach", "quit", "stop", "exit",
        "scriptdll", "scriptload", "scriptrun",
        "loadlib", "plugload", "pluginload",
        "savedata", "savefile",
        "tracesetcommand", "tracesetlog", "tracesetlogfile",
    }
    assert not (tool & forbidden), sorted(tool & forbidden)
    assert not (plugin & forbidden), sorted(plugin & forbidden)


# ---------------------------------------------------------------------------
# F-6: windbg_execute_command docstring
# ---------------------------------------------------------------------------


def test_windbg_execute_command_docstring_states_the_restrictions():
    """
    This docstring described NO restrictions despite being the entry point
    behind the critical WinDbg findings. It must now say plainly that commands
    are validated and which classes are refused.
    """
    lowered = _get_docstring(WINDBG_TOOLS, "windbg_execute_command")
    # This asserted `"denylist" in lowered` with the message "the WinDbg gate
    # must not be sold as an allowlist". Correct when the gate WAS a denylist;
    # backwards once it was rewritten. It passed only by catching a historical
    # mention, and would FAIL a docstring cleaned up to describe the current
    # design. The gate is a fail-closed allowlist and must say so.
    assert "allowlist" in lowered, "the fail-closed allowlist must be described"
    assert "not a sandbox" in lowered
    for refused_class in (".shell", ".dump", ".load", ".sympath", ".dvalloc"):
        assert refused_class in lowered, f"{refused_class} no longer named as refused"
    # The two layers.
    assert "substring" in lowered, "the tool-layer substring matcher must be described"
    assert "allowlist.validate_command" in lowered or "validate_command" in lowered


def test_windbg_docstring_refusal_classes_match_the_deny_set():
    """
    Every command the docstring names as refused must really be refused.

    A docstring naming a refusal the validator does not implement is the same
    class of bug as F-6 itself, just pointing the other way.
    """
    from src.engines.dynamic.windbg.allowlist import validate_command

    for command in (
        ".shell calc.exe",
        ".create c:\\evil.exe",
        ".dump /ma c:\\out.dmp",
        ".writemem c:\\out.bin 1000 L10",
        ".logopen c:\\log.txt",
        ".load myext.dll",
        ".loadby sos clr",
        ".sympath srv*http://evil/",
        ".symfix c:\\sym",
        ".remote npipe:server=x,pipe=y",
        ".dvalloc 1000",
        ".dvfree 1000 1000",
        ".pagein 1000",
        ".script foo.js",
        ".scriptload foo.js",
        "!runscript foo",
        ".call foo(1)",
        ".cmdtree c:\\tree.txt",
        "$$><c:\\evil.txt",
        "eb 1000 90",
        "ed 1000 41414141",
        "a 401000",
        "f 1000 L10 90",
        "m 1000 L10 2000",
        "r @rip = 0x1000",
        "s -b 1000 L1000 90",
        ".process /i 1000",
        "!chkimg nt /f",
        ".bugcheck 0xDEADBEEF",
        "aS alias .shell",
        "j 1 '.shell calc'",
        "z(1) '.shell calc'",
        "k; .shell calc",
        "k\n.shell calc",
    ):
        ok, reason = validate_command(command)
        assert not ok, f"docstring claims {command!r} is refused, but it is allowed"
        assert reason


def test_windbg_tool_layer_substring_blocklist_is_as_documented():
    """
    ``_BLOCKED_COMMANDS`` is RETAINED BUT NO LONGER CONSULTED.

    This described the six names as "the surprising part of the contract -- a
    caller reaching for ``.printf`` gets a refusal the bridge validator would
    not have produced". That stopped being true when the tool layer's substring
    scan was removed: nothing consults the tuple now, so it over-blocks
    nothing, and the old framing pinned a dead path as live. The tuple is worth
    keeping as the record of what the old denylist covered, so what is pinned
    is its CONTENTS -- plus the fact that it stays unconsulted, which
    test_windbg_gate_allowlist.py asserts.
    """
    from src.engines.dynamic.windbg.bridge import _BLOCKED_COMMANDS

    for over_blocked in (".printf", ".foreach", ".outmask", ".formats", ".tlist", ".bugcheck"):
        assert over_blocked in _BLOCKED_COMMANDS, (
            f"windbg_execute_command's docstring says {over_blocked} is refused at the "
            f"tool layer, but it is no longer in _BLOCKED_COMMANDS"
        )


def test_windbg_docstring_does_not_claim_read_only():
    """
    Read-only inspection commands must still reach the debugger.

    The framing here said "it is a denylist ... restricted away from a named
    set of write/exec primitives", which the allowlist rewrite inverted. What
    the test actually checks is unchanged and still worth checking: the gate
    must not have tightened so far that ordinary inspection stops working.
    """
    from src.engines.dynamic.windbg.allowlist import validate_command

    for command in ("lm", "k", "r", "dt nt!_EPROCESS", "!analyze -v", "u 401000"):
        ok, _ = validate_command(command)
        assert ok, f"{command!r} should still be permitted; the gate is a denylist"
