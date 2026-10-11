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
import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
README = REPO_ROOT / "README.md"
# The capability tables, the security model and the configuration reference
# moved out of README.md into docs/ when the README was cut down to an
# overview. They are the same claims about the same code, so the assertions
# follow them to their new files rather than being dropped, and
# test_readme_links_to_the_claim_docs keeps each one reachable from the front
# page. A claim nobody can find is only marginally better than a false one.
ARCHITECTURE_SCENE = REPO_ROOT / "docs" / "architecture.excalidraw"
TOOLS_DOC = REPO_ROOT / "docs" / "tools.md"
SECURITY_DOC = REPO_ROOT / "docs" / "security.md"
CONFIG_DOC = REPO_ROOT / "docs" / "configuration.md"
CLAIM_DOCS = (README, TOOLS_DOC, SECURITY_DOC, CONFIG_DOC)
PYPROJECT = REPO_ROOT / "pyproject.toml"
SERVER_PY = SRC / "server.py"
DYNAMIC_TOOLS = SRC / "tools" / "dynamic_tools.py"
WINDBG_TOOLS = SRC / "tools" / "windbg_tools.py"
VT_TOOLS = SRC / "tools" / "vt_tools.py"
PLUGIN_CPP = SRC / "engines" / "dynamic" / "x64dbg" / "plugin" / "plugin.cpp"


# Helpers


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


# F-11: tool counts


def test_tool_reference_headline_count_matches_code():
    """docs/tools.md '## Capabilities (N tools)' must equal the real tool count."""
    text = TOOLS_DOC.read_text(encoding="utf-8")
    match = re.search(r"^## Capabilities \((\d+) tools\)", text, re.M)
    assert match, "docs/tools.md is missing the '## Capabilities (N tools)' heading"
    assert int(match.group(1)) == count_registered_tools()


def test_readme_tool_count_matches_code():
    """
    The README's pitch names a tool count too, and it drifts like any other.

    It used to carry the whole capability table, so the heading assertion above
    covered it. Now it just says "N tools" in prose and links to docs/tools.md;
    every such number in the file must still be the real one, or the front page
    advertises a roster the server does not have.
    """
    counts = {int(n) for n in re.findall(r"(\d+) tools", README.read_text(encoding="utf-8"))}
    assert counts, "README no longer states a tool count at all"
    assert counts == {count_registered_tools()}, (
        f"README advertises {sorted(counts)} tools; the code registers "
        f"{count_registered_tools()}"
    )


def test_no_file_uses_an_em_dash_or_its_lookalikes():
    """
    Em dashes are not used in this project's prose; ordinary punctuation is.

    This is a house style rule, so it needs a test for the same reason the
    banner comments did: a rule nothing enforces is one that comes back a
    commit at a time, and the character is invisible in review because it
    looks like punctuation rather than a mistake.

    The lookalikes are included because replacing one dash with a slightly
    different dash is the obvious way to satisfy the letter of the rule and
    miss it: U+2013 EN DASH reads almost identically at small sizes, and
    U+2212 MINUS SIGN was in docs/coverage.md doing arithmetic where ASCII
    '-' belongs. ASCII hyphen-minus is always fine and is not checked.
    """
    forbidden = {
        "\u2010": "HYPHEN",
        "\u2011": "NON-BREAKING HYPHEN",
        "\u2012": "FIGURE DASH",
        "\u2013": "EN DASH",
        "\u2014": "EM DASH",
        "\u2015": "HORIZONTAL BAR",
        "\u2212": "MINUS SIGN",
        "\ufe58": "SMALL EM DASH",
        "\uff0d": "FULLWIDTH HYPHEN-MINUS",
    }
    skip_dirs = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache"}
    # Checked where a human writes prose. uv.lock and the Excalidraw scene are
    # generated or tool-owned, and LICENSE is not ours to edit.
    suffixes = {".md", ".py", ".txt", ".yml", ".yaml", ".toml", ".cpp", ".h", ".ps1", ".sh"}
    offenders = []
    for path in sorted(REPO_ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in suffixes:
            continue
        if set(path.relative_to(REPO_ROOT).parts) & skip_dirs:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for char, name in forbidden.items():
            if char in text:
                line = text[: text.index(char)].count("\n") + 1
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{line} has {name}")
    assert not offenders, "Use ordinary punctuation instead:\n" + "\n".join(offenders)


def test_architecture_diagram_tool_count_matches_code():
    """
    The README's architecture diagram states a tool count, and it drifts too.

    It is a PNG on the page, which is why this reads the Excalidraw scene the
    PNG is exported from instead. That distinction is the whole point of the
    test: the diagram shipped claiming 290 tools against 147 registered, and
    every other assertion in this file was blind to it, because a number
    rasterised into an image is not text any of them can see. The scene is
    JSON, so the claim is checkable at the one place an editor actually edits.

    This asserts the count only. Everything else the diagram says is prose
    about the architecture and is no more checkable here than it is in the
    surrounding docs; a number that contradicts the README two screens up is a
    different kind of wrong.
    """
    scene = json.loads(ARCHITECTURE_SCENE.read_text(encoding="utf-8"))
    labels = [
        element["text"]
        for element in scene["elements"]
        if element.get("type") == "text" and "MCP tools" in element.get("text", "")
    ]
    assert len(labels) == 1, (
        f"expected exactly one 'N MCP tools' label in {ARCHITECTURE_SCENE.name}, found {labels}"
    )
    match = re.search(r"(\d+) MCP tools", labels[0])
    assert match, f"the diagram's tool-count label lost its number: {labels[0]!r}"
    assert int(match.group(1)) == count_registered_tools(), (
        f"the architecture diagram advertises {match.group(1)} tools; the code "
        f"registers {count_registered_tools()}. Edit "
        f"{ARCHITECTURE_SCENE.name} and re-export both PNGs in docs/images/."
    )


def test_architecture_diagram_pngs_are_present():
    """
    The README references both themes; a missing one renders as a broken image.

    Cheap to assert and easy to get wrong, because the scene and the exports
    are three separate files that a careless edit updates one of.
    """
    for theme in ("dark", "light"):
        png = REPO_ROOT / "docs" / "images" / f"architecture-{theme}.png"
        assert png.is_file(), f"{png.relative_to(REPO_ROOT)} is missing"
        assert png.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n", f"{png.name} is not a PNG"
        assert f"architecture-{theme}.png" in README.read_text(encoding="utf-8"), (
            f"architecture-{theme}.png is not referenced by README.md"
        )


def test_server_module_docstring_tool_count_matches_code():
    """src/server.py's module docstring must not overstate the tool count."""
    tree = ast.parse(SERVER_PY.read_text(encoding="utf-8"), filename=str(SERVER_PY))
    doc = ast.get_docstring(tree)
    assert doc, "src/server.py lost its module docstring"
    match = re.search(r"Provides (\d+) tools", doc)
    assert match, "server.py docstring no longer states a tool count"
    assert int(match.group(1)) == count_registered_tools()


def test_tool_reference_category_counts_sum_to_total():
    """
    The per-category '### Name - N tools' counts must add up to the headline.

    The original table's categories summed to 245 while the code registered
    279; a table that sums to the wrong number is the shape the bug took, so
    the sum is what gets asserted.
    """
    text = TOOLS_DOC.read_text(encoding="utf-8")
    section_counts = [int(n) for n in re.findall(r"^### .+ - (\d+) tools?$", text, re.M)]
    assert section_counts, "docs/tools.md no longer lists per-category tool counts"
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
        # Registration was moved out of main() into register_all_tools(),
        # which main() calls; collect register_* calls from both so the
        # invariant still covers every module's entry point.
        if isinstance(node, ast.FunctionDef) and node.name in ("main", "register_all_tools"):
            for call in ast.walk(node):
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                    if call.func.id.startswith("register_"):
                        called.add(call.func.id)
    assert called, "main()/register_all_tools() no longer calls any register_*_tools function"

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


# F-11: VirusTotal is lookup-only, samples are never uploaded


def test_no_doc_advertises_virustotal_submission():
    """
    The README promised VT 'file submission'. No such tool exists.

    This is good security -- no sample exfiltration path can fire, even by
    accident -- but the promise had to go, and it must not come back without
    the code to match it. Swept across every claim-bearing doc, not just the
    README: the promise would be equally false in docs/tools.md.
    """
    for path in CLAIM_DOCS:
        text = path.read_text(encoding="utf-8").lower()
        for claim in ("file submission", "submit file", "upload sample", "sample upload"):
            assert claim not in text, f"{path.name} re-advertises VirusTotal {claim!r}"


def test_docs_state_samples_are_never_uploaded():
    """
    The never-uploads property is a genuine selling point; keep it stated.

    Required in BOTH places on purpose: docs/security.md is where the claim is
    argued from the code, and the README is where someone deciding whether to
    point this at a sample will actually read it.
    """
    for path in (README, SECURITY_DOC):
        text = path.read_text(encoding="utf-8").lower()
        assert "never uploaded" in text or "never upload" in text, (
            f"{path.name} no longer states that samples are never uploaded"
        )


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


# F-11: YARA is generation-only, and the dead extra stays gone


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


def test_tool_reference_describes_yara_as_generation_not_scanning():
    text = TOOLS_DOC.read_text(encoding="utf-8")
    yara_lines = [ln for ln in text.splitlines() if "YARA" in ln or "yara" in ln]
    assert yara_lines, "docs/tools.md no longer mentions YARA at all"
    joined = " ".join(yara_lines).lower()
    assert "generation" in joined or "generate" in joined
    assert "rule scanning" not in joined
    assert "yara-python" not in joined, "the docs still point at the removed extra"


# F-11: 'analyze in a VM' guidance, and the code that backs it


def test_docs_carry_isolated_vm_guidance():
    """Also required in both places, and for the same reason as never-uploaded."""
    for path in (README, SECURITY_DOC):
        text = path.read_text(encoding="utf-8").lower()
        assert "isolated vm" in text or "isolated virtual machine" in text, (
            f"{path.name} no longer tells the reader to work in an isolated VM"
        )


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


def test_docs_document_confinement_controls():
    """
    Every confinement knob has to be documented somewhere a reader can find.

    docs/configuration.md is the reference and must name all three;
    docs/security.md must at least name the allow-list, since that is where the
    default posture is explained and an operator who reads only that page still
    needs to know the variable exists.
    """
    config_text = CONFIG_DOC.read_text(encoding="utf-8")
    for var in (
        "BINARY_MCP_ALLOWED_DIRS",
        "BINARY_MCP_REQUIRE_CONFINEMENT",
        "BINARY_MCP_ALLOW_ANY_PATH",
    ):
        assert var in config_text, f"docs/configuration.md no longer documents {var}"

    assert "BINARY_MCP_ALLOWED_DIRS" in SECURITY_DOC.read_text(encoding="utf-8"), (
        "docs/security.md explains the default confinement posture but no longer "
        "names the variable that changes it"
    )


def test_readme_links_to_the_claim_docs():
    """
    The README is an overview now, so its job is to route to the detail.

    Without this, the tests above could all pass against docs that nothing
    links to: the tool roster, the security model and the config reference
    would be correct and unreachable. Every path asserted here is a file the
    other tests in this module pin.
    """
    text = README.read_text(encoding="utf-8")
    for target in ("docs/tools.md", "docs/security.md", "docs/configuration.md", "INSTALL.md"):
        assert target in text, f"README no longer links to {target}"


def test_documented_confinement_defaults_match_security_module():
    """
    docs/security.md describes the CURRENT default posture; verify it in code.

    Defaults moved during this audit (F-8: unset used to mean "any path").
    A doc that describes the old posture is worse than one that says nothing,
    because an operator would skip configuring an allow-list they actually
    still need.
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


def test_documented_auto_pdb_default_matches_code():
    """
    The symbol-fetch default decides whether sample metadata leaves the host.

    docs/security.md and docs/configuration.md both state the default policy is
    `microsoft` -- fetch a PDB only for binaries whose version info names
    Microsoft. If that default ever became `always`, both docs would be telling
    an analyst their samples stay private while every first import announced one
    to the symbol server. test_auto_pdb.py asserts auto_pdb_policy() ==
    AUTO_PDB_DEFAULT, which holds whatever that constant is, so the literal is
    what gets pinned here, together with the docs that quote it.
    """
    from src.utils.pdb_fetcher import AUTO_PDB_DEFAULT, AUTO_PDB_POLICIES

    assert AUTO_PDB_DEFAULT == "microsoft", (
        "the BINARY_MCP_AUTO_PDB default changed; docs/security.md and "
        "docs/configuration.md both state `microsoft`"
    )
    assert set(AUTO_PDB_POLICIES) == {"microsoft", "always", "never"}

    for path in (SECURITY_DOC, CONFIG_DOC):
        text = path.read_text(encoding="utf-8")
        assert "BINARY_MCP_AUTO_PDB" in text, f"{path.name} no longer names the key"
        assert "`microsoft`" in text, (
            f"{path.name} no longer states the default symbol-fetch policy"
        )


# F-6: x64dbg_execute_command docstring


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


# F-6: windbg_execute_command docstring


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


# The configuration surface
#
# CONFIG_KEYS in src/utils/config.py is the project's own description of the
# knobs it honours, and `diagnose_setup` reports against it -- so a key listed
# there that nothing reads is not a cosmetic docs bug. It is an operator
# setting a variable, seeing it acknowledged, and getting no change in
# behaviour. Four keys were in exactly that state:
#
#   X64DBG_BRIDGE_URL     advertised "http://localhost:27042"; the bridge reads
#                         X64DBG_HOST/X64DBG_PORT and binds 8765
#   BINARY_MCP_CACHE_DIR  the real name is BINARY_CACHE_DIR
#   BINARY_MCP_SESSION_DIR  nothing read it; UnifiedSessionManager now does
#   BINARY_MCP_LOG_LEVEL    nothing read it; basicConfig now does
#
# The two tests below close that loop from both sides, which is the only way a
# surface like this stays true: one refuses a key nothing reads, the other
# refuses an operator-facing variable nothing documents.

# Prefixes that mark an environment variable as this project's own.
PROJECT_ENV_PREFIXES = (
    "BINARY_MCP_",
    "BINARY_CACHE_DIR",
    "GHIDRA_",
    "X64DBG_",
    "WINDBG_",
    "KDNET_",
    "VT_",
    "OBSIDIAN_",
)

# Variables that are real, read by src/, and deliberately absent from
# CONFIG_KEYS because they are not operator-facing. Each one is an internal
# channel between two parts of this project, so documenting it as a setting
# would invite someone to set it.
INTERNAL_ENV_VARS = {
    # Server -> Ghidra Jython subprocess. Set by the runner on every launch;
    # a value the operator supplied would be overwritten.
    "GHIDRA_CONTEXT_JSON",
    "GHIDRA_TARGET_ADDRESSES",
    "GHIDRA_ANALYSIS_BUDGET",
    "GHIDRA_ANALYSIS_DEPTH",
    # OBSIDIAN_AUTH_TOKEN used to be listed here, as "an escape hatch
    # documented in a procedure rather than a server setting". It stopped being
    # that when the endpoint policy made it REQUIRED for a non-loopback
    # debugger host, so it moved to CONFIG_KEYS. Nothing internal is left in
    # this direction.
}


# Functions whose first positional string argument names an environment
# variable. get_config* live in src/utils/config.py; the os.* forms are used
# directly where config.py is not imported.
_ENV_READ_FUNCS = frozenset({"getenv", "get_config", "get_config_bool", "get_config_int"})


def _subscript_base_name(node: ast.AST) -> str:
    """Name of the thing being subscripted, for ``os.environ[...]`` / ``env[...]``."""
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _project_env_literals() -> dict[str, list[Path]]:
    """Map every project environment variable named in src/ to the files naming it.

    Three shapes are collected, because the codebase uses all three and a
    collector that missed one would report a real variable as undocumented (or
    a documented key as dead):

      1. the first string argument of an env-reading call --
         ``os.environ.get("X")``, ``os.getenv("X")``, ``get_config("X")``;
      2. a subscript of an environment mapping -- ``os.environ["X"]``, and
         ``env["X"] = ...`` where a subprocess environment is being built;
      3. a module constant whose name contains ENV --
         ``ENV_ALLOW_ANY_PATH = "BINARY_MCP_ALLOW_ANY_PATH"``. security.py,
         windbg_tools.py, pdb_fetcher.py and remote.py all bind their variable
         names this way and then pass the constant, so the literal never
         appears at the call site;
      4. the elements of a literal sequence a ``for`` loop iterates --
         ``for var in ("GHIDRA_HOME", "GHIDRA_INSTALL_DIR")``, which is how
         GhidraRunner checks an alias chain.

    A bare uppercase string is deliberately NOT enough. ``ErrorCode`` members
    in src/utils/structured_errors.py are spelled exactly like environment
    variables (``WINDBG_NOT_FOUND = "WINDBG_NOT_FOUND"``), and treating those
    as settings would fill this test with findings that are not variables at
    all.
    """
    found: dict[str, list[Path]] = {}

    def record(name: object, path: Path) -> None:
        if isinstance(name, str) and name.isupper() and name.startswith(PROJECT_ENV_PREFIXES):
            found.setdefault(name, []).append(path)

    for path in _iter_python_sources():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue  # Jython 2.7 analysis scripts are not Python 3
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript):
                base = _subscript_base_name(node.value)
                if base in ("environ", "env") and isinstance(node.slice, ast.Constant):
                    record(node.slice.value, path)
            elif isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                is_env_read = name in _ENV_READ_FUNCS or (
                    name == "get"
                    and isinstance(func, ast.Attribute)
                    and _subscript_base_name(func.value) == "environ"
                )
                if is_env_read and node.args and isinstance(node.args[0], ast.Constant):
                    record(node.args[0].value, path)
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                for target in node.targets:
                    if isinstance(target, ast.Name) and "ENV" in target.id.upper():
                        record(node.value.value, path)
            elif isinstance(node, ast.For) and isinstance(node.iter, (ast.Tuple, ast.List)):
                for element in node.iter.elts:
                    if isinstance(element, ast.Constant):
                        record(element.value, path)

    return found


def test_no_config_key_is_dead():
    """Every key in CONFIG_KEYS is read by something outside config.py.

    This is the test X64DBG_BRIDGE_URL would have failed for its whole life.
    """
    from src.utils.config import CONFIG_KEYS

    config_py = SRC / "utils" / "config.py"
    readers = {
        name: [p for p in paths if p != config_py]
        for name, paths in _project_env_literals().items()
    }
    dead = sorted(key for key in CONFIG_KEYS if not readers.get(key))
    assert not dead, (
        f"CONFIG_KEYS advertises {dead}, but no module outside config.py "
        f"mentions them. Either wire the key up or remove it -- a key the "
        f"server acknowledges and ignores is worse than one it never offered."
    )


def test_no_operator_facing_env_var_is_undocumented():
    """Every project env var read by src/ is in CONFIG_KEYS or named internal.

    The counterpart to the test above. Without it, a new setting (the transport
    and remote keys are the current example) can be read by the code and
    documented nowhere, which is how CONFIG_KEYS fell behind in the first
    place.
    """
    from src.utils.config import CONFIG_KEYS

    undocumented = sorted(
        name
        for name in _project_env_literals()
        if name not in CONFIG_KEYS and name not in INTERNAL_ENV_VARS
    )
    assert not undocumented, (
        f"src/ reads {undocumented}, which appear in neither CONFIG_KEYS nor "
        f"INTERNAL_ENV_VARS. Add operator-facing keys to CONFIG_KEYS (and to "
        f"docs/configuration.md), or list them as internal here with a reason."
    )


def test_configuration_doc_documents_the_transport_keys():
    """The HTTP transport's controls are reachable from the configuration reference.

    Pinned separately from the generic check above because these are the keys
    that decide whether this server is reachable from the network. An operator
    who cannot find them cannot turn them on correctly -- and the fail-closed
    policy means they will be refused rather than silently exposed, which only
    helps if the refusal points somewhere.
    """
    config_text = CONFIG_DOC.read_text(encoding="utf-8")
    for var in (
        "BINARY_MCP_TRANSPORT",
        "BINARY_MCP_HTTP_HOST",
        "BINARY_MCP_HTTP_TOKEN",
        "BINARY_MCP_REMOTE_ALLOW",
        "BINARY_MCP_REMOTE_TLS_CERT",
        "BINARY_MCP_REMOTE_TLS_CA",
        "BINARY_MCP_REMOTE_CLIENT_ALLOWLIST",
    ):
        assert var in config_text, f"docs/configuration.md no longer documents {var}"


def test_security_doc_covers_the_http_transport():
    """docs/security.md must state what the HTTP transport exposes.

    The rest of that file was written for a server reachable only as a
    subprocess of its own client. A transport that accepts network connections
    changes the threat model, so the page has to say so.
    """
    security_text = SECURITY_DOC.read_text(encoding="utf-8")
    assert "BINARY_MCP_TRANSPORT" in security_text, (
        "docs/security.md does not mention the HTTP transport, which is the one "
        "setting that makes this server reachable from another host"
    )
    assert "BINARY_MCP_REMOTE_ALLOW" in security_text, (
        "docs/security.md does not name the opt-in required for a non-loopback bind"
    )


def test_stdio_is_still_the_default_transport():
    """The default must stay stdio: no listener unless asked for.

    Pinned against the code, not the docs, because this is the claim the
    security model rests on.
    """
    import src.utils.remote as remote

    assert remote.resolve_transport_config.__module__ == "src.utils.remote"
    # Resolved with the transport variable absent from the environment.
    import os

    saved = os.environ.pop(remote.ENV_TRANSPORT, None)
    try:
        import src.utils.config as config_module

        saved_cache, saved_loaded = config_module._config_cache, config_module._env_loaded
        config_module._config_cache, config_module._env_loaded = {}, True
        try:
            assert remote.resolve_transport_config().transport == "stdio"
        finally:
            config_module._config_cache = saved_cache
            config_module._env_loaded = saved_loaded
    finally:
        if saved is not None:
            os.environ[remote.ENV_TRANSPORT] = saved


def test_http_transport_is_gated_in_the_server_entry_point():
    """src/server.py must route the http transport through RemoteAccessGate.

    AST-based because importing src.server needs a Ghidra installation. The
    failure this guards against is a plain ``app.run(transport="http", ...)``
    added later: it would serve the full tool roster to anyone who can reach
    the port, with no token, Host check or client allowlist.
    """
    tree = ast.parse(SERVER_PY.read_text(encoding="utf-8"))
    http_runs = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and any(
            kw.arg == "transport"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value in ("http", "streamable-http", "sse")
            for kw in node.keywords
        )
    ]
    assert http_runs, "src/server.py no longer starts an HTTP transport at all"
    for call in http_runs:
        middleware = [kw for kw in call.keywords if kw.arg == "middleware"]
        assert middleware, (
            "an HTTP transport is started in src/server.py without a middleware "
            "argument, so RemoteAccessGate is not in front of it"
        )
        assert "RemoteAccessGate" in ast.dump(middleware[0].value), (
            "the HTTP transport's middleware does not include RemoteAccessGate"
        )
