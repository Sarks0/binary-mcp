"""
Regression tests for the Ghidra headless launch hang (fixed 2026-07-22).

Root cause chain (see docs / commit message for the full write-up):

1. The MCP pointed at a Ghidra 12.1 install whose Jython extension was only a
   downloaded-but-unextracted zip, so analyzeHeadless exited 1.
2. The Jython guard that should have caught that never fired, because version
   detection read ``<install>/application.properties`` -- a path that exists on
   no real install (the file lives under ``<install>/Ghidra/``) -- so the
   version came back None and the gate treated it as "assume fine".
3. On Windows, subprocess launches a .bat as ``cmd.exe /c <bat>``; Ghidra's
   launcher reads ``%cmdcmdline%``, sees ``/c``, and sets DOUBLE_CLICKED=y.
4. A "double-clicked" launcher runs ``pause`` on a nonzero exit.
5. The runner never detached stdin, so ``pause`` blocked on -- and consumed --
   the MCP server's own JSON-RPC pipe, hanging the whole session.

Plus a secondary bug: dotted project names orphaned Ghidra ``.lock`` files
because the sanitiser preserved dots while cleanup reconstructed paths by
concatenation.

These tests lock in the four fixes. 8 of the 11 fail against the pre-fix code;
the other 3 are deliberate controls.
"""

import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

# Match the MCP/fastmcp shim used by the other runner tests so importing the
# runner (which transitively pulls in src.*) works without the real deps.
sys.modules["mcp"] = MagicMock()
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.types"] = MagicMock()
_identity_decorator = lambda fn: fn  # noqa: E731
_fastmcp_instance = MagicMock()
_fastmcp_instance.tool = MagicMock(return_value=_identity_decorator)
_fastmcp_stub = MagicMock()
_fastmcp_stub.FastMCP = MagicMock(return_value=_fastmcp_instance)
sys.modules["fastmcp"] = _fastmcp_stub


from src.engines.static.ghidra.runner import GhidraRunner  # noqa: E402
from src.utils.security import UserFacingError  # noqa: E402


@pytest.fixture(autouse=True)
def _no_real_user_extensions(monkeypatch):
    """Neutralise the per-user Jython scan so negative tests don't flip green
    on a dev machine that happens to have Jython installed system-wide."""
    monkeypatch.setattr(
        GhidraRunner, "_user_settings_extension_roots", lambda self: []
    )


# -- helpers ----------------------------------------------------------------


def _stub_install(
    base_dir,
    *,
    version: str | None = "11.4",
    version_at_root: bool = False,
    jython_dir_rel: str | None = None,
    extra_files: tuple[str, ...] = (),
):
    """
    Create a minimal Ghidra install under ``base_dir/ghidra``.

    ``version_at_root`` selects where application.properties is written:
      - False (default): under ``Ghidra/`` -- the REAL install layout.
      - True: at the install root -- the layout the older fixtures used.
    """
    install = base_dir / "ghidra"
    (install / "support").mkdir(parents=True)
    (install / "support" / "analyzeHeadless").touch()
    (install / "support" / "analyzeHeadless.bat").touch()

    if version is not None:
        rel = "application.properties" if version_at_root \
            else "Ghidra/application.properties"
        prop = install / rel
        prop.parent.mkdir(parents=True, exist_ok=True)
        prop.write_text(
            f"application.name=Ghidra\napplication.version={version}\n",
            encoding="utf-8",
        )

    if jython_dir_rel:
        jdir = install / jython_dir_rel
        jdir.mkdir(parents=True)
        (jdir / "jython-standalone.jar").write_bytes(b"PK\x03\x04")

    for rel in extra_files:
        path = install / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"stub")

    return install


def _run_analyze_capturing_popen(runner, tmp_path, binary_name="sample.bin",
                                  project_name=None):
    """
    Drive ``analyze()`` far enough to spawn the subprocess, capturing the
    Popen args, then abort cleanly. Returns (popen_args, popen_kwargs).

    We stub the Jython gate open (so we reach Popen regardless of the fixture)
    and make Popen return a fake process that "succeeds" with empty output; the
    output file won't exist, but we only care about how Popen was called, so we
    intercept before analyze() inspects the result by raising from communicate.
    """
    binary = tmp_path / binary_name
    binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
    script_dir = tmp_path / "scripts"
    script_dir.mkdir()
    output = tmp_path / "out.json"

    captured = {}

    class _FakeProc:
        returncode = 0
        pid = 4321

        def communicate(self, timeout=None):
            return ("", "")

        def poll(self):
            return 0

    def _fake_popen(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _FakeProc()

    runner.ensure_jython_available = lambda: None  # bypass the gate for this path
    with patch("subprocess.Popen", _fake_popen):
        try:
            runner.analyze(
                binary_path=str(binary),
                script_path=str(script_dir),
                script_name="core_analysis.py",
                output_path=str(output),
                project_name=project_name,
                timeout=30,
            )
        except Exception:
            # analyze() raises later (no output file produced); irrelevant here.
            pass
    return captured.get("args"), captured.get("kwargs")


# -- Fix 1: stdin detachment (the hang) -------------------------------------


def test_popen_detaches_stdin(tmp_path):
    """The child MUST get stdin=DEVNULL so a Windows `pause` can't block on --
    and consume -- the MCP server's JSON-RPC stdin."""
    install = _stub_install(tmp_path, version="11.4")
    runner = GhidraRunner(ghidra_path=str(install))
    _, kwargs = _run_analyze_capturing_popen(runner, tmp_path)
    assert kwargs is not None, "Popen was never called"
    assert kwargs.get("stdin") == subprocess.DEVNULL


def test_popen_still_captures_stdout_stderr(tmp_path):
    """Control: detaching stdin must not disturb stdout/stderr capture."""
    install = _stub_install(tmp_path, version="11.4")
    runner = GhidraRunner(ghidra_path=str(install))
    _, kwargs = _run_analyze_capturing_popen(runner, tmp_path)
    assert kwargs.get("stdout") == subprocess.PIPE
    assert kwargs.get("stderr") == subprocess.PIPE


# -- Fix 2: version detection on the real install layout --------------------


def test_version_detected_under_ghidra_subdir(tmp_path):
    """application.properties under Ghidra/ (the real layout) must resolve."""
    install = _stub_install(tmp_path, version="12.1.2", version_at_root=False)
    runner = GhidraRunner(ghidra_path=str(install))
    assert runner._get_ghidra_version() == (12, 1)


def test_version_detected_at_root_still_works(tmp_path):
    """Control: the root-layout the minimal fixtures use must keep working."""
    install = _stub_install(tmp_path, version="11.4", version_at_root=True)
    runner = GhidraRunner(ghidra_path=str(install))
    assert runner._get_ghidra_version() == (11, 4)


# -- Fix 2 (cont.): the Jython gate actually fires now ----------------------


def test_jython_gate_fires_on_real_layout_without_extension(tmp_path):
    """12.1 real-layout install with NO Jython must raise, not silently pass."""
    install = _stub_install(tmp_path, version="12.1.2", version_at_root=False)
    runner = GhidraRunner(ghidra_path=str(install))
    with pytest.raises(UserFacingError, match="Jython"):
        runner.ensure_jython_available()


def test_jython_gate_rejects_downloaded_but_unextracted_zip(tmp_path):
    """A downloaded Jython *.zip that was never installed must NOT satisfy the
    gate -- analyzeHeadless can't load an un-extracted extension."""
    install = _stub_install(
        tmp_path,
        version="12.1.2",
        version_at_root=False,
        extra_files=(
            "Extensions/Ghidra/ghidra_12.1.2_PUBLIC_Jython.zip",
        ),
    )
    runner = GhidraRunner(ghidra_path=str(install))
    with pytest.raises(UserFacingError, match="Jython"):
        runner.ensure_jython_available()


def test_jython_gate_passes_when_extension_installed(tmp_path):
    """Control-ish: an actually-installed extension satisfies the gate."""
    install = _stub_install(
        tmp_path,
        version="12.1.2",
        version_at_root=False,
        jython_dir_rel="Ghidra/Extensions/Jython/lib",
    )
    runner = GhidraRunner(ghidra_path=str(install))
    runner.ensure_jython_available()  # must not raise


# -- Fix 3: dot flattening in project names ---------------------------------


def test_dotted_derived_project_name_is_flattened(tmp_path):
    """A dotted sample name must yield a dot-free Ghidra project name so the
    files Ghidra creates match the paths cleanup reconstructs."""
    install = _stub_install(tmp_path, version="11.4")
    runner = GhidraRunner(ghidra_path=str(install))
    args, _ = _run_analyze_capturing_popen(
        runner, tmp_path, binary_name="okular.stage2.exe"
    )
    cmd = args[0]
    # cmd = [analyzeHeadless, project_dir, project_name, "-import", binary, ...]
    project_name = cmd[2]
    assert "." not in project_name
    assert project_name == "okular_stage2"


def test_dotted_explicit_project_name_is_flattened(tmp_path):
    """An explicitly-supplied dotted project name is flattened too."""
    install = _stub_install(tmp_path, version="11.4")
    runner = GhidraRunner(ghidra_path=str(install))
    args, _ = _run_analyze_capturing_popen(
        runner, tmp_path, project_name="my.proj.v2"
    )
    assert "." not in args[0][2]
    assert args[0][2] == "my_proj_v2"


# -- Fix 4: environment variable resolution ---------------------------------


def test_ghidra_install_dir_is_honoured(tmp_path, monkeypatch):
    """GHIDRA_INSTALL_DIR (Ghidra's canonical name) must be read, not ignored."""
    install = _stub_install(tmp_path, version="11.4")
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(install))
    runner = GhidraRunner()
    assert runner.ghidra_path == install


def test_invalid_ghidra_home_does_not_mask_valid_install_dir(tmp_path, monkeypatch):
    """A bogus GHIDRA_HOME must fall through to a valid GHIDRA_INSTALL_DIR
    rather than dropping to slow auto-detection (or failing)."""
    install = _stub_install(tmp_path, version="11.4")
    monkeypatch.setenv("GHIDRA_HOME", str(tmp_path / "does-not-exist"))
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(install))
    runner = GhidraRunner()
    assert runner.ghidra_path == install


def test_ghidra_home_takes_precedence_over_install_dir(tmp_path, monkeypatch):
    """Control: when both are valid, GHIDRA_HOME wins (historical precedence)."""
    home = _stub_install(tmp_path / "a", version="11.4")
    other = _stub_install(tmp_path / "b", version="11.4")
    monkeypatch.setenv("GHIDRA_HOME", str(home))
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(other))
    runner = GhidraRunner()
    assert runner.ghidra_path == home
