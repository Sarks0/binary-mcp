"""
Tests for attaching analysis to a pre-existing Ghidra project.

The workflow this supports: a human imports a binary into the Ghidra GUI,
renames functions and writes comments, and then wants that work available to
the MCP server instead of a fresh throwaway import. The project is the source
of truth -- a re-pull replaces what is in the analysis cache.

Covers:
- Discovery of projects on disk (both storage schemes, lock detection).
- Command construction: -process rather than -import, and the flags that make
  the read non-destructive.
- The delete guard, which is the whole safety story: a project we did not
  create must survive the failure paths that rmtree a managed one.
- Identity verification, so one program's functions cannot be filed under
  another binary's cache key.
- Rename-clobber accounting, so the authoritative-project contract is visible
  rather than silent.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.modules["mcp"] = MagicMock()
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.types"] = MagicMock()
_identity_decorator = lambda fn: fn  # noqa: E731
_fastmcp_instance = MagicMock()
_fastmcp_instance.tool = MagicMock(return_value=_identity_decorator)
_fastmcp_stub = MagicMock()
_fastmcp_stub.FastMCP = MagicMock(return_value=_fastmcp_instance)
sys.modules["fastmcp"] = _fastmcp_stub


# Fixtures


def _make_ghidra_install(tmp_path: Path) -> Path:
    """Minimal tree that satisfies GhidraRunner's install validation."""
    ghidra = tmp_path / "ghidra"
    (ghidra / "support").mkdir(parents=True)
    headless = ghidra / "support" / "analyzeHeadless"
    headless.write_text("#!/bin/sh\nexit 0\n")
    headless.chmod(0o755)
    return ghidra


def _make_project(
    directory: Path, name: str, programs: list[str] | None = None, locked: bool = False
) -> Path:
    """Create a project on disk using the current (indexed) storage scheme."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.gpr").write_text("")
    idata = directory / f"{name}.rep" / "idata"
    idata.mkdir(parents=True)
    if programs is not None:
        lines = ["VERSION=1", "/"]
        for i, prog in enumerate(programs):
            lines.append(f"  ~{i:08d}:{prog}:{i:04x}")
        lines += [f"NEXT-ID:{len(programs):x}", "MD5:0"]
        (idata / "~index.dat").write_text("\n".join(lines) + "\n")
    if locked:
        (directory / f"{name}.lock").write_text("")
    return directory / f"{name}.gpr"


def _make_binary(tmp_path: Path, name: str = "okular.exe") -> Path:
    binary = tmp_path / name
    binary.write_bytes(b"MZ" + b"\x00" * 512)
    return binary


@pytest.fixture
def runner(tmp_path, monkeypatch):
    from src.engines.static.ghidra.runner import GhidraRunner

    r = GhidraRunner(str(_make_ghidra_install(tmp_path)))
    # The Jython precondition stats a real install tree; the fixture above is
    # deliberately minimal, so short-circuit it.
    r._jython_check_done = True
    return r


class _FakeProc:
    pid = 4242
    returncode = 0
    stdout = None
    stderr = None

    def communicate(self, timeout=None):
        return ("Ghidra output", "")

    def poll(self):
        return 0

    def kill(self):
        pass


@pytest.fixture
def captured_cmd(monkeypatch):
    """Capture the argv GhidraRunner.analyze builds, without running Ghidra."""
    captured: dict = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return _FakeProc()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    return captured


# Discovery


class TestDiscovery:
    def test_finds_projects_and_programs(self, tmp_path, monkeypatch):
        from src.engines.static.ghidra import project_discovery as pd

        monkeypatch.setenv("BINARY_CACHE_DIR", str(tmp_path / "cache"))
        gui = tmp_path / "gui"
        _make_project(gui, "okular.stage2", programs=["okular.exe", "helper.dll"])

        projects = pd.discover_projects([gui])
        assert [p.name for p in projects] == ["okular.stage2"]
        assert projects[0].program_names == ["okular.exe", "helper.dll"]

    def test_dotted_project_name_survives(self, tmp_path):
        """A GUI project may be called anything; we must not rewrite the name.

        The import path sanitises dots out of project names, but that is only
        safe for names it invents. Applying it to a name that already exists on
        disk would send Ghidra to a project that isn't there.
        """
        from src.engines.static.ghidra import project_discovery as pd

        gui = tmp_path / "gui"
        _make_project(gui, "okular.stage2", programs=["okular.exe"])
        assert pd.find_project("okular.stage2", [gui]).name == "okular.stage2"

    def test_index_fileid_suffix_is_stripped(self, tmp_path):
        """Item lines are ``storage:name[:fileId]`` -- the id is not the name."""
        from src.engines.static.ghidra import project_discovery as pd

        gui = tmp_path / "gui"
        _make_project(gui, "P", programs=["thing.exe"])
        assert pd.find_project("P", [gui]).program_names == ["thing.exe"]

    def test_subfolder_programs_get_their_path(self, tmp_path):
        from src.engines.static.ghidra import project_discovery as pd

        gui = tmp_path / "gui"
        _make_project(gui, "P", programs=[])
        idata = gui / "P.rep" / "idata"
        (idata / "~index.dat").write_text(
            "VERSION=1\n/\n  ~0:root.exe\n/stage2\n  ~1:payload.bin\nNEXT-ID:2\nMD5:0\n"
        )
        progs = {p.name: p.path for p in pd.find_project("P", [gui]).programs}
        assert progs == {"root.exe": "/root.exe", "payload.bin": "/stage2/payload.bin"}

    def test_legacy_mangled_scheme_via_prp(self, tmp_path):
        """Projects with no ~index.dat fall back to .prp property files."""
        from src.engines.static.ghidra import project_discovery as pd

        gui = tmp_path / "gui"
        _make_project(gui, "Legacy", programs=None)
        item = gui / "Legacy.rep" / "idata" / "_o_kular"
        item.mkdir(parents=True)
        (item / "thing.prp").write_text(
            '<FILE_INFO><BASIC_INFO>'
            '<STATE NAME="NAME" TYPE="string" VALUE="old_thing.exe" />'
            '<STATE NAME="CONTENT_TYPE" TYPE="string" VALUE="Program" />'
            "</BASIC_INFO></FILE_INFO>"
        )
        assert pd.find_project("Legacy", [gui]).program_names == ["old_thing.exe"]

    def test_lock_file_is_reported(self, tmp_path):
        from src.engines.static.ghidra import project_discovery as pd

        gui = tmp_path / "gui"
        _make_project(gui, "Open", programs=["a.exe"], locked=True)
        _make_project(gui, "Closed", programs=["b.exe"])
        by_name = {p.name: p.locked for p in pd.discover_projects([gui])}
        assert by_name == {"Open": True, "Closed": False}

    def test_unreadable_project_reports_error_not_crash(self, tmp_path):
        """A .gpr with no .rep must list, flagged, rather than sink the listing."""
        from src.engines.static.ghidra import project_discovery as pd

        gui = tmp_path / "gui"
        gui.mkdir()
        (gui / "Broken.gpr").write_text("")
        [proj] = pd.discover_projects([gui])
        assert proj.programs is None
        assert "Broken.rep" in proj.program_error

    def test_managed_flag_distinguishes_our_projects(self, tmp_path, monkeypatch):
        from src.engines.static.ghidra import project_discovery as pd

        monkeypatch.setenv("BINARY_CACHE_DIR", str(tmp_path / "cache"))
        managed = tmp_path / "cache" / "ghidra_projects"
        gui = tmp_path / "gui"
        _make_project(managed, "auto", programs=["x.exe"])
        _make_project(gui, "handmade", programs=["y.exe"])

        flags = {p.name: p.managed for p in pd.discover_projects([managed, gui])}
        assert flags == {"auto": True, "handmade": False}


# Command construction


class TestAttachCommand:
    def test_uses_process_not_import(self, tmp_path, runner, captured_cmd):
        gui = tmp_path / "gui"
        _make_project(gui, "proj", programs=["okular.exe"])
        binary = _make_binary(tmp_path)

        runner.analyze(
            binary_path=str(binary),
            script_path=str(tmp_path),
            script_name="core_analysis.py",
            output_path=str(tmp_path / "cache" / "out.json"),
            project_name="proj",
            project_dir=str(gui),
            use_existing_project=True,
        )
        cmd = captured_cmd["cmd"]

        assert "-process" in cmd
        assert "-import" not in cmd
        # -overwrite would replace the annotated program on import, and Ghidra
        # ignores it for -process anyway.
        assert "-overwrite" not in cmd
        # -deleteProject on someone else's project is the worst outcome here.
        assert "-deleteProject" not in cmd

    def test_read_only_and_noanalysis_by_default(self, tmp_path, runner, captured_cmd):
        """-process re-analyses and saves back; both flags are what stop it."""
        gui = tmp_path / "gui"
        _make_project(gui, "proj", programs=["okular.exe"])
        binary = _make_binary(tmp_path)

        runner.analyze(
            binary_path=str(binary),
            script_path=str(tmp_path),
            script_name="core_analysis.py",
            output_path=str(tmp_path / "cache" / "out.json"),
            project_name="proj",
            project_dir=str(gui),
            use_existing_project=True,
        )
        assert "-readOnly" in captured_cmd["cmd"]
        assert "-noanalysis" in captured_cmd["cmd"]

    def test_program_name_defaults_to_binary_filename(
        self, tmp_path, runner, captured_cmd
    ):
        gui = tmp_path / "gui"
        _make_project(gui, "proj", programs=["okular.exe"])
        binary = _make_binary(tmp_path, "okular.exe")

        runner.analyze(
            binary_path=str(binary),
            script_path=str(tmp_path),
            script_name="core_analysis.py",
            output_path=str(tmp_path / "cache" / "out.json"),
            project_name="proj",
            project_dir=str(gui),
            use_existing_project=True,
        )
        cmd = captured_cmd["cmd"]
        assert cmd[cmd.index("-process") + 1] == "okular.exe"

    def test_folder_path_joins_onto_project_arg(self, tmp_path, runner, captured_cmd):
        gui = tmp_path / "gui"
        _make_project(gui, "proj", programs=["p.bin"])
        binary = _make_binary(tmp_path)

        runner.analyze(
            binary_path=str(binary),
            script_path=str(tmp_path),
            script_name="core_analysis.py",
            output_path=str(tmp_path / "cache" / "out.json"),
            project_name="proj",
            project_dir=str(gui),
            use_existing_project=True,
            folder_path="/stage2/",
        )
        assert captured_cmd["cmd"][2] == "proj/stage2"

    def test_dotted_project_name_not_sanitised(self, tmp_path, runner, captured_cmd):
        gui = tmp_path / "gui"
        _make_project(gui, "okular.stage2", programs=["okular.exe"])
        binary = _make_binary(tmp_path)

        runner.analyze(
            binary_path=str(binary),
            script_path=str(tmp_path),
            script_name="core_analysis.py",
            output_path=str(tmp_path / "cache" / "out.json"),
            project_name="okular.stage2",
            project_dir=str(gui),
            use_existing_project=True,
        )
        # Sanitising to okular_stage2 would make Ghidra create a new empty
        # project and report success having analysed nothing.
        assert captured_cmd["cmd"][2] == "okular.stage2"

    def test_import_mode_is_unchanged(self, tmp_path, runner, captured_cmd):
        """The default path must keep importing exactly as it did."""
        binary = _make_binary(tmp_path)

        runner.analyze(
            binary_path=str(binary),
            script_path=str(tmp_path),
            script_name="core_analysis.py",
            output_path=str(tmp_path / "cache" / "out.json"),
        )
        cmd = captured_cmd["cmd"]
        assert "-import" in cmd
        assert "-overwrite" in cmd
        assert "-process" not in cmd
        assert "-readOnly" not in cmd


# Preflight


class TestAttachPreflight:
    def _attach(self, runner, tmp_path, **kwargs):
        binary = _make_binary(tmp_path)
        return runner.analyze(
            binary_path=str(binary),
            script_path=str(tmp_path),
            script_name="core_analysis.py",
            output_path=str(tmp_path / "cache" / "out.json"),
            use_existing_project=True,
            **kwargs,
        )

    def test_missing_project_names_the_alternatives(self, tmp_path, runner):
        from src.utils.security import UserFacingError

        gui = tmp_path / "gui"
        _make_project(gui, "real", programs=["a.exe"])

        with pytest.raises(UserFacingError) as exc:
            self._attach(runner, tmp_path, project_name="ghost", project_dir=str(gui))
        assert "real" in str(exc.value)

    def test_missing_directory_is_actionable(self, tmp_path, runner):
        from src.utils.security import UserFacingError

        with pytest.raises(UserFacingError) as exc:
            self._attach(
                runner, tmp_path, project_name="x", project_dir=str(tmp_path / "nope")
            )
        assert "GHIDRA_PROJECT_DIR" in str(exc.value)

    def test_locked_project_is_refused_with_a_reason(self, tmp_path, runner):
        """Ghidra allows one holder; failing here beats a Java lock trace."""
        from src.utils.security import UserFacingError

        gui = tmp_path / "gui"
        _make_project(gui, "open", programs=["a.exe"], locked=True)

        with pytest.raises(UserFacingError) as exc:
            self._attach(runner, tmp_path, project_name="open", project_dir=str(gui))
        assert "Ghidra Front End" in str(exc.value)

    def test_flag_like_project_name_refused(self, tmp_path, runner):
        """A leading '-' would be parsed as an argument, not a project."""
        from src.utils.security import UserFacingError

        gui = tmp_path / "gui"
        gui.mkdir()
        with pytest.raises(UserFacingError):
            self._attach(runner, tmp_path, project_name="-rf", project_dir=str(gui))

    def test_folder_path_rejects_parent_segments(self, tmp_path, runner):
        from src.utils.security import UserFacingError

        gui = tmp_path / "gui"
        _make_project(gui, "proj", programs=["a.exe"])
        binary = _make_binary(tmp_path)

        with pytest.raises(UserFacingError):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(tmp_path),
                script_name="core_analysis.py",
                output_path=str(tmp_path / "cache" / "out.json"),
                project_name="proj",
                project_dir=str(gui),
                use_existing_project=True,
                folder_path="../../elsewhere",
            )

    def test_project_name_with_metacharacters_refused(self, tmp_path, runner):
        gui = tmp_path / "gui"
        gui.mkdir()
        with pytest.raises((ValueError, Exception)):
            self._attach(
                runner, tmp_path, project_name="a; rm -rf /", project_dir=str(gui)
            )


# The delete guard


class TestProjectDeleteGuard:
    """The single most destructive thing this feature could do.

    ``_cleanup_project`` rmtrees the .rep and unlinks the .gpr, and it runs on
    the timeout and non-zero-exit paths. Against a project someone spent weeks
    annotating, one slow Ghidra run would otherwise destroy it.
    """

    def test_user_project_survives_cleanup(self, tmp_path, runner):
        gui = tmp_path / "gui"
        _make_project(gui, "precious", programs=["a.exe"])

        runner._cleanup_project(gui, "precious", self_created=False)

        assert (gui / "precious.gpr").is_file()
        assert (gui / "precious.rep").is_dir()

    def test_managed_project_is_still_cleaned(self, tmp_path, runner):
        """Import-mode cleanup must keep working, or lock files accumulate."""
        managed = tmp_path / "cache" / "ghidra_projects"
        _make_project(managed, "mine", programs=["a.exe"])
        (managed / "mine.lock").write_text("")

        runner._cleanup_project(managed, "mine", self_created=True)

        assert not (managed / "mine.gpr").exists()
        assert not (managed / "mine.rep").exists()
        assert not (managed / "mine.lock").exists()

    def test_cleanup_defaults_to_cleaning(self, tmp_path, runner):
        """Existing callers pass no flag and must retain their behaviour."""
        managed = tmp_path / "cache" / "ghidra_projects"
        _make_project(managed, "mine", programs=["a.exe"])

        runner._cleanup_project(managed, "mine")

        assert not (managed / "mine.rep").exists()

    def test_ghidra_failure_leaves_attached_project_intact(
        self, tmp_path, runner, monkeypatch
    ):
        """End-to-end: a non-zero Ghidra exit must not touch a user project."""
        from src.engines.static.ghidra.runner import GhidraAnalysisError

        gui = tmp_path / "gui"
        _make_project(gui, "precious", programs=["okular.exe"])
        binary = _make_binary(tmp_path)

        class FailingProc(_FakeProc):
            returncode = 1

            def communicate(self, timeout=None):
                return ("", "java.lang.Exception: boom")

        monkeypatch.setattr("subprocess.Popen", lambda cmd, **kw: FailingProc())

        with pytest.raises(GhidraAnalysisError):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(tmp_path),
                script_name="core_analysis.py",
                output_path=str(tmp_path / "cache" / "out.json"),
                project_name="precious",
                project_dir=str(gui),
                use_existing_project=True,
            )

        assert (gui / "precious.gpr").is_file()
        assert (gui / "precious.rep").is_dir()

    def test_ghidra_timeout_leaves_attached_project_intact(
        self, tmp_path, runner, monkeypatch
    ):
        """The timeout path is the likelier one on a big annotated binary."""
        import subprocess

        from src.engines.static.ghidra.runner import GhidraAnalysisError

        gui = tmp_path / "gui"
        _make_project(gui, "precious", programs=["okular.exe"])
        binary = _make_binary(tmp_path)

        class HangingProc(_FakeProc):
            def communicate(self, timeout=None):
                raise subprocess.TimeoutExpired(cmd="analyzeHeadless", timeout=1)

        monkeypatch.setattr("subprocess.Popen", lambda cmd, **kw: HangingProc())

        with pytest.raises(GhidraAnalysisError):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(tmp_path),
                script_name="core_analysis.py",
                output_path=str(tmp_path / "cache" / "out.json"),
                project_name="precious",
                project_dir=str(gui),
                use_existing_project=True,
                timeout=30,
            )

        assert (gui / "precious.gpr").is_file()
        assert (gui / "precious.rep").is_dir()


# Identity verification


@pytest.fixture
def server_module(tmp_path_factory, monkeypatch):
    fake_ghidra = tmp_path_factory.mktemp("ghidra_home")
    (fake_ghidra / "support").mkdir()
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    monkeypatch.setenv("GHIDRA_HOME", str(fake_ghidra))
    sys.modules.pop("src.server", None)
    import src.server as server_mod

    return server_mod


def _ctx_with_sha(sha: str, name: str = "okular.exe") -> dict:
    return {"metadata": {"name": name, "executable_sha256": sha}, "functions": []}


class TestAttachedProgramIdentity:
    """Nothing about -process guarantees the program is the binary we asked for.

    The cache is keyed on the SHA256 of ``binary_path``. A project can hold
    several binaries, names repeat across versions, and a wildcard takes what
    it finds -- so without this check one program's functions get filed under
    another's key and every later tool call is confidently wrong.
    """

    def test_matching_hash_passes_silently(self, server_module, tmp_path, monkeypatch):
        from src.engines.static.ghidra.project_cache import ProjectCache

        binary = _make_binary(tmp_path)
        monkeypatch.setattr(
            server_module, "cache", ProjectCache(cache_dir=str(tmp_path / "c"))
        )
        real_sha = server_module.cache._get_binary_hash(str(binary))

        warning = server_module._verify_attached_program(
            _ctx_with_sha(real_sha), str(binary), "proj", "okular.exe"
        )
        assert warning is None

    def test_mismatched_hash_refuses_to_cache(
        self, server_module, tmp_path, monkeypatch
    ):
        from src.engines.static.ghidra.project_cache import ProjectCache
        from src.utils.security import UserFacingError

        binary = _make_binary(tmp_path)
        monkeypatch.setattr(
            server_module, "cache", ProjectCache(cache_dir=str(tmp_path / "c"))
        )

        with pytest.raises(UserFacingError) as exc:
            server_module._verify_attached_program(
                _ctx_with_sha("00" * 32, "someone_else.dll"),
                str(binary),
                "proj",
                "okular.exe",
            )
        message = str(exc.value)
        assert "someone_else.dll" in message
        assert "ghidra_program" in message

    def test_hash_case_is_ignored(self, server_module, tmp_path, monkeypatch):
        from src.engines.static.ghidra.project_cache import ProjectCache

        binary = _make_binary(tmp_path)
        monkeypatch.setattr(
            server_module, "cache", ProjectCache(cache_dir=str(tmp_path / "c"))
        )
        real_sha = server_module.cache._get_binary_hash(str(binary))

        assert (
            server_module._verify_attached_program(
                _ctx_with_sha(real_sha.upper()), str(binary), "proj", None
            )
            is None
        )

    def test_missing_hash_warns_but_proceeds(
        self, server_module, tmp_path, monkeypatch
    ):
        """Old Ghidra versions record no SHA256; degrade, don't refuse."""
        from src.engines.static.ghidra.project_cache import ProjectCache

        binary = _make_binary(tmp_path)
        monkeypatch.setattr(
            server_module, "cache", ProjectCache(cache_dir=str(tmp_path / "c"))
        )

        warning = server_module._verify_attached_program(
            _ctx_with_sha(""), str(binary), "proj", "okular.exe"
        )
        assert warning is not None
        assert "Could not verify" in warning


# Rename clobber accounting


class TestRenameClobberAccounting:
    """The project wins, but a rename vanishing must never be silent."""

    def _fn(self, name, address, cache_only=False):
        fn = {"name": name, "address": address, "name_source": "USER_DEFINED"}
        if cache_only:
            fn["cache_only_rename"] = True
        return fn

    def test_counts_overwritten_cache_only_renames(self, server_module):
        existing = {"functions": [self._fn("decrypt_blob", "0x1000", cache_only=True)]}
        incoming = {"functions": [self._fn("FUN_00001000", "0x1000")]}

        count, samples = server_module._count_rename_clobbers(existing, incoming)
        assert count == 1
        assert samples == ["decrypt_blob -> FUN_00001000"]

    def test_gui_rename_between_pulls_is_not_a_clobber(self, server_module):
        """The core workflow must not be reported as losing anything.

        Renaming in the Ghidra GUI and re-pulling changes the name at that
        address too. Counting it would tell the user they had lost a rename and
        advise them to go rename it in the GUI -- which is exactly what they
        just did.
        """
        existing = {"functions": [self._fn("aes_key", "0x1000")]}
        incoming = {"functions": [self._fn("aes_expand_key", "0x1000")]}

        assert server_module._count_rename_clobbers(existing, incoming) == (0, [])

    def test_default_names_are_not_counted(self, server_module):
        """Replacing FUN_* with a real name is a gain, not a loss."""
        existing = {"functions": [self._fn("FUN_00001000", "0x1000")]}
        incoming = {"functions": [self._fn("aes_expand_key", "0x1000")]}

        count, samples = server_module._count_rename_clobbers(existing, incoming)
        assert count == 0
        assert samples == []

    def test_unchanged_names_are_not_counted(self, server_module):
        existing = {"functions": [self._fn("same_name", "0x1000", cache_only=True)]}
        incoming = {"functions": [self._fn("same_name", "0x1000")]}

        assert server_module._count_rename_clobbers(existing, incoming)[0] == 0

    def test_addresses_absent_from_the_project_are_ignored(self, server_module):
        """Only functions the re-pull actually replaced can be clobbered."""
        existing = {"functions": [self._fn("my_name", "0x9999", cache_only=True)]}
        incoming = {"functions": [self._fn("other", "0x1000")]}

        assert server_module._count_rename_clobbers(existing, incoming)[0] == 0

    def test_no_existing_cache_is_not_a_clobber(self, server_module):
        incoming = {"functions": [self._fn("whatever", "0x1000")]}
        assert server_module._count_rename_clobbers(None, incoming) == (0, [])

    def test_samples_are_capped_but_count_is_not(self, server_module):
        existing = {
            "functions": [
                self._fn(f"my_func_{i}", f"0x{i:04x}", cache_only=True)
                for i in range(12)
            ]
        }
        incoming = {
            "functions": [self._fn(f"FUN_{i:08x}", f"0x{i:04x}") for i in range(12)]
        }

        count, samples = server_module._count_rename_clobbers(existing, incoming)
        assert count == 12
        assert len(samples) == 5

    def test_rename_function_stamps_the_marker(
        self, server_module, tmp_path, monkeypatch
    ):
        """The counter depends on this marker, so pin where it comes from."""
        from src.engines.static.ghidra.project_cache import ProjectCache

        binary = _make_binary(tmp_path)
        ctx = {
            "metadata": {"image_base": "0x140000000"},
            "functions": [
                {
                    "address": "0x140001000",
                    "name": "FUN_140001000",
                    "name_source": "DEFAULT",
                    "signature": "",
                    "pseudocode": "",
                }
            ],
        }
        cache = ProjectCache(cache_dir=str(tmp_path / "c"))
        monkeypatch.setattr(server_module, "cache", cache)
        monkeypatch.setattr(
            server_module, "get_analysis_context", lambda *a, **kw: ctx
        )

        server_module.rename_function(
            str(binary), "decrypt_blob", address="0x140001000"
        )

        assert cache.get_cached(str(binary))["functions"][0]["cache_only_rename"]


# End to end through get_analysis_context


def _ghidra_output(sha: str) -> dict:
    """What core_analysis.py would emit for a project a human has worked on."""
    return {
        "metadata": {
            "name": "okular.exe",
            "executable_sha256": sha,
            "image_base": "0x140000000",
            "executable_format": "PE",
            "language": "x86:LE:64:default",
            "compiler": "windows",
            "min_address": "0x140001000",
            "max_address": "0x140009000",
        },
        "functions": [
            {
                "address": "0x140001000",
                "name": "aes_expand_key",
                "name_source": "USER_DEFINED",
                "plate_comment": "reversed by hand",
                "instruction_comments": [
                    {"addr": "0x140001004", "kind": "eol", "text": "round key"}
                ],
                "basic_blocks": [],
                "called_functions": [],
            },
            {
                "address": "0x140002000",
                "name": "FUN_140002000",
                "name_source": "DEFAULT",
                "plate_comment": "",
                "instruction_comments": [],
                "basic_blocks": [],
                "called_functions": [],
            },
        ],
        "imports": [{"library": "kernel32.dll", "name": "CreateFileW"}],
        "strings": [],
        "memory_map": [],
        "data_types": {"structures": [], "enums": []},
        "analysis_stats": {},
    }


@pytest.fixture
def attach_env(server_module, tmp_path, monkeypatch):
    """A server wired to a temp cache, with a discoverable project on disk."""
    import json

    from src.engines.static.ghidra.project_cache import ProjectCache

    gui = tmp_path / "gui"
    _make_project(gui, "okular.stage2", programs=["okular.exe"])
    binary = _make_binary(tmp_path)

    monkeypatch.setenv("BINARY_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("GHIDRA_PROJECT_DIR", str(gui))
    cache = ProjectCache(cache_dir=str(tmp_path / "cache"))
    monkeypatch.setattr(server_module, "cache", cache)

    sha = cache._get_binary_hash(str(binary))
    calls: dict = {}

    def fake_analyze(**kwargs):
        Path(kwargs["output_path"]).write_text(json.dumps(calls["output"]))
        calls["kwargs"] = kwargs
        return {
            "success": True,
            "stdout": "ok",
            "stderr": "",
            "elapsed_time": 1.0,
            "attached": kwargs.get("use_existing_project"),
        }

    calls["output"] = _ghidra_output(sha)
    monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)

    return {
        "server": server_module,
        "binary": binary,
        "cache": cache,
        "sha": sha,
        "calls": calls,
        "gui": gui,
    }


class TestAttachEndToEnd:
    def test_gui_work_reaches_the_cache(self, attach_env):
        env = attach_env
        env["server"].analyze_binary(
            str(env["binary"]), ghidra_project="okular.stage2"
        )

        cached = env["cache"].get_cached(str(env["binary"]))
        fn = cached["functions"][0]
        assert fn["name"] == "aes_expand_key"
        assert fn["plate_comment"] == "reversed by hand"
        assert cached["metadata"]["source_project"] == "okular.stage2"

    def test_runner_told_to_attach(self, attach_env):
        env = attach_env
        env["server"].analyze_binary(
            str(env["binary"]), ghidra_project="okular.stage2"
        )

        kwargs = env["calls"]["kwargs"]
        assert kwargs["use_existing_project"] is True
        assert kwargs["project_name"] == "okular.stage2"
        assert kwargs["project_dir"] == str(env["gui"])

    def test_attach_bypasses_the_cache(self, attach_env):
        """A warm cache must not short-circuit an attach.

        The point of re-pulling is to collect work done in the GUI since the
        cache was built, so serving the cache would return exactly the stale
        answer the caller is trying to replace.
        """
        env = attach_env
        env["cache"].save_cached(str(env["binary"]), _ghidra_output(env["sha"]))

        env["server"].analyze_binary(
            str(env["binary"]), ghidra_project="okular.stage2"
        )
        assert "kwargs" in env["calls"], "Ghidra was not run despite a warm cache"

    def test_no_project_still_uses_the_cache(self, attach_env):
        """Control: the ordinary path must keep short-circuiting."""
        env = attach_env
        env["cache"].save_cached(str(env["binary"]), _ghidra_output(env["sha"]))

        env["server"].analyze_binary(str(env["binary"]))
        assert "kwargs" not in env["calls"]

    def test_clobbered_rename_is_reported(self, attach_env):
        env = attach_env
        stale = _ghidra_output(env["sha"])
        # What rename_function leaves behind: a new name plus the marker
        # saying it exists only in the cache.
        stale["functions"][0]["name"] = "my_cache_only_rename"
        stale["functions"][0]["cache_only_rename"] = True
        env["cache"].save_cached(str(env["binary"]), stale)

        result = env["server"].analyze_binary(
            str(env["binary"]), ghidra_project="okular.stage2"
        )
        assert "my_cache_only_rename -> aes_expand_key" in result
        assert "Ghidra GUI" in result

    def test_repeated_gui_renames_report_nothing_lost(self, attach_env):
        """Rename in the GUI, re-pull, twice. Nothing should read as lost."""
        env = attach_env
        env["server"].analyze_binary(
            str(env["binary"]), ghidra_project="okular.stage2"
        )

        renamed = _ghidra_output(env["sha"])
        renamed["functions"][0]["name"] = "aes_key_expansion_v2"
        env["calls"]["output"] = renamed
        result = env["server"].analyze_binary(
            str(env["binary"]), ghidra_project="okular.stage2"
        )

        assert "aes_key_expansion_v2" == (
            env["cache"].get_cached(str(env["binary"]))["functions"][0]["name"]
        )
        assert "Replaced" not in result
        assert "do not survive" not in result

    def test_wrong_binary_is_refused_and_not_cached(self, attach_env):
        """A hash mismatch must not reach the cache under the wrong key."""
        from src.utils.security import UserFacingError

        env = attach_env
        env["calls"]["output"] = _ghidra_output("00" * 32)

        with pytest.raises(UserFacingError):
            env["server"].get_analysis_context(
                str(env["binary"]), ghidra_project="okular.stage2"
            )

        assert env["cache"].get_cached(str(env["binary"])) is None

    def test_unknown_project_names_alternatives(self, attach_env):
        from src.utils.security import UserFacingError

        env = attach_env
        with pytest.raises(UserFacingError) as exc:
            env["server"].get_analysis_context(
                str(env["binary"]), ghidra_project="typo"
            )
        assert "okular.stage2" in str(exc.value)

    def test_notes_survive_a_repull(self, attach_env):
        """Notes are address-keyed, so a GUI rename must not orphan them."""
        env = attach_env
        env["server"].analyze_binary(
            str(env["binary"]), ghidra_project="okular.stage2"
        )
        env["server"].add_note(
            str(env["binary"]), "0x140001000", "key schedule", kind="plate"
        )

        # The human renames it again in Ghidra, then we re-pull.
        renamed = _ghidra_output(env["sha"])
        renamed["functions"][0]["name"] = "aes_key_expansion_v2"
        env["calls"]["output"] = renamed
        env["server"].analyze_binary(
            str(env["binary"]), ghidra_project="okular.stage2"
        )

        cached = env["cache"].get_cached(str(env["binary"]))
        assert cached["functions"][0]["name"] == "aes_key_expansion_v2"
        assert cached["functions"][0]["notes"]["plate"] == "key schedule"
