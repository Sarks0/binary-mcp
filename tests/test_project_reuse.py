"""
Tests for Ghidra project reuse and targeted decompiles.

The problem these cover: on a 17 MB, 30K-function DLL every Ghidra invocation
re-imported the binary (`-import ... -overwrite`) and re-ran auto-analysis from
scratch -- about seven minutes -- before doing whatever it was actually asked
for. A targeted decompile of ONE function paid that in full, which made the
"analyze structural, decompile on demand" workflow cost a re-analysis per
function.

Covers:
- Project names are keyed on binary content, so an old and a new build of the
  same DLL do not fight over one project.
- The owner record gates reuse: matching hash + analyzed => `-process`;
  anything else => `-import`.
- The reuse command shape (no -import/-overwrite, -noanalysis, -readOnly).
- A failed reuse falls back to a fresh import instead of erroring.
- Targeted runs skip the resume manifest and pass exact addresses.
- The delta merge preserves program-wide fields and rebuilds reverse xrefs.
"""

from __future__ import annotations

import json
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


@pytest.fixture
def server_module(tmp_path_factory, monkeypatch):
    fake_ghidra = tmp_path_factory.mktemp("ghidra_home")
    (fake_ghidra / "support").mkdir()
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    monkeypatch.setenv("GHIDRA_HOME", str(fake_ghidra))
    sys.modules.pop("src.server", None)
    import src.server as server_mod

    return server_mod


@pytest.fixture
def runner(tmp_path):
    from src.engines.static.ghidra.runner import GhidraRunner

    fake_ghidra = tmp_path / "ghidra"
    (fake_ghidra / "support").mkdir(parents=True)
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    return GhidraRunner(ghidra_path=str(fake_ghidra))


def _cache(tmp_path):
    from src.engines.static.ghidra.project_cache import ProjectCache

    return ProjectCache(cache_dir=str(tmp_path / "cache"))


def _make_project(cache_obj, project_name):
    """Create the on-disk shape `project_exists` looks for."""
    pdir = cache_obj.cache_dir / "ghidra_projects"
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / f"{project_name}.gpr").write_text("")
    (pdir / f"{project_name}.rep").mkdir(exist_ok=True)


# -- Project naming ----------------------------------------------------------


class TestProjectNaming:
    def test_project_name_includes_content_hash(self, tmp_path):
        cache_obj = _cache(tmp_path)
        binary = tmp_path / "mpengine.dll"
        binary.write_bytes(b"MZ" + b"\x00" * 64)

        name = cache_obj.project_name_for(str(binary))
        assert name.startswith("mpengine_")
        assert name == f"mpengine_{cache_obj._get_binary_hash(str(binary))[:8]}"

    def test_two_builds_of_one_dll_get_separate_projects(self, tmp_path):
        """The patch-diff case. Sharing a project across builds would mean
        every switch between old and new pays a re-import -- and, worse, a
        reused project could hand back the wrong build's code."""
        cache_obj = _cache(tmp_path)
        old = tmp_path / "old" / "mpengine.dll"
        new = tmp_path / "new" / "mpengine.dll"
        old.parent.mkdir()
        new.parent.mkdir()
        old.write_bytes(b"MZ" + b"\x01" * 64)
        new.write_bytes(b"MZ" + b"\x02" * 64)

        assert cache_obj.project_name_for(str(old)) != cache_obj.project_name_for(str(new))

    def test_legacy_stem_name_still_derivable_for_cleanup(self, tmp_path):
        """Installs upgraded from before reuse have stem-named projects on
        disk; cleanup has to keep finding them."""
        cache_obj = _cache(tmp_path)
        assert cache_obj._get_project_name("/tmp/foo bar.dll") == "foo_bar"

    def test_invalidate_drops_both_legacy_and_hashed_projects(self, tmp_path):
        cache_obj = _cache(tmp_path)
        binary = tmp_path / "target.dll"
        binary.write_bytes(b"MZ" + b"\x00" * 64)
        cache_obj.save_cached(str(binary), {"functions": []})

        hashed = cache_obj.project_name_for(str(binary))
        legacy = cache_obj._get_project_name(str(binary))
        _make_project(cache_obj, hashed)
        _make_project(cache_obj, legacy)

        cache_obj.invalidate(str(binary), include_project=True)

        pdir = cache_obj.cache_dir / "ghidra_projects"
        assert not (pdir / f"{hashed}.gpr").exists()
        assert not (pdir / f"{legacy}.gpr").exists()


# -- Owner record ------------------------------------------------------------


class TestProjectState:
    def test_round_trip(self, tmp_path):
        cache_obj = _cache(tmp_path)
        binary = tmp_path / "target.dll"
        binary.write_bytes(b"MZ" + b"\x00" * 64)
        name = cache_obj.project_name_for(str(binary))

        assert cache_obj.write_project_state(
            name, str(binary), program_name="target.dll", analyzed=True
        )
        state = cache_obj.read_project_state(name)
        assert state["program_name"] == "target.dll"
        assert state["analyzed"] is True
        assert state["binary_hash"] == cache_obj._get_binary_hash(str(binary))

    def test_missing_record_reads_as_none(self, tmp_path):
        assert _cache(tmp_path).read_project_state("nope") is None

    def test_project_exists_requires_both_gpr_and_rep(self, tmp_path):
        cache_obj = _cache(tmp_path)
        pdir = cache_obj.cache_dir / "ghidra_projects"
        pdir.mkdir(parents=True)
        (pdir / "half.gpr").write_text("")
        assert not cache_obj.project_exists("half")
        (pdir / "half.rep").mkdir()
        assert cache_obj.project_exists("half")


# -- The reuse decision ------------------------------------------------------


class TestReuseDecision:
    def _seed(self, tmp_path, monkeypatch, server_module, *, analyzed=True):
        cache_obj = _cache(tmp_path)
        binary = tmp_path / "target.dll"
        binary.write_bytes(b"MZ" + b"\x00" * 64)
        monkeypatch.setattr(server_module, "cache", cache_obj)

        name = cache_obj.project_name_for(str(binary))
        _make_project(cache_obj, name)
        cache_obj.write_project_state(
            name, str(binary), program_name="target.dll", analyzed=analyzed
        )
        return binary, name

    def _decide(self, server_module, binary, name, **overrides):
        kwargs = {
            "analysis_depth": "structural",
            "force_reanalyze": False,
            "processor": None,
            "loader": None,
            "pdb_path": None,
        }
        kwargs.update(overrides)
        return server_module._project_reuse_decision(str(binary), name, **kwargs)

    def test_matching_owner_record_permits_reuse(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, name = self._seed(tmp_path, monkeypatch, server_module)
        reuse, _ = self._decide(server_module, binary, name)
        assert reuse is True

    def test_no_project_on_disk_refuses(self, tmp_path, monkeypatch, server_module):
        binary, name = self._seed(tmp_path, monkeypatch, server_module)
        (server_module.cache.cache_dir / "ghidra_projects" / f"{name}.gpr").unlink()
        reuse, reason = self._decide(server_module, binary, name)
        assert reuse is False
        assert "no Ghidra project" in reason

    def test_missing_owner_record_refuses(self, tmp_path, monkeypatch, server_module):
        binary, name = self._seed(tmp_path, monkeypatch, server_module)
        server_module.cache.clear_project_state(name)
        reuse, reason = self._decide(server_module, binary, name)
        assert reuse is False
        assert "owner record" in reason

    def test_record_for_a_different_binary_refuses(
        self, tmp_path, monkeypatch, server_module
    ):
        """The silent-corruption case: reusing here would decompile whatever
        program happens to be in the project, under the caller's name."""
        binary, name = self._seed(tmp_path, monkeypatch, server_module)
        state_path = server_module.cache._project_state_path(name)
        state = json.loads(state_path.read_text())
        state["binary_hash"] = "0" * 64
        state_path.write_text(json.dumps(state))

        reuse, reason = self._decide(server_module, binary, name)
        assert reuse is False
        assert "different binary" in reason

    def test_unanalyzed_project_refuses_for_structural(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, name = self._seed(tmp_path, monkeypatch, server_module, analyzed=False)
        reuse, reason = self._decide(server_module, binary, name)
        assert reuse is False
        assert "without analysis" in reason

    def test_unanalyzed_project_still_serves_a_shallow_request(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, name = self._seed(tmp_path, monkeypatch, server_module, analyzed=False)
        reuse, _ = self._decide(server_module, binary, name, analysis_depth="shallow")
        assert reuse is True

    @pytest.mark.parametrize(
        "override",
        [
            {"force_reanalyze": True},
            {"processor": "x86:LE:64:default"},
            {"loader": "PeLoader"},
            {"pdb_path": "/tmp/target.pdb"},
        ],
    )
    def test_import_only_options_refuse_reuse(
        self, tmp_path, monkeypatch, server_module, override
    ):
        binary, name = self._seed(tmp_path, monkeypatch, server_module)
        reuse, _ = self._decide(server_module, binary, name, **override)
        assert reuse is False


# -- Runner command shape ----------------------------------------------------


class TestReuseCommand:
    def _capture(self, runner, tmp_path, monkeypatch, **kwargs):
        binary = tmp_path / "sample.dll"
        binary.write_bytes(b"MZ" + b"\x00" * 64)
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        out = tmp_path / "out.json"

        seen = {}

        def fake_run_headless(cmd, env, *args, **kw):
            seen["cmd"] = cmd
            seen["env"] = env
            seen["kwargs"] = kw
            return {"success": True, "stdout": "", "stderr": ""}

        monkeypatch.setattr(runner, "_run_headless", fake_run_headless)
        runner.analyze(
            binary_path=str(binary),
            script_path=str(scripts),
            script_name="core_analysis.py",
            output_path=str(out),
            project_name="sample_deadbeef",
            keep_project=True,
            **kwargs,
        )
        return seen

    def test_reuse_run_does_not_import(self, runner, tmp_path, monkeypatch):
        seen = self._capture(
            runner, tmp_path, monkeypatch,
            reuse_project=True, program_name="sample.dll",
        )
        cmd = seen["cmd"]
        assert "-import" not in cmd
        assert "-overwrite" not in cmd
        assert "-process" in cmd
        assert cmd[cmd.index("-process") + 1] == "sample.dll"
        # No auto-analysis: the program in the project is already analyzed,
        # and re-running it is the seven minutes this whole path removes.
        assert "-noanalysis" in cmd
        # Nothing is written back, so Ghidra must not re-save the database.
        assert "-readOnly" in cmd
        assert seen["kwargs"]["reused_project"] is True

    def test_import_run_is_unchanged(self, runner, tmp_path, monkeypatch):
        seen = self._capture(runner, tmp_path, monkeypatch)
        cmd = seen["cmd"]
        assert "-import" in cmd
        assert "-overwrite" in cmd
        assert "-process" not in cmd
        assert seen["kwargs"]["reused_project"] is False

    def test_unsafe_program_name_falls_back_to_wildcard(
        self, runner, tmp_path, monkeypatch
    ):
        """`-process` reads its argument as a glob, so a name carrying a
        wildcard would silently widen the selection."""
        seen = self._capture(
            runner, tmp_path, monkeypatch,
            reuse_project=True, program_name="weird*name",
        )
        cmd = seen["cmd"]
        assert cmd[cmd.index("-process") + 1] == "*"

    def test_unknown_program_name_falls_back_to_wildcard(
        self, runner, tmp_path, monkeypatch
    ):
        seen = self._capture(runner, tmp_path, monkeypatch, reuse_project=True)
        cmd = seen["cmd"]
        assert cmd[cmd.index("-process") + 1] == "*"

    @pytest.mark.parametrize(
        "override",
        [
            {"processor": "x86:LE:64:default"},
            {"loader": "PeLoader"},
        ],
    )
    def test_reuse_rejects_import_only_options(
        self, runner, tmp_path, monkeypatch, override
    ):
        with pytest.raises(ValueError, match="reuse_project cannot be combined"):
            self._capture(runner, tmp_path, monkeypatch, reuse_project=True, **override)

    def test_reuse_requires_keep_project(self, runner, tmp_path, monkeypatch):
        binary = tmp_path / "sample.dll"
        binary.write_bytes(b"MZ" + b"\x00" * 64)
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        with pytest.raises(ValueError, match="keep_project"):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(scripts),
                script_name="core_analysis.py",
                output_path=str(tmp_path / "out.json"),
                keep_project=False,
                reuse_project=True,
            )

    def test_target_addresses_reach_the_script_env(
        self, runner, tmp_path, monkeypatch
    ):
        seen = self._capture(
            runner, tmp_path, monkeypatch,
            target_addresses=["0x140001000", "140002000"],
        )
        assert seen["env"]["GHIDRA_TARGET_ADDRESSES"] == "0x140001000,140002000"

    def test_non_hex_target_address_is_rejected(self, runner, tmp_path, monkeypatch):
        with pytest.raises(ValueError, match="Invalid target address"):
            self._capture(
                runner, tmp_path, monkeypatch,
                target_addresses=["0x1000; rm -rf /"],
            )


class TestReuseFailureCleanup:
    def test_reuse_timeout_keeps_the_project_and_drops_the_lock(self, runner, tmp_path):
        """A reuse run is -readOnly, so a kill cannot have damaged the
        database -- but a stale lock would break every later run."""
        pdir = tmp_path / "ghidra_projects"
        pdir.mkdir()
        (pdir / "p.gpr").write_text("")
        (pdir / "p.rep").mkdir()
        (pdir / "p.lock").write_text("")

        runner._cleanup_after_failure(pdir, "p", reused_project=True)

        assert not (pdir / "p.lock").exists()
        assert (pdir / "p.gpr").exists()
        assert (pdir / "p.rep").exists()

    def test_import_failure_still_removes_the_whole_project(self, runner, tmp_path):
        pdir = tmp_path / "ghidra_projects"
        pdir.mkdir()
        (pdir / "p.gpr").write_text("")
        (pdir / "p.rep").mkdir()
        (pdir / "p.lock").write_text("")

        runner._cleanup_after_failure(pdir, "p", reused_project=False)

        assert not (pdir / "p.gpr").exists()
        assert not (pdir / "p.rep").exists()


# -- End-to-end wiring through get_analysis_context --------------------------


def _seed_analyzed_binary(tmp_path, monkeypatch, server_module, depth="structural"):
    cache_obj = _cache(tmp_path)
    binary = tmp_path / "target.dll"
    binary.write_bytes(b"MZ" + b"\x00" * 128)
    cache_obj.save_cached(
        str(binary),
        {
            "metadata": {"analysis_depth": depth, "name": "target.dll"},
            "functions": [
                {
                    "address": "0x401000",
                    "name": "Parse",
                    "signature": "void Parse(void)",
                    "pseudocode": None,
                    "call_sites": [
                        {
                            "call_site": "0x401010",
                            "callee_addr": "0x402000",
                            "callee_name": "Helper",
                            "is_external": False,
                        }
                    ],
                },
                {"address": "0x402000", "name": "Helper", "pseudocode": None},
            ],
            "imports": [{"name": "CreateFileW", "library": "kernel32.dll"}],
            "strings": [{"address": "0x403000", "value": "hello"}],
            "memory_map": [{"name": ".text", "start": "0x401000"}],
            "data_types": {"structures": [{"name": "FOO"}], "enums": []},
            "xrefs_to_function": {"402000": [{"from_func_name": "Parse"}]},
        },
    )
    monkeypatch.setattr(server_module, "cache", cache_obj)
    monkeypatch.setattr(server_module, "get_allowed_dirs", lambda: [tmp_path])
    return binary, cache_obj


class TestTargetedRunWiring:
    def test_targeted_run_passes_addresses_and_skips_the_manifest(
        self, tmp_path, monkeypatch, server_module
    ):
        """Writing a manifest here would serialise every completed address in
        a 30K-function cache to tell Ghidra to skip work it never looks at."""
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        captured = {}

        def fake_analyze(**kwargs):
            captured.update(kwargs)
            Path(kwargs["output_path"]).write_text(json.dumps({
                "metadata": {"name": "target.dll"},
                "functions": [
                    {"address": "0x401000", "name": "Parse",
                     "pseudocode": "void Parse(void) { return; }",
                     "call_sites": []},
                ],
                "analysis_stats": {"delta_run": True, "targeted_run": True},
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)
        server_module.get_analysis_context(
            str(binary), target_addresses=["0x401000"], force_decompile=True
        )

        assert captured["target_addresses"] == ["0x401000"]
        assert captured["resume_manifest"] is None
        assert captured["force_decompile"] is True
        # Nor the full resume cache: loading a multi-GB JSON is what OOMs the
        # JVM on exactly the binaries this path exists for.
        assert captured["resume_from_cache"] is None

    def test_a_refused_targeted_run_releases_the_run_lock(
        self, tmp_path, monkeypatch, server_module
    ):
        """The refusal happens after the lock is taken. Leaking it would make
        the next caller queue for an hour on a run that never started."""
        from src.utils.security import UserFacingError

        cache_obj = _cache(tmp_path)
        binary = tmp_path / "nocache.dll"
        binary.write_bytes(b"MZ" + b"\x00" * 128)
        monkeypatch.setattr(server_module, "cache", cache_obj)
        monkeypatch.setattr(server_module, "get_allowed_dirs", lambda: [tmp_path])

        with pytest.raises(UserFacingError) as excinfo:
            server_module.get_analysis_context(
                str(binary), target_addresses=["0x401000"]
            )

        # Hold the traceback, which holds the frame, which holds the lock's
        # context manager -- exactly what a server that logs exc_info does.
        # Without it CPython's refcounting closes the generator and runs its
        # `finally` for us, so the leak this guards against hides behind the
        # garbage collector instead of showing up.
        assert excinfo.traceback

        # If the lock were still held, this non-blocking acquisition raises.
        with server_module._delta_run_lock(
            cache_obj.cache_dir,
            str(binary),
            lock_key=cache_obj._get_project_name(str(binary)),
            wait_seconds=0.0,
        ):
            pass

    def test_targeted_run_without_a_cache_is_refused(
        self, tmp_path, monkeypatch, server_module
    ):
        from src.utils.security import UserFacingError

        cache_obj = _cache(tmp_path)
        binary = tmp_path / "nocache.dll"
        binary.write_bytes(b"MZ" + b"\x00" * 128)
        monkeypatch.setattr(server_module, "cache", cache_obj)
        monkeypatch.setattr(server_module, "get_allowed_dirs", lambda: [tmp_path])

        with pytest.raises(UserFacingError):
            server_module.get_analysis_context(
                str(binary), target_addresses=["0x401000"]
            )

    def test_import_run_records_the_owner_state(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, cache_obj = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)

        def fake_analyze(**kwargs):
            Path(kwargs["output_path"]).write_text(json.dumps({
                "metadata": {"name": "target.dll", "executable_format": "PE"},
                "functions": [{"address": "0x401000", "name": "Parse"}],
                "imports": [], "strings": [], "memory_map": [],
                "analysis_stats": {},
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)
        server_module.get_analysis_context(str(binary), force_reanalyze=True)

        state = cache_obj.read_project_state(cache_obj.project_name_for(str(binary)))
        assert state is not None
        assert state["program_name"] == "target.dll"
        assert state["analyzed"] is True

    def test_second_run_reuses_the_project(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, cache_obj = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        name = cache_obj.project_name_for(str(binary))
        _make_project(cache_obj, name)
        cache_obj.write_project_state(
            name, str(binary), program_name="target.dll", analyzed=True
        )
        captured = {}

        def fake_analyze(**kwargs):
            captured.update(kwargs)
            Path(kwargs["output_path"]).write_text(json.dumps({
                "metadata": {"name": "target.dll"},
                "functions": [
                    {"address": "0x401000", "name": "Parse",
                     "pseudocode": "void Parse(void) { return; }"},
                ],
                "analysis_stats": {"delta_run": True, "targeted_run": True},
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)
        server_module.get_analysis_context(
            str(binary), target_addresses=["0x401000"], force_decompile=True
        )

        assert captured["reuse_project"] is True
        assert captured["program_name"] == "target.dll"

    def test_a_reuse_that_produces_nothing_falls_back_to_import(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, cache_obj = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        name = cache_obj.project_name_for(str(binary))
        _make_project(cache_obj, name)
        cache_obj.write_project_state(
            name, str(binary), program_name="target.dll", analyzed=True
        )
        attempts = []

        def fake_analyze(**kwargs):
            attempts.append(kwargs["reuse_project"])
            if kwargs["reuse_project"]:
                # Project could not be opened -- no output written.
                return {"elapsed_time": 0.5, "stdout": "", "stderr": ""}
            Path(kwargs["output_path"]).write_text(json.dumps({
                "metadata": {"name": "target.dll", "executable_format": "PE"},
                "functions": [{"address": "0x401000", "name": "Parse",
                               "pseudocode": "void Parse(void) { return; }"}],
                "imports": [], "strings": [], "memory_map": [],
                "analysis_stats": {"delta_run": True, "targeted_run": True},
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)
        merged = server_module.get_analysis_context(
            str(binary), target_addresses=["0x401000"], force_decompile=True
        )

        # Reuse was tried, came back empty, and the run completed anyway --
        # a broken project costs one import, not a failed call.
        assert attempts == [True, False]
        assert merged["functions"][0]["pseudocode"]
        # The import rewrote the record with a project that demonstrably works.
        assert cache_obj.read_project_state(name) is not None


class TestDeltaMergePreservation:
    def test_targeted_delta_does_not_wipe_program_wide_fields(
        self, tmp_path, monkeypatch, server_module
    ):
        """A targeted run skips the program-wide sweeps, so its empty lists
        must not win the merge -- that would delete every string and import
        the binary has."""
        binary, cache_obj = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)

        def fake_analyze(**kwargs):
            Path(kwargs["output_path"]).write_text(json.dumps({
                "metadata": {"name": "target.dll"},
                "functions": [
                    {"address": "0x401000", "name": "Parse",
                     "pseudocode": "void Parse(void) { return; }",
                     "call_sites": [
                         {"call_site": "0x401010", "callee_addr": "0x402000",
                          "callee_name": "Helper", "is_external": False},
                     ]},
                ],
                "analysis_stats": {"delta_run": True, "targeted_run": True,
                                   "partial_context": True},
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)
        merged = server_module.get_analysis_context(
            str(binary), target_addresses=["0x401000"], force_decompile=True
        )

        assert merged["imports"] == [{"name": "CreateFileW", "library": "kernel32.dll"}]
        assert merged["strings"][0]["value"] == "hello"
        assert merged["memory_map"][0]["name"] == ".text"
        assert merged["data_types"]["structures"] == [{"name": "FOO"}]
        # And the untouched function survived alongside the new body.
        names = {f["name"] for f in merged["functions"]}
        assert names == {"Parse", "Helper"}

    def test_targeted_delta_rebuilds_reverse_xrefs(
        self, tmp_path, monkeypatch, server_module
    ):
        """The delta only knows about the functions it processed, so adopting
        its index verbatim used to leave get_xrefs(direction='to') answering
        'no callers' for the whole binary after any targeted decompile."""
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)

        def fake_analyze(**kwargs):
            Path(kwargs["output_path"]).write_text(json.dumps({
                "metadata": {"name": "target.dll"},
                "functions": [
                    {"address": "0x402000", "name": "Helper",
                     "pseudocode": "void Helper(void) { return; }",
                     "call_sites": []},
                ],
                "analysis_stats": {"delta_run": True, "targeted_run": True},
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)
        merged = server_module.get_analysis_context(
            str(binary), target_addresses=["0x402000"], force_decompile=True
        )

        # Parse still calls Helper, and the index still says so.
        assert "402000" in merged["xrefs_to_function"]
        assert merged["xrefs_to_function"]["402000"][0]["from_func_name"] == "Parse"

    def test_a_delta_run_never_lowers_the_recorded_depth(
        self, tmp_path, monkeypatch, server_module
    ):
        """Targeted runs use the default structural depth. Stamping that on a
        fully-decompiled cache would send every later tool down the recovery
        path for bodies it already has."""
        binary, _ = _seed_analyzed_binary(
            tmp_path, monkeypatch, server_module, depth="full"
        )

        def fake_analyze(**kwargs):
            Path(kwargs["output_path"]).write_text(json.dumps({
                "metadata": {"name": "target.dll"},
                "functions": [
                    {"address": "0x401000", "name": "Parse",
                     "pseudocode": "void Parse(void) { return; }"},
                ],
                "analysis_stats": {"delta_run": True, "targeted_run": True},
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)
        merged = server_module.get_analysis_context(
            str(binary), target_addresses=["0x401000"], force_decompile=True
        )

        assert merged["metadata"]["analysis_depth"] == "full"


class TestJythonTargetParsing:
    """The Jython script cannot be imported here (Ghidra/Java imports, Python 2
    builtins), but its target-address parser is pure Python and is the piece
    that silently returns nothing if it is wrong -- so lift just those
    functions out of the source and exercise them for real."""

    @staticmethod
    def _load():
        import ast

        source = (
            Path(__file__).parent.parent
            / "src" / "engines" / "static" / "ghidra" / "scripts"
            / "core_analysis.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        wanted = {"_parse_hex_addr", "_parse_target_addresses"}
        picked = [
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in wanted
        ]
        assert {n.name for n in picked} == wanted

        namespace = {"safe_format": lambda fmt, *a, **k: fmt.format(*a, **k)}
        exec(  # noqa: S102 - executing our own source, by design
            compile(ast.Module(body=picked, type_ignores=[]), "<core_analysis>", "exec"),
            namespace,
        )
        return namespace

    def test_parses_prefixed_and_bare_hex(self):
        parse = self._load()["_parse_target_addresses"]
        assert parse("0x140001000,140002000") == [0x140001000, 0x140002000]

    def test_accepts_whitespace_separation(self):
        parse = self._load()["_parse_target_addresses"]
        assert parse("0x1000 0x2000") == [0x1000, 0x2000]

    def test_deduplicates_while_preserving_order(self):
        parse = self._load()["_parse_target_addresses"]
        assert parse("0x2000,0x1000,0x2000") == [0x2000, 0x1000]

    def test_drops_unparseable_entries_without_losing_the_batch(self):
        """One bad address should not cost the caller every other target."""
        parse = self._load()["_parse_target_addresses"]
        assert parse("0x1000,zzz,0x2000") == [0x1000, 0x2000]

    def test_empty_input_is_empty(self):
        parse = self._load()["_parse_target_addresses"]
        assert parse("") == []
        assert parse(None) == []


class TestBatchDecompileTool:
    def test_batch_uses_one_ghidra_run_for_the_whole_list(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        calls = []

        def fake_context(bp, **kwargs):
            calls.append(kwargs)
            ctx = server_module.cache.get_cached(bp)
            for fn in ctx["functions"]:
                fn["pseudocode"] = f"void {fn['name']}(void) {{ return; }}"
            return ctx

        monkeypatch.setattr(server_module, "get_analysis_context", fake_context)
        result = server_module.decompile_functions(
            str(binary), ["Parse", "Helper"]
        )

        assert len(calls) == 1
        assert calls[0]["target_addresses"] == ["0x401000", "0x402000"]
        assert "Decompiled this run: 2" in result
        assert "void Parse(void)" in result
        assert "void Helper(void)" in result

    def test_addresses_are_accepted_as_well_as_names(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        calls = []

        def fake_context(bp, **kwargs):
            calls.append(kwargs)
            ctx = server_module.cache.get_cached(bp)
            for fn in ctx["functions"]:
                fn["pseudocode"] = "void f(void) { return; }"
            return ctx

        monkeypatch.setattr(server_module, "get_analysis_context", fake_context)
        server_module.decompile_functions(str(binary), ["0x401000", "Helper"])

        assert calls[0]["target_addresses"] == ["0x401000", "0x402000"]

    def test_already_warm_functions_are_not_re_decompiled(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, cache_obj = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        ctx = cache_obj.get_cached(str(binary))
        ctx["functions"][0]["pseudocode"] = "void Parse(void) { return; }"
        cache_obj.save_cached(str(binary), ctx)

        calls = []

        def fake_context(bp, **kwargs):
            calls.append(kwargs)
            fresh = server_module.cache.get_cached(bp)
            for fn in fresh["functions"]:
                fn.setdefault("pseudocode", None)
                if fn["name"] == "Helper":
                    fn["pseudocode"] = "void Helper(void) { return; }"
            return fresh

        monkeypatch.setattr(server_module, "get_analysis_context", fake_context)
        result = server_module.decompile_functions(str(binary), ["Parse", "Helper"])

        assert calls[0]["target_addresses"] == ["0x402000"]
        assert "Already cached: 1" in result

    def test_unknown_names_are_reported_not_guessed(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        monkeypatch.setattr(
            server_module, "get_analysis_context",
            lambda bp, **kw: server_module.cache.get_cached(bp),
        )
        result = server_module.decompile_functions(str(binary), ["NoSuchFunction"])

        assert "Unresolved: 1" in result
        assert "NoSuchFunction" in result

    def test_empty_list_is_rejected(self, tmp_path, monkeypatch, server_module):
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        assert "empty" in server_module.decompile_functions(str(binary), [])

    def test_oversized_batch_is_rejected(self, tmp_path, monkeypatch, server_module):
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        result = server_module.decompile_functions(
            str(binary), [f"f{i}" for i in range(201)]
        )
        assert "cap is 200" in result

    def test_marks_only_the_bodies_it_actually_showed(
        self, tmp_path, monkeypatch, server_module
    ):
        """docs/coverage.md: a function is reviewed once its body has been
        handed over. Warming the cache hands nothing to anyone."""
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)

        def fake_context(bp, **kwargs):
            ctx = server_module.cache.get_cached(bp)
            for fn in ctx["functions"]:
                fn["pseudocode"] = f"void {fn['name']}(void) {{ return; }}"
            return ctx

        marked = []
        monkeypatch.setattr(server_module, "get_analysis_context", fake_context)
        monkeypatch.setattr(
            server_module, "auto_mark_reviewed",
            lambda c, bp, addrs, **kw: marked.extend(addrs),
        )

        server_module.decompile_functions(
            str(binary), ["Parse", "Helper"], include_bodies=False
        )
        assert marked == []

        server_module.decompile_functions(
            str(binary), ["Parse", "Helper"], include_bodies=True
        )
        assert sorted(marked) == ["0x401000", "0x402000"]

    def test_withheld_bodies_are_not_marked_reviewed(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)

        def fake_context(bp, **kwargs):
            ctx = server_module.cache.get_cached(bp)
            for fn in ctx["functions"]:
                fn["pseudocode"] = "void f(void) { return; }" + "x" * 4000
            return ctx

        marked = []
        monkeypatch.setattr(server_module, "get_analysis_context", fake_context)
        monkeypatch.setattr(
            server_module, "auto_mark_reviewed",
            lambda c, bp, addrs, **kw: marked.extend(addrs),
        )

        result = server_module.decompile_functions(
            str(binary), ["Parse", "Helper"], max_body_chars=5000
        )

        assert "withheld" in result
        assert len(marked) == 1

    def test_bodies_over_budget_are_withheld_not_truncated(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)

        def fake_context(bp, **kwargs):
            ctx = server_module.cache.get_cached(bp)
            for fn in ctx["functions"]:
                fn["pseudocode"] = "x" * 5000
            return ctx

        monkeypatch.setattr(server_module, "get_analysis_context", fake_context)
        result = server_module.decompile_functions(
            str(binary), ["Parse", "Helper"], max_body_chars=6000
        )

        assert "withheld" in result
        assert "Decompiled this run: 2" in result
