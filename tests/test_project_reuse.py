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

import contextlib
import json
import sys
import threading
import time
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
    # The job registry is built at import time from the cache root, and the
    # decompile paths now run through it. Without this the suite would write
    # job records into the developer's real ~/ghidra_mcp_cache.
    monkeypatch.setenv("BINARY_CACHE_DIR", str(tmp_path_factory.mktemp("cache")))
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
        reuse, _, _ = self._decide(server_module, binary, name)
        assert reuse is True

    def test_no_project_on_disk_refuses(self, tmp_path, monkeypatch, server_module):
        binary, name = self._seed(tmp_path, monkeypatch, server_module)
        (server_module.cache.cache_dir / "ghidra_projects" / f"{name}.gpr").unlink()
        reuse, reason, _ = self._decide(server_module, binary, name)
        assert reuse is False
        assert "no Ghidra project" in reason

    def test_missing_owner_record_refuses(self, tmp_path, monkeypatch, server_module):
        binary, name = self._seed(tmp_path, monkeypatch, server_module)
        server_module.cache.clear_project_state(name)
        reuse, reason, _ = self._decide(server_module, binary, name)
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

        reuse, reason, _ = self._decide(server_module, binary, name)
        assert reuse is False
        assert "different binary" in reason

    def test_unanalyzed_project_refuses_for_structural(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, name = self._seed(tmp_path, monkeypatch, server_module, analyzed=False)
        reuse, reason, _ = self._decide(server_module, binary, name)
        assert reuse is False
        assert "without analysis" in reason

    def test_unanalyzed_project_still_serves_a_shallow_request(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, name = self._seed(tmp_path, monkeypatch, server_module, analyzed=False)
        reuse, _, _ = self._decide(server_module, binary, name, analysis_depth="shallow")
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
        reuse, _, _ = self._decide(server_module, binary, name, **override)
        assert reuse is False


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
            # The real get_analysis_context persists; the tool reads the
            # bodies back from the cache rather than from the return value.
            server_module.cache.save_cached(bp, ctx)
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
            server_module.cache.save_cached(bp, ctx)
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
            server_module.cache.save_cached(bp, fresh)
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
            server_module.cache.save_cached(bp, ctx)
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
            server_module.cache.save_cached(bp, ctx)
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
            server_module.cache.save_cached(bp, ctx)
            return ctx

        monkeypatch.setattr(server_module, "get_analysis_context", fake_context)
        result = server_module.decompile_functions(
            str(binary), ["Parse", "Helper"], max_body_chars=6000
        )

        assert "withheld" in result
        assert "Decompiled this run: 2" in result


class TestInlineDeadline:
    """Deadline-then-degrade: block only as long as is safe, then hand back a
    job handle. Correct against a client that waits 30 seconds and one that
    waits 28 hours, without either being configured anywhere."""

    def test_wait_returns_a_handle_when_work_outlives_the_deadline(
        self, tmp_path, monkeypatch, server_module
    ):
        import threading

        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        monkeypatch.setenv("BINARY_MCP_INLINE_DEADLINE", "1")
        release = threading.Event()

        def slow_context(bp, **kwargs):
            release.wait(10)
            ctx = server_module.cache.get_cached(bp)
            for fn in ctx["functions"]:
                fn["pseudocode"] = "void f(void) { return; }"
            server_module.cache.save_cached(bp, ctx)
            return ctx

        monkeypatch.setattr(server_module, "get_analysis_context", slow_context)
        result = server_module.decompile_function(str(binary), "Parse", wait=True)

        assert "job_id:" in result
        assert "Still running after 1s" in result
        release.set()

    def test_wait_answers_inline_when_work_beats_the_deadline(
        self, tmp_path, monkeypatch, server_module
    ):
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        monkeypatch.setenv("BINARY_MCP_INLINE_DEADLINE", "30")

        def quick_context(bp, **kwargs):
            ctx = server_module.cache.get_cached(bp)
            for fn in ctx["functions"]:
                fn["pseudocode"] = "void Parse(void) { return; }"
            server_module.cache.save_cached(bp, ctx)
            return ctx

        monkeypatch.setattr(server_module, "get_analysis_context", quick_context)
        result = server_module.decompile_function(str(binary), "Parse", wait=True)

        # The whole point: a fast decompile still reads as an ordinary
        # synchronous call, with no job id anywhere in the answer.
        assert "job_id" not in result
        assert "void Parse(void) { return; }" in result

    def test_a_failed_job_reports_the_reason_not_a_handle(
        self, tmp_path, monkeypatch, server_module
    ):
        """Handing back a job id for work that already failed would send the
        caller to poll a job whose only content is the error."""
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        monkeypatch.setenv("BINARY_MCP_INLINE_DEADLINE", "30")

        def boom(bp, **kwargs):
            raise RuntimeError("ghidra exploded")

        monkeypatch.setattr(server_module, "get_analysis_context", boom)
        result = server_module.decompile_function(str(binary), "Parse", wait=True)

        assert "ghidra exploded" in result
        assert "job_id:" not in result

    def test_wait_false_still_returns_immediately(
        self, tmp_path, monkeypatch, server_module
    ):
        import threading

        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        monkeypatch.setenv("BINARY_MCP_INLINE_DEADLINE", "300")
        release = threading.Event()

        def slow_context(bp, **kwargs):
            release.wait(10)
            return server_module.cache.get_cached(bp)

        monkeypatch.setattr(server_module, "get_analysis_context", slow_context)
        result = server_module.decompile_function(str(binary), "Parse", wait=False)

        # Must not have honoured the 300s deadline.
        assert "job_id:" in result
        release.set()

    def test_warm_cache_never_touches_the_job_registry(
        self, tmp_path, monkeypatch, server_module
    ):
        """A cache hit needs no Ghidra run, so it must not pay for a claim
        file, a job record, a thread and a poll."""
        binary, cache_obj = _seed_analyzed_binary(
            tmp_path, monkeypatch, server_module, depth="full"
        )
        ctx = cache_obj.get_cached(str(binary))
        for fn in ctx["functions"]:
            fn["pseudocode"] = "void f(void) { return; }"
        cache_obj.save_cached(str(binary), ctx)

        submitted = []
        monkeypatch.setattr(
            server_module.jobs, "submit",
            lambda **kw: submitted.append(kw) or {"error": "should not submit"},
        )

        result = server_module.analyze_binary(
            str(binary), skip_compatibility_check=True
        )

        assert submitted == []
        assert "Binary Analysis Complete" in result

    def test_deadline_is_configurable_and_bounded(self, monkeypatch, server_module):
        monkeypatch.setenv("BINARY_MCP_INLINE_DEADLINE", "90")
        assert server_module._inline_deadline() == 90.0

        monkeypatch.delenv("BINARY_MCP_INLINE_DEADLINE", raising=False)
        assert server_module._inline_deadline() == 25.0

        monkeypatch.setenv("BINARY_MCP_INLINE_DEADLINE", "99999")
        with pytest.raises(ValueError):
            server_module._inline_deadline()


class TestReviewFindings:
    """Regressions for defects found reviewing this change."""

    def test_one_unusable_address_does_not_fail_the_whole_frontier(
        self, tmp_path, monkeypatch, server_module
    ):
        """Batching made a single bad address expensive: runner.analyze
        validates every target and raises on the first mismatch, so a callee
        Ghidra renders outside the default space (EXTERNAL:00000008) used to
        take the entire frontier down with it."""
        assert server_module._HEX_ADDR_RE.match("0x140001000")
        assert server_module._HEX_ADDR_RE.match("140001000")
        assert not server_module._HEX_ADDR_RE.match("0xexternal:00000008")
        assert not server_module._HEX_ADDR_RE.match("0x1000; rm -rf /")

    def test_targeted_run_does_not_promote_a_shallow_cache(
        self, tmp_path, monkeypatch, server_module
    ):
        """A targeted decompile says nothing about how the program was
        analyzed. Tagging a shallow cache 'structural' claims an auto-analysis
        pass that never ran, and every later tool then accepts it."""
        binary, _ = _seed_analyzed_binary(
            tmp_path, monkeypatch, server_module, depth="shallow"
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

        assert merged["metadata"]["analysis_depth"] == "shallow"

    def test_a_reuse_run_that_exits_nonzero_falls_back_to_import(
        self, tmp_path, monkeypatch, server_module
    ):
        """A stale .lock from a killed run makes -process exit non-zero. Only
        catching 'exit 0 but no output' left that surfacing as a hard failure
        with the stale owner record still in place."""
        from src.engines.static.ghidra.runner import GhidraAnalysisError

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
                raise GhidraAnalysisError("project is locked", diagnostic="lock")
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

        assert attempts == [True, False]
        assert merged["functions"][0]["pseudocode"]

    def test_an_import_failure_is_still_raised(
        self, tmp_path, monkeypatch, server_module
    ):
        """The fallback must not swallow a genuine import failure -- there is
        nothing left to fall back to."""
        from src.engines.static.ghidra.runner import GhidraAnalysisError

        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)

        def always_fails(**kwargs):
            raise GhidraAnalysisError("no load spec found")

        monkeypatch.setattr(server_module.runner, "analyze", always_fails)
        with pytest.raises(GhidraAnalysisError):
            server_module.get_analysis_context(
                str(binary), target_addresses=["0x401000"], force_decompile=True
            )

    def test_a_bad_deadline_does_not_orphan_a_ghidra_run(
        self, tmp_path, monkeypatch, server_module
    ):
        """validate_numeric_range raises rather than clamping. Resolving the
        deadline after submit would start Ghidra and then discard the job_id
        with the ValueError, leaving a run nobody has a handle to."""
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        monkeypatch.setenv("BINARY_MCP_INLINE_DEADLINE", "99999")
        submitted = []
        monkeypatch.setattr(
            server_module.jobs, "submit",
            lambda **kw: submitted.append(kw) or {"job_id": "x", "state": "running"},
        )

        result = server_module.decompile_function(str(binary), "Parse", wait=True)

        assert submitted == [], "nothing may be submitted before the deadline parses"
        assert "Error" in result

    def test_binary_hash_is_memoized_but_notices_a_changed_file(self, tmp_path):
        cache_obj = _cache(tmp_path)
        binary = tmp_path / "target.dll"
        binary.write_bytes(b"MZ" + b"\x00" * 64)

        reads = []
        real_open = open

        def counting_open(path, *a, **kw):
            if str(path) == str(binary):
                reads.append(path)
            return real_open(path, *a, **kw)

        import builtins
        original = builtins.open
        builtins.open = counting_open
        try:
            first = cache_obj._get_binary_hash(str(binary))
            second = cache_obj._get_binary_hash(str(binary))
            assert first == second
            assert len(reads) == 1, "the second call must not re-read the file"

            # A changed file must produce a fresh hash, or the memo would serve
            # another binary's cache and another binary's Ghidra project.
            import os as _os
            binary.write_bytes(b"MZ" + b"\xff" * 64)
            _os.utime(binary, (0, 0))
            assert cache_obj._get_binary_hash(str(binary)) != first
        finally:
            builtins.open = original

    def test_runner_and_cache_agree_on_long_project_names(self, tmp_path, runner):
        """The two derivations must produce the same name or cache cleanup
        targets a project that does not exist."""
        long_stem = "a" * 150
        binary = tmp_path / f"{long_stem}.dll"
        binary.write_bytes(b"MZ" + b"\x00" * 64)
        scripts = tmp_path / "scripts"
        scripts.mkdir()

        seen = {}
        runner._run_headless = lambda cmd, env, *a, **kw: seen.update(cmd=cmd) or {}
        runner.analyze(
            binary_path=str(binary),
            script_path=str(scripts),
            script_name="core_analysis.py",
            output_path=str(tmp_path / "out.json"),
        )

        cache_obj = _cache(tmp_path)
        assert seen["cmd"][2] == cache_obj._get_project_name(str(binary))


class TestFinalReviewFindings:
    """Regressions for the final review pass."""

    def test_the_hash_suffix_survives_the_runner_name_clamp(self, tmp_path):
        """project_name_for appended the hash and the runner then truncated it
        off, so Ghidra created `<prefix>_43e6` while project_exists looked for
        `<stem>_43e6bd75`. Reuse could never engage for a long stem, and the
        .rep leaked under a name no cleanup path knows."""
        from src.engines.static.ghidra.project_cache import _PROJECT_NAME_MAX

        cache_obj = _cache(tmp_path)
        binary = tmp_path / ("a" * 150 + ".dll")
        binary.write_bytes(b"MZ" + b"\x00" * 64)

        name = cache_obj.project_name_for(str(binary))
        assert len(name) <= _PROJECT_NAME_MAX
        assert name[:_PROJECT_NAME_MAX] == name, "the runner clamp must be a no-op"
        assert name.endswith(cache_obj._get_binary_hash(str(binary))[:8])

    def test_skip_decompile_first_pass_hits_its_own_cache(
        self, tmp_path, monkeypatch, server_module
    ):
        """The documented large-binary workflow. skip_decompile=True writes a
        'structural' cache but the request says depth='full', so without
        lowering the requested depth every repeat invocation re-ran Ghidra."""
        binary, cache_obj = _seed_analyzed_binary(
            tmp_path, monkeypatch, server_module, depth="structural"
        )

        hit = server_module._acceptable_cached_context(
            str(binary), analysis_depth="full", skip_decompile=True
        )
        assert hit is not None, "the structural first pass must hit its own cache"

        miss = server_module._acceptable_cached_context(
            str(binary), analysis_depth="full", skip_decompile=False
        )
        assert miss is None, "a genuine full request must still miss"

    def test_warm_path_still_enforces_the_allowed_dirs(
        self, tmp_path, monkeypatch, server_module
    ):
        """The warm short-circuit returns a cached report without reaching
        get_analysis_context, where the confinement check used to live."""
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        elsewhere = tmp_path / "outside"
        elsewhere.mkdir()
        monkeypatch.setattr(server_module, "get_allowed_dirs", lambda: [elsewhere])

        result = server_module.analyze_binary(
            str(binary), skip_compatibility_check=True
        )
        assert "Binary Analysis Complete" not in result
        assert "Invalid" in result or "denied" in result.lower()

    def test_a_legacy_cache_without_a_depth_tag_is_not_demoted(
        self, tmp_path, monkeypatch, server_module
    ):
        """A cache written before the depth was stamped reads as 'full'
        everywhere else. Reading it as None here let a targeted delta write
        'structural' over a fully-decompiled binary."""
        cache_obj = _cache(tmp_path)
        binary = tmp_path / "legacy.dll"
        binary.write_bytes(b"MZ" + b"\x00" * 128)
        cache_obj.save_cached(str(binary), {
            "metadata": {"name": "legacy.dll"},   # no analysis_depth at all
            "functions": [
                {"address": "0x401000", "name": "Parse", "pseudocode": None},
            ],
            "imports": [], "strings": [], "memory_map": [],
        })
        monkeypatch.setattr(server_module, "cache", cache_obj)
        monkeypatch.setattr(server_module, "get_allowed_dirs", lambda: [tmp_path])

        def fake_analyze(**kwargs):
            Path(kwargs["output_path"]).write_text(json.dumps({
                "metadata": {"name": "legacy.dll"},
                "functions": [{"address": "0x401000", "name": "Parse",
                               "pseudocode": "void Parse(void) { return; }"}],
                "analysis_stats": {"delta_run": True, "targeted_run": True},
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)
        merged = server_module.get_analysis_context(
            str(binary), target_addresses=["0x401000"], force_decompile=True
        )
        assert merged["metadata"]["analysis_depth"] == "full"

    def test_the_merged_cache_is_written_once_per_run(
        self, tmp_path, monkeypatch, server_module
    ):
        """Two full gzip writes per targeted decompile, on the hot path."""
        binary, cache_obj = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        saves = []
        real_save = cache_obj.save_cached
        monkeypatch.setattr(
            cache_obj, "save_cached",
            lambda bp, data: saves.append(bp) or real_save(bp, data),
        )

        def fake_analyze(**kwargs):
            Path(kwargs["output_path"]).write_text(json.dumps({
                "metadata": {"name": "target.dll"},
                "functions": [{"address": "0x401000", "name": "Parse",
                               "pseudocode": "void Parse(void) { return; }"}],
                "analysis_stats": {"delta_run": True, "targeted_run": True},
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)
        server_module.get_analysis_context(
            str(binary), target_addresses=["0x401000"], force_decompile=True
        )
        assert len(saves) == 1, f"expected one save, got {len(saves)}"

    def test_a_transient_record_read_failure_is_not_a_vanished_job(self, tmp_path):
        """read() maps every OSError to None, so a Windows sharing violation on
        the heartbeat-rewritten record looked identical to a missing job and
        told the caller their running analysis had disappeared."""
        from src.engines.jobs import JobRegistry

        registry = JobRegistry(tmp_path, stale_after=60, heartbeat_interval=60)
        submitted = registry.submit(kind="test", key="k", fn=lambda ctx: {"ok": 1})
        job_id = submitted["job_id"]

        real_read = registry.read
        calls = {"n": 0}

        def flaky_read(jid):
            calls["n"] += 1
            if calls["n"] == 1:
                return None      # transient
            return real_read(jid)

        registry.read = flaky_read
        record = registry.wait(job_id, timeout=5)
        assert record is not None, "one bad read must not read as 'job gone'"
        assert record["state"] == "succeeded"

    def test_the_hash_memo_expires(self, tmp_path, monkeypatch):
        """mtime granularity is ~15.6ms on Windows, so a same-size rewrite can
        be invisible to the fingerprint. The TTL bounds how long that can serve
        the previous build's project."""
        import src.engines.static.ghidra.project_cache as pc

        cache_obj = _cache(tmp_path)
        binary = tmp_path / "target.dll"
        binary.write_bytes(b"MZ" + b"\x00" * 64)
        first = cache_obj._get_binary_hash(str(binary))

        # Same size, same mtime -- invisible to the fingerprint.
        import os as _os
        stat = _os.stat(binary)
        binary.write_bytes(b"MZ" + b"\xff" * 64)
        _os.utime(binary, ns=(stat.st_atime_ns, stat.st_mtime_ns))

        assert cache_obj._get_binary_hash(str(binary)) == first, "memo still warm"

        clock = [1e9]
        monkeypatch.setattr(pc.time, "monotonic", lambda: clock[0])
        cache_obj._hash_memo.clear()
        cache_obj._get_binary_hash(str(binary))
        clock[0] += pc._HASH_MEMO_TTL_SECONDS + 1
        binary.write_bytes(b"MZ" + b"\xaa" * 64)
        _os.utime(binary, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        assert cache_obj._get_binary_hash(str(binary)) != first, "TTL must expire it"


class TestTargetedRunLockPosture:
    """A targeted run must queue behind a stem-mate rather than fail instantly.

    `ProjectCache._get_project_name` is the legacy stem-only name and is
    deliberately still the lock key, because "two binaries sharing a stem are
    exactly the pair a same-named old/new build produces, and serialising them
    costs a queue rather than a corrupted run". A queue is the designed cost.

    Passing `wait_seconds=0.0` on the targeted path charged a hard failure
    instead. Observed on a patch-diff workload across four builds of one DLL:
    6 of 47 targeted decompiles failed the moment a *different build* took the
    lock, five of which were retried unchanged a minute later and succeeded.

    Only a job-backed run can afford the queue, though -- it degrades to a
    handle and the caller polls. The inline path keeps failing fast; see
    `test_an_inline_targeted_run_still_fails_fast`.
    """

    def _fake_analyze(self, **kwargs):
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

    @contextlib.contextmanager
    def _stem_mate_holding_the_lock(self, server_module, cache_obj, binary):
        """Hold the run lock as a different build of the same DLL would."""
        holder_in = threading.Event()
        release = threading.Event()

        def _hold():
            with server_module._delta_run_lock(
                cache_obj.cache_dir,
                # Different path, same stem -- so the same lock key. This is
                # exactly the production collision.
                "/other/build/target.dll",
                lock_key=cache_obj._get_project_name(str(binary)),
            ):
                holder_in.set()
                release.wait(10)

        holder = threading.Thread(target=_hold, daemon=True)
        holder.start()
        assert holder_in.wait(5)
        try:
            yield release
        finally:
            release.set()
            holder.join(timeout=10)

    def test_a_job_backed_targeted_run_queues_behind_a_stem_mate(
        self, tmp_path, monkeypatch, server_module
    ):
        """The old/new build pair is the patch-diff case; it must not fail."""
        binary, cache_obj = _seed_analyzed_binary(
            tmp_path, monkeypatch, server_module
        )
        monkeypatch.setattr(server_module.runner, "analyze", self._fake_analyze)

        with self._stem_mate_holding_the_lock(
            server_module, cache_obj, binary
        ) as release:
            done = []

            def _run():
                done.append(server_module.get_analysis_context(
                    str(binary),
                    target_addresses=["0x401000"],
                    force_decompile=True,
                    job_context=MagicMock(),
                ))

            runner_thread = threading.Thread(target=_run, daemon=True)
            runner_thread.start()
            # Queued, not refused: still waiting while the stem-mate holds it.
            runner_thread.join(timeout=1.0)
            assert done == []

            release.set()
            runner_thread.join(timeout=10)

        assert len(done) == 1 and done[0] is not None

    def test_an_inline_targeted_run_still_fails_fast(
        self, tmp_path, monkeypatch, server_module
    ):
        """Without a job there is no handle to poll, so queueing would just
        hang the client. `expand_callgraph` decompiles frontier batches on the
        request path and already records a refused batch and moves on."""
        binary, cache_obj = _seed_analyzed_binary(
            tmp_path, monkeypatch, server_module
        )
        monkeypatch.setattr(server_module.runner, "analyze", self._fake_analyze)

        with self._stem_mate_holding_the_lock(server_module, cache_obj, binary):
            started = time.monotonic()
            with pytest.raises(RuntimeError, match="already running"):
                server_module.get_analysis_context(
                    str(binary),
                    target_addresses=["0x401000"],
                    force_decompile=True,
                )
            assert time.monotonic() - started < 2.0

    def test_the_queue_is_bounded_well_below_a_plain_analysis(
        self, tmp_path, monkeypatch, server_module
    ):
        """Queueing must not mean queueing for the plain-analysis hour.

        A targeted decompile is interactive. Waiting `_RUN_LOCK_WAIT_SECONDS`
        behind a full analysis would leave the caller polling a handle that has
        not started for most of an hour; an error naming the wait beats that.
        """
        binary, _ = _seed_analyzed_binary(tmp_path, monkeypatch, server_module)
        monkeypatch.setattr(server_module.runner, "analyze", self._fake_analyze)

        real_lock = server_module._delta_run_lock
        captured = {}

        def capturing_lock(cache_dir, binary_path, **kwargs):
            captured.update(kwargs)
            return real_lock(cache_dir, binary_path, **kwargs)

        monkeypatch.setattr(server_module, "_delta_run_lock", capturing_lock)
        server_module.get_analysis_context(
            str(binary),
            target_addresses=["0x401000"],
            force_decompile=True,
            job_context=MagicMock(),
        )

        assert captured["wait_seconds"] > 0, "a job-backed targeted run queues"
        assert captured["wait_seconds"] < server_module._RUN_LOCK_WAIT_SECONDS
