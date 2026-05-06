"""
Tests for Ghidra large-binary performance optimisations.

Covers:
- ProjectCache gzip round-trip + legacy .json backward read.
- Function address index side-car and get_function_by_address lookups.
- GhidraRunner plumbing of resume/range/skip_decompile into subprocess env.
- get_analysis_context wiring for incremental=True.
"""

import gzip
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.modules["mcp"] = MagicMock()
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.types"] = MagicMock()
# Shim fastmcp so src.server imports without its real deps. ``.tool()`` must
# return an identity decorator so @app.tool-wrapped functions stay callable
# from tests (shared with test_get_xrefs.py).
_identity_decorator = lambda fn: fn  # noqa: E731
_fastmcp_instance = MagicMock()
_fastmcp_instance.tool = MagicMock(return_value=_identity_decorator)
_fastmcp_stub = MagicMock()
_fastmcp_stub.FastMCP = MagicMock(return_value=_fastmcp_instance)
sys.modules["fastmcp"] = _fastmcp_stub


# -- ProjectCache ------------------------------------------------------------

class TestProjectCacheCompression:
    def _cache(self, tmp_path):
        from src.engines.static.ghidra.project_cache import ProjectCache
        return ProjectCache(cache_dir=str(tmp_path))

    def _make_binary(self, tmp_path, name="bin"):
        binary = tmp_path / name
        binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
        return binary

    def test_save_writes_gzipped_json(self, tmp_path):
        cache = self._cache(tmp_path)
        binary = self._make_binary(tmp_path)

        payload = {
            "metadata": {"name": "bin"},
            "functions": [{"address": "0x401000", "name": "entry"}],
        }
        assert cache.save_cached(str(binary), payload)

        import hashlib
        h = hashlib.sha256(binary.read_bytes()).hexdigest()
        gz_path = tmp_path / f"{h}.json.gz"
        assert gz_path.exists()

        # Plain .json cache should NOT be written
        assert not (tmp_path / f"{h}.json").exists()

        # Round-trip
        with gzip.open(gz_path, "rt", encoding="utf-8") as f:
            assert json.load(f) == payload

    def test_round_trip_via_api(self, tmp_path):
        cache = self._cache(tmp_path)
        binary = self._make_binary(tmp_path)
        payload = {"functions": [{"address": "0x1000", "name": "f"}]}

        cache.save_cached(str(binary), payload)
        assert cache.has_cached(str(binary))
        assert cache.get_cached(str(binary)) == payload

    def test_legacy_uncompressed_json_still_readable(self, tmp_path):
        """An older install with plain .json caches must keep working."""
        cache = self._cache(tmp_path)
        binary = self._make_binary(tmp_path)

        import hashlib
        h = hashlib.sha256(binary.read_bytes()).hexdigest()
        legacy = tmp_path / f"{h}.json"
        legacy.write_text(json.dumps({"functions": [], "metadata": {"v": 1}}))

        assert cache.has_cached(str(binary))
        data = cache.get_cached(str(binary))
        assert data == {"functions": [], "metadata": {"v": 1}}

    def test_saving_after_legacy_read_removes_legacy_file(self, tmp_path):
        cache = self._cache(tmp_path)
        binary = self._make_binary(tmp_path)

        import hashlib
        h = hashlib.sha256(binary.read_bytes()).hexdigest()
        legacy = tmp_path / f"{h}.json"
        legacy.write_text(json.dumps({"functions": []}))

        cache.save_cached(str(binary), {"functions": [{"address": "0x1", "name": "a"}]})

        assert (tmp_path / f"{h}.json.gz").exists()
        assert not legacy.exists()

    def test_function_index_built_and_used(self, tmp_path):
        cache = self._cache(tmp_path)
        binary = self._make_binary(tmp_path)

        payload = {
            "functions": [
                {"address": "0x1000", "name": "a"},
                {"address": "0x2000", "name": "b"},
                {"address": "0x3000", "name": "c"},
            ]
        }
        cache.save_cached(str(binary), payload)

        import hashlib
        h = hashlib.sha256(binary.read_bytes()).hexdigest()
        idx_path = tmp_path / f"{h}.funcidx.json"
        assert idx_path.exists()
        idx = json.loads(idx_path.read_text())
        assert idx == {"0x1000": 0, "0x2000": 1, "0x3000": 2}

        got = cache.get_function_by_address(str(binary), "0x2000")
        assert got == {"address": "0x2000", "name": "b"}

        assert cache.get_function_by_address(str(binary), "0xdeadbeef") is None

    def test_get_cache_path_returns_gz_when_present(self, tmp_path):
        cache = self._cache(tmp_path)
        binary = self._make_binary(tmp_path)
        cache.save_cached(str(binary), {"functions": []})

        path = cache.get_cache_path(str(binary))
        assert path is not None
        assert str(path).endswith(".json.gz")

    def test_invalidate_removes_all_artefacts(self, tmp_path):
        cache = self._cache(tmp_path)
        binary = self._make_binary(tmp_path)
        cache.save_cached(str(binary), {"functions": [{"address": "0x1", "name": "a"}]})

        assert cache.invalidate(str(binary))
        assert not cache.has_cached(str(binary))

        import hashlib
        h = hashlib.sha256(binary.read_bytes()).hexdigest()
        assert not (tmp_path / f"{h}.json.gz").exists()
        assert not (tmp_path / f"{h}.funcidx.json").exists()
        assert not (tmp_path / f"{h}.meta.json").exists()

    def test_indirect_call_keys_round_trip_through_gzip(self, tmp_path):
        # Wave 2: indirect_calls + xrefs_to_function_indirect + vtables
        # are additive cache keys. They must survive the gzip cache
        # round-trip cleanly (no schema-level rewriting / lossy
        # serialisation).
        cache = self._cache(tmp_path)
        binary = self._make_binary(tmp_path)
        payload = {
            "metadata": {"name": "x", "image_base": "0x140000000"},
            "functions": [
                {
                    "address": "0x140001000",
                    "name": "dispatcher",
                    "indirect_calls": [
                        {
                            "call_site": "0x14000204a",
                            "operand": "[RAX+0x18]",
                            "loaded_from": None,
                        },
                        {
                            "call_site": "0x140002080",
                            "operand": "[0x140030000]",
                            "loaded_from": "0x140030000",
                        },
                    ],
                },
            ],
            "xrefs_to_function_indirect": {
                "140030000": [
                    {
                        "from_func_addr": "0x140001000",
                        "from_func_name": "dispatcher",
                        "from_call_site": "0x140002080",
                        "operand": "[0x140030000]",
                    },
                ],
            },
            "vtables": [
                {
                    "section": ".rdata",
                    "address": "0x140030000",
                    "slot_count": 28,
                    "stride": 8,
                    "tags": ["DRIVER_DISPATCH_TABLE"],
                    "targets": [
                        {
                            "slot": 0,
                            "address": "0x140001000",
                            "name": "DriverEntry",
                        },
                    ],
                },
            ],
        }
        cache.save_cached(str(binary), payload)
        loaded = cache.get_cached(str(binary))
        assert loaded == payload

    def test_invalidate_keeps_notes_sidecar(self, tmp_path):
        # Wave 1B: user-supplied notes must survive cache.invalidate so
        # that force_reanalyze / load_pdb don't wipe annotations.
        cache = self._cache(tmp_path)
        binary = self._make_binary(tmp_path)
        cache.save_cached(str(binary), {"functions": [{"address": "0x1", "name": "a"}]})
        cache.write_notes(
            str(binary),
            [{"function_key": "a", "kind": "plate", "addr": None, "text": "n"}],
        )

        import hashlib
        h = hashlib.sha256(binary.read_bytes()).hexdigest()
        notes_path = tmp_path / f"{h}.notes.json"
        assert notes_path.exists()

        assert cache.invalidate(str(binary))

        # Cache artefacts gone, side-car preserved.
        assert not (tmp_path / f"{h}.json.gz").exists()
        assert notes_path.exists()
        assert cache.read_notes(str(binary)) == [
            {"function_key": "a", "kind": "plate", "addr": None, "text": "n"}
        ]


# -- GhidraRunner env plumbing ----------------------------------------------


class _FakeRunResult:
    """Popen-shaped stand-in for runner.analyze tests.

    runner.analyze now uses subprocess.Popen + manual lifecycle (so timeout
    cleanup can fan out to grandchildren). Tests patch subprocess.Popen and
    return one of these to simulate a successful run.
    """

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = None
        self.stderr = None
        self.pid = 1
        self._out = stdout
        self._err = stderr

    def communicate(self, timeout=None):
        return (self._out, self._err)

    def poll(self):
        return self.returncode

    def kill(self):
        pass


@pytest.fixture
def runner(tmp_path, monkeypatch):
    """A GhidraRunner pointed at a fake install so we can exercise analyze()."""
    from src.engines.static.ghidra.runner import GhidraRunner

    fake_ghidra = tmp_path / "ghidra"
    (fake_ghidra / "support").mkdir(parents=True)
    (fake_ghidra / "support" / "analyzeHeadless").touch()

    return GhidraRunner(ghidra_path=str(fake_ghidra))


class TestRunnerEnvPlumbing:
    def _prepare(self, runner, tmp_path):
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x00" * 128)
        script_dir = tmp_path / "scripts"
        script_dir.mkdir()
        output = tmp_path / "out.json"
        return binary, script_dir, output

    def test_resume_and_range_env_vars_forwarded(self, runner, tmp_path):
        binary, script_dir, output = self._prepare(runner, tmp_path)
        captured = {}

        def fake_run(cmd, env, **kwargs):
            captured["env"] = dict(env)
            return _FakeRunResult()

        with patch("subprocess.Popen", side_effect=fake_run):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(script_dir),
                script_name="core_analysis.py",
                output_path=str(output),
                resume_from_cache="/tmp/prior.json.gz",
                start_address="0x61abbc",
                end_address="0x800000",
                skip_decompile=True,
                max_functions=5000,
                function_timeout=15,
            )

        env = captured["env"]
        assert env["GHIDRA_RESUME_CACHE"] == "/tmp/prior.json.gz"
        assert env["GHIDRA_START_ADDRESS"] == "0x61abbc"
        assert env["GHIDRA_END_ADDRESS"] == "0x800000"
        assert env["GHIDRA_SKIP_DECOMPILE"] == "1"
        assert env["GHIDRA_MAX_FUNCTIONS"] == "5000"
        assert env["GHIDRA_FUNCTION_TIMEOUT"] == "15"
        assert env["GHIDRA_CONTEXT_JSON"] == str(output)

    def test_no_resume_env_when_not_requested(self, runner, tmp_path):
        binary, script_dir, output = self._prepare(runner, tmp_path)
        captured = {}

        def fake_run(cmd, env, **kwargs):
            captured["env"] = dict(env)
            return _FakeRunResult()

        with patch("subprocess.Popen", side_effect=fake_run):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(script_dir),
                script_name="core_analysis.py",
                output_path=str(output),
            )

        env = captured["env"]
        assert "GHIDRA_RESUME_CACHE" not in env
        assert "GHIDRA_START_ADDRESS" not in env
        assert "GHIDRA_END_ADDRESS" not in env
        assert "GHIDRA_SKIP_DECOMPILE" not in env
        assert "GHIDRA_ENABLE_FID" not in env

    def test_enable_fid_sets_env(self, runner, tmp_path):
        binary, script_dir, output = self._prepare(runner, tmp_path)
        captured = {}

        def fake_run(cmd, env, **kwargs):
            captured["env"] = dict(env)
            return _FakeRunResult()

        with patch("subprocess.Popen", side_effect=fake_run):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(script_dir),
                script_name="core_analysis.py",
                output_path=str(output),
                enable_fid=True,
            )

        assert captured["env"]["GHIDRA_ENABLE_FID"] == "1"

    def test_analysis_depth_full_default(self, runner, tmp_path):
        binary, script_dir, output = self._prepare(runner, tmp_path)
        captured = {}

        def fake_run(cmd, env, **kwargs):
            captured["cmd"] = list(cmd)
            captured["env"] = dict(env)
            return _FakeRunResult()

        with patch("subprocess.Popen", side_effect=fake_run):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(script_dir),
                script_name="core_analysis.py",
                output_path=str(output),
            )

        assert "-noanalysis" not in captured["cmd"]
        assert "GHIDRA_SKIP_DECOMPILE" not in captured["env"]
        assert captured["env"]["GHIDRA_ANALYSIS_DEPTH"] == "full"

    def test_analysis_depth_structural(self, runner, tmp_path):
        binary, script_dir, output = self._prepare(runner, tmp_path)
        captured = {}

        def fake_run(cmd, env, **kwargs):
            captured["cmd"] = list(cmd)
            captured["env"] = dict(env)
            return _FakeRunResult()

        with patch("subprocess.Popen", side_effect=fake_run):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(script_dir),
                script_name="core_analysis.py",
                output_path=str(output),
                analysis_depth="structural",
            )

        assert "-noanalysis" not in captured["cmd"]
        assert captured["env"]["GHIDRA_SKIP_DECOMPILE"] == "1"
        assert captured["env"]["GHIDRA_ANALYSIS_DEPTH"] == "structural"

    def test_analysis_depth_shallow_adds_noanalysis_flag(self, runner, tmp_path):
        binary, script_dir, output = self._prepare(runner, tmp_path)
        captured = {}

        def fake_run(cmd, env, **kwargs):
            captured["cmd"] = list(cmd)
            captured["env"] = dict(env)
            return _FakeRunResult()

        with patch("subprocess.Popen", side_effect=fake_run):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(script_dir),
                script_name="core_analysis.py",
                output_path=str(output),
                analysis_depth="shallow",
            )

        assert "-noanalysis" in captured["cmd"]
        assert captured["env"]["GHIDRA_SKIP_DECOMPILE"] == "1"
        assert captured["env"]["GHIDRA_ANALYSIS_DEPTH"] == "shallow"

    def test_analysis_depth_invalid_rejected(self, runner, tmp_path):
        binary, script_dir, output = self._prepare(runner, tmp_path)
        with pytest.raises(ValueError, match="Invalid analysis_depth"):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(script_dir),
                script_name="core_analysis.py",
                output_path=str(output),
                analysis_depth="thorough",
            )

    def test_pdb_staged_adjacent_and_cleaned_up(self, runner, tmp_path):
        """pdb_path should appear next to the binary while subprocess runs,
        and be removed afterwards."""
        binary, script_dir, output = self._prepare(runner, tmp_path)

        pdb_src = tmp_path / "external" / "my_binary.pdb"
        pdb_src.parent.mkdir()
        pdb_src.write_bytes(b"PDB fake")

        expected_staged = binary.parent / f"{binary.stem}.pdb"
        saw_staged_during_run = {"ok": False}

        def fake_run(cmd, env, **kwargs):
            saw_staged_during_run["ok"] = expected_staged.exists()
            return _FakeRunResult()

        with patch("subprocess.Popen", side_effect=fake_run):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(script_dir),
                script_name="core_analysis.py",
                output_path=str(output),
                pdb_path=str(pdb_src),
            )

        assert saw_staged_during_run["ok"], "PDB wasn't staged adjacent to binary"
        # Cleaned up after analyze returns
        assert not expected_staged.exists()

    def test_max_heap_sets_java_options(self, runner, tmp_path):
        binary, script_dir, output = self._prepare(runner, tmp_path)
        captured = {}

        def fake_run(cmd, env, **kwargs):
            captured["env"] = dict(env)
            return _FakeRunResult()

        with patch("subprocess.Popen", side_effect=fake_run):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(script_dir),
                script_name="core_analysis.py",
                output_path=str(output),
                max_heap_mb=8192,
            )

        assert "-Xmx8192m" in captured["env"]["_JAVA_OPTIONS"]

    def test_max_heap_default_from_env_var(self, runner, tmp_path, monkeypatch):
        binary, script_dir, output = self._prepare(runner, tmp_path)
        monkeypatch.setenv("GHIDRA_MAX_HEAP_MB", "6144")
        captured = {}

        def fake_run(cmd, env, **kwargs):
            captured["env"] = dict(env)
            return _FakeRunResult()

        with patch("subprocess.Popen", side_effect=fake_run):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(script_dir),
                script_name="core_analysis.py",
                output_path=str(output),
            )

        assert "-Xmx6144m" in captured["env"]["_JAVA_OPTIONS"]

    def test_max_heap_respects_existing_xmx(self, runner, tmp_path, monkeypatch):
        """If the user has already set -Xmx via _JAVA_OPTIONS, do not clobber it."""
        binary, script_dir, output = self._prepare(runner, tmp_path)
        monkeypatch.setenv("_JAVA_OPTIONS", "-Xmx16g -XX:+UseG1GC")
        captured = {}

        def fake_run(cmd, env, **kwargs):
            captured["env"] = dict(env)
            return _FakeRunResult()

        with patch("subprocess.Popen", side_effect=fake_run):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(script_dir),
                script_name="core_analysis.py",
                output_path=str(output),
                max_heap_mb=4096,
            )

        # User-provided -Xmx16g preserved; runner did not append a second one.
        assert captured["env"]["_JAVA_OPTIONS"] == "-Xmx16g -XX:+UseG1GC"

    def test_resume_manifest_env_var(self, runner, tmp_path):
        binary, script_dir, output = self._prepare(runner, tmp_path)
        captured = {}

        def fake_run(cmd, env, **kwargs):
            captured["env"] = dict(env)
            return _FakeRunResult()

        with patch("subprocess.Popen", side_effect=fake_run):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(script_dir),
                script_name="core_analysis.py",
                output_path=str(output),
                resume_manifest="/tmp/manifest.json",
            )

        assert captured["env"]["GHIDRA_RESUME_MANIFEST"] == "/tmp/manifest.json"

    def test_pdb_missing_file_raises(self, runner, tmp_path):
        binary, script_dir, output = self._prepare(runner, tmp_path)

        with patch("subprocess.Popen", return_value=_FakeRunResult()):
            try:
                runner.analyze(
                    binary_path=str(binary),
                    script_path=str(script_dir),
                    script_name="core_analysis.py",
                    output_path=str(output),
                    pdb_path=str(tmp_path / "nonexistent.pdb"),
                )
            except FileNotFoundError:
                return
        raise AssertionError("Expected FileNotFoundError for missing PDB")


# -- GhidraRunner timeout cleanup -------------------------------------------
#
# Regression: subprocess.run on Windows can hang indefinitely after timeout
# fires because Ghidra's java.exe grandchildren survive the .bat kill and
# keep the captured pipes open. runner.analyze now uses Popen + manual
# lifecycle and calls _kill_process_tree on timeout (taskkill /F /T on
# Windows, killpg(SIGKILL) on POSIX).


class _StuckPopen:
    """Popen stand-in whose first communicate() call raises TimeoutExpired."""

    def __init__(self, *, drain_returns=("partial-stdout", "partial-stderr"),
                 poll_after_kill=-9):
        self.pid = 9999
        self.returncode = None
        self.stdout = None
        self.stderr = None
        self._communicate_calls = 0
        self._drain_returns = drain_returns
        self._poll_after_kill = poll_after_kill
        self.kill_called = False

    def communicate(self, timeout=None):
        self._communicate_calls += 1
        if self._communicate_calls == 1:
            import subprocess as _subprocess
            raise _subprocess.TimeoutExpired(
                cmd=["fake-ghidra"], timeout=timeout, output="hang-stdout",
                stderr="hang-stderr",
            )
        return self._drain_returns

    def poll(self):
        return self.returncode if self.kill_called else None

    def kill(self):
        self.kill_called = True
        self.returncode = self._poll_after_kill


class TestRunnerTimeoutCleanup:
    def _prepare(self, runner, tmp_path):
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"\x00" * 128)
        script_dir = tmp_path / "scripts"
        script_dir.mkdir()
        output = tmp_path / "out.json"
        return binary, script_dir, output

    def test_timeout_invokes_process_tree_kill(self, runner, tmp_path, monkeypatch):
        """When communicate() times out, _kill_process_tree must be called
        with the Popen instance so the whole java.exe tree gets torn down."""
        from src.engines.static.ghidra import runner as runner_mod

        binary, script_dir, output = self._prepare(runner, tmp_path)
        stuck = _StuckPopen()

        kill_calls = []

        def fake_kill(proc):
            kill_calls.append(proc)
            proc.kill()

        monkeypatch.setattr(runner_mod, "_kill_process_tree", fake_kill)

        with patch("subprocess.Popen", return_value=stuck):
            with pytest.raises(runner_mod.GhidraAnalysisError) as exc_info:
                runner.analyze(
                    binary_path=str(binary),
                    script_path=str(script_dir),
                    script_name="core_analysis.py",
                    output_path=str(output),
                    timeout=30,
                )

        assert kill_calls == [stuck], "tree-kill must run exactly once on timeout"
        assert "timed out after 30s" in str(exc_info.value)
        # Diagnostic should surface partial output so the user sees how far
        # Ghidra got.
        assert exc_info.value.diagnostic, "diagnostic must not be empty on timeout"

    def test_drain_timeout_does_not_hang(self, runner, tmp_path, monkeypatch):
        """If even the post-kill drain communicate() times out (descendant
        still holding pipes), runner.analyze must still return promptly via
        GhidraAnalysisError instead of blocking indefinitely."""
        from src.engines.static.ghidra import runner as runner_mod

        binary, script_dir, output = self._prepare(runner, tmp_path)

        class _DoublyStuckPopen(_StuckPopen):
            def communicate(self, timeout=None):
                self._communicate_calls += 1
                import subprocess as _subprocess
                raise _subprocess.TimeoutExpired(
                    cmd=["fake-ghidra"], timeout=timeout,
                    output="hang", stderr="hang",
                )

        stuck = _DoublyStuckPopen()
        monkeypatch.setattr(runner_mod, "_kill_process_tree",
                            lambda p: setattr(p, "returncode", -9))

        # Force-close the proc's pipes; runner code should swallow that.
        with patch("subprocess.Popen", return_value=stuck):
            with pytest.raises(runner_mod.GhidraAnalysisError):
                runner.analyze(
                    binary_path=str(binary),
                    script_path=str(script_dir),
                    script_name="core_analysis.py",
                    output_path=str(output),
                    timeout=10,
                )

    def test_kill_process_tree_uses_taskkill_on_windows(self, monkeypatch):
        """_kill_process_tree on Windows must invoke taskkill /F /T."""
        from src.engines.static.ghidra import runner as runner_mod

        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = list(cmd)
            captured["kwargs"] = kwargs
            class R:
                returncode = 0
            return R()

        # Pretend we're on Windows.
        monkeypatch.setattr(runner_mod.os, "name", "nt")

        proc = _StuckPopen()  # poll() returns None until kill()

        with patch("subprocess.run", side_effect=fake_run):
            runner_mod._kill_process_tree(proc)

        assert captured["cmd"][0] == "taskkill"
        assert "/F" in captured["cmd"]
        assert "/T" in captured["cmd"]
        assert str(proc.pid) in captured["cmd"]

    @pytest.mark.skipif(
        os.name == "nt",
        reason="os.killpg/os.getpgid are POSIX-only; the Windows path is "
               "covered by test_kill_process_tree_uses_taskkill_on_windows.",
    )
    def test_kill_process_tree_uses_killpg_on_posix(self, monkeypatch):
        """_kill_process_tree on POSIX must SIGKILL the child's process group."""
        from src.engines.static.ghidra import runner as runner_mod

        monkeypatch.setattr(runner_mod.os, "name", "posix")

        killpg_calls = []

        def fake_killpg(pgid, sig):
            killpg_calls.append((pgid, sig))

        monkeypatch.setattr(runner_mod.os, "killpg", fake_killpg)
        monkeypatch.setattr(runner_mod.os, "getpgid", lambda pid: 12345)

        proc = _StuckPopen()
        runner_mod._kill_process_tree(proc)

        assert killpg_calls, "killpg must be invoked on POSIX"
        pgid, sig = killpg_calls[0]
        assert pgid == 12345
        assert sig == runner_mod.signal.SIGKILL

    def test_kill_process_tree_skips_already_dead_proc(self):
        """Don't bother killing if the process already exited."""
        from src.engines.static.ghidra import runner as runner_mod

        class _DeadPopen:
            pid = 1
            def poll(self):
                return 0  # already exited

        with patch("subprocess.run") as mock_run:
            runner_mod._kill_process_tree(_DeadPopen())
            assert not mock_run.called


# -- get_analysis_context incremental wiring --------------------------------


@pytest.fixture
def server_module(tmp_path_factory, monkeypatch):
    """Import src.server with a stubbed Ghidra installation."""
    fake_ghidra = tmp_path_factory.mktemp("ghidra_home")
    (fake_ghidra / "support").mkdir()
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    monkeypatch.setenv("GHIDRA_HOME", str(fake_ghidra))

    # Ensure a fresh import in case a prior test already loaded it
    sys.modules.pop("src.server", None)
    import src.server as server_mod
    return server_mod


class TestIncrementalWiring:
    def test_incremental_passes_cache_path_to_runner(
        self, tmp_path, monkeypatch, server_module
    ):
        """incremental=True with an existing cache should hand the path to Ghidra."""
        from src.engines.static.ghidra.project_cache import ProjectCache

        binary = tmp_path / "target.bin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 128)

        cache_obj = ProjectCache(cache_dir=str(tmp_path / "cache"))
        cache_obj.save_cached(
            str(binary),
            {"functions": [{"address": "0x1000", "name": "pre"}], "metadata": {}},
        )

        monkeypatch.setattr(server_module, "cache", cache_obj)
        monkeypatch.setattr(
            server_module, "get_allowed_dirs", lambda: [tmp_path]
        )

        captured = {}

        def fake_analyze(**kwargs):
            captured.update(kwargs)
            output = Path(kwargs["output_path"])
            output.write_text(json.dumps({
                "metadata": {"executable_format": "ELF"},
                "functions": [{"address": "0x1000", "name": "pre"}],
                "imports": [{"library": "libc"}],
                "strings": [],
                "memory_map": [{"name": ".text"}],
                "analysis_stats": {"resumed": True, "resumed_from_count": 1},
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)

        server_module.get_analysis_context(str(binary), incremental=True)

        # Manifest path now does the work that resume_from_cache used to.
        # The legacy resume_from_cache kwarg is set to None when manifest is
        # present so the Jython script never loads the multi-GB JSON.
        manifest_arg = captured.get("resume_manifest")
        assert manifest_arg is not None
        assert manifest_arg.endswith(".json")
        assert captured.get("resume_from_cache") is None

    def test_address_range_without_incremental_auto_promotes(
        self, tmp_path, monkeypatch, server_module
    ):
        """Caller passes start_address with incremental=False and an existing
        cache. Server must auto-promote to incremental so the cache merges
        instead of getting overwritten."""
        from src.engines.static.ghidra.project_cache import ProjectCache

        binary = tmp_path / "target.bin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 128)

        cache_obj = ProjectCache(cache_dir=str(tmp_path / "cache"))
        # Pretend we already have a 41K-function cache from a structural pass.
        cache_obj.save_cached(
            str(binary),
            {
                "functions": [
                    {"address": f"0x{0x1000+i:x}", "name": f"f{i}"}
                    for i in range(10)
                ],
                "metadata": {"executable_format": "ELF"},
            },
        )

        monkeypatch.setattr(server_module, "cache", cache_obj)
        monkeypatch.setattr(
            server_module, "get_allowed_dirs", lambda: [tmp_path]
        )

        captured = {}

        def fake_analyze(**kwargs):
            captured.update(kwargs)
            Path(kwargs["output_path"]).write_text(json.dumps({
                "metadata": {"executable_format": "ELF"},
                "functions": [{"address": "0x1000", "name": "pre"}],
                "imports": [], "strings": [], "memory_map": [{"name": ".text"}],
                "analysis_stats": {"resumed": True, "resumed_from_count": 10},
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)

        # Call without incremental=True. Should auto-promote.
        server_module.get_analysis_context(
            str(binary),
            start_address="0x180920000",
            end_address="0x180BA46FC",
            skip_decompile=False,
        )

        manifest_arg = captured.get("resume_manifest")
        assert manifest_arg is not None, (
            "auto-promotion should have written a resume manifest to merge "
            "instead of overwriting the existing cache"
        )
        assert captured.get("resume_from_cache") is None

    def test_address_range_without_incremental_no_cache_runs_full(
        self, tmp_path, monkeypatch, server_module
    ):
        """If no cache exists yet, do not auto-promote -- a fresh range run
        is fine when there is nothing to preserve."""
        from src.engines.static.ghidra.project_cache import ProjectCache

        binary = tmp_path / "target.bin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 128)

        cache_obj = ProjectCache(cache_dir=str(tmp_path / "cache"))

        monkeypatch.setattr(server_module, "cache", cache_obj)
        monkeypatch.setattr(
            server_module, "get_allowed_dirs", lambda: [tmp_path]
        )

        captured = {}

        def fake_analyze(**kwargs):
            captured.update(kwargs)
            Path(kwargs["output_path"]).write_text(json.dumps({
                "metadata": {"executable_format": "ELF"},
                "functions": [], "imports": [], "strings": [],
                "memory_map": [{"name": ".text"}],
                "analysis_stats": {},
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)

        server_module.get_analysis_context(
            str(binary), start_address="0x1000", end_address="0x2000",
        )

        assert captured.get("resume_from_cache") is None


class TestResumeManifest:
    def test_manifest_skip_decompile_true_marks_all_complete(self, tmp_path):
        from src.server import _write_resume_manifest

        existing = {
            "functions": [
                {"address": "0x1000", "pseudocode": None},
                {"address": "0x2000", "pseudocode": "int f() { return 0; }"},
                {"address": "0x3000", "decompile_status": "skipped_thunk_or_external"},
            ],
        }
        path = _write_resume_manifest(
            tmp_path, "/tmp/whatever.bin", existing, skip_decompile=True,
        )
        assert path is not None
        with open(path) as f:
            data = json.load(f)
        # skip_decompile=True -> every entry counts as complete
        assert set(data["complete_addresses"]) == {"0x1000", "0x2000", "0x3000"}

    def test_manifest_skip_decompile_false_only_with_pseudocode(self, tmp_path):
        from src.server import _write_resume_manifest

        existing = {
            "functions": [
                {"address": "0x1000", "pseudocode": None},
                {"address": "0x2000", "pseudocode": "int f() {}"},
                {"address": "0x3000", "decompile_status": "skipped_thunk_or_external"},
                {"address": "0x4000", "decompile_status": "thread_timeout",
                 "pseudocode": None},
            ],
        }
        path = _write_resume_manifest(
            tmp_path, "/tmp/whatever.bin", existing, skip_decompile=False,
        )
        with open(path) as f:
            data = json.load(f)
        # skip_decompile=False -> only entries with pseudocode (or thunks)
        assert set(data["complete_addresses"]) == {"0x2000", "0x3000"}
        # 0x1000 (no pseudocode) and 0x4000 (timed out) are NOT complete and
        # will be re-decompiled this run.

    def test_manifest_handles_no_functions(self, tmp_path):
        from src.server import _write_resume_manifest

        path = _write_resume_manifest(
            tmp_path, "/tmp/x.bin", {"functions": []}, skip_decompile=False,
        )
        with open(path) as f:
            data = json.load(f)
        assert data["complete_addresses"] == []

    def test_manifest_includes_run_id(self, tmp_path):
        from src.server import _write_resume_manifest

        path = _write_resume_manifest(
            tmp_path, "/tmp/x.bin", {"functions": []}, skip_decompile=False,
        )
        with open(path) as f:
            data = json.load(f)
        assert "run_id" in data
        assert "-" in data["run_id"]  # "<pid>-<monotonic_ns>"

    def test_manifest_atomic_write(self, tmp_path):
        """Verify the writer goes through .tmp + os.replace, not a direct open."""
        from unittest.mock import patch

        from src.server import _write_resume_manifest

        observed_replace = []

        real_replace = os.replace

        def spy_replace(src, dst):
            observed_replace.append((str(src), str(dst)))
            return real_replace(src, dst)

        with patch("src.server.os.replace", side_effect=spy_replace):
            _write_resume_manifest(
                tmp_path, "/tmp/x.bin", {"functions": []}, skip_decompile=False,
            )

        assert len(observed_replace) == 1
        src, dst = observed_replace[0]
        assert src.endswith(".tmp")
        assert dst.endswith(".json")


class TestDeltaRunLock:
    def test_concurrent_delta_runs_blocked(self, tmp_path):
        """Acquiring the lock once blocks a second concurrent acquisition."""
        from src.server import _delta_run_lock

        with _delta_run_lock(tmp_path, "/tmp/sample.bin"):
            with pytest.raises(RuntimeError, match="incremental analysis is already running"):
                with _delta_run_lock(tmp_path, "/tmp/sample.bin"):
                    pass  # pragma: no cover

    def test_lock_releases_after_use(self, tmp_path):
        """After exit, a follow-up acquisition succeeds."""
        from src.server import _delta_run_lock

        with _delta_run_lock(tmp_path, "/tmp/sample.bin"):
            pass
        # Should not raise.
        with _delta_run_lock(tmp_path, "/tmp/sample.bin"):
            pass


class TestDeltaMerge:
    def test_replaces_by_address(self):
        from src.server import _merge_delta_into_cache

        existing = {
            "functions": [
                {"address": "0x1000", "name": "old", "pseudocode": None},
                {"address": "0x2000", "name": "untouched"},
            ],
            "imports": [{"library": "old.dll"}],
        }
        delta = {
            "functions": [
                {"address": "0x1000", "name": "new", "pseudocode": "int f() {}"},
            ],
            "imports": [{"library": "new.dll"}],
            "metadata": {"format": "PE"},
            "analysis_stats": {"delta_run": True, "functions_analyzed": 1},
        }
        merged = _merge_delta_into_cache(existing, delta)
        # 0x1000 replaced; 0x2000 preserved unchanged
        funcs_by_addr = {f["address"]: f for f in merged["functions"]}
        assert funcs_by_addr["0x1000"]["pseudocode"] == "int f() {}"
        assert funcs_by_addr["0x2000"]["name"] == "untouched"
        # Top-level fields take from delta
        assert merged["imports"] == [{"library": "new.dll"}]
        assert merged["metadata"] == {"format": "PE"}

    def test_appends_new_addresses(self):
        from src.server import _merge_delta_into_cache

        existing = {"functions": [{"address": "0x1000", "name": "old"}]}
        delta = {
            "functions": [
                {"address": "0x1000", "name": "old"},
                {"address": "0x9000", "name": "newly_discovered"},
            ],
            "analysis_stats": {"delta_run": True},
        }
        merged = _merge_delta_into_cache(existing, delta)
        addrs = [f["address"] for f in merged["functions"]]
        assert "0x9000" in addrs
        assert len(addrs) == 2

    def test_preserves_skipped_functions_when_delta_lacks_them(self):
        from src.server import _merge_delta_into_cache

        existing = {
            "functions": [],
            "skipped_functions": [{"name": "fail", "address": "0xdead"}],
        }
        delta = {"functions": [], "analysis_stats": {"delta_run": True}}
        merged = _merge_delta_into_cache(existing, delta)
        assert merged["skipped_functions"] == [
            {"name": "fail", "address": "0xdead"}
        ]


class TestDeltaIntegration:
    def test_delta_run_merges_into_existing_cache(
        self, tmp_path, monkeypatch, server_module
    ):
        """End-to-end: existing cache has 5 structural-only entries, the
        Ghidra delta brings pseudocode for 2 of them. Result should be the
        full 5 with pseudocode filled where the delta provided it."""
        from src.engines.static.ghidra.project_cache import ProjectCache

        binary = tmp_path / "target.bin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 128)

        cache_obj = ProjectCache(cache_dir=str(tmp_path / "cache"))
        existing = {
            "metadata": {"executable_format": "ELF"},
            "functions": [
                {"address": f"0x{0x1000+i*0x10:x}", "name": f"f{i}",
                 "pseudocode": None}
                for i in range(5)
            ],
            "imports": [{"library": "libc"}],
            "strings": [],
            "memory_map": [{"name": ".text"}],
        }
        cache_obj.save_cached(str(binary), existing)

        monkeypatch.setattr(server_module, "cache", cache_obj)
        monkeypatch.setattr(
            server_module, "get_allowed_dirs", lambda: [tmp_path]
        )

        def fake_analyze(**kwargs):
            output = Path(kwargs["output_path"])
            # Simulate delta containing only the 2 newly-decompiled funcs.
            output.write_text(json.dumps({
                "metadata": {"executable_format": "ELF"},
                "functions": [
                    {"address": "0x1010", "name": "f1",
                     "pseudocode": "int f1() { return 1; }"},
                    {"address": "0x1020", "name": "f2",
                     "pseudocode": "int f2() { return 2; }"},
                ],
                "imports": [{"library": "libc"}],
                "strings": [],
                "memory_map": [{"name": ".text"}],
                "analysis_stats": {
                    "delta_run": True, "functions_analyzed": 2,
                },
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)

        merged = server_module.get_analysis_context(
            str(binary), incremental=True, skip_decompile=False,
        )

        addrs = {f["address"]: f for f in merged["functions"]}
        # All 5 retained
        assert len(addrs) == 5
        # The two delta entries got their pseudocode filled in
        assert addrs["0x1010"]["pseudocode"].startswith("int f1")
        assert addrs["0x1020"]["pseudocode"].startswith("int f2")
        # The three untouched still have None pseudocode
        assert addrs["0x1000"]["pseudocode"] is None
        assert addrs["0x1030"]["pseudocode"] is None
        assert addrs["0x1040"]["pseudocode"] is None


# -- Error propagation through get_analysis_context -------------------------
# Regression tests for docs/ghidra-mcp-defender-issues.md (Issue 2):
# get_analysis_context used to wrap every exception in a plain RuntimeError,
# stripping GhidraAnalysisError.diagnostic and UserFacingError type info so
# analyze_binary's curated handlers were unreachable.


class TestErrorPropagation:
    def _setup(self, tmp_path, monkeypatch, server_module):
        from src.engines.static.ghidra.project_cache import ProjectCache
        binary = tmp_path / "target.bin"
        binary.write_bytes(b"MZ" + b"\x00" * 128)
        cache_obj = ProjectCache(cache_dir=str(tmp_path / "cache"))
        monkeypatch.setattr(server_module, "cache", cache_obj)
        monkeypatch.setattr(server_module, "get_allowed_dirs", lambda: [tmp_path])
        return binary

    def test_ghidra_analysis_error_propagates_with_diagnostic(
        self, tmp_path, monkeypatch, server_module
    ):
        from src.engines.static.ghidra.runner import GhidraAnalysisError
        binary = self._setup(tmp_path, monkeypatch, server_module)

        def fake_analyze(**kwargs):
            raise GhidraAnalysisError(
                "Ghidra exited with code 1",
                diagnostic="UnsupportedClassVersionError: Ghidra/Util/Exception/CancelledException",
            )

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)

        with pytest.raises(GhidraAnalysisError) as exc_info:
            server_module.get_analysis_context(str(binary))

        assert "UnsupportedClassVersionError" in exc_info.value.diagnostic

    def test_user_facing_error_propagates(
        self, tmp_path, monkeypatch, server_module
    ):
        from src.utils.security import UserFacingError
        binary = self._setup(tmp_path, monkeypatch, server_module)

        def fake_analyze(**kwargs):
            output = Path(kwargs["output_path"])
            output.write_text(json.dumps({
                "metadata": {},
                "functions": [],
                "imports": [],
                "strings": [],
                "memory_map": [],
            }))
            return {
                "elapsed_time": 1.0,
                "stdout": "Exception: Cannot import file",
                "stderr": "",
            }

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)

        with pytest.raises(UserFacingError) as exc_info:
            server_module.get_analysis_context(str(binary))

        assert exc_info.value.user_message
        assert exc_info.value.error_id

    def test_analyze_binary_surfaces_ghidra_diagnostic(
        self, tmp_path, monkeypatch, server_module
    ):
        from src.engines.static.ghidra.runner import GhidraAnalysisError
        binary = self._setup(tmp_path, monkeypatch, server_module)

        def fake_analyze(**kwargs):
            raise GhidraAnalysisError(
                "Ghidra exited with code 1",
                diagnostic="OSGi bundle cache corrupt; clear ~/.ghidra/.../osgi",
            )

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)

        result = server_module.analyze_binary(
            str(binary), skip_compatibility_check=True
        )

        assert "OSGi bundle cache corrupt" in result
        assert "Reference ID:" not in result or "Diagnostic:" in result


class TestDecompileOnDemand:
    """decompile_function should auto-fill pseudocode when the cache was
    produced with skip_decompile / analysis_depth=structural."""

    def test_structural_cache_triggers_targeted_decompile(
        self, tmp_path, monkeypatch, server_module
    ):
        from src.engines.static.ghidra.project_cache import ProjectCache

        binary = tmp_path / "target.bin"
        binary.write_bytes(b"MZ" + b"\x00" * 128)

        cache_obj = ProjectCache(cache_dir=str(tmp_path / "cache"))
        # Pre-seed a structural cache: function exists, pseudocode is None.
        cache_obj.save_cached(
            str(binary),
            {
                "metadata": {"analysis_depth": "structural"},
                "functions": [
                    {"address": "0x401000", "name": "FUN_401000",
                     "signature": "void FUN_401000(void)", "pseudocode": None},
                ],
                "imports": [], "strings": [], "memory_map": [],
            },
        )

        monkeypatch.setattr(server_module, "cache", cache_obj)
        monkeypatch.setattr(server_module, "get_allowed_dirs", lambda: [tmp_path])

        captured = {}

        def fake_analyze(**kwargs):
            captured.update(kwargs)
            output = Path(kwargs["output_path"])
            output.write_text(json.dumps({
                "metadata": {"analysis_depth": "full"},
                "functions": [
                    {"address": "0x401000", "name": "FUN_401000",
                     "signature": "void FUN_401000(void)",
                     "pseudocode": "void FUN_401000(void) { return; }"},
                ],
                "imports": [], "strings": [], "memory_map": [],
                "analysis_stats": {"delta_run": True, "redecompiled": 1},
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)

        result = server_module.decompile_function(str(binary), "FUN_401000")

        assert captured.get("start_address") == "0x401000"
        assert captured.get("max_functions") == 1
        assert "FUN_401000(void) { return; }" in result


# Regression for the cache depth-rejection bug introduced by PR #116:
# tools that don't read pseudocode (get_strings, get_imports, ...) must
# accept a cached structural analysis. Previously they inherited the "full"
# default and forced a 30-min Ghidra reanalysis on every call.
class TestDefaultDepthAcceptsStructuralCache:
    def _seed(self, tmp_path, monkeypatch, server_module, cached_depth):
        from src.engines.static.ghidra.project_cache import ProjectCache

        binary = tmp_path / "target.bin"
        binary.write_bytes(b"MZ" + b"\x00" * 128)

        cache_obj = ProjectCache(cache_dir=str(tmp_path / "cache"))
        cache_obj.save_cached(
            str(binary),
            {
                "metadata": {"analysis_depth": cached_depth},
                "functions": [
                    {"address": "0x401000", "name": "main",
                     "signature": "int main(void)", "pseudocode": None},
                ],
                "imports": [{"library": "kernel32.dll", "name": "CreateFileA"}],
                "exports": [],
                "strings": [
                    {"address": "0x402000", "value": "ExclusionList",
                     "length": 13, "type": "string", "xrefs": []},
                ],
                "memory_map": [{"name": ".text"}],
            },
        )
        monkeypatch.setattr(server_module, "cache", cache_obj)
        monkeypatch.setattr(server_module, "get_allowed_dirs", lambda: [tmp_path])
        return binary

    def test_get_strings_returns_from_structural_cache_without_running_ghidra(
        self, tmp_path, monkeypatch, server_module
    ):
        binary = self._seed(tmp_path, monkeypatch, server_module, "structural")

        def fail_if_called(**kwargs):
            raise AssertionError(
                "runner.analyze must NOT be invoked when a structural cache "
                "satisfies the default-depth caller (regression: PR #116)."
            )

        monkeypatch.setattr(server_module.runner, "analyze", fail_if_called)

        result = server_module.get_strings(str(binary))

        assert "ExclusionList" in result

    def test_get_imports_returns_from_structural_cache_without_running_ghidra(
        self, tmp_path, monkeypatch, server_module
    ):
        binary = self._seed(tmp_path, monkeypatch, server_module, "structural")

        def fail_if_called(**kwargs):
            raise AssertionError(
                "runner.analyze must NOT be invoked for get_imports on a "
                "structural cache."
            )

        monkeypatch.setattr(server_module.runner, "analyze", fail_if_called)

        result = server_module.get_imports(str(binary))

        assert "CreateFileA" in result

    def test_full_cache_also_satisfies_default_depth(
        self, tmp_path, monkeypatch, server_module
    ):
        binary = self._seed(tmp_path, monkeypatch, server_module, "full")

        def fail_if_called(**kwargs):
            raise AssertionError(
                "runner.analyze must NOT be invoked when a full cache is "
                "available."
            )

        monkeypatch.setattr(server_module.runner, "analyze", fail_if_called)

        result = server_module.get_strings(str(binary))

        assert "ExclusionList" in result

    def test_shallow_cache_still_forces_reanalysis(
        self, tmp_path, monkeypatch, server_module
    ):
        """A shallow cache lacks auto-analyzer-derived strings; the depth
        check must still upgrade it to structural."""
        binary = self._seed(tmp_path, monkeypatch, server_module, "shallow")

        captured = {}

        def fake_analyze(**kwargs):
            captured.update(kwargs)
            output = Path(kwargs["output_path"])
            output.write_text(json.dumps({
                "metadata": {"analysis_depth": "structural"},
                "functions": [
                    {"address": "0x401000", "name": "main",
                     "signature": "int main(void)", "pseudocode": None},
                ],
                "imports": [{"library": "kernel32.dll", "name": "CreateFileA"}],
                "exports": [],
                "strings": [
                    {"address": "0x402000", "value": "FreshAfterReanalyze",
                     "length": 19, "type": "string", "xrefs": []},
                ],
                "memory_map": [{"name": ".text"}],
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)

        result = server_module.get_strings(str(binary))

        assert captured, "runner.analyze should be invoked for shallow cache"
        assert "FreshAfterReanalyze" in result

    def test_analyze_binary_top_level_default_remains_full(
        self, tmp_path, monkeypatch, server_module
    ):
        """analyze_binary is the user-facing entry point and must default to
        analysis_depth='full' regardless of the lowered get_analysis_context
        floor."""
        binary = tmp_path / "target.bin"
        binary.write_bytes(b"MZ" + b"\x00" * 128)

        from src.engines.static.ghidra.project_cache import ProjectCache
        cache_obj = ProjectCache(cache_dir=str(tmp_path / "cache"))
        monkeypatch.setattr(server_module, "cache", cache_obj)
        monkeypatch.setattr(server_module, "get_allowed_dirs", lambda: [tmp_path])

        captured = {}

        def fake_analyze(**kwargs):
            captured.update(kwargs)
            output = Path(kwargs["output_path"])
            output.write_text(json.dumps({
                "metadata": {"executable_format": "PE",
                             "analysis_depth": "full"},
                "functions": [
                    {"address": "0x401000", "name": "main",
                     "signature": "int main(void)",
                     "pseudocode": "int main(void) { return 0; }"},
                ],
                "imports": [], "strings": [], "memory_map": [{"name": ".text"}],
            }))
            return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(server_module.runner, "analyze", fake_analyze)

        server_module.analyze_binary(str(binary), skip_compatibility_check=True)

        assert captured.get("analysis_depth") == "full", (
            "analyze_binary's top-level default must remain 'full'; "
            f"got {captured.get('analysis_depth')!r}"
        )
