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


# -- GhidraRunner env plumbing ----------------------------------------------


class _FakeRunResult:
    def __init__(self):
        self.returncode = 0
        self.stdout = ""
        self.stderr = ""


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

        with patch("subprocess.run", side_effect=fake_run):
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

        with patch("subprocess.run", side_effect=fake_run):
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

        with patch("subprocess.run", side_effect=fake_run):
            runner.analyze(
                binary_path=str(binary),
                script_path=str(script_dir),
                script_name="core_analysis.py",
                output_path=str(output),
                enable_fid=True,
            )

        assert captured["env"]["GHIDRA_ENABLE_FID"] == "1"

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

        with patch("subprocess.run", side_effect=fake_run):
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

    def test_pdb_missing_file_raises(self, runner, tmp_path):
        binary, script_dir, output = self._prepare(runner, tmp_path)

        with patch("subprocess.run", return_value=_FakeRunResult()):
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

        resume_arg = captured.get("resume_from_cache")
        assert resume_arg is not None
        assert resume_arg.endswith(".json.gz")

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

        resume_arg = captured.get("resume_from_cache")
        assert resume_arg is not None, (
            "auto-promotion should have set resume_from_cache to merge "
            "instead of overwriting the existing cache"
        )

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
