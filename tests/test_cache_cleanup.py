"""
Tests for the cache cleanup story:

- ProjectCache._prune_legacy_duplicates auto-runs on __init__ and removes
  legacy ``<hash>.json`` duplicates when a ``<hash>.json.gz`` exists,
  without touching side-car files (.meta.json / .funcidx.json /
  .notes.json) that share the same stem.
- ProjectCache.invalidate(include_project=True) and
  ProjectCache.clear_all(include_projects=True) drop the matching
  ghidra_projects/ artifacts.
- The clean_cache MCP tool wires both together and reports freed bytes.
"""

from __future__ import annotations

import hashlib
import sys
from unittest.mock import MagicMock

import pytest

# Stub MCP deps before importing src.server, mirroring the harness used
# by tests/test_notes_sidecar.py and tests/test_ghidra_perf.py.
sys.modules["mcp"] = MagicMock()
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.types"] = MagicMock()
_identity_decorator = lambda fn: fn  # noqa: E731
_fastmcp_instance = MagicMock()
_fastmcp_instance.tool = MagicMock(return_value=_identity_decorator)
_fastmcp_stub = MagicMock()
_fastmcp_stub.FastMCP = MagicMock(return_value=_fastmcp_instance)
sys.modules["fastmcp"] = _fastmcp_stub


def _binary(tmp_path, name="bin"):
    binary = tmp_path / name
    binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
    return binary


def _binary_hash(binary):
    return hashlib.sha256(binary.read_bytes()).hexdigest()


def _cache(cache_dir):
    from src.engines.static.ghidra.project_cache import ProjectCache

    return ProjectCache(cache_dir=str(cache_dir))


# --- Auto-prune legacy .json duplicates -------------------------------------


def test_prune_removes_legacy_when_gz_exists(tmp_path):
    """Legacy <hash>.json is dropped when <hash>.json.gz is present."""
    h = "0" * 64
    (tmp_path / f"{h}.json").write_text("{}")
    (tmp_path / f"{h}.json.gz").write_bytes(b"\x1f\x8b")

    _cache(tmp_path)

    assert not (tmp_path / f"{h}.json").exists()
    assert (tmp_path / f"{h}.json.gz").exists()


def test_prune_preserves_legacy_when_no_gz(tmp_path):
    """Legacy <hash>.json is kept when no .gz counterpart exists."""
    h = "1" * 64
    (tmp_path / f"{h}.json").write_text("{}")

    _cache(tmp_path)

    assert (tmp_path / f"{h}.json").exists()


def test_prune_does_not_touch_sidecars(tmp_path):
    """.meta.json / .funcidx.json / .notes.json all survive even with .gz present."""
    h = "2" * 64
    (tmp_path / f"{h}.json.gz").write_bytes(b"\x1f\x8b")
    (tmp_path / f"{h}.meta.json").write_text('{"meta": true}')
    (tmp_path / f"{h}.funcidx.json").write_text('{"idx": 1}')
    (tmp_path / f"{h}.notes.json").write_text('{"notes": []}')

    _cache(tmp_path)

    assert (tmp_path / f"{h}.meta.json").exists()
    assert (tmp_path / f"{h}.funcidx.json").exists()
    assert (tmp_path / f"{h}.notes.json").exists()


def test_prune_is_idempotent(tmp_path):
    """Re-instantiating the cache after a prune is a no-op (no errors)."""
    h = "3" * 64
    (tmp_path / f"{h}.json").write_text("{}")
    (tmp_path / f"{h}.json.gz").write_bytes(b"\x1f\x8b")

    _cache(tmp_path)
    _cache(tmp_path)  # second init must not error

    assert not (tmp_path / f"{h}.json").exists()
    assert (tmp_path / f"{h}.json.gz").exists()


# --- invalidate(include_project=True) ---------------------------------------


def _make_project_artifacts(cache_dir, project_name):
    """Create the .gpr / .lock / .rep/ artifacts for a project_name."""
    project_dir = cache_dir / "ghidra_projects"
    project_dir.mkdir(parents=True, exist_ok=True)
    gpr = project_dir / f"{project_name}.gpr"
    lock = project_dir / f"{project_name}.lock"
    rep = project_dir / f"{project_name}.rep"
    gpr.write_text("")
    lock.write_text("")
    rep.mkdir()
    (rep / "data.txt").write_text("project state")
    return gpr, lock, rep


def test_invalidate_with_project_drops_ghidra_artifacts(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    binary = _binary(tmp_path)

    cache = _cache(cache_dir)
    cache.save_cached(str(binary), {"functions": [], "metadata": {}})
    gpr, lock, rep = _make_project_artifacts(cache_dir, binary.stem)

    cache.invalidate(str(binary), include_project=True)

    assert not gpr.exists()
    assert not lock.exists()
    assert not rep.exists()


def test_invalidate_default_keeps_ghidra_artifacts(tmp_path):
    """Without include_project, the .gpr/.rep/ are preserved."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    binary = _binary(tmp_path)

    cache = _cache(cache_dir)
    cache.save_cached(str(binary), {"functions": [], "metadata": {}})
    gpr, lock, rep = _make_project_artifacts(cache_dir, binary.stem)

    cache.invalidate(str(binary))  # default: include_project=False

    assert gpr.exists()
    assert lock.exists()
    assert rep.exists()


def test_clear_all_with_projects_wipes_directory(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    binary = _binary(tmp_path)

    cache = _cache(cache_dir)
    cache.save_cached(str(binary), {"functions": [], "metadata": {}})
    _make_project_artifacts(cache_dir, binary.stem)

    cache.clear_all(include_projects=True)

    assert not (cache_dir / "ghidra_projects").exists()


def test_clear_all_default_keeps_ghidra_projects_dir(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    binary = _binary(tmp_path)

    cache = _cache(cache_dir)
    cache.save_cached(str(binary), {"functions": [], "metadata": {}})
    _make_project_artifacts(cache_dir, binary.stem)

    cache.clear_all()  # default: include_projects=False

    assert (cache_dir / "ghidra_projects").exists()


def test_project_name_matches_runner_sanitization(tmp_path):
    """ProjectCache._get_project_name must mirror runner's sanitisation
    (non-alphanum -> _, leading - -> proj_)."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    cache = _cache(cache_dir)

    assert cache._get_project_name("/tmp/foo bar.dll") == "foo_bar"
    assert cache._get_project_name("/tmp/-leading.exe") == "proj_-leading"
    assert cache._get_project_name("/tmp/normal.elf") == "normal"


# --- clean_cache MCP tool ---------------------------------------------------


@pytest.fixture
def server_with_temp_cache(tmp_path, tmp_path_factory, monkeypatch):
    """Wire src.server.cache to a temp ProjectCache rooted in tmp_path.

    Stubs out the GhidraRunner detection that runs at server import
    time (the runner.py module-level instance demands a real Ghidra
    install or GHIDRA_HOME) so import succeeds in CI.
    """
    fake_ghidra = tmp_path_factory.mktemp("ghidra_home")
    (fake_ghidra / "support").mkdir()
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    monkeypatch.setenv("GHIDRA_HOME", str(fake_ghidra))
    monkeypatch.setenv("BINARY_MCP_ALLOWED_DIRS", "")
    sys.modules.pop("src.server", None)
    import src.server as server_module
    from src.engines.static.ghidra.project_cache import ProjectCache

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setattr(server_module, "cache", ProjectCache(cache_dir=str(cache_dir)))
    return server_module, cache_dir


def test_clean_cache_per_binary_invalidates_and_reports(server_with_temp_cache, tmp_path):
    server_module, cache_dir = server_with_temp_cache
    binary = _binary(tmp_path)
    server_module.cache.save_cached(str(binary), {"functions": [], "metadata": {}})
    h = _binary_hash(binary)
    assert (cache_dir / f"{h}.json.gz").exists()

    result = server_module.clean_cache(binary_path=str(binary))

    assert "Cache invalidated" in result
    assert "Notes side-car preserved" in result
    assert "Freed:" in result
    assert not (cache_dir / f"{h}.json.gz").exists()


def test_clean_cache_full_wipe_no_args(server_with_temp_cache, tmp_path):
    server_module, cache_dir = server_with_temp_cache
    b1 = _binary(tmp_path, "a.bin")
    b2 = _binary(tmp_path, "b.bin")
    server_module.cache.save_cached(str(b1), {"functions": [], "metadata": {}})
    server_module.cache.save_cached(str(b2), {"functions": [], "metadata": {}})

    result = server_module.clean_cache()

    assert "Cache fully wiped" in result
    assert "Top-level entries removed:" in result
    assert not list(cache_dir.glob("*.json.gz"))


def test_clean_cache_include_ghidra_projects_drops_dir(server_with_temp_cache, tmp_path):
    server_module, cache_dir = server_with_temp_cache
    binary = _binary(tmp_path)
    server_module.cache.save_cached(str(binary), {"functions": [], "metadata": {}})
    _make_project_artifacts(cache_dir, binary.stem)

    result = server_module.clean_cache(binary_path=str(binary), include_ghidra_projects=True)

    assert "Ghidra project removed: yes" in result
    project_dir = cache_dir / "ghidra_projects"
    assert not (project_dir / f"{binary.stem}.gpr").exists()
    assert not (project_dir / f"{binary.stem}.rep").exists()


def test_clean_cache_missing_binary_returns_friendly_error(server_with_temp_cache, tmp_path):
    server_module, _ = server_with_temp_cache
    missing = tmp_path / "does-not-exist.dll"

    result = server_module.clean_cache(binary_path=str(missing))

    assert "Binary not found" in result
    assert "clean_cache() with no arguments" in result


def test_clean_cache_preserves_notes_sidecar(server_with_temp_cache, tmp_path):
    """Per-binary invalidate must NOT touch the notes side-car."""
    server_module, cache_dir = server_with_temp_cache
    binary = _binary(tmp_path)
    server_module.cache.save_cached(str(binary), {"functions": [], "metadata": {}})
    h = _binary_hash(binary)
    notes = cache_dir / f"{h}.notes.json"
    notes.write_text('{"notes": [{"address": "0x1000", "text": "hi"}]}')

    server_module.clean_cache(binary_path=str(binary))

    assert notes.exists()
    assert "hi" in notes.read_text()
