"""
Tests for the Jython extension detection in GhidraRunner.

Ghidra 12.1 (release note GP-6754, May 2026) stopped bundling Jython. Since
core_analysis.py and enable_pdb_load.py are Jython scripts, analyzeHeadless
silently fails on 12.1+ without the Jython extension installed. The runner
now gates analyze() on the presence of an installed Jython extension and
surfaces a UserFacingError with install instructions when it's missing.

Covers:
- Old Ghidra (<12.1): Jython bundled, no extension check needed.
- New Ghidra (>=12.1) with installed extension: passes.
- New Ghidra (>=12.1) without extension: raises UserFacingError.
- Downloaded-but-not-installed zip is rejected.
- Malformed application.properties: conservative no-op.
- Version-string parsing across the suffix variants Ghidra ships.
- Cache hit on _jython_check_done.
- Both candidate extension dirs (Ghidra/Extensions/Jython and
  Extensions/Jython) are honored.
"""

import sys
from unittest.mock import MagicMock

import pytest

# Match the MCP/fastmcp shim from test_ghidra_perf.py so importing the runner
# (which transitively pulls in src.* modules) works without the real deps.
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

# -- helpers ----------------------------------------------------------------


def _stub_ghidra_install(
    base_dir,
    *,
    version: str | None,
    jython_dir_rel: str | None = None,
    extra_files: tuple[str, ...] = (),
):
    """
    Create a minimal Ghidra installation under ``base_dir``.

    - support/analyzeHeadless is always touched so _is_valid_ghidra_installation
      would pass (we don't actually use the auto-detect path; we pass
      ghidra_path explicitly, but having it here matches a realistic install).
    - application.properties is written iff ``version`` is not None. When
      ``version`` is the empty string, the file is written without an
      application.version line at all (simulates a corrupted file).
    - jython_dir_rel, when given, is a relative dir under base_dir; a stub
      ``stub.jar`` is created inside it so _jython_extension_dir_has_jar
      returns True.
    - extra_files: arbitrary relative paths to touch (used to simulate the
      downloaded-but-unextracted Jython zip).
    """
    install = base_dir / "ghidra"
    (install / "support").mkdir(parents=True)
    (install / "support" / "analyzeHeadless").touch()

    if version is not None:
        # ``version`` of "" => no version line written (malformed file).
        if version == "":
            (install / "application.properties").write_text(
                "application.name=Ghidra\n# no version line here\n",
                encoding="utf-8",
            )
        else:
            (install / "application.properties").write_text(
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


# -- _get_ghidra_version parsing -------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("12.1", (12, 1)),
        ("12.1.0", (12, 1)),
        ("12.1_DEV", (12, 1)),
        ("12.1-RC1", (12, 1)),
        ("12.1+build.7", (12, 1)),
        ("11.4", (11, 4)),
        ("11.4.5_DEV", (11, 4)),
    ],
)
def test_get_ghidra_version_parses_supported_formats(tmp_path, raw, expected):
    install = _stub_ghidra_install(tmp_path, version=raw)
    runner = GhidraRunner(ghidra_path=str(install))
    assert runner._get_ghidra_version() == expected


@pytest.mark.parametrize(
    "raw",
    [
        "garbage",
        "DEV",
        "v12",   # missing minor
        "12.",   # trailing dot, no minor digits
        "...",
        "12-RC1",
    ],
)
def test_get_ghidra_version_returns_none_for_unparseable(tmp_path, raw):
    install = _stub_ghidra_install(tmp_path, version=raw)
    runner = GhidraRunner(ghidra_path=str(install))
    assert runner._get_ghidra_version() is None


def test_get_ghidra_version_returns_none_when_properties_missing(tmp_path):
    install = _stub_ghidra_install(tmp_path, version=None)
    runner = GhidraRunner(ghidra_path=str(install))
    assert runner._read_version_string() is None
    assert runner._get_ghidra_version() is None


def test_get_ghidra_version_returns_none_when_value_empty(tmp_path):
    # version="" writes the file without an application.version line at all,
    # which is the realistic "malformed properties" case the parser must
    # tolerate.
    install = _stub_ghidra_install(tmp_path, version="")
    runner = GhidraRunner(ghidra_path=str(install))
    assert runner._read_version_string() is None
    assert runner._get_ghidra_version() is None


# -- ensure_jython_available -----------------------------------------------


def test_old_ghidra_without_extension_does_not_raise(tmp_path):
    """Ghidra 11.4 ships Jython bundled, so we never require the extension."""
    install = _stub_ghidra_install(tmp_path, version="11.4")
    runner = GhidraRunner(ghidra_path=str(install))

    # Should not raise.
    runner.ensure_jython_available()
    assert runner._jython_available() is True

    diag = runner.diagnose()
    assert diag["jython_required"] is False


def test_new_ghidra_with_extension_does_not_raise(tmp_path):
    """Ghidra 12.1 with the extension installed under
    Ghidra/Extensions/Jython/lib/ should pass cleanly."""
    install = _stub_ghidra_install(
        tmp_path,
        version="12.1",
        jython_dir_rel="Ghidra/Extensions/Jython/lib",
    )
    runner = GhidraRunner(ghidra_path=str(install))

    runner.ensure_jython_available()

    diag = runner.diagnose()
    assert diag["jython_required"] is True
    assert diag["jython_available"] is True


def test_new_ghidra_without_extension_raises_user_facing(tmp_path):
    """Ghidra 12.1 with no Jython dir must raise UserFacingError and the
    message must point users at File -> Install Extensions."""
    install = _stub_ghidra_install(tmp_path, version="12.1")
    runner = GhidraRunner(ghidra_path=str(install))

    with pytest.raises(UserFacingError) as excinfo:
        runner.ensure_jython_available()

    msg = excinfo.value.user_message.lower()
    assert "jython" in msg
    assert "install extensions" in msg

    diag = runner.diagnose()
    assert diag["jython_required"] is True
    assert diag["jython_available"] is False


def test_downloaded_zip_is_not_enough(tmp_path):
    """A zip dropped under Extensions/Ghidra/ but never extracted is the
    'I downloaded it from the website but never clicked Install Extensions'
    case -- analyzeHeadless cannot load it, so we must still raise."""
    install = _stub_ghidra_install(
        tmp_path,
        version="12.1",
        extra_files=(
            "Extensions/Ghidra/ghidra_12.1_PUBLIC_Jython.zip",
        ),
    )
    runner = GhidraRunner(ghidra_path=str(install))

    with pytest.raises(UserFacingError):
        runner.ensure_jython_available()


def test_malformed_application_properties_is_conservative(tmp_path):
    """If we can't parse the version, treat Jython as available rather than
    blocking users on a minimally-stubbed/customised install."""
    install = _stub_ghidra_install(tmp_path, version="garbage")
    runner = GhidraRunner(ghidra_path=str(install))

    # Must NOT raise on unknown version.
    runner.ensure_jython_available()

    diag = runner.diagnose()
    assert diag["jython_required"] is False
    # _jython_available is True for unparseable versions by design.
    assert diag["jython_available"] is True


def test_missing_application_properties_is_conservative(tmp_path):
    """No application.properties file at all should also be a no-op."""
    install = _stub_ghidra_install(tmp_path, version=None)
    runner = GhidraRunner(ghidra_path=str(install))

    runner.ensure_jython_available()

    diag = runner.diagnose()
    assert diag["jython_required"] is False
    assert diag["jython_available"] is True


# -- caching ----------------------------------------------------------------


def test_ensure_jython_available_caches_result(tmp_path):
    """After a successful check, subsequently removing the extension dir
    must NOT cause the second call to raise. This proves
    self._jython_check_done short-circuits the re-stat."""
    install = _stub_ghidra_install(
        tmp_path,
        version="12.1",
        jython_dir_rel="Ghidra/Extensions/Jython/lib",
    )
    runner = GhidraRunner(ghidra_path=str(install))

    runner.ensure_jython_available()
    assert runner._jython_check_done is True

    # Nuke the extension dir. If the cache weren't honored, the next call
    # would re-stat, see nothing, and raise.
    import shutil
    shutil.rmtree(install / "Ghidra" / "Extensions" / "Jython")

    # Must still be a no-op.
    runner.ensure_jython_available()


def test_old_ghidra_caches_after_first_call(tmp_path):
    """Old-Ghidra path also flips the cache flag so we don't keep re-reading
    application.properties on every analyze()."""
    install = _stub_ghidra_install(tmp_path, version="11.4")
    runner = GhidraRunner(ghidra_path=str(install))

    assert runner._jython_check_done is False
    runner.ensure_jython_available()
    assert runner._jython_check_done is True


# -- both candidate extension dirs honored ---------------------------------


@pytest.mark.parametrize(
    "jython_dir_rel",
    [
        "Ghidra/Extensions/Jython/lib",
        "Extensions/Jython/lib",
    ],
)
def test_both_extension_dirs_honored(tmp_path, jython_dir_rel):
    """Both Ghidra/Extensions/Jython and Extensions/Jython are valid install
    locations depending on the zip layout the user used."""
    install = _stub_ghidra_install(
        tmp_path,
        version="12.1",
        jython_dir_rel=jython_dir_rel,
    )
    runner = GhidraRunner(ghidra_path=str(install))

    # Should not raise.
    runner.ensure_jython_available()
    assert runner._jython_available() is True


@pytest.mark.parametrize(
    "jython_dir_rel",
    [
        # Some layouts drop jars directly in the extension root, not lib/.
        "Ghidra/Extensions/Jython",
        "Extensions/Jython",
    ],
)
def test_extension_dir_with_jar_at_root_honored(tmp_path, jython_dir_rel):
    """_jython_extension_dir_has_jar accepts jars directly under the
    extension dir as well as under lib/."""
    install = _stub_ghidra_install(
        tmp_path,
        version="12.1",
        jython_dir_rel=jython_dir_rel,
    )
    runner = GhidraRunner(ghidra_path=str(install))

    runner.ensure_jython_available()
    assert runner._jython_available() is True


def test_empty_jython_dir_without_jar_does_not_satisfy(tmp_path):
    """A directory at the expected path but with no .jar files inside
    (a half-finished install / a stray empty dir) must still raise."""
    install = _stub_ghidra_install(tmp_path, version="12.1")
    # Create the dir but no jar inside.
    (install / "Ghidra" / "Extensions" / "Jython").mkdir(parents=True)
    runner = GhidraRunner(ghidra_path=str(install))

    with pytest.raises(UserFacingError):
        runner.ensure_jython_available()
