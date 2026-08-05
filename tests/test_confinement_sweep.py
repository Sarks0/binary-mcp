"""
Second-pass confinement sweep: F-18, the F-8 *ordering* class, and F-5.

The first remediation pass added a confinement check to
``sanitize_binary_path`` and validated session IDs in one of the two session
managers. An adversarial review found the pass incomplete in three ways, and
every test here pins one of those gaps shut:

* **F-18 (HIGH)** -- ``extract_python_packed`` passed ``output_dir`` through
  completely unvalidated. The analyzer then did
  ``Path(output_dir).mkdir(parents=True, exist_ok=True)`` and wrote archive
  members into it, so the MODEL chose the destination and the SAMPLE chose the
  filenames and bytes. Only traversal *within* ``output_dir`` was blocked.

* **F-8 ordering** -- several tools touched the raw path before any check:
  ``analyze_binary`` asked the cache and the compatibility checker about it,
  ``check_binary`` parsed its headers with no confinement at all, ``load_pdb``
  handed it to the symbol fetcher (which reads the file *and then makes a
  network request*), ``start_analysis_session`` / ``find_related_sessions``
  hashed it, and the ``log_to_session`` decorator hashed it before the tool
  body ran. A check that happens after the read protects nothing, so these
  tests assert the reads never happen -- not merely that the call fails.

* **F-5** -- the identical unvalidated ``store_dir / f"{session_id}..."``
  construction in ``engines/static/ghidra/analysis_session.py`` was never
  swept, and the session tools reported a malformed ID as "not found" /
  "Failed to delete", hiding the real reason.

Each ordering test uses a recorder that captures what it was handed, so a
regression shows up as "the cache was asked about /outside/secret.bin" rather
than as a vague assertion failure.
"""

import sys
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from src.engines.static.ghidra.analysis_session import AnalysisSession
from src.utils.security import (
    ENV_ALLOW_ANY_PATH,
    ENV_ALLOW_HARDLINKS,
    ENV_ALLOWED_DIRS,
    ENV_REQUIRE_CONFINEMENT,
    reset_confinement_warning,
)

TRAVERSAL_IDS = (
    "../../../../tmp/pwned",
    "..",
    "not-a-uuid",
    "12345678-1234-1234-1234-123456789012/../../etc/passwd",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def quarantine(tmp_path, monkeypatch):
    """
    Point the real default allow-list at a controlled directory.

    Same approach as tests/test_path_confinement.py: patch the inputs to
    ``default_quarantine_dirs()`` rather than stubbing it, so the production
    policy function is what decides, and ``tmp_path/outside`` is genuinely out
    of bounds even though it lives under the system temp dir.
    """
    q = tmp_path / "quarantine"
    q.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(q))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.delenv("BINARY_CACHE_DIR", raising=False)
    monkeypatch.delenv(ENV_ALLOWED_DIRS, raising=False)
    monkeypatch.delenv(ENV_REQUIRE_CONFINEMENT, raising=False)
    monkeypatch.delenv(ENV_ALLOW_ANY_PATH, raising=False)
    monkeypatch.delenv(ENV_ALLOW_HARDLINKS, raising=False)
    reset_confinement_warning()
    return q


class _ToolProxy:
    """
    Attribute proxy over ``src.server`` that unwraps FastMCP tool objects.

    ``@app.tool()`` returns a ``FunctionTool``, which is not callable, so
    ``server.delete_session(...)`` would raise TypeError. Other test modules
    dodge this by stubbing the whole ``fastmcp`` module in ``sys.modules``
    before importing the server -- but that stub is global and leaks between
    files, so whether a tool is a plain function here would depend on test
    ORDER. Unwrapping ``.fn`` works under both regimes. Attribute writes are
    forwarded to the real module so ``monkeypatch.setattr(server, ...)``
    still patches the server, not the proxy.
    """

    def __init__(self, module):
        object.__setattr__(self, "_module", module)

    def __getattr__(self, name):
        attr = getattr(self._module, name)
        return getattr(attr, "fn", attr)

    def __setattr__(self, name, value):
        setattr(self._module, name, value)

    def __delattr__(self, name):
        delattr(self._module, name)


@pytest.fixture
def server(tmp_path_factory, monkeypatch):
    """
    Import ``src.server`` with Ghidra detection stubbed.

    ``runner.py`` demands a real Ghidra install (or GHIDRA_HOME) at import
    time, so CI needs the fake tree. Matches the fixture in
    tests/test_cache_cleanup.py.
    """
    fake_ghidra = tmp_path_factory.mktemp("ghidra_home")
    (fake_ghidra / "support").mkdir()
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    monkeypatch.setenv("GHIDRA_HOME", str(fake_ghidra))
    sys.modules.pop("src.server", None)
    import src.server as server_mod

    return _ToolProxy(server_mod)


@pytest.fixture
def outside_binary(tmp_path):
    """A perfectly valid PE-looking file that is simply out of bounds."""
    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)
    f = outside / "secret.bin"
    f.write_bytes(b"MZ\x90\x00" + b"\x00" * 128)
    return f


class Recorder:
    """Callable that records every invocation instead of doing the work."""

    def __init__(self, result=None):
        self.calls: list[tuple] = []
        self.result = result

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.result

    @property
    def paths(self) -> list[str]:
        return [str(a[0]) for a, _ in self.calls if a]


def _disable_auto_session(server, monkeypatch):
    """Keep the session manager out of tests that are not about it."""
    monkeypatch.setattr(server.session_manager, "auto_session_enabled", False)


# ---------------------------------------------------------------------------
# F-18: extraction destination is confined
# ---------------------------------------------------------------------------


def _py2exe_sample(path: Path) -> Path:
    """An MZ stub with a py2exe-looking ZIP overlay containing one .pyc."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("payload.pyc", b"\x00" * 32)
    path.write_bytes(b"MZ\x90\x00" + b"py2exe" + b"\x00" * 64 + buf.getvalue())
    return path


@pytest.fixture
def extraction_root(server, tmp_path, monkeypatch):
    """Redirect the extraction root (it is computed from $HOME at import)."""
    root = tmp_path / "quarantine" / "extract_root"
    monkeypatch.setattr(server, "EXTRACTION_OUTPUT_DIR", root)
    return root


def test_extraction_refuses_absolute_output_dir_outside_root(
    server, quarantine, extraction_root, tmp_path, monkeypatch
):
    """
    F-18: the model must not be able to aim a sample's own filenames at an
    arbitrary directory (a Startup folder, ~/.config/autostart, a cron dir).
    """
    _disable_auto_session(server, monkeypatch)
    sample = _py2exe_sample(quarantine / "packed.exe")
    evil = tmp_path / "startup"

    result = server.extract_python_packed(
        binary_path=str(sample), output_dir=str(evil), packer_type="py2exe"
    )

    # Assert the SECURITY property, not the wording. The previous assertion
    # pinned "must be within", which was the leaky spelling: that message
    # interpolated the resolved extraction root (a Path.home()-derived
    # directory) straight back to the model. Routing this handler through
    # safe_path_error removed the host path, so a test that demanded the old
    # string was pinning the leak in place.
    assert "Invalid path" in result or "outside the directories" in result
    assert str(extraction_root) not in result, "refusal must not echo host layout"
    assert str(evil) not in result, "refusal must not echo the requested path"
    assert not evil.exists(), "the refused destination must not be created"


def test_extraction_refuses_traversal_output_dir(
    server, quarantine, extraction_root, tmp_path, monkeypatch
):
    """Relative traversal out of the extraction root is refused too."""
    _disable_auto_session(server, monkeypatch)
    sample = _py2exe_sample(quarantine / "packed.exe")

    result = server.extract_python_packed(
        binary_path=str(sample),
        output_dir="../../../../escape",
        packer_type="py2exe",
    )

    assert "Invalid path" in result or "outside the directories" in result
    assert str(extraction_root) not in result, "refusal must not echo host layout"
    assert not (tmp_path / "escape").exists()


def test_extraction_refuses_symlinked_output_dir(
    server, quarantine, extraction_root, tmp_path, monkeypatch
):
    """A symlink planted inside the root cannot redirect the extraction."""
    _disable_auto_session(server, monkeypatch)
    sample = _py2exe_sample(quarantine / "packed.exe")
    extraction_root.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (extraction_root / "link").symlink_to(elsewhere)

    result = server.extract_python_packed(
        binary_path=str(sample), output_dir="link/out", packer_type="py2exe"
    )

    assert "Error" in result or "must be within" in result
    assert not (elsewhere / "out").exists()


def test_extraction_into_root_still_works_end_to_end(
    server, quarantine, extraction_root, monkeypatch
):
    """
    The legitimate flow is unchanged: a relative destination is created inside
    the extraction root and the sample's files land there.
    """
    _disable_auto_session(server, monkeypatch)
    sample = _py2exe_sample(quarantine / "packed.exe")

    result = server.extract_python_packed(
        binary_path=str(sample), output_dir="sample1", packer_type="py2exe"
    )

    assert "Successfully extracted" in result
    extracted = extraction_root / "sample1" / "payload.pyc"
    assert extracted.is_file()
    assert str(extraction_root / "sample1") in result


def test_python_packer_read_only_tools_still_work_in_bounds(
    server, quarantine, monkeypatch
):
    """
    Control for the sibling tools audited alongside F-18: they take no output
    directory, but they were switched to the same confinement chokepoint, so
    prove the ordinary read-only flow still works.
    """
    _disable_auto_session(server, monkeypatch)
    sample = _py2exe_sample(quarantine / "packed.exe")
    pyc = quarantine / "mod.pyc"
    pyc.write_bytes(b"\x0d\x0d\x00\x00" + b"\x00" * 32)

    assert "py2exe" in server.detect_python_packer(binary_path=str(sample)).lower()
    listing = server.list_python_archive_contents(binary_path=str(sample))
    assert "payload.pyc" in listing
    assert "PYC FILE ANALYSIS" in server.analyze_pyc_file(pyc_path=str(pyc))


def test_extraction_refuses_out_of_bounds_binary(
    server, quarantine, extraction_root, outside_binary, monkeypatch
):
    """Control: the *input* side of the same tool stays confined."""
    _disable_auto_session(server, monkeypatch)
    result = server.extract_python_packed(
        binary_path=str(outside_binary), output_dir="sample1", packer_type="py2exe"
    )
    assert "Error" in result
    assert not (extraction_root / "sample1").exists()


# ---------------------------------------------------------------------------
# F-8 ordering: nothing touches the raw path before confinement
# ---------------------------------------------------------------------------


def test_analyze_binary_does_not_consult_cache_before_confinement(
    server, quarantine, outside_binary, monkeypatch
):
    """
    F-8 ordering: ``cache.get_cached(binary_path)`` and
    ``compatibility_checker.check_compatibility(binary_path)`` both ran on the
    RAW argument, before ``get_analysis_context`` validated it. Both open the
    file. The refusal that came afterwards was worthless -- the read had
    already happened and its result had already been reported.
    """
    _disable_auto_session(server, monkeypatch)
    get_cached = Recorder(result=None)
    check_compat = Recorder()
    monkeypatch.setattr(server.cache, "get_cached", get_cached)
    monkeypatch.setattr(
        server.compatibility_checker, "check_compatibility", check_compat
    )
    ctx = Recorder(result={})
    monkeypatch.setattr(server, "get_analysis_context", ctx)

    result = server.analyze_binary(binary_path=str(outside_binary))

    assert "Error" in result
    assert get_cached.calls == [], (
        f"cache was handed an unconfined path: {get_cached.paths}"
    )
    assert check_compat.calls == [], (
        f"compatibility checker was handed an unconfined path: {check_compat.paths}"
    )
    assert ctx.calls == []


def test_analyze_binary_in_bounds_still_reaches_the_cache(
    server, quarantine, monkeypatch
):
    """Control for the test above: the legitimate flow is untouched."""
    _disable_auto_session(server, monkeypatch)
    sample = quarantine / "sample.bin"
    sample.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)

    get_cached = Recorder(result=None)
    monkeypatch.setattr(server.cache, "get_cached", get_cached)
    monkeypatch.setattr(
        server.compatibility_checker, "check_compatibility", Recorder()
    )
    monkeypatch.setattr(
        server,
        "get_analysis_context",
        Recorder(result={"metadata": {"name": "sample.bin"}, "functions": []}),
    )

    result = server.analyze_binary(binary_path=str(sample))

    assert "Binary Analysis Complete" in result
    # And the cache saw the RESOLVED path, not the raw argument.
    assert get_cached.paths == [str(sample.resolve())]


def test_decompile_function_does_not_peek_the_cache_unconfined(
    server, quarantine, outside_binary, monkeypatch
):
    """
    ``decompile_function`` peeks at the cache (which hashes the file) and only
    falls through to ``get_analysis_context`` -- the one place that validated
    -- when the peek misses. So the validated path was the *uncommon* one.
    """
    _disable_auto_session(server, monkeypatch)
    get_cached = Recorder(result=None)
    monkeypatch.setattr(server.cache, "get_cached", get_cached)
    ctx = Recorder(result={"functions": []})
    monkeypatch.setattr(server, "get_analysis_context", ctx)

    result = server.decompile_function(
        binary_path=str(outside_binary), function_name="main"
    )

    assert "Error" in result
    assert get_cached.calls == [], f"cache peek saw {get_cached.paths}"
    assert ctx.calls == []


def test_get_notes_does_not_hash_unconfined_path(
    server, quarantine, outside_binary, monkeypatch
):
    """
    ``cache.read_notes`` hashes the binary to find its side-car, and the
    ``address``-less call path never reached any validator at all.
    """
    _disable_auto_session(server, monkeypatch)
    read_notes = Recorder(result=[])
    monkeypatch.setattr(server.cache, "read_notes", read_notes)

    result = server.get_notes(binary_path=str(outside_binary))

    assert "Error" in result
    assert read_notes.calls == [], f"notes side-car lookup saw {read_notes.paths}"


def test_check_binary_confines_before_parsing_headers(
    server, quarantine, outside_binary, monkeypatch
):
    """
    ``check_binary`` had no confinement at all: it did a bare
    ``Path(binary_path).exists()`` and then parsed the file's headers. That
    made it the cheapest oracle in the server -- existence, format, bitness and
    .NET-ness for any file the process can read.
    """
    check_compat = Recorder()
    monkeypatch.setattr(
        server.compatibility_checker, "check_compatibility", check_compat
    )

    result = server.check_binary(binary_path=str(outside_binary))

    assert "Error" in result
    assert check_compat.calls == [], (
        f"check_binary read an unconfined path: {check_compat.paths}"
    )


def test_check_binary_out_of_bounds_is_not_an_existence_oracle(
    server, quarantine, tmp_path, outside_binary, monkeypatch
):
    """A present and an absent out-of-bounds path must answer identically."""
    monkeypatch.setattr(
        server.compatibility_checker, "check_compatibility", Recorder()
    )
    present = server.check_binary(binary_path=str(outside_binary))
    absent = server.check_binary(binary_path=str(tmp_path / "outside" / "nope.bin"))

    # Reference IDs differ per call; compare the part that carries meaning.
    assert present.splitlines()[0] == absent.splitlines()[0]


def test_load_pdb_confines_before_symbol_fetch(
    server, quarantine, outside_binary, monkeypatch
):
    """
    ``fetch_pdb`` opens the binary, parses its CodeView (RSDS) record and then
    makes a NETWORK request derived from what it read. It ran on the raw path.
    """
    from src.utils import pdb_fetcher

    fetch = Recorder()
    monkeypatch.setattr(pdb_fetcher, "fetch_pdb", fetch)
    _disable_auto_session(server, monkeypatch)

    result = server.load_pdb(binary_path=str(outside_binary))

    assert "Error" in result or "not found" in result
    assert fetch.calls == [], "symbol fetcher was handed an unconfined path"


def test_log_to_session_decorator_does_not_hash_unconfined_path(
    server, quarantine, outside_binary, monkeypatch
):
    """
    The decorator called ``ensure_session(binary_path=...)`` BEFORE the tool
    body. ``ensure_session`` opens and SHA256s the file to correlate sessions,
    then writes the path and hash into the session store -- so a decorated tool
    called with /etc/shadow read it, hashed it and persisted the result before
    anything checked whether the path was allowed.
    """
    ensure = Recorder(result="fake-session")
    monkeypatch.setattr(server.session_manager, "auto_session_enabled", True)
    monkeypatch.setattr(server.session_manager, "ensure_session", ensure)
    monkeypatch.setattr(server.session_manager, "active_session_id", None)

    server.detect_python_packer(binary_path=str(outside_binary))

    assert ensure.calls == [], "auto-session hashed an unconfined path"


def test_log_to_session_decorator_still_starts_sessions_in_bounds(
    server, quarantine, monkeypatch
):
    """Control: auto-session keeps working for allowed paths."""
    sample = quarantine / "sample.bin"
    sample.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    ensure = Recorder(result="fake-session")
    monkeypatch.setattr(server.session_manager, "auto_session_enabled", True)
    monkeypatch.setattr(server.session_manager, "ensure_session", ensure)
    monkeypatch.setattr(server.session_manager, "active_session_id", None)

    server.detect_python_packer(binary_path=str(sample))

    assert len(ensure.calls) == 1
    assert ensure.calls[0][1]["binary_path"] == str(sample.resolve())


def test_start_analysis_session_confines_before_hashing(
    server, quarantine, outside_binary, monkeypatch
):
    """``start_session`` hashes the binary; that must not happen unconfined."""
    start = Recorder(result="fake-session")
    monkeypatch.setattr(server.session_manager, "start_session", start)

    result = server.start_analysis_session(
        binary_path=str(outside_binary), name="probe"
    )

    assert "Error" in result
    assert start.calls == []


def test_find_related_sessions_confines_before_hashing(
    server, quarantine, outside_binary, monkeypatch
):
    """Same hash-the-file problem, plus a "do you have this file?" oracle."""
    find = Recorder(result=[])
    monkeypatch.setattr(server.session_manager, "find_sessions_for_binary", find)

    result = server.find_related_sessions(binary_path=str(outside_binary))

    assert "Error" in result
    assert find.calls == []


def test_hardlinked_sample_is_refused_by_the_tool_layer(
    server, quarantine, tmp_path, monkeypatch
):
    """
    End to end: the hard-link bypass is refused where a caller would hit it,
    not just in the validator's unit tests.
    """
    import os

    if os.name == "nt":
        pytest.skip("st_nlink is not a reliable hard-link signal on Windows")

    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)
    secret = outside / "secret"
    secret.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    link = quarantine / "sample.bin"
    os.link(secret, link)

    check_compat = Recorder()
    monkeypatch.setattr(
        server.compatibility_checker, "check_compatibility", check_compat
    )

    result = server.check_binary(binary_path=str(link))

    assert "Error" in result
    assert check_compat.calls == []


# ---------------------------------------------------------------------------
# F-5: the second, unswept session store
# ---------------------------------------------------------------------------


@pytest.fixture
def ghidra_sessions(tmp_path):
    return AnalysisSession(store_dir=str(tmp_path / "sessions"))


@pytest.mark.parametrize("payload", TRAVERSAL_IDS)
def test_ghidra_session_paths_reject_bad_ids(ghidra_sessions, payload):
    """
    The same construction unified_session.py was fixed for, in the copy the
    first pass missed: ``store_dir / f"{session_id}.session.json.gz"``.
    """
    with pytest.raises(ValueError, match="Invalid session ID format"):
        ghidra_sessions._get_session_path(payload)
    with pytest.raises(ValueError, match="Invalid session ID format"):
        ghidra_sessions._get_metadata_path(payload)


def test_ghidra_session_traversal_touches_nothing_outside_store(
    ghidra_sessions, tmp_path
):
    """End to end: no create, no read, no unlink outside the store."""
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.meta.json"
    victim.write_text("{}")

    payload = "../outside/victim"
    for call in (
        lambda: ghidra_sessions.save_session(payload),
        lambda: ghidra_sessions.get_metadata(payload),
        lambda: ghidra_sessions.get_session(payload),
        lambda: ghidra_sessions.get_section(payload, "summary"),
        lambda: ghidra_sessions.delete_session(payload),
    ):
        with pytest.raises(ValueError):
            call()

    assert victim.exists(), "traversal payload deleted a file outside the store"
    assert list(ghidra_sessions.store_dir.iterdir()) == []


def test_ghidra_session_round_trip_still_works(ghidra_sessions, tmp_path):
    """Legitimate flow: start -> save -> read metadata -> delete."""
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)

    session_id = ghidra_sessions.start_session(str(binary), name="round trip")
    ghidra_sessions.log_tool_call("get_strings", {"binary_path": str(binary)}, "out")

    assert ghidra_sessions.save_session() is True
    assert ghidra_sessions.get_metadata(session_id)["name"] == "round trip"
    assert ghidra_sessions.get_session(session_id)["tool_calls"]
    assert ghidra_sessions.delete_session(session_id) is True
    assert ghidra_sessions.delete_session(session_id) is False


def test_ghidra_session_uppercase_uuid_is_accepted(ghidra_sessions, tmp_path):
    """Normalisation, not rejection: the same UUID in caps is the same ID."""
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    session_id = ghidra_sessions.start_session(str(binary), name="caps")
    ghidra_sessions.save_session()

    assert ghidra_sessions.get_metadata(session_id.upper()) is not None


# ---------------------------------------------------------------------------
# F-5 (UX): a malformed ID must not be reported as a missing/failed session
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", TRAVERSAL_IDS)
def test_delete_session_reports_the_real_reason(server, payload):
    result = server.delete_session(session_id=payload)
    assert "Invalid session ID format" in result
    assert "not found" not in result
    assert "Failed to delete" not in result


@pytest.mark.parametrize("payload", TRAVERSAL_IDS)
def test_save_session_reports_the_real_reason(server, payload):
    result = server.save_session(session_id=payload)
    assert "Invalid session ID format" in result
    assert "Failed to save" not in result


@pytest.mark.parametrize("payload", TRAVERSAL_IDS)
def test_session_readers_report_the_real_reason(server, payload):
    for result in (
        server.get_session_summary(session_id=payload),
        server.load_full_session(session_id=payload),
        server.load_session_section(session_id=payload, section="summary"),
    ):
        assert "Invalid session ID format" in result
        assert "not found" not in result


def test_valid_but_absent_session_id_still_says_not_found(server):
    """
    Control: the two answers must stay distinguishable in BOTH directions. A
    well-formed ID with no session behind it is still "not found".
    """
    result = server.delete_session(session_id="123e4567-e89b-42d3-a456-426614174000")
    assert "not found" in result
    assert "Invalid session ID format" not in result


class TestCarveOutputDirAnchoring:
    """A relative output_dir must not land in the server's install tree.

    Path.absolute() resolves a relative path against the process CWD, which
    for a stdio MCP server is the directory the client launched it from -- in
    the documented configs, the binary-mcp install tree. So
    extract_embedded_binaries(output_dir="out") wrote bytes CARVED OUT OF THE
    SAMPLE into the server's own source directory, and the system-directory
    denylist never saw a prefix to object to.
    """

    def _clean_env(self, monkeypatch):
        for var in (
            "BINARY_MCP_ALLOWED_DIRS",
            "BINARY_MCP_ALLOW_ANY_PATH",
            "BINARY_MCP_CARVE_DIR",
        ):
            monkeypatch.delenv(var, raising=False)

    def test_relative_dir_anchors_to_the_carve_cache(self, monkeypatch):
        from src.utils.carving import _default_carve_dir, _validate_output_dir

        self._clean_env(monkeypatch)
        resolved = _validate_output_dir(Path("extracted"))

        assert str(resolved).startswith(str(_default_carve_dir()))
        assert str(Path.cwd()) not in str(resolved)

    def test_server_artifact_dirs_are_not_blocked_by_the_denylist(self, monkeypatch):
        """The denylist blocks $HOME wholesale, which contains the carve cache.
        Without the artifact-dir exemption the tool's own DEFAULT output
        location was refused -- the write-then-refuse class again."""
        from src.utils.carving import _default_carve_dir, _validate_output_dir

        self._clean_env(monkeypatch)
        assert _validate_output_dir(_default_carve_dir())

    @pytest.mark.parametrize(
        "target",
        [".ssh", ".config/autostart", ".local/bin", "Desktop", ""],
    )
    def test_sensitive_home_paths_are_refused(self, target, monkeypatch):
        """A NON-ROOT home, which is what exposed this.

        The first version of this test used the real Path.home(). It passed on
        Linux for an incidental reason -- CI and local runs are root, so home
        is /root, which happened to sit on the old system-directory denylist.
        On the macOS runner home is /Users/runner and all three of these were
        ALLOWED: the tool would write bytes carved out of a sample into
        ~/.config/autostart (login persistence), ~/.local/bin (on PATH) or
        ~/.ssh. Pinning a synthetic home makes the check mean the same thing
        on every platform and as any user.
        """
        from src.utils.carving import _validate_output_dir
        from src.utils.structured_errors import StructuredBaseError

        self._clean_env(monkeypatch)
        # Deliberately NOT under tmp_path: the system temp directory is the one
        # location this validator permits without an allow-list, so a fake home
        # inside it would be allowed for the right reason and prove nothing.
        fake_home = Path("/synthetic-home/analyst")
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setenv("USERPROFILE", str(fake_home))

        with pytest.raises(StructuredBaseError):
            _validate_output_dir(fake_home / target if target else fake_home)

    @pytest.mark.parametrize("target", ["/etc", "/usr/local/bin"])
    def test_system_dirs_are_still_refused(self, target, monkeypatch):
        from src.utils.carving import _validate_output_dir
        from src.utils.structured_errors import StructuredBaseError

        self._clean_env(monkeypatch)
        with pytest.raises(StructuredBaseError):
            _validate_output_dir(Path(target))


class TestSymbolCacheTildeExpansion:
    """The three cache resolvers must agree on '~'.

    security.default_quarantine_dirs() and carving._default_carve_dir() both
    expand it; pdb_fetcher._default_symbol_cache() did not, so
    BINARY_MCP_SYMBOL_CACHE=~/symbols created a LITERAL '~' directory under the
    CWD while confinement allowed $HOME/symbols -- download a PDB, then refuse
    to read it back.
    """

    def test_tilde_is_expanded(self, monkeypatch):
        from src.utils.pdb_fetcher import _default_symbol_cache

        monkeypatch.setenv("BINARY_MCP_SYMBOL_CACHE", "~/sym-relocated")
        resolved = _default_symbol_cache()

        assert "~" not in str(resolved)
        assert resolved == Path.home() / "sym-relocated"

    def test_relocated_cache_is_readable_back(self, monkeypatch, tmp_path):
        from src.utils.security import sanitize_binary_path

        monkeypatch.setenv("BINARY_MCP_SYMBOL_CACHE", str(tmp_path / "syms"))
        monkeypatch.setenv("BINARY_MCP_ALLOWED_DIRS", str(tmp_path / "quarantine"))
        (tmp_path / "quarantine").mkdir()
        cache = tmp_path / "syms"
        cache.mkdir()
        pdb = cache / "x.pdb"
        pdb.write_bytes(b"MZ")

        assert sanitize_binary_path(str(pdb)) == pdb.resolve()
