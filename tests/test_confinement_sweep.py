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

import inspect
import os
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


# Fixtures


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


# F-18: extraction destination is confined


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


# F-8 ordering: nothing touches the raw path before confinement


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

    analysed = {"metadata": {"name": "sample.bin"}, "functions": []}

    class CacheReads(Recorder):
        """Miss first (so analysis runs), hit afterwards.

        analyze_binary no longer builds its summary from get_analysis_context's
        return value: it runs the analysis and then reads the result back out
        of the cache. A stub that misses forever therefore describes an
        impossible state -- analysis succeeded but wrote nothing -- and the
        tool correctly says the cache could not be read back.
        """

        def __call__(self, *args, **kwargs):
            super().__call__(*args, **kwargs)
            return None if len(self.calls) == 1 else analysed

    get_cached = CacheReads()
    monkeypatch.setattr(server.cache, "get_cached", get_cached)
    monkeypatch.setattr(
        server.compatibility_checker, "check_compatibility", Recorder()
    )
    monkeypatch.setattr(server, "get_analysis_context", Recorder(result=analysed))

    result = server.analyze_binary(binary_path=str(sample))

    assert "Binary Analysis Complete" in result
    # And the cache saw the RESOLVED path, not the raw argument -- on EVERY
    # read, including the post-analysis read-back added since this was written.
    assert get_cached.paths, "the cache was never consulted; guard is vacuous"
    assert set(get_cached.paths) == {str(sample.resolve())}


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


@pytest.fixture
def hardlinked_sample(quarantine, tmp_path):
    """
    An in-bounds hard link to an out-of-bounds inode, plus that inode.

    Shared because three tests needed the same six lines and the same skip
    reason; the previous copies drifted only in variable names. Returns
    ``(link, target)`` so a test can exercise the hard-link refusal and the
    plain out-of-bounds refusal against the same fixture.
    """
    if os.name == "nt":
        pytest.skip("the hard-link check is not enabled on Windows (see _reject_hardlinked_file)")

    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)
    target = outside / "secret"
    target.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    link = quarantine / "sample.bin"
    os.link(target, link)
    return link, target


def test_hardlinked_sample_is_refused_by_the_tool_layer(
    server, hardlinked_sample, monkeypatch
):
    """
    End to end: the hard-link bypass is refused where a caller would hit it,
    not just in the validator's unit tests.
    """
    link, _ = hardlinked_sample

    check_compat = Recorder()
    monkeypatch.setattr(
        server.compatibility_checker, "check_compatibility", check_compat
    )

    result = server.check_binary(binary_path=str(link))

    assert "Error" in result
    assert check_compat.calls == []


@pytest.mark.parametrize("tool_name", ["check_binary", "analyze_binary"])
def test_hardlink_refusal_is_not_reported_as_a_bad_path(
    server, hardlinked_sample, tmp_path, monkeypatch, tool_name
):
    """
    The refusal must say what was wrong WHERE a caller reads it.

    The test above asserts only ``"Error" in result``, which is how this
    shipped: ``analyze_binary`` and ``check_binary`` were the two handlers
    still answering a refused path with ``safe_error_message("Invalid binary
    file or path", e)``, i.e. four words and a reference ID. A hard-linked
    staging copy and a genuine confinement violation were byte-identical, so
    the link count could only be found by reading src/utils/security.py.

    Both tools now route through ``safe_path_error``, which reconstructs the
    category from the exception type -- and the type is now distinct.
    """
    _disable_auto_session(server, monkeypatch)
    link, secret = hardlinked_sample

    tool = getattr(server, tool_name)
    hardlink_result = tool(binary_path=str(link))
    # Same tool, same posture, a genuinely out-of-bounds path.
    oob_result = tool(binary_path=str(secret))

    assert "Error" in hardlink_result
    assert "Error" in oob_result

    # Distinguishable is only half of it: the refusal must still withhold host
    # layout. Without this pair, the test is satisfied by ANY two different
    # strings -- including the leaky "Access denied: ... is outside the default
    # quarantine directories (<every resolved dir>)" that tools validating via
    # get_analysis_context still return today, which interpolates the
    # Path.home()-derived allow-list and so the operator's username. Asserting
    # only "the texts differ" is what let that survive a review.
    for label, text in (("hard link", hardlink_result), ("out of bounds", oob_result)):
        assert str(tmp_path) not in text, (
            f"{tool_name} echoed host layout in its {label} refusal; the "
            f"resolved directory list belongs in the log, against the "
            f"reference ID, not in the caller's transcript"
        )

    # Reference IDs are per-call, so compare the text without them.
    def _without_reference_id(text):
        return "\n".join(
            line for line in text.splitlines() if not line.startswith("Reference ID:")
        )

    assert _without_reference_id(hardlink_result) != _without_reference_id(oob_result), (
        f"{tool_name} reports a hard-link refusal and an out-of-bounds path "
        f"with the same text, so the failure reads as 'wrong path' when the "
        f"path was accepted and the link count was not"
    )
    assert "hard link" in hardlink_result
    assert ENV_ALLOW_HARDLINKS in hardlink_result, (
        f"{tool_name} refuses the link without naming the opt-out, leaving the "
        f"caller to find it in the source"
    )
    assert "hard link" not in oob_result


# Whole-surface sweep: every tool that takes a binary_path


# Placeholders for the OTHER required arguments of each tool, so the sweep can
# call it at all. Values are deliberately boring -- the point is to reach the
# path check, which happens before any of these matter.
_SWEEP_ARGS = {
    "function_name": "main",
    "function_names": ["main"],
    "function": "main",
    "name": "sweep",
    "address": "0x1000",
    "type_name": "T",
    "pattern": "90",
    "query": "x",
    "output_path": "out.txt",
    "rule_name": "r",
    "tag": "t",
    "session_id": "00000000-0000-4000-8000-000000000000",
    # Added after the sweep was found to be silently dropping these: the
    # for/else below `break`s out for any tool whose other required argument
    # has no placeholder, so decrypt_xor, expand_callgraph and
    # extract_python_packed -- all three of which had their path arms rewritten
    # in the change that added this sweep -- were covered by nothing at all.
    "key": "41",
    "root": "main",
    "output_dir": "out",
    "note": "n",
    "new_name": "renamed",
}

# Extra OPTIONAL arguments a few tools need before they will look at the path
# at all. rename_function returns "Must provide either 'address' or 'old_name'"
# from its own argument check, which runs first, so without this the sweep
# drove it to an argument error and learned nothing about its path handling.
# Kept explicit and per-tool rather than passing every optional argument the
# sweep happens to have a value for, which would change what is under test.
_SWEEP_EXTRA_ARGS = {
    "rename_function": {"old_name": "main"},
}

# Module-level callables that take a binary_path but are not MCP tools, so the
# sweep's "every tool returns a refusal string" contract does not apply: the
# validators raise by design, and these helpers are called with a cache or a
# resolved address by their real callers.
_SWEEP_NON_TOOL_HELPERS = {
    "auto_mark_reviewed",
    "find_table_base_refs",
}

# Module-level helpers that happen to take a binary_path but are not MCP tools.
# They are the validators themselves (and pdb_fetcher.auto_fetch_pdb, a helper
# imported into the server namespace), so they RAISE rather than return a
# refusal string -- which is the contract the tools below are built on.
_SWEEP_NOT_TOOLS = {
    "sanitize_binary_path",
    "confine_binary_path",
    "get_analysis_context",
    "auto_fetch_pdb",
}


def _binary_path_tools(server):
    """
    Every callable in src.server taking ``binary_path`` we can drive.

    Returns ``(found, skipped)``. The skipped list is the point: this used to
    `break` out of the argument loop and move on, so a tool whose other
    required argument had no placeholder simply vanished from the sweep. Seven
    did, three of them modified by the change that added the sweep, and
    nothing failed -- the guard test only checked a floor count and four
    hardcoded names. Handing the list back lets the guard assert it.
    """
    found = []
    skipped = []
    for name in sorted(dir(server._module)):
        if name.startswith("_") or name in _SWEEP_NOT_TOOLS:
            continue
        fn = getattr(server, name)
        if not callable(fn) or inspect.isclass(fn):
            continue
        try:
            signature = inspect.signature(fn)
        except (TypeError, ValueError):
            continue
        if "binary_path" not in signature.parameters:
            continue
        kwargs = {}
        unsupplied = [
            pname
            for pname, param in signature.parameters.items()
            if pname != "binary_path"
            and param.default is inspect.Parameter.empty
            and pname not in _SWEEP_ARGS
        ]
        if unsupplied:
            skipped.append((name, unsupplied))
            continue
        for pname, param in signature.parameters.items():
            if pname == "binary_path" or param.default is not inspect.Parameter.empty:
                continue
            kwargs[pname] = _SWEEP_ARGS[pname]
        kwargs.update(_SWEEP_EXTRA_ARGS.get(name, {}))
        found.append((name, fn, kwargs))
    return found, skipped


def test_the_sweep_finds_the_tools_it_claims_to(server):
    """
    Guard the sweep itself: silent discovery failure would assert nothing.

    The ``server`` fixture is a _ToolProxy, and ``dir()`` on the proxy returns
    nothing -- an earlier version of this sweep enumerated the proxy instead
    of the module and cheerfully reported that zero tools took a binary_path.
    """
    tools, skipped = _binary_path_tools(server)
    names = {name for name, _, _ in tools}
    assert len(tools) >= 20, f"sweep found only {len(tools)} tools: {sorted(names)}"
    for expected in ("analyze_binary", "check_binary", "get_functions", "get_xrefs"):
        assert expected in names, f"sweep no longer reaches {expected}"

    # Nothing may drop out silently. A floor count and four names could not
    # see it when seven tools vanished for want of an argument placeholder --
    # add a required argument to any swept tool and it leaves the sweep
    # without failing anything. Anything genuinely not a tool is named in
    # _SWEEP_NON_TOOL_HELPERS, so the remainder has to be empty.
    unexplained = [
        (name, args) for name, args in skipped
        if name not in _SWEEP_NON_TOOL_HELPERS
    ]
    assert not unexplained, (
        "these binary_path tools are silently outside the sweep; add a "
        "placeholder to _SWEEP_ARGS for each argument listed, or name the "
        "callable in _SWEEP_NON_TOOL_HELPERS if it is not a tool:\n  "
        + "\n  ".join(f"{n}: needs {a}" for n, a in unexplained)
    )


@pytest.fixture
def refused_paths(quarantine, tmp_path):
    """
    Every shape of refusal a tool can be handed, as ``(label, path)``.

    The hard-link case is appended only on POSIX, so the sweeps that use this
    still run on Windows for the other two. An earlier version took the
    hard-link fixture directly, which made the whole sweep skip on Windows --
    throwing away out-of-bounds and missing-file leak coverage on the one
    platform where the hard-link check is deliberately absent, and so the one
    platform where the remaining refusals carry more of the weight.
    """
    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)
    target = outside / "secret"
    target.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)

    adir = quarantine / "a-directory"
    adir.mkdir(exist_ok=True)

    cases = [
        ("out of bounds", target),
        ("missing", quarantine / "nope.bin"),
        # The directory case is the reason this list exists as a fixture. Its
        # absence is how a live leak survived this very sweep: a directory is
        # refused by sanitize_binary_path with ValueError, which was not in
        # ProjectCache._REFUSALS, so the refusal was laundered into a cache
        # miss, a Ghidra job was submitted for a directory, and the job
        # record's raw error text came back to the caller.
        ("directory", adir),
    ]
    if os.name != "nt":
        link = quarantine / "sample.bin"
        os.link(target, link)
        cases.append(("hard link", link))
    return cases


def test_no_tool_leaks_host_layout_when_it_refuses_a_path(
    server, refused_paths, tmp_path, monkeypatch
):
    """
    No tool may echo the resolved allow-list, whatever refuses the path.

    This is the structural form of the F-10 guarantee, and it exists because
    the per-handler form was not enough. ``decompile_functions`` leaked the
    whole quarantine list -- ``Path.home()``-derived, so the operator's
    username -- through a chain no single handler owned: ``get_cached``
    swallowed the refusal into a cache miss, the tool read that as "analyse
    it", a job was submitted, ``get_analysis_context`` raised inside the job
    work function, the job record stored the refusal's text, and
    ``_run_or_degrade`` returned it as ``f"Error: {reason}"``. Every link was
    locally defensible. Asserting on the whole surface is what catches that.
    """
    _disable_auto_session(server, monkeypatch)

    offenders = []
    for name, fn, kwargs in _binary_path_tools(server)[0]:
        for label, path in refused_paths:
            try:
                result = str(fn(binary_path=str(path), **kwargs))
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                offenders.append(f"{name} [{label}] raised {type(exc).__name__}")
                continue
            if str(tmp_path) in result:
                offenders.append(f"{name} [{label}] echoed host layout")

    assert not offenders, (
        "tools disclosed host layout, or raised instead of returning a "
        "refusal:\n  " + "\n  ".join(offenders)
    )


def test_every_tool_names_the_category_of_a_confinement_refusal(
    server, refused_paths, monkeypatch
):
    """
    A refusal has to say WHICH refusal it was, not just that one happened.

    The B3 field report: a hard-linked staging copy and an out-of-bounds path
    came back as the same four words plus a reference ID, so the failure read
    as "wrong path" when the path had been accepted and only the link count
    refused. Fixing the two handlers named in that report left ~25 tools still
    collapsing, which is why this asserts over the surface instead.

    Tools reach this guarantee two ways and the test does not care which: an
    explicit ``except (PathTraversalError, FileSizeError)`` arm calling
    safe_path_error, or the catch-all, since safe_tool_error routes those two
    types through safe_path_error precisely so a tool cannot regress by
    forgetting an arm.
    """
    _disable_auto_session(server, monkeypatch)
    cases = dict(refused_paths)

    vague = []
    for name, fn, kwargs in _binary_path_tools(server)[0]:
        oob_result = str(fn(binary_path=str(cases["out of bounds"]), **kwargs))
        if "outside the directories" not in oob_result:
            vague.append(f"{name}: out-of-bounds refusal does not say so")

        # Only on POSIX: the hard-link check is not enabled on Windows, so
        # there is no hard-link refusal to name there. The out-of-bounds half
        # above does not depend on it and now runs everywhere -- taking the
        # hard-link fixture directly made this whole test skip on Windows,
        # which is the mistake refused_paths was introduced to fix and which
        # was fixed in only one of the two sweeps the first time.
        if "hard link" not in cases:
            continue
        hardlink_result = str(fn(binary_path=str(cases["hard link"]), **kwargs))
        if "hard link" not in hardlink_result:
            vague.append(f"{name}: hard-link refusal does not mention the link")
        if hardlink_result == oob_result:
            vague.append(f"{name}: the two refusals are identical")

    assert not vague, (
        "refusals that do not name their own category:\n  " + "\n  ".join(vague)
    )


# F-5: the second, unswept session store


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


# F-5 (UX): a malformed ID must not be reported as a missing/failed session


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
