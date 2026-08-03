"""
Tests for path-confinement hardening (audit items H8, H9, M13, P4, F-8, F-13,
F-14).

Before the first round of this change, ``sanitize_binary_path`` only enforced
directory confinement when the *caller* passed ``allowed_dirs``. Almost every
tool entry point called it bare, so an operator who set
``BINARY_MCP_ALLOWED_DIRS`` still got arbitrary-file reads handed to
Ghidra/ILSpy (H9), and an unset config silently meant "allow any" with no
signal (M13). The validator now resolves the configured allow-list itself and
can fail closed, so confinement is applied uniformly without touching ~30 call
sites.

F-8 closed the remaining hole: "unset" no longer means "unrestricted". With no
``BINARY_MCP_ALLOWED_DIRS`` the server confines analysis to
``default_quarantine_dirs()``, and operators who genuinely want the old
behaviour set ``BINARY_MCP_ALLOW_ANY_PATH=1``.

F-13/F-14 cover ``sanitize_output_path``: relative output paths anchor to the
allowed directory instead of the process CWD, and the symlink-component check
runs on the pre-resolution path so it can actually fire.

``read_full`` also read whole files into memory unbounded (H8); it now rejects
oversized files.
"""

import os
import tempfile
from pathlib import Path

import pytest

from src.utils.binary_reader import BinaryReader
from src.utils.security import (
    ENV_ALLOW_ANY_PATH,
    ENV_ALLOW_HARDLINKS,
    ENV_ALLOWED_DIRS,
    ENV_REQUIRE_CONFINEMENT,
    PathTraversalError,
    default_quarantine_dirs,
    reset_confinement_warning,
    sanitize_binary_path,
    sanitize_output_dir,
    sanitize_output_path,
)

posix_only = pytest.mark.skipif(
    os.name == "nt",
    reason="st_nlink is not a reliable hard-link signal on Windows",
)


@pytest.fixture
def quarantine(tmp_path, monkeypatch):
    """
    Redirect the *real* default allow-list at a controlled directory.

    ``default_quarantine_dirs()`` includes the system temp dir, which is where
    pytest's ``tmp_path`` lives -- so without this, every fixture path would sit
    inside the default allow-list and the denial paths would be untestable.
    Patching ``tempfile.gettempdir`` and ``Path.home`` exercises the production
    function rather than a stub, while leaving ``tmp_path/outside`` genuinely
    out of bounds.
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

# -- H9 / P4: confinement is applied even when the caller omits allowed_dirs --


def test_confinement_applied_when_caller_omits_allowed_dirs(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    inside_file = allowed / "sample.bin"
    inside_file.write_bytes(b"MZ\x00\x00")
    outside_file = outside / "secret.bin"
    outside_file.write_bytes(b"MZ\x00\x00")

    monkeypatch.setenv("BINARY_MCP_ALLOWED_DIRS", str(allowed))
    monkeypatch.delenv("BINARY_MCP_REQUIRE_CONFINEMENT", raising=False)

    # Caller passes NO allowed_dirs -- confinement must still apply.
    assert sanitize_binary_path(str(inside_file)) == inside_file.resolve()
    with pytest.raises(PathTraversalError):
        sanitize_binary_path(str(outside_file))


def test_explicit_allowed_dirs_still_enforced(tmp_path, monkeypatch):
    """Control: an explicitly-passed allow-list keeps working unchanged."""
    monkeypatch.delenv("BINARY_MCP_ALLOWED_DIRS", raising=False)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside_file = tmp_path / "b.bin"
    outside_file.write_bytes(b"MZ\x00\x00")
    with pytest.raises(PathTraversalError):
        sanitize_binary_path(str(outside_file), allowed_dirs=[allowed])


# -- F-8: unconfigured is confined-by-default, not open-by-default --------


def test_unconfigured_confines_to_quarantine_dirs(tmp_path, quarantine):
    """
    F-8: with nothing configured, analysis is confined -- not unrestricted.

    This test previously asserted the opposite (``test_unconfigured_allows_by_
    default``). That was the finding: a stdio MCP server launched from a client
    config usually has neither env var set, so the model could hand
    ``analyze_binary`` any path on the host.
    """
    inside = quarantine / "sample.bin"
    inside.write_bytes(b"MZ\x00\x00")
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside = outside_dir / "secret.bin"
    outside.write_bytes(b"MZ\x00\x00")

    # Inside a default quarantine dir: still works, no configuration needed.
    assert sanitize_binary_path(str(inside)) == inside.resolve()

    # Anywhere else: denied by default.
    with pytest.raises(PathTraversalError):
        sanitize_binary_path(str(outside))


def test_unconfigured_denial_names_the_env_var(tmp_path, quarantine):
    """The denial must be self-explanatory: env var name + example value."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside = outside_dir / "secret.bin"
    outside.write_bytes(b"MZ\x00\x00")

    with pytest.raises(PathTraversalError) as exc:
        sanitize_binary_path(str(outside))

    message = str(exc.value)
    assert ENV_ALLOWED_DIRS in message
    # An example value, not just the variable name -- an operator must be able
    # to copy the fix out of the error.
    assert f"{ENV_ALLOWED_DIRS}=" in message
    # And the documented escape hatch for genuinely unrestricted access.
    assert ENV_ALLOW_ANY_PATH in message
    # Plus the directories that *are* permitted, so the user can see the gap.
    assert str(quarantine) in message


def test_default_quarantine_dirs_cover_temp_but_not_system_files(quarantine):
    """The default allow-list must be usable but must not cover secrets."""
    dirs = default_quarantine_dirs()
    assert quarantine in dirs, "system temp dir must be analysable by default"

    # The paths F-8 was actually about must not be reachable.
    for secret in ("/etc/shadow", "/root/.ssh/id_rsa", "/proc/self/environ"):
        assert not any(
            Path(secret).is_relative_to(d) for d in dirs
        ), f"{secret} must not fall inside a default quarantine dir"


def test_allow_any_path_escape_hatch_restores_unrestricted(tmp_path, quarantine, monkeypatch):
    """Operators who genuinely need arbitrary paths have a documented switch."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside = outside_dir / "secret.bin"
    outside.write_bytes(b"MZ\x00\x00")

    monkeypatch.setenv(ENV_ALLOW_ANY_PATH, "1")
    assert sanitize_binary_path(str(outside)) == outside.resolve()


def test_allow_any_path_warns_once_per_process(tmp_path, quarantine, monkeypatch, caplog):
    """Unrestricted access is loud, but only once -- and resettable for tests."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside = outside_dir / "secret.bin"
    outside.write_bytes(b"MZ\x00\x00")
    monkeypatch.setenv(ENV_ALLOW_ANY_PATH, "1")

    with caplog.at_level("WARNING", logger="src.utils.security"):
        sanitize_binary_path(str(outside))
        sanitize_binary_path(str(outside))
    warnings = [r for r in caplog.records if "confinement is DISABLED" in r.getMessage()]
    assert len(warnings) == 1

    # The latch is a module global; reset_confinement_warning() is the
    # supported way for tests to clear it (F-8 item 4).
    caplog.clear()
    reset_confinement_warning()
    with caplog.at_level("WARNING", logger="src.utils.security"):
        sanitize_binary_path(str(outside))
    assert any("confinement is DISABLED" in r.getMessage() for r in caplog.records)


def test_require_confinement_beats_allow_any_path(tmp_path, quarantine, monkeypatch):
    """
    An operator who demanded a hard boundary must not be silently downgraded.

    If both flags are set the strict one wins, so a stray
    BINARY_MCP_ALLOW_ANY_PATH in a client config cannot undo
    BINARY_MCP_REQUIRE_CONFINEMENT.
    """
    f = quarantine / "a.bin"
    f.write_bytes(b"MZ\x00\x00")
    monkeypatch.setenv(ENV_ALLOW_ANY_PATH, "1")
    monkeypatch.setenv(ENV_REQUIRE_CONFINEMENT, "1")
    with pytest.raises(PathTraversalError):
        sanitize_binary_path(str(f))


def test_falsy_allowed_dirs_argument_is_not_an_opt_out(tmp_path, quarantine):
    """
    F-8: ``allowed_dirs=None`` must not bypass the default posture.

    Several call sites pass ``allowed_dirs=get_allowed_dirs()``, which is None
    whenever the operator configured nothing. Honouring that as a per-call
    opt-out would leave the whole fix unreachable from pe_tools, authenticode,
    similarity_hashes, carving and server.
    """
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside = outside_dir / "secret.bin"
    outside.write_bytes(b"MZ\x00\x00")

    with pytest.raises(PathTraversalError):
        sanitize_binary_path(str(outside), allowed_dirs=None)
    with pytest.raises(PathTraversalError):
        sanitize_binary_path(str(outside), allowed_dirs=[])


def test_out_of_bounds_path_is_not_an_existence_oracle(tmp_path, quarantine):
    """
    Confinement is decided before the existence/file-type checks.

    Otherwise a caller who cannot read a file can still probe for it: a missing
    path answers FileNotFoundError, a directory answers "Path is not a file",
    and an existing file answers with a confinement error. That difference maps
    out /root, ~/.ssh and friends one probe at a time. Every out-of-bounds path
    must give the same answer regardless of what is actually there.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    existing = outside / "present.bin"
    existing.write_bytes(b"MZ\x00\x00")

    for probe in (outside / "absent.bin", outside, existing):
        with pytest.raises(PathTraversalError):
            sanitize_binary_path(str(probe))


def test_in_bounds_missing_file_still_reports_not_found(quarantine):
    """Control: inside the allow-list the useful diagnostics are unchanged."""
    with pytest.raises(FileNotFoundError):
        sanitize_binary_path(str(quarantine / "absent.bin"))


def test_symlink_out_of_quarantine_rejected_by_default(tmp_path, quarantine):
    """A symlink inside the quarantine dir cannot smuggle in an outside file."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    target = outside_dir / "secret.bin"
    target.write_bytes(b"MZ\x00\x00")
    link = quarantine / "innocent.bin"
    link.symlink_to(target)

    with pytest.raises(PathTraversalError):
        sanitize_binary_path(str(link))


def test_require_confinement_fails_closed_when_unconfigured(tmp_path, monkeypatch):
    """Operators can demand a hard boundary: unset allow-list -> refuse."""
    monkeypatch.delenv("BINARY_MCP_ALLOWED_DIRS", raising=False)
    monkeypatch.setenv("BINARY_MCP_REQUIRE_CONFINEMENT", "1")
    f = tmp_path / "a.bin"
    f.write_bytes(b"MZ\x00\x00")
    with pytest.raises(PathTraversalError) as exc:
        sanitize_binary_path(str(f))
    # Even the strict refusal has to tell the operator what to set.
    assert f"{ENV_ALLOWED_DIRS}=" in str(exc.value)


def test_require_confinement_allows_inside_configured_dir(tmp_path, monkeypatch):
    """Fail-closed mode still permits files inside the configured allow-list."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    f = allowed / "a.bin"
    f.write_bytes(b"MZ\x00\x00")
    monkeypatch.setenv("BINARY_MCP_ALLOWED_DIRS", str(allowed))
    monkeypatch.setenv("BINARY_MCP_REQUIRE_CONFINEMENT", "1")
    assert sanitize_binary_path(str(f)) == f.resolve()


# -- F-13: relative output paths anchor to allowed_dir, not the process CWD --


def test_relative_output_path_resolves_under_allowed_dir(tmp_path):
    """
    F-13: ``output_path="report.md"`` is documented but always failed.

    ``.resolve()`` anchored a relative path to the process CWD -- for a stdio
    MCP server, wherever the client happened to launch it -- so the containment
    check below it rejected every documented relative example.
    """
    allowed = tmp_path / "reports"
    allowed.mkdir()
    assert sanitize_output_path(Path("report.md"), allowed) == allowed / "report.md"


def test_relative_output_path_is_not_cwd_relative(tmp_path, monkeypatch):
    """The anchor is allowed_dir even when the CWD is somewhere else entirely."""
    allowed = tmp_path / "reports"
    allowed.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert sanitize_output_path(Path("report.md"), allowed) == allowed / "report.md"


def test_relative_output_path_in_existing_subdir(tmp_path):
    """Relative sub-paths work too, as long as the parent directory exists."""
    allowed = tmp_path / "reports"
    (allowed / "sub").mkdir(parents=True)
    assert (
        sanitize_output_path(Path("sub/report.md"), allowed)
        == allowed / "sub" / "report.md"
    )


def test_relative_traversal_still_rejected(tmp_path):
    """F-13 must not weaken the check: relative '..' still cannot escape."""
    allowed = tmp_path / "reports"
    allowed.mkdir()
    for evil in ("../../etc/passwd", "../escape.md", "../../../../../../etc/shadow"):
        with pytest.raises(PathTraversalError):
            sanitize_output_path(Path(evil), allowed)


def test_absolute_output_path_outside_allowed_dir_rejected(tmp_path):
    """Absolute paths outside the allowed dir are rejected as before."""
    allowed = tmp_path / "reports"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    for evil in (outside / "x.md", Path("/etc/passwd")):
        with pytest.raises((PathTraversalError, ValueError)):
            sanitize_output_path(evil, allowed)


def test_absolute_output_path_inside_allowed_dir_accepted(tmp_path):
    """Control: the pre-existing absolute-path contract is unchanged."""
    allowed = tmp_path / "reports"
    allowed.mkdir()
    assert (
        sanitize_output_path(allowed / "report.md", allowed) == allowed / "report.md"
    )


# -- F-14: the symlink-component check must actually be able to fire --


def test_symlinked_output_parent_rejected(tmp_path):
    """
    F-14: the old loop walked post-``resolve()`` parents and never fired.

    The link here points back *inside* the allowed dir, so the containment
    check passes -- only a pre-resolution symlink test can catch it. That is
    the case that matters: whoever controls the link can repoint it between the
    check and the write.
    """
    allowed = tmp_path / "reports"
    real = allowed / "real"
    real.mkdir(parents=True)
    (allowed / "link").symlink_to(real)

    with pytest.raises(PathTraversalError, match="Symlinks not allowed"):
        sanitize_output_path(Path("link/report.md"), allowed)


def test_symlinked_output_leaf_rejected(tmp_path):
    """An existing symlink at the leaf would be written *through*."""
    allowed = tmp_path / "reports"
    allowed.mkdir()
    (allowed / "target.md").write_text("x")
    (allowed / "report.md").symlink_to(allowed / "target.md")

    with pytest.raises(PathTraversalError, match="Symlinks not allowed"):
        sanitize_output_path(Path("report.md"), allowed)


def test_symlinked_allowed_dir_itself_is_tolerated(tmp_path):
    """
    Only the user-controlled portion is inspected.

    macOS ships ``/tmp -> /private/tmp`` and ``/var -> /private/var``, so
    rejecting symlinks *at or above* the allow-list root would make an
    allow-list rooted under either unusable.
    """
    real = tmp_path / "real_reports"
    real.mkdir()
    allowed = tmp_path / "reports_link"
    allowed.symlink_to(real)

    assert sanitize_output_path(Path("report.md"), allowed) == real / "report.md"


def test_output_parent_must_exist(tmp_path):
    """Control: a missing parent is still a ValueError, not a silent pass."""
    allowed = tmp_path / "reports"
    allowed.mkdir()
    with pytest.raises(ValueError):
        sanitize_output_path(Path("nope/report.md"), allowed)


# -- Hard-link bypass: resolve() cannot see through a second directory entry --


@posix_only
def test_hardlinked_file_in_quarantine_is_rejected(tmp_path, quarantine):
    """
    The headline bypass: a hard link republishes an out-of-bounds inode.

    ``resolve()`` follows symlinks, and a symlink out of the quarantine dir is
    already refused. A hard link has no target to follow -- it IS the inode
    under a second name -- so this construction passed every containment check
    and read back the real contents of the outside file.
    """
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    secret = outside_dir / "secret"
    secret.write_bytes(b"TOPSECRET")

    link = quarantine / "innocent.bin"
    os.link(secret, link)

    # Sanity: the payload really does read back the outside file's content,
    # so this is a content-disclosure bypass and not a theoretical one.
    assert link.read_bytes() == b"TOPSECRET"
    assert link.resolve() == link  # resolve() is blind to it

    with pytest.raises(PathTraversalError) as exc:
        sanitize_binary_path(str(link))
    assert "hard link" in str(exc.value)


@posix_only
def test_hardlink_denial_names_the_narrow_escape_hatch(tmp_path, quarantine):
    """
    The false-positive escape hatch must be in the error, and must be the
    NARROW one: a de-duplicated corpus should not have to disable confinement
    entirely (BINARY_MCP_ALLOW_ANY_PATH) to be analysable.
    """
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    secret = outside_dir / "secret"
    secret.write_bytes(b"x")
    link = quarantine / "sample.bin"
    os.link(secret, link)

    with pytest.raises(PathTraversalError) as exc:
        sanitize_binary_path(str(link))
    assert ENV_ALLOW_HARDLINKS in str(exc.value)


@posix_only
def test_hardlink_opt_out_restores_access_without_widening_confinement(
    tmp_path, quarantine, monkeypatch
):
    """
    ``cp -l`` corpora and ``rsync --link-dest`` stores are legitimate.

    With the opt-out set the linked sample is analysable again -- but directory
    confinement is untouched, so an outside path is still denied.
    """
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    secret = outside_dir / "secret"
    secret.write_bytes(b"MZ\x00\x00")
    link = quarantine / "sample.bin"
    os.link(secret, link)

    monkeypatch.setenv(ENV_ALLOW_HARDLINKS, "1")
    assert sanitize_binary_path(str(link)) == link.resolve()
    # The opt-out is hard-link-specific, not a confinement kill switch.
    with pytest.raises(PathTraversalError):
        sanitize_binary_path(str(secret))


@posix_only
def test_singly_linked_file_is_unaffected(quarantine):
    """Control: the overwhelmingly common case must not regress."""
    f = quarantine / "ordinary.bin"
    f.write_bytes(b"MZ\x00\x00")
    assert f.stat().st_nlink == 1
    assert sanitize_binary_path(str(f)) == f.resolve()


@posix_only
def test_hardlink_check_is_skipped_when_confinement_is_disabled(
    tmp_path, quarantine, monkeypatch
):
    """
    With BINARY_MCP_ALLOW_ANY_PATH there is no boundary left to bypass.

    Rejecting a multiply-linked file in that mode would be a pure false
    positive: the operator has already said every readable file is fair game.
    """
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    secret = outside_dir / "secret"
    secret.write_bytes(b"MZ\x00\x00")
    link = quarantine / "sample.bin"
    os.link(secret, link)

    monkeypatch.setenv(ENV_ALLOW_ANY_PATH, "1")
    assert sanitize_binary_path(str(link)) == link.resolve()


@posix_only
def test_directories_are_not_hardlink_checked(quarantine):
    """
    ``st_nlink`` counts '..' entries, so every directory with a subdirectory
    has nlink > 1. Only regular files are checked -- otherwise a sample sitting
    in any normal directory tree would be refused.
    """
    parent = quarantine / "corpus"
    (parent / "sub1").mkdir(parents=True)
    (parent / "sub2").mkdir(parents=True)
    assert parent.stat().st_nlink > 1

    sample = parent / "sample.bin"
    sample.write_bytes(b"MZ\x00\x00")
    assert sanitize_binary_path(str(sample)) == sample.resolve()


# -- F-18: sanitize_output_dir confines an extraction destination --


def test_output_dir_relative_is_created_under_root(tmp_path):
    root = tmp_path / "extracted"
    result = sanitize_output_dir("sample1", root)
    assert result == (root / "sample1").resolve()
    assert result.is_dir()


def test_output_dir_absolute_outside_root_rejected(tmp_path):
    root = tmp_path / "extracted"
    evil = tmp_path / "startup"
    with pytest.raises(PathTraversalError):
        sanitize_output_dir(str(evil), root)
    assert not evil.exists(), "rejected destination must not be created"


def test_output_dir_traversal_rejected(tmp_path):
    root = tmp_path / "extracted"
    for evil in ("../escape", "../../../../etc/cron.d", "a/../../escape"):
        with pytest.raises(PathTraversalError):
            sanitize_output_dir(evil, root)
    assert not (tmp_path / "escape").exists()


def test_output_dir_symlinked_component_rejected(tmp_path):
    """
    F-14 applies here too: a pre-planted link inside the root would redirect
    the whole extraction, and it can be repointed between check and write.

    The link here points back *inside* the root, so containment passes and only
    the pre-resolution symlink test can catch it -- exactly the case that
    matters, since whoever controls the link can repoint it at any moment.
    """
    root = tmp_path / "extracted"
    real = root / "real"
    real.mkdir(parents=True)
    (root / "link").symlink_to(real)

    with pytest.raises(PathTraversalError, match="Symlinks not allowed"):
        sanitize_output_dir("link/sub", root)


def test_output_dir_symlink_out_of_root_rejected(tmp_path):
    """A link that leaves the root is caught by the containment test itself."""
    root = tmp_path / "extracted"
    root.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / "link").symlink_to(elsewhere)

    with pytest.raises(PathTraversalError):
        sanitize_output_dir("link/sub", root)
    assert not (elsewhere / "sub").exists()


def test_output_dir_rejects_existing_non_directory(tmp_path):
    root = tmp_path / "extracted"
    root.mkdir()
    (root / "taken").write_text("x")
    with pytest.raises(ValueError):
        sanitize_output_dir("taken", root)


def test_output_dir_nested_relative_path_is_created(tmp_path):
    """Nested relative destinations work -- parents do not have to pre-exist."""
    root = tmp_path / "extracted"
    result = sanitize_output_dir("a/b/c", root)
    assert result == (root / "a" / "b" / "c").resolve()
    assert result.is_dir()


# -- H8: read_full must not slurp an unbounded file into memory --


def test_read_full_accepts_within_cap(tmp_path):
    f = tmp_path / "small.bin"
    f.write_bytes(b"\x00" * 1024)
    with BinaryReader(str(f)) as reader:
        assert reader.read_full(max_bytes=8192) == b"\x00" * 1024


def test_read_full_rejects_oversized(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(b"\x00" * 4096)
    with BinaryReader(str(f)) as reader:
        with pytest.raises(ValueError, match="too large"):
            reader.read_full(max_bytes=1024)
