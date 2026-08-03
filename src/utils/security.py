"""Security utilities for input validation and sanitization."""

import logging
import os
import re
import tempfile
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

# Sentinel distinguishing "caller did not specify allowed_dirs" (resolve the
# configured allow-list from BINARY_MCP_ALLOWED_DIRS) from an explicit
# allowed_dirs=None. Almost every tool entry point omits the argument, so this
# is what lets confinement apply uniformly without touching every call site.
_UNSET: object = object()

# Environment variables that drive the path-confinement policy. Named here so
# error messages and the policy helpers cannot drift out of sync -- an operator
# who hits a confinement error is told the exact variable to set.
ENV_ALLOWED_DIRS = "BINARY_MCP_ALLOWED_DIRS"
ENV_REQUIRE_CONFINEMENT = "BINARY_MCP_REQUIRE_CONFINEMENT"
ENV_ALLOW_ANY_PATH = "BINARY_MCP_ALLOW_ANY_PATH"
# Opt-out for the hard-link rejection below. Narrower than ENV_ALLOW_ANY_PATH:
# it keeps directory confinement fully in force and only re-permits multiply
# linked regular files, which is what a de-duplicated sample corpus looks like.
ENV_ALLOW_HARDLINKS = "BINARY_MCP_ALLOW_HARDLINKS"

# The "confinement disabled" warning is emitted once per process, not per call.
_confinement_warning_emitted = False

# Canonical RFC 4122 version-4 UUID, lowercase hex. The version nibble is pinned
# to '4' and the variant nibble to [89ab] because that is exactly what
# uuid.uuid4() emits -- the only way session IDs are ever minted (F-5).
_SESSION_ID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
)


def _env_flag(name: str) -> bool:
    """True if environment variable ``name`` holds a truthy value."""
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _confinement_required() -> bool:
    """True if the operator demands a configured allow-list (fail closed)."""
    return _env_flag(ENV_REQUIRE_CONFINEMENT)


def _unrestricted_access_requested() -> bool:
    """True if the operator explicitly opted out of confinement entirely."""
    return _env_flag(ENV_ALLOW_ANY_PATH)


def _hardlinks_allowed() -> bool:
    """True if the operator opted out of the hard-link rejection."""
    return _env_flag(ENV_ALLOW_HARDLINKS)


def reset_confinement_warning() -> None:
    """
    Clear the once-per-process "confinement disabled" latch.

    ``_confinement_warning_emitted`` is a module global so a long-lived server
    logs the unconfined-access warning once rather than on every call. Tests
    that assert the warning is emitted need to clear it between cases, so the
    reset is exposed here instead of having them poke at the private global.
    """
    global _confinement_warning_emitted
    _confinement_warning_emitted = False


def default_quarantine_dirs() -> list[Path]:
    """
    Directories analysis is confined to when no allow-list is configured.

    Audit F-8: an unset ``BINARY_MCP_ALLOWED_DIRS`` used to mean "any path on
    this host is fair game". Rather than fail every unconfigured install, the
    default is now a small allow-list covering the places malware samples and
    this server's own artifacts actually live:

      * the system temp directory -- where samples are normally dropped and
        where every tool that unpacks/carves writes its scratch files;
      * this server's cache root (``$BINARY_CACHE_DIR`` or
        ``~/ghidra_mcp_cache``) -- Ghidra projects, saved sessions, carved
        output;
      * the symbol/carve caches (``~/.binary_mcp_cache`` on Windows,
        ``$XDG_CACHE_HOME``/``~/.cache`` + ``/binary_mcp`` on POSIX -- the XDG
        variable must be honoured here because carving._default_carve_dir and
        pdb_fetcher._default_symbol_cache both honour it, and a hardcoded
        ``~/.cache`` silently breaks carve -> analyse whenever it is set;
      * this server's OUTPUT root (``~/.binary_mcp_output``) -- memory dumps,
        module dumps, minidumps, carved/decrypted files and reports. Omitting
        it broke the project's own unpack -> dump -> re-analyse loop:
        x64dbg_dump_memory / x64dbg_dump_module / x64dbg_create_minidump write
        there, and the very next analyze_binary on what they produced was
        refused. Artifacts this server itself wrote are exactly as trustworthy
        as the sample they came from, so confining to them changes nothing
        about the threat model.

    That keeps the common "download a sample to /tmp and analyse it" workflow
    working while blocking the paths that make F-8 a security problem
    (``/etc/shadow``, ``~/.ssh/id_rsa``, ``~/.aws/credentials``, ...). Anything
    else is an explicit operator decision via ``BINARY_MCP_ALLOWED_DIRS``.

    Non-existent entries are fine: containment is a prefix test, so a missing
    directory simply never matches.

    Returns:
        Ordered, de-duplicated list of default allow-list directories.
    """
    candidates: list[Path] = []

    try:
        candidates.append(Path(tempfile.gettempdir()))
    except (OSError, RuntimeError):  # pragma: no cover - platform specific
        pass

    candidates.extend(server_artifact_dirs())

    deduped: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key not in seen:
            seen.add(key)
            deduped.append(candidate)
    return deduped


def server_artifact_dirs() -> list[Path]:
    """
    Directories THIS SERVER ITSELF writes, and must always be able to read back.

    Split out of :func:`default_quarantine_dirs` because these are unioned into
    the allow-list unconditionally -- including when the operator has configured
    ``BINARY_MCP_ALLOWED_DIRS``.

    Without that union, setting an allow-list (the posture every confinement
    denial message tells the operator to adopt) silently broke every
    write-then-read loop the server has: ``extract_python_packed`` wrote to
    ``~/.binary_mcp_output/extracted`` and then refused to analyse what it had
    just produced, and the same held for memory/module dumps, carved and
    decrypted files, reports and the Ghidra cache. That is the third time this
    bug class has shipped, so the invariant is stated once, here: an artifact
    this server wrote is exactly as trustworthy as the sample it came from, and
    refusing to read it back buys no security while breaking core workflows.

    Deliberately EXCLUDES the system temp directory. Temp is a sample *drop*
    location, not a server artifact directory; unioning it in would let any
    file under /tmp bypass an allow-list the operator set specifically to
    exclude it. Temp stays in :func:`default_quarantine_dirs` only, which
    applies when no allow-list is configured at all.

    Returns:
        Ordered, de-duplicated list of server-owned artifact directories.
    """
    candidates: list[Path] = []

    # Read the cache root from the environment directly rather than importing
    # src.utils.config: security.py is imported by nearly every module and must
    # stay free of intra-package imports (and of config's .env side effects).
    cache_root = os.environ.get("BINARY_CACHE_DIR", "").strip()
    try:
        home = Path.home()
    except (OSError, RuntimeError):  # pragma: no cover - HOME unset
        home = None

    if cache_root:
        candidates.append(Path(cache_root))
    elif home is not None:
        candidates.append(home / "ghidra_mcp_cache")

    if home is not None:
        candidates.append(home / ".binary_mcp_cache")
        # Honour XDG_CACHE_HOME so this stays in agreement with
        # carving._default_carve_dir() and pdb_fetcher._default_symbol_cache(),
        # which both consult it. Hardcoding ~/.cache made carve -> analyse fail
        # whenever the operator had XDG_CACHE_HOME set.
        xdg_cache = os.environ.get("XDG_CACHE_HOME", "").strip()
        if xdg_cache:
            candidates.append(Path(xdg_cache) / "binary_mcp")
        candidates.append(home / ".cache" / "binary_mcp")
        # Output root: dumps, carved/decrypted files, reports, YARA rules.
        # Written by this server, and routinely fed straight back into
        # analyze_binary.
        candidates.append(home / ".binary_mcp_output")

    # Explicit relocations of the same caches. Same bug class as the XDG drift
    # above: if the operator moves the carve or symbol cache and we do not
    # follow, this server writes artifacts it then refuses to read back.
    for override in ("BINARY_MCP_CARVE_DIR", "BINARY_MCP_SYMBOL_CACHE"):
        value = os.environ.get(override, "").strip()
        if value:
            candidates.append(Path(value).expanduser())

    deduped: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key not in seen:
            seen.add(key)
            deduped.append(candidate)
    return deduped


def _confinement_setup_hint() -> str:
    """
    Actionable remediation text appended to every confinement denial.

    A denial the operator cannot act on is worse than no denial at all -- they
    just conclude the server is broken. Name the variable, show the separator
    for *this* platform, and give a concrete example value.
    """
    sep = os.pathsep
    if os.name == "nt":
        example = f"C:\\samples{sep}C:\\quarantine"
    else:
        try:
            # Never let the *hint* raise: it only runs while we are already
            # building a denial, and a RuntimeError here would replace an
            # actionable security error with a confusing crash.
            home_example = str(Path.home() / "quarantine")
        except (OSError, RuntimeError):  # pragma: no cover - HOME unset
            home_example = "/var/quarantine"
        example = f"/srv/samples{sep}{home_example}"
    return (
        f"To analyse files elsewhere, set {ENV_ALLOWED_DIRS} to the "
        f"directories you want to expose, separated by '{sep}', e.g. "
        f"{ENV_ALLOWED_DIRS}={example} . "
        f"To restore the previous unrestricted behaviour set "
        f"{ENV_ALLOW_ANY_PATH}=1 (not recommended: every file readable by this "
        f"process then becomes reachable through this server)."
    )


def _default_confinement_denied(binary_path: str, allowed_dirs: list[Path]) -> str:
    """Denial message for a path outside the implicit quarantine allow-list."""
    listed = ", ".join(str(d) for d in allowed_dirs) or "(none)"
    return (
        f"Access denied: {binary_path} is outside the default quarantine "
        f"directories ({listed}). {ENV_ALLOWED_DIRS} is not set, so this "
        f"server confines analysis to those directories by default. "
        f"{_confinement_setup_hint()}"
    )


def _warn_confinement_disabled_once(binary_path: str) -> None:
    """Warn (once) that binary paths are not restricted to any directory."""
    global _confinement_warning_emitted
    if _confinement_warning_emitted:
        return
    _confinement_warning_emitted = True
    logger.warning(
        "Path confinement is DISABLED: %s is set, so binary paths are not "
        "restricted to any directory and any file readable by this process "
        "can be handed to an analysis engine. Unset it and use %s to confine "
        "analysis to a quarantine directory. (first unconfined access: %s)",
        ENV_ALLOW_ANY_PATH,
        ENV_ALLOWED_DIRS,
        binary_path,
    )


class SecurityError(Exception):
    """Base exception for security-related errors."""
    pass


class PathTraversalError(SecurityError):
    """Raised when path traversal attempt is detected."""
    pass


class FileSizeError(SecurityError):
    """Raised when file size exceeds limits."""
    pass


def _reject_hardlinked_file(path: Path, binary_path: str) -> None:
    """
    Refuse a confined read of a regular file that has more than one name.

    Audit (hard-link bypass of the F-8 quarantine posture): confinement is
    enforced with ``resolve()`` + ``is_relative_to()``, and ``resolve()`` sees
    through *symlinks* only. A hard link has no target to follow -- it IS the
    inode, under a second name -- so

        os.link("/etc/hostname", "/tmp/sample.bin")
        sanitize_binary_path("/tmp/sample.bin")

    passed every check and handed the caller the contents of /etc/hostname.
    Anything with write access to a quarantine directory (which, by default,
    includes the system temp dir that every local user can write to) could
    therefore republish an arbitrary same-filesystem file under an in-bounds
    name. That defeats the entire point of the allow-list.

    There is no way to ask the kernel "which other names does this inode have",
    so the only available answer is to refuse regular files with
    ``st_nlink > 1`` while confinement is active. The trade-off:

      * FALSE POSITIVES are real but narrow. A hard-linked corpus (``cp -l``,
        ``rsync --link-dest`` backups, content-addressed sample stores that
        de-duplicate with links) will be refused even though it is legitimate.
        Those setups get :data:`ENV_ALLOW_HARDLINKS`, which re-permits multiply
        linked files *without* weakening directory confinement -- deliberately
        a much smaller hammer than ``BINARY_MCP_ALLOW_ANY_PATH``.
      * NOTHING THIS SERVER WRITES trips it: cache entries, carved output,
        dumps and extracted files are all created fresh with one link.
      * Directories are exempt: ``st_nlink`` counts subdirectory ``..``
        entries, so any non-empty directory has nlink > 1. Only regular files
        are checked. Symlinks never reach here as themselves (the caller has
        already resolved them, and out-of-bounds targets were rejected above).
      * POSIX ONLY. On Windows ``os.stat`` fills ``st_nlink`` from a different
        API path and reports 0 or 1 for files that do have multiple NTFS hard
        links, so the check would be simultaneously unreliable and unable to
        catch the equivalent attack. Rather than pretend, it is skipped there
        and the limitation is stated here.

    Args:
        path: Resolved, in-bounds path that is known to exist and be a file.
        binary_path: The caller's original argument, for the error message.

    Raises:
        PathTraversalError: If ``path`` is a regular file with several links.
    """
    if os.name == "nt" or _hardlinks_allowed():
        return

    try:
        st = path.stat()
    except OSError:
        # Let the caller's own stat() below produce the error; a failure here
        # must not turn into a confusing security denial.
        return

    if st.st_nlink > 1:
        raise PathTraversalError(
            f"Access denied: {binary_path} is a hard link (it has "
            f"{st.st_nlink} names). Directory confinement resolves symlinks "
            f"but cannot see through a hard link, so a multiply-linked file "
            f"inside an allowed directory may be the same inode as a file "
            f"outside it. Copy the sample instead of linking it, or set "
            f"{ENV_ALLOW_HARDLINKS}=1 if this corpus is intentionally "
            f"de-duplicated with hard links."
        )


def sanitize_binary_path(
    binary_path: str,
    allowed_dirs: "list[Path] | None" = _UNSET,
    max_size_bytes: int = 500 * 1024 * 1024  # 500MB default
) -> Path:
    """
    Sanitize and validate binary path to prevent path traversal.

    Args:
        binary_path: User-supplied path to binary file
        allowed_dirs: List of allowed base directories. Omit it (the default)
            to have the configured ``BINARY_MCP_ALLOWED_DIRS`` allow-list
            applied automatically -- this is what confines every tool entry
            point without each one having to pass the list. Pass an explicit
            non-empty list to override. ``None``/``[]`` is *not* an opt-out
            (audit F-8): it falls back to the configured allow-list and then to
            :func:`default_quarantine_dirs`.
        max_size_bytes: Maximum allowed file size in bytes

    Returns:
        Validated absolute path

    Raises:
        PathTraversalError: If path is invalid, outside allowed directories,
            or confinement is required but unconfigured
        FileSizeError: If file exceeds size limit
        FileNotFoundError: If file does not exist
        ValueError: If path validation fails
    """
    # Resolve the confinement policy centrally so every caller is confined
    # uniformly. Historically most call sites passed no allowed_dirs and thus
    # silently skipped confinement even when the operator had set
    # BINARY_MCP_ALLOWED_DIRS (audit H9/P4).
    #
    # A falsy allowed_dirs is treated identically to an omitted one rather than
    # as "opt out of confinement" (audit F-8). Several call sites pass
    # ``allowed_dirs=get_allowed_dirs()``, which is None whenever the operator
    # has not configured an allow-list -- honouring that as an opt-out would
    # have left the fix below unreachable from exactly the tools that need it
    # (pe_tools, authenticode, similarity_hashes, carving, server).
    if allowed_dirs is _UNSET or not allowed_dirs:
        allowed_dirs = get_allowed_dirs()
        if allowed_dirs:
            # Union the server's own artifact directories into the operator's
            # allow-list. Setting BINARY_MCP_ALLOWED_DIRS previously REPLACED
            # the defaults outright, which meant the recommended posture broke
            # every write-then-read loop in the server -- see the rationale on
            # server_artifact_dirs(). Temp is deliberately not included, so the
            # operator's restriction still means what they intended.
            allowed_dirs = list(allowed_dirs) + server_artifact_dirs()

    confined_by_default = False
    if not allowed_dirs:
        # No explicit allow-list. This used to mean "permit any path on the
        # host" after a single stderr warning (audit F-8). A stdio MCP server
        # launched from a client config typically has neither env var set and
        # nobody reads its stderr, so that default handed the model
        # /etc/shadow, ~/.ssh/id_rsa and ~/.aws/credentials on request. The
        # posture is now closed by default, with three escape valves in
        # descending order of strictness:
        #
        #   1. BINARY_MCP_REQUIRE_CONFINEMENT -- refuse to run at all without
        #      an explicit allow-list. Checked first so it always wins: an
        #      operator who demanded a hard boundary must not be downgraded by
        #      the looser flag below.
        #   2. BINARY_MCP_ALLOW_ANY_PATH -- the documented opt-out that
        #      restores the historical unrestricted behaviour.
        #   3. Otherwise: confine to default_quarantine_dirs(), and if the
        #      requested path falls outside them raise an error that names the
        #      env var to set and shows an example value.
        if _confinement_required():
            raise PathTraversalError(
                f"Path confinement is required ({ENV_REQUIRE_CONFINEMENT} is "
                f"set) but {ENV_ALLOWED_DIRS} is not configured; refusing to "
                f"open {binary_path}. {_confinement_setup_hint()}"
            )
        if _unrestricted_access_requested():
            _warn_confinement_disabled_once(binary_path)
            allowed_dirs = None  # normalise [] -> None for the checks below
        else:
            allowed_dirs = default_quarantine_dirs()
            confined_by_default = True

    # Check for symlinks BEFORE resolving (prevent TOCTOU race)
    raw_path = Path(binary_path)

    if raw_path.is_symlink() and allowed_dirs:
        try:
            real_target = raw_path.resolve()
            is_symlink_allowed = False
            for allowed_dir in allowed_dirs:
                resolved_allowed = allowed_dir.resolve()
                if real_target.is_relative_to(resolved_allowed):
                    is_symlink_allowed = True
                    break
            if not is_symlink_allowed:
                if confined_by_default:
                    raise PathTraversalError(
                        _default_confinement_denied(
                            f"the symlink target of {binary_path}", allowed_dirs
                        )
                    )
                raise PathTraversalError(
                    f"Symlink target outside allowed directories: {binary_path}"
                )
        except (OSError, RuntimeError) as e:
            raise PathTraversalError(f"Invalid symlink: {e}")

    # Convert to Path object and resolve to absolute path
    try:
        path = raw_path.resolve()
    except (OSError, RuntimeError) as e:
        raise PathTraversalError(f"Invalid path: {e}")

    # Check if path is within allowed directories.
    #
    # This runs BEFORE the existence and file-type checks on purpose. Those
    # checks answer questions about the target, and answering them for a path
    # the caller is not allowed to touch turns this function into a filesystem
    # oracle: FileNotFoundError vs "Path is not a file" vs a size error lets a
    # caller map out /root, /home/*/.ssh and so on one probe at a time without
    # ever reading a byte. Confinement is decided first so an out-of-bounds
    # path yields exactly one answer -- denied -- regardless of what is there.
    if allowed_dirs:
        is_allowed = False
        for allowed_dir in allowed_dirs:
            try:
                resolved_allowed = allowed_dir.resolve()
                if path.is_relative_to(resolved_allowed):
                    is_allowed = True
                    break
            except (OSError, RuntimeError, ValueError):
                continue

        if not is_allowed:
            if confined_by_default:
                raise PathTraversalError(
                    _default_confinement_denied(binary_path, allowed_dirs)
                )
            raise PathTraversalError(
                f"Access denied: Path outside allowed directories: {binary_path}"
            )

    # Check if path exists
    if not path.exists():
        raise FileNotFoundError(f"File does not exist: {binary_path}")

    # Must be a file, not directory
    if not path.is_file():
        raise ValueError(f"Path is not a file: {binary_path}")

    # Hard-link check. Only meaningful while confinement is active: with
    # BINARY_MCP_ALLOW_ANY_PATH set there is no boundary left to bypass, so
    # refusing a multiply-linked file would be pure false positive. See
    # _reject_hardlinked_file for why resolve() cannot cover this case and what
    # the false-positive trade-off is.
    if allowed_dirs:
        _reject_hardlinked_file(path, binary_path)

    # Check file size to prevent DoS
    try:
        file_size = path.stat().st_size
        if file_size > max_size_bytes:
            raise FileSizeError(
                f"File too large: {file_size} bytes (max: {max_size_bytes})"
            )
    except OSError as e:
        raise ValueError(f"Cannot get file size: {e}")

    return path


def validate_hex_address(address: str) -> str:
    """
    Validate hexadecimal memory address.

    Args:
        address: Hexadecimal address string (with or without 0x prefix)

    Returns:
        Validated address string without 0x prefix

    Raises:
        ValueError: If address is invalid
    """
    # Remove 0x prefix if present
    addr = address.lower().replace('0x', '').strip()

    # Must be valid hexadecimal
    if not re.match(r'^[0-9a-f]+$', addr):
        raise ValueError(f"Invalid hexadecimal address: {address}")

    # Length check (16 characters max for 64-bit)
    if len(addr) > 16:
        raise ValueError(
            f"Address too long for 64-bit architecture: {address}"
        )

    # Must not be empty
    if len(addr) == 0:
        raise ValueError("Address cannot be empty")

    return addr


def validate_numeric_range(
    value: int,
    min_val: int,
    max_val: int,
    param_name: str = "value"
) -> int:
    """
    Validate numeric value is within acceptable range.

    Args:
        value: Value to validate
        min_val: Minimum allowed value (inclusive)
        max_val: Maximum allowed value (inclusive)
        param_name: Parameter name for error messages

    Returns:
        Validated value

    Raises:
        TypeError: If value is not an integer
        ValueError: If value is outside range
    """
    if not isinstance(value, int):
        raise TypeError(f"{param_name} must be an integer, got {type(value).__name__}")

    if value < min_val or value > max_val:
        raise ValueError(
            f"{param_name} must be between {min_val} and {max_val}, got {value}"
        )

    return value


def _reject_symlinked_components(raw_path: Path, abs_allowed: Path) -> None:
    """
    Refuse an output path whose user-supplied components include a symlink.

    Audit F-14: the previous version of this check walked ``abs_path.parents``
    *after* ``.resolve()`` had already collapsed every symlink, so it could
    never fire. Do not re-introduce that ordering -- a symlink test is only
    meaningful on the pre-resolution path, which is why
    :func:`sanitize_binary_path` inspects ``raw_path`` before resolving it.

    The check is not redundant with the containment test in the caller. That
    test resolves the path and proves the *current* target sits inside the
    allowed directory; the write happens later. If any user-supplied component
    is a symlink, whoever controls it can repoint it between the check and the
    write (TOCTOU) -- so a symlinked component is rejected even when it
    currently resolves back inside the allowed directory.

    Only the portion below ``abs_allowed`` is inspected. Components at or above
    it are the operator's own directory layout, and rejecting those would break
    ordinary systems: macOS exposes ``/tmp -> /private/tmp`` and
    ``/var -> /private/var``, so an allow-list rooted under either would be
    unusable. ``carving._validate_output_dir`` draws the same line for the same
    reason.

    Args:
        raw_path: Absolute but *unresolved* candidate output path.
        abs_allowed: Already-resolved allow-list root.

    Raises:
        PathTraversalError: If a component below ``abs_allowed`` is a symlink.
    """
    for component in (raw_path, *raw_path.parents):
        try:
            if component.resolve() == abs_allowed:
                return
        except (OSError, RuntimeError):
            # Unresolvable component: stop walking rather than guess. The
            # caller's containment check has already passed on the resolved
            # path, so there is nothing further to prove here.
            return
        if component.is_symlink():
            raise PathTraversalError(
                f"Symlinks not allowed in output path: {component}"
            )


def sanitize_output_path(output_path: Path, allowed_dir: Path) -> Path:
    """
    Sanitize output path to prevent directory traversal.

    A relative ``output_path`` is interpreted relative to ``allowed_dir``, so
    the documented ergonomics (``output_path="report.md"``) work as advertised.

    Args:
        output_path: Requested output path. Absolute, or relative to
            ``allowed_dir``.
        allowed_dir: Base directory for outputs

    Returns:
        Validated absolute path within allowed directory

    Raises:
        PathTraversalError: If path is outside allowed directory, or a
            user-supplied component below it is a symlink
        ValueError: If path is invalid
    """
    try:
        abs_allowed = allowed_dir.resolve()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid path: {e}")

    # Audit F-13: this used to call output_path.resolve() directly, which
    # anchors a relative path to the *process* CWD -- for a stdio MCP server
    # that is whatever directory the client happened to launch it from. Every
    # documented relative example ("report.md") therefore resolved outside
    # allowed_dir and failed with PathTraversalError, pushing users towards
    # absolute paths. Anchoring to allowed_dir instead restores the intended
    # ergonomics without weakening anything: the resolve() + is_relative_to()
    # containment test below is unchanged, so a relative "../../etc/passwd"
    # still resolves outside the allowed directory and is still rejected.
    raw_path = output_path if output_path.is_absolute() else allowed_dir / output_path

    try:
        abs_path = raw_path.resolve()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid path: {e}")

    # Check if path is within allowed directory
    try:
        if not abs_path.is_relative_to(abs_allowed):
            raise PathTraversalError(
                f"Output path must be within {abs_allowed}"
            )
    except ValueError:
        raise PathTraversalError(
            f"Output path must be within {abs_allowed}"
        )

    # Ensure parent directory exists
    if not abs_path.parent.exists():
        raise ValueError(f"Parent directory does not exist: {abs_path.parent}")

    # Symlink check runs on the pre-resolution path -- see F-14 note in
    # _reject_symlinked_components for why the post-resolution walk was dead.
    _reject_symlinked_components(raw_path, abs_allowed)

    return abs_path


def sanitize_output_dir(output_dir: str | Path, allowed_dir: Path) -> Path:
    """
    Confine a caller-supplied *directory* to ``allowed_dir``, then create it.

    Audit F-18 (HIGH): ``extract_python_packed`` passed ``output_dir`` through
    completely unvalidated to ``PythonPackerAnalyzer.extract_pyinstaller``,
    which did ``Path(output_dir).mkdir(parents=True, exist_ok=True)`` and then
    wrote archive members into it. Only traversal *within* ``output_dir`` was
    blocked (the Zip Slip guard), so the destination itself was arbitrary: the
    model chose the directory (a Startup folder, ``~/.ssh``, a cron drop-in)
    and the SAMPLE chose the filenames and the bytes. That is an
    attacker-controlled write primitive with a model-controlled target -- the
    worst half of each.

    Why this is not just :func:`sanitize_output_path`: that function requires
    the parent to already exist, because it validates a *file* about to be
    written into an existing tree. An extraction root legitimately needs
    directories created. Creation is what makes ordering critical here, so the
    order is fixed and must not be rearranged:

      1. anchor a relative path under ``allowed_dir`` (never the process CWD --
         see the F-13 note in :func:`sanitize_output_path`);
      2. resolve and prove containment;
      3. reject symlinked components below ``allowed_dir`` (F-14) -- otherwise
         a pre-planted link inside the root redirects the whole extraction;
      4. only THEN mkdir.

    Args:
        output_dir: Requested directory. Absolute, or relative to
            ``allowed_dir``.
        allowed_dir: Root the output directory must live under. Created if
            missing so containment can be evaluated against a real path.

    Returns:
        Validated, existing absolute directory inside ``allowed_dir``.

    Raises:
        PathTraversalError: If the path escapes ``allowed_dir`` or a
            user-supplied component below it is a symlink.
        ValueError: If the path is invalid or is not a directory.
    """
    try:
        allowed_dir.mkdir(parents=True, exist_ok=True)
        abs_allowed = allowed_dir.resolve()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid output root: {e}")

    requested = Path(output_dir) if not isinstance(output_dir, Path) else output_dir
    raw_path = requested if requested.is_absolute() else allowed_dir / requested

    try:
        abs_path = raw_path.resolve()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid path: {e}")

    if not abs_path.is_relative_to(abs_allowed):
        raise PathTraversalError(
            f"Output directory must be within {abs_allowed} (requested: "
            f"{output_dir}). Extraction writes sample-controlled bytes under "
            f"sample-controlled filenames, so it is confined to this server's "
            f"own output root."
        )

    _reject_symlinked_components(raw_path, abs_allowed)

    if abs_path.exists() and not abs_path.is_dir():
        raise ValueError(f"Output path exists and is not a directory: {abs_path}")

    try:
        abs_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise ValueError(f"Cannot create output directory: {e}")

    return abs_path


def safe_regex_compile(pattern: str, max_length: int = 100, timeout_ms: int = 1000):
    """
    Safely compile regex pattern with complexity limits.

    Args:
        pattern: Regex pattern to compile
        max_length: Maximum pattern length
        timeout_ms: Timeout for regex operations (informational, used by callers)

    Returns:
        Compiled regex pattern

    Raises:
        ValueError: If pattern is too complex or dangerous
    """
    import re as _re

    # Validate pattern length
    if len(pattern) > max_length:
        raise ValueError(f"Regex pattern too long (max {max_length} characters)")

    # Structural ReDoS detection: check for nested quantifiers
    # This catches patterns like (.+)+, ([a-z]+)+, (a|a)+, (\\w+\\s?)*, etc.
    nested_quantifier_re = _re.compile(
        r'(?:'
        r'\([^)]*[+*][^)]*\)[+*?]'   # Group with quantifier followed by quantifier
        r'|'
        r'\([^)]*\)\{[0-9,]+\}'       # Group followed by {n,m} quantifier
        r'|'
        r'[+*]\)+[+*]'                # Quantifier, close group(s), quantifier
        r')'
    )
    if nested_quantifier_re.search(pattern):
        raise ValueError(
            "Potentially dangerous regex: nested quantifiers detected (ReDoS risk)"
        )

    # Check for excessive alternation within groups (e.g., (a|a|a|a|a|...))
    excessive_alternation_re = _re.compile(r'\([^)]*(?:\|[^)]*){10,}\)')
    if excessive_alternation_re.search(pattern):
        raise ValueError(
            "Potentially dangerous regex: excessive alternation detected (ReDoS risk)"
        )

    # Check for excessive group nesting depth
    depth = 0
    max_depth = 0
    for char in pattern:
        if char == '(':
            depth += 1
            max_depth = max(max_depth, depth)
        elif char == ')':
            depth -= 1
    if max_depth > 5:
        raise ValueError(
            f"Regex nesting too deep ({max_depth} levels, max 5)"
        )

    try:
        return _re.compile(pattern, _re.IGNORECASE)
    except _re.error as e:
        raise ValueError(f"Invalid regex pattern: {e}")


def validate_state_id(state_id: str) -> str:
    """
    Validate a debug state ID to prevent path traversal.

    State IDs are generated as hex SHA256 prefixes and must match
    that format strictly.

    Args:
        state_id: State identifier string

    Returns:
        Validated state ID

    Raises:
        ValueError: If state_id format is invalid
    """
    if not state_id or not isinstance(state_id, str):
        raise ValueError("State ID cannot be empty")
    state_id = state_id.strip()
    if not re.match(r'^[a-f0-9]{1,64}$', state_id):
        raise ValueError(
            "Invalid state ID format: must be 1-64 hex characters"
        )
    return state_id


def validate_session_id(session_id: str) -> str:
    """
    Validate an analysis session ID to prevent path traversal.

    Audit finding F-5 (MEDIUM): session IDs arrive straight from MCP tool
    arguments and get interpolated into a filename under the session store::

        self.store_dir / f"{session_id}.session.json.gz"

    A ``session_id`` of ``'../../../../tmp/pwned'`` therefore escaped the store
    directory entirely, giving a caller read/write/unlink on any path ending in
    ``.session.json.gz`` or ``.meta.json``. Session IDs are minted exclusively
    by ``uuid.uuid4()``, so pinning them to a canonical RFC 4122 version-4 UUID
    is both complete and lossless -- no legitimate ID is ever rejected.

    The first remediation pass fixed this at the chokepoint in
    ``src/engines/session/unified_session.py`` but left the second, identical
    construction in ``engines/static/ghidra/analysis_session.py`` untouched.
    That is why the validator now lives here: a shared helper cannot be fixed in
    one copy and forgotten in the other. ``unified_session._validate_session_id``
    still carries its own private copy of the same regex (that module is owned
    elsewhere); the two are deliberately identical in shape and behaviour.

    Args:
        session_id: Session identifier string

    Returns:
        Validated session ID, normalised to lowercase

    Raises:
        ValueError: If session_id is not a canonical UUIDv4
    """
    if not session_id or not isinstance(session_id, str):
        raise ValueError("Session ID cannot be empty")
    # strip() before matching mirrors validate_state_id(); the anchored regex
    # still rejects embedded whitespace, NUL bytes and path separators because
    # none of them can appear inside a UUID character class.
    session_id = session_id.strip().lower()
    if not _SESSION_ID_RE.match(session_id):
        raise ValueError(
            "Invalid session ID format: must be a UUID "
            "(e.g. 123e4567-e89b-42d3-a456-426614174000)"
        )
    return session_id


def validate_parameter_pattern(value: str, param_name: str, pattern: str = r'^[a-zA-Z0-9:_.\-]+$', max_length: int = 200) -> str:
    """
    Validate a string parameter against an allowed pattern.

    Args:
        value: Parameter value to validate
        param_name: Parameter name for error messages
        pattern: Regex pattern for allowed characters
        max_length: Maximum allowed length

    Returns:
        Validated parameter string

    Raises:
        ValueError: If parameter is invalid
    """
    if not value or not isinstance(value, str):
        raise ValueError(f"{param_name} cannot be empty")
    value = value.strip()
    if len(value) > max_length:
        raise ValueError(f"{param_name} too long (max {max_length} characters)")
    if not re.match(pattern, value):
        raise ValueError(
            f"Invalid {param_name}: contains disallowed characters"
        )
    return value


def get_allowed_dirs() -> list[Path] | None:
    """
    Get allowed directories from configuration.

    Reads BINARY_MCP_ALLOWED_DIRS environment variable. Entries are
    separated by ``os.pathsep`` (``:`` on POSIX, ``;`` on Windows) so
    drive-letter paths like ``C:\\Users\\foo`` parse correctly on both
    platforms.

    Returns None if not configured. Note that "not configured" no longer means
    "unrestricted" for binary paths: :func:`sanitize_binary_path` falls back to
    :func:`default_quarantine_dirs` (audit F-8). This function deliberately
    keeps reporting the raw operator configuration, because other callers
    (e.g. ``carving._validate_output_dir``) need to distinguish "operator set an
    allow-list" from "operator set nothing" to choose their own fallback.

    Returns:
        List of allowed directory Paths, or None if not configured
    """
    import os
    dirs_config = os.environ.get("BINARY_MCP_ALLOWED_DIRS", "").strip()
    if not dirs_config:
        return None
    return [Path(d.strip()) for d in dirs_config.split(os.pathsep) if d.strip()]


# ---------------------------------------------------------------------------
# Non-disclosing text for path-validation failures (audit F-10)
# ---------------------------------------------------------------------------
#
# The MESSAGE of a confinement failure is itself host state. _default_confinement
# _denied() interpolates the resolved quarantine directory list and
# _confinement_setup_hint() prints ``Path.home() / "quarantine"`` as its worked
# example, so ``str(PathTraversalError)`` carries the operator's username and
# directory layout. Anything that forwards that text to the model leaks it into
# the transcript, and from there into generated reports.
#
# This mapping lives HERE rather than in src/tools/error_hygiene.py because both
# layers need it and src/utils/ cannot import from src/tools/ (error_hygiene
# already imports this module). Keeping one copy is the point: the first
# remediation pass fixed the tool handlers and left the src/utils/ producers --
# carving.carve, similarity_hashes.compute, authenticode.inspect -- forwarding
# the same text through StructuredError.reason, which curated_structured_text
# deliberately preserves. A second copy is how that happened.
PATH_ERROR_GUIDANCE: "dict[type, str]" = {
    PathTraversalError: (
        "the path is outside the directories this server is allowed to read. "
        f"Analyse files from a directory the operator exposed via "
        f"{ENV_ALLOWED_DIRS} (or the default quarantine directories). The "
        f"configured directories are intentionally not listed here; ask the "
        f"operator, or have them set {ENV_ALLOWED_DIRS} / "
        f"{ENV_ALLOW_ANY_PATH}. Output paths must likewise stay inside this "
        "server's own output directory -- pass a bare filename rather than "
        "an absolute path."
    ),
    FileSizeError: (
        "the file is larger than this server's analysis size limit. Carve "
        "out the region of interest and analyse that instead."
    ),
    FileNotFoundError: (
        "no file exists at the path supplied. Check the name and extension, "
        "and confirm the sample was copied onto this host."
    ),
    IsADirectoryError: "the path names a directory, not a file.",
    NotADirectoryError: "a component of the path is not a directory.",
    PermissionError: (
        "this server does not have permission to read the path supplied."
    ),
}


def path_error_guidance(error: Exception) -> "str | None":
    """
    Return non-disclosing guidance for a path-validation error, or None.

    None means the exception type is not one whose category can be described
    without echoing its text -- callers decide their own fallback. Iteration
    order is irrelevant: the mapped types are siblings, never subclasses of one
    another.

    Args:
        error: The caught path-validation exception.

    Returns:
        Guidance text safe to show the model, or None if unmapped.
    """
    for exc_type, text in PATH_ERROR_GUIDANCE.items():
        if isinstance(error, exc_type):
            return text
    return None


def safe_path_reason(error: Exception) -> str:
    """
    Non-disclosing ``StructuredError.reason`` text for a path failure.

    For library code in ``src/utils/`` that raises ``StructuredBaseError`` from
    a :func:`sanitize_binary_path` failure. Unlike
    :func:`path_error_guidance` this ALWAYS returns a safe string, because the
    unmapped cases leak too: ``sanitize_binary_path`` raises ``ValueError("Path
    is not a file: <resolved path>")``, which interpolates the resolved
    absolute path.

    Put the original text in ``debug_info`` instead -- that field is dropped
    from model-facing output by ``error_hygiene.curated_structured_text`` and
    written to the server log, where the operator can already see the host.

    Args:
        error: The caught path-validation exception.

    Returns:
        Guidance text safe to show the model. Never echoes ``error``.
    """
    guidance = path_error_guidance(error)
    if guidance is not None:
        return guidance
    return (
        "the path could not be validated against this server's confinement "
        f"policy. Supply a path to an existing file inside a directory the "
        f"operator exposed via {ENV_ALLOWED_DIRS} (or the default quarantine "
        f"directories). The specific reason and the configured directories are "
        f"recorded in the server log rather than here."
    )


class UserFacingError(Exception):
    """
    Exception with separate user-facing and internal error messages.

    Prevents information disclosure by showing safe messages to users
    while logging detailed internal errors.
    """

    def __init__(self, user_message: str, internal_details: str = None):
        """
        Initialize user-facing error.

        Args:
            user_message: Safe message shown to user
            internal_details: Detailed error info logged internally
        """
        super().__init__(user_message)
        self.user_message = user_message
        self.internal_details = internal_details
        self.error_id = str(uuid.uuid4())[:8]

        # Log internal details with error ID for tracking
        if internal_details:
            logger.error(f"Error {self.error_id}: {internal_details}")

    def __str__(self):
        return f"{self.user_message}\nReference ID: {self.error_id}"


def safe_error_message(
    user_message: str,
    internal_details: Exception = None,
    error_id: str = None
) -> str:
    """
    Create a safe error message for users without exposing internals.

    Args:
        user_message: User-friendly error description
        internal_details: Exception or details to log internally
        error_id: Optional error ID (generated if not provided)

    Returns:
        Safe error message with reference ID
    """
    if error_id is None:
        error_id = str(uuid.uuid4())[:8]

    # Log internal details
    if internal_details:
        logger.error(f"Error {error_id}: {internal_details}", exc_info=True)

    # If the exception carries a curated diagnostic (e.g. GhidraAnalysisError
    # with extracted stderr context), surface it. The diagnostic is already
    # filtered to actionable lines from a trusted subprocess -- it tells the
    # user *why* the call failed (poisoned OSGi cache, JDK mismatch, OOM,
    # missing file, ...) rather than hiding behind a reference ID.
    diagnostic = getattr(internal_details, "diagnostic", None) if internal_details else None
    if diagnostic:
        return (
            f"Error: {user_message}\n"
            f"Reference ID: {error_id}\n\n"
            f"Diagnostic:\n{diagnostic}"
        )

    return f"Error: {user_message}\nReference ID: {error_id}\nPlease contact support with this reference ID."
