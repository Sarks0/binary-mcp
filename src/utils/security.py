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

# The "confinement disabled" warning is emitted once per process, not per call.
_confinement_warning_emitted = False


def _env_flag(name: str) -> bool:
    """True if environment variable ``name`` holds a truthy value."""
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _confinement_required() -> bool:
    """True if the operator demands a configured allow-list (fail closed)."""
    return _env_flag(ENV_REQUIRE_CONFINEMENT)


def _unrestricted_access_requested() -> bool:
    """True if the operator explicitly opted out of confinement entirely."""
    return _env_flag(ENV_ALLOW_ANY_PATH)


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
        ``~/.cache/binary_mcp`` on POSIX).

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
        candidates.append(home / ".cache" / "binary_mcp")

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
