"""
Embedded-binary carver: walk PE resources + overlay, classify, dump flagged blobs.

Surfaces:
- walk_resources(pe) -> Iterator[(resource_path, file_offset, size)]
- classify_blob(data) -> (detected_type, description, entropy, flag_reasons)
- carve(binary_path, output_dir, max_total_mb) -> CarvingResult
- render_markdown(result) -> str

Used by `extract_embedded_binaries` MCP tool. Pure utility -- no MCP coupling.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import struct  # noqa: F401  (re-exported for tests; kept for parity with other utils)
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# --- Constants ---

ENTROPY_THRESHOLD = 7.2
ENTROPY_MIN_SIZE = 2048
DEFAULT_MAX_DEPTH = 8
DEFAULT_MAX_TOTAL_MB = 64

# Magic byte signatures. We rely on triage_tools.detect_file_type for the
# coverage it already implements (PE / ELF / Mach-O / OLE / MSI / ZIP / PDF /
# .NET) and add archive-and-shellcode patterns it does not cover.
_MAGIC_PATTERNS: list[tuple[bytes, str, str]] = [
    (b"7z\xBC\xAF\x27\x1C", "7z", "magic:7z"),
    (b"Rar!\x1A\x07\x00", "rar", "magic:rar"),
    (b"Rar!\x1A\x07\x01\x00", "rar", "magic:rar5"),
    (b"\x1F\x8B", "gzip", "magic:gzip"),
    (b"BZh", "bzip2", "magic:bzip2"),
    (b"\xFD7zXZ\x00", "xz", "magic:xz"),
]

# x86 / x64 shellcode prologue heuristics (head of blob only).
_SHELLCODE_PATTERNS: list[tuple[re.Pattern[bytes], str]] = [
    # CALL+pop: E8 ?? ?? ?? ?? followed by pop register / push register
    (re.compile(rb"\xE8.{4}[\x50-\x5F]", re.DOTALL), "shellcode:call_pop"),
    # cld; call $+5 -- common stage-zero prologue
    (re.compile(rb"\xFC\xE8.{4}", re.DOTALL), "shellcode:cld_call"),
    # FS:[0x30] PEB walk (x86)
    (re.compile(rb"\x64\xA1\x30\x00\x00\x00", re.DOTALL), "shellcode:peb_walk_x86"),
    # GS:[0x60] PEB walk (x64)
    (re.compile(rb"\x65\x48\x8B\x04\x25\x60\x00\x00\x00", re.DOTALL), "shellcode:peb_walk_x64"),
]


# --- Dataclasses ---


@dataclass(frozen=True)
class CarvedBlob:
    """One embedded blob discovered during carving."""

    source: str  # "resource" | "overlay"
    resource_path: str  # "RT_RCDATA/101/1033" or "" for overlay
    file_offset: int
    size: int
    sha256: str
    detected_type: str
    detected_description: str
    entropy: float
    flagged: bool
    flag_reasons: tuple[str, ...]
    written_path: str | None = None
    write_skipped_reason: str | None = None


@dataclass
class CarvingResult:
    """Top-level carving result."""

    binary_path: str
    binary_sha256: str
    output_dir: str
    blobs: list[CarvedBlob] = field(default_factory=list)
    truncated: bool = False
    truncated_reason: str = ""
    total_extracted_bytes: int = 0


# --- Resource walker ---


def _walk_subtree(
    directory: Any,
    path_parts: list[str],
    depth: int,
    max_depth: int,
) -> Iterator[tuple[str, int, int]]:
    """Recursive descent. Yields (path, rva, size) for every leaf data entry."""
    if depth > max_depth:
        logger.warning("resource walk depth %d exceeded max_depth=%d", depth, max_depth)
        return
    entries = getattr(directory, "entries", None) or []
    for entry in entries:
        if entry.id is not None:
            label = str(entry.id)
        elif entry.name:
            label = str(entry.name)
        else:
            label = "?"
        new_parts = path_parts + [label]
        sub = getattr(entry, "directory", None)
        if sub is not None:
            yield from _walk_subtree(sub, new_parts, depth + 1, max_depth)
            continue
        data = getattr(entry, "data", None)
        if data is None:
            continue
        try:
            ds = data.struct
            yield "/".join(new_parts), int(ds.OffsetToData), int(ds.Size)
        except AttributeError:
            continue


def walk_resources(
    pe: Any, *, max_depth: int = DEFAULT_MAX_DEPTH
) -> Iterator[tuple[str, int, int]]:
    """
    Walk pe.DIRECTORY_ENTRY_RESOURCE, yielding (resource_path, file_offset, size).

    `resource_path` is human-readable like "RT_RCDATA/101/1033". `file_offset`
    is the absolute offset in the on-disk file (computed via
    ``pe.get_offset_from_rva``); leaves whose RVA cannot be mapped are skipped.

    Args:
        pe: A pefile.PE with parsed resource directory.
        max_depth: Recursion depth cap. Resource trees are 3 levels deep
            normally; this protects against resource-bombing.
    """
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return

    try:
        import pefile
    except ImportError:
        pefile = None  # type: ignore[assignment]

    entries = getattr(root, "entries", None) or []
    for type_entry in entries:
        if type_entry.id is not None:
            type_label = (
                pefile.RESOURCE_TYPE.get(type_entry.id, f"Unknown({type_entry.id})")
                if pefile is not None
                else f"id_{type_entry.id}"
            )
        elif type_entry.name:
            type_label = str(type_entry.name)
        else:
            type_label = "Unknown"

        sub = getattr(type_entry, "directory", None)
        if sub is None:
            continue
        for rel_path, rva, size in _walk_subtree(
            sub, [type_label], depth=2, max_depth=max_depth
        ):
            try:
                file_off = pe.get_offset_from_rva(rva)
            except Exception:
                logger.debug("get_offset_from_rva(0x%X) failed; skipping leaf", rva)
                continue
            yield rel_path, int(file_off), int(size)


# --- Classifier ---


def classify_blob(data: bytes) -> tuple[str, str, float, list[str]]:
    """
    Classify a blob via magic bytes + entropy.

    Returns:
        (detected_type, detected_description, entropy, flag_reasons)
    """
    from src.tools.triage_tools import detect_file_type
    from src.utils.crypto_analysis import calculate_entropy

    if not data:
        return "empty", "empty blob", 0.0, []

    detected = detect_file_type(data)
    detected_type = detected.get("type", "unknown")
    description = detected.get("description", "")
    entropy = calculate_entropy(data)

    reasons: list[str] = []

    # detect_file_type already covers PE / ELF / Mach-O / OLE / MSI / ZIP /
    # PDF / .NET. If it found one of those, surface a magic flag.
    interesting = ("pe", "dotnet", "elf", "macho", "msi", "ole", "zip", "pdf")
    if detected_type in interesting:
        reasons.append(f"magic:{detected_type}")

    # Extra archive / compressor magics that detect_file_type does not handle.
    for magic, type_label, reason in _MAGIC_PATTERNS:
        if data.startswith(magic):
            reasons.append(reason)
            if detected_type == "unknown":
                detected_type = type_label
                description = description or f"{type_label} archive/compressed stream"
            break

    # Shellcode prologues -- only check the head; full-file scan is wasteful.
    head = data[: min(len(data), 4096)]
    for pat, reason in _SHELLCODE_PATTERNS:
        if pat.search(head):
            reasons.append(reason)
            break

    # Entropy heuristic. Recorded alongside any magic / shellcode reasons so
    # callers can see when a blob is high-entropy (compressed / encrypted /
    # packed) regardless of whether it also matched a magic pattern.
    if entropy > ENTROPY_THRESHOLD and len(data) > ENTROPY_MIN_SIZE:
        reasons.append(f"entropy>{ENTROPY_THRESHOLD}")

    return detected_type, description, entropy, reasons


# --- Output dir defaulting + validation ---


# Hard denylist of POSIX system directories that no carver output should
# ever land in. Used when no BINARY_MCP_ALLOWED_DIRS allow-list is
# configured; otherwise the allow-list is authoritative. The ``/private/...``
# entries cover macOS, where ``/etc`` is a symlink to ``/private/etc`` and
# ``Path.resolve()`` returns the latter form.
_DANGEROUS_PREFIXES: tuple[str, ...] = (
    "/etc",
    "/private/etc",
    "/sys",
    "/proc",
    "/boot",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/sbin",
    "/bin",
    "/var/spool",
    "/private/var/spool",
    "/var/log",
    "/private/var/log",
    "/var/lib",
    "/private/var/lib",
    "/root",
    "/private/var/root",
)


def _is_within(child: Path, parent: Path) -> bool:
    """Cross-platform check that ``child`` is inside ``parent``.

    Path.is_relative_to() does case-sensitive part-by-part comparison and
    breaks on Windows where C:\\Users\\...\\sandbox\\out vs the same path
    with mixed case fails despite being the same directory. Normalize via
    os.path.normcase + commonpath instead.
    """
    try:
        c = os.path.normcase(str(child))
        p = os.path.normcase(str(parent))
        return os.path.commonpath([c, p]) == p
    except (ValueError, OSError):
        # commonpath raises on different drives (Windows) or absolute-vs-
        # relative mix. In either case, the child is not within the parent.
        return False


def _validate_output_dir(out: Path) -> Path:
    """
    Validate a user-supplied carving output directory.

    Rejects parent traversal (``..``), symlinks anywhere on the existing
    portion of the path, and -- when no ``BINARY_MCP_ALLOWED_DIRS`` allow-list
    is configured -- a hard-coded denylist of POSIX system directories.

    Args:
        out: User-supplied output directory (already ``.expanduser()``'d).

    Returns:
        Resolved absolute path (symlinks collapsed).

    Raises:
        StructuredBaseError: With ``ErrorCode.PARAMETER_INVALID`` when the
            path fails validation. Never returns an unsafe path.
    """
    from src.utils.security import get_allowed_dirs
    from src.utils.structured_errors import (
        ErrorCode,
        StructuredBaseError,
        StructuredError,
    )

    if any(part == ".." for part in out.parts):
        raise StructuredBaseError(
            StructuredError(
                error=ErrorCode.PARAMETER_INVALID,
                message="Invalid output_dir",
                reason="output_dir must not contain '..' (parent traversal)",
                suggestions=["Use an absolute path with no '..' components"],
                debug_info={"output_dir": str(out)},
            )
        )

    # Reject if the user-supplied leaf is itself a symlink. We deliberately
    # don't reject symlinks in *parent* components -- on macOS the system
    # exposes ``/var -> /private/var`` and ``/tmp -> /private/tmp`` as
    # legitimate OS topology, and pytest's ``tmp_path`` lives behind those.
    # The denylist below is checked against BOTH the user-input absolute
    # path and the symlink-resolved path, which catches the practical
    # threat (a user-controlled symlink pointing into ``/etc`` etc.).
    try:
        if out.is_symlink():
            raise StructuredBaseError(
                StructuredError(
                    error=ErrorCode.PARAMETER_INVALID,
                    message="Invalid output_dir",
                    reason=f"output_dir is a symlink: {out}",
                    suggestions=["Provide a non-symlinked absolute path"],
                    debug_info={"output_dir": str(out)},
                )
            )
    except OSError:
        # Stat failed -- treat as suspect input
        raise StructuredBaseError(
            StructuredError(
                error=ErrorCode.PARAMETER_INVALID,
                message="Invalid output_dir",
                reason=f"Cannot stat output_dir: {out}",
                debug_info={"output_dir": str(out)},
            )
        ) from None

    try:
        resolved = out.resolve()
    except (OSError, RuntimeError) as e:
        raise StructuredBaseError(
            StructuredError(
                error=ErrorCode.PARAMETER_INVALID,
                message="Invalid output_dir",
                reason=f"Path could not be resolved: {e}",
                debug_info={"output_dir": str(out)},
            )
        ) from e

    if not resolved.is_absolute():
        raise StructuredBaseError(
            StructuredError(
                error=ErrorCode.PARAMETER_INVALID,
                message="Invalid output_dir",
                reason="output_dir must resolve to an absolute path",
                debug_info={"output_dir": str(out), "resolved": str(resolved)},
            )
        )

    allowed = get_allowed_dirs()
    if allowed:
        for d in allowed:
            try:
                d_resolved = d.resolve()
            except (OSError, RuntimeError):
                continue
            if _is_within(resolved, d_resolved):
                return resolved
        raise StructuredBaseError(
            StructuredError(
                error=ErrorCode.PARAMETER_INVALID,
                message="Invalid output_dir",
                reason="output_dir is not within any BINARY_MCP_ALLOWED_DIRS entry",
                suggestions=[
                    "Add the desired directory to BINARY_MCP_ALLOWED_DIRS",
                    "Or omit output_dir to use the default carve cache",
                ],
                debug_info={
                    "output_dir": str(out),
                    "resolved": str(resolved),
                    "allowed_dirs": [str(d) for d in allowed],
                },
            )
        )

    # No allow-list configured: hard-block obvious system directories. Check
    # the unresolved absolute path *and* the symlink-resolved path so a
    # user-controlled "/tmp/link -> /etc" attack is caught even when the link
    # itself isn't on the denylist.
    abs_user = out if out.is_absolute() else out.absolute()
    for candidate in {str(abs_user), str(resolved)}:
        for prefix in _DANGEROUS_PREFIXES:
            if candidate == prefix or candidate.startswith(prefix + "/"):
                raise StructuredBaseError(
                    StructuredError(
                        error=ErrorCode.PARAMETER_INVALID,
                        message="Invalid output_dir",
                        reason=f"output_dir resolves to a system directory: {candidate}",
                        suggestions=[
                            "Choose a path under your home or a temp directory",
                            "Or set BINARY_MCP_ALLOWED_DIRS to an explicit allow-list",
                        ],
                        debug_info={"output_dir": str(out), "resolved": str(resolved)},
                    )
                )

    return resolved


def _default_carve_dir() -> Path:
    """
    Resolve the default carving cache root.

    Mirrors pdb_fetcher._default_symbol_cache():
      - $BINARY_MCP_CARVE_DIR if set
      - Windows: ~/.binary_mcp_cache/carved
      - POSIX:   ${XDG_CACHE_HOME:-~/.cache}/binary_mcp/carved
    """
    explicit = os.environ.get("BINARY_MCP_CARVE_DIR")
    if explicit:
        return Path(explicit).expanduser()
    if sys.platform == "win32":
        return Path.home() / ".binary_mcp_cache" / "carved"
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "binary_mcp" / "carved"


# --- Orchestrator ---


def carve(
    binary_path: str | Path,
    output_dir: Path | None = None,
    *,
    max_total_mb: int = DEFAULT_MAX_TOTAL_MB,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> CarvingResult:
    """
    Carve embedded blobs from a PE's resource directory and overlay.

    Args:
        binary_path: Path to the PE file.
        output_dir: Output directory for flagged blobs. If None, defaults to
            ``_default_carve_dir() / <binary_sha256>``.
        max_total_mb: Total carved-byte budget. Once exceeded, remaining
            flagged blobs are recorded in the result but not written to disk.
        max_depth: Resource-tree recursion cap.

    Returns:
        CarvingResult with the per-blob table.

    Raises:
        StructuredBaseError: For invalid binary_path, malformed PE, invalid
            output_dir, or output_dir mkdir failure.
    """
    import pefile

    from src.utils.security import (
        FileSizeError,
        PathTraversalError,
        get_allowed_dirs,
        sanitize_binary_path,
    )
    from src.utils.structured_errors import (
        ErrorCode,
        StructuredBaseError,
        StructuredError,
    )

    try:
        sanitized = sanitize_binary_path(
            str(binary_path), allowed_dirs=get_allowed_dirs()
        )
    except (PathTraversalError, FileSizeError, FileNotFoundError, ValueError) as e:
        raise StructuredBaseError(
            StructuredError(
                error=ErrorCode.PARAMETER_INVALID,
                message="Invalid binary path",
                reason=str(e),
                suggestions=["Provide an absolute path to an existing PE file"],
                debug_info={"binary_path": str(binary_path)},
            )
        ) from e

    raw = Path(sanitized).read_bytes()
    binary_sha256 = hashlib.sha256(raw).hexdigest()

    if output_dir is None:
        # Default cache dir is host-controlled, not user-controlled; bypass
        # the user-input validator.
        out = _default_carve_dir() / binary_sha256
    else:
        out = _validate_output_dir(Path(output_dir).expanduser())

    if max_total_mb <= 0:
        raise StructuredBaseError(
            StructuredError(
                error=ErrorCode.PARAMETER_INVALID,
                message="Invalid max_total_mb",
                reason=f"max_total_mb must be > 0, got {max_total_mb}",
                debug_info={"max_total_mb": max_total_mb},
            )
        )

    try:
        pe = pefile.PE(str(sanitized), fast_load=True)
    except pefile.PEFormatError as e:
        raise StructuredBaseError(
            StructuredError(
                error=ErrorCode.PARAMETER_INVALID,
                message="Not a valid PE file",
                reason=str(e),
                suggestions=["Verify the file is a Windows PE binary"],
                debug_info={"binary_path": str(sanitized)},
            )
        ) from e

    try:
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("parse_data_directories(RESOURCE) raised: %s", e)

        # Collect candidate chunks first (cheap), then process in order.
        chunks: list[tuple[str, str, int, bytes]] = []

        for path, file_off, size in walk_resources(pe, max_depth=max_depth):
            if size <= 0:
                continue
            if file_off < 0 or file_off + size > len(raw):
                logger.debug("resource %s out of bounds (off=%d size=%d)", path, file_off, size)
                continue
            chunks.append(("resource", path, file_off, raw[file_off : file_off + size]))

        overlay_off = pe.get_overlay_data_start_offset()
        if overlay_off is not None and 0 <= overlay_off < len(raw):
            overlay_data = raw[overlay_off:]
            if overlay_data:
                chunks.append(("overlay", "", int(overlay_off), overlay_data))

        result = CarvingResult(
            binary_path=str(sanitized),
            binary_sha256=binary_sha256,
            output_dir=str(out),
        )
        budget = max_total_mb * 1024 * 1024
        spent = 0
        out_created = False

        for source, rpath, foff, data in chunks:
            sha256 = hashlib.sha256(data).hexdigest()
            detected_type, description, entropy, reasons = classify_blob(data)
            flagged = bool(reasons)
            written_path: str | None = None
            skip_reason: str | None = None

            if flagged:
                if spent + len(data) > budget:
                    skip_reason = f"max_total_mb={max_total_mb} budget reached"
                    if not result.truncated:
                        result.truncated = True
                        result.truncated_reason = skip_reason
                else:
                    if not out_created:
                        try:
                            out.mkdir(parents=True, exist_ok=True)
                            out_created = True
                        except OSError as e:
                            raise StructuredBaseError(
                                StructuredError(
                                    error=ErrorCode.OPERATION_FAILED,
                                    message="Failed to create output_dir",
                                    reason=str(e),
                                    debug_info={"output_dir": str(out)},
                                )
                            ) from e
                    target = out / sha256
                    sidecar = out / f"{sha256}.json"
                    # Atomic create-or-fail: O_EXCL closes the TOCTOU window
                    # in the previous "if target.exists(): ... else: write"
                    # pattern. 0o600 keeps potentially-malicious payloads
                    # readable only by the owning user.
                    try:
                        fd = os.open(
                            str(target),
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                            0o600,
                        )
                    except FileExistsError:
                        written_path = str(target)
                        skip_reason = "exists (no overwrite)"
                    else:
                        wrote_blob = False
                        try:
                            with os.fdopen(fd, "wb") as f:
                                f.write(data)
                            wrote_blob = True
                            written_path = str(target)
                            spent += len(data)
                        except OSError as e:
                            skip_reason = f"write failed: {e}"
                            try:
                                target.unlink()
                            except OSError:
                                pass

                        if wrote_blob:
                            # Atomic sidecar create -- if a sidecar already
                            # exists at this sha256, leave it alone (honours
                            # the never-overwrite contract for both blob and
                            # metadata).
                            try:
                                sfd = os.open(
                                    str(sidecar),
                                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                    0o600,
                                )
                            except FileExistsError:
                                logger.debug(
                                    "sidecar already exists, leaving it: %s",
                                    sidecar,
                                )
                            else:
                                try:
                                    with os.fdopen(sfd, "w", encoding="utf-8") as f:
                                        json.dump(
                                            {
                                                "source": source,
                                                "resource_path": rpath,
                                                "file_offset": foff,
                                                "size": len(data),
                                                "sha256": sha256,
                                                "detected_type": detected_type,
                                                "detected_description": description,
                                                "entropy": round(entropy, 4),
                                                "flag_reasons": list(reasons),
                                                "parent_binary": str(sanitized),
                                                "parent_sha256": binary_sha256,
                                            },
                                            f,
                                            indent=2,
                                        )
                                except OSError as e:
                                    logger.debug("sidecar write failed: %s", e)
                                    try:
                                        sidecar.unlink()
                                    except OSError:
                                        pass

            result.blobs.append(
                CarvedBlob(
                    source=source,
                    resource_path=rpath,
                    file_offset=foff,
                    size=len(data),
                    sha256=sha256,
                    detected_type=detected_type,
                    detected_description=description,
                    entropy=entropy,
                    flagged=flagged,
                    flag_reasons=tuple(reasons),
                    written_path=written_path,
                    write_skipped_reason=skip_reason,
                )
            )

        result.total_extracted_bytes = spent
        return result
    finally:
        pe.close()


# --- Markdown rendering ---


def render_markdown(result: CarvingResult) -> str:
    """Render a CarvingResult as a markdown report with blob table."""
    lines: list[str] = [
        "Embedded Binary Carving",
        f"Binary: {Path(result.binary_path).name}",
        f"SHA-256: {result.binary_sha256}",
        f"Output dir: {result.output_dir}",
        f"Blobs found: {len(result.blobs)}",
        f"Total extracted: {result.total_extracted_bytes} bytes",
    ]
    if result.truncated:
        lines.append(f"WARNING: extraction truncated -- {result.truncated_reason}")
    lines.append("")

    if not result.blobs:
        lines.append("No embedded blobs detected.")
        return "\n".join(lines)

    lines.append(
        "| # | Source | Path | Offset | Size | SHA-256 | Type | Entropy | Flagged | Written |"
    )
    lines.append(
        "|---|--------|------|--------|------|---------|------|---------|---------|---------|"
    )
    for i, b in enumerate(result.blobs, 1):
        path_label = b.resource_path or "(overlay)"
        sha_short = b.sha256[:12]
        if b.flagged:
            flagged_label = ", ".join(b.flag_reasons)
        else:
            flagged_label = "no"

        if b.written_path and not b.write_skipped_reason:
            written_label = "yes"
        elif b.written_path and b.write_skipped_reason:
            written_label = f"yes [{b.write_skipped_reason}]"
        elif b.write_skipped_reason:
            written_label = f"no ({b.write_skipped_reason})"
        else:
            written_label = "no"

        lines.append(
            f"| {i} | {b.source} | {path_label} | 0x{b.file_offset:X} | "
            f"{b.size} | {sha_short} | {b.detected_type} | {b.entropy:.2f} | "
            f"{flagged_label} | {written_label} |"
        )
    return "\n".join(lines)
