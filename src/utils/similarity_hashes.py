"""
Similarity / clustering hashes for PE files.

Computes the four cheap signals analysts pivot on in VirusTotal and YARA:
- imphash               (toolchain + import-set cluster)
- rich_hash             (md5 of the un-XORed Rich header bytes; Mandiant/Yara
                         standard. We deliberately hash ``RICH_HEADER.clear_data``
                         rather than ``raw_data`` so the result is consistent
                         across files built with the same toolchain.)
- authentihash_sha256   (full Authenticode hash regardless of signing)
- per-section sha256    (one entry per PE section)
- ssdeep / tlsh         (full-file fuzzy hashes; optional)

ssdeep and python-tlsh wrap native libraries; both are gated behind
``try/except ImportError`` so the tool degrades gracefully when those wheels
are not installed.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# --- Dataclasses ---


@dataclass(frozen=True)
class SectionHash:
    name: str
    size: int
    sha256: str


@dataclass
class SimilarityHashes:
    binary_path: str
    binary_size: int
    file_sha256: str
    imphash: str | None = None
    rich_hash: str | None = None
    authentihash_sha256: str | None = None
    section_hashes: list[SectionHash] = field(default_factory=list)
    ssdeep: str | None = None
    tlsh: str | None = None
    fuzzy_unavailable: list[str] = field(default_factory=list)


# --- Hash computers ---


def compute_imphash(pe: Any) -> str | None:
    """Return pe.get_imphash() or None when the binary has no imports."""
    try:
        h = pe.get_imphash()
    except Exception as e:  # noqa: BLE001
        logger.debug("get_imphash raised: %s", e)
        return None
    return h or None


def compute_rich_hash(pe: Any) -> str | None:
    """
    Return md5(RICH_HEADER.clear_data) -- the Mandiant / Yara standard.

    ``clear_data`` is the un-XORed canonical Rich-header byte sequence; the
    hash is therefore consistent across any binaries built with the same
    Microsoft-toolchain version mix, which is what makes it useful for
    clustering. ``raw_data`` (which is XORed with a per-file checksum key)
    would produce a different hash for every file -- avoid.
    """
    rich = getattr(pe, "RICH_HEADER", None)
    if not rich:
        return None
    clear = getattr(rich, "clear_data", None)
    if not clear:
        return None
    return hashlib.md5(clear).hexdigest()  # noqa: S324  (clustering, not crypto)


def compute_section_hashes(pe: Any) -> list[SectionHash]:
    """One SectionHash per PE section: name, size, sha256(get_data())."""
    out: list[SectionHash] = []
    for section in getattr(pe, "sections", []) or []:
        try:
            name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
        except Exception:  # noqa: BLE001
            name = "<unknown>"
        try:
            data = section.get_data()
        except Exception as e:  # noqa: BLE001
            logger.debug("section %s get_data() failed: %s", name, e)
            continue
        out.append(
            SectionHash(
                name=name,
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
            )
        )
    return out


def compute_fuzzy(file_bytes: bytes) -> tuple[str | None, str | None, list[str]]:
    """
    Best-effort fuzzy hashing.

    Returns ``(ssdeep_hash, tlsh_hash, unavailable_names)``. Each component is
    None on ImportError or compute failure; the unavailable list lets callers
    surface "install ssdeep" hints in their output.
    """
    unavailable: list[str] = []

    ssdeep_hash: str | None = None
    try:
        import ssdeep  # type: ignore[import-not-found]
    except ImportError:
        unavailable.append("ssdeep")
    else:
        try:
            ssdeep_hash = ssdeep.hash(file_bytes)
        except Exception as e:  # noqa: BLE001
            logger.debug("ssdeep.hash raised: %s", e)
            ssdeep_hash = None

    tlsh_hash: str | None = None
    try:
        import tlsh  # type: ignore[import-not-found]
    except ImportError:
        unavailable.append("tlsh")
    else:
        try:
            # tlsh.hash returns "" for inputs < 50 bytes or low-entropy data.
            raw = tlsh.hash(file_bytes)
            tlsh_hash = raw or None
        except Exception as e:  # noqa: BLE001
            logger.debug("tlsh.hash raised: %s", e)
            tlsh_hash = None

    return ssdeep_hash, tlsh_hash, unavailable


# --- Orchestrator ---


def compute(binary_path: str | Path) -> SimilarityHashes:
    """
    Compute every similarity hash for a PE.

    Raises:
        StructuredBaseError: For invalid path or non-PE input. Never raises
            for "no rich header" / "no imports" / "fuzzy lib missing" -- those
            simply leave the corresponding fields ``None``.
    """
    import pefile

    from src.utils.authenticode import compute_authentihash
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
    file_sha256 = hashlib.sha256(raw).hexdigest()

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
        # imphash needs imports parsed
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("parse_data_directories(IMPORT) raised: %s", e)

        imphash = compute_imphash(pe)
        rich_hash = compute_rich_hash(pe)
        section_hashes = compute_section_hashes(pe)

        try:
            authentihash = compute_authentihash(pe, digest="sha256").hex()
        except Exception as e:  # noqa: BLE001
            logger.warning("compute_authentihash failed: %s", e)
            authentihash = None

        ssdeep_hash, tlsh_hash, unavailable = compute_fuzzy(raw)

        return SimilarityHashes(
            binary_path=str(sanitized),
            binary_size=len(raw),
            file_sha256=file_sha256,
            imphash=imphash,
            rich_hash=rich_hash,
            authentihash_sha256=authentihash,
            section_hashes=section_hashes,
            ssdeep=ssdeep_hash,
            tlsh=tlsh_hash,
            fuzzy_unavailable=unavailable,
        )
    finally:
        pe.close()


# --- Markdown ---


def _vt_line(label: str, value: str | None, vt_key: str) -> str:
    if not value:
        return f"  {label:<22} <none>"
    return f"  {label:<22} {value}\n  {' ':<22} VT search: {vt_key}:{value}"


def render_markdown(result: SimilarityHashes) -> str:
    """Render a SimilarityHashes as a markdown report with VT pivot hints."""
    lines: list[str] = [
        "Similarity / Clustering Hashes",
        f"Binary: {Path(result.binary_path).name}",
        f"Size: {result.binary_size} bytes",
        f"SHA-256: {result.file_sha256}",
        "",
        "Cluster hashes:",
        _vt_line("imphash:", result.imphash, "imphash"),
        _vt_line("rich_hash:", result.rich_hash, "rich_pe_hash"),
        _vt_line("authentihash:", result.authentihash_sha256, "authentihash"),
        _vt_line("ssdeep:", result.ssdeep, "ssdeep"),
        _vt_line("tlsh:", result.tlsh, "tlsh"),
        "",
    ]

    if result.section_hashes:
        lines.append("Section hashes:")
        lines.append("| Name | Size | SHA-256 |")
        lines.append("|------|------|---------|")
        for s in result.section_hashes:
            lines.append(f"| {s.name} | {s.size} | {s.sha256} |")
        lines.append("")
    else:
        lines.append("Section hashes: <none>")
        lines.append("")

    if result.fuzzy_unavailable:
        missing = ", ".join(result.fuzzy_unavailable)
        lines.append(
            f"Note: fuzzy hashing libs unavailable ({missing}). "
            "Install with `pip install ssdeep python-tlsh` "
            "(may require libfuzzy / libtlsh system packages) to enable."
        )

    return "\n".join(lines)
