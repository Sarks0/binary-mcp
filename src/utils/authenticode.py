"""
Authenticode (PKCS#7) signature inspection for PE files.

Implements:
- Authentihash computation per the Microsoft "Windows Authenticode Portable
  Executable Signature Format" specification. Hashes everything in the file
  EXCEPT the OptionalHeader.CheckSum (4 bytes), the security entry in the
  data-directory (8 bytes at index 4), and the certificate table itself.
- WIN_CERTIFICATE / PKCS#7 SignedData parsing via asn1crypto, surfacing
  signer CN, full issuer chain, embedded SpcIndirectDataContent.messageDigest
  for Authentihash comparison, and any RFC3161 / legacy counter-signature.

References:
- https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx
- RFC 5652 (CMS), RFC 3161 (Time-Stamp Protocol)
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Microsoft Authenticode OIDs
SPC_INDIRECT_DATA_OID = "1.3.6.1.4.1.311.2.1.4"
MS_RFC3161_COUNTERSIGNATURE_OID = "1.3.6.1.4.1.311.3.3.1"
PKCS9_COUNTERSIGNATURE_OID = "1.2.840.113549.1.9.6"
PKCS9_MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4"

# WIN_CERTIFICATE.wCertificateType
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002

# Hard cap on the security-directory blob size. Real-world Authenticode
# signatures top out around ~80 KB even with full timestamp chains; 16 MB
# is generous headroom for legitimate edge cases (multi-sig builds, deep
# counter-signatures) while still bounding asn1crypto's parse cost on
# malformed or hostile inputs.
MAX_PKCS7_BYTES = 16 * 1024 * 1024


# --- Dataclasses ---


@dataclass
class CertInfo:
    """One certificate in a signature chain."""

    subject_cn: str
    issuer_cn: str
    serial_hex: str
    not_before: datetime | None
    not_after: datetime | None
    sha256: str
    sha1: str


@dataclass
class TimestampInfo:
    """RFC3161 or legacy PKCS#9 counter-signature timestamp."""

    kind: str  # "rfc3161" | "legacy"
    tsa_cn: str | None
    time: datetime | None
    chain: list[CertInfo] = field(default_factory=list)


@dataclass
class AuthenticodeSignature:
    """Parsed PKCS#7 SignedData from a PE security directory."""

    signer_cn: str
    signer_serial_hex: str
    signer_issuer_cn: str
    signer_not_before: datetime | None
    signer_not_after: datetime | None
    digest_algorithm: str
    embedded_message_digest: bytes
    # Tri-state describing the embedded SpcIndirectDataContent message-digest
    # extraction result:
    #   "parsed"      -> embedded_message_digest holds the real digest bytes
    #   "missing"     -> no SpcIndirectDataContent / no embedded digest present
    #   "parse_error" -> a signature blob is present but the embedded digest
    #                    could not be extracted (treated as tampered upstream)
    digest_status: str = "parsed"
    chain: list[CertInfo] = field(default_factory=list)
    timestamp: TimestampInfo | None = None


# --- Authentihash ---


def _hash_pe_regions(
    data: bytes,
    *,
    checksum_offset: int,
    security_dir_entry_offset: int,
    cert_offset: int,
    cert_size: int,
    digest: str,
) -> bytes:
    """
    Hash a PE file per the Authenticode spec, given precomputed field offsets.

    Hashes:
      [0, checksum_offset)
      [checksum_offset + 4, security_dir_entry_offset)
      [security_dir_entry_offset + 8, cert_offset) if signed, else to EOF
      [cert_offset + cert_size, EOF)             if signed

    Args:
        data: Raw PE file bytes.
        checksum_offset: File offset of OptionalHeader.CheckSum (4-byte field).
        security_dir_entry_offset: File offset of DATA_DIRECTORY[4]
            (the 8-byte security entry: VirtualAddress + Size).
        cert_offset: File offset of the WIN_CERTIFICATE table (== security
            directory's VirtualAddress, which is a *file offset*, not an RVA).
            Pass 0 for unsigned files.
        cert_size: Size of the certificate table in bytes. Pass 0 for unsigned.
        digest: hashlib digest name (e.g. "sha1", "sha256").

    Returns:
        Raw digest bytes.

    Raises:
        ValueError: If the offset/size ranges are inconsistent or out of bounds.
    """
    n = len(data)
    if not 0 < checksum_offset < n:
        raise ValueError(f"checksum_offset {checksum_offset} out of range (file size {n})")
    if not checksum_offset + 4 <= security_dir_entry_offset < n:
        raise ValueError(
            f"security_dir_entry_offset {security_dir_entry_offset} not after checksum"
        )
    if security_dir_entry_offset + 8 > n:
        raise ValueError("security data-directory entry extends past EOF")

    h = hashlib.new(digest)
    h.update(data[:checksum_offset])
    h.update(data[checksum_offset + 4 : security_dir_entry_offset])

    after_dd = security_dir_entry_offset + 8
    if cert_offset and cert_size:
        if cert_offset < after_dd:
            raise ValueError(
                f"cert_offset {cert_offset} overlaps security DD entry"
            )
        if cert_offset + cert_size > n:
            raise ValueError(
                f"cert table {cert_offset}+{cert_size} extends past EOF ({n})"
            )
        h.update(data[after_dd:cert_offset])
        h.update(data[cert_offset + cert_size :])
    else:
        h.update(data[after_dd:])

    return h.digest()


def compute_authentihash(pe: Any, *, digest: str = "sha256") -> bytes:
    """
    Compute the Authentihash of a parsed PE.

    Args:
        pe: A pefile.PE instance (must have OPTIONAL_HEADER and __data__).
        digest: hashlib digest name. Use the algorithm advertised by the
            embedded PKCS#7 SignerInfo for round-trip comparison.

    Returns:
        Raw digest bytes.
    """
    checksum_offset = pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum")
    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    sec_dir_offset = security_dir.get_file_offset()
    return _hash_pe_regions(
        bytes(pe.__data__),
        checksum_offset=checksum_offset,
        security_dir_entry_offset=sec_dir_offset,
        cert_offset=security_dir.VirtualAddress,
        cert_size=security_dir.Size,
        digest=digest,
    )


# --- WIN_CERTIFICATE + PKCS#7 parsing ---


def _strip_win_certificate(blob: bytes) -> tuple[int, bytes] | None:
    """
    Strip the 8-byte WIN_CERTIFICATE header and return (cert_type, payload).

    Returns None if blob is too short or malformed.
    """
    if len(blob) < 8:
        return None
    import struct

    dw_length, _w_revision, w_cert_type = struct.unpack_from("<IHH", blob, 0)
    if dw_length < 8 or dw_length > len(blob):
        return None
    return w_cert_type, blob[8:dw_length]


def _cert_info(cert: Any) -> CertInfo:
    """Build a CertInfo from an asn1crypto.x509.Certificate."""
    der = cert.dump()
    try:
        subject_cn = cert.subject.native.get("common_name", str(cert.subject.human_friendly))
    except Exception:
        subject_cn = str(cert.subject.human_friendly)
    try:
        issuer_cn = cert.issuer.native.get("common_name", str(cert.issuer.human_friendly))
    except Exception:
        issuer_cn = str(cert.issuer.human_friendly)
    serial = cert["tbs_certificate"]["serial_number"].native
    serial_hex = format(serial, "x") if isinstance(serial, int) else str(serial)
    validity = cert["tbs_certificate"]["validity"]
    return CertInfo(
        subject_cn=str(subject_cn),
        issuer_cn=str(issuer_cn),
        serial_hex=serial_hex,
        not_before=validity["not_before"].native,
        not_after=validity["not_after"].native,
        sha256=hashlib.sha256(der).hexdigest(),
        sha1=hashlib.sha1(der).hexdigest(),  # noqa: S324  (fingerprint, not crypto)
    )


def _find_signer_cert(signer_info: Any, certs: list[Any]) -> Any | None:
    """Match SignerInfo.sid against the candidate cert set."""
    sid = signer_info["sid"]
    name = sid.name
    if name == "issuer_and_serial_number":
        target_serial = sid.chosen["serial_number"].native
        target_issuer = sid.chosen["issuer"]
        for c in certs:
            if (
                c["tbs_certificate"]["serial_number"].native == target_serial
                and c["tbs_certificate"]["issuer"] == target_issuer
            ):
                return c
    elif name == "subject_key_identifier":
        target = sid.chosen.native
        for c in certs:
            for ext in c["tbs_certificate"]["extensions"] or []:
                if ext["extn_id"].native == "key_identifier":
                    if ext["extn_value"].parsed.native == target:
                        return c
    return None


def _ordered_chain(signer_cert: Any | None, all_certs: list[Any]) -> list[Any]:
    """Order certs starting at the signer and walking up by issuer match."""
    if signer_cert is None:
        return list(all_certs)
    by_subject: dict[bytes, Any] = {c.subject.dump(): c for c in all_certs}
    chain = [signer_cert]
    seen: set[bytes] = {signer_cert.subject.dump()}
    cur = signer_cert
    while True:
        issuer_key = cur.issuer.dump()
        nxt = by_subject.get(issuer_key)
        if nxt is None or nxt.subject.dump() in seen:
            break
        chain.append(nxt)
        seen.add(nxt.subject.dump())
        if nxt.subject.dump() == nxt.issuer.dump():  # self-signed root
            break
        cur = nxt
    return chain


class _MissingAuthenticodeDigestError(Exception):
    """Raised when there is no SpcIndirectDataContent at all (vs malformed)."""


def _extract_authenticode_message_digest(signed_data: Any) -> tuple[str, bytes]:
    """
    Extract the digest algorithm + Authentihash bytes embedded inside
    SpcIndirectDataContent. Returns (algo_name, digest_bytes).

    Raises:
        _MissingAuthenticodeDigestError: encapContentInfo does not carry the
            Authenticode SpcIndirectDataContent OID -- there is no embedded
            digest to extract. Callers should treat this as "missing" rather
            than "parse_error".
        Exception: any other failure (malformed inner ASN.1, etc.) bubbles
            out as a normal exception and should be treated as "parse_error".
    """
    from asn1crypto import algos
    from asn1crypto.core import Any as Asn1Any
    from asn1crypto.core import ObjectIdentifier, Sequence

    class _SpcAttr(Sequence):
        _fields = [
            ("type", ObjectIdentifier),
            ("value", Asn1Any, {"optional": True}),
        ]

    class _SpcIndirectDataContent(Sequence):
        _fields = [
            ("data", _SpcAttr),
            ("message_digest", algos.DigestInfo),
        ]

    encap = signed_data["encap_content_info"]
    content_type = encap["content_type"].native
    if content_type != SPC_INDIRECT_DATA_OID:
        raise _MissingAuthenticodeDigestError(
            f"unexpected encapContentInfo OID {content_type} (want SpcIndirectDataContent)"
        )
    content = encap["content"]
    inner = content.parsed if hasattr(content, "parsed") and content.parsed else content
    if isinstance(inner, bytes):
        spc_bytes = inner
    else:
        try:
            spc_bytes = inner.contents
        except AttributeError:
            spc_bytes = inner.dump()
            if spc_bytes[:1] in (b"\x04",):  # OCTET STRING tag
                # Strip outer tag/length to get inner SEQUENCE
                from asn1crypto.parser import parse

                _, _, _, _, spc_bytes = parse(spc_bytes)
    spc = _SpcIndirectDataContent.load(spc_bytes)
    algo = spc["message_digest"]["digest_algorithm"]["algorithm"].native
    md = spc["message_digest"]["digest"].native
    return algo, md


def _parse_rfc3161_timestamp(token_bytes: bytes) -> TimestampInfo | None:
    """Parse an RFC3161 timeStampToken (a CMS SignedData wrapping TSTInfo)."""
    try:
        from asn1crypto import cms, tsp
    except Exception:
        return None
    try:
        outer = cms.ContentInfo.load(token_bytes)
        if outer["content_type"].native != "signed_data":
            return None
        sd = outer["content"]
        encap = sd["encap_content_info"]
        if encap["content_type"].native != "tst_info":
            return None
        tst_bytes = encap["content"].parsed if hasattr(encap["content"], "parsed") else None
        if tst_bytes is None:
            inner = encap["content"]
            tst_bytes = inner.contents if hasattr(inner, "contents") else bytes(inner)
        if isinstance(tst_bytes, (bytes, bytearray)):
            tst = tsp.TSTInfo.load(bytes(tst_bytes))
        else:
            tst = tst_bytes  # already parsed
        gen_time = tst["gen_time"].native
        certs = [c.chosen for c in (sd["certificates"] or []) if c.name == "certificate"]
        signer_infos = sd["signer_infos"]
        signer_cert = None
        if len(signer_infos):
            signer_cert = _find_signer_cert(signer_infos[0], certs)
        chain_certs = _ordered_chain(signer_cert, certs)
        chain = [_cert_info(c) for c in chain_certs]
        tsa_cn = chain[0].subject_cn if chain else None
        return TimestampInfo(kind="rfc3161", tsa_cn=tsa_cn, time=gen_time, chain=chain)
    except Exception as e:
        logger.debug("RFC3161 timestamp parse failed: %s", e)
        return None


def _parse_legacy_countersignature(
    counter_signer_info: Any, outer_certs: list[Any]
) -> TimestampInfo | None:
    """Parse a PKCS#9 counterSignature SignerInfo (legacy timestamp format)."""
    try:
        signer_cert = _find_signer_cert(counter_signer_info, outer_certs)
        chain_certs = _ordered_chain(signer_cert, outer_certs)
        chain = [_cert_info(c) for c in chain_certs]
        # signing-time attribute (PKCS#9, OID 1.2.840.113549.1.9.5)
        signing_time = None
        for attr in counter_signer_info["signed_attrs"] or []:
            if attr["type"].native == "signing_time":
                signing_time = attr["values"][0].native
                break
        tsa_cn = chain[0].subject_cn if chain else None
        return TimestampInfo(kind="legacy", tsa_cn=tsa_cn, time=signing_time, chain=chain)
    except Exception as e:
        logger.debug("Legacy counter-signature parse failed: %s", e)
        return None


def _extract_timestamp(signer_info: Any, outer_certs: list[Any]) -> TimestampInfo | None:
    """Walk SignerInfo.unsignedAttrs for either RFC3161 or legacy timestamps."""
    from asn1crypto import cms

    unsigned = signer_info["unsigned_attrs"]
    if unsigned is None or len(unsigned) == 0:
        return None
    for attr in unsigned:
        oid = attr["type"].dotted
        if oid == MS_RFC3161_COUNTERSIGNATURE_OID:
            try:
                # asn1crypto's .dump() returns the full DER-encoded value
                # including the outer tag and length, which is what
                # cms.ContentInfo.load() expects. Do NOT use .contents:
                # for Any-wrapped CMS values .contents returns only the
                # inner-value octets, stripping the outer tag, and the
                # subsequent ContentInfo.load() silently fails (token is
                # then discarded by the broad-except), losing RFC3161
                # timestamps entirely.
                value = attr["values"][0]
                token_bytes = value.dump()
                ts = _parse_rfc3161_timestamp(token_bytes)
                if ts is None and hasattr(value, "parsed") and value.parsed is not None:
                    # Fallback: some asn1crypto versions wrap the token in an
                    # Any whose .dump() is the wrapped form; .parsed.dump()
                    # is the inner ContentInfo's DER.
                    try:
                        ts = _parse_rfc3161_timestamp(value.parsed.dump())
                    except Exception as e:
                        logger.debug("RFC3161 .parsed.dump() fallback failed: %s", e)
                if ts is not None:
                    return ts
            except Exception as e:
                logger.debug("MS RFC3161 attr parse failed: %s", e)
        elif oid == PKCS9_COUNTERSIGNATURE_OID:
            try:
                # values are SignerInfo
                cs_value = attr["values"][0]
                if isinstance(cs_value, cms.SignerInfo):
                    return _parse_legacy_countersignature(cs_value, outer_certs)
                # Re-parse via SignerInfo
                cs = cms.SignerInfo.load(cs_value.dump())
                return _parse_legacy_countersignature(cs, outer_certs)
            except Exception as e:
                logger.debug("Legacy CS attr parse failed: %s", e)
    return None


def parse_pkcs7(cert_table_blob: bytes) -> AuthenticodeSignature | None:
    """
    Parse a WIN_CERTIFICATE blob from DATA_DIRECTORY[4] and return signer info.

    Args:
        cert_table_blob: The bytes of the certificate table, including the
            8-byte WIN_CERTIFICATE header.

    Returns:
        AuthenticodeSignature, or None if the blob is malformed or carries a
        non-PKCS#7 certificate type.
    """
    stripped = _strip_win_certificate(cert_table_blob)
    if stripped is None:
        return None
    cert_type, pkcs7_blob = stripped
    if cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA:
        logger.info("WIN_CERTIFICATE type=0x%04x is not PKCS#7 SignedData", cert_type)
        return None

    from asn1crypto import cms

    try:
        outer = cms.ContentInfo.load(pkcs7_blob)
    except Exception as e:
        logger.debug("ContentInfo.load failed: %s", e)
        return None
    if outer["content_type"].native != "signed_data":
        return None

    signed_data = outer["content"]
    cert_set = signed_data["certificates"]
    certs = [c.chosen for c in (cert_set or []) if c.name == "certificate"]
    signer_infos = signed_data["signer_infos"]
    if len(signer_infos) == 0:
        return None
    signer_info = signer_infos[0]

    digest_algo = signed_data["digest_algorithms"][0]["algorithm"].native
    digest_status: str
    try:
        spc_algo, embedded_md = _extract_authenticode_message_digest(signed_data)
        digest_status = "parsed"
    except _MissingAuthenticodeDigestError as e:
        # No SpcIndirectDataContent at all -- nothing to compare against,
        # so this is "no embedded Authenticode digest", NOT tampering.
        logger.debug("No SpcIndirectDataContent present: %s", e)
        spc_algo, embedded_md = digest_algo, b""
        digest_status = "missing"
    except Exception as e:
        # Something *was* present but we could not parse it. This is exactly
        # the malicious-tamper case the broad-except used to silently swallow:
        # report it explicitly so callers can flag tampered=True.
        logger.debug("Authenticode message-digest extraction failed: %s", e)
        spc_algo, embedded_md = digest_algo, b""
        digest_status = "parse_error"

    signer_cert = _find_signer_cert(signer_info, certs)
    chain_certs = _ordered_chain(signer_cert, certs)
    chain = [_cert_info(c) for c in chain_certs]

    if signer_cert is not None:
        info = _cert_info(signer_cert)
        signer_cn = info.subject_cn
        signer_issuer_cn = info.issuer_cn
        signer_serial_hex = info.serial_hex
        not_before = info.not_before
        not_after = info.not_after
    else:
        signer_cn = "<embedded signer cert not present>"
        signer_issuer_cn = ""
        signer_serial_hex = ""
        not_before = None
        not_after = None

    timestamp = _extract_timestamp(signer_info, certs)

    return AuthenticodeSignature(
        signer_cn=signer_cn,
        signer_serial_hex=signer_serial_hex,
        signer_issuer_cn=signer_issuer_cn,
        signer_not_before=not_before,
        signer_not_after=not_after,
        digest_algorithm=spc_algo or digest_algo,
        embedded_message_digest=bytes(embedded_md),
        digest_status=digest_status,
        chain=chain,
        timestamp=timestamp,
    )


# --- Orchestration ---


def inspect(binary_path: str | Path) -> dict[str, Any]:
    """
    Inspect a PE file's Authenticode signature.

    Returns a dict suitable for both structured consumers and markdown rendering.
    Never raises for "no signature" — that is a successful result with
    `signed=False`. Raises StructuredBaseError for malformed input.
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
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 4:
            return {
                "binary_path": str(sanitized),
                "signed": False,
                "reason": "no security data directory present",
            }

        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if sec_dir.VirtualAddress == 0 or sec_dir.Size == 0:
            return {
                "binary_path": str(sanitized),
                "signed": False,
                "reason": "no security data directory present",
            }

        data = bytes(pe.__data__)
        cert_offset = sec_dir.VirtualAddress
        cert_size = sec_dir.Size
        if cert_size > MAX_PKCS7_BYTES:
            raise StructuredBaseError(
                StructuredError(
                    error=ErrorCode.PARAMETER_INVALID,
                    message="Certificate table is too large",
                    reason=(
                        f"cert_size={cert_size} exceeds the "
                        f"{MAX_PKCS7_BYTES}-byte cap; refusing to parse."
                    ),
                    suggestions=[
                        "File may be malformed or carry a hostile signature blob",
                        "Inspect the security data-directory entry manually",
                    ],
                    debug_info={
                        "cert_size": cert_size,
                        "max": MAX_PKCS7_BYTES,
                        "cert_offset": cert_offset,
                    },
                )
            )
        if cert_offset + cert_size > len(data):
            raise StructuredBaseError(
                StructuredError(
                    error=ErrorCode.OPERATION_FAILED,
                    message="Certificate table extends past end of file",
                    reason="security DATA_DIRECTORY entry references bytes outside the file",
                    suggestions=["File may be truncated or corrupted"],
                    debug_info={
                        "cert_offset": cert_offset,
                        "cert_size": cert_size,
                        "file_size": len(data),
                    },
                )
            )

        cert_blob = data[cert_offset : cert_offset + cert_size]
        signature = parse_pkcs7(cert_blob)
        if signature is None:
            return {
                "binary_path": str(sanitized),
                "signed": True,
                "parsed": False,
                "reason": "WIN_CERTIFICATE present but is not parseable PKCS#7 SignedData",
                "cert_offset": cert_offset,
                "cert_size": cert_size,
            }

        algo = signature.digest_algorithm
        try:
            computed = compute_authentihash(pe, digest=algo)
        except (ValueError, KeyError) as e:
            raise StructuredBaseError(
                StructuredError(
                    error=ErrorCode.OPERATION_FAILED,
                    message="Failed to compute Authentihash",
                    reason=str(e),
                    suggestions=["File header offsets are inconsistent"],
                    debug_info={"algorithm": algo},
                )
            ) from e

        embedded = signature.embedded_message_digest
        status = signature.digest_status  # "parsed" | "missing" | "parse_error"
        match = status == "parsed" and computed == embedded
        # Tampered semantics:
        #   "parsed"      -> tampered iff computed != embedded
        #   "missing"     -> no embedded digest to compare; NOT tampered
        #   "parse_error" -> signature blob exists but we couldn't extract the
        #                    embedded digest -> treat as tampered (a malformed
        #                    SpcIndirectDataContent is exactly how an attacker
        #                    would try to make tampering "silently pass")
        if status == "parsed":
            tampered = not match
        elif status == "parse_error":
            tampered = True
        else:  # "missing"
            tampered = False

        return {
            "binary_path": str(sanitized),
            "signed": True,
            "parsed": True,
            "signature_digest_status": status,
            "signature": {
                "signer_cn": signature.signer_cn,
                "signer_issuer_cn": signature.signer_issuer_cn,
                "signer_serial_hex": signature.signer_serial_hex,
                "not_before": signature.signer_not_before,
                "not_after": signature.signer_not_after,
                "digest_algorithm": signature.digest_algorithm,
                "chain": [_cert_info_to_dict(c) for c in signature.chain],
                "timestamp": _timestamp_to_dict(signature.timestamp),
            },
            "authentihash": {
                "algorithm": algo,
                "computed_hex": computed.hex(),
                "embedded_hex": embedded.hex(),
                "match": match,
                "tampered": tampered,
            },
        }
    finally:
        pe.close()


def _cert_info_to_dict(c: CertInfo) -> dict[str, Any]:
    return {
        "subject_cn": c.subject_cn,
        "issuer_cn": c.issuer_cn,
        "serial_hex": c.serial_hex,
        "not_before": c.not_before,
        "not_after": c.not_after,
        "sha256": c.sha256,
        "sha1": c.sha1,
    }


def _timestamp_to_dict(t: TimestampInfo | None) -> dict[str, Any] | None:
    if t is None:
        return None
    return {
        "kind": t.kind,
        "tsa_cn": t.tsa_cn,
        "time": t.time,
        "chain": [_cert_info_to_dict(c) for c in t.chain],
    }


# --- Markdown rendering ---


def _fmt_dt(d: datetime | None) -> str:
    if d is None:
        return "<none>"
    try:
        return d.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    except Exception:
        return str(d)


def render_markdown(result: dict[str, Any]) -> str:
    """Render an `inspect()` result as a markdown report."""
    lines: list[str] = ["Authenticode Signature", f"File: {Path(result['binary_path']).name}", ""]

    if not result.get("signed"):
        lines.append("Signed: no")
        if result.get("reason"):
            lines.append(f"Reason: {result['reason']}")
        return "\n".join(lines)

    if not result.get("parsed", False):
        lines.append("Signed: yes (signature present, but not parseable)")
        if result.get("reason"):
            lines.append(f"Reason: {result['reason']}")
        if "cert_offset" in result:
            lines.append(
                f"Cert table: offset=0x{result['cert_offset']:X}, size={result['cert_size']}"
            )
        return "\n".join(lines)

    sig = result["signature"]
    ah = result["authentihash"]

    lines.append("Signed: yes")
    lines.append(f"Signer CN: {sig['signer_cn']}")
    lines.append(f"Issuer CN: {sig['signer_issuer_cn']}")
    lines.append(f"Serial: {sig['signer_serial_hex']}")
    lines.append(
        f"Validity: {_fmt_dt(sig['not_before'])} -> {_fmt_dt(sig['not_after'])}"
    )
    lines.append(f"Digest Algorithm: {sig['digest_algorithm']}")
    lines.append("")

    chain = sig.get("chain") or []
    if chain:
        lines.append("Issuer Chain:")
        for i, c in enumerate(chain, 1):
            lines.append(f"  {i}. CN={c['subject_cn']} -- issuer={c['issuer_cn']}")
        lines.append("")

        lines.append("Certificate SHA-256 (for VT/CT-log pivoting):")
        for i, c in enumerate(chain, 1):
            label = "signer" if i == 1 else ("root" if i == len(chain) else f"int. {i - 1}")
            lines.append(f"  [{label:>9}] {c['sha256']}")
        lines.append("")

    ts = sig.get("timestamp")
    if ts:
        lines.append(f"Counter-signature ({ts['kind']}):")
        if ts.get("tsa_cn"):
            lines.append(f"  TSA: {ts['tsa_cn']}")
        if ts.get("time"):
            lines.append(f"  Time: {_fmt_dt(ts['time'])}")
        lines.append("")

    lines.append("Authentihash:")
    lines.append(f"  Algorithm: {ah['algorithm']}")
    lines.append(f"  Computed:  {ah['computed_hex']}")
    lines.append(f"  Embedded:  {ah['embedded_hex'] or '<none>'}")
    if ah.get("tampered"):
        lines.append("  Match:     NO  (tampering detected — file bytes differ from signed image)")
    elif ah.get("match"):
        lines.append("  Match:     yes (no tampering detected)")
    else:
        lines.append("  Match:     <embedded message-digest unavailable>")

    return "\n".join(lines)
