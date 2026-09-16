"""
Hash validation shared by every provider that addresses files by digest.

Audit note: the original ``vt_tools`` validated a hash by LENGTH alone --
``len(h) not in (32, 40, 64)`` -- and then interpolated it into a request
path. Any 32/40/64-character string containing ``/``, ``?`` or ``#`` passed
that check and could address a different endpoint on the provider's API. Both
callers now share this one implementation so the mistake cannot be re-made
independently in a third.
"""

import re

#: MD5, SHA-1 or SHA-256, lower-case hex, anchored.
_ANY_HASH_RE = re.compile(r"\A(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")

#: YARAify additionally accepts a SHA3-384 digest.
_SHA3_384_RE = re.compile(r"\A[0-9a-f]{96}\Z")
_ANY_HASH_WITH_SHA3_RE = re.compile(
    r"\A(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{96})\Z"
)


def normalise_hash(
    file_hash: str,
    *,
    sha256_only: bool = False,
    allow_sha3_384: bool = False,
) -> str:
    """
    Lower-case, strip and validate a file hash used as a provider object id.

    Args:
        file_hash: MD5, SHA-1 or SHA-256 (plus SHA3-384 when allowed).
        sha256_only: Enforce SHA-256, which some endpoints require.
        allow_sha3_384: Also accept a 96-character SHA3-384 digest.

    Returns:
        The canonical lower-case hash.

    Raises:
        ValueError: If the value is not a hex digest of an accepted length.
            The message is a validation message the model needs in order to
            correct its own call, so it is deliberately specific (audit F-10
            keeps this class of message); it quotes no host state.
    """
    candidate = (file_hash or "").strip().lower()

    if sha256_only:
        pattern, expected = _SHA256_RE, "a hex SHA256 (64 characters)"
    elif allow_sha3_384:
        pattern = _ANY_HASH_WITH_SHA3_RE
        expected = "a hex MD5 (32), SHA1 (40), SHA256 (64) or SHA3-384 (96)"
    else:
        pattern, expected = _ANY_HASH_RE, "a hex MD5 (32), SHA1 (40) or SHA256 (64)"

    if not pattern.match(candidate):
        raise ValueError(
            f"Invalid hash: {len(candidate)} characters. Expected {expected} "
            "with no other characters."
        )
    return candidate
