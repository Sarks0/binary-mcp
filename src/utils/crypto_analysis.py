"""
Crypto analysis utilities for detecting and decrypting encrypted payloads.

Provides tools for:
- Entropy calculation
- XOR key detection and brute-force
- Base64 detection and decoding
- Common encryption pattern detection
"""

import base64
import logging
import math
from collections import Counter
from pathlib import Path

logger = logging.getLogger(__name__)


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.

    Args:
        data: Bytes to analyze

    Returns:
        Entropy in bits per byte (0-8 scale)
        - 0: All same bytes
        - ~4.5: English text
        - ~7.5-8: Encrypted/compressed data
    """
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def detect_base64(data: bytes) -> dict:
    """
    Detect if data is Base64 encoded.

    Args:
        data: Bytes to analyze

    Returns:
        Detection result with confidence and decoded data
    """
    result = {
        "detected": False,
        "confidence": 0.0,
        "decoded": None,
        "decoded_entropy": None
    }

    # Check if data looks like Base64
    try:
        text = data.decode('ascii', errors='ignore')
        # Remove whitespace
        text = ''.join(text.split())

        if not text:
            return result

        # Base64 character set check
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        text_chars = set(text)

        if not text_chars.issubset(valid_chars):
            return result

        # Length check (Base64 length should be divisible by 4)
        if len(text) % 4 != 0:
            # Try padding
            text += '=' * (4 - len(text) % 4)

        # Try decoding
        decoded = base64.b64decode(text)
        decoded_entropy = calculate_entropy(decoded)

        # Calculate confidence based on character distribution and successful decode
        char_ratio = len(text_chars) / len(valid_chars)
        confidence = 0.5 + (char_ratio * 0.3)

        # Higher confidence if decoded data has lower entropy (likely plaintext)
        if decoded_entropy < 6.0:
            confidence += 0.2

        result["detected"] = True
        result["confidence"] = min(confidence, 1.0)
        result["decoded"] = decoded
        result["decoded_entropy"] = decoded_entropy

    except Exception as e:
        logger.debug(f"Base64 detection failed: {e}")

    return result


def analyze_xor(
    data: bytes,
    key_length_range: tuple[int, int] = (1, 16),
    top_n: int = 5
) -> list[dict]:
    """
    Analyze XOR-encrypted data and find likely keys.

    Uses frequency analysis to find probable XOR keys.

    Args:
        data: Encrypted bytes
        key_length_range: Range of key lengths to try (min, max)
        top_n: Number of top candidates to return

    Returns:
        List of candidate keys with confidence scores
    """
    candidates = []
    min_len, max_len = key_length_range

    for key_len in range(min_len, min(max_len + 1, 17)):  # Cap at 16 for performance
        # For each key length, analyze byte positions
        key_bytes = []
        confidence_sum = 0

        for pos in range(key_len):
            # Get all bytes at this position in the key cycle
            pos_bytes = bytes(data[i] for i in range(pos, len(data), key_len))

            if not pos_bytes:
                continue

            # Find most likely XOR key byte using frequency analysis
            # In English text, space (0x20) is most common
            # XOR with 0x20 should give us the key byte
            best_key_byte = None
            best_score = -1

            for candidate_key in range(256):
                decrypted = bytes(b ^ candidate_key for b in pos_bytes)

                # Score based on printable ASCII ratio
                printable = sum(1 for b in decrypted if 32 <= b < 127)
                score = printable / len(decrypted)

                # Bonus for common characters
                for common in b' etaoinshrdlu':
                    score += decrypted.count(common) * 0.01

                if score > best_score:
                    best_score = score
                    best_key_byte = candidate_key

            key_bytes.append(best_key_byte)
            confidence_sum += best_score

        if key_bytes:
            key = bytes(key_bytes)
            avg_confidence = confidence_sum / len(key_bytes)

            # Decrypt sample for verification
            decrypted_sample = xor_decrypt(data[:100], key)
            sample_entropy = calculate_entropy(decrypted_sample)

            # Lower entropy after decryption = higher confidence
            if sample_entropy < 6.0:
                avg_confidence += 0.2

            candidates.append({
                "key": key,
                "key_hex": key.hex().upper(),
                "key_length": key_len,
                "confidence": min(avg_confidence, 1.0),
                "decrypted_sample": decrypted_sample[:50],
                "sample_entropy": sample_entropy
            })

    # Sort by confidence
    candidates.sort(key=lambda x: x["confidence"], reverse=True)
    return candidates[:top_n]


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    """
    Decrypt data using XOR with repeating key.

    Args:
        data: Encrypted data
        key: XOR key

    Returns:
        Decrypted data
    """
    if not key:
        return data

    key_len = len(key)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))


def detect_crypto_patterns(data: bytes) -> list[dict]:
    """
    Detect encryption/encoding patterns in data.

    Analyzes data for common crypto patterns:
    - XOR encryption
    - Base64 encoding
    - RC4-like patterns
    - High entropy (encrypted/compressed)

    Args:
        data: Bytes to analyze

    Returns:
        List of detected patterns with confidence scores
    """
    patterns = []

    # Overall entropy
    entropy = calculate_entropy(data)

    # Check for Base64
    b64_result = detect_base64(data)
    if b64_result["detected"]:
        patterns.append({
            "type": "base64",
            "confidence": b64_result["confidence"],
            "details": {
                "decoded_length": len(b64_result["decoded"]) if b64_result["decoded"] else 0,
                "decoded_entropy": b64_result["decoded_entropy"]
            }
        })

    # Check for single-byte XOR
    xor_candidates = analyze_xor(data, key_length_range=(1, 1))
    if xor_candidates and xor_candidates[0]["confidence"] > 0.5:
        candidate = xor_candidates[0]
        patterns.append({
            "type": "xor_single_byte",
            "confidence": candidate["confidence"],
            "details": {
                "key": candidate["key_hex"],
                "sample_entropy": candidate["sample_entropy"]
            }
        })

    # Check for multi-byte XOR
    xor_candidates = analyze_xor(data, key_length_range=(2, 8))
    if xor_candidates and xor_candidates[0]["confidence"] > 0.5:
        candidate = xor_candidates[0]
        patterns.append({
            "type": "xor_multi_byte",
            "confidence": candidate["confidence"],
            "details": {
                "key_length": candidate["key_length"],
                "key": candidate["key_hex"],
                "sample_entropy": candidate["sample_entropy"]
            }
        })

    # High entropy suggests encryption
    if entropy > 7.5:
        patterns.append({
            "type": "high_entropy",
            "confidence": min((entropy - 7.0) / 1.0, 1.0),
            "details": {
                "entropy": entropy,
                "likely": "encrypted or compressed"
            }
        })

    # Check for null byte patterns (might indicate Unicode or padding)
    null_count = data.count(b'\x00')
    if null_count > len(data) * 0.2:
        patterns.append({
            "type": "null_bytes",
            "confidence": null_count / len(data),
            "details": {
                "null_ratio": null_count / len(data),
                "likely": "UTF-16 or padded data"
            }
        })

    # Sort by confidence
    patterns.sort(key=lambda x: x["confidence"], reverse=True)
    return patterns


def try_common_xor_keys(data: bytes) -> list[dict]:
    """
    Try XOR decryption with common malware keys.

    Args:
        data: Encrypted data

    Returns:
        List of successful decryptions
    """
    common_keys = [
        b'\x00',
        b'\xff',
        b'\xaa',
        b'\x55',
        b'0',
        b'\xde\xad\xbe\xef',
        b'\xca\xfe\xba\xbe',
        b'\x41',  # 'A'
        b'\x90',  # NOP
        b'\xcc',  # INT3
    ]

    results = []

    for key in common_keys:
        decrypted = xor_decrypt(data, key)
        entropy = calculate_entropy(decrypted)

        # Check if decryption looks successful
        if entropy < 6.0:  # Lower entropy = more likely plaintext
            # Check for PE header
            if decrypted[:2] == b'MZ':
                results.append({
                    "key": key.hex().upper(),
                    "type": "PE executable",
                    "entropy": entropy,
                    "confidence": 0.95
                })
            # Check for printable text
            elif all(32 <= b < 127 or b in (9, 10, 13) for b in decrypted[:50]):
                results.append({
                    "key": key.hex().upper(),
                    "type": "ASCII text",
                    "entropy": entropy,
                    "confidence": 0.7
                })

    return results


def analyze_file(file_path: str) -> dict:
    """
    Comprehensive crypto analysis of a file.

    Args:
        file_path: Path to file

    Returns:
        Analysis results
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    data = path.read_bytes()

    return {
        "file": str(path),
        "size": len(data),
        "entropy": calculate_entropy(data),
        "patterns": detect_crypto_patterns(data),
        "common_key_matches": try_common_xor_keys(data[:1024]),  # Sample
        "xor_analysis": analyze_xor(data[:10000], top_n=3)  # Sample
    }
