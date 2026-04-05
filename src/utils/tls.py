"""
TLS certificate management for secure remote MCP access.

Provides:
- TLS certificate loading and validation
- Self-signed certificate generation for development/testing
- ACME/Let's Encrypt support (future)
- Certificate chain validation
- Strong TLS configuration (TLS 1.2+, cipher suites)

Security requirements:
- TLS 1.2 minimum (TLS 1.3 preferred)
- Strong cipher suites only
- Certificate validation mandatory for remote
- No insecure fallback allowed
"""

from __future__ import annotations

import datetime
import logging
import ssl
from enum import Enum
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.utils.config import get_config, get_config_bool, is_remote_host

logger = logging.getLogger(__name__)


class TLSMode(Enum):
    """TLS operation modes."""

    DISABLED = "disabled"  # No TLS (stdio only recommended)
    SELF_SIGNED = "self_signed"  # Auto-generated self-signed cert
    CERT_FILE = "cert_file"  # User-provided certificate
    AUTO_TLS = "auto_tls"  # Future: ACME/Let's Encrypt


class TLSConfigurationError(Exception):
    """TLS configuration error."""

    pass


class TLSValidationError(Exception):
    """TLS certificate validation error."""

    pass


# Strong TLS configuration
MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_2
RECOMMENDED_TLS_VERSION = ssl.TLSVersion.TLSv1_3

# Secure cipher suites (TLS 1.2)
# No weak ciphers, no RC4, no 3DES, no MD5, no SHA1 for MAC
SECURE_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!SHA1"


def create_ssl_context(
    cert_file: Path | None = None,
    key_file: Path | None = None,
    require_client_cert: bool = False,
    min_version: ssl.TLSVersion = MIN_TLS_VERSION,
) -> ssl.SSLContext:
    """
    Create secure SSL context for MCP server.

    Args:
        cert_file: Path to certificate file
        key_file: Path to private key file
        require_client_cert: Whether to require client certificates (mTLS)
        min_version: Minimum TLS version

    Returns:
        Configured SSL context

    Raises:
        TLSConfigurationError: If configuration is invalid
    """
    # Create context with strong defaults
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Set minimum version
    context.minimum_version = min_version

    # Strong cipher configuration
    context.set_ciphers(SECURE_CIPHERS)

    # Disable compression (CRIME attack)
    context.options |= ssl.OP_NO_COMPRESSION

    # Disable TLS 1.0/1.1 if possible
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1

    # Enable post-handshake authentication for mTLS
    if require_client_cert:
        context.verify_mode = ssl.CERT_REQUIRED
        context.post_handshake_auth = True
    else:
        context.verify_mode = ssl.CERT_NONE  # Server doesn't verify clients

    # Load certificate and key
    if cert_file and key_file:
        try:
            context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
            logger.info(f"Loaded TLS certificate from {cert_file}")
        except ssl.SSLError as e:
            raise TLSConfigurationError(f"Failed to load TLS certificate: {e}")

    return context


def generate_self_signed_cert(
    hostname: str, output_dir: Path, validity_days: int = 365, key_size: int = 4096
) -> tuple[Path, Path]:
    """
    Generate self-signed certificate for development/testing.

    WARNING: Self-signed certificates provide encryption but not authentication.
    They are vulnerable to MITM attacks. Use only for:
    - Local development
    - Trusted network segments
    - When you distribute the certificate out-of-band

    For production, use proper PKI or Let's Encrypt.

    Args:
        hostname: Server hostname/IP
        output_dir: Directory to save certificate and key
        validity_days: Certificate validity period
        key_size: RSA key size (minimum 2048, recommend 4096)

    Returns:
        Tuple of (cert_path, key_path)

    Raises:
        TLSConfigurationError: If generation fails
    """
    if key_size < 2048:
        raise TLSConfigurationError("Key size must be at least 2048 bits")

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Make certificate directory accessible only to owner
    import os

    os.chmod(output_dir, 0o700)

    cert_path = output_dir / "server.crt"
    key_path = output_dir / "server.key"

    # Check if already exists
    if cert_path.exists() and key_path.exists():
        # Validate existing certificate
        try:
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())

            # Check if still valid
            now = datetime.datetime.now(datetime.UTC)
            if cert.not_valid_after_utc > now:
                logger.info(
                    f"Using existing self-signed certificate (valid until {cert.not_valid_after_utc})"
                )
                return (cert_path, key_path)
            else:
                logger.warning("Existing certificate expired, regenerating...")
        except Exception as e:
            logger.warning(f"Could not read existing certificate: {e}, regenerating...")

    try:
        # Generate RSA key
        logger.info(f"Generating {key_size}-bit RSA key...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        # Subject and issuer (self-signed, so same)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Binary MCP Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ]
        )

        # Subject Alternative Names (important for IP addresses)
        san_list = [x509.DNSName(hostname)]

        # Also add as IPAddress if hostname looks like IP
        try:
            import ipaddress

            ip = ipaddress.ip_address(hostname)
            san_list.append(x509.IPAddress(ip))
        except ValueError:
            pass  # Not an IP address

        san = x509.SubjectAlternativeName(san_list)

        # Build certificate
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(san, critical=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Write private key (secure permissions)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with open(key_path, "wb") as f:
            f.write(key_pem)
        os.chmod(key_path, 0o600)  # Owner read/write only

        # Write certificate
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        with open(cert_path, "wb") as f:
            f.write(cert_pem)
        os.chmod(cert_path, 0o644)  # World-readable (public cert)

        logger.info("Generated self-signed certificate:")
        logger.info(f"  Certificate: {cert_path}")
        logger.info(f"  Private Key: {key_path}")
        logger.info(f"  Valid: {now} to {cert.not_valid_after_utc}")
        logger.info(f"  Hostname: {hostname}")
        logger.warning(
            "SECURITY WARNING: Self-signed certificate - verify fingerprint out-of-band!"
        )
        logger.warning(f"SHA-256 Fingerprint: {cert.fingerprint(hashes.SHA256()).hex()}")

        return (cert_path, key_path)

    except Exception as e:
        raise TLSConfigurationError(f"Failed to generate certificate: {e}")


def validate_certificate(cert_path: Path, key_path: Path) -> dict[str, Any]:
    """
    Validate certificate file and key.

    Args:
        cert_path: Path to certificate
        key_path: Path to private key

    Returns:
        Validation report dictionary

    Raises:
        TLSValidationError: If validation fails
    """
    errors = []
    warnings = []
    info = {}

    # Check files exist
    if not cert_path.exists():
        raise TLSValidationError(f"Certificate file not found: {cert_path}")
    if not key_path.exists():
        raise TLSValidationError(f"Key file not found: {key_path}")

    # Check permissions on private key
    import stat

    key_stat = key_path.stat()
    key_mode = stat.filemode(key_stat.st_mode)

    # Check if key is readable by others (security issue)
    if key_stat.st_mode & stat.S_IROTH or key_stat.st_mode & stat.S_IWOTH:
        errors.append(f"Private key {key_path} is readable by others (mode: {key_mode})")

    try:
        # Load certificate
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        # Load key
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)

        # Verify key matches certificate
        cert_pubkey = cert.public_key()
        if hasattr(key, "public_key"):
            key_pubkey = key.public_key()

            # Compare public key numbers
            if hasattr(cert_pubkey, "public_numbers") and hasattr(key_pubkey, "public_numbers"):
                if cert_pubkey.public_numbers() != key_pubkey.public_numbers():
                    errors.append("Private key does not match certificate public key")

        # Check certificate validity
        now = datetime.datetime.now(datetime.UTC)

        if now < cert.not_valid_before_utc:
            errors.append(f"Certificate not yet valid (valid from {cert.not_valid_before_utc})")

        if now > cert.not_valid_after_utc:
            errors.append(f"Certificate expired on {cert.not_valid_after_utc}")

        # Check expiration warning (30 days)
        days_until_expiry = (cert.not_valid_after_utc - now).days
        if days_until_expiry < 30:
            warnings.append(f"Certificate expires in {days_until_expiry} days")

        # Certificate info
        info = {
            "subject": str(cert.subject),
            "issuer": str(cert.issuer),
            "valid_from": cert.not_valid_before_utc.isoformat(),
            "valid_until": cert.not_valid_after_utc.isoformat(),
            "days_until_expiry": days_until_expiry,
            "serial_number": str(cert.serial_number),
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "signature_algorithm": cert.signature_algorithm_oid._name,
        }

        # Check for weak signature algorithm
        weak_algorithms = ["md5", "sha1"]
        if any(weak in info["signature_algorithm"].lower() for weak in weak_algorithms):
            warnings.append(f"Weak signature algorithm: {info['signature_algorithm']}")

        # Check key size
        if hasattr(key, "key_size"):
            info["key_size"] = key.key_size
            if key.key_size < 2048:
                errors.append(f"Weak key size: {key.key_size} bits (minimum 2048)")
            elif key.key_size < 4096:
                warnings.append(f"Key size {key.key_size} bits (recommend 4096)")

    except Exception as e:
        errors.append(f"Certificate parsing error: {e}")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "info": info,
    }


def get_tls_configuration_from_config() -> tuple[TLSMode, ssl.SSLContext | None]:
    """
    Load TLS configuration from environment/config.

    Returns:
        Tuple of (TLS mode, SSL context or None)

    Raises:
        TLSConfigurationError: If TLS is required but not configured
    """
    mode_str = get_config("MCP_TLS_MODE", "disabled")

    try:
        mode = TLSMode(mode_str)
    except ValueError:
        raise TLSConfigurationError(f"Invalid TLS mode: {mode_str}")

    # Check if TLS is required for remote
    transport = get_config("MCP_TRANSPORT", "stdio")
    host = get_config("MCP_HOST", "127.0.0.1")
    allow_remote = get_config_bool("MCP_ALLOW_REMOTE", False)
    require_tls_remote = get_config_bool("MCP_TLS_REQUIRED_FOR_REMOTE", True)

    is_remote = transport != "stdio" and (is_remote_host(host) or allow_remote)

    if is_remote and require_tls_remote and mode == TLSMode.DISABLED:
        raise TLSConfigurationError(
            "TLS is required for remote access. "
            "Set MCP_TLS_MODE=self_signed for auto-generated cert, "
            "or provide MCP_TLS_CERT_PATH/MCP_TLS_KEY_PATH. "
            "To explicitly disable (INSECURE), set MCP_TLS_REQUIRED_FOR_REMOTE=false"
        )

    if mode == TLSMode.DISABLED:
        logger.warning("TLS is disabled - connections will be unencrypted!")
        return (mode, None)

    if mode == TLSMode.SELF_SIGNED:
        # Generate or use existing self-signed cert
        cert_dir = Path.home() / ".binary_mcp_output" / "tls"

        # Get hostname from config or detect
        hostname = host if host != "0.0.0.0" else "localhost"

        try:
            cert_path, key_path = generate_self_signed_cert(hostname, cert_dir)
            context = create_ssl_context(cert_path, key_path)
            logger.info(f"Using self-signed TLS certificate for {hostname}")
            return (mode, context)
        except Exception as e:
            raise TLSConfigurationError(f"Failed to generate self-signed certificate: {e}")

    if mode == TLSMode.CERT_FILE:
        # Load user-provided certificate
        cert_path_str = get_config("MCP_TLS_CERT_PATH")
        key_path_str = get_config("MCP_TLS_KEY_PATH")

        if not cert_path_str or not key_path_str:
            raise TLSConfigurationError(
                "MCP_TLS_MODE=cert_file requires MCP_TLS_CERT_PATH and MCP_TLS_KEY_PATH"
            )

        cert_path = Path(cert_path_str)
        key_path = Path(key_path_str)

        # Validate certificate
        validation = validate_certificate(cert_path, key_path)
        if not validation["valid"]:
            raise TLSConfigurationError(
                f"Certificate validation failed: {', '.join(validation['errors'])}"
            )

        for warning in validation["warnings"]:
            logger.warning(f"Certificate warning: {warning}")

        context = create_ssl_context(cert_path, key_path)
        logger.info(f"Loaded TLS certificate: {validation['info'].get('subject', 'unknown')}")
        return (mode, context)

    if mode == TLSMode.AUTO_TLS:
        # Future: ACME/Let's Encrypt
        raise TLSConfigurationError("AUTO_TLS not yet implemented (coming in future release)")

    return (mode, None)


def get_certificate_fingerprint(cert_path: Path) -> str | None:
    """
    Get SHA-256 fingerprint of certificate.

    Args:
        cert_path: Path to certificate

    Returns:
        Hex fingerprint string
    """
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        return None


def print_security_warning(tls_mode: TLSMode, host: str, port: int) -> None:
    """
    Print security warnings for remote access configuration.

    Args:
        tls_mode: TLS configuration mode
        host: Listen host
        port: Listen port
    """
    if is_remote_host(host):
        print("\n" + "=" * 70)
        print("SECURITY WARNING: Remote Access Enabled")
        print("=" * 70)

        if tls_mode == TLSMode.DISABLED:
            print("⚠️  TLS is DISABLED - all traffic is UNENCRYPTED!")
            print("   Anyone on the network can intercept and modify traffic.")
            print("   This should ONLY be used on trusted networks.")
        elif tls_mode == TLSMode.SELF_SIGNED:
            print("ℹ️  Using self-signed certificate.")
            print("   Clients must verify the certificate fingerprint out-of-band.")
            print("   Vulnerable to MITM if fingerprint is not verified.")

        print(f"\n   Listening on: {host}:{port}")
        print(f"   TLS Mode: {tls_mode.value}")
        print("\n   Authentication: Bearer token required")
        print("   (Set MCP_AUTH_TOKEN in .env)")
        print("=" * 70 + "\n")
