#!/usr/bin/env python3
"""
Generate secure authentication token for Binary MCP remote access.

This script generates a cryptographically secure bearer token suitable
for MCP_AUTH_TOKEN configuration. Tokens are:
- High entropy (256+ bits)
- URL-safe (no special characters that break URLs)
- Minimum 32 characters (configurable)

Usage:
    python scripts/generate_token.py
    python scripts/generate_token.py --length 64
    python scripts/generate_token.py --validate existing_token
"""

import argparse
import secrets
import sys

# Ensure src is in path for imports
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

from src.utils.auth import generate_secure_token, verify_token_strength


def main():
    parser = argparse.ArgumentParser(
        description="Generate or validate authentication tokens for Binary MCP"
    )
    parser.add_argument(
        "--length",
        type=int,
        default=48,
        help="Token length (default: 48, minimum: 32)",
    )
    parser.add_argument(
        "--validate",
        metavar="TOKEN",
        help="Validate an existing token instead of generating",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of tokens to generate (default: 1)",
    )

    args = parser.parse_args()

    if args.validate:
        # Validate existing token
        print("=" * 60)
        print("TOKEN VALIDATION")
        print("=" * 60)

        result = verify_token_strength(args.validate)

        print(f"Token: {args.validate[:20]}...")
        print(f"Length: {result['length']} characters")
        print(f"Effective Entropy: {result['entropy_bits']:.0f} bits")
        print(f"Character Diversity: {result['character_diversity']}/4")
        print(f"Unique Char Ratio: {result['unique_char_ratio'] * 100:.1f}%")

        if result["is_strong"]:
            print("\n✅ Token is STRONG")
        else:
            print("\n⚠️  Token has WEAKNESSES:")
            for issue in result["issues"]:
                print(f"   - {issue}")

        print("=" * 60)
        sys.exit(0 if result["is_strong"] else 1)

    # Generate new token(s)
    print("=" * 60)
    print("BINARY MCP - SECURE TOKEN GENERATOR")
    print("=" * 60)
    print()

    # Enforce minimum length
    length = max(32, args.length)
    if length != args.length:
        print(f"Note: Adjusted length to {length} (minimum 32)\n")

    tokens = []
    for i in range(args.count):
        token = generate_secure_token(length)
        tokens.append(token)

        # Validate the generated token
        result = verify_token_strength(token)

        if args.count > 1:
            print(f"Token {i + 1}:")
        else:
            print("Generated Token:")

        print(f"  {token}")
        print(f"  Length: {len(token)} chars")
        print(f"  Entropy: {result['entropy_bits']:.0f} bits")
        print()

    print("=" * 60)
    print("CONFIGURATION")
    print("=" * 60)
    print()
    print("Add this to your .env file:")
    print()
    print("# Binary MCP Authentication")
    print("MCP_TRANSPORT=sse")
    print("MCP_HOST=0.0.0.0")
    print("MCP_ALLOW_REMOTE=true")
    print(f"MCP_AUTH_TOKEN={tokens[0]}")
    print()
    print("=" * 60)
    print("SECURITY RECOMMENDATIONS")
    print("=" * 60)
    print()
    print("1. Keep this token SECRET - it grants full access to your MCP server")
    print("2. Set restrictive file permissions on .env: chmod 600 .env")
    print("3. Use TLS in production (MCP_TLS_MODE=self_signed or cert_file)")
    print("4. Configure IP allowlist if possible (MCP_ALLOWED_IPS=your.network/24)")
    print("5. Review audit logs regularly (MCP_AUDIT_LOG_PATH)")
    print()
    print("For VM/host setup:")
    print("  - VM: Set the token in ~/.env or environment variable")
    print("  - Host: Claude Desktop config needs the token in Authorization header")
    print()

    # Security warning for large count
    if args.count > 1:
        print("=" * 60)
        print("WARNING: Multiple tokens generated")
        print("Only use one token per server - store others securely")
        print("=" * 60)

    # Save to file option
    save = input("\nSave to .env file? (y/N): ").lower().strip()
    if save in ("y", "yes"):
        env_path = __import__("pathlib").Path(".env")

        # Read existing
        if env_path.exists():
            with open(env_path, "r") as f:
                existing = f.read()
        else:
            existing = ""

        # Check if token already exists
        if "MCP_AUTH_TOKEN=" in existing:
            overwrite = (
                input("MCP_AUTH_TOKEN already exists in .env. Overwrite? (y/N): ").lower().strip()
            )
            if overwrite not in ("y", "yes"):
                print("Skipped. Token not saved.")
                return

            # Replace existing token
            import re

            existing = re.sub(r"MCP_AUTH_TOKEN=.*\n?", f"MCP_AUTH_TOKEN={tokens[0]}\n", existing)
        else:
            # Append token
            existing += f"\n# Generated by generate_token.py\nMCP_AUTH_TOKEN={tokens[0]}\n"

        with open(env_path, "w") as f:
            f.write(existing)

        # Set restrictive permissions
        import os

        os.chmod(env_path, 0o600)

        print(f"✓ Saved to {env_path} (permissions: 600)")


if __name__ == "__main__":
    main()
