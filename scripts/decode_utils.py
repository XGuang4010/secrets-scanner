#!/usr/bin/env python3
"""
Decode utilities for secrets-scanner AI Agent.

Provides convenient functions for common decoding operations
that AI needs when analyzing potential secrets.

Usage:
    from decode_utils import decode_jwt, calculate_entropy, is_base64

Or command line:
    python3 decode_utils.py jwt "eyJhbGciOiJIUzI1NiJ9..."
    python3 decode_utils.py entropy "AKIAIOSFODNN7EXAMPLE"
"""

import base64
import json
import math
import sys
import urllib.parse
from typing import Dict, Optional, Tuple


def decode_base64(data: str) -> Optional[str]:
    """Decode standard Base64 string."""
    try:
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        decoded = base64.b64decode(data)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def decode_base64url(data: str) -> Optional[str]:
    """Decode Base64URL string (used in JWT)."""
    try:
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        decoded = base64.urlsafe_b64decode(data)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def decode_jwt(token: str) -> Optional[Dict]:
    """
    Decode JWT token without verification.
    
    Returns dict with 'header', 'payload', 'signature' keys.
    Returns None if token is not valid JWT format.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    
    header_b64, payload_b64, signature = parts
    
    result = {}
    
    # Decode header
    header_json = decode_base64url(header_b64)
    if header_json:
        try:
            result["header"] = json.loads(header_json)
        except json.JSONDecodeError:
            result["header_raw"] = header_json
    
    # Decode payload
    payload_json = decode_base64url(payload_b64)
    if payload_json:
        try:
            result["payload"] = json.loads(payload_json)
        except json.JSONDecodeError:
            result["payload_raw"] = payload_json
    
    result["signature"] = signature[:20] + "..." if len(signature) > 20 else signature
    result["is_truncated"] = len(token) < 50  # Likely truncated if too short
    
    return result


def is_valid_jwt(token: str) -> bool:
    """Check if string looks like a valid JWT (has valid header)."""
    decoded = decode_jwt(token)
    if not decoded:
        return False
    header = decoded.get("header", {})
    return "alg" in header and "typ" in header


def is_truncated_jwt(token: str) -> bool:
    """Check if JWT appears truncated (ends with ... or too short)."""
    if "..." in token or "\u00b7\u00b7\u00b7" in token:
        return True
    parts = token.split(".")
    if len(parts) != 3:
        return True
    # Valid JWT parts are usually >100 chars each
    if len(parts[0]) < 10 or len(parts[1]) < 10:
        return True
    return False


def decode_hex(data: str) -> Optional[str]:
    """Decode hex string to ASCII."""
    try:
        # Remove spaces and 0x prefix
        cleaned = data.replace(" ", "").replace("0x", "")
        if len(cleaned) % 2 != 0:
            return None
        decoded = bytes.fromhex(cleaned)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def url_decode(data: str) -> str:
    """URL decode string."""
    return urllib.parse.unquote(data)


def calculate_entropy(data: str) -> Tuple[float, float, float]:
    """
    Calculate Shannon entropy of a string.
    
    Returns:
        (entropy, max_possible, normalized)
        - entropy: Shannon entropy in bits
        - max_possible: Maximum possible entropy for string length
        - normalized: entropy / max_possible (0.0 to 1.0)
    """
    if not data:
        return 0.0, 0.0, 0.0
    
    entropy = 0.0
    length = len(data)
    unique_chars = set(data)
    
    for char in unique_chars:
        p_x = float(data.count(char)) / length
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    
    max_possible = math.log2(length) if length > 1 else 1.0
    normalized = entropy / math.log2(max(len(unique_chars), 2))
    
    return entropy, max_possible, normalized


def is_base64(data: str) -> bool:
    """Check if string looks like base64 encoded data."""
    # Base64 chars
    base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if not all(c in base64_chars for c in data):
        return False
    
    # Length should be multiple of 4 (with padding)
    if len(data) % 4 != 0:
        return False
    
    # Should have reasonable length
    if len(data) < 4:
        return False
    
    # Try decoding
    decoded = decode_base64(data)
    return decoded is not None


def analyze_secret(secret: str) -> Dict:
    """
    Comprehensive analysis of a potential secret string.
    
    Returns dict with various analysis results.
    """
    result = {
        "length": len(secret),
        "entropy": None,
        "is_base64": False,
        "is_jwt": False,
        "is_truncated_jwt": False,
        "decoded_jwt": None,
        "is_hex": False,
        "decoded_hex": None,
    }
    
    # Entropy
    ent, max_ent, norm = calculate_entropy(secret)
    result["entropy"] = {
        "bits": round(ent, 4),
        "max_possible": round(max_ent, 4),
        "normalized": round(norm, 4),
    }
    
    # Check base64
    result["is_base64"] = is_base64(secret)
    
    # Check JWT
    result["is_jwt"] = is_valid_jwt(secret)
    result["is_truncated_jwt"] = is_truncated_jwt(secret)
    if result["is_jwt"]:
        result["decoded_jwt"] = decode_jwt(secret)
    
    # Check hex
    result["is_hex"] = all(c in "0123456789abcdefABCDEF" for c in secret) and len(secret) % 2 == 0
    if result["is_hex"]:
        result["decoded_hex"] = decode_hex(secret)
    
    return result


def main():
    if len(sys.argv) < 3:
        print("Usage: decode_utils.py <command> <data>")
        print("")
        print("Commands:")
        print("  jwt <token>        Decode JWT token")
        print("  b64 <string>       Base64 decode")
        print("  b64url <string>    Base64URL decode")
        print("  hex <string>       Hex decode")
        print("  url <string>       URL decode")
        print("  entropy <string>   Calculate entropy")
        print("  analyze <string>   Full analysis")
        sys.exit(1)
    
    cmd = sys.argv[1]
    data = sys.argv[2]
    
    if cmd == "jwt":
        result = decode_jwt(data)
        if result:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print("ERROR: Not a valid JWT token", file=sys.stderr)
            sys.exit(1)
    
    elif cmd == "b64":
        result = decode_base64(data)
        print(result if result else "ERROR: Invalid base64")
    
    elif cmd == "b64url":
        result = decode_base64url(data)
        print(result if result else "ERROR: Invalid base64url")
    
    elif cmd == "hex":
        result = decode_hex(data)
        print(result if result else "ERROR: Invalid hex")
    
    elif cmd == "url":
        print(url_decode(data))
    
    elif cmd == "entropy":
        ent, max_ent, norm = calculate_entropy(data)
        print(f"Entropy: {ent:.4f} bits")
        print(f"Max possible: {max_ent:.4f} bits")
        print(f"Normalized: {norm:.4f}")
    
    elif cmd == "analyze":
        result = analyze_secret(data)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    
    else:
        print(f"ERROR: Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
