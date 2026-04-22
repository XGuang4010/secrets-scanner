"""Shared utility functions for secret verification plugins."""

import base64
import json
import math
import re


def extract_secret_from_match(match: str) -> str:
    """Extract the secret value from a match line."""
    m = re.search(r'[=:]\s*["\']?([^"\';,\s]+)', match)
    if m:
        return m.group(1)
    # fallback: take the longest alphanumeric token
    tokens = re.findall(r'[A-Za-z0-9_\-/+=]+', match)
    if tokens:
        return max(tokens, key=len)
    return ""


def extract_pairs_from_context(context: dict) -> dict:
    """Extract key=value pairs from surrounding context lines."""
    result = {}
    for line in (
        list(context.get("before", []))
        + [context.get("match_line", "")]
        + list(context.get("after", []))
    ):
        for m in re.finditer(r'([A-Za-z0-9_\.]+)\s*[=:]\s*["\']?([^"\';,\s]+)', line):
            key = m.group(1)
            val = m.group(2)
            result[key] = val
    return result


def calculate_entropy(data: str) -> tuple:
    """Calculate Shannon entropy of a string. Returns (entropy, max_possible, normalized)."""
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


def is_valid_jwt(token: str) -> bool:
    """Check if a string is a valid JWT token (checks header structure only)."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        header_b64 = parts[0]
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding
        decoded = base64.urlsafe_b64decode(header_b64)
        header = json.loads(decoded)
        return "alg" in header and "typ" in header
    except Exception:
        return False


def mask(value: str) -> str:
    """Mask a secret for safe logging."""
    if not value:
        return "****"
    if len(value) > 8:
        return value[:2] + "****" + value[-2:]
    return "****"
