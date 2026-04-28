"""Nissan secret validator plugin."""

import sys
import urllib.error
import urllib.request
from urllib.parse import urlencode

from ._utils import extract_secret_from_match, extract_pairs_from_context, mask

TIMEOUT = 10

TOKEN_URL = "https://prod.eu2.auth.kamereon.org/kauth/oauth2/a-ncb-prod/access_token"


def validate(finding: dict) -> dict:
    """
    Validate Nissan Kamereon OAuth client credentials via client_credentials flow.
    Read-only: POST to token endpoint.
    """
    match = finding.get("match", "")
    context = finding.get("context", {})
    pairs = extract_pairs_from_context(context)

    client_id = pairs.get("client_id", pairs.get("ClientID", ""))
    client_secret = pairs.get("client_secret", pairs.get("ClientSecret", ""))

    # Fallback extraction from matched line
    if not client_id or not client_secret:
        secret = extract_secret_from_match(match)
        if secret:
            if not client_id and len(secret) < 40:
                client_id = secret
            elif not client_secret and len(secret) >= 32:
                client_secret = secret

    if not client_id or not client_secret:
        return {
            "status": "NOT_TESTABLE",
            "detail": "缺少 client_id 或 client_secret，无法验证",
            "validator": "nissan",
        }

    data = urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    })

    try:
        print(f"[INFO] Nissan: testing client_id={mask(client_id)}", file=sys.stderr)
        req = urllib.request.Request(
            TOKEN_URL,
            data=data.encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            if resp.status == 200 and "access_token" in body:
                return {
                    "status": "VALID",
                    "detail": "Nissan Kamereon OAuth 返回有效 access_token",
                    "validator": "nissan",
                    "http_status": resp.status,
                }
            return {
                "status": "UNKNOWN",
                "detail": f"HTTP {resp.status}",
                "validator": "nissan",
                "http_status": resp.status,
            }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        if e.code == 401 or "invalid_client" in body.lower():
            return {
                "status": "INVALID",
                "detail": f"HTTP {e.code} 认证失败",
                "validator": "nissan",
                "http_status": e.code,
            }
        return {
            "status": "UNKNOWN",
            "detail": f"HTTP {e.code}",
            "validator": "nissan",
            "http_status": e.code,
        }
    except Exception as e:
        print(f"[WARN] Nissan validator error: {e}", file=sys.stderr)
        return {
            "status": "UNKNOWN",
            "detail": f"网络错误: {type(e).__name__}",
            "validator": "nissan",
        }

# Auto-registered rule IDs for dynamic plugin discovery
RULE_IDS = ["nissan-api-key"]
