"""VW Group (Volkswagen, Seat, Skoda, Cupra) secret validator plugin."""

import sys
import urllib.error
import urllib.request
from urllib.parse import urlencode

from ._utils import extract_secret_from_match, extract_pairs_from_context, mask

TIMEOUT = 10

# VW We Connect / VW ID mobile OAuth token endpoint
TOKEN_URL = "https://mbboauth-1d.prd.ece.vwg-connect.com/mbbcoauth/mobile/oauth2/v1/token"


def validate(finding: dict) -> dict:
    """
    Validate VW Group OAuth client credentials via client_credentials flow.
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
            "validator": "vw-group",
        }

    data = urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    })

    try:
        print(f"[INFO] VW Group: testing client_id={mask(client_id)}", file=sys.stderr)
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
                    "detail": "VW Group OAuth 返回有效 access_token",
                    "validator": "vw-group",
                    "http_status": resp.status,
                }
            return {
                "status": "UNKNOWN",
                "detail": f"HTTP {resp.status}",
                "validator": "vw-group",
                "http_status": resp.status,
            }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        if e.code == 401 or "invalid_client" in body.lower():
            return {
                "status": "INVALID",
                "detail": f"HTTP {e.code} 认证失败",
                "validator": "vw-group",
                "http_status": e.code,
            }
        return {
            "status": "UNKNOWN",
            "detail": f"HTTP {e.code}",
            "validator": "vw-group",
            "http_status": e.code,
        }
    except Exception as e:
        print(f"[WARN] VW validator error: {e}", file=sys.stderr)
        return {
            "status": "UNKNOWN",
            "detail": f"网络错误: {type(e).__name__}",
            "validator": "vw-group",
        }

# Auto-registered rule IDs for dynamic plugin discovery
RULE_IDS = ["vw-api-key"]
