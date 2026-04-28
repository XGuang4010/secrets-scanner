"""PSA Group (Citroen, DS, Opel, Peugeot) secret validator plugin."""

import sys
import urllib.error
import urllib.request
from urllib.parse import urlencode

from ._utils import extract_secret_from_match, extract_pairs_from_context, mask

TIMEOUT = 10

TOKEN_URLS = {
    "citroen": "https://idpcvs.citroen.com/am/oauth2/access_token",
    "ds": "https://idpcvs.driveds.com/am/oauth2/access_token",
    "opel": "https://idpcvs.opel.com/am/oauth2/access_token",
    "peugeot": "https://idpcvs.peugeot.com/am/oauth2/access_token",
}


def _detect_brand(text: str) -> str:
    text = text.lower()
    for brand in TOKEN_URLS:
        if brand in text:
            return brand
    if "driveds" in text:
        return "ds"
    if "psa" in text:
        return "citroen"  # default fallback
    return ""


def validate(finding: dict) -> dict:
    """
    Validate PSA Group OAuth client credentials via client_credentials flow.
    Read-only: POST to token endpoint.
    """
    match = finding.get("match", "")
    context = finding.get("context", {})
    pairs = extract_pairs_from_context(context)

    text = f"{match} {finding.get('file', '')} " + " ".join(
        list(context.get("before", []))
        + [context.get("match_line", "")]
        + list(context.get("after", []))
    )

    brand = _detect_brand(text)
    if not brand:
        return {
            "status": "NOT_TESTABLE",
            "detail": "无法识别 PSA 品牌 (citroen/ds/opel/peugeot)",
            "validator": "psa-group",
        }

    client_id = pairs.get("client_id", pairs.get("ClientID", ""))
    client_secret = pairs.get("client_secret", pairs.get("ClientSecret", ""))

    if not client_id or not client_secret:
        # Attempt to infer from the raw match if pairs are incomplete
        secret = extract_secret_from_match(match)
        if secret and not client_id and len(secret) < 40:
            client_id = secret
        elif secret and not client_secret and len(secret) >= 32:
            client_secret = secret

    if not client_id or not client_secret:
        return {
            "status": "NOT_TESTABLE",
            "detail": "缺少 client_id 或 client_secret，无法验证",
            "validator": "psa-group",
        }

    url = TOKEN_URLS[brand]
    data = urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    })

    try:
        print(f"[INFO] PSA {brand}: testing client_id={mask(client_id)}", file=sys.stderr)
        req = urllib.request.Request(
            url,
            data=data.encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            if resp.status == 200 and "access_token" in body:
                return {
                    "status": "VALID",
                    "detail": f"{brand.title()} OAuth 返回有效 access_token",
                    "validator": "psa-group",
                    "http_status": resp.status,
                }
            return {
                "status": "UNKNOWN",
                "detail": f"HTTP {resp.status}",
                "validator": "psa-group",
                "http_status": resp.status,
            }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        if e.code == 401 or "invalid_client" in body.lower():
            return {
                "status": "INVALID",
                "detail": f"HTTP {e.code} 认证失败",
                "validator": "psa-group",
                "http_status": e.code,
            }
        return {
            "status": "UNKNOWN",
            "detail": f"HTTP {e.code}",
            "validator": "psa-group",
            "http_status": e.code,
        }
    except Exception as e:
        print(f"[WARN] PSA validator error: {e}", file=sys.stderr)
        return {
            "status": "UNKNOWN",
            "detail": f"网络错误: {type(e).__name__}",
            "validator": "psa-group",
        }

# Auto-registered rule IDs for dynamic plugin discovery
RULE_IDS = ["psa-api-key"]
