"""Renault secret validator plugin."""

import sys
import urllib.error
import urllib.request

from ._utils import extract_secret_from_match, extract_pairs_from_context, mask

TIMEOUT = 10

KAMEREON_BASE = "https://api-wired-prod-1-euw1.wrd-aws.com"
GIGYA_BASE = "https://accounts.eu1.gigya.com"


def validate(finding: dict) -> dict:
    """
    Validate Renault API key via Kamereon or Gigya endpoints.
    Read-only: sends GET requests to public/read-only endpoints.
    """
    match = finding.get("match", "")
    context = finding.get("context", {})
    pairs = extract_pairs_from_context(context)

    api_key = extract_secret_from_match(match)
    if not api_key:
        api_key = pairs.get("KamereonAPIKey", pairs.get("GigyaAPIKey", ""))

    if not api_key:
        return {
            "status": "NOT_TESTABLE",
            "detail": "未提取到 Renault API Key",
            "validator": "renault",
        }

    # Try Kamereon API first (read-only endpoint)
    url = f"{KAMEREON_BASE}/commerce/v1/persons?country=FR"
    try:
        print(f"[INFO] Renault: testing Kamereon API key={mask(api_key)}", file=sys.stderr)
        req = urllib.request.Request(
            url,
            headers={"x-kamereon-api-key": api_key},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return {
                "status": "VALID" if resp.status == 200 else "UNKNOWN",
                "detail": f"Kamereon API 返回 HTTP {resp.status}",
                "validator": "renault",
                "http_status": resp.status,
            }
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            # Fallback: try Gigya API key validation
            gigya_url = f"{GIGYA_BASE}/accounts.getAccountInfo?apiKey={api_key}"
            try:
                req2 = urllib.request.Request(gigya_url, method="GET")
                with urllib.request.urlopen(req2, timeout=TIMEOUT) as resp2:
                    return {
                        "status": "VALID" if resp2.status == 200 else "UNKNOWN",
                        "detail": f"Gigya API 返回 HTTP {resp2.status}",
                        "validator": "renault",
                        "http_status": resp2.status,
                    }
            except urllib.error.HTTPError as e2:
                if e2.code in (400, 401, 403):
                    return {
                        "status": "INVALID",
                        "detail": "Kamereon 和 Gigya API 均返回认证失败",
                        "validator": "renault",
                        "http_status": e2.code,
                    }
                return {
                    "status": "UNKNOWN",
                    "detail": f"Gigya HTTP {e2.code}",
                    "validator": "renault",
                    "http_status": e2.code,
                }
        return {
            "status": "UNKNOWN",
            "detail": f"Kamereon HTTP {e.code}",
            "validator": "renault",
            "http_status": e.code,
        }
    except Exception as e:
        print(f"[WARN] Renault validator error: {e}", file=sys.stderr)
        return {
            "status": "UNKNOWN",
            "detail": f"网络错误: {type(e).__name__}",
            "validator": "renault",
        }

# Auto-registered rule IDs for dynamic plugin discovery
RULE_IDS = ["renault-api-key"]
