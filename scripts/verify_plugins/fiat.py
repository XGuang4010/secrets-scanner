"""Fiat secret validator plugin."""

import sys
import urllib.error
import urllib.request

from ._utils import extract_secret_from_match, extract_pairs_from_context, mask

TIMEOUT = 10

# Hard-coded public XApiKey values used in evcc source code.
# If the discovered secret matches one of these, it is not a leaked credential.
KNOWN_PUBLIC_KEYS = {
    "qLYupk65UU1tw2Ih1cJhs4izijgRDbir2UFHA3Je",
    "JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys",
}


def validate(finding: dict) -> dict:
    """
    Validate Fiat API key via channels endpoint.
    Read-only: sends a GET request with X-Api-Key header.
    """
    match = finding.get("match", "")
    context = finding.get("context", {})
    pairs = extract_pairs_from_context(context)

    api_key = extract_secret_from_match(match)
    if not api_key:
        api_key = pairs.get("XApiKey", "")

    if not api_key:
        return {
            "status": "NOT_TESTABLE",
            "detail": "未提取到 Fiat API Key",
            "validator": "fiat",
        }

    if api_key in KNOWN_PUBLIC_KEYS:
        return {
            "status": "INVALID",
            "detail": "该密钥为 Fiat 公开的硬编码 XApiKey，非有效凭证",
            "validator": "fiat",
        }

    url = "https://channels.sdpr-01.fcagcv.com"
    try:
        print(f"[INFO] Fiat: testing XApiKey={mask(api_key)}", file=sys.stderr)
        req = urllib.request.Request(
            url,
            headers={"X-Api-Key": api_key},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return {
                "status": "VALID" if resp.status == 200 else "UNKNOWN",
                "detail": f"Fiat API 返回 HTTP {resp.status}",
                "validator": "fiat",
                "http_status": resp.status,
            }
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {
                "status": "INVALID",
                "detail": f"HTTP {e.code} 认证失败",
                "validator": "fiat",
                "http_status": e.code,
            }
        return {
            "status": "UNKNOWN",
            "detail": f"HTTP {e.code}",
            "validator": "fiat",
            "http_status": e.code,
        }
    except Exception as e:
        print(f"[WARN] Fiat validator error: {e}", file=sys.stderr)
        return {
            "status": "UNKNOWN",
            "detail": f"网络错误: {type(e).__name__}",
            "validator": "fiat",
        }

# Auto-registered rule IDs for dynamic plugin discovery
RULE_IDS = ["fiat-api-key"]
