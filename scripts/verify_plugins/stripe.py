"""Stripe secret validator plugin."""

import sys
import urllib.error
import urllib.request

from ._utils import extract_secret_from_match, mask

TIMEOUT = 10


def validate(finding: dict) -> dict:
    """Validate Stripe key via read-only charges list endpoint."""
    match = finding.get("match", "")
    key = extract_secret_from_match(match)
    
    if not key or not key.startswith("sk_"):
        return {
            "status": "NOT_TESTABLE",
            "detail": "未检测到 Stripe 密钥格式",
            "validator": "stripe",
        }
    
    url = "https://api.stripe.com/v1/charges?limit=1"
    
    try:
        print(f"[INFO] Stripe: testing key={mask(key)}", file=sys.stderr)
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            if resp.status == 200:
                return {
                    "status": "VALID",
                    "detail": "Stripe API 认证成功",
                    "validator": "stripe",
                    "http_status": resp.status,
                }
            return {
                "status": "UNKNOWN",
                "detail": f"返回 HTTP {resp.status}",
                "validator": "stripe",
                "http_status": resp.status,
            }
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {
                "status": "INVALID",
                "detail": "HTTP 401 认证失败",
                "validator": "stripe",
                "http_status": e.code,
            }
        return {
            "status": "UNKNOWN",
            "detail": f"HTTP {e.code}",
            "validator": "stripe",
            "http_status": e.code,
        }
    except Exception as e:
        print(f"[WARN] Stripe validator error: {e}", file=sys.stderr)
        return {
            "status": "UNKNOWN",
            "detail": f"网络错误: {type(e).__name__}",
            "validator": "stripe",
        }

# Auto-registered rule IDs for dynamic plugin discovery
RULE_IDS = ["stripe-api-key", "stripe-secret-key"]
