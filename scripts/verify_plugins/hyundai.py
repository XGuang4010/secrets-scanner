"""Hyundai Bluelink secret validator plugin."""

import json
import sys
import urllib.error
import urllib.request

from ._utils import extract_secret_from_match, extract_pairs_from_context, mask

TIMEOUT = 10


def validate(finding: dict) -> dict:
    """
    Validate Hyundai Bluelink credentials via device registration endpoint.
    Read-only: registers a dummy device to check secret validity.
    """
    context = finding.get("context", {})
    match = finding.get("match", "")
    pairs = extract_pairs_from_context(context)

    service_secret = extract_secret_from_match(match)
    if not service_secret:
        service_secret = pairs.get("CCSPServiceSecret", "")

    service_id = pairs.get("CCSPServiceID", "")
    application_id = pairs.get("CCSPApplicationID", "")

    if not all([service_id, service_secret, application_id]):
        return {
            "status": "NOT_TESTABLE",
            "detail": "缺少 CCSPServiceID/CCSPServiceSecret/CCSPApplicationID",
            "validator": "hyundai-bluelink",
        }

    url = "https://prd.eu-ccapi.hyundai.com:8080/api/v1/spa/notifications/register"
    payload = json.dumps({
        "ccspServiceId": service_id,
        "ccspApplicationId": application_id,
        "ccspServiceSecret": service_secret,
        "pushType": "GCM",
        "pushRegId": "test"
    })

    try:
        print(f"[INFO] Hyundai: testing CCSPServiceID={mask(service_id)}", file=sys.stderr)
        req = urllib.request.Request(
            url,
            data=payload.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            if resp.status == 200 and "deviceId" in body:
                return {
                    "status": "VALID",
                    "detail": "设备注册成功，返回 deviceId",
                    "validator": "hyundai-bluelink",
                    "http_status": resp.status,
                }
            return {
                "status": "UNKNOWN",
                "detail": f"返回 HTTP {resp.status}",
                "validator": "hyundai-bluelink",
                "http_status": resp.status,
            }
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {
                "status": "INVALID",
                "detail": "HTTP 401 认证失败",
                "validator": "hyundai-bluelink",
                "http_status": e.code,
            }
        return {
            "status": "UNKNOWN",
            "detail": f"HTTP {e.code}",
            "validator": "hyundai-bluelink",
            "http_status": e.code,
        }
    except Exception as e:
        print(f"[WARN] Hyundai validator error: {e}", file=sys.stderr)
        return {
            "status": "UNKNOWN",
            "detail": f"网络错误: {type(e).__name__}",
            "validator": "hyundai-bluelink",
        }

# Auto-registered rule IDs for dynamic plugin discovery
RULE_IDS = ["hyundai-api-key", "hyundai-bluelink"]
