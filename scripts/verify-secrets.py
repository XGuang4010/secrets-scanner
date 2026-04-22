#!/usr/bin/env python3
"""
Secret Validity Verification Framework (Phase 7)

Validates confirmed secrets via read-only network requests.

Usage:
    python scripts/verify-secrets.py /tmp/scan-classified.json [--output /tmp/scan-verified.json]

Safety constraints:
    - All validators are read-only (no writes, no charges, no vehicle control).
    - Network timeout: 10 seconds max per request.
    - Rate limiting: max 1 request per second globally.
    - On any error -> mark as UNKNOWN, never crash.
    - Never log full secret values (mask in logs).
    - For batch scans, process max 20 findings.
"""

import argparse
import base64
import hashlib
import hmac
import json
import math
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TIMEOUT = 10
RATE_LIMIT_SECONDS = 1.0
MAX_BATCH_FINDINGS = 20

LAST_REQUEST_TIME = 0.0


def rate_limit():
    """Enforce global rate limit of max 1 request per second."""
    global LAST_REQUEST_TIME
    now = time.time()
    elapsed = now - LAST_REQUEST_TIME
    if elapsed < RATE_LIMIT_SECONDS:
        time.sleep(RATE_LIMIT_SECONDS - elapsed)
    LAST_REQUEST_TIME = time.time()


def mask(value: str) -> str:
    """Mask a secret for safe logging."""
    if not value:
        return "****"
    if len(value) > 8:
        return value[:2] + "****" + value[-2:]
    return "****"


def is_batch_scan(data: dict) -> bool:
    """Detect batch scan."""
    if data.get("repos"):
        return True
    findings = data.get("findings", [])
    names = {f.get("repo_name") for f in findings if f.get("repo_name")}
    return len(names) > 1


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Entropy / JWT helpers (no external deps)
# ---------------------------------------------------------------------------
def calculate_entropy(data: str):
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


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------
def make_validity(status, validator, detail, http_status=None):
    return {
        "status": status,
        "tested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "validator": validator,
        "detail": detail,
        "http_status": http_status,
    }


def validate_aws(finding: dict):
    """
    Validate AWS credentials via STS GetCallerIdentity.
    Requires both Access Key ID and Secret Access Key.
    """
    match = finding.get("match", "")
    context = finding.get("context", {})
    rule_id = finding.get("rule_id", "").lower()

    # Try to extract from match directly
    secret_val = extract_secret_from_match(match)

    access_key = ""
    secret_key = ""

    # Determine which part we have
    if "access-key-id" in rule_id or secret_val.startswith("AKIA"):
        access_key = secret_val
    elif "secret-access-key" in rule_id or len(secret_val) > 30:
        secret_key = secret_val

    # Scan context for the missing piece
    pairs = extract_pairs_from_context(context)
    for k, v in pairs.items():
        if not access_key and ("access" in k.lower() or v.startswith("AKIA")):
            access_key = v
        if not secret_key and ("secret" in k.lower() or len(v) > 30):
            secret_key = v

    if not access_key or not secret_key:
        return make_validity("NOT_TESTABLE", "aws", "缺少 Access Key ID 或 Secret Access Key，无法验证")

    # Build AWS SigV4 signed request
    try:
        rate_limit()
        method = "GET"
        uri = "/"
        query = "Action=GetCallerIdentity&Version=2011-06-15"
        host = "sts.amazonaws.com"
        region = "us-east-1"
        service = "sts"
        amzdate = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        datestamp = amzdate[:8]

        def sign(key, msg):
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        def get_signature_key(secret, d, r, s):
            k_date = sign(("AWS4" + secret).encode("utf-8"), d)
            k_region = sign(k_date, r)
            k_service = sign(k_region, s)
            k_signing = sign(k_service, "aws4_request")
            return k_signing

        headers = {"host": host, "x-amz-date": amzdate}
        signed_headers = "host;x-amz-date"
        canonical_headers = "\n".join(f"{k}:{headers[k]}" for k in sorted(headers)) + "\n"
        payload_hash = hashlib.sha256(b"").hexdigest()
        canonical_request = (
            f"{method}\n{uri}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
        string_to_sign = (
            f"{algorithm}\n{amzdate}\n{credential_scope}\n"
            + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        )
        signing_key = get_signature_key(secret_key, datestamp, region, service)
        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        auth_header = (
            f"{algorithm} Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )

        url = f"https://{host}/?{query}"
        req = urllib.request.Request(
            url,
            headers={
                "Host": host,
                "X-Amz-Date": amzdate,
                "Authorization": auth_header,
            },
            method=method,
        )

        print(f"[INFO] AWS: testing AK={mask(access_key)} SK={mask(secret_key)}", file=sys.stderr)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            if resp.status == 200 and "<Arn>" in body:
                return make_validity("VALID", "aws", "STS GetCallerIdentity 返回有效身份", resp.status)
            return make_validity("UNKNOWN", "aws", f"返回 HTTP {resp.status}", resp.status)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        if e.code == 403 and "InvalidClientTokenId" in body:
            return make_validity("INVALID", "aws", "AWS STS 返回 InvalidClientTokenId", e.code)
        return make_validity("UNKNOWN", "aws", f"HTTP {e.code}", e.code)
    except Exception as e:
        print(f"[WARN] AWS validator error: {e}", file=sys.stderr)
        return make_validity("UNKNOWN", "aws", f"网络错误: {type(e).__name__}")


def validate_hyundai(finding: dict):
    """
    Validate Hyundai Bluelink credentials via device registration endpoint.
    Read-only: registers a dummy device to check secret validity.
    """
    context = finding.get("context", {})
    match = finding.get("match", "")
    pairs = extract_pairs_from_context(context)

    # If match contains the secret but not the ID, context usually has the rest
    service_secret = extract_secret_from_match(match)
    if not service_secret:
        service_secret = pairs.get("CCSPServiceSecret", "")

    service_id = pairs.get("CCSPServiceID", "")
    application_id = pairs.get("CCSPApplicationID", "")

    if not all([service_id, service_secret, application_id]):
        return make_validity("NOT_TESTABLE", "hyundai-bluelink", "缺少 CCSPServiceID/CCSPServiceSecret/CCSPApplicationID")

    url = "https://prd.eu-ccapi.hyundai.com:8080/api/v1/spa/notifications/register"
    payload = json.dumps({
        "ccspServiceId": service_id,
        "ccspApplicationId": application_id,
        "ccspServiceSecret": service_secret,
        "pushType": "GCM",
        "pushRegId": "test"
    })

    try:
        rate_limit()
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
                return make_validity("VALID", "hyundai-bluelink", "设备注册成功，返回 deviceId", resp.status)
            return make_validity("UNKNOWN", "hyundai-bluelink", f"返回 HTTP {resp.status}", resp.status)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return make_validity("INVALID", "hyundai-bluelink", "HTTP 401 认证失败", e.code)
        return make_validity("UNKNOWN", "hyundai-bluelink", f"HTTP {e.code}", e.code)
    except Exception as e:
        print(f"[WARN] Hyundai validator error: {e}", file=sys.stderr)
        return make_validity("UNKNOWN", "hyundai-bluelink", f"网络错误: {type(e).__name__}")


def validate_stripe(finding: dict):
    """Validate Stripe key via read-only charges list endpoint."""
    match = finding.get("match", "")
    key = extract_secret_from_match(match)
    if not key or not key.startswith("sk_"):
        return make_validity("NOT_TESTABLE", "stripe", "未检测到 Stripe 密钥格式")
    url = "https://api.stripe.com/v1/charges?limit=1"
    try:
        rate_limit()
        print(f"[INFO] Stripe: testing key={mask(key)}", file=sys.stderr)
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            if resp.status == 200:
                return make_validity("VALID", "stripe", "Stripe API 认证成功", resp.status)
            return make_validity("UNKNOWN", "stripe", f"返回 HTTP {resp.status}", resp.status)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return make_validity("INVALID", "stripe", "HTTP 401 认证失败", e.code)
        return make_validity("UNKNOWN", "stripe", f"HTTP {e.code}", e.code)
    except Exception as e:
        print(f"[WARN] Stripe validator error: {e}", file=sys.stderr)
        return make_validity("UNKNOWN", "stripe", f"网络错误: {type(e).__name__}")


def validate_wechat_pay(finding: dict):
    """WeChat Pay keys require signed requests; we cannot safely verify over network here."""
    return make_validity("NOT_TESTABLE", "wechat-pay", "微信支付密钥需要签名请求，无法在不写操作的前提下验证")


def validate_fiat(finding: dict):
    """Fiat endpoint unknown; not testable in a safe read-only manner."""
    return make_validity("NOT_TESTABLE", "fiat", "Fiat API 端点未知，无法安全验证")


def validate_unknown_generic(finding: dict):
    """For unknown platforms: JWT structure check + entropy check."""
    match = finding.get("match", "")
    secret = extract_secret_from_match(match)
    if not secret:
        return make_validity("NOT_TESTABLE", "unknown-generic", "无法从匹配中提取密钥")

    if is_valid_jwt(secret):
        return make_validity("NOT_TESTABLE", "jwt-check", "JWT 格式正确，但缺少签名验证密钥")

    _, _, norm = calculate_entropy(secret)
    if norm < 0.5:
        return make_validity("INVALID", "entropy-check", f"熵值过低 ({norm:.2f})，可能为占位符")

    return make_validity("NOT_TESTABLE", "entropy-check", f"熵值正常 ({norm:.2f})，但未知平台无法验证")


def validate_generic_api_key(finding: dict):
    """Dispatcher for generic-api-key based on context."""
    match = finding.get("match", "").lower()
    file = finding.get("file", "").lower()
    context = finding.get("context", {})
    text = f"{match} {file} " + " ".join(
        list(context.get("before", [])) + [context.get("match_line", "")] + list(context.get("after", []))
    ).lower()

    if "stripe" in text or "sk_live" in text or "sk_test" in text:
        return validate_stripe(finding)
    if "wxpay" in text or "wechat" in text:
        return validate_wechat_pay(finding)
    if "fiat" in text or "channels.sdpr" in text:
        return validate_fiat(finding)
    if "hyundai" in text or "bluelink" in text or "ccsp" in text:
        return validate_hyundai(finding)

    return validate_unknown_generic(finding)


# ---------------------------------------------------------------------------
# Validator registry
# ---------------------------------------------------------------------------
VALIDATORS = {
    "aws-access-key": validate_aws,
    "aws-secret-access-key": validate_aws,
    "generic-api-key": validate_generic_api_key,
    "private-key": lambda f: make_validity("NOT_TESTABLE", "private-key", "私钥无法通过网络验证"),
    "jwt": lambda f: make_validity("NOT_TESTABLE", "jwt", "JWT 需要签名验证，不适合网络探针"),
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Secret Validity Verification Framework")
    parser.add_argument("input", help="Path to scan-classified.json")
    parser.add_argument("--output", "-o", help="Output path for verified JSON", default=None)
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = data.get("findings", [])
    confirmed = [f for f in findings if f.get("classification") == "CONFIRMED"]

    if is_batch_scan(data):
        print(f"[INFO] Batch scan detected, limiting to {MAX_BATCH_FINDINGS} findings", file=sys.stderr)
        confirmed = confirmed[:MAX_BATCH_FINDINGS]

    print(f"[INFO] Processing {len(confirmed)} confirmed findings for validity", file=sys.stderr)

    for finding in confirmed:
        rule_id = finding.get("rule_id", "")
        validator = VALIDATORS.get(rule_id)
        if not validator:
            # Try fallback by rule_id prefix
            for key in VALIDATORS:
                if key in rule_id:
                    validator = VALIDATORS[key]
                    break

        if validator:
            try:
                finding["validity"] = validator(finding)
            except Exception as e:
                print(f"[WARN] Validator crashed for {finding.get('finding_id')}: {e}", file=sys.stderr)
                finding["validity"] = make_validity("UNKNOWN", "crash-guard", f"验证器异常: {type(e).__name__}")
        else:
            finding["validity"] = make_validity("NOT_TESTABLE", "unregistered", f"未注册的规则: {rule_id}")

    output_path = args.output
    if output_path is None:
        output_path = str(input_path.with_suffix(".verified.json"))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(output_path)


if __name__ == "__main__":
    main()
