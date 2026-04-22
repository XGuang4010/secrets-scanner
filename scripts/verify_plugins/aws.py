"""AWS secret validator plugin."""

import hashlib
import hmac
import sys
import urllib.error
import urllib.request
from datetime import datetime

from ._utils import extract_secret_from_match, extract_pairs_from_context, mask

TIMEOUT = 10


def validate(finding: dict) -> dict:
    """
    Validate AWS credentials via STS GetCallerIdentity.
    Requires both Access Key ID and Secret Access Key.
    """
    match = finding.get("match", "")
    context = finding.get("context", {})
    rule_id = finding.get("rule_id", "").lower()

    secret_val = extract_secret_from_match(match)

    access_key = ""
    secret_key = ""

    if "access-key-id" in rule_id or secret_val.startswith("AKIA"):
        access_key = secret_val
    elif "secret-access-key" in rule_id or len(secret_val) > 30:
        secret_key = secret_val

    pairs = extract_pairs_from_context(context)
    for k, v in pairs.items():
        if not access_key and ("access" in k.lower() or v.startswith("AKIA")):
            access_key = v
        if not secret_key and ("secret" in k.lower() or len(v) > 30):
            secret_key = v

    if not access_key or not secret_key:
        return {
            "status": "NOT_TESTABLE",
            "detail": "缺少 Access Key ID 或 Secret Access Key，无法验证",
            "validator": "aws",
        }

    try:
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
                return {
                    "status": "VALID",
                    "detail": "STS GetCallerIdentity 返回有效身份",
                    "validator": "aws",
                    "http_status": resp.status,
                }
            return {
                "status": "UNKNOWN",
                "detail": f"返回 HTTP {resp.status}",
                "validator": "aws",
                "http_status": resp.status,
            }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        if e.code == 403 and "InvalidClientTokenId" in body:
            return {
                "status": "INVALID",
                "detail": "AWS STS 返回 InvalidClientTokenId",
                "validator": "aws",
                "http_status": e.code,
            }
        return {
            "status": "UNKNOWN",
            "detail": f"HTTP {e.code}",
            "validator": "aws",
            "http_status": e.code,
        }
    except Exception as e:
        print(f"[WARN] AWS validator error: {e}", file=sys.stderr)
        return {
            "status": "UNKNOWN",
            "detail": f"网络错误: {type(e).__name__}",
            "validator": "aws",
        }
