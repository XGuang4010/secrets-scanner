"""Generic secret validator plugin.

Handles dispatching for generic-api-key, private-key, jwt, and unknown platforms.
"""

from ._utils import extract_secret_from_match, calculate_entropy, is_valid_jwt


def _validate_wechat_pay(finding: dict) -> dict:
    """WeChat Pay keys require signed requests; we cannot safely verify over network here."""
    return {
        "status": "NOT_TESTABLE",
        "detail": "微信支付密钥需要签名请求，无法在不写操作的前提下验证",
        "validator": "wechat-pay",
    }


def _validate_fiat(finding: dict) -> dict:
    """Route to dedicated Fiat validator."""
    from . import fiat
    return fiat.validate(finding)


def _validate_unknown_generic(finding: dict) -> dict:
    """For unknown platforms: JWT structure check + entropy check."""
    match = finding.get("match", "")
    secret = extract_secret_from_match(match)
    if not secret:
        return {
            "status": "NOT_TESTABLE",
            "detail": "无法从匹配中提取密钥",
            "validator": "unknown-generic",
        }

    if is_valid_jwt(secret):
        return {
            "status": "NOT_TESTABLE",
            "detail": "JWT 格式正确，但缺少签名验证密钥",
            "validator": "jwt-check",
        }

    _, _, norm = calculate_entropy(secret)
    if norm < 0.5:
        return {
            "status": "INVALID",
            "detail": f"熵值过低 ({norm:.2f})，可能为占位符",
            "validator": "entropy-check",
        }

    return {
        "status": "NOT_TESTABLE",
        "detail": f"熵值正常 ({norm:.2f})，但未知平台无法验证",
        "validator": "entropy-check",
    }


def _validate_private_key(finding: dict) -> dict:
    """Private keys cannot be verified over the network."""
    return {
        "status": "NOT_TESTABLE",
        "detail": "私钥无法通过网络验证",
        "validator": "private-key",
    }


def _validate_jwt(finding: dict) -> dict:
    """JWT requires signature verification, not suitable for network probes."""
    return {
        "status": "NOT_TESTABLE",
        "detail": "JWT 需要签名验证，不适合网络探针",
        "validator": "jwt",
    }


def validate(finding: dict) -> dict:
    """
    Dispatcher for generic secrets.
    Routes to appropriate validator based on context and rule_id.
    """
    rule_id = finding.get("rule_id", "").lower()
    
    # Handle private-key and jwt directly by rule_id
    if rule_id == "private-key":
        return _validate_private_key(finding)
    if rule_id == "jwt":
        return _validate_jwt(finding)
    
    # For generic-api-key, dispatch based on context clues
    match = finding.get("match", "").lower()
    file = finding.get("file", "").lower()
    context = finding.get("context", {})
    text = f"{match} {file} " + " ".join(
        list(context.get("before", [])) + [context.get("match_line", "")] + list(context.get("after", []))
    ).lower()

    if "stripe" in text or "sk_live" in text or "sk_test" in text:
        from . import stripe
        return stripe.validate(finding)
    if "wxpay" in text or "wechat" in text:
        return _validate_wechat_pay(finding)
    if "fiat" in text or "channels.sdpr" in text:
        return _validate_fiat(finding)
    if "hyundai" in text or "bluelink" in text or "ccsp" in text:
        from . import hyundai
        return hyundai.validate(finding)
    if any(b in text for b in ("citroen", "peugeot", "opel", "driveds", "psa")):
        from . import psa
        return psa.validate(finding)
    if "toyota" in text:
        from . import toyota
        return toyota.validate(finding)
    if "renault" in text or "gigya" in text or "kamereon" in text:
        from . import renault
        return renault.validate(finding)
    if "nissan" in text:
        from . import nissan
        return nissan.validate(finding)
    if "subaru" in text:
        from . import subaru
        return subaru.validate(finding)
    if any(b in text for b in ("volkswagen", "vwgroup", "weconnect", "seat", "skoda", "cupra", "vw")):
        from . import vw
        return vw.validate(finding)

    return _validate_unknown_generic(finding)

# Auto-registered rule IDs for dynamic plugin discovery
RULE_IDS = ["generic-api-key", "private-key", "jwt"]
