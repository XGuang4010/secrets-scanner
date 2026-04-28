"""
Shared report utilities for secrets-scanner.

Used by both generate-report.py and batch-generate-report.py to avoid
 duplicating mask, severity, hazard, and formatting logic.
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------
SEVERITY_EMOJI = {
    "HIGH": ("🔴", "高"),
    "MEDIUM": ("🟡", "中"),
    "LOW": ("🟢", "低"),
    "UNKNOWN": ("⚪", "未知"),
}

HIGH_KEYWORDS = [
    "aws-access-key",
    "gcp-api-key",
    "azure",
    "github",
    "gitlab",
    "slack",
    "stripe",
    "openai",
    "private-key",
]
MEDIUM_KEYWORDS = ["generic", "password", "secret", "token", "api-key"]


# ---------------------------------------------------------------------------
# Hazard analysis mapping
# ---------------------------------------------------------------------------
HAZARD_MAP = [
    (
        "generic-api-key",
        re.compile(r"vehicle[/\\]", re.I),
        "车辆OEM API密钥泄露。攻击者可注册虚拟设备并获取车辆远程控制权限，实现远程解锁、启动空调、获取实时GPS位置等操作。",
    ),
    (
        "generic-api-key",
        re.compile(r"wxpay|wechat", re.I),
        "微信支付API密钥泄露。攻击者可发起支付请求、查询交易、申请退款，造成资金损失。",
    ),
    (
        "generic-api-key",
        re.compile(r"stripe|sk_live|sk_test", re.I),
        "Stripe支付密钥泄露。攻击者可发起退款、查看交易记录、获取客户支付信息。",
    ),
    (
        "aws-access-key",
        re.compile(r"."),
        "AWS访问密钥泄露。攻击者可访问云资源、创建/删除实例、读取存储桶数据，导致数据泄露和费用损失。",
    ),
    (
        "private-key",
        re.compile(r"."),
        "私钥泄露。攻击者可解密通信流量、伪造身份签名、入侵服务器，造成严重的安全事件。",
    ),
    (
        "jwt",
        re.compile(r"."),
        "JWT密钥泄露。攻击者可伪造身份令牌、越权访问系统、冒充其他用户执行敏感操作。",
    ),
    (
        "github",
        re.compile(r"."),
        "GitHub 个人访问令牌泄露。攻击者可访问代码仓库、修改代码、删除仓库、访问私有资源。",
    ),
    (
        "api-key",
        re.compile(r"."),
        "API 密钥泄露。攻击者可调用相关接口，获取未授权的数据或执行敏感操作。",
    ),
    (
        "password",
        re.compile(r"."),
        "硬编码密码发现。攻击者可使用该密码登录系统，获取未授权访问。",
    ),
]


# ---------------------------------------------------------------------------
# Masking helpers
# ---------------------------------------------------------------------------
def mask_secret(value: str) -> str:
    """Mask a secret for display: first 4 + **** + last 4."""
    if not value:
        return "****"
    if len(value) > 8:
        return value[:4] + "****" + value[-4:]
    return "****"


def mask_match_line(match: str) -> str:
    """Mask the secret value inside a match line."""
    # Try key = "value" or key = value patterns first
    m = re.search(r'([=:])\s*(["\']?)([^"\';,\s]+)', match)
    if m:
        quote = m.group(2)
        if quote in ('"', "'"):
            start = m.start(2)
            end = m.end(2)
        else:
            start = m.start(3)
            end = m.end(3)
        val = match[start:end]
        if len(val) > 4:
            masked = mask_secret(val)
            return match[:start] + masked + match[end:]
    # Fallback: look for standalone quoted long strings
    m2 = re.search(r'(["\'])([^"\']{8,})(["\'])', match)
    if m2:
        start = m2.start(2)
        end = m2.end(2)
        val = m2.group(2)
        masked = mask_secret(val)
        return match[:start] + masked + match[end:]
    return match


# ---------------------------------------------------------------------------
# Context helpers
# ---------------------------------------------------------------------------
def is_production_context(file: str, context: dict) -> bool:
    """Heuristic: does the context look like production code?"""
    test_indicators = ["test", "spec", "mock", "example", "demo", "fixture", "sample"]
    lowered = file.lower()
    if any(ind in lowered for ind in test_indicators):
        return False
    for line in context.get("before", []) + context.get("after", []):
        lowered_line = line.lower()
        if any(ind in lowered_line for ind in test_indicators):
            return False
    return True


def derive_owner_repo(repo_path: str) -> tuple:
    """Derive owner/repo from a local path."""
    if not repo_path or repo_path == "unknown":
        return "unknown", "unknown"
    parts = [p for p in repo_path.replace("\\", "/").split("/") if p]
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    if len(parts) == 1:
        return "unknown", parts[0]
    return "unknown", "unknown"


# ---------------------------------------------------------------------------
# Severity / Hazard
# ---------------------------------------------------------------------------
def get_severity(rule_id: str, description: str, file: str, context: dict, match: str) -> str:
    """Determine severity based on rule type and context."""
    rid = rule_id.lower()
    desc = (description or "").lower()
    combined = f"{rid} {desc} {file.lower()} {match.lower()}"

    # HIGH
    if "wechat-pay" in rid or "wxpay" in combined or "wechat" in combined:
        return "HIGH"
    for kw in HIGH_KEYWORDS:
        if kw in rid or kw in desc:
            if kw == "jwt" and not is_production_context(file, context):
                return "MEDIUM"
            return "HIGH"

    # MEDIUM
    if rid == "generic-api-key" and "vehicle/" in file.lower():
        return "MEDIUM"
    for kw in MEDIUM_KEYWORDS:
        if kw in rid or kw in desc:
            return "MEDIUM"

    return "LOW"


def get_hazard(rule_id: str, file: str, match: str, context: dict) -> str:
    """Return hazard description based on rule and context."""
    text = f"{file}\n{match}\n"
    for line in context.get("before", []) + context.get("after", []):
        text += line + "\n"

    for rid_pat, ctx_pat, hazard in HAZARD_MAP:
        if rid_pat in rule_id.lower() and ctx_pat.search(text):
            return hazard

    return f"{rule_id} 类型的敏感信息泄露。攻击者可能利用该凭证访问相关服务或资源，建议立即轮换。"


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def format_context(context: dict) -> str:
    """Format code context for Markdown display."""
    lines = []
    for line in context.get("before", []):
        lines.append(f"     {line}")
    match_line = context.get("match_line", "")
    if match_line:
        lines.append(f"  >>> {match_line}")
    for line in context.get("after", []):
        lines.append(f"     {line}")
    return "\n".join(lines)


def build_recommendations_lines(has_confirmed: bool, repo_path: str = None) -> List[str]:
    """Build remediation recommendations in Chinese."""
    lines = []
    lines.append("## 修复建议")
    lines.append("")
    if has_confirmed:
        lines.append("### 立即行动")
        lines.append("")
        lines.append("1. **立即轮换泄露的凭证**")
        lines.append("   - 通过服务商控制台作废已泄露的密钥/令牌")
        lines.append("   - 生成新的凭证")
        lines.append("   - 更新应用程序中的配置")
        lines.append("")
        lines.append("2. **审计访问日志**")
        lines.append("   - 检查泄露的凭证是否被未授权方使用")
        lines.append("   - 查找可疑活动")
        lines.append("")
        lines.append("### 预防措施")
        lines.append("")
        lines.append("1. **使用环境变量** 存储所有密钥，禁止硬编码")
        lines.append("2. **将 `.env` 文件加入 `.gitignore`** 后再提交代码")
        lines.append("3. **使用 pre-commit 钩子**（如 gitleaks、detect-secrets）进行秘密扫描")
        lines.append("4. **定期轮换密钥** 并限制密钥权限范围")
        lines.append("5. **审查历史提交** 中是否曾泄露过敏感信息:")
        if repo_path:
            lines.append(f"   ```bash")
            lines.append(f"   cd {repo_path}")
            lines.append(f"   git log --all --full-history --source -- '*.env' '*.key' '*secret*'")
            lines.append(f"   ```")
        else:
            lines.append("   ```bash")
            lines.append("   git log --all --full-history --source -- '*.env' '*.key' '*secret*'")
            lines.append("   ```")
    else:
        lines.append("- 继续使用 pre-commit 钩子防止未来的泄露")
        lines.append("- 将所有密钥存储在环境变量或密钥管理系统中")
        lines.append("- 切勿提交包含硬编码凭证的 `.env` 文件或配置文件")
    lines.append("")
    return lines
