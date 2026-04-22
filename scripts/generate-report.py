#!/usr/bin/env python3
"""
Generate Chinese Markdown report from AI-classified scan results.

Only CONFIRMED findings are included in the report.
FALSE_POSITIVE findings are skipped (they're used for auto-learning instead).

Usage:
  python scripts/generate-report.py /tmp/scan-classified.json [output-dir]

Output:
  Prints path to generated Markdown report
"""

import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Hazard analysis mapping
# ---------------------------------------------------------------------------
HAZARD_MAP = [
    # (rule_id_pattern, context/match pattern, hazard_text)
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
]


def get_hazard(rule_id: str, file: str, match: str, context: dict) -> str:
    """Return Chinese hazard description based on rule and context."""
    text = f"{file}\n{match}\n"
    for line in context.get("before", []) + context.get("after", []):
        text += line + "\n"

    for rid_pat, ctx_pat, hazard in HAZARD_MAP:
        if rid_pat in rule_id.lower() and ctx_pat.search(text):
            return hazard

    # generic fallback
    return f"{rule_id} 类型的敏感信息泄露。攻击者可能利用该凭证访问相关服务或资源，建议立即轮换。"


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------
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


def get_severity(rule_id: str, description: str, file: str, context: dict, match: str) -> str:
    """Determine severity based on rule type and context."""
    rid = rule_id.lower()
    desc = description.lower()
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


SEVERITY_EMOJI = {
    "HIGH": ("🔴", "高"),
    "MEDIUM": ("🟡", "中"),
    "LOW": ("🟢", "低"),
}


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
    # Look for a value after = or : (with optional quotes)
    m = re.search(r'([=:])\s*(["\']?)([^"\';,\s]+)', match)
    if not m:
        return match
    start = m.start(3)
    end = m.end(3)
    val = m.group(3)
    masked = mask_secret(val)
    return match[:start] + masked + match[end:]


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------
def derive_owner_repo(repo_path: str):
    """Derive owner/repo from a local path."""
    if not repo_path or repo_path == "unknown":
        return "unknown", "unknown"
    parts = [p for p in repo_path.replace("\\", "/").split("/") if p]
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    if len(parts) == 1:
        return "unknown", parts[0]
    return "unknown", "unknown"


def is_batch_scan(data: dict) -> bool:
    """Detect batch scan from top-level fields or heterogeneous findings."""
    if data.get("repos"):
        return True
    findings = data.get("findings", [])
    repo_names = {f.get("repo_name") for f in findings if f.get("repo_name")}
    return len(repo_names) > 1


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


def format_finding(finding: dict) -> list:
    """Format a single finding in Chinese."""
    lines = []
    rule_id = finding.get("rule_id", "unknown")
    file_path = finding.get("file", "unknown")
    line_num = finding.get("line", 0)
    match = finding.get("match", "")
    context = finding.get("context", {})
    reason = finding.get("reason", "")
    severity = finding.get("_severity", "LOW")
    emoji, sev_text = SEVERITY_EMOJI.get(severity, ("⚪", "未知"))

    lines.append(f"### [{rule_id}] {file_path}:{line_num}")
    lines.append("")
    lines.append(f"- **文件路径**: `{file_path}`")
    lines.append(f"- **行号**: {line_num}")
    lines.append(f"- **规则**: {rule_id}")
    lines.append(f"- **风险等级**: {emoji} {sev_text}")
    lines.append(f"- **发现内容**: `{mask_match_line(match)}`")
    lines.append("- **代码上下文**:")
    lines.append("  ```")
    for ctx_line in format_context(context).split("\n"):
        lines.append(f"  {ctx_line}")
    lines.append("  ```")
    hazard = get_hazard(rule_id, file_path, match, context)
    lines.append(f"- **可能危害**: {hazard}")
    if reason:
        lines.append(f"- **分类依据**: {reason}")
    lines.append("")
    return lines


def build_summary_lines(confirmed, high_risk, medium_risk, low_risk, false_positives, all_findings):
    lines = []
    lines.append("## 统计摘要")
    lines.append("")
    lines.append("| 类别 | 数量 |")
    lines.append("|------|------|")
    lines.append(f"| 高风险确认泄露 | {len(high_risk)} |")
    lines.append(f"| 中风险确认泄露 | {len(medium_risk)} |")
    lines.append(f"| 低风险确认泄露 | {len(low_risk)} |")
    lines.append(f"| 误报（已过滤） | {len(false_positives)} |")
    lines.append(f"| 原始发现总数 | {len(all_findings)} |")
    lines.append("")
    return lines


def build_recommendations_lines(has_confirmed: bool, repo_path: str) -> list:
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
        lines.append("4. **审查历史提交** 中是否曾泄露过敏感信息:")
        lines.append(f"   ```bash")
        lines.append(f"   cd {repo_path}")
        lines.append(f"   git log --all --full-history --source -- '*.env' '*.key' '*secret*'")
        lines.append(f"   ```")
    else:
        lines.append("- 继续使用 pre-commit 钩子防止未来的泄露")
        lines.append("- 将所有密钥存储在环境变量或密钥管理系统中")
        lines.append("- 切勿提交包含硬编码凭证的 `.env` 文件或配置文件")
    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Main report generation
# ---------------------------------------------------------------------------
def generate_report(classified_data: dict, output_dir=None):
    if output_dir is None:
        output_dir = Path("/tmp")
    else:
        output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    scan_id = classified_data.get("scan_id", "unknown")
    top_repo_path = classified_data.get("repo_path", "unknown")
    timestamp = classified_data.get("timestamp", datetime.now().isoformat())
    all_findings = classified_data.get("findings", [])

    confirmed = [f for f in all_findings if f.get("classification") == "CONFIRMED"]
    false_positives = [f for f in all_findings if f.get("classification") == "FALSE_POSITIVE"]

    print(f"[INFO] 确认泄露数: {len(confirmed)}", file=sys.stderr)
    print(f"[INFO] 已过滤误报数: {len(false_positives)}", file=sys.stderr)

    batch = is_batch_scan(classified_data)

    # Assign severity
    high_risk = []
    medium_risk = []
    low_risk = []
    for f in confirmed:
        sev = get_severity(
            f.get("rule_id", ""),
            f.get("description", ""),
            f.get("file", ""),
            f.get("context", {}),
            f.get("match", ""),
        )
        f["_severity"] = sev
        if sev == "HIGH":
            high_risk.append(f)
        elif sev == "MEDIUM":
            medium_risk.append(f)
        else:
            low_risk.append(f)

    lines = []

    if batch:
        lines.append("# 批量仓库敏感信息扫描报告")
        lines.append("")
        lines.append(f"**扫描ID**: `{scan_id}`")
        lines.append(f"**扫描时间**: {timestamp}")
        lines.append("**扫描工具**: secrets-scanner")
        lines.append("")
        lines.extend(build_summary_lines(confirmed, high_risk, medium_risk, low_risk, false_positives, all_findings))

        if not confirmed:
            lines.append("> **未发现确认的敏感信息泄露。**")
            lines.append(f"> 共分析了 {len(false_positives)} 条潜在发现，均已归类为误报。")
            lines.append("")
        else:
            lines.append("## 敏感信息详情")
            lines.append("")
            # Group by repo_name
            groups = defaultdict(list)
            for f in confirmed:
                groups[f.get("repo_name", "unknown")].append(f)
            for repo_name in sorted(groups.keys()):
                repo_findings = groups[repo_name]
                # derive owner from first finding's repo_path
                first_path = repo_findings[0].get("repo_path", top_repo_path)
                owner, _ = derive_owner_repo(first_path)
                lines.append(f"### {owner}/{repo_name}")
                lines.append("")
                lines.append(f"**仓库地址**: https://github.com/{owner}/{repo_name}")
                lines.append(f"**该仓库确认泄露数**: {len(repo_findings)}")
                lines.append("")
                for f in repo_findings:
                    lines.extend(format_finding(f))
    else:
        owner, repo = derive_owner_repo(top_repo_path)
        lines.append(f"# {owner}/{repo} 敏感信息扫描报告")
        lines.append("")
        lines.append(f"**仓库地址**: https://github.com/{owner}/{repo}")
        lines.append(f"**扫描时间**: {timestamp}")
        lines.append("**扫描工具**: secrets-scanner")
        lines.append("")
        lines.extend(build_summary_lines(confirmed, high_risk, medium_risk, low_risk, false_positives, all_findings))

        if not confirmed:
            lines.append("> **未发现确认的敏感信息泄露。**")
            lines.append(f"> 共分析了 {len(false_positives)} 条潜在发现，均已归类为误报。")
            lines.append("")
        else:
            lines.append("## 敏感信息详情")
            lines.append("")
            for f in confirmed:
                lines.extend(format_finding(f))

    lines.extend(build_recommendations_lines(bool(confirmed), top_repo_path))

    if false_positives:
        lines.append("---")
        lines.append("")
        lines.append(f"*本次扫描分析了 {len(false_positives)} 条潜在发现并将其归类为误报。AI 将生成/更新白名单规则以在后续扫描中过滤类似模式。*")

    # Determine filename
    if batch:
        report_name = f"batch-{scan_id}-results.md"
    else:
        owner, repo = derive_owner_repo(top_repo_path)
        report_name = f"{owner}-{repo}-secrets-detected-results.md"

    report_path = output_dir / report_name
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate-report.py <scan-classified.json> [output-dir]", file=sys.stderr)
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None

    if not input_path.exists():
        print(f"ERROR: 输入文件不存在: {input_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: JSON 解析失败: {e}", file=sys.stderr)
        sys.exit(1)

    report_path = generate_report(data, output_dir)
    print(str(report_path))


if __name__ == "__main__":
    main()
