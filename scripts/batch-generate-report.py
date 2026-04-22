#!/usr/bin/env python3
"""
批量报告生成器 - 从 batch-scan-findings.json 直接生成中文 Markdown 报告。

支持两种情况：
1. 已分类结果（scan-classified.json）- 使用 classification 字段
2. 未分类结果（batch-scan-findings.json）- 显示原始 findings

Usage:
  python scripts/batch-generate-report.py /tmp/batch-scan-findings.json [output-dir]
  python scripts/batch-generate-report.py /tmp/scan-classified.json [output-dir]

Output:
  生成中文 Markdown 报告到指定目录（默认 /tmp）
"""

import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional


# ---------------------------------------------------------------------------
# 风险等级映射
# ---------------------------------------------------------------------------
HIGH_KEYWORDS = [
    "aws-access-key", "gcp-api-key", "azure", "github", "gitlab",
    "slack", "stripe", "openai", "private-key", "jwt", "rsa-private-key",
    "ssh-private-key", "api-key", "secret-key", "access-token"
]
MEDIUM_KEYWORDS = ["generic", "password", "secret", "token", "api-key"]

SEVERITY_EMOJI = {
    "HIGH": ("🔴", "高"),
    "MEDIUM": ("🟡", "中"),
    "LOW": ("🟢", "低"),
    "UNKNOWN": ("⚪", "未知"),
}


# ---------------------------------------------------------------------------
# 脱敏函数
# ---------------------------------------------------------------------------
def mask_secret(value: str) -> str:
    """脱敏：显示前4位 + **** + 后4位"""
    if not value:
        return "****"
    if len(value) > 8:
        return value[:4] + "****" + value[-4:]
    return "****"


def mask_match_line(match: str) -> str:
    """在匹配行中脱敏敏感值"""
    # 匹配 = 或 : 后的值（可能有引号）
    patterns = [
        r'([=:])\s*(["\']?)([^"\';,\s]+)',  # key = value
        r'(["\'])([^"\']{8,})(["\'])',  # "long_secret"
    ]
    for pattern in patterns:
        m = re.search(pattern, match)
        if m:
            # 根据匹配组数确定位置
            if len(m.groups()) == 3:
                if m.group(2) in ['"', "'"]:
                    # key = "value" 格式
                    start = m.start(2)
                    end = m.end(2)
                else:
                    # key = value 格式
                    start = m.start(3)
                    end = m.end(3)
                val = match[start:end]
                if len(val) > 4:
                    masked = mask_secret(val)
                    return match[:start] + masked + match[end:]
    return match


# ---------------------------------------------------------------------------
# 风险分析
# ---------------------------------------------------------------------------
def get_hazard(rule_id: str, file: str, match: str, context: dict) -> str:
    """根据规则类型和上下文返回风险描述"""
    rule_lower = rule_id.lower()
    file_lower = file.lower()
    
    # AWS 密钥
    if "aws" in rule_lower:
        return "AWS 访问密钥泄露。攻击者可访问云资源、创建/删除实例、读取存储桶数据，导致数据泄露和费用损失。"
    
    # 私钥
    if "private-key" in rule_lower or "privatekey" in rule_lower:
        return "私钥文件泄露。攻击者可解密通信流量、伪造身份签名、入侵服务器，造成严重的安全事件。"
    
    # GitHub Token
    if "github" in rule_lower:
        return "GitHub 个人访问令牌泄露。攻击者可访问代码仓库、修改代码、删除仓库、访问私有资源。"
    
    # API Key
    if "api-key" in rule_lower or "apikey" in rule_lower:
        if "stripe" in rule_lower or "stripe" in file_lower:
            return "Stripe API 密钥泄露。攻击者可发起支付、退款、查看交易记录。"
        if "vehicle" in file_lower or "car" in file_lower:
            return "车辆 OEM API 密钥泄露。攻击者可注册虚拟设备并获取车辆远程控制权限。"
        return "API 密钥泄露。攻击者可调用相关接口，获取未授权的数据或执行敏感操作。"
    
    # JWT
    if "jwt" in rule_lower:
        return "JWT 密钥泄露。攻击者可伪造身份令牌、越权访问系统、冒充其他用户。"
    
    # 通用密码
    if "password" in rule_lower:
        return "硬编码密码发现。攻击者可使用该密码登录系统，获取未授权访问。"
    
    # 通用密钥
    return f"{rule_id} 类型的敏感信息泄露。攻击者可能利用该凭证访问相关服务或资源，建议立即轮换。"


def get_severity(rule_id: str, description: str, file: str, match: str) -> str:
    """根据规则类型确定风险等级"""
    rid = rule_id.lower()
    desc = description.lower() if description else ""
    combined = f"{rid} {desc} {file.lower()}"
    
    # 高风险
    for kw in HIGH_KEYWORDS:
        if kw in rid or kw in desc:
            # 测试文件降低风险
            if any(ind in file.lower() for ind in ["test", "spec", "mock", "example", "demo"]):
                return "MEDIUM"
            return "HIGH"
    
    # 中风险
    for kw in MEDIUM_KEYWORDS:
        if kw in rid or kw in desc:
            return "MEDIUM"
    
    return "LOW"


def is_test_context(file: str, context: dict) -> bool:
    """判断是否测试/示例代码上下文"""
    test_indicators = ["test", "spec", "mock", "example", "demo", "fixture", "sample"]
    lowered = file.lower()
    if any(ind in lowered for ind in test_indicators):
        return True
    
    for line in context.get("before", []) + context.get("after", []):
        lowered_line = line.lower()
        if any(ind in lowered_line for ind in test_indicators):
            return True
    return False


# ---------------------------------------------------------------------------
# 报告格式化
# ---------------------------------------------------------------------------
def format_context(context: dict) -> str:
    """格式化代码上下文用于 Markdown 显示"""
    lines = []
    
    # 前序行
    for i, line in enumerate(context.get("before", []), 1):
        lines.append(f"     {line}")
    
    # 匹配行
    match_line = context.get("match_line", "")
    if match_line:
        lines.append(f"  >>> {match_line}")
    
    # 后续行
    for i, line in enumerate(context.get("after", []), 1):
        lines.append(f"     {line}")
    
    return "\n".join(lines)


def format_finding(finding: dict, show_classification: bool = True) -> List[str]:
    """格式化单个 finding 为 Markdown"""
    lines = []
    
    rule_id = finding.get("rule_id", "unknown")
    file_path = finding.get("file", "unknown")
    line_num = finding.get("line", 0)
    match = finding.get("match", "")
    context = finding.get("context", {})
    
    # 分类信息
    classification = finding.get("classification", "PENDING")
    reason = finding.get("reason", "")
    
    # 风险等级
    if show_classification and classification == "CONFIRMED":
        severity = finding.get("_severity", "MEDIUM")
    else:
        # 未分类时使用启发式判断
        severity = get_severity(rule_id, finding.get("description", ""), file_path, match)
    
    emoji, sev_text = SEVERITY_EMOJI.get(severity, ("⚪", "未知"))
    
    lines.append(f"### [{rule_id}] {file_path}:{line_num}")
    lines.append("")
    lines.append(f"- **文件路径**: `{file_path}`")
    lines.append(f"- **行号**: {line_num}")
    lines.append(f"- **规则类型**: {rule_id}")
    
    if show_classification:
        status_emoji = {
            "CONFIRMED": "✅",
            "FALSE_POSITIVE": "❌",
            "PENDING": "⏳"
        }.get(classification, "⏳")
        lines.append(f"- **分类状态**: {status_emoji} {classification}")
    
    lines.append(f"- **风险等级**: {emoji} {sev_text}")
    lines.append(f"- **匹配内容**: `{mask_match_line(match)}`")
    lines.append("- **代码上下文**:")
    lines.append("  ```")
    for ctx_line in format_context(context).split("\n"):
        lines.append(f"  {ctx_line}")
    lines.append("  ```")
    
    hazard = get_hazard(rule_id, file_path, match, context)
    lines.append(f"- **潜在风险**: {hazard}")
    
    if reason:
        lines.append(f"- **分类依据**: {reason}")
    
    lines.append("")
    return lines


def derive_owner_repo(repo_path: str) -> tuple:
    """从路径提取 owner/repo"""
    if not repo_path or repo_path == "unknown":
        return "unknown", "unknown"
    parts = [p for p in repo_path.replace("\\", "/").split("/") if p]
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    if len(parts) == 1:
        return "unknown", parts[0]
    return "unknown", "unknown"


# ---------------------------------------------------------------------------
# 报告生成
# ---------------------------------------------------------------------------
def build_summary(
    findings: List[dict],
    repos: List[dict],
    has_classification: bool
) -> List[str]:
    """构建统计摘要"""
    lines = []
    lines.append("## 📊 统计摘要")
    lines.append("")
    
    # 基础统计
    total_findings = len(findings)
    total_repos = len(repos) if repos else len(set(f.get("repo_name") for f in findings if f.get("repo_name")))
    repos_with_findings = len(set(f.get("repo_name") for f in findings if f.get("repo_name")))
    
    lines.append(f"| 指标 | 数值 |")
    lines.append(f"|------|------|")
    lines.append(f"| 扫描仓库总数 | {total_repos} |")
    lines.append(f"| 涉及敏感信息仓库 | {repos_with_findings} |")
    lines.append(f"| 原始发现总数 | {total_findings} |")
    
    # 分类统计
    if has_classification:
        confirmed = [f for f in findings if f.get("classification") == "CONFIRMED"]
        false_positives = [f for f in findings if f.get("classification") == "FALSE_POSITIVE"]
        pending = [f for f in findings if f.get("classification") not in ("CONFIRMED", "FALSE_POSITIVE")]
        
        lines.append(f"| ✅ 确认泄露 | {len(confirmed)} |")
        lines.append(f"| ❌ 误报过滤 | {len(false_positives)} |")
        if pending:
            lines.append(f"| ⏳ 待分类 | {len(pending)} |")
    
    # 风险等级统计
    high_count = sum(1 for f in findings if get_severity(
        f.get("rule_id", ""), f.get("description", ""), f.get("file", ""), f.get("match", "")
    ) == "HIGH")
    medium_count = sum(1 for f in findings if get_severity(
        f.get("rule_id", ""), f.get("description", ""), f.get("file", ""), f.get("match", "")
    ) == "MEDIUM")
    
    lines.append(f"| 🔴 高风险 | {high_count} |")
    lines.append(f"| 🟡 中风险 | {medium_count} |")
    
    lines.append("")
    return lines


def build_recommendations(has_confirmed: bool) -> List[str]:
    """构建修复建议"""
    lines = []
    lines.append("## 🔧 修复建议")
    lines.append("")
    
    if has_confirmed:
        lines.append("### ⚠️ 立即行动")
        lines.append("")
        lines.append("1. **立即轮换泄露的凭证**")
        lines.append("   - 通过服务商控制台作废已泄露的密钥/令牌")
        lines.append("   - 生成新的凭证并更新应用程序配置")
        lines.append("   - 检查是否有异常访问日志")
        lines.append("")
        lines.append("2. **审计访问日志**")
        lines.append("   - 检查泄露的凭证是否被未授权方使用")
        lines.append("   - 查找可疑活动并评估影响范围")
        lines.append("")
    
    lines.append("### 🛡️ 预防措施")
    lines.append("")
    lines.append("1. **使用环境变量** 存储所有密钥，禁止硬编码")
    lines.append("2. **将 `.env` 文件加入 `.gitignore`** 后再提交代码")
    lines.append("3. **使用 pre-commit 钩子**（如 gitleaks、detect-secrets）进行秘密扫描")
    lines.append("4. **定期轮换密钥** 并限制密钥权限范围")
    lines.append("5. **审查历史提交** 中是否曾泄露过敏感信息")
    lines.append("")
    
    return lines


def generate_batch_report(data: dict, output_dir: Optional[Path] = None) -> Path:
    """生成批量扫描中文报告"""
    if output_dir is None:
        output_dir = Path("/tmp")
    else:
        output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 提取数据
    scan_id = data.get("scan_id", "unknown")
    timestamp = data.get("timestamp", datetime.now().isoformat())
    repos = data.get("repos", [])
    findings = data.get("findings", [])
    
    # 判断是否已分类
    has_classification = any(f.get("classification") for f in findings)
    
    # 分类统计
    confirmed = [f for f in findings if f.get("classification") == "CONFIRMED"]
    false_positives = [f for f in findings if f.get("classification") == "FALSE_POSITIVE"]
    pending = [f for f in findings if not f.get("classification")]
    
    print(f"[INFO] 总发现数: {len(findings)}", file=sys.stderr)
    if has_classification:
        print(f"[INFO] 确认泄露: {len(confirmed)}", file=sys.stderr)
        print(f"[INFO] 误报过滤: {len(false_positives)}", file=sys.stderr)
    else:
        print(f"[INFO] 未分类发现: {len(pending)}（原始 findings）", file=sys.stderr)
    
    lines = []
    lines.append("# 🔍 批量仓库敏感信息扫描报告")
    lines.append("")
    lines.append(f"**扫描ID**: `{scan_id}`")
    lines.append(f"**扫描时间**: {timestamp}")
    lines.append("**扫描工具**: secrets-scanner")
    lines.append("")
    
    # 统计摘要
    lines.extend(build_summary(findings, repos, has_classification))
    
    # 发现详情
    if not findings:
        lines.append("> **未发现任何敏感信息。**")
        lines.append("")
    else:
        lines.append("## 🔎 敏感信息详情")
        lines.append("")
        
        # 确定要显示哪些 findings
        if has_classification:
            # 已分类：只显示 CONFIRMED，其他只做统计
            display_findings = confirmed
            
            if not display_findings:
                lines.append("> **未发现确认的敏感信息泄露。**")
                lines.append("")
                lines.append(f"> 共分析了 {len(false_positives)} 条潜在发现，均已归类为误报。")
                lines.append("")
            else:
                # 按仓库分组
                groups = defaultdict(list)
                for f in display_findings:
                    repo_name = f.get("repo_name", "unknown")
                    groups[repo_name].append(f)
                
                for repo_name in sorted(groups.keys()):
                    repo_findings = groups[repo_name]
                    repo_path = repo_findings[0].get("repo_path", "unknown")
                    owner, _ = derive_owner_repo(repo_path)
                    
                    lines.append(f"### 📁 {owner}/{repo_name}")
                    lines.append("")
                    lines.append(f"- **仓库路径**: `{repo_path}`")
                    lines.append(f"- **确认发现数**: {len(repo_findings)}")
                    if false_positives:
                        fp_count = len([fp for fp in false_positives if fp.get("repo_name") == repo_name])
                        if fp_count > 0:
                            lines.append(f"- **过滤误报数**: {fp_count}")
                    lines.append("")
                    
                    for f in repo_findings:
                        f["_severity"] = get_severity(
                            f.get("rule_id", ""),
                            f.get("description", ""),
                            f.get("file", ""),
                            f.get("match", "")
                        )
                        lines.extend(format_finding(f, show_classification=True))
        else:
            # 未分类：显示所有 findings（但说明未分类）
            groups = defaultdict(list)
            for f in findings:
                repo_name = f.get("repo_name", "unknown")
                groups[repo_name].append(f)
            
            lines.append("> ⚠️ **注意**: 以下发现未经 AI 分类，可能包含误报")
            lines.append("")
            
            for repo_name in sorted(groups.keys()):
                repo_findings = groups[repo_name]
                repo_path = repo_findings[0].get("repo_path", "unknown")
                owner, _ = derive_owner_repo(repo_path)
                
                lines.append(f"### 📁 {owner}/{repo_name}")
                lines.append("")
                lines.append(f"- **仓库路径**: `{repo_path}`")
                lines.append(f"- **原始发现数**: {len(repo_findings)}")
                lines.append("")
                
                # 未分类模式下，只显示前10个详情，其余简化显示
                display_count = min(10, len(repo_findings))
                for f in repo_findings[:display_count]:
                    lines.extend(format_finding(f, show_classification=False))
                
                if len(repo_findings) > 10:
                    lines.append(f"")
                    lines.append(f"> *还有 {len(repo_findings) - 10} 条发现，请运行 AI 分类后查看完整报告*")
                    lines.append("")
    
    # 修复建议
    lines.extend(build_recommendations(bool(confirmed)))
    
    # 脚注
    if false_positives:
        lines.append("---")
        lines.append("")
        lines.append(f"*本次扫描分析了 {len(false_positives)} 条潜在发现并将其归类为误报。*")
    
    # 生成文件名
    report_name = f"batch-{scan_id}-report.md"
    report_path = output_dir / report_name
    
    # 写入文件（分块写入处理大文件）
    with open(report_path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    
    return report_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 batch-generate-report.py <batch-scan-findings.json|scan-classified.json> [output-dir]", file=sys.stderr)
        print("", file=sys.stderr)
        print("  支持两种输入格式:", file=sys.stderr)
        print("    - batch-scan-findings.json: 批量扫描原始结果", file=sys.stderr)
        print("    - scan-classified.json: AI 分类后的结果", file=sys.stderr)
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
    
    report_path = generate_batch_report(data, output_dir)
    print(str(report_path))


if __name__ == "__main__":
    main()
