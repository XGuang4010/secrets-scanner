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
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from report_common import (
    SEVERITY_EMOJI,
    build_recommendations_lines,
    derive_owner_repo,
    format_context,
    get_hazard,
    get_severity,
    mask_match_line,
    mask_secret,
)


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
        f.get("rule_id", ""), f.get("description", ""), f.get("file", ""), f.get("context", {}), f.get("match", "")
    ) == "HIGH")
    medium_count = sum(1 for f in findings if get_severity(
        f.get("rule_id", ""), f.get("description", ""), f.get("file", ""), f.get("context", {}), f.get("match", "")
    ) == "MEDIUM")
    
    lines.append(f"| 🔴 高风险 | {high_count} |")
    lines.append(f"| 🟡 中风险 | {medium_count} |")
    
    lines.append("")
    return lines


def generate_batch_report(data: dict, output_dir: Optional[Path] = None) -> Path:
    """生成批量扫描中文报告"""
    if output_dir is None:
        output_dir = Path.cwd()
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
                            f.get("context", {}),
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
    lines.extend(build_recommendations_lines(bool(confirmed)))
    
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
