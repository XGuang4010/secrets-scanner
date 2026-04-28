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
import sys
from collections import defaultdict

if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")
from datetime import datetime
from pathlib import Path

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


def is_batch_scan(data: dict) -> bool:
    """Detect batch scan from top-level fields or heterogeneous findings."""
    if data.get("repos"):
        return True
    findings = data.get("findings", [])
    repo_names = {f.get("repo_name") for f in findings if f.get("repo_name")}
    return len(repo_names) > 1


def format_finding(finding: dict, validity: dict = None) -> list:
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
    
    # Add verification result if available
    if validity:
        status = validity.get("status", "UNKNOWN")
        detail = validity.get("detail", "")
        validator = validity.get("validator", "")
        http_status = validity.get("http_status", "")
        
        status_emoji = {
            "VALID": "✅",
            "INVALID": "❌",
            "UNKNOWN": "❓",
            "NOT_TESTABLE": "🔒",
        }.get(status, "❓")
        
        lines.append(f"- **实际验证**: {status_emoji} {status}")
        if detail:
            lines.append(f"  - 详情: {detail}")
        if validator:
            lines.append(f"  - 验证器: `{validator}`")
        if http_status:
            lines.append(f"  - HTTP 状态: {http_status}")
    
    lines.append("")
    return lines


def build_summary_lines(confirmed, high_risk, medium_risk, low_risk, false_positives, all_findings, verification_map=None):
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
    
    # Add verification summary if available
    if verification_map:
        valid_count = sum(1 for v in verification_map.values() if v.get("status") == "VALID")
        invalid_count = sum(1 for v in verification_map.values() if v.get("status") == "INVALID")
        unknown_count = sum(1 for v in verification_map.values() if v.get("status") == "UNKNOWN")
        not_testable_count = sum(1 for v in verification_map.values() if v.get("status") == "NOT_TESTABLE")
        lines.append("")
        lines.append("| 验证结果 | 数量 |")
        lines.append("|------|------|")
        lines.append(f"| ✅ 有效 (VALID) | {valid_count} |")
        lines.append(f"| ❌ 无效 (INVALID) | {invalid_count} |")
        lines.append(f"| ❓ 未知 (UNKNOWN) | {unknown_count} |")
        lines.append(f"| 🔒 无法验证 (NOT_TESTABLE) | {not_testable_count} |")
    
    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Main report generation
# ---------------------------------------------------------------------------
def generate_report(classified_data: dict, output_dir=None, verified_data=None):
    if output_dir is None:
        output_dir = Path.cwd()
    else:
        output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    scan_id = classified_data.get("scan_id", "unknown")
    top_repo_path = classified_data.get("repo_path", "unknown")
    timestamp = classified_data.get("timestamp", datetime.now().isoformat())
    all_findings = classified_data.get("findings", [])

    # Build verification lookup map
    verification_map = {}
    if verified_data and "findings" in verified_data:
        for vf in verified_data["findings"]:
            fid = vf.get("finding_id")
            if fid and "validity" in vf:
                verification_map[fid] = vf["validity"]

    confirmed = [f for f in all_findings if f.get("classification") == "CONFIRMED"]
    false_positives = [f for f in all_findings if f.get("classification") == "FALSE_POSITIVE"]

    print(f"[INFO] 确认泄露数: {len(confirmed)}", file=sys.stderr)
    print(f"[INFO] 已过滤误报数: {len(false_positives)}", file=sys.stderr)
    if verification_map:
        print(f"[INFO] 验证结果已加载: {len(verification_map)} 条", file=sys.stderr)

    batch = is_batch_scan(classified_data)

    # Assign severity (prefer AI-classified severity, fallback to heuristic)
    high_risk = []
    medium_risk = []
    low_risk = []
    for f in confirmed:
        sev = f.get("severity", "").upper()
        if sev not in ("HIGH", "MEDIUM", "LOW"):
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
        lines.extend(build_summary_lines(confirmed, high_risk, medium_risk, low_risk, false_positives, all_findings, verification_map))

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
                    validity = verification_map.get(f.get("finding_id"))
                    lines.extend(format_finding(f, validity))
    else:
        owner, repo = derive_owner_repo(top_repo_path)
        lines.append(f"# {owner}/{repo} 敏感信息扫描报告")
        lines.append("")
        lines.append(f"**仓库地址**: https://github.com/{owner}/{repo}")
        lines.append(f"**扫描时间**: {timestamp}")
        lines.append("**扫描工具**: secrets-scanner")
        lines.append("")
        lines.extend(build_summary_lines(confirmed, high_risk, medium_risk, low_risk, false_positives, all_findings, verification_map))

        if not confirmed:
            lines.append("> **未发现确认的敏感信息泄露。**")
            lines.append(f"> 共分析了 {len(false_positives)} 条潜在发现，均已归类为误报。")
            lines.append("")
        else:
            lines.append("## 敏感信息详情")
            lines.append("")
            for f in confirmed:
                validity = verification_map.get(f.get("finding_id"))
                lines.extend(format_finding(f, validity))

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
        print("Usage: python3 generate-report.py <scan-classified.json> [output-dir] [--verified <scan-verified.json>]", file=sys.stderr)
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Parse optional --verified flag
    verified_path = None
    if "--verified" in sys.argv:
        idx = sys.argv.index("--verified")
        if idx + 1 < len(sys.argv):
            verified_path = Path(sys.argv[idx + 1])
    
    # Auto-infer verified path if not provided
    if not verified_path and input_path.name == "scan-classified.json":
        auto_path = input_path.parent / "scan-verified.json"
        if auto_path.exists():
            verified_path = auto_path

    if not input_path.exists():
        print(f"ERROR: 输入文件不存在: {input_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: JSON 解析失败: {e}", file=sys.stderr)
        sys.exit(1)

    # Load verification data if available
    verified_data = None
    if verified_path and verified_path.exists():
        try:
            with open(verified_path, "r", encoding="utf-8") as f:
                verified_data = json.load(f)
            print(f"[INFO] 已加载验证结果: {verified_path}", file=sys.stderr)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[WARN] 无法读取验证结果: {e}", file=sys.stderr)

    report_path = generate_report(data, output_dir, verified_data)
    print(str(report_path))


if __name__ == "__main__":
    main()
