#!/usr/bin/env python3
"""Generate Markdown reports from gitleaks JSON output."""

import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def load_findings(json_paths):
    """Load and deduplicate findings from one or more gitleaks JSON files."""
    findings = []
    seen = set()
    for path in json_paths:
        p = Path(path)
        if not p.exists():
            print(f"WARNING: JSON file not found: {path}", file=sys.stderr)
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"WARNING: Failed to parse {path}: {e}", file=sys.stderr)
            continue
        if isinstance(data, dict):
            items = data.get("findings", [])
        elif isinstance(data, list):
            items = data
        else:
            print(f"WARNING: Unexpected JSON structure in {path}", file=sys.stderr)
            continue
        for item in items:
            fp = item.get("Fingerprint", "")
            if not fp:
                fp = f"{item.get('File','')}:{item.get('RuleID','')}:{item.get('StartLine','')}"
            if fp not in seen:
                seen.add(fp)
                item["_source_file"] = str(p)
                findings.append(item)
    return findings


def mask_secret(value):
    """Mask a secret: first 4 + **** + last 4 if length > 8, else ****."""
    if not value or value == "***":
        return "****"
    if len(value) > 8:
        return value[:4] + "****" + value[-4:]
    return "****"


def extract_match_secret(finding):
    """Extract the best secret value to mask from a finding."""
    secret = finding.get("Secret", "")
    if secret and secret != "***":
        return secret
    match = finding.get("Match", "")
    if not match:
        return ""
    # Try to extract just the value portion from patterns like KEY="value"
    if "=" in match:
        parts = match.split("=", 1)
        val = parts[1].strip().strip('"').strip("'")
        if val:
            return val
    return match


def get_context(repo_path, finding):
    """Extract +/- 3 lines around the finding with line numbers."""
    file_rel = finding.get("File", "")
    start_line = finding.get("StartLine", 1)
    end_line = finding.get("EndLine", start_line)
    file_path = Path(repo_path) / file_rel

    if not file_path.exists():
        return f"[File not found: {file_rel}]"

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        return f"[Error reading {file_rel}: {e}]"

    # Determine line range (1-indexed)
    ctx_start = max(1, start_line - 3)
    ctx_end = min(len(lines), end_line + 3)

    result = []
    for i in range(ctx_start, ctx_end + 1):
        line_text = lines[i - 1].rstrip("\n\r")
        marker = ">>> " if start_line <= i <= end_line else "    "
        result.append(f"{marker}{i:4d} | {line_text}")

    return "\n".join(result)


def generate_markdown(repo_path, findings, output_dir):
    """Generate a Markdown report from findings."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(findings)

    # Determine counts per source file
    source_counts = defaultdict(int)
    for f in findings:
        src = f.get("_source_file", "unknown")
        source_counts[src] += 1

    # Group by RuleID
    rule_groups = defaultdict(list)
    for f in findings:
        rule_groups[f.get("RuleID", "Unknown")].append(f)

    # Sort rule groups by RuleID for consistent output
    sorted_rules = sorted(rule_groups.keys())

    lines = []
    lines.append("# Secrets Scan Report")
    lines.append("")
    lines.append(f"**Repository:** `{repo_path}`")
    lines.append(f"**Scan Date:** {scan_date}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Source | Findings |")
    lines.append("|--------|----------|")
    for src, count in sorted(source_counts.items()):
        name = Path(src).name
        lines.append(f"| {name} | {count} |")
    lines.append(f"| **Total Unique** | **{total}** |")
    lines.append("")

    lines.append("## Findings by Rule")
    lines.append("")

    for rule_id in sorted_rules:
        group = rule_groups[rule_id]
        lines.append(f"### {rule_id} ({len(group)})")
        lines.append("")
        for f in group:
            file_rel = f.get("File", "unknown")
            line_num = f.get("StartLine", 0)
            secret_raw = extract_match_secret(f)
            masked = mask_secret(secret_raw)
            desc = f.get("Description", "")
            lines.append(f"- `{file_rel}:{line_num}` -- `{masked}`")
            if desc:
                lines.append(f"  - **Description:** {desc}")
            ctx = get_context(repo_path, f)
            lines.append("  - **Context:**")
            lines.append("    ```")
            for ctx_line in ctx.splitlines():
                lines.append(f"    {ctx_line}")
            lines.append("    ```")
            lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    lines.append("1. Rotate any exposed credentials immediately.")
    lines.append("2. Move secrets to environment variables or secret management systems.")
    lines.append("3. Add `.env` files and secret configs to `.gitignore`.")
    lines.append("4. Review historical commits for previously leaked secrets.")
    lines.append("")

    md_path = output_dir / "secrets-report.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return md_path


def main():
    if len(sys.argv) < 4:
        print("Usage: python3 generate-report.py <repo_path> <output_dir> <json_file1> [json_file2 ...]", file=sys.stderr)
        sys.exit(1)

    repo_path = sys.argv[1]
    output_dir = sys.argv[2]
    json_files = sys.argv[3:]

    findings = load_findings(json_files)
    if not findings:
        print("No findings to report.", file=sys.stderr)
        # Still generate an empty report

    md_path = generate_markdown(repo_path, findings, output_dir)
    print(str(md_path))


if __name__ == "__main__":
    main()
