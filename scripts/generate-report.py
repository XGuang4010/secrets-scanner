#!/usr/bin/env python3
"""
Generate Markdown report from AI-classified scan results.

Only CONFIRMED findings are included in the report.
FALSE_POSITIVE findings are skipped (they're used for auto-learning instead).

Usage:
  python scripts/generate-report.py /tmp/scan-classified.json
  
Output:
  Prints path to generated Markdown report
"""

import json
import sys
from datetime import datetime
from pathlib import Path


def mask_secret(value):
    """Mask a secret for display: first 4 + **** + last 4."""
    if not value:
        return "****"
    if len(value) > 8:
        return value[:4] + "****" + value[-4:]
    return "****"


def get_severity(rule_id, description):
    """Determine severity based on rule type."""
    high_severity = ["aws", "gcp", "azure", "github", "gitlab", "slack", "stripe", "openai"]
    medium_severity = ["generic", "password", "secret", "token"]
    
    rule_lower = rule_id.lower()
    desc_lower = description.lower()
    
    for keyword in high_severity:
        if keyword in rule_lower or keyword in desc_lower:
            return "HIGH"
    
    for keyword in medium_severity:
        if keyword in rule_lower or keyword in desc_lower:
            return "MEDIUM"
    
    return "LOW"


def format_context(context):
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


def generate_report(classified_data, output_dir=None):
    """Generate Markdown report from classified findings."""
    if output_dir is None:
        output_dir = Path("/tmp")
    else:
        output_dir = Path(output_dir)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    scan_id = classified_data.get("scan_id", "unknown")
    repo_path = classified_data.get("repo_path", "unknown")
    timestamp = classified_data.get("timestamp", datetime.now().isoformat())
    all_findings = classified_data.get("findings", [])
    
    # Filter to only CONFIRMED findings
    confirmed = [f for f in all_findings if f.get("classification") == "CONFIRMED"]
    false_positives = [f for f in all_findings if f.get("classification") == "FALSE_POSITIVE"]
    
    # Group confirmed by severity
    high_risk = []
    medium_risk = []
    low_risk = []
    
    for f in confirmed:
        severity = get_severity(f.get("rule_id", ""), f.get("description", ""))
        f["_severity"] = severity
        if severity == "HIGH":
            high_risk.append(f)
        elif severity == "MEDIUM":
            medium_risk.append(f)
        else:
            low_risk.append(f)
    
    lines = []
    lines.append("# Secrets Scan Report")
    lines.append("")
    lines.append(f"**Repository:** `{repo_path}`")
    lines.append(f"**Scan ID:** `{scan_id}`")
    lines.append(f"**Scan Date:** {timestamp}")
    lines.append("")
    
    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append("| Category | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| **Confirmed Leaks** | **{len(confirmed)}** |")
    lines.append(f"| - High Severity | {len(high_risk)} |")
    lines.append(f"| - Medium Severity | {len(medium_risk)} |")
    lines.append(f"| - Low Severity | {len(low_risk)} |")
    lines.append(f"| False Positives (filtered) | {len(false_positives)} |")
    lines.append(f"| **Total Raw Findings** | {len(all_findings)} |")
    lines.append("")
    
    if not confirmed:
        lines.append("> **No confirmed secrets detected.**")
        lines.append("> ")
        lines.append(f"> {len(false_positives)} potential findings were analyzed and classified as false positives.")
        lines.append("")
    
    # Findings by severity
    if confirmed:
        lines.append("## Findings by Severity")
        lines.append("")
        
        if high_risk:
            lines.append(f"### 🔴 HIGH ({len(high_risk)})")
            lines.append("")
            for f in high_risk:
                lines.extend(format_finding(f))
        
        if medium_risk:
            lines.append(f"### 🟡 MEDIUM ({len(medium_risk)})")
            lines.append("")
            for f in medium_risk:
                lines.extend(format_finding(f))
        
        if low_risk:
            lines.append(f"### 🟢 LOW ({len(low_risk)})")
            lines.append("")
            for f in low_risk:
                lines.extend(format_finding(f))
    
    # Recommendations
    lines.append("## Recommendations")
    lines.append("")
    
    if confirmed:
        lines.append("### Immediate Actions")
        lines.append("")
        lines.append("1. **Rotate exposed credentials immediately**")
        lines.append("   - Invalidate leaked keys/tokens via provider dashboard")
        lines.append("   - Generate new credentials")
        lines.append("   - Update applications with new credentials")
        lines.append("")
        lines.append("2. **Audit access logs**")
        lines.append("   - Check if leaked credentials were used by unauthorized parties")
        lines.append("   - Look for suspicious activity")
        lines.append("")
        
        lines.append("### Prevention")
        lines.append("")
        lines.append("1. **Use environment variables** for all secrets")
        lines.append("2. **Add `.env` files to `.gitignore`** before committing")
        lines.append("3. **Use secret scanning pre-commit hooks** (gitleaks, detect-secrets)")
        lines.append("4. **Review historical commits** for previously leaked secrets:")
        lines.append(f"   ```bash")
        lines.append(f"   cd {repo_path}")
        lines.append(f"   git log --all --full-history --source -- '*.env' '*.key' '*secret*'")
        lines.append(f"   ```")
    else:
        lines.append("- Continue using pre-commit hooks to prevent future leaks")
        lines.append("- Store all secrets in environment variables or secret management systems")
        lines.append("- Never commit `.env` files or configuration files with hardcoded credentials")
    
    lines.append("")
    
    # Auto-learning note
    if false_positives:
        lines.append("---")
        lines.append("")
        lines.append("*This scan analyzed " + str(len(false_positives)) + " potential findings and classified them as false positives. " + "The AI will generate/update allowlist rules to filter similar patterns in future scans.*")
    
    # Write report
    report_path = output_dir / f"secrets-report-{scan_id}.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    
    return report_path


def format_finding(finding):
    """Format a single finding for the report."""
    lines = []
    
    rule_id = finding.get("rule_id", "unknown")
    description = finding.get("description", "")
    file_path = finding.get("file", "unknown")
    line_num = finding.get("line", 0)
    secret = finding.get("secret", "")
    masked = mask_secret(secret)
    reason = finding.get("reason", "")
    context = finding.get("context", {})
    
    lines.append(f"**{rule_id}** - {description}")
    lines.append("")
    lines.append(f"- **Location:** `{file_path}:{line_num}`")
    lines.append(f"- **Masked Value:** `{masked}`")
    if reason:
        lines.append(f"- **Classification Reason:** {reason}")
    lines.append("")
    lines.append("- **Context:**")
    lines.append("  ```")
    for ctx_line in format_context(context).split("\n"):
        lines.append(f"  {ctx_line}")
    lines.append("  ```")
    lines.append("")
    
    return lines


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate-report.py <scan-classified.json> [output-dir]", file=sys.stderr)
        sys.exit(1)
    
    input_path = Path(sys.argv[1])
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)
    
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse JSON: {e}", file=sys.stderr)
        sys.exit(1)
    
    report_path = generate_report(data, output_dir)
    print(str(report_path))


if __name__ == "__main__":
    main()
