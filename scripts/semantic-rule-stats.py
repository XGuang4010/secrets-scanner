#!/usr/bin/env python3
"""
Semantic rules statistics and management.

Tracks hit counts, effectiveness, and provides insights for rule optimization.

Usage:
  python scripts/semantic-rule-stats.py --list
  python scripts/semantic-rule-stats.py --report
  python scripts/semantic-rule-stats.py --unused
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
SEMANTIC_DIR = SKILL_DIR / "references" / "semantic-rules"


def load_yaml_rules():
    """Load all semantic rule YAML files."""
    import yaml
    rules = []
    for rule_file in sorted(SEMANTIC_DIR.glob("*.yaml")):
        try:
            with open(rule_file, "r") as f:
                data = yaml.safe_load(f)
            data["_source_file"] = rule_file.name
            rules.append(data)
        except Exception as e:
            print(f"WARNING: Failed to load {rule_file}: {e}", file=sys.stderr)
    return rules


def load_yaml_fallback():
    """Fallback: parse YAML-like structure without PyYAML."""
    rules = []
    for rule_file in sorted(SEMANTIC_DIR.glob("*.yaml")):
        try:
            content = rule_file.read_text()
            # Simple parsing for hit_stats section
            rule = {"_source_file": rule_file.name, "hit_stats": {}}
            for line in content.split("\n"):
                if "total_hits:" in line:
                    rule["hit_stats"]["total_hits"] = int(line.split(":")[1].strip())
                if "confirmed_as_fp:" in line:
                    rule["hit_stats"]["confirmed_as_fp"] = int(line.split(":")[1].strip())
                if "confirmed_as_real:" in line:
                    rule["hit_stats"]["confirmed_as_real"] = int(line.split(":")[1].strip())
                if "pattern_name:" in line:
                    rule["pattern_name"] = line.split(":")[1].strip().strip('"')
                if "pattern_id:" in line:
                    rule["pattern_id"] = line.split(":")[1].strip().strip('"')
                if "hit_count:" in line:
                    rule["hit_count"] = int(line.split(":")[1].strip())
            rules.append(rule)
        except Exception as e:
            print(f"WARNING: Failed to parse {rule_file}: {e}", file=sys.stderr)
    return rules


def list_rules(rules):
    """Display all semantic rules."""
    print("=" * 80)
    print("SEMANTIC RULES INVENTORY")
    print("=" * 80)
    print()

    total_hits = 0
    total_fp = 0
    total_real = 0

    for rule in rules:
        stats = rule.get("hit_stats", {})
        hits = stats.get("total_hits", rule.get("hit_count", 0))
        fp = stats.get("confirmed_as_fp", 0)
        real = stats.get("confirmed_as_real", 0)
        total_hits += hits
        total_fp += fp
        total_real += real

        print(f"Rule: {rule.get('pattern_name', 'Unknown')}")
        print(f"  ID: {rule.get('pattern_id', 'unknown')}")
        print(f"  File: {rule.get('_source_file', 'N/A')}")
        print(f"  Hits: {hits} (FP: {fp}, Real: {real})")
        print()

    print("-" * 80)
    print(f"Total: {len(rules)} rules")
    print(f"Total hits: {total_hits} (FP: {total_fp}, Real: {total_real})")
    print()


def report_effectiveness(rules):
    """Analyze rule effectiveness."""
    print("=" * 80)
    print("RULE EFFECTIVENESS REPORT")
    print("=" * 80)
    print()

    for rule in rules:
        stats = rule.get("hit_stats", {})
        hits = stats.get("total_hits", rule.get("hit_count", 0))
        fp = stats.get("confirmed_as_fp", 0)
        real = stats.get("confirmed_as_real", 0)

        if hits == 0:
            continue

        accuracy = (fp / hits * 100) if hits > 0 else 0
        name = rule.get("pattern_name", "Unknown")

        print(f"{name}")
        print(f"  Total hits: {hits}")
        print(f"  Correctly identified as FP: {fp} ({accuracy:.1f}%)")
        print(f"  Misclassified (real secrets): {real}")

        if accuracy >= 90:
            print(f"  Status: ✅ Excellent - Ready for promotion to confirmed")
        elif accuracy >= 70:
            print(f"  Status: 🟡 Good - Needs more validation")
        elif accuracy >= 50:
            print(f"  Status: 🟠 Fair - Review needed")
        else:
            print(f"  Status: ❌ Poor - Consider revision or removal")
        print()


def find_unused_rules(rules):
    """Find rules that have never been hit."""
    print("=" * 80)
    print("UNUSED RULES (0 hits)")
    print("=" * 80)
    print()

    unused = []
    for rule in rules:
        hits = rule.get("hit_stats", {}).get("total_hits", rule.get("hit_count", 0))
        if hits == 0:
            unused.append(rule)

    if not unused:
        print("All rules have been hit at least once.")
    else:
        for rule in unused:
            print(f"- {rule.get('pattern_name', 'Unknown')} ({rule.get('_source_file', 'N/A')})")
        print(f"\nTotal unused: {len(unused)}")
        print("Consider removing or reviewing these rules.")


def generate_markdown_report(rules):
    """Generate a Markdown report of semantic rules."""
    lines = []
    lines.append("# Semantic Rules Report")
    lines.append("")
    lines.append("| Rule | Hits | FP | Real | Accuracy | Status |")
    lines.append("|------|------|-----|------|----------|--------|")

    for rule in rules:
        stats = rule.get("hit_stats", {})
        hits = stats.get("total_hits", rule.get("hit_count", 0))
        fp = stats.get("confirmed_as_fp", 0)
        real = stats.get("confirmed_as_real", 0)
        accuracy = (fp / hits * 100) if hits > 0 else 0
        name = rule.get("pattern_name", "Unknown")

        if accuracy >= 90:
            status = "✅ Ready"
        elif accuracy >= 70:
            status = "🟡 Good"
        elif accuracy >= 50:
            status = "🟠 Review"
        else:
            status = "❌ Poor"

        lines.append(f"| {name} | {hits} | {fp} | {real} | {accuracy:.0f}% | {status} |")

    report_path = SKILL_DIR / "references" / "semantic-rules-report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Report saved to: {report_path}")


def main():
    parser = argparse.ArgumentParser(description="Semantic rules statistics")
    parser.add_argument("--list", action="store_true", help="List all rules")
    parser.add_argument("--report", action="store_true", help="Show effectiveness report")
    parser.add_argument("--unused", action="store_true", help="Find unused rules")
    parser.add_argument("--markdown", action="store_true", help="Generate Markdown report")

    args = parser.parse_args()

    # Try PyYAML first, fallback to simple parser
    try:
        rules = load_yaml_rules()
    except ImportError:
        rules = load_yaml_fallback()

    if not rules:
        print("No semantic rules found.")
        sys.exit(1)

    if args.list:
        list_rules(rules)
    elif args.report:
        report_effectiveness(rules)
    elif args.unused:
        find_unused_rules(rules)
    elif args.markdown:
        generate_markdown_report(rules)
    else:
        # Default: show all
        list_rules(rules)
        print("\n")
        report_effectiveness(rules)


if __name__ == "__main__":
    main()
