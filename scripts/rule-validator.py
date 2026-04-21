#!/usr/bin/env python3
"""
Rule lifecycle validator for secrets-scanner.

Manages experimental -> confirmed promotion based on validation scans.

Usage:
  python scripts/rule-validator.py --validate          # Validate all rules
  python scripts/rule-validator.py --promote           # Promote validated rules
  python scripts/rule-validator.py --clean             # Remove orphaned rules
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
RULES_DIR = SKILL_DIR / "references" / "rules"
LEARNING_DIR = SKILL_DIR / ".learning"
AUTO_FILTER_PATH = RULES_DIR / "auto-filter-rules.toml"
VALIDATION_THRESHOLD = 3
ORPHAN_THRESHOLD = 10


def parse_toml_rules(path):
    """Parse auto-filter-rules.toml and extract rule blocks."""
    if not path.exists():
        return []
    
    content = path.read_text(encoding="utf-8")
    rules = []
    current_rule = None
    current_block = []
    
    for line in content.splitlines():
        if line.strip().startswith("[[rules]]"):
            if current_rule is not None:
                current_rule["_raw"] = "\n".join(current_block)
                rules.append(current_rule)
            current_rule = {"_raw_lines": []}
            current_block = [line]
        elif current_rule is not None:
            current_block.append(line)
            # Parse key-value pairs
            if "=" in line and not line.strip().startswith("["):
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key in ("id", "description", "status", "created", "validated_at"):
                    current_rule[key] = val
                elif key == "validation_count":
                    try:
                        current_rule[key] = int(val)
                    except ValueError:
                        current_rule[key] = 0
                elif key == "source_scans":
                    # Parse array format ["001", "002"]
                    val = val.strip("[]")
                    if val:
                        current_rule[key] = [v.strip().strip('"').strip("'") for v in val.split(",")]
                    else:
                        current_rule[key] = []
    
    if current_rule is not None:
        current_rule["_raw"] = "\n".join(current_block)
        rules.append(current_rule)
    
    return rules


def validate_regexes(rules):
    """Validate that all regexes in allowlist rules compile correctly."""
    errors = []
    
    for rule in rules:
        rule_id = rule.get("id", "unknown")
        # Extract regexes from raw block
        raw = rule.get("_raw", "")
        
        # Find all regexes in allowlist section
        in_allowlist = False
        for line in raw.splitlines():
            if "[allowlist]" in line:
                in_allowlist = True
            elif line.strip().startswith("[") and "allowlist" not in line:
                in_allowlist = False
            
            if in_allowlist and "regexes" in line and "=" in line:
                # Extract regex values from the line
                val_part = line.split("=", 1)[1].strip()
                # Handle multi-line arrays
                if val_part.startswith("["):
                    # Single line array
                    regexes = extract_regexes_from_array(val_part)
                    for regex in regexes:
                        try:
                            re.compile(regex)
                        except re.error as e:
                            errors.append(f"  {rule_id}: Invalid regex '{regex[:50]}...' - {e}")
    
    return errors


def extract_regexes_from_array(text):
    """Extract regex strings from a TOML array declaration."""
    # Simple parser for ['''regex1''', '''regex2'''] format
    regexes = []
    # Find all triple-quoted strings
    parts = text.split("'''")
    for i in range(1, len(parts), 2):
        if i < len(parts):
            regexes.append(parts[i])
    return regexes


def check_rule_effectiveness(rules):
    """Check if experimental rules have prevented false positives in recent scans."""
    if not LEARNING_DIR.exists():
        return {}
    
    learning_files = sorted(LEARNING_DIR.glob("scan-*-false-positives.json"))
    if not learning_files:
        return {}
    
    # Load all learning data
    all_false_positives = []
    for f in learning_files:
        try:
            with open(f, "r", encoding="utf-8") as fp:
                data = json.load(fp)
                all_false_positives.extend(data.get("false_positives", []))
        except (json.JSONDecodeError, IOError):
            continue
    
    # Check each experimental rule
    effectiveness = {}
    for rule in rules:
        if rule.get("status") != "experimental":
            continue
        
        rule_id = rule.get("id", "")
        # Check if any recent false positive would have been caught by this rule
        # This is approximate - we check if the rule's patterns match recent false positives
        raw = rule.get("_raw", "")
        regexes = extract_all_regexes(raw)
        
        match_count = 0
        for fp in all_false_positives:
            secret = fp.get("secret", "")
            match_val = fp.get("match", "")
            for regex in regexes:
                try:
                    if re.search(regex, secret) or re.search(regex, match_val):
                        match_count += 1
                        break
                except re.error:
                    continue
        
        effectiveness[rule_id] = match_count
    
    return effectiveness


def extract_all_regexes(raw_text):
    """Extract all regex patterns from a rule block."""
    regexes = []
    in_allowlist = False
    
    for line in raw_text.splitlines():
        if "[allowlist]" in line:
            in_allowlist = True
        elif line.strip().startswith("[") and "allowlist" not in line:
            in_allowlist = False
        
        if in_allowlist and ("regexes" in line or "regexTarget" in line):
            # Try to extract regex from the line
            val_part = line.split("=", 1)[1].strip() if "=" in line else ""
            if val_part.startswith("["):
                regexes.extend(extract_regexes_from_array(val_part))
            elif "'''" in val_part:
                parts = val_part.split("'''")
                if len(parts) >= 3:
                    regexes.append(parts[1])
    
    return regexes


def promote_rules(rules, effectiveness):
    """Promote experimental rules that have validated enough times."""
    promoted = []
    
    for rule in rules:
        if rule.get("status") != "experimental":
            continue
        
        rule_id = rule.get("id", "")
        current_count = rule.get("validation_count", 0)
        effective_count = effectiveness.get(rule_id, 0)
        
        # Increment validation count if rule was effective
        if effective_count > 0:
            current_count += 1
            rule["validation_count"] = current_count
        
        # Promote if threshold reached
        if current_count >= VALIDATION_THRESHOLD:
            rule["status"] = "confirmed"
            rule["validated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            promoted.append(rule_id)
    
    return promoted


def remove_orphaned_rules(rules):
    """Remove experimental rules that haven't validated after many scans."""
    orphaned = []
    kept = []
    
    for rule in rules:
        if rule.get("status") == "experimental":
            count = rule.get("validation_count", 0)
            created = rule.get("created", "")
            # Rough check: if created long ago and still 0 validations
            if count == 0 and created:
                try:
                    created_date = datetime.strptime(created, "%Y-%m-%d")
                    days_old = (datetime.now() - created_date).days
                    if days_old > 30:  # Older than 30 days with 0 validations
                        orphaned.append(rule.get("id", ""))
                        continue
                except ValueError:
                    pass
        kept.append(rule)
    
    return kept, orphaned


def rewrite_rules_file(rules):
    """Rewrite auto-filter-rules.toml with updated rules."""
    lines = [
        'title = "AI-Generated Filter Rules"',
        f'last_updated = "{datetime.now(timezone.utc).isoformat()}"',
        "",
    ]
    
    for rule in rules:
        lines.append("[[rules]]")
        lines.append(f'id = "{rule.get("id", "")}"')
        lines.append(f'description = "{rule.get("description", "")}"')
        lines.append(f'status = "{rule.get("status", "experimental")}"')
        lines.append(f'created = "{rule.get("created", "")}"')
        
        if rule.get("validated_at"):
            lines.append(f'validated_at = "{rule.get("validated_at")}"')
        
        lines.append(f'validation_count = {rule.get("validation_count", 0)}')
        
        source_scans = rule.get("source_scans", [])
        if source_scans:
            scans_str = ", ".join(f'"{s}"' for s in source_scans)
            lines.append(f'source_scans = [{scans_str}]')
        
        # Copy allowlist section from raw
        raw = rule.get("_raw", "")
        in_allowlist = False
        for line in raw.splitlines():
            if "[allowlist]" in line:
                in_allowlist = True
            if in_allowlist:
                lines.append(line)
        
        lines.append("")
    
    AUTO_FILTER_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OK] Updated {AUTO_FILTER_PATH}")


def validate():
    """Run full validation cycle."""
    print("=== Rule Validation ===")
    
    if not AUTO_FILTER_PATH.exists():
        print("[INFO] No auto-filter rules found")
        return
    
    rules = parse_toml_rules(AUTO_FILTER_PATH)
    print(f"[INFO] Found {len(rules)} rules")
    
    experimental = [r for r in rules if r.get("status") == "experimental"]
    confirmed = [r for r in rules if r.get("status") == "confirmed"]
    print(f"[INFO]  - Experimental: {len(experimental)}")
    print(f"[INFO]  - Confirmed: {len(confirmed)}")
    
    # Validate regexes
    print("\n[VALIDATE] Checking regex compilation...")
    errors = validate_regexes(rules)
    if errors:
        print(f"[WARN] Found {len(errors)} invalid regexes:")
        for err in errors:
            print(err)
    else:
        print("[OK] All regexes compile successfully")
    
    # Check effectiveness
    print("\n[VALIDATE] Checking rule effectiveness...")
    effectiveness = check_rule_effectiveness(rules)
    if effectiveness:
        for rule_id, count in effectiveness.items():
            print(f"  {rule_id}: prevented {count} false positives")
    
    # Promote validated rules
    print("\n[PROMOTE] Checking for rules to promote...")
    promoted = promote_rules(rules, effectiveness)
    if promoted:
        print(f"[OK] Promoted to confirmed: {', '.join(promoted)}")
    else:
        print("[INFO] No rules ready for promotion")
    
    # Clean orphaned rules
    print("\n[CLEAN] Checking for orphaned rules...")
    rules, orphaned = remove_orphaned_rules(rules)
    if orphaned:
        print(f"[OK] Removed orphaned rules: {', '.join(orphaned)}")
    else:
        print("[INFO] No orphaned rules found")
    
    # Rewrite file
    rewrite_rules_file(rules)
    print("\n[OK] Validation complete")


def main():
    parser = argparse.ArgumentParser(description="Rule lifecycle validator")
    parser.add_argument("--validate", action="store_true", help="Run full validation")
    parser.add_argument("--promote", action="store_true", help="Promote validated rules only")
    parser.add_argument("--clean", action="store_true", help="Remove orphaned rules only")
    
    args = parser.parse_args()
    
    if args.validate or args.promote or args.clean:
        validate()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
