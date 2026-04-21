#!/usr/bin/env python3
"""Merge all .toml rule files into a single gitleaks config."""

import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

SCRIPT_DIR = Path(__file__).resolve().parent
RULES_DIR = SCRIPT_DIR.parent / "references" / "rules"
DEFAULT_OUTPUT = "/tmp/gitleaks-custom-rules.toml"


def parse_toml(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def format_rule(rule):
    lines = ["[[rules]]"]
    for key, value in rule.items():
        if isinstance(value, list):
            val_str = "[" + ", ".join(f'"{v}"' for v in value) + "]"
            lines.append(f"{key} = {val_str}")
        elif isinstance(value, str):
            lines.append(f"{key} = '''{value}'''")
        elif isinstance(value, (int, float)):
            lines.append(f"{key} = {value}")
        elif isinstance(value, bool):
            lines.append(f"{key} = {str(value).lower()}")
        else:
            lines.append(f'{key} = """{str(value)}"""')
    return "\n".join(lines)


def main():
    output_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(DEFAULT_OUTPUT)

    toml_files = sorted(RULES_DIR.glob("*.toml"))
    if not toml_files:
        print(f"WARNING: No .toml files found in {RULES_DIR}")
        sys.exit(0)

    all_rules = []
    for f in toml_files:
        data = parse_toml(f)
        rules = data.get("rules", [])
        if isinstance(rules, dict):
            rules = [rules]
        all_rules.extend(rules)

    lines = ['title = "Merged Custom Rules"', ""]
    for rule in all_rules:
        lines.append(format_rule(rule))
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Merged {len(all_rules)} rules from {len(toml_files)} files")


if __name__ == "__main__":
    main()
