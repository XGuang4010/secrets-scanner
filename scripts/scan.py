#!/usr/bin/env python3
"""
Scan orchestrator for secrets-scanner.

Phases:
  1. Preflight: detect platform, verify gitleaks binary, merge rules
  2. Detection: run gitleaks, extract context for each finding
  3. Output: write /tmp/scan-findings.json for AI classification

Usage:
  python scripts/scan.py --preflight
  python scripts/scan.py --detect <repo-path>
  python scripts/scan.py --full <repo-path>
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
TOOLS_DIR = SKILL_DIR / "tools"
RULES_DIR = SKILL_DIR / "references" / "rules"
LEARNING_DIR = SKILL_DIR / ".learning"
MANIFEST_PATH = TOOLS_DIR / "manifest.json"
TMP_DIR = Path("/tmp")

PLATFORM_MAP = {
    "Linux-x86_64": "linux-x86_64",
    "Linux-aarch64": "linux-aarch64",
    "Darwin-x86_64": "darwin-x86_64",
    "Darwin-arm64": "darwin-arm64",
}


def detect_platform():
    """Detect current platform for gitleaks binary selection."""
    system = platform.system()
    machine = platform.machine()
    key = f"{system}-{machine}"
    mapped = PLATFORM_MAP.get(key)
    if not mapped:
        print(f"ERROR: Unsupported platform: {system} {machine}")
        sys.exit(1)
    return mapped


def get_binary_path():
    """Locate gitleaks binary based on platform."""
    try:
        with open(MANIFEST_PATH, "r") as f:
            manifest = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Manifest not found at {MANIFEST_PATH}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid manifest JSON: {e}")
        sys.exit(1)

    plat = detect_platform()
    binary_name = manifest.get("binaries", {}).get(plat)
    if not binary_name:
        print(f"ERROR: No binary configured for platform: {plat}")
        sys.exit(1)

    binary_path = TOOLS_DIR / binary_name
    if not binary_path.exists():
        print(f"ERROR: Binary not found: {binary_path}")
        print("Run: python scripts/update-gitleaks.py")
        sys.exit(1)

    return binary_path


def verify_binary(binary_path):
    """Run gitleaks version to verify binary works."""
    try:
        result = subprocess.run(
            [str(binary_path), "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            print(f"ERROR: Binary verification failed: {result.stderr.strip()}")
            sys.exit(1)
        print(f"[OK] gitleaks: {result.stdout.strip()}")
    except Exception as e:
        print(f"ERROR: Cannot execute binary: {e}")
        sys.exit(1)


def merge_rules():
    """Merge base rules + auto-filter rules into single config."""
    base_path = RULES_DIR / "gitleaks-base.toml"
    filter_path = RULES_DIR / "auto-filter-rules.toml"
    merged_path = TMP_DIR / "gitleaks-merged.toml"

    if not base_path.exists():
        print(f"WARNING: Base rules not found at {base_path}")
        # Use gitleaks default rules
        return None

    lines = []
    # Read base rules
    lines.append(f"# Base rules from {base_path.name}\n")
    lines.append(base_path.read_text(encoding="utf-8"))
    lines.append("\n")

    # Read auto-filter rules if exists
    if filter_path.exists():
        lines.append(f"# Auto-filter rules from {filter_path.name}\n")
        lines.append(filter_path.read_text(encoding="utf-8"))
        lines.append("\n")

    merged_path.write_text("".join(lines), encoding="utf-8")
    print(f"[OK] Merged rules -> {merged_path}")
    return merged_path


def run_gitleaks(binary_path, repo_path, config_path=None):
    """Run gitleaks detection and return path to JSON report."""
    report_path = TMP_DIR / "gitleaks-raw.json"

    cmd = [
        str(binary_path),
        "detect",
        "--source", str(repo_path),
        "--verbose",
        "--report-format", "json",
        "--report-path", str(report_path),
    ]

    if config_path and config_path.exists():
        cmd.extend(["--config", str(config_path)])

    print(f"[RUN] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    # gitleaks exits with code 1 when findings exist
    if result.returncode not in (0, 1):
        print(f"ERROR: gitleaks failed with code {result.returncode}")
        print(f"STDERR: {result.stderr}")
        sys.exit(1)

    if not report_path.exists():
        print("WARNING: No report generated (no findings or error)")
        return None

    return report_path


def extract_context(repo_path, file_rel, line_num, radius=5):
    """Extract +-radius lines around the finding."""
    file_path = Path(repo_path) / file_rel

    if not file_path.exists():
        return {
            "before": [],
            "match_line": f"[File not found: {file_rel}]",
            "after": [],
        }

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        return {
            "before": [],
            "match_line": f"[Error reading {file_rel}: {e}]",
            "after": [],
        }

    # 1-indexed to 0-indexed
    idx = line_num - 1
    start = max(0, idx - radius)
    end = min(len(lines), idx + radius + 1)

    before = [lines[i].rstrip("\n\r") for i in range(start, idx)]
    match_line = lines[idx].rstrip("\n\r") if idx < len(lines) else ""
    after = [lines[i].rstrip("\n\r") for i in range(idx + 1, end)]

    return {
        "before": before,
        "match_line": match_line,
        "after": after,
    }


def build_findings_data(repo_path, raw_report_path):
    """Parse gitleaks JSON and build structured findings with context."""
    try:
        with open(raw_report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse gitleaks report: {e}")
        sys.exit(1)

    # gitleaks v8+ uses flat list; older versions use {"findings": [...]}
    if isinstance(data, dict):
        findings = data.get("findings", [])
    elif isinstance(data, list):
        findings = data
    else:
        findings = []

    print(f"[INFO] Raw findings from gitleaks: {len(findings)}")

    results = []
    for item in findings:
        file_rel = item.get("File", "")
        line_num = item.get("StartLine", 1)

        context = extract_context(repo_path, file_rel, line_num, radius=5)

        record = {
            "finding_id": str(uuid.uuid4())[:8],
            "rule_id": item.get("RuleID", "unknown"),
            "description": item.get("Description", ""),
            "file": file_rel,
            "line": line_num,
            "end_line": item.get("EndLine", line_num),
            "match": item.get("Match", ""),
            "secret": item.get("Secret", ""),
            "fingerprint": item.get("Fingerprint", ""),
            "context": context,
        }
        results.append(record)

    return results


def write_findings_for_agent(findings, repo_path):
    """Write structured findings to /tmp for AI Agent classification."""
    output = {
        "scan_id": datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
        "repo_path": str(repo_path),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "findings": findings,
    }

    output_path = TMP_DIR / "scan-findings.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"[OK] Findings prepared for AI classification: {output_path}")
    print(f"[INFO] Next: Agent should read this file and classify each finding")
    return output_path


def rotate_learning_directory():
    """Ensure .learning/ exists and rotate old files (keep max 3)."""
    LEARNING_DIR.mkdir(parents=True, exist_ok=True)

    files = sorted(LEARNING_DIR.glob("scan-*-false-positives.json"))
    while len(files) > 3:
        oldest = files.pop(0)
        print(f"[ROTATE] Removing old learning data: {oldest.name}")
        oldest.unlink()


def preflight():
    """Run preflight checks."""
    print("=== Phase 1: Preflight ===")
    binary_path = get_binary_path()
    verify_binary(binary_path)
    merge_rules()
    rotate_learning_directory()
    print("[OK] Preflight complete\n")
    return binary_path


def detect(repo_path):
    """Run full detection pipeline."""
    repo_path = Path(repo_path).resolve()
    if not repo_path.exists():
        print(f"ERROR: Repository not found: {repo_path}")
        sys.exit(1)

    binary_path = preflight()
    config_path = TMP_DIR / "gitleaks-merged.toml"

    print("=== Phase 2: Detection ===")
    report_path = run_gitleaks(binary_path, repo_path, config_path)

    if not report_path:
        # No findings
        findings = []
    else:
        findings = build_findings_data(repo_path, report_path)

    if not findings:
        print("[OK] No secrets detected")
        # Write empty findings file so Agent knows scan completed
        write_findings_for_agent([], repo_path)
        return

    write_findings_for_agent(findings, repo_path)
    print(f"[OK] Detection complete. {len(findings)} findings require AI classification\n")


def main():
    parser = argparse.ArgumentParser(description="Secrets scanner orchestrator")
    parser.add_argument("--preflight", action="store_true", help="Run preflight checks only")
    parser.add_argument("--detect", metavar="REPO_PATH", help="Run detection on repository")
    parser.add_argument("--full", metavar="REPO_PATH", help="Run full pipeline (preflight + detect)")

    args = parser.parse_args()

    if args.preflight:
        preflight()
    elif args.detect:
        detect(args.detect)
    elif args.full:
        detect(args.full)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
