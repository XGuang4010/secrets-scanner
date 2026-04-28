#!/usr/bin/env python3
"""
Scan orchestrator for secrets-scanner.

Phases:
  1. Preflight: detect platform, verify gitleaks binary, merge rules
  2. Detection: run gitleaks, extract context for each finding
  3. Output: write scan-findings.json to the system temp directory for AI classification

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
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
TOOLS_DIR = SKILL_DIR / "tools"
RULES_DIR = SKILL_DIR / "references" / "rules"
LEARNING_DIR = SKILL_DIR / ".learning"
MANIFEST_PATH = TOOLS_DIR / "manifest.json"
TMP_DIR = Path(tempfile.gettempdir())
VERIFIED_STAMP = TOOLS_DIR / ".verified.json"

PLATFORM_MAP = {
    "Linux-x86_64": "linux-x86_64",
    "Linux-aarch64": "linux-aarch64",
    "Darwin-x86_64": "darwin-x86_64",
    "Darwin-arm64": "darwin-arm64",
    "Windows-AMD64": "windows-x86_64",
    "Windows-amd64": "windows-x86_64",
    "Windows-arm64": "windows-arm64",
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


def _load_config():
    """Read config.yaml (minimal parser, no external deps)."""
    config_path = SKILL_DIR / "config.yaml"
    data = {}
    current_section = None
    if not config_path.exists():
        return data
    with open(config_path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.endswith(":") and "=" not in stripped:
                current_section = stripped[:-1]
                data[current_section] = {}
                continue
            if ":" in stripped:
                key, val = stripped.split(":", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if current_section:
                    data[current_section][key] = val
                else:
                    data[key] = val
    return data


def _load_manifest():
    """Load manifest.json with error handling."""
    try:
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Manifest not found at {MANIFEST_PATH}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid manifest JSON: {e}")
        sys.exit(1)


def get_binary_path():
    """Locate gitleaks binary based on config.yaml or manifest."""
    # 1. Check config.yaml for explicit binary path
    config = _load_config()
    cfg_binary = config.get("gitleaks", {}).get("binary_path", "").strip()
    if cfg_binary:
        p = Path(cfg_binary)
        if p.is_absolute():
            if p.exists():
                return p
        else:
            resolved = SKILL_DIR / p
            if resolved.exists():
                return resolved
        # Config path points to a non-existent binary (e.g., cross-platform
        # config drift). Fall through to manifest inference rather than failing.

    # 2. Fallback to manifest-based inference
    manifest = _load_manifest()
    plat = detect_platform()
    binary_name = manifest.get("binaries", {}).get(plat)
    if not binary_name:
        print(f"ERROR: No binary configured for platform: {plat}")
        sys.exit(1)

    return TOOLS_DIR / binary_name


def verify_binary(binary_path):
    """Run gitleaks version to verify binary works."""
    try:
        result = subprocess.run(
            [str(binary_path), "version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
        )
        if result.returncode != 0:
            print(f"ERROR: Binary verification failed: {result.stderr.strip()}")
            sys.exit(1)
        return result.stdout.strip()
    except Exception as e:
        print(f"ERROR: Cannot execute binary: {e}")
        sys.exit(1)


def _read_verified_stamp():
    """Read cached verification state."""
    if not VERIFIED_STAMP.exists():
        return None
    try:
        with open(VERIFIED_STAMP, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _write_verified_stamp(binary_path, version):
    """Cache verification state so future scans skip the version call."""
    try:
        stat = binary_path.stat()
        data = {
            "path": str(binary_path),
            "mtime": stat.st_mtime,
            "size": stat.st_size,
            "version": version,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(VERIFIED_STAMP, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass


def _is_verified(binary_path):
    """Return True if binary has not changed since last successful verification."""
    stamp = _read_verified_stamp()
    if not stamp:
        return False
    if stamp.get("path") != str(binary_path):
        return False
    try:
        stat = binary_path.stat()
        return (
            stamp.get("mtime") == stat.st_mtime
            and stamp.get("size") == stat.st_size
        )
    except OSError:
        return False


def _ensure_gitleaks():
    """Ensure gitleaks binary is present and working with minimal overhead.

    Uses a fingerprint-based verification cache to avoid spawning the binary
    on every scan. Only re-verifies when the binary changes (mtime/size).
    Falls back to auto-install via check-gitleaks.py when the binary is
    missing or broken.
    """
    binary_path = get_binary_path()

    # Fast path: cached verification
    if _is_verified(binary_path):
        return binary_path

    # Verify binary (slow path)
    if binary_path.exists():
        version_str = verify_binary(binary_path)
        _write_verified_stamp(binary_path, version_str)
        return binary_path

    # Missing binary — attempt auto-install once
    check_script = SCRIPT_DIR / "check-gitleaks.py"
    if not check_script.exists():
        print(f"ERROR: gitleaks binary missing and {check_script} not found")
        sys.exit(1)

    print("[INFO] gitleaks not found; auto-installing...")
    result = subprocess.run(
        [sys.executable, str(check_script), "--install"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
    )
    if result.returncode != 0:
        print("ERROR: Auto-install failed")
        if result.stderr:
            print(result.stderr)
        sys.exit(1)

    # Re-resolve path after install (config/manifest may have been updated)
    binary_path = get_binary_path()
    if not binary_path.exists():
        print(f"ERROR: Binary still missing after install: {binary_path}")
        sys.exit(1)

    version_str = verify_binary(binary_path)
    _write_verified_stamp(binary_path, version_str)
    return binary_path


def _parse_filter_allowlists(filter_path):
    """Parse auto-filter-rules.toml and extract all allowlist regexes/paths.

    Returns: (regexes_list, paths_list)
    """
    if not filter_path.exists():
        return [], []

    content = filter_path.read_text(encoding="utf-8")
    regexes = []
    paths = []

    lines = content.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        # Match [[rules.allowlists]] or [rules.allowlist] or [allowlist]
        if line.strip() in ("[[rules.allowlists]]", "[rules.allowlist]", "[allowlist]"):
            i += 1
            # Read until next [[rules]] or EOF or blank line that ends block
            while i < len(lines):
                sub = lines[i].strip()
                if sub.startswith("[[") or sub.startswith("[") and "allowlist" not in sub:
                    break
                if sub.startswith("regexes"):
                    # Multi-line array
                    val = sub.split("=", 1)[1].strip() if "=" in sub else ""
                    if val.startswith("["):
                        arr_lines = [val]
                        while not arr_lines[-1].rstrip().endswith("]"):
                            i += 1
                            if i >= len(lines):
                                break
                            arr_lines.append(lines[i].strip())
                        arr_text = " ".join(arr_lines)
                        # Extract triple-quoted strings
                        parts = arr_text.split("'''")
                        for j in range(1, len(parts), 2):
                            if j < len(parts):
                                regexes.append(parts[j])
                elif sub.startswith("paths"):
                    val = sub.split("=", 1)[1].strip() if "=" in sub else ""
                    if val.startswith("["):
                        arr_lines = [val]
                        while not arr_lines[-1].rstrip().endswith("]"):
                            i += 1
                            if i >= len(lines):
                                break
                            arr_lines.append(lines[i].strip())
                        arr_text = " ".join(arr_lines)
                        parts = arr_text.split("'''")
                        for j in range(1, len(parts), 2):
                            if j < len(parts):
                                paths.append(parts[j])
                i += 1
            continue
        i += 1

    return regexes, paths


def merge_rules():
    """Merge base rules + auto-filter allowlists into single config.

    gitleaks v8.30+ does not allow [[rules]] without a regex field.
    Auto-filter entries (pure allowlists) are merged into the global
    [allowlist] section of the base config instead of being appended as
    standalone rules.
    """
    base_path = RULES_DIR / "gitleaks-base.toml"
    filter_path = RULES_DIR / "auto-filter-rules.toml"
    merged_path = TMP_DIR / "gitleaks-merged.toml"

    if not base_path.exists():
        print(f"WARNING: Base rules not found at {base_path}")
        return None

    base_text = base_path.read_text(encoding="utf-8")

    # Extract auto-filter allowlist entries
    filter_regexes, filter_paths = _parse_filter_allowlists(filter_path)
    print(f"[INFO] Auto-filter entries: {len(filter_regexes)} regexes, {len(filter_paths)} paths")

    if not filter_regexes and not filter_paths:
        # No filter rules to merge; use base as-is
        merged_path.write_text(base_text, encoding="utf-8")
        print(f"[OK] Using base rules only -> {merged_path}")
        return merged_path

    # Find the global [allowlist] section in base and insert filter entries
    lines = base_text.splitlines()
    in_allowlist = False
    in_regexes = False
    in_paths = False
    regexes_end_idx = -1
    paths_end_idx = -1
    regexes_indent = "    "
    paths_indent = "    "

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "[allowlist]":
            in_allowlist = True
            continue
        if in_allowlist and stripped.startswith("[["):
            in_allowlist = False
            continue

        if in_allowlist and stripped.startswith("regexes"):
            in_regexes = True
            regexes_indent = line[:len(line) - len(line.lstrip())]
            if stripped.rstrip().endswith("]"):
                regexes_end_idx = idx
                in_regexes = False
            continue
        if in_regexes:
            if stripped.rstrip().endswith("]"):
                regexes_end_idx = idx
                in_regexes = False
            continue

        if in_allowlist and stripped.startswith("paths"):
            in_paths = True
            paths_indent = line[:len(line) - len(line.lstrip())]
            if stripped.rstrip().endswith("]"):
                paths_end_idx = idx
                in_paths = False
            continue
        if in_paths:
            if stripped.rstrip().endswith("]"):
                paths_end_idx = idx
                in_paths = False
            continue

    # Build new lines
    new_lines = list(lines)
    inserted = 0

    if regexes_end_idx >= 0 and filter_regexes:
        # Insert before the closing ] of regexes array
        insert_lines = []
        for rx in filter_regexes:
            insert_lines.append(f"{regexes_indent}  '''{rx}''',")
        new_lines = new_lines[:regexes_end_idx + inserted] + insert_lines + new_lines[regexes_end_idx + inserted:]
        inserted += len(insert_lines)
        print(f"[OK] Merged {len(filter_regexes)} auto-filter regexes into global allowlist")

    if paths_end_idx >= 0 and filter_paths:
        # Adjust index if regexes were inserted before it
        adjusted_paths_idx = paths_end_idx + inserted if paths_end_idx > regexes_end_idx else paths_end_idx
        insert_lines = []
        for p in filter_paths:
            insert_lines.append(f"{paths_indent}  '''{p}''',")
        new_lines = new_lines[:adjusted_paths_idx] + insert_lines + new_lines[adjusted_paths_idx:]
        print(f"[OK] Merged {len(filter_paths)} auto-filter paths into global allowlist")

    merged_path.write_text("\n".join(new_lines), encoding="utf-8")
    print(f"[OK] Merged rules -> {merged_path}")
    return merged_path


def _is_git_repo(repo_path):
    """Check if the given path is a git repository."""
    return (Path(repo_path) / ".git").exists()


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

    # Non-git directories require --no-git to scan files directly
    if not _is_git_repo(repo_path):
        cmd.append("--no-git")
        print(f"[INFO] Non-git directory detected, adding --no-git")

    if config_path and config_path.exists():
        cmd.extend(["--config", str(config_path)])

    print(f"[RUN] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")

    # Detect config errors even if returncode is 1
    stderr_lower = result.stderr.lower()
    if "unable to load gitleaks config" in stderr_lower or "toml" in stderr_lower:
        print(f"ERROR: gitleaks config error (code {result.returncode})")
        print(f"STDERR: {result.stderr}")
        sys.exit(1)

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

    # Handle edge case: empty file or line number out of range
    if not lines or idx < 0 or idx >= len(lines):
        return {
            "before": [],
            "match_line": f"[Line {line_num} out of range in {file_rel}]",
            "after": [],
        }

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

    binary_path = _ensure_gitleaks()
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
