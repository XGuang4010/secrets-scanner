#!/usr/bin/env python3
"""
Batch scanner for multiple repositories.
Runs scan.py on each repo, aggregates findings, and outputs combined JSON.

Usage:
  python scripts/batch-scan.py /home/davei/projects/repo1 /home/davei/projects/repo2 ...
  python scripts/batch-scan.py --list-file /path/to/repo_list.json

Output: /tmp/batch-scan-findings.json (aggregated from all repos)
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
TMP_DIR = Path(tempfile.gettempdir())

def run_scan(repo_path):
    """Run scan.py --detect on a single repo and return findings data."""
    repo_path = Path(repo_path).resolve()
    repo_name = repo_path.name
    
    print(f"\n{'='*60}")
    print(f"Scanning: {repo_name}")
    print(f"{'='*60}")
    
    cmd = [
        sys.executable,
        str(SCRIPT_DIR / "scan.py"),
        "--detect",
        str(repo_path),
    ]
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
    )
    
    if result.returncode not in (0, 1):
        print(f"  [✗] scan.py failed for {repo_name}: {result.stderr[:200]}")
        return None
    
    # Read findings from /tmp/scan-findings.json
    findings_path = TMP_DIR / "scan-findings.json"
    if not findings_path.exists():
        print(f"  [✗] No findings file generated for {repo_name}")
        return None
    
    try:
        with open(findings_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"  [✗] Failed to read findings: {e}")
        return None
    
    findings = data.get("findings", [])
    print(f"  [✓] Found {len(findings)} raw findings")
    
    # Rename findings file to avoid collision
    batch_file = TMP_DIR / f"scan-findings-{repo_name}.json"
    os.rename(findings_path, batch_file)
    
    return {
        "repo_name": repo_name,
        "repo_path": str(repo_path),
        "findings_count": len(findings),
        "findings": findings,
        "findings_file": str(batch_file),
    }


def main():
    parser = argparse.ArgumentParser(description="Batch scan multiple repositories")
    parser.add_argument("repos", nargs="*", help="Repository paths to scan")
    parser.add_argument("--list-file", help="JSON file with repo list (from search)")
    parser.add_argument("--base-dir", default=str(Path.cwd()), help="Base directory for repo list resolution")
    parser.add_argument("--output", default=str(TMP_DIR / "batch-scan-findings.json"), help="Output file path")

    args = parser.parse_args()

    # Collect repo paths
    repo_paths = []
    base_dir = Path(args.base_dir)

    if args.list_file:
        with open(args.list_file, "r") as f:
            repo_list = json.load(f)
        for r in repo_list:
            path = base_dir / r["name"]
            if path.exists():
                repo_paths.append(path)
            else:
                print(f"[SKIP] {r['name']} not found at {path}")
    
    repo_paths.extend([Path(p) for p in args.repos])
    
    if not repo_paths:
        print("ERROR: No repositories to scan")
        sys.exit(1)
    
    print(f"Batch scanning {len(repo_paths)} repositories...")
    
    results = []
    total_findings = 0
    
    for repo_path in repo_paths:
        result = run_scan(repo_path)
        if result:
            results.append(result)
            total_findings += result["findings_count"]
    
    # Aggregate all findings
    all_findings = []
    for r in results:
        for f in r["findings"]:
            f["repo_name"] = r["repo_name"]
            f["repo_path"] = r["repo_path"]
            all_findings.append(f)
    
    output = {
        "scan_id": f"batch-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_repos": len(results),
        "total_findings": total_findings,
        "repos": results,
        "findings": all_findings,
    }
    
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"Batch scan complete!")
    print(f"  Repos scanned: {len(results)}")
    print(f"  Total findings: {total_findings}")
    print(f"  Output: {args.output}")
    print(f"{'='*60}")

    # 自动生成中文报告
    print(f"\n[Auto] Generating report...")
    try:
        # 检查是否有分类后的文件
        classified_path = TMP_DIR / "scan-classified.json"
        if classified_path.exists():
            # 使用 generate-report.py 处理已分类结果
            cmd = [
                sys.executable,
                str(SCRIPT_DIR / "generate-report.py"),
                str(classified_path),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                report_path = result.stdout.strip()
                print(f"  [\u2713] Classified report generated: {report_path}")
            else:
                print(f"  [!] generate-report.py failed: {result.stderr[:200]}")
        else:
            # 使用 batch-generate-report.py 处理未分类结果
            cmd = [
                sys.executable,
                str(SCRIPT_DIR / "batch-generate-report.py"),
                str(args.output),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                report_path = result.stdout.strip()
                print(f"  [\u2713] Raw report generated: {report_path}")
            else:
                print(f"  [!] batch-generate-report.py failed: {result.stderr[:200]}")
    except Exception as e:
        print(f"  [!] Auto report generation skipped: {e}")


if __name__ == "__main__":
    main()
