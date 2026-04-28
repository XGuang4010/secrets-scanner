#!/usr/bin/env python3
"""
Merge verification results back into classified findings.

Usage:
    python scripts/merge_verification_results.py \
        --classified /tmp/scan-classified.json \
        --verified /tmp/scan-verified.json \
        --output /tmp/scan-merged.json

Logic:
    1. Read classified findings (ground truth with classification/severity/context).
    2. Read verified findings (with `validity` field added by verify-secrets.py).
    3. Match by `finding_id`.
    4. Copy `validity` field from verified → classified.
    5. Write merged JSON.
"""

import argparse
import json
import sys
from pathlib import Path


def merge(classified_path: Path, verified_path: Path, output_path: Path) -> dict:
    with open(classified_path, "r", encoding="utf-8") as f:
        classified = json.load(f)

    with open(verified_path, "r", encoding="utf-8") as f:
        verified = json.load(f)

    # Build lookup: finding_id -> validity
    validity_map = {}
    for vf in verified.get("findings", []):
        fid = vf.get("finding_id")
        if fid and "validity" in vf:
            validity_map[fid] = vf["validity"]

    # Merge into classified
    merged_count = 0
    for cf in classified.get("findings", []):
        fid = cf.get("finding_id")
        if fid and fid in validity_map:
            cf["validity"] = validity_map[fid]
            merged_count += 1

    # Update metadata
    classified.setdefault("_meta", {})
    classified["_meta"]["verification_merged"] = {
        "verified_file": str(verified_path),
        "merged_count": merged_count,
        "total_classified": len(classified.get("findings", [])),
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(classified, f, indent=2, ensure_ascii=False)

    return classified


def main():
    parser = argparse.ArgumentParser(
        description="Merge verification results into classified findings"
    )
    parser.add_argument(
        "--classified", required=True, type=Path,
        help="Path to scan-classified.json"
    )
    parser.add_argument(
        "--verified", required=True, type=Path,
        help="Path to scan-verified.json (output from verify-secrets.py)"
    )
    parser.add_argument(
        "--output", "-o", type=Path,
        help="Output path for merged JSON. Defaults to <classified>.merged.json"
    )
    args = parser.parse_args()

    if not args.classified.exists():
        print(f"ERROR: Classified file not found: {args.classified}", file=sys.stderr)
        sys.exit(1)
    if not args.verified.exists():
        print(f"ERROR: Verified file not found: {args.verified}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output
    if output_path is None:
        output_path = args.classified.with_suffix(".merged.json")

    result = merge(args.classified, args.verified, output_path)
    merged = result.get("_meta", {}).get("verification_merged", {})
    print(f"[OK] Merged {merged.get('merged_count', 0)} / {merged.get('total_classified', 0)} findings")
    print(f"     Output: {output_path}")


if __name__ == "__main__":
    main()
