#!/usr/bin/env python3
"""
Secret Validity Verification Framework (Plugin-based)

Validates confirmed secrets via read-only network requests.

Usage:
    python scripts/verify-secrets.py /tmp/scan-classified.json [--output /tmp/scan-verified.json]

Safety constraints:
    - All validators are read-only (no writes, no charges, no vehicle control).
    - Network timeout: 10 seconds max per request.
    - Rate limiting: max 1 request per second globally.
    - On any error -> mark as UNKNOWN, never crash.
    - Never log full secret values (mask in logs).
    - For batch scans, process max 20 findings.
"""

import argparse
import json
import sys
import time

if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime, timezone
from pathlib import Path

from verify_plugins import get_plugin
from verify_plugins._utils import mask

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TIMEOUT = 10
RATE_LIMIT_SECONDS = 1.0
MAX_BATCH_FINDINGS = 20

LAST_REQUEST_TIME = 0.0


def rate_limit():
    """Enforce global rate limit of max 1 request per second."""
    global LAST_REQUEST_TIME
    now = time.time()
    elapsed = now - LAST_REQUEST_TIME
    if elapsed < RATE_LIMIT_SECONDS:
        time.sleep(RATE_LIMIT_SECONDS - elapsed)
    LAST_REQUEST_TIME = time.time()


def make_validity(status, validator, detail, http_status=None):
    """Create a validity result dictionary."""
    return {
        "status": status,
        "tested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "validator": validator,
        "detail": detail,
        "http_status": http_status,
    }


def is_batch_scan(data: dict) -> bool:
    """Detect batch scan."""
    if data.get("repos"):
        return True
    findings = data.get("findings", [])
    names = {f.get("repo_name") for f in findings if f.get("repo_name")}
    return len(names) > 1


def _call_plugin(plugin, finding):
    """Internal: call the plugin validate function."""
    return plugin.validate(finding)


def validate_finding(finding: dict) -> dict:
    """
    Validate a single finding using the appropriate plugin.

    Handles plugin routing, rate limiting, timeout (via ThreadPoolExecutor),
    and exception handling.
    """
    rule_id = finding.get("rule_id", "")
    finding_id = finding.get("finding_id", "")

    plugin = get_plugin(rule_id)

    if not plugin:
        return make_validity(
            "NOT_TESTABLE",
            "unregistered",
            f"未注册的规则: {rule_id}"
        )

    # Apply rate limit before calling plugin
    rate_limit()

    try:
        # Use ThreadPoolExecutor to enforce uniform timeout
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_call_plugin, plugin, finding)
            try:
                result = future.result(timeout=TIMEOUT)
            except TimeoutError:
                return make_validity(
                    "UNKNOWN",
                    "timeout",
                    "验证超时（10秒）"
                )

        # Ensure result has required fields
        if not isinstance(result, dict):
            return make_validity(
                "UNKNOWN",
                "framework",
                "插件返回格式错误",
            )

        # Add tested_at if missing
        if "tested_at" not in result:
            result["tested_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        return result

    except Exception as e:
        print(
            f"[WARN] Validator crashed for {finding_id}: {type(e).__name__}: {e}",
            file=sys.stderr
        )
        return make_validity(
            "UNKNOWN",
            "crash-guard",
            f"验证器异常: {type(e).__name__}"
        )


def main():
    parser = argparse.ArgumentParser(description="Secret Validity Verification Framework")
    parser.add_argument("input", help="Path to scan-classified.json")
    parser.add_argument("--output", "-o", help="Output path for verified JSON", default=None)
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = data.get("findings", [])
    confirmed = [f for f in findings if f.get("classification") == "CONFIRMED"]

    if is_batch_scan(data):
        print(f"[INFO] Batch scan detected, limiting to {MAX_BATCH_FINDINGS} findings", file=sys.stderr)
        confirmed = confirmed[:MAX_BATCH_FINDINGS]

    print(f"[INFO] Processing {len(confirmed)} confirmed findings for validity", file=sys.stderr)

    for finding in confirmed:
        rule_id = finding.get("rule_id", "")
        finding_id = finding.get("finding_id", "")

        print(f"[INFO] Processing {finding_id} (rule: {rule_id})", file=sys.stderr)

        finding["validity"] = validate_finding(finding)

        # Log result with masked sensitive data
        validity = finding["validity"]
        print(
            f"[INFO] Result: {validity.get('status')} ({validity.get('validator')})",
            file=sys.stderr
        )

    output_path = args.output
    if output_path is None:
        output_path = str(input_path.with_suffix(".verified.json"))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(output_path)


if __name__ == "__main__":
    main()
