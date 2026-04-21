---
name: secrets-scanner
description: Scan local code repositories for leaked secrets using gitleaks. Supports custom rules and auto-updating binaries.
---

# Secrets Scanner

## Overview
Scan local repositories for hardcoded secrets, API keys, tokens, and credentials using gitleaks with support for custom detection rules.

## When to Use
- User says "scan repo for secrets", "check for leaked credentials", "find API keys in code"
- Any request involving secret detection, credential scanning, or token leakage

## Prerequisites
- gitleaks binary in tools/ directory
- Python 3.8+ for update script

## Workflow

### Phase 1: Preflight
1. Detect platform via Python platform module
2. Read tools/manifest.json to locate the correct binary for this platform
3. Check if binary exists at tools/gitleaks-PLATFORM
4. Run binary with version flag to verify it works
5. If missing or broken, prompt user to run python scripts/update-gitleaks.py
6. Check if references/rules/ directory contains .toml files

### Phase 2: Scan
1. Run default scan:
   ./tools/gitleaks-PLATFORM detect --source REPO_PATH --verbose --report-format json --report-path /tmp/gitleaks-default.json
2. If custom rules exist, merge all .toml files into a single config and run:
   ./tools/gitleaks-PLATFORM detect --source REPO_PATH --config MERGED_TOML --verbose --report-format json --report-path /tmp/gitleaks-custom.json

### Phase 3: Merge Results
1. Read both JSON outputs if they exist
2. Deduplicate by Fingerprint field
3. Group findings by RuleID

### Phase 4: Context Extraction
For each finding, read the source file and extract plus/minus 3 lines around the matched location.

### Phase 5: Report Generation
Generate Markdown report using templates/report.md structure.

### Phase 6: Report Generation (Script)
Run the report generation script to produce the final deliverable:
```bash
python3 scripts/generate-report.py <repo_path> <output_dir> <json_file1> [json_file2 ...]
```

This script will:
1. Read and deduplicate findings from one or more gitleaks JSON files by `Fingerprint`
2. Extract surrounding code context (+/- 3 lines) from the repository source files
3. Mask secrets in the report (first/last 4 chars only)
4. Generate a Markdown report with summary, findings grouped by RuleID, and recommendations
5. Print the Markdown file path to stdout

The canonical output of this skill is Markdown only. DOCX conversion is NOT handled by this skill. If users need a DOCX, they can install pandoc separately and run:
```bash
pandoc secrets-report.md -o secrets-report.docx
```

## Custom Rules
Place TOML rule files in references/rules/. Each file follows gitleaks rule format.
See references/rules/company-token.toml for example.

## Updating gitleaks
Run python scripts/update-gitleaks.py to download the latest release.
