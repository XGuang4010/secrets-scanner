---
name: secrets-scanner
description: "AI-driven secrets scanner with continuous learning. Uses gitleaks for detection, AI Agent for context-aware classification, and auto-generates filter rules from false positives."
trigger: /scan-secrets
---

> Before executing any workflow below, read this SKILL.md in full.

# Secrets Scanner

## Overview

Scan repositories for hardcoded secrets with AI-powered context analysis.
Unlike traditional scanners, this tool uses the AI Agent to classify findings as real leaks vs false positives, and auto-learns from confirmed false positives to reduce noise in future scans.

## When To Use

- User says "scan repo for secrets", "check for leaked credentials"
- After adding new dependencies or configuration files
- Periodic security audits

## Directory Structure

```
secrets-scanner/
  scripts/
    scan.py                   # Orchestrator: run gitleaks, prepare data
    check-gitleaks.py         # Verify / auto-install / update gitleaks binary
    generate-report.py        # Generate Markdown from classified results
    batch-generate-report.py  # Batch-optimized report generator
    batch-scan.py             # Scan multiple repos and aggregate findings
    verify-secrets.py         # Optional: validate secrets via read-only probes
    merge_verification_results.py  # Merge verify output back into classified JSON
    rule-validator.py         # Validate regexes, manage rule lifecycle
    decode_utils.py           # AI utility: JWT/base64/hex/entropy analysis
  references/
    classification-guide.md   # Detailed classification logic by secret type
    workflow.md               # Detailed Phase 3-7 instructions and templates
    pitfalls.md               # Known traps and edge cases
    procedures/batch-scanning.md
    procedures/verify-plugins.md
    semantic-rules/*.yaml
    rules/
      gitleaks-base.toml          # Core detection rules
      auto-filter-rules.toml      # AI-generated allowlist rules
      *.toml                      # Project-specific custom rules
  tools/
    gitleaks-{platform}
  .learning/           # Ephemeral false-positive storage (max 3 scans)
```

## Quick Reference

| Command | Action |
|---------|--------|
| `/scan-secrets <repo-path>` | Full scan with AI classification and auto-learning |
| `/scan-secrets validate-rules` | Run rule lifecycle: validate regexes, promote confirmed, clean orphans |
| `/scan-secrets verify` | Validate confirmed secrets via read-only network probes |
| `/scan-secrets reset-learning` | Clear `.learning/` and auto-filter-rules.toml |
| `/scan-secrets batch <repo1> <repo2>...` | Batch scan multiple repos and aggregate findings |

## Workflow Overview

**Phase 1: Preflight** — `python scripts/scan.py --preflight`
Detects platform, verifies gitleaks binary, merges base + filter rules.

**Phase 2: Detection** — `python scripts/scan.py --detect <repo-path>`
Runs gitleaks, extracts ±5 lines context per finding into `scan-findings.json` in the system temp directory.

**Phase 2.5: Decode Utilities** (Optional, for AI use)
When analyzing JWT, base64, or hex-encoded secrets, the Agent can use `scripts/decode_utils.py` for structured decoding and entropy analysis without manual calculation.

**Phase 3: AI Classification** — Agent reads `scan-findings.json` from the system temp directory
Classifies each finding as CONFIRMED or FALSE_POSITIVE.
**Before classifying, read `references/classification-guide.md` and `references/workflow.md` for detailed logic, few-shot examples, and output format.**

**Phase 4: Report Generation** — `python scripts/generate-report.py <scan-classified.json>`
Produces markdown report of CONFIRMED findings only.

**Phase 5: Auto-Learning** — Agent (if false_positives > 0)
Generates allowlist rules for gitleaks and semantic rules for AI.
Rules start as `experimental`, promote to `confirmed` after 3 validations.
**Read `references/workflow.md` for detailed rule generation templates.**

**Phase 6: Rule Validation** — `python scripts/rule-validator.py`
Promotes validated rules, removes orphaned rules.

**Phase 7: Verification** (Optional) — `python scripts/verify-secrets.py`
Read-only network probes to validate confirmed secrets. Plugin-based.

## Core Classification Rules

- **CONFIRMED**: Real secret in production context, standard format, no indicators of being example/placeholder.
- **FALSE_POSITIVE**: Clear indicators (placeholder syntax, test variable names, example comments).
- **When uncertain: CONFIRMED** (conservative bias).

**Severity (CONFIRMED only):**
- **HIGH**: Cloud provider keys, payment keys, private keys, production admin tokens
- **MEDIUM**: Generic API keys, JWT tokens in production, database passwords
- **LOW**: Test credentials, CI tokens, weak passwords in dev contexts

## Key Constraints

- **Preserve all original fields** when generating `scan-classified.json`. Only ADD classification fields — never REMOVE or REPLACE original fields (`file`, `line`, `context`, `secret`, `match`, etc.).
- **Always classify with context** — never based on file path alone.
- **Do not exclude findings based on file path** — test files CAN contain real secrets.
- **Never modify base rules** — only append to `auto-filter-rules.toml`.
- **Experimental first** — new rules start as experimental, need 3 validations.

## Three-Layer Rule System

| Layer | File | Purpose | Managed By |
|-------|------|---------|------------|
| **Base** | `references/rules/gitleaks-base.toml` | Core detection | Manual / upstream |
| **AI Filter** | `references/rules/auto-filter-rules.toml` | Auto-generated allowlist (gitleaks-level) | AI Agent |
| **Custom** | `references/rules/*.toml` | Project-specific rules | User |
| **Semantic** | `references/semantic-rules/*.yaml` | AI context-aware judgment logic | AI Agent |

**Precedence:** Custom > AI Filter > Base

**Note:** The main scanning flow (`scan.py`) loads **Base + AI Filter** only. Custom `.toml` files exist for manual rule extensions but are not automatically merged into the live scan config unless explicitly requested.

## Error Handling

| Scenario | Action |
|----------|--------|
| gitleaks binary missing | `scan.py` auto-installs via `check-gitleaks.py`; or run `python scripts/check-gitleaks.py --install` manually |
| No findings | Generate empty report |
| AI classification fails | Fallback: report all findings (conservative) |
| Regex validation fails | Log error, skip invalid rule, continue |
| `.learning/` full | Delete oldest, proceed with rotation |
| Secret validation fails | Mark as `UNKNOWN`, continue |

## Rules

1. Always classify with context.
2. Conservative bias: uncertain findings are CONFIRMED.
3. Never modify base rules.
4. Experimental first: need 3 validations to promote.
5. Learning retention: max 3 scans.
6. Auto-learning is mandatory if false positives exist.
7. Pipeline runs autonomously — no human confirmation.

## References

- **Detailed classification logic**: `references/classification-guide.md`
- **Detailed workflow templates**: `references/workflow.md`
- **Known pitfalls**: `references/pitfalls.md`
- **Batch scanning**: `references/procedures/batch-scanning.md`
- **Verify plugin interface**: `references/procedures/verify-plugins.md`
