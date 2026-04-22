---
name: secrets-scanner
description: "AI-driven secrets scanner with continuous learning. Uses gitleaks for detection, AI Agent for context-aware classification, and auto-generates filter rules from false positives."
trigger: /scan-secrets
---

> **Before executing any workflow below, you MUST first read this SKILL.md in full.**

# Secrets Scanner

## Overview

Scan code repositories for hardcoded secrets with **AI-powered context analysis**.
Unlike traditional scanners that report every match, this tool uses the AI Agent
to read surrounding code context and classify findings as **real leaks** vs
**false positives**.

**Key capabilities:**
- gitleaks engine for broad detection
- AI Agent analyzes code context (+-5 lines) for each finding
- Auto-generates allowlist rules from confirmed false positives
- Rules graduate from `[experimental]` to `[confirmed]` after 3 validation scans
- Retains only last 3 scans' false positive raw data; older data is summarized into rules

## When to Use

- User says "scan repo for secrets", "check for leaked credentials"
- After adding new dependencies or configuration files
- Periodic security audits

## Directory Structure

```
secrets-scanner/
  SKILL.md                          # This file
  scripts/
    scan.py                         # Orchestrator: run gitleaks, prepare data
    generate-report.py              # Generate Markdown from classified results
    rule-validator.py               # Validate regexes, manage rule lifecycle
  references/
    classification-guide.md           # Detailed classification logic by secret type
    rules/
      gitleaks-base.toml              # Base detection rules (read-only)
      auto-filter-rules.toml          # AI-generated allowlist rules
  tools/
    gitleaks-{platform}             # Detection engine binary
    manifest.json                   # Version tracking
  .learning/                        # Ephemeral false-positive storage (max 3 scans)
    scan-001-false-positives.json
    scan-002-false-positives.json
    scan-003-false-positives.json
```

## Three-Layer Rule System

| Layer | File | Purpose | Managed By |
|-------|------|---------|------------|
| **Base** | `gitleaks-base.toml` | Core detection rules from gitleaks | Manual / upstream |
| **AI Filter** | `auto-filter-rules.toml` | Allowlist rules auto-generated from false positives | AI Agent |
| **Custom** | `references/rules/*.toml` | Project-specific rules | User |

**Rule precedence:** Custom > AI Filter > Base

## Quick Reference

| Command | Action |
|---------|--------|
| `/scan-secrets <repo-path>` | Full scan with AI classification and auto-learning |
| `/scan-secrets validate-rules` | Check experimental rules, promote validated ones |
| `/scan-secrets reset-learning` | Clear .learning/ and auto-filter-rules.toml |

## Workflow

### Phase 1: Preflight (Python script)

**Executed by:** `python scripts/scan.py --preflight`

1. Detect platform and locate gitleaks binary
2. Verify binary works (`gitleaks version`)
3. Check rule files exist:
   - `references/rules/gitleaks-base.toml`
   - `references/rules/auto-filter-rules.toml` (create if missing)
4. Merge base + auto-filter rules into `/tmp/gitleaks-merged.toml`

### Phase 2: Detection (Python script)

**Executed by:** `python scripts/scan.py --detect <repo-path>`

1. Run gitleaks with merged rules:
   ```bash
   ./tools/gitleaks detect \
     --source <repo-path> \
     --config /tmp/gitleaks-merged.toml \
     --verbose \
     --report-format json \
     --report-path /tmp/gitleaks-raw.json
   ```

2. Parse JSON and extract context for each finding:
   - Read source file
   - Extract +-5 lines around match
   - Build structured record:
     ```json
     {
       "finding_id": "uuid",
       "rule_id": "aws-access-key",
       "file": "src/config.py",
       "line": 42,
       "match": "AKIAIOSFODNN7EXAMPLE",
       "secret": "AKIAIOSFODNN7EXAMPLE",
       "context": {
         "before": ["line-5", "line-4", "line-3", "line-2", "line-1"],
         "match_line": "        'access_key': 'AKIAIOSFODNN7EXAMPLE',",
         "after": ["line+1", "line+2", "line+3", "line+4", "line+5"]
       }
     }
     ```

3. Write all findings with context to `/tmp/scan-findings.json`

### Phase 3: AI Classification (Agent)

**Executed by:** AI Agent (you)

**Your task:** Read `/tmp/scan-findings.json` and classify each finding.

**Quick Reference:** For detailed classification logic by secret type (API Key, Password, Token, etc.), read `references/classification-guide.md`.

**Instructions:**
1. Read `/tmp/scan-findings.json` using your file tool
2. Read `references/classification-guide.md` for detailed type-specific logic
3. For each finding, analyze the code context:
   - **Variable names**: Does it contain "test", "mock", "example", "fake"?
   - **Comments**: Any "TODO", "FIXME", "example", "placeholder" nearby?
   - **Value patterns**: Is it a real-format key (AKIA..., ghp_..., sk-...) or obvious placeholder (<API_KEY>, xxxxxx, 123456)?
   - **Surrounding code**: Is this production config or test fixture?
   - **Conservative bias**: When uncertain, classify as CONFIRMED

**Few-Shot Examples:**

```python
# Example 1: CONFIRMED - Real API key in production
# File: src/payments.py
stripe.api_key = "sk_live_ABC123EXAMPLE_fake_key_for_demo"
# Analysis: Valid sk_live_ prefix, long random suffix, production file
# → CONFIRMED

# Example 2: FALSE_POSITIVE - Test credential in test file
# File: tests/test_auth.py
def test_login(self):
    # Using test credentials
    test_password = "password123"
# Analysis: test_ prefix, test file path, explicit test comment
# → FALSE_POSITIVE (pattern: test_data)

# Example 3: CONFIRMED - Weak password in ambiguous context (conservative)
# File: config/settings.py
DATABASE_PASSWORD = "admin123"
# Analysis: No test markers, real variable name, config file
# → CONFIRMED (when uncertain, be conservative)

# Example 4: FALSE_POSITIVE - Placeholder in documentation
# File: README.md
curl -H "Api-Key: YOUR_API_KEY_HERE"
# Analysis: YOUR_ prefix + _HERE suffix, documentation file
# → FALSE_POSITIVE (pattern: placeholder)

# Example 5: FALSE_POSITIVE - AWS official sample key
aws_key = "AKIAIOSFODNN7EXAMPLE"
# Analysis: AKIA prefix but ends with EXAMPLE (AWS official doc sample)
# → FALSE_POSITIVE (AWS sample keys use EXAMPLE suffix)
```

4. Output classification to `/tmp/scan-classified.json`.
   
   **CRITICAL:** You MUST preserve ALL original finding fields and add classification fields on top:
   ```json
   {
     "scan_id": "2024-01-15-001",
     "repo_path": "/path/to/repo",
     "timestamp": "2024-01-15T10:30:00Z",
     "findings": [
       {
         "finding_id": "abc123",
         "rule_id": "aws-access-key",
         "description": "...",
         "file": "src/config.py",
         "line": 42,
         "end_line": 42,
         "match": "AKIAIO...MPLE",
         "secret": "***",
         "fingerprint": "...",
         "context": {
           "before": ["..."],
           "match_line": "...",
           "after": ["..."]
         },
         "classification": "CONFIRMED | FALSE_POSITIVE",
         "confidence": "high | medium | low",
         "reason": "Detailed explanation",
         "false_positive_pattern": null | {
           "type": "placeholder | example_value | test_data | comment_indicated | format_mismatch",
           "description": "Human-readable pattern description",
           "extracted_regex": "suggested regex for filtering",
           "affected_rule": "rule_id"
         }
       }
     ],
     "summary": {
       "total": 47,
       "confirmed": 12,
       "false_positives": 35
     }
   }
   ```
   
   The `generate-report.py` script requires `file`, `line`, `context`, and `secret` fields to produce the report. Do NOT strip these fields.

**Classification rules:**
- **CONFIRMED**: Real secret in production context, standard format, no indicators of being example/placeholder
- **FALSE_POSITIVE**: Clear indicators it's not a real secret (placeholder format, test variable names, example comments)
- When confidence is low, mark as CONFIRMED (conservative)

**Important:** Do NOT exclude findings based on file path (e.g., test/ directories). Test files CAN contain real secrets.

### Phase 4: Report Generation (Python script)

**Executed by:** `python scripts/generate-report.py /tmp/scan-classified.json`

1. Read classified results
2. Generate Markdown report containing only CONFIRMED findings:
   - Summary statistics
   - Each finding with file path, line number, masked secret preview
   - Code context (+-3 lines, marked)
   - Severity assessment
   - Remediation recommendations

3. Output path printed to stdout

### Phase 5: Auto-Learning (Agent)

**Executed by:** AI Agent (you)

**Trigger:** After every scan, if `summary.false_positives > 0`

**Your task:**

1. Read all FALSE_POSITIVE entries from `/tmp/scan-classified.json`
2. Read existing `references/rules/auto-filter-rules.toml`
3. Analyze patterns across false positives:
   - Group by `false_positive_pattern.type`
   - Look for common string patterns in `secret` and `match` fields
   - Review `context` to understand why each was marked false positive
   - Identify generalizable regex patterns

4. Generate new allowlist rules. For each distinct pattern:
   ```toml
   # Auto-generated: 2024-01-15T10:35:00Z
   # Source: scan-2024-01-15-001, {count} false positives analyzed
   # Pattern: {brief description}
   
   [[rules]]
   id = "auto-filter-{pattern-type}-{date}"
   description = "Filter {pattern description} ({count} matches in scan-{id})"
   status = "experimental"
   created = "2024-01-15"
   validation_count = 0
   source_scans = ["001"]
   [allowlist]
   regexes = [
     '''{generated regex}''',
   ]
   ```

5. Append new rules to `references/rules/auto-filter-rules.toml`
   - Only add rules for patterns not already covered
   - Update `last_updated` timestamp

6. Manage `.learning/` directory:
   - Get current scan number from `.learning/` contents (001, 002, or 003)
   - Write this scan's false positives to `.learning/scan-{NNN}-false-positives.json`:
     ```json
     {
       "scan_id": "2024-01-15-001",
       "timestamp": "2024-01-15T10:30:00Z",
       "false_positives": [
         {
           "finding_id": "...",
           "rule_id": "...",
           "file": "...",
           "line": 0,
           "secret": "...",
           "match": "...",
           "reason": "...",
           "pattern_type": "..."
         }
       ]
     }
     ```
   - If this creates a 4th file, delete the oldest one before writing

**Rule generation guidelines:**
- Only add allowlist rules (regexes, paths, stopswords)
- Never modify base detection rules in `gitleaks-base.toml`
- Prefer specific patterns over broad ones (avoid over-filtering)
- Include clear `description` explaining the pattern and source
- Always start with `status = "experimental"` and `validation_count = 0`
- Test that your regex compiles (basic sanity check)

### Phase 6: Rule Lifecycle Validation (Python script)

**Executed by:** `python scripts/rule-validator.py`

**Trigger:** Automatically after every scan, or manually via `/scan-secrets validate-rules`

1. Read `auto-filter-rules.toml`
2. For each `[experimental]` rule:
   - Check if it prevented any false positives in recent scans
   - If yes, increment `validation_count`
   - If `validation_count >= 3`, promote to `[confirmed]`:
     ```toml
     status = "confirmed"
     validated_at = "2024-01-20"
     ```
3. Validate all regexes compile correctly
4. Remove rules that haven't validated after 10 scans (orphaned rules)

## State Management

### .learning/ Directory (Max 3 scans retained)

```
.learning/
  scan-001-false-positives.json   # Oldest
  scan-002-false-positives.json
  scan-003-false-positives.json   # Newest (current)
```

When a 4th scan completes:
1. Delete `scan-001-false-positives.json`
2. Shift: 002->001, 003->002
3. Add new as 003
4. Trigger Agent to summarize deleted scan's patterns into permanent rules

### auto-filter-rules.toml Format

```toml
title = "AI-Generated Filter Rules"
last_updated = "2024-01-15T10:35:00Z"

[[rules]]
id = "auto-filter-placeholder-20240115"
description = "Filter <PLACEHOLDER> patterns"
status = "confirmed"          # experimental | confirmed
created = "2024-01-15"
validated_at = "2024-01-18"
validation_count = 3
source_scans = ["001", "002", "003"]
[allowlist]
regexes = [
  '''<[^>]+>''',
]

[[rules]]
id = "auto-filter-test-prefix-20240115"
description = "Filter test_ prefixed values"
status = "experimental"
created = "2024-01-15"
validation_count = 1
source_scans = ["003"]
[allowlist]
regexes = [
  '''["\']?test[_-]?[a-z0-9]+["\']?''',
]
```

## Agent Classification Prompt Template

When classifying findings, use this structured reasoning:

```
For each finding, analyze:

1. SECRET VALUE ANALYSIS
   - Does it match a known real secret format? (AWS AKIA, GitHub ghp_, etc.)
   - Is it obviously fake? (123456, password, xxxxxx, <PLACEHOLDER>)
   - Length and entropy appear random or structured?

2. CODE CONTEXT ANALYSIS
   - Variable name: contains test/example/mock/fake?
   - Comments nearby: mention "example", "placeholder", "TODO"?
   - Is this in a config file, test file, or documentation?
   - Is the secret hardcoded or loaded from env?

3. CLASSIFICATION DECISION
   - CONFIRMED: Real secret format + production context + no indicators of being fake
   - FALSE_POSITIVE: Clear indicators (placeholder syntax, test variable names, example comments)
   - When uncertain: CONFIRMED (conservative)

4. PATTERN EXTRACTION (for false positives only)
   - What pattern caused this to be flagged incorrectly?
   - Can this be generalized into a regex allowlist?
   - Which rule_id is affected?
```

## Error Handling

| Scenario | Action |
|----------|--------|
| gitleaks binary missing | Run `python scripts/update-gitleaks.py` |
| No findings | Generate empty report with "No secrets detected" |
| AI classification fails | Fallback: report all findings (conservative) |
| Regex validation fails | Log error, skip invalid rule, continue |
| `.learning/` full | Delete oldest, proceed with rotation |

## Integration Notes

**This skill expects:**
- Agent has file read/write capabilities
- Agent can execute shell commands (for gitleaks)
- Agent can reason about code context (core feature)

**Performance considerations:**
- Batch analysis: Agent processes all findings in one pass via JSON file
- Typical scan: 10-100 findings, analysis takes <30 seconds
- Large repos: If >200 findings, script pre-groups by rule_id for efficiency

## Rules

1. **Always classify with context**: Never classify based on file path alone
2. **Conservative bias**: Uncertain findings are CONFIRMED, not filtered
3. **Never modify base rules**: Only append to `auto-filter-rules.toml`
4. **Experimental first**: New rules start as experimental, need 3 validations
5. **Learning retention**: Keep only last 3 scans' raw false positives
6. **Auto-learning is mandatory**: After every scan, if false positives exist, update rules
7. **No human confirmation**: The entire pipeline runs autonomously

## Pitfalls & Lessons Learned

### GitHub Push Protection on Example Secrets

When committing `.learning/` files or documentation that contain example secret patterns (e.g., `https://hooks.slack.com/services/...`), GitHub push protection will block the push even if these are clearly documented examples.

**Workarounds:**
- Sanitize learning data before commit: truncate values, replace sensitive segments with `...` or `EXAMPLE`
- Use `EXAMPLE` or `FAKE` markers in all documentation examples: `sk_live_EXAMPLE_xxx` instead of realistic-looking values
- Consider adding `.learning/` to `.gitignore` if push protection is persistently problematic

### Context Extraction Edge Cases

gitleaks scans git history, so it may report findings with line numbers from old commits that no longer exist in the current file (file deleted, renamed, or shortened). `scan.py` handles this by checking bounds before extracting context.

**If you see `[Line N out of range in filename]`: this is expected for historical findings. Use the `match` field for classification instead of context.**

### Field Preservation is Critical

The Agent MUST preserve all original fields (`file`, `line`, `context`, `secret`, `match`, etc.) when generating `scan-classified.json`. `generate-report.py` needs these fields to produce the final report. Only ADD classification fields — never REMOVE or REPLACE original fields.

**Common mistake:** Creating a minimal classified JSON with only `finding_id` and `classification`. This breaks report generation.

### Type-Specific Classification Sensitivity

Different secret types require different levels of context analysis:

| Type | Context Needed | Why |
|------|---------------|-----|
| API Keys (ghp_, sk-, AKIA...) | Low | Format itself reveals authenticity |
| Passwords | **High** | Same string can be real or fake depending on context |
| JWT Tokens | Medium | Check if truncated (`...`) or in Postman/test files |
| Private Keys | Low | Check if full length vs truncated example |

**Passwords are the hardest.** `password=password123` in `tests/auth.py` is clearly fake, but the same string in `config/production.yml` is a real (weak) leak. Always analyze variable names, comments, and file paths for password findings.

### Batch Scanning Tips

When scanning multiple repositories:
1. Run `scan.py --detect` on each repo individually (don't try to merge gitleaks runs)
2. Aggregate findings from multiple `/tmp/scan-findings.json` files
3. Classify all findings in one batch for efficiency
4. Generate per-repo reports plus a master summary
5. Extract patterns from the combined false positive pool for better rule generalization

(End of file)
