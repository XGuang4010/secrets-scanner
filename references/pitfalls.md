# Pitfalls & Lessons Learned

## GitHub Push Protection on Example Secrets

When committing `.learning/` files or documentation that contain example secret patterns (e.g., `https://hooks.slack.com/services/...`), GitHub push protection will block the push even if these are clearly documented examples.

**Workarounds:**
- Sanitize learning data before commit: truncate values, replace sensitive segments with `...` or `EXAMPLE`
- Use `EXAMPLE` or `FAKE` markers in all documentation examples: `sk_live_EXAMPLE_xxx` instead of realistic-looking values
- Consider adding `.learning/` to `.gitignore` if push protection is persistently problematic

## Context Extraction Edge Cases

gitleaks scans git history, so it may report findings with line numbers from old commits that no longer exist in the current file (file deleted, renamed, or shortened). `scan.py` handles this by checking bounds before extracting context.

**If you see `[Line N out of range in filename]`: this is expected for historical findings. Use the `match` field for classification instead of context.**

## gitleaks v8.30+ Configuration Merge Trap

gitleaks v8.30+ **does not allow pure-allowlist `[[rules]]`** (rules without a `regex` or `path` field). Two failure modes:

1. **Simple string concatenation** of `gitleaks-base.toml` + `auto-filter-rules.toml` → `toml: table allowlist already exists` (base has global `[allowlist]`, filter rules also contain `[allowlist]` blocks)
2. **Filter rules as standalone `[[rules]]`** → `both |regex| and |path| are empty, this rule will have no effect`

**Fix in `scan.py`:**
- `merge_rules()` parses `auto-filter-rules.toml` to extract allowlist `regexes` and `paths`
- These entries are **injected into the global `[allowlist]` section** of `gitleaks-base.toml`
- `auto-filter-rules.toml` retains its `[[rules]]` format for `rule-validator.py` lifecycle management, but is **not** passed raw to gitleaks

**Critical detail:** gitleaks uses exit code `1` for both "findings exist" AND "config error". `scan.py` must inspect stderr for `unable to load gitleaks config` or `toml` to distinguish fatal errors from normal detection results.

## gitleaks Entropy Threshold Causes False Negatives

gitleaks rules with `entropy = N` filter matches below that Shannon entropy value. This is intended to reduce false positives (e.g., `password=123456` has low entropy), but it also **silently drops real secrets** whose character distribution happens to be uneven.

**Example:** Tanuki Java Service Wrapper license keys (`XXXX-XXXX-XXXX-XXXX` hex format):
```
key.1: 738d-5fef-1202-50e7 → entropy=3.3661 (filtered, threshold=3.5)
key.2: 83dc-f00f-75b5-ec96 → entropy=3.5766 (detected)
key.4: a169-5d98-4bf8-e647 → entropy=3.5766 (detected)
```

8 license keys → only 3 detected because 5 had entropy < 3.5.

**When to adjust:** If you know a specific secret type is consistently under the threshold, either:
1. Lower the rule's entropy (affects ALL matches of that rule — increases FP rate)
2. Add a dedicated rule for that secret type with a lower/no entropy requirement
3. Accept the false negatives as a known limitation

## PLATFORM_MAP Inconsistency Between Scripts

**Critical**: Different scripts in the skill may use different `PLATFORM_MAP` conventions. For example:
- `scan.py`: `{"Linux-x86_64": "linux-x86_64"}` → matches manifest.json keys
- `update-gitleaks.py`: `{"linux-x86_64": "linux_x64"}` → maps manifest key to release filename
- A new script that copies one convention without understanding the other will fail with "No binary configured for platform"

**Rule:** Always verify that your platform key matches the target (manifest.json key vs release filename vs whatever the upstream tool expects). There are THREE different conventions in play:

| Context | Example |
|---------|---------|
| manifest.json keys | `linux-x86_64` |
| GitHub release filenames | `linux_x64` |
| `platform.system()` output | `Linux` |

## Non-Git Directories Require `--no-git`

By default, gitleaks scans **git history only** (0 commits scanned for non-git dirs). For directories without `.git/`, `scan.py` must append `--no-git` to the gitleaks command, or detection returns zero findings silently.

## Field Preservation is Critical

The Agent MUST preserve all original fields (`file`, `line`, `context`, `secret`, `match`, etc.) when generating `scan-classified.json`. `generate-report.py` needs these fields to produce the final report. Only ADD classification fields — never REMOVE or REPLACE original fields.

**Common mistake:** Creating a minimal classified JSON with only `finding_id` and `classification`. This breaks report generation.

## `.learning/` File Format Compatibility

`.learning/scan-*-false-positives.json` files may exist in two formats due to evolution of the data structure:
- **Old format**: Plain list of finding objects
- **New format**: Dict with `{"false_positives": [...], "scan_id", "timestamp", ...}`

`rule-validator.py` reads these files during Phase 6 validation. If it encounters the old list format, it will crash with `AttributeError: 'list' object has no attribute 'get'`.

**Fix:** `rule-validator.py` has been patched to handle both formats via `isinstance(data, list)` check. If you see this error, ensure you're using the latest version of the script.

## Type-Specific Classification Sensitivity

Different secret types require different levels of context analysis:

| Type | Context Needed | Why |
|------|---------------|-----|
| API Keys (ghp_, sk-, AKIA...) | Low | Format itself reveals authenticity |
| Passwords | **High** | Same string can be real or fake depending on context |
| JWT Tokens | Medium | Check if truncated (`...`) or in Postman/test files |
| Private Keys | Low | Check if full length vs truncated example |

**Passwords are the hardest.** `password=password123` in `tests/auth.py` is clearly fake, but the same string in `config/production.yml` is a real (weak) leak. Always analyze variable names, comments, and file paths for password findings.
