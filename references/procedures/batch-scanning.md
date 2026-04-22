# Batch Scanning Procedure

Scan multiple repositories in one run, aggregate findings, and extract cross-repo patterns.

## When to Use

- Evaluating scanner accuracy on a corpus of open-source projects
- Testing new rules against diverse codebases before deployment
- Generating statistical data on false positive rates by language/project type

## Prerequisites

- `scripts/batch-scan.py` exists (or create it from template)
- `scripts/scan.py` works for single-repo scans
- Sufficient disk space for cloned repositories
- GitHub API access (no auth needed for public repos, but rate-limited)

## Workflow

### Step 1: Search and Select Repositories

Use GitHub API to find repositories by language and star count:

```python
# Python search helper
import urllib.request, json

def search_repos(language, stars_range="400..700", per_page=8):
    url = f'https://api.github.com/search/repositories?q=language:{language}+stars:{stars_range}&sort=stars&order=desc&per_page={per_page}'
    req = urllib.request.Request(url, headers={
        'User-Agent': 'secrets-scanner-batch-test',
        'Accept': 'application/vnd.github.v3+json'
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode('utf-8')).get('items', [])
```

**Pitfall:** GitHub API rate limit is 60 requests/hour for unauthenticated requests. For large batches, space out searches or use authenticated requests.

### Step 2: Batch Clone

**Recommended approach:** Use a shell script + terminal background mode.

```bash
#!/bin/bash
# save as /tmp/clone-batch.sh
cd /home/davei/projects

repos=(
  "https://github.com/user/repo1.git"
  "https://github.com/user/repo2.git"
  # ...
)

for url in "${repos[@]}"; do
    name=$(basename "$url" .git)
    [ -d "$name" ] && continue
    echo "[CLONE] $name ..."
    git clone --depth=1 "$url" 2>&1 || echo "[FAIL] $name"
    sleep 1  # Rate limiting
done
```

Run with terminal background mode (execute_code has 300s limit, often insufficient):
```bash
bash /tmp/clone-batch.sh
```

**Pitfall:** Some repos may fail to clone due to network issues or TLS errors. Always verify which repos actually exist before scanning.

**Pitfall:** Large repos (e.g., spring-boot-all with 3000+ files) may take >2 minutes to clone. Background mode is essential.

### Step 3: Prepare Repo List

Filter to only successfully cloned repos:

```python
import json, os

with open('.repo_list.json') as f:
    repos = json.load(f)

available = []
for r in repos:
    if os.path.exists(f"/home/davei/projects/{r['name']}"):
        available.append(r)

with open('.repo_list_available.json', 'w') as f:
    json.dump(available, f, indent=2)
```

### Step 4: Run Batch Scan

```bash
cd /path/to/secrets-scanner
python3 scripts/batch-scan.py \
  --list-file /home/davei/projects/.repo_list_available.json \
  --output /tmp/batch-scan-findings.json
```

**What batch-scan.py does:**
1. Runs `scan.py --detect` on each repo individually
2. Renames each `/tmp/scan-findings.json` to avoid collision
3. Aggregates all findings with `repo_name` and `repo_path` fields
4. Outputs combined JSON to `/tmp/batch-scan-findings.json`

**Pitfall:** Large repos may cause scan.py to timeout. The batch scanner skips failed repos and continues with the rest.

### Step 5: Classify Findings

Read `/tmp/batch-scan-findings.json` and classify all findings at once. The aggregated format includes `repo_name` for each finding:

```json
{
  "findings": [
    {
      "repo_name": "application-gateway-kubernetes-ingress",
      "repo_path": "/home/davei/projects/application-gateway-kubernetes-ingress",
      "rule_id": "private-key",
      "file": "tests/data/k8s.cert.key",
      ...
    }
  ]
}
```

**Efficiency tip:** Process all findings in one batch rather than per-repo. Cross-repo pattern extraction is more effective with the full dataset.

### Step 6: Generate Report

```bash
python3 scripts/generate-report.py /tmp/scan-classified.json
```

For batch scans, the report will show aggregate statistics across all repos.

### Step 7: Auto-Learning (Cross-Repo Patterns)

After batch classification, analyze the combined false positive pool:

1. **Look for language-specific patterns:** Do Java projects share common FP patterns? (e.g., test properties files)
2. **Look for framework-specific patterns:** Kubernetes testdata? Spring Boot application.yml defaults?
3. **Look for structural patterns:** Are FPs concentrated in `testdata/`, `tests/`, `docs/`?

Generate dead rules that generalize across the entire batch:

```toml
# Example: testdata TLS certificates (found in 30 matches across 1 repo)
[[rules]]
id = "auto-filter-k8s-testdata-tls-20260422"
description = "Filter test fixture TLS certificates in e2e testdata directories"
status = "experimental"
[allowlist]
paths = [
  '''.*testdata/.*''',
  '''.*tests/data/.*''',
]
regexes = [
  '''name:\s*testsecret-[a-z]+''',
]
```

## Batch Scan Results Template

When documenting batch scan results, use this structure:

```
Batch: {batch-id}
Repos: {N} ({language breakdown})
Stars range: {min}-{max}
Total findings: {N}
Confirmed: {N}
False Positives: {N}

Per-repo breakdown:
- repo1: 0 findings
- repo2: 30 findings (all FP: testdata TLS certs)
- ...

New rules generated:
- auto-filter-xxx (experimental, {N} matches)
```

## Known Batch Scan Patterns

### Kubernetes E2E Testdata (High FP Rate)

**Project type:** Kubernetes controllers, ingress controllers, operators
**Pattern:** `scripts/e2e/cmd/runner/testdata/**/*.yaml`
**Content:** Test TLS certificates, `testsecret-tls` secrets, base64-encoded keys
**Classification:** FALSE_POSITIVE (test fixtures)
**Dead rule:** Filter `testdata/` directories with `testsecret-*` naming

### Java/Maven Properties (Medium FP Rate)

**Project type:** Spring Boot, Java web apps
**Pattern:** `src/test/resources/*.properties`
**Content:** `database.password=test123`, `api.key=demo`
**Classification:** Usually FALSE_POSITIVE (test resources)

### Go Test Fixtures (Low FP Rate)

**Project type:** Go CLI tools, libraries
**Pattern:** `testdata/*`, `*_test.go`
**Content:** Usually no secrets detected in Go testdata

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| Clone times out | Repo too large or network slow | Use `--depth=1` shallow clone; run in background |
| TLS handshake failed | GitHub rate limiting or network | Retry with `sleep 2` between clones |
| scan.py no output | gitleaks found nothing or crashed | Check `/tmp/gitleaks-raw.json` manually |
| Empty batch findings file | All repos had 0 findings | Normal for clean repos; document the result |
| Disk full | Cloned too many large repos | Monitor `df -h`; remove repos after scanning |

## Lessons from Past Batch Scans

### Scan 2026-04-22 (20 repos, ~500-700 stars)
- **Java (8 repos):** 0 findings total. Clean repos with no hardcoded secrets.
- **Go (7 repos):** 30 findings from 1 repo (`application-gateway-kubernetes-ingress`), all in `testdata/` directories. All FALSE_POSITIVE (test fixture TLS certs).
- **Python (7 repos):** 0 findings total.
- **Learning:** Kubernetes e2e testdata is a major source of false positives. `testdata/` directories should be filtered by default for k8s-related rules.
- **Tooling:** `batch-scan.py` worked correctly. `decode_utils.py` was not needed for this batch (no JWT/base64 secrets found).

### Scan 2026-04-21 (20 repos, mixed sizes)
- 38 raw findings, 9 confirmed, 29 false positives
- Generated 5 experimental dead rules covering: YOUR_* placeholders, JWT in Postman, doc examples, test certs, example keys, DocSearch API keys
