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

**Option A: Classified results (AI-reviewed)** — Use the standard report generator:
```bash
python3 scripts/generate-report.py /tmp/scan-classified.json
```

**Option B: Raw/unclassified results** — Use the batch-optimized report generator:
```bash
python3 scripts/batch-generate-report.py /tmp/batch-scan-findings.json [output-dir]
```

`batch-generate-report.py` is optimized for batch scans:
- **Chinese output**: All headers, summaries, and risk descriptions are in Chinese
- **Code context**: Shows surrounding code for each finding
- **Smart truncation**: Unclassified scans show first 10 findings per repo with a hint to run AI classification for the rest
- **Valid-only detail**: When run on classified results, only `CONFIRMED` findings get full detail; `FALSE_POSITIVE` findings are counted in statistics but not listed

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
**Note:** Exception: Go testdata containing RPM package names in JSON files can trigger `generic-api-key` (see RPM Package Names pattern below)

### RPM Package Names in JSON (Extreme FP Rate)

**Project type:** Security scanners, vulnerability databases, container image analyzers
**Pattern:** `testdata/**/*.json` containing CVE/VEX data
**Content:** RPM package version strings like `rubygem-apipie-bindings-0:0.6.0-1.el8sat.src`
**Rule:** `generic-api-key`
**Classification:** FALSE_POSITIVE (package names, not secrets)
**Dead rule:** Filter `.json` files in `testdata/` matching RPM version format
**Example matches:** `rh-sso7-keycloak-0:18.0.7-1.redhat_00001.1.el9sso.src`, `eap7-snakeyaml-0:1.33.0-2.SP1_redhat_00001.1.el9eap.src`

### JNA Windows API Declarations (High FP Rate)

**Project type:** Java desktop apps using JNA for native Windows APIs
**Pattern:** `*.java` files with JNA interface declarations
**Content:** `Advapi32 advapi32 = Advapi32.INSTANCE;`
**Rule:** `generic-api-key`
**Classification:** FALSE_POSITIVE (API interface declaration, not a secret)
**Dead rule:** Filter `Advapi32.INSTANCE` and similar JNA interface patterns

### Hibernate Test Passwords (Medium FP Rate)

**Project type:** Java ORM frameworks (Hibernate, Spring Data JPA)
**Pattern:** `src/test/java/**/test/**/*.java`
**Content:** Same hardcoded test password reused across multiple test classes, e.g., `password = "3fabb4de8f1ee2e97d7793bab2db1116"`
**Rule:** `generic-api-key`
**Classification:** FALSE_POSITIVE (test fixture data)
**Dead rule:** Filter specific known test password values in Hibernate test paths

### QQ Group Links in README (Low FP Rate)

**Project type:** Chinese open-source projects
**Pattern:** `README.md`
**Content:** `idkey=44c2b0331f1bdca6c9d404e863edd83973fa97224b79778db79505fc592f00bc` in QQ group join URLs
**Rule:** `generic-api-key`
**Classification:** FALSE_POSITIVE (social media group link parameter)
**Dead rule:** Filter `wpa/qunwpa?idkey=` URLs in markdown files

### Cython Struct Definitions (Low FP Rate)

**Project type:** Python libraries with Cython extensions (scikit-image, numpy, etc.)
**Pattern:** `*.pxi` files
**Content:** `Heapitem:\n    cnp.float64_t value` (Cython struct with typed fields)
**Rule:** `generic-api-key`
**Classification:** FALSE_POSITIVE (Cython type definitions)
**Dead rule:** Filter `.pxi` files

### XML Base64 Icon Data (Low FP Rate)

**Project type:** Java/Android desktop apps with XML resource files
**Pattern:** `src/main/resources/**/*.xml` containing icon data
**Content:** Base64-encoded SVG/icon data starting with `EAA...`
**Rule:** `square-access-token`
**Classification:** FALSE_POSITIVE (base64 icon data)
**Dead rule:** Filter `EAA[A-Za-z0-9+/]{40,}` in XML resource files

### Minified JavaScript Bundles (High FP Rate)

**Project type:** Any web project with bundled frontend assets
**Pattern:** `*.js` files, especially `vendor.[hash].js` or library bundles (xterm.js, etc.)
**Content:** Minified variable assignment chains like `t.FourKeyMap=t.TwoKeyMap=void ` or `t.getColumnByKey=t.getColumnById=t.orderBy=t.getCell=void `
**Rule:** `generic-api-key`
**Classification:** FALSE_POSITIVE (minified JS variable names, not real API keys)
**Dead rule:** Filter `t\.[A-Za-z]+=t\.[A-Za-z]+(?:=t\.[A-Za-z]+)?=void` in `.js` files
**Note:** This pattern is extremely common at 10k+ star repos that ship web UIs. A single minified bundle can trigger 4+ identical FPs.

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| Clone times out | Repo too large or network slow; `execute_code` has 300s limit | Use `--depth=1` shallow clone; **use `terminal(background=True)`** for large repos (e.g., logstash >120s); run clone script in background with `notify_on_complete` |
| TLS handshake failed | GitHub rate limiting or network | Retry with `sleep 2` between clones |
| scan.py no output | gitleaks found nothing or crashed | Check `/tmp/gitleaks-raw.json` manually |
| Empty batch findings file | All repos had 0 findings | Normal for clean repos; document the result |
| Disk full | Cloned too many large repos | Monitor `df -h`; remove repos after scanning |
| Report is 25MB+ | Unclassified batch scan with hundreds of findings | Use `batch-generate-report.py` instead of `generate-report.py`; truncation reduces size by 99%+ |

## Lessons from Past Batch Scans

### Scan 2026-04-22 (20 repos, ~500-700 stars)
- **Java (8 repos):** 0 findings total. Clean repos with no hardcoded secrets.
- **Go (7 repos):** 30 findings from 1 repo (`application-gateway-kubernetes-ingress`), all in `testdata/` directories. All FALSE_POSITIVE (test fixture TLS certs).
- **Python (7 repos):** 0 findings total.
- **Learning:** Kubernetes e2e testdata is a major source of false positives. `testdata/` directories should be filtered by default for k8s-related rules.
- **Tooling:** `batch-scan.py` worked correctly. `decode_utils.py` was not needed for this batch (no JWT/base64 secrets found).

### Scan 2026-04-22 (20 repos, ~100-150 stars)
- **Java (7 repos):** 0 findings total.
- **Go (7 repos):** 337 findings from 1 repo (`claircore`), all FALSE_POSITIVE.
  - 334 matches: RPM package version strings in `testdata/**/*.json` (CVE/VEX data)
  - 3 matches: `SEGMENT_WRITE_KEY` in testdata Dockerfiles
- **Python (6 repos):** 1 finding from `wyldcard` - base64 icon data in XML matched as `square-access-token`. FALSE_POSITIVE.
- **Learning:** Small-star repos can have extreme FP rates from testdata. `claircore` alone produced 334 FPs from RPM package names. The `generic-api-key` rule is overly broad for package manager metadata.
- **Star-range insight:** 100-star repos appear to have the highest FP density due to less mature test data management.

### Scan 2026-04-22 (18 repos, ~5000-6500 stars)
- **Java (7 repos):** 12 findings from `processing` (JNA API declarations, all FP), 9 from `IJPay` (2 CONFIRMED WeChat Pay API keys + 7 FPs), 11 from `hibernate-orm` (test passwords, all FP), 4 from `jetlinks-community` (test PEM files, all FP), 3 from `Spring-Cloud-Platform` (nacos log tokens, all FP).
- **Go (7 repos):** 25 findings from `evcc` - **20 CONFIRMED vehicle OEM API secrets** + 5 FPs (testdata JWT/keys). This is the first batch with significant confirmed leaks.
  - Confirmed secrets: Hyundai CCSP secret, Fiat ApiKey/XApiKey, Skoda/Seat/Toyota/Nissan/Renault/Smart/Subaru/PSA/JLR/VW client secrets
- **Python (6 repos):** 11 findings total (jwt_tool README examples, scikit-image docstring URLs).
- **Learning:** High-star repos DO contain real hardcoded secrets. `evcc` hardcodes 12 car manufacturers' API keys in production vehicle integration code. Payment SDKs like `IJPay` also embed real API keys in demo configs.
- **Star-range insight:** 5000+ star repos have the highest confirmed-secret rate. Popularity correlates with real integration code that needs actual API credentials.
- **Tooling:** `decode_utils.py` was used successfully to analyze JWT structure during classification.

### Scan 2026-04-22 (20 repos, ~5000 stars, plugin-era)
- **Multi-language:** 14 repos with findings, 6 clean. 309 total raw findings.
- **Breakdown by rule:** `generic-api-key` (188), `private-key` (104), `curl-auth-user` (14), `jwt` (3).
- **Top repos:** `dotenvx` (122), `x402` (101), `opencloud` (26), `pyrefly` (19), `tagspaces` (13).
- **Unclassified mode report:** 96KB (2000 lines) after truncation optimization. Down from 25MB (8924 lines) in unoptimized mode.
- **Learning:** High-star repos with broad language diversity produce massive raw finding volumes. Report truncation (first 10 per repo for unclassified) is essential for usability.
- **Tooling:** `batch-generate-report.py` with Chinese output and smart truncation successfully reduced report size by 99.6%.

### Star-Range Correlation Summary

Based on four batch scans across star ranges:

| Star Range | Repos | Total Findings | Confirmed | FP Rate | Notes |
|------------|-------|---------------|-----------|---------|-------|
| ~100 | 20 | 338 | 0 | 100% | Extreme FP from testdata (RPM names, test fixtures) |
| ~500 | 19 | 30 | 0 | 100% | Moderate FP, mostly k8s testdata TLS certs |
| ~5000 (Apr 22 early) | 18 | 80 | 22 | 72.5% | Real secrets emerge (vehicle APIs, payment keys) |
| ~5000 (Apr 22 plugin) | 20 | 309 | TBD* | TBD* | Unclassified; requires AI review for confirmation count |
| ~15000 (Apr 27) | 10 | 23 | 5 | 78.3% | Minified JS bundles dominate FPs; real secrets still present (exploit keys, service APIs) |

*309 raw findings from the plugin-era scan are pending AI classification. Pre-truncation report was 25MB; post-optimization report is 96KB.

**Implication:** For scanner calibration and rule testing, use a mix of star ranges. Low-star repos are best for discovering FP patterns; high-star repos are best for discovering real secret patterns.

### Scan 2026-04-21 (20 repos, mixed sizes)
- 38 raw findings, 9 confirmed, 29 false positives
- Generated 5 experimental dead rules covering: YOUR_* placeholders, JWT in Postman, doc examples, test certs, example keys, DocSearch API keys

### Scan 2026-04-27 (10 repos, ~14000-15000 stars, Java + Python)
- **Java (5 repos):** 14 findings from 2 repos (`onedev`: 7, `vert.x`: 7). `logstash`, `Arduino`, `CircleImageView` were clean.
  - `onedev`: 4 FPs from minified xterm.js bundles (`t.FourKeyMap=t.TwoKeyMap=void`), 3 CONFIRMED Tanuki wrapper license keys (LOW)
  - `vert.x`: 2 FPs from Javadoc PEM examples, 5 FPs from TLS test fixture PEM arrays (all FALSE_POSITIVE)
- **Python (5 repos):** 8 findings from 3 repos (`py12306`: 7, `llmware`: 1, `social-engineer-toolkit`: 1). `memray`, `XSStrike` were clean.
  - `py12306`: 1 CONFIRMED ruokuai captcha API key (MEDIUM), 4 FPs from minified vendor.js bundles, 1 FP config placeholder, 1 FP docstring param
  - `llmware`: 1 FP HuggingFace repo name (`llmware/bonchon`)
  - `social-engineer-toolkit`: 1 CONFIRMED hardcoded private key in F5 CVE exploit (HIGH)
- **Learning:** At ~15k stars, minified JS bundles become the dominant false positive source (8/18 = 44%). Mature projects still contain real secrets in integration/exploit code. Javadoc examples and test fixture PEM data are reliable FP patterns for Java projects.
- **Tooling:** Background terminal mode essential for cloning large repos (logstash >120s). `execute_code` 300s timeout kills foreground clone operations.
- **New rules:** 2 dead rules (minified JS, Javadoc PEM examples) + 3 semantic rules (minified JS analysis, Javadoc example keys, test PEM fixtures).
