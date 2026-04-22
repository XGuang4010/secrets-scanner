# Secret Validator Plugin Architecture

The verification framework (`scripts/verify-secrets.py`) uses a **plugin-based architecture** where each secret type validator is an independent module. The framework layer enforces all safety constraints centrally, while plugins only implement business logic.

## Why Plugin Architecture

**Before:** Monolithic single file with all validators inline. Adding a new validator required modifying the core file, risking regressions in existing validators.

**After:** Each validator is a standalone module. Adding a new validator = create one file + register in `__init__.py`. Zero risk to existing validators.

## Directory Structure

```
scripts/
  verify-secrets.py              # Framework: CLI, routing, safety enforcement
  verify_plugins/
    __init__.py                  # Registry: rule_id -> plugin module
    _utils.py                    # Shared tools: secret extraction, entropy, JWT check, masking
    aws.py                       # AWS STS SigV4 validator
    stripe.py                    # Stripe API validator
    hyundai.py                   # Hyundai Bluelink validator
    generic.py                   # Dispatcher + fallback (JWT, entropy, NOT_TESTABLE)
```

## Framework Responsibilities (verify-secrets.py)

| Concern | Implementation |
|---------|---------------|
| Rate limiting | Global `rate_limit()` — 1 req/s, enforced before every plugin call |
| Timeout | `ThreadPoolExecutor` with 10s `future.result(timeout=TIMEOUT)` |
| Exception handling | Plugin crash → caught → `UNKNOWN` + `crash-guard`, never propagates |
| Log masking | `mask()` applied to all secret values in stderr logs |
| Batch limiting | Max 20 findings for batch scans |
| Output formatting | Wraps plugin result with `tested_at` timestamp |
| Plugin routing | `get_plugin(rule_id)` → exact match → prefix fallback → `None` |

Plugins **do NOT** handle any of these concerns. They only implement `validate(finding)`.

## Plugin Interface Contract

Every plugin module must implement exactly one function:

```python
def validate(finding: dict) -> dict:
    """
    Args:
        finding: Single finding dict from scan-classified.json.
                 Keys available: finding_id, rule_id, file, line, match, context, etc.

    Returns:
        {
            "status": "VALID" | "INVALID" | "UNKNOWN" | "NOT_TESTABLE",
            "detail": "Human-readable explanation (Chinese or English)",
            "validator": "plugin-name-for-tracing",
            "http_status": 200,  # optional, for network-based validators
        }
    """
```

**Rules for plugin authors:**
- Do NOT call `rate_limit()` — the framework calls it before invoking your plugin
- Do NOT catch broad exceptions — the framework handles crashes
- Do NOT log raw secrets — use `from ._utils import mask` if you need to log
- Do NOT set `tested_at` — the framework adds it after your return
- Do NOT import framework modules — only import `_utils` and standard library

## How to Add a New Validator

### Step 1: Create plugin file

Create `scripts/verify_plugins/{platform}.py`:

```python
"""{Platform} secret validator plugin."""

import urllib.error
import urllib.request

from ._utils import extract_secret_from_match, mask

TIMEOUT = 10


def validate(finding: dict) -> dict:
    match = finding.get("match", "")
    secret = extract_secret_from_match(match)

    if not secret:
        return {
            "status": "NOT_TESTABLE",
            "detail": "Could not extract secret from match",
            "validator": "{platform}",
        }

    # Build your read-only verification request here
    url = "https://api.example.com/v1/verify"
    try:
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {secret}"},
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            if resp.status == 200:
                return {
                    "status": "VALID",
                    "detail": "API accepted the credential",
                    "validator": "{platform}",
                    "http_status": resp.status,
                }
            return {
                "status": "UNKNOWN",
                "detail": f"Unexpected HTTP {resp.status}",
                "validator": "{platform}",
                "http_status": resp.status,
            }
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {
                "status": "INVALID",
                "detail": "Authentication failed (401)",
                "validator": "{platform}",
                "http_status": e.code,
            }
        return {
            "status": "UNKNOWN",
            "detail": f"HTTP {e.code}",
            "validator": "{platform}",
            "http_status": e.code,
        }
```

### Step 2: Register in the registry

Edit `scripts/verify_plugins/__init__.py`:

```python
from . import aws, stripe, hyundai, generic, {platform}  # add import

REGISTRY = {
    "aws-access-key": aws,
    "aws-secret-access-key": aws,
    "generic-api-key": generic,
    "private-key": generic,
    "jwt": generic,
    "{your-rule-id}": {platform},  # add mapping
}
```

### Step 3: Test

```bash
cd scripts
python3 verify-secrets.py /tmp/scan-classified.json
```

## The Generic Dispatcher

`verify_plugins/generic.py` handles `generic-api-key` findings by inspecting the code context and routing to the appropriate platform-specific validator:

```
generic-api-key finding
    ├── context contains "stripe" or "sk_live"  →  stripe.validate()
    ├── context contains "wxpay" or "wechat"    →  NOT_TESTABLE (needs signed request)
    ├── context contains "fiat"                 →  NOT_TESTABLE (unknown endpoint)
    ├── context contains "hyundai" or "bluelink" →  hyundai.validate()
    └── otherwise                               →  JWT check + entropy analysis
```

If you add a new platform that uses `generic-api-key` rule (common for API keys detected by gitleaks), update the dispatcher in `generic.py` to route to your plugin.

## Safety Constraints (Non-Negotiable)

All validators in this framework must obey these constraints. The framework enforces some; the plugin author must ensure the rest:

| Constraint | Enforced By | Plugin Author Responsibility |
|-----------|-------------|------------------------------|
| Read-only only | Framework logs | Never send write/modify/delete requests |
| 10s timeout | `ThreadPoolExecutor` | Design requests to complete well under 10s |
| 1 req/s rate limit | `rate_limit()` before each call | None — framework handles |
| Secret masking in logs | `mask()` in framework logs | Use `mask()` in any plugin-specific logs |
| Never crash | Exception wrapper | Let exceptions propagate; framework catches |
| Batch limit 20 | Pre-filter in main() | None |

## Testing Plugins in Isolation

```python
# Test a single plugin without running the full framework
from verify_plugins.aws import validate

test_finding = {
    "rule_id": "aws-access-key",
    "match": "access_key = 'AKIAIOSFODNN7EXAMPLE'",
    "context": {
        "before": ["secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"],
        "match_line": "access_key = 'AKIAIOSFODNN7EXAMPLE'",
        "after": [],
    }
}
result = validate(test_finding)
print(result)
```
