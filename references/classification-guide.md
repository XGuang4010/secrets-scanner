# Secrets Classification Guide

## Purpose

This document provides detailed classification logic for different types of sensitive information detected by gitleaks. Use this guide when the Agent cannot confidently classify a finding based on intuition alone.

**Rule of thumb:** When uncertain, classify as CONFIRMED (conservative bias).

---

## Classification Matrix

| Type | Examples | Placeholder Signals | Production Signals | Context Dependency |
|------|----------|-------------------|-------------------|-------------------|
| **API Key** | `ghp_xxx`, `sk-xxx`, `AKIAxxx` | `YOUR_API_KEY`, `<API_KEY>`, `xxx...xxx` | Standard format + random suffix | Low |
| **Password** | `password123`, `MyP@ssw0rd` | `password`, `123456`, `admin` in tests/docs | Weak string in production config | **High** |
| **Token** | `Bearer eyJ...`, `token=abc123` | `test_token`, `example_token` | Real JWT format, long random string | Medium |
| **Database URL** | `postgres://user:pass@host` | `localhost`, `example.com` | Real hostname, production domain | Medium |
| **Private Key** | `-----BEGIN RSA PRIVATE KEY-----` | Short key, `EXAMPLE` in content | Full length, valid format | Low |

---

## Type 1: API Keys (Low Context Dependency)

### Characteristics
- Usually have fixed prefixes: `ghp_`, `gho_`, `github_pat_`, `sk-`, `sk-live-`, `sk-test-`, `AKIA`, `ASIA`, etc.
- High entropy (random-looking suffix)
- Standardized length

### CONFIRMED Signals
```python
# Real format with production indicators
api_key = "sk-live-ABC123EXAMPLE_fake_key_for_demo"  # sk-live- prefix + random
aws_key = "AKIAIOSFODNN7EXAMPLE"                        # AKIA prefix (note: EXAMPLE suffix means it's actually a sample, see below)
gh_token = "ghp_EXAMPLE_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"   # ghp_ + 36 chars
```

### FALSE_POSITIVE Signals
```python
# Obvious placeholders
api_key = "YOUR_API_KEY_HERE"              # YOUR_ prefix + _HERE suffix
api_key = "<API_KEY>"                      # Angle brackets
api_key = "xxxxxxxxxxxxxxxx"               # Repeated x's
api_key = "test_key_123456"                # test_ prefix

# AWS sample keys (official AWS examples use EXAMPLE suffix)
aws_key = "AKIAIOSFODNN7EXAMPLE"           # Official AWS documentation sample
aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # Official AWS sample
```

### AWS Special Case
AWS provides official sample keys for documentation. Any AKIA key ending with `EXAMPLE` or containing `EXAMPLE` is a sample:
- `AKIAIOSFODNN7EXAMPLE` → FALSE_POSITIVE (official AWS doc sample)
- `AKIAQWERTYUIOPASDFGH` → CONFIRMED (real format, no EXAMPLE marker)

---

## Type 2: Passwords (High Context Dependency)

### Characteristics
- Usually weak strings: common words + numbers
- Highly context-dependent: same value can be real or fake depending on usage
- **Must analyze variable names, comments, and file paths**

### CONFIRMED Signals
```python
# Production config without test markers
# File: config/production.yml
database:
  password: "MyP@ssw0rd123"        # No test markers, production path

# File: src/database.py
DB_PASSWORD = "supersecret2024"    # Real variable name in production code
```

### FALSE_POSITIVE Signals
```python
# File: tests/test_login.py
def test_authentication(self):
    test_password = "password123"   # test_ prefix
    mock_password = "admin"         # mock_ prefix
    example_pwd = "123456"          # example_ prefix

# File: README.md
# Example usage with password "password123"   # Comment says "Example"

# File: docs/setup.md
# Default password: admin                       # Documentation default
```

### Borderline Cases (CONFIRMED - Conservative)
```python
# File: config/settings.py (ambiguous path)
password = "password123"            # No test markers, but weak password
# → CONFIRMED because we cannot be sure it's fake
#   Weak passwords in config files are still real leaks
```

### Decision Tree for Passwords
```
Password finding
    │
    ├─ Variable name contains test/mock/example/fake/dummy?
    │   └─ FALSE_POSITIVE
    │
    ├─ Comment nearby says "example", "test", "placeholder", "dummy"?
    │   └─ FALSE_POSITIVE
    │
    ├─ File is README.md, docs/, examples/, or test file?
    │   └─ FALSE_POSITIVE
    │
    └─ No clear indicators either way?
        └─ CONFIRMED (conservative bias)
```

---

## Type 3: Tokens (Medium Context Dependency)

### Characteristics
- Can be opaque strings or structured (JWT)
- JWT format: `eyJ...` (base64url-encoded JSON)
- Bearer tokens: `Bearer <token>`

### CONFIRMED Signals
```python
# Real JWT format
auth_token = "eyJEXAMPLE.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Real Bearer token in production
Authorization: Bearer a1b2c3d4e5f6...      # Long random string
```

### FALSE_POSITIVE Signals
```python
# Test tokens
test_token = "test_token_123456"     # test_ prefix
mock_bearer = "mock_token"           # mock_ prefix

# Example JWT (short, invalid format)
example_jwt = "eyJ..."               # Truncated with ...

# Documentation placeholders
curl -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

---

## Type 4: Database Connection Strings (Medium Context Dependency)

### Characteristics
- URLs with embedded credentials: `protocol://user:password@host`
- Hostname indicates environment: localhost (test) vs real domain (production)

### CONFIRMED Signals
```python
# Production database
database_url = "postgresql://admin:secretpass@prod.db.company.com:5432/myapp"
# Real hostname (prod.db.company.com) + real-looking credentials
```

### FALSE_POSITIVE Signals
```python
# Local development
DATABASE_URL = "postgresql://user:password@localhost:5432/testdb"
# localhost = test environment

# Documentation example
# Connect: mysql://user:pass@example.com/db   # example.com = reserved domain

# Docker compose default
POSTGRES_PASSWORD: postgres            # Default Docker password
```

---

## Type 5: Private Keys (Low Context Dependency)

### Characteristics
- PEM format with headers
- Should be full-length (not truncated)
- Contains valid base64 content

### CONFIRMED Signals
```python
# Full private key
private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA2a2rwplBQLpMx+pSGo5v0+l8sjBjNgFkYCVqiR3lFEj8F6Gf
...
-----END RSA PRIVATE KEY-----"""
```

### FALSE_POSITIVE Signals
```python
# Example/truncated key
# Example private key:
# -----BEGIN RSA PRIVATE KEY-----
# MII...
# -----END RSA PRIVATE KEY-----

# Short test key
test_key = "-----BEGIN RSA PRIVATE KEY-----\nABC...\n-----END RSA PRIVATE KEY-----"
```

---

## Few-Shot Examples

### Example 1: API Key in Production (CONFIRMED)
```python
# File: src/payments.py
stripe.api_key = "sk_live_ABC123EXAMPLE_fake_key_for_demo"
```
**Analysis:**
- Type: API Key (Stripe)
- Format: Valid `sk_live_` prefix with long random suffix
- Context: Production source file
- Variable name: `stripe.api_key` (real, not test)
- **Classification: CONFIRMED**

### Example 2: Password in Test (FALSE_POSITIVE)
```python
# File: tests/test_auth.py
def test_login(self):
    # Using test credentials
    test_password = "password123"
```
**Analysis:**
- Type: Password
- Value: Weak string "password123"
- Context: Test file (`tests/`)
- Variable name: `test_password`
- Comment: "Using test credentials"
- **Classification: FALSE_POSITIVE**
- Pattern: `test_` prefix + explicit test comment

### Example 3: Password in Ambiguous Context (CONFIRMED)
```python
# File: config/settings.py
DATABASE_PASSWORD = "admin123"
```
**Analysis:**
- Type: Password
- Value: Weak string "admin123"
- Context: Config file (ambiguous - could be dev or prod)
- Variable name: `DATABASE_PASSWORD` (real, not test)
- No test markers, no example comments
- **Classification: CONFIRMED** (conservative bias)
- Note: Even weak passwords in config files should be reported

### Example 4: Placeholder in Documentation (FALSE_POSITIVE)
```bash
# File: README.md
# Usage:
# curl -H "Api-Key: YOUR_API_KEY_HERE" https://api.example.com/data
```
**Analysis:**
- Type: API Key
- Value: "YOUR_API_KEY_HERE"
- Context: README.md documentation
- Pattern: `YOUR_` prefix + `_HERE` suffix
- **Classification: FALSE_POSITIVE**
- Pattern type: `placeholder`

### Example 5: Real Token in Config (CONFIRMED)
```yaml
# File: config/production.yml
auth:
  jwt_secret: "EXAMPLE_TOKEN_a1b2c3d4e5f6g7h8i9j0"
```
**Analysis:**
- Type: Token
- Value: Long random string
- Context: Production config path
- Variable name: `jwt_secret` (real)
- No test markers
- **Classification: CONFIRMED**

---

## Pattern Extraction Guide

When marking FALSE_POSITIVE, extract patterns using these templates:

| Pattern Type | Description | Example Regex |
|-------------|-------------|---------------|
| `placeholder` | YOUR_* , <...>, xxx... | `YOUR_[A-Z_]+` or `<[^>]+>` |
| `example_value` | example_*, sample_* | `example_[a-zA-Z0-9_]+` |
| `test_data` | test_*, mock_*, fake_* | `test_[a-zA-Z0-9_]+` |
| `comment_indicated` | TODO, FIXME, example | N/A (context-based) |
| `format_mismatch` | Truncated, invalid format | `\.{3,}` or incomplete JWT |

---

## Version History

| Date | Changes |
|------|---------|
| 2026-04-21 | Initial version with 5 type categories and few-shot examples |

---

*This guide is maintained by the AI Agent. Update it when new patterns are discovered during scans.*
