"""GitHub Personal Access Token validator plugin.

Validates GitHub PATs via read-only API request.
Safety: read-only GET request, 10s timeout, masks secrets in logs.
"""

import sys
import urllib.error
import urllib.request

from ._utils import mask

TIMEOUT = 10


def validate(finding: dict) -> dict:
    """Validate a GitHub PAT via the /user API endpoint."""
    match = finding.get("match", "")

    # Extract the token from the match line
    token = None
    # Try to find ghp_... value
    import re
    m = re.search(r'(ghp_[a-zA-Z0-9]{36})', match)
    if m:
        token = m.group(1)

    if not token:
        return {
            "status": "NOT_TESTABLE",
            "detail": "无法从匹配中提取 GitHub PAT",
            "validator": "github-pat",
        }

    url = "https://api.github.com/user"

    try:
        print(f"[INFO] GitHub: testing token={mask(token)}", file=sys.stderr)
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "secrets-scanner-verify",
            },
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            if resp.status == 200:
                return {
                    "status": "VALID",
                    "detail": "GitHub API 认证成功，Token 有效",
                    "validator": "github-pat",
                    "http_status": resp.status,
                }
            return {
                "status": "UNKNOWN",
                "detail": f"返回 HTTP {resp.status}",
                "validator": "github-pat",
                "http_status": resp.status,
            }
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {
                "status": "INVALID",
                "detail": "HTTP 401 认证失败，Token 无效或已撤销",
                "validator": "github-pat",
                "http_status": e.code,
            }
        return {
            "status": "UNKNOWN",
            "detail": f"HTTP {e.code}",
            "validator": "github-pat",
            "http_status": e.code,
        }
    except Exception as e:
        print(f"[WARN] GitHub validator error: {e}", file=sys.stderr)
        return {
            "status": "UNKNOWN",
            "detail": f"网络错误: {type(e).__name__}",
            "validator": "github-pat",
        }


# Auto-registered rule IDs for dynamic plugin discovery
RULE_IDS = ["github-pat"]
