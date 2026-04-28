"""Plugin registry for secret verification.

Supports both static (hard-coded) and dynamic (runtime-discovered) plugin registration.
"""

import importlib
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Static imports (backward-compatible)
# ---------------------------------------------------------------------------
from . import aws, stripe, hyundai, generic, fiat, psa, toyota, renault, nissan, subaru, vw, github_pat

REGISTRY = {
    "aws-access-key": aws,
    "aws-secret-access-key": aws,
    "generic-api-key": generic,
    "private-key": generic,
    "jwt": generic,
    "fiat-api-key": fiat,
    "psa-api-key": psa,
    "toyota-api-key": toyota,
    "renault-api-key": renault,
    "nissan-api-key": nissan,
    "subaru-api-key": subaru,
    "vw-api-key": vw,
    "stripe-api-key": stripe,
    "stripe-secret-key": stripe,
    "hyundai-api-key": hyundai,
    "hyundai-bluelink": hyundai,
    "github-pat": github_pat,
}

# ---------------------------------------------------------------------------
# Dynamic plugin discovery
# ---------------------------------------------------------------------------
def _discover_plugins():
    """Scan verify_plugins/ directory and auto-register new plugins.

    Each plugin module may export a `RULE_IDS` list:
        RULE_IDS = ["my-api-key", "my-secret-key"]

    If a module has `RULE_IDS`, it is auto-registered for each rule_id.
    Existing hard-coded entries are NOT overwritten.
    """
    pkg_dir = Path(__file__).resolve().parent
    for py_file in sorted(pkg_dir.glob("*.py")):
        name = py_file.stem
        if name.startswith("_"):
            continue  # skip __init__.py, _utils.py, etc.

        # Skip already-known modules (backward compat)
        already_registered = name in {
            "aws", "stripe", "hyundai", "generic", "fiat", "psa",
            "toyota", "renault", "nissan", "subaru", "vw", "github_pat",
        }
        if already_registered:
            continue

        try:
            mod = importlib.import_module(f".{name}", __package__)
        except Exception:
            continue  # ignore broken plugins

        rule_ids = getattr(mod, "RULE_IDS", None)
        if not rule_ids:
            continue  # module has no RULE_IDS, skip

        for rid in rule_ids:
            if rid not in REGISTRY:
                REGISTRY[rid] = mod


_discover_plugins()


def get_plugin(rule_id: str):
    """
    Get plugin module for a given rule_id.

    First tries exact match, then falls back to prefix matching.
    Returns None if no plugin found.
    """
    # First try exact match
    if rule_id in REGISTRY:
        return REGISTRY[rule_id]

    # Try prefix fuzzy match
    for key, plugin in REGISTRY.items():
        if key in rule_id:
            return plugin

    return None
