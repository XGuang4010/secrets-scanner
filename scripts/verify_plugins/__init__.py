"""Plugin registry for secret verification."""

from . import aws, stripe, hyundai, generic

REGISTRY = {
    "aws-access-key": aws,
    "aws-secret-access-key": aws,
    "generic-api-key": generic,
    "private-key": generic,
    "jwt": generic,
}


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
