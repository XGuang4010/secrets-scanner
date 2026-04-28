"""Tests for scripts/rule-validator.py"""

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import importlib.util

def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

rule_validator = _load_module("rule_validator", SCRIPT_DIR / "rule-validator.py")

from rule_validator import (
    extract_all_regexes,
    extract_regexes_from_array,
    promote_rules,
    remove_orphaned_rules,
    validate_regexes,
)


class TestValidateRegexes(unittest.TestCase):
    def test_valid_regex(self):
        rules = [
            {
                "id": "test-valid",
                "allowlist": {"regexes": [r"test_[a-z0-9]+"]},
            }
        ]
        errors = validate_regexes(rules)
        self.assertEqual(len(errors), 0)

    def test_invalid_regex(self):
        rules = [
            {
                "id": "test-invalid",
                "allowlist": {"regexes": [r"[invalid("]},
            }
        ]
        errors = validate_regexes(rules)
        self.assertEqual(len(errors), 1)
        self.assertIn("test-invalid", errors[0])

    def test_no_regexes(self):
        rules = [{"id": "test-none", "allowlist": {}}]
        errors = validate_regexes(rules)
        self.assertEqual(len(errors), 0)


class TestExtractRegexesFromArray(unittest.TestCase):
    def test_basic_extraction(self):
        text = "regexes = ['''test_pattern''', '''another_pattern''']"
        result = extract_regexes_from_array(text)
        self.assertEqual(result, ["test_pattern", "another_pattern"])

    def test_empty_array(self):
        text = "regexes = []"
        result = extract_regexes_from_array(text)
        self.assertEqual(result, [])


class TestExtractAllRegexes(unittest.TestCase):
    def test_extract_from_rule(self):
        rule = {"allowlist": {"regexes": [r"pattern1", r"pattern2"]}}
        result = extract_all_regexes(rule)
        self.assertEqual(result, ["pattern1", "pattern2"])

    def test_no_allowlist(self):
        rule = {}
        result = extract_all_regexes(rule)
        self.assertEqual(result, [])


class TestPromoteRules(unittest.TestCase):
    def test_promote_after_threshold(self):
        rules = [
            {
                "id": "rule-1",
                "status": "experimental",
                "validation_count": 2,
            }
        ]
        effectiveness = {"rule-1": 1}
        promoted = promote_rules(rules, effectiveness)
        self.assertEqual(promoted, ["rule-1"])
        self.assertEqual(rules[0]["status"], "confirmed")
        self.assertIn("validated_at", rules[0])

    def test_not_promoted_below_threshold(self):
        rules = [
            {
                "id": "rule-1",
                "status": "experimental",
                "validation_count": 1,
            }
        ]
        effectiveness = {"rule-1": 1}
        promoted = promote_rules(rules, effectiveness)
        self.assertEqual(promoted, [])
        self.assertEqual(rules[0]["status"], "experimental")
        self.assertEqual(rules[0]["validation_count"], 2)

    def test_no_effectiveness_no_promote(self):
        rules = [
            {
                "id": "rule-1",
                "status": "experimental",
                "validation_count": 0,
            }
        ]
        effectiveness = {}
        promoted = promote_rules(rules, effectiveness)
        self.assertEqual(promoted, [])
        self.assertEqual(rules[0]["validation_count"], 0)

    def test_confirmed_not_promoted(self):
        rules = [
            {
                "id": "rule-1",
                "status": "confirmed",
                "validation_count": 5,
            }
        ]
        effectiveness = {"rule-1": 1}
        promoted = promote_rules(rules, effectiveness)
        self.assertEqual(promoted, [])


class TestRemoveOrphanedRules(unittest.TestCase):
    def test_remove_old_experimental_with_zero_validations(self):
        old_date = (datetime.now() - timedelta(days=40)).strftime("%Y-%m-%d")
        rules = [
            {
                "id": "old-rule",
                "status": "experimental",
                "validation_count": 0,
                "created": old_date,
            }
        ]
        kept, orphaned = remove_orphaned_rules(rules)
        self.assertEqual(len(orphaned), 1)
        self.assertEqual(orphaned[0], "old-rule")
        self.assertEqual(len(kept), 0)

    def test_keep_recent_experimental(self):
        recent_date = (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%d")
        rules = [
            {
                "id": "new-rule",
                "status": "experimental",
                "validation_count": 0,
                "created": recent_date,
            }
        ]
        kept, orphaned = remove_orphaned_rules(rules)
        self.assertEqual(len(orphaned), 0)
        self.assertEqual(len(kept), 1)

    def test_keep_confirmed_regardless_of_age(self):
        old_date = (datetime.now() - timedelta(days=40)).strftime("%Y-%m-%d")
        rules = [
            {
                "id": "confirmed-rule",
                "status": "confirmed",
                "validation_count": 0,
                "created": old_date,
            }
        ]
        kept, orphaned = remove_orphaned_rules(rules)
        self.assertEqual(len(orphaned), 0)
        self.assertEqual(len(kept), 1)

    def test_keep_experimental_with_validations(self):
        old_date = (datetime.now() - timedelta(days=40)).strftime("%Y-%m-%d")
        rules = [
            {
                "id": "validated-rule",
                "status": "experimental",
                "validation_count": 1,
                "created": old_date,
            }
        ]
        kept, orphaned = remove_orphaned_rules(rules)
        self.assertEqual(len(orphaned), 0)
        self.assertEqual(len(kept), 1)


class TestCheckRuleEffectiveness(unittest.TestCase):
    def test_no_learning_dir(self):
        import rule_validator as rv

        original_dir = rv.LEARNING_DIR
        with tempfile.TemporaryDirectory() as tmpdir:
            rv.LEARNING_DIR = Path(tmpdir) / "nonexistent"
            rules = [{"id": "rule-1", "status": "experimental", "allowlist": {"regexes": [r"test"]}}]
            result = rv.check_rule_effectiveness(rules)
            self.assertEqual(result, {})
            rv.LEARNING_DIR = original_dir

    def test_learning_with_false_positives(self):
        import rule_validator as rv

        original_dir = rv.LEARNING_DIR
        with tempfile.TemporaryDirectory() as tmpdir:
            rv.LEARNING_DIR = Path(tmpdir)
            # Create a false positives file in new format
            fp_data = {
                "false_positives": [
                    {"secret": "test_value_123", "match": "api_key = 'test_value_123'"}
                ]
            }
            fp_file = rv.LEARNING_DIR / "scan-001-false-positives.json"
            fp_file.write_text(json.dumps(fp_data), encoding="utf-8")

            rules = [
                {
                    "id": "rule-1",
                    "status": "experimental",
                    "allowlist": {"regexes": [r"test_value"]},
                }
            ]
            result = rv.check_rule_effectiveness(rules)
            self.assertEqual(result.get("rule-1"), 1)
            rv.LEARNING_DIR = original_dir


if __name__ == "__main__":
    unittest.main()
