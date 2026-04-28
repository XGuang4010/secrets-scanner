"""Tests for scripts/decode_utils.py"""

import json
import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from decode_utils import (
    analyze_secret,
    calculate_entropy,
    decode_base64,
    decode_base64url,
    decode_hex,
    decode_jwt,
    is_base64,
    is_truncated_jwt,
    is_valid_jwt,
    url_decode,
)


class TestBase64(unittest.TestCase):
    def test_decode_standard(self):
        self.assertEqual(decode_base64("SGVsbG8gV29ybGQ="), "Hello World")

    def test_decode_invalid(self):
        self.assertIsNone(decode_base64("!!!not-base64!!!"))

    def test_decode_urlsafe(self):
        self.assertEqual(decode_base64url("SGVsbG8gV29ybGQ"), "Hello World")


class TestJWT(unittest.TestCase):
    def test_decode_valid_jwt(self):
        # header: {"alg":"HS256","typ":"JWT"}
        # payload: {"sub":"123"}
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.mqk_zyL5O5NpWQ8"
        result = decode_jwt(token)
        self.assertIsNotNone(result)
        self.assertEqual(result["header"]["alg"], "HS256")
        self.assertEqual(result["payload"]["sub"], "1234567890")

    def test_invalid_jwt_not_three_parts(self):
        self.assertIsNone(decode_jwt("only.two"))
        self.assertIsNone(decode_jwt("onlyone"))

    def test_is_valid_jwt_true(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.mqk_zyL5O5NpWQ8"
        self.assertTrue(is_valid_jwt(token))

    def test_is_valid_jwt_false(self):
        self.assertFalse(is_valid_jwt("not.a.jwt"))

    def test_is_truncated_jwt(self):
        self.assertTrue(is_truncated_jwt("eyJhbGciOiJIUzI1NiJ9..."))
        self.assertTrue(is_truncated_jwt("eyJhbGciOiJIUzI1NiJ9.eyJz.d"))
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.mqk_zyL5O5NpWQ8"
        self.assertFalse(is_truncated_jwt(token))


class TestHex(unittest.TestCase):
    def test_decode_hex(self):
        self.assertEqual(decode_hex("48656c6c6f"), "Hello")

    def test_decode_hex_with_prefix(self):
        self.assertEqual(decode_hex("0x48656c6c6f"), "Hello")

    def test_decode_hex_odd_length(self):
        self.assertIsNone(decode_hex("48656"))


class TestURLEncode(unittest.TestCase):
    def test_url_decode(self):
        self.assertEqual(url_decode("Hello%20World"), "Hello World")


class TestEntropy(unittest.TestCase):
    def test_empty_string(self):
        ent, max_ent, norm = calculate_entropy("")
        self.assertEqual(ent, 0.0)

    def test_uniform_distribution(self):
        # "abcd" has uniform distribution -> high normalized entropy
        ent, max_ent, norm = calculate_entropy("abcd")
        self.assertGreater(norm, 0.9)

    def test_repeated_char(self):
        ent, max_ent, norm = calculate_entropy("aaaaaaaa")
        self.assertEqual(ent, 0.0)


class TestIsBase64(unittest.TestCase):
    def test_valid_base64(self):
        self.assertTrue(is_base64("SGVsbG8gV29ybGQ="))

    def test_invalid_characters(self):
        self.assertFalse(is_base64("Hello World!"))

    def test_too_short(self):
        self.assertFalse(is_base64("ab"))


class TestAnalyzeSecret(unittest.TestCase):
    def test_jwt_secret(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.mqk_zyL5O5NpWQ8"
        result = analyze_secret(token)
        self.assertTrue(result["is_jwt"])
        self.assertIsNotNone(result["decoded_jwt"])

    def test_base64_secret(self):
        result = analyze_secret("SGVsbG8gV29ybGQ=")
        self.assertTrue(result["is_base64"])

    def test_hex_secret(self):
        result = analyze_secret("48656c6c6f")
        self.assertTrue(result["is_hex"])

    def test_entropy_present(self):
        result = analyze_secret("random_secret_value_123")
        self.assertIn("bits", result["entropy"])
        self.assertIn("normalized", result["entropy"])


class TestCLI(unittest.TestCase):
    def test_jwt_command_output(self):
        import subprocess

        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.mqk_zyL5O5NpWQ8"
        result = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "decode_utils.py"), "jwt", token],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["header"]["alg"], "HS256")

    def test_analyze_command_output(self):
        import subprocess

        result = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "decode_utils.py"), "analyze", "SGVsbG8="],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["length"], 8)


if __name__ == "__main__":
    unittest.main()
