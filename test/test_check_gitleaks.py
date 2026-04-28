"""Tests for scripts/check-gitleaks.py"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import importlib.util

def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

check_gitleaks = _load_module("check_gitleaks", SCRIPT_DIR / "check-gitleaks.py")


class TestDetectPlatform(unittest.TestCase):
    def test_linux_x86_64(self):
        with mock.patch("platform.system", return_value="Linux"), \
             mock.patch("platform.machine", return_value="x86_64"):
            self.assertEqual(check_gitleaks.detect_platform(), "linux-x86_64")

    def test_windows_arm64(self):
        with mock.patch("platform.system", return_value="Windows"), \
             mock.patch("platform.machine", return_value="arm64"):
            self.assertEqual(check_gitleaks.detect_platform(), "windows-arm64")

    def test_unsupported(self):
        with mock.patch("platform.system", return_value="Solaris"), \
             mock.patch("platform.machine", return_value="sparc"):
            with self.assertRaises(SystemExit):
                check_gitleaks.detect_platform()


class TestLoadYaml(unittest.TestCase):
    def test_simple_config(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write('gitleaks:\n  version: "8.30.1"\n  auto_install: true\n')
            temp_path = f.name

        try:
            result = check_gitleaks._load_yaml(Path(temp_path))
            self.assertEqual(result["gitleaks"]["version"], "8.30.1")
            self.assertEqual(result["gitleaks"]["auto_install"], "true")
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_comments_and_empty_lines(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write('# Comment\n\ngitleaks:\n  version: "8.30.1"\n')
            temp_path = f.name

        try:
            result = check_gitleaks._load_yaml(Path(temp_path))
            self.assertEqual(result["gitleaks"]["version"], "8.30.1")
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_missing_file(self):
        result = check_gitleaks._load_yaml(Path("/nonexistent/config.yaml"))
        self.assertEqual(result, {})


class TestSaveYaml(unittest.TestCase):
    def test_roundtrip(self):
        data = {
            "gitleaks": {
                "version": "8.30.1",
                "auto_install": True,
                "binary_path": "",
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            temp_path = f.name

        try:
            check_gitleaks._save_yaml(Path(temp_path), data)
            content = Path(temp_path).read_text(encoding="utf-8")
            self.assertIn('version: "8.30.1"', content)
            self.assertIn("auto_install: true", content)
            self.assertIn('binary_path: ""', content)
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestGetBinaryPath(unittest.TestCase):
    def test_from_config_absolute(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = Path(tmpdir) / "gitleaks.exe"
            binary.write_text("fake", encoding="utf-8")
            config = {"gitleaks": {"binary_path": str(binary)}}
            manifest = {"binaries": {}}
            result = check_gitleaks.get_binary_path(config, manifest)
            self.assertEqual(result, binary)

    def test_from_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.object(check_gitleaks, "TOOLS_DIR", Path(tmpdir)), \
                 mock.patch("check_gitleaks.detect_platform", return_value="linux-x86_64"):
                config = {"gitleaks": {"binary_path": ""}}
                manifest = {"binaries": {"linux-x86_64": "gitleaks-linux-x64"}}
                result = check_gitleaks.get_binary_path(config, manifest)
                self.assertEqual(result, Path(tmpdir) / "gitleaks-linux-x64")

    def test_no_binary_configured(self):
        with mock.patch("check_gitleaks.detect_platform", return_value="linux-x86_64"):
            config = {"gitleaks": {"binary_path": ""}}
            manifest = {"binaries": {}}
            with self.assertRaises(SystemExit):
                check_gitleaks.get_binary_path(config, manifest)


class TestVerifyBinary(unittest.TestCase):
    def test_binary_not_found(self):
        ok, errors = check_gitleaks.verify_binary(Path("/nonexistent/gitleaks"))
        self.assertFalse(ok)
        self.assertTrue(any("not found" in e for e in errors))

    def test_binary_exists_but_fails_version(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_binary = Path(tmpdir) / "fake_gitleaks"
            fake_binary.write_text("#!/bin/sh\nexit 1", encoding="utf-8")
            if sys.platform != "win32":
                import os
                os.chmod(fake_binary, 0o755)

            with mock.patch("subprocess.run") as mock_run:
                mock_run.return_value = mock.MagicMock(returncode=1, stderr="error")
                ok, errors = check_gitleaks.verify_binary(fake_binary)
                self.assertFalse(ok)


class TestGetConfig(unittest.TestCase):
    def test_creates_default_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original_path = check_gitleaks.CONFIG_PATH
            try:
                check_gitleaks.CONFIG_PATH = Path(tmpdir) / "config.yaml"
                config = check_gitleaks.get_config()
                self.assertEqual(config["gitleaks"]["version"], "8.30.1")
                self.assertTrue(check_gitleaks.CONFIG_PATH.exists())
            finally:
                check_gitleaks.CONFIG_PATH = original_path

    def test_reads_existing_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original_path = check_gitleaks.CONFIG_PATH
            try:
                check_gitleaks.CONFIG_PATH = Path(tmpdir) / "config.yaml"
                check_gitleaks.CONFIG_PATH.write_text(
                    'gitleaks:\n  version: "9.0.0"\n', encoding="utf-8"
                )
                config = check_gitleaks.get_config()
                self.assertEqual(config["gitleaks"]["version"], "9.0.0")
            finally:
                check_gitleaks.CONFIG_PATH = original_path


class TestDownloadPlatformMap(unittest.TestCase):
    def test_all_platforms_mapped(self):
        for platform in check_gitleaks.PLATFORM_MAP.values():
            self.assertIn(platform, check_gitleaks.DOWNLOAD_PLATFORM_MAP)


if __name__ == "__main__":
    unittest.main()
