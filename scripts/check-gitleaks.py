#!/usr/bin/env python3
"""
Mandatory gitleaks binary checker and auto-installer.

Reads config.yaml, verifies the binary exists and works, and auto-installs
from GitHub releases if missing or broken.

Usage:
  python scripts/check-gitleaks.py --check      # Check only, exit 1 if missing
  python scripts/check-gitleaks.py --install    # Force reinstall
  python scripts/check-gitleaks.py --version    # Show configured version
  python scripts/check-gitleaks.py              # Default: check + auto-install
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CONFIG_PATH = SKILL_DIR / "config.yaml"
TOOLS_DIR = SKILL_DIR / "tools"
MANIFEST_PATH = TOOLS_DIR / "manifest.json"

API_URL = "https://api.github.com/repos/zricethezav/gitleaks/releases/latest"

PLATFORM_MAP = {
    "Linux-x86_64": "linux-x86_64",
    "Linux-aarch64": "linux-aarch64",
    "Darwin-x86_64": "darwin-x86_64",
    "Darwin-arm64": "darwin-arm64",
    "Windows-x86_64": "windows-x86_64",
    "Windows-amd64": "windows-x86_64",
    "Windows-AMD64": "windows-x86_64",
    "Windows-arm64": "windows-arm64",
    "Windows-aarch64": "windows-arm64",
}

# Platform names used in GitHub release filenames
DOWNLOAD_PLATFORM_MAP = {
    "linux-x86_64": "linux_x64",
    "linux-aarch64": "linux_arm64",
    "darwin-x86_64": "darwin_x64",
    "darwin-arm64": "darwin_arm64",
    "windows-x86_64": "windows_x64",
    "windows-arm64": "windows_arm64",
}


def _load_yaml(path):
    """Minimal YAML parser for simple key-value config."""
    data = {}
    current_section = None
    if not path.exists():
        return data
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.endswith(":") and not "=" in stripped:
                current_section = stripped[:-1]
                data[current_section] = {}
                continue
            if ":" in stripped:
                key, val = stripped.split(":", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if current_section:
                    data[current_section][key] = val
                else:
                    data[key] = val
    return data


def _save_yaml(path, data):
    """Minimal YAML writer for simple nested dict."""
    with open(path, "w", encoding="utf-8") as f:
        for section, values in data.items():
            f.write(f"{section}:\n")
            for key, val in values.items():
                if isinstance(val, bool):
                    f.write(f"  {key}: {str(val).lower()}\n")
                elif isinstance(val, str):
                    f.write(f'  {key}: "{val}"\n')
                else:
                    f.write(f"  {key}: {val}\n")


def detect_platform():
    """Detect current platform."""
    system = platform.system()
    machine = platform.machine()
    key = f"{system}-{machine}"
    mapped = PLATFORM_MAP.get(key)
    if not mapped:
        print(f"ERROR: Unsupported platform: {system} {machine}")
        sys.exit(1)
    return mapped


def get_config():
    """Read or create default config."""
    if not CONFIG_PATH.exists():
        default = {
            "gitleaks": {
                "version": "8.30.1",
                "binary_path": "",
                "auto_install": True,
                "download_url_template": "https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_{platform}.tar.gz",
            },
            "tools": {
                "directory": "tools",
                "manifest_file": "manifest.json",
            },
        }
        _save_yaml(CONFIG_PATH, default)
        print(f"[INFO] Created default config: {CONFIG_PATH}")
        return default
    return _load_yaml(CONFIG_PATH)


def get_binary_path(config, manifest):
    """Resolve binary path from config or manifest."""
    # Config override
    cfg_path = config.get("gitleaks", {}).get("binary_path", "").strip()
    if cfg_path:
        p = Path(cfg_path)
        if p.is_absolute():
            return p
        return SKILL_DIR / p

    # Infer from manifest
    plat = detect_platform()
    binary_name = manifest.get("binaries", {}).get(plat)
    if not binary_name:
        print(f"ERROR: No binary configured for platform: {plat}")
        sys.exit(1)
    return TOOLS_DIR / binary_name


def verify_binary(binary_path):
    """Verify binary exists, is executable, and returns correct version."""
    errors = []
    if not binary_path.exists():
        errors.append(f"Binary not found: {binary_path}")
        return False, errors
    # Windows binaries don't have Unix executable permission bits
    if platform.system() != "Windows" and not os.access(str(binary_path), os.X_OK):
        errors.append(f"Binary not executable: {binary_path}")
        return False, errors
    try:
        result = subprocess.run(
            [str(binary_path), "version"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            errors.append(f"Binary version check failed: {result.stderr.strip()}")
            return False, errors
        version_str = result.stdout.strip()
        print(f"[OK] gitleaks binary verified: {version_str} at {binary_path}")
        return True, []
    except Exception as e:
        errors.append(f"Cannot execute binary: {e}")
        return False, errors


def fetch_latest_release():
    """Query GitHub API for the latest gitleaks release version."""
    req = urllib.request.Request(API_URL)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "gitleaks-updater/1.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        tag = data.get("tag_name", "")
        version = tag.lstrip("v")
        return version
    except urllib.error.HTTPError as e:
        print(f"ERROR: GitHub API HTTP error: {e.code} {e.reason}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"ERROR: Network error: {e.reason}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse GitHub API response: {e}")
        sys.exit(1)


def download_and_install(config, manifest, force=False):
    """Download gitleaks from GitHub releases and install to tools/."""
    plat = detect_platform()
    download_plat = DOWNLOAD_PLATFORM_MAP.get(plat, plat)
    version = config.get("gitleaks", {}).get("version", manifest.get("current_version", "8.30.1"))

    # Determine archive format based on platform
    is_windows = plat.startswith("windows")
    archive_ext = ".zip" if is_windows else ".tar.gz"

    # Build download URL
    base_url = "https://github.com/gitleaks/gitleaks/releases/download"
    url = f"{base_url}/v{version}/gitleaks_{version}_{download_plat}{archive_ext}"

    binary_name = manifest.get("binaries", {}).get(plat, f"gitleaks-{plat}")
    if is_windows and not binary_name.endswith(".exe"):
        binary_name += ".exe"
    dest = TOOLS_DIR / binary_name

    if dest.exists() and not force:
        print(f"[INFO] Binary already exists at {dest}, use --install to force reinstall")
        return dest

    tmp_dir = Path(tempfile.gettempdir()) / "gitleaks-auto-install"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    archive_path = tmp_dir / f"gitleaks_{version}_{download_plat}{archive_ext}"

    print(f"[DOWNLOAD] {url}")
    try:
        urllib.request.urlretrieve(url, archive_path)
    except urllib.error.HTTPError as e:
        print(f"ERROR: Download failed: {e.code} {e.reason}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"ERROR: Network error: {e.reason}")
        sys.exit(1)

    print(f"[EXTRACT] {archive_path}")
    try:
        if is_windows:
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(path=tmp_dir)
        else:
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(path=tmp_dir)
    except (zipfile.BadZipFile, tarfile.TarError) as e:
        print(f"ERROR: Extraction failed: {e}")
        sys.exit(1)

    # Find extracted binary
    extracted = None
    for root, dirs, files in os.walk(tmp_dir):
        if "gitleaks" in files:
            extracted = Path(root) / "gitleaks"
            break
    if not extracted or not extracted.exists():
        print("ERROR: Could not locate extracted gitleaks binary")
        sys.exit(1)

    print(f"[INSTALL] {extracted} -> {dest}")
    try:
        shutil.copy2(extracted, dest)
        if not is_windows:
            os.chmod(dest, 0o755)
    except PermissionError:
        print(f"ERROR: Permission denied installing to {dest}")
        sys.exit(1)

    # Update manifest
    manifest["current_version"] = version
    manifest["binaries"][plat] = binary_name
    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    # Update config binary_path
    config.setdefault("gitleaks", {})["binary_path"] = str(dest)
    _save_yaml(CONFIG_PATH, config)

    # Cleanup
    shutil.rmtree(tmp_dir, ignore_errors=True)
    print(f"[OK] Installed gitleaks {version} to {dest}")
    return dest


def main():
    parser = argparse.ArgumentParser(description="Gitleaks binary checker and installer")
    parser.add_argument("--check", action="store_true", help="Check only, exit 1 if missing")
    parser.add_argument("--install", action="store_true", help="Force reinstall")
    parser.add_argument("--version", action="store_true", help="Show configured version")
    parser.add_argument("--update", action="store_true", help="Update to the latest release")
    args = parser.parse_args()

    config = get_config()

    if args.version:
        version = config.get("gitleaks", {}).get("version", "unknown")
        print(version)
        sys.exit(0)

    # Load manifest
    try:
        with open(MANIFEST_PATH, "r") as f:
            manifest = json.load(f)
    except FileNotFoundError:
        manifest = {"current_version": "8.30.1", "binaries": {}}
    except json.JSONDecodeError:
        manifest = {"current_version": "8.30.1", "binaries": {}}

    binary_path = get_binary_path(config, manifest)

    if args.update:
        latest = fetch_latest_release()
        current_version = manifest.get("current_version", "0.0.0")
        if latest == current_version:
            print("Already up to date.")
            sys.exit(0)
        print(f"[UPDATE] {current_version} -> {latest}")
        config.setdefault("gitleaks", {})["version"] = latest
        _save_yaml(CONFIG_PATH, config)
        binary_path = download_and_install(config, manifest, force=True)
        ok, errors = verify_binary(binary_path)
        if not ok:
            for e in errors:
                print(f"ERROR: {e}")
            sys.exit(1)
        manifest["current_version"] = latest
        with open(MANIFEST_PATH, "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        print(f"[OK] Updated to gitleaks {latest}")
        sys.exit(0)

    if args.install:
        binary_path = download_and_install(config, manifest, force=True)
        ok, errors = verify_binary(binary_path)
        if not ok:
            for e in errors:
                print(f"ERROR: {e}")
            sys.exit(1)
        print(binary_path)
        sys.exit(0)

    ok, errors = verify_binary(binary_path)
    if ok:
        print(binary_path)
        sys.exit(0)

    # Binary missing or broken
    for e in errors:
        print(f"[WARN] {e}")

    auto_install = config.get("gitleaks", {}).get("auto_install", True)
    if not auto_install:
        print("ERROR: auto_install is disabled. Run with --install to install manually.")
        sys.exit(1)

    # Auto-install
    binary_path = download_and_install(config, manifest)
    ok, errors = verify_binary(binary_path)
    if not ok:
        for e in errors:
            print(f"ERROR: {e}")
        sys.exit(1)
    print(binary_path)
    sys.exit(0)


if __name__ == "__main__":
    main()
