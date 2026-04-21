#!/usr/bin/env python3
"""Update gitleaks binary to the latest release."""

import json
import os
import platform
import shutil
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
TOOLS_DIR = SKILL_DIR / "tools"
MANIFEST_PATH = TOOLS_DIR / "manifest.json"

API_URL = "https://api.github.com/repos/zricethezav/gitleaks/releases/latest"

PLATFORM_MAP = {
    "linux-x86_64": "linux_x64",
    "linux-aarch64": "linux_arm64",
    "darwin-x86_64": "darwin_x64",
    "darwin-arm64": "darwin_arm64",
}


def get_local_platform():
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "linux":
        if machine in ("x86_64", "amd64"):
            return "linux-x86_64"
        elif machine in ("aarch64", "arm64"):
            return "linux-aarch64"
    elif system == "darwin":
        if machine in ("x86_64", "amd64"):
            return "darwin-x86_64"
        elif machine in ("aarch64", "arm64"):
            return "darwin-arm64"
    return None


def read_manifest():
    print(f"[1/7] Reading manifest: {MANIFEST_PATH}")
    try:
        with open(MANIFEST_PATH, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Manifest not found at {MANIFEST_PATH}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in manifest: {e}")
        sys.exit(1)


def fetch_latest_release():
    print(f"[2/7] Querying GitHub API: {API_URL}")
    req = urllib.request.Request(API_URL)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "gitleaks-updater/1.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        tag = data.get("tag_name", "")
        version = tag.lstrip("v")
        assets = data.get("assets", [])
        return version, assets
    except urllib.error.HTTPError as e:
        print(f"ERROR: GitHub API HTTP error: {e.code} {e.reason}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"ERROR: Network error: {e.reason}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse GitHub API response: {e}")
        sys.exit(1)


def find_asset(assets, platform_key, version):
    mapped = PLATFORM_MAP.get(platform_key)
    if not mapped:
        print(f"ERROR: Unsupported platform: {platform_key}")
        sys.exit(1)
    pattern = f"gitleaks_{version}_{mapped}.tar.gz"
    for asset in assets:
        name = asset.get("name", "")
        if name == pattern:
            return asset
    print(f"ERROR: No asset found matching pattern '{pattern}'")
    sys.exit(1)


def download_asset(asset, dest_dir):
    url = asset.get("browser_download_url")
    name = asset.get("name", "download.tar.gz")
    if not url:
        print("ERROR: Asset missing download URL")
        sys.exit(1)
    dest = dest_dir / name
    print(f"[3/7] Downloading {name} ...")
    try:
        urllib.request.urlretrieve(url, dest)
    except urllib.error.HTTPError as e:
        print(f"ERROR: Download failed: {e.code} {e.reason}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"ERROR: Download failed: {e.reason}")
        sys.exit(1)
    except PermissionError:
        print(f"ERROR: Permission denied writing to {dest}")
        sys.exit(1)
    print(f"        -> {dest}")
    return dest


def extract_binary(archive_path, extract_dir):
    print(f"[4/7] Extracting {archive_path.name} ...")
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getmembers()
            gitleaks_members = [
                m
                for m in members
                if m.name == "gitleaks" or m.name.endswith("/gitleaks")
            ]
            if not gitleaks_members:
                print("ERROR: 'gitleaks' binary not found inside archive")
                sys.exit(1)
            tar.extractall(path=extract_dir)
    except tarfile.TarError as e:
        print(f"ERROR: Failed to extract archive: {e}")
        sys.exit(1)
    # Locate extracted binary
    for root, dirs, files in os.walk(extract_dir):
        if "gitleaks" in files:
            return Path(root) / "gitleaks"
    print("ERROR: Could not locate extracted gitleaks binary")
    sys.exit(1)


def install_binary(src, dest):
    print(f"[5/7] Installing binary to {dest} ...")
    try:
        shutil.copy2(src, dest)
        os.chmod(dest, 0o755)
    except PermissionError:
        print(f"ERROR: Permission denied installing to {dest}")
        sys.exit(1)
    print(f"        -> {dest}")


def verify_binary(binary_path):
    print(f"[6/7] Verifying binary: {binary_path} version")
    import subprocess

    try:
        result = subprocess.run(
            [str(binary_path), "version"], capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            print(f"ERROR: Binary verification failed: {result.stderr.strip()}")
            sys.exit(1)
        print(f"        Output: {result.stdout.strip()}")
    except FileNotFoundError:
        print(f"ERROR: Binary not found after install: {binary_path}")
        sys.exit(1)
    except PermissionError:
        print(f"ERROR: Permission denied executing {binary_path}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("ERROR: Binary verification timed out")
        sys.exit(1)


def update_manifest(new_version):
    print(f"[7/7] Updating manifest version to {new_version} ...")
    try:
        with open(MANIFEST_PATH, "r") as f:
            manifest = json.load(f)
        manifest["current_version"] = new_version
        with open(MANIFEST_PATH, "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        print("        Done.")
    except Exception as e:
        print(f"ERROR: Failed to update manifest: {e}")
        sys.exit(1)


def main():
    local_platform = get_local_platform()
    if not local_platform:
        print(f"ERROR: Unsupported platform: {platform.system()} {platform.machine()}")
        sys.exit(1)
    print(f"Detected platform: {local_platform}")

    manifest = read_manifest()
    current_version = manifest.get("current_version", "0.0.0")
    print(f"Current version: {current_version}")

    latest_version, assets = fetch_latest_release()
    print(f"Latest version: {latest_version}")

    if latest_version == current_version:
        print("Already up to date.")
        sys.exit(0)

    asset = find_asset(assets, local_platform, latest_version)
    tmp_dir = Path("/tmp") / "gitleaks-update"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    archive = download_asset(asset, tmp_dir)
    extracted = extract_binary(archive, tmp_dir)

    binary_name = manifest["binaries"].get(local_platform, "gitleaks")
    dest = TOOLS_DIR / binary_name
    install_binary(extracted, dest)
    verify_binary(dest)
    update_manifest(latest_version)

    # Cleanup
    shutil.rmtree(tmp_dir, ignore_errors=True)
    print("\nUpdate complete!")


if __name__ == "__main__":
    main()
