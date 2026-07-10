#!/usr/bin/env python3
"""Download the latest Hayabusa release for this platform and extract it to ./hayabusa/."""
import json
import platform
import shutil
import stat
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

API_URL = "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
DEST_DIR = Path(__file__).parent / "hayabusa"


def platform_tag():
    system = platform.system()
    machine = platform.machine().lower()

    if system == "Windows":
        if machine in ("amd64", "x86_64"):
            return "win-x64"
        if machine in ("arm64", "aarch64"):
            return "win-aarch64"
        return "win-x86"
    if system == "Linux":
        if machine in ("aarch64", "arm64"):
            return "lin-aarch64-gnu"
        return "lin-x64-gnu"
    if system == "Darwin":
        if machine in ("arm64", "aarch64"):
            return "mac-aarch64"
        return "mac-x64"

    raise RuntimeError(f"Unsupported platform: {system} {machine}")


def fetch_release():
    request = urllib.request.Request(
        API_URL, headers={"User-Agent": "hayabusa-downloader"}
    )
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def find_asset(release, tag):
    for asset in release["assets"]:
        name = asset["name"]
        if tag in name and "live-response" not in name and name.endswith(".zip"):
            return asset
    raise RuntimeError(f"No release asset found matching platform tag '{tag}'")


def download_and_extract(asset, version):
    print(f"Downloading {asset['name']} ({version})...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        zip_path = Path(tmp_dir) / asset["name"]
        request = urllib.request.Request(
            asset["browser_download_url"], headers={"User-Agent": "hayabusa-downloader"}
        )
        with urllib.request.urlopen(request) as response, open(zip_path, "wb") as f:
            shutil.copyfileobj(response, f)

        if DEST_DIR.exists():
            shutil.rmtree(DEST_DIR)
        DEST_DIR.mkdir(parents=True)

        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(DEST_DIR)

    if platform.system() != "Windows":
        for path in DEST_DIR.rglob("hayabusa*"):
            if path.is_file():
                path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    print(f"Extracted to {DEST_DIR}")


if __name__ == "__main__":
    try:
        tag = platform_tag()
        release = fetch_release()
        asset = find_asset(release, tag)
        download_and_extract(asset, release["tag_name"])
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
