"""Publish the completed CI package set without reusing an existing version."""

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib


def main(assets):
    with open("Cargo.toml", "rb") as manifest:
        version = tomllib.load(manifest)["workspace"]["package"]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise SystemExit("Release version must be major.minor.patch")
    if not assets or any(not Path(asset).is_file() for asset in assets):
        raise SystemExit("Release assets are missing")
    if len({Path(asset).name for asset in assets}) != len(assets):
        raise SystemExit("Release asset names must be unique")

    commit = os.environ["GITHUB_SHA"]
    raw_commit = subprocess.check_output(["git", "cat-file", "commit", commit], text=True)
    headers = raw_commit.split("\n\n", 1)[0]
    changes = re.findall(r"^change-id ([k-z]{32})$", headers, re.MULTILINE)
    if len(changes) != 1:
        raise SystemExit("Release commit must contain one jj change-id header")

    repo = os.environ["GH_REPO"]
    tag = f"v{version}"
    tags = subprocess.check_output(
        ["gh", "api", "--paginate", f"repos/{repo}/releases", "--jq", ".[].tag_name"],
        text=True,
    ).splitlines()
    if tag in tags:
        raise SystemExit(f"Release {tag} already exists")

    with tempfile.TemporaryDirectory() as directory:
        notes = Path(directory) / "notes.md"
        notes.write_text(
            f"Version: {version}\njj change: {changes[0]}\nGit commit: {commit}\n",
            encoding="utf-8",
        )
        # Reserve the tag atomically; an existing tag must never be reused or moved.
        subprocess.check_call([
            "gh", "api", "--method", "POST", f"repos/{repo}/git/refs",
            "-f", f"ref=refs/tags/{tag}", "-f", f"sha={commit}", "--silent",
        ])
        subprocess.check_call([
            "gh", "release", "create", tag, *assets, "--verify-tag",
            "--target", commit, "--title", tag, "--notes-file", str(notes),
        ])


if __name__ == "__main__":
    main(sys.argv[1:])
