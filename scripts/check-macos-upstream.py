#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Validate the pinned standalone macOS app release and its immutable commit."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

import tomllib

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "macos" / "DefenseClawMac" / "upstream.lock.toml"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
STABLE_TAG_PATTERN = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def load_lock(path: Path) -> dict[str, str]:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"cannot read upstream lock {path}: {exc}") from exc
    required = ("repository", "tag", "commit", "source_version", "imported_at")
    missing = [key for key in required if not isinstance(raw.get(key), str) or not raw[key].strip()]
    if missing:
        raise ValueError(f"upstream lock is missing string fields: {', '.join(missing)}")
    lock = {key: str(raw[key]).strip() for key in required}
    if lock["repository"].count("/") != 1:
        raise ValueError("repository must have owner/name form")
    if not STABLE_TAG_PATTERN.fullmatch(lock["tag"]):
        raise ValueError("tag must be a stable semantic-version release tag")
    if lock["source_version"] != lock["tag"].removeprefix("v"):
        raise ValueError("source_version must match the stable release tag")
    if not SHA_PATTERN.fullmatch(lock["commit"]):
        raise ValueError("commit must be a lowercase 40-character SHA-1")
    return lock


def github_json(path: str) -> Any:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "defenseclaw-macos-upstream-check",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(f"https://api.github.com{path}", headers=headers)
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310 - fixed GitHub API host
            return json.load(response)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(f"GitHub API request failed for {path}: {exc}") from exc


def resolve_tag(repository: str, tag: str) -> str:
    ref = github_json(f"/repos/{repository}/git/ref/tags/{quote(tag, safe='')}")
    obj = ref.get("object") or {}
    seen: set[str] = set()
    while obj.get("type") == "tag":
        sha = str(obj.get("sha", ""))
        if not SHA_PATTERN.fullmatch(sha) or sha in seen:
            raise RuntimeError(f"invalid or cyclic annotated tag object for {tag}")
        seen.add(sha)
        tag_object = github_json(f"/repos/{repository}/git/tags/{sha}")
        obj = tag_object.get("object") or {}
    commit = str(obj.get("sha", ""))
    if obj.get("type") != "commit" or not SHA_PATTERN.fullmatch(commit):
        raise RuntimeError(f"tag {tag} does not resolve to an immutable commit")
    return commit


def current_release(repository: str) -> tuple[str, str]:
    releases = github_json(f"/repos/{repository}/releases?per_page=100")
    if not isinstance(releases, list):
        raise RuntimeError("GitHub releases response is not a list")
    candidates: list[tuple[tuple[int, int, int], str]] = []
    for release in releases:
        if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
            continue
        tag = str(release.get("tag_name", "")).strip()
        match = STABLE_TAG_PATTERN.fullmatch(tag)
        if match:
            candidates.append((tuple(int(part) for part in match.groups()), tag))
    if not candidates:
        raise RuntimeError("repository has no stable semantic-version release")
    _, tag = max(candidates)
    return tag, resolve_tag(repository, tag)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--offline", action="store_true", help="validate lock syntax without GitHub access")
    parser.add_argument("--json", action="store_true", help="emit the resolved state as JSON")
    parser.add_argument(
        "--print-latest-tag",
        action="store_true",
        help="print the highest stable semantic-version release tag",
    )
    args = parser.parse_args()

    try:
        lock = load_lock(args.lock)
    except ValueError as exc:
        print(f"macOS upstream check failed: {exc}", file=sys.stderr)
        return 1

    try:
        if args.print_latest_tag:
            if args.offline:
                parser.error("--print-latest-tag requires GitHub access")
            latest_tag, _ = current_release(lock["repository"])
            print(latest_tag)
            return 0
        if args.offline:
            result: dict[str, Any] = {"status": "valid-offline", "lock": lock}
        else:
            latest_tag, latest_commit = current_release(lock["repository"])
            result = {
                "status": "current" if (latest_tag, latest_commit) == (lock["tag"], lock["commit"]) else "stale",
                "repository": lock["repository"],
                "pinned_tag": lock["tag"],
                "pinned_commit": lock["commit"],
                "latest_tag": latest_tag,
                "latest_commit": latest_commit,
            }
    except RuntimeError as exc:
        print(f"macOS upstream check failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.offline:
        print(f"macOS upstream lock valid: {lock['tag']}@{lock['commit'][:12]} (offline)")
    elif result["status"] == "current":
        print(f"macOS app source is current: {lock['tag']}@{lock['commit'][:12]}")
    if result["status"] == "stale":
        print(
            f"macOS app pin is stale: pinned {lock['tag']}@{lock['commit'][:12]}, "
            f"latest stable is {result['latest_tag']}@{result['latest_commit'][:12]}. "
            f"Run scripts/update-macos-app.sh {result['latest_tag']}.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
