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

"""Download the exact immutable proof set used to repair the stable channel."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

EXPECTED_REPOSITORY = "cisco-ai-defense/defenseclaw"
ASSET_DOWNLOAD_TIMEOUT_SECONDS = 60
MAX_PROOF_BYTES = {
    "checksums.txt": 4 * 1024 * 1024,
    "checksums.txt.bundle": 16 * 1024 * 1024,
    "checksums.txt.pem": 64 * 1024,
    "checksums.txt.sig": 64 * 1024,
    "release-provenance.json": 1024 * 1024,
    "release-source-map.json": 1024 * 1024,
    "upgrade-manifest.json": 1024 * 1024,
}
REQUIRED_PROOF_ASSETS = tuple(MAX_PROOF_BYTES)
Runner = Callable[..., subprocess.CompletedProcess[bytes]]


class ReleaseCustodyError(RuntimeError):
    """The immutable release proof could not be downloaded safely."""


def _load_asset_ids(release_json: Path) -> dict[str, int]:
    try:
        release = json.loads(release_json.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseCustodyError(f"could not read published release metadata: {exc}") from exc
    assets = release.get("assets") if isinstance(release, dict) else None
    if not isinstance(assets, list) or any(not isinstance(asset, dict) for asset in assets):
        raise ReleaseCustodyError("published release has an invalid asset inventory")

    required = set(REQUIRED_PROOF_ASSETS)
    asset_ids: dict[str, int] = {}
    for asset in assets:
        name = asset.get("name")
        if name not in required:
            continue
        identifier = asset.get("id")
        if name in asset_ids or not isinstance(identifier, int) or isinstance(identifier, bool) or identifier <= 0:
            raise ReleaseCustodyError(f"published release has ambiguous custody for {name!r}")
        asset_ids[name] = identifier
    if set(asset_ids) != required:
        missing = sorted(required - set(asset_ids))
        raise ReleaseCustodyError(f"published release is missing exact custody assets: {missing}")
    return asset_ids


def _bounded_detail(value: object, *, limit: int = 500) -> str:
    if isinstance(value, bytes):
        rendered = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        rendered = value
    else:
        rendered = ""
    detail = " ".join(rendered.strip().split())
    return detail if len(detail) <= limit else f"{detail[:limit]}..."


def _require_safe_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReleaseCustodyError(f"could not inspect release custody directory: {exc}") from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ReleaseCustodyError("release custody directory is not in exclusive owner custody")


def _require_safe_asset(path: Path, name: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReleaseCustodyError(f"could not inspect downloaded release custody for {name!r}: {exc}") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ReleaseCustodyError(f"downloaded release custody is unsafe: {name!r}")
    if not 0 < info.st_size <= MAX_PROOF_BYTES[name]:
        raise ReleaseCustodyError(f"downloaded release custody is outside its size bound: {name!r}")


def download_release_custody(
    *,
    repository: str,
    release_json: Path,
    output_dir: Path,
    runner: Runner = subprocess.run,
    timeout_seconds: int = ASSET_DOWNLOAD_TIMEOUT_SECONDS,
) -> None:
    """Download the required proof assets by their exact positive GitHub IDs."""

    if repository != EXPECTED_REPOSITORY:
        raise ReleaseCustodyError(f"release repository must be exactly {EXPECTED_REPOSITORY}, got {repository!r}")
    if timeout_seconds <= 0:
        raise ReleaseCustodyError("release asset download timeout must be positive")
    asset_ids = _load_asset_ids(release_json)

    if os.path.lexists(output_dir):
        raise ReleaseCustodyError("release custody directory must not exist before exact download")
    try:
        output_dir.mkdir(mode=0o700)
    except OSError as exc:
        raise ReleaseCustodyError(f"could not create release custody directory: {exc}") from exc
    _require_safe_directory(output_dir)

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ReleaseCustodyError("runner cannot create no-follow custody files")
    for name in REQUIRED_PROOF_ASSETS:
        path = output_dir / name
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
        except OSError as exc:
            raise ReleaseCustodyError(f"could not create release custody file for {name!r}: {exc}") from exc
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            command = [
                "gh",
                "api",
                "-H",
                "Accept: application/octet-stream",
                f"repos/{repository}/releases/assets/{asset_ids[name]}",
            ]
            try:
                completed = runner(
                    command,
                    check=False,
                    stdout=stream,
                    stderr=subprocess.PIPE,
                    timeout=timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise ReleaseCustodyError(
                    f"release asset {name!r} download timed out after {timeout_seconds} seconds"
                ) from exc
            except (OSError, subprocess.SubprocessError) as exc:
                raise ReleaseCustodyError(f"release asset {name!r} download could not run: {exc}") from exc
            if completed.returncode != 0:
                detail = _bounded_detail(completed.stderr)
                suffix = f": {detail}" if detail else ""
                raise ReleaseCustodyError(
                    f"release asset {name!r} download failed with exit {completed.returncode}{suffix}"
                )
            stream.flush()
            os.fsync(stream.fileno())
        _require_safe_asset(path, name)

    with os.scandir(output_dir) as iterator:
        entries = list(iterator)
    required = set(REQUIRED_PROOF_ASSETS)
    if {entry.name for entry in entries} != required or len(entries) != len(required):
        raise ReleaseCustodyError(f"downloaded release custody is not the exact {len(required)}-file set")
    _require_safe_directory(output_dir)
    for name in REQUIRED_PROOF_ASSETS:
        _require_safe_asset(output_dir / name, name)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release-json", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        download_release_custody(
            repository=args.repository,
            release_json=args.release_json,
            output_dir=args.output_dir,
        )
        print(f"downloaded exact {len(REQUIRED_PROOF_ASSETS)}-asset release custody set")
        return 0
    except ReleaseCustodyError as exc:
        print(f"release custody download failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
