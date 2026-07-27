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

"""Authenticate immutable release custody before repairing the stable channel.

The normal release path compares GitHub custody with the exact Actions
candidate.  A repair may run after that artifact expires, so it instead uses
the signed checksum manifest as the closed payload inventory and compares every
entry with GitHub's digest for the immutable release.  Only the small proof and
provenance files need to be downloaded again.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Sequence
from os import stat_result
from pathlib import Path
from typing import Any

VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ASSET_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
CHECKSUM_LINE_RE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$")

MAX_RELEASE_JSON_BYTES = 8 * 1024 * 1024
MAX_CHECKSUMS_BYTES = 4 * 1024 * 1024
MAX_PROOF_BYTES = {
    "checksums.txt": MAX_CHECKSUMS_BYTES,
    "checksums.txt.bundle": 16 * 1024 * 1024,
    "checksums.txt.pem": 64 * 1024,
    "checksums.txt.sig": 64 * 1024,
    "release-provenance.json": 1024 * 1024,
    "release-source-map.json": 1024 * 1024,
    "upgrade-manifest.json": 1024 * 1024,
}
PROOF_ASSET_NAMES = frozenset(
    {
        "checksums.txt",
        "checksums.txt.bundle",
        "checksums.txt.pem",
        "checksums.txt.sig",
    }
)
DOWNLOADED_ASSET_NAMES = frozenset(MAX_PROOF_BYTES)
REQUIRED_PAYLOAD_NAMES = frozenset(
    {
        "defenseclaw-upgrade.sh",
        "defenseclaw-upgrade.ps1",
        "defenseclaw-rescue.sh",
        "defenseclaw-rescue.ps1",
        "install.sh",
        "install.ps1",
        "release-provenance.json",
        "release-source-map.json",
        "upgrade-manifest.json",
    }
)


class RepairTargetError(RuntimeError):
    """The published release is not an authenticated channel target."""


def _is_link_or_reparse(value: stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(value, "st_file_attributes", 0)
    return stat.S_ISLNK(value.st_mode) or bool(reparse_flag and file_attributes & reparse_flag)


def _path_identity(value: stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


_file_identity = _path_identity
_directory_identity = _path_identity


def _read_regular(
    path: Path,
    *,
    label: str,
    maximum: int,
    expected_identity: tuple[int, int, int, int, int, int] | None = None,
) -> bytes:
    # Repair verification cannot use release_channel._read_bounded_regular_file:
    # every read must remain bound to the one directory snapshot captured
    # before verification, and the Windows fallback must reject reparse points.
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    named_before: stat_result | None = None
    if not nofollow:
        # Windows does not expose O_NOFOLLOW. Bind the opened descriptor to a
        # nonsymlink/reparse-point pathname identity on that fallback.
        try:
            named_before = path.lstat()
        except OSError as exc:
            raise RepairTargetError(f"could not inspect {label}: {exc}") from exc
        if _is_link_or_reparse(named_before) or not stat.S_ISREG(named_before.st_mode):
            raise RepairTargetError(f"{label} must be a regular nonsymlink file")

    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RepairTargetError(f"could not open {label} as a regular nonsymlink file: {exc}") from exc

    payload = bytearray()
    try:
        before = os.fstat(descriptor)
        before_identity = _file_identity(before)
        if _is_link_or_reparse(before) or not stat.S_ISREG(before.st_mode):
            raise RepairTargetError(f"{label} must be a regular nonsymlink file")
        if expected_identity is not None and before_identity != expected_identity:
            raise RepairTargetError(f"{label} changed before it was read")
        if named_before is not None and before_identity != _file_identity(named_before):
            raise RepairTargetError(f"{label} changed while it was opened")
        if not 0 < before.st_size <= maximum:
            raise RepairTargetError(f"{label} has invalid size: {before.st_size}")

        while len(payload) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - len(payload) + 1))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise RepairTargetError(f"could not read {label}: {exc}") from exc
    finally:
        os.close(descriptor)

    if len(payload) > maximum:
        raise RepairTargetError(f"{label} has invalid size: greater than {maximum}")
    if len(payload) != before.st_size or before_identity != _file_identity(after):
        raise RepairTargetError(f"{label} changed while it was read")
    if named_before is not None:
        try:
            named_after = path.lstat()
        except OSError as exc:
            raise RepairTargetError(f"could not re-inspect {label}: {exc}") from exc
        if _is_link_or_reparse(named_after) or _file_identity(named_after) != before_identity:
            raise RepairTargetError(f"{label} changed while it was read")
    return bytes(payload)


def _download_snapshot(
    download_dir: Path,
) -> tuple[
    dict[str, tuple[Path, tuple[int, int, int, int, int, int]]],
    tuple[int, int, int, int, int, int],
]:
    try:
        directory_before = download_dir.lstat()
        entries = tuple(download_dir.iterdir())
        entry_rows = tuple((entry, entry.lstat()) for entry in entries)
        directory_after = download_dir.lstat()
    except OSError as exc:
        raise RepairTargetError(f"could not inspect repair custody directory: {exc}") from exc
    if _is_link_or_reparse(directory_before) or not stat.S_ISDIR(directory_before.st_mode):
        raise RepairTargetError("repair custody directory must be a real directory")
    directory_identity = _directory_identity(directory_before)
    if directory_identity != _directory_identity(directory_after):
        raise RepairTargetError("repair custody directory changed while it was inspected")

    snapshot: dict[str, tuple[Path, tuple[int, int, int, int, int, int]]] = {}
    for entry, metadata in entry_rows:
        if entry.name in snapshot or _is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise RepairTargetError("repair custody directory does not contain the exact bounded proof set")
        snapshot[entry.name] = (entry, _file_identity(metadata))
    if set(snapshot) != DOWNLOADED_ASSET_NAMES:
        raise RepairTargetError("repair custody directory does not contain the exact bounded proof set")
    return snapshot, directory_identity


def _require_unchanged_download_directory(
    download_dir: Path,
    expected_identity: tuple[int, int, int, int, int, int],
) -> None:
    try:
        current = download_dir.lstat()
    except OSError as exc:
        raise RepairTargetError(f"could not re-inspect repair custody directory: {exc}") from exc
    if (
        _is_link_or_reparse(current)
        or not stat.S_ISDIR(current.st_mode)
        or _directory_identity(current) != expected_identity
    ):
        raise RepairTargetError("repair custody directory changed during verification")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_object(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepairTargetError(f"{label} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RepairTargetError(f"{label} must contain a JSON object")
    return value


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _parse_checksums(payload: bytes) -> dict[str, str]:
    # The shared channel parser intentionally returns only the three channel
    # bindings. Repair custody instead needs the complete, sorted manifest so
    # every immutable GitHub asset can be compared before channel publication.
    if b"\0" in payload or b"\r" in payload or not payload.endswith(b"\n"):
        raise RepairTargetError("checksums.txt must be canonical NUL-free LF text")
    try:
        lines = payload.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise RepairTargetError("checksums.txt must contain only ASCII") from exc
    if not lines:
        raise RepairTargetError("checksums.txt is empty")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        match = CHECKSUM_LINE_RE.fullmatch(line)
        if match is None:
            raise RepairTargetError(f"checksums.txt line {line_number} is invalid")
        digest, name = match.groups()
        if name in entries:
            raise RepairTargetError(f"checksums.txt repeats asset {name!r}")
        entries[name] = digest
    if list(entries) != sorted(entries):
        raise RepairTargetError("checksums.txt asset names must be strictly sorted")
    rendered = "".join(f"{entries[name]}  {name}\n" for name in sorted(entries)).encode("ascii")
    if rendered != payload:
        raise RepairTargetError("checksums.txt is not canonically encoded")
    return entries


def _remote_assets(release: dict[str, Any], version: str) -> dict[str, str]:
    if release.get("tag_name") != version:
        raise RepairTargetError("published release tag does not match the requested version")
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise RepairTargetError("channel repair requires a published non-prerelease release")
    if release.get("immutable") is not True:
        raise RepairTargetError("channel repair requires GitHub Immutable Releases custody")
    rows = release.get("assets")
    if not isinstance(rows, list):
        raise RepairTargetError("published release lacks an asset inventory")
    assets: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RepairTargetError("published release contains an invalid asset row")
        name = row.get("name")
        digest = row.get("digest")
        if not isinstance(name, str) or ASSET_NAME_RE.fullmatch(name) is None or name in assets:
            raise RepairTargetError(f"published release has an invalid or duplicate asset name: {name!r}")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise RepairTargetError(f"GitHub did not report a SHA-256 digest for {name!r}")
        digest_value = digest.removeprefix("sha256:")
        if SHA256_RE.fullmatch(digest_value) is None:
            raise RepairTargetError(f"GitHub reported a malformed digest for {name!r}")
        assets[name] = digest_value
    return assets


def _validate_source_identity(
    *,
    provenance_payload: bytes,
    source_map_payload: bytes,
    version: str,
    commit: str,
    source_tree: str,
    expected_bridge: str,
) -> None:
    provenance = _json_object(provenance_payload, label="release provenance")
    source_map = _json_object(source_map_payload, label="release source map")
    expected_map_keys = {
        "schema_version",
        "release_version",
        "source_commit",
        "source_tree",
        "policy_mode",
        "policy_commit",
        "policy_tree",
        "source_install_identity",
        "bridge",
    }
    expected_provenance_keys = {
        "schema_version",
        "release_version",
        "source_commit",
        "source_tree",
        "policy_commit",
        "policy_tree",
        "release_source_map_sha256",
        "source_install_identity",
        "bridge",
    }
    if set(source_map) != expected_map_keys or set(provenance) != expected_provenance_keys:
        raise RepairTargetError("release identity assets do not use the closed schema-1 field sets")
    if source_map.get("schema_version") != 1 or provenance.get("schema_version") != 1:
        raise RepairTargetError("release identity schema version mismatch")
    if source_map.get("policy_mode") != "same_as_release_source":
        raise RepairTargetError("release source map policy mode mismatch")
    for document, label in ((source_map, "source map"), (provenance, "provenance")):
        if document.get("release_version") != version:
            raise RepairTargetError(f"release {label} version mismatch")
        if document.get("source_commit") != commit or document.get("policy_commit") != commit:
            raise RepairTargetError(f"release {label} commit mismatch")
        if document.get("source_tree") != source_tree or document.get("policy_tree") != source_tree:
            raise RepairTargetError(f"release {label} tree mismatch")
        identity = document.get("source_install_identity")
        if not isinstance(identity, dict) or set(identity) != {
            "schema_version",
            "source_release",
            "source_install_compatibility_epoch",
            "runtime_config_version",
        }:
            raise RepairTargetError(f"release {label} source-install identity is not closed")
        if identity.get("schema_version") != 1 or identity.get("source_release") != version:
            raise RepairTargetError(f"release {label} source-install identity mismatch")
        if (
            type(identity.get("source_install_compatibility_epoch")) is not int
            or type(identity.get("runtime_config_version")) is not int
        ):
            raise RepairTargetError(f"release {label} source-install identity has invalid versions")
        bridge = document.get("bridge")
        if not isinstance(bridge, dict) or set(bridge) != {
            "version",
            "commit",
            "tree",
            "checksums_sha256",
        }:
            raise RepairTargetError(f"release {label} bridge identity is not closed")
        if bridge.get("version") != expected_bridge:
            raise RepairTargetError(f"release {label} bridge version mismatch")
        if (
            SHA1_RE.fullmatch(str(bridge.get("commit", ""))) is None
            or SHA1_RE.fullmatch(str(bridge.get("tree", ""))) is None
        ):
            raise RepairTargetError(f"release {label} bridge Git identity is malformed")
        if SHA256_RE.fullmatch(str(bridge.get("checksums_sha256", ""))) is None:
            raise RepairTargetError(f"release {label} bridge checksum digest is malformed")
    shared = {
        "release_version",
        "source_commit",
        "source_tree",
        "policy_commit",
        "policy_tree",
        "source_install_identity",
        "bridge",
    }
    if any(source_map.get(name) != provenance.get(name) for name in shared):
        raise RepairTargetError("release source map and provenance disagree")
    if source_map_payload != _canonical_json(source_map) or provenance_payload != _canonical_json(provenance):
        raise RepairTargetError("release identity JSON is not canonical")
    if provenance.get("release_source_map_sha256") != _sha256(source_map_payload):
        raise RepairTargetError("release provenance does not authenticate the source map")


def _upgrade_manifest_bridge(payload: bytes, *, version: str) -> str:
    manifest = _json_object(payload, label="upgrade manifest")
    if payload != _canonical_json(manifest):
        raise RepairTargetError("upgrade manifest JSON is not canonical")
    if manifest.get("schema_version") != 2 or manifest.get("release_version") != version:
        raise RepairTargetError("upgrade manifest release identity mismatch")
    minimum = manifest.get("minimum_source_version")
    bridge = manifest.get("required_bridge_version")
    if (
        not isinstance(minimum, str)
        or VERSION_RE.fullmatch(minimum) is None
        or not isinstance(bridge, str)
        or VERSION_RE.fullmatch(bridge) is None
        or bridge != minimum
    ):
        raise RepairTargetError("upgrade manifest bridge contract is invalid")
    if tuple(map(int, bridge.split("."))) >= tuple(map(int, version.split("."))):
        raise RepairTargetError("upgrade manifest bridge must be older than its release")
    tested = manifest.get("tested_source_versions")
    if (
        not isinstance(tested, list)
        or any(not isinstance(item, str) or VERSION_RE.fullmatch(item) is None for item in tested)
        or len(tested) != len(set(tested))
        or bridge not in tested
    ):
        raise RepairTargetError("upgrade manifest does not bind the bridge in its tested sources")
    return bridge


def verify_target(
    *,
    release_json: Path,
    download_dir: Path,
    version: str,
    commit: str,
    source_tree: str,
) -> None:
    if VERSION_RE.fullmatch(version) is None:
        raise RepairTargetError("version must be canonical X.Y.Z")
    if tuple(map(int, version.split("."))) < (0, 8, 8):
        raise RepairTargetError("signed stable-channel repair starts with release 0.8.8")
    if SHA1_RE.fullmatch(commit) is None or SHA1_RE.fullmatch(source_tree) is None:
        raise RepairTargetError("commit and source tree must be lowercase 40-character Git IDs")
    release = _json_object(
        _read_regular(release_json, label="release API response", maximum=MAX_RELEASE_JSON_BYTES),
        label="release API response",
    )
    remote = _remote_assets(release, version)
    snapshot, directory_identity = _download_snapshot(download_dir)
    downloaded = {
        name: _read_regular(
            snapshot[name][0],
            label=name,
            maximum=MAX_PROOF_BYTES[name],
            expected_identity=snapshot[name][1],
        )
        for name in sorted(DOWNLOADED_ASSET_NAMES)
    }
    _require_unchanged_download_directory(download_dir, directory_identity)
    for name, payload in downloaded.items():
        if remote.get(name) != _sha256(payload):
            raise RepairTargetError(f"downloaded {name} differs from GitHub immutable custody")
    checksums = _parse_checksums(downloaded["checksums.txt"])
    if not REQUIRED_PAYLOAD_NAMES <= checksums.keys():
        missing = sorted(REQUIRED_PAYLOAD_NAMES - checksums.keys())
        raise RepairTargetError(f"signed checksums omit channel recovery assets: {missing!r}")
    expected_remote_names = set(checksums) | PROOF_ASSET_NAMES
    if set(remote) != expected_remote_names:
        raise RepairTargetError("published asset namespace differs from signed checksum custody")
    for name, digest in checksums.items():
        if remote.get(name) != digest:
            raise RepairTargetError(f"GitHub custody digest differs from signed checksum for {name}")
    expected_bridge = _upgrade_manifest_bridge(
        downloaded["upgrade-manifest.json"],
        version=version,
    )
    _validate_source_identity(
        provenance_payload=downloaded["release-provenance.json"],
        source_map_payload=downloaded["release-source-map.json"],
        version=version,
        commit=commit,
        source_tree=source_tree,
        expected_bridge=expected_bridge,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-json", type=Path, required=True)
    parser.add_argument("--download-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source-tree", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        verify_target(
            release_json=args.release_json,
            download_dir=args.download_dir,
            version=args.version,
            commit=args.commit,
            source_tree=args.source_tree,
        )
    except (OSError, RepairTargetError) as exc:
        print(f"release channel repair verification failed: {exc}", file=sys.stderr)
        return 1
    print(f"authenticated immutable channel target: {args.version} at {args.commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
