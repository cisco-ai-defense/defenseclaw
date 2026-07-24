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
"""Create and validate the authenticated DefenseClaw stable release channel.

The channel document is deliberately a fixed-order line protocol rather than
JSON.  The external POSIX rescue bootstrap can therefore validate it without
``jq``, Python, or evaluating network-controlled shell text.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from collections.abc import Sequence
from pathlib import Path

SCHEMA = "defenseclaw-release-channel-v1"
CHANNEL = "stable"
RESOLVER_NAME = "defenseclaw-upgrade.sh"
MAX_CHANNEL_BYTES = 16 * 1024
MAX_CHECKSUMS_BYTES = 4 * 1024 * 1024
VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
CHECKSUM_RE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$")
FIELD_ORDER = (
    "schema",
    "channel",
    "repository",
    "target_version",
    "target_tag",
    "target_ref",
    "target_commit",
    "resolver_name",
    "resolver_url",
    "resolver_sha256",
)


class ChannelError(RuntimeError):
    """The release channel is malformed, inconsistent, or regressive."""


def _read_bounded_regular_file(path: Path, *, label: str, max_bytes: int) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ChannelError(f"could not inspect {label} {path}: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ChannelError(f"{label} must be a regular file: {path}")
    if info.st_size <= 0 or info.st_size > max_bytes:
        raise ChannelError(f"{label} has invalid size: {info.st_size}")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ChannelError(f"could not read {label} {path}: {exc}") from exc
    if len(payload) != info.st_size:
        raise ChannelError(f"{label} changed while it was read: {path}")
    return payload


def _validate_version(value: str) -> tuple[int, int, int]:
    if VERSION_RE.fullmatch(value) is None:
        raise ChannelError(f"target version must be canonical X.Y.Z: {value!r}")
    return tuple(map(int, value.split(".")))  # type: ignore[return-value]


def _validate_repository(value: str) -> None:
    if REPOSITORY_RE.fullmatch(value) is None or ".." in value:
        raise ChannelError(f"repository is not a canonical owner/name slug: {value!r}")


def _resolver_url(repository: str, version: str) -> str:
    return f"https://github.com/{repository}/releases/download/{version}/{RESOLVER_NAME}"


def build_channel(
    *,
    repository: str,
    version: str,
    commit: str,
    resolver_sha256: str,
) -> dict[str, str]:
    """Return one strict, self-consistent stable-channel record."""

    _validate_repository(repository)
    _validate_version(version)
    if COMMIT_RE.fullmatch(commit) is None:
        raise ChannelError("target commit must be a lowercase 40-character Git object ID")
    if SHA256_RE.fullmatch(resolver_sha256) is None:
        raise ChannelError("resolver digest must be a lowercase SHA-256")
    return {
        "schema": SCHEMA,
        "channel": CHANNEL,
        "repository": repository,
        "target_version": version,
        "target_tag": version,
        "target_ref": f"refs/tags/{version}",
        "target_commit": commit,
        "resolver_name": RESOLVER_NAME,
        "resolver_url": _resolver_url(repository, version),
        "resolver_sha256": resolver_sha256,
    }


def render_channel(channel: dict[str, str]) -> bytes:
    """Validate and render the canonical signed bytes."""

    validated = validate_channel(channel)
    return ("".join(f"{name}={validated[name]}\n" for name in FIELD_ORDER)).encode("ascii")


def parse_channel(payload: bytes) -> dict[str, str]:
    """Parse only the exact canonical line encoding accepted by the bootstrap."""

    if not payload or len(payload) > MAX_CHANNEL_BYTES:
        raise ChannelError("channel document has invalid size")
    if b"\0" in payload or b"\r" in payload or not payload.endswith(b"\n"):
        raise ChannelError("channel document must be NUL-free canonical LF text")
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ChannelError("channel document must contain only ASCII") from exc
    lines = text.splitlines()
    if len(lines) != len(FIELD_ORDER):
        raise ChannelError(f"channel document must contain exactly {len(FIELD_ORDER)} fields")
    values: dict[str, str] = {}
    for expected_name, line in zip(FIELD_ORDER, lines, strict=True):
        prefix = f"{expected_name}="
        if not line.startswith(prefix):
            raise ChannelError(f"channel field order mismatch: expected {expected_name!r}")
        value = line[len(prefix) :]
        if not value:
            raise ChannelError(f"channel field {expected_name!r} is empty")
        values[expected_name] = value
    validated = validate_channel(values)
    if render_channel_without_validation(validated) != payload:
        raise ChannelError("channel document is not canonically encoded")
    return validated


def render_channel_without_validation(channel: dict[str, str]) -> bytes:
    return "".join(f"{name}={channel[name]}\n" for name in FIELD_ORDER).encode("ascii")


def validate_channel(
    channel: dict[str, str],
    *,
    expected_repository: str | None = None,
    expected_version: str | None = None,
) -> dict[str, str]:
    """Reject ambiguity and verify every derived target binding."""

    if set(channel) != set(FIELD_ORDER):
        missing = sorted(set(FIELD_ORDER) - set(channel))
        extra = sorted(set(channel) - set(FIELD_ORDER))
        raise ChannelError(f"channel fields differ from schema (missing={missing}, extra={extra})")
    if channel["schema"] != SCHEMA:
        raise ChannelError(f"unsupported channel schema: {channel['schema']!r}")
    if channel["channel"] != CHANNEL:
        raise ChannelError(f"unsupported release channel: {channel['channel']!r}")
    repository = channel["repository"]
    _validate_repository(repository)
    if expected_repository is not None and repository != expected_repository:
        raise ChannelError(f"channel repository mismatch: got {repository!r}, expected {expected_repository!r}")
    version = channel["target_version"]
    _validate_version(version)
    if expected_version is not None and version != expected_version:
        raise ChannelError(f"channel target mismatch: got {version!r}, expected {expected_version!r}")
    if channel["target_tag"] != version:
        raise ChannelError("channel target tag does not equal target version")
    if channel["target_ref"] != f"refs/tags/{version}":
        raise ChannelError("channel target ref is not the exact immutable tag ref")
    if COMMIT_RE.fullmatch(channel["target_commit"]) is None:
        raise ChannelError("channel target commit is not a lowercase Git object ID")
    if channel["resolver_name"] != RESOLVER_NAME:
        raise ChannelError("channel resolver name is not the reviewed POSIX resolver")
    if channel["resolver_url"] != _resolver_url(repository, version):
        raise ChannelError("channel resolver URL is not derived from repository and tag")
    if SHA256_RE.fullmatch(channel["resolver_sha256"]) is None:
        raise ChannelError("channel resolver digest is not a lowercase SHA-256")
    return dict(channel)


def resolver_digest_from_checksums(path: Path) -> str:
    """Extract exactly one reviewed POSIX resolver digest."""

    payload = _read_bounded_regular_file(
        path,
        label="release checksum manifest",
        max_bytes=MAX_CHECKSUMS_BYTES,
    )
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ChannelError("release checksum manifest must contain only ASCII") from exc
    entries: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        match = CHECKSUM_RE.fullmatch(line)
        if match is None:
            raise ChannelError(f"invalid release checksum line {line_number}: {line!r}")
        digest, name = match.groups()
        if name in entries:
            raise ChannelError(f"duplicate release checksum entry: {name}")
        entries[name] = digest
    try:
        return entries[RESOLVER_NAME]
    except KeyError as exc:
        raise ChannelError(f"release checksum manifest does not bind {RESOLVER_NAME}") from exc


def compare_channels(current: dict[str, str], candidate: dict[str, str]) -> str:
    """Return ``same`` or ``advance``; reject conflicts and rollbacks."""

    current = validate_channel(current)
    candidate = validate_channel(candidate)
    if current["repository"] != candidate["repository"]:
        raise ChannelError("candidate channel changes repository ownership")
    current_version = _validate_version(current["target_version"])
    candidate_version = _validate_version(candidate["target_version"])
    if candidate_version < current_version:
        raise ChannelError("candidate channel would roll back the stable target")
    if candidate_version == current_version:
        if current != candidate:
            raise ChannelError("candidate changes an already-published stable version binding")
        return "same"
    return "advance"


def _load_channel(path: Path) -> dict[str, str]:
    return parse_channel(
        _read_bounded_regular_file(
            path,
            label="release channel",
            max_bytes=MAX_CHANNEL_BYTES,
        )
    )


def _write_new(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ChannelError(f"writing release channel stalled: {path}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--repository", required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--commit", required=True)
    create.add_argument("--checksums", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--repository")
    validate.add_argument("--version")
    validate.add_argument("channel", type=Path)

    compare = subparsers.add_parser("compare")
    compare.add_argument("--current", type=Path, required=True)
    compare.add_argument("--candidate", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "create":
            digest = resolver_digest_from_checksums(args.checksums)
            channel = build_channel(
                repository=args.repository,
                version=args.version,
                commit=args.commit,
                resolver_sha256=digest,
            )
            _write_new(args.output, render_channel(channel))
            print(f"stable channel candidate created: {args.version}")
        elif args.command == "validate":
            validate_channel(
                _load_channel(args.channel),
                expected_repository=args.repository,
                expected_version=args.version,
            )
            print("stable channel document valid")
        elif args.command == "compare":
            print(
                compare_channels(
                    _load_channel(args.current),
                    _load_channel(args.candidate),
                )
            )
        else:  # pragma: no cover - argparse owns command selection.
            raise AssertionError(args.command)
    except ChannelError as exc:
        print(f"release channel error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
