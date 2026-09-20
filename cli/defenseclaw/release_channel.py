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
"""Canonical signed stable-channel contract shared by clients and publishers."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

SCHEMA = "defenseclaw-release-channel-v1"
CHANNEL = "stable"
RESOLVER_NAME = "defenseclaw-upgrade.sh"
POSIX_INSTALLER_NAME = "install.sh"
WINDOWS_INSTALLER_NAME = "install.ps1"
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
    "posix_installer_name",
    "posix_installer_url",
    "posix_installer_sha256",
    "windows_installer_name",
    "windows_installer_url",
    "windows_installer_sha256",
)


class ChannelError(RuntimeError):
    """The stable channel is malformed, inconsistent, or regressive."""


def _read_bounded_regular_file(path: Path, *, label: str, max_bytes: int) -> bytes:
    """Read one stable bounded file from a single non-following descriptor."""

    try:
        named_before = path.lstat()
    except OSError as exc:
        raise ChannelError(f"could not inspect {label} {path}: {exc}") from exc
    if not stat.S_ISREG(named_before.st_mode):
        raise ChannelError(f"{label} must be a regular file: {path}")
    if not 0 < named_before.st_size <= max_bytes:
        raise ChannelError(f"{label} has invalid size: {named_before.st_size}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ChannelError(f"could not open {label} {path}: {exc}") from exc

    def file_identity(info: os.stat_result) -> tuple[int, int]:
        return info.st_dev, info.st_ino

    def file_state(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    read_succeeded = False
    try:
        try:
            opened_before = os.fstat(descriptor)
            if not stat.S_ISREG(opened_before.st_mode):
                raise ChannelError(f"{label} must be a regular file: {path}")
            if not 0 < opened_before.st_size <= max_bytes:
                raise ChannelError(f"{label} has invalid size: {opened_before.st_size}")
            if file_identity(named_before) != file_identity(opened_before):
                raise ChannelError(f"{label} changed before it was read: {path}")

            chunks: list[bytes] = []
            remaining = opened_before.st_size
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    raise ChannelError(f"{label} changed while it was read: {path}")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise ChannelError(f"{label} changed while it was read: {path}")

            opened_after = os.fstat(descriptor)
            try:
                named_after = path.lstat()
            except OSError as exc:
                raise ChannelError(f"{label} disappeared while it was read: {path}") from exc
            if (
                file_state(named_before) != file_state(named_after)
                or file_state(opened_before) != file_state(opened_after)
                or file_identity(named_after) != file_identity(opened_after)
            ):
                raise ChannelError(f"{label} changed while it was read: {path}")
            payload = b"".join(chunks)
            read_succeeded = True
            return payload
        except OSError as exc:
            raise ChannelError(f"could not read {label} {path}: {exc}") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            if read_succeeded:
                raise ChannelError(f"could not close {label} {path}: {exc}") from exc


def version_key(value: str) -> tuple[int, int, int]:
    """Return a canonical semantic-version tuple."""
    if VERSION_RE.fullmatch(value) is None:
        raise ChannelError(f"target version must be canonical X.Y.Z: {value!r}")
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)


def _validate_repository(value: str) -> None:
    if REPOSITORY_RE.fullmatch(value) is None or ".." in value:
        raise ChannelError(f"repository is not a canonical owner/name slug: {value!r}")


def release_asset_url(repository: str, version: str, name: str) -> str:
    """Return one exact immutable release-asset URL."""
    return f"https://github.com/{repository}/releases/download/{version}/{name}"


def resolver_url(repository: str, version: str) -> str:
    """Return the only resolver URL admitted by the channel schema."""
    return release_asset_url(repository, version, RESOLVER_NAME)


def build_channel(
    *,
    repository: str,
    version: str,
    commit: str,
    resolver_sha256: str,
    posix_installer_sha256: str,
    windows_installer_sha256: str,
) -> dict[str, str]:
    """Return one strict, self-consistent stable-channel record."""
    _validate_repository(repository)
    version_key(version)
    if COMMIT_RE.fullmatch(commit) is None:
        raise ChannelError("target commit must be a lowercase 40-character Git object ID")
    if SHA256_RE.fullmatch(resolver_sha256) is None:
        raise ChannelError("resolver digest must be a lowercase SHA-256")
    if SHA256_RE.fullmatch(posix_installer_sha256) is None:
        raise ChannelError("POSIX installer digest must be a lowercase SHA-256")
    if SHA256_RE.fullmatch(windows_installer_sha256) is None:
        raise ChannelError("Windows installer digest must be a lowercase SHA-256")
    return {
        "schema": SCHEMA,
        "channel": CHANNEL,
        "repository": repository,
        "target_version": version,
        "target_tag": version,
        "target_ref": f"refs/tags/{version}",
        "target_commit": commit,
        "resolver_name": RESOLVER_NAME,
        "resolver_url": resolver_url(repository, version),
        "resolver_sha256": resolver_sha256,
        "posix_installer_name": POSIX_INSTALLER_NAME,
        "posix_installer_url": release_asset_url(repository, version, POSIX_INSTALLER_NAME),
        "posix_installer_sha256": posix_installer_sha256,
        "windows_installer_name": WINDOWS_INSTALLER_NAME,
        "windows_installer_url": release_asset_url(repository, version, WINDOWS_INSTALLER_NAME),
        "windows_installer_sha256": windows_installer_sha256,
    }


def render_channel_without_validation(channel: dict[str, str]) -> bytes:
    """Render an already-validated channel in fixed field order."""
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
    version_key(version)
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
    if channel["resolver_url"] != resolver_url(repository, version):
        raise ChannelError("channel resolver URL is not derived from repository and tag")
    if SHA256_RE.fullmatch(channel["resolver_sha256"]) is None:
        raise ChannelError("channel resolver digest is not a lowercase SHA-256")
    if channel["posix_installer_name"] != POSIX_INSTALLER_NAME:
        raise ChannelError("channel POSIX installer name is not the reviewed installer")
    if channel["posix_installer_url"] != release_asset_url(repository, version, POSIX_INSTALLER_NAME):
        raise ChannelError("channel POSIX installer URL is not derived from repository and tag")
    if SHA256_RE.fullmatch(channel["posix_installer_sha256"]) is None:
        raise ChannelError("channel POSIX installer digest is not a lowercase SHA-256")
    if channel["windows_installer_name"] != WINDOWS_INSTALLER_NAME:
        raise ChannelError("channel Windows installer name is not the reviewed installer")
    if channel["windows_installer_url"] != release_asset_url(repository, version, WINDOWS_INSTALLER_NAME):
        raise ChannelError("channel Windows installer URL is not derived from repository and tag")
    if SHA256_RE.fullmatch(channel["windows_installer_sha256"]) is None:
        raise ChannelError("channel Windows installer digest is not a lowercase SHA-256")
    return dict(channel)


def render_channel(channel: dict[str, str]) -> bytes:
    """Validate and render the canonical signed bytes."""
    return render_channel_without_validation(validate_channel(channel))


def parse_channel(payload: bytes) -> dict[str, str]:
    """Parse only the exact fixed-order ASCII encoding accepted by rescue."""
    if not payload or len(payload) > MAX_CHANNEL_BYTES:
        raise ChannelError("channel document has invalid size")
    if b"\0" in payload or b"\r" in payload or not payload.endswith(b"\n"):
        raise ChannelError("channel document must be NUL-free canonical LF text")
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ChannelError("channel document must contain only ASCII") from exc
    lines = text[:-1].split("\n")
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


def compare_channels(current: dict[str, str], candidate: dict[str, str]) -> str:
    """Return ``same`` or ``advance``; reject conflicts and rollbacks."""
    current = validate_channel(current)
    candidate = validate_channel(candidate)
    if current["repository"] != candidate["repository"]:
        raise ChannelError("candidate channel changes repository ownership")
    current_version = version_key(current["target_version"])
    candidate_version = version_key(candidate["target_version"])
    if candidate_version < current_version:
        raise ChannelError("candidate channel would roll back the stable target")
    if candidate_version == current_version:
        if current != candidate:
            raise ChannelError("candidate changes an already-published stable version binding")
        return "same"
    return "advance"


def load_channel(path: Path) -> dict[str, str]:
    """Load one bounded regular channel file."""
    return parse_channel(
        _read_bounded_regular_file(
            path,
            label="release channel",
            max_bytes=MAX_CHANNEL_BYTES,
        )
    )


def channel_asset_digests_from_checksums(path: Path) -> dict[str, str]:
    """Extract the exact resolver and public-installer bindings."""
    payload = _read_bounded_regular_file(
        path,
        label="release checksum manifest",
        max_bytes=MAX_CHECKSUMS_BYTES,
    )
    if b"\0" in payload or b"\r" in payload or not payload.endswith(b"\n"):
        raise ChannelError("release checksum manifest must be NUL-free canonical LF text")
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ChannelError("release checksum manifest must contain only ASCII") from exc
    lines = text[:-1].split("\n")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        match = CHECKSUM_RE.fullmatch(line)
        if match is None:
            raise ChannelError(f"invalid release checksum line {line_number}: {line!r}")
        digest, name = match.groups()
        if name in entries:
            raise ChannelError(f"duplicate release checksum entry: {name}")
        entries[name] = digest
    required = (RESOLVER_NAME, POSIX_INSTALLER_NAME, WINDOWS_INSTALLER_NAME)
    missing = [name for name in required if name not in entries]
    if missing:
        raise ChannelError(f"release checksum manifest does not bind {', '.join(missing)}")
    return {name: entries[name] for name in required}


def resolver_digest_from_checksums(path: Path) -> str:
    """Extract exactly one reviewed POSIX resolver digest."""
    return channel_asset_digests_from_checksums(path)[RESOLVER_NAME]
