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

"""Exact identity checks for first-party DefenseClaw scanner artifacts.

The plugin scanner must inspect third-party ``dist/`` trees, so self-scan
avoidance cannot be a directory-name heuristic.  This module recognizes only:

* the installed Python package itself;
* an exact, home-anchored path where DefenseClaw installs a connector bridge;
* the repository-owned OpenClaw runtime projection; or
* a deployed runtime matching the immutable wheel/repository fingerprint.

Deployed extensions never act as their own reference and an expected install
path is not evidence of identity. Adding or changing a runtime file therefore
turns a relocated or installed copy back into an ordinary scan target.
Symlinks, reparse points, oversized trees, and malformed references never
qualify.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterable
from pathlib import Path

from defenseclaw.extension_fingerprint import (
    REFERENCE_PACKAGE_PATH,
    ExtensionFingerprintError,
    fingerprint_deployed_runtime,
    fingerprint_repository_runtime,
    load_reference,
)

_MAX_MANIFEST_BYTES = 256 * 1024
_MAX_BRIDGE_BYTES = 2 * 1024 * 1024


def canonical_path_identity(path: str | os.PathLike[str]) -> str:
    """Return the host-native canonical identity spelling for *path*.

    ``realpath`` collapses links and ``normcase`` supplies Windows'
    case-insensitive identity semantics while remaining a no-op on POSIX.
    """

    expanded = os.path.expanduser(os.fspath(path))
    return os.path.normcase(os.path.realpath(os.path.abspath(expanded)))


def _is_plain_regular_file(path: str) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and not bool(attributes & reparse_flag)


def _read_bounded_plain_file(path: str, maximum_bytes: int) -> bytes | None:
    """Read a stable regular-file descriptor without following a raced leaf."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        current = os.lstat(path)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        attributes = getattr(current, "st_file_attributes", 0)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or bool(attributes & reparse_flag)
            or not os.path.samestat(opened, current)
            or opened.st_size > maximum_bytes
        ):
            return None

        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(128 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        return payload if len(payload) <= maximum_bytes else None
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_json_object(path: str) -> dict | None:
    payload = _read_bounded_plain_file(path, _MAX_MANIFEST_BYTES)
    if payload is None:
        return None
    try:
        value = json.loads(payload.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _looks_like_extension_root(path: str) -> bool:
    if not os.path.isdir(path):
        return False
    package = _read_json_object(os.path.join(path, "package.json"))
    manifest = _read_json_object(os.path.join(path, "openclaw.plugin.json"))
    if package is None or manifest is None:
        return False
    return (
        package.get("name") == "defenseclaw"
        and str(package.get("main") or "").replace("\\", "/") == "dist/index.js"
        and manifest.get("id") == "defenseclaw"
    )


def _looks_like_python_package(path: str) -> bool:
    return all(
        _is_plain_regular_file(os.path.join(path, *parts))
        for parts in (
            ("__init__.py",),
            ("scanner", "plugin_scanner", "scanner.py"),
            ("scanner", "plugin_scanner", "self_identity.py"),
        )
    )


def _looks_like_bridge_file(path: str) -> bool:
    payload = _read_bounded_plain_file(path, _MAX_BRIDGE_BYTES)
    if payload is None:
        return False
    try:
        source = payload.decode("utf-8", errors="strict")
    except UnicodeError:
        return False
    # These are stable product/API markers, not a filename-only exemption.
    return "DefenseClaw" in source and "/api/v1/" in source


def _repository_extension_root() -> Path | None:
    """Return the canonical source runtime root only in an actual checkout."""

    package_root = Path(__file__).resolve().parents[2]
    repository_root = package_root.parent.parent
    candidate = repository_root / "extensions" / "defenseclaw"
    try:
        in_checkout = (
            (repository_root / "pyproject.toml").is_file()
            and (repository_root / "cli" / "defenseclaw").resolve() == package_root
            and candidate.is_dir()
        )
    except OSError:
        return None
    return candidate if in_checkout else None


def _packaged_extension_reference() -> Path:
    package_root = Path(__file__).resolve().parents[2]
    return package_root.joinpath(*REFERENCE_PACKAGE_PATH.split("/"))


def _immutable_extension_reference() -> tuple[Path | None, dict[str, object] | None]:
    """Resolve repository bytes or the wheel-packaged digest, never user state."""

    source = _repository_extension_root()
    if source is not None:
        try:
            return source, fingerprint_repository_runtime(source)
        except ExtensionFingerprintError:
            return source, None
    try:
        return None, load_reference(_packaged_extension_reference())
    except ExtensionFingerprintError:
        return None, None


def _default_connector_artifacts() -> tuple[str, ...]:
    home = os.path.abspath(str(Path.home()))
    claude_home = os.path.abspath(
        os.path.expanduser(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(home, ".claude"))
    )
    codex_home = os.path.abspath(os.path.expanduser(os.environ.get("CODEX_HOME") or os.path.join(home, ".codex")))
    zepto_home = os.path.abspath(
        os.path.expanduser(os.environ.get("ZEPTOCLAW_HOME") or os.path.join(home, ".zeptoclaw"))
    )
    return (
        os.path.join(home, ".defenseclaw", "extensions", "defenseclaw"),
        os.path.join(home, ".openclaw", "extensions", "defenseclaw"),
        os.path.join(claude_home, "extensions", "defenseclaw"),
        os.path.join(codex_home, "extensions", "defenseclaw"),
        os.path.join(zepto_home, "extensions", "defenseclaw"),
        os.path.join(home, ".config", "amp", "plugins", "defenseclaw.ts"),
        os.path.join(home, ".config", "opencode", "plugins", "defenseclaw.js"),
    )


def first_party_self_reason(
    target: str | os.PathLike[str],
    *,
    trusted_paths: Iterable[str | os.PathLike[str]] = (),
) -> str | None:
    """Explain why *target* is an exact first-party artifact, if it is one.

    ``trusted_paths`` is reserved for concrete paths resolved from the active
    DefenseClaw configuration (for example a non-default OpenClaw home).  It
    does not accept name patterns or parent directories.
    """

    target_path = os.path.abspath(os.path.expanduser(os.fspath(target)))
    target_identity = canonical_path_identity(target_path)

    package_root = Path(__file__).resolve().parents[2]
    if target_identity == canonical_path_identity(package_root) and _looks_like_python_package(target_path):
        return "installed DefenseClaw Python package"

    expected = [*_default_connector_artifacts(), *(os.fspath(path) for path in trusted_paths)]
    expected_identities = {canonical_path_identity(path) for path in expected if os.fspath(path)}

    if os.path.isfile(target_path):
        if target_identity in expected_identities and _looks_like_bridge_file(target_path):
            return "installed DefenseClaw connector bridge"
        return None

    if not _looks_like_extension_root(target_path):
        return None

    source_root, reference_fingerprint = _immutable_extension_reference()

    # A link resolving to the canonical repository extension still compares
    # with repository-owned bytes.  Do not run the deployed-tree inventory on
    # the source root because that root intentionally also carries TypeScript,
    # tests, and lockfiles outside the dist-plugin runtime projection. The
    # exact checkout path also remains recognizable before its generated
    # ``dist/index.js`` exists; only relocated/deployed trees need a complete
    # immutable runtime fingerprint.
    if source_root is not None and target_identity == canonical_path_identity(source_root):
        return "repository DefenseClaw connector extension"
    if reference_fingerprint is None:
        return None

    try:
        target_fingerprint = fingerprint_deployed_runtime(target_path)
    except ExtensionFingerprintError:
        return None
    if target_fingerprint == reference_fingerprint:
        return "byte-identical DefenseClaw connector extension"
    return None


def is_first_party_self_target(
    target: str | os.PathLike[str],
    *,
    trusted_paths: Iterable[str | os.PathLike[str]] = (),
) -> bool:
    return first_party_self_reason(target, trusted_paths=trusted_paths) is not None


__all__ = [
    "canonical_path_identity",
    "first_party_self_reason",
    "is_first_party_self_target",
]
