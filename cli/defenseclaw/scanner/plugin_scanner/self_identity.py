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
* an exact connector-bridge path whose bytes match setup's publication lock;
* the repository-owned OpenClaw runtime projection; or
* a deployed runtime matching the immutable wheel/repository fingerprint.

Deployed extensions never act as their own reference and an expected install
path is not evidence of identity. Adding or changing a runtime file therefore
turns a relocated or installed copy back into an ordinary scan target.
Symlinks, reparse points, oversized trees, and malformed references never
qualify.
"""

from __future__ import annotations

import hashlib
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
_BRIDGE_CONNECTOR_BY_FILENAME = {
    "defenseclaw.js": "opencode",
    "defenseclaw.ts": "amp",
}
_BRIDGE_PUBLICATION_SCHEMA = {
    "amp": {
        "target_location_field": "hook_script_paths",
        "digest_filename": "defenseclaw.ts",
    },
    "opencode": {
        "target_location_field": "hook_config_paths",
        "digest_filename": "opencode-plugin.js",
    },
}
_BRIDGE_TEMPLATE_DIGESTS = {
    "amp": "7be90e8e95eadb6b121ed1f18bd799b50a75d5ab91d8ea4feb4b06f6c1607ff4",
    "opencode": "88ec1c1eec6570bd63316df66399e77e8b7f524c48fe71f91dad896440c6c029",
}
_BRIDGE_DYNAMIC_LINES = {
    "amp": (
        (
            b'const DC_API_ADDR = "',
            b'"\n',
            b'const DC_API_ADDR = "{{.APIAddr}}"\n',
            "api",
        ),
        (
            b'const DC_TOKEN_FILE = "',
            b'"\n',
            b'const DC_TOKEN_FILE = "{{.TokenFileJS}}"\n',
            "token",
        ),
        (
            b'const DC_FAIL_MODE: string = "',
            b'" // "open" or "closed"\n',
            b'const DC_FAIL_MODE: string = "{{.FailMode}}" // "open" or "closed"\n',
            "mode",
        ),
    ),
    "opencode": (
        (
            b'const DC_API_ADDR = "',
            b'";\n',
            b'const DC_API_ADDR = "{{.APIAddr}}";\n',
            "api",
        ),
        (
            b'const DC_TOKEN_FILE = "',
            b'";\n',
            b'const DC_TOKEN_FILE = "{{.TokenFileJS}}";\n',
            "token",
        ),
        (
            b'const DC_FAIL_MODE = "',
            b'"; // "open" or "closed"\n',
            b'const DC_FAIL_MODE = "{{.FailMode}}"; // "open" or "closed"\n',
            "mode",
        ),
    ),
}
_LOWER_HEX = frozenset("0123456789abcdef")


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


def _read_bounded_plain_file(
    path: str,
    maximum_bytes: int,
    *,
    require_private_owner: bool = False,
) -> bytes | None:
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
        if require_private_owner and os.name != "nt":
            if opened.st_uid != os.geteuid() or opened.st_mode & 0o077:
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


def _read_json_object(
    path: str,
    *,
    require_private_owner: bool = False,
) -> dict | None:
    payload = _read_bounded_plain_file(
        path,
        _MAX_MANIFEST_BYTES,
        require_private_owner=require_private_owner,
    )
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


def _bridge_file_payload(path: str) -> bytes | None:
    """Return bounded bridge bytes after the cheap product-marker gate."""

    payload = _read_bounded_plain_file(path, _MAX_BRIDGE_BYTES)
    if payload is None:
        return None
    try:
        source = payload.decode("utf-8", errors="strict")
    except UnicodeError:
        return None
    # Markers are only a cheap rejection gate. They never grant the exemption;
    # _matches_registered_bridge_publication also requires the exact bytes and
    # path recorded by connector setup's hook-contract publication lock.
    if "DefenseClaw" not in source or "/api/v1/" not in source:
        return None
    return payload


def _looks_like_bridge_file(path: str) -> bool:
    payload = _bridge_file_payload(path)
    return payload is not None and _matches_registered_bridge_publication(
        path,
        payload,
    )


def _hook_contract_lock_path() -> str:
    # Keep this aligned with the CLI's canonical data-root resolution,
    # including DEFENSECLAW_HOME and the sudo invoking-user fallback.
    from defenseclaw.config import default_data_path

    return os.path.abspath(
        os.path.expanduser(
            os.path.join(
                os.fspath(default_data_path()),
                "hook_contract_lock.json",
            )
        )
    )


def _valid_sha256_digest(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return ""
    digest = value.removeprefix("sha256:")
    if len(digest) != 64 or any(char not in _LOWER_HEX for char in digest):
        return ""
    return digest


def _valid_published_path(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value.strip() == value
        and not any(char in value for char in "\x00\r\n")
        and os.path.isabs(value)
        and os.path.normpath(value) == value
    )


def _valid_bridge_api_address(value: bytes) -> bool:
    try:
        address = value.decode("ascii", errors="strict")
    except UnicodeError:
        return False
    host, separator, port = address.rpartition(":")
    if not host or not separator or not port.isascii() or not port.isdecimal():
        return False
    try:
        port_number = int(port)
    except ValueError:
        return False
    if not 1 <= port_number <= 65535:
        return False
    # Setup supplies a host or IP literal, never JavaScript or URL syntax.
    return all(char.isalnum() or char in ".:-[]%" for char in host)


def _valid_bridge_dynamic_value(
    kind: str,
    value: bytes,
    *,
    connector: str,
    data_dir: str,
) -> bool:
    if kind == "api":
        return _valid_bridge_api_address(value)
    if kind == "mode":
        return value in {b"open", b"closed"}
    if kind != "token":
        return False
    try:
        token_path = json.loads('"' + value.decode("utf-8", errors="strict") + '"')
    except (UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(token_path, str):
        return False
    expected = os.path.abspath(
        os.path.join(data_dir, "hooks", f".hook-{connector}.token")
    )
    return os.path.normcase(token_path) == os.path.normcase(expected)


def _matches_immutable_bridge_template(
    connector: str,
    payload: bytes,
    *,
    data_dir: str,
) -> bool:
    """Verify all non-rendered bridge bytes against a packaged fingerprint."""

    specifications = _BRIDGE_DYNAMIC_LINES.get(connector)
    expected_digest = _BRIDGE_TEMPLATE_DIGESTS.get(connector)
    if specifications is None or expected_digest is None:
        return False
    lines = payload.splitlines(keepends=True)
    for prefix, suffix, canonical, kind in specifications:
        matches = [
            index
            for index, line in enumerate(lines)
            if line.startswith(prefix) and line.endswith(suffix)
        ]
        if len(matches) != 1:
            return False
        index = matches[0]
        value = lines[index][len(prefix) : -len(suffix)]
        if not _valid_bridge_dynamic_value(
            kind,
            value,
            connector=connector,
            data_dir=data_dir,
        ):
            return False
        lines[index] = canonical
    return hashlib.sha256(b"".join(lines)).hexdigest() == expected_digest


def _matches_registered_bridge_publication(path: str, payload: bytes) -> bool:
    """Match a dynamic bridge to setup's exact path-and-digest publication."""

    connector = _BRIDGE_CONNECTOR_BY_FILENAME.get(
        os.path.normcase(os.path.basename(path))
    )
    if connector is None:
        return False
    publication = _BRIDGE_PUBLICATION_SCHEMA[connector]

    lock_path = _hook_contract_lock_path()
    data_dir = os.path.dirname(lock_path)
    if not _matches_immutable_bridge_template(
        connector,
        payload,
        data_dir=data_dir,
    ):
        return False

    lock = _read_json_object(lock_path, require_private_owner=True)
    if lock is None or type(lock.get("version")) is not int:
        return False
    if not 1 <= lock["version"] <= 2:
        return False
    connectors = lock.get("connectors")
    entry = connectors.get(connector) if isinstance(connectors, dict) else None
    if not isinstance(entry, dict) or entry.get("connector") != connector:
        return False

    locations = entry.get("locations")
    published_paths = (
        locations.get(publication["target_location_field"])
        if isinstance(locations, dict)
        else None
    )
    if not isinstance(published_paths, list):
        return False
    target_identity = canonical_path_identity(path)
    path_matches = False
    for published_path in published_paths:
        if not _valid_published_path(published_path):
            continue
        if canonical_path_identity(published_path) == target_identity:
            path_matches = True
            break
    if not path_matches:
        return False

    digests = entry.get("hook_script_digests")
    if not isinstance(digests, dict):
        return False
    digest_filename = publication["digest_filename"]
    expected_digest = _valid_sha256_digest(digests.get(digest_filename))
    if not expected_digest:
        return False

    digest_payload = payload
    if connector == "opencode":
        # OpenCode's agent-visible plugin is a hook config publication, while
        # its durable hook-contract digest is keyed to the rendered source in
        # DEFENSECLAW_HOME/hooks. Bind both roles explicitly instead of
        # assuming the configured basename appears in hook_script_digests.
        expected_source_path = os.path.join(data_dir, "hooks", digest_filename)
        script_paths = locations.get("hook_script_paths")
        if not isinstance(script_paths, list) or not any(
            _valid_published_path(candidate)
            and canonical_path_identity(candidate)
            == canonical_path_identity(expected_source_path)
            for candidate in script_paths
        ):
            return False
        digest_payload = _read_bounded_plain_file(
            expected_source_path,
            _MAX_BRIDGE_BYTES,
        )
        if digest_payload is None:
            return False

        # Newer locks can additionally carry the configured plugin's direct
        # digest. When present, it must agree with the bytes being exempted.
        direct_digest = _valid_sha256_digest(
            digests.get(os.path.basename(path))
        )
        if direct_digest and hashlib.sha256(payload).hexdigest() != direct_digest:
            return False
    return hashlib.sha256(digest_payload).hexdigest() == expected_digest


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
