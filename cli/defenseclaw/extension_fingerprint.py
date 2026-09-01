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

"""Deterministic identity for the separately shipped OpenClaw extension.

The Python wheel and plugin archive are separate release artifacts.  This
module gives both builds one small, deterministic contract: a SHA-256 digest
over the exact files selected by ``make dist-plugin``.  Scanner exemptions can
then compare a deployed tree with repository-owned bytes during development or
with the reference embedded in an installed wheel.  A deployed tree is never
allowed to act as its own reference.

Keep this module standard-library-only.  The release staging helper imports it
before the DefenseClaw environment necessarily exists.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Final, NoReturn

REFERENCE_FORMAT: Final = "defenseclaw-openclaw-extension-runtime-v1"
REFERENCE_ALGORITHM: Final = "sha256"
REFERENCE_PACKAGE_PATH: Final = "_data/plugin/extension-runtime-fingerprint.json"

_TOP_LEVEL_FILES: Final = frozenset({"package.json", "openclaw.plugin.json"})
_RUNTIME_DIRECTORIES: Final = frozenset({"dist"})
_RUNTIME_NODE_PACKAGES: Final = frozenset({"argparse", "js-yaml"})
_MAX_FILES: Final = 1024
_MAX_DIRECTORIES: Final = 1024
_MAX_BYTES: Final = 64 * 1024 * 1024
_MAX_MANIFEST_BYTES: Final = 256 * 1024
_SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")


class ExtensionFingerprintError(ValueError):
    """The extension payload or reference is not a safe canonical runtime."""


def _lstat_plain(path: Path, *, directory: bool) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ExtensionFingerprintError(f"required extension path is unavailable: {path}") from exc
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(info, "st_file_attributes", 0)
    wanted = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not wanted or stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag):
        kind = "directory" if directory else "file"
        raise ExtensionFingerprintError(f"extension runtime path is not a plain {kind}: {path}")
    return info


def _read_manifest(root: Path, name: str) -> dict[str, object]:
    path = root / name
    info = _lstat_plain(path, directory=False)
    if info.st_size > _MAX_MANIFEST_BYTES:
        raise ExtensionFingerprintError(f"extension manifest exceeds the size limit: {name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExtensionFingerprintError(f"extension manifest is not valid UTF-8 JSON: {name}") from exc
    if not isinstance(value, dict):
        raise ExtensionFingerprintError(f"extension manifest must be a JSON object: {name}")
    return value


def _validate_product_identity(root: Path) -> None:
    package = _read_manifest(root, "package.json")
    plugin = _read_manifest(root, "openclaw.plugin.json")
    if package.get("name") != "defenseclaw":
        raise ExtensionFingerprintError("extension package name is not defenseclaw")
    if str(package.get("main") or "").replace("\\", "/") != "dist/index.js":
        raise ExtensionFingerprintError("extension package main is not dist/index.js")
    if plugin.get("id") != "defenseclaw":
        raise ExtensionFingerprintError("OpenClaw extension id is not defenseclaw")


def _is_runtime_relative(relative: str, *, directory: bool) -> bool:
    parts = relative.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        return False
    if len(parts) == 1:
        if directory:
            return parts[0] in _RUNTIME_DIRECTORIES or parts[0] == "node_modules"
        return parts[0] in _TOP_LEVEL_FILES
    if parts[0] in _RUNTIME_DIRECTORIES:
        return True
    if parts[0] == "node_modules" and len(parts) >= 2:
        if parts[1] not in _RUNTIME_NODE_PACKAGES:
            return False
        return True
    return False


def _raise_walk_error(error: OSError) -> NoReturn:
    raise ExtensionFingerprintError("extension runtime inventory is not fully readable") from error


def _walk_selected_directory(root: Path, relative_root: str) -> list[tuple[str, Path, int]]:
    selected = root
    for part in relative_root.split("/"):
        selected /= part
        _lstat_plain(selected, directory=True)
    rows: list[tuple[str, Path, int]] = []
    for current, directories, files in os.walk(
        selected,
        topdown=True,
        onerror=_raise_walk_error,
        followlinks=False,
    ):
        current_path = Path(current)
        for name in [*directories, *files]:
            child = current_path / name
            try:
                info = child.lstat()
            except OSError as exc:
                _raise_walk_error(exc)
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            attributes = getattr(info, "st_file_attributes", 0)
            if stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag):
                raise ExtensionFingerprintError(f"extension runtime contains link indirection: {child}")
        directories.sort(key=lambda value: value.casefold())
        files.sort(key=lambda value: value.casefold())
        for name in files:
            child = current_path / name
            info = _lstat_plain(child, directory=False)
            relative = child.relative_to(root).as_posix()
            rows.append((relative, child, info.st_size))
    return rows


def _repository_runtime_rows(root: Path) -> list[tuple[str, Path, int]]:
    """Select only files that the ``dist-plugin`` tar recipe publishes."""

    rows: list[tuple[str, Path, int]] = []
    for name in sorted(_TOP_LEVEL_FILES):
        path = root / name
        info = _lstat_plain(path, directory=False)
        rows.append((name, path, info.st_size))
    rows.extend(_walk_selected_directory(root, "dist"))
    for dependency in sorted(_RUNTIME_NODE_PACKAGES):
        path = root / "node_modules" / dependency
        if path.exists():
            rows.extend(_walk_selected_directory(root, f"node_modules/{dependency}"))
    return rows


def _deployed_runtime_rows(root: Path) -> list[tuple[str, Path, int]]:
    """Inventory an extracted plugin archive, rejecting every extra entry."""

    rows: list[tuple[str, Path, int]] = []
    normalized_paths: set[str] = set()
    total_bytes = 0
    directory_count = 0
    pending = [root]
    while pending:
        current_path = pending.pop()
        try:
            iterator = os.scandir(current_path)
        except OSError as exc:
            _raise_walk_error(exc)
        with iterator:
            for entry in iterator:
                child = Path(entry.path)
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    _raise_walk_error(exc)
                relative = child.relative_to(root).as_posix()
                normalized = relative.casefold()
                if normalized in normalized_paths:
                    raise ExtensionFingerprintError("extension runtime contains a case-insensitive path collision")
                normalized_paths.add(normalized)

                is_directory = stat.S_ISDIR(info.st_mode)
                is_file = stat.S_ISREG(info.st_mode)
                reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                attributes = getattr(info, "st_file_attributes", 0)
                if stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag):
                    raise ExtensionFingerprintError(f"extension runtime contains link indirection: {child}")
                if is_directory:
                    if not _is_runtime_relative(relative, directory=True):
                        raise ExtensionFingerprintError(
                            f"extension runtime contains an unexpected directory: {relative}"
                        )
                    directory_count += 1
                    if directory_count > _MAX_DIRECTORIES:
                        raise ExtensionFingerprintError("extension runtime exceeds the fingerprint bounds")
                    pending.append(child)
                    continue
                if not is_file:
                    raise ExtensionFingerprintError(f"extension runtime path is not a plain file: {child}")
                if not _is_runtime_relative(relative, directory=False):
                    raise ExtensionFingerprintError(f"extension runtime contains an unexpected file: {relative}")
                total_bytes += info.st_size
                if len(rows) + 1 > _MAX_FILES or total_bytes > _MAX_BYTES:
                    raise ExtensionFingerprintError("extension runtime exceeds the fingerprint bounds")
                rows.append((relative, child, info.st_size))
    return rows


def _fingerprint_rows(rows: list[tuple[str, Path, int]]) -> dict[str, object]:
    if not rows:
        raise ExtensionFingerprintError("extension runtime inventory is empty")
    rows.sort(key=lambda row: row[0])
    normalized = [relative.casefold() for relative, _path, _size in rows]
    if len(normalized) != len(set(normalized)):
        raise ExtensionFingerprintError("extension runtime contains a case-insensitive path collision")

    total = sum(size for _relative, _path, size in rows)
    if len(rows) > _MAX_FILES or total > _MAX_BYTES:
        raise ExtensionFingerprintError("extension runtime exceeds the fingerprint bounds")

    digest = hashlib.sha256()
    digest.update(REFERENCE_FORMAT.encode("ascii"))
    digest.update(b"\0")
    for relative, path, size in rows:
        try:
            encoded_relative = relative.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ExtensionFingerprintError("extension runtime path is not valid Unicode") from exc
        digest.update(encoded_relative)
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        try:
            with path.open("rb") as handle:
                while chunk := handle.read(128 * 1024):
                    digest.update(chunk)
        except OSError as exc:
            raise ExtensionFingerprintError(f"extension runtime file became unreadable: {relative}") from exc
        digest.update(b"\0")
    return {
        "algorithm": REFERENCE_ALGORITHM,
        "file_count": len(rows),
        "format": REFERENCE_FORMAT,
        "sha256": digest.hexdigest(),
        "total_bytes": total,
    }


def fingerprint_repository_runtime(root: str | os.PathLike[str]) -> dict[str, object]:
    """Fingerprint the canonical runtime projection of a source checkout."""

    path = Path(root)
    _lstat_plain(path, directory=True)
    _validate_product_identity(path)
    if not (path / "dist" / "index.js").is_file():
        raise ExtensionFingerprintError("canonical extension runtime is missing dist/index.js")
    return _fingerprint_rows(_repository_runtime_rows(path))


def fingerprint_deployed_runtime(root: str | os.PathLike[str]) -> dict[str, object]:
    """Fingerprint an exact extracted runtime tree with no source-only files."""

    path = Path(root)
    _lstat_plain(path, directory=True)
    _validate_product_identity(path)
    _lstat_plain(path / "dist" / "index.js", directory=False)
    return _fingerprint_rows(_deployed_runtime_rows(path))


def canonical_reference_bytes(document: dict[str, object]) -> bytes:
    """Validate and serialize one reference with stable cross-platform bytes."""

    validated = validate_reference(document)
    return (json.dumps(validated, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def validate_reference(document: object) -> dict[str, object]:
    expected_keys = {"algorithm", "file_count", "format", "sha256", "total_bytes"}
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise ExtensionFingerprintError("extension fingerprint reference has an invalid schema")
    if document.get("format") != REFERENCE_FORMAT or document.get("algorithm") != REFERENCE_ALGORITHM:
        raise ExtensionFingerprintError("extension fingerprint reference uses an unsupported format")
    digest = document.get("sha256")
    count = document.get("file_count")
    total = document.get("total_bytes")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise ExtensionFingerprintError("extension fingerprint reference has an invalid digest")
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= _MAX_FILES:
        raise ExtensionFingerprintError("extension fingerprint reference has an invalid file count")
    if not isinstance(total, int) or isinstance(total, bool) or not 0 <= total <= _MAX_BYTES:
        raise ExtensionFingerprintError("extension fingerprint reference has an invalid byte count")
    return {
        "algorithm": REFERENCE_ALGORITHM,
        "file_count": count,
        "format": REFERENCE_FORMAT,
        "sha256": digest,
        "total_bytes": total,
    }


def load_reference(path: str | os.PathLike[str]) -> dict[str, object]:
    reference = Path(path)
    _lstat_plain(reference, directory=False)
    try:
        if reference.stat().st_size > _MAX_MANIFEST_BYTES:
            raise ExtensionFingerprintError("extension fingerprint reference exceeds the size limit")
        document = json.loads(reference.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExtensionFingerprintError("extension fingerprint reference is not valid UTF-8 JSON") from exc
    return validate_reference(document)


__all__ = [
    "ExtensionFingerprintError",
    "REFERENCE_ALGORITHM",
    "REFERENCE_FORMAT",
    "REFERENCE_PACKAGE_PATH",
    "canonical_reference_bytes",
    "fingerprint_deployed_runtime",
    "fingerprint_repository_runtime",
    "load_reference",
    "validate_reference",
]
