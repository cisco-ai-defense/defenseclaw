# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Canonical filesystem identity for connector plugins.

Plugin identity is the connector plus the ID declared by the first supported
manifest.  Directory names are storage details and must not be used to merge
two manifest-backed plugins.
"""

from __future__ import annotations

import json
import ntpath
import os
import posixpath
import re
import stat
from dataclasses import dataclass
from typing import Any

import yaml

MANIFEST_FILES = (
    os.path.join(".codex-plugin", "plugin.json"),
    os.path.join(".claude-plugin", "plugin.json"),
    "plugin.json",
    "plugin.yaml",
    "plugin.yml",
    "package.json",
    "manifest.json",
    "openclaw.plugin.json",
)
_MAX_MANIFEST_BYTES = 1_048_576
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


class PluginIdentityError(ValueError):
    """The manifest identity or its physical representation is unsafe."""


class AmbiguousPluginIdentityError(PluginIdentityError):
    """More than one physical directory claims one connector identity."""


@dataclass(frozen=True)
class PluginPhysicalIdentity:
    plugin_id: str
    path: str
    manifest: str


def is_link_or_reparse(path: str) -> bool:
    """Return true for POSIX links and Windows reparse-point entries."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag)


def validate_plugin_id(value: object) -> str:
    """Validate an ID as one portable, non-special filesystem segment."""
    if not isinstance(value, str):
        raise PluginIdentityError("plugin manifest ID must be a string")
    plugin_id = value.strip()
    if not plugin_id:
        raise PluginIdentityError("plugin manifest ID must not be empty")
    if plugin_id in {".", ".."} or _CONTROL.search(plugin_id):
        raise PluginIdentityError("plugin manifest ID contains a special or control value")
    if any(char in plugin_id for char in ("/", "\\")):
        raise PluginIdentityError("plugin manifest ID must be a single path segment")
    if ntpath.isabs(plugin_id) or posixpath.isabs(plugin_id):
        raise PluginIdentityError("plugin manifest ID must not be an absolute path")
    if any(char in plugin_id for char in '<>:"|?*') or plugin_id.endswith((" ", ".")):
        raise PluginIdentityError("plugin manifest ID uses an unsafe or reserved path form")
    stem = plugin_id.split(".", 1)[0].casefold()
    if stem in _WINDOWS_RESERVED:
        raise PluginIdentityError("plugin manifest ID is a reserved device name")
    return plugin_id


def _regular_file_no_links(path: str, root: str) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if is_link_or_reparse(path) or not stat.S_ISREG(info.st_mode):
        return False
    current = os.path.dirname(path)
    root_abs = os.path.abspath(root)
    while os.path.abspath(current) != root_abs:
        if is_link_or_reparse(current):
            return False
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent
    real_root = os.path.realpath(root)
    real_path = os.path.realpath(path)
    return real_path != real_root and real_path.startswith(real_root + os.sep)


def read_plugin_manifest(plugin_path: str) -> tuple[dict[str, Any], str] | None:
    """Read the first supported bounded, regular manifest without links."""
    root = os.path.realpath(plugin_path)
    if is_link_or_reparse(plugin_path) or not os.path.isdir(root):
        raise PluginIdentityError("plugin source must be a regular directory, not a link")
    for rel in MANIFEST_FILES:
        path = os.path.join(plugin_path, rel)
        if not _regular_file_no_links(path, root):
            continue
        try:
            with open(path, "rb") as handle:
                raw = handle.read(_MAX_MANIFEST_BYTES + 1)
        except OSError as exc:
            raise PluginIdentityError(f"could not read plugin manifest {rel}: {exc}") from exc
        if len(raw) > _MAX_MANIFEST_BYTES:
            raise PluginIdentityError(f"plugin manifest {rel} exceeds size limit")
        try:
            text = raw.decode("utf-8")
            payload = yaml.safe_load(text) if rel.endswith((".yaml", ".yml")) else json.loads(text)
        except (UnicodeDecodeError, ValueError, yaml.YAMLError) as exc:
            raise PluginIdentityError(f"invalid plugin manifest {rel}: {exc}") from exc
        if not isinstance(payload, dict):
            raise PluginIdentityError(f"plugin manifest {rel} must contain an object")
        return payload, rel
    return None


def canonical_plugin_id(plugin_path: str) -> tuple[str, str]:
    """Return validated manifest ID, with basename fallback for legacy bundles."""
    manifest = read_plugin_manifest(plugin_path)
    if manifest is not None:
        payload, rel = manifest
        declared = payload.get("id") or payload.get("name")
        if declared is None:
            # Some supported connector manifests (notably Antigravity's
            # plugin.json contract) explicitly permit directory-name identity.
            return validate_plugin_id(os.path.basename(os.path.normpath(plugin_path))), rel
        return validate_plugin_id(declared), rel
    return validate_plugin_id(os.path.basename(os.path.normpath(plugin_path))), ""


def filesystem_identity_key(value: str, root: str) -> str:
    """Use case-insensitive collision rules only where the target FS does."""
    probe = os.path.join(root, "DcLaW-CaSe-PrObE")
    insensitive = os.path.normcase(probe) == os.path.normcase(probe.swapcase())
    current = os.path.abspath(root)
    while not insensitive:
        if os.path.exists(current):
            parent, base = os.path.split(current)
            swapped = os.path.join(parent, base.swapcase())
            if swapped != current and os.path.exists(swapped):
                try:
                    insensitive = os.path.samefile(current, swapped)
                except OSError:
                    pass
            if insensitive:
                break
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return value.casefold() if insensitive else value


def enumerate_physical_identities(root: str) -> list[PluginPhysicalIdentity]:
    """Read immediate plugin entries; reject links and path escapes."""
    if not os.path.exists(root):
        return []
    if is_link_or_reparse(root) or not os.path.isdir(root):
        raise PluginIdentityError(f"plugin root is not a regular directory: {root}")
    real_root = os.path.realpath(root)
    found: list[PluginPhysicalIdentity] = []
    try:
        entries = list(os.scandir(root))
    except OSError as exc:
        raise PluginIdentityError(f"could not enumerate plugin root {root}: {exc}") from exc
    for entry in entries:
        if entry.name.startswith(".dclaw-"):
            continue
        try:
            if entry.is_symlink() or is_link_or_reparse(entry.path):
                raise PluginIdentityError(f"linked plugin entry is not allowed: {entry.path}")
            if not entry.is_dir(follow_symlinks=False):
                continue
        except OSError as exc:
            raise PluginIdentityError(f"could not inspect plugin entry {entry.path}: {exc}") from exc
        real_path = os.path.realpath(entry.path)
        if not real_path.startswith(real_root + os.sep):
            raise PluginIdentityError(f"plugin entry escapes configured root: {entry.path}")
        plugin_id, manifest = canonical_plugin_id(entry.path)
        found.append(PluginPhysicalIdentity(plugin_id, entry.path, manifest))
    return found


def resolve_plugin_identity(root: str, plugin_id: str) -> PluginPhysicalIdentity | None:
    """Resolve exactly one physical claimant or fail closed on ambiguity."""
    requested = validate_plugin_id(plugin_id)
    key = filesystem_identity_key(requested, root)
    matches = [
        item for item in enumerate_physical_identities(root) if filesystem_identity_key(item.plugin_id, root) == key
    ]
    if len(matches) > 1:
        paths = ", ".join(item.path for item in matches)
        raise AmbiguousPluginIdentityError(
            f"ambiguous plugin identity {requested!r}: {paths}; remove or rename duplicate directories"
        )
    return matches[0] if matches else None
