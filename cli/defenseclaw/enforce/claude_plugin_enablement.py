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

"""Claude Code shows a quarantined plugin as disabled (rel-1-0-6:GAP-0289).

``plugin quarantine`` moves the plugin's files and the hook refuses the
plugin, but Claude Code's own ``enabledPlugins`` still said ``true``, so
``claude plugin list`` showed the plugin enabled. Quarantine now sets the
plugin's ``true`` entries in the user's Claude Code settings to ``false`` and
records which ones it changed; ``plugin restore`` sets exactly those back to
``true``. Other entries, and an entry the user changed in between, are left
as they are.
"""

from __future__ import annotations

import json
import os
import stat
from typing import Any

from defenseclaw.connector_paths import (
    MCPWriteUnsupportedError,
    _locked_claude_file_update,
    _write_private_config,
    claude_config_dir,
)

# Records of the entries quarantine disabled, next to the plugin quarantine
# tree (never inside it, where a file would read as a quarantined plugin).
RECORD_DIR = "claude-enabled-plugins"
_MAX_SETTINGS_BYTES = 4 << 20


class SettingsNotChangedError(Exception):
    """The Claude Code settings were left as they are; the message says why."""


def settings_path() -> str:
    return os.path.join(claude_config_dir(), "settings.json")


def _record_path(quarantine_dir: str, plugin: str) -> str:
    base = os.path.dirname(os.path.abspath(quarantine_dir))
    return os.path.join(base, RECORD_DIR, plugin.replace("/", "_") + ".json")


def _check_settings_file(path: str) -> bool:
    """False when there is no settings file. Raises SettingsNotChangedError for a
    file this command must not replace: a link (a dotfiles checkout), not a
    regular file, too large, or (POSIX) owned by another account, as under
    sudo with HOME kept: replacing it would leave the user a root-owned
    settings file Claude Code cannot read (rel-1-0-6:GAP-0289 review)."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        raise SettingsNotChangedError(f"{path} is a link; not changed")
    if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_SETTINGS_BYTES:
        raise SettingsNotChangedError(f"{path} is not a plain settings file; not changed")
    if os.name != "nt" and info.st_uid != os.geteuid():
        raise SettingsNotChangedError(f"{path} belongs to another user; not changed")
    return True


def _read_settings(path: str) -> tuple[bytes, dict[str, Any]] | None:
    """The settings bytes and object, or None when there is no file or it is
    not a JSON object (never rewritten then)."""
    if not _check_settings_file(path):
        return None
    with open(path, "rb") as handle:
        raw = handle.read(_MAX_SETTINGS_BYTES + 1)
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        return None
    return (raw, doc) if isinstance(doc, dict) else None


def _write_settings(path: str, original: bytes, doc: dict[str, Any]) -> bool:
    """Replace the settings unless they changed since they were read."""
    _check_settings_file(path)
    with open(path, "rb") as handle:
        if handle.read(_MAX_SETTINGS_BYTES + 1) != original:
            return False
    _write_private_config(path, (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    return True


def _same_plugin(key: Any, plugin: str) -> bool:
    return isinstance(key, str) and key.split("@", 1)[0].casefold() == plugin.casefold()


def _read_record(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as handle:
            record = json.load(handle)
    except (OSError, ValueError):
        return {}
    return record if isinstance(record, dict) else {}


def _put_record_back(record_path: str, previous: bytes | None) -> None:
    """Undo a record write whose settings change did not happen, so restore
    never turns on an entry quarantine did not turn off."""
    try:
        if previous is None:
            os.unlink(record_path)
        else:
            _write_private_config(record_path, previous)
    except OSError:
        pass


def disable_for_quarantine(plugin: str, quarantine_dir: str) -> list[str]:
    """Set the plugin's enabled entries to false; return the keys changed.

    Raises SettingsNotChangedError when the settings file must be left alone."""
    path = settings_path()
    if not _check_settings_file(path):
        return []
    record_path = _record_path(quarantine_dir, plugin)
    with _locked_claude_file_update(path, label="Claude Code settings lock"):
        for _ in range(3):
            loaded = _read_settings(path)
            if loaded is None:
                return []
            raw, doc = loaded
            enabled = doc.get("enabledPlugins")
            if not isinstance(enabled, dict):
                return []
            keys = [key for key, value in enabled.items() if value is True and _same_plugin(key, plugin)]
            if not keys:
                return []
            try:
                with open(record_path, "rb") as handle:
                    previous_raw: bytes | None = handle.read()
            except OSError:
                previous_raw = None
            previous = [key for key in _read_record(record_path).get("keys", []) if isinstance(key, str)]
            # The record is written first: restore must know every entry
            # quarantine turned off, also after a crash between the writes.
            os.makedirs(os.path.dirname(record_path), mode=0o700, exist_ok=True)
            _write_private_config(
                record_path,
                json.dumps({"settings": path, "keys": sorted(set(previous) | set(keys))}, indent=2).encode("utf-8"),
            )
            for key in keys:
                enabled[key] = False
            try:
                written = _write_settings(path, raw, doc)
            except BaseException:
                _put_record_back(record_path, previous_raw)
                raise
            if written:
                return keys
            _put_record_back(record_path, previous_raw)
    raise SettingsNotChangedError(f"{path} kept changing while it was being updated; not changed")


def restore_after_quarantine(plugin: str, quarantine_dir: str) -> list[str]:
    """Set back to true the entries quarantine turned off; return them.

    Raises SettingsNotChangedError when the settings file must be left alone."""
    record_path = _record_path(quarantine_dir, plugin)
    record = _read_record(record_path)
    keys = [key for key in record.get("keys", []) if isinstance(key, str)]
    if not keys:
        return []
    path = record.get("settings") if isinstance(record.get("settings"), str) else settings_path()
    if not _check_settings_file(path):
        return []
    with _locked_claude_file_update(path, label="Claude Code settings lock"):
        for _ in range(3):
            loaded = _read_settings(path)
            if loaded is None:
                return []
            raw, doc = loaded
            enabled = doc.get("enabledPlugins")
            # An entry the user removed or set again stays as the user left it.
            restored = [key for key in keys if isinstance(enabled, dict) and enabled.get(key) is False]
            for key in restored:
                enabled[key] = True
            if not restored or _write_settings(path, raw, doc):
                try:
                    os.unlink(record_path)
                except OSError:
                    pass
                return restored
    raise SettingsNotChangedError(f"{path} kept changing while it was being updated; not changed")


__all__ = [
    "MCPWriteUnsupportedError",
    "SettingsNotChangedError",
    "disable_for_quarantine",
    "restore_after_quarantine",
    "settings_path",
]
