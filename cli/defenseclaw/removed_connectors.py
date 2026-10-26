# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""until 1.1: what is left of OpenHands and OmniGent on a host an older release set up.

DefenseClaw no longer supports either agent. The gateway teardown of these
teardown-only connectors (``internal/gateway/connector/removed.go``) removes
what an older setup wrote for them, by identity, and never blocks anything:
DefenseClaw's entries in their agent configs, its hook script or policy
module, its import-path line, tokens, runtime record, receipts and lock
entry. :func:`leftovers` lists what that teardown could not remove, as
information, under :data:`NOTICE`, for ``defenseclaw status``, ``defenseclaw
doctor``, ``defenseclaw uninstall`` and the installers. It only reads. The Go
side lists the same (``RemovedConnectorLeftovers``).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

import yaml

# The one line every surface prints (removed.go RemovedConnectorNotice).
NOTICE = "OpenHands/OmniGent support was removed in 1.0.5; DefenseClaw no longer guards it."

# removed.go removedConfigReadLimit and removedScriptReadLimit.
_READ_LIMIT = 256 << 20
_SCRIPT_LIMIT = 1 << 20
_MARKER_LINES = 3
_MODULE = "defenseclaw_omnigent_policy"
_POLICY_KEY = "defenseclaw_guardrail"
_BOM = b"\xef\xbb\xbf"


@dataclass(frozen=True)
class _Removed:
    name: str
    label: str
    script: str
    marker: str
    config_file: str
    default_dir: str
    config_step: str
    kind: str


_CONNECTORS: tuple[_Removed, ...] = (
    _Removed(
        name="openhands",
        label="OpenHands",
        script="openhands-hook.sh",
        marker="# defenseclaw-managed-hook v",
        config_file="hooks.json",
        default_dir=".openhands",
        config_step=(
            "remove every hook whose command runs openhands-hook.sh (or defenseclaw-hook --connector openhands) "
            "from this file, then restart OpenHands"
        ),
        kind="hook script",
    ),
    _Removed(
        name="omnigent",
        label="OmniGent",
        script=_MODULE + ".py",
        marker="# defenseclaw-managed-policy v",
        config_file="config.yaml",
        default_dir=".omnigent",
        config_step=(
            f"remove {_MODULE} from policy_modules and the {_POLICY_KEY} policy (handler "
            f"{_MODULE}.defenseclaw_policy) from this file, then restart OmniGent"
        ),
        kind="policy module",
    ),
)

NAMES: tuple[str, ...] = tuple(c.name for c in _CONNECTORS)


def is_removed(name: str | None) -> bool:
    """Recognize OpenHands or OmniGent, including the old OpenHands ID aliases."""
    return isinstance(name, str) and name.strip().casefold() in {*NAMES, "open-hands", "open_hands"}


# How a Windows hooks.json command names the OpenHands connector of the
# native launcher (defenseclaw-hook --connector openhands).
_LAUNCHER_FLAG = re.compile(r"--connector(?:\s*=\s*|\s+)[\"']?open[-_]?hands\b", re.IGNORECASE)


def _has_marker(data: bytes, marker: str) -> bool:
    head = data.split(b"\n", _MARKER_LINES)[:_MARKER_LINES]
    return any(line.strip().startswith(marker.encode()) for line in head)


def _read_candidate(path: str) -> bytes | None:
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > _SCRIPT_LIMIT:
            return None
        with open(path, "rb") as fh:
            return fh.read(_SCRIPT_LIMIT + 1)
    except OSError:
        return None


def _runs_marked_hook(text: str) -> bool:
    """Whether a command runs a file holding DefenseClaw's OpenHands hook (removed.go removedRunsMarkedHook)."""
    for word in text.split():
        word = word.strip("\"';,")
        if not (os.path.isabs(word) or word.startswith("~/")):
            continue
        data = _read_candidate(os.path.abspath(os.path.expanduser(word)))
        if data and _has_marker(data, _CONNECTORS[0].marker) and b"openhands" in data.lower():
            return True
    return False


# The characters that may stand next to a path in a command (removed.go removedWordEdge).
_WORD_EDGE = " \t\r\n\"'`=;&|()"


def _runs_path(text: str, paths: list[str]) -> bool:
    """Whether a command names one of *paths* whole, never a longer name ending in it (removed.go removedRunsPath)."""

    def fold(value: str) -> str:
        return value.replace("\\", "/").lower() if os.name == "nt" else value

    text = fold(text)
    for path in paths:
        word = fold(path)
        start = text.find(word) if word else -1
        while start >= 0:
            end = start + len(word)
            if (start == 0 or text[start - 1] in _WORD_EDGE) and (end == len(text) or text[end] in _WORD_EDGE):
                return True
            start = text.find(word, start + 1)
    return False


def _owned_hook_paths(data_dir: str, c: _Removed, home: str) -> list[str]:
    """The paths an older setup wrote the hook script to, as a command names them (removed.go ownedHookPaths)."""
    if not data_dir:
        return []
    paths = [os.path.join(_absolute(data_dir), "hooks", c.script)]
    locations = _lock_entry(data_dir, c).get("locations")
    recorded = locations.get("hook_script_paths") if isinstance(locations, dict) else None
    if isinstance(recorded, list):
        paths += [_absolute(p) for p in recorded if isinstance(p, str) and os.path.basename(p) == c.script]
    home = _absolute(home) if home else ""
    for path in list(paths):
        if home and _is_under(path, home) and _key(path) != _key(home):
            paths.append("~/" + os.path.relpath(path, home).replace(os.sep, "/"))
    return list(dict.fromkeys(paths))


def _text_names(c: _Removed, text: str, paths: list[str]) -> bool:
    """Whether one config text (a command, a module name) is DefenseClaw's (removed.go namesFor).

    An OpenHands command is DefenseClaw's only when it runs DefenseClaw's hook
    script by its path (*paths*), runs a file that carries the hook marker, or
    names the launcher's OpenHands connector; the script name alone is not
    identity (GAP-1842).
    """
    if c.name == "omnigent":
        return _MODULE in text.lower()
    return bool(_LAUNCHER_FLAG.search(text)) or _runs_path(text, paths) or _runs_marked_hook(text)


def _value_names(c: _Removed, value: object, paths: list[str]) -> bool:
    """Whether a string or key anywhere in a decoded JSON or YAML value names DefenseClaw's entries."""
    stack, seen = [value], set()
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if _text_names(c, item, paths):
                return True
        elif isinstance(item, (dict, list, tuple)):
            # YAML aliases share one object: visit it once.
            if id(item) in seen:
                continue
            seen.add(id(item))
            if isinstance(item, dict):
                for key, val in item.items():
                    if _text_names(c, str(key), paths):
                        return True
                    stack.append(val)
            else:
                stack.extend(item)
    return False


def _config_names(c: _Removed, data: bytes, paths: list[str]) -> tuple[bool, str]:
    """Whether an agent config still names DefenseClaw's entries, and why it could not be checked."""
    if _text_names(c, data.decode("utf-8", "replace"), paths):
        return True, ""
    if len(data) > _READ_LIMIT:
        return False, f"it is larger than {_READ_LIMIT >> 20} MiB"
    body = data[len(_BOM) :] if data.startswith(_BOM) else data
    if not body.strip():
        return False, ""
    try:
        text = body.decode("utf-8")
        doc = json.loads(text) if c.name == "openhands" else yaml.safe_load(text)
    except (UnicodeDecodeError, ValueError, yaml.YAMLError, RecursionError) as exc:
        kind = "JSON" if c.name == "openhands" else "YAML"
        return False, f"it is not {kind}: {exc}"
    return _value_names(c, doc, paths), ""


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.normpath(left)) == os.path.normcase(os.path.normpath(right))


def _pth_has_line(pth: str, hooks: str) -> bool:
    try:
        with open(pth, "rb") as fh:
            data = fh.read(_READ_LIMIT + 1)
    except OSError:
        return False
    if data.startswith(_BOM):
        data = data[len(_BOM) :]
    for line in data.decode("utf-8", "replace").split("\n"):
        line = line.strip()
        if line and not line.startswith("#") and _same_path(line, hooks):
            return True
    return False


@dataclass(frozen=True)
class Leftover:
    path: str
    what: str
    step: str


@dataclass(frozen=True)
class RemovedConnectorLeftovers:
    """What the teardown of one removed connector left on this host (information only)."""

    connector: str
    label: str
    items: tuple[Leftover, ...]

    def as_json(self) -> dict:
        return {
            "connector": self.connector,
            "label": self.label,
            "notice": NOTICE,
            "items": [{"path": i.path, "what": i.what, "step": i.step} for i in self.items],
        }

    def lines(self, *, without_under: str = "", moved: dict[str, str] | None = None) -> list[str]:
        """Text lines for a person: the notice, then each item; items under *without_under* are left out.

        An item under a folder in *moved* (old path to new path) is named at
        its new path and is listed even under *without_under*.
        """
        items: list[Leftover] = []
        for item in self.items:
            path = _moved_path(item.path, moved or {})
            if path == item.path and without_under and _is_under(item.path, without_under):
                continue
            items.append(Leftover(path, item.what, item.step))
        if not items:
            return []
        return [NOTICE] + [f"  - {i.path}: {i.what}. To remove: {i.step}." for i in items]


def _moved_path(path: str, moved: dict[str, str]) -> str:
    for old, new in moved.items():
        if _same_path(path, old):
            return new
        if _is_under(path, old):
            return os.path.join(new, os.path.relpath(path, old))
    return path


def kept_backups_root(data_dir: str) -> str:
    """Where a data folder removal moves what is left in the removed connectors' backup folders.

    The gateway teardown removes the setup receipts there; anything else (a
    copy 1.0.4 saved of an edited OmniGent module) is the user's. So
    ``uninstall --all`` and Windows Setup (DELETEUSERDATA=1) move it beside
    the data folder before they remove it: ``<data folder>-removed-connector-
    backups/<connector>``. Windows Setup uses the same name
    (removedConnectorBackupsKeptRoot).
    """
    return os.path.normpath(data_dir) + "-removed-connector-backups"


def backup_dirs(data_dir: str) -> list[tuple[str, str]]:
    """(connector, connector_backups/<connector> folder) for each removed connector that has one."""
    out: list[tuple[str, str]] = []
    for c in _CONNECTORS:
        path = os.path.join(data_dir, "connector_backups", c.name)
        if os.path.lexists(path):
            out.append((c.name, path))
    return out


def _is_under(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == os.path.abspath(root)
    except ValueError:
        return False


def _key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _absolute(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    return os.path.abspath(os.path.expanduser(value))


def _json_file(path: str) -> dict:
    try:
        if os.path.getsize(path) > _READ_LIMIT:
            return {}
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _backup_target(data_dir: str, name: str, logical: str) -> str:
    record = _json_file(os.path.join(data_dir, "connector_backups", name, logical + ".json"))
    if record.get("connector") != name or record.get("logical_name") != logical:
        return ""
    path = record.get("path")
    return path.strip() if isinstance(path, str) else ""


def _lock_entry(data_dir: str, c: _Removed) -> dict:
    lock = _json_file(os.path.join(data_dir, "hook_contract_lock.json"))
    connectors = lock.get("connectors")
    entry = connectors.get(c.name) if isinstance(connectors, dict) else None
    return entry if isinstance(entry, dict) else {}


def _lock_config_paths(data_dir: str, c: _Removed) -> list[str]:
    locations = _lock_entry(data_dir, c).get("locations")
    paths = locations.get("hook_config_paths") if isinstance(locations, dict) else None
    if not isinstance(paths, list):
        return []
    return [_absolute(p) for p in paths if isinstance(p, str) and os.path.basename(p).lower() == c.config_file]


def _lock_workspace(data_dir: str, c: _Removed) -> str:
    posture = _lock_entry(data_dir, c).get("registration_posture")
    workspace = posture.get("workspace_dir") if isinstance(posture, dict) else None
    return workspace if isinstance(workspace, str) else ""


def _config_paths(data_dir: str, c: _Removed, home: str, workspace: str = "") -> list[str]:
    """The agent configs an older setup may have changed (removed.go configPaths)."""
    paths: list[str] = []
    workspaces = [workspace]
    if data_dir:
        paths.append(_backup_target(data_dir, c.name, "config"))
        paths.extend(_lock_config_paths(data_dir, c))
        workspaces.append(_lock_workspace(data_dir, c))
    paths.append(os.path.join(home, c.default_dir, c.config_file))
    if c.name == "openhands":
        for root in workspaces:
            root = _absolute(root)
            if root and not (data_dir and _is_under(root, data_dir)):
                paths.append(os.path.join(root, c.default_dir, c.config_file))
    if c.name == "omnigent":
        paths.append(_absolute(os.environ.get("OMNIGENT_CONFIG", "")))
        env_home = _absolute(os.environ.get("OMNIGENT_CONFIG_HOME", ""))
        if env_home:
            paths.append(os.path.join(env_home, c.config_file))
    out: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if path and _key(path) not in seen:
            seen.add(_key(path))
            out.append(path)
    return out


def _leftovers_of(data_dir: str, c: _Removed, home: str, workspace: str = "") -> list[Leftover]:
    items: list[Leftover] = []
    owned = _owned_hook_paths(data_dir, c, home)
    for path in _config_paths(data_dir, c, home, workspace):
        try:
            if not os.path.exists(path):
                continue
            with open(path, "rb") as fh:
                data = fh.read(_READ_LIMIT + 1)
        except OSError as exc:
            items.append(Leftover(path, f"could not be read ({exc})", "check it by hand: " + c.config_step))
            continue
        names, why = _config_names(c, data, owned)
        if names:
            items.append(
                Leftover(path, f"still names DefenseClaw's {c.label} entries, which DefenseClaw could not remove",
                         c.config_step)
            )
        elif why:
            items.append(Leftover(path, f"could not be checked ({why})", "check it by hand: " + c.config_step))
    if not data_dir:
        return items
    hooks = os.path.join(data_dir, "hooks")
    if c.name == "omnigent":
        pth = _backup_target(data_dir, c.name, "pth")
        if pth and _pth_has_line(pth, hooks):
            items.append(
                Leftover(
                    pth,
                    "adds DefenseClaw's hook folder to OmniGent's Python import path",
                    f"remove only the line {hooks} from this file (delete the file when that was its only line)",
                )
            )
    script = os.path.join(hooks, c.script)
    data = _read_candidate(script)
    if data is not None and _has_marker(data, c.marker):
        items.append(Leftover(script, f"DefenseClaw's old {c.label} {c.kind}", "delete it once nothing above runs it"))
    for token in (os.path.join(hooks, f".hook-{c.name}.token"), os.path.join(hooks, f".otlp-{c.name}.token")):
        if os.path.lexists(token):
            items.append(Leftover(token, f"a DefenseClaw token for {c.label}; nothing accepts it", "delete it"))
    record = os.path.join(hooks, f".hookcfg.{c.name}")
    if os.path.lexists(record):
        items.append(Leftover(record, f"DefenseClaw's old {c.label} hook settings; nothing reads them", "delete it"))
    backups = os.path.join(data_dir, "connector_backups", c.name)
    if os.path.lexists(backups):
        items.append(
            Leftover(backups, f"files DefenseClaw saved when it set up {c.label}",
                     "copy back what you need, then delete this folder")
        )
    return items


def leftovers(data_dir: str, *, home: str | None = None, workspace: str = "") -> list[RemovedConnectorLeftovers]:
    """Return what each removed connector left on this host (none when nothing is left).

    *workspace* is the configured connector workspace (``claw.workspace_dir``),
    where a workspace-pinned 1.0.x OpenHands setup registered its hook.
    """
    home = home or os.path.expanduser("~")
    out: list[RemovedConnectorLeftovers] = []
    for c in _CONNECTORS:
        items = _leftovers_of(data_dir or "", c, home, workspace or "")
        if items:
            out.append(RemovedConnectorLeftovers(c.name, c.label, tuple(items)))
    return out


def configured(config_path: str) -> bool:
    """Whether ``config.yaml`` still names OpenHands or OmniGent as a connector (before the upgrade migrates it)."""
    try:
        with open(config_path, encoding="utf-8") as handle:
            raw = yaml.safe_load(handle.read(_READ_LIMIT))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return False
    if not isinstance(raw, dict):
        return False
    guardrail = raw.get("guardrail") if isinstance(raw.get("guardrail"), dict) else {}
    claw = raw.get("claw") if isinstance(raw.get("claw"), dict) else {}
    connectors = guardrail.get("connectors")
    names = [*(connectors if isinstance(connectors, dict) else {}), guardrail.get("connector"), claw.get("mode")]
    return any(is_removed(str(name)) for name in names if name)


def found(data_dir: str) -> bool:
    """Whether an older setup of OpenHands or OmniGent is on this host: something it left, or the config names it.

    The installers ask before the upgrade (the new gateway's first start
    removes what it can), so they can print :data:`NOTICE` once after it.
    """
    return bool(leftovers(data_dir)) or configured(os.path.join(data_dir or "", "config.yaml"))


def installer_lines(data_dir: str, found_before: bool) -> list[str]:
    """The installers' lines after an upgrade: :data:`NOTICE` once, then what is left.

    Nothing when no older setup was found before the upgrade and nothing is
    left now.
    """
    left = leftovers(data_dir)
    if not left and not found_before:
        return []
    return [NOTICE] + [line for item in left for line in item.lines()[1:]]
