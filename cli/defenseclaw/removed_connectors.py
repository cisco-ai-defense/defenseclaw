# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""until 1.1: what the removed OpenHands and OmniGent connectors leave on a host.

DefenseClaw 1.0.4 removed both connectors (#1182). Their teardown
(``internal/gateway/connector/removed.go``) does two things only: it replaces
the hook script an older DefenseClaw wrote (OpenHands' ``openhands-hook.sh``,
OmniGent's policy module), proven by its DefenseClaw marker, with a stub that
blocks every call, and it revokes the connector's tokens, except the OpenHands
hook token: an old OpenHands hook, or a copy of it in the hooks folder, that
finds no token lets every call run in fail mode open. Everything else
stays. :func:`leftovers` lists it, with the step to remove each item by hand,
for ``defenseclaw status``, ``defenseclaw doctor`` and ``defenseclaw
uninstall``. It only reads. The Go side lists the same for ``connector
teardown`` and Windows Setup (``RemovedConnectorLeftovers``). Delete this
module in 1.1.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass

import yaml

_READ_LIMIT = 16 << 20
_SCRIPT_LIMIT = 1 << 20
_MARKER_LINES = 3
# Every stub the 1.0.4 teardown writes says this; the stubs an older teardown
# left (they allowed every call) do not.
STUB_PHRASE = "support was removed in DefenseClaw 1.0.4"
_MODULE = "defenseclaw_omnigent_policy"
_POLICY_KEY = "defenseclaw_guardrail"
# A removed connector's script that is gone while an agent config still runs
# or imports it: that agent does not block its calls (removed.go
# RemovedScriptGoneWhat). doctor fails on it.
SCRIPT_GONE_WHAT = (
    "gone, while an agent config above still runs or imports it, so DefenseClaw does not block those calls"
)
# A removed connector's stub the agent may not run or load (its mode is not
# one that works, or another account owns it): that agent may let its calls
# through (removed.go RemovedStubUnusableWhat). doctor fails on it.
STUB_UNUSABLE_WHAT = (
    "the stub, but with a mode or owner that may keep the agent from running or loading it, "
    "so DefenseClaw may not block those calls"
)


@dataclass(frozen=True)
class _Removed:
    name: str
    label: str
    script: str
    marker: str
    config_file: str
    default_dir: str
    config_what: str
    config_step: str
    # The mode the teardown writes the stub with (removed.go mode).
    mode: int
    # Mirrors removed.go keepHookToken until the removed connectors expire.
    keep_hook_token: bool = False


_CONNECTORS: tuple[_Removed, ...] = (
    _Removed(
        name="openhands",
        label="OpenHands",
        script="openhands-hook.sh",
        marker="# defenseclaw-managed-hook v",
        config_file="hooks.json",
        default_dir=".openhands",
        config_what="OpenHands still runs DefenseClaw's hook from here; it blocks every call",
        config_step=(
            "remove every hook whose command runs openhands-hook.sh (or defenseclaw-hook --connector openhands) "
            "from this file, then restart OpenHands"
        ),
        keep_hook_token=True,
        mode=0o700,
    ),
    _Removed(
        name="omnigent",
        label="OmniGent",
        script=_MODULE + ".py",
        marker="# defenseclaw-managed-policy v",
        config_file="config.yaml",
        default_dir=".omnigent",
        config_what="OmniGent still imports DefenseClaw's policy module from here; it denies every request",
        config_step=(
            f"remove {_MODULE} from policy_modules and the {_POLICY_KEY} policy (handler "
            f"{_MODULE}.defenseclaw_policy) from this file, then restart OmniGent"
        ),
        mode=0o600,
    ),
)

NAMES: tuple[str, ...] = tuple(c.name for c in _CONNECTORS)
KEPT_HOOK_TOKEN_NAMES: frozenset[str] = frozenset(c.name for c in _CONNECTORS if c.keep_hook_token)


def is_removed(name: str | None) -> bool:
    """Recognize a connector removed in 1.0.4, including its old ID aliases."""
    return isinstance(name, str) and name.strip().casefold() in {*NAMES, "open-hands", "open_hands"}

# How a Windows hooks.json command names the OpenHands connector of the
# native launcher (defenseclaw-hook --connector openhands).
_LAUNCHER_FLAG = re.compile(r"--connector(?:\s*=\s*|\s+)[\"']?open[-_]?hands\b", re.IGNORECASE)
_BOM = b"\xef\xbb\xbf"


def _text_names(c: _Removed, text: str) -> bool:
    """Whether one config text (a command, a module name) names the script."""
    lower = text.lower()
    if c.name == "omnigent":
        return _MODULE in lower
    return "openhands-hook.sh" in lower or bool(_LAUNCHER_FLAG.search(text))


def _script_names(c: _Removed, text: str) -> bool:
    """Whether one config text runs or imports the script file itself.

    A Windows registration of the native launcher (``--connector openhands``)
    needs no script: the launcher reaches the retired route, which blocks.
    """
    return (_MODULE if c.name == "omnigent" else "openhands-hook.sh") in text.lower()


def _value_names(c: _Removed, value: object, names=_text_names) -> bool:
    """Whether a string or key anywhere in a decoded JSON or YAML value names the script."""
    stack, seen = [value], set()
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if names(c, item):
                return True
        elif isinstance(item, (dict, list, tuple)):
            # YAML aliases share one object: visit it once.
            if id(item) in seen:
                continue
            seen.add(id(item))
            if isinstance(item, dict):
                for key, val in item.items():
                    if names(c, str(key)):
                        return True
                    stack.append(val)
            else:
                stack.extend(item)
    return False


def _config_names(c: _Removed, data: bytes, names=_text_names) -> tuple[bool, str]:
    """Whether an agent config still runs or imports the script, and why it could not be checked.

    The bytes and the decoded values (JSON for hooks.json, YAML for
    config.yaml) are checked, so a name written with escapes is found too.
    """
    if names(c, data.decode("utf-8", "replace")):
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
    return _value_names(c, doc, names), ""


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.normpath(left)) == os.path.normcase(os.path.normpath(right))


def _pth_leftover(pth: str, hooks: str) -> Leftover | None:
    """OmniGent's import-path file, while it still holds DefenseClaw's line (the hook folder)."""
    line_step = (
        f"remove only the line {hooks} (DefenseClaw's hook folder) from this file, and keep every other line, "
        f"once no OmniGent config.yaml names {_MODULE}"
    )
    try:
        if not os.path.exists(pth):
            return None
        with open(pth, "rb") as fh:
            data = fh.read(_READ_LIMIT + 1)
        if len(data) > _READ_LIMIT:
            raise OSError(f"it is larger than {_READ_LIMIT >> 20} MiB")
    except OSError as exc:
        return Leftover(pth, f"could not be read ({exc})", "check it by hand: " + line_step)
    if data.startswith(_BOM):
        data = data[len(_BOM) :]
    own = other = False
    for line in data.decode("utf-8", "replace").split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if _same_path(line, hooks):
            own = True
        else:
            other = True
    if not own:
        return None
    what = "adds DefenseClaw's hook folder to OmniGent's Python import path"
    if other:
        return Leftover(pth, what + "; it holds other import paths too", line_step)
    return Leftover(
        pth, what + "; it holds nothing else", f"delete this file once no OmniGent config.yaml names {_MODULE}"
    )


@dataclass(frozen=True)
class Leftover:
    path: str
    what: str
    step: str


@dataclass(frozen=True)
class RemovedConnectorLeftovers:
    """What one removed connector left on this host."""

    connector: str
    label: str
    items: tuple[Leftover, ...]

    def as_json(self) -> dict:
        return {
            "connector": self.connector,
            "label": self.label,
            "items": [{"path": i.path, "what": i.what, "step": i.step} for i in self.items],
        }

    def lines(self, *, without_under: str = "", moved: dict[str, str] | None = None) -> list[str]:
        """Text lines for a person; items under *without_under* are left out.

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
        return [f"{self.label} support was removed in DefenseClaw 1.0.4. Left for you to remove by hand:"] + [
            f"  - {i.path}: {i.what}. To remove: {i.step}." for i in items
        ]


def _moved_path(path: str, moved: dict[str, str]) -> str:
    for old, new in moved.items():
        if _same_path(path, old):
            return new
        if _is_under(path, old):
            return os.path.join(new, os.path.relpath(path, old))
    return path


def kept_backups_root(data_dir: str) -> str:
    """Where a data folder removal moves the removed connectors' backups.

    connector_backups/<connector> holds the only copy of the files as they
    were before an older DefenseClaw's setup changed them (the removed
    connectors' teardown never puts them back), and the leftover list tells
    the user to copy back what they need from it. So ``uninstall --all`` and
    Windows Setup (DELETEUSERDATA=1) move it beside the data folder before
    they remove it: ``<data folder>-removed-connector-backups/<connector>``.
    Windows Setup uses the same name (removedConnectorBackupsKeptRoot).
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
    paths: list[str] = []
    workspaces = [workspace]
    if data_dir:
        paths.append(_backup_target(data_dir, c.name, "config"))
        paths.extend(_lock_config_paths(data_dir, c))
        workspaces.append(_lock_workspace(data_dir, c))
    paths.append(os.path.join(home, c.default_dir, c.config_file))
    if c.name == "openhands":
        # A 1.0.x setup with a pinned workspace (claw.workspace_dir, or the
        # one its lock entry records) wrote the repo-local
        # <workspace>/.openhands/hooks.json instead, unless the workspace was
        # inside the data directory (removed.go configPaths).
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


def _script_state(path: str, c: _Removed) -> str:
    """absent, stub, owned (an older release wrote it), foreign, or an error text."""
    if not os.path.lexists(path):
        return "absent"
    if os.path.islink(path) or not os.path.isfile(path):
        return "foreign"
    try:
        if os.path.getsize(path) > _SCRIPT_LIMIT:
            return "foreign"
        with open(path, "rb") as fh:
            data = fh.read(_SCRIPT_LIMIT + 1)
    except OSError as exc:
        return f"could not be read ({exc})"
    head = data.split(b"\n", _MARKER_LINES)[:_MARKER_LINES]
    if not any(line.strip().startswith(c.marker.encode()) for line in head):
        return "foreign"
    if STUB_PHRASE.encode() not in data:
        return "owned"
    return "unusable" if _stub_unusable(path, c) else "stub"


def _stub_unusable(path: str, c: _Removed) -> bool:
    """Whether the agent may not run or load the stub, or another account may change it.

    The same check as removed.go removedStubMetadataRefusal: its owner cannot
    read it, an OpenHands stub is not executable by its owner, others may
    write it, or another account than the hooks folder's owner owns it. No
    such check applies on Windows.
    """
    if os.name == "nt":
        return False
    try:
        info = os.lstat(path)
        folder = os.stat(os.path.dirname(path))
    except OSError:
        return True
    perm = info.st_mode & 0o777
    if not perm & 0o400 or (c.mode & 0o100 and not perm & 0o100) or perm & 0o022:
        return True
    return info.st_uid != folder.st_uid


def _links(path: str) -> int:
    try:
        return os.stat(path).st_nlink
    except OSError:
        return 1


def _hard_link_step(c: _Removed, script: str) -> str:
    lister = f"fsutil hardlink list {script}" if os.name == "nt" else f"find / -xdev -samefile {script}"
    return (
        "copy back what you need from connector_backups before deleting any linked name there; "
        f"delete every other name of this file ({lister} lists them), then run "
        f"defenseclaw-gateway connector teardown --connector {c.name}, which writes the stub and revokes the tokens"
    )


def _foreign_step(c: _Removed) -> str:
    return (
        "if it is not yours, delete it; if it is, move it out of DefenseClaw's hooks folder; then run "
        f"defenseclaw-gateway connector teardown --connector {c.name}, which revokes the tokens"
    )


def _kept_token(c: _Removed, token: str) -> Leftover:
    # The teardown keeps the OpenHands hook token (removed.go keepHookToken).
    what = (
        f"the {c.label} hook token, which DefenseClaw keeps: an old {c.label} hook ({c.script} or a copy of it in "
        "this folder) that finds no token lets every call run in fail mode open; with it, the hook reaches the "
        "gateway, which blocks every call. Nothing in DefenseClaw 1.0.4 accepts it"
    )
    step = (
        f"delete it only once no {c.label} hooks.json, in your home or in any workspace, runs {c.script} "
        f"or a copy of it, and {c.label} was restarted"
    )
    return Leftover(token, what, step)


def _stub_publication_receipt(data_dir: str, c: _Removed) -> str:
    """Find the read-only marker for an interrupted module CAS publication."""
    script = os.path.abspath(os.path.join(data_dir, "hooks", c.script))
    digest = hashlib.sha256(os.fsencode(script)).hexdigest()[:24]
    name = f".defenseclaw-cas-{digest}.intent"
    for folder in (
        os.path.join(data_dir, "connector_backups", c.name),
        os.path.join(data_dir, "hooks", ".defenseclaw-cas-state"),
    ):
        for suffix in ("", ".complete"):
            candidate = os.path.join(folder, name + suffix)
            if os.path.lexists(candidate):
                return candidate
    return ""


def _leftovers_of(data_dir: str, c: _Removed, home: str, workspace: str = "") -> list[Leftover]:
    items: list[Leftover] = []
    teardown = f"run defenseclaw-gateway connector teardown --connector {c.name}"
    # A config that runs or imports the script file, or that could not be read
    # or checked (it may).
    runs_script = False
    for path in _config_paths(data_dir, c, home, workspace):
        try:
            if not os.path.exists(path):
                continue
            with open(path, "rb") as fh:
                data = fh.read(_READ_LIMIT + 1)
        except OSError as exc:
            items.append(Leftover(path, f"could not be read ({exc})", "check it by hand: " + c.config_step))
            runs_script = True
            continue
        script_named, script_why = _config_names(c, data, _script_names)
        runs_script = runs_script or script_named or bool(script_why)
        names, why = _config_names(c, data)
        if names:
            items.append(Leftover(path, c.config_what, c.config_step))
        elif why:
            items.append(
                Leftover(
                    path,
                    f"could not be checked ({why}), so it may still name DefenseClaw's hook",
                    "check it by hand: " + c.config_step,
                )
            )
    if not data_dir:
        return items
    hooks = os.path.join(data_dir, "hooks")
    if c.name == "omnigent":
        pth = _backup_target(data_dir, c.name, "pth")
        left = _pth_leftover(pth, hooks) if pth else None
        if left:
            items.append(left)
    script = os.path.join(hooks, c.script)
    publication_receipt = _stub_publication_receipt(data_dir, c)
    state = _script_state(script, c)
    # The teardown keeps the tokens while an old hook may still run at the
    # script path (removed.go hookLeft): they go once its step is done.
    token_step = teardown
    links = _links(script) if state == "owned" else 1
    if state == "stub":
        items.append(
            Leftover(script, f"the stub that blocks every {c.label} call", "delete it once nothing above runs it")
        )
    elif state == "unusable":
        items.append(Leftover(script, STUB_UNUSABLE_WHAT, f"{teardown}, which puts it right"))
    elif state == "owned" and links > 1:
        what = (
            f"still the hook script an older DefenseClaw wrote, with {links} names (hard links); teardown leaves it "
            "and its tokens, so every name still reaches the gateway, which blocks every call"
        )
        items.append(Leftover(script, what, _hard_link_step(c, script)))
        token_step = f"follow the step for {script} first"
    elif state == "owned":
        items.append(Leftover(script, "still the hook script an older DefenseClaw wrote", teardown))
    elif state == "foreign":
        what = (
            "not changed: DefenseClaw cannot prove it wrote it (a link, no DefenseClaw marker in its first lines, "
            "or not a regular file); teardown keeps its tokens, so an old hook here still reaches the gateway, "
            "which blocks every call"
        )
        items.append(Leftover(script, what, _foreign_step(c)))
        token_step = f"follow the step for {script} first"
    elif state == "absent":
        if runs_script:
            step = f"{teardown}, which writes the stub that blocks every call; or {c.config_step}"
            items.append(Leftover(script, SCRIPT_GONE_WHAT, step))
    else:
        items.append(Leftover(script, state, "delete it once nothing above runs it"))
    if publication_receipt:
        items.append(
            Leftover(
                publication_receipt,
                "interrupted publication of the stub that blocks every call; cleanup is incomplete",
                teardown + " before deleting saved copies or tokens; keep this receipt if teardown reports an error",
            )
        )
    if c.name == "openhands":
        record = os.path.join(hooks, ".hookcfg.openhands")
        if os.path.lexists(record):
            what = "the runtime settings of the removed hook; DefenseClaw no longer reads it"
            items.append(Leftover(record, what, "delete it"))
    backups = os.path.join(data_dir, "connector_backups", c.name)
    if os.path.lexists(backups):
        backup_step = "copy back what you need, then delete this folder"
        if publication_receipt:
            backup_step = "do not delete this folder until " + teardown + " has recovered the interrupted publication"
        items.append(
            Leftover(
                backups,
                "the copies of your files DefenseClaw saved before its setup changed them (pristine_bytes, base64)",
                backup_step,
            )
        )
    if c.name == "omnigent" and os.path.isdir(backups):
        # The teardown saves an edited policy module there before it writes
        # the stub (removed.go keepEdited).
        for entry in sorted(os.listdir(backups)):
            if entry.startswith(c.script + ".edited-"):
                items.append(
                    Leftover(
                        os.path.join(backups, entry),
                        f"your edited {c.script}, as it was when the teardown replaced it with the stub that blocks "
                        "every call",
                        "copy back what you need (not into DefenseClaw's hooks folder), then delete it",
                    )
                )
    hook_token = os.path.join(hooks, f".hook-{c.name}.token")
    if c.keep_hook_token and os.path.lexists(hook_token):
        items.append(_kept_token(c, hook_token))
        hook_token = ""
    for token in (hook_token, os.path.join(hooks, f".otlp-{c.name}.token")):
        if token and os.path.lexists(token):
            items.append(Leftover(token, "a DefenseClaw token for the removed connector", token_step))
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
