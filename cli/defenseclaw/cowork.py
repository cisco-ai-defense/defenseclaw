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

"""Claude Cowork, per-user route: the DefenseClaw account plugin.

Cowork (the agent mode of Claude Desktop) does not read
``~/.claude/settings.json``. It loads hooks from the plugins of the user's
Claude account and runs them on this device as the user. ``defenseclaw setup
cowork`` builds a plugin zip whose ``hooks/hooks.json`` the Go gateway renders
(``defenseclaw-gateway connector cowork-plugin``): the Claude Code connector's
own per-user handler, so Cowork events reach the gateway's Claude Code hook
route. The user uploads the zip in Claude (Customize > Plugins > Add > Upload
plugin); DefenseClaw cannot add or remove an account plugin itself.

This module holds the plugin files, the state ``setup cowork`` records under
``<data_dir>/cowork/``, and the Cowork row that ``status`` and ``doctor``
show. Managed hosts are covered by machine policy and get no row here.
"""

from __future__ import annotations

import glob
import hashlib
import io
import json
import ntpath
import os
import stat
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from defenseclaw.file_permissions import atomic_write_private_bytes
from defenseclaw.inventory.claude_desktop import GLOB_MAX, claude_desktop_data_dirs, desktop_platform

PLUGIN_NAME = "defenseclaw"
STATE_DIR = "cowork"
ZIP_NAME = "defenseclaw-cowork-plugin.zip"
STATE_NAME = "plugin-state.json"
UNINSTALLED_SUFFIX = ".cowork-uninstalled"
# The gateway's last Cowork hook call (Go gateway.CoworkActivityFile), kept
# across gateway restarts (cowork-1-0-8 GAP-0038).
ACTIVITY_NAME = "gateway-activity.json"
_ACTIVITY_MAX_BYTES = 4096

# The events connector.CoworkPluginHookEvents registers (Claude Desktop
# 4.4212.0, engine 2.1.309). A rendered document naming any other event is
# refused before it is zipped.
COWORK_EVENTS = frozenset(
    {
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "PostToolUseFailure",
        "SubagentStart",
        "SubagentStop",
        "Stop",
        "SessionEnd",
    }
)

UPLOAD_PATH_TEXT = "Customize > Plugins > Add > Upload plugin"
REMOVE_PATH_TEXT = "Customize > Plugins, then the ... menu > Remove"

_STATE_MAX_BYTES = 64 * 1024
_ZIP_DATE = (1980, 1, 1, 0, 0, 0)
_BUNDLED_GUARD = "hooks/defenseclaw-hook-guard.exe"
_BUNDLED_GUARD_COMMAND = "${CLAUDE_PLUGIN_ROOT}/" + _BUNDLED_GUARD
_GUARD_MAX_BYTES = 64 * 1024 * 1024


def state_dir(data_dir: str) -> str:
    return os.path.join(os.fspath(data_dir), STATE_DIR)


def zip_path(data_dir: str) -> str:
    return os.path.join(state_dir(data_dir), ZIP_NAME)


def state_path(data_dir: str) -> str:
    return os.path.join(state_dir(data_dir), STATE_NAME)


def uninstalled_marker_path(data_dir: str) -> str:
    return os.path.normpath(os.fspath(data_dir)) + UNINSTALLED_SUFFIX


def mark_uninstalled(data_dir: str) -> None:
    """Record a completed per-user removal outside the removed data folder.

    Raises OSError when the folder that holds the marker is unsafe; on Windows
    that is a folder whose owner or writers are outside the Windows owner
    trust set. Such a folder gets no marker: its owner controls it, and the
    plugin's guard ignores a marker there anyway (cowork-1-0-8 GAP-0085).
    """
    marker = uninstalled_marker_path(data_dir)
    for suffix in (".notice", ".context"):
        try:
            os.rmdir(marker + suffix)
        except OSError:
            pass
    atomic_write_private_bytes(
        marker,
        b"removed\n",
        protect_parent=False,
    )


def clear_uninstalled_marker(data_dir: str) -> None:
    """A new Cowork build is an installed account again."""
    marker = uninstalled_marker_path(data_dir)
    try:
        os.unlink(marker)
    except FileNotFoundError:
        pass
    for suffix in (".notice", ".context"):
        try:
            os.rmdir(marker + suffix)
        except OSError:
            pass


def load_state(data_dir: str) -> dict[str, Any]:
    """The recorded plugin state, or {} when setup cowork never ran."""
    try:
        with open(state_path(data_dir), "rb") as fh:
            raw = fh.read(_STATE_MAX_BYTES + 1)
    except OSError:
        return {}
    if len(raw) > _STATE_MAX_BYTES:
        return {}
    try:
        state = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}


def recorded_gateway_activity(data_dir: str) -> datetime | None:
    """The last Cowork hook call the gateway recorded in the cowork folder,
    also before its last restart; None when there is none (GAP-0038)."""
    try:
        with open(os.path.join(state_dir(data_dir), ACTIVITY_NAME), "rb") as fh:
            raw = fh.read(_ACTIVITY_MAX_BYTES + 1)
    except OSError:
        return None
    if len(raw) > _ACTIVITY_MAX_BYTES:
        return None
    try:
        activity = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return parse_timestamp(activity.get("last_activity_at")) if isinstance(activity, dict) else None


def save_state(data_dir: str, state: dict[str, Any]) -> None:
    _atomic_write(state_path(data_dir), (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def _atomic_write(path: str, data: bytes) -> None:
    from defenseclaw.file_permissions import atomic_write_private_bytes

    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    atomic_write_private_bytes(path, data)


def _zip_build(data_dir: str) -> int:
    """The build number of the plugin zip already on disk (1.0.<build>), or 0."""
    try:
        with zipfile.ZipFile(zip_path(data_dir)) as zf:
            version = json.loads(zf.read(".claude-plugin/plugin.json")).get("version", "")
        major, minor, build = str(version).split(".")
        return int(build) if (major, minor) == ("1", "0") else 0
    except (OSError, KeyError, ValueError, zipfile.BadZipFile, AttributeError):
        return 0


def next_version(state: dict[str, Any], now: datetime | None = None, data_dir: str = "") -> tuple[int, str]:
    """The next build number and plugin version: every build is newer.

    The build number is the build time (YYYYMMDDHHMMSS), and at least one
    more than the recorded one and the one in the zip on disk, so a lost
    state file never reuses a version an account already holds.
    """
    stamp = int((now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y%m%d%H%M%S"))
    try:
        previous = int(state.get("build", 0))
    except (TypeError, ValueError):
        previous = 0
    if data_dir:
        previous = max(previous, _zip_build(data_dir))
    build = max(stamp, max(previous, 0) + 1)
    return build, f"1.0.{build}"


def validate_hooks_document(doc: Any) -> dict[str, Any]:
    """Check the gateway's hooks.json shape before it is zipped."""
    if not isinstance(doc, dict) or set(doc) != {"hooks"} or not isinstance(doc["hooks"], dict):
        raise ValueError("the gateway returned a hooks document without a top-level hooks map")
    hooks = doc["hooks"]
    if set(hooks) != COWORK_EVENTS:
        missing = sorted(COWORK_EVENTS - set(hooks))
        extra = sorted(set(hooks) - COWORK_EVENTS)
        raise ValueError(f"the gateway's Cowork hook events differ (missing {missing}, extra {extra})")
    for event, groups in hooks.items():
        if not isinstance(groups, list) or not groups:
            raise ValueError(f"{event}: no hook group")
        for group in groups:
            handlers = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(handlers, list) or not handlers:
                raise ValueError(f"{event}: a hook group without handlers")
            for handler in handlers:
                if (
                    not isinstance(handler, dict)
                    or handler.get("type") != "command"
                    or not str(handler.get("command") or "").strip()
                ):
                    raise ValueError(f"{event}: a handler that is not a DefenseClaw command")
    return doc


def plugin_manifest(version: str, defenseclaw_version: str) -> dict[str, Any]:
    return {
        "name": PLUGIN_NAME,
        "version": version,
        "description": (
            "DefenseClaw inspects every Cowork prompt and tool call on this device before it runs, "
            f"can block it, and audits it. Built by defenseclaw setup cowork (DefenseClaw {defenseclaw_version}) "
            "for one account on one device."
        ),
        "author": {"name": "DefenseClaw"},
    }


def _bundled_windows_hooks(hooks_doc: dict[str, Any]) -> tuple[dict[str, Any], bytes | None]:
    """Keep the Windows account hook runnable after installed binaries are removed."""
    handlers = [handler for groups in hooks_doc["hooks"].values() for group in groups for handler in group["hooks"]]
    cowork_handlers = [handler for handler in handlers if (handler.get("args") or [None])[0] == "cowork-guard"]
    if not cowork_handlers:
        return hooks_doc, None
    if len(cowork_handlers) != len(handlers):
        raise ValueError("the Cowork plugin mixes Windows guard and other handlers")
    source = cowork_handlers[0].get("command")
    if any(handler.get("command") != source for handler in cowork_handlers):
        raise ValueError("the Cowork plugin names different Windows guards")
    if (
        not isinstance(source, str)
        or not os.path.isabs(source)
        or os.path.basename(source).lower() != "defenseclaw-hook-guard.exe"
    ):
        raise ValueError("the Cowork plugin has no installed Windows guard")
    for event, groups in hooks_doc["hooks"].items():
        for group in groups:
            for handler in group["hooks"]:
                args = handler.get("args")
                if (
                    not isinstance(args, list)
                    or len(args) != 4
                    or args[0] != "cowork-guard"
                    or not all(isinstance(arg, str) for arg in args)
                    or not os.path.isabs(args[1])
                    or not os.path.isabs(args[2])
                    or os.path.basename(args[2]).lower() != "defenseclaw-hook.exe"
                    or args[3] != event
                    or os.path.normcase(source) == os.path.normcase(args[2])
                ):
                    raise ValueError("the Cowork plugin has an invalid Windows guard invocation")
    before = os.lstat(source)
    if not stat.S_ISREG(before.st_mode) or before.st_size > _GUARD_MAX_BYTES:
        raise ValueError("the installed Windows guard is not a regular file of supported size")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(source, flags)
    with os.fdopen(fd, "rb") as guard_file:
        opened = os.fstat(guard_file.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("the installed Windows guard changed while building the plugin")
        guard = guard_file.read(_GUARD_MAX_BYTES + 1)
    if len(guard) > _GUARD_MAX_BYTES:
        raise ValueError("the installed Windows guard exceeds the plugin size limit")
    bundled = json.loads(json.dumps(hooks_doc))
    for groups in bundled["hooks"].values():
        for group in groups:
            for handler in group["hooks"]:
                handler["command"] = _BUNDLED_GUARD_COMMAND
    return bundled, guard


def plugin_zip_bytes(hooks_doc: dict[str, Any], version: str, defenseclaw_version: str) -> bytes:
    """Build the account plugin, including its Windows guard when needed.

    Cowork does not accept a top-level bin/ folder. A guard under hooks/ is
    owned by the plugin, so the account hook remains runnable after uninstall.
    Fixed timestamps make the same inputs give the same bytes.
    """
    hooks_doc, guard = _bundled_windows_hooks(hooks_doc)
    entries = {
        ".claude-plugin/plugin.json": plugin_manifest(version, defenseclaw_version),
        "hooks/hooks.json": hooks_doc,
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=_ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, json.dumps(entries[name], indent=2) + "\n")
        if guard is not None:
            info = zipfile.ZipInfo(_BUNDLED_GUARD, date_time=_ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o755 << 16
            zf.writestr(info, guard)
    return buf.getvalue()


def write_plugin_zip(data_dir: str, data: bytes) -> tuple[str, str]:
    path = zip_path(data_dir)
    _atomic_write(path, data)
    return path, hashlib.sha256(data).hexdigest()


# BUILTIN\\Administrators: the default owner of what an elevated token creates.
_ADMINISTRATORS_SID = "S-1-5-32-544"


def plugin_write_refusal(data_dir: str, exc: OSError) -> str:
    """One sentence for a plugin zip DefenseClaw would not or could not write.

    The private-file writer refuses a folder another account owns. On Windows
    that is a ``cowork`` folder an elevated session created before the CLI
    made the user the owner of what it creates (cowork-1-0-8 GAP-0050,
    GAP-0054): BUILTIN\\Administrators owns it. The sentence names the folder,
    the cause and the fix (icacls by SID, as doctor does).
    """
    folder = os.path.dirname(zip_path(data_dir))
    if os.name == "nt":
        try:
            from defenseclaw.file_permissions import _windows_acl_snapshot, _windows_current_user_sid

            owner_sid = _windows_acl_snapshot(folder)[0]
            if owner_sid == _ADMINISTRATORS_SID:
                return (
                    f"Cannot build the Cowork plugin: {folder} belongs to the Administrators group because it was "
                    "created from an elevated administrator session. From an elevated prompt run: "
                    f'icacls "{folder}" /setowner "*{_windows_current_user_sid()}" /T /C /Q, '
                    "then run defenseclaw setup cowork again."
                )
        except (OSError, ValueError, IndexError):
            pass
    return (
        f"Cannot build the Cowork plugin in {folder}: {exc}. Fix the folder, then run defenseclaw setup cowork again."
    )


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def cowork_activity_from_health(health: Any) -> dict[str, datetime]:
    """Cowork activity the gateway reports on its Claude Code connector.

    The gateway marks a Claude Code hook call from Cowork's host loop (its
    hook process carries CLAUDE_CODE_IS_COWORK=1) and reports it under
    ``connectors[name=claudecode].surfaces.cowork`` with
    ``last_activity_at`` and ``last_session_start_at``. A gateway that
    reports neither has seen no Cowork call since it started.
    """
    if not isinstance(health, dict):
        return {}
    rows = health.get("connectors")
    if not isinstance(rows, list):
        rows = []
    single = health.get("connector")
    if isinstance(single, dict):
        rows = [*rows, single]
    for row in rows:
        if not isinstance(row, dict) or str(row.get("name") or "").strip().lower() != "claudecode":
            continue
        surfaces = row.get("surfaces")
        cowork = surfaces.get("cowork") if isinstance(surfaces, dict) else None
        if not isinstance(cowork, dict):
            return {}
        out: dict[str, datetime] = {}
        for key in ("last_activity_at", "last_session_start_at"):
            if (stamp := parse_timestamp(cowork.get(key))) is not None:
                out[key] = stamp
        return out
    return {}


def _claude_desktop_dirs(platform: str | None = None) -> list[str]:
    platform = platform or desktop_platform()
    dirs: list[str] = []
    if platform == "darwin":
        dirs += ["/Applications/Claude.app", os.path.join(os.path.expanduser("~"), "Applications", "Claude.app")]
    elif platform == "windows":
        local = os.environ.get("LOCALAPPDATA", "")
        if local and os.path.isabs(local):
            # The installer's app folder and the MSIX package folder.
            dirs.append(os.path.join(local, "AnthropicClaude"))
            dirs += sorted(glob.glob(os.path.join(local, "Packages", "Claude_*")))[:GLOB_MAX]
    return dirs + claude_desktop_data_dirs(platform)


def claude_desktop_installed() -> bool:
    """Whether Claude Desktop is installed or has run for this account."""
    return any(os.path.isdir(path) for path in _claude_desktop_dirs())


def open_claude() -> bool:
    """Start Claude Desktop; True when the request was handed to the OS."""
    try:
        if sys.platform == "darwin":
            result = subprocess.run(
                ["/usr/bin/open", "-b", "com.anthropic.claudefordesktop"],
                capture_output=True,
                timeout=15,
                check=False,
            )
            return result.returncode == 0
        if os.name == "nt":
            os.startfile("claude://")  # type: ignore[attr-defined]  # noqa: S606 - fixed URL, no shell
            return True
        result = subprocess.run(["xdg-open", "claude://"], capture_output=True, timeout=15, check=False)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def file_dialog_hint() -> str:
    if sys.platform == "darwin":
        return "in the file dialog press Cmd+Shift+G and paste the path"
    if os.name == "nt":
        return "paste the path into the File name box"
    return "press Ctrl+L in the file dialog and paste the path"


def upload_steps(path: str) -> list[str]:
    return [
        f"In Claude Desktop open {UPLOAD_PATH_TEXT}.",
        f"Choose this file ({file_dialog_hint()}): {path}",
        "Wait until Claude finishes checking the plugin (about 2 minutes), then start a Cowork task.",
    ]


@dataclass(frozen=True)
class CoworkStatus:
    """The Cowork row of status and doctor."""

    protected: bool
    detail: str
    step: str = ""
    reason_code: str = ""
    last_event_at: str = ""
    plugin_version: str = ""
    plugin_zip: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "protected": self.protected,
            "detail": self.detail,
            "step": self.step,
            "reason_code": self.reason_code,
            "last_event_at": self.last_event_at or None,
            "plugin_version": self.plugin_version or None,
            "plugin_zip": self.plugin_zip or None,
        }


def _claudecode_enabled(cfg: Any) -> bool:
    try:
        actives = [str(c).strip().lower() for c in (cfg.active_connectors() or [])]
    except Exception:  # noqa: BLE001 - an unreadable roster is "not set up"
        return False
    if "claudecode" not in actives:
        return False
    gc = getattr(cfg, "guardrail", None)
    if gc is None or not hasattr(gc, "effective_enabled"):
        return True
    try:
        return bool(gc.effective_enabled("claudecode")) and bool(getattr(gc, "enabled", True))
    except Exception:  # noqa: BLE001 - an unreadable switch is not proof that the hooks run
        return False


def claudecode_mode(cfg: Any) -> str:
    """The Claude Code connector's effective guardrail mode: action or observe."""
    gc = getattr(cfg, "guardrail", None)
    try:
        mode = str(gc.effective_mode("claudecode") or "").strip().lower() if gc is not None else ""
    except Exception:  # noqa: BLE001 - unknown reads as the record-only default
        mode = ""
    return "action" if mode == "action" else "observe"


OBSERVE_HINT = "turn on blocking with: defenseclaw setup claude-code --mode action"


def mode_text(cfg: Any) -> str:
    """How Cowork calls are treated, for the setup message and the status row."""
    if claudecode_mode(cfg) == "action":
        return "action mode: policy hits are blocked"
    return f"observe mode: records only; {OBSERVE_HINT}"


def managed_host(cfg: Any) -> str:
    """Name the managed deployment of this host, or ""."""
    if str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise":
        return "managed_enterprise"
    try:
        from defenseclaw.upgrade_shim import managed_deployment

        return managed_deployment() or ""
    except Exception:  # noqa: BLE001 - no marker readable: not managed here
        return ""


def _utc_text(stamp: datetime) -> str:
    return stamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def windows_plugin_hooks_need_rebuild(zip_file: str) -> bool:
    """Whether a readable Windows plugin archive lacks the current guard form."""
    if sys.platform != "win32":
        return False
    try:
        with zipfile.ZipFile(zip_file) as zf, zf.open("hooks/hooks.json") as entry:
            raw = entry.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            return True
        doc = json.loads(raw)
    except (OSError, KeyError, ValueError, zipfile.BadZipFile):
        return False
    hooks = doc.get("hooks") if isinstance(doc, dict) else None
    if not isinstance(hooks, dict) or set(hooks) != COWORK_EVENTS:
        return True
    for event, groups in hooks.items():
        if not isinstance(groups, list) or not groups:
            return True
        for group in groups:
            handlers = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(handlers, list) or not handlers:
                return True
            for handler in handlers:
                if not isinstance(handler, dict):
                    return True
                args = handler.get("args")
                if (
                    handler.get("command") != _BUNDLED_GUARD_COMMAND
                    or not isinstance(args, list)
                    or len(args) != 4
                    or args[0] != "cowork-guard"
                    or not all(isinstance(arg, str) for arg in args)
                    or not ntpath.isabs(args[1])
                    or not ntpath.isabs(args[2])
                    or ntpath.basename(args[2]).lower() != "defenseclaw-hook.exe"
                    or args[3] != event
                ):
                    return True
    return False


def cowork_status(
    cfg: Any,
    health: Any,
    *,
    gateway_running: bool,
    health_authenticated: bool = True,
    claudecode_skipped: bool = False,
) -> CoworkStatus | None:
    """The Cowork row, or None when Cowork plays no part on this account.

    Cowork counts as protected only on evidence for the current plugin build:
    Cowork activity in the gateway's authenticated status, a Cowork event
    setup recorded after this build, or the gateway's own record of its last
    Cowork call after this build (kept across a gateway restart, GAP-0038).
    A rebuild clears the recorded event (setup cowork), so an upload that
    never happened does not read as protected. Every other case names the
    missing step.
    """
    if managed_host(cfg):
        return None
    data_dir = str(getattr(cfg, "data_dir", "") or "")
    state = load_state(data_dir) if data_dir else {}
    if not state:
        if not claude_desktop_installed():
            return None
        return CoworkStatus(
            False,
            "not protected: Claude Desktop is installed, but Cowork has no DefenseClaw plugin",
            "defenseclaw setup cowork",
            "cowork_plugin_not_built",
        )
    version = str(state.get("version") or "")
    zip_file = str(state.get("zip") or zip_path(data_dir))
    built_at = parse_timestamp(state.get("built_at"))
    recorded = parse_timestamp(state.get("last_event_at"))
    persisted = recorded_gateway_activity(data_dir)
    live = (
        cowork_activity_from_health(health).get("last_activity_at")
        if health_authenticated and gateway_running
        else None
    )
    stale_live = None
    if built_at is None:
        # A state without a valid build time (hand-edited or legacy) proves
        # no build: no event counts for it.
        recorded = live = persisted = None
    else:
        if recorded is not None and recorded < built_at:
            recorded = None
        if persisted is not None and persisted < built_at:
            stale_live, persisted = persisted, None
        # Activity the gateway saw before this build came from an earlier
        # plugin (or none): the account may not hold this build yet.
        if live is not None and live < built_at:
            stale_live, live = live, None
    confirmed_earlier = max((t for t in (recorded, persisted) if t is not None), default=None)
    last = max((t for t in (confirmed_earlier, live) if t is not None), default=None)
    common = {"last_event_at": last.isoformat() if last else "", "plugin_version": version, "plugin_zip": zip_file}
    upload = f"upload {zip_file} in Claude ({UPLOAD_PATH_TEXT}), then start a Cowork task"
    if not _claudecode_enabled(cfg):
        return CoworkStatus(
            False,
            "not protected: the Claude Code connector, whose hooks the Cowork plugin runs, is off",
            "defenseclaw setup claude-code",
            "cowork_claudecode_off",
            **common,
        )
    if not gateway_running:
        return CoworkStatus(
            False,
            "not protected while the sidecar is not answering"
            + (f" (last Cowork event {_utc_text(last)})" if last else ""),
            "defenseclaw-gateway start",
            "cowork_gateway_down",
            **common,
        )
    if claudecode_skipped:
        return CoworkStatus(
            False,
            "not protected: the gateway skipped the Claude Code connector when it started",
            "defenseclaw doctor",
            "cowork_claudecode_not_started",
            **common,
        )
    if not health_authenticated:
        confirmed = f" (last confirmed {_utc_text(confirmed_earlier)})" if confirmed_earlier is not None else ""
        return CoworkStatus(
            False,
            "not confirmed: the gateway's authenticated status is unavailable, so its Cowork activity cannot be read"
            + confirmed,
            "defenseclaw-gateway status",
            "cowork_health_unavailable",
            **common,
        )
    if windows_plugin_hooks_need_rebuild(zip_file):
        return CoworkStatus(
            False,
            f"plugin {version} uses an older Windows hook command; rebuild and upload the Cowork plugin",
            "defenseclaw setup cowork",
            "cowork_plugin_stale",
            **common,
        )
    if last is None:
        earlier = max(
            (t for t in (parse_timestamp(state.get("previous_event_at")), stale_live) if t is not None), default=None
        )
        since = f"; last Cowork event {_utc_text(earlier)} came from an earlier plugin build" if earlier else ""
        return CoworkStatus(
            False,
            f"not protected yet: no Cowork event has reached DefenseClaw since plugin {version} was built{since}",
            upload,
            "cowork_no_events",
            **common,
        )
    # No Cowork call since the gateway started: the evidence is from before
    # its restart; the plugin still runs the same hooks (GAP-0038).
    since = "" if live is not None else "; none since the gateway restarted"
    return CoworkStatus(
        True,
        f"protected, {mode_text(cfg)} (plugin {version}; last Cowork event {_utc_text(last)}{since})",
        **common,
    )
