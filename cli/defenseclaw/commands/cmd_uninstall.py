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

"""defenseclaw uninstall / reset — clean removal and config wipe.

Removes DefenseClaw artifacts from the system in a predictable,
scriptable way so operators aren't left with a mess after evaluating
the tool. ``reset`` is the "lose my data" button — it wipes user state
under ``~/.defenseclaw`` but keeps an in-tree managed runtime, the
binaries, and the agent framework's plugin in place so
``defenseclaw quickstart`` can reinstall cleanly.

Connector polymorphism (S7.3)
-----------------------------
Removal of the agent framework's defenseclaw artifacts is delegated to
``defenseclaw-gateway connector teardown`` — the canonical sentinel that
each connector adapter implements (S7.2). This keeps the Python flow
honest: it never has to know how Codex / Claude Code / ZeptoClaw
configure themselves, which previously meant the OpenClaw teardown was
the only one that worked.

The Python side still owns OpenClaw-specific revert paths as a fallback
for very old gateway binaries (pre-S7.2) where the ``connector teardown``
subcommand is not available. The fallback only ever runs against
OpenClaw, never against the other adapters — calling
``restore_openclaw_config`` against a Codex install would corrupt it.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import click

from defenseclaw import config as config_module
from defenseclaw import legacy_connector, ux
from defenseclaw.commands import windows_native_uninstall

# Connectors whose teardown the Python CLI knows how to perform locally
# without going through ``defenseclaw-gateway connector teardown``. This
# is the conservative fallback path used when the gateway binary is too
# old to expose the connector subcommand.
_PYTHON_FALLBACK_CONNECTORS: frozenset[str] = frozenset({"openclaw"})
# .uv holds the Python the installer's venv runs on (scripts/install.sh).
_RESET_PRESERVED_ENTRIES: tuple[str, ...] = (".venv", ".uv")
# The installers (scripts/install.sh, scripts/install.ps1) write this record
# beside the launchers when they install uv because it was missing: one
# "<sha256>  <name>" line per file. `uninstall --binaries` removes the files
# that still match it, and keeps a uv that was updated or replaced since.
_UV_RECORD = "defenseclaw-uv.sha256"
_UV_NAMES = {"win32": ("uv.exe", "uvx.exe", "uvw.exe")}
_UV_NAMES_POSIX = ("uv", "uvx")
_UV_RECORD_MAX_BYTES = 4096
# The folders DefenseClaw created because they were missing (the gateway's
# install watcher, connector setup); see the Go connector package's
# watcher_created_dirs.go. Uninstall removes the ones still empty.
_CREATED_DIRS_RECORD = "watcher-created-dirs.json"
_CREATED_DIRS_RECORD_MAX_BYTES = 1 << 20
_WIN_SYNCHRONIZE = 0x00100000
_WIN_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_CONNECTOR_BACKUP_MARKERS: dict[str, tuple[str, ...]] = {
    "openclaw": (os.path.join("connector_backups", "openclaw", "openclaw.json.json"),),
    "codex": (
        "codex_backup.json",
        "codex_config_backup.json",
        os.path.join("connector_backups", "codex", "config.toml.json"),
        os.path.join("connector_backups", "codex", "managed_config.toml.json"),
    ),
    "claudecode": (
        "claudecode_backup.json",
        os.path.join("connector_backups", "claudecode", "settings.json.json"),
    ),
    "amp": (
        os.path.join("connector_backups", "amp", "config.json"),
    ),
    "antigravity": (
        os.path.join("connector_backups", "antigravity", "hooks.json.json"),
        os.path.join("connector_backups", "antigravity", "config.json"),
    ),
    "copilot": (os.path.join("connector_backups", "copilot", "config.json"),),
    "cursor": (
        os.path.join("connector_backups", "cursor", "config.json"),
        os.path.join("connector_backups", "cursor", "hooks.json.json"),
    ),
    "hermes": (
        os.path.join("connector_backups", "hermes", "config.yaml.json"),
        os.path.join("connector_backups", "hermes", "shell-hooks-allowlist.json.json"),
        os.path.join("connector_backups", "hermes", "config.json"),
    ),
    "omnigent": (
        os.path.join("connector_backups", "omnigent", "config.json"),
        os.path.join("connector_backups", "omnigent", "module.json"),
        os.path.join("connector_backups", "omnigent", "pth.json"),
    ),
    "opencode": (os.path.join("connector_backups", "opencode", "config.json"),),
    "openhands": (os.path.join("connector_backups", "openhands", "config.json"),),
    "devin": (os.path.join("connector_backups", "devin", "config.json"),),
    # A retired connector ID's setup backup still selects gateway teardown,
    # which Go resolves through connector.RetiredConnector.
    **legacy_connector.BACKUP_MARKERS,
    "zeptoclaw": (
        "zeptoclaw_backup.json",
        os.path.join("connector_backups", "zeptoclaw", "config.json.json"),
    ),
}


@dataclass
class UninstallPlan:
    """Aggregated summary of what an uninstall/reset intends to do."""

    stop_gateway: bool = True
    revert_openclaw: bool = True
    remove_plugin: bool = True
    remove_data_dir: bool = False
    remove_binaries: bool = False
    data_dir: str = ""
    openclaw_config_file: str = ""
    openclaw_home: str = ""
    # connector is the active framework adapter resolved from config.
    # connectors is the actual teardown sweep, which may include inactive
    # adapters with leftover rollback markers.
    connector: str = ""
    # connectors is the full sweep set. It always includes the active
    # connector unless OpenClaw was explicitly excluded, plus any inactive
    # connector with rollback markers still present under data_dir.
    connectors: tuple[str, ...] = ()
    # Reset keeps the in-tree Windows runtime that is executing this command.
    # Full uninstall deliberately leaves this empty and removes everything.
    preserve_data_entries: tuple[str, ...] = ()
    platform_name: str = ""
    install_root: str = ""
    managed_venv: str = ""
    gateway_path: str = ""
    binary_targets: tuple[str, ...] = ()
    # data_bound_launchers are the launchers in install_root that run the
    # CLI's virtual environment in data_dir (links on Linux and macOS, .cmd
    # shims on Windows). `--all` removes them with data_dir even without
    # --binaries: they stop working once it is gone.
    data_bound_launchers: tuple[str, ...] = ()
    # sandbox_teardown runs ``defenseclaw-gateway sandbox teardown --yes``
    # before the sidecar stops: DefenseClaw's OpenShell sandboxes,
    # providers, profiles and images go, the gateway config setup changed is
    # restored, and OpenShell itself stays installed.
    sandbox_teardown: bool = False
    # sandbox_teardown_skipped is set when there is sandbox state but
    # --skip-sandbox-teardown leaves it (Docker or OpenShell are gone, say).
    sandbox_teardown_skipped: bool = False
    # setup_leftovers are the %LOCALAPPDATA%\DefenseClaw folders that
    # DefenseClaw Setup left after the installer replaced it (Windows,
    # --binaries only).
    setup_leftovers: tuple[str, ...] = ()
    # observability_teardown removes the local observability stack
    # (`defenseclaw setup local-observability`) and its data volumes before
    # its Compose files in data_dir go (uninstall --all only).
    observability_teardown: bool = False
    # uv_leftovers are uv's download cache and the Python it fetched, which
    # installers before 1.0.2 left outside data_dir (~/.cache/uv,
    # ~/.local/share/uv/python; %LOCALAPPDATA%\uv\cache, %APPDATA%\uv\python)
    # when they installed uv (--all --binaries only, and only when that uv
    # goes too and no other uv is on PATH).
    uv_leftovers: tuple[str, ...] = ()
    # mac_app is DefenseClawMac.app when it is installed (macOS). Uninstall
    # does not remove the app, its login item or its background service; the
    # plan says how to.
    mac_app: str = ""


@dataclass(frozen=True)
class ExecutionPhaseResult:
    """Outcome of one externally visible uninstall/reset phase."""

    name: str
    status: str
    detail: str = ""


@dataclass(frozen=True)
class ExecutionResult:
    """Structured outcome used by commands and automation-facing tests."""

    phases: tuple[ExecutionPhaseResult, ...]

    @property
    def succeeded(self) -> bool:
        return all(phase.status in {"succeeded", "scheduled"} for phase in self.phases)


@dataclass(frozen=True)
class _WindowsProcessWaiter:
    label: str
    pid: int
    handle: int


# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------


@click.command("uninstall")
@click.option("--all", "wipe_data", is_flag=True, help="Also delete ~/.defenseclaw (audit log, config, secrets).")
@click.option(
    "--binaries",
    is_flag=True,
    help="Additionally remove DefenseClaw CLI, gateway, ACP guard, and helper binaries from ~/.local/bin.",
)
@click.option(
    "--keep-openclaw",
    is_flag=True,
    help="Do NOT revert OpenClaw config or remove its plugin; other connector teardown still runs.",
)
@click.option(
    "--skip-sandbox-teardown",
    is_flag=True,
    help=(
        "Leave DefenseClaw's OpenShell sandboxes, images and gateway change in place "
        "(when Docker or OpenShell are gone or broken); 'defenseclaw-gateway sandbox teardown' removes them later."
    ),
)
@click.option("--dry-run", is_flag=True, help="Show what would happen without touching the system.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def uninstall_cmd(
    wipe_data: bool,
    binaries: bool,
    keep_openclaw: bool,
    skip_sandbox_teardown: bool,
    dry_run: bool,
    yes: bool,
) -> None:
    """Uninstall DefenseClaw (reversibly by default)."""
    if _dispatch_native_windows_uninstall(
        wipe_data=wipe_data,
        binaries=binaries,
        dry_run=dry_run,
        yes=yes,
    ):
        return

    plan = _build_plan(
        wipe_data=wipe_data,
        binaries=binaries,
        revert_openclaw=not keep_openclaw,
        remove_plugin=not keep_openclaw,
        skip_sandbox_teardown=skip_sandbox_teardown,
    )
    ux.banner("DefenseClaw Uninstall")
    _render_plan(plan, dry_run=dry_run)

    if dry_run:
        ux.subhead("(dry-run — nothing modified)")
        return

    if not yes and not click.confirm("  Proceed?", default=False):
        ux.subhead("Cancelled.")
        raise SystemExit(1)

    _execute_plan(plan)


def _dispatch_native_windows_uninstall(
    *,
    wipe_data: bool,
    dry_run: bool,
    yes: bool,
    binaries: bool = False,
    platform_name: str | None = None,
) -> bool:
    """Prefer authenticated native Setup before consulting generic markers.

    Setup removes its own program files either way. With binaries, what an
    earlier script install left in %USERPROFILE%\\.local\\bin (and its user
    Path entry) and the folders a replaced Setup left go too, once Setup is
    done.
    """

    try:
        request = windows_native_uninstall.prepare_native_windows_uninstall(
            wipe_data=wipe_data,
            platform_name=platform_name,
        )
    except windows_native_uninstall.NativeWindowsUninstallRefusal as exc:
        raise click.ClickException(str(exc)) from exc
    if request is None:
        return False

    ux.banner("DefenseClaw Uninstall")
    click.echo(f"  {ux.dim('→')} authenticated native Windows installation")
    click.echo(f"  {ux.dim('→')} Setup: {request.setup_path}")
    if wipe_data:
        click.echo(f"  {ux.dim('→')} user data will be deleted")
    else:
        click.echo(f"  {ux.dim('→')} user data will be preserved")
    if binaries:
        click.echo(
            f"  {ux.dim('→')} after Setup: DefenseClaw files left in %USERPROFILE%\\.local\\bin "
            "and its user Path entry are removed too"
        )
    click.echo(f"  {ux.dim('→')} a restart may be required to finish exact cleanup")

    if dry_run:
        ux.subhead("(dry-run — nothing modified)")
        return True
    if not yes and not click.confirm("  Proceed?", default=False):
        ux.subhead("Cancelled.")
        raise SystemExit(1)

    try:
        outcome = windows_native_uninstall.execute_native_windows_uninstall(request)
    except windows_native_uninstall.NativeWindowsUninstallRefusal as exc:
        raise click.ClickException(str(exc)) from exc
    if outcome.returncode == 0:
        ux.ok("Native Windows uninstall completed.")
        if binaries:
            _remove_script_install_after_native_setup(request.platform_name)
        return True
    if outcome.restart_required:
        ux.ok("Native Windows uninstall is armed; restart required (Windows exit code 3010).")
        raise SystemExit(outcome.returncode)
    if outcome.refused:
        ux.err("Authenticated native Setup refused the uninstall (Windows exit code 1603).")
        raise SystemExit(outcome.returncode)
    ux.err(f"Authenticated native Setup exited with Windows code {outcome.returncode}.")
    raise SystemExit(outcome.returncode)


def _remove_script_install_after_native_setup(platform_name: str) -> None:
    """Remove what install.ps1 left beside a native Setup install (--binaries).

    The launchers go only when the plan validation proves them DefenseClaw's
    (the installer's defenseclaw.cmd shim); a refusal is reported with what
    stays, and the uninstall exits non-zero.
    """
    data_dir = str(config_module.default_data_path())
    install_root, binary_targets = _owned_binary_targets(platform_name)
    binary_targets += _installer_uv_targets(install_root, platform_name)
    plan = UninstallPlan(
        platform_name=platform_name,
        install_root=install_root,
        data_dir=data_dir,
        managed_venv=os.path.join(data_dir, ".venv"),
        gateway_path="",
        binary_targets=binary_targets,
        remove_binaries=True,
    )
    try:
        if any(os.path.lexists(path) for path in binary_targets):
            _remove_binaries(plan)
        else:
            _remove_install_bookkeeping(install_root, data_dir)
            if _install_root_empties(plan):
                with contextlib.suppress(OSError):
                    os.rmdir(install_root)
                _remove_user_path_entry(plan)
        _remove_setup_leftovers(_windows_setup_leftovers(platform_name))
    except (OSError, click.ClickException) as exc:
        detail = exc.format_message() if isinstance(exc, click.ClickException) else str(exc)
        ux.err(f"DefenseClaw files in {install_root} were not all removed: {detail}")
        raise SystemExit(1) from exc


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------


@click.command("reset")
@click.option(
    "--skip-sandbox-teardown",
    is_flag=True,
    help=(
        "Leave DefenseClaw's OpenShell sandboxes, images and gateway change in place "
        "(when Docker or OpenShell are gone or broken)."
    ),
)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def reset_cmd(skip_sandbox_teardown: bool, yes: bool) -> None:
    """Wipe user state so 'defenseclaw quickstart' starts clean.

    Keeps a managed .venv runtime, binaries, and the OpenClaw plugin
    installed so reinstall is fast. For a full uninstall use
    'defenseclaw uninstall --all --binaries'.
    """
    plan = _build_plan(
        wipe_data=True,
        binaries=False,
        revert_openclaw=True,
        remove_plugin=False,  # keep plugin around for quick re-enable
        preserve_data_entries=_RESET_PRESERVED_ENTRIES,
        skip_sandbox_teardown=skip_sandbox_teardown,
    )
    ux.banner("DefenseClaw Reset")
    _render_plan(plan, dry_run=False)

    if not yes and not click.confirm(
        f"  This will DELETE resettable state under {plan.data_dir}. Continue?",
        default=False,
    ):
        ux.subhead("Cancelled.")
        raise SystemExit(1)

    _execute_plan(plan)
    ux.ok("Reset complete. Run 'defenseclaw quickstart' to reinstall.")


# ---------------------------------------------------------------------------
# Planning + execution
# ---------------------------------------------------------------------------


def _resolve_active_connector(cfg) -> str:
    """Return the active connector for ``cfg``, lowercased.

    Mirrors :meth:`Config.active_connector` but tolerates older
    in-process configs that haven't been migrated yet. We can't rely on
    ``Config.active_connector`` existing because ``_build_plan`` is
    called even when config loading raised.
    """
    if cfg is None:
        return ""
    if hasattr(cfg, "active_connector") and callable(cfg.active_connector):
        try:
            name = (cfg.active_connector() or "").strip().lower()
            if name:
                return name
        except Exception:
            pass
    if hasattr(cfg, "guardrail") and hasattr(cfg.guardrail, "connector"):
        name = (cfg.guardrail.connector or "").strip().lower()
        if name:
            return name
    return ""


def _resolve_active_connectors(cfg) -> list[str]:
    """Return the FULL active-connector set for ``cfg``, lowercased.

    Uninstall/reset must tear down EVERY configured connector on a
    multi-connector install — otherwise a non-primary connector keeps its
    hook scripts after ``~/.defenseclaw`` is wiped, leaving dangling hooks
    that point at a deleted data dir. Prefers ``Config.active_connectors()``
    (the authoritative multi-connector set); falls back to the singular
    active connector for older / single-connector configs.
    """
    if cfg is not None and hasattr(cfg, "active_connectors") and callable(cfg.active_connectors):
        try:
            names = [(n or "").strip().lower() for n in cfg.active_connectors()]
            names = [n for n in names if n]
            # An authoritative empty plural set means unconfigured. Falling
            # through to active_connector() here resurrects its historical
            # OpenClaw default after reset.
            return names
        except Exception:  # noqa: BLE001 — fall back to the singular connector.
            pass
    single = _resolve_active_connector(cfg)
    return [single] if single else []


def _build_plan(
    *,
    wipe_data: bool,
    binaries: bool,
    revert_openclaw: bool,
    remove_plugin: bool,
    preserve_data_entries: tuple[str, ...] = (),
    platform_name: str | None = None,
    skip_sandbox_teardown: bool = False,
) -> UninstallPlan:
    platform_name = platform_name or sys.platform
    data_dir = str(config_module.default_data_path())
    install_root, binary_targets = _owned_binary_targets(platform_name)
    binary_targets += _installer_uv_targets(install_root, platform_name)
    data_bound_launchers = (
        _data_bound_launchers(binary_targets, data_dir, platform_name) if wipe_data and not binaries else ()
    )

    # Config identifies active connectors. If it is missing or unreadable,
    # only durable rollback markers may authorize connector teardown.
    cfg = None
    config_file = config_module.config_path_for_data_dir(data_dir)
    if config_file.is_file():
        try:
            cfg = config_module.load()
        except Exception:
            pass

    active_connectors = _resolve_active_connectors(cfg)
    resolved_connector = _resolve_active_connector(cfg)
    connector = (
        resolved_connector
        if resolved_connector in active_connectors
        else (active_connectors[0] if active_connectors else "")
    )

    # The default path is a private candidate only. It is not stored,
    # rendered, or used unless configuration or durable OpenClaw ownership
    # evidence adds OpenClaw to the teardown set.
    configured_openclaw = "openclaw" in active_connectors
    if configured_openclaw:
        openclaw_candidate = str(getattr(cfg.claw, "config_file", "") or "")
        openclaw_home_candidate = str(getattr(cfg.claw, "home_dir", "") or "")
        openclaw_owned = True
    else:
        default_home_candidate = os.path.expanduser("~/.openclaw")
        default_config_candidate = os.path.join(default_home_candidate, "openclaw.json")
        openclaw_candidate, openclaw_owned = _owned_openclaw_candidate(
            data_dir,
            default_config_candidate,
        )
        openclaw_home_candidate = os.path.dirname(openclaw_candidate) if openclaw_owned else ""

    connectors = _teardown_connectors(
        active_connectors,
        data_dir=data_dir,
        openclaw_config_file=openclaw_candidate,
        include_openclaw=revert_openclaw,
        openclaw_owned=openclaw_owned,
    )
    owns_openclaw = "openclaw" in connectors
    openclaw_config_file = openclaw_candidate if owns_openclaw else ""
    openclaw_home = openclaw_home_candidate if owns_openclaw else ""

    sandbox_state = _sandbox_state_present(cfg, data_dir, platform_name)
    return UninstallPlan(
        sandbox_teardown=sandbox_state and not skip_sandbox_teardown,
        sandbox_teardown_skipped=sandbox_state and skip_sandbox_teardown,
        stop_gateway=True,
        revert_openclaw=revert_openclaw and owns_openclaw,
        remove_plugin=remove_plugin and owns_openclaw,
        remove_data_dir=wipe_data,
        remove_binaries=binaries,
        data_dir=data_dir,
        openclaw_config_file=openclaw_config_file,
        openclaw_home=openclaw_home,
        connector=connector,
        connectors=connectors,
        preserve_data_entries=preserve_data_entries,
        platform_name=platform_name,
        install_root=install_root,
        managed_venv=os.path.join(data_dir, ".venv"),
        gateway_path=(
            os.path.join(install_root, "defenseclaw-gateway.exe")
            if platform_name == "win32"
            else (shutil.which("defenseclaw-gateway") or os.path.join(install_root, "defenseclaw-gateway"))
        ),
        binary_targets=binary_targets,
        data_bound_launchers=data_bound_launchers,
        setup_leftovers=_windows_setup_leftovers(platform_name) if binaries else (),
        observability_teardown=(
            wipe_data and not preserve_data_entries and _local_observability_stack_file(data_dir) != ""
        ),
        mac_app=_installed_mac_app(platform_name) if wipe_data and binaries else "",
        uv_leftovers=(
            _installer_uv_leftovers(install_root, binary_targets, data_dir, platform_name)
            if wipe_data and binaries
            else ()
        ),
    )


def _local_observability_stack_file(data_dir: str) -> str:
    """Return the Compose file of the local observability stack in data_dir."""
    path = os.path.join(data_dir, "observability-stack", "docker-compose.yml")
    return path if os.path.isfile(path) and not os.path.islink(path) else ""


# Where DefenseClawMac.app is installed (packaging/macos/app).
_MAC_APP_NAME = "DefenseClawMac.app"


def _installed_mac_app(platform_name: str) -> str:
    if platform_name != "darwin":
        return ""
    for parent in ("/Applications", os.path.expanduser("~/Applications")):
        path = os.path.join(parent, _MAC_APP_NAME)
        if os.path.isdir(path):
            return path
    return ""


# DefenseClaw Setup keeps its hook launcher and transaction log under
# %LOCALAPPDATA%\DefenseClaw. When the installer replaces Setup it keeps the
# launcher, because agent hooks that Setup wrote may still run it until each
# connector is set up again (it moves the launcher's state file aside, which
# turns the launcher off), so nothing else removes these folders.
_WINDOWS_SETUP_LEFTOVERS = ("HookRuntime", "InstallerState")


def _windows_setup_leftovers(platform_name: str) -> tuple[str, ...]:
    if platform_name != "win32":
        return ()
    try:
        local_app_data = windows_native_uninstall._known_folder_path(windows_native_uninstall._LOCAL_APP_DATA_FOLDER_ID)
    except Exception:  # noqa: BLE001 - no Known Folder means nothing to clean.
        return ()
    root = os.path.join(local_app_data, "DefenseClaw") if local_app_data else ""
    if (
        not root
        or os.path.lexists(os.path.join(local_app_data, "Programs", "DefenseClaw"))
        or os.path.lexists(os.path.join(root, "InstallerCache"))
        or os.path.lexists(os.path.join(root, "HookRuntime", "hook-runtime-state.json"))
    ):
        # A Setup install, or its cleanup after the next sign-in, still owns them.
        return ()
    return tuple(
        path for path in (os.path.join(root, name) for name in _WINDOWS_SETUP_LEFTOVERS) if os.path.lexists(path)
    )


def _remove_setup_leftovers(paths: tuple[str, ...]) -> None:
    for path in paths:
        try:
            if _is_reparse_path(path):
                if os.path.isdir(path):
                    os.rmdir(path)
                else:
                    os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            ux.warn(f"could not remove {path}: {exc}")
            continue
        ux.ok(f"removed {path}")
    parents = {os.path.dirname(path) for path in paths}
    for parent in parents:
        with contextlib.suppress(OSError):
            os.rmdir(parent)


def _launcher_link_target(path: str) -> str:
    """Return the absolute target of a launcher link, or "" for anything else."""
    try:
        if not os.path.islink(path):
            return ""
        target = os.readlink(path)
    except OSError:
        return ""
    return os.path.normpath(os.path.join(os.path.dirname(path), target))


def _is_data_bound_launcher(path: str, data_dir: str, platform_name: str) -> bool:
    """Report whether the launcher at path runs the CLI's venv in data_dir.

    Linux and macOS installs link ``~/.local/bin/defenseclaw`` (and the
    scanner launchers) into ``<data_dir>/.venv``; Windows installs write
    ``.cmd`` shims that call the venv's ``Scripts`` folder. Removing data_dir
    leaves them dangling. A launcher that points anywhere else (a source
    checkout's ``make install`` links into the repository) keeps working.
    """
    venv = _normalized(os.path.join(data_dir, ".venv"))
    if platform_name != "win32":
        link = _launcher_link_target(path)
        return bool(link) and os.path.commonpath((_normalized(link), venv)) == venv
    name = os.path.basename(path)
    if not os.path.isfile(path) or _is_reparse_path(path):
        return False
    if name.lower().endswith(".cmd"):
        expected = f'"{os.path.join(venv, "Scripts", name[:-4] + ".exe")}" %*'.lower()
    elif name.lower() == "defenseclaw":
        # The Git Bash launcher: exec "C:/.../.venv/Scripts/defenseclaw.exe" "$@"
        expected = f'exec "{os.path.join(venv, "Scripts", "defenseclaw.exe")}" "$@"'.replace("\\", "/").lower()
    else:
        return False
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as stream:
            contents = stream.read(16_385)
    except OSError:
        return False
    return len(contents) <= 16_384 and expected in contents.lower()


def _data_bound_launchers(binary_targets: tuple[str, ...], data_dir: str, platform_name: str) -> tuple[str, ...]:
    """Name the launchers that stop working once data_dir is removed."""
    bound = tuple(path for path in binary_targets if _is_data_bound_launcher(path, data_dir, platform_name))
    # On Windows the deferred helper removes shims only beside the CLI shim
    # it verifies, so the others go only when defenseclaw.cmd does.
    if platform_name == "win32" and not any(os.path.basename(path).lower() == "defenseclaw.cmd" for path in bound):
        return ()
    return bound


def _installer_uv_targets(install_root: str, platform_name: str) -> tuple[str, ...]:
    """Return the uv files the installer put in install_root, and its record.

    Only files that still match the digest the installer recorded are
    listed; a uv updated or replaced since then belongs to the user.
    """
    record = os.path.join(install_root, _UV_RECORD)
    try:
        info = os.lstat(record)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _UV_RECORD_MAX_BYTES:
            return ()
        with open(record, encoding="utf-8", errors="strict") as stream:
            lines = stream.read(_UV_RECORD_MAX_BYTES).splitlines()
    except (OSError, UnicodeError):
        return ()
    names = _UV_NAMES.get(platform_name, _UV_NAMES_POSIX)
    targets: list[str] = []
    for line in lines:
        digest, _, name = line.strip().partition("  ")
        if name not in names:
            continue
        path = os.path.join(install_root, name)
        try:
            if not stat.S_ISREG(os.lstat(path).st_mode) or _sha256_file(path) != digest.lower():
                continue
        except OSError:
            continue
        targets.append(path)
    targets.append(record)
    return tuple(targets)


def _uv_default_dirs(platform_name: str) -> tuple[str, str]:
    """Return uv's default cache folder and managed-Python folder."""
    if platform_name == "win32":
        local = os.environ.get("LOCALAPPDATA", "")
        roaming = os.environ.get("APPDATA", "")
        return (
            os.path.join(local, "uv", "cache") if os.path.isabs(local) else "",
            os.path.join(roaming, "uv", "python") if os.path.isabs(roaming) else "",
        )
    home = os.path.expanduser("~")
    cache = os.environ.get("XDG_CACHE_HOME", "")
    data = os.environ.get("XDG_DATA_HOME", "")
    cache = cache if os.path.isabs(cache) else os.path.join(home, ".cache")
    data = data if os.path.isabs(data) else os.path.join(home, ".local", "share")
    return os.path.join(cache, "uv"), os.path.join(data, "uv", "python")


def _venv_base_python_dir(data_dir: str, python_root: str) -> str:
    """Return the folder in python_root that the data dir's venv runs on, or ""."""
    try:
        with open(os.path.join(data_dir, ".venv", "pyvenv.cfg"), encoding="utf-8") as stream:
            lines = stream.read(16_384).splitlines()
    except (OSError, UnicodeError):
        return ""
    home = next(
        (value.strip() for key, _, value in (line.partition("=") for line in lines) if key.strip() == "home"),
        "",
    )
    if not home or not os.path.isabs(home):
        return ""
    root = _normalized(os.path.realpath(python_root))
    base = _normalized(os.path.realpath(home))
    try:
        if os.path.commonpath((root, base)) != root or base == root:
            return ""
    except ValueError:
        return ""
    first = os.path.relpath(base, root).split(os.sep)[0]
    return os.path.join(python_root, first)


def _installer_uv_leftovers(
    install_root: str, binary_targets: tuple[str, ...], data_dir: str, platform_name: str
) -> tuple[str, ...]:
    """Name the uv cache and Python an older installer left for DefenseClaw.

    Only when uninstall removes the uv the installer installed (its digest
    still matches), no other uv is on PATH, and uv's folders are the
    defaults. The Python folder goes only when it holds nothing but the
    Python the data dir's venv runs on (and uv's links and bookkeeping).
    """
    uv_name = _UV_NAMES.get(platform_name, _UV_NAMES_POSIX)[0]
    if not any(os.path.basename(target) == uv_name for target in binary_targets):
        return ()
    root = _normalized(install_root)
    for directory in os.get_exec_path():
        if directory and _normalized(directory) != root and os.path.isfile(os.path.join(directory, uv_name)):
            return ()
    cache, python_root = _uv_default_dirs(platform_name)
    leftovers: list[str] = []
    if cache and not os.environ.get("UV_CACHE_DIR") and _plain_owned_dir(cache):
        leftovers.append(cache)
    if python_root and not os.environ.get("UV_PYTHON_INSTALL_DIR") and _plain_owned_dir(python_root):
        base = _venv_base_python_dir(data_dir, python_root)
        if base and _only_python(python_root, base):
            leftovers.append(python_root)
    return tuple(leftovers)


def _plain_owned_dir(path: str) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISDIR(info.st_mode) or _is_reparse_path(path):
        return False
    return not hasattr(os, "getuid") or info.st_uid == os.getuid()


def _only_python(python_root: str, base: str) -> bool:
    """Report whether python_root holds only base, links to it and uv's dot files."""
    wanted = _normalized(os.path.realpath(base))
    try:
        entries = list(os.scandir(python_root))
    except OSError:
        return False
    for entry in entries:
        if entry.name.startswith("."):
            continue
        if _normalized(entry.path) == _normalized(base) and not _is_reparse_path(entry.path):
            continue
        if _is_reparse_path(entry.path) and _normalized(os.path.realpath(entry.path)) == wanted:
            continue
        return False
    return True


def _running_base_python() -> str:
    return os.path.realpath(os.path.abspath(getattr(sys, "_base_executable", "") or sys.executable))


def _holds_running_python(path: str) -> bool:
    """Report whether path holds the Python this CLI runs on (Windows only matters)."""
    if sys.platform != "win32":
        return False
    return _below(os.path.realpath(path), _running_base_python())


def _deferred_interpreter_dirs(plan: UninstallPlan, base_python: str) -> list[str]:
    """Name the folders holding base_python that the deferred helper removes after it exits.

    The helper runs on base_python, so it cannot remove them while it runs:
    the installer's <data_dir>/.uv (scripts/install.ps1), or a uv Python
    folder the plan removes (uv_leftovers).
    """
    candidates = []
    if plan.remove_data_dir and not plan.preserve_data_entries:
        candidates.append(os.path.join(plan.data_dir, ".uv"))
    candidates.extend(plan.uv_leftovers)
    return [path for path in candidates if os.path.isdir(path) and _below(os.path.realpath(path), base_python)]


def _remove_uv_leftovers(paths: tuple[str, ...]) -> None:
    """Remove the uv folders the plan names, then their parents left empty."""
    for path in paths:
        try:
            _remove_tree_no_follow(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            ux.warn(f"could not remove {path}: {exc}")
            continue
        ux.ok(f"removed {path}")
        _remove_empty_parents(path)


def _remove_tree_no_follow(path: str) -> None:
    """Remove a folder tree; links and junctions inside go without being followed."""
    if _is_reparse_path(path):
        raise OSError(f"refusing link or reparse point {path}")
    with os.scandir(path) as entries:
        children = list(entries)
    for entry in children:
        if _is_reparse_path(entry.path):
            if entry.is_dir(follow_symlinks=False) or (sys.platform == "win32" and os.path.isdir(entry.path)):
                os.rmdir(entry.path)
            else:
                os.unlink(entry.path)
        elif entry.is_dir(follow_symlinks=False):
            _remove_tree_no_follow(entry.path)
        else:
            os.unlink(entry.path)
    os.rmdir(path)


def _remove_empty_parents(path: str) -> None:
    """Remove the parents of path that are empty now, up to the home folder."""
    home = _normalized(os.path.expanduser("~"))
    parent = os.path.dirname(os.path.abspath(path))
    while parent and _normalized(parent) != home and os.path.dirname(parent) != parent:
        try:
            if os.path.commonpath((home, _normalized(parent))) != home:
                return
            os.rmdir(parent)
        except (OSError, ValueError):
            return
        parent = os.path.dirname(parent)


def _remove_created_dirs(data_dir: str) -> None:
    """Remove the folders DefenseClaw created in the home folder that are still empty.

    The gateway records them (_CREATED_DIRS_RECORD): the folders its install
    watcher created to watch, and the parents of the agent config files a
    connector setup wrote. Deepest first, each goes only while it is an empty
    real folder reached through real folders from the home folder; one with
    content stays, and so does its record.
    """
    record = os.path.join(data_dir, _CREATED_DIRS_RECORD)
    try:
        info = os.lstat(record)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _CREATED_DIRS_RECORD_MAX_BYTES:
            return
        with open(record, encoding="utf-8") as stream:
            dirs = json.load(stream).get("dirs")
    except (OSError, ValueError, AttributeError):
        return
    if not isinstance(dirs, list):
        return
    home = os.path.abspath(os.path.expanduser("~"))
    kept: list[str] = []
    removed: list[str] = []
    for path in sorted({d for d in dirs if isinstance(d, str)}, key=len, reverse=True):
        if not os.path.isabs(path) or not _below(home, path):
            kept.append(path)
            continue
        if not _real_dir_chain(home, path):
            continue
        try:
            os.rmdir(path)
        except FileNotFoundError:
            continue
        except OSError:
            kept.append(path)
            continue
        removed.append(path)
    try:
        if kept:
            with open(record, "w", encoding="utf-8") as stream:
                json.dump({"dirs": sorted(kept)}, stream)
                stream.write("\n")
        else:
            os.unlink(record)
    except OSError:
        pass
    if removed:
        ux.ok(f"removed the empty folders DefenseClaw created: {', '.join(sorted(removed))}")


def _below(root: str, path: str) -> bool:
    root = _normalized(root)
    candidate = _normalized(path)
    try:
        return candidate != root and os.path.commonpath((root, candidate)) == root
    except ValueError:
        return False


def _real_dir_chain(root: str, path: str) -> bool:
    """Report whether path and each folder up to root is a real folder."""
    root = _normalized(root)
    current = os.path.abspath(path)
    while _normalized(current) != root:
        try:
            info = os.lstat(current)
        except OSError:
            return False
        if not stat.S_ISDIR(info.st_mode) or _is_reparse_path(current):
            return False
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent
    return True


def _sha256_file(path: str) -> str:
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sandbox_state_present(cfg, data_dir: str, platform_name: str) -> bool:
    """Report whether DefenseClaw may hold OpenShell sandbox state.

    OpenShell sandboxes run on Linux and macOS only. Teardown is planned when
    sandboxes are enabled or the data directory holds sandbox state (images,
    records, the setup receipt), so a host that never used them is untouched.
    """
    if platform_name == "win32":
        return False
    openshell = getattr(cfg, "openshell", None) if cfg is not None else None
    if openshell is not None and (getattr(openshell, "enabled", False) or getattr(openshell, "wrappers", None)):
        return True
    return os.path.isdir(os.path.join(data_dir, "sandboxes"))


def _owned_binary_targets(platform_name: str) -> tuple[str, tuple[str, ...]]:
    """Freeze the exact launcher paths owned by each supported installer."""
    if platform_name == "win32":
        home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
        install_root = os.path.abspath(os.path.join(home, ".local", "bin"))
        names = (
            "defenseclaw.cmd",
            # The installer's extensionless launcher for Git Bash.
            "defenseclaw",
            "defenseclaw-gateway.exe",
            "defenseclaw-acp.exe",
            "defenseclaw-hook.exe",
            "skill-scanner.cmd",
            "mcp-scanner.cmd",
            # Written by install.ps1: binds defenseclaw-hook.exe to the data dir.
            "defenseclaw-hook-state.json",
        )
    else:
        install_root = os.path.abspath(os.path.expanduser("~/.local/bin"))
        names = (
            "defenseclaw-gateway",
            "defenseclaw-acp",
            "defenseclaw",
            "skill-scanner",
            "skill-scanner-api",
            "skill-scanner-pre-commit",
            "mcp-scanner",
            "mcp-scanner-api",
            "litellm",
        )
    return install_root, tuple(os.path.join(install_root, name) for name in names)


def _owned_openclaw_candidate(data_dir: str, default_candidate: str) -> tuple[str, bool]:
    """Return an OpenClaw config path only when durable ownership exists.

    Supports the legacy connector backup marker, an adjacent legacy pristine
    file, and the current pristine-backup index. Indexed snapshots must be
    real files inside *data_dir* and targets must be absolute openclaw.json
    paths; malformed or reparse-point evidence is ignored.
    """
    legacy_marker = os.path.join(
        data_dir,
        "connector_backups",
        "openclaw",
        "openclaw.json.json",
    )
    adjacent_pristine = _expand(default_candidate) + ".pristine"
    if (
        os.path.isfile(legacy_marker)
        and not _is_reparse_path(legacy_marker)
        or os.path.isfile(adjacent_pristine)
        and not _is_reparse_path(adjacent_pristine)
    ):
        return default_candidate, True

    index_path = os.path.join(data_dir, "openclaw-backups.json")
    if not os.path.isfile(index_path) or _is_reparse_path(index_path):
        return "", False
    try:
        with open(index_path, encoding="utf-8") as fh:
            index = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return "", False

    entries = index.get("entries", {}) if isinstance(index, dict) else {}
    if not isinstance(entries, dict):
        return "", False
    resolved_data_dir = os.path.normcase(os.path.realpath(data_dir))
    owned_targets: list[str] = []
    for target, entry in entries.items():
        if (
            not isinstance(target, str)
            or not os.path.isabs(target)
            or os.path.basename(target).lower() != "openclaw.json"
            or not isinstance(entry, dict)
            or os.path.lexists(target)
            and _is_reparse_path(target)
        ):
            continue
        pristine = entry.get("pristine", "")
        if not isinstance(pristine, str) or not os.path.isfile(pristine) or _is_reparse_path(pristine):
            continue
        resolved_pristine = os.path.normcase(os.path.realpath(pristine))
        try:
            inside_data_dir = os.path.commonpath((resolved_data_dir, resolved_pristine)) == resolved_data_dir
        except ValueError:
            inside_data_dir = False
        if inside_data_dir:
            owned_targets.append(target)

    if not owned_targets:
        return "", False
    default_abs = os.path.normcase(os.path.abspath(_expand(default_candidate)))
    for target in owned_targets:
        if os.path.normcase(os.path.abspath(target)) == default_abs:
            return target, True
    return sorted(owned_targets, key=os.path.normcase)[0], True


def _teardown_connectors(
    active_connectors: str | list[str] | tuple[str, ...],
    *,
    data_dir: str,
    openclaw_config_file: str,
    include_openclaw: bool,
    openclaw_owned: bool = False,
) -> tuple[str, ...]:
    """Return connector names that uninstall should restore before cleanup.

    The configured active set — EVERY connector under ``guardrail.connectors``,
    not just the primary — is the authoritative source: on a multi-connector
    install all of them must be torn down or their hook scripts outlive the
    wiped data dir. Backup markers are layered on top as durable evidence that
    DefenseClaw touched an agent-owned config in the past, so inactive
    connectors from a previous boot, crash, or connector switch are swept too.

    A bare string is accepted (and treated as a single-element set) for
    backward compatibility with single-connector callers.
    """
    out: list[str] = []

    def add(name: str) -> None:
        name = (name or "").strip().lower()
        if not name:
            return
        if name == "openclaw" and not include_openclaw:
            return
        if name not in out:
            out.append(name)

    if isinstance(active_connectors, str):
        active_connectors = [active_connectors]
    for connector_name in active_connectors:
        add(connector_name)
    if openclaw_owned:
        add("openclaw")
    for name, markers in _CONNECTOR_BACKUP_MARKERS.items():
        if name == "openclaw":
            # OpenClaw evidence also selects an external target path, so it is
            # validated centrally by _owned_openclaw_candidate().
            continue
        for marker in markers:
            marker_path = os.path.join(data_dir, marker)
            if os.path.isfile(marker_path) and not _is_reparse_path(marker_path):
                add(name)
                break

    if include_openclaw and openclaw_config_file:
        pristine = _expand(openclaw_config_file) + ".pristine"
        if os.path.isfile(pristine):
            add("openclaw")

    return tuple(out)


def _render_plan(plan: UninstallPlan, *, dry_run: bool) -> None:
    # "Plan" (not "Uninstall plan") — the command banner above already names
    # the operation (Uninstall / Reset), so repeating it here is redundant and,
    # for reset, was an outright mismatch ("Uninstall plan" under a Reset).
    ux.banner("Plan")
    if len(plan.connectors) > 1:
        # Multi-connector installs serve N equal peers — there is no "primary",
        # so list them all without singling one out.
        click.echo(f"  • {ux.bold('active connectors:')}   {', '.join(plan.connectors)}")
    else:
        click.echo(f"  • {ux.bold('active connector:')}    {plan.connector or 'none'}")
    display_connectors = plan.connectors
    teardown = ", ".join(display_connectors) if display_connectors else "no"
    click.echo(f"  • {ux.bold('connector teardown:')}  {teardown}")
    if plan.sandbox_teardown:
        click.echo(f"  • {ux.bold('sandbox teardown:')}    yes (OpenShell itself is kept)")
        # Teardown runs with --yes: work a copy-mode sandbox holds is gone
        # with it, so say where to see it before the confirmation.
        click.echo(
            f"      {ux.dim('·')} work a copy-mode sandbox holds that was never pulled back is deleted with it "
            "(`defenseclaw sandbox teardown --dry-run` names it)"
        )
    elif plan.sandbox_teardown_skipped:
        click.echo(f"  • {ux.bold('sandbox teardown:')}    skipped (--skip-sandbox-teardown)")
        # What teardown needs to find DefenseClaw's sandboxes later lives in
        # the data dir and runs with the gateway binary.
        later = "`defenseclaw-gateway sandbox teardown` removes them later"
        if plan.remove_data_dir:
            later = (
                f"{plan.data_dir} holds the records teardown finds them by and goes, "
                "so remove them yourself (`openshell sandbox list`)"
            )
        elif plan.remove_binaries:
            later = "reinstall DefenseClaw and run `defenseclaw-gateway sandbox teardown` to remove them"
        click.echo(
            f"      {ux.dim('·')} DefenseClaw's OpenShell sandboxes, images, gateway change and shell wrappers "
            f"stay; {later}"
        )
    click.echo(f"  • {ux.bold('stop sidecar:')}        {'yes' if plan.stop_gateway else 'no'}")
    if "openclaw" in display_connectors:
        click.echo(
            f"  • {ux.bold('revert openclaw.json:')} {'yes' if plan.revert_openclaw else 'no'} "
            f"({plan.openclaw_config_file})"
        )
        click.echo(f"  • {ux.bold('remove plugin:')}        {'yes' if plan.remove_plugin else 'no'}")
    click.echo(f"  • {ux.bold('wipe ' + plan.data_dir + ':')} {'yes' if plan.remove_data_dir else 'no'}")
    if plan.preserve_data_entries:
        click.echo(f"  • {ux.bold('preserve runtime:')}      {', '.join(plan.preserve_data_entries)}")
    click.echo(f"  • {ux.bold('remove binaries:')}     {'yes' if plan.remove_binaries else 'no'}")
    if plan.remove_binaries:
        # Only the launchers that are there: the owned-name list also names
        # optional ones (scanner APIs, litellm) that most installs never had.
        for target in plan.binary_targets:
            if os.path.lexists(target):
                click.echo(f"      {ux.dim('·')} {target}")
        for path in plan.setup_leftovers:
            click.echo(f"      {ux.dim('·')} {path} (left by DefenseClaw Setup)")
        for path in plan.uv_leftovers:
            click.echo(f"      {ux.dim('·')} {path} (what the installer's uv downloaded for DefenseClaw)")
        if plan.platform_name == "win32":
            click.echo(
                f"      {ux.dim('·')} the {plan.install_root} entry in your user Path, "
                "once nothing else is left in that folder"
            )
    elif plan.remove_data_dir:
        # The launchers into the data dir stop working with it, so they go
        # too; the rest keep working and stay until --binaries.
        for target in plan.data_bound_launchers:
            click.echo(f"      {ux.dim('·')} {target} (runs {plan.data_dir}, so it goes with it)")
        kept = [
            target
            for target in plan.binary_targets
            if os.path.lexists(target)
            and target not in plan.data_bound_launchers
            and os.path.basename(target) != _UV_RECORD
        ]
        developer = _windows_developer_files(plan.install_root) if plan.platform_name == "win32" else []
        if developer:
            click.echo(f"      {ux.dim('·')} kept: {_windows_developer_removal(developer)}")
        elif kept:
            click.echo(
                f"      {ux.dim('·')} kept: {', '.join(os.path.basename(target) for target in kept)} "
                f"in {plan.install_root} (add --binaries to remove them too)"
            )
    if plan.observability_teardown:
        click.echo(
            f"  • {ux.bold('local observability:')} its containers and data volumes go (docker compose down --volumes)"
        )
    if _requires_deferred_cleanup(plan):
        click.echo(f"  • {ux.bold('deferred cleanup:')}   after this managed CLI exits")
    if plan.mac_app:
        # Not removed here: the app owns its login item and background
        # service, which it unregisters itself.
        click.echo(
            f"  • {ux.bold('kept:')}                {plan.mac_app}: quit it, turn off its login item "
            "(System Settings > General > Login Items), then move it to the Trash"
        )
    click.echo()


def _execute_plan(plan: UninstallPlan) -> ExecutionResult:
    """Execute *plan*, surfacing the exact phase that failed.

    Destructive phases are intentionally sequential: connector restoration
    must finish before data containing its rollback state is removed. A phase
    failure stops later work, prints the completed/failed phase ledger, and
    propagates as a Click error so callers receive a non-zero exit status.
    """
    phases: list[ExecutionPhaseResult] = []

    def run_phase(name: str, action: Callable[[], None]) -> None:
        try:
            action()
        except Exception as exc:
            phases.append(ExecutionPhaseResult(name, "failed", str(exc)))
            _render_execution_result(ExecutionResult(tuple(phases)))
            if isinstance(exc, click.ClickException):
                raise
            raise click.ClickException(f"{name} failed: {exc}") from exc
        phases.append(ExecutionPhaseResult(name, "succeeded"))

    run_phase("plan validation", lambda: _validate_plan(plan))
    if plan.sandbox_teardown:
        # Before the sidecar stops: the daemon deletes its own sandboxes.
        run_phase("sandbox teardown", lambda: _sandbox_teardown(plan))
    if plan.stop_gateway:
        run_phase("gateway stop", lambda: _stop_gateway(plan))
    if plan.connectors:
        run_phase("connector teardown", lambda: _connector_teardown(plan))
    if plan.stop_gateway and plan.data_dir:
        # The gateway is stopped, so its watcher no longer uses them.
        _remove_created_dirs(plan.data_dir)
    if "copilot" in plan.connectors or plan.remove_data_dir:
        _remove_orphan_copilot_plugin()
    if plan.remove_plugin and "openclaw" in plan.connectors:
        # Plugin removal is OpenClaw-specific. For other connectors the
        # gateway sentinel teardown above already removed their hook
        # scripts and config patches. This helper is idempotent and
        # reports "not installed" when OpenClaw was never used.
        run_phase("plugin removal", lambda: _remove_plugin(plan))
    if plan.setup_leftovers:
        # After connector teardown, so no agent hook still runs the launcher.
        run_phase("Setup leftovers removal", lambda: _remove_setup_leftovers(plan.setup_leftovers))
    if plan.observability_teardown:
        # Before data removal: Compose needs the stack's files in data_dir.
        # A stack Docker cannot reach stays, with the command that removes it.
        _local_observability_teardown(plan.data_dir)
    deferred = _requires_deferred_cleanup(plan)
    if deferred:
        status: list[str] = []

        def schedule() -> None:
            status.append(_schedule_deferred_cleanup(plan))

        run_phase("deferred cleanup", schedule)
        phases[-1] = ExecutionPhaseResult(
            "deferred cleanup",
            "scheduled",
            # The result file stays for the operator to read; the next
            # uninstall's helper removes it.
            f"result: {status[0]}, kept for you to read",
        )
    elif plan.remove_data_dir:
        run_phase(
            "data removal",
            lambda: _remove_data_dir(
                plan.data_dir,
                preserve_entries=plan.preserve_data_entries,
            ),
        )
        if plan.data_bound_launchers and not plan.remove_binaries:
            run_phase("launcher removal", lambda: _remove_data_bound_launchers(plan))
    if plan.remove_data_dir and not plan.preserve_data_entries:
        _remove_empty_plugin_cache()
    if plan.remove_binaries and not deferred:
        run_phase("binary removal", lambda: _remove_binaries(plan))
    elif plan.remove_binaries:
        # The helper removes the launchers once this CLI exits; the
        # installer's bookkeeping is not in use, so it goes now, and so does
        # the Path entry of a folder the helper leaves empty.
        _remove_install_bookkeeping(plan.install_root, plan.data_dir)
        if _install_root_empties(plan):
            _remove_user_path_entry(plan)
    if plan.uv_leftovers:
        # Last: on Linux and macOS this CLI may run on the Python that goes.
        # On Windows that one is in use until the deferred helper exits,
        # which removes it then (_deferred_interpreter_dirs).
        _remove_uv_leftovers(tuple(path for path in plan.uv_leftovers if not _holds_running_python(path)))

    result = ExecutionResult(tuple(phases))
    _render_execution_result(result)
    return result


def _remove_data_bound_launchers(plan: UninstallPlan) -> None:
    """Remove the launchers into the removed data dir (see _data_bound_launchers).

    Each one is checked again first: still an owned launcher name in the
    install root that runs the data dir's virtual environment.
    """
    owned = set(plan.binary_targets)
    failures: list[str] = []
    for path in plan.data_bound_launchers:
        if path not in owned or not _is_data_bound_launcher(path, plan.data_dir, plan.platform_name):
            continue
        try:
            os.unlink(path)
            ux.ok(f"removed {path}")
        except FileNotFoundError:
            pass
        except OSError as exc:
            failures.append(f"{path}: {exc}")
    if failures:
        raise OSError("; ".join(failures))


# The manifest of the Copilot plugin a managed deployment renders into each
# account (~/.copilot/installed-plugins/defenseclaw/defenseclaw).
_COPILOT_PLUGIN_MANIFEST = {
    "name": "defenseclaw",
    "description": "DefenseClaw guardrail hooks",
    "version": "1.0.0",
    "hooks": "hooks/hooks.json",
}


def _remove_orphan_copilot_plugin() -> None:
    """Remove DefenseClaw's managed Copilot plugin once nothing manages it.

    A managed deployment renders this plugin into each account and its own
    uninstall removes it. On a host with no managed deployment a leftover
    copy only names a hook binary that may be gone, so the per-user
    uninstall removes it. The plugin must hold exactly DefenseClaw's
    rendered manifest and managed Copilot hook commands; anything else is
    the user's and stays.
    """
    from defenseclaw import upgrade_shim

    if upgrade_shim.managed_deployment():
        return
    plugin = os.path.join(os.path.expanduser("~"), ".copilot", "installed-plugins", "defenseclaw", "defenseclaw")
    hooks_dir = os.path.join(plugin, "hooks")
    manifest = os.path.join(plugin, "plugin.json")
    hooks_file = os.path.join(hooks_dir, "hooks.json")
    try:
        if _is_reparse_path(plugin) or _is_reparse_path(hooks_dir):
            return
        if sorted(os.listdir(plugin)) != ["hooks", "plugin.json"] or os.listdir(hooks_dir) != ["hooks.json"]:
            return
        if not all(stat.S_ISREG(os.lstat(path).st_mode) for path in (manifest, hooks_file)):
            return
        with open(manifest, encoding="utf-8") as handle:
            if json.load(handle) != _COPILOT_PLUGIN_MANIFEST:
                return
        with open(hooks_file, encoding="utf-8") as handle:
            events = json.load(handle).get("hooks")
        handlers = [h for group in events.values() for h in group] if isinstance(events, dict) else []
        if not handlers or not all(
            isinstance(h, dict)
            and "copilot" in str(h.get("command", ""))
            and "enterprise-managed" in str(h.get("command", ""))
            for h in handlers
        ):
            return
        os.unlink(hooks_file)
        os.unlink(manifest)
        os.rmdir(hooks_dir)
        os.rmdir(plugin)
        with contextlib.suppress(OSError):
            os.rmdir(os.path.dirname(plugin))
        ux.ok(f"removed orphaned Copilot plugin {plugin}")
    except (OSError, ValueError, AttributeError, TypeError):
        return


def _remove_empty_plugin_cache() -> None:
    """Remove the gateway's plugin cache folder in TempDir while it is empty.

    Current gateways create it only for a plugin they load; earlier ones
    created it at every start. A folder with content, or anything that is
    not a folder, stays.
    """
    uid = os.getuid() if hasattr(os, "getuid") else 0
    path = os.path.join(tempfile.gettempdir(), f"defenseclaw-plugin-cache-{uid}")
    try:
        if stat.S_ISDIR(os.lstat(path).st_mode) and not _is_reparse_path(path):
            os.rmdir(path)
    except OSError:
        pass


def _render_execution_result(result: ExecutionResult) -> None:
    """Render a compact, stable phase ledger for humans and automation."""
    ux.subhead("Phase results:")
    for phase in result.phases:
        suffix = f" ({phase.detail})" if phase.detail else ""
        click.echo(f"  {phase.name}: {phase.status}{suffix}")


def _normalized(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _validate_owned_root(path: str, label: str, *, reject_reparse: bool = True) -> str:
    if not path or not os.path.isabs(path):
        raise click.ClickException(f"refusing non-absolute {label}: {path}")
    resolved = _normalized(path)
    if resolved == os.path.normcase(str(Path(resolved).anchor)):
        raise click.ClickException(f"refusing root-like {label}: {path}")
    if reject_reparse and os.path.lexists(path) and _is_reparse_path(path):
        raise click.ClickException(f"refusing symlink or reparse-point {label}: {path}")
    return resolved


def _validate_windows_ancestor_chain(path: str, label: str) -> None:
    candidate = Path(os.path.abspath(path))
    while str(candidate) != candidate.anchor:
        if os.path.lexists(candidate) and _is_reparse_path(candidate):
            raise click.ClickException(f"refusing reparse-point ancestor for {label}: {candidate}")
        candidate = candidate.parent


# What `make all` (Makefile _source-dev-install) publishes into the Windows
# install root: regular-file copies plus the source ownership marker.
_WINDOWS_DEVELOPER_FILES = (
    "defenseclaw.exe",
    "defenseclaw-gateway.exe",
    "defenseclaw-acp.exe",
    "litellm.exe",
    "skill-scanner.exe",
    "skill-scanner-api.exe",
    "skill-scanner-pre-commit.exe",
    "mcp-scanner.exe",
    "mcp-scanner-api.exe",
    ".defenseclaw-source-root",
)


def _windows_developer_files(install_root: str) -> list[str]:
    """Return the files a `make all` developer install published, if it is one.

    A developer install has the source ownership marker and no installer
    shim. Uninstall does not remove it (the CLI runs from one of these
    copies); the plan and the refusal name the files instead.
    """
    if not install_root or os.path.lexists(os.path.join(install_root, "defenseclaw.cmd")):
        return []
    if not os.path.lexists(os.path.join(install_root, ".defenseclaw-source-root")):
        return []
    return [
        os.path.join(install_root, name)
        for name in _WINDOWS_DEVELOPER_FILES
        if os.path.lexists(os.path.join(install_root, name))
    ]


def _windows_developer_removal(files: list[str]) -> str:
    quoted = ", ".join("'" + path.replace("'", "''") + "'" for path in files)
    return (
        "this is a developer install from 'make all', which uninstall does not remove. "
        "Run 'defenseclaw uninstall' without --binaries (add --all to remove data too), "
        f"then remove the developer files from PowerShell:\n  Remove-Item -LiteralPath {quoted}"
    )


def _validate_windows_binary_ownership(plan: UninstallPlan) -> None:
    """Require the installer-authored CLI shim before removing paired artifacts."""
    existing = [path for path in plan.binary_targets if os.path.lexists(path)]
    if not existing:
        return
    shim = os.path.join(plan.install_root, "defenseclaw.cmd")
    if not os.path.isfile(shim) or _is_reparse_path(shim):
        developer = _windows_developer_files(plan.install_root)
        if developer:
            raise click.ClickException(f"refusing Windows binary removal: {_windows_developer_removal(developer)}")
        raise click.ClickException("refusing Windows binary removal without the installer-owned defenseclaw.cmd shim")
    try:
        with open(shim, encoding="utf-8-sig", errors="strict") as stream:
            contents = stream.read(16_385)
    except (OSError, UnicodeError) as exc:
        raise click.ClickException(f"could not verify Windows CLI shim ownership: {exc}") from exc
    if len(contents) > 16_384:
        raise click.ClickException("refusing oversized Windows CLI shim")
    expected_cli = os.path.join(plan.managed_venv, "Scripts", "defenseclaw.exe")
    expected_invocation = f'"{expected_cli}" %*'.lower()
    if expected_invocation not in contents.lower():
        raise click.ClickException("refusing Windows binary removal: CLI shim targets an unrelated runtime")


def _validate_plan(plan: UninstallPlan) -> None:
    """Validate every destructive root and exact artifact before mutation."""
    if plan.remove_data_dir:
        resolved_data = _validate_owned_root(plan.data_dir, "data path")
        if plan.platform_name == "win32":
            _validate_windows_ancestor_chain(plan.data_dir, "data path")
        if plan.managed_venv and os.path.lexists(plan.managed_venv) and _is_reparse_path(plan.managed_venv):
            raise click.ClickException(f"refusing symlink or reparse-point managed runtime: {plan.managed_venv}")
        protected = {
            os.path.normcase(os.path.realpath(os.path.expanduser("~"))),
            os.path.normcase(str(Path(resolved_data).anchor)),
            os.path.normcase(os.path.realpath("/")),
        }
        if os.path.normcase(os.path.realpath(plan.data_dir)) in protected:
            raise click.ClickException(f"refusing protected data path: {plan.data_dir}")
        ownership_markers = ("config.yaml", "audit.db", ".env", "policies", "quarantine", ".venv")
        if os.path.isdir(plan.data_dir) and not any(
            os.path.exists(os.path.join(plan.data_dir, marker))
            and not _is_reparse_path(os.path.join(plan.data_dir, marker))
            for marker in ownership_markers
        ):
            raise click.ClickException(
                f"refusing to remove {plan.data_dir}: path does not look like a DefenseClaw data directory"
            )
        if plan.install_root:
            install_root_candidate = _normalized(plan.install_root)
            try:
                common = os.path.commonpath((resolved_data, install_root_candidate))
                overlap = common in {resolved_data, install_root_candidate}
            except ValueError:
                overlap = False
            if overlap:
                raise click.ClickException("refusing overlapping data and binary install roots")

    if plan.data_dir:
        for markers in _CONNECTOR_BACKUP_MARKERS.values():
            for marker in markers:
                marker_path = os.path.join(plan.data_dir, marker)
                if os.path.lexists(marker_path) and _is_reparse_path(marker_path):
                    raise click.ClickException(f"refusing symlink or reparse-point connector backup: {marker_path}")

    for path, label in (
        (plan.openclaw_config_file if plan.revert_openclaw else "", "OpenClaw config"),
        (plan.openclaw_home if plan.remove_plugin else "", "OpenClaw home"),
    ):
        if path and os.path.lexists(_expand(path)) and _is_reparse_path(_expand(path)):
            raise click.ClickException(f"refusing symlink or reparse-point {label}: {path}")
        if path and plan.platform_name == "win32":
            _validate_windows_ancestor_chain(_expand(path), label)

    if plan.remove_binaries:
        install_root = _validate_owned_root(
            plan.install_root,
            "binary install root",
            reject_reparse=plan.platform_name == "win32",
        )
        if plan.platform_name == "win32":
            _validate_windows_ancestor_chain(plan.install_root, "binary install root")
        allowed_names = (
            {
                "defenseclaw.cmd",
                "defenseclaw",
                "defenseclaw-gateway.exe",
                "defenseclaw-acp.exe",
                "defenseclaw-hook.exe",
                "skill-scanner.cmd",
                "mcp-scanner.cmd",
                "defenseclaw-hook-state.json",
                _UV_RECORD,
                *_UV_NAMES["win32"],
            }
            if plan.platform_name == "win32"
            else {
                "defenseclaw-gateway",
                "defenseclaw-acp",
                "defenseclaw",
                "skill-scanner",
                "skill-scanner-api",
                "skill-scanner-pre-commit",
                "mcp-scanner",
                "mcp-scanner-api",
                "litellm",
                _UV_RECORD,
                *_UV_NAMES_POSIX,
            }
        )
        for target in plan.binary_targets:
            if (
                _normalized(os.path.dirname(target)) != install_root
                or os.path.basename(target).lower() not in allowed_names
            ):
                raise click.ClickException(f"refusing unowned binary target: {target}")
            if plan.platform_name == "win32" and os.path.lexists(target) and _is_reparse_path(target):
                raise click.ClickException(f"refusing symlink or reparse-point binary target: {target}")
        if plan.platform_name == "win32":
            _validate_windows_binary_ownership(plan)

    if plan.gateway_path:
        if plan.platform_name == "win32":
            install_root = _validate_owned_root(plan.install_root, "binary install root")
            _validate_windows_ancestor_chain(plan.install_root, "binary install root")
            if (
                _normalized(os.path.dirname(plan.gateway_path)) != install_root
                or os.path.basename(plan.gateway_path).lower() != "defenseclaw-gateway.exe"
            ):
                raise click.ClickException(f"refusing unowned gateway target: {plan.gateway_path}")
        elif not os.path.isabs(plan.gateway_path) or os.path.basename(plan.gateway_path) != "defenseclaw-gateway":
            raise click.ClickException(f"refusing invalid gateway target: {plan.gateway_path}")


def _requires_deferred_cleanup(plan: UninstallPlan) -> bool:
    if (
        plan.platform_name != "win32"
        or not plan.remove_data_dir
        or not plan.managed_venv
        or ".venv" in plan.preserve_data_entries
    ):
        return False
    executable = _normalized(sys.executable)
    runtime = _normalized(plan.managed_venv)
    try:
        return os.path.commonpath((runtime, executable)) == runtime
    except ValueError:
        return False


def _schedule_deferred_cleanup(plan: UninstallPlan) -> str:
    """Start the validated standalone helper and wait for its ready signal."""
    _validate_plan(plan)
    base_python = os.path.realpath(os.path.abspath(getattr(sys, "_base_executable", "") or ""))
    interpreter_dirs = _deferred_interpreter_dirs(plan, base_python) if base_python else []
    # The installer's Python is in <data_dir>\.uv (install.ps1); any other
    # base Python inside the data dir is not trusted to run the helper.
    uv_dir = os.path.join(plan.data_dir, ".uv")
    if (
        not base_python
        or not os.path.isfile(base_python)
        or _is_reparse_path(base_python)
        or (
            _normalized(base_python).startswith(_normalized(plan.data_dir) + os.sep)
            and not (
                _normalized(base_python).startswith(_normalized(uv_dir) + os.sep)
                and not _is_reparse_path(uv_dir)
            )
        )
    ):
        raise click.ClickException("no trusted base Python is available for deferred cleanup")

    token = uuid.uuid4().hex
    helper_dir = tempfile.mkdtemp(prefix=f"defenseclaw-uninstall-{token}-")
    helper_path = os.path.join(helper_dir, "windows_uninstall_helper.py")
    manifest_path = os.path.join(helper_dir, "plan.json")
    ready_path = os.path.join(helper_dir, "ready.json")
    status_path = os.path.join(tempfile.gettempdir(), f"defenseclaw-uninstall-result-{token}.json")
    source = os.path.join(os.path.dirname(__file__), "windows_uninstall_helper.py")
    try:
        shutil.copyfile(source, helper_path)
        manifest = {
            "parent_pid": os.getpid(),
            # Windows venv launchers report the base interpreter as the live
            # process image even though sys.executable names Scripts/python.exe.
            "parent_executable": base_python,
            "install_root": plan.install_root,
            "data_dir": plan.data_dir,
            "managed_venv": plan.managed_venv,
            "protected_paths": [
                os.path.realpath(os.path.expanduser("~")),
                str(Path(os.path.abspath(plan.data_dir)).anchor),
            ],
            "binary_targets": list(plan.binary_targets if plan.remove_binaries else plan.data_bound_launchers),
            "remove_data_dir": plan.remove_data_dir,
            "remove_empty_install_root": plan.remove_binaries,
            # The folders holding the helper's own Python: they go once it exits.
            "interpreter_dirs": interpreter_dirs,
            "ready_path": ready_path,
            "status_path": status_path,
        }
        with open(manifest_path, "w", encoding="utf-8") as stream:
            json.dump(manifest, stream, sort_keys=True)
        flags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
        process = subprocess.Popen(
            [base_python, "-I", helper_path, manifest_path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=flags,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if os.path.isfile(ready_path):
                with open(ready_path, encoding="utf-8") as stream:
                    ready = json.load(stream)
                if ready.get("status") != "ready":
                    raise click.ClickException(
                        f"deferred cleanup helper rejected the plan: {ready.get('detail', 'unknown error')}"
                    )
                return status_path
            if process.poll() is not None:
                raise click.ClickException(f"deferred cleanup helper exited before ready (exit {process.returncode})")
            time.sleep(0.05)
        process.terminate()
        raise click.ClickException("deferred cleanup helper did not become ready")
    except Exception:
        if not os.path.exists(ready_path):
            shutil.rmtree(helper_dir, ignore_errors=True)
        raise


def _capture_managed_process(
    pid_file: str,
    expected_executable: str,
    *,
    label: str,
) -> _WindowsProcessWaiter | None:
    """Open an identity-bound Windows process handle from a safe PID record."""
    import ctypes
    from ctypes import wintypes

    from defenseclaw.doctor_gateway import canonical_path, read_pid_record

    record = read_pid_record(pid_file)
    if record.status == "missing":
        return None
    if record.status != "ok":
        raise click.ClickException(f"refusing unsafe {label} PID record: {record.reason}")
    if not record.executable or canonical_path(record.executable) != canonical_path(expected_executable):
        raise click.ClickException(f"refusing {label} PID record for an unowned executable")
    identity = record.start_identity
    if not identity:
        raise click.ClickException(f"refusing {label} PID record without a start identity")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_process.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    handle = open_process(
        _WIN_SYNCHRONIZE | _WIN_PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        record.pid,
    )
    if not handle:
        if ctypes.get_last_error() == 87:  # ERROR_INVALID_PARAMETER: process exited.
            return None
        raise click.ClickException(f"could not open identity-bound {label} process {record.pid}")
    try:
        query_image = kernel32.QueryFullProcessImageNameW
        query_image.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        )
        query_image.restype = wintypes.BOOL
        size = wintypes.DWORD(32768)
        image = ctypes.create_unicode_buffer(size.value)
        if not query_image(handle, 0, image, ctypes.byref(size)):
            raise click.ClickException(f"could not verify {label} executable identity")
        if canonical_path(image.value) != canonical_path(expected_executable):
            raise click.ClickException(f"refusing {label} PID reused by an unowned executable")

        class FILETIME(ctypes.Structure):
            _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

        get_times = kernel32.GetProcessTimes
        get_times.argtypes = tuple([wintypes.HANDLE] + [ctypes.POINTER(FILETIME)] * 4)
        get_times.restype = wintypes.BOOL
        creation, exit_time, kernel_time, user_time = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        if not get_times(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            raise click.ClickException(f"could not verify {label} start identity")
        ticks_100ns = (creation.high << 32) | creation.low
        unix_ns = (ticks_100ns - 116_444_736_000_000_000) * 100
        if str(unix_ns) != identity:
            raise click.ClickException(f"{label} PID start identity does not match")
        return _WindowsProcessWaiter(label=label, pid=record.pid, handle=int(handle))
    except Exception:
        close_handle(handle)
        raise


def _capture_managed_processes(plan: UninstallPlan) -> list[_WindowsProcessWaiter]:
    waiters: list[_WindowsProcessWaiter] = []
    try:
        for label, filename in (("watchdog", "watchdog.pid"), ("gateway", "gateway.pid")):
            waiter = _capture_managed_process(
                os.path.join(plan.data_dir, filename),
                plan.gateway_path,
                label=label,
            )
            if waiter is not None:
                waiters.append(waiter)
    except Exception:
        _close_process_waiters(waiters)
        raise
    return waiters


def _close_process_waiters(waiters: list[_WindowsProcessWaiter]) -> None:
    if not waiters:
        return
    import ctypes
    from ctypes import wintypes

    close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    for waiter in waiters:
        close_handle(waiter.handle)


def _wait_managed_processes(waiters: list[_WindowsProcessWaiter]) -> None:
    if not waiters:
        return
    import ctypes
    from ctypes import wintypes

    wait = ctypes.WinDLL("kernel32", use_last_error=True).WaitForSingleObject
    wait.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    wait.restype = wintypes.DWORD
    for waiter in waiters:
        if wait(waiter.handle, 15_000) != 0:
            raise click.ClickException(f"identity-bound {waiter.label} process did not exit (PID {waiter.pid})")


def _managed_host_has_no_own_gateway(plan: UninstallPlan | None) -> bool:
    """Report whether this Linux or macOS host has a managed deployment and
    this account's per-user gateway is not running (its gateway.pid names no
    live process)."""
    if os.name == "nt":
        return False
    from defenseclaw import upgrade_shim

    if not upgrade_shim.managed_deployment():
        return False
    data_dir = plan.data_dir if plan is not None and plan.data_dir else config_module.default_data_path()
    return not _pid_file_names_a_live_process(os.path.join(str(data_dir), "gateway.pid"))


def _pid_file_names_a_live_process(path: str) -> bool:
    """Report whether the gateway PID file at *path* names a live process
    (the file holds the PID, alone or as the ``pid`` of a JSON record)."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read(4096).strip()
    except OSError:
        return False
    pid: object = None
    try:
        pid = json.loads(text)
    except ValueError:
        return False
    if isinstance(pid, dict):
        pid = pid.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True  # alive, owned by another account
    return True


def _stop_gateway(plan: UninstallPlan | None = None) -> None:
    gw = plan.gateway_path if plan is not None else shutil.which("defenseclaw-gateway")
    if gw is None:
        ux.subhead("sidecar not on PATH — nothing to stop")
        return
    waiters: list[_WindowsProcessWaiter] = []
    try:
        if plan is not None and not os.path.isfile(gw):
            ux.subhead("owned sidecar is not installed — nothing to stop")
            return
        if plan is not None and plan.platform_name == "win32":
            waiters = _capture_managed_processes(plan)
        watchdog = subprocess.run(
            [gw, "watchdog", "stop"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        if watchdog.returncode != 0:
            detail = (watchdog.stderr or watchdog.stdout or "unknown error").strip()
            raise click.ClickException(f"could not stop watchdog: {detail}")
        proc = subprocess.run(
            [gw, "stop"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        if proc.returncode != 0 and _managed_host_has_no_own_gateway(plan):
            # On a managed host `stop` refuses whenever this account's own
            # gateway is not running (and it cannot run there), so there is
            # nothing of this install to stop; the teardown continues.
            ux.subhead("no per-user sidecar runs for this account on this managed host — nothing to stop")
            return
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "unknown error").strip()
            raise click.ClickException(f"could not stop sidecar: {detail}")
        _wait_managed_processes(waiters)
        _close_process_waiters(waiters)
        waiters = []
        ux.ok("sidecar stopped")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise click.ClickException(f"could not stop sidecar: {exc}") from exc
    finally:
        _close_process_waiters(waiters)


def _gateway_supports_sandbox_teardown(gateway_path: str) -> bool:
    """Return True iff the gateway binary has ``sandbox teardown``."""
    try:
        proc = subprocess.run(
            [gateway_path, "sandbox", "teardown", "--help"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0 and "--keep-images" in (proc.stdout or "")


# The exit status of a sandbox command where sandboxes are not supported
# (sandboxcli.ErrUnsupported: the platform, or a managed_enterprise
# deployment): none can have run, so there is nothing to tear down.
_SANDBOX_UNSUPPORTED_EXIT = 3


def _sandbox_teardown(plan: UninstallPlan) -> None:
    """Run ``defenseclaw-gateway sandbox teardown --yes``.

    A gateway without the command predates OpenShell 0.1 sandboxes, and one
    that reports sandboxes unsupported here never ran any, so there is
    nothing of them to remove. Any other failed teardown stops the
    uninstall: the data directory still holds the receipt needed to restore
    the OpenShell gateway configuration. ``--skip-sandbox-teardown`` leaves
    the sandboxes to a later teardown.
    """
    gw = plan.gateway_path
    if not gw or not os.path.isfile(gw):
        ux.subhead("gateway binary not installed — no sandboxes to tear down")
        return
    if not _gateway_supports_sandbox_teardown(gw):
        ux.subhead("this gateway has no OpenShell sandbox support — nothing to tear down")
        return
    try:
        proc = subprocess.run(
            [gw, "sandbox", "teardown", "--yes"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=900,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise click.ClickException(f"sandbox teardown did not finish: {exc}") from exc
    for line in (proc.stdout or "").splitlines():
        if line.strip():
            click.echo(f"  {ux.dim('·')} {line.strip()}")
    detail = (proc.stderr or proc.stdout or "").strip().splitlines()
    if proc.returncode == _SANDBOX_UNSUPPORTED_EXIT:
        reason = detail[-1].lstrip("✗ ").strip() if detail else "OpenShell sandboxes are not supported here"
        ux.subhead(f"sandbox teardown skipped: {reason}")
        return
    if proc.returncode != 0:
        raise click.ClickException(
            "aborting uninstall: sandbox teardown failed"
            + (f" ({detail[-1]})" if detail else "")
            + "; fix it and rerun, run `defenseclaw-gateway sandbox teardown` yourself first, "
            + "or rerun with --skip-sandbox-teardown to leave the sandboxes for a later teardown"
        )
    ux.ok("sandbox teardown complete")


def _gateway_supports_connector_teardown(gateway_path: str | None = None) -> bool:
    """Return True iff the local ``defenseclaw-gateway`` exposes the
    ``connector teardown`` subcommand introduced in S7.2.

    Older binaries print a usage error that includes ``unknown command``
    on stderr; the subprocess returncode is also non-zero. We detect
    by asking for ``--help`` on the ``connector`` subcommand — which is
    a non-destructive probe — and checking exit code + output.
    """
    gw = gateway_path or shutil.which("defenseclaw-gateway")
    if gw is None:
        return False
    try:
        proc = subprocess.run(
            [gw, "connector", "--help"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if proc.returncode != 0:
        return False
    combined = (proc.stdout or "") + (proc.stderr or "")
    return "teardown" in combined and "list-backups" in combined


def _connector_teardown(plan: UninstallPlan) -> None:
    """Run connector teardown via the canonical sentinel, falling back
    to the OpenClaw-specific Python helpers when the gateway binary
    is too old (pre-S7.2) or the connector isn't OpenClaw.

    For non-OpenClaw connectors the Python fallback path is **not**
    safe — calling ``restore_openclaw_config`` against a Codex install
    would corrupt it — so we hard-fail in that case with a clear
    remediation pointing at the gateway upgrade path.
    """
    connectors = plan.connectors
    gateway_supported = _gateway_supports_connector_teardown(plan.gateway_path or None)
    for name in connectors:
        if gateway_supported:
            teardown_ok = (
                _run_gateway_connector_teardown(name, plan=plan)
                if plan.gateway_path
                else _run_gateway_connector_teardown(name)
            )
            if teardown_ok:
                continue
            if name != "openclaw" and _gateway_connector_is_unknown(name, plan=plan):
                # An older release registered this connector and this build no
                # longer ships it, so nothing can tear it down. Its leftover
                # agent-side hook entries are documented for manual removal;
                # they must not block uninstalling DefenseClaw itself.
                ux.warn(
                    f"{name} is not a connector this DefenseClaw build ships; skipping its "
                    "host teardown. Remove any DefenseClaw hook entries from that agent's "
                    "config by hand (see Upgrade → Renamed and removed connectors in the docs)."
                )
                continue
            ux.warn(f"gateway connector teardown for {name} reported errors — see output above")
            if name != "openclaw":
                raise click.ClickException(
                    f"aborting uninstall: {name} teardown failed, so "
                    "DefenseClaw will not remove data or binaries that may be "
                    "needed to restore the agent configuration"
                )

        if name in _PYTHON_FALLBACK_CONNECTORS:
            _revert_openclaw_python(plan)
            continue

        raise click.ClickException(
            f"aborting uninstall: no Python fallback for connector '{name}'. "
            "Upgrade defenseclaw-gateway to v0.7+ (introduces 'connector teardown') "
            "and re-run 'defenseclaw uninstall'."
        )


# ``defenseclaw-gateway connector verify`` exits 2 for a connector name its
# registry cannot resolve (a config error), distinct from 1 for residue.
_GATEWAY_UNKNOWN_CONNECTOR_EXIT = 2


def _gateway_connector_is_unknown(connector: str, *, plan: UninstallPlan | None = None) -> bool:
    """Report whether the gateway registry does not know *connector* at all.

    Only an explicit "unknown connector" verdict returns True; a missing
    gateway, a launch failure, or residue all return False so the caller keeps
    its fail-closed abort.
    """
    gw = plan.gateway_path if plan is not None and plan.gateway_path else shutil.which("defenseclaw-gateway")
    if gw is None:
        return False
    try:
        proc = subprocess.run(
            [
                gw,
                "connector",
                "verify",
                "--connector",
                connector,
                *(["--data-dir", plan.data_dir] if plan is not None else []),
            ],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == _GATEWAY_UNKNOWN_CONNECTOR_EXIT and "unknown connector" in (proc.stderr or "")


def _run_gateway_connector_teardown(connector: str, *, plan: UninstallPlan | None = None) -> bool:
    """Invoke ``defenseclaw-gateway connector teardown --connector <name>``.

    Returns True on success (rc == 0), False on any error. stdout/stderr
    is forwarded to the operator so they can see exactly what each
    adapter restored.
    """
    gw = plan.gateway_path if plan is not None else shutil.which("defenseclaw-gateway")
    if gw is None:
        return False
    try:
        proc = subprocess.run(
            [
                gw,
                "connector",
                "teardown",
                "--connector",
                connector,
                *(["--data-dir", plan.data_dir] if plan is not None else []),
            ],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        ux.warn(f"gateway connector teardown failed to launch: {exc}")
        return False
    if proc.stdout:
        for line in proc.stdout.splitlines():
            click.echo(f"  {ux.dim('·')} {line}")
    if proc.stderr and proc.returncode != 0:
        for line in proc.stderr.splitlines():
            click.echo(f"  {ux._style('⚠', fg='yellow', bold=True)} {line}")
    if proc.returncode == 0:
        verify_args = [
            gw,
            "connector",
            "verify",
            "--connector",
            connector,
            *(["--data-dir", plan.data_dir] if plan is not None else []),
        ]
        try:
            verified = subprocess.run(
                verify_args,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            ux.warn(f"gateway connector verification failed to launch: {exc}")
            return False
        if verified.returncode != 0:
            detail = (verified.stderr or verified.stdout or "residual connector state").strip()
            ux.warn(f"{connector} teardown verification failed: {detail}")
            return False
        ux.ok(f"{connector} teardown via gateway sentinel")
        return True
    return False


def _revert_openclaw_python(plan: UninstallPlan) -> None:
    """OpenClaw-specific revert path used as a fallback when the gateway
    sentinel is unavailable. NOT safe for other connectors."""
    from defenseclaw.guardrail import (
        pristine_backup_path,
        restore_openclaw_config,
    )

    pristine = pristine_backup_path(plan.openclaw_config_file, plan.data_dir)
    target = _expand(plan.openclaw_config_file)
    if pristine:
        try:
            shutil.copy2(pristine, target)
            ux.ok(f"restored {target} from pristine backup ({os.path.basename(pristine)})")
            return
        except OSError as exc:
            ux.warn(f"pristine restore failed: {exc} — falling back to config edit")

    # Fall back to the surgical restore — removes our plugin registration
    # without rolling the file back to its exact prior state.
    try:
        ok = restore_openclaw_config(plan.openclaw_config_file, original_model="")
        if ok:
            ux.ok(f"removed DefenseClaw entries from {plan.openclaw_config_file}")
        else:
            raise click.ClickException(f"could not revert {plan.openclaw_config_file} (missing or malformed)")
    except Exception as exc:
        if isinstance(exc, click.ClickException):
            raise
        raise click.ClickException(f"openclaw.json revert failed: {exc}") from exc


def _remove_plugin(plan: UninstallPlan) -> None:
    from defenseclaw.guardrail import uninstall_openclaw_plugin

    result = uninstall_openclaw_plugin(plan.openclaw_home)
    if result == "cli":
        ux.ok("plugin uninstalled via openclaw CLI")
    elif result == "manual":
        ux.ok("plugin directory removed")
    elif result == "":
        ux.subhead("plugin was not installed")
    else:
        raise click.ClickException("plugin uninstall failed (check permissions)")


def _is_reparse_path(path: str | os.PathLike[str]) -> bool:
    """Return whether *path* is a symlink or Windows reparse point."""
    if os.path.islink(path):
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction and isjunction(path):
        return True
    # Python 3.10/3.11 do not expose os.path.isjunction(). Windows lstat
    # still exposes the reparse attribute, covering junctions and mount
    # points without resolving or traversing them.
    try:
        attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _remove_tree_entry(entry: os.DirEntry[str]) -> None:
    """Remove one direct child without following symlinks/reparse points."""
    if _is_reparse_path(entry.path):
        if os.path.isdir(entry.path):
            os.rmdir(entry.path)
        else:
            os.unlink(entry.path)
        return
    if entry.is_dir(follow_symlinks=False):
        shutil.rmtree(entry.path)
        return
    os.unlink(entry.path)


def _remove_data_dir(
    data_dir: str,
    *,
    preserve_entries: tuple[str, ...] = (),
) -> None:
    # Safety guard: an empty / root-like path here would be catastrophic
    # because we're about to recursively delete. Bail out unless the
    # directory genuinely looks like a DefenseClaw data dir (i.e.
    # contains one of the files we ourselves write on init). This
    # protects operators who set ``DEFENSECLAW_HOME`` to somewhere weird
    # like ``/`` or ``$HOME`` against a catastrophic rm -rf.
    if not data_dir or not os.path.isdir(data_dir):
        ux.subhead(f"{data_dir} does not exist — skipping")
        return
    if _is_reparse_path(data_dir):
        raise click.ClickException(f"refusing to remove symlink or reparse-point data path {data_dir}")

    unknown_preserves = set(preserve_entries) - set(_RESET_PRESERVED_ENTRIES)
    if unknown_preserves:
        raise click.ClickException(
            "refusing unrecognized reset preservation entries: " + ", ".join(sorted(unknown_preserves))
        )

    # Disallow top-level / root-ish paths outright.
    resolved = os.path.realpath(data_dir)
    protected = {
        os.path.normcase(os.path.realpath(os.path.expanduser("~"))),
        os.path.normcase(str(Path(resolved).anchor)),
        os.path.normcase(os.path.realpath("/")),
    }
    if os.path.normcase(resolved) in protected:
        raise click.ClickException(f"refusing to remove protected path {resolved}")

    preserved: set[str] = set()
    for name in preserve_entries:
        candidate = os.path.join(data_dir, name)
        if not os.path.lexists(candidate):
            continue
        if _is_reparse_path(candidate) or not os.path.isdir(candidate):
            raise click.ClickException(f"refusing to preserve unsafe managed runtime {candidate}")
        if os.path.commonpath((resolved, os.path.realpath(candidate))) != resolved:
            raise click.ClickException(f"managed runtime resolves outside the data directory: {candidate}")
        preserved.add(name)

    markers = (
        "config.yaml",
        "audit.db",
        ".env",
        "policies",
        "quarantine",
        ".venv",
    )
    if not any(os.path.exists(os.path.join(data_dir, m)) for m in markers):
        raise click.ClickException(
            f"refusing to remove {data_dir}: path does not look like a DefenseClaw data directory"
        )

    failures: list[str] = []
    with os.scandir(data_dir) as entries:
        children = list(entries)

    # Delete non-markers first. If one fails, retain the known markers so a
    # later retry can still prove this is a DefenseClaw directory instead of
    # getting stranded after a partial deletion.
    for marker_pass in (False, True):
        if failures:
            break
        for entry in children:
            if entry.name in preserved:
                continue
            if (entry.name in markers) != marker_pass:
                continue
            try:
                _remove_tree_entry(entry)
            except OSError as exc:
                failures.append(f"{entry.name}: {exc}")

    if failures:
        raise OSError("; ".join(failures))

    if preserved:
        ux.ok(f"removed resettable state from {data_dir} (preserved {', '.join(sorted(preserved))})")
        return

    try:
        os.rmdir(data_dir)
    except OSError as exc:
        raise OSError(f"could not remove data directory: {exc}") from exc
    ux.ok(f"removed {data_dir}")


def _remove_binaries(plan: UninstallPlan | None = None) -> None:
    if plan is None:
        platform_name = sys.platform
        install_root, targets = _owned_binary_targets(platform_name)
        plan = UninstallPlan(
            platform_name=platform_name,
            install_root=install_root,
            gateway_path=os.path.join(
                install_root,
                "defenseclaw-gateway.exe" if platform_name == "win32" else "defenseclaw-gateway",
            ),
            binary_targets=targets,
            remove_binaries=True,
        )
    _validate_plan(plan)
    failures: list[str] = []
    targets = list(plan.binary_targets)
    if plan.platform_name == "win32":
        targets.sort(key=lambda path: os.path.basename(path).lower() == "defenseclaw.cmd")
    for path in targets:
        if not os.path.lexists(path):
            # The plan lists only the launchers that exist; the owned-name
            # list also names optional ones most installs never had.
            continue
        last_error: OSError | None = None
        attempts = 40 if plan.platform_name == "win32" else 1
        for attempt in range(attempts):
            try:
                if plan.platform_name == "win32":
                    _validate_plan(plan)
                os.unlink(path)
                ux.ok(f"removed {path}")
                last_error = None
                break
            except FileNotFoundError:
                last_error = None
                break
            except OSError as exc:
                last_error = exc
                if attempt + 1 < attempts:
                    time.sleep(0.25)
        if last_error is not None:
            failures.append(f"{path}: {last_error}")

    if failures:
        raise OSError("; ".join(failures))

    _remove_install_bookkeeping(plan.install_root, plan.data_dir)
    if plan.platform_name == "win32" and _install_root_empties(plan):
        with contextlib.suppress(OSError):
            os.rmdir(plan.install_root)
        _remove_user_path_entry(plan)
    elif plan.platform_name != "win32":
        # An empty ~/.local/bin goes too, and so does ~/.local when that
        # leaves it empty.
        try:
            if not os.listdir(plan.install_root):
                os.rmdir(plan.install_root)
                _remove_empty_parents(plan.install_root)
        except OSError:
            pass

    # A pip-installed CLI is outside this plan; we don't shell out to pip
    # because we can't be sure which environment was used. Mention it only
    # when another defenseclaw is still on PATH.
    remaining = shutil.which("defenseclaw")
    if remaining:
        ux.subhead(
            f"another defenseclaw remains at {remaining}; if you installed it with pip, run 'pip uninstall defenseclaw'"
        )


# Hidden files the installers keep next to the launchers: the source-install
# marker and the publish custody directory. Neither is useful once the
# launchers are gone.
_INSTALL_BOOKKEEPING = (".defenseclaw-source-root", ".defenseclaw-install-custody")


def _legacy_custody_parents() -> list[str]:
    """Temp folders where pre-1.0 installers parked retired binaries."""
    if sys.platform == "win32":
        return []
    return sorted({tempfile.gettempdir(), "/tmp"})


def _legacy_home_custody_dirs(data_dir: str) -> list[str]:
    """Custody folders pre-1.0 installers left beside DEFENSECLAW_HOME.

    install.sh removes the same folders after a 1.0 install, but a source
    install never runs it, so they pile up with each 0.8.x install.
    """
    if sys.platform == "win32" or not data_dir:
        return []
    parents = {os.path.expanduser("~"), os.path.dirname(os.path.abspath(os.path.expanduser(data_dir)))}
    return [os.path.join(parent, ".defenseclaw-install-custody") for parent in sorted(parents)]


def _remove_install_bookkeeping(install_root: str, data_dir: str = "") -> None:
    paths = [os.path.join(install_root, name) for name in _INSTALL_BOOKKEEPING]
    paths.extend(_legacy_home_custody_dirs(data_dir))
    for parent in _legacy_custody_parents():
        try:
            names = os.listdir(parent)
        except OSError:
            continue
        paths.extend(os.path.join(parent, name) for name in names if name.startswith(".defenseclaw-install-custody-"))
    for path in paths:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            ux.warn(f"could not inspect {path}: {exc}")
            continue
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            if os.path.dirname(path) == install_root:
                ux.warn(f"left {path}: it is not owned by this account")
            continue
        try:
            if stat.S_ISDIR(info.st_mode):
                shutil.rmtree(path)
            else:
                os.unlink(path)
        except OSError as exc:
            ux.warn(f"could not remove {path}: {exc}")
            continue
        ux.ok(f"removed {path}")


def _install_root_empties(plan: UninstallPlan) -> bool:
    """Report whether the install root holds nothing but what this plan removes.

    install.ps1 added the folder to the user Path for DefenseClaw; once
    nothing else is in it, the entry goes. A folder other tools still use
    keeps its entry.
    """
    try:
        names = os.listdir(plan.install_root)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    owned = {os.path.basename(path).lower() for path in plan.binary_targets}
    owned.update(name.lower() for name in _INSTALL_BOOKKEEPING)
    return all(name.lower() in owned for name in names)


def _path_without_entry(raw: str, directory: str, expand: Callable[[str], str]) -> str:
    """Return the Path value raw without its entries naming directory.

    The other entries, their order and their unexpanded %VAR% text stay. An
    entry names directory when it does after expand (and without quotes or a
    trailing backslash), compared without case as Windows does.
    """
    wanted = directory.rstrip("\\/").lower()
    kept = []
    for entry in raw.split(";"):
        candidate = expand(entry.strip().strip('"')).rstrip("\\/").lower() if entry.strip() else ""
        if candidate and candidate == wanted:
            continue
        kept.append(entry)
    return ";".join(kept)


def _remove_user_path_entry(plan: UninstallPlan) -> None:
    """Remove the install root from the user Path install.ps1 added it to (Windows)."""
    if plan.platform_name != "win32" or sys.platform != "win32":
        return
    try:
        changed = _edit_windows_user_path(plan.install_root)
    except OSError as exc:
        ux.warn(f"could not remove {plan.install_root} from your user Path: {exc}; remove it in Environment Variables")
        return
    if changed:
        ux.ok(f"removed {plan.install_root} from your user Path (new terminals get the change)")


def _edit_windows_user_path(directory: str) -> bool:
    import ctypes
    import winreg

    access = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, access) as key:
        try:
            raw, kind = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            return False
        if kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or not isinstance(raw, str):
            return False
        # winreg returns REG_EXPAND_SZ unexpanded; writing it back with its
        # own kind keeps the %VAR% entries.
        value = _path_without_entry(raw, directory, winreg.ExpandEnvironmentStrings)
        if value == raw:
            return False
        winreg.SetValueEx(key, "Path", 0, kind, value)
    # Tell Explorer, so terminals opened from now on get the new Path.
    result = ctypes.c_size_t()
    ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x1A, 0, "Environment", 2, 5000, ctypes.byref(result))
    return True


def _local_observability_teardown(data_dir: str) -> None:
    """Remove the local observability stack's containers and data volumes.

    Only when Docker is installed and holds the stack: a host that never ran
    `defenseclaw setup local-observability` is not touched. A stack Docker
    cannot reach stays, with the command that removes it.
    """
    compose_file = _local_observability_stack_file(data_dir)
    if not compose_file or not shutil.which("docker"):
        return
    try:
        from defenseclaw.observability import local_stack
    except Exception:  # noqa: BLE001 - a broken bundle leaves nothing to drive.
        return
    manual = f"docker compose -p {local_stack.COMPOSE_PROJECT} down --volumes"
    try:
        controller = local_stack.LocalStackController(os.path.dirname(compose_file))
        if not _local_observability_present(controller, local_stack.COMPOSE_PROJECT):
            return
        controller.reset(confirmed=True)
    except Exception as exc:  # noqa: BLE001 - reported, the uninstall goes on.
        ux.warn(f"the local observability stack and its data volumes stay: {exc}; remove them with: {manual}")
        return
    ux.ok("removed the local observability stack and its data volumes")


def _local_observability_present(controller, project: str) -> bool:
    """Report whether Docker holds a container or volume of the stack."""
    label = f"label=com.docker.compose.project={project}"
    for argv in (
        [controller.docker_path, "ps", "--all", "--quiet", "--filter", label],
        [controller.docker_path, "volume", "ls", "--quiet", "--filter", label],
    ):
        result = controller.runner.run(argv, timeout=15, env=controller.environment)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()
            raise RuntimeError(f"Docker did not answer ({detail[0] if detail else f'exit {result.returncode}'})")
        if result.stdout.strip():
            return True
    return False


def _expand(p: str) -> str:
    if p.startswith("~/"):
        return os.path.expanduser(p)
    return p
