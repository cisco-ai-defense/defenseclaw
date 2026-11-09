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

import base64
import codecs
import contextlib
import errno
import filecmp
import glob
import json
import ntpath
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

import click

from defenseclaw import codex_toml, legacy_connector, link_guard, ux
from defenseclaw import config as config_module

# Imported here, not where it is used: by then the data removal has deleted
# the virtual environment this CLI runs from (GAP-1397).
from defenseclaw.bootstrap import _DEFAULT_GUARDRAIL_PORT, remove_own_api_port_claims
from defenseclaw.commands import legacy_setup_install, windows_uninstall_helper
from defenseclaw.commands.cmd_doctor import _codex_otel_marked_kept
from defenseclaw.connector_paths import claude_settings_paths, codex_home
from defenseclaw.file_lock import tui_lock_held
from defenseclaw.gateway import path_gateway
from defenseclaw.winquote import (
    powershell_literal,
    powershell_literal_before_typographic_quotes,
    powershell_literal_value,
)

# Connectors whose teardown the Python CLI knows how to perform locally
# without going through ``defenseclaw-gateway connector teardown``. This
# is the conservative fallback path used when the gateway binary is too
# old to expose the connector subcommand.
_PYTHON_FALLBACK_CONNECTORS: frozenset[str] = frozenset({"openclaw"})
# .uv holds the Python the installer's venv runs on (scripts/install.sh).
_RESET_PRESERVED_ENTRIES: tuple[str, ...] = (".venv", ".uv")
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
# The installers (scripts/install.sh, scripts/install.ps1) write this record
# beside the launchers when they install uv because it was missing: one
# "<sha256>  <name>" line per file. `uninstall --binaries` removes the files
# that still match it, and keeps a uv that was updated or replaced since.
_UV_RECORD = "defenseclaw-uv.sha256"
# `defenseclaw-gateway stop` itself waits up to about 25s (shutdown request,
# 10s graceful exit, then a signal and 10s more, then a kill), so a shorter
# wait here failed the whole uninstall while the stop was still working
# (GAP-2100).
_GATEWAY_STOP_TIMEOUT_SECONDS = 45
_UV_NAMES = {"win32": ("uv.exe", "uvx.exe", "uvw.exe")}
_UV_NAMES_POSIX = ("uv", "uvx")
_UV_RECORD_MAX_BYTES = 4096
# The 0.8.x installer left uv, uv's cache and ~/.sigstore (its temporary
# Cosign) without a marker. The upgrade from 0.8.x records them only on
# evidence a user's own uv or Cosign cannot meet (scripts/install.sh,
# find_legacy_leftovers; GAP-0908): "uv-cache", with the 0.8.x uv in
# _UV_RECORD, and "sigstore", one claim per line. uv's Python folder is never
# claimed: other tools can share it.
_LEGACY_LEFTOVERS_RECORD = "legacy-install-leftovers"
_LEGACY_LEFTOVERS_MAX_BYTES = 4096
# What uv itself keeps at the top of its cache: its tag and lock files and
# one versioned bucket per kind (archive-v0, wheels-v5, simple-v16, ...).
_UV_CACHE_TOP_ENTRY = re.compile(r"CACHEDIR\.TAG|\.gitignore|\.lock|[a-z]+(?:-[a-z]+)*-v[0-9]+")
# The folders DefenseClaw created because they were missing (the gateway's
# install watcher, connector setup); see the Go connector package's
# watcher_created_dirs.go. Uninstall removes the ones still empty.
_CREATED_DIRS_RECORD = "watcher-created-dirs.json"
_CREATED_DIRS_RECORD_MAX_BYTES = 1 << 20
_WIN_SYNCHRONIZE = 0x00100000
_WIN_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
# until 1.1: OpenHands and OmniGent, whose older-release state uninstall still
# tears down (connector_backups markers, their hook script or policy module,
# and active_connector.json names). The teardown removes what DefenseClaw wrote
# for them, by identity; uninstall lists what is left.
_REMOVED_CONNECTOR_BACKUP_MARKERS: dict[str, tuple[str, ...]] = {
    "omnigent": (
        os.path.join("connector_backups", "omnigent", "config.json"),
        os.path.join("connector_backups", "omnigent", "module.json"),
        os.path.join("connector_backups", "omnigent", "pth.json"),
        os.path.join("hooks", "defenseclaw_omnigent_policy.py"),
    ),
    "openhands": (
        os.path.join("connector_backups", "openhands", "config.json"),
        os.path.join("hooks", "openhands-hook.sh"),
    ),
}
_ACTIVE_CONNECTOR_STATE = "active_connector.json"
_ACTIVE_CONNECTOR_STATE_MAX_BYTES = 64 * 1024
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
    "opencode": (os.path.join("connector_backups", "opencode", "config.json"),),
    "devin": (os.path.join("connector_backups", "devin", "config.json"),),
    # until 1.1: OpenHands and OmniGent were removed in 1.0.4 (#1182). An older
    # release's setup backup still selects gateway teardown, which Go resolves
    # through its teardown-only connector.RetiredConnector adapters.
    **_REMOVED_CONNECTOR_BACKUP_MARKERS,
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
    # store_dir is the data_dir config.yaml names when it is another folder
    # than data_dir (the install home): the hook scripts and connector records
    # are there, so teardown reads them there (GAP-0874).
    store_dir: str = ""
    # previous_stores are the folders earlier `config set data_dir` moves left
    # behind (config.previous_store_dirs): Setup wrote records there that a
    # move does not carry (GAP-0874).
    previous_stores: tuple[str, ...] = ()
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
    # live_sandboxes are the live-mounted sandboxes the daemon listed: the
    # teardown stops them and their undo points go (GAP-0295).
    live_sandboxes: tuple[str, ...] = ()
    # running_sandboxes are the sandboxes the daemon listed as running, as
    # (name, workdir mode). They stop the run before any change, unless
    # stop_sandboxes (--stop-sandboxes) lets the teardown stop and delete
    # them (GAP-0368).
    running_sandboxes: tuple[tuple[str, str], ...] = ()
    stop_sandboxes: bool = False
    # sandbox_list_error is why ``sandbox list`` could not say which
    # sandboxes run ("" when it did). The teardown would delete whatever
    # runs, so an unknown answer stops the run too, unless stop_sandboxes.
    sandbox_list_error: str = ""
    # sandboxes_off is set when that unknown answer came with sandboxes off:
    # `sandbox list` cannot list them then, and the off-state teardown's dry
    # run is what names them, once the OpenShell gateway answers (GAP-0037).
    sandboxes_off: bool = False
    # setup_leftovers are the %LOCALAPPDATA%\DefenseClaw folders that
    # DefenseClaw Setup left after the installer replaced it (Windows,
    # --binaries only).
    setup_leftovers: tuple[str, ...] = ()
    # until the 0.8 bridge retires: legacy_setup is a DefenseClaw Setup 0.8.x
    # install the installer left beside this one (its data in another folder,
    # review L5 of cowork-1-0-8 GAP-0088). uninstall removes it without
    # running any of its programs (Windows, uninstall only).
    legacy_setup: legacy_setup_install.LegacySetupInstall | None = None
    # observability_teardown removes the local observability stack
    # (`defenseclaw setup local-observability`) and its data volumes before
    # its Compose files in data_dir go (uninstall --all only).
    observability_teardown: bool = False
    # uv_leftovers are uv's default cache and receipt folder when the upgrade
    # from 0.8.x recorded them and the 0.8.x installer's uv goes too
    # (--all --binaries; GAP-0908).
    uv_leftovers: tuple[str, ...] = ()
    # uv_kept are the uv files and folders next to a uv in install_root that
    # stay because nothing recorded DefenseClaw installed them; the plan and
    # the result name them (--all --binaries, Linux and macOS; GAP-0908).
    uv_kept: tuple[str, ...] = ()
    # uv_cache_entries is uv's cache folder when it holds DefenseClaw entries
    # an earlier installer's uv downloaded there; `uv cache clean defenseclaw`
    # removes only those (--all --binaries; GAP-1411).
    uv_cache_entries: str = ""
    # sigstore_cache is ~/.sigstore when the upgrade from 0.8.x recorded that
    # the 0.8.x installer's temporary Cosign created it and nothing has
    # written to it since (--all --binaries; GAP-0908).
    sigstore_cache: str = ""
    # hook_temp_dirs are the scratch folders (defenseclaw-hook.*) DefenseClaw's
    # shell hooks left in the temp folders (--all; GAP-1411).
    hook_temp_dirs: tuple[str, ...] = ()
    # mac_app is DefenseClawMac.app when it is installed (macOS). Uninstall
    # does not remove the app, its login item or its background service; the
    # plan says how to.
    mac_app: str = ""
    # quarantined are the skill and plugin copies DefenseClaw moved out of
    # the agents' folders (data_dir/quarantine/<kind>/<connector>/<name>):
    # often the only copy, which `--all` deletes with data_dir (GAP-0422).
    quarantined: tuple[str, ...] = ()
    # acp_entries are the guarded ACP editor entries `defenseclaw acp setup`
    # wrote for this account, as (client, agent, editor settings file). They
    # go with their contract locks, as `defenseclaw acp remove` takes them
    # out; until 1.0.6 they stayed and kept starting defenseclaw-acp
    # (GAP-2632). A managed computer's enrollment owns its entries.
    acp_entries: tuple[tuple[str, str, str], ...] = ()
    # config_error is why config.yaml did not load ("" when it did). The
    # uninstall goes on from the connector records and says so; it used to
    # drop the error without a word (rel-1-0-6 GAP-0153).
    config_error: str = ""

    @property
    def records_dir(self) -> str:
        """The folder that holds the connector records and hook scripts."""
        return self.store_dir or self.data_dir

    @property
    def record_dirs(self) -> tuple[str, ...]:
        """Every folder Setup can have written records in.

        The configured data_dir, the folders earlier moves left, then the install home.

        ``config set data_dir`` carries the connector records and seals to the
        new folder and leaves the ACP ownership records, probe and
        created-folder records, OpenClaw backup index and removed-connector
        state in the folder they were written in, and later setups write in the
        new one. Teardown reads every record where it is, each with its own
        ownership proof (GAP-0874).
        """
        return _record_dirs(self.store_dir, self.previous_stores, self.data_dir)


def _record_dirs(store_dir: str, previous_stores: tuple[str, ...], data_dir: str) -> tuple[str, ...]:
    """The folders Setup can have written records in, the current one first, without repeats."""
    seen: list[str] = []
    for folder in (store_dir, *previous_stores, data_dir):
        if folder and not any(config_module._same_folder(folder, known) for known in seen):
            seen.append(folder)
    return tuple(seen)


@dataclass(frozen=True)
class ExecutionPhaseResult:
    """Outcome of one externally visible uninstall/reset phase."""

    name: str
    status: str
    detail: str = ""
    # What the user does about each distinct reason a phase failed (one line each).
    next_steps: tuple[str, ...] = ()


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
@click.option(
    "--all",
    "wipe_data",
    is_flag=True,
    help="Also delete ~/.defenseclaw (audit log, config, secrets, and the skills and plugins it quarantined).",
)
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
@click.option(
    "--stop-sandboxes",
    is_flag=True,
    help=(
        "Stop and delete running OpenShell sandboxes with the sandbox teardown (work a copy-mode sandbox "
        "never pulled back is lost). Without it a running sandbox stops the run before any change."
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
    stop_sandboxes: bool = False,
) -> None:
    """Uninstall DefenseClaw (reversibly by default)."""
    plan = _build_plan(
        wipe_data=wipe_data,
        binaries=binaries,
        revert_openclaw=not keep_openclaw,
        remove_plugin=not keep_openclaw,
        skip_sandbox_teardown=skip_sandbox_teardown,
        legacy_setup=True,
    )
    plan = _with_listed_sandboxes(plan, stop_sandboxes)
    ux.banner("DefenseClaw Uninstall")
    _render_plan(plan, dry_run=dry_run)
    cowork_plugin = _cowork_plugin_built(plan)
    if cowork_plugin:
        ux.echo(f"  • {_COWORK_PLUGIN_STAYS}")

    if dry_run:
        refusal = _open_tui_refusal(plan) or _running_sandboxes_refusal(plan)
        if refusal:
            # The real run stops at plan validation (GAP-2585).
            ux.warn(f"a real run would stop before any change: {refusal}")
        if cowork_plugin:
            # The real run ends with this step; the dry run shows it too (GAP-0084 review F1).
            ux.echo(f"  • DefenseClaw cannot remove its Cowork plugin from your Claude account: {_COWORK_REMOVAL_STEP}")
        ux.subhead("(dry-run — nothing modified)")
        return

    _refuse_running_sandboxes(plan)
    if not yes and not click.confirm("  Proceed?", default=False):
        ux.subhead("Cancelled.")
        raise SystemExit(1)

    from defenseclaw import opencode_service

    # Found before the teardown: --binaries removes the CLI's own files.
    opencode_binary = opencode_service.account_binary() if "opencode" in plan.connectors else ""
    gateway_ports = _configured_gateway_ports()
    result = _execute_plan(plan)
    cowork_problem = _record_cowork_removal(plan.data_dir) if cowork_plugin and plan.remove_data_dir else ""
    _remove_marked_native_otel_left(gateway_ports)
    if opencode_binary:
        # OpenCode V2's background server kept the plugin it loaded (rel-1-0-6 GAP-0026).
        outcome = opencode_service.restart_if_running(opencode_binary)
        opencode_service.report(outcome, what="drops the DefenseClaw plugin")
    if plan.connectors:
        # The plan said so; the end says it again, once it is true (GAP-0255).
        ux.warn("Close any agent session still open: it runs without DefenseClaw's hooks now.")
    if cowork_plugin and not cowork_problem:
        ux.warn(f"DefenseClaw cannot remove its Cowork plugin from your Claude account: {_COWORK_REMOVAL_STEP}")
    _render_kept_and_next_steps(plan)
    left = _phases_left(result)
    if cowork_problem:
        for phase in left:
            _print_phase_left(phase)
        _report_cowork_removal_not_recorded(cowork_problem)
    if left:
        for phase in left:
            _print_phase_left(phase)
        raise SystemExit(1)


_LEGACY_SETUP_PHASE = "DefenseClaw Setup 0.8.x removal"
_SETUP_LEFTOVERS_PHASE = "Setup leftovers removal"
_EARLIER_FOLDER_RECORDS_PHASE = "Earlier data folder records removal"
# Phases that end "failed" without stopping the uninstall: what stayed, and the step for each reason.
_PHASE_LEFT_HEADINGS = {
    _LEGACY_SETUP_PHASE: "DefenseClaw Setup 0.8.x was not removed completely",
    _SETUP_LEFTOVERS_PHASE: "The folders DefenseClaw Setup left were not removed completely",
    _EARLIER_FOLDER_RECORDS_PHASE: "Records Setup wrote in an earlier data folder were not removed",
}


def _phases_left(result: ExecutionResult) -> list[ExecutionPhaseResult]:
    """The phases that could not do all of their removal (none when each did)."""
    return [phase for phase in result.phases if phase.name in _PHASE_LEFT_HEADINGS and phase.status == "failed"]


def _print_phase_left(phase: ExecutionPhaseResult) -> None:
    """Say what stayed, then one next step for each distinct reason it stayed."""
    ux.err(f"{_PHASE_LEFT_HEADINGS[phase.name]}: {phase.detail}")
    if not phase.next_steps:
        ux.err("Fix what is named above, then run the command again.")
        return
    for step in phase.next_steps:
        ux.err(f"  - {step}")


# The one reminder that always reaches the user: the in-chat notice after an
# uninstall reaches only the model, and Claude Desktop shows no banner. Every
# path (uninstall plan, dry run, reset) prints this
# constant (cowork-1-0-8 GAP-0084).
_COWORK_PLUGIN_STAYS = (
    "The DefenseClaw Cowork plugin stays in your Claude account. Remove it in Claude: Customize > Plugins."
)

_COWORK_REMOVAL_STEP = (
    "remove it in Claude Desktop (Customize > Plugins, then the ... menu > Remove). "
    "A plugin built with 1.0.9 lets Cowork calls run after the data folder is removed; older plugins may block."
)


def _cowork_plugin_built(plan: UninstallPlan) -> bool:
    """Whether setup cowork built an account plugin from this data dir."""
    from defenseclaw import cowork

    return bool(plan.data_dir) and os.path.exists(cowork.state_path(plan.data_dir))


def _record_cowork_removal(data_dir: str) -> str:
    """Write the Cowork removal marker; return why it could not, or "".

    It runs after the teardown, so a refusal must not stop what is left of the
    uninstall: the caller finishes, then reports it and exits 1
    (cowork-1-0-8 GAP-0085). No marker means the plugin keeps blocking, never
    that Cowork looks uninstalled.
    """
    from defenseclaw import cowork

    try:
        cowork.mark_uninstalled(data_dir)
    except OSError as exc:
        return str(exc)
    return ""


def _print_cowork_removal_not_recorded(problem: str) -> None:
    ux.err(f"DefenseClaw could not record its removal for the Cowork plugin: {problem}")
    ux.err(
        "Until you remove the DefenseClaw plugin in Claude Desktop (Customize > Plugins, then the ... menu > "
        "Remove), it blocks every Cowork tool call."
    )


def _report_cowork_removal_not_recorded(problem: str) -> None:
    _print_cowork_removal_not_recorded(problem)
    raise SystemExit(1)


_NATIVE_OTEL_READ_LIMIT = 1024 * 1024


def _read_agent_config(path: str) -> bytes:
    """Read one agent config for the post-uninstall OTel check, or b"" (bounded)."""
    try:
        with open(path, "rb") as stream:
            raw = stream.read(_NATIVE_OTEL_READ_LIMIT + 1)
    except OSError:
        return b""
    return b"" if len(raw) > _NATIVE_OTEL_READ_LIMIT else raw


def _marked_claude_otel_headers(env) -> list[str]:
    """Claude Code OTLP header keys that carry both DefenseClaw markers and a bearer.

    Mirror of cmd_doctor._codex_otel_marked_kept for the Claude Code env
    block: x-defenseclaw-source = claudecode, x-defenseclaw-client =
    claudecode-otel/..., and an authorization bearer.
    """
    if not isinstance(env, dict):
        return []
    fields = []
    for key in sorted(env, key=str):
        value = env.get(key)
        if not (
            isinstance(key, str)
            and key.startswith("OTEL_EXPORTER_OTLP_")
            and key.endswith("_HEADERS")
            and isinstance(value, str)
        ):
            continue
        headers = {}
        for item in value.split(","):
            name, sep, header_value = item.partition("=")
            if sep:
                headers[name.strip().lower()] = header_value.strip()
        scheme, _, credential = headers.get("authorization", "").partition(" ")
        if (
            headers.get("x-defenseclaw-source") == "claudecode"
            and headers.get("x-defenseclaw-client", "").startswith("claudecode-otel/")
            and scheme.lower() == "bearer"
            and len(credential.strip()) >= 8
        ):
            fields.append(key)
    return fields


def _paired_claude_otel_endpoints(env, headers: list[str]) -> list[tuple[str, str]]:
    """The OTEL_EXPORTER_OTLP_*_ENDPOINT keys that pair with the marked header keys.

    OTEL_EXPORTER_OTLP_<SIGNAL>_HEADERS pairs with OTEL_EXPORTER_OTLP_<SIGNAL>_ENDPOINT
    (and the signal-less HEADERS with ENDPOINT). Returns (key, host:port) for each
    paired endpoint that is set and points at this machine (where the DefenseClaw
    gateway served it); a remote collector endpoint is the user's and is kept.
    """
    from urllib.parse import urlsplit

    pairs = []
    for header_key in headers:
        key = header_key[: -len("HEADERS")] + "ENDPOINT"
        value = env.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        try:
            parsed = urlsplit(value.strip())
            host, port = parsed.hostname or "", parsed.port
        except ValueError:
            continue
        if host not in ("127.0.0.1", "localhost", "::1"):
            continue
        # hostname:port, never the netloc: it may carry userinfo.
        pairs.append((key, f"{host}:{port}" if port else host))
    return pairs


_TOML_TABLE_HEADER = re.compile(r"^\s*\[(?!\[)\s*([^\[\]]+?)\s*\]\s*(?:#.*)?$")
_TOML_KEY_PART = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'[^']*'|[^.]+")


def _toml_header_path(inner: str) -> list[str]:
    """The dotted key of a [table] header, each part stripped of spaces and quotes."""
    return [part.strip().strip("\"'") for part in _TOML_KEY_PART.findall(inner) if part.strip()]


def _codex_config_without_otel_keys(raw: bytes, keys: set[str], *, drop_inert_table: bool = False) -> bytes | None:
    """config.toml without the [otel.<key>] tables of the given otel keys, or None.

    Text-level, so every other line (comments, order, quoting) stays byte for
    byte. None when the result does not parse to the same document minus
    exactly those otel keys (an inline table or another layout): then nothing
    is written and the caller names the manual step instead.

    ``drop_inert_table`` also drops the [otel] table itself when the keys that
    remain in it are only ``environment`` and ``log_user_prompt``: without an
    exporter they change nothing, and Setup wrote them beside the exporters.
    """
    try:
        before = codex_toml.loads(raw)
        text = raw.decode("utf-8-sig")
    except (UnicodeError, TypeError, ValueError):
        return None
    remaining = {key for key in (before.get("otel") or {}) if key not in keys}
    drop_table = drop_inert_table and remaining <= _CODEX_OTEL_INERT_KEYS
    kept: list[str] = []
    dropping = False
    for line in text.splitlines(keepends=True):
        match = _TOML_TABLE_HEADER.match(line)
        if match:
            path = _toml_header_path(match.group(1))
            dropping = (len(path) >= 2 and path[0] == "otel" and path[1] in keys) or (
                drop_table and path == ["otel"]
            )
        elif line.lstrip().startswith("[["):
            dropping = False
        if not dropping:
            kept.append(line)
    data = "".join(kept).encode("utf-8")
    try:
        after = codex_toml.loads(data)
    except (UnicodeError, TypeError, ValueError):
        return None
    expected = dict(before)
    otel = {key: value for key, value in (expected.get("otel") or {}).items() if key not in keys}
    if drop_table:
        expected.pop("otel", None)
    elif otel or "otel" in after:
        expected["otel"] = otel
    else:
        expected.pop("otel", None)
    if after != expected:
        return None
    return (codecs.BOM_UTF8 if raw.startswith(codecs.BOM_UTF8) else b"") + data


_CODEX_OTEL_INERT_KEYS = frozenset({"environment", "log_user_prompt"})
_CODEX_OTEL_EXPORTER_KEYS = ("exporter", "trace_exporter", "metrics_exporter")
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
_DEFAULT_GATEWAY_API_PORT = 18970


def _configured_gateway_ports() -> frozenset[int]:
    """The API port this account's config.yaml names (the default when it cannot be read).

    Read before uninstall removes the data folder: the credential-less Codex
    exporters Setup wrote point at this port (rel-1-0-2 GAP-0376).
    """
    try:
        data_dir = str(config_module.default_data_path())
        if config_module.config_path_for_data_dir(data_dir).is_file():
            port = int(config_module.load().gateway.api_port)
            if 0 < port < 65536:
                return frozenset({port})
    except Exception:  # noqa: BLE001 - an unreadable config falls back to the default port.
        pass
    return frozenset({_DEFAULT_GATEWAY_API_PORT})


def _configured_claim_ports() -> frozenset[int]:
    """The API and guardrail ports this account's config.yaml names (the defaults when it cannot be read).

    These are the ports a gateway stop releases; their claim files in the shared
    claim folder are this account's to drop (cowork-1-0-8 GAP-0102).
    """
    ports = set(_configured_gateway_ports())
    guardrail = _DEFAULT_GUARDRAIL_PORT
    try:
        data_dir = str(config_module.default_data_path())
        if config_module.config_path_for_data_dir(data_dir).is_file():
            guardrail = int(config_module.load().guardrail.port)
    except Exception:  # noqa: BLE001 - an unreadable config falls back to the default port.
        pass
    if 0 < guardrail < 65536:
        ports.add(guardrail)
    return frozenset(ports)


def _codex_gateway_exporters(otel, ports: frozenset[int]) -> list[tuple[str, str]]:
    """Codex [otel] exporters that only point at the DefenseClaw gateway port, as (field, target).

    Setup wrote an exporter table for the gateway it configured; once its
    credential is gone the table still sends to that port, which nothing
    serves after uninstall (rel-1-0-2 GAP-0376, LEAD 10-31). Only a table that
    holds nothing but ``endpoint`` and ``protocol``, with a loopback endpoint on
    the port, counts: one with headers, TLS settings, another host or another
    port is the user's own and stays.
    """
    if not isinstance(otel, dict) or not ports:
        return []
    found = []
    for key in _CODEX_OTEL_EXPORTER_KEYS:
        table = otel.get(key)
        if not isinstance(table, dict) or not table:
            continue
        targets = []
        for kind, exporter in table.items():
            if kind not in ("otlp-http", "otlp-grpc") or not isinstance(exporter, dict):
                targets = []
                break
            if not set(exporter) <= {"endpoint", "protocol"}:
                targets = []
                break
            endpoint = exporter.get("endpoint")
            try:
                parsed = urllib.parse.urlsplit(endpoint) if isinstance(endpoint, str) else None
                port = parsed.port if parsed is not None else None
            except ValueError:
                parsed, port = None, None
            if parsed is None or (parsed.hostname or "") not in _LOOPBACK_HOSTS or port not in ports:
                targets = []
                break
            targets.append(f"{parsed.hostname}:{port}")
        if targets:
            found.append((f"otel.{key}", targets[0]))
    return found


def _replace_agent_config(path: str, original: bytes, data: bytes) -> bool:
    """Write data over path atomically if it still holds original; False if not done.

    A link is never replaced (the write would swap the link for a file), and a
    file the agent changed since it was read is left alone.
    """
    try:
        if os.path.islink(path) or _read_agent_config(path) != original:
            return False
        mode = stat.S_IMODE(os.stat(path).st_mode)
        fd, temp = tempfile.mkstemp(prefix=".defenseclaw-otel-", dir=os.path.dirname(path) or ".")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            if os.name != "nt":
                os.chmod(temp, mode)
            os.replace(temp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temp)
            raise
    except OSError:
        return False
    return True


def _remove_marked_native_otel_left(gateway_ports: frozenset[int] = frozenset()) -> None:
    """Remove the agent OTel entries DefenseClaw wrote that the teardown left (GAP-2517).

    Teardown removes every exporter whose credential DefenseClaw can name. One
    an earlier DefenseClaw setup wrote with a bearer no install recorded (a
    pre-setup copy put back, say) stayed, and kept sending telemetry and that
    bearer to a gateway port nothing serves after uninstall. Uninstall stops
    the gateway, so it removes what DefenseClaw identifies by its own markers
    (LEAD 03:45 ruling, option 1): a Codex [otel] exporter or a Claude Code
    OTLP *_HEADERS key with x-defenseclaw-source, x-defenseclaw-client and a
    bearer, plus the paired *_ENDPOINT key at this machine. A Codex exporter
    with no credential at all that sends only to this machine's DefenseClaw
    gateway port is Setup's too (rel-1-0-2 GAP-0376). Anything else is kept.
    When the file cannot be changed safely (a link, an unusual layout, a file
    the agent holds or changed) it is left as is and uninstall names the
    manual step.
    """
    removed: list[str] = []
    left: list[tuple[str, str]] = []
    codex_config = os.path.join(codex_home(), "config.toml")
    raw = _read_agent_config(codex_config)
    try:
        document = codex_toml.loads(raw) if raw else {}
    except (UnicodeError, TypeError, ValueError):
        document = {}
    otel = document.get("otel") if isinstance(document, dict) else None
    marked = _codex_otel_marked_kept(otel, 0)
    configured = _codex_gateway_exporters(otel, gateway_ports)
    marked += [pair for pair in configured if pair[0] not in {field for field, _ in marked}]
    if marked:
        fields = ", ".join(field for field, _ in marked)
        targets = ", ".join(sorted({target for _, target in marked}))
        data = _codex_config_without_otel_keys(
            raw, {field.split(".", 1)[1] for field, _ in marked}, drop_inert_table=bool(configured)
        )
        if data is not None and _replace_agent_config(codex_config, raw, data):
            removed.append(
                f"{codex_config}: removed {fields}, the exporters DefenseClaw set up to {targets} "
                "(nothing serves that port now)"
            )
        else:
            left.append(
                (
                    f"{codex_config}: {fields} carry DefenseClaw's x-defenseclaw-source and "
                    f"x-defenseclaw-client headers and a bearer, and could not be removed safely; "
                    f"Codex still sends its telemetry and that bearer to {targets}, which DefenseClaw no longer serves",
                    f"delete the {fields} tables from {codex_config}",
                )
            )
    claude_settings = claude_settings_paths()[0]
    raw = _read_agent_config(claude_settings)
    try:
        settings = json.loads(raw.decode("utf-8-sig")) if raw else {}
    except (UnicodeError, ValueError):
        settings = {}
    env = settings.get("env") if isinstance(settings, dict) else None
    headers = _marked_claude_otel_headers(env)
    if headers:
        # Each marked *_HEADERS key pairs with its *_ENDPOINT key: removing the
        # headers alone leaves Claude Code exporting to the dead port.
        endpoints = _paired_claude_otel_endpoints(env, headers)
        targets = ", ".join(sorted({target for _, target in endpoints}))
        keys = headers + [key for key, _ in endpoints]
        sends = f" to {targets}" if targets else ""
        new_settings = dict(settings)
        new_settings["env"] = {key: value for key, value in env.items() if key not in keys}
        bom = codecs.BOM_UTF8 if raw.startswith(codecs.BOM_UTF8) else b""
        data = bom + (json.dumps(new_settings, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        if _replace_agent_config(claude_settings, raw, data):
            removed.append(
                f"{claude_settings}: removed env {', '.join(keys)}, the DefenseClaw-marked OTLP entries{sends} "
                "(nothing serves that port now)"
            )
        else:
            left.append(
                (
                    f"{claude_settings}: env {', '.join(headers)} carry DefenseClaw's x-defenseclaw-source and "
                    f"x-defenseclaw-client headers and a bearer, and could not be removed safely; "
                    f"Claude Code still sends its telemetry and that bearer{sends}",
                    f"delete {', '.join(keys)} from the env block of {claude_settings}",
                )
            )
    for line in removed:
        ux.ok(line)
    for detail, step in left:
        ux.warn(detail)
        ux.echo(f"    {step}")


def _render_kept_and_next_steps(plan: UninstallPlan) -> None:
    """Say what a partial uninstall kept and how to resume or finish it.

    The default uninstall keeps the data dir and the binaries, so the user
    needs to know that the config, the audit log and the policies are still
    there and which command turns protection back on.
    """
    if plan.remove_data_dir and plan.remove_binaries:
        return
    # --all without --binaries removed the defenseclaw launcher with the data
    # dir it runs, so nothing below may name a defenseclaw command (GAP-1923).
    launcher_gone = bool(plan.data_bound_launchers) and not plan.remove_binaries
    left = [
        target
        for target in plan.binary_targets
        if launcher_gone and target not in plan.data_bound_launchers and os.path.lexists(target)
    ]
    kept: list[str] = []
    if not plan.remove_data_dir and plan.data_dir:
        kept.append(f"{plan.data_dir}: config, audit log, policies and secrets")
    if launcher_gone and left:
        names = ", ".join(os.path.basename(target) for target in left)
        kept.append(f"{plan.install_root}: {names} (the defenseclaw command went with the data)")
    elif not plan.remove_binaries and plan.install_root and not launcher_gone:
        kept.append(f"{plan.install_root}: the DefenseClaw commands")
    if kept:
        ux.subhead("Kept:")
        for line in kept:
            ux.echo(f"  • {line}")
    if plan.remove_binaries:
        _render_next_steps_without_commands(plan)
        return
    # A Windows `make all` developer install refuses --binaries, so naming
    # that command sent the user to a refusal (GAP-1256).
    developer = (
        _windows_developer_files(plan.install_root)
        if plan.platform_name == "win32" and not plan.remove_binaries
        else []
    )
    if launcher_gone and not developer:
        _render_next_steps_after_launcher_removal(plan, left)
        return
    ux.subhead("Next steps:")
    if plan.remove_data_dir and not launcher_gone:
        ux.echo("  • set DefenseClaw up again:  defenseclaw quickstart")
    elif not plan.remove_data_dir:
        ux.echo("  • turn protection back on:   defenseclaw setup guardrail")
    if developer:
        if not plan.remove_data_dir:
            ux.echo("  • remove the data too:       defenseclaw uninstall --all")
        ux.echo("  • remove the developer files (PowerShell):")
        click.echo(f"      Remove-Item -LiteralPath {_powershell_quoted_paths(developer)}")
        return
    ux.echo("  • remove everything:         defenseclaw uninstall --all --binaries")


_INSTALL_URL = "https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download"


def _render_next_steps_after_launcher_removal(plan: UninstallPlan, left: list[str]) -> None:
    """Next steps after --all removed the launcher with the data (GAP-1923)."""
    ux.subhead("Next steps (the defenseclaw command was removed):")
    if left and plan.platform_name == "win32":
        ux.echo("  • remove the rest (PowerShell):")
        click.echo(f"      Remove-Item -LiteralPath {_powershell_quoted_paths(left)}")
    elif left:
        import shlex

        ux.echo(f"  • remove the rest:           rm -f {' '.join(shlex.quote(path) for path in left)}")
    _render_reinstall_step(plan)


def _render_next_steps_without_commands(plan: UninstallPlan) -> None:
    """Next steps after --binaries kept the data: none may run defenseclaw (GAP-1745)."""
    windows = plan.platform_name == "win32"
    ux.subhead("Next steps (the defenseclaw command was removed):")
    if plan.data_dir and windows:
        ux.echo("  • remove the kept data (PowerShell):")
        click.echo(f"      Remove-Item -Recurse -Force -LiteralPath {_powershell_quoted_paths([plan.data_dir])}")
    elif plan.data_dir:
        import shlex

        ux.echo(f"  • remove the kept data:      rm -rf {shlex.quote(plan.data_dir)}")
    _render_reinstall_step(plan)


def _render_reinstall_step(plan: UninstallPlan) -> None:
    """Say how to get DefenseClaw back once its command is gone."""
    windows = plan.platform_name == "win32"
    from defenseclaw.upgrade_shim import managed_deployment

    if managed_deployment():
        # The organization's deployment installs DefenseClaw and guards the
        # account; a per-user reinstall is not the way back.
        return
    then = "defenseclaw quickstart" if plan.remove_data_dir else "defenseclaw setup guardrail"
    ux.echo(f"  • use DefenseClaw again:     reinstall it, then run '{then}'")
    if windows:
        click.echo(f"      irm {_INSTALL_URL}/install.ps1 | iex")
    else:
        click.echo(f"      curl -LsSf {_INSTALL_URL}/install.sh | bash")


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
@click.option(
    "--stop-sandboxes",
    is_flag=True,
    help=(
        "Stop and delete running OpenShell sandboxes with the sandbox teardown (work a copy-mode sandbox "
        "never pulled back is lost). Without it a running sandbox stops the run before any change."
    ),
)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def reset_cmd(skip_sandbox_teardown: bool, yes: bool, stop_sandboxes: bool = False) -> None:
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
    plan = _with_listed_sandboxes(plan, stop_sandboxes)
    ux.banner("DefenseClaw Reset")
    _render_plan(plan, dry_run=False)
    # Read before the wipe: reset deletes the Cowork state this looks for.
    cowork_plugin = _cowork_plugin_built(plan)
    if cowork_plugin:
        ux.echo(f"  • {_COWORK_PLUGIN_STAYS}")

    _refuse_running_sandboxes(plan)
    if not yes and not click.confirm(
        f"  This will DELETE resettable state under {plan.data_dir}. Continue?",
        default=False,
    ):
        ux.subhead("Cancelled.")
        raise SystemExit(1)

    _execute_plan(plan)
    cowork_problem = _record_cowork_removal(plan.data_dir) if cowork_plugin else ""
    if cowork_plugin and not cowork_problem:
        ux.warn(f"DefenseClaw cannot remove its Cowork plugin from your Claude account: {_COWORK_REMOVAL_STEP}")
    ux.ok("Reset complete. Run 'defenseclaw quickstart' to reinstall.")
    if cowork_problem:
        _report_cowork_removal_not_recorded(cowork_problem)


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
    legacy_setup: bool = False,
) -> UninstallPlan:
    platform_name = platform_name or sys.platform
    data_dir = str(config_module.default_data_path())
    legacy = legacy_setup_install.find(platform_name) if legacy_setup else None
    install_root, binary_targets = _owned_binary_targets(platform_name)
    binary_targets += _installer_uv_targets(install_root, platform_name)
    # Reset keeps .venv, so the launchers that run it keep working and stay:
    # its closing advice is to run 'defenseclaw quickstart' (GAP-0029).
    data_bound_launchers = (
        _data_bound_launchers(binary_targets, data_dir, platform_name)
        if wipe_data and not binaries and ".venv" not in preserve_data_entries
        else ()
    )

    # Config identifies active connectors. If it is missing or unreadable,
    # only durable rollback markers may authorize connector teardown.
    cfg = None
    config_error = ""
    config_file = config_module.config_path_for_data_dir(data_dir)
    if config_file.is_file():
        try:
            cfg = config_module.load()
        except Exception as exc:  # noqa: BLE001 - any load failure is reported in the plan.
            config_error = _one_line(str(exc) or type(exc).__name__)

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
    # Setup wrote its records (connector records, ACP ownership records, the
    # OpenClaw backup index) in the data_dir config.yaml names, which can be
    # another folder than the install home (GAP-0874).
    store_dir = config_module.configured_store_dir()
    previous_stores = tuple(
        folder
        for folder in config_module.previous_store_dirs()
        if not any(config_module._same_folder(folder, current) for current in (store_dir, data_dir) if current)
    )
    record_dirs = _record_dirs(store_dir, previous_stores, data_dir)
    if configured_openclaw:
        openclaw_candidate = str(getattr(cfg.claw, "config_file", "") or "")
        openclaw_home_candidate = str(getattr(cfg.claw, "home_dir", "") or "")
        openclaw_owned = True
    else:
        default_home_candidate = os.path.expanduser("~/.openclaw")
        default_config_candidate = os.path.join(default_home_candidate, "openclaw.json")
        openclaw_candidate, openclaw_owned = next(
            (
                owned
                for owned in (_owned_openclaw_candidate(home, default_config_candidate) for home in record_dirs)
                if owned[1]
            ),
            ("", False),
        )
        openclaw_home_candidate = os.path.dirname(openclaw_candidate) if openclaw_owned else ""

    connectors = tuple(
        dict.fromkeys(
            name
            for home in record_dirs
            for name in _teardown_connectors(
                active_connectors,
                data_dir=home,
                openclaw_config_file=openclaw_candidate,
                include_openclaw=revert_openclaw,
                openclaw_owned=openclaw_owned,
            )
        )
    )
    owns_openclaw = "openclaw" in connectors
    openclaw_config_file = openclaw_candidate if owns_openclaw else ""
    openclaw_home = openclaw_home_candidate if owns_openclaw else ""

    sandbox_state = _sandbox_state_present(cfg, data_dir, platform_name)
    uv_leftovers = (
        _installer_uv_leftovers(install_root, binary_targets, data_dir, platform_name) if wipe_data and binaries else ()
    )
    return UninstallPlan(
        sandbox_teardown=sandbox_state and not skip_sandbox_teardown,
        sandbox_teardown_skipped=sandbox_state and skip_sandbox_teardown,
        stop_gateway=True,
        revert_openclaw=revert_openclaw and owns_openclaw,
        remove_plugin=remove_plugin and owns_openclaw,
        remove_data_dir=wipe_data,
        remove_binaries=binaries,
        data_dir=data_dir,
        store_dir=store_dir,
        previous_stores=previous_stores,
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
            else (path_gateway(honor_override=False) or os.path.join(install_root, "defenseclaw-gateway"))
        ),
        binary_targets=binary_targets,
        data_bound_launchers=data_bound_launchers,
        setup_leftovers=_windows_setup_leftovers(platform_name, legacy) if binaries else (),
        legacy_setup=legacy,
        observability_teardown=(
            wipe_data and not preserve_data_entries and _local_observability_stack_file(data_dir) != ""
        ),
        mac_app=_installed_mac_app(platform_name) if wipe_data and binaries else "",
        uv_leftovers=uv_leftovers,
        uv_kept=_uv_kept(install_root, binary_targets + uv_leftovers, platform_name) if wipe_data and binaries else (),
        uv_cache_entries=(
            _uv_cache_with_defenseclaw(data_dir, platform_name, uv_leftovers)
            if wipe_data and binaries and not preserve_data_entries
            else ""
        ),
        sigstore_cache=_legacy_sigstore_cache(data_dir) if wipe_data and binaries else "",
        hook_temp_dirs=_hook_temp_dirs(platform_name) if wipe_data and not preserve_data_entries else (),
        quarantined=_quarantined_copies(data_dir) if wipe_data and not preserve_data_entries else (),
        acp_entries=_acp_editor_entries(cfg, record_dirs),
        config_error=config_error,
    )


def _one_line(text: str, limit: int = 400) -> str:
    """*text* on one line, at most *limit* characters."""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def _acp_editor_entries(cfg, data_dirs: tuple[str, ...]) -> tuple[tuple[str, str, str], ...]:
    """The guarded editor entries this runtime can prove `acp setup` wrote (GAP-2632).

    The proof is the one `defenseclaw acp remove` uses, from the ownership
    record in each folder setup can have written it in (``UninstallPlan.record_dirs``),
    so a foreign or adopted entry is never named. An editor file that cannot
    be read is left as it is.
    """
    if getattr(cfg, "deployment_mode", "") == "managed_enterprise":
        return ()
    found = dict.fromkeys(entry for data_dir in data_dirs for entry in _proven_acp_entries(data_dir))
    return tuple(sorted(found))


def _proven_acp_entries(data_dir: str) -> tuple[tuple[str, str, str], ...]:
    """The editor entries the ownership record in data_dir proves `acp setup` wrote."""
    from defenseclaw.commands import cmd_acp

    records = cmd_acp._owned_entry_records(data_dir)
    entries: list[tuple[str, str, str]] = []
    for client in sorted(cmd_acp._CLIENTS):
        try:
            path = cmd_acp._client_path(client)
            servers = cmd_acp._read_json_object(path).get("agent_servers")
        except (OSError, ValueError, RuntimeError, click.ClickException):
            continue
        if not isinstance(servers, dict):
            continue
        entries.extend(
            (client, agent, str(path))
            for agent in sorted(cmd_acp._AGENTS)
            if cmd_acp._pair_entry_names(servers, client, agent, records)
        )
    return tuple(entries)


def _remove_acp_editor_entries(plan: UninstallPlan) -> None:
    """Take out the plan's ACP editor entries, their contract locks and their records."""
    # Each folder's proof is read before any entry goes: a removal changes the editor files.
    proven = {home: _proven_acp_entries(home) for home in plan.record_dirs}
    for home, entries in proven.items():
        if entries:
            _remove_acp_editor_entries_in(home, entries)


def _remove_acp_editor_entries_in(data_dir: str, entries: tuple[tuple[str, str, str], ...]) -> None:
    from defenseclaw.commands import cmd_acp

    records = cmd_acp._owned_entry_records(data_dir)
    paths = {client: cmd_acp._remove_client_entry(client, agent, records) for client, agent, _ in entries}
    # A linked acp directory holds another runtime's locks and records.
    if cmd_acp._acp_dir_is_redirected(data_dir):
        return
    pairs = {(client, agent) for client, agent, _path in entries}
    for client, agent in pairs:
        lock = cmd_acp._contract_lock_path(data_dir, client, agent)
        if lock.is_file() and not lock.is_symlink():
            lock.unlink()
    for client, path in paths.items():
        try:
            # Another entry this runtime wrote in the same file keeps a current pin.
            cmd_acp._refresh_client_contract_digests(data_dir, client, path)
        except click.ClickException as exc:
            ux.warn(f"{exc.message}; `defenseclaw acp verify` names what to repair")
    remaining = {key: digest for key, digest in records.items() if key[:2] not in pairs}
    if remaining != records:
        cmd_acp._write_entry_records(data_dir, remaining)


# The connectors whose setup leaves a scoped hook credential and a backup of the
# agent settings in the folder it ran in, and `config set data_dir` copies both
# into the new folder and leaves the originals. OpenClaw keeps its own backup
# index and pristine copies (read per folder above), and a removed connector's
# backups go with the removed-connector listing.
_MOVED_RECORD_CONNECTORS = (
    "amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "opencode",
)
# The backup records a connector writes straight under the data folder, not in
# connector_backups: Claude Code's and Codex's, which `config set data_dir`
# copies into the new folder like the rest (GAP-0942).
def _top_level_backup_records(connector: str) -> tuple[str, ...]:
    return tuple(
        marker for marker in _CONNECTOR_BACKUP_MARKERS.get(connector, ()) if os.path.basename(marker) == marker
    )


# The keys of each top-level record, from the structs that write it
# (claudeCodeBackup, codexConfigBackup and the earlier codexBackup): the keys
# every record carries, and every key a record may carry. A file at the name
# that holds any other key, or lacks a required one, belongs to the account.
_TOP_LEVEL_BACKUP_SHAPES: dict[str, tuple[dict[str, type], frozenset[str]]] = {
    "claudecode_backup.json": (
        {"had_hooks_key": bool},
        frozenset({
            "original_hooks", "had_hooks_key", "managed_hook_commands", "had_env_key", "original_env",
            "env_backup_captured", "managed_env", "managed_absent_env", "retired_otlp_credentials",
            "otlp_headers_helper_captured", "had_otlp_headers_helper", "original_otlp_headers_helper",
            "managed_otlp_headers_helper",
        }),
    ),
    "codex_config_backup.json": (
        {"had_hooks_key": bool, "added_codex_hooks_flag": bool},
        frozenset({
            "had_hooks_key", "original_hooks", "added_codex_hooks_flag", "had_otel_block", "original_otel",
            "operator_otel", "had_notify", "original_notify",
        }),
    ),
    "codex_backup.json": ({"had_base_url": bool, "old_base_url": str}, frozenset({"had_base_url", "old_base_url"})),
}


def _is_setup_top_level_backup(path: str) -> bool:
    """Whether *path* holds the record Setup writes under that file name: its required keys and no other key."""
    shape = _TOP_LEVEL_BACKUP_SHAPES.get(os.path.basename(path))
    if shape is None:
        return False
    required, allowed = shape
    try:
        with open(path, "rb") as stream:
            raw = stream.read(_BACKUP_RECORD_MAX_BYTES + 1)
        document = json.loads(raw) if len(raw) <= _BACKUP_RECORD_MAX_BYTES else None
    except (OSError, ValueError):
        return False
    return (
        isinstance(document, dict)
        and set(document) <= allowed
        and all(type(document.get(key)) is kind for key, kind in required.items())
    )


# The hook script a Unix setup generates for a connector, and the other
# per-connector record it writes beside the hooks.
_CONNECTOR_HOOK_SCRIPTS = {
    "claudecode": "claude-code-hook.sh",
    "codex": "codex-hook.sh",
    "devin": "devin-hook.sh",
    "hermes": "hermes-hook.sh",
}
_CONNECTOR_SETUP_RECORDS = {"hermes": ("hermes-home-setup.json",)}
_HOOK_SCRIPT_MARKER = b"# defenseclaw-managed-hook v"
# A backup record carries the agent file's bytes, so it can be large.
_BACKUP_RECORD_MAX_BYTES = 8 * 1024 * 1024
# What the agent-config restore keeps beside a backup record (agent_config_restore.go).
_BACKUP_COMPANION_SUFFIXES = (".last-good", ".restore-notice", ".restore-notice-seen")
# Records of the folder as a whole: its hook contract lock and the records of the
# config and install home the hooks run under. They go once no connector's
# credential, backup or script is left in the folder.
_FOLDER_RECORDS = (
    "hook_contract_lock.json",
    os.path.join("hooks", ".config-record"),
    os.path.join("hooks", ".install-home-record"),
)


def _remove_earlier_folder_connector_records(plan: UninstallPlan) -> list[str]:
    """Remove the connector records `config set data_dir` left in the folders it moved away from.

    A move copies the scoped hook credentials, the hook contract lock and the
    connector backups to the new folder and leaves the originals, and the
    install home keeps the records Setup wrote before the first move. Teardown
    reads and removes the folder config.yaml names, so those copies stayed
    after a teardown that reported itself verified: a credential in a folder no
    install uses (GAP-0915). Only what DefenseClaw wrote, by name and shape, as
    a regular file this account owns, in a real folder this account owns, for a
    connector this uninstall tore down; the folder, the config, the audit store
    and every other file stay. Returns what DefenseClaw wrote and could not
    remove, one line each, so the caller does not report a clean uninstall.
    """
    names = tuple(name for name in plan.connectors if name in _MOVED_RECORD_CONNECTORS)
    stayed: list[str] = []
    if not names:
        return stayed
    for folder in plan.record_dirs:
        if config_module._same_folder(folder, plan.records_dir):
            continue
        removed, left = _remove_connector_records_in(folder, names)
        stayed.extend(left)
        if removed:
            ux.ok(f"removed {removed} connector record(s) the earlier data folder {folder} still held")
    return stayed


def _account_owned_regular_file(path: str) -> bool:
    """Whether *path* is a regular file, not a link, that this account owns."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode) or _is_reparse_path(path):
        return False
    if os.name == "nt":
        from defenseclaw.file_permissions import windows_guard_private_file_error

        return windows_guard_private_file_error(path) is None
    return info.st_uid == os.geteuid()


def _account_owned_real_dir(path: str) -> bool:
    """Whether *path* is a folder, not a link, that this account owns."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISDIR(info.st_mode) or _is_reparse_path(path):
        return False
    return os.name == "nt" or info.st_uid == os.geteuid()


def _link_on_path(folder: str) -> str:
    """The first link on the way to *folder* (or *folder* itself), else "".

    A folder recorded earlier can sit below a parent that was a real folder
    when it was recorded and is a link now; the account that can replace the
    parent can point it anywhere. Links the system owns (a root-owned /var or
    /tmp link) are not the account's to move and are not counted.
    """
    for link, _kind in link_guard.links_on_path(folder):
        if os.name != "nt":
            try:
                if os.lstat(link).st_uid == 0:
                    continue
            except OSError:
                pass
        return link
    return ""


def _backup_record_stem(logical_name: str) -> str:
    """The file name managed_backup.go gives a backup record for a logical name."""
    stem = re.sub(r"[/\\: ]", "_", logical_name)
    return stem or "config"


# The logical names Setup gives the agent files it backs up for these connectors
# (captureManagedFileBackup in internal/gateway/connector); a record is <stem>.json.
_SETUP_BACKUP_RECORD_FILES = frozenset(
    _backup_record_stem(logical) + ".json"
    for logical in (
        "config", "config.yaml", "config.toml", "config.json", "settings", "settings.json",
        "hooks.json", "managed_config.toml", "shell-hooks-allowlist.json",
    )
)


def _setup_backup_record_stem(path: str, connector: str) -> str:
    """The stem of a backup record Setup wrote at *path* for *connector*, else "".

    Setup writes ``<stem>.json`` with the connector, a logical name that gives
    the file name, the pristine digest and the capture time; a ``.json`` file
    of any other shape or name is the account's own and is not read as ours.
    """
    name = os.path.basename(path)
    try:
        with open(path, "rb") as stream:
            raw = stream.read(_BACKUP_RECORD_MAX_BYTES + 1)
        document = json.loads(raw) if len(raw) <= _BACKUP_RECORD_MAX_BYTES else None
    except (OSError, ValueError):
        return ""
    if not isinstance(document, dict) or document.get("connector") != connector:
        return ""
    logical = document.get("logical_name")
    if (
        not isinstance(logical, str)
        or not isinstance(document.get("pristine_sha256"), str)
        or not isinstance(document.get("captured_at"), str)
        or isinstance(document.get("version"), bool)
        or not isinstance(document.get("version"), int)
    ):
        return ""
    stem = _backup_record_stem(logical)
    return stem if name == f"{stem}.json" else ""


def _remove_connector_records_in(folder: str, names: tuple[str, ...]) -> tuple[int, list[str]]:
    """Remove *names*' records from one earlier folder; return the count removed and what stayed."""
    removed = 0
    stayed: list[str] = []
    if not os.path.lexists(folder):
        return removed, stayed
    linked = _link_on_path(folder)
    if linked or not _account_owned_real_dir(folder):
        # Replaced since the plan was read, or reached through a link: nothing under it is ours to follow.
        why = f"{linked} is a link on its path" if linked else "not a folder this account owns"
        return removed, [f"{folder} ({why}, so it was not entered)"]
    hooks = os.path.join(folder, "hooks")
    backups = os.path.join(folder, "connector_backups")

    def drop(path: str) -> None:
        """Remove a file DefenseClaw wrote; say so when it cannot be removed."""
        nonlocal removed
        if not os.path.lexists(path):
            return
        if not _account_owned_regular_file(path):
            stayed.append(f"{path} (a link, or a file another account owns)")
            return
        try:
            os.unlink(path)
        except OSError as exc:
            stayed.append(f"{path} ({exc.strerror or exc})")
            return
        removed += 1

    def real_dir(path: str) -> bool:
        """Whether *path* is a real folder to enter; a folder that is there and is not one is reported once."""
        if not os.path.lexists(path):
            return False
        if _account_owned_real_dir(path) and _real_dir_chain(folder, path):
            return True
        note = f"{path} (a link, or a folder another account owns, so it was not entered)"
        if note not in stayed:
            stayed.append(note)
        return False

    for name in names:
        if real_dir(hooks):
            drop(os.path.join(hooks, f".hook-{name}.token"))
            script = _CONNECTOR_HOOK_SCRIPTS.get(name)
            if script and _is_generated_hook_script(os.path.join(hooks, script)):
                drop(os.path.join(hooks, script))
        for record in _CONNECTOR_SETUP_RECORDS.get(name, ()):
            drop(os.path.join(folder, record))
        for record in _top_level_backup_records(name):
            path = os.path.join(folder, record)
            # A file of another shape at the name is the account's own; a link there is reported by drop.
            if os.path.lexists(path) and (not _account_owned_regular_file(path) or _is_setup_top_level_backup(path)):
                drop(path)
        backup = os.path.join(backups, name)
        if real_dir(backups) and real_dir(backup):
            try:
                entries = sorted(os.listdir(backup))
            except OSError:
                entries = []
            stems = {}
            for entry in entries:
                path = os.path.join(backup, entry)
                if entry in _SETUP_BACKUP_RECORD_FILES and _is_reparse_path(path):
                    # Setup writes regular files: a link at the name of one of its records is not followed and
                    # is reported. A link under any other name belongs to the account (a link to a file of its own
                    # kept beside the records); it stays, and the folder with it, so the shared records stay too.
                    stayed.append(f"{path} (a link, so it was not followed)")
                elif entry.endswith(".json") and _account_owned_regular_file(path):
                    stem = _setup_backup_record_stem(path, name)
                    if stem:
                        stems[stem] = path
            for stem, path in stems.items():
                drop(path)
                # Beside a record Setup wrote: the last known good copy and the restore notice.
                for suffix in _BACKUP_COMPANION_SUFFIXES:
                    drop(os.path.join(backup, stem + suffix))
            with contextlib.suppress(OSError):
                os.rmdir(backup)
    if _connector_state_remains(folder):
        return removed, stayed
    for record in _FOLDER_RECORDS:
        drop(os.path.join(folder, record))
    for path in (hooks, backups):
        if real_dir(path):
            with contextlib.suppress(OSError):
                os.rmdir(path)
    return removed, stayed


def _is_generated_hook_script(path: str) -> bool:
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or _is_reparse_path(path):
            return False
        with open(path, "rb") as stream:
            return _HOOK_SCRIPT_MARKER in stream.read(512)
    except OSError:
        return False


def _connector_state_remains(folder: str) -> bool:
    """Whether the folder still holds a credential, backup or hook script of a connector.

    The hooks folder and the backups folder are looked at on their own: a
    folder with no hooks left can still hold another connector's backup.
    """
    for name in _MOVED_RECORD_CONNECTORS:
        for record in _top_level_backup_records(name):
            path = os.path.join(folder, record)
            # A file of another shape at the name belongs to the account and keeps nothing of ours in this folder.
            if os.path.lexists(path) and (not _account_owned_regular_file(path) or _is_setup_top_level_backup(path)):
                return True
    for name in ("hooks", "connector_backups"):
        if _is_reparse_path(os.path.join(folder, name)):
            return True  # not entered, so not known to be empty
        try:
            entries = os.listdir(os.path.join(folder, name))
        except FileNotFoundError:
            continue
        except OSError:
            return True  # not readable: keep the shared records
        if name == "connector_backups" and entries:
            return True
        for entry in entries:
            if (entry.startswith(".hook-") and entry.endswith(".token")) or entry.endswith("-hook.sh"):
                return True
    return False


def _quarantined_copies(data_dir: str) -> tuple[str, ...]:
    """The quarantined skill and plugin copies under data_dir/quarantine."""
    root = os.path.join(data_dir, "quarantine")
    found: list[str] = []
    for kind in ("skills", "plugins"):
        try:
            connectors = sorted(os.scandir(os.path.join(root, kind)), key=lambda entry: entry.name)
        except OSError:
            continue
        for connector in connectors:
            if not connector.is_dir(follow_symlinks=False):
                continue
            try:
                found.extend(sorted(entry.path for entry in os.scandir(connector.path)))
            except OSError:
                continue
    return tuple(found)


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
# connector is set up again, and points it at a copy of this install's hook
# (GAP-1000), so nothing else removes these folders.
_WINDOWS_SETUP_LEFTOVERS = ("HookRuntime", "InstallerState")


def _windows_setup_leftovers(
    platform_name: str, legacy: legacy_setup_install.LegacySetupInstall | None = None
) -> tuple[str, ...]:
    if platform_name != "win32":
        return ()
    local_app_data = legacy_setup_install.local_app_data()
    root = os.path.join(local_app_data, "DefenseClaw") if local_app_data else ""
    state = os.path.join(root, "HookRuntime", "hook-runtime-state.json") if root else ""
    # A DefenseClaw Setup 0.8.x install this uninstall removes takes its
    # program folder, its cache and its launcher state with it.
    removed = legacy is not None and not legacy.problem
    if (
        not root
        or (not removed and os.path.lexists(os.path.join(local_app_data, "Programs", "DefenseClaw")))
        or (not removed and os.path.lexists(os.path.join(root, "InstallerCache")))
        or (os.path.lexists(state) and not removed and not _installer_launcher_trampoline(state, root))
    ):
        # A Setup install, or its cleanup after the next sign-in, still owns them.
        return ()
    return tuple(
        path for path in (os.path.join(root, name) for name in _WINDOWS_SETUP_LEFTOVERS) if os.path.lexists(path)
    )


def _installer_launcher_trampoline(state_path: str, root: str) -> bool:
    """True for the launcher state install.ps1 publishes once it replaces
    Setup: it delegates to a copy of this install's hook under
    HookRuntime\\delegated (GAP-1000), so it goes with this install."""
    delegated = os.path.normcase(os.path.join(root, "HookRuntime", "delegated")) + os.sep
    try:
        if os.path.islink(state_path) or os.path.getsize(state_path) > 64 * 1024:
            return False
        with open(state_path, encoding="utf-8-sig") as handle:
            hook = json.load(handle).get("hook_path")
    except (OSError, ValueError, AttributeError):
        return False
    return isinstance(hook, str) and os.path.normcase(os.path.abspath(hook)).startswith(delegated)


def _remove_legacy_setup_install(install: legacy_setup_install.LegacySetupInstall) -> list[str]:
    """Remove a DefenseClaw Setup 0.8.x install; return what could not be done."""
    done, problems = legacy_setup_install.remove(install, edit_user_path=_edit_windows_user_path)
    for line in done:
        ux.ok(line)
    for line in problems:
        ux.warn(line)
    return problems


def _remove_setup_leftovers(paths: tuple[str, ...]) -> list[link_guard.Problem]:
    """Remove the folders DefenseClaw Setup left under %LOCALAPPDATA%\\DefenseClaw.

    A link at the folder above them or higher (the folder itself may be a
    link, which goes without being followed) keeps them: nothing is removed
    through a link. Returns what stays for that reason, each with its step.
    """
    kept: list[link_guard.Problem] = []
    for path in paths:
        linked = link_guard.link_problem(path, include_self=False)
        if linked:
            kept.append(link_guard.Problem(f"could not remove {path}: {linked}", linked.step))
            continue
        try:
            if _is_reparse_path(path):
                # Only the link goes: rmdir removes a Windows directory link, unlink any other.
                if sys.platform == "win32" and os.path.isdir(path):
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
        # Only a real folder: rmdir on a link would remove the link.
        if link_guard.link_problem(parent) is None:
            with contextlib.suppress(OSError):
                os.rmdir(parent)
    return kept


def _launcher_link_target(path: str) -> str:
    """Return the absolute target of a launcher link, or "" for anything else."""
    try:
        if not os.path.islink(path):
            return ""
        target = os.readlink(path)
    except OSError:
        return ""
    return os.path.normpath(os.path.join(os.path.dirname(path), target))


# Recognition limit for an older uv console-script launcher. The current
# native entry is checked against the installed gateway image instead.
_WINDOWS_CLI_LAUNCHER_MAX_BYTES = 4 * 1024 * 1024
# The Windows CLI launchers: defenseclaw.exe (what PowerShell and cmd.exe run)
# and the defenseclaw.cmd shim. Either may be the one running this CLI.
_WINDOWS_CLI_LAUNCHERS = ("defenseclaw.exe", "defenseclaw.cmd")


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
        try:
            return windows_uninstall_helper.shim_runs(path, os.path.join(venv, "Scripts", name[:-4] + ".exe"))
        except (OSError, ValueError):
            return False
    if name.lower() == "defenseclaw":
        # The current Git Bash launcher uses the native entry. Older copies
        # named the virtual environment directly and remain removable.
        native = os.path.join(os.path.dirname(path), "defenseclaw.exe")
        candidates = (native, os.path.join(venv, "Scripts", "defenseclaw.exe"))
        try:
            with open(path, "rb") as stream:
                data = stream.read(4097)
            if len(data) > 4096:
                return False
            text = data.decode("utf-8").lower()
        except (OSError, UnicodeError):
            return False
        return any(f'exec "{candidate}" "$@"'.replace("\\", "/").lower() in text for candidate in candidates)
    elif name.lower() == "defenseclaw.exe":
        # The current entry is a copy of the installed native gateway image;
        # its adjacent state binds it to this data root. Retain recognition
        # of the older uv console launcher for upgrade and rollback.
        directory = os.path.dirname(path)
        gateway = os.path.join(directory, "defenseclaw-gateway.exe")
        state_path = os.path.join(directory, "defenseclaw-hook-state.json")
        try:
            if (
                os.path.isfile(gateway)
                and not _is_reparse_path(gateway)
                and os.path.isfile(state_path)
                and not _is_reparse_path(state_path)
                and filecmp.cmp(path, gateway, shallow=False)
            ):
                with open(state_path, encoding="utf-8") as stream:
                    text = stream.read((128 << 10) + 1)
                if len(text) > 128 << 10:
                    raise ValueError("oversized native launcher state")
                state = json.loads(text)
                if (
                    isinstance(state, dict)
                    and state.get("schema_version") == 1
                    and state.get("install_kind") == "powershell-windows"
                    and state.get("install_scope") == "user"
                    and _normalized(state.get("data_root", "")) == _normalized(data_dir)
                ):
                    return True
        except (OSError, ValueError, TypeError):
            pass
        # The old launcher stores the interpreter path in UTF-8. Decode
        # before comparing so non-ASCII profile names still match.
        expected = os.path.join(venv, "Scripts", "python.exe").lower()
        try:
            with open(path, "rb") as stream:
                data = stream.read(_WINDOWS_CLI_LAUNCHER_MAX_BYTES + 1)
        except OSError:
            return False
        return (
            len(data) <= _WINDOWS_CLI_LAUNCHER_MAX_BYTES
            and expected in data.decode("utf-8", errors="replace").lower()
        )
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


def _uv_config_dir() -> str:
    """Return uv's config folder on Linux and macOS, where its installer keeps its receipt."""
    config = os.environ.get("XDG_CONFIG_HOME", "")
    return os.path.join(config if os.path.isabs(config) else os.path.expanduser("~/.config"), "uv")


def _installer_uv_leftovers(
    install_root: str, binary_targets: tuple[str, ...], data_dir: str, platform_name: str
) -> tuple[str, ...]:
    """Name uv's cache and receipt folder when the upgrade from 0.8.x recorded them.

    Only when uninstall removes the 0.8.x installer's uv (it still matches
    the record the upgrade wrote), no other uv is on PATH, and the folders
    are uv's defaults. The upgrade found only DefenseClaw's packages in the
    cache; it goes whole only if nothing in it changed since. uv's Python
    folder always stays: other tools can share it.
    """
    uv_name = _UV_NAMES.get(platform_name, _UV_NAMES_POSIX)[0]
    if not any(os.path.basename(target) == uv_name for target in binary_targets):
        return ()
    if "uv-cache" not in _legacy_leftover_claims(data_dir):
        return ()
    root = _normalized(install_root)
    for directory in os.get_exec_path():
        if directory and _normalized(directory) != root and os.path.isfile(os.path.join(directory, uv_name)):
            return ()
    leftovers: list[str] = []
    cache = _uv_default_dirs(platform_name)[0]
    custom = os.environ.get("UV_CACHE_DIR", "")
    if (
        cache
        and (not custom or _below(data_dir, custom))
        and _plain_owned_dir(cache)
        and _only_uv_cache_entries(cache)
        and _untouched_since_upgrade(cache, data_dir)
    ):
        leftovers.append(cache)
    # uv's own installer, which the 0.8.x installer ran, left its receipt.
    config = _uv_config_dir()
    receipt = os.path.join(config, "uv-receipt.json")
    try:
        names = os.listdir(config) if _plain_owned_dir(config) else []
        with open(receipt, encoding="utf-8") as stream:
            prefix = json.loads(stream.read(16_384)).get("install_prefix", "")
    except (OSError, ValueError, AttributeError):
        names, prefix = [], ""
    if names == ["uv-receipt.json"] and isinstance(prefix, str) and _normalized(prefix) == root:
        leftovers.append(config)
    return tuple(leftovers)


def _uv_kept(install_root: str, removed: tuple[str, ...], platform_name: str) -> tuple[str, ...]:
    """Name the uv files and folders that stay next to a uv in install_root (GAP-0908).

    Nothing recorded that DefenseClaw installed them, or the uv changed since,
    so they stay; the plan and the result say so instead of leaving them
    silently.
    """
    if platform_name == "win32":
        return ()
    binaries = [os.path.join(install_root, name) for name in _UV_NAMES_POSIX]
    if not any(os.path.lexists(path) for path in binaries):
        return ()
    gone = {_normalized(path) for path in removed}
    cache, python = _uv_default_dirs(platform_name)
    # uv's installer adds env and env.fish when the folder is not on PATH (a
    # shell profile line loads env), and `uv python install` links its Python
    # into the folder: they stay with the shell profile and uv's Python.
    extras = [os.path.join(install_root, name) for name in ("env", "env.fish")]
    try:
        links = sorted(entry.path for entry in os.scandir(install_root) if entry.is_symlink())
    except OSError:
        links = []
    extras += [link for link in links if python and _below(os.path.realpath(python), os.path.realpath(link))]
    return tuple(
        path
        for path in (*binaries, *extras, cache, _uv_config_dir(), python)
        if path and os.path.lexists(path) and _normalized(path) not in gone
    )


def _only_uv_cache_entries(cache: str) -> bool:
    """Report whether cache holds only what uv keeps there (_UV_CACHE_TOP_ENTRY)."""
    try:
        return all(_UV_CACHE_TOP_ENTRY.fullmatch(name) for name in os.listdir(cache))
    except OSError:
        return False


def _legacy_leftover_claims(data_dir: str) -> frozenset[str]:
    """Read the claims the upgrade from 0.8.x recorded (_LEGACY_LEFTOVERS_RECORD)."""
    record = os.path.join(data_dir, _LEGACY_LEFTOVERS_RECORD)
    try:
        info = os.lstat(record)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _LEGACY_LEFTOVERS_MAX_BYTES:
            return frozenset()
        with open(record, encoding="utf-8", errors="strict") as stream:
            lines = stream.read(_LEGACY_LEFTOVERS_MAX_BYTES).splitlines()
    except (OSError, UnicodeError):
        return frozenset()
    return frozenset(line.strip() for line in lines if line.strip() in ("uv-cache", "sigstore"))


def _untouched_since_upgrade(path: str, data_dir: str) -> bool:
    """Report whether nothing in path changed after the upgrade wrote _LEGACY_LEFTOVERS_RECORD."""
    try:
        recorded = os.lstat(os.path.join(data_dir, _LEGACY_LEFTOVERS_RECORD)).st_mtime
        if os.lstat(path).st_mtime > recorded:
            return False
        for root, dirs, files in os.walk(path):
            for name in (*dirs, *files):
                if os.lstat(os.path.join(root, name)).st_mtime > recorded:
                    return False
    except OSError:
        return False
    return True


def _legacy_sigstore_cache(data_dir: str) -> str:
    """Return ~/.sigstore when the 0.8.x installer's temporary Cosign made it, else "".

    Only when the upgrade from 0.8.x recorded it, no cosign is on PATH, and
    nothing in it is newer than that record: a Cosign that used it since
    makes it the user's.
    """
    if "sigstore" not in _legacy_leftover_claims(data_dir) or shutil.which("cosign"):
        return ""
    path = os.path.expanduser("~/.sigstore")
    if not _plain_owned_dir(path) or not _untouched_since_upgrade(path, data_dir):
        return ""
    return path


def _uv_cache_with_defenseclaw(data_dir: str, platform_name: str, uv_leftovers: tuple[str, ...]) -> str:
    """Return uv's cache folder when it holds DefenseClaw entries, else "".

    Installers before 1.0.2 had uv download DefenseClaw into uv's own cache,
    one entry per install (GAP-1411). The cache is account-wide, so only
    DefenseClaw entries go (`uv cache clean defenseclaw`), unless the plan
    removes the whole cache anyway (uv_leftovers).
    """
    cache = os.environ.get("UV_CACHE_DIR", "")
    if not os.path.isabs(cache) or _normalized(cache) == _normalized(data_dir) or _below(data_dir, cache):
        cache = _uv_default_dirs(platform_name)[0]
    if not cache or cache in uv_leftovers or not _plain_owned_dir(cache):
        return ""
    patterns = (
        "archive-v*/*/defenseclaw-*.dist-info",
        "wheels-v*/*/defenseclaw",
        "wheels-v*/*/*/defenseclaw",
        "sdists-v*/editable/*/*/defenseclaw-*.whl",
    )
    if any(glob.glob(os.path.join(glob.escape(cache), pattern)) for pattern in patterns):
        return cache
    return ""


def _uv_editable_leftovers(cache: str) -> list[str]:
    """Return the uv cache entries of DefenseClaw editable builds (GAP-1873).

    `uv cache clean defenseclaw` leaves the editable wheel a `make all` built
    (sdists-v*/editable/<source>/) and the archive it unpacked into
    (archive-v*/<id>/ with defenseclaw-<v>.dist-info and its .pth). Each
    entry goes only when it holds nothing but DefenseClaw's build.
    """
    root = glob.escape(cache)
    entries: list[str] = []
    for source in sorted(glob.glob(os.path.join(root, "sdists-v*", "editable", "*"))):
        wheels = glob.glob(os.path.join(glob.escape(source), "*", "*.whl"))
        if wheels and all(os.path.basename(wheel).startswith("defenseclaw-") for wheel in wheels):
            entries.append(source)
    for archive in sorted(glob.glob(os.path.join(root, "archive-v*", "*"))):
        infos = glob.glob(os.path.join(glob.escape(archive), "*.dist-info"))
        if infos and all(os.path.basename(info).startswith("defenseclaw-") for info in infos):
            entries.append(archive)
    return [entry for entry in entries if os.path.isdir(entry) and not _is_reparse_path(entry)]


def _clean_uv_cache_entries(plan: UninstallPlan) -> None:
    """Remove DefenseClaw's entries from uv's cache; say how when that fails."""
    cache = plan.uv_cache_entries
    command = "uv cache clean defenseclaw"
    linked = link_guard.link_problem(cache) if plan.platform_name == "win32" else None
    if linked:
        _warn_kept_behind_link(cache, linked)
        return
    uv_name = _UV_NAMES.get(plan.platform_name, _UV_NAMES_POSIX)[0]
    candidates = (os.path.join(plan.install_root, uv_name), shutil.which(uv_name) or "")
    uv = next((path for path in candidates if path and os.path.isfile(path) and os.access(path, os.X_OK)), "")
    if not uv:
        ux.warn(f"kept DefenseClaw's entries in uv's cache {cache}: no uv to remove them; run `{command}`")
        return
    env = dict(os.environ, UV_CACHE_DIR=cache)
    try:
        result = subprocess.run(
            [uv, "cache", "clean", "defenseclaw"],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        ux.warn(f"kept DefenseClaw's entries in uv's cache {cache} ({exc}); run `{command}`")
        return
    if result.returncode != 0:
        ux.warn(f"kept DefenseClaw's entries in uv's cache {cache} (uv exited {result.returncode}); run `{command}`")
        return
    # uv's clean does not reach editable builds; they go here (GAP-1873). On Windows an entry with a link
    # at it or above it (an archive-v* or editable folder that is a junction) stays: nothing goes through a link.
    behind_link: set[str] = set()
    for entry in _uv_editable_leftovers(cache):
        linked = link_guard.link_problem(entry) if plan.platform_name == "win32" else None
        if linked:
            _warn_kept_behind_link(entry, linked)
            behind_link.add(entry)
            continue
        with contextlib.suppress(OSError):
            _remove_tree_no_follow(entry)
    left = [entry for entry in _uv_editable_leftovers(cache) if entry not in behind_link]
    if left:
        ux.warn(f"kept {len(left)} DefenseClaw entr{'y' if len(left) == 1 else 'ies'} in uv's cache: {', '.join(left)}")
        return
    if behind_link:
        return
    ux.ok(f"removed DefenseClaw's entries from uv's cache {cache}")


# mktemp -d -t defenseclaw-hook.XXXXXXXX (_hardening.sh); BSD mktemp, on
# macOS, adds its own suffix to that template.
_HOOK_TEMP_DIR_RE = re.compile(r"defenseclaw-hook\.[A-Za-z0-9]{8}(\.[A-Za-z0-9]+)?")


def _hook_temp_roots() -> tuple[str, ...]:
    """Return the temp folders mktemp -t uses: $TMPDIR, else /tmp."""
    roots: list[str] = []
    for root in (os.environ.get("TMPDIR", ""), tempfile.gettempdir(), "/tmp"):
        if root and os.path.isabs(root) and all(_normalized(root) != _normalized(seen) for seen in roots):
            roots.append(root)
    return tuple(roots)


def _hook_temp_dirs(platform_name: str) -> tuple[str, ...]:
    """Name the scratch folders DefenseClaw's shell hooks left in the temp folders.

    Each hook runs with a private HOME made by mktemp and removes it when it
    exits; a hook that was killed, or one of an earlier release, left it
    behind (GAP-1411). Only this account's real folders count.
    """
    if platform_name == "win32" or not hasattr(os, "getuid"):
        return ()
    found: list[str] = []
    for root in _hook_temp_roots():
        try:
            entries = list(os.scandir(root))
        except OSError:
            continue
        for entry in entries:
            if not _HOOK_TEMP_DIR_RE.fullmatch(entry.name):
                continue
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid():
                found.append(entry.path)
    return tuple(sorted(found))


def _remove_hook_temp_dirs(paths: tuple[str, ...]) -> None:
    removed = 0
    for path in paths:
        try:
            _remove_tree_no_follow(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            ux.warn(f"could not remove {path}: {exc}")
            continue
        removed += 1
    if removed:
        ux.ok(f"removed {removed} scratch folder(s) DefenseClaw hooks left (defenseclaw-hook.*)")


def _plain_owned_dir(path: str) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISDIR(info.st_mode) or _is_reparse_path(path):
        return False
    return not hasattr(os, "getuid") or info.st_uid == os.getuid()


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
    the installer's <data_dir>/.uv (scripts/install.ps1).
    """
    candidates = []
    if plan.remove_data_dir and not plan.preserve_data_entries:
        candidates.append(os.path.join(plan.data_dir, ".uv"))
    return [path for path in candidates if os.path.isdir(path) and _below(os.path.realpath(path), base_python)]


def _remove_leftover_dirs(paths: tuple[str, ...], *, platform_name: str = sys.platform) -> None:
    """Remove the uv and Sigstore folders the plan names, then their parents left empty.

    On Windows a folder with a link at it or above it stays, named with the step.
    """
    for path in paths:
        linked = link_guard.link_problem(path) if platform_name == "win32" else None
        if linked:
            _warn_kept_behind_link(path, linked)
            continue
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


def _remove_probe_created_state(data_dir: str) -> None:
    """Remove what agent version probes created in the home folder (GAP-0901).

    Discovery runs each installed agent CLI with ``--version``, and some CLIs
    create their config and cache folders on the way. Discovery records those
    with a fingerprint (agent_discovery.PROBE_STATE_RECORD); each entry still
    exactly as the probe left it, so never used since, is removed, then the
    parent folders the probes created while they are empty.
    """
    from defenseclaw.inventory import agent_discovery

    record = os.path.join(data_dir, agent_discovery.PROBE_STATE_RECORD)
    try:
        info = os.lstat(record)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _CREATED_DIRS_RECORD_MAX_BYTES:
            return
        with open(record, encoding="utf-8") as stream:
            payload = json.load(stream)
        paths, dirs = payload.get("paths"), payload.get("dirs")
    except (OSError, ValueError, AttributeError):
        return
    home = os.path.abspath(os.path.expanduser("~"))
    removed: list[str] = []
    for path, fingerprint in sorted((paths or {}).items() if isinstance(paths, dict) else (), reverse=True):
        if not isinstance(path, str) or not os.path.isabs(path):
            continue
        try:
            path_info = os.lstat(path)
        except OSError:
            continue
        cursor_tmp = (
            os.name != "nt"
            and path == f"/var/tmp/cursor-agent-logs-{os.getuid()}"
            and stat.S_ISDIR(path_info.st_mode)
            and path_info.st_uid == os.getuid()
        )
        if not cursor_tmp and not _below(home, path):
            continue
        if not cursor_tmp and not _real_dir_chain(home, os.path.dirname(path)):
            continue
        if os.path.islink(path):
            continue
        if agent_discovery.probe_state_fingerprint(path) != fingerprint:
            continue  # used since: the agent's own state now
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)
        except OSError:
            continue
        removed.append(path)
    for path in sorted((d for d in dirs or [] if isinstance(d, str)), key=len, reverse=True):
        if os.path.isabs(path) and _below(home, path) and _real_dir_chain(home, path):
            with contextlib.suppress(OSError):
                os.rmdir(path)
    with contextlib.suppress(OSError):
        os.unlink(record)
    if removed:
        ux.ok(f"removed what agent version probes created: {', '.join(sorted(removed))}")


def _below(root: str, path: str) -> bool:
    root = _normalized(root)
    candidate = _normalized(path)
    try:
        return candidate != root and os.path.commonpath((root, candidate)) == root
    except ValueError:
        return False


def _real_dir_chain(root: str, path: str) -> bool:
    """Report whether path and each folder below root on the way to it is a real folder.

    The path is read as written, a ".." included: the system follows a link
    before it reads the ".." after it, so folding it into the component
    before it would pass a path that a link has redirected. A path that
    wanders out of root by ".." is not below it.
    """
    raw_root = os.path.normcase(str(Path(root if os.path.isabs(root) else os.path.abspath(root))))
    folded_root = _normalized(root)
    target = path if os.path.isabs(path) else os.path.abspath(path)
    parts = Path(target).parts
    dotdot = ".." in parts
    folded_target = _normalized(target)
    # A path that folds to the root is the root only when nothing in it can redirect:
    # root/link/.. leaves by the link before the .. is read, so it is walked like the rest.
    if folded_target == folded_root and not dotdot:
        return True
    if folded_target != folded_root and not _below(folded_root, target):
        return False
    current = Path(parts[0])
    inside = False
    for part in parts[1:]:
        current = current / part
        if inside:
            try:
                info = os.lstat(current)
            except OSError:
                return False
            if not stat.S_ISDIR(info.st_mode) or _is_reparse_path(str(current)):
                return False
            continue
        key = os.path.normcase(str(current))
        inside = key == raw_root or (not dotdot and key == folded_root)
    return inside


def _sha256_file(path: str) -> str:
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sandbox_tree_has_state(root: str, *, empty_files_are_state: bool = False) -> bool:
    """Find state in a tree without following links out of it."""
    pending = [root]
    while pending:
        path = pending.pop()
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            if path == root:
                return False
            return True  # an entry disappeared during the scan
        except OSError:
            return True
        if stat.S_ISDIR(info.st_mode):
            try:
                with os.scandir(path) as entries:
                    pending.extend(entry.path for entry in entries)
            except OSError:
                return True  # let teardown report inaccessible state
        elif not stat.S_ISREG(info.st_mode):
            return True  # links and special files may hold state
        elif info.st_size or empty_files_are_state:
            return True
        else:
            try:
                if not os.access(path, os.R_OK, follow_symlinks=False):
                    return True
            except (OSError, NotImplementedError):
                return True
    return False


def _sandbox_state_present(cfg, data_dir: str, platform_name: str) -> bool:
    """Report whether DefenseClaw may hold OpenShell sandbox state.

    OpenShell sandboxes run on Linux and macOS only. A fresh install may have
    an empty image-store lock even though it has never set up sandboxes.
    """
    if platform_name == "win32":
        return False
    openshell = getattr(cfg, "openshell", None) if cfg is not None else None
    if openshell is not None and (getattr(openshell, "enabled", False) or getattr(openshell, "wrappers", None)):
        return True
    sandbox_dir = os.path.join(data_dir, "sandboxes")
    try:
        mode = os.lstat(sandbox_dir).st_mode
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if stat.S_ISLNK(mode):
        return True
    if not stat.S_ISDIR(mode):
        return False
    if _sandbox_tree_has_state(sandbox_dir):
        return True

    # The old preflight ignored an empty tree and a single empty manager
    # directory. Preserve that decision even if OpenShell has separate state.
    # Other empty entries used to request teardown, so check for a related
    # OpenShell setup before treating those entries as disposable markers.
    try:
        with os.scandir(sandbox_dir) as entries:
            for entry in entries:
                if entry.name != "manager":
                    break
                with os.scandir(entry.path) as manager_entries:
                    if next(manager_entries, None) is not None:
                        break
            else:
                return False
    except OSError:
        return True

    home = os.path.expanduser("~")
    # OpenShell state and user gateway config are tie-breakers for empty
    # markers under sandboxes, not independent teardown triggers.
    state_roots = {os.path.join(home, ".local", "state", "openshell")}
    if xdg_state := os.environ.get("XDG_STATE_HOME"):
        if os.path.isabs(xdg_state):
            state_roots.add(os.path.join(xdg_state, "openshell"))
    # UserConfigDir in Go uses XDG_CONFIG_HOME, else ~/.config. Gateway
    # registration and gateway.toml/env live here; their absence matters even
    # when the DefenseClaw setup receipt has not been written. An empty
    # config directory alone is not a gateway configuration.
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config and not os.path.isabs(xdg_config):
        return True  # Go cannot resolve a relative XDG_CONFIG_HOME
    config_roots = {os.path.join(home, ".config", "openshell")}
    if xdg_config:
        config_roots.add(os.path.join(xdg_config, "openshell"))
    for path in state_roots:
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError:
            return True
        return True
    return any(_sandbox_tree_has_state(path, empty_files_are_state=True) for path in config_roots)


def _owned_binary_targets(platform_name: str) -> tuple[str, tuple[str, ...]]:
    """Freeze the exact launcher paths owned by each supported installer."""
    if platform_name == "win32":
        home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
        install_root = os.path.abspath(os.path.join(home, ".local", "bin"))
        names = (
            "defenseclaw.cmd",
            # The installer's copy of the venv's native launcher, which
            # PowerShell and cmd.exe run before defenseclaw.cmd (GAP-2237).
            "defenseclaw.exe",
            # The installer's extensionless launcher for Git Bash.
            "defenseclaw",
            "defenseclaw-gateway.exe",
            "defenseclaw-acp.exe",
            "defenseclaw-hook.exe",
            # The Claude Code PreToolUse guard of the one-line install (GAP-2467).
            "defenseclaw-hook-guard.exe",
            "skill-scanner.cmd",
            "mcp-scanner.cmd",
            # Written by install.ps1: binds defenseclaw-hook.exe to the data dir.
            "defenseclaw-hook-state.json",
        )
    else:
        install_root = os.path.abspath(os.path.expanduser("~/.local/bin"))
        names = (
            "defenseclaw-gateway",
            "defenseclaw-hook-post",
            # The native Claude Code hook launcher, installed on Linux and macOS (1.0.8, GAP-0571).
            "defenseclaw-hook-user",
            "defenseclaw-acp",
            "defenseclaw-sensor-helper",
            "defenseclaw",
            "skill-scanner",
            "skill-scanner-api",
            "skill-scanner-pre-commit",
            "mcp-scanner",
            "mcp-scanner-api",
            "litellm",
        )
    targets = tuple(os.path.join(install_root, name) for name in names)
    return install_root, targets + _retired_source_install_copies(install_root, names)


# install_publish renames a running binary aside to this name when `make all`
# replaces it; a copy still mapped then stays until a later rebuild prunes it.
# install.ps1 renames a running one aside to <name>.old-<yyyyMMddTHHmmssfff>
# when an upgrade or its restore replaces it under hook traffic (GAP-1760).
_RETIRED_COPY_RE = re.compile(
    r"\.(?P<name>.+)\.source-install-old-[0-9a-f]+|(?P<aside>.+)\.old-[0-9]{8}T[0-9]{9}", re.IGNORECASE
)


def _is_retired_source_install_copy(name: str, owned: tuple[str, ...] | set[str]) -> bool:
    match = _RETIRED_COPY_RE.fullmatch(name)
    return bool(match) and (match.group("name") or match.group("aside")).lower() in {item.lower() for item in owned}


def _retired_source_install_copies(install_root: str, names: tuple[str, ...]) -> tuple[str, ...]:
    """Name the copies of DefenseClaw's binaries a source install renamed aside (GAP-1929)."""
    try:
        entries = sorted(os.scandir(install_root), key=lambda entry: entry.name)
    except OSError:
        return ()
    return tuple(
        entry.path
        for entry in entries
        if _is_retired_source_install_copy(entry.name, names) and entry.is_file(follow_symlinks=False)
    )


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

    for name in _removed_connectors_in_active_state(data_dir):
        add(name)

    # The agent's own config is evidence too: a Codex config.toml or Claude
    # Code settings.json that still names DefenseClaw (a notify entry or
    # hooks from an install whose data folder and backups are gone) is torn
    # down even when that connector is not active, and its teardown removes
    # only the entries DefenseClaw owns (GAP-0376).
    for name, path in _agent_config_wiring_files():
        if _names_defenseclaw(path):
            add(name)

    if include_openclaw and openclaw_config_file:
        pristine = _expand(openclaw_config_file) + ".pristine"
        if os.path.isfile(pristine):
            add("openclaw")

    return tuple(out)


def _agent_config_wiring_files() -> list[tuple[str, str]]:
    """(connector, user config file) whose DefenseClaw wiring outlives its backup markers."""
    return [
        ("codex", os.path.join(codex_home(), "config.toml")),
        ("claudecode", claude_settings_paths()[0]),
    ]


def _names_defenseclaw(path: str) -> bool:
    """Whether a regular, not linked, agent config file carries DefenseClaw wiring (first 1 MiB)."""
    try:
        if not os.path.isfile(path) or os.path.islink(path) or _is_reparse_path(path):
            return False
        with open(path, "rb") as stream:
            text = stream.read(1 << 20).lower()
    except OSError:
        return False
    return any(marker in text for marker in _DEFENSECLAW_WIRING_MARKERS)


#: What DefenseClaw writes into an agent config, never a bare project path
#: that merely contains the word: its hook launcher and gateway executables
#: (a Codex notify entry names either), its data folder (hook scripts, notify
#: bridge) and its telemetry header names.
_DEFENSECLAW_WIRING_MARKERS = (
    b"defenseclaw-hook",
    b"defenseclaw-gateway",
    b".defenseclaw/",
    b".defenseclaw\\",
    b"x-defenseclaw-",
)


_DATA_REMOVED_LEFTOVER_NOTE = (
    "  DefenseClaw's data folder is removed by this uninstall, so a hook or policy listed above "
    "names a file that no longer exists, and the agent fails on it: remove it from the agent's config."
)
_LEFTOVER_HEADER = re.compile(r"^OpenHands/OmniGent support was removed in 1\.0\.5; DefenseClaw no longer guards it\.$")


def _removed_connector_leftover_lines(
    data_dir: str,
    *,
    data_removed: bool,
    found: list | None = None,
    moved: dict[str, str] | None = None,
) -> list[str]:
    """until 1.1: the lines that list what a removed connector left (none when nothing is).

    *found* is a list read earlier (removed_connectors.leftovers); *moved*
    names the backups moved out of the data folder at their new path.
    """
    if not data_dir:
        return []
    from defenseclaw.removed_connectors import leftovers

    lines: list[str] = []
    for left in leftovers(data_dir) if found is None else found:
        lines.extend(left.lines(without_under=data_dir if data_removed else "", moved=moved))
    return lines


def _print_removed_connector_leftovers(
    data_dir: str,
    *,
    data_removed: bool,
    found: list | None = None,
    moved: dict[str, str] | None = None,
) -> None:
    """until 1.1: list what the OpenHands/OmniGent teardown could not remove, with the steps.

    The teardown removes what DefenseClaw wrote for them and blocks nothing;
    this is information. Every uninstall form prints it. What a data folder removal
    takes away (*data_removed*) is not listed; the backups it keeps are, at
    the place they moved to (*moved*).
    """
    lines = _removed_connector_leftover_lines(data_dir, data_removed=data_removed, found=found, moved=moved)
    if not lines:
        return
    if data_removed:
        lines.append(_DATA_REMOVED_LEFTOVER_NOTE)
    click.echo("\n".join(lines))


def _move_removed_connector_backups_out(data_dir: str, platform_name: str = sys.platform) -> dict[str, str]:
    """until 1.1: move each removed connector's backups out of a data folder that is about to go.

    The leftover list tells the user to copy back what they need from
    ``connector_backups/<connector>``, so the data removal must not take it
    (removed_connectors.kept_backups_root). Returns old path to new path.
    A link or reparse point there is not DefenseClaw's copy, and the data
    removal unlinks it without following it. A folder that cannot be moved
    stops the uninstall before any data or binary is removed.
    """
    from defenseclaw.removed_connectors import backup_dirs, kept_backups_root

    moved: dict[str, str] = {}
    root = kept_backups_root(data_dir)
    for name, path in backup_dirs(data_dir):
        if _is_reparse_path(path) or _is_reparse_path(os.path.dirname(path)) or not os.path.isdir(path):
            continue
        # On Windows, never move into or through a link: the files stay where they are.
        linked = link_guard.link_problem(root) if platform_name == "win32" else None
        if linked:
            raise click.ClickException(
                f"could not move {path} (your files as they were before DefenseClaw's setup) out of the data "
                f"folder to {root}: {linked}. No data or binaries were removed.\n  {linked.step}"
            )
        try:
            if os.path.lexists(root) and (_is_reparse_path(root) or not os.path.isdir(root)):
                raise OSError(f"{root} is in the way and is not a folder")
            os.makedirs(root, mode=0o700, exist_ok=True)
            target = os.path.join(root, name)
            count = 2
            while os.path.lexists(target):
                target = os.path.join(root, f"{name}-{count}")
                count += 1
            try:
                os.rename(path, target)
            except OSError as exc:
                if exc.errno != errno.EXDEV:
                    raise
                # A data folder on its own filesystem (GAP-1447): the copy
                # stays, and the data removal takes the original.
                shutil.copytree(path, target, symlinks=True)
        except OSError as exc:
            raise click.ClickException(
                f"could not move {path} (your files as they were before DefenseClaw's setup) out of the data "
                f"folder to {root}: {exc}. No data or binaries were removed: move it out yourself, then run the "
                "same uninstall command again"
            ) from exc
        moved[path] = target
    return moved


def _removed_connectors_in_active_state(data_dir: str) -> tuple[str, ...]:
    """Removed connector names the gateway's active roster still lists.

    until 1.1: config loading drops OpenHands and OmniGent, so the configured
    roster no longer names them; the active roster an older gateway wrote
    (``{"names": [...]}`` or ``{"name": ...}``) is the remaining evidence that
    their agent-side state is installed. Only removed names are taken from it.
    """
    if not data_dir:
        return ()
    path = os.path.join(data_dir, _ACTIVE_CONNECTOR_STATE)
    if not os.path.isfile(path) or _is_reparse_path(path):
        return ()
    try:
        if os.path.getsize(path) > _ACTIVE_CONNECTOR_STATE_MAX_BYTES:
            return ()
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        return ()
    if not isinstance(state, dict):
        return ()
    names = state.get("names")
    if not isinstance(names, list) or not names:
        names = [state.get("name")]
    found: list[str] = []
    for name in names:
        folded = name.strip().lower() if isinstance(name, str) else ""
        if folded in _REMOVED_CONNECTOR_BACKUP_MARKERS and folded not in found:
            found.append(folded)
    return tuple(found)


_OPEN_SESSION_NOTE = (
    "an agent session that is open now goes on without DefenseClaw (its hooks fail and nothing checks "
    "its tool calls): close it first, or restart it once DefenseClaw is back"
)


def _render_plan(plan: UninstallPlan, *, dry_run: bool) -> None:
    # "Plan" (not "Uninstall plan") — the command banner above already names
    # the operation (Uninstall / Reset), so repeating it here is redundant and,
    # for reset, was an outright mismatch ("Uninstall plan" under a Reset).
    ux.banner("Plan")
    if len(plan.connectors) > 1:
        # Multi-connector installs serve N equal peers — there is no "primary",
        # so list them all without singling one out.
        ux.echo(f"  • {ux.bold('active connectors:')}   {', '.join(plan.connectors)}")
    else:
        ux.echo(f"  • {ux.bold('active connector:')}    {plan.connector or 'none'}")
    display_connectors = plan.connectors
    teardown = ", ".join(display_connectors) if display_connectors else "no"
    ux.echo(f"  • {ux.bold('connector teardown:')}  {teardown}")
    if plan.config_error:
        ux.warn(
            f"config.yaml did not load ({plan.config_error}); the teardown goes on from the connector "
            f"records in {plan.records_dir}",
            indent="    ",
        )
    if display_connectors:
        # An open Codex session ran on after the uninstall with every hook
        # failing, and its next marker command ran (GAP-0255).
        ux.echo(f"      {ux.dim('·')} {_OPEN_SESSION_NOTE}")
    if plan.acp_entries:
        ux.echo(f"  • {ux.bold('ACP editor entries:')}  removed with their contract locks")
        for client, agent, path in plan.acp_entries:
            ux.echo(f"      {ux.dim('·')} {client}/{agent} in {path}")
    if plan.platform_name == "win32" and not plan.sandbox_teardown:
        ux.echo(f"  • {ux.bold('sandbox teardown:')}    no (OpenShell sandboxes do not run on Windows)")
    elif plan.sandbox_teardown:
        ux.echo(f"  • {ux.bold('sandbox teardown:')}    yes (OpenShell itself is kept)")
        # Teardown runs with --yes: work a copy-mode sandbox holds is gone
        # with it, so say where to see it before the confirmation.
        ux.echo(
            f"      {ux.dim('·')} work a copy-mode sandbox holds that was never pulled back is deleted with it "
            "(`defenseclaw sandbox teardown --dry-run` names it)"
        )
        live = f" ({', '.join(plan.live_sandboxes)})" if plan.live_sandboxes else ""
        ux.echo(
            f"      {ux.dim('·')} a live-mounted sandbox{live} is stopped and deleted with its undo point; what its "
            "agent already wrote in your folder stays as it is (before you uninstall, `defenseclaw sandbox review "
            "NAME` shows it and `defenseclaw sandbox undo NAME` reverts it)"
        )
        if plan.running_sandboxes:
            running = ", ".join(name for name, _ in plan.running_sandboxes)
            if plan.stop_sandboxes:
                ux.echo(f"      {ux.dim('·')} running sandboxes ({running}) are stopped and deleted (--stop-sandboxes)")
            else:
                ux.echo(
                    f"      {ux.dim('·')} running sandboxes ({running}) stop this run before any change: stop them "
                    "first, or add --stop-sandboxes"
                )
        elif plan.sandbox_list_error:
            unread = f"the sandbox list could not be read ({plan.sandbox_list_error})"
            if plan.stop_sandboxes:
                ux.echo(f"      {ux.dim('·')} {unread}: any running sandbox is stopped and deleted (--stop-sandboxes)")
            elif plan.sandboxes_off:
                ux.echo(
                    f"      {ux.dim('·')} {unread}: this run stops before any change; while sandboxes are off, "
                    f"{_OFF_SANDBOXES_CHECK}; or add --stop-sandboxes or --skip-sandbox-teardown"
                )
            else:
                ux.echo(
                    f"      {ux.dim('·')} {unread}: this run stops before any change; check with "
                    "`defenseclaw sandbox list`, or add --stop-sandboxes"
                )
    elif plan.sandbox_teardown_skipped:
        ux.echo(f"  • {ux.bold('sandbox teardown:')}    skipped (--skip-sandbox-teardown)")
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
        ux.echo(
            f"      {ux.dim('·')} DefenseClaw's OpenShell sandboxes, images, gateway change and shell wrappers "
            f"stay; {later}"
        )
    else:
        ux.echo(f"  • {ux.bold('sandbox teardown:')}    no (no OpenShell sandbox state)")
    feed = _sandbox_kernel_feed_hint(plan)
    if feed:
        ux.echo(f"  • {ux.bold('sandbox kernel feed:')} stays (a root service); {feed}")
    ux.echo(f"  • {ux.bold('stop sidecar:')}        {'yes' if plan.stop_gateway else 'no'}")
    if "openclaw" in display_connectors:
        ux.echo(
            f"  • {ux.bold('revert openclaw.json:')} {'yes' if plan.revert_openclaw else 'no'} "
            f"({plan.openclaw_config_file})"
        )
        ux.echo(f"  • {ux.bold('remove plugin:')}        {'yes' if plan.remove_plugin else 'no'}")
    ux.echo(f"  • {ux.bold('wipe ' + plan.data_dir + ':')} {'yes' if plan.remove_data_dir else 'no'}")
    if plan.store_dir:
        ux.echo(
            f"  • {ux.bold('data_dir in config.yaml:')} {plan.store_dir}: the connector hooks and records are "
            "read there; this uninstall does not remove that folder"
        )
    for folder in plan.previous_stores:
        ux.echo(
            f"  • {ux.bold('earlier data_dir:')} {folder}: the setup records left there are read and removed; "
            "this uninstall does not remove that folder"
        )
    if plan.store_dir and plan.connectors and not plan.remove_data_dir:
        ux.echo(
            f"  • {ux.bold('install home records:')} {plan.data_dir}: the hook credential, hook contract lock and "
            "connector backups copied from there to the data_dir are removed; the config and the rest stay"
        )
    if plan.remove_data_dir and plan.data_dir:
        from defenseclaw.removed_connectors import backup_dirs, kept_backups_root

        for _name, path in backup_dirs(plan.data_dir):
            ux.echo(
                f"      {ux.dim('·')} kept: {path} (your files as they were before DefenseClaw's setup) "
                f"moves to {kept_backups_root(plan.data_dir)}"
            )
    if plan.quarantined:
        # GAP-0422: often the only copy of a skill or plugin; say so before it goes.
        ux.echo(
            f"      {ux.dim('·')} {len(plan.quarantined)} quarantined skill/plugin copies in "
            f"{os.path.join(plan.data_dir, 'quarantine')}, which exist nowhere else. To keep one, restore it "
            "first: defenseclaw skill restore NAME (or defenseclaw plugin restore NAME)"
        )
    if plan.hook_temp_dirs:
        roots = sorted({os.path.dirname(path) for path in plan.hook_temp_dirs})
        ux.echo(
            f"      {ux.dim('·')} {len(plan.hook_temp_dirs)} scratch folder(s) DefenseClaw hooks left "
            f"(defenseclaw-hook.*) in {', '.join(roots)}"
        )
    if plan.uv_cache_entries:
        ux.echo(
            f"      {ux.dim('·')} DefenseClaw's entries in uv's cache {plan.uv_cache_entries} "
            "(uv cache clean defenseclaw)"
        )
    if plan.preserve_data_entries:
        ux.echo(f"  • {ux.bold('preserve runtime:')}      {', '.join(plan.preserve_data_entries)}")
    ux.echo(f"  • {ux.bold('remove binaries:')}     {'yes' if plan.remove_binaries else 'no'}")
    if plan.remove_binaries:
        # Only the launchers that are there: the owned-name list also names
        # optional ones (scanner APIs, litellm) that most installs never had.
        for target in plan.binary_targets:
            if os.path.lexists(target):
                ux.echo(f"      {ux.dim('·')} {target}")
        for path in plan.setup_leftovers:
            linked = link_guard.link_problem(path, include_self=False)
            note = f"stays: {linked}" if linked else "left by DefenseClaw Setup"
            ux.echo(f"      {ux.dim('·')} {path} ({note})")
        for path in plan.uv_leftovers:
            ux.echo(f"      {ux.dim('·')} {path} (left by the 0.8.x installer's uv)")
        if plan.sigstore_cache:
            ux.echo(f"      {ux.dim('·')} {plan.sigstore_cache} (left by the 0.8.x installer's Cosign)")
        if plan.uv_kept:
            ux.echo(f"      {ux.dim('·')} kept: {_uv_kept_note(plan.uv_kept)}")
        if plan.platform_name == "win32":
            ux.echo(
                f"      {ux.dim('·')} the {plan.install_root} entry in your user Path, "
                "once nothing else is left in that folder"
            )
    elif plan.remove_data_dir:
        # The launchers into the data dir stop working with it, so they go
        # too; the rest keep working and stay until --binaries.
        for target in plan.data_bound_launchers:
            ux.echo(f"      {ux.dim('·')} {target} (runs {plan.data_dir}, so it goes with it)")
        kept = [
            target
            for target in plan.binary_targets
            if os.path.lexists(target)
            and target not in plan.data_bound_launchers
            and os.path.basename(target) != _UV_RECORD
        ]
        developer = _windows_developer_files(plan.install_root) if plan.platform_name == "win32" else []
        if developer:
            ux.echo(f"      {ux.dim('·')} kept: {_windows_developer_removal(developer)}")
        elif kept:
            ux.echo(
                f"      {ux.dim('·')} kept: {', '.join(os.path.basename(target) for target in kept)} "
                f"in {plan.install_root} (add --binaries to remove them too)"
            )
    if plan.legacy_setup is not None:
        first, *rest = legacy_setup_install.plan_lines(plan.legacy_setup, plan.data_dir)
        ux.echo(f"  • {ux.bold('DefenseClaw Setup:')}   {first}")
        for line in rest:
            ux.echo(f"      {ux.dim('·')} {line}")
    if plan.observability_teardown:
        ux.echo(
            f"  • {ux.bold('local observability:')} its containers and data volumes go (docker compose down --volumes)"
        )
    if _requires_deferred_cleanup(plan):
        ux.echo(f"  • {ux.bold('deferred cleanup:')}   after this managed CLI exits")
    if plan.mac_app:
        # Not removed here: the app owns its login item and background
        # service, which it unregisters itself.
        ux.echo(
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
            # The raised error below carries the full reason (and any recovery
            # recipe); repeating it in the ledger printed long guidance twice.
            phases.append(ExecutionPhaseResult(name, "failed", "see the error below"))
            _render_execution_result(ExecutionResult(tuple(phases)))
            if isinstance(exc, click.ClickException):
                raise
            raise click.ClickException(f"{name} failed: {exc}") from exc
        phases.append(ExecutionPhaseResult(name, "succeeded"))

    run_phase("plan validation", lambda: _validate_plan(plan))
    if plan.sandbox_teardown:
        # Before the sidecar stops: the daemon deletes its own sandboxes.
        run_phase("sandbox teardown", lambda: _sandbox_teardown(plan))
    # Read before the data goes: the ports of the gateway this run stops.
    claim_ports = _configured_claim_ports() if plan.stop_gateway else frozenset()
    gateway_stopped: list[bool] = []
    if plan.stop_gateway:
        run_phase("gateway stop", lambda: gateway_stopped.append(bool(_stop_gateway(plan))))
    if plan.connectors:
        run_phase("connector teardown", lambda: _connector_teardown(plan))
        if not plan.remove_data_dir:
            _turn_guardrail_off(plan.data_dir)
    if plan.acp_entries:
        # Before data removal: the records that prove the entries are there.
        run_phase("ACP editor entries", lambda: _remove_acp_editor_entries(plan))
    if plan.connectors and len(plan.record_dirs) > 1:
        # After the teardown: no agent registration names these copies any more.
        earlier_stayed = _remove_earlier_folder_connector_records(plan)
        if earlier_stayed:
            phases.append(
                ExecutionPhaseResult(
                    _EARLIER_FOLDER_RECORDS_PHASE,
                    "failed",
                    "; ".join(earlier_stayed),
                    ("remove what is named above (it can hold a hook credential), then run the command again",),
                )
            )
    # until 1.1: read what a removed connector left before its backups move:
    # their records name the agent configs outside the data folder.
    from defenseclaw.removed_connectors import backup_dirs, leftovers

    removed_left = {home: leftovers(home) for home in plan.record_dirs}
    moved: dict[str, str] = {}
    if plan.remove_data_dir and plan.data_dir and backup_dirs(plan.data_dir):
        run_phase(
            "removed connector backups",
            lambda: moved.update(_move_removed_connector_backups_out(plan.data_dir, plan.platform_name)),
        )
    # A data_dir moved out of the install home stays: the wipe takes the install home only.
    for home, found in removed_left.items():
        _print_removed_connector_leftovers(
            home, data_removed=plan.remove_data_dir and home == plan.data_dir, found=found, moved=moved
        )
    if plan.stop_gateway:
        for home in plan.record_dirs:
            _remove_probe_created_state(home)
            # The gateway is stopped, so its watcher no longer uses them.
            _remove_created_dirs(home)
    if "copilot" in plan.connectors or plan.remove_data_dir:
        _remove_orphan_copilot_plugin(plan.platform_name)
    if plan.remove_data_dir and plan.data_dir:
        # Before the data dir (and the registry naming them) goes.
        _remove_mcp_writer_backups(plan.data_dir, plan.platform_name)
        _remove_unregistered_mcp_writer_backups(plan.platform_name)
        _remove_legacy_codex_candidate()
    if plan.remove_plugin and "openclaw" in plan.connectors:
        # Plugin removal is OpenClaw-specific. For other connectors the
        # gateway sentinel teardown above already removed their hook
        # scripts and config patches. This helper is idempotent and
        # reports "already removed" when the teardown already removed it.
        run_phase("plugin removal", lambda: _remove_plugin(plan))
    setup_leftovers = plan.setup_leftovers
    if plan.legacy_setup is not None:
        # After connector teardown; before the leftovers and the data, which
        # the old gateway may hold open when both use one data folder.
        problems = _remove_legacy_setup_install(plan.legacy_setup)
        steps = tuple(dict.fromkeys(step for step in (getattr(item, "step", "") for item in problems) if step))
        phases.append(
            ExecutionPhaseResult(
                _LEGACY_SETUP_PHASE, "failed" if problems else "succeeded", "; ".join(problems), steps
            )
        )
        # What is left on disk now decides, not the plan.
        setup_leftovers = _windows_setup_leftovers(plan.platform_name) if plan.remove_binaries else ()
    if setup_leftovers:
        # After connector teardown, so no agent hook still runs the launcher.
        stayed: list[link_guard.Problem] = []
        run_phase(_SETUP_LEFTOVERS_PHASE, lambda: stayed.extend(_remove_setup_leftovers(setup_leftovers) or ()))
        if stayed:
            steps = tuple(dict.fromkeys(item.step for item in stayed if item.step))
            phases[-1] = ExecutionPhaseResult(_SETUP_LEFTOVERS_PHASE, "failed", "; ".join(stayed), steps)
    if plan.hook_temp_dirs:
        # After connector teardown: no hook runs in them any more.
        _remove_hook_temp_dirs(plan.hook_temp_dirs)
    if plan.uv_cache_entries:
        # Before binary removal: the installer's uv may be the one that runs.
        _clean_uv_cache_entries(plan)
    if plan.observability_teardown:
        # Before data removal: Compose needs the stack's files in data_dir.
        # A stack Docker cannot reach stays, with the command that removes it.
        _local_observability_teardown(plan.data_dir)
    deferred = _requires_deferred_cleanup(plan)
    held: list[str] = []
    denied: list[str] = []
    if deferred:
        status: list[str] = []

        def schedule() -> None:
            held.extend(_deferred_cleanup_held_folders(plan))
            denied.extend(_deferred_cleanup_denied_entries(plan))
            status.append(_schedule_deferred_cleanup(plan))

        run_phase("deferred cleanup", schedule)
        # The result file stays for the operator to read; the next
        # uninstall's helper removes it. It said nothing about the data
        # folder still being there, so a failed cleanup looked like a
        # finished uninstall (cowork-1-0-8 GAP-0058).
        if denied:
            # Known before the CLI exits: say it will fail, not that it may
            # (cowork-1-0-8 GAP-0063).
            detail = (
                f"will not finish: this account cannot remove {_denied_note(denied)}, so {plan.data_dir} "
                f"stays; the result is written to {status[0]}, kept for you to read"
            )
        else:
            detail = (
                f"not finished yet: {plan.data_dir} is removed within about a minute after this command "
                f"exits; the result is written to {status[0]}, kept for you to read. If a program still "
                "holds a file or folder in it, the removal fails and DefenseClaw stays; the next "
                "defenseclaw command then says why"
            )
        phases[-1] = ExecutionPhaseResult("deferred cleanup", "scheduled", detail)
    elif plan.remove_data_dir:
        run_phase(
            "data removal",
            lambda: _remove_data_dir(
                plan.data_dir,
                preserve_entries=plan.preserve_data_entries,
                platform_name=plan.platform_name,
            ),
        )
        if plan.data_bound_launchers and not plan.remove_binaries:
            run_phase("launcher removal", lambda: _remove_data_bound_launchers(plan))
    if plan.remove_data_dir and not plan.preserve_data_entries:
        _remove_empty_plugin_cache()
    if gateway_stopped and gateway_stopped[0]:
        # The gateway start leaves this account's port claims where every
        # account's init reads them (%ProgramData% on Windows, /var/tmp). With
        # the gateway stopped its claims are stale, and the next gateway start
        # claims its ports again (cowork-1-0-8 GAP-0102). Only the ports this
        # stop released, and only after it worked.
        remove_own_api_port_claims(claim_ports)
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
        _remove_leftover_dirs(
            tuple(path for path in plan.uv_leftovers if not _holds_running_python(path)),
            platform_name=plan.platform_name,
        )
    if plan.sigstore_cache:
        _remove_leftover_dirs((plan.sigstore_cache,), platform_name=plan.platform_name)

    result = ExecutionResult(tuple(phases))
    _render_execution_result(result)
    for folder in held:
        ux.warn(
            f"{folder} is open in another program (a terminal or File Explorer window whose current folder "
            "is inside it, or an agent session still running): close it now, or the cleanup cannot remove "
            f"{plan.data_dir}"
        )
    if denied:
        ux.warn(
            f"this account cannot remove {_denied_note(denied)}: Windows denies it access (probably created "
            "by an earlier elevated run, such as a hook an elevated Claude Desktop ran), so the cleanup "
            f"cannot remove {plan.data_dir}. An elevated "
            "defenseclaw uninstall removes it: open a prompt with Run as administrator and run "
            "this uninstall command again"
        )
    if plan.uv_kept:
        ux.warn(f"kept {_uv_kept_note(plan.uv_kept)}")
    return result


def _denied_note(denied: list[str]) -> str:
    shown = ", ".join(denied[:_DENIED_SHOWN])
    more = len(denied) - _DENIED_SHOWN
    return f"{shown} and {more} more" if more > 0 else shown


def _uv_kept_note(kept: tuple[str, ...]) -> str:
    return (
        f"{', '.join(kept)}: not recorded as installed by DefenseClaw; "
        "remove them yourself if DefenseClaw added them"
    )


def _turn_guardrail_off(data_dir: str) -> None:
    """Record in the kept config that the connectors are torn down (GAP-1312).

    The default uninstall keeps ~/.defenseclaw. With guardrail.enabled still
    true, status listed every torn-down connector as active, and the next
    gateway start set their hooks up again. Off is what
    ``setup guardrail --disable`` writes; ``setup guardrail`` turns it back on
    with the kept connectors and modes.
    """
    if not data_dir or not config_module.config_path_for_data_dir(data_dir).is_file():
        return
    try:
        cfg = config_module.load(data_dir=data_dir)
        if not cfg.guardrail.enabled:
            return
        cfg.guardrail.enabled = False
        cfg.save()
    except Exception as exc:  # noqa: BLE001 - the hooks are already gone
        ux.warn(
            f"could not turn the guardrail off in the kept config ({exc}); "
            "run: defenseclaw setup guardrail --disable"
        )
        return
    ux.ok("guardrail turned off in the kept config (guardrail.enabled = false)")


def _remove_data_bound_launchers(plan: UninstallPlan) -> None:
    """Remove the launchers into the removed data dir (see _data_bound_launchers).

    Each one is checked again first: still an owned launcher name in the
    install root that runs the data dir's virtual environment.
    """
    if plan.platform_name == "win32":
        _validate_windows_ancestor_chain(plan.install_root, "binary install root")
    owned = set(plan.binary_targets)
    failures: list[str] = []
    for path in plan.data_bound_launchers:
        if path not in owned or not _is_data_bound_launcher(path, plan.data_dir, plan.platform_name):
            continue
        if plan.platform_name == "win32":
            # Again just before each unlink: a link made since the first look stops the rest.
            try:
                _validate_windows_ancestor_chain(plan.install_root, "binary install root")
            except click.ClickException as exc:
                failures.append(f"{path}: {exc.message}")
                break
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


def _orphan_copilot_handler_owned(handler: object) -> bool:
    """Recognize the published managed Local hook commands, including 1.0.0 Windows."""
    if not isinstance(handler, dict) or handler.get("type") != "command":
        return False
    if handler.keys() - {"type", "command", "timeout", "timeoutSec"}:
        return False
    command = handler.get("command")
    if not isinstance(command, str) or len(command) > 65536:
        return False
    windows = re.fullmatch(
        r"(?i)[A-Z]:\\Windows\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe "
        r"-NoLogo -NoProfile -NonInteractive -EncodedCommand ([A-Za-z0-9+/=]+)",
        command,
    )
    if windows:
        try:
            script = base64.b64decode(windows.group(1), validate=True).decode("utf-16le")
        except (ValueError, UnicodeError):
            return False
        bound = re.search(
            r"& ('(?:[^']|'')+defenseclaw-hook\.exe') 'hook' '--connector' 'copilot' "
            r"'--event' '([A-Za-z]+)' '--enterprise-managed' '--hook-surface' 'vscode-local' "
            r"\| Microsoft\.PowerShell\.Core\\Out-Host",
            script,
            re.IGNORECASE,
        )
        if not bound:
            return False
        binary, event = bound.groups()
        args = (
            f"'hook' '--connector' 'copilot' '--event' '{event}' "
            "'--enterprise-managed' '--hook-surface' 'vscode-local'"
        )
        argv = f"hook --connector copilot --event {event} --enterprise-managed --hook-surface vscode-local"
        statements = [
            "$ErrorActionPreference='Stop'",
            "$env:NoDefaultCurrentDirectoryInExePath='1'",
        ]

        def run(constrained_fail_closed: str) -> list[str]:
            return [
                "if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { "
                f"$ErrorActionPreference='Continue'; & {binary} {args} | Microsoft.PowerShell.Core\\Out-Host; "
                f"{constrained_fail_closed}exit $LASTEXITCODE }}",
                f"$hookStart=[System.Diagnostics.ProcessStartInfo]::new({binary},'{argv}')",
                "$hookStart.UseShellExecute=$false",
                "$hookStart.RedirectStandardError=$true",
                "$hookProcess=[System.Diagnostics.Process]::Start($hookStart)",
                "$hookProcess.StandardError.BaseStream.CopyTo([Console]::OpenStandardError())",
                "$hookProcess.WaitForExit()",
                "exit $hookProcess.ExitCode",
            ]

        if script == "; ".join([*statements, *run("")]):
            return True  # 1.0.0 render, before the removed-deployment guard
        gateway = powershell_literal(
            ntpath.join(ntpath.dirname(powershell_literal_value(binary[1:-1])), "defenseclaw-gateway.exe")
        )

        def guard(gateway: str) -> str:
            return (
                "if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { "
                f"if (-not (Microsoft.PowerShell.Management\\Test-Path -LiteralPath {binary}) -and "
                f"-not (Microsoft.PowerShell.Management\\Test-Path -LiteralPath {gateway})) {{ exit 0 }} }} "
                f"elseif (-not [System.IO.File]::Exists({binary}) -and "
                f"-not [System.IO.File]::Exists({gateway})) {{ exit 0 }}"
            )

        # The guarded render through 1.0.6, and the current one, whose
        # Constrained Language branch exits 1 when the launcher never started;
        # builds before 1.0.9 doubled only the apostrophe of the gateway path
        # (g072 review 3 M3), as they did the launcher's in binary.
        return script in {
            "; ".join([*statements, guard(literal), *run(fail_closed)])
            for literal in (gateway, powershell_literal_before_typographic_quotes(gateway))
            for fail_closed in ("", "if ($null -eq $LASTEXITCODE) { exit 1 }; ")
        }

    prefix, sep, tail = command.partition(" hook --connector copilot --enterprise-managed --event '")
    if not sep:
        return False
    event = re.fullmatch(r"([A-Za-z]+)' --hook-surface vscode-local", tail)
    binary = re.search(r"'([^']*/defenseclaw-hook)'$", prefix)
    if not event or not binary:
        return False
    quoted = "'" + binary.group(1) + "'"
    render = quoted + sep + tail
    if command == render:
        return True  # 1.0.0 render
    marker = "'" + posixpath.join(posixpath.dirname(binary.group(1)), "defenseclaw-gateway") + "'"
    return command == f"[ -e {quoted} ] || [ -e {marker} ] || exit 0; exec {render}"


def _remove_mcp_writer_backups(data_dir: str, platform_name: str = sys.platform) -> None:
    """Remove the agent-config backups the MCP writer left next to each config (GAP-1699).

    ``defenseclaw mcp set`` copies each agent config it edits to a
    ``.defenseclaw-<name>.bak`` sibling and records it in
    ``<data_dir>/connector_backups/mcp/registry.json``. Removing the data dir
    drops that registry, so the full copies would stay behind with nothing
    pointing at them. Only a regular file at exactly the name the writer
    gives that recorded config is removed.
    """
    from defenseclaw.connector_paths import _managed_mcp_backup_path

    registry = os.path.join(data_dir, "connector_backups", "mcp", "registry.json")
    try:
        with open(registry, encoding="utf-8") as handle:
            entries = json.load(handle)
    except (OSError, ValueError):
        return
    if not isinstance(entries, dict):
        return
    for entry in entries.values():
        if not isinstance(entry, dict):
            continue
        target, backup = entry.get("path"), entry.get("backup")
        if not isinstance(target, str) or not isinstance(backup, str):
            continue
        expected = os.path.abspath(_managed_mcp_backup_path(target))
        if os.path.normcase(os.path.abspath(backup)) != os.path.normcase(expected):
            continue
        linked = link_guard.link_problem(expected, include_self=False) if platform_name == "win32" else None
        if linked:
            _warn_kept_behind_link(expected, linked)
            continue
        try:
            if not stat.S_ISREG(os.lstat(expected).st_mode):
                continue
            os.unlink(expected)
        except FileNotFoundError:
            continue
        except OSError as exc:
            ux.warn(f"could not remove the MCP config backup {expected}: {exc}")
            continue
        ux.ok(f"removed {expected}")


def _remove_unregistered_mcp_writer_backups(platform_name: str = sys.platform) -> None:
    """Remove the MCP writer's backups the registry no longer names (GAP-1636).

    An install upgraded from an earlier release can keep a
    ``.defenseclaw-<name>.bak`` copy beside an agent config whose registry
    entry it never had or already dropped, so ``uninstall --all`` left
    ``~/.codex/.defenseclaw-config.toml.bak`` with DefenseClaw's hook entries.
    The name is the writer's own marker: only a regular file at exactly the
    name the writer gives one of the user-scope configs DefenseClaw edits is
    removed.
    """
    from defenseclaw.connector_paths import KNOWN_CONNECTORS, _managed_mcp_backup_path, mcp_source_locations

    seen: set[str] = set()
    for connector in KNOWN_CONNECTORS:
        try:
            locations = mcp_source_locations(connector)
        except Exception:  # noqa: BLE001 - a connector whose paths do not resolve has no backup to find
            continue
        for location in locations:
            if not os.path.isabs(location):
                continue
            backup = os.path.abspath(_managed_mcp_backup_path(location))
            if backup in seen:
                continue
            seen.add(backup)
            linked = link_guard.link_problem(backup, include_self=False) if platform_name == "win32" else None
            if linked:
                if os.path.lexists(backup):
                    _warn_kept_behind_link(backup, linked)
                continue
            try:
                if not stat.S_ISREG(os.lstat(backup).st_mode):
                    continue
                os.unlink(backup)
            except FileNotFoundError:
                continue
            except OSError as exc:
                ux.warn(f"could not remove the MCP config backup {backup}: {exc}")
                continue
            ux.ok(f"removed {backup}")


def _remove_legacy_codex_candidate() -> None:
    """Remove empty 0.8.x guardrail staging files left beside Codex config."""
    home = os.path.abspath(os.path.expanduser("~"))
    codex_dir = os.path.join(home, ".codex")
    if not _real_dir_chain(home, codex_dir):
        return
    try:
        with os.scandir(codex_dir) as entries:
            for entry in entries:
                if not re.fullmatch(
                    r"\.\.defenseclaw-config\.toml\.bak\.observability-v8-candidate-[0-9a-f]{32}\.tmp",
                    entry.name,
                ):
                    continue
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISREG(info.st_mode) and info.st_size == 0:
                    os.unlink(entry.path)
                    ux.ok(f"removed {entry.path}")
    except FileNotFoundError:
        return
    except OSError as exc:
        ux.warn(f"could not remove legacy Codex staging file in {codex_dir}: {exc}")


def _remove_orphan_copilot_plugin(platform_name: str = sys.platform) -> None:
    """Remove DefenseClaw's managed Copilot plugin once nothing manages it.

    A managed deployment renders this plugin into each account and its own
    uninstall removes it. On a host with no managed deployment a leftover
    copy may name a hook binary that is gone. Remove only the commands
    rendered by DefenseClaw and keep any independent plugin handlers.
    """
    from defenseclaw import upgrade_shim

    if upgrade_shim.managed_deployment():
        return
    plugin = os.path.join(os.path.expanduser("~"), ".copilot", "installed-plugins", "defenseclaw", "defenseclaw")
    hooks_dir = os.path.join(plugin, "hooks")
    manifest = os.path.join(plugin, "plugin.json")
    hooks_file = os.path.join(hooks_dir, "hooks.json")
    try:
        linked = link_guard.link_problem(plugin) if platform_name == "win32" else None
        if linked:
            if os.path.lexists(plugin):
                _warn_kept_behind_link(plugin, linked)
            return
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
            document = json.load(handle)
        if not isinstance(document, dict):
            return
        events = document.get("hooks")
        if not isinstance(events, dict) or not all(isinstance(group, list) for group in events.values()):
            return
        changed = False
        for event, group in list(events.items()):
            remaining = [handler for handler in group if not _orphan_copilot_handler_owned(handler)]
            if len(remaining) == len(group):
                continue
            changed = True
            if remaining:
                events[event] = remaining
            else:
                del events[event]
        if not changed:
            return
        if events or document.keys() - {"hooks", "version"}:
            temp_path = ""
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", dir=hooks_dir, prefix=".hooks-", delete=False
                ) as temp:
                    temp_path = temp.name
                    json.dump(document, temp, indent=2)
                    temp.write("\n")
                    temp.flush()
                    os.fsync(temp.fileno())
                os.replace(temp_path, hooks_file)
            finally:
                if temp_path:
                    with contextlib.suppress(OSError):
                        os.unlink(temp_path)
            ux.ok(f"removed DefenseClaw handlers from orphaned Copilot plugin {plugin}")
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
    """Refuse a Windows *path* with a link at it or at any folder above it, naming the link and the safe step."""
    # A relative path (the OpenClaw config and home come from the user config) is looked at as the
    # absolute path it names, as before.
    problem = link_guard.link_problem(os.path.abspath(path))
    if problem:
        raise click.ClickException(f"refusing {label}: {problem}\n  {problem.step}")


def _warn_kept_behind_link(path: str, problem: link_guard.Problem) -> None:
    """Say that *path* stays because of a link, with the step for that link."""
    ux.warn(f"kept {path}: {problem}\n  {problem.step}")


# What `make all` (Makefile _source-dev-install) publishes into the Windows
# install root: regular-file copies plus the source ownership marker.
_WINDOWS_DEVELOPER_FILES = (
    "defenseclaw.exe",
    "defenseclaw-gateway.exe",
    "defenseclaw-acp.exe",
    "defenseclaw-hook.exe",
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


def _powershell_quoted_paths(files: list[str]) -> str:
    return ", ".join(powershell_literal(path) for path in files)


def _windows_developer_removal(files: list[str]) -> str:
    quoted = _powershell_quoted_paths(files)
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
        # The deferred helper repeats this check with the same reader.
        runs_cli = windows_uninstall_helper.shim_runs(
            shim, os.path.join(plan.managed_venv, "Scripts", "defenseclaw.exe")
        )
    except OSError as exc:
        raise click.ClickException(f"could not verify Windows CLI shim ownership: {exc}") from exc
    except ValueError:
        raise click.ClickException("refusing oversized Windows CLI shim") from None
    if not runs_cli:
        raise click.ClickException("refusing Windows binary removal: CLI shim targets an unrelated runtime")


def _is_empty_dir(path: str) -> bool:
    try:
        with os.scandir(path) as entries:
            return next(entries, None) is None
    except OSError:
        return False


def _open_tui_refusal(plan: UninstallPlan) -> str:
    """Why a data removal cannot run now because a TUI is open ('' when it can)."""
    if not (plan.remove_data_dir and plan.data_dir and tui_lock_held(plan.data_dir)):
        return ""
    if plan.preserve_data_entries:
        command = "defenseclaw reset"
    elif plan.remove_binaries:
        command = "defenseclaw uninstall --all --binaries"
    else:
        command = "defenseclaw uninstall --all"
    # The TUI cannot run this itself, so name the terminal command (GAP-2585).
    return (
        "the DefenseClaw TUI (defenseclaw tui) is open for this account and keeps "
        f"writing to {plan.data_dir}. Quit every open TUI (Ctrl+C), then run "
        f"`{command}` in a terminal."
    )


def _validate_plan(plan: UninstallPlan) -> None:
    """Validate every destructive root and exact artifact before mutation."""
    _refuse_running_sandboxes(plan)
    if plan.remove_data_dir:
        refusal = _open_tui_refusal(plan)
        if refusal:
            # An open TUI keeps writing audit.db and its state files, so the
            # data removal failed half-done with "Directory not empty" (GAP-2576).
            raise click.ClickException(refusal)
        if plan.platform_name == "win32":
            _validate_windows_ancestor_chain(plan.data_dir, "data path")
        resolved_data = _validate_owned_root(plan.data_dir, "data path")
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
        # An empty folder holds nothing to remove; it is what the data phase
        # leaves when the data dir is a mount point (GAP-1980).
        if (
            os.path.isdir(plan.data_dir)
            and not _is_empty_dir(plan.data_dir)
            and not any(
                os.path.exists(os.path.join(plan.data_dir, marker))
                and not _is_reparse_path(os.path.join(plan.data_dir, marker))
                for marker in ownership_markers
            )
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
        if path and plan.platform_name == "win32":
            _validate_windows_ancestor_chain(_expand(path), label)
        if path and os.path.lexists(_expand(path)) and _is_reparse_path(_expand(path)):
            raise click.ClickException(f"refusing symlink or reparse-point {label}: {path}")

    if plan.remove_binaries:
        if plan.platform_name == "win32":
            _validate_windows_ancestor_chain(plan.install_root, "binary install root")
        install_root = _validate_owned_root(
            plan.install_root,
            "binary install root",
            reject_reparse=plan.platform_name == "win32",
        )
        allowed_names = (
            {
                "defenseclaw.cmd",
                "defenseclaw.exe",
                "defenseclaw",
                "defenseclaw-gateway.exe",
                "defenseclaw-acp.exe",
                "defenseclaw-hook.exe",
                "defenseclaw-hook-guard.exe",
                "skill-scanner.cmd",
                "mcp-scanner.cmd",
                "defenseclaw-hook-state.json",
                _UV_RECORD,
                *_UV_NAMES["win32"],
            }
            if plan.platform_name == "win32"
            else {
                "defenseclaw-gateway",
                "defenseclaw-hook-post",
                "defenseclaw-hook-user",
                "defenseclaw-acp",
                "defenseclaw-sensor-helper",
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
            name = os.path.basename(target).lower()
            if _normalized(os.path.dirname(target)) != install_root or (
                name not in allowed_names and not _is_retired_source_install_copy(name, allowed_names)
            ):
                raise click.ClickException(f"refusing unowned binary target: {target}")
            if plan.platform_name == "win32" and os.path.lexists(target) and _is_reparse_path(target):
                raise click.ClickException(f"refusing symlink or reparse-point binary target: {target}")
        if plan.platform_name == "win32":
            _validate_windows_binary_ownership(plan)

    if plan.gateway_path:
        if plan.platform_name == "win32":
            _validate_windows_ancestor_chain(plan.install_root, "binary install root")
            install_root = _validate_owned_root(plan.install_root, "binary install root")
            if (
                _normalized(os.path.dirname(plan.gateway_path)) != install_root
                or os.path.basename(plan.gateway_path).lower() != "defenseclaw-gateway.exe"
            ):
                raise click.ClickException(f"refusing unowned gateway target: {plan.gateway_path}")
        elif not os.path.isabs(plan.gateway_path) or os.path.basename(plan.gateway_path) != "defenseclaw-gateway":
            raise click.ClickException(f"refusing invalid gateway target: {plan.gateway_path}")


def _requires_deferred_cleanup(plan: UninstallPlan) -> bool:
    if not plan.remove_data_dir or ".venv" in plan.preserve_data_entries:
        return False
    return _running_from_managed_venv(plan)


def _running_from_managed_venv(plan: UninstallPlan) -> bool:
    """Whether this Windows CLI runs from the plan's managed runtime (so its shim may be running)."""
    if plan.platform_name != "win32" or not plan.managed_venv:
        return False
    executable = _normalized(sys.executable)
    runtime = _normalized(plan.managed_venv)
    try:
        return os.path.commonpath((runtime, executable)) == runtime
    except ValueError:
        return False


def _helper_failure_detail(*result_paths: str) -> str:
    """Return ": <reason> (details: <file>)" from the first failed helper result, else "".

    The helper runs with no console and its stdout and stderr are discarded,
    so a failed run explains itself only in its result file (GAP-0751).
    """
    for path in result_paths:
        try:
            with open(path, encoding="utf-8") as stream:
                result = json.load(stream)
        except (OSError, ValueError):
            continue
        if isinstance(result, dict) and result.get("status") == "failed" and result.get("detail"):
            return f": {result['detail']} (details: {path})"
    return ""


# How often and how long the CLI re-checks a held folder before it warns:
# a scanner's or indexer's brief hold lets go within it.
_HELD_FOLDER_CHECKS = 5
_HELD_FOLDER_CHECK_INTERVAL = 0.5


def _deferred_cleanup_skip(plan: UninstallPlan) -> set[str]:
    """What the deferred-cleanup checks leave out: the runtimes the helper removes after this CLI, and kept entries."""
    skip = {plan.managed_venv, os.path.join(plan.data_dir, ".uv")}
    skip.update(os.path.join(plan.data_dir, name) for name in plan.preserve_data_entries)
    return skip


def _deferred_cleanup_held_folders(plan: UninstallPlan) -> list[str]:
    """The data folders another program holds, which the deferred cleanup cannot remove (GAP-0058).

    The cleanup runs after this CLI exits, with no console, so a folder it
    could not remove (on the test computer hooks\\.outage-warnings; which
    program, if any, held it was not identified) left the whole data folder
    behind while the console said nothing. The check changes nothing; the
    runtime this CLI runs from and the Python the helper runs on are not
    checked (they go after it exits). A brief hold is re-checked before it is
    reported. The check is advisory: if it fails, it reports nothing and the
    cleanup is still scheduled.
    """
    skip = _deferred_cleanup_skip(plan)
    try:
        held = windows_uninstall_helper.held_folders(plan.data_dir, skip)
        for _ in range(_HELD_FOLDER_CHECKS - 1):
            if not held:
                break
            time.sleep(_HELD_FOLDER_CHECK_INTERVAL)
            still = set(windows_uninstall_helper.held_folders(plan.data_dir, skip))
            held = [folder for folder in held if folder in still]
    except Exception:  # noqa: BLE001 - an advisory check must never stop the cleanup.
        return []
    return held


# How many of the entries this account cannot remove the console names.
_DENIED_SHOWN = 3


def _deferred_cleanup_denied_entries(plan: UninstallPlan) -> list[str]:
    """The data entries this account cannot remove, which stop the deferred cleanup (GAP-0063).

    A file or folder an elevated run created as the Administrators group
    (hooks\\.outage-warnings, written by a hook that an elevated Claude
    Desktop ran) cannot be removed from a token without elevation; the
    cleanup, which runs after this CLI exits, failed on it and the data
    folder stayed. An elevated token removes it, so it reports nothing.
    Skips what _deferred_cleanup_held_folders skips. Advisory, as that one:
    an error reports nothing and the cleanup is still scheduled.
    """
    skip = _deferred_cleanup_skip(plan)
    try:
        return windows_uninstall_helper.denied_entries(plan.data_dir, skip)
    except Exception:  # noqa: BLE001 - an advisory check must never stop the cleanup.
        return []


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
                raise click.ClickException(
                    f"deferred cleanup helper exited before ready (exit {process.returncode})"
                    + _helper_failure_detail(status_path, f"{manifest_path}.failed.json")
                )
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


def _stop_gateway(plan: UninstallPlan | None = None) -> bool:
    """Stop the sidecar: True when `stop` worked, False when there was nothing to stop."""
    gw = plan.gateway_path if plan is not None else path_gateway(honor_override=False)
    if gw is None:
        ux.subhead("sidecar not on PATH — nothing to stop")
        return False
    waiters: list[_WindowsProcessWaiter] = []
    try:
        if plan is not None and not os.path.isfile(gw):
            ux.subhead("owned sidecar is not installed — nothing to stop")
            return False
        if plan is not None and plan.platform_name == "win32":
            waiters = _capture_managed_processes(plan)
        watchdog = subprocess.run(
            [gw, "watchdog", "stop"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=_GATEWAY_STOP_TIMEOUT_SECONDS,
        )
        if watchdog.returncode != 0:
            detail = (watchdog.stderr or watchdog.stdout or "unknown error").strip()
            raise click.ClickException(f"could not stop watchdog: {detail}")
        proc = subprocess.run(
            [gw, "stop"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=_GATEWAY_STOP_TIMEOUT_SECONDS,
        )
        if proc.returncode != 0 and _managed_host_has_no_own_gateway(plan):
            # On a managed host `stop` refuses whenever this account's own
            # gateway is not running (and it cannot run there), so there is
            # nothing of this install to stop; the teardown continues.
            ux.subhead("no per-user sidecar runs for this account on this managed host — nothing to stop")
            return False
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "unknown error").strip()
            raise click.ClickException(f"could not stop sidecar: {detail}")
        _wait_managed_processes(waiters)
        _close_process_waiters(waiters)
        waiters = []
        ux.ok("sidecar stopped")
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise click.ClickException(f"could not stop sidecar: {exc}") from exc
    finally:
        _close_process_waiters(waiters)


# The sandbox kernel feed (``sudo defenseclaw-gateway sandbox kernel-feed
# install``) is a root service with its own root-owned copy of the helper. A
# per-user uninstall cannot remove it, so the plan says how.
_SANDBOX_FEED_UNIT = "/etc/systemd/system/defenseclaw-sandbox-feed.service"
_SANDBOX_FEED_HELPER = "/usr/local/libexec/defenseclaw/defenseclaw-sensor-helper"


def _sandbox_kernel_feed_hint(plan: UninstallPlan, unit: str = _SANDBOX_FEED_UNIT) -> str:
    """How to remove the sandbox kernel feed, or "" when it is not installed.

    While the gateway stays, its ``sandbox kernel-feed uninstall`` does it;
    the feed's own copy of the helper can remove it at any time, also after
    this uninstall removed the gateway.
    """
    if not sys.platform.startswith("linux") or not os.path.isfile(unit):
        return ""
    if plan.gateway_path and not plan.remove_binaries:
        return f"remove it with `sudo {plan.gateway_path} sandbox kernel-feed uninstall`"
    return f"remove it with `sudo {_SANDBOX_FEED_HELPER} --sandbox-feed --uninstall`"


# How long ``sandbox list`` may take before the run treats it as unanswered.
_SANDBOX_LIST_TIMEOUT_SECONDS = 10


def _listed_sandboxes(gateway_path: str) -> tuple[list, str, bool]:
    """The sandbox rows ``sandbox list`` prints, why it could not say ('' when it did), and whether sandboxes are off.

    No gateway binary, or a gateway that reports sandboxes unsupported here,
    answers with no rows: no sandbox can run, and the teardown deletes none.
    A failed, timed-out or unreadable list is an unknown answer (GAP-0448).
    """
    if not gateway_path or not os.path.isfile(gateway_path):
        return [], "", False
    try:
        proc = subprocess.run(
            [gateway_path, "sandbox", "list", "--output", "json"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=_SANDBOX_LIST_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return [], f"`sandbox list` did not answer within {_SANDBOX_LIST_TIMEOUT_SECONDS} seconds", False
    except OSError as exc:
        return [], f"`sandbox list` could not run: {exc.strerror or exc}", False
    if proc.returncode == _SANDBOX_UNSUPPORTED_EXIT:
        return [], "", False
    off = proc.returncode != 0 and _sandboxes_off(proc.stdout)
    if off and _off_teardown_finds_no_running_sandbox(gateway_path):
        # Sandboxes are off and the teardown, which asks OpenShell itself
        # while they are off, finds no sandbox that runs: none, or only
        # stopped ones, as with sandboxes on (GAP-0765, GAP-1810). One that
        # may run, or sandboxes it could not list (GAP-1782), keep the
        # unknown answer below.
        return [], "", False
    if proc.returncode != 0:
        lines = [
            line.strip().removeprefix("✗").strip().removeprefix("Error:").strip()
            for line in (proc.stderr or "").splitlines()
            if line.strip()
        ]
        reason = lines[-1][:300] if lines else f"it exited with status {proc.returncode}"
        return [], f"`sandbox list` failed: {reason}", off
    try:
        rows = json.loads(proc.stdout or "").get("sandboxes")
    except (ValueError, AttributeError):
        rows = None
    if not isinstance(rows, list):
        return [], "`sandbox list` printed no sandbox list", False
    return [row for row in rows if isinstance(row, dict) and row.get("name")], "", False


def _sandboxes_off(stdout: str) -> bool:
    """Whether ``sandbox list --output json`` said sandboxes are off.

    While they are off the gateway answers ``{"enabled": false,
    "available": false, "reason": ...}`` and exits 1 (GAP-1817).
    """
    try:
        answer = json.loads(stdout or "")
    except ValueError:
        return False
    return isinstance(answer, dict) and answer.get("enabled") is False and answer.get("available") is False


# The dry run's "sandboxes" row ("sandboxes         none", "unknown (...)",
# or the names, a stopped one as "NAME (stopped)"), and its line when it has
# nothing to tear down at all.
_TEARDOWN_SANDBOXES = re.compile(r"^\s*sandboxes\s+(\S.*?)\s*$", re.MULTILINE)
_TEARDOWN_STOPPED_SANDBOX = re.compile(r"^[a-z0-9][a-z0-9-]* \((?:stopped|completed|deleted|missing)\)$")
_TEARDOWN_NOTHING = "nothing to tear down"


def _off_teardown_finds_no_running_sandbox(gateway_path: str) -> bool:
    """Whether ``sandbox teardown --dry-run`` names no sandbox that may run.

    With sandboxes off no daemon lists the sandboxes, and the teardown asks
    OpenShell's gateway directly for those of this data directory: a dry run
    that names none, or only stopped ones, is the answer the list could not
    give. A dry run that fails, could not list them ("unknown") or names one
    that may run keeps the list unknown.
    """
    if not _gateway_supports_sandbox_teardown(gateway_path):
        return False
    try:
        proc = subprocess.run(
            [gateway_path, "sandbox", "teardown", "--dry-run"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=_SANDBOX_LIST_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    out = proc.stdout or ""
    if proc.returncode != 0:
        return False
    if _TEARDOWN_NOTHING in out:
        return True
    row = _TEARDOWN_SANDBOXES.search(out)
    if not row:
        return False
    if row.group(1) == "none":
        return True
    return all(_TEARDOWN_STOPPED_SANDBOX.match(entry) for entry in row.group(1).split(", "))


def _live_mounted_sandboxes(rows: list) -> tuple[str, ...]:
    """The live-mounted sandboxes in *rows* (GAP-0295)."""
    return tuple(
        sorted(str(row["name"]) for row in rows if row.get("workdir_mode") == "mount" and row.get("phase") != "deleted")
    )


# The phases (lowercased by the daemon) of a sandbox whose workload no longer
# runs: stopped, completed (its workload ended), deleted (gone, its snapshot
# kept) and missing (OpenShell no longer has it). Every other phase may run:
# creating, provisioning, starting, ready, stopping, deleting, unknown, and
# error, which may still run its containers (manager.foreignOne) (GAP-0449).
_STOPPED_SANDBOX_PHASES = frozenset({"stopped", "completed", "deleted", "missing"})


def _running_sandboxes(rows: list) -> tuple[tuple[str, str], ...]:
    """The sandboxes in *rows* that may run, as (name, workdir mode) (GAP-0368)."""
    return tuple(
        sorted(
            (str(row["name"]), str(row.get("workdir_mode") or ""))
            for row in rows
            if str(row.get("phase") or "").strip().lower() not in _STOPPED_SANDBOX_PHASES
        )
    )


def _with_listed_sandboxes(plan: UninstallPlan, stop_sandboxes: bool) -> UninstallPlan:
    """*plan* with the sandboxes its teardown would stop, from one ``sandbox list``."""
    if not plan.sandbox_teardown:
        return plan
    rows, error, off = _listed_sandboxes(plan.gateway_path)
    if error and not _gateway_supports_sandbox_teardown(plan.gateway_path):
        # A gateway without ``sandbox teardown`` deletes no sandbox
        # (_sandbox_teardown), so there is nothing to protect.
        error = ""
    return replace(
        plan,
        live_sandboxes=_live_mounted_sandboxes(rows),
        running_sandboxes=_running_sandboxes(rows),
        stop_sandboxes=stop_sandboxes,
        sandbox_list_error=error,
        sandboxes_off=bool(error) and off,
    )


# How to see the sandboxes while they are off: `sandbox list` asks the
# sandbox daemon, which has them off; the teardown asks OpenShell itself.
_OFF_SANDBOXES_CHECK = (
    "`defenseclaw sandbox list` cannot list them: `defenseclaw-gateway sandbox teardown --dry-run` names them "
    "once the OpenShell gateway answers (when it does not, start it"
    + (" with `systemctl --user start openshell-gateway`" if sys.platform.startswith("linux") else "")
    + ")"
)


def _running_sandboxes_refusal(plan: UninstallPlan) -> str:
    """Why running sandboxes stop this run before any change ('' when they do not).

    The teardown stops and deletes every sandbox, with the work a copy-mode
    one holds that was never pulled back. A conversion to a managed install
    ran into the sandboxes users still worked in (GAP-0368), so a running
    sandbox needs the user to stop it, or --stop-sandboxes.
    """
    if not plan.sandbox_teardown or plan.stop_sandboxes:
        return ""
    if plan.sandbox_list_error and plan.sandboxes_off:
        # With sandboxes off `sandbox list` fails whatever runs, so it is no
        # way to check (GAP-0037): the off-state teardown's dry run names the
        # sandboxes once the OpenShell gateway answers.
        return (
            f"the sandbox list could not be read ({plan.sandbox_list_error}), so this run cannot tell whether "
            "OpenShell sandboxes still run for this account; a running sandbox may hold work never pulled back, "
            "and the sandbox teardown would stop and delete it; nothing was changed. While sandboxes are off, "
            f"{_OFF_SANDBOXES_CHECK}. Then run this command again, add --stop-sandboxes to stop and delete any "
            "running sandbox with the teardown, or add --skip-sandbox-teardown to uninstall without the sandbox "
            "teardown."
        )
    if plan.sandbox_list_error:
        # A destructive step does not go ahead on an unknown answer (GAP-0448).
        return (
            f"the sandbox list could not be read ({plan.sandbox_list_error}), so this run cannot tell whether "
            "OpenShell sandboxes still run for this account; a running sandbox may hold work never pulled back, "
            "and the sandbox teardown would stop and delete it; nothing was changed. Run `defenseclaw sandbox list` "
            "to check (for copy-mode work, use `defenseclaw sandbox pull NAME --apply`, `--branch`, or "
            "`--patch-out FILE` and confirm the project, branch or patch file contains it; "
            "`defenseclaw sandbox stop NAME` stops one), then run this command again, or add --stop-sandboxes to "
            "stop and delete any running sandbox with the teardown."
        )
    if not plan.running_sandboxes:
        return ""
    import shlex

    steps = []
    for name, mode in plan.running_sandboxes:
        quoted = shlex.quote(name)
        stop = f"`defenseclaw sandbox stop {quoted}`"
        if mode == "copy":
            steps.append(
                f"use `defenseclaw sandbox pull {quoted} --apply` to save its work in the project "
                f"(or `--branch` for a Git branch or `--patch-out FILE` for a patch); "
                f"confirm the project, branch or patch file contains it, then {stop}"
            )
        elif mode == "mount":
            steps.append(f"`defenseclaw sandbox review {quoted}` shows what it changed in your folder, then {stop}")
        else:
            steps.append(stop)
    count = len(plan.running_sandboxes)
    names = ", ".join(name for name, _ in plan.running_sandboxes)
    return (
        f"{count} OpenShell {'sandbox runs' if count == 1 else 'sandboxes run'} for this account ({names}), and the "
        "sandbox teardown would stop and delete "
        f"{'it' if count == 1 else 'them'} with any work never pulled back; nothing was changed. "
        + "; ".join(steps)
        + ". Then run this command again, or add --stop-sandboxes to stop and delete "
        f"{'it' if count == 1 else 'them'} with the teardown."
    )


def _refuse_running_sandboxes(plan: UninstallPlan) -> None:
    refusal = _running_sandboxes_refusal(plan)
    if refusal:
        raise click.ClickException(refusal)


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
    # Its output comes at the end, and deleting a sandbox can take minutes.
    ux.subhead("tearing down DefenseClaw's OpenShell sandboxes (deleting a sandbox can take a few minutes)")
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
    # GAP-1073: with the data directory removed, --skip-sandbox-teardown also
    # deletes the receipt a later teardown restores the OpenShell gateway
    # configuration from, so the way on keeps the data instead.
    later = (
        "rerun uninstall with --skip-sandbox-teardown and without --all or --binaries (that keeps the data "
        "directory, with the receipt teardown restores the OpenShell gateway configuration from, and the gateway), "
        "then run `defenseclaw-gateway sandbox teardown` once Docker and OpenShell work, and uninstall again"
        if plan.remove_data_dir or plan.remove_binaries
        else "rerun uninstall with --skip-sandbox-teardown"
    )
    for line in (proc.stdout or "").splitlines():
        if line.strip():
            # The gateway hint is for its teardown command, not uninstall.
            hint = line.replace("rerun with --keep-images", later)
            ux.echo(f"  {ux.dim('·')} {hint.strip()}")
    detail = (proc.stderr or "").strip().splitlines()
    # GAP-0282: teardown goes on past a failed step, so the last line is the
    # last step that worked. The failures are the lines it marks with a cross.
    failed = [
        line.strip().removeprefix("✗").strip()
        for line in ((proc.stdout or "") + "\n" + (proc.stderr or "")).splitlines()
        if line.strip().startswith("✗")
    ]
    undone = sum(1 for line in (proc.stdout or "").splitlines() if line.strip().startswith("✓"))
    if proc.returncode == _SANDBOX_UNSUPPORTED_EXIT:
        reason = failed[-1] if failed else (detail[-1] if detail else "OpenShell sandboxes are not supported here")
        ux.subhead(f"sandbox teardown skipped: {reason}")
        return
    if proc.returncode != 0:
        reason = "; ".join(failed) or (detail[-1] if detail else f"gateway exited with status {proc.returncode}")
        raise click.ClickException(
            "aborting uninstall: sandbox teardown failed"
            + (f" ({reason})" if reason else "")
            + (f"; {undone} step(s) listed above already ran and stay done" if undone else "")
            + "; fix it and rerun, run `defenseclaw-gateway sandbox teardown` yourself first, or "
            + (
                later
                if plan.remove_data_dir or plan.remove_binaries
                else "rerun with --skip-sandbox-teardown to leave the sandboxes for a later teardown"
            )
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
    gw = gateway_path or path_gateway(honor_override=False)
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
            errors: list[str] = []
            teardown_ok = (
                _run_gateway_connector_teardown(name, plan=plan, errors=errors)
                if plan.gateway_path
                else _run_gateway_connector_teardown(name, errors=errors)
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
                reason = f" ({errors[-1]})" if errors else ""
                raise click.ClickException(
                    f"aborting uninstall: {name} teardown failed{reason}, so "
                    "DefenseClaw will not remove data or binaries that may be "
                    "needed to restore the agent configuration. No data or binaries "
                    "were removed; fix the error and run the same uninstall command again"
                )

        if name in _PYTHON_FALLBACK_CONNECTORS:
            _revert_openclaw_python(plan)
            continue

        raise click.ClickException(
            f"aborting uninstall: no Python fallback for connector '{name}'. "
            "Upgrade defenseclaw-gateway to v0.7+ (introduces 'connector teardown') "
            "and re-run 'defenseclaw uninstall'."
        )


# A connector teardown or verify runs the gateway's full config load, which
# on a busy Windows host with remote observability destinations took 108 s;
# the old fixed 60 s aborted every uninstall run there (GAP-1663).
_CONNECTOR_COMMAND_TIMEOUT_S = 300

# ``defenseclaw-gateway connector verify`` exits 2 for a connector name its
# registry cannot resolve (a config error), distinct from 1 for residue.
_GATEWAY_UNKNOWN_CONNECTOR_EXIT = 2


def _gateway_connector_is_unknown(connector: str, *, plan: UninstallPlan | None = None) -> bool:
    """Report whether the gateway registry does not know *connector* at all.

    Only an explicit "unknown connector" verdict returns True; a missing
    gateway, a launch failure, or residue all return False so the caller keeps
    its fail-closed abort.
    """
    gw = plan.gateway_path if plan is not None and plan.gateway_path else path_gateway(honor_override=False)
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
                *(["--data-dir", plan.records_dir] if plan is not None else []),
            ],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=_CONNECTOR_COMMAND_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == _GATEWAY_UNKNOWN_CONNECTOR_EXIT and "unknown connector" in (proc.stderr or "")


def _run_gateway_connector_teardown(
    connector: str,
    *,
    plan: UninstallPlan | None = None,
    errors: list[str] | None = None,
) -> bool:
    """Invoke ``defenseclaw-gateway connector teardown --connector <name>``.

    Returns True on success (rc == 0), False on any error. stdout/stderr
    is forwarded to the operator so they can see exactly what each
    adapter restored. On failure the one-line reason is appended to
    *errors*, so the final abort message can name it.
    """

    def failed(detail: str) -> bool:
        if errors is not None and detail.strip():
            errors.append(detail.strip())
        return False

    def last_line(*texts: str | None) -> str:
        for text in texts:
            lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
            if lines:
                return lines[-1]
        return ""

    gw = plan.gateway_path if plan is not None else path_gateway(honor_override=False)
    if gw is None:
        return False
    ux.subhead(f"tearing down {connector} (on a busy host this can take a few minutes)...")
    try:
        proc = subprocess.run(
            [
                gw,
                "connector",
                "teardown",
                "--connector",
                connector,
                *(["--data-dir", plan.records_dir] if plan is not None else []),
            ],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=_CONNECTOR_COMMAND_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        ux.warn(f"gateway connector teardown failed to launch: {exc}")
        return failed(f"teardown did not run: {exc}")
    if proc.stdout:
        in_leftovers = False
        for line in proc.stdout.splitlines():
            plain = _ANSI_ESCAPE.sub("", line).rstrip()
            # The gateway's own "✓ <connector> teardown complete" line would
            # double the verified line printed below.
            if plain.strip().endswith(f"{connector} teardown complete"):
                continue
            # until 1.1: a removed connector's leftovers. The uninstall lists
            # them once every teardown ran, without what its data removal
            # takes and with the backups where it moves them
            # (_print_removed_connector_leftovers).
            if _LEFTOVER_HEADER.match(plain) or (in_leftovers and plain.startswith("  - ")):
                in_leftovers = True
                continue
            in_leftovers = False
            ux.echo(f"  {ux.dim('·')} {line.strip()}")
    if proc.stderr:
        for line in proc.stderr.splitlines():
            ux.echo(f"  {ux._style('⚠', fg='yellow', bold=True)} {line}")
    if proc.returncode == 0:
        verify_args = [
            gw,
            "connector",
            "verify",
            "--connector",
            connector,
            *(["--data-dir", plan.records_dir] if plan is not None else []),
        ]
        try:
            verified = subprocess.run(
                verify_args,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=_CONNECTOR_COMMAND_TIMEOUT_S,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            ux.warn(f"gateway connector verification failed to launch: {exc}")
            return failed(f"verification did not run: {exc}")
        if verified.returncode != 0:
            detail = (verified.stderr or verified.stdout or "residual connector state").strip()
            ux.warn(f"{connector} teardown verification failed: {detail}")
            return failed(last_line(detail))
        ux.ok(f"{connector} teardown complete (verified)")
        return True
    return failed(last_line(proc.stderr, proc.stdout))


def _revert_openclaw_python(plan: UninstallPlan) -> None:
    """OpenClaw-specific revert path used as a fallback when the gateway
    sentinel is unavailable. NOT safe for other connectors."""
    from defenseclaw.guardrail import (
        pristine_backup_path,
        restore_openclaw_config,
    )

    pristine = next(
        filter(None, (pristine_backup_path(plan.openclaw_config_file, home) for home in plan.record_dirs)), None
    )
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
        # defenseclaw reset keeps the plugin folder (remove_plugin=False): leave the
        # entry disabled so OpenClaw cannot load it again (GAP-0598).
        ok = restore_openclaw_config(
            plan.openclaw_config_file,
            original_model="",
            keep_disabled_if_plugin_present=not plan.remove_plugin,
        )
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
        # This step runs right after the openclaw connector teardown, which
        # normally removes the plugin itself; "not installed" read as if it
        # never had been (GAP-2497).
        ux.ok("DefenseClaw OpenClaw plugin already removed (nothing left to remove)")
    else:
        raise click.ClickException("plugin uninstall failed (check permissions)")


def _is_reparse_path(path: str | os.PathLike[str]) -> bool:
    """Return whether *path* is a symlink or Windows reparse point."""
    return link_guard.is_reparse(path)


def _rmtree_gone_ok(path: str) -> None:
    """rmtree that counts a file or folder another remover took first as removed.

    Two uninstalls of one account at once (two terminals) walk the same
    trees: each failed with ENOENT on what the other had just deleted and
    left data behind for a second run (GAP-2355).
    """

    def gone_ok(function, failed_path, exc) -> None:
        error = exc if isinstance(exc, BaseException) else exc[1]
        if isinstance(error, FileNotFoundError):
            return
        raise error

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=gone_ok)
    else:
        shutil.rmtree(path, onerror=gone_ok)


def _remove_tree_entry(entry: os.DirEntry[str]) -> None:
    """Remove one direct child without following symlinks/reparse points."""
    try:
        if _is_reparse_path(entry.path):
            if os.path.isdir(entry.path):
                os.rmdir(entry.path)
            else:
                os.unlink(entry.path)
            return
        if entry.is_dir(follow_symlinks=False):
            _rmtree_gone_ok(entry.path)
            return
        os.unlink(entry.path)
    except FileNotFoundError:
        return  # another remover took it first: it is gone (GAP-2355)


def _remove_data_dir(
    data_dir: str,
    *,
    preserve_entries: tuple[str, ...] = (),
    platform_name: str = sys.platform,
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
    if platform_name == "win32":
        # A link at the data folder or above it: it stays, and nothing goes through the link.
        _validate_windows_ancestor_chain(data_dir, "data path")
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
    if not _is_empty_dir(data_dir) and not any(os.path.exists(os.path.join(data_dir, m)) for m in markers):
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
    except FileNotFoundError:
        pass  # a concurrent uninstall of this account removed it (GAP-2355)
    except OSError as exc:
        # A data dir on its own filesystem (GAP-1447) is a mount point: the
        # contents are gone, and only an administrator can unmount the folder.
        if exc.errno == errno.EBUSY or os.path.ismount(data_dir):
            ux.ok(f"emptied {data_dir}; the empty folder stays because it is a mount point (unmount it to remove it)")
            return
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
    deferred_launchers: list[str] = []
    launchers = [p for p in targets if ntpath.basename(p).lower() in _WINDOWS_CLI_LAUNCHERS and os.path.lexists(p)]
    if (
        plan.platform_name == "win32"
        and any(ntpath.basename(path).lower() == "defenseclaw.cmd" for path in launchers)
        and _running_from_managed_venv(plan)
    ):
        # The launcher running this CLI cannot go now: Windows keeps a running
        # defenseclaw.exe, and cmd.exe reads defenseclaw.cmd again after this
        # CLI exits (deleting it ends the command with "The batch file cannot
        # be found." and exit 1). The helper removes both once they are done.
        try:
            _schedule_deferred_cleanup(replace(plan, binary_targets=tuple(launchers), remove_data_dir=False))
        except click.ClickException:
            # Without the helper the shim still goes last.
            targets.sort(key=lambda path: ntpath.basename(path).lower() == "defenseclaw.cmd")
        else:
            deferred_launchers = launchers
            targets = [path for path in targets if path not in launchers]
    elif plan.platform_name == "win32":
        targets.sort(key=lambda path: ntpath.basename(path).lower() == "defenseclaw.cmd")
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
    for path in deferred_launchers:
        ux.ok(f"{path} is removed right after this command exits")

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
    if remaining and _normalized(remaining) not in {_normalized(path) for path in deferred_launchers}:
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
