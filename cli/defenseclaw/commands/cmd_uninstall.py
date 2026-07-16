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
from defenseclaw import ux

# Connectors whose teardown the Python CLI knows how to perform locally
# without going through ``defenseclaw-gateway connector teardown``. This
# is the conservative fallback path used when the gateway binary is too
# old to expose the connector subcommand.
_PYTHON_FALLBACK_CONNECTORS: frozenset[str] = frozenset({"openclaw"})
_RESET_PRESERVED_ENTRIES: tuple[str, ...] = (".venv",)
_WIN_SYNCHRONIZE = 0x00100000
_WIN_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_CONNECTOR_BACKUP_MARKERS: dict[str, tuple[str, ...]] = {
    "openclaw": (os.path.join("connector_backups", "openclaw", "openclaw.json.json"),),
    "codex": (
        "codex_backup.json",
        "codex_config_backup.json",
        os.path.join("connector_backups", "codex", "config.toml.json"),
    ),
    "claudecode": (
        "claudecode_backup.json",
        os.path.join("connector_backups", "claudecode", "settings.json.json"),
    ),
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
    help="Additionally remove the defenseclaw + defenseclaw-gateway binaries from ~/.local/bin.",
)
@click.option(
    "--keep-openclaw",
    is_flag=True,
    help="Do NOT revert OpenClaw config or remove its plugin; other connector teardown still runs.",
)
@click.option("--dry-run", is_flag=True, help="Show what would happen without touching the system.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def uninstall_cmd(
    wipe_data: bool,
    binaries: bool,
    keep_openclaw: bool,
    dry_run: bool,
    yes: bool,
) -> None:
    """Uninstall DefenseClaw (reversibly by default)."""
    plan = _build_plan(
        wipe_data=wipe_data,
        binaries=binaries,
        revert_openclaw=not keep_openclaw,
        remove_plugin=not keep_openclaw,
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


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------


@click.command("reset")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def reset_cmd(yes: bool) -> None:
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
    in-process configs that haven't been migrated yet — the same
    pattern used in :mod:`cmd_setup_sandbox`. We can't rely on
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
) -> UninstallPlan:
    platform_name = platform_name or sys.platform
    data_dir = str(config_module.default_data_path())
    install_root, binary_targets = _owned_binary_targets(platform_name)

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

    return UninstallPlan(
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
    )


def _owned_binary_targets(platform_name: str) -> tuple[str, tuple[str, ...]]:
    """Freeze the exact launcher paths owned by each supported installer."""
    if platform_name == "win32":
        home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
        install_root = os.path.abspath(os.path.join(home, ".local", "bin"))
        names = (
            "defenseclaw.cmd",
            "defenseclaw-gateway.exe",
            "defenseclaw-hook.exe",
        )
    else:
        install_root = os.path.abspath(os.path.expanduser("~/.local/bin"))
        names = (
            "defenseclaw-gateway",
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
        for target in plan.binary_targets:
            click.echo(f"      {ux.dim('·')} {target}")
    if _requires_deferred_cleanup(plan):
        click.echo(f"  • {ux.bold('deferred cleanup:')}   after this managed CLI exits")
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
    if plan.stop_gateway:
        run_phase("gateway stop", lambda: _stop_gateway(plan))
    if plan.connectors:
        run_phase("connector teardown", lambda: _connector_teardown(plan))
    if plan.remove_plugin and "openclaw" in plan.connectors:
        # Plugin removal is OpenClaw-specific. For other connectors the
        # gateway sentinel teardown above already removed their hook
        # scripts and config patches. This helper is idempotent and
        # reports "not installed" when OpenClaw was never used.
        run_phase("plugin removal", lambda: _remove_plugin(plan))
    deferred = _requires_deferred_cleanup(plan)
    if deferred:
        status: list[str] = []

        def schedule() -> None:
            status.append(_schedule_deferred_cleanup(plan))

        run_phase("deferred cleanup", schedule)
        phases[-1] = ExecutionPhaseResult(
            "deferred cleanup",
            "scheduled",
            f"result: {status[0]}",
        )
    elif plan.remove_data_dir:
        run_phase(
            "data removal",
            lambda: _remove_data_dir(
                plan.data_dir,
                preserve_entries=plan.preserve_data_entries,
            ),
        )
    if plan.remove_binaries and not deferred:
        run_phase("binary removal", lambda: _remove_binaries(plan))

    result = ExecutionResult(tuple(phases))
    _render_execution_result(result)
    return result


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


def _validate_windows_binary_ownership(plan: UninstallPlan) -> None:
    """Require the installer-authored CLI shim before removing paired artifacts."""
    existing = [path for path in plan.binary_targets if os.path.lexists(path)]
    if not existing:
        return
    shim = os.path.join(plan.install_root, "defenseclaw.cmd")
    if not os.path.isfile(shim) or _is_reparse_path(shim):
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


def _runtime_isolation_generations(data_dir: str) -> tuple[str, ...]:
    """Return exact managed generations that still hold moved user skills.

    Empty connector parents are harmless lifecycle residue. Any child below a
    connector parent is retained fail-closed: it may be the sole copy of a
    skill whose runtime policy moved it outside the client's discovery root.
    The walk is deliberately fixed-depth and never follows a path alias.
    """
    root = os.path.join(data_dir, "quarantine", "skills", "runtime-isolation")
    if not os.path.lexists(root):
        return ()
    if _is_reparse_path(root) or not os.path.isdir(root):
        raise click.ClickException(
            f"refusing unsafe runtime-isolation root: {root}"
        )

    generations: list[str] = []
    with os.scandir(root) as connectors:
        for connector in connectors:
            if _is_reparse_path(connector.path) or not connector.is_dir(
                follow_symlinks=False,
            ):
                raise click.ClickException(
                    "refusing unsafe runtime-isolation connector entry: "
                    f"{connector.path}"
                )
            with os.scandir(connector.path) as entries:
                for entry in entries:
                    if _is_reparse_path(entry.path):
                        raise click.ClickException(
                            "refusing unsafe runtime-isolation generation: "
                            f"{entry.path}"
                        )
                    generations.append(entry.path)
    return tuple(generations)


def _require_runtime_isolation_restored(data_dir: str) -> None:
    generations = _runtime_isolation_generations(data_dir)
    if not generations:
        return
    raise click.ClickException(
        f"refusing to delete {len(generations)} runtime-isolated skill "
        "generation(s); these may be the only copies. Inspect each skill with "
        "'defenseclaw skill info <name> --json', run 'defenseclaw skill enable "
        "<name> --connector codex', then restore it with 'defenseclaw skill "
        "restore <name> --connector codex' before reset or uninstall --all"
    )


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
        _require_runtime_isolation_restored(plan.data_dir)
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
            {"defenseclaw.cmd", "defenseclaw-gateway.exe", "defenseclaw-hook.exe"}
            if plan.platform_name == "win32"
            else {
                "defenseclaw-gateway",
                "defenseclaw",
                "skill-scanner",
                "skill-scanner-api",
                "skill-scanner-pre-commit",
                "mcp-scanner",
                "mcp-scanner-api",
                "litellm",
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
    if (
        not base_python
        or not os.path.isfile(base_python)
        or _is_reparse_path(base_python)
        or _normalized(base_python).startswith(_normalized(plan.data_dir) + os.sep)
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
            "binary_targets": list(plan.binary_targets) if plan.remove_binaries else [],
            "remove_data_dir": plan.remove_data_dir,
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

    _require_runtime_isolation_restored(data_dir)

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
            click.echo(f"  {ux.dim('·')} {path} not installed")
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

    # Clean up the pip-installed Python package symlink if operators
    # used ``pip install defenseclaw`` — we don't shell out to pip
    # because we can't be sure which environment they used.
    ux.subhead("if you installed the Python CLI via pip, run 'pip uninstall defenseclaw' manually")


def _expand(p: str) -> str:
    if p.startswith("~/"):
        return os.path.expanduser(p)
    return p
