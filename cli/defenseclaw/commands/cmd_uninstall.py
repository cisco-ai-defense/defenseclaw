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
        return all(phase.status == "succeeded" for phase in self.phases)


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
) -> UninstallPlan:
    data_dir = str(config_module.default_data_path())

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
            if os.path.isfile(os.path.join(data_dir, marker)):
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

    if plan.stop_gateway:
        run_phase("gateway stop", _stop_gateway)
    if plan.connectors:
        run_phase("connector teardown", lambda: _connector_teardown(plan))
    if plan.remove_plugin and "openclaw" in plan.connectors:
        # Plugin removal is OpenClaw-specific. For other connectors the
        # gateway sentinel teardown above already removed their hook
        # scripts and config patches. This helper is idempotent and
        # reports "not installed" when OpenClaw was never used.
        run_phase("plugin removal", lambda: _remove_plugin(plan))
    if plan.remove_data_dir:
        run_phase(
            "data removal",
            lambda: _remove_data_dir(
                plan.data_dir,
                preserve_entries=plan.preserve_data_entries,
            ),
        )
    if plan.remove_binaries:
        run_phase("binary removal", _remove_binaries)

    result = ExecutionResult(tuple(phases))
    _render_execution_result(result)
    return result


def _render_execution_result(result: ExecutionResult) -> None:
    """Render a compact, stable phase ledger for humans and automation."""
    ux.subhead("Phase results:")
    for phase in result.phases:
        suffix = f" ({phase.detail})" if phase.detail else ""
        click.echo(f"  {phase.name}: {phase.status}{suffix}")


def _stop_gateway() -> None:
    gw = shutil.which("defenseclaw-gateway")
    if gw is None:
        ux.subhead("sidecar not on PATH — nothing to stop")
        return
    try:
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
        ux.ok("sidecar stopped")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise click.ClickException(f"could not stop sidecar: {exc}") from exc


def _gateway_supports_connector_teardown() -> bool:
    """Return True iff the local ``defenseclaw-gateway`` exposes the
    ``connector teardown`` subcommand introduced in S7.2.

    Older binaries print a usage error that includes ``unknown command``
    on stderr; the subprocess returncode is also non-zero. We detect
    by asking for ``--help`` on the ``connector`` subcommand — which is
    a non-destructive probe — and checking exit code + output.
    """
    gw = shutil.which("defenseclaw-gateway")
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
    gateway_supported = _gateway_supports_connector_teardown()
    for name in connectors:
        if gateway_supported:
            if _run_gateway_connector_teardown(name):
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


def _run_gateway_connector_teardown(connector: str) -> bool:
    """Invoke ``defenseclaw-gateway connector teardown --connector <name>``.

    Returns True on success (rc == 0), False on any error. stdout/stderr
    is forwarded to the operator so they can see exactly what each
    adapter restored.
    """
    gw = shutil.which("defenseclaw-gateway")
    if gw is None:
        return False
    try:
        proc = subprocess.run(
            [gw, "connector", "teardown", "--connector", connector],
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
            ux.warn(f"could not revert {plan.openclaw_config_file} (missing or malformed)")
    except Exception as exc:
        ux.warn(f"openclaw.json revert failed: {exc}")


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
        ux.warn("plugin uninstall failed (check permissions)")


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


def _remove_binaries() -> None:
    targets = [
        os.path.expanduser("~/.local/bin/defenseclaw-gateway"),
        os.path.expanduser("~/.local/bin/defenseclaw"),
        # Scanner entry points symlinked by `make cli-install`. Keep
        # this list in sync with the Makefile `cli-install` loop so a
        # fresh install / uninstall round-trip leaves no orphan links.
        os.path.expanduser("~/.local/bin/skill-scanner"),
        os.path.expanduser("~/.local/bin/skill-scanner-api"),
        os.path.expanduser("~/.local/bin/skill-scanner-pre-commit"),
        os.path.expanduser("~/.local/bin/mcp-scanner"),
        os.path.expanduser("~/.local/bin/mcp-scanner-api"),
        os.path.expanduser("~/.local/bin/litellm"),
    ]
    for path in targets:
        if not os.path.lexists(path):
            click.echo(f"  {ux.dim('·')} {path} not installed")
            continue
        try:
            os.unlink(path)
            ux.ok(f"removed {path}")
        except OSError as exc:
            ux.warn(f"failed to remove {path}: {exc}")

    # Clean up the pip-installed Python package symlink if operators
    # used ``pip install defenseclaw`` — we don't shell out to pip
    # because we can't be sure which environment they used.
    ux.subhead("if you installed the Python CLI via pip, run 'pip uninstall defenseclaw' manually")


def _expand(p: str) -> str:
    if p.startswith("~/"):
        return os.path.expanduser(p)
    return p
