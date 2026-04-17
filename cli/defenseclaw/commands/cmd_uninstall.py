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
the tool. ``reset`` is the "lose my data" button — it wipes
``~/.defenseclaw`` but keeps the binaries and the OpenClaw plugin
in place so ``defenseclaw quickstart`` can reinstall cleanly.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

import click

from defenseclaw import config as config_module


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
@click.option("--keep-openclaw", is_flag=True, help="Do NOT revert ~/.openclaw/openclaw.json or remove the plugin.")
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
    _render_plan(plan, dry_run=dry_run)

    if dry_run:
        click.echo("  (dry-run — nothing modified)")
        return

    if not yes and not click.confirm("  Proceed?", default=False):
        click.echo("  Cancelled.")
        raise SystemExit(1)

    _execute_plan(plan)


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------

@click.command("reset")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def reset_cmd(yes: bool) -> None:
    """Wipe ~/.defenseclaw so 'defenseclaw quickstart' starts clean.

    Keeps binaries and the OpenClaw plugin installed so reinstall is
    fast. For a full uninstall use 'defenseclaw uninstall --all
    --binaries'.
    """
    plan = _build_plan(
        wipe_data=True,
        binaries=False,
        revert_openclaw=True,
        remove_plugin=False,  # keep plugin around for quick re-enable
    )
    _render_plan(plan, dry_run=False)

    if not yes and not click.confirm(
        f"  This will DELETE {plan.data_dir}. Continue?", default=False
    ):
        click.echo("  Cancelled.")
        raise SystemExit(1)

    _execute_plan(plan)
    click.echo("  ✓ Reset complete. Run 'defenseclaw quickstart' to reinstall.")


# ---------------------------------------------------------------------------
# Planning + execution
# ---------------------------------------------------------------------------

def _build_plan(
    *,
    wipe_data: bool,
    binaries: bool,
    revert_openclaw: bool,
    remove_plugin: bool,
) -> UninstallPlan:
    data_dir = str(config_module.default_data_path())

    # Best-effort config load to discover OpenClaw paths. A broken or
    # missing config is fine here — we fall back to sensible defaults
    # rather than blocking the uninstall.
    openclaw_config_file = ""
    openclaw_home = ""
    try:
        cfg = config_module.load()
        openclaw_config_file = cfg.claw.config_file
        openclaw_home = cfg.claw.home_dir
    except Exception:
        openclaw_home = os.path.expanduser("~/.openclaw")
        openclaw_config_file = os.path.join(openclaw_home, "openclaw.json")

    return UninstallPlan(
        stop_gateway=True,
        revert_openclaw=revert_openclaw,
        remove_plugin=remove_plugin,
        remove_data_dir=wipe_data,
        remove_binaries=binaries,
        data_dir=data_dir,
        openclaw_config_file=openclaw_config_file,
        openclaw_home=openclaw_home,
    )


def _render_plan(plan: UninstallPlan, *, dry_run: bool) -> None:
    click.echo()
    click.echo("  ── Uninstall plan ────────────────────────────────────")
    click.echo()
    click.echo(f"  • stop sidecar:        {'yes' if plan.stop_gateway else 'no'}")
    click.echo(f"  • revert openclaw.json: {'yes' if plan.revert_openclaw else 'no'} "
               f"({plan.openclaw_config_file})")
    click.echo(f"  • remove plugin:        {'yes' if plan.remove_plugin else 'no'}")
    click.echo(f"  • wipe {plan.data_dir}: {'yes' if plan.remove_data_dir else 'no'}")
    click.echo(f"  • remove binaries:     {'yes' if plan.remove_binaries else 'no'}")
    click.echo()


def _execute_plan(plan: UninstallPlan) -> None:
    if plan.stop_gateway:
        _stop_gateway()
    if plan.revert_openclaw:
        _revert_openclaw(plan)
    if plan.remove_plugin:
        _remove_plugin(plan)
    if plan.remove_data_dir:
        _remove_data_dir(plan.data_dir)
    if plan.remove_binaries:
        _remove_binaries()


def _stop_gateway() -> None:
    gw = shutil.which("defenseclaw-gateway")
    if gw is None:
        click.echo("  · sidecar not on PATH — nothing to stop")
        return
    try:
        subprocess.run([gw, "stop"], capture_output=True, text=True, timeout=15)
        click.echo("  ✓ sidecar stopped")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        click.echo(f"  ⚠ could not stop sidecar: {exc}")


def _revert_openclaw(plan: UninstallPlan) -> None:
    """Restore openclaw.json, preferring the pristine backup if we have it."""
    from defenseclaw.guardrail import (
        pristine_backup_path,
        restore_openclaw_config,
    )

    pristine = pristine_backup_path(plan.openclaw_config_file, plan.data_dir)
    target = _expand(plan.openclaw_config_file)
    if pristine:
        try:
            shutil.copy2(pristine, target)
            click.echo(f"  ✓ restored {target} from pristine backup ({os.path.basename(pristine)})")
            return
        except OSError as exc:
            click.echo(f"  ⚠ pristine restore failed: {exc} — falling back to config edit")

    # Fall back to the surgical restore — removes our plugin registration
    # without rolling the file back to its exact prior state.
    try:
        ok = restore_openclaw_config(plan.openclaw_config_file, original_model="")
        if ok:
            click.echo(f"  ✓ removed DefenseClaw entries from {plan.openclaw_config_file}")
        else:
            click.echo(f"  ⚠ could not revert {plan.openclaw_config_file} (missing or malformed)")
    except Exception as exc:
        click.echo(f"  ⚠ openclaw.json revert failed: {exc}")


def _remove_plugin(plan: UninstallPlan) -> None:
    from defenseclaw.guardrail import uninstall_openclaw_plugin

    result = uninstall_openclaw_plugin(plan.openclaw_home)
    if result == "cli":
        click.echo("  ✓ plugin uninstalled via openclaw CLI")
    elif result == "manual":
        click.echo("  ✓ plugin directory removed")
    elif result == "":
        click.echo("  · plugin was not installed")
    else:
        click.echo("  ⚠ plugin uninstall failed (check permissions)")


def _remove_data_dir(data_dir: str) -> None:
    # Safety guard: an empty / root-like path here would be catastrophic
    # because we're about to recursively delete. Bail out unless the
    # directory genuinely looks like a DefenseClaw data dir (i.e.
    # contains one of the files we ourselves write on init). This
    # protects operators who set ``DEFENSECLAW_HOME`` to somewhere weird
    # like ``/`` or ``$HOME`` against a catastrophic rm -rf.
    if not data_dir or not os.path.isdir(data_dir):
        click.echo(f"  · {data_dir} does not exist — skipping")
        return
    # Disallow top-level / root-ish paths outright.
    resolved = os.path.realpath(data_dir)
    if resolved in ("/", os.path.expanduser("~"), os.path.realpath(os.path.expanduser("~"))):
        click.echo(f"  ⚠ refusing to remove protected path {resolved}")
        return
    markers = ("config.yaml", "audit.db", ".env", "policies", "quarantine")
    if not any(os.path.exists(os.path.join(data_dir, m)) for m in markers):
        click.echo(
            f"  ⚠ {data_dir} does not look like a DefenseClaw data dir "
            "(no config.yaml / audit.db / policies) — skipping"
        )
        return
    try:
        shutil.rmtree(data_dir)
        click.echo(f"  ✓ removed {data_dir}")
    except OSError as exc:
        click.echo(f"  ⚠ failed to remove {data_dir}: {exc}")


def _remove_binaries() -> None:
    targets = [
        os.path.expanduser("~/.local/bin/defenseclaw-gateway"),
        os.path.expanduser("~/.local/bin/defenseclaw"),
    ]
    for path in targets:
        if not os.path.lexists(path):
            click.echo(f"  · {path} not installed")
            continue
        try:
            os.unlink(path)
            click.echo(f"  ✓ removed {path}")
        except OSError as exc:
            click.echo(f"  ⚠ failed to remove {path}: {exc}")

    # Clean up the pip-installed Python package symlink if operators
    # used ``pip install defenseclaw`` — we don't shell out to pip
    # because we can't be sure which environment they used.
    click.echo(
        "  · if you installed the Python CLI via pip, run "
        "'pip uninstall defenseclaw' manually"
    )


def _expand(p: str) -> str:
    if p.startswith("~/"):
        return os.path.expanduser(p)
    return p
