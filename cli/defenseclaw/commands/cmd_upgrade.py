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

"""defenseclaw upgrade — Upgrade DefenseClaw to the latest version.

Backs up the current installation, restores openclaw.json to its
pre-DefenseClaw state, uninstalls the old setup, rebuilds from the
latest source, and reinstalls.
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import subprocess
import sys

import click

from defenseclaw.context import AppContext, pass_ctx


@click.command("upgrade")
@click.option(
    "--source-dir",
    default=None,
    metavar="DIR",
    help=(
        "Path to the defenseclaw source repository. "
        "Defaults to the directory discovered via the installed package."
    ),
)
@click.option("--skip-pull", is_flag=True, help="Skip git pull before rebuilding")
@click.option(
    "--local",
    "local_dist",
    default=None,
    metavar="DIR",
    help="Install from a local dist/ directory instead of rebuilding from source",
)
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
@pass_ctx
def upgrade(
    app: AppContext,
    source_dir: str | None,
    skip_pull: bool,
    local_dist: str | None,
    yes: bool,
) -> None:
    """Upgrade DefenseClaw to the latest version.

    Backs up ~/.defenseclaw/ and ~/.openclaw/openclaw.json, reverts OpenClaw
    to its pre-DefenseClaw state, uninstalls the current setup, pulls the
    latest source (or installs from a local dist/), rebuilds, and reinstalls
    with your existing configuration.

    Equivalent to running scripts/upgrade.sh directly.
    """
    from defenseclaw.paths import scripts_dir

    click.echo()
    click.echo("  ── DefenseClaw Upgrade ───────────────────────────────────")
    click.echo()

    # ── Resolve source directory ──────────────────────────────────────────────

    if local_dist is None:
        resolved_source = _resolve_source_dir(source_dir)
        if resolved_source is None:
            click.echo(
                "  ✗ Could not find the defenseclaw source directory.\n"
                "    Use --source-dir <path> to specify it explicitly,\n"
                "    or --local <dist-dir> to install from pre-built artifacts.",
                err=True,
            )
            raise SystemExit(1)
        click.echo(f"  ✓ Source directory: {resolved_source}")
    else:
        resolved_source = None
        click.echo(f"  ✓ Local dist: {local_dist}")

    # ── Confirm ───────────────────────────────────────────────────────────────

    if not yes:
        click.echo()
        click.echo("  This will:")
        click.echo("    1. Back up ~/.defenseclaw/ and ~/.openclaw/openclaw.json")
        click.echo("    2. Restore openclaw.json to its pre-DefenseClaw state")
        click.echo("    3. Uninstall the current DefenseClaw plugin and gateway")
        if local_dist:
            click.echo(f"    4. Install from local dist: {local_dist}")
        else:
            if not skip_pull:
                click.echo("    4. Pull latest changes from git")
            click.echo("    5. Rebuild and reinstall DefenseClaw")
        click.echo("    6. Re-configure guardrail with your existing settings")
        click.echo()
        if not click.confirm("  Proceed?", default=False):
            click.echo("  Aborted.")
            return

    # ── Save current guardrail settings ──────────────────────────────────────

    click.echo()
    click.echo("  ── Saving Configuration ─────────────────────────────────")
    click.echo()

    gc = app.cfg.guardrail if app.cfg else None
    saved_mode = gc.mode if gc else ""
    saved_port = gc.port if gc else None
    saved_scanner_mode = gc.scanner_mode if gc else ""
    saved_block_message = gc.block_message if gc else ""

    click.echo(
        f"  ✓ Saved settings: mode={saved_mode or 'default'} "
        f"port={saved_port or 'default'} scanner={saved_scanner_mode or 'default'}"
    )

    # ── Create backup ─────────────────────────────────────────────────────────

    click.echo()
    click.echo("  ── Creating Backup ──────────────────────────────────────")
    click.echo()

    backup_dir = _create_backup(app.cfg)
    click.echo(f"  ✓ Backup saved to: {backup_dir}")

    # ── Restore openclaw.json ─────────────────────────────────────────────────

    click.echo()
    click.echo("  ── Restoring openclaw.json ──────────────────────────────")
    click.echo()

    openclaw_config = os.path.expanduser(app.cfg.claw.config_file) if app.cfg else None
    openclaw_home = os.path.expanduser(app.cfg.claw.home_dir) if app.cfg else os.path.expanduser("~/.openclaw")

    _restore_openclaw_json(openclaw_config, openclaw_home, app.cfg)

    # ── Stop gateway ──────────────────────────────────────────────────────────

    click.echo()
    click.echo("  ── Stopping Services ────────────────────────────────────")
    click.echo()

    _run_silent(["defenseclaw-gateway", "stop"], "Gateway stopped", "Gateway was not running")

    # Remove plugin directory directly (belt-and-suspenders after restore)
    plugin_dir = os.path.join(openclaw_home, "extensions", "defenseclaw")
    if os.path.isdir(plugin_dir):
        shutil.rmtree(plugin_dir, ignore_errors=True)
        click.echo(f"  ✓ Removed plugin directory: {plugin_dir}")

    # ── Update and rebuild ────────────────────────────────────────────────────

    click.echo()
    click.echo("  ── Rebuilding ───────────────────────────────────────────")
    click.echo()

    if local_dist:
        _install_from_local(local_dist, scripts_dir())
    elif resolved_source is not None:
        _rebuild_from_source(resolved_source, skip_pull)

    # ── Re-configure guardrail ────────────────────────────────────────────────

    click.echo()
    click.echo("  ── Re-configuring Guardrail ─────────────────────────────")
    click.echo()

    setup_args = ["defenseclaw", "setup", "guardrail", "--non-interactive"]
    if saved_mode:
        setup_args += ["--mode", saved_mode]
    if saved_port:
        setup_args += ["--port", str(saved_port)]
    if saved_scanner_mode:
        setup_args += ["--scanner-mode", saved_scanner_mode]
    if saved_block_message:
        setup_args += ["--block-message", saved_block_message]

    click.echo(f"  → Running: {' '.join(setup_args)}")
    result = subprocess.run(setup_args, check=False)
    if result.returncode == 0:
        click.echo("  ✓ Guardrail re-configured")
    else:
        click.echo("  ⚠ Guardrail setup returned non-zero — check output above")

    # ── Start gateway ─────────────────────────────────────────────────────────

    click.echo()
    click.echo("  ── Starting Services ────────────────────────────────────")
    click.echo()

    _run_silent(["defenseclaw-gateway", "start"], "Gateway started", "Could not start gateway")

    result = subprocess.run(
        ["openclaw", "gateway", "restart"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode == 0:
        click.echo("  ✓ OpenClaw gateway restarted — DefenseClaw plugin loaded")
    else:
        click.echo("  ⚠ Could not restart OpenClaw gateway automatically")
        click.echo("    Run manually: openclaw gateway restart")

    # ── Done ──────────────────────────────────────────────────────────────────

    click.echo()
    click.echo("  ── Upgrade Complete ─────────────────────────────────────")
    click.echo()
    click.echo("  ✓ DefenseClaw has been upgraded successfully")
    click.echo(f"  Backup: {backup_dir}")
    click.echo()
    click.echo("  Run 'defenseclaw status' to verify all components are healthy.")
    click.echo()

    if app.logger:
        app.logger.log_action("upgrade", "defenseclaw", f"backup={backup_dir}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_source_dir(explicit: str | None) -> str | None:
    """Return the defenseclaw source repository path, or None if not found."""
    if explicit:
        if os.path.isdir(explicit) and os.path.isfile(os.path.join(explicit, "Makefile")):
            return explicit
        return None

    # Try: directory containing this file -> ../../../../ (4 levels up from
    # cli/defenseclaw/commands/cmd_upgrade.py → defenseclaw/)
    candidate = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
    )
    if os.path.isfile(os.path.join(candidate, "Makefile")):
        return candidate

    # Try well-known locations
    for path in [
        os.path.expanduser("~/defenseclaw"),
        os.path.expanduser("~/.defenseclaw/src"),
    ]:
        if os.path.isfile(os.path.join(path, "Makefile")):
            return path

    return None


def _create_backup(cfg) -> str:
    """Back up ~/.defenseclaw/ config files and ~/.openclaw/openclaw.json."""
    data_dir = cfg.data_dir if cfg else os.path.expanduser("~/.defenseclaw")
    backup_root = os.path.join(data_dir, "backups")
    timestamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    backup_dir = os.path.join(backup_root, f"upgrade-{timestamp}")
    os.makedirs(backup_dir, exist_ok=True)

    # Backup defenseclaw config files
    for fname in ("config.yaml", ".env", "guardrail_runtime.json", "device.key"):
        src = os.path.join(data_dir, fname)
        if os.path.isfile(src):
            shutil.copy2(src, backup_dir)
            click.echo(f"  ✓ Backed up: {fname}")

    policies_dir = os.path.join(data_dir, "policies")
    if os.path.isdir(policies_dir):
        shutil.copytree(policies_dir, os.path.join(backup_dir, "policies"))
        click.echo("  ✓ Backed up: policies/")

    # Backup openclaw.json and all .bak files
    openclaw_home = os.path.expanduser(cfg.claw.home_dir) if cfg else os.path.expanduser("~/.openclaw")
    oc_json = os.path.join(openclaw_home, "openclaw.json")
    if os.path.isfile(oc_json):
        shutil.copy2(oc_json, os.path.join(backup_dir, "openclaw.json"))
        click.echo("  ✓ Backed up: openclaw.json (current)")

    for bak in sorted(_glob_files(openclaw_home, "openclaw.json.bak*")):
        shutil.copy2(bak, os.path.join(backup_dir, os.path.basename(bak)))
        click.echo(f"  ✓ Backed up: {os.path.basename(bak)}")

    return backup_dir


def _restore_openclaw_json(openclaw_config: str | None, _openclaw_home: str, cfg) -> None:
    """Restore openclaw.json to its pre-DefenseClaw state.

    Strategy (in order of preference):
      1. openclaw.json.bak exists and has no defenseclaw entries → copy it back
      2. Use restore_openclaw_config() to programmatically remove defenseclaw entries
    """
    from defenseclaw.guardrail import restore_openclaw_config

    if openclaw_config is None:
        click.echo("  ⚠ openclaw.json path unknown — skipping restore")
        return

    original_bak = openclaw_config + ".bak"
    if os.path.isfile(original_bak):
        if not _has_defenseclaw_entries(original_bak):
            shutil.copy2(original_bak, openclaw_config)
            click.echo("  ✓ Restored openclaw.json from original backup (defenseclaw-free)")
            return
        click.echo("  ⚠ Backup also has defenseclaw entries — using programmatic restore")

    original_model = cfg.guardrail.original_model if cfg else ""
    if restore_openclaw_config(openclaw_config, original_model):
        click.echo("  ✓ Removed DefenseClaw entries from openclaw.json")
    else:
        click.echo("  ⚠ Could not restore openclaw.json — check it manually")


def _has_defenseclaw_entries(path: str) -> bool:
    """Return True if openclaw.json contains defenseclaw plugin registration."""
    try:
        with open(path) as f:
            data = json.load(f)
        return "defenseclaw" in data.get("plugins", {}).get("allow", [])
    except (OSError, json.JSONDecodeError):
        return False


def _rebuild_from_source(source_dir: str, skip_pull: bool) -> None:
    """Git pull (optional), rebuild gateway binary, and reinstall Python CLI."""
    if not skip_pull:
        if os.path.isdir(os.path.join(source_dir, ".git")):
            click.echo("  → Running git pull ...")
            result = subprocess.run(["git", "pull"], cwd=source_dir, check=False)
            if result.returncode == 0:
                click.echo("  ✓ Source updated")
            else:
                click.echo("  ⚠ git pull failed — continuing with current source")
        else:
            click.echo("  ⚠ Not a git repository — skipping git pull")

    # Rebuild Go gateway
    click.echo("  → Building defenseclaw-gateway ...")
    result = subprocess.run(
        ["make", "gateway-install"],
        cwd=source_dir, check=False,
    )
    if result.returncode == 0:
        click.echo("  ✓ defenseclaw-gateway rebuilt and installed")
    else:
        click.echo("  ✗ make gateway-install failed", err=True)
        raise SystemExit(1)

    # Reinstall Python CLI — uninstall old wheel first so stale site-packages
    # (e.g. old guardrail.py that writes models.providers.defenseclaw) can't
    # shadow the new source.
    click.echo("  → Installing Python CLI ...")
    venv = os.path.expanduser("~/.defenseclaw/.venv")
    venv_uv = os.path.join(venv, "bin", "uv")
    venv_python = os.path.join(venv, "bin", "python")
    uv = venv_uv if os.path.isfile(venv_uv) else (shutil.which("uv") or "uv")
    python = venv_python if os.path.isfile(venv_python) else sys.executable

    # Step 1: uninstall old wheel so editable install takes full effect.
    subprocess.run(
        [uv, "pip", "uninstall", "defenseclaw", "--python", python, "-q"],
        check=False, capture_output=True,
    )

    # Step 2: install editable from current source.
    result = subprocess.run(
        [uv, "pip", "install", "-e", source_dir, "--python", python, "--quiet"],
        check=False,
    )
    if result.returncode != 0:
        subprocess.run(
            [python, "-m", "pip", "install", "-e", source_dir, "--quiet"],
            check=True,
        )
    click.echo("  ✓ Python CLI updated")

    # Rebuild plugin (best-effort)
    click.echo("  → Rebuilding OpenClaw plugin ...")
    result = subprocess.run(
        ["make", "plugin", "plugin-install"],
        cwd=source_dir, check=False,
        capture_output=True,
    )
    if result.returncode == 0:
        click.echo("  ✓ Plugin rebuilt and staged")
    else:
        click.echo("  ⚠ Plugin build failed — run 'make plugin plugin-install' manually")


def _install_from_local(local_dist: str, scripts: str) -> None:
    """Install from a local dist/ directory using install.sh --local."""
    install_sh = os.path.join(scripts, "install.sh")
    if not os.path.isfile(install_sh):
        click.echo(f"  ✗ install.sh not found at {install_sh}", err=True)
        raise SystemExit(1)

    click.echo(f"  → Running install.sh --local {local_dist} --yes ...")
    result = subprocess.run(
        ["bash", install_sh, "--local", local_dist, "--yes"],
        check=False,
    )
    if result.returncode != 0:
        click.echo("  ✗ install.sh failed", err=True)
        raise SystemExit(1)
    click.echo("  ✓ Installed from local dist")


def _run_silent(cmd: list[str], ok_msg: str, fail_msg: str) -> bool:
    """Run a command, printing ok_msg on success and fail_msg on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode == 0:
            click.echo(f"  ✓ {ok_msg}")
            return True
        click.echo(f"  ⚠ {fail_msg}")
        return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        click.echo(f"  ⚠ {fail_msg}")
        return False


def _glob_files(directory: str, pattern: str) -> list[str]:
    """Return files in directory matching a simple prefix+suffix glob."""
    import fnmatch
    try:
        return [
            os.path.join(directory, f)
            for f in os.listdir(directory)
            if fnmatch.fnmatch(f, pattern)
        ]
    except OSError:
        return []
