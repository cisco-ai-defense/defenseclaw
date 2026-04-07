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

Replaces changed files (gateway binary, Python CLI, TS plugin), runs
version-specific migrations, and restarts services. Does NOT uninstall
or reinstall from scratch.
"""

from __future__ import annotations

import datetime
import os
import shutil
import subprocess
import sys

import click

from defenseclaw.context import AppContext, pass_ctx


@click.command("upgrade")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
@pass_ctx
def upgrade(
    app: AppContext,
    yes: bool,
) -> None:
    """Upgrade DefenseClaw to the latest version.

    Replaces changed files (gateway binary, plugin, Python CLI), runs
    version-specific migrations, and restarts services. Your existing
    configuration is preserved.
    """
    from defenseclaw import __version__ as current_version

    click.echo()
    click.echo("  ── DefenseClaw Upgrade ───────────────────────────────────")
    click.echo()

    # ── Resolve source directory ──────────────────────────────────────────────

    resolved_source = _resolve_source_dir()
    if resolved_source is None:
        click.echo(
            "  ✗ Could not find the defenseclaw source directory.",
            err=True,
        )
        raise SystemExit(1)

    # ── Detect versions ───────────────────────────────────────────────────────

    new_version = _read_source_version(resolved_source)
    click.echo(f"  ✓ Installed version: {current_version}")
    click.echo(f"  ✓ New version:       {new_version}")

    if new_version == current_version and not yes:
        click.echo()
        click.echo("  Already at the latest version.")
        if not click.confirm("  Re-apply upgrade anyway?", default=False):
            return

    # ── Confirm ───────────────────────────────────────────────────────────────

    if not yes:
        click.echo()
        click.echo("  This will:")
        click.echo("    1. Back up ~/.defenseclaw/ and ~/.openclaw/openclaw.json")
        click.echo("    2. Replace gateway binary, Python CLI, and plugin files")
        click.echo("    3. Run version-specific migrations")
        click.echo("    4. Restart services")
        click.echo()
        if not click.confirm("  Proceed?", default=False):
            click.echo("  Aborted.")
            return

    # ── Create backup ─────────────────────────────────────────────────────────

    click.echo()
    click.echo("  ── Creating Backup ──────────────────────────────────────")
    click.echo()

    backup_dir = _create_backup(app.cfg)
    click.echo(f"  ✓ Backup saved to: {backup_dir}")

    # ── Stop services ─────────────────────────────────────────────────────────

    click.echo()
    click.echo("  ── Stopping Services ────────────────────────────────────")
    click.echo()

    _run_silent(["defenseclaw-gateway", "stop"], "Gateway stopped", "Gateway was not running")

    # ── Replace files ─────────────────────────────────────────────────────────

    click.echo()
    click.echo("  ── Replacing Files ──────────────────────────────────────")
    click.echo()

    _replace_gateway(resolved_source)
    _replace_python_cli(resolved_source)
    _replace_plugin(resolved_source, app.cfg)

    # ── Run migrations ────────────────────────────────────────────────────────

    click.echo()
    click.echo("  ── Running Migrations ───────────────────────────────────")
    click.echo()

    openclaw_home = os.path.expanduser(
        app.cfg.claw.home_dir if app.cfg else "~/.openclaw"
    )

    from defenseclaw.migrations import run_migrations
    count = run_migrations(current_version, new_version, openclaw_home)
    if count == 0:
        click.echo("  ✓ No migrations needed")
    else:
        click.echo(f"  ✓ Applied {count} migration(s)")

    # ── Start services ────────────────────────────────────────────────────────

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
    click.echo(f"  ✓ DefenseClaw upgraded: {current_version} → {new_version}")
    click.echo(f"  Backup: {backup_dir}")
    click.echo()
    click.echo("  Run 'defenseclaw status' to verify all components are healthy.")
    click.echo()

    if app.logger:
        app.logger.log_action(
            "upgrade", "defenseclaw",
            f"from={current_version} to={new_version} backup={backup_dir}",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_source_dir() -> str | None:
    """Return the defenseclaw source repository path, or None if not found."""
    candidate = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
    )
    if os.path.isfile(os.path.join(candidate, "Makefile")):
        return candidate

    for path in [
        os.path.expanduser("~/defenseclaw"),
        os.path.expanduser("~/.defenseclaw/src"),
    ]:
        if os.path.isfile(os.path.join(path, "Makefile")):
            return path

    return None


def _read_source_version(source_dir: str) -> str:
    """Read the version from pyproject.toml in the source directory."""
    pyproject = os.path.join(source_dir, "pyproject.toml")
    try:
        with open(pyproject) as f:
            for line in f:
                if line.strip().startswith("version"):
                    # version = "0.3.0"
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return "unknown"


def _create_backup(cfg) -> str:
    """Back up ~/.defenseclaw/ config files and ~/.openclaw/openclaw.json."""
    data_dir = cfg.data_dir if cfg else os.path.expanduser("~/.defenseclaw")
    backup_root = os.path.join(data_dir, "backups")
    timestamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    backup_dir = os.path.join(backup_root, f"upgrade-{timestamp}")
    os.makedirs(backup_dir, exist_ok=True)

    for fname in ("config.yaml", ".env", "guardrail_runtime.json", "device.key"):
        src = os.path.join(data_dir, fname)
        if os.path.isfile(src):
            shutil.copy2(src, backup_dir)
            click.echo(f"  ✓ Backed up: {fname}")

    policies_dir = os.path.join(data_dir, "policies")
    if os.path.isdir(policies_dir):
        shutil.copytree(policies_dir, os.path.join(backup_dir, "policies"))
        click.echo("  ✓ Backed up: policies/")

    openclaw_home = os.path.expanduser(cfg.claw.home_dir) if cfg else os.path.expanduser("~/.openclaw")
    oc_json = os.path.join(openclaw_home, "openclaw.json")
    if os.path.isfile(oc_json):
        shutil.copy2(oc_json, os.path.join(backup_dir, "openclaw.json"))
        click.echo("  ✓ Backed up: openclaw.json")

    return backup_dir


def _replace_gateway(source_dir: str) -> None:
    """Rebuild and replace the gateway binary."""
    click.echo("  → Building defenseclaw-gateway ...")
    result = subprocess.run(
        ["make", "gateway-install"],
        cwd=source_dir, check=False,
    )
    if result.returncode == 0:
        click.echo("  ✓ Gateway binary replaced")
    else:
        click.echo("  ✗ make gateway-install failed", err=True)
        raise SystemExit(1)


def _replace_python_cli(source_dir: str) -> None:
    """Replace the Python CLI via editable install (updates changed files)."""
    click.echo("  → Updating Python CLI ...")
    uv = shutil.which("uv")
    if not uv:
        click.echo("  ✗ uv not found on PATH — cannot update Python CLI", err=True)
        raise SystemExit(1)

    venv = os.path.expanduser("~/.defenseclaw/.venv")
    venv_python = os.path.join(venv, "bin", "python")
    python = venv_python if os.path.isfile(venv_python) else sys.executable

    if not os.path.isdir(venv):
        subprocess.run([uv, "venv", venv, "--python", "3.12"], check=True)

    subprocess.run(
        [uv, "pip", "install", "-e", source_dir, "--python", python],
        check=True,
    )
    click.echo("  ✓ Python CLI updated")


def _replace_plugin(source_dir: str, cfg) -> None:
    """Rebuild and replace the plugin files."""
    click.echo("  → Rebuilding plugin ...")
    result = subprocess.run(
        ["make", "plugin", "plugin-install"],
        cwd=source_dir, check=False,
        capture_output=True,
    )
    if result.returncode == 0:
        click.echo("  ✓ Plugin files replaced")
    else:
        click.echo("  ⚠ Plugin build failed — run 'make plugin plugin-install' manually")


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
