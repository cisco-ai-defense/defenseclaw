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

Downloads pre-built release artifacts (gateway binary and Python CLI wheel)
from the GitHub release, runs version-specific migrations, and restarts
services. No source checkout or build toolchain required.

This matches the upgrade path used by scripts/upgrade.sh.
"""

from __future__ import annotations

import datetime
import os
import platform
import shutil
import subprocess
import sys
import tempfile

import click
import requests

from defenseclaw.context import AppContext, pass_ctx

GITHUB_REPO = "cisco-ai-defense/defenseclaw"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}"
GITHUB_DL = f"https://github.com/{GITHUB_REPO}/releases/download"


@click.command("upgrade")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
@click.option("--version", "target_version", default=None, help="Upgrade to a specific release version (e.g. 0.3.1)")
@pass_ctx
def upgrade(
    app: AppContext,
    yes: bool,
    target_version: str | None,
) -> None:
    """Upgrade DefenseClaw to the latest version.

    Downloads pre-built release artifacts (gateway binary, Python CLI wheel)
    from GitHub Releases, runs version-specific migrations, and restarts
    services. Your existing configuration is preserved.
    """
    from defenseclaw import __version__ as current_version

    click.echo()
    click.echo("  ── DefenseClaw Upgrade ───────────────────────────────────")
    click.echo()

    # ── Resolve target version ───────────────────────────────────────────────

    if target_version is None:
        click.echo("  → Fetching latest release from GitHub ...")
        target_version = _fetch_latest_version()
        if target_version is None:
            click.echo("  ✗ Could not determine latest release. Use --version to specify.", err=True)
            raise SystemExit(1)

    target_version = target_version.lstrip("v")
    click.echo(f"  ✓ Installed version: {current_version}")
    click.echo(f"  ✓ Target version:    {target_version}")

    if target_version == current_version and not yes:
        click.echo()
        click.echo("  Already at the latest version.")
        if not click.confirm("  Re-apply upgrade anyway?", default=False):
            return

    # ── Platform detection ───────────────────────────────────────────────────

    os_name, arch = _detect_platform()
    click.echo(f"  ✓ Platform: {os_name}/{arch}")

    # ── Confirm ──────────────────────────────────────────────────────────────

    if not yes:
        click.echo()
        click.echo("  This will:")
        click.echo("    1. Back up ~/.defenseclaw/ and ~/.openclaw/openclaw.json")
        click.echo("    2. Download and replace gateway binary and Python CLI")
        click.echo(f"       Source: github.com/{GITHUB_REPO}/releases/tag/{target_version}")
        click.echo("    3. Run version-specific migrations")
        click.echo("    4. Restart services")
        click.echo()
        if not click.confirm("  Proceed?", default=False):
            click.echo("  Aborted.")
            return

    # ── Create backup ────────────────────────────────────────────────────────

    click.echo()
    click.echo("  ── Creating Backup ──────────────────────────────────────")
    click.echo()

    backup_dir = _create_backup(app.cfg)
    click.echo(f"  ✓ Backup saved to: {backup_dir}")

    # ── Stop services ────────────────────────────────────────────────────────

    click.echo()
    click.echo("  ── Stopping Services ────────────────────────────────────")
    click.echo()

    _run_silent(["defenseclaw-gateway", "stop"], "Gateway stopped", "Gateway was not running")

    # ── Download, migrate, and restart ────────────────────────────────────────
    # Wrapped in try/finally so the gateway is always restarted even if the
    # download or migration step fails (e.g. unreleased version → HTTP 404).

    try:
        click.echo()
        click.echo("  ── Downloading Release Artifacts ────────────────────────")
        click.echo()

        _replace_gateway_from_release(target_version, os_name, arch)
        _replace_python_cli_from_release(target_version)

        click.echo()
        click.echo("  ── Running Migrations ───────────────────────────────────")
        click.echo()

        openclaw_home = os.path.expanduser(
            app.cfg.claw.home_dir if app.cfg else "~/.openclaw"
        )

        from defenseclaw.migrations import run_migrations
        count = run_migrations(current_version, target_version, openclaw_home)
        if count == 0:
            click.echo("  ✓ No migrations needed")
        else:
            click.echo(f"  ✓ Applied {count} migration(s)")

    finally:
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

    # ── Done ─────────────────────────────────────────────────────────────────

    click.echo()
    click.echo("  ── Upgrade Complete ─────────────────────────────────────")
    click.echo()
    click.echo(f"  ✓ DefenseClaw upgraded: {current_version} → {target_version}")
    click.echo(f"  Backup: {backup_dir}")
    click.echo()
    click.echo("  Run 'defenseclaw status' to verify all components are healthy.")
    click.echo()

    if app.logger:
        app.logger.log_action(
            "upgrade", "defenseclaw",
            f"from={current_version} to={target_version} backup={backup_dir}",
        )


# ---------------------------------------------------------------------------
# GitHub release helpers
# ---------------------------------------------------------------------------

def _fetch_latest_version() -> str | None:
    """Fetch the latest release version from GitHub.

    Uses GITHUB_TOKEN / GH_TOKEN for authentication when available to
    avoid hitting the unauthenticated rate limit (60 req/h).
    """
    try:
        headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = requests.get(f"{GITHUB_API}/releases/latest", headers=headers, timeout=15)
        resp.raise_for_status()
        tag = resp.json().get("tag_name", "")
        return tag.lstrip("v") if tag else None
    except (requests.RequestException, KeyError, ValueError):
        return None


def _detect_platform() -> tuple[str, str]:
    """Return (os_name, arch) matching goreleaser naming convention."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        click.echo(f"  ✗ Unsupported architecture: {machine}", err=True)
        raise SystemExit(1)

    if system not in ("darwin", "linux"):
        click.echo(f"  ✗ Unsupported OS: {system}", err=True)
        raise SystemExit(1)

    return system, arch


def _replace_gateway_from_release(version: str, os_name: str, arch: str) -> None:
    """Download and install the gateway binary from a GitHub release."""
    install_dir = os.path.expanduser("~/.local/bin")
    os.makedirs(install_dir, exist_ok=True)

    tarball = f"defenseclaw_{version}_{os_name}_{arch}.tar.gz"
    url = f"{GITHUB_DL}/{version}/{tarball}"

    click.echo(f"  → Downloading gateway binary ({os_name}/{arch}) ...")

    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, tarball)
        _download_file(url, dest)

        subprocess.run(
            ["tar", "-xzf", dest, "-C", tmp],
            check=True, capture_output=True,
        )

        src = os.path.join(tmp, "defenseclaw")
        target = os.path.join(install_dir, "defenseclaw-gateway")
        shutil.copy2(src, target)
        os.chmod(target, 0o755)

        if os_name == "darwin":
            subprocess.run(
                ["codesign", "-f", "-s", "-", target],
                capture_output=True, check=False,
            )

    click.echo("  ✓ Gateway binary replaced")


def _replace_python_cli_from_release(version: str) -> None:
    """Download and install the Python CLI wheel from a GitHub release."""
    uv = shutil.which("uv")
    if not uv:
        click.echo("  ✗ uv not found on PATH — cannot update Python CLI", err=True)
        raise SystemExit(1)

    venv = os.path.expanduser("~/.defenseclaw/.venv")
    venv_python = os.path.join(venv, "bin", "python")
    python = venv_python if os.path.isfile(venv_python) else sys.executable

    if not os.path.isdir(venv):
        click.echo("  → Creating venv ...")
        subprocess.run([uv, "venv", venv, "--python", "3.12"], check=True)

    whl_name = f"defenseclaw-{version}-py3-none-any.whl"
    url = f"{GITHUB_DL}/{version}/{whl_name}"

    click.echo("  → Downloading Python CLI wheel ...")

    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, whl_name)
        _download_file(url, dest)

        subprocess.run(
            [uv, "pip", "install", "--python", python, "--quiet", dest],
            check=True,
        )

    install_dir = os.path.expanduser("~/.local/bin")
    os.makedirs(install_dir, exist_ok=True)
    symlink = os.path.join(install_dir, "defenseclaw")
    venv_bin = os.path.join(venv, "bin", "defenseclaw")
    if os.path.isfile(venv_bin):
        if os.path.islink(symlink) or os.path.exists(symlink):
            os.remove(symlink)
        os.symlink(venv_bin, symlink)

    click.echo("  ✓ Python CLI replaced")


def _download_file(url: str, dest: str) -> None:
    """Download a file from url to dest, raising on failure."""
    resp = requests.get(url, stream=True, timeout=60, allow_redirects=True)
    if resp.status_code != 200:
        click.echo(f"  ✗ Download failed ({resp.status_code}): {url}", err=True)
        raise SystemExit(1)
    with open(dest, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

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
