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
import tempfile
import time

import click
import requests

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx

GITHUB_REPO = "cisco-ai-defense/defenseclaw"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}"
GITHUB_DL = f"https://github.com/{GITHUB_REPO}/releases/download"


@click.command("upgrade")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
@click.option("--version", "target_version", default=None, help="Upgrade to a specific release version (e.g. 0.3.1)")
@click.option("--health-timeout", default=60, type=int, help="Seconds to wait for gateway health after restart")
@pass_ctx
def upgrade(
    app: AppContext,
    yes: bool,
    target_version: str | None,
    health_timeout: int,
) -> None:
    """Upgrade DefenseClaw to the latest version.

    Downloads pre-built release artifacts (gateway binary, Python CLI wheel)
    from GitHub Releases, runs version-specific migrations, and restarts
    services. Your existing configuration is preserved.

    The upgrade is non-destructive: artifacts are downloaded and verified
    before the gateway is stopped, so a failed download never disrupts a
    running gateway.
    """
    from defenseclaw import __version__ as current_version

    ux.banner("DefenseClaw Upgrade")

    # ── Resolve target version ───────────────────────────────────────────────

    if target_version is None:
        click.echo(f"  {ux.dim('→')} Fetching latest release from GitHub ...")
        target_version = _fetch_latest_version()
        if target_version is None:
            ux.err("Could not determine latest release. Use --version to specify.", indent="  ")
            raise SystemExit(1)

    target_version = target_version.lstrip("v")
    ux.kv("Installed version", current_version, indent="  ", key_width=22)
    ux.kv("Target version", target_version, indent="  ", key_width=22)

    # ── Same-version repair ──────────────────────────────────────────────────

    if target_version == current_version:
        click.echo()
        ux.subhead(
            f"Already at version {current_version}; continuing to re-apply "
            "release artifacts and same-version migrations.",
        )

    # ── Platform detection ───────────────────────────────────────────────────

    os_name, arch = _detect_platform()
    ux.kv("Platform", f"{os_name}/{arch}", indent="  ", key_width=22)

    # ── Pre-flight: verify artifacts exist ───────────────────────────────────

    ux.banner("Pre-flight Check")

    _preflight_check(target_version, os_name, arch)

    # ── Download artifacts to temp (gateway still running) ───────────────────

    ux.banner("Downloading Release Artifacts")

    staging_dir = tempfile.mkdtemp(prefix="defenseclaw-upgrade-")
    try:
        gw_binary_path = _download_gateway(target_version, os_name, arch, staging_dir)
        whl_path = _download_wheel(target_version, staging_dir)
    except SystemExit:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise

    # ── Confirm ──────────────────────────────────────────────────────────────

    if not yes:
        click.echo()
        click.echo(f"  {ux.bold('This will:')}")
        click.echo(
            f"    {ux.dim('1.')} Back up ~/.defenseclaw/ and ~/.openclaw/openclaw.json"
        )
        click.echo(
            f"    {ux.dim('2.')} Stop the gateway, replace binaries from downloaded artifacts"
        )
        click.echo(f"    {ux.dim('3.')} Run version-specific migrations")
        click.echo(f"    {ux.dim('4.')} Restart services and verify health")
        click.echo()
        if not click.confirm("  Proceed?", default=False):
            ux.subhead("Aborted.")
            shutil.rmtree(staging_dir, ignore_errors=True)
            return

    # ── Create backup ────────────────────────────────────────────────────────

    ux.banner("Creating Backup")

    backup_dir = _create_backup(app.cfg)
    ux.ok(f"Backup saved to: {backup_dir}")

    # ── Stop gateway, install, migrate, restart ──────────────────────────────

    ux.banner("Stopping Services")

    _run_silent(["defenseclaw-gateway", "stop"], "Gateway stopped", "Gateway was not running")

    try:
        ux.banner("Installing Artifacts")

        _install_gateway(gw_binary_path, os_name)
        _install_wheel(whl_path)

        ux.banner("Running Migrations")

        openclaw_home = os.path.expanduser(
            app.cfg.claw.home_dir if app.cfg else "~/.openclaw"
        )
        # Thread the operator's data_dir through so migrations that
        # touch ``<data_dir>/.env`` / ``<data_dir>/active_connector.json``
        # / etc. (introduced in the connector-v3 wave, PR #194) hit the
        # right path even when the operator runs with a non-default
        # ``DEFENSECLAW_HOME``. Falls back to the upgrade module's
        # default expansion when the config could not be loaded.
        data_dir = (
            app.cfg.data_dir if app.cfg and app.cfg.data_dir
            else os.path.expanduser("~/.defenseclaw")
        )

        from defenseclaw.migrations import run_migrations
        count = run_migrations(current_version, target_version, openclaw_home, data_dir)
        click.echo()
        if count == 0:
            ux.ok("No migrations needed")
        else:
            ux.ok(f"Applied {count} migration(s)")

    finally:
        # Always clean up staging dir first, even if restart fails.
        shutil.rmtree(staging_dir, ignore_errors=True)

        ux.banner("Starting Services")

        _run_silent(["defenseclaw-gateway", "start"], "Gateway started", "Could not start gateway")

        result = subprocess.run(
            ["openclaw", "gateway", "restart"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode == 0:
            ux.ok("OpenClaw gateway restarted — DefenseClaw plugin loaded")
        else:
            ux.warn("Could not restart OpenClaw gateway automatically")
            ux.subhead("Run manually: openclaw gateway restart")

        # Health verification
        ux.banner("Verifying Gateway Health")
        _poll_health(app.cfg, health_timeout)

    # ── Done ─────────────────────────────────────────────────────────────────

    ux.banner("Upgrade Complete")
    ux.ok(f"DefenseClaw upgraded: {current_version} → {target_version}")
    click.echo(f"  {ux.bold('Backup:')} {backup_dir}")
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
        ux.err(f"Unsupported architecture: {machine}", indent="  ")
        raise SystemExit(1)

    if system not in ("darwin", "linux"):
        ux.err(f"Unsupported OS: {system}", indent="  ")
        raise SystemExit(1)

    return system, arch


def _preflight_check(version: str, os_name: str, arch: str) -> None:
    """Verify release artifacts exist on GitHub before touching anything."""
    tarball = f"defenseclaw_{version}_{os_name}_{arch}.tar.gz"
    whl_name = f"defenseclaw-{version}-py3-none-any.whl"
    urls = [
        f"{GITHUB_DL}/{version}/{tarball}",
        f"{GITHUB_DL}/{version}/{whl_name}",
    ]
    for url in urls:
        try:
            resp = requests.head(url, timeout=15, allow_redirects=True)
            if resp.status_code >= 400:
                ux.err(f"Artifact not found ({resp.status_code}): {url}", indent="  ")
                ux.err(
                    f"Version {version} may not exist or is missing platform artifacts.",
                    indent="    ",
                )
                raise SystemExit(1)
        except requests.RequestException as exc:
            ux.err(f"Could not reach GitHub: {exc}", indent="  ")
            raise SystemExit(1)
    ux.ok("Release artifacts verified")


def _download_gateway(version: str, os_name: str, arch: str, staging_dir: str) -> str:
    """Download the gateway tarball to staging_dir and extract. Returns path to binary."""
    tarball = f"defenseclaw_{version}_{os_name}_{arch}.tar.gz"
    url = f"{GITHUB_DL}/{version}/{tarball}"

    click.echo(f"  {ux.dim('→')} Downloading gateway binary ({os_name}/{arch}) ...")
    dest = os.path.join(staging_dir, tarball)
    _download_file(url, dest)
    subprocess.run(["tar", "-xzf", dest, "-C", staging_dir], check=True, capture_output=True)
    binary = os.path.join(staging_dir, "defenseclaw")
    ux.ok("Gateway binary downloaded")
    return binary


def _download_wheel(version: str, staging_dir: str) -> str:
    """Download the Python CLI wheel to staging_dir. Returns path to wheel."""
    whl_name = f"defenseclaw-{version}-py3-none-any.whl"
    url = f"{GITHUB_DL}/{version}/{whl_name}"

    click.echo(f"  {ux.dim('→')} Downloading Python CLI wheel ...")
    dest = os.path.join(staging_dir, whl_name)
    _download_file(url, dest)
    ux.ok("Python CLI wheel downloaded")
    return dest


def _install_gateway(binary_path: str, os_name: str) -> None:
    """Install a pre-downloaded gateway binary."""
    install_dir = os.path.expanduser("~/.local/bin")
    os.makedirs(install_dir, exist_ok=True)
    target = os.path.join(install_dir, "defenseclaw-gateway")
    shutil.copy2(binary_path, target)
    os.chmod(target, 0o755)
    if os_name == "darwin":
        subprocess.run(["codesign", "-f", "-s", "-", target], capture_output=True, check=False)
    ux.ok("Gateway binary installed")


def _install_wheel(whl_path: str) -> None:
    """Install a pre-downloaded Python CLI wheel."""
    uv = shutil.which("uv")
    if not uv:
        ux.err("uv not found on PATH — cannot update Python CLI", indent="  ")
        raise SystemExit(1)

    venv = os.path.expanduser("~/.defenseclaw/.venv")
    venv_python = os.path.join(venv, "bin", "python")

    if not os.path.isfile(venv_python):
        click.echo(f"  {ux.dim('→')} Creating venv ...")
        subprocess.run([uv, "venv", venv, "--python", "3.12"], check=True)

    subprocess.run([uv, "pip", "install", "--python", venv_python, "--quiet", whl_path], check=True)

    install_dir = os.path.expanduser("~/.local/bin")
    os.makedirs(install_dir, exist_ok=True)
    symlink = os.path.join(install_dir, "defenseclaw")
    venv_bin = os.path.join(venv, "bin", "defenseclaw")
    if os.path.isfile(venv_bin):
        if os.path.islink(symlink) or os.path.exists(symlink):
            os.remove(symlink)
        os.symlink(venv_bin, symlink)
    ux.ok("Python CLI installed")


def _poll_health(cfg, timeout_seconds: int = 60) -> None:
    """Poll the sidecar health endpoint until healthy or timeout."""
    from defenseclaw.gateway import OrchestratorClient

    bind = _api_bind_host(cfg)
    api_port = 18970
    token = ""
    if cfg:
        api_port = cfg.gateway.api_port
        token = cfg.gateway.resolved_token()

    client = OrchestratorClient(host=bind, port=api_port, token=token)

    deadline = time.monotonic() + timeout_seconds
    # Treat the pre-first-probe window the same way the gateway does so the
    # first successful "starting" reply is recognized as a state change and
    # printed. A missing/unreachable endpoint is surfaced as "unreachable" on
    # the first transient failure instead of being silently swallowed, which
    # was the #96 gotcha — operators saw no output for the full 60s timeout
    # when the sidecar crashed mid-upgrade.
    last_state = ""
    last_err = ""
    click.echo(
        f"  {ux.dim('→')} Waiting for gateway to become healthy "
        f"(timeout {timeout_seconds}s) ..."
    )

    while time.monotonic() < deadline:
        try:
            snap = client.health()
            if snap and isinstance(snap, dict):
                last_err = ""
                gw_state = snap.get("gateway", {}).get("state", "unknown")
                if gw_state != last_state:
                    click.echo(
                        f"    {ux.dim('gateway:')} {gw_state}"
                    )
                    last_state = gw_state
                if gw_state == "running":
                    ux.ok("Gateway is healthy")
                    return
            else:
                # 2xx with an empty/non-dict body — treat like unreachable so
                # the operator still sees a progress line instead of silence.
                err_label = "health endpoint returned no payload"
                if err_label != last_err:
                    click.echo(
                        f"    {ux.dim('gateway:')} unreachable ({err_label})"
                    )
                    last_err = err_label
                    last_state = ""
        except (OSError, ValueError) as exc:
            # Print the first unreachable reason and any distinct follow-up
            # so the operator can correlate with gateway.log. We deliberately
            # don't flood on every retry — only on transitions.
            err_label = type(exc).__name__
            detail = str(exc).splitlines()[0] if str(exc) else ""
            if detail:
                err_label = f"{err_label}: {detail}"
            if err_label != last_err:
                click.echo(
                    f"    {ux.dim('gateway:')} unreachable ({err_label})"
                )
                last_err = err_label
                last_state = ""
        time.sleep(2)

    ux.warn(f"Gateway did not become healthy within {timeout_seconds}s")
    ux.subhead(
        "Check logs: ~/.defenseclaw/gateway.log (pretty) / "
        "~/.defenseclaw/gateway.jsonl (structured)"
    )
    ux.subhead("Run:  defenseclaw-gateway status")


def _api_bind_host(cfg) -> str:
    """Resolve the API bind address, mirroring sidecar.runAPI in Go."""
    if not cfg:
        return "127.0.0.1"
    api_bind = getattr(cfg.gateway, "api_bind", "")
    if api_bind:
        return api_bind
    if cfg.openshell.is_standalone() and cfg.guardrail.host not in ("", "localhost", "127.0.0.1"):
        return cfg.guardrail.host
    return "127.0.0.1"


def _download_file(url: str, dest: str) -> None:
    """Download a file from url to dest, raising on failure."""
    resp = requests.get(url, stream=True, timeout=60, allow_redirects=True)
    if resp.status_code != 200:
        ux.err(f"Download failed ({resp.status_code}): {url}", indent="  ")
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

    # Back up every file the connector-v3 migration may touch. Listing
    # them explicitly (rather than copying the whole data_dir) keeps
    # the backup small and predictable: an operator restoring the
    # backup gets exactly the credentials + state files they had
    # pre-upgrade, not a snapshot of unrelated cache directories.
    for fname in (
        "config.yaml",
        ".env",
        "guardrail_runtime.json",
        "device.key",
        "active_connector.json",
        "codex_backup.json",
        "claudecode_backup.json",
        "zeptoclaw_backup.json",
        "codex_config_backup.json",
    ):
        src = os.path.join(data_dir, fname)
        if os.path.isfile(src):
            shutil.copy2(src, backup_dir)
            ux.ok(f"Backed up: {fname}")

    policies_dir = os.path.join(data_dir, "policies")
    if os.path.isdir(policies_dir):
        shutil.copytree(policies_dir, os.path.join(backup_dir, "policies"))
        ux.ok("Backed up: policies/")

    connector_backups_dir = os.path.join(data_dir, "connector_backups")
    if os.path.isdir(connector_backups_dir):
        shutil.copytree(
            connector_backups_dir,
            os.path.join(backup_dir, "connector_backups"),
        )
        ux.ok("Backed up: connector_backups/")

    openclaw_home = os.path.expanduser(cfg.claw.home_dir) if cfg else os.path.expanduser("~/.openclaw")
    oc_json = os.path.join(openclaw_home, "openclaw.json")
    if os.path.isfile(oc_json):
        shutil.copy2(oc_json, os.path.join(backup_dir, "openclaw.json"))
        ux.ok("Backed up: openclaw.json")

    return backup_dir


def _run_silent(cmd: list[str], ok_msg: str, fail_msg: str) -> bool:
    """Run a command, printing ok_msg on success and fail_msg on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode == 0:
            ux.ok(ok_msg)
            return True
        ux.warn(fail_msg)
        return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        ux.warn(fail_msg)
        return False
