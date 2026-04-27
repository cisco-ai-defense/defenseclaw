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

"""defenseclaw quickstart — zero-prompt first-run setup.

Designed for ``make all`` and ``install.sh --quickstart``. Picks safe
defaults (observe mode, local scanner, no judge) and runs every step
of the install flow without asking the user a single question. Power
users who want something different should use ``defenseclaw init
--enable-guardrail`` or ``defenseclaw setup guardrail`` instead.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import click

from defenseclaw import __version__
from defenseclaw.context import AppContext


@click.command("quickstart")
@click.option(
    "--mode",
    type=click.Choice(["observe", "action"], case_sensitive=False),
    default="observe",
    show_default=True,
    help="Guardrail mode. 'observe' logs findings only; 'action' blocks when critical.",
)
@click.option(
    "--scanner",
    "scanner_mode",
    type=click.Choice(["local", "remote", "both"], case_sensitive=False),
    default="local",
    show_default=True,
    help="Scanner backend. 'local' is the zero-key default; 'remote'/'both' require CISCO_AI_DEFENSE_API_KEY.",
)
@click.option(
    "--with-judge/--no-judge",
    "with_judge",
    default=False,
    help="Enable the LLM Judge adjudicator (reuses the unified DEFENSECLAW_LLM_KEY).",
)
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Never prompt. Same as --yes; kept for install-script compat.",
)
@click.option(
    "--yes",
    is_flag=True,
    help="Assume yes for confirmations.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Re-run all steps even if the environment is already initialized.",
)
@click.option(
    "--agent",
    "agent_name",
    type=click.Choice(
        ["openclaw", "zeptoclaw", "claudecode", "codex"],
        case_sensitive=False,
    ),
    default=None,
    help="Agent framework connector (default: auto-detect or openclaw).",
)
@click.option(
    "--skip-gateway",
    is_flag=True,
    help="Do not start the sidecar at the end of quickstart.",
)
def quickstart_cmd(
    mode: str,
    scanner_mode: str,
    with_judge: bool,
    non_interactive: bool,
    yes: bool,
    force: bool,
    agent_name: str | None,
    skip_gateway: bool,
) -> None:
    """Zero-prompt end-to-end setup with safe defaults.

    Equivalent to running ``init`` → ``setup guardrail`` → ``gateway
    start`` but with a scripted, non-interactive UX. Missing API keys
    are listed at the end so the operator knows exactly what (if
    anything) to wire up before the guardrail becomes useful.
    """
    _ = non_interactive, yes  # accepted for script compatibility

    from defenseclaw import config as cfg_mod
    from defenseclaw.bootstrap import bootstrap_env
    from defenseclaw.commands.cmd_setup import (
        _detect_openclaw_gateway_token,
        execute_guardrail_setup,
    )
    from defenseclaw.credentials import mask
    from defenseclaw.db import Store
    from defenseclaw.logger import Logger

    connector = agent_name or "openclaw"

    click.echo()
    click.echo(f"  DefenseClaw v{__version__} — quickstart")
    click.echo("  ──────────────────────────────────────────────────────")
    click.echo()

    # --- Step 1: load-or-create config ---
    try:
        cfg = cfg_mod.load()
        new_config = False
    except Exception:
        cfg = cfg_mod.default_config()
        new_config = True

    if force:
        click.echo("  [1/5] Forcing re-init (--force)")
    elif new_config:
        click.echo("  [1/5] Creating fresh configuration…")
    else:
        click.echo("  [1/5] Reusing existing configuration…")
    cfg.environment = cfg_mod.detect_environment()
    cfg.save()
    click.echo(f"        config:  {cfg_mod.config_path()}")
    click.echo(f"        data:    {cfg.data_dir}")

    # --- Step 2: bootstrap dirs, DB, policies, gateway defaults ---
    click.echo()
    click.echo("  [2/5] Bootstrapping environment…")
    store = Store(cfg.audit_db)
    store.init()
    logger = Logger(store, cfg.splunk)
    try:
        report = bootstrap_env(cfg, logger)
        _render_bootstrap_report(report)
    finally:
        # Bootstrap doesn't close store/logger — we'll reuse both below.
        pass

    # --- Step 3: Gateway token auto-detection ---
    click.echo()
    click.echo(f"  [3/5] Detecting gateway token (connector: {connector})…")
    if connector == "openclaw":
        token = _detect_openclaw_gateway_token(cfg.claw.config_file)
        if token:
            click.echo(f"        ✓ OPENCLAW_GATEWAY_TOKEN = {mask(token)}")
            cfg.gateway.token_env = "OPENCLAW_GATEWAY_TOKEN"
        else:
            click.echo("        ⚠ No OpenClaw token detected.")
            click.echo("          This is expected if you're running DefenseClaw before OpenClaw")
            click.echo("          is set up. Re-run 'defenseclaw quickstart' after installing OpenClaw.")
    else:
        if not cfg.gateway.device_key_file:
            cfg.gateway.device_key_file = os.path.join(cfg.data_dir, "device.key")
        click.echo(f"        ℹ {connector} connector uses device-key auth (no token needed).")
        click.echo(f"        device key: {cfg.gateway.device_key_file}")

    # --- Step 4: apply safe guardrail defaults + execute setup ---
    click.echo()
    click.echo(f"  [4/5] Configuring guardrail (mode={mode}, scanner={scanner_mode}, connector={connector})…")
    gc = cfg.guardrail
    gc.enabled = True
    gc.mode = mode
    gc.scanner_mode = scanner_mode
    gc.connector = connector
    gc.judge.enabled = with_judge

    app = AppContext()
    app.cfg = cfg
    app.store = store
    app.logger = logger

    # For OpenClaw connector, verify its config file exists before patching.
    # Other connectors handle their own setup in the Go gateway.
    if connector == "openclaw":
        oc_path = (
            os.path.expanduser(cfg.claw.config_file)
            if cfg.claw.config_file.startswith("~/")
            else cfg.claw.config_file
        )
        if not os.path.isfile(oc_path):
            click.echo(f"        ⚠ OpenClaw config not found at {cfg.claw.config_file}")
            click.echo("          Guardrail will be saved but not activated. Run 'defenseclaw setup guardrail'")
            click.echo("          after installing OpenClaw to patch its config.")
            gc.enabled = False
            cfg.save()
            guardrail_ok = False
            warnings: list[str] = [f"OpenClaw config missing at {cfg.claw.config_file}"]
        else:
            guardrail_ok, warnings = execute_guardrail_setup(app, save_config=True)
    else:
        guardrail_ok, warnings = execute_guardrail_setup(app, save_config=True)

    for w in warnings:
        click.echo(f"        ⚠ {w}")

    # --- Step 5: start the sidecar ---
    click.echo()
    if skip_gateway:
        click.echo("  [5/5] Skipping sidecar start (--skip-gateway).")
    else:
        click.echo("  [5/5] Starting sidecar…")
        _start_sidecar(cfg, guardrail_ok)

    # --- Summary ---
    click.echo()
    click.echo("  ──────────────────────────────────────────────────────")
    _print_credentials_summary(cfg)
    click.echo()
    click.echo("  Next steps:")
    click.echo("    defenseclaw doctor          Verify the installation")
    click.echo("    defenseclaw keys list       See which API keys are missing")
    click.echo("    defenseclaw status          Check sidecar + guardrail status")
    click.echo()

    # Cleanup shared handles we opened above.
    try:
        logger.close()
    finally:
        store.close()

    # Quickstart reports a non-zero exit only when the environment is in
    # a definitely-unusable state. Missing OpenClaw is *expected* on
    # first install, so we treat it as a warning rather than an error.
    if report.errors:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _render_bootstrap_report(report) -> None:
    """One-line status for each bootstrap step."""
    new_marker = "created" if report.is_new_config else "preserved"
    click.echo(f"        config:  {new_marker}")
    click.echo(f"        audit:   {report.audit_db}")
    if report.rego_seeded:
        click.echo(f"        rego:    {report.rego_seeded}")
    if report.guardrail_profiles_seeded:
        click.echo(
            "        rule packs: seeded " + ", ".join(report.guardrail_profiles_seeded)
        )
    if report.guardrail_profiles_preserved:
        click.echo(
            "        rule packs: preserved " + ", ".join(report.guardrail_profiles_preserved)
        )
    if report.splunk_bridge_dest:
        state = "preserved" if report.splunk_bridge_preserved else "seeded"
        click.echo(f"        splunk:  {state} {report.splunk_bridge_dest}")
    for err in report.errors:
        click.echo(f"        ✗ {err}")


def _start_sidecar(cfg, guardrail_ok: bool) -> None:
    """Start ``defenseclaw-gateway`` and optionally restart after guardrail patch."""
    gw = shutil.which("defenseclaw-gateway")
    if gw is None:
        click.echo("        ⚠ defenseclaw-gateway not on PATH — run 'make gateway-install'")
        return

    pid_file = os.path.join(cfg.data_dir, "gateway.pid")
    if _sidecar_running(pid_file):
        click.echo("        ✓ sidecar already running")
        if guardrail_ok:
            # Reload config so the new guardrail settings take effect.
            _run([gw, "restart"], timeout=15)
            click.echo("        ✓ sidecar restarted to apply guardrail")
        return

    result = _run([gw, "start"], timeout=30)
    if result is not None and result.returncode == 0:
        pid = _read_pid(pid_file)
        if pid:
            click.echo(f"        ✓ sidecar started (PID {pid})")
        else:
            click.echo("        ✓ sidecar started")
    else:
        click.echo("        ✗ sidecar failed to start — run 'defenseclaw-gateway status'")


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _sidecar_running(pid_file: str) -> bool:
    pid = _read_pid(pid_file)
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def _read_pid(pid_file: str) -> int | None:
    try:
        with open(pid_file, encoding="utf-8") as fh:
            raw = fh.read().strip()
        try:
            return int(raw)
        except ValueError:
            return int(json.loads(raw)["pid"])
    except (FileNotFoundError, ValueError, KeyError, OSError, TypeError):
        return None


def _print_credentials_summary(cfg) -> None:
    """Summarize which credentials are set vs. required vs. optional."""
    from defenseclaw.credentials import Requirement
    from defenseclaw.credentials import classify as _classify

    statuses = _classify(cfg)
    required_missing = [s for s in statuses if s.requirement is Requirement.REQUIRED and not s.resolution.is_set]
    optional_missing = [s for s in statuses if s.requirement is Requirement.OPTIONAL and not s.resolution.is_set]
    set_count = sum(1 for s in statuses if s.resolution.is_set)

    click.echo(f"  API keys: {set_count} set, {len(required_missing)} required missing, "
               f"{len(optional_missing)} optional missing.")

    if required_missing:
        click.echo()
        click.echo("  REQUIRED keys not yet set:")
        for s in required_missing:
            click.echo(f"    • {s.resolution.env_name}  —  {s.spec.description}")

    if optional_missing:
        click.echo()
        click.echo("  Optional keys (run 'defenseclaw keys list' for the full list):")
        # Only show the first few to keep the summary short.
        for s in optional_missing[:4]:
            click.echo(f"    • {s.resolution.env_name}  —  {s.spec.description}")
        if len(optional_missing) > 4:
            click.echo(f"    … and {len(optional_missing) - 4} more")
