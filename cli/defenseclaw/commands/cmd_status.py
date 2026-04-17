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

"""defenseclaw status — Show current enforcement status and health.

Mirrors internal/cli/status.go.
"""

from __future__ import annotations

import shutil

import click

from defenseclaw.context import AppContext, pass_ctx


@click.command()
@pass_ctx
def status(app: AppContext) -> None:
    """Show DefenseClaw status.

    Displays environment, sandbox health, scanner availability,
    enforcement counts, and activity summary.
    """
    cfg = app.cfg

    click.echo("DefenseClaw Status")
    click.echo("══════════════════")
    click.echo(f"  Environment:  {cfg.environment}")
    click.echo(f"  Data dir:     {cfg.data_dir}")
    click.echo(f"  Config:       {cfg.data_dir}/config.yaml")
    click.echo(f"  Audit DB:     {cfg.audit_db}")
    click.echo()

    # Sandbox
    if shutil.which(cfg.openshell.binary):
        click.echo("  Sandbox:      available")
    else:
        click.echo("  Sandbox:      not available (OpenShell not found)")

    # Scanners
    click.echo()
    click.echo("  Scanners:")
    scanner_bins = [
        ("skill-scanner", cfg.scanners.skill_scanner.binary),
        ("mcp-scanner", cfg.scanners.mcp_scanner.binary),
        ("codeguard", "built-in"),
    ]
    for name, binary in scanner_bins:
        if binary == "built-in":
            click.echo(f"    {name:<16s} built-in")
        elif shutil.which(binary):
            click.echo(f"    {name:<16s} installed")
        else:
            click.echo(f"    {name:<16s} not found")

    # Counts from DB
    if app.store:
        try:
            counts = app.store.get_counts()
            click.echo()
            click.echo("  Enforcement:")
            click.echo(f"    Blocked skills:  {counts.blocked_skills}")
            click.echo(f"    Allowed skills:  {counts.allowed_skills}")
            click.echo(f"    Blocked MCPs:    {counts.blocked_mcps}")
            click.echo(f"    Allowed MCPs:    {counts.allowed_mcps}")
            click.echo()
            click.echo("  Activity:")
            click.echo(f"    Total scans:     {counts.total_scans}")
            click.echo(f"    Active alerts:   {counts.alerts}")
        except Exception:
            pass

    # Observability destinations (OTel exporter + audit sinks)
    _print_observability_status(cfg)

    # Sidecar status
    click.echo()
    from defenseclaw.gateway import OrchestratorClient
    bind = "127.0.0.1"
    if cfg.openshell.is_standalone() and cfg.guardrail.host not in ("", "localhost", "127.0.0.1"):
        bind = cfg.guardrail.host
    client = OrchestratorClient(
        host=bind,
        port=cfg.gateway.api_port,
        token=cfg.gateway.resolved_token(),
    )
    from defenseclaw.commands import hint
    if client.is_running():
        click.secho("  Sidecar:      running", fg="green")
        hint(
            "Dashboard:     defenseclaw alerts",
            "Health check:  defenseclaw doctor",
        )
    else:
        click.echo("  Sidecar:      not running")
        hint("Start sidecar:  defenseclaw-gateway start")


def _print_observability_status(cfg) -> None:
    """Enumerate every observability destination — gateway OTel exporter
    plus every ``audit_sinks`` entry — in a single section.

    The old ``_print_splunk_integration_status`` was hard-coded to the
    legacy ``cfg.splunk`` hydration and the single ``otel:`` block and
    so couldn't see Datadog, Honeycomb, New Relic, or extra Splunk HEC
    sinks configured via ``setup observability``. This walks the YAML
    via the observability writer so whatever ``setup observability add``
    writes shows up here for free.
    """
    # Lazy import so ``status`` stays fast on systems that never
    # configured observability (avoids the YAML read when possible).
    from defenseclaw.observability import list_destinations
    from defenseclaw.observability.presets import PRESETS

    try:
        destinations = list_destinations(cfg.data_dir)
    except Exception:
        destinations = []

    click.echo()
    click.echo("  Observability:")

    if not destinations:
        click.echo("    (none configured — run `defenseclaw setup observability add <preset>`)")
        return

    for d in destinations:
        label = PRESETS[d.preset_id].display_name if d.preset_id in PRESETS else d.kind
        state = click.style("enabled", fg="green") if d.enabled else click.style("disabled", fg="bright_black")
        target_tag = "otel" if d.target == "otel" else "sink"
        click.echo(f"    {d.name:<26s} [{target_tag}] {state}  — {label}")

        if d.target == "otel" and d.enabled:
            enabled_signals = [s for s, on in d.signals.items() if on]
            if enabled_signals:
                click.echo(f"      signals: {', '.join(sorted(enabled_signals))}")
            if d.endpoint:
                click.echo(f"      endpoint: {d.endpoint}")
        elif d.enabled and d.endpoint:
            click.echo(f"      endpoint: {d.endpoint}")
