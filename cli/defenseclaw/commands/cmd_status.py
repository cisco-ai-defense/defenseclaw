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

    # Splunk integration
    _print_splunk_integration_status(cfg)

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
    if client.is_running():
        click.secho("  Sidecar:      running", fg="green")
    else:
        click.echo("  Sidecar:      not running")


def _print_splunk_integration_status(cfg) -> None:
    otel = cfg.otel
    sc = cfg.splunk
    has_splunk = otel.enabled or sc.enabled

    if not has_splunk:
        click.echo()
        click.echo("  Splunk:       not configured")
        return

    click.echo()
    click.echo("  Splunk:")

    if otel.enabled:
        click.echo("    O11y (OTLP):    enabled")
        if otel.traces.enabled and otel.traces.endpoint:
            click.echo(f"      Traces:       {otel.traces.endpoint}{otel.traces.url_path}")
        if otel.metrics.enabled and otel.metrics.endpoint:
            click.echo(f"      Metrics:      {otel.metrics.endpoint}{otel.metrics.url_path}")
        if otel.logs.enabled and otel.logs.endpoint:
            click.echo(f"      Logs:         {otel.logs.endpoint}{otel.logs.url_path}")
    else:
        click.echo("    O11y (OTLP):    disabled")

    if sc.enabled:
        click.echo(f"    HEC (logs):     enabled → {sc.hec_endpoint}")
    else:
        click.echo("    HEC (logs):     disabled")
