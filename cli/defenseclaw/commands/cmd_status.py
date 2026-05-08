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

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx

# ---------------------------------------------------------------------------
# Color conventions for `defenseclaw status`
# ---------------------------------------------------------------------------
#
# Labels (e.g. "Environment:", "Data dir:") render as bold-and-dim
# so they recede slightly compared to the value. The values use the
# default foreground because operators eye-scan for *what's set*,
# not for the labels.
#
# Status verbs use marker-color pairs the rest of the CLI shares:
#   - running / installed / available / built-in → green
#   - not running / not found / not available     → yellow (advisory)
#   - never red — `status` is observational; failures live in `doctor`
#
# Layout intentionally preserves the original two-space separator
# between label and value (e.g. "  Data dir:     /Users/...") so
# tests that grep for substrings like ``"Environment:"`` keep
# matching unchanged.

_STATUS_LABEL_WIDTH = 14  # "Environment:  " — locks legacy alignment


def _label(text: str) -> str:
    """Render a status label bold-and-dim.

    Returns plain text when colors are off so the substring stays
    intact for ``CliRunner`` output assertions.
    """
    return ux._style(text, fg="bright_black", bold=True)


def _status_row(key: str, value: str) -> None:
    """Print one ``  Label: value`` row using the legacy 14-col layout.

    Padding goes inside the dim label so the bold style covers the
    whole "Environment:  " region. Empty values render as a dim
    em-dash to keep the row tracking its column.
    """
    label_padded = (key + ":").ljust(_STATUS_LABEL_WIDTH)
    rendered_value = ux.dim("—") if not value else value
    click.echo(f"  {ux._style(label_padded, fg='bright_black', bold=True)}{rendered_value}")


@click.command()
@pass_ctx
def status(app: AppContext) -> None:
    """Show DefenseClaw status.

    Displays environment, sandbox health, scanner availability,
    enforcement counts, and activity summary.
    """
    cfg = app.cfg

    # Title block — `═` divider matches the legacy double-line look
    # but now scales to the title length and renders cyan-bold.
    click.echo()
    click.echo(ux._style("DefenseClaw Status", fg="cyan", bold=True))
    click.echo(ux._style("══════════════════", fg="cyan"))

    _status_row("Environment", cfg.environment)
    _status_row("Data dir", cfg.data_dir)
    _status_row("Config", f"{cfg.data_dir}/config.yaml")
    _status_row("Audit DB", cfg.audit_db)
    click.echo()

    # Sandbox
    if shutil.which(cfg.openshell.binary):
        _status_row("Sandbox", ux._style("available", fg="green"))
    else:
        _status_row(
            "Sandbox",
            ux._style("not available", fg="yellow") + ux.dim(" (OpenShell not found)"),
        )

    # Scanners
    ux.section("Scanners")
    scanner_bins = [
        ("skill-scanner", cfg.scanners.skill_scanner.binary),
        ("mcp-scanner", cfg.scanners.mcp_scanner.binary),
        ("codeguard", "built-in"),
    ]
    for name, binary in scanner_bins:
        if binary == "built-in":
            click.echo(f"    {ux.bold(f'{name:<16s}')}{ux.dim('built-in')}")
        elif shutil.which(binary):
            click.echo(f"    {ux.bold(f'{name:<16s}')}{ux._style('installed', fg='green')}")
        else:
            click.echo(f"    {ux.bold(f'{name:<16s}')}{ux._style('not found', fg='yellow')}")

    # Counts from DB. The numeric labels stay tight-aligned to match
    # the legacy 16-char column; we color the labels and leave the
    # numbers in default fg so they stand out.
    if app.store:
        try:
            counts = app.store.get_counts()
            ux.section("Enforcement")
            for label, val in (
                ("Blocked skills", counts.blocked_skills),
                ("Allowed skills", counts.allowed_skills),
                ("Blocked MCPs", counts.blocked_mcps),
                ("Allowed MCPs", counts.allowed_mcps),
            ):
                click.echo(f"    {_label((label + ':').ljust(16))} {val}")
            ux.section("Activity")
            for label, val in (
                ("Total scans", counts.total_scans),
                ("Active alerts", counts.alerts),
            ):
                click.echo(f"    {_label((label + ':').ljust(16))} {val}")
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
        _status_row("Sidecar", ux._style("running", fg="green"))
        _print_connected_agent(bind, cfg.gateway.api_port)
        hint(
            "Dashboard:     defenseclaw alerts",
            "Health check:  defenseclaw doctor",
        )
    else:
        _status_row("Sidecar", ux._style("not running", fg="yellow"))
        # Even when the sidecar is down, show the *configured* agent
        # so operators know what `start` will spin up.
        configured = cfg.active_connector() if hasattr(cfg, "active_connector") else (cfg.claw.mode or "openclaw")
        _status_row(
            "Agent",
            f"{_friendly_connector_name(configured)} ({configured})"
            + ux.dim(" — configured, not connected"),
        )
        hint("Start sidecar:  defenseclaw-gateway start")


_FRIENDLY_CONNECTOR_NAMES = {
    "openclaw": "OpenClaw",
    "zeptoclaw": "ZeptoClaw",
    "claudecode": "Claude Code",
    "codex": "Codex",
    "hermes": "Hermes",
    "cursor": "Cursor",
    "windsurf": "Windsurf",
    "geminicli": "Gemini CLI",
    "copilot": "GitHub Copilot CLI",
}


def _friendly_connector_name(name: str | None) -> str:
    """Mirror internal/tui/connector_label.go::FriendlyConnectorName.

    Kept duplicated to avoid coupling the Python CLI to the Go TUI
    binary — the friendly-name table is small and rarely changes.
    """
    if not name:
        return "OpenClaw"
    name = name.strip()
    if name in _FRIENDLY_CONNECTOR_NAMES:
        return _FRIENDLY_CONNECTOR_NAMES[name]
    return name[:1].upper() + name[1:]


def _print_connected_agent(host: str, port: int) -> None:
    """Read /health and surface the active-connector block.

    Failure modes are intentionally swallowed — the sidecar may have
    just come up, or the operator may be on an old gateway build that
    pre-dates the connector field. We never want `defenseclaw status`
    to error because of an optional UX line.
    """
    try:
        import json as _json
        import urllib.request as _urlreq

        url = f"http://{host}:{port}/health"
        req = _urlreq.Request(url)
        with _urlreq.urlopen(req, timeout=3) as resp:  # noqa: S310 — loopback only
            data = _json.loads(resp.read().decode("utf-8"))
    except Exception:
        return

    conn = data.get("connector") if isinstance(data, dict) else None
    if not isinstance(conn, dict):
        _status_row("Agent", ux.dim("(no active connector)"))
        return

    name = str(conn.get("name") or "").strip()
    state = str(conn.get("state") or "").strip().upper()
    friendly = _friendly_connector_name(name)

    # Color the state verb to match the rest of the row family:
    # RUNNING green, anything else yellow (dormant / starting / etc.).
    # Errors are surfaced via the requests/errors line below; the
    # state verb stays advisory.
    state_text = ""
    if state:
        if state in ("RUNNING", "ACTIVE", "READY", "UP"):
            state_text = " — " + ux._style(state, fg="green")
        else:
            state_text = " — " + ux._style(state, fg="yellow")

    _status_row("Agent", f"{friendly} ({name}){state_text}")

    tool_mode = str(conn.get("tool_inspection_mode") or "").strip()
    sub_policy = str(conn.get("subprocess_policy") or "").strip()
    if tool_mode or sub_policy:
        click.echo(
            f"                {ux.dim('tool inspection:')} {tool_mode or 'n/a'}    "
            f"{ux.dim('subprocess:')} {sub_policy or 'n/a'}"
        )

    requests = int(conn.get("requests") or 0)
    errors = int(conn.get("errors") or 0)
    inspections = int(conn.get("tool_inspections") or 0)
    tool_blocks = int(conn.get("tool_blocks") or 0)
    sub_blocks = int(conn.get("subprocess_blocks") or 0)
    # Errors get colored when non-zero so eyes catch them first.
    err_text = (
        ux._style(f"errors: {errors}", fg="red", bold=True)
        if errors
        else ux.dim(f"errors: {errors}")
    )
    block_text_tool = (
        ux._style(f"tool blocks: {tool_blocks}", fg="yellow")
        if tool_blocks
        else ux.dim(f"tool blocks: {tool_blocks}")
    )
    block_text_sub = (
        ux._style(f"subprocess blocks: {sub_blocks}", fg="yellow")
        if sub_blocks
        else ux.dim(f"subprocess blocks: {sub_blocks}")
    )
    click.echo(
        f"                {ux.dim(f'requests: {requests}')}  {err_text}  "
        f"{ux.dim(f'tool inspections: {inspections}')}  {block_text_tool}  "
        f"{block_text_sub}"
    )


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

    ux.section("Observability")

    if not destinations:
        click.echo(
            "    "
            + ux.dim("(none configured — run `defenseclaw setup observability add <preset>`)")
        )
        return

    for d in destinations:
        label = PRESETS[d.preset_id].display_name if d.preset_id in PRESETS else d.kind
        state = (
            ux._style("enabled", fg="green")
            if d.enabled
            else ux._style("disabled", fg="bright_black")
        )
        target_tag = "otel" if d.target == "otel" else "sink"
        click.echo(
            f"    {ux.bold(f'{d.name:<26s}')}{ux.dim(f'[{target_tag}]')} {state}"
            f"  {ux.dim('—')} {label}"
        )

        if d.target == "otel" and d.enabled:
            enabled_signals = [s for s, on in d.signals.items() if on]
            if enabled_signals:
                click.echo(
                    f"      {ux.dim('signals:')} {', '.join(sorted(enabled_signals))}"
                )
            if d.endpoint:
                click.echo(f"      {ux.dim('endpoint:')} {d.endpoint}")
        elif d.enabled and d.endpoint:
            click.echo(f"      {ux.dim('endpoint:')} {d.endpoint}")
