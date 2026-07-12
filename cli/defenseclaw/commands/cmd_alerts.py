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

"""defenseclaw alerts — View and manage security alerts.

P3-#20 collapsed the legacy Textual TUI here in favour of the Go-based
panel shipped with ``defenseclaw tui`` (internal/tui/alerts.go). This
module now renders a plain, pipe-friendly table by default and supports
``--show N`` for scripted deep dives. The ``--tui`` flag is retained as
a no-op for backward compatibility with muscle memory and older docs;
it prints a deprecation notice and falls through to the table so
existing aliases/scripts keep working.
"""

from __future__ import annotations

import json
import uuid

import click

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx

# ---------------------------------------------------------------------------
# Table view helpers
# ---------------------------------------------------------------------------

_OVERHEAD   = 19
_W_IDX      = 2
_W_SEV      = 8
_W_TIME     = 5
_W_ACTION   = 17
_W_TARGET   = 11
_W_FIXED    = _W_IDX + _W_SEV + _W_TIME + _W_ACTION + _W_TARGET  # = 43

_SEV_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _trunc(s: str, width: int) -> str:
    s = s.strip()
    if len(s) <= width:
        return s
    return s[: width - 1] + "…"


def _trunc_path(s: str, width: int) -> str:
    s = s.strip()
    if len(s) <= width:
        return s
    parts = s.rstrip("/").split("/")
    for n in range(1, len(parts) + 1):
        candidate = "/".join(parts[-n:])
        if len(candidate) + 2 <= width:
            return "…/" + candidate
    tail = parts[-1]
    if len(tail) + 2 <= width:
        return "…/" + tail
    return "…" + s[-(width - 1):]


def _humanize_details(raw: str) -> str:
    if not raw:
        return ""
    tokens = raw.split()
    if not any("=" in t for t in tokens):
        return raw
    kv: dict[str, str] = {}
    plain: list[str] = []
    for tok in tokens:
        if "=" in tok:
            k, v = tok.split("=", 1)
            kv[k] = v
        else:
            plain.append(tok)
    parts: list[str] = []
    if "host" in kv and "port" in kv:
        parts.append(f"{kv.pop('host')}:{kv.pop('port')}")
    elif "port" in kv:
        parts.append(f":{kv.pop('port')}")
    for key in ("mode", "environment", "status", "protocol", "scanner_mode"):
        if key in kv:
            parts.append(kv.pop(key))
    if "model" in kv:
        parts.append(kv.pop("model").split("/")[-1])
    for key in ("max_severity", "scanner", "findings"):
        kv.pop(key, None)
    for k, v in kv.items():
        parts.append(f"{k}={v}")
    parts.extend(plain)
    return " ".join(parts)


def _findings_json(findings: list[dict], width: int) -> str:
    suffix = "…"
    close = "]"
    parts: list[str] = []
    for f in findings:
        entry = json.dumps({"severity": f["severity"], "title": f["title"]}, separators=(",", ":"))
        candidate = "[" + ",".join(parts + [entry]) + close
        if len(candidate) > width:
            if parts:
                trunc = "[" + ",".join(parts) + "," + suffix
                if len(trunc) <= width:
                    return trunc
            full = json.dumps(
                [{"severity": f["severity"], "title": f["title"]} for f in findings],
                separators=(",", ":"),
            )
            return _trunc(full, width)
        parts.append(entry)
    return "[" + ",".join(parts) + close


def _kv(details: str) -> dict[str, str]:
    return dict(tok.split("=", 1) for tok in (details or "").split() if "=" in tok)


# When --connector is set, scan a generous window of recent alerts so the
# filter can surface up to --limit matches even when other connectors
# dominate the most-recent rows. Bounded so a huge audit DB stays responsive.
_CONNECTOR_SCAN_POOL = 2000


def _event_connector(event) -> str:
    """Connector attributed to an alert, from its ``connector=`` kv field.

    Mirrors the TUI Alerts panel (``parse_kv_details(...).get("connector")``)
    so CLI and TUI agree on attribution. Gateway-global alerts (e.g.
    ``sink-failure``) carry no connector and return ""."""
    return _kv(event.details or "").get("connector", "").lower()


def _filter_by_connector(alert_list: list, connector: str | None) -> list:
    """Keep only alerts whose connector matches ``connector`` (substring,
    case-insensitive — same match rule as the TUI ``connector:`` token).

    An empty/None ``connector`` is a no-op so single-connector and unfiltered
    invocations behave exactly as before."""
    needle = (connector or "").strip().lower()
    if not needle:
        return alert_list
    return [e for e in alert_list if needle in _event_connector(e)]


def _render_table(alert_list: list, store, connector: str | None = None) -> None:
    """Plain Rich table — the single renderer since the Textual TUI
    was retired in P3-#20. Kept in a helper so the deprecated
    ``--tui`` flag can fall through here without duplicating the
    column/width logic."""
    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table

    console = Console()
    term_width = console.size.width
    w_details = max(11, term_width - _OVERHEAD - _W_FIXED)

    scope = f" — connector={connector}" if (connector or "").strip() else ""
    table = Table(
        title=f"Security Alerts (last {len(alert_list)}){scope}",
        caption=(
            "Run [bold]defenseclaw alerts --show #[/bold] for full details, "
            "or [bold]defenseclaw tui[/bold] for the interactive Alerts panel."
        ),
        show_lines=False,
    )
    table.add_column("#",         no_wrap=True)
    table.add_column("Severity",  style="bold", no_wrap=True)
    table.add_column("Time",      no_wrap=True)
    table.add_column("Action",    no_wrap=True)
    table.add_column("Target",    no_wrap=True)
    table.add_column("Details [--show #]", no_wrap=True)

    sev_styles = {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "cyan",
    }

    for idx, e in enumerate(alert_list, 1):
        sev_style = sev_styles.get(e.severity, "")
        sev_cell = f"[{sev_style}]{e.severity}[/{sev_style}]" if sev_style else e.severity
        ts     = e.timestamp.strftime("%H:%M") if e.timestamp else ""
        action = _trunc(e.action or "", _W_ACTION)
        target = _trunc_path(e.target or "", _W_TARGET)
        kv_map = _kv(e.details or "")
        scanner_name = kv_map.get("scanner", "")
        if e.action == "scan" and scanner_name and e.target:
            findings = store.get_findings_for_target(e.target, scanner_name)
            raw_details = _findings_json(findings, w_details) if findings else _humanize_details(e.details or "")
        else:
            raw_details = _humanize_details(e.details or "")
        details = _trunc(raw_details, w_details)
        table.add_row(
            escape(str(idx)), sev_cell, ts,
            escape(action), escape(target), escape(details),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# CLI command group (default = table view)
# ---------------------------------------------------------------------------

@click.group("alerts", invoke_without_command=True)
@click.option("-n", "--limit", default=25, help="Number of alerts to load")
@click.option("--show", "show_idx", default=None, type=int,
              help="Print full details for alert # and exit (non-interactive)")
@click.option(
    "--connector",
    "connector",
    default=None,
    help=(
        "Filter alerts by connector attribution (optional on any install). "
        "Only show alerts attributed to this connector (e.g. codex, "
        "claudecode, antigravity). Matches the per-event connector= field, "
        "mirroring the TUI's `connector:` search token."
    ),
)
@click.option(
    "--tui/--no-tui",
    default=False,
    help=(
        "Deprecated: the interactive TUI moved to `defenseclaw tui` in P3-#20. "
        "This flag now prints a deprecation notice and falls back to the table."
    ),
)
@click.pass_context
def alerts(
    ctx: click.Context,
    limit: int,
    show_idx: int | None,
    connector: str | None,
    tui: bool,
) -> None:
    """View and manage security alerts."""
    if ctx.invoked_subcommand is not None:
        return
    app = ctx.find_object(AppContext)
    if app is None:
        raise click.ClickException("internal error: AppContext missing")
    _alerts_default(app, limit, show_idx, tui, connector)


def _alerts_default(
    app: AppContext,
    limit: int,
    show_idx: int | None,
    tui: bool,
    connector: str | None = None,
) -> None:
    """View security alerts as a table (legacy ``defenseclaw alerts``)."""
    if not app.store:
        ux.warn("No audit store available. Run 'defenseclaw init' first.")
        return

    needle = (connector or "").strip()
    if needle:
        # Scan a wider window, then keep up to --limit matching the connector.
        pool = app.store.list_alerts(max(limit, _CONNECTOR_SCAN_POOL))
        alert_list = _filter_by_connector(pool, needle)[:limit]
    else:
        alert_list = app.store.list_alerts(limit)

    if not alert_list:
        if needle:
            ux.ok(
                f"No alerts from connector '{needle}' in the last "
                f"{max(limit, _CONNECTOR_SCAN_POOL)} events."
            )
        else:
            ux.ok("No alerts. All clear.")
        return

    if show_idx is not None:
        if show_idx < 1 or show_idx > len(alert_list):
            ux.err(f"alert #{show_idx} not found (1–{len(alert_list)})")
            raise SystemExit(1)
        e = alert_list[show_idx - 1]
        sev_fg = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "white",
        }.get(e.severity, "bright_black")
        click.echo(f"{ux.bold(f'Alert #{show_idx}')}")
        click.echo(f"  {ux._style('Severity:', fg='bright_black', bold=True)}  ", nl=False)
        click.echo(ux._style(e.severity, fg=sev_fg, bold=e.severity in ("CRITICAL", "HIGH")))
        ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else ""
        click.echo(f"  {ux._style('Timestamp:', fg='bright_black', bold=True)} {ts}")
        click.echo(f"  {ux._style('Action:', fg='bright_black', bold=True)}    {e.action}")
        if e.target:
            click.echo(f"  {ux._style('Target:', fg='bright_black', bold=True)}    {e.target}")
        if e.details:
            human = _humanize_details(e.details)
            if human:
                click.echo(f"  {ux._style('Details:', fg='bright_black', bold=True)}   {human}")
        kv_map = _kv(e.details or "")
        scanner_name = kv_map.get("scanner", "")
        if e.action == "scan" and scanner_name and e.target:
            findings = app.store.get_findings_for_target(e.target, scanner_name)
            if findings:
                click.echo(f"  {ux.bold('Findings:')}")
                for f in findings:
                    tag = f"[{f['severity']}]"
                    sev_tag_fg = {
                        "CRITICAL": "red",
                        "HIGH": "red",
                        "MEDIUM": "yellow",
                        "LOW": "cyan",
                        "INFO": "bright_black",
                    }.get(f["severity"], "white")
                    click.echo(f"    {ux._style(tag, fg=sev_tag_fg, bold=True)}", nl=False)
                    loc = f"  {f['location']}" if f["location"] else ""
                    click.echo(f" {f['title']}{loc}")
        return

    if tui:
        ux.warn(
            "`defenseclaw alerts --tui` has been retired. "
            "Launch `defenseclaw tui` and press 2 for the Alerts panel.",
        )

    _render_table(alert_list, app.store, connector=needle)


@alerts.command("acknowledge")
@click.option(
    "--severity",
    type=click.Choice(["all", "CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    default="all",
    show_default=True,
    help="Limit which severities are acknowledged.",
)
@pass_ctx
def alerts_acknowledge(app: AppContext, severity: str) -> None:
    """Mark alerts acknowledged through the canonical protected-state API."""
    n = _set_alert_disposition(app, severity, "acknowledged")
    ux.ok(f"Acknowledged {n} alert(s).")


@alerts.command("dismiss")
@click.option(
    "--severity",
    type=click.Choice(["all", "CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    default="all",
    show_default=True,
    help="Limit which severities are cleared from the active list.",
)
@pass_ctx
def alerts_dismiss(app: AppContext, severity: str) -> None:
    """Dismiss alerts through the canonical protected-state API."""
    n = _set_alert_disposition(app, severity, "dismissed")
    ux.ok(f"Dismissed {n} alert(s) from the active list.")


def _set_alert_disposition(app: AppContext, severity: str, disposition: str) -> int:
    if app.cfg is None or getattr(app.cfg, "_source_config_version", None) != 8:
        raise click.ClickException("Configuration schema v8 is required — run 'defenseclaw upgrade' first.")
    from defenseclaw.gateway import OrchestratorClient
    from defenseclaw.logger import _gateway_api_host

    token = app.cfg.gateway.resolved_token()
    if not token:
        raise click.ClickException("Gateway authentication is unavailable; start or reconfigure the v8 gateway.")
    client = OrchestratorClient(
        host=_gateway_api_host(app.cfg),
        port=int(app.cfg.gateway.api_port),
        timeout=10,
        token=token,
    )
    try:
        response = client.set_alert_disposition(
            operation_id=f"alert-review-{uuid.uuid4().hex}",
            disposition=disposition,
            severity=severity,
        )
    except Exception as exc:
        raise click.ClickException("Canonical alert disposition was not confirmed by the gateway.") from exc
    finally:
        client.close()
    return int(response.get("applied", 0)) + int(response.get("no_change", 0))
