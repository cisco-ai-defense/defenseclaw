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

import click

from defenseclaw.audit_actions import ACTION_ACK_ALERTS, ACTION_DISMISS_ALERTS
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


def _render_table(alert_list: list, store) -> None:
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

    table = Table(
        title=f"Security Alerts (last {len(alert_list)})",
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
    "--tui/--no-tui",
    default=False,
    help=(
        "Deprecated: the interactive TUI moved to `defenseclaw tui` in P3-#20. "
        "This flag now prints a deprecation notice and falls back to the table."
    ),
)
@click.pass_context
def alerts(ctx: click.Context, limit: int, show_idx: int | None, tui: bool) -> None:
    """View and manage security alerts."""
    if ctx.invoked_subcommand is not None:
        return
    app = ctx.find_object(AppContext)
    if app is None:
        raise click.ClickException("internal error: AppContext missing")
    _alerts_default(app, limit, show_idx, tui)


def _alerts_default(app: AppContext, limit: int, show_idx: int | None, tui: bool) -> None:
    """View security alerts as a table (legacy ``defenseclaw alerts``)."""
    if not app.store:
        click.echo("No audit store available. Run 'defenseclaw init' first.")
        return

    alert_list = app.store.list_alerts(limit)

    if not alert_list:
        click.echo("No alerts. All clear.")
        return

    if show_idx is not None:
        if show_idx < 1 or show_idx > len(alert_list):
            click.echo(f"error: alert #{show_idx} not found (1–{len(alert_list)})", err=True)
            raise SystemExit(1)
        e = alert_list[show_idx - 1]
        sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(e.severity, "white")
        click.echo(f"Alert #{show_idx}")
        click.echo("  Severity:  ", nl=False)
        click.secho(e.severity, fg=sev_color)
        click.echo(f"  Timestamp: {e.timestamp.strftime('%Y-%m-%d %H:%M:%S') if e.timestamp else ''}")
        click.echo(f"  Action:    {e.action}")
        if e.target:
            click.echo(f"  Target:    {e.target}")
        if e.details:
            human = _humanize_details(e.details)
            if human:
                click.echo(f"  Details:   {human}")
        kv_map = _kv(e.details or "")
        scanner_name = kv_map.get("scanner", "")
        if e.action == "scan" and scanner_name and e.target:
            findings = app.store.get_findings_for_target(e.target, scanner_name)
            if findings:
                click.echo("  Findings:")
                sev_colors = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}
                for f in findings:
                    color = sev_colors.get(f["severity"], "white")
                    click.secho(f"    [{f['severity']}]", fg=color, nl=False)
                    loc = f"  {f['location']}" if f["location"] else ""
                    click.echo(f" {f['title']}{loc}")
        return

    if tui:
        click.echo(
            "note: `defenseclaw alerts --tui` has been retired. "
            "Launch `defenseclaw tui` and press 2 for the Alerts panel.",
            err=True,
        )

    _render_table(alert_list, app.store)


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
    """Mark alerts as acknowledged (downgrades severity to ACK in the audit DB)."""
    if not app.store:
        raise click.ClickException("No audit store — run 'defenseclaw init' first.")
    before = {"open_severities": severity}
    n = app.store.acknowledge_alerts("all" if severity == "all" else severity)
    after = {"acknowledged_rows": n}
    if app.logger:
        app.logger.log_activity(
            actor="cli:operator",
            action=ACTION_ACK_ALERTS,
            target_type="alert",
            target_id="audit_events",
            before=before,
            after=after,
            diff=[{"path": "/alerts", "op": "replace", "before": before, "after": after}],
        )
    click.echo(f"Acknowledged {n} alert(s).")


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
    """Dismiss alerts from the active operator view (same DB update as acknowledge)."""
    if not app.store:
        raise click.ClickException("No audit store — run 'defenseclaw init' first.")
    before = {"visible_severities": severity}
    n = app.store.dismiss_alerts_visible("all" if severity == "all" else severity)
    after = {"cleared_rows": n}
    if app.logger:
        app.logger.log_activity(
            actor="cli:operator",
            action=ACTION_DISMISS_ALERTS,
            target_type="alert",
            target_id="audit_events",
            before=before,
            after=after,
            diff=[{"path": "/alerts", "op": "replace", "before": before, "after": after}],
        )
    click.echo(f"Dismissed {n} alert(s) from the active list.")
