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
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help=(
        "Emit status as a JSON document (environment, scanners, enforcement, "
        "activity, and the full per-connector roster with effective mode). "
        "Config/DB-derived; no live /health counters."
    ),
)
@pass_ctx
def status(app: AppContext, as_json: bool) -> None:
    """Show DefenseClaw status.

    Displays environment, sandbox health, scanner availability,
    enforcement counts, and activity summary. On multi-connector installs
    it also lists the active connector roster with each peer's mode.

    ``--json`` emits the same information as a machine-readable document for
    automation and the TUI.
    """
    cfg = app.cfg

    # SU-13: machine-readable status for automation/TUI. Emitted before any
    # human rendering so the output is pure JSON.
    if as_json:
        import json

        click.echo(json.dumps(_status_payload(app), indent=2))
        return

    # Title block — `═` divider matches the legacy double-line look
    # but now scales to the title length and renders cyan-bold.
    click.echo()
    click.echo(ux._style("DefenseClaw Status", fg="cyan", bold=True))
    click.echo(ux._style("══════════════════", fg="cyan"))

    _status_row("Environment", cfg.environment)
    _status_row("Data dir", cfg.data_dir)
    _status_row("Config", f"{cfg.data_dir}/config.yaml")
    _status_row("Audit DB", cfg.audit_db)
    _status_row("Scope", _connector_scope_text(cfg))
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

    # N3: surface the active policy's scanner action overrides (data.json).
    # Only `policy show` exposed these before, so `status` was blind to a
    # policy that, say, downgrades a scanner surface to warn/allow. Empty for a
    # policy that declares none, so the common case renders nothing.
    overrides_summary = _scanner_overrides_summary(cfg)
    if overrides_summary:
        click.echo(f"    {ux.bold('overrides'.ljust(16))}{ux.dim(overrides_summary)}")

    # Counts from DB. The numeric labels stay tight-aligned to match
    # the legacy 16-char column; we color the labels and leave the
    # numbers in default fg so they stand out.
    if app.store:
        # SU-05: surface audit-DB errors instead of silently dropping the
        # Enforcement + Activity sections. The previous bare `except: pass`
        # made the output look complete when the DB was missing/locked/corrupt
        # — the operator saw neither counts nor any error. Render the section
        # headers with an explicit "unavailable" line on failure. status stays
        # exit-0 (it is an informational command parsed by the TUI/scripts and
        # should not hard-fail on a transient DB read); the error is visible.
        try:
            counts = app.store.get_counts()
        except Exception as exc:  # noqa: BLE001 — surface the error, don't hide it
            counts = None
            db_error = str(exc)
        else:
            db_error = ""

        ux.section("Enforcement")
        if counts is not None:
            for label, val in (
                ("Blocked skills", counts.blocked_skills),
                ("Allowed skills", counts.allowed_skills),
                ("Blocked MCPs", counts.blocked_mcps),
                ("Allowed MCPs", counts.allowed_mcps),
            ):
                click.echo(f"    {_label((label + ':').ljust(16))} {val}")
        else:
            click.echo(
                f"    {ux._style('unavailable', fg='yellow')} "
                f"{ux.dim(f'(audit DB error: {db_error})')}"
            )

        ux.section("Activity")
        if counts is not None:
            for label, val in (
                ("Total scans", counts.total_scans),
                ("Active alerts", counts.alerts),
            ):
                click.echo(f"    {_label((label + ':').ljust(16))} {val}")
        else:
            click.echo(
                f"    {ux._style('unavailable', fg='yellow')} "
                f"{ux.dim(f'(audit DB error: {db_error})')}"
            )

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

    # Render the "Agents" roster uniformly — one section that lists every
    # active connector with its effective mode (and, when the sidecar is up,
    # live /health counters per connector). The same code path drives a
    # single-connector install (one row) and a fan-out install (N rows), so the
    # output never branches on connector count.
    if client.is_running():
        _status_row("Sidecar", ux._style("running", fg="green"))
        _print_agents(cfg, bind, cfg.gateway.api_port)
        hint(
            "Dashboard:     defenseclaw alerts",
            "Health check:  defenseclaw doctor",
            "Operator overview: defenseclaw status | Sidecar subsystems: defenseclaw-gateway status",
        )
    else:
        _status_row("Sidecar", ux._style("not running", fg="yellow"))
        # Even when the sidecar is down, show the *configured* agents
        # so operators know what `start` will spin up.
        _print_agents(cfg)
        hint(
            "Start sidecar:  defenseclaw-gateway start",
            "Operator overview: defenseclaw status | Sidecar subsystems: defenseclaw-gateway status",
        )


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
    "openhands": "OpenHands",
    "antigravity": "Antigravity",
    "opencode": "OpenCode",
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


def _connector_scope_text(cfg) -> str:
    workspace = ""
    resolver = getattr(cfg, "connector_workspace_dir", None)
    if callable(resolver):
        try:
            workspace = resolver()
        except Exception:
            workspace = ""
    if not workspace:
        workspace = (getattr(getattr(cfg, "claw", None), "workspace_dir", "") or "").strip()
    if workspace:
        return f"workspace ({workspace})"
    return "global user config"


def _print_agents(cfg, host: str | None = None, port: int | None = None) -> None:
    """Render the "Agents" roster as one section, for ANY connector count.

    Config-derived (``active_connectors()`` + ``GuardrailConfig.effective_mode``)
    so it lists every active connector and its effective mode regardless of
    sidecar state. The exact same section is rendered whether the install has
    zero, one, or many connectors — there is no separate single-connector
    ``Agent:`` block. ``active_connectors()`` returns one name on a
    single-connector install and N on a fan-out install, so the same loop
    drives both.

    When ``host``/``port`` are supplied and the sidecar is up, *every*
    connector is annotated with its own live state and counters (read from
    ``/health`` ``connectors[]``). There is no privileged "primary" — each
    active agent reports its own tally.
    """
    try:
        actives = [c for c in (cfg.active_connectors() if hasattr(cfg, "active_connectors") else []) if c]
    except Exception:
        actives = []
    if not actives:
        # Uniform empty state — same "Agents" section whether the install has
        # zero, one, or many connectors (no separate single-connector block).
        _status_row("Agents", ux.dim("(no active connector)"))
        return

    health_map = _fetch_health_connectors(host, port) if host and port else {}

    gc = getattr(cfg, "guardrail", None)

    def _is_enabled(name: str) -> bool:
        # An explicit ``enabled: false`` override (set by
        # ``guardrail disable --connector X``) means the connector was torn
        # down and is no longer enforcing. Default True so single-connector
        # installs and never-disabled connectors keep reading as active.
        if gc is None or not hasattr(gc, "effective_enabled"):
            return True
        try:
            return bool(gc.effective_enabled(name))
        except Exception:
            return True

    enabled_count = sum(1 for c in actives if _is_enabled(c))
    disabled_count = len(actives) - enabled_count
    header = f"{enabled_count} active"
    if disabled_count:
        header += f", {disabled_count} disabled"
    _status_row("Agents", header)
    for conn in actives:
        mode = ""
        if gc is not None and hasattr(gc, "effective_mode"):
            try:
                mode = (gc.effective_mode(conn) or "").strip()
            except Exception:
                mode = ""
        friendly = _friendly_connector_name(conn)
        if not _is_enabled(conn):
            # Operator-disabled: hooks were torn down, so there is no live
            # health entry. Mark it explicitly rather than letting it fall to
            # the dim "not reporting" branch, which is indistinguishable from a
            # connector the sidecar simply hasn't surfaced yet.
            disabled_label = ux._style("DISABLED", fg="yellow")
            disabled_text = ux.dim(f"{friendly} ({conn}) — mode={mode or '?'}")
            click.echo(f"                {disabled_text} — {disabled_label}")
            continue
        hc = health_map.get(conn.strip().lower())
        if hc:
            suffix = _connector_state_verb(str(hc.get("state") or ""))
            click.echo(f"                {friendly} ({conn}) — mode={mode or '?'}{suffix}")
            _print_agent_counters(hc, indent="                  ")
        else:
            dim_text = ux.dim(f"{friendly} ({conn}) — mode={mode or '?'}")
            click.echo(f"                {dim_text}")


def _fetch_health(host: str | None, port: int | None) -> dict | None:
    """Return the parsed ``/health`` document (or ``None``).

    Failures are intentionally swallowed — the sidecar may have just come up,
    or the operator may be on an old gateway build. We never want
    ``defenseclaw status`` to error because of an optional UX line.
    """
    if not host or not port:
        return None
    try:
        import json as _json
        import urllib.request as _urlreq

        url = f"http://{host}:{port}/health"
        req = _urlreq.Request(url)
        with _urlreq.urlopen(req, timeout=3) as resp:  # noqa: S310 — loopback only
            data = _json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _fetch_health_connectors(host: str | None, port: int | None) -> dict[str, dict]:
    """Map ``connector-name`` → its ``ConnectorHealth`` from ``/health``.

    Reads the per-connector ``connectors[]`` array so every active connector
    can render its own live counters. Falls back to folding in the singular
    ``connector`` field so an older gateway (which only reports the primary)
    still surfaces at least that connector's counters.
    """
    data = _fetch_health(host, port)
    if not isinstance(data, dict):
        return {}
    out: dict[str, dict] = {}
    conns = data.get("connectors")
    if isinstance(conns, list):
        for c in conns:
            if isinstance(c, dict):
                nm = str(c.get("name") or "").strip().lower()
                if nm:
                    out[nm] = c
    single = data.get("connector")
    if isinstance(single, dict):
        nm = str(single.get("name") or "").strip().lower()
        if nm and nm not in out:
            out[nm] = single
    return out


def _connector_state_verb(state: str) -> str:
    """Format a connector state as a colored ``— STATE`` suffix.

    RUNNING green, anything else yellow (dormant / starting / etc.). Empty
    state yields an empty string so callers can append unconditionally.
    """
    s = (state or "").strip().upper()
    if not s:
        return ""
    if s in ("RUNNING", "ACTIVE", "READY", "UP"):
        return " — " + ux._style(s, fg="green")
    return " — " + ux._style(s, fg="yellow")


def _print_agent_counters(conn: dict, indent: str = "                ") -> None:
    """Print the tool-inspection + request/blocks counter lines for a connector."""
    tool_mode = str(conn.get("tool_inspection_mode") or "").strip()
    sub_policy = str(conn.get("subprocess_policy") or "").strip()
    if tool_mode or sub_policy:
        click.echo(
            f"{indent}{ux.dim('tool inspection:')} {tool_mode or 'n/a'}    "
            f"{ux.dim('subprocess:')} {sub_policy or 'n/a'}"
        )

    requests = int(conn.get("requests") or 0)
    errors = int(conn.get("errors") or 0)
    inspections = int(conn.get("tool_inspections") or 0)
    tool_blocks = int(conn.get("tool_blocks") or 0)
    sub_blocks = int(conn.get("subprocess_blocks") or 0)
    # Errors get colored when non-zero so eyes catch them first.
    err_text = ux._style(f"errors: {errors}", fg="red", bold=True) if errors else ux.dim(f"errors: {errors}")
    block_text_tool = (
        ux._style(f"tool blocks: {tool_blocks}", fg="yellow") if tool_blocks else ux.dim(f"tool blocks: {tool_blocks}")
    )
    block_text_sub = (
        ux._style(f"subprocess blocks: {sub_blocks}", fg="yellow")
        if sub_blocks
        else ux.dim(f"subprocess blocks: {sub_blocks}")
    )
    click.echo(
        f"{indent}{ux.dim(f'requests: {requests}')}  {err_text}  "
        f"{ux.dim(f'tool inspections: {inspections}')}  {block_text_tool}  "
        f"{block_text_sub}"
    )


def _print_observability_status(cfg) -> None:
    """Enumerate every observability destination — gateway OTel exporter
    plus every ``audit_sinks`` entry — in a single section.

    The old ``_print_splunk_integration_status`` was hard-coded to Splunk
    hydration and a single exporter and
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
        click.echo("    " + ux.dim("(none configured — run `defenseclaw setup observability add <preset>`)"))
        return

    for d in destinations:
        label = PRESETS[d.preset_id].display_name if d.preset_id in PRESETS else d.kind
        state = ux._style("enabled", fg="green") if d.enabled else ux._style("disabled", fg="bright_black")
        target_tag = "otel" if d.target == "otel" else "sink"
        click.echo(f"    {ux.bold(f'{d.name:<26s}')}{ux.dim(f'[{target_tag}]')} {state}  {ux.dim('—')} {label}")

        if d.target == "otel" and d.enabled:
            enabled_signals = [s for s, on in d.signals.items() if on]
            if enabled_signals:
                click.echo(f"      {ux.dim('signals:')} {', '.join(sorted(enabled_signals))}")
            if d.endpoint:
                click.echo(f"      {ux.dim('endpoint:')} {d.endpoint}")
        elif d.enabled and d.endpoint:
            click.echo(f"      {ux.dim('endpoint:')} {d.endpoint}")


def _scanner_overrides_summary(cfg) -> str:
    """One-line summary of the active policy's scanner action overrides (N3).

    Reads the active policy's synced ``data.json`` (the same file ``policy
    show`` reads) and formats its ``scanner_overrides`` block, e.g.
    ``mcp: MEDIUM install=block, file=quarantine | plugin: HIGH ...``. Returns
    ``""`` when the policy declares none or the file is unreadable, so default
    installs and missing-policy installs render nothing.
    """
    try:
        from defenseclaw.enforce.admission import _read_policy_data
        from defenseclaw.tui.services.overview_state import (
            format_scanner_overrides_summary,
        )

        data = _read_policy_data(getattr(cfg, "policy_dir", "") or "")
    except Exception:  # noqa: BLE001 — the override line is purely informational.
        return ""
    if not isinstance(data, dict):
        return ""
    overrides = data.get("scanner_overrides", {})
    flat: list[tuple[str, str, str, str]] = []
    if isinstance(overrides, dict):
        for scanner_type, sevs in overrides.items():
            if not isinstance(sevs, dict):
                continue
            for severity, surface_actions in sevs.items():
                if not isinstance(surface_actions, dict):
                    continue
                for surface in ("install", "file", "runtime"):
                    action = surface_actions.get(surface)
                    if action:
                        flat.append(
                            (str(scanner_type), str(severity), surface, str(action))
                        )
    return format_scanner_overrides_summary(tuple(flat))


def _scanner_status_map(cfg) -> dict[str, str]:
    """Scanner availability as a JSON-friendly map (mirrors the text Scanners
    section): ``installed`` / ``not_found`` / ``built-in``."""
    out: dict[str, str] = {}
    for name, binary in (
        ("skill-scanner", cfg.scanners.skill_scanner.binary),
        ("mcp-scanner", cfg.scanners.mcp_scanner.binary),
        ("codeguard", "built-in"),
    ):
        if binary == "built-in":
            out[name] = "built-in"
        else:
            out[name] = "installed" if shutil.which(binary) else "not_found"
    return out


def _connector_roster(cfg) -> list[dict]:
    """Config-derived connector roster (name / friendly / mode / enabled).

    Shares the ``active_connectors()`` + ``effective_mode`` / ``effective_enabled``
    derivation used by the human ``Agents`` section (minus the live /health
    annotations), so ``status --json`` and the text output never disagree. It is
    phantom-safe: ``active_connectors()`` returns ``[]`` on an unconfigured
    install, so the roster is empty rather than a fabricated ``openclaw``.
    """
    try:
        actives = [c for c in (cfg.active_connectors() if hasattr(cfg, "active_connectors") else []) if c]
    except Exception:
        actives = []
    gc = getattr(cfg, "guardrail", None)

    def _mode(name: str) -> str:
        if gc is not None and hasattr(gc, "effective_mode"):
            try:
                return (gc.effective_mode(name) or "").strip()
            except Exception:
                return ""
        return ""

    def _enabled(name: str) -> bool:
        if gc is None or not hasattr(gc, "effective_enabled"):
            return True
        try:
            return bool(gc.effective_enabled(name))
        except Exception:
            return True

    return [
        {
            "name": c,
            "friendly": _friendly_connector_name(c),
            "mode": _mode(c),
            "enabled": _enabled(c),
        }
        for c in actives
    ]


def _status_payload(app) -> dict:
    """Build the machine-readable status document for ``status --json`` (SU-13).

    Config + audit-DB derived only (no live ``/health`` call) so the JSON is
    fast and reliable for automation even when the sidecar is down. Includes a
    cheap ``sidecar.running`` probe but not per-connector live counters.
    SU-05: audit-DB read failures surface as ``enforcement``/``activity`` =
    ``null`` plus an ``audit_db_error`` field, never a silent drop.
    """
    cfg = app.cfg
    payload: dict = {
        "environment": cfg.environment,
        "data_dir": cfg.data_dir,
        "config": f"{cfg.data_dir}/config.yaml",
        "audit_db": cfg.audit_db,
        "scope": _connector_scope_text(cfg),
        "sandbox": {"available": bool(shutil.which(cfg.openshell.binary))},
        "scanners": _scanner_status_map(cfg),
        "connectors": _connector_roster(cfg),
    }

    if app.store:
        try:
            counts = app.store.get_counts()
        except Exception as exc:  # noqa: BLE001 — surface, don't hide (SU-05)
            payload["enforcement"] = None
            payload["activity"] = None
            payload["audit_db_error"] = str(exc)
        else:
            payload["enforcement"] = {
                "blocked_skills": counts.blocked_skills,
                "allowed_skills": counts.allowed_skills,
                "blocked_mcps": counts.blocked_mcps,
                "allowed_mcps": counts.allowed_mcps,
            }
            payload["activity"] = {
                "total_scans": counts.total_scans,
                "active_alerts": counts.alerts,
            }
    else:
        payload["enforcement"] = None
        payload["activity"] = None

    bind = "127.0.0.1"
    if cfg.openshell.is_standalone() and cfg.guardrail.host not in ("", "localhost", "127.0.0.1"):
        bind = cfg.guardrail.host
    try:
        from defenseclaw.gateway import OrchestratorClient

        client = OrchestratorClient(
            host=bind,
            port=cfg.gateway.api_port,
            token=cfg.gateway.resolved_token(),
        )
        running = bool(client.is_running())
    except Exception:
        running = False
    payload["sidecar"] = {"running": running}

    return payload
