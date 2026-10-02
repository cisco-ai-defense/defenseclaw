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

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click

from defenseclaw import ux
from defenseclaw.config import config_path, legacy_standalone_configured
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.openclaw_presence import openclaw_implied_but_not_installed
from defenseclaw.scanner_binary import resolve_scanner_binary

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

# Reuse the established operator-evidence staleness semantics from the TUI's
# Doctor cache.  This is a presentation freshness bound, not a transport or
# readiness timeout: an idle/stopped OpenCode client simply becomes
# unverified, and is never guessed to be running with ``--pure``.
_OPENCODE_HEARTBEAT_FRESHNESS = timedelta(minutes=15)
_OPENCODE_CLOCK_SKEW_TOLERANCE = timedelta(minutes=5)
_OPENCODE_REGISTRATION_SOURCES = frozenset({"manual", "automatic"})
_RUNTIME_HEALTHY_STATES = frozenset({"running", "active", "ready", "up", "healthy", "ok"})


# Only the standalone profile reports its profile in `status`. The Secure
# Client and unmanaged output (text rows and JSON keys) stays exactly as it
# was before enterprise profiles existed.
_STANDALONE_ENTERPRISE_PROFILE = "standalone"


def _enterprise_profile(cfg) -> str:
    """Return the managed_enterprise profile, or "" for unmanaged installs.

    Mirrors internal/managed/profile.go: the service pin wins, then the
    config's ``enterprise.profile``, then the per-OS default (standalone on
    Linux, secure_client elsewhere). Read-only; never raises.
    """
    if str(getattr(cfg, "deployment_mode", "") or "").strip().lower() != "managed_enterprise":
        return ""
    pinned = os.environ.get("DEFENSECLAW_ENTERPRISE_PROFILE", "").strip().lower()
    if pinned:
        return pinned
    configured = ""
    try:
        import yaml

        with open(config_path()) as handle:
            raw = yaml.safe_load(handle) or {}
        enterprise = raw.get("enterprise") if isinstance(raw, dict) else None
        if isinstance(enterprise, dict):
            configured = str(enterprise.get("profile") or "").strip().lower()
    except (OSError, ValueError, ImportError):
        configured = ""
    except Exception:  # noqa: BLE001 - status must never fail on a malformed config
        configured = ""
    if configured:
        return configured
    return _default_enterprise_profile()


def _default_enterprise_profile() -> str:
    """Return the per-OS default profile: standalone on Linux, secure_client elsewhere."""
    import sys

    return "standalone" if sys.platform.startswith("linux") else "secure_client"


def _opencode_registration_source_valid(value: object) -> bool:
    """Accept only an exact source emitted by gateway registration."""

    return isinstance(value, str) and value in _OPENCODE_REGISTRATION_SOURCES


def _runtime_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _opencode_runtime_truth(
    row: dict | None,
    *,
    gateway_started_at: object = "",
    gateway_available: bool = True,
    now: datetime | None = None,
) -> tuple[str, str]:
    """Return the bounded OpenCode runtime state and operator detail.

    The connector row is accepted only from the authenticated, profile-bound
    status document at each caller.  A heartbeat proves that the managed
    plugin loaded in the current gateway generation; freshness prevents an
    old client session from leaving the configured adapter green forever.
    OpenCode exposes no authenticated ``--pure`` signal, so this helper never
    infers that reason from absent runtime evidence.
    """

    if not gateway_available:
        return "degraded", "runtime load unverified: authenticated gateway status is unavailable"
    if not isinstance(row, dict):
        return "degraded", "runtime load unverified: authenticated status has no OpenCode connector row"

    raw_state = str(row.get("state") or "").strip().lower() or "unknown"
    if raw_state in {"stopped", "offline", "down", "disabled"}:
        return raw_state, f"OpenCode runtime reports {raw_state}; managed bridge load is not asserted"

    if not _opencode_registration_source_valid(row.get("source")):
        return (
            "degraded",
            "runtime load unverified: authenticated status does not prove a current "
            "manual or automatic OpenCode registration",
        )

    heartbeat_raw = row.get("load_heartbeat_at")
    if not isinstance(heartbeat_raw, str) or not heartbeat_raw.strip():
        # OpenCode reports the load when it starts, so a closed OpenCode is
        # idle, not degraded (GAP-1632; doctor shows it as a skip, GAP-1565).
        return (
            "idle",
            "no authenticated load heartbeat yet: OpenCode has not loaded the plugin since the "
            "gateway started, which is normal while OpenCode is closed",
        )
    heartbeat = _runtime_timestamp(heartbeat_raw)
    if heartbeat is None:
        return "degraded", "runtime load unverified: authenticated load heartbeat is malformed"

    gateway_started = _runtime_timestamp(gateway_started_at)
    if gateway_started is None:
        return "degraded", "runtime load unverified: gateway generation timestamp is missing or malformed"
    if heartbeat < gateway_started:
        return "degraded", "runtime load unverified: load heartbeat predates the current gateway generation"

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    else:
        current = current.astimezone(timezone.utc)
    age = current - heartbeat
    if age < -_OPENCODE_CLOCK_SKEW_TOLERANCE:
        return "degraded", "runtime load unverified: authenticated load heartbeat is ahead of the local clock"
    if age > _OPENCODE_HEARTBEAT_FRESHNESS:
        return (
            "degraded",
            "runtime load unverified: authenticated load heartbeat is stale "
            f"(last received at {heartbeat_raw.strip()}); "
            "OpenCode may be stopped or idle",
        )
    if raw_state not in _RUNTIME_HEALTHY_STATES:
        return raw_state, f"OpenCode runtime reports {raw_state}; authenticated load heartbeat is fresh"
    return raw_state, f"managed bridge authenticated load heartbeat is fresh (received at {heartbeat_raw.strip()})"


def _omnigent_effective_runtime_state(cfg, state: str) -> tuple[str, str]:
    """Project adapter liveness through passive OmniGent policy readiness."""

    raw_state = str(state or "")
    if raw_state.strip().lower() not in {"running", "active", "ready", "up"}:
        return raw_state, ""
    try:
        from defenseclaw.commands.cmd_doctor import _omnigent_runtime_readiness

        readiness, detail = _omnigent_runtime_readiness(cfg)
    except Exception as exc:  # noqa: BLE001 - presentation must remain available.
        readiness, detail = "warn", f"policy readiness unavailable: {exc}"
    if readiness not in {"pass", "bound"}:
        return "degraded", detail
    return raw_state, detail


# GAP-1149: counting alerts reads every audit row, which took minutes on a
# 2 GB audit database; status shows "not counted" (JSON: null) after this.
_ALERT_COUNT_SECONDS = 3.0


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
    # Keep at least one space after the colon for labels as long as the
    # column ("Model routing:").
    label_padded = (key + ":").ljust(max(_STATUS_LABEL_WIDTH, len(key) + 2))
    rendered_value = ux.dim("—") if not value else value
    ux.echo(f"  {ux._style(label_padded, fg='bright_black', bold=True)}{rendered_value}")


@click.command()
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help=(
        "Emit status as a JSON document (environment, scanners, enforcement, "
        "activity, and the full per-connector roster with effective mode). "
        "Includes authenticated, profile-bound sidecar state when available."
    ),
)
@pass_ctx
def status(app: AppContext, as_json: bool) -> None:
    """Show DefenseClaw status.

    Displays environment, sandbox state, scanner availability,
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
    ux.echo()
    ux.echo(ux._style("DefenseClaw Status", fg="cyan", bold=True))
    ux.echo(ux._style("══════════════════", fg="cyan"))

    _status_row("Environment", cfg.environment)
    if getattr(cfg, "deployment_mode", ""):
        _status_row("Deployment", cfg.deployment_mode)
    profile = _enterprise_profile(cfg)
    if profile == _STANDALONE_ENTERPRISE_PROFILE:
        _status_row("Enterprise", f"{profile} (managed by your organization)")
    _status_row("Data dir", cfg.data_dir)
    _status_row("Config", str(config_path()))
    _status_row("Audit DB", cfg.audit_db)
    _status_row("Scope", _connector_scope_text(cfg))
    ux.echo()

    # Sandbox. The legacy openshell-sandbox mode was removed; a host that
    # still carries its config is pointed at the cleanup command.
    if legacy_standalone_configured(cfg):
        _status_row(
            "Sandbox",
            ux._style("legacy install detected", fg="yellow")
            + ux.dim(" (run: defenseclaw sandbox legacy-cleanup)"),
        )
    elif _sandboxes_enabled(cfg):
        _status_row("Sandbox", ux._style("on", fg="green") + ux.dim(" (details: defenseclaw sandbox status)"))
    elif _host_is_windows():
        _status_row("Sandbox", ux.dim("not supported on Windows"))
    else:
        _status_row("Sandbox", ux.dim("off (set up with: defenseclaw sandbox setup)"))

    # Scanners
    ux.section("Scanners")
    scanner_bins = [
        ("skill-scanner", cfg.scanners.skill_scanner.binary),
        ("mcp-scanner", cfg.scanners.mcp_scanner.binary),
        ("codeguard", "built-in"),
    ]
    for name, binary in scanner_bins:
        if binary == "built-in":
            ux.echo(f"    {ux.bold(f'{name:<16s}')}{ux.dim('built-in')}")
        elif resolve_scanner_binary(binary):
            ux.echo(f"    {ux.bold(f'{name:<16s}')}{ux._style('installed', fg='green')}")
        else:
            ux.echo(f"    {ux.bold(f'{name:<16s}')}{ux._style('not found', fg='yellow')}")

    # N3: surface the active policy's scanner action overrides (data.json).
    # Only `policy show` exposed these before, so `status` was blind to a
    # policy that, say, downgrades a scanner surface to warn/allow. Empty for a
    # policy that declares none, so the common case renders nothing.
    overrides_summary = _scanner_overrides_summary(cfg)
    if overrides_summary:
        ux.echo(f"    {ux.bold('overrides'.ljust(16))}{ux.dim(overrides_summary)}")

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
            counts = app.store.get_counts(alert_count_seconds=_ALERT_COUNT_SECONDS)
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
                ux.echo(f"    {_label((label + ':').ljust(16))} {val}")
        else:
            ux.echo(f"    {ux._style('unavailable', fg='yellow')} {ux.dim(f'(audit DB error: {db_error})')}")

        ux.section("Activity")
        if counts is not None:
            for label, val in (
                ("Total scans", counts.total_scans),
                ("Active alerts", counts.alerts),
            ):
                if val is None:
                    val = ux.dim("not counted (too many audit events to count quickly; list them: defenseclaw alerts)")
                ux.echo(f"    {_label((label + ':').ljust(16))} {val}")
        else:
            ux.echo(f"    {ux._style('unavailable', fg='yellow')} {ux.dim(f'(audit DB error: {db_error})')}")

    # Canonical v8 collection, routing, redaction, and destination status.
    _print_observability_status(cfg)

    # Sidecar status
    ux.echo()
    from defenseclaw.gateway import OrchestratorClient, gateway_api_client_host

    bind = gateway_api_client_host(cfg)
    client = OrchestratorClient(
        host=bind,
        port=cfg.gateway.api_port,
        token=cfg.gateway.resolved_token(),
    )
    from defenseclaw.commands import hint

    # Render the "Agents" roster uniformly — one section that lists every
    # active connector with its effective mode (and, when the sidecar is up,
    # live counters from its identity-bound status snapshot). The same code
    # path drives a single-connector install (one row) and a fan-out install
    # (N rows), so the output never branches on connector count.
    health = _fetch_runtime_bound_health(client, cfg)
    if health is not None:
        from defenseclaw.commands.cmd_doctor import _gateway_runs_replaced_binary

        if _gateway_runs_replaced_binary(cfg):
            _status_row(
                "Sidecar",
                ux._style("running a replaced binary; run defenseclaw-gateway restart", fg="yellow"),
            )
        else:
            _status_row("Sidecar", ux._style("running", fg="green"))
        _print_audit_log_health(cfg, health)
        _print_agents(cfg, health=health)
        _print_application_protection(cfg, health=health)
        _print_semantic_routing(cfg, health=health)
        _print_llm_judge(health)
        _print_hook_guardian(cfg)
        hint(
            "Dashboard:     defenseclaw alerts",
            "Health check:  defenseclaw doctor",
            "Operator overview: defenseclaw status | Sidecar subsystems: defenseclaw-gateway status",
        )
    else:
        try:
            from defenseclaw.commands.cmd_doctor import _foreign_gateway_port_holder, _free_api_port_hint

            holder = _foreign_gateway_port_holder(cfg)
        except Exception:  # noqa: BLE001 - status stays best effort
            holder = ""
        if holder:
            _status_row(
                "Sidecar",
                ux._style(f"not running; port {cfg.gateway.api_port} is held by {holder}", fg="yellow"),
            )
        else:
            _status_row(
                "Sidecar",
                ux._style("not running; start it: defenseclaw-gateway start", fg="yellow"),
            )
        _print_audit_log_health(cfg, None)
        # Even when the sidecar is down, show the *configured* agents
        # so operators know what `start` will spin up.
        _print_agents(cfg, sidecar_down=True)
        _print_application_protection(cfg)
        _print_semantic_routing(cfg)
        _print_hook_guardian(cfg)
        hint(
            "Free the port:  stop that process, or run: defenseclaw setup gateway --api-port "
            f"{_free_api_port_hint(cfg)} --non-interactive"
            if holder
            else "Start sidecar:  defenseclaw-gateway start",
            "Operator overview: defenseclaw status | Sidecar subsystems: defenseclaw-gateway status",
        )


_FRIENDLY_CONNECTOR_NAMES = {
    "openclaw": "OpenClaw",
    "zeptoclaw": "ZeptoClaw",
    "claudecode": "Claude Code",
    "codex": "Codex",
    "hermes": "Hermes",
    "cursor": "Cursor",
    "devin": "Devin",
    "copilot": "GitHub Copilot CLI",
    "openhands": "OpenHands",
    "antigravity": "Antigravity",
    "opencode": "OpenCode",
    "amp": "Amp",
    "omnigent": "OmniGent",
    "kiro": "Kiro",
}
_CURSOR_PRIORITY_CONFLICT_DISCLOSURE = "priority-conflict-detection=unavailable (none inferred)"


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


def _cursor_priority_conflict_disclosure(name: str) -> str:
    if name.strip().lower() == "cursor":
        return _CURSOR_PRIORITY_CONFLICT_DISCLOSURE
    return ""


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


def _guardrail_turned_off(gc) -> bool:
    """Whether ``guardrail.enabled`` is explicitly false in the config."""
    return getattr(gc, "enabled", True) is False


def _print_agents(
    cfg,
    *,
    health: dict | None = None,
    sidecar_down: bool = False,
) -> None:
    """Render the "Agents" roster as one section, for ANY connector count.

    Config-derived (``active_connectors()`` + ``GuardrailConfig.effective_mode``)
    so it lists every active connector and its effective mode regardless of
    sidecar state. The exact same section is rendered whether the install has
    zero, one, or many connectors — there is no separate single-connector
    ``Agent:`` block. ``active_connectors()`` returns one name on a
    single-connector install and N on a fan-out install, so the same loop
    drives both.

    When a runtime-bound health snapshot is supplied, *every* connector is
    annotated with its own live state and counters. There is no privileged
    "primary" — each active agent reports its own tally.
    """
    try:
        manual_actives = [c for c in (cfg.active_connectors() if hasattr(cfg, "active_connectors") else []) if c]
    except Exception:
        manual_actives = []
    health_map = _fetch_health_connectors(health=health)
    not_started = _connectors_not_started(health)
    state = _application_protection_status(cfg, health=health)

    roster: dict[str, dict] = {}
    for conn in manual_actives:
        key = conn.strip().lower()
        if key:
            roster[key] = {"name": key, "source": "manual"}
    for key, hc in health_map.items():
        source = str(hc.get("source") or "").strip().lower() or "manual"
        if key and source == "automatic":
            roster[key] = {"name": key, "source": "automatic"}
    for row in state.get("active") or []:
        if not isinstance(row, dict):
            continue
        key = str(row.get("connector") or "").strip().lower()
        if key and str(row.get("source") or "").strip().lower() == "automatic":
            roster.setdefault(key, {"name": key, "source": "automatic"})

    actives = sorted(roster)
    if not actives:
        # Uniform empty state — same "Agents" section whether the install has
        # zero, one, or many connectors (no separate single-connector block).
        _status_row("Agents", ux.dim("(no active connector)"))
        return

    gc = getattr(cfg, "guardrail", None)
    # ``guardrail.enabled: false`` (``setup guardrail --disable``, or the
    # default ``uninstall``) makes the gateway tear every hook connector
    # down, so none of them enforces (GAP-1312). The OpenClaw row reports the
    # OpenClaw gateway connection instead (#958) and keeps its own state.
    guardrail_off = _guardrail_turned_off(gc) and any(c != "openclaw" for c in actives)

    def _is_enabled(name: str) -> bool:
        # An explicit ``enabled: false`` override (set by
        # ``guardrail disable --connector X``) means the connector was torn
        # down and is no longer enforcing. Default True so single-connector
        # installs and never-disabled connectors keep reading as active.
        if guardrail_off and name != "openclaw":
            return False
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
    if guardrail_off and not enabled_count:
        header = ux._style(f"{len(actives)} configured, guardrail off (nothing is guarded)", fg="yellow")
    if sidecar_down and enabled_count:
        # Hooks are configured but nothing answers them: each connector falls
        # back to its fail-mode (open = calls run unchecked, closed = blocked).
        header = f"{enabled_count} configured, not enforced while the sidecar is stopped"
        if disabled_count:
            header += f" ({disabled_count} disabled)"
        header = ux._style(header, fg="yellow")
    _status_row("Agents", header)
    if guardrail_off:
        ux.echo(" " * 16 + ux.dim("Turn protection back on: defenseclaw setup guardrail"))
    if sidecar_down and enabled_count:
        ux.echo(
            " " * 16
            + ux.dim(
                "Hooks fall back to each connector's fail-mode: open lets calls run "
                "unchecked, closed blocks them. Start it: defenseclaw-gateway start"
            )
        )
    for conn in actives:
        source = roster.get(conn, {}).get("source", "manual")
        mode = _effective_status_mode(cfg, conn, source)
        fail_mode = _effective_status_fail_mode(cfg, conn)
        fail_mode_suffix = f" fail-mode={fail_mode['effective']} provenance={fail_mode['provenance']}"
        friendly = _friendly_connector_name(conn)
        disclosure = _cursor_priority_conflict_disclosure(conn)
        disclosure_suffix = f" {disclosure}" if disclosure else ""
        if not _is_enabled(conn):
            # Operator-disabled: hooks were torn down, so there is no live
            # health entry. Mark it explicitly rather than letting it fall to
            # the dim "not reporting" branch, which is indistinguishable from a
            # connector the sidecar simply hasn't surfaced yet.
            disabled_label = ux._style("DISABLED", fg="yellow")
            disabled_text = ux.dim(f"{friendly} ({conn}) — mode={mode or '?'}{fail_mode_suffix}{disclosure_suffix}")
            ux.echo(f"                {disabled_text} — {disabled_label}")
            continue
        hc = health_map.get(conn.strip().lower())
        source_suffix = f" source={source}"
        if hc:
            runtime_detail = ""
            runtime_state = str(hc.get("state") or "")
            if conn == "opencode":
                runtime_state, runtime_detail = _opencode_runtime_truth(
                    hc,
                    gateway_started_at=health.get("started_at") if isinstance(health, dict) else "",
                    gateway_available=isinstance(health, dict),
                )
            elif conn == "omnigent":
                runtime_state, runtime_detail = _omnigent_effective_runtime_state(cfg, runtime_state)
            elif conn == "openclaw" and openclaw_implied_but_not_installed(cfg):
                # The gateway does not dial an OpenClaw gateway that is only
                # the claw.mode default and is not installed (#958).
                runtime_state, runtime_detail = "off", "OpenClaw is not installed"
            suffix = _connector_state_verb(runtime_state)
            if runtime_detail:
                suffix += ux.dim(f" ({runtime_detail})")
            suffix += _hook_runtime_degraded_suffix(cfg, conn)
            ux.echo(
                f"                {friendly} ({conn}) — mode={mode or '?'}"
                f"{fail_mode_suffix}{source_suffix}{disclosure_suffix}{suffix}"
            )
            _print_agent_counters(hc, indent="                  ")
        else:
            dim_text = ux.dim(
                f"{friendly} ({conn}) — mode={mode or '?'}{fail_mode_suffix}{source_suffix}{disclosure_suffix}"
            )
            if conn == "opencode":
                runtime_state, runtime_detail = _opencode_runtime_truth(
                    None,
                    gateway_started_at=health.get("started_at") if isinstance(health, dict) else "",
                    gateway_available=isinstance(health, dict),
                )
                suffix = _connector_state_verb(runtime_state)
                suffix += ux.dim(f" ({runtime_detail})")
                ux.echo(f"                {dim_text}{suffix}")
            elif conn == "openclaw" and openclaw_implied_but_not_installed(cfg):
                suffix = _connector_state_verb("off") + ux.dim(" (OpenClaw is not installed)")
                ux.echo(f"                {dim_text}{suffix}")
            elif conn.strip().lower() in not_started:
                # Setup failed when the gateway started (GAP-1714).
                suffix = _connector_state_verb("not running") + ux.dim(
                    " (setup failed when the gateway started, so it is not enforced; "
                    f"see gateway.log, then run: defenseclaw setup {conn.strip().lower()})"
                )
                ux.echo(f"                {dim_text}{suffix}")
            else:
                # A drifted or removed hook registration shows with the
                # gateway stopped too (GAP-1230).
                ux.echo(f"                {dim_text}{_hook_runtime_degraded_suffix(cfg, conn)}")


def _canonical_data_dir(value) -> str | None:
    """Return the platform-canonical absolute form of a configured data dir."""
    try:
        raw = os.fspath(value)
    except TypeError:
        return None
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return os.path.normcase(os.path.abspath(os.path.normpath(raw)))
    except (OSError, ValueError):
        return None


def _fetch_runtime_bound_health(client, cfg) -> dict | None:
    """Fetch health only from the verified managed sidecar listener.

    ``/health`` is intentionally unauthenticated and a different profile may
    already own the configured loopback port. The authenticated ``/status``
    response is accepted only when Doctor's existing process/listener trust
    proves the endpoint and its runtime PID plus canonical data directory bind
    back to that exact listener. Treat missing, malformed, or mismatched
    identity as unavailable so status never splices another process or
    profile's connector evidence into this profile's output.
    """
    try:
        from defenseclaw.commands.cmd_doctor import (
            _authenticated_runtime_matches,
            _trusted_gateway_listener,
        )

        trust = _trusted_gateway_listener(cfg)
    except Exception:
        return None
    if not trust.trusted:
        return None
    try:
        document = client.status()
    except Exception:
        return None
    if not isinstance(document, dict):
        return None
    try:
        runtime_ok, _runtime_detail = _authenticated_runtime_matches(
            cfg,
            trust.pid,
            json.dumps(document),
        )
    except (TypeError, ValueError):
        return None
    if not runtime_ok:
        return None
    health = document.get("health")
    if not isinstance(health, dict):
        return None
    return health


def _fetch_health_connectors(
    *,
    health: dict | None = None,
) -> dict[str, dict]:
    """Map ``connector-name`` → its bound ``ConnectorHealth`` snapshot.

    Reads the per-connector ``connectors[]`` array so every active connector
    can render its own live counters. Falls back to folding in the singular
    ``connector`` field so an older gateway (which only reports the primary)
    still surfaces at least that connector's counters.
    """
    if not isinstance(health, dict):
        return {}
    out: dict[str, dict] = {}
    conns = health.get("connectors")
    if isinstance(conns, list):
        for c in conns:
            if isinstance(c, dict):
                nm = str(c.get("name") or "").strip().lower()
                if nm:
                    out[nm] = c
    single = health.get("connector")
    if isinstance(single, dict):
        nm = str(single.get("name") or "").strip().lower()
        if nm and nm not in out:
            out[nm] = single
    return out


def _effective_status_mode(cfg, connector: str, source: str = "manual") -> str:
    if source == "automatic":
        try:
            app = getattr(cfg, "application_protection", None)
            if app is not None and hasattr(app, "effective_guardrail_mode"):
                return app.effective_guardrail_mode(connector)
        except Exception:
            pass
    gc = getattr(cfg, "guardrail", None)
    if gc is not None and hasattr(gc, "effective_mode"):
        try:
            return (gc.effective_mode(connector) or "").strip()
        except Exception:
            return ""
    return ""


def _effective_status_fail_mode(cfg, connector: str) -> dict:
    """Return the shared fail-mode report without making status fragile."""

    try:
        from defenseclaw.fail_mode import connector_fail_mode_report

        return connector_fail_mode_report(cfg, connector)
    except Exception:  # noqa: BLE001 - status must survive incomplete runtime state.
        guardrail = getattr(cfg, "guardrail", None)
        resolver = getattr(guardrail, "effective_hook_fail_mode", None)
        try:
            effective = str(resolver(connector) if callable(resolver) else "").strip().lower()
        except Exception:  # noqa: BLE001 - preserve the informational command.
            effective = ""
        return {
            "effective": effective or "unknown",
            "provenance": "config-unverified",
            "configured": effective or "unknown",
            "desired": effective or "unknown",
            "runtime": None,
            "current": None,
            "drift": ["report-unavailable"],
            "sources": [],
        }


def _hook_runtime_degraded_suffix(cfg, connector: str) -> str:
    """`` — DEGRADED (...)`` when a hook script, token or registration drifted (GAP-1141, GAP-1138, GAP-1230)."""
    try:
        from defenseclaw.hook_integrity import hook_registration_problems, hook_runtime_problems, setup_command

        problems = hook_runtime_problems(cfg, connector) or hook_registration_problems(cfg, connector)
    except Exception:  # noqa: BLE001 - status must survive incomplete runtime state.
        return ""
    if not problems:
        return ""
    return (
        " — "
        + ux._style("DEGRADED", fg="red", bold=True)
        + ux.dim(f" ({problems[0]}; run `{setup_command(connector)}`)")
    )


def _connectors_not_started(health: dict | None) -> set[str]:
    """Configured connectors the gateway could not set up at start (GAP-1714)."""
    guardrail = health.get("guardrail") if isinstance(health, dict) else None
    details = guardrail.get("details") if isinstance(guardrail, dict) else None
    names = details.get("connectors_not_started") if isinstance(details, dict) else None
    if not isinstance(names, list):
        return set()
    return {name.strip().lower() for name in names if isinstance(name, str) and name.strip()}


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
        ux.echo(
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
    ux.echo(
        f"{indent}{ux.dim(f'requests: {requests}')}  {err_text}  "
        f"{ux.dim(f'tool inspections: {inspections}')}  {block_text_tool}  "
        f"{block_text_sub}"
    )


def _print_application_protection(cfg, health: dict | None = None) -> None:
    state = _application_protection_status(cfg, health=health)
    enabled = bool(state.get("enabled", getattr(getattr(cfg, "application_protection", None), "enabled", False)))
    status_text = ux._style("enabled", fg="green") if enabled else ux._style("disabled", fg="yellow")
    health_state = str(state.get("health_state") or "").strip()
    if health_state and health_state.lower() not in ("enabled", "disabled"):
        status_text += ux.dim(f" ({health_state})")
    _status_row("App protect", status_text)
    if not enabled:
        # GAP-1498: no "(disabled)" echo, no scan that will never run; say
        # what the feature does and how to turn it on.
        ux.echo(
            "                "
            + ux.dim(
                "guards AI apps that discovery finds; to turn it on, set "
                "application_protection.enabled: true in the config file "
                "('defenseclaw config path') and restart the gateway"
            )
        )
        return
    guardrail_mode = str(state.get("guardrail_mode") or "observe")
    asset_mode = str(state.get("asset_policy_mode") or "observe")
    trust_check = "on" if bool(state.get("require_trusted_binary_paths")) else "off"
    ux.echo(
        "                "
        + ux.dim(f"auto guardrail={guardrail_mode} asset_policy={asset_mode} trusted-path-check={trust_check}")
    )

    discovered = [r for r in state.get("discovered") or [] if isinstance(r, dict)]
    active = [r for r in state.get("active") or [] if isinstance(r, dict)]
    skipped = [r for r in state.get("skipped") or [] if isinstance(r, dict)]
    errors = state.get("last_activation_errors") or {}
    if not discovered and not active and not skipped and not errors:
        ux.echo("                " + ux.dim("(awaiting discovery scan)"))
        return

    if discovered:
        ux.echo("                " + ux.bold("discovered"))
        for row in discovered[:8]:
            conn = str(row.get("connector") or "").strip()
            conf = row.get("confidence")
            conf_text = f"{float(conf):.2f}" if isinstance(conf, (int, float)) else "?"
            state_text = str(row.get("state") or "active")
            ux.echo(
                f"                  {_friendly_connector_name(conn)} ({conn}) — "
                f"confidence={conf_text} state={state_text}"
            )
    if active:
        ux.echo("                " + ux.bold("auto-protected"))
        for row in active:
            conn = str(row.get("connector") or "").strip()
            source = str(row.get("source") or "automatic")
            ux.echo(f"                  {_friendly_connector_name(conn)} ({conn}) — source={source}")
    if skipped:
        ux.echo("                " + ux.bold("skipped"))
        for row in skipped[:8]:
            conn = str(row.get("connector") or "").strip()
            reason = str(row.get("reason") or "unknown")
            detail = str(row.get("detail") or "")
            suffix = f" — {detail}" if detail else ""
            ux.echo(f"                  {_friendly_connector_name(conn)} ({conn}) — {reason}{ux.dim(suffix)}")
    if isinstance(errors, dict) and errors:
        ux.echo("                " + ux.bold("last activation errors"))
        for conn, err in sorted(errors.items()):
            ux.echo(f"                  {_friendly_connector_name(conn)} ({conn}) — {ux._style(str(err), fg='yellow')}")


def _application_protection_status(cfg, health: dict | None = None) -> dict:
    state = _load_application_protection_state(cfg)
    app_cfg = getattr(cfg, "application_protection", None)
    if app_cfg is not None:
        state.setdefault("enabled", bool(getattr(app_cfg, "enabled", False)))
        state.setdefault("min_confidence", getattr(app_cfg, "min_confidence", 0.80))
        state.setdefault("remove_when_gone", getattr(app_cfg, "remove_when_gone", False))
        state.setdefault("gone_after_min", getattr(app_cfg, "gone_after_min", 60))
        if hasattr(app_cfg, "effective_guardrail_mode"):
            state.setdefault("guardrail_mode", app_cfg.effective_guardrail_mode("__automatic__"))
        else:
            state.setdefault("guardrail_mode", "observe")
        if hasattr(app_cfg, "effective_asset_policy_mode"):
            state.setdefault("asset_policy_mode", app_cfg.effective_asset_policy_mode("__automatic__"))
        else:
            state.setdefault("asset_policy_mode", "observe")
    ai_cfg = getattr(cfg, "ai_discovery", None)
    if ai_cfg is not None:
        state.setdefault(
            "require_trusted_binary_paths",
            bool(getattr(ai_cfg, "require_trusted_binary_paths", False)),
        )
        state.setdefault(
            "trusted_binary_prefixes",
            list(getattr(ai_cfg, "trusted_binary_prefixes", []) or []),
        )

    live = None
    if isinstance(health, dict):
        live = health.get("application_protection")
    if isinstance(live, dict):
        state["health_state"] = str(live.get("state") or "")
        if live.get("last_error"):
            state["last_error"] = live.get("last_error")
        details = live.get("details")
        if isinstance(details, dict):
            for key in (
                "enabled",
                "last_scan",
                "discovered",
                "active",
                "skipped",
                "guardrail_mode",
                "asset_policy_mode",
                "require_trusted_binary_paths",
                "trusted_binary_prefixes",
            ):
                if key in details:
                    state[key] = details[key]
            if "last_errors" in details:
                state["last_activation_errors"] = details.get("last_errors") or {}
            if "state_file" in details:
                state["state_file"] = details["state_file"]

    state.setdefault("state_file", str(Path(getattr(cfg, "data_dir", "")) / "application_protection_state.json"))
    state.setdefault("discovered", [])
    state.setdefault("active", [])
    state.setdefault("skipped", [])
    state.setdefault("last_activation_errors", {})
    state.setdefault("guardrail_mode", "observe")
    state.setdefault("asset_policy_mode", "observe")
    state.setdefault("require_trusted_binary_paths", False)
    state.setdefault("trusted_binary_prefixes", [])
    return state


def _semantic_routing_status(cfg, health: dict | None = None) -> dict:
    routing = getattr(cfg, "routing", None)
    enabled = bool(getattr(routing, "enabled", False)) if routing is not None else False
    remote = getattr(routing, "remote", {}) or {} if routing is not None else {}
    endpoint = str(remote.get("endpoint") or "").strip() if isinstance(remote, dict) else ""
    state = {
        "configured": enabled,
        "mode": "remote" if endpoint else "managed",
        "version": str(getattr(routing, "version", "") or "0.3.0") if routing is not None else "0.3.0",
        "port": int(getattr(routing, "port", 0) or 8080) if routing is not None else 8080,
        "model_count": len(getattr(routing, "models", []) or []) if routing is not None else 0,
        "runtime_state": "unknown" if enabled else "disabled",
    }
    live = health.get("routing") if isinstance(health, dict) else None
    if isinstance(live, dict):
        state["runtime_state"] = str(live.get("state") or state["runtime_state"])
        if live.get("last_error"):
            state["last_error"] = str(live["last_error"])
    return state


def _print_semantic_routing(cfg, health: dict | None = None) -> None:
    state = _semantic_routing_status(cfg, health=health)
    if not state["configured"]:
        _status_row("Model routing", ux._style("disabled", fg="bright_black"))
        return
    runtime = str(state["runtime_state"])
    color = "green" if runtime == "running" else "yellow"
    value = f"{state['mode']} — {runtime}; {state['model_count']} model(s)"
    _status_row("Model routing", ux._style(value, fg=color))


def _print_audit_log_health(cfg, health: dict | None) -> None:
    """Warn when audit events are not being recorded (GAP-1528).

    Enforcement keeps working when the audit database cannot be written (a
    full disk), so without this row status looked healthy while blocks were
    missing from alerts and audit.
    """
    from defenseclaw.audit_capacity import audit_disk_full_notice

    value = audit_disk_full_notice(str(getattr(cfg, "audit_db", "") or ""))
    telemetry = health.get("telemetry") if isinstance(health, dict) else None
    if not value and isinstance(telemetry, dict):
        state = str(telemetry.get("state") or "").strip().lower()
        if state and state not in _RUNTIME_HEALTHY_STATES:
            from defenseclaw.commands.cmd_doctor import _telemetry_error_reason

            reason = _telemetry_error_reason(telemetry.get("details"))
            since = str(telemetry.get("since") or "").strip()
            if reason:
                value = reason + (f" (since {since})" if since and not since.startswith("0001") else "")
                value += "; run 'defenseclaw doctor'"
    if value:
        _status_row("Audit log", ux._style(value[0].upper() + value[1:], fg="yellow"))


def _print_llm_judge(health: dict | None) -> None:
    """Show the LLM judge row when the gateway has made judge calls.

    A judge whose provider failed every call was invisible here: the hook
    lane kept the rule verdicts and only the audit rows said so (GAP-1120).
    """
    guardrail = health.get("guardrail") if isinstance(health, dict) else None
    details = guardrail.get("details") if isinstance(guardrail, dict) else None
    if not isinstance(details, dict) or not details.get("judge_state"):
        return
    state = str(details.get("judge_state"))
    total = details.get("judge_recent_calls", 0)
    failed = details.get("judge_failed_calls", 0)
    if state == "ok":
        _status_row("LLM judge", ux._style(f"working (last {total} call(s) completed)", fg="green"))
        return
    if state == "failing":
        value = f"failing: all of its last {total} call(s) failed, so only the rules decide"
    else:
        value = f"degraded: {failed} of its last {total} call(s) failed"
    last_error = str(details.get("judge_last_error") or "").strip()
    if last_error:
        value += f"; last error: {last_error}"
    _status_row("LLM judge", ux._style(value + "; run 'defenseclaw doctor'", fg="yellow"))


def _load_application_protection_state(cfg) -> dict:
    data_dir = getattr(cfg, "data_dir", "") or ""
    if not data_dir:
        return {}
    path = Path(data_dir) / "application_protection_state.json"
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {"state_file": str(path)}
    return data if isinstance(data, dict) else {"state_file": str(path)}


def _print_hook_guardian(cfg) -> None:
    state = _hook_guardian_status(cfg)
    managed = str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise"
    if not managed and not state.get("configured"):
        return

    if not state.get("configured"):
        _status_row("Hook guardian", ux._style("not reconciled", fg="yellow"))
        ux.echo("                " + ux.dim("(no hook_guardian_state.json yet)"))
        return

    ok = bool(state.get("ok"))
    status_text = ux._style("healthy", fg="green") if ok else ux._style("attention", fg="yellow")
    target_count = int(state.get("target_count") or 0)
    success_count = int(state.get("success_count") or 0)
    failure_count = int(state.get("failure_count") or 0)
    status_text += ux.dim(f" ({success_count}/{target_count} targets ok)")
    if failure_count:
        status_text += ux.dim(f", {failure_count} failed")
    _status_row("Hook guardian", status_text)

    updated = str(state.get("updated_at") or "").strip()
    manifest = str(state.get("manifest") or "").strip()
    if updated or manifest:
        detail = []
        if updated:
            detail.append(f"last run: {updated}")
        if manifest:
            detail.append(f"manifest: {manifest}")
        ux.echo("                " + ux.dim("  ".join(detail)))

    results = [r for r in state.get("results") or [] if isinstance(r, dict)]
    for row in results[:8]:
        conn = str(row.get("connector") or "").strip()
        user = str(row.get("user") or row.get("user_home") or "").strip()
        label = f"{_friendly_connector_name(conn)} ({conn})"
        if user:
            label += f" for {user}"
        if row.get("ok"):
            ux.echo(f"                  {label} — ok")
        else:
            err = str(row.get("error") or "failed")
            ux.echo(f"                  {label} — {ux._style(err, fg='yellow')}")


def _hook_guardian_status(cfg) -> dict:
    data_dir = getattr(cfg, "data_dir", "") or ""
    path = Path(data_dir) / "hook_guardian_state.json" if data_dir else Path("hook_guardian_state.json")
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {"configured": False, "state_file": str(path)}
    if not isinstance(data, dict):
        return {"configured": False, "state_file": str(path)}
    data.setdefault("state_file", str(path))
    data["configured"] = True
    data.setdefault("results", [])
    data.setdefault("target_count", len(data.get("results") or []))
    data.setdefault("success_count", sum(1 for r in data.get("results") or [] if isinstance(r, dict) and r.get("ok")))
    data.setdefault("failure_count", max(0, int(data.get("target_count") or 0) - int(data.get("success_count") or 0)))
    return data


def _print_observability_status(cfg) -> None:
    """Render the compiler-owned canonical v8 destination plan."""

    from defenseclaw.config import config_path_for_data_dir
    from defenseclaw.observability.v8_status import inspect_v8_operator_status

    ux.section("Observability")
    try:
        status = inspect_v8_operator_status(config_path_for_data_dir(cfg.data_dir))
    except Exception as exc:  # noqa: BLE001 - status remains useful when the sidecar is stopped.
        ux.echo("    " + ux._style(f"canonical v8 plan unavailable: {exc}", fg="yellow"))
        _print_native_delivery_status(_native_delivery_summary(cfg))
        return

    retention = "unbounded" if status.unbounded_retention else f"{status.retention_days} days"
    ux.echo(f"    {ux.dim('plan:')} {status.plan_digest[:12]}  {ux.dim('retention:')} {retention}")
    for destination in status.destinations:
        state = ux._style("enabled", fg="green") if destination.enabled else ux._style("disabled", fg="bright_black")
        signals = ",".join(destination.selected_signals) or "none"
        ux.echo(
            f"    {ux.bold(f'{destination.name:<26s}')}"
            f"{ux.dim(f'[{destination.kind}]')} {state}  "
            f"{signals}  {destination.redaction_label}"
        )
        if destination.endpoint:
            ux.echo(f"      {ux.dim('target:')} {destination.endpoint}")
    _print_native_delivery_status(_native_delivery_summary(cfg, audit_db=status.local_path))


def _native_delivery_summary(cfg, *, audit_db: str = ""):
    """Return the shared bounded, path-free native OTLP evidence summary."""

    from defenseclaw.observability.custody_status import (
        inspect_connector_custody,
        summarize_native_delivery,
    )

    data_dir = str(getattr(cfg, "data_dir", "") or "")
    database = audit_db
    if not database:
        try:
            from defenseclaw.config import config_path_for_data_dir
            from defenseclaw.observability.v8_status import inspect_v8_operator_status

            database = inspect_v8_operator_status(config_path_for_data_dir(data_dir)).local_path
        except Exception:  # noqa: BLE001 - fall back to the configured audit ledger.
            database = ""
    database = database or str(getattr(cfg, "audit_db", "") or "")
    if not database:
        database = os.path.join(data_dir, "audit.db")
    return summarize_native_delivery(inspect_connector_custody(database, data_dir))


def _print_native_delivery_status(summary) -> None:
    """Render delivery truth separately from collector/runtime health."""

    hours = summary.observation_window_hours
    scope = f"bounded {hours}h"
    if summary.event_rows_truncated:
        scope += ", truncated; counts partial"
    delivery_context = f"native OTLP delivery ({scope}; collector/runtime health does not prove accepted delivery):"
    ux.echo("    " + ux.dim(delivery_context))
    if not summary.connectors:
        reason = f"; {summary.reason.replace('_', ' ')}" if summary.reason else ""
        ux.echo(f"      {ux.dim(f'no evidence ({scope}{reason})')}")
        return
    for item in summary.connectors:
        instance = "" if item.default else " (additional instance)"
        state = item.state.replace("_", "-")
        color = "green" if item.state == "accepted" else "yellow"
        if item.state == "no_evidence":
            color = "bright_black"
        ux.echo(f"      {ux.bold(item.connector + instance)}  {ux._style(state, fg=color)} — {item.detail}")


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
                        flat.append((str(scanner_type), str(severity), surface, str(action)))
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
            out[name] = "installed" if resolve_scanner_binary(binary) else "not_found"
    return out


def _connector_roster(cfg, health: dict | None = None) -> list[dict]:
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
        if name != "openclaw" and _guardrail_turned_off(gc):
            return False
        if gc is None or not hasattr(gc, "effective_enabled"):
            return True
        try:
            return bool(gc.effective_enabled(name))
        except Exception:
            return True

    rows: dict[str, dict] = {
        c: {
            "name": c,
            "friendly": _friendly_connector_name(c),
            "mode": _mode(c),
            "fail_mode": _effective_status_fail_mode(cfg, c),
            "enabled": _enabled(c),
            "source": "manual",
        }
        for c in actives
    }
    for name, hc in _fetch_health_connectors(health=health).items():
        source = str(hc.get("source") or "").strip().lower()
        if source != "automatic":
            continue
        rows[name] = {
            "name": name,
            "friendly": _friendly_connector_name(name),
            "mode": _effective_status_mode(cfg, name, source),
            "fail_mode": _effective_status_fail_mode(cfg, name),
            "enabled": True,
            "source": "automatic",
            "state": hc.get("state"),
        }
    state = _application_protection_status(cfg, health=health)
    for row in state.get("active") or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("connector") or "").strip().lower()
        if not name:
            continue
        rows.setdefault(
            name,
            {
                "name": name,
                "friendly": _friendly_connector_name(name),
                "mode": _effective_status_mode(cfg, name, "automatic"),
                "fail_mode": _effective_status_fail_mode(cfg, name),
                "enabled": True,
                "source": "automatic",
            },
        )
    health_map = _fetch_health_connectors(health=health)
    if "opencode" in rows:
        runtime_state, runtime_detail = _opencode_runtime_truth(
            health_map.get("opencode"),
            gateway_started_at=health.get("started_at") if isinstance(health, dict) else "",
            gateway_available=isinstance(health, dict),
        )
        rows["opencode"]["state"] = runtime_state
        rows["opencode"]["runtime_detail"] = runtime_detail
    if "omnigent" in rows and (omnigent_health := health_map.get("omnigent")) is not None:
        runtime_state, readiness_detail = _omnigent_effective_runtime_state(
            cfg,
            str(omnigent_health.get("state") or ""),
        )
        rows["omnigent"]["state"] = runtime_state
        if readiness_detail:
            rows["omnigent"]["readiness_detail"] = readiness_detail
    cursor = rows.get("cursor")
    if cursor is not None:
        cursor["priority_conflict_detection"] = {
            "status": "unavailable",
            "conflict_inferred": False,
        }
    return [rows[name] for name in sorted(rows)]


def _status_payload(app) -> dict:
    """Build the machine-readable status document for ``status --json`` (SU-13).

    Config + audit-DB data forms the reliable baseline for automation. Live
    sidecar state is accepted only from an authenticated ``/status`` response
    whose runtime data directory matches the resolved configuration.
    SU-05: audit-DB read failures surface as ``enforcement``/``activity`` =
    ``null`` plus an ``audit_db_error`` field, never a silent drop.
    """
    cfg = app.cfg
    payload: dict = {
        "environment": cfg.environment,
        "deployment_mode": getattr(cfg, "deployment_mode", ""),
    }
    profile = _enterprise_profile(cfg)
    if profile == _STANDALONE_ENTERPRISE_PROFILE:
        payload["enterprise_profile"] = profile
    payload.update(
        {
            "data_dir": cfg.data_dir,
            "config": str(config_path()),
            "audit_db": cfg.audit_db,
            "scope": _connector_scope_text(cfg),
            "sandbox": {
                "available": False,
                "enabled": _sandboxes_enabled(cfg),
                "legacy_standalone": legacy_standalone_configured(cfg),
            },
            "scanners": _scanner_status_map(cfg),
        }
    )

    if app.store:
        try:
            counts = app.store.get_counts(alert_count_seconds=_ALERT_COUNT_SECONDS)
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

    from defenseclaw.gateway import OrchestratorClient, gateway_api_client_host

    bind = gateway_api_client_host(cfg)
    try:
        client = OrchestratorClient(
            host=bind,
            port=cfg.gateway.api_port,
            token=cfg.gateway.resolved_token(),
        )
        health = _fetch_runtime_bound_health(client, cfg)
    except Exception:
        health = None
    running = health is not None
    payload["sidecar"] = {"running": running}
    payload["connectors"] = _connector_roster(cfg, health=health)
    payload["application_protection"] = _application_protection_status(cfg, health=health)
    payload["semantic_routing"] = _semantic_routing_status(cfg, health=health)
    payload["hook_guardian"] = _hook_guardian_status(cfg)
    payload["native_otlp_delivery"] = _native_delivery_summary(cfg).as_json()

    return payload


def _sandboxes_enabled(cfg) -> bool:
    # Identity check, as doctor's: a stand-in config must not read as on.
    return getattr(getattr(cfg, "openshell", None), "enabled", False) is True


def _host_is_windows() -> bool:
    from defenseclaw.platform_support import host_os

    return host_os() == "windows"
