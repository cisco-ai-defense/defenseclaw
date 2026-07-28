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

"""Native Docker Compose lifecycle for the bundled local OTel stack."""

from __future__ import annotations

import json as _json
import os
from collections.abc import Callable
from typing import Any, TypeVar

import click

from defenseclaw import ux
from defenseclaw.audit_actions import ACTION_SETUP_LOCAL_OBSERVABILITY
from defenseclaw.bundle_refresh import RefreshResult, refresh_local_observability_stack
from defenseclaw.commands.redaction_status import print_redaction_status_hint
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.observability.local_stack import (
    CONTRACT,
    LocalStackController,
    LocalStackError,
    resolve_stack_dir,
)

_PRESET_ID = "local-otlp"
_DEFAULT_SIGNALS: tuple[str, ...] = ("traces", "metrics", "logs")


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@click.group(
    "local-observability",
    invoke_without_command=True,
    short_help="Run the bundled Prom/Loki/Tempo/Grafana stack on loopback.",
)
@click.pass_context
def local_observability(ctx: click.Context) -> None:
    """Drive the bundled local observability stack.

    Provides a one-command path to the same compose stack that
    historically lived under ``deploy/observability/``. Subcommands:

    \b
      up       Start the stack, wait for readiness, wire config.yaml
      down     Stop containers, keep volumes
      reset    Stop + wipe all metric / log / trace data volumes
      status   Show compose ps + per-service readiness probes
      logs     Tail logs for one or all services
      url      Print the Grafana / Prometheus / Tempo / Loki URLs

    Bare invocation is an alias for ``up`` so ``defenseclaw setup
    local-observability`` matches the ergonomics of ``setup splunk
    --logs``.
    """
    if ctx.invoked_subcommand is None:
        ctx.invoke(up_cmd)


# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------


@local_observability.command("up")
@click.option(
    "--timeout",
    type=int,
    default=180,
    show_default=True,
    help="Readiness wait budget (seconds) for the stack's OTLP + Grafana ports.",
)
@click.option(
    "--no-wait",
    is_flag=True,
    help="Skip the readiness wait (container ps only).",
)
@click.option(
    "--no-config",
    is_flag=True,
    help=(
        "Do not write config.yaml. Useful for 'just start the containers' "
        "flows where a different canonical destination already owns routing."
    ),
)
@click.option(
    "--endpoint",
    default=None,
    help="Override the OTLP endpoint stamped into config.yaml (default: native stack contract).",
)
@click.option(
    "--signals",
    default=",".join(_DEFAULT_SIGNALS),
    show_default=True,
    help="Comma-separated canonical signals to enable (traces,metrics,logs).",
)
@click.option(
    "--service-name",
    default="defenseclaw",
    show_default=True,
    help="Value to stamp into observability.resource.attributes.service.name.",
)
@click.option(
    "--refresh-bundle/--no-refresh-bundle",
    "refresh_bundle",
    default=True,
    show_default=True,
    help=(
        "Before starting the stack, refresh ~/.defenseclaw/observability-stack/ "
        "from the wheel/repo bundle so newly-shipped controller / compose changes "
        "take effect. Operator-editable surfaces (Grafana dashboards, Prometheus "
        "rules, Loki/Tempo/OTel-Collector configs) are refreshed by default; "
        "pass --no-refresh-config to preserve local edits. If the stack is "
        "already running, it will be stopped, refreshed, and restarted "
        "automatically."
    ),
)
@click.option(
    "--refresh-config/--no-refresh-config",
    "refresh_config",
    default=True,
    show_default=True,
    help=(
        "When refreshing the bundle, overwrite operator-editable surfaces "
        "(grafana/, prometheus/, loki/, tempo/, otel-collector/) with the "
        "bundled versions. Pass --no-refresh-config to preserve local "
        "dashboard / rule / config edits."
    ),
)
@pass_ctx
def up_cmd(
    app: AppContext,
    timeout: int,
    no_wait: bool,
    no_config: bool,
    endpoint: str | None,
    signals: str,
    service_name: str,
    refresh_bundle: bool,
    refresh_config: bool,
) -> None:
    """Start the stack, wait for readiness, and wire the gateway config."""
    controller = _resolve_controller(app.cfg.data_dir)
    _run_native_controller(controller.preflight, "Docker preflight")

    if refresh_bundle:
        _refresh_and_maybe_restart_local_observability(
            app.cfg.data_dir,
            refresh_config=refresh_config,
            controller=controller,
        )

    click.echo(f"  {ux.dim('→')} Starting local observability stack (this takes ~30s)...")
    # Bundle refresh may replace the controller's Compose file. Resolve a fresh
    # controller so every platform launches the verified active copy.
    controller = _resolve_controller(app.cfg.data_dir)
    started = _run_native_controller(
        lambda: controller.up(timeout=timeout, wait=not no_wait),
        "Docker Compose up",
    )
    contract = started.contract

    otlp_endpoint = endpoint or str(contract.get("otlp_endpoint") or "127.0.0.1:4317")
    otlp_protocol = str(contract.get("otlp_protocol") or "grpc")

    logs_enabled = False
    if not no_config and not started.readiness_verified:
        click.echo(
            f"  {ux.dim('→')} Stack readiness was not verified; "
            "config.yaml was not changed. Run without --no-wait after the "
            "stack is ready to enable export."
        )
    elif not no_config:
        selected_signals = _parse_signals(signals)
        try:
            _apply_local_otlp_config(
                app,
                endpoint=otlp_endpoint,
                protocol=otlp_protocol,
                signals=selected_signals,
                service_name=service_name,
            )
        except click.ClickException:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise click.ClickException(
                f"local observability configuration failed; config.yaml is unchanged: {exc}"
            ) from exc
        click.echo(
            f"  {ux.bold('Config updated:')} observability.destinations[local-observability], endpoint={otlp_endpoint}"
        )

        logs_enabled = "logs" in selected_signals

    _print_stack_summary(contract, logs_enabled=logs_enabled, cfg=app.cfg)

    if app.logger:
        app.logger.log_action(
            ACTION_SETUP_LOCAL_OBSERVABILITY,
            "stack",
            (f"action=up endpoint={otlp_endpoint} protocol={otlp_protocol} logs={'true' if logs_enabled else 'false'}"),
        )


# ---------------------------------------------------------------------------
# down / reset
# ---------------------------------------------------------------------------


@local_observability.command("down")
@click.option(
    "--disable-config",
    is_flag=True,
    help="Also disable the canonical local-observability destination.",
)
@pass_ctx
def down_cmd(app: AppContext, disable_config: bool) -> None:
    """Stop the stack (volumes preserved)."""
    controller = _resolve_controller(app.cfg.data_dir)
    _run_native_controller(controller.down, "Docker Compose down")

    if disable_config:
        from defenseclaw.commands.cmd_setup_observability import (
            _require_v8_operator_status,
            _set_v8_destination_enabled,
        )

        _require_v8_operator_status(app.cfg.data_dir)
        _set_v8_destination_enabled(app.cfg.data_dir, "local-observability", False, "")
        click.echo(f"  {ux.bold('Config updated:')} observability.destinations[local-observability].enabled=false")

    if app.logger:
        app.logger.log_action(
            ACTION_SETUP_LOCAL_OBSERVABILITY,
            "stack",
            "action=down",
        )


@local_observability.command("reset")
@click.option(
    "--yes",
    is_flag=True,
    help="Skip the destructive-action confirmation prompt.",
)
@pass_ctx
def reset_cmd(app: AppContext, yes: bool) -> None:
    """Stop the stack and drop all persisted metric / log / trace volumes."""
    if not yes and not click.confirm(
        "  This wipes Prometheus / Loki / Tempo / Grafana data. Continue?",
        default=False,
    ):
        click.echo("  Aborted.")
        return

    controller = _resolve_controller(app.cfg.data_dir)
    _run_native_controller(
        lambda: controller.reset(confirmed=True),
        "Docker Compose reset",
    )

    if app.logger:
        app.logger.log_action(
            ACTION_SETUP_LOCAL_OBSERVABILITY,
            "stack",
            "action=reset",
        )


# ---------------------------------------------------------------------------
# status / logs / url
# ---------------------------------------------------------------------------


@local_observability.command("status")
@pass_ctx
def status_cmd(app: AppContext) -> None:
    """Show compose ps and per-service readiness probes."""
    controller = _resolve_controller(app.cfg.data_dir)
    output = _run_native_controller(controller.status, "Docker Compose status")
    click.echo(output, nl=False)


@local_observability.command("logs")
@click.option("--service", default=None, help="Compose service to target (default: all).")
@click.option("--follow/--no-follow", default=False, help="Stream logs until Ctrl+C.")
@pass_ctx
def logs_cmd(app: AppContext, service: str | None, follow: bool) -> None:
    """Tail logs from the running stack."""
    controller = _resolve_controller(app.cfg.data_dir)
    output = _run_native_controller(
        lambda: controller.logs(service=service, follow=follow),
        "Docker Compose logs",
    )
    if output:
        click.echo(output, nl=False)


@local_observability.command("url")
@click.option("--json", "emit_json", is_flag=True, help="Emit machine-readable JSON.")
@pass_ctx
def url_cmd(_app: AppContext, emit_json: bool) -> None:
    """Print the Grafana / Prometheus / Tempo / Loki URLs."""
    if emit_json:
        click.echo(_json.dumps(CONTRACT, separators=(",", ":")))
        return
    click.echo(_format_urls(CONTRACT))


@local_observability.command("env")
@click.option("--json", "emit_json", is_flag=True, help="Emit machine-readable JSON.")
@pass_ctx
def env_cmd(_app: AppContext, emit_json: bool) -> None:
    """Print environment values that point a gateway at the local collector."""
    values = LocalStackController.environment_contract()
    if emit_json:
        click.echo(_json.dumps(values, separators=(",", ":")))
        return
    for key, value in values.items():
        click.echo(f"{key}={value}")


# ---------------------------------------------------------------------------
# Internals — native controller
# ---------------------------------------------------------------------------


T = TypeVar("T")


def _run_native_controller(operation: Callable[[], T], description: str) -> T:
    try:
        return operation()
    except LocalStackError as exc:
        click.echo(f"  error: {description}: {exc}", err=True)
        raise SystemExit(1) from exc


def _resolve_controller(data_dir: str) -> LocalStackController:
    try:
        return LocalStackController(resolve_stack_dir(data_dir))
    except LocalStackError as exc:
        click.echo(f"  error: {exc}", err=True)
        raise SystemExit(1) from exc


def _refresh_and_maybe_restart_local_observability(
    data_dir: str,
    *,
    refresh_config: bool,
    controller: LocalStackController,
) -> RefreshResult:
    """Refresh the seeded observability stack, stopping any running stack first.

    Sequence:

    1. Detect a running ``defenseclaw-observability`` compose project.
    2. If running, invoke the native controller's ``down`` operation so the
       compose project releases its container names. Volumes
       (Grafana / Prometheus / Loki / Tempo data) survive ``down`` so
       the operator's history is preserved across the bounce.
    3. Refresh ``~/.defenseclaw/observability-stack/`` from the bundle.
       Operator-editable config surfaces (dashboards, rules, OTel
       collector config) are refreshed by default; pass
       ``refresh_config=False`` to preserve them.
    4. The caller then constructs a fresh controller and runs ``up`` so the
       bundle is what materializes the next stack.

    Best-effort throughout: refresh failures or a missing bundle are
    surfaced as warnings, never raised — the operator can still bring
    the stack up against the existing seeded copy.
    """
    was_running = _run_native_controller(controller.is_running, "Docker project check")
    stopped = False
    if was_running:
        click.echo(f"  {ux.dim('→')} Stopping running observability stack to refresh bundle...")
        _run_native_controller(
            controller.down,
            "Docker Compose down before refresh",
        )
        stopped = True

    result = refresh_local_observability_stack(
        data_dir,
        refresh_config=refresh_config,
    )
    result.was_running = was_running
    result.stopped = stopped

    if result.skipped_reason:
        click.echo(f"  {ux.dim('→')} Bundle refresh skipped: {result.skipped_reason}")
        return result
    if result.errors:
        for err in result.errors[:3]:
            click.echo(f"  warning: refresh: {err}")
        if stopped:
            click.echo(f"  {ux.dim('→')} Restarting previously running observability stack after refresh failure...")
            _run_native_controller(
                lambda: controller.up(timeout=180, wait=False),
                "Docker Compose restart after refresh failure",
            )
    if result.refreshed:
        count = len(result.refreshed_paths)
        preserved_count = len(result.preserved_paths)
        click.echo(
            f"  {ux.bold('Bundle refreshed:')} ~/.defenseclaw/observability-stack/ "
            f"({count} file{'s' if count != 1 else ''} updated, "
            f"{preserved_count} preserved)"
        )
    else:
        click.echo(f"  {ux.dim('→')} Bundle refresh: no changes (seeded copy already matches bundle)")
    if result.preserved_paths and not refresh_config:
        preserved = ", ".join(sorted(result.preserved_paths)[:5])
        if len(result.preserved_paths) > 5:
            preserved = f"{preserved}, ..."
        click.echo(
            "  "
            + ux.dim("→")
            + " Preserved local observability config: "
            + preserved
            + ". Omit --no-refresh-config, or pass --refresh-config, to "
            + "overwrite dashboards/rules/config with the bundled versions."
        )
    return result


# ---------------------------------------------------------------------------
# Internals — config writer
# ---------------------------------------------------------------------------


def _apply_local_otlp_config(
    app: AppContext,
    *,
    endpoint: str,
    protocol: str,
    signals: tuple[str, ...],
    service_name: str,
) -> None:
    """Write one unified canonical v8 destination."""
    from defenseclaw.commands.cmd_setup_observability import _add_v8_destination, _require_v8_operator_status
    from defenseclaw.observability.presets import PRESETS
    from defenseclaw.observability.v8_yaml import V8YAMLMutation

    _require_v8_operator_status(app.cfg.data_dir)
    _add_v8_destination(
        app.cfg.data_dir,
        PRESETS[_PRESET_ID],
        {
            "endpoint": endpoint,
            "protocol": protocol,
            "insecure": "true",
            "service_name": service_name,
        },
        name="local-observability",
        enabled=True,
        signals=signals,
        token_value=None,
        target=None,
        dry_run=False,
        extra_mutations=[
            V8YAMLMutation.set(
                ("observability", "resource", "attributes", "service.name"),
                service_name,
            )
        ],
    )
    _reload_cfg_from_data_dir(app)


def _reload_cfg_from_data_dir(app: AppContext) -> None:
    """Reload app.cfg from the data dir (see cmd_setup.py for rationale)."""
    from defenseclaw import config as cfg_mod

    data_dir = app.cfg.data_dir
    previous = os.environ.get("DEFENSECLAW_HOME")
    os.environ["DEFENSECLAW_HOME"] = data_dir
    try:
        app.cfg = cfg_mod.load()
    finally:
        if previous is None:
            os.environ.pop("DEFENSECLAW_HOME", None)
        else:
            os.environ["DEFENSECLAW_HOME"] = previous


def _format_urls(contract: dict[str, str] | Any) -> str:
    return "\n".join(
        (
            f"Grafana:    {contract.get('grafana_url', CONTRACT['grafana_url'])}",
            f"Prometheus: {contract.get('prometheus_url', CONTRACT['prometheus_url'])}",
            f"Tempo API:  {contract.get('tempo_url', CONTRACT['tempo_url'])}",
            f"Loki API:   {contract.get('loki_url', CONTRACT['loki_url'])}",
            f"OTLP gRPC:  {contract.get('otlp_endpoint', CONTRACT['otlp_endpoint'])}",
            f"OTLP HTTP:  {contract.get('otlp_http_endpoint', CONTRACT['otlp_http_endpoint'])}",
        )
    )


def _parse_signals(raw: str) -> tuple[str, ...]:
    allowed = {"traces", "metrics", "logs"}
    parts = tuple(s.strip() for s in raw.split(",") if s.strip())
    bad = [p for p in parts if p not in allowed]
    if bad:
        click.echo(
            f"  error: unknown signal(s) {bad}; allowed: {sorted(allowed)}",
            err=True,
        )
        raise SystemExit(2)
    return parts or _DEFAULT_SIGNALS


def _print_stack_summary(
    contract: dict[str, Any],
    *,
    logs_enabled: bool = False,
    cfg: Any = None,
) -> None:
    click.echo()
    ux.section("Local observability stack is up")
    click.echo(f"    {ux.bold('Grafana:')}    {contract.get('grafana_url', 'http://localhost:3000')}  (admin / admin)")
    click.echo(f"    {ux.bold('Prometheus:')} {contract.get('prometheus_url', 'http://localhost:9090')}")
    click.echo(f"    {ux.bold('Tempo API:')}  {contract.get('tempo_url', 'http://localhost:3200')}")
    click.echo(f"    {ux.bold('Loki API:')}   {contract.get('loki_url', 'http://localhost:3100')}")
    click.echo(f"    {ux.bold('OTLP gRPC:')}  {contract.get('otlp_endpoint', '127.0.0.1:4317')}")
    click.echo(f"    {ux.bold('OTLP HTTP:')}  {contract.get('otlp_http_endpoint', '127.0.0.1:4318')}")
    click.echo()
    if logs_enabled:
        ux.ok(
            "Logs:        canonical v8 logs enabled on local-observability "
            "(security, lifecycle, audit, and health families)."
        )
    else:
        ux.subhead("Logs:        not configured (--no-config or logs omitted from --signals).")
    click.echo()
    print_redaction_status_hint(cfg)
    click.echo()
    ux.section("Next steps")
    click.echo("    defenseclaw-gateway restart         # pick up the new config")
    click.echo("    defenseclaw setup local-observability status")
    click.echo("    defenseclaw setup local-observability down   # stop (keeps data)")
    click.echo("    defenseclaw setup local-observability reset  # stop + wipe data")
    click.echo()


__all__ = ["local_observability"]
