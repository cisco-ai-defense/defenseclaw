# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Manage the bundled local observability stack on Windows, macOS, and Linux."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any, TypeVar

import click

from defenseclaw import ux
from defenseclaw.audit_actions import ACTION_SETUP_LOCAL_OBSERVABILITY
from defenseclaw.bundle_refresh import RefreshResult, refresh_local_observability_stack
from defenseclaw.commands.redaction_status import print_redaction_status_hint
from defenseclaw.config import config_path_for_data_dir, locked_config_yaml, write_config_yaml_secure
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.observability.local_stack import (
    CONTRACT,
    LocalStackController,
    LocalStackError,
    resolve_stack_dir,
)
from defenseclaw.platform_support import local_observability_stack_supported

_PRESET_ID = "local-otlp"
_AUDIT_SINK_PRESET_ID = "otlp"
_AUDIT_SINK_NAME = "local-otlp-logs"
_DEFAULT_SIGNALS: tuple[str, ...] = ("traces", "metrics", "logs")


@click.group(
    "local-observability",
    invoke_without_command=True,
    short_help="Run the bundled Prom/Loki/Tempo/Grafana stack on loopback.",
)
@click.pass_context
def local_observability(ctx: click.Context) -> None:
    """Drive the bundled local observability stack.

    Bare invocation remains an alias for ``up``.
    """
    if not local_observability_stack_supported():
        raise click.ClickException(
            "Bundled local observability is unavailable on this operating system."
        )
    if ctx.invoked_subcommand is None:
        ctx.invoke(up_cmd)


@local_observability.command("up")
@click.option(
    "--timeout",
    type=click.IntRange(min=1),
    default=180,
    show_default=True,
    help="Readiness wait budget in seconds.",
)
@click.option("--no-wait", is_flag=True, help="Start containers without enabling config.")
@click.option("--no-config", is_flag=True, help="Do not write config.yaml.")
@click.option("--endpoint", default=None, help="Override the configured OTLP endpoint.")
@click.option(
    "--signals",
    default=",".join(_DEFAULT_SIGNALS),
    show_default=True,
    help="Comma-separated OTel signals to enable (traces,metrics,logs).",
)
@click.option("--service-name", default="defenseclaw", show_default=True)
@click.option(
    "--with-audit-sink/--no-audit-sink",
    "with_audit_sink",
    default=True,
    show_default=True,
)
@click.option(
    "--refresh-bundle/--no-refresh-bundle",
    "refresh_bundle",
    default=True,
    show_default=True,
)
@click.option(
    "--refresh-config/--no-refresh-config",
    "refresh_config",
    default=True,
    show_default=True,
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
    with_audit_sink: bool,
    refresh_bundle: bool,
    refresh_config: bool,
) -> None:
    """Start the stack, verify readiness, then wire the gateway config."""
    controller = _resolve_controller(app.cfg.data_dir)
    _run_controller_check(controller.preflight, "Docker preflight")

    if refresh_bundle:
        refresh_result = _refresh_and_maybe_restart_local_observability(
            app.cfg.data_dir,
            refresh_config=refresh_config,
            controller=controller,
        )
        if refresh_result.errors:
            raise SystemExit(1)
        controller = _resolve_controller(app.cfg.data_dir)

    click.echo(f"  {ux.dim('→')} Starting local observability stack (this takes ~30s)...")
    try:
        started = controller.up(timeout=timeout, wait=not no_wait)
    except LocalStackError as exc:
        click.echo(f"  error: {exc}", err=True)
        raise SystemExit(1) from exc

    contract = started.contract
    otlp_endpoint = endpoint or contract["otlp_endpoint"]
    otlp_protocol = contract["otlp_protocol"]
    sink_applied = False

    if no_wait and not no_config:
        ux.warn(
            "--no-wait skips readiness verification; config.yaml was not changed. "
            "Run 'defenseclaw setup local-observability up' after the stack is ready."
        )
        no_config = True

    if not no_config:
        try:
            _apply_local_observability_config_transaction(
                app,
                endpoint=otlp_endpoint,
                protocol=otlp_protocol,
                signals=_parse_signals(signals),
                service_name=service_name,
                with_audit_sink=with_audit_sink,
            )
            sink_applied = with_audit_sink
        except BaseException as exc:
            _reload_cfg_from_data_dir(app)
            if isinstance(exc, KeyboardInterrupt):
                raise
            click.echo(
                f"  error: configuration failed; config.yaml is unchanged: {exc}",
                err=True,
            )
            raise SystemExit(1) from exc

        click.echo(
            f"  {ux.bold('Config updated:')} otel.enabled=true, endpoint={otlp_endpoint}"
        )
        if sink_applied:
            click.echo(
                f"  {ux.bold('Config updated:')} "
                f"audit_sinks[{_AUDIT_SINK_NAME}].enabled=true, kind=otlp_logs"
            )

    _print_stack_summary(contract, audit_sink_enabled=sink_applied, cfg=app.cfg)
    if app.logger:
        app.logger.log_action(
            ACTION_SETUP_LOCAL_OBSERVABILITY,
            "stack",
            (
                f"action=up endpoint={otlp_endpoint} protocol={otlp_protocol} "
                f"readiness={'true' if started.readiness_verified else 'skipped'} "
                f"audit_sink={'true' if sink_applied else 'false'}"
            ),
        )


@local_observability.command("down")
@click.option("--disable-config", is_flag=True, help="Also disable the local OTLP config.")
@pass_ctx
def down_cmd(app: AppContext, disable_config: bool) -> None:
    """Stop the stack while preserving its named volumes."""
    controller = _resolve_controller(app.cfg.data_dir)
    _run_controller_check(controller.down, "Docker Compose down")

    sink_disabled = False
    if disable_config:
        try:
            destination_disabled, sink_disabled = (
                _disable_local_observability_config_transaction(app)
            )
            _reload_cfg_from_data_dir(app)
        except BaseException as exc:
            _reload_cfg_from_data_dir(app)
            if isinstance(exc, KeyboardInterrupt):
                raise
            click.echo(
                f"  error: config disable failed; config.yaml is unchanged: {exc}",
                err=True,
            )
            raise SystemExit(1) from exc
        if destination_disabled or sink_disabled:
            click.echo(f"  {ux.bold('Config updated:')} local observability disabled")
        else:
            click.echo("  Config unchanged: no local observability destination was present.")

    if app.logger:
        app.logger.log_action(
            ACTION_SETUP_LOCAL_OBSERVABILITY,
            "stack",
            f"action=down audit_sink_disabled={'true' if sink_disabled else 'false'}",
        )


@local_observability.command("reset")
@click.option("--yes", is_flag=True, help="Skip the destructive-action confirmation prompt.")
@pass_ctx
def reset_cmd(app: AppContext, yes: bool) -> None:
    """Stop the stack and delete only its verified named volumes."""
    if not yes and not click.confirm(
        "  This wipes Prometheus / Loki / Tempo / Grafana data. Continue?",
        default=False,
    ):
        click.echo("  Aborted.")
        return
    controller = _resolve_controller(app.cfg.data_dir)
    _run_controller_check(
        lambda: controller.reset(confirmed=True), "Docker Compose reset"
    )
    if app.logger:
        app.logger.log_action(
            ACTION_SETUP_LOCAL_OBSERVABILITY, "stack", "action=reset"
        )


@local_observability.command("status")
@pass_ctx
def status_cmd(app: AppContext) -> None:
    """Show Compose state and per-service readiness probes."""
    controller = _resolve_controller(app.cfg.data_dir)
    output = _run_controller_check(controller.status, "Docker Compose status")
    click.echo(output, nl=False)


@local_observability.command("logs")
@click.option("--service", default=None, help="Compose service to target (default: all).")
@click.option("--follow/--no-follow", default=False, help="Stream logs until Ctrl+C.")
@pass_ctx
def logs_cmd(app: AppContext, service: str | None, follow: bool) -> None:
    """Show bounded logs, or stream them until cancellation."""
    controller = _resolve_controller(app.cfg.data_dir)
    output = _run_controller_check(
        lambda: controller.logs(service=service, follow=follow), "Docker Compose logs"
    )
    if output:
        click.echo(output, nl=False)


@local_observability.command("url")
@click.option("--json", "emit_json", is_flag=True, help="Emit machine-readable JSON.")
@pass_ctx
def url_cmd(_app: AppContext, emit_json: bool) -> None:
    """Print the Grafana, Prometheus, Tempo, Loki, and OTLP endpoints."""
    if emit_json:
        click.echo(json.dumps(CONTRACT, separators=(",", ":")))
        return
    click.echo(_format_urls(CONTRACT))


@local_observability.command("env")
@click.option("--json", "emit_json", is_flag=True, help="Emit machine-readable JSON.")
@pass_ctx
def env_cmd(_app: AppContext, emit_json: bool) -> None:
    """Print environment values that point a gateway at the local collector."""
    values = LocalStackController.environment_contract()
    if emit_json:
        click.echo(json.dumps(values, separators=(",", ":")))
        return
    for key, value in values.items():
        click.echo(f"{key}={value}")


T = TypeVar("T")


def _run_controller_check(operation: Callable[[], T], description: str) -> T:
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
    controller: LocalStackController | None = None,
) -> RefreshResult:
    """Stop an owned running project, securely refresh assets, then return."""
    active = controller or _resolve_controller(data_dir)
    was_running = _run_controller_check(active.is_running, "Docker project check")
    stopped = False
    if was_running:
        click.echo(
            f"  {ux.dim('→')} Stopping running observability stack to refresh bundle..."
        )
        _run_controller_check(active.down, "Docker Compose down before refresh")
        stopped = True

    result = refresh_local_observability_stack(data_dir, refresh_config=refresh_config)
    result.was_running = was_running
    result.stopped = stopped

    if result.skipped_reason:
        click.echo(f"  {ux.dim('→')} Bundle refresh skipped: {result.skipped_reason}")
        return result
    if result.errors:
        for error in result.errors[:5]:
            click.echo(f"  error: bundle refresh: {error}", err=True)
        return result
    if result.refreshed:
        click.echo(
            f"  {ux.bold('Bundle refreshed:')} ~/.defenseclaw/observability-stack/ "
            f"({len(result.refreshed_paths)} files updated, "
            f"{len(result.preserved_paths)} preserved)"
        )
    else:
        click.echo(
            f"  {ux.dim('→')} Bundle refresh: no changes "
            "(seeded copy already matches bundle)"
        )
    if result.preserved_paths and not refresh_config:
        preserved = ", ".join(sorted(result.preserved_paths)[:5])
        if len(result.preserved_paths) > 5:
            preserved += ", ..."
        click.echo(
            f"  {ux.dim('→')} Preserved local observability config: {preserved}. "
            "Omit --no-refresh-config, or pass --refresh-config, to overwrite it."
        )
    return result


def _apply_local_observability_config_transaction(
    app: AppContext,
    *,
    endpoint: str,
    protocol: str,
    signals: tuple[str, ...],
    service_name: str,
    with_audit_sink: bool,
) -> None:
    """Build both local destinations in memory and commit exactly once."""
    from defenseclaw.observability.presets import resolve_preset
    from defenseclaw.observability.writer import (
        _advance_named_otel_config_version,
        _apply_audit_sink_preset,
        _apply_otel_preset,
        _load_yaml,
        _resolve_inputs,
    )

    cfg_path = str(config_path_for_data_dir(app.cfg.data_dir))
    otel_preset = resolve_preset(_PRESET_ID)
    otel_inputs = _resolve_inputs(
        otel_preset,
        {
            "endpoint": endpoint,
            "protocol": protocol,
            "insecure": "true",
            "service_name": service_name,
        },
    )
    sink_preset = resolve_preset(_AUDIT_SINK_PRESET_ID)
    sink_inputs = _resolve_inputs(
        sink_preset,
        {"endpoint": endpoint, "protocol": protocol, "insecure": "true"},
    )
    with locked_config_yaml(cfg_path):
        raw = _load_yaml(cfg_path)
        warnings: list[str] = []
        _apply_otel_preset(
            raw,
            otel_preset,
            otel_inputs,
            data_dir=app.cfg.data_dir,
            enabled=True,
            signals=signals,  # type: ignore[arg-type]
            dest_name="local-observability",
            warnings=warnings,
        )
        if any(warning.startswith("migrated flat OTel exporter") for warning in warnings):
            _advance_named_otel_config_version(raw)
        if with_audit_sink:
            _apply_audit_sink_preset(
                raw,
                sink_preset,
                sink_inputs,
                name=_AUDIT_SINK_NAME,
                enabled=True,
                warnings=warnings,
            )
        write_config_yaml_secure(cfg_path, raw)
    _reload_cfg_from_data_dir(app)


def _disable_local_observability_config_transaction(
    app: AppContext,
) -> tuple[bool, bool]:
    """Disable both local routes under one config lock and one atomic write."""
    from defenseclaw.observability.writer import _find_otel_destination, _find_sink, _load_yaml

    cfg_path = str(config_path_for_data_dir(app.cfg.data_dir))
    with locked_config_yaml(cfg_path):
        raw = _load_yaml(cfg_path)
        destination_disabled = False
        sink_disabled = False
        destination = _find_otel_destination(raw, "local-observability")
        otel = raw.get("otel")
        if destination is not None and isinstance(otel, dict):
            destination["enabled"] = False
            destinations = otel.get("destinations") or []
            otel["enabled"] = any(
                isinstance(item, dict) and bool(item.get("enabled", False))
                for item in destinations
            )
            destination_disabled = True
        elif isinstance(otel, dict) and not isinstance(otel.get("destinations"), list):
            otel["enabled"] = False
            destination_disabled = True
        sink = _find_sink(raw, _AUDIT_SINK_NAME)
        if sink is not None:
            sink["enabled"] = False
            sink_disabled = True
        if destination_disabled or sink_disabled:
            write_config_yaml_secure(cfg_path, raw)
    return destination_disabled, sink_disabled


def _reload_cfg_from_data_dir(app: AppContext) -> None:
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


def _parse_signals(raw: str) -> tuple[str, ...]:
    allowed = {"traces", "metrics", "logs"}
    parts = tuple(item.strip() for item in raw.split(",") if item.strip())
    invalid = [item for item in parts if item not in allowed]
    if invalid:
        raise click.ClickException(
            f"unknown signal(s) {invalid}; allowed: {sorted(allowed)}"
        )
    return parts or _DEFAULT_SIGNALS


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


def _print_stack_summary(
    contract: dict[str, str],
    *,
    audit_sink_enabled: bool = False,
    cfg: Any = None,
) -> None:
    click.echo()
    ux.section("Local observability stack is up")
    for line in _format_urls(contract).splitlines():
        click.echo(f"    {line}")
    click.echo()
    if audit_sink_enabled:
        ux.ok(f"Audit sink: {_AUDIT_SINK_NAME} (otlp_logs) → local OTLP endpoint.")
    else:
        ux.subhead("Audit sink: not configured (--no-audit-sink / --no-config).")
    click.echo()
    print_redaction_status_hint(cfg)
    click.echo()
    ux.section("Next steps")
    click.echo("    defenseclaw-gateway restart")
    click.echo("    defenseclaw setup local-observability status")
    click.echo("    defenseclaw setup local-observability down   # stop (keeps data)")
    click.echo("    defenseclaw setup local-observability reset  # stop + wipe owned data")
    click.echo()


__all__ = ["local_observability"]
