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

"""First-class Galileo Cloud and self-hosted observability setup."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlparse, urlunparse

import click

from defenseclaw import ux
from defenseclaw.commands.cmd_setup_observability import (
    _add_v8_destination,
    _remove_v8_destination,
    _require_v8_operator_status,
    _set_v8_destination_enabled,
)
from defenseclaw.config import config_path_for_data_dir
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.observability import resolve_preset
from defenseclaw.observability.trace_canary import TraceCanaryError, run_trace_canary

_DESTINATION = "galileo"
_KEY_ENV = "GALILEO_API_KEY"
_CLOUD_TRACE_ENDPOINT = "https://api.galileo.ai/otel/traces"


@click.group("galileo", invoke_without_command=True)
@click.option(
    "--deployment",
    type=click.Choice(["cloud", "self-hosted"]),
    default="cloud",
    show_default=True,
)
@click.option("--project", default=None, help="Galileo project name or ID")
@click.option("--logstream", default=None, help="Galileo Log stream name or ID")
@click.option(
    "--console-url",
    default=None,
    help="Self-hosted Galileo console URL; the API trace endpoint is derived from it.",
)
@click.option(
    "--trace-endpoint",
    default=None,
    help="Exact Galileo OTLP HTTP traces endpoint (overrides URL derivation).",
)
@click.option(
    "--persist-api-key",
    is_flag=True,
    help="Copy GALILEO_API_KEY from the environment into ~/.defenseclaw/.env.",
)
@click.option("--disabled", is_flag=True, help="Write the destination disabled.")
@click.option("--dry-run", is_flag=True, help="Preview config changes without writing.")
@click.option("--non-interactive", is_flag=True, help="Require all values through flags/environment.")
@click.pass_context
def galileo(
    ctx: click.Context,
    deployment: str,
    project: str | None,
    logstream: str | None,
    console_url: str | None,
    trace_endpoint: str | None,
    persist_api_key: bool,
    disabled: bool,
    dry_run: bool,
    non_interactive: bool,
) -> None:
    """Configure Galileo OTLP trace export.

    With no subcommand this runs the guided cloud/self-hosted setup. Galileo
    receives traces only; local-observability can remain enabled alongside it.
    """

    if ctx.invoked_subcommand is not None:
        return
    app = ctx.find_object(AppContext)
    if app is None:
        raise click.ClickException("DefenseClaw application context is unavailable")

    if not non_interactive:
        ux.section("Galileo Observability Setup")
        deployment = click.prompt(
            "  Deployment",
            type=click.Choice(["cloud", "self-hosted"]),
            default=deployment,
        )
        if deployment == "self-hosted" and not console_url and not trace_endpoint:
            console_url = click.prompt("  Galileo console URL")
        project = project or click.prompt("  Galileo project name or ID")
        logstream = logstream or click.prompt("  Galileo Log stream", default="default")
        api_key: str | None = None
        if not _resolve_secret(app.cfg.data_dir):
            api_key = click.prompt("  Galileo API key", hide_input=True, confirmation_prompt=True)
    else:
        api_key = None

    if not project:
        raise click.ClickException("--project is required")
    if not logstream:
        raise click.ClickException("--logstream is required")
    project = _validate_routing_header("project", project)
    logstream = _validate_routing_header("logstream", logstream)
    endpoint = _resolve_trace_endpoint(deployment, console_url, trace_endpoint)
    resolved_key = api_key or _resolve_secret(app.cfg.data_dir)
    if not resolved_key:
        raise click.ClickException(f"{_KEY_ENV} is not set; export it or omit --non-interactive for a hidden prompt")

    inputs = {"endpoint": endpoint, "project": project, "logstream": logstream}
    v8_status = _require_v8_operator_status(app.cfg.data_dir)
    existed = any(destination.name == _DESTINATION for destination in v8_status.destinations)
    try:
        result, warnings = _add_v8_destination(
            app.cfg.data_dir,
            resolve_preset("galileo"),
            inputs,
            name=_DESTINATION,
            enabled=not disabled,
            signals=("traces",),
            token_value=resolved_key if api_key or persist_api_key else None,
            target=None,
            dry_run=dry_run,
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    _print_v8_setup_result(
        result,
        warnings,
        deployment=deployment,
        endpoint=endpoint,
        project=project,
        logstream=logstream,
        dry_run=dry_run,
        existed=existed,
    )


@galileo.command("status")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON")
@pass_ctx
def status_cmd(app: AppContext, as_json: bool) -> None:
    """Show the configured Galileo destination without secret values."""

    payload = _v8_status_payload(app, _require_v8_operator_status(app.cfg.data_dir))
    _print_status_payload(payload, as_json=as_json)


@galileo.command("enable")
@pass_ctx
def enable_cmd(app: AppContext) -> None:
    """Enable the Galileo destination."""

    _require_v8_operator_status(app.cfg.data_dir)
    _set_v8_destination_enabled(app.cfg.data_dir, _DESTINATION, True, "")


@galileo.command("disable")
@pass_ctx
def disable_cmd(app: AppContext) -> None:
    """Disable Galileo without deleting its configuration."""

    _require_v8_operator_status(app.cfg.data_dir)
    _set_v8_destination_enabled(app.cfg.data_dir, _DESTINATION, False, "")


@galileo.command("remove")
@click.option("--yes", is_flag=True, help="Skip confirmation")
@pass_ctx
def remove_cmd(app: AppContext, yes: bool) -> None:
    """Remove the Galileo destination; the shared API key is preserved."""

    if not yes and not click.confirm("  Remove the Galileo OTLP destination?", default=False):
        click.echo("  Aborted.")
        return
    _require_v8_operator_status(app.cfg.data_dir)
    _remove_v8_destination(app.cfg.data_dir, _DESTINATION, "")
    click.echo("  GALILEO_API_KEY was preserved.")


@galileo.command("test")
@click.option("--timeout", type=float, default=15.0, show_default=True)
@pass_ctx
def test_cmd(app: AppContext, timeout: float) -> None:
    """Emit and acknowledge a content-free trace through Galileo."""

    status = _require_v8_operator_status(app.cfg.data_dir)
    destination = next(
        (item for item in status.destinations if item.name == _DESTINATION),
        None,
    )
    if destination is None:
        raise click.ClickException("Galileo is not configured")
    if not destination.enabled:
        raise click.ClickException("Galileo is disabled; enable it before running the canary")
    _test_galileo_trace_canary(app.cfg.data_dir, timeout)


def _test_galileo_trace_canary(data_dir: str, timeout: float) -> None:
    try:
        result = run_trace_canary(
            destination=_DESTINATION,
            config_path=str(config_path_for_data_dir(data_dir)),
            data_dir=data_dir,
            timeout=timeout,
        )
    except TraceCanaryError as exc:
        raise click.ClickException(
            f"Galileo runtime canary failed ({exc.failure_class}): {exc.message}"
        ) from exc
    click.echo(f"  {result.destination}: runtime canary acknowledged")
    click.echo(f"  trace_id={result.trace_id}; generation={result.generation}")



def _print_v8_setup_result(
    result,
    warnings: list[str],
    *,
    deployment: str,
    endpoint: str,
    project: str,
    logstream: str,
    dry_run: bool,
    existed: bool,
) -> None:
    """Render one secret-free result from the canonical v8 writer."""

    click.echo()
    ux.section("Galileo configured" if not dry_run else "Galileo configuration preview")
    click.echo(f"  Action:      {'UPDATE' if existed else 'ADD'}")
    click.echo(f"  Deployment:  {deployment}")
    click.echo(f"  Destination: {_DESTINATION}")
    click.echo(f"  Endpoint:    {endpoint}")
    click.echo(f"  Project:     {project}")
    click.echo(f"  Log stream:  {logstream}")
    click.echo("  Signals:     traces")
    click.echo("  Delivery:    real-time after each completed model/tool operation (≤1s batch delay)")
    click.echo(f"  Config:      v8 ({'changed' if result.changed else 'already configured'})")
    for warning in warnings:
        ux.warn(warning, indent="  ")
    if not dry_run:
        ux.subhead("Next: defenseclaw setup galileo test")


def _v8_status_payload(app: AppContext, status) -> dict:
    """Build a v8 Galileo status solely from masked plan and safe health."""

    destination = next(
        (item for item in status.destinations if item.name == _DESTINATION),
        None,
    )
    selected = set(destination.selected_signals) if destination else set()
    payload = {
        "configured": destination is not None,
        "name": _DESTINATION,
        "enabled": bool(destination and destination.enabled),
        "endpoint": destination.endpoint if destination else "",
        "signals": {
            "traces": "traces" in selected,
            "metrics": "metrics" in selected,
            "logs": "logs" in selected,
        },
        "api_key": "configured" if _resolve_secret(app.cfg.data_dir) else "missing",
        "config_version": 8,
    }
    if destination is None:
        return payload

    from defenseclaw.observability.v8_status import destination_health_from_gateway

    health = destination_health_from_gateway(_gateway_health_snapshot(app)).get(_DESTINATION)
    if health is None:
        return payload
    safe_health = {
        key: value
        for key, value in {
            "state": health.state,
            "reason": health.reason,
            "queue_items": health.queue_items,
            "queue_bytes": health.queue_bytes,
            "queue_max_items": health.queue_max_items,
            "queue_max_bytes": health.queue_max_bytes,
            "dropped": health.dropped,
            "last_success": health.last_success,
            "last_failure": health.last_failure,
            "last_error_class": health.last_error_class,
        }.items()
        if value not in (None, "")
    }
    if safe_health:
        payload["health"] = safe_health
    return payload


def _print_status_payload(payload: dict, *, as_json: bool) -> None:
    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    ux.section("Galileo status")
    for key, value in payload.items():
        click.echo(f"  {key.replace('_', ' ').title():<12} {value}")


def _gateway_api_base(app: AppContext) -> str:
    host = str(getattr(app.cfg.gateway, "api_bind", "") or "127.0.0.1")
    if host in {"0.0.0.0", "::", "[::]", "localhost"}:
        host = "127.0.0.1"
    port = int(getattr(app.cfg.gateway, "api_port", 18970) or 18970)
    return f"http://{host}:{port}"




def _gateway_health_snapshot(app: AppContext) -> dict:
    request = urllib.request.Request(_gateway_api_base(app) + "/health", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=1.5) as response:  # noqa: S310 - loopback gateway
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
        return {}
    return body if isinstance(body, dict) else {}




def _resolve_trace_endpoint(deployment: str, console_url: str | None, override: str | None) -> str:
    if override:
        return _validate_https_endpoint(override)
    if deployment == "cloud":
        return _CLOUD_TRACE_ENDPOINT
    if not console_url:
        raise click.ClickException("--console-url or --trace-endpoint is required for self-hosted Galileo")
    parsed = urlparse(console_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise click.ClickException("self-hosted Galileo console URL must be credential-free https://")
    host = parsed.hostname
    if host.startswith("console-"):
        host = "api-" + host[len("console-") :]
    elif host.startswith("console."):
        host = "api." + host[len("console.") :]
    elif host == "console":
        host = "api"
    else:
        raise click.ClickException("cannot derive Galileo API hostname; pass --trace-endpoint explicitly")
    if parsed.port:
        host = f"{host}:{parsed.port}"
    path = parsed.path.rstrip("/") + "/otel/traces"
    return urlunparse(("https", host, path, "", "", ""))


def _validate_https_endpoint(value: str) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise click.ClickException("Galileo trace endpoint must be credential-free https:// without query or fragment")
    return value.rstrip("/")


def _validate_routing_header(name: str, value: str) -> str:
    """Reject metadata that the Go secret-header expander could reinterpret."""

    value = value.strip()
    if not value:
        raise click.ClickException(f"Galileo {name} must not be empty")
    if len(value) > 512:
        raise click.ClickException(f"Galileo {name} must be 512 characters or fewer")
    if "$" in value or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise click.ClickException(f"Galileo {name} must not contain '$' or control characters")
    return value




def _dotenv_value(data_dir: str, key: str) -> str:
    try:
        with open(os.path.join(data_dir, ".env")) as handle:
            for line in handle:
                if line.startswith(f"{key}="):
                    value = line.split("=", 1)[1].strip()
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                        value = value[1:-1]
                    return value
    except OSError:
        pass
    return ""


def _resolve_secret(data_dir: str) -> str:
    return os.environ.get(_KEY_ENV, "") or _dotenv_value(data_dir, _KEY_ENV)
