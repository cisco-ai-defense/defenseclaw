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

"""defenseclaw setup local-observability — drive the bundled OTel stack.

Thin Click wrapper around ``bin/openclaw-observability-bridge`` that
also wires ``~/.defenseclaw/config.yaml`` to point the gateway's OTLP
exporter at the local collector after a successful ``up``. Mirrors the
shape of ``defenseclaw setup splunk --logs`` so operators get one
consistent "docker-compose-backed local sidecar" flow across Splunk
and the Prom/Loki/Tempo/Grafana stack.

The bridge's ``up --output json`` contract is the single source of
truth for endpoint + protocol so we never drift between what the
container published and what we stamp into ``config.yaml``.
"""

from __future__ import annotations

import json as _json
import os
import shutil
import socket
import subprocess
from typing import Any

import click

from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.paths import local_observability_bridge_bin

_PRESET_ID = "local-otlp"
_DEFAULT_SIGNALS: tuple[str, ...] = ("traces", "metrics", "logs")
_STACK_PORTS: tuple[tuple[int, str], ...] = (
    (3000, "Grafana"),
    (3100, "Loki"),
    (3200, "Tempo"),
    (4317, "OTLP gRPC"),
    (4318, "OTLP HTTP"),
    (9090, "Prometheus"),
)


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
        "flows where a different preset already owns the otel: block."
    ),
)
@click.option(
    "--endpoint",
    default=None,
    help="Override the OTLP endpoint stamped into config.yaml (default: from bridge).",
)
@click.option(
    "--signals",
    default=",".join(_DEFAULT_SIGNALS),
    show_default=True,
    help="Comma-separated OTel signals to enable (traces,metrics,logs).",
)
@click.option(
    "--service-name",
    default="defenseclaw",
    show_default=True,
    help="Value to stamp into otel.resource.attributes.service.name.",
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
) -> None:
    """Start the stack, wait for readiness, and wire the gateway config."""
    if not _preflight_docker():
        raise SystemExit(1)

    bridge = _resolve_bridge(app.cfg.data_dir)

    click.echo("  Starting local observability stack (this takes ~30s)...")
    contract = _run_bridge_up(bridge, timeout=timeout, no_wait=no_wait)
    if contract is None:
        raise SystemExit(1)

    otlp_endpoint = endpoint or str(contract.get("otlp_endpoint") or "127.0.0.1:4317")
    otlp_protocol = str(contract.get("otlp_protocol") or "grpc")

    if not no_config:
        _apply_local_otlp_config(
            app,
            endpoint=otlp_endpoint,
            protocol=otlp_protocol,
            signals=_parse_signals(signals),
            service_name=service_name,
        )
        click.echo(f"  Config updated: otel.enabled=true, endpoint={otlp_endpoint}")

    _print_stack_summary(contract)

    if app.logger:
        app.logger.log_action(
            "setup-local-observability",
            "stack",
            f"action=up endpoint={otlp_endpoint} protocol={otlp_protocol}",
        )


# ---------------------------------------------------------------------------
# down / reset
# ---------------------------------------------------------------------------


@local_observability.command("down")
@click.option(
    "--disable-config",
    is_flag=True,
    help="Also flip otel.enabled=false in config.yaml.",
)
@pass_ctx
def down_cmd(app: AppContext, disable_config: bool) -> None:
    """Stop the stack (volumes preserved)."""
    bridge = _resolve_bridge(app.cfg.data_dir)
    _run_bridge(bridge, ["down"])

    if disable_config:
        from defenseclaw.observability import set_destination_enabled

        try:
            set_destination_enabled("otel", False, app.cfg.data_dir)
            click.echo("  Config updated: otel.enabled=false")
        except ValueError as exc:
            click.echo(f"  warning: could not disable otel block: {exc}")

    if app.logger:
        app.logger.log_action(
            "setup-local-observability", "stack", "action=down",
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

    bridge = _resolve_bridge(app.cfg.data_dir)
    _run_bridge(bridge, ["reset"])

    if app.logger:
        app.logger.log_action(
            "setup-local-observability", "stack", "action=reset",
        )


# ---------------------------------------------------------------------------
# status / logs / url
# ---------------------------------------------------------------------------


@local_observability.command("status")
@pass_ctx
def status_cmd(app: AppContext) -> None:
    """Show compose ps and per-service readiness probes."""
    bridge = _resolve_bridge(app.cfg.data_dir)
    _run_bridge(bridge, ["status"])


@local_observability.command("logs")
@click.option("--service", default=None, help="Compose service to target (default: all).")
@click.option("--follow/--no-follow", default=False, help="Stream logs until Ctrl+C.")
@pass_ctx
def logs_cmd(app: AppContext, service: str | None, follow: bool) -> None:
    """Tail logs from the running stack."""
    bridge = _resolve_bridge(app.cfg.data_dir)
    args = ["logs"]
    if follow:
        args.append("--follow")
    if service:
        args.extend(["--service", service])
    _run_bridge(bridge, args)


@local_observability.command("url")
@click.option("--json", "emit_json", is_flag=True, help="Emit machine-readable JSON.")
@pass_ctx
def url_cmd(app: AppContext, emit_json: bool) -> None:
    """Print the Grafana / Prometheus / Tempo / Loki URLs."""
    bridge = _resolve_bridge(app.cfg.data_dir)
    args = ["url"]
    if emit_json:
        args.extend(["--output", "json"])
    _run_bridge(bridge, args)


# ---------------------------------------------------------------------------
# Internals — bridge invocation
# ---------------------------------------------------------------------------


def _resolve_bridge(data_dir: str) -> str:
    bridge = local_observability_bridge_bin(data_dir)
    if not bridge:
        click.echo(
            "  error: local observability bridge not found. "
            "Run 'defenseclaw init' to seed it.",
            err=True,
        )
        raise SystemExit(1)
    return bridge


def _run_bridge_up(
    bridge: str, *, timeout: int, no_wait: bool,
) -> dict[str, Any] | None:
    """Invoke ``bridge up --output json`` and return the parsed contract.

    The bridge waits for TCP readiness on 4317 + HTTP readiness on
    Grafana + Prometheus before emitting the contract, so returning the
    parsed JSON means the stack is actually serving traffic (not just
    ``docker compose up -d`` finished).
    """
    cmd = [bridge, "up", "--output", "json", "--timeout", str(timeout)]
    if no_wait:
        cmd.append("--no-wait")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(timeout + 30, 60),
        )
    except subprocess.TimeoutExpired:
        click.echo("  error: bridge timed out while bringing up the stack", err=True)
        return None
    except OSError as exc:
        click.echo(f"  error: could not execute bridge: {exc}", err=True)
        return None

    if result.returncode != 0:
        click.echo(
            f"  error: bridge failed (exit {result.returncode})",
            err=True,
        )
        for line in (result.stderr or result.stdout or "").splitlines()[:10]:
            click.echo(f"    {line}", err=True)
        return None

    raw = (result.stdout or "").strip()
    # The bridge prints the contract on its own line; any other text on
    # stdout is assumed to be incidental (e.g. docker compose status),
    # so we scan for the first line that parses as JSON.
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = _json.loads(line)
        except ValueError:
            continue
        if isinstance(parsed, dict) and parsed.get("otlp_endpoint"):
            return parsed
    click.echo(
        "  error: bridge completed but did not emit a readiness contract",
        err=True,
    )
    return None


def _run_bridge(bridge: str, args: list[str]) -> None:
    try:
        subprocess.run([bridge, *args], check=False)
    except OSError as exc:
        click.echo(f"  error: could not execute bridge: {exc}", err=True)
        raise SystemExit(1) from exc


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
    """Write/refresh the ``otel:`` block via the shared observability writer."""
    from defenseclaw.observability import apply_preset

    apply_preset(
        _PRESET_ID,
        {
            "endpoint": endpoint,
            # ``protocol`` is declared on the preset; callers can still
            # force http here for SDKs that can't speak grpc locally.
            "protocol": protocol,
        },
        app.cfg.data_dir,
        name=service_name,
        enabled=True,
        signals=signals,  # type: ignore[arg-type]
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


# ---------------------------------------------------------------------------
# Internals — preflight + formatting
# ---------------------------------------------------------------------------


def _preflight_docker() -> bool:
    """Confirm Docker is installed + running and the stack's ports are free."""
    click.echo("  Pre-flight checks:")
    docker = shutil.which("docker")
    if not docker:
        click.echo("    Docker installed... NOT FOUND")
        click.echo("    Install Docker: https://docs.docker.com/get-docker/")
        return False
    click.echo("    Docker installed... ok")

    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            click.echo("    Docker daemon running... NOT RUNNING")
            click.echo("    Start Docker Desktop / the engine and try again.")
            return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        click.echo("    Docker daemon running... NOT RUNNING")
        return False
    click.echo("    Docker daemon running... ok")

    # Port conflicts are advisory — compose will already own the ports
    # on a re-up so "in use by defenseclaw-*" should not block us.
    for port, label in _STACK_PORTS:
        if _port_in_use(port) and not _port_owned_by_stack(port):
            click.echo(
                f"    Port {port} ({label})... IN USE (by a non-stack process)",
            )
            click.echo(
                f"    Free port {port} or stop the conflicting service before retrying.",
            )
            return False
        click.echo(f"    Port {port} ({label})... available")

    return True


def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.25)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _port_owned_by_stack(port: int) -> bool:
    """Return True if ``port`` is bound by a defenseclaw-observability container.

    Best-effort — returns False if Docker is unreachable. Prevents the
    preflight from falsely blocking a re-invocation of ``up`` while the
    stack is already healthy.
    """
    try:
        result = subprocess.run(
            [
                "docker",
                "ps",
                "--filter",
                "label=com.docker.compose.project=defenseclaw-observability",
                "--format",
                "{{.Ports}}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False
    if result.returncode != 0:
        return False
    needle = f":{port}->"
    return needle in (result.stdout or "")


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


def _print_stack_summary(contract: dict[str, Any]) -> None:
    click.echo()
    click.echo("  Local observability stack is up:")
    click.echo(f"    Grafana:    {contract.get('grafana_url', 'http://localhost:3000')}  (admin / admin)")
    click.echo(f"    Prometheus: {contract.get('prometheus_url', 'http://localhost:9090')}")
    click.echo(f"    Tempo API:  {contract.get('tempo_url', 'http://localhost:3200')}")
    click.echo(f"    Loki API:   {contract.get('loki_url', 'http://localhost:3100')}")
    click.echo(f"    OTLP gRPC:  {contract.get('otlp_endpoint', '127.0.0.1:4317')}")
    click.echo(f"    OTLP HTTP:  {contract.get('otlp_http_endpoint', '127.0.0.1:4318')}")
    click.echo()
    click.echo("  Next steps:")
    click.echo("    defenseclaw-gateway restart         # pick up the new config")
    click.echo("    defenseclaw setup local-observability status")
    click.echo("    defenseclaw setup local-observability down   # stop (keeps data)")
    click.echo("    defenseclaw setup local-observability reset  # stop + wipe data")
    click.echo()


__all__ = ["local_observability"]
