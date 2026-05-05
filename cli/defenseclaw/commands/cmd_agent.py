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

"""defenseclaw agent - local agent inventory commands."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import click
import requests

from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.gateway import OrchestratorClient
from defenseclaw.inventory import agent_discovery, ai_signatures


@click.group()
def agent() -> None:
    """Inspect locally installed agent surfaces."""


@agent.command("discover")
@click.option("--refresh", is_flag=True, help="Refresh cached discovery before rendering.")
@click.option("--no-cache", is_flag=True, help="Bypass the discovery cache for this run.")
@click.option("--json", "as_json", is_flag=True, help="Output discovery as JSON.")
@click.option(
    "--emit-otel/--no-emit-otel",
    default=True,
    show_default=True,
    help="Best-effort emit sanitized discovery telemetry through the sidecar.",
)
@click.option(
    "--require-otel",
    is_flag=True,
    help="Fail when telemetry emission cannot reach the sidecar.",
)
@click.option("--gateway-host", default=None, help="Sidecar API host override.")
@click.option("--gateway-port", type=int, default=None, help="Sidecar API port override.")
@click.option(
    "--gateway-token-env",
    default=None,
    help="Environment variable containing the sidecar API token override.",
)
@pass_ctx
def discover(
    app: AppContext,
    refresh: bool,
    no_cache: bool,
    as_json: bool,
    emit_otel: bool,
    require_otel: bool,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> None:
    """Run local agent discovery and optionally emit OTel telemetry."""
    started = time.monotonic()
    disc = agent_discovery.discover_agents(use_cache=not no_cache, refresh=refresh)
    duration_ms = int((time.monotonic() - started) * 1000)

    otel_result = {"attempted": False, "emitted": False, "error": ""}
    if emit_otel:
        report = _sanitized_discovery_report(disc, duration_ms=duration_ms)
        otel_result = _emit_discovery_report(
            app,
            report,
            gateway_host=gateway_host,
            gateway_port=gateway_port,
            gateway_token_env=gateway_token_env,
        )
        if require_otel and not otel_result["emitted"]:
            raise click.ClickException(str(otel_result["error"] or "OTel emission failed"))

    if as_json:
        payload = dataclasses.asdict(disc)
        payload["otel"] = otel_result
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    click.echo(agent_discovery.render_discovery_table(disc).rstrip())
    if emit_otel:
        if otel_result["emitted"]:
            click.echo("  OTel: emitted agent discovery telemetry")
        elif otel_result["error"]:
            click.echo(f"  OTel: not emitted ({otel_result['error']})", err=True)


@agent.command("usage")
@click.option("--refresh", is_flag=True, help="Ask the running sidecar to scan before rendering.")
@click.option("--json", "as_json", is_flag=True, help="Output AI usage visibility as JSON.")
@click.option("--gateway-host", default=None, help="Sidecar API host override.")
@click.option("--gateway-port", type=int, default=None, help="Sidecar API port override.")
@click.option(
    "--gateway-token-env",
    default=None,
    help="Environment variable containing the sidecar API token override.",
)
@pass_ctx
def usage(
    app: AppContext,
    refresh: bool,
    as_json: bool,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> None:
    """Show continuous AI visibility from the running sidecar."""
    client = _usage_client(
        app,
        gateway_host=gateway_host,
        gateway_port=gateway_port,
        gateway_token_env=gateway_token_env,
    )
    try:
        payload = client.scan_ai_usage() if refresh else client.ai_usage()
    except requests.ConnectionError as exc:
        raise click.ClickException(f"sidecar unavailable: {exc}") from exc
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        raise click.ClickException(f"sidecar rejected AI usage request: HTTP {status}") from exc
    except requests.RequestException as exc:
        raise click.ClickException(f"sidecar request failed: {exc}") from exc

    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    click.echo(_render_ai_usage_table(payload).rstrip())


@agent.group("signatures")
def signatures() -> None:
    """Manage AI discovery signature packs."""


@signatures.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output merged signatures as JSON.")
@click.option("--include-disabled", is_flag=True, help="Include configured disabled signatures.")
@pass_ctx
def signatures_list(app: AppContext, as_json: bool, include_disabled: bool) -> None:
    """List the merged AI discovery signature catalog."""
    cfg = _load_config_best_effort(app)
    disabled = [] if include_disabled else list(getattr(cfg.ai_discovery, "disabled_signature_ids", []) or [])
    try:
        sigs = ai_signatures.load_ai_signatures(
            data_dir=cfg.data_dir,
            signature_packs=cfg.ai_discovery.signature_packs,
            allow_workspace_signatures=cfg.ai_discovery.allow_workspace_signatures,
            scan_roots=cfg.ai_discovery.scan_roots,
            disabled_signature_ids=disabled,
        )
    except ai_signatures.SignaturePackError as exc:
        raise click.ClickException(str(exc)) from exc

    if as_json:
        click.echo(json.dumps([asdict(sig) for sig in sigs], indent=2, sort_keys=True))
        return
    click.echo(_render_signatures_table(sigs).rstrip())


@signatures.command("validate")
@click.argument("pack_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Output validation details as JSON.")
def signatures_validate(pack_path: Path, as_json: bool) -> None:
    """Validate a signature pack without installing it."""
    try:
        sigs = ai_signatures.validate_signature_pack(pack_path)
    except ai_signatures.SignaturePackError as exc:
        raise click.ClickException(str(exc)) from exc
    if as_json:
        payload = {"ok": True, "path": str(pack_path), "signatures": [asdict(sig) for sig in sigs]}
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    click.echo(f"Signature pack valid: {pack_path} ({len(sigs)} signatures)")


@signatures.command("install")
@click.argument("pack_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--replace", is_flag=True, help="Replace an installed pack with the same pack id.")
@pass_ctx
def signatures_install(app: AppContext, pack_path: Path, replace: bool) -> None:
    """Install a validated pack into the managed signature-pack directory."""
    cfg = _load_config_best_effort(app)
    try:
        dest = ai_signatures.install_signature_pack(pack_path, data_dir=cfg.data_dir, replace=replace)
    except ai_signatures.SignaturePackError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Installed signature pack: {dest}")


@signatures.command("disable")
@click.argument("signature_id")
@pass_ctx
def signatures_disable(app: AppContext, signature_id: str) -> None:
    """Disable one signature id in ai_discovery.disabled_signature_ids."""
    cfg = _load_config_best_effort(app)
    normalized = ai_signatures.normalize_signature_id(signature_id)
    if not normalized:
        raise click.ClickException("signature id must not be empty")
    disabled = list(getattr(cfg.ai_discovery, "disabled_signature_ids", []) or [])
    if normalized not in disabled:
        disabled.append(normalized)
        cfg.ai_discovery.disabled_signature_ids = sorted(disabled)
        cfg.save()
    click.echo(f"Disabled AI signature: {normalized}")


@signatures.command("enable")
@click.argument("signature_id")
@pass_ctx
def signatures_enable(app: AppContext, signature_id: str) -> None:
    """Re-enable one signature id previously disabled in config."""
    cfg = _load_config_best_effort(app)
    normalized = ai_signatures.normalize_signature_id(signature_id)
    disabled = list(getattr(cfg.ai_discovery, "disabled_signature_ids", []) or [])
    if normalized in disabled:
        cfg.ai_discovery.disabled_signature_ids = [s for s in disabled if s != normalized]
        cfg.save()
    click.echo(f"Enabled AI signature: {normalized}")


def _load_config_best_effort(app: AppContext):
    cfg = getattr(app, "cfg", None)
    if cfg is not None:
        return cfg
    from defenseclaw import config as cfg_mod

    try:
        cfg = cfg_mod.load()
    except Exception:
        cfg = cfg_mod.default_config()
    app.cfg = cfg
    return cfg


def _render_signatures_table(sigs: list[ai_signatures.AISignature]) -> str:
    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:
        return _render_signatures_plain(sigs)

    from io import StringIO

    stream = StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None, width=120)
    table = Table(title=f"AI discovery signatures ({len(sigs)})")
    table.add_column("ID")
    table.add_column("Category")
    table.add_column("Product")
    table.add_column("Vendor")
    table.add_column("Confidence")
    table.add_column("Source")
    for sig in sorted(sigs, key=lambda s: (s.category, s.id)):
        table.add_row(sig.id, sig.category, sig.name, sig.vendor, f"{sig.confidence:.2f}", _source_label(sig.source))
    console.print(table)
    return stream.getvalue()


def _render_signatures_plain(sigs: list[ai_signatures.AISignature]) -> str:
    lines = [f"AI discovery signatures ({len(sigs)})"]
    for sig in sorted(sigs, key=lambda s: (s.category, s.id)):
        parts = [sig.id, sig.category, sig.name, sig.vendor, f"{sig.confidence:.2f}", _source_label(sig.source)]
        lines.append(" | ".join(parts))
    return "\n".join(lines) + "\n"


def _source_label(source: str) -> str:
    if source == "builtin":
        return source
    return os.path.basename(source)


def _emit_discovery_report(
    app: AppContext,
    report: dict[str, Any],
    *,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> dict[str, Any]:
    result = {"attempted": True, "emitted": False, "error": ""}
    host, port, token = _resolve_gateway_target(
        app,
        gateway_host=gateway_host,
        gateway_port=gateway_port,
        gateway_token_env=gateway_token_env,
    )
    if not token:
        result["error"] = "gateway token unavailable"
        return result

    try:
        client = OrchestratorClient(host=host, port=port, token=token, timeout=3)
        client.emit_agent_discovery(report)
        result["emitted"] = True
    except (requests.ConnectionError, requests.Timeout) as exc:
        result["error"] = f"sidecar unavailable: {exc}"
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        result["error"] = f"sidecar rejected discovery telemetry: HTTP {status}"
    except requests.RequestException as exc:
        result["error"] = f"sidecar request failed: {exc}"
    return result


def _resolve_gateway_target(
    app: AppContext,
    *,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> tuple[str, int, str]:
    host = gateway_host or "127.0.0.1"
    port = gateway_port or 18970
    token = os.environ.get(gateway_token_env or "", "") if gateway_token_env else ""

    cfg = getattr(app, "cfg", None)
    if cfg is None:
        try:
            from defenseclaw import config as cfg_mod

            cfg = cfg_mod.load()
        except Exception:
            cfg = None

    if cfg is not None:
        gw = getattr(cfg, "gateway", None)
        if gw is not None:
            host = gateway_host or getattr(gw, "host", "") or host
            port = gateway_port or int(getattr(gw, "api_port", 0) or port)
            if not token and hasattr(gw, "resolved_token"):
                token = gw.resolved_token()

    return host, port, token


def _usage_client(
    app: AppContext,
    *,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> OrchestratorClient:
    host, port, token = _resolve_gateway_target(
        app,
        gateway_host=gateway_host,
        gateway_port=gateway_port,
        gateway_token_env=gateway_token_env,
    )
    if not token:
        raise click.ClickException("gateway token unavailable")
    return OrchestratorClient(host=host, port=port, token=token, timeout=5)


def _render_ai_usage_table(payload: dict[str, Any]) -> str:
    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:
        return _render_ai_usage_plain(payload)

    from io import StringIO

    stream = StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None, width=120)
    summary = payload.get("summary", {}) or {}
    title = "AI visibility"
    if not payload.get("enabled", True):
        title += " (disabled)"
    table = Table(title=title)
    table.add_column("State")
    table.add_column("Category")
    table.add_column("Product")
    table.add_column("Vendor")
    table.add_column("Detector")
    table.add_column("Evidence")
    for sig in payload.get("signals", []) or []:
        evidence = ",".join(sig.get("evidence_types", []) or [])
        table.add_row(
            str(sig.get("state", "")),
            str(sig.get("category", "")),
            str(sig.get("product", "")),
            str(sig.get("vendor", "")),
            str(sig.get("detector", "")),
            evidence,
        )
    console.print(table)
    console.print(
        f"Scanned: {summary.get('scanned_at', '-')}; "
        f"active={summary.get('active_signals', 0)} "
        f"new={summary.get('new_signals', 0)} "
        f"changed={summary.get('changed_signals', 0)} "
        f"gone={summary.get('gone_signals', 0)} "
        f"files={summary.get('files_scanned', 0)}"
    )
    return stream.getvalue()


def _render_ai_usage_plain(payload: dict[str, Any]) -> str:
    lines = ["AI visibility"]
    summary = payload.get("summary", {}) or {}
    for sig in payload.get("signals", []) or []:
        lines.append(
            " | ".join([
                str(sig.get("state", "")),
                str(sig.get("category", "")),
                str(sig.get("product", "")),
                str(sig.get("vendor", "")),
                str(sig.get("detector", "")),
            ])
        )
    lines.append(
        f"active={summary.get('active_signals', 0)} "
        f"new={summary.get('new_signals', 0)} "
        f"changed={summary.get('changed_signals', 0)} "
        f"gone={summary.get('gone_signals', 0)}"
    )
    return "\n".join(lines) + "\n"


def _sanitized_discovery_report(disc: agent_discovery.AgentDiscovery, *, duration_ms: int) -> dict[str, Any]:
    agents: dict[str, dict[str, Any]] = {}
    for name, signal in disc.agents.items():
        agents[name] = {
            "installed": bool(signal.installed),
            "has_config": bool(signal.config_path),
            "config_basename": _basename(signal.config_path),
            "config_path_hash": _path_hash(signal.config_path),
            "has_binary": bool(signal.binary_path),
            "binary_basename": _basename(signal.binary_path),
            "binary_path_hash": _path_hash(signal.binary_path),
            "version": _bounded(signal.version, 160),
            "version_probe_status": _probe_status(signal),
            "error_class": _error_class(signal.error),
        }
    return {
        "source": "cli",
        "scanned_at": disc.scanned_at,
        "cache_hit": bool(disc.cache_hit),
        "duration_ms": duration_ms,
        "agents": agents,
    }


def _basename(path: str) -> str:
    return os.path.basename(path) if path else ""


def _path_hash(path: str) -> str:
    if not path:
        return ""
    digest = hashlib.sha256(os.path.abspath(path).encode("utf-8")).hexdigest()
    return "sha256:" + digest


def _bounded(value: str, max_len: int) -> str:
    value = (value or "").replace("\r", " ").replace("\n", " ").strip()
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."


def _probe_status(signal: agent_discovery.AgentSignal) -> str:
    if signal.version:
        return "ok"
    if signal.error:
        return _error_class(signal.error)
    if signal.binary_path:
        return "unknown"
    return "not_probed"


def _error_class(error: str) -> str:
    err = (error or "").lower()
    if not err:
        return ""
    if "timed out" in err or "timeout" in err:
        return "timeout"
    if "exited" in err:
        return "nonzero_exit"
    if "empty" in err:
        return "empty_output"
    if "failed" in err:
        return "probe_failed"
    return "other"
