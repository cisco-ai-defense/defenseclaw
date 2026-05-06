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


_AI_USAGE_STATES: tuple[str, ...] = ("new", "changed", "active", "gone")


@agent.command("usage")
@click.option("--refresh", is_flag=True, help="Ask the running sidecar to scan before rendering.")
@click.option("--json", "as_json", is_flag=True, help="Output AI usage visibility as JSON.")
@click.option(
    "--detail",
    "detail",
    is_flag=True,
    help=(
        "Render one row per signal (the full inventory) instead of the grouped "
        "summary. Useful for forensics; expect hundreds of rows on a typical box."
    ),
)
@click.option(
    "--state",
    "states",
    multiple=True,
    type=click.Choice(_AI_USAGE_STATES),
    help="Filter signals by state. Repeatable. When omitted, 'gone' is hidden.",
)
@click.option(
    "--category",
    "categories",
    multiple=True,
    help="Filter by signal category (repeatable, case-insensitive exact match).",
)
@click.option(
    "--product",
    "products",
    multiple=True,
    help="Filter by product name (repeatable, case-insensitive substring match).",
)
@click.option(
    "--component",
    "components",
    multiple=True,
    help=(
        "Filter by component/SDK name from the parsed manifest "
        "(repeatable, case-insensitive substring). Falls back to "
        "matching against product when a signal has no component block."
    ),
)
@click.option(
    "--show-gone",
    is_flag=True,
    help="Include 'gone' signals in the table (suppressed by default to cut noise).",
)
@click.option(
    "--by-detector",
    "by_detector",
    is_flag=True,
    help=(
        "Show one row per (state, category, product, vendor, detector) "
        "instead of the normalized one-row-per-product view. Use this "
        "when triaging WHICH detector saw a product (forensics) — by "
        "default we collapse so e.g. Claude Code doesn't show 7 times "
        "just because it was found by binary, process, mcp, config, "
        "shell-history, and desktop-app detectors."
    ),
)
@click.option(
    "--limit",
    type=int,
    default=0,
    help="Cap rows shown (0 = no cap). Use --json for the unfiltered list.",
)
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
    detail: bool,
    states: tuple[str, ...],
    categories: tuple[str, ...],
    products: tuple[str, ...],
    components: tuple[str, ...],
    show_gone: bool,
    by_detector: bool,
    limit: int,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> None:
    """Show continuous AI visibility from the running sidecar.

    By default the rendered table groups signals by
    (state, product, vendor, ecosystem, name) so an SDK / agent /
    CLI shows up exactly ONCE per (state, vendor) -- with the list
    of categories and detectors that found it rolled into two
    columns. Pre-normalization, "Claude Code" routinely showed up
    6-7 times in one operator's report because it was found by the
    binary, process, mcp, config, shell-history, and desktop-app
    detectors all at once -- the operator wanted "where is Claude
    Code", not "by what method was it discovered". Use
    ``--by-detector`` to split rows by detector again (forensics);
    ``--detail`` falls back to the per-signal view; ``--json`` is
    unchanged for tooling.
    """
    if limit < 0:
        raise click.BadParameter("--limit must be >= 0", param_hint="--limit")

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

    click.echo(
        _render_ai_usage_table(
            payload,
            detail=detail,
            states=states,
            categories=categories,
            products=products,
            components=components,
            show_gone=show_gone,
            by_detector=by_detector,
            limit=limit,
        ).rstrip()
    )


# ---------------------------------------------------------------------------
# agent processes / agent components — high-fidelity views over the
# enriched AI inventory the sidecar now collects.
#
# These two siblings of `agent usage` are intentionally narrow:
#   - `processes` answers "what AI processes are alive on this box right
#     now and what are they doing?" — sourced from the
#     `runtime{}` block on every signal that came from the process
#     detector.
#   - `components` answers "what SDKs/frameworks (with version) are
#     installed across the workspaces I scan?" — sourced from the new
#     `GET /api/v1/ai-usage/components` rollup so we don't redo the
#     dedupe logic in the CLI.
# ---------------------------------------------------------------------------


@agent.command("processes")
@click.option("--refresh", is_flag=True, help="Ask the sidecar to scan before rendering.")
@click.option("--json", "as_json", is_flag=True, help="Output the live process list as JSON.")
@click.option(
    "--limit",
    type=int,
    default=0,
    help="Cap rows shown (0 = no cap).",
)
@click.option("--gateway-host", default=None, help="Sidecar API host override.")
@click.option("--gateway-port", type=int, default=None, help="Sidecar API port override.")
@click.option(
    "--gateway-token-env",
    default=None,
    help="Environment variable containing the sidecar API token override.",
)
@pass_ctx
def processes(
    app: AppContext,
    refresh: bool,
    as_json: bool,
    limit: int,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> None:
    """List AI processes the sidecar currently observes (PID, user, uptime).

    Only signals whose detector emitted a ``runtime`` block are
    surfaced (i.e. the process detector). For the broader installed
    surface use ``defenseclaw agent usage`` or
    ``defenseclaw agent components``.
    """
    if limit < 0:
        raise click.BadParameter("--limit must be >= 0", param_hint="--limit")

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

    raw_signals = payload.get("signals", []) or []
    process_signals = [s for s in raw_signals if s.get("runtime")]
    # Most-recently-seen first so an operator hunting a runaway agent
    # sees fresh activity at the top.
    process_signals.sort(
        key=lambda s: str(s.get("last_active_at", "") or s.get("last_seen", "")),
        reverse=True,
    )

    if as_json:
        click.echo(json.dumps({"processes": process_signals}, indent=2, sort_keys=True))
        return

    click.echo(_render_ai_processes_table(process_signals, limit=limit).rstrip())


@agent.group("components", invoke_without_command=True)
@click.option("--refresh", is_flag=True, help="Ask the sidecar to scan before rendering.")
@click.option("--json", "as_json", is_flag=True, help="Output the components rollup as JSON.")
@click.option(
    "--ecosystem",
    "ecosystems",
    multiple=True,
    help="Filter by ecosystem (npm, pypi, go, …). Repeatable, case-insensitive.",
)
@click.option(
    "--name",
    "names",
    multiple=True,
    help="Filter by component name (repeatable, case-insensitive substring).",
)
@click.option(
    "--min-identity",
    "min_identity",
    type=click.FloatRange(0.0, 1.0),
    default=None,
    help=(
        "Filter rows by identity_score (0..1). Useful when triaging "
        "high-confidence components only, e.g. ``--min-identity 0.8``."
    ),
)
@click.option(
    "--min-presence",
    "min_presence",
    type=click.FloatRange(0.0, 1.0),
    default=None,
    help=(
        "Filter rows by presence_score (0..1). Pair with ``--min-identity`` "
        "for the high-id, high-presence subset."
    ),
)
@click.option(
    "--limit",
    type=int,
    default=0,
    help="Cap rows shown (0 = no cap).",
)
@click.option("--gateway-host", default=None, help="Sidecar API host override.")
@click.option("--gateway-port", type=int, default=None, help="Sidecar API port override.")
@click.option(
    "--gateway-token-env",
    default=None,
    help="Environment variable containing the sidecar API token override.",
)
@click.pass_context
@pass_ctx
def components_cmd(
    app: AppContext,
    click_ctx: click.Context,
    refresh: bool,
    as_json: bool,
    ecosystems: tuple[str, ...],
    names: tuple[str, ...],
    min_identity: float | None,
    min_presence: float | None,
    limit: int,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> None:
    """Show the deduped AI components/SDK rollup with versions, install counts, and confidence.

    Calls ``GET /api/v1/ai-usage/components`` so the sidecar does the
    join across detectors and workspaces; the CLI just filters and
    renders.

    Subcommands ``show NAME`` and ``history NAME`` drill into a single
    component using the same authoritative SQL inventory store.
    """
    # Stash the listing options on click_ctx.meta (NOT click_ctx.obj)
    # so children (`components show`, `components history`) can re-use
    # the same gateway plumbing without re-declaring every flag.
    #
    # Why meta and not obj: the rest of the CLI uses
    # ``make_pass_decorator(AppContext, ensure=True)`` (= ``pass_ctx``)
    # which walks up the click context tree looking for an instance of
    # ``AppContext`` in ``ctx.obj``. If we replaced obj with a dict here,
    # any subcommand wrapped with ``@pass_ctx`` would silently get a
    # *fresh* AppContext (because of ``ensure=True``), losing config +
    # logger state. ``ctx.meta`` is reserved for exactly this kind of
    # cross-command piggyback and is invisible to the pass-decorator.
    click_ctx.meta["agent.components.gateway_host"] = gateway_host
    click_ctx.meta["agent.components.gateway_port"] = gateway_port
    click_ctx.meta["agent.components.gateway_token_env"] = gateway_token_env
    click_ctx.meta["agent.components.app"] = app
    if click_ctx.invoked_subcommand is not None:
        # The subcommand owns the network call. ``components show ...``
        # would otherwise pay for one ``ai_usage_components`` round trip
        # plus its own ``ai_usage_component_locations`` for no reason.
        return
    if limit < 0:
        raise click.BadParameter("--limit must be >= 0", param_hint="--limit")

    client = _usage_client(
        app,
        gateway_host=gateway_host,
        gateway_port=gateway_port,
        gateway_token_env=gateway_token_env,
    )
    try:
        if refresh:
            client.scan_ai_usage()
        payload = client.ai_usage_components()
    except requests.ConnectionError as exc:
        raise click.ClickException(f"sidecar unavailable: {exc}") from exc
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        raise click.ClickException(f"sidecar rejected components request: HTTP {status}") from exc
    except requests.RequestException as exc:
        raise click.ClickException(f"sidecar request failed: {exc}") from exc

    rows = _filter_components(
        payload.get("components", []) or [],
        ecosystems=ecosystems,
        names=names,
        min_identity=min_identity,
        min_presence=min_presence,
    )

    if as_json:
        click.echo(json.dumps({"components": rows}, indent=2, sort_keys=True))
        return

    click.echo(_render_ai_components_table(rows, payload=payload, limit=limit).rstrip())


@components_cmd.command("show")
@click.argument("name")
@click.option(
    "--ecosystem",
    "ecosystem",
    default=None,
    help=(
        "Disambiguate when the same component name exists in more "
        "than one ecosystem (npm, pypi, go, …). Optional when the "
        "name is unique across the inventory."
    ),
)
@click.option("--json", "as_json", is_flag=True, help="Output the show payload as JSON.")
@click.pass_context
def components_show(
    click_ctx: click.Context,
    name: str,
    ecosystem: str | None,
    as_json: bool,
) -> None:
    """Print the per-install location detail for one component.

    Resolves ``NAME`` against the components rollup, then fetches
    ``GET /api/v1/ai-usage/components/{ecosystem}/{name}/locations``
    so an operator can see *every* place the SDK was detected (one
    row per evidence record, including detector + match quality +
    workspace + basename + raw path when redaction is off).
    """
    app, host, port, token_env = _components_meta(click_ctx)
    client = _usage_client(
        app,
        gateway_host=host,
        gateway_port=port,
        gateway_token_env=token_env,
    )
    component, error = _resolve_component(client, name=name, ecosystem=ecosystem)
    if error:
        raise click.ClickException(error)
    eco = str(component.get("ecosystem", "")).strip()
    cname = str(component.get("name", "")).strip()
    try:
        loc_payload = client.ai_usage_component_locations(eco, cname)
    except requests.ConnectionError as exc:
        raise click.ClickException(f"sidecar unavailable: {exc}") from exc
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        raise click.ClickException(
            f"sidecar rejected locations request: HTTP {status}") from exc
    except requests.RequestException as exc:
        raise click.ClickException(f"sidecar request failed: {exc}") from exc

    if as_json:
        click.echo(json.dumps(
            {"component": component, "locations": loc_payload},
            indent=2, sort_keys=True))
        return
    click.echo(_render_component_show(component, loc_payload).rstrip())


@components_cmd.command("history")
@click.argument("name")
@click.option(
    "--ecosystem",
    "ecosystem",
    default=None,
    help="Disambiguate when ``NAME`` exists in multiple ecosystems.",
)
@click.option(
    "--limit",
    type=int,
    default=0,
    help="Cap rows shown (0 = no cap; sidecar caps at 50).",
)
@click.option("--json", "as_json", is_flag=True, help="Output the history payload as JSON.")
@click.pass_context
def components_history(
    click_ctx: click.Context,
    name: str,
    ecosystem: str | None,
    limit: int,
    as_json: bool,
) -> None:
    """Print the confidence trend (last N scans) for one component.

    Reads ``GET /api/v1/ai-usage/components/{ecosystem}/{name}/history``
    so the rendering matches whatever
    ``inventory.ComputeComponentConfidence`` produced at scan time.
    """
    if limit < 0:
        raise click.BadParameter("--limit must be >= 0", param_hint="--limit")
    app, host, port, token_env = _components_meta(click_ctx)
    client = _usage_client(
        app,
        gateway_host=host,
        gateway_port=port,
        gateway_token_env=token_env,
    )
    component, error = _resolve_component(client, name=name, ecosystem=ecosystem)
    if error:
        raise click.ClickException(error)
    eco = str(component.get("ecosystem", "")).strip()
    cname = str(component.get("name", "")).strip()
    try:
        hist_payload = client.ai_usage_component_history(eco, cname)
    except requests.ConnectionError as exc:
        raise click.ClickException(f"sidecar unavailable: {exc}") from exc
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        raise click.ClickException(
            f"sidecar rejected history request: HTTP {status}") from exc
    except requests.RequestException as exc:
        raise click.ClickException(f"sidecar request failed: {exc}") from exc

    if as_json:
        click.echo(json.dumps(
            {"component": component, "history": hist_payload},
            indent=2, sort_keys=True))
        return
    click.echo(_render_component_history(component, hist_payload, limit=limit).rstrip())


# ---------------------------------------------------------------------------
# agent confidence — explain + policy inspection.
#
# `confidence explain NAME` is the operator's debugging tool: it
# fetches the same /components rollup the listing uses and renders
# the per-evidence factor breakdown (the one ConfidenceFactor doc
# comment promises). The policy subcommands call the new
# /confidence/policy endpoints so an operator can show, validate, or
# print-the-default for the YAML the engine actually loaded.
# ---------------------------------------------------------------------------


@agent.group("confidence")
def confidence_group() -> None:
    """Inspect and tune the AI confidence engine."""


@confidence_group.command("explain")
@click.argument("name")
@click.option(
    "--ecosystem",
    "ecosystem",
    default=None,
    help="Disambiguate when ``NAME`` exists in multiple ecosystems.",
)
@click.option("--json", "as_json", is_flag=True, help="Output the explain payload as JSON.")
@click.option("--gateway-host", default=None, help="Sidecar API host override.")
@click.option("--gateway-port", type=int, default=None, help="Sidecar API port override.")
@click.option(
    "--gateway-token-env",
    default=None,
    help="Environment variable containing the sidecar API token override.",
)
@pass_ctx
def confidence_explain(
    app: AppContext,
    name: str,
    ecosystem: str | None,
    as_json: bool,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> None:
    """Print the per-evidence confidence breakdown for one component.

    Renders the same identity + presence factor tables the engine
    used to compute the score. Each row shows the detector, evidence
    fingerprint, match quality, likelihood ratio, and the
    percentage-point shift that factor contributed — so an operator
    can audit "why 92% and not 99%" without reading source.
    """
    client = _usage_client(
        app,
        gateway_host=gateway_host,
        gateway_port=gateway_port,
        gateway_token_env=gateway_token_env,
    )
    component, error = _resolve_component(client, name=name, ecosystem=ecosystem)
    if error:
        raise click.ClickException(error)

    if as_json:
        click.echo(json.dumps({"component": component}, indent=2, sort_keys=True))
        return
    click.echo(_render_confidence_explain(component).rstrip())


@confidence_group.group("policy")
def confidence_policy_group() -> None:
    """Inspect and validate the confidence policy YAML."""


@confidence_policy_group.command("show")
@click.option(
    "--source",
    type=click.Choice(("merged", "default")),
    default="merged",
    show_default=True,
    help=(
        "``merged`` returns whatever the engine actually uses (default + any "
        "operator override deep-merged on top); ``default`` returns the "
        "embedded baseline so you can diff."
    ),
)
@click.option("--json", "as_json", is_flag=True, help="Output as JSON instead of YAML.")
@click.option("--gateway-host", default=None, help="Sidecar API host override.")
@click.option("--gateway-port", type=int, default=None, help="Sidecar API port override.")
@click.option(
    "--gateway-token-env",
    default=None,
    help="Environment variable containing the sidecar API token override.",
)
@pass_ctx
def confidence_policy_show(
    app: AppContext,
    source: str,
    as_json: bool,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> None:
    """Print the active confidence policy."""
    client = _usage_client(
        app,
        gateway_host=gateway_host,
        gateway_port=gateway_port,
        gateway_token_env=gateway_token_env,
    )
    try:
        payload = client.ai_usage_confidence_policy(source=source)
    except requests.ConnectionError as exc:
        raise click.ClickException(f"sidecar unavailable: {exc}") from exc
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        raise click.ClickException(
            f"sidecar rejected policy request: HTTP {status}") from exc
    except requests.RequestException as exc:
        raise click.ClickException(f"sidecar request failed: {exc}") from exc

    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    click.echo(_render_confidence_policy(payload).rstrip())


@confidence_policy_group.command("default")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON instead of YAML.")
@click.option("--gateway-host", default=None, help="Sidecar API host override.")
@click.option("--gateway-port", type=int, default=None, help="Sidecar API port override.")
@click.option(
    "--gateway-token-env",
    default=None,
    help="Environment variable containing the sidecar API token override.",
)
@pass_ctx
def confidence_policy_default(
    app: AppContext,
    as_json: bool,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> None:
    """Print the embedded default policy (a starting point for an override file)."""
    # Convenience alias for `confidence policy show --source default`.
    # Operators redirect this to a file as the canonical "starter
    # template": `defenseclaw agent confidence policy default >
    # ~/.defenseclaw/confidence_policy.yaml`.
    client = _usage_client(
        app,
        gateway_host=gateway_host,
        gateway_port=gateway_port,
        gateway_token_env=gateway_token_env,
    )
    try:
        payload = client.ai_usage_confidence_policy(source="default")
    except requests.ConnectionError as exc:
        raise click.ClickException(f"sidecar unavailable: {exc}") from exc
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        raise click.ClickException(
            f"sidecar rejected policy request: HTTP {status}") from exc
    except requests.RequestException as exc:
        raise click.ClickException(f"sidecar request failed: {exc}") from exc

    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    click.echo(_render_confidence_policy(payload).rstrip())


@confidence_policy_group.command("validate")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--json", "as_json", is_flag=True, help="Output the validate payload as JSON.")
@click.option("--gateway-host", default=None, help="Sidecar API host override.")
@click.option("--gateway-port", type=int, default=None, help="Sidecar API port override.")
@click.option(
    "--gateway-token-env",
    default=None,
    help="Environment variable containing the sidecar API token override.",
)
@pass_ctx
def confidence_policy_validate(
    app: AppContext,
    path: str,
    as_json: bool,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> None:
    """Dry-run a candidate policy file against the sidecar's loader.

    Writes nothing to disk on the gateway host. Exits non-zero when
    the file fails to deep-merge cleanly on top of the embedded
    default — the same outcome the operator would see at the next
    sidecar boot, but caught up front.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            yaml_text = fh.read()
    except OSError as exc:
        raise click.ClickException(f"cannot read {path}: {exc}") from exc
    client = _usage_client(
        app,
        gateway_host=gateway_host,
        gateway_port=gateway_port,
        gateway_token_env=gateway_token_env,
    )
    try:
        payload = client.ai_usage_validate_confidence_policy(yaml_text)
    except requests.ConnectionError as exc:
        raise click.ClickException(f"sidecar unavailable: {exc}") from exc
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        raise click.ClickException(
            f"sidecar rejected validate request: HTTP {status}") from exc
    except requests.RequestException as exc:
        raise click.ClickException(f"sidecar request failed: {exc}") from exc

    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if payload.get("valid"):
            click.echo(f"OK: {path} (version={payload.get('version', '?')})")
        else:
            click.echo(f"INVALID: {path}: {payload.get('error', 'unknown')}", err=True)
    if not payload.get("valid"):
        # Non-zero exit so `&&` chains in operator scripts halt on
        # validation failure. The error itself is already on
        # stderr/stdout; click would otherwise swallow the contract.
        raise click.exceptions.Exit(1)


# ---------------------------------------------------------------------------
# agent discovery — one-shot toggle for the sidecar AI-discovery service.
#
# Background: ``ai_discovery.enabled`` is read once at sidecar boot
# (``inventory.NewContinuousDiscoveryService`` returns nil otherwise),
# so flipping the flag on disk is necessary but not sufficient. The
# operator-friendly path is "flip + save + restart + (optional) scan",
# and the previous workflow required three separate commands plus
# manual YAML editing. These subcommands fold all of that into one
# step and stay parameter-compatible with ``defenseclaw guardrail
# {enable,disable}`` so muscle memory transfers.
# ---------------------------------------------------------------------------


_AI_DISCOVERY_MODES: tuple[str, ...] = ("passive", "enhanced")

# Bounds for tunable knobs. The sidecar enforces its own minimums
# (config.go viper defaults to 5/60), but the CLI rejects clearly
# nonsense values up front so the operator gets a friendly error
# instead of a silent clamp three days later when the audit log
# shows zero scans.
_SCAN_INTERVAL_MIN_RANGE = (1, 24 * 60)        # 1 minute … 24 hours
_PROCESS_INTERVAL_S_RANGE = (5, 60 * 60)        # 5 seconds … 1 hour
_MAX_FILES_PER_SCAN_RANGE = (10, 100_000)
# 4 KiB up to 16 MiB — anything beyond that almost certainly means
# the operator has a runaway log file in scan_roots and would
# benefit from rejecting the value.
_MAX_FILE_BYTES_RANGE = (4 * 1024, 16 * 1024 * 1024)


@agent.group("discovery")
def discovery() -> None:
    """Toggle and inspect the sidecar AI discovery service."""


@discovery.command("enable")
@click.option(
    "--mode",
    type=click.Choice(_AI_DISCOVERY_MODES),
    default=None,
    help="Discovery mode (defaults to existing config or 'enhanced').",
)
@click.option(
    "--scan-roots",
    "scan_roots",
    default=None,
    help=(
        "Comma-separated roots for artifact scans (overrides existing "
        "ai_discovery.scan_roots). Tildes are kept; the sidecar expands them."
    ),
)
@click.option(
    "--scan-interval-min",
    "scan_interval_min",
    type=click.IntRange(*_SCAN_INTERVAL_MIN_RANGE),
    default=None,
    help=(
        "Minutes between full discovery scans. "
        f"Range {_SCAN_INTERVAL_MIN_RANGE[0]}..{_SCAN_INTERVAL_MIN_RANGE[1]}; default 5."
    ),
)
@click.option(
    "--process-interval-s",
    "process_interval_s",
    type=click.IntRange(*_PROCESS_INTERVAL_S_RANGE),
    default=None,
    help=(
        "Seconds between cheap process-list polls. "
        f"Range {_PROCESS_INTERVAL_S_RANGE[0]}..{_PROCESS_INTERVAL_S_RANGE[1]}; default 60."
    ),
)
@click.option(
    "--max-files-per-scan",
    "max_files_per_scan",
    type=click.IntRange(*_MAX_FILES_PER_SCAN_RANGE),
    default=None,
    help="Cap on number of files inspected per scan (default 1000).",
)
@click.option(
    "--max-file-bytes",
    "max_file_bytes",
    type=click.IntRange(*_MAX_FILE_BYTES_RANGE),
    default=None,
    help="Per-file byte cap when reading manifests/configs (default 524288).",
)
@click.option(
    "--include-shell-history/--no-include-shell-history",
    "include_shell_history",
    default=None,
    help="Inspect shell history for AI CLI invocations (default: on).",
)
@click.option(
    "--include-package-manifests/--no-include-package-manifests",
    "include_package_manifests",
    default=None,
    help="Inspect package.json/pyproject/Cargo.toml/etc. for AI SDKs (default: on).",
)
@click.option(
    "--include-env-var-names/--no-include-env-var-names",
    "include_env_var_names",
    default=None,
    help="Inspect environment variable names for AI provider keys (default: on).",
)
@click.option(
    "--include-network-domains/--no-include-network-domains",
    "include_network_domains",
    default=None,
    help="Inspect /etc/hosts and SSH configs for AI provider domains (default: on).",
)
@click.option(
    "--emit-otel/--no-emit-otel",
    "emit_otel",
    default=None,
    help="Forward sanitized discovery telemetry through the sidecar (default: on).",
)
@click.option(
    "--allow-workspace-signatures/--no-allow-workspace-signatures",
    "allow_workspace_signatures",
    default=None,
    help=(
        "Honor signature packs found inside scanned workspaces. "
        "Off by default (workspace-supplied signatures can override "
        "the operator's intent)."
    ),
)
@click.option(
    "--store-raw-local-paths/--no-store-raw-local-paths",
    "store_raw_local_paths",
    default=None,
    help=(
        "Persist raw local paths in the discovery state file. Off by "
        "default for privacy; only enable for diagnostics on a trusted "
        "machine."
    ),
)
@click.option("--restart/--no-restart", default=True,
              help="Restart the gateway after enabling so the sidecar wires the discovery service (default: on).")
@click.option("--scan/--no-scan", default=True,
              help="Trigger an immediate scan after restart (default: on).")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@click.option("--gateway-host", default=None, help="Sidecar API host override (for --scan).")
@click.option("--gateway-port", type=int, default=None, help="Sidecar API port override (for --scan).")
@click.option(
    "--gateway-token-env",
    default=None,
    help="Environment variable containing the sidecar API token override (for --scan).",
)
@pass_ctx
def discovery_enable(
    app: AppContext,
    mode: str | None,
    scan_roots: str | None,
    scan_interval_min: int | None,
    process_interval_s: int | None,
    max_files_per_scan: int | None,
    max_file_bytes: int | None,
    include_shell_history: bool | None,
    include_package_manifests: bool | None,
    include_env_var_names: bool | None,
    include_network_domains: bool | None,
    emit_otel: bool | None,
    allow_workspace_signatures: bool | None,
    store_raw_local_paths: bool | None,
    restart: bool,
    scan: bool,
    yes: bool,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> None:
    """Enable the sidecar AI discovery service.

    Sets ``ai_discovery.enabled = true`` in ``~/.defenseclaw/config.yaml``,
    persists, and (when ``--restart`` is on) bounces the gateway so
    ``inventory.NewContinuousDiscoveryService`` actually constructs
    the service. With ``--scan`` (the default) this command also calls
    ``POST /api/v1/ai-usage/scan`` once the sidecar is back up so the
    operator gets the first inventory snapshot in the same flow.

    All ``ai_discovery.*`` knobs can be set inline as flags so this
    command is fully scriptable; for an interactive walkthrough that
    prompts for each value with the existing config as the default,
    use ``defenseclaw agent discovery setup``.
    """
    cfg = _require_loaded_config(app)
    ad = cfg.ai_discovery

    pending = _build_discovery_overrides(
        mode=mode,
        scan_roots=scan_roots,
        scan_interval_min=scan_interval_min,
        process_interval_s=process_interval_s,
        max_files_per_scan=max_files_per_scan,
        max_file_bytes=max_file_bytes,
        include_shell_history=include_shell_history,
        include_package_manifests=include_package_manifests,
        include_env_var_names=include_env_var_names,
        include_network_domains=include_network_domains,
        emit_otel=emit_otel,
        allow_workspace_signatures=allow_workspace_signatures,
        store_raw_local_paths=store_raw_local_paths,
    )

    from defenseclaw import ux

    if ad.enabled:
        # If the operator passed tuning flags alongside --yes, treat
        # this as an idempotent "apply these new settings" rather
        # than a no-op. Otherwise the only way to nudge the scan
        # interval on an already-enabled install would be to disable
        # then re-enable, which is an unnecessary downtime window
        # and surprises scripts that pipeline these commands.
        diff = _preview_discovery_changes(ad, pending)
        if not diff:
            click.echo(
                f"  {ux.dim('AI discovery is already enabled')} "
                f"(mode={ad.mode!r}, scan_interval_min={ad.scan_interval_min}).",
            )
            if scan and restart:
                _trigger_post_enable_scan(
                    app,
                    gateway_host=gateway_host,
                    gateway_port=gateway_port,
                    gateway_token_env=gateway_token_env,
                )
            return

        ux.section("Updating AI discovery settings")
    else:
        ux.section("Enabling AI discovery")

    diff = _preview_discovery_changes(ad, pending)
    for label, before, after in diff:
        ux.subhead(f"{label}: {before!r} → {after!r}", indent="  ")
    if restart:
        ux.subhead(
            "Will restart the gateway so the sidecar starts the discovery service.",
            indent="  ",
        )
    else:
        ux.subhead(
            "--no-restart specified: enabled flag is persisted but the discovery service "
            "won't run until you restart the gateway manually "
            "('defenseclaw-gateway restart').",
            indent="  ",
        )
    if scan and not restart:
        ux.subhead(
            "--no-restart implies --no-scan (scan would still hit a stale sidecar).",
            indent="  ",
        )
        scan = False

    click.echo()
    if not yes and not click.confirm("  Proceed?", default=True):
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise SystemExit(1)

    was_enabled = bool(ad.enabled)
    _apply_discovery_settings(ad, pending)
    ad.enabled = True
    if not ad.mode:
        ad.mode = "enhanced"

    try:
        cfg.save()
        ux.ok(
            "Config saved (ai_discovery.enabled = true, "
            f"mode={ad.mode}, scan_interval_min={ad.scan_interval_min})",
            indent="  ",
        )
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        ux.subhead("Re-run after fixing the underlying I/O error.", indent="    ")
        raise SystemExit(1)

    connector = _resolve_connector_for_restart(cfg)
    if restart:
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            cfg.data_dir,
            cfg.gateway.host,
            cfg.gateway.port,
            connector=connector,
        )
        ux.ok("Sidecar restarted; AI discovery is live.", indent="  ")
        click.echo()

        if scan:
            _trigger_post_enable_scan(
                app,
                gateway_host=gateway_host,
                gateway_port=gateway_port,
                gateway_token_env=gateway_token_env,
            )

    action_suffix = "enable" if not was_enabled else "update"
    _log_discovery_action(
        app,
        action=f"ai_discovery-{action_suffix}",
        details=(
            f"mode={ad.mode} scan_interval_min={ad.scan_interval_min} "
            f"restart={restart} scan={scan} changes={len(diff)}"
        ),
    )


@discovery.command("disable")
@click.option("--restart/--no-restart", default=True,
              help="Restart the gateway after disabling so the discovery service stops (default: on).")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@pass_ctx
def discovery_disable(app: AppContext, restart: bool, yes: bool) -> None:
    """Disable the sidecar AI discovery service.

    Sets ``ai_discovery.enabled = false`` in ``~/.defenseclaw/config.yaml``
    and (when ``--restart`` is on) restarts the gateway so the sidecar
    drops the running discovery service.
    """
    from defenseclaw import ux

    cfg = _require_loaded_config(app)
    ad = cfg.ai_discovery

    if not ad.enabled:
        click.echo(f"  {ux.dim('AI discovery is already disabled.')}")
        return

    ux.section("Disabling AI discovery")
    if restart:
        ux.subhead(
            "Will restart the gateway so the discovery service stops immediately.",
            indent="  ",
        )
    else:
        ux.subhead(
            "--no-restart specified: gateway will keep scanning until you restart "
            "it manually ('defenseclaw-gateway restart').",
            indent="  ",
        )
    click.echo()

    if not yes and not click.confirm("  Proceed?", default=True):
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise SystemExit(1)

    ad.enabled = False
    try:
        cfg.save()
        ux.ok("Config saved (ai_discovery.enabled = false)", indent="  ")
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        ux.subhead("Re-run after fixing the underlying I/O error.", indent="    ")
        raise SystemExit(1)

    if restart:
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            cfg.data_dir,
            cfg.gateway.host,
            cfg.gateway.port,
            connector=_resolve_connector_for_restart(cfg),
        )
        ux.ok("Sidecar restarted; AI discovery is stopped.", indent="  ")
        click.echo()

    _log_discovery_action(
        app,
        action="ai_discovery-disable",
        details=f"restart={restart}",
    )


@discovery.command("status")
@click.option("--json", "as_json", is_flag=True, help="Output status as JSON.")
@click.option("--gateway-host", default=None, help="Sidecar API host override.")
@click.option("--gateway-port", type=int, default=None, help="Sidecar API port override.")
@click.option(
    "--gateway-token-env",
    default=None,
    help="Environment variable containing the sidecar API token override.",
)
@pass_ctx
def discovery_status(
    app: AppContext,
    as_json: bool,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> None:
    """Show on-disk + live AI discovery status.

    Reports the value persisted in ``config.yaml`` *and* what the
    running sidecar reports via ``GET /api/v1/ai-usage`` so operators
    can spot the "configured-on, sidecar-stale" drift that produces
    the HTTP 503 from ``defenseclaw agent usage --refresh``.
    """
    cfg = _require_loaded_config(app)
    ad = cfg.ai_discovery
    on_disk = {
        "enabled": bool(ad.enabled),
        "mode": str(ad.mode or ""),
        "scan_interval_min": int(ad.scan_interval_min or 0),
        "process_interval_s": int(ad.process_interval_s or 0),
        "scan_roots": list(ad.scan_roots or []),
        "include_shell_history": bool(ad.include_shell_history),
        "include_package_manifests": bool(ad.include_package_manifests),
        "include_env_var_names": bool(ad.include_env_var_names),
        "include_network_domains": bool(ad.include_network_domains),
        "emit_otel": bool(ad.emit_otel),
    }

    live: dict[str, Any] = {"reachable": False, "enabled": None, "summary": None, "error": ""}
    try:
        client = _usage_client(
            app,
            gateway_host=gateway_host,
            gateway_port=gateway_port,
            gateway_token_env=gateway_token_env,
        )
        try:
            payload = client.ai_usage()
            live["reachable"] = True
            live["enabled"] = bool(payload.get("enabled", False))
            live["summary"] = payload.get("summary") or {}
        except requests.ConnectionError as exc:
            live["error"] = f"sidecar unavailable: {exc}"
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "unknown"
            live["error"] = f"sidecar rejected request: HTTP {status}"
        except requests.RequestException as exc:
            live["error"] = f"sidecar request failed: {exc}"
    except click.ClickException as exc:
        live["error"] = str(exc.message)

    drift = (
        live["reachable"]
        and live["enabled"] is not None
        and live["enabled"] != on_disk["enabled"]
    )

    if as_json:
        click.echo(json.dumps(
            {"on_disk": on_disk, "live": live, "drift": drift},
            indent=2,
            sort_keys=True,
        ))
        return

    from defenseclaw import ux

    ux.section("AI discovery status")
    ux.kv("Configured", "enabled" if on_disk["enabled"] else "disabled", indent="  ")
    ux.kv("Mode", on_disk["mode"] or "(unset)", indent="  ")
    ux.kv("Scan roots", ", ".join(on_disk["scan_roots"]) or "(none)", indent="  ")
    ux.kv("Scan interval", f"{on_disk['scan_interval_min']} min", indent="  ")

    click.echo()
    ux.section("Live (sidecar)")
    if not live["reachable"]:
        ux.warn(live["error"] or "sidecar unreachable", indent="  ")
        ux.subhead(
            "Start it with 'defenseclaw-gateway start' if you expect AI discovery "
            "to be running.",
            indent="  ",
        )
    else:
        ux.kv("Service", "running" if live["enabled"] else "disabled", indent="  ")
        summary = live["summary"] or {}
        ux.kv("Last scan", str(summary.get("scanned_at") or "-"), indent="  ")
        ux.kv("Active signals", str(summary.get("active_signals", 0)), indent="  ")
        ux.kv("New signals", str(summary.get("new_signals", 0)), indent="  ")

    if drift:
        click.echo()
        ux.warn(
            "Drift: config and sidecar disagree — restart the gateway "
            "('defenseclaw-gateway restart') to sync.",
            indent="  ",
        )


@discovery.command("setup")
@click.option("--yes", is_flag=True,
              help="Skip the final confirmation; still walks the prompts.")
@click.option("--restart/--no-restart", default=True,
              help="Restart the gateway after saving (default: on).")
@click.option("--scan/--no-scan", default=True,
              help="Trigger an immediate scan after restart (default: on).")
@click.option("--gateway-host", default=None, help="Sidecar API host override (for --scan).")
@click.option("--gateway-port", type=int, default=None, help="Sidecar API port override (for --scan).")
@click.option(
    "--gateway-token-env",
    default=None,
    help="Environment variable containing the sidecar API token override (for --scan).",
)
@pass_ctx
def discovery_setup(
    app: AppContext,
    yes: bool,
    restart: bool,
    scan: bool,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> None:
    """Walk an interactive wizard for AI discovery settings.

    Each prompt defaults to the current value in ``config.yaml`` so
    pressing Enter on every step is a no-op. The wizard saves the
    config, optionally restarts the gateway, and (by default)
    triggers a fresh scan so the operator sees the inventory in the
    same flow.
    """
    cfg = _require_loaded_config(app)
    ad = cfg.ai_discovery

    from defenseclaw import ux

    ux.section("AI discovery setup")
    ux.subhead(
        "Press Enter on any prompt to keep the current value.",
        indent="  ",
    )
    click.echo()

    # ----- Cadence ---------------------------------------------------------
    ux.section("Cadence")
    enable_pref = click.confirm(
        "  Enable AI discovery?",
        default=bool(ad.enabled) if ad.enabled is not None else True,
    )
    mode_default = ad.mode if ad.mode in _AI_DISCOVERY_MODES else "enhanced"
    mode = click.prompt(
        "  Mode",
        type=click.Choice(_AI_DISCOVERY_MODES, case_sensitive=False),
        default=mode_default,
        show_default=True,
    )
    scan_interval_min = click.prompt(
        "  Scan interval (minutes)",
        type=click.IntRange(*_SCAN_INTERVAL_MIN_RANGE),
        default=int(ad.scan_interval_min or 5),
        show_default=True,
    )
    process_interval_s = click.prompt(
        "  Process-list poll interval (seconds)",
        type=click.IntRange(*_PROCESS_INTERVAL_S_RANGE),
        default=int(ad.process_interval_s or 60),
        show_default=True,
    )

    # ----- Scope -----------------------------------------------------------
    click.echo()
    ux.section("Scope")
    roots_default = ", ".join(ad.scan_roots or ["~"])
    raw_roots = click.prompt(
        "  Scan roots (comma-separated paths)",
        default=roots_default,
        show_default=True,
    )
    scan_roots = _normalize_scan_roots(raw_roots)
    if not scan_roots:
        # Defensive: an empty list disables artifact scanning entirely
        # and the next sidecar restart will produce a confusing
        # "files_scanned=0" report. Push back rather than silently
        # accepting it — the wizard is an interactive surface and we
        # have a friendly UX budget.
        ux.warn(
            "Empty scan roots would disable artifact scanning. "
            "Reverting to the previous list.",
            indent="  ",
        )
        scan_roots = list(ad.scan_roots or ["~"])
    max_files_per_scan = click.prompt(
        "  Max files inspected per scan",
        type=click.IntRange(*_MAX_FILES_PER_SCAN_RANGE),
        default=int(ad.max_files_per_scan or 1000),
        show_default=True,
    )
    max_file_bytes = click.prompt(
        "  Max bytes read per file",
        type=click.IntRange(*_MAX_FILE_BYTES_RANGE),
        default=int(ad.max_file_bytes or 512 * 1024),
        show_default=True,
    )

    # ----- Privacy / detection toggles ------------------------------------
    click.echo()
    ux.section("Detection sources")
    ux.subhead(
        "Each source can be turned off if you'd rather the sidecar "
        "not inspect that artifact class.",
        indent="  ",
    )
    include_shell_history = click.confirm(
        "  Inspect shell history (~/.zsh_history etc.)?",
        default=bool(ad.include_shell_history),
    )
    include_package_manifests = click.confirm(
        "  Inspect package manifests (package.json, pyproject.toml, …)?",
        default=bool(ad.include_package_manifests),
    )
    include_env_var_names = click.confirm(
        "  Inspect environment variable names (no values logged)?",
        default=bool(ad.include_env_var_names),
    )
    include_network_domains = click.confirm(
        "  Inspect /etc/hosts and SSH config for AI provider domains?",
        default=bool(ad.include_network_domains),
    )

    # ----- Output ---------------------------------------------------------
    click.echo()
    ux.section("Output")
    emit_otel = click.confirm(
        "  Forward sanitized telemetry through the sidecar (OTel)?",
        default=bool(ad.emit_otel),
    )
    allow_workspace_signatures = click.confirm(
        "  Honor signature packs found inside scanned workspaces? "
        "(off is safer)",
        default=bool(ad.allow_workspace_signatures),
    )
    store_raw_local_paths = click.confirm(
        "  Persist raw local paths in the discovery state file? "
        "(off is safer)",
        default=bool(ad.store_raw_local_paths),
    )

    # ----- Diff + confirm -------------------------------------------------
    pending = _build_discovery_overrides(
        mode=mode,
        scan_roots=scan_roots,
        scan_interval_min=scan_interval_min,
        process_interval_s=process_interval_s,
        max_files_per_scan=max_files_per_scan,
        max_file_bytes=max_file_bytes,
        include_shell_history=include_shell_history,
        include_package_manifests=include_package_manifests,
        include_env_var_names=include_env_var_names,
        include_network_domains=include_network_domains,
        emit_otel=emit_otel,
        allow_workspace_signatures=allow_workspace_signatures,
        store_raw_local_paths=store_raw_local_paths,
    )
    diff = _preview_discovery_changes(ad, pending)
    enabled_changed = bool(ad.enabled) != bool(enable_pref)

    click.echo()
    ux.section("Summary")
    if enabled_changed:
        ux.subhead(
            f"enabled: {bool(ad.enabled)!r} → {bool(enable_pref)!r}",
            indent="  ",
        )
    if not diff and not enabled_changed:
        click.echo(f"  {ux.dim('No changes — current config already matches your answers.')}")
        return
    for label, before, after in diff:
        ux.subhead(f"{label}: {before!r} → {after!r}", indent="  ")
    if restart:
        ux.subhead(
            "Will restart the gateway so the sidecar applies these settings.",
            indent="  ",
        )
    else:
        ux.subhead(
            "--no-restart specified: changes are persisted but the sidecar "
            "won't pick them up until you restart manually.",
            indent="  ",
        )

    if scan and not restart:
        ux.subhead("--no-restart implies --no-scan.", indent="  ")
        scan = False
    if scan and not enable_pref:
        ux.subhead(
            "Discovery is being disabled — skipping the post-save scan.",
            indent="  ",
        )
        scan = False

    click.echo()
    if not yes and not click.confirm("  Save and apply?", default=True):
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise SystemExit(1)

    _apply_discovery_settings(ad, pending)
    ad.enabled = bool(enable_pref)
    if not ad.mode:
        ad.mode = "enhanced"

    try:
        cfg.save()
        ux.ok(
            "Config saved (ai_discovery.enabled = "
            f"{str(ad.enabled).lower()}, mode={ad.mode}, "
            f"scan_interval_min={ad.scan_interval_min})",
            indent="  ",
        )
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        ux.subhead("Re-run after fixing the underlying I/O error.", indent="    ")
        raise SystemExit(1)

    connector = _resolve_connector_for_restart(cfg)
    if restart:
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            cfg.data_dir,
            cfg.gateway.host,
            cfg.gateway.port,
            connector=connector,
        )
        ux.ok("Sidecar restarted; new settings are live.", indent="  ")
        click.echo()

        if scan and ad.enabled:
            _trigger_post_enable_scan(
                app,
                gateway_host=gateway_host,
                gateway_port=gateway_port,
                gateway_token_env=gateway_token_env,
            )

    _log_discovery_action(
        app,
        action="ai_discovery-setup",
        details=(
            f"enabled={ad.enabled} mode={ad.mode} "
            f"scan_interval_min={ad.scan_interval_min} "
            f"changes={len(diff)} restart={restart} scan={scan}"
        ),
    )


@discovery.command("scan")
@click.option("--json", "as_json", is_flag=True, help="Output the post-scan summary as JSON.")
@click.option("--gateway-host", default=None, help="Sidecar API host override.")
@click.option("--gateway-port", type=int, default=None, help="Sidecar API port override.")
@click.option(
    "--gateway-token-env",
    default=None,
    help="Environment variable containing the sidecar API token override.",
)
@pass_ctx
def discovery_scan(
    app: AppContext,
    as_json: bool,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> None:
    """Trigger one immediate AI discovery scan via the sidecar.

    Thin wrapper around ``POST /api/v1/ai-usage/scan`` that surfaces a
    friendly summary line on success and an actionable hint on the
    canonical failure mode (HTTP 503 = ai_discovery disabled in
    config). Operators were previously typing ``defenseclaw agent
    usage --refresh`` for this same effect; that command is still
    around but its name implies "render the table" rather than
    "trigger a scan", which is the cause of repeated confusion.
    """
    from defenseclaw import ux

    client = _usage_client(
        app,
        gateway_host=gateway_host,
        gateway_port=gateway_port,
        gateway_token_env=gateway_token_env,
    )
    try:
        payload = client.scan_ai_usage()
    except requests.ConnectionError as exc:
        raise click.ClickException(f"sidecar unavailable: {exc}") from exc
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        if status == 503:
            raise click.ClickException(
                "sidecar rejected scan: HTTP 503 (ai_discovery disabled in "
                "config). Run 'defenseclaw agent discovery enable' first."
            ) from exc
        raise click.ClickException(
            f"sidecar rejected scan: HTTP {status}"
        ) from exc
    except requests.RequestException as exc:
        raise click.ClickException(f"sidecar request failed: {exc}") from exc

    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    summary = payload.get("summary") or {}
    ux.section("AI discovery scan")
    ux.ok(
        f"Scan complete: active={summary.get('active_signals', 0)} "
        f"new={summary.get('new_signals', 0)} "
        f"changed={summary.get('changed_signals', 0)} "
        f"files={summary.get('files_scanned', 0)}",
        indent="  ",
    )
    ux.subhead(
        "Run 'defenseclaw agent usage' for the full table or "
        "'agent discovery status' to confirm config drift.",
        indent="  ",
    )


def _normalize_scan_roots(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


# ---------------------------------------------------------------------------
# Shared mutation pipeline for ``agent discovery enable`` / ``setup``.
#
# Both flows end up writing ``cfg.ai_discovery.*`` and bouncing the
# gateway. The flag-driven enable path and the interactive setup path
# both feed into the same trio of helpers below so:
#
#   1. The diff displayed to the operator is identical regardless of
#      whether they typed ``--scan-interval-min 10`` or answered "10"
#      at the prompt.
#   2. Audit-log lines have the same shape.
#   3. A future test can pin the contract by stubbing one helper
#      instead of two parallel code paths.
# ---------------------------------------------------------------------------


def _build_discovery_overrides(
    *,
    mode: str | None = None,
    scan_roots: str | list[str] | None = None,
    scan_interval_min: int | None = None,
    process_interval_s: int | None = None,
    max_files_per_scan: int | None = None,
    max_file_bytes: int | None = None,
    include_shell_history: bool | None = None,
    include_package_manifests: bool | None = None,
    include_env_var_names: bool | None = None,
    include_network_domains: bool | None = None,
    emit_otel: bool | None = None,
    allow_workspace_signatures: bool | None = None,
    store_raw_local_paths: bool | None = None,
) -> dict[str, Any]:
    """Collect non-None overrides into a stable, ordered mapping.

    ``None`` is the "leave as-is" sentinel — Click default of ``None``
    on every flag means an unset flag never clobbers existing config.
    Returning a dict (not kwargs) keeps the call sites symmetrical and
    lets the diff helper iterate keys deterministically. Order is
    fixed so the diff output is the same shape for the same input on
    every run; reviewers reading two log lines side-by-side don't
    have to debug a dict-iteration reordering.
    """
    overrides: dict[str, Any] = {}
    if mode is not None:
        overrides["mode"] = mode
    if scan_roots is not None:
        overrides["scan_roots"] = (
            list(scan_roots) if isinstance(scan_roots, list)
            else _normalize_scan_roots(scan_roots)
        )
    if scan_interval_min is not None:
        overrides["scan_interval_min"] = int(scan_interval_min)
    if process_interval_s is not None:
        overrides["process_interval_s"] = int(process_interval_s)
    if max_files_per_scan is not None:
        overrides["max_files_per_scan"] = int(max_files_per_scan)
    if max_file_bytes is not None:
        overrides["max_file_bytes"] = int(max_file_bytes)
    if include_shell_history is not None:
        overrides["include_shell_history"] = bool(include_shell_history)
    if include_package_manifests is not None:
        overrides["include_package_manifests"] = bool(include_package_manifests)
    if include_env_var_names is not None:
        overrides["include_env_var_names"] = bool(include_env_var_names)
    if include_network_domains is not None:
        overrides["include_network_domains"] = bool(include_network_domains)
    if emit_otel is not None:
        overrides["emit_otel"] = bool(emit_otel)
    if allow_workspace_signatures is not None:
        overrides["allow_workspace_signatures"] = bool(allow_workspace_signatures)
    if store_raw_local_paths is not None:
        overrides["store_raw_local_paths"] = bool(store_raw_local_paths)
    return overrides


def _preview_discovery_changes(
    ad: Any,
    overrides: dict[str, Any],
) -> list[tuple[str, Any, Any]]:
    """Return a list of (label, before, after) tuples for the diff line.

    Skips no-op overrides (where the value already matches the on-disk
    config). The label ordering matches ``_build_discovery_overrides``
    so a reader scanning a transcript can correlate entries by row.
    Lists are compared element-wise after the ``_normalize_scan_roots``
    pass so " ~ , /workspace" is detected as a no-op against ["~",
    "/workspace"].
    """
    diff: list[tuple[str, Any, Any]] = []
    for key, after in overrides.items():
        before = getattr(ad, key, None)
        if isinstance(before, list) and isinstance(after, list):
            if list(before) == list(after):
                continue
        elif before == after:
            continue
        diff.append((key, before, after))
    return diff


def _apply_discovery_settings(ad: Any, overrides: dict[str, Any]) -> None:
    """Mutate the AIDiscoveryConfig dataclass in place.

    Kept tiny on purpose so tests can assert on either the diff
    helper or the applier independently. We never set ``enabled``
    here — the enable/disable commands own that flag explicitly.
    """
    for key, value in overrides.items():
        if key == "enabled":
            continue
        setattr(ad, key, value)


def _resolve_connector_for_restart(cfg: Any) -> str:
    """Return the active connector name in lower-kebab form.

    Mirrors :func:`cmd_guardrail._resolve_active_connector` so the
    restart helper teardowns/setups the right adapter. Falls back to
    "openclaw" when nothing else is configured (matches Go default).
    """
    try:
        active = cfg.active_connector()
        if active:
            return str(active).strip().lower()
    except Exception:
        pass
    gc = getattr(cfg, "guardrail", None)
    if gc is not None:
        connector = getattr(gc, "connector", "")
        if connector:
            return str(connector).strip().lower()
    claw = getattr(cfg, "claw", None)
    if claw is not None:
        mode = getattr(claw, "mode", "")
        if mode:
            return str(mode).strip().lower()
    return "openclaw"


def _trigger_post_enable_scan(
    app: AppContext,
    *,
    gateway_host: str | None,
    gateway_port: int | None,
    gateway_token_env: str | None,
) -> None:
    """POST /api/v1/ai-usage/scan with bounded retries.

    The sidecar is in the middle of restarting when this is called, so
    a single shot would race with the listener bind. Retry a handful
    of times with a short backoff; surface the final failure as a
    warning rather than aborting — the user can always retry with
    ``defenseclaw agent usage --refresh``.
    """
    from defenseclaw import ux

    delays = (0.5, 1.0, 2.0, 3.0)
    last_err = ""
    for delay in delays:
        time.sleep(delay)
        try:
            client = _usage_client(
                app,
                gateway_host=gateway_host,
                gateway_port=gateway_port,
                gateway_token_env=gateway_token_env,
            )
            payload = client.scan_ai_usage()
            summary = payload.get("summary") or {}
            ux.ok(
                "Initial scan complete: "
                f"active={summary.get('active_signals', 0)} "
                f"new={summary.get('new_signals', 0)} "
                f"files={summary.get('files_scanned', 0)}",
                indent="  ",
            )
            return
        except (requests.ConnectionError, requests.Timeout) as exc:
            last_err = f"sidecar unavailable: {exc}"
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "unknown"
            last_err = f"sidecar rejected scan: HTTP {status}"
            # 503 right after restart is expected; keep retrying.
            if status != 503:
                break
        except requests.RequestException as exc:
            last_err = f"sidecar request failed: {exc}"
            break
        except click.ClickException as exc:
            last_err = str(exc.message)
            break
    ux.warn(
        f"Could not run an initial scan ({last_err or 'sidecar unreachable'}). "
        "Re-run with 'defenseclaw agent usage --refresh' once the sidecar is up.",
        indent="  ",
    )


def _log_discovery_action(app: AppContext, *, action: str, details: str) -> None:
    """Best-effort audit-log of an AI-discovery toggle.

    Routes through the AppContext logger when available; tolerates
    pre-init contexts where ``app.logger`` is None (init flows reuse
    these commands).
    """
    logger = getattr(app, "logger", None)
    if logger is None:
        return
    try:
        logger.log_action(action, "config", details)
    except Exception:
        # Audit failures must never block a config flip.
        pass


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


def _require_loaded_config(app: AppContext):
    """Return ``app.cfg``, lazily loading the real ``config.yaml`` when missing.

    The ``agent`` Click group lives in :data:`defenseclaw.main.SKIP_LOAD_COMMANDS`
    so that pre-init commands like ``agent discover`` (which only touches
    the local agent inventory and never persists state) can run before
    the operator has even executed ``defenseclaw init``. The subcommands
    in :func:`discovery_enable` / :func:`discovery_disable` / :func:`discovery_status`,
    however, MUST read and write ``ai_discovery.*`` and would otherwise
    crash with ``AttributeError: 'NoneType' object has no attribute
    'ai_discovery'``.

    Unlike :func:`_load_config_best_effort` we deliberately do NOT fall
    back to :func:`config.default_config` when loading fails — these
    commands persist via ``cfg.save()``, and writing a synthesized
    default config under the operator's real ``~/.defenseclaw/`` would
    silently clobber connector / guardrail settings they rely on.
    Failing fast with a clear "run init first" message is the safer
    UX for toggle commands.
    """
    cfg = getattr(app, "cfg", None)
    if cfg is not None:
        return cfg
    from defenseclaw import config as cfg_mod

    try:
        cfg = cfg_mod.load()
    except Exception as exc:
        raise click.ClickException(
            f"unable to load config (run 'defenseclaw init' first): {exc}"
        ) from exc
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


# State weight for stable, "what's new first" sort order in both summary
# and detail views. ``new`` ranks above ``changed`` because that's what an
# operator most wants to triage; ``gone`` is last (and hidden by default).
_AI_USAGE_STATE_ORDER: dict[str, int] = {
    "new": 0,
    "changed": 1,
    "active": 2,
    "gone": 3,
}


def _filter_ai_usage_signals(
    signals: list[dict[str, Any]],
    *,
    states: tuple[str, ...],
    categories: tuple[str, ...],
    products: tuple[str, ...],
    show_gone: bool,
    components: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Apply the operator-supplied filters to the raw signal list.

    Filtering is intentionally done client-side: the sidecar already
    streamed everything it knows over a single ``GET /api/v1/ai-usage``
    call, so re-querying with different filters would only burn round
    trips. The matching rules:

    * ``states`` — exact, case-insensitive set membership. When empty,
      ``gone`` is suppressed unless ``show_gone`` is set; this is the
      "default == not-noisy" behavior the rest of the command relies on.
    * ``categories`` — exact, case-insensitive set membership against
      ``signal.category``.
    * ``products`` — case-insensitive **substring** match against
      ``signal.product``. Substring (not exact) so that operators can
      type ``--product claude`` and catch both ``Claude Code`` and
      ``Claude Desktop`` without memorising the exact catalog spelling.
    * ``components`` — case-insensitive substring match against
      ``signal.component.name`` (or ``signal.product`` for legacy
      signatures that don't carry a component block). Lets the
      operator type ``--component openai`` and pick out every
      OpenAI-named SDK install across npm/pypi/go.
    """
    state_set = {s.lower() for s in states} if states else set()
    category_set = {c.lower() for c in categories} if categories else set()
    product_needles = [p.lower() for p in products] if products else []
    component_needles = [c.lower() for c in components] if components else []

    out: list[dict[str, Any]] = []
    for sig in signals or []:
        state = str(sig.get("state", "")).lower()
        if state_set:
            if state not in state_set:
                continue
        elif state == "gone" and not show_gone:
            continue
        if category_set and str(sig.get("category", "")).lower() not in category_set:
            continue
        if product_needles:
            product = str(sig.get("product", "")).lower()
            if not any(needle in product for needle in product_needles):
                continue
        if component_needles:
            comp = sig.get("component") or {}
            comp_name = str(comp.get("name", "")).lower()
            haystack = comp_name or str(sig.get("product", "")).lower()
            if not any(needle in haystack for needle in component_needles):
                continue
        out.append(sig)
    return out


def _summarize_ai_usage_signals(
    signals: list[dict[str, Any]],
    *,
    by_detector: bool = False,
) -> list[tuple[tuple[str, str, str, str, str], int, list[str]]]:
    """Collapse signals to one row per product (default) or per
    (state, category, product, vendor, detector) when
    ``by_detector=True``.

    Returns a list of ``((state, category, product, vendor, detector),
    count, basenames)`` tuples sorted by state weight, then descending
    count, then category/product alphabetically. In the default
    normalized mode the ``category`` and ``detector`` slots in the
    legacy 5-tuple carry comma-joined aggregates ("ai_cli,
    active_process, mcp_server" / "binary, process, mcp") so callers
    that snapshot the tuple shape keep working AND see the roll-up.

    Wide-net detectors emit one signal per evidence file (every
    ``package.json``, every ``pyproject.toml``, every
    ``requirements.txt`` found under any scan root). On a typical
    developer workstation that produces hundreds of
    ``package_dependency`` rows that all share the same
    ``(product, vendor, detector)`` tuple — which is exactly the
    "too noisy" failure mode this view fixes. Grouping keeps the
    information density high and pushes the actual evidence (file
    basenames) into a single column the operator can scan.
    """
    rows = _summarize_ai_usage_signals_full(signals, by_detector=by_detector)
    return [(row["key"], row["count"], row["basenames"]) for row in rows]


def _summarize_ai_usage_signals_full(
    signals: list[dict[str, Any]],
    *,
    by_detector: bool = False,
) -> list[dict[str, Any]]:
    """Internal grouped form that also carries component / version /
    last-active rollups for the new high-fidelity columns.

    Default behavior (``by_detector=False``) collapses by
    ``(state, product, vendor, ecosystem, name, version)`` and
    aggregates the constituent ``categories[]`` / ``detectors[]``
    so a product like "Claude Code" -- which is independently
    discovered by the binary / process / mcp / config / shell
    detectors -- shows up as ONE row tagged "via 7 channels"
    instead of seven near-identical rows.

    ``by_detector=True`` reverts to the legacy
    ``(state, category, product, vendor, detector, ecosystem, name,
    version)`` key for forensics / per-detector inspection. This
    matches what every prior version of the CLI emitted, so
    operators with shell aliases that pipe `agent usage --by-detector`
    into grep/awk see no change.

    The returned dicts are an additive superset; the legacy 5-tuple
    is preserved on the ``key`` field with ``categories`` /
    ``detectors`` joined when in normalized mode.
    """
    # Use a dict keyed on a tuple regardless of mode -- the tuple
    # length differs but Python doesn't care; we just choose which
    # axes to fold into the key.
    groups: dict[tuple, dict[str, Any]] = {}
    for sig in signals:
        comp = sig.get("component") or {}
        ecosystem = str(comp.get("ecosystem", "")).lower()
        comp_name = str(comp.get("name", "")).lower()
        version = str(comp.get("version", "") or sig.get("version", "") or "")
        category = str(sig.get("category", ""))
        detector = str(sig.get("detector", ""))
        if by_detector:
            key = (
                str(sig.get("state", "")),
                category,
                str(sig.get("product", "")),
                str(sig.get("vendor", "")),
                detector,
                ecosystem,
                comp_name,
                version,
            )
        else:
            # Drop category and detector from the key -- "Claude
            # Code" is the same product whether we found it via
            # `binary` or `mcp`. Categories / detectors are
            # aggregated as list columns instead.
            key = (
                str(sig.get("state", "")),
                str(sig.get("product", "")),
                str(sig.get("vendor", "")),
                ecosystem,
                comp_name,
                version,
            )
        slot = groups.get(key)
        if slot is None:
            slot = {
                # Legacy 5-tuple shape for back-compat. In
                # normalized mode the category / detector slots
                # are filled in below from the joined aggregates
                # (we use the aggregated lists, not just the
                # current sig, so the key the caller sees is
                # stable across signal order).
                "key": (
                    str(sig.get("state", "")),
                    "",  # category(ies) -- filled after loop
                    str(sig.get("product", "")),
                    str(sig.get("vendor", "")),
                    "",  # detector(s) -- filled after loop
                ),
                "count": 0,
                "basenames": [],
                "ecosystem": comp.get("ecosystem", ""),
                "component": comp.get("name", ""),
                "framework": comp.get("framework", ""),
                "version": version,
                "last_active_at": "",
                # Aggregated lists -- we always populate these so
                # downstream renderers can show a "Categories" /
                # "Detectors" column in normalized mode without a
                # second pass over the signals. Insertion order is
                # preserved (most-frequent detectors appear in
                # discovery order) and we dedupe to keep noise
                # down.
                "categories": [],
                "detectors": [],
                # Per-component confidence rolls up identically
                # across every signal in the same (ecosystem,
                # name) group -- `EnrichSignalsWithComponentConfidence`
                # (gateway-side) stamps the same numbers on every
                # row before the API returns them. Capture the
                # first non-empty pair so the default grouped view
                # can render a per-group confidence column without
                # forcing operators into --detail.
                "identity_score": None,
                "identity_band": "",
                "presence_score": None,
                "presence_band": "",
            }
            groups[key] = slot
        slot["count"] += 1
        if category and category not in slot["categories"]:
            slot["categories"].append(category)
        if detector and detector not in slot["detectors"]:
            slot["detectors"].append(detector)
        # Preserve insertion order so the sample reflects what the
        # detector saw first; dedupe so we do not show the same file
        # twice for groups that span multiple matching signatures.
        seen = slot["basenames"]
        for bn in sig.get("basenames", []) or []:
            if bn and bn not in seen:
                seen.append(bn)
        # Track the most recent last_active_at across the group;
        # ISO-8601 strings sort lexicographically, so we can take
        # max() without parsing.
        la = str(sig.get("last_active_at", "") or "")
        if la and la > slot["last_active_at"]:
            slot["last_active_at"] = la
        # First non-empty wins -- subsequent signals in the same
        # group MUST agree (same component => same engine output),
        # but if a future detector starts shipping per-signal
        # variation we still keep the highest-quality observation
        # rather than blindly overwriting.
        if slot["identity_band"] == "" and sig.get("identity_band"):
            slot["identity_band"] = str(sig.get("identity_band", ""))
            slot["identity_score"] = sig.get("identity_score")
        if slot["presence_band"] == "" and sig.get("presence_band"):
            slot["presence_band"] = str(sig.get("presence_band", ""))
            slot["presence_score"] = sig.get("presence_score")

    # Backfill the legacy 5-tuple key now that we know the full
    # aggregated category / detector list. Joining with ", " keeps
    # the format readable when piped through `grep` / `awk`; the
    # raw lists remain on the dict for renderers that want them.
    for slot in groups.values():
        cats_join = ", ".join(slot["categories"])
        dets_join = ", ".join(slot["detectors"])
        legacy = list(slot["key"])
        legacy[1] = cats_join
        legacy[4] = dets_join
        slot["key"] = tuple(legacy)

    rows = list(groups.values())
    rows.sort(
        key=lambda row: (
            _AI_USAGE_STATE_ORDER.get(row["key"][0].lower(), 99),
            -row["count"],
            row["key"][1],
            row["key"][2],
        )
    )
    return rows


def _format_runtime(runtime: dict[str, Any]) -> str:
    """Render the new ``runtime`` block compactly for the detail view.

    Format: ``pid=1234 user=alice up=3h12m`` — fields are dropped when
    the underlying value is missing so signatures from non-process
    detectors (which won't have a runtime block at all) just render an
    empty string and tests that don't seed runtime data stay stable.
    """
    if not runtime:
        return ""
    parts: list[str] = []
    pid = runtime.get("pid")
    if pid:
        parts.append(f"pid={pid}")
    user = runtime.get("user")
    if user:
        parts.append(f"user={user}")
    uptime = runtime.get("uptime_sec")
    if isinstance(uptime, (int, float)) and uptime > 0:
        parts.append(f"up={_humanize_seconds(int(uptime))}")
    comm = runtime.get("comm")
    if comm and not parts:
        # If nothing else parsed cleanly, at least show the comm name
        # so the row isn't blank for an active process.
        parts.append(str(comm))
    return " ".join(parts)


def _humanize_seconds(seconds: int) -> str:
    """Compact ``[Nd][Nh][Nm][Ns]`` formatting; uses the two largest units."""
    if seconds <= 0:
        return "0s"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    units = [(days, "d"), (hours, "h"), (minutes, "m"), (secs, "s")]
    nonzero = [(v, u) for v, u in units if v > 0]
    if not nonzero:
        return "0s"
    chosen = nonzero[:2]
    return "".join(f"{v}{u}" for v, u in chosen)


def _format_relative_time(value: Any) -> str:
    """Render an ISO-8601 timestamp as ``Nm ago`` / ``Nh ago``.

    Operators care about freshness, not the wall-clock value
    (``2026-05-05T03:14:09.123Z`` in a table is just visual noise).
    Falls back to the raw string if parsing fails so we never lose
    ground truth.
    """
    if not value:
        return ""
    text = str(value)
    try:
        from datetime import datetime, timezone
        s = text.replace("Z", "+00:00")
        ts = datetime.fromisoformat(s)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = (now - ts).total_seconds()
        if delta < 0:
            return text
        if delta < 60:
            return f"{int(delta)}s ago"
        if delta < 3600:
            return f"{int(delta // 60)}m ago"
        if delta < 86400:
            return f"{int(delta // 3600)}h ago"
        days = int(delta // 86400)
        if days < 30:
            return f"{days}d ago"
        return ts.strftime("%Y-%m-%d")
    except Exception:
        return text


def _format_evidence_sample(basenames: list[str], *, limit: int = 3) -> str:
    """Render up to ``limit`` basenames with a ``(+N)`` suffix for the rest.

    Empty input yields an empty string so Rich does not pad cells with a
    misleading placeholder. The ``(+N)`` suffix mirrors how the rest of
    the CLI summarises truncated lists (see e.g. ``cmd_doctor`` and the
    guardrail status renderer).
    """
    if not basenames:
        return ""
    head = basenames[:limit]
    sample = ", ".join(head)
    extra = len(basenames) - len(head)
    if extra > 0:
        sample += f" (+{extra})"
    return sample


def _format_csv_truncated(items: list[str], *, limit: int = 2) -> str:
    """Compact "<a>, <b> (+N)" rendering for the rolled-up
    Categories / Detectors columns in the default normalized view.

    Mirrors :func:`_format_evidence_sample` but with a smaller
    default ``limit`` because category / detector names tend to be
    longer than file basenames (e.g. ``provider_history``,
    ``shell_history``, ``application``) and a 3-item cell would
    push the rest of the table off-screen at common widths.
    """
    if not items:
        return ""
    head = items[:limit]
    sample = ", ".join(head)
    extra = len(items) - len(head)
    if extra > 0:
        sample += f" (+{extra})"
    return sample


def _render_ai_usage_table(
    payload: dict[str, Any],
    *,
    detail: bool = False,
    states: tuple[str, ...] = (),
    categories: tuple[str, ...] = (),
    products: tuple[str, ...] = (),
    components: tuple[str, ...] = (),
    show_gone: bool = False,
    by_detector: bool = False,
    limit: int = 0,
) -> str:
    raw_signals = payload.get("signals", []) or []
    filtered = _filter_ai_usage_signals(
        raw_signals,
        states=states,
        categories=categories,
        products=products,
        show_gone=show_gone,
        components=components,
    )
    summary = payload.get("summary", {}) or {}
    enabled = payload.get("enabled", True)

    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:
        return _render_ai_usage_plain(
            payload,
            signals=filtered,
            detail=detail,
            by_detector=by_detector,
            limit=limit,
        )

    from io import StringIO

    stream = StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None, width=120)

    title = "AI visibility"
    if not enabled:
        title += " (disabled)"
    counts_caption = (
        f"active={summary.get('active_signals', 0)} "
        f"new={summary.get('new_signals', 0)} "
        f"changed={summary.get('changed_signals', 0)} "
        f"gone={summary.get('gone_signals', 0)}"
    )
    table_title = f"{title} — {counts_caption}"

    if detail:
        rows = filtered
        displayed = rows[:limit] if limit > 0 else rows
        # Conditionally surface the high-fidelity columns: only show
        # Component/Version/Runtime/Last active when at least one row
        # actually has them. Keeps the legacy detail view compact for
        # operators on signature packs that haven't been promoted to
        # the v2 component schema yet.
        has_component = any((sig.get("component") or {}).get("name") for sig in displayed)
        has_version = any(
            ((sig.get("component") or {}).get("version") or sig.get("version"))
            for sig in displayed
        )
        has_runtime = any(sig.get("runtime") for sig in displayed)
        has_last_active = any(sig.get("last_active_at") for sig in displayed)
        # Identity / Presence columns appear only when the gateway
        # has the two-axis engine wired (v2+). Older sidecars still
        # render cleanly because the column is dropped entirely.
        has_confidence = any(
            sig.get("identity_band") or sig.get("presence_band")
            for sig in displayed
        )
        # The richer Phase-2 evidence records ride alongside the
        # legacy basenames slice so we can pull from whichever the
        # signal carries.
        has_rich_evidence = any(sig.get("evidence") for sig in displayed)

        table = Table(title=table_title)
        table.add_column("State")
        table.add_column("Category")
        table.add_column("Product")
        if has_component:
            table.add_column("Component")
        if has_version:
            table.add_column("Version")
        table.add_column("Vendor")
        table.add_column("Detector")
        if has_confidence:
            table.add_column("Identity")
            table.add_column("Presence")
        if has_runtime:
            table.add_column("Runtime")
        if has_last_active:
            table.add_column("Last active")
        table.add_column("Evidence")
        # Per-component confidence is identical for every signal
        # in the same (ecosystem, name) group -- repeating it on
        # all 685 rows of the same SDK was misleading operators
        # into thinking we computed a per-row score. We sort the
        # detail view (state, then group identity) so signals from
        # the same component are contiguous, then blank the
        # Identity/Presence cells after the first row of each run.
        # Falls back to product/vendor for legacy signals that
        # have no Component block so we still dedup something
        # sensible there too.
        def _conf_group_key(s: dict[str, Any]) -> tuple[str, str, str, str]:
            c = s.get("component") or {}
            return (
                str(c.get("ecosystem", "")),
                str(c.get("name", "")),
                str(s.get("product", "")),
                str(s.get("vendor", "")),
            )

        # Stable sort: group by confidence-key but preserve the
        # caller's incoming state/category ordering inside each
        # group so the rest of the table still reads naturally.
        displayed = sorted(displayed, key=_conf_group_key)
        prev_conf_key: tuple[str, str, str, str] | None = None
        for sig in displayed:
            comp = sig.get("component") or {}
            runtime = sig.get("runtime") or {}
            row: list[str] = [
                str(sig.get("state", "")),
                str(sig.get("category", "")),
                str(sig.get("product", "")),
            ]
            if has_component:
                ecosystem = str(comp.get("ecosystem", ""))
                comp_name = str(comp.get("name", ""))
                if ecosystem and comp_name:
                    row.append(f"{comp_name} ({ecosystem})")
                else:
                    row.append(comp_name)
            if has_version:
                ver = str(comp.get("version", "") or sig.get("version", "") or "")
                row.append(ver)
            row.extend([
                str(sig.get("vendor", "")),
                str(sig.get("detector", "")),
            ])
            if has_confidence:
                conf_key = _conf_group_key(sig)
                if conf_key == prev_conf_key:
                    row.append("")
                    row.append("")
                else:
                    row.append(_format_confidence(
                        sig.get("identity_score"), sig.get("identity_band")))
                    row.append(_format_confidence(
                        sig.get("presence_score"), sig.get("presence_band")))
                    prev_conf_key = conf_key
            if has_runtime:
                row.append(_format_runtime(runtime))
            if has_last_active:
                row.append(_format_relative_time(sig.get("last_active_at", "")))
            # Prefer the richer evidence records (basename + quality
            # + match_kind) when the gateway included them; older
            # signals only ship the basenames slice so we fall back
            # to the legacy renderer to keep them rendering.
            if has_rich_evidence and sig.get("evidence"):
                row.append(_format_evidence_records(sig.get("evidence") or []))
            else:
                row.append(_format_evidence_sample(sig.get("basenames", []) or []))
            table.add_row(*row)
        console.print(table)
        hidden = len(rows) - len(displayed)
        signal_word = _pluralize(len(rows), "signal", "signals")
        if hidden > 0:
            shown_clause = f"{len(displayed)} of {len(rows)} {signal_word} shown"
        else:
            shown_clause = f"{len(rows)} {signal_word} shown"
        footer = (
            f"{shown_clause} "
            f"(scanned {summary.get('scanned_at', '-')}, "
            f"files={summary.get('files_scanned', 0)})."
        )
        if hidden > 0:
            footer += f" {hidden} more hidden by --limit; raise it or use --json for the full list."
        console.print(footer)
        return stream.getvalue()

    full_groups = _summarize_ai_usage_signals_full(filtered, by_detector=by_detector)
    displayed_full = full_groups[:limit] if limit > 0 else full_groups
    has_component = any(g.get("component") for g in displayed_full)
    has_version = any(g.get("version") for g in displayed_full)
    has_last_active = any(g.get("last_active_at") for g in displayed_full)
    # Surface confidence in the default grouped view so operators
    # don't have to drop into --detail just to see whether the
    # gateway is sure about a component. Only render when at least
    # one row carries the v2 fields (older sidecars stay clean).
    has_confidence = any(
        g.get("identity_band") or g.get("presence_band") for g in displayed_full
    )

    table = Table(title=table_title)
    table.add_column("State")
    # Column header reflects normalization mode: in the default
    # one-row-per-product mode each row carries multiple categories
    # / detectors so the headers go plural; in --by-detector mode we
    # restore the legacy singular labels (and the legacy 5-tuple
    # contains a single value in each slot, just as before).
    if by_detector:
        cat_header, det_header = "Category", "Detector"
    else:
        cat_header, det_header = "Categories", "Detectors"
    table.add_column(cat_header)
    table.add_column("Product")
    if has_component:
        table.add_column("Component")
    if has_version:
        table.add_column("Version")
    table.add_column("Vendor")
    table.add_column(det_header)
    table.add_column("Count", justify="right")
    if has_confidence:
        table.add_column("Identity")
        table.add_column("Presence")
    if has_last_active:
        table.add_column("Last active")
    table.add_column("Sample evidence")
    for g in displayed_full:
        state, category_join, product, vendor, detector_join = g["key"]
        # In the normalized view we render compact "<first>, <second> (+N)"
        # cells so a product with 5 detectors does not blow up the
        # table width. The legacy 5-tuple already carries the joined
        # form (see backfill at the end of `_summarize_ai_usage_signals_full`)
        # but truncation needs the raw list, so prefer those when
        # they're populated.
        if not by_detector:
            cat_cell = _format_csv_truncated(g.get("categories") or [], limit=2)
            det_cell = _format_csv_truncated(g.get("detectors") or [], limit=2)
        else:
            cat_cell = category_join
            det_cell = detector_join
        row: list[str] = [state, cat_cell, product]
        if has_component:
            ecosystem = str(g.get("ecosystem", ""))
            comp_name = str(g.get("component", ""))
            if ecosystem and comp_name:
                row.append(f"{comp_name} ({ecosystem})")
            else:
                row.append(comp_name)
        if has_version:
            row.append(str(g.get("version", "")))
        row.extend([vendor, det_cell, str(g["count"])])
        if has_confidence:
            row.append(_format_confidence(
                g.get("identity_score"), g.get("identity_band")))
            row.append(_format_confidence(
                g.get("presence_score"), g.get("presence_band")))
        if has_last_active:
            row.append(_format_relative_time(g.get("last_active_at", "")))
        row.append(_format_evidence_sample(g["basenames"]))
        table.add_row(*row)
    console.print(table)
    total_signals = sum(g["count"] for g in full_groups)
    group_word = _pluralize(len(full_groups), "group", "groups")
    signal_word = _pluralize(total_signals, "signal", "signals")
    footer = (
        f"{len(full_groups)} {group_word}, {total_signals} {signal_word} "
        f"(scanned {summary.get('scanned_at', '-')}, "
        f"files={summary.get('files_scanned', 0)})."
    )
    hidden = len(full_groups) - len(displayed_full)
    if hidden > 0:
        footer += f" {hidden} more {_pluralize(hidden, 'group', 'groups')} hidden by --limit."
    footer += (
        " Use --detail for per-signal rows, --by-detector to split by "
        "category/detector, --json for raw, --state/--category/--product"
        "/--component to filter."
    )
    console.print(footer)
    return stream.getvalue()


def _pluralize(n: int, singular: str, plural: str) -> str:
    return singular if n == 1 else plural


def _render_ai_usage_plain(
    payload: dict[str, Any],
    *,
    signals: list[dict[str, Any]] | None = None,
    detail: bool = False,
    by_detector: bool = False,
    limit: int = 0,
) -> str:
    """Rich-free fallback used when the optional ``rich`` import fails.

    Mirrors the rich version's structure (header line, then either
    grouped or per-signal rows, then the counts footer) so log scrapes
    stay parseable across both renderers.
    """
    if signals is None:
        signals = payload.get("signals", []) or []
    summary = payload.get("summary", {}) or {}
    lines = ["AI visibility"]

    if detail:
        rows = signals[:limit] if limit > 0 else signals
        for sig in rows:
            comp = sig.get("component") or {}
            runtime = sig.get("runtime") or {}
            ver = str(comp.get("version", "") or sig.get("version", "") or "")
            comp_name = str(comp.get("name", ""))
            ecosystem = str(comp.get("ecosystem", ""))
            comp_label = f"{comp_name} ({ecosystem})" if comp_name and ecosystem else comp_name
            evidence_cell = (
                _format_evidence_records(sig.get("evidence") or [])
                if sig.get("evidence")
                else _format_evidence_sample(sig.get("basenames", []) or [])
            )
            fields = [
                str(sig.get("state", "")),
                str(sig.get("category", "")),
                str(sig.get("product", "")),
                comp_label,
                ver,
                str(sig.get("vendor", "")),
                str(sig.get("detector", "")),
                _format_confidence(sig.get("identity_score"), sig.get("identity_band")),
                _format_confidence(sig.get("presence_score"), sig.get("presence_band")),
                _format_runtime(runtime),
                _format_relative_time(sig.get("last_active_at", "")),
                evidence_cell,
            ]
            lines.append(" | ".join(fields))
    else:
        full_groups = _summarize_ai_usage_signals_full(signals, by_detector=by_detector)
        rows_full = full_groups[:limit] if limit > 0 else full_groups
        for g in rows_full:
            state, category_join, product, vendor, detector_join = g["key"]
            ecosystem = str(g.get("ecosystem", ""))
            comp_name = str(g.get("component", ""))
            comp_label = f"{comp_name} ({ecosystem})" if comp_name and ecosystem else comp_name
            # Plain renderer keeps the joined string format -- it is
            # log-scrape friendly and operators piping through awk
            # already handle commas inside fields.
            lines.append(" | ".join([
                state,
                category_join,
                product,
                comp_label,
                str(g.get("version", "")),
                vendor,
                detector_join,
                str(g["count"]),
                _format_relative_time(g.get("last_active_at", "")),
                _format_evidence_sample(g["basenames"]),
            ]))

    lines.append(
        f"active={summary.get('active_signals', 0)} "
        f"new={summary.get('new_signals', 0)} "
        f"changed={summary.get('changed_signals', 0)} "
        f"gone={summary.get('gone_signals', 0)}"
    )
    return "\n".join(lines) + "\n"


def _render_ai_processes_table(
    process_signals: list[dict[str, Any]],
    *,
    limit: int = 0,
) -> str:
    """Render the live AI processes view: PID/PPID/uptime/user/comm/product."""
    displayed = process_signals[:limit] if limit > 0 else process_signals

    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:
        return _render_ai_processes_plain(displayed)

    from io import StringIO

    stream = StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None, width=120)

    title = f"AI processes ({len(process_signals)} live)"
    table = Table(title=title)
    table.add_column("PID", justify="right")
    table.add_column("PPID", justify="right")
    table.add_column("User")
    table.add_column("Up")
    table.add_column("Product")
    table.add_column("Vendor")
    table.add_column("Comm")
    table.add_column("Last active")
    for sig in displayed:
        runtime = sig.get("runtime") or {}
        table.add_row(
            str(runtime.get("pid", "") or ""),
            str(runtime.get("ppid", "") or ""),
            str(runtime.get("user", "") or ""),
            _humanize_seconds(int(runtime.get("uptime_sec", 0) or 0)),
            str(sig.get("product", "")),
            str(sig.get("vendor", "")),
            str(runtime.get("comm", "") or ""),
            _format_relative_time(sig.get("last_active_at", "")),
        )
    console.print(table)
    hidden = len(process_signals) - len(displayed)
    footer = f"{len(displayed)} of {len(process_signals)} shown"
    if hidden > 0:
        footer += f" ({hidden} hidden by --limit)"
    footer += ". Use --json for the full list."
    console.print(footer)
    return stream.getvalue()


def _render_ai_processes_plain(process_signals: list[dict[str, Any]]) -> str:
    lines = [f"AI processes ({len(process_signals)} live)"]
    for sig in process_signals:
        runtime = sig.get("runtime") or {}
        lines.append(
            " | ".join([
                str(runtime.get("pid", "") or ""),
                str(runtime.get("ppid", "") or ""),
                str(runtime.get("user", "") or ""),
                _humanize_seconds(int(runtime.get("uptime_sec", 0) or 0)),
                str(sig.get("product", "")),
                str(sig.get("vendor", "")),
                str(runtime.get("comm", "") or ""),
                _format_relative_time(sig.get("last_active_at", "")),
            ])
        )
    return "\n".join(lines) + "\n"


def _render_ai_components_table(
    components: list[dict[str, Any]],
    *,
    payload: dict[str, Any] | None = None,
    limit: int = 0,
) -> str:
    """Render the deduped components rollup. One row per (ecosystem, name)."""
    displayed = components[:limit] if limit > 0 else components

    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:
        return _render_ai_components_plain(displayed)

    from io import StringIO

    stream = StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None, width=140)

    # Conditionally surface confidence + detectors columns: only show
    # them when at least one row carries the v2 rollup fields. Keeps
    # the listing compact on older sidecars that have not been
    # upgraded to the two-axis engine yet.
    has_confidence = any(
        c.get("identity_band") or c.get("presence_band") for c in displayed)
    has_detectors = any(c.get("detectors") for c in displayed)

    title = f"AI components ({len(components)} unique)"
    table = Table(title=title)
    table.add_column("Ecosystem")
    table.add_column("Component")
    table.add_column("Versions")
    table.add_column("Framework")
    table.add_column("Vendor")
    table.add_column("Workspaces", justify="right")
    table.add_column("Installs", justify="right")
    if has_confidence:
        table.add_column("Identity")
        table.add_column("Presence")
    if has_detectors:
        table.add_column("Detectors")
    table.add_column("Last seen")
    for c in displayed:
        row: list[str] = [
            str(c.get("ecosystem", "")),
            str(c.get("name", "")),
            _format_versions(c.get("versions") or c.get("version") or ""),
            str(c.get("framework", "")),
            str(c.get("vendor", "")),
            # New rollup uses workspace_count/install_count; fall
            # back to the older "workspaces"/"installs" keys for
            # back-compat with v1 payloads.
            str(c.get("workspace_count", c.get("workspaces", 0)) or 0),
            str(c.get("install_count", c.get("installs", 0)) or 0),
        ]
        if has_confidence:
            row.append(_format_confidence(
                c.get("identity_score"), c.get("identity_band")))
            row.append(_format_confidence(
                c.get("presence_score"), c.get("presence_band")))
        if has_detectors:
            row.append(_format_detectors(c.get("detectors") or []))
        row.append(_format_relative_time(
            c.get("last_active_at") or c.get("last_seen", "")))
        table.add_row(*row)
    console.print(table)
    hidden = len(components) - len(displayed)
    footer = f"{len(displayed)} of {len(components)} shown"
    if hidden > 0:
        footer += f" ({hidden} hidden by --limit)"
    footer += (
        ". Use --json for the full rollup, "
        "`agent components show NAME` for per-install detail, "
        "`agent confidence explain NAME` for the score breakdown."
    )
    console.print(footer)
    return stream.getvalue()


def _render_ai_components_plain(components: list[dict[str, Any]]) -> str:
    lines = [f"AI components ({len(components)} unique)"]
    has_confidence = any(
        c.get("identity_band") or c.get("presence_band") for c in components)
    for c in components:
        cells = [
            str(c.get("ecosystem", "")),
            str(c.get("name", "")),
            _format_versions(c.get("versions") or c.get("version") or ""),
            str(c.get("framework", "")),
            str(c.get("vendor", "")),
            str(c.get("workspace_count", c.get("workspaces", 0)) or 0),
            str(c.get("install_count", c.get("installs", 0)) or 0),
        ]
        if has_confidence:
            cells.append(_format_confidence(
                c.get("identity_score"), c.get("identity_band")))
            cells.append(_format_confidence(
                c.get("presence_score"), c.get("presence_band")))
        cells.append(_format_relative_time(
            c.get("last_active_at") or c.get("last_seen", "")))
        lines.append(" | ".join(cells))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Helpers shared by `agent components`, `agent components show`,
# `agent components history`, and `agent confidence explain`.
# Centralised so the CLI's confidence rendering stays in lockstep
# with what the gateway returns.
# ---------------------------------------------------------------------------


def _format_confidence(score: Any, band: Any) -> str:
    """Render ``band (XX%)`` for the listing tables.

    Tolerates missing inputs (older sidecars, signals without an
    engine result yet) by returning an empty string so the column
    stays visually balanced.
    """
    band_str = str(band or "").strip()
    try:
        pct = round(float(score) * 100) if score is not None else None
    except (TypeError, ValueError):
        pct = None
    if pct is None and not band_str:
        return ""
    if pct is None:
        return band_str
    if not band_str:
        return f"{pct}%"
    return f"{band_str} ({pct}%)"


def _format_logit_delta(pp: Any) -> str:
    """Render a percentage-point shift like ``+12.4pp`` or ``-3.1pp``.

    Used by the confidence explain waterfall so an operator can see
    each evidence row's contribution without converting log-odds in
    their head.
    """
    try:
        v = float(pp)
    except (TypeError, ValueError):
        return ""
    sign = "+" if v >= 0 else ""
    return f"{sign}{v:.1f}pp"


def _format_versions(versions: Any) -> str:
    """Compact version string for the listing column.

    The rollup ships ``versions: []string`` (multiple distinct
    versions seen across installs); the older API shipped a single
    ``version`` scalar. Handle both transparently.
    """
    if isinstance(versions, list):
        cleaned = [str(v).strip() for v in versions if str(v).strip()]
        if not cleaned:
            return ""
        if len(cleaned) <= 3:
            return ", ".join(cleaned)
        return f"{', '.join(cleaned[:3])} (+{len(cleaned) - 3} more)"
    if not versions:
        return ""
    return str(versions)


def _format_detectors(detectors: list[Any], *, limit: int = 4) -> str:
    """Render the detector set as a compact, sorted, deduped list."""
    cleaned = sorted({str(d).strip() for d in detectors if str(d).strip()})
    if not cleaned:
        return ""
    if len(cleaned) <= limit:
        return ", ".join(cleaned)
    return f"{', '.join(cleaned[:limit])} (+{len(cleaned) - limit} more)"


def _format_evidence_records(
    records: list[dict[str, Any]],
    *,
    limit: int = 3,
) -> str:
    """Render Phase-2 ``evidence[]`` rows compactly for a column.

    Each row is shaped as ``basename · q=0.7 · substring`` so an
    operator can see at a glance which detector fed which filename
    and how confident the match was. Falls back gracefully when
    ``quality`` or ``match_kind`` are missing so legacy gateway
    payloads still render.
    """
    cleaned: list[str] = []
    for ev in records or []:
        if not isinstance(ev, dict):
            continue
        basename = str(ev.get("basename", "")).strip()
        if not basename:
            # Path-hash-only evidence still gets surfaced so the
            # operator knows something was scored, just unprintable.
            phash = str(ev.get("path_hash", "")).strip()
            basename = (phash[:14] + "…") if phash else "<no-path>"
        bits = [basename]
        try:
            q = float(ev.get("quality"))
            if q < 1.0 or q > 1.0:
                bits.append(f"q={q:.2g}")
        except (TypeError, ValueError):
            pass
        match_kind = str(ev.get("match_kind", "")).strip()
        if match_kind and match_kind != "exact":
            bits.append(match_kind)
        cleaned.append(" · ".join(bits))
    if not cleaned:
        return ""
    if len(cleaned) <= limit:
        return "; ".join(cleaned)
    extra = len(cleaned) - limit
    return f"{'; '.join(cleaned[:limit])} (+{extra} more)"


def _components_meta(
    click_ctx: click.Context,
) -> tuple[AppContext | None, str | None, int | None, str | None]:
    """Pull the gateway plumbing the parent ``components`` group stashed
    on ``click_ctx.meta``.

    Returns ``(app, gateway_host, gateway_port, gateway_token_env)``.
    Each value falls back to ``None`` so the caller still gets a
    usable client (``_usage_client`` handles ``None`` for every field).
    Falls back to ``current_context().obj`` when meta is empty so
    direct ``defenseclaw agent components show ...`` invocations
    (no parent group context, e.g. in tests) keep working.
    """
    meta = click_ctx.meta if click_ctx is not None else {}
    app = meta.get("agent.components.app")
    if app is None:
        # Last-resort lookup so test harnesses that pass the
        # AppContext via `runner.invoke(..., obj=app)` still get a
        # functioning client.
        obj = (click_ctx.obj if click_ctx is not None else None)
        if isinstance(obj, AppContext):
            app = obj
    return (
        app,
        meta.get("agent.components.gateway_host"),
        meta.get("agent.components.gateway_port"),
        meta.get("agent.components.gateway_token_env"),
    )


def _filter_components(
    components: list[dict[str, Any]],
    *,
    ecosystems: tuple[str, ...] = (),
    names: tuple[str, ...] = (),
    min_identity: float | None = None,
    min_presence: float | None = None,
) -> list[dict[str, Any]]:
    """Apply the operator-supplied filters to the components rollup."""
    eco_set = {e.lower() for e in ecosystems} if ecosystems else set()
    name_needles = [n.lower() for n in names] if names else []
    rows: list[dict[str, Any]] = []
    for c in components:
        if eco_set and str(c.get("ecosystem", "")).lower() not in eco_set:
            continue
        if name_needles:
            cname = str(c.get("name", "")).lower()
            if not any(needle in cname for needle in name_needles):
                continue
        if min_identity is not None:
            try:
                if float(c.get("identity_score", 0) or 0) < min_identity:
                    continue
            except (TypeError, ValueError):
                continue
        if min_presence is not None:
            try:
                if float(c.get("presence_score", 0) or 0) < min_presence:
                    continue
            except (TypeError, ValueError):
                continue
        rows.append(c)
    return rows


def _resolve_component(
    client: OrchestratorClient,
    *,
    name: str,
    ecosystem: str | None,
) -> tuple[dict[str, Any], str | None]:
    """Look up a component by name + (optional) ecosystem.

    Returns ``(component_dict, error_string)``. The error string is
    non-empty when the lookup is ambiguous (multiple ecosystems) or
    the name is not present in the rollup. We push this disambiguation
    server-side rather than into the show/history handlers because
    every drill-down command needs the same lookup.
    """
    try:
        payload = client.ai_usage_components()
    except requests.ConnectionError as exc:
        return {}, f"sidecar unavailable: {exc}"
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        return {}, f"sidecar rejected components request: HTTP {status}"
    except requests.RequestException as exc:
        return {}, f"sidecar request failed: {exc}"

    needle = name.strip().lower()
    if not needle:
        return {}, "component name is required"
    eco_filter = (ecosystem or "").strip().lower()
    matches: list[dict[str, Any]] = []
    for c in payload.get("components", []) or []:
        if str(c.get("name", "")).lower() != needle:
            continue
        if eco_filter and str(c.get("ecosystem", "")).lower() != eco_filter:
            continue
        matches.append(c)
    if not matches:
        scope = f" in ecosystem {ecosystem!r}" if ecosystem else ""
        return {}, f"component {name!r} not found{scope}"
    if len(matches) > 1:
        ecos = sorted({str(c.get("ecosystem", "")) for c in matches})
        return {}, (
            f"component {name!r} is ambiguous across ecosystems "
            f"{', '.join(ecos)}; pass --ecosystem to disambiguate"
        )
    return matches[0], None


def _render_component_show(
    component: dict[str, Any],
    locations_payload: dict[str, Any],
) -> str:
    """Render `agent components show NAME`."""
    locs = list(locations_payload.get("locations", []) or [])
    eco = str(component.get("ecosystem", ""))
    name = str(component.get("name", ""))
    header = (
        f"Component: {name} ({eco})\n"
        f"  versions={_format_versions(component.get('versions'))}\n"
        f"  identity={_format_confidence(component.get('identity_score'), component.get('identity_band'))} "
        f"presence={_format_confidence(component.get('presence_score'), component.get('presence_band'))}\n"
        f"  detectors={_format_detectors(component.get('detectors') or [], limit=10)}\n"
    )

    has_raw = any(loc.get("raw_path") for loc in locs)

    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:
        plain = [header, f"Locations ({len(locs)}):"]
        for loc in locs:
            cells = [
                str(loc.get("detector", "")),
                str(loc.get("state", "")),
                str(loc.get("workspace_hash", "") or "")[:14],
                str(loc.get("basename", "")),
                _format_confidence_quality(loc.get("quality")),
                str(loc.get("match_kind", "")),
                _format_relative_time(loc.get("last_seen", "")),
            ]
            if has_raw:
                cells.append(str(loc.get("raw_path", "")))
            plain.append(" | ".join(cells))
        if not has_raw:
            plain.append("(raw paths hidden — flip privacy.disable_redaction "
                         "and ai_discovery.store_raw_local_paths to surface them)")
        return "\n".join(plain) + "\n"

    from io import StringIO

    stream = StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None, width=140)
    console.print(header.rstrip())
    table = Table(title=f"Locations ({len(locs)})")
    table.add_column("Detector")
    table.add_column("State")
    table.add_column("Workspace")
    table.add_column("Basename")
    table.add_column("Quality")
    table.add_column("Match")
    table.add_column("Last seen")
    if has_raw:
        table.add_column("Raw path")
    for loc in locs:
        cells = [
            str(loc.get("detector", "")),
            str(loc.get("state", "")),
            str(loc.get("workspace_hash", "") or "")[:14],
            str(loc.get("basename", "")),
            _format_confidence_quality(loc.get("quality")),
            str(loc.get("match_kind", "")),
            _format_relative_time(loc.get("last_seen", "")),
        ]
        if has_raw:
            cells.append(str(loc.get("raw_path", "")))
        table.add_row(*cells)
    console.print(table)
    if not has_raw:
        console.print(
            "(raw paths hidden — flip privacy.disable_redaction and "
            "ai_discovery.store_raw_local_paths to surface them)"
        )
    return stream.getvalue()


def _format_confidence_quality(quality: Any) -> str:
    """Render the per-evidence quality (a 0..1 float) compactly."""
    try:
        q = float(quality)
    except (TypeError, ValueError):
        return ""
    return f"{q:.2g}"


def _render_component_history(
    component: dict[str, Any],
    history_payload: dict[str, Any],
    *,
    limit: int = 0,
) -> str:
    """Render `agent components history NAME`."""
    rows = list(history_payload.get("history", []) or [])
    if limit > 0:
        rows = rows[:limit]
    eco = str(component.get("ecosystem", ""))
    name = str(component.get("name", ""))
    header = f"Confidence history: {name} ({eco}) — {len(rows)} snapshot(s)"

    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:
        out = [header]
        for r in rows:
            out.append(" | ".join([
                _history_row_timestamp(r),
                _format_confidence(r.get("identity_score"), r.get("identity_band")),
                _format_confidence(r.get("presence_score"), r.get("presence_band")),
                _format_detectors(_history_row_detectors(r), limit=6),
            ]))
        return "\n".join(out) + "\n"

    from io import StringIO

    stream = StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None, width=140)
    table = Table(title=header)
    table.add_column("Scanned at")
    table.add_column("Identity")
    table.add_column("Presence")
    table.add_column("Detectors")
    for r in rows:
        table.add_row(
            _history_row_timestamp(r),
            _format_confidence(r.get("identity_score"), r.get("identity_band")),
            _format_confidence(r.get("presence_score"), r.get("presence_band")),
            _format_detectors(_history_row_detectors(r), limit=6),
        )
    console.print(table)
    return stream.getvalue()


def _history_row_timestamp(row: dict[str, Any]) -> str:
    """Pick the timestamp for one history row.

    The Go store ships ``scanned_at`` (the JSON tag on
    ``ComponentHistoryRow.ScannedAt``). Older sidecar versions and
    test stubs sometimes use ``computed_at`` instead, so we accept
    both. ``scanned_at`` wins because that's the production wire
    contract.
    """
    return str(row.get("scanned_at") or row.get("computed_at") or "")


def _history_row_detectors(row: dict[str, Any]) -> list[str]:
    """Normalise the ``detectors`` field to a list of strings.

    ``ComponentHistoryRow.Detectors`` is persisted as a
    comma-separated TEXT column in SQLite and ships as a JSON string
    over the wire. Iterating that string directly (the previous
    behaviour) yielded individual characters and the rendered
    column degenerated to ``,``. Splitting first restores the
    intended one-detector-per-element semantics. A list value is
    accepted too so older payloads / hand-rolled stubs round-trip.
    """
    raw = row.get("detectors")
    if isinstance(raw, list):
        return [str(d) for d in raw if str(d).strip()]
    if isinstance(raw, str):
        return [seg.strip() for seg in raw.split(",") if seg.strip()]
    return []


def _render_confidence_explain(component: dict[str, Any]) -> str:
    """Render `agent confidence explain NAME` waterfall."""
    eco = str(component.get("ecosystem", ""))
    name = str(component.get("name", ""))

    id_score = component.get("identity_score")
    pr_score = component.get("presence_score")
    id_band = component.get("identity_band", "")
    pr_band = component.get("presence_band", "")

    header = (
        f"Confidence: {name} ({eco})\n"
        f"  identity={_format_confidence(id_score, id_band)}  "
        f"presence={_format_confidence(pr_score, pr_band)}\n"
    )

    id_factors = component.get("identity_factors") or []
    pr_factors = component.get("presence_factors") or []

    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:
        # Plain text rendering preserves the same column order so log
        # scrapes stay parseable across both renderers.
        out = [header.rstrip()]
        for axis_name, factors, score in (
            ("Identity factors", id_factors, id_score),
            ("Presence factors", pr_factors, pr_score),
        ):
            out.append(axis_name + ":")
            for f in factors:
                out.append(_format_factor_row(f, score))
        return "\n".join(out) + "\n"

    from io import StringIO

    stream = StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None, width=140)
    console.print(header.rstrip())
    for axis_name, factors, score in (
        ("Identity factors", id_factors, id_score),
        ("Presence factors", pr_factors, pr_score),
    ):
        table = Table(title=axis_name)
        table.add_column("Detector")
        table.add_column("Evidence")
        table.add_column("Match")
        table.add_column("Quality", justify="right")
        # The presence axis re-uses the `specificity` column for
        # `recency`; the engine documents this on
        # ConfidenceFactor.Specificity. We still call the column
        # "Spec/Recency" so an operator sees both axes side-by-side
        # without surprise.
        table.add_column("Spec/Recency", justify="right")
        table.add_column("LR", justify="right")
        table.add_column("Logit Δ", justify="right")
        table.add_column("Shift")
        for f in factors:
            table.add_row(
                str(f.get("detector", "")),
                str(f.get("evidence_id", "")),
                str(f.get("match_kind", "")),
                _format_confidence_quality(f.get("quality")),
                _format_confidence_quality(f.get("specificity")),
                _format_confidence_quality(f.get("lr")),
                _format_confidence_quality(f.get("logit_delta")),
                _format_logit_delta(_factor_pp_shift(f, score)),
            )
        console.print(table)
    return stream.getvalue()


def _factor_pp_shift(factor: dict[str, Any], score: Any) -> float:
    """Mirror inventory.ConfidenceFactor.PercentagePointShift in Python.

    Uses the local derivative of the sigmoid so the shift line on
    the explain table matches what the Go engine would render.
    """
    try:
        delta = float(factor.get("logit_delta", 0) or 0)
        s = float(score or 0)
    except (TypeError, ValueError):
        return 0.0
    return delta * s * (1 - s) * 100


def _format_factor_row(f: dict[str, Any], score: Any) -> str:
    """Plain-text fallback for one factor row."""
    return " | ".join([
        str(f.get("detector", "")),
        str(f.get("evidence_id", "")),
        str(f.get("match_kind", "")),
        _format_confidence_quality(f.get("quality")),
        _format_confidence_quality(f.get("specificity")),
        _format_confidence_quality(f.get("lr")),
        _format_confidence_quality(f.get("logit_delta")),
        _format_logit_delta(_factor_pp_shift(f, score)),
    ])


def _render_confidence_policy(payload: dict[str, Any]) -> str:
    """Render `agent confidence policy {show, default}` as YAML.

    Falls back to indented pretty-print when PyYAML is unavailable.
    """
    policy = payload.get("policy", {}) or {}
    source = payload.get("source", "")
    header = f"# DefenseClaw confidence policy (source={source})"
    try:
        import yaml as pyyaml  # type: ignore
    except Exception:
        return header + "\n" + json.dumps(policy, indent=2, sort_keys=True) + "\n"
    body = pyyaml.safe_dump(policy, sort_keys=False, default_flow_style=False)
    return header + "\n" + body


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
