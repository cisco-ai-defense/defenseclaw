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

"""defenseclaw setup observability — unified observability destination setup.

Wraps the preset registry (``defenseclaw.observability.presets``) and
the YAML/dotenv writer (``defenseclaw.observability.writer``) behind a
Click command group. The Go TUI shells out to this command group with
``--non-interactive`` so both front-ends share one code path.

Subcommands
-----------
add <preset>          Configure / re-configure a destination
list                  Enumerate configured destinations
enable <name>         Flip ``enabled: true``
disable <name>        Flip ``enabled: false``
remove <name>         Delete an audit_sinks entry
test <name>           Probe the configured endpoint and report status
migrate-splunk        Move legacy ``splunk:`` block to ``audit_sinks[]``
migrate-otel          Convert flat ``otel:`` transport into a named route

All destructive subcommands write through the shared secure atomic
config writer so a crash mid-write cannot leave the gateway with an
unparseable config and managed-mode writes remain administrator-gated.
"""

from __future__ import annotations

import contextlib
import json as _json
import os
import socket
import ssl
import stat
import tempfile
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

import click
import yaml

from defenseclaw import ux
from defenseclaw.audit_actions import ACTION_SETUP_OBSERVABILITY
from defenseclaw.commands.redaction_status import print_redaction_status_hint
from defenseclaw.config import (
    _assert_config_write_allowed,
    config_path_for_data_dir,
    locked_config_yaml,
    write_config_yaml_secure,
)
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.file_permissions import set_file_mode
from defenseclaw.observability import (
    PRESETS,
    Destination,
    WriteResult,
    apply_preset,
    list_destinations,
    migrate_flat_otel,
    preset_choices,
    remove_destination,
    resolve_preset,
    set_destination_enabled,
)
from defenseclaw.observability.display import redact_endpoint_for_display

# Per-connector (D5b) sink writes reuse the writer's preset-resolution,
# sink-entry builder, and secret writer so the per-connector path never
# drifts from the global ``apply_preset`` path. They are imported (not
# re-implemented) because the writer module is outside this lane's edit
# surface; the per-connector routing target is the only difference.
from defenseclaw.observability.writer import (
    _NAME_RE as _SINK_NAME_RE,
)
from defenseclaw.observability.writer import (
    _apply_secret,
    _build_sink_entry,
    _destination_name,
    _resolve_inputs,
    _resolve_target,
    _sink_endpoint,
    _sink_preset_id,
    _sink_protocol,
)
from defenseclaw.platform_support import (
    LOCAL_SHELL_STACKS_UNSUPPORTED_REASON,
    destination_platform_unsupported,
    is_local_shell_stack_destination,
    local_shell_stacks_supported,
)

# All prompt keys across all presets. Exposed as Click options so the
# same command surface covers every preset; the writer ignores unknown
# keys per preset.
_ALL_PROMPT_FLAGS = (
    "realm", "site", "region", "dataset",
    "endpoint", "protocol", "project", "logstream",
    "host", "port", "index", "source", "sourcetype",
    "url", "method", "url_path", "verify_tls",
)


@click.group("observability")
def observability() -> None:
    """Configure OpenTelemetry + audit log destinations.

    Supports Splunk Observability Cloud, Splunk HEC, Datadog, Honeycomb,
    New Relic, Grafana Cloud, plus generic OTLP and generic HTTP JSONL
    fallbacks. For chat/incident notifier webhooks (Slack, PagerDuty,
    Webex, HMAC-signed), see ``defenseclaw setup webhook`` — that's a
    separate ``webhooks[]`` list and not an audit-sink.
    Splunk configuration authored with ``defenseclaw setup splunk``
    remains fully back-compatible (those flags are aliases for
    ``observability add splunk-o11y`` / ``splunk-hec`` /
    ``splunk-enterprise``).
    """


# ---------------------------------------------------------------------------
# add
# ---------------------------------------------------------------------------


@observability.command("add")
@click.argument(
    "preset_id",
    metavar="<preset>",
    type=click.Choice(preset_choices(), case_sensitive=False),
)
@click.option("--name", default=None, help="Destination name (default: derived from preset+inputs)")
@click.option("--target", type=click.Choice(["otel", "audit_sinks"]), default=None,
              help="Target for generic OTLP presets (otel exporter vs. otlp_logs sink)")
@click.option("--signals", default=None,
              help="Comma-separated OTel signals to enable (traces,metrics,logs)")
@click.option("--token", "token_value", default=None,
              help="Secret value to persist under the preset's token_env in ~/.defenseclaw/.env")
@click.option("--enabled/--disabled", "enabled", default=True,
              help="Mark destination enabled (default) or disabled")
@click.option("--connector", default=None,
              help="Scope this sink to a connector (omit = global). A connector's "
                   "events route to its per-connector audit_sinks when set, "
                   "falling back to the global audit_sinks otherwise. Applies to "
                   "audit_sinks only (OTel destinations are process-wide).")
@click.option("--dry-run", is_flag=True, help="Preview YAML/dotenv changes without writing")
@click.option("--non-interactive", is_flag=True, help="Skip prompts; use flags only")
# Prompt flags — shared across all presets; writer resolves per-preset.
@click.option("--realm", default=None)
@click.option("--site", default=None)
@click.option("--region", default=None)
@click.option("--dataset", default=None)
@click.option("--endpoint", default=None)
@click.option("--protocol", type=click.Choice(["grpc", "http"]), default=None)
@click.option("--project", default=None, help="Vendor project name or ID")
@click.option("--logstream", default=None, help="Vendor Log stream name or ID")
@click.option("--host", default=None)
@click.option("--port", default=None)
@click.option("--index", default=None)
@click.option("--source", default=None)
@click.option("--sourcetype", default=None)
@click.option("--url", default=None)
@click.option("--method", default=None)
@click.option("--url-path", "url_path", default=None)
@click.option("--verify-tls/--no-verify-tls", "verify_tls", default=None)
@pass_ctx
def add_destination(  # noqa: PLR0912, PLR0913 — many flags to mirror preset prompts
    app: AppContext,
    preset_id: str,
    name: str | None,
    target: str | None,
    signals: str | None,
    token_value: str | None,
    enabled: bool,
    connector: str | None,
    dry_run: bool,
    non_interactive: bool,
    realm, site, region, dataset,
    endpoint, protocol, project, logstream,
    host, port, index, source, sourcetype,
    url, method, url_path, verify_tls,
) -> None:
    """Configure a telemetry destination.

    Examples:

    \b
      # Non-interactive (CI / TUI shell-out)
      defenseclaw setup observability add datadog \\
          --non-interactive --site us5 --token "$DD_API_KEY"
    \b
      # Interactive (default)
      defenseclaw setup observability add splunk-enterprise
    """
    if preset_id.lower() == "local-otlp" and not local_shell_stacks_supported():
        raise click.ClickException(LOCAL_SHELL_STACKS_UNSUPPORTED_REASON)
    preset = resolve_preset(preset_id.lower())

    raw_inputs: dict[str, str | None] = {
        "realm": realm, "site": site, "region": region, "dataset": dataset,
        "endpoint": endpoint, "protocol": protocol,
        "project": project, "logstream": logstream,
        "host": host, "port": port, "index": index, "source": source,
        "sourcetype": sourcetype,
        "url": url, "method": method, "url_path": url_path,
    }
    if verify_tls is not None:
        raw_inputs["verify_tls"] = "true" if verify_tls else "false"

    if not non_interactive:
        raw_inputs = _prompt_missing(preset, raw_inputs)

    inputs: dict[str, str] = {k: str(v) for k, v in raw_inputs.items() if v is not None}

    signal_tuple = None
    if signals:
        parsed = tuple(s.strip() for s in signals.split(",") if s.strip())
        allowed = {"traces", "metrics", "logs"}
        bad = [s for s in parsed if s not in allowed]
        if bad:
            click.echo(f"error: unknown signal(s) {bad}; allowed: {sorted(allowed)}", err=True)
            raise SystemExit(2)
        signal_tuple = parsed  # type: ignore[assignment]

    connector_name = (connector or "").strip()
    try:
        resolved_inputs = _resolve_inputs(preset, inputs)
        candidate_endpoint = resolved_inputs.get("endpoint") or resolved_inputs.get("host", "")
        if (
            not local_shell_stacks_supported()
            and preset.id in {"splunk-hec", "splunk-enterprise"}
            and is_local_shell_stack_destination(
                preset_id=preset.id,
                kind="splunk_hec",
                endpoint=candidate_endpoint,
            )
        ):
            raise click.ClickException(LOCAL_SHELL_STACKS_UNSUPPORTED_REASON)
        if not non_interactive and token_value is None:
            token_value = _prompt_secret(preset, app.cfg.data_dir)
        if connector_name:
            result = _apply_sink_to_connector(
                preset,
                inputs,
                app.cfg.data_dir,
                connector_name,
                name=name,
                enabled=enabled,
                secret_value=token_value,
                target_override=target,
                dry_run=dry_run,
            )
        else:
            result = apply_preset(
                preset.id,
                inputs,
                app.cfg.data_dir,
                name=name,
                enabled=enabled,
                signals=signal_tuple,
                secret_value=token_value,
                target_override=target,
                dry_run=dry_run,
            )
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc

    _print_write_result(result, action="add", dry_run=dry_run, connector=connector_name)
    print_redaction_status_hint(app.cfg)
    click.echo()

    if app.logger and not dry_run:
        app.logger.log_action(
            ACTION_SETUP_OBSERVABILITY,
            "config",
            f"action=add preset={preset.id} name={result.name} target={result.target}"
            + (f" connector={connector_name}" if connector_name else ""),
        )


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@observability.command("list")
@click.option("--json", "emit_json", is_flag=True, help="Emit machine-readable JSON")
@click.option("--connector", default=None,
              help="List a connector's per-connector audit_sinks (omit = global). "
                   "When the connector has no per-connector sinks it inherits the "
                   "global audit_sinks.")
@pass_ctx
def list_cmd(app: AppContext, emit_json: bool, connector: str | None) -> None:
    """List configured observability destinations."""
    connector_name = (connector or "").strip()
    if connector_name:
        dests = _connector_destinations(app.cfg.data_dir, connector_name)
        if dests is None:
            if emit_json:
                click.echo("[]")
                return
            ux.subhead(
                f"No per-connector audit_sinks for {connector_name!r} — "
                "inherits the global audit_sinks."
            )
            return
        if emit_json:
            click.echo(_json.dumps([_dest_to_dict(d) for d in dests], indent=2))
            return
        if not dests:
            ux.subhead(f"Connector {connector_name!r} has an explicit empty sink set.")
            return
        click.echo()
        ux.section(f"Observability destinations — connector {connector_name}")
        _print_destination_header()
        for d in dests:
            _print_destination_row(d)
        click.echo()
        return
    dests = list_destinations(app.cfg.data_dir)
    if emit_json:
        click.echo(_json.dumps([_dest_to_dict(d) for d in dests], indent=2))
        return
    if not dests:
        ux.subhead("No destinations configured.")
        ux.subhead("Add one with: defenseclaw setup observability add <preset>")
        return
    click.echo()
    ux.section("Observability destinations")
    _print_destination_header()
    for d in dests:
        _print_destination_row(d)
    click.echo()


# ---------------------------------------------------------------------------
# enable / disable
# ---------------------------------------------------------------------------


@observability.command("enable")
@click.argument("name")
@click.option("--connector", default=None, help="Target a connector's per-connector sink")
@pass_ctx
def enable_cmd(app: AppContext, name: str, connector: str | None) -> None:
    """Enable a destination (``name=otel`` targets the gateway exporter)."""
    connector_name = (connector or "").strip()
    _gate_named_local_destination(app.cfg.data_dir, name, connector_name)
    try:
        if connector_name:
            result = _set_connector_sink_enabled(app.cfg.data_dir, connector_name, name, True)
        else:
            result = set_destination_enabled(name, True, app.cfg.data_dir)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    _print_write_result(result, action="enable", dry_run=False, connector=connector_name)


@observability.command("disable")
@click.argument("name")
@click.option("--connector", default=None, help="Target a connector's per-connector sink")
@pass_ctx
def disable_cmd(app: AppContext, name: str, connector: str | None) -> None:
    """Disable a destination."""
    connector_name = (connector or "").strip()
    _gate_named_local_destination(app.cfg.data_dir, name, connector_name)
    try:
        if connector_name:
            result = _set_connector_sink_enabled(app.cfg.data_dir, connector_name, name, False)
        else:
            result = set_destination_enabled(name, False, app.cfg.data_dir)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    _print_write_result(result, action="disable", dry_run=False, connector=connector_name)


# ---------------------------------------------------------------------------
# remove
# ---------------------------------------------------------------------------


@observability.command("remove")
@click.argument("name")
@click.option("--connector", default=None, help="Target a connector's per-connector sink")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt")
@pass_ctx
def remove_cmd(app: AppContext, name: str, connector: str | None, yes: bool) -> None:
    """Delete a destination (``name=otel`` disables but preserves the block)."""
    connector_name = (connector or "").strip()
    _gate_named_local_destination(app.cfg.data_dir, name, connector_name)
    label = f"{name!r}" + (f" (connector {connector_name})" if connector_name else "")
    if not yes and not click.confirm(f"  Remove destination {label}?", default=False):
        click.echo("  Aborted.")
        return
    try:
        if connector_name:
            result = _remove_connector_sink(app.cfg.data_dir, connector_name, name)
        else:
            result = remove_destination(name, app.cfg.data_dir)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    _print_write_result(result, action="remove", dry_run=False, connector=connector_name)


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------


@observability.command("test")
@click.argument("name")
@click.option("--timeout", type=float, default=5.0, help="Per-probe timeout in seconds")
@pass_ctx
def test_cmd(app: AppContext, name: str, timeout: float) -> None:
    """Probe a destination for reachability + auth.

    Safe to run — we POST a marker event for webhook/HEC sinks and TCP
    dial OTLP endpoints. Failures are reported with actionable hints.
    """
    dests = {d.name: d for d in list_destinations(app.cfg.data_dir)}
    d = dests.get(name)
    if d is None:
        click.echo(f"error: no destination named {name!r}", err=True)
        click.echo("  Known destinations:", err=True)
        for k in sorted(dests):
            click.echo(f"    - {k}", err=True)
        raise SystemExit(2)
    _gate_local_destination(d)
    if not d.enabled:
        ux.warn(f"destination {name!r} is currently disabled.")

    click.echo()
    label = "Splunk Enterprise (HEC)" if d.preset_id == "splunk-enterprise" else d.kind
    display_endpoint = redact_endpoint_for_display(
        d.endpoint or "(no endpoint)",
        hide_path=d.target != "otel",
    )
    click.echo(
        f"  {ux.bold('Testing')} {ux.bold(name)} "
        f"{ux.dim('[' + label + ']')}: {display_endpoint}"
    )
    if d.target == "otel":
        _test_otel(app.cfg.data_dir, name, timeout=timeout)
    elif d.kind == "splunk_hec":
        _test_splunk_hec(app.cfg.data_dir, name, timeout=timeout)
    elif d.kind == "otlp_logs":
        _test_otlp_logs(app.cfg.data_dir, name, timeout=timeout)
    elif d.kind == "http_jsonl":
        _test_http_jsonl(app.cfg.data_dir, name, timeout=timeout)
    else:
        click.echo(f"  Unknown kind {d.kind!r} — cannot test.")
    click.echo()


# ---------------------------------------------------------------------------
# migrate-splunk
# ---------------------------------------------------------------------------


@observability.command("migrate-otel")
@click.option("--apply", "do_apply", is_flag=True, help="Write the migration (default: preview)")
@pass_ctx
def migrate_otel_cmd(app: AppContext, do_apply: bool) -> None:
    """Convert a flat OTel exporter into ``otel.destinations[]``.

    This is the only supported transition from pre-fan-out configuration.
    It is idempotent and saves a backup before writing.
    """

    result = migrate_flat_otel(app.cfg.data_dir, dry_run=not do_apply)
    if not result.yaml_changes:
        click.echo("  No flat OTel exporter found — nothing to migrate.")
        return
    _print_write_result(result, action="migrate", dry_run=not do_apply)


# ---------------------------------------------------------------------------
# migrate-splunk
# ---------------------------------------------------------------------------


@observability.command("migrate-splunk")
@click.option("--apply", "do_apply", is_flag=True, help="Write the migration (default: preview)")
@pass_ctx
def migrate_splunk_cmd(app: AppContext, do_apply: bool) -> None:
    """Migrate the legacy ``splunk:`` block into ``audit_sinks[]``.

    Idempotent: safe to re-run. Always preserves non-Splunk sinks. The
    Go gateway rejects any top-level ``splunk:`` block on start, so this
    command exists to help operators upgrade to the v4 schema.
    """
    import yaml

    cfg_path = str(config_path_for_data_dir(app.cfg.data_dir))
    try:
        with open(cfg_path) as f:
            raw: dict[str, Any] = yaml.safe_load(f) or {}
    except OSError as exc:
        click.echo(f"error: cannot read {cfg_path}: {exc}", err=True)
        raise SystemExit(1) from exc

    legacy = raw.get("splunk")
    if not isinstance(legacy, dict) or not legacy:
        click.echo("  No legacy splunk: block found — nothing to migrate.")
        return

    # Build the equivalent audit_sinks entry.
    host = "localhost"
    endpoint = str(legacy.get("hec_endpoint", "") or "")
    if (
        not local_shell_stacks_supported()
        and is_local_shell_stack_destination(kind="splunk_hec", endpoint=endpoint)
    ):
        raise click.ClickException(LOCAL_SHELL_STACKS_UNSUPPORTED_REASON)
    if endpoint:
        parsed = urlparse(endpoint)
        if parsed.hostname:
            host = parsed.hostname

    name = f"splunk-hec-{_slug(host)}"
    # a legacy ``splunk:`` block whose ``verify_tls`` field is
    # absent or false used to silently downgrade certificate validation
    # under the new ``audit_sinks`` shape. Migrate to the explicit
    # ``insecure_skip_verify`` opt-out so the migrated sink is now
    # secure by default. We only carry the insecure mode forward when
    # the operator EXPLICITLY set ``verify_tls=false``; absence implies
    # the new secure default.
    legacy_verify_present = "verify_tls" in legacy
    legacy_verify_explicit_false = legacy_verify_present and not bool(legacy.get("verify_tls"))
    new_block: dict[str, Any] = {
        "endpoint": endpoint,
        "token_env": str(legacy.get("hec_token_env", "") or "DEFENSECLAW_SPLUNK_HEC_TOKEN"),
        "index": str(legacy.get("index", "") or "defenseclaw"),
        "source": str(legacy.get("source", "") or "defenseclaw"),
        "sourcetype": str(legacy.get("sourcetype", "") or "_json"),
    }
    if legacy_verify_explicit_false:
        new_block["insecure_skip_verify"] = True
        click.echo(
            "  ⚠ migrated legacy verify_tls=false → insecure_skip_verify=true; "
            "remove this opt-out for production",
        )
    new_entry: dict[str, Any] = {
        "name": name,
        "kind": "splunk_hec",
        "enabled": bool(legacy.get("enabled", False)),
        "splunk_hec": new_block,
    }

    sinks = raw.get("audit_sinks")
    if not isinstance(sinks, list):
        sinks = []
    # Skip migration if an equivalent sink already exists.
    for s in sinks:
        if not isinstance(s, dict):
            continue
        hec = s.get("splunk_hec") or {}
        if s.get("kind") == "splunk_hec" and hec.get("endpoint") == endpoint:
            click.echo(f"  audit_sinks already contains {s.get('name')!r} with same endpoint; skipping")
            if do_apply:
                raw.pop("splunk", None)
                write_config_yaml_secure(cfg_path, raw)
                click.echo("  Removed legacy splunk: block.")
            return

    click.echo()
    ux.section("Migration preview")
    click.echo(f"    {ux.dim('audit_sinks +=')} ")
    click.echo("      " + yaml.safe_dump(new_entry, sort_keys=False).replace("\n", "\n      ").rstrip())
    click.echo(f"    {ux.dim('splunk: (removed)')}")
    click.echo()

    if not do_apply:
        ux.subhead("Dry-run — re-run with --apply to write.")
        return

    sinks.append(new_entry)
    raw["audit_sinks"] = sinks
    raw.pop("splunk", None)
    write_config_yaml_secure(cfg_path, raw)
    click.echo(f"  Migrated splunk: block to audit_sinks[{name}].")
    if app.logger:
        app.logger.log_action(
            ACTION_SETUP_OBSERVABILITY, "config",
            f"action=migrate-splunk name={name}",
        )


# ---------------------------------------------------------------------------
# Interactive helpers
# ---------------------------------------------------------------------------


def _prompt_missing(
    preset, raw_inputs: dict[str, str | None],
) -> dict[str, str | None]:
    ux.section(f"{preset.display_name} Setup")
    ux.subhead(preset.description)
    click.echo()

    resolved = dict(raw_inputs)
    for flag_name, placeholder, desc, default in preset.prompts:
        if resolved.get(flag_name):
            continue
        prompt_text = f"  {desc}"
        resolved[flag_name] = click.prompt(
            prompt_text, default=default or placeholder, show_default=True,
        )
    return resolved


def _prompt_secret(preset, data_dir: str) -> str | None:
    if not preset.token_env:
        return None
    env_val = os.environ.get(preset.token_env, "")
    dotenv_val = _peek_dotenv(data_dir, preset.token_env)
    existing = env_val or dotenv_val
    hint = _mask(existing) if existing else "(not set)"
    label = preset.token_label or preset.token_env
    val = click.prompt(
        f"  {label} [{hint}]",
        default="", show_default=False, hide_input=True,
    )
    if val:
        return val
    return None  # writer will warn if missing


def _peek_dotenv(data_dir: str, key: str) -> str:
    path = os.path.join(data_dir, ".env")
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith(f"{key}="):
                    v = line.split("=", 1)[1].strip()
                    if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                        v = v[1:-1]
                    return v
    except FileNotFoundError:
        pass
    return ""


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "****"
    return value[:4] + "..." + value[-4:]


# ---------------------------------------------------------------------------
# Test probes
# ---------------------------------------------------------------------------


def _test_otel(data_dir: str, name: str, *, timeout: float) -> None:
    """Dial the configured OTel signal endpoints over TCP.

    A full OTLP probe would require an SDK + collector context — TCP
    reachability + TLS handshake is the most portable approximation.
    """
    import yaml

    cfg_path = str(config_path_for_data_dir(data_dir))
    try:
        with open(cfg_path) as f:
            raw: dict[str, Any] = yaml.safe_load(f) or {}
    except OSError as exc:
        click.echo(f"  ✗ cannot read config.yaml: {exc}")
        return
    otel_root = raw.get("otel") or {}
    using_named_destinations = isinstance(otel_root.get("destinations"), list)
    if using_named_destinations:
        otel = next(
            (
                item for item in otel_root["destinations"]
                if isinstance(item, dict) and item.get("name") == name
            ),
            {},
        )
    else:
        otel = otel_root
    if not otel_root.get("enabled") or not otel.get("enabled"):
        click.echo("  ⚠ destination enabled=false — exporter will not run until enabled")
    for sig in ("traces", "metrics", "logs"):
        block = otel.get(sig) or {}
        signal_enabled = bool(block.get("enabled"))
        if not using_named_destinations and "enabled" not in block:
            signal_enabled = bool(block.get("endpoint") or otel.get("endpoint"))
        if not signal_enabled:
            click.echo(f"    {sig:<8} disabled")
            continue
        endpoint = str(block.get("endpoint", "") or "")
        protocol = str(block.get("protocol") or otel.get("protocol") or "grpc")
        if not endpoint:
            endpoint = str(otel.get("endpoint", "") or "")
        ok, msg = _tcp_probe(endpoint, protocol, timeout=timeout)
        click.echo(f"    {sig:<8} {'✓' if ok else '✗'} {msg}")


def _test_splunk_hec(data_dir: str, name: str, *, timeout: float) -> None:
    ok, message = probe_splunk_hec(data_dir, name, timeout=timeout)
    click.echo(f"  {'✓' if ok else '✗'} {message}")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse 3xx redirects on the token-bearing HEC probe.

    ``urllib.request.urlopen`` follows redirects by default and replays
    request headers — including ``Authorization: Splunk <token>`` — to the
    redirect target. A malicious/misconfigured HEC endpoint could 302 the
    probe to an attacker host and harvest the token. Raising on any 30x
    keeps the credential pinned to the validated origin (F-0184).
    """

    def http_error_301(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirects disabled (token would be forwarded)",
            headers, fp,
        )

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


def probe_splunk_hec(data_dir: str, name: str, *, timeout: float = 10.0) -> tuple[bool, str]:
    import yaml

    cfg_path = str(config_path_for_data_dir(data_dir))
    with open(cfg_path) as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}
    sink = next(
        (s for s in (raw.get("audit_sinks") or [])
         if isinstance(s, dict) and s.get("name") == name),
        None,
    )
    if sink is None:
        return False, f"sink {name!r} vanished between list and probe"
    hec = sink.get("splunk_hec") or {}
    endpoint = str(hec.get("endpoint", "") or "")
    token_env = str(hec.get("token_env", "") or "")
    token = os.environ.get(token_env, "") if token_env else ""
    if not token:
        token = _peek_dotenv(data_dir, token_env)
    if not token:
        return False, f"token not set (env={token_env})"
    # TLS verification is ON by default. ``insecure_skip_verify``
    # is the explicit opt-out for dev environments with self-signed
    # HEC. The legacy ``verify_tls`` flag is honoured only when
    # explicitly true (no-op against the new secure default); explicit
    # false is silently IGNORED so probing this sink can never silently
    # leak the HEC token to a MITM peer.
    insecure_skip_verify = bool(hec.get("insecure_skip_verify", False))
    verify_tls = not insecure_skip_verify
    body = _json.dumps({
        "event": "defenseclaw observability test",
        "sourcetype": hec.get("sourcetype", "_json"),
        "index": hec.get("index", "defenseclaw"),
        "source": hec.get("source", "defenseclaw"),
    }).encode()
    req = urllib.request.Request(  # noqa: S310 — endpoint validated below
        endpoint,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        },
    )
    parsed = urlparse(endpoint)
    if parsed.scheme not in ("http", "https"):
        return False, f"endpoint must be http(s):// (got {endpoint!r})"
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    # Use a dedicated opener that refuses redirects so the ``Authorization:
    # Splunk <token>`` header is never replayed to a redirect target (F-0184).
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        _NoRedirectHandler(),
    )
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310
            return True, f"HEC responded {resp.status} {resp.reason}"
    except urllib.error.HTTPError as exc:
        hint = "check token/index permissions" if exc.code in (401, 403) else ""
        return False, f"HTTP {exc.code} {exc.reason} {hint}".strip()
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        return False, str(exc)


def _test_otlp_logs(data_dir: str, name: str, *, timeout: float) -> None:
    import yaml

    cfg_path = str(config_path_for_data_dir(data_dir))
    with open(cfg_path) as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}
    sink = next(
        (s for s in (raw.get("audit_sinks") or [])
         if isinstance(s, dict) and s.get("name") == name),
        None,
    )
    if sink is None:
        click.echo(f"  ✗ sink {name!r} vanished between list and probe")
        return
    block = sink.get("otlp_logs") or {}
    endpoint = str(block.get("endpoint", "") or "")
    protocol = str(block.get("protocol") or "grpc")
    ok, msg = _tcp_probe(endpoint, protocol, timeout=timeout)
    click.echo(f"  {'✓' if ok else '✗'} {msg}")


def _test_http_jsonl(data_dir: str, name: str, *, timeout: float) -> None:
    import yaml

    cfg_path = str(config_path_for_data_dir(data_dir))
    with open(cfg_path) as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}
    sink = next(
        (s for s in (raw.get("audit_sinks") or [])
         if isinstance(s, dict) and s.get("name") == name),
        None,
    )
    if sink is None:
        click.echo(f"  ✗ sink {name!r} vanished between list and probe")
        return
    block = sink.get("http_jsonl") or {}
    url = str(block.get("url", "") or "")
    method = str(block.get("method", "POST") or "POST").upper()
    bearer_env = str(block.get("bearer_env", "") or "")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        click.echo(f"  ✗ url must be http(s):// (got {url!r})")
        return
    if parsed.scheme == "http":
        click.echo("  ⚠ url is http:// — events will be sent in plaintext")
    headers = {"Content-Type": "application/x-ndjson"}
    if bearer_env:
        token = os.environ.get(bearer_env, "") or _peek_dotenv(data_dir, bearer_env)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        else:
            click.echo(f"  ⚠ bearer env {bearer_env!r} not set — sending unauthenticated probe")
    body = (_json.dumps({"probe": "defenseclaw.observability.test"}) + "\n").encode()
    req = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310
    # parity: TLS verification is ON by default for the HTTP
    # JSONL probe; only ``insecure_skip_verify=true`` disables it.
    insecure_skip_verify = bool(block.get("insecure_skip_verify", False))
    verify_tls = not insecure_skip_verify
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        click.echo("  ⚠ TLS certificate verification DISABLED (insecure_skip_verify=true)")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
            click.echo(f"  ✓ webhook responded {resp.status} {resp.reason}")
    except urllib.error.HTTPError as exc:
        click.echo(f"  {'✓' if 200 <= exc.code < 500 else '✗'} HTTP {exc.code} {exc.reason}")
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        click.echo(f"  ✗ {exc}")


def _tcp_probe(endpoint: str, protocol: str, *, timeout: float) -> tuple[bool, str]:
    """Return (ok, message) after attempting to open a TCP connection.

    ``endpoint`` is host[:port]; if port is absent we default per
    protocol (443 for https, 80 for http, 4317 for grpc).
    """
    endpoint = endpoint.strip()
    if not endpoint:
        return False, "endpoint is empty"
    host = endpoint
    port: int | None = None
    if "://" in endpoint:
        parsed = urlparse(endpoint)
        host = parsed.hostname or ""
        port = parsed.port
    elif ":" in endpoint and not endpoint.endswith("]"):
        host, _, port_s = endpoint.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            host = endpoint
            port = None
    if port is None:
        port = 4317 if protocol == "grpc" else 443
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"TCP reachable {host}:{port} ({protocol})"
    except OSError as exc:
        return False, f"TCP unreachable {host}:{port} ({protocol}): {exc}"


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _print_write_result(
    result: WriteResult,
    *,
    action: str,
    dry_run: bool,
    connector: str = "",
) -> None:
    click.echo()
    mode_tag = f"{ux.dim('[dry-run]')} " if dry_run else ""
    scope = f" {ux.dim('@' + connector)}" if connector else ""
    display_action = action.upper()
    if action == "add":
        updating = any(
            "overwriting existing" in warning or "already existed" in warning
            for warning in result.warnings
        )
        display_action = "UPDATE" if updating else "ADD"
    click.echo(
        f"  {mode_tag}{ux.bold(display_action)} "
        f"{ux.bold(result.target)}:{ux.bold(result.name)} "
        f"(preset={result.preset_id}){scope}"
    )
    line_indent = "      " if dry_run else "    "
    for line in result.yaml_changes:
        click.echo(f"{line_indent}{ux.dim('yaml:')} {line}")
    for line in result.dotenv_changes:
        click.echo(f"{line_indent}{ux.dim('env:')}  {line}")
    for line in result.warnings:
        ux.warn(line, indent=line_indent)
    if not dry_run:
        ux.subhead("Next: defenseclaw-gateway restart (to reload config)")
    click.echo()


def _destination_signals(d: Destination) -> str:
    if d.target != "otel":
        return "audit-events"
    enabled = [name for name in ("traces", "metrics", "logs") if d.signals.get(name)]
    return ",".join(enabled) or "none"


def _print_destination_header() -> None:
    click.echo(
        f"  {'NAME':<28} {'TARGET':<12} {'KIND':<10} {'ENABLED':<11} "
        f"{'PROTOCOL':<10} {'SIGNALS':<22} {'PRESET':<18} ENDPOINT"
    )
    click.echo(
        f"  {'-' * 28} {'-' * 12} {'-' * 10} {'-' * 11} "
        f"{'-' * 10} {'-' * 22} {'-' * 18} {'-' * 36}"
    )


def _print_destination_row(d: Destination) -> None:
    endpoint = redact_endpoint_for_display(
        d.endpoint or "(none)",
        hide_path=d.target != "otel",
    )
    if len(endpoint) > 54:
        endpoint = endpoint[:51] + "..."
    enabled = "yes" if d.enabled else "no"
    if _destination_platform_status(d) == "unsupported":
        enabled = "unsupported"
    click.echo(
        f"  {ux.bold(f'{d.name:<28}')} {d.target:<12} {d.kind:<10} "
        f"{enabled:<11} {(d.protocol or '-'):<10} "
        f"{_destination_signals(d):<22} "
        f"{(d.preset_id or '-'):<18} {endpoint}"
    )


def _gate_local_destination(destination: Destination) -> None:
    if local_shell_stacks_supported():
        return
    if is_local_shell_stack_destination(
        name=destination.name,
        preset_id=destination.preset_id,
        kind=destination.kind,
        endpoint=destination.endpoint,
    ):
        raise click.ClickException(LOCAL_SHELL_STACKS_UNSUPPORTED_REASON)


def _destination_platform_status(destination: Destination) -> str:
    if destination_platform_unsupported(
        name=destination.name,
        preset_id=destination.preset_id,
        kind=destination.kind,
        endpoint=destination.endpoint,
    ):
        return "unsupported"
    return "supported"


def _gate_named_local_destination(data_dir: str, name: str, connector: str) -> None:
    if local_shell_stacks_supported():
        return
    destinations = (
        _connector_destinations(data_dir, connector)
        if connector
        else list_destinations(data_dir)
    )
    for destination in destinations or ():
        if destination.name == name:
            _gate_local_destination(destination)
            return


def _dest_to_dict(d: Destination) -> dict[str, Any]:
    return {
        "name": d.name,
        "target": d.target,
        "kind": d.kind,
        "enabled": d.enabled,
        "platform_status": _destination_platform_status(d),
        "preset_id": d.preset_id,
        "endpoint": d.endpoint,
        "protocol": d.protocol,
        "signals": d.signals,
    }


# ---------------------------------------------------------------------------
# Per-connector audit_sinks (D5b)
#
# These write a SURGICAL slice of ``config.yaml`` —
# ``observability.connectors[<name>].audit_sinks`` — under the shared config
# lock, mirroring the sibling ``defenseclaw.observability.writer`` (which
# writes the top-level ``audit_sinks:`` list). They deliberately do NOT route
# through ``Config.save()``: that would re-serialize the whole (possibly
# stale) dataclass and could clobber a concurrently-written global block. The
# ``observability.connectors`` schema is round-tripped by
# ``config.ObservabilityConfig`` so any *fully-loaded* ``cfg.save()`` (a setup
# wizard, the TUI) preserves these entries.
#
# Preset resolution, the sink-entry builder, and the secret writer are reused
# from the writer module so the per-connector path never drifts from the
# global ``apply_preset`` path — only the routing target differs.
# ---------------------------------------------------------------------------


def _obs_load_raw(path: str) -> dict[str, Any]:
    import yaml

    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping at top level")
    return data


def _connector_audit_sinks_list(
    raw: dict[str, Any], connector: str, *, create: bool,
) -> list[Any] | None:
    """Return ``observability.connectors[connector].audit_sinks``.

    ``create=True`` materialises the nested path; ``create=False`` returns
    ``None`` for a missing path ("inherit the global audit_sinks").
    """
    obs = raw.get("observability")
    if not isinstance(obs, dict):
        if not create:
            return None
        obs = {}
        raw["observability"] = obs
    conns = obs.get("connectors")
    if not isinstance(conns, dict):
        if not create:
            return None
        conns = {}
        obs["connectors"] = conns
    entry = conns.get(connector)
    if not isinstance(entry, dict):
        if not create:
            return None
        entry = {}
        conns[connector] = entry
    sinks = entry.get("audit_sinks")
    if not isinstance(sinks, list):
        if not create:
            return None
        sinks = []
        entry["audit_sinks"] = sinks
    return sinks


def _prune_observability(raw: dict[str, Any], connector: str) -> None:
    """Drop now-empty per-connector dimensions / connector / block."""
    obs = raw.get("observability")
    if not isinstance(obs, dict):
        return
    conns = obs.get("connectors")
    if not isinstance(conns, dict):
        return
    entry = conns.get(connector)
    if isinstance(entry, dict):
        if entry.get("audit_sinks") == []:
            entry.pop("audit_sinks", None)
        if entry.get("webhooks") == []:
            entry.pop("webhooks", None)
        if not entry:
            conns.pop(connector, None)
    if not conns:
        obs.pop("connectors", None)
    if not obs:
        raw.pop("observability", None)


def _apply_sink_to_connector(
    preset,
    inputs: dict[str, str],
    data_dir: str,
    connector: str,
    *,
    name: str | None,
    enabled: bool,
    secret_value: str | None,
    target_override: str | None,
    dry_run: bool,
) -> WriteResult:
    """Write an audit-sink preset under observability.connectors[connector]."""
    effective_target = _resolve_target(preset, target_override)
    if effective_target != "audit_sinks":
        raise ValueError(
            "--connector applies to audit_sinks only; the OTel gateway exporter "
            f"(preset {preset.id!r}) is a single global block. Re-run without "
            "--connector, or use a sink preset / --target audit_sinks."
        )
    resolved_inputs = _resolve_inputs(preset, inputs)
    dest_name = _destination_name(preset, name, resolved_inputs)
    if not _SINK_NAME_RE.match(dest_name):
        raise ValueError(
            f"destination name {dest_name!r} must match {_SINK_NAME_RE.pattern}"
        )
    entry = _build_sink_entry(preset, resolved_inputs, name=dest_name, enabled=enabled)

    warnings: list[str] = []
    # Secrets land in ~/.defenseclaw/.env (shared per token_env across
    # connectors, exactly like the global path) — reused verbatim.
    dotenv_changes = _apply_secret(data_dir, preset, secret_value, dry_run=dry_run)

    if not dry_run:
        cfg_path = str(config_path_for_data_dir(data_dir))
        with locked_config_yaml(cfg_path):
            raw = _obs_load_raw(cfg_path)
            sinks = _connector_audit_sinks_list(raw, connector, create=True)
            idx = next(
                (i for i, s in enumerate(sinks)
                 if isinstance(s, dict) and s.get("name") == dest_name),
                -1,
            )
            if idx >= 0:
                warnings.append(
                    f"observability.connectors[{connector}].audit_sinks[{dest_name}] "
                    "already existed — fields overwritten (other keys preserved)",
                )
                merged = dict(sinks[idx]) if isinstance(sinks[idx], dict) else {}
                merged.update(entry)
                sinks[idx] = merged
            else:
                sinks.append(entry)
            write_config_yaml_secure(cfg_path, raw)

    return WriteResult(
        name=dest_name,
        target="audit_sinks",
        preset_id=preset.id,
        yaml_changes=[
            f"observability.connectors[{connector}].audit_sinks[{dest_name}] "
            f"kind={entry.get('kind')} enabled={entry.get('enabled')}",
        ],
        dotenv_changes=dotenv_changes,
        warnings=warnings,
        dry_run=dry_run,
    )


def _connector_destinations(data_dir: str, connector: str) -> list[Destination] | None:
    """Return a connector's per-connector audit sinks, or None if unset."""
    raw = _obs_load_raw(str(config_path_for_data_dir(data_dir)))
    sinks = _connector_audit_sinks_list(raw, connector, create=False)
    if sinks is None:
        return None
    out: list[Destination] = []
    for sink in sinks:
        if not isinstance(sink, dict):
            continue
        kind = str(sink.get("kind", "") or "")
        name = str(sink.get("name", "") or "")
        if not name or not kind:
            continue
        out.append(
            Destination(
                name=name,
                target="audit_sinks",
                kind=kind,
                enabled=bool(sink.get("enabled", False)),
                preset_id=_sink_preset_id(sink),
                endpoint=_sink_endpoint(sink),
                protocol=_sink_protocol(sink),
                signals={},
            ),
        )
    return out


def _set_connector_sink_enabled(
    data_dir: str, connector: str, name: str, enabled: bool,
) -> WriteResult:
    cfg_path = str(config_path_for_data_dir(data_dir))
    with locked_config_yaml(cfg_path):
        raw = _obs_load_raw(cfg_path)
        sinks = _connector_audit_sinks_list(raw, connector, create=False)
        idx = next(
            (i for i, s in enumerate(sinks or [])
             if isinstance(s, dict) and s.get("name") == name),
            -1,
        )
        if idx < 0:
            raise ValueError(
                f"no per-connector audit sink named {name!r} for connector {connector!r}"
            )
        sinks[idx]["enabled"] = bool(enabled)
        write_config_yaml_secure(cfg_path, raw)
    return WriteResult(
        name=name,
        target="audit_sinks",
        preset_id="",
        yaml_changes=[
            f"observability.connectors[{connector}].audit_sinks[{name}].enabled = {bool(enabled)}",
        ],
        dotenv_changes=[],
        warnings=[],
        dry_run=False,
    )


def _remove_connector_sink(data_dir: str, connector: str, name: str) -> WriteResult:
    cfg_path = str(config_path_for_data_dir(data_dir))
    with locked_config_yaml(cfg_path):
        raw = _obs_load_raw(cfg_path)
        sinks = _connector_audit_sinks_list(raw, connector, create=False)
        if sinks is None:
            raise ValueError(
                f"no per-connector audit sinks for connector {connector!r}"
            )
        new = [s for s in sinks if isinstance(s, dict) and s.get("name") != name]
        if len(new) == len(sinks):
            raise ValueError(
                f"no per-connector audit sink named {name!r} for connector {connector!r}"
            )
        sinks[:] = new
        _prune_observability(raw, connector)
        write_config_yaml_secure(cfg_path, raw)
    return WriteResult(
        name=name,
        target="audit_sinks",
        preset_id="",
        yaml_changes=[f"observability.connectors[{connector}].audit_sinks[{name}] removed"],
        dotenv_changes=[],
        warnings=[],
        dry_run=False,
    )


def _slug(value: str) -> str:
    import re
    out = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return out[:40] or "default"


def _write_atomically(cfg_path: str, raw: dict[str, Any]) -> None:
    """Compatibility wrapper around the authoritative secure config writer.

    Older callers and the F-0186 regression test import this private helper.
    Keep current main's managed-mode authorization and existing POSIX mode
    preservation while applying the native Windows owner-only DACL before any
    secret-bearing bytes are written.
    """
    _assert_config_write_allowed(cfg_path, raw)
    directory = os.path.dirname(cfg_path) or "."
    os.makedirs(directory, exist_ok=True)
    target_mode = 0o600
    if os.name != "nt":
        try:
            existing_mode = stat.S_IMODE(os.stat(cfg_path).st_mode)
        except OSError:
            existing_mode = None
        if existing_mode is not None and existing_mode != 0o600:
            target_mode = existing_mode & 0o600
            if target_mode == 0o600 and existing_mode & 0o077 == 0o040:
                target_mode = 0o640
            elif target_mode == 0:
                target_mode = 0o600

    fd = -1
    tmp = ""
    try:
        fd, tmp = tempfile.mkstemp(prefix=".config.", suffix=".tmp", dir=directory)
        set_file_mode(fd, tmp, target_mode)
        stream = os.fdopen(fd, "w")
        fd = -1
        with stream as f:
            yaml.safe_dump(raw, f, default_flow_style=False, sort_keys=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, cfg_path)
        tmp = ""
    finally:
        if fd != -1:
            with contextlib.suppress(OSError):
                os.close(fd)
        if tmp:
            with contextlib.suppress(OSError):
                os.unlink(tmp)


# ---------------------------------------------------------------------------
# Registry accessor for cmd_setup.py (imports register the group under setup)
# ---------------------------------------------------------------------------


__all__ = ["observability", "PRESETS"]
