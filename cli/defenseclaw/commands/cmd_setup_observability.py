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

"""Canonical-v8 observability destination setup.

The command writes only ``observability.destinations`` through the surgical
v8 YAML writer. Pre-v8 conversion belongs exclusively to ``defenseclaw
upgrade`` and is intentionally not a live setup mode.

Subcommands
-----------
add <preset>          Configure / re-configure a destination
list                  Enumerate configured destinations
enable <name>         Flip ``enabled: true``
disable <name>        Flip ``enabled: false``
remove <name>         Delete an optional destination
test <name>           Probe the configured endpoint and report status

All destructive subcommands write through the shared secure atomic
config writer so a crash mid-write cannot leave the gateway with an
unparseable config and managed-mode writes remain administrator-gated.
"""

from __future__ import annotations

import json as _json
import os
import re
from typing import Any

import click

from defenseclaw import ux
from defenseclaw.audit_actions import ACTION_SETUP_OBSERVABILITY
from defenseclaw.config import config_path_for_data_dir
from defenseclaw.config_inspect import ConfigInspectError
from defenseclaw.context import AppContext, mark_setup_secret_changed, pass_ctx, setup_secret_changed
from defenseclaw.observability import (
    PRESETS,
    Preset,
    preset_choices,
    resolve_preset,
)
from defenseclaw.observability.v8_presets import (
    DESTINATION_NAME_RE as _SINK_NAME_RE,
)
from defenseclaw.observability.v8_presets import (
    _load_dotenv,
    adapter_destination_fields,
    secret_note_is_info,
)
from defenseclaw.observability.v8_presets import (
    apply_secret as _apply_secret,
)
from defenseclaw.observability.v8_presets import (
    destination_name as _destination_name,
)
from defenseclaw.observability.v8_presets import (
    render_header_template as _render_header_template,
)
from defenseclaw.observability.v8_presets import (
    render_template as _render_template,
)
from defenseclaw.observability.v8_presets import (
    resolve_inputs as _resolve_inputs,
)
from defenseclaw.platform_support import (
    LOCAL_OBSERVABILITY_UNSUPPORTED_REASON,
    LOCAL_SPLUNK_UNSUPPORTED_REASON,
    destination_platform_unsupported,
    is_local_observability_stack_destination,
    is_local_splunk_stack_destination,
    local_observability_stack_supported,
    local_splunk_stack_supported,
)

_LEGACY_GENERATED_GALILEO_SEND = {
    "signals": ["traces"],
    "buckets": ["*"],
    "redaction_profile": "none",
}


@click.group("observability")
def observability() -> None:
    """Configure telemetry destinations.

    Supports Splunk Observability Cloud, Splunk HEC, Splunk Enterprise
    HEC, Datadog, Honeycomb, New Relic, Grafana Cloud, Galileo, the local
    observability stack, plus generic OTLP and generic HTTP JSONL
    adapters ('defenseclaw setup observability add --help' lists the
    preset ids). For chat/incident notifier webhooks (Slack, PagerDuty,
    Webex, HMAC-signed), see ``defenseclaw setup webhook`` — that's a
    separate ``webhooks[]`` list and not a telemetry destination.
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
@click.option("--signals", default=None,
              help="Comma-separated OTel signals to enable (traces,metrics,logs)")
@click.option("--token", "token_value", default=None,
              envvar="DEFENSECLAW_SETUP_OBSERVABILITY_TOKEN",
              show_envvar=True,
              help="Secret value to persist under the preset's token_env in ~/.defenseclaw/.env."
                   " Command-line values are visible to other local users (ps); prefer the env var.")
@click.option("--enabled/--disabled", "enabled", default=True,
              help="Mark destination enabled (default) or disabled")
@click.option("--dry-run", is_flag=True, help="Preview YAML/dotenv changes without writing")
@click.option("--non-interactive", is_flag=True, help="Skip prompts; use flags only")
# Prompt flags — shared across all presets; writer resolves per-preset.
@click.option("--realm", default=None, help="Splunk Observability realm (for example us1)")
@click.option("--site", default=None, help="Datadog site (us1, us3, us5, eu, ...)")
@click.option("--region", default=None, help="New Relic region (us or eu), or Grafana Cloud region/zone")
@click.option("--dataset", default=None, help="Honeycomb dataset name")
@click.option("--endpoint", default=None,
              help="Endpoint: OTLP host:port or URL (otlp, local-otlp), or the Splunk Enterprise HEC URL")
@click.option("--protocol", type=click.Choice(["grpc", "http"]), default=None, help="OTLP transport")
@click.option("--project", default=None, help="Vendor project name or ID")
@click.option("--logstream", default=None, help="Vendor Log stream name or ID")
@click.option("--host", default=None, help="Splunk HEC host name or IP, without scheme (splunk-hec)")
@click.option("--port", default=None, help="Splunk HEC port (splunk-hec; default 8088)")
@click.option("--index", default=None, help="Splunk index for HEC events")
@click.option("--source", default=None, help="Splunk HEC source field")
@click.option("--sourcetype", default=None, help="Splunk HEC sourcetype field")
@click.option("--url", default=None, help="Webhook URL, https only (webhook)")
@click.option("--method", default=None, help="Webhook HTTP method: POST, PUT or PATCH (webhook)")
@click.option("--verify-tls/--no-verify-tls", "verify_tls", default=None,
              help="Verify the Splunk HEC TLS certificate (default: on; --no-verify-tls for a self-signed collector)")
@click.option(
    "--allow-private-networks",
    is_flag=True,
    help="Allow an endpoint on this computer or a private network (for a collector you run yourself)",
)
@click.option(
    "--plaintext",
    is_flag=True,
    help="Send OTLP without TLS (for a collector you run yourself that has no TLS)",
)
@click.option(
    "--environment",
    default=None,
    help=(
        "Tag all telemetry from this gateway with deployment.environment.name "
        "(for example, to tell apart computers that share a host name)"
    ),
)
@pass_ctx
def add_destination(  # noqa: PLR0912, PLR0913 — many flags to mirror preset prompts
    app: AppContext,
    preset_id: str,
    name: str | None,
    signals: str | None,
    token_value: str | None,
    enabled: bool,
    dry_run: bool,
    non_interactive: bool,
    realm, site, region, dataset,
    endpoint, protocol, project, logstream,
    host, port, index, source, sourcetype,
    url, method, verify_tls,
    allow_private_networks,
    plaintext,
    environment,
) -> None:
    """Configure a telemetry destination from a <preset>.

    \b
    Presets: splunk-o11y, splunk-hec, splunk-enterprise, datadog,
             honeycomb, newrelic, grafana-cloud, galileo, local-otlp,
             otlp, webhook

    Examples:

    \b
      # Non-interactive (CI / TUI shell-out)
      defenseclaw setup observability add datadog \\
          --non-interactive --site us5 --token "$DD_API_KEY"
    \b
      # Interactive (default)
      defenseclaw setup observability add splunk-enterprise
    \b
      # Tag this computer's telemetry (host.name comes from the OS)
      defenseclaw setup observability add otlp --non-interactive \\
          --endpoint 10.0.0.5:4317 --protocol grpc \\
          --allow-private-networks --plaintext --environment lab-win2
    \b
      # Feed the bundled Grafana boards on another computer (plain otlp
      # exports canonical metric labels the boards do not read)
      defenseclaw setup observability add local-otlp --non-interactive \\
          --endpoint stack-host:4317
    """
    preset = resolve_preset(preset_id.lower())
    token_source = click.get_current_context().get_parameter_source("token_value")
    if token_source == click.core.ParameterSource.ENVIRONMENT:
        click.echo("Using token from DEFENSECLAW_SETUP_OBSERVABILITY_TOKEN.")

    raw_inputs: dict[str, str | None] = {
        "realm": realm, "site": site, "region": region, "dataset": dataset,
        "endpoint": endpoint, "protocol": protocol,
        "project": project, "logstream": logstream,
        "host": host, "port": port, "index": index, "source": source,
        "sourcetype": sourcetype,
        "url": url, "method": method,
    }
    if verify_tls is not None:
        raw_inputs["verify_tls"] = "true" if verify_tls else "false"

    if not non_interactive:
        raw_inputs = _prompt_missing(preset, raw_inputs)
        if token_value is None:
            token_value = _prompt_secret(preset, app.cfg.data_dir)

    inputs: dict[str, str] = {k: str(v) for k, v in raw_inputs.items() if v is not None}
    _refuse_endpoint_credentials(preset, inputs)

    signal_tuple = None
    if signals:
        parsed = tuple(s.strip() for s in signals.split(",") if s.strip())
        allowed = {"traces", "metrics", "logs"}
        bad = [s for s in parsed if s not in allowed]
        if bad:
            click.echo(f"error: unknown signal(s) {bad}; allowed: {sorted(allowed)}", err=True)
            raise SystemExit(2)
        signal_tuple = parsed  # type: ignore[assignment]

    try:
        resolved_inputs = _resolve_inputs(preset, inputs)
        _gate_local_preset(
            preset,
            resolved_inputs,
            name=name or "",
        )
        if not non_interactive and not allow_private_networks:
            # GAP-1643: ask here instead of failing after every prompt.
            allow_private_networks, plaintext = _confirm_private_endpoint(preset, resolved_inputs, plaintext)
        _require_v8_operator_status(app.cfg.data_dir)
        destination_name = _destination_name(preset, name, _resolve_inputs(preset, resolved_inputs))
        # Only picks "added" or "updated" for the summary line. A missing or
        # unreadable config is the add step's to report, not this lookup's.
        try:
            existed = any(
                existing.get("name") == destination_name
                for existing in _v8_authored_destinations(app.cfg.data_dir)
            )
        except (OSError, ValueError):
            existed = False
        result, warnings = _add_v8_destination(
            app.cfg.data_dir,
            preset,
            resolved_inputs,
            name=name,
            enabled=enabled,
            signals=signal_tuple,
            token_value=token_value,
            target=None,
            dry_run=dry_run,
            extra_mutations=_v8_environment_mutations(app.cfg.data_dir, environment),
            allow_private_networks=allow_private_networks,
            plaintext=plaintext,
        )
    except ConfigInspectError as exc:
        message = str(exc)
        if "secret_reference_unresolved" in (exc.reason or "") and preset.token_env:
            message = (
                f"{preset.token_env} is not set. Pass --token <value>, or store it first with: "
                f"defenseclaw keys set {preset.token_env}"
            )
        raise click.ClickException(message) from exc
    except ValueError as exc:
        message = str(exc)
        if "set allow_private_networks" in message and not allow_private_networks:
            # One plain line; the v8 schema path means nothing to the user.
            message = (
                "This endpoint is on this computer or a private network. To send to a collector you "
                "run yourself, add --allow-private-networks (or use the local-otlp preset for the "
                "local stack)."
            )
        raise click.ClickException(message) from exc
    mode = "DRY-RUN " if dry_run else ""
    if not result.changed:
        changed = "key updated, already configured" if setup_secret_changed() else "already configured"
    else:
        changed = "updated" if existed else "added"
    # GAP-1336: the generated name is what every later command takes.
    click.echo(f"  {mode}{preset.display_name}: {changed} as destination '{destination_name}'")
    echo_setup_notes(preset, warnings)
    if preset.id == "galileo" and not inputs.get("endpoint"):
        # GAP-2289: the default endpoint only serves Galileo Cloud keys.
        click.echo(
            "  Endpoint: Galileo Cloud (api.galileo.ai) by default; for another Galileo cluster "
            "add --endpoint <https://<cluster>/otel/traces>"
        )
    if not dry_run:
        click.echo(f"  Test it with: defenseclaw setup observability test {destination_name}")

    if not dry_run:
        # The destination is already saved, and the gateway loads it when it
        # starts, so a stopped gateway (or a failed auto-restart) only skips
        # the audit event (GAP-1202): exit 0 with a note, never "run again".
        from defenseclaw.commands.cmd_setup import _log_setup_action

        _log_setup_action(
            app,
            ACTION_SETUP_OBSERVABILITY,
            _setup_observability_add_details(
                destination_name,
                preset.id,
                _resolve_inputs(preset, resolved_inputs).get("endpoint", ""),
                updated=existed and result.changed,
            ),
            allow_offline=True,
            offline_note=(
                "  Saved. The gateway isn't running; it loads this destination when it starts "
                "(defenseclaw-gateway start)."
            ),
        )


def _refuse_endpoint_credentials(preset: Preset, inputs: dict[str, str]) -> None:
    """Refuse user:password in --endpoint/--url in plain words (GAP-2205).

    The v8 schema rejects such an endpoint as a failed source shape at
    destinations[N], which reads as a broken config.yaml.
    """

    for key in ("endpoint", "url"):
        value = inputs.get(key, "").strip()
        scheme, separator, rest = value.partition("://")
        authority = re.split(r"[/?#]", rest if separator and scheme else value, maxsplit=1)[0]
        if "@" not in authority:
            continue
        where = (
            f"pass it with --token (stored as {preset.token_env} in ~/.defenseclaw/.env)"
            if preset.token_env
            else "add a header to the destination in config.yaml, for example "
            "headers: {Authorization: {env: OTEL_AUTHORIZATION}}, and put the value in that environment variable"
        )
        raise click.ClickException(
            f"--{key} must not contain a user name or password (user:password@). "
            f"Nothing was saved. Remove them from the URL and {where}."
        )


def _setup_observability_add_details(name: str, preset_id: str, endpoint: str, *, updated: bool) -> str:
    """Audit details for ``setup observability add`` (GAP-2144).

    They name the destination, the preset and the endpoint, so two adds can
    be told apart. The endpoint keeps only its scheme, host, port and path:
    any user:password and query string are dropped.
    """
    details = f"action={'update' if updated else 'add'} name={name} preset={preset_id}"
    endpoint = (endpoint or "").strip()
    if endpoint:
        from urllib.parse import urlsplit

        parts = urlsplit(endpoint if "://" in endpoint else f"//{endpoint}")
        host = parts.netloc.rsplit("@", 1)[-1]
        shown = f"{parts.scheme}://{host}{parts.path}" if parts.scheme else f"{host}{parts.path}"
        if shown:
            details += f" endpoint={shown}"
    return details


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@observability.command("list")
@click.option("--json", "emit_json", is_flag=True, help="Emit machine-readable JSON")
@pass_ctx
def list_cmd(app: AppContext, emit_json: bool) -> None:
    """List configured observability destinations."""
    _print_v8_destination_list(_require_v8_operator_status(app.cfg.data_dir), emit_json=emit_json)


# ---------------------------------------------------------------------------
# enable / disable
# ---------------------------------------------------------------------------


@observability.command("enable")
@click.argument("name")
@pass_ctx
def enable_cmd(app: AppContext, name: str) -> None:
    """Turn a disabled destination back on."""
    _require_v8_operator_status(app.cfg.data_dir)
    _set_v8_destination_enabled(app.cfg.data_dir, name, True)


@observability.command("disable")
@click.argument("name")
@pass_ctx
def disable_cmd(app: AppContext, name: str) -> None:
    """Disable a destination."""
    _require_v8_operator_status(app.cfg.data_dir)
    _set_v8_destination_enabled(app.cfg.data_dir, name, False)


# ---------------------------------------------------------------------------
# remove
# ---------------------------------------------------------------------------


@observability.command("remove")
@click.argument("name")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt")
@pass_ctx
def remove_cmd(app: AppContext, name: str, yes: bool) -> None:
    """Delete a destination you added."""
    _require_v8_operator_status(app.cfg.data_dir)
    # GAP-1707: reject an unknown name before asking to remove it.
    _v8_source_destination_index(app.cfg.data_dir, name)
    if not yes and not click.confirm(f"  Remove destination {name!r}?", default=False):
        click.echo("  Aborted.")
        return
    _remove_v8_destination(app.cfg.data_dir, name)


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------


@observability.command("test")
@click.argument("name")
@click.option("--timeout", type=float, default=5.0, help="Per-probe timeout in seconds")
@click.option(
    "--write-probe",
    is_flag=True,
    help="Send one marked, content-free probe to the named destination.",
)
@pass_ctx
def test_cmd(app: AppContext, name: str, timeout: float, write_probe: bool) -> None:
    """Probe a destination for reachability + auth.

    Safe to run — we POST a marker event for webhook/HEC sinks and TCP
    dial OTLP endpoints. Failures are reported with actionable hints.
    """
    _require_v8_operator_status(app.cfg.data_dir)
    _test_v8_destination(app.cfg.data_dir, name, timeout, write_probe=write_probe)


# Exact-v8 operator path
# ---------------------------------------------------------------------------


def echo_setup_notes(preset: Preset, notes: list[str], *, indent: str = "  ") -> None:
    """Print what a destination setup did to the secret, then its warnings."""

    for note in notes:
        if secret_note_is_info(preset, note):
            ux.ok(note, indent=indent)
        else:
            ux.warn(note, indent=indent)


def _add_v8_destination(
    data_dir: str,
    preset: Preset,
    inputs: dict[str, str],
    *,
    name: str | None,
    enabled: bool,
    signals,
    token_value: str | None,
    target: str | None,
    dry_run: bool,
    extra_mutations=(),
    allow_private_networks: bool = False,
    plaintext: bool = False,
):
    """Add or update one v8 destination through the surgical writer."""

    from defenseclaw.observability.v8_writer import mutate_v8_config
    from defenseclaw.observability.v8_yaml import V8YAMLMutation

    resolved = _resolve_inputs(preset, inputs)
    destination_name = _destination_name(preset, name, resolved)
    if not _SINK_NAME_RE.fullmatch(destination_name):
        raise ValueError(
            f"destination name {destination_name!r} must match {_SINK_NAME_RE.pattern}"
        )
    destination = _build_v8_preset_destination(
        preset,
        resolved,
        name=destination_name,
        enabled=enabled,
        signals=signals,
        target=target,
    )
    if allow_private_networks:
        destination.setdefault("network_safety", {})["allow_private_networks"] = True
    warnings: list[str] = []
    if destination.get("kind") == "otlp":
        # An http:// endpoint already says "no TLS"; the validator requires
        # tls.insecure for it, so write it rather than refuse the endpoint.
        endpoint = str(destination.get("endpoint", ""))
        if plaintext and endpoint.lower().startswith("https://"):
            if str(resolved.get("endpoint", "")).lower().startswith("https://"):
                raise ValueError("--plaintext cannot be used with an https:// endpoint")
            # The http protocol defaults a bare host:port to https://.
            destination["endpoint"] = "http://" + endpoint[len("https://"):]
        if plaintext or endpoint.lower().startswith("http://"):
            destination["tls"] = {"insecure": True}
        elif allow_private_networks and not destination.get("tls", {}).get("insecure"):
            warnings.append(
                "This destination sends over TLS. If the collector has no TLS "
                "(like the local observability stack), add --plaintext."
            )
    elif plaintext:
        raise ValueError("--plaintext applies to OTLP destinations only")
    authored = _v8_authored_destinations(data_dir)
    matches = [
        (index, existing)
        for index, existing in enumerate(authored)
        if existing.get("name") == destination_name
    ]
    if len(matches) > 1:
        raise ValueError(f"destination {destination_name!r} appears more than once in config.yaml")
    if matches:
        index, existing = matches[0]
        if existing.get("kind") != destination["kind"]:
            raise ValueError(
                f"destination {destination_name!r} already has kind {existing.get('kind')!r}; "
                "remove it before changing adapter kind"
            )
        mutations = _v8_destination_update_mutations(index, existing, destination)
    else:
        mutations = [
            V8YAMLMutation.set(
                ("observability", "destinations", len(authored)),
                destination,
            )
        ]
    mutations.extend(extra_mutations)

    stored_secret = token_value
    if preset.id == "grafana-cloud":
        if stored_secret and not stored_secret.startswith("Basic "):
            stored_secret = "Basic " + stored_secret
        elif not stored_secret:
            warnings.append(
                "GRAFANA_OTLP_TOKEN must contain the complete Authorization value, including the Basic prefix"
            )
    secret_before = _stored_secret(data_dir, preset.token_env)
    warnings.extend(_apply_secret(data_dir, preset, stored_secret, dry_run=dry_run))
    if not dry_run and _stored_secret(data_dir, preset.token_env) != secret_before:
        # GAP-2356: the running gateway still holds the old key, and
        # config.yaml may be unchanged, so the restart has to be asked for.
        mark_setup_secret_changed()
    validator = None
    if dry_run and stored_secret and preset.token_env:
        validator = _staged_secret_validator({preset.token_env: stored_secret})
    result = mutate_v8_config(
        config_path_for_data_dir(data_dir),
        mutations,
        data_dir=data_dir,
        validator=validator,
        dry_run=dry_run,
    )
    return result, warnings


def _stored_secret(data_dir: str, key: str) -> str | None:
    """The value of key in ~/.defenseclaw/.env, or None."""

    if not key:
        return None
    try:
        with open(os.path.join(data_dir, ".env"), "rb") as handle:
            return _load_dotenv(handle.read()).get(key)
    except (OSError, UnicodeDecodeError):
        return None


def _staged_secret_validator(overrides: dict[str, str]):
    """Validate a dry-run candidate with the unwritten --token value (GAP-1890).

    A real add writes the key to .env and the environment before it validates;
    a dry run writes nothing, so the value goes to the validator directly.
    """
    from defenseclaw.observability import v8_writer

    def validate(path: str, data_dir: str | None) -> None:
        result = v8_writer.inspect_v8_config(
            "validate",
            config_path=path,
            data_dir=data_dir,
            environment_overrides=overrides,
        )
        if result.valid is not True:
            raise RuntimeError("the configuration validator rejected the candidate")

    return validate


def _v8_authored_destinations(data_dir: str) -> list[dict[str, Any]]:
    from defenseclaw.observability.v8_config import load_validate_v8

    path = config_path_for_data_dir(data_dir)
    source = load_validate_v8(path.read_bytes(), source_name=str(path)).source
    observability = source.get("observability")
    if not isinstance(observability, dict):
        return []
    destinations = observability.get("destinations")
    if not isinstance(destinations, list):
        return []
    return [dict(value) for value in destinations if isinstance(value, dict)]


def _v8_environment_mutations(data_dir: str, environment: str | None) -> list[Any]:
    """Mutations that set the gateway-wide deployment.environment.name tag.

    host.name is reserved and always comes from the operating system, so two
    computers with the same name (a cloned VM, for example) are told apart by
    this tag. A retired ``deployment.environment`` spelling, when present, is
    removed so only the canonical name remains.
    """

    if environment is None:
        return []
    from defenseclaw.observability.v8_config import load_validate_v8
    from defenseclaw.observability.v8_yaml import V8YAMLMutation

    value = environment.strip()
    if not value:
        raise ValueError("--environment needs a nonblank value")
    prefix = ("observability", "resource", "attributes")
    mutations = [V8YAMLMutation.set((*prefix, "deployment.environment.name"), value)]
    path = config_path_for_data_dir(data_dir)
    source = load_validate_v8(path.read_bytes(), source_name=str(path)).source
    attributes = ((source.get("observability") or {}).get("resource") or {}).get("attributes") or {}
    if isinstance(attributes, dict) and "deployment.environment" in attributes:
        mutations.append(V8YAMLMutation.delete((*prefix, "deployment.environment")))
    return mutations


def _build_v8_preset_destination(
    preset: Preset,
    inputs: dict[str, str],
    *,
    name: str,
    enabled: bool,
    signals,
    target: str | None,
) -> dict[str, Any]:
    del target
    explicit_signals = tuple(signals or ())

    if preset.adapter_kind is not None:
        destination: dict[str, Any] = {"name": name, "enabled": enabled}
        destination.update(adapter_destination_fields(preset, inputs))
        return destination

    endpoint = _render_template(preset.endpoint_template, inputs)
    protocol = (inputs.get("protocol") or preset.otel_protocol or "grpc").strip()
    if protocol == "http" and not endpoint.lower().startswith(("http://", "https://")):
        endpoint = "https://" + endpoint
    destination = {
        "name": name,
        "kind": "otlp",
        "enabled": enabled,
        "endpoint": endpoint,
    }
    destination["protocol"] = "http/protobuf" if protocol == "http" else protocol
    if preset.id == "galileo":
        destination["preset"] = "galileo"
        if explicit_signals and explicit_signals != ("traces",):
            raise ValueError("the Galileo preset supports traces only")
        # Keep the first-class Galileo command's real-time batching contract
        # when it writes the v8 destination shape.  This is an explicit
        # preset override; the generic v8 OTLP default remains five seconds.
        destination["batch"] = {"scheduled_delay_ms": 1000}

    headers: dict[str, Any] = {}
    for key, template in preset.otel_headers.items():
        rendered = _render_header_template(template, inputs)
        headers[key] = _v8_header_value(rendered)
    if preset.id == "honeycomb" and inputs.get("dataset"):
        headers["x-honeycomb-dataset"] = inputs["dataset"]
    if headers:
        destination["headers"] = headers
    if preset.signal_url_paths:
        destination["signal_overrides"] = {
            signal: {"path": path}
            for signal, path in preset.signal_url_paths.items()
            if not explicit_signals or signal in explicit_signals
        }
    if preset.otel_tls_insecure:
        destination["tls"] = {"insecure": True}
        destination["network_safety"] = {"allow_private_networks": True}

    # Galileo's preset compiler owns its supported trace-family selection.
    # An authored concise send would bypass that compatibility filter and
    # admit unsupported trace shapes, so even an explicit ``traces`` request
    # uses the preset-generated capability-default route.
    selected = () if preset.id == "galileo" else explicit_signals
    if selected:
        destination["send"] = {
            "signals": list(selected),
            "buckets": ["*"],
        }
    return destination


def _v8_header_value(value: str) -> Any:
    match = re.fullmatch(r"\$\{([A-Z_][A-Z0-9_]*)\}", value)
    if match:
        return {"env": match.group(1)}
    composite = re.fullmatch(r"Basic \$\{([A-Z_][A-Z0-9_]*)\}", value)
    if composite:
        return {"env": composite.group(1)}
    if "${" in value:
        raise ValueError("secret-backed headers must be a whole environment reference")
    return value


def _v8_destination_update_mutations(
    index: int,
    existing: dict[str, Any],
    destination: dict[str, Any],
):
    from defenseclaw.observability.v8_yaml import V8YAMLMutation

    base = ("observability", "destinations", index)
    mutations = []
    for field in (
        "name",
        "kind",
        "enabled",
        "preset",
        "path",
        "listen",
        "endpoint",
        "protocol",
        "method",
        "token_env",
        "bearer_env",
        "index",
        "source",
        "sourcetype",
        "timeout_ms",
    ):
        if field in destination:
            mutations.append(V8YAMLMutation.set((*base, field), destination[field]))
    for field in ("tls", "network_safety", "batch", "rotation"):
        nested = destination.get(field)
        if isinstance(nested, dict):
            for key, value in nested.items():
                mutations.append(V8YAMLMutation.set((*base, field, key), value))
    headers = destination.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            mutations.append(V8YAMLMutation.set((*base, "headers", key), value))
    overrides = destination.get("signal_overrides")
    send = destination.get("send")
    if isinstance(send, dict):
        desired_overrides = overrides if isinstance(overrides, dict) else {}
        existing_overrides = existing.get("signal_overrides")
        if isinstance(existing_overrides, dict):
            for signal in existing_overrides:
                if signal not in desired_overrides:
                    mutations.append(
                        V8YAMLMutation.delete((*base, "signal_overrides", signal))
                    )
        for signal, override in desired_overrides.items():
            if isinstance(override, dict):
                for key, value in override.items():
                    mutations.append(
                        V8YAMLMutation.set((*base, "signal_overrides", signal, key), value)
                    )
    if isinstance(send, dict):
        if existing.get("routes"):
            raise ValueError(
                "cannot replace advanced routes with --signals; remove routes explicitly first"
            )
        for key, value in send.items():
            mutations.append(V8YAMLMutation.set((*base, "send", key), value))
    elif (
        destination.get("preset") == "galileo"
        and existing.get("send") == _LEGACY_GENERATED_GALILEO_SEND
    ):
        # Retire only the exact concise policy written by earlier Galileo
        # setup versions. Operator-authored sends and advanced routes remain
        # untouched.
        mutations.append(V8YAMLMutation.delete((*base, "send")))
    return mutations


def _require_v8_operator_status(data_dir: str):
    """Return canonical status or reject a non-v8 source."""

    from defenseclaw.config_inspect import ConfigInspectError
    from defenseclaw.observability.v8_config import V8ConfigError
    from defenseclaw.observability.v8_status import (
        inspect_v8_operator_status,
    )

    path = config_path_for_data_dir(data_dir)
    try:
        return inspect_v8_operator_status(path)
    except (ConfigInspectError, V8ConfigError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc


def _print_v8_destination_list(status, *, emit_json: bool) -> None:
    rows = [
        {
            "name": destination.name,
            "kind": destination.kind,
            "enabled": destination.enabled,
            "generated": destination.generated,
            "signals": list(destination.selected_signals),
            "capabilities": list(destination.capabilities),
            "policy": destination.policy_form,
            "bucket_count": len(destination.buckets),
            "redaction": destination.redaction_label,
            "target": destination.endpoint,
            "platform_status": _destination_platform_status(destination),
        }
        for destination in status.destinations
    ]
    if emit_json:
        click.echo(_json.dumps(rows, indent=2))
        return
    click.echo()
    ux.section("Observability destinations")
    click.echo(
        f"  {'NAME':<24} {'KIND':<12} {'STATE':<9} {'SIGNALS':<22} "
        f"{'BUCKETS':<8} {'POLICY':<20} REDACTION"
    )
    for row in rows:
        state = (
            "unsupported"
            if row["platform_status"] == "unsupported"
            else "enabled" if row["enabled"] else "disabled"
        )
        signals = ",".join(row["signals"]) or "none"
        click.echo(
            f"  {row['name'][:23]:<24} {row['kind'][:11]:<12} {state:<9} "
            f"{signals[:21]:<22} {row['bucket_count']:<8} "
            f"{row['policy'][:19]:<20} {row['redaction']}"
        )
    click.echo(
        f"  Retention: {status.retention_days} days"
        if status.retention_days
        else "  Retention: unbounded"
    )
    click.echo(f"  Plan digest: {status.plan_digest}")
    click.echo()


def _endpoint_is_private(raw: str) -> bool:
    """True when ``raw`` (host:port or URL) names this computer or a private network."""

    from urllib.parse import urlsplit

    from defenseclaw.observability.v8_config import (
        ENDPOINT_HOST_LOCALHOST,
        ENDPOINT_HOST_PRIVATE,
        classify_endpoint_host,
    )

    raw = (raw or "").strip()
    if not raw:
        return False
    try:
        host = urlsplit(raw if "://" in raw else "//" + raw).hostname or ""
    except ValueError:
        return False
    return bool(host) and classify_endpoint_host(host) in {ENDPOINT_HOST_LOCALHOST, ENDPOINT_HOST_PRIVATE}


def _confirm_private_endpoint(
    preset: Preset,
    resolved_inputs: dict[str, str],
    plaintext: bool,
) -> tuple[bool, bool]:
    """Interactive add: ask before writing a loopback/private endpoint.

    Returns ``(allow_private_networks, plaintext)``.  A "no" stops with one
    plain line, before anything is written.
    """

    if preset.otel_tls_insecure:
        return False, plaintext  # the local-stack preset already allows loopback
    endpoint = resolved_inputs.get("endpoint") or resolved_inputs.get("host", "")
    if not _endpoint_is_private(endpoint):
        return False, plaintext
    click.echo(f"  {endpoint} is on this computer or a private network.")
    if not click.confirm("  Is this a collector you run yourself?", default=True):
        raise click.ClickException(
            "Not saved. Use a public collector endpoint, or the local-otlp preset for the local stack."
        )
    kind = preset.adapter_kind or "otlp"
    if kind == "otlp" and not plaintext and "://" not in endpoint:
        plaintext = not click.confirm("  Does this collector use TLS?", default=False)
    return True, plaintext


def _gate_local_preset(
    preset: Preset,
    resolved_inputs: dict[str, str],
    *,
    name: str,
) -> None:
    """Reject only bundled local destinations unavailable on this host."""

    endpoint = resolved_inputs.get("endpoint") or resolved_inputs.get("host", "")
    kind = preset.adapter_kind or "otlp"
    if not local_observability_stack_supported() and is_local_observability_stack_destination(
        name=name,
        preset_id=preset.id,
        kind=kind,
        endpoint=endpoint,
    ):
        raise click.ClickException(LOCAL_OBSERVABILITY_UNSUPPORTED_REASON)
    if not local_splunk_stack_supported() and is_local_splunk_stack_destination(
        preset_id=preset.id,
        kind=kind,
        endpoint=endpoint,
    ):
        raise click.ClickException(LOCAL_SPLUNK_UNSUPPORTED_REASON)


def _destination_platform_status(destination) -> str:
    return (
        "unsupported"
        if destination_platform_unsupported(
            name=destination.name,
            preset_id=getattr(destination, "preset", ""),
            kind=destination.kind,
            endpoint=destination.endpoint,
        )
        else "supported"
    )


def _v8_source_destination_index(data_dir: str, name: str) -> int:
    from defenseclaw.observability.v8_config import load_validate_v8

    path = config_path_for_data_dir(data_dir)
    validated = load_validate_v8(path.read_bytes(), source_name=str(path)).source
    observability = validated.get("observability")
    if not isinstance(observability, dict):
        observability = {}
    destinations = observability.get("destinations")
    if not isinstance(destinations, list):
        destinations = []
    matches = [
        index
        for index, destination in enumerate(destinations)
        if isinstance(destination, dict) and destination.get("name") == name
    ]
    if len(matches) != 1:
        if name == "local-sqlite":
            raise click.ClickException(
                "local-sqlite is mandatory and cannot be disabled or removed"
            )
        # GAP-1928: the shared not-found shape, without "v8" jargon.
        known = (
            destination.get("name")
            for destination in destinations
            if isinstance(destination, dict) and destination.get("name")
        )
        raise click.ClickException(
            ux.not_found_message("observability destination", name, known, "defenseclaw setup observability list")
        )
    return matches[0]


def _set_v8_destination_enabled(
    data_dir: str,
    name: str,
    enabled: bool,
) -> None:
    from defenseclaw.observability.v8_writer import mutate_v8_config
    from defenseclaw.observability.v8_yaml import V8YAMLMutation

    index = _v8_source_destination_index(data_dir, name)
    result = mutate_v8_config(
        config_path_for_data_dir(data_dir),
        [V8YAMLMutation.set(("observability", "destinations", index, "enabled"), enabled)],
        data_dir=data_dir,
    )
    state = "enabled" if enabled else "disabled"
    suffix = "" if result.changed else " (already set)"
    click.echo(f"  {name}: {state}{suffix}")


def _remove_v8_destination(data_dir: str, name: str) -> None:
    from defenseclaw.observability.v8_writer import mutate_v8_config
    from defenseclaw.observability.v8_yaml import V8YAMLMutation

    index = _v8_source_destination_index(data_dir, name)
    try:
        authored = _v8_authored_destinations(data_dir)
    except (OSError, ValueError):
        authored = []
    mutate_v8_config(
        config_path_for_data_dir(data_dir),
        [V8YAMLMutation.delete(("observability", "destinations", index))],
        data_dir=data_dir,
    )
    click.echo(f"  {name}: removed")
    # GAP-1892: add wrote the key to .env; say so when nothing else uses it.
    removed: set[str] = set()
    kept: set[str] = set()
    for destination in authored:
        (removed if destination.get("name") == name else kept).update(_env_references(destination))
    dotenv = os.path.join(data_dir, ".env")
    for env_name in sorted(removed - kept):
        if _peek_dotenv(data_dir, env_name):
            click.echo(
                f"  {env_name} is still stored in {dotenv}; remove it with: "
                f"defenseclaw keys remove {env_name}"
            )


def _env_references(value: Any) -> set[str]:
    """Names of every {env: NAME} secret reference inside a destination."""
    if isinstance(value, dict):
        found: set[str] = set()
        if set(value) == {"env"} and isinstance(value["env"], str):
            found.add(value["env"])
        for item in value.values():
            found |= _env_references(item)
        return found
    if isinstance(value, list):
        return set().union(*(_env_references(item) for item in value)) if value else set()
    return set()


def _test_v8_destination(
    data_dir: str,
    name: str,
    timeout: float,
    *,
    write_probe: bool,
) -> None:
    from defenseclaw.config_inspect import ConfigInspectError, inspect_v8_config
    from defenseclaw.observability.destination_test import (
        NETWORK_FAILURE_CLASSES,
        NETWORK_PATH_NOTE,
        DestinationTestError,
        canonical_local_compliance_recorder,
        run_destination_test,
    )

    path = config_path_for_data_dir(data_dir)
    try:
        inspected = inspect_v8_config("effective", config_path=str(path), data_dir=data_dir)
        result = run_destination_test(
            inspected.effective or {},
            name=name,
            data_dir=inspected.data_dir,
            timeout=timeout,
            write_probe=write_probe,
            compliance=canonical_local_compliance_recorder(
                config_path=inspected.source,
                data_dir=inspected.data_dir,
            ),
        )
    except ConfigInspectError as exc:
        raise click.ClickException(str(exc)) from exc
    except DestinationTestError as exc:
        message = f"destination test failed ({exc.failure_class}): {exc.message}"
        if exc.failure_class == "not_found":
            message = _unknown_destination_message(name, inspected.effective or {})
        elif exc.failure_class == "authentication_failed" and _is_galileo_destination(
            inspected.effective or {}, name
        ):
            # GAP-2289: a key from another Galileo cluster gets 401 at the default endpoint.
            message += (
                ". For a Galileo cluster other than api.galileo.ai, run 'defenseclaw setup observability "
                "add galileo' again with --endpoint <https://<cluster>/otel/traces>"
            )
        elif exc.failure_class in NETWORK_FAILURE_CLASSES:
            # GAP-2344: same note as 'observability destination test'.
            message += f"\n{NETWORK_PATH_NOTE}"
        raise click.ClickException(message) from exc
    click.echo(f"  {result.destination}: {result.mode} succeeded")
    if result.mode == "handshake" and result.authentication_verified:
        click.echo("  authentication: credentials accepted (empty export; nothing was written)")
    click.echo(f"  protocol={result.protocol}; endpoints={result.endpoint_count}")
    click.echo(f"  probe_id={result.probe_id}; compliance activity recorded locally")
    click.echo(f"  {NETWORK_PATH_NOTE}")


def _is_galileo_destination(effective: dict, name: str) -> bool:
    destinations = effective.get("destinations") if isinstance(effective, dict) else None
    for item in destinations or []:
        if isinstance(item, dict) and item.get("name") == name:
            transport = item.get("transport") if isinstance(item.get("transport"), dict) else {}
            headers = transport.get("headers") if isinstance(transport.get("headers"), dict) else {}
            return item.get("preset") == "galileo" or any(
                str(key).lower() == "galileo-api-key" for key in headers
            )
    return False


def _unknown_destination_message(name: str, effective: dict) -> str:
    """Name the configured destinations when ``test`` gets an unknown one (GAP-1336)."""
    destinations = effective.get("destinations") if isinstance(effective, dict) else None
    names = sorted(
        str(item.get("name"))
        for item in destinations or []
        if isinstance(item, dict) and item.get("name")
    )
    configured = ", ".join(names) if names else "none"
    return (
        f"no observability destination is named '{name}'; configured: {configured}. "
        "Pass one of those names (see 'defenseclaw setup observability list')"
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
    # Last four only, like keys set/list (GAP-1366).
    return "..." + value[-4:]


# Registry accessor for cmd_setup.py (imports register the group under setup)
# ---------------------------------------------------------------------------


__all__ = ["observability", "PRESETS"]
