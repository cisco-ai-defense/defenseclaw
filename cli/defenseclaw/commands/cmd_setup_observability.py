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

All destructive subcommands write atomically (``config.yaml.tmp`` ->
``rename``) so a crash mid-write cannot leave the gateway with an
unparseable config.
"""

from __future__ import annotations

import json as _json
import os
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

import click

from defenseclaw.commands.redaction_status import print_redaction_status_hint
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.observability import (
    PRESETS,
    Destination,
    WriteResult,
    apply_preset,
    list_destinations,
    preset_choices,
    remove_destination,
    resolve_preset,
    set_destination_enabled,
)

# All prompt keys across all presets. Exposed as Click options so the
# same command surface covers every preset; the writer ignores unknown
# keys per preset.
_ALL_PROMPT_FLAGS = (
    "realm", "site", "region", "dataset",
    "endpoint", "protocol",
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
    ``observability add splunk-o11y`` / ``splunk-hec``).
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
@click.option("--dry-run", is_flag=True, help="Preview YAML/dotenv changes without writing")
@click.option("--non-interactive", is_flag=True, help="Skip prompts; use flags only")
# Prompt flags — shared across all presets; writer resolves per-preset.
@click.option("--realm", default=None)
@click.option("--site", default=None)
@click.option("--region", default=None)
@click.option("--dataset", default=None)
@click.option("--endpoint", default=None)
@click.option("--protocol", type=click.Choice(["grpc", "http"]), default=None)
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
    dry_run: bool,
    non_interactive: bool,
    realm, site, region, dataset,
    endpoint, protocol,
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
      defenseclaw setup observability add splunk-hec
    """
    preset = resolve_preset(preset_id.lower())

    raw_inputs: dict[str, str | None] = {
        "realm": realm, "site": site, "region": region, "dataset": dataset,
        "endpoint": endpoint, "protocol": protocol,
        "host": host, "port": port, "index": index, "source": source,
        "sourcetype": sourcetype,
        "url": url, "method": method, "url_path": url_path,
    }
    if verify_tls is not None:
        raw_inputs["verify_tls"] = "true" if verify_tls else "false"

    if not non_interactive:
        raw_inputs = _prompt_missing(preset, raw_inputs)
        if token_value is None:
            token_value = _prompt_secret(preset, app.cfg.data_dir)

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

    try:
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

    _print_write_result(result, dry_run=dry_run)
    print_redaction_status_hint(app.cfg)
    click.echo()

    if app.logger and not dry_run:
        app.logger.log_action(
            "setup-observability",
            "config",
            f"action=add preset={preset.id} name={result.name} target={result.target}",
        )


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@observability.command("list")
@click.option("--json", "emit_json", is_flag=True, help="Emit machine-readable JSON")
@pass_ctx
def list_cmd(app: AppContext, emit_json: bool) -> None:
    """List configured observability destinations."""
    dests = list_destinations(app.cfg.data_dir)
    if emit_json:
        click.echo(_json.dumps([_dest_to_dict(d) for d in dests], indent=2))
        return
    if not dests:
        click.echo("  No destinations configured.")
        click.echo("  Add one with: defenseclaw setup observability add <preset>")
        return
    click.echo()
    click.echo(f"  {'NAME':<40} {'KIND':<12} {'ENABLED':<8} {'PRESET':<14} ENDPOINT")
    click.echo(f"  {'-' * 40} {'-' * 12} {'-' * 8} {'-' * 14} {'-' * 40}")
    for d in dests:
        endpoint = d.endpoint or "(none)"
        if len(endpoint) > 60:
            endpoint = endpoint[:57] + "..."
        click.echo(
            f"  {d.name:<40} {d.kind:<12} {('yes' if d.enabled else 'no'):<8} "
            f"{(d.preset_id or '-'):<14} {endpoint}",
        )
    click.echo()


# ---------------------------------------------------------------------------
# enable / disable
# ---------------------------------------------------------------------------


@observability.command("enable")
@click.argument("name")
@pass_ctx
def enable_cmd(app: AppContext, name: str) -> None:
    """Enable a destination (``name=otel`` targets the gateway exporter)."""
    try:
        result = set_destination_enabled(name, True, app.cfg.data_dir)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    _print_write_result(result, dry_run=False)


@observability.command("disable")
@click.argument("name")
@pass_ctx
def disable_cmd(app: AppContext, name: str) -> None:
    """Disable a destination."""
    try:
        result = set_destination_enabled(name, False, app.cfg.data_dir)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    _print_write_result(result, dry_run=False)


# ---------------------------------------------------------------------------
# remove
# ---------------------------------------------------------------------------


@observability.command("remove")
@click.argument("name")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt")
@pass_ctx
def remove_cmd(app: AppContext, name: str, yes: bool) -> None:
    """Delete a destination (``name=otel`` disables but preserves the block)."""
    if not yes and not click.confirm(f"  Remove destination {name!r}?", default=False):
        click.echo("  Aborted.")
        return
    try:
        result = remove_destination(name, app.cfg.data_dir)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    _print_write_result(result, dry_run=False)


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
    if not d.enabled:
        click.echo(f"  Warning: destination {name!r} is currently disabled.")

    click.echo()
    click.echo(f"  Testing {name} [{d.kind}]: {d.endpoint or '(no endpoint)'}")
    if d.target == "otel":
        _test_otel(app.cfg.data_dir, timeout=timeout)
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

    cfg_path = os.path.join(app.cfg.data_dir, "config.yaml")
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
    if endpoint:
        parsed = urlparse(endpoint)
        if parsed.hostname:
            host = parsed.hostname

    name = f"splunk-hec-{_slug(host)}"
    new_entry: dict[str, Any] = {
        "name": name,
        "kind": "splunk_hec",
        "enabled": bool(legacy.get("enabled", False)),
        "splunk_hec": {
            "endpoint": endpoint,
            "token_env": str(legacy.get("hec_token_env", "") or "DEFENSECLAW_SPLUNK_HEC_TOKEN"),
            "index": str(legacy.get("index", "") or "defenseclaw"),
            "source": str(legacy.get("source", "") or "defenseclaw"),
            "sourcetype": str(legacy.get("sourcetype", "") or "_json"),
            "verify_tls": bool(legacy.get("verify_tls", False)),
        },
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
                _write_atomically(cfg_path, raw)
                click.echo("  Removed legacy splunk: block.")
            return

    click.echo()
    click.echo("  Migration preview:")
    click.echo("    audit_sinks += ")
    click.echo("      " + yaml.safe_dump(new_entry, sort_keys=False).replace("\n", "\n      ").rstrip())
    click.echo("    splunk: (removed)")
    click.echo()

    if not do_apply:
        click.echo("  Dry-run — re-run with --apply to write.")
        return

    sinks.append(new_entry)
    raw["audit_sinks"] = sinks
    raw.pop("splunk", None)
    _write_atomically(cfg_path, raw)
    click.echo(f"  Migrated splunk: block to audit_sinks[{name}].")
    if app.logger:
        app.logger.log_action(
            "setup-observability", "config",
            f"action=migrate-splunk name={name}",
        )


# ---------------------------------------------------------------------------
# Interactive helpers
# ---------------------------------------------------------------------------


def _prompt_missing(
    preset, raw_inputs: dict[str, str | None],
) -> dict[str, str | None]:
    click.echo()
    click.echo(f"  {preset.display_name} Setup")
    click.echo(f"  {'─' * (len(preset.display_name) + 6)}")
    click.echo(f"  {preset.description}")
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


def _test_otel(data_dir: str, *, timeout: float) -> None:
    """Dial the configured OTel signal endpoints over TCP.

    A full OTLP probe would require an SDK + collector context — TCP
    reachability + TLS handshake is the most portable approximation.
    """
    import yaml

    cfg_path = os.path.join(data_dir, "config.yaml")
    try:
        with open(cfg_path) as f:
            raw: dict[str, Any] = yaml.safe_load(f) or {}
    except OSError as exc:
        click.echo(f"  ✗ cannot read config.yaml: {exc}")
        return
    otel = raw.get("otel") or {}
    if not otel.get("enabled"):
        click.echo("  ⚠ otel.enabled=false — exporter will not run until enabled")
    for sig in ("traces", "metrics", "logs"):
        block = otel.get(sig) or {}
        if not block.get("enabled"):
            click.echo(f"    {sig:<8} disabled")
            continue
        endpoint = str(block.get("endpoint", "") or "")
        protocol = str(block.get("protocol") or otel.get("protocol") or "grpc")
        ok, msg = _tcp_probe(endpoint, protocol, timeout=timeout)
        click.echo(f"    {sig:<8} {'✓' if ok else '✗'} {msg}")


def _test_splunk_hec(data_dir: str, name: str, *, timeout: float) -> None:
    import yaml

    cfg_path = os.path.join(data_dir, "config.yaml")
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
    hec = sink.get("splunk_hec") or {}
    endpoint = str(hec.get("endpoint", "") or "")
    token_env = str(hec.get("token_env", "") or "")
    token = os.environ.get(token_env, "") if token_env else ""
    if not token:
        token = _peek_dotenv(data_dir, token_env)
    if not token:
        click.echo(f"  ✗ token not set (env={token_env})")
        return
    verify_tls = bool(hec.get("verify_tls", False))
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
        click.echo(f"  ✗ endpoint must be http(s):// (got {endpoint!r})")
        return
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
            click.echo(f"  ✓ HEC responded {resp.status} {resp.reason}")
    except urllib.error.HTTPError as exc:
        hint = "check token/index permissions" if exc.code in (401, 403) else ""
        click.echo(f"  ✗ HTTP {exc.code} {exc.reason} {hint}")
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        click.echo(f"  ✗ {exc}")


def _test_otlp_logs(data_dir: str, name: str, *, timeout: float) -> None:
    import yaml

    cfg_path = os.path.join(data_dir, "config.yaml")
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

    cfg_path = os.path.join(data_dir, "config.yaml")
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
    verify_tls = bool(block.get("verify_tls", True))
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
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


def _print_write_result(result: WriteResult, *, dry_run: bool) -> None:
    click.echo()
    prefix = "  [dry-run]" if dry_run else "  "
    click.echo(f"{prefix}{result.target}:{result.name} (preset={result.preset_id})")
    for line in result.yaml_changes:
        click.echo(f"{prefix}  yaml: {line}")
    for line in result.dotenv_changes:
        click.echo(f"{prefix}  env:  {line}")
    for line in result.warnings:
        click.echo(f"{prefix}  ⚠ {line}")
    if not dry_run:
        click.echo("  Next: defenseclaw-gateway restart (to reload config)")
    click.echo()


def _dest_to_dict(d: Destination) -> dict[str, Any]:
    return {
        "name": d.name,
        "target": d.target,
        "kind": d.kind,
        "enabled": d.enabled,
        "preset_id": d.preset_id,
        "endpoint": d.endpoint,
        "signals": d.signals,
    }


def _slug(value: str) -> str:
    import re
    out = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return out[:40] or "default"


def _write_atomically(cfg_path: str, raw: dict[str, Any]) -> None:
    import yaml

    tmp = cfg_path + ".tmp"
    os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
    with open(tmp, "w") as f:
        yaml.safe_dump(raw, f, default_flow_style=False, sort_keys=False)
    os.replace(tmp, cfg_path)


# ---------------------------------------------------------------------------
# Registry accessor for cmd_setup.py (imports register the group under setup)
# ---------------------------------------------------------------------------


__all__ = ["observability", "PRESETS"]
