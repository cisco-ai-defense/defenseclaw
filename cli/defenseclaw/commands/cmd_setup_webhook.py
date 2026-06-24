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

"""``defenseclaw setup webhook`` — Slack/PagerDuty/Webex/generic notifier CRUD.

This group is the *disambiguated* webhook surface: it manages the
top-level ``webhooks:`` list in ``config.yaml`` (chat/incident notifiers
consumed by ``internal/gateway/webhook.go``). The preset
``setup observability add webhook`` writes a separate audit-sink and is
now labeled "Generic HTTP JSONL" to avoid the collision.

Subcommands
-----------
add <type>            Create a webhook entry (slack/pagerduty/webex/generic)
list                  Show configured webhooks (secrets redacted)
show <name>           Pretty-print a single webhook entry
enable <name>         Flip ``enabled: true``
disable <name>        Flip ``enabled: false``
remove <name>         Delete the entry
test <name>           Dispatch a synthetic event and print result

All writes go through ``defenseclaw.webhooks.writer`` which performs
atomic tmp+rename and the same SSRF validation used by the Go gateway.
The Go TUI shells out to this group with ``--non-interactive``.
"""

from __future__ import annotations

import json as _json
import os
from typing import Any

import click

from defenseclaw import ux
from defenseclaw.audit_actions import ACTION_SETUP_WEBHOOK
from defenseclaw.config import config_path_for_data_dir, locked_config_yaml, write_config_yaml_secure
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.webhooks import (
    DispatchResult,
    WebhookView,
    WebhookWriteResult,
    apply_webhook,
    list_webhooks,
    remove_webhook,
    send_synthetic,
    set_webhook_enabled,
    synthetic_event,
    validate_webhook_url,
)
from defenseclaw.webhooks.writer import (
    DEFAULT_MIN_SEVERITY,
    DEFAULT_TIMEOUT_SECONDS,
    VALID_EVENT_CATEGORIES,
    VALID_SEVERITIES,
    VALID_TYPES,
    _normalize_events,
    redact_webhook_url,
)

_WEBHOOK_TYPES = list(VALID_TYPES)


@click.group("webhook")
def webhook() -> None:
    """Configure Slack/PagerDuty/Webex/generic chat + incident webhooks.

    Separate from ``setup observability add webhook`` (which configures
    a generic HTTP JSONL audit-log forwarder). This group edits the
    top-level ``webhooks:`` list consumed by the runtime dispatcher.
    """


# ---------------------------------------------------------------------------
# add
# ---------------------------------------------------------------------------


@webhook.command("add")
@click.argument(
    "webhook_type",
    metavar="<type>",
    type=click.Choice(_WEBHOOK_TYPES, case_sensitive=False),
)
@click.option("--name", default=None, help="Destination name (default: derived from type+host)")
@click.option("--url", default=None, help="Webhook URL (Slack/PagerDuty/Webex/generic endpoint)")
@click.option("--secret-env", default=None,
              help="Environment variable NAME holding the secret/routing key/bot token")
@click.option("--room-id", default=None, help="Webex room ID (Webex only)")
@click.option(
    "--min-severity",
    type=click.Choice(list(VALID_SEVERITIES), case_sensitive=False),
    default=None,
    help=f"Minimum severity to forward (default: {DEFAULT_MIN_SEVERITY})",
)
@click.option(
    "--events",
    default=None,
    help="Comma-separated event categories to forward "
         f"(allowed: {', '.join(VALID_EVENT_CATEGORIES)})",
)
@click.option("--timeout-seconds", type=int, default=None,
              help=f"Per-delivery timeout (default: {DEFAULT_TIMEOUT_SECONDS})")
@click.option("--cooldown-seconds", type=int, default=None,
              help="Override dedup cooldown (omit=runtime default 300s; 0=disabled)")
@click.option("--enabled/--disabled", "enabled", default=True,
              help="Mark webhook enabled (default) or disabled")
@click.option("--connector", default=None,
              help="Scope this webhook to a connector (omit = global). A "
                   "connector's events route to its per-connector webhooks "
                   "when set, falling back to the global webhooks otherwise.")
@click.option("--dry-run", is_flag=True, help="Preview YAML changes without writing")
@click.option("--non-interactive", is_flag=True, help="Skip prompts; use flags only")
@pass_ctx
def add_webhook(  # noqa: PLR0913 — mirrors the prompt surface
    app: AppContext,
    webhook_type: str,
    name: str | None,
    url: str | None,
    secret_env: str | None,
    room_id: str | None,
    min_severity: str | None,
    events: str | None,
    timeout_seconds: int | None,
    cooldown_seconds: int | None,
    enabled: bool,
    connector: str | None,
    dry_run: bool,
    non_interactive: bool,
) -> None:
    """Create or update a webhook notifier.

    Examples:

    \b
      # Slack (no auth header, URL carries the secret)
      defenseclaw setup webhook add slack --url https://hooks.slack.com/...
    \b
      # PagerDuty (routing key in an env var)
      defenseclaw setup webhook add pagerduty \\
          --url https://events.pagerduty.com/v2/enqueue \\
          --secret-env DEFENSECLAW_PD_KEY
    \b
      # Webex (bot token + room ID)
      defenseclaw setup webhook add webex \\
          --url https://webexapis.com/v1/messages \\
          --secret-env DEFENSECLAW_WEBEX_TOKEN --room-id Y2lzY29z...
    \b
      # Generic HMAC (payload signed with SHA-256)
      defenseclaw setup webhook add generic \\
          --url https://siem.example.com/hook \\
          --secret-env DEFENSECLAW_SIEM_SECRET
    """
    wt = webhook_type.lower()

    if not non_interactive:
        url = _prompt_missing(url, label="Webhook URL")
        if wt == "pagerduty":
            secret_env = _prompt_missing(
                secret_env,
                label="Env var holding PagerDuty routing key",
                default="DEFENSECLAW_PD_ROUTING_KEY",
                is_env_name=True,
            )
        elif wt == "webex":
            secret_env = _prompt_missing(
                secret_env,
                label="Env var holding Webex bot token",
                default="DEFENSECLAW_WEBEX_TOKEN",
                is_env_name=True,
            )
            room_id = _prompt_missing(room_id, label="Webex room ID")
        elif wt == "generic" and not secret_env:
            if click.confirm("  Sign payloads with HMAC-SHA256?", default=True):
                secret_env = _prompt_missing(
                    None,
                    label="Env var holding HMAC secret",
                    default="DEFENSECLAW_WEBHOOK_SECRET",
                    is_env_name=True,
                )

    if not url:
        click.echo("error: --url is required", err=True)
        raise SystemExit(2)

    events_list: list[str] | None = None
    if events is not None:
        events_list = [e.strip() for e in events.split(",") if e.strip()]

    connector_name = (connector or "").strip()
    try:
        if connector_name:
            result = _apply_webhook_to_connector(
                app.cfg.data_dir,
                connector_name,
                name=name,
                type_=wt,
                url=url,
                secret_env=secret_env,
                room_id=room_id,
                min_severity=min_severity,
                events=events_list,
                timeout_seconds=timeout_seconds,
                cooldown_seconds=cooldown_seconds,
                enabled=enabled,
                dry_run=dry_run,
            )
        else:
            result = apply_webhook(
                name=name,
                type_=wt,
                url=url,
                data_dir=app.cfg.data_dir,
                secret_env=secret_env,
                room_id=room_id,
                min_severity=min_severity,
                events=events_list,
                timeout_seconds=timeout_seconds,
                cooldown_seconds=cooldown_seconds,
                enabled=enabled,
                dry_run=dry_run,
            )
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc

    _print_write_result(result, connector=connector_name)

    if app.logger and not dry_run:
        app.logger.log_action(
            ACTION_SETUP_WEBHOOK,
            "config",
            f"action=add type={result.type} name={result.name}"
            + (f" connector={connector_name}" if connector_name else ""),
        )


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@webhook.command("list")
@click.option("--json", "emit_json", is_flag=True, help="Emit machine-readable JSON")
@click.option("--connector", default=None,
              help="List a connector's per-connector webhooks (omit = global). "
                   "When the connector has no per-connector webhooks it inherits "
                   "the global list.")
@pass_ctx
def list_cmd(app: AppContext, emit_json: bool, connector: str | None) -> None:
    """List configured webhooks (secrets are referenced, never printed)."""
    connector_name = (connector or "").strip()
    if connector_name:
        entries = _connector_webhook_views(app.cfg.data_dir, connector_name)
        if entries is None:
            if emit_json:
                click.echo("[]")
                return
            ux.subhead(
                f"No per-connector webhooks for {connector_name!r} — "
                "inherits the global webhooks."
            )
            return
    else:
        entries = list_webhooks(app.cfg.data_dir)
    if emit_json:
        click.echo(_json.dumps([_view_to_dict(v) for v in entries], indent=2))
        return
    if not entries:
        ux.subhead("No webhooks configured.")
        ux.subhead("Add one with: defenseclaw setup webhook add <type>")
        return
    click.echo()
    ux.section("Webhooks")
    click.echo(f"  {'NAME':<32} {'TYPE':<10} {'ENABLED':<8} {'SEVERITY':<10} URL")
    click.echo(f"  {'-' * 32} {'-' * 10} {'-' * 8} {'-' * 10} {'-' * 40}")
    for v in entries:
        safe_url = redact_webhook_url(v.url)
        u = safe_url if len(safe_url) <= 60 else safe_url[:57] + "..."
        click.echo(
            f"  {v.name:<32} {v.type:<10} {('yes' if v.enabled else 'no'):<8} "
            f"{v.min_severity:<10} {u}",
        )
    click.echo()


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


@webhook.command("show")
@click.argument("name")
@click.option("--json", "emit_json", is_flag=True, help="Emit JSON")
@pass_ctx
def show_cmd(app: AppContext, name: str, emit_json: bool) -> None:
    """Pretty-print a single webhook entry (secret values never printed)."""
    entries = {v.name: v for v in list_webhooks(app.cfg.data_dir)}
    v = entries.get(name)
    if v is None:
        click.echo(f"error: no webhook named {name!r}", err=True)
        raise SystemExit(2)
    if emit_json:
        click.echo(_json.dumps(_view_to_dict(v), indent=2))
        return
    click.echo()
    state = ux._style("enabled", fg="green") if v.enabled else ux.dim("disabled")
    click.echo(f"  {ux.bold(v.name)} [{v.type}] {state}")
    click.echo(f"    {ux.dim('URL:')}            {redact_webhook_url(v.url)}")
    if v.secret_env:
        click.echo(f"    {ux.dim('Secret env:')}     {v.secret_env} (value not shown)")
    if v.room_id:
        click.echo(f"    {ux.dim('Room ID:')}        {v.room_id}")
    click.echo(f"    {ux.dim('Min severity:')}   {v.min_severity}")
    click.echo(f"    {ux.dim('Events:')}         {', '.join(v.events) if v.events else '(all)'}")
    click.echo(f"    {ux.dim('Timeout:')}        {v.timeout_seconds}s")
    if v.cooldown_seconds is None:
        click.echo(f"    {ux.dim('Cooldown:')}       runtime default (300s)")
    elif v.cooldown_seconds == 0:
        click.echo(f"    {ux.dim('Cooldown:')}       disabled (every matching event delivered)")
    else:
        click.echo(f"    {ux.dim('Cooldown:')}       {v.cooldown_seconds}s")
    click.echo()


# ---------------------------------------------------------------------------
# enable / disable
# ---------------------------------------------------------------------------


@webhook.command("enable")
@click.argument("name")
@click.option("--connector", default=None, help="Target a connector's per-connector webhook")
@pass_ctx
def enable_cmd(app: AppContext, name: str, connector: str | None) -> None:
    """Enable a webhook."""
    connector_name = (connector or "").strip()
    try:
        if connector_name:
            result = _set_connector_webhook_enabled(app.cfg.data_dir, connector_name, name, True)
        else:
            result = set_webhook_enabled(name, True, app.cfg.data_dir)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    _print_write_result(result, connector=connector_name)


@webhook.command("disable")
@click.argument("name")
@click.option("--connector", default=None, help="Target a connector's per-connector webhook")
@pass_ctx
def disable_cmd(app: AppContext, name: str, connector: str | None) -> None:
    """Disable a webhook (preserves the entry)."""
    connector_name = (connector or "").strip()
    try:
        if connector_name:
            result = _set_connector_webhook_enabled(app.cfg.data_dir, connector_name, name, False)
        else:
            result = set_webhook_enabled(name, False, app.cfg.data_dir)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    _print_write_result(result, connector=connector_name)


# ---------------------------------------------------------------------------
# remove
# ---------------------------------------------------------------------------


@webhook.command("remove")
@click.argument("name")
@click.option("--connector", default=None, help="Target a connector's per-connector webhook")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt")
@pass_ctx
def remove_cmd(app: AppContext, name: str, connector: str | None, yes: bool) -> None:
    """Delete a webhook entry."""
    connector_name = (connector or "").strip()
    label = f"{name!r}" + (f" (connector {connector_name})" if connector_name else "")
    if not yes and not click.confirm(f"  Remove webhook {label}?", default=False):
        click.echo("  Aborted.")
        return
    try:
        if connector_name:
            result = _remove_connector_webhook(app.cfg.data_dir, connector_name, name)
        else:
            result = remove_webhook(name, app.cfg.data_dir)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    _print_write_result(result, connector=connector_name)


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------


@webhook.command("test")
@click.argument("name")
@click.option("--dry-run", is_flag=True, help="Format the payload but do NOT deliver")
@click.option("--timeout", type=float, default=5.0, help="Per-delivery timeout in seconds")
@pass_ctx
def test_cmd(app: AppContext, name: str, dry_run: bool, timeout: float) -> None:
    """Dispatch a synthetic event through a configured webhook.

    Safe to run repeatedly — every invocation stamps a unique event ID
    so receivers don't dedup. Use ``--dry-run`` to inspect the payload
    without delivering.
    """
    entries = {v.name: v for v in list_webhooks(app.cfg.data_dir)}
    v = entries.get(name)
    if v is None:
        click.echo(f"error: no webhook named {name!r}", err=True)
        click.echo("  Known webhooks:", err=True)
        for k in sorted(entries):
            click.echo(f"    - {k}", err=True)
        raise SystemExit(2)

    secret_value = ""
    if v.secret_env:
        secret_value = os.environ.get(v.secret_env, "")
        if not secret_value and not dry_run:
            click.echo(
                f"error: env var {v.secret_env!r} is unset; export it or pass --dry-run",
                err=True,
            )
            raise SystemExit(2)

    if not dry_run:
        # URL was validated at write-time but re-check — operators
        # sometimes hand-edit config.yaml and the runtime gateway would
        # reject the entry anyway. Fail fast with a clear message.
        try:
            validate_webhook_url(v.url)
        except ValueError as exc:
            click.echo(f"error: URL rejected by SSRF guard: {exc}", err=True)
            raise SystemExit(2) from exc

    evt = synthetic_event(
        action="webhook.test",
        target=f"defenseclaw-{v.name}",
        severity=v.min_severity,
        details=f"Synthetic test event for {v.name}",
    )

    click.echo()
    click.echo(
        f"  {ux.bold('Testing webhook')} {ux.bold(v.name)} [{v.type}] "
        f"{ux.dim('→')} {v.url}"
    )
    if dry_run:
        ux.subhead("(dry-run) formatting only, no delivery")

    result: DispatchResult = send_synthetic(
        webhook_type=v.type,
        url=v.url,
        secret=secret_value,
        room_id=v.room_id,
        event=evt,
        timeout_seconds=max(1, int(timeout)),
        name=v.name,
        preview_only=dry_run,
    )

    click.echo(f"    {ux.dim('Payload:')}        {result.payload_bytes} bytes")
    click.echo(f"    {ux.dim('Preview:')}        {result.request_body_preview[:160]}")
    if result.request_headers:
        click.echo(f"    {ux.bold('Headers:')}")
        for k, hv in sorted(result.request_headers.items()):
            click.echo(f"      {k}: {hv}")
    if dry_run:
        ux.ok("Result:         dry-run OK", indent="    ")
    elif result.ok:
        ux.ok(f"Result:         ok (HTTP {result.status_code})", indent="    ")
    else:
        detail = result.error or "unknown error"
        if result.status_code is not None:
            ux.err(f"Result:         fail (HTTP {result.status_code}): {detail}", indent="    ")
        else:
            ux.err(f"Result:         fail: {detail}", indent="    ")
    click.echo()

    # Log the outcome *before* possibly exiting non-zero so failed
    # dispatches still leave an audit trail.
    if app.logger and not dry_run:
        app.logger.log_action(
            ACTION_SETUP_WEBHOOK,
            "test",
            f"name={v.name} type={v.type} ok={result.ok}",
        )

    if not dry_run and not result.ok:
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _prompt_missing(
    value: str | None,
    *,
    label: str,
    default: str | None = None,
    is_env_name: bool = False,
) -> str:
    if value:
        return value
    prompt = f"  {label}"
    if default:
        prompt += f" [{default}]"
    while True:
        answer = click.prompt(prompt, default=default or "", show_default=False).strip()
        if not answer:
            click.echo("  (required)")
            continue
        if is_env_name and _looks_like_secret(answer):
            click.echo(
                "  That looks like an actual secret value. Please supply the "
                "NAME of the environment variable holding it (e.g. "
                "DEFENSECLAW_WEBEX_TOKEN) and export the value in your shell.",
            )
            continue
        return answer


def _looks_like_secret(value: str) -> bool:
    """Heuristic mirror of _looks_like_secret in cmd_setup.py."""
    if not value:
        return False
    prefixes = ("sk-", "sk-ant-", "ghp_", "gho_", "xoxb-", "xoxp-", "Bearer ")
    if any(value.startswith(p) for p in prefixes):
        return True
    if len(value) > 30 and not value.isupper():
        return True
    return False


def _view_to_dict(v: WebhookView) -> dict[str, Any]:
    return {
        "name": v.name,
        "type": v.type,
        # Webhook URLs embed the bearer secret in their path/query; redact
        # so ``list``/``show`` (and their ``--json``) never print it (F-0181).
        "url": redact_webhook_url(v.url),
        "secret_env": v.secret_env,
        "room_id": v.room_id,
        "min_severity": v.min_severity,
        "events": v.events,
        "timeout_seconds": v.timeout_seconds,
        "cooldown_seconds": v.cooldown_seconds,
        "enabled": v.enabled,
    }


def _print_write_result(result: WebhookWriteResult, *, connector: str = "") -> None:
    click.echo()
    mode = f"{ux.dim('(dry-run)')} " if result.dry_run else ""
    scope = f" {ux.dim('@' + connector)}" if connector else ""
    click.echo(f"  {mode}{ux.bold('Webhook')} {result.name!r} [{result.type}]{scope}")
    if result.yaml_changes:
        click.echo(f"  {ux.bold('YAML changes:')}")
        for line in result.yaml_changes:
            click.echo(f"    {ux.dim('-')} {line}")
    if result.warnings:
        click.echo(f"  {ux.bold('Warnings:')}")
        for w in result.warnings:
            ux.warn(w, indent="    ")
    click.echo()


# ---------------------------------------------------------------------------
# Per-connector webhooks (D5b)
#
# These commands write a SURGICAL slice of ``config.yaml`` —
# ``observability.connectors[<name>].webhooks`` — under the shared config
# lock, mirroring the sibling ``defenseclaw.webhooks.writer`` (which writes
# the top-level ``webhooks:`` list). They deliberately do NOT route through
# ``Config.save()``: that would re-serialize the whole (possibly stale)
# dataclass and could clobber a concurrently-written global ``webhooks:``
# block. The ``observability.connectors`` schema is round-tripped by
# ``config.ObservabilityConfig`` so any *fully-loaded* ``cfg.save()`` (a
# setup wizard, the TUI) preserves these entries.
#
# Validation (SSRF guard, type/severity/env-name checks, name derivation) is
# reused from the writer's public ``apply_webhook`` via a ``dry_run`` probe,
# so the per-connector path never drifts from the global path.
# ---------------------------------------------------------------------------


def _wh_load_raw(path: str) -> dict[str, Any]:
    import yaml

    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping at top level")
    return data


def _connector_webhook_list(
    raw: dict[str, Any], connector: str, *, create: bool,
) -> list[Any] | None:
    """Return the ``observability.connectors[connector].webhooks`` list.

    With ``create=True`` the nested path is materialised and the list
    returned for mutation. With ``create=False`` a missing path yields
    ``None`` ("no per-connector webhooks — inherit global").
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
    whs = entry.get("webhooks")
    if not isinstance(whs, list):
        if not create:
            return None
        whs = []
        entry["webhooks"] = whs
    return whs


def _prune_observability(raw: dict[str, Any], connector: str) -> None:
    """Drop now-empty per-connector dimensions / connector / block.

    Called after a remove so deleting the last per-connector webhook
    restores global inheritance (key absent = inherit) and leaves the
    config tidy.
    """
    obs = raw.get("observability")
    if not isinstance(obs, dict):
        return
    conns = obs.get("connectors")
    if not isinstance(conns, dict):
        return
    entry = conns.get(connector)
    if isinstance(entry, dict):
        if entry.get("webhooks") == []:
            entry.pop("webhooks", None)
        if entry.get("audit_sinks") == []:
            entry.pop("audit_sinks", None)
        if not entry:
            conns.pop(connector, None)
    if not conns:
        obs.pop("connectors", None)
    if not obs:
        raw.pop("observability", None)


def _apply_webhook_to_connector(
    data_dir: str,
    connector: str,
    *,
    name: str | None,
    type_: str,
    url: str | None,
    secret_env: str | None,
    room_id: str | None,
    min_severity: str | None,
    events: list[str] | None,
    timeout_seconds: int | None,
    cooldown_seconds: int | None,
    enabled: bool,
    dry_run: bool,
) -> WebhookWriteResult:
    """Insert/update a per-connector webhook (D5b)."""
    # Reuse the writer's full validation + name derivation via a dry-run
    # apply against the global surface (validates, never writes).
    probe = apply_webhook(
        name=name,
        type_=type_,
        url=url or "",
        data_dir=data_dir,
        secret_env=secret_env,
        room_id=room_id,
        min_severity=min_severity,
        events=events,
        timeout_seconds=timeout_seconds,
        cooldown_seconds=cooldown_seconds,
        enabled=enabled,
        dry_run=True,
    )
    derived_name = probe.name
    severity = (min_severity or DEFAULT_MIN_SEVERITY).upper()
    timeout = int(timeout_seconds) if timeout_seconds is not None else DEFAULT_TIMEOUT_SECONDS
    entry: dict[str, Any] = {
        "name": derived_name,
        "url": (url or "").strip(),
        "type": type_,
        "min_severity": severity,
        "events": list(_normalize_events(events)),
        "timeout_seconds": timeout,
        "enabled": bool(enabled),
    }
    if cooldown_seconds is not None:
        entry["cooldown_seconds"] = int(cooldown_seconds)
    if secret_env:
        entry["secret_env"] = secret_env
    if room_id:
        entry["room_id"] = room_id

    warnings = list(probe.warnings)
    if not dry_run:
        cfg_path = str(config_path_for_data_dir(data_dir))
        with locked_config_yaml(cfg_path):
            raw = _wh_load_raw(cfg_path)
            whs = _connector_webhook_list(raw, connector, create=True)
            idx = next(
                (i for i, w in enumerate(whs)
                 if isinstance(w, dict) and w.get("name") == derived_name),
                -1,
            )
            if idx >= 0:
                warnings.append(
                    f"observability.connectors[{connector}].webhooks[{derived_name}] "
                    "already existed — fields overwritten (other keys preserved)",
                )
                merged = dict(whs[idx]) if isinstance(whs[idx], dict) else {}
                # Preserve a prior cooldown when the caller did not set one.
                if cooldown_seconds is None and "cooldown_seconds" in merged:
                    entry["cooldown_seconds"] = merged["cooldown_seconds"]
                merged.update(entry)
                whs[idx] = merged
            else:
                whs.append(entry)
            write_config_yaml_secure(cfg_path, raw)
    return WebhookWriteResult(
        name=derived_name,
        type=type_,
        yaml_changes=[
            f"observability.connectors[{connector}].webhooks[{derived_name}] "
            f"type={type_} enabled={bool(enabled)} severity={severity}",
        ],
        warnings=warnings,
        dry_run=dry_run,
    )


def _view_from_dict(entry: dict[str, Any]) -> WebhookView:
    """Build a WebhookView from a raw per-connector webhook dict.

    Mirrors ``webhooks.writer.list_webhooks`` field handling so rendering
    (and ``--json`` redaction) is identical to the global list.
    """
    url = str(entry.get("url", "") or "")
    cd_raw = entry.get("cooldown_seconds")
    if cd_raw is None:
        cooldown: int | None = None
    else:
        try:
            cooldown = int(cd_raw)
        except (TypeError, ValueError):
            cooldown = None
    return WebhookView(
        name=str(entry.get("name", "") or ""),
        type=str(entry.get("type", "generic") or "generic"),
        url=url,
        secret_env=str(entry.get("secret_env", "") or ""),
        room_id=str(entry.get("room_id", "") or ""),
        min_severity=str(entry.get("min_severity", "") or DEFAULT_MIN_SEVERITY).upper(),
        events=[str(e) for e in (entry.get("events") or [])],
        timeout_seconds=int(entry.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS) or DEFAULT_TIMEOUT_SECONDS),
        cooldown_seconds=cooldown,
        enabled=bool(entry.get("enabled", False)),
    )


def _connector_webhook_views(data_dir: str, connector: str) -> list[WebhookView] | None:
    """Return a connector's per-connector webhooks, or None if unset."""
    raw = _wh_load_raw(str(config_path_for_data_dir(data_dir)))
    whs = _connector_webhook_list(raw, connector, create=False)
    if whs is None:
        return None
    return [_view_from_dict(w) for w in whs if isinstance(w, dict) and w.get("url")]


def _set_connector_webhook_enabled(
    data_dir: str, connector: str, name: str, enabled: bool,
) -> WebhookWriteResult:
    cfg_path = str(config_path_for_data_dir(data_dir))
    with locked_config_yaml(cfg_path):
        raw = _wh_load_raw(cfg_path)
        whs = _connector_webhook_list(raw, connector, create=False)
        idx = next(
            (i for i, w in enumerate(whs or [])
             if isinstance(w, dict) and w.get("name") == name),
            -1,
        )
        if idx < 0:
            raise ValueError(
                f"no per-connector webhook named {name!r} for connector {connector!r}"
            )
        whs[idx]["enabled"] = bool(enabled)
        type_ = str(whs[idx].get("type", "") or "")
        write_config_yaml_secure(cfg_path, raw)
    return WebhookWriteResult(
        name=name,
        type=type_,
        yaml_changes=[
            f"observability.connectors[{connector}].webhooks[{name}].enabled = {bool(enabled)}",
        ],
        warnings=[],
        dry_run=False,
    )


def _remove_connector_webhook(
    data_dir: str, connector: str, name: str,
) -> WebhookWriteResult:
    cfg_path = str(config_path_for_data_dir(data_dir))
    with locked_config_yaml(cfg_path):
        raw = _wh_load_raw(cfg_path)
        whs = _connector_webhook_list(raw, connector, create=False)
        if whs is None:
            raise ValueError(
                f"no per-connector webhooks for connector {connector!r}"
            )
        removed = None
        kept = []
        for w in whs:
            if isinstance(w, dict) and w.get("name") == name and removed is None:
                removed = w
                continue
            kept.append(w)
        if removed is None:
            raise ValueError(
                f"no per-connector webhook named {name!r} for connector {connector!r}"
            )
        whs[:] = kept
        _prune_observability(raw, connector)
        write_config_yaml_secure(cfg_path, raw)
    return WebhookWriteResult(
        name=name,
        type=str(removed.get("type", "") or ""),
        yaml_changes=[f"observability.connectors[{connector}].webhooks[{name}] removed"],
        warnings=[],
        dry_run=False,
    )
