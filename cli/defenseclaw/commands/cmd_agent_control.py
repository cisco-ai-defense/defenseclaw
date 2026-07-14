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

"""DefenseClaw Agent Control policy synchronization commands."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import signal
import socket
import tempfile
from dataclasses import asdict
from pathlib import Path
from threading import Event
from typing import Any

import click

from defenseclaw.agent_control.models import extract_candidates
from defenseclaw.agent_control.publisher import (
    ActivationError,
    GatewayClient,
    ManagedPublisher,
    NativeValidator,
    PublicationError,
    SingleWriterLock,
)
from defenseclaw.agent_control.state import load_state
from defenseclaw.agent_control.sync import (
    AgentControlSynchronizer,
    SynchronizationError,
    agent_control_observability_init_kwargs,
    configured_rule_pack_base_dirs,
    load_agent_control_sdk,
    resolve_agent_control_sdk_credentials,
)
from defenseclaw.context import AppContext, pass_ctx


@click.group(name="agent-control")
def agent_control_cmd() -> None:
    """Synchronize Agent Control policy into local DefenseClaw enforcement."""


def default_installation_id() -> str:
    """Return a stable, readable first-run installation identifier."""
    hostname = re.sub(r"[^A-Za-z0-9._-]+", "-", socket.gethostname()).strip("-.")
    return f"defenseclaw-{hostname or 'host'}"[:255]


def configure_agent_control(
    app: AppContext,
    *,
    deployment: str,
    server_url: str,
    installation_id: str,
    api_key_env: str,
    enable_rule_pack: bool,
    manage_opa: bool,
    include_content: bool,
    target_type: str | None = None,
    api_key_header: str | None = None,
    observability_sink: str | None = None,
    otel_destination: str | None = None,
    manual_activation: bool = False,
    require_rules: bool = False,
    save_config: bool = True,
    api_key_override: str | None = None,
    sdk: Any | None = None,
    validator: NativeValidator | None = None,
) -> Path:
    """Preflight, validate, and publish one initial managed snapshot.

    Config is not saved until the SDK snapshot has passed the strict envelope
    parser and native validators.  This gives setup a fail-safe boundary: a
    failed first fetch leaves the existing local regex posture on disk.
    """
    try:
        if not app.cfg.policy_dir:
            raise click.ClickException("policy_dir must be configured before Agent Control setup")

        original_guardrail = copy.deepcopy(app.cfg.guardrail)
        original_agent_control = copy.deepcopy(app.cfg.agent_control)
        settings = app.cfg.agent_control
        settings.enabled = True
        settings.deployment = deployment.strip()
        settings.server_url = server_url.strip().rstrip("/")
        settings.api_key_env = api_key_env.strip()
        settings.target_type = (target_type or "").strip() or (
            "log_stream" if settings.deployment == "cisco_cloud" else "defenseclaw.installation"
        )
        settings.installation_id = installation_id.strip()
        if not settings.installation_id and settings.target_type == "defenseclaw.installation":
            settings.installation_id = default_installation_id()
        if not settings.installation_id:
            raise click.ClickException("--installation-id must be the enterprise Galileo log stream ID")
        settings.api_key_header = (api_key_header or "").strip() or (
            "Galileo-API-Key" if settings.deployment == "cisco_cloud" else "X-API-Key"
        )
        settings.rule_pack.enabled = enable_rule_pack
        settings.opa.enabled = manage_opa
        settings.observability.include_content = include_content
        if observability_sink is not None:
            settings.observability.sink = observability_sink.strip()
        if otel_destination is not None:
            settings.observability.otel_destination = otel_destination.strip()
        if manual_activation:
            settings.opa.activation = "manual"
            settings.rule_pack.activation = "manual"
        settings.validate()

        managed_regex = app.cfg.guardrail.regex_source in {"agent_control", "hybrid"}
        if enable_rule_pack != managed_regex:
            raise click.ClickException(
                "Agent Control rule-pack sync and guardrail.regex_source must be configured together"
            )

        override = (api_key_override or "").strip()
        server_url_resolved, resolved_api_key = resolve_agent_control_sdk_credentials(
            settings,
            app.cfg.data_dir,
            require_key=sdk is None and not override,
        )
        api_key = override or resolved_api_key
        if sdk is None:
            sdk = load_agent_control_sdk()

        controls: list[dict[str, Any]]
        try:
            sdk.init(
                agent_name=settings.agent_name,
                agent_description="DefenseClaw policy synchronization",
                server_url=server_url_resolved,
                api_key=api_key,
                api_key_header=settings.resolved_api_key_header(),
                target_type=settings.resolved_target_type(),
                target_id=settings.installation_id,
                policy_refresh_interval_seconds=settings.refresh_seconds,
                **agent_control_observability_init_kwargs(app.cfg),
            )
            snapshot = sdk.get_server_controls()
            if snapshot is None:
                raise SynchronizationError("Agent Control did not return a successful initial snapshot")
            controls = snapshot
            candidates = extract_candidates(controls)
            if require_rules and not candidates.rules:
                raise SynchronizationError("the effective Agent Control snapshot contains no DefenseClaw regex rules")
        except Exception as exc:
            detail = str(exc) if isinstance(exc, SynchronizationError) else f"{type(exc).__name__}"
            raise click.ClickException(f"Agent Control connectivity/policy validation failed ({detail})") from exc
        finally:
            try:
                sdk.shutdown()
            except Exception:
                pass

        publisher = ManagedPublisher(
            data_dir=app.cfg.data_dir,
            policy_dir=app.cfg.policy_dir,
            managed_dir=settings.managed_dir,
            opa_enabled=settings.opa.enabled,
        )
        validator = validator or NativeValidator()
        publications: list[Any] = []
        with SingleWriterLock(publisher.lock_path):
            publisher.prepare()

            # Stage and validate every enabled lane before changing either
            # active artifact. A bad rule bucket must never leave a new OPA
            # threshold file active (or vice versa).
            opa_content: bytes | None = None
            rule_content: bytes | None = None
            if settings.opa.enabled:
                opa_content = candidates.opa_artifact(settings.opa.precedence)
                opa_candidate = publisher.stage_opa(opa_content)
                validator.validate_opa(
                    rego_dir=Path(app.cfg.policy_dir),
                    candidate=opa_candidate,
                )
            if settings.rule_pack.enabled:
                rule_content = candidates.rule_pack_artifact()
                if rule_content is not None:
                    overlay_candidate = publisher.stage_rule_pack(rule_content)
                    validator.validate_rule_pack(
                        base_dirs=configured_rule_pack_base_dirs(app.cfg),
                        overlay_dir=overlay_candidate,
                        regex_source=app.cfg.guardrail.regex_source,
                    )

            try:
                if settings.opa.enabled and opa_content is not None:
                    publications.append(publisher.publish_opa(opa_content))
                if settings.rule_pack.enabled:
                    publications.append(publisher.publish_rule_pack(rule_content))

                overlay_path = str(publisher.rule_pack_root)
                overlay_norm = os.path.normpath(overlay_path.strip())
                overlays = [
                    value
                    for value in app.cfg.guardrail.rule_pack_overlay_dirs
                    if os.path.normpath(value.strip()) != overlay_norm
                ]
                if settings.rule_pack.enabled:
                    overlays.append(overlay_path)
                app.cfg.guardrail.rule_pack_overlay_dirs = overlays
                app.cfg.guardrail.validate()
                if save_config:
                    app.cfg.save()
            except Exception as exc:
                rollback_error: Exception | None = None
                for publication in reversed(publications):
                    try:
                        publisher.rollback(publication)
                    except Exception as rollback_exc:  # pragma: no cover - critical contingency
                        rollback_error = rollback_exc
                        break
                if rollback_error is not None:
                    raise PublicationError(
                        f"Agent Control setup failed ({type(exc).__name__}); artifact rollback failed"
                    ) from rollback_error
                raise

        return publisher.managed_dir
    except Exception:
        if "original_guardrail" in locals():
            app.cfg.guardrail = original_guardrail
            app.cfg.agent_control = original_agent_control
        raise


@agent_control_cmd.command("setup")
@click.option("--deployment", type=click.Choice(["cisco_cloud", "self_hosted"]), default="cisco_cloud")
@click.option("--server-url", required=True, help="Agent Control service URL")
@click.option("--installation-id", default="", help="Stable installation ID (default: defenseclaw-<hostname>)")
@click.option("--api-key-env", default="AGENT_CONTROL_API_KEY", help="Environment variable holding the API key")
@click.option(
    "--target-type",
    type=click.Choice(["log_stream", "defenseclaw.installation"]),
    default=None,
    help="Agent Control policy target (deployment default when omitted).",
)
@click.option("--api-key-header", default=None, help="API-key HTTP header (deployment default when omitted).")
@click.option("--enable-rule-pack/--no-enable-rule-pack", default=None)
@click.option(
    "--regex-source",
    type=click.Choice(["agent_control", "hybrid"]),
    default=None,
    help="Required when Agent Control rule buckets are enabled",
)
@click.option("--manage-opa/--no-manage-opa", default=None)
@click.option("--include-content/--metadata-only", default=None)
@click.option(
    "--observability-sink",
    type=click.Choice(["agent_control", "otel"]),
    default=None,
    help="Send enforcement ControlSpans to Agent Control Monitor or a named OTEL destination.",
)
@click.option("--otel-destination", default=None, help="Named DefenseClaw OTEL destination for ControlSpans.")
@click.option("--manual-activation", is_flag=True, help="Publish without reloading/restarting the gateway")
@pass_ctx
def setup_agent_control(
    app: AppContext,
    deployment: str,
    server_url: str,
    installation_id: str,
    api_key_env: str,
    target_type: str | None,
    api_key_header: str | None,
    enable_rule_pack: bool | None,
    regex_source: str | None,
    manage_opa: bool | None,
    include_content: bool | None,
    observability_sink: str | None,
    otel_destination: str | None,
    manual_activation: bool,
) -> None:
    """Configure a stable DefenseClaw installation target and managed paths."""
    original_guardrail = copy.deepcopy(app.cfg.guardrail)
    original_agent_control = copy.deepcopy(app.cfg.agent_control)
    settings = app.cfg.agent_control
    effective_rule_pack = settings.rule_pack.enabled if enable_rule_pack is None else enable_rule_pack
    if effective_rule_pack and regex_source is None:
        raise click.UsageError("--regex-source is required when Agent Control rule buckets are enabled")
    if not effective_rule_pack and regex_source is not None:
        raise click.UsageError("--regex-source requires --enable-rule-pack")
    app.cfg.guardrail.regex_source = regex_source if effective_rule_pack else "local"
    try:
        managed_dir = configure_agent_control(
            app,
            deployment=deployment,
            server_url=server_url,
            installation_id=installation_id,
            api_key_env=api_key_env,
            target_type=target_type,
            api_key_header=api_key_header,
            enable_rule_pack=effective_rule_pack,
            manage_opa=settings.opa.enabled if manage_opa is None else manage_opa,
            include_content=(settings.observability.include_content if include_content is None else include_content),
            observability_sink=observability_sink,
            otel_destination=otel_destination,
            manual_activation=manual_activation,
        )
    except Exception:
        app.cfg.guardrail = original_guardrail
        app.cfg.agent_control = original_agent_control
        raise

    click.echo("Agent Control synchronization configured.")
    click.echo(f"  agent:       {settings.agent_name}")
    click.echo(f"  target_type: {settings.resolved_target_type()}")
    click.echo(f"  deployment:    {settings.deployment}")
    click.echo(f"  server_url:    {settings.server_url}")
    click.echo(f"  target_id:     {settings.installation_id}")
    click.echo(f"  visibility:    {settings.observability.sink}")
    click.echo(f"  managed_dir:   {managed_dir}")
    click.echo("Bind the DefenseClaw controls to this exact target, then run:")
    click.echo("  defenseclaw agent-control sync --once")


@agent_control_cmd.command("sync")
@click.option("--once", "mode", flag_value="once", default=True, help="Synchronize one successful snapshot and exit")
@click.option("--watch", "mode", flag_value="watch", help="Run continuously and watch the SDK cache")
@pass_ctx
def sync_agent_control(app: AppContext, mode: str) -> None:
    """Fetch, validate, publish, and activate effective DefenseClaw controls."""
    stop_event = Event()
    previous_handlers: dict[int, Any] = {}
    if mode == "watch":
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, lambda _signum, _frame: stop_event.set())
    try:
        synchronizer = AgentControlSynchronizer(app.cfg, stop_event=stop_event, audit_logger=app.logger)
        state = synchronizer.run_watch() if mode == "watch" else synchronizer.run_once()
    except (SynchronizationError, PublicationError, ActivationError, OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
    click.echo(json.dumps(asdict(state), indent=2, sort_keys=True))


@agent_control_cmd.command("status")
@click.option("--json-output", is_flag=True, help="Emit machine-readable JSON")
@pass_ctx
def status_agent_control(app: AppContext, json_output: bool) -> None:
    """Show redacted synchronizer and active policy state."""
    publisher = ManagedPublisher(
        data_dir=app.cfg.data_dir,
        policy_dir=app.cfg.policy_dir,
        managed_dir=app.cfg.agent_control.managed_dir,
    )
    state = load_state(publisher.state_path)
    value = asdict(state)
    value["enabled"] = app.cfg.agent_control.enabled
    value["managed_dir"] = str(publisher.managed_dir)
    value.setdefault("opa_active_digest", None)
    value.setdefault("rule_pack_active_digest", None)
    if app.cfg.agent_control.installation_id:
        value["target_id_hash"] = (
            "sha256:" + hashlib.sha256(app.cfg.agent_control.installation_id.encode("utf-8")).hexdigest()
        )
    value["deployment"] = app.cfg.agent_control.deployment
    value["server_url"] = app.cfg.agent_control.server_url
    value["installation_id"] = app.cfg.agent_control.installation_id
    value["target_type"] = app.cfg.agent_control.resolved_target_type()
    value["api_key_header"] = app.cfg.agent_control.resolved_api_key_header()
    value["observability_sink"] = app.cfg.agent_control.observability.sink
    value["regex_source"] = app.cfg.guardrail.regex_source
    try:
        sdk = load_agent_control_sdk()
        value["sdk_version"] = str(getattr(sdk, "__version__", "unknown"))
        value["sdk_compatible"] = True
    except SynchronizationError:
        value["sdk_compatible"] = False
    token = app.cfg.gateway.resolved_token()
    if token:
        try:
            runtime = GatewayClient(
                bind=app.cfg.gateway.api_bind,
                port=app.cfg.gateway.api_port,
                token=token,
            ).status()
            opa_status = runtime.get("agent_control") or {}
            rule_status = runtime.get("rule_pack") or {}
            value["opa_active_digest"] = opa_status.get("artifact_digest") if opa_status.get("present") else None
            value["rule_pack_active_digest"] = (
                rule_status.get("artifact_digest") if rule_status.get("present") else None
            )
            value["runtime_status"] = "available"
            value["opa_generation"] = runtime.get("generation")
        except Exception:
            value["runtime_status"] = "unavailable"
    else:
        value["runtime_status"] = "unavailable"
    if json_output:
        click.echo(json.dumps(value, indent=2, sort_keys=True))
        return
    click.echo(f"Status:              {state.status}")
    click.echo(f"Regex source:        {value['regex_source']}")
    click.echo(f"Deployment:          {value['deployment']}")
    click.echo(f"Server:              {value['server_url'] or '-'}")
    click.echo(f"Installation:        {value['installation_id'] or '-'}")
    click.echo(f"Policy target:       {value['target_type']}")
    click.echo(f"ControlSpan sink:    {value['observability_sink']}")
    click.echo(f"SDK compatible:      {value['sdk_compatible']}")
    click.echo(f"Gateway readback:    {value['runtime_status']}")
    click.echo(f"Snapshot:            {state.snapshot_state} (freshness: {state.snapshot_freshness})")
    click.echo(f"OPA published/active: {state.opa_published_digest or '-'} / {value['opa_active_digest'] or '-'}")
    click.echo(
        f"Rules published/active: {state.rule_pack_published_digest or '-'} / {value['rule_pack_active_digest'] or '-'}"
    )
    click.echo(
        "Enforcement visibility: "
        f"{state.observability_status} "
        f"(sent={state.observability_sent_events}, dropped={state.observability_dropped_events}, "
        f"unmapped={state.observability_unmapped_records})"
    )
    if state.rule_pack_pending_restart:
        click.echo("Rule activation:      pending gateway restart")
        click.echo("Operator command:     defenseclaw-gateway restart")
    if state.last_error:
        click.echo(f"Last error:          {state.last_error}")
    if state.observability_last_error:
        click.echo(f"Visibility error:    {state.observability_last_error}")


@agent_control_cmd.command("validate")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@pass_ctx
def validate_agent_control(app: AppContext, path: Path) -> None:
    """Validate an Agent Control effective snapshot JSON file without writes."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, list):
            raise ValueError("validation input must be a get_server_controls() JSON list")
        candidates = extract_candidates(value)
        if not app.cfg.policy_dir:
            raise ValueError("policy_dir is required for native Agent Control validation")
        validator = NativeValidator()
        with tempfile.TemporaryDirectory(prefix="defenseclaw-agent-control-validate-") as tmp:
            candidate = Path(tmp) / "data-agent-control.json"
            candidate.write_bytes(candidates.opa_artifact(app.cfg.agent_control.opa.precedence))
            candidate.chmod(0o600)
            validator.validate_opa(rego_dir=Path(app.cfg.policy_dir), candidate=candidate)

            rule_content = candidates.rule_pack_artifact()
            if rule_content is not None:
                overlay = Path(tmp) / "rule-pack"
                rules = overlay / "rules"
                rules.mkdir(parents=True, mode=0o700)
                rule_file = rules / "agent-control.yaml"
                rule_file.write_bytes(rule_content)
                rule_file.chmod(0o600)
                validator.validate_rule_pack(
                    base_dirs=configured_rule_pack_base_dirs(app.cfg),
                    overlay_dir=overlay,
                )
    except (PublicationError, OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        json.dumps(
            {
                "status": "valid",
                "matching_controls": candidates.matching_controls,
                "ignored_controls": candidates.ignored_controls,
                "opa_source_digest": candidates.opa_source_digest,
                "rule_pack_source_digest": candidates.rule_pack_source_digest,
                "rules": len(candidates.rules),
            },
            indent=2,
            sort_keys=True,
        )
    )
