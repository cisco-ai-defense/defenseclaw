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

import hashlib
import json
import signal
import tempfile
import uuid
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
)
from defenseclaw.agent_control.state import load_state
from defenseclaw.agent_control.sync import (
    AgentControlSynchronizer,
    SynchronizationError,
    configured_rule_pack_base_dirs,
    load_agent_control_sdk,
)
from defenseclaw.context import AppContext, pass_ctx


@click.group(name="agent-control")
def agent_control_cmd() -> None:
    """Synchronize Agent Control policy into local DefenseClaw enforcement."""


@agent_control_cmd.command("setup")
@click.option("--target-id", default="", help="Stable Agent Control target ID (default: generate UUID)")
@click.option("--enable-rule-pack/--no-enable-rule-pack", default=None)
@click.option("--manual-activation", is_flag=True, help="Publish without reloading/restarting the gateway")
@pass_ctx
def setup_agent_control(
    app: AppContext,
    target_id: str,
    enable_rule_pack: bool | None,
    manual_activation: bool,
) -> None:
    """Configure a stable DefenseClaw installation target and managed paths."""
    try:
        sdk = load_agent_control_sdk()
    except SynchronizationError as exc:
        raise click.ClickException(str(exc)) from exc
    if not app.cfg.policy_dir:
        raise click.ClickException("policy_dir must be configured before Agent Control setup")

    settings = app.cfg.agent_control
    settings.target_id = target_id.strip() or settings.target_id.strip() or str(uuid.uuid4())
    settings.enabled = True
    if enable_rule_pack is not None:
        settings.rule_pack.enabled = enable_rule_pack
    if manual_activation:
        settings.opa.activation = "manual"
        settings.rule_pack.activation = "manual"
    settings.validate()

    try:
        sdk.init(
            agent_name=settings.agent_name,
            agent_description="DefenseClaw policy synchronization",
            target_type=settings.target_type,
            target_id=settings.target_id,
            policy_refresh_interval_seconds=settings.refresh_seconds,
        )
        if sdk.get_server_controls() is None:
            raise RuntimeError("Agent Control did not return a successful initial snapshot")
    except Exception as exc:
        raise click.ClickException(
            f"Agent Control connectivity validation failed ({type(exc).__name__})"
        ) from exc
    finally:
        try:
            sdk.shutdown()
        except Exception:
            pass

    publisher = ManagedPublisher(
        data_dir=app.cfg.data_dir,
        policy_dir=app.cfg.policy_dir,
        managed_dir=settings.managed_dir,
    )
    publisher.prepare()
    disabled = extract_candidates([]).opa_artifact(settings.opa.precedence)
    if publisher.active_digest(publisher.opa_active_path) is None:
        publisher.publish_opa(disabled)
    overlay_path = str(publisher.rule_pack_root)
    overlays = list(app.cfg.guardrail.rule_pack_overlay_dirs)
    if settings.rule_pack.enabled and overlay_path not in overlays:
        overlays.append(overlay_path)
    if not settings.rule_pack.enabled:
        overlays = [value for value in overlays if value != overlay_path]
    app.cfg.guardrail.rule_pack_overlay_dirs = overlays
    app.cfg.save()

    click.echo("Agent Control synchronization configured.")
    click.echo(f"  agent:       {settings.agent_name}")
    click.echo(f"  target_type: {settings.target_type}")
    click.echo(f"  target_id:   {settings.target_id}")
    click.echo(f"  managed_dir: {publisher.managed_dir}")
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
    if app.cfg.agent_control.target_id:
        value["target_id_hash"] = "sha256:" + hashlib.sha256(
            app.cfg.agent_control.target_id.encode("utf-8")
        ).hexdigest()
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
            value["opa_active_digest"] = (
                opa_status.get("artifact_digest") if opa_status.get("present") else None
            )
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
    click.echo(f"SDK compatible:      {value['sdk_compatible']}")
    click.echo(f"Gateway readback:    {value['runtime_status']}")
    click.echo(f"Snapshot:            {state.snapshot_state} (freshness: {state.snapshot_freshness})")
    click.echo(f"OPA published/active: {state.opa_published_digest or '-'} / {value['opa_active_digest'] or '-'}")
    click.echo(
        f"Rules published/active: {state.rule_pack_published_digest or '-'} / "
        f"{value['rule_pack_active_digest'] or '-'}"
    )
    if state.rule_pack_pending_restart:
        click.echo("Rule activation:      pending gateway restart")
        click.echo("Operator command:     defenseclaw-gateway restart")
    if state.last_error:
        click.echo(f"Last error:          {state.last_error}")


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
