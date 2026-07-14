"""Agent Control SDK lifecycle and DefenseClaw policy synchronization."""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from threading import Event
from typing import Any, Protocol
from urllib.parse import urlsplit

from defenseclaw.audit_actions import (
    ACTION_AGENT_CONTROL_ACTIVATE,
    ACTION_AGENT_CONTROL_PUBLISH,
    ACTION_AGENT_CONTROL_ROLLBACK,
    ACTION_AGENT_CONTROL_SYNC,
)

from .coordinated_otel import CoordinatedOTELTraceWriter
from .models import (
    OPA_EVALUATOR,
    RULE_PACK_EVALUATOR,
    CandidateSet,
    ControlValidationError,
    digest_bytes,
    extract_lane_candidates,
    snapshot_counts,
)
from .observability import EnforcementEventBridge
from .publisher import (
    ActivationError,
    GatewayClient,
    ManagedPublisher,
    NativeValidator,
    PublicationError,
    PublishedArtifact,
    RollbackDivergenceError,
    SingleWriterLock,
)
from .state import SyncState, load_state, save_state, utc_now

logger = logging.getLogger(__name__)

_ENV_REFERENCE_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class SynchronizationError(RuntimeError):
    pass


class AgentControlSDK(Protocol):
    __version__: str

    def init(self, **kwargs: Any) -> Any: ...

    def get_server_controls(self) -> list[dict[str, Any]] | None: ...

    def write_events(self, events: Any) -> Any: ...

    def shutdown(self) -> None: ...


def load_agent_control_sdk() -> AgentControlSDK:
    if sys.version_info < (3, 12):
        raise SynchronizationError("Agent Control integration requires Python 3.12 or newer")
    try:
        import agent_control
    except ImportError as exc:
        raise SynchronizationError("Agent Control SDK is not installed; install defenseclaw[agent-control]") from exc
    return agent_control


def resolve_agent_control_sdk_credentials(settings: Any, data_dir: str, *, require_key: bool = True) -> tuple[str, str]:
    """Resolve explicit SDK connection kwargs from config + the secret store."""
    from defenseclaw.credentials import resolve

    settings.validate()
    credential = resolve(settings.api_key_env, data_dir)
    if require_key and not credential.is_set:
        raise SynchronizationError(
            f"Agent Control credential ${settings.api_key_env} is not set; "
            f"run 'defenseclaw keys set {settings.api_key_env}'"
        )
    return settings.server_url.rstrip("/"), credential.value


def agent_control_observability_init_kwargs(cfg: Any) -> dict[str, Any]:
    """Build secret-safe SDK observability options from DefenseClaw config.

    The normal ``agent_control`` sink preserves Agent Control Monitor delivery.
    The ``otel`` sink reuses one named DefenseClaw OTLP destination, resolving
    its environment references in memory so credentials never enter the Agent
    Control configuration block.
    """
    settings = cfg.agent_control.observability
    if not settings.enabled:
        return {"observability_enabled": False}
    if settings.sink == "agent_control":
        return {"observability_enabled": True}

    destination = next(
        (item for item in cfg.otel.destinations if item.name == settings.otel_destination),
        None,
    )
    if destination is None:
        raise SynchronizationError(
            f"Agent Control OTEL destination {settings.otel_destination!r} is not configured; "
            "run 'defenseclaw setup galileo' first"
        )
    if not cfg.otel.enabled or not destination.enabled or not destination.traces.enabled:
        raise SynchronizationError(
            f"Agent Control OTEL destination {settings.otel_destination!r} must have trace export enabled"
        )
    protocol = (destination.traces.protocol or destination.protocol).strip().lower()
    if protocol != "http":
        raise SynchronizationError("Agent Control ControlSpan export requires an OTLP HTTP destination")

    endpoint = (destination.traces.endpoint or destination.endpoint).strip()
    url_path = destination.traces.url_path.strip()
    if url_path:
        endpoint = endpoint.rstrip("/") + "/" + url_path.lstrip("/")
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise SynchronizationError("Agent Control OTEL endpoint must be an absolute HTTPS URL without credentials")

    from defenseclaw.credentials import resolve

    headers: dict[str, str] = {}
    for name, raw_value in destination.headers.items():
        value = str(raw_value)

        def replace_secret(match: re.Match[str]) -> str:
            env_name = match.group(1)
            credential = resolve(env_name, cfg.data_dir)
            if not credential.is_set:
                raise SynchronizationError(
                    f"Agent Control OTEL credential ${env_name} is not set; run 'defenseclaw keys set {env_name}'"
                )
            return credential.value

        value = _ENV_REFERENCE_RE.sub(replace_secret, value)
        if "\r" in value or "\n" in value:
            raise SynchronizationError(f"Agent Control OTEL header {name!r} contains a newline")
        headers[str(name)] = value

    if not any(name.lower() == "galileo-api-key" for name in headers):
        raise SynchronizationError("Agent Control OTEL destination is missing the Galileo-API-Key header")
    if not any(name.lower() in {"project", "projectid"} for name in headers):
        raise SynchronizationError("Agent Control OTEL destination is missing a Galileo project routing header")
    if not any(name.lower() in {"logstream", "logstreamid"} for name in headers):
        raise SynchronizationError("Agent Control OTEL destination is missing a Galileo log stream routing header")

    return {
        "observability_enabled": True,
        "observability_sink_name": "otel",
        "observability_sink_config": {
            "enabled": True,
            "endpoint": endpoint,
            "headers": headers,
            "service_name": cfg.agent_control.agent_name,
        },
    }


class AgentControlSynchronizer:
    def __init__(
        self,
        cfg: Any,
        *,
        sdk: AgentControlSDK | None = None,
        publisher: ManagedPublisher | None = None,
        gateway: GatewayClient | None = None,
        validator: NativeValidator | None = None,
        stop_event: Event | None = None,
        audit_logger: Any | None = None,
    ) -> None:
        self.cfg = cfg
        self.settings = cfg.agent_control
        self.settings.validate()
        if not self.settings.enabled:
            raise SynchronizationError("Agent Control integration is disabled")
        if self.settings.opa.enabled and not cfg.policy_dir:
            raise SynchronizationError("policy_dir is required for Agent Control OPA synchronization")
        self.sdk_server_url, self.sdk_api_key = resolve_agent_control_sdk_credentials(
            self.settings,
            cfg.data_dir,
            require_key=sdk is None,
        )
        self.sdk = sdk or load_agent_control_sdk()
        self.publisher = publisher or ManagedPublisher(
            data_dir=cfg.data_dir,
            policy_dir=cfg.policy_dir,
            managed_dir=self.settings.managed_dir,
            opa_enabled=self.settings.opa.enabled,
        )
        if gateway is None:
            token = cfg.gateway.resolved_token()
            requires_activation = (self.settings.opa.enabled and self.settings.opa.activation == "reload") or (
                self.settings.rule_pack.enabled and self.settings.rule_pack.activation == "restart"
            )
            if requires_activation and not token:
                raise SynchronizationError("a DefenseClaw gateway token is required for automatic activation")
            gateway = GatewayClient(
                bind=cfg.gateway.api_bind,
                port=cfg.gateway.api_port,
                token=token,
            )
        self.gateway = gateway
        self.validator = validator or NativeValidator()
        self.stop_event = stop_event or Event()
        self.audit_logger = audit_logger
        self.state = load_state(self.publisher.state_path)
        self.state.agent_name = self.settings.agent_name
        self.state.target_type = self.settings.resolved_target_type()
        self.state.target_id_hash = (
            "sha256:" + hashlib.sha256(self.settings.installation_id.encode("utf-8")).hexdigest()
        )
        self.state.sdk_version = str(getattr(self.sdk, "__version__", "unknown"))
        self.event_bridge: EnforcementEventBridge | None = None
        if self.settings.observability.enabled:
            event_log_path = Path(cfg.data_dir) / "gateway.jsonl"
            if self.settings.observability.include_content and cfg.privacy.disable_redaction:
                event_log_path = Path(cfg.data_dir) / "agent-control" / "gateway-events-unredacted.jsonl"
            try:
                trace_writer = None
                if self.settings.observability.sink == "otel":
                    sink_config = agent_control_observability_init_kwargs(cfg)["observability_sink_config"]
                    trace_writer = CoordinatedOTELTraceWriter(
                        endpoint=sink_config["endpoint"],
                        headers=sink_config["headers"],
                        service_name=sink_config["service_name"],
                    )
                self.event_bridge = EnforcementEventBridge(
                    event_log_path=event_log_path,
                    agent_name=self.settings.agent_name,
                    sdk=self.sdk,
                    state=self.state,
                    include_content=self.settings.observability.include_content,
                    trace_writer=trace_writer,
                )
                self.state.observability_status = "waiting_for_log"
                self.state.observability_last_error = None
            except Exception as exc:
                error_type = type(exc).__name__
                logger.warning("Agent Control observability bridge init failed (%s)", error_type)
                self.state.observability_status = "degraded"
                self.state.observability_last_error = f"observability bridge initialization failed ({error_type})"
        else:
            self.state.observability_status = "disabled"
        if self.settings.opa.enabled and self.settings.opa.precedence == "remote":
            logger.warning(
                "Agent Control OPA precedence is remote; central policy may weaken local thresholds or trust"
            )

    def run_once(self) -> SyncState:
        self.publisher.prepare()
        with SingleWriterLock(self.publisher.lock_path):
            try:
                controls = self._initialize_until_snapshot(
                    deadline=time.monotonic() + self.settings.init_retry_max_seconds
                )
                self._reconcile_state()
                self.process_snapshot(controls)
                self._update_observability_controls(controls)
                self._poll_observability()
                return self.state
            finally:
                self._shutdown_sdk()

    def run_watch(self) -> SyncState:
        self.publisher.prepare()
        with SingleWriterLock(self.publisher.lock_path):
            try:
                controls = self._initialize_until_snapshot(deadline=None)
                self._reconcile_state()
                last_projection: tuple[str, str, str] | None = None
                failed_projection: tuple[str, str, str] | None = None
                failure_attempts = 0
                retry_not_before = 0.0
                while True:
                    try:
                        projection = self._projection_identity(controls)
                        if projection != last_projection:
                            now = time.monotonic()
                            if projection != failed_projection:
                                failed_projection = projection
                                failure_attempts = 0
                                retry_not_before = 0.0
                            if now >= retry_not_before:
                                self.process_snapshot(controls)
                                self._update_observability_controls(controls)
                                last_projection = projection
                                failed_projection = None
                                failure_attempts = 0
                                retry_not_before = 0.0
                    except (ControlValidationError, PublicationError, ActivationError, SynchronizationError) as exc:
                        failure_attempts += 1
                        delay = _watch_retry_delay(
                            failure_attempts,
                            poll_seconds=self.settings.cache_poll_seconds,
                            cap_seconds=self.settings.init_retry_max_seconds,
                        )
                        retry_not_before = time.monotonic() + delay
                        self._record_error(exc)
                        logger.error(
                            "Agent Control policy synchronization failed; unchanged snapshot retry in %.1fs: %s",
                            delay,
                            self.state.last_error,
                        )

                    self._poll_observability()
                    if self.stop_event.wait(self.settings.cache_poll_seconds):
                        self._poll_observability()
                        break
                    try:
                        cached = self.sdk.get_server_controls()
                    except Exception as exc:
                        error = SynchronizationError(f"Agent Control SDK cache read failed ({type(exc).__name__})")
                        self._record_error(error)
                        logger.error("Agent Control policy synchronization failed: %s", self.state.last_error)
                        continue
                    if cached is not None:
                        controls = cached
                return self.state
            finally:
                self._shutdown_sdk()

    def process_snapshot(self, controls: list[dict[str, Any]]) -> SyncState:
        previous_snapshot_state = self.state.snapshot_state
        previous_sources = (self.state.opa_source_digest, self.state.rule_pack_source_digest)
        try:
            matching_controls, ignored_controls = snapshot_counts(controls)
        except ControlValidationError as exc:
            self._record_error(exc)
            raise

        self.state.snapshot_state = "nonempty" if matching_controls else "empty"
        self.state.snapshot_freshness = "not_exposed_by_sdk"
        self.state.matching_controls = matching_controls
        self.state.ignored_controls = ignored_controls
        self.state.last_observed_at = utc_now()
        lane_errors: list[str] = []
        rollback_diverged = False

        if self.settings.opa.enabled:
            try:
                self._apply_opa(extract_lane_candidates(controls, OPA_EVALUATOR))
            except (ControlValidationError, PublicationError, ActivationError, OSError) as exc:
                lane_errors.append(f"opa: {exc}")
                rollback_diverged = rollback_diverged or isinstance(exc, RollbackDivergenceError)
        if self.settings.rule_pack.enabled:
            try:
                self._apply_rule_pack(extract_lane_candidates(controls, RULE_PACK_EVALUATOR))
            except (ControlValidationError, PublicationError, ActivationError, OSError) as exc:
                lane_errors.append(f"rule_pack: {exc}")
                rollback_diverged = rollback_diverged or isinstance(exc, RollbackDivergenceError)

        if lane_errors:
            self._audit(ACTION_AGENT_CONTROL_SYNC, "snapshot-rejected", None)
            error_type = RollbackDivergenceError if rollback_diverged else SynchronizationError
            error = error_type("; ".join(lane_errors))
            self._record_error(error)
            raise error

        if previous_snapshot_state != self.state.snapshot_state or previous_sources != (
            self.state.opa_source_digest,
            self.state.rule_pack_source_digest,
        ):
            self._audit(ACTION_AGENT_CONTROL_SYNC, "snapshot", None)

        self.state.status = "active"
        opa_pending = (
            self.settings.opa.enabled
            and self.settings.opa.activation == "manual"
            and self.state.opa_published_digest != self.state.opa_active_digest
        )
        rule_pending = (
            self.settings.rule_pack.enabled
            and self.settings.rule_pack.activation == "manual"
            and self.state.rule_pack_published_digest != self.state.rule_pack_active_digest
        )
        self.state.rule_pack_pending_restart = rule_pending
        if opa_pending or rule_pending:
            self.state.status = "published_pending_activation"
        self.state.last_error = None
        save_state(self.publisher.state_path, self.state)
        return self.state

    def _apply_opa(self, candidates: CandidateSet) -> None:
        previous_source_digest = self.state.opa_source_digest
        previous_published_digest = self.state.opa_published_digest
        previous_last_published_at = self.state.last_published_at
        content = candidates.opa_artifact(self.settings.opa.precedence)
        artifact_digest = digest_bytes(content)
        self.state.opa_source_digest = candidates.opa_source_digest
        current_digest = (
            self.state.opa_published_digest
            if self.settings.opa.activation == "manual"
            else self.state.opa_active_digest
        )
        if current_digest == artifact_digest:
            return

        candidate_path = self.publisher.stage_opa(content)
        self.validator.validate_opa(rego_dir=Path(self.cfg.policy_dir), candidate=candidate_path)
        publication = self.publisher.publish_opa(content)
        self.state.opa_published_digest = artifact_digest
        self.state.last_published_at = utc_now()
        self._persist_publication(
            publication,
            lane="opa",
            previous_source_digest=previous_source_digest,
            previous_published_digest=previous_published_digest,
            previous_last_published_at=previous_last_published_at,
        )
        self._audit(ACTION_AGENT_CONTROL_PUBLISH, "opa", artifact_digest)
        if self.settings.opa.activation == "manual":
            return

        try:
            self.gateway.reload_opa(artifact_digest)
        except Exception as activation_error:
            self.publisher.rollback(publication)
            previous_digest = (
                digest_bytes(publication.previous)
                if publication.previous_existed and publication.previous is not None
                else None
            )
            self.state.opa_published_digest = previous_digest
            try:
                self.gateway.reload_opa(previous_digest)
            except Exception as rollback_error:
                raise RollbackDivergenceError(
                    f"OPA activation failed ({activation_error}); rollback verification failed ({rollback_error})"
                ) from rollback_error
            self.state.opa_active_digest = previous_digest
            self._audit(ACTION_AGENT_CONTROL_ROLLBACK, "opa", previous_digest)
            raise ActivationError(
                f"OPA activation failed and LKG was restored: {activation_error}"
            ) from activation_error

        self.state.opa_active_digest = artifact_digest
        self.state.last_activated_at = utc_now()
        self._audit(ACTION_AGENT_CONTROL_ACTIVATE, "opa", artifact_digest)

    def _apply_rule_pack(self, candidates: CandidateSet) -> None:
        previous_source_digest = self.state.rule_pack_source_digest
        previous_published_digest = self.state.rule_pack_published_digest
        previous_last_published_at = self.state.last_published_at
        if len(candidates.rules) > self.settings.rule_pack.max_rules:
            raise PublicationError(
                f"rule-pack candidate exceeds configured max_rules={self.settings.rule_pack.max_rules}"
            )
        content = candidates.rule_pack_artifact()
        artifact_digest = digest_bytes(content) if content is not None else None
        self.state.rule_pack_source_digest = candidates.rule_pack_source_digest
        current_digest = (
            self.state.rule_pack_published_digest
            if self.settings.rule_pack.activation == "manual"
            else self.state.rule_pack_active_digest
        )
        if current_digest == artifact_digest:
            return

        if self.settings.rule_pack.activation == "restart":
            self.gateway.ensure_restart_supported()

        if content is not None:
            overlay_dir = self.publisher.stage_rule_pack(content)
            self.validator.validate_rule_pack(
                base_dirs=self._rule_pack_base_dirs(),
                overlay_dir=overlay_dir,
                regex_source=self.cfg.guardrail.regex_source,
            )
        publication = self.publisher.publish_rule_pack(content)
        self.state.rule_pack_published_digest = artifact_digest
        self.state.last_published_at = utc_now()
        if self.settings.rule_pack.activation == "manual":
            self.state.rule_pack_pending_restart = True
        self._persist_publication(
            publication,
            lane="rule_pack",
            previous_source_digest=previous_source_digest,
            previous_published_digest=previous_published_digest,
            previous_last_published_at=previous_last_published_at,
        )
        self._audit(ACTION_AGENT_CONTROL_PUBLISH, "rule_pack", artifact_digest)
        if self.settings.rule_pack.activation == "manual":
            return

        try:
            self.gateway.restart_and_verify_rule_pack(artifact_digest)
        except Exception as activation_error:
            self.publisher.rollback(publication)
            previous_digest = (
                digest_bytes(publication.previous)
                if publication.previous_existed and publication.previous is not None
                else None
            )
            self.state.rule_pack_published_digest = previous_digest
            try:
                self.gateway.restart_and_verify_rule_pack(previous_digest)
            except Exception as rollback_error:
                raise RollbackDivergenceError(
                    f"rule-pack activation failed ({activation_error}); rollback verification failed ({rollback_error})"
                ) from rollback_error
            self.state.rule_pack_active_digest = previous_digest
            self.state.rule_pack_pending_restart = False
            self._audit(ACTION_AGENT_CONTROL_ROLLBACK, "rule_pack", previous_digest)
            raise ActivationError(
                f"rule-pack activation failed and LKG was restored: {activation_error}"
            ) from activation_error

        self.state.rule_pack_active_digest = artifact_digest
        self.state.rule_pack_pending_restart = False
        self.state.last_activated_at = utc_now()
        self._audit(ACTION_AGENT_CONTROL_ACTIVATE, "rule_pack", artifact_digest)

    def _persist_publication(
        self,
        publication: PublishedArtifact,
        *,
        lane: str,
        previous_source_digest: str | None,
        previous_published_digest: str | None,
        previous_last_published_at: str | None,
    ) -> None:
        try:
            save_state(self.publisher.state_path, self.state)
        except OSError as exc:
            try:
                self.publisher.rollback(publication)
            except (PublicationError, RollbackDivergenceError) as rollback_error:
                raise RollbackDivergenceError(
                    f"{lane} state persistence failed ({exc}); publication rollback failed ({rollback_error})"
                ) from rollback_error
            setattr(self.state, f"{lane}_source_digest", previous_source_digest)
            setattr(self.state, f"{lane}_published_digest", previous_published_digest)
            self.state.last_published_at = previous_last_published_at
            if lane == "rule_pack":
                self.state.rule_pack_pending_restart = False
            raise PublicationError(f"{lane} state persistence failed; publication was rolled back") from exc

    def _initialize_until_snapshot(self, *, deadline: float | None) -> list[dict[str, Any]]:
        delay = 1.0
        while not self.stop_event.is_set():
            try:
                self.sdk.init(
                    agent_name=self.settings.agent_name,
                    agent_description="DefenseClaw policy synchronization",
                    server_url=self.sdk_server_url,
                    api_key=self.sdk_api_key,
                    api_key_header=self.settings.resolved_api_key_header(),
                    target_type=self.settings.resolved_target_type(),
                    target_id=self.settings.installation_id,
                    policy_refresh_interval_seconds=self.settings.refresh_seconds,
                    **agent_control_observability_init_kwargs(self.cfg),
                )
                controls = self.sdk.get_server_controls()
                if controls is not None:
                    return controls
                error: Exception = SynchronizationError("Agent Control initialization returned no snapshot")
            except Exception as exc:
                error = exc
            self._record_error(error)
            self._shutdown_sdk()
            if deadline is not None and time.monotonic() >= deadline:
                break
            wait_for = min(delay, float(self.settings.init_retry_max_seconds))
            wait_for += random.uniform(0, min(1.0, wait_for * 0.1))
            if deadline is not None:
                wait_for = min(wait_for, max(0.0, deadline - time.monotonic()))
                if wait_for <= 0:
                    break
            if self.stop_event.wait(wait_for):
                break
            delay = min(delay * 2, float(self.settings.init_retry_max_seconds))
        raise SynchronizationError("stopped before Agent Control produced a successful snapshot")

    def _projection_identity(self, controls: list[dict[str, Any]]) -> tuple[str, str, str]:
        payload = json.dumps(controls, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=repr)
        return (hashlib.sha256(payload.encode("utf-8")).hexdigest(), "", self.settings.opa.precedence)

    def _rule_pack_base_dirs(self) -> list[Path]:
        return configured_rule_pack_base_dirs(self.cfg)

    def _reconcile_state(self) -> None:
        """Rebuild diagnostic state from disk and authoritative runtime readback."""
        paths: list[tuple[Path, str]] = []
        if self.settings.opa.enabled:
            paths.append((self.publisher.opa_active_path, "opa_published_digest"))
        if self.settings.rule_pack.enabled:
            paths.append((self.publisher.rule_pack_active_path, "rule_pack_published_digest"))
        for path, attribute in paths:
            setattr(self.state, attribute, self.publisher.active_digest(path))
        try:
            status = self.gateway.status()
        except (AttributeError, ActivationError, OSError):
            return
        opa = status.get("agent_control") or {}
        rules = status.get("rule_pack") or {}
        self.state.opa_active_digest = opa.get("artifact_digest") if opa.get("present") else None
        self.state.rule_pack_active_digest = rules.get("artifact_digest") if rules.get("present") else None

    def _record_error(self, error: Exception) -> None:
        self.state.status = (
            "critical_disk_runtime_divergence" if isinstance(error, RollbackDivergenceError) else "error_lkg_preserved"
        )
        safe = _safe_error(error, extra_secrets=(self.sdk_api_key,))
        if self.settings.installation_id:
            safe = safe.replace(self.settings.installation_id, "<installation-id-redacted>")
        self.state.last_error = safe
        save_state(self.publisher.state_path, self.state)

    def _shutdown_sdk(self) -> None:
        try:
            self.sdk.shutdown()
        except Exception as exc:
            logger.error("Agent Control SDK shutdown failed (%s)", type(exc).__name__)

    def _update_observability_controls(self, controls: list[dict[str, Any]]) -> None:
        if self.event_bridge is None:
            return
        self.event_bridge.update_controls(controls if self.settings.rule_pack.enabled else [])

    def _poll_observability(self) -> None:
        if self.event_bridge is None:
            return
        if self.event_bridge.poll():
            try:
                save_state(self.publisher.state_path, self.state)
            except OSError as exc:
                logger.error("Agent Control observability cursor persistence failed (%s)", type(exc).__name__)

    def _audit(self, action: str, lane: str, digest: str | None) -> None:
        if self.audit_logger is None:
            return
        details = f"lane={lane}"
        if digest:
            details += f" digest={digest}"
        try:
            self.audit_logger.log_action(action, self.state.target_id_hash or "target:redacted", details)
        except Exception:
            logger.exception("Agent Control audit event failed")


def _safe_error(error: Exception, *, extra_secrets: Sequence[str] = ()) -> str:
    message = str(error).replace("\r", " ").replace("\n", " ")
    for secret_name in (
        "AGENT_CONTROL_API_KEY",
        "DEFENSECLAW_GATEWAY_TOKEN",
        "OPENCLAW_GATEWAY_TOKEN",
    ):
        import os

        secret = os.getenv(secret_name, "")
        if secret:
            message = message.replace(secret, "<redacted>")
    for secret in extra_secrets:
        if secret:
            message = message.replace(secret, "<redacted>")
    return message[:1000]


def _watch_retry_delay(attempt: int, *, poll_seconds: int, cap_seconds: int) -> float:
    """Return capped exponential retry delay with bounded jitter."""
    base = max(1.0, float(poll_seconds))
    cap = max(base, float(cap_seconds))
    delay = min(cap, base * (2 ** min(max(0, attempt - 1), 16)))
    return min(cap, delay + random.uniform(0, min(1.0, delay * 0.1)))


def configured_rule_pack_base_dirs(cfg: Any) -> list[Path]:
    """Return every base profile a global overlay can be applied after."""
    values = [cfg.guardrail.rule_pack_dir]
    values.extend(cfg.guardrail.effective_rule_pack_dir(name) for name in cfg.guardrail.connectors)

    application = cfg.application_protection
    app_default = application.guardrail.rule_pack_dir or cfg.guardrail.rule_pack_dir
    values.append(app_default)
    for entry in application.connectors.values():
        values.append(entry.guardrail.rule_pack_dir or app_default)

    unique: list[Path] = []
    seen: set[str] = set()
    for value in values:
        if not value:
            continue
        normalized = str(Path(value).expanduser())
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append(Path(normalized))
    return unique
