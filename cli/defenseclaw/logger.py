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

"""Python CLI handoff to the process-owned Observability v8 runtime.

This module is deliberately transport-only. It does not write audit tables,
forward directly to Splunk, choose destinations, or redact producer data. The
running gateway owns collection, generated-family validation, mandatory-floor
handling, local persistence, route-specific redaction, and destination fanout.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Mapping
from typing import Any, Protocol

import requests
from urllib3.exceptions import NewConnectionError

from defenseclaw.gateway import OrchestratorClient
from defenseclaw.models import ScanResult


class CanonicalObservabilityError(RuntimeError):
    """The CLI could not confirm canonical v8 admission."""


class CanonicalObservabilityUnavailableError(CanonicalObservabilityError):
    """The canonical v8 runtime is absent or cannot be reached."""


class _CanonicalRecorder(Protocol):
    def emit_cli_observability(self, payload: Mapping[str, Any]) -> None: ...

    def close(self) -> None: ...


class _GatewayConfigRecorder:
    """Resolve mutable gateway access only when a fact is emitted."""

    def __init__(self, cfg: Any) -> None:
        self._cfg = cfg
        self._runtime_token: str | None = None

    def emit_cli_observability(self, payload: Mapping[str, Any]) -> None:
        gateway = getattr(self._cfg, "gateway", None)
        if gateway is None:
            raise CanonicalObservabilityUnavailableError("gateway configuration is unavailable")
        token_resolver = getattr(gateway, "resolved_token", None)
        token = self._runtime_token or (token_resolver() if callable(token_resolver) else "")
        if not token:
            # A first gateway start may create the canonical token after this
            # CLI process loaded config (for example: init --no-start-gateway,
            # then setup <connector> --restart). Refresh the installation
            # dotenv once at emission time so the command can authenticate its
            # final canonical audit fact without requiring a second invocation.
            data_dir = str(getattr(self._cfg, "data_dir", "") or "")
            if data_dir:
                from defenseclaw.config import _load_dotenv_into_os

                _load_dotenv_into_os(data_dir)
                token = token_resolver() if callable(token_resolver) else ""
        if not token:
            raise CanonicalObservabilityUnavailableError(
                "gateway authentication is unavailable"
            )

        try:
            self._emit_with_token(payload, gateway, token)
        except requests.HTTPError as exc:
            # A gateway restart can create or replace the canonical token after
            # this process loaded .env.  Existing environment variables are
            # intentionally not overwritten by the general dotenv loader, so
            # resolved_token() can still return the old value here.  A 401
            # proves the rejected request was not admitted and is therefore
            # the one server response that is safe to retry. Read the current
            # installation-owned token and retry exactly once; every other
            # rejection remains fail-closed.
            if not _is_authentication_rejection(exc):
                raise
            refreshed = _refreshed_gateway_token(self._cfg, gateway, token)
            if not refreshed:
                raise
            self._emit_with_token(payload, gateway, refreshed)
            self._runtime_token = refreshed

    def _emit_with_token(
        self,
        payload: Mapping[str, Any],
        gateway: Any,
        token: str,
    ) -> None:
        client = OrchestratorClient(
            host=_gateway_api_host(self._cfg),
            port=int(getattr(gateway, "api_port", 18970)),
            timeout=10,
            token=token,
        )
        try:
            client.emit_cli_observability(payload)
        except requests.RequestException as exc:
            if _is_definite_preconnect_failure(exc):
                raise CanonicalObservabilityUnavailableError(
                    "canonical Observability v8 runtime is unavailable"
                ) from exc
            raise
        finally:
            client.close()

    def close(self) -> None:
        return


def _is_authentication_rejection(exc: requests.HTTPError) -> bool:
    response = getattr(exc, "response", None)
    return response is not None and response.status_code == 401


def _refreshed_gateway_token(cfg: Any, gateway: Any, rejected_token: str) -> str:
    """Return a newly persisted canonical token after a confirmed HTTP 401.

    Custom ``gateway.token_env`` values remain authoritative: silently
    switching those to the default dotenv key would violate explicit operator
    intent. The built-in canonical and legacy names may legitimately become
    stale during first boot or an upgrade handoff, so those can recover from
    the current installation's private dotenv.
    """

    token_env = str(getattr(gateway, "token_env", "") or "").strip()
    if token_env not in {
        "",
        "DEFENSECLAW_GATEWAY_TOKEN",
        "OPENCLAW_GATEWAY_TOKEN",
    }:
        return ""
    data_dir = str(getattr(cfg, "data_dir", "") or "")
    refreshed = _gateway_token_from_dotenv(data_dir, token_env=token_env)
    if not refreshed or secrets.compare_digest(
        refreshed.encode("utf-8"),
        rejected_token.encode("utf-8"),
    ):
        return ""
    return refreshed


def _gateway_token_from_dotenv(data_dir: str, *, token_env: str) -> str:
    """Read the selected built-in gateway token from one installation.

    An empty selector follows :meth:`GatewayConfig.resolved_token` precedence:
    canonical DefenseClaw first, then the legacy OpenClaw name. An explicit
    built-in selector reads only that key.
    """

    if not data_dir:
        return ""
    candidates = (token_env,) if token_env else ("DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN")
    values: dict[str, str] = {}
    path = os.path.join(data_dir, ".env")
    try:
        with open(path, encoding="utf-8") as stream:
            for raw_line in stream:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                if key not in candidates or key in values:
                    continue
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    value = value[1:-1]
                values[key] = value
    except (OSError, UnicodeError):
        return ""
    return next((values.get(name, "") for name in candidates if values.get(name)), "")


class _NoRuntimeRecorder:
    """Explicit bootstrap/recovery capability: no buffering and no writes."""

    def emit_cli_observability(self, _payload: Mapping[str, Any]) -> None:
        return

    def close(self) -> None:
        return


class Logger:
    """Emit CLI facts through one injected canonical-v8 recorder."""

    def __init__(self, recorder: _CanonicalRecorder) -> None:
        if recorder is None or not callable(getattr(recorder, "emit_cli_observability", None)):
            raise TypeError("Logger requires a canonical Observability v8 recorder")
        self._recorder = recorder

    @classmethod
    def from_config(cls, cfg: Any) -> Logger:
        """Create a lazy handoff to the gateway that owns ``cfg``.

        Construction performs no network or secret lookup. The ordinary CLI's
        config-version gate owns v7 rejection before this method is called.
        """

        if cfg is None or getattr(cfg, "gateway", None) is None:
            raise CanonicalObservabilityError("gateway configuration is unavailable")
        return cls(_GatewayConfigRecorder(cfg))

    @classmethod
    def no_runtime(cls) -> Logger:
        """Return an explicit bootstrap/recovery logger that emits nothing.

        This capability never buffers raw facts and never writes SQLite,
        JSONL, Splunk, OTLP, or any other sink. It is intentionally distinct
        from :meth:`from_config` so ordinary command paths cannot silently
        degrade to it.
        """

        return cls(_NoRuntimeRecorder())

    def log_scan(self, result: ScanResult, *, error: str = "", connector: str | None = None) -> None:
        scan: dict[str, Any] = {
            "scanner": result.scanner,
            "target": result.target,
            "timestamp": result.timestamp.isoformat(),
            "findings": [_scan_finding_wire(finding) for finding in result.findings],
            "duration_ms": int(result.duration.total_seconds() * 1000),
        }
        if error:
            # A scan that could not finish is recorded as scan.failed, so
            # audit export, OTLP and alerts show it (GAP-1504).
            scan["error"] = error.replace("\x00", "").encode("utf-8")[:4000].decode("utf-8", "ignore")
        # Name the agent whose skill/plugin/MCP server was scanned, so the
        # scan telemetry says which connector the asset belongs to (GAP-1381).
        if connector:
            scan["connector"] = connector
        self._emit({"kind": "scan", "run_id": _current_run_id(), "scan": scan})

    def log_scan_failed(self, scanner: str, target: str, error: str, *, duration_ms: int = 0) -> None:
        from datetime import datetime, timedelta, timezone

        self.log_scan(
            ScanResult(
                scanner=scanner,
                target=target,
                timestamp=datetime.now(timezone.utc),
                findings=[],
                duration=timedelta(milliseconds=max(0, duration_ms)),
            ),
            error=error or "scan failed",
        )

    def log_action(self, action: str, target: str, details: str) -> None:
        self._emit(
            {
                "kind": "action",
                "run_id": _current_run_id(),
                "action": {"name": action, "target": target, "details": details},
            }
        )

    def log_config_change(self, operation: str, details: str, *, actor: str | None = None) -> None:
        """Record a CLI setting change as an Activity mutation that names it.

        ``log_action("config-update", "config", ...)`` reaches the v8 trail
        without its details, so Activity -> Mutations read only "cli
        config-update config" for ``guardrail mode`` or ``block-at``
        (GAP-1217). ``details`` is ``key=value`` text: ``scope=`` names the
        target, ``previous=`` is the old value of the first field, and that
        field becomes the diff (``mode: observe -> action``).
        """

        if actor is None:
            from defenseclaw.config_writer import ACTOR_PREFIX_CLI, current_actor

            actor = current_actor(ACTOR_PREFIX_CLI)
        fields: dict[str, str] = {}
        for token in details.split():
            key, sep, value = token.partition("=")
            if sep and key:
                fields[key] = value
        scope = _target_token(fields.pop("scope", ""))
        previous = fields.pop("previous", None)
        target_id = f"{_target_token(operation)}:{scope}" if scope else _target_token(operation)
        diff: list[dict[str, Any]] = []
        before: dict[str, Any] | None = None
        if fields:
            key, value = next(iter(fields.items()))
            entry: dict[str, Any] = {"path": key, "op": "replace", "after": value or "(unset)"}
            if previous is not None:
                entry["before"] = previous or "(unset)"
                before = {key: previous}
            diff.append(entry)
        self.log_activity(
            actor=actor,
            action="config-update",
            target_type="config",
            target_id=target_id or "config",
            before=before,
            after=dict(fields) or None,
            diff=diff,
        )

    def log_activity(
        self,
        *,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        before: Any | None = None,
        after: Any | None = None,
        diff: list[dict[str, Any]] | None = None,
        version_from: str = "",
        version_to: str = "",
        severity: str = "INFO",
    ) -> None:
        # Source values intentionally remain untouched. The v8 runtime creates
        # an independent projection for SQLite and every selected destination.
        activity: dict[str, Any] = {
            "actor": actor,
            "action": action,
            "target_type": target_type or "unknown",
            "target_id": target_id or "unknown",
            "diff": diff or [],
            "version_from": version_from,
            "version_to": version_to,
            "severity": severity or "INFO",
        }
        if before is not None:
            activity["before"] = before
        if after is not None:
            activity["after"] = after
        self._emit({"kind": "activity", "run_id": _current_run_id(), "activity": activity})

    def log_alert(
        self,
        source: str,
        severity: str,
        summary: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        alert: dict[str, Any] = {
            "source": source,
            "severity": severity or "WARN",
            "summary": summary,
        }
        if details is not None:
            alert["details"] = details
        self._emit({"kind": "alert", "run_id": _current_run_id(), "alert": alert})

    def log_llm_bridge(
        self,
        *,
        model: str,
        provider: str,
        status: str,
        duration_ms: float,
        input_tokens: int = 0,
        output_tokens: int = 0,
        response_model: str = "",
        response_id: str = "",
        finish_reasons: list[str] | None = None,
    ) -> None:
        """Submit one observed LiteLLM call to generated v8 signals."""

        self._emit(
            {
                "kind": "llm_bridge",
                "run_id": _current_run_id(),
                "llm_bridge": {
                    "model": model,
                    "provider": provider,
                    "status": status,
                    "duration_ms": duration_ms,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "response_model": response_model,
                    "response_id": response_id,
                    "finish_reasons": list(finish_reasons or []),
                },
            }
        )

    def log_webhook_delivery(
        self,
        *,
        webhook_kind: str,
        target_url: str,
        status_code: int,
        duration_ms: float,
        succeeded: bool,
    ) -> None:
        """Submit one observed synthetic delivery to generated v8 metrics."""

        self._emit(
            {
                "kind": "webhook_delivery",
                "run_id": _current_run_id(),
                "webhook_delivery": {
                    "webhook_kind": webhook_kind,
                    "target_url": target_url,
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                    "succeeded": succeeded,
                },
            }
        )

    def close(self) -> None:
        close = getattr(self._recorder, "close", None)
        if callable(close):
            close()

    def _emit(self, payload: Mapping[str, Any]) -> None:
        try:
            self._recorder.emit_cli_observability(payload)
        except CanonicalObservabilityError:
            raise
        except Exception as exc:
            raise CanonicalObservabilityError(_unconfirmed_audit_reason(exc)) from exc


def _unconfirmed_audit_reason(exc: BaseException) -> str:
    """Why the gateway did not confirm an audit event, in the user's words (GAP-2019).

    The cause's own text (URLs, payload fragments) stays out of the message.
    """
    import requests

    status = getattr(getattr(exc, "response", None), "status_code", None)
    if status in (401, 403):
        return (
            "the gateway on this port refused this account's credentials; "
            "check with 'defenseclaw doctor' that it is this account's gateway"
        )
    if isinstance(exc, requests.Timeout):
        return (
            "the gateway could not record it in time, likely because its audit database is busy "
            "or slow; gateway.log has the cause. Try again in a minute"
        )
    if status == 400:
        # GAP-0070: the gateway named the fixed reason (never payload text); a 400 is not a busy gateway.
        reason = _gateway_rejection_reason(exc)
        detail = f" ({reason})" if reason else ""
        return (
            f"the gateway rejected it as an invalid request{detail}; "
            "the CLI and the gateway may be different versions, check 'defenseclaw doctor'"
        )
    if isinstance(status, int) and status >= 500:
        # GAP-2381: a 5xx is not always a busy database; the gateway logs the cause.
        return (
            f"the gateway could not record it (HTTP {status}); gateway.log has the cause. "
            "If it names a busy or locked audit database, try again in a minute"
        )
    return "the gateway did not acknowledge it; gateway.log has the cause. Try again in a minute"


def _gateway_rejection_reason(exc: BaseException) -> str:
    try:
        reason = exc.response.json().get("reason", "")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        return ""
    return reason if isinstance(reason, str) and len(reason) <= 80 else ""


# Fields the gateway's canonical scan ingress accepts for one finding
# (cliObservabilityV8Finding). Detector-internal fields such as confidence and
# evidence stay in CLI output only; the gateway rejects unknown members, so
# sending them would fail admission for every scan that reports a finding.
_SCAN_FINDING_WIRE_FIELDS = (
    "id",
    "severity",
    "title",
    "description",
    "location",
    "remediation",
    "scanner",
    "tags",
    "rule_id",
    "line_number",
)


def _scan_finding_wire(finding: Any) -> dict[str, Any]:
    data = finding.to_dict()
    return {key: data[key] for key in _SCAN_FINDING_WIRE_FIELDS if key in data}


def _gateway_api_host(cfg: Any) -> str:
    from defenseclaw.config import api_bind_host

    bind = api_bind_host(cfg)
    if bind in {"", "0.0.0.0", "::", "[::]", "localhost"}:
        return "127.0.0.1"
    return bind


def _is_definite_preconnect_failure(exc: requests.RequestException) -> bool:
    """Return true only when no request bytes could have reached the gateway.

    Connect timeouts are explicitly safe to retry. Requests wraps DNS and
    connection-refused failures in a ``ConnectionError`` whose nested urllib3
    reason is ``NewConnectionError``. Read timeouts, resets, protocol errors,
    and generic connection failures remain ambiguous because the gateway may
    already have committed the canonical record.
    """

    if isinstance(exc, requests.ConnectTimeout):
        return True
    pending: list[BaseException] = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        if isinstance(current, NewConnectionError):
            return True
        for related in (
            getattr(current, "reason", None),
            current.__cause__,
            current.__context__,
            *current.args,
        ):
            if isinstance(related, BaseException):
                pending.append(related)
    return False


def _current_run_id() -> str:
    return os.environ.get("DEFENSECLAW_RUN_ID", "").strip()


def _target_token(value: str) -> str:
    """Keep only characters the gateway accepts in an admin target reference."""

    cleaned = "".join(ch if ch.isalnum() or ch in "._:/-" else "-" for ch in value.strip())
    return cleaned.lstrip("._:/-")
