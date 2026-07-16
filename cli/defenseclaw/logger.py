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

    def emit_cli_observability(self, payload: Mapping[str, Any]) -> None:
        gateway = getattr(self._cfg, "gateway", None)
        if gateway is None:
            raise CanonicalObservabilityUnavailableError("gateway configuration is unavailable")
        token_resolver = getattr(gateway, "resolved_token", None)
        token = token_resolver() if callable(token_resolver) else ""
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
                "gateway authentication is unavailable; start or reconfigure the v8 gateway"
            )
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

    def log_scan(self, result: ScanResult) -> None:
        payload = {
            "kind": "scan",
            "run_id": _current_run_id(),
            "scan": {
                "scanner": result.scanner,
                "target": result.target,
                "timestamp": result.timestamp.isoformat(),
                "findings": [finding.to_dict() for finding in result.findings],
                "duration_ms": int(result.duration.total_seconds() * 1000),
            },
        }
        self._emit(payload)

    def log_action(self, action: str, target: str, details: str) -> None:
        self._emit(
            {
                "kind": "action",
                "run_id": _current_run_id(),
                "action": {"name": action, "target": target, "details": details},
            }
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
            raise CanonicalObservabilityError("canonical Observability v8 admission was not confirmed") from exc


def _gateway_api_host(cfg: Any) -> str:
    gateway = cfg.gateway
    bind = str(getattr(gateway, "api_bind", "") or "").strip()
    if not bind:
        openshell = getattr(cfg, "openshell", None)
        guardrail = getattr(cfg, "guardrail", None)
        standalone = bool(
            openshell is not None and callable(getattr(openshell, "is_standalone", None)) and openshell.is_standalone()
        )
        guardrail_host = str(getattr(guardrail, "host", "") or "").strip()
        if standalone and guardrail_host and guardrail_host != "localhost":
            bind = guardrail_host
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
