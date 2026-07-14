"""Completed OTEL traces for gateway prompt decisions and optional controls."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any


def _fixed_hex(seed: str, width: int) -> str:
    value = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:width]
    return value if int(value, 16) != 0 else ("0" * (width - 1) + "1")


def _source_hex(value: Any, width: int, fallback_seed: str) -> str:
    if isinstance(value, str) and len(value) == width:
        try:
            if int(value, 16) != 0:
                return value.lower()
        except ValueError:
            pass
    return _fixed_hex(fallback_seed, width)


def _timestamp_ns(value: Any) -> int:
    if isinstance(value, str):
        try:
            return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1_000_000_000)
        except ValueError:
            pass
    return time.time_ns()


def _prompt_text(content: dict[str, Any] | None) -> str:
    if content:
        for key in ("prompt", "raw_request_body"):
            value = content.get(key)
            if isinstance(value, str) and value:
                return value
    return "<content omitted by DefenseClaw privacy settings>"


class _CoordinatedIDGenerator:
    def __init__(self, trace_id: str, parent_span_id: str) -> None:
        from opentelemetry.sdk.trace.id_generator import RandomIdGenerator

        self._trace_id = int(trace_id, 16)
        self._parent_span_id = int(parent_span_id, 16)
        self._parent_pending = True
        self._random = RandomIdGenerator()

    def generate_trace_id(self) -> int:
        return self._trace_id

    def is_trace_id_random(self) -> bool:
        return False

    def generate_span_id(self) -> int:
        if self._parent_pending:
            self._parent_pending = False
            return self._parent_span_id
        return self._random.generate_span_id()


class CoordinatedOTELTraceWriter:
    """Export one completed application parent with zero or more controls."""

    def __init__(
        self,
        *,
        endpoint: str,
        headers: dict[str, str],
        service_name: str,
        exporter_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.headers = dict(headers)
        self.service_name = service_name
        self.exporter_factory = exporter_factory

    def write_trace(
        self,
        *,
        source: dict[str, Any],
        content: dict[str, Any] | None,
        controls: Sequence[Any],
    ) -> bool:
        from agent_control.otel_sink import control_event_to_otel_span
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.trace import Status, StatusCode, set_span_in_context

        decision = source.get("hook_decision")
        if not isinstance(decision, dict):
            return False

        request_key = str(decision.get("evaluation_id") or source.get("request_id") or source.get("ts") or "")
        source_trace_id = str(source.get("trace_id") or "")
        trace_seed = f"defenseclaw:coordinated-prompt:{source_trace_id}:{request_key}"
        # Reuse the gateway's IDs so this completed batch belongs to the
        # actual prompt trace. The parent is intentionally re-emitted after
        # control evaluation; OTLP backends can then ingest the parent and all
        # optional control children as one coordinated lifecycle.
        trace_id = _source_hex(source.get("trace_id"), 32, trace_seed)
        parent_span_id = _source_hex(source.get("span_id"), 16, trace_seed + ":parent")
        exporter_factory = self.exporter_factory or OTLPSpanExporter
        exporter = exporter_factory(endpoint=self.endpoint, headers=self.headers)
        provider = TracerProvider(
            resource=Resource.create({"service.name": self.service_name}),
            id_generator=_CoordinatedIDGenerator(trace_id, parent_span_id),
        )
        provider.add_span_processor(BatchSpanProcessor(exporter))
        tracer = provider.get_tracer("defenseclaw.agent_control.coordinated")

        connector = str(source.get("connector") or source.get("provider") or "agent")
        agent_name = str(source.get("agent_name") or source.get("agent_type") or connector)
        prompt = _prompt_text(content)
        action = str(decision.get("action") or "allow")
        result = {
            "action": action,
            "matched_controls": len(controls),
            "evaluation_id": decision.get("evaluation_id"),
        }
        end_ns = _timestamp_ns(source.get("ts"))
        latency_ms = decision.get("latency_ms")
        duration_ns = int(float(latency_ms) * 1_000_000) if isinstance(latency_ms, (int, float)) else 0
        start_ns = max(0, end_ns - duration_ns)

        parent = tracer.start_span(f"invoke_agent {connector}", start_time=start_ns)
        try:
            parent.set_attributes(
                {
                    "gen_ai.operation.name": "invoke_agent",
                    "gen_ai.agent.name": agent_name,
                    "gen_ai.provider.name": connector,
                    "openinference.span.kind": "AGENT",
                    "gen_ai.input.messages": json.dumps([{"role": "user", "content": prompt}]),
                    "gen_ai.output.messages": json.dumps([{"role": "assistant", "content": result}]),
                    "gen_ai.conversation.id": str(source.get("session_id") or source.get("request_id") or trace_id),
                    "defenseclaw.coordinated_trace": True,
                    "defenseclaw.source.trace_id": source_trace_id,
                    "defenseclaw.source.span_id": str(source.get("span_id") or ""),
                    "defenseclaw.control.count": len(controls),
                }
            )
            parent_context = set_span_in_context(parent)
            for event in controls:
                span_data = control_event_to_otel_span(event)
                child = tracer.start_span(
                    span_data.name,
                    context=parent_context,
                    start_time=span_data.start_time_unix_nano,
                )
                child.set_attributes(span_data.attributes)
                if span_data.error_message:
                    child.set_status(Status(StatusCode.ERROR, span_data.error_message))
                child.end(end_time=span_data.end_time_unix_nano)
            parent.set_status(Status(StatusCode.OK))
        finally:
            parent.end(end_time=max(end_ns, start_ns + 1))

        flushed = provider.force_flush()
        provider.shutdown()
        return bool(flushed)
