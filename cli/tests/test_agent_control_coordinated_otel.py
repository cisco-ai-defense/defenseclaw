# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from defenseclaw.agent_control.coordinated_otel import CoordinatedOTELTraceWriter
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

TRACE_ID = "1234567890abcdef1234567890abcdef"
PARENT_SPAN_ID = "1234567890abcdef"


class TrackingExporter(InMemorySpanExporter):
    def __init__(self) -> None:
        super().__init__()
        self.export_calls = 0

    def export(self, spans: Any) -> Any:
        self.export_calls += 1
        return super().export(spans)


def source(*, action: str = "allow") -> dict[str, Any]:
    return {
        "ts": "2026-07-14T19:24:50Z",
        "event_type": "hook_decision",
        "trace_id": TRACE_ID,
        "span_id": PARENT_SPAN_ID,
        "session_id": "session-1",
        "request_id": "request-1",
        "connector": "codex",
        "hook_decision": {
            "event": "UserPromptSubmit",
            "action": action,
            "evaluation_id": "evaluation-1",
            "latency_ms": 12,
        },
    }


def control(control_id: int) -> SimpleNamespace:
    return SimpleNamespace(
        control_execution_id=f"execution-{control_id}",
        trace_id=TRACE_ID,
        span_id=PARENT_SPAN_ID,
        agent_name="defenseclaw-policy-sync",
        control_id=control_id,
        control_name=f"control-{control_id}",
        check_stage="pre",
        applies_to="llm_call",
        action="deny",
        matched=True,
        confidence=0.99,
        evaluator_name="defenseclaw.rule_pack",
        selector_path="*",
        timestamp=datetime(2026, 7, 14, 19, 24, 50, tzinfo=UTC),
        execution_duration_ms=3,
        metadata={"source": "defenseclaw.gateway", "rule_ids": ["rule-1"]},
        error_message=None,
    )


class CoordinatedOTELTraceWriterTests(unittest.TestCase):
    def _write(self, controls: list[Any]) -> tuple[TrackingExporter, list[Any]]:
        exporter = TrackingExporter()
        writer = CoordinatedOTELTraceWriter(
            endpoint="https://example.test/v1/traces",
            headers={"authorization": "test"},
            service_name="defenseclaw-policy-sync",
            exporter_factory=lambda **_: exporter,
        )

        self.assertTrue(
            writer.write_trace(
                source=source(action="block" if controls else "allow"), content={"prompt": "hello"}, controls=controls
            )
        )
        return exporter, list(exporter.get_finished_spans())

    def test_exports_completed_prompt_parent_when_no_control_matches(self) -> None:
        exporter, spans = self._write([])

        self.assertEqual(exporter.export_calls, 1)
        self.assertEqual(len(spans), 1)
        parent = spans[0]
        self.assertEqual(parent.context.trace_id, int(TRACE_ID, 16))
        self.assertEqual(parent.context.span_id, int(PARENT_SPAN_ID, 16))
        self.assertEqual(parent.attributes["defenseclaw.control.count"], 0)
        messages = json.loads(parent.attributes["gen_ai.input.messages"])
        self.assertEqual(messages[0]["content"], "hello")

    def test_exports_one_control_as_child_of_actual_prompt_parent(self) -> None:
        exporter, spans = self._write([control(43)])

        self.assertEqual(exporter.export_calls, 1)
        self.assertEqual(len(spans), 2)
        parent = next(span for span in spans if span.name == "invoke_agent codex")
        child = next(span for span in spans if span.name == "agent_control.control_execution")
        self.assertEqual(child.context.trace_id, parent.context.trace_id)
        self.assertEqual(child.parent.span_id, parent.context.span_id)
        self.assertEqual(child.attributes["agent_control.control_id"], 43)

    def test_exports_multiple_controls_in_the_same_completed_batch(self) -> None:
        exporter, spans = self._write([control(43), control(44)])

        self.assertEqual(exporter.export_calls, 1)
        self.assertEqual(len(spans), 3)
        parent = next(span for span in spans if span.name == "invoke_agent codex")
        children = [span for span in spans if span.name == "agent_control.control_execution"]
        self.assertEqual({span.attributes["agent_control.control_id"] for span in children}, {43, 44})
        self.assertTrue(all(span.parent.span_id == parent.context.span_id for span in children))


if __name__ == "__main__":
    unittest.main()
