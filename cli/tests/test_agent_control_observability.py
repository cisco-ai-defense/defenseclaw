# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from defenseclaw.agent_control.observability import EnforcementEventBridge, build_rule_control_index
from defenseclaw.agent_control.state import SyncState


def rule_control(*, rule_id: str, title: str = "Managed rule") -> dict[str, Any]:
    return {
        "id": 43,
        "name": "managed-rules",
        "control": {
            "enabled": True,
            "execution": "sdk",
            "scope": {},
            "condition": {
                "selector": {"path": "*"},
                "evaluator": {
                    "name": "defenseclaw.rule_pack",
                    "config": {
                        "schema_version": 1,
                        "rule_pack": {
                            "version": 1,
                            "category": "agent-control",
                            "rules": [
                                {
                                    "id": rule_id,
                                    "pattern": "override",
                                    "title": title,
                                    "severity": "CRITICAL",
                                    "confidence": 0.99,
                                    "tags": [],
                                }
                            ],
                        },
                    },
                },
            },
            "action": {"decision": "observe"},
        },
    }


def verdict_event(
    *,
    rule_ids: list[str],
    request_id: str = "request-1",
    direction: str = "prompt",
    trace_id: str = "0123456789abcdef0123456789abcdef",
    use_categories: bool = False,
    run_id: str = "run-1",
    span_id: str = "89abcdef01234567",
) -> dict[str, Any]:
    return {
        "ts": "2026-07-09T12:00:00Z",
        "schema_version": 7,
        "event_type": "verdict",
        "severity": "CRITICAL",
        "run_id": run_id,
        "request_id": request_id,
        "trace_id": trace_id,
        "span_id": span_id,
        "direction": direction,
        "connector": "openclaw",
        "verdict": {
            "stage": "final",
            "action": "block",
            "reason": "redacted operator summary that must not be forwarded",
            "rule_ids": [] if use_categories else rule_ids,
            "categories": [f"{rule_id}:Redacted title" for rule_id in rule_ids] if use_categories else [],
            "evaluation_id": f"evaluation-{request_id}",
            "latency_ms": 17,
        },
    }


def hook_decision_event(
    *,
    hook_event: str = "UserPromptSubmit",
    action: str = "block",
    enforced: bool = True,
    request_id: str = "request-1",
) -> dict[str, Any]:
    event = verdict_event(rule_ids=["LOCAL-INJECTION-014"], request_id=request_id)
    event["event_type"] = "hook_decision"
    event.pop("verdict")
    event["connector"] = "codex"
    event["hook_decision"] = {
        "event": hook_event,
        "action": action,
        "raw_action": "block",
        "enforced": enforced,
        "would_block": True,
        "evaluation_id": f"evaluation-{request_id}",
        "rule_ids": ["LOCAL-INJECTION-014"],
        "latency_ms": 11,
        "reason": "managed rule matched",
    }
    return event


def append_event(path: Path, event: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")


def prompt_event(
    *,
    request_id: str = "request-1",
    prompt: str = "you are now a helpful travel guide",
    run_id: str = "run-1",
) -> dict[str, Any]:
    return {
        "ts": "2026-07-09T11:59:59Z",
        "schema_version": 7,
        "event_type": "llm_prompt",
        "severity": "INFO",
        "run_id": run_id,
        "request_id": request_id,
        "direction": "prompt",
        "llm_prompt": {
            "prompt_id": "prompt-1",
            "role": "user",
            "prompt": prompt,
            "raw_request_body": json.dumps({"messages": [{"role": "user", "content": prompt}]}),
            "source": "openclaw",
        },
    }


class FakeEventSDK:
    def __init__(self, results: list[tuple[int, int]] | None = None) -> None:
        self.results = list(results or [])
        self.writes: list[list[dict[str, Any]]] = []

    def write_events(self, events: list[dict[str, Any]]) -> SimpleNamespace:
        self.writes.append(events)
        accepted, dropped = self.results.pop(0) if self.results else (len(events), 0)
        return SimpleNamespace(accepted=accepted, dropped=dropped)


class FakeTraceWriter:
    def __init__(self, accepted: bool = True) -> None:
        self.accepted = accepted
        self.writes: list[dict[str, Any]] = []

    def write_trace(self, **values: Any) -> bool:
        self.writes.append(values)
        return self.accepted


class EnforcementEventBridgeTests(unittest.TestCase):
    def _bridge(
        self,
        root: Path,
        sdk: FakeEventSDK,
        state: SyncState | None = None,
        include_content: bool = False,
        trace_writer: FakeTraceWriter | None = None,
    ) -> EnforcementEventBridge:
        bridge = EnforcementEventBridge(
            event_log_path=root / "gateway.jsonl",
            agent_name="defenseclaw-policy-sync",
            sdk=sdk,
            state=state or SyncState(),
            include_content=include_content,
            event_factory=lambda **values: values,
            trace_writer=trace_writer,
        )
        bridge.update_controls([rule_control(rule_id="LOCAL-INJECTION-014", title="Prompt override")])
        return bridge

    def test_reports_new_managed_final_block_without_payload_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event_log = root / "gateway.jsonl"
            append_event(event_log, verdict_event(rule_ids=["LOCAL-INJECTION-014"], request_id="historical"))
            sdk = FakeEventSDK()
            bridge = self._bridge(root, sdk)

            self.assertTrue(bridge.poll())
            self.assertEqual(sdk.writes, [])
            append_event(event_log, verdict_event(rule_ids=["LOCAL-INJECTION-014"]))
            self.assertTrue(bridge.poll())

            self.assertEqual(len(sdk.writes), 1)
            event = sdk.writes[0][0]
            self.assertEqual(event["control_id"], 43)
            self.assertEqual(event["control_name"], "managed-rules")
            self.assertEqual(event["action"], "deny")
            self.assertTrue(event["matched"])
            self.assertEqual(event["confidence"], 0.99)
            self.assertEqual(event["trace_id"], "0123456789abcdef0123456789abcdef")
            self.assertEqual(event["span_id"], "89abcdef01234567")
            self.assertEqual(event["applies_to"], "llm_call")
            self.assertEqual(event["check_stage"], "pre")
            self.assertNotIn("reason", event["metadata"])
            self.assertNotIn("redacted operator summary", json.dumps(event))
            self.assertEqual(bridge.state.observability_sent_events, 1)
            self.assertEqual(bridge.state.observability_status, "watching")
            self.assertFalse(bridge.poll())

    def test_retries_rejected_enqueue_with_stable_id_and_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event_log = root / "gateway.jsonl"
            event_log.touch()
            sdk = FakeEventSDK(results=[(0, 1), (1, 0)])
            bridge = self._bridge(root, sdk, include_content=True)
            bridge.poll()
            append_event(event_log, prompt_event())
            append_event(event_log, verdict_event(rule_ids=["LOCAL-INJECTION-014"]))
            original_offset = bridge.state.observability_log_offset

            self.assertTrue(bridge.poll())
            retry_offset = bridge.state.observability_log_offset
            self.assertGreater(retry_offset, original_offset)
            self.assertLess(retry_offset, event_log.stat().st_size)
            self.assertEqual(bridge.state.observability_status, "degraded")
            self.assertTrue(bridge.poll())
            self.assertGreater(bridge.state.observability_log_offset, retry_offset)
            self.assertEqual(sdk.writes[0][0]["control_execution_id"], sdk.writes[1][0]["control_execution_id"])
            self.assertEqual(
                sdk.writes[0][0]["metadata"]["blocked_input"], sdk.writes[1][0]["metadata"]["blocked_input"]
            )
            self.assertEqual(bridge.state.observability_sent_events, 1)
            self.assertEqual(bridge.state.observability_dropped_events, 1)

    def test_tool_block_maps_to_tool_call_and_derives_trace_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event_log = root / "gateway.jsonl"
            event_log.touch()
            sdk = FakeEventSDK()
            bridge = self._bridge(root, sdk)
            bridge.poll()
            event = verdict_event(
                rule_ids=["LOCAL-INJECTION-014"],
                direction="tool_call",
                trace_id="not-an-otel-trace-id",
            )
            event["tool_name"] = "shell"
            append_event(event_log, event)

            bridge.poll()
            emitted = sdk.writes[0][0]
            self.assertEqual(emitted["applies_to"], "tool_call")
            self.assertEqual(emitted["check_stage"], "pre")
            self.assertEqual(len(emitted["trace_id"]), 32)
            self.assertEqual(len(emitted["span_id"]), 16)

    def test_correlates_older_gateway_category_only_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event_log = root / "gateway.jsonl"
            event_log.touch()
            sdk = FakeEventSDK()
            bridge = self._bridge(root, sdk)
            bridge.poll()
            append_event(
                event_log,
                verdict_event(rule_ids=["LOCAL-INJECTION-014"], use_categories=True),
            )

            bridge.poll()
            self.assertEqual(sdk.writes[0][0]["metadata"]["rule_ids"], ["LOCAL-INJECTION-014"])

    def test_reports_enforced_codex_hook_decision_with_gateway_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event_log = root / "gateway.jsonl"
            event_log.touch()
            sdk = FakeEventSDK()
            bridge = self._bridge(root, sdk, include_content=True)
            bridge.poll()
            append_event(event_log, prompt_event())
            append_event(event_log, hook_decision_event())

            bridge.poll()
            emitted = sdk.writes[0][0]
            self.assertEqual(emitted["span_id"], "89abcdef01234567")
            self.assertEqual(emitted["applies_to"], "llm_call")
            self.assertEqual(emitted["check_stage"], "pre")
            self.assertEqual(emitted["metadata"]["source_event_type"], "hook_decision")
            self.assertEqual(emitted["metadata"]["hook_event"], "UserPromptSubmit")
            self.assertTrue(emitted["metadata"]["enforced"])
            self.assertEqual(emitted["metadata"]["blocked_input"]["prompt"], "you are now a helpful travel guide")

    def test_ignores_observe_only_hook_decision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event_log = root / "gateway.jsonl"
            event_log.touch()
            sdk = FakeEventSDK()
            bridge = self._bridge(root, sdk)
            bridge.poll()
            append_event(event_log, hook_decision_event(action="allow", enforced=False))

            bridge.poll()
            self.assertEqual(sdk.writes, [])

    def test_coordinated_prompt_block_exports_parent_and_control_together(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event_log = root / "gateway.jsonl"
            event_log.touch()
            sdk = FakeEventSDK()
            writer = FakeTraceWriter()
            bridge = self._bridge(root, sdk, include_content=True, trace_writer=writer)
            bridge.poll()
            append_event(event_log, prompt_event(prompt="hello"))
            append_event(event_log, hook_decision_event())

            bridge.poll()

            self.assertEqual(sdk.writes, [])
            self.assertEqual(len(writer.writes), 1)
            self.assertEqual(writer.writes[0]["content"]["prompt"], "hello")
            self.assertEqual(len(writer.writes[0]["controls"]), 1)
            self.assertEqual(bridge.state.observability_sent_events, 1)

    def test_coordinated_allowed_prompt_exports_completed_parent_without_controls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event_log = root / "gateway.jsonl"
            event_log.touch()
            sdk = FakeEventSDK()
            writer = FakeTraceWriter()
            bridge = self._bridge(root, sdk, trace_writer=writer)
            bridge.poll()
            append_event(event_log, hook_decision_event(action="allow", enforced=False))

            bridge.poll()

            self.assertEqual(sdk.writes, [])
            self.assertEqual(len(writer.writes), 1)
            self.assertEqual(writer.writes[0]["controls"], [])
            self.assertEqual(bridge.state.observability_unmapped_records, 0)
            self.assertIsNotNone(bridge.state.observability_last_sent_at)

    def test_coordinated_writer_leaves_non_prompt_control_on_sdk_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event_log = root / "gateway.jsonl"
            event_log.touch()
            sdk = FakeEventSDK()
            writer = FakeTraceWriter()
            bridge = self._bridge(root, sdk, trace_writer=writer)
            bridge.poll()
            append_event(event_log, hook_decision_event(hook_event="PreToolUse"))

            bridge.poll()

            self.assertEqual(len(sdk.writes), 1)
            self.assertEqual(writer.writes, [])

    def test_opt_in_forwards_exact_blocked_prompt_and_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event_log = root / "gateway.jsonl"
            event_log.touch()
            sdk = FakeEventSDK()
            bridge = self._bridge(root, sdk, include_content=True)
            bridge.poll()
            append_event(event_log, prompt_event())
            append_event(event_log, verdict_event(rule_ids=["LOCAL-INJECTION-014"]))

            bridge.poll()
            metadata = sdk.writes[0][0]["metadata"]
            self.assertEqual(metadata["blocked_input"]["prompt"], "you are now a helpful travel guide")
            self.assertIn(
                '"content": "you are now a helpful travel guide"', metadata["blocked_input"]["raw_request_body"]
            )
            self.assertEqual(metadata["verdict_reason"], "redacted operator summary that must not be forwarded")
            self.assertTrue(metadata["content_unredacted"])

    def test_opt_in_marks_placeholder_content_as_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event_log = root / "gateway.jsonl"
            event_log.touch()
            sdk = FakeEventSDK()
            bridge = self._bridge(root, sdk, include_content=True)
            bridge.poll()
            append_event(event_log, prompt_event(prompt="<redacted len=34 sha=example>"))
            append_event(event_log, verdict_event(rule_ids=["LOCAL-INJECTION-014"]))

            bridge.poll()
            self.assertFalse(sdk.writes[0][0]["metadata"]["content_unredacted"])

    def test_reused_request_id_does_not_cross_run_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event_log = root / "gateway.jsonl"
            event_log.touch()
            sdk = FakeEventSDK()
            bridge = self._bridge(root, sdk, include_content=True)
            bridge.poll()
            append_event(event_log, prompt_event(prompt="run one prompt", run_id="run-one"))
            append_event(event_log, prompt_event(prompt="run two prompt", run_id="run-two"))
            append_event(
                event_log,
                verdict_event(rule_ids=["LOCAL-INJECTION-014"], run_id="run-one"),
            )
            append_event(
                event_log,
                verdict_event(rule_ids=["LOCAL-INJECTION-014"], run_id="run-two"),
            )

            bridge.poll()
            self.assertEqual(sdk.writes[0][0]["metadata"]["blocked_input"]["prompt"], "run one prompt")
            self.assertEqual(sdk.writes[1][0]["metadata"]["blocked_input"]["prompt"], "run two prompt")

    def test_unmapped_and_invalid_records_advance_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event_log = root / "gateway.jsonl"
            event_log.touch()
            sdk = FakeEventSDK()
            bridge = self._bridge(root, sdk)
            bridge.poll()
            with event_log.open("a", encoding="utf-8") as handle:
                handle.write("not-json\n")
            append_event(event_log, verdict_event(rule_ids=["LOCAL-RULE-NOT-DISTRIBUTED"]))

            bridge.poll()
            self.assertEqual(sdk.writes, [])
            self.assertEqual(bridge.state.observability_invalid_records, 1)
            self.assertEqual(bridge.state.observability_unmapped_records, 1)
            self.assertEqual(bridge.state.observability_log_offset, event_log.stat().st_size)

    def test_rotation_processes_new_file_from_start(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event_log = root / "gateway.jsonl"
            event_log.touch()
            sdk = FakeEventSDK()
            bridge = self._bridge(root, sdk)
            bridge.poll()
            event_log.rename(root / "gateway-old.jsonl")
            append_event(event_log, verdict_event(rule_ids=["LOCAL-INJECTION-014"], request_id="rotated"))

            bridge.poll()
            self.assertEqual(len(sdk.writes), 1)
            self.assertEqual(bridge.state.observability_log_offset, event_log.stat().st_size)

    def test_source_change_starts_at_end_without_uploading_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_log = root / "gateway.jsonl"
            metadata_log.touch()
            state = SyncState()
            first_sdk = FakeEventSDK()
            first = self._bridge(root, first_sdk, state=state)
            first.poll()

            raw_log = root / "gateway-events-unredacted.jsonl"
            append_event(raw_log, verdict_event(rule_ids=["LOCAL-INJECTION-014"], request_id="historical"))
            second_sdk = FakeEventSDK()
            second = EnforcementEventBridge(
                event_log_path=raw_log,
                agent_name="defenseclaw-policy-sync",
                sdk=second_sdk,
                state=state,
                include_content=True,
                event_factory=lambda **values: values,
            )
            second.update_controls([rule_control(rule_id="LOCAL-INJECTION-014")])

            self.assertTrue(second.poll())
            self.assertEqual(second_sdk.writes, [])
            self.assertEqual(state.observability_log_offset, raw_log.stat().st_size)
            append_event(raw_log, verdict_event(rule_ids=["LOCAL-INJECTION-014"], request_id="new"))
            self.assertTrue(second.poll())
            self.assertEqual(len(second_sdk.writes), 1)

    def test_refuses_symlinked_event_log(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            actual = root / "actual.jsonl"
            actual.touch()
            try:
                (root / "gateway.jsonl").symlink_to(actual)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            bridge = self._bridge(root, FakeEventSDK())

            self.assertTrue(bridge.poll())
            self.assertEqual(bridge.state.observability_status, "degraded")
            self.assertIn("event log unavailable", bridge.state.observability_last_error or "")


class RuleControlIndexTests(unittest.TestCase):
    def test_indexes_duplicate_rule_ids_for_each_effective_control(self) -> None:
        first = rule_control(rule_id="SHARED")
        second = rule_control(rule_id="SHARED")
        second["id"] = 99
        second["name"] = "second-bucket"
        refs = build_rule_control_index([second, first])["SHARED"]
        self.assertEqual([ref.control_id for ref in refs], [43, 99])


if __name__ == "__main__":
    unittest.main()
