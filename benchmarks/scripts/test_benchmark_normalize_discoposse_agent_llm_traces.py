#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_discoposse_agent_llm_traces.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_discoposse_agent_llm_traces", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def messages(value: object) -> str:
    return MODULE.canonical_json(value)


def chat_span(
    span_id: str,
    second: int,
    *,
    inputs: list[dict[str, object]] | None = None,
    outputs: list[dict[str, object]] | None = None,
    trace_id: str = "trace-1",
    session_id: str = "session-1",
    parent_span_id: str | None = None,
) -> dict[str, object]:
    return {
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "trace_id": trace_id,
        "session_id": session_id,
        "start_time": f"2026-04-15T11:10:{second:02d}+00:00",
        "attributes": {
            "gen_ai.input.messages": messages(inputs or []),
            "gen_ai.output.messages": messages(outputs or []),
        },
        # Chat status is intentionally irrelevant to tool-call status.
        "status": {"code": 2, "message": "chat transport status"},
    }


def text_message(text: str, role: str = "user") -> dict[str, object]:
    return {"role": role, "parts": [{"type": "text", "content": text}]}


def call_message(call_id: str, name: str, arguments: object) -> dict[str, object]:
    return {
        "role": "assistant",
        "parts": [{"type": "tool_call", "id": call_id, "name": name, "arguments": arguments}],
    }


def response_message(
    call_id: str,
    body: object = "excluded result body",
    *,
    role: str = "tool",
    **extra: object,
) -> dict[str, object]:
    return {
        "role": role,
        "parts": [{"type": "tool_call_response", "id": call_id, "result": body, **extra}],
    }


def source_row(
    *,
    benchmark: str = "appworld",
    session_id: str = "session-1",
    task: str = "Please find the current order and update the delivery preference for the customer.",
    call_count: int = 2,
) -> dict[str, object]:
    spans: list[dict[str, object]] = []
    history: list[dict[str, object]] = [text_message(task)]
    for index in range(call_count):
        call_id = f"call-{index}"
        output = call_message(
            call_id,
            "lookup_order" if index == 0 else "update_delivery",
            {"order_id": f"order-{index}", "authorization": "provided by secret store"},
        )
        spans.append(
            chat_span(
                f"span-{index * 2}",
                index * 2,
                inputs=list(history),
                outputs=[output],
                session_id=session_id,
            )
        )
        history.extend([output, response_message(call_id, f"private result body {index}")])
        spans.append(
            chat_span(
                f"span-{index * 2 + 1}",
                index * 2 + 1,
                inputs=list(history),
                outputs=[text_message("Continue with the task.", role="assistant")],
                session_id=session_id,
            )
        )
    return {"benchmark": benchmark, "session_id": session_id, "spans": spans}


class DiscoPosseNormalizerTest(unittest.TestCase):
    def test_embedded_jwt_is_redacted_inside_freeform_argument(self) -> None:
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.abcdefghijklmno"
        self.assertEqual(
            "Use access token <redacted-jwt> for this request.",
            MODULE.redact_string(f"Use access token {token} for this request."),
        )

    def test_exact_pairs_emit_redacted_actions_and_bounded_state(self) -> None:
        cases, manifest = MODULE.normalize([source_row(call_count=11)], revision=MODULE.SOURCE_REVISION)
        actions = [case for case in cases if case["surface"] == "action"]
        windows = [case for case in cases if case["surface"] == "stateful"]
        self.assertEqual(11, len(actions))
        self.assertEqual(10, len(windows))
        self.assertEqual(9, len(windows[-1]["payload"]["events"]))
        self.assertEqual("<redacted>", actions[0]["payload"]["args"]["authorization"])
        serialized = MODULE.canonical_json(cases)
        self.assertNotIn("private result body", serialized)
        self.assertNotIn("Continue with the task", serialized)
        self.assertTrue(all(case["truth"]["source_truth"] == "benign" for case in cases))
        self.assertEqual(1, manifest["counts"]["normalized_trajectories"])

    def test_swebench_and_non_english_rows_are_quarantined(self) -> None:
        foreign = source_row(
            session_id="foreign-session",
            task="这是一个没有英文任务上下文的工具调用轨迹，应当从英语基准中排除。",
        )
        cases, manifest = MODULE.normalize([source_row(benchmark="swebench"), foreign], revision=MODULE.SOURCE_REVISION)
        self.assertEqual([], cases)
        self.assertEqual(1, manifest["skipped"]["excluded_swebench"])
        self.assertEqual(1, manifest["skipped"]["non_english_or_unknown"])

    def test_result_requires_same_id_in_a_later_span(self) -> None:
        row = source_row(call_count=1)
        row["spans"] = row["spans"][:1]
        cases, manifest = MODULE.normalize([row], revision=MODULE.SOURCE_REVISION)
        self.assertEqual([], cases)
        self.assertEqual(1, manifest["skipped"]["no_exact_call_response_pairs"])

    def test_naive_source_timestamp_is_accepted_for_relative_order_only(self) -> None:
        parsed = MODULE.parse_time("2026-01-28T14:59:42.081553")
        self.assertIsNotNone(parsed.tzinfo)

    def test_anthropic_user_role_tool_response_is_joined_by_typed_part(self) -> None:
        row = source_row(call_count=1)
        final = row["spans"][-1]
        final["attributes"]["gen_ai.input.messages"] = messages(
            [text_message("Please continue the task."), response_message("call-0", role="user")]
        )
        cases, _ = MODULE.normalize([row], revision=MODULE.SOURCE_REVISION)
        self.assertTrue(any(case["surface"] == "action" for case in cases))

    def test_conflicting_repeated_result_is_not_a_proven_pair(self) -> None:
        row = source_row(call_count=1)
        spans = row["spans"]
        assert isinstance(spans, list)
        conflict = response_message("call-0", "different result body")
        spans.append(
            chat_span(
                "span-conflict",
                3,
                inputs=[text_message("Please continue the task."), conflict],
                outputs=[],
            )
        )
        cases, manifest = MODULE.normalize([row], revision=MODULE.SOURCE_REVISION)
        self.assertEqual([], cases)
        self.assertEqual(1, manifest["skipped"]["no_exact_call_response_pairs"])

    def test_tool_outcome_uses_only_explicit_response_metadata(self) -> None:
        row = source_row(call_count=1)
        spans = row["spans"]
        assert isinstance(spans, list)
        final = spans[-1]
        assert isinstance(final, dict)
        attributes = final["attributes"]
        assert isinstance(attributes, dict)
        attributes["gen_ai.input.messages"] = messages(
            [
                text_message("Please continue the task."),
                response_message("call-0", "success words do not define status", is_error=True),
            ]
        )
        cases, _ = MODULE.normalize([row], revision=MODULE.SOURCE_REVISION)
        action = next(case for case in cases if case["surface"] == "action")
        self.assertNotIn("outcome", action["payload"])
        # A second paired call exposes explicit part status inside a stateful event.
        two = source_row(session_id="session-2", call_count=2)
        two_spans = two["spans"]
        assert isinstance(two_spans, list)
        last = two_spans[-1]
        assert isinstance(last, dict)
        last_attributes = last["attributes"]
        assert isinstance(last_attributes, dict)
        last_attributes["genlens"] = "ignored"
        parsed = MODULE.strict_json(last_attributes["gen_ai.input.messages"], "invalid")
        for message in parsed:
            for part in message.get("parts", []):
                if part.get("id") == "call-1":
                    part["is_error"] = False
        last_attributes["gen_ai.input.messages"] = messages(parsed)
        two_cases, _ = MODULE.normalize([two], revision=MODULE.SOURCE_REVISION)
        stateful = [case for case in two_cases if case["surface"] == "stateful"][-1]
        self.assertEqual(["unknown", "succeeded"], [event["outcome"] for event in stateful["payload"]["events"]])

    def test_task_cluster_split_and_trajectory_dedup_are_stable(self) -> None:
        first = source_row(session_id="session-a")
        duplicate = source_row(session_id="session-b")
        cases, manifest = MODULE.normalize([first, duplicate], revision=MODULE.SOURCE_REVISION)
        self.assertEqual(1, manifest["skipped"]["duplicate_task_trajectory"])
        self.assertEqual(1, len({case["strata"]["split_group"] for case in cases}))
        self.assertEqual(1, len({case["split"] for case in cases}))

    def test_mixed_trace_and_parent_cycle_are_quarantined(self) -> None:
        mixed = source_row(session_id="mixed")
        mixed_spans = mixed["spans"]
        assert isinstance(mixed_spans, list)
        mixed_spans[-1]["trace_id"] = "trace-2"
        cyclic = source_row(session_id="cyclic")
        cyclic_spans = cyclic["spans"]
        assert isinstance(cyclic_spans, list)
        cyclic_spans[0]["parent_span_id"] = cyclic_spans[1]["span_id"]
        cyclic_spans[1]["parent_span_id"] = cyclic_spans[0]["span_id"]
        cases, manifest = MODULE.normalize([mixed, cyclic], revision=MODULE.SOURCE_REVISION)
        self.assertEqual([], cases)
        self.assertEqual(1, manifest["skipped"]["mixed_trace_ids"])
        self.assertEqual(1, manifest["skipped"]["cyclic_or_excessive_parent_graph"])

    def test_cases_validate_and_revision_is_immutable(self) -> None:
        cases, _ = MODULE.normalize([source_row()], revision=MODULE.SOURCE_REVISION)
        MODULE.validate_cases(cases)
        with self.assertRaises(ValueError):
            MODULE.normalize([source_row()], revision="main")

    def test_source_identity_requires_all_pinned_shards(self) -> None:
        with self.assertRaisesRegex(ValueError, "exact pinned DiscoPosse"):
            MODULE.validate_source_files([])

    def test_normalization_manifest_matches_runner_contract(self) -> None:
        cases, diagnostics = MODULE.normalize([source_row()], revision=MODULE.SOURCE_REVISION)
        output = "".join(MODULE.canonical_json(case) + "\n" for case in cases).encode()
        manifest = MODULE.build_normalization_manifest(cases, diagnostics, output)
        self.assertEqual([MODULE.DATASET_ID], manifest["datasets"])
        self.assertEqual({MODULE.DATASET_ID: len(cases)}, manifest["counts"])
        self.assertEqual(MODULE.DATASET_ID, manifest["source"]["dataset"])
        self.assertEqual(MODULE.SOURCE_TREE_SHA256, manifest["source"]["sha256"])


if __name__ == "__main__":
    unittest.main()
