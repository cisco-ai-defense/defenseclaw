# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("benchmark_normalize_cyber_task_horizons.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_cyber_task_horizons", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sample(messages: list[dict[str, object]], *, score: object = "C") -> dict[str, object]:
    return {
        "id": "intercode-ctf_pwn/task_1",
        "uuid": "run-example",
        "metadata": {"category": "pwn"},
        "scores": {"includes": {"value": score, "explanation": "excluded prose"}},
        "messages": messages,
        "input": "excluded prompt",
        "target": "excluded target",
        "attachments": {"one": "excluded attachment"},
    }


def linked_messages(*, error: object = None, command: str = "id") -> list[dict[str, object]]:
    call = {
        "id": "call-example",
        "function": "bash",
        "arguments": {"cmd": command},
        "type": "function",
    }
    result: dict[str, object] = {
        "role": "tool",
        "tool_call_id": "call-example",
        "function": "bash",
        "content": "excluded result body",
    }
    if error is not None:
        result["error"] = error
    return [{"role": "assistant", "tool_calls": [call]}, result]


def test_linked_non_error_result_is_unknown_not_success() -> None:
    events, counts, complete = MODULE.project_messages(sample(linked_messages()))
    assert complete
    assert events[0]["outcome"] == "unknown"
    assert events[0]["command"] == "id"
    assert counts["non_error_results_without_exit_code"] == 1
    assert "excluded result body" not in MODULE.canonical_json(events)


def test_exact_argument_and_command_whitespace_is_preserved() -> None:
    command = "  printf '%s\\n' preserved  "
    events, _, complete = MODULE.project_messages(sample(linked_messages(command=command)))
    assert complete
    assert events[0]["command"] == command
    assert events[0]["args"]["cmd"] == command


def test_explicit_string_and_structured_errors_are_failed_without_body() -> None:
    for error in ("excluded failure prose", {"type": "ToolError", "message": "excluded structured prose"}):
        events, counts, complete = MODULE.project_messages(sample(linked_messages(error=error)))
        assert complete
        assert events[0]["outcome"] == "failed"
        assert counts["explicit_failed_results"] == 1
        assert "excluded" not in MODULE.canonical_json(events)


def test_unlinked_and_duplicate_results_are_rejected() -> None:
    with pytest.raises(MODULE.ProjectionError, match="unlinked_or_duplicate_result"):
        MODULE.project_messages(sample([linked_messages()[1]]))
    messages = linked_messages()
    with pytest.raises(MODULE.ProjectionError, match="unlinked_or_duplicate_result"):
        MODULE.project_messages(sample([*messages, messages[1]]))


def test_unexecuted_emitted_call_makes_projection_incomplete() -> None:
    messages = linked_messages()
    messages.append(
        {
            "role": "assistant",
            "tool_calls": [{"id": "never-ran", "function": "bash", "arguments": {"cmd": "whoami"}}],
        }
    )
    events, counts, complete = MODULE.project_messages(sample(messages))
    assert len(events) == 1
    assert not complete
    assert counts["unexecuted_emitted_calls"] == 1


def test_target_or_sensitive_material_is_excluded_and_breaks_completeness() -> None:
    events, counts, complete = MODULE.project_messages(
        sample(linked_messages(command="printf 'picoCTF{excluded-answer}'"))
    )
    assert events == []
    assert not complete
    assert counts["excluded_call:action_contains_target_or_sensitive_material"] == 1


def test_complete_trajectory_truth_is_contextual_not_deterministic() -> None:
    truth = MODULE.stateful_truth(complete=True, correct=True)
    assert truth["source_truth"] == "malicious"
    assert truth["deterministic_truth"] == "contextual_or_dual_use"
    assert truth["applicability"] == "in_scope"
    assert truth["expected_disposition"] == "detect_only"
    assert MODULE.atomic_truth()["source_truth"] == "unknown"


def test_incorrect_or_partial_trajectory_is_out_of_scope() -> None:
    for complete, correct in ((False, True), (True, False), (False, False)):
        truth = MODULE.stateful_truth(complete=complete, correct=correct)
        assert truth["source_truth"] == "unknown"
        assert truth["applicability"] == "out_of_scope"


def test_bounded_arguments_reject_large_or_deep_values() -> None:
    with pytest.raises(MODULE.ProjectionError, match="argument_value_too_large"):
        MODULE.bounded({"cmd": "x" * (MODULE.MAX_VALUE_BYTES + 1)})
    nested: object = "value"
    for _ in range(MODULE.MAX_DEPTH + 2):
        nested = {"values": nested}
    with pytest.raises(MODULE.ProjectionError, match="arguments_too_deep"):
        MODULE.bounded(nested)


def test_archive_members_reject_traversal_and_ignore_non_samples(tmp_path: Path) -> None:
    safe = tmp_path / "safe.eval"
    with zipfile.ZipFile(safe, "w") as archive:
        archive.writestr("header.json", "{}")
        archive.writestr("samples/intercode-ctf_pwn/task_1_epoch_1.json", "{}")
    with zipfile.ZipFile(safe) as archive:
        assert [item.filename for item in MODULE.safe_members(archive)] == [
            "samples/intercode-ctf_pwn/task_1_epoch_1.json"
        ]
    unsafe = tmp_path / "unsafe.eval"
    with zipfile.ZipFile(unsafe, "w") as archive:
        archive.writestr("../escape.json", "{}")
    with zipfile.ZipFile(unsafe) as archive, pytest.raises(ValueError, match="unsafe"):
        MODULE.safe_members(archive)


def test_duplicate_json_keys_are_rejected() -> None:
    with pytest.raises(MODULE.ProjectionError, match="duplicate_json_key"):
        json.loads('{"id":"one","id":"two"}', object_pairs_hook=MODULE.strict_object)


def test_pinned_revision_is_enforced(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="pinned revision"):
        MODULE.normalize_directory(tmp_path, "main")


def test_real_pinned_subset_normalizes_and_validates() -> None:
    source = Path("/tmp/cyber-task-horizons-selected")
    if not all((source / name).is_file() for name in MODULE.ARCHIVES):
        pytest.skip("pinned Cyber Task Horizons subset is not present")
    cases, manifest = MODULE.normalize_directory(source, MODULE.SOURCE_REVISION)
    MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)
    assert manifest["cases"] == len(cases)
    assert manifest["counts"] == {MODULE.DATASET_ID: len(cases)}
    statistics = manifest["adapter_statistics"]["cyber-task-horizons-v1"]
    core_statistics = {
        key: value
        for key, value in statistics.items()
        if not key.startswith(("category:", "model:", "rejection:"))
    }
    assert core_statistics == {
        "action_cases": 562,
        "benign_controls": 0,
        "cases": 1008,
        "complete_bounded_contextual_positives": 69,
        "correct_trajectories": 120,
        "deterministic_malicious_proofs": 0,
        "emitted_calls": 616,
        "excluded_call:action_contains_target_or_sensitive_material": 54,
        "explicit_failed_results": 17,
        "linked_results": 616,
        "non_error_results_without_exit_code": 599,
        "result_bodies_excluded": 616,
        "result_bytes_excluded": 486946,
        "selected_tool:bash": 467,
        "selected_tool:python": 95,
        "source_samples": 120,
        "stateful_cases": 446,
        "trajectories_exceeding_bound": 11,
        "trajectories_without_projected_events": 4,
        "unique_tasks": 74,
    }
    assert not any(
        key.startswith("rejection:")
        for key in statistics
    )
    assert not any(case["truth"].get("deterministic_truth") == "deterministic_malicious" for case in cases)
    assert all(len(case["payload"].get("events", [])) <= MODULE.MAX_EVENTS for case in cases)
    rendered = json.dumps(cases)
    for excluded in ("attachments", "reasoning", "excluded result body", "picoCTF{"):
        assert excluded not in rendered
