#!/usr/bin/env python3

import importlib.util
import json
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_soc_agent_traces.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_soc_agent_traces", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def call_message(call_id: str, name: str, arguments: object) -> dict[str, object]:
    encoded = arguments if isinstance(arguments, str) else json.dumps(arguments)
    return {
        "role": "assistant",
        "content": "private reasoning that must not be projected",
        "tool_calls": [
            {
                "id": call_id,
                "type": "function",
                "function": {"name": name, "arguments": encoded},
            }
        ],
    }


def result_message(call_id: str, name: str, content: str) -> dict[str, object]:
    return {"role": "tool", "tool_call_id": call_id, "name": name, "content": content}


def row(scenario_id: str, messages: list[dict[str, object]], **extra: object) -> dict[str, object]:
    return {
        "scenario_id": scenario_id,
        "trace": json.dumps(
            [
                {"role": "system", "content": "hidden system prompt"},
                {"role": "user", "content": "hidden incident prompt"},
                *messages,
                {"role": "assistant", "content": "hidden final diagnosis"},
            ]
        ),
        "ground_truth": json.dumps({"verdict": "malicious", "secret": "GROUND_TRUTH_MARKER"}),
        "evidence": "EVIDENCE_MARKER",
        "verdict": "malicious",
        **extra,
    }


class NormalizeSOCAgentTracesTests(unittest.TestCase):
    def test_result_and_incident_content_never_reaches_benign_payload(self) -> None:
        source = row(
            "SCT-1",
            [
                call_message("call_0", "get_surrounding_events", {"alert_id": "A-1", "window_minutes": 30}),
                result_message(
                    "call_0",
                    "get_surrounding_events",
                    "credential dumping, persistence, firewall disabled; EVIDENCE_MARKER",
                ),
            ],
        )
        cases, manifest = MODULE.normalize_rows([source])
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["truth"]["deterministic_truth"], "benign")
        serialized = MODULE.canonical_json(cases[0])
        for forbidden in (
            "credential dumping",
            "persistence",
            "firewall disabled",
            "EVIDENCE_MARKER",
            "GROUND_TRUTH_MARKER",
            "hidden incident prompt",
            "hidden final diagnosis",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(manifest["cases"], 1)

    def test_pairing_is_exact_causal_and_unambiguous(self) -> None:
        source = row(
            "SCT-2",
            [
                call_message("missing", "lookup_attack", {"query": "credential dumping"}),
                call_message("mismatch", "search_sigma", {"query": "registry run key"}),
                result_message("mismatch", "lookup_attack", "ignored"),
                call_message("duplicate", "get_asset_context", {"hostname": "WKS-001"}),
                result_message("duplicate", "get_asset_context", "first"),
                result_message("duplicate", "get_asset_context", "second"),
            ],
        )
        cases, manifest = MODULE.normalize_rows([source])
        self.assertEqual(cases, [])
        stats = manifest["adapter_statistics"][MODULE.ADAPTER]
        self.assertEqual(stats["excluded_missing_or_ambiguous_result"], 2)
        self.assertEqual(stats["excluded_noncausal_or_mismatched_result"], 1)
        self.assertEqual(stats["duplicate_results"], 1)

    def test_closed_schemas_are_benign_and_extra_fields_are_contextual(self) -> None:
        fixtures = [
            ("get_process_tree", {"host": "WKS-001", "process_name": "powershell.exe"}),
            ("lookup_attack", {"query": "credential dumping"}),
            ("search_sigma", {"query": "registry run key"}),
            ("get_asset_context", {"hostname": "WKS-001"}),
            ("get_related_alerts", {"user": "analyst.one", "hours": 24}),
            ("search_cve", {"query": "Log4j"}),
            ("retrieve_playbook", {"technique_id": "T1003.001"}),
            ("get_process_tree", {"host": "WKS-001", "recursive": True}),
        ]
        messages: list[dict[str, object]] = []
        for index, (name, arguments) in enumerate(fixtures):
            call_id = f"call_{index}"
            messages.extend([call_message(call_id, name, arguments), result_message(call_id, name, "ignored")])
        cases, _ = MODULE.normalize_rows([row("SCT-3", messages)])
        atomic = sorted(
            (case for case in cases if case["surface"] == "action"),
            key=lambda item: item["strata"]["sequence_index"],
        )
        self.assertEqual(len(atomic), len(fixtures))
        self.assertTrue(all(case["truth"]["applicability"] == "in_scope" for case in atomic[:-1]))
        self.assertEqual(atomic[-1]["truth"]["applicability"], "out_of_scope")

    def test_shell_mutation_admin_and_remediation_tools_stay_contextual(self) -> None:
        fixtures = [
            ("run_shell", {"command": "rm -rf ./workspace"}),
            ("disable_edr", {"host": "WKS-001"}),
            ("remediate_incident", {"alert_id": "A-1"}),
        ]
        messages: list[dict[str, object]] = []
        for index, (name, arguments) in enumerate(fixtures):
            call_id = f"call_{index}"
            messages.extend([call_message(call_id, name, arguments), result_message(call_id, name, "success")])
        cases, _ = MODULE.normalize_rows([row("SCT-4", messages)])
        self.assertEqual(len(cases), 3)
        self.assertTrue(all(case["truth"]["applicability"] == "out_of_scope" for case in cases))
        self.assertTrue(all(case["truth"]["source_truth"] == "unknown" for case in cases))

    def test_diagnoses_and_source_labels_are_never_projected(self) -> None:
        source = row(
            "SCT-5",
            [
                call_message(
                    "risk",
                    "calculate_risk",
                    {"asset_criticality": "high", "confidence": 0.9, "techniques": ["T1003"], "verdict": "malicious"},
                ),
                result_message("risk", "calculate_risk", "ignored"),
                call_message("other", "unknown_reader", {"diagnosis": "malicious"}),
                result_message("other", "unknown_reader", "ignored"),
            ],
        )
        cases, manifest = MODULE.normalize_rows([source])
        self.assertEqual(cases, [])
        stats = manifest["adapter_statistics"][MODULE.ADAPTER]
        self.assertEqual(stats["excluded_diagnosis_bearing_tool"], 1)
        self.assertEqual(stats["excluded_narrative_or_label_argument"], 1)

    def test_redaction_is_stable_and_value_specific(self) -> None:
        arguments = {"user": "alice@example.com", "query": "Bearer abcdefghijklmnop"}
        first = MODULE.project_value(arguments)
        second = MODULE.project_value(arguments)
        third = MODULE.project_value({"user": "bob@example.com", "query": "Bearer abcdefghijklmnop"})
        self.assertEqual(first, second)
        self.assertNotEqual(first["user"], third["user"])
        self.assertNotIn("alice", MODULE.canonical_json(first))
        self.assertNotIn("abcdefghijklmnop", MODULE.canonical_json(first))

    def test_non_english_arguments_are_excluded(self) -> None:
        source = row(
            "SCT-6",
            [
                call_message("call_0", "lookup_attack", {"query": "сбор учетных данных"}),
                result_message("call_0", "lookup_attack", "ignored"),
            ],
        )
        cases, manifest = MODULE.normalize_rows([source])
        self.assertEqual(cases, [])
        self.assertEqual(manifest["adapter_statistics"][MODULE.ADAPTER]["excluded_non_english_arguments"], 1)

    def test_stateful_windows_contain_calls_and_unknown_outcomes_only(self) -> None:
        source = row(
            "SCT-7",
            [
                call_message("call_0", "lookup_attack", {"query": "credential dumping"}),
                result_message("call_0", "lookup_attack", "SECRET_RESULT_ONE"),
                call_message("call_1", "search_sigma", {"query": "browser credential store"}),
                result_message("call_1", "search_sigma", "SECRET_RESULT_TWO"),
            ],
        )
        cases, _ = MODULE.normalize_rows([source])
        stateful = [case for case in cases if case["surface"] == "stateful"]
        self.assertEqual(len(stateful), 1)
        self.assertEqual(len(stateful[0]["payload"]["events"]), 2)
        self.assertTrue(all(event["outcome"] == "unknown" for event in stateful[0]["payload"]["events"]))
        serialized = MODULE.canonical_json(stateful[0])
        self.assertNotIn("SECRET_RESULT_ONE", serialized)
        self.assertNotIn("SECRET_RESULT_TWO", serialized)

    def test_real_dedup_and_trajectory_disjoint_groups(self) -> None:
        messages = [
            call_message("call_0", "lookup_attack", {"query": "credential dumping"}),
            result_message("call_0", "lookup_attack", "ignored"),
        ]
        cases, manifest = MODULE.normalize_rows([row("SCT-8A", messages), row("SCT-8B", messages)])
        self.assertEqual(len(cases), 1)
        self.assertEqual(manifest["exact_payload_duplicates_removed"], 1)
        first, _ = MODULE.normalize_rows([row("SCT-8A", messages)])
        second, _ = MODULE.normalize_rows([row("SCT-8B", messages)])
        self.assertNotEqual(first[0]["strata"]["split_group"], second[0]["strata"]["split_group"])

    def test_manifest_and_cases_pass_strict_validation(self) -> None:
        source = row(
            "SCT-9",
            [
                call_message("call_0", "get_asset_context", {"hostname": "WKS-001"}),
                result_message("call_0", "get_asset_context", "ignored"),
            ],
        )
        cases, manifest = MODULE.normalize_rows([source])
        MODULE.validate_cases(cases)
        self.assertEqual(
            set(manifest),
            {
                "schema_version",
                "datasets",
                "cases",
                "counts",
                "exact_payload_duplicates_removed",
                "label_conflicts_excluded",
                "adapter_statistics",
                "output_sha256",
                "source",
            },
        )
        self.assertEqual(manifest["counts"], {MODULE.DATASET_ID: len(cases)})


if __name__ == "__main__":
    unittest.main()
