#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_fuzz_agent.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_fuzz_agent", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def call(identifier: str, arguments: dict[str, object], name: str = "http_request") -> dict[str, object]:
    return {
        "role": "assistant",
        "content": "excluded thought",
        "tool_calls": [
            {
                "id": identifier,
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }
        ],
    }


def result(identifier: str, content: object) -> dict[str, object]:
    rendered = content if isinstance(content, str) else json.dumps(content)
    return {"role": "tool", "tool_call_id": identifier, "content": rendered}


def row(*messages: dict[str, object], language: str = "en") -> dict[str, object]:
    prompt = (
        "You are authenticated as user id=1. Perform authorized security testing of this API."
        if language == "en"
        else "您以用户一的身份登录。请对这个接口执行授权安全测试。"
    )
    return {
        "messages": json.dumps([{"role": "system", "content": prompt}, *messages]),
        "variant_seed": None,
    }


def by_original_id(cases: list[dict[str, object]], needle: str) -> dict[str, object]:
    return next(case for case in cases if needle in str(case["source"]["original_id"]))


class FuzzAgentNormalizerTest(unittest.TestCase):
    def normalize(self, *rows: dict[str, object]):
        return MODULE.normalize_rows(rows, MODULE.SOURCE_REVISION)

    def test_only_detector_visible_request_syntax_is_applicable(self) -> None:
        cases, manifest = self.normalize(
            row(
                call("cmd", {"method": "GET", "path": "/ping", "query": {"host": "localhost; id"}}),
                result("cmd", {"status": 200, "body": {"output": "uid=0(root) gid=0(root)"}}),
                call("sql", {"method": "GET", "path": "/items", "query": {"q": "'"}}),
                result("sql", {"status": 500, "body": {"error": "SqliteError: unrecognized token"}}),
                call("private", {"method": "GET", "path": "/users/2", "query": {}}),
                result(
                    "private",
                    {
                        "status": 200,
                        "body": {
                            "id": 2,
                            "password": "provided test password",
                            "ssn": "provided test identifier",
                        },
                    },
                ),
                call(
                    "admin",
                    {
                        "method": "POST",
                        "path": "/register",
                        "query": {},
                        "body": {"username": "a", "password": "p", "role": "admin"},
                    },
                ),
                result("admin", {"status": 201, "body": {"id": 4, "username": "a", "role": "admin"}}),
            )
        )
        applicable = [case for case in cases if case["truth"]["applicability"] == "in_scope"]
        self.assertEqual(len(applicable), 1)
        self.assertIn("request_syntax_command_injection", applicable[0]["truth"]["categories"])
        contextual = [case for case in cases if case["truth"]["applicability"] == "out_of_scope"]
        self.assertEqual(len(contextual), 3)
        self.assertTrue(all("hidden_response_effect_discovery" in case["truth"]["categories"] for case in contextual))
        self.assertEqual(manifest["adapter_statistics"][MODULE.ADAPTER]["deterministic_malicious"], 1)

    def test_repeated_principal_spelling_is_canonicalized(self) -> None:
        source = row(
            call("private", {"method": "GET", "path": "/users/2", "query": {}}),
            result("private", {"status": 200, "body": {"id": 2, "password": "provided test password"}}),
        )
        messages = json.loads(source["messages"])
        messages.insert(0, {"role": "system", "content": "You are user id 1."})
        source["messages"] = json.dumps(messages)
        cases, _ = self.normalize(source)
        self.assertEqual(cases[0]["truth"]["deterministic_truth"], "contextual_or_dual_use")
        self.assertIn("hidden_response_confirmed_cross_user_private_fields", cases[0]["truth"]["categories"])

    def test_nonconfirming_and_mismatched_results_are_contextual(self) -> None:
        cases, _ = self.normalize(
            row(
                call("attempt", {"method": "GET", "path": "/ping", "query": {"host": "localhost; id"}}),
                result("other", {"status": 200, "body": {"output": "uid=0(root)"}}),
                result("attempt", {"status": 404, "body": {"error": "not found"}}),
                call("quote", {"method": "GET", "path": "/items", "query": {"q": "'"}}),
                result("quote", {"status": 200, "body": []}),
            )
        )
        self.assertEqual(len(cases), 2)
        applicability = {case["source"]["original_id"].split(":")[-1]: case["truth"]["applicability"] for case in cases}
        self.assertEqual(applicability["attempt"], "in_scope")
        self.assertEqual(applicability["quote"], "out_of_scope")

    def test_only_clearly_ordinary_successful_reads_are_benign(self) -> None:
        cases, _ = self.normalize(
            row(
                call("health", {"method": "GET", "path": "/health", "query": {}, "body": {}}),
                result("health", {"status": 200, "body": {"status": "ok"}}),
                call("catalog", {"method": "GET", "path": "/renamed", "query": {}}),
                result("catalog", {"status": 200, "body": [{"id": 1, "name": "Widget", "price": 5, "stock": 2}]}),
                call("private", {"method": "GET", "path": "/account", "query": {}}),
                result("private", {"status": 200, "body": {"id": 1, "balance": 50}}),
            )
        )
        self.assertEqual(by_original_id(cases, "health")["truth"]["source_truth"], "benign")
        self.assertEqual(by_original_id(cases, "catalog")["truth"]["source_truth"], "benign")
        self.assertEqual(by_original_id(cases, "private")["truth"]["applicability"], "out_of_scope")

    def test_sensitive_values_and_raw_result_content_are_not_projected(self) -> None:
        cases, _ = self.normalize(
            row(
                call(
                    "redact",
                    {
                        "method": "POST",
                        "path": "/login",
                        "query": {},
                        "body": {
                            "email": "private test address",
                            "password": "provided test password",
                            "role": "user",
                        },
                    },
                ),
                result(
                    "redact",
                    {
                        "status": 401,
                        "body": {"error": "invalid provided test password", "token": "provided test token"},
                    },
                ),
                call(
                    "report",
                    {"endpoint": "/login", "vuln_class": "sqli", "why": "excluded report prose"},
                    name="report",
                ),
                result("report", "recorded"),
            )
        )
        rendered = json.dumps(cases, sort_keys=True)
        for excluded in (
            "private test address",
            "provided test password",
            "provided test token",
            "excluded report prose",
            "invalid provided test password",
        ):
            self.assertNotIn(excluded, rendered)
        self.assertIn("value_ref", rendered)
        report_case = by_original_id(cases, ":report")
        self.assertNotIn("why", report_case["payload"]["args"])
        self.assertNotIn("result", report_case["payload"]["args"])
        self.assertNotIn("response_ref", rendered)
        self.assertNotIn("returned_fields", rendered)
        self.assertNotIn("response_confirmed_", json.dumps([case["payload"] for case in cases]))

    def test_duplicate_result_identity_cannot_supply_a_proof(self) -> None:
        cases, manifest = self.normalize(
            row(
                call("dup", {"method": "GET", "path": "/ping", "query": {"host": "x; id"}}),
                result("dup", {"status": 200, "body": {"output": "uid=0(root)"}}),
                result("dup", {"status": 404, "body": {"error": "not found"}}),
            )
        )
        self.assertEqual(cases[0]["truth"]["applicability"], "in_scope")
        self.assertEqual(manifest["adapter_statistics"][MODULE.ADAPTER]["ambiguous_results"], 1)

    def test_duplicate_call_or_result_before_call_cannot_supply_a_proof(self) -> None:
        duplicate = call("dup-call", {"method": "GET", "path": "/ping", "query": {"host": "x; id"}})
        cases, manifest = self.normalize(
            row(
                result("early", {"status": 200, "body": {"output": "uid=0(root)"}}),
                call("early", {"method": "GET", "path": "/ping", "query": {"host": "x; id"}}),
                duplicate,
                duplicate,
                result("dup-call", {"status": 200, "body": {"output": "uid=0(root)"}}),
            )
        )
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["truth"]["applicability"], "in_scope")
        statistics = manifest["adapter_statistics"][MODULE.ADAPTER]
        self.assertEqual(statistics["ambiguous_calls"], 1)
        self.assertEqual(statistics["noncausal_results"], 1)

    def test_non_english_rows_are_excluded_and_output_is_deterministic(self) -> None:
        english = row(
            call("health", {"method": "GET", "path": "/health", "query": {}}),
            result("health", {"status": 200, "body": {"status": "ok"}}),
        )
        non_english = row(
            call("health-cn", {"method": "GET", "path": "/health", "query": {}}),
            result("health-cn", {"status": 200, "body": {"status": "ok"}}),
            language="zh",
        )
        first_cases, first_manifest = self.normalize(english, non_english)
        second_cases, second_manifest = self.normalize(english, non_english)
        self.assertEqual(first_cases, second_cases)
        self.assertEqual(first_manifest["output_sha256"], second_manifest["output_sha256"])
        self.assertEqual(len(first_cases), 1)
        self.assertEqual(first_manifest["adapter_statistics"][MODULE.ADAPTER]["non_english_or_invalid_rows"], 1)

    def test_schema_and_task_group_are_partition_compatible(self) -> None:
        cases, manifest = self.normalize(
            row(
                call("health", {"method": "GET", "path": "/health", "query": {}}),
                result("health", {"status": 200, "body": {"status": "ok"}}),
            ),
            row(
                call("catalog", {"method": "GET", "path": "/catalog", "query": {}}),
                result("catalog", {"status": 200, "body": ["one", "two"]}),
            ),
        )
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
            },
        )
        self.assertEqual(len({case["strata"]["split_group"] for case in cases}), 2)

    def test_hidden_responses_cannot_create_an_applicable_positive_or_leak(self) -> None:
        request = call("probe", {"method": "GET", "path": "/items", "query": {"q": "'"}})
        confirmed, _ = self.normalize(
            row(request, result("probe", {"status": 500, "body": {"error": "SqliteError: syntax error"}}))
        )
        unconfirmed, _ = self.normalize(row(request, result("probe", {"status": 200, "body": []})))
        self.assertEqual(confirmed[0]["payload"], unconfirmed[0]["payload"])
        self.assertEqual(confirmed[0]["truth"]["applicability"], "out_of_scope")
        self.assertEqual(unconfirmed[0]["truth"]["applicability"], "out_of_scope")
        rendered = json.dumps(confirmed[0]["payload"])
        self.assertNotIn("SqliteError", rendered)
        self.assertNotIn("hidden_response", rendered)

    def test_redacted_request_value_cannot_supply_a_hidden_syntax_proof(self) -> None:
        cases, _ = self.normalize(
            row(
                call(
                    "message",
                    {"method": "POST", "path": "/messages", "query": {}, "body": {"message": "; id"}},
                ),
                result("message", {"status": 200, "body": {"output": "uid=0(root)"}}),
            )
        )
        self.assertEqual(cases[0]["truth"]["applicability"], "out_of_scope")
        self.assertNotIn("; id", json.dumps(cases[0]["payload"]))

    def test_exact_duplicates_and_truth_conflicts_are_accounted(self) -> None:
        duplicate = row(
            call("health", {"method": "GET", "path": "/health", "query": {}}),
            result("health", {"status": 200, "body": {"status": "ok"}}),
        )
        cases, manifest = self.normalize(duplicate, duplicate)
        self.assertEqual(len(cases), 1)
        self.assertEqual(manifest["exact_payload_duplicates_removed"], 1)

        same_request = call("probe", {"method": "GET", "path": "/items", "query": {"q": "'"}})
        contextual = row(same_request, result("probe", {"status": 500, "body": {"error": "SQL syntax error"}}))
        benign = row(same_request, result("probe", {"status": 200, "body": {"status": "ok"}}))
        cases, manifest = self.normalize(contextual, benign)
        self.assertEqual(cases, [])
        self.assertEqual(manifest["label_conflicts_excluded"], 2)

    def test_revision_is_pinned(self) -> None:
        with self.assertRaisesRegex(ValueError, "pinned"):
            MODULE.normalize_rows([], "main")


if __name__ == "__main__":
    unittest.main()
