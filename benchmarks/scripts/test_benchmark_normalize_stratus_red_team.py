# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("benchmark_normalize_stratus_red_team.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_stratus_red_team", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def cloudtrail_event(**overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "awsRegion": "us-test-1",
        "eventID": "00000000-0000-4000-8000-000000000001",
        "eventName": "DeleteTrail",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventTime": "2024-07-31T12:46:41Z",
        "requestID": "00000000-0000-4000-8000-000000000002",
        "requestParameters": {"name": "test-trail"},
        "responseElements": None,
        "sourceIPAddress": "192.0.2.8",
        "userAgent": "excluded agent prose",
        "userIdentity": {
            "accessKeyId": "provided by the source credential store",
            "accountId": "000000000000",
            "arn": "arn:aws:iam::000000000000:user/test-user",
            "principalId": "TESTPRINCIPAL",
            "type": "IAMUser",
            "userName": "test-user",
        },
    }
    event.update(overrides)
    return event


def test_projection_excludes_sensitive_and_unbounded_fields() -> None:
    event = cloudtrail_event(
        requestParameters={
            "name": "test-trail",
            "policyDocument": "excluded policy prose",
            "parameters": "excluded command body",
            "nextToken": "excluded pagination token",
        },
        errorCode="AccessDenied",
        errorMessage="long free-form error and encoded authorization details",
    )
    projected = MODULE.event_projection(event, "aws.defense-evasion.cloudtrail-delete")
    rendered = MODULE.canonical_json(projected["args"])
    assert "accessKeyId" not in rendered
    assert "sSHPublicKey" not in rendered
    assert "sourceIPAddress" not in rendered
    assert "userAgent" not in rendered
    request_parameters = projected["args"]["request_parameters"]
    assert "policyDocument" not in request_parameters
    assert "parameters" not in request_parameters
    assert "nextToken" not in request_parameters
    assert "long free-form error" not in rendered
    assert projected["outcome"] == "failed"
    status = projected["args"]["status"]
    assert status["error_code"] == "AccessDenied"
    assert status["error_message_present"] is True
    assert len(status["error_message_sha256"]) == 64


def test_response_elements_null_never_proves_failure_or_success() -> None:
    projected = MODULE.event_projection(
        cloudtrail_event(responseElements=None), "aws.defense-evasion.cloudtrail-delete"
    )
    assert projected["outcome"] == "succeeded"
    assert MODULE.exact_closure(projected, "aws.defense-evasion.cloudtrail-delete")
    failed = MODULE.event_projection(
        cloudtrail_event(responseElements={"ignored": True}, errorCode="AccessDenied"),
        "aws.defense-evasion.cloudtrail-delete",
    )
    assert failed["outcome"] == "failed"
    assert not MODULE.exact_closure(failed, "aws.defense-evasion.cloudtrail-delete")


def test_contextual_target_is_not_promoted() -> None:
    event = cloudtrail_event(
        eventName="GetSecretValue",
        eventSource="secretsmanager.amazonaws.com",
        requestParameters={"secretId": "arn:aws:secretsmanager:us-test-1:000000000000:secret:test"},
    )
    projected = MODULE.event_projection(event, "aws.credential-access.secretsmanager-retrieve-secrets")
    truth = MODULE.truth(projected, "aws.credential-access.secretsmanager-retrieve-secrets")
    assert truth["source_truth"] == "malicious"
    assert truth["deterministic_truth"] == "contextual_or_dual_use"
    assert truth["applicability"] == "out_of_scope"
    assert truth["expected_disposition"] == "detect_only"


def test_open_ssh_ingress_requires_exact_world_scope_and_port() -> None:
    base = cloudtrail_event(
        eventName="AuthorizeSecurityGroupIngress",
        eventSource="ec2.amazonaws.com",
        requestParameters={
            "cidrIp": "0.0.0.0/0",
            "fromPort": 22,
            "toPort": 22,
            "groupId": "sg-test",
        },
    )
    technique = "aws.exfiltration.ec2-security-group-open-port-22-ingress"
    assert MODULE.exact_closure(MODULE.event_projection(base, technique), technique)
    bounded = copy.deepcopy(base)
    bounded["requestParameters"]["cidrIp"] = "10.0.0.0/8"
    assert not MODULE.exact_closure(MODULE.event_projection(bounded, technique), technique)


def test_world_scope_accepts_any_ipv4_slash_zero_base() -> None:
    technique = "aws.exfiltration.ec2-security-group-open-port-22-ingress"
    event = cloudtrail_event(
        eventName="AuthorizeSecurityGroupIngress",
        eventSource="ec2.amazonaws.com",
        requestParameters={"cidrIp": "208.236.235.254/0", "fromPort": 22, "toPort": 22},
    )
    assert MODULE.exact_closure(MODULE.event_projection(event, technique), technique)


def test_duplicate_json_keys_are_rejected() -> None:
    with pytest.raises(MODULE.ProjectionError, match="duplicate_json_key"):
        json.loads('{"eventName":"one","eventName":"two"}', object_pairs_hook=MODULE.strict_object)


def test_oversized_and_deep_requests_are_rejected() -> None:
    with pytest.raises(MODULE.ProjectionError, match="request_value_too_large"):
        MODULE.project_request({"name": "x" * (MODULE.MAX_VALUE_BYTES + 1)})
    nested: object = "value"
    for _ in range(MODULE.MAX_DEPTH + 2):
        nested = {"values": nested}
    with pytest.raises(MODULE.ProjectionError, match="request_too_deep"):
        MODULE.project_request({"values": nested})


def test_pinned_revision_is_enforced(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="pinned revision"):
        MODULE.normalize_directory(tmp_path, "main")


def test_real_pinned_corpus_normalizes_and_validates() -> None:
    source = Path("/tmp/stratus-red-team.rQvnEL/repo")
    if not source.exists():
        pytest.skip("pinned Stratus fixture is not present")
    cases, manifest = MODULE.normalize_directory(source, MODULE.SOURCE_REVISION)
    MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)
    assert manifest["source_events"] == 310
    assert manifest["source_files"] == 35
    assert manifest["counts"]["action_cases"] == 310
    assert manifest["counts"]["failed_events"] == 52
    assert manifest["counts"]["successful_events"] == 258
    assert manifest["counts"]["exact_closure_events"] > 0
    assert all(case["split"] == "development" for case in cases)
    assert all(
        len(case["payload"].get("events", [])) <= MODULE.MAX_EVENTS for case in cases if case["surface"] == "stateful"
    )
