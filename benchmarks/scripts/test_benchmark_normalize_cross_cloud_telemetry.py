# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("benchmark_normalize_cross_cloud_telemetry.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_cross_cloud_telemetry", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_aws_projection_excludes_credentials_noise_and_bodies() -> None:
    row = {
        "eventName": "DeleteVolume",
        "eventSource": "ec2.amazonaws.com",
        "eventTime": "2024-11-24T04:42:32Z",
        "awsRegion": "us-test-1",
        "sourceIPAddress": "excluded address",
        "userAgent": "excluded agent prose",
        "userIdentity": {
            "type": "Root",
            "principalId": "account-placeholder",
            "accessKeyId": "provided by the source credential store",
        },
        "requestParameters": {"volumeId": "vol-example", "token": "excluded token"},
        "responseElements": {"requestId": "excluded response", "_return": True},
    }
    event = MODULE.aws_projection(row)
    rendered = MODULE.canonical_json(event["args"])
    assert event["outcome"] == "succeeded"
    assert "sourceIPAddress" not in rendered
    assert "userAgent" not in rendered
    assert "accessKeyId" not in rendered
    assert "excluded response" not in rendered
    assert "excluded token" not in rendered
    assert event["args"]["request_parameters"] == {"volumeId": "vol-example"}


def test_aws_no_error_without_response_is_unknown() -> None:
    event = MODULE.aws_projection(
        {
            "eventName": "DeleteVolume",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2024-11-24T04:42:32Z",
            "requestParameters": {"volumeId": "vol-example"},
            "responseElements": None,
        }
    )
    assert event["outcome"] == "unknown"
    assert not MODULE.exact_closure("aws", "disk_wipe", event, True)


def test_azure_exact_closure_requires_payload_success_and_resource() -> None:
    row = {
        "operationName": {"value": "Microsoft.Authorization/roleAssignments/delete"},
        "eventTimestamp": "2024-11-07T19:42:46Z",
        "status": {"value": "Succeeded"},
        "caller": "actor-placeholder",
        "resourceId": "/subscriptions/sub/resourceGroups/group/providers/Microsoft.Authorization/roleAssignments/role",
        "authorization": {
            "action": "Microsoft.Authorization/roleAssignments/delete",
            "scope": "/subscriptions/sub/resourceGroups/group",
        },
        "claims": {"token": "excluded"},
        "properties": {"responseBody": "excluded response body"},
        "operationId": "operation-placeholder",
    }
    event = MODULE.azure_projection(row)
    assert MODULE.exact_closure("azure", "account_access_removal", event, True)
    assert not MODULE.exact_closure("azure", "account_access_removal", event, False)
    rendered = MODULE.canonical_json(event["args"])
    assert "excluded response body" not in rendered
    assert "claims" not in rendered


def test_azure_ip_caller_is_noise_not_actor_identity() -> None:
    row = {
        "operationName": {"value": "Microsoft.Authorization/roleAssignments/delete"},
        "eventTimestamp": "2024-11-07T19:42:46Z",
        "status": {"value": "Succeeded"},
        "caller": "192.0.2.15",
        "resourceId": "/subscriptions/sub/providers/Microsoft.Authorization/roleAssignments/role",
    }
    event = MODULE.azure_projection(row)
    assert "actor" not in event["args"]


def test_gcp_object_delete_closes_only_with_empty_success_status() -> None:
    row = {
        "timestamp": "2024-10-31T23:52:33Z",
        "protoPayload": {
            "methodName": "storage.objects.delete",
            "serviceName": "storage.googleapis.com",
            "resourceName": "projects/_/buckets/example/objects/file.txt",
            "authenticationInfo": {
                "principalEmail": "agent@example.invalid",
                "serviceAccountKeyName": "excluded key identity",
            },
            "authorizationInfo": [
                {
                    "granted": True,
                    "permission": "storage.objects.delete",
                    "resource": "projects/_/buckets/example/objects/file.txt",
                }
            ],
            "request": {"bucket": "example", "object": "file.txt", "data": "excluded body"},
            "requestMetadata": {"callerIp": "excluded", "callerSuppliedUserAgent": "excluded"},
            "status": {},
        },
    }
    event = MODULE.gcp_projection(row)
    assert MODULE.exact_closure("gcp", "data_destruction", event, True)
    rendered = MODULE.canonical_json(event["args"])
    assert "serviceAccountKeyName" not in rendered
    assert "requestMetadata" not in rendered
    assert "excluded body" not in rendered


def test_paired_control_is_never_promoted() -> None:
    event = {
        "operation": "DeleteVolume",
        "outcome": "succeeded",
        "args": {"request": {"volumeId": "vol-example"}},
    }
    truth = MODULE.truth("aws", "disk_wipe", event, False)
    assert truth["source_truth"] == "benign"
    assert truth["applicability"] == "out_of_scope"
    assert truth["expected_disposition"] == "detect_only"


def test_nonclosure_attack_event_remains_unknown_context() -> None:
    event = {
        "operation": "DescribeVolumes",
        "outcome": "succeeded",
        "args": {"request": {"volumeId": "vol-example"}},
    }
    truth = MODULE.truth("aws", "disk_wipe", event, True)
    assert truth["source_truth"] == "unknown"
    assert truth["deterministic_truth"] == "contextual_or_dual_use"
    assert truth["applicability"] == "out_of_scope"


def test_json_stream_supports_concatenated_arrays_and_rejects_duplicates() -> None:
    rows = MODULE.parse_json_stream(b'[{"eventName":"one"}][{"eventName":"two"}]')
    assert [row["eventName"] for row in rows] == ["one", "two"]
    with pytest.raises(MODULE.ProjectionError, match="duplicate_json_key"):
        MODULE.parse_json_stream(b'{"eventName":"one","eventName":"two"}')


def test_bounded_projection_rejects_oversized_and_deep_values() -> None:
    with pytest.raises(MODULE.ProjectionError, match="value_too_large"):
        MODULE.project_selected({"name": "x" * (MODULE.MAX_VALUE_BYTES + 1)})
    nested: object = "value"
    for _ in range(MODULE.MAX_DEPTH + 2):
        nested = {"values": nested}
    with pytest.raises(MODULE.ProjectionError, match="value_too_deep"):
        MODULE.project_selected({"values": nested})


def test_noncanonical_derived_member_is_excluded(tmp_path: Path) -> None:
    import zipfile

    path = tmp_path / "aws.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("aws_logs/default-logs/aws-disk_wipe-0-y-logs.json", "[]")
        archive.writestr("aws_logs/default-logs/aws-disk_wipe-0-y-cloudwatch-logs.json", "[]")
        archive.writestr("aws_logs/default-logs/aws-disk_wipe-0-y-cloudwatch-jq-logs.json", "[]")
    with zipfile.ZipFile(path) as archive:
        members = MODULE.safe_members(archive, "aws")
    assert [member.filename for member in members] == ["aws_logs/default-logs/aws-disk_wipe-0-y-logs.json"]


def test_pinned_revision_is_enforced(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="immutable Zenodo record"):
        MODULE.normalize_directory(tmp_path, "latest")


def test_real_pinned_corpus_normalizes_and_validates() -> None:
    source = Path("/tmp/cross-cloud-telemetry-v2")
    required = [*(metadata["name"] for metadata in MODULE.ARCHIVES.values()), MODULE.ATTACK_SCRIPTS["name"]]
    if not all((source / str(name)).is_file() for name in required):
        pytest.skip("pinned Cross-Platform Cloud Telemetry fixture is not present")
    cases, manifest = MODULE.normalize_directory(source, MODULE.SOURCE_REVISION)
    MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)
    assert manifest["counts"]["action_cases"] > 0
    assert manifest["counts"]["exact_closure_events"] > 0
    assert sum(manifest["providers"].values()) == manifest["counts"]["action_cases"]
    assert len(manifest["exact_closure_evidence"]) == 3
    assert {case["strata"]["platform"] for case in cases} == {"aws", "azure", "gcp"}
    assert all(case["split"] == "development" for case in cases)
    assert all(
        len(case["payload"].get("events", [])) <= MODULE.MAX_EVENTS for case in cases if case["surface"] == "stateful"
    )
    rendered = json.dumps(cases)
    for forbidden in (
        "accessKeyId",
        "serviceAccountKeyName",
        "sourceIPAddress",
        "userAgent",
        "requestMetadata",
        "responseBody",
    ):
        assert forbidden not in rendered
