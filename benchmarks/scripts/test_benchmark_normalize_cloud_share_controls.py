# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("benchmark_normalize_cloud_share_controls.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_cloud_share_controls", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

def base_event(event_id: str, event_name: str, event_source: str, **overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "eventID": event_id,
        "eventTime": "2024-08-18T14:19:44Z",
        "eventName": event_name,
        "eventSource": event_source,
        "awsRegion": "us-east-1",
        "requestParameters": None,
        "responseElements": None,
    }
    event.update(overrides)
    return event


def snapshot_request(verb: str, identity: str = "111122223333") -> dict[str, object]:
    item = {"group": "all"} if identity == "all" else {"userId": identity}
    return {
        "attributeType": "CREATE_VOLUME_PERMISSION",
        "createVolumePermission": {verb: {"items": [item]}},
        "snapshotId": "snap-00000000000000001",
    }


def image_request(verb: str) -> dict[str, object]:
    return {
        "attributeType": "launchPermission",
        "imageId": "ami-00000000000000001",
        "launchPermission": {verb: {"items": [{"group": "all"}]}},
    }


def rds_request(verb: str) -> dict[str, object]:
    key = "valuesToAdd" if verb == "add" else "valuesToRemove"
    return {
        "attributeName": "restore",
        "dBSnapshotIdentifier": "synthetic-db-snapshot",
        key: ["111122223333"],
    }


def elastic_records() -> list[tuple[str, dict[str, object]]]:
    return [
        (
            next(path for path in MODULE.ELASTIC_FILES if "snapshot-attribute" in path),
            base_event(
                "00000000-0000-4000-8000-000000000001",
                "ModifySnapshotAttribute",
                "ec2.amazonaws.com",
                requestParameters=snapshot_request("remove", "all"),
                responseElements={"_return": True, "requestId": "excluded"},
            ),
        ),
        (
            next(path for path in MODULE.ELASTIC_FILES if "image-attribute" in path),
            base_event(
                "00000000-0000-4000-8000-000000000002",
                "ModifyImageAttribute",
                "ec2.amazonaws.com",
                requestParameters=image_request("remove"),
                responseElements={"_return": True, "requestId": "excluded"},
            ),
        ),
        (
            next(path for path in MODULE.ELASTIC_FILES if "db-snapshot" in path),
            base_event(
                "00000000-0000-4000-8000-000000000003",
                "ModifyDBSnapshotAttribute",
                "rds.amazonaws.com",
                requestParameters=rds_request("remove"),
                responseElements={
                    "dBSnapshotAttributes": [{"attributeName": "restore", "attributeValues": []}],
                    "dBSnapshotIdentifier": "synthetic-db-snapshot",
                },
            ),
        ),
    ]


def cybersec_records() -> list[tuple[str, dict[str, object]]]:
    return [
        (
            MODULE.CYBERSEC_FILE,
            base_event(
                event_id,
                "ModifySnapshotAttribute",
                "ec2.amazonaws.com",
                requestParameters=snapshot_request("add", account),
                errorCode="Client.UnauthorizedOperation",
                errorMessage="You are not authorized to perform this operation.",
            ),
        )
        for event_id, account in (
            ("00000000-0000-4000-8000-000000000004", "111122223333"),
            ("00000000-0000-4000-8000-000000000005", "111122223333"),
            ("00000000-0000-4000-8000-000000000006", "111122223333"),
            ("00000000-0000-4000-8000-000000000007", "444455556666"),
        )
    ]


def traildiscover_records() -> list[tuple[str, dict[str, object]]]:
    return [
        (
            "events/EC2/ModifySnapshotAttribute.json.cloudtrail",
            base_event(
                "00000000-0000-4000-8000-000000000008",
                "ModifySnapshotAttribute",
                "ec2.amazonaws.com",
                requestParameters=snapshot_request("remove"),
                errorCode="Client.UnauthorizedOperation",
                errorMessage="bounded failure detail",
            ),
        ),
        (
            "events/EC2/ModifyImageAttribute.json.cloudtrail",
            base_event(
                "00000000-0000-4000-8000-000000000009",
                "ModifyImageAttribute",
                "ec2.amazonaws.com",
                errorCode="Client.InvalidParameterCombination",
                errorMessage="No attributes specified.",
            ),
        ),
        (
            "events/RDS/ModifyDBSnapshotAttribute.json.cloudtrail",
            base_event(
                "00000000-0000-4000-8000-000000000010",
                "ModifyDBSnapshotAttribute",
                "rds.amazonaws.com",
                errorCode="AccessDenied",
                errorMessage="bounded failure detail",
            ),
        ),
    ]


def test_normalized_counts_and_measurement_boundary() -> None:
    cases, manifest = MODULE.normalize_records(
        elastic_records(),
        cybersec_records(),
        traildiscover_records(),
        cybersec_successes_excluded=1,
    )
    MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)
    assert len(cases) == 10
    statistics = manifest["adapter_statistics"]["cloud-share-same-operation-controls-v1"]
    assert statistics["scoreable_negative_cases"] == 8
    assert statistics["parser_only_out_of_scope_cases"] == 2
    assert {key: statistics[f"control_kind:{key}"] for key in (
        "failed_no_effect",
        "incomplete_failure",
        "successful_remove",
    )} == {"failed_no_effect": 5, "incomplete_failure": 2, "successful_remove": 3}
    assert all(source.redistribution == "download-only" for source in MODULE.SOURCES.values())
    assert all(len(source.revision) == 40 for source in MODULE.SOURCES.values())
    assert all(source.source_url.endswith(source.revision) for source in MODULE.SOURCES.values())


def test_traildiscover_only_manifest_excludes_disabled_companion_datasets() -> None:
    cases, manifest = MODULE.normalize_records(
        elastic_records(),
        cybersec_records(),
        traildiscover_records(),
        cybersec_successes_excluded=1,
        selected_sources=["traildiscover"],
    )

    assert len(cases) == 3
    assert manifest["datasets"] == [MODULE.SOURCES["traildiscover"].dataset]
    assert manifest["counts"] == {MODULE.SOURCES["traildiscover"].dataset: 3}
    assert manifest["adapter_statistics"]["cloud-share-same-operation-controls-v1"][
        "cybersec_successful_additions_excluded"
    ] == 0


def test_projection_preserves_detector_argument_shape_but_excludes_result_and_sensitive_fields() -> None:
    row = base_event(
        "00000000-0000-4000-8000-000000000011",
        "ModifySnapshotAttribute",
        "ec2.amazonaws.com",
        requestParameters=snapshot_request("remove", "all"),
        responseElements={"_return": True, "requestId": "excluded response identifier"},
        userIdentity={"accessKeyId": "secret", "arn": "excluded principal"},
        sourceIPAddress="excluded source",
        userAgent="excluded agent",
        tlsDetails={"cipherSuite": "excluded tls"},
    )
    event = MODULE.project_event(row)
    assert event["control_kind"] == "successful_remove"
    args = event["args"]
    assert args["request_parameters"] == snapshot_request("remove", "all")
    assert "response_elements" not in args
    rendered = MODULE.canonical_json(args)
    for forbidden in ("accessKeyId", "excluded principal", "sourceIPAddress", "userAgent", "tlsDetails"):
        assert forbidden not in rendered


def test_error_message_is_not_retained() -> None:
    row = cybersec_records()[0][1]
    row["errorMessage"] = "sensitive free-form failure detail"
    event = MODULE.project_event(row)
    rendered = MODULE.canonical_json(event["args"])
    assert "sensitive free-form failure detail" not in rendered
    assert event["args"]["status"]["error_message_present"] is True
    assert set(event["args"]["status"]) == {"outcome", "error_code", "error_message_present"}


def test_incomplete_failures_are_parser_only_and_not_hard_negatives() -> None:
    event = MODULE.project_event(traildiscover_records()[1][1])
    case = MODULE.make_case("traildiscover", traildiscover_records()[1][0], event)
    assert case["truth"]["applicability"] == "out_of_scope"
    assert case["truth"]["source_truth"] == "unknown"
    assert case["strata"]["hard_negative"] is False
    assert "excluded from FPR scoring" in case["truth"]["exclusion_reason"]


def test_successful_addition_cannot_enter_negative_control_corpus() -> None:
    addition = base_event(
        "00000000-0000-4000-8000-000000000012",
        "ModifySnapshotAttribute",
        "ec2.amazonaws.com",
        requestParameters=snapshot_request("add", "all"),
        responseElements={"_return": True},
    )
    with pytest.raises(ValueError, match="not a same-operation negative control"):
        MODULE.normalize_records(
            elastic_records(),
            [*cybersec_records(), (MODULE.CYBERSEC_FILE, addition)],
            traildiscover_records(),
            cybersec_successes_excluded=0,
        )


def test_malformed_or_ambiguous_source_is_rejected() -> None:
    with pytest.raises(MODULE.ProjectionError, match="duplicate_json_key"):
        MODULE.parse_json('{"eventName":"one","eventName":"two"}')
    with pytest.raises(MODULE.ProjectionError, match="non_finite_json"):
        MODULE.parse_json('{"value":NaN}')
    malformed = base_event(
        "00000000-0000-4000-8000-000000000013",
        "ModifySnapshotAttribute",
        "ec2.amazonaws.com",
        requestParameters={"snapshotId": "snap-only"},
        responseElements={"_return": True},
    )
    with pytest.raises(MODULE.ProjectionError, match="invalid_snapshot_request"):
        MODULE.project_event(malformed)


def test_real_pinned_sources_normalize_when_downloaded() -> None:
    elastic = Path("/private/tmp/elastic-integrations-f79b2e9c")
    cybersec = Path("/private/tmp/cybersec-cloudtrail-v6/test.jsonl")
    traildiscover = Path("/private/tmp/traildiscover-f96cbdb0")
    if not elastic.exists() or not cybersec.exists() or not traildiscover.exists():
        pytest.skip("pinned public source artifacts are not present")
    cases, manifest = MODULE.normalize_sources(elastic, cybersec, traildiscover)
    MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)
    statistics = manifest["adapter_statistics"]["cloud-share-same-operation-controls-v1"]
    assert statistics["scoreable_negative_cases"] == 8
    assert statistics["parser_only_out_of_scope_cases"] == 2
    assert statistics["cybersec_successful_additions_excluded"] == 1
