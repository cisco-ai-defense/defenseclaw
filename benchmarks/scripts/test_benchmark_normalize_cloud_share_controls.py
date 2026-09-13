# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("benchmark_normalize_cloud_share_controls.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_cloud_share_controls", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

TESTDATA = Path(__file__).with_name("testdata") / "cloud_share_same_operation_controls"


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


def snapshot_request(verb: str, identity: str = "123456789012") -> dict[str, object]:
    item = {"group": "all"} if identity == "all" else {"userId": identity}
    return {
        "attributeType": "CREATE_VOLUME_PERMISSION",
        "createVolumePermission": {verb: {"items": [item]}},
        "snapshotId": "snap-046281ab24d756c50",
    }


def image_request(verb: str) -> dict[str, object]:
    return {
        "attributeType": "launchPermission",
        "imageId": "ami-0beb42caf02660314",
        "launchPermission": {verb: {"items": [{"group": "all"}]}},
    }


def rds_request(verb: str) -> dict[str, object]:
    key = "valuesToAdd" if verb == "add" else "valuesToRemove"
    return {
        "attributeName": "restore",
        "dBSnapshotIdentifier": "test-cloudtrail-event-instance-29973-snap",
        key: ["444455556666"],
    }


def elastic_records() -> list[tuple[str, dict[str, object]]]:
    return [
        (
            next(path for path in MODULE.ELASTIC_FILES if "snapshot-attribute" in path),
            base_event(
                "5e68a70c-9e8b-49c3-a6c5-63ab2bc2685a",
                "ModifySnapshotAttribute",
                "ec2.amazonaws.com",
                requestParameters=snapshot_request("remove", "all"),
                responseElements={"_return": True, "requestId": "excluded"},
            ),
        ),
        (
            next(path for path in MODULE.ELASTIC_FILES if "image-attribute" in path),
            base_event(
                "b837800c-c462-4907-86f7-73b02fd4958f",
                "ModifyImageAttribute",
                "ec2.amazonaws.com",
                requestParameters=image_request("remove"),
                responseElements={"_return": True, "requestId": "excluded"},
            ),
        ),
        (
            next(path for path in MODULE.ELASTIC_FILES if "db-snapshot" in path),
            base_event(
                "10c9f9e2-cf43-4498-8096-0552cbb174d7",
                "ModifyDBSnapshotAttribute",
                "rds.amazonaws.com",
                requestParameters=rds_request("remove"),
                responseElements={
                    "dBSnapshotAttributes": [{"attributeName": "restore", "attributeValues": []}],
                    "dBSnapshotIdentifier": "test-cloudtrail-event-instance-29973-snap",
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
            ("09a73ee0-5e92-4fc4-b2ec-cdfa45e8f156", "642574392309"),
            ("307520b15-3300-4604-83c3-8c9b906342c6", "642574392309"),
            ("6bea0e59-56fb-4370-9b64-65ca88c3834d", "642574392309"),
            ("cc2f0916-60ea-4bfd-b5d3-19bf7d3f77df", "221698185189"),
        )
    ]


def traildiscover_records() -> list[tuple[str, dict[str, object]]]:
    return [
        (
            "events/EC2/ModifySnapshotAttribute.json.cloudtrail",
            base_event(
                "1b5e60ad-3f81-43c8-8b33-7c1788ae9bd1",
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
                "11fe0ffa-a7b2-4241-afaf-8ea1f92b30f6",
                "ModifyImageAttribute",
                "ec2.amazonaws.com",
                errorCode="Client.InvalidParameterCombination",
                errorMessage="No attributes specified.",
            ),
        ),
        (
            "events/RDS/ModifyDBSnapshotAttribute.json.cloudtrail",
            base_event(
                "d5036f48-5b3c-4a3a-8464-b876468ef0c8",
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
    assert manifest["scoreable_negative_cases"] == 8
    assert manifest["parser_only_out_of_scope_cases"] == 2
    assert manifest["counts_by_control_kind"] == {
        "failed_no_effect": 5,
        "incomplete_failure": 2,
        "successful_remove": 3,
    }
    assert "too small for production false-positive-rate claims" in manifest["limitations"][0]
    assert manifest["labeling"] == {
        "method": "deterministic_source_argument_and_outcome_projection",
        "llm_labels": False,
        "secrets_retained": False,
    }
    assert all(source["redistribution"] == "download-only" for source in manifest["sources"])
    assert all(len(source["revision"]) == 40 for source in manifest["sources"])
    assert all(source["source_url"].endswith(source["revision"]) for source in manifest["sources"])


def test_projection_preserves_detector_argument_shape_but_excludes_result_and_sensitive_fields() -> None:
    row = base_event(
        "5e68a70c-9e8b-49c3-a6c5-63ab2bc2685a",
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
        "53b76a15-ff04-4d4d-a1d0-6322e4a2f68a",
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
        "5e68a70c-9e8b-49c3-a6c5-63ab2bc2685a",
        "ModifySnapshotAttribute",
        "ec2.amazonaws.com",
        requestParameters={"snapshotId": "snap-only"},
        responseElements={"_return": True},
    )
    with pytest.raises(MODULE.ProjectionError, match="invalid_snapshot_request"):
        MODULE.project_event(malformed)


def test_committed_normalized_fixture_is_schema_valid_and_public_only() -> None:
    cases = [json.loads(line) for line in (TESTDATA / "normalized.jsonl").read_text().splitlines()]
    MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)
    assert len(cases) == 3
    assert {case["source"]["dataset"] for case in cases} == {
        MODULE.SOURCES["elastic"].dataset,
        MODULE.SOURCES["cybersec"].dataset,
        MODULE.SOURCES["traildiscover"].dataset,
    }
    assert all(case["source"]["redistribution"] == "download-only" for case in cases)
    rendered = MODULE.canonical_json(cases)
    for forbidden in ("accessKeyId", "sourceIPAddress", "userAgent", "tlsDetails", "arn:aws", "authorization failure message"):
        assert forbidden not in rendered


def test_real_pinned_sources_normalize_when_downloaded() -> None:
    elastic = Path("/private/tmp/elastic-integrations-f79b2e9c")
    cybersec = Path("/private/tmp/cybersec-cloudtrail-v6/test.jsonl")
    traildiscover = Path("/private/tmp/traildiscover-f96cbdb0")
    if not elastic.exists() or not cybersec.exists() or not traildiscover.exists():
        pytest.skip("pinned public source artifacts are not present")
    cases, manifest = MODULE.normalize_sources(elastic, cybersec, traildiscover)
    MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)
    assert manifest["scoreable_negative_cases"] == 8
    assert manifest["parser_only_out_of_scope_cases"] == 2
    assert manifest["cybersec_successful_additions_excluded"] == 1
