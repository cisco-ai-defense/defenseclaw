#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize pinned public AWS same-operation cloud-share controls.

This corpus is deliberately narrow. It measures whether a post-action
detector distinguishes successful permission removal and failed permission
mutation from a successful snapshot/image/database-snapshot share. It does
not establish whether a cross-account grant was authorized, and it must not
be used to claim a production false-positive rate: only eight cases qualify
for that denominator.

The source artifacts remain download-only. The normalizer emits bounded
request/status projections and excludes credentials, principals, source
addresses, user agents, TLS metadata, and free-form error messages. No LLM
labels are used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, NamedTuple

SCHEMA_VERSION = "1"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"

ELASTIC_REVISION = "f79b2e9c59de04d980d0bb087421f2c2b1a9cd8d"
CYBERSEC_REVISION = "f90172fc32a3900e97f63bd30538abcc9565f238"
TRAILDISCOVER_REVISION = "f96cbdb0591f78d16b1948e84c211becce6258e6"

ELASTIC_ROOT_URL = f"https://github.com/elastic/integrations/tree/{ELASTIC_REVISION}"
CYBERSEC_ROOT_URL = (
    "https://huggingface.co/datasets/achinta3/cybersec-jsonschemabench-cloudtrail-v6/"
    f"tree/{CYBERSEC_REVISION}"
)
TRAILDISCOVER_ROOT_URL = f"https://github.com/adanalvarez/TrailDiscover/tree/{TRAILDISCOVER_REVISION}"

ELASTIC_FILES = {
    "packages/aws/data_stream/cloudtrail/_dev/test/pipeline/test-modify-snapshot-attribute-json.log":
        "ac88166706e7e7bb4d4cb8754ee9557d96eae4fd7cc8342aa69d3acbd651ca10",
    "packages/aws/data_stream/cloudtrail/_dev/test/pipeline/test-modify-image-attribute-json.log":
        "96b5b7f5e58819b7d8ad6a6d625c7e9caf68441d602775f13cfdbe12124e1fa5",
    "packages/aws/data_stream/cloudtrail/_dev/test/pipeline/test-modify-db-snapshot-attributte-json.log":
        "bd2da0af6baf59814bcb21cb8a165b707655dd7a01af7a933940198e1868580a",
}
CYBERSEC_FILE = "test.jsonl"
CYBERSEC_SHA256 = "3152ba9b67e76da15138b8f86bac655ac5bac4dc8cb4281ec300e01179bbffde"
TRAILDISCOVER_FILES = {
    "events/EC2/ModifySnapshotAttribute.json.cloudtrail":
        "5c4f785d727065a8ad99eb83b17aa642ba584662470844ef24e466304bcc654b",
    "events/EC2/ModifyImageAttribute.json.cloudtrail":
        "0ca14ad0e494a2793e18b0468faf83904c9075decb74d02c1ca0c297d0008c4c",
    "events/RDS/ModifyDBSnapshotAttribute.json.cloudtrail":
        "bbdb412a926c78849135b6a651284bcbc593e698507b8cb94a1583621842735e",
}

MAX_SMALL_FILE_BYTES = 256 * 1024
MAX_CYBERSEC_BYTES = 150 * 1024 * 1024
MAX_OUTER_LINE_BYTES = 2 * 1024 * 1024
MAX_INNER_LINE_BYTES = 64 * 1024
MAX_ERROR_BYTES = 64 * 1024
ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
RESOURCE_ID = re.compile(r"^(?:snap-[A-Za-z0-9]+|ami-[A-Za-z0-9]+|[A-Za-z0-9][A-Za-z0-9_.:-]{0,254})$")
EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,127}$")
SUPPORTED_OPERATIONS = {
    ("ec2.amazonaws.com", "ModifySnapshotAttribute"): "ebs_snapshot",
    ("ec2.amazonaws.com", "ModifyImageAttribute"): "ami",
    ("rds.amazonaws.com", "ModifyDBSnapshotAttribute"): "rds_snapshot",
}


class ProjectionError(ValueError):
    """A source record cannot be projected into the bounded corpus."""


class SourceSpec(NamedTuple):
    dataset: str
    revision: str
    license: str
    license_note: str
    source_url: str
    redistribution: str = "download-only"


SOURCES = {
    "elastic": SourceSpec(
        dataset="elastic/integrations-aws-cloudtrail-fixtures",
        revision=ELASTIC_REVISION,
        license="Elastic-2.0",
        license_note="Repository default license; fixture files contain no overriding notice.",
        source_url=ELASTIC_ROOT_URL,
    ),
    "cybersec": SourceSpec(
        dataset="achinta3/cybersec-jsonschemabench-cloudtrail-v6",
        revision=CYBERSEC_REVISION,
        license="other",
        license_note="Dataset card: public flAWS CloudTrail records plus original synthetic chains.",
        source_url=CYBERSEC_ROOT_URL,
    ),
    "traildiscover": SourceSpec(
        dataset="adanalvarez/TrailDiscover",
        revision=TRAILDISCOVER_REVISION,
        license="CC-BY-4.0",
        license_note="Repository LICENSE is Creative Commons Attribution 4.0 International.",
        source_url=TRAILDISCOVER_ROOT_URL,
    ),
}

SOURCE_ARTIFACTS = {
    "elastic": [{"path": path, "sha256": sha256} for path, sha256 in ELASTIC_FILES.items()],
    "cybersec": [{"path": CYBERSEC_FILE, "sha256": CYBERSEC_SHA256}],
    "traildiscover": [
        {"path": path, "sha256": sha256} for path, sha256 in TRAILDISCOVER_FILES.items()
    ],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elastic-checkout", type=Path, required=True)
    parser.add_argument("--cybersec-jsonl", type=Path, required=True)
    parser.add_argument("--traildiscover-checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ProjectionError(f"non_finite_json:{value}")


def parse_json(data: str) -> object:
    try:
        return json.loads(data, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ProjectionError("invalid_json") from exc


def required_text(value: object, code: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProjectionError(code)
    result = value.strip()
    if len(result.encode("utf-8")) > maximum:
        raise ProjectionError(code)
    return result


def checked_file(root: Path, relative: str, expected_sha256: str, maximum: int) -> Path:
    resolved_root = root.resolve(strict=True)
    unresolved = resolved_root / relative
    if unresolved.is_symlink():
        raise ValueError(f"source path must not be a symlink: {relative}")
    candidate = unresolved.resolve(strict=True)
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise ValueError(f"source path escapes checkout: {relative}")
    if not candidate.is_file() or candidate.is_symlink():
        raise ValueError(f"source path is not a regular file: {relative}")
    size = candidate.stat().st_size
    if size > maximum:
        raise ValueError(f"source file is too large: {relative}")
    if file_sha256(candidate) != expected_sha256:
        raise ValueError(f"source hash does not match pinned revision: {relative}")
    return candidate


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def parse_time(value: object) -> str:
    text = required_text(value, "invalid_event_time", 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProjectionError("invalid_event_time") from exc
    if parsed.tzinfo is None:
        raise ProjectionError("event_time_without_timezone")
    return text


def string_list(value: object, code: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 16:
        raise ProjectionError(code)
    result: list[str] = []
    for item in value:
        text = required_text(item, code, 256)
        if text != "all" and not ACCOUNT_ID.fullmatch(text):
            raise ProjectionError(code)
        result.append(text)
    return result


def permission_items(value: object, code: str) -> dict[str, dict[str, list[dict[str, str]]]]:
    if not isinstance(value, dict) or set(value) not in ({"add"}, {"remove"}):
        raise ProjectionError(code)
    verb = next(iter(value))
    body = value[verb]
    if not isinstance(body, dict) or set(body) != {"items"}:
        raise ProjectionError(code)
    items = body["items"]
    if not isinstance(items, list) or not items or len(items) > 16:
        raise ProjectionError(code)
    projected: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict) or len(item) != 1:
            raise ProjectionError(code)
        if "group" in item and item["group"] == "all":
            projected.append({"group": "all"})
        elif "userId" in item and isinstance(item["userId"], str) and ACCOUNT_ID.fullmatch(item["userId"]):
            projected.append({"userId": item["userId"]})
        else:
            raise ProjectionError(code)
    return {verb: {"items": projected}}


def project_request(event_name: str, value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ProjectionError("invalid_request_parameters")
    if event_name == "ModifySnapshotAttribute":
        required = {"attributeType", "createVolumePermission", "snapshotId"}
        if set(value) != required or value.get("attributeType") != "CREATE_VOLUME_PERMISSION":
            raise ProjectionError("invalid_snapshot_request")
        snapshot_id = required_text(value["snapshotId"], "invalid_snapshot_id")
        if not RESOURCE_ID.fullmatch(snapshot_id):
            raise ProjectionError("invalid_snapshot_id")
        return {
            "attributeType": "CREATE_VOLUME_PERMISSION",
            "createVolumePermission": permission_items(
                value["createVolumePermission"], "invalid_create_volume_permission"
            ),
            "snapshotId": snapshot_id,
        }
    if event_name == "ModifyImageAttribute":
        required = {"attributeType", "imageId", "launchPermission"}
        if set(value) != required or value.get("attributeType") != "launchPermission":
            raise ProjectionError("invalid_image_request")
        image_id = required_text(value["imageId"], "invalid_image_id")
        if not RESOURCE_ID.fullmatch(image_id):
            raise ProjectionError("invalid_image_id")
        return {
            "attributeType": "launchPermission",
            "imageId": image_id,
            "launchPermission": permission_items(value["launchPermission"], "invalid_launch_permission"),
        }
    if event_name == "ModifyDBSnapshotAttribute":
        allowed = {"attributeName", "dBSnapshotIdentifier", "valuesToAdd", "valuesToRemove"}
        if not set(value).issubset(allowed) or value.get("attributeName") != "restore":
            raise ProjectionError("invalid_db_snapshot_request")
        if set(value) not in (
            {"attributeName", "dBSnapshotIdentifier", "valuesToAdd"},
            {"attributeName", "dBSnapshotIdentifier", "valuesToRemove"},
        ):
            raise ProjectionError("invalid_db_snapshot_request")
        resource = required_text(value["dBSnapshotIdentifier"], "invalid_db_snapshot_id")
        if not RESOURCE_ID.fullmatch(resource):
            raise ProjectionError("invalid_db_snapshot_id")
        result: dict[str, object] = {"attributeName": "restore", "dBSnapshotIdentifier": resource}
        mutation = "valuesToAdd" if "valuesToAdd" in value else "valuesToRemove"
        result[mutation] = string_list(value[mutation], "invalid_db_snapshot_permission")
        return result
    raise ProjectionError("unsupported_operation")


def project_response(event_name: str, value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ProjectionError("invalid_response_elements")
    if event_name in {"ModifySnapshotAttribute", "ModifyImageAttribute"}:
        if value.get("_return") is not True:
            raise ProjectionError("invalid_ec2_response")
        return {"_return": True}
    if event_name == "ModifyDBSnapshotAttribute":
        identifier = required_text(value.get("dBSnapshotIdentifier"), "invalid_db_snapshot_response_id")
        if not RESOURCE_ID.fullmatch(identifier):
            raise ProjectionError("invalid_db_snapshot_response_id")
        attributes = value.get("dBSnapshotAttributes")
        if not isinstance(attributes, list) or len(attributes) > 16:
            raise ProjectionError("invalid_db_snapshot_response")
        projected: list[dict[str, object]] = []
        for item in attributes:
            if not isinstance(item, dict) or set(item) != {"attributeName", "attributeValues"}:
                raise ProjectionError("invalid_db_snapshot_response")
            name = required_text(item["attributeName"], "invalid_db_snapshot_response")
            if name != "restore":
                raise ProjectionError("invalid_db_snapshot_response")
            values = item["attributeValues"]
            if not isinstance(values, list) or len(values) > 16:
                raise ProjectionError("invalid_db_snapshot_response")
            projected_values = [required_text(v, "invalid_db_snapshot_response") for v in values]
            if any(v != "all" and not ACCOUNT_ID.fullmatch(v) for v in projected_values):
                raise ProjectionError("invalid_db_snapshot_response")
            projected.append({"attributeName": name, "attributeValues": projected_values})
        return {"dBSnapshotAttributes": projected, "dBSnapshotIdentifier": identifier}
    raise ProjectionError("unsupported_operation")


def mutation_kind(event_name: str, request: Mapping[str, object]) -> str:
    if event_name == "ModifySnapshotAttribute":
        value = request["createVolumePermission"]
        assert isinstance(value, dict)
        return next(iter(value))
    if event_name == "ModifyImageAttribute":
        value = request["launchPermission"]
        assert isinstance(value, dict)
        return next(iter(value))
    if "valuesToAdd" in request:
        return "add"
    if "valuesToRemove" in request:
        return "remove"
    raise ProjectionError("missing_permission_mutation")


def project_event(row: Mapping[str, Any]) -> dict[str, Any]:
    event_id = required_text(row.get("eventID"), "invalid_event_id", 128)
    if not EVENT_ID.fullmatch(event_id):
        raise ProjectionError("invalid_event_id")
    event_name = required_text(row.get("eventName"), "invalid_event_name", 96)
    event_source = required_text(row.get("eventSource"), "invalid_event_source", 96)
    resource_class = SUPPORTED_OPERATIONS.get((event_source, event_name))
    if resource_class is None:
        raise ProjectionError("unsupported_operation")
    error_code = row.get("errorCode")
    if error_code is not None:
        error_code = required_text(error_code, "invalid_error_code", 128)
    error_message = row.get("errorMessage")
    if error_message is not None and not isinstance(error_message, str):
        raise ProjectionError("invalid_error_message")
    if isinstance(error_message, str) and len(error_message.encode("utf-8")) > MAX_ERROR_BYTES:
        raise ProjectionError("error_message_too_large")
    failed = error_code is not None
    request = project_request(event_name, row.get("requestParameters"))
    response = project_response(event_name, row.get("responseElements"))
    if failed and response is not None:
        raise ProjectionError("failed_event_has_success_response")
    if not failed and response is None:
        raise ProjectionError("success_without_response_proof")
    status: dict[str, object] = {
        "outcome": "failed" if failed else "succeeded",
        "error_code": error_code,
        "error_message_present": error_message is not None,
    }
    args: dict[str, object] = {
        "provider": "aws",
        "event_id": event_id,
        "event_name": event_name,
        "event_source": event_source,
        "event_time": parse_time(row.get("eventTime")),
        "region": required_text(row.get("awsRegion"), "invalid_region", 64),
        "request_parameters": request,
        "status": status,
    }
    kind = "incomplete_failure" if request is None else ("failed_no_effect" if failed else f"successful_{mutation_kind(event_name, request)}")
    return {
        "event_id": event_id,
        "event_name": event_name,
        "event_source": event_source,
        "resource_class": resource_class,
        "control_kind": kind,
        "args": args,
    }


def truth(control_kind: str) -> dict[str, Any]:
    categories = ["cloud_share_same_operation_control", "aws_cloudtrail"]
    if control_kind == "incomplete_failure":
        return {
            "source_truth": "unknown",
            "deterministic_truth": "contextual_or_dual_use",
            "label_confidence": "high",
            "label_source": "source:incomplete_failed_operation",
            "applicability": "out_of_scope",
            "expected_disposition": "detect_only",
            "exclusion_reason": "The failed record has no request parameters, so sharing intent cannot be evaluated; it is parser-only and excluded from FPR scoring.",
            "categories": [*categories, "parser_only_incomplete_failure"],
        }
    if control_kind == "failed_no_effect":
        reason = "failed_operation_no_effect"
    elif control_kind == "successful_remove":
        reason = "successful_permission_removal"
    else:
        raise ProjectionError("unsupported_control_kind")
    return {
        "source_truth": "benign",
        "deterministic_truth": "benign",
        "label_confidence": "high",
        "label_source": f"source:{reason}",
        "applicability": "in_scope",
        "expected_disposition": "allow",
        "categories": [*categories, reason, "post_action_outcome_control"],
    }


def source_record(spec: SourceSpec, original_id: str) -> dict[str, str]:
    return {
        "dataset": spec.dataset,
        "revision": spec.revision,
        "original_id": original_id,
        "license": spec.license,
        "redistribution": spec.redistribution,
    }


def make_case(source_key: str, source_path: str, event: Mapping[str, Any]) -> dict[str, Any]:
    spec = SOURCES[source_key]
    control_kind = str(event["control_kind"])
    scoreable = control_kind != "incomplete_failure"
    event_id = str(event["event_id"])
    trajectory = digest(spec.dataset, spec.revision, event_id)[:24]
    return {
        "schema_version": SCHEMA_VERSION,
        "id": f"cloud-share-controls/{source_key}/{event_id}",
        "source": source_record(spec, f"{source_path}#{event_id}"),
        "split": "development",
        "surface": "action",
        "payload": {
            "direction": "tool_call",
            "tool_name": "aws.cloudtrail_event",
            "args": event["args"],
        },
        "truth": truth(control_kind),
        "strata": {
            "platform": "aws",
            "language": "en",
            "ecosystem": "aws_cloudtrail",
            "domain": "cloud_snapshot_sharing",
            "document_type": f"{event['event_source']}:{event['event_name']}",
            "hard_negative": scoreable,
            "split_group": digest(spec.dataset, spec.revision, str(event["resource_class"]))[:24],
            "trajectory_id": trajectory,
            "sequence_index": 0,
            "call_index": 0,
        },
    }


def load_elastic(root: Path) -> list[tuple[str, Mapping[str, Any]]]:
    result: list[tuple[str, Mapping[str, Any]]] = []
    for relative, expected_hash in ELASTIC_FILES.items():
        path = checked_file(root, relative, expected_hash, MAX_SMALL_FILE_BYTES)
        value = parse_json(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"Elastic fixture must be one JSON object: {relative}")
        result.append((relative, value))
    return result


def load_traildiscover(root: Path) -> list[tuple[str, Mapping[str, Any]]]:
    result: list[tuple[str, Mapping[str, Any]]] = []
    for relative, expected_hash in TRAILDISCOVER_FILES.items():
        path = checked_file(root, relative, expected_hash, MAX_SMALL_FILE_BYTES)
        value = parse_json(path.read_text(encoding="utf-8"))
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise ValueError(f"TrailDiscover fixture must contain one event: {relative}")
        result.append((relative, value[0]))
    return result


def load_cybersec(path: Path) -> tuple[list[tuple[str, Mapping[str, Any]]], int]:
    if path.is_symlink():
        raise ValueError("CybersecJSONSchemaBench input must not be a symlink")
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("CybersecJSONSchemaBench input must be a regular file")
    if resolved.name != CYBERSEC_FILE or resolved.stat().st_size > MAX_CYBERSEC_BYTES:
        raise ValueError("CybersecJSONSchemaBench input is not the pinned test.jsonl artifact")
    if file_sha256(resolved) != CYBERSEC_SHA256:
        raise ValueError("CybersecJSONSchemaBench hash does not match pinned revision")
    selected: dict[str, tuple[str, Mapping[str, Any]]] = {}
    excluded_successes: set[str] = set()
    with resolved.open("r", encoding="utf-8") as handle:
        for line_number, outer_line in enumerate(handle, start=1):
            if len(outer_line.encode("utf-8")) > MAX_OUTER_LINE_BYTES:
                raise ValueError(f"CybersecJSONSchemaBench line is too large: {line_number}")
            outer = parse_json(outer_line)
            if not isinstance(outer, dict):
                raise ValueError(f"CybersecJSONSchemaBench line is not an object: {line_number}")
            inner = outer.get("input_jsonl")
            if not isinstance(inner, str):
                raise ValueError(f"CybersecJSONSchemaBench input_jsonl is missing: {line_number}")
            for inner_line in inner.splitlines():
                if len(inner_line.encode("utf-8")) > MAX_INNER_LINE_BYTES:
                    raise ValueError("CybersecJSONSchemaBench embedded record is too large")
                wrapper = parse_json(inner_line)
                if not isinstance(wrapper, dict) or not isinstance(wrapper.get("raw_record"), dict):
                    raise ValueError("CybersecJSONSchemaBench embedded raw_record is missing")
                raw = wrapper["raw_record"]
                operation = (raw.get("eventSource"), raw.get("eventName"))
                if operation not in SUPPORTED_OPERATIONS:
                    continue
                event_id = required_text(raw.get("eventID"), "invalid_event_id", 128)
                projected = project_event(raw)
                if projected["control_kind"] == "successful_add":
                    excluded_successes.add(event_id)
                    continue
                if projected["control_kind"] != "failed_no_effect":
                    raise ValueError(f"unexpected Cybersec cloud-share operation outcome: {event_id}")
                candidate = (CYBERSEC_FILE, raw)
                previous = selected.setdefault(event_id, candidate)
                if canonical_json(project_event(previous[1])) != canonical_json(projected):
                    raise ValueError(f"conflicting duplicate Cybersec event: {event_id}")
    if len(selected) != 4 or len(excluded_successes) != 1:
        raise ValueError("expected four failed controls and one excluded successful addition in pinned Cybersec data")
    return [selected[key] for key in sorted(selected)], len(excluded_successes)


def normalize_records(
    elastic: Sequence[tuple[str, Mapping[str, Any]]],
    cybersec: Sequence[tuple[str, Mapping[str, Any]]],
    traildiscover: Sequence[tuple[str, Mapping[str, Any]]],
    *,
    cybersec_successes_excluded: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    groups = {"elastic": elastic, "cybersec": cybersec, "traildiscover": traildiscover}
    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    seen: set[tuple[str, str]] = set()
    source_counts: Counter[str] = Counter()
    operation_counts: Counter[str] = Counter()
    for source_key, records in groups.items():
        for source_path, row in records:
            event = project_event(row)
            identity = (source_key, str(event["event_id"]))
            if identity in seen:
                raise ValueError(f"duplicate source event: {source_key}/{event['event_id']}")
            seen.add(identity)
            control_kind = str(event["control_kind"])
            if control_kind not in {"successful_remove", "failed_no_effect", "incomplete_failure"}:
                raise ValueError(f"event is not a same-operation negative control: {source_key}/{event['event_id']}")
            cases.append(make_case(source_key, source_path, event))
            counts[control_kind] += 1
            source_counts[source_key] += 1
            operation_counts[str(event["resource_class"])] += 1
    cases.sort(key=lambda case: str(case["id"]))
    expected = {"successful_remove": 3, "failed_no_effect": 5, "incomplete_failure": 2}
    if dict(counts) != expected:
        raise ValueError(f"unexpected pinned control counts: {dict(counts)}")
    if dict(source_counts) != {"elastic": 3, "cybersec": 4, "traildiscover": 3}:
        raise ValueError(f"unexpected pinned source counts: {dict(source_counts)}")
    manifest_sources = []
    for key in ("elastic", "cybersec", "traildiscover"):
        spec = SOURCES[key]
        manifest_sources.append(
            {
                "key": key,
                "dataset": spec.dataset,
                "revision": spec.revision,
                "license": spec.license,
                "license_note": spec.license_note,
                "redistribution": spec.redistribution,
                "source_url": spec.source_url,
                "selected_cases": source_counts[key],
                "artifacts": SOURCE_ARTIFACTS[key],
            }
        )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "corpus": "cloud-share-same-operation-controls-v1",
        "cases": len(cases),
        "scoreable_negative_cases": counts["successful_remove"] + counts["failed_no_effect"],
        "parser_only_out_of_scope_cases": counts["incomplete_failure"],
        "counts_by_control_kind": {key: counts[key] for key in sorted(counts)},
        "counts_by_resource_class": {key: operation_counts[key] for key in sorted(operation_counts)},
        "cybersec_successful_additions_excluded": cybersec_successes_excluded,
        "labeling": {
            "method": "deterministic_source_argument_and_outcome_projection",
            "llm_labels": False,
            "secrets_retained": False,
        },
        "measurement_scope": "Post-action successful external-share effect only; failed operations and successful permission removals are negative controls.",
        "limitations": [
            "The eight-case scoreable denominator is too small for production false-positive-rate claims.",
            "CloudTrail does not prove whether a successful cross-account grant was approved; authorization requires deployment policy.",
            "Incomplete failed records are parser-only and excluded from precision and FPR scoring.",
        ],
        "sources": manifest_sources,
    }
    return cases, manifest


def normalize_sources(elastic_root: Path, cybersec_path: Path, traildiscover_root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cybersec, excluded = load_cybersec(cybersec_path)
    return normalize_records(
        load_elastic(elastic_root),
        cybersec,
        load_traildiscover(traildiscover_root),
        cybersec_successes_excluded=excluded,
    )


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path) -> None:
    import jsonschema

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for row in rows:
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"{row.get('id', '<unknown>')}:{location}: {errors[0].message}")


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_outputs(
    cases: Sequence[dict[str, Any]],
    manifest: Mapping[str, Any],
    output: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    corpus = "".join(f"{canonical_json(case)}\n" for case in cases)
    output_manifest = dict(manifest)
    output_manifest["output_sha256"] = hashlib.sha256(corpus.encode("utf-8")).hexdigest()
    atomic_write(output, corpus)
    atomic_write(manifest_path, f"{json.dumps(output_manifest, indent=2, sort_keys=True)}\n")
    return output_manifest


def main() -> int:
    args = parse_args()
    cases, manifest = normalize_sources(args.elastic_checkout, args.cybersec_jsonl, args.traildiscover_checkout)
    validate_cases(cases, args.schema)
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    output_manifest = write_outputs(cases, manifest, args.output, manifest_path)
    print(json.dumps({"output": str(args.output), **output_manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
