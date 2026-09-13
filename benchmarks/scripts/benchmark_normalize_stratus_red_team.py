#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize pinned Stratus Red Team CloudTrail detonation logs.

The committed logs prove that an event belongs to a Stratus detonation, but
they do not make every discovery or setup event independently malicious.  This
adapter therefore emits authoritative positives only for successful terminal
operations whose request parameters close a narrow deterministic proof.  All
other events remain development-only contextual evidence.

Response bodies, user agents, source addresses, access keys, free-form policy
or command bodies, and unbounded request fields are deliberately excluded.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
DATASET_ID = "DataDog/stratus-red-team"
SOURCE_URL = "https://github.com/DataDog/stratus-red-team"
SOURCE_REVISION = "efadfd50605f29c644167787ce907b7577793f54"
SOURCE_LICENSE = "Apache-2.0"
SOURCE_REDISTRIBUTION = "download-only"
SOURCE_SUBDIR = Path("docs/detonation-logs")
SOURCE_SHA256 = "9662bfa8fe044094c9a0ca5d965921374a2e49197ee4a5467888623b66be44da"
SOURCE_FILES = 35
SOURCE_EVENTS = 310
MAX_EVENTS = 8
MAX_WINDOW_SECONDS = 1800
MAX_FILE_BYTES = 256 * 1024
MAX_REQUEST_BYTES = 32 * 1024
MAX_VALUE_BYTES = 4096
MAX_ITEMS = 64
MAX_DEPTH = 8
SAFE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,159}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/+=,-]{0,239}$")
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"

# Only bounded fields that establish resource, scope, permission, or target
# identity are retained.  In particular, command/policy bodies and pagination
# tokens are excluded even when they occur in the public source.
REQUEST_FIELDS = frozenset(
    {
        "DeleteFlowLogsRequest",
        "EnableSerialConsoleAccessRequest",
        "FlowLogId",
        "action",
        "add",
        "attribute",
        "attributeName",
        "attributeType",
        "blockDeviceMapping",
        "cidrIp",
        "commandId",
        "content",
        "createVolumePermission",
        "dBSnapshotIdentifier",
        "disableApiStop",
        "disableApiTermination",
        "documentName",
        "dryRun",
        "durationSeconds",
        "enabled",
        "eventSelectors",
        "filterSet",
        "filters",
        "force",
        "fromPort",
        "fullyQualifiedArn",
        "functionName",
        "groupId",
        "imageId",
        "includeManagementEvents",
        "instanceId",
        "instanceIds",
        "instanceOSUser",
        "instanceType",
        "instancesSet",
        "interactive",
        "ipPermissions",
        "ipProtocol",
        "items",
        "launchPermission",
        "layers",
        "maxResults",
        "modelId",
        "monitorMode",
        "monitoring",
        "name",
        "names",
        "originSequenceNumber",
        "passwordResetRequired",
        "policyArn",
        "principal",
        "publish",
        "readWriteType",
        "resolverQueryLogConfigId",
        "roleArn",
        "roleArns",
        "roleName",
        "roleSessionName",
        "serialPort",
        "sessionId",
        "snapshotId",
        "source",
        "statementId",
        "subnetId",
        "tags",
        "target",
        "toPort",
        "trailName",
        "type",
        "userName",
        "userId",
        "values",
        "valuesToAdd",
        "withDecryption",
    }
)

# The operation expected to represent the named detonation.  Successful
# operations not in EXACT_CLOSURES remain source-positive but contextual.
TECHNIQUE_OPERATIONS = {
    "aws.credential-access.ec2-get-password-data": {"GetPasswordData"},
    "aws.credential-access.ec2-steal-instance-credentials": {"SendCommand"},
    "aws.credential-access.secretsmanager-batch-retrieve-secrets": {"BatchGetSecretValue"},
    "aws.credential-access.secretsmanager-retrieve-secrets": {"GetSecretValue"},
    "aws.credential-access.ssm-retrieve-securestring-parameters": {"GetParameters"},
    "aws.defense-evasion.cloudtrail-delete": {"DeleteTrail"},
    "aws.defense-evasion.cloudtrail-event-selectors": {"PutEventSelectors"},
    "aws.defense-evasion.cloudtrail-stop": {"StopLogging"},
    "aws.defense-evasion.dns-delete-logs": {"DeleteResolverQueryLogConfig"},
    "aws.defense-evasion.organizations-leave": {"LeaveOrganization"},
    "aws.defense-evasion.vpc-remove-flow-logs": {"DeleteFlowLogs"},
    "aws.discovery.ec2-download-user-data": {"DescribeInstanceAttribute"},
    "aws.execution.ec2-launch-unusual-instances": {"RunInstances"},
    "aws.execution.ec2-user-data": {"ModifyInstanceAttribute"},
    "aws.execution.ssm-send-command": {"SendCommand"},
    "aws.execution.ssm-start-session": {"StartSession"},
    "aws.exfiltration.ec2-security-group-open-port-22-ingress": {"AuthorizeSecurityGroupIngress"},
    "aws.exfiltration.ec2-share-ami": {"ModifyImageAttribute"},
    "aws.exfiltration.ec2-share-ebs-snapshot": {"ModifySnapshotAttribute"},
    "aws.exfiltration.rds-share-snapshot": {"ModifyDBSnapshotAttribute"},
    "aws.impact.bedrock-invoke-model": {"InvokeModel"},
    "aws.initial-access.console-login-without-mfa": {"ConsoleLogin"},
    "aws.lateral-movement.ec2-instance-connect": {"SendSSHPublicKey"},
    "aws.lateral-movement.ec2-serial-console-send-ssh-public-key": {"SendSerialConsoleSSHPublicKey"},
    "aws.persistence.iam-backdoor-role": {"UpdateAssumeRolePolicy"},
    "aws.persistence.iam-backdoor-user": {"CreateAccessKey"},
    "aws.persistence.iam-create-admin-user": {"AttachUserPolicy"},
    "aws.persistence.iam-create-backdoor-role": {"AttachRolePolicy"},
    "aws.persistence.iam-create-user-login-profile": {"CreateLoginProfile"},
    "aws.persistence.lambda-backdoor-function": {"AddPermission20150331v2"},
    "aws.persistence.lambda-layer-extension": {"UpdateFunctionConfiguration20150331v2"},
    "aws.persistence.lambda-overwrite-code": {"UpdateFunctionCode20150331v2"},
    "aws.persistence.rolesanywhere-create-trust-anchor": {"CreateTrustAnchor"},
    "aws.persistence.sts-federation-token": {"GetFederationToken"},
    "aws.privilege-escalation.iam-update-user-login-profile": {"UpdateLoginProfile"},
}


class ProjectionError(ValueError):
    """An untrusted source record cannot be projected safely."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--revision", default=SOURCE_REVISION)
    parser.add_argument("--split", choices=("development",), default="development")
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


def required_text(value: object, code: str, maximum: int = 240) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProjectionError(code)
    result = value.strip()
    if len(result.encode("utf-8")) > maximum:
        raise ProjectionError(code)
    return result


def bounded_value(value: object, *, depth: int = 0) -> object:
    if depth > MAX_DEPTH:
        raise ProjectionError("request_too_deep")
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ProjectionError("non_finite_request_value")
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            raise ProjectionError("request_value_too_large")
        return value
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("request_list_too_large")
        return [bounded_value(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS or any(not isinstance(key, str) for key in value):
            raise ProjectionError("invalid_request_object")
        return {key: bounded_value(item, depth=depth + 1) for key, item in value.items() if key in REQUEST_FIELDS}
    raise ProjectionError("unsupported_request_value")


def project_request(value: object) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ProjectionError("invalid_request_parameters")
    projected = bounded_value(value)
    if not isinstance(projected, dict):
        raise ProjectionError("invalid_request_parameters")
    if len(canonical_json(projected).encode("utf-8")) > MAX_REQUEST_BYTES:
        raise ProjectionError("request_parameters_too_large")
    return projected


def project_principal(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ProjectionError("invalid_principal")
    projected: dict[str, str] = {}
    for source_key, output_key in (
        ("type", "type"),
        ("accountId", "account_id"),
        ("arn", "arn"),
        ("principalId", "principal_id"),
        ("userName", "user_name"),
    ):
        item = value.get(source_key)
        if item is None:
            continue
        projected[output_key] = required_text(item, f"invalid_principal_{output_key}", 1024)
    if not projected:
        raise ProjectionError("empty_principal")
    return projected


def project_resources(value: object) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ProjectionError("invalid_resources")
    result: list[dict[str, str]] = []
    for resource in value:
        if not isinstance(resource, dict):
            raise ProjectionError("invalid_resource")
        projected: dict[str, str] = {}
        for source_key, output_key in (("ARN", "arn"), ("accountId", "account_id"), ("type", "type")):
            if source_key in resource:
                projected[output_key] = required_text(resource[source_key], f"invalid_resource_{output_key}", 2048)
        if projected:
            result.append(projected)
    return result


def parse_time(value: object) -> datetime:
    text = required_text(value, "invalid_event_time", 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProjectionError("invalid_event_time") from exc
    if parsed.tzinfo is None:
        raise ProjectionError("event_time_without_timezone")
    return parsed


def event_projection(row: Mapping[str, Any], technique: str) -> dict[str, Any]:
    event_name = required_text(row.get("eventName"), "invalid_event_name", 160)
    event_source = required_text(row.get("eventSource"), "invalid_event_source", 160)
    event_id = required_text(row.get("eventID"), "invalid_event_id", 240)
    request_id = row.get("requestID")
    if request_id is not None:
        request_id = required_text(request_id, "invalid_request_id", 240)
    if not SAFE_NAME.fullmatch(event_name) or not SAFE_NAME.fullmatch(event_source):
        raise ProjectionError("unsafe_operation_identity")
    if not SAFE_ID.fullmatch(event_id) or (request_id and not SAFE_ID.fullmatch(request_id)):
        raise ProjectionError("unsafe_event_identity")
    event_time = parse_time(row.get("eventTime"))
    error_code = row.get("errorCode")
    error_message = row.get("errorMessage")
    if error_code is not None:
        error_code = required_text(error_code, "invalid_error_code", 240)
    if error_message is not None and not isinstance(error_message, str):
        raise ProjectionError("invalid_error_message")
    failed = error_code is not None
    status: dict[str, object] = {
        "outcome": "failed" if failed else "succeeded",
        "error_code": error_code,
        "error_message_present": error_message is not None,
    }
    if error_message is not None:
        encoded = error_message.encode("utf-8")
        status["error_message_bytes"] = len(encoded)
        status["error_message_sha256"] = hashlib.sha256(encoded).hexdigest()
    args: dict[str, object] = {
        "provider": "aws",
        "event_name": event_name,
        "event_source": event_source,
        "event_id": event_id,
        "event_time": row["eventTime"],
        "region": required_text(row.get("awsRegion"), "invalid_region", 120),
        "principal": project_principal(row.get("userIdentity")),
        "request_parameters": project_request(row.get("requestParameters")),
        "status": status,
        "technique": technique,
    }
    if request_id is not None:
        args["request_id"] = request_id
    resources = project_resources(row.get("resources"))
    if resources:
        args["resources"] = resources
    return {
        "event_id": event_id,
        "event_name": event_name,
        "event_source": event_source,
        "event_time": event_time,
        "args": args,
        "outcome": "failed" if failed else "succeeded",
    }


def technique_from_path(path: Path) -> tuple[str, str]:
    if path.suffix != ".json":
        raise ProjectionError("unsupported_source_file")
    technique = path.stem
    if technique not in TECHNIQUE_OPERATIONS:
        raise ProjectionError("unknown_technique")
    parts = technique.split(".")
    if len(parts) < 3 or parts[0] != "aws":
        raise ProjectionError("invalid_technique")
    return technique, parts[1]


def is_target(event: Mapping[str, Any], technique: str) -> bool:
    return str(event["event_name"]) in TECHNIQUE_OPERATIONS[technique]


def request(event: Mapping[str, Any]) -> Mapping[str, Any]:
    args = event["args"]
    assert isinstance(args, dict)
    value = args["request_parameters"]
    assert isinstance(value, dict)
    return value


def exact_closure(event: Mapping[str, Any], technique: str) -> bool:
    """Return true only for terminal effects with a closed request proof."""
    if event["outcome"] != "succeeded" or not is_target(event, technique):
        return False
    name = event["event_name"]
    params = request(event)
    if name in {"DeleteTrail", "StopLogging", "DeleteResolverQueryLogConfig"}:
        return bool(params)
    if name == "DeleteFlowLogs":
        flow_logs = params.get("DeleteFlowLogsRequest")
        return isinstance(flow_logs, dict) and bool(flow_logs.get("FlowLogId"))
    if name == "PutEventSelectors":
        selectors = params.get("eventSelectors")
        return isinstance(selectors, list) and any(
            isinstance(item, dict) and item.get("includeManagementEvents") is False for item in selectors
        )
    if name == "AuthorizeSecurityGroupIngress":
        cidr = params.get("cidrIp")
        try:
            world_scope = isinstance(cidr, str) and ipaddress.ip_network(cidr, strict=False).prefixlen == 0
        except ValueError:
            world_scope = False
        direct = world_scope and params.get("fromPort") == 22 and params.get("toPort") == 22
        permissions = params.get("ipPermissions")
        nested = isinstance(permissions, list) and any(
            isinstance(item, dict)
            and item.get("fromPort") == 22
            and item.get("toPort") == 22
            and "0.0.0.0/0" in canonical_json(item)
            for item in permissions
        )
        return direct or nested
    if name in {"ModifyImageAttribute", "ModifySnapshotAttribute", "ModifyDBSnapshotAttribute"}:
        args = event["args"]
        assert isinstance(args, dict)
        principal = args.get("principal")
        account = principal.get("account_id") if isinstance(principal, dict) else None
        identifiers = re.findall(r'"(?:userId|valuesToAdd)":(?:\[)?"([0-9]{12}|all)"', canonical_json(params))
        return any(identifier == "all" or identifier != account for identifier in identifiers)
    if name == "AttachUserPolicy" or name == "AttachRolePolicy":
        policy = params.get("policyArn")
        return isinstance(policy, str) and policy.endswith("/AdministratorAccess")
    return False


def truth(event: Mapping[str, Any], technique: str) -> dict[str, Any]:
    categories = ["stratus_red_team", "aws_cloudtrail", technique]
    if exact_closure(event, technique):
        return {
            "source_truth": "malicious",
            "deterministic_truth": "deterministic_malicious",
            "label_confidence": "high",
            "label_source": "source:committed_detonation_exact_successful_operation",
            "applicability": "in_scope",
            "expected_disposition": "block",
            "categories": [*categories, "exact_terminal_operation"],
        }
    target = is_target(event, technique)
    return {
        "source_truth": "malicious" if target and event["outcome"] == "succeeded" else "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "high" if target else "medium",
        "label_source": (
            "source:committed_detonation_contextual_operation"
            if target
            else "source:committed_detonation_supporting_telemetry"
        ),
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "exclusion_reason": (
            "The event failed or does not independently close a deterministic malicious proof; "
            "responseElements null is never treated as success evidence."
        ),
        "categories": [*categories, "contextual_or_supporting_event"],
    }


def source_record(revision: str, original_id: str) -> dict[str, str]:
    return {
        "dataset": DATASET_ID,
        "revision": revision,
        "original_id": original_id,
        "license": SOURCE_LICENSE,
        "redistribution": SOURCE_REDISTRIBUTION,
    }


def strata(technique: str, tactic: str, event: Mapping[str, Any], trajectory: str, index: int) -> dict[str, Any]:
    return {
        "platform": "aws",
        "language": "english",
        "ecosystem": "aws_cloudtrail",
        "campaign": technique,
        "domain": tactic,
        "document_type": f"{event['event_source']}:{event['event_name']}",
        "split_group": digest(SOURCE_REVISION, technique)[:24],
        "trajectory_id": trajectory,
        "sequence_index": index,
        "call_index": 0,
    }


def event_payload(event: Mapping[str, Any], *, offset_seconds: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"tool_name": "aws.cloudtrail_event", "args": event["args"]}
    if offset_seconds is not None:
        result["outcome"] = event["outcome"]
        result["offset_seconds"] = offset_seconds
    return result


def normalize_directory(root: Path, revision: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError(f"revision must equal pinned revision {SOURCE_REVISION}")
    resolved = root.resolve(strict=True)
    logs = (resolved / SOURCE_SUBDIR).resolve(strict=True) if (resolved / SOURCE_SUBDIR).is_dir() else resolved
    if not logs.is_dir():
        raise ValueError("input directory does not contain Stratus detonation logs")
    paths = sorted(logs.glob("*.json"))
    if len(paths) != SOURCE_FILES or any(path.parent != logs for path in paths):
        raise ValueError(f"expected exactly {SOURCE_FILES} pinned detonation log files")

    source_hash = hashlib.sha256()
    for path in paths:
        data = path.read_bytes()
        if len(data) > MAX_FILE_BYTES:
            raise ValueError(f"source file too large: {path.name}")
        source_hash.update(path.name.encode("utf-8"))
        source_hash.update(b"\0")
        source_hash.update(data)
        source_hash.update(b"\0")
    if source_hash.hexdigest() != SOURCE_SHA256:
        raise ValueError("source detonation-log hash does not match pinned revision")

    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    operations: Counter[str] = Counter()
    techniques: Counter[str] = Counter()
    seen_events: set[tuple[str, str]] = set()
    for path in paths:
        technique, tactic = technique_from_path(path)
        try:
            raw = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=strict_object,
                parse_constant=reject_nonfinite,
            )
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
            raise ValueError(f"invalid JSON in {path.name}") from exc
        if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
            raise ValueError(f"{path.name} must contain a JSON event array")
        events = [event_projection(item, technique) for item in raw]
        events.sort(key=lambda item: (item["event_time"], item["event_id"]))
        trajectory = digest(revision, technique)[:24]
        for index, event in enumerate(events):
            identity = (technique, str(event["event_id"]))
            if identity in seen_events:
                raise ValueError(f"duplicate event identity: {technique}/{event['event_id']}")
            seen_events.add(identity)
            operation = f"{event['event_source']}:{event['event_name']}"
            operations[operation] += 1
            techniques[technique] += 1
            if event["outcome"] == "failed":
                counts["failed_events"] += 1
            else:
                counts["successful_events"] += 1
            if exact_closure(event, technique):
                counts["exact_closure_events"] += 1
            elif is_target(event, technique):
                counts["contextual_target_events"] += 1
            else:
                counts["supporting_events"] += 1

            original = f"{path.name}#{event['event_id']}"
            cases.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "id": f"stratus/{trajectory}/action-{index:04d}",
                    "source": source_record(revision, original),
                    "split": "development",
                    "surface": "action",
                    "payload": {"direction": "tool_call", **event_payload(event)},
                    "truth": truth(event, technique),
                    "strata": strata(technique, tactic, event, trajectory, index),
                }
            )
            counts["action_cases"] += 1

            prior = [
                candidate
                for candidate in events[:index]
                if (event["event_time"] - candidate["event_time"]).total_seconds() <= MAX_WINDOW_SECONDS
            ]
            window = [*prior[-(MAX_EVENTS - 1) :], event]
            if len(window) < 2:
                continue
            start = window[0]["event_time"]
            payload_events = [
                event_payload(item, offset_seconds=int((item["event_time"] - start).total_seconds())) for item in window
            ]
            cases.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "id": f"stratus/{trajectory}/window-{index:04d}",
                    "source": source_record(revision, f"{original}:window"),
                    "split": "development",
                    "surface": "stateful",
                    "payload": {"events": payload_events},
                    "truth": truth(event, technique),
                    "strata": strata(technique, tactic, event, trajectory, index),
                }
            )
            counts["stateful_cases"] += 1

    if counts["action_cases"] != SOURCE_EVENTS:
        raise ValueError(f"expected exactly {SOURCE_EVENTS} pinned events")
    cases.sort(key=lambda case: str(case["id"]))
    counts["cases"] = len(cases)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source_id": DATASET_ID,
        "source_url": SOURCE_URL,
        "source_revision": revision,
        "source_license": SOURCE_LICENSE,
        "source_sha256": SOURCE_SHA256,
        "source_files": len(paths),
        "source_events": SOURCE_EVENTS,
        "row_count": len(cases),
        "counts": dict(sorted(counts.items())),
        "operations": dict(sorted(operations.items())),
        "techniques": dict(sorted(techniques.items())),
        "normalization": (
            "Exact CloudTrail operation, bounded request parameters, principal/resource/request "
            "identities, explicit error status, timestamp, and order only. Response bodies, user "
            "agents, source addresses, credential fields, command/policy bodies, and prose excluded."
        ),
        "label_limitation": (
            "Committed detonation provenance is not atomic malicious proof. Only successful, "
            "closed terminal operations are authoritative; failed, discovery, setup, and dual-use "
            "events are contextual development-only cases. responseElements:null is ignored."
        ),
    }
    return cases, manifest


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path) -> None:
    import jsonschema

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for row in rows:
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"{row.get('id', '<unknown>')}:{location}: {errors[0].message}")


def write_outputs(cases: Sequence[dict[str, Any]], manifest: dict[str, Any], output: Path, manifest_path: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = "".join(canonical_json(case) + "\n" for case in cases)
    manifest["output_sha256"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    for path, content in (
        (output, serialized),
        (manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n"),
    ):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            handle.write(content)
            temporary = Path(handle.name)
        os.replace(temporary, path)


def main() -> int:
    args = parse_args()
    cases, manifest = normalize_directory(args.input_dir, args.revision)
    validate_cases(cases, args.schema)
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    write_outputs(cases, manifest, args.output, manifest_path)
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
