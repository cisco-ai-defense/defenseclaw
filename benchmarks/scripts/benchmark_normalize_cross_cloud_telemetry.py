#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize Cross-Platform Cloud Telemetry v2 into benchmark case-v1.

The corpus contains paired payload-present (``-y``) and payload-absent
(``-n``) trials.  It also contains derived query and CloudWatch exports.  This
adapter reads only the canonical ``*-logs.json`` files so the same provider
event is not counted repeatedly.

An attack-labelled file is trajectory evidence, not proof that every event is
malicious.  Only three payload-specific terminal effects have both a closed
resource identity and explicit structured success evidence.  All other attack
events and all controls remain development-only contextual cases.
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
import zipfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = "1"
DATASET_ID = "zenodo/19933893"
SOURCE_URL = "https://zenodo.org/records/19933893"
SOURCE_REVISION = "19933893"
SOURCE_LICENSE = "CC-BY-4.0"
SOURCE_REDISTRIBUTION = "download-only"
MAX_EVENTS = 8
MAX_WINDOW_SECONDS = 1800
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_VALUE_BYTES = 4096
MAX_ITEMS = 64
MAX_DEPTH = 8
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"

ARCHIVES = {
    "aws": {
        "name": "aws_logs_redacted.zip",
        "size": 45907326,
        "sha256": "f75046f8660e648981040d5180950867a7e82cb8b799708ff572a927d2d35f5b",
    },
    "azure": {
        "name": "azure_logs_redacted.zip",
        "size": 10356405,
        "sha256": "5a94d05e4877593bad1602a68a6f4e775f72323e9e408ae0d0480d7126789dee",
    },
    "gcp": {
        "name": "gcp_logs_redacted.zip",
        "size": 14931409,
        "sha256": "2765fedd91ce6a03c9a8d156a3d83e34dd493e7a366d0b38abd88a00ad10c5a4",
    },
}

ATTACK_SCRIPTS = {
    "name": "attack_scripts.zip",
    "size": 168198,
    "sha256": "4599be3e224f3b9b43e76ab4ec1bfa8e3b209ebe529fb218ae4e65dd22417900",
}

CANONICAL_NAME = re.compile(
    r"^(?P<provider>aws|azure|gcp)-(?P<technique>[a-z0-9_-]+)-"
    r"(?P<trial>[0-9]+|clean)-(?P<payload>[ny])-logs\.json$"
)
SAFE_OPERATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,239}$")

# These fields preserve bounded identity, scope, and policy-relevant values.
# Credentials, key material, command/content bodies, tokens, HTTP metadata,
# source addresses, user agents, and free-form messages are intentionally not
# present in this allowlist.
REQUEST_FIELDS = frozenset(
    {
        "action",
        "authorizationInfo",
        "bindings",
        "bucket",
        "bucketName",
        "cidrIp",
        "condition",
        "disk",
        "diskName",
        "dryRun",
        "force",
        "granted",
        "groupId",
        "instance",
        "instanceId",
        "location",
        "member",
        "members",
        "name",
        "object",
        "operation",
        "parent",
        "permission",
        "permissionType",
        "project",
        "projectId",
        "resource",
        "resourceAttributes",
        "role",
        "roleName",
        "scope",
        "type",
        "value",
        "values",
        "volumeId",
        "zone",
    }
)

# A closure must also be payload-specific in the paired corpus.  Broadly
# dangerous-looking teardown operations appearing in both arms are excluded.
EXACT_CLOSURES = {
    ("aws", "disk_wipe", "DeleteVolume"),
    ("azure", "account_access_removal", "Microsoft.Authorization/roleAssignments/delete"),
    ("gcp", "data_destruction", "storage.objects.delete"),
}

SCRIPT_EVIDENCE = {
    ("aws", "disk_wipe", "DeleteVolume"): (
        "attack_scripts/aws-attacks/attack_scripts/vm_attacks.sh",
        "aws ec2 delete-volume",
    ),
    ("azure", "account_access_removal", "Microsoft.Authorization/roleAssignments/delete"): (
        "attack_scripts/azure-attacks/215_account_access_removal_att_script.sh",
        "az role assignment delete",
    ),
    ("gcp", "data_destruction", "storage.objects.delete"): (
        "attack_scripts/gcp-attacks/attack-scripts/storage-attacks.py",
        "google.cloud.storage.Blob.delete",
    ),
}


class ProjectionError(ValueError):
    """A source record cannot be projected without weakening integrity."""

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
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def sha256_path(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ProjectionError(f"non_finite_json:{value}")


def required_text(value: object, code: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProjectionError(code)
    result = value.strip()
    if len(result.encode()) > maximum:
        raise ProjectionError(code)
    return result


def optional_text(value: object, code: str, maximum: int = 4096) -> str | None:
    if value in (None, ""):
        return None
    return required_text(value, code, maximum)


def actor_text(value: object, code: str, maximum: int = 2048) -> str | None:
    result = optional_text(value, code, maximum)
    if result is None:
        return None
    try:
        ipaddress.ip_address(result.strip("[]"))
    except ValueError:
        return result
    return None


def value_field(value: object) -> object:
    if isinstance(value, dict) and "value" in value:
        return value["value"]
    return value


def bounded_value(value: object, *, depth: int = 0) -> object:
    if depth > MAX_DEPTH:
        raise ProjectionError("value_too_deep")
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ProjectionError("non_finite_value")
        return value
    if isinstance(value, str):
        if len(value.encode()) > MAX_VALUE_BYTES:
            raise ProjectionError("value_too_large")
        return value
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("list_too_large")
        return [bounded_value(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS or any(not isinstance(key, str) for key in value):
            raise ProjectionError("invalid_object")
        return {key: bounded_value(item, depth=depth + 1) for key, item in value.items() if key in REQUEST_FIELDS}
    raise ProjectionError("unsupported_value")


def project_selected(value: object) -> object:
    projected = bounded_value(value)
    if len(canonical_json(projected).encode()) > 32 * 1024:
        raise ProjectionError("projected_value_too_large")
    return projected


def parse_time(value: object) -> datetime:
    text = required_text(value, "invalid_timestamp", 80)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProjectionError("invalid_timestamp") from exc
    if parsed.tzinfo is None:
        raise ProjectionError("timestamp_without_timezone")
    return parsed


def status_projection(outcome: str, evidence: str, code: object = None, message: object = None) -> dict[str, object]:
    result: dict[str, object] = {"outcome": outcome, "evidence": evidence}
    if code not in (None, "", 0):
        result["error_code"] = required_text(str(code), "invalid_error_code", 240)
    if message not in (None, ""):
        if not isinstance(message, str):
            raise ProjectionError("invalid_error_message")
        encoded = message.encode()
        result.update(
            {
                "error_message_present": True,
                "error_message_bytes": len(encoded),
                "error_message_sha256": hashlib.sha256(encoded).hexdigest(),
            }
        )
    return result


def aws_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    operation = required_text(row.get("eventName"), "missing_aws_operation", 240)
    service = required_text(row.get("eventSource"), "missing_aws_service", 240)
    timestamp_text = required_text(row.get("eventTime"), "missing_aws_time", 80)
    error_code = row.get("errorCode")
    response = row.get("responseElements")
    if error_code not in (None, ""):
        outcome = "failed"
    elif isinstance(response, dict) and response:
        outcome = "succeeded"
    else:
        outcome = "unknown"
    principal_source = row.get("userIdentity")
    principal: dict[str, str] = {}
    if isinstance(principal_source, dict):
        for source_key, output_key in (
            ("type", "type"),
            ("accountId", "account_id"),
            ("arn", "arn"),
            ("principalId", "principal_id"),
            ("userName", "user_name"),
            ("invokedBy", "invoked_by"),
        ):
            item = optional_text(principal_source.get(source_key), f"invalid_principal_{output_key}", 2048)
            if item is not None:
                principal[output_key] = item
    request = row.get("requestParameters") or {}
    if not isinstance(request, dict):
        raise ProjectionError("invalid_aws_request")
    args: dict[str, object] = {
        "provider": "aws",
        "event_source": service,
        "event_name": operation,
        "event_id": str(row.get("eventID") or digest(service, operation, timestamp_text)[:24]),
        "event_time": timestamp_text,
        "request_parameters": project_selected(request),
        "status": {
            "outcome": outcome,
            "error_code": optional_text(error_code, "invalid_error_code", 240),
            "error_message_present": row.get("errorMessage") not in (None, ""),
        },
    }
    if principal:
        args["principal"] = principal
    region = optional_text(row.get("awsRegion"), "invalid_aws_region", 120)
    if region:
        args["region"] = region
    request_id = optional_text(row.get("requestID"), "invalid_aws_request_id", 240)
    if request_id:
        args["request_id"] = request_id
    return {
        "tool_name": "aws.cloudtrail_event",
        "operation": operation,
        "service": service,
        "time": parse_time(timestamp_text),
        "outcome": outcome,
        "args": args,
    }


def azure_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    operation = required_text(value_field(row.get("operationName")), "missing_azure_operation", 240)
    timestamp_text = required_text(row.get("eventTimestamp"), "missing_azure_time", 80)
    status_text = str(value_field(row.get("status")) or "").strip()
    lowered = status_text.lower()
    if lowered == "succeeded":
        outcome, evidence = "succeeded", "azure_status_succeeded"
    elif lowered in {"failed", "canceled", "cancelled"}:
        outcome, evidence = "failed", f"azure_status_{lowered}"
    else:
        outcome, evidence = "unknown", f"azure_status_{lowered or 'missing'}"
    resource_id = optional_text(row.get("resourceId"), "invalid_azure_resource", 4096)
    authorization = row.get("authorization")
    projected_authorization: dict[str, str] = {}
    if isinstance(authorization, dict):
        for key in ("action", "scope"):
            item = optional_text(authorization.get(key), f"invalid_azure_authorization_{key}", 4096)
            if item:
                projected_authorization[key] = item
    args: dict[str, object] = {
        "provider": "azure",
        "service": str(value_field(row.get("resourceProviderName")) or operation.split("/", 1)[0]),
        "operation": operation,
        "timestamp": timestamp_text,
        "status": status_projection(outcome, evidence),
    }
    actor = actor_text(row.get("caller"), "invalid_azure_actor", 2048)
    if actor:
        args["actor"] = {"principal_id": actor}
    if resource_id:
        args["resources"] = [{"id": resource_id}]
    if projected_authorization:
        args["request"] = {"authorization": projected_authorization}
    for source, output in (("operationId", "operation_id"), ("correlationId", "correlation_id")):
        item = optional_text(row.get(source), f"invalid_azure_{output}", 240)
        if item:
            args[output] = item
    return {
        "tool_name": "azure.activity_event",
        "operation": operation,
        "service": str(args["service"]),
        "time": parse_time(timestamp_text),
        "outcome": outcome,
        "args": args,
    }


def gcp_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    payload = row.get("protoPayload")
    if not isinstance(payload, dict):
        raise ProjectionError("missing_gcp_proto_payload")
    operation = required_text(payload.get("methodName"), "missing_gcp_operation", 240)
    service = required_text(payload.get("serviceName"), "missing_gcp_service", 240)
    timestamp_text = required_text(row.get("timestamp"), "missing_gcp_time", 80)
    status = payload.get("status")
    if status == {}:
        outcome, evidence, error_code, error_message = "succeeded", "gcp_empty_status_success", None, None
    elif isinstance(status, dict) and (status.get("code") not in (None, 0) or status.get("message")):
        outcome, evidence = "failed", "gcp_structured_error"
        error_code, error_message = status.get("code"), status.get("message")
    else:
        outcome, evidence, error_code, error_message = "unknown", "gcp_status_missing", None, None
    authentication = payload.get("authenticationInfo")
    actor: dict[str, str] = {}
    if isinstance(authentication, dict):
        for source, output in (("principalEmail", "principal_email"), ("principalSubject", "principal_subject")):
            item = optional_text(authentication.get(source), f"invalid_gcp_{output}", 2048)
            if item:
                actor[output] = item
    resource_id = optional_text(payload.get("resourceName"), "invalid_gcp_resource", 4096)
    request = payload.get("request") or {}
    authorization = payload.get("authorizationInfo") or []
    if not isinstance(request, dict) or not isinstance(authorization, list):
        raise ProjectionError("invalid_gcp_request")
    args: dict[str, object] = {
        "provider": "gcp",
        "service": service,
        "operation": operation,
        "timestamp": timestamp_text,
        "request": {
            "parameters": project_selected(request),
            "authorization": project_selected(authorization),
        },
        "status": status_projection(outcome, evidence, error_code, error_message),
    }
    if actor:
        args["actor"] = actor
    if resource_id:
        args["resources"] = [{"id": resource_id}]
    return {
        "tool_name": "gcp.audit_event",
        "operation": operation,
        "service": service,
        "time": parse_time(timestamp_text),
        "outcome": outcome,
        "args": args,
    }


PROJECTORS = {"aws": aws_projection, "azure": azure_projection, "gcp": gcp_projection}


def parse_json_stream(data: bytes) -> list[dict[str, Any]]:
    """Parse an array, object, or concatenated arrays/objects from a member."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProjectionError("invalid_utf8") from exc
    decoder = json.JSONDecoder(object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    values: list[object] = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        try:
            value, offset = decoder.raw_decode(text, offset)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise ProjectionError("invalid_json") from exc
        values.extend(value if isinstance(value, list) else [value])
    if any(not isinstance(value, dict) for value in values):
        raise ProjectionError("event_not_object")
    return values  # type: ignore[return-value]


def safe_members(archive: zipfile.ZipFile, provider: str) -> list[zipfile.ZipInfo]:
    result: list[zipfile.ZipInfo] = []
    expanded = 0
    seen: set[str] = set()
    for info in archive.infolist():
        path = PurePosixPath(info.filename)
        if path.is_absolute() or ".." in path.parts or info.filename in seen:
            raise ValueError("unsafe or duplicate zip member")
        seen.add(info.filename)
        if info.is_dir():
            continue
        match = CANONICAL_NAME.fullmatch(path.name)
        if not match or match.group("provider") != provider:
            continue
        expanded += info.file_size
        if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
            raise ValueError(f"{provider} canonical members exceed expanded-size bound")
        if info.file_size > MAX_MEMBER_BYTES:
            raise ValueError(f"oversized canonical member: {info.filename}")
        result.append(info)
    return sorted(result, key=lambda info: info.filename)


def technique_name(raw: str) -> str:
    normalized = raw.removesuffix("-with-webapp")
    if normalized == "use_alternative_authenticationa_material":
        return "use_alternative_authentication_material"
    return normalized


def domain_for(technique: str) -> str:
    groups = {
        "impact": {
            "account_access_removal",
            "data_destruction",
            "data_encrypted_for_impact",
            "data_manipulation",
            "defacement",
            "disk_wipe",
            "endpoint_denial_of_service",
            "inhibit_system_recovery",
        },
        "credential_access": {
            "brute_force",
            "credentials_from_password_stores",
            "steal_application_access_token",
            "steal_web_session_cookie",
            "unsecured_credentials",
        },
        "persistence": {
            "account_manipulation",
            "create_account",
            "event_triggered_execution",
            "implant_internal_image",
            "scheduled_task_job",
            "traffic_signaling",
        },
        "collection": {"archive_collected_data", "automated_collection", "clipboard_data", "data_staged"},
        "execution": {"cloud_administration_command", "command_and_scripting_interpreter", "user_execution"},
        "exfiltration": {"automated_exfiltration", "scheduled_transfer"},
        "initial_access": {"drive_by_compromise", "exploit_public_facing_application", "valid_accounts"},
        "lateral_movement": {"exploitation_of_remote_services", "use_alternative_authentication_material"},
        "command_and_control": {"ingress_tool_transfer", "remote_access_software"},
        "privilege_escalation": {"access_token_manipulation"},
    }
    return next((domain for domain, names in groups.items() if technique in names), "other")


def resource_present(event: Mapping[str, Any]) -> bool:
    args = event["args"]
    if not isinstance(args, dict):
        return False
    resources = args.get("resources")
    if isinstance(resources, list) and any(isinstance(item, dict) and item.get("id") for item in resources):
        return True
    request = args.get("request") or args.get("request_parameters")
    return isinstance(request, dict) and any(key in canonical_json(request) for key in ("volumeId", "resource"))


def exact_closure(provider: str, technique: str, event: Mapping[str, Any], payload_present: bool) -> bool:
    if not payload_present or event["outcome"] != "succeeded" or not resource_present(event):
        return False
    return (provider, technique, str(event["operation"])) in EXACT_CLOSURES


def truth(provider: str, technique: str, event: Mapping[str, Any], payload_present: bool) -> dict[str, Any]:
    categories = ["cross_cloud_telemetry", provider, domain_for(technique), technique]
    if exact_closure(provider, technique, event, payload_present):
        return {
            "source_truth": "malicious",
            "deterministic_truth": "contextual_or_dual_use",
            "label_confidence": "high",
            "label_source": "source:paired_attack_specific_exact_successful_operation",
            "applicability": "out_of_scope",
            "expected_disposition": "detect_only",
            "exclusion_reason": (
                "The terminal operation is exact and attack-specific in this paired corpus, but the same "
                "single resource deletion or IAM removal is legitimate administration without protected-resource "
                "policy."
            ),
            "categories": [*categories, "exact_policy_relevant_terminal_operation"],
        }
    if not payload_present:
        return {
            "source_truth": "benign",
            "deterministic_truth": "contextual_or_dual_use",
            "label_confidence": "high",
            "label_source": "source:paired_control_payload_absent",
            "applicability": "out_of_scope",
            "expected_disposition": "detect_only",
            "exclusion_reason": (
                "The matched control omits the attack payload, but setup and teardown operations "
                "are not universal allow truth."
            ),
            "categories": [*categories, "paired_control"],
        }
    return {
        "source_truth": "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "medium",
        "label_source": "source:payload_trajectory_contextual_operation",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "exclusion_reason": (
            "Attack-file membership does not prove this supporting, failed, unresolved, or "
            "dual-use event is independently malicious."
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


def event_payload(event: Mapping[str, Any], *, offset_seconds: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"tool_name": event["tool_name"], "args": event["args"]}
    if offset_seconds is not None:
        result.update({"outcome": event["outcome"], "offset_seconds": offset_seconds})
    return result


def normalize_directory(root: Path, revision: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError(f"revision must equal immutable Zenodo record {SOURCE_REVISION}")
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("input path must be a directory")
    archive_paths: dict[str, Path] = {}
    archive_manifest: dict[str, object] = {}
    scripts_path = (resolved / str(ATTACK_SCRIPTS["name"])).resolve(strict=True)
    try:
        scripts_path.relative_to(resolved)
    except ValueError as exc:
        raise ValueError("attack-script path escapes input directory") from exc
    if scripts_path.stat().st_size != ATTACK_SCRIPTS["size"] or sha256_path(scripts_path) != ATTACK_SCRIPTS["sha256"]:
        raise ValueError("attack-script archive does not match immutable record")
    archive_manifest[str(ATTACK_SCRIPTS["name"])] = {
        "bytes": ATTACK_SCRIPTS["size"],
        "role": "workload_label_evidence",
        "sha256": ATTACK_SCRIPTS["sha256"],
    }
    for provider, metadata in ARCHIVES.items():
        path = (resolved / str(metadata["name"])).resolve(strict=True)
        try:
            path.relative_to(resolved)
        except ValueError as exc:
            raise ValueError("archive path escapes input directory") from exc
        if path.stat().st_size != metadata["size"] or sha256_path(path) != metadata["sha256"]:
            raise ValueError(f"{provider} archive does not match immutable record")
        archive_paths[provider] = path
        archive_manifest[str(metadata["name"])] = {
            "bytes": metadata["size"],
            "role": "provider_audit_telemetry",
            "sha256": metadata["sha256"],
        }

    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    operations: Counter[str] = Counter()
    techniques: Counter[str] = Counter()
    domains: Counter[str] = Counter()
    result_strata: Counter[str] = Counter()
    providers: Counter[str] = Counter()
    rejected: Counter[str] = Counter()
    for provider, archive_path in archive_paths.items():
        with zipfile.ZipFile(archive_path) as archive:
            members = safe_members(archive, provider)
            counts[f"{provider}_canonical_files"] = len(members)
            for info in members:
                match = CANONICAL_NAME.fullmatch(PurePosixPath(info.filename).name)
                assert match is not None
                technique = technique_name(match.group("technique"))
                payload_present = match.group("payload") == "y"
                logging_profile = PurePosixPath(info.filename).parts[-2].removesuffix("-logs")
                try:
                    rows = parse_json_stream(archive.read(info))
                except ProjectionError as exc:
                    rejected[f"file:{exc.code}"] += 1
                    continue
                events: list[dict[str, Any]] = []
                for source_index, row in enumerate(rows):
                    try:
                        event = PROJECTORS[provider](row)
                    except ProjectionError as exc:
                        rejected[f"event:{exc.code}"] += 1
                        continue
                    event["source_index"] = source_index
                    events.append(event)
                events.sort(key=lambda event: (event["time"], event["source_index"], event["operation"]))
                trajectory = digest(revision, info.filename)[:24]
                for sequence_index, event in enumerate(events):
                    operation_key = f"{provider}:{event['service']}:{event['operation']}"
                    operations[operation_key] += 1
                    techniques[f"{provider}:{technique}"] += 1
                    domains[domain_for(technique)] += 1
                    result_strata[f"{provider}:{event['outcome']}"] += 1
                    providers[provider] += 1
                    counts["payload_present_events" if payload_present else "control_events"] += 1
                    closure = exact_closure(provider, technique, event, payload_present)
                    counts["exact_closure_events" if closure else "contextual_events"] += 1
                    original = f"{info.filename}#{event['source_index']}"
                    strata = {
                        "platform": provider,
                        "language": "english",
                        "ecosystem": f"{provider}_audit_log",
                        "campaign": technique,
                        "domain": domain_for(technique),
                        "document_type": str(event["operation"])[:160],
                        "hard_negative": not payload_present,
                        "split_group": digest(revision, provider, technique)[:24],
                        "trajectory_id": trajectory,
                        "sequence_index": sequence_index,
                        "call_index": 0,
                    }
                    case_id = f"cross-cloud/{trajectory}/action-{sequence_index:05d}"
                    cases.append(
                        {
                            "schema_version": SCHEMA_VERSION,
                            "id": case_id,
                            "source": source_record(revision, original),
                            "split": "development",
                            "surface": "action",
                            "payload": {"direction": "tool_call", **event_payload(event)},
                            "truth": truth(provider, technique, event, payload_present),
                            "strata": strata,
                        }
                    )
                    counts["action_cases"] += 1
                    prior = [
                        candidate
                        for candidate in events[:sequence_index]
                        if 0 <= (event["time"] - candidate["time"]).total_seconds() <= MAX_WINDOW_SECONDS
                    ]
                    window = [*prior[-(MAX_EVENTS - 1) :], event]
                    if len(window) < 2:
                        continue
                    start = window[0]["time"]
                    payload_events = [
                        event_payload(item, offset_seconds=int((item["time"] - start).total_seconds()))
                        for item in window
                    ]
                    stateful = dict(cases[-1])
                    stateful.update(
                        {
                            "id": f"cross-cloud/{trajectory}/window-{sequence_index:05d}",
                            "source": source_record(revision, f"{original}:window"),
                            "surface": "stateful",
                            "payload": {"events": payload_events},
                        }
                    )
                    stateful["strata"] = {**strata, "document_type": f"{logging_profile}:{event['operation']}"[:160]}
                    cases.append(stateful)
                    counts["stateful_cases"] += 1

    cases.sort(key=lambda case: str(case["id"]))
    counts["cases"] = len(cases)
    statistics = dict(sorted(counts.items()))
    for prefix, counter in (
        ("rejected", rejected),
        ("operation", operations),
        ("technique", techniques),
        ("domain", domains),
        ("result", result_strata),
        ("provider", providers),
    ):
        statistics.update({f"{prefix}:{key}": value for key, value in sorted(counter.items())})
    source_sha256 = digest(
        *(f"{name}:{metadata['sha256']}" for name, metadata in sorted(archive_manifest.items()))
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET_ID],
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {"cross-cloud-telemetry-v1": statistics},
        "source": {
            "dataset": DATASET_ID,
            "revision": revision,
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
            "path": "pinned Zenodo archives",
            "paths": sorted(archive_manifest),
            "bytes": sum(int(metadata["bytes"]) for metadata in archive_manifest.values()),
            "files": len(archive_manifest),
            "sha256": source_sha256,
            "source_url": SOURCE_URL,
        },
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
    manifest["output_sha256"] = hashlib.sha256(serialized.encode()).hexdigest()
    for path, content in ((output, serialized), (manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            handle.write(content)
            temporary = Path(handle.name)
        os.replace(temporary, path)


def main() -> int:
    args = parse_args()
    cases, manifest = normalize_directory(args.input_dir, args.revision)
    validate_cases(cases, args.schema)
    write_outputs(cases, manifest, args.output, args.manifest or args.output.with_suffix(".manifest.json"))
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
