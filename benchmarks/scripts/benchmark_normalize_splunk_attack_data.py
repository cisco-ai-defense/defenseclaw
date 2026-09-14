#!/usr/bin/env python3
# ruff: noqa: E501 -- pinned public provenance paths and hashes are intentionally literal.
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize a pinned, targeted slice of public Splunk Attack Data.

This adapter intentionally does not ingest the whole repository.  It accepts
only an audited set of small endpoint and Kubernetes files, verifies every
file against the pinned revision, and projects only fields needed for a
deterministic proof.  Process creation proves that a command started, not that
its requested mutation completed; those records remain contextual.  A record
is authoritative only when consequence telemetry proves the exact security-
control mutation completed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NamedTuple

SCHEMA_VERSION = "1"
DATASET_ID = "splunk/attack_data"
SOURCE_URL = "https://github.com/splunk/attack_data"
SOURCE_REVISION = "be1980668e58497d23ba77ba25769996c4d1efaa"
SOURCE_LICENSE = "Apache-2.0"
SOURCE_REDISTRIBUTION = "download-only"
MAX_EVENTS = 8
MAX_WINDOW_SECONDS = 1800
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_COMMAND_BYTES = 16 * 1024
MAX_VALUE_BYTES = 4096
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"


class Subset(NamedTuple):
    key: str
    data_path: str
    metadata_path: str
    platform: str
    domain: str
    format: str


SUBSETS = (
    Subset(
        "defender_exclusion_effect",
        "datasets/attack_techniques/T1562.001/defender_exclusion_defender_operational_wineventlog/defender_operational_wineventlog.log",
        "datasets/attack_techniques/T1562.001/defender_exclusion_defender_operational_wineventlog/defender_exclusion_defender_operational_wineventlog_old.yml",
        "windows",
        "security_control_tamper",
        "xml",
    ),
    Subset(
        "defender_exclusion_process_and_registry",
        "datasets/attack_techniques/T1562.001/defender_exclusion_sysmon/sysmon.log",
        "datasets/attack_techniques/T1562.001/defender_exclusion_sysmon/defender_exclusion_sysmon.yml",
        "windows",
        "security_control_tamper",
        "xml",
    ),
    Subset(
        "defender_logging_disable",
        "datasets/attack_techniques/T1562.001/disable_defender_logging/sysmon.log",
        "datasets/attack_techniques/T1562.001/disable_defender_logging/disable_defender_logging.yml",
        "windows",
        "logging_tamper",
        "xml",
    ),
    Subset(
        "audit_policy_security",
        "datasets/attack_techniques/T1562.002/auditpol_tampering/auditpol_tampering_security.log",
        "datasets/attack_techniques/T1562.002/auditpol_tampering/auditpol_tampering.yml",
        "windows",
        "audit_tamper",
        "xml",
    ),
    Subset(
        "audit_policy_sysmon",
        "datasets/attack_techniques/T1562.002/auditpol_tampering/auditpol_tampering_sysmon.log",
        "datasets/attack_techniques/T1562.002/auditpol_tampering/auditpol_tampering.yml",
        "windows",
        "audit_tamper",
        "xml",
    ),
    Subset(
        "firewall_rule_registry_delete",
        "datasets/attack_techniques/T1112/firewall_modify_delete/firewall-mod-delete.log",
        "datasets/attack_techniques/T1112/firewall_modify_delete/firewall_modify_delete.yml",
        "windows",
        "firewall_tamper",
        "xml",
    ),
    Subset(
        "firewall_rule_delete_event",
        "datasets/attack_techniques/T1562.004/firewall_win_event/delete_rule/MPSSVC_Rule-Level_Policy_Change-4948.log",
        "datasets/attack_techniques/T1562.004/firewall_win_event/delete_rule/delete_rule_old.yml",
        "windows",
        "firewall_tamper",
        "xml",
    ),
    Subset(
        "credential_store_delete_process",
        "datasets/attack_techniques/T1555/cmdkey_delete_credentials_store/cmdkey_del_sys.log",
        "datasets/attack_techniques/T1555/cmdkey_delete_credentials_store/cmdkey_delete_credentials_store_old.yml",
        "windows",
        "credential_store",
        "xml",
    ),
    Subset(
        "kubernetes_privileged_pod",
        "datasets/attack_techniques/T1204/kubernetes_privileged_pod/kubernetes_privileged_pod.json",
        "datasets/attack_techniques/T1204/kubernetes_privileged_pod/kubernetes_privileged_pod.yml",
        "kubernetes",
        "privileged_workload",
        "json",
    ),
    Subset(
        "kubernetes_daemonset",
        "datasets/attack_techniques/T1204/kubernetes_audit_daemonset_created/kubernetes_audit_daemonset_created.json",
        "datasets/attack_techniques/T1204/kubernetes_audit_daemonset_created/kubernetes_audit_daemonset_created.yml",
        "kubernetes",
        "persistence",
        "json",
    ),
    Subset(
        "kubernetes_cronjob",
        "datasets/attack_techniques/T1053.007/kubernetes_audit_cron_job_creation/kubernetes_audit_cron_job_creation.json",
        "datasets/attack_techniques/T1053.007/kubernetes_audit_cron_job_creation/kubernetes_audit_cron_job_creation.yml",
        "kubernetes",
        "persistence",
        "json",
    ),
    Subset(
        "kubernetes_unauthorized_denied",
        "datasets/attack_techniques/T1204/kubernetes_unauthorized_access/kubernetes_unauthorized_access.json",
        "datasets/attack_techniques/T1204/kubernetes_unauthorized_access/kubernetes_unauthorized_access.yml",
        "kubernetes",
        "authorization",
        "json",
    ),
    Subset(
        "mysql_shell_process",
        "datasets/attack_techniques/T1548/mysql/sysmon_linux.log",
        "datasets/attack_techniques/T1548/mysql/mysql.yml",
        "linux",
        "sql_execution",
        "xml",
    ),
    Subset(
        "sqlite_shell_process",
        "datasets/attack_techniques/T1548/sqlite3/sysmon_linux.log",
        "datasets/attack_techniques/T1548/sqlite3/sqlite3.yml",
        "linux",
        "sql_execution",
        "xml",
    ),
)

# Actual SHA-256 values of the Git LFS payloads and metadata at SOURCE_REVISION.
EXPECTED_SHA256 = {
    "datasets/attack_techniques/T1053.007/kubernetes_audit_cron_job_creation/kubernetes_audit_cron_job_creation.json": "9826b39d9c2d2998f7313414980429af6600ee8db118cec80dabb81461ee5974",
    "datasets/attack_techniques/T1053.007/kubernetes_audit_cron_job_creation/kubernetes_audit_cron_job_creation.yml": "4df327e45048d47b0df362e585cfd915a208b65a51fa212f2ce65597cc4fd176",
    "datasets/attack_techniques/T1112/firewall_modify_delete/firewall-mod-delete.log": "ac2b4ab4628203e0fe7ee7a52d77bc9451f094c94e09f21e3add1e0cf406c7da",
    "datasets/attack_techniques/T1112/firewall_modify_delete/firewall_modify_delete.yml": "908545bf31f935b1cc1436f1c48914bd9f022226d98bfb58b233bc2764b0290e",
    "datasets/attack_techniques/T1204/kubernetes_audit_daemonset_created/kubernetes_audit_daemonset_created.json": "ed7b4fc9ab8c5b26db18bd241e413893f2e21e52e34a9259c0123407dcc49895",
    "datasets/attack_techniques/T1204/kubernetes_audit_daemonset_created/kubernetes_audit_daemonset_created.yml": "cd6ae6db9e33d10a9a023c13e8b1c4a2a103ab2eb4bb92735b21d0ec965e515d",
    "datasets/attack_techniques/T1204/kubernetes_privileged_pod/kubernetes_privileged_pod.json": "7d82ba47ac8df48a7c2256406e4afe32f43dc0836c8aaeca876079831bb51e6e",
    "datasets/attack_techniques/T1204/kubernetes_privileged_pod/kubernetes_privileged_pod.yml": "9aa77c9bab0c098c3721169a8c902276bbe2ab2ce05829cea34936f032026d69",
    "datasets/attack_techniques/T1204/kubernetes_unauthorized_access/kubernetes_unauthorized_access.json": "dff87213032a06345d98bac6b26f7486080e17b9e744f38b2bf6553bc0bae65f",
    "datasets/attack_techniques/T1204/kubernetes_unauthorized_access/kubernetes_unauthorized_access.yml": "4fc0ad7be351d26c7bba443cae71341ed4b25d19d33dd5d5d16a891b6947b9e2",
    "datasets/attack_techniques/T1548/mysql/mysql.yml": "d5d14ad2ef5e65f27cce5320217adad7ce1bdbdd6b24f65db12150d9e06dd3aa",
    "datasets/attack_techniques/T1548/mysql/sysmon_linux.log": "76e048a0fa814602e87dca01d81d2eb29cf54cdd7802b4b49d1ddac192b4d6c0",
    "datasets/attack_techniques/T1548/sqlite3/sqlite3.yml": "097518dbb3e2c3038ae0e115140c4748519781b1d6bf3b96433c47514cfd1df8",
    "datasets/attack_techniques/T1548/sqlite3/sysmon_linux.log": "b386156cb7d13a99e081cbb1058f892530a71f9b8e134ec31d6a7f95a5ea51cc",
    "datasets/attack_techniques/T1555/cmdkey_delete_credentials_store/cmdkey_del_sys.log": "ffc7ce78b4f480507f25eb52c7009e8ed238fb96bc97740c01a33d23b1a29069",
    "datasets/attack_techniques/T1555/cmdkey_delete_credentials_store/cmdkey_delete_credentials_store_old.yml": "d24417dee49062ab7f1d91b5bff621edcc1766aecccfab2b37198876b0cfd306",
    "datasets/attack_techniques/T1562.001/defender_exclusion_defender_operational_wineventlog/defender_exclusion_defender_operational_wineventlog_old.yml": "e8df5d5afb1627034c323b01f04ba5d951b91b140fddc70b6e8614637e92448c",
    "datasets/attack_techniques/T1562.001/defender_exclusion_defender_operational_wineventlog/defender_operational_wineventlog.log": "e49ea1bdb0d05ec52f1a91164edb5849c110ec4a53cdba41081ac7fc52a63145",
    "datasets/attack_techniques/T1562.001/defender_exclusion_sysmon/defender_exclusion_sysmon.yml": "c8fa153c95b8c9001dbafdefe83a46a1d182e688a5e3701aafc21691a599d4f9",
    "datasets/attack_techniques/T1562.001/defender_exclusion_sysmon/sysmon.log": "9898052d0f26516f344af733a7f58bcfe863848cdf1195549d94737c350bcd28",
    "datasets/attack_techniques/T1562.001/disable_defender_logging/disable_defender_logging.yml": "63ad9f4f221c685837c028087701282f6c765d3115d991522339b864a153eb6f",
    "datasets/attack_techniques/T1562.001/disable_defender_logging/sysmon.log": "5a4b56945aa8474bb3b9ce30b22469a77f821a24c040447c0f1b557051a0c64b",
    "datasets/attack_techniques/T1562.002/auditpol_tampering/auditpol_tampering.yml": "c10422db2b9c81f987f4651fddb2ef980d4853a03f35d7bde31bd982274504d2",
    "datasets/attack_techniques/T1562.002/auditpol_tampering/auditpol_tampering_security.log": "72676e3ca8de940f4eb181c3642c4f3ce3df5fea2e5a4da29d346ea562ab4045",
    "datasets/attack_techniques/T1562.002/auditpol_tampering/auditpol_tampering_sysmon.log": "a417ec3d8d48c9cdcf4d5bcfc834fe100ba8a03105bcf08305f5af40a830b363",
    "datasets/attack_techniques/T1562.004/firewall_win_event/delete_rule/MPSSVC_Rule-Level_Policy_Change-4948.log": "ae7eb20a84350d696b605bb540e9f93fb545ed4b6f2f31a247ed9819df19f54d",
    "datasets/attack_techniques/T1562.004/firewall_win_event/delete_rule/delete_rule_old.yml": "18905818cd442e7e9173664c71abaca29d46fe3a0c3fb8b031a2add5363aa28d",
}

REJECTED_SUBSETS = {
    "datasets/attack_techniques/T1059.003/atomic_red_team": "SQL process creation has no result or consequence event.",
    "datasets/attack_techniques/T1505.001/simulation": "Simulation logs do not establish successful SQL persistence.",
    "datasets/attack_techniques/T1562.001/disable_defender_operational_wineventlog": "The files are collection-side activity, not a closed Defender-disable proof.",
    "datasets/attack_techniques/T1562.004/firewall_win_event/added_rule": "Adding a rule has no direction or exposure proof.",
    "datasets/attack_techniques/T1562.004/firewall_win_event/modify_rule": "The event does not establish that the modification weakened policy.",
    "datasets/attack_techniques/T1555/cmdkey_create_credential_store": "Credential creation is dual-use and only process-start telemetry is present.",
}


class ProjectionError(ValueError):
    """An untrusted source record cannot be projected safely."""


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


def bounded_text(value: object, field: str, maximum: int = MAX_VALUE_BYTES) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProjectionError(f"missing_{field}")
    result = value.strip()
    if len(result.encode()) > maximum:
        raise ProjectionError(f"oversized_{field}")
    return result


def local_name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def child(element: ET.Element, name: str) -> ET.Element | None:
    return next((item for item in element if local_name(item) == name), None)


def child_text(element: ET.Element, name: str, *, required: bool = True) -> str | None:
    item = child(element, name)
    if item is None or not item.text or not item.text.strip():
        if required:
            raise ProjectionError(f"missing_{name.lower()}")
        return None
    return bounded_text(item.text, name.lower())


def parse_time(value: str) -> datetime:
    match = re.fullmatch(r"(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)(?:\.(\d+))?Z?", value)
    if not match:
        raise ProjectionError("invalid_timestamp")
    fraction = (match.group(2) or "")[:6].ljust(6, "0")
    return datetime.fromisoformat(f"{match.group(1)}.{fraction}+00:00").astimezone(timezone.utc)


def event_data(root: ET.Element) -> dict[str, str]:
    container = child(root, "EventData")
    if container is None:
        return {}
    result: dict[str, str] = {}
    for item in container:
        if local_name(item) != "Data":
            continue
        name = item.attrib.get("Name")
        if not name or name in result:
            raise ProjectionError("invalid_event_data")
        value = item.text or ""
        if len(value.encode()) > MAX_COMMAND_BYTES:
            raise ProjectionError("oversized_event_value")
        result[name] = value
    return result


def parse_xml_events(path: Path) -> list[dict[str, Any]]:
    data = path.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        raise ProjectionError("oversized_source_file")
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ProjectionError("unsafe_xml_declaration")
    rows: list[dict[str, Any]] = []
    for line_number, raw in enumerate(data.splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise ProjectionError(f"invalid_xml_line_{line_number}") from exc
        system = child(root, "System")
        if system is None:
            raise ProjectionError("missing_system")
        provider_element = child(system, "Provider")
        time_element = child(system, "TimeCreated")
        execution_element = child(system, "Execution")
        provider = bounded_text(
            provider_element.attrib.get("Name") if provider_element is not None else None, "provider"
        )
        timestamp = bounded_text(
            time_element.attrib.get("SystemTime") if time_element is not None else None, "timestamp"
        )
        values = event_data(root)
        rows.append(
            {
                "provider": provider,
                "event_id": child_text(system, "EventID"),
                "record_id": child_text(system, "EventRecordID"),
                "timestamp": parse_time(timestamp),
                "host": child_text(system, "Computer"),
                "execution_process_id": execution_element.attrib.get("ProcessID")
                if execution_element is not None
                else None,
                "execution_thread_id": execution_element.attrib.get("ThreadID")
                if execution_element is not None
                else None,
                "data": values,
            }
        )
    return rows


def relevant_xml(subset: Subset, event: Mapping[str, Any]) -> bool:
    values = event["data"]
    assert isinstance(values, dict)
    command = str(values.get("CommandLine", ""))
    target = str(values.get("TargetObject", ""))
    combined = f"{command}\n{target}"
    if subset.key == "defender_exclusion_effect":
        return event["event_id"] == "5007" and "Windows Defender\\Exclusions\\" in str(values.get("New Value", ""))
    if subset.key == "defender_exclusion_process_and_registry":
        return ("MpPreference" in command and "Exclusion" in command) or "Windows Defender\\Exclusions\\" in target
    if subset.key == "defender_logging_disable":
        return "DefenderApiLogger" in combined or "DefenderAuditLogger" in combined
    if subset.key.startswith("audit_policy"):
        return command.lower().lstrip().startswith("auditpol") or event["event_id"] == "4719"
    if subset.key == "firewall_rule_registry_delete":
        return event["event_id"] in {"12", "13"} and "FirewallPolicy\\FirewallRules\\" in target
    if subset.key == "firewall_rule_delete_event":
        return event["event_id"] == "4948"
    if subset.key == "credential_store_delete_process":
        return event["event_id"] == "1" and "/delete:" in command.lower() and "cmdkey" in command.lower()
    if subset.key == "mysql_shell_process":
        return event["event_id"] == "1" and "mysql -e \\!" in command.lower()
    if subset.key == "sqlite_shell_process":
        return event["event_id"] == "1" and "sqlite3 " in command.lower() and " .shell " in command.lower()
    return False


def xml_projection(subset: Subset, event: Mapping[str, Any]) -> dict[str, Any]:
    values = event["data"]
    assert isinstance(values, dict)
    args: dict[str, Any] = {
        "provider": event["provider"],
        "event_id": event["event_id"],
        "record_id": event["record_id"],
        "host": event["host"],
        "timestamp": event["timestamp"].isoformat().replace("+00:00", "Z"),
    }
    mapping = {
        "User": "user",
        "SubjectUserName": "user",
        "SubjectDomainName": "user_domain",
        "ProcessGuid": "process_guid",
        "ProcessId": "process_id",
        "Image": "process_image",
        "ParentProcessGuid": "parent_process_guid",
        "ParentProcessId": "parent_process_id",
        "ParentImage": "parent_image",
        "EventType": "operation",
        "TargetObject": "resource",
        "New Value": "new_value",
        "Old Value": "old_value",
        "Details": "details",
        "ProfileChanged": "profile",
        "RuleId": "rule_id",
        "RuleName": "rule_name",
        "CategoryId": "category_id",
        "SubcategoryId": "subcategory_id",
        "SubcategoryGuid": "subcategory_guid",
        "AuditPolicyChanges": "audit_policy_changes",
        "ClientProcessId": "client_process_id",
        "SubjectLogonId": "logon_id",
    }
    for source, destination in mapping.items():
        value = values.get(source)
        if isinstance(value, str) and value.strip() and value.strip() != "-":
            args[destination] = bounded_text(value, destination)
    command = values.get("CommandLine")
    process_guid = values.get("ProcessGuid")
    identity = process_guid or f"{event['host']}:{event['record_id']}"
    return {
        "args": args,
        "command": bounded_text(command, "command", MAX_COMMAND_BYTES) if command else None,
        "dialect": command_dialect(str(command)) if command else None,
        "identity": digest(subset.key, str(identity))[:24],
        # Sysmon Event ID 1 is positive evidence that the exact process and
        # command line started. It does not prove the requested mutation, but
        # it is a successful predecessor for a same-process consequence join.
        "outcome": "succeeded" if exact_consequence(subset, event) or (event["event_id"] == "1" and command) else "unknown",
        "timestamp": event["timestamp"],
        "tool_name": "shell" if command else "windows.event",
    }


def command_dialect(command: str) -> str:
    lowered = command.lstrip().lower()
    if lowered.startswith(("powershell", "pwsh")):
        return "powershell"
    if "\\" in command or lowered.startswith(("auditpol", "cmdkey", "reg ")):
        return "cmd"
    return "posix"


def exact_consequence(subset: Subset, event: Mapping[str, Any]) -> bool:
    values = event["data"]
    assert isinstance(values, dict)
    if subset.key == "defender_exclusion_effect":
        return event["event_id"] == "5007" and "Windows Defender\\Exclusions\\" in str(values.get("New Value", ""))
    if subset.key == "defender_exclusion_process_and_registry":
        return (
            event["event_id"] == "13"
            and values.get("EventType") == "SetValue"
            and "Windows Defender\\Exclusions\\" in str(values.get("TargetObject", ""))
        )
    if subset.key == "defender_logging_disable":
        target = str(values.get("TargetObject", ""))
        details = str(values.get("Details", "")).lower()
        return (
            event["event_id"] == "13"
            and values.get("EventType") == "SetValue"
            and ("DefenderApiLogger" in target or "DefenderAuditLogger" in target)
            and ("0x00000000" in details or details.strip() == "0")
        )
    return False


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def safe_list(value: object, maximum: int = 16) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > maximum or any(not isinstance(item, dict) for item in value):
        raise ProjectionError("invalid_kubernetes_list")
    return value


def kubernetes_projection(subset: Subset, row: Mapping[str, Any]) -> dict[str, Any]:
    object_ref = row.get("objectRef")
    status = row.get("responseStatus")
    user = row.get("user")
    request = row.get("requestObject")
    if not isinstance(object_ref, dict) or not isinstance(status, dict) or not isinstance(user, dict):
        raise ProjectionError("invalid_kubernetes_event")
    code = status.get("code")
    if type(code) is not int:
        raise ProjectionError("invalid_kubernetes_status")
    args: dict[str, Any] = {
        "verb": bounded_text(row.get("verb"), "verb"),
        "stage": bounded_text(row.get("stage"), "stage"),
        "status_code": code,
        "user": bounded_text(user.get("username"), "user"),
        "resource": bounded_text(object_ref.get("resource"), "resource"),
    }
    for source in ("namespace", "name", "apiGroup", "apiVersion"):
        value = object_ref.get(source)
        if isinstance(value, str) and value.strip():
            args[source] = bounded_text(value, source)
    if isinstance(request, dict):
        spec = request.get("spec")
        if not isinstance(spec, dict):
            raise ProjectionError("invalid_kubernetes_spec")
        projected_spec: dict[str, Any] = {}
        for name in ("hostNetwork", "hostPID", "hostIPC", "suspend", "schedule"):
            value = spec.get(name)
            if type(value) in {bool, str}:
                projected_spec[name] = value
        containers = spec.get("containers")
        if containers is None:
            template = spec.get("template")
            if isinstance(template, dict):
                template_spec = template.get("spec")
                if isinstance(template_spec, dict):
                    containers = template_spec.get("containers")
                    for name in ("hostNetwork", "hostPID", "hostIPC"):
                        if type(template_spec.get(name)) is bool:
                            projected_spec[name] = template_spec[name]
        projected_containers = []
        for container in safe_list(containers):
            item: dict[str, Any] = {}
            for name in ("name", "image"):
                value = container.get(name)
                if isinstance(value, str) and value.strip():
                    item[name] = bounded_text(value, name)
            security = container.get("securityContext")
            if isinstance(security, dict) and type(security.get("privileged")) is bool:
                item["privileged"] = security["privileged"]
            if item:
                projected_containers.append(item)
        if projected_containers:
            projected_spec["containers"] = projected_containers
        volumes = spec.get("volumes")
        projected_volumes = []
        for volume in safe_list(volumes):
            host_path = volume.get("hostPath")
            if isinstance(host_path, dict) and isinstance(host_path.get("path"), str):
                projected_volumes.append({"host_path": bounded_text(host_path["path"], "host_path")})
        if projected_volumes:
            projected_spec["volumes"] = projected_volumes
        args["spec"] = projected_spec
    timestamp_text = row.get("stageTimestamp") or row.get("requestReceivedTimestamp")
    timestamp = parse_time(bounded_text(timestamp_text, "timestamp"))
    audit_id = bounded_text(row.get("auditID"), "audit_id")
    outcome = "succeeded" if 200 <= code < 300 else "denied" if code in {401, 403} else "failed"
    return {
        "args": args,
        "command": None,
        "dialect": None,
        "identity": digest(subset.key, audit_id)[:24],
        "outcome": outcome,
        "timestamp": timestamp,
        "tool_name": "kubernetes.audit",
    }


def read_kubernetes(path: Path, subset: Subset) -> list[dict[str, Any]]:
    data = path.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        raise ProjectionError("oversized_source_file")
    try:
        row = json.loads(data, object_pairs_hook=strict_object)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ProjectionError("invalid_json") from exc
    if not isinstance(row, dict):
        raise ProjectionError("invalid_kubernetes_event")
    return [kubernetes_projection(subset, row)]


def truth(subset: Subset, event: Mapping[str, Any]) -> dict[str, Any]:
    categories = ["splunk_attack_data", subset.domain, subset.key]
    if event["tool_name"] == "windows.event" and event["outcome"] == "succeeded" and subset.key in {
        "defender_exclusion_effect",
        "defender_exclusion_process_and_registry",
        "defender_logging_disable",
    }:
        return {
            "source_truth": "malicious",
            "deterministic_truth": "deterministic_malicious",
            "label_confidence": "high",
            "label_source": "source:attack_range_exact_consequence_event",
            "applicability": "in_scope",
            "expected_disposition": "block",
            "categories": [*categories, "exact_completed_security_control_mutation"],
        }
    source_truth = "unknown" if event["outcome"] in {"failed", "denied"} else "malicious"
    return {
        "source_truth": source_truth,
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "high" if event["outcome"] in {"succeeded", "denied"} else "medium",
        "label_source": "source:attack_range_contextual_telemetry",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "exclusion_reason": (
            "The event is denied, proves only process creation, or records a dual-use mutation without "
            "enough policy context to establish a deterministic malicious action."
        ),
        "categories": [*categories, "contextual_or_incomplete_result"],
    }


def source_record(revision: str, original_id: str) -> dict[str, str]:
    return {
        "dataset": DATASET_ID,
        "revision": revision,
        "original_id": original_id,
        "license": SOURCE_LICENSE,
        "redistribution": SOURCE_REDISTRIBUTION,
    }


def bounded_window_truth(event_truth: Mapping[str, Any], window: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    result = dict(event_truth)
    if event_truth["applicability"] != "in_scope":
        return result
    terminal_guid = str(window[-1].get("args", {}).get("process_guid", ""))
    has_exact_predecessor = bool(terminal_guid) and any(
        item.get("tool_name") == "shell"
        and item.get("outcome") == "succeeded"
        and item.get("args", {}).get("process_guid") == terminal_guid
        for item in window[:-1]
    )
    if has_exact_predecessor:
        result["categories"] = [*result["categories"], "same_process_request_consequence_chain"]
        return result
    result.update(
        {
            "deterministic_truth": "contextual_or_dual_use",
            "applicability": "out_of_scope",
            "expected_disposition": "detect_only",
            "exclusion_reason": "The window repeats an atomic consequence but does not contain a same-process request-to-consequence proof.",
            "categories": [*result["categories"], "no_distinct_bounded_chain_proof"],
        }
    )
    return result


def payload(event: Mapping[str, Any], *, stateful: bool = False, offset_seconds: int = 0) -> dict[str, Any]:
    result: dict[str, Any] = {"tool_name": event["tool_name"], "args": event["args"]}
    if event.get("command"):
        result["command"] = event["command"]
        result["dialect"] = event["dialect"]
    if stateful:
        result["outcome"] = event["outcome"]
        result["offset_seconds"] = offset_seconds
    return result


def checked_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"source path escapes input directory: {relative}") from exc
    return candidate


def normalize_directory(root: Path, revision: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError(f"revision must equal pinned revision {SOURCE_REVISION}")
    resolved = root.resolve(strict=True)
    hashes: dict[str, str] = {}
    for relative, expected in EXPECTED_SHA256.items():
        path = checked_path(resolved, relative)
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"source hash mismatch: {relative}")
        hashes[relative] = actual

    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    subset_counts: Counter[str] = Counter()
    for subset in SUBSETS:
        path = checked_path(resolved, subset.data_path)
        if subset.format == "xml":
            raw_events = parse_xml_events(path)
            counts["source_events"] += len(raw_events)
            events = [xml_projection(subset, item) for item in raw_events if relevant_xml(subset, item)]
        else:
            events = read_kubernetes(path, subset)
            counts["source_events"] += len(events)
        events.sort(key=lambda item: (item["timestamp"], item["identity"]))
        subset_counts[subset.key] = len(events)
        counts["selected_events"] += len(events)
        trajectory = digest(revision, subset.key)[:24]
        for index, event in enumerate(events):
            event_truth = truth(subset, event)
            original = f"{subset.data_path}#{event['identity']}"
            strata = {
                "platform": subset.platform,
                "language": "english",
                "ecosystem": "splunk_attack_data",
                "campaign": subset.key,
                "domain": subset.domain,
                "document_type": event["tool_name"],
                "split_group": trajectory,
                "trajectory_id": trajectory,
                "sequence_index": index,
                "call_index": 0,
            }
            cases.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "id": f"splunk-attack-data/{trajectory}/action-{index:04d}",
                    "source": source_record(revision, original),
                    "split": "development",
                    "surface": "action",
                    "payload": {"direction": "tool_call", **payload(event)},
                    "truth": event_truth,
                    "strata": strata,
                }
            )
            counts["action_cases"] += 1
            if event_truth["applicability"] == "in_scope":
                counts["action_authoritative_cases"] += 1
            else:
                counts["action_contextual_cases"] += 1

            prior = [
                candidate
                for candidate in events[:index]
                if (event["timestamp"] - candidate["timestamp"]).total_seconds() <= MAX_WINDOW_SECONDS
            ]
            window = [*prior[-(MAX_EVENTS - 1) :], event]
            if len(window) < 2:
                continue
            start = window[0]["timestamp"]
            window_truth = bounded_window_truth(event_truth, window)
            cases.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "id": f"splunk-attack-data/{trajectory}/window-{index:04d}",
                    "source": source_record(revision, f"{original}:window"),
                    "split": "development",
                    "surface": "stateful",
                    "payload": {
                        "events": [
                            payload(
                                item,
                                stateful=True,
                                offset_seconds=int((item["timestamp"] - start).total_seconds()),
                            )
                            for item in window
                        ]
                    },
                    "truth": window_truth,
                    "strata": strata,
                }
            )
            counts["stateful_cases"] += 1
            if window_truth["applicability"] == "in_scope":
                counts["stateful_authoritative_cases"] += 1
            else:
                counts["stateful_contextual_cases"] += 1

    cases.sort(key=lambda item: item["id"])
    counts["cases"] = len(cases)
    combined_hash = digest(*(f"{path}:{value}" for path, value in sorted(hashes.items())))
    statistics = dict(sorted(counts.items()))
    statistics.update({f"subset:{key}": value for key, value in sorted(subset_counts.items())})
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET_ID],
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {"splunk-attack-data-v1": statistics},
        "source": {
            "dataset": DATASET_ID,
            "revision": revision,
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
            "path": "targeted audited subsets",
            "paths": sorted(hashes),
            "bytes": sum((resolved / path).stat().st_size for path in hashes),
            "files": len(hashes),
            "rows": counts["source_events"],
            "sha256": combined_hash,
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
