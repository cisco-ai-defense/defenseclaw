# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("benchmark_normalize_splunk_attack_data.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_splunk_attack_data", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def xml_event(event_id: str, values: dict[str, str]) -> bytes:
    data = "".join(f"<Data Name='{name}'>{value}</Data>" for name, value in values.items())
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><Provider Name='Test Provider'/><EventID>"
        f"{event_id}</EventID><TimeCreated SystemTime='2025-01-02T03:04:05.123456700Z'/>"
        "<EventRecordID>42</EventRecordID><Execution ProcessID='7' ThreadID='8'/>"
        "<Computer>test-host</Computer></System><EventData>"
        f"{data}</EventData></Event>"
    ).encode()


def subset(key: str) -> object:
    return next(item for item in MODULE.SUBSETS if item.key == key)


def test_defender_consequence_is_authoritative(tmp_path: Path) -> None:
    path = tmp_path / "events.log"
    path.write_bytes(
        xml_event(
            "5007",
            {
                "New Value": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Temp = 0x0",
                "Old Value": "",
            },
        )
    )
    raw = MODULE.parse_xml_events(path)[0]
    selected = subset("defender_exclusion_effect")
    assert MODULE.relevant_xml(selected, raw)
    projected = MODULE.xml_projection(selected, raw)
    assert projected["outcome"] == "succeeded"
    assert MODULE.truth(selected, projected)["applicability"] == "in_scope"


def test_process_creation_proves_only_successful_predecessor_start(tmp_path: Path) -> None:
    path = tmp_path / "events.log"
    path.write_bytes(
        xml_event(
            "1",
            {
                "CommandLine": r"powershell Add-MpPreference -ExclusionPath C:\Temp -Force",
                "ProcessGuid": "{00000000-0000-4000-8000-000000000001}",
                "Hashes": "excluded digest fields",
                "DestinationIp": "192.0.2.9",
            },
        )
    )
    raw = MODULE.parse_xml_events(path)[0]
    selected = subset("defender_exclusion_process_and_registry")
    projected = MODULE.xml_projection(selected, raw)
    assert projected["outcome"] == "succeeded"
    assert MODULE.truth(selected, projected)["applicability"] == "out_of_scope"
    assert MODULE.truth(selected, projected)["expected_disposition"] == "detect_only"
    rendered = MODULE.canonical_json(MODULE.payload(projected))
    assert "Hashes" not in rendered
    assert "192.0.2.9" not in rendered


def test_logging_registry_consequence_requires_zero(tmp_path: Path) -> None:
    path = tmp_path / "events.log"
    base = {
        "EventType": "SetValue",
        "TargetObject": r"HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\Start",
        "Details": "DWORD (0x00000000)",
        "ProcessGuid": "{00000000-0000-4000-8000-000000000002}",
    }
    path.write_bytes(xml_event("13", base))
    raw = MODULE.parse_xml_events(path)[0]
    selected = subset("defender_logging_disable")
    assert MODULE.exact_consequence(selected, raw)
    changed = dict(base, Details="DWORD (0x00000001)")
    path.write_bytes(xml_event("13", changed))
    assert not MODULE.exact_consequence(selected, MODULE.parse_xml_events(path)[0])


def test_unsafe_xml_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "events.log"
    path.write_text("<!DOCTYPE foo><Event/>", encoding="utf-8")
    with pytest.raises(MODULE.ProjectionError, match="unsafe_xml"):
        MODULE.parse_xml_events(path)


def test_kubernetes_failed_and_privileged_events_stay_contextual() -> None:
    denied = {
        "auditID": "00000000-0000-4000-8000-000000000003",
        "verb": "create",
        "stage": "ResponseComplete",
        "stageTimestamp": "2025-01-02T03:04:05.000000Z",
        "user": {"username": "test-user"},
        "objectRef": {"resource": "jobs", "namespace": "test"},
        "responseStatus": {"code": 403, "message": "excluded free-form response"},
        "requestObject": None,
    }
    denied_subset = subset("kubernetes_unauthorized_denied")
    projected = MODULE.kubernetes_projection(denied_subset, denied)
    assert projected["outcome"] == "denied"
    assert MODULE.truth(denied_subset, projected)["source_truth"] == "unknown"
    assert "excluded free-form response" not in MODULE.canonical_json(MODULE.payload(projected))

    privileged = dict(denied)
    privileged["auditID"] = "00000000-0000-4000-8000-000000000004"
    privileged["responseStatus"] = {"code": 201}
    privileged["objectRef"] = {"resource": "pods", "namespace": "default", "name": "test-pod"}
    privileged["requestObject"] = {
        "metadata": {"annotations": {"large": "excluded body"}},
        "spec": {
            "hostPID": True,
            "containers": [
                {"name": "test", "image": "registry.example/test:1", "securityContext": {"privileged": True}}
            ],
        },
    }
    privileged_subset = subset("kubernetes_privileged_pod")
    projected = MODULE.kubernetes_projection(privileged_subset, privileged)
    assert projected["outcome"] == "succeeded"
    assert MODULE.truth(privileged_subset, projected)["applicability"] == "out_of_scope"
    assert "excluded body" not in MODULE.canonical_json(MODULE.payload(projected))


def test_duplicate_json_keys_are_rejected() -> None:
    with pytest.raises(MODULE.ProjectionError, match="duplicate_json_key"):
        json.loads('{"verb":"get","verb":"create"}', object_pairs_hook=MODULE.strict_object)


def test_pinned_revision_is_enforced(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="pinned revision"):
        MODULE.normalize_directory(tmp_path, "main")


def test_real_targeted_projection_validates() -> None:
    source = Path("/tmp/splunk-attack-data-targeted")
    if not source.exists():
        pytest.skip("targeted Splunk fixture is not present")
    cases, manifest = MODULE.normalize_directory(source, MODULE.SOURCE_REVISION)
    MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)
    assert manifest["cases"] == len(cases)
    assert manifest["counts"]["selected_events"] > 0
    assert manifest["counts"]["action_authoritative_cases"] > 0
    assert manifest["rejected_subsets"]
    assert all(case["split"] == "development" for case in cases)
    assert all(
        len(case["payload"].get("events", [])) <= MODULE.MAX_EVENTS for case in cases if case["surface"] == "stateful"
    )
