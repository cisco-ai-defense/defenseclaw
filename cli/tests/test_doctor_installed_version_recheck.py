# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-0723: Connector compatibility reports the version the agent has now.

The discovery cache (a day) and the gateway hook contract lock (until the
gateway restarts) keep the version recorded before an agent update. The row
printed that value as ``installed`` and judged compatibility on it.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest import mock

import pytest
from defenseclaw import doctor_health
from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _DoctorResult
from defenseclaw.connector_contracts import KIRO_CLI_HOOK_FLOOR
from defenseclaw.inventory import agent_discovery
from defenseclaw.inventory.agent_discovery import AgentDiscovery, AgentSignal

_BINARY = "/opt/codex/bin/codex"


@pytest.fixture(autouse=True)
def _fresh_probe_answers():
    # One probe answer is shared inside a Doctor run; each test is its own run.
    # The host this runs on may have a real agent on PATH: no launch candidates
    # unless a test names them, so only the recorded path is probed.
    doctor_health.end_installed_version_run()
    with mock.patch.object(agent_discovery, "_binary_candidates_for_agent", return_value=()):
        yield
    doctor_health.end_installed_version_run()


def _discovery(version: str = "codex-cli 0.160.0", binary: str = _BINARY) -> AgentDiscovery:
    agents = {
        name: AgentSignal(name=name, installed=False, config_path="", binary_path="", version="", error="")
        for name in agent_discovery.DISCOVERABLE_CONNECTORS
    }
    agents["codex"] = AgentSignal(
        name="codex", installed=True, config_path="", binary_path=binary, version=version, error=""
    )
    return AgentDiscovery(scanned_at="2026-11-06T00:00:00Z", agents=agents, cache_hit=True)


def _row(discovery, probe_result, data_dir: str = "") -> tuple[dict, mock.Mock]:
    r = _DoctorResult()
    probe = mock.Mock(return_value=probe_result)
    with (
        mock.patch("defenseclaw.doctor_health.read_cached_discovery", return_value=discovery),
        mock.patch.object(agent_discovery, "_version_for_agent_binary", probe),
        mock.patch.object(cmd_doctor, "_doctor_component_evidence", return_value=()),
        mock.patch.object(cmd_doctor, "_connector_enabled", return_value=True),
        mock.patch.object(cmd_doctor, "_unverified_executable_note", return_value=("", "")),
    ):
        cmd_doctor._check_component_connector_compatibility(SimpleNamespace(data_dir=data_dir), ["codex"], r)
    return next(c for c in r.checks if c["label"] == "Connector compatibility: codex"), probe


def test_an_updated_agent_is_reported_at_the_version_it_has_now() -> None:
    row, probe = _row(_discovery(), ("codex-cli 0.167.0", ""))
    assert "installed=0.167.0" in row["detail"]
    assert "installed=0.160.0" not in row["detail"]
    assert "recorded as 0.160.0 before the agent updated" in row["detail"]
    assert row["status"] == "pass"
    assert probe.call_args.args[:2] == ("codex", _BINARY)


def test_an_unchanged_agent_keeps_the_plain_installed_row() -> None:
    # Benign twin: nothing to qualify when the agent still reports the recorded version.
    row, _ = _row(_discovery(), ("codex-cli 0.160.0", ""))
    assert "installed=0.160.0" in row["detail"]
    assert "recorded" not in row["detail"]
    assert row["status"] == "pass"


def test_a_probe_that_cannot_run_calls_the_version_recorded_not_installed() -> None:
    row, _ = _row(_discovery(), ("", agent_discovery.VERSION_PROBE_TIMED_OUT))
    assert "installed=" not in row["detail"]
    assert "recorded=0.160.0 (not re-checked now: the version probe timed out)" in row["detail"]
    assert row["status"] == "pass"


def test_an_untrusted_executable_is_not_run_and_the_row_says_so() -> None:
    row, _ = _row(_discovery(), ("", agent_discovery.UNTRUSTED_PREFIX_ERROR))
    assert "installed=" not in row["detail"]
    assert "not in a trusted install location" in row["detail"]


def test_a_probe_error_text_never_reaches_the_row() -> None:
    row, _ = _row(_discovery(), ("", "version probe exited 1: secret-token-xyz"))
    assert "secret-token-xyz" not in row["detail"]
    assert "the version probe did not return a version" in row["detail"]


def test_no_recorded_executable_is_not_probed() -> None:
    row, probe = _row(_discovery(binary=""), ("codex-cli 0.167.0", ""))
    probe.assert_not_called()
    assert "recorded=0.160.0 (not re-checked now: no executable path is recorded)" in row["detail"]


def test_a_connector_the_agent_is_not_installed_for_is_not_probed() -> None:
    discovery = _discovery()
    discovery.agents["codex"] = AgentSignal(
        name="codex", installed=False, config_path="", binary_path="", version="", error=""
    )
    _, probe = _row(discovery, ("codex-cli 0.167.0", ""))
    probe.assert_not_called()


def test_the_gateway_lock_fallback_is_rechecked_on_the_executable_it_recorded(tmp_path) -> None:
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps(
            {
                "connectors": {
                    "codex": {
                        "raw_agent_version": "codex-cli 0.160.0",
                        "agent_executable": _BINARY,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    r = _DoctorResult()
    probe = mock.Mock(return_value=("codex-cli 0.167.0", ""))
    with (
        mock.patch("defenseclaw.inventory.agent_discovery._read_cache", return_value=None),
        mock.patch.object(agent_discovery, "_version_for_agent_binary", probe),
        mock.patch.object(cmd_doctor, "_doctor_component_evidence", return_value=()),
        mock.patch.object(cmd_doctor, "_connector_enabled", return_value=True),
        mock.patch.object(cmd_doctor, "_unverified_executable_note", return_value=("", "")),
    ):
        cmd_doctor._check_component_connector_compatibility(SimpleNamespace(data_dir=str(tmp_path)), ["codex"], r)
    row = next(c for c in r.checks if c["label"] == "Connector compatibility: codex")
    assert "installed=0.167.0" in row["detail"]
    assert probe.call_args.args[:2] == ("codex", _BINARY)


def test_the_repair_planner_judges_the_version_found_now() -> None:
    seen: list[str] = []

    def assess(connectors, discovery):
        seen.append(discovery.agents["codex"].version)
        return ()

    with (
        mock.patch.object(cmd_doctor, "_doctor_active_connectors", return_value=["codex"]),
        mock.patch.object(cmd_doctor, "_connector_enabled", return_value=True),
        mock.patch("defenseclaw.doctor_health.read_cached_discovery", return_value=_discovery()),
        mock.patch.object(agent_discovery, "_version_for_agent_binary", return_value=("codex-cli 0.167.0", "")),
        mock.patch("defenseclaw.doctor_health.assess_connector_health", side_effect=assess),
    ):
        cmd_doctor._connector_compatibility_problems(SimpleNamespace(data_dir=""))
    assert seen == ["codex-cli 0.167.0"]


def test_recheck_never_mutates_the_evidence_it_was_given() -> None:
    discovery = _discovery()
    with mock.patch.object(agent_discovery, "_version_for_agent_binary", return_value=("codex-cli 0.167.0", "")):
        check = doctor_health.recheck_installed_versions(discovery, ["codex"], "")
    assert discovery.agents["codex"].version == "codex-cli 0.160.0"
    assert check.discovery.agents["codex"].version == "codex-cli 0.167.0"
    assert dict(check.changed) == {"codex": "0.160.0"}


def test_recheck_without_evidence_probes_nothing() -> None:
    with mock.patch.object(agent_discovery, "_version_for_agent_binary") as probe:
        check = doctor_health.recheck_installed_versions(None, ["codex"], "")
    probe.assert_not_called()
    assert check.discovery is None and not check.changed and not check.unchecked


def test_a_recorded_banner_never_reaches_the_row_beyond_its_semver() -> None:
    # M2: the recorded text is evidence from a file; only a plain version is shown.
    recorded = "codex-cli 0.160.0 INJECTED-MARKER \x1b[31mred"
    row, _ = _row(_discovery(version=recorded), ("codex-cli 0.167.0", ""))
    assert "INJECTED-MARKER" not in row["detail"]
    assert "\x1b" not in row["detail"]
    assert "installed=0.167.0" in row["detail"]
    assert "recorded as 0.160.0 before the agent updated" in row["detail"]


def test_a_recorded_text_without_a_plain_version_is_not_quoted() -> None:
    row, _ = _row(_discovery(version="codex-cli build-INJECTED-MARKER"), ("codex-cli 0.167.0", ""))
    assert "INJECTED-MARKER" not in row["detail"]
    assert "installed=0.167.0" in row["detail"]


def _proxy_discovery(name: str, version: str, binary: str) -> AgentDiscovery:
    agents = {
        n: AgentSignal(name=n, installed=False, config_path="", binary_path="", version="", error="")
        for n in agent_discovery.DISCOVERABLE_CONNECTORS
    }
    agents[name] = AgentSignal(name=name, installed=True, config_path="", binary_path=binary, version=version, error="")
    return AgentDiscovery(scanned_at="2026-11-06T00:00:00Z", agents=agents, cache_hit=True)


@pytest.mark.parametrize("name", ["openclaw", "zeptoclaw"])
def test_a_proxy_connector_row_reports_the_version_it_has_now(name: str) -> None:
    # M1: proxy connectors state an installed version too.
    discovery = _proxy_discovery(name, "2026.9.1", f"/opt/{name}/bin/{name}")
    probe = mock.Mock(return_value=("2026.10.2", ""))
    with mock.patch.object(agent_discovery, "_version_for_agent_binary", probe):
        check = doctor_health.recheck_installed_versions(discovery, [name], "")
    assert check.discovery.agents[name].version == "2026.10.2"
    assert dict(check.changed) == {name: "2026.9.1"}
    probe.assert_called_once()


@pytest.mark.parametrize("name", ["openclaw", "zeptoclaw"])
def test_a_proxy_connector_that_cannot_be_probed_is_called_recorded(name: str) -> None:
    discovery = _proxy_discovery(name, "2026.9.1", f"/opt/{name}/bin/{name}")
    with mock.patch.object(
        agent_discovery, "_version_for_agent_binary", return_value=("", agent_discovery.VERSION_PROBE_TIMED_OUT)
    ):
        check = doctor_health.recheck_installed_versions(discovery, [name], "")
    assert check.discovery is discovery
    assert dict(check.unchecked) == {name: "the version probe timed out"}


def _kiro_discovery(forms: list[dict[str, str]], **fields: str) -> AgentDiscovery:
    agents = {
        n: AgentSignal(name=n, installed=False, config_path="", binary_path="", version="", error="")
        for n in agent_discovery.DISCOVERABLE_CONNECTORS
    }
    agents["kiro"] = AgentSignal(
        name="kiro",
        installed=True,
        config_path="",
        binary_path=forms[0]["path"] if forms else fields.get("binary_path", ""),
        version=fields.get("version", forms[0]["version"] if forms else ""),
        error="",
        kiro_forms=forms,
    )
    return AgentDiscovery(scanned_at="2026-11-06T00:00:00Z", agents=agents, cache_hit=True)


def _kiro_cli_form(version: str, path: str = "/opt/kiro/bin/kiro-cli") -> dict[str, str]:
    return {"kind": "cli", "version": f"kiro-cli {version}", "unread": "", "path": path}


def _kiro_row(discovery, probe_result) -> dict:
    r = _DoctorResult()
    with (
        mock.patch("defenseclaw.doctor_health.read_cached_discovery", return_value=discovery),
        mock.patch.object(agent_discovery, "_version_for_agent_binary", mock.Mock(return_value=probe_result)),
        mock.patch.object(cmd_doctor, "_doctor_component_evidence", return_value=()),
        mock.patch.object(cmd_doctor, "_connector_enabled", return_value=True),
        mock.patch.object(cmd_doctor, "_unverified_executable_note", return_value=("", "")),
    ):
        cmd_doctor._check_component_connector_compatibility(SimpleNamespace(data_dir=""), ["kiro"], r)
    return next(c for c in r.checks if c["label"] == "Connector compatibility: kiro")


def _below(version: str) -> str:
    major, minor, patch = (int(x) for x in version.split("."))
    return f"{major}.{max(minor - 1, 0)}.{patch}" if minor else f"{max(major - 1, 0)}.0.0"


def _above(version: str) -> str:
    major, minor, patch = (int(x) for x in version.split("."))
    return f"{major}.{minor + 1}.{patch}"


def test_kiro_updated_past_its_floor_is_no_longer_failed_on_the_recorded_version() -> None:
    # M1, reverse update: recorded below the hook floor, current at or above it.
    old, new = _below(KIRO_CLI_HOOK_FLOOR), _above(KIRO_CLI_HOOK_FLOOR)
    row = _kiro_row(_kiro_discovery([_kiro_cli_form(old)]), (f"kiro-cli {new}", ""))
    assert row["status"] == "pass"
    assert f"installed={new}" in row["detail"]
    assert f"installed={old}" not in row["detail"]


def test_kiro_downgraded_below_its_floor_is_no_longer_called_protected_on_the_recorded_version() -> None:
    # M1: recorded above the floor, current below it. Must not read as protected.
    old, new = _above(KIRO_CLI_HOOK_FLOOR), _below(KIRO_CLI_HOOK_FLOOR)
    row = _kiro_row(_kiro_discovery([_kiro_cli_form(old)]), (f"kiro-cli {new}", ""))
    assert row["status"] != "pass"
    assert f"installed={old}" not in row["detail"]
    assert "recorded=" not in row["detail"]


def test_kiro_form_that_cannot_be_read_now_is_called_recorded_not_installed() -> None:
    version = _above(KIRO_CLI_HOOK_FLOOR)
    row = _kiro_row(
        _kiro_discovery([_kiro_cli_form(version)]), ("", agent_discovery.VERSION_PROBE_TIMED_OUT)
    )
    assert "installed=" not in row["detail"]
    assert f"recorded={version} (not re-checked now: the version probe timed out)" in row["detail"]


def test_kiro_unchanged_keeps_the_plain_installed_row() -> None:
    version = _above(KIRO_CLI_HOOK_FLOOR)
    row = _kiro_row(_kiro_discovery([_kiro_cli_form(version)]), (f"kiro-cli {version}", ""))
    assert f"installed={version}" in row["detail"]
    assert "recorded" not in row["detail"]


def test_kiro_evidence_that_names_no_path_for_a_form_is_never_called_installed() -> None:
    version = _above(KIRO_CLI_HOOK_FLOOR)
    form = _kiro_cli_form(version, path="")
    probe = mock.Mock(return_value=(f"kiro-cli {version}", ""))
    with mock.patch.object(agent_discovery, "_version_for_agent_binary", probe):
        check = doctor_health.recheck_installed_versions(_kiro_discovery([form], binary_path="/x"), ["kiro"], "")
    probe.assert_not_called()
    assert "kiro" in check.unchecked


def test_one_run_probes_each_agent_once_across_the_gate_the_planner_and_the_row() -> None:
    # M3: connector safety gate, review planner and final row of one dry-run.
    probe = mock.Mock(return_value=("codex-cli 0.167.0", ""))
    with (
        mock.patch.object(cmd_doctor, "_doctor_active_connectors", return_value=["codex"]),
        mock.patch.object(cmd_doctor, "_connector_enabled", return_value=True),
        mock.patch("defenseclaw.doctor_health.read_cached_discovery", return_value=_discovery()),
        mock.patch.object(agent_discovery, "_version_for_agent_binary", probe),
        mock.patch.object(cmd_doctor, "_doctor_component_evidence", return_value=()),
        mock.patch.object(cmd_doctor, "_unverified_executable_note", return_value=("", "")),
    ):
        cfg = SimpleNamespace(data_dir="")
        cmd_doctor._plan_connector_compatibility_gate(cfg)
        cmd_doctor._plan_connector_compatibility_review(cfg)
        cmd_doctor._check_component_connector_compatibility(cfg, ["codex"], _DoctorResult())
    assert probe.call_count == 1


def test_a_new_run_probes_again() -> None:
    probe = mock.Mock(side_effect=[("codex-cli 0.167.0", ""), ("codex-cli 0.168.0", "")])
    with mock.patch.object(agent_discovery, "_version_for_agent_binary", probe):
        first = doctor_health.recheck_installed_versions(_discovery(), ["codex"], "")
        doctor_health.begin_installed_version_run()
        second = doctor_health.recheck_installed_versions(_discovery(), ["codex"], "")
    assert first.discovery.agents["codex"].version == "codex-cli 0.167.0"
    assert second.discovery.agents["codex"].version == "codex-cli 0.168.0"


# ---- M1: an update that moves the launched executable -------------------------

_OLD = "/opt/old/bin/codex"
_NEW = "/opt/new/bin/codex"


def _by_path(answers: dict[str, tuple[str, str]]) -> mock.Mock:
    return mock.Mock(side_effect=lambda _name, path, *_a, **_k: answers[path])


def _row_with_candidates(candidates: tuple[str, ...], answers: dict[str, tuple[str, str]]) -> tuple[dict, mock.Mock]:
    r = _DoctorResult()
    probe = _by_path(answers)
    with (
        mock.patch("defenseclaw.doctor_health.read_cached_discovery", return_value=_discovery(binary=_OLD)),
        mock.patch.object(agent_discovery, "_version_for_agent_binary", probe),
        mock.patch.object(agent_discovery, "_binary_candidates_for_agent", return_value=candidates),
        mock.patch.object(cmd_doctor, "_doctor_component_evidence", return_value=()),
        mock.patch.object(cmd_doctor, "_connector_enabled", return_value=True),
        mock.patch.object(cmd_doctor, "_unverified_executable_note", return_value=("", "")),
    ):
        cmd_doctor._check_component_connector_compatibility(SimpleNamespace(data_dir=""), ["codex"], r)
    return next(c for c in r.checks if c["label"] == "Connector compatibility: codex"), probe


def test_a_newly_preferred_executable_is_the_one_reported_installed() -> None:
    # The old copy stays on disk at an unsupported version; the update put a new one first.
    row, _ = _row_with_candidates(
        (_NEW, _OLD), {_NEW: ("codex-cli 0.167.0", ""), _OLD: ("codex-cli 0.100.0", "")}
    )
    assert "installed=0.167.0" in row["detail"]
    assert "0.100.0" not in row["detail"]
    assert row["status"] == "pass"


def test_a_downgrade_to_a_preferred_unsupported_executable_is_not_a_pass() -> None:
    row, _ = _row_with_candidates(
        (_NEW, _OLD), {_NEW: ("codex-cli 0.100.0", ""), _OLD: ("codex-cli 0.160.0", "")}
    )
    assert "installed=0.100.0" in row["detail"]
    assert row["status"] == "fail"


def test_a_preferred_executable_that_cannot_answer_falls_back_like_discovery() -> None:
    row, probe = _row_with_candidates(
        (_NEW, _OLD),
        {_NEW: ("", agent_discovery.UNTRUSTED_PREFIX_ERROR), _OLD: ("codex-cli 0.160.0", "")},
    )
    assert "installed=0.160.0" in row["detail"]
    assert row["status"] == "pass"
    assert [c.args[1] for c in probe.call_args_list] == [_NEW, _OLD]


def test_the_same_executable_in_the_candidates_keeps_the_plain_row() -> None:
    row, probe = _row_with_candidates((_OLD,), {_OLD: ("codex-cli 0.160.0", "")})
    assert "installed=0.160.0" in row["detail"]
    assert "recorded" not in row["detail"]
    assert probe.call_count == 1


def test_a_moved_executable_with_the_same_version_is_probed_at_its_new_path_only() -> None:
    check = None
    probe = _by_path({_NEW: ("codex-cli 0.160.0", ""), _OLD: ("codex-cli 0.100.0", "")})
    with (
        mock.patch.object(agent_discovery, "_version_for_agent_binary", probe),
        mock.patch.object(agent_discovery, "_binary_candidates_for_agent", return_value=(_NEW, _OLD)),
    ):
        check = doctor_health.recheck_installed_versions(_discovery(binary=_OLD), ["codex"], "")
    signal = check.discovery.agents["codex"]
    assert (signal.binary_path, signal.version) == (_NEW, "codex-cli 0.160.0")
    assert check.changed == {}


def test_kiro_install_at_a_new_path_is_judged_with_the_recorded_ones() -> None:
    new = "/opt/new/bin/kiro-cli"
    old = "/opt/kiro/bin/kiro-cli"
    discovery = _kiro_discovery([_kiro_cli_form(_below(KIRO_CLI_HOOK_FLOOR), old)])
    answers = {new: (f"kiro-cli {KIRO_CLI_HOOK_FLOOR}", ""), old: (f"kiro-cli {_below(KIRO_CLI_HOOK_FLOOR)}", "")}
    with (
        mock.patch.object(agent_discovery, "_version_for_agent_binary", _by_path(answers)),
        mock.patch.object(agent_discovery, "_binary_candidates_for_agent", return_value=(new, old)),
    ):
        check = doctor_health.recheck_installed_versions(discovery, ["kiro"], "")
    forms = check.discovery.agents["kiro"].kiro_forms
    assert {f["path"] for f in forms} == {new, old}
    assert check.discovery.agents["kiro"].kiro_cli_version == f"kiro-cli {KIRO_CLI_HOOK_FLOOR}"


def test_kiro_new_install_that_cannot_be_read_is_not_invented() -> None:
    new = "/opt/new/bin/kiro-cli"
    old = "/opt/kiro/bin/kiro-cli"
    discovery = _kiro_discovery([_kiro_cli_form(KIRO_CLI_HOOK_FLOOR, old)])
    answers = {new: ("", agent_discovery.VERSION_PROBE_TIMED_OUT), old: (f"kiro-cli {KIRO_CLI_HOOK_FLOOR}", "")}
    with (
        mock.patch.object(agent_discovery, "_version_for_agent_binary", _by_path(answers)),
        mock.patch.object(agent_discovery, "_binary_candidates_for_agent", return_value=(new, old)),
    ):
        check = doctor_health.recheck_installed_versions(discovery, ["kiro"], "")
    assert check.discovery is discovery
    assert dict(check.unchecked) == {"kiro": "the version probe timed out"}


# ---- review 3 M1: Kiro forms follow the current launch order -----------------

_K_OLD = "/opt/kiro-old/bin/kiro-cli"
_K_NEW = "/opt/kiro-new/bin/kiro-cli"


def _kiro_check(old_version: str, candidates: tuple[str, ...], answers: dict[str, tuple[str, str]]):
    discovery = _kiro_discovery([_kiro_cli_form(old_version, _K_OLD)])
    with (
        mock.patch.object(agent_discovery, "_version_for_agent_binary", _by_path(answers)),
        mock.patch.object(agent_discovery, "_binary_candidates_for_agent", return_value=candidates),
    ):
        return doctor_health.recheck_installed_versions(discovery, ["kiro"], "")


def _kiro_gate_and_row(old_version: str, candidates: tuple[str, ...], answers: dict[str, tuple[str, str]]):
    discovery = _kiro_discovery([_kiro_cli_form(old_version, _K_OLD)])
    r = _DoctorResult()
    with (
        mock.patch.object(agent_discovery, "_version_for_agent_binary", _by_path(answers)),
        mock.patch.object(agent_discovery, "_binary_candidates_for_agent", return_value=candidates),
        mock.patch.object(cmd_doctor, "_doctor_active_connectors", return_value=["kiro"]),
        mock.patch("defenseclaw.doctor_health.read_cached_discovery", return_value=discovery),
        mock.patch.object(cmd_doctor, "_doctor_component_evidence", return_value=()),
        mock.patch.object(cmd_doctor, "_connector_enabled", return_value=True),
        mock.patch.object(cmd_doctor, "_unverified_executable_note", return_value=("", "")),
    ):
        cfg = SimpleNamespace(data_dir="")
        gate = cmd_doctor._plan_connector_compatibility_gate(cfg)
        cmd_doctor._check_component_connector_compatibility(cfg, ["kiro"], r)
    return gate, next(c for c in r.checks if c["label"] == "Connector compatibility: kiro")


def test_kiro_newly_preferred_install_is_selected_before_the_recorded_one() -> None:
    old, new = KIRO_CLI_HOOK_FLOOR, _above(KIRO_CLI_HOOK_FLOOR)
    check = _kiro_check(
        old, (_K_NEW, _K_OLD), {_K_NEW: (f"kiro-cli {new}", ""), _K_OLD: (f"kiro-cli {old}", "")}
    )
    signal = check.discovery.agents["kiro"]
    assert [f["path"] for f in signal.kiro_forms] == [_K_NEW, _K_OLD]
    assert (signal.binary_path, signal.version) == (_K_NEW, f"kiro-cli {new}")


def test_kiro_replaced_install_with_a_supported_one_has_no_stale_failure() -> None:
    # The old below-floor CLI is gone; the supported replacement is all there is.
    old, new = _below(KIRO_CLI_HOOK_FLOOR), _above(KIRO_CLI_HOOK_FLOOR)
    gate, row = _kiro_gate_and_row(
        old, (_K_NEW,), {_K_NEW: (f"kiro-cli {new}", ""), _K_OLD: ("", "no such file")}
    )
    assert row["status"] == "pass"
    assert f"installed={new}" in row["detail"]
    assert "auxiliary" not in row["detail"] and old not in row["detail"]
    assert gate.state != "manual"


def test_kiro_replaced_protected_install_with_a_below_floor_one_is_not_a_pass() -> None:
    # The old protected CLI is gone; the one launched now is below its hook floor.
    old, new = _above(KIRO_CLI_HOOK_FLOOR), _below(KIRO_CLI_HOOK_FLOOR)
    gate, row = _kiro_gate_and_row(
        old, (_K_NEW,), {_K_NEW: (f"kiro-cli {new}", ""), _K_OLD: ("", "no such file")}
    )
    assert row["status"] != "pass"
    assert f"installed={old}" not in row["detail"]
    assert gate.state == "manual"


def test_kiro_retired_install_that_still_answers_is_judged_after_the_current_ones() -> None:
    old, new = _below(KIRO_CLI_HOOK_FLOOR), _above(KIRO_CLI_HOOK_FLOOR)
    check = _kiro_check(
        old, (_K_NEW,), {_K_NEW: (f"kiro-cli {new}", ""), _K_OLD: (f"kiro-cli {old}", "")}
    )
    assert [f["path"] for f in check.discovery.agents["kiro"].kiro_forms] == [_K_NEW, _K_OLD]


def test_kiro_retired_install_that_does_not_answer_is_dropped() -> None:
    new = _above(KIRO_CLI_HOOK_FLOOR)
    check = _kiro_check(
        _below(KIRO_CLI_HOOK_FLOOR), (_K_NEW,), {_K_NEW: (f"kiro-cli {new}", ""), _K_OLD: ("", "gone")}
    )
    assert [f["path"] for f in check.discovery.agents["kiro"].kiro_forms] == [_K_NEW]
    assert check.unchecked == {}


def test_kiro_everything_recorded_gone_and_nothing_current_stays_recorded_not_installed() -> None:
    check = _kiro_check(KIRO_CLI_HOOK_FLOOR, (), {_K_OLD: ("", "gone")})
    assert "kiro" in check.unchecked
    assert check.changed == {}


# ---- review 3 M2: the candidate list and the answer are one per run ----------


def test_a_candidate_that_appears_mid_run_does_not_split_the_gate_from_the_row() -> None:
    answers = {_NEW: ("codex-cli 0.100.0", ""), _OLD: ("codex-cli 0.160.0", "")}
    listings = iter([(_OLD,), (_NEW, _OLD)])
    r = _DoctorResult()
    probe = _by_path(answers)
    doctor_health.begin_installed_version_run()
    with (
        mock.patch.object(agent_discovery, "_version_for_agent_binary", probe),
        mock.patch.object(agent_discovery, "_binary_candidates_for_agent", side_effect=lambda *_a: next(listings)),
        mock.patch.object(cmd_doctor, "_doctor_active_connectors", return_value=["codex"]),
        mock.patch("defenseclaw.doctor_health.read_cached_discovery", return_value=_discovery(binary=_OLD)),
        mock.patch.object(cmd_doctor, "_doctor_component_evidence", return_value=()),
        mock.patch.object(cmd_doctor, "_connector_enabled", return_value=True),
        mock.patch.object(cmd_doctor, "_unverified_executable_note", return_value=("", "")),
    ):
        cfg = SimpleNamespace(data_dir="")
        gate = cmd_doctor._plan_connector_compatibility_gate(cfg)
        cmd_doctor._check_component_connector_compatibility(cfg, ["codex"], r)
    row = next(c for c in r.checks if c["label"] == "Connector compatibility: codex")
    assert gate.state == "noop" and row["status"] == "pass"
    assert "installed=0.160.0" in row["detail"]
    assert [c.args[1] for c in probe.call_args_list] == [_OLD]


def test_outside_a_run_the_candidate_list_expires_with_the_answers() -> None:
    answers = {_NEW: ("codex-cli 0.167.0", ""), _OLD: ("codex-cli 0.160.0", "")}
    listings = iter([(_OLD,), (_NEW, _OLD)])
    clock = _slow_clock()
    with (
        mock.patch.object(agent_discovery, "_version_for_agent_binary", _by_path(answers)),
        mock.patch.object(agent_discovery, "_binary_candidates_for_agent", side_effect=lambda *_a: next(listings)),
        mock.patch.object(doctor_health.time, "monotonic", clock),
    ):
        first = doctor_health.recheck_installed_versions(_discovery(binary=_OLD), ["codex"], "")
        second = doctor_health.recheck_installed_versions(_discovery(binary=_OLD), ["codex"], "")
    assert first.discovery.agents["codex"].binary_path == _OLD
    assert second.discovery.agents["codex"].binary_path == _NEW


# ---- M2: one answer for a whole run, however long ----------------------------


def _slow_clock() -> mock.Mock:
    # Every reading is further than the share bound from the one before it.
    ticks = iter(range(1000, 100000, int(doctor_health._PROBE_SHARE_SECONDS) + 1))
    return mock.Mock(side_effect=lambda: float(next(ticks)))


def test_a_run_longer_than_the_share_bound_still_probes_once() -> None:
    probe = mock.Mock(side_effect=[("codex-cli 0.160.0", ""), ("codex-cli 0.100.0", "")])
    clock = _slow_clock()
    doctor_health.begin_installed_version_run()
    with (
        mock.patch.object(agent_discovery, "_version_for_agent_binary", probe),
        mock.patch.object(doctor_health.time, "monotonic", clock),
    ):
        first = doctor_health.recheck_installed_versions(_discovery(), ["codex"], "")
        second = doctor_health.recheck_installed_versions(_discovery(), ["codex"], "")
    assert probe.call_count == 1
    assert first.changed == second.changed == {}


def test_outside_a_run_an_answer_expires() -> None:
    probe = mock.Mock(side_effect=[("codex-cli 0.160.0", ""), ("codex-cli 0.167.0", "")])
    clock = _slow_clock()
    with (
        mock.patch.object(agent_discovery, "_version_for_agent_binary", probe),
        mock.patch.object(doctor_health.time, "monotonic", clock),
    ):
        doctor_health.recheck_installed_versions(_discovery(), ["codex"], "")
        second = doctor_health.recheck_installed_versions(_discovery(), ["codex"], "")
    assert probe.call_count == 2
    assert second.discovery.agents["codex"].version == "codex-cli 0.167.0"


def test_the_doctor_command_closes_its_run_scope_when_it_ends() -> None:
    import click

    @click.command()
    def run() -> None:
        doctor_health.begin_installed_version_run()
        click.get_current_context().call_on_close(doctor_health.end_installed_version_run)
        assert doctor_health._probe_run_scoped

    from click.testing import CliRunner

    assert CliRunner().invoke(run).exit_code == 0
    assert not doctor_health._probe_run_scoped


# ---- review 6 M1: an unreadable install never supplies protection -----------


def test_kiro_unreadable_old_install_does_not_protect_a_below_floor_current_one() -> None:
    # The old path is still listed but does not answer; the CLI launched now is
    # positively below its floor. The recorded version of the old install is
    # not evidence: no protected install, the lifecycle gate refuses.
    old, new = _above(KIRO_CLI_HOOK_FLOOR), _below(KIRO_CLI_HOOK_FLOOR)
    gate, row = _kiro_gate_and_row(
        old,
        (_K_NEW, _K_OLD),
        {_K_NEW: (f"kiro-cli {new}", ""), _K_OLD: ("", agent_discovery.VERSION_PROBE_TIMED_OUT)},
    )
    assert gate.state == "manual"
    assert row["status"] != "pass"
    assert f"recorded={old}" not in row["detail"] and f"installed={old}" not in row["detail"]


def test_kiro_unreadable_old_install_beside_a_supported_current_one_is_not_a_failure() -> None:
    # Benign twin: the install launched now is protected; the one that cannot
    # answer is reported as unread and does not block repair.
    old = new = _above(KIRO_CLI_HOOK_FLOOR)
    gate, row = _kiro_gate_and_row(
        old,
        (_K_NEW, _K_OLD),
        {_K_NEW: (f"kiro-cli {new}", ""), _K_OLD: ("", agent_discovery.VERSION_PROBE_TIMED_OUT)},
    )
    assert gate.state != "manual"
    assert row["status"] == "pass"
    assert f"installed={new}" in row["detail"]


def test_kiro_unreadable_install_is_recorded_unread_not_with_its_old_version() -> None:
    old = _above(KIRO_CLI_HOOK_FLOOR)
    check = _kiro_check(
        old,
        (_K_NEW, _K_OLD),
        {_K_NEW: (f"kiro-cli {old}", ""), _K_OLD: ("", agent_discovery.VERSION_PROBE_TIMED_OUT)},
    )
    forms = {f["path"]: f for f in check.discovery.agents["kiro"].kiro_forms}
    assert forms[_K_OLD]["version"] == "" and "could not be read" in forms[_K_OLD]["unread"]
    assert forms[_K_NEW]["version"] == f"kiro-cli {old}"


# ---- review 6 M2: the evidence is one per run --------------------------------


def _two_reads_gate_and_row(first, second, answers, *, scoped: bool):
    r = _DoctorResult()
    probe = _by_path(answers)
    if scoped:
        doctor_health.begin_installed_version_run()
    with (
        mock.patch.object(agent_discovery, "_version_for_agent_binary", probe),
        mock.patch.object(cmd_doctor, "_doctor_active_connectors", return_value=["codex"]),
        mock.patch("defenseclaw.doctor_health.read_cached_discovery", side_effect=[first, second]),
        mock.patch.object(cmd_doctor, "_doctor_component_evidence", return_value=()),
        mock.patch.object(cmd_doctor, "_connector_enabled", return_value=True),
        mock.patch.object(cmd_doctor, "_unverified_executable_note", return_value=("", "")),
    ):
        cfg = SimpleNamespace(data_dir="")
        gate = cmd_doctor._plan_connector_compatibility_gate(cfg)
        cmd_doctor._check_component_connector_compatibility(cfg, ["codex"], r)
    row = next(c for c in r.checks if c["label"] == "Connector compatibility: codex")
    return gate, row, probe


def test_a_recorded_path_that_changes_mid_run_does_not_split_the_gate_from_the_row() -> None:
    answers = {_OLD: ("codex-cli 0.160.0", ""), _NEW: ("codex-cli 0.100.0", "")}
    gate, row, probe = _two_reads_gate_and_row(
        _discovery(binary=_OLD), _discovery(binary=_NEW), answers, scoped=True
    )
    assert gate.state == "noop" and row["status"] == "pass"
    assert "installed=0.160.0" in row["detail"]
    assert [c.args[1] for c in probe.call_args_list] == [_OLD]


def test_outside_a_run_the_evidence_is_read_again() -> None:
    # Nothing shares evidence without a Doctor run (no clock-based sharing).
    answers = {_OLD: ("codex-cli 0.160.0", ""), _NEW: ("codex-cli 0.100.0", "")}
    reads = iter([_discovery(binary=_OLD), _discovery(binary=_NEW)])
    with mock.patch("defenseclaw.doctor_health.read_cached_discovery", side_effect=lambda _d: next(reads)):
        first = doctor_health.read_run_discovery("")
        second = doctor_health.read_run_discovery("")
    assert first.agents["codex"].binary_path == _OLD
    assert second.agents["codex"].binary_path == _NEW
    assert answers  # probes are not involved


def test_the_run_evidence_is_read_again_after_the_attended_refresh() -> None:
    reads = iter([_discovery(binary=_OLD), _discovery(binary=_NEW)])
    doctor_health.begin_installed_version_run()
    with mock.patch("defenseclaw.doctor_health.read_cached_discovery", side_effect=lambda _d: next(reads)):
        first = doctor_health.read_run_discovery("")
        assert doctor_health.read_run_discovery("") is first
        doctor_health.reset_installed_version_probes()
        second = doctor_health.read_run_discovery("")
    assert second.agents["codex"].binary_path == _NEW


def _unversioned() -> AgentDiscovery:
    # A fresh account: init cached codex before setup, so no version was probed.
    discovery = _discovery(version="")
    discovery.agents["codex"] = AgentSignal(
        name="codex",
        installed=True,
        config_path="",
        binary_path=_BINARY,
        version="",
        error=agent_discovery.VERSION_NOT_PROBED,
    )
    return discovery


def test_a_configured_connector_cached_without_a_version_is_read_now() -> None:
    # GAP-0752: the row warned "version was not observed" until `agent discover --refresh`.
    row, probe = _row(_unversioned(), ("codex-cli 0.160.0", ""))
    assert "installed=0.160.0" in row["detail"]
    assert "not observed" not in row["detail"]
    assert "recorded" not in row["detail"]
    assert row["status"] == "pass"
    assert probe.call_args.args[:2] == ("codex", _BINARY)


def test_an_unversioned_connector_whose_probe_fails_still_warns_not_observed() -> None:
    row, _ = _row(_unversioned(), ("", agent_discovery.VERSION_PROBE_TIMED_OUT))
    assert "not observed" in row["detail"]
    assert row["status"] == "warn"


def test_an_unversioned_agent_nobody_set_up_is_not_run() -> None:
    result = doctor_health.recheck_installed_versions(_unversioned(), ["claudecode"], "")
    assert result.discovery.agents["codex"].version == ""
    assert not result.changed
