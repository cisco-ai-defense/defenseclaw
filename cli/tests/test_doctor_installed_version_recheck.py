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

from defenseclaw import doctor_health
from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _DoctorResult
from defenseclaw.inventory import agent_discovery
from defenseclaw.inventory.agent_discovery import AgentDiscovery, AgentSignal

_BINARY = "/opt/codex/bin/codex"


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
    assert "recorded as codex-cli 0.160.0 before the agent updated" in row["detail"]
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
    assert dict(check.changed) == {"codex": "codex-cli 0.160.0"}


def test_recheck_without_evidence_probes_nothing() -> None:
    with mock.patch.object(agent_discovery, "_version_for_agent_binary") as probe:
        check = doctor_health.recheck_installed_versions(None, ["codex"], "")
    probe.assert_not_called()
    assert check.discovery is None and not check.changed and not check.unchecked
