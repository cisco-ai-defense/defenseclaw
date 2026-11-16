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

"""GAP-0823: the Hook contract row never prints a stale agent version unlabeled.

The Connector compatibility row re-reads the version the agent reports now. The
Hook contract row used the discovery cache, so after an agent self-update it
printed the version setup recorded as a bare ``agent=`` value. One format for
every connector: the value is unlabeled only when the agent just reported it.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest
from defenseclaw import doctor_health
from defenseclaw.commands.cmd_doctor import _check_hook_contract_lock, _DoctorResult
from defenseclaw.inventory import agent_discovery
from defenseclaw.inventory.agent_discovery import AgentDiscovery, AgentSignal

_BINARY = "/opt/agent/bin/agent"
_CONTRACTS = {
    "claudecode": "claudecode-hooks-v2",
    "codex": "codex-hooks-v1",
}
_LOCKED = {"claudecode": "2.1.312 (Claude Code)", "codex": "codex-cli 0.160.0"}
_UPDATED = {"claudecode": "2.1.319 (Claude Code)", "codex": "codex-cli 0.161.0"}


@pytest.fixture(autouse=True)
def _fresh_probe_answers():
    doctor_health.end_installed_version_run()
    with mock.patch.object(agent_discovery, "_binary_candidates_for_agent", return_value=()):
        yield
    doctor_health.end_installed_version_run()


def _setup(tmp_path, connector: str) -> mock.MagicMock:
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps(
            {
                "connectors": {
                    connector: {
                        "connector": connector,
                        "compatibility_status": "known",
                        "contract_id": _CONTRACTS[connector],
                        "raw_agent_version": _LOCKED[connector],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    cfg = mock.MagicMock()
    cfg.data_dir = str(tmp_path)
    return cfg


def _discovery(connector: str, version: str) -> AgentDiscovery:
    agents = {
        name: AgentSignal(name=name, installed=False, config_path="", binary_path="", version="", error="")
        for name in agent_discovery.DISCOVERABLE_CONNECTORS
    }
    agents[connector] = AgentSignal(
        name=connector, installed=True, config_path="", binary_path=_BINARY, version=version, error=""
    )
    return AgentDiscovery(scanned_at="2026-11-07T00:00:00Z", agents=agents, cache_hit=True)


def _row(cfg, connector: str, *, cached: str, probe: tuple[str, str]) -> dict:
    result = _DoctorResult()
    with (
        mock.patch.object(doctor_health, "read_run_discovery", return_value=_discovery(connector, cached)),
        mock.patch.object(agent_discovery, "_version_for_agent_binary", return_value=probe),
    ):
        _check_hook_contract_lock(cfg, connector, result, platform_name="linux")
    return result.checks[-1]


@pytest.mark.parametrize("connector", ["claudecode", "codex"])
def test_agent_updated_after_setup_is_named_and_the_recorded_value_is_labeled(tmp_path, connector: str) -> None:
    # The cache still holds the recorded version; the agent reports the new one.
    row = _row(_setup(tmp_path, connector), connector, cached=_LOCKED[connector], probe=(_UPDATED[connector], ""))
    detail = row["detail"]
    assert row["status"] == "pass", detail
    assert f"agent={_LOCKED[connector]} (recorded at setup)" in detail
    assert f"agent_updated={_UPDATED[connector]!r}" in detail


@pytest.mark.parametrize("connector", ["claudecode", "codex"])
def test_a_version_the_agent_just_reported_stays_unlabeled(tmp_path, connector: str) -> None:
    row = _row(_setup(tmp_path, connector), connector, cached=_LOCKED[connector], probe=(_LOCKED[connector], ""))
    detail = row["detail"]
    assert row["status"] == "pass", detail
    assert f"agent={_LOCKED[connector]}" in detail
    assert "recorded at setup" not in detail
    assert "agent_updated=" not in detail


@pytest.mark.parametrize("connector", ["claudecode", "codex"])
def test_a_probe_that_cannot_run_labels_the_value_as_recorded(tmp_path, connector: str) -> None:
    row = _row(
        _setup(tmp_path, connector),
        connector,
        cached=_LOCKED[connector],
        probe=("", agent_discovery.VERSION_PROBE_TIMED_OUT),
    )
    detail = row["detail"]
    assert row["status"] == "pass", detail
    assert f"agent={_LOCKED[connector]} (recorded at setup)" in detail
    assert "agent_updated=" not in detail
