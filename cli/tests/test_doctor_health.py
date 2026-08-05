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

"""Focused tests for standalone Doctor component and connector health."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from defenseclaw.doctor_health import (
    ComponentEvidence,
    HealthStatus,
    RemediationAuthorizationError,
    RemediationChoice,
    RemediationKind,
    assess_component_health,
    assess_connector_health,
    authorize_remediation,
    build_health_report,
    read_cached_discovery,
)


def _by_subject(findings):
    return {getattr(finding, "component", None) or getattr(finding, "connector", None): finding for finding in findings}


def _signal(*, installed: bool, version: str = "", error: str = ""):
    return SimpleNamespace(
        installed=installed,
        version=version,
        error=error,
        configured=True,
        active=True,
    )


def test_component_drift_is_typed_and_drops_probe_secrets() -> None:
    findings = assess_component_health(
        (
            ComponentEvidence("cli", "v0.8.6+local-build"),
            ComponentEvidence("gateway", "0.8.5", status="ok"),
            ComponentEvidence(
                "plugin",
                "https://operator:secret@example.invalid/plugin",
                status="error",
            ),
        )
    )
    by_name = _by_subject(findings)

    assert by_name["cli"].status is HealthStatus.SUPPORTED
    assert by_name["cli"].installed_version == "0.8.6"
    assert by_name["gateway"].status is HealthStatus.UNSUPPORTED
    assert by_name["gateway"].reason_code == "component-version-drift"
    assert by_name["gateway"].installed_version == "0.8.5"
    assert by_name["gateway"].expected_version == "0.8.6"
    assert by_name["gateway"].remediations[0].argv == (
        "defenseclaw",
        "upgrade",
        "--version",
        "0.8.6",
    )
    assert by_name["plugin"].status is HealthStatus.UNAVAILABLE
    assert "secret" not in repr(findings).lower()


def test_state_changing_component_repair_requires_attended_confirmation() -> None:
    gateway = _by_subject(
        assess_component_health(
            (
                ComponentEvidence("cli", "0.8.6"),
                ComponentEvidence("gateway", "0.8.5"),
                ComponentEvidence("plugin", "0.8.6"),
            )
        )
    )["gateway"]
    choice = gateway.remediations[0]

    with pytest.raises(RemediationAuthorizationError) as unconfirmed:
        authorize_remediation(choice)
    assert unconfirmed.value.code == "confirmation-required"

    with pytest.raises(RemediationAuthorizationError) as unattended:
        authorize_remediation(choice, confirmed=True, unattended=True)
    assert unattended.value.code == "unattended-repair-refused"

    assert authorize_remediation(choice, confirmed=True) == choice.argv


def test_connector_contract_states_and_capabilities_are_manifest_derived() -> None:
    discovery = SimpleNamespace(
        agents={
            "codex": _signal(
                installed=True,
                version="codex-cli 0.133.1; bearer=never-reflect-this",
                error="https://secret.invalid/?token=never-reflect-this",
            ),
            "claudecode": _signal(installed=True),
            "cursor": _signal(installed=True, version="cursor 0.1.0"),
            "openclaw": _signal(installed=True, version="OpenClaw 99.0.0"),
        }
    )

    findings = assess_connector_health(
        ("codex", "claude-code", "cursor", "openclaw", "hermes"),
        discovery,
    )
    by_name = _by_subject(findings)

    codex = by_name["codex"]
    assert codex.status is HealthStatus.SUPPORTED
    assert codex.installed_version == "0.133.1"
    assert codex.contract_id == "codex-hooks-v3"
    assert codex.capabilities is not None
    assert codex.capabilities.connection_kind == "hook"
    assert codex.capabilities.can_block is True
    assert codex.capabilities.supports_fail_closed is True
    assert "PreToolUse" in codex.capabilities.block_events

    claude = by_name["claudecode"]
    assert claude.status is HealthStatus.UNTESTED
    assert claude.reason_code == "connector-version-not-observed"
    assert claude.contract_id == "claudecode-hooks-v1"
    assert claude.capabilities is not None
    assert claude.capabilities.can_ask_native is True
    assert claude.remediations[1].kind is RemediationKind.MANUAL
    assert claude.remediations[1].argv == ("defenseclaw", "setup", "claude-code")
    assert claude.remediations[1].experimental is True

    cursor = by_name["cursor"]
    assert cursor.status is HealthStatus.UNSUPPORTED
    assert cursor.reason_code == "connector-version-outside-contract"
    assert cursor.installed_version == "0.1.0"
    assert cursor.supported_agent_ranges

    openclaw = by_name["openclaw"]
    assert openclaw.status is HealthStatus.SUPPORTED
    assert openclaw.reason_code == "proxy-connector-not-version-gated"
    assert openclaw.capabilities is not None
    assert openclaw.capabilities.connection_kind == "proxy"

    hermes = by_name["hermes"]
    assert hermes.status is HealthStatus.UNAVAILABLE
    assert hermes.reason_code == "connector-agent-unavailable"

    rendered = json.dumps(
        build_health_report(
            ("codex", "claude-code", "cursor", "openclaw", "hermes"),
            discovery,
            components=(
                ComponentEvidence("cli", "0.8.6"),
                ComponentEvidence("gateway", "0.8.6"),
                ComponentEvidence("plugin", "0.8.6"),
            ),
        ).to_dict(),
        sort_keys=True,
    )
    assert "never-reflect-this" not in rendered
    assert "secret.invalid" not in rendered


def test_discovery_absence_is_unavailable_and_unregistered_names_are_bounded() -> None:
    findings = assess_connector_health(
        ("codex", "https://user:password@example.invalid/custom"),
        None,
    )

    assert findings[0].status is HealthStatus.UNAVAILABLE
    assert findings[0].reason_code == "agent-discovery-unavailable"
    assert findings[1].status is HealthStatus.UNSUPPORTED
    assert findings[1].connector == "unregistered-connector"
    assert "password" not in repr(findings)


def test_valid_json_non_object_discovery_cache_is_rejected(tmp_path) -> None:
    (tmp_path / "agent_discovery.json").write_text("[]", encoding="utf-8")

    assert read_cached_discovery(str(tmp_path)) is None


def test_generic_unattended_experimental_repair_is_refused() -> None:
    choice = RemediationChoice(
        choice_id="experimental-connector-repair",
        summary="Experimental connector setup",
        kind=RemediationKind.COMMAND,
        argv=("defenseclaw", "setup", "codex"),
        changes_state=True,
        requires_confirmation=True,
        unattended_allowed=True,
        experimental=True,
    )

    with pytest.raises(RemediationAuthorizationError) as exc:
        authorize_remediation(choice, confirmed=True, unattended=True)
    assert exc.value.code == "experimental-unattended-repair-refused"

    assert authorize_remediation(choice, confirmed=True, unattended=False) == choice.argv


def test_manual_choices_are_never_promoted_to_executable_repairs() -> None:
    choice = RemediationChoice(
        choice_id="manual",
        summary="Manual action",
        kind=RemediationKind.MANUAL,
        argv=("defenseclaw", "setup", "codex"),
        changes_state=True,
        requires_confirmation=True,
    )

    with pytest.raises(RemediationAuthorizationError) as exc:
        authorize_remediation(choice, confirmed=True)
    assert exc.value.code == "manual-remediation-required"
