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

"""Typed, secret-safe Doctor health evidence.

This module deliberately has no Click integration and performs no repair.  It
turns the existing component probes, connector contract manifest, and cached
agent-discovery evidence into a bounded schema that a future Doctor renderer or
fix planner can consume safely.

Discovery is evidence, not authority: a discovered binary or version never
authorizes setup or execution.  Remediation choices are exact and carry enough
policy metadata for callers to reject unattended or experimental changes.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from defenseclaw.connector_contracts import (
    HOOK_CONTRACTS,
    PROXY_CONNECTORS,
    STATUS_KNOWN,
    STATUS_NOT_GATED,
    STATUS_UNVERSIONED,
    ConnectorContract,
    normalize_agent_version,
    normalize_connector,
    resolve_connector_contract,
)

_COMPONENT_NAMES = ("cli", "gateway", "plugin")
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,127}$")


class HealthStatus(str, Enum):
    """Bounded compatibility state exposed by Doctor."""

    SUPPORTED = "supported"
    UNTESTED = "untested"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"


class RemediationKind(str, Enum):
    """Whether a remediation can be represented as one exact argv."""

    COMMAND = "command"
    MANUAL = "manual"


@dataclass(frozen=True)
class RemediationChoice:
    """One explicit remediation option.

    ``argv`` is displayable for manual choices, but
    :func:`authorize_remediation` never returns a manual choice for execution.
    This lets Doctor explain an exact interactive command without turning it
    into a generic unattended repair primitive.
    """

    choice_id: str
    summary: str
    kind: RemediationKind
    argv: tuple[str, ...] = ()
    changes_state: bool = False
    requires_confirmation: bool = False
    unattended_allowed: bool = False
    experimental: bool = False


class RemediationAuthorizationError(ValueError):
    """Raised when a caller tries to execute a choice outside its policy."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def authorize_remediation(
    choice: RemediationChoice,
    *,
    confirmed: bool = False,
    unattended: bool = False,
) -> tuple[str, ...]:
    """Return an authorized argv without executing it.

    Manual choices are never executable through this API.  Experimental
    choices require an attended confirmation, and every state-changing choice
    can independently require confirmation.  Consequently, a generic
    ``doctor --fix --yes`` loop cannot silently apply an untested connector
    setup command.
    """

    if choice.kind is not RemediationKind.COMMAND or not choice.argv:
        raise RemediationAuthorizationError("manual-remediation-required")
    if unattended and choice.experimental:
        raise RemediationAuthorizationError("experimental-unattended-repair-refused")
    if unattended and not choice.unattended_allowed:
        raise RemediationAuthorizationError("unattended-repair-refused")
    if (choice.experimental or choice.changes_state or choice.requires_confirmation) and not confirmed:
        raise RemediationAuthorizationError("confirmation-required")
    return choice.argv


@dataclass(frozen=True)
class ComponentEvidence:
    """Secret-free subset accepted from the existing version probes."""

    name: str
    version: str
    status: str = "ok"


@dataclass(frozen=True)
class ComponentHealthFinding:
    component: str
    status: HealthStatus
    reason_code: str
    summary: str
    installed_version: str = ""
    expected_version: str = ""
    capabilities: tuple[str, ...] = ()
    remediations: tuple[RemediationChoice, ...] = ()


@dataclass(frozen=True)
class VersionRange:
    contract_id: str
    min_inclusive: str = ""
    max_exclusive: str = ""


@dataclass(frozen=True)
class ConnectorCapabilities:
    """Manifest-derived connector capabilities with no free-form notes."""

    connection_kind: str
    can_block: bool = False
    can_ask_native: bool = False
    supports_fail_closed: bool = False
    supports_traceparent: bool = False
    native_otlp: bool = False
    native_otlp_auth: str = ""
    native_otlp_signals: tuple[str, ...] = ()
    events: tuple[str, ...] = ()
    aid_surfaces: tuple[str, ...] = ()
    ask_events: tuple[str, ...] = ()
    block_events: tuple[str, ...] = ()
    scope: str = ""


@dataclass(frozen=True)
class ConnectorHealthFinding:
    connector: str
    status: HealthStatus
    reason_code: str
    summary: str
    installed_version: str = ""
    contract_id: str = ""
    supported_agent_ranges: tuple[VersionRange, ...] = ()
    capabilities: ConnectorCapabilities | None = None
    remediations: tuple[RemediationChoice, ...] = ()


@dataclass(frozen=True)
class DoctorHealthReport:
    components: tuple[ComponentHealthFinding, ...]
    connectors: tuple[ConnectorHealthFinding, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready representation containing only bounded fields."""

        return {
            "components": [_component_finding_dict(finding) for finding in self.components],
            "connectors": [_connector_finding_dict(finding) for finding in self.connectors],
        }


_COMPONENT_CAPABILITIES: dict[str, tuple[str, ...]] = {
    "cli": ("configuration", "diagnostics", "upgrade-control"),
    "gateway": ("policy-enforcement", "sidecar-api", "telemetry"),
    "plugin": ("openclaw-integration",),
}


def probe_component_evidence() -> tuple[ComponentEvidence, ...]:
    """Run the existing CLI/gateway/plugin probes and discard unsafe detail.

    Origins, subprocess output, exception text, build metadata, and filesystem
    paths intentionally do not cross this adapter.
    """

    from defenseclaw.commands import cmd_version

    components = (
        cmd_version._cli_component(),
        cmd_version._gateway_component(),
        cmd_version._plugin_component(),
    )
    return tuple(
        ComponentEvidence(name=component.name, version=component.version, status=component.status)
        for component in components
    )


def read_cached_discovery(data_dir: str) -> Any | None:
    """Read valid bounded discovery evidence without scanning or writing.

    Doctor dry-runs promise not to mutate the installation.  The normal
    discovery entrypoint refreshes and persists its cache when evidence is
    absent, so health checks use only an already-valid cache and offer the
    explicit refresh command when it is missing or expired.
    """

    if not isinstance(data_dir, str) or not data_dir or "\x00" in data_dir:
        return None
    from defenseclaw.inventory.agent_discovery import _read_cache

    return _read_cache(data_dir=data_dir)


def assess_component_health(
    evidence: Iterable[ComponentEvidence],
) -> tuple[ComponentHealthFinding, ...]:
    """Assess CLI/gateway/plugin version alignment against the invoked CLI."""

    by_name: dict[str, ComponentEvidence] = {}
    for item in evidence:
        if item.name in _COMPONENT_NAMES and item.name not in by_name:
            by_name[item.name] = item

    cli = by_name.get("cli")
    expected = _safe_semver(cli.version) if cli and cli.status == "ok" else ""
    findings: list[ComponentHealthFinding] = []
    for name in _COMPONENT_NAMES:
        item = by_name.get(name)
        capabilities = _COMPONENT_CAPABILITIES[name]
        if item is None or item.status != "ok":
            findings.append(
                ComponentHealthFinding(
                    component=name,
                    status=HealthStatus.UNAVAILABLE,
                    reason_code="component-not-available",
                    summary=f"{name} version evidence is unavailable",
                    expected_version=expected,
                    capabilities=capabilities,
                    remediations=_component_remediations(name, HealthStatus.UNAVAILABLE, expected),
                )
            )
            continue

        installed = _safe_semver(item.version)
        if not installed:
            findings.append(
                ComponentHealthFinding(
                    component=name,
                    status=HealthStatus.UNTESTED,
                    reason_code="component-version-unparseable",
                    summary=f"{name} version could not be verified",
                    expected_version=expected,
                    capabilities=capabilities,
                    remediations=_component_remediations(name, HealthStatus.UNTESTED, expected),
                )
            )
            continue

        if name == "cli":
            findings.append(
                ComponentHealthFinding(
                    component=name,
                    status=HealthStatus.SUPPORTED,
                    reason_code="cli-version-reference",
                    summary="CLI version is the component compatibility reference",
                    installed_version=installed,
                    expected_version=installed,
                    capabilities=capabilities,
                )
            )
            continue

        if not expected:
            findings.append(
                ComponentHealthFinding(
                    component=name,
                    status=HealthStatus.UNTESTED,
                    reason_code="cli-version-unavailable",
                    summary=f"{name} version cannot be compared without a verified CLI version",
                    installed_version=installed,
                    capabilities=capabilities,
                    remediations=_component_remediations(name, HealthStatus.UNTESTED, ""),
                )
            )
        elif installed != expected:
            findings.append(
                ComponentHealthFinding(
                    component=name,
                    status=HealthStatus.UNSUPPORTED,
                    reason_code="component-version-drift",
                    summary=f"{name} version does not match the CLI release",
                    installed_version=installed,
                    expected_version=expected,
                    capabilities=capabilities,
                    remediations=_component_remediations(name, HealthStatus.UNSUPPORTED, expected),
                )
            )
        else:
            findings.append(
                ComponentHealthFinding(
                    component=name,
                    status=HealthStatus.SUPPORTED,
                    reason_code="component-version-aligned",
                    summary=f"{name} version matches the CLI release",
                    installed_version=installed,
                    expected_version=expected,
                    capabilities=capabilities,
                )
            )
    return tuple(findings)


def assess_connector_health(
    active_connectors: Iterable[str],
    discovery: Any | None,
) -> tuple[ConnectorHealthFinding, ...]:
    """Assess every configured connector from existing discovery evidence.

    The function never scans the host, reads connector config, or executes an
    agent binary.  Callers choose when and how discovery evidence is produced.
    """

    active = _normalized_active_connectors(active_connectors)
    signals = _normalized_discovery_signals(discovery)
    findings: list[ConnectorHealthFinding] = []
    for connector in active:
        public_name = (
            connector if connector in PROXY_CONNECTORS or connector in HOOK_CONTRACTS else "unregistered-connector"
        )
        ranges = _supported_ranges(connector)

        if connector not in PROXY_CONNECTORS and connector not in HOOK_CONTRACTS:
            findings.append(
                ConnectorHealthFinding(
                    connector=public_name,
                    status=HealthStatus.UNSUPPORTED,
                    reason_code="connector-contract-unregistered",
                    summary="Active connector has no registered DefenseClaw compatibility contract",
                    remediations=(_interactive_setup_choice(public_name, experimental=True),),
                )
            )
            continue

        signal = signals.get(connector)
        if discovery is None:
            findings.append(
                ConnectorHealthFinding(
                    connector=public_name,
                    status=HealthStatus.UNAVAILABLE,
                    reason_code="agent-discovery-unavailable",
                    summary=f"{public_name} compatibility cannot be checked without discovery evidence",
                    supported_agent_ranges=ranges,
                    remediations=_unavailable_connector_remediations(public_name),
                )
            )
            continue
        if signal is None or not bool(getattr(signal, "installed", False)):
            findings.append(
                ConnectorHealthFinding(
                    connector=public_name,
                    status=HealthStatus.UNAVAILABLE,
                    reason_code="connector-agent-unavailable",
                    summary=f"{public_name} is active but its agent installation is unavailable",
                    supported_agent_ranges=ranges,
                    remediations=_unavailable_connector_remediations(public_name),
                )
            )
            continue

        raw_version = getattr(signal, "version", "")
        raw_version = raw_version if isinstance(raw_version, str) else ""
        compatibility = resolve_connector_contract(connector, raw_version)

        if compatibility.status == STATUS_NOT_GATED:
            findings.append(
                ConnectorHealthFinding(
                    connector=public_name,
                    status=HealthStatus.SUPPORTED,
                    reason_code="proxy-connector-not-version-gated",
                    summary=f"{public_name} uses a proxy contract and is not agent-version gated",
                    installed_version=_safe_semver_from_agent(raw_version),
                    capabilities=ConnectorCapabilities(connection_kind="proxy"),
                )
            )
            continue

        if compatibility.status == STATUS_KNOWN and compatibility.contract is not None:
            contract = compatibility.contract
            findings.append(
                ConnectorHealthFinding(
                    connector=public_name,
                    status=HealthStatus.SUPPORTED,
                    reason_code="connector-contract-matched",
                    summary=f"{public_name} matches a supported connector contract",
                    installed_version=_safe_semver_from_agent(raw_version),
                    contract_id=_safe_token(contract.contract_id),
                    supported_agent_ranges=ranges,
                    capabilities=_contract_capabilities(contract),
                )
            )
            continue

        if compatibility.status == STATUS_UNVERSIONED:
            contract = compatibility.contract
            findings.append(
                ConnectorHealthFinding(
                    connector=public_name,
                    status=HealthStatus.UNTESTED,
                    reason_code="connector-version-not-observed",
                    summary=f"{public_name} is installed, but its version was not observed",
                    contract_id=_safe_token(contract.contract_id) if contract else "",
                    supported_agent_ranges=ranges,
                    capabilities=_contract_capabilities(contract) if contract else None,
                    remediations=_untested_connector_remediations(public_name),
                )
            )
            continue

        normalized = _safe_semver_from_agent(raw_version)
        if normalized:
            findings.append(
                ConnectorHealthFinding(
                    connector=public_name,
                    status=HealthStatus.UNSUPPORTED,
                    reason_code="connector-version-outside-contract",
                    summary=f"{public_name} agent version is outside the registered contract ranges",
                    installed_version=normalized,
                    supported_agent_ranges=ranges,
                    remediations=_unsupported_connector_remediations(public_name, ranges),
                )
            )
        else:
            findings.append(
                ConnectorHealthFinding(
                    connector=public_name,
                    status=HealthStatus.UNTESTED,
                    reason_code="connector-version-unparseable",
                    summary=f"{public_name} agent version could not be verified",
                    supported_agent_ranges=ranges,
                    remediations=_untested_connector_remediations(public_name),
                )
            )
    return tuple(findings)


def build_health_report(
    active_connectors: Iterable[str],
    discovery: Any | None,
    *,
    components: Iterable[ComponentEvidence] | None = None,
) -> DoctorHealthReport:
    """Build the standalone health report.

    Passing component evidence keeps this function side-effect free.  Omitting
    it opts into the existing read-only version probes.
    """

    component_evidence = probe_component_evidence() if components is None else tuple(components)
    return DoctorHealthReport(
        components=assess_component_health(component_evidence),
        connectors=assess_connector_health(active_connectors, discovery),
    )


def _safe_semver(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    # Component releases require all three numeric segments.  Keep only the
    # normalized triple so prerelease/build text or hostile probe output is
    # never reflected in Doctor output.
    stripped = value.strip()
    if len(stripped) > 128:
        return ""
    match = re.fullmatch(r"v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+][A-Za-z0-9.-]+)?", stripped)
    if not match:
        return ""
    try:
        return ".".join(str(int(match.group(index))) for index in (1, 2, 3))
    except ValueError:
        return ""


def _safe_semver_from_agent(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = normalize_agent_version(value[:512])
    return normalized if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", normalized) else ""


def _safe_token(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    stripped = value.strip()
    return stripped if _SAFE_TOKEN_RE.fullmatch(stripped) else ""


def _safe_tokens(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(token for item in value if (token := _safe_token(item)))


def _component_remediations(
    component: str,
    status: HealthStatus,
    expected_version: str,
) -> tuple[RemediationChoice, ...]:
    if status is HealthStatus.SUPPORTED:
        return ()
    if component == "gateway" and expected_version:
        return (
            RemediationChoice(
                choice_id="upgrade-gateway-release",
                summary=f"Run the authenticated DefenseClaw upgrade to release {expected_version}",
                kind=RemediationKind.COMMAND,
                argv=("defenseclaw", "upgrade", "--version", expected_version),
                changes_state=True,
                requires_confirmation=True,
                unattended_allowed=False,
            ),
        )
    if component == "plugin" and expected_version:
        return (
            RemediationChoice(
                choice_id="reinstall-openclaw-plugin-release",
                summary=f"Reinstall the OpenClaw plugin from the DefenseClaw {expected_version} release tarball",
                kind=RemediationKind.MANUAL,
                changes_state=True,
                requires_confirmation=True,
                unattended_allowed=False,
            ),
        )
    return (
        RemediationChoice(
            choice_id="inspect-component-versions",
            summary="Inspect the bounded component version report",
            kind=RemediationKind.COMMAND,
            argv=("defenseclaw", "version", "--json", "--no-drift-exit"),
            changes_state=False,
            unattended_allowed=True,
        ),
    )


def _normalized_active_connectors(connectors: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for raw in connectors:
        if not isinstance(raw, str) or len(raw) > 128:
            name = ""
        else:
            name = normalize_connector(raw)
        if not name:
            name = "invalid-connector"
        if name in seen:
            continue
        seen.add(name)
        result.append(name)
    return tuple(result)


def _normalized_discovery_signals(discovery: Any | None) -> dict[str, Any]:
    agents = getattr(discovery, "agents", None)
    if not isinstance(agents, Mapping):
        return {}
    result: dict[str, Any] = {}
    for raw_name, signal in agents.items():
        if not isinstance(raw_name, str):
            continue
        if len(raw_name) > 128:
            continue
        name = normalize_connector(raw_name)
        if name and name not in result:
            result[name] = signal
    return result


def _supported_ranges(connector: str) -> tuple[VersionRange, ...]:
    ranges: list[VersionRange] = []
    for contract in HOOK_CONTRACTS.get(connector, ()):
        contract_id = _safe_token(contract.contract_id)
        minimum = _safe_semver(contract.min_agent_version) if contract.min_agent_version else ""
        maximum = _safe_semver(contract.max_agent_version) if contract.max_agent_version else ""
        if contract_id:
            ranges.append(
                VersionRange(
                    contract_id=contract_id,
                    min_inclusive=minimum,
                    max_exclusive=maximum,
                )
            )
    return tuple(ranges)


def _contract_capabilities(contract: ConnectorContract) -> ConnectorCapabilities:
    raw = contract.capabilities if isinstance(contract.capabilities, Mapping) else {}
    return ConnectorCapabilities(
        connection_kind="hook",
        can_block=raw.get("can_block") is True,
        can_ask_native=raw.get("can_ask_native") is True,
        supports_fail_closed=raw.get("supports_fail_closed") is True,
        supports_traceparent=contract.supports_traceparent,
        native_otlp=contract.native_otlp,
        native_otlp_auth=_safe_token(contract.native_otlp_auth),
        native_otlp_signals=_safe_tokens(contract.native_otlp_signals),
        events=_safe_tokens(contract.events),
        aid_surfaces=_safe_tokens(contract.aid_surfaces),
        ask_events=_safe_tokens(raw.get("ask_events")),
        block_events=_safe_tokens(raw.get("block_events")),
        scope=_safe_token(raw.get("scope")),
    )


def _setup_command_name(connector: str) -> str:
    return "claude-code" if connector == "claudecode" else connector


def _refresh_discovery_choice() -> RemediationChoice:
    return RemediationChoice(
        choice_id="refresh-agent-discovery",
        summary="Refresh bounded local agent discovery evidence",
        kind=RemediationKind.COMMAND,
        argv=("defenseclaw", "agent", "discover", "--refresh", "--no-emit-otel"),
        changes_state=True,
        unattended_allowed=True,
    )


def _interactive_setup_choice(connector: str, *, experimental: bool) -> RemediationChoice:
    setup_name = _setup_command_name(connector)
    return RemediationChoice(
        choice_id="review-interactive-connector-setup",
        summary=f"Review {connector} setup and choose the intended mode interactively",
        kind=RemediationKind.MANUAL,
        argv=("defenseclaw", "setup", setup_name),
        changes_state=True,
        requires_confirmation=True,
        unattended_allowed=False,
        experimental=experimental,
    )


def _untested_connector_remediations(connector: str) -> tuple[RemediationChoice, ...]:
    return (
        _refresh_discovery_choice(),
        _interactive_setup_choice(connector, experimental=True),
    )


def _unavailable_connector_remediations(connector: str) -> tuple[RemediationChoice, ...]:
    return (
        RemediationChoice(
            choice_id="install-connector-agent",
            summary=f"Install {connector} from its trusted vendor distribution",
            kind=RemediationKind.MANUAL,
            changes_state=True,
            requires_confirmation=True,
            unattended_allowed=False,
        ),
        _refresh_discovery_choice(),
    )


def _unsupported_connector_remediations(
    connector: str,
    ranges: tuple[VersionRange, ...],
) -> tuple[RemediationChoice, ...]:
    range_text = ", ".join(_range_label(item) for item in ranges) or "a registered version"
    return (
        RemediationChoice(
            choice_id="install-supported-connector-version",
            summary=f"Install {connector} {range_text} from its trusted vendor distribution",
            kind=RemediationKind.MANUAL,
            changes_state=True,
            requires_confirmation=True,
            unattended_allowed=False,
        ),
        _refresh_discovery_choice(),
    )


def _range_label(value: VersionRange) -> str:
    parts: list[str] = []
    if value.min_inclusive:
        parts.append(f">={value.min_inclusive}")
    if value.max_exclusive:
        parts.append(f"<{value.max_exclusive}")
    return " ".join(parts) or value.contract_id


def _remediation_dict(choice: RemediationChoice) -> dict[str, Any]:
    return {
        "choice_id": choice.choice_id,
        "summary": choice.summary,
        "kind": choice.kind.value,
        "argv": list(choice.argv),
        "changes_state": choice.changes_state,
        "requires_confirmation": choice.requires_confirmation,
        "unattended_allowed": choice.unattended_allowed,
        "experimental": choice.experimental,
    }


def _component_finding_dict(finding: ComponentHealthFinding) -> dict[str, Any]:
    return {
        "component": finding.component,
        "status": finding.status.value,
        "reason_code": finding.reason_code,
        "summary": finding.summary,
        "installed_version": finding.installed_version,
        "expected_version": finding.expected_version,
        "capabilities": list(finding.capabilities),
        "remediations": [_remediation_dict(choice) for choice in finding.remediations],
    }


def _connector_finding_dict(finding: ConnectorHealthFinding) -> dict[str, Any]:
    capabilities = finding.capabilities
    return {
        "connector": finding.connector,
        "status": finding.status.value,
        "reason_code": finding.reason_code,
        "summary": finding.summary,
        "installed_version": finding.installed_version,
        "contract_id": finding.contract_id,
        "supported_agent_ranges": [
            {
                "contract_id": item.contract_id,
                "min_inclusive": item.min_inclusive,
                "max_exclusive": item.max_exclusive,
            }
            for item in finding.supported_agent_ranges
        ],
        "capabilities": (
            None
            if capabilities is None
            else {
                "connection_kind": capabilities.connection_kind,
                "can_block": capabilities.can_block,
                "can_ask_native": capabilities.can_ask_native,
                "supports_fail_closed": capabilities.supports_fail_closed,
                "supports_traceparent": capabilities.supports_traceparent,
                "native_otlp": capabilities.native_otlp,
                "native_otlp_auth": capabilities.native_otlp_auth,
                "native_otlp_signals": list(capabilities.native_otlp_signals),
                "events": list(capabilities.events),
                "aid_surfaces": list(capabilities.aid_surfaces),
                "ask_events": list(capabilities.ask_events),
                "block_events": list(capabilities.block_events),
                "scope": capabilities.scope,
            }
        ),
        "remediations": [_remediation_dict(choice) for choice in finding.remediations],
    }
