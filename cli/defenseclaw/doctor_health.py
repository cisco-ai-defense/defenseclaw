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

import dataclasses
import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from defenseclaw.connector_contracts import (
    HOOK_CONTRACTS,
    KIRO_CLI_HOOK_FLOOR,
    KIRO_FORM_CLI,
    KIRO_FORM_IDE,
    KIRO_IDE_GLOBAL_HOOKS_FLOOR,
    PROXY_CONNECTORS,
    REGISTERED_CONNECTORS,
    STATUS_KNOWN,
    STATUS_NOT_GATED,
    STATUS_UNVERSIONED,
    ConnectorContract,
    KiroFormVerdict,
    assess_kiro,
    assess_kiro_signal,
    judge_kiro_form,
    kiro_cli_below_hook_floor,
    kiro_cli_below_hook_floor_reason,
    kiro_ide_below_hook_floor,
    known_broken_entry,
    known_warning_entry,
    normalize_agent_version,
    normalize_connector,
    resolve_connector_contract,
)

_COMPONENT_NAMES = ("cli", "gateway", "plugin")
_CONNECTOR_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
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


def _openclaw_compatibility_summary(public_name: str, raw_version: str) -> str:
    # The doctor row names the hook mode OpenClaw runs in, from the OS and the
    # probed version only (rel-1-0-10 GAP-0047): Windows is native, before
    # 2026.8.35 the proxy, otherwise hybrid.
    from defenseclaw.connector_contracts import openclaw_lacks_native_hooks
    from defenseclaw.platform_support import uses_guardrail_proxy

    if not uses_guardrail_proxy("openclaw"):
        # Windows: no proxy; setup refuses an OpenClaw before 2026.8.35.
        return (
            f"{public_name} uses its native plugin hooks (no guardrail proxy on this host) "
            "and is not agent-version gated"
        )
    if raw_version and openclaw_lacks_native_hooks(raw_version):
        return (
            f"{public_name} uses the guardrail proxy and is not agent-version gated "
            "(native hooks need OpenClaw 2026.8.35 or later)"
        )
    return f"{public_name} uses its plugin hooks next to the proxy and is not agent-version gated"


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


_AUTO_GATEWAY_EXECUTABLE = object()


def probe_component_evidence(
    *,
    gateway_executable: str | None | object = _AUTO_GATEWAY_EXECUTABLE,
) -> tuple[ComponentEvidence, ...]:
    """Run the existing CLI/gateway/plugin probes and discard unsafe detail.

    Origins, subprocess output, exception text, build metadata, and filesystem
    paths intentionally do not cross this adapter.  Supplying
    ``gateway_executable`` (including an explicit ``None``) makes the gateway
    probe use exactly that lifecycle controller rather than resolving another
    binary from the ambient environment.
    """

    from defenseclaw.commands import cmd_version

    gateway_component = (
        cmd_version._gateway_component()
        if gateway_executable is _AUTO_GATEWAY_EXECUTABLE
        else cmd_version._gateway_component_for_binary(
            gateway_executable if isinstance(gateway_executable, str) else None,
            pinned=True,
        )
    )
    components = (
        cmd_version._cli_component(),
        gateway_component,
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

    return _read_cache(data_dir=data_dir) or _discovery_from_hook_contract_lock(data_dir)


@dataclass(frozen=True)
class _LockDiscovery:
    """Agent versions the gateway recorded; it covers only the connectors it lists."""

    agents: Mapping[str, Any]
    partial: bool = True


def _discovery_from_hook_contract_lock(data_dir: str) -> _LockDiscovery | None:
    """Agent versions from the gateway's hook_contract_lock.json.

    The gateway probes each hook connector's agent at start and records the
    version it selected the contract from. The discovery cache expires after
    a day, and an upgrade starts without one, so Doctor falls back to this
    evidence instead of reporting compatibility as unknown. It reads a file;
    it never runs an agent.
    """

    import json
    import os

    from defenseclaw.inventory.agent_discovery import AgentSignal

    path = os.path.join(data_dir, "hook_contract_lock.json")
    try:
        if os.path.getsize(path) > 4 << 20:
            return None
        with open(path, encoding="utf-8") as fh:
            lock = json.load(fh)
    except (OSError, ValueError):
        return None
    entries = lock.get("connectors") if isinstance(lock, Mapping) else None
    if not isinstance(entries, Mapping):
        return None
    agents: dict[str, Any] = {}
    for name, entry in entries.items():
        if not isinstance(name, str) or not isinstance(entry, Mapping):
            continue
        version = entry.get("raw_agent_version")
        if isinstance(version, str) and version.strip():
            executable = entry.get("agent_executable")
            agents[name] = AgentSignal(
                name=name,
                installed=True,
                config_path="",
                binary_path=executable if isinstance(executable, str) else "",
                version=version,
                error="",
            )
    return _LockDiscovery(agents=agents) if agents else None


@dataclass(frozen=True)
class InstalledVersionCheck:
    """Discovery evidence with each agent version re-read now.

    ``changed`` maps a connector to the semver the evidence recorded, when
    the agent reports another one today (empty when the recorded text held no
    plain version: probe-style evidence never reaches a row). ``unchecked``
    maps a connector to why its recorded version could not be re-read; its
    row must call the value recorded, not installed (GAP-0723).
    """

    discovery: Any | None
    changed: Mapping[str, str]
    unchecked: Mapping[str, str]


#: One answer is shared by everything one Doctor run judges: the connector
#: safety gate, the repair planner and the compatibility row. That covers both
#: which executables an agent can launch from (the candidate list is built
#: once, newly discovered paths first, the recorded one last) and what each one
#: answers (every candidate is probed once), so the gate and the row can never
#: judge two different installs, however long the run takes. Doctor opens the
#: run scope and closes it when the command ends; outside a run an answer is
#: kept for this long only.
_PROBE_SHARE_SECONDS = 120.0
_probe_answers: dict[tuple[str, str, str], tuple[float, str, str]] = {}
_candidate_lists: dict[tuple[str, str], tuple[float, tuple[str, ...]]] = {}
#: The discovery evidence the run judges (it names the recorded executable and
#: version every candidate list is ordered against). It is read once per run:
#: a cache or lock update halfway through must not hand the gate one recorded
#: path and the row another. Only a run shares it; there is no time bound.
_run_evidence: dict[str, Any] = {}
_probe_run_scoped = False


def begin_installed_version_run() -> None:
    """Open a Doctor run: candidates and probe answers are shared until it ends."""

    global _probe_run_scoped
    reset_installed_version_probes()
    _probe_run_scoped = True


def end_installed_version_run() -> None:
    """Close the Doctor run (answers are forgotten, the time bound applies again)."""

    global _probe_run_scoped
    reset_installed_version_probes()
    _probe_run_scoped = False


def reset_installed_version_probes() -> None:
    """Forget every shared candidate list and probe answer (Doctor calls it
    after an attended discovery refresh, which just re-read every version)."""

    _probe_answers.clear()
    _candidate_lists.clear()
    _run_evidence.clear()


def read_run_discovery(data_dir: str) -> Any | None:
    """:func:`read_cached_discovery`, read once for the whole Doctor run.

    The gate, the planner and the row all start from this one evidence object,
    so they pick the same recorded path and compare the same recorded version.
    Outside a run every call reads the cache again.
    """

    if not _probe_run_scoped:
        return read_cached_discovery(data_dir)
    if data_dir not in _run_evidence:
        _run_evidence[data_dir] = read_cached_discovery(data_dir)
    return _run_evidence[data_dir]


def _fresh(stamp: float) -> bool:
    return _probe_run_scoped or time.monotonic() - stamp < _PROBE_SHARE_SECONDS


def _probe_agent_version(name: str, path: str, data_dir: str) -> tuple[str, str]:
    from defenseclaw.inventory import agent_discovery

    key = (name, path, data_dir)
    hit = _probe_answers.get(key)
    if hit is not None and _fresh(hit[0]):
        return hit[1], hit[2]
    spec = agent_discovery._SPECS.get(name)
    version_args = spec.version_args if spec is not None else ("--version",)
    found, error = agent_discovery._version_for_agent_binary(name, path, version_args, data_dir=data_dir or None)
    _probe_answers[key] = (time.monotonic(), found, error)
    return found, error


def _launch_candidates(name: str, data_dir: str) -> tuple[str, ...]:
    """The executables the agent launches from now, in discovery order.

    Listed once per Doctor run (and once per share bound outside one): an
    install that appears while the run goes on joins the next run, not the
    gate or the row halfway through this one.
    """

    from defenseclaw.inventory import agent_discovery

    key = (name, data_dir)
    hit = _candidate_lists.get(key)
    if hit is not None and _fresh(hit[0]):
        return hit[1]
    spec = agent_discovery._SPECS.get(name)
    try:
        listed = agent_discovery._binary_candidates_for_agent(name, spec) if spec is not None else ()
    except Exception:  # noqa: BLE001 - candidate listing is best effort; the recorded path still counts.
        listed = ()
    paths: list[str] = []
    seen: set[str] = set()
    for candidate in listed:
        if candidate and agent_discovery._path_key(candidate) not in seen:
            seen.add(agent_discovery._path_key(candidate))
            paths.append(candidate)
    _candidate_lists[key] = (time.monotonic(), tuple(paths))
    return _candidate_lists[key][1]


def _current_executable(name: str, recorded_path: str, data_dir: str) -> tuple[str, str, str]:
    """Find the executable the agent launches from now and read its version.

    Discovery walks its launch candidates in order and keeps the first that
    reports a version; an update can put a new executable ahead of the one the
    evidence recorded (another package manager, another install root), so the
    recorded path alone can name an agent that is no longer the one launched.
    Walk the same candidates, the recorded path last (and only if it still
    answers), and return ``(path, version, error)`` of the first that answers;
    ``error`` is the first probe failure when none does.
    """

    from defenseclaw.inventory import agent_discovery

    candidates = list(_launch_candidates(name, data_dir))
    if recorded_path.strip() and agent_discovery._path_key(recorded_path) not in {
        agent_discovery._path_key(c) for c in candidates
    }:
        candidates.append(recorded_path)
    first_error = ""
    for candidate in candidates:
        found, error = _probe_agent_version(name, candidate, data_dir)
        if found.strip() and not error:
            return candidate, found, ""
        first_error = first_error or error or "no version"
    return "", "", first_error


def _probe_failure_reason(error: str) -> str:
    from defenseclaw.inventory import agent_discovery

    if error == agent_discovery.UNTRUSTED_PREFIX_ERROR:
        return "its executable is not in a trusted install location"
    if error == agent_discovery.VERSION_PROBE_TIMED_OUT:
        return "the version probe timed out"
    return "the version probe did not return a version"


def _recheck_kiro(signal: Any, data_dir: str) -> tuple[Any, bool, str]:
    """Re-read every Kiro install the evidence names and re-judge the forms.

    Kiro is judged form by form (assess_kiro_signal), from ``kiro_forms`` and
    not from ``AgentSignal.version``, so every form is probed on the path the
    evidence recorded for it. Evidence that names a version without the path
    of each form it covers cannot be re-read and stays recorded. A form that
    cannot be read now stays as recorded and the connector is ``unchecked``.
    Returns ``(signal, changed, unchecked_reason)``.
    """

    from defenseclaw.inventory import agent_discovery

    recorded_forms = getattr(signal, "kiro_forms", None)
    if isinstance(recorded_forms, (list, tuple)) and recorded_forms:
        forms = [{k: str(v or "") for k, v in f.items()} for f in recorded_forms if isinstance(f, dict)]
        if not forms or any(not f.get("path", "").strip() for f in forms):
            return signal, False, "an install it recorded has no executable path"
    else:
        path = getattr(signal, "binary_path", "")
        version = getattr(signal, "version", "")
        if getattr(signal, "kiro_cli_version", "") and getattr(signal, "kiro_ide_version", ""):
            return signal, False, "the paths of its installs are not recorded"
        if not isinstance(path, str) or not path.strip():
            return signal, False, "no executable path is recorded"
        forms = [{"kind": "", "version": version if isinstance(version, str) else "", "unread": "", "path": path}]

    # Fresh discovery judges the launch candidates in launch order, so the
    # forms are rebuilt the same way: every current candidate first (a new
    # install ahead of the recorded one is selected before it), then a
    # recorded install the candidates no longer name only if it still
    # answers. One that does not is retired: it is no longer an install, and
    # judging it would turn stale evidence into a verdict (a PASS for a copy
    # that is gone, a failure for one that was replaced). A current install
    # that cannot answer keeps the form recorded for it and is labelled
    # recorded=; one that was never recorded is not invented.
    recorded_by_path = {agent_discovery._path_key(f["path"]): f for f in forms}
    current = _launch_candidates("kiro", data_dir)
    current_keys = {agent_discovery._path_key(c) for c in current}
    order = [(c, recorded_by_path.get(agent_discovery._path_key(c))) for c in current]
    order += [(f["path"], f) for f in forms if agent_discovery._path_key(f["path"]) not in current_keys]

    reason = gone = ""
    updated: list[dict[str, str]] = []
    for path, held in order[: agent_discovery._KIRO_FORMS_MAX]:
        retired = agent_discovery._path_key(path) not in current_keys
        found, error = _probe_agent_version("kiro", path, data_dir)
        normalized = normalize_agent_version(found) if found.strip() and not error else ""
        surface = agent_discovery._kiro_binary_surface(path, found) if normalized else ""
        if not normalized or not surface:
            if retired:
                gone = gone or _probe_failure_reason(error)
                continue
            why = _probe_failure_reason(error)
            reason = reason or why
            if held is not None:
                # An install that cannot answer now is unread, as fresh
                # discovery records it: the version it had when recorded is
                # kept out of the judgment, so it neither protects (a stale
                # PASS) nor makes a below-floor install that did answer an
                # auxiliary finding.
                held_version = held.get("version", "")
                ide = bool(held_version) and not held_version.startswith("kiro-cli")
                updated.append(
                    {
                        "kind": held.get("kind", "") or (KIRO_FORM_IDE if ide else KIRO_FORM_CLI),
                        "version": "",
                        "unread": f"{path} is installed, but its version could not be read ({why})",
                        "path": path,
                    }
                )
            continue
        read = f"kiro-cli {normalized}" if surface == KIRO_FORM_CLI else normalized
        updated.append({"kind": surface, "version": read, "unread": "", "path": path})
    if not any(form["version"] for form in updated):
        # Nothing answered: there is no positive evidence either way, so the
        # recorded evidence stays and the row calls it recorded.
        return signal, False, reason or gone or "none of the installs it recorded answers now"

    def same(a: dict[str, str], b: dict[str, str]) -> bool:
        return (
            agent_discovery._path_key(a["path"]) == agent_discovery._path_key(b["path"])
            and normalize_agent_version(a["version"]) == normalize_agent_version(b["version"])
            and (not b.get("kind", "") or a["kind"] == b["kind"])
            and bool(a.get("unread", "")) == bool(b.get("unread", ""))
        )

    changed = len(updated) != len(forms) or not all(same(u, f) for u, f in zip(updated, forms, strict=True))
    if not changed:
        return signal, False, reason

    per_surface: dict[str, tuple[str, str]] = {}
    for form in updated:
        if not form["version"] or form["unread"]:
            continue
        below = kiro_cli_below_hook_floor if form["kind"] == KIRO_FORM_CLI else kiro_ide_below_hook_floor
        held = per_surface.get(form["kind"])
        if held is None or (below(held[1]) and not below(form["version"])):
            per_surface[form["kind"]] = (form["path"], form["version"])
    selected = assess_kiro(
        [judge_kiro_form(f["kind"], f["version"], unread=f["unread"], path=f["path"]) for f in updated]
    ).selected
    binary_path = getattr(signal, "binary_path", "")
    version = getattr(signal, "version", "")
    if selected is not None and selected.path:
        binary_path, version = selected.path, selected.version
    elif per_surface:
        binary_path, version = per_surface.get(KIRO_FORM_CLI) or per_surface[KIRO_FORM_IDE]
    return (
        dataclasses.replace(
            signal,
            binary_path=binary_path,
            version=version,
            error="",
            kiro_cli_version=per_surface.get(KIRO_FORM_CLI, ("", ""))[1],
            kiro_ide_version=per_surface.get(KIRO_FORM_IDE, ("", ""))[1],
            kiro_forms=updated,
        ),
        True,
        # At least one install was read now; an install that did not answer is
        # its own unread finding, not a "recorded" label on the versions read.
        "",
    )


def recheck_installed_versions(
    discovery: Any | None,
    connectors: Iterable[str],
    data_dir: str,
) -> InstalledVersionCheck:
    """Re-read the version of each active connector's agent.

    The discovery cache lives a day and the gateway hook contract lock
    keeps the version setup selected the contract from, so after the agent
    updated both still name the old version. Doctor judged compatibility on
    it and printed it as ``installed``. This runs the same bounded,
    trusted-path-only ``--version`` probe discovery uses (never a scan, a
    write or a terminal) on the executable the evidence names, for every
    connector row that states a version (hook, proxy and Kiro forms alike),
    and returns the evidence with the version found now. A probe that cannot
    run leaves the recorded version in place and says why in ``unchecked``.
    One probe answer is shared by every caller of a Doctor run
    (:func:`reset_installed_version_probes`).

    An installed agent whose evidence holds no version at all (the scan that
    wrote it ran before the connector was set up, or an update followed the
    scan) is read the same way: the row would otherwise warn that the version
    was not observed until `agent discover --refresh` (GAP-0752). Only active
    connectors are probed, so an agent nobody set up is never run.
    """

    agents = getattr(discovery, "agents", None)
    if not isinstance(agents, Mapping) or not dataclasses.is_dataclass(discovery):
        return InstalledVersionCheck(discovery, {}, {})
    from defenseclaw.inventory import agent_discovery

    wanted = set(_normalized_active_connectors(connectors))
    updated = dict(agents)
    replaced = False
    changed: dict[str, str] = {}
    unchecked: dict[str, str] = {}
    for raw_name, signal in agents.items():
        name = normalize_connector(raw_name) if isinstance(raw_name, str) and len(raw_name) <= 128 else ""
        recorded = getattr(signal, "version", "")
        if (
            name not in wanted
            or not dataclasses.is_dataclass(signal)
            or not getattr(signal, "installed", False)
            or not isinstance(recorded, str)
        ):
            continue
        if name == "kiro":
            before = _kiro_installed_token(signal)
            fresh, did_change, why = _recheck_kiro(signal, data_dir)
            if why:
                unchecked[name] = why
            if did_change:
                changed[name] = before
                updated[raw_name] = fresh
                replaced = True
            continue
        if name not in agent_discovery._SPECS:
            unchecked[name] = "no version probe is defined for it"
            continue
        recorded_path = getattr(signal, "binary_path", "")
        recorded_path = recorded_path if isinstance(recorded_path, str) else ""
        path, found, error = _current_executable(name, recorded_path, data_dir)
        if not found:
            unchecked[name] = _probe_failure_reason(error) if error else "no executable path is recorded"
            continue
        version_changed = found.strip() != recorded.strip()
        moved = agent_discovery._path_key(path) != agent_discovery._path_key(recorded_path) if recorded_path else True
        if version_changed and recorded.strip():
            changed[name] = _safe_semver_from_agent(recorded)
        if version_changed or moved:
            updated[raw_name] = dataclasses.replace(
                signal,
                binary_path=path,
                version=found,
                error="",
                source=agent_discovery._agent_source(name, path),
            )
            replaced = True
    if not replaced:
        return InstalledVersionCheck(discovery, {}, unchecked)
    return InstalledVersionCheck(dataclasses.replace(discovery, agents=updated), changed, unchecked)


def _kiro_installed_token(signal: Any) -> str:
    selected = assess_kiro_signal(signal).selected
    return _safe_semver_from_agent(selected.normalized) if selected is not None else ""


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


def _kiro_floor_finding(
    normalized: str, ranges: tuple[str, ...], *, auxiliary: bool = False
) -> ConnectorHealthFinding:
    return ConnectorHealthFinding(
        connector="kiro",
        status=HealthStatus.UNSUPPORTED,
        reason_code="kiro-cli-below-hook-floor-auxiliary" if auxiliary else "connector-version-outside-contract",
        summary=kiro_cli_below_hook_floor_reason(normalized),
        installed_version=normalized,
        supported_agent_ranges=ranges,
        remediations=(
            RemediationChoice(
                choice_id="install-supported-connector-version",
                summary=f"Update Kiro CLI to {KIRO_CLI_HOOK_FLOOR} or later, then rerun setup",
                kind=RemediationKind.MANUAL,
                changes_state=True,
                requires_confirmation=True,
                unattended_allowed=False,
            ),
            _refresh_discovery_choice(),
        ),
    )


def _kiro_form_finding(form: KiroFormVerdict, ranges: tuple[str, ...], *, auxiliary: bool) -> ConnectorHealthFinding:
    """The finding of one Kiro form assess_kiro does not protect.

    An auxiliary form sits beside the protected form setup covers: it is
    reported, but it does not block repairing that form.
    """

    if form.below_floor and form.kind != KIRO_FORM_IDE:
        return _kiro_floor_finding(form.normalized, ranges, auxiliary=auxiliary)
    if form.below_floor:
        return ConnectorHealthFinding(
            connector="kiro",
            status=HealthStatus.UNSUPPORTED,
            reason_code="kiro-ide-below-global-hooks-floor" + ("-auxiliary" if auxiliary else ""),
            summary=(
                f"Kiro IDE {form.normalized} is below {KIRO_IDE_GLOBAL_HOOKS_FLOOR}, the first build that reads "
                "the global ~/.kiro/hooks file, so its agent sessions run without DefenseClaw hooks"
            ),
            installed_version=form.normalized,
            supported_agent_ranges=ranges,
            remediations=(
                RemediationChoice(
                    choice_id="install-supported-connector-version",
                    summary=f"Update Kiro IDE to {KIRO_IDE_GLOBAL_HOOKS_FLOOR} or later, then rerun setup",
                    kind=RemediationKind.MANUAL,
                    changes_state=True,
                    requires_confirmation=True,
                    unattended_allowed=False,
                ),
                _refresh_discovery_choice(),
            ),
        )
    product = "a Kiro IDE install" if form.kind == KIRO_FORM_IDE else "kiro-cli"
    return ConnectorHealthFinding(
        connector="kiro",
        status=HealthStatus.UNTESTED,
        reason_code="kiro-version-unknown-auxiliary" if auxiliary else "connector-version-not-observed",
        summary=(
            f"{product} is installed, but its version could not be read, so DefenseClaw cannot check it "
            "against its hook floor and does not count it as protected"
        ),
        supported_agent_ranges=ranges,
        remediations=_untested_connector_remediations("kiro"),
    )


def _kiro_health_findings(signal: Any, ranges: tuple[str, ...]) -> list[ConnectorHealthFinding]:
    """Kiro's findings from assess_kiro: the protected form setup covers is
    supported, and every other installed form gets its own finding, so a
    supported IDE never hides an old or unreadable kiro-cli (or the reverse)."""

    kiro = assess_kiro_signal(signal)
    if kiro.selected is None:
        return [_kiro_form_finding(form, ranges, auxiliary=False) for form in kiro.forms]
    findings = [
        ConnectorHealthFinding(
            connector="kiro",
            status=HealthStatus.SUPPORTED,
            reason_code="connector-not-version-gated",
            summary="kiro is not agent-version gated",
            installed_version=_safe_semver_from_agent(kiro.selected.normalized),
            capabilities=ConnectorCapabilities(connection_kind="hook"),
        )
    ]
    findings.extend(_kiro_form_finding(form, ranges, auxiliary=True) for form in kiro.unprotected())
    return findings


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
        registered = connector in PROXY_CONNECTORS or connector in HOOK_CONTRACTS or connector in REGISTERED_CONNECTORS
        public_name = connector if registered or _CONNECTOR_NAME_RE.fullmatch(connector) else "unregistered-connector"
        ranges = _supported_ranges(connector)

        if not registered:
            findings.append(
                ConnectorHealthFinding(
                    connector=public_name,
                    status=HealthStatus.UNSUPPORTED,
                    reason_code="connector-contract-unregistered",
                    summary=f"Active connector {public_name} has no registered DefenseClaw compatibility contract",
                    remediations=(_interactive_setup_choice(public_name, experimental=True),),
                )
            )
            continue

        signal = signals.get(connector)
        if discovery is None or (signal is None and getattr(discovery, "partial", False)):
            findings.append(
                ConnectorHealthFinding(
                    connector=public_name,
                    status=HealthStatus.UNAVAILABLE,
                    reason_code="agent-discovery-unavailable",
                    summary=(
                        f"{public_name} compatibility cannot be checked without discovery evidence; "
                        "run: defenseclaw agent discover --refresh"
                    ),
                    supported_agent_ranges=ranges,
                    remediations=(_refresh_discovery_choice(),),
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

        if connector == "kiro":
            findings.extend(_kiro_health_findings(signal, ranges))
            continue

        raw_version = getattr(signal, "version", "")
        raw_version = raw_version if isinstance(raw_version, str) else ""
        compatibility = resolve_connector_contract(connector, raw_version)

        if compatibility.status == STATUS_NOT_GATED:
            proxy = connector in PROXY_CONNECTORS
            findings.append(
                ConnectorHealthFinding(
                    connector=public_name,
                    status=HealthStatus.SUPPORTED,
                    reason_code="proxy-connector-not-version-gated" if proxy else "connector-not-version-gated",
                    summary=(
                        (
                            _openclaw_compatibility_summary(public_name, raw_version)
                            if connector == "openclaw"
                            else f"{public_name} uses a proxy contract and is not agent-version gated"
                        )
                        if proxy
                        else f"{public_name} is not agent-version gated"
                    ),
                    installed_version=_safe_semver_from_agent(raw_version),
                    capabilities=ConnectorCapabilities(connection_kind="proxy" if proxy else "hook"),
                )
            )
            continue

        warned = known_warning_entry(connector, raw_version) if compatibility.warning else None
        if compatibility.status == STATUS_KNOWN and compatibility.contract is not None and warned is not None:
            # Hermes 0.19.0-0.21.0 are guarded except in their TUI and
            # dashboard chat, which run tools without the hooks: a warning
            # that points past those releases, not a failure.
            contract = compatibility.contract
            findings.append(
                ConnectorHealthFinding(
                    connector=public_name,
                    status=HealthStatus.UNTESTED,
                    reason_code="connector-version-partly-guarded",
                    summary=f"{public_name} is guarded, but {warned['reason']}",
                    installed_version=_safe_semver_from_agent(raw_version),
                    contract_id=_safe_token(contract.contract_id),
                    supported_agent_ranges=ranges,
                    capabilities=_contract_capabilities(contract),
                    remediations=_known_broken_connector_remediations(public_name, warned),
                )
            )
            continue

        if compatibility.status == STATUS_KNOWN and compatibility.contract is not None and compatibility.untested:
            contract = compatibility.contract
            newest = _safe_token(compatibility.newest_tested.lstrip("<"))
            findings.append(
                ConnectorHealthFinding(
                    connector=public_name,
                    status=HealthStatus.SUPPORTED,
                    reason_code="connector-version-untested-newer",
                    summary=(
                        f"{public_name} is an untested newer version"
                        + (f" (tested versions end at {newest})" if newest else "")
                        + "; no known problems"
                    ),
                    installed_version=_safe_semver_from_agent(raw_version),
                    contract_id=_safe_token(contract.contract_id),
                    supported_agent_ranges=ranges,
                    capabilities=_contract_capabilities(contract),
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
        broken, _ = known_broken_entry(connector, raw_version)
        if normalized or broken is not None:
            # A known-broken version says why, and points past the broken
            # releases instead of at a range that holds them.
            findings.append(
                ConnectorHealthFinding(
                    connector=public_name,
                    status=HealthStatus.UNSUPPORTED,
                    reason_code="connector-version-outside-contract",
                    summary=(
                        f"{public_name} agent version is on the known-broken list: {broken['reason']}"
                        if broken is not None
                        else f"{public_name} agent version is not covered by a tested connector contract"
                    ),
                    installed_version=normalized,
                    supported_agent_ranges=ranges,
                    remediations=(
                        _known_broken_connector_remediations(public_name, broken)
                        if broken is not None
                        else _unsupported_connector_remediations(public_name, ranges)
                    ),
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
                    remediations=_unreadable_connector_version_remediations(public_name, ranges),
                )
            )
    return tuple(findings)


def connector_agent_missing(data_dir: str, connector: str, *, last_activity_at: Any = None) -> bool:
    """Whether ``connector``'s agent is not installed, so nothing runs the
    hooks setup staged for it (GAP-0513).

    The proof is the gateway's (``connector.CachedAgentNotFound``): the last
    recorded discovery scan found no installation and no executable, however
    old it is, because neither ``status`` nor ``doctor`` rescans and the
    cache's one-day lifetime made a staged connector RUNNING again on day
    two. A verified harness image for the connector (the sandbox-only
    layout, in which setup and the gateway admit the connector for the
    agent inside the image) is not missing. An executable on the PATH of
    the shell that runs status or doctor is no proof either way: that shell
    is not the agent, and any file named like the agent on its PATH would
    otherwise turn a negative scan into a healthy RUNNING row (1.0.4
    review, loop round 4). Such an agent counts once ``defenseclaw agent
    discover --refresh`` records it or the gateway takes a hook call from
    it; until then status and doctor only name it (GAP-0052). Without a
    recorded scan there is no proof, so the answer is then False. Nothing
    is scanned or run.

    ``last_activity_at`` is the gateway's last authenticated hook call for
    the connector (``ConnectorHealth.last_activity_at``). A call after the
    scan proves the agent runs (Claude Code started from an absolute path or
    an IDE after a scan that missed it), so the stale scan is no proof; with
    a scan time that cannot be read, the live call wins too.
    """

    if not _last_scan_found_no_agent(data_dir, connector):
        return False
    if hook_call_after_scan(data_dir, last_activity_at):
        return False
    from defenseclaw.sandbox_images import verified_harness_contract

    return verified_harness_contract(data_dir, connector) is None


def hook_call_after_scan(data_dir: str, last_activity_at: Any) -> str:
    """The gateway's last authenticated hook call for a connector, as RFC
    3339 UTC, when it came after the last agent discovery scan (or the scan
    time cannot be read); "" otherwise. Status and doctor both take it as
    proof that the agent runs (connector_agent_missing)."""

    activity = _parse_timestamp(last_activity_at)
    if activity is None:
        return ""
    scanned = _last_scan_time(data_dir)
    if scanned is not None and activity <= scanned:
        return ""
    return activity.isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any):
    """An RFC 3339 timestamp (Go's nanosecond form included) as an aware
    UTC datetime, or None."""

    from datetime import datetime, timezone

    if not isinstance(value, str) or not value.strip():
        return None
    text = re.sub(r"(\.\d{6})\d+", r"\1", value.strip()).replace("Z", "+00:00").replace("z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _last_scan_time(data_dir: str):
    """The ``scanned_at`` of agent_discovery.json, or None."""

    import json

    from defenseclaw.inventory.agent_discovery import _cache_path

    if not isinstance(data_dir, str) or not data_dir or "\x00" in data_dir:
        return None
    try:
        path = _cache_path(data_dir=data_dir)
        if path.stat().st_size > 4 << 20:
            return None
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError):
        return None
    return _parse_timestamp(payload.get("scanned_at") if isinstance(payload, Mapping) else None)


def _last_scan_found_no_agent(data_dir: str, connector: str) -> bool:
    """Whether agent_discovery.json, read whatever its age, records
    ``connector`` as not installed with no executable path."""

    import json

    from defenseclaw.inventory.agent_discovery import _cache_path

    if not isinstance(data_dir, str) or not data_dir or "\x00" in data_dir:
        return False
    try:
        path = _cache_path(data_dir=data_dir)
        if path.stat().st_size > 4 << 20:
            return False
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError):
        return False
    agents = payload.get("agents") if isinstance(payload, Mapping) else None
    signal = agents.get(connector.strip().lower()) if isinstance(agents, Mapping) else None
    if not isinstance(signal, Mapping):
        return False
    binary_path = signal.get("binary_path")
    return signal.get("installed") is False and not (isinstance(binary_path, str) and binary_path.strip())


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


def _unreadable_connector_version_remediations(
    connector: str,
    ranges: tuple[VersionRange, ...],
) -> tuple[RemediationChoice, ...]:
    # Setup refuses a version it cannot read in observe and action mode, so
    # setup is not a next step: read it again, or install a covered version.
    return (_refresh_discovery_choice(), *_unsupported_connector_remediations(connector, ranges)[:1])


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
    range_text = supported_range_text(ranges) or "a registered version"
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


def _known_broken_connector_remediations(connector: str, broken: dict[str, Any]) -> tuple[RemediationChoice, ...]:
    return (
        RemediationChoice(
            choice_id="install-supported-connector-version",
            summary=f"Install a {connector} release that is not known broken ({broken['issue']}), "
            f"then run: defenseclaw setup {connector}",
            kind=RemediationKind.MANUAL,
            changes_state=True,
            requires_confirmation=True,
            unattended_allowed=False,
        ),
        _refresh_discovery_choice(),
    )


def supported_range_text(ranges: Iterable[VersionRange]) -> str:
    """Render supported agent ranges, joining contracts that continue each other.

    claudecode-hooks-v1 (>=2.1.154 and <2.1.219) and claudecode-hooks-v2
    (>=2.1.219) read as ">=2.1.154", not as two overlapping-looking ranges.
    """

    merged: list[VersionRange] = []
    for item in ranges:
        last = merged[-1] if merged else None
        if last is not None and last.max_exclusive and last.max_exclusive == item.min_inclusive:
            merged[-1] = VersionRange(
                contract_id=last.contract_id,
                min_inclusive=last.min_inclusive,
                max_exclusive=item.max_exclusive,
            )
        else:
            merged.append(item)
    return ", ".join(version_range_label(item.min_inclusive, item.max_exclusive) or item.contract_id for item in merged)


def version_range_label(minimum: str, maximum: str) -> str:
    """Render one version range as setup and doctor name it: ">=a and <b"."""

    if minimum and maximum:
        return f">={minimum} and <{maximum}"
    if minimum:
        return f">={minimum}"
    return f"<{maximum}" if maximum else ""


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
