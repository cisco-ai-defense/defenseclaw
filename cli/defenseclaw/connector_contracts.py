# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Connector version compatibility contracts used by CLI setup.

The gateway owns enforcement at runtime in
``internal/gateway/connector/hook_contract.go``. This module mirrors the
published contract IDs and version ranges so setup can fail early when an
operator selects an action-mode hook connector whose installed agent version is
outside the DefenseClaw-supported hook surface.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

STATUS_KNOWN = "known"
STATUS_UNVERSIONED = "unversioned"
STATUS_UNKNOWN = "unknown"
STATUS_NOT_GATED = "not-gated"

_VERSION_RE = re.compile(r"(?i)(?:^|[^0-9])v?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?")
_CONTRACT_PLATFORMS = frozenset({"darwin", "linux", "windows"})
_PLATFORM_OVERRIDE_FIELDS = frozenset(
    {
        "agent_version",
        "default_for_unversioned",
        "hook_script_version",
        "events",
        "aid_surfaces",
        "native_otlp",
        "native_otlp_auth",
        "native_otlp_signals",
        "native_otlp_endpoint_template",
    }
)
_AGENT_VERSION_OVERRIDE_FIELDS = frozenset({"exact", "min_inclusive", "max_exclusive"})
_STRING_OVERRIDE_FIELDS = frozenset(
    {
        "hook_script_version",
        "native_otlp_auth",
        "native_otlp_endpoint_template",
    }
)
_STRING_LIST_OVERRIDE_FIELDS = frozenset({"events", "aid_surfaces", "native_otlp_signals"})


@dataclass(frozen=True)
class ConnectorContract:
    connector: str
    contract_id: str
    exact_agent_versions: tuple[str, ...] = ()
    min_agent_version: str = ""
    max_agent_version: str = ""
    default_for_unversioned: bool = False
    hook_script_version: str = ""
    hook_script: str = ""
    hook_config_path_templates: tuple[str, ...] = ()
    response_field: str = ""
    events: tuple[str, ...] = ()
    aid_surfaces: tuple[str, ...] = ()
    supports_traceparent: bool = False
    native_otlp: bool = False
    native_otlp_auth: str = ""
    native_otlp_signals: tuple[str, ...] = ()
    native_otlp_endpoint_template: str = ""
    capabilities: dict[str, Any] = field(default_factory=dict)
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConnectorCompatibility:
    connector: str
    raw_version: str
    normalized_version: str
    status: str
    reason: str
    contract: ConnectorContract | None = None
    # A known resolution for a version newer than every tested range: no
    # known-broken entry matches, so the newest contract applies.
    untested: bool = False
    newest_tested: str = ""

    @property
    def supported(self) -> bool:
        return self.status in {STATUS_KNOWN, STATUS_UNVERSIONED, STATUS_NOT_GATED}


UNTESTED_NEWER_VERSION = "untested newer version"


def normalize_connector(name: str | None) -> str:
    value = (name or "").strip().lower()
    if value in {"claude", "claude-code", "claude_code"}:
        return "claudecode"
    if value in {"open-hands", "open_hands"}:
        return "openhands"
    return value


def hook_contract_manifest() -> dict[str, Any]:
    """Return the packaged hook contract compatibility manifest."""
    text = resources.files("defenseclaw.inventory").joinpath(
        "hook_contracts.json",
    ).read_text(encoding="utf-8")
    loaded = json.loads(text)
    if not isinstance(loaded, dict):
        raise ValueError("hook_contracts.json must contain an object")
    return loaded


def _load_contracts_from_manifest(
    manifest: dict[str, Any],
    *,
    platform_name: str | None = None,
) -> tuple[frozenset[str], dict[str, tuple[ConnectorContract, ...]]]:
    platform_name = _contract_platform(platform_name)
    connectors = manifest.get("connectors", {})
    if not isinstance(connectors, dict):
        raise ValueError("hook_contracts.json connectors must be an object")

    proxy_connectors: set[str] = set()
    hook_contracts: dict[str, tuple[ConnectorContract, ...]] = {}
    for raw_name, raw_spec in connectors.items():
        name = normalize_connector(str(raw_name))
        spec = raw_spec if isinstance(raw_spec, dict) else {}
        if spec.get("kind") == "proxy":
            proxy_connectors.add(name)

        contracts: list[ConnectorContract] = []
        for raw_contract in spec.get("contracts", []):
            if not isinstance(raw_contract, dict):
                continue
            contract_spec = _contract_spec_for_platform(
                raw_contract,
                connector=name,
                platform_name=platform_name,
            )
            version = contract_spec.get("agent_version", {})
            if not isinstance(version, dict):
                version = {}
            contracts.append(
                ConnectorContract(
                    connector=name,
                    contract_id=str(contract_spec.get("contract_id", "")).strip(),
                    exact_agent_versions=tuple(str(v) for v in version.get("exact", []) if v),
                    min_agent_version=str(version.get("min_inclusive", "") or ""),
                    max_agent_version=str(version.get("max_exclusive", "") or ""),
                    default_for_unversioned=bool(contract_spec.get("default_for_unversioned", False)),
                    hook_script_version=str(contract_spec.get("hook_script_version", "") or ""),
                    hook_script=str(contract_spec.get("hook_script", "") or ""),
                    hook_config_path_templates=tuple(
                        str(v) for v in contract_spec.get("hook_config_path_templates", []) if v
                    ),
                    response_field=str(contract_spec.get("response_field", "") or ""),
                    events=tuple(str(v) for v in contract_spec.get("events", []) if v),
                    aid_surfaces=tuple(str(v) for v in contract_spec.get("aid_surfaces", []) if v),
                    supports_traceparent=bool(contract_spec.get("supports_traceparent", False)),
                    native_otlp=bool(contract_spec.get("native_otlp", False)),
                    native_otlp_auth=str(contract_spec.get("native_otlp_auth", "") or ""),
                    native_otlp_signals=tuple(str(v) for v in contract_spec.get("native_otlp_signals", []) if v),
                    native_otlp_endpoint_template=str(contract_spec.get("native_otlp_endpoint_template", "") or ""),
                    capabilities=dict(contract_spec.get("capabilities", {}) or {}),
                    notes=tuple(str(v) for v in contract_spec.get("notes", []) if v),
                )
            )
        if contracts:
            defaults = [contract.contract_id for contract in contracts if contract.default_for_unversioned]
            if len(defaults) > 1:
                raise ValueError(
                    f"hook_contracts.json connector {name!r} has multiple default contracts "
                    f"for platform {platform_name!r}: {defaults}"
                )
            hook_contracts[name] = tuple(contracts)
    return frozenset(proxy_connectors), hook_contracts


def _contract_platform(platform_name: str | None) -> str:
    if platform_name is None:
        if sys.platform == "darwin":
            return "darwin"
        if sys.platform == "win32":
            return "windows"
        return "linux"
    if not isinstance(platform_name, str) or platform_name not in _CONTRACT_PLATFORMS:
        raise ValueError("hook contract platform must be one of darwin, linux, or windows")
    return platform_name


def _contract_spec_for_platform(
    raw_contract: dict[str, Any],
    *,
    connector: str,
    platform_name: str,
) -> dict[str, Any]:
    raw_overrides = raw_contract.get("platform_overrides", {})
    if not isinstance(raw_overrides, dict):
        raise ValueError(f"hook contract {connector!r} platform_overrides must be an object")
    for raw_platform, raw_override in raw_overrides.items():
        if raw_platform not in _CONTRACT_PLATFORMS:
            raise ValueError(f"hook contract {connector!r} has unknown platform override {raw_platform!r}")
        _validate_platform_override(
            raw_override,
            connector=connector,
            contract_id=str(raw_contract.get("contract_id", "") or ""),
            platform_name=raw_platform,
        )

    contract_spec = dict(raw_contract)
    contract_spec.pop("platform_overrides", None)
    selected = raw_overrides.get(platform_name)
    if selected is None:
        return contract_spec
    override = dict(selected)
    version_override = override.pop("agent_version", None)
    contract_spec.update(override)
    if version_override is not None:
        base_version = contract_spec.get("agent_version", {})
        if not isinstance(base_version, dict):
            base_version = {}
        merged_version = dict(base_version)
        merged_version.update(version_override)
        contract_spec["agent_version"] = merged_version
    return contract_spec


def _validate_platform_override(
    raw_override: Any,
    *,
    connector: str,
    contract_id: str,
    platform_name: str,
) -> None:
    location = f"{connector}/{contract_id or '<missing-id>'}/{platform_name}"
    if not isinstance(raw_override, dict):
        raise ValueError(f"hook contract platform override {location} must be an object")
    unknown = sorted(set(raw_override) - _PLATFORM_OVERRIDE_FIELDS)
    if unknown:
        raise ValueError(f"hook contract platform override {location} has unknown fields: {unknown}")
    version = raw_override.get("agent_version")
    if version is not None:
        if not isinstance(version, dict):
            raise ValueError(f"hook contract platform override {location} agent_version must be an object")
        unknown_version = sorted(set(version) - _AGENT_VERSION_OVERRIDE_FIELDS)
        if unknown_version:
            raise ValueError(
                f"hook contract platform override {location} agent_version has unknown fields: {unknown_version}"
            )
        for field_name in ("min_inclusive", "max_exclusive"):
            value = version.get(field_name)
            if value is not None and not isinstance(value, str):
                raise ValueError(
                    f"hook contract platform override {location} agent_version.{field_name} must be a string"
                )
        if "exact" in version:
            _validate_string_list(
                version["exact"],
                location=f"{location} agent_version.exact",
            )
    for field_name in ("default_for_unversioned", "native_otlp"):
        if field_name in raw_override and type(raw_override[field_name]) is not bool:
            raise ValueError(f"hook contract platform override {location} {field_name} must be a boolean")
    for field_name in _STRING_OVERRIDE_FIELDS:
        if field_name in raw_override and not isinstance(raw_override[field_name], str):
            raise ValueError(f"hook contract platform override {location} {field_name} must be a string")
    for field_name in _STRING_LIST_OVERRIDE_FIELDS:
        if field_name in raw_override:
            _validate_string_list(
                raw_override[field_name],
                location=f"{location} {field_name}",
            )


def _validate_string_list(value: Any, *, location: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"hook contract platform override {location} must be a string list")


HOOK_CONTRACT_MANIFEST = hook_contract_manifest()
PROXY_CONNECTORS, HOOK_CONTRACTS = _load_contracts_from_manifest(HOOK_CONTRACT_MANIFEST)


def _load_known_broken(manifest: dict[str, Any]) -> dict[str, tuple[dict[str, str], ...]]:
    out: dict[str, tuple[dict[str, str], ...]] = {}
    for raw_name, raw_spec in (manifest.get("connectors", {}) or {}).items():
        entries = raw_spec.get("known_broken_versions", []) if isinstance(raw_spec, dict) else []
        if not isinstance(entries, list):
            raise ValueError(f"hook_contracts.json connector {raw_name!r} known_broken_versions must be a list")
        parsed = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"hook_contracts.json connector {raw_name!r} has a malformed known-broken entry")
            keys = ("exact", "min_inclusive", "max_exclusive", "reason", "issue")
            item = {key: str(entry.get(key, "") or "") for key in keys}
            has_version = item["exact"] or item["min_inclusive"] or item["max_exclusive"]
            if not item["reason"] or not item["issue"] or not has_version:
                raise ValueError(
                    f"hook_contracts.json connector {raw_name!r} known-broken entry needs a version, reason and issue"
                )
            parsed.append(item)
        if parsed:
            out[normalize_connector(str(raw_name))] = tuple(parsed)
    return out


KNOWN_BROKEN_VERSIONS = _load_known_broken(HOOK_CONTRACT_MANIFEST)
# Every connector the manifest registers, including not-gated ones (Kiro)
# that publish no hook contract.
REGISTERED_CONNECTORS = frozenset(
    normalize_connector(str(name)) for name in (HOOK_CONTRACT_MANIFEST.get("connectors", {}) or {})
)


def stable_agent_version(connector: str, raw: str | None) -> str:
    """Mirror Go stableRawAgentVersionForContract: drop Amp's relative
    release-age suffix (" (released <date>, 3d ago)"), which changes as time
    passes without a binary change. Other connectors keep the raw string."""

    value = (raw or "").strip()
    if normalize_connector(connector) != "amp":
        return value
    marker = value.find(" (released ")
    if marker <= 0 or not value.endswith(")"):
        return value
    return value[:marker].strip()


def normalize_agent_version(raw: str | None) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    match = _VERSION_RE.search(raw)
    if not match:
        return ""
    parts = [match.group(1), match.group(2) or "0", match.group(3) or "0"]
    normalized: list[str] = []
    for part in parts:
        try:
            normalized.append(str(int(part)))
        except ValueError:
            return ""
    return ".".join(normalized)


# Mirror Go connector.KiroCLIHookFloor: before it a non-interactive
# `kiro-cli chat --v3` run loads no hooks (kiro.dev/docs/cli/headless), so its
# tool calls never reach DefenseClaw (rel-1-0-4 GAP-0227).
KIRO_CLI_HOOK_FLOOR = str(HOOK_CONTRACT_MANIFEST["connectors"]["kiro"]["cli_hook_floor"])
KIRO_IDE_GLOBAL_HOOKS_FLOOR = str(HOOK_CONTRACT_MANIFEST["connectors"]["kiro"]["ide_global_hooks_floor"])
# The banner `kiro-cli --version` prints; the Kiro IDE launcher prints a bare
# version, which is not a kiro-cli version.
_KIRO_CLI_VERSION_RE = re.compile(r"(?i)^kiro-cli\s+v?[0-9]")


def kiro_cli_below_hook_floor(raw: str | None) -> str:
    """Return the normalized kiro-cli version when *raw* is a kiro-cli banner
    below KIRO_CLI_HOOK_FLOOR, else ""."""

    value = (raw or "").strip()
    if not _KIRO_CLI_VERSION_RE.match(value):
        return ""
    normalized = normalize_agent_version(value)
    if normalized and _compare_version(normalized, KIRO_CLI_HOOK_FLOOR) < 0:
        return normalized
    return ""


def kiro_cli_below_hook_floor_reason(normalized: str) -> str:
    """Mirror Go connector.KiroCLIBelowHookFloorReason."""

    floor = KIRO_CLI_HOOK_FLOOR
    return (
        f"kiro-cli {normalized} is below {floor}: before {floor} a non-interactive kiro-cli --v3 run loads no hooks, "
        f"so its tool calls never reach DefenseClaw; update Kiro CLI to {floor} or later"
    )


def kiro_ide_below_hook_floor(raw: str | None) -> str:
    """Return an IDE version that cannot read the global hooks file."""

    value = (raw or "").strip()
    if not value or _KIRO_CLI_VERSION_RE.match(value):
        return ""
    normalized = normalize_agent_version(value)
    if normalized and _compare_version(normalized, KIRO_IDE_GLOBAL_HOOKS_FLOOR) < 0:
        return normalized
    return ""


# The one Kiro detection judgment, mirroring Go enterprisehooks.AssessKiro
# (internal/enterprisehooks/kiro_forms.go); both are held to
# internal/enterprisehooks/testdata/kiro_forms_table.json. Each installed form
# (kiro-cli, each Kiro IDE install) is judged on its own: at or above its
# floor it is protected, below it it is not, and a form whose version could
# not be read is unknown, which is not protected. Setup and doctor use it.
KIRO_FORM_CLI = "cli"
KIRO_FORM_IDE = "ide"
KIRO_CODE_CLI_BELOW_FLOOR = "kiro_cli_below_hook_floor"
KIRO_CODE_IDE_BELOW_FLOOR = "kiro_ide_below_global_hooks_floor"
KIRO_CODE_UNVERIFIED = "hook_contract_unverified"
_KIRO_IDE_VERSION_SUFFIX = "+kiro-ide"


@dataclass(frozen=True)
class KiroFormVerdict:
    """One installed Kiro form and its judgment."""

    kind: str
    version: str
    normalized: str
    protected: bool
    code: str = ""
    reason: str = ""
    path: str = ""

    @property
    def below_floor(self) -> bool:
        return self.code in (KIRO_CODE_CLI_BELOW_FLOOR, KIRO_CODE_IDE_BELOW_FLOOR)

    @property
    def unknown(self) -> bool:
        return not self.protected and not self.normalized


@dataclass(frozen=True)
class KiroAssessment:
    """Every installed Kiro form, the one a setup covers, and its refusals."""

    forms: tuple[KiroFormVerdict, ...]
    selected: KiroFormVerdict | None
    #: Why action setup refuses: no installed form is protected (or none is
    #: installed). "" when one is protected.
    action_refusal: str
    #: Why observe setup refuses too: no form is protected and one is known
    #: to be below its floor (GAP-0828). An unknown form refuses action only.
    every_mode_refusal: str

    def unprotected(self) -> tuple[KiroFormVerdict, ...]:
        return tuple(form for form in self.forms if not form.protected)


def judge_kiro_form(kind: str, version: str = "", *, unread: str = "", path: str = "") -> KiroFormVerdict:
    """Judge one installed Kiro form against its floor (Go JudgeKiroForm)."""

    raw = (version or "").strip()
    if raw.endswith(_KIRO_IDE_VERSION_SUFFIX):
        raw = raw[: -len(_KIRO_IDE_VERSION_SUFFIX)].strip()
    normalized = normalize_agent_version(raw)
    where = (unread or "").strip()
    if kind == KIRO_FORM_IDE:
        if not normalized:
            reason = (
                f"{where or 'Kiro IDE is installed, but its version could not be read'}, so it is not verified "
                f"against a known hook contract (the global hooks file needs Kiro IDE {KIRO_IDE_GLOBAL_HOOKS_FLOOR} "
                "or later) and is not counted as protected"
            )
            return KiroFormVerdict(kind, raw, "", False, KIRO_CODE_UNVERIFIED, reason, path)
        if _compare_version(normalized, KIRO_IDE_GLOBAL_HOOKS_FLOOR) < 0:
            reason = (
                f"Kiro IDE {normalized} is below {KIRO_IDE_GLOBAL_HOOKS_FLOOR}, the first build that reads the "
                "global ~/.kiro/hooks file, so its agent sessions run without DefenseClaw hooks; update Kiro IDE"
            )
            return KiroFormVerdict(kind, raw, normalized, False, KIRO_CODE_IDE_BELOW_FLOOR, reason, path)
        return KiroFormVerdict(kind, raw, normalized, True, path=path)
    if not normalized:
        reason = (
            f"{where or 'kiro-cli is installed, but its version could not be read'}; without a version "
            "DefenseClaw cannot check this kiro-cli against its hook floor, so it is not counted as protected"
        )
        return KiroFormVerdict(kind, raw, "", False, KIRO_CODE_UNVERIFIED, reason, path)
    if _compare_version(normalized, KIRO_CLI_HOOK_FLOOR) < 0:
        return KiroFormVerdict(
            kind, raw, normalized, False, KIRO_CODE_CLI_BELOW_FLOOR, kiro_cli_below_hook_floor_reason(normalized), path
        )
    return KiroFormVerdict(kind, raw, normalized, True, path=path)


def assess_kiro(forms: list[KiroFormVerdict] | tuple[KiroFormVerdict, ...]) -> KiroAssessment:
    """Combine judged forms: a protected kiro-cli is selected, else a
    protected IDE; without one action setup refuses (Go AssessKiro)."""

    forms = tuple(forms)
    selected = next((f for f in forms if f.protected and f.kind == KIRO_FORM_CLI), None) or next(
        (f for f in forms if f.protected), None
    )
    if selected is not None:
        return KiroAssessment(forms, selected, "", "")
    action = next((f.reason for f in forms), "no Kiro installation was found, so no Kiro form is known to be protected")
    every_mode = next((f.reason for f in forms if f.below_floor), "")
    return KiroAssessment(forms, None, action, every_mode)


def kiro_forms_from_signal(signal: Any) -> tuple[KiroFormVerdict, ...]:
    """Judge every Kiro form an agent-discovery signal recorded.

    ``kiro_forms`` (cache schema 7 and later) lists each probed install. A
    signal without it (an earlier cache, or a hook-contract lock) has only
    the selected version: a ``kiro-cli`` banner is the CLI, a bare version the
    IDE, and an installed signal with no version an unknown kiro-cli.
    """

    recorded = getattr(signal, "kiro_forms", None)
    if isinstance(recorded, (list, tuple)) and recorded:
        out: list[KiroFormVerdict] = []
        for item in recorded:
            if not isinstance(item, dict):
                continue
            kind = KIRO_FORM_IDE if item.get("kind") == KIRO_FORM_IDE else KIRO_FORM_CLI
            out.append(
                judge_kiro_form(
                    kind,
                    str(item.get("version") or ""),
                    unread=str(item.get("unread") or ""),
                    path=str(item.get("path") or ""),
                )
            )
        return tuple(out)
    out = []
    for kind, field_name in ((KIRO_FORM_CLI, "kiro_cli_version"), (KIRO_FORM_IDE, "kiro_ide_version")):
        value = getattr(signal, field_name, "")
        if isinstance(value, str) and value.strip():
            out.append(judge_kiro_form(kind, value))
    if out:
        return tuple(out)
    version = getattr(signal, "version", "")
    version = version.strip() if isinstance(version, str) else ""
    if version:
        kind = KIRO_FORM_CLI if _KIRO_CLI_VERSION_RE.match(version) else KIRO_FORM_IDE
        return (judge_kiro_form(kind, version),)
    if bool(getattr(signal, "installed", False)):
        error = getattr(signal, "error", "")
        path = getattr(signal, "binary_path", "")
        where = f"{path or 'kiro-cli'} is installed, but its version could not be read"
        if isinstance(error, str) and error.strip():
            where += f" ({error.strip()})"
        return (judge_kiro_form(KIRO_FORM_CLI, "", unread=where, path=str(path or "")),)
    return ()


def assess_kiro_signal(signal: Any) -> KiroAssessment:
    """:func:`assess_kiro` for an agent-discovery signal (or ``None``)."""

    return assess_kiro(kiro_forms_from_signal(signal) if signal is not None else ())


def resolve_connector_contract(
    connector: str,
    raw_version: str | None,
    *,
    platform_name: str | None = None,
) -> ConnectorCompatibility:
    name = normalize_connector(connector)
    raw = (raw_version or "").strip()
    if platform_name is None:
        proxy_connectors = PROXY_CONNECTORS
        hook_contracts = HOOK_CONTRACTS
    else:
        proxy_connectors, hook_contracts = _load_contracts_from_manifest(
            HOOK_CONTRACT_MANIFEST,
            platform_name=platform_name,
        )
    if name in proxy_connectors:
        return ConnectorCompatibility(
            connector=name,
            raw_version=raw,
            normalized_version=normalize_agent_version(raw),
            status=STATUS_NOT_GATED,
            reason="proxy/chat connector; no hook contract gate",
            contract=None,
        )
    contracts = hook_contracts.get(name, ())
    if not contracts:
        spec = HOOK_CONTRACT_MANIFEST.get("connectors", {}).get(name, {})
        if isinstance(spec, dict) and spec.get("compatibility_gate") in {
            STATUS_NOT_GATED,
            "acp-contract",
        }:
            if name == "kiro" and (below := kiro_cli_below_hook_floor(raw)):
                return ConnectorCompatibility(
                    connector=name,
                    raw_version=raw,
                    normalized_version=below,
                    status=STATUS_UNKNOWN,
                    reason=kiro_cli_below_hook_floor_reason(below),
                    contract=None,
                )
            return ConnectorCompatibility(
                connector=name,
                raw_version=raw,
                normalized_version=normalize_agent_version(raw),
                status=STATUS_NOT_GATED,
                reason="connector has no hook contract gate",
                contract=None,
            )
        return ConnectorCompatibility(
            connector=name,
            raw_version=raw,
            normalized_version="",
            status=STATUS_UNKNOWN,
            reason="no DefenseClaw hook contract registered for connector",
            contract=None,
        )
    if not raw:
        contract = _default_contract(contracts)
        return ConnectorCompatibility(
            connector=name,
            raw_version="",
            normalized_version="",
            status=STATUS_UNVERSIONED,
            reason="agent version not probed; using connector default hook contract",
            contract=contract,
        )
    normalized = normalize_agent_version(raw)
    if not normalized:
        return ConnectorCompatibility(
            connector=name,
            raw_version=raw,
            normalized_version="",
            status=STATUS_UNKNOWN,
            reason="could not normalize agent version",
            contract=None,
        )
    for entry in KNOWN_BROKEN_VERSIONS.get(name, ()):
        if (entry["exact"] and _exact_agent_version_match(raw, (entry["exact"],))) or (
            not entry["exact"]
            and _version_in_range(normalized, entry["min_inclusive"], entry["max_exclusive"])
        ):
            return ConnectorCompatibility(
                connector=name,
                raw_version=raw,
                normalized_version=normalized,
                status=STATUS_UNKNOWN,
                reason=f"agent version {normalized} is known broken: {entry['reason']} ({entry['issue']})",
                contract=None,
            )
    for contract in contracts:
        if _contract_matches_agent_version(contract, raw, normalized):
            return ConnectorCompatibility(
                connector=name,
                raw_version=raw,
                normalized_version=normalized,
                status=STATUS_KNOWN,
                reason=f"matched hook contract {contract.contract_id}",
                contract=contract,
            )
    newest = _newest_contract_below(contracts, normalized)
    if newest is not None:
        contract, label = newest
        return ConnectorCompatibility(
            connector=name,
            raw_version=raw,
            normalized_version=normalized,
            status=STATUS_KNOWN,
            reason=(
                f"{UNTESTED_NEWER_VERSION}: {normalized} is newer than the tested versions ({label}); "
                f"no known problems; using hook contract {contract.contract_id}"
            ),
            contract=contract,
            untested=True,
            newest_tested=label,
        )
    return ConnectorCompatibility(
        connector=name,
        raw_version=raw,
        normalized_version=normalized,
        status=STATUS_UNKNOWN,
        reason="no hook contract matches normalized agent version",
        contract=None,
    )


def connector_lock_contract_invariant(connector: str, entry: Any) -> str:
    """Return the first incompatible protected-lock invariant, if any."""

    name = normalize_connector(connector)
    recorded_connector = entry.get("connector") if isinstance(entry, dict) else None
    if not isinstance(recorded_connector, str) or normalize_connector(recorded_connector) != name:
        return "contract"
    # The Go lock writer uses ``omitempty`` for version strings, so an
    # unversioned selection is canonically serialized without either version
    # field.  Preserve strict rejection for an explicitly malformed value,
    # while treating field absence as the empty version that Go resolved.
    if "raw_agent_version" in entry:
        raw_version = entry.get("raw_agent_version")
        if not isinstance(raw_version, str):
            return "version"
    else:
        raw_version = ""
    compatibility = resolve_connector_contract(name, raw_version)
    if compatibility.status == STATUS_NOT_GATED:
        if entry.get("compatibility_status") != STATUS_NOT_GATED:
            return "contract"
        if entry.get("hook_fail_mode") not in {"open", "closed"}:
            return "fail-mode"
        return ""
    contract = compatibility.contract
    if contract is None or not compatibility.supported:
        return "contract"
    if compatibility.status == STATUS_UNVERSIONED and not contract.default_for_unversioned:
        return "version"
    if entry.get("compatibility_status") != compatibility.status:
        return "contract"
    if entry.get("normalized_agent_version", "") != compatibility.normalized_version:
        return "version"
    if entry.get("contract_id") != contract.contract_id:
        return "contract"
    if entry.get("hook_script_version") != contract.hook_script_version:
        return "version"
    if entry.get("hook_fail_mode") not in {"open", "closed"}:
        return "fail-mode"
    locations = entry.get("locations")
    if not isinstance(locations, dict):
        return "location"
    config_paths = locations.get("hook_config_paths")
    runtime_paths = locations.get("hook_script_paths")
    if not isinstance(config_paths, list) or not config_paths:
        return "location"
    if not isinstance(runtime_paths, list) or not runtime_paths:
        return "location"
    for path in (*config_paths, *runtime_paths):
        if (
            not isinstance(path, str)
            or not path
            or path.strip() != path
            or any(char in path for char in "\x00\r\n")
            or not os.path.isabs(path)
            or os.path.normpath(path) != path
        ):
            return "location"
    return ""


def _newest_contract_below(
    contracts: tuple[ConnectorContract, ...],
    normalized: str,
) -> tuple[ConnectorContract, str] | None:
    """Mirror Go newestContractBelow: the newest contract when ``normalized``
    is newer than every bound of its version scheme, or between two exact pins
    of one contract (date-style builds with a major >= 1000 compare only with
    date-style bounds)."""

    def date_style(value: str) -> bool:
        return _version_tuple(value)[0] >= 1000

    scheme = date_style(normalized)
    best: ConnectorContract | None = None
    newest = label = ""
    for contract in contracts:
        bounds = pins_above = 0
        upper = upper_label = ""
        for pin in contract.exact_agent_versions:
            pin_norm = normalize_agent_version(pin)
            if not pin_norm or date_style(pin_norm) != scheme:
                continue
            cmp = _compare_version(normalized, pin_norm)
            if cmp == 0:
                return None
            if cmp < 0:
                pins_above += 1
                continue
            bounds += 1
            if not upper or _compare_version(pin_norm, upper) > 0:
                upper, upper_label = pin_norm, pin
        # Between two exact pins of one contract (Devin on Linux) is an
        # untested version of it; below all of its pins is under its floor.
        if pins_above and not bounds:
            return None
        if contract.min_agent_version or contract.max_agent_version:
            edge = contract.max_agent_version or contract.min_agent_version
            if date_style(edge) == scheme:
                if not contract.max_agent_version or _compare_version(normalized, contract.max_agent_version) < 0:
                    return None
                bounds += 1
                if not upper or _compare_version(contract.max_agent_version, upper) > 0:
                    upper, upper_label = contract.max_agent_version, "<" + contract.max_agent_version
        if bounds and (not newest or _compare_version(upper, newest) >= 0):
            best, newest, label = contract, upper, upper_label
    if best is None:
        return None
    return best, label


def _contract_matches_agent_version(
    contract: ConnectorContract,
    raw_version: str,
    normalized_version: str,
) -> bool:
    if contract.exact_agent_versions and _exact_agent_version_match(
        raw_version, contract.exact_agent_versions
    ):
        return True
    # Empty min/max would otherwise accept any normalized version.
    if contract.min_agent_version or contract.max_agent_version:
        return _version_in_range(
            normalized_version,
            contract.min_agent_version,
            contract.max_agent_version,
        )
    return False


def _exact_agent_version_match(raw: str, expected: tuple[str, ...]) -> bool:
    fields = raw.strip().split()
    if not fields or len(fields) > 2:
        return False
    token = fields[-1]
    if len(fields) == 2 and fields[0].lower() not in {"agent", "cursor-agent"}:
        return False
    if token[:1].lower() == "v":
        token = token[1:]
    return any(token.lower() == candidate.strip().lower() for candidate in expected)


def _version_in_range(version: str, min_version: str, max_version: str) -> bool:
    if not version:
        return False
    if min_version and _compare_version(version, min_version) < 0:
        return False
    if max_version and _compare_version(version, max_version) >= 0:
        return False
    return True


def _default_contract(contracts: tuple[ConnectorContract, ...]) -> ConnectorContract:
    for contract in contracts:
        if contract.default_for_unversioned:
            return contract
    return contracts[0]


def _compare_version(a: str, b: str) -> int:
    av = _version_tuple(a)
    bv = _version_tuple(b)
    if av < bv:
        return -1
    if av > bv:
        return 1
    return 0


def compare_agent_versions(a: str, b: str) -> int:
    """Compare two normalized semver-like agent versions."""

    return _compare_version(a, b)


# First OpenClaw release known to change LLM transport away from a
# fetch-only path. Setup and doctor emit an advisory; they do not block.
OPENCLAW_TRANSPORT_ADVISORY_SINCE = "2026.6.8"


def openclaw_needs_interception_advisory(raw_version: str | None) -> bool:
    """Return True when OpenClaw is in the transport-changed range.

    OpenClaw 2026.6.8+ may emit provider traffic through undici or
    embedded runtimes that skip a fetch-only interceptor. The
    interceptor now covers those layers; this advisory tells the
    operator to confirm doctor's interception self-test rather than
    treating a live proxy port as proof.
    """

    normalized = normalize_agent_version(raw_version or "")
    if not normalized:
        return False
    return compare_agent_versions(normalized, OPENCLAW_TRANSPORT_ADVISORY_SINCE) >= 0


def _version_tuple(value: str) -> tuple[int, int, int]:
    normalized = normalize_agent_version(value)
    if not normalized:
        return (0, 0, 0)
    parts = normalized.split(".")
    nums = [int(part) for part in parts[:3]]
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2])
