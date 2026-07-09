# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure Setup panel state helpers for the Textual TUI migration."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Literal
from urllib.parse import urlparse

from defenseclaw.tui.services.cli_choices import REGIONAL_PROVIDERS

ReadinessStatus = Literal["pass", "warn", "fail"]
ValidationSeverity = Literal["ok", "warning", "error"]
ConfigFieldKind = Literal["string", "int", "bool", "password", "choice", "header"]


@dataclass(frozen=True)
class SetupCommandIntent:
    """Command intent returned by Setup models without executing it.

    ``follow_up`` carries zero or more additional intents that should run
    sequentially after the primary command succeeds. The Registry wizard
    uses this to queue ``registry sync`` and ``skill scan`` after a
    successful ``registry add``. Each follow-up runs only if the prior
    step exits 0.
    """

    label: str
    args: tuple[str, ...]
    hint: str = ""
    binary: str = "defenseclaw"
    category: str = "setup"
    origin: str = "setup"
    follow_up: tuple[SetupCommandIntent, ...] = ()
    # Secret payload fed to the child over stdin instead of argv so it
    # never shows up in process listings (e.g. ``keys set`` reads a hidden
    # prompt). ``None`` means "no stdin payload".
    secret_stdin: str | None = None
    # Secret-bearing environment variables injected into the child process
    # environment rather than passed as ``--env KEY=secret`` on the command
    # line. Empty mapping means "no overrides".
    env_overrides: tuple[tuple[str, str], ...] = ()

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.binary, *self.args)


@dataclass(frozen=True)
class ReadinessCheck:
    title: str
    detail: str
    status: ReadinessStatus
    fix: SetupCommandIntent | None = None


@dataclass(frozen=True)
class CredentialRow:
    env_name: str
    feature: str = ""
    requirement: str = ""
    source: str = ""
    set: bool = False
    description: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> CredentialRow:
        return cls(
            env_name=str(raw.get("env_name") or raw.get("EnvName") or ""),
            feature=str(raw.get("feature") or raw.get("Feature") or ""),
            requirement=str(raw.get("requirement") or raw.get("Requirement") or "").strip().lower(),
            source=str(raw.get("source") or raw.get("Source") or "").strip(),
            set=bool(raw.get("set") if "set" in raw else raw.get("Set", False)),
            description=str(raw.get("description") or raw.get("Description") or ""),
        )


@dataclass(frozen=True)
class CredentialSnapshot:
    rows: tuple[CredentialRow, ...] = ()
    loaded_at: datetime | None = None
    error: str = ""
    loading: bool = False
    exit_error: str = ""

    @property
    def missing_required(self) -> tuple[CredentialRow, ...]:
        return missing_credential_rows(self.rows)


@dataclass(frozen=True)
class RestartQueue:
    pending: bool = False
    reason: str = ""
    queued_at: datetime | None = None
    last_started_at: str = ""

    def with_reason(self, reason: str, *, last_started_at: str = "") -> RestartQueue:
        reason = reason.strip()
        if not reason:
            return self
        if self.pending:
            joined = self.reason
            if reason not in joined:
                joined = f"{joined}; {reason}" if joined else reason
            return RestartQueue(
                pending=True,
                reason=joined,
                queued_at=self.queued_at,
                last_started_at=self.last_started_at or last_started_at,
            )
        return RestartQueue(
            pending=True,
            reason=reason,
            queued_at=datetime.now(timezone.utc),
            last_started_at=last_started_at,
        )

    def should_clear_for_started_at(self, started_at: str) -> bool:
        return self.pending and bool(self.last_started_at) and bool(started_at) and started_at != self.last_started_at


@dataclass(frozen=True)
class ValidationResult:
    severity: ValidationSeverity = "ok"
    message: str = ""


@dataclass(frozen=True)
class ConfigField:
    label: str
    key: str = ""
    kind: ConfigFieldKind | str = "string"
    value: str = ""
    original: str = ""
    options: tuple[str, ...] = ()
    hint: str = ""

    @property
    def interactive(self) -> bool:
        return self.kind != "header"

    def with_value(self, value: str) -> ConfigField:
        return ConfigField(
            label=self.label,
            key=self.key,
            kind=self.kind,
            value=value,
            original=self.original,
            options=self.options,
            hint=self.hint,
        )


@dataclass(frozen=True)
class ConfigSection:
    name: str
    fields: tuple[ConfigField, ...]
    summary: str
    help: str = ""


@dataclass(frozen=True)
class ConfigDiffEntry:
    key: str
    before: str
    after: str
    secret: bool = False


def parse_credential_rows(raw: bytes | str) -> tuple[CredentialRow, ...]:
    """Parse `defenseclaw keys list --json` output with Go-compatible trimming."""

    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = raw
    payload = _trim_credential_json(text)
    if not payload.strip():
        return ()
    data = json.loads(payload)
    if not isinstance(data, list):
        raise ValueError("credential JSON must be a list")
    return tuple(CredentialRow.from_mapping(row) for row in data if isinstance(row, Mapping))


def _trim_credential_json(text: str) -> str:
    stripped = text.strip()
    if not stripped or stripped.startswith("["):
        return stripped
    marker = "\n["
    index = stripped.find(marker)
    if index >= 0:
        return stripped[index + 1 :].strip()
    return stripped


def missing_credential_rows(rows: Sequence[CredentialRow]) -> tuple[CredentialRow, ...]:
    return tuple(row for row in rows if row.requirement.lower() == "required" and not row.set)


# Maps a regional provider id to its config sub-block name. ``vertex_ai`` is
# the provider id but the persisted block is ``llm.vertex`` (see config.py
# ``LLMConfig.vertex``); Azure carries an endpoint instead of a region.
_REGIONAL_BLOCK: dict[str, str] = {"bedrock": "bedrock", "vertex_ai": "vertex", "azure": "azure"}


def build_readiness_checks(
    cfg: object | Mapping[str, Any] | None,
    health: object | Mapping[str, Any] | None,
    doctor: object | Mapping[str, Any] | None,
    credentials: Sequence[CredentialRow],
    queue: RestartQueue = RestartQueue(),
    gateway_status: object | Mapping[str, Any] | None = None,
) -> tuple[ReadinessCheck, ...]:
    """Build Setup readiness rows using the same status/fix contract as Go."""

    checks: list[ReadinessCheck] = []

    # B1: route readiness through the full active connector SET, not the
    # singular ``claw.mode``. A multi-connector install (e.g. hermes + codex
    # via ``guardrail.connectors``) previously showed only the primary
    # connector here — or, after the last connector was removed, a phantom
    # "openclaw". ``active_connectors()`` is R1-clean (empty when nothing is
    # configured) so this both surfaces every active connector and stops
    # fabricating one when the install is genuinely empty.
    connectors = _active_connector_names(cfg)
    if connectors:
        for connector in connectors:
            checks.append(ReadinessCheck(f"Active Connector: {connector}", "configured", "pass"))
    else:
        checks.append(
            ReadinessCheck(
                "Active Connector",
                "No connector mode is configured.",
                "fail",
                # Default to OpenClaw with ``--yes`` so anyone that wires this
                # readiness fix to a quick-action keybinding never accidentally
                # launches the interactive picker (which blocks on stdin and
                # is impossible to drive cleanly from the embedded TUI). The
                # Setup panel's wizard form is still the preferred entry point
                # — this is the safe fallback if the fix runs unattended.
                _intent(
                    "defenseclaw",
                    ("setup", "openclaw", "--yes"),
                    "setup openclaw",
                    "setup",
                ),
            ),
        )

    gateway_state = str(_get_path(health, "gateway.state", "") or "")
    api_state = str(_get_path(health, "api.state", "") or "")
    availability_state = str(_get_path(gateway_status, "state", "") or "").strip().lower()
    availability_detail = str(_get_path(gateway_status, "last_error", "") or "").strip()
    if availability_state in {"error", "failed"}:
        checks.append(
            ReadinessCheck(
                "Gateway / API Health",
                availability_detail or "Gateway health probe failed.",
                "fail",
            ),
        )
    elif availability_state in {"offline", "stopped", "down"}:
        checks.append(
            ReadinessCheck(
                "Gateway / API Health",
                availability_detail or "Gateway health endpoint is offline.",
                "fail",
                _intent("defenseclaw-gateway", ("start",), "start", "daemon"),
            ),
        )
    elif availability_state in {"starting", "reconnecting"}:
        checks.append(
            ReadinessCheck(
                "Gateway / API Health",
                availability_detail or "Gateway is starting.",
                "warn",
            ),
        )
    elif availability_state in {"running", "ready", "healthy", "ok", "disabled"}:
        checks.append(ReadinessCheck("Gateway / API Health", "Gateway and API are healthy.", "pass"))
    elif health is None:
        checks.append(
            ReadinessCheck(
                "Gateway / API Health",
                "Gateway health endpoint is offline.",
                "fail",
                _intent("defenseclaw-gateway", ("start",), "start", "daemon"),
            ),
        )
    elif not _state_healthy_or_disabled(gateway_state) or not _state_healthy(api_state):
        checks.append(
            ReadinessCheck(
                "Gateway / API Health",
                f"gateway={gateway_state} api={api_state}",
                "warn",
                _intent("defenseclaw-gateway", ("restart",), "restart", "daemon"),
            ),
        )
    else:
        checks.append(ReadinessCheck("Gateway / API Health", "Gateway and API are healthy.", "pass"))

    if not bool(_get_path(cfg, "guardrail.enabled", False)):
        checks.append(
            ReadinessCheck(
                "Guardrail",
                "Guardrail is disabled or config is unavailable.",
                "warn",
                _intent("defenseclaw", ("setup", "guardrail"), "setup guardrail", "setup"),
            ),
        )
    else:
        mode = str(_get_path(cfg, "guardrail.mode", "") or "observe")
        checks.append(ReadinessCheck("Guardrail", f"enabled in {mode} mode", "pass"))

    missing = list(missing_credential_rows(credentials))
    if not missing:
        missing.extend(
            CredentialRow(env_name=env, requirement="required") for env in _doctor_missing_credentials(doctor)
        )
    if missing:
        checks.append(
            ReadinessCheck(
                "Required Credentials",
                f"{len(missing)} required credential(s) missing",
                "fail",
                _intent("defenseclaw", ("keys", "fill-missing", "--yes"), "keys fill-missing", "setup"),
            ),
        )
    else:
        checks.append(
            ReadinessCheck(
                "Required Credentials",
                "No missing required credentials detected.",
                "pass",
            ),
        )

    provider = str(_get_path(cfg, "llm.provider", "") or "").strip()
    model = str(_get_path(cfg, "llm.model", "") or "").strip()
    instance_name = str(_get_path(cfg, "llm.instance_name", "") or "").strip()
    # A custom-provider instance overlay supplies base_url/model/keys at
    # resolve time, so binding one is a complete config even when the
    # inline llm.model is blank.
    if provider and (model or instance_name):
        detail = f"{provider}/{model}" if model else f"{provider} (via instance {instance_name})"
        checks.append(ReadinessCheck("LLM Config", detail, "pass"))
    else:
        checks.append(
            ReadinessCheck(
                "LLM Config",
                "Unified llm.provider/model is incomplete.",
                "warn",
                _intent("defenseclaw", ("setup", "llm"), "setup llm", "setup"),
            ),
        )

    # Regional provider (Bedrock / Vertex AI / Azure) needs a region (or an
    # Azure endpoint) before the SDK can route; surface the gap explicitly
    # so a half-configured regional block doesn't fail silently at runtime.
    if provider in REGIONAL_PROVIDERS:
        region = str(
            _get_path(cfg, f"llm.{_REGIONAL_BLOCK[provider]}.region", "")
            or _get_path(cfg, "llm.region", "")
            or "").strip()
        azure_endpoint = str(_get_path(cfg, "llm.azure.endpoint", "") or "").strip()
        configured = region or (provider == "azure" and azure_endpoint)
        if configured:
            where = azure_endpoint if (provider == "azure" and not region) else region
            checks.append(ReadinessCheck("Regional Provider", f"{provider} ({where})", "pass"))
        else:
            need = "endpoint" if provider == "azure" else "region"
            checks.append(
                ReadinessCheck(
                    "Regional Provider",
                    f"{provider} selected but no {need} configured.",
                    "warn",
                    _intent("defenseclaw", ("setup", "llm"), "setup llm", "setup"),
                ),
            )

    # Custom-provider overlay binding. ``llm.instance_name`` points at an
    # entry in custom-providers.json whose base_url / env keys / TLS apply
    # at resolve time. Only surface the row when an overlay is in play.
    if instance_name:
        checks.append(
            ReadinessCheck("Custom-provider Overlay", f"instance '{instance_name}' bound", "pass")
        )

    if any(
        str(_get_path(cfg, key, "") or "").strip()
        for key in (
            "scanners.skill_scanner.binary",
            "scanners.mcp_scanner.binary",
            "scanners.codeguard",
        )
    ):
        checks.append(ReadinessCheck("Scanner Availability", "Scanner config present.", "pass"))
    else:
        checks.append(
            ReadinessCheck(
                "Scanner Availability",
                "Scanner binaries are not configured.",
                "warn",
                # Two-step consent: dry-run lists the fixers a regular
                # ``doctor --fix --yes`` would apply, and the follow-up
                # actually applies them. The user sees the dry-run output
                # plus a CommandPreviewScreen confirm before any state
                # changes hit disk.
                SetupCommandIntent(
                    label="doctor --fix (preview)",
                    args=("doctor", "--fix", "--dry-run"),
                    binary="defenseclaw",
                    category="setup",
                    origin="setup",
                    follow_up=(
                        SetupCommandIntent(
                            label="doctor --fix (apply)",
                            args=("doctor", "--fix", "--yes"),
                            binary="defenseclaw",
                            category="setup",
                            origin="setup",
                        ),
                    ),
                ),
            ),
        )

    audit_sinks = _get_path(cfg, "audit_sinks", ()) or ()
    if bool(_get_path(cfg, "otel.enabled", False)) or len(audit_sinks) > 0:
        checks.append(ReadinessCheck("Observability / Audit Sinks", "Telemetry or audit sink configured.", "pass"))
    else:
        checks.append(
            ReadinessCheck(
                "Observability / Audit Sinks",
                "No OTel exporter or audit sink is configured.",
                "warn",
                _intent(
                    "defenseclaw",
                    ("setup", "local-observability", "status"),
                    "setup local-observability status",
                    "setup",
                ),
            ),
        )

    if bool(_get_path(cfg, "asset_policy.enabled", False)) and _registry_required_but_empty(cfg):
        checks.append(
            ReadinessCheck(
                "Registry / Asset Policy",
                "Registry-required asset policy has no promoted registry entries.",
                "warn",
                _intent("defenseclaw", ("registry", "sync", "--all"), "registry sync --all", "setup"),
            ),
        )
    else:
        checks.append(ReadinessCheck("Registry / Asset Policy", "Registry policy is ready or not required.", "pass"))

    if queue.pending:
        checks.append(
            ReadinessCheck(
                "Restart Pending",
                queue.reason,
                "warn",
                _intent("defenseclaw-gateway", ("restart",), "restart", "daemon"),
            ),
        )
    else:
        checks.append(ReadinessCheck("Restart Pending", "No queued restart.", "pass"))

    return tuple(checks)


def validate_config_field(field: ConfigField) -> ValidationResult:
    """Validate one config editor field with Go-compatible severities."""

    value = field.value.strip()
    if field.kind == "header":
        return ValidationResult()

    if field.kind == "bool" and value not in {"true", "false"}:
        return ValidationResult("error", "expected true or false")
    if field.kind == "choice" and field.options and value not in field.options:
        return ValidationResult("error", "choose one of: " + ", ".join(field.options))
    if field.kind == "int":
        try:
            number = int(value)
        except ValueError:
            return ValidationResult("error", "expected an integer")
        if "port" in field.key and not 1 <= number <= 65535:
            return ValidationResult("error", "port must be between 1 and 65535")
        if any(marker in field.key for marker in ("timeout", "interval", "retries", "max_")) and number < 0:
            return ValidationResult("error", "value must be zero or greater")

    if is_config_env_name_field(field) and value and not looks_like_env_name(value):
        if looks_like_secret_value(value):
            return ValidationResult("warning", "this looks like a secret value, not an env var name")
        return ValidationResult("error", "env var names must match A-Z, 0-9, and underscores")

    if _looks_like_url_field(field.key) and value:
        if _is_otlp_endpoint_field(field.key) and "://" not in value:
            if _validate_host_port(value):
                return ValidationResult()
            return ValidationResult("error", "expected a URL with scheme and host or host:port")
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            return ValidationResult("error", "expected a URL with scheme and host")
        if parsed.username or parsed.password:
            return ValidationResult("error", "URL must not embed credentials")
        if parsed.scheme not in {"http", "https", "grpc"}:
            return ValidationResult("warning", "uncommon URL scheme")

    if "dedup_window" in field.key and value and not _looks_like_go_duration_or_seconds(value):
        return ValidationResult("error", "duration must be like 30s, 1m, or a seconds integer")
    if "tls_skip_verify" in field.key and value == "true":
        return ValidationResult("warning", "TLS verification is disabled; dev-only")
    if is_secret_config_field(field) and field.kind != "password" and looks_like_secret_value(value):
        return ValidationResult("warning", "secret-like value will be saved inline")
    return ValidationResult()


def config_diff(sections: Sequence[ConfigSection]) -> tuple[ConfigDiffEntry, ...]:
    entries: list[ConfigDiffEntry] = []
    for section in sections:
        for field_ in section.fields:
            if field_.value == field_.original:
                continue
            entries.append(
                ConfigDiffEntry(
                    key=field_.key,
                    before=mask_config_value(field_, field_.original),
                    after=mask_config_value(field_, field_.value),
                    secret=is_secret_config_field(field_),
                ),
            )
    return tuple(entries)


def validation_errors(sections: Sequence[ConfigSection]) -> tuple[str, ...]:
    errors: list[str] = []
    for section in sections:
        for field_ in section.fields:
            if field_.kind == "header":
                continue
            result = validate_config_field(field_)
            if result.severity == "error":
                errors.append(f"{field_.key}: {result.message}")
    return tuple(errors)


def mask_secret(value: str) -> str:
    value = value.strip()
    if not value:
        return "(empty)"
    if len(value) <= 4:
        return "****"
    return "****" + value[-4:]


def is_secret_config_field(field: ConfigField) -> bool:
    return field.kind == "password" or _is_secret_name(field.key) or _is_secret_name(field.label)


def is_config_env_name_field(field: ConfigField) -> bool:
    return (
        field.key.endswith("_env") or ".api_key_env" in field.key or ".token_env" in field.key or " Env" in field.label
    )


def mask_config_value(field: ConfigField, value: str) -> str:
    if is_secret_config_field(field) or (is_config_env_name_field(field) and looks_like_secret_value(value)):
        return mask_secret(value)
    if not value.strip():
        return "(empty)"
    return value


def looks_like_env_name(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Z_][A-Z0-9_]*", value.strip()))


def looks_like_secret_value(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    lower = stripped.lower()
    if (
        stripped.startswith(("sk-", "ghp_", "gho_", "ghs_", "AIza", "AKIA", "ASIA", "eyJ"))
        or "bearer " in lower
        or "-----BEGIN " in stripped
    ):
        return True
    if "." in stripped and stripped.count(".") == 2 and len(stripped) > 40:
        return True
    return len(stripped) >= 32 and not looks_like_env_name(stripped)


def get_config_value(cfg: object | Mapping[str, Any] | None, key: str, default: Any = "") -> Any:
    return _get_path(cfg, key, default)


def set_config_value(cfg: object | dict[str, Any], key: str, value: Any) -> None:
    parts = key.split(".")
    if not parts:
        return
    target: Any = cfg
    for part in parts[:-1]:
        if isinstance(target, dict):
            target = target.setdefault(part, {})
            continue
        next_target = getattr(target, part, None)
        if next_target is None:
            next_target = SimpleNamespace()
            setattr(target, part, next_target)
        target = next_target
    leaf = parts[-1]
    if isinstance(target, dict):
        target[leaf] = value
    else:
        setattr(target, leaf, value)


def apply_config_field(cfg: object | dict[str, Any], key: str, value: str) -> None:
    """Apply one Setup config field into a Python config object or dict."""

    if not key or key in {"config_version", "firewall.hint"}:
        return
    if key.startswith("firewall."):
        return
    if key.startswith(("skill_actions.", "mcp_actions.", "plugin_actions.")):
        _apply_action_matrix_field(cfg, key, value)
        return
    if _apply_global_registry_required_field(cfg, key, value):
        return
    if key.startswith("asset_policy.connectors."):
        _apply_per_connector_asset_policy_field(cfg, key, value)
        return
    if key.startswith("asset_policy."):
        _apply_typed_field(cfg, key, value)
        return
    if key.startswith("connector_hooks."):
        _apply_connector_hook_field(cfg, key, value)
        return
    if key.startswith("guardrail.connectors."):
        _apply_per_connector_guardrail_field(cfg, key, value)
        return
    if key.startswith("guardrail.judge.hook_connectors."):
        _apply_judge_hook_connector_toggle(cfg, key, value)
        return
    _apply_typed_field(cfg, key, value)


def _apply_global_registry_required_field(cfg: object | dict[str, Any], key: str, value: str) -> bool:
    """Route broad TUI registry-required edits through the shared resolver."""
    parts = key.split(".")
    if len(parts) != 3 or parts[0] != "asset_policy" or parts[2] != "registry_required":
        return False
    if parts[1] not in {"skill", "mcp", "plugin"}:
        return False
    try:
        from defenseclaw.config import Config  # noqa: PLC0415
        from defenseclaw.registry_policy import reconcile_registry_required  # noqa: PLC0415
    except Exception:  # noqa: BLE001 - dict/test fixtures use the generic writer.
        return False
    if not isinstance(cfg, Config):
        return False
    reconcile_registry_required(cfg, parts[1], value.strip().lower() == "true")
    return True


# B4/E4c/E4d: the config editor exposes every per-connector guardrail override.
# Top-level ``PerConnectorGuardrailConfig`` fields editable via the 4-part
# ``guardrail.connectors.<c>.<field>`` key; the nested HILT block is edited via
# the 5-part ``guardrail.connectors.<c>.hilt.<field>`` key. ``rule_pack_dir`` /
# ``block_message`` are free-text strings; ``mode`` is an enum string;
# ``hook_fail_mode`` normalizes to open/closed; ``enabled`` is a bool. The
# per-connector judge state is NOT here — it is membership in the
# ``guardrail.judge.hook_connectors`` list (see _apply_judge_hook_connector_toggle).
_PER_CONNECTOR_GUARDRAIL_STR_FIELDS = frozenset({"mode", "rule_pack_dir", "block_message"})
_PER_CONNECTOR_GUARDRAIL_BOOL_FIELDS = frozenset({"enabled"})
_PER_CONNECTOR_GUARDRAIL_FAIL_MODE_FIELDS = frozenset({"hook_fail_mode"})
_PER_CONNECTOR_GUARDRAIL_FIELDS = (
    _PER_CONNECTOR_GUARDRAIL_STR_FIELDS
    | _PER_CONNECTOR_GUARDRAIL_BOOL_FIELDS
    | _PER_CONNECTOR_GUARDRAIL_FAIL_MODE_FIELDS
)
_PER_CONNECTOR_HILT_FIELDS = frozenset({"enabled", "min_severity"})


def _coerce_per_connector_value(field_name: str, value: str) -> Any:
    """Coerce a TUI string value to the type ``PerConnectorGuardrailConfig`` expects.

    Bool fields (``enabled``) parse ``"true"``/``"false"``; ``hook_fail_mode``
    normalizes to the ``open``/``closed`` enum (mirroring cmd_setup's
    ``_apply_hook_connector_setup`` and the global guardrail apply path);
    everything else is a free-text / enum string written verbatim.
    """

    if field_name in _PER_CONNECTOR_GUARDRAIL_BOOL_FIELDS:
        return value.strip().lower() == "true"
    if field_name in _PER_CONNECTOR_GUARDRAIL_FAIL_MODE_FIELDS:
        return "closed" if value.strip().lower() == "closed" else "open"
    return value


def _apply_per_connector_guardrail_field(cfg: object | dict[str, Any], key: str, value: str) -> None:
    """Write one ``guardrail.connectors.<c>.<field>`` override (B4/E4c/E4d).

    The naive ``set_config_value`` traversal would replace a typed
    :class:`PerConnectorGuardrailConfig` entry with a plain ``dict`` (or create
    one for a missing connector), which breaks the ``effective_*`` resolvers the
    boot loop reads. So construct/locate the typed entry and ``setattr`` the
    field (type-coerced), preserving any sibling overrides. The nested HILT block
    (``guardrail.connectors.<c>.hilt.<field>``, 5 parts) is materialized on first
    write so a present block explicitly overrides the global one (see
    ``GuardrailConfig.effective_hilt``). Dict-backed configs (test fixtures)
    round-trip fine through the nested-dict fallback.
    """

    parts = key.split(".")
    # guardrail.connectors.<c>.<field>        -> 4 parts (top-level override)
    # guardrail.connectors.<c>.hilt.<field>   -> 5 parts (nested HILT block)
    if len(parts) not in (4, 5) or parts[1] != "connectors":
        return
    connector = parts[2].strip()
    if not connector:
        return
    field_name = parts[3]
    is_hilt = len(parts) == 5
    if is_hilt:
        if field_name != "hilt" or parts[4] not in _PER_CONNECTOR_HILT_FIELDS:
            return
    elif field_name not in _PER_CONNECTOR_GUARDRAIL_FIELDS:
        return
    guardrail = getattr(cfg, "guardrail", None)
    connectors = getattr(guardrail, "connectors", None) if guardrail is not None else None
    if guardrail is None or isinstance(guardrail, Mapping) or not isinstance(connectors, dict):
        # Dict-backed config (or an unexpected shape): nested-dict creation
        # round-trips cleanly and never strips a typed sibling.
        leaf = parts[4] if is_hilt else field_name
        set_config_value(cfg, key, _coerce_per_connector_value(leaf, value))
        return
    try:
        from defenseclaw.config import HILTConfig, PerConnectorGuardrailConfig  # noqa: PLC0415
    except Exception:  # noqa: BLE001 - degrade to the dict fallback.
        set_config_value(cfg, key, value)
        return
    entry = connectors.get(connector)
    if not isinstance(entry, PerConnectorGuardrailConfig):
        replacement = PerConnectorGuardrailConfig()
        if isinstance(entry, Mapping):
            for sib_key, sib_val in entry.items():
                if hasattr(replacement, sib_key):
                    setattr(replacement, sib_key, sib_val)
        connectors[connector] = replacement
        entry = replacement
    if is_hilt:
        # A present hilt block (even partial) explicitly overrides the global
        # one — materialize it on first touch, then set just the named leaf.
        block = entry.hilt if isinstance(entry.hilt, HILTConfig) else HILTConfig()
        entry.hilt = block
        sub_field = parts[4]
        if sub_field == "enabled":
            block.enabled = value.strip().lower() == "true"
        else:  # min_severity
            block.min_severity = value.strip().upper()
        return
    setattr(entry, field_name, _coerce_per_connector_value(field_name, value))


def _apply_judge_hook_connector_toggle(cfg: object | dict[str, Any], key: str, value: str) -> None:
    """Add/remove one connector from ``guardrail.judge.hook_connectors`` (B4 judge half).

    The per-connector hook-lane judge state is NOT a
    :class:`PerConnectorGuardrailConfig` field — it is membership in the
    ``guardrail.judge.hook_connectors`` gate list. The synthetic
    ``guardrail.judge.hook_connectors.<c>`` key from the editor toggles that
    membership *surgically* (mirrors the CLI ``--judge-hook-connectors`` opt-in /
    opt-out): a ``true`` write adds the connector, a ``false`` write removes it.
    The rest of the judge block is never touched. The ``"*"`` every-connector
    sentinel is honored like the CLI's ``_apply_judge_enablement`` opt-out: a
    ``true`` write is a no-op (already covered) and a ``false`` write leaves
    ``"*"`` intact rather than expanding-then-subtracting (the ambiguous case the
    CLI deliberately refuses, J6).
    """

    parts = key.split(".")
    if len(parts) != 4 or parts[:3] != ["guardrail", "judge", "hook_connectors"]:
        return
    connector = parts[3].strip()
    if not connector:
        return
    enable = value.strip().lower() == "true"
    name = connector.lower()

    gate_raw = _get_path(cfg, "guardrail.judge.hook_connectors", None)
    gate = [str(entry) for entry in gate_raw] if isinstance(gate_raw, (list, tuple)) else []
    is_all = any((entry or "").strip() == "*" for entry in gate)
    contains = any((entry or "").strip().lower() == name for entry in gate)

    if enable:
        if is_all or contains:
            return  # already covered — nothing to change.
        new_gate = [*gate, connector]
    else:
        if is_all or not contains:
            # "*" covers everything (leave it intact, J6); or the connector
            # was never listed — either way there is nothing to remove.
            return
        new_gate = [entry for entry in gate if (entry or "").strip().lower() != name]

    # Write the list back, preserving a typed JudgeConfig (never a dict that
    # would shadow the dataclass) — set_config_value handles the dict fixture.
    guardrail = getattr(cfg, "guardrail", None)
    judge = getattr(guardrail, "judge", None) if guardrail is not None else None
    if judge is not None and not isinstance(judge, Mapping):
        judge.hook_connectors = new_gate
    else:
        set_config_value(cfg, "guardrail.judge.hook_connectors", new_gate)


def split_csv(value: str) -> list[str]:
    parts = [part.strip() for part in value.strip().split(",")]
    return [part for part in parts if part]


def parse_kv_csv(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in split_csv(value):
        key, sep, val = part.partition("=")
        if sep and key.strip():
            out[key.strip()] = val.strip()
    return out


def _intent(binary: str, args: tuple[str, ...], label: str, category: str) -> SetupCommandIntent:
    return SetupCommandIntent(label=label, args=args, binary=binary, category=category, origin="readiness")


def _state_healthy(state: str) -> bool:
    return state.strip().lower() in {"running", "ok", "healthy", "ready"}


def _state_healthy_or_disabled(state: str) -> bool:
    return state.strip().lower() == "disabled" or _state_healthy(state)


def _doctor_missing_credentials(doctor: object | Mapping[str, Any] | None) -> tuple[str, ...]:
    if doctor is None:
        return ()
    if isinstance(doctor, Mapping):
        raw = doctor.get("missing_required_credentials") or doctor.get("missingRequiredCredentials") or ()
    else:
        method = getattr(doctor, "missing_required_credentials", None)
        if callable(method):
            raw = method()
        else:
            method = getattr(doctor, "MissingRequiredCredentials", None)
            raw = method() if callable(method) else getattr(doctor, "missing_required_credentials", ())
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return ()
    return tuple(str(item) for item in raw if str(item).strip())


def _active_connector_names(cfg: object | Mapping[str, Any] | None) -> list[str]:
    """Resolve the active connector set for the readiness panel (B1).

    Prefers the live ``Config.active_connectors()`` (multi-connector aware and
    R1-clean: empty when nothing is configured, never a phantom "openclaw").
    Falls back to reading the config shape directly when given a plain mapping
    (the test fixtures pass dicts): the ``guardrail.connectors`` map keys, then
    the singular ``guardrail.connector`` / ``claw.mode`` markers. An empty
    result means "no connector configured" and drives the fail row.
    """
    method = getattr(cfg, "active_connectors", None)
    if callable(method):
        try:
            names = method()
        except Exception:  # noqa: BLE001 — never let a config quirk blank readiness.
            names = None
        if isinstance(names, (list, tuple)):
            return [str(name).strip() for name in names if str(name).strip()]

    connectors_map = _get_path(cfg, "guardrail.connectors", None)
    if isinstance(connectors_map, Mapping):
        keys = [str(key).strip() for key in connectors_map if str(key).strip()]
        if keys:
            return sorted(set(keys))
    singular = (
        str(_get_path(cfg, "guardrail.connector", "") or "").strip()
        or str(_get_path(cfg, "claw.mode", "") or "").strip()
    )
    return [singular] if singular else []


def _registry_required_but_empty(cfg: object | Mapping[str, Any] | None) -> bool:
    for key in ("asset_policy.skill", "asset_policy.mcp", "asset_policy.plugin"):
        if bool(_get_path(cfg, f"{key}.registry_required", False)) and not _get_path(cfg, f"{key}.registry", ()):
            return True
    return False


def _get_path(obj: object | Mapping[str, Any] | None, path: str, default: Any = "") -> Any:
    if obj is None:
        return default
    target: Any = obj
    for part in path.split("."):
        if isinstance(target, Mapping):
            if part not in target:
                return default
            target = target[part]
        else:
            if not hasattr(target, part):
                return default
            target = getattr(target, part)
        if target is None:
            return default
    return target


def _is_secret_name(name: str) -> bool:
    lowered = name.strip().lower()
    return bool(lowered) and any(
        marker in lowered
        for marker in ("password", "secret", "token", "api_key", "apikey", "access_key", "private_key")
    )


def _looks_like_url_field(key: str) -> bool:
    return any(marker in key for marker in ("url", "endpoint", "api_base", "base_url"))


def _is_otlp_endpoint_field(key: str) -> bool:
    return False


def _validate_host_port(value: str) -> bool:
    host, sep, port = value.rpartition(":")
    if not sep or not host.strip().strip("[]"):
        return False
    try:
        port_num = int(port)
    except ValueError:
        return False
    return 1 <= port_num <= 65535


_GO_DURATION_RE = re.compile("^(?:\\d+(?:\\.\\d+)?(?:ns|us|\\u00b5s|ms|s|m|h))+$")


def _looks_like_go_duration_or_seconds(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    if stripped.isdigit():
        return True
    return bool(_GO_DURATION_RE.fullmatch(stripped))


def _apply_typed_field(cfg: object | dict[str, Any], key: str, value: str) -> None:
    if key in _BOOL_FIELD_KEYS:
        set_config_value(cfg, key, value == "true")
        return
    if key in _INT_FIELD_KEYS:
        try:
            parsed = int(value)
        except ValueError:
            parsed = 0
        set_config_value(cfg, key, parsed)
        return
    if key in _CSV_FIELD_KEYS:
        set_config_value(cfg, key, split_csv(value))
        return
    if key in _KV_CSV_FIELD_KEYS:
        set_config_value(cfg, key, parse_kv_csv(value))
        return
    if key in _TRISTATE_FIELD_KEYS:
        parsed_bool: bool | None
        if value.strip().lower() == "true":
            parsed_bool = True
        elif value.strip().lower() == "false":
            parsed_bool = False
        else:
            parsed_bool = None
        set_config_value(cfg, key, parsed_bool)
        return
    if key == "guardrail.hook_fail_mode":
        set_config_value(cfg, key, "closed" if value.strip() == "closed" else "open")
        return
    if key == "guardrail.hilt.min_severity":
        set_config_value(cfg, key, value.strip().upper())
        return
    if key == "scanners.skill_scanner.policy" and value.strip() == "none":
        set_config_value(cfg, key, "")
        return
    set_config_value(cfg, key, value)


def _apply_connector_hook_field(cfg: object | dict[str, Any], key: str, value: str) -> None:
    parts = key.split(".")
    if len(parts) < 3 or not parts[1].strip():
        return
    _apply_typed_field(cfg, key, value)


def _apply_action_matrix_field(cfg: object | dict[str, Any], key: str, value: str) -> None:
    parts = key.split(".")
    if len(parts) != 3:
        return
    prefix, severity, column = parts
    if prefix not in {"skill_actions", "mcp_actions", "plugin_actions"}:
        return
    if severity not in {"critical", "high", "medium", "low", "info"}:
        return
    if column not in {"file", "runtime", "install"}:
        return
    set_config_value(cfg, key, value)


def _coerce_per_connector_asset_policy_value(field_name: str, value: str) -> Any:
    raw = value.strip()
    if field_name == "registry_required":
        lowered = raw.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        return None
    return raw.lower()


def _apply_per_connector_asset_policy_field(cfg: object | dict[str, Any], key: str, value: str) -> None:
    """Write one ``asset_policy.connectors.<c>`` scalar override.

    The generic config writer would materialize missing typed entries as
    ``SimpleNamespace`` objects, which breaks ``AssetPolicyConfig.effective_*``
    resolution. Mirror the guardrail override writer: preserve typed map
    entries, materialize optional per-type blocks only when touched, and use
    ``None`` for blank per-connector ``registry_required`` so it inherits the
    global setting.
    """

    parts = key.split(".")
    # asset_policy.connectors.<connector>.mode
    # asset_policy.connectors.<connector>.<asset>.{default,registry_required,registry_empty_action}
    if len(parts) not in (4, 5) or parts[1] != "connectors":
        return
    connector = parts[2].strip()
    if not connector:
        return
    is_mode = len(parts) == 4
    if is_mode:
        if parts[3] != "mode":
            return
        asset_type = ""
        field_name = "mode"
    else:
        asset_type = parts[3]
        field_name = parts[4]
        if asset_type not in {"skill", "mcp", "plugin"} or field_name not in {
            "default",
            "registry_required",
            "registry_empty_action",
        }:
            return

    asset_policy = getattr(cfg, "asset_policy", None)
    connectors = getattr(asset_policy, "connectors", None) if asset_policy is not None else None
    if asset_policy is None or isinstance(asset_policy, Mapping) or not isinstance(connectors, dict):
        set_config_value(cfg, key, _coerce_per_connector_asset_policy_value(field_name, value))
        return

    coerced = _coerce_per_connector_asset_policy_value(field_name, value)
    if field_name == "registry_required" and coerced is not None:
        try:
            from defenseclaw.config import Config  # noqa: PLC0415
            from defenseclaw.registry_policy import reconcile_registry_required  # noqa: PLC0415
        except Exception:  # noqa: BLE001 - continue through the typed fallback.
            pass
        else:
            if isinstance(cfg, Config):
                reconcile_registry_required(cfg, asset_type, coerced, connector=connector)
                return

    try:
        from defenseclaw.config import PerConnectorAssetPolicy, PerConnectorAssetTypePolicy  # noqa: PLC0415
    except Exception:  # noqa: BLE001 - degrade to the dict fallback.
        set_config_value(cfg, key, _coerce_per_connector_asset_policy_value(field_name, value))
        return

    entry = connectors.get(connector)
    if not isinstance(entry, PerConnectorAssetPolicy):
        replacement = PerConnectorAssetPolicy()
        if isinstance(entry, Mapping):
            for sib_key, sib_val in entry.items():
                if hasattr(replacement, sib_key):
                    setattr(replacement, sib_key, sib_val)
        connectors[connector] = replacement
        entry = replacement
    if is_mode:
        entry.mode = _coerce_per_connector_asset_policy_value(field_name, value)
        return

    block = getattr(entry, asset_type, None)
    if not isinstance(block, PerConnectorAssetTypePolicy):
        replacement_block = PerConnectorAssetTypePolicy()
        if isinstance(block, Mapping):
            for sib_key, sib_val in block.items():
                if hasattr(replacement_block, sib_key):
                    setattr(replacement_block, sib_key, sib_val)
        setattr(entry, asset_type, replacement_block)
        block = replacement_block
    setattr(block, field_name, coerced)


_BOOL_FIELD_KEYS = frozenset(
    {
        "privacy.disable_redaction",
        "notifications.enabled",
        "notifications.block_enforced",
        "notifications.block_would_block",
        "notifications.hitl_approval",
        "notifications.sources.hook",
        "notifications.sources.guardrail",
        "notifications.sources.asset_policy",
        "gateway.auto_approve_safe",
        "gateway.tls",
        "gateway.tls_skip_verify",
        "guardrail.enabled",
        "guardrail.allow_empty_providers",
        "guardrail.allow_unknown_llm_domains",
        "guardrail.hilt.enabled",
        "guardrail.retain_judge_bodies",
        "guardrail.judge_sweep",
        "guardrail.judge.enabled",
        "guardrail.judge.injection",
        "guardrail.judge.exfil",
        "guardrail.judge.pii",
        "guardrail.judge.pii_prompt",
        "guardrail.judge.pii_completion",
        "guardrail.judge.tool_injection",
        "scanners.skill_scanner.lenient",
        "scanners.skill_scanner.use_llm",
        "scanners.skill_scanner.use_behavioral",
        "scanners.skill_scanner.enable_meta",
        "scanners.skill_scanner.use_trigger",
        "scanners.skill_scanner.use_virustotal",
        "scanners.skill_scanner.use_aidefense",
        "scanners.mcp_scanner.scan_prompts",
        "scanners.mcp_scanner.scan_resources",
        "scanners.mcp_scanner.scan_instructions",
        "ai_discovery.enabled",
        "ai_discovery.allow_workspace_signatures",
        "ai_discovery.include_shell_history",
        "ai_discovery.include_package_manifests",
        "ai_discovery.include_env_var_names",
        "ai_discovery.include_network_domains",
        "ai_discovery.emit_otel",
        "ai_discovery.store_raw_local_paths",
        "gateway.watcher.enabled",
        "gateway.watcher.skill.enabled",
        "gateway.watcher.skill.take_action",
        "gateway.watcher.plugin.enabled",
        "gateway.watcher.plugin.take_action",
        "gateway.watcher.mcp.take_action",
        "gateway.watchdog.enabled",
        "otel.enabled",
        "otel.logs.emit_individual_findings",
        "watch.auto_block",
        "watch.allow_list_bypass_scan",
        "watch.rescan_enabled",
        "asset_policy.enabled",
        "asset_policy.skill.registry_required",
        "asset_policy.mcp.registry_required",
        "asset_policy.mcp.runtime_detection.enabled",
        "asset_policy.mcp.runtime_detection.terminal_commands",
        "asset_policy.plugin.registry_required",
        "claude_code.enabled",
        "claude_code.scan_on_session_start",
        "claude_code.scan_on_stop",
        "codex.enabled",
        "codex.scan_on_session_start",
        "codex.scan_on_stop",
    }
)

_INT_FIELD_KEYS = frozenset(
    {
        "llm.timeout",
        "llm.max_retries",
        "notifications.max_per_minute",
        "gateway.port",
        "gateway.api_port",
        "gateway.reconnect_ms",
        "gateway.max_reconnect_ms",
        "gateway.approval_timeout_s",
        "guardrail.port",
        "guardrail.llm.timeout",
        "guardrail.llm.max_retries",
        "guardrail.judge.llm.timeout",
        "guardrail.judge.llm.max_retries",
        "scanners.skill_scanner.llm_consensus_runs",
        "scanners.skill_scanner.llm.timeout",
        "scanners.skill_scanner.llm.max_retries",
        "scanners.mcp_scanner.llm.timeout",
        "scanners.mcp_scanner.llm.max_retries",
        "scanners.plugin_llm.timeout",
        "scanners.plugin_llm.max_retries",
        "ai_discovery.scan_interval_min",
        "ai_discovery.process_interval_s",
        "ai_discovery.max_files_per_scan",
        "ai_discovery.max_file_bytes",
        "gateway.watchdog.interval",
        "gateway.watchdog.debounce",
        "otel.metrics.export_interval_s",
        "otel.batch.max_export_batch_size",
        "otel.batch.scheduled_delay_ms",
        "otel.batch.max_queue_size",
        "watch.debounce_ms",
        "watch.rescan_interval_min",
        "cisco_ai_defense.timeout_ms",
        "claude_code.component_scan_interval_minutes",
        "codex.component_scan_interval_minutes",
    }
)

_CSV_FIELD_KEYS = frozenset(
    {
        "guardrail.judge.fallbacks",
        "ai_discovery.scan_roots",
        "ai_discovery.signature_packs",
        "ai_discovery.disabled_signature_ids",
        "gateway.watcher.skill.dirs",
        "gateway.watcher.plugin.dirs",
        "cisco_ai_defense.enabled_rules",
        "claude_code.scan_paths",
        "codex.scan_paths",
    }
)

_KV_CSV_FIELD_KEYS = frozenset({"otel.resource.attributes"})

_TRISTATE_FIELD_KEYS = frozenset({"openshell.auto_pair", "openshell.host_networking"})
