# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure Setup panel model and parity metadata for the Textual TUI."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Literal

from defenseclaw import config as dc_config
from defenseclaw.acp_catalog import ACP_AGENT_IDS, ACP_CLIENT_IDS
from defenseclaw.connector_contracts import normalize_connector
from defenseclaw.notification_capabilities import desktop_notification_capability
from defenseclaw.observability.v8_config import (
    BUCKETS as REDACTION_BUCKETS,
)
from defenseclaw.observability.v8_config import (
    DETECTOR_GROUPS as REDACTION_DETECTOR_GROUPS,
)
from defenseclaw.observability.v8_config import (
    FIELD_CLASSES as REDACTION_FIELD_CLASSES,
)
from defenseclaw.observability.v8_config import (
    FIELD_MODES as REDACTION_FIELD_MODES,
)
from defenseclaw.observability.v8_config import (
    SEVERITIES as REDACTION_SEVERITIES,
)
from defenseclaw.observability.v8_redaction_policy import (
    CUSTOM_PROFILE_BASES as REDACTION_CUSTOM_PROFILE_BASES,
)
from defenseclaw.observability.v8_status import V8OperatorStatus
from defenseclaw.platform_support import (
    LOCAL_OBSERVABILITY_UNSUPPORTED_REASON,
    host_os,
    local_observability_stack_supported,
    local_splunk_stack_supported,
    openshell_sandboxes_supported,
)
from defenseclaw.tui.services.catalog_state import friendly_connector_name
from defenseclaw.tui.services.cli_choices import (
    AI_DISCOVERY_MODES,
    AZURE_AUTH_MODES,
    BEDROCK_AUTH_MODES,
    CUSTOM_PROVIDER_BASE_TYPES,
    CUSTOM_PROVIDER_REQUEST_TYPES,
    GUARDRAIL_JUDGE_INHERIT_PATHS,
    GUARDRAIL_JUDGE_LLM_ROLES,
    LLM_INHERIT_PATHS,
    LLM_ROLES,
    REGIONAL_PROVIDERS,
    VERTEX_AUTH_MODES,
    supported_connector_choices,
)
from defenseclaw.tui.services.cli_choices import (
    CONNECTORS as _CHOICE_CONNECTORS,
)
from defenseclaw.tui.services.cli_choices import (
    GUARDRAIL_CONNECTORS as _CHOICE_GUARDRAIL_CONNECTORS,
)
from defenseclaw.tui.services.cli_choices import (
    LLM_OVERRIDE_PROVIDERS as _CHOICE_LLM_OVERRIDE_PROVIDERS,
)
from defenseclaw.tui.services.cli_choices import (
    LLM_PROVIDERS as _CHOICE_LLM_PROVIDERS,
)
from defenseclaw.tui.services.cli_choices import (
    SCANNER_LLM_PROVIDERS as _SCANNER_LLM_PROVIDERS,
)
from defenseclaw.tui.services.cli_choices import (
    SKILL_SCANNER_POLICIES as _SKILL_SCANNER_POLICIES,
)
from defenseclaw.tui.services.cli_choices import (
    WIZARD_LLM_PROVIDERS as _CHOICE_WIZARD_LLM_PROVIDERS,
)
from defenseclaw.tui.services.sandbox_state import DEFAULT_SANDBOX_HARNESSES, SANDBOX_HARNESS_SPECS, compute_driver
from defenseclaw.tui.services.setup_state import (
    OPENSHELL_INHERIT_CHOICE,
    ConfigDiffEntry,
    ConfigField,
    ConfigSection,
    CredentialRow,
    CredentialSnapshot,
    RestartQueue,
    SetupCommandIntent,
    SetupPreviewRisk,
    ValidationResult,
    apply_config_field,
    blocking_validation_errors,
    build_readiness_checks,
    config_diff,
    failing_exports,
    get_config_value,
    guardrail_mode_label,
    is_python_modeled,
    looks_like_secret_value,
    mask_secret,
    split_csv,
    telemetry_readiness_detail,
    validate_config_field,
    validation_errors,
)

SetupMode = Literal["wizards", "config"]
WizardFieldKind = Literal["bool", "string", "choice", "int", "password", "section", "preset", "whtype", "regid"]
UninstallOption = Literal["dry-run", "keep-data", "wipe-data", "wipe-all"]

# These re-exports keep existing callers (panels, tests) importing from
# ``defenseclaw.tui.panels.setup`` working unchanged while routing the
# canonical definition through ``cli_choices``. Drop the re-exports
# only after every importer is migrated to ``cli_choices`` directly.
CONNECTORS = _CHOICE_CONNECTORS
GUARDRAIL_CONNECTORS = _CHOICE_GUARDRAIL_CONNECTORS
_WIZARD_LLM_PROVIDERS = _CHOICE_WIZARD_LLM_PROVIDERS
LLM_PROVIDERS = _CHOICE_LLM_PROVIDERS
LLM_OVERRIDE_PROVIDERS = _CHOICE_LLM_OVERRIDE_PROVIDERS

_GUARDRAIL_SCOPE_CONNECTOR = "selected-connector"
_GUARDRAIL_SCOPE_GLOBAL = "global-all-active"
_GUARDRAIL_SCOPES = (_GUARDRAIL_SCOPE_CONNECTOR, _GUARDRAIL_SCOPE_GLOBAL)


class SetupWizard(IntEnum):
    CONNECTOR_SETUP = 0
    CREDENTIALS = 1
    LLM = 2
    LOCAL_OBSERVABILITY = 3
    TOKEN_ROTATION = 4
    CUSTOM_PROVIDERS = 5
    SKILL_SCANNER = 6
    MCP_SCANNER = 7
    GATEWAY = 8
    GUARDRAIL = 9
    SPLUNK = 10
    OBSERVABILITY = 11
    WEBHOOKS = 12
    SANDBOX = 13
    REGISTRIES = 14
    NOTIFICATIONS_ROUTING = 15
    AI_DISCOVERY = 16
    SPLUNK_DASHBOARDS = 17
    TRUSTED_PATHS = 18
    GUARDRAIL_ACTIONS = 19
    REDACTION = 20
    ACP_GUARD = 21


WIZARD_NAMES: tuple[str, ...] = (
    "Connector Setup",
    "Credentials",
    "LLM",
    "Local OTel",
    "Token Rotation",
    "Custom Providers",
    "Skill Scanner",
    "MCP Scanner",
    "Gateway",
    "Guardrail",
    "Splunk",
    "Observability / Galileo",
    "Webhooks",
    "Sandbox",
    "Registries",
    "Notifications Routing",
    "AI Discovery",
    "Splunk Dashboards",
    "Trusted Paths",
    "Guardrail Actions",
    "Redaction Policy",
    "ACP Guard",
)

WIZARD_COMMANDS: dict[SetupWizard, tuple[str, ...]] = {
    SetupWizard.CONNECTOR_SETUP: ("setup",),
    SetupWizard.CREDENTIALS: ("keys",),
    SetupWizard.LLM: ("setup", "llm"),
    SetupWizard.LOCAL_OBSERVABILITY: ("setup", "local-observability"),
    SetupWizard.TOKEN_ROTATION: ("setup", "rotate-token"),
    SetupWizard.CUSTOM_PROVIDERS: ("setup", "provider"),
    SetupWizard.SKILL_SCANNER: ("setup", "skill-scanner"),
    SetupWizard.MCP_SCANNER: ("setup", "mcp-scanner"),
    SetupWizard.GATEWAY: ("setup", "gateway"),
    SetupWizard.GUARDRAIL: ("setup", "guardrail"),
    SetupWizard.SPLUNK: ("setup", "splunk"),
    SetupWizard.OBSERVABILITY: ("setup", "observability", "add"),
    SetupWizard.WEBHOOKS: ("setup", "webhook", "add"),
    # OpenShell 0.1 sandboxes (slot 13 held the removed legacy wizard).
    SetupWizard.SANDBOX: ("sandbox", "setup"),
    SetupWizard.REGISTRIES: ("registry", "add"),
    # NOTIFICATIONS_ROUTING fan-outs to multiple
    # ``setup notifications-set <slot> <value>`` calls; the first
    # primary intent uses this base prefix and follow_ups carry the
    # remaining flips.
    SetupWizard.NOTIFICATIONS_ROUTING: ("setup", "notifications-set"),
    # Discovery enable/disable share the same wizard; the choice toggle
    # decides which sub-command this resolves to in ``build_wizard_args``.
    SetupWizard.AI_DISCOVERY: ("agent", "discovery", "enable"),
    # Splunk O11y dashboards: apply or destroy. Same shape as
    # AI_DISCOVERY — the action toggle picks the sub-command at
    # arg-build time. The dashboards subgroup is mounted under
    # ``setup splunk`` (see cmd_setup.add_command(splunk_o11y_dashboards)).
    SetupWizard.SPLUNK_DASHBOARDS: ("setup", "splunk", "dashboards", "apply"),
    SetupWizard.TRUSTED_PATHS: ("setup", "trusted-paths", "list"),
    SetupWizard.GUARDRAIL_ACTIONS: ("guardrail", "status"),
    SetupWizard.REDACTION: ("setup", "redaction"),
    SetupWizard.ACP_GUARD: ("acp", "setup"),
}

# First argv words the Setup tasks run ("setup", "keys", "guardrail", "agent"
# …): a finished or failed command of one of these clears a task's
# "running" badge (``mark_wizard_complete``).
WIZARD_COMMAND_FAMILIES: frozenset[str] = frozenset(command[0] for command in WIZARD_COMMANDS.values() if command)


def _wizard_action_family(wizard: SetupWizard) -> tuple[str, ...]:
    """The argv prefix a wizard's sibling actions share (``()``: no fallback).

    Its WIZARD_COMMANDS entry without the action word: ``agent discovery``
    for ``agent discovery enable``, ``guardrail`` for ``guardrail status``.
    A bare ``setup`` family is shared by most tasks, so it never matches, and
    the Sandbox task finishes only on its own setup and doctor runs.
    """

    command = WIZARD_COMMANDS.get(wizard, ())
    family = command[:-1] if len(command) >= 2 else command
    if wizard == SetupWizard.SANDBOX or family in {(), ("setup",)}:
        return ()
    return family

# The sentence every openshell.admin refusal starts with (sandboxapi.AdminMessage).
ADMIN_POLICY_MESSAGE = "blocked by your organization's DefenseClaw policy"
# Choice value for pack-governed openshell keys left unset.
OPENSHELL_INHERIT = OPENSHELL_INHERIT_CHOICE

SANDBOX_WIZARD_UNSUPPORTED_REASON = (
    "OpenShell sandboxes run on Linux and macOS only; Windows and WSL2 are not supported."
)

NOTIFICATION_ROUTING_SLOTS: tuple[tuple[str, str, str], ...] = (
    # (slot id, label, default state)
    ("block_enforced", "Block (enforced)", "yes"),
    ("block_would_block", "Block (would-block / observe)", "no"),
    ("hitl_approval", "HITL Approval", "yes"),
    ("sources.hook", "Source: Hooks", "yes"),
    ("sources.guardrail", "Source: Guardrail", "yes"),
    ("sources.asset_policy", "Source: Asset Policy", "yes"),
)

# The hints only repeated the label ("Toggle hitl approval.", GAP-2386).
_NOTIFICATION_SLOT_HINTS: dict[str, str] = {
    "block_enforced": "Show a desktop notification when a call is blocked.",
    "block_would_block": "Show a desktop notification when observe mode would have blocked a call.",
    "hitl_approval": "Show a desktop notification when an action waits for your approval.",
    "sources.hook": "Notify about verdicts from agent hooks (Claude Code, Codex, ...).",
    "sources.guardrail": "Notify about verdicts from the LLM guardrail.",
    "sources.asset_policy": "Notify when a skill or MCP server is blocked by the allow list.",
}
_RESTART_GATEWAY_HINT = "Restart the gateway so the change takes effect now."

_MISSING_FIELDS_PREFIX = "Missing required field(s): "

WIZARD_DESCRIPTIONS: tuple[str, ...] = (
    "Add, switch or remove the agents DefenseClaw protects.",
    "See which API keys are missing and set them.",
    "Pick the model and API key the scanners and judge use.",
    "Start, stop or reset the bundled local dashboards (Docker).",
    "Replace the gateway and hook tokens in one step.",
    "Add or remove LLM providers the guardrail should recognize.",
    "Choose how skills are scanned and which analyzers run.",
    "Choose how MCP servers are scanned and what gets checked.",
    "Set the gateway host, ports, TLS and token.",
    "Turn on the LLM guardrail and choose observe or action (block).",
    "Send events to Splunk HEC or a local Splunk.",
    "Send logs, traces and metrics to an observability vendor.",
    "Post alerts to Slack, PagerDuty, Webex or any URL.",
    "Run coding agents in OpenShell sandboxes.",
    "Add a skill or MCP catalog you trust.",
    "Choose which events send you notifications.",
    "Find the AI tools in use on this machine.",
    "Create or remove the Splunk Observability dashboards.",
    "List the folders where agent binaries are trusted.",
    "Turn the guardrail on or off, set fail mode and approvals.",
    "Choose what is hidden from logs and exports.",
    "Protect an ACP agent in Zed or JetBrains.",
)

WIZARD_HOW_TO: tuple[str, ...] = (
    "Runs: defenseclaw setup <connector> --yes. Need connector, guardrail mode, and restart preference "
    "(scanner mode for proxy connectors).",
    "Runs: defenseclaw keys list / check / set / remove / fill-missing. "
    "Need env var name for set and remove, and the secret only for set.",
    "Runs: defenseclaw setup llm --non-interactive. Need provider, model, optional base URL, and API key env or value.",
    "Runs: defenseclaw setup local-observability <action>. "
    "Need Docker for up/reset; status/url require no credentials.",
    "Runs: defenseclaw setup rotate-token --yes. Rotates every configured scoped-hook credential transactionally.",
    "Runs: defenseclaw setup provider add|remove|list|show. Need provider name and domains for add/remove.",
    "Runs: defenseclaw setup skill-scanner. Need optional LLM, VirusTotal, or Cisco AI Defense credentials.",
    "Runs: defenseclaw setup mcp-scanner. Need analyzer list and prompt/resource/instruction scan choices.",
    "Runs: defenseclaw setup gateway. Need host, ports, TLS posture, and optional token source.",
    "Runs: defenseclaw setup guardrail. Need mode, scanner mode, optional judge model, and remote scanner credentials.",
    "Runs: defenseclaw setup splunk. Need HEC endpoint/token or local Docker and license acceptance.",
    "Runs: defenseclaw setup observability add <preset>. Choose Galileo or another vendor, then provide "
    "endpoint/project, credentials, and signals.",
    "Runs: defenseclaw setup webhook add <type>. Need webhook URL, secret env where required, and event filters.",
    "Runs: defenseclaw sandbox setup --non-interactive in this terminal (sudo prompts and image builds show), "
    "or defenseclaw sandbox doctor. Needs Docker; installs OpenShell only when you tick it.",
    "Runs: defenseclaw registry add <id> --non-interactive. Need source id, kind, content type, and manifest URL.",
    "Runs one defenseclaw setup notifications-set <slot> on|off per changed toggle. No credentials required.",
    "Runs: defenseclaw agent discovery enable --yes (or disable). Mirrors cadence, scope, and privacy toggles.",
    "Runs: defenseclaw setup splunk dashboards apply|destroy --yes. Requires the Splunk O11y realm + API token.",
    "Runs: defenseclaw setup trusted-paths list|add|remove. Need a directory for add/remove.",
    "Runs: defenseclaw guardrail status|enable|disable|fail-mode|hilt|block-message with optional --connector.",
    (
        "Runs: defenseclaw setup redaction. Quick actions are non-interactive; the guided workflow exposes every "
        "advanced bucket, profile, destination, and ordered-route setting."
    ),
    "Runs: defenseclaw acp setup. Choose an editor client, ACP agent, profile, and observe or action mode.",
)

OBSERVABILITY_PRESETS: tuple[tuple[str, str], ...] = (
    ("splunk-o11y", "Splunk Observability Cloud"),
    ("splunk-hec", "Splunk HEC"),
    ("splunk-enterprise", "Splunk Enterprise HEC"),
    ("datadog", "Datadog"),
    ("honeycomb", "Honeycomb"),
    ("newrelic", "New Relic"),
    ("grafana-cloud", "Grafana Cloud"),
    ("galileo", "Galileo Cloud / Self-hosted"),
    ("local-otlp", "Local Observability Stack"),
    ("otlp", "Generic OTLP"),
    ("webhook", "Generic HTTP JSONL"),
)
WEBHOOK_TYPES: tuple[tuple[str, str], ...] = (
    ("slack", "Slack (incoming webhook)"),
    ("pagerduty", "PagerDuty (Events API v2)"),
    ("webex", "Cisco Webex (bot)"),
    ("generic", "Generic HMAC-signed"),
)
REGISTRY_KIND_OPTIONS: tuple[str, ...] = ("clawhub", "smithery", "skills_sh", "http_yaml", "http_json", "git", "file")
REGISTRY_CONTENT_OPTIONS: tuple[str, ...] = ("skill", "mcp", "both")


@dataclass(frozen=True)
class WizardFormField:
    label: str
    kind: WizardFieldKind | str
    flag: str = ""
    no_flag: str = ""
    value: str = ""
    default: str = ""
    options: tuple[str, ...] = ()
    hint: str = ""
    required: bool = False
    # Optional predicate that decides whether this field is shown for the
    # current driver-field values (e.g. only show Bedrock rows when the
    # selected provider is ``bedrock``). ``None`` means "always visible".
    # Excluded from equality/repr so existing argv/parity tests that
    # compare fields by their data values stay stable when a predicate is
    # attached.
    visible_when: Callable[[Mapping[str, str]], bool] | None = dataclass_field(default=None, compare=False, repr=False)
    # Optional model-picker hook. When set, pressing Enter on this field
    # opens the searchable ModelPickerScreen instead of submitting the
    # form. The string is the picker mode (currently only ``"llm"``).
    picker: str = dataclass_field(default="", compare=False, repr=False)

    def __post_init__(self) -> None:
        if self.hint or self.kind == "section":
            return
        object.__setattr__(self, "hint", _default_wizard_field_hint(self.label, self.kind, self.flag))

    def with_value(self, value: str) -> WizardFormField:
        return WizardFormField(
            self.label,
            self.kind,
            self.flag,
            self.no_flag,
            value,
            self.default,
            self.options,
            self.hint,
            self.required,
            visible_when=self.visible_when,
            picker=self.picker,
        )

    def is_visible(self, driver_values: Mapping[str, str]) -> bool:
        if self.visible_when is None:
            return True
        try:
            return bool(self.visible_when(driver_values))
        except Exception:  # noqa: BLE001 - a bad predicate must never crash the form.
            return True


@dataclass(frozen=True)
class WizardGoal:
    """A goal-first entry point that sits in front of a setup wizard.

    Selecting a goal seeds ``presets`` (field overrides keyed exactly the
    way :func:`_field_value_overrides` emits them — by ``--flag`` or
    ``@Label`` for flag-less rows) and narrows the form to ``fields`` plus
    any required selectors, preset-touched rows, and the conditional groups
    those presets reveal. An empty ``fields`` *and* empty ``presets`` means
    the "Advanced — show all settings" escape hatch that reproduces today's
    full form.

    ``available_when(cfg) -> bool`` hides goals that do not apply to the
    current configuration (e.g. an Agent-LLM goal only makes sense for
    proxy-backed connectors).
    """

    id: str
    label: str
    summary: str = ""
    presets: Mapping[str, str] = dataclass_field(default_factory=dict)
    fields: tuple[str, ...] = ()
    available_when: Callable[[Any], bool] | None = dataclass_field(default=None, compare=False, repr=False)

    @property
    def is_advanced(self) -> bool:
        return not self.fields and not self.presets

    def is_available(self, cfg: object | Mapping[str, Any] | None) -> bool:
        if self.available_when is None:
            return True
        try:
            return bool(self.available_when(cfg))
        except Exception:  # noqa: BLE001 - a bad predicate must never hide the menu.
            return True


@dataclass(frozen=True)
class SetupPanelAction:
    handled: bool
    intent: SetupCommandIntent | None = None
    hint: str = ""
    open_form: bool = False
    open_diff: bool = False
    open_resource_editor: str = ""
    refresh_credentials: bool = False
    clear_restart_queue: bool = False
    open_model_picker: bool = False
    # Open the text editor modal for the focused row: "form" (wizard form
    # field) or "config" (config editor field). ``field_editor_value`` seeds
    # it (the current value plus the key that was pressed); None means the
    # current value.
    open_field_editor: str = ""
    field_editor_value: str | None = None
    # Setup navigation pickers: "detail" (readiness + task detail),
    # "sections" (grouped config sections) or "fields" (config field finder).
    open_picker: str = ""


@dataclass(frozen=True)
class SetupWizardInfo:
    wizard: SetupWizard
    name: str
    command: tuple[str, ...]
    description: str
    how_to: str
    status: str = ""

    @property
    def argv(self) -> tuple[str, ...]:
        return ("defenseclaw", *self.command)


@dataclass(frozen=True)
class SetupSectionLabel:
    index: int
    name: str
    active: bool
    summary: str
    help: str = ""
    field_count: int = 0
    editable_count: int = 0


@dataclass(frozen=True)
class SetupSectionTabHit:
    index: int
    row: int
    start: int
    end: int
    name: str


@dataclass(frozen=True)
class SetupFocusedRowAction:
    area: str
    action: str
    hotkey: str
    description: str
    intent: SetupCommandIntent | None = None


@dataclass(frozen=True)
class SetupFocusedRowMetadata:
    mode: SetupMode | str
    label: str
    value: str = ""
    kind: str = ""
    key: str = ""
    section: str = ""
    hint: str = ""
    validation: ValidationResult = ValidationResult()
    action: SetupFocusedRowAction | None = None
    restart_hint: str = ""


@dataclass(frozen=True)
class SetupSaveRestartHints:
    changes: int
    validation_errors: tuple[str, ...]
    restart_pending: bool
    restart_reason: str = ""
    save_hint: str = ""
    restart_hint: str = ""
    saved_hint: str = ""
    action_bar: tuple[str, ...] = ()
    # ``issues`` counts every validation error in the draft (untouched rows
    # included, for display); ``blocking`` counts only errors on changed
    # fields, which are the ones that stop a save.
    issues: int = 0
    blocking: int = 0
    blocking_errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToggleState:
    visible: bool = False
    current: bool = False

    def show(self, current: bool) -> ToggleState:
        return ToggleState(True, current)

    def hide(self) -> ToggleState:
        return ToggleState(False, self.current)


@dataclass(frozen=True)
class UninstallChoice:
    option: UninstallOption
    hotkey: str
    label: str
    detail: str
    danger: bool = False


UNINSTALL_CHOICES: tuple[UninstallChoice, ...] = (
    UninstallChoice("dry-run", "p", "Preview plan", "Runs uninstall --dry-run and changes nothing."),
    UninstallChoice("keep-data", "u", "Uninstall, keep data", "Reverts hooks/plugin integration and keeps data.", True),
    UninstallChoice("wipe-data", "a", "Uninstall and wipe data", "Also deletes audit DB, config, and secrets.", True),
    UninstallChoice(
        "wipe-all", "e", "Uninstall everything", "Also deletes the data and the defenseclaw binaries.", True
    ),
)


@dataclass
class UninstallModalState:
    visible: bool = False
    cursor: int = 0

    def show(self) -> None:
        self.visible = True
        self.cursor = 0

    def hide(self) -> None:
        self.visible = False

    def cursor_up(self) -> None:
        self.cursor = max(0, self.cursor - 1)

    def cursor_down(self) -> None:
        self.cursor = min(len(UNINSTALL_CHOICES) - 1, self.cursor + 1)

    def select_by_hotkey(self, hotkey: str) -> bool:
        for index, choice in enumerate(UNINSTALL_CHOICES):
            if choice.hotkey == hotkey:
                self.cursor = index
                return True
        return False

    def selected(self) -> UninstallOption:
        if self.cursor < 0 or self.cursor >= len(UNINSTALL_CHOICES):
            return "dry-run"
        return UNINSTALL_CHOICES[self.cursor].option


class SetupPanelModel:
    """Data-only Setup model. Textual widgets can bind to this without owning IO."""

    def __init__(
        self,
        cfg: object | Mapping[str, Any] | None = None,
        *,
        os_name: str | None = None,
    ) -> None:
        self.config = cfg
        self.observability_status: V8OperatorStatus | None = None
        self.observability_status_error = ""
        self.os_name = os_name
        self.mode: SetupMode = "wizards"
        self.active_wizard = SetupWizard.CONNECTOR_SETUP
        self.active_section = 0
        self.active_line = 0
        self.config_scroll = 0
        self.credential_cursor = 0
        self.credential_snapshot = CredentialSnapshot()
        self.restart_queue = RestartQueue()
        self.last_saved_at: datetime | None = None
        self.readiness_checks = build_readiness_checks(cfg, None, None, (), self.restart_queue)
        self.sections = build_setup_sections(
            cfg,
            self.os_name,
            observability_status=self.observability_status,
            observability_status_error=self.observability_status_error,
        )
        self.wizard_status: dict[SetupWizard, str] = {}
        self._wizard_run_started: dict[SetupWizard, datetime] = {}
        # A check-only run (the Sandbox wizard's doctor) puts back the status it found.
        self._status_before_check: dict[SetupWizard, str] = {}
        # The last gateway health, so a new export plan can name the failing
        # exports (GAP-2394).
        self._readiness_health: Any = None
        self.failing_exports: tuple[str, ...] = ()
        self.form_fields: list[WizardFormField] = []
        self.form_cursor = 0
        self.form_active = False
        self.form_reveal = False
        self.form_error = ""
        # Set when disk changes while the operator has an unsaved wizard form
        # or config-editor draft. The authoritative config/readiness state
        # still advances, but the draft remains intact until run/cancel/revert.
        self.disk_change_pending = False
        # Goal-first entry layer: a contextual "what do you want to do?" menu
        # that sits in front of the wizard form. ``active_goal`` is carried
        # into the form so its preset filter survives dependent rebuilds.
        self.goal_active = False
        self.goal_cursor = 0
        self.goals: tuple[WizardGoal, ...] = ()
        self.active_goal: WizardGoal | None = None
        # The open form came from the goal menu, so Esc goes back to it.
        self.form_from_goal_menu = False
        # What ``sandbox doctor --json`` found (the app runs it when the
        # Sandbox wizard opens); None until it answers.
        self.sandbox_machine: SandboxMachineCheck | None = None

    def set_config(
        self,
        cfg: object | Mapping[str, Any] | None,
        *,
        external: bool = False,
    ) -> None:
        active_name = self.sections[self.active_section].name if self.sections else ""
        active_field = self.current_field()
        active_key = active_field.key if active_field is not None else ""
        preserve_config_draft = external and self.mode == "config" and self.has_changes()
        preserve_wizard_draft = external and self.form_active
        self.config = cfg
        self.observability_status = None
        self.observability_status_error = ""
        if not preserve_config_draft:
            self.sections = build_setup_sections(cfg, self.os_name, observability_status=None)
            if active_name:
                for index, section in enumerate(self.sections):
                    if section.name == active_name:
                        self.active_section = index
                        break
            self.active_section = _clamp(self.active_section, 0, max(0, len(self.sections) - 1))
            # Keep the cursor on the field just saved rather than jumping to
            # the top of the section.
            self.active_line = self._line_for_key(active_key)
            self.config_scroll = 0
        self.disk_change_pending = preserve_config_draft or preserve_wizard_draft
        # Readiness rows depend on cfg.gateway / cfg.guardrail / cfg.audit /
        # cfg.observability, so rebuild them whenever the cached config
        # changes; otherwise we keep showing rows derived from the
        # snapshot captured at __init__ time even after `setup` runs.
        self.rebuild_readiness_checks()

    def set_observability_status(
        self,
        status: V8OperatorStatus | None,
        *,
        error: str = "",
    ) -> None:
        """Install the masked canonical v8 plan without losing config edits."""

        self.observability_status = status
        self.observability_status_error = error.strip()
        # The readiness Telemetry row names the configured exports (GAP-2351)
        # and the failing ones (GAP-2394).
        self.failing_exports = failing_exports(status, self._readiness_health)
        detail = telemetry_readiness_detail(status, self.failing_exports)
        state = "warn" if self.failing_exports else "pass"
        self.readiness_checks = tuple(
            replace(check, detail=detail, status=state) if check.title == "Telemetry" else check
            for check in self.readiness_checks
        )
        active_name = self.sections[self.active_section].name if self.sections else ""
        rebuilt = build_setup_sections(
            self.config,
            self.os_name,
            observability_status=status,
            observability_status_error=self.observability_status_error,
        )
        existing = {section.name: section for section in self.sections}
        self.sections = tuple(
            section if section.name == "Observability" else existing.get(section.name, section) for section in rebuilt
        )
        if active_name:
            self.active_section = next(
                (index for index, section in enumerate(self.sections) if section.name == active_name),
                self.active_section,
            )
        self.active_section = _clamp(self.active_section, 0, max(0, len(self.sections) - 1))
        current = self.current_section()
        self.active_line = _clamp(self.active_line, 0, max(0, len(current.fields) - 1) if current else 0)

    def rebuild_readiness_checks(
        self,
        *,
        health: Any = None,
        doctor: Any = None,
        credentials: tuple[Any, ...] | None = None,
        gateway_status: Any = None,
    ) -> None:
        """Re-evaluate Setup readiness rows from the current inputs.

        Mirrors Go's ``syncSetupDerivedState`` (``internal/tui/app.go::529-532``):
        whenever cfg / health / doctor / credentials change, the Setup
        panel rebuilds its readiness rows so e.g. "Gateway health
        endpoint is offline" flips to "OK" the instant the /health
        poll succeeds.
        """

        rows = credentials
        if rows is None:
            snapshot = self.credential_snapshot
            rows = tuple(getattr(snapshot, "rows", ()) or ())
        self._readiness_health = health
        self.failing_exports = failing_exports(self.observability_status, health)
        self.readiness_checks = build_readiness_checks(
            self.config,
            health,
            doctor,
            rows,
            self.restart_queue,
            gateway_status,
            observability=self.observability_status,
        )

    def wizard_infos(self, *, now: datetime | None = None) -> tuple[SetupWizardInfo, ...]:
        return tuple(
            SetupWizardInfo(
                wizard=wizard,
                name=WIZARD_NAMES[int(wizard)],
                command=WIZARD_COMMANDS[wizard],
                description=WIZARD_DESCRIPTIONS[int(wizard)],
                how_to=WIZARD_HOW_TO[int(wizard)],
                status=(
                    "unsupported"
                    if not self.wizard_available(wizard)
                    else self._formatted_wizard_status(wizard, now=now)
                ),
            )
            for wizard in SetupWizard
        )

    def any_wizard_running(self) -> bool:
        """True while at least one wizard row should show elapsed time.

        Used by the app shell to decide whether to re-render the Setup
        panel inside the per-tick animator so the ``running 12s...``
        badge counts up live during the gateway-verify wait.
        """

        return bool(self._wizard_run_started)

    def _formatted_wizard_status(self, wizard: SetupWizard, *, now: datetime | None = None) -> str:
        """Return the user-facing status badge for a wizard row.

        The raw ``wizard_status`` value is a state machine string
        (``"running..."``, ``"done"``, ``"failed"``). The renderer
        decorates the running state with elapsed seconds so a long
        ``defenseclaw setup`` run with ``--verify`` (which can sit in
        a 30s gateway probe) looks like ``running 17s...`` instead
        of a frozen ``running...`` that operators reasonably mistake
        for a hung process.
        """

        raw = self.wizard_status.get(wizard, "")
        if raw != "running...":
            return raw
        started = self._wizard_run_started.get(wizard)
        if started is None:
            return raw
        now = now or datetime.now(timezone.utc)
        elapsed = max(int((now - started).total_seconds()), 0)
        return f"running {elapsed}s..."

    def active_wizard_info(self, *, now: datetime | None = None) -> SetupWizardInfo:
        wizard = self.active_wizard
        return SetupWizardInfo(
            wizard=wizard,
            name=WIZARD_NAMES[int(wizard)],
            command=WIZARD_COMMANDS[wizard],
            description=WIZARD_DESCRIPTIONS[int(wizard)],
            how_to=WIZARD_HOW_TO[int(wizard)],
            status=(
                "unsupported" if not self.wizard_available(wizard) else self._formatted_wizard_status(wizard, now=now)
            ),
        )

    def wizard_available(self, wizard: SetupWizard | int) -> bool:
        wizard = SetupWizard(wizard)
        if wizard == SetupWizard.SANDBOX:
            return openshell_sandboxes_supported(self.os_name)
        return not (wizard == SetupWizard.LOCAL_OBSERVABILITY and not local_observability_stack_supported(self.os_name))

    def wizard_unavailable_reason(self, wizard: SetupWizard | int) -> str:
        if self.wizard_available(wizard):
            return ""
        if SetupWizard(wizard) == SetupWizard.SANDBOX:
            return SANDBOX_WIZARD_UNSUPPORTED_REASON
        return LOCAL_OBSERVABILITY_UNSUPPORTED_REASON

    def section_labels(self) -> tuple[SetupSectionLabel, ...]:
        return tuple(
            SetupSectionLabel(
                index=index,
                name=section.name,
                active=index == self.active_section,
                summary=section.summary,
                help=section.help,
                field_count=len(section.fields),
                editable_count=sum(1 for field in section.fields if field.interactive),
            )
            for index, section in enumerate(self.sections)
        )

    def section_tab_rows(self, width: int = 80) -> tuple[tuple[SetupSectionTabHit, ...], ...]:
        """Return wrapped config-section tab hit boxes, matching the Go row packing."""

        if not self.sections:
            return ()
        max_width = max(width, 20)
        rows: list[tuple[SetupSectionTabHit, ...]] = []
        row: list[SetupSectionTabHit] = []
        cursor = 0
        row_index = 0
        for index, section in enumerate(self.sections):
            tab_width = len(section.name) + 2
            separator = 1 if row else 0
            if row and cursor + separator + tab_width > max_width:
                rows.append(tuple(row))
                row = []
                cursor = 0
                row_index += 1
                separator = 0
            start = cursor + separator
            row.append(SetupSectionTabHit(index, row_index, start, start + tab_width, section.name))
            cursor = start + tab_width
        if row:
            rows.append(tuple(row))
        return tuple(rows)

    def section_tab_hit(self, x: int, y: int, *, width: int = 80, start_y: int = 2) -> int | None:
        row_index = y - start_y
        rows = self.section_tab_rows(width)
        if row_index < 0 or row_index >= len(rows):
            return None
        for hit in rows[row_index]:
            if hit.start <= x < hit.end:
                return hit.index
        return None

    def select_section(self, index: int) -> bool:
        if not 0 <= index < len(self.sections):
            return False
        changed = index != self.active_section
        self.active_section = index
        self.active_line = self.first_editable_line()
        self.config_scroll = 0
        return changed

    def move_section(self, delta: int) -> bool:
        if not self.sections or delta == 0:
            return False
        next_index = _clamp(self.active_section + delta, 0, len(self.sections) - 1)
        return self.select_section(next_index)

    def current_section(self) -> ConfigSection | None:
        if not 0 <= self.active_section < len(self.sections):
            return None
        return self.sections[self.active_section]

    def current_field(self) -> ConfigField | None:
        section = self.current_section()
        if section is None or not 0 <= self.active_line < len(section.fields):
            return None
        return section.fields[self.active_line]

    def set_credential_snapshot(
        self,
        rows: Sequence[CredentialRow],
        *,
        loaded_at: Any = None,
        error: Exception | str | None = None,
    ) -> None:
        self.credential_snapshot = CredentialSnapshot(
            rows=tuple(rows),
            loaded_at=loaded_at,
            error=str(error) if error else "",
        )
        self.credential_cursor = _clamp(self.credential_cursor, 0, max(0, len(rows) - 1))

    def selected_credential(self) -> CredentialRow | None:
        rows = self.credential_snapshot.rows
        if 0 <= self.credential_cursor < len(rows):
            return rows[self.credential_cursor]
        return None

    def credential_action(self, action: str) -> SetupPanelAction:
        if action == "s":
            # Open the "set" goal: the header named the whole wizard ("See
            # which API keys are missing and set them.") and Action still
            # cycled through list/check/remove (GAP-2256).
            goal = next((g for g in wizard_goals(SetupWizard.CREDENTIALS, self.config) if g.id == "set"), None)
            self.open_wizard_form(SetupWizard.CREDENTIALS, goal=goal)
            for index, field in enumerate(self.form_fields):
                if field.label == "Action":
                    self.form_fields[index] = field.with_value("set")
                if field.label == "Env Name" and self.selected_credential() is not None:
                    self.form_fields[index] = field.with_value(self.selected_credential().env_name)
            return SetupPanelAction(True, open_form=True)
        if action == "f":
            return SetupPanelAction(
                True,
                SetupCommandIntent(
                    "keys fill-missing",
                    ("keys", "fill-missing", "--yes"),
                ),
            )
        if action == "c":
            return SetupPanelAction(True, SetupCommandIntent("keys check", ("keys", "check")))
        if action == "r":
            return SetupPanelAction(True, refresh_credentials=True)
        return SetupPanelAction(False)

    def credential_empty_state(self) -> str:
        if self.credential_snapshot.error:
            return "keys list --json failed: " + self.credential_snapshot.error
        if not self.credential_snapshot.rows:
            return "No credential snapshot loaded. Next: press r to refresh or c to run keys check."
        return ""

    def set_restart_queue(self, queue: RestartQueue) -> None:
        self.restart_queue = queue

    def queue_restart(self, reason: str, *, last_started_at: str = "") -> None:
        self.restart_queue = self.restart_queue.with_reason(reason, last_started_at=last_started_at)

    def clear_restart_queue(self) -> None:
        self.restart_queue = RestartQueue()

    def restart_now_intent(self) -> SetupCommandIntent | None:
        if not self.restart_queue.pending:
            return None
        return SetupCommandIntent(
            label="restart",
            args=("restart",),
            binary="defenseclaw-gateway",
            category="daemon",
            origin="restart-queue",
        )

    def mark_restart_started(self, started_at: str) -> bool:
        if self.restart_queue.should_clear_for_started_at(started_at):
            self.clear_restart_queue()
            return True
        return False

    def config_diff(self) -> tuple[ConfigDiffEntry, ...]:
        return config_diff(self.sections)

    def validation_errors(self) -> tuple[str, ...]:
        return validation_errors(self.sections)

    def blocking_validation_errors(self) -> tuple[str, ...]:
        return blocking_validation_errors(self.sections)

    def has_changes(self) -> bool:
        return bool(self.config_diff())

    def review_save_action(self) -> SetupPanelAction:
        errors = self.blocking_validation_errors()
        if errors:
            return SetupPanelAction(True, hint="Fix config validation: " + errors[0])
        changes = len(self.config_diff())
        if changes == 0:
            return SetupPanelAction(True, hint="No config changes to save.")
        plural = "" if changes == 1 else "s"
        return SetupPanelAction(True, hint=f"Review {changes} config change{plural} before saving.", open_diff=True)

    def mark_saved(self, saved_at: datetime | None = None) -> None:
        self.last_saved_at = saved_at or datetime.now(timezone.utc)

    def save_restart_hints(self) -> SetupSaveRestartHints:
        errors = self.validation_errors()
        blocking = self.blocking_validation_errors()
        changes = len(self.config_diff())
        field = self.current_field()
        save_hint = "No config changes to save."
        if blocking:
            save_hint = "Fix config validation before saving: " + blocking[0]
        elif changes:
            save_hint = "Review and save applies changed fields, then queues a gateway restart when needed."
        restart_hint = ""
        actions = ["[`] Wizards", "[Arrows] Navigate", "[Enter/Click] Edit/Toggle"]
        if changes:
            actions.extend(("[S] Review & Save", "\\[r] Revert"))
        if self.restart_queue.pending:
            restart_hint = "Restart pending: " + self.restart_queue.reason + "  [G] restart now  [C] clear"
            actions.extend(("[G] Restart Now", "[C] Clear Restart"))
        elif field is not None and field.interactive:
            restart_hint = "Restart: queued on save when runtime settings change"
        saved_hint = ""
        if self.last_saved_at is not None:
            # "Saved 12:08 UTC", not a microsecond ISO stamp (GAP-1554).
            saved_hint = "Saved " + self.last_saved_at.astimezone(timezone.utc).strftime("%H:%M UTC")
            actions.append(saved_hint)
        return SetupSaveRestartHints(
            changes=changes,
            validation_errors=errors,
            restart_pending=self.restart_queue.pending,
            restart_reason=self.restart_queue.reason,
            save_hint=save_hint,
            restart_hint=restart_hint,
            saved_hint=saved_hint,
            action_bar=tuple(actions),
            issues=len(errors),
            blocking=len(blocking),
            blocking_errors=blocking,
        )

    def focused_row_action(self) -> SetupFocusedRowAction:
        if self.form_active:
            if not self.form_fields:
                return SetupFocusedRowAction("form", "close", "Esc", "Close the empty setup form.")
            cursor = _clamp(self.form_cursor, 0, len(self.form_fields) - 1)
            field = self.form_fields[cursor]
            if field.kind == "section":
                return SetupFocusedRowAction("form", "skip", "Down", "Section divider; move to a field.")
            if field.kind == "bool":
                return SetupFocusedRowAction("form", "toggle", "Enter/Space", "Toggle this setup option.")
            if field.options:
                return SetupFocusedRowAction("form", "cycle", "Left/Right", "Cycle through available choices.")
            return SetupFocusedRowAction("form", "edit", "Enter", "Edit this setup value.")
        if self.mode == "config":
            field = self.current_field()
            section = self.current_section()
            if field is None:
                return SetupFocusedRowAction("config", "none", "", "No config row is focused.")
            if section is not None and section.name == "Observability":
                return SetupFocusedRowAction(
                    "config",
                    "open_observability_editor",
                    "E",
                    "Open the destination editor.",
                )
            if section is not None and section.name == "Webhooks":
                return SetupFocusedRowAction(
                    "config",
                    "open_webhooks_editor",
                    "E",
                    "Open the interactive Webhooks editor for list entries.",
                )
            if not field.interactive:
                return SetupFocusedRowAction("config", "read_only", "", field.hint or "This config row is read-only.")
            if field.kind == "bool":
                return SetupFocusedRowAction("config", "toggle", "Enter/Space", "Toggle true or false.")
            if field.kind == "choice":
                return SetupFocusedRowAction("config", "cycle", "Enter/Space", "Cycle through allowed choices.")
            return SetupFocusedRowAction("config", "edit", "Enter", "Edit this config value.")
        info = self.active_wizard_info()
        return SetupFocusedRowAction(
            "wizard",
            "open_form",
            "Enter",
            info.description,
            SetupCommandIntent(
                label="setup " + info.name,
                args=info.command,
                category="setup",
                origin="setup-wizard-row",
            ),
        )

    def focused_row_metadata(self) -> SetupFocusedRowMetadata:
        action = self.focused_row_action()
        if self.form_active:
            if not self.form_fields:
                return SetupFocusedRowMetadata("wizards", "(empty form)", action=action)
            cursor = _clamp(self.form_cursor, 0, len(self.form_fields) - 1)
            field = self.form_fields[cursor]
            return SetupFocusedRowMetadata(
                "wizards",
                field.label,
                value=render_wizard_value(field, reveal=self.form_reveal),
                kind=str(field.kind),
                hint=field.hint,
                action=action,
            )
        if self.mode == "config":
            field = self.current_field()
            section = self.current_section()
            if field is None:
                return SetupFocusedRowMetadata("config", "(no field)", action=action)
            validation = validate_config_field(field)
            hints = self.save_restart_hints()
            return SetupFocusedRowMetadata(
                "config",
                field.label,
                value=field.value,
                kind=str(field.kind),
                key=field.key,
                section=section.name if section else "",
                hint=field.hint or (section.help if section else ""),
                validation=validation,
                action=action,
                restart_hint=hints.restart_hint,
            )
        info = self.active_wizard_info()
        return SetupFocusedRowMetadata(
            "wizards",
            info.name,
            value=info.status,
            kind="wizard",
            hint=info.how_to,
            action=action,
        )

    def apply_changes_to_config(self) -> None:
        if self.config is None:
            raise RuntimeError("setup: no config loaded")
        for section in self.sections:
            for field in section.fields:
                if field.value != field.original:
                    apply_config_field(self.config, field.key, field.value)
        if self.disk_change_pending:
            # The draft was based on an older disk generation. Changed fields
            # were just merged into the latest authoritative object; rebuild
            # so externally changed, untouched fields are visible too.
            self.sections = build_setup_sections(self.config, self.os_name)
            self.disk_change_pending = False
        else:
            self.sections = tuple(
                ConfigSection(
                    section.name,
                    tuple(_field_with_original(field, field.value) for field in section.fields),
                    section.summary,
                    section.help,
                )
                for section in self.sections
            )

    def _line_for_key(self, key: str) -> int:
        section = self.current_section()
        if key and section is not None:
            for index, field in enumerate(section.fields):
                if field.kind != "header" and field.key == key:
                    return index
        return self.first_editable_line()

    def first_editable_line(self) -> int:
        if not self.sections:
            return 0
        for index, field in enumerate(self.sections[self.active_section].fields):
            if field.kind != "header":
                return index
        return 0

    def move_active_line(self, delta: int) -> bool:
        section = self.current_section()
        if section is None or delta == 0:
            return False
        step = 1 if delta > 0 else -1
        target = self.active_line
        for _ in range(abs(delta)):
            target += step
            while 0 <= target < len(section.fields) and section.fields[target].kind == "header":
                target += step
            target = _clamp(target, 0, max(0, len(section.fields) - 1))
        if target == self.active_line:
            return False
        self.active_line = target
        if self.active_line < self.config_scroll:
            self.config_scroll = self.active_line
        return True

    def cycle_current_field(self, delta: int = 1) -> bool:
        field = self.current_field()
        section = self.current_section()
        if field is None or section is None or not field.interactive:
            return False
        next_value = field.value
        if field.kind == "bool":
            next_value = "false" if field.value == "true" else "true"
        elif field.kind == "choice" and field.options:
            try:
                index = field.options.index(field.value)
            except ValueError:
                index = 0
            next_value = field.options[(index + delta) % len(field.options)]
        else:
            return False
        self._replace_current_field(field.with_value(next_value))
        return True

    def set_current_field_value(self, value: str) -> bool:
        field = self.current_field()
        if field is None or not field.interactive:
            return False
        self._replace_current_field(field.with_value(value))
        return True

    def _replace_current_field(self, field: ConfigField) -> None:
        section = self.current_section()
        if section is None:
            return
        fields = section.fields[: self.active_line] + (field,) + section.fields[self.active_line + 1 :]
        self.sections = (
            self.sections[: self.active_section]
            + (ConfigSection(section.name, fields, section.summary, section.help),)
            + self.sections[self.active_section + 1 :]
        )

    def open_goal_menu(self, wizard: SetupWizard | int | None = None) -> bool:
        """Open the contextual goal menu for ``wizard``.

        Returns ``True`` when a menu was opened. When the wizard exposes only
        the always-present Advanced goal there is nothing to choose, so this
        opens the full form directly and returns ``False`` (no regression for
        wizards without a goal set).
        """

        if wizard is not None:
            self.active_wizard = SetupWizard(wizard)
        if not self.wizard_available(self.active_wizard):
            self.form_active = False
            self.goal_active = False
            self.form_error = self.wizard_unavailable_reason(self.active_wizard)
            return False
        self.goals = wizard_goals(self.active_wizard, self.config)
        if len(self.goals) <= 1:
            self.open_wizard_form(self.active_wizard, goal=self.goals[0] if self.goals else None)
            return False
        self.goal_active = True
        self.goal_cursor = 0
        self.form_active = False
        self.active_goal = None
        return True

    def move_goal_cursor(self, delta: int) -> None:
        if not self.goals:
            self.goal_cursor = 0
            return
        self.goal_cursor = _clamp(self.goal_cursor + delta, 0, len(self.goals) - 1)

    def select_active_goal(self) -> None:
        """Open the wizard form for the goal under the cursor."""

        if not self.goals:
            self.open_wizard_form(self.active_wizard)
            return
        goal = self.goals[_clamp(self.goal_cursor, 0, len(self.goals) - 1)]
        self.open_wizard_form(self.active_wizard, goal=goal)
        self.form_from_goal_menu = True

    def back_to_goal_menu(self) -> bool:
        """Close a form opened from the goal menu and show that menu again.

        Esc in "Add or configure a connector" went back to the Setup task
        list, so the next Enter opened another task (GAP-2091). Returns
        ``False`` when the form was not opened from the goal menu.
        """

        if not (self.form_active and self.form_from_goal_menu and self.goals):
            return False
        goals, cursor = self.goals, self.goal_cursor
        self.close_wizard_form()
        self.goals, self.goal_cursor, self.goal_active = goals, cursor, True
        return True

    def open_wizard_form(
        self,
        wizard: SetupWizard | int | None = None,
        *,
        goal: WizardGoal | None = None,
    ) -> None:
        if wizard is not None:
            self.active_wizard = SetupWizard(wizard)
        self.form_from_goal_menu = False
        # Advanced goals carry no presets/filter, so treat them like "no goal".
        self.active_goal = goal if (goal is not None and not goal.is_advanced) else None
        presets = dict(self.active_goal.presets) if self.active_goal else {}
        base = list(wizard_form_defs(self.active_wizard, self.config))
        if presets:
            seeded = _seed_parametrized_fields(self.active_wizard, presets, self.config)
            if seeded is not None:
                base = list(seeded)
            rebuild = _DEPENDENT_FIELD_REBUILDERS.get(self.active_wizard)
            if rebuild is not None:
                merged = _field_value_overrides(base)
                merged.update(presets)
                base = list(rebuild(merged, self.config))
            else:
                base = list(_overlay_field_overrides(base, presets))
        if self.active_wizard == SetupWizard.SANDBOX:
            # Built with the machine check, when there is one.
            base = list(self._sandbox_form_fields(presets))
        if self.active_goal is not None:
            base = list(_filter_fields_for_goal(base, self.active_goal))
            base = list(_narrow_goal_connectors(base, self.active_goal, self.config, opening=True))
            base = list(_narrow_manage_goal_fields(base, self.active_wizard, self.active_goal))
            if self.active_wizard == SetupWizard.CREDENTIALS and self.active_goal.id == "remove":
                base = [_stored_key_picker(field, self.config) if field.label == "Env Name" else field for field in base]
            if self.active_wizard == SetupWizard.CREDENTIALS and self.active_goal.id == "set":
                base = [
                    replace(field, hint=_SECRET_VALUE_SET_HINT) if field.label == "Secret Value" else field
                    for field in base
                ]
        self.form_fields = base
        self.form_active = True
        self.goal_active = False
        self.form_reveal = False
        self.form_error = ""
        self.disk_change_pending = False
        self._place_form_cursor()

    def _place_form_cursor(self) -> None:
        """Put the form cursor on the first editable (non-section) row."""

        self.form_cursor = 0
        for offset, field in enumerate(self.form_fields):
            if field.kind != "section":
                self.form_cursor = offset
                return

    def close_wizard_form(self) -> None:
        if self.active_wizard == SetupWizard.SANDBOX:
            # Setup, or the operator, may change the machine before the
            # wizard opens again: check it again then.
            self.sandbox_machine = None
        self.form_fields = []
        self.form_cursor = 0
        self.form_active = False
        self.form_reveal = False
        self.form_error = ""
        self.goal_active = False
        self.goal_cursor = 0
        self.goals = ()
        self.active_goal = None
        self.form_from_goal_menu = False
        self.disk_change_pending = False

    def recompute_dependent_fields(self) -> None:
        """Rebuild the active form when a driver field (provider/role/action)
        changed, re-deriving conditional groups and dynamic option lists
        while preserving every value the operator already entered.

        Called from the app's single field-write chokepoint after a driver
        row changes. No-op for wizards without dependent fields. When a goal
        is active its field filter is re-applied so the narrowed subset (and
        its seeded presets) survives the rebuild.
        """

        rebuild = _DEPENDENT_FIELD_REBUILDERS.get(self.active_wizard)
        if rebuild is None:
            return
        overrides = _field_value_overrides(self.form_fields)
        if self.active_wizard == SetupWizard.REDACTION:
            # Action/route-action changes rebuild this dynamic form. Never
            # carry a prior live-write choice into the newly selected policy
            # operation; the operator must opt out of dry-run again.
            overrides["--dry-run"] = "yes"
            overrides["--restart"] = "no"
        if self.active_wizard == SetupWizard.GUARDRAIL:
            scope = wizard_field_value(self.form_fields, "Scope")
            disable_label = next(
                (field.label for field in self.form_fields if field.flag == "--disable"),
                "",
            )
            scope_changed = (scope == _GUARDRAIL_SCOPE_GLOBAL and disable_label == "Disable Selected Connector") or (
                scope == _GUARDRAIL_SCOPE_CONNECTOR and disable_label == "Disable Guardrail Globally"
            )
            if scope_changed:
                # The connector and global toggles intentionally share the
                # CLI flag, but their values must not cross a scope rebuild.
                overrides.pop("--disable", None)
        if self.active_wizard in {SetupWizard.CONNECTOR_SETUP, SetupWizard.GUARDRAIL}:
            connector_field = next(
                (field for field in self.form_fields if field.flag == "--connector" or field.label == "Connector"),
                None,
            )
            if connector_field is not None and connector_field.value != connector_field.default:
                # Connector-scoped rows must be re-seeded from the newly
                # selected peer. Carrying these values across a connector
                # change can display (and then write) another peer's policy.
                connector_scoped_flags = (
                    ("@Guardrail Mode",)
                    if self.active_wizard == SetupWizard.CONNECTOR_SETUP
                    else (
                        "--mode",
                        "--rule-pack",
                        "--block-message",
                        "--human-approval",
                        "--hilt-min-severity",
                    )
                )
                for flag in connector_scoped_flags:
                    overrides.pop(flag, None)
        # Re-seed any preset the goal filter may have hidden so it persists
        # across the rebuild even when its row is not currently visible.
        if self.active_goal is not None:
            for key, value in self.active_goal.presets.items():
                overrides.setdefault(key, value)
        if self.active_wizard == SetupWizard.SANDBOX:
            fields = list(self._sandbox_form_fields(overrides))
        else:
            fields = list(rebuild(overrides, self.config))
        if self.active_goal is not None:
            fields = list(_filter_fields_for_goal(fields, self.active_goal))
            fields = list(_narrow_goal_connectors(fields, self.active_goal, self.config))
            fields = list(_narrow_manage_goal_fields(fields, self.active_wizard, self.active_goal))
        self.form_fields = fields
        if self.form_fields:
            self.form_cursor = _clamp(self.form_cursor, 0, len(self.form_fields) - 1)
            # Keep the cursor off a freshly-revealed section divider.
            if self.form_fields[self.form_cursor].kind == "section":
                for offset, field in enumerate(self.form_fields[self.form_cursor :], start=self.form_cursor):
                    if field.kind != "section":
                        self.form_cursor = offset
                        break
        else:
            self.form_cursor = 0

    def _sandbox_form_fields(self, overrides: Mapping[str, str]) -> tuple[WizardFormField, ...]:
        return _apply_dynamic_fields(
            sandbox_wizard_fields(self.config, machine=self.sandbox_machine, os_name=self.os_name),
            overrides,
            {"action": (overrides.get("@Action") or "setup").strip() or "setup"},
        )

    def sandbox_machine_wanted(self) -> bool:
        """Whether the open Sandbox wizard is waiting for the machine check."""
        return self.form_active and self.active_wizard == SetupWizard.SANDBOX and self.sandbox_machine is None

    def apply_sandbox_machine_check(self, check: SandboxMachineCheck) -> None:
        """Take the machine check and refresh an open Sandbox form.

        Install OpenShell follows the check unless the operator already
        changed it; every other answer stays as entered.
        """
        before = next((f for f in self.form_fields if f.flag == "--install-openshell"), None)
        self.sandbox_machine = check
        if not (self.form_active and self.active_wizard == SetupWizard.SANDBOX):
            return
        overrides = _field_value_overrides(self.form_fields)
        if before is not None and before.value == before.default:
            overrides.pop("--install-openshell", None)
        self.form_fields = list(self._sandbox_form_fields(overrides))
        if self.form_fields:
            self.form_cursor = _clamp(self.form_cursor, 0, len(self.form_fields) - 1)

    def toggle_form_reveal(self) -> bool:
        if not any(field.kind == "password" for field in self.form_fields):
            return False
        self.form_reveal = not self.form_reveal
        return True

    def missing_required_fields(self) -> tuple[str, ...]:
        return missing_required_fields(self.active_wizard, self.form_fields)

    def current_form_error(self) -> str:
        """``form_error``, minus a "Missing required field(s)" the user has since filled.

        The message stayed on screen after Env Name was filled, until Run
        (GAP-1395)."""

        if self.form_error.startswith(_MISSING_FIELDS_PREFIX):
            missing = self.missing_required_fields()
            if not missing:
                self.form_error = ""
            else:
                self.form_error = _MISSING_FIELDS_PREFIX + ", ".join(missing)
        return self.form_error

    def wizard_command_preview(self) -> str:
        """Return the shell command the wizard will execute with current values.

        Used in the wizard form header so operators see exactly what
        ``defenseclaw …`` will run before they hit Ctrl+R — matching
        the transparency of the interactive ``defenseclaw setup``
        prompt where the chosen flags are echoed back.
        """

        if not self.form_active or not self.form_fields:
            command = WIZARD_COMMANDS.get(self.active_wizard, ())
            return "defenseclaw " + " ".join(command) if command else "defenseclaw"
        try:
            args = build_wizard_args(self.active_wizard, self.form_fields, self.config)
        except Exception:  # noqa: BLE001
            command = WIZARD_COMMANDS.get(self.active_wizard, ())
            return "defenseclaw " + " ".join(command) if command else "defenseclaw"
        from defenseclaw.tui.command_line import display_argv  # the CLI tree; keep it off the model import

        args, secret_env = wizard_secrets_to_env(args)
        masked = mask_wizard_secret_values(self.form_fields, args)
        # The run passes these in the environment (GAP-1888); show them the
        # way a shell would, values hidden.
        env_prefix = "".join(f"{name}=<redacted> " for name, _value in secret_env)
        return env_prefix + ("defenseclaw " + display_argv(masked) if masked else "defenseclaw")

    def mark_wizard_complete(self, args: Sequence[str], *, success: bool = True, cancelled: bool = False) -> None:
        """Clear the per-wizard "running..." badge after a setup run.

        ``cancelled`` (the preview or the run was cancelled) puts back the
        status the row had before, rather than "failed".

        Maps the executed argv back to the matching wizard so the Setup
        panel reflects the real state instead of a permanently-spinning
        row. We match by the longest argv prefix so subcommands like
        ``setup observability add`` find the OBSERVABILITY wizard even
        when extra flags follow.
        """

        best: SetupWizard | None = None
        best_len = 0
        connector_mode_prefixes = (("setup", "codex"), ("setup", "claude-code"))
        if (
            any(tuple(args[: len(prefix)]) == prefix for prefix in connector_mode_prefixes)
            and self.wizard_status.get(SetupWizard.GUARDRAIL) == "running..."
        ):
            # The focused Guardrail mode workflow deliberately executes an
            # existing connector-specific setup command. Prefer the wizard
            # that actually started the run over CONNECTOR_SETUP's generic
            # one-token ``setup`` prefix.
            best = SetupWizard.GUARDRAIL
            best_len = 2
        for wizard, command in WIZARD_COMMANDS.items():
            if len(command) > len(args):
                continue
            if tuple(args[: len(command)]) != command:
                continue
            if len(command) > best_len:
                best = wizard
                best_len = len(command)
        if (
            best is None
            and tuple(args[:2]) == ("sandbox", "doctor")
            and self.wizard_status.get(SetupWizard.SANDBOX) == "running..."
        ):
            # The Sandbox wizard's doctor action; other sandbox commands
            # (enable, disable, ...) never mark the wizard.
            best = SetupWizard.SANDBOX
        # A wizard with several actions runs sibling commands its
        # WIZARD_COMMANDS prefix doesn't cover (Guardrail actions runs
        # guardrail block-message / hilt / fail-mode, AI discovery runs
        # disable, Splunk dashboards runs destroy): the one running wizard
        # whose action family matches more of the argv than any prefix did
        # finishes, or its row spins forever.
        running = [
            (wizard, len(family))
            for wizard, status in self.wizard_status.items()
            if status == "running..."
            and (family := _wizard_action_family(wizard))
            and tuple(args[: len(family)]) == family
        ]
        if len(running) == 1 and running[0][1] > best_len:
            best = running[0][0]
        if best is None:
            return
        if cancelled:
            if self.wizard_status.get(best) != "running...":
                # Nothing of this task was running (a palette command was
                # cancelled): keep the row as it is.
                return
            before = self._status_before_check.pop(best, "")
            if before and before != "running...":
                self.wizard_status[best] = before
            else:
                self.wizard_status.pop(best, None)
            self._wizard_run_started.pop(best, None)
            return
        if best in self._status_before_check and tuple(args[:2]) == ("sandbox", "doctor"):
            # Only a check: the wizard's setup status stays what it was.
            before = self._status_before_check.pop(best)
            if not success:
                self.wizard_status[best] = "check failed"
            elif before and before != "running...":
                self.wizard_status[best] = before
            else:
                self.wizard_status[best] = "checked"
            self._wizard_run_started.pop(best, None)
            return
        self._status_before_check.pop(best, None)
        self.wizard_status[best] = "done" if success else "failed"
        self._wizard_run_started.pop(best, None)

    def submit_wizard_form(self) -> SetupPanelAction:
        missing = self.missing_required_fields()
        if missing:
            self.form_error = _MISSING_FIELDS_PREFIX + ", ".join(missing)
            return SetupPanelAction(True)
        if self.active_wizard == SetupWizard.CREDENTIALS and wizard_field_value(self.form_fields, "Action") == "set":
            env_name = wizard_field_value(self.form_fields, "Env Name")
            if looks_like_secret_value(env_name):
                self.form_error = "Env Name looks like a secret value. Use an env var name such as DEFENSECLAW_LLM_KEY."
                return SetupPanelAction(True)
        if self.active_wizard in {SetupWizard.GUARDRAIL, SetupWizard.GUARDRAIL_ACTIONS}:
            if error := _guardrail_connector_selection_error(self.config, self.form_fields):
                self.form_error = error
                return SetupPanelAction(True)
        # Notifications routing fans out one CLI call per *changed*
        # slot. With no changes there is nothing to apply; emitting the
        # bare ``setup notifications-set`` prefix here would run a
        # malformed CLI invocation (missing the slot positional arg)
        # that Click would reject. Bail with a friendly hint instead.
        if self.active_wizard == SetupWizard.NOTIFICATIONS_ROUTING:
            if not notifications_routing_intents(self.form_fields):
                self.form_error = (
                    "No toggles changed — flip at least one notification "
                    "slot before submitting, or press Escape to cancel."
                )
                return SetupPanelAction(True)
        args = build_wizard_args(self.active_wizard, self.form_fields, self.config)
        # Secret flag values go to the child's environment, not its argv,
        # which every local account can read with ps (GAP-1888).
        args, secret_env = wizard_secrets_to_env(args)
        name = WIZARD_NAMES[int(self.active_wizard)]
        if self.active_wizard == SetupWizard.OBSERVABILITY:
            # Named after the Setup task and the chosen destination: a Datadog
            # run said "setup Observability / Galileo failed" (GAP-1891), and
            # Setup has no "Observability" task (GAP-2351).
            preset = wizard_field_value(self.form_fields, "Preset")
            name = "Export telemetry" + (f" / {observability_preset_label(preset)}" if preset else "")
        if self.active_wizard == SetupWizard.NOTIFICATIONS_ROUTING:
            # "setup Notifications Routing" for the task "What notifies you"
            # (GAP-2386).
            name = "What notifies you"
        if self.active_wizard == SetupWizard.CONNECTOR_SETUP and len(args) > 1 and not args[1].startswith("-"):
            # "setup claude-code", not "setup Connector Setup" (GAP-1709).
            name = args[1]
        if self.active_wizard == SetupWizard.GUARDRAIL:
            connector = wizard_field_value(self.form_fields, "Connector")
            if connector:
                name += f" ({connector})"
        keys_run = self.active_wizard == SetupWizard.CREDENTIALS and len(args) > 1
        # Credentials "set" feeds the secret over stdin (hidden prompt) so
        # it never lands in the child's argv. See F-0801.
        secret_stdin: str | None = None
        if self.active_wizard == SetupWizard.CREDENTIALS and wizard_field_value(self.form_fields, "Action") == "set":
            secret_value = wizard_field_value(self.form_fields, "Secret Value", raw=True)
            if secret_value:
                secret_stdin = secret_value + "\n"
        follow_up: tuple[SetupCommandIntent, ...] = ()
        if self.active_wizard == SetupWizard.REGISTRIES:
            follow_up = registry_wizard_follow_up_intents(self.form_fields)
        elif self.active_wizard == SetupWizard.SPLUNK:
            follow_up = splunk_wizard_follow_up_intents(self.form_fields)
        elif self.active_wizard == SetupWizard.NOTIFICATIONS_ROUTING:
            # The first changed slot is the primary intent; remaining
            # slots run as follow_ups in order. The "no changes" path
            # is already short-circuited above.
            follow_up = notifications_routing_intents(self.form_fields)[1:]
        redaction_action = wizard_field_value(self.form_fields, "Action") or "status"
        risk: SetupPreviewRisk = (
            "setup"
            if self.active_wizard == SetupWizard.REDACTION and redaction_action == "interactive"
            else "read-only"
        )
        # Sandbox setup may call sudo (the OpenShell installer) and builds
        # images for minutes: it runs in the real terminal (App.suspend).
        terminal = self.active_wizard == SetupWizard.SANDBOX and tuple(args[:2]) == ("sandbox", "setup")
        if terminal:
            risk = "setup"
        # The Sandbox wizard's doctor action only reads this machine: its
        # toast says doctor, and it leaves the wizard's status as it was.
        doctor = tuple(args[:2]) == ("sandbox", "doctor")
        category = "info" if doctor else "setup"
        # "keys remove", not "setup Credentials" (GAP-2061).
        label = "sandbox doctor" if doctor else (" ".join(args[:2]) if keys_run else "setup " + name)
        consequence = ""
        if keys_run and tuple(args[:2]) == ("keys", "remove") and len(args) > 2:
            from defenseclaw.commands.cmd_keys import required_removal_warning

            consequence = required_removal_warning(self.config, args[2])
        # A cancelled run (or a finished check) puts this status back.
        self._status_before_check[self.active_wizard] = self.wizard_status.get(self.active_wizard, "")
        self.wizard_status[self.active_wizard] = "running..."
        self._wizard_run_started[self.active_wizard] = datetime.now(timezone.utc)
        self.close_wizard_form()
        return SetupPanelAction(
            True,
            SetupCommandIntent(
                label=label,
                args=args,
                binary="defenseclaw",
                category=category,
                origin="setup-wizard",
                follow_up=follow_up,
                secret_stdin=secret_stdin,
                env_overrides=secret_env,
                risk=risk,
                terminal=terminal,
                consequence=consequence,
            ),
        )


def build_setup_sections(
    cfg: object | Mapping[str, Any] | None,
    os_name: str | None = None,
    *,
    observability_status: V8OperatorStatus | None = None,
    observability_status_error: str = "",
) -> tuple[ConfigSection, ...]:
    """Return the Go Setup config section/field catalog.

    ``os_name`` (defaulting to the host OS) drops connectors the platform
    can't run from the editable "Mode" choice, so a Windows operator is
    never offered the proxy connectors (openclaw/zeptoclaw) that only
    exist on macOS/Linux.
    """

    sections: list[ConfigSection] = [
        ConfigSection(
            "General",
            (
                _header("Config Version", "config_version", _fmt_config_version(cfg)),
                _header(".. Paths .."),
                _field(cfg, "Data Dir", "data_dir", hint="Root directory for DefenseClaw state."),
                _field(cfg, "Audit DB", "audit_db", hint="SQLite file path for the audit log."),
                _field(cfg, "Quarantine Dir", "quarantine_dir", hint="Where quarantined assets are moved."),
                _field(cfg, "Plugin Dir", "plugin_dir", hint="Directory DefenseClaw scans for installed plugins."),
                _field(cfg, "Policy Dir", "policy_dir", hint="Root of policy packs."),
                _field(cfg, "Environment", "environment", hint="Free-form deployment label."),
                _header(".. Unified LLM (for scanners + guardrail) .."),
                _field(cfg, "Provider", "llm.provider", "choice", LLM_PROVIDERS, "LLM provider family."),
                _field(cfg, "Model", "llm.model", hint="Model identifier."),
                _field(cfg, "API Key Env", "llm.api_key_env", hint="Env var NAME holding the unified key."),
                _field(cfg, "API Key (redacted)", "llm.api_key", "password", hint="Inline key; prefer API Key Env."),
                _field(cfg, "Base URL", "llm.base_url", hint="Override provider base URL."),
                _field(cfg, "Timeout (s)", "llm.timeout", "int", hint="Per-request timeout in seconds."),
                _field(cfg, "Max Retries", "llm.max_retries", "int", hint="Retries with exponential backoff."),
            ),
            "Global paths, environment label, and the shared LLM key fallback.",
            "Config Version is read-only; edit unified LLM fields here instead of legacy inspect_llm.",
        ),
        ConfigSection(
            "Agent",
            (
                _field(cfg, "Agent ID", "agent.id", hint="Stable lower-kebab-case identity."),
                _field(cfg, "Agent Name", "agent.name", hint="Human-readable display name."),
            ),
            "Logical agent identity used for aggregation, webhooks, and enterprise reporting.",
        ),
        ConfigSection(
            "Notifications",
            (
                (
                    _field(cfg, "Enabled", "notifications.enabled", "bool", hint="Master desktop notification switch.")
                    if desktop_notification_capability(os_name).supported
                    else ConfigField(
                        "Enabled (native desktop unsupported on Windows)",
                        "notifications.enabled",
                        "header",
                        str(get_config_value(cfg, "notifications.enabled", False)).lower(),
                        str(get_config_value(cfg, "notifications.enabled", False)).lower(),
                        hint="Read-only legacy setting; Windows toast delivery is inactive.",
                    )
                ),
                _header(".. Categories .."),
                _field(
                    cfg,
                    "Block (enforced)",
                    "notifications.block_enforced",
                    "bool",
                    hint="Toast when a request is actually denied.",
                ),
                _field(
                    cfg,
                    "Block (would-block)",
                    "notifications.block_would_block",
                    "bool",
                    hint="Toast for observe-mode would-block verdicts.",
                ),
                _field(
                    cfg,
                    "HITL Approval",
                    "notifications.hitl_approval",
                    "bool",
                    hint="Toast when a HITL approval prompt is pending.",
                ),
                _header(".. Sources .."),
                _field(cfg, "Source: Hook", "notifications.sources.hook", "bool", hint="Allow hook notifications."),
                _field(
                    cfg,
                    "Source: Guardrail",
                    "notifications.sources.guardrail",
                    "bool",
                    hint="Allow guardrail notifications.",
                ),
                _field(
                    cfg,
                    "Source: Asset Policy",
                    "notifications.sources.asset_policy",
                    "bool",
                    hint="Allow asset-policy notifications.",
                ),
                _header(".. Throttle .."),
                _field(
                    cfg,
                    "Dedup Window",
                    "notifications.dedup_window",
                    hint="Duration string like 30s, 1m, or 500ms.",
                ),
                _field(
                    cfg,
                    "Max Per Minute",
                    "notifications.max_per_minute",
                    "int",
                    hint="Global notification rate cap.",
                ),
            ),
            (
                "User-session desktop toasts for blocks, would-blocks, and HITL approvals."
                if desktop_notification_capability(os_name).supported
                else "Native Windows desktop/toast notifications are unsupported; delivery is inactive."
            ),
            "Restart the gateway after editing; the dispatcher snapshots config at boot.",
        ),
        ConfigSection(
            "Claw",
            (
                _field(
                    cfg,
                    "Mode",
                    "claw.mode",
                    "choice",
                    supported_connector_choices(os_name),
                    "Legacy single-agent setting; set up each connector in Setup tasks instead.",
                ),
                _openclaw_path_field(cfg, "Home Dir", "claw.home_dir", "Legacy: OpenClaw home directory."),
                _openclaw_path_field(cfg, "Config File", "claw.config_file", "Legacy: OpenClaw main config file."),
            ),
            "Legacy single-agent setting (claw.mode). Connectors are set up one by one in "
            "Setup tasks; these fields matter only to installs that still use one agent.",
        ),
        ConfigSection(
            "Agent Hooks",
            _agent_hook_summary_fields(),
            "Dedicated agent hook policy: when scans run, fail behavior, and watched paths.",
        ),
        ConfigSection(
            "Connector Hooks",
            _connector_hook_summary_fields(cfg),
            "Advanced connector_hooks map for configured and future agent connectors.",
        ),
        ConfigSection(
            "Gateway",
            (
                _field(cfg, "Host", "gateway.host", hint="Where clients reach the gateway."),
                _field(cfg, "Port", "gateway.port", "int", hint="WebSocket port."),
                _field(cfg, "API Port", "gateway.api_port", "int", hint="REST sidecar port."),
                _field(cfg, "API Bind", "gateway.api_bind", hint="Bind address for API Port."),
                _field(cfg, "Auto Approve Safe", "gateway.auto_approve_safe", "bool", hint="Auto-approve CLEAN scans."),
                _field(cfg, "TLS", "gateway.tls", "bool", hint="Force wss:// and cert validation."),
                _field(cfg, "TLS Skip Verify", "gateway.tls_skip_verify", "bool", hint="Skip cert verification."),
                _field(cfg, "Reconnect MS", "gateway.reconnect_ms", "int", hint="Initial reconnect backoff."),
                _field(cfg, "Max Reconnect MS", "gateway.max_reconnect_ms", "int", hint="Reconnect backoff ceiling."),
                _field(
                    cfg,
                    "Approval Timeout (s)",
                    "gateway.approval_timeout_s",
                    "int",
                    hint="Operator approval wait budget.",
                ),
                _field(cfg, "Token Env", "gateway.token_env", hint="Env var NAME holding gateway auth token."),
                _field(cfg, "Token (redacted)", "gateway.token", "password", hint="Inline gateway token."),
                _field(cfg, "Device Key File", "gateway.device_key_file", hint="Path to per-machine private key."),
            ),
            "Sidecar WebSocket gateway: connection settings, TLS/auth, API bind, reconnect tuning.",
        ),
        _guardrail_section(cfg),
        _scanners_section(cfg),
        ConfigSection(
            "Asset Policy", tuple(_asset_policy_fields(cfg)), "Registry requirements and default allow/deny behavior."
        ),
        _ai_discovery_section(cfg),
        _gateway_watcher_section(cfg),
        ConfigSection(
            "Gateway Watchdog",
            (
                _field(cfg, "Enabled", "gateway.watchdog.enabled", "bool", hint="Turn the watchdog on/off."),
                _field(cfg, "Interval (s)", "gateway.watchdog.interval", "int", hint="Seconds between health checks."),
                _field(
                    cfg,
                    "Debounce (failures)",
                    "gateway.watchdog.debounce",
                    "int",
                    hint="Consecutive failures before restart.",
                ),
            ),
            "Health-check loop that restarts the gateway process when it becomes unresponsive.",
        ),
        ConfigSection(
            "Observability",
            _v8_observability_fields(observability_status, error=observability_status_error),
            "Telemetry collection, retention, routing, and per-route redaction policy.",
            "Read-only effective plan; press E to manage destinations through setup observability.",
        ),
        ConfigSection("Webhooks", tuple(_webhook_summary_fields(cfg)), "Read-only notifier webhook summary."),
        ConfigSection("Skill Admission", admission_action_fields("skill", cfg), "Skill admission action per severity."),
        ConfigSection("MCP Admission", admission_action_fields("mcp", cfg), "MCP admission action per severity."),
        ConfigSection("Plugin Admission", admission_action_fields("plugin", cfg), "Plugin admission action per severity."),
        _watch_section(cfg),
        _openshell_section(cfg),
        ConfigSection(
            "Inspect LLM (legacy - read-only)",
            (
                _header("Provider", value=_value(cfg, "inspect_llm.provider") or UNSET_VALUE),
                _header("Model", value=_value(cfg, "inspect_llm.model") or UNSET_VALUE),
                _header("API Key Env", value=_value(cfg, "inspect_llm.api_key_env") or UNSET_VALUE),
                _header("Base URL", value=_value(cfg, "inspect_llm.base_url") or UNSET_VALUE),
                _header("Timeout (s)", value=_value(cfg, "inspect_llm.timeout") or UNSET_VALUE),
                _header("Max Retries", value=_value(cfg, "inspect_llm.max_retries") or UNSET_VALUE),
            ),
            "Deprecated v4 block. Edit the Unified LLM section instead.",
        ),
        ConfigSection(
            "Cisco AI Defense", tuple(_cisco_ai_defense_fields(cfg)), "Cloud-hosted prompt/response moderation."
        ),
        ConfigSection("Firewall", tuple(_firewall_fields(cfg)), "Host firewall anchor paths. Read-only in the TUI."),
        ConfigSection(
            "Trusted Paths",
            tuple(_trusted_paths_summary_fields(cfg)),
            "Binary locations trusted for connector discovery. Read-only here; "
            "manage via 'defenseclaw setup trusted-paths'.",
        ),
    ]
    return tuple(_lock_unmodeled_fields(section) for section in sections)


UNMODELED_CONFIG_HINT = "Read-only here; edit this in config.yaml"
READ_ONLY_VALUE = "read-only"


def _lock_unmodeled_fields(section: ConfigSection) -> ConfigSection:
    """Turn rows ``Config.save()`` can't persist into read-only rows.

    Editing such a row would look saved but be dropped on write, so it is
    shown read-only with where to change it instead.
    """

    fields = tuple(
        _read_only_row(field, UNMODELED_CONFIG_HINT)
        if field.kind != "header" and field.key and not is_python_modeled(None, field.key)
        else field
        for field in section.fields
    )
    if fields == section.fields:
        return section
    return ConfigSection(section.name, fields, section.summary, section.help)


# An unset read-only field: the Value read "read-only" as if that were the
# value (GAP-2253); the Validation/Hint columns say it is read-only.
UNSET_VALUE = "(unset)"


def _read_only_row(field: ConfigField, hint: str) -> ConfigField:
    shown = field.value or UNSET_VALUE
    return ConfigField(label=field.label, key=field.key, kind="header", value=shown, original=shown, hint=hint)


def _openclaw_path_field(cfg: object | Mapping[str, Any] | None, label: str, key: str, hint: str) -> ConfigField:
    """claw.home_dir / claw.config_file: only the OpenClaw connector reads them.

    With Mode codex (or amp) and no OpenClaw connector the default
    ~/.openclaw paths looked like that agent's paths (GAP-2253), so they are
    shown read-only as unused instead.
    """

    mode = _active_connector(cfg) or "openclaw"
    if mode == "openclaw" or "openclaw" in _active_connector_names_for_setup(cfg):
        return _field(cfg, label, key, hint=hint)
    shown = f"(not used: Mode is {mode})"
    return ConfigField(
        label=label,
        key=key,
        kind="header",
        value=shown,
        original=shown,
        hint="Only OpenClaw reads this path. To edit it, set Mode to openclaw, save, and reopen the editor.",
    )


def admission_action_fields(asset_type: str, cfg: object | Mapping[str, Any] | None) -> tuple[ConfigField, ...]:
    """``admission.<type>.actions.<severity>``: the action shorthand a scan
    finding at that severity gets. Blank inherits (for skills) the skill
    scanner gate, then admission.defaults, then the built-in default."""
    if asset_type not in {"skill", "mcp", "plugin"}:
        return (ConfigField("(unknown admission type)", f"admission.{asset_type}.error", "header"),)
    out = [
        ConfigField(
            label=f".. {asset_type.upper()} ACTIONS (per severity) ..",
            key=f"admission.{asset_type}.hint",
            kind="header",
            hint="block/quarantine reject the install; warn admits with a warning; allow admits; blank=default",
        ),
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        out.append(
            _field(
                cfg,
                severity[:1].upper() + severity[1:],
                f"admission.{asset_type}.actions.{severity}",
                "choice",
                ("", "block", "quarantine", "warn", "allow"),
                f"On a {severity.upper()} finding; blank=the default for this severity.",
            )
        )
    return tuple(out)


def connector_setup_command(wire: str) -> tuple[tuple[str, ...], str]:
    alias = _connector_setup_alias(wire)
    if not alias:
        return (), ""
    return ("setup", alias, "--yes"), "setup " + alias


def is_guardrail_supporting(connector: str) -> bool:
    return connector.strip().lower() in GUARDRAIL_CONNECTORS


def _stored_key_picker(field: WizardFormField, cfg: object | Mapping[str, Any] | None) -> WizardFormField:
    """The remove form's Env Name as a pick list of the names stored in .env (GAP-2061).

    Only names are read, never values. The gateway's own token stays out of
    the list (``keys list`` says not to remove it). With nothing stored the
    field stays free text.
    """

    from defenseclaw.commands.cmd_keys import _dotenv_names, _gateway_token_names

    data_dir = _llm_data_dir(cfg) or os.path.expanduser("~/.defenseclaw")
    try:
        reserved = _gateway_token_names(cfg)
    except Exception:  # noqa: BLE001 - a partial config still lists the stored names.
        reserved = {"DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN"}
    names = tuple(sorted(name for name in _dotenv_names(os.path.join(data_dir, ".env")) if name not in reserved))
    if not names:
        return replace(field, hint=f"Name of the entry to delete; nothing is stored in {data_dir}/.env yet.")
    return replace(
        field,
        kind="choice",
        value="",
        default="",
        options=("", *names),
        hint="Pick the stored entry to delete (←/→ or Enter steps through them).",
    )


_SECRET_VALUE_SET_HINT = "Paste the key; it is sent on stdin and never shown."


def _credentials_wizard_fields() -> tuple[WizardFormField, ...]:
    return (
        WizardFormField(
            "Action",
            "choice",
            value="list",
            default="list",
            options=("list", "check", "fill-missing", "set", "remove"),
            hint="list/check show which keys are set; fill-missing asks for unset ones; "
            "set stores one key; remove deletes one.",
        ),
        WizardFormField("Env Name", "string", hint="The key's environment variable name, e.g. OPENAI_API_KEY."),
        WizardFormField("Secret Value", "password", hint="For Action set: " + _SECRET_VALUE_SET_HINT),
    )


def _local_observability_wizard_fields() -> tuple[WizardFormField, ...]:
    return (
        WizardFormField(
            "Action",
            "choice",
            value="status",
            default="status",
            options=("status", "url", "up", "logs", "down", "reset"),
        ),
        WizardFormField("Timeout", "int", value="180", default="180"),
        WizardFormField("No Wait", "bool", value="no", default="no"),
        WizardFormField("No Config", "bool", value="no", default="no"),
        WizardFormField("Signals", "string", value="traces,metrics,logs", default="traces,metrics,logs"),
        WizardFormField("Service Name", "string", value="defenseclaw", default="defenseclaw"),
        WizardFormField("Confirm Reset", "bool", value="no", default="no"),
        WizardFormField("Service", "string"),
        WizardFormField("Follow", "bool", value="no", default="no"),
        WizardFormField("JSON Output", "bool", value="no", default="no"),
    )


def _token_rotation_wizard_fields() -> tuple[WizardFormField, ...]:
    return (
        WizardFormField("Connector", "choice", value="", default="", options=("", *CONNECTORS)),
        WizardFormField("Refresh Hooks", "bool", value="yes", default="yes"),
    )


def _trusted_paths_wizard_fields() -> tuple[WizardFormField, ...]:
    return (
        WizardFormField(
            "Action",
            "choice",
            value="list",
            default="list",
            options=("list", "add", "remove"),
            hint="List, add, or remove trusted connector-binary prefixes.",
        ),
        WizardFormField("Directory", "string", hint="Directory prefix to trust or remove."),
        WizardFormField("Force", "bool", value="no", default="no", hint="Allow add even if checks warn."),
        WizardFormField("JSON Output", "bool", value="no", default="no", hint="Emit machine-readable JSON."),
    )


def _acp_wizard_fields() -> tuple[WizardFormField, ...]:
    def managed(values: Mapping[str, str]) -> bool:
        return values.get("managed_enrollment") == "yes"

    return (
        WizardFormField(
            "Client",
            "choice",
            "--client",
            value="zed",
            default="zed",
            options=ACP_CLIENT_IDS,
            required=True,
            hint="Editor that launches the agent over ACP.",
        ),
        WizardFormField(
            "Agent",
            "choice",
            "--agent",
            value="kiro",
            default="kiro",
            options=ACP_AGENT_IDS,
            required=True,
            hint="ACP agent DefenseClaw sits in front of and guards.",
        ),
        WizardFormField(
            "Profile",
            "string",
            "--profile",
            value="default",
            default="default",
            required=True,
            hint="ACP policy profile (acp.profiles) the guard enforces.",
        ),
        WizardFormField(
            "Action Mode",
            "bool",
            "--activate",
            value="no",
            default="no",
            hint="No observes only; yes blocks policy violations.",
        ),
        WizardFormField(
            "Managed Enrollment",
            "bool",
            "--managed",
            value="no",
            default="no",
            hint="Use centrally owned enterprise policy and a pre-provisioned per-binding token.",
        ),
        WizardFormField(
            "Runtime Data Dir",
            "string",
            "--runtime-data-dir",
            hint="Target user's private DefenseClaw data directory.",
            visible_when=managed,
        ),
        WizardFormField(
            "Token File",
            "string",
            "--token-file",
            hint="Token path emitted by defenseclaw-gateway enterprise acp enroll.",
            visible_when=managed,
        ),
    )


def _guardrail_actions_wizard_fields(
    overrides: Mapping[str, str] | None = None,
    cfg: object | Mapping[str, Any] | None = None,
) -> tuple[WizardFormField, ...]:
    overrides = overrides or {}
    scope = (overrides.get("@Scope") or _GUARDRAIL_SCOPE_GLOBAL).strip()
    if scope not in _GUARDRAIL_SCOPES:
        scope = _GUARDRAIL_SCOPE_GLOBAL

    def connector_scope(dv: Mapping[str, str]) -> bool:
        return dv.get("scope") == _GUARDRAIL_SCOPE_CONNECTOR

    candidates = (
        WizardFormField(
            "Scope",
            "choice",
            value=scope,
            default=_GUARDRAIL_SCOPE_GLOBAL,
            options=_GUARDRAIL_SCOPES,
            hint=(
                "global-all-active affects every active connector; selected-connector changes only the chosen member."
            ),
        ),
        WizardFormField(
            "Connector",
            "choice",
            "--connector",
            value="",
            default="",
            options=_guardrail_connector_choices(cfg),
            hint="Active connector this action should change.",
            required=True,
            visible_when=connector_scope,
        ),
        WizardFormField(
            "Action",
            "choice",
            value="status",
            default="status",
            options=("status", "enable", "disable", "fail-mode", "hilt", "block-message"),
            hint="Guardrail command to run.",
        ),
        WizardFormField(
            "Fail Mode",
            "choice",
            value="open",
            default="open",
            options=("open", "closed"),
            hint="For guardrail fail-mode.",
        ),
        WizardFormField(
            "HITL State",
            "choice",
            value="on",
            default="on",
            options=("on", "off"),
            hint="For guardrail hilt.",
        ),
        WizardFormField(
            "Approval Min Severity",
            "choice",
            "--min-severity",
            value="HIGH",
            default="HIGH",
            options=("CRITICAL", "HIGH", "MEDIUM", "LOW"),
            hint="For guardrail hilt.",
        ),
        WizardFormField("Block Message", "string", hint="For guardrail block-message."),
        WizardFormField("Clear Message", "bool", value="no", default="no", hint="Clear the custom block message."),
        WizardFormField("Restart Gateway", "bool", "--restart", "--no-restart", value="yes", default="yes"),
    )
    return _apply_dynamic_fields(candidates, overrides, {"scope": scope})


def _custom_action_is(*names: str) -> Callable[[Mapping[str, str]], bool]:
    targets = {n.strip().lower() for n in names}
    return lambda dv: (dv.get("action", "") or "").strip().lower() in targets


def _custom_base_type_is(*names: str) -> Callable[[Mapping[str, str]], bool]:
    targets = {n.strip().lower() for n in names}

    def predicate(dv: Mapping[str, str]) -> bool:
        if (dv.get("action", "") or "").strip().lower() != "add":
            return False
        return (dv.get("base_type", "") or "").strip().lower() in targets

    return predicate


def _custom_providers_fields_for(overrides: Mapping[str, str] | None = None) -> tuple[WizardFormField, ...]:
    overrides = overrides or {}
    action = (overrides.get("@Action") or "list").strip().lower() or "list"
    base_type = (overrides.get("--base-provider-type") or "").strip().lower()
    is_add = _custom_action_is("add")
    is_add_or_remove = _custom_action_is("add", "remove")
    is_bedrock = _custom_base_type_is("bedrock")
    is_vertex = _custom_base_type_is("vertex_ai")
    is_azure = _custom_base_type_is("azure")
    candidates: tuple[WizardFormField, ...] = (
        WizardFormField("Action", "choice", value="list", default="list", options=("list", "show", "add", "remove")),
        WizardFormField("Name", "string", visible_when=is_add_or_remove, required=True),
        WizardFormField("Domains", "string", hint="LLM allow-list domains, comma-separated.", visible_when=is_add),
        WizardFormField(
            "Base Provider Type",
            "choice",
            "--base-provider-type",
            value="",
            default="",
            options=CUSTOM_PROVIDER_BASE_TYPES,
            hint="Upstream family; blank infers from model prefix.",
            visible_when=is_add,
        ),
        WizardFormField("Base URL", "string", "--base-url", hint="https://llm.internal:8443", visible_when=is_add),
        WizardFormField(
            "Available Models (CSV)",
            "string",
            "--available-model",
            hint="Model ids served by this instance, comma-separated.",
            visible_when=is_add,
        ),
        WizardFormField(
            "Allowed Requests (CSV)",
            "string",
            "--allowed-request",
            hint=f"Subset of {', '.join(CUSTOM_PROVIDER_REQUEST_TYPES)}; blank=all.",
            visible_when=is_add,
        ),
        WizardFormField(
            "Request Path Overrides (CSV)",
            "string",
            "--request-path-override",
            hint="key=value pairs, e.g. chat=/openai/v1/chat/completions.",
            visible_when=is_add,
        ),
        WizardFormField("Env Keys", "string", hint="API-key env vars, comma-separated.", visible_when=is_add),
        WizardFormField("Profile ID", "string", visible_when=is_add),
        WizardFormField("Ollama Ports", "string", hint="Extra loopback ports, comma-separated.", visible_when=is_add),
        WizardFormField(
            "CA Cert File", "string", "--ca-cert-file", hint="PEM CA bundle for self-signed certs.", visible_when=is_add
        ),
        WizardFormField(
            "Insecure Skip Verify",
            "bool",
            "--insecure-skip-verify",
            value="no",
            default="no",
            hint="Disable TLS verification (trusted labs only).",
            visible_when=is_add,
        ),
        WizardFormField("Bedrock", "section", visible_when=is_bedrock),
        WizardFormField("Region", "string", "--bedrock-region", visible_when=is_bedrock),
        WizardFormField(
            "Auth Mode", "choice", "--bedrock-auth-mode", options=BEDROCK_AUTH_MODES, visible_when=is_bedrock
        ),
        WizardFormField("Access Key Env", "string", "--bedrock-access-key-env", visible_when=is_bedrock),
        WizardFormField("Secret Key Env", "string", "--bedrock-secret-key-env", visible_when=is_bedrock),
        WizardFormField("Session Token Env", "string", "--bedrock-session-token-env", visible_when=is_bedrock),
        WizardFormField("Profile Name", "string", "--bedrock-profile-name", visible_when=is_bedrock),
        WizardFormField("Inference Profile", "string", "--bedrock-inference-profile", visible_when=is_bedrock),
        WizardFormField(
            "Deployment Aliases (CSV)",
            "string",
            "--bedrock-deployment",
            hint="alias=model-id pairs, comma-separated.",
            visible_when=is_bedrock,
        ),
        WizardFormField("Vertex AI", "section", visible_when=is_vertex),
        WizardFormField("Project ID", "string", "--vertex-project-id", visible_when=is_vertex),
        WizardFormField("Region", "string", "--vertex-region", visible_when=is_vertex),
        WizardFormField("Auth Mode", "choice", "--vertex-auth-mode", options=VERTEX_AUTH_MODES, visible_when=is_vertex),
        WizardFormField(
            "Service Account JSON Env", "string", "--vertex-service-account-json-env", visible_when=is_vertex
        ),
        WizardFormField("Azure", "section", visible_when=is_azure),
        WizardFormField("Endpoint", "string", "--azure-endpoint", visible_when=is_azure),
        WizardFormField("API Version", "string", "--azure-api-version", visible_when=is_azure),
        WizardFormField("Auth Mode", "choice", "--azure-auth-mode", options=AZURE_AUTH_MODES, visible_when=is_azure),
        WizardFormField(
            "Deployment Aliases (CSV)",
            "string",
            "--azure-deployment-alias",
            hint="model=deployment pairs, comma-separated.",
            visible_when=is_azure,
        ),
        WizardFormField("Reload Sidecar", "bool", value="yes", default="yes", visible_when=is_add_or_remove),
    )
    driver = {"action": action, "base_type": base_type}
    return _apply_dynamic_fields(candidates, overrides, driver)


def _custom_providers_wizard_fields() -> tuple[WizardFormField, ...]:
    return _custom_providers_fields_for({})


_REDACTION_ACTIONS: tuple[str, ...] = (
    "interactive",
    "status",
    "remove-all",
    "apply-all",
    "apply-defaults",
    "defaults-set",
    "defaults-reset",
    "bucket-list",
    "bucket-set",
    "bucket-reset",
    "profile-list",
    "profile-show",
    "profile-set",
    "profile-remove",
    "destination-show",
    "destination-send",
    "destination-inherit",
    "route-list",
    "route-add",
    "route-set",
    "route-move",
    "route-remove",
)
_REDACTION_MUTATION_ACTIONS = frozenset(
    {
        "remove-all",
        "apply-all",
        "apply-defaults",
        "defaults-set",
        "defaults-reset",
        "bucket-set",
        "bucket-reset",
        "profile-set",
        "profile-remove",
        "destination-send",
        "destination-inherit",
        "route-add",
        "route-set",
        "route-move",
        "route-remove",
    }
)


def _redaction_action_is(*actions: str) -> Callable[[Mapping[str, str]], bool]:
    selected = frozenset(actions)
    return lambda values: values.get("action", "status") in selected


def _redaction_wizard_fields_for(
    overrides: Mapping[str, str] | None = None,
) -> tuple[WizardFormField, ...]:
    """Action-dependent TUI form for the complete v8 redaction CLI surface."""

    overrides = overrides or {}
    action = overrides.get("@Action", "status")
    route_action = overrides.get("--route-action", "send")
    mutation = _redaction_action_is(*_REDACTION_MUTATION_ACTIONS)
    profile_actions = _redaction_action_is(
        "apply-all",
        "apply-defaults",
        "defaults-set",
        "bucket-set",
        "destination-send",
        "route-add",
        "route-set",
    )

    def profile_visible(values: Mapping[str, str]) -> bool:
        if not profile_actions(values):
            return False
        return not (values.get("action") in {"route-add", "route-set"} and values.get("route_action", "send") == "drop")

    candidates: list[WizardFormField] = [
        WizardFormField(
            "Action",
            "choice",
            value=action,
            default="status",
            options=_REDACTION_ACTIONS,
            required=True,
        ),
        WizardFormField("Policy", "section"),
        WizardFormField(
            "Profile",
            "string",
            "--profile",
            value=overrides.get("--profile", "sensitive"),
            default="sensitive",
            visible_when=profile_visible,
            hint="Built-in (none, sensitive, content, strict) or custom profile name.",
        ),
        WizardFormField(
            "Collect Logs",
            "choice",
            "--logs",
            value=overrides.get("--logs", "keep"),
            default="keep",
            options=("keep", "on", "off"),
            visible_when=_redaction_action_is("defaults-set", "bucket-set"),
        ),
        WizardFormField(
            "Collect Traces",
            "choice",
            "--traces",
            value=overrides.get("--traces", "keep"),
            default="keep",
            options=("keep", "on", "off"),
            visible_when=_redaction_action_is("defaults-set", "bucket-set"),
        ),
        WizardFormField(
            "Collect Metrics",
            "choice",
            "--metrics",
            value=overrides.get("--metrics", "keep"),
            default="keep",
            options=("keep", "on", "off"),
            visible_when=_redaction_action_is("defaults-set", "bucket-set"),
        ),
        WizardFormField(
            "Bucket",
            "choice",
            value=overrides.get("@Bucket", REDACTION_BUCKETS[0]),
            default=REDACTION_BUCKETS[0],
            options=REDACTION_BUCKETS,
            required=True,
            visible_when=_redaction_action_is("bucket-set", "bucket-reset"),
        ),
        WizardFormField(
            "Inherit Bucket Profile",
            "bool",
            "--inherit-profile",
            value=overrides.get("--inherit-profile", "no"),
            default="no",
            visible_when=_redaction_action_is("bucket-set"),
            hint="Remove the bucket profile override; leave Profile blank when enabled.",
        ),
        WizardFormField("Custom Profile", "section"),
        WizardFormField(
            "Custom Profile Name",
            "string",
            value=overrides.get("@Custom Profile Name", ""),
            required=True,
            visible_when=_redaction_action_is("profile-show", "profile-set", "profile-remove"),
        ),
        WizardFormField(
            "Extends",
            "choice",
            "--extends",
            value=overrides.get("--extends", "sensitive"),
            default="sensitive",
            options=REDACTION_CUSTOM_PROFILE_BASES,
            visible_when=_redaction_action_is("profile-set"),
        ),
        WizardFormField(
            "Detector Groups (CSV)",
            "string",
            "--detector",
            value=overrides.get("--detector", ",".join(REDACTION_DETECTOR_GROUPS)),
            default=",".join(REDACTION_DETECTOR_GROUPS),
            visible_when=_redaction_action_is("profile-set"),
        ),
    ]
    for field_class in REDACTION_FIELD_CLASSES:
        flag = f"--field-{field_class}"
        candidates.append(
            WizardFormField(
                f"Field: {field_class}",
                "choice",
                flag,
                value=overrides.get(flag, "inherit"),
                default="inherit",
                options=("inherit", *REDACTION_FIELD_MODES),
                visible_when=_redaction_action_is("profile-set"),
            )
        )
    candidates.extend(
        (
            WizardFormField(
                "Replace With",
                "string",
                "--replace-with",
                value=overrides.get("--replace-with", ""),
                default="",
                visible_when=_redaction_action_is("profile-remove"),
                hint="Leave blank to remove only an unreferenced profile.",
            ),
            WizardFormField("Destination / Route", "section"),
            WizardFormField(
                "Destination",
                "string",
                value=overrides.get("@Destination", ""),
                required=True,
                visible_when=_redaction_action_is(
                    "destination-show",
                    "destination-send",
                    "destination-inherit",
                    "route-list",
                    "route-add",
                    "route-set",
                    "route-move",
                    "route-remove",
                ),
            ),
            WizardFormField(
                "Route Name",
                "string",
                value=overrides.get("@Route Name", ""),
                required=True,
                visible_when=_redaction_action_is("route-add", "route-set", "route-move", "route-remove"),
            ),
            WizardFormField(
                "Signals (CSV)",
                "string",
                "--signal",
                value=overrides.get("--signal", "logs"),
                default="logs",
                required=True,
                visible_when=_redaction_action_is("destination-send", "route-add", "route-set"),
            ),
            WizardFormField(
                "Buckets (CSV)",
                "string",
                "--bucket",
                value=overrides.get("--bucket", "*"),
                default="*",
                required=True,
                visible_when=_redaction_action_is("destination-send", "route-add", "route-set"),
            ),
            WizardFormField(
                "Sources (CSV)",
                "string",
                "--source",
                value=overrides.get("--source", ""),
                visible_when=_redaction_action_is("route-add", "route-set"),
            ),
            WizardFormField(
                "Connectors (CSV)",
                "string",
                "--connector",
                value=overrides.get("--connector", ""),
                visible_when=_redaction_action_is("route-add", "route-set"),
            ),
            WizardFormField(
                "Producer Actions (CSV)",
                "string",
                "--producer-action",
                value=overrides.get("--producer-action", ""),
                visible_when=_redaction_action_is("route-add", "route-set"),
            ),
            WizardFormField(
                "Event Names (CSV)",
                "string",
                "--event-name",
                value=overrides.get("--event-name", ""),
                visible_when=_redaction_action_is("route-add", "route-set"),
            ),
            WizardFormField(
                "Minimum Severity",
                "choice",
                "--min-severity",
                value=overrides.get("--min-severity", ""),
                options=("", *REDACTION_SEVERITIES),
                visible_when=_redaction_action_is("route-add", "route-set"),
            ),
            WizardFormField(
                "Route Action",
                "choice",
                "--route-action",
                value=route_action,
                default="send",
                options=("send", "drop"),
                visible_when=_redaction_action_is("route-add", "route-set"),
            ),
            WizardFormField(
                "Position",
                "int",
                "--position",
                value=overrides.get("--position", "1"),
                default="1",
                required=True,
                visible_when=_redaction_action_is("route-add", "route-move"),
            ),
            WizardFormField("Execution", "section"),
            # The CLI intentionally has no --json option on bucket list or
            # destination show; keep this predicate aligned with Click.
            WizardFormField(
                "JSON Output",
                "bool",
                "--json",
                value=overrides.get("--json", "no"),
                default="no",
                visible_when=_redaction_action_is(
                    "status",
                    "profile-list",
                    "profile-show",
                    "route-list",
                    *_REDACTION_MUTATION_ACTIONS,
                ),
            ),
            WizardFormField(
                "Dry Run",
                "bool",
                "--dry-run",
                value=overrides.get("--dry-run", "yes"),
                default="yes",
                visible_when=mutation,
                hint="On by default. Toggle off only after reviewing the command and consequences.",
            ),
            WizardFormField(
                "Restart Gateway",
                "bool",
                "--restart",
                value=overrides.get("--restart", "no"),
                default="no",
                visible_when=mutation,
            ),
        )
    )
    return _apply_dynamic_fields(
        candidates,
        overrides,
        {"action": action, "route_action": route_action},
    )


def redaction_wizard_fields(
    cfg: object | Mapping[str, Any] | None = None,
) -> tuple[WizardFormField, ...]:
    del cfg
    return _redaction_wizard_fields_for({})


def _redaction_csv(fields: Sequence[WizardFormField], label: str) -> tuple[str, ...]:
    return tuple(value.strip() for value in wizard_field_value(fields, label).split(",") if value.strip())


def _append_redaction_repeated(args: list[str], flag: str, values: Sequence[str]) -> None:
    for value in values:
        args.extend((flag, value))


def _append_redaction_mutation_flags(args: list[str], fields: Sequence[WizardFormField]) -> None:
    # The TUI command-preview screen is the attended confirmation boundary.
    # Defaulting Dry Run to yes keeps every mutation preview-only until the
    # operator explicitly toggles it off; --yes prevents a hidden stdin prompt
    # on native Windows once the command has been approved.
    args.append("--yes")
    if wizard_bool_value(fields, "Dry Run", "yes") == "yes":
        args.append("--dry-run")
    if wizard_bool_value(fields, "JSON Output", "no") == "yes":
        args.append("--json")
    if wizard_bool_value(fields, "Restart Gateway", "no") == "yes":
        args.append("--restart")


_REDACTION_COLLECT_FLAGS: tuple[tuple[str, str, str], ...] = (
    ("Collect Logs", "--logs", "--no-logs"),
    ("Collect Traces", "--traces", "--no-traces"),
    ("Collect Metrics", "--metrics", "--no-metrics"),
)


def _append_redaction_collect_flags(args: list[str], fields: Sequence[WizardFormField]) -> None:
    for label, enabled, disabled in _REDACTION_COLLECT_FLAGS:
        value = wizard_field_value(fields, label)
        if value == "on":
            args.append(enabled)
        elif value == "off":
            args.append(disabled)


def _build_redaction_apply_args(args: list[str], action: str, fields: Sequence[WizardFormField]) -> None:
    args.extend(
        (
            "apply",
            "--scope",
            "all-configurable" if action == "apply-all" else "defaults",
        )
    )
    if profile := wizard_field_value(fields, "Profile"):
        args.extend(("--profile", profile))


def _build_redaction_defaults_args(args: list[str], action: str, fields: Sequence[WizardFormField]) -> None:
    verb = action.removeprefix("defaults-")
    args.extend(("defaults", verb))
    if verb != "set":
        return
    if profile := wizard_field_value(fields, "Profile"):
        args.extend(("--profile", profile))
    _append_redaction_collect_flags(args, fields)


def _build_redaction_bucket_args(args: list[str], action: str, fields: Sequence[WizardFormField]) -> None:
    verb = action.removeprefix("bucket-")
    args.extend(("bucket", verb))
    if verb == "list":
        return
    args.append(wizard_field_value(fields, "Bucket"))
    if verb != "set":
        return
    if wizard_bool_value(fields, "Inherit Bucket Profile", "no") == "yes":
        args.append("--inherit-profile")
    elif profile := wizard_field_value(fields, "Profile"):
        args.extend(("--profile", profile))
    _append_redaction_collect_flags(args, fields)


def _build_redaction_profile_args(args: list[str], action: str, fields: Sequence[WizardFormField]) -> None:
    verb = action.removeprefix("profile-")
    args.extend(("profile", verb))
    if verb == "list":
        return
    args.append(wizard_field_value(fields, "Custom Profile Name"))
    if verb == "set":
        args.extend(("--extends", wizard_field_value(fields, "Extends")))
        _append_redaction_repeated(args, "--detector", _redaction_csv(fields, "Detector Groups (CSV)"))
        for field_class in REDACTION_FIELD_CLASSES:
            mode = wizard_field_value(fields, f"Field: {field_class}")
            if mode and mode != "inherit":
                args.extend(("--field", f"{field_class}={mode}"))
    elif verb == "remove" and (replacement := wizard_field_value(fields, "Replace With")):
        args.extend(("--replace-with", replacement))


def _build_redaction_destination_args(args: list[str], action: str, fields: Sequence[WizardFormField]) -> None:
    verb = action.removeprefix("destination-")
    args.extend(("destination", verb, wizard_field_value(fields, "Destination")))
    if verb != "send":
        return
    _append_redaction_repeated(args, "--signal", _redaction_csv(fields, "Signals (CSV)"))
    _append_redaction_repeated(args, "--bucket", _redaction_csv(fields, "Buckets (CSV)"))
    if profile := wizard_field_value(fields, "Profile"):
        args.extend(("--profile", profile))


def _append_redaction_route_selectors(args: list[str], fields: Sequence[WizardFormField]) -> None:
    _append_redaction_repeated(args, "--signal", _redaction_csv(fields, "Signals (CSV)"))
    _append_redaction_repeated(args, "--bucket", _redaction_csv(fields, "Buckets (CSV)"))
    for label, flag in (
        ("Sources (CSV)", "--source"),
        ("Connectors (CSV)", "--connector"),
        ("Producer Actions (CSV)", "--producer-action"),
        ("Event Names (CSV)", "--event-name"),
    ):
        _append_redaction_repeated(args, flag, _redaction_csv(fields, label))
    if severity := wizard_field_value(fields, "Minimum Severity"):
        args.extend(("--min-severity", severity))


def _build_redaction_route_args(args: list[str], action: str, fields: Sequence[WizardFormField]) -> None:
    verb = action.removeprefix("route-")
    destination = wizard_field_value(fields, "Destination")
    args.extend(("route", verb, destination))
    if verb == "list":
        return
    args.append(wizard_field_value(fields, "Route Name"))
    if verb == "move":
        args.extend(("--position", wizard_field_value(fields, "Position")))
        return
    if verb == "remove":
        return
    _append_redaction_route_selectors(args, fields)
    route_action = wizard_field_value(fields, "Route Action") or "send"
    args.extend(("--route-action", route_action))
    profile = wizard_field_value(fields, "Profile")
    if route_action == "send" and profile:
        args.extend(("--profile", profile))
    if verb == "add" and (position := wizard_field_value(fields, "Position")):
        args.extend(("--position", position))


_REDACTION_ARG_BUILDERS: tuple[tuple[str, Callable[[list[str], str, Sequence[WizardFormField]], None]], ...] = (
    ("apply-", _build_redaction_apply_args),
    ("defaults-", _build_redaction_defaults_args),
    ("bucket-", _build_redaction_bucket_args),
    ("profile-", _build_redaction_profile_args),
    ("destination-", _build_redaction_destination_args),
    ("route-", _build_redaction_route_args),
)


def _build_redaction_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    action = wizard_field_value(fields, "Action") or "status"
    if action == "interactive":
        return ("setup", "redaction")

    args: list[str] = ["setup", "redaction"]
    simple = {"status": "status", "remove-all": "remove-all"}.get(action)
    if simple is not None:
        args.append(simple)
    else:
        builder = next((value for prefix, value in _REDACTION_ARG_BUILDERS if action.startswith(prefix)), None)
        if builder is None:
            raise ValueError(f"unknown redaction action: {action}")
        builder(args, action, fields)

    if action in {"status", "profile-list", "profile-show", "route-list"}:
        if wizard_bool_value(fields, "JSON Output", "no") == "yes":
            args.append("--json")
    elif action in _REDACTION_MUTATION_ACTIONS:
        _append_redaction_mutation_flags(args, fields)
    return tuple(args)


# What each scanner and LLM field means and what its choices do. The
# generated hints only repeated the label or flag ("Select scan policy.",
# "Sets --llm-model.", GAP-2522).
_SCANNER_LLM_HINTS: dict[str, str] = {
    "--llm-provider": "The judge's provider, saved in the shared llm: block every scanner uses.",
    "--llm-model": "Model id for the LLM review, e.g. claude-haiku-4-5; saved in the shared llm: block.",
}
_SKILL_SCANNER_HINTS: dict[str, str] = {
    **_SCANNER_LLM_HINTS,
    "--use-behavioral": "Follow data through the skill's scripts to catch behavior its description hides.",
    "--use-llm": "Have an LLM review each skill's instructions, with the LLM Provider and Model below.",
    "--llm-consensus-runs": "LLM reviews per skill; only findings most runs agree on are kept. 0 = one review.",
    "--enable-meta": "A second LLM pass over all findings that drops false positives and ranks the rest.",
    "--use-trigger": "Flag skill descriptions so broad that they would trigger on almost any request.",
    "--use-virustotal": "Optional: look up the skill's files on VirusTotal; needs VIRUSTOTAL_API_KEY.",
    "--use-aidefense": "Optional: send skill content to Cisco AI Defense; needs an AI Defense API key.",
    "--use-osv": "Optional: check the skill's declared dependencies against OSV.dev (needs network).",
    "--llm-base-url": "Endpoint of an openai-compatible or vllm judge, e.g. http://127.0.0.1:8000/v1.",
    "--policy": (
        "quiet (recommended, with the LLM judge): fewest false positives; low-noise and balanced "
        "report more for review; strict: fewest exceptions; permissive: trusted skills."
    ),
    "--fail-on-severity": "Findings at or above this severity block the skill (recommended: HIGH).",
    "--review-queue-min": "Findings from this severity up to the block level are flagged for review (MEDIUM).",
    "--lenient": "yes (the default): scan skills with malformed front matter or missing fields; no: fail them.",
}
_MCP_SCANNER_HINTS: dict[str, str] = {
    **_SCANNER_LLM_HINTS,
    "--analyzers": (
        "auto (the default, also what an empty field means) picks them for you, or a comma-separated "
        "list: yara (local rules), "
        "api (Cisco AI Defense), llm (LLM review), behavioral (code vs. description), "
        "readiness (timeouts, retries)."
    ),
    "--api-endpoint": "Cisco AI Defense API URL for the api analyzer; empty keeps the current one.",
    "--api-key-env": "Env var NAME holding the Cisco AI Defense API key, e.g. CISCO_AI_DEFENSE_API_KEY.",
    "--api-timeout-ms": "How long the api analyzer waits for Cisco AI Defense, in milliseconds.",
    "--scan-prompts": "Also check the prompt templates the server offers.",
    "--scan-resources": "Also check the resources (files, data) the server exposes.",
    "--scan-instructions": "Also check the instructions text the server sends to the agent.",
}
_LLM_FORM_HINTS: dict[str, str] = {
    "--role": (
        "unified: the shared LLM for scanners and judge; agent: the same, and the judge inherits it; "
        "judge: only the guardrail judge's LLM."
    ),
    "--provider": "Where the model runs; Bedrock, Vertex AI and Azure show their own fields below.",
    "--model": "Model id, e.g. claude-haiku-4-5; Enter opens the model picker.",
    "--api-key-env": "Env var NAME holding the API key; defenseclaw keys set stores it.",
    "--base-url": "Endpoint of a proxy or self-hosted model; empty uses the provider's.",
    "--timeout": "Seconds to wait for one LLM request.",
    "--max-retries": "How often a failed or timed-out LLM request is retried.",
    "--bedrock-auth-mode": (
        "api_key: a Bedrock API key; iam_credentials: access key env vars; "
        "profile: an AWS profile; instance_role: the host's IAM role."
    ),
    "--bedrock-access-key-env": "Env var holding the AWS access key ID.",
    "--bedrock-secret-key-env": "Env var holding the AWS secret access key.",
    "--bedrock-session-token-env": "Env var holding the AWS session token (temporary credentials).",
    "--bedrock-profile-name": "AWS profile name from ~/.aws/config.",
    "--bedrock-inference-profile": "Inference-profile prefix for cross-region models, e.g. us.",
    "--vertex-project-id": "GCP project that hosts Vertex AI.",
    "--vertex-auth-mode": (
        "service_account: a key file; adc: gcloud application-default credentials; "
        "workload_identity: the workload's own identity."
    ),
    "--vertex-service-account-json-env": "Env var holding the path to the service-account JSON file.",
    "--azure-auth-mode": "api_key: an Azure OpenAI key; managed_identity: the host's managed identity.",
}


def _hinted(fields: tuple[WizardFormField, ...], hints: Mapping[str, str]) -> tuple[WizardFormField, ...]:
    """``fields`` with the hints in ``hints`` (by flag) in place of generated ones."""

    return tuple(replace(field, hint=hints[field.flag]) if field.flag in hints else field for field in fields)


def wizard_form_defs(
    wizard: SetupWizard | int, cfg: object | Mapping[str, Any] | None = None
) -> tuple[WizardFormField, ...]:
    """Look up the field list for ``wizard``.

    Self-contained wizards live in ``_WIZARD_FORM_BUILDERS``; the
    inline ``if`` ladder below covers the wizards that still take
    extra arguments (config snapshots, preset/whtype seed values).
    Prefer the registry path when adding a new wizard.
    """

    wizard = SetupWizard(wizard)
    builder = _WIZARD_FORM_BUILDERS.get(wizard)
    if builder is not None:
        return builder(cfg)
    if wizard == SetupWizard.SKILL_SCANNER:
        # Policy and lenient open on the effective config, as the gateway
        # form does: "balanced" / "no" showed on a permissive, lenient
        # install, and Run kept the real values (GAP-2536). A field left at
        # its current value emits no flag; a change always emits one.
        policy, lenient = _skill_scanner_policy_values(cfg)
        policies = _SKILL_SCANNER_POLICIES
        gate = (_cfg_str(cfg, "scanners.skill_scanner.fail_on_severity") or "HIGH").upper()
        review = (_cfg_str(cfg, "scanners.skill_scanner.review_queue_min") or "MEDIUM").upper()
        severities = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        skill_fields = (
            _cfg_bool_field("LLM Judge", "--use-llm", cfg, "scanners.skill_scanner.use_llm"),
            WizardFormField(
                "LLM Provider",
                "choice",
                "--llm-provider",
                value="anthropic",
                default="anthropic",
                options=_SCANNER_LLM_PROVIDERS,
            ),
            WizardFormField("LLM Model", "string", "--llm-model"),
            WizardFormField("LLM Base URL", "string", "--llm-base-url"),
            WizardFormField("LLM Consensus Runs", "int", "--llm-consensus-runs", value="0", default="0"),
            WizardFormField(
                "Scan Policy",
                "choice",
                "--policy",
                value=policy,
                default=policy,
                options=policies if policy in policies else (policy, *policies),
            ),
            WizardFormField(
                "Block At", "choice", "--fail-on-severity", value=gate, default=gate, options=severities
            ),
            WizardFormField(
                "Review From", "choice", "--review-queue-min", value=review, default=review, options=severities
            ),
            _cfg_bool_field("Behavioral Analyzer", "--use-behavioral", cfg, "scanners.skill_scanner.use_behavioral"),
            _cfg_bool_field("Meta Analyzer", "--enable-meta", cfg, "scanners.skill_scanner.enable_meta"),
            _cfg_bool_field("Trigger Analyzer", "--use-trigger", cfg, "scanners.skill_scanner.use_trigger"),
            _cfg_bool_field(
                "VirusTotal Scanner", "--use-virustotal", cfg, "scanners.skill_scanner.analyzers.virustotal.enabled"
            ),
            _cfg_bool_field(
                "AI Defense Analyzer", "--use-aidefense", cfg, "scanners.skill_scanner.analyzers.aidefense.enabled"
            ),
            _cfg_bool_field("OSV Dependency Checks", "--use-osv", cfg, "scanners.skill_scanner.analyzers.osv.enabled"),
            WizardFormField("Lenient Mode", "bool", "--lenient", "--no-lenient", value=lenient, default=lenient),
            WizardFormField("Verify After Setup", "bool", "--verify", "--no-verify", value="yes", default="yes"),
        )
        return _hinted(skill_fields, _SKILL_SCANNER_HINTS)
    if wizard == SetupWizard.MCP_SCANNER:
        analyzers = _cfg_str(cfg, "scanners.mcp_scanner.analyzers", "auto")  # GAP-2536
        mcp_fields = (
            WizardFormField("Analyzers", "string", "--analyzers", value=analyzers, default=analyzers),
            WizardFormField(
                "LLM Provider",
                "choice",
                "--llm-provider",
                value="anthropic",
                default="anthropic",
                options=_SCANNER_LLM_PROVIDERS,
            ),
            WizardFormField("LLM Model", "string", "--llm-model"),
            WizardFormField(
                "API Endpoint",
                "string",
                "--api-endpoint",
                value="",
                default="",
            ),
            WizardFormField(
                "API Key Env",
                "string",
                "--api-key-env",
                value="",
                default="",
            ),
            WizardFormField(
                "API Timeout (ms)",
                "int",
                "--api-timeout-ms",
                value="",
                default="",
            ),
            _cfg_bool_field("Scan Prompts", "--scan-prompts", cfg, "scanners.mcp_scanner.scan_prompts"),
            _cfg_bool_field("Scan Resources", "--scan-resources", cfg, "scanners.mcp_scanner.scan_resources"),
            _cfg_bool_field("Scan Instructions", "--scan-instructions", cfg, "scanners.mcp_scanner.scan_instructions"),
            WizardFormField("Verify After Setup", "bool", "--verify", "--no-verify", value="yes", default="yes"),
        )
        return _hinted(mcp_fields, _MCP_SCANNER_HINTS)
    if wizard == SetupWizard.GATEWAY:
        # Start from the configured gateway: the form showed localhost /
        # 9090 / 9099 on a gateway at 127.0.0.1:19020, so an edit of one
        # field looked like it would move the others (GAP-1473). A field
        # left at its current value emits no flag.
        host = _cfg_str(cfg, "gateway.host", "localhost")
        port = _cfg_port(cfg, "gateway.port")
        api_port = _cfg_port(cfg, "gateway.api_port")
        return (
            WizardFormField("Remote Mode", "bool", "--remote", value="no", default="no"),
            WizardFormField(
                "Host", "string", "--host", value=host, default=host, hint="Address of the gateway to connect to."
            ),
            WizardFormField(
                "Port", "int", "--port", value=port, default=port, hint="The gateway's WebSocket port."
            ),
            WizardFormField(
                "API Port",
                "int",
                "--api-port",
                value=api_port,
                default=api_port,
                hint="The gateway's REST API port, which hooks and this TUI call.",
            ),
            WizardFormField("Auth Token", "password", "--token"),
            WizardFormField("SSM Param", "string", "--ssm-param"),
            WizardFormField("SSM Region", "string", "--ssm-region"),
            WizardFormField("SSM Profile", "string", "--ssm-profile"),
            WizardFormField("Verify After Setup", "bool", "--verify", "--no-verify", value="yes", default="yes"),
        )
    if wizard == SetupWizard.GUARDRAIL:
        return guardrail_wizard_fields(cfg)
    if wizard == SetupWizard.SPLUNK:
        return splunk_wizard_fields()
    if wizard == SetupWizard.OBSERVABILITY:
        return observability_wizard_fields("splunk-o11y", cfg)
    if wizard == SetupWizard.WEBHOOKS:
        return webhook_wizard_fields("slack")
    return ()


# Single source of truth for form builders. Lookups are deferred to
# call time (via lambdas) so this dict can sit above the function
# definitions it references without import-order gymnastics. New
# wizards should land here so the dispatch ladder above doesn't grow.
_WIZARD_FORM_BUILDERS: dict[SetupWizard, Any] = {
    SetupWizard.CONNECTOR_SETUP: lambda cfg=None: connector_setup_wizard_fields(cfg),
    SetupWizard.CREDENTIALS: lambda cfg=None: _credentials_wizard_fields(),
    SetupWizard.LLM: lambda cfg=None: llm_wizard_fields(cfg),
    SetupWizard.LOCAL_OBSERVABILITY: lambda cfg=None: _local_observability_wizard_fields(),
    SetupWizard.TOKEN_ROTATION: lambda cfg=None: _token_rotation_wizard_fields(),
    SetupWizard.CUSTOM_PROVIDERS: lambda cfg=None: _custom_providers_wizard_fields(),
    SetupWizard.GUARDRAIL: lambda cfg=None: guardrail_wizard_fields(cfg),
    SetupWizard.SPLUNK: lambda cfg=None: splunk_wizard_fields(),
    SetupWizard.OBSERVABILITY: lambda cfg=None: observability_wizard_fields("splunk-o11y", cfg),
    SetupWizard.WEBHOOKS: lambda cfg=None: webhook_wizard_fields("slack"),
    SetupWizard.REGISTRIES: lambda cfg=None: registry_wizard_fields(),
    SetupWizard.NOTIFICATIONS_ROUTING: lambda cfg=None: notifications_routing_wizard_fields(cfg),
    SetupWizard.AI_DISCOVERY: lambda cfg=None: ai_discovery_wizard_fields(cfg),
    SetupWizard.SPLUNK_DASHBOARDS: lambda cfg=None: splunk_dashboards_wizard_fields(),
    SetupWizard.TRUSTED_PATHS: lambda cfg=None: _trusted_paths_wizard_fields(),
    SetupWizard.GUARDRAIL_ACTIONS: lambda cfg=None: _guardrail_actions_wizard_fields(cfg=cfg),
    SetupWizard.REDACTION: lambda cfg=None: redaction_wizard_fields(cfg),
    SetupWizard.ACP_GUARD: lambda cfg=None: _acp_wizard_fields(),
    SetupWizard.SANDBOX: lambda cfg=None: sandbox_wizard_fields(cfg),
}


# Wizards whose form re-derives when a driver field changes. Each rebuilder
# takes ``(overrides, cfg)`` where ``overrides`` is the by-flag snapshot of
# current values, and returns the filtered field list for the new driver
# selection. Lambdas keep resolution lazy so the builders can live anywhere.
_DEPENDENT_FIELD_REBUILDERS: dict[SetupWizard, Any] = {
    SetupWizard.CONNECTOR_SETUP: lambda overrides, cfg: connector_setup_wizard_fields(
        cfg,
        overrides=overrides,
    ),
    SetupWizard.LLM: lambda overrides, cfg: _llm_wizard_fields_for(
        provider=overrides.get("--provider", "anthropic"),
        role=overrides.get("--role", "unified"),
        overrides=overrides,
        cfg=cfg,
    ),
    SetupWizard.GUARDRAIL: lambda overrides, cfg: _guardrail_wizard_fields_for(overrides, cfg),
    SetupWizard.GUARDRAIL_ACTIONS: lambda overrides, cfg: _guardrail_actions_wizard_fields(overrides, cfg),
    SetupWizard.CUSTOM_PROVIDERS: lambda overrides, cfg: _custom_providers_fields_for(overrides),
    SetupWizard.REDACTION: lambda overrides, _cfg: _redaction_wizard_fields_for(overrides),
    SetupWizard.SANDBOX: lambda overrides, cfg: _apply_dynamic_fields(
        sandbox_wizard_fields(cfg),
        overrides,
        {"action": (overrides.get("@Action") or "setup").strip() or "setup"},
    ),
}


# ---------------------------------------------------------------------------
# Goal-first wizard entry points. Every setup wizard gets a short "what do you
# want to do?" menu whose entries seed preset values and narrow the form to
# the rows that matter for that intent. Most wizards append an "Advanced —
# show all settings" goal that reproduces today's full form, so power users
# keep the flat editor and the menu never traps anyone.
# ---------------------------------------------------------------------------


_ADVANCED_GOAL = WizardGoal(
    id="advanced",
    label="Advanced — show all settings",
    summary="Open the full form with every field (the flat editor).",
)
_NO_ADVANCED_GOAL_WIZARDS = frozenset({SetupWizard.CONNECTOR_SETUP})

# LLM conditional section headers. Listing them in a goal keeps the matching
# provider's auth rows (Bedrock/Vertex/Azure/TLS) when the operator picks a
# regional/custom provider inside that goal, without surfacing them otherwise.
_LLM_PROVIDER_SECTIONS: tuple[str, ...] = ("Bedrock", "Vertex AI", "Azure", "TLS")
_GUARDRAIL_JUDGE_SECTIONS: tuple[str, ...] = (
    "Judge: Bedrock",
    "Judge: Vertex AI",
    "Judge: Azure",
    "Judge: TLS",
)


def _cfg_str(cfg: object | Mapping[str, Any] | None, path: str, default: str = "") -> str:
    return str(get_config_value(cfg, path, default) or default).strip()


def _cfg_bool_field(label: str, flag: str, cfg: object | Mapping[str, Any] | None, path: str) -> WizardFormField:
    """A yes/no field that opens on the configured value and can turn it off.

    The scanner analyzer toggles showed a hard-coded "no" on an install
    where the analyzer was on, and "no" emitted nothing, so the form could
    enable an analyzer but never disable it (GAP-2571). An unchanged field
    emits no flag; a change emits ``flag`` or ``--no-<flag>``.
    """

    value = get_config_value(cfg, path, False)
    if not isinstance(value, bool):
        value = str(value).strip().lower() in {"1", "true", "yes", "on"}
    current = "yes" if value else "no"
    return WizardFormField(label, "bool", flag, "--no-" + flag[2:], value=current, default=current)


def _skill_scanner_policy_values(cfg: object | Mapping[str, Any] | None) -> tuple[str, str]:
    """The effective skill-scanner policy and lenient mode as form values.

    The defaults match ``SkillScannerConfig`` (quiet, lenient on); an empty
    policy is the recommended quiet preset.
    """

    policy = get_config_value(cfg, "scanners.skill_scanner.policy", "quiet")
    policy = str(policy).strip() or "quiet"
    lenient = get_config_value(cfg, "scanners.skill_scanner.lenient", True)
    if not isinstance(lenient, bool):
        lenient = str(lenient).strip().lower() in {"1", "true", "yes", "on"}
    return policy, "yes" if lenient else "no"


def _cfg_port(cfg: object | Mapping[str, Any] | None, path: str) -> str:
    """A configured port as text, or "" when unset (0 means unset)."""

    value = _cfg_str(cfg, path)
    return "" if value in {"", "0"} else value


def _active_connector(cfg: object | Mapping[str, Any] | None) -> str:
    return _cfg_str(cfg, "claw.mode", "").lower()


def _active_connector_names_for_setup(cfg: object | Mapping[str, Any] | None) -> list[str]:
    method = getattr(cfg, "active_connectors", None)
    if callable(method):
        try:
            names = method()
        except Exception:  # noqa: BLE001 - a bad config object must not hide setup workflows.
            names = None
        if isinstance(names, (list, tuple)):
            resolved = [str(name).strip().lower() for name in names if str(name).strip()]
            if resolved:
                return resolved

    connectors_map = get_config_value(cfg, "guardrail.connectors", None)
    if isinstance(connectors_map, Mapping):
        keys = sorted({str(key).strip().lower() for key in connectors_map if str(key).strip()})
        if keys:
            return keys

    singular = _active_connector(cfg)
    return [singular] if singular else []


def _guardrail_connector_choices(cfg: object | Mapping[str, Any] | None) -> tuple[str, ...]:
    """Connector choices for Guardrail forms.

    A populated multi-connector roster is authoritative: policy forms may only
    target its active members. Fresh and legacy single-connector setup keeps
    the full catalog so an operator can still choose the first connector.
    """

    active = _active_connector_names_for_setup(cfg)
    if len(active) <= 1:
        return ("", *CONNECTORS)
    return ("", *dict.fromkeys(active))


def _guardrail_default_scope(cfg: object | Mapping[str, Any] | None) -> str:
    """Prefer a selected-connector policy form only when a real fleet exists."""

    if len(_active_connector_names_for_setup(cfg)) > 1:
        return _GUARDRAIL_SCOPE_CONNECTOR
    return _GUARDRAIL_SCOPE_GLOBAL


def _guardrail_form_scope(fields: Sequence[WizardFormField]) -> str:
    scope = wizard_field_value(fields, "Scope")
    return scope if scope in _GUARDRAIL_SCOPES else _GUARDRAIL_SCOPE_CONNECTOR


def _guardrail_connector_selection_error(
    cfg: object | Mapping[str, Any] | None,
    fields: Sequence[WizardFormField],
) -> str:
    """Reject a non-member target when the active roster is authoritative."""

    if _guardrail_form_scope(fields) != _GUARDRAIL_SCOPE_CONNECTOR:
        return ""
    requested = wizard_field_value(fields, "Connector").strip()
    active = _active_connector_names_for_setup(cfg)
    if not requested or len(active) <= 1:
        return ""
    wanted = normalize_connector(requested)
    members = {normalize_connector(name) for name in active}
    if wanted in members:
        return ""
    return f"Connector {requested!r} is not active. Active connectors: {', '.join(active)}."


def _connector_is_proxy(connector: str) -> bool:
    """True for proxy-backed connectors that host both judge AND agent LLMs."""

    name = (connector or "").strip().lower()
    if not name:
        return False
    try:
        from defenseclaw.commands.cmd_setup import connector_llm_role  # noqa: PLC0415

        return connector_llm_role(name) == "judge_and_agent"
    except Exception:  # noqa: BLE001 - degrade to the static proxy set.
        return name in GUARDRAIL_CONNECTORS


def _any_active_connector_is_proxy(cfg: object | Mapping[str, Any] | None) -> bool:
    return any(_connector_is_proxy(connector) for connector in _active_connector_names_for_setup(cfg))


def _guardrail_enabled(cfg: object | Mapping[str, Any] | None) -> bool:
    """True when the guardrail master switch is on (``guardrail.enabled``)."""

    return bool(get_config_value(cfg, "guardrail.enabled", False))


def _llm_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    main_configured = bool(_cfg_str(cfg, "llm.model"))
    main_label = "Change my main model" if main_configured else "Set up my main model"
    return (
        WizardGoal(
            "main",
            main_label,
            summary="Pick the provider, model, and API key for the unified LLM.",
            presets={"--role": "unified"},
            fields=("Provider", "Model", "API Key", "API Key Env", *_LLM_PROVIDER_SECTIONS),
        ),
        WizardGoal(
            "judge",
            "Add or change the Judge LLM",
            summary="Configure a dedicated judge model for guardrail verdicts.",
            presets={"--role": "judge", "--inherit-from": "llm"},
            fields=("Provider", "Model", "API Key Env", "API Key", "Inherit From", *_LLM_PROVIDER_SECTIONS),
            available_when=lambda c: _guardrail_enabled(c) or _any_active_connector_is_proxy(c),
        ),
        WizardGoal(
            "agent",
            "Configure the Agent LLM",
            summary="Set the agent-side model (proxy connectors only).",
            presets={"--role": "agent"},
            fields=("Provider", "Model", "API Key", "API Key Env", *_LLM_PROVIDER_SECTIONS),
            available_when=lambda c: _any_active_connector_is_proxy(c),
        ),
        WizardGoal(
            "regional",
            "Use a regional provider (Bedrock / Vertex / Azure)",
            summary="Switch to a cloud-region provider; auth rows appear on pick.",
            fields=("Provider", "Model", *_LLM_PROVIDER_SECTIONS),
        ),
        WizardGoal(
            "instance",
            "Connect a self-hosted / custom instance",
            summary="Point at an OpenAI-compatible endpoint with optional TLS.",
            fields=("Provider", "Instance Name", "Base URL", "Model", *_LLM_PROVIDER_SECTIONS),
        ),
        WizardGoal(
            "test",
            "Test my LLM connection",
            summary="Save and send a one-shot reachability probe.",
            presets={"--ping": "yes"},
            fields=("Provider", "Model", "API Key", *_LLM_PROVIDER_SECTIONS),
        ),
    )


def _guardrail_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "mode",
            "Switch enforcement mode (observe / action)",
            summary="Toggle log-only (observe) vs blocking (action) enforcement.",
            fields=("Mode",),
        ),
        WizardGoal(
            "judge",
            "Set up / change the LLM Judge",
            summary="Configure global judge settings shared by all active connectors.",
            presets={"@Scope": _GUARDRAIL_SCOPE_GLOBAL, "--detection-strategy": "regex_judge"},
            fields=(
                "Scope",
                "Provider",
                "--judge-model",
                "--judge-api-key-env",
                "--judge-api-base",
                "--detection-strategy",
                "--inherit-from",
                *_GUARDRAIL_JUDGE_SECTIONS,
            ),
        ),
        WizardGoal(
            "cisco",
            "Connect Cisco AI Defense",
            summary="Configure global Cisco settings shared by all active connectors.",
            presets={"@Scope": _GUARDRAIL_SCOPE_GLOBAL},
            fields=("Scope", "--cisco-endpoint", "--cisco-api-key-env", "--cisco-timeout-ms"),
        ),
        WizardGoal(
            "hitl",
            "Require human approval (HITL)",
            summary="Gate high-severity verdicts on a human approval step.",
            presets={"--human-approval": "yes"},
            fields=("--human-approval", "--hilt-min-severity"),
        ),
        WizardGoal(
            "detection",
            "Tune global detection strategy",
            summary="Change the detection strategy for all active connectors.",
            presets={"@Scope": _GUARDRAIL_SCOPE_GLOBAL},
            fields=("Scope", "--detection-strategy"),
        ),
        WizardGoal(
            "rule-pack",
            "Change a connector rule pack",
            summary="Change only one active connector's rule pack override.",
            fields=("Connector", "--rule-pack"),
        ),
    )


def _connector_setup_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "add",
            "Add or configure a connector",
            summary="Protect one more agent next to the ones already set up (or replace them).",
            presets={"@Action": "setup"},
            # The task text promises the guardrail mode; without the field a
            # connector added here always got the CLI default (GAP-1957).
            fields=("Connector", "Action", "Guardrail Mode", "Replace Existing", "Restart Gateway"),
        ),
        WizardGoal(
            "proxy-stack",
            "Set up a connector with local Grafana",
            summary="Set up a hook connector and start the local Prometheus/Loki/Tempo/Grafana stack.",
            presets={"@Action": "setup", "@Local Stack": "yes"},
            fields=("Connector", "Guardrail Mode", "Local Stack"),
        ),
        WizardGoal(
            "bulk",
            "Choose which agents DefenseClaw protects",
            summary="Pick every agent to protect in one step; the others are turned off.",
            presets={"@Action": "batch"},
            fields=(
                "Connectors (CSV)",
                "Detected Connectors",
                "All Supported Connectors",
                "Action",
                "Guardrail Mode",
                "Restart Gateway",
            ),
        ),
        WizardGoal(
            "rerun",
            "Re-run setup for a connector",
            summary="Set up one connector again, for example to change its guardrail mode.",
            presets={"@Action": "setup"},
            fields=("Connector", "Action", "Guardrail Mode", "Scanner Mode", "Verify After Setup"),
        ),
        WizardGoal(
            "remove",
            "Remove a connector",
            summary="Drop a connector from the active set; force is required for the last connector.",
            presets={"@Action": "remove"},
            fields=("Connector", "Action", "Restart Gateway", "Force Last Connector Removal"),
        ),
    )


def _credentials_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "list",
            "See which credentials are set",
            summary="List env-backed credentials and their status.",
            presets={"@Action": "list"},
            fields=("Action",),
        ),
        WizardGoal(
            "check",
            "Check required credentials",
            summary="Verify every required credential is present.",
            presets={"@Action": "check"},
            fields=("Action",),
        ),
        WizardGoal(
            "fill",
            "Fill in missing required credentials",
            summary="Prompt for any required credential that is unset.",
            presets={"@Action": "fill-missing"},
            fields=("Action",),
        ),
        WizardGoal(
            "set",
            "Set one API key",
            summary="Store one key in ~/.defenseclaw/.env; it is sent on stdin and never shown.",
            presets={"@Action": "set"},
            fields=("Action", "Env Name", "Secret Value"),
        ),
        WizardGoal(
            "remove",
            "Remove a stored credential",
            summary="Delete one entry from ~/.defenseclaw/.env (a rotated or mistyped key).",
            presets={"@Action": "remove"},
            fields=("Action", "Env Name"),
        ),
    )


def _local_observability_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "status",
            "Check stack status",
            summary="Report whether the local OTel stack is running.",
            presets={"@Action": "status"},
            fields=("Action",),
        ),
        WizardGoal(
            "up",
            "Start the local stack",
            summary="Bring up the bundled OTel stack (needs Docker).",
            presets={"@Action": "up"},
            fields=("Action", "Timeout", "Signals", "No Wait"),
        ),
        WizardGoal(
            "url",
            "Show the dashboard URL",
            summary="Print the local dashboard URL.",
            presets={"@Action": "url"},
            fields=("Action",),
        ),
        WizardGoal(
            "logs",
            "Tail logs",
            summary="Stream logs from a stack service.",
            presets={"@Action": "logs"},
            fields=("Action", "Service", "Follow"),
        ),
        WizardGoal(
            "down",
            "Stop the stack",
            summary="Stop the local OTel stack.",
            presets={"@Action": "down"},
            fields=("Action",),
        ),
        WizardGoal(
            "reset",
            "Reset / wipe the stack",
            summary="Tear down and delete local stack state.",
            presets={"@Action": "reset"},
            fields=("Action", "Confirm Reset"),
        ),
    )


def _token_rotation_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "auto",
            "Rotate the gateway token",
            summary="Make a new gateway token and update every protected agent's hooks; nothing changes if a step fails.",
            fields=("Refresh Hooks",),
        ),
        WizardGoal(
            "specific",
            "Rotate the gateway token, refresh one agent",
            summary="Same new token for every agent; only the chosen agent's hooks are rewritten now.",
            fields=("Connector", "Refresh Hooks"),
        ),
    )


def _custom_providers_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "list",
            "List custom provider instances",
            summary="Show every configured custom-provider overlay.",
            presets={"@Action": "list"},
        ),
        WizardGoal(
            "show",
            "Show one instance",
            summary="Print one instance's configuration.",
            presets={"@Action": "show"},
        ),
        WizardGoal(
            "add-openai",
            "Add a self-hosted / OpenAI-compatible instance",
            summary="Register an OpenAI-compatible endpoint.",
            presets={"@Action": "add", "--base-provider-type": "openai"},
        ),
        WizardGoal(
            "add-regional",
            "Add a regional instance (Bedrock / Vertex / Azure)",
            summary="Register a cloud-region provider overlay.",
            presets={"@Action": "add"},
        ),
        WizardGoal(
            "remove",
            "Remove an instance",
            summary="Delete a custom-provider overlay.",
            presets={"@Action": "remove"},
        ),
    )


def _skill_scanner_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "strictness",
            "Set scan strictness",
            summary="Choose the scan policy and lenient mode.",
            fields=("Scan Policy", "Lenient Mode"),
        ),
        WizardGoal(
            "llm",
            "Enable LLM-assisted analysis",
            summary="Turn on the LLM analyzer and pick its model.",
            presets={"--use-llm": "yes"},
            fields=("LLM Analyzer", "LLM Provider", "LLM Model", "LLM Consensus Runs"),
        ),
        WizardGoal(
            "analyzers",
            "Turn on extra analyzers",
            summary="Enable behavioral, meta, and trigger analyzers.",
            fields=("Behavioral Analyzer", "Meta Analyzer", "Trigger Analyzer"),
        ),
        WizardGoal(
            "threat-intel",
            "Connect threat intel (VirusTotal / AI Defense)",
            summary="Enable VirusTotal and Cisco AI Defense analyzers.",
            fields=("VirusTotal Scanner", "AI Defense Analyzer"),
        ),
    )


def _mcp_scanner_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "analyzers",
            "Choose which analyzers run",
            summary="Pick the analyzer list for MCP scans.",
            fields=("Analyzers",),
        ),
        WizardGoal(
            "llm",
            "Enable LLM analysis",
            summary="Select the LLM provider and model for MCP scans.",
            fields=("LLM Provider", "LLM Model"),
        ),
        WizardGoal(
            "remote",
            "Use a remote scan API",
            summary="Point scans at a remote scan API endpoint.",
            fields=("API Endpoint", "API Key Env", "API Timeout (ms)"),
        ),
        WizardGoal(
            "targets",
            "Scan prompts / resources / instructions",
            summary="Choose which MCP surfaces to scan.",
            fields=("Scan Prompts", "Scan Resources", "Scan Instructions"),
        ),
    )


def _gateway_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "ports",
            "Change host and ports",
            summary="Set the gateway host, WebSocket port, and API port.",
            fields=("Host", "Port", "API Port"),
        ),
        WizardGoal(
            "remote",
            "Connect to a remote gateway",
            summary="Target a remote gateway with an auth token.",
            presets={"--remote": "yes"},
            fields=("Remote Mode", "Host", "Port", "API Port", "Auth Token"),
        ),
        WizardGoal(
            "token",
            "Set the auth token",
            summary="Set the gateway auth token directly.",
            fields=("Auth Token",),
        ),
        WizardGoal(
            "ssm",
            "Pull the token from AWS SSM",
            summary="Resolve the auth token from an SSM parameter.",
            fields=("SSM Param", "SSM Region", "SSM Profile"),
        ),
    )


def _splunk_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "o11y",
            "Send to Splunk Observability Cloud",
            summary="Stream telemetry to Splunk Observability Cloud.",
            presets={"@Mode": "splunk-o11y"},
            fields=("Mode", "Realm", "Access Token", "Apply Dashboards After"),
        ),
        WizardGoal(
            "local-docker",
            "Run a local Splunk (Docker)",
            summary="Spin up a local Splunk via Docker for logs.",
            presets={"@Mode": "local-docker"},
            fields=("Mode", "Accept Splunk License", "Traces", "Metrics", "Logs Export"),
            available_when=lambda _cfg: local_splunk_stack_supported(),
        ),
        WizardGoal(
            "enterprise",
            "Send to Splunk Enterprise HEC",
            summary="Forward events to a Splunk Enterprise HEC endpoint.",
            presets={"@Mode": "enterprise"},
            fields=("Mode", "HEC Endpoint", "HEC Token", "HEC Index", "HEC Source", "HEC Sourcetype"),
        ),
    )


def _observability_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "list",
            "List destinations",
            summary="List the telemetry destinations.",
            presets={"@Action": "list"},
            fields=("Action", "JSON Output"),
        ),
        WizardGoal(
            "enable",
            "Enable a destination",
            summary="Enable a destination by name.",
            presets={"@Action": "enable"},
            fields=("Action", "Name"),
        ),
        WizardGoal(
            "disable",
            "Disable a destination",
            summary="Disable a destination by name.",
            presets={"@Action": "disable"},
            fields=("Action", "Name"),
        ),
        WizardGoal(
            "remove",
            "Remove a destination",
            summary="Remove a destination by name.",
            presets={"@Action": "remove"},
            fields=("Action", "Name"),
        ),
        WizardGoal(
            "splunk-o11y",
            "Splunk Observability Cloud",
            summary="Add the Splunk Observability Cloud preset.",
            presets={"@Preset": "splunk-o11y"},
        ),
        WizardGoal(
            "datadog",
            "Datadog",
            summary="Add the Datadog preset.",
            presets={"@Preset": "datadog"},
        ),
        WizardGoal(
            "honeycomb",
            "Honeycomb",
            summary="Add the Honeycomb preset.",
            presets={"@Preset": "honeycomb"},
        ),
        WizardGoal(
            "newrelic",
            "New Relic",
            summary="Add the New Relic preset.",
            presets={"@Preset": "newrelic"},
        ),
        WizardGoal(
            "grafana-cloud",
            "Grafana Cloud",
            summary="Add the Grafana Cloud preset.",
            presets={"@Preset": "grafana-cloud"},
        ),
        WizardGoal(
            "galileo",
            "Galileo Cloud / Self-hosted",
            summary="Send GenAI OTLP traces to a Galileo project and Log stream.",
            presets={"@Preset": "galileo"},
        ),
        WizardGoal(
            "otlp",
            "Generic OTLP endpoint",
            summary="Add a generic OTLP exporter preset.",
            presets={"@Preset": "otlp"},
        ),
    )


def _webhooks_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "list",
            "List webhooks",
            summary="List global webhooks or one connector's per-connector webhooks.",
            presets={"@Action": "list"},
            fields=("Action", "Connector", "JSON Output"),
        ),
        WizardGoal(
            "enable",
            "Enable a webhook",
            summary="Enable a global or per-connector webhook by name.",
            presets={"@Action": "enable"},
            fields=("Action", "Name", "Connector"),
        ),
        WizardGoal(
            "disable",
            "Disable a webhook",
            summary="Disable a global or per-connector webhook by name.",
            presets={"@Action": "disable"},
            fields=("Action", "Name", "Connector"),
        ),
        WizardGoal(
            "remove",
            "Remove a webhook",
            summary="Remove a global or per-connector webhook by name.",
            presets={"@Action": "remove"},
            fields=("Action", "Name", "Connector"),
        ),
        WizardGoal(
            "slack",
            "Add a Slack alert webhook",
            summary="Send alerts to a Slack incoming webhook.",
            presets={"@Type": "slack"},
        ),
        WizardGoal(
            "pagerduty",
            "Add PagerDuty incidents",
            summary="Open PagerDuty incidents via Events API v2.",
            presets={"@Type": "pagerduty"},
        ),
        WizardGoal(
            "webex",
            "Add a Cisco Webex bot",
            summary="Post alerts to a Cisco Webex room.",
            presets={"@Type": "webex"},
        ),
        WizardGoal(
            "generic",
            "Add a generic HMAC webhook",
            summary="POST signed JSON to a generic endpoint.",
            presets={"@Type": "generic"},
        ),
    )


def _registries_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "clawhub",
            "Add a ClawHub catalog",
            summary="Register a ClawHub catalog source.",
            presets={"--kind": "clawhub"},
            fields=("Source id", "Content", "Sync Now", "Scan After Sync"),
        ),
        WizardGoal(
            "http",
            "Add an HTTP manifest (YAML/JSON)",
            summary="Register an HTTP manifest catalog.",
            presets={"--kind": "http_yaml"},
            fields=("Source id", "Content", "Manifest URL", "Auth env (optional)"),
        ),
        WizardGoal(
            "smithery",
            "Add Smithery / skills.sh",
            summary="Register a Smithery or skills.sh source.",
            presets={"--kind": "smithery"},
            fields=("Source id", "Content"),
        ),
        WizardGoal(
            "git",
            "Add a Git / file source",
            summary="Register a Git or local file catalog.",
            presets={"--kind": "git"},
            fields=("Source id", "Content", "Manifest URL"),
        ),
    )


def _notifications_routing_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "verdicts",
            "Choose which verdicts notify me",
            summary="Pick which verdicts show a desktop notification.",
            fields=(
                "Block (enforced)",
                "Block (would-block / observe)",
                "HITL Approval",
                "Restart Gateway After",
            ),
        ),
        WizardGoal(
            "sources",
            "Choose which sources notify me",
            summary="Pick which parts of DefenseClaw can notify you.",
            fields=(
                "Source: Hooks",
                "Source: Guardrail",
                "Source: Asset Policy",
                "Restart Gateway After",
            ),
        ),
    )


def _ai_discovery_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "toggle",
            "Turn AI discovery on / off",
            summary="Enable or disable the AI discovery sidecar.",
            fields=("Enable",),
        ),
        WizardGoal(
            "cadence",
            "Set the scan cadence",
            summary="Tune the discovery mode and scan intervals.",
            fields=("Mode", "Scan Interval (min)", "Process Poll (sec)"),
        ),
        WizardGoal(
            "scope",
            "Set where it scans (scope)",
            summary="Choose scan roots and per-scan limits.",
            fields=("Scan Roots (CSV)", "Max Files / Scan", "Max Bytes / File"),
        ),
        WizardGoal(
            "sources",
            "Choose detection sources",
            summary="Toggle shell history, manifests, env, and domains.",
            fields=("Shell History", "Package Manifests", "Env Var Names", "Network Domains"),
        ),
    )


def _splunk_dashboards_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "apply",
            "Apply dashboards",
            summary="Apply the Splunk O11y dashboards.",
            presets={"@Action": "apply"},
            fields=("Action", "With Detectors", "Enable Detectors"),
        ),
        WizardGoal(
            "apply-detectors",
            "Apply dashboards + detectors",
            summary="Apply dashboards and enable detectors.",
            presets={"@Action": "apply", "--with-detectors": "yes", "--enable-detectors": "yes"},
            fields=("Action", "With Detectors", "Enable Detectors"),
        ),
        WizardGoal(
            "destroy",
            "Remove dashboards",
            summary="Destroy the Splunk O11y dashboards.",
            presets={"@Action": "destroy"},
            fields=("Action",),
        ),
    )


def _trusted_paths_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "list",
            "List trusted prefixes",
            summary="Show built-in and operator-added binary-prefix trust roots.",
            presets={"@Action": "list"},
            fields=("Action", "JSON Output"),
        ),
        WizardGoal(
            "add",
            "Trust a connector binary directory",
            summary="Add a directory prefix used for connector binary discovery.",
            presets={"@Action": "add"},
            fields=("Action", "Directory", "Force"),
        ),
        WizardGoal(
            "remove",
            "Remove an operator-added prefix",
            summary="Remove a trusted prefix from the operator-managed list.",
            presets={"@Action": "remove"},
            fields=("Action", "Directory"),
        ),
    )


def _guardrail_actions_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "status",
            "Show guardrail status",
            summary="Show the full active connector roster, or narrow to one connector.",
            presets={"@Action": "status"},
            fields=("Scope", "Connector", "Action"),
        ),
        WizardGoal(
            "enable",
            "Enable guardrail",
            summary="Enable globally or re-enable one connector override.",
            presets={"@Action": "enable"},
            fields=("Scope", "Connector", "Action", "Restart Gateway"),
        ),
        WizardGoal(
            "disable",
            "Disable guardrail",
            summary="Disable globally or disable one connector override.",
            presets={"@Action": "disable"},
            fields=("Scope", "Connector", "Action", "Restart Gateway"),
        ),
        WizardGoal(
            "fail-mode",
            "Set fail mode",
            summary="Set fail-open/fail-closed globally or for one connector.",
            presets={"@Action": "fail-mode"},
            fields=("Scope", "Connector", "Action", "Fail Mode", "Restart Gateway"),
        ),
        WizardGoal(
            "hilt",
            "Set human approval",
            summary="Toggle HILT and severity globally or for one connector.",
            presets={"@Action": "hilt"},
            fields=("Scope", "Connector", "Action", "HITL State", "Approval Min Severity", "Restart Gateway"),
        ),
        WizardGoal(
            "block-message",
            "Set block message",
            summary="Set or clear the custom block message globally or for one connector.",
            presets={"@Action": "block-message"},
            fields=("Scope", "Connector", "Action", "Block Message", "Clear Message", "Restart Gateway"),
        ),
    )


_REDACTION_ADVANCED_FIELDS: tuple[str, ...] = (
    "Action",
    "Profile",
    "Collect Logs",
    "Collect Traces",
    "Collect Metrics",
    "Bucket",
    "Inherit Bucket Profile",
    "Custom Profile Name",
    "Extends",
    "Detector Groups (CSV)",
    *(f"Field: {field_class}" for field_class in REDACTION_FIELD_CLASSES),
    "Replace With",
    "Destination",
    "Route Name",
    "Signals (CSV)",
    "Buckets (CSV)",
    "Sources (CSV)",
    "Connectors (CSV)",
    "Producer Actions (CSV)",
    "Event Names (CSV)",
    "Minimum Severity",
    "Route Action",
    "Position",
    "JSON Output",
    "Dry Run",
    "Restart Gateway",
)


def _redaction_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "status",
            "Inspect effective redaction",
            summary=f"Show compiler-owned destination and {len(REDACTION_BUCKETS)}-bucket policy.",
            presets={"@Action": "status"},
            fields=("Action", "JSON Output"),
        ),
        WizardGoal(
            "remove-all",
            "Remove all configurable redaction",
            summary="Select profile none everywhere; dry-run is on by default.",
            presets={"@Action": "remove-all"},
            fields=("Action", "Dry Run", "JSON Output", "Restart Gateway"),
        ),
        WizardGoal(
            "apply-all",
            "Apply one profile everywhere",
            summary="Clear narrower overrides and use one profile on every configurable projection.",
            presets={"@Action": "apply-all"},
            fields=("Action", "Profile", "Dry Run", "JSON Output", "Restart Gateway"),
        ),
        WizardGoal(
            "baseline",
            "Change the global baseline",
            summary="Set the inherited default profile without replacing narrower overrides.",
            presets={"@Action": "apply-defaults"},
            fields=("Action", "Profile", "Dry Run", "JSON Output", "Restart Gateway"),
        ),
        WizardGoal(
            "advanced",
            "Show advanced settings",
            summary="Buckets, collection, custom profiles, destinations, selectors, and ordered routes.",
            presets={"@Action": "bucket-set"},
            fields=_REDACTION_ADVANCED_FIELDS,
        ),
        WizardGoal(
            "interactive",
            "Open the complete guided workflow",
            summary="Run the CLI wizard in Activity with prompts and staged review.",
            presets={"@Action": "interactive"},
            fields=("Action",),
        ),
    )


def _acp_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "observe",
            "Observe ACP traffic",
            summary="Install the guard without blocking traffic.",
            presets={"--activate": "no"},
            fields=("Client", "Agent", "Profile", "Action Mode"),
        ),
        WizardGoal(
            "action",
            "Enforce ACP policy",
            summary="Fail closed and block denied ACP operations.",
            presets={"--activate": "yes"},
            fields=("Client", "Agent", "Profile", "Action Mode"),
        ),
        WizardGoal(
            "enterprise",
            "Enroll managed enterprise ACP",
            summary="Use centrally pinned policy and a guardian-provisioned per-binding token.",
            presets={"--managed": "yes"},
            fields=(
                "Client",
                "Agent",
                "Profile",
                "Action Mode",
                "Managed Enrollment",
                "Runtime Data Dir",
                "Token File",
            ),
        ),
    )


# Per-wizard goal builders. Each returns the *contextual* goals (without the
# trailing Advanced entry, which ``wizard_goals`` always appends). Lambdas keep
# resolution lazy so builders can live anywhere in the module.
_WIZARD_GOAL_BUILDERS: dict[SetupWizard, Any] = {
    SetupWizard.CONNECTOR_SETUP: _connector_setup_goals,
    SetupWizard.CREDENTIALS: _credentials_goals,
    SetupWizard.LLM: _llm_goals,
    SetupWizard.LOCAL_OBSERVABILITY: _local_observability_goals,
    SetupWizard.TOKEN_ROTATION: _token_rotation_goals,
    SetupWizard.CUSTOM_PROVIDERS: _custom_providers_goals,
    SetupWizard.SKILL_SCANNER: _skill_scanner_goals,
    SetupWizard.MCP_SCANNER: _mcp_scanner_goals,
    SetupWizard.GATEWAY: _gateway_goals,
    SetupWizard.GUARDRAIL: _guardrail_goals,
    SetupWizard.SPLUNK: _splunk_goals,
    SetupWizard.OBSERVABILITY: _observability_goals,
    SetupWizard.WEBHOOKS: _webhooks_goals,
    SetupWizard.REGISTRIES: _registries_goals,
    SetupWizard.NOTIFICATIONS_ROUTING: _notifications_routing_goals,
    SetupWizard.AI_DISCOVERY: _ai_discovery_goals,
    SetupWizard.SPLUNK_DASHBOARDS: _splunk_dashboards_goals,
    SetupWizard.TRUSTED_PATHS: _trusted_paths_goals,
    SetupWizard.GUARDRAIL_ACTIONS: _guardrail_actions_goals,
    SetupWizard.REDACTION: _redaction_goals,
    SetupWizard.ACP_GUARD: _acp_goals,
}


def wizard_goals(wizard: SetupWizard | int, cfg: object | Mapping[str, Any] | None = None) -> tuple[WizardGoal, ...]:
    """Resolve the goal menu for ``wizard``.

    Goals whose ``available_when`` predicate is False for the current config
    are dropped. Most wizards append an "Advanced — show all settings" goal so
    the flat editor stays reachable; lifecycle-only wizards intentionally keep
    the menu curated.
    """

    wizard = SetupWizard(wizard)
    builder = _WIZARD_GOAL_BUILDERS.get(wizard)
    goals: tuple[WizardGoal, ...] = ()
    if builder is not None:
        try:
            goals = tuple(goal for goal in builder(cfg) if goal.is_available(cfg))
        except Exception:  # noqa: BLE001 - a bad builder must not break the menu.
            goals = ()
    if wizard in _NO_ADVANCED_GOAL_WIZARDS:
        return goals
    return (*goals, _ADVANCED_GOAL)


def _seed_parametrized_fields(
    wizard: SetupWizard,
    presets: Mapping[str, str],
    cfg: object | Mapping[str, Any] | None,
) -> tuple[WizardFormField, ...] | None:
    """Rebuild the base field set for wizards whose form shape depends on a
    preset/type selector that has no dependent-field rebuilder (Observability
    presets and Webhook channel types). Returns ``None`` when no swap applies.
    """

    if wizard == SetupWizard.OBSERVABILITY:
        preset_id = (presets.get("@Preset") or "").strip()
        if preset_id:
            return observability_wizard_fields(preset_id, cfg)
    if wizard == SetupWizard.WEBHOOKS:
        channel = (presets.get("@Type") or "").strip()
        if channel:
            return webhook_wizard_fields(channel)
    return None


def _effective_strategy_text(cfg: object | Mapping[str, Any] | None, strategy: str) -> str:
    """``strategy`` as the connectors run it.

    A judge strategy with the judge off (or gated to no active connector)
    scans regex only, as ``defenseclaw guardrail status`` says; the header
    read "Strategy: regex_judge" there (GAP-2092).
    """

    if strategy not in {"regex_judge", "judge_first"}:
        return strategy
    if not bool(get_config_value(cfg, "guardrail.judge.enabled", False)):
        return "regex_only (judge off)"
    gate = get_config_value(cfg, "guardrail.judge.hook_connectors", None) or ()
    gated = {str(name).strip().lower() for name in gate}
    connectors = _active_connector_names_for_setup(cfg)
    if "*" in gated or _any_active_connector_is_proxy(cfg) or not connectors or gated & set(connectors):
        return strategy
    return "regex_only (judge on for no active connector)"


def wizard_state_summary(wizard: SetupWizard | int, cfg: object | Mapping[str, Any] | None = None) -> str:
    """One-line "here's what's configured today" string for the goal menu.

    Returns an empty string for wizards without a useful summary so the
    renderer can omit the line entirely.
    """

    wizard = SetupWizard(wizard)
    if wizard == SetupWizard.LLM:
        provider = _cfg_str(cfg, "llm.provider")
        model = _cfg_str(cfg, "llm.model")
        main = f"{provider}/{model}" if (provider and model) else (model or provider or "not set")
        judge = _cfg_str(cfg, "guardrail.judge.llm.model") or _cfg_str(cfg, "guardrail.judge.model") or "not set"
        connectors = _active_connector_names_for_setup(cfg)
        connector_summary = ", ".join(connectors) if connectors else "none"
        role = "judge+agent available" if _any_active_connector_is_proxy(cfg) else "judge only"
        return f"Main: {main}  ·  Judge: {judge}  ·  Connectors: {connector_summary} ({role})"
    if wizard == SetupWizard.REDACTION:
        profile = _cfg_str(cfg, "observability.defaults.redaction_profile", "none") or "none"
        posture = "unredacted" if profile == "none" else "redacted"
        return f"Default profile: {profile} ({posture})  ·  Each observability destination can set its own profile"
    if wizard == SetupWizard.GUARDRAIL:
        mode = guardrail_mode_label(cfg)
        enabled = "on" if _guardrail_enabled(cfg) else "off"
        strategy = _cfg_str(cfg, "guardrail.detection_strategy", "regex_only") or "regex_only"
        return f"Guardrail: {enabled}  ·  Mode: {mode}  ·  Strategy: {_effective_strategy_text(cfg, strategy)}"
    if wizard == SetupWizard.CONNECTOR_SETUP:
        connectors = _active_connector_names_for_setup(cfg)
        return f"Active connectors: {', '.join(connectors) if connectors else 'not set'}"
    if wizard == SetupWizard.AI_DISCOVERY:
        enabled = "on" if bool(get_config_value(cfg, "ai_discovery.enabled", True)) else "off"
        mode = _cfg_str(cfg, "ai_discovery.mode", "enhanced") or "enhanced"
        return f"AI discovery: {enabled}  ·  Mode: {mode}"
    if wizard == SetupWizard.GATEWAY:
        host = _cfg_str(cfg, "gateway.api_bind") or "127.0.0.1"
        port = _cfg_str(cfg, "gateway.api_port") or "?"
        return f"Gateway API: {host}:{port}"
    return ""


_AI_DISCOVERY_MODES = AI_DISCOVERY_MODES


def ai_discovery_wizard_fields(
    cfg: object | Mapping[str, Any] | None = None,
) -> tuple[WizardFormField, ...]:
    """Build the AI Discovery wizard form.

    Defaults are seeded from the active config so the operator can
    treat the wizard as a tuning dialog (press Enter on each row to
    keep the current value), mirroring the CLI's ``discovery setup``
    behavior. The wizard maps to either ``agent discovery enable`` or
    ``agent discovery disable`` depending on the ``Enable`` toggle.
    """

    def _cfg_int(path: str, fallback: int) -> str:
        val = get_config_value(cfg, f"ai_discovery.{path}", fallback)
        try:
            return str(int(val))
        except (TypeError, ValueError):
            return str(fallback)

    def _cfg_bool(path: str, fallback: bool) -> str:
        val = get_config_value(cfg, f"ai_discovery.{path}", fallback)
        return "yes" if bool(val) else "no"

    enabled_default = _cfg_bool("enabled", True)
    mode_current = get_config_value(cfg, "ai_discovery.mode", "enhanced")
    mode_default = mode_current if mode_current in _AI_DISCOVERY_MODES else "enhanced"

    roots_default_raw = get_config_value(cfg, "ai_discovery.scan_roots", ("~",))
    if isinstance(roots_default_raw, (list, tuple)):
        roots_default = ", ".join(str(item) for item in roots_default_raw) or "~"
    else:
        roots_default = str(roots_default_raw or "~")

    return (
        WizardFormField("Cadence", "section"),
        WizardFormField(
            "Enable",
            "bool",
            value=enabled_default,
            default=enabled_default,
        ),
        WizardFormField(
            "Mode",
            "choice",
            "--mode",
            value=mode_default,
            default=mode_default,
            options=_AI_DISCOVERY_MODES,
        ),
        WizardFormField(
            "Scan Interval (min)",
            "int",
            "--scan-interval-min",
            value=_cfg_int("scan_interval_min", 5),
            default=_cfg_int("scan_interval_min", 5),
        ),
        WizardFormField(
            "Process Poll (sec)",
            "int",
            "--process-interval-s",
            value=_cfg_int("process_interval_s", 60),
            default=_cfg_int("process_interval_s", 60),
        ),
        WizardFormField("Scope", "section"),
        WizardFormField(
            "Scan Roots (CSV)",
            "string",
            "--scan-roots",
            value=roots_default,
            default=roots_default,
        ),
        WizardFormField(
            "Max Files / Scan",
            "int",
            "--max-files-per-scan",
            value=_cfg_int("max_files_per_scan", 1000),
            default=_cfg_int("max_files_per_scan", 1000),
        ),
        WizardFormField(
            "Max Bytes / File",
            "int",
            "--max-file-bytes",
            value=_cfg_int("max_file_bytes", 524288),
            default=_cfg_int("max_file_bytes", 524288),
        ),
        WizardFormField("Detection Sources", "section"),
        WizardFormField(
            "Shell History",
            "bool",
            "--include-shell-history",
            "--no-include-shell-history",
            value=_cfg_bool("include_shell_history", True),
            default=_cfg_bool("include_shell_history", True),
        ),
        WizardFormField(
            "Package Manifests",
            "bool",
            "--include-package-manifests",
            "--no-include-package-manifests",
            value=_cfg_bool("include_package_manifests", True),
            default=_cfg_bool("include_package_manifests", True),
        ),
        WizardFormField(
            "Env Var Names",
            "bool",
            "--include-env-var-names",
            "--no-include-env-var-names",
            value=_cfg_bool("include_env_var_names", True),
            default=_cfg_bool("include_env_var_names", True),
        ),
        WizardFormField(
            "Network Domains",
            "bool",
            "--include-network-domains",
            "--no-include-network-domains",
            value=_cfg_bool("include_network_domains", True),
            default=_cfg_bool("include_network_domains", True),
        ),
        WizardFormField(
            "Online Model Provenance",
            "bool",
            "--lookup-model-provenance-online",
            "--no-lookup-model-provenance-online",
            value=_cfg_bool("lookup_model_provenance_online", False),
            default=_cfg_bool("lookup_model_provenance_online", False),
        ),
        WizardFormField("Output / Privacy", "section"),
        WizardFormField(
            "Honor Workspace Signatures",
            "bool",
            "--allow-workspace-signatures",
            "--no-allow-workspace-signatures",
            value=_cfg_bool("allow_workspace_signatures", False),
            default=_cfg_bool("allow_workspace_signatures", False),
        ),
        WizardFormField(
            "Store Raw Local Paths",
            "bool",
            "--store-raw-local-paths",
            "--no-store-raw-local-paths",
            value=_cfg_bool("store_raw_local_paths", False),
            default=_cfg_bool("store_raw_local_paths", False),
        ),
        WizardFormField("Rollout", "section"),
        WizardFormField(
            "Restart Gateway",
            "bool",
            "--restart",
            "--no-restart",
            value="yes",
            default="yes",
        ),
        WizardFormField(
            "Scan Immediately",
            "bool",
            "--scan",
            "--no-scan",
            value="yes",
            default="yes",
        ),
    )


def _build_ai_discovery_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    """Translate the AI Discovery wizard form to a CLI invocation.

    ``Enable=no`` resolves to ``agent discovery disable``; the disable
    sub-command only consumes ``--restart`` and ``--yes``, so we drop
    the tuning flags in that branch.
    """

    enable = wizard_bool_value(fields, "Enable", "yes")
    restart = wizard_bool_value(fields, "Restart Gateway", "yes")
    scan = wizard_bool_value(fields, "Scan Immediately", "yes")

    if enable == "no":
        args: list[str] = ["agent", "discovery", "disable", "--yes"]
        if restart == "no":
            args.append("--no-restart")
        return tuple(args)

    args = ["agent", "discovery", "enable", "--yes"]
    if mode := wizard_field_value(fields, "Mode"):
        args.extend(("--mode", mode))
    if interval := wizard_field_value(fields, "Scan Interval (min)"):
        args.extend(("--scan-interval-min", interval))
    if poll := wizard_field_value(fields, "Process Poll (sec)"):
        args.extend(("--process-interval-s", poll))
    if roots := wizard_field_value(fields, "Scan Roots (CSV)"):
        # The CLI accepts a raw CSV string and normalizes internally
        # (``_normalize_scan_roots``); we keep that shape so a future
        # CLI change to the splitter is honored without a TUI patch.
        args.extend(("--scan-roots", roots))
    if max_files := wizard_field_value(fields, "Max Files / Scan"):
        args.extend(("--max-files-per-scan", max_files))
    if max_bytes := wizard_field_value(fields, "Max Bytes / File"):
        args.extend(("--max-file-bytes", max_bytes))

    bool_flags: tuple[tuple[str, str, str], ...] = (
        ("Shell History", "--include-shell-history", "--no-include-shell-history"),
        ("Package Manifests", "--include-package-manifests", "--no-include-package-manifests"),
        ("Env Var Names", "--include-env-var-names", "--no-include-env-var-names"),
        ("Network Domains", "--include-network-domains", "--no-include-network-domains"),
        (
            "Online Model Provenance",
            "--lookup-model-provenance-online",
            "--no-lookup-model-provenance-online",
        ),
        ("Honor Workspace Signatures", "--allow-workspace-signatures", "--no-allow-workspace-signatures"),
        ("Store Raw Local Paths", "--store-raw-local-paths", "--no-store-raw-local-paths"),
    )
    for label, on_flag, off_flag in bool_flags:
        value = wizard_bool_value(fields, label, "yes")
        args.append(on_flag if value == "yes" else off_flag)

    if restart == "no":
        args.append("--no-restart")
    if scan == "no":
        args.append("--no-scan")
    return tuple(args)


def splunk_dashboards_wizard_fields() -> tuple[WizardFormField, ...]:
    """Apply / destroy chooser for the Splunk O11y dashboards command.

    The dashboards subgroup also accepts an optional name prefix (useful
    for smoke tests) and an explicit O11y API token; both are surfaced
    as optional fields so operators can override the env-derived
    defaults without dropping out to a shell.
    """

    return (
        WizardFormField(
            "Action",
            "choice",
            value="apply",
            default="apply",
            options=("apply", "destroy"),
        ),
        WizardFormField(
            "With Detectors",
            "bool",
            "--with-detectors",
            "--dashboards-only",
            value="no",
            default="no",
        ),
        WizardFormField(
            "Enable Detectors",
            "bool",
            "--enable-detectors",
            value="no",
            default="no",
        ),
        WizardFormField(
            "Name Prefix",
            "string",
            "--name-prefix",
        ),
        WizardFormField(
            "O11y API Token",
            "password",
            "--o11y-api-token",
        ),
        WizardFormField(
            "API URL",
            "string",
            "--api-url",
        ),
    )


def _build_splunk_dashboards_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    """Translate the dashboards wizard into the chosen sub-command argv.

    ``Action=destroy`` deliberately keeps ``--yes`` so the TUI doesn't
    park on the CLI's confirm prompt; the preview screen surfaced by
    ``_confirm_and_run_intent`` already covers the operator-consent
    moment for destructive runs.
    """

    action = wizard_field_value(fields, "Action") or "apply"
    args: list[str] = ["setup", "splunk", "dashboards", action, "--yes"]

    # ``--with-detectors`` is required for the detector tuning flag to
    # actually persist; leaving them coupled keeps the form honest.
    if wizard_bool_value(fields, "With Detectors", "no") == "yes":
        args.append("--with-detectors")
        if wizard_bool_value(fields, "Enable Detectors", "no") == "yes":
            args.append("--enable-detectors")

    if prefix := wizard_field_value(fields, "Name Prefix"):
        args.extend(("--name-prefix", prefix))
    if token := wizard_field_value(fields, "O11y API Token"):
        args.extend(("--o11y-api-token", token))
    if api_url := wizard_field_value(fields, "API URL"):
        args.extend(("--api-url", api_url))
    return tuple(args)


def notifications_routing_wizard_fields(
    cfg: object | Mapping[str, Any] | None = None,
) -> tuple[WizardFormField, ...]:
    """Per-slot toggle wizard for ``setup notifications-set``.

    Reads each slot's current value from the active config (when
    available) so the toggles surface the *current* state instead of
    factory defaults. Each slot is rendered as a wizard-only bool;
    ``build_wizard_args`` emits ``setup notifications-set <slot> on``
    or ``off`` for whichever slots differ from the snapshot the form
    was seeded with.
    """

    fields: list[WizardFormField] = [WizardFormField("Notification Toggles", "section")]
    for slot, label, fallback in NOTIFICATION_ROUTING_SLOTS:
        # Look up the current on/off state per slot. The dotted path
        # mirrors ``_NOTIFICATION_SLOTS`` from the CLI.
        if "." in slot:
            parent, attr = slot.split(".", 1)
            obj = get_config_value(cfg, f"notifications.{parent}", None)
            current = bool(getattr(obj, attr, fallback == "yes")) if obj is not None else (fallback == "yes")
        else:
            current = bool(get_config_value(cfg, f"notifications.{slot}", fallback == "yes"))
        value = "yes" if current else "no"
        fields.append(
            WizardFormField(label, "bool", value=value, default=value, hint=_NOTIFICATION_SLOT_HINTS.get(slot, ""))
        )
    fields.append(
        WizardFormField(
            "Restart Gateway After",
            "bool",
            value="yes",
            default="yes",
            hint=_RESTART_GATEWAY_HINT,
        )
    )
    return tuple(fields)


def notifications_routing_intents(
    fields: Sequence[WizardFormField],
) -> tuple[SetupCommandIntent, ...]:
    """Emit one ``setup notifications-set`` intent per toggle that
    changed away from its snapshot default. Each intent honors the
    operator's ``Restart Gateway After`` choice. Returning an empty
    tuple means "nothing to apply".
    """

    restart = wizard_bool_value(fields, "Restart Gateway After", "yes")
    intents: list[SetupCommandIntent] = []
    label_to_slot = {label: slot for slot, label, _ in NOTIFICATION_ROUTING_SLOTS}
    for field in fields:
        slot = label_to_slot.get(field.label)
        if slot is None:
            continue
        if field.value == field.default:
            continue
        value = "on" if field.value == "yes" else "off"
        args: list[str] = ["setup", "notifications-set", slot, value]
        if restart == "no":
            args.append("--no-restart")
        intents.append(
            SetupCommandIntent(
                label=f"notifications-set {slot}={value}",
                args=tuple(args),
                origin="setup-wizard",
            )
        )
    return tuple(intents)


def _build_token_rotation_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    args = ["setup", "rotate-token", "--yes"]
    if connector := wizard_field_value(fields, "Connector"):
        args.extend(("--connector", connector))
    if wizard_bool_value(fields, "Refresh Hooks", "yes") == "no":
        args.append("--no-restart")
    return tuple(args)


def _build_trusted_paths_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    action = wizard_field_value(fields, "Action") or "list"
    args = ["setup", "trusted-paths", action]
    if action in {"add", "remove"}:
        if directory := wizard_field_value(fields, "Directory", raw=True):
            args.append(directory.strip())
    if action == "add" and wizard_bool_value(fields, "Force", "no") == "yes":
        args.append("--force")
    if wizard_bool_value(fields, "JSON Output", "no") == "yes":
        args.append("--json")
    return tuple(args)


def _build_observability_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    action = wizard_field_value(fields, "Action") or "add"
    connector = wizard_field_value(fields, "Connector")
    if action == "list":
        args = ["setup", "observability", "list"]
        if connector:
            args.extend(("--connector", connector))
        if wizard_bool_value(fields, "JSON Output", "no") == "yes":
            args.append("--json")
        return tuple(args)
    if action in {"enable", "disable", "remove"}:
        args = ["setup", "observability", action]
        if name := wizard_field_value(fields, "Name", raw=True):
            args.append(name.strip())
        if connector:
            args.extend(("--connector", connector))
        if action == "remove":
            args.append("--yes")
        return tuple(args)

    preset = next((field.value for field in fields if field.kind == "preset"), "")
    args = ["setup", "observability", "add"]
    if preset:
        args.append(preset)
    args.append("--non-interactive")
    for field in fields:
        if field.kind in {"section", "preset"} or field.label in {"Action", "JSON Output"}:
            continue
        if field.kind == "bool":
            if field.value == field.default:
                continue
            if field.value == "yes" and field.flag:
                args.append(field.flag)
            elif field.value == "no" and field.no_flag:
                args.append(field.no_flag)
            continue
        if field.kind in {"string", "int", "choice", "password"}:
            value = field.value.strip()
            if value and field.flag:
                args.extend((field.flag, value))
    return tuple(args)


def _build_webhook_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    action = wizard_field_value(fields, "Action") or "add"
    connector = wizard_field_value(fields, "Connector")
    if action == "list":
        args = ["setup", "webhook", "list"]
        if connector:
            args.extend(("--connector", connector))
        if wizard_bool_value(fields, "JSON Output", "no") == "yes":
            args.append("--json")
        return tuple(args)
    if action in {"enable", "disable", "remove"}:
        args = ["setup", "webhook", action]
        if name := wizard_field_value(fields, "Name", raw=True):
            args.append(name.strip())
        if connector:
            args.extend(("--connector", connector))
        if action == "remove":
            args.append("--yes")
        return tuple(args)

    channel = next((field.value for field in fields if field.kind == "whtype"), "")
    args = ["setup", "webhook", "add"]
    if channel:
        args.append(channel)
    args.append("--non-interactive")
    hmac_disabled = wizard_bool_value(fields, "Enable HMAC Signing", "yes") == "no"
    for field in fields:
        if field.kind in {"section", "whtype"} or field.label in {"Action", "JSON Output", "Enable HMAC Signing"}:
            continue
        if hmac_disabled and field.label == "HMAC secret env (optional)":
            continue
        if field.kind == "bool":
            if field.value == field.default:
                continue
            if field.value == "yes" and field.flag:
                args.append(field.flag)
            elif field.value == "no" and field.no_flag:
                args.append(field.no_flag)
            continue
        if field.kind in {"string", "int", "choice", "password"}:
            value = field.value.strip()
            if value and field.flag:
                args.extend((field.flag, value))
    return tuple(args)


def _build_guardrail_actions_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    action = wizard_field_value(fields, "Action") or "status"
    connector = (
        wizard_field_value(fields, "Connector") if _guardrail_form_scope(fields) == _GUARDRAIL_SCOPE_CONNECTOR else ""
    )
    restart = wizard_bool_value(fields, "Restart Gateway", "yes")

    if action == "status":
        args = ["guardrail", "status"]
        if connector:
            args.extend(("--connector", connector))
        return tuple(args)

    if action in {"enable", "disable"}:
        args = ["guardrail", action, "--yes"]
    elif action == "fail-mode":
        args = ["guardrail", "fail-mode", wizard_field_value(fields, "Fail Mode") or "open", "--yes"]
    elif action == "hilt":
        args = ["guardrail", "hilt", wizard_field_value(fields, "HITL State") or "on", "--yes"]
        if severity := wizard_field_value(fields, "Approval Min Severity"):
            args.extend(("--min-severity", severity))
    elif action == "block-message":
        args = ["guardrail", "block-message"]
        if wizard_bool_value(fields, "Clear Message", "no") == "yes":
            args.append("--clear")
        elif message := wizard_field_value(fields, "Block Message", raw=True):
            args.append(message.strip())
        args.append("--yes")
    else:
        return ("guardrail", "status")

    if connector:
        args.extend(("--connector", connector))
    if restart == "no":
        args.append("--no-restart")
    return tuple(args)


_GUARDRAIL_CONNECTOR_SETUP_FLAGS: frozenset[str] = frozenset(
    {
        "--connector",
        "--mode",
        "--rule-pack",
        "--rule-pack-dir",
        "--block-message",
        "--human-approval",
        "--hilt-min-severity",
        "--restart",
        "--verify",
    }
)


def _build_guardrail_setup_args(
    fields: Sequence[WizardFormField],
    cfg: object | Mapping[str, Any] | None,
) -> tuple[str, ...]:
    """Build a Guardrail setup argv without crossing the selected scope.

    Connector scope is an allow-list: process-global scanner, port, Cisco,
    strategy, judge, LLM-role, and redaction flags cannot leak into the argv
    even if stale/injected form rows are present. Global scope omits a
    connector on multi-connector installs so its all-active effect is explicit.
    """

    scope = _guardrail_form_scope(fields)
    connector = wizard_field_value(fields, "Connector").strip()
    disable = any(field.flag == "--disable" and field.value == "yes" for field in fields)
    restart = wizard_bool_value(fields, "Restart After", "yes")

    if disable:
        args = ["guardrail", "disable", "--yes"]
        if scope == _GUARDRAIL_SCOPE_CONNECTOR and connector:
            args.extend(("--connector", connector))
        if restart == "no":
            args.append("--no-restart")
        return tuple(args)

    active = _active_connector_names_for_setup(cfg)
    base: list[str] = ["setup", "guardrail", "--non-interactive"]
    judge_provider = ""
    judge_model = ""
    judge_dirty = False
    for field in fields:
        if field.kind == "section" or field.flag == "--disable":
            continue
        if scope == _GUARDRAIL_SCOPE_CONNECTOR and field.flag and field.flag not in _GUARDRAIL_CONNECTOR_SETUP_FLAGS:
            continue
        if scope == _GUARDRAIL_SCOPE_GLOBAL and field.flag == "--connector" and len(active) > 1:
            continue
        if field.label == "Provider" and field.flag == "":
            judge_provider = field.value
            judge_dirty = judge_dirty or field.value != field.default
            continue
        if field.label == "Model" and field.flag == "--judge-model":
            judge_model = field.value
            judge_dirty = judge_dirty or field.value != field.default
            continue
        if field.kind == "bool":
            if field.flag in {"--human-approval", "--disable-redaction"}:
                if field.value == "yes" and field.flag:
                    base.append(field.flag)
                elif field.value == "no" and field.no_flag:
                    base.append(field.no_flag)
                continue
            if field.value == field.default:
                continue
            if field.value == "yes" and field.flag:
                base.append(field.flag)
            elif field.value == "no" and field.no_flag:
                base.append(field.no_flag)
            continue
        if field.kind not in {"string", "int", "choice", "password"} or not field.flag:
            continue
        if field.flag == "--block-message" and field.value != field.default:
            base.extend((field.flag, field.value))
            continue
        if not field.value or (field.value == field.default and not field.required):
            continue
        if field.flag in _GUARDRAIL_REPEATABLE_FLAGS:
            for item in (chunk.strip() for chunk in field.value.split(",")):
                if item:
                    base.extend((field.flag, item))
            continue
        base.extend((field.flag, field.value))

    if judge_dirty and judge_model:
        combined = f"{judge_provider}/{judge_model}" if judge_provider else judge_model
        base.extend(("--judge-model", combined))
    return tuple(base)


def _build_notifications_routing_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    intents = notifications_routing_intents(fields)
    if intents:
        return intents[0].args
    # No toggles changed — keep the regression guard happy by returning
    # the bare prefix; the wizard submitter surfaces a "nothing to
    # apply" hint to the operator.
    return WIZARD_COMMANDS[SetupWizard.NOTIFICATIONS_ROUTING]


# --- Sandbox wizard (slot 13) ---------------------------------------------

# (connector name, wizard label, command) for every harness the Go tree runs
# (harness.Names()); with openshell.harnesses empty, setup's defaults are on.
SANDBOX_WIZARD_HARNESSES: tuple[tuple[str, str, str], ...] = SANDBOX_HARNESS_SPECS


# sandboxcli.consentGatewayRestart: a bind-mount or telemetry change restarts
# the shared OpenShell gateway, and --non-interactive restarts it only while
# no sandbox runs on it.
_GATEWAY_RESTART_NOTE = (
    "restarts the OpenShell gateway, which drops the connections of every running sandbox; "
    "while sandboxes run, setup skips the restart (apply it later with: defenseclaw sandbox doctor --fix)."
)
# The gateway of an OpenShell installed another way than the one whose
# service DefenseClaw restarts it through: setup writes the change, and its
# user restarts it (DoctorReport.GatewayUnmanaged).
_GATEWAY_MANUAL_RESTART_NOTE = (
    "is written to the gateway's configuration; DefenseClaw cannot restart this gateway, "
    "so you restart it yourself, the way you started it, to apply it."
)

# The largest auth.json sandboxcli.codexAuthKey reads.
_CODEX_AUTH_MAX_BYTES = 1 << 20


def _codex_auth_key_source(env: Mapping[str, str], home: str) -> str:
    """Where ``codex login --with-api-key`` stored an API key, or "".

    Mirrors ``sandboxcli.codexAuthKey``: $CODEX_HOME (when absolute, else
    ~/.codex)/auth.json, a regular file of at most 1 MiB whose
    ``OPENAI_API_KEY`` is a non-empty string. A ChatGPT login (tokens only)
    is not shared.
    """

    codex_home = str(env.get("CODEX_HOME", "")).strip()
    label = "$CODEX_HOME/auth.json"
    if not codex_home or not os.path.isabs(codex_home):
        codex_home, label = os.path.join(home, ".codex"), "~/.codex/auth.json"
    path = os.path.join(codex_home, "auth.json")
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _CODEX_AUTH_MAX_BYTES:
            return ""
        with open(path, encoding="utf-8") as handle:
            auth = json.load(handle)
    except (OSError, ValueError):
        return ""
    key = auth.get("OPENAI_API_KEY") if isinstance(auth, dict) else None
    return label if isinstance(key, str) and key.strip() else ""


def _sandbox_credential_summary(
    env: Mapping[str, str] | None = None, home: str | None = None, llm: str = ""
) -> str:
    """Which model credential each harness would share (names only, never values).

    Mirrors ``sandboxcli.runLLM`` and ``detectLLM`` for a run without
    ``--llm``, which takes ``openshell.llm`` (*llm*): under ``auto`` (the
    default) environment variables, and for Codex the API key in auth.json,
    with an Amazon Bedrock key (``AWS_BEARER_TOKEN_BEDROCK``) last; ``none``
    shares nothing; a provider shares only its own key, and a run without it
    is refused. A provider the harness has no credential for gives way to
    ``auto``.
    """

    env = os.environ if env is None else env
    home = os.path.expanduser("~") if home is None else home
    choice = str(llm or "").strip().lower() or "auto"

    def first(*names: str) -> str:
        return next((name for name in names if str(env.get(name, "")).strip()), "")

    bedrock = ("bedrock", "AWS_BEARER_TOKEN_BEDROCK", lambda: first("AWS_BEARER_TOKEN_BEDROCK"))
    # (openshell.llm choice, the variable a refusal names, the source found)
    harnesses = (
        (
            "Claude Code",
            (
                ("anthropic", "ANTHROPIC_API_KEY", lambda: first("ANTHROPIC_API_KEY")),
                ("claude-oauth", "CLAUDE_CODE_OAUTH_TOKEN", lambda: first("CLAUDE_CODE_OAUTH_TOKEN")),
                bedrock,
            ),
        ),
        (
            "Codex",
            (
                (
                    "openai",
                    "OPENAI_API_KEY",
                    lambda: first("OPENAI_API_KEY", "CODEX_API_KEY") or _codex_auth_key_source(env, home),
                ),
                bedrock,
            ),
        ),
    )
    parts = []
    for label, candidates in harnesses:
        if choice == "none":
            parts.append(f"{label}: none shared (openshell.llm none; log in inside the sandbox)")
            continue
        chosen = [c for c in candidates if c[0] == choice]
        found = ""
        for _llm, _name, value in chosen or candidates:
            found = value()
            if found:
                break
        if found:
            parts.append(f"{label}: {found} found")
        elif chosen:
            parts.append(
                f"{label}: none found (openshell.llm {choice}: runs are refused until you set {chosen[0][1]})"
            )
        elif choice != "auto":
            # A provider the harness has no credential for gives way to auto.
            parts.append(
                f"{label}: none found (openshell.llm {choice} does not apply to {label}, so auto; "
                "log in inside the sandbox)"
            )
        else:
            parts.append(f"{label}: none found (log in inside the sandbox)")
    return " · ".join(parts)


@dataclass(frozen=True)
class SandboxMachineCheck:
    """What ``defenseclaw sandbox doctor --json`` says about this machine, for the wizard."""

    summary: str  # one line per check
    openshell_needed: bool = False
    openshell_detail: str = ""
    error: str = ""
    # An OpenShell installed another way than the Homebrew formula (macOS)
    # or without the openshell-gateway user unit (Linux), whose gateway
    # DefenseClaw cannot start or restart (DoctorReport.GatewayUnmanaged):
    # setup uses it while it answers and writes a gateway change for the
    # user to restart it on. Installing OpenShell would change nothing.
    openshell_unmanaged: bool = False
    # With OpenShell installed (a supported CLI, or one newer than
    # supported), the failing check whose doctor's fix openshell_detail
    # gives: installing OpenShell would change nothing. Setup stops on a
    # CLI or gateway one before it installs anything; a "vm-driver" one it
    # fixes with the install's consent (e2fsprogs) or stops on.
    openshell_attention: str = ""


_DOCTOR_GLYPHS = {"pass": "✓", "warn": "⚠", "fail": "✗"}

# The checks setup stops on, in its order, when it does not install
# OpenShell (sandboxcli/setup.go, after step 3).
_SETUP_STOPS = ("openshell-cli", "gateway-registration", "mtls-permissions", "gateway-version", "gateway-service")


def sandbox_machine_check(report: Mapping[str, Any] | None, error: str = "") -> SandboxMachineCheck:
    """Summarize a ``sandbox doctor --json`` report (or why it did not run).

    OpenShell counts as needed exactly when ``sandbox setup`` offers to
    install it: where its install step runs NVIDIA's installer, for a CLI
    missing or one it upgrades (the report's ``openshell_install``,
    DoctorReport.OpenShellInstallNeeded). With OpenShell installed, any
    other failing check is not the install's (it would install nothing):
    the first one setup stops on, a gateway's before a MicroVM driver's,
    is shown with the doctor's fix (``openshell_attention``). On a MicroVM
    (vm) gateway, or a Mac whose docker driver has no Landlock (which setup
    switches to MicroVMs), that includes a failed ``vm-driver`` check. A
    MicroVM mounts no host folders, so the bind-mount check is left out
    there. An OpenShell installed another way than the Homebrew formula
    (macOS) or without the openshell-gateway user unit (Linux) is marked,
    as setup marks it: setup uses its gateway while it answers (the user
    restarts it after a gateway change) and stops, with the doctor's fix,
    where that gateway does not answer. A gateway service that warns is
    shown with its detail.
    """

    if not isinstance(report, Mapping):
        why = error or "the sandbox doctor did not answer"
        return SandboxMachineCheck(summary=f"not checked: {why}", error=why)
    checks: dict[str, Mapping[str, Any]] = {}
    for item in report.get("checks") or ():
        if isinstance(item, Mapping) and item.get("id"):
            checks[str(item["id"])] = item

    def status(check_id: str) -> str:
        return str((checks.get(check_id) or {}).get("status") or "").lower()

    def detail(check_id: str) -> str:
        return str((checks.get(check_id) or {}).get("detail") or "").strip()

    def fix_of(check_id: str) -> str:
        """The doctor's fix of a check, as setup prints it, else its detail."""
        fix = (checks.get(check_id) or {}).get("fix")
        fix = fix if isinstance(fix, Mapping) else {}
        summary, command = str(fix.get("summary") or "").strip(), str(fix.get("command") or "").strip()
        if not summary:
            return detail(check_id)
        return summary + (f" (`{command}`)" if command else "")

    # The driver the gateway runs, else the one its files configure
    # (DoctorReport.Driver, .ConfiguredDriver; the Go doctor always names
    # one). On a Mac whose docker driver has no Landlock (Docker Desktop's
    # VM) setup switches the gateway to MicroVMs, which is its default
    # (sandboxcli/setup.go): the MicroVM driver's needs count then, and no
    # bind mounts do.
    driver = str(report.get("driver") or report.get("configured_driver") or "").strip()
    on_microvm = not compute_driver(driver).host_mounts
    mac = detail("platform").startswith("darwin/")
    microvm = on_microvm or (mac and status("landlock") != "pass")
    parts: list[str] = []
    docker = status("docker")
    if docker:
        version = str(report.get("docker_version") or "").strip()
        text = f"Docker {version}".strip() if docker == "pass" else f"Docker: {detail('docker') or docker}"
        parts.append(f"{_DOCTOR_GLYPHS.get(docker, '·')} {text}")
    landlock = status("landlock")
    if landlock in _DOCTOR_GLYPHS and on_microvm:
        # The MicroVM's own kernel enforces it (sandboxcli.machineLine).
        parts.append(f"{_DOCTOR_GLYPHS[landlock]} Landlock (MicroVM)")
    elif landlock in _DOCTOR_GLYPHS:
        parts.append(f"{_DOCTOR_GLYPHS[landlock]} Landlock" + (f" {detail('landlock')}" if landlock == "pass" else ""))
    cli = status("openshell-cli")
    service = report.get("service")
    service = service if isinstance(service, Mapping) else {}
    # An OpenShell installed another way than the Homebrew formula (macOS)
    # or without the openshell-gateway user unit (Linux) whose service runs
    # the gateway (DoctorReport.GatewayUnmanaged): setup uses its gateway
    # while it answers, and stops on the doctor's fix where it does not.
    # Its install step would find the CLI and install nothing.
    without_service = cli not in {"", "fail"} and not service.get("installed")
    manager = service.get("manager")
    unmanaged = without_service and manager in {"systemd", "brew"}
    # A doctor older than openshell_install: a failed CLI check.
    install = report.get("openshell_install")
    needed = not unmanaged and (install if isinstance(install, bool) else cli in {"", "fail"})
    # Else the first failing check setup stops on, with the doctor's fix.
    attention = "" if needed else next((i for i in _SETUP_STOPS if status(i) == "fail"), "")
    version = str(report.get("cli_version") or "").strip()
    name = f"OpenShell {version}" if version else "OpenShell"
    if unmanaged:
        # As setup's machine line marks it (sandboxcli/setup.go), and says
        # what it does with its gateway, naming where that OpenShell is.
        where = str(report.get("cli_path") or "").strip()
        if manager == "systemd":
            parts.append(f"⚠ {name} has no openshell-gateway user service")
            how = ", without the openshell-gateway user service DefenseClaw starts and restarts the gateway through on Linux"
        else:
            parts.append(f"⚠ {name} is not from Homebrew's nvidia/openshell formula")
            how = (
                " than the nvidia/openshell/openshell Homebrew formula, whose service DefenseClaw starts "
                "and restarts the gateway through"
            )
        openshell = (
            f"{name}{f' at {where}' if where else ''} was installed another way{how}: setup uses its gateway "
            "as it runs, but DefenseClaw cannot start or restart it; after a gateway change, restart it yourself, "
            "the way you started it"
        )
    if attention == "openshell-cli":
        # One newer than supported, which the install step does not downgrade.
        openshell = f"OpenShell needs attention: {fix_of(attention) or 'not supported'}"
        parts.append("✗ OpenShell " + (detail("openshell-cli") or "not supported"))
    elif attention:
        # A stopped gateway service is started, a gateway of another
        # release than the CLI restarted through its service.
        openshell = f"the OpenShell gateway needs attention: {fix_of(attention) or 'not answering'}"
        gateway = str(report.get("gateway_version") or "").strip()
        if attention == "gateway-version" and gateway and gateway != version:
            parts.append(f"✗ {name}, but the gateway runs {gateway}")
        elif status("gateway-service") == "fail":
            # A gateway that answers while the service is stopped is run
            # by something else.
            parts.append("✗ OpenShell gateway service stopped" if gateway else "✗ OpenShell gateway not running")
        else:
            parts.append("✗ OpenShell gateway needs attention")
    elif unmanaged:
        pass
    elif not needed:
        openshell = f"{name} is installed"
        if status("gateway-service") == "warn":
            parts.append(f"⚠ {name}: {detail('gateway-service') or 'gateway service needs attention'}")
        else:
            parts.append(f"✓ {name}")
    elif "not on PATH" in detail("openshell-cli"):
        openshell = "OpenShell is not installed"
        parts.append("✗ OpenShell not installed")
    else:
        openshell = f"OpenShell needs attention: {detail('openshell-cli') or 'not found'}"
        parts.append("✗ OpenShell " + (detail("openshell-cli") or "not found"))
    vm_driver = status("vm-driver") if microvm else ""
    if vm_driver == "pass":
        parts.append("✓ MicroVM driver")
    elif vm_driver in {"warn", "fail"}:
        parts.append(f"{_DOCTOR_GLYPHS[vm_driver]} MicroVM driver: {detail('vm-driver') or vm_driver}")
    # Setup gets to the MicroVM driver past the gateway checks only.
    if vm_driver == "fail" and not needed and not attention:
        attention = "vm-driver"
        openshell = f"the MicroVM driver needs attention: {fix_of('vm-driver') or 'not ready'}"
    mounts = "" if microvm else status("bind-mounts")
    if mounts == "pass":
        parts.append("✓ bind mounts")
    elif mounts in {"warn", "fail"}:
        off = detail("bind-mounts").startswith("disabled")
        parts.append("✗ bind mounts off" if off else "✗ bind mounts: " + detail("bind-mounts"))
    # One check per line: joined on one line, the checks after the first
    # few were cut off at 80 columns.
    return SandboxMachineCheck(
        summary="\n".join(parts),
        openshell_needed=needed,
        openshell_detail=openshell,
        openshell_unmanaged=unmanaged,
        openshell_attention=attention,
    )


def _sandbox_allowed_harnesses(cfg: object | Mapping[str, Any] | None) -> tuple[str, ...]:
    """openshell.admin.allowed_harnesses (empty: any harness)."""
    admin = _openshell_admin(cfg)
    return tuple(str(h).strip() for h in (_admin_value(admin, "allowed_harnesses", ()) or ()) if str(h).strip())


def sandbox_wizard_fields(
    cfg: object | Mapping[str, Any] | None = None,
    *,
    machine: SandboxMachineCheck | None = None,
    os_name: str | None = None,
) -> tuple[WizardFormField, ...]:
    """The OpenShell sandbox setup wizard (``defenseclaw sandbox setup``).

    Every consent the interactive command asks for is a field here, so the
    wizard runs the command with ``--non-interactive`` and explicit flags:
    the answers are the consent. ``machine`` is the doctor's check of this
    machine; until it answers, Install OpenShell stays off. On macOS there is
    no telemetry question: the Homebrew gateway does not read gateway.env,
    so setup cannot turn OpenShell's telemetry off there. Nor is there a
    mounts question: setup runs macOS sandboxes in OpenShell MicroVMs, which
    mount no host folders, so every run there works on a copy.
    """

    configured = {str(name) for name in (get_config_value(cfg, "openshell.harnesses", []) or [])}
    allowed = _sandbox_allowed_harnesses(cfg)
    harnesses = [entry for entry in SANDBOX_WIZARD_HARNESSES if not allowed or entry[0] in allowed]

    def is_setup(values: Mapping[str, str]) -> bool:
        return (values.get("action") or "setup") == "setup"

    fields: list[WizardFormField] = [
        WizardFormField(
            "Action",
            "choice",
            value="setup",
            default="setup",
            options=("setup", "doctor"),
            hint="setup: the one-time sandbox setup. doctor: only check this machine.",
        ),
        WizardFormField(
            "Harnesses",
            "section",
            value="" if harnesses else f"none may run: {ADMIN_POLICY_MESSAGE}",
            hint="The harnesses that run in sandboxes."
            + (f" Your organization allows: {', '.join(allowed)}." if allowed else ""),
            visible_when=is_setup,
        ),
    ]
    # As setup does: the configured harnesses, else its defaults (the first
    # the organization allows when it allows none of them).
    defaults = {name for name, _label, _command in harnesses if name in DEFAULT_SANDBOX_HARNESSES} or {
        name for name, _label, _command in harnesses[:1]
    }
    for name, label, command in harnesses:
        on = "yes" if (name in configured if configured else name in defaults) else "no"
        fields.append(
            WizardFormField(
                label,
                "bool",
                value=on,
                default=on,
                hint=f"Run `{command}` in a sandbox (--harness {name}).",
                visible_when=is_setup,
            )
        )
    macos = (host_os() if os_name is None else os_name).strip().lower() == "darwin"
    # On macOS the installer installs a Homebrew formula, without sudo.
    installer = "NVIDIA's pinned, sha256-verified installer " + (
        "(it installs the nvidia/openshell Homebrew formula; no sudo)"
        if macos
        else "(uses sudo; the terminal asks for your password)"
    )
    # On macOS setup installs e2fsprogs, which the MicroVM driver formats
    # its disks with, under the same consent as OpenShell (sandboxcli/setup.go).
    e2fsprogs = " Yes also installs e2fsprogs for the MicroVM driver when it is missing (brew install e2fsprogs)."
    if machine is None:
        machine_line = "Checking this machine… (defenseclaw sandbox doctor)"
        install, install_hint = "no", f"Install OpenShell 0.1.1 with {installer} if it is missing."
    elif machine.error:
        machine_line = machine.summary
        install, install_hint = "no", f"Could not check this machine; yes installs OpenShell 0.1.1 with {installer}."
    elif machine.openshell_needed:
        machine_line = machine.summary
        install = "yes"
        install_hint = f"{machine.openshell_detail}: yes installs OpenShell 0.1.1 with {installer}."
    elif machine.openshell_attention == "vm-driver":
        # Under the install's consent setup installs e2fsprogs and signs
        # the formula's driver (sandboxcli/setup.go prepareMicroVMs).
        machine_line = machine.summary
        install = "no"
        install_hint = (
            f"{machine.openshell_detail}; OpenShell is installed, and yes lets setup install e2fsprogs "
            "(brew install e2fsprogs) or sign the MicroVM driver when that is what it needs."
        )
    elif machine.openshell_attention:
        # The doctor's fix: installing OpenShell would change nothing.
        machine_line = machine.summary
        install, install_hint = "no", f"{machine.openshell_detail}; installing OpenShell would change nothing."
    else:
        machine_line = machine.summary
        install, install_hint = "no", f"{machine.openshell_detail}; nothing to install."
    # Setup gets to e2fsprogs only past the OpenShell and gateway checks: not
    # where it stops on a gateway fix.
    stops = machine is not None and machine.openshell_attention != ""
    if macos and not stops:
        install_hint += e2fsprogs
    # A gateway no gateway service runs is its user's to restart
    # (DoctorReport.GatewayUnmanaged): setup writes the change.
    unmanaged = machine is not None and machine.openshell_unmanaged
    restart_note = _GATEWAY_MANUAL_RESTART_NOTE if unmanaged else _GATEWAY_RESTART_NOTE
    microvm_restart = (
        "; you restart the gateway yourself, the way you started it" if unmanaged else " and restarts it once"
    )
    fields += [
        WizardFormField(
            "Credentials",
            "section",
            hint=_sandbox_credential_summary(llm=str(get_config_value(cfg, "openshell.llm", "") or "")),
            visible_when=is_setup,
        ),
        WizardFormField(
            "This machine",
            "section",
            value=machine_line,
            hint="Your answers here are the consent: setup runs without asking again "
            "(only sudo may ask for your password).",
            visible_when=is_setup,
        ),
        WizardFormField(
            "Install OpenShell",
            "bool",
            "--install-openshell",
            value=install,
            default=install,
            hint=install_hint,
            visible_when=is_setup,
        ),
    ]
    if macos:
        # Setup on macOS asks no mounts question: it runs sandboxes in
        # MicroVMs, which mount no host folders (--no-mounts would do nothing).
        fields.append(
            WizardFormField(
                "MicroVMs",
                "section",
                value="every run works on a copy",
                hint="Docker Desktop's Linux kernel has no Landlock, so setup switches the OpenShell gateway to "
                'its MicroVM driver (compute_driver = "vm"; Apple silicon; experimental upstream)'
                + microvm_restart
                + ". MicroVMs mount no host folders: the agent works on a copy, and defenseclaw sandbox pull "
                "brings the changes back. The first run of each image prepares its MicroVM disk (about a minute "
                "and 5 GB).",
                visible_when=is_setup,
            )
        )
    else:
        fields += [
            WizardFormField(
                "Mount Project Folder",
                "bool",
                no_flag="--no-mounts",
                value="yes",
                default="yes",
                hint="Allow sandboxes to mount the folder you launch from (enables bind mounts on your local "
                "OpenShell gateway; DefenseClaw mounts only the launch folder and the read-only settings Claude Code "
                "and Codex sandboxes need). No: no Claude Code or Codex sandbox can start, and other harnesses "
                "run on a copy. "
                "Turning bind mounts on " + restart_note,
                visible_when=is_setup,
            ),
            WizardFormField(
                "Disable OpenShell Telemetry",
                "bool",
                no_flag="--upstream-telemetry",
                value="yes",
                default="yes",
                hint="Turn OpenShell's anonymous usage telemetry off (gateway.env). Changing it " + restart_note,
                visible_when=is_setup,
            ),
        ]
    fields += [
        WizardFormField(
            "Shell Wrappers",
            "bool",
            "--wrappers",
            "--no-wrappers",
            value="no",
            default="no",
            hint="Make the chosen harnesses' commands (`claude`, `codex`, ...) run sandboxed when you type them "
            "(a marked block in your shell rc; undo any time with defenseclaw sandbox disable <harness>).",
            visible_when=is_setup,
        ),
        WizardFormField(
            "Build Images Now",
            "bool",
            no_flag="--skip-images",
            value="yes",
            default="yes",
            hint="Build the harness images now (the first build is about 3 GB). No: the first run builds them.",
            visible_when=is_setup,
        ),
    ]
    return tuple(fields)


def _sandbox_selected_harnesses(fields: Sequence[WizardFormField]) -> list[str]:
    return [
        name
        for name, label, _command in SANDBOX_WIZARD_HARNESSES
        if wizard_bool_value(fields, label, "no") == "yes"
    ]


def _build_sandbox_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    if (wizard_field_value(fields, "Action") or "setup") == "doctor":
        return ("sandbox", "doctor")
    args = ["sandbox", "setup", "--non-interactive"]
    for name in _sandbox_selected_harnesses(fields):
        args.extend(("--harness", name))
    if wizard_bool_value(fields, "Install OpenShell", "no") == "yes":
        args.append("--install-openshell")
    if wizard_bool_value(fields, "Mount Project Folder", "yes") == "no":
        args.append("--no-mounts")
    if wizard_bool_value(fields, "Disable OpenShell Telemetry", "yes") == "no":
        args.append("--upstream-telemetry")
    args.append("--wrappers" if wizard_bool_value(fields, "Shell Wrappers", "no") == "yes" else "--no-wrappers")
    if wizard_bool_value(fields, "Build Images Now", "yes") == "no":
        args.append("--skip-images")
    return tuple(args)


def _build_acp_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    args = ["acp", "setup"]
    for label, flag in (("Client", "--client"), ("Agent", "--agent"), ("Profile", "--profile")):
        value = wizard_field_value(fields, label).strip()
        if value:
            args.extend((flag, value))
    if wizard_bool_value(fields, "Action Mode", "no") == "yes":
        args.append("--activate")
    if wizard_bool_value(fields, "Managed Enrollment", "no") == "yes":
        args.append("--managed")
        for label, flag in (("Runtime Data Dir", "--runtime-data-dir"), ("Token File", "--token-file")):
            value = wizard_field_value(fields, label).strip()
            if value:
                args.extend((flag, value))
    return tuple(args)


# Guardrail judge flags whose CSV field value repeats once per item, matching
# the CLI's ``multiple=True`` options (fallbacks + regional deployment aliases).
_GUARDRAIL_REPEATABLE_FLAGS: frozenset[str] = frozenset(
    {"--judge-bedrock-deployment", "--judge-azure-deployment-alias"}
)


def _connector_guardrail_mode_args(fields: Sequence[WizardFormField]) -> tuple[str, ...] | None:
    """Build the focused Guardrail mode workflow for hook connectors.

    ``setup codex`` and ``setup claude-code`` own additive, per-connector
    roster updates. Keep every other Guardrail workflow on ``setup guardrail``
    because judge, Cisco, scanner, and other global settings do not belong on
    these connector-specific commands.
    """

    form_labels = {field.label for field in fields if field.kind != "section"}
    if form_labels != {"Connector", "Mode"}:
        return None
    connector = wizard_field_value(fields, "Connector").strip().lower()
    command = {
        "claude-code": "claude-code",
        "claudecode": "claude-code",
        "codex": "codex",
    }.get(connector)
    if command is None:
        return None
    mode = wizard_field_value(fields, "Mode").strip().lower()
    if mode not in {"observe", "action"}:
        mode = "observe"
    return ("setup", command, "--yes", "--mode", mode)


def build_wizard_args(
    wizard: SetupWizard | int,
    fields: Sequence[WizardFormField],
    cfg: object | Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    """Translate a wizard's filled-in form into a CLI argv tuple.

    Self-contained builders live in ``_WIZARD_ARG_BUILDERS``. Wizards
    that lean on the shared "base + --non-interactive + emit each
    field's flag" loop below are handled inline because the loop runs
    over per-wizard field metadata.
    """

    wizard = SetupWizard(wizard)
    if wizard in {SetupWizard.GUARDRAIL, SetupWizard.GUARDRAIL_ACTIONS}:
        if error := _guardrail_connector_selection_error(cfg, fields):
            raise ValueError(error)
    if wizard == SetupWizard.GUARDRAIL:
        connector_mode_args = _connector_guardrail_mode_args(fields)
        if connector_mode_args is not None:
            return connector_mode_args
        return _build_guardrail_setup_args(fields, cfg)
    if wizard == SetupWizard.GUARDRAIL_ACTIONS:
        return _build_guardrail_actions_args(fields)
    del cfg
    builder = _WIZARD_ARG_BUILDERS.get(wizard)
    if builder is not None:
        return builder(fields)

    base = list(WIZARD_COMMANDS[wizard])
    if wizard == SetupWizard.OBSERVABILITY:
        preset = next((field.value for field in fields if field.kind == "preset"), "")
        if preset:
            base.append(preset)
    if wizard == SetupWizard.WEBHOOKS:
        channel = next((field.value for field in fields if field.kind == "whtype"), "")
        if channel:
            base.append(channel)
    if wizard == SetupWizard.REGISTRIES:
        source_id = next((field.value.strip() for field in fields if field.kind == "regid"), "")
        if source_id:
            base.append(source_id)
    if wizard == SetupWizard.SPLUNK:
        # Mode choice rewrites the pipeline bools so the operator only
        # has to pick one option in the guided picker. Custom keeps the
        # current bool selections untouched.
        mode = wizard_field_value(fields, "Mode")
        if mode in {"splunk-o11y", "local-docker", "enterprise"}:
            pipeline_map = {
                "splunk-o11y": "--o11y",
                "local-docker": "--logs",
                "enterprise": "--enterprise",
            }
            base.append(pipeline_map[mode])
    base.append("--non-interactive")

    always_pass_defaults = wizard in {SetupWizard.OBSERVABILITY, SetupWizard.WEBHOOKS}
    judge_provider = ""
    judge_model = ""
    judge_dirty = False
    splunk_mode_value = ""
    if wizard == SetupWizard.SPLUNK:
        splunk_mode_value = wizard_field_value(fields, "Mode")
    splunk_pipeline_labels = {"Enable O11y", "Enable Local Logs", "Enable Enterprise"}
    webhook_hmac_disabled = (
        wizard == SetupWizard.WEBHOOKS and wizard_bool_value(fields, "Enable HMAC Signing", "yes") == "no"
    )
    for field in fields:
        if field.kind in {"section", "preset", "whtype", "regid"}:
            continue
        if wizard == SetupWizard.SPLUNK:
            # Pipeline picker drives the bool flags; don't double-emit.
            if field.label == "Mode" and field.flag == "":
                continue
            if field.label == "Apply Dashboards After":
                continue
            if (
                splunk_mode_value in {"splunk-o11y", "local-docker", "enterprise"}
                and field.label in splunk_pipeline_labels
            ):
                continue
        if wizard == SetupWizard.WEBHOOKS:
            # ``Enable HMAC Signing`` is a wizard-only toggle (no flag).
            if field.label == "Enable HMAC Signing":
                continue
            if webhook_hmac_disabled and field.label == "HMAC secret env (optional)":
                continue
        if field.label == "Provider" and field.flag == "":
            judge_provider = field.value
            judge_dirty = judge_dirty or field.value != field.default
            continue
        if field.label == "Model" and field.flag == "--judge-model":
            judge_model = field.value
            judge_dirty = judge_dirty or field.value != field.default
            continue
        if field.kind == "bool":
            # ``--human-approval`` is tri-state on
            # the CLI (default=None), so emit the explicit on/off form rather
            # than relying on the "skip when value==default" shortcut.
            if wizard == SetupWizard.GUARDRAIL and field.flag == "--human-approval":
                if field.value == "yes" and field.flag:
                    base.append(field.flag)
                elif field.value == "no" and field.no_flag:
                    base.append(field.no_flag)
                continue
            if field.value == field.default:
                continue
            if field.value == "yes" and field.flag:
                base.append(field.flag)
            elif field.value == "no" and field.no_flag:
                base.append(field.no_flag)
            continue
        if field.kind in {"string", "int", "choice", "password"}:
            if wizard == SetupWizard.MCP_SCANNER and field.flag == "--analyzers" and not field.value.strip():
                # Clearing the list showed an empty field while Run kept the
                # old list; empty now means auto, as the hint says (GAP-2572).
                if field.default not in {"", "auto"}:
                    base.extend((field.flag, "auto"))
                continue
            if not field.value or not field.flag:
                continue
            if not always_pass_defaults and field.value == field.default and not field.required:
                continue
            # CSV-style multi-flag fields (e.g. --judge-fallback, the judge
            # regional deployment aliases) repeat the flag once per value.
            if field.flag in _GUARDRAIL_REPEATABLE_FLAGS:
                for item in (chunk.strip() for chunk in field.value.split(",")):
                    if item:
                        base.extend((field.flag, item))
                continue
            base.extend((field.flag, field.value))

    if judge_dirty and judge_model:
        combined = f"{judge_provider}/{judge_model}" if judge_provider else judge_model
        base.extend(("--judge-model", combined))
    return tuple(base)


# Self-contained arg builders. Wizards listed here bypass the generic
# ``base + --non-interactive + emit-each-field-flag`` machinery below
# the dict. Lambdas keep lookups lazy so each builder can be defined
# anywhere in the file.
_WIZARD_ARG_BUILDERS: dict[SetupWizard, Any] = {
    SetupWizard.CONNECTOR_SETUP: lambda fields: _build_connector_setup_args(fields),
    SetupWizard.CREDENTIALS: lambda fields: _build_credentials_args(fields),
    SetupWizard.LLM: lambda fields: _build_llm_args(fields),
    SetupWizard.LOCAL_OBSERVABILITY: lambda fields: _build_local_observability_args(fields),
    SetupWizard.TOKEN_ROTATION: lambda fields: _build_token_rotation_args(fields),
    SetupWizard.CUSTOM_PROVIDERS: lambda fields: _build_custom_provider_args(fields),
    SetupWizard.OBSERVABILITY: lambda fields: _build_observability_args(fields),
    SetupWizard.WEBHOOKS: lambda fields: _build_webhook_args(fields),
    SetupWizard.SANDBOX: lambda fields: _build_sandbox_args(fields),
    SetupWizard.NOTIFICATIONS_ROUTING: lambda fields: _build_notifications_routing_args(fields),
    SetupWizard.AI_DISCOVERY: lambda fields: _build_ai_discovery_args(fields),
    SetupWizard.SPLUNK_DASHBOARDS: lambda fields: _build_splunk_dashboards_args(fields),
    SetupWizard.TRUSTED_PATHS: lambda fields: _build_trusted_paths_args(fields),
    SetupWizard.GUARDRAIL_ACTIONS: lambda fields: _build_guardrail_actions_args(fields),
    SetupWizard.REDACTION: lambda fields: _build_redaction_args(fields),
    SetupWizard.ACP_GUARD: lambda fields: _build_acp_args(fields),
}


def missing_required_fields(wizard: SetupWizard | int, fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    wizard = SetupWizard(wizard)
    missing: list[str] = []
    if wizard == SetupWizard.CREDENTIALS and wizard_field_value(fields, "Action") == "set":
        if not wizard_field_value(fields, "Env Name"):
            missing.append("Env Name")
        if not wizard_field_value(fields, "Secret Value", raw=True):
            missing.append("Secret Value")
    if wizard == SetupWizard.CREDENTIALS and wizard_field_value(fields, "Action") == "remove":
        if not wizard_field_value(fields, "Env Name"):
            missing.append("Env Name")
    if wizard == SetupWizard.CUSTOM_PROVIDERS:
        action = wizard_field_value(fields, "Action")
        if action in {"add", "remove"} and not wizard_field_value(fields, "Name"):
            missing.append("Name")
        # ``setup provider add`` accepts either a domain allow-list or a
        # --base-url; require at least one rather than mandating Domains.
        if action == "add" and not wizard_field_value(fields, "Domains") and not wizard_field_value(fields, "Base URL"):
            missing.append("Domains or Base URL")
    if wizard == SetupWizard.TRUSTED_PATHS:
        action = wizard_field_value(fields, "Action")
        if action in {"add", "remove"} and not wizard_field_value(fields, "Directory"):
            missing.append("Directory")
    if wizard == SetupWizard.SANDBOX and (wizard_field_value(fields, "Action") or "setup") == "setup":
        if not _sandbox_selected_harnesses(fields):
            labels = {field.label for field in fields}
            offered = [label for _name, label, _command in SANDBOX_WIZARD_HARNESSES if label in labels]
            if not offered:
                missing.append(f"a harness ({ADMIN_POLICY_MESSAGE})")
            elif len(offered) <= 2:
                missing.append(f"a harness ({' or '.join(offered)})")
            else:
                missing.append("a harness (turn one on under Harnesses)")
    if wizard == SetupWizard.ACP_GUARD and wizard_bool_value(fields, "Managed Enrollment", "no") == "yes":
        for label in ("Runtime Data Dir", "Token File"):
            if not wizard_field_value(fields, label):
                missing.append(label)
    if wizard == SetupWizard.REDACTION:
        action = wizard_field_value(fields, "Action") or "status"
        if action in {"apply-all", "apply-defaults"} and not wizard_field_value(fields, "Profile"):
            missing.append("Profile")
        if action in {"profile-show", "profile-set", "profile-remove"} and not wizard_field_value(
            fields, "Custom Profile Name"
        ):
            missing.append("Custom Profile Name")
        if action.startswith(("destination-", "route-")) and not wizard_field_value(fields, "Destination"):
            missing.append("Destination")
        if action in {"route-add", "route-set", "route-move", "route-remove"} and not wizard_field_value(
            fields, "Route Name"
        ):
            missing.append("Route Name")
    if wizard == SetupWizard.CONNECTOR_SETUP:
        action = wizard_field_value(fields, "Action") or "setup"
        if action in {"setup", "remove"} and not wizard_field_value(fields, "Connector"):
            missing.append("Connector")
        if (
            action == "batch"
            and not wizard_field_value(fields, "Connectors (CSV)")
            and wizard_bool_value(fields, "Detected Connectors", "no") != "yes"
            and wizard_bool_value(fields, "All Supported Connectors", "no") != "yes"
        ):
            missing.append("Connectors (CSV) or Detected/All")
    if (
        wizard == SetupWizard.GUARDRAIL_ACTIONS
        and wizard_field_value(fields, "Action") == "block-message"
        and not wizard_field_value(fields, "Block Message", raw=True)
        and wizard_bool_value(fields, "Clear Message", "no") != "yes"
    ):
        missing.append("Block Message or Clear Message")
    if wizard in {SetupWizard.OBSERVABILITY, SetupWizard.WEBHOOKS}:
        action = wizard_field_value(fields, "Action") or "add"
        if action in {"enable", "disable", "remove"} and not wizard_field_value(fields, "Name", raw=True):
            missing.append("Name")
    for field in fields:
        if wizard in {SetupWizard.OBSERVABILITY, SetupWizard.WEBHOOKS}:
            action = wizard_field_value(fields, "Action") or "add"
            if action != "add":
                continue
        if not field.required or field.kind in {"section", "preset", "whtype", "regid", "bool"}:
            continue
        if not field.value.strip():
            missing.append(field.label)
    return tuple(dict.fromkeys(missing))


def render_wizard_value(field: WizardFormField, *, reveal: bool = False) -> str:
    if field.kind != "password":
        return field.value
    if reveal:
        return field.value or "(empty)"
    return mask_secret(field.value)


# Secret flags the Setup wizards fill, with the variable that command reads
# instead (Click envvar). argv is readable by every local account (ps, /proc),
# the environment only by the same user (GAP-1888).
WIZARD_SECRET_ENV: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("setup", "observability", "add"), "--token", "DEFENSECLAW_SETUP_OBSERVABILITY_TOKEN"),
    (("setup", "llm"), "--api-key", "DEFENSECLAW_SETUP_LLM_API_KEY"),
    (("setup", "gateway"), "--token", "DEFENSECLAW_SETUP_GATEWAY_TOKEN"),
    (("setup", "splunk"), "--access-token", "DEFENSECLAW_SETUP_SPLUNK_ACCESS_TOKEN"),
    (("setup", "splunk"), "--hec-token", "DEFENSECLAW_SETUP_SPLUNK_HEC_TOKEN"),
    (("setup", "splunk", "dashboards"), "--o11y-api-token", "SFX_AUTH_TOKEN"),
)


def wizard_secrets_to_env(args: Sequence[str]) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
    """Move secret ``--flag value`` pairs out of argv into env overrides."""

    names = {
        flag: env_name for prefix, flag, env_name in WIZARD_SECRET_ENV if tuple(args[: len(prefix)]) == prefix
    }
    out: list[str] = []
    env: list[tuple[str, str]] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in names and index + 1 < len(args):
            env.append((names[arg], args[index + 1]))
            index += 2
            continue
        flag, equals, value = arg.partition("=")
        if equals and flag in names:
            env.append((names[flag], value))
            index += 1
            continue
        out.append(arg)
        index += 1
    return tuple(out), tuple(env)


def observability_preset_label(preset_id: str) -> str:
    """Short destination name: 'Datadog', 'Galileo Cloud', 'Generic OTLP'."""

    label = dict(OBSERVABILITY_PRESETS).get(preset_id, preset_id or "destination")
    return label.split(" / ")[0]


def mask_wizard_secret_values(fields: Sequence[WizardFormField], args: Sequence[str]) -> tuple[str, ...]:
    """Redact password-field values from a rendered wizard command preview.

    The wizard header echoes the exact ``defenseclaw …`` argv it will run.
    Password fields (API keys, tokens, secrets, credentials) emit their
    value verbatim as an argv token, so any token that equals a non-empty
    password value — or whose ``flag=value`` tail equals one — is replaced
    with ``<redacted>`` before display. See F-0481.
    """

    secret_values = {field.value for field in fields if field.kind == "password" and field.value}
    if not secret_values:
        return tuple(args)
    masked: list[str] = []
    for arg in args:
        if arg in secret_values:
            masked.append("<redacted>")
            continue
        if "=" in arg:
            flag, value = arg.split("=", 1)
            if value in secret_values:
                masked.append(f"{flag}=<redacted>")
                continue
        masked.append(arg)
    return tuple(masked)


def notifications_desired_action(currently_enabled: bool) -> str:
    return "off" if currently_enabled else "on"


def notifications_toggle_intent(currently_enabled: bool) -> SetupCommandIntent:
    action = notifications_desired_action(currently_enabled)
    return SetupCommandIntent(
        label=f"setup notifications {action}",
        args=("setup", "notifications", action, "--yes"),
        category="setup",
        origin="notifications-modal",
    )


def notifications_consequence_copy(currently_enabled: bool) -> tuple[str, ...]:
    if currently_enabled:
        return (
            "Turning notifications OFF stops the toaster.",
            "Event history, telemetry destinations, and webhooks are NOT affected.",
        )
    return (
        "Turning notifications ON surfaces hook, guardrail, and asset-policy blocks.",
        "Observe-mode would-blocks and pending HITL approval prompts can generate toasts.",
        "Clicking a notification does not approve anything.",
    )


def uninstall_args_for_option(option: UninstallOption) -> tuple[tuple[str, ...], str]:
    if option == "keep-data":
        return ("uninstall", "--yes"), "uninstall --yes"
    if option == "wipe-data":
        return ("uninstall", "--all", "--yes"), "uninstall --all --yes"
    if option == "wipe-all":
        return ("uninstall", "--all", "--binaries", "--yes"), "uninstall --all --binaries --yes"
    return ("uninstall", "--dry-run"), "uninstall dry-run"


def uninstall_intent(option: UninstallOption) -> SetupCommandIntent:
    args, display = uninstall_args_for_option(option)
    return SetupCommandIntent(
        label=display,
        args=args,
        category="destructive" if option != "dry-run" else "setup",
        origin="uninstall-modal",
    )


# The connector install.sh offers first; the Setup form starts on it when no
# connector is configured (GAP-2159).
_DEFAULT_SETUP_CONNECTOR = "codex"


def connector_setup_wizard_fields(
    cfg: object | Mapping[str, Any] | None = None,
    os_name: str | None = None,
    *,
    overrides: Mapping[str, str] | None = None,
) -> tuple[WizardFormField, ...]:
    overrides = dict(overrides or {})
    choices = supported_connector_choices(os_name)
    if "@Connector" in overrides:
        connector = str(overrides.get("@Connector", "") or "").strip()
    else:
        connector = str(get_config_value(cfg, "guardrail.connector", "") or "").strip()
        if not connector:
            connector = str(get_config_value(cfg, "claw.mode", "") or "").strip()
    # No connector configured: start where install.sh does (codex), not on
    # openclaw, so Ctrl+R can't set up an agent nobody picked (GAP-2159).
    connector = connector or _DEFAULT_SETUP_CONNECTOR
    # A stored compatibility mirror can name a proxy connector that this OS
    # can't run (e.g. a config copied from macOS opened on Windows); fall back
    # to the first supported connector rather than offering an unusable default.
    if connector not in choices:
        connector = choices[0] if choices else connector
    action = str(overrides.get("@Action", "setup") or "setup").strip().lower()
    mode = (
        str(get_config_value(cfg, "guardrail.mode", "observe") or "observe")
        if action == "batch"
        else _effective_guardrail_value(cfg, connector, "effective_mode", "guardrail.mode")
    )
    mode = mode.strip().lower()
    if mode not in {"observe", "action"}:
        mode = "observe"
    # Rebuilders run only after Connector/Action driver changes. Re-seed this
    # connector-scoped value instead of carrying a prior connector's mode (or
    # a single-connector mode into intentional bare batch reconciliation).
    overrides.pop("@Guardrail Mode", None)
    scanner_mode = str(get_config_value(cfg, "guardrail.scanner_mode", "local") or "local")
    fields = (
        WizardFormField(
            "Connector",
            "choice",
            value=connector,
            default=connector,
            options=choices,
            hint="The agent to protect (←/→ to change).",
        ),
        WizardFormField(
            "Connectors (CSV)",
            "string",
            hint="Batch setup only: comma-separated active connector names, e.g. codex,hermes,antigravity.",
        ),
        WizardFormField(
            "Action",
            "choice",
            value="setup",
            default="setup",
            options=("setup", "batch", "remove"),
            hint="Set up/add one connector, choose the active connector set, or remove one.",
        ),
        WizardFormField(
            "Guardrail Mode",
            "choice",
            value=mode,
            default=mode,
            options=("observe", "action"),
            hint="observe only logs what would be blocked; action blocks it.",
        ),
        WizardFormField(
            "Scanner Mode",
            "choice",
            value=scanner_mode,
            default=scanner_mode,
            options=("local", "remote", "both"),
            hint="Where scans run: on this machine, in the Cisco AI Defense cloud, or both.",
        ),
        WizardFormField(
            "Replace Existing",
            "bool",
            value="no",
            default="no",
            hint="yes turns off the agents set up now and protects only this one; no adds it next to them.",
        ),
        WizardFormField(
            "Workspace Dir",
            "string",
            hint="Optional workspace-scoped connector config directory.",
        ),
        WizardFormField(
            "Restart Gateway",
            "bool",
            value="yes",
            default="yes",
            hint="Restart the gateway so the change takes effect now.",
        ),
        WizardFormField(
            "Detected Connectors",
            "bool",
            value="no",
            default="no",
            hint="Batch setup only: include every locally detected hook connector.",
        ),
        WizardFormField(
            "All Supported Connectors",
            "bool",
            value="no",
            default="no",
            hint="Batch setup only: include every supported hook connector.",
        ),
        WizardFormField(
            "Local Stack",
            "bool",
            value="no",
            default="no",
            hint="Also start the local Prometheus/Loki/Tempo/Grafana stack.",
        ),
        WizardFormField(
            "Verify After Setup",
            "bool",
            value="yes",
            default="yes",
            hint="Check that the connector reaches the guardrail once setup is done.",
        ),
        WizardFormField(
            "Force Last Connector Removal",
            "bool",
            value="no",
            default="no",
            hint="Allow removing the final connector and fully unconfiguring enforcement.",
        ),
    )
    if not is_guardrail_supporting(connector):
        # Only the proxy connectors take --scanner-mode / --verify; the form
        # offered them for Claude Code too, where they did nothing (GAP-2059).
        fields = tuple(field for field in fields if field.label not in _PROXY_ONLY_CONNECTOR_FIELDS)
    return _overlay_field_overrides(fields, overrides)


_PROXY_ONLY_CONNECTOR_FIELDS = frozenset({"Scanner Mode", "Verify After Setup"})


# ---------------------------------------------------------------------------
# Dynamic dependent-field machinery (connector-aware LLM / guardrail judge /
# custom-provider wizards). These wizards expose provider-specific field
# groups (Bedrock / Vertex / Azure / TLS) that appear only for the matching
# provider. The TUI is a pure argv builder, so we reuse the *pure* catalog
# readers from ``defenseclaw.commands._llm_picker`` (no interactive pickers)
# to populate model/region choices, and emit each selection as a ``--flag``.
# ---------------------------------------------------------------------------


def _llm_data_dir(cfg: object | Mapping[str, Any] | None) -> str:
    """Best-effort DefenseClaw data dir for custom-provider overlay reads."""
    for attr in ("data_dir", "config_dir", "home"):
        val = getattr(cfg, attr, "")
        if isinstance(val, str) and val:
            return val
    env = os.environ.get("DEFENSECLAW_HOME")
    if env:
        return env
    return os.path.expanduser("~/.defenseclaw")


def _llm_catalog_provider_choices() -> tuple[str, ...]:
    """Canonical provider ids, catalog order first, plus ``custom``."""
    base: list[str] = []
    try:
        from defenseclaw.commands import _llm_picker  # noqa: PLC0415

        base = [str(p.get("name", "")).strip() for p in _llm_picker.catalog_providers()]
        base = [name for name in base if name]
    except Exception:  # noqa: BLE001 - degrade to the static list.
        base = []
    if not base:
        base = list(_WIZARD_LLM_PROVIDERS)
    base.append("custom")
    return tuple(dict.fromkeys(base))


def llm_catalog_models(provider: str, instance_name: str = "", data_dir: str = "") -> tuple[str, ...]:
    """Curated model ids for ``provider`` (or a custom instance's models)."""
    try:
        from defenseclaw.commands import _llm_picker  # noqa: PLC0415

        models: list[str] = []
        if instance_name:
            inst = _llm_picker.custom_instance(data_dir, instance_name)
            if inst:
                models = [str(m) for m in (inst.get("available_models") or []) if m]
        if not models:
            entry = _llm_picker.catalog_entry(provider)
            if entry:
                models = [str(m) for m in (entry.get("models") or []) if m]
        return tuple(models)
    except Exception:  # noqa: BLE001 - the picker falls back to free text.
        return ()


def _llm_catalog_regions(provider: str) -> tuple[str, ...]:
    try:
        from defenseclaw.commands import _llm_picker  # noqa: PLC0415

        entry = _llm_picker.catalog_entry(provider) or {}
        return tuple(str(r) for r in (entry.get("regions") or []) if r)
    except Exception:  # noqa: BLE001
        return ()


def llm_model_candidates(
    fields: Sequence[WizardFormField],
    cfg: object | Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    """Curated model ids for the provider/instance currently selected in *fields*.

    Used by the searchable model picker so the modal can offer catalog
    suggestions while still accepting any free-text model id.
    """

    provider = (wizard_field_value(fields, "Provider") or "anthropic").strip().lower()
    instance = (wizard_field_value(fields, "Instance Name") or "").strip()
    return llm_catalog_models(provider, instance, _llm_data_dir(cfg))


def _provider_is(*names: str) -> Callable[[Mapping[str, str]], bool]:
    targets = {n.strip().lower() for n in names}
    return lambda dv: (dv.get("provider", "") or "").strip().lower() in targets


def _bedrock_auth_mode_is(*modes: str) -> Callable[[Mapping[str, str]], bool]:
    targets = {mode.strip().lower() for mode in modes}
    return lambda dv: (
        (dv.get("provider", "") or "").strip().lower() == "bedrock"
        and (dv.get("bedrock_auth_mode", "") or "api_key").strip().lower() in targets
    )


def _provider_regional_or_custom(dv: Mapping[str, str]) -> bool:
    provider = (dv.get("provider", "") or "").strip().lower()
    return provider in REGIONAL_PROVIDERS or provider == "custom"


def _field_value_overrides(fields: Sequence[WizardFormField]) -> dict[str, str]:
    """Snapshot current field values keyed by flag (``@label`` fallback).

    Keying by flag keeps preserved values stable across a dependent-field
    rebuild even when two provider groups reuse a label (e.g. both Bedrock
    and Vertex have an ``Auth Mode`` row) — their flags differ, so values
    never collide.
    """

    out: dict[str, str] = {}
    for field in fields:
        if field.kind == "section":
            continue
        key = field.flag or ("@" + field.label)
        out[key] = field.value
    return out


def _apply_dynamic_fields(
    candidates: Sequence[WizardFormField],
    overrides: Mapping[str, str],
    driver: Mapping[str, str],
) -> tuple[WizardFormField, ...]:
    """Filter ``candidates`` by visibility and overlay preserved values."""
    out: list[WizardFormField] = []
    for field in candidates:
        if not field.is_visible(driver):
            continue
        if field.kind != "section":
            key = field.flag or ("@" + field.label)
            if key in overrides:
                field = field.with_value(overrides[key])
        out.append(field)
    return tuple(out)


def _overlay_field_overrides(
    fields: Sequence[WizardFormField], overrides: Mapping[str, str]
) -> tuple[WizardFormField, ...]:
    """Overlay ``overrides`` onto ``fields`` by flag/``@label`` key.

    Unlike :func:`_apply_dynamic_fields` this does not re-derive visibility;
    it is used to seed a goal's presets onto a wizard that has no dependent
    rebuilder (the value carries through to :func:`build_wizard_args`).
    """

    out: list[WizardFormField] = []
    for field in fields:
        if field.kind != "section":
            key = field.flag or ("@" + field.label)
            if key in overrides:
                field = field.with_value(overrides[key])
        out.append(field)
    return tuple(out)


def _prune_empty_sections(fields: Sequence[WizardFormField]) -> tuple[WizardFormField, ...]:
    """Drop section dividers that have no following non-section row before
    the next divider, so a goal filter never leaves an orphaned header.
    """

    out: list[WizardFormField] = []
    for index, field in enumerate(fields):
        if field.kind == "section":
            has_child = False
            for following in fields[index + 1 :]:
                if following.kind == "section":
                    break
                has_child = True
                break
            if not has_child:
                continue
        out.append(field)
    return tuple(out)


# Goals that act on a connector that is already set up.
_CONFIGURED_CONNECTOR_GOALS = frozenset({"rerun", "remove"})

# "Choose which agents DefenseClaw protects" is the batch goal, so the
# "Batch setup only:" hint prefixes said nothing (GAP-2386).
_BULK_GOAL_HINTS: dict[str, str] = {
    "Connectors (CSV)": "Agents to protect, comma-separated (e.g. codex,hermes); the others are turned off.",
    "Detected Connectors": "Also protect every agent found on this machine.",
    "All Supported Connectors": "Protect every agent DefenseClaw supports.",
}
_REMOVE_CONNECTOR_HINT = "The agent to stop protecting; its hooks are removed (←/→ to pick)."


def _pin_goal_action(
    fields: Sequence[WizardFormField], goal: WizardGoal | None
) -> tuple[WizardFormField, ...]:
    """Keep a goal's Action row on the goal's own action.

    Each goal shows only the rows its action needs, so cycling Action in
    "Add or configure a connector" to batch asked for Connectors (CSV) or
    Detected/All rows the form never showed, and remove kept the ignored
    Guardrail Mode and Replace Existing rows (GAP-2026). "See which
    credentials are set" cycled to remove and then asked for an Env Name
    row it never showed (GAP-2185). The other actions have their own goals.
    """

    action = (goal.presets.get("@Action") or "") if goal is not None else ""
    if not action:
        return tuple(fields)
    return tuple(
        replace(
            field,
            options=(action,),
            value=action,
            default=action,
            hint="Fixed by this goal.",
        )
        if field.label == "Action" and field.kind == "choice" and action in field.options
        else field
        for field in fields
    )


def _narrow_goal_connectors(
    fields: Sequence[WizardFormField],
    goal: WizardGoal | None,
    cfg: object | Mapping[str, Any] | None,
    *,
    opening: bool = False,
) -> tuple[WizardFormField, ...]:
    """Offer only configured connectors to "Re-run setup" and "Remove".

    The Connector row cycled through every supported connector, so one Right
    press picked an agent that was not installed (GAP-1547). Configured
    connectors are listed alphabetically and the row starts on the first one
    unless it already holds a configured connector.
    """

    fields = _pin_goal_action(fields, goal)
    if goal is not None and goal.id == "bulk" and goal.presets.get("@Action") == "batch":
        # The Connectors row started empty instead of on the agents
        # protected now (GAP-2386).
        current = ",".join(sorted(dict.fromkeys(_active_connector_names_for_setup(cfg))))
        return tuple(
            replace(
                field,
                hint=_BULK_GOAL_HINTS[field.label],
                **({"value": current, "default": current} if field.label == "Connectors (CSV)" and not field.value else {}),
            )
            if field.label in _BULK_GOAL_HINTS
            else field
            for field in fields
        )
    if goal is None or goal.id not in _CONFIGURED_CONNECTOR_GOALS:
        return tuple(fields)
    configured = tuple(sorted(dict.fromkeys(_active_connector_names_for_setup(cfg))))
    if not configured:
        return tuple(fields)
    removing = goal.id == "remove"
    narrowed: list[WizardFormField] = []
    for field in fields:
        if field.label == "Connector" and field.kind == "choice":
            value = field.value if field.value in configured else configured[0]
            default = field.default if field.default in configured else configured[0]
            if removing and opening:
                # A destructive goal opened on the first roster entry, so
                # Ctrl+R removed claudecode before anything was picked
                # (GAP-2387): it starts with no connector chosen.
                value = default = ""
            field = replace(field, options=configured, value=value, default=default)
            if removing:
                field = replace(field, hint=_REMOVE_CONNECTOR_HINT)
        narrowed.append(field)
    return tuple(narrowed)


_MANAGE_GOAL_NOUNS: dict[SetupWizard, str] = {
    SetupWizard.OBSERVABILITY: "destination",
    SetupWizard.WEBHOOKS: "webhook",
}


def _narrow_manage_goal_fields(
    fields: Sequence[WizardFormField],
    wizard: SetupWizard | None,
    goal: WizardGoal | None,
) -> tuple[WizardFormField, ...]:
    """List/enable/disable/remove goals show only the rows their command takes.

    The preset's required rows (Splunk "Realm us1 - Sets --realm.") survived
    the goal filter, but ``setup observability list|enable|remove`` never
    passes them, and Name kept the generic add/enable/remove hint (GAP-2276).
    """

    noun = _MANAGE_GOAL_NOUNS.get(wizard) if wizard is not None else None
    action = (goal.presets.get("@Action") or "") if goal is not None else ""
    if noun is None or goal is None or action not in {"list", "enable", "disable", "remove"}:
        return tuple(fields)
    wanted = set(goal.fields)
    narrowed: list[WizardFormField] = []
    for field in fields:
        if field.label not in wanted:
            continue
        if field.label == "Name":
            field = replace(field, hint=f"Name of the {noun} to {action}.")
        narrowed.append(field)
    return tuple(narrowed)


def _filter_fields_for_goal(fields: Sequence[WizardFormField], goal: WizardGoal | None) -> tuple[WizardFormField, ...]:
    """Narrow ``fields`` to the rows relevant for ``goal``.

    A row is kept when it is a required selector (so driver rows like
    Role/Provider always survive a rebuild), is explicitly listed in
    ``goal.fields`` (by label *or* flag), or is touched by ``goal.presets``
    (so the seeded value stays visible and reaches the arg builder).

    Conditional rows (``visible_when`` set, e.g. the Bedrock/Vertex/Azure
    auth groups) are kept only when their owning section header is named in
    ``goal.fields`` — so a goal that lists ``"Bedrock"`` reveals that whole
    group when the operator picks a Bedrock provider, while a goal that does
    not name it (e.g. the Cisco goal) never surfaces unrelated judge groups.
    Orphaned section headers are pruned afterwards. An advanced goal (empty
    ``fields``) returns the rows unchanged.
    """

    if goal is None or not goal.fields:
        return tuple(fields)
    wanted = set(goal.fields)
    preset_keys = set(goal.presets.keys())
    kept: list[WizardFormField] = []
    current_section = ""
    for field in fields:
        if field.kind == "section":
            current_section = field.label
            kept.append(field)
            continue
        key = field.flag or ("@" + field.label)
        keep = (
            field.required
            or field.label in wanted
            or (bool(field.flag) and field.flag in wanted)
            or key in preset_keys
            or (field.visible_when is not None and current_section in wanted)
        )
        if keep:
            kept.append(field)
    return _prune_empty_sections(kept)


def _llm_wizard_fields_for(
    *,
    provider: str,
    role: str,
    overrides: Mapping[str, str],
    cfg: object | Mapping[str, Any] | None = None,
) -> tuple[WizardFormField, ...]:
    provider = (provider or "anthropic").strip().lower() or "anthropic"
    role = (role or "unified").strip().lower() or "unified"
    if role not in LLM_ROLES:
        role = "unified"
    provider_default = str(get_config_value(cfg, "llm.provider", "anthropic") or "anthropic").strip().lower()
    api_key_env = str(
        get_config_value(cfg, "llm.api_key_env", dc_config.DEFENSECLAW_LLM_KEY_ENV) or dc_config.DEFENSECLAW_LLM_KEY_ENV
    )
    timeout = str(get_config_value(cfg, "llm.timeout", 30) or 30)
    retries = str(get_config_value(cfg, "llm.max_retries", 2) or 2)
    model_default = str(get_config_value(cfg, "llm.model", "") or "")
    base_url_default = str(get_config_value(cfg, "llm.base_url", "") or "")
    region_opts = _llm_catalog_regions(provider)
    bedrock_auth_mode = str(get_config_value(cfg, "llm.bedrock.auth_mode", "api_key") or "api_key").strip().lower()
    bedrock_auth_mode = (overrides.get("--bedrock-auth-mode") or bedrock_auth_mode).strip().lower() or "api_key"
    is_bedrock = _provider_is("bedrock")
    is_bedrock_iam = _bedrock_auth_mode_is("iam_credentials")
    is_bedrock_profile = _bedrock_auth_mode_is("profile")
    is_vertex = _provider_is("vertex_ai")
    is_azure = _provider_is("azure")

    candidates: tuple[WizardFormField, ...] = (
        WizardFormField("Role", "choice", "--role", value=role, default="unified", options=LLM_ROLES, required=True),
        WizardFormField(
            "Provider",
            "choice",
            "--provider",
            value=provider,
            default=provider_default or "anthropic",
            options=_llm_catalog_provider_choices(),
            required=True,
        ),
        WizardFormField(
            "Instance Name",
            "string",
            "--instance-name",
            hint="Custom-provider instance from `setup provider add` (optional).",
        ),
        WizardFormField(
            "Model", "string", "--model", value=model_default, default=model_default, required=True, picker="llm"
        ),
        WizardFormField("API Key Env", "string", "--api-key-env", value=api_key_env, default=api_key_env),
        WizardFormField("API Key", "password", "--api-key"),
        WizardFormField("Base URL", "string", "--base-url", value=base_url_default, default=base_url_default),
        WizardFormField("Timeout", "int", "--timeout", value=timeout, default=timeout),
        WizardFormField("Max Retries", "int", "--max-retries", value=retries, default=retries),
        WizardFormField("Bedrock", "section", visible_when=is_bedrock),
        WizardFormField(
            "Region",
            "choice" if region_opts else "string",
            "--bedrock-region",
            options=region_opts,
            hint="AWS region, e.g. us-east-1.",
            visible_when=is_bedrock,
        ),
        WizardFormField(
            "Auth Mode",
            "choice",
            "--bedrock-auth-mode",
            value=bedrock_auth_mode,
            default=bedrock_auth_mode,
            options=BEDROCK_AUTH_MODES,
            visible_when=is_bedrock,
        ),
        WizardFormField("Access Key Env", "string", "--bedrock-access-key-env", visible_when=is_bedrock_iam),
        WizardFormField("Secret Key Env", "string", "--bedrock-secret-key-env", visible_when=is_bedrock_iam),
        WizardFormField("Session Token Env", "string", "--bedrock-session-token-env", visible_when=is_bedrock_iam),
        WizardFormField("Profile Name", "string", "--bedrock-profile-name", visible_when=is_bedrock_profile),
        WizardFormField("Inference Profile", "string", "--bedrock-inference-profile", visible_when=is_bedrock),
        WizardFormField(
            "Deployment Aliases (CSV)",
            "string",
            "--bedrock-deployment",
            hint="alias=model-id pairs, comma-separated (repeatable).",
            visible_when=is_bedrock,
        ),
        WizardFormField("Vertex AI", "section", visible_when=is_vertex),
        WizardFormField("Project ID", "string", "--vertex-project-id", visible_when=is_vertex),
        WizardFormField(
            "Region", "string", "--vertex-region", hint="GCP location, e.g. us-central1.", visible_when=is_vertex
        ),
        WizardFormField("Auth Mode", "choice", "--vertex-auth-mode", options=VERTEX_AUTH_MODES, visible_when=is_vertex),
        WizardFormField(
            "Service Account JSON Env", "string", "--vertex-service-account-json-env", visible_when=is_vertex
        ),
        WizardFormField("Azure", "section", visible_when=is_azure),
        WizardFormField(
            "Endpoint", "string", "--azure-endpoint", hint="https://name.openai.azure.com", visible_when=is_azure
        ),
        WizardFormField("API Version", "string", "--azure-api-version", hint="e.g. 2024-10-21.", visible_when=is_azure),
        WizardFormField("Auth Mode", "choice", "--azure-auth-mode", options=AZURE_AUTH_MODES, visible_when=is_azure),
        WizardFormField(
            "Deployment Aliases (CSV)",
            "string",
            "--azure-deployment-alias",
            hint="model=deployment pairs, comma-separated (repeatable).",
            visible_when=is_azure,
        ),
        WizardFormField("TLS", "section", visible_when=_provider_regional_or_custom),
        WizardFormField(
            "TLS CA Cert File",
            "string",
            "--tls-ca-cert-file",
            hint="PEM CA bundle for self-signed endpoints.",
            visible_when=_provider_regional_or_custom,
        ),
        WizardFormField(
            "Insecure Skip Verify",
            "bool",
            "--insecure-skip-verify",
            value="no",
            default="no",
            hint="Disable TLS verification (lab use only).",
            visible_when=_provider_regional_or_custom,
        ),
        WizardFormField("Apply", "section"),
        WizardFormField(
            "Inherit From",
            "choice",
            "--inherit-from",
            value="",
            default="",
            options=("", *LLM_INHERIT_PATHS),
            hint="Copy a sibling LLM block before applying flags (optional).",
        ),
        WizardFormField(
            "Ping After Save",
            "bool",
            "--ping",
            "--no-ping",
            value="no",
            default="no",
            hint="Send a one-shot reachability probe after saving.",
        ),
    )
    driver = {"provider": provider, "role": role, "bedrock_auth_mode": bedrock_auth_mode}
    return _apply_dynamic_fields(_hinted(candidates, _LLM_FORM_HINTS), overrides, driver)


def llm_wizard_fields(cfg: object | Mapping[str, Any] | None = None) -> tuple[WizardFormField, ...]:
    provider = str(get_config_value(cfg, "llm.provider", "anthropic") or "anthropic").strip().lower() or "anthropic"
    return _llm_wizard_fields_for(provider=provider, role="unified", overrides={}, cfg=cfg)


# Repeatable flags whose CSV field value fans out to one ``--flag value``
# pair per comma-separated item (mirrors ``multiple=True`` on the CLI).
_LLM_REPEATABLE_FLAGS: frozenset[str] = frozenset({"--bedrock-deployment", "--azure-deployment-alias"})


def _build_llm_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    """Translate the connector-aware LLM wizard form into ``setup llm`` argv.

    Only the *visible* fields reach this builder (the model already pruned
    the hidden provider groups), so every non-empty string/choice row maps
    1:1 to its ``--flag value``. ``--role`` is always emitted because it is
    the selector that decides where the block is written.
    """

    base: list[str] = ["setup", "llm", "--non-interactive"]
    for field in fields:
        if field.kind == "section":
            continue
        if field.kind == "bool":
            if field.value == field.default:
                continue
            if field.value == "yes" and field.flag:
                base.append(field.flag)
            elif field.value == "no" and field.no_flag:
                base.append(field.no_flag)
            continue
        if not field.flag:
            continue
        value = field.value.strip()
        if not value:
            continue
        if field.flag in _LLM_REPEATABLE_FLAGS:
            for item in split_csv(value):
                if item:
                    base.extend((field.flag, item))
            continue
        base.extend((field.flag, value))
    return tuple(base)


def _guardrail_wizard_fields_for(
    overrides: Mapping[str, str] | None = None,
    cfg: object | Mapping[str, Any] | None = None,
) -> tuple[WizardFormField, ...]:
    overrides = overrides or {}
    active_connectors = _active_connector_names_for_setup(cfg)
    scope = (overrides.get("@Scope") or _guardrail_default_scope(cfg)).strip()
    if scope not in _GUARDRAIL_SCOPES:
        scope = _guardrail_default_scope(cfg)
    connector_policy = scope == _GUARDRAIL_SCOPE_CONNECTOR
    if "--connector" in overrides:
        connector = str(overrides.get("--connector", "") or "").strip()
    else:
        connector = str(get_config_value(cfg, "guardrail.connector", "") or "").strip()
        if not connector:
            connector = str(get_config_value(cfg, "claw.mode", "") or "").strip()
        if connector_policy and len(active_connectors) > 1:
            connector = ""
    if not connector_policy and len(active_connectors) > 1:
        # A global/all-active form has no selected-connector presentation.
        connector = ""
    mode = (
        _effective_guardrail_value(cfg, connector, "effective_mode", "guardrail.mode")
        if connector_policy and connector
        else str(get_config_value(cfg, "guardrail.mode", "observe"))
    )
    mode = mode.strip().lower() or "observe"
    scanner_mode = str(get_config_value(cfg, "guardrail.scanner_mode", "local") or "local")
    strategy = str(get_config_value(cfg, "guardrail.detection_strategy", "regex_only") or "regex_only")
    # The pack the scope enforces: config_version 9 rule_pack, else the v8 dir.
    rule_pack_dir = _effective_guardrail_value(
        cfg, connector if connector_policy else "", "effective_rule_pack_dir", "guardrail.rule_pack_dir"
    )
    rule_pack_options: tuple[str, ...] = ("default", "strict", "permissive")
    pack_name = os.path.basename(rule_pack_dir.rstrip("/\\")).strip() if rule_pack_dir else ""
    rule_pack = pack_name.lower() or "default"
    if rule_pack not in rule_pack_options:
        # A custom pack is active. Show it as the untouched value so the form
        # never emits ``--rule-pack default`` over it; picking a preset still
        # emits that preset.
        rule_pack = f"custom ({pack_name})"
        rule_pack_options = (rule_pack, *rule_pack_options)
    judge_provider = "bedrock"
    judge_model = ""
    judge_provider_default = "bedrock"
    judge_model_default = ""
    if judge := str(
        get_config_value(cfg, "guardrail.judge.llm.model", "")
        or get_config_value(cfg, "guardrail.judge.model", "")
        or ""
    ):
        if "/" in judge:
            judge_provider, judge_model = judge.split("/", 1)
        else:
            judge_model = judge
            judge_provider = str(get_config_value(cfg, "guardrail.judge.llm.provider", "") or "") or judge_provider
    elif model := str(get_config_value(cfg, "llm.model", "") or ""):
        judge_model = model
        judge_model_default = model
        if provider := str(get_config_value(cfg, "llm.provider", "") or ""):
            judge_provider = provider
            judge_provider_default = provider
    # Mirror the CLI's server-side promotion (cmd_setup ``_apply...`` ~ the
    # ``gc.judge.enabled`` branch): once a dedicated judge model is set the
    # judge actually runs, so leaving the wizard on ``regex_only`` would
    # silently keep it off. Surface ``regex_judge`` so the displayed strategy
    # matches what saving the form will write. Only a dedicated
    # ``guardrail.judge.model`` triggers this — a value merely inherited from
    # ``llm.model`` is not emitted as ``--judge-model`` and must not promote.
    # A judge strategy with the judge off scans regex only (the goal menu's
    # "Now: regex_only (judge off)"), so open the form on that (GAP-2349).
    if not judge and strategy in ("regex_judge", "judge_first"):
        if not bool(get_config_value(cfg, "guardrail.judge.enabled", False)):
            strategy = "regex_only"
    # The field default is the current strategy, so any other choice
    # (regex_only included) is emitted as --detection-strategy; the CLI flag
    # defaults to "keep current" (GAP-2349).
    strategy_default = strategy
    if judge and strategy in ("", "regex_only"):
        strategy = "regex_judge"
    strategy = (overrides.get("--detection-strategy") or strategy).strip() or "regex_only"
    # A live provider change (driver) wins so the conditional Bedrock /
    # Vertex / Azure judge groups re-derive against the new selection.
    judge_provider = (overrides.get("@Provider") or judge_provider).strip().lower() or judge_provider
    judge_key_env = str(
        get_config_value(cfg, "guardrail.judge.llm.api_key_env", "")
        or get_config_value(cfg, "guardrail.judge.api_key_env", "")
        or ""
    )
    judge_key_default = ""
    if not judge_key_env:
        judge_key_env = str(get_config_value(cfg, "llm.api_key_env", "") or "")
        judge_key_default = judge_key_env
    judge_base = str(
        get_config_value(cfg, "guardrail.judge.llm.base_url", "")
        or get_config_value(cfg, "guardrail.judge.api_base", "")
        or ""
    )
    judge_base_default = ""
    if not judge_base:
        judge_base = str(get_config_value(cfg, "llm.base_url", "") or "")
        judge_base_default = judge_base
    judge_bedrock_auth_mode = (
        str(get_config_value(cfg, "guardrail.judge.llm.bedrock.auth_mode", "api_key") or "api_key").strip().lower()
    )
    judge_bedrock_auth_mode = (
        overrides.get("--judge-bedrock-auth-mode") or judge_bedrock_auth_mode
    ).strip().lower() or "api_key"
    effective_hilt = (
        _effective_hilt_block(cfg, connector)
        if connector_policy and connector
        else get_config_value(cfg, "guardrail.hilt", None)
    )
    hilt = "yes" if bool(get_config_value(effective_hilt, "enabled", False)) else "no"
    hilt_min_severity = str(get_config_value(effective_hilt, "min_severity", "HIGH") or "HIGH").upper()
    block_message = (
        _effective_guardrail_value(cfg, connector, "effective_block_message", "guardrail.block_message")
        if connector_policy and connector
        else str(get_config_value(cfg, "guardrail.block_message", "") or "")
    )

    def connector_scope(dv: Mapping[str, str]) -> bool:
        return dv.get("scope") == _GUARDRAIL_SCOPE_CONNECTOR

    def global_scope(dv: Mapping[str, str]) -> bool:
        return dv.get("scope") == _GUARDRAIL_SCOPE_GLOBAL

    def connector_or_bootstrap_target(dv: Mapping[str, str]) -> bool:
        return connector_scope(dv) or (global_scope(dv) and len(active_connectors) <= 1)

    def j_strategy(dv: Mapping[str, str]) -> bool:
        return global_scope(dv) and (dv.get("strategy", "") or "").strip().lower() in {
            "regex_judge",
            "judge_first",
        }

    def j_provider_is(*names: str) -> Callable[[Mapping[str, str]], bool]:
        provider_visible = _provider_is(*names)
        return lambda dv: j_strategy(dv) and provider_visible(dv)

    def j_bedrock_auth_mode_is(*modes: str) -> Callable[[Mapping[str, str]], bool]:
        auth_visible = _bedrock_auth_mode_is(*modes)
        return lambda dv: j_strategy(dv) and auth_visible(dv)

    def j_provider_regional_or_custom(dv: Mapping[str, str]) -> bool:
        return j_strategy(dv) and _provider_regional_or_custom(dv)

    j_bedrock = j_provider_is("bedrock")
    j_bedrock_iam = j_bedrock_auth_mode_is("iam_credentials")
    j_bedrock_profile = j_bedrock_auth_mode_is("profile")
    j_vertex = j_provider_is("vertex_ai", "vertex")
    j_azure = j_provider_is("azure")
    j_region_opts = _llm_catalog_regions(judge_provider)
    judge_bedrock_region = str(get_config_value(cfg, "guardrail.judge.llm.bedrock.region", "") or "").strip()
    if j_region_opts and judge_bedrock_region and judge_bedrock_region not in j_region_opts:
        j_region_opts = (judge_bedrock_region, *j_region_opts)
    candidates: tuple[WizardFormField, ...] = (
        WizardFormField("Operation Scope", "section"),
        WizardFormField(
            "Scope",
            "choice",
            value=scope,
            default=_guardrail_default_scope(cfg),
            options=_GUARDRAIL_SCOPES,
            hint="Change one connector's policy, or the settings shared by every protected agent.",
        ),
        WizardFormField("Connector policy (this connector only)", "section", visible_when=connector_scope),
        WizardFormField("Global settings (all active connectors)", "section", visible_when=global_scope),
        WizardFormField(
            "Connector",
            "choice",
            "--connector",
            value=connector,
            default=connector,
            options=_guardrail_connector_choices(cfg),
            required=True,
            hint="The connector whose policy this changes (on a first setup, also the one set up).",
            visible_when=connector_or_bootstrap_target,
        ),
        WizardFormField(
            "Mode",
            "choice",
            "--mode",
            value=mode,
            default=mode,
            options=("observe", "action"),
            hint="observe only logs what the policy would block; action blocks it.",
        ),
        WizardFormField(
            "Scanner Mode",
            "choice",
            "--scanner-mode",
            value=scanner_mode,
            default="local",
            options=("local", "remote", "both"),
            visible_when=global_scope,
        ),
        WizardFormField(
            "Proxy Port",
            "int",
            "--port",
            value=str(get_config_value(cfg, "guardrail.port", "") or ""),
            visible_when=global_scope,
        ),
        WizardFormField("Detection", "section", visible_when=global_scope),
        WizardFormField(
            "Strategy",
            "choice",
            "--detection-strategy",
            value=strategy,
            default=strategy_default,
            options=("regex_only", "regex_judge", "judge_first"),
            hint=(
                "Rule/regex scanning is the baseline; regex_judge and judge_first turn the LLM judge on "
                "(set its model and key in 'Set up / change the LLM Judge')."
            ),
            visible_when=global_scope,
        ),
        WizardFormField(
            "Rule Pack",
            "choice",
            "--rule-pack",
            value=rule_pack,
            default=rule_pack,
            options=rule_pack_options,
        ),
        WizardFormField(
            "Block Message",
            "string",
            "--block-message",
            value=block_message,
            default=block_message,
            hint="Custom message for the selected connector, or every connector in global scope.",
        ),
        WizardFormField("LLM Judge", "section", visible_when=j_strategy),
        WizardFormField(
            "Provider",
            "choice",
            value=judge_provider,
            default=judge_provider_default,
            options=_llm_catalog_provider_choices(),
            visible_when=j_strategy,
        ),
        WizardFormField(
            "Model",
            "string",
            "--judge-model",
            value=judge_model,
            default=judge_model_default,
            picker="llm",
            visible_when=j_strategy,
        ),
        WizardFormField(
            "API Key Env",
            "string",
            "--judge-api-key-env",
            value=judge_key_env,
            default=judge_key_default,
            visible_when=j_strategy,
        ),
        WizardFormField(
            "API Base URL",
            "string",
            "--judge-api-base",
            value=judge_base,
            default=judge_base_default,
            visible_when=j_strategy,
        ),
        WizardFormField(
            "Instance Name",
            "string",
            "--judge-instance-name",
            hint="Custom-provider instance for the judge (optional).",
            visible_when=j_strategy,
        ),
        WizardFormField(
            "LLM Role",
            "choice",
            "--llm-role",
            value="judge_only",
            default="judge_only",
            options=GUARDRAIL_JUDGE_LLM_ROLES,
            hint="judge_only=hook connectors; judge_and_agent=proxy connectors.",
            visible_when=j_strategy,
        ),
        WizardFormField(
            "Inherit From",
            "choice",
            "--inherit-from",
            value="",
            default="",
            options=GUARDRAIL_JUDGE_INHERIT_PATHS,
            hint="Copy a sibling LLM block onto the judge before flags (optional).",
            visible_when=j_strategy,
        ),
        WizardFormField("Judge: Bedrock", "section", visible_when=j_bedrock),
        WizardFormField(
            "Region",
            "choice" if j_region_opts else "string",
            "--judge-bedrock-region",
            value=judge_bedrock_region,
            default=judge_bedrock_region,
            options=j_region_opts,
            hint="AWS region, e.g. us-east-1.",
            visible_when=j_bedrock,
        ),
        WizardFormField(
            "Auth Mode",
            "choice",
            "--judge-bedrock-auth-mode",
            value=judge_bedrock_auth_mode,
            default=judge_bedrock_auth_mode,
            options=BEDROCK_AUTH_MODES,
            visible_when=j_bedrock,
        ),
        WizardFormField("Access Key Env", "string", "--judge-bedrock-access-key-env", visible_when=j_bedrock_iam),
        WizardFormField("Secret Key Env", "string", "--judge-bedrock-secret-key-env", visible_when=j_bedrock_iam),
        WizardFormField("Session Token Env", "string", "--judge-bedrock-session-token-env", visible_when=j_bedrock_iam),
        WizardFormField("Profile Name", "string", "--judge-bedrock-profile-name", visible_when=j_bedrock_profile),
        WizardFormField("Inference Profile", "string", "--judge-bedrock-inference-profile", visible_when=j_bedrock),
        WizardFormField(
            "Deployment Aliases (CSV)",
            "string",
            "--judge-bedrock-deployment",
            hint="alias=model-id pairs, comma-separated (repeatable).",
            visible_when=j_bedrock,
        ),
        WizardFormField("Judge: Vertex AI", "section", visible_when=j_vertex),
        WizardFormField("Project ID", "string", "--judge-vertex-project-id", visible_when=j_vertex),
        WizardFormField("Region", "string", "--judge-vertex-region", hint="GCP location.", visible_when=j_vertex),
        WizardFormField(
            "Auth Mode", "choice", "--judge-vertex-auth-mode", options=VERTEX_AUTH_MODES, visible_when=j_vertex
        ),
        WizardFormField(
            "Service Account JSON Env",
            "string",
            "--judge-vertex-service-account-json-env",
            visible_when=j_vertex,
        ),
        WizardFormField("Judge: Azure", "section", visible_when=j_azure),
        WizardFormField(
            "Endpoint", "string", "--judge-azure-endpoint", hint="https://name.openai.azure.com", visible_when=j_azure
        ),
        WizardFormField("API Version", "string", "--judge-azure-api-version", visible_when=j_azure),
        WizardFormField(
            "Auth Mode", "choice", "--judge-azure-auth-mode", options=AZURE_AUTH_MODES, visible_when=j_azure
        ),
        WizardFormField(
            "Deployment Aliases (CSV)",
            "string",
            "--judge-azure-deployment-alias",
            hint="model=deployment pairs, comma-separated (repeatable).",
            visible_when=j_azure,
        ),
        WizardFormField("Judge: TLS", "section", visible_when=j_provider_regional_or_custom),
        WizardFormField(
            "TLS CA Cert File",
            "string",
            "--judge-tls-ca-cert-file",
            hint="PEM CA bundle for self-signed judge endpoints.",
            visible_when=j_provider_regional_or_custom,
        ),
        WizardFormField(
            "Insecure Skip Verify",
            "bool",
            "--judge-insecure-skip-verify",
            value="no",
            default="no",
            hint="Disable TLS verification for the judge (lab use only).",
            visible_when=j_provider_regional_or_custom,
        ),
        WizardFormField("Cisco AI Defense (global)", "section", visible_when=global_scope),
        WizardFormField(
            "Endpoint",
            "string",
            "--cisco-endpoint",
            value=str(get_config_value(cfg, "cisco_ai_defense.endpoint", "") or ""),
            visible_when=global_scope,
        ),
        WizardFormField(
            "API Key Env",
            "string",
            "--cisco-api-key-env",
            value=str(get_config_value(cfg, "cisco_ai_defense.api_key_env", "") or ""),
            visible_when=global_scope,
        ),
        WizardFormField(
            "Timeout (ms)",
            "int",
            "--cisco-timeout-ms",
            value=str(get_config_value(cfg, "cisco_ai_defense.timeout_ms", "") or ""),
            visible_when=global_scope,
        ),
        WizardFormField("Advanced", "section"),
        WizardFormField("Human Approval", "bool", "--human-approval", "--no-human-approval", value=hilt, default=hilt),
        WizardFormField(
            "Approval Min Severity",
            "choice",
            "--hilt-min-severity",
            value=hilt_min_severity,
            default=hilt_min_severity,
            options=("HIGH", "MEDIUM", "LOW", "CRITICAL"),
        ),
        WizardFormField("Post-Setup", "section"),
        WizardFormField("Restart After", "bool", "--restart", "--no-restart", value="yes", default="yes"),
        WizardFormField("Verify After Setup", "bool", "--verify", "--no-verify", value="yes", default="yes"),
        WizardFormField(
            "Disable Selected Connector",
            "bool",
            "--disable",
            value="no",
            default="no",
            hint="Uses guardrail disable --connector; peer connectors remain enabled.",
            visible_when=connector_scope,
        ),
        WizardFormField(
            "Disable Guardrail Globally",
            "bool",
            "--disable",
            value="no",
            default="no",
            hint="Explicit global kill switch: affects every active connector.",
            visible_when=global_scope,
        ),
    )
    return _apply_dynamic_fields(
        candidates,
        overrides,
        {
            "provider": judge_provider,
            "bedrock_auth_mode": judge_bedrock_auth_mode,
            "strategy": strategy,
            "scope": scope,
        },
    )


def guardrail_wizard_fields(cfg: object | Mapping[str, Any] | None = None) -> tuple[WizardFormField, ...]:
    return _guardrail_wizard_fields_for({}, cfg)


SPLUNK_PIPELINE_OPTIONS: tuple[str, ...] = ("splunk-o11y", "local-docker", "enterprise", "custom")


def splunk_wizard_fields(os_name: str | None = None) -> tuple[WizardFormField, ...]:
    local_available = local_splunk_stack_supported(os_name)
    options = (
        SPLUNK_PIPELINE_OPTIONS
        if local_available
        else tuple(option for option in SPLUNK_PIPELINE_OPTIONS if option != "local-docker")
    )
    fields = (
        WizardFormField("Pipeline", "section"),
        WizardFormField(
            "Mode",
            "choice",
            "",
            value="splunk-o11y",
            default="splunk-o11y",
            options=options,
        ),
        WizardFormField(
            "Apply Dashboards After",
            "bool",
            value="no",
            default="no",
        ),
        WizardFormField("Splunk Pipelines", "section"),
        WizardFormField("Enable O11y", "bool", "--o11y", value="no", default="no"),
        WizardFormField("Enable Local Logs", "bool", "--logs", value="no", default="no"),
        WizardFormField("Enable Enterprise", "bool", "--enterprise", value="no", default="no"),
        WizardFormField("Splunk O11y Settings", "section"),
        WizardFormField("Realm", "string", "--realm"),
        WizardFormField("Access Token", "password", "--access-token"),
        WizardFormField("HEC", "section"),
        WizardFormField("HEC Endpoint", "string", "--hec-endpoint"),
        WizardFormField("HEC Token", "password", "--hec-token"),
        WizardFormField("Skip HEC Test", "bool", "--skip-test", value="no", default="no"),
        WizardFormField("App Name", "string", "--app-name", value="defenseclaw", default="defenseclaw"),
        WizardFormField("Traces", "bool", "--traces", "--no-traces", value="yes", default="yes"),
        WizardFormField("Metrics", "bool", "--metrics", "--no-metrics", value="yes", default="yes"),
        WizardFormField("Logs Export", "bool", "--logs-export", "--no-logs-export", value="no", default="no"),
        WizardFormField("HEC Index", "string", "--index", value="defenseclaw_local", default="defenseclaw_local"),
        WizardFormField("HEC Source", "string", "--source", value="defenseclaw", default="defenseclaw"),
        WizardFormField(
            "HEC Sourcetype", "string", "--sourcetype", value="defenseclaw:json", default="defenseclaw:json"
        ),
        WizardFormField("Advanced", "section"),
        WizardFormField("Accept Splunk License", "bool", "--accept-splunk-license", value="no", default="no"),
        WizardFormField("Show Credentials", "bool", "--show-credentials", value="no", default="no"),
        WizardFormField("Disable", "bool", "--disable", value="no", default="no"),
    )
    if local_available:
        return fields
    local_labels = {"Enable Local Logs", "Accept Splunk License", "Show Credentials"}
    return tuple(field for field in fields if field.label not in local_labels)


def splunk_wizard_follow_up_intents(
    fields: Sequence[WizardFormField],
) -> tuple[SetupCommandIntent, ...]:
    """Queue ``splunk_o11y_dashboards apply`` when the operator opted
    in. Mirrors the CLI's "Apply dashboards now?" follow-up prompt.
    """

    if wizard_bool_value(fields, "Apply Dashboards After", "no") != "yes":
        return ()
    return (
        SetupCommandIntent(
            label="setup splunk dashboards apply",
            args=("setup", "splunk", "dashboards", "apply", "--yes"),
            origin="setup-wizard",
        ),
    )


def observability_wizard_fields(
    preset_id: str,
    cfg: object | Mapping[str, Any] | None = None,
) -> tuple[WizardFormField, ...]:
    preset_options = tuple(
        preset for preset, _ in OBSERVABILITY_PRESETS if preset != "local-otlp" or local_observability_stack_supported()
    )
    fields: list[WizardFormField] = [
        WizardFormField(
            "Action",
            "choice",
            value="add",
            default="add",
            options=("add", "list", "enable", "disable", "remove"),
            hint="Add a destination, list destinations, or manage an existing destination.",
        ),
        WizardFormField(
            "Preset",
            "preset",
            value=preset_id,
            default=preset_id,
            options=preset_options,
        ),
        WizardFormField("Name", "string", "--name", hint="Optional for add; required for enable/disable/remove."),
        WizardFormField("Enabled", "bool", "--enabled", "--disabled", value="yes", default="yes"),
        WizardFormField("JSON Output", "bool", value="no", default="no", hint="For list actions."),
        WizardFormField("Dry Run", "bool", "--dry-run", value="no", default="no"),
    ]
    if preset_id == "splunk-o11y":
        fields.extend(
            (
                WizardFormField("Realm", "string", "--realm", value="us1", default="us1", required=True),
                WizardFormField("Signals", "string", "--signals", value="traces,metrics", default="traces,metrics"),
                WizardFormField("Access Token", "password", "--token"),
            ),
        )
    elif preset_id == "splunk-hec":
        fields.extend(
            (
                WizardFormField("Host", "string", "--host", value="localhost", default="localhost", required=True),
                WizardFormField("Port", "int", "--port", value="8088", default="8088", required=True),
                WizardFormField("Index", "string", "--index", value="defenseclaw", default="defenseclaw"),
                WizardFormField("Source", "string", "--source", value="defenseclaw", default="defenseclaw"),
                WizardFormField("Sourcetype", "string", "--sourcetype", value="_json", default="_json"),
                WizardFormField("Verify TLS", "bool", "--verify-tls", "--no-verify-tls", value="no", default="no"),
                WizardFormField("HEC Token", "password", "--token"),
            ),
        )
    elif preset_id == "splunk-enterprise":
        fields.extend(
            (
                WizardFormField("Endpoint", "string", "--endpoint", required=True),
                WizardFormField("Index", "string", "--index", value="defenseclaw", default="defenseclaw"),
                WizardFormField("Source", "string", "--source", value="defenseclaw", default="defenseclaw"),
                WizardFormField("Sourcetype", "string", "--sourcetype", value="_json", default="_json"),
                WizardFormField("HEC Token", "password", "--token"),
            ),
        )
    elif preset_id == "datadog":
        fields.extend(
            (
                WizardFormField("Site", "string", "--site", value="us5", default="us5", required=True),
                WizardFormField(
                    "Signals", "string", "--signals", value="traces,metrics,logs", default="traces,metrics,logs"
                ),
                WizardFormField("API Key", "password", "--token"),
            ),
        )
    elif preset_id == "honeycomb":
        fields.extend(
            (
                WizardFormField(
                    "Dataset", "string", "--dataset", value="defenseclaw", default="defenseclaw", required=True
                ),
                WizardFormField(
                    "Signals", "string", "--signals", value="traces,metrics,logs", default="traces,metrics,logs"
                ),
                WizardFormField("API Key", "password", "--token"),
            ),
        )
    elif preset_id == "newrelic":
        fields.extend(
            (
                WizardFormField(
                    "Region", "choice", "--region", value="us", default="us", options=("us", "eu"), required=True
                ),
                WizardFormField(
                    "Signals", "string", "--signals", value="traces,metrics,logs", default="traces,metrics,logs"
                ),
                WizardFormField("License Key", "password", "--token"),
            ),
        )
    elif preset_id == "grafana-cloud":
        fields.extend(
            (
                WizardFormField(
                    "Region/Zone", "string", "--region", value="prod-us-east-0", default="prod-us-east-0", required=True
                ),
                WizardFormField(
                    "Signals", "string", "--signals", value="traces,metrics,logs", default="traces,metrics,logs"
                ),
                WizardFormField("OTLP Token", "password", "--token"),
            ),
        )
    elif preset_id == "galileo":
        fields.extend(
            (
                WizardFormField(
                    "Trace Endpoint",
                    "string",
                    "--endpoint",
                    value="https://api.galileo.ai/otel/traces",
                    default="https://api.galileo.ai/otel/traces",
                    required=True,
                    hint="Cloud default or exact self-hosted /otel/traces endpoint.",
                ),
                WizardFormField("Project", "string", "--project", required=True),
                WizardFormField(
                    "Log Stream", "string", "--logstream", value="default", default="default", required=True
                ),
                WizardFormField(
                    "API Key",
                    "password",
                    "--token",
                    hint="Required unless GALILEO_API_KEY is already configured in the environment or .env.",
                ),
            ),
        )
    elif preset_id == "otlp":
        fields.extend(
            (
                WizardFormField("Endpoint", "string", "--endpoint", required=True),
                WizardFormField(
                    "Protocol", "choice", "--protocol", value="grpc", default="grpc", options=("grpc", "http")
                ),
                WizardFormField(
                    "Signals", "string", "--signals", value="traces,metrics,logs", default="traces,metrics,logs"
                ),
            ),
        )
    elif preset_id == "webhook":
        fields.extend(
            (
                WizardFormField("URL", "string", "--url", required=True),
                WizardFormField("Method", "choice", "--method", value="POST", default="POST", options=("POST", "PUT")),
                WizardFormField("Verify TLS", "bool", "--verify-tls", "--no-verify-tls", value="yes", default="yes"),
                WizardFormField("Bearer Token (optional)", "password", "--token"),
            ),
        )
    return tuple(fields)


def webhook_wizard_fields(channel_type: str) -> tuple[WizardFormField, ...]:
    fields: list[WizardFormField] = [
        WizardFormField(
            "Action",
            "choice",
            value="add",
            default="add",
            options=("add", "list", "enable", "disable", "remove"),
            hint="Add a webhook, list webhooks, or manage an existing webhook.",
        ),
        WizardFormField(
            "Type", "whtype", value=channel_type, default=channel_type, options=tuple(kind for kind, _ in WEBHOOK_TYPES)
        ),
        WizardFormField("Name", "string", "--name", hint="Optional for add; required for enable/disable/remove."),
        WizardFormField("URL", "string", "--url", required=True),
        WizardFormField("Enabled", "bool", "--enabled", "--disabled", value="yes", default="yes"),
        WizardFormField(
            "Connector",
            "choice",
            "--connector",
            value="",
            default="",
            options=("", *CONNECTORS),
            hint="Optional: scope this webhook to one connector; blank keeps the CLI default/global behavior.",
        ),
        WizardFormField("JSON Output", "bool", value="no", default="no", hint="For list actions."),
        WizardFormField(
            "Min Severity",
            "choice",
            "--min-severity",
            value="HIGH",
            default="HIGH",
            options=("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
        ),
        WizardFormField(
            "Events",
            "string",
            "--events",
            value="block,scan,guardrail,drift,health",
            default="block,scan,guardrail,drift,health",
        ),
        WizardFormField("Timeout (seconds)", "int", "--timeout-seconds", value="10", default="10"),
        WizardFormField("Cooldown (seconds)", "string", "--cooldown-seconds"),
        WizardFormField("Dry Run", "bool", "--dry-run", value="no", default="no"),
    ]
    if channel_type == "slack":
        fields.append(WizardFormField("Secret env (optional)", "string", "--secret-env"))
    elif channel_type == "pagerduty":
        fields.append(
            WizardFormField(
                "Routing key env",
                "string",
                "--secret-env",
                value="DEFENSECLAW_PD_ROUTING_KEY",
                default="DEFENSECLAW_PD_ROUTING_KEY",
                required=True,
            ),
        )
    elif channel_type == "webex":
        fields.extend(
            (
                WizardFormField(
                    "Bot token env",
                    "string",
                    "--secret-env",
                    value="DEFENSECLAW_WEBEX_TOKEN",
                    default="DEFENSECLAW_WEBEX_TOKEN",
                    required=True,
                ),
                WizardFormField("Room ID", "string", "--room-id", required=True),
            ),
        )
    elif channel_type == "generic":
        # ``Enable HMAC Signing`` defaults to yes to mirror the CLI's
        # default behaviour (``click.confirm(...default=True)``). When
        # disabled, ``--secret-env`` is skipped so the webhook ships
        # unsigned. The build_wizard_args function consults this bool
        # to suppress the matching ``--secret-env`` value.
        fields.extend(
            (
                WizardFormField(
                    "Enable HMAC Signing",
                    "bool",
                    value="yes",
                    default="yes",
                ),
                WizardFormField(
                    "HMAC secret env (optional)",
                    "string",
                    "--secret-env",
                    value="DEFENSECLAW_WEBHOOK_SECRET",
                    default="DEFENSECLAW_WEBHOOK_SECRET",
                ),
            ),
        )
    return tuple(fields)


def registry_wizard_fields() -> tuple[WizardFormField, ...]:
    return (
        WizardFormField("Source id", "regid", value="corp-skills", default="corp-skills", required=True),
        WizardFormField(
            "Kind",
            "choice",
            "--kind",
            value="http_yaml",
            default="http_yaml",
            options=REGISTRY_KIND_OPTIONS,
            required=True,
        ),
        WizardFormField(
            "Content",
            "choice",
            "--content",
            value="skill",
            default="skill",
            options=REGISTRY_CONTENT_OPTIONS,
            required=True,
        ),
        WizardFormField("Manifest URL", "string", "--url"),
        WizardFormField("Auth env (optional)", "string", "--auth-env"),
        WizardFormField("Enabled", "bool", "--enabled", "--disabled", value="yes", default="yes"),
        # Post-add follow-ups (do NOT forward as CLI flags on ``registry
        # add``; consumed by the wizard arg-builder to queue follow-up
        # intents). Mirror the CLI prompts in
        # ``cli/defenseclaw/commands/cmd_registry.py``.
        WizardFormField("Sync Now", "bool", value="yes", default="yes"),
        WizardFormField("Scan After Sync", "bool", value="yes", default="yes"),
    )


def registry_wizard_follow_up_intents(
    fields: Sequence[WizardFormField],
) -> tuple[SetupCommandIntent, ...]:
    """Return follow-up intents queued after ``registry add`` succeeds.

    The Registry wizard exposes ``Sync Now`` and ``Scan After Sync``
    booleans. When the user keeps them enabled, we chain
    ``registry sync <id>`` and ``skill scan --registry <id>`` after the
    add call returns 0. Mirrors the interactive CLI follow-up prompts.
    """

    source_id = next((field.value.strip() for field in fields if field.kind == "regid"), "")
    intents: list[SetupCommandIntent] = []
    if not source_id:
        return ()
    if wizard_bool_value(fields, "Sync Now", "yes") == "yes":
        intents.append(
            SetupCommandIntent(
                label=f"registry sync {source_id}",
                args=("registry", "sync", source_id),
                origin="setup-wizard",
            )
        )
    if wizard_bool_value(fields, "Scan After Sync", "yes") == "yes":
        intents.append(
            SetupCommandIntent(
                label=f"skill scan ({source_id})",
                args=("skill", "scan", "--registry", source_id),
                origin="setup-wizard",
            )
        )
    return tuple(intents)


def wizard_field_value(fields: Sequence[WizardFormField], label: str, *, raw: bool = False) -> str:
    for field in fields:
        if field.label == label:
            return field.value if raw else field.value.strip()
    return ""


def wizard_bool_value(fields: Sequence[WizardFormField], label: str, fallback: str) -> str:
    value = wizard_field_value(fields, label).lower()
    return value if value in {"yes", "no"} else fallback


def _build_connector_setup_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    connector = wizard_field_value(fields, "Connector") or _DEFAULT_SETUP_CONNECTOR
    action = wizard_field_value(fields, "Action") or "setup"
    if action == "batch":
        out = ["setup", "--yes"]
        for name in split_csv(wizard_field_value(fields, "Connectors (CSV)")):
            out.extend(("--connector", name))
        if wizard_bool_value(fields, "Detected Connectors", "no") == "yes":
            out.append("--detected")
        if wizard_bool_value(fields, "All Supported Connectors", "no") == "yes":
            out.append("--all")
        if mode := wizard_field_value(fields, "Guardrail Mode"):
            out.extend(("--mode", mode))
        if wizard_bool_value(fields, "Restart Gateway", "yes") == "no":
            out.append("--no-restart")
        return tuple(out)
    if action == "remove":
        # No default here: the Remove goal starts unpicked (GAP-2387).
        picked = wizard_field_value(fields, "Connector")
        out = ["setup", "remove", *((picked,) if picked else ()), "--yes"]
        if wizard_bool_value(fields, "Restart Gateway", "yes") == "no":
            out.append("--no-restart")
        if wizard_bool_value(fields, "Force Last Connector Removal", "no") == "yes":
            out.append("--force")
        return tuple(out)

    args, _display = connector_setup_command(connector)
    if not args:
        args, _display = connector_setup_command("openclaw")
        connector = "openclaw"
    out = list(args)
    # ``--mode`` and ``--no-restart`` apply to every connector (proxy and
    # hook). Previously the hook branch dropped ``--mode`` silently, so
    # ``setup codex --mode action`` from the wizard ended up running
    # ``setup codex`` and defaulting to observe.
    if mode := wizard_field_value(fields, "Guardrail Mode"):
        out.extend(("--mode", mode))
    if wizard_bool_value(fields, "Restart Gateway", "yes") == "no":
        out.append("--no-restart")
    if is_guardrail_supporting(connector):
        # Only the proxy connectors take ``--scanner-mode`` /
        # ``--verify``; hook connectors use ``--with-local-stack``.
        if scanner := wizard_field_value(fields, "Scanner Mode"):
            out.extend(("--scanner-mode", scanner))
        if wizard_bool_value(fields, "Verify After Setup", "yes") == "no":
            out.append("--no-verify")
        return tuple(out)
    if wizard_bool_value(fields, "Replace Existing", "no") == "yes":
        out.append("--replace")
    if workspace_dir := wizard_field_value(fields, "Workspace Dir"):
        out.extend(("--workspace", workspace_dir))
    if wizard_bool_value(fields, "Local Stack", "no") == "yes":
        out.append("--with-local-stack")
    return tuple(out)


def _build_credentials_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    action = wizard_field_value(fields, "Action")
    if action == "check":
        return ("keys", "check")
    if action == "fill-missing":
        # ``--non-interactive`` lists the missing creds without trying
        # to drive per-key hidden prompts (which the TUI subprocess
        # cannot satisfy). User then runs 'Set' for each.
        return ("keys", "fill-missing", "--yes")
    if action == "set":
        args = ["keys", "set"]
        if env_name := wizard_field_value(fields, "Env Name"):
            args.append(env_name)
        args.append("--value-stdin")
        # The secret value is intentionally NOT placed in argv (it would be
        # visible in process listings). ``--value-stdin`` makes ``keys set``
        # read one line from stdin instead of the terminal; the value is
        # carried on the intent's ``secret_stdin`` and written (then stdin
        # closed) by the executor. See F-0801.
        return tuple(args)
    if action == "remove":
        # The command preview is the confirmation; the CLI prompt can't be
        # answered from the TUI subprocess.
        # An empty name previews as <ENV_NAME> (the run waits for one), not
        # as an empty quoted argument (GAP-2061).
        return ("keys", "remove", wizard_field_value(fields, "Env Name") or "<ENV_NAME>", "--yes")
    # The readable table, not --json: this output is read by a person in
    # Activity (GAP-1162). The Setup panel loads its own JSON copy.
    return ("keys", "list")


def _build_local_observability_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    action = wizard_field_value(fields, "Action") or "status"
    args = ["setup", "local-observability", action]
    if action == "up":
        if (timeout := wizard_field_value(fields, "Timeout")) and timeout != "180":
            args.extend(("--timeout", timeout))
        if wizard_bool_value(fields, "No Wait", "no") == "yes":
            args.append("--no-wait")
        if wizard_bool_value(fields, "No Config", "no") == "yes":
            args.append("--no-config")
        if (signals := wizard_field_value(fields, "Signals")) and signals != "traces,metrics,logs":
            args.extend(("--signals", signals))
        if (service := wizard_field_value(fields, "Service Name")) and service != "defenseclaw":
            args.extend(("--service-name", service))
    elif action == "reset" and wizard_bool_value(fields, "Confirm Reset", "no") == "yes":
        args.append("--yes")
    elif action == "logs":
        if service := wizard_field_value(fields, "Service"):
            args.extend(("--service", service))
        if wizard_bool_value(fields, "Follow", "no") == "yes":
            args.append("--follow")
    elif action == "url" and wizard_bool_value(fields, "JSON Output", "no") == "yes":
        args.append("--json")
    return tuple(args)


# Custom-provider flags whose CSV field repeats once per item (mirrors the
# CLI's ``multiple=True`` options).
_CUSTOM_PROVIDER_REPEATABLE_FLAGS: frozenset[str] = frozenset(
    {
        "--available-model",
        "--allowed-request",
        "--request-path-override",
        "--bedrock-deployment",
        "--azure-deployment-alias",
    }
)


def _build_custom_provider_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    action = wizard_field_value(fields, "Action")
    if action == "show":
        return ("setup", "provider", "show")
    if action not in {"add", "remove"}:
        return ("setup", "provider", "list")
    args: list[str] = ["setup", "provider", action]
    if name := wizard_field_value(fields, "Name"):
        args.extend(("--name", name))
    if action == "remove":
        if wizard_bool_value(fields, "Reload Sidecar", "yes") == "no":
            args.append("--no-reload")
        return tuple(args)
    # action == "add": label-only CSV groups first, then every flagged
    # field that survived the dependent-field visibility filter.
    for domain in split_csv(wizard_field_value(fields, "Domains")):
        args.extend(("--domain", domain))
    for env_key in split_csv(wizard_field_value(fields, "Env Keys")):
        args.extend(("--env-key", env_key))
    if profile_id := wizard_field_value(fields, "Profile ID"):
        args.extend(("--profile-id", profile_id))
    for port in split_csv(wizard_field_value(fields, "Ollama Ports")):
        args.extend(("--ollama-port", port))
    for field in fields:
        if field.kind == "section" or not field.flag:
            continue
        if field.kind == "bool":
            if field.value == "yes":
                args.append(field.flag)
            continue
        value = field.value.strip()
        if not value:
            continue
        if field.flag in _CUSTOM_PROVIDER_REPEATABLE_FLAGS:
            for item in split_csv(value):
                if item:
                    args.extend((field.flag, item))
            continue
        args.extend((field.flag, value))
    if wizard_bool_value(fields, "Reload Sidecar", "yes") == "no":
        args.append("--no-reload")
    return tuple(args)


def _guardrail_connector_keys(cfg: object | Mapping[str, Any] | None) -> list[str]:
    """Active connectors to render per-connector guardrail groups for (B4).

    Prefers the live ``Config.active_connectors()`` (multi-connector aware,
    R1-clean) so every active hook connector gets an editable override group;
    falls back to the ``guardrail.connectors`` map keys for dict-backed configs.
    Connectors with an existing override are always included even when the
    active set can't be resolved, so a configured override never becomes
    invisible/uneditable.
    """

    names: list[str] = []
    method = getattr(cfg, "active_connectors", None)
    if callable(method):
        try:
            names = [str(n).strip() for n in method() if str(n).strip()]
        except Exception:  # noqa: BLE001 - degrade to the map keys below.
            names = []
    overrides = get_config_value(cfg, "guardrail.connectors", None)
    override_keys = (
        [str(k).strip() for k in overrides.keys() if str(k).strip()] if isinstance(overrides, Mapping) else []
    )
    # Merge, preserving active-set order then any override-only keys.
    seen: set[str] = set()
    merged: list[str] = []
    for name in (*names, *override_keys):
        if name and name not in seen:
            seen.add(name)
            merged.append(name)
    return merged


def _rule_pack_options(cfg: object | Mapping[str, Any] | None) -> tuple[str, ...]:
    """``guardrail.rule_pack`` choices: the presets, then the custom_packs names."""
    guardrail = cfg.get("guardrail") if isinstance(cfg, Mapping) else getattr(cfg, "guardrail", None)
    custom = guardrail.get("custom_packs") if isinstance(guardrail, Mapping) else getattr(guardrail, "custom_packs", None)
    presets = ("default", "strict", "permissive")
    names = sorted(str(name) for name in (custom or {}) if str(name) not in presets)
    return ("", *presets, *names)


def _effective_guardrail_value(
    cfg: object | Mapping[str, Any] | None, connector: str, method_name: str, fallback_path: str
) -> str:
    """Resolve a connector's *effective* guardrail value for display (B4).

    Calls the matching ``GuardrailConfig.effective_*(connector)`` resolver so
    the editor shows what the connector actually uses (its override, or the
    inherited global). Falls back to the raw global path for dict-backed
    configs that don't expose the resolver.
    """

    guardrail = getattr(cfg, "guardrail", None)
    if (
        method_name == "effective_hook_fail_mode"
        and connector in {"claudecode", "codex", "amp"}
        and hasattr(cfg, "data_dir")
    ):
        try:
            from defenseclaw.fail_mode import connector_fail_mode_report

            report = connector_fail_mode_report(
                cfg,
                connector,
                inspect_effective_policy=False,
            )
            detail = f"provenance: {report['provenance']}"
            if report.get("note"):
                detail += f"; {report['note']}"
            if report["drift"]:
                detail += f"; status: {', '.join(report['drift'])}"
            return f"{report['effective']} ({detail})"
        except Exception:  # noqa: BLE001 - config editor must remain available during drift.
            pass
    resolver = getattr(guardrail, method_name, None) if guardrail is not None else None
    if callable(resolver):
        try:
            return str(resolver(connector) or "")
        except Exception:  # noqa: BLE001 - degrade to the raw global value.
            pass
    leaf = {
        "effective_mode": "mode",
        "effective_hook_fail_mode": "hook_fail_mode",
        "effective_block_message": "block_message",
        "effective_rule_pack_dir": "rule_pack_dir",
    }.get(method_name, "")
    overrides = get_config_value(cfg, "guardrail.connectors", None)
    if connector and leaf and isinstance(overrides, Mapping):
        normalized = connector.strip().lower().replace("-", "").replace("_", "")
        for name, entry in overrides.items():
            candidate = str(name).strip().lower().replace("-", "").replace("_", "")
            if candidate != normalized:
                continue
            value = get_config_value(entry, leaf, "")
            if str(value or "").strip():
                return str(value)
            break
    return str(get_config_value(cfg, fallback_path, "") or "")


def _effective_guardrail_bool(
    cfg: object | Mapping[str, Any] | None,
    connector: str,
    method_name: str,
    fallback_path: str,
    *,
    default: bool,
) -> str:
    """Resolve a connector's effective *boolean* guardrail value for display (B4).

    The boolean sibling of :func:`_effective_guardrail_value`: calls the matching
    ``GuardrailConfig.effective_*(connector)`` resolver and returns the canonical
    ``"true"``/``"false"`` string the ``bool`` :class:`ConfigField` renders, so a
    connector shows what it actually uses (its override, or the inherited
    default). Falls back to the raw global path (then *default*) for dict-backed
    configs that don't expose the resolver.
    """

    guardrail = getattr(cfg, "guardrail", None)
    resolver = getattr(guardrail, method_name, None) if guardrail is not None else None
    if callable(resolver):
        try:
            return "true" if resolver(connector) else "false"
        except Exception:  # noqa: BLE001 - degrade to the raw global value.
            pass
    if fallback_path:
        return "true" if get_config_value(cfg, fallback_path, default) else "false"
    return "true" if default else "false"


def _effective_hilt_block(cfg: object | Mapping[str, Any] | None, connector: str) -> object | None:
    """Resolve a connector's effective HILT (human-approval) block (B4/E4d).

    Returns the connector's override block when present, else the inherited
    global block, via ``GuardrailConfig.effective_hilt(connector)`` — so the
    editor shows the approval state the connector actually uses. Degrades to the
    raw global ``guardrail.hilt`` (then ``None``) for dict-backed configs.
    """

    guardrail = getattr(cfg, "guardrail", None)
    resolver = getattr(guardrail, "effective_hilt", None) if guardrail is not None else None
    if callable(resolver):
        try:
            return resolver(connector)
        except Exception:  # noqa: BLE001 - degrade to the raw global block.
            pass
    overrides = get_config_value(cfg, "guardrail.connectors", None)
    if connector and isinstance(overrides, Mapping):
        normalized = connector.strip().lower().replace("-", "").replace("_", "")
        for name, entry in overrides.items():
            candidate = str(name).strip().lower().replace("-", "").replace("_", "")
            if candidate != normalized:
                continue
            block = get_config_value(entry, "hilt", None)
            if block is not None:
                return block
            break
    return get_config_value(cfg, "guardrail.hilt", None)


def _effective_judge_hook_state(cfg: object | Mapping[str, Any] | None, connector: str) -> str:
    """Effective hook-lane judge state for *connector* (B4 — Flag #2 judge half).

    Per-connector judge is membership in the ``guardrail.judge.hook_connectors``
    gate list, not a :class:`PerConnectorGuardrailConfig` field. Returns
    ``"true"`` when the gate covers this connector — either via the ``"*"``
    every-connector sentinel or an explicit (fold/whitespace-tolerant) entry,
    matching the Go gate (``JudgeConfig.HookConnectorEnabled``) the gateway
    enforces and the CLI's ``_gate_is_all``/``_gate_contains``.
    """

    gate = get_config_value(cfg, "guardrail.judge.hook_connectors", None)
    if not isinstance(gate, (list, tuple)):
        return "false"
    name = connector.strip().lower()
    for entry in gate:
        token = str(entry or "").strip()
        if token == "*" or token.lower() == name:
            return "true"
    return "false"


def _judge_hook_connectors_wizard_value(cfg: object | Mapping[str, Any] | None) -> str:
    gate = get_config_value(cfg, "guardrail.judge.hook_connectors", None)
    if not isinstance(gate, (list, tuple)):
        return ""
    tokens = [str(entry or "").strip() for entry in gate if str(entry or "").strip()]
    if tokens == ["*"]:
        return "all"
    return ",".join(tokens)


def _per_connector_guardrail_fields(cfg: object | Mapping[str, Any] | None) -> list[ConfigField]:
    """Build per-connector guardrail override groups for the config editor (B4).

    One header + editable rows per active connector covering every per-connector
    guardrail control: ``mode``, ``rule_pack_dir``, ``enabled`` (E4c),
    ``hook_fail_mode``, ``hilt`` enable + min-severity, ``block_message`` (E4d),
    and the hook-lane judge toggle (membership in
    ``guardrail.judge.hook_connectors``). Each row displays the *effective* value
    (the connector's override, or the inherited global) and is wired to the raw
    per-connector path so editing it pins an override for that connector only —
    the apply path (``setup_state._apply_per_connector_guardrail_field`` /
    ``_apply_judge_hook_connector_toggle``) writes a typed override so the
    boot-loop ``effective_*`` resolvers keep working.
    """

    keys = _guardrail_connector_keys(cfg)
    if not keys:
        return []
    # Single-connector installs with no existing overrides have nothing to
    # disambiguate — the global fields above already cover them — so skip the
    # extra groups. (``guardrail.connectors`` defaults to an empty dict, so
    # test for actual entries, not just "is a map".)
    overrides = get_config_value(cfg, "guardrail.connectors", None)
    has_overrides = isinstance(overrides, Mapping) and len(overrides) > 0
    if len(keys) < 2 and not has_overrides:
        return []
    rows: list[ConfigField] = [_header(".. Per-Connector Overrides ..")]
    for connector in keys:
        label = friendly_connector_name(connector) or connector
        rows.append(_header(f".. {label} ({connector}) .."))
        mode_field = _field(
            cfg,
            "Mode",
            f"guardrail.connectors.{connector}.mode",
            "choice",
            ("observe", "action"),
            f"Per-connector mode for {connector} (blank inherits the global mode).",
        )
        rows.append(
            _field_with_original(
                mode_field, _effective_guardrail_value(cfg, connector, "effective_mode", "guardrail.mode")
            )
        )
        pack_field = _field(
            cfg,
            "Rule Pack",
            f"guardrail.connectors.{connector}.rule_pack",
            "choice",
            _rule_pack_options(cfg),
            f"Per-connector rule pack for {connector} (blank inherits the global pack).",
        )
        rows.append(
            _field_with_original(
                pack_field,
                _effective_guardrail_value(cfg, connector, "effective_rule_pack", "guardrail.rule_pack"),
            )
        )
        # E4c: per-connector guardrail enable/disable. ``effective_enabled``
        # defaults to True (an unset override inherits "enabled"), so there is
        # no global path to fall back to — the default IS enabled.
        enabled_field = _field(
            cfg,
            "Enabled",
            f"guardrail.connectors.{connector}.enabled",
            "bool",
            hint=f"Per-connector guardrail switch for {connector} (off tears down its hooks; on by default).",
        )
        rows.append(
            _field_with_original(
                enabled_field,
                _effective_guardrail_bool(cfg, connector, "effective_enabled", "", default=True),
            )
        )
        # Fail-mode writes must use the Guardrail action so config and the
        # installed registration are updated transactionally. Keep the live
        # effective value visible here, but do not expose a raw config edit.
        fail_value = _effective_guardrail_value(cfg, connector, "effective_hook_fail_mode", "guardrail.hook_fail_mode")
        rows.append(
            ConfigField(
                label="Hook Fail Mode (use Guardrail action)",
                key=f"guardrail.connectors.{connector}.hook_fail_mode",
                kind="header",
                value=fail_value,
                original=fail_value,
            )
        )
        # E4d: human-in-the-loop approval. A per-connector hilt block fully
        # replaces the global one (see GuardrailConfig.effective_hilt), so show
        # the effective block's enable + min-severity.
        hilt_block = _effective_hilt_block(cfg, connector)
        hilt_field = _field(
            cfg,
            "Human Approval",
            f"guardrail.connectors.{connector}.hilt.enabled",
            "bool",
            hint=f"Ask before supported high-risk actions for {connector}.",
        )
        rows.append(
            _field_with_original(
                hilt_field,
                "true" if getattr(hilt_block, "enabled", False) else "false",
            )
        )
        sev_field = _field(
            cfg,
            "Approval Min Severity",
            f"guardrail.connectors.{connector}.hilt.min_severity",
            "choice",
            ("HIGH", "MEDIUM", "LOW", "CRITICAL"),
            f"Minimum severity for {connector} approval prompts.",
        )
        rows.append(
            _field_with_original(
                sev_field,
                str(getattr(hilt_block, "min_severity", "") or ""),
            )
        )
        # E4d: per-connector block message returned when a request is blocked.
        block_field = _field(
            cfg,
            "Block Message",
            f"guardrail.connectors.{connector}.block_message",
            hint=f"Per-connector block message for {connector} (blank inherits the global message).",
        )
        rows.append(
            _field_with_original(
                block_field,
                _effective_guardrail_value(cfg, connector, "effective_block_message", "guardrail.block_message"),
            )
        )
        # Flag #2 (judge half): per-connector judge is membership in the
        # guardrail.judge.hook_connectors LIST, not a PerConnectorGuardrailConfig
        # field. The synthetic ``guardrail.judge.hook_connectors.<c>`` key routes
        # to _apply_judge_hook_connector_toggle, which adds/removes this one name
        # surgically (mirrors the CLI --judge-hook-connectors).
        judge_field = _field(
            cfg,
            "LLM Judge (hook lane)",
            f"guardrail.judge.hook_connectors.{connector}",
            "bool",
            hint=f"Add/remove {connector} from the hook-lane judge gate (guardrail.judge.hook_connectors).",
        )
        rows.append(
            _field_with_original(
                judge_field,
                _effective_judge_hook_state(cfg, connector),
            )
        )
    return rows


def _guardrail_section(cfg: object | Mapping[str, Any] | None) -> ConfigSection:
    fields = [
        _header(".. Core .."),
        _field(cfg, "Enabled", "guardrail.enabled", "bool", hint="Master guardrail switch."),
        _field(cfg, "Mode", "guardrail.mode", "choice", ("observe", "action"), "observe=log only; action=block."),
        _header(
            "Hook Fail Mode (use Guardrail action)",
            "guardrail.hook_fail_mode",
            _value(cfg, "guardrail.hook_fail_mode"),
        ),
        _field(
            cfg,
            "Scanner Mode",
            "guardrail.scanner_mode",
            "choice",
            ("local", "remote", "both"),
            "local=regex/judge; remote=Cisco AI Defense; both=chained.",
        ),
        _field(cfg, "Connector", "guardrail.connector", "choice", ("", *CONNECTORS), "Blank follows claw.mode."),
        _field(
            cfg,
            "Allow Empty Providers",
            "guardrail.allow_empty_providers",
            "bool",
            hint="Let sidecar boot with no upstream providers.",
        ),
        _field(
            cfg,
            "Allow Unknown LLM Domains",
            "guardrail.allow_unknown_llm_domains",
            "bool",
            hint="Permit unknown LLM-looking hosts.",
        ),
        _field(cfg, "Human Approval", "guardrail.hilt.enabled", "bool", hint="Ask before supported high-risk actions."),
        _field(
            cfg,
            "Approval Min Severity",
            "guardrail.hilt.min_severity",
            "choice",
            ("HIGH", "MEDIUM", "LOW", "CRITICAL"),
            "Minimum severity for approval prompts.",
        ),
        _field(cfg, "Host", "guardrail.host", hint="Proxy bind address."),
        _field(cfg, "Port", "guardrail.port", "int", hint="Proxy listen port."),
        _field(cfg, "Model", "guardrail.model", hint="Legacy upstream model identifier."),
        _field(cfg, "Model Name", "guardrail.model_name", hint="Display name shown to agents."),
        _field(cfg, "Original Model", "guardrail.original_model", hint="Client-visible original model."),
        _field(cfg, "API Key Env", "guardrail.api_key_env", hint="Legacy upstream API key env name."),
        _field(cfg, "API Base", "guardrail.api_base", hint="Legacy upstream API URL."),
        *_llm_override_fields(cfg, "Guardrail", "guardrail.llm"),
        _field(cfg, "Block Message", "guardrail.block_message", hint="Response text returned when blocked."),
        _field(
            cfg, "Stream Buffer", "guardrail.stream_buffer_bytes", "int", hint="Chunk size for streaming inspection."
        ),
        _field(
            cfg,
            "Retain Judge Bodies",
            "guardrail.retain_judge_bodies",
            "bool",
            hint="Persist raw judge verdicts locally.",
        ),
        _header(".. Detection .."),
        _field(
            cfg,
            "Strategy",
            "guardrail.detection_strategy",
            "choice",
            ("regex_only", "regex_judge", "judge_first"),
            "Global detection strategy.",
        ),
        _field(
            cfg,
            "Strategy (Prompt)",
            "guardrail.detection_strategy_prompt",
            "choice",
            ("", "regex_only", "regex_judge", "judge_first"),
            "Prompt override; blank=inherit.",
        ),
        _field(
            cfg,
            "Strategy (Completion)",
            "guardrail.detection_strategy_completion",
            "choice",
            ("", "regex_only", "regex_judge", "judge_first"),
            "Completion override; blank=inherit.",
        ),
        _field(
            cfg,
            "Strategy (Tool Call)",
            "guardrail.detection_strategy_tool_call",
            "choice",
            ("", "regex_only", "regex_judge", "judge_first"),
            "Tool-call override; blank=inherit.",
        ),
        _field(
            cfg,
            "Rule Pack",
            "guardrail.rule_pack",
            "choice",
            _rule_pack_options(cfg),
            "Preset or guardrail.custom_packs name; add a custom pack with: guardrail use-pack DIR.",
        ),
        _field(
            cfg,
            "Block At",
            "guardrail.block_at",
            "choice",
            ("", "CRITICAL", "HIGH", "MEDIUM", "LOW"),
            "Lowest severity prompts, completions and tool calls block at; blank=the rule pack's level.",
        ),
        _field(
            cfg,
            "Alert At",
            "guardrail.alert_at",
            "choice",
            ("", "CRITICAL", "HIGH", "MEDIUM", "LOW"),
            "Lowest severity prompts, completions and tool calls alert at; blank=the rule pack's level.",
        ),
        _field(cfg, "Judge Sweep", "guardrail.judge_sweep", "bool", hint="Judge all requests in regex_only mode."),
        _header(".. LLM Judge .."),
        _field(cfg, "Judge Enabled", "guardrail.judge.enabled", "bool", hint="Enable LLM-as-judge scanner."),
        _field(cfg, "Judge Model", "guardrail.judge.model", hint="Legacy judge model id."),
        _field(cfg, "Judge API Key Env", "guardrail.judge.api_key_env", hint="Legacy judge API key env."),
        _field(cfg, "Judge API Base", "guardrail.judge.api_base", hint="Legacy judge API base URL."),
        _field(cfg, "Judge Timeout", "guardrail.judge.timeout", hint="Seconds to wait for one judge call."),
        _field(
            cfg, "Adjudication Timeout", "guardrail.judge.adjudication_timeout", hint="Total judge fallback budget."
        ),
        _field(cfg, "Fallbacks", "guardrail.judge.fallbacks", hint="CSV of backup judge models."),
        *_llm_override_fields(cfg, "Judge", "guardrail.judge.llm"),
        _header(".. Judge Categories .."),
        _field(cfg, "Injection", "guardrail.judge.injection", "bool", hint="Detect prompt injection."),
        _field(cfg, "Exfiltration", "guardrail.judge.exfil", "bool", hint="Detect data exfiltration attempts."),
        _field(cfg, "PII", "guardrail.judge.pii", "bool", hint="Master PII toggle."),
        _field(cfg, "PII (Prompt)", "guardrail.judge.pii_prompt", "bool", hint="Flag PII on inbound prompts."),
        _field(cfg, "PII (Completion)", "guardrail.judge.pii_completion", "bool", hint="Flag PII on completions."),
        _field(
            cfg, "Tool Injection", "guardrail.judge.tool_injection", "bool", hint="Detect payloads in tool-call args."
        ),
    ]
    # B4: per-connector override groups (mode, rule-pack, enabled, fail-mode,
    # hilt, block-message, judge) so the connectors[...] map the boot loop
    # actually reads is fully visible + editable, not just the singular/global
    # fields above.
    fields.extend(_per_connector_guardrail_fields(cfg))
    return ConfigSection("Guardrail", tuple(fields), "LLM-egress proxy and judge settings.")


def _scanners_section(cfg: object | Mapping[str, Any] | None) -> ConfigSection:
    fields = [
        _header(".. Skill Scanner .."),
        _field(
            cfg,
            "Policy",
            "scanners.skill_scanner.policy",
            "choice",
            _SKILL_SCANNER_POLICIES,
            "Skill scanner policy (recommended: quiet with the LLM judge).",
        ),
        _field(
            cfg,
            "Block At",
            "scanners.skill_scanner.fail_on_severity",
            "choice",
            ("", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
            "Findings at or above this severity block (empty: HIGH).",
        ),
        _field(
            cfg,
            "Review From",
            "scanners.skill_scanner.review_queue_min",
            "choice",
            ("", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
            "Findings from here up to Block At go to review (empty: MEDIUM).",
        ),
        _field(cfg, "Lenient", "scanners.skill_scanner.lenient", "bool", hint="Tolerate malformed skills (off: fail them)."),
        _field(cfg, "Use LLM", "scanners.skill_scanner.use_llm", "bool", hint="Run the LLM judge (recommended)."),
        _field(
            cfg,
            "Judge Source",
            "scanners.skill_scanner.judge_source",
            "choice",
            ("", "inherit", "override"),
            "inherit: the top-level llm block; override: the LLM override below.",
        ),
        _field(
            cfg, "LLM Consensus Runs", "scanners.skill_scanner.llm_consensus_runs", "int", hint="Number of LLM votes."
        ),
        _field(cfg, "Use Behavioral", "scanners.skill_scanner.use_behavioral", "bool", hint="Run behavioral analysis."),
        _field(cfg, "Enable Meta", "scanners.skill_scanner.enable_meta", "bool", hint="Scan skill metadata."),
        _field(
            cfg, "Use Trigger", "scanners.skill_scanner.use_trigger", "bool", hint="Enable trigger-word heuristics."
        ),
        _field(
            cfg,
            "Use VirusTotal",
            "scanners.skill_scanner.analyzers.virustotal.enabled",
            "bool",
            hint="Optional: look up artifact hashes.",
        ),
        _field(
            cfg,
            "VirusTotal Key Env",
            "scanners.skill_scanner.analyzers.virustotal.api_key_env",
            hint="Env var NAME for VirusTotal key (empty: VIRUSTOTAL_API_KEY).",
        ),
        _field(
            cfg,
            "Use AI Defense",
            "scanners.skill_scanner.analyzers.aidefense.enabled",
            "bool",
            hint="Optional: chain a Cisco AI Defense scan.",
        ),
        _field(
            cfg,
            "Use OSV",
            "scanners.skill_scanner.analyzers.osv.enabled",
            "bool",
            hint="Optional: check dependencies on OSV.dev.",
        ),
        *_llm_override_fields(cfg, "Skill Scanner", "scanners.skill_scanner.llm"),
        _header(".. MCP Scanner .."),
        _field(cfg, "Analyzers", "scanners.mcp_scanner.analyzers", hint="CSV of analyzer IDs; auto: YARA plus a ready LLM."),
        _field(cfg, "Scan Prompts", "scanners.mcp_scanner.scan_prompts", "bool", hint="Scan MCP prompt templates."),
        _field(
            cfg, "Scan Resources", "scanners.mcp_scanner.scan_resources", "bool", hint="Scan MCP resource contents."
        ),
        _field(
            cfg, "Scan Instructions", "scanners.mcp_scanner.scan_instructions", "bool", hint="Scan server instructions."
        ),
        *_llm_override_fields(cfg, "MCP Scanner", "scanners.mcp_scanner.llm"),
        _header(".. Plugin / CodeGuard .."),
        _field(cfg, "Plugin Scanner", "scanners.plugin_scanner", hint="Command to scan connector plugins."),
        *_llm_override_fields(cfg, "Plugin Scanner", "scanners.plugin_llm"),
        _field(cfg, "CodeGuard", "scanners.codeguard", hint="Command for CodeGuard skill."),
    ]
    return ConfigSection("Scanners", tuple(fields), "Skill/MCP/Plugin scanner binaries and behavior flags.")


def _ai_discovery_section(cfg: object | Mapping[str, Any] | None) -> ConfigSection:
    fields = (
        _field(cfg, "Enabled", "ai_discovery.enabled", "bool", hint="Run AI discovery service."),
        _field(cfg, "Mode", "ai_discovery.mode", hint="passive or enhanced."),
        _field(cfg, "Scan Interval (min)", "ai_discovery.scan_interval_min", "int", hint="Minutes between full scans."),
        _field(
            cfg, "Process Interval (s)", "ai_discovery.process_interval_s", "int", hint="Seconds between process scans."
        ),
        _field(cfg, "Scan Roots", "ai_discovery.scan_roots", hint="CSV roots for artifact scans."),
        _field(cfg, "Signature Packs", "ai_discovery.signature_packs", hint="CSV custom signature packs."),
        _field(
            cfg,
            "Workspace Signatures",
            "ai_discovery.allow_workspace_signatures",
            "bool",
            hint="Allow workspace signatures.",
        ),
        _field(
            cfg, "Disabled Signatures", "ai_discovery.disabled_signature_ids", hint="CSV signature IDs to suppress."
        ),
        _field(
            cfg, "Shell History", "ai_discovery.include_shell_history", "bool", hint="Match known AI command patterns."
        ),
        _field(
            cfg,
            "Package Manifests",
            "ai_discovery.include_package_manifests",
            "bool",
            hint="Detect AI SDK dependencies.",
        ),
        _field(cfg, "Env Var Names", "ai_discovery.include_env_var_names", "bool", hint="Detect env var names only."),
        _field(
            cfg, "Provider Domains", "ai_discovery.include_network_domains", "bool", hint="Detect provider domains."
        ),
        _field(
            cfg,
            "Online Model Provenance",
            "ai_discovery.lookup_model_provenance_online",
            "bool",
            hint="Send recovered public model repository IDs to Hugging Face for lineage enrichment.",
        ),
        _field(cfg, "Max Files", "ai_discovery.max_files_per_scan", "int", hint="Max files per scan."),
        _field(cfg, "Max File Bytes", "ai_discovery.max_file_bytes", "int", hint="Skip larger files."),
        _field(
            cfg,
            "Store Raw Local Paths",
            "ai_discovery.store_raw_local_paths",
            "bool",
            hint="Store raw paths locally only.",
        ),
    )
    return ConfigSection("AI Discovery", fields, "Continuous local discovery for supported and shadow AI usage.")


def _gateway_watcher_section(cfg: object | Mapping[str, Any] | None) -> ConfigSection:
    fields = (
        _field(cfg, "Enabled", "gateway.watcher.enabled", "bool", hint="Master switch for all watchers."),
        _header(".. Skill .."),
        _field(cfg, "Enabled", "gateway.watcher.skill.enabled", "bool", hint="Watch skill directories."),
        _field(
            cfg, "Take Action", "gateway.watcher.skill.take_action", "bool", hint="Re-apply enforcement on changes."
        ),
        _field(cfg, "Dirs", "gateway.watcher.skill.dirs", hint="CSV extra skill directories."),
        _header(".. Plugin .."),
        _field(cfg, "Enabled", "gateway.watcher.plugin.enabled", "bool", hint="Watch plugin_dir."),
        _field(cfg, "Take Action", "gateway.watcher.plugin.take_action", "bool", hint="Re-apply enforcement."),
        _field(cfg, "Dirs", "gateway.watcher.plugin.dirs", hint="CSV extra plugin directories."),
        _header(".. MCP .."),
        _field(
            cfg,
            "Take Action",
            "gateway.watcher.mcp.take_action",
            "bool",
            hint="Re-apply enforcement on MCP config changes.",
        ),
    )
    return ConfigSection("Gateway Watcher", fields, "Filesystem watcher that auto-scans assets as they appear.")


def _watch_section(cfg: object | Mapping[str, Any] | None) -> ConfigSection:
    return ConfigSection(
        "Watch",
        (
            _field(cfg, "Debounce MS", "watch.debounce_ms", "int", hint="Milliseconds to wait for edits to settle."),
            _field(cfg, "Auto Block", "watch.auto_block", "bool", hint="Block high findings automatically."),
            _field(
                cfg, "Rescan Enabled", "watch.rescan_enabled", "bool", hint="Periodically re-scan installed artifacts."
            ),
            _field(cfg, "Rescan Interval Min", "watch.rescan_interval_min", "int", hint="Minutes between rescans."),
        ),
        "Filesystem-watch tuning shared across asset watchers.",
    )


def _openshell_admin(cfg: object | Mapping[str, Any] | None) -> Any:
    return get_config_value(cfg, "openshell.admin", None)


def _admin_value(admin: Any, name: str, default: Any = None) -> Any:
    if admin is None:
        return default
    if isinstance(admin, Mapping):
        return admin.get(name, default)
    return getattr(admin, name, default)


def openshell_managed(cfg: object | Mapping[str, Any] | None) -> bool:
    """Whether config.yaml is administrator-owned (managed_enterprise)."""
    mode = str(get_config_value(cfg, "deployment_mode", "") or "").strip().lower()
    return mode in {"managed_enterprise", "managed"}


# openshell.admin.locked entries and the config keys they pin.
_OPENSHELL_LOCKED_CONFIG_KEYS: dict[str, tuple[str, ...]] = {
    "pack": ("openshell.pack", "openshell.pack_dir"),
    "profile": ("openshell.profile",),
    "yolo": ("openshell.yolo",),
    "workdir.mode": ("openshell.workdir.mode",),
    "workdir.unmask": ("openshell.workdir.unmask",),
    "mcp.import": ("openshell.mcp.import",),
    "mcp.host_ports": ("openshell.mcp.host_ports",),
    "resources": ("openshell.resources.cpu", "openshell.resources.memory"),
}


def openshell_admin_locks(cfg: object | Mapping[str, Any] | None) -> dict[str, str]:
    """The ``openshell.*`` keys an administrator constrains, with the reason.

    Mirrors the openshell.admin switches the Go resolver (internal/openshell/
    packs) enforces; the config editor shows these keys read-only. In
    managed_enterprise the whole file is administrator-owned, which
    :func:`_openshell_section` handles separately.
    """

    admin = _openshell_admin(cfg)
    locks: dict[str, str] = {}
    if admin is None:
        return locks

    def lock(keys: Sequence[str], reason: str) -> None:
        for key in keys:
            locks.setdefault(key, reason)

    required = str(_admin_value(admin, "required_pack", "") or "").strip()
    if required:
        lock(("openshell.pack", "openshell.pack_dir"), f"your organization requires the {required} pack")
    if _admin_value(admin, "allow_yolo") is False:
        lock(("openshell.yolo",), "skip-permissions mode is not allowed")
    if _admin_value(admin, "allow_mount") is False:
        lock(("openshell.workdir.mode",), "your organization requires copy mode")
    if _admin_value(admin, "allow_host_ports") is False:
        lock(("openshell.mcp.host_ports",), "opening host ports is not allowed")
    if _admin_value(admin, "allow_unblock") is False:
        reason = "unblocking and allow entries are not allowed"
        lock(("openshell.egress.allow", "openshell.egress.unblocked", "openshell.egress.feed"), reason)
    if _admin_value(admin, "block_large_uploads") is True:
        lock(("openshell.egress.block_large_uploads",), "your organization blocks large uploads to first-seen hosts")
    for entry in _admin_value(admin, "locked", ()) or ():
        keys = _OPENSHELL_LOCKED_CONFIG_KEYS.get(str(entry).strip())
        if keys:
            lock(keys, f"locked by your organization (openshell.admin.locked: {str(entry).strip()})")
    return locks


def _openshell_inherit_value(cfg: object | Mapping[str, Any] | None, key: str) -> str:
    raw = _openshell_raw(cfg, key)
    if raw is None or raw == "":
        return OPENSHELL_INHERIT
    if isinstance(raw, bool):
        return "true" if raw else "false"
    return str(raw)


def _openshell_raw(cfg: object | Mapping[str, Any] | None, key: str) -> Any:
    if key == "openshell.mcp.import":
        mcp = get_config_value(cfg, "openshell.mcp", None)
        if isinstance(mcp, Mapping):
            return mcp.get("import", mcp.get("import_"))
        return getattr(mcp, "import_", None) if mcp is not None else None
    return get_config_value(cfg, key, None)


def _openshell_admin_summary(cfg: object | Mapping[str, Any] | None) -> str:
    admin = _openshell_admin(cfg)
    if admin is None:
        return "none"
    parts: list[str] = []
    for name in ("required_pack", "required_pack_digest", "min_profile"):
        value = str(_admin_value(admin, name, "") or "").strip()
        if value:
            parts.append(f"{name}={value}")
    for name in ("allow_yolo", "allow_mount", "allow_host_ports", "allow_unblock", "allow_learn_mode"):
        value = _admin_value(admin, name)
        if isinstance(value, bool):
            parts.append(f"{name}={'true' if value else 'false'}")
    if _admin_value(admin, "block_large_uploads") is True:
        parts.append("block_large_uploads=true")
    for name in ("allowed_harnesses", "egress_block", "egress_allow_only", "require_copy_for", "locked"):
        values = [str(item) for item in (_admin_value(admin, name, ()) or ()) if str(item).strip()]
        if values:
            parts.append(f"{name}={','.join(values)}")
    resources = _admin_value(admin, "max_resources")
    for name in ("cpu", "memory"):
        value = str(_admin_value(resources, name, "") or "").strip()
        if value:
            parts.append(f"max_{name}={value}")
    return "; ".join(parts) or "none"


def _openshell_locked_value(cfg: object | Mapping[str, Any] | None, key: str, value: str) -> str:
    """A locked key's value as it takes effect: the admin switches clamp these three."""
    shown = value or "(unset)"
    admin = _openshell_admin(cfg)
    if key == "openshell.yolo" and _admin_value(admin, "allow_yolo") is False and value != "false":
        return f"{shown} → off by policy"
    if key == "openshell.workdir.mode" and _admin_value(admin, "allow_mount") is False and value != "copy":
        return f"{shown} → copy by policy"
    if key == "openshell.mcp.host_ports" and _admin_value(admin, "allow_host_ports") is False and value:
        return f"{shown} → none by policy"
    if (
        key == "openshell.egress.block_large_uploads"
        and _admin_value(admin, "block_large_uploads") is True
        and value != "true"
    ):
        return f"{shown} → on by policy"
    return f"{shown} (locked)"


def _openshell_section(cfg: object | Mapping[str, Any] | None) -> ConfigSection:
    """The ``openshell:`` keys (OpenShell 0.1 sandboxes).

    Keys the selected sandbox policy pack governs stay "inherit" unless set.
    Keys an administrator constrains (openshell.admin) are read-only with the
    reason; in managed_enterprise every key is (the file is administrator-owned).
    """

    managed = openshell_managed(cfg)
    locks = openshell_admin_locks(cfg)
    min_profile = str(_admin_value(_openshell_admin(cfg), "min_profile", "") or "").strip()
    profile_rank = {name: index for index, name in enumerate(dc_config.OPENSHELL_PROFILES)}
    profiles = tuple(
        name
        for name in dc_config.OPENSHELL_PROFILES
        if not min_profile or profile_rank.get(name, 0) >= profile_rank.get(min_profile, 0)
    )

    def field(label: str, key: str, kind: str = "string", options: Sequence[str] = (), hint: str = "") -> ConfigField:
        inherit = kind == "choice" and OPENSHELL_INHERIT in options
        value = _openshell_inherit_value(cfg, key) if inherit else _value(cfg, key)
        reason = "config.yaml is administrator-owned (managed_enterprise)" if managed else locks.get(key, "")
        if reason:
            # A short value that fits the column; the sentence is the row's
            # hint (the focused-field line, and the status on Enter).
            shown = _openshell_locked_value(cfg, key, value)
            return ConfigField(
                label=label,
                key=key,
                kind="header",
                value=shown,
                original=shown,
                hint=f"Read-only: {ADMIN_POLICY_MESSAGE}; {reason}.",
            )
        return ConfigField(
            label=label, key=key, kind=kind, value=value, original=value, options=tuple(options), hint=hint
        )

    inherit_bool = (OPENSHELL_INHERIT, "true", "false")
    fields: list[ConfigField] = [
        field("Enabled", "openshell.enabled", "bool", hint="Sandbox listeners and API on the daemon (sandbox setup turns it on)."),
        field("OpenShell Binary", "openshell.binary", hint="The upstream openshell CLI."),
        field("Gateway Name", "openshell.gateway.name", hint="OpenShell gateway registration; empty uses the active one."),
        field("Gateway Workspace", "openshell.gateway.workspace", hint="OpenShell workspace; empty is default."),
        field("Ingress Port", "openshell.ingress_port", "int", hint="Sandbox hook ingress; 0 is api_port+1."),
        field("Egress Port", "openshell.egress_port", "int", hint="DefenseClaw egress proxy; 0 is api_port+2."),
        field("Pack", "openshell.pack", hint="Policy pack: open, balanced, strict, a custom pack, or a path."),
        field("Pack Dir", "openshell.pack_dir", hint="Custom packs as <name>/pack.yaml."),
        field(
            "Profile",
            "openshell.profile",
            "choice",
            (OPENSHELL_INHERIT, *profiles),
            hint="Network profile; inherit takes the pack's."
            + (f" Your organization requires at least {min_profile}." if min_profile else ""),
        ),
        field("Skip-permissions (yolo)", "openshell.yolo", "choice", inherit_bool, hint="--dangerously-skip-permissions by default."),
        field(
            "Model Credential",
            "openshell.llm",
            "choice",
            dc_config.OPENSHELL_LLM_CHOICES,
            hint="What a run shares (sandbox run --llm; the wrappers, TUI and app too). auto: the first key found, Bedrock last.",
        ),
        field(
            "Keep Headless Sandboxes",
            "openshell.keep_headless",
            "bool",
            hint="Keep a --prompt run's sandbox (sandbox run --keep); off deletes it when nothing is left to bring back or undo.",
        ),
        field("Workdir Mode", "openshell.workdir.mode", "choice", (OPENSHELL_INHERIT, "mount", "copy"), hint="mount: live folder (Docker driver); copy: untrusted repos, and every run on a MicroVM (vm) gateway."),
        field("Secret Masks", "openshell.workdir.masks", hint="Extra secret-file globs, comma-separated."),
        field("Unmask", "openshell.workdir.unmask", hint="Masked paths to share, comma-separated."),
        field("Max Upload MB", "openshell.workdir.max_upload_mb", "int", hint="Copy-mode upload cap; 0 inherits."),
        field("Git Depth", "openshell.workdir.git_depth", "int", hint="Copy-mode history depth."),
        field("On Exit", "openshell.workdir.on_exit", "choice", ("ask", "keep", "undo"), hint="End-of-session default."),
        field(
            "Undo Restores Ignored Dirs",
            "openshell.workdir.undo_ignored.enabled",
            "bool",
            hint="Keep a copy of node_modules/.venv with each undo point so undo restores them (Linux mount mode).",
        ),
        field(
            "Undo Ignored Max MB",
            "openshell.workdir.undo_ignored.max_mb",
            "int",
            hint="Cap on one undo point's copies; a directory past it is only reported. 0 is 500.",
        ),
        field(
            "Undo Ignored Dirs",
            "openshell.workdir.undo_ignored.dirs",
            hint="Directory names kept at any depth, comma-separated; empty is node_modules, .venv, venv.",
        ),
        field("Egress Block", "openshell.egress.block", hint="Blocked hosts, comma-separated."),
        field("Egress Allow", "openshell.egress.allow", hint="Allowlist for balanced/strict, comma-separated."),
        field("Egress Unblocked", "openshell.egress.unblocked", hint="'Always' unblocks the daemon wrote, comma-separated."),
        field("Egress Ports", "openshell.egress.ports", hint="Proxy ports, comma-separated; empty inherits."),
        field("Large Upload MB", "openshell.egress.large_upload_mb", "int", hint="First-seen-host upload alert; 0 inherits."),
        field(
            "Block Large Uploads",
            "openshell.egress.block_large_uploads",
            "bool",
            hint="Also cut that upload and refuse the host until it is unblocked; off follows the pack.",
        ),
        field("Blocklist Feed", "openshell.egress.feed", "choice", (OPENSHELL_INHERIT, "builtin", "none"), hint="The pack's feeds unless set."),
        field("Base Image", "openshell.image.base", hint="Overlay base image; empty is the pinned NVIDIA base."),
        field("Approval Debounce ms", "openshell.approvals.debounce_ms", "int", hint="Batch approvals until hooks are quiet."),
        field("Agent Proposals", "openshell.approvals.agent_proposals", "choice", inherit_bool, hint="Let the agent propose rules (default on)."),
        field("CPU", "openshell.resources.cpu", hint="Per-sandbox CPU, for example 2 or 500m."),
        field("Memory", "openshell.resources.memory", hint="Per-sandbox memory, for example 4Gi."),
        field("Harnesses", "openshell.harnesses", hint="claudecode, codex (feeds the policy connectors)."),
        _header(
            "Shell Wrappers",
            "openshell.wrappers",
            (_value(cfg, "openshell.wrappers") or "none")
            + "  — change with: defenseclaw sandbox enable|disable <harness> (Sandboxes panel: w)",
        ),
        field("MCP Import", "openshell.mcp.import", "choice", inherit_bool, hint="Bring the harness's MCP servers along."),
        field("MCP Host Ports", "openshell.mcp.host_ports", hint="Localhost ports opened for host MCP servers, comma-separated."),
        field("Upstream Telemetry", "openshell.upstream_telemetry", "bool", hint="Keep OpenShell's anonymous usage telemetry."),
        field("Token Delivery", "openshell.token_delivery", "choice", ("provider", "env"), hint="How the sandbox token reaches hooks."),
        field("Middleware (experimental)", "openshell.middleware.enabled", "bool", hint="Supervisor middleware; Phase 3."),
        _header(
            "Organization Policy",
            "openshell.admin",
            _openshell_admin_summary(cfg)
            + ("  — administrator-owned (managed_enterprise)" if managed else "  — edit config.yaml directly"),
        ),
    ]
    legacy_mode = _value(cfg, "openshell.mode")
    if legacy_mode:
        fields.append(
            _header("Legacy Mode", "openshell.mode", f"{legacy_mode}  — run: defenseclaw sandbox legacy-cleanup --dry-run")
        )
    summary = "NVIDIA OpenShell sandboxes: the agent sees only the project folder; DefenseClaw judges every call."
    if managed:
        summary += " Administrator-owned (managed_enterprise): read-only."
    elif locks:
        summary += f" {len(locks)} key(s) are set by your organization's policy."
    return ConfigSection(
        "OpenShell Sandboxes",
        tuple(fields),
        summary,
        "Pack-governed keys show 'inherit' until set. Run 'defenseclaw sandbox policy explain' to see every "
        "resolved setting and where it comes from.",
    )


def _asset_policy_fields(cfg: object | Mapping[str, Any] | None) -> tuple[ConfigField, ...]:
    fields = [
        _field(cfg, "Enabled", "asset_policy.enabled", "bool", hint="Master asset admission switch."),
        _field(cfg, "Mode", "asset_policy.mode", "choice", ("observe", "action"), "observe=log; action=block."),
    ]
    for label, prefix, runtime in (
        ("Skill", "asset_policy.skill", False),
        ("MCP", "asset_policy.mcp", True),
        ("Plugin", "asset_policy.plugin", False),
    ):
        fields.extend(
            (
                _header(f".. {label} .."),
                _field(cfg, "Default", prefix + ".default", "choice", ("allow", "deny"), "Fallback action."),
                _field(
                    cfg,
                    "Registry Required",
                    prefix + ".registry_required",
                    "bool",
                    hint="Require approved registry entry.",
                ),
                _field(
                    cfg,
                    "Empty Registry Action",
                    prefix + ".registry_empty_action",
                    "choice",
                    ("deny", "allow"),
                    "Behavior when registry required but empty.",
                ),
            ),
        )
        if runtime:
            fields.extend(
                (
                    _field(
                        cfg,
                        "Runtime Detection",
                        prefix + ".runtime_detection.enabled",
                        "bool",
                        hint="Detect runtime MCP usage.",
                    ),
                    _field(
                        cfg,
                        "Terminal Commands",
                        prefix + ".runtime_detection.terminal_commands",
                        "bool",
                        hint="Inspect terminal command surfaces.",
                    ),
                    _field(
                        cfg,
                        "Unknown Terminal MCP",
                        prefix + ".runtime_detection.unknown_terminal_mcp",
                        "choice",
                        ("observe", "action"),
                        "Unknown MCP posture.",
                    ),
                ),
            )
    fields.extend(_per_connector_asset_policy_fields(cfg))
    return tuple(fields)


def _asset_policy_connector_keys(cfg: object | Mapping[str, Any] | None) -> list[str]:
    names = _active_connector_names_for_setup(cfg)
    overrides = get_config_value(cfg, "asset_policy.connectors", None)
    override_keys = (
        [str(key).strip().lower() for key in overrides if str(key).strip()] if isinstance(overrides, Mapping) else []
    )
    seen: set[str] = set()
    merged: list[str] = []
    for name in (*names, *override_keys):
        normalized = name.strip().lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            merged.append(normalized)
    return merged


def _effective_asset_policy_mode(cfg: object | Mapping[str, Any] | None, connector: str) -> str:
    asset_policy = get_config_value(cfg, "asset_policy", None)
    effective = getattr(asset_policy, "effective_mode", None)
    if callable(effective):
        try:
            return str(effective(connector) or "observe")
        except Exception:  # noqa: BLE001 - fall back to mapping-style lookup.
            pass
    override = str(get_config_value(cfg, f"asset_policy.connectors.{connector}.mode", "") or "").strip()
    return override or str(get_config_value(cfg, "asset_policy.mode", "observe") or "observe")


def _effective_asset_policy_value(
    cfg: object | Mapping[str, Any] | None,
    connector: str,
    asset_type: str,
    leaf: str,
) -> str:
    asset_policy = get_config_value(cfg, "asset_policy", None)
    effective = getattr(asset_policy, "effective_asset_type_policy", None)
    if callable(effective):
        try:
            policy = effective(connector, asset_type)
            value = getattr(policy, leaf, "") if policy is not None else ""
            if isinstance(value, bool):
                return "true" if value else "false"
            return str(value or "")
        except Exception:  # noqa: BLE001 - fall back to mapping-style lookup.
            pass
    if leaf == "registry_required":
        override = get_config_value(cfg, f"asset_policy.connectors.{connector}.{asset_type}.{leaf}", None)
        if isinstance(override, bool):
            return "true" if override else "false"
        base = bool(get_config_value(cfg, f"asset_policy.{asset_type}.{leaf}", False))
        return "true" if base else "false"
    override = str(get_config_value(cfg, f"asset_policy.connectors.{connector}.{asset_type}.{leaf}", "") or "")
    if override:
        return override
    default = "deny" if leaf == "registry_empty_action" else "allow"
    return str(get_config_value(cfg, f"asset_policy.{asset_type}.{leaf}", default) or default)


def _per_connector_asset_policy_fields(cfg: object | Mapping[str, Any] | None) -> list[ConfigField]:
    keys = _asset_policy_connector_keys(cfg)
    if not keys:
        return []
    overrides = get_config_value(cfg, "asset_policy.connectors", None)
    has_overrides = isinstance(overrides, Mapping) and len(overrides) > 0
    if len(keys) < 2 and not has_overrides:
        return []

    rows: list[ConfigField] = [_header(".. Per-Connector Overrides ..")]
    for connector in keys:
        label = friendly_connector_name(connector) or connector
        rows.append(_header(f".. {label} ({connector}) .."))
        rows.append(
            ConfigField(
                "Mode",
                f"asset_policy.connectors.{connector}.mode",
                "choice",
                _effective_asset_policy_mode(cfg, connector),
                _effective_asset_policy_mode(cfg, connector),
                ("", "observe", "action"),
                f"Per-connector asset-policy mode for {connector}; blank inherits the global mode.",
            )
        )
        for asset_type in ("skill", "mcp", "plugin"):
            asset_label = asset_type.upper() if asset_type == "mcp" else asset_type.title()
            rows.append(_header(f".. {label} {asset_label} .."))
            for field_label, leaf, options in (
                ("Default", "default", ("", "allow", "deny")),
                ("Registry Required", "registry_required", ("", "true", "false")),
                ("Empty Registry Action", "registry_empty_action", ("", "deny", "warn", "allow", "block")),
            ):
                value = _effective_asset_policy_value(cfg, connector, asset_type, leaf)
                rows.append(
                    ConfigField(
                        field_label,
                        f"asset_policy.connectors.{connector}.{asset_type}.{leaf}",
                        "choice",
                        value,
                        value,
                        options,
                        f"{asset_label} override for {connector}; blank inherits the global {asset_type} policy.",
                    )
                )
    return rows


def _hook_summary_row(label: str, key: str, connector: str) -> ConfigField:
    alias = _connector_setup_alias(connector)
    hint = f"Set by defenseclaw setup {alias}" if alias else UNMODELED_CONFIG_HINT
    return ConfigField(label=label, key=key, kind="header", value=READ_ONLY_VALUE, original=READ_ONLY_VALUE, hint=hint)


def _agent_hook_summary_fields() -> tuple[ConfigField, ...]:
    """Read-only summary of the legacy ``claude_code`` / ``codex`` hook blocks.

    The Python config doesn't model these blocks, so edits here could never
    be saved; the connector setup commands own them.
    """

    return (
        _hook_summary_row("Claude Code", "claude_code", "claudecode"),
        _hook_summary_row("Codex", "codex", "codex"),
    )


def _connector_hook_summary_fields(cfg: object | Mapping[str, Any] | None) -> tuple[ConfigField, ...]:
    """One read-only row per connector for the ``connector_hooks`` map."""

    names = list(CONNECTORS)
    hooks = get_config_value(cfg, "connector_hooks", {}) or {}
    if isinstance(hooks, Mapping):
        names.extend(str(name) for name in hooks if str(name).strip())
    return tuple(
        _hook_summary_row(_connector_hook_label(name), "connector_hooks." + name, name)
        for name in sorted(dict.fromkeys(names))
    )


def _v8_observability_fields(
    status: V8OperatorStatus | None,
    *,
    error: str = "",
) -> tuple[ConfigField, ...]:
    """Render the masked compiler-owned v8 plan as read-only config rows."""

    how_to = _header(
        "How to edit",
        "observability.hint",
        "press E to manage destinations; collection, routes, redaction, and retention live in config.yaml",
    )
    if status is None:
        return (
            _header("Status", "observability.status", error.strip() or "loading telemetry destinations\u2026"),
            how_to,
        )

    retention = "unbounded" if status.unbounded_retention else f"{status.retention_days} days"
    fields: list[ConfigField] = [
        _header("Plan Digest", "observability.plan_digest", status.plan_digest[:12]),
        _header("Bucket Catalog", "observability.bucket_catalog_version", str(status.bucket_catalog_version)),
        _header("Local SQLite", "observability.local.path", status.local_path or "(default)"),
        _header("Retention", "observability.local.retention_days", retention),
        _header(
            "Judge Bodies",
            "observability.local.judge_bodies_path",
            ("enabled · " if status.judge_bodies_enabled else "disabled · ")
            + (status.judge_bodies_path or "(default)"),
        ),
        _header(".. Destinations .."),
    ]
    if not status.destinations:
        fields.append(_header("Destinations", "observability.destinations", "none configured"))
    for destination in status.destinations:
        signals = ",".join(destination.selected_signals) or "none"
        buckets = ",".join(destination.buckets) or "none"
        state = "enabled" if destination.enabled else "disabled"
        summary = (
            f"{destination.kind} · {state} · signals={signals} · "
            f"redaction={destination.redaction_label} · buckets={buckets} · "
            f"limits={destination.delivery_limits_label}"
        )
        if destination.endpoint:
            summary += f" · {destination.endpoint}"
        fields.append(_header(destination.name, f"observability.destinations.{destination.name}", summary))
    fields.append(_header(".. Collection Buckets .."))
    for bucket in status.buckets:
        signals = ",".join(bucket.collected_signals) or "disabled"
        fields.append(
            _header(
                bucket.name,
                f"observability.buckets.{bucket.name}",
                f"collect={signals} · local_redaction={bucket.redaction_profile}",
            )
        )
    if status.warnings:
        fields.append(_header(".. Warnings .."))
        fields.extend(
            _header(code, f"observability.warnings.{index}", f"{path}: {summary}")
            for index, (code, path, summary) in enumerate(status.warnings)
        )
    fields.append(how_to)
    return tuple(fields)


def _llm_override_fields(
    cfg: object | Mapping[str, Any] | None,
    label: str,
    prefix: str,
) -> tuple[ConfigField, ...]:
    return (
        _header(f".. {label} LLM Override .."),
        _field(cfg, "Provider", prefix + ".provider", "choice", LLM_OVERRIDE_PROVIDERS, "Blank inherits Unified LLM."),
        _field(cfg, "Model", prefix + ".model", hint="Blank inherits Unified LLM model."),
        _field(cfg, "API Key Env", prefix + ".api_key_env", hint="Env var NAME for this component."),
        _field(cfg, "API Key (redacted)", prefix + ".api_key", "password", hint="Inline component key."),
        _field(cfg, "Base URL", prefix + ".base_url", hint="Optional local/proxy endpoint."),
        _field(cfg, "Timeout (s)", prefix + ".timeout", "int", hint="Per-request timeout."),
        _field(cfg, "Max Retries", prefix + ".max_retries", "int", hint="Retry count."),
    )


def _webhook_summary_fields(cfg: object | Mapping[str, Any] | None) -> tuple[ConfigField, ...]:
    hooks = get_config_value(cfg, "webhooks", ()) or ()
    hint_value = "press [E] for interactive editor, or run defenseclaw setup webhook ..."
    hint = ConfigField("How to edit", "webhooks.hint", "header", hint_value, hint_value)
    if not hooks:
        return (
            ConfigField("Status", "webhooks.summary", "header", "no webhooks configured", "no webhooks configured"),
            hint,
        )
    out = []
    for index, hook in enumerate(hooks):
        kind = str(_mapping_or_attr(hook, "type", "webhook") or "webhook")
        name = str(_mapping_or_attr(hook, "name", "") or f"{kind}[{index}]")
        url = str(_mapping_or_attr(hook, "url", ""))
        enabled = bool(_mapping_or_attr(hook, "enabled", False))
        # Escape the opening bracket so Rich renders ``[enabled] url``
        # as literal text. Without the backslash the parser interprets
        # ``enabled``/``disabled`` as a style name and the setup panel
        # crashes with ``MissingStyle: 'enabled' is not a valid color``
        # the moment any webhook is configured.
        summary = f"\\[{'enabled' if enabled else 'disabled'}] {url}"
        out.append(ConfigField(name, f"webhooks.{index}", "header", summary, summary))
    out.append(hint)
    return tuple(out)


def _trusted_paths_summary_fields(cfg: object | Mapping[str, Any] | None) -> tuple[ConfigField, ...]:
    """Read-only summary of the binary-discovery trusted-prefix allow-list.

    Mutations go through the CLI (``defenseclaw setup trusted-paths ...``) so
    the TUI, the inline setup prompt, and the discovery gate all share a single
    persistence path and can't drift. We reuse ``_collect_trusted_prefixes`` —
    the exact view the CLI renders — so the panel can never disagree with it.
    """
    from defenseclaw.commands.cmd_setup import _collect_trusted_prefixes  # noqa: PLC0415

    data_dir = ""
    for attr in ("data_dir", "config_dir", "home"):
        val = getattr(cfg, attr, "")
        if isinstance(val, str) and val:
            data_dir = val
            break
    if not data_dir:
        data_dir = os.environ.get("DEFENSECLAW_HOME") or os.path.expanduser("~/.defenseclaw")

    try:
        rows = _collect_trusted_prefixes(data_dir)
    except Exception:
        rows = []

    defaults = [r for r in rows if r.get("source") == "default"]
    operator = [r for r in rows if r.get("source") != "default"]
    present = sum(1 for r in defaults if r.get("status") == "ok")

    # NOTE: the *proactive* "which connectors are in an untrusted dir" highlight
    # lives in the interactive editor (TrustedPathsEditorScreen), opened from
    # this section. We deliberately do NOT run connector discovery here — this
    # builder feeds the static Setup panel that re-renders on every refresh, so
    # a subprocess discovery pass would be both slow and host-dependent.
    out: list[ConfigField] = [
        _header(
            "Built-in defaults",
            "trusted_paths.defaults",
            f"{len(defaults)} default prefixes, {present} present on this host",
        )
    ]
    if operator:
        for index, row in enumerate(operator):
            # Escape the opening bracket so Rich renders ``[src/status]`` as
            # literal text rather than parsing it as a style tag (which would
            # crash the panel — see the webhook summary note above).
            summary = f"\\[{row.get('source')}/{row.get('status')}] {row.get('resolved')}"
            out.append(_header(f"Operator path {index + 1}", f"trusted_paths.op.{index}", summary))
    else:
        out.append(
            _header(
                "Operator-added",
                "trusted_paths.operator",
                "none — all trust comes from built-in defaults",
            )
        )
    out.append(
        _header(
            "How to edit",
            "trusted_paths.hint",
            "defenseclaw setup trusted-paths add|remove <dir>",
        )
    )
    return tuple(out)


def _cisco_ai_defense_fields(cfg: object | Mapping[str, Any] | None) -> tuple[ConfigField, ...]:
    return (
        _field(cfg, "Endpoint", "cisco_ai_defense.endpoint", hint="Cisco AI Defense API endpoint."),
        _field(cfg, "API Key (redacted)", "cisco_ai_defense.api_key", "password", hint="Inline Cisco key."),
        _field(cfg, "API Key Env", "cisco_ai_defense.api_key_env", hint="Env var NAME holding Cisco key."),
        _field(cfg, "Timeout (ms)", "cisco_ai_defense.timeout_ms", "int", hint="HTTP timeout for probes."),
        _field(cfg, "Enabled Rules", "cisco_ai_defense.enabled_rules", hint="CSV cloud rules."),
    )


def _firewall_fields(cfg: object | Mapping[str, Any] | None) -> tuple[ConfigField, ...]:
    return (
        _header("Config File", "firewall.config_file", _value(cfg, "firewall.config_file")),
        _header("Rules File", "firewall.rules_file", _value(cfg, "firewall.rules_file")),
        _header("Anchor Name", "firewall.anchor_name", _value(cfg, "firewall.anchor_name")),
        _header("How to edit", "firewall.hint", "edit config.yaml directly - these paths bind to system-owned files"),
    )


def _field(
    cfg: object | Mapping[str, Any] | None,
    label: str,
    key: str,
    kind: str = "string",
    options: Sequence[str] = (),
    hint: str = "",
) -> ConfigField:
    value = _value(cfg, key)
    return ConfigField(label=label, key=key, kind=kind, value=value, original=value, options=tuple(options), hint=hint)


def _field_with_original(field: ConfigField, value: str) -> ConfigField:
    return ConfigField(
        label=field.label,
        key=field.key,
        kind=field.kind,
        value=value,
        original=value,
        options=field.options,
        hint=field.hint,
    )


def _header(label: str, key: str = "", value: str = "") -> ConfigField:
    return ConfigField(label=label, key=key, kind="header", value=str(value), original=str(value))


def _value(cfg: object | Mapping[str, Any] | None, key: str) -> str:
    raw = get_config_value(cfg, key, "")
    if isinstance(raw, bool):
        return "true" if raw else "false"
    if isinstance(raw, (list, tuple)):
        return ",".join(str(item) for item in raw)
    if isinstance(raw, dict):
        return ",".join(f"{key}={value}" for key, value in sorted(raw.items()))
    if raw is None:
        return ""
    return str(raw)


def _fmt_config_version(cfg: object | Mapping[str, Any] | None) -> str:
    version = get_config_value(cfg, "config_version", "")
    if not version:
        # ``Config`` keeps the on-disk version in ``_source_config_version``
        # (there is no ``config_version`` attribute), so a v8 file showed
        # "(unset)" (GAP-1161).
        version = getattr(cfg, "_source_config_version", 0) or ""
    if not version:
        return "(unset)"
    return str(version)


def _connector_setup_alias(wire: str) -> str:
    normalized = wire.strip().lower().replace("_", "-")
    if normalized in {"claudecode", "claude-code"}:
        return "claude-code"
    if normalized in {
        "openclaw",
        "zeptoclaw",
        "codex",
        "hermes",
        "cursor",
        "devin",
        "copilot",
        "openhands",
        "antigravity",
        "opencode",
        "amp",
        "omnigent",
        "kiro",
    }:
        return normalized
    return ""


def _connector_hook_label(name: str) -> str:
    return friendly_connector_name(name) if name else "Connector"


def _bifrost_providers() -> tuple[str, ...]:
    return (
        "openai",
        "azure",
        "anthropic",
        "bedrock",
        "cohere",
        "vertex",
        "mistral",
        "ollama",
        "groq",
        "sgl",
        "parasail",
        "perplexity",
        "cerebras",
        "gemini",
        "openrouter",
        "elevenlabs",
        "huggingface",
        "nebius",
        "xai",
        "replicate",
        "vllm",
        "runway",
        "fireworks",
    )


def _mapping_or_attr(obj: object, name: str, default: Any = "") -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _default_wizard_field_hint(label: str, kind: str, flag: str = "") -> str:
    lowered = label.lower()
    if kind == "bool":
        if lowered.startswith("restart gateway"):
            return _RESTART_GATEWAY_HINT
        if lowered == "verify after setup":
            return "Run the connectivity checks once the settings are saved."
        return f"Toggle {lowered}."
    if kind in {"choice", "preset", "whtype", "regid"}:
        return f"Select {lowered}."
    if kind == "password":
        return f"Secret value for {lowered}; prefer env-backed storage when available."
    if flag:
        return f"Sets {flag}."
    return f"Value for {lowered}."


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(value, high))
