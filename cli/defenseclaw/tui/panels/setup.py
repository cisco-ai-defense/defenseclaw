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

import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Literal

from defenseclaw import config as dc_config
from defenseclaw.notification_capabilities import desktop_notification_capability
from defenseclaw.platform_support import (
    LOCAL_SHELL_STACKS_UNSUPPORTED_REASON,
    local_shell_stacks_supported,
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
    WIZARD_LLM_PROVIDERS as _CHOICE_WIZARD_LLM_PROVIDERS,
)
from defenseclaw.tui.services.setup_state import (
    ConfigDiffEntry,
    ConfigField,
    ConfigSection,
    CredentialRow,
    CredentialSnapshot,
    RestartQueue,
    SetupCommandIntent,
    ValidationResult,
    apply_config_field,
    build_readiness_checks,
    config_diff,
    get_config_value,
    looks_like_secret_value,
    mask_secret,
    split_csv,
    validate_config_field,
    validation_errors,
)

SetupMode = Literal["wizards", "config"]
WizardFieldKind = Literal["bool", "string", "choice", "int", "password", "section", "preset", "whtype", "regid"]
UninstallOption = Literal["dry-run", "keep-data", "wipe-data"]

# These re-exports keep existing callers (panels, tests) importing from
# ``defenseclaw.tui.panels.setup`` working unchanged while routing the
# canonical definition through ``cli_choices``. Drop the re-exports
# only after every importer is migrated to ``cli_choices`` directly.
CONNECTORS = _CHOICE_CONNECTORS
GUARDRAIL_CONNECTORS = _CHOICE_GUARDRAIL_CONNECTORS
_WIZARD_LLM_PROVIDERS = _CHOICE_WIZARD_LLM_PROVIDERS
LLM_PROVIDERS = _CHOICE_LLM_PROVIDERS
LLM_OVERRIDE_PROVIDERS = _CHOICE_LLM_OVERRIDE_PROVIDERS


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
}

NOTIFICATION_ROUTING_SLOTS: tuple[tuple[str, str, str], ...] = (
    # (slot id, label, default state)
    ("block_enforced", "Block (enforced)", "yes"),
    ("block_would_block", "Block (would-block / observe)", "no"),
    ("hitl_approval", "HITL Approval", "yes"),
    ("sources.hook", "Source: Hooks", "yes"),
    ("sources.guardrail", "Source: Guardrail", "yes"),
    ("sources.asset_policy", "Source: Asset Policy", "yes"),
)

WIZARD_DESCRIPTIONS: tuple[str, ...] = (
    "Run first-class setup for any connector.",
    "List, check, fill, or set env-backed credentials.",
    "Configure the unified LLM block non-interactively.",
    "Inspect and manage the bundled local observability stack.",
    "Rotate the gateway token and refresh connector hooks.",
    "Manage the custom provider overlay.",
    "Configure skill scanner analyzers and policy.",
    "Configure MCP scanner analyzers and scan targets.",
    "Configure gateway host, ports, TLS, and auth.",
    "Configure the LLM guardrail proxy and judge.",
    "Configure Splunk HEC or local Splunk integration.",
    "Add and manage Galileo, unified OTel, and audit sink destinations.",
    "Add chat or incident notifier webhooks.",
    "Initialize and configure OpenShell sandbox policy.",
    "Register an external skill or MCP catalog source.",
    "Toggle notification categories and event sources.",
    "Enable or tune the sidecar AI Discovery service.",
    "Apply or destroy Splunk O11y dashboards.",
    "Manage trusted connector-binary discovery prefixes.",
    "Run connector-scoped guardrail status and policy quick actions.",
)

WIZARD_HOW_TO: tuple[str, ...] = (
    "Runs: defenseclaw setup <connector> --yes. Need connector, restart preference, guardrail mode, and scanner mode.",
    "Runs: defenseclaw keys list --json / check / set / fill-missing. Need env var name and secret only for set.",
    "Runs: defenseclaw setup llm --non-interactive. Need provider, model, optional base URL, and API key env or value.",
    "Runs: defenseclaw setup local-observability <action>. "
    "Need Docker for up/reset; status/url require no credentials.",
    "Runs: defenseclaw setup rotate-token --yes. Need connector override only when auto-detect is not enough.",
    "Runs: defenseclaw setup provider add|remove|list|show. Need provider name and domains for add/remove.",
    "Runs: defenseclaw setup skill-scanner. Need optional LLM, VirusTotal, or Cisco AI Defense credentials.",
    "Runs: defenseclaw setup mcp-scanner. Need analyzer list and prompt/resource/instruction scan choices.",
    "Runs: defenseclaw setup gateway. Need host, ports, TLS posture, and optional token source.",
    "Runs: defenseclaw setup guardrail. Need mode, scanner mode, optional judge model, and remote scanner credentials.",
    "Runs: defenseclaw setup splunk. Need HEC endpoint/token or local Docker and license acceptance.",
    "Runs: defenseclaw setup observability add <preset>. Choose Galileo or another vendor, then provide "
    "endpoint/project, credentials, and signals.",
    "Runs: defenseclaw setup webhook add <type>. Need webhook URL, secret env where required, and event filters.",
    "Runs: defenseclaw sandbox setup. Need OpenShell policy choices and optional sandbox home/network settings.",
    "Runs: defenseclaw registry add <id> --non-interactive. Need source id, kind, content type, and manifest URL.",
    "Runs one defenseclaw setup notifications-set <slot> on|off per changed toggle. No credentials required.",
    "Runs: defenseclaw agent discovery enable --yes (or disable). Mirrors cadence, scope, and privacy toggles.",
    "Runs: defenseclaw setup splunk dashboards apply|destroy --yes. Requires the Splunk O11y realm + API token.",
    "Runs: defenseclaw setup trusted-paths list|add|remove. Need a directory for add/remove.",
    "Runs: defenseclaw guardrail status|enable|disable|fail-mode|hilt|block-message with optional --connector.",
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
    visible_when: Callable[[Mapping[str, str]], bool] | None = dataclass_field(
        default=None, compare=False, repr=False
    )
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
        self.sections = build_setup_sections(cfg)
        self.wizard_status: dict[SetupWizard, str] = {}
        self._wizard_run_started: dict[SetupWizard, datetime] = {}
        self.form_fields: list[WizardFormField] = []
        self.form_cursor = 0
        self.form_active = False
        self.form_reveal = False
        self.form_error = ""
        # Goal-first entry layer: a contextual "what do you want to do?" menu
        # that sits in front of the wizard form. ``active_goal`` is carried
        # into the form so its preset filter survives dependent rebuilds.
        self.goal_active = False
        self.goal_cursor = 0
        self.goals: tuple[WizardGoal, ...] = ()
        self.active_goal: WizardGoal | None = None

    def set_config(self, cfg: object | Mapping[str, Any] | None) -> None:
        active_name = self.sections[self.active_section].name if self.sections else ""
        self.config = cfg
        self.sections = build_setup_sections(cfg)
        if active_name:
            for index, section in enumerate(self.sections):
                if section.name == active_name:
                    self.active_section = index
                    break
        self.active_section = _clamp(self.active_section, 0, max(0, len(self.sections) - 1))
        self.active_line = self.first_editable_line()
        self.config_scroll = 0
        # Readiness rows depend on cfg.gateway / cfg.guardrail / cfg.audit /
        # cfg.observability, so rebuild them whenever the cached config
        # changes; otherwise we keep showing rows derived from the
        # snapshot captured at __init__ time even after `setup` runs.
        self.rebuild_readiness_checks()

    def rebuild_readiness_checks(
        self,
        *,
        health: Any = None,
        doctor: Any = None,
        credentials: tuple[Any, ...] | None = None,
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
        self.readiness_checks = build_readiness_checks(
            self.config,
            health,
            doctor,
            rows,
            self.restart_queue,
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
                    if wizard == SetupWizard.LOCAL_OBSERVABILITY
                    and not local_shell_stacks_supported(self.os_name)
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

    def _formatted_wizard_status(
        self, wizard: SetupWizard, *, now: datetime | None = None
    ) -> str:
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
                "unsupported"
                if wizard == SetupWizard.LOCAL_OBSERVABILITY
                and not local_shell_stacks_supported(self.os_name)
                else self._formatted_wizard_status(wizard, now=now)
            ),
        )

    def wizard_available(self, wizard: SetupWizard | int) -> bool:
        return not (
            SetupWizard(wizard) == SetupWizard.LOCAL_OBSERVABILITY
            and not local_shell_stacks_supported(self.os_name)
        )

    def wizard_unavailable_reason(self, wizard: SetupWizard | int) -> str:
        return "" if self.wizard_available(wizard) else LOCAL_SHELL_STACKS_UNSUPPORTED_REASON

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
            self.open_wizard_form(SetupWizard.CREDENTIALS)
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

    def has_changes(self) -> bool:
        return bool(self.config_diff())

    def review_save_action(self) -> SetupPanelAction:
        errors = self.validation_errors()
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
        changes = len(self.config_diff())
        field = self.current_field()
        save_hint = "No config changes to save."
        if errors:
            save_hint = "Fix config validation before saving: " + errors[0]
        elif changes:
            save_hint = "Review and save applies changed fields, then queues a gateway restart when needed."
        restart_hint = ""
        actions = ["[`] Wizards", "[Arrows] Navigate", "[Enter/Click] Edit/Toggle"]
        if changes:
            actions.extend(("[S] Review & Save", "[R] Revert"))
        if self.restart_queue.pending:
            restart_hint = "Restart pending: " + self.restart_queue.reason + "  [G] restart now  [C] clear"
            actions.extend(("[G] Restart Now", "[C] Clear Restart"))
        elif field is not None and field.interactive:
            restart_hint = "Restart: queued on save when runtime settings change"
        saved_hint = ""
        if self.last_saved_at is not None:
            saved_hint = "Saved at " + self.last_saved_at.astimezone(timezone.utc).isoformat()
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
            return SetupFocusedRowAction("form", "edit", "Type", "Edit this setup value.")
        if self.mode == "config":
            field = self.current_field()
            section = self.current_section()
            if field is None:
                return SetupFocusedRowAction("config", "none", "", "No config row is focused.")
            if section is not None and section.name == "Audit Sinks":
                return SetupFocusedRowAction(
                    "config",
                    "open_audit_sinks_editor",
                    "E",
                    "Open the interactive Audit Sinks editor for list entries.",
                )
            if section is not None and section.name == "Webhooks":
                return SetupFocusedRowAction(
                    "config",
                    "open_webhooks_editor",
                    "E",
                    "Open the interactive Webhooks editor for list entries.",
                )
            if not field.interactive:
                return SetupFocusedRowAction("config", "read_only", "", "This config row is read-only.")
            if field.kind == "bool":
                return SetupFocusedRowAction("config", "toggle", "Enter/Space", "Toggle true or false.")
            if field.kind == "choice":
                return SetupFocusedRowAction("config", "cycle", "Enter/Space", "Cycle through allowed choices.")
            return SetupFocusedRowAction("config", "edit", "Type", "Edit this config value.")
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
        self.sections = tuple(
            ConfigSection(
                section.name,
                tuple(_field_with_original(field, field.value) for field in section.fields),
                section.summary,
                section.help,
            )
            for section in self.sections
        )

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
            self.form_error = LOCAL_SHELL_STACKS_UNSUPPORTED_REASON
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

    def open_wizard_form(
        self,
        wizard: SetupWizard | int | None = None,
        *,
        goal: WizardGoal | None = None,
    ) -> None:
        if wizard is not None:
            self.active_wizard = SetupWizard(wizard)
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
        if self.active_goal is not None:
            base = list(_filter_fields_for_goal(base, self.active_goal))
        self.form_fields = base
        self.form_active = True
        self.goal_active = False
        self.form_reveal = False
        self.form_error = ""
        self._place_form_cursor()

    def _place_form_cursor(self) -> None:
        """Put the form cursor on the first editable (non-section) row."""

        self.form_cursor = 0
        for offset, field in enumerate(self.form_fields):
            if field.kind != "section":
                self.form_cursor = offset
                return

    def close_wizard_form(self) -> None:
        self.form_fields = []
        self.form_cursor = 0
        self.form_active = False
        self.form_reveal = False
        self.form_error = ""
        self.goal_active = False
        self.goal_cursor = 0
        self.goals = ()
        self.active_goal = None

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
        if self.active_wizard in {SetupWizard.CONNECTOR_SETUP, SetupWizard.GUARDRAIL}:
            connector_field = next(
                (
                    field
                    for field in self.form_fields
                    if field.flag == "--connector" or field.label == "Connector"
                ),
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
        fields = list(rebuild(overrides, self.config))
        if self.active_goal is not None:
            fields = list(_filter_fields_for_goal(fields, self.active_goal))
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

    def toggle_form_reveal(self) -> bool:
        if not any(field.kind == "password" for field in self.form_fields):
            return False
        self.form_reveal = not self.form_reveal
        return True

    def missing_required_fields(self) -> tuple[str, ...]:
        return missing_required_fields(self.active_wizard, self.form_fields)

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
        masked = mask_wizard_secret_values(self.form_fields, args)
        return "defenseclaw " + " ".join(masked) if masked else "defenseclaw"

    def mark_wizard_complete(self, args: Sequence[str], *, success: bool = True) -> None:
        """Clear the per-wizard "running..." badge after a setup run.

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
        if best is None:
            return
        self.wizard_status[best] = "done" if success else "failed"
        self._wizard_run_started.pop(best, None)

    def submit_wizard_form(self) -> SetupPanelAction:
        missing = self.missing_required_fields()
        if missing:
            self.form_error = "Missing required field(s): " + ", ".join(missing)
            return SetupPanelAction(True)
        if self.active_wizard == SetupWizard.CREDENTIALS and wizard_field_value(self.form_fields, "Action") == "set":
            env_name = wizard_field_value(self.form_fields, "Env Name")
            if looks_like_secret_value(env_name):
                self.form_error = "Env Name looks like a secret value. Use an env var name such as DEFENSECLAW_LLM_KEY."
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
        name = WIZARD_NAMES[int(self.active_wizard)]
        if self.active_wizard == SetupWizard.GUARDRAIL:
            connector = wizard_field_value(self.form_fields, "Connector")
            if connector:
                name += f" ({connector})"
        # Credentials "set" feeds the secret over stdin (hidden prompt) so
        # it never lands in the child's argv. See F-0801.
        secret_stdin: str | None = None
        if (
            self.active_wizard == SetupWizard.CREDENTIALS
            and wizard_field_value(self.form_fields, "Action") == "set"
        ):
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
        self.wizard_status[self.active_wizard] = "running..."
        self._wizard_run_started[self.active_wizard] = datetime.now(timezone.utc)
        self.close_wizard_form()
        return SetupPanelAction(
            True,
            SetupCommandIntent(
                label="setup " + name,
                args=args,
                binary="defenseclaw",
                category="setup",
                origin="setup-wizard",
                follow_up=follow_up,
                secret_stdin=secret_stdin,
            ),
        )


def build_setup_sections(
    cfg: object | Mapping[str, Any] | None, os_name: str | None = None
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
                _header(".. Unified LLM (shared by scanners + guardrail) .."),
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
            "Privacy",
            (
                _field(
                    cfg,
                    "Disable Redaction",
                    "privacy.disable_redaction",
                    "bool",
                    hint="true stores raw content in all sinks.",
                ),
            ),
            "Redaction and privacy controls for audit DB, OTel, Splunk, webhooks, and terminal logs.",
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
                    "Active agent framework.",
                ),
                _field(cfg, "Home Dir", "claw.home_dir", hint="Override for connector home directory."),
                _field(cfg, "Config File", "claw.config_file", hint="Connector primary config file."),
            ),
            "Which agent framework DefenseClaw defends.",
        ),
        ConfigSection(
            "Agent Hooks",
            (*_agent_hook_fields(cfg, "Claude Code", "claude_code"), *_agent_hook_fields(cfg, "Codex", "codex")),
            "Dedicated agent hook policy: when scans run, fail behavior, and watched paths.",
        ),
        ConfigSection(
            "Connector Hooks",
            tuple(_connector_hook_map_fields(cfg)),
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
        ConfigSection("Audit Sinks", tuple(_audit_sink_summary_fields(cfg)), "Read-only audit sink summary."),
        ConfigSection("Webhooks", tuple(_webhook_summary_fields(cfg)), "Read-only notifier webhook summary."),
        ConfigSection("OTel", tuple(_otel_fields(cfg)), "OpenTelemetry exporter config."),
        ConfigSection(
            "Skill Actions", tuple(action_matrix_fields("skill_actions", cfg)), "Skill admission response matrix."
        ),
        ConfigSection("MCP Actions", tuple(action_matrix_fields("mcp_actions", cfg)), "MCP admission response matrix."),
        ConfigSection(
            "Plugin Actions", tuple(action_matrix_fields("plugin_actions", cfg)), "Plugin admission response matrix."
        ),
        _watch_section(cfg),
        _openshell_section(cfg),
        ConfigSection(
            "Inspect LLM (legacy - read-only)",
            (
                _header("Provider", value=_value(cfg, "inspect_llm.provider")),
                _header("Model", value=_value(cfg, "inspect_llm.model")),
                _header("API Key Env", value=_value(cfg, "inspect_llm.api_key_env")),
                _header("Base URL", value=_value(cfg, "inspect_llm.base_url")),
                _header("Timeout (s)", value=_value(cfg, "inspect_llm.timeout")),
                _header("Max Retries", value=_value(cfg, "inspect_llm.max_retries")),
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
    return tuple(sections)


def action_matrix_fields(prefix: str, cfg: object | Mapping[str, Any] | None) -> tuple[ConfigField, ...]:
    if prefix not in {"skill_actions", "mcp_actions", "plugin_actions"}:
        return (ConfigField("(unknown actions prefix)", prefix + ".error", "header"),)
    out = [
        ConfigField(
            label=".. " + prefix.replace("_", " ").upper() + " (severity -> file / runtime / install) ..",
            key=prefix + ".hint",
            kind="header",
            value="file: quarantine/none; runtime: enable/disable; install: none/block/allow",
            original="file: quarantine/none; runtime: enable/disable; install: none/block/allow",
        ),
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        label = severity[:1].upper() + severity[1:]
        out.extend(
            (
                _field(
                    cfg,
                    f"{label} - file",
                    f"{prefix}.{severity}.file",
                    "choice",
                    ("none", "quarantine"),
                    f"On {severity.upper()}: quarantine moves the artifact; none leaves it in place.",
                ),
                _field(
                    cfg,
                    f"{label} - runtime",
                    f"{prefix}.{severity}.runtime",
                    "choice",
                    ("enable", "disable"),
                    f"On {severity.upper()}: disable stops runtime invocation; enable keeps it live.",
                ),
                _field(
                    cfg,
                    f"{label} - install",
                    f"{prefix}.{severity}.install",
                    "choice",
                    ("none", "block", "allow"),
                    f"On {severity.upper()}: block rejects installs; allow permits; none defers.",
                ),
            ),
        )
    return tuple(out)


def connector_setup_command(wire: str) -> tuple[tuple[str, ...], str]:
    alias = _connector_setup_alias(wire)
    if not alias:
        return (), ""
    return ("setup", alias, "--yes"), "setup " + alias


def is_guardrail_supporting(connector: str) -> bool:
    return connector.strip().lower() in GUARDRAIL_CONNECTORS


def _credentials_wizard_fields() -> tuple[WizardFormField, ...]:
    return (
        WizardFormField(
            "Action",
            "choice",
            value="list",
            default="list",
            options=("list", "check", "fill-missing", "set"),
            hint="list uses keys list --json; set writes to env-backed storage.",
        ),
        WizardFormField("Env Name", "string", hint="Credential environment variable name."),
        WizardFormField("Secret Value", "password", hint="Only used by Action=set."),
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
        WizardFormField("Audit Sink", "bool", value="yes", default="yes"),
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


def _guardrail_actions_wizard_fields() -> tuple[WizardFormField, ...]:
    return (
        WizardFormField(
            "Connector",
            "choice",
            "--connector",
            value="",
            default="",
            options=("", *CONNECTORS),
            hint="Optional: scope this guardrail action to one connector; blank keeps CLI global/all-active behavior.",
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
        WizardFormField(
            "Domains", "string", hint="LLM allow-list domains, comma-separated.", visible_when=is_add
        ),
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
        WizardFormField(
            "Auth Mode", "choice", "--vertex-auth-mode", options=VERTEX_AUTH_MODES, visible_when=is_vertex
        ),
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
        return (
            WizardFormField("Behavioral Analyzer", "bool", "--use-behavioral", value="no", default="no"),
            WizardFormField("LLM Analyzer", "bool", "--use-llm", value="no", default="no"),
            WizardFormField(
                "LLM Provider",
                "choice",
                "--llm-provider",
                value="anthropic",
                default="anthropic",
                options=_WIZARD_LLM_PROVIDERS,
            ),
            WizardFormField("LLM Model", "string", "--llm-model"),
            WizardFormField("LLM Consensus Runs", "int", "--llm-consensus-runs", value="0", default="0"),
            WizardFormField("Meta Analyzer", "bool", "--enable-meta", value="no", default="no"),
            WizardFormField("Trigger Analyzer", "bool", "--use-trigger", value="no", default="no"),
            WizardFormField("VirusTotal Scanner", "bool", "--use-virustotal", value="no", default="no"),
            WizardFormField("AI Defense Analyzer", "bool", "--use-aidefense", value="no", default="no"),
            WizardFormField(
                "Scan Policy",
                "choice",
                "--policy",
                value="balanced",
                default="balanced",
                options=("strict", "balanced", "permissive", "none"),
            ),
            WizardFormField("Lenient Mode", "bool", "--lenient", value="no", default="no"),
            WizardFormField("Verify After Setup", "bool", "--verify", "--no-verify", value="yes", default="yes"),
        )
    if wizard == SetupWizard.MCP_SCANNER:
        return (
            WizardFormField(
                "Analyzers",
                "string",
                "--analyzers",
                value="yara,api,llm,behavioral,readiness",
                default="yara,api,llm,behavioral,readiness",
            ),
            WizardFormField(
                "LLM Provider",
                "choice",
                "--llm-provider",
                value="anthropic",
                default="anthropic",
                options=_WIZARD_LLM_PROVIDERS,
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
            WizardFormField("Scan Prompts", "bool", "--scan-prompts", value="no", default="no"),
            WizardFormField("Scan Resources", "bool", "--scan-resources", value="no", default="no"),
            WizardFormField("Scan Instructions", "bool", "--scan-instructions", value="no", default="no"),
            WizardFormField("Verify After Setup", "bool", "--verify", "--no-verify", value="yes", default="yes"),
        )
    if wizard == SetupWizard.GATEWAY:
        return (
            WizardFormField("Remote Mode", "bool", "--remote", value="no", default="no"),
            WizardFormField("Host", "string", "--host", value="localhost", default="localhost"),
            WizardFormField("Port", "int", "--port", value="9090", default="9090"),
            WizardFormField("API Port", "int", "--api-port", value="9099", default="9099"),
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
        return observability_wizard_fields("splunk-o11y")
    if wizard == SetupWizard.WEBHOOKS:
        return webhook_wizard_fields("slack")
    if wizard == SetupWizard.SANDBOX:
        return (
            WizardFormField("Sandbox IP", "string", "--sandbox-ip", value="10.200.0.2", default="10.200.0.2"),
            WizardFormField("Host IP", "string", "--host-ip", value="10.200.0.1", default="10.200.0.1"),
            WizardFormField("Sandbox Home", "string", "--sandbox-home", value="/home/sandbox", default="/home/sandbox"),
            WizardFormField("OpenClaw Port", "int", "--openclaw-port", value="18789", default="18789"),
            WizardFormField(
                "Policy",
                "choice",
                "--policy",
                value="permissive",
                default="permissive",
                options=("default", "strict", "permissive"),
            ),
            WizardFormField("DNS", "string", "--dns", value="8.8.8.8,1.1.1.1", default="8.8.8.8,1.1.1.1"),
            WizardFormField("No Auto Pair", "bool", "--no-auto-pair", value="no", default="no"),
            WizardFormField("No Host Networking", "bool", "--no-host-networking", value="no", default="no"),
            WizardFormField("No Guardrail", "bool", "--no-guardrail", value="no", default="no"),
            WizardFormField("Disable", "bool", "--disable", value="no", default="no"),
        )
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
    SetupWizard.OBSERVABILITY: lambda cfg=None: observability_wizard_fields("splunk-o11y"),
    SetupWizard.WEBHOOKS: lambda cfg=None: webhook_wizard_fields("slack"),
    SetupWizard.REGISTRIES: lambda cfg=None: registry_wizard_fields(),
    SetupWizard.NOTIFICATIONS_ROUTING: lambda cfg=None: notifications_routing_wizard_fields(cfg),
    SetupWizard.AI_DISCOVERY: lambda cfg=None: ai_discovery_wizard_fields(cfg),
    SetupWizard.SPLUNK_DASHBOARDS: lambda cfg=None: splunk_dashboards_wizard_fields(),
    SetupWizard.TRUSTED_PATHS: lambda cfg=None: _trusted_paths_wizard_fields(),
    SetupWizard.GUARDRAIL_ACTIONS: lambda cfg=None: _guardrail_actions_wizard_fields(),
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
    SetupWizard.CUSTOM_PROVIDERS: lambda overrides, cfg: _custom_providers_fields_for(overrides),
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
            summary="Choose the judge provider, model, and detection strategy.",
            presets={"--detection-strategy": "regex_judge"},
            fields=(
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
            summary="Point the guardrail at a Cisco AI Defense endpoint.",
            fields=("--cisco-endpoint", "--cisco-api-key-env", "--cisco-timeout-ms"),
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
            "Tune detection strategy / rule pack",
            summary="Adjust the regex/judge strategy and rule pack.",
            fields=("--detection-strategy", "--rule-pack"),
        ),
    )


def _connector_setup_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "add",
            "Add or configure a connector",
            summary="Add a connector peer, or replace the configured set when requested.",
            presets={"@Action": "setup"},
            fields=("Connector", "Action", "Replace Existing", "Restart Gateway"),
        ),
        WizardGoal(
            "proxy-stack",
            "Set up a proxy connector with the local stack",
            summary="Bring up the local guardrail/scanner stack for a proxy.",
            presets={"@Action": "setup", "@Local Stack": "yes"},
            fields=("Connector", "Guardrail Mode", "Scanner Mode", "Local Stack"),
        ),
        WizardGoal(
            "bulk",
            "Set active connectors",
            summary="Run bare setup to choose the active hook connector set.",
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
            summary="Re-apply guardrail/scanner settings and verify one connector.",
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
            "Set a credential value",
            summary="Write a single env-backed credential.",
            presets={"@Action": "set"},
            fields=("Action", "Env Name", "Secret Value"),
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
            fields=("Action", "Timeout", "Signals", "Audit Sink", "No Wait"),
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
            "Rotate shared token for active connectors",
            summary="Rotate the gateway token and refresh every active connector hook.",
            fields=("Refresh Hooks",),
        ),
        WizardGoal(
            "specific",
            "Rotate shared token with connector hint",
            summary="Token storage is shared; connector only narrows the hook refresh path.",
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
            summary="Set the gateway host, proxy port, and API port.",
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
            available_when=lambda _cfg: local_shell_stacks_supported(),
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
            summary="List global destinations or one connector's per-connector sinks.",
            presets={"@Action": "list"},
            fields=("Action", "Connector", "JSON Output"),
        ),
        WizardGoal(
            "enable",
            "Enable a destination",
            summary="Enable a global or per-connector audit sink by name.",
            presets={"@Action": "enable"},
            fields=("Action", "Name", "Connector"),
        ),
        WizardGoal(
            "disable",
            "Disable a destination",
            summary="Disable a global or per-connector audit sink by name.",
            presets={"@Action": "disable"},
            fields=("Action", "Name", "Connector"),
        ),
        WizardGoal(
            "remove",
            "Remove a destination",
            summary="Remove a global or per-connector audit sink by name.",
            presets={"@Action": "remove"},
            fields=("Action", "Name", "Connector"),
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


def _sandbox_goals(cfg: object | Mapping[str, Any] | None) -> tuple[WizardGoal, ...]:
    del cfg
    return (
        WizardGoal(
            "init",
            "Initialize the sandbox (defaults)",
            summary="Set up the OpenShell sandbox with a policy.",
            fields=("Policy",),
        ),
        WizardGoal(
            "network",
            "Set the sandbox network (IPs / DNS)",
            summary="Configure sandbox/host IPs and DNS.",
            fields=("Sandbox IP", "Host IP", "DNS", "No Host Networking"),
        ),
        WizardGoal(
            "policy",
            "Change the sandbox policy",
            summary="Switch the sandbox enforcement policy.",
            fields=("Policy",),
        ),
        WizardGoal(
            "disable",
            "Disable the sandbox",
            summary="Turn the sandbox off.",
            presets={"--disable": "yes"},
            fields=("Disable",),
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
            summary="Toggle block/observe/HITL verdict notifications.",
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
            summary="Toggle hook/guardrail/asset-policy sources.",
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
            fields=("Connector", "Action"),
        ),
        WizardGoal(
            "enable",
            "Enable guardrail",
            summary="Enable globally or re-enable one connector override.",
            presets={"@Action": "enable"},
            fields=("Connector", "Action", "Restart Gateway"),
        ),
        WizardGoal(
            "disable",
            "Disable guardrail",
            summary="Disable globally or disable one connector override.",
            presets={"@Action": "disable"},
            fields=("Connector", "Action", "Restart Gateway"),
        ),
        WizardGoal(
            "fail-mode",
            "Set fail mode",
            summary="Set fail-open/fail-closed globally or for one connector.",
            presets={"@Action": "fail-mode"},
            fields=("Connector", "Action", "Fail Mode", "Restart Gateway"),
        ),
        WizardGoal(
            "hilt",
            "Set human approval",
            summary="Toggle HILT and severity globally or for one connector.",
            presets={"@Action": "hilt"},
            fields=("Connector", "Action", "HITL State", "Approval Min Severity", "Restart Gateway"),
        ),
        WizardGoal(
            "block-message",
            "Set block message",
            summary="Set or clear the custom block message globally or for one connector.",
            presets={"@Action": "block-message"},
            fields=("Connector", "Action", "Block Message", "Clear Message", "Restart Gateway"),
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
    SetupWizard.SANDBOX: _sandbox_goals,
    SetupWizard.REGISTRIES: _registries_goals,
    SetupWizard.NOTIFICATIONS_ROUTING: _notifications_routing_goals,
    SetupWizard.AI_DISCOVERY: _ai_discovery_goals,
    SetupWizard.SPLUNK_DASHBOARDS: _splunk_dashboards_goals,
    SetupWizard.TRUSTED_PATHS: _trusted_paths_goals,
    SetupWizard.GUARDRAIL_ACTIONS: _guardrail_actions_goals,
}


def wizard_goals(
    wizard: SetupWizard | int, cfg: object | Mapping[str, Any] | None = None
) -> tuple[WizardGoal, ...]:
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

    del cfg
    if wizard == SetupWizard.OBSERVABILITY:
        preset_id = (presets.get("@Preset") or "").strip()
        if preset_id:
            return observability_wizard_fields(preset_id)
    if wizard == SetupWizard.WEBHOOKS:
        channel = (presets.get("@Type") or "").strip()
        if channel:
            return webhook_wizard_fields(channel)
    return None


def wizard_state_summary(
    wizard: SetupWizard | int, cfg: object | Mapping[str, Any] | None = None
) -> str:
    """One-line "here's what's configured today" string for the goal menu.

    Returns an empty string for wizards without a useful summary so the
    renderer can omit the line entirely.
    """

    wizard = SetupWizard(wizard)
    if wizard == SetupWizard.LLM:
        provider = _cfg_str(cfg, "llm.provider")
        model = _cfg_str(cfg, "llm.model")
        main = f"{provider}/{model}" if (provider and model) else (model or provider or "not set")
        judge = _cfg_str(cfg, "guardrail.judge.model") or "not set"
        connectors = _active_connector_names_for_setup(cfg)
        connector_summary = ", ".join(connectors) if connectors else "none"
        role = "judge+agent available" if _any_active_connector_is_proxy(cfg) else "judge only"
        return f"Main: {main}  ·  Judge: {judge}  ·  Connectors: {connector_summary} ({role})"
    if wizard == SetupWizard.GUARDRAIL:
        mode = _cfg_str(cfg, "guardrail.mode", "observe") or "observe"
        enabled = "on" if _guardrail_enabled(cfg) else "off"
        strategy = _cfg_str(cfg, "guardrail.detection_strategy", "regex_only") or "regex_only"
        return f"Guardrail: {enabled}  ·  Mode: {mode}  ·  Strategy: {strategy}"
    if wizard == SetupWizard.CONNECTOR_SETUP:
        connectors = _active_connector_names_for_setup(cfg)
        return f"Active connectors: {', '.join(connectors) if connectors else 'not set'}"
    if wizard == SetupWizard.AI_DISCOVERY:
        enabled = "on" if bool(get_config_value(cfg, "ai_discovery.enabled", True)) else "off"
        mode = _cfg_str(cfg, "ai_discovery.mode", "enhanced") or "enhanced"
        return f"AI discovery: {enabled}  ·  Mode: {mode}"
    if wizard == SetupWizard.GATEWAY:
        host = _cfg_str(cfg, "gateway.host") or "localhost"
        port = _cfg_str(cfg, "gateway.port") or "9090"
        return f"Gateway: {host}:{port}"
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
        WizardFormField("Output / Privacy", "section"),
        WizardFormField(
            "Emit OTel",
            "bool",
            "--emit-otel",
            "--no-emit-otel",
            value=_cfg_bool("emit_otel", True),
            default=_cfg_bool("emit_otel", True),
        ),
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
        ("Emit OTel", "--emit-otel", "--no-emit-otel"),
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
            WizardFormField(label, "bool", value=value, default=value)
        )
    fields.append(
        WizardFormField(
            "Restart Gateway After",
            "bool",
            value="yes",
            default="yes",
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
    connector = wizard_field_value(fields, "Connector")
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


def _build_notifications_routing_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    intents = notifications_routing_intents(fields)
    if intents:
        return intents[0].args
    # No toggles changed — keep the regression guard happy by returning
    # the bare prefix; the wizard submitter surfaces a "nothing to
    # apply" hint to the operator.
    return WIZARD_COMMANDS[SetupWizard.NOTIFICATIONS_ROUTING]


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
    del cfg
    if wizard == SetupWizard.GUARDRAIL:
        connector_mode_args = _connector_guardrail_mode_args(fields)
        if connector_mode_args is not None:
            return connector_mode_args
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
        wizard == SetupWizard.WEBHOOKS
        and wizard_bool_value(fields, "Enable HMAC Signing", "yes") == "no"
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
            if splunk_mode_value in {"splunk-o11y", "local-docker", "enterprise"} and field.label in splunk_pipeline_labels:
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
            # ``--human-approval`` / ``--disable-redaction`` are tri-state on
            # the CLI (default=None), so emit the explicit on/off form rather
            # than relying on the "skip when value==default" shortcut.
            if wizard == SetupWizard.GUARDRAIL and field.flag in {
                "--human-approval",
                "--disable-redaction",
            }:
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
    SetupWizard.NOTIFICATIONS_ROUTING: lambda fields: _build_notifications_routing_args(fields),
    SetupWizard.AI_DISCOVERY: lambda fields: _build_ai_discovery_args(fields),
    SetupWizard.SPLUNK_DASHBOARDS: lambda fields: _build_splunk_dashboards_args(fields),
    SetupWizard.TRUSTED_PATHS: lambda fields: _build_trusted_paths_args(fields),
    SetupWizard.GUARDRAIL_ACTIONS: lambda fields: _build_guardrail_actions_args(fields),
}


def missing_required_fields(wizard: SetupWizard | int, fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    wizard = SetupWizard(wizard)
    missing: list[str] = []
    if wizard == SetupWizard.CREDENTIALS and wizard_field_value(fields, "Action") == "set":
        if not wizard_field_value(fields, "Env Name"):
            missing.append("Env Name")
        if not wizard_field_value(fields, "Secret Value", raw=True):
            missing.append("Secret Value")
    if wizard == SetupWizard.CUSTOM_PROVIDERS:
        action = wizard_field_value(fields, "Action")
        if action in {"add", "remove"} and not wizard_field_value(fields, "Name"):
            missing.append("Name")
        # ``setup provider add`` accepts either a domain allow-list or a
        # --base-url; require at least one rather than mandating Domains.
        if (
            action == "add"
            and not wizard_field_value(fields, "Domains")
            and not wizard_field_value(fields, "Base URL")
        ):
            missing.append("Domains or Base URL")
    if wizard == SetupWizard.TRUSTED_PATHS:
        action = wizard_field_value(fields, "Action")
        if action in {"add", "remove"} and not wizard_field_value(fields, "Directory"):
            missing.append("Directory")
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


def mask_wizard_secret_values(
    fields: Sequence[WizardFormField], args: Sequence[str]
) -> tuple[str, ...]:
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


def redaction_desired_action(currently_disabled: bool) -> str:
    return "on" if currently_disabled else "off"


def redaction_toggle_intent(currently_disabled: bool) -> SetupCommandIntent:
    action = redaction_desired_action(currently_disabled)
    return SetupCommandIntent(
        label=f"setup redaction {action}",
        args=("setup", "redaction", action, "--yes"),
        category="setup",
        origin="redaction-modal",
    )


def redaction_consequence_copy(currently_disabled: bool) -> tuple[str, ...]:
    if currently_disabled:
        return (
            "Re-enables redaction - placeholders return on the next sidecar boot.",
            "Existing already-emitted audit rows, Splunk events, OTel logs, and webhooks stay as written.",
        )
    return (
        "Disabling redaction writes RAW content to SQLite audit DB.",
        "RAW content also reaches Splunk HEC, OTel log exporters, webhooks, gateway.log, and the Logs panel.",
        "Only proceed if every downstream sink lives in the same trust boundary as this install.",
    )


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
            "Audit DB, Splunk, OTel, and webhooks are NOT affected.",
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
    return ("uninstall", "--dry-run"), "uninstall dry-run"


def uninstall_intent(option: UninstallOption) -> SetupCommandIntent:
    args, display = uninstall_args_for_option(option)
    return SetupCommandIntent(
        label=display,
        args=args,
        category="destructive" if option != "dry-run" else "setup",
        origin="uninstall-modal",
    )


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
            connector = str(get_config_value(cfg, "claw.mode", "openclaw") or "openclaw").strip()
    connector = connector or "openclaw"
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
        WizardFormField("Connector", "choice", value=connector, default=connector, options=choices),
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
        WizardFormField("Guardrail Mode", "choice", value=mode, default=mode, options=("observe", "action")),
        WizardFormField(
            "Scanner Mode", "choice", value=scanner_mode, default=scanner_mode, options=("local", "remote", "both")
        ),
        WizardFormField(
            "Replace Existing",
            "bool",
            value="no",
            default="no",
            hint="Replace the configured connector set instead of adding this connector as a peer.",
        ),
        WizardFormField(
            "Workspace Dir",
            "string",
            hint="Optional workspace-scoped connector config directory.",
        ),
        WizardFormField("Restart Gateway", "bool", value="yes", default="yes"),
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
        WizardFormField("Local Stack", "bool", value="no", default="no"),
        WizardFormField("Verify After Setup", "bool", value="yes", default="yes"),
        WizardFormField(
            "Force Last Connector Removal",
            "bool",
            value="no",
            default="no",
            hint="Allow removing the final connector and fully unconfiguring enforcement.",
        ),
    )
    return _overlay_field_overrides(fields, overrides)


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


def _filter_fields_for_goal(
    fields: Sequence[WizardFormField], goal: WizardGoal | None
) -> tuple[WizardFormField, ...]:
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
        WizardFormField("Region", "string", "--vertex-region", hint="GCP location, e.g. us-central1.", visible_when=is_vertex),
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
    return _apply_dynamic_fields(candidates, overrides, driver)


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
    active_connectors = _guardrail_connector_keys(cfg)
    if "--connector" in overrides:
        connector = str(overrides.get("--connector", "") or "").strip()
    else:
        connector = str(get_config_value(cfg, "guardrail.connector", "") or "").strip()
        if not connector:
            connector = str(get_config_value(cfg, "claw.mode", "") or "").strip()
        if len(active_connectors) > 1:
            connector = ""
    mode = (
        _effective_guardrail_value(cfg, connector, "effective_mode", "guardrail.mode")
        if connector
        else ("observe" if len(active_connectors) > 1 else str(get_config_value(cfg, "guardrail.mode", "observe")))
    )
    mode = mode.strip().lower() or "observe"
    scanner_mode = str(get_config_value(cfg, "guardrail.scanner_mode", "local") or "local")
    strategy = str(get_config_value(cfg, "guardrail.detection_strategy", "regex_only") or "regex_only")
    rule_pack_dir = (
        _effective_guardrail_value(cfg, connector, "effective_rule_pack_dir", "guardrail.rule_pack_dir")
        if connector
        else ""
    )
    rule_pack = os.path.basename(rule_pack_dir.rstrip("/\\")).strip().lower() if rule_pack_dir else "default"
    if rule_pack not in {"default", "strict", "permissive"}:
        rule_pack = "default"
    judge_provider = "bedrock"
    judge_model = ""
    judge_provider_default = "bedrock"
    judge_model_default = ""
    if judge := str(get_config_value(cfg, "guardrail.judge.model", "") or ""):
        if "/" in judge:
            judge_provider, judge_model = judge.split("/", 1)
        else:
            judge_model = judge
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
    if judge and strategy in ("", "regex_only"):
        strategy = "regex_judge"
    strategy = (overrides.get("--detection-strategy") or strategy).strip() or "regex_only"
    # A live provider change (driver) wins so the conditional Bedrock /
    # Vertex / Azure judge groups re-derive against the new selection.
    judge_provider = (overrides.get("@Provider") or judge_provider).strip().lower() or judge_provider
    judge_key_env = str(get_config_value(cfg, "guardrail.judge.api_key_env", "") or "")
    judge_key_default = ""
    if not judge_key_env:
        judge_key_env = str(get_config_value(cfg, "llm.api_key_env", "") or "")
        judge_key_default = judge_key_env
    judge_base = str(get_config_value(cfg, "guardrail.judge.api_base", "") or "")
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
    effective_hilt = _effective_hilt_block(cfg, connector) if connector else None
    hilt = "yes" if bool(get_config_value(effective_hilt, "enabled", False)) else "no"
    hilt_min_severity = str(get_config_value(effective_hilt, "min_severity", "HIGH") or "HIGH").upper()
    redaction = "yes" if bool(get_config_value(cfg, "privacy.disable_redaction", False)) else "no"

    def j_strategy(dv: Mapping[str, str]) -> bool:
        return (dv.get("strategy", "") or "").strip().lower() in {"regex_judge", "judge_first"}

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
    candidates: tuple[WizardFormField, ...] = (
        WizardFormField("Core", "section"),
        WizardFormField(
            "Connector",
            "choice",
            "--connector",
            value=connector,
            default=connector,
            options=("", *CONNECTORS),
            required=True,
            hint="Choose the connector peer this guardrail setup should update.",
        ),
        WizardFormField("Mode", "choice", "--mode", value=mode, default=mode, options=("observe", "action")),
        WizardFormField(
            "Scanner Mode",
            "choice",
            "--scanner-mode",
            value=scanner_mode,
            default="local",
            options=("local", "remote", "both"),
        ),
        WizardFormField("Proxy Port", "int", "--port", value=str(get_config_value(cfg, "guardrail.port", "") or "")),
        WizardFormField("Detection", "section"),
        WizardFormField(
            "Strategy",
            "choice",
            "--detection-strategy",
            value=strategy,
            default="regex_only",
            options=("regex_only", "regex_judge", "judge_first"),
            hint="Rule/regex scanning is the baseline; judge strategies add LLM review on top.",
        ),
        WizardFormField(
            "Rule Pack",
            "choice",
            "--rule-pack",
            value=rule_pack,
            default=rule_pack,
            options=("default", "strict", "permissive"),
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
        WizardFormField("Auth Mode", "choice", "--judge-azure-auth-mode", options=AZURE_AUTH_MODES, visible_when=j_azure),
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
        WizardFormField("Cisco AI Defense", "section"),
        WizardFormField(
            "Endpoint",
            "string",
            "--cisco-endpoint",
            value=str(get_config_value(cfg, "cisco_ai_defense.endpoint", "") or ""),
        ),
        WizardFormField(
            "API Key Env",
            "string",
            "--cisco-api-key-env",
            value=str(get_config_value(cfg, "cisco_ai_defense.api_key_env", "") or ""),
        ),
        WizardFormField(
            "Timeout (ms)",
            "int",
            "--cisco-timeout-ms",
            value=str(get_config_value(cfg, "cisco_ai_defense.timeout_ms", "") or ""),
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
        WizardFormField(
            "Disable Redaction", "bool", "--disable-redaction", "--enable-redaction", value=redaction, default=redaction
        ),
        WizardFormField("Post-Setup", "section"),
        WizardFormField("Restart After", "bool", "--restart", "--no-restart", value="yes", default="yes"),
        WizardFormField("Verify After Setup", "bool", "--verify", "--no-verify", value="yes", default="yes"),
        WizardFormField("Disable", "bool", "--disable", value="no", default="no"),
    )
    return _apply_dynamic_fields(
        candidates,
        overrides,
        {
            "provider": judge_provider,
            "bedrock_auth_mode": judge_bedrock_auth_mode,
            "strategy": strategy,
        },
    )


def guardrail_wizard_fields(cfg: object | Mapping[str, Any] | None = None) -> tuple[WizardFormField, ...]:
    return _guardrail_wizard_fields_for({}, cfg)


SPLUNK_PIPELINE_OPTIONS: tuple[str, ...] = ("splunk-o11y", "local-docker", "enterprise", "custom")


def splunk_wizard_fields(os_name: str | None = None) -> tuple[WizardFormField, ...]:
    local_available = local_shell_stacks_supported(os_name)
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


def observability_wizard_fields(preset_id: str) -> tuple[WizardFormField, ...]:
    preset_options = tuple(
        preset
        for preset, _ in OBSERVABILITY_PRESETS
        if preset != "local-otlp" or local_shell_stacks_supported()
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
        WizardFormField(
            "Connector",
            "choice",
            "--connector",
            value="",
            default="",
            options=("", *CONNECTORS),
            hint="Optional: scope this audit sink to one connector; blank keeps the CLI default/global behavior.",
        ),
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
                    "Target", "choice", "--target", value="otel", default="otel", options=("otel", "audit_sinks")
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
    connector = wizard_field_value(fields, "Connector") or "openclaw"
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
        out = ["setup", "remove", connector, "--yes"]
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
        # The secret value is intentionally NOT placed in argv (it would be
        # visible in process listings). ``keys set`` reads it from a hidden
        # stdin prompt instead; the value is carried on the intent's
        # ``secret_stdin`` and written by the executor. See F-0801.
        return tuple(args)
    return ("keys", "list", "--json")


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
        if wizard_bool_value(fields, "Audit Sink", "yes") == "no":
            args.append("--no-audit-sink")
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
        [str(k).strip() for k in overrides.keys() if str(k).strip()]
        if isinstance(overrides, Mapping)
        else []
    )
    # Merge, preserving active-set order then any override-only keys.
    seen: set[str] = set()
    merged: list[str] = []
    for name in (*names, *override_keys):
        if name and name not in seen:
            seen.add(name)
            merged.append(name)
    return merged


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
            "Rule Pack Dir",
            f"guardrail.connectors.{connector}.rule_pack_dir",
            hint=f"Per-connector rule pack for {connector} (blank inherits the global pack).",
        )
        rows.append(
            _field_with_original(
                pack_field,
                _effective_guardrail_value(cfg, connector, "effective_rule_pack_dir", "guardrail.rule_pack_dir"),
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
        # E4d: hook-response fail mode (open=allow on failure, closed=block).
        fail_field = _field(
            cfg,
            "Hook Fail Mode",
            f"guardrail.connectors.{connector}.hook_fail_mode",
            "choice",
            ("open", "closed"),
            f"Per-connector hook fail mode for {connector} (inherits the global mode when unset).",
        )
        rows.append(
            _field_with_original(
                fail_field,
                _effective_guardrail_value(cfg, connector, "effective_hook_fail_mode", "guardrail.hook_fail_mode"),
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
        _field(
            cfg,
            "Hook Fail Mode",
            "guardrail.hook_fail_mode",
            "choice",
            ("open", "closed"),
            "open=allow hook response failures; closed=block.",
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
        _field(cfg, "Rule Pack Dir", "guardrail.rule_pack_dir", hint="Path to active rule pack."),
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
        _field(cfg, "Binary", "scanners.skill_scanner.binary", hint="Path/name of skill-scanner executable."),
        _field(
            cfg,
            "Policy",
            "scanners.skill_scanner.policy",
            "choice",
            ("strict", "balanced", "permissive", "none"),
            "Skill scanner policy.",
        ),
        _field(cfg, "Lenient", "scanners.skill_scanner.lenient", "bool", hint="Downgrade findings by one severity."),
        _field(cfg, "Use LLM", "scanners.skill_scanner.use_llm", "bool", hint="Enable LLM-assisted classification."),
        _field(
            cfg, "LLM Consensus Runs", "scanners.skill_scanner.llm_consensus_runs", "int", hint="Number of LLM votes."
        ),
        _field(cfg, "Use Behavioral", "scanners.skill_scanner.use_behavioral", "bool", hint="Run behavioral analysis."),
        _field(cfg, "Enable Meta", "scanners.skill_scanner.enable_meta", "bool", hint="Scan skill metadata."),
        _field(
            cfg, "Use Trigger", "scanners.skill_scanner.use_trigger", "bool", hint="Enable trigger-word heuristics."
        ),
        _field(cfg, "Use VirusTotal", "scanners.skill_scanner.use_virustotal", "bool", hint="Submit artifact hashes."),
        _field(
            cfg,
            "VirusTotal Key Env",
            "scanners.skill_scanner.virustotal_api_key_env",
            hint="Env var NAME for VirusTotal key.",
        ),
        _field(
            cfg,
            "VirusTotal API Key (redacted)",
            "scanners.skill_scanner.virustotal_api_key",
            "password",
            hint="Inline VirusTotal key.",
        ),
        _field(
            cfg, "Use AI Defense", "scanners.skill_scanner.use_aidefense", "bool", hint="Chain Cisco AI Defense scan."
        ),
        *_llm_override_fields(cfg, "Skill Scanner", "scanners.skill_scanner.llm"),
        _header(".. MCP Scanner .."),
        _field(cfg, "Binary", "scanners.mcp_scanner.binary", hint="Path/name of mcp-scanner executable."),
        _field(cfg, "Analyzers", "scanners.mcp_scanner.analyzers", hint="CSV of analyzer IDs."),
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
        _field(cfg, "Max Files", "ai_discovery.max_files_per_scan", "int", hint="Max files per scan."),
        _field(cfg, "Max File Bytes", "ai_discovery.max_file_bytes", "int", hint="Skip larger files."),
        _field(cfg, "Emit OTel", "ai_discovery.emit_otel", "bool", hint="Emit sanitized AI visibility telemetry."),
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
            _field(cfg, "Allow List Bypass", "watch.allow_list_bypass_scan", "bool", hint="Skip allow-listed rescans."),
            _field(
                cfg, "Rescan Enabled", "watch.rescan_enabled", "bool", hint="Periodically re-scan installed artifacts."
            ),
            _field(cfg, "Rescan Interval Min", "watch.rescan_interval_min", "int", hint="Minutes between rescans."),
        ),
        "Filesystem-watch tuning shared across asset watchers.",
    )


def _openshell_section(cfg: object | Mapping[str, Any] | None) -> ConfigSection:
    return ConfigSection(
        "OpenShell",
        (
            _field(cfg, "Binary", "openshell.binary", hint="Path to openshell executable."),
            _field(cfg, "Policy Dir", "openshell.policy_dir", hint="OpenShell policy YAML directory."),
            _field(
                cfg,
                "Mode",
                "openshell.mode",
                "choice",
                ("", "docker", "standalone"),
                "docker, standalone, or blank auto-detect.",
            ),
            _field(cfg, "Version", "openshell.version", hint="Pinned OpenShell version."),
            _field(cfg, "Sandbox Home", "openshell.sandbox_home", hint="Root of per-sandbox state."),
            _field(
                cfg,
                "Auto Pair (tristate)",
                "openshell.auto_pair",
                "choice",
                ("", "true", "false"),
                "Blank=default true.",
            ),
            _field(
                cfg,
                "Host Networking (tristate)",
                "openshell.host_networking",
                "choice",
                ("", "true", "false"),
                "Blank=default false.",
            ),
        ),
        "NVIDIA OpenShell sandbox integration.",
    )


def _otel_fields(cfg: object | Mapping[str, Any] | None) -> tuple[ConfigField, ...]:
    return (
        _header(".. Process-wide policy .."),
        _field(cfg, "Enabled", "otel.enabled", "bool", hint="Master OpenTelemetry export switch."),
        _header(".. Traces .."),
        _field(
            cfg,
            "Sampler",
            "otel.traces.sampler",
            "choice",
            (
                "always_on",
                "always_off",
                "traceidratio",
                "parentbased_always_on",
                "parentbased_always_off",
                "parentbased_traceidratio",
            ),
            "Trace sampler.",
        ),
        _field(cfg, "Sampler Arg", "otel.traces.sampler_arg", hint="Trace sampler argument."),
        _header(".. Logs .."),
        _field(
            cfg,
            "Emit individual findings",
            "otel.logs.emit_individual_findings",
            "bool",
            hint="One record per finding.",
        ),
        _header(".. Metrics .."),
        _field(
            cfg, "Export interval (s)", "otel.metrics.export_interval_s", "int", hint="Seconds between metric pushes."
        ),
        _field(
            cfg, "Temporality", "otel.metrics.temporality", "choice", ("delta", "cumulative"), "Metric temporality."
        ),
        _header(".. Batch .."),
        _field(
            cfg, "Max export batch size", "otel.batch.max_export_batch_size", "int", hint="Max records per request."
        ),
        _field(cfg, "Scheduled delay (ms)", "otel.batch.scheduled_delay_ms", "int", hint="Batch flush delay."),
        _field(cfg, "Max queue size", "otel.batch.max_queue_size", "int", hint="In-memory queue size."),
        _header(".. Resource .."),
        _field(cfg, "Attributes", "otel.resource.attributes", hint="CSV resource attributes."),
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
        [str(key).strip().lower() for key in overrides if str(key).strip()]
        if isinstance(overrides, Mapping)
        else []
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


def _agent_hook_fields(cfg: object | Mapping[str, Any] | None, label: str, prefix: str) -> tuple[ConfigField, ...]:
    return (
        _header(f".. {label} .."),
        _field(cfg, "Enabled", prefix + ".enabled", "bool", hint=f"{label} hooks master switch."),
        _field(
            cfg, "Mode", prefix + ".mode", "choice", ("", "observe", "action"), "Blank inherits connector defaults."
        ),
        _field(cfg, "Fail Mode", prefix + ".fail_mode", "choice", ("", "open", "closed"), "Legacy policy-layer hint."),
        _field(
            cfg,
            "Scan on Session Start",
            prefix + ".scan_on_session_start",
            "bool",
            hint="Run checks when session begins.",
        ),
        _field(cfg, "Scan on Stop", prefix + ".scan_on_stop", "bool", hint="Run checks when session stops."),
        _field(cfg, "Scan Paths", prefix + ".scan_paths", hint="CSV extra paths scanned by hooks."),
        _field(
            cfg,
            "Component Scan Interval (min)",
            prefix + ".component_scan_interval_minutes",
            "int",
            hint="Minimum minutes between repeated scans.",
        ),
    )


def _connector_hook_map_fields(cfg: object | Mapping[str, Any] | None) -> tuple[ConfigField, ...]:
    names = list(CONNECTORS)
    hooks = get_config_value(cfg, "connector_hooks", {}) or {}
    if isinstance(hooks, Mapping):
        names.extend(str(name) for name in hooks if str(name).strip())
    unique = sorted(dict.fromkeys(names))
    out: list[ConfigField] = []
    for name in unique:
        out.extend(_agent_hook_fields(cfg, _connector_hook_label(name), "connector_hooks." + name))
    return tuple(out)


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


def _audit_sink_summary_fields(cfg: object | Mapping[str, Any] | None) -> tuple[ConfigField, ...]:
    sinks = get_config_value(cfg, "audit_sinks", ()) or ()
    hint = ConfigField(
        "How to edit",
        "audit_sinks.hint",
        "header",
        "press E to open the interactive editor",
        "press E to open the interactive editor",
    )
    if not sinks:
        return (
            ConfigField("Status", "audit_sinks.summary", "header", "no sinks configured", "no sinks configured"),
            hint,
        )
    out = []
    for sink in sinks:
        name = str(_mapping_or_attr(sink, "name", "sink"))
        kind = str(_mapping_or_attr(sink, "kind", ""))
        enabled = bool(_mapping_or_attr(sink, "enabled", True))
        # ``kind`` is the audit-sink type (``stdout``, ``file``,
        # ``splunk_hec``, …) — every lowercase value would be parsed
        # as a Rich style and the kind/state would silently drop
        # from the summary. Escape both bracket pairs.
        state = "enabled" if enabled else "disabled"
        summary = f"{name} \\[{kind}] \\[{state}]"
        out.append(ConfigField(name, "audit_sinks." + name, "header", summary, summary))
    out.append(hint)
    return tuple(out)


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
        return "(unset)"
    return str(version)


def _connector_setup_alias(wire: str) -> str:
    normalized = wire.strip().lower().replace("_", "-")
    if normalized in {"claudecode", "claude-code"}:
        return "claude-code"
    if normalized in {"openclaw", "zeptoclaw", "codex", "hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity", "opencode", "omnigent"}:
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
