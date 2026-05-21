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

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Literal

from defenseclaw import config as dc_config
from defenseclaw.tui.services.cli_choices import (
    AI_DISCOVERY_MODES,
    CONNECTORS as _CHOICE_CONNECTORS,
    GUARDRAIL_CONNECTORS as _CHOICE_GUARDRAIL_CONNECTORS,
    LLM_OVERRIDE_PROVIDERS as _CHOICE_LLM_OVERRIDE_PROVIDERS,
    LLM_PROVIDERS as _CHOICE_LLM_PROVIDERS,
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
    "Observability",
    "Webhooks",
    "Sandbox",
    "Registries",
    "Notifications Routing",
    "AI Discovery",
    "Splunk Dashboards",
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
    "Add unified OTel and audit sink presets.",
    "Add chat or incident notifier webhooks.",
    "Initialize and configure OpenShell sandbox policy.",
    "Register an external skill or MCP catalog source.",
    "Toggle notification categories and event sources.",
    "Enable or tune the sidecar AI Discovery service.",
    "Apply or destroy Splunk O11y dashboards.",
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
    "Runs: defenseclaw setup observability add <preset>. Need vendor preset, endpoint/realm, token, and signals.",
    "Runs: defenseclaw setup webhook add <type>. Need webhook URL, secret env where required, and event filters.",
    "Runs: defenseclaw sandbox setup. Need OpenShell policy choices and optional sandbox home/network settings.",
    "Runs: defenseclaw registry add <id> --non-interactive. Need source id, kind, content type, and manifest URL.",
    "Runs one defenseclaw setup notifications-set <slot> on|off per changed toggle. No credentials required.",
    "Runs: defenseclaw agent discovery enable --yes (or disable). Mirrors cadence, scope, and privacy toggles.",
    "Runs: defenseclaw setup splunk dashboards apply|destroy --yes. Requires the Splunk O11y realm + API token.",
)

OBSERVABILITY_PRESETS: tuple[tuple[str, str], ...] = (
    ("splunk-o11y", "Splunk Observability Cloud"),
    ("splunk-hec", "Splunk HEC"),
    ("splunk-enterprise", "Splunk Enterprise HEC"),
    ("datadog", "Datadog"),
    ("honeycomb", "Honeycomb"),
    ("newrelic", "New Relic"),
    ("grafana-cloud", "Grafana Cloud"),
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
        )


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

    def __init__(self, cfg: object | Mapping[str, Any] | None = None) -> None:
        self.config = cfg
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
                status=self._formatted_wizard_status(wizard, now=now),
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
            status=self._formatted_wizard_status(wizard, now=now),
        )

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

    def open_wizard_form(self, wizard: SetupWizard | int | None = None) -> None:
        if wizard is not None:
            self.active_wizard = SetupWizard(wizard)
        self.form_fields = list(wizard_form_defs(self.active_wizard, self.config))
        self.form_cursor = 0
        self.form_active = True
        self.form_reveal = False
        self.form_error = ""

    def close_wizard_form(self) -> None:
        self.form_fields = []
        self.form_cursor = 0
        self.form_active = False
        self.form_reveal = False
        self.form_error = ""

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
        return "defenseclaw " + " ".join(args) if args else "defenseclaw"

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
            ),
        )


def build_setup_sections(cfg: object | Mapping[str, Any] | None) -> tuple[ConfigSection, ...]:
    """Return the Go Setup config section/field catalog."""

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
                _field(cfg, "Enabled", "notifications.enabled", "bool", hint="Master desktop notification switch."),
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
            "User-session desktop toasts for blocks, would-blocks, and HITL approvals.",
            "Restart the gateway after editing; the dispatcher snapshots config at boot.",
        ),
        ConfigSection(
            "Claw",
            (
                _field(cfg, "Mode", "claw.mode", "choice", CONNECTORS, "Active agent framework."),
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
            "Advanced connector_hooks map for current and future agent connectors.",
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


def connector_setup_command_for_mode(wire: str) -> tuple[tuple[str, ...], str]:
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


def _custom_providers_wizard_fields() -> tuple[WizardFormField, ...]:
    return (
        WizardFormField(
            "Action", "choice", value="list", default="list", options=("list", "show", "add", "remove")
        ),
        WizardFormField("Name", "string"),
        WizardFormField("Domains", "string"),
        WizardFormField("Env Keys", "string"),
        WizardFormField("Profile ID", "string"),
        WizardFormField("Ollama Ports", "string"),
        WizardFormField("Reload Sidecar", "bool", value="yes", default="yes"),
    )


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
}


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

    _BOOL_FLAGS: tuple[tuple[str, str, str], ...] = (
        ("Shell History", "--include-shell-history", "--no-include-shell-history"),
        ("Package Manifests", "--include-package-manifests", "--no-include-package-manifests"),
        ("Env Var Names", "--include-env-var-names", "--no-include-env-var-names"),
        ("Network Domains", "--include-network-domains", "--no-include-network-domains"),
        ("Emit OTel", "--emit-otel", "--no-emit-otel"),
        ("Honor Workspace Signatures", "--allow-workspace-signatures", "--no-allow-workspace-signatures"),
        ("Store Raw Local Paths", "--store-raw-local-paths", "--no-store-raw-local-paths"),
    )
    for label, on_flag, off_flag in _BOOL_FLAGS:
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


def _build_notifications_routing_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    intents = notifications_routing_intents(fields)
    if intents:
        return intents[0].args
    # No toggles changed — keep the regression guard happy by returning
    # the bare prefix; the wizard submitter surfaces a "nothing to
    # apply" hint to the operator.
    return WIZARD_COMMANDS[SetupWizard.NOTIFICATIONS_ROUTING]


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

    del cfg
    wizard = SetupWizard(wizard)
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
            if wizard == SetupWizard.GUARDRAIL and field.flag in {
                "--human-approval",
                "--disable-redaction",
                "--judge",
                "--share-judge-key-with-scanners",
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
            # CSV-style multi-flag fields (e.g. --judge-fallback) repeat
            # the flag once per value.
            if field.flag == "--judge-fallback":
                for item in (chunk.strip() for chunk in field.value.split(",")):
                    if item:
                        base.extend(("--judge-fallback", item))
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
    SetupWizard.LOCAL_OBSERVABILITY: lambda fields: _build_local_observability_args(fields),
    SetupWizard.TOKEN_ROTATION: lambda fields: _build_token_rotation_args(fields),
    SetupWizard.CUSTOM_PROVIDERS: lambda fields: _build_custom_provider_args(fields),
    SetupWizard.NOTIFICATIONS_ROUTING: lambda fields: _build_notifications_routing_args(fields),
    SetupWizard.AI_DISCOVERY: lambda fields: _build_ai_discovery_args(fields),
    SetupWizard.SPLUNK_DASHBOARDS: lambda fields: _build_splunk_dashboards_args(fields),
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
        if action == "add" and not wizard_field_value(fields, "Domains"):
            missing.append("Domains")
    for field in fields:
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


def connector_setup_wizard_fields(cfg: object | Mapping[str, Any] | None = None) -> tuple[WizardFormField, ...]:
    connector = str(get_config_value(cfg, "claw.mode", "openclaw") or "openclaw").strip() or "openclaw"
    mode = str(get_config_value(cfg, "guardrail.mode", "observe") or "observe")
    scanner_mode = str(get_config_value(cfg, "guardrail.scanner_mode", "local") or "local")
    return (
        WizardFormField("Connector", "choice", value=connector, default=connector, options=CONNECTORS, required=True),
        WizardFormField("Guardrail Mode", "choice", value=mode, default=mode, options=("observe", "action")),
        WizardFormField(
            "Scanner Mode", "choice", value=scanner_mode, default=scanner_mode, options=("local", "remote", "both")
        ),
        WizardFormField("Restart Gateway", "bool", value="yes", default="yes"),
        WizardFormField("Local Stack", "bool", value="no", default="no"),
        WizardFormField("Verify After Setup", "bool", value="yes", default="yes"),
    )


def llm_wizard_fields(cfg: object | Mapping[str, Any] | None = None) -> tuple[WizardFormField, ...]:
    provider = str(get_config_value(cfg, "llm.provider", "anthropic") or "anthropic")
    api_key_env = str(
        get_config_value(cfg, "llm.api_key_env", dc_config.DEFENSECLAW_LLM_KEY_ENV) or dc_config.DEFENSECLAW_LLM_KEY_ENV
    )
    timeout = str(get_config_value(cfg, "llm.timeout", 30) or 30)
    retries = str(get_config_value(cfg, "llm.max_retries", 2) or 2)
    return (
        WizardFormField(
            "Provider", "choice", "--provider", value=provider, default=provider, options=LLM_PROVIDERS, required=True
        ),
        WizardFormField(
            "Model",
            "string",
            "--model",
            value=str(get_config_value(cfg, "llm.model", "") or ""),
            default=str(get_config_value(cfg, "llm.model", "") or ""),
            required=True,
        ),
        WizardFormField("API Key Env", "string", "--api-key-env", value=api_key_env, default=api_key_env),
        WizardFormField("API Key", "password", "--api-key"),
        WizardFormField(
            "Base URL",
            "string",
            "--base-url",
            value=str(get_config_value(cfg, "llm.base_url", "") or ""),
            default=str(get_config_value(cfg, "llm.base_url", "") or ""),
        ),
        WizardFormField("Timeout", "int", "--timeout", value=timeout, default=timeout),
        WizardFormField("Max Retries", "int", "--max-retries", value=retries, default=retries),
    )


def guardrail_wizard_fields(cfg: object | Mapping[str, Any] | None = None) -> tuple[WizardFormField, ...]:
    connector = str(get_config_value(cfg, "guardrail.connector", "") or "")
    if not connector:
        connector = str(get_config_value(cfg, "claw.mode", "openclaw") or "openclaw")
    fail_mode = str(get_config_value(cfg, "guardrail.hook_fail_mode", "open") or "open").lower()
    if fail_mode not in {"open", "closed"}:
        fail_mode = "open"
    judge_enabled_default = "yes" if bool(get_config_value(cfg, "guardrail.judge.enabled", False)) else "no"
    judge_fallbacks_raw = get_config_value(cfg, "guardrail.judge.fallbacks", []) or []
    if isinstance(judge_fallbacks_raw, (list, tuple)):
        judge_fallbacks_csv = ",".join(str(item) for item in judge_fallbacks_raw if str(item).strip())
    else:
        judge_fallbacks_csv = str(judge_fallbacks_raw)
    mode = str(get_config_value(cfg, "guardrail.mode", "observe") or "observe")
    scanner_mode = str(get_config_value(cfg, "guardrail.scanner_mode", "local") or "local")
    strategy = str(get_config_value(cfg, "guardrail.detection_strategy", "regex_only") or "regex_only")
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
    hilt = "yes" if bool(get_config_value(cfg, "guardrail.hilt.enabled", False)) else "no"
    redaction = "yes" if bool(get_config_value(cfg, "privacy.disable_redaction", False)) else "no"
    return (
        WizardFormField("Core", "section"),
        WizardFormField(
            "Connector",
            "choice",
            "--connector",
            value=connector,
            default=connector,
            options=CONNECTORS,
        ),
        WizardFormField("Mode", "choice", "--mode", value=mode, default="observe", options=("observe", "action")),
        WizardFormField(
            "Hook Fail Mode",
            "choice",
            "--fail-mode",
            value=fail_mode,
            default="open",
            options=("open", "closed"),
        ),
        WizardFormField(
            "Scanner Mode",
            "choice",
            "--scanner-mode",
            value=scanner_mode,
            default="local",
            options=("local", "remote", "both"),
        ),
        WizardFormField("Proxy Port", "int", "--port", value=str(get_config_value(cfg, "guardrail.port", "") or "")),
        WizardFormField(
            "Block Message",
            "string",
            "--block-message",
            value=str(get_config_value(cfg, "guardrail.block_message", "") or ""),
        ),
        WizardFormField("Detection", "section"),
        WizardFormField(
            "Strategy",
            "choice",
            "--detection-strategy",
            value=strategy,
            default="regex_only",
            options=("regex_only", "regex_judge", "judge_first"),
        ),
        WizardFormField(
            "Rule Pack",
            "choice",
            "--rule-pack",
            value="default",
            default="default",
            options=("default", "strict", "permissive"),
        ),
        WizardFormField("LLM Judge", "section"),
        WizardFormField(
            "Judge",
            "bool",
            "--judge",
            "--no-judge",
            value=judge_enabled_default,
            default=judge_enabled_default,
        ),
        WizardFormField(
            "Provider", "choice", value=judge_provider, default=judge_provider_default, options=_bifrost_providers()
        ),
        WizardFormField("Model", "string", "--judge-model", value=judge_model, default=judge_model_default),
        WizardFormField(
            "Fallback Models (CSV)",
            "string",
            "--judge-fallback",
            value=judge_fallbacks_csv,
            default=judge_fallbacks_csv,
        ),
        WizardFormField("API Key Env", "string", "--judge-api-key-env", value=judge_key_env, default=judge_key_default),
        WizardFormField("API Base URL", "string", "--judge-api-base", value=judge_base, default=judge_base_default),
        WizardFormField(
            "Share Judge Key With Scanners",
            "bool",
            "--share-judge-key-with-scanners",
            "--no-share-judge-key-with-scanners",
            value="no",
            default="no",
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
            value=str(get_config_value(cfg, "guardrail.hilt.min_severity", "HIGH") or "HIGH").upper(),
            default=str(get_config_value(cfg, "guardrail.hilt.min_severity", "HIGH") or "HIGH").upper(),
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


SPLUNK_PIPELINE_OPTIONS: tuple[str, ...] = ("splunk-o11y", "local-docker", "enterprise", "custom")


def splunk_wizard_fields() -> tuple[WizardFormField, ...]:
    return (
        WizardFormField("Pipeline", "section"),
        WizardFormField(
            "Mode",
            "choice",
            "",
            value="splunk-o11y",
            default="splunk-o11y",
            options=SPLUNK_PIPELINE_OPTIONS,
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
    fields: list[WizardFormField] = [
        WizardFormField(
            "Preset",
            "preset",
            value=preset_id,
            default=preset_id,
            options=tuple(preset for preset, _ in OBSERVABILITY_PRESETS),
        ),
        WizardFormField("Name (optional)", "string", "--name"),
        WizardFormField("Enabled", "bool", "--enabled", "--disabled", value="yes", default="yes"),
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
            "Type", "whtype", value=channel_type, default=channel_type, options=tuple(kind for kind, _ in WEBHOOK_TYPES)
        ),
        WizardFormField("Name (optional)", "string", "--name"),
        WizardFormField("URL", "string", "--url", required=True),
        WizardFormField("Enabled", "bool", "--enabled", "--disabled", value="yes", default="yes"),
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
    args, _display = connector_setup_command_for_mode(connector)
    if not args:
        args, _display = connector_setup_command_for_mode("openclaw")
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
        if secret := wizard_field_value(fields, "Secret Value", raw=True):
            args.extend(("--value", secret))
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


def _build_custom_provider_args(fields: Sequence[WizardFormField]) -> tuple[str, ...]:
    action = wizard_field_value(fields, "Action")
    if action == "add":
        args = ["setup", "provider", "add"]
        if name := wizard_field_value(fields, "Name"):
            args.extend(("--name", name))
        for domain in split_csv(wizard_field_value(fields, "Domains")):
            args.extend(("--domain", domain))
        for env_key in split_csv(wizard_field_value(fields, "Env Keys")):
            args.extend(("--env-key", env_key))
        if profile_id := wizard_field_value(fields, "Profile ID"):
            args.extend(("--profile-id", profile_id))
        for port in split_csv(wizard_field_value(fields, "Ollama Ports")):
            args.extend(("--ollama-port", port))
        if wizard_bool_value(fields, "Reload Sidecar", "yes") == "no":
            args.append("--no-reload")
        return tuple(args)
    if action == "remove":
        args = ["setup", "provider", "remove"]
        if name := wizard_field_value(fields, "Name"):
            args.extend(("--name", name))
        if wizard_bool_value(fields, "Reload Sidecar", "yes") == "no":
            args.append("--no-reload")
        return tuple(args)
    if action == "show":
        return ("setup", "provider", "show")
    return ("setup", "provider", "list")


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
        _header(".. Globals .."),
        _field(cfg, "Enabled", "otel.enabled", "bool", hint="Master OpenTelemetry export switch."),
        _field(cfg, "Protocol", "otel.protocol", "choice", ("grpc", "http/protobuf"), "Default OTLP transport."),
        _field(cfg, "Endpoint", "otel.endpoint", hint="Default collector URL."),
        _field(cfg, "TLS Insecure", "otel.tls.insecure", "bool", hint="Skip TLS verification."),
        _field(cfg, "TLS CA Cert", "otel.tls.ca_cert", hint="Path to CA bundle."),
        _field(cfg, "Headers", "otel.headers", hint="CSV key=value headers; values redacted in summaries."),
        _header(".. Traces .."),
        _field(cfg, "Enabled", "otel.traces.enabled", "bool", hint="Export spans."),
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
        _field(cfg, "Endpoint override", "otel.traces.endpoint", hint="Traces-only collector URL."),
        _field(
            cfg,
            "Protocol override",
            "otel.traces.protocol",
            "choice",
            ("", "grpc", "http/protobuf"),
            "Traces-only protocol.",
        ),
        _field(cfg, "URL Path", "otel.traces.url_path", hint="HTTP path suffix."),
        _header(".. Logs .."),
        _field(cfg, "Enabled", "otel.logs.enabled", "bool", hint="Export OTel log records."),
        _field(
            cfg,
            "Emit individual findings",
            "otel.logs.emit_individual_findings",
            "bool",
            hint="One record per finding.",
        ),
        _field(cfg, "Endpoint override", "otel.logs.endpoint", hint="Logs-only collector URL."),
        _field(
            cfg,
            "Protocol override",
            "otel.logs.protocol",
            "choice",
            ("", "grpc", "http/protobuf"),
            "Logs-only protocol.",
        ),
        _field(cfg, "URL Path", "otel.logs.url_path", hint="HTTP path suffix."),
        _header(".. Metrics .."),
        _field(cfg, "Enabled", "otel.metrics.enabled", "bool", hint="Export metrics."),
        _field(
            cfg, "Export interval (s)", "otel.metrics.export_interval_s", "int", hint="Seconds between metric pushes."
        ),
        _field(
            cfg, "Temporality", "otel.metrics.temporality", "choice", ("delta", "cumulative"), "Metric temporality."
        ),
        _field(cfg, "Endpoint override", "otel.metrics.endpoint", hint="Metrics-only collector URL."),
        _field(
            cfg,
            "Protocol override",
            "otel.metrics.protocol",
            "choice",
            ("", "grpc", "http/protobuf"),
            "Metrics-only protocol.",
        ),
        _field(cfg, "URL Path", "otel.metrics.url_path", hint="HTTP path suffix."),
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
    return tuple(fields)


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
    if normalized in {"openclaw", "zeptoclaw", "codex", "hermes", "cursor", "windsurf", "geminicli", "copilot"}:
        return normalized
    return ""


def _connector_hook_label(name: str) -> str:
    return {
        "codex": "Codex",
        "claudecode": "Claude Code",
        "zeptoclaw": "ZeptoClaw",
        "openclaw": "OpenClaw",
    }.get(name, name[:1].upper() + name[1:] if name else "Connector")


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
