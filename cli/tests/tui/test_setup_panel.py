# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Setup Textual model parity tests."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from types import SimpleNamespace

from defenseclaw.tui.panels.setup import (
    CONNECTORS,
    WIZARD_DESCRIPTIONS,
    WIZARD_HOW_TO,
    SetupPanelModel,
    SetupWizard,
    UninstallModalState,
    action_matrix_fields,
    build_setup_sections,
    build_wizard_args,
    connector_setup_command_for_mode,
    connector_setup_wizard_fields,
    guardrail_wizard_fields,
    missing_required_fields,
    notifications_consequence_copy,
    notifications_desired_action,
    notifications_toggle_intent,
    observability_wizard_fields,
    redaction_consequence_copy,
    redaction_desired_action,
    redaction_toggle_intent,
    render_wizard_value,
    uninstall_args_for_option,
    uninstall_intent,
    webhook_wizard_fields,
    wizard_field_value,
    wizard_form_defs,
)
from defenseclaw.tui.services.setup_state import (
    ConfigDiffEntry,
    ConfigField,
    ConfigSection,
    CredentialRow,
    RestartQueue,
    build_readiness_checks,
    config_diff,
    mask_secret,
    parse_credential_rows,
    validate_config_field,
)


def _field_by_key(sections: Sequence[ConfigSection], key: str) -> ConfigField:
    for section in sections:
        for field in section.fields:
            if field.key == key:
                return field
    raise AssertionError(f"field not found: {key}")


def _section(sections: Sequence[ConfigSection], name: str) -> ConfigSection:
    for section in sections:
        if section.name == name:
            return section
    raise AssertionError(f"section not found: {name}")


def _with_field(fields: Sequence, label: str, value: str) -> tuple:
    return tuple(field.with_value(value) if field.label == label else field for field in fields)


def test_setup_config_sections_match_go_catalog_order() -> None:
    names = tuple(section.name for section in build_setup_sections({}))

    assert names == (
        "General",
        "Agent",
        "Privacy",
        "Notifications",
        "Claw",
        "Agent Hooks",
        "Connector Hooks",
        "Gateway",
        "Guardrail",
        "Scanners",
        "Asset Policy",
        "AI Discovery",
        "Gateway Watcher",
        "Gateway Watchdog",
        "Audit Sinks",
        "Webhooks",
        "OTel",
        "Skill Actions",
        "MCP Actions",
        "Plugin Actions",
        "Watch",
        "OpenShell",
        "Inspect LLM (legacy - read-only)",
        "Cisco AI Defense",
        "Firewall",
    )


def test_notifications_fields_preserve_config_editor_catalog() -> None:
    section = _section(build_setup_sections({}), "Notifications")
    fields = {field.key: field for field in section.fields}

    assert set(fields) >= {
        "notifications.enabled",
        "notifications.block_enforced",
        "notifications.block_would_block",
        "notifications.hitl_approval",
        "notifications.sources.hook",
        "notifications.sources.guardrail",
        "notifications.sources.asset_policy",
        "notifications.dedup_window",
        "notifications.max_per_minute",
    }
    assert fields["notifications.enabled"].kind == "bool"
    assert fields["notifications.dedup_window"].hint
    assert fields["notifications.max_per_minute"].kind == "int"


def test_action_matrix_has_header_and_severity_triplets() -> None:
    fields = action_matrix_fields("skill_actions", {})

    assert len(fields) == 16
    assert fields[0].kind == "header"
    assert fields[1].key == "skill_actions.critical.file"
    assert fields[1].options == ("none", "quarantine")
    assert fields[2].options == ("enable", "disable")
    assert fields[3].options == ("none", "block", "allow")


def test_config_validation_matches_go_setup_state_rules() -> None:
    assert validate_config_field(ConfigField("TLS", "gateway.tls", "bool", "maybe")).severity == "error"
    assert validate_config_field(ConfigField("Port", "gateway.port", "int", "70000")).message == (
        "port must be between 1 and 65535"
    )
    assert validate_config_field(ConfigField("Retries", "llm.max_retries", "int", "-1")).severity == "error"
    assert validate_config_field(ConfigField("API Key Env", "llm.api_key_env", "string", "sk-secret")).severity == (
        "warning"
    )
    assert (
        validate_config_field(ConfigField("Base URL", "llm.base_url", "string", "https://u:p@example.com")).severity
        == "error"
    )
    assert validate_config_field(ConfigField("Endpoint", "otel.endpoint", "string", "localhost:4317")).severity == "ok"
    assert validate_config_field(ConfigField("Dedup", "notifications.dedup_window", "string", "1\u00b5s")).severity == (
        "ok"
    )
    assert (
        validate_config_field(ConfigField("Dedup", "notifications.dedup_window", "string", "30 bananas")).severity
        == "error"
    )
    assert validate_config_field(ConfigField("TLS Skip", "gateway.tls_skip_verify", "bool", "true")).severity == (
        "warning"
    )


def test_secret_masking_and_config_diff_hide_sensitive_values() -> None:
    field = ConfigField(
        "API Key (redacted)",
        "llm.api_key",
        "password",
        "sk-new-abcdefghijklmnopqrstuvwxyz",
        "sk-old-abcdefghijklmnopqrstuvwxyz",
    )

    assert mask_secret("") == "(empty)"
    assert mask_secret("abcd") == "****"
    assert mask_secret("abcdef") == "****cdef"
    assert config_diff((ConfigSection("General", (field,), ""),)) == (
        ConfigDiffEntry(
            key="llm.api_key",
            before="****wxyz",
            after="****wxyz",
            secret=True,
        ),
    )


def test_credentials_parse_missing_and_readiness_fix_intents() -> None:
    rows = parse_credential_rows(
        'WARNING: old output\n[{"env_name":"OPENAI_API_KEY","requirement":"required","set":false}]'
    )
    queue = RestartQueue().with_reason("config saved from TUI", last_started_at="old-start")
    checks = build_readiness_checks(
        {"claw": {"mode": "codex"}, "llm": {"provider": "openai", "model": "gpt-5"}},
        {"gateway": {"state": "running"}, "api": {"state": "ready"}},
        {},
        rows,
        queue,
    )
    by_title = {check.title: check for check in checks}

    assert rows[0].env_name == "OPENAI_API_KEY"
    assert rows[0].requirement == "required"
    assert rows[0].set is False
    assert by_title["Required Credentials"].status == "fail"
    assert by_title["Required Credentials"].fix is not None
    assert by_title["Required Credentials"].fix.args == ("keys", "fill-missing", "--non-interactive")
    assert by_title["Restart Pending"].status == "warn"
    assert by_title["Restart Pending"].fix is not None
    assert by_title["Restart Pending"].fix.binary == "defenseclaw-gateway"


def test_connector_wizard_builds_go_argv_for_supported_connectors() -> None:
    assert connector_setup_command_for_mode("claudecode") == (
        ("setup", "claude-code", "--yes"),
        "setup claude-code",
    )

    fields = connector_setup_wizard_fields({})
    fields = _with_field(fields, "Connector", "openclaw")
    fields = _with_field(fields, "Guardrail Mode", "action")
    fields = _with_field(fields, "Scanner Mode", "both")
    fields = _with_field(fields, "Restart Gateway", "no")
    fields = _with_field(fields, "Verify After Setup", "no")
    assert build_wizard_args(SetupWizard.CONNECTOR_SETUP, fields) == (
        "setup",
        "openclaw",
        "--yes",
        "--mode",
        "action",
        "--no-restart",
        "--scanner-mode",
        "both",
        "--no-verify",
    )

    fields = connector_setup_wizard_fields({})
    fields = _with_field(fields, "Connector", "codex")
    fields = _with_field(fields, "Restart Gateway", "no")
    fields = _with_field(fields, "Local Stack", "yes")
    assert build_wizard_args(SetupWizard.CONNECTOR_SETUP, fields) == (
        "setup",
        "codex",
        "--yes",
        "--mode",
        "observe",
        "--no-restart",
        "--with-local-stack",
    )

    # Regression: hook-connector wizard must forward --mode so action
    # mode actually sticks. Previously the hook branch dropped --mode
    # and codex/claudecode silently downgraded to observe.
    fields = connector_setup_wizard_fields({})
    fields = _with_field(fields, "Connector", "codex")
    fields = _with_field(fields, "Guardrail Mode", "action")
    assert build_wizard_args(SetupWizard.CONNECTOR_SETUP, fields) == (
        "setup",
        "codex",
        "--yes",
        "--mode",
        "action",
    )

    fields = connector_setup_wizard_fields({})
    fields = _with_field(fields, "Connector", "claudecode")
    fields = _with_field(fields, "Guardrail Mode", "action")
    fields = _with_field(fields, "Local Stack", "yes")
    assert build_wizard_args(SetupWizard.CONNECTOR_SETUP, fields) == (
        "setup",
        "claude-code",
        "--yes",
        "--mode",
        "action",
        "--with-local-stack",
    )

    assert set(CONNECTORS) == {
        "openclaw",
        "zeptoclaw",
        "codex",
        "claudecode",
        "hermes",
        "cursor",
        "windsurf",
        "geminicli",
        "copilot",
    }


def test_credentials_matrix_actions_are_data_only_and_validate_required_fields() -> None:
    fields = wizard_form_defs(SetupWizard.CREDENTIALS)

    assert build_wizard_args(SetupWizard.CREDENTIALS, fields) == ("keys", "list", "--json")
    assert build_wizard_args(SetupWizard.CREDENTIALS, _with_field(fields, "Action", "check")) == ("keys", "check")
    assert build_wizard_args(SetupWizard.CREDENTIALS, _with_field(fields, "Action", "fill-missing")) == (
        "keys",
        "fill-missing",
        "--non-interactive",
    )

    set_fields = _with_field(fields, "Action", "set")
    assert missing_required_fields(SetupWizard.CREDENTIALS, set_fields) == ("Env Name", "Secret Value")

    set_fields = _with_field(set_fields, "Env Name", "OPENAI_API_KEY")
    set_fields = _with_field(set_fields, "Secret Value", "sk-live")
    assert build_wizard_args(SetupWizard.CREDENTIALS, set_fields) == (
        "keys",
        "set",
        "OPENAI_API_KEY",
        "--value",
        "sk-live",
    )
    assert render_wizard_value(set_fields[2]) == "****live"
    assert render_wizard_value(set_fields[2], reveal=True) == "sk-live"


def test_guardrail_wizard_inherits_unified_llm_without_forcing_override() -> None:
    cfg = {
        "llm": {
            "provider": "openai",
            "model": "gpt-5",
            "api_key_env": "OPENAI_API_KEY",
            "base_url": "https://api.openai.com/v1",
        },
        "guardrail": {"mode": "observe", "scanner_mode": "local", "judge": {}, "hilt": {}},
    }
    fields = guardrail_wizard_fields(cfg)

    assert wizard_field_value(fields, "Provider") == "openai"
    assert wizard_field_value(fields, "Model") == "gpt-5"
    assert "--judge-model" not in build_wizard_args(SetupWizard.GUARDRAIL, fields)
    assert "--judge-api-key-env" not in build_wizard_args(SetupWizard.GUARDRAIL, fields)
    assert "--judge-api-base" not in build_wizard_args(SetupWizard.GUARDRAIL, fields)

    fields = _with_field(fields, "Model", "gpt-5-mini")
    assert "--judge-model" in build_wizard_args(SetupWizard.GUARDRAIL, fields)
    assert "openai/gpt-5-mini" in build_wizard_args(SetupWizard.GUARDRAIL, fields)


def test_observability_and_webhook_wizards_pass_positionals_and_defaults() -> None:
    obs = observability_wizard_fields("splunk-o11y")
    assert missing_required_fields(SetupWizard.OBSERVABILITY, obs) == ()
    assert missing_required_fields(SetupWizard.OBSERVABILITY, observability_wizard_fields("otlp")) == ("Endpoint",)

    obs = _with_field(obs, "Access Token", "token-123")
    assert build_wizard_args(SetupWizard.OBSERVABILITY, obs) == (
        "setup",
        "observability",
        "add",
        "splunk-o11y",
        "--non-interactive",
        "--realm",
        "us1",
        "--signals",
        "traces,metrics",
        "--token",
        "token-123",
    )

    webhook = webhook_wizard_fields("pagerduty")
    assert missing_required_fields(SetupWizard.WEBHOOKS, webhook) == ("URL",)

    webhook = _with_field(webhook, "URL", "https://events.pagerduty.com/v2/enqueue")
    assert build_wizard_args(SetupWizard.WEBHOOKS, webhook) == (
        "setup",
        "webhook",
        "add",
        "pagerduty",
        "--non-interactive",
        "--url",
        "https://events.pagerduty.com/v2/enqueue",
        "--min-severity",
        "HIGH",
        "--events",
        "block,scan,guardrail,drift,health",
        "--timeout-seconds",
        "10",
        "--secret-env",
        "DEFENSECLAW_PD_ROUTING_KEY",
    )


def test_modal_toggle_and_uninstall_state_match_go_args_and_copy() -> None:
    assert redaction_desired_action(currently_disabled=True) == "on"
    assert redaction_toggle_intent(currently_disabled=True).args == ("setup", "redaction", "on", "--yes")
    assert "RAW content" in redaction_consequence_copy(currently_disabled=False)[0]

    assert notifications_desired_action(currently_enabled=True) == "off"
    assert notifications_toggle_intent(currently_enabled=False).args == ("setup", "notifications", "on", "--yes")
    assert "Audit DB" in notifications_consequence_copy(currently_enabled=True)[1]

    modal = UninstallModalState()
    modal.show()
    assert modal.visible is True
    assert modal.select_by_hotkey("a") is True
    assert modal.selected() == "wipe-data"
    assert uninstall_args_for_option("dry-run") == (("uninstall", "--dry-run"), "uninstall dry-run")
    assert uninstall_intent("wipe-data").args == ("uninstall", "--all", "--yes")
    assert uninstall_intent("wipe-data").category == "destructive"


def test_setup_panel_credentials_restart_and_config_save_state() -> None:
    model = SetupPanelModel({})

    assert "No credential snapshot loaded" in model.credential_empty_state()
    model.set_credential_snapshot([], error="boom")
    assert "boom" in model.credential_empty_state()

    model.set_credential_snapshot((CredentialRow(env_name="OPENAI_API_KEY", requirement="required"),))
    action = model.credential_action("s")
    assert action.handled is True
    assert action.open_form is True
    assert wizard_field_value(model.form_fields, "Action") == "set"
    assert wizard_field_value(model.form_fields, "Env Name") == "OPENAI_API_KEY"

    result = model.submit_wizard_form()
    assert result.intent is None
    assert "Secret Value" in model.form_error

    model.form_fields = list(_with_field(model.form_fields, "Secret Value", "sk-secret"))
    result = model.submit_wizard_form()
    assert result.intent is not None
    assert result.intent.args == ("keys", "set", "OPENAI_API_KEY", "--value", "sk-secret")

    model.queue_restart("config saved from TUI", last_started_at="old")
    assert model.restart_now_intent() is not None
    assert model.restart_now_intent().binary == "defenseclaw-gateway"
    assert model.mark_restart_started("new") is True
    assert model.restart_now_intent() is None

    cfg: dict = {}
    model = SetupPanelModel(cfg)
    model.sections = (
        ConfigSection(
            "Notifications",
            (ConfigField("Enabled", "notifications.enabled", "bool", "false", "true"),),
            "",
        ),
    )
    assert model.has_changes() is True
    model.apply_changes_to_config()
    assert cfg["notifications"]["enabled"] is False
    assert model.has_changes() is False


def test_config_field_catalog_preserves_secret_kind_and_choice_options() -> None:
    sections = build_setup_sections(
        {"llm": {"api_key": "sk-abcdefghijklmnopqrstuvwxyz"}, "openshell": {"auto_pair": None}}
    )

    assert _field_by_key(sections, "llm.api_key").kind == "password"
    assert _field_by_key(sections, "openshell.auto_pair").options == ("", "true", "false")
    assert _field_by_key(sections, "claw.mode").options == CONNECTORS


def test_setup_wizard_info_and_form_field_hints_are_complete() -> None:
    model = SetupPanelModel({})
    infos = model.wizard_infos()

    assert len(infos) == len(WIZARD_DESCRIPTIONS) == len(WIZARD_HOW_TO)
    assert infos[0].name == "Connector Setup"
    assert infos[0].argv == ("defenseclaw", "setup")
    assert "defenseclaw setup <connector>" in infos[0].how_to
    assert all(info.description for info in infos)
    assert all("defenseclaw" in info.how_to for info in infos)

    for wizard in SetupWizard:
        fields = wizard_form_defs(wizard)
        assert fields, f"{wizard.name} should expose form fields"
        for field in fields:
            if field.kind == "section":
                continue
            assert field.hint.strip(), f"{wizard.name}/{field.label} missing hint"


def test_setup_section_and_focused_row_metadata_exposes_actions_and_restart_hints() -> None:
    model = SetupPanelModel({"llm": {"provider": "openai"}, "notifications": {"enabled": True}})
    model.mode = "config"
    labels = model.section_labels()
    assert labels[0].name == "General"
    assert labels[0].active is True
    assert labels[0].editable_count > 0

    model.sections = (
        ConfigSection(
            "Notifications",
            (ConfigField("Enabled", "notifications.enabled", "bool", "true", "true", hint="Master switch."),),
            "Notification controls.",
        ),
        ConfigSection(
            "Audit Sinks",
            (ConfigField("Status", "audit_sinks.summary", "header", "no sinks configured", "no sinks configured"),),
            "Read-only audit sink summary.",
        ),
    )
    model.active_section = 0
    model.active_line = next(
        index
        for index, field in enumerate(model.sections[model.active_section].fields)
        if field.key == "notifications.enabled"
    )
    focused = model.focused_row_metadata()
    assert focused.section == "Notifications"
    assert focused.label == "Enabled"
    assert focused.action is not None
    assert focused.action.action == "toggle"
    assert focused.action.hotkey == "Enter/Space"
    assert "Restart:" in focused.restart_hint

    hints = model.save_restart_hints()
    assert hints.changes == 0
    assert hints.save_hint == "No config changes to save."
    assert "[`] Wizards" in hints.action_bar

    section = model.sections[model.active_section]
    field = section.fields[model.active_line]
    model.sections = (
        model.sections[: model.active_section]
        + (
            ConfigSection(
                section.name,
                section.fields[: model.active_line]
                + (field.with_value("false"),)
                + section.fields[model.active_line + 1 :],
                section.summary,
                section.help,
            ),
        )
        + model.sections[model.active_section + 1 :]
    )
    hints = model.save_restart_hints()
    assert hints.changes == 1
    assert "[S] Review & Save" in hints.action_bar
    assert "Review and save" in hints.save_hint

    model.queue_restart("config saved from Textual TUI")
    hints = model.save_restart_hints()
    assert hints.restart_pending is True
    assert "[G] Restart Now" in hints.action_bar
    assert "Restart pending: config saved from Textual TUI" in hints.restart_hint

    for index, section in enumerate(model.sections):
        if section.name == "Audit Sinks":
            model.active_section = index
            model.active_line = 0
            break
    focused = model.focused_row_metadata()
    assert focused.action is not None
    assert focused.action.action == "open_audit_sinks_editor"
    assert focused.action.hotkey == "E"


def test_setup_section_tabs_wrap_hit_test_and_field_actions() -> None:
    model = SetupPanelModel({})
    model.sections = (
        ConfigSection("General", (ConfigField("Mode", "claw.mode", "choice", "codex", "codex", CONNECTORS),), ""),
        ConfigSection("Agent", (ConfigField("Enabled", "agent.enabled", "bool", "true", "true"),), ""),
        ConfigSection("Connector Hooks", (ConfigField("Header", kind="header"), ConfigField("Path", "x.y")), ""),
        ConfigSection("OpenTelemetry", (ConfigField("Endpoint", "otel.endpoint"),), ""),
    )

    rows = model.section_tab_rows(width=28)

    assert len(rows) >= 2
    assert model.section_tab_hit(rows[1][0].start, rows[1][0].row + 2, width=28) == rows[1][0].index
    assert model.select_section(rows[1][0].index) is True
    assert model.active_section == rows[1][0].index
    assert model.active_line == 1
    assert model.config_scroll == 0

    assert model.move_section(1) is True
    assert model.current_section().name == "OpenTelemetry"
    assert model.move_section(99) is False

    model.select_section(0)
    assert model.cycle_current_field() is True
    assert model.current_field().value == CONNECTORS[(CONNECTORS.index("codex") + 1) % len(CONNECTORS)]
    assert model.set_current_field_value("openclaw") is True
    assert model.current_field().value == "openclaw"

    model.select_section(1)
    assert model.cycle_current_field() is True
    assert model.current_field().value == "false"


def test_setup_review_save_action_and_saved_hint_are_model_level() -> None:
    model = SetupPanelModel({})
    model.sections = (
        ConfigSection("Gateway", (ConfigField("Port", "gateway.port", "int", "70000", "9090"),), ""),
    )

    invalid = model.review_save_action()
    assert invalid.handled is True
    assert invalid.open_diff is False
    assert "Fix config validation" in invalid.hint

    model.sections = (
        ConfigSection("Gateway", (ConfigField("Port", "gateway.port", "int", "9091", "9090"),), ""),
    )
    review = model.review_save_action()
    assert review.handled is True
    assert review.open_diff is True
    assert review.hint == "Review 1 config change before saving."

    model.mark_saved(datetime(2026, 5, 20, 12, 0, tzinfo=timezone.utc))
    hints = model.save_restart_hints()
    assert hints.saved_hint == "Saved at 2026-05-20T12:00:00+00:00"
    assert hints.saved_hint in hints.action_bar


def test_webhook_wizard_enable_hmac_signing_gates_secret_env() -> None:
    """Generic webhook wizard now exposes an ``Enable HMAC Signing``
    bool that mirrors the CLI's confirm prompt. When disabled the
    --secret-env flag is dropped so the webhook ships unsigned.
    """

    fields = webhook_wizard_fields("generic")
    labels = {field.label for field in fields}
    assert "Enable HMAC Signing" in labels
    assert "HMAC secret env (optional)" in labels

    fields = _with_field(fields, "URL", "https://hooks.example/dc")
    argv = build_wizard_args(SetupWizard.WEBHOOKS, fields)
    assert "--secret-env" in argv
    secret_idx = argv.index("--secret-env")
    assert argv[secret_idx + 1] == "DEFENSECLAW_WEBHOOK_SECRET"

    no_hmac = _with_field(fields, "Enable HMAC Signing", "no")
    argv = build_wizard_args(SetupWizard.WEBHOOKS, no_hmac)
    assert "--secret-env" not in argv


def test_splunk_wizard_pipeline_picker_maps_to_bool_flag_and_queues_dashboards() -> None:
    """Splunk wizard now has a Pipeline picker (splunk-o11y / local-docker /
    enterprise / custom). The picker rewrites the pipeline bool flags so
    the operator only chooses one option in the guided form.

    Selecting ``Apply Dashboards After`` queues a follow-up intent to
    ``defenseclaw splunk_o11y_dashboards apply``, mirroring the CLI
    interactive prompt.
    """

    from defenseclaw.tui.panels.setup import (
        SPLUNK_PIPELINE_OPTIONS,
        splunk_wizard_follow_up_intents,
    )

    fields = wizard_form_defs(SetupWizard.SPLUNK)
    mode_field = next(field for field in fields if field.label == "Mode")
    assert tuple(mode_field.options) == SPLUNK_PIPELINE_OPTIONS

    enterprise_fields = _with_field(fields, "Mode", "enterprise")
    argv = build_wizard_args(SetupWizard.SPLUNK, enterprise_fields)
    assert "--enterprise" in argv
    assert "--o11y" not in argv
    assert "--logs" not in argv

    custom_fields = _with_field(fields, "Mode", "custom")
    custom_fields = _with_field(custom_fields, "Enable O11y", "yes")
    custom_fields = _with_field(custom_fields, "Enable Local Logs", "yes")
    argv = build_wizard_args(SetupWizard.SPLUNK, custom_fields)
    assert "--o11y" in argv
    assert "--logs" in argv
    assert "--enterprise" not in argv

    assert splunk_wizard_follow_up_intents(fields) == ()
    follow = splunk_wizard_follow_up_intents(_with_field(fields, "Apply Dashboards After", "yes"))
    assert len(follow) == 1
    assert follow[0].args == ("setup", "splunk", "dashboards", "apply", "--yes")


def test_doctor_fix_readiness_intent_chains_dry_run_then_apply() -> None:
    """Doctor --fix readiness fix now runs as a two-step consent flow.

    First step is ``doctor --fix --dry-run`` (no state changes); on
    success a follow-up ``doctor --fix --yes`` actually applies the
    fixers. This mirrors the CLI behavior where a user would inspect
    ``doctor --fix --dry-run`` before re-running with ``--yes``.
    """

    from defenseclaw.tui.services.setup_state import build_readiness_checks

    class _FakeCfg:
        guardrail = SimpleNamespace(enabled=False)
        otel = SimpleNamespace(enabled=False)
        scanners = SimpleNamespace(
            skill_scanner=SimpleNamespace(binary=""),
            mcp_scanner=SimpleNamespace(binary=""),
            codeguard="",
        )
        cisco_ai_defense = SimpleNamespace(endpoint="", api_key_env="")
        llm = SimpleNamespace(provider="", model="")
        audit_sinks: tuple = ()
        webhooks: tuple = ()
        webhook_endpoint = ""

    cfg = _FakeCfg()
    checks = build_readiness_checks(cfg, None, None, (), RestartQueue())
    by_title = {check.title: check for check in checks}
    scanner_check = by_title["Scanner Availability"]
    assert scanner_check.fix is not None
    assert scanner_check.fix.args == ("doctor", "--fix", "--dry-run")
    assert len(scanner_check.fix.follow_up) == 1
    follow_up = scanner_check.fix.follow_up[0]
    assert follow_up.args == ("doctor", "--fix", "--yes")


def test_registry_wizard_attaches_sync_and_scan_follow_ups() -> None:
    """Registry wizard mirrors CLI ``registry add`` follow-up prompts.

    Sync Now and Scan After Sync default to ``yes``; turning them off
    drops the corresponding intent. Without ``Source id`` (a regid kind
    field) no follow-up is queued.
    """

    from defenseclaw.tui.panels.setup import registry_wizard_follow_up_intents

    fields = wizard_form_defs(SetupWizard.REGISTRIES)
    intents = registry_wizard_follow_up_intents(fields)
    labels = tuple(intent.label for intent in intents)
    args = tuple(intent.args for intent in intents)
    assert labels == ("registry sync corp-skills", "skill scan (corp-skills)")
    assert args == (
        ("registry", "sync", "corp-skills"),
        ("skill", "scan", "--registry", "corp-skills"),
    )

    only_sync = _with_field(fields, "Scan After Sync", "no")
    intents = registry_wizard_follow_up_intents(only_sync)
    assert tuple(intent.args for intent in intents) == (("registry", "sync", "corp-skills"),)

    no_follow = _with_field(_with_field(fields, "Scan After Sync", "no"), "Sync Now", "no")
    assert registry_wizard_follow_up_intents(no_follow) == ()


def test_scanner_wizards_offer_unified_llm_provider_list() -> None:
    """The skill and MCP scanner wizards must expose the same provider
    catalogue as the unified ``_configure_llm`` flow — not the legacy
    ``anthropic|openai`` pair that drifted out of date."""

    expected_providers = {
        "anthropic",
        "openai",
        "openrouter",
        "azure",
        "gemini",
        "ollama",
        "vllm",
        "lm_studio",
    }

    skill_fields = wizard_form_defs(SetupWizard.SKILL_SCANNER)
    skill_provider = next(field for field in skill_fields if field.label == "LLM Provider")
    assert expected_providers.issubset(set(skill_provider.options))

    mcp_fields = wizard_form_defs(SetupWizard.MCP_SCANNER)
    mcp_provider = next(field for field in mcp_fields if field.label == "LLM Provider")
    assert expected_providers.issubset(set(mcp_provider.options))

    mcp_field_labels = {field.label for field in mcp_fields}
    assert {"API Endpoint", "API Key Env", "API Timeout (ms)"}.issubset(mcp_field_labels)

    mcp_fields = _with_field(mcp_fields, "API Endpoint", "https://example.cisco.com/v1")
    mcp_fields = _with_field(mcp_fields, "API Key Env", "CISCO_AI_DEFENSE_API_KEY")
    mcp_fields = _with_field(mcp_fields, "API Timeout (ms)", "5000")
    argv = build_wizard_args(SetupWizard.MCP_SCANNER, mcp_fields)
    assert ("--api-endpoint", "https://example.cisco.com/v1") == argv[argv.index("--api-endpoint") : argv.index("--api-endpoint") + 2]
    assert ("--api-key-env", "CISCO_AI_DEFENSE_API_KEY") == argv[argv.index("--api-key-env") : argv.index("--api-key-env") + 2]
    assert ("--api-timeout-ms", "5000") == argv[argv.index("--api-timeout-ms") : argv.index("--api-timeout-ms") + 2]


def test_guardrail_wizard_forwards_new_flags() -> None:
    """Guardrail wizard now surfaces the CLI flags the interactive
    walkthrough used to gate behind multi-step prompts.

    Connector, hook fail-mode, judge on/off, judge fallbacks (CSV ->
    repeated flag), and share-judge-key-with-scanners must all reach
    ``setup guardrail --non-interactive ...``.
    """

    fields = guardrail_wizard_fields({})
    fields = _with_field(fields, "Connector", "claudecode")
    fields = _with_field(fields, "Hook Fail Mode", "closed")
    fields = _with_field(fields, "Judge", "yes")
    fields = _with_field(fields, "Fallback Models (CSV)", "claude-3-opus, gpt-4o,gemini-pro")
    fields = _with_field(fields, "Share Judge Key With Scanners", "yes")

    argv = build_wizard_args(SetupWizard.GUARDRAIL, fields)
    assert "--connector" in argv
    connector_idx = argv.index("--connector")
    assert argv[connector_idx + 1] == "claudecode"
    assert "--fail-mode" in argv
    fail_idx = argv.index("--fail-mode")
    assert argv[fail_idx + 1] == "closed"
    assert "--judge" in argv
    assert "--no-judge" not in argv
    fallback_positions = [i for i, value in enumerate(argv) if value == "--judge-fallback"]
    assert len(fallback_positions) == 3
    assert argv[fallback_positions[0] + 1] == "claude-3-opus"
    assert argv[fallback_positions[1] + 1] == "gpt-4o"
    assert argv[fallback_positions[2] + 1] == "gemini-pro"
    assert "--share-judge-key-with-scanners" in argv


def test_ai_discovery_wizard_maps_to_enable_or_disable() -> None:
    """The AI Discovery wizard forwards every form value to the
    ``agent discovery enable`` flag set, and switches to
    ``agent discovery disable`` when the operator flips ``Enable=no``.

    The disable branch deliberately drops the tuning flags because the
    CLI's ``disable`` sub-command rejects them.
    """

    from defenseclaw.tui.panels.setup import (
        _build_ai_discovery_args,
        ai_discovery_wizard_fields,
    )

    fields = ai_discovery_wizard_fields(None)
    argv = _build_ai_discovery_args(fields)
    assert argv[:4] == ("agent", "discovery", "enable", "--yes")
    assert "--mode" in argv
    assert "--scan-interval-min" in argv
    assert "--include-shell-history" in argv  # default-on bool
    # Defaults match the CLI's defaults so the wizard only emits the
    # opt-out variant when the operator flips a toggle.
    assert "--no-restart" not in argv
    assert "--no-scan" not in argv

    skip_restart = _with_field(_with_field(fields, "Restart Gateway", "no"), "Scan Immediately", "no")
    argv = _build_ai_discovery_args(skip_restart)
    assert "--no-restart" in argv
    assert "--no-scan" in argv

    # Disable branch: tuning flags must not leak through.
    disabled = _with_field(fields, "Enable", "no")
    argv = _build_ai_discovery_args(disabled)
    assert argv == ("agent", "discovery", "disable", "--yes")

    # Toggling a privacy field off must surface the ``--no-*`` variant.
    flipped = _with_field(fields, "Shell History", "no")
    argv = _build_ai_discovery_args(flipped)
    assert "--no-include-shell-history" in argv
    assert "--include-shell-history" not in argv


def test_splunk_dashboards_wizard_apply_destroy_round_trips() -> None:
    """The Splunk dashboards wizard routes through the CLI subgroup
    (``setup splunk dashboards``) and only forwards optional flags the
    operator actually filled in.
    """

    from defenseclaw.tui.panels.setup import (
        _build_splunk_dashboards_args,
        splunk_dashboards_wizard_fields,
    )

    fields = splunk_dashboards_wizard_fields()
    argv = _build_splunk_dashboards_args(fields)
    assert argv == ("setup", "splunk", "dashboards", "apply", "--yes")

    destroyed = _with_field(fields, "Action", "destroy")
    argv = _build_splunk_dashboards_args(destroyed)
    assert argv[:5] == ("setup", "splunk", "dashboards", "destroy", "--yes")

    # Detector flags must opt in; ``--enable-detectors`` is gated on
    # ``--with-detectors`` to keep the form coherent with the CLI.
    with_detectors = _with_field(fields, "With Detectors", "yes")
    with_detectors = _with_field(with_detectors, "Enable Detectors", "yes")
    with_detectors = _with_field(with_detectors, "Name Prefix", "smoke-")
    argv = _build_splunk_dashboards_args(with_detectors)
    assert "--with-detectors" in argv
    assert "--enable-detectors" in argv
    assert ("--name-prefix", "smoke-") == argv[argv.index("--name-prefix") : argv.index("--name-prefix") + 2]


def test_splunk_dashboards_wizard_drops_enable_detectors_when_with_detectors_off() -> None:
    """``--enable-detectors`` MUST be gated on ``--with-detectors``.

    If we let it through unconditionally the CLI would silently ignore
    it (the dashboards subgroup only persists detector-tuning when the
    detectors actually ship) and operators would assume the toggle
    "worked" when it didn't. The form should not paper over that
    mismatch.
    """

    from defenseclaw.tui.panels.setup import (
        _build_splunk_dashboards_args,
        splunk_dashboards_wizard_fields,
    )

    fields = splunk_dashboards_wizard_fields()
    # Operator flipped Enable Detectors=yes but left With Detectors=no.
    rogue = _with_field(fields, "Enable Detectors", "yes")
    argv = _build_splunk_dashboards_args(rogue)
    assert "--with-detectors" not in argv
    assert "--enable-detectors" not in argv


def test_splunk_dashboards_wizard_omits_empty_optional_flags() -> None:
    """Empty optional fields (``Name Prefix`` / ``O11y API Token`` /
    ``API URL``) must NOT be forwarded as empty arg pairs.

    A bare ``--o11y-api-token ""`` reaches the Click parser and the
    CLI proceeds to authenticate with an empty bearer, which then
    looks like a credential bug at the SignalFx layer. The wizard
    must drop these cleanly when the operator leaves them blank.
    """

    from defenseclaw.tui.panels.setup import (
        _build_splunk_dashboards_args,
        splunk_dashboards_wizard_fields,
    )

    fields = splunk_dashboards_wizard_fields()
    argv = _build_splunk_dashboards_args(fields)
    # None of the optional pass-through flags should appear when their
    # backing fields are empty (the defaults are all empty strings).
    for flag in ("--name-prefix", "--o11y-api-token", "--api-url"):
        assert flag not in argv, f"{flag} leaked into argv: {argv}"


def test_ai_discovery_disable_honors_no_restart_flag() -> None:
    """Disabling AI Discovery while opting out of the gateway restart
    should produce ``agent discovery disable --yes --no-restart`` and
    nothing else.

    The disable sub-command rejects every tuning flag the enable form
    surfaces, so any flag bleed-through here would fail the CLI run.
    """

    from defenseclaw.tui.panels.setup import (
        _build_ai_discovery_args,
        ai_discovery_wizard_fields,
    )

    fields = ai_discovery_wizard_fields(None)
    fields = _with_field(fields, "Enable", "no")
    fields = _with_field(fields, "Restart Gateway", "no")
    argv = _build_ai_discovery_args(fields)
    assert argv == ("agent", "discovery", "disable", "--yes", "--no-restart")


def test_notifications_routing_wizard_emits_one_intent_per_changed_slot() -> None:
    """The Notifications Routing wizard turns each *changed* slot into
    a ``setup notifications-set <slot> on|off`` invocation.

    Unchanged toggles must NOT emit a command (otherwise the wizard
    would noisily reapply the entire matrix on every submit, restarting
    the gateway each time). Toggling ``Restart Gateway After`` to ``no``
    appends ``--no-restart`` to each emitted command.
    """

    from defenseclaw.tui.panels.setup import (
        notifications_routing_intents,
        notifications_routing_wizard_fields,
    )

    fields = notifications_routing_wizard_fields(None)
    # No changes -> no intents queued.
    assert notifications_routing_intents(fields) == ()

    # Flip the hook source off and HITL approval off; leave the rest.
    fields = _with_field(fields, "Source: Hooks", "no")
    fields = _with_field(fields, "HITL Approval", "no")
    intents = notifications_routing_intents(fields)
    args_seen = tuple(intent.args for intent in intents)
    assert args_seen == (
        ("setup", "notifications-set", "hitl_approval", "off"),
        ("setup", "notifications-set", "sources.hook", "off"),
    )

    # Suppress the restart on each emitted command.
    fields = _with_field(fields, "Restart Gateway After", "no")
    intents = notifications_routing_intents(fields)
    assert all(intent.args[-1] == "--no-restart" for intent in intents)


def test_notifications_routing_submit_with_no_changes_surfaces_form_error() -> None:
    """Guard against the malformed ``setup notifications-set`` invocation
    that would happen if the operator opened the wizard, made no toggle
    changes, and pressed Submit.

    Without this guard the primary intent would be the bare prefix
    ``("setup", "notifications-set")`` (no slot positional arg) which
    Click rejects with ``Error: Missing argument 'SLOT'``. The wizard
    submitter should refuse early with a friendly hint instead.
    """

    from defenseclaw.tui.panels.setup import SetupWizard, SetupPanelModel

    model = SetupPanelModel(cfg=None)
    model.open_wizard_form(SetupWizard.NOTIFICATIONS_ROUTING)
    result = model.submit_wizard_form()
    # The submit handler should signal "handled" but emit no command
    # intent — the wizard form stays open with a form_error hint.
    assert result.handled is True
    assert result.intent is None
    assert model.form_error is not None
    assert "No toggles changed" in model.form_error
    # And the wizard's status must NOT have been bumped to running.
    assert model.wizard_status.get(SetupWizard.NOTIFICATIONS_ROUTING) != "running..."


def test_cli_choices_module_matches_cli_source_of_truth() -> None:
    """``cli_choices`` is the only place the TUI should read provider
    catalogues from. This test asserts the centralized lists agree
    with the CLI's own constants, catching drift the moment either
    side adds or removes an entry.

    Both modules currently maintain their own constant; the assertion
    runs an exact set + ordering compare so a future contributor who
    edits one side without the other gets a single, obvious failure.
    """

    from defenseclaw.commands.cmd_setup import _WIZARD_LLM_PROVIDERS as CLI_PROVIDERS
    from defenseclaw.tui.services.cli_choices import (
        AI_DISCOVERY_MODES,
        CONNECTORS as TUI_CONNECTORS,
        GUARDRAIL_CONNECTORS,
        WIZARD_LLM_PROVIDERS,
    )

    assert tuple(WIZARD_LLM_PROVIDERS) == tuple(CLI_PROVIDERS)
    # The TUI's CONNECTORS list re-exports through panels.setup; both
    # must point at the same tuple object to prevent drift.
    assert CONNECTORS == TUI_CONNECTORS
    # GUARDRAIL_CONNECTORS must be a subset of CONNECTORS — proxy
    # connectors live in the connector picker too.
    assert GUARDRAIL_CONNECTORS.issubset(set(TUI_CONNECTORS))
    # AI discovery modes match the values cmd_agent.py accepts.
    from defenseclaw.commands.cmd_agent import _AI_DISCOVERY_MODES as CLI_AI_MODES

    assert tuple(AI_DISCOVERY_MODES) == tuple(CLI_AI_MODES)


def test_every_wizard_arg_builder_returns_non_empty_argv_for_defaults() -> None:
    """Regression guard for every wizard's ``build_wizard_args``.

    The hook-connector ``--mode`` bug slipped in because the arg builder
    silently swallowed a field; this test exercises every registered
    wizard with its default form so we catch the next class of silent
    drops. The assertion is intentionally weak (argv non-empty + base
    command prefix correct) so adding new fields doesn't churn it.
    """

    from defenseclaw.tui.panels.setup import WIZARD_COMMANDS

    for wizard in SetupWizard:
        fields = wizard_form_defs(wizard)
        argv = build_wizard_args(wizard, fields)
        assert argv, f"{wizard.name}: build_wizard_args returned empty argv for defaults"
        prefix = WIZARD_COMMANDS.get(wizard)
        if prefix is not None and prefix:
            assert tuple(argv[: len(prefix)]) == prefix, (
                f"{wizard.name}: expected argv prefix {prefix!r}, got {argv!r}"
            )
