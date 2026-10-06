# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The Setup center's pure parts: task status, readiness mapping, nav and detail.

``setup_catalog.task_status`` rates every task from the config and the
readiness checks; ``setup_center`` turns the model into the nav list, the
group table and the detail. No Textual app here.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from defenseclaw.tui.panels import setup_catalog, setup_center
from defenseclaw.tui.panels.setup import WIZARD_DESCRIPTIONS, SetupPanelModel, SetupWizard, wizard_goals
from defenseclaw.tui.services.setup_state import (
    ConfigField,
    ConfigSection,
    CredentialRow,
    CredentialSnapshot,
    ReadinessCheck,
    SetupCommandIntent,
)

STATES = {"ok", "attention", "off", "na"}


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / ".defenseclaw"))
    from defenseclaw.config import default_config

    return default_config()


def _check(title: str, status: str = "warn", detail: str = "broken", fix: tuple[str, ...] = ()) -> ReadinessCheck:
    intent = SetupCommandIntent(" ".join(fix), fix) if fix else None
    return ReadinessCheck(title, detail, status, intent)  # type: ignore[arg-type]


def _status(wizard: SetupWizard, cfg, readiness=(), **kwargs) -> setup_catalog.TaskStatus:
    return setup_catalog.task_status(wizard, cfg, readiness, **kwargs)


# --- task_status ------------------------------------------------------------


@pytest.mark.parametrize("group", setup_catalog.GROUP_TITLES)
def test_every_task_of_every_group_gets_a_status(config, group) -> None:
    for wizard in setup_catalog.group_tasks(group):
        status = _status(wizard, config)
        assert status.state in STATES, wizard
        assert status.label.startswith(setup_catalog.TASK_GLYPHS[status.state] + " "), wizard
        assert len(status.label) <= 22, (wizard, status.label)


@pytest.mark.parametrize("cfg", [None, {}, SimpleNamespace()])
def test_missing_config_never_breaks_the_status_column(cfg) -> None:
    statuses = {wizard: _status(wizard, cfg) for wizard in SetupWizard}

    assert all(status.state in STATES for status in statuses.values())
    assert statuses[SetupWizard.CONNECTOR_SETUP].state in {"attention", "off"}
    assert statuses[SetupWizard.GUARDRAIL].state == "off"
    assert statuses[SetupWizard.WEBHOOKS].state == "off"
    assert statuses[SetupWizard.TOKEN_ROTATION].state == "na"


def test_statuses_follow_the_config(config) -> None:
    config.guardrail.enabled = True
    config.guardrail.mode = "action"
    config.guardrail.hook_fail_mode = "open"
    config.scanners.skill_scanner.policy = "strict"
    config.acp.enabled = True

    guardrail = _status(SetupWizard.GUARDRAIL, config)
    assert guardrail.state == "ok" and "action" in guardrail.text
    assert "open" in _status(SetupWizard.GUARDRAIL_ACTIONS, config).text
    assert "strict" in _status(SetupWizard.SKILL_SCANNER, config).text
    assert _status(SetupWizard.ACP_GUARD, config).state == "ok"

    config.guardrail.enabled = False
    assert _status(SetupWizard.GUARDRAIL_ACTIONS, config).state == "off"


def test_counted_tasks_count_what_is_configured() -> None:
    cfg = {
        "registries": {
            "sources": [{"id": "a", "enabled": True}, {"id": "b", "enabled": True}, {"id": "c", "enabled": False}]
        },
        "webhooks": [{"url": "https://x", "enabled": True}, {"url": "https://y", "enabled": False}],
        "ai_discovery": {"trusted_binary_prefixes": ["/opt/a", "/opt/b", "/opt/c"]},
    }

    assert _status(SetupWizard.REGISTRIES, cfg).text.startswith("2 ")
    assert _status(SetupWizard.WEBHOOKS, cfg).text.startswith("1 ")
    assert "3" in _status(SetupWizard.TRUSTED_PATHS, cfg).text


def test_credentials_status_comes_from_the_key_snapshot() -> None:
    missing = CredentialSnapshot(
        rows=(
            CredentialRow("OPENAI_API_KEY", requirement="required", set=False),
            CredentialRow("VT_API_KEY", requirement="required", set=False),
            CredentialRow("OTHER", requirement="optional", set=True),
        )
    )
    complete = CredentialSnapshot(rows=(CredentialRow("OPENAI_API_KEY", requirement="required", set=True),))

    assert _status(SetupWizard.CREDENTIALS, None, credentials=missing).state == "attention"
    assert "2" in _status(SetupWizard.CREDENTIALS, None, credentials=missing).text
    assert _status(SetupWizard.CREDENTIALS, None, credentials=complete).state == "ok"
    assert _status(SetupWizard.CREDENTIALS, None, credentials=CredentialSnapshot(error="boom")).state == "attention"
    # Not loaded yet: not set up rather than a false "all good".
    assert _status(SetupWizard.CREDENTIALS, None, credentials=CredentialSnapshot()).state == "off"


def test_telemetry_statuses_come_from_the_canonical_plan() -> None:
    def destination(name, kind="otlp", preset="", enabled=True, generated=False):
        return SimpleNamespace(name=name, kind=kind, preset=preset, enabled=enabled, generated=generated)

    plan = SimpleNamespace(
        destinations=(
            destination("local", kind="sqlite", generated=True),
            destination("o11y", preset="splunk-o11y"),
            destination("hec", kind="splunk_hec"),
            destination("off", enabled=False),
        )
    )

    exported = _status(SetupWizard.OBSERVABILITY, None, observability=plan)
    assert exported.state == "ok" and exported.text == "2 exports + local"
    assert _status(SetupWizard.SPLUNK, None, observability=plan).state == "ok"
    assert _status(SetupWizard.SPLUNK_DASHBOARDS, None, observability=plan).state == "na"
    assert _status(SetupWizard.OBSERVABILITY, None).state == "off"
    assert _status(SetupWizard.OBSERVABILITY, None, observability_error="invalid v8").state == "attention"
    assert _status(SetupWizard.SPLUNK_DASHBOARDS, None).state == "off"


def test_a_task_this_os_cannot_run_is_not_applicable(config) -> None:
    assert _status(SetupWizard.SANDBOX, config, available=False).state == "na"


# --- readiness mapping -------------------------------------------------------


@pytest.mark.parametrize(
    ("check", "owners"),
    [
        ("Connector", {SetupWizard.CONNECTOR_SETUP}),
        ("Gateway / API Health", {SetupWizard.GATEWAY}),
        ("Guardrail", {SetupWizard.GUARDRAIL}),
        ("Required Credentials", {SetupWizard.CREDENTIALS}),
        ("LLM Config", {SetupWizard.LLM}),
        ("Regional Provider", {SetupWizard.LLM}),
        ("Scanner Availability", {SetupWizard.SKILL_SCANNER, SetupWizard.MCP_SCANNER}),
        ("Registry / Asset Policy", {SetupWizard.REGISTRIES}),
        ("Restart Pending", {SetupWizard.GATEWAY}),
    ],
)
def test_a_failing_check_belongs_to_the_task_that_fixes_it(check, owners) -> None:
    readiness = (_check(check),)
    owning = {
        wizard
        for wizard in SetupWizard
        if any(problem.owned for problem in setup_catalog.task_problems(wizard, readiness))
    }

    assert owning == owners
    for wizard in owners:
        assert _status(wizard, None, readiness).state == "attention", wizard


def test_passing_checks_are_not_problems() -> None:
    readiness = (_check("LLM Config", status="pass"), _check("Connector: codex", status="pass"))

    assert all(not setup_catalog.task_problems(wizard, readiness) for wizard in SetupWizard)


def test_a_dependency_problem_shows_on_the_task_that_uses_it(config) -> None:
    config.guardrail.enabled = True
    config.guardrail.detection_strategy = "regex_judge"
    readiness = (_check("LLM Config", fix=("setup", "llm")),)

    problems = setup_catalog.task_problems(SetupWizard.GUARDRAIL, readiness, config)

    assert [problem.owned for problem in problems] == [False]
    assert problems[0].why and problems[0].fix == "defenseclaw setup llm"
    # It is the LLM task's problem; the guardrail itself is fine.
    assert _status(SetupWizard.GUARDRAIL, config, readiness).state == "ok"
    config.guardrail.detection_strategy = "regex_only"
    assert not setup_catalog.task_problems(SetupWizard.GUARDRAIL, readiness, config)


def test_gateway_problems_say_which_one() -> None:
    offline = _status(SetupWizard.GATEWAY, None, (_check("Gateway / API Health", status="fail"),))
    queued = _status(SetupWizard.GATEWAY, None, (_check("Restart Pending"),))

    assert offline.state == queued.state == "attention"
    assert offline.text != queued.text


# --- nav, table and detail -----------------------------------------------------


@pytest.fixture
def model(config):
    return SetupPanelModel(config)


def test_task_nav_lists_groups_with_counts_and_the_config_editor(model) -> None:
    model.active_wizard = SetupWizard.SKILL_SCANNER
    statuses = setup_center.task_statuses(model)
    statuses[SetupWizard.REDACTION] = setup_catalog.TaskStatus("attention", "x")

    items = setup_center.task_nav(model, statuses)

    assert [item.label for item in items[:-1]] == list(setup_catalog.GROUP_TITLES)
    assert items[-1].key == setup_center.NAV_CONFIG
    assert [item.label for item in items if item.active] == ["Guardrail & scanning"]
    guardrail = items[1]
    assert guardrail.badge.startswith(str(len(setup_catalog.group_tasks(guardrail.label))))
    assert "!" in guardrail.badge
    for item, group in zip(items, setup_catalog.GROUP_TITLES, strict=False):
        attention = any(statuses[w].state == "attention" for w in setup_catalog.group_tasks(group))
        assert ("!" in item.badge) == attention


def test_task_rows_are_the_selected_groups_tasks(model) -> None:
    model.active_wizard = SetupWizard.GATEWAY
    rows = setup_center.task_rows(model, setup_center.task_statuses(model))

    tasks = setup_catalog.group_tasks("Gateway & advanced")
    assert [label for label, _status in rows] == [setup_catalog.wizard_label(w) for w in tasks]
    assert all(status[:1] in setup_catalog.TASK_GLYPHS.values() for _label, status in rows)


def test_a_running_or_failed_run_shows_in_the_status_cell(model) -> None:
    statuses = setup_center.task_statuses(model)
    model.wizard_status[SetupWizard.LLM] = "failed"
    model.wizard_status[SetupWizard.GATEWAY] = "running..."

    assert setup_center.status_cell(model, SetupWizard.LLM, statuses[SetupWizard.LLM]).startswith("!")
    assert "running" in setup_center.status_cell(model, SetupWizard.GATEWAY, statuses[SetupWizard.GATEWAY])


def test_header_counts_tasks_by_state() -> None:
    statuses = {
        SetupWizard.LLM: setup_catalog.TaskStatus("ok"),
        SetupWizard.GATEWAY: setup_catalog.TaskStatus("ok"),
        SetupWizard.REDACTION: setup_catalog.TaskStatus("attention"),
        SetupWizard.SPLUNK: setup_catalog.TaskStatus("off"),
    }

    assert setup_center.header_counts(statuses) == (2, 1)


def test_select_nav_switches_group_view_and_section(model) -> None:
    model.active_wizard = SetupWizard.LLM
    assert model.open_goal_menu(SetupWizard.LLM)

    assert setup_center.select_nav(model, "group:Alerts & telemetry")
    assert not model.goal_active and model.mode == "wizards"
    assert model.active_wizard is setup_catalog.group_tasks("Alerts & telemetry")[0]
    # A task already in the chosen group stays selected.
    model.active_wizard = SetupWizard.SPLUNK
    assert setup_center.select_nav(model, "group:Alerts & telemetry")
    assert model.active_wizard is SetupWizard.SPLUNK

    assert setup_center.select_nav(model, setup_center.NAV_CONFIG) and model.mode == "config"
    last = len(model.sections) - 1
    assert setup_center.select_nav(model, f"section:{last}") and model.active_section == last
    assert not setup_center.select_nav(model, f"section:{last + 1}")
    assert setup_center.select_nav(model, setup_center.NAV_TASKS) and model.mode == "wizards"
    assert not setup_center.select_nav(model, "group:No such group")
    assert not setup_center.select_nav(model, "nonsense")


def test_select_nav_never_discards_an_open_form(model) -> None:
    model.open_wizard_form(SetupWizard.CONNECTOR_SETUP)

    assert not setup_center.select_nav(model, "group:Alerts & telemetry")
    assert not setup_center.select_nav(model, setup_center.NAV_CONFIG)
    assert model.form_active


def test_config_nav_groups_sections_and_marks_edits(model) -> None:
    model.mode = "config"
    model.select_section(0)
    field_index = next(i for i, field in enumerate(model.sections[0].fields) if field.kind == "string" and field.key)
    model.active_line = field_index
    assert model.set_current_field_value("edited-value")

    items = setup_center.config_nav(model)

    assert items[0].key == setup_center.NAV_TASKS
    sections = [item for item in items if item.key.startswith("section:")]
    assert len(sections) == len(model.sections)
    assert all(item.group for item in sections)
    active = [item for item in sections if item.active]
    assert [item.key for item in active] == ["section:0"]
    assert "1" in active[0].badge


def test_task_detail_says_what_now_what_to_fix_and_what_it_runs(model) -> None:
    model.active_wizard = SetupWizard.LLM
    model.readiness_checks = (_check("LLM Config", fix=("setup", "llm")),)
    statuses = setup_center.task_statuses(model)

    aside = setup_center.task_aside(model, statuses)
    plain = aside.body.plain

    assert aside.title == setup_catalog.wizard_label(SetupWizard.LLM)
    assert " ".join(WIZARD_DESCRIPTIONS[int(SetupWizard.LLM)].split()) in plain
    assert "defenseclaw setup llm" in plain
    assert all(goal.label in plain for goal in wizard_goals(SetupWizard.LLM, model.config))


def test_task_detail_explains_an_unavailable_task(model) -> None:
    model.os_name = "windows"
    model.active_wizard = SetupWizard.SANDBOX

    plain = setup_center.task_aside(model, setup_center.task_statuses(model)).body.plain

    assert model.wizard_unavailable_reason(SetupWizard.SANDBOX) in plain


def test_config_aside_masks_secrets_and_shows_the_old_value() -> None:
    secret = ConfigField("API Key", "llm.api_key", "password", "sk-live-123456", "sk-old-999999")
    plain_field = ConfigField("Port", "gateway.port", "int", "9999", "18789")
    model = SimpleNamespace(
        current_section=lambda: ConfigSection("Gateway", (secret, plain_field), "Gateway settings."),
        current_field=lambda: secret,
    )

    text = setup_center.config_aside(model).body.plain
    assert "sk-live" not in text and "123456" not in text and "999999" not in text

    model.current_field = lambda: plain_field
    text = setup_center.config_aside(model).body.plain
    assert "9999" in text and "18789" in text

    # A secret pasted into an env-name field is not shown either.
    pasted = ConfigField("API Key Env", "llm.api_key_env", "string", "sk-proj-abcdefghijklmnop123456", "OPENAI_API_KEY")
    model.current_field = lambda: pasted
    text = setup_center.config_aside(model).body.plain
    assert "abcdefghijklmnop" not in text


def test_glyph_style_colours_only_task_states() -> None:
    assert setup_center.glyph_style("✓ on") and setup_center.glyph_style("! 2 missing")
    assert setup_center.glyph_style("active") == ""


def test_rules_only_install_and_gateway_api_port(config) -> None:
    """GAP-1160: a rules-only hook install needs no LLM, and the Gateway task
    shows the sidecar API listener, not the OpenClaw gateway port."""

    from defenseclaw.tui.panels.activity import ActivityEntry
    from defenseclaw.tui.services.setup_state import build_readiness_checks

    config.claw.mode = "claudecode"
    config.guardrail.connector = "claudecode"
    config.guardrail.judge.enabled = False
    config.llm.provider = ""
    config.llm.model = ""
    config.gateway.api_port = 19000
    checks = {check.title: check for check in build_readiness_checks(config, None, None, ())}
    llm = checks["LLM Config"]
    assert llm.status == "pass" and "not required" in llm.detail

    gateway = _status(SetupWizard.GATEWAY, config)
    assert gateway.text.endswith(":19000")

    from datetime import timedelta

    entry = ActivityEntry("defenseclaw setup claude-code --yes", exit_code=0, done=True, duration=timedelta(seconds=13.01))
    assert entry.status_label == "exit 0 (13.0s)"


async def test_config_version_and_restart_banner_after_restart() -> None:
    """GAP-1161: a v8 config shows its version; a successful gateway restart
    clears the queued-restart banner."""

    from defenseclaw.tui.app import DefenseClawTUI
    from defenseclaw.tui.panels.setup import _fmt_config_version

    assert _fmt_config_version(SimpleNamespace(_source_config_version=8)) == "8"
    assert _fmt_config_version(None) == "(unset)"

    app = DefenseClawTUI()
    app.setup_model.queue_restart("config saved from Textual TUI")
    assert app.setup_model.restart_queue.pending
    await app._handle_successful_command("defenseclaw-gateway", ("restart",))  # noqa: SLF001
    assert not app.setup_model.restart_queue.pending
