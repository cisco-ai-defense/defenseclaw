# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Setup slot 13 (the sandbox setup wizard) and the OpenShell config editor section."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner
from defenseclaw import config as dc_config
from defenseclaw.commands import cmd_sandbox
from defenseclaw.context import AppContext
from defenseclaw.tui.panels.setup import (
    ADMIN_POLICY_MESSAGE,
    SetupPanelModel,
    SetupWizard,
    _sandbox_credential_summary,
    build_setup_sections,
    build_wizard_args,
    openshell_admin_locks,
    sandbox_machine_check,
    sandbox_wizard_fields,
    wizard_form_defs,
)
from defenseclaw.tui.services.setup_state import (
    apply_config_field,
    validate_config_field,
)


def _set(fields, label: str, value: str):
    return [field.with_value(value) if field.label == label else field for field in fields]


def _section(cfg):
    return next(section for section in build_setup_sections(cfg) if section.name == "OpenShell Sandboxes")


def _field(cfg, key: str):
    return next(field for field in _section(cfg).fields if field.key == key)


# --- the wizard ----------------------------------------------------------------


def test_defaults_set_up_every_harness_with_mounts_and_telemetry_off() -> None:
    fields = list(wizard_form_defs(SetupWizard.SANDBOX))
    assert build_wizard_args(SetupWizard.SANDBOX, fields) == (
        "sandbox",
        "setup",
        "--non-interactive",
        "--harness",
        "claudecode",
        "--harness",
        "codex",
        "--no-wrappers",
    )


def test_configured_harnesses_seed_the_toggles() -> None:
    fields = sandbox_wizard_fields({"openshell": {"harnesses": ["codex"]}})
    values = {field.label: field.value for field in fields}
    assert values["Claude Code"] == "no" and values["Codex"] == "yes"


@pytest.mark.parametrize(
    ("changes", "expected_tail"),
    [
        ({"Install OpenShell": "yes"}, ("--install-openshell", "--no-wrappers")),
        ({"Mount Project Folder": "no"}, ("--no-mounts", "--no-wrappers")),
        ({"Disable OpenShell Telemetry": "no"}, ("--upstream-telemetry", "--no-wrappers")),
        ({"Shell Wrappers": "yes"}, ("--wrappers",)),
        ({"Build Images Now": "no"}, ("--no-wrappers", "--skip-images")),
    ],
)
def test_each_consent_maps_to_its_flag(changes: dict[str, str], expected_tail: tuple[str, ...]) -> None:
    fields = list(wizard_form_defs(SetupWizard.SANDBOX))
    fields = _set(fields, "Codex", "no")
    for label, value in changes.items():
        fields = _set(fields, label, value)
    args = build_wizard_args(SetupWizard.SANDBOX, fields)
    assert args[:5] == ("sandbox", "setup", "--non-interactive", "--harness", "claudecode")
    assert args[5:] == expected_tail


def test_doctor_action_only_checks_the_machine() -> None:
    fields = _set(list(wizard_form_defs(SetupWizard.SANDBOX)), "Action", "doctor")
    assert build_wizard_args(SetupWizard.SANDBOX, fields) == ("sandbox", "doctor")


def test_every_wizard_argv_parses_with_the_click_stubs(monkeypatch) -> None:
    ran: list[list[str]] = []
    monkeypatch.setattr(cmd_sandbox, "_execv", lambda path, argv: ran.append(argv))
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: "/opt/dc/defenseclaw-gateway")
    monkeypatch.setattr("defenseclaw.platform_support.host_os", lambda: "linux")
    base = list(wizard_form_defs(SetupWizard.SANDBOX))
    variants = [
        base,
        _set(base, "Action", "doctor"),
        _set(_set(_set(base, "Install OpenShell", "yes"), "Shell Wrappers", "yes"), "Build Images Now", "no"),
        _set(_set(base, "Mount Project Folder", "no"), "Disable OpenShell Telemetry", "no"),
    ]
    for fields in variants:
        args = build_wizard_args(SetupWizard.SANDBOX, fields)
        result = CliRunner().invoke(cmd_sandbox.sandbox, list(args[1:]), obj=AppContext())
        assert result.exit_code == 0, (args, result.output)
    assert len(ran) == len(variants)


def test_doctor_hides_the_setup_rows_and_setup_brings_them_back() -> None:
    model = SetupPanelModel({}, os_name="linux")
    model.open_goal_menu(SetupWizard.SANDBOX)
    model.form_fields = _set(model.form_fields, "Codex", "no")
    model.form_fields = _set(model.form_fields, "Action", "doctor")
    model.recompute_dependent_fields()
    assert [field.label for field in model.form_fields] == ["Action"]
    assert model.wizard_command_preview() == "defenseclaw sandbox doctor"
    model.form_fields = _set(model.form_fields, "Action", "setup")
    model.recompute_dependent_fields()
    labels = [field.label for field in model.form_fields]
    assert "Claude Code" in labels and "Build Images Now" in labels
    assert model.wizard_command_preview().startswith("defenseclaw sandbox setup --non-interactive")


def test_a_harness_is_required() -> None:
    model = SetupPanelModel({}, os_name="linux")
    model.open_goal_menu(SetupWizard.SANDBOX)
    model.form_fields = _set(_set(model.form_fields, "Claude Code", "no"), "Codex", "no")
    action = model.submit_wizard_form()
    assert action.intent is None
    assert "a harness" in model.form_error


def test_setup_runs_in_the_terminal_and_doctor_does_not() -> None:
    model = SetupPanelModel({}, os_name="darwin")
    model.open_goal_menu(SetupWizard.SANDBOX)
    assert model.form_active
    action = model.submit_wizard_form()
    assert action.intent is not None
    assert action.intent.terminal is True and action.intent.risk == "setup"
    assert action.intent.args[:2] == ("sandbox", "setup")

    model.open_goal_menu(SetupWizard.SANDBOX)
    model.form_fields = _set(model.form_fields, "Action", "doctor")
    doctor = model.submit_wizard_form()
    assert doctor.intent is not None and doctor.intent.terminal is False
    assert doctor.intent.category == "info" and action.intent.category == "setup"
    assert doctor.intent.args == ("sandbox", "doctor")


def test_either_action_clears_the_running_badge() -> None:
    model = SetupPanelModel({}, os_name="linux")
    for args in (("sandbox", "setup", "--non-interactive"), ("sandbox", "doctor")):
        model.wizard_status[SetupWizard.SANDBOX] = "running..."
        model.mark_wizard_complete(args, success=True)
        assert model.wizard_status[SetupWizard.SANDBOX] == "done", args


def test_other_sandbox_commands_never_mark_the_wizard() -> None:
    model = SetupPanelModel({}, os_name="linux")
    for args in (("sandbox", "enable", "claude"), ("sandbox", "doctor")):
        model.mark_wizard_complete(args, success=True)
        assert SetupWizard.SANDBOX not in model.wizard_status, args


# ``defenseclaw-gateway sandbox doctor --json`` on a machine without OpenShell.
NO_OPENSHELL = {
    "ok": False,
    "docker_version": "29.4.0",
    "checks": [
        {"id": "platform", "title": "Platform", "status": "pass", "detail": "linux/arm64"},
        {"id": "landlock", "title": "Landlock", "status": "pass", "detail": "ABI 6"},
        {"id": "docker", "title": "Docker", "status": "pass", "detail": "29.4.0"},
        {"id": "openshell-cli", "title": "OpenShell CLI", "status": "fail", "detail": "openshell is not on PATH"},
        {"id": "bind-mounts", "title": "Project bind mounts", "status": "fail", "detail": "disabled in gateway.toml"},
    ],
}
READY = {
    "ok": True,
    "docker_version": "29.4.0",
    "cli_version": "0.1.1",
    "checks": [
        {"id": "docker", "title": "Docker", "status": "pass", "detail": "29.4.0"},
        {"id": "landlock", "title": "Landlock", "status": "skip", "detail": "enforced by the Docker Desktop VM kernel"},
        {"id": "openshell-cli", "title": "OpenShell CLI", "status": "pass", "detail": "0.1.1 at /usr/bin/openshell"},
        {"id": "gateway-service", "title": "Gateway service", "status": "pass", "detail": "running"},
        {"id": "bind-mounts", "title": "Project bind mounts", "status": "pass", "detail": "enabled"},
    ],
}


def _row(model: SetupPanelModel, label: str):
    return next(field for field in model.form_fields if field.label == label)


def test_the_form_says_it_is_checking_the_machine_until_the_doctor_answers() -> None:
    model = SetupPanelModel({}, os_name="linux")
    model.open_goal_menu(SetupWizard.SANDBOX)
    assert model.sandbox_machine_wanted()
    assert _row(model, "This machine").value.startswith("Checking this machine")
    assert _row(model, "Install OpenShell").value == "no"


def test_a_missing_openshell_presets_the_install_and_says_why() -> None:
    model = SetupPanelModel({}, os_name="linux")
    model.open_goal_menu(SetupWizard.SANDBOX)
    model.apply_sandbox_machine_check(sandbox_machine_check(NO_OPENSHELL))
    assert not model.sandbox_machine_wanted()
    machine = _row(model, "This machine").value
    assert machine == "✓ Docker 29.4.0 · ✓ Landlock ABI 6 · ✗ OpenShell not installed · ✗ bind mounts off"
    install = _row(model, "Install OpenShell")
    assert install.value == "yes"
    assert install.hint.startswith("OpenShell is not installed: yes installs OpenShell 0.1.1")
    assert "--install-openshell" in model.wizard_command_preview()

    # The operator's own answer survives a later check and an Action rebuild.
    model.form_fields = _set(model.form_fields, "Install OpenShell", "no")
    model.apply_sandbox_machine_check(sandbox_machine_check(NO_OPENSHELL))
    model.recompute_dependent_fields()
    assert _row(model, "Install OpenShell").value == "no"
    # Reopening the wizard starts from the check again.
    model.close_wizard_form()
    model.open_goal_menu(SetupWizard.SANDBOX)
    assert _row(model, "Install OpenShell").value == "yes"


def test_an_installed_openshell_needs_no_install() -> None:
    check = sandbox_machine_check(READY)
    assert check.summary == "✓ Docker 29.4.0 · ✓ OpenShell 0.1.1 · ✓ bind mounts"
    assert check.openshell_needed is False
    fields = sandbox_wizard_fields({}, machine=check)
    install = next(field for field in fields if field.label == "Install OpenShell")
    assert install.value == "no" and install.hint == "OpenShell 0.1.1 is installed; nothing to install."


def test_a_stopped_gateway_or_a_failed_doctor() -> None:
    service = {"id": "gateway-service", "status": "fail", "detail": "inactive"}
    stopped = {**READY, "checks": [*READY["checks"][:3], service]}
    check = sandbox_machine_check(stopped)
    assert check.openshell_needed and "✗ OpenShell gateway not running" in check.summary
    failed = sandbox_machine_check(None, "'defenseclaw-gateway sandbox doctor' did not finish within 90s")
    assert failed.summary.startswith("not checked: ") and failed.error
    install = next(f for f in sandbox_wizard_fields({}, machine=failed) if f.label == "Install OpenShell")
    assert install.value == "no" and install.hint.startswith("Could not check this machine")


def test_the_answers_are_the_consent() -> None:
    machine = next(field for field in sandbox_wizard_fields({}) if field.label == "This machine")
    assert "Your answers here are the consent" in machine.hint
    assert "asks for your consent" not in machine.hint


def test_harnesses_follow_the_organization_allowlist() -> None:
    cfg = {"openshell": {"admin": {"allowed_harnesses": ["codex"]}}}
    fields = list(wizard_form_defs(SetupWizard.SANDBOX, cfg))
    labels = [field.label for field in fields]
    assert "Codex" in labels and "Claude Code" not in labels
    assert "--harness claudecode" not in " ".join(build_wizard_args(SetupWizard.SANDBOX, fields))
    assert "allows: codex" in next(field for field in fields if field.label == "Harnesses").hint

    model = SetupPanelModel({"openshell": {"admin": {"allowed_harnesses": ["geminicli"]}}}, os_name="linux")
    model.open_goal_menu(SetupWizard.SANDBOX)
    assert ADMIN_POLICY_MESSAGE in _row(model, "Harnesses").value
    assert model.submit_wizard_form().intent is None
    assert ADMIN_POLICY_MESSAGE in model.form_error


@pytest.mark.asyncio
async def test_opening_the_wizard_checks_the_machine_once(monkeypatch) -> None:
    from defenseclaw.tui import sandbox_panel
    from defenseclaw.tui.app import DefenseClawTUI
    from defenseclaw.tui.panels.setup import SetupPanelAction

    probes: list[int] = []

    def probe():
        probes.append(1)
        return sandbox_machine_check(NO_OPENSHELL)

    monkeypatch.setattr(sandbox_panel, "probe_sandbox_machine", probe)
    app = DefenseClawTUI(config=None)
    async with app.run_test(size=(120, 40)) as pilot:
        app.setup_model.open_goal_menu(SetupWizard.SANDBOX)
        app._apply_setup_action(SetupPanelAction(True))  # noqa: SLF001
        app._apply_setup_action(SetupPanelAction(True))  # noqa: SLF001 - no second probe while one runs
        for _ in range(20):
            await pilot.pause()
            if app.setup_model.sandbox_machine is not None:
                break
        assert app.setup_model.sandbox_machine is not None
        assert _row(app.setup_model, "Install OpenShell").value == "yes"
        app._apply_setup_action(SetupPanelAction(True))  # noqa: SLF001 - answered: no new probe
        await pilot.pause()
    assert probes == [1]


def test_credential_summary_names_sources_never_values(tmp_path: Path) -> None:
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "auth.json").write_text("{}", encoding="utf-8")
    summary = _sandbox_credential_summary({"ANTHROPIC_API_KEY": "sk-ant-secret-value"}, str(tmp_path))
    assert "ANTHROPIC_API_KEY found" in summary and "~/.codex/auth.json found" in summary
    assert "sk-ant-secret-value" not in summary
    none = _sandbox_credential_summary({}, str(tmp_path / "nothing"))
    assert none.count("none found") == 2


# --- the config editor ----------------------------------------------------------


def test_admin_constraints_make_their_keys_read_only_with_the_reason() -> None:
    cfg = {
        "openshell": {
            "profile": "strict",
            "admin": {
                "required_pack": "balanced",
                "allow_yolo": False,
                "allow_mount": False,
                "allow_host_ports": False,
                "allow_unblock": False,
                "locked": ["resources", "mcp.import"],
            },
        }
    }
    locks = openshell_admin_locks(cfg)
    assert locks["openshell.pack"] == "your organization requires the balanced pack"
    assert locks["openshell.yolo"] == "skip-permissions mode is not allowed"
    assert locks["openshell.workdir.mode"] == "your organization requires copy mode"
    assert locks["openshell.mcp.host_ports"] == "opening host ports is not allowed"
    assert locks["openshell.egress.unblocked"] == "unblocking and allow entries are not allowed"
    assert "openshell.admin.locked: resources" in locks["openshell.resources.memory"]
    assert "openshell.admin.locked: mcp.import" in locks["openshell.mcp.import"]
    assert "openshell.profile" not in locks

    pack = _field(cfg, "openshell.pack")
    assert pack.interactive is False
    # A short value that fits the column; the reason is the row's hint.
    assert pack.value == "(unset) (locked)"
    assert pack.hint == (
        "Read-only: blocked by your organization's DefenseClaw policy; your organization requires the balanced pack."
    )
    # The admin switches clamp these: the row shows the value that takes effect.
    assert _field(cfg, "openshell.yolo").value == "inherit → off by policy"
    assert _field(cfg, "openshell.workdir.mode").value == "inherit → copy by policy"
    assert _field({**cfg, "openshell": {**cfg["openshell"], "yolo": False}}, "openshell.yolo").value == (
        "false (locked)"
    )
    assert _field(cfg, "openshell.profile").interactive is True
    policy = _field(cfg, "openshell.admin")
    assert "required_pack=balanced" in policy.value and "allow_unblock=false" in policy.value


def test_a_locked_row_says_why_when_focused_or_edited() -> None:
    from defenseclaw.tui.app import DefenseClawTUI

    cfg = {"openshell": {"admin": {"required_pack": "balanced", "allow_yolo": False}}}
    app = DefenseClawTUI(config=None)
    app.setup_model = SetupPanelModel(cfg, os_name="linux")
    model = app.setup_model
    model.mode = "config"
    model.active_section = next(i for i, section in enumerate(model.sections) if section.name == "OpenShell Sandboxes")
    fields = model.sections[model.active_section].fields
    model.active_line = next(i for i, field in enumerate(fields) if field.key == "openshell.yolo")
    reason = "Read-only: blocked by your organization's DefenseClaw policy; skip-permissions mode is not allowed."
    assert model.focused_row_metadata().hint == reason
    assert model.focused_row_action().description == reason
    for key in ("enter", "space", "x"):
        action = app._handle_setup_config_key(key)  # noqa: SLF001
        assert action.hint == reason, key
    assert model.current_field().value == "inherit → off by policy"
    assert not model.has_changes()


def test_managed_enterprise_makes_the_whole_section_read_only() -> None:
    section = _section({"deployment_mode": "managed_enterprise", "openshell": {"enabled": True}})
    assert all(not field.interactive for field in section.fields)
    assert "Administrator-owned" in section.summary


def test_min_profile_limits_the_profile_choices() -> None:
    field = _field({"openshell": {"admin": {"min_profile": "balanced"}}}, "openshell.profile")
    assert field.options == ("inherit", "balanced", "strict")
    assert "at least balanced" in field.hint


def test_pack_governed_keys_show_inherit_until_set() -> None:
    cfg = dc_config.Config()
    assert _field(cfg, "openshell.yolo").value == "inherit"
    assert _field(cfg, "openshell.mcp.import").value == "inherit"
    cfg.openshell.mcp.import_ = False
    assert _field(cfg, "openshell.mcp.import").value == "false"
    assert _field(cfg, "openshell.wrappers").interactive is False


def test_edits_are_written_with_the_go_types() -> None:
    cfg = dc_config.Config()
    for key, value in (
        ("openshell.enabled", "true"),
        ("openshell.yolo", "false"),
        ("openshell.mcp.import", "true"),
        ("openshell.approvals.agent_proposals", "inherit"),
        ("openshell.profile", "inherit"),
        ("openshell.workdir.mode", "copy"),
        ("openshell.egress.ports", "80, 443"),
        ("openshell.mcp.host_ports", "5432"),
        ("openshell.egress.block", "paste.example, webhook.example"),
        ("openshell.ingress_port", "0"),
        ("openshell.approvals.debounce_ms", "1500"),
        ("openshell.wrappers", "claudecode"),
    ):
        apply_config_field(cfg, key, value)
    o = cfg.openshell
    assert o.enabled is True and o.yolo is False and o.mcp.import_ is True
    assert o.approvals.agent_proposals is None
    assert o.profile == "" and o.workdir.mode == "copy"
    assert o.egress.ports == [80, 443] and o.mcp.host_ports == [5432]
    assert o.egress.block == ["paste.example", "webhook.example"]
    assert o.ingress_port == 0 and o.approvals.debounce_ms == 1500
    assert o.wrappers == []  # written only by sandbox enable/disable


@pytest.mark.parametrize(
    ("key", "kind", "value", "ok"),
    [
        ("openshell.ingress_port", "int", "0", True),
        ("openshell.ingress_port", "int", "18971", True),
        ("openshell.egress_port", "int", "70000", False),
        ("openshell.egress.ports", "string", "80,443", True),
        ("openshell.egress.ports", "string", "80,http", False),
        ("openshell.mcp.host_ports", "string", "0", False),
        ("openshell.resources.cpu", "string", "500m", True),
        ("openshell.resources.cpu", "string", "lots", False),
        ("openshell.resources.memory", "string", "4Gi", True),
        ("openshell.resources.memory", "string", "4 gigs", False),
        ("openshell.harnesses", "string", "claudecode,codex", True),
        ("openshell.harnesses", "string", "geminicli", False),
        ("openshell.workdir.git_depth", "int", "-1", False),
    ],
)
def test_openshell_validation(key: str, kind: str, value: str, ok: bool) -> None:
    from defenseclaw.tui.services.setup_state import ConfigField

    result = validate_config_field(ConfigField(label=key, key=key, kind=kind, value=value, original=""))
    assert (result.severity != "error") is ok, result


@pytest.mark.parametrize(
    ("sequence", "expected"),
    [("\x12", "ctrl+r"), ("\x14", "ctrl+t"), ("\x15", "ctrl+u"), ("\t", "tab"), ("\x7f", "backspace"), ("A", "A")],
)
def test_terminal_control_keys_reach_the_setup_form_by_name(
    sequence: str, expected: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real terminal sends Ctrl+R as "\\x12"; the wizard form's Ctrl+R run
    (and Ctrl+T reveal, Ctrl+U clear) match the key name."""
    from defenseclaw.tui.app import _panel_key
    from textual._xterm_parser import XTermParser

    monkeypatch.chdir(tmp_path)
    # A debug parser appends every key to ./keys.log.
    events = list(XTermParser(debug=False).feed(sequence))
    assert len(events) == 1
    assert _panel_key(events[0]) == expected
    assert not (tmp_path / "keys.log").exists()
