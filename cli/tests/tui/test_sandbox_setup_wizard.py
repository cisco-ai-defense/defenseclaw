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


@pytest.fixture(autouse=True)
def _linux_host(monkeypatch):
    # The wizard's fields depend on the host (no telemetry question on macOS);
    # pin Linux unless a test names the platform.
    monkeypatch.setattr("defenseclaw.tui.panels.setup.host_os", lambda: "linux")


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


def test_macos_has_no_telemetry_question() -> None:
    # The Homebrew gateway does not read gateway.env, so the answer would do nothing.
    fields = list(sandbox_wizard_fields(os_name="darwin"))
    assert "Disable OpenShell Telemetry" not in {field.label for field in fields}
    assert "--upstream-telemetry" not in build_wizard_args(SetupWizard.SANDBOX, fields)
    assert "Disable OpenShell Telemetry" in {field.label for field in sandbox_wizard_fields(os_name="linux")}


def test_macos_has_no_mounts_question_and_says_every_run_works_on_a_copy() -> None:
    # Setup on macOS runs sandboxes in OpenShell MicroVMs, which mount no host folders.
    fields = list(sandbox_wizard_fields(os_name="darwin"))
    labels = [field.label for field in fields]
    assert "Mount Project Folder" not in labels
    microvm = next(field for field in fields if field.label == "MicroVMs")
    assert microvm.kind == "section" and microvm.value == "every run works on a copy"
    assert 'compute_driver = "vm"' in microvm.hint and "defenseclaw sandbox pull" in microvm.hint
    args = build_wizard_args(SetupWizard.SANDBOX, fields)
    assert "--no-mounts" not in args
    harnesses = ("--harness", "claudecode", "--harness", "codex")
    assert args == ("sandbox", "setup", "--non-interactive", *harnesses, "--no-wrappers")
    linux = [field.label for field in sandbox_wizard_fields(os_name="linux")]
    assert "Mount Project Folder" in linux and "MicroVMs" not in linux


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


def test_a_cancelled_run_is_not_a_failure() -> None:
    """A cancelled preview or run puts back the row's status, not "failed"."""
    from defenseclaw.tui.panels.setup_center import status_cell, task_statuses

    model = SetupPanelModel({}, os_name="linux")
    model.wizard_status[SetupWizard.SANDBOX] = "running..."
    model.mark_wizard_complete(("sandbox", "setup", "--non-interactive"), success=False, cancelled=True)
    assert SetupWizard.SANDBOX not in model.wizard_status
    assert status_cell(model, SetupWizard.SANDBOX, task_statuses(model)[SetupWizard.SANDBOX]) != "! last run failed"
    _run_doctor(model)
    before = model.wizard_status[SetupWizard.SANDBOX]
    model.wizard_status[SetupWizard.SANDBOX] = "running..."
    model._status_before_check[SetupWizard.SANDBOX] = before
    model.mark_wizard_complete(("sandbox", "doctor"), success=False, cancelled=True)
    assert model.wizard_status[SetupWizard.SANDBOX] == before


def test_cancelling_a_rerun_keeps_the_earlier_result() -> None:
    model = SetupPanelModel({}, os_name="linux")
    model.wizard_status[SetupWizard.SANDBOX] = "done"
    model.open_goal_menu(SetupWizard.SANDBOX)
    action = model.submit_wizard_form()
    assert model.wizard_status[SetupWizard.SANDBOX] == "running..."
    model.mark_wizard_complete(action.intent.args, success=False, cancelled=True)
    assert model.wizard_status[SetupWizard.SANDBOX] == "done"
    # A finished run drops the saved status, so a later cancel can't bring it back.
    model.open_goal_menu(SetupWizard.SANDBOX)
    action = model.submit_wizard_form()
    model.mark_wizard_complete(action.intent.args, success=False)
    assert model.wizard_status[SetupWizard.SANDBOX] == "failed"
    assert SetupWizard.SANDBOX not in model._status_before_check


def _run_doctor(model: SetupPanelModel, *, success: bool = True):
    model.open_goal_menu(SetupWizard.SANDBOX)
    model.form_fields = _set(model.form_fields, "Action", "doctor")
    model.recompute_dependent_fields()
    action = model.submit_wizard_form()
    assert model.wizard_status[SetupWizard.SANDBOX] == "running..."
    model.mark_wizard_complete(action.intent.args, success=success)
    return action


def test_doctor_is_named_doctor_and_never_marks_setup_done() -> None:
    """R2-59: the doctor action only checks; its toast says doctor and the status stays."""
    model = SetupPanelModel({}, os_name="linux")
    action = _run_doctor(model)
    # The toast is "<label> finished"; suggested_next_action keys off it too.
    assert action.intent.label == "sandbox doctor"
    assert model.wizard_status[SetupWizard.SANDBOX] == "checked"
    _run_doctor(model, success=False)
    assert model.wizard_status[SetupWizard.SANDBOX] == "check failed"
    model.wizard_status[SetupWizard.SANDBOX] = "done"  # setup ran earlier
    _run_doctor(model)
    assert model.wizard_status[SetupWizard.SANDBOX] == "done"
    model.open_goal_menu(SetupWizard.SANDBOX)
    setup = model.submit_wizard_form()
    assert setup.intent.label == "setup Sandbox"


HARNESS_LABELS = (
    "Claude Code", "Codex", "Amp", "Antigravity", "GitHub Copilot CLI", "Cursor Agent",
    "Devin CLI", "Hermes Agent", "Kiro CLI", "OmniGent", "OpenCode", "OpenHands",
)  # fmt: skip


def _harness_toggles(cfg) -> list[tuple[str, str]]:
    return [(field.label, field.value) for field in sandbox_wizard_fields(cfg) if field.label in HARNESS_LABELS]


def test_every_harness_is_offered_and_setups_defaults_are_on() -> None:
    """R2-59: setup offers every harness (harness.Names()), not only Claude Code and Codex."""
    toggles = _harness_toggles({})
    assert [label for label, _value in toggles] == list(HARNESS_LABELS)
    # sandboxcli.defaultHarnesses: only these are on when nothing is configured.
    assert [label for label, value in toggles if value == "yes"] == ["Claude Code", "Codex"]
    fields = _set(_set(list(sandbox_wizard_fields({})), "OpenCode", "yes"), "Codex", "no")
    assert build_wizard_args(SetupWizard.SANDBOX, fields)[3:7] == ("--harness", "claudecode", "--harness", "opencode")
    # Configured ones are on; an organization allowlist limits the choice.
    assert [label for label, value in _harness_toggles({"openshell": {"harnesses": ["hermes"]}}) if value == "yes"] == [
        "Hermes Agent"
    ]
    admin = {"openshell": {"admin": {"allowed_harnesses": ["opencode"]}}}
    assert _harness_toggles(admin) == [("OpenCode", "yes")]


def test_gateway_changes_warn_that_they_restart_the_gateway() -> None:
    hints = {field.label: field.hint for field in sandbox_wizard_fields({}, os_name="linux")}
    for label in ("Disable OpenShell Telemetry", "Mount Project Folder"):
        assert "restarts the OpenShell gateway" in hints[label], label
        assert "drops the connections of every running sandbox" in hints[label], label


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
    assert machine.split("\n") == [
        "✓ Docker 29.4.0",
        "✓ Landlock ABI 6",
        "✗ OpenShell not installed",
        "✗ bind mounts off",
    ]
    install = _row(model, "Install OpenShell")
    assert install.value == "yes"
    assert install.hint.startswith("OpenShell is not installed: yes installs OpenShell 0.1.1")
    assert "--install-openshell" in model.wizard_command_preview()

    # The operator's own answer survives a later check and an Action rebuild.
    model.form_fields = _set(model.form_fields, "Install OpenShell", "no")
    model.apply_sandbox_machine_check(sandbox_machine_check(NO_OPENSHELL))
    model.recompute_dependent_fields()
    assert _row(model, "Install OpenShell").value == "no"
    # Setup may have changed the machine: reopening the wizard checks it again.
    model.close_wizard_form()
    model.open_goal_menu(SetupWizard.SANDBOX)
    assert model.sandbox_machine_wanted()
    assert _row(model, "This machine").value.startswith("Checking this machine")


def test_an_installed_openshell_needs_no_install() -> None:
    check = sandbox_machine_check(READY)
    assert check.summary.split("\n") == ["✓ Docker 29.4.0", "✓ OpenShell 0.1.1", "✓ bind mounts"]
    assert check.openshell_needed is False
    fields = sandbox_wizard_fields({}, machine=check)
    install = next(field for field in fields if field.label == "Install OpenShell")
    assert install.value == "no" and install.hint == "OpenShell 0.1.1 is installed; nothing to install."


@pytest.mark.parametrize(
    ("os_name", "says", "never"),
    [("linux", "uses sudo", "Homebrew"), ("darwin", "nvidia/openshell Homebrew formula", "uses sudo")],
)
def test_the_install_hint_says_how_openshell_is_installed(os_name: str, says: str, never: str) -> None:
    # On macOS NVIDIA's installer installs a Homebrew formula, without sudo.
    for machine in (None, sandbox_machine_check(NO_OPENSHELL)):
        fields = sandbox_wizard_fields({}, machine=machine, os_name=os_name)
        hint = next(field for field in fields if field.label == "Install OpenShell").hint
        assert says in hint and never not in hint, hint


# The doctor's Gateway fix for the gateway of an OpenShell installed another
# way that does not answer (openshell doctor.go unmanagedFix).
UNMANAGED_DOWN_FIX = {
    "summary": "start that OpenShell's gateway yourself, the way you started it before. DefenseClaw starts and restarts "
    "the gateway only through Homebrew's nvidia/openshell/openshell service, and the OpenShell 0.1.1 at "
    "/Users/dev/openshell-direct/prefix/bin/openshell was installed another way",
    "command": "defenseclaw sandbox setup --install-openshell",
}


def _unmanaged(manager: str, cli: str, service_status: str, service_detail: str, gateway: str) -> dict:
    """READY on an OpenShell whose gateway no gateway service runs; gateway is its Gateway check's status."""
    version = {"id": "gateway-version", "status": gateway, "detail": "0.1.1 healthy at https://127.0.0.1:17670"}
    if gateway == "fail":
        version = {**version, "detail": "the gateway is not answering: connection refused", "fix": UNMANAGED_DOWN_FIX}
    unit = "openshell-gateway" if manager == "systemd" else "nvidia/openshell/openshell"
    return {
        **READY,
        "cli_path": cli,
        "checks": [
            *READY["checks"][:2],
            {"id": "openshell-cli", "title": "OpenShell CLI", "status": "pass", "detail": f"0.1.1 at {cli}"},
            {"id": "gateway-service", "status": service_status, "detail": service_detail},
            version,
        ],
        "service": {"manager": manager, "unit": unit, "installed": False},
    }


def test_an_openshell_outside_the_homebrew_formula_is_used_while_its_gateway_answers() -> None:
    # RT U1: the doctor said "✓ ready for sandboxes" on a Mac whose gateway
    # was started by hand, while setup refused that OpenShell up front
    # ("✗ … is not from Homebrew's nvidia/openshell formula"). Setup uses the
    # gateway that answers (sandboxcli/setup.go), and the wizard says what
    # DefenseClaw will not do with it.
    cli = "/Users/dev/openshell-direct/prefix/bin/openshell"
    by_hand = (
        "…/openshell-gateway (process 4666) was started by hand, not Homebrew's nvidia/openshell/openshell service"
    )
    check = sandbox_machine_check(_unmanaged("brew", cli, "warn", by_hand, "pass"))
    assert check.openshell_unmanaged and not check.openshell_needed and check.openshell_attention == ""
    assert "⚠ OpenShell 0.1.1 is not from Homebrew's nvidia/openshell formula" in check.summary.split("\n")
    install = _install_field(check, "darwin")
    assert install.value == "no"
    assert install.hint.startswith(
        f"OpenShell 0.1.1 at {cli} was installed another way than the nvidia/openshell/openshell Homebrew formula, "
        "whose service DefenseClaw starts and restarts the gateway through: setup uses its gateway as it runs, but "
        "DefenseClaw cannot start or restart it; after a gateway change, restart it yourself, the way you started it; "
        "nothing to install."
    ), install.hint
    # Setup goes on to e2fsprogs; the MicroVM switch is the user's restart.
    assert "e2fsprogs" in install.hint
    micro = next(f for f in sandbox_wizard_fields({}, machine=check, os_name="darwin") if f.label == "MicroVMs")
    assert "you restart the gateway yourself" in micro.hint and "restarts it once" not in micro.hint

    # With its gateway down setup stops where it would have to start it,
    # with the doctor's fix, before e2fsprogs.
    down = sandbox_machine_check(_unmanaged("brew", cli, "fail", "nvidia/openshell/openshell is not installed", "fail"))
    assert down.openshell_unmanaged and not down.openshell_needed and down.openshell_attention == "gateway-version"
    assert down.summary.split("\n")[-2:] == [
        "⚠ OpenShell 0.1.1 is not from Homebrew's nvidia/openshell formula",
        "✗ OpenShell gateway not running",
    ]
    install = _install_field(down, "darwin")
    assert install.value == "no" and install.hint == (
        f"the OpenShell gateway needs attention: {UNMANAGED_DOWN_FIX['summary']} "
        f"(`{UNMANAGED_DOWN_FIX['command']}`); installing OpenShell would change nothing."
    )
    # The formula's own service, stopped, is started through it.
    formula = {**_unmanaged("brew", cli, "fail", "stopped", "fail"), "service": {"manager": "brew", "installed": True}}
    assert sandbox_machine_check(formula).openshell_unmanaged is False


@pytest.mark.parametrize("gateway", ["pass", "fail"])
def test_an_openshell_without_the_linux_user_unit_is_used_while_its_gateway_answers(gateway: str) -> None:
    # A supported CLI from the release binaries, no openshell-gateway unit:
    # the wizard preset "Install OpenShell" to yes, whose
    # `setup --install-openshell` installed nothing; then setup refused it
    # up front even with its gateway run by hand. Setup uses a gateway that
    # answers and writes a gateway change for the user to restart it on;
    # with none answering it stops on the doctor's fix.
    cli = "/home/dev/.local/bin/openshell"
    service = "openshell-gateway is not installed" + (
        "; the gateway that answers runs another way" if gateway == "pass" else ""
    )
    report = _unmanaged("systemd", cli, "warn" if gateway == "pass" else "fail", service, gateway)
    check = sandbox_machine_check(report)
    assert check.openshell_unmanaged and not check.openshell_needed
    lines = check.summary.split("\n")
    assert "⚠ OpenShell 0.1.1 has no openshell-gateway user service" in lines
    model = SetupPanelModel({}, os_name="linux")
    model.open_goal_menu(SetupWizard.SANDBOX)
    model.apply_sandbox_machine_check(check)
    install = _row(model, "Install OpenShell")
    assert install.value == "no", install
    assert "--install-openshell" not in model.wizard_command_preview()
    if gateway == "pass":
        assert check.openshell_attention == "" and "✗ OpenShell gateway not running" not in lines
        assert install.hint == (
            f"OpenShell 0.1.1 at {cli} was installed another way, without the openshell-gateway user service "
            "DefenseClaw starts and restarts the gateway through on Linux: setup uses its gateway as it runs, but "
            "DefenseClaw cannot start or restart it; after a gateway change, restart it yourself, the way you "
            "started it; nothing to install."
        )
        # The mounts and telemetry changes are written, not restarted.
        for label in ("Mount Project Folder", "Disable OpenShell Telemetry"):
            hint = _row(model, label).hint
            assert "you restart it yourself, the way you started it" in hint and "doctor --fix" not in hint, hint
    else:
        assert check.openshell_attention == "gateway-version" and "✗ OpenShell gateway not running" in lines
        assert install.hint.startswith("the OpenShell gateway needs attention: start that OpenShell's gateway yourself")
    # The unit installed and stopped is started through it; without a CLI
    # NVIDIA's installer runs and sets the unit up.
    unit = {**report, "service": {"manager": "systemd", "unit": "openshell-gateway", "installed": True}}
    assert sandbox_machine_check(unit).openshell_unmanaged is False
    assert sandbox_machine_check({**NO_OPENSHELL, "service": report["service"]}).openshell_needed


def test_a_warning_gateway_service_is_shown() -> None:
    service = {"id": "gateway-service", "status": "warn", "detail": "runs but does not start at login"}
    check = sandbox_machine_check({**READY, "checks": [*READY["checks"][:3], service]})
    assert "⚠ OpenShell 0.1.1: runs but does not start at login" in check.summary.split("\n")
    assert not check.openshell_needed and not check.openshell_unmanaged


START = "systemctl --user enable --now openshell-gateway"


def _stopped(**report) -> dict:
    """READY with its openshell-gateway unit installed but stopped."""
    service = {
        "id": "gateway-service",
        "status": "fail",
        "detail": "openshell-gateway is inactive",
        "fix": {"summary": "start the gateway and enable it at login", "command": START, "automatic": True},
    }
    return {
        **READY,
        "service": {"manager": "systemd", "unit": "openshell-gateway", "installed": True},
        "checks": [*READY["checks"][:3], service],
        **report,
    }


@pytest.mark.parametrize("openshell_install", [False, None])
def test_a_stopped_gateway_is_not_an_install(openshell_install) -> None:
    # A supported CLI whose unit is stopped: the wizard preset "Install
    # OpenShell" to yes, whose install found the CLI and installed nothing.
    # Setup offers it only for a CLI missing or one it upgrades
    # (sandboxcli/setup.go); the hint is the doctor's fix. An older doctor
    # reports no openshell_install.
    report = _stopped() if openshell_install is None else _stopped(openshell_install=openshell_install)
    check = sandbox_machine_check(report)
    assert not check.openshell_needed and not check.openshell_unmanaged
    assert check.openshell_attention == "gateway-service"
    assert "✗ OpenShell gateway not running" in check.summary.split("\n")
    model = SetupPanelModel({}, os_name="linux")
    model.open_goal_menu(SetupWizard.SANDBOX)
    model.apply_sandbox_machine_check(check)
    install = _row(model, "Install OpenShell")
    assert install.value == "no"
    assert install.hint == (
        f"the OpenShell gateway needs attention: start the gateway and enable it at login (`{START}`); "
        "installing OpenShell would change nothing."
    )
    assert "--install-openshell" not in model.wizard_command_preview()


def test_a_stopped_service_while_a_gateway_answers() -> None:
    # Something else runs the gateway that answers: it is the service that
    # is stopped, not the gateway.
    check = sandbox_machine_check(_stopped(openshell_install=False, gateway_version="0.1.1"))
    assert "✗ OpenShell gateway service stopped" in check.summary.split("\n")
    assert "✗ OpenShell gateway not running" not in check.summary.split("\n")


def test_the_install_follows_the_doctors_openshell_install() -> None:
    # The Go doctor says when setup's install step runs NVIDIA's installer
    # (DoctorReport.OpenShellInstallNeeded): a CLI newer than supported is
    # not one, whose install would refuse to downgrade it.
    newer = {
        "id": "openshell-cli",
        "status": "fail",
        "detail": "OpenShell 0.2.0 is not supported; DefenseClaw drives >=0.1.1 <0.2.0",
        "fix": {
            "summary": "DefenseClaw's install step does not downgrade OpenShell: remove OpenShell 0.2.0, "
            "then install OpenShell 0.1.1",
            "command": "defenseclaw sandbox setup --install-openshell",
        },
    }
    report = {**READY, "cli_version": "0.2.0", "openshell_install": False, "checks": [READY["checks"][0], newer]}
    check = sandbox_machine_check(report)
    assert not check.openshell_needed and check.openshell_attention == "openshell-cli"
    install = next(
        f for f in sandbox_wizard_fields({}, machine=check, os_name="linux") if f.label == "Install OpenShell"
    )
    assert install.value == "no" and install.hint.startswith(
        "OpenShell needs attention: DefenseClaw's install step does not downgrade OpenShell: remove OpenShell 0.2.0"
    )
    assert sandbox_machine_check({**NO_OPENSHELL, "openshell_install": True}).openshell_needed


def test_a_failed_doctor() -> None:
    failed = sandbox_machine_check(None, "'defenseclaw-gateway sandbox doctor' did not finish within 90s")
    assert failed.summary.startswith("not checked: ") and failed.error
    install = next(f for f in sandbox_wizard_fields({}, machine=failed) if f.label == "Install OpenShell")
    assert install.value == "no" and install.hint.startswith("Could not check this machine")


def test_a_gateway_of_another_release_than_the_cli_is_not_an_install() -> None:
    # A supported CLI and a gateway answering 0.0.40: the wizard preset
    # "Install OpenShell" to yes, whose install found the CLI and installed
    # nothing. Setup no longer offers it (sandboxcli/setup.go); the hint is
    # the doctor's fix.
    restart = (
        "the gateway that answers runs OpenShell 0.0.40, not the OpenShell 0.1.1 installed here, so installing "
        "OpenShell would change nothing: restart the openshell-gateway user service so it runs the gateway "
        "installed with the CLI"
    )
    version = {
        "id": "gateway-version",
        "status": "fail",
        "detail": "OpenShell 0.0.40 is older than 0.1.1; upgrade it in place to 0.1.1",
        "fix": {"summary": restart, "command": "systemctl --user restart openshell-gateway", "automatic": True},
    }
    check = sandbox_machine_check({**READY, "gateway_version": "0.0.40", "checks": [*READY["checks"], version]})
    assert not check.openshell_needed and not check.openshell_unmanaged
    assert "✗ OpenShell 0.1.1, but the gateway runs 0.0.40" in check.summary.split("\n")
    install = next(
        f for f in sandbox_wizard_fields({}, machine=check, os_name="linux") if f.label == "Install OpenShell"
    )
    assert install.value == "no"
    hint = (
        f"the OpenShell gateway needs attention: {restart} "
        "(`systemctl --user restart openshell-gateway`); installing OpenShell would change nothing."
    )
    assert install.hint == hint

    # On a Mac whose MicroVM driver also fails, the gateway's fix stays the
    # hint, with the install off: setup stops on it before e2fsprogs. The
    # driver's failure had turned the install on and hidden the fix.
    mac = {
        **MAC_MICROVM,
        "gateway_version": "0.0.40",
        "checks": [
            *MAC_MICROVM["checks"],
            {**version, "fix": {**version["fix"], "command": "brew services restart nvidia/openshell/openshell"}},
        ],
    }
    check = sandbox_machine_check(mac)
    assert not check.openshell_needed and check.openshell_attention == "gateway-version"
    assert "✗ MicroVM driver: e2fsprogs is not installed" in check.summary.split("\n")
    install = _install_field(check, "darwin")
    assert install.value == "no"
    assert install.hint == hint.replace(
        "systemctl --user restart openshell-gateway", "brew services restart nvidia/openshell/openshell"
    )


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

    model = SetupPanelModel({"openshell": {"admin": {"allowed_harnesses": ["openclaw"]}}}, os_name="linux")
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
    # Pin Linux: on Windows the wizard does not open, so there is no probe.
    app = DefenseClawTUI(config=None, setup_model=SetupPanelModel(None, os_name="linux"))
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


# The doctor on a Mac whose gateway runs the docker driver on Docker
# Desktop, whose VM kernel has no Landlock, as the Go doctor reports it: it
# names the driver, and checks what a switch to MicroVMs needs (here
# e2fsprogs is missing, a reason too long for one line at 80 columns).
MAC_DOCKER_DESKTOP = {
    "ok": False,
    "docker_version": "29.1.5",
    "cli_version": "0.1.1",
    "driver": "docker",
    "configured_driver": "docker",
    "checks": [
        {"id": "platform", "title": "Platform", "status": "warn", "detail": "darwin/arm64: macOS sandboxes run in OpenShell MicroVMs"},
        {"id": "docker", "title": "Docker", "status": "pass", "detail": "Docker 29.1.5 (Docker Desktop)"},
        {"id": "landlock", "title": "Landlock", "status": "fail", "detail": "the Docker Desktop VM kernel has no Landlock"},
        {
            "id": "vm-driver",
            "title": "MicroVM driver",
            "status": "fail",
            "detail": "e2fsprogs is not installed where the MicroVM driver looks for it, Homebrew's keg "
            "(opt/e2fsprogs under /opt/homebrew or /usr/local): the driver formats every MicroVM's disks with its mke2fs and debugfs",
        },
        {"id": "openshell-cli", "title": "OpenShell CLI", "status": "pass", "detail": "0.1.1 at /opt/homebrew/bin/openshell"},
        {"id": "gateway-service", "title": "Gateway service", "status": "pass", "detail": "running"},
        {"id": "bind-mounts", "title": "Project bind mounts", "status": "fail", "detail": "disabled in gateway.toml"},
    ],
}


def _check(check_id: str, status: str, detail: str = "") -> dict[str, str]:
    return {"id": check_id, "status": status, "detail": detail}


# The doctor on a Mac whose gateway runs OpenShell's MicroVM (vm) driver,
# with e2fsprogs missing.
MAC_MICROVM = {
    "ok": False,
    "docker_version": "29.1.5",
    "cli_version": "0.1.1",
    "driver": "vm",
    "checks": [
        _check("platform", "warn", "macOS sandboxes run in OpenShell MicroVMs"),
        _check("docker", "pass", "Docker 29.1.5 (Docker Desktop)"),
        _check("landlock", "pass", "enforced by the MicroVM's own kernel; OpenShell refuses to start without it"),
        _check("openshell-cli", "pass", "0.1.1 at /opt/homebrew/bin/openshell"),
        _check("gateway-service", "pass", "running"),
        _check("vm-driver", "fail", "e2fsprogs is not installed"),
        # Even when a doctor reports it: a MicroVM mounts no host folders.
        _check("bind-mounts", "fail", "disabled in gateway.toml"),
    ],
}
MAC_MICROVM_LINES = [
    "✓ Docker 29.1.5",
    "✓ Landlock (MicroVM)",
    "✓ OpenShell 0.1.1",
    "✗ MicroVM driver: e2fsprogs is not installed",
]
MAC_DOCKER_DESKTOP_LINES = [
    "✓ Docker 29.1.5",
    "✗ Landlock",
    "✓ OpenShell 0.1.1",
    "✗ MicroVM driver: e2fsprogs is not installed",
]


def _install_field(machine, os_name: str):
    fields = sandbox_wizard_fields({}, machine=machine, os_name=os_name)
    return next(field for field in fields if field.label == "Install OpenShell")


def _lines(report) -> list[str]:
    return sandbox_machine_check(report).summary.split("\n")


def test_a_microvm_gateway_skips_bind_mounts_and_checks_its_driver() -> None:
    check = sandbox_machine_check(MAC_MICROVM)
    assert check.summary.split("\n") == MAC_MICROVM_LINES
    # With OpenShell installed the hint is the doctor's fix, and a yes is
    # what has setup install e2fsprogs: the only way from the wizard.
    assert check.openshell_needed is False and check.openshell_attention == "vm-driver"
    assert check.openshell_detail == "the MicroVM driver needs attention: e2fsprogs is not installed"
    install = _install_field(check, "darwin")
    assert install.value == "no"
    assert install.hint == (
        "the MicroVM driver needs attention: e2fsprogs is not installed; OpenShell is installed, and yes lets setup "
        "install e2fsprogs (brew install e2fsprogs) or sign the MicroVM driver when that is what it needs."
    )
    fix = {"summary": "install what the MicroVM driver needs with Homebrew", "command": "brew install e2fsprogs"}
    fixed = {**MAC_MICROVM, "checks": [*MAC_MICROVM["checks"][:5], {**MAC_MICROVM["checks"][5], "fix": fix}]}
    assert sandbox_machine_check(fixed).openshell_detail == (
        "the MicroVM driver needs attention: install what the MicroVM driver needs with Homebrew (`brew install e2fsprogs`)"
    )

    # The driver the files configure counts before the gateway runs it.
    assert _lines({**MAC_MICROVM, "driver": "", "configured_driver": "vm"}) == MAC_MICROVM_LINES
    ready = {**MAC_MICROVM, "checks": [*MAC_MICROVM["checks"][:5], _check("vm-driver", "pass")]}
    assert _lines(ready)[-1] == "✓ MicroVM driver"
    assert sandbox_machine_check(ready).openshell_needed is False

    # The docker driver skips the vm-driver check and keeps the bind-mount line.
    docker = {**READY, "driver": "docker", "checks": [*READY["checks"], _check("vm-driver", "skip")]}
    assert _lines(docker) == ["✓ Docker 29.4.0", "✓ OpenShell 0.1.1", "✓ bind mounts"]


def test_a_docker_desktop_mac_is_checked_for_the_switch_to_microvms() -> None:
    # Setup switches such a Mac's gateway to MicroVMs by default: the wizard
    # shows the MicroVM driver's needs, with the install off (OpenShell is
    # installed), and asks about no bind mounts (sandboxcli/setup.go).
    check = sandbox_machine_check(MAC_DOCKER_DESKTOP)
    assert check.summary.split("\n") == [
        "✓ Docker 29.1.5",
        "✗ Landlock",
        "✓ OpenShell 0.1.1",
        "✗ MicroVM driver: " + MAC_DOCKER_DESKTOP["checks"][3]["detail"],
    ]
    assert check.openshell_needed is False and check.openshell_attention == "vm-driver"
    assert check.openshell_detail.startswith("the MicroVM driver needs attention: e2fsprogs is not installed")
    assert _install_field(check, "darwin").value == "no"
    # A Docker VM with Landlock (Colima) keeps the docker driver and its
    # bind mounts; so does Linux.
    colima = {
        **MAC_DOCKER_DESKTOP,
        "checks": [
            _check("platform", "warn", "darwin/arm64"),
            _check("docker", "pass"),
            _check("landlock", "pass", "ABI 6"),
            _check("vm-driver", "skip", "the gateway runs the docker driver"),
            _check("openshell-cli", "pass"),
            _check("bind-mounts", "pass"),
        ],
    }
    assert _lines(colima) == ["✓ Docker 29.1.5", "✓ Landlock ABI 6", "✓ OpenShell 0.1.1", "✓ bind mounts"]
    linux = {**colima, "checks": [_check("platform", "pass", "linux/arm64"), *colima["checks"][1:2], _check("landlock", "fail"), *colima["checks"][3:]]}
    assert _lines(linux)[-1] == "✓ bind mounts" and sandbox_machine_check(linux).openshell_needed is False


def test_only_macos_offers_e2fsprogs_with_the_install() -> None:
    for machine in (None, sandbox_machine_check(READY), sandbox_machine_check(NO_OPENSHELL)):
        darwin, linux = _install_field(machine, "darwin").hint, _install_field(machine, "linux").hint
        assert "e2fsprogs" in darwin and "e2fsprogs" not in linux, (darwin, linux)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("report", "lines"),
    [(MAC_DOCKER_DESKTOP, MAC_DOCKER_DESKTOP_LINES), (MAC_MICROVM, MAC_MICROVM_LINES)],
)
async def test_every_machine_check_is_on_screen_at_80x24(monkeypatch, report, lines) -> None:
    # On one line, the machine check was cut off at 80 columns after the first few checks.
    from defenseclaw.tui import sandbox_panel
    from defenseclaw.tui.app import DefenseClawTUI
    from defenseclaw.tui.panels.setup import SetupPanelAction
    from fixtures import screen_text

    monkeypatch.setattr(sandbox_panel, "probe_sandbox_machine", lambda: sandbox_machine_check(report))
    app = DefenseClawTUI(config=None, setup_model=SetupPanelModel(None, os_name="darwin"))
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("setup")
        app.setup_model.open_goal_menu(SetupWizard.SANDBOX)
        app._apply_setup_action(SetupPanelAction(True))  # noqa: SLF001
        for _ in range(20):
            await pilot.pause()
            if app.setup_model.sandbox_machine is not None:
                break
        # Walk down to the field under the machine check, as a person would.
        for _ in app.setup_model.form_fields:
            if app.setup_model.focused_row_metadata().label == "Install OpenShell":
                break
            await pilot.press("down")
        await pilot.pause()
        text = screen_text(app)
    for check in lines:
        assert check in text, text


def test_credential_summary_names_sources_never_values(tmp_path: Path) -> None:
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "auth.json").write_text('{"OPENAI_API_KEY": "sk-openai-secret-value"}', encoding="utf-8")
    summary = _sandbox_credential_summary({"ANTHROPIC_API_KEY": "sk-ant-secret-value"}, str(tmp_path))
    assert "ANTHROPIC_API_KEY found" in summary and "~/.codex/auth.json found" in summary
    assert "secret-value" not in summary
    none = _sandbox_credential_summary({}, str(tmp_path / "nothing"))
    assert none.count("none found") == 2


def _codex_summary(home: Path, auth: str | None, env: dict[str, str] | None = None) -> str:
    if auth is not None:
        (home / ".codex").mkdir(exist_ok=True)
        (home / ".codex" / "auth.json").write_text(auth, encoding="utf-8")
    return _sandbox_credential_summary(env or {}, str(home)).split(" · ")[1]


_NO_CODEX = "Codex: none found (log in inside the sandbox)"


@pytest.mark.parametrize(
    "auth",
    [
        "{}",
        '{"OPENAI_API_KEY": null, "tokens": {"id_token": "t"}}',  # a ChatGPT login is not shared
        '{"OPENAI_API_KEY": "  "}',
        '{"OPENAI_API_KEY": 7}',
        "[]",
        "not json",
    ],
)
def test_credential_summary_counts_only_an_auth_json_api_key(tmp_path: Path, auth: str) -> None:
    # sandboxcli.codexAuthKey shares only the key `codex login --with-api-key` stored.
    assert _codex_summary(tmp_path, auth) == _NO_CODEX


def test_credential_summary_reads_codex_home_like_the_run(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    (codex_home / "auth.json").write_text('{"OPENAI_API_KEY": "sk-x"}', encoding="utf-8")
    env = {"CODEX_HOME": str(codex_home)}
    assert _codex_summary(home, None, env) == "Codex: $CODEX_HOME/auth.json found"
    # A relative CODEX_HOME is ignored: ~/.codex, which has no key yet.
    assert _codex_summary(home, None, {"CODEX_HOME": "codex-home"}) == _NO_CODEX
    # CODEX_HOME replaces ~/.codex: a key only there is not counted.
    (codex_home / "auth.json").write_text("{}", encoding="utf-8")
    assert _codex_summary(home, '{"OPENAI_API_KEY": "sk-y"}', env) == _NO_CODEX


def test_credential_summary_skips_a_symlinked_auth_json(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text('{"OPENAI_API_KEY": "sk-x"}', encoding="utf-8")
    (tmp_path / ".codex").mkdir()
    try:
        (tmp_path / ".codex" / "auth.json").symlink_to(real)
    except OSError:
        pytest.skip("symlinks are unavailable")
    assert _codex_summary(tmp_path, None) == _NO_CODEX


def test_credential_summary_counts_a_bedrock_key_last(tmp_path: Path) -> None:
    # `sandbox run --llm auto` shares a Bedrock key when no other is set (#955).
    summary = _sandbox_credential_summary({"AWS_BEARER_TOKEN_BEDROCK": "bedrock-secret"}, str(tmp_path))
    assert summary == "Claude Code: AWS_BEARER_TOKEN_BEDROCK found · Codex: AWS_BEARER_TOKEN_BEDROCK found"
    assert "bedrock-secret" not in summary
    both = _sandbox_credential_summary(
        {"AWS_BEARER_TOKEN_BEDROCK": "b", "ANTHROPIC_API_KEY": "a", "OPENAI_API_KEY": "o"}, str(tmp_path)
    )
    assert both == "Claude Code: ANTHROPIC_API_KEY found · Codex: OPENAI_API_KEY found"


def test_credential_summary_follows_openshell_llm(tmp_path: Path) -> None:
    # Runs take openshell.llm (the wrappers, the TUI and the app pass no --llm),
    # as sandboxcli.runLLM does, and so does Go `sandbox setup`.
    keys = {"AWS_BEARER_TOKEN_BEDROCK": "b", "ANTHROPIC_API_KEY": "a", "OPENAI_API_KEY": "o"}
    assert _sandbox_credential_summary(keys, str(tmp_path), llm="bedrock") == (
        "Claude Code: AWS_BEARER_TOKEN_BEDROCK found · Codex: AWS_BEARER_TOKEN_BEDROCK found"
    )
    assert _sandbox_credential_summary(keys, str(tmp_path), llm="none") == (
        "Claude Code: none shared (openshell.llm none; log in inside the sandbox)"
        " · Codex: none shared (openshell.llm none; log in inside the sandbox)"
    )
    # A provider without its key refuses the run; one the harness has no
    # credential for takes auto.
    missing = _sandbox_credential_summary({"ANTHROPIC_API_KEY": "a"}, str(tmp_path), llm="bedrock")
    assert missing == (
        "Claude Code: none found (openshell.llm bedrock: runs are refused until you set AWS_BEARER_TOKEN_BEDROCK)"
        " · Codex: none found (openshell.llm bedrock: runs are refused until you set AWS_BEARER_TOKEN_BEDROCK)"
    )
    assert _sandbox_credential_summary(keys, str(tmp_path), llm="claude-oauth") == (
        "Claude Code: none found (openshell.llm claude-oauth: runs are refused until you set CLAUDE_CODE_OAUTH_TOKEN)"
        " · Codex: OPENAI_API_KEY found"
    )
    assert _sandbox_credential_summary(keys, str(tmp_path), llm=" AUTO ") == (
        "Claude Code: ANTHROPIC_API_KEY found · Codex: OPENAI_API_KEY found"
    )


def test_wizard_credentials_row_reads_openshell_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "a")
    fields = sandbox_wizard_fields({"openshell": {"llm": "none"}})
    row = next(f for f in fields if f.label == "Credentials")
    assert "none shared (openshell.llm none" in row.hint
    assert "ANTHROPIC_API_KEY" not in row.hint


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
                "block_large_uploads": True,
                "locked": ["resources", "mcp.import"],
            },
        }
    }
    locks = openshell_admin_locks(cfg)
    assert locks["openshell.egress.block_large_uploads"] == "your organization blocks large uploads to first-seen hosts"
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
    assert _field(cfg, "openshell.egress.block_large_uploads").value == "(unset) → on by policy"
    assert _field(cfg, "openshell.profile").interactive is True
    policy = _field(cfg, "openshell.admin")
    assert "required_pack=balanced" in policy.value and "allow_unblock=false" in policy.value
    assert "block_large_uploads=true" in policy.value


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
        # Every Go harness, by name or command, as `sandbox setup --harness` writes them.
        ("openshell.harnesses", "string", "devin,antigravity,agy,cursor-agent,kiro,claude-code", True),
        # The gateway loads a well-formed unknown name; the sandbox commands refuse it (a warning).
        ("openshell.harnesses", "string", "notaharness-example", True),
        ("openshell.harnesses", "string", "not a name", False),
        ("openshell.harnesses", "string", "-leading", False),
        ("openshell.workdir.git_depth", "int", "-1", False),
        ("openshell.workdir.undo_ignored.max_mb", "int", "500", True),
        ("openshell.workdir.undo_ignored.max_mb", "int", "1048577", False),
        ("openshell.workdir.undo_ignored.dirs", "string", "node_modules, .venv, vendor", True),
        ("openshell.workdir.undo_ignored.dirs", "string", "web/node_modules", False),
        ("openshell.workdir.undo_ignored.dirs", "string", ".git", False),
        ("openshell.workdir.undo_ignored.dirs", "string", "..", False),
    ],
)
def test_openshell_validation(key: str, kind: str, value: str, ok: bool) -> None:
    from defenseclaw.tui.services.setup_state import ConfigField

    result = validate_config_field(ConfigField(label=key, key=key, kind=kind, value=value, original=""))
    assert (result.severity != "error") is ok, result


def test_openshell_harnesses_other_than_the_launch_dialogs_never_block_a_save() -> None:
    from defenseclaw.tui.services.setup_state import ConfigField, ConfigSection, validation_errors

    key = "openshell.harnesses"

    def field(value: str) -> ConfigField:
        return ConfigField(label=key, key=key, kind="string", value=value, original="")

    assert validate_config_field(field("devin,hermes,openhands")).severity == "ok"
    unknown = validate_config_field(field("claudecode,notaharness-example"))
    assert unknown.severity == "warning" and "notaharness-example" in unknown.message
    # validation_errors checks every field, so a bad one here would block any save.
    assert validation_errors([ConfigSection("OpenShell", (field("devin,omnigent,notaharness-example"),), "")]) == ()


def test_the_harness_table_matches_the_go_registry() -> None:
    """HARNESSES mirrors internal/openshell/harness: every registered Spec's name, command and display name."""
    import re

    from defenseclaw.tui.services.sandbox_state import HARNESSES, resolve_harness

    root = Path(__file__).resolve().parents[3]
    specs: dict[str, tuple[str, str]] = {}
    for path in sorted((root / "internal" / "openshell" / "harness").glob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        for block in re.findall(r"= register\(&Spec\{\n(.*?)\n\}\)", path.read_text(encoding="utf-8"), re.S):
            fields = dict(re.findall(r'^\t(Name|Command|DisplayName):\s*"([^"]*)"', block, re.M))
            specs[fields["Name"]] = (fields["Command"], fields["DisplayName"])
    assert specs == HARNESSES
    for name, (command, display) in HARNESSES.items():
        assert resolve_harness(name) == resolve_harness(command) == resolve_harness(display.upper()) == name
    assert resolve_harness("Claude-Code") == "claudecode" and resolve_harness("openclaw") == ""


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


@pytest.mark.asyncio
async def test_long_hints_wrap_instead_of_running_off_the_screen(monkeypatch) -> None:
    """R2-59: a table row is one line, so long hints were cut at the screen edge."""
    from defenseclaw.tui import sandbox_panel
    from defenseclaw.tui.app import DefenseClawTUI
    from textual.widgets import DataTable

    monkeypatch.setattr(sandbox_panel, "probe_sandbox_machine", lambda: sandbox_machine_check(None, "not in tests"))
    app = DefenseClawTUI(setup_model=SetupPanelModel({}, os_name="linux"))
    width = 140
    async with app.run_test(size=(width, 50)) as pilot:
        await pilot.press("0")
        await pilot.pause()
        app.setup_model.active_wizard = SetupWizard.SANDBOX
        app.setup_model.open_goal_menu(SetupWizard.SANDBOX)
        app._render_chrome()  # noqa: SLF001
        await pilot.pause()
        _columns, rows = app._setup_table()  # noqa: SLF001
        hints = {row[0]: row[3] for row in rows}
        full = {field.label: field.hint for field in app.setup_model.form_fields}
        mount = hints["Mount Project Folder"]
        assert "\n" in mount and mount.replace("\n", " ") == full["Mount Project Folder"]
        assert all(len(line) < width for line in mount.split("\n"))
        table = app.query_one("#panel-table", DataTable)
        assert any(row.height > 1 for row in table.rows.values())


def test_credential_summary_says_a_provider_that_does_not_apply_gives_way_to_auto(tmp_path: Path) -> None:
    # openshell.llm gemini names no credential Claude Code or Codex has, so
    # both run as auto, which here finds nothing: the summary says why.
    summary = _sandbox_credential_summary({}, str(tmp_path / "nothing"), llm="gemini")
    assert summary == (
        "Claude Code: none found (openshell.llm gemini does not apply to Claude Code, so auto; log in inside the sandbox)"
        " · Codex: none found (openshell.llm gemini does not apply to Codex, so auto; log in inside the sandbox)"
    )
    # auto itself keeps the plain wording.
    assert _sandbox_credential_summary({}, str(tmp_path / "nothing")).count("(log in inside the sandbox)") == 2
