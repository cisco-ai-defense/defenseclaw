"""GAP-2571 / GAP-2572: the scanner analyzer forms run what they show."""

from __future__ import annotations

from click.testing import CliRunner
from defenseclaw.tui.panels.setup import SetupWizard, build_wizard_args, wizard_form_defs


def _edit(fields, **values):
    return [field.with_value(values.get(field.label, field.value)) for field in fields]


def test_skill_analyzer_toggles_open_on_config_and_can_turn_off() -> None:
    cfg = {"scanners": {"skill_scanner": {"use_behavioral": True}}}
    fields = wizard_form_defs(SetupWizard.SKILL_SCANNER, cfg)
    values = {field.label: field.value for field in fields}
    assert (values["Behavioral Analyzer"], values["Meta Analyzer"]) == ("yes", "no")
    assert "--use-behavioral" not in build_wizard_args(SetupWizard.SKILL_SCANNER, fields)

    argv = build_wizard_args(SetupWizard.SKILL_SCANNER, _edit(fields, **{"Behavioral Analyzer": "no"}))
    assert "--no-use-behavioral" in argv


def test_mcp_emptied_analyzers_resets_to_auto() -> None:
    fields = wizard_form_defs(SetupWizard.MCP_SCANNER, {"scanners": {"mcp_scanner": {"analyzers": "yara,behavioral"}}})
    argv = build_wizard_args(SetupWizard.MCP_SCANNER, _edit(fields, Analyzers=""))
    assert argv[argv.index("--analyzers") + 1] == "auto"


def test_setup_skill_scanner_no_use_behavioral_turns_it_off() -> None:
    from defenseclaw.commands.cmd_setup import setup
    from tests.helpers import cleanup_app, make_app_context

    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.scanners.skill_scanner.use_behavioral = True
        argv = ["skill-scanner", "--non-interactive", "--no-verify", "--no-use-behavioral"]
        result = CliRunner().invoke(setup, argv, obj=app, catch_exceptions=False)
        assert result.exit_code == 0, result.output
        assert app.cfg.scanners.skill_scanner.use_behavioral is False
    finally:
        cleanup_app(app, db_path, tmp_dir)
