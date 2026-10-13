"""GAP-2536: the scanner goal forms open on the effective config."""

from __future__ import annotations

from click.testing import CliRunner
from defenseclaw.tui.panels.setup import (
    SetupWizard,
    build_wizard_args,
    wizard_form_defs,
)


def _values(wizard: SetupWizard, cfg: object) -> dict[str, str]:
    return {field.label: field.value for field in wizard_form_defs(wizard, cfg)}


def test_scanner_forms_prefill_the_effective_config() -> None:
    # An unset config is quiet / lenient / auto, as `config get` reports.
    unset = {"scanners": {"skill_scanner": {}, "mcp_scanner": {}}}
    skill = _values(SetupWizard.SKILL_SCANNER, unset)
    assert (skill["Scan Policy"], skill["Lenient Mode"]) == ("quiet", "yes")
    assert _values(SetupWizard.MCP_SCANNER, unset)["Analyzers"] == "auto"

    cfg = {"scanners": {"skill_scanner": {"policy": "", "lenient": False}, "mcp_scanner": {"analyzers": "yara"}}}
    skill = _values(SetupWizard.SKILL_SCANNER, cfg)
    assert (skill["Scan Policy"], skill["Lenient Mode"]) == ("quiet", "no")
    assert _values(SetupWizard.MCP_SCANNER, cfg)["Analyzers"] == "yara"


def test_strictness_form_runs_exactly_what_it_shows() -> None:
    fields = wizard_form_defs(SetupWizard.SKILL_SCANNER, {"scanners": {"skill_scanner": {}}})
    unchanged = build_wizard_args(SetupWizard.SKILL_SCANNER, fields)
    assert "--policy" not in unchanged and "--lenient" not in unchanged

    edited = [
        field.with_value({"Scan Policy": "balanced", "Lenient Mode": "no"}.get(field.label, field.value))
        for field in fields
    ]
    argv = build_wizard_args(SetupWizard.SKILL_SCANNER, edited)
    assert argv[argv.index("--policy") + 1] == "balanced"
    assert "--no-lenient" in argv


def test_setup_skill_scanner_no_lenient_turns_lenient_off() -> None:
    from defenseclaw.commands.cmd_setup import setup
    from tests.helpers import cleanup_app, make_app_context

    app, tmp_dir, db_path = make_app_context()
    try:
        assert app.cfg.scanners.skill_scanner.lenient is True
        argv = ["skill-scanner", "--non-interactive", "--no-verify", "--no-lenient", "--policy", "balanced"]
        result = CliRunner().invoke(setup, argv, obj=app, catch_exceptions=False)
        assert result.exit_code == 0, result.output
        assert app.cfg.scanners.skill_scanner.lenient is False
        assert app.cfg.scanners.skill_scanner.policy == "balanced"
    finally:
        cleanup_app(app, db_path, tmp_dir)
