"""GAP-0719 near variants: the unset hook fail mode reads the same through every reader.

The global key, a named connector, the whole-section views and the Secure Client report
all take the default from GuardrailConfig.hook_fail_mode_resolution.
"""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner
from defenseclaw.commands import cmd_config

from tests.environment import isolated_home_env


def _run(tmp_path, monkeypatch, config, args, *, show=False):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    path = tmp_path / "config.yaml"
    path.write_text("config_version: 9\ngateway: {}\nobservability: {}\n" + config, encoding="utf-8")
    with patch.object(cmd_config.config_module, "config_path", return_value=path):
        if show:
            with patch.object(cmd_config, "inspect_v8_config", return_value=SimpleNamespace(effective={})):
                result = CliRunner().invoke(cmd_config.config_cmd, args)
        else:
            result = CliRunner().invoke(cmd_config.config_cmd, args)
    assert result.exit_code == 0, result.output
    return result


def test_active_connector_default_ignores_unrelated_auto_overlay(tmp_path, monkeypatch):
    config = (
        "guardrail: {connector: codex, mode: action, rule_pack: default}\n"
        "application_protection: {enabled: true, guardrail: {hook_fail_mode: closed}}\n"
    )
    active = _run(tmp_path, monkeypatch, config, ["get", "guardrail.connectors.codex.hook_fail_mode"])
    global_read = _run(tmp_path, monkeypatch, config, ["get", "guardrail.hook_fail_mode"])
    assert active.stdout == "open\n"
    assert global_read.stdout == "open\n", global_read.stderr


def test_parent_get_exposes_same_default_as_leaf(tmp_path, monkeypatch):
    config = "guardrail: {rule_pack: default}\n"
    leaf = _run(tmp_path, monkeypatch, config, ["get", "guardrail.hook_fail_mode"])
    parent = _run(tmp_path, monkeypatch, config, ["get", "guardrail", "--effective"])
    assert leaf.stdout == "open\n"
    assert yaml.safe_load(parent.stdout)["hook_fail_mode"] == "open"


def test_show_section_exposes_effective_unset_default(tmp_path, monkeypatch):
    config = "guardrail: {rule_pack: permissive}\n"
    shown = _run(tmp_path, monkeypatch, config, ["show", "--section", "guardrail"], show=True)
    assert yaml.safe_load(shown.stdout)["guardrail"]["hook_fail_mode"] == "open"


def test_auto_connector_source_names_saved_connector_key(tmp_path, monkeypatch):
    config = (
        "guardrail: {connector: openclaw}\n"
        "application_protection: {enabled: true, connectors: {codex: {guardrail: {hook_fail_mode: closed}}}}\n"
    )
    result = _run(tmp_path, monkeypatch, config, ["get", "guardrail.connectors.codex.hook_fail_mode"])
    assert result.stdout == "closed\n"
    assert "config:application_protection.connectors.codex.guardrail.hook_fail_mode" in result.stderr


def test_secure_client_unset_mode_is_reported_as_default_not_saved():
    from defenseclaw.config import _apply_secure_client_hook_fail_default, default_config
    from defenseclaw.fail_mode import connector_fail_mode_report

    cfg = default_config()
    cfg.guardrail.connector = "codex"
    raw = {
        "deployment_mode": "managed_enterprise",
        "enterprise": {"profile": "secure_client"},
        "guardrail": {"connector": "codex", "mode": "action"},
    }
    _apply_secure_client_hook_fail_default(cfg, raw)
    assert cfg.guardrail.hook_fail_mode_resolution("codex") == ("open", "secure-client-default")
    assert connector_fail_mode_report(cfg, "codex", inspect_effective_policy=False)["configured"] is None


def test_secure_client_unset_status_has_no_configured_value():
    from defenseclaw.config import _apply_secure_client_hook_fail_default, default_config
    from defenseclaw.fail_mode import connector_fail_mode_report

    cfg = default_config()
    cfg.guardrail.connector = "codex"
    raw = {
        "deployment_mode": "managed_enterprise",
        "enterprise": {"profile": "secure_client"},
        "guardrail": {"connector": "codex", "mode": "action"},
    }
    _apply_secure_client_hook_fail_default(cfg, raw)
    report = connector_fail_mode_report(cfg, "codex", inspect_effective_policy=False)
    assert report["desired"] == "open"
    assert report["configured"] is None


def test_saved_global_value_is_kept_under_effective_with_auto_overlay(tmp_path, monkeypatch):
    config = (
        "guardrail: {connector: codex, mode: action, rule_pack: default, hook_fail_mode: open}\n"
        "application_protection: {enabled: true, guardrail: {hook_fail_mode: closed}}\n"
    )
    result = _run(tmp_path, monkeypatch, config, ["get", "guardrail.hook_fail_mode", "--effective"])
    assert result.stdout == "open\n"


def test_auto_overlay_still_applies_to_a_connector_outside_the_active_set(tmp_path, monkeypatch):
    config = (
        "guardrail: {connector: openclaw}\n"
        "application_protection: {enabled: true, guardrail: {hook_fail_mode: closed}}\n"
    )
    result = _run(tmp_path, monkeypatch, config, ["get", "guardrail.connectors.codex.hook_fail_mode"])
    assert result.stdout == "closed\n"
    assert "config:application_protection.guardrail.hook_fail_mode" in result.stderr


def test_strict_pack_whole_section_view_is_closed(tmp_path, monkeypatch):
    parent = _run(tmp_path, monkeypatch, "guardrail: {rule_pack: strict}\n", ["get", "guardrail", "--effective"])
    assert yaml.safe_load(parent.stdout)["hook_fail_mode"] == "closed"


def test_saved_mode_is_shown_as_saved_in_the_section_view(tmp_path, monkeypatch):
    shown = _run(
        tmp_path,
        monkeypatch,
        "guardrail: {rule_pack: permissive, hook_fail_mode: closed}\n",
        ["show", "--section", "guardrail"],
        show=True,
    )
    assert yaml.safe_load(shown.stdout)["guardrail"]["hook_fail_mode"] == "closed"


def _run_without_config_file(tmp_path, monkeypatch, args):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    path = tmp_path / "config.yaml"
    assert not path.exists()
    with patch.object(cmd_config.config_module, "config_path", return_value=path):
        result = CliRunner().invoke(cmd_config.config_cmd, args)
    assert result.exit_code == 0, result.output
    return result


def test_no_file_show_section_reports_the_default_tier_mode(tmp_path, monkeypatch):
    shown = _run_without_config_file(tmp_path, monkeypatch, ["show", "--section", "guardrail"])
    assert yaml.safe_load(shown.stdout)["guardrail"]["hook_fail_mode"] == "open"


def test_no_file_full_show_reports_the_default_tier_mode(tmp_path, monkeypatch):
    shown = _run_without_config_file(tmp_path, monkeypatch, ["show"])
    assert yaml.safe_load(shown.stdout)["guardrail"]["hook_fail_mode"] == "open"


@pytest.mark.parametrize("alias", ["claude-code", "claude_code", "claudecode"])
def test_auto_overlay_source_names_the_saved_connector_key(tmp_path, monkeypatch, alias):
    config = (
        "guardrail: {connector: openclaw}\n"
        f"application_protection: {{enabled: true, connectors: {{{alias}: {{guardrail: {{hook_fail_mode: closed}}}}}}}}\n"
    )
    result = _run(tmp_path, monkeypatch, config, ["get", "guardrail.connectors.claudecode.hook_fail_mode"])
    assert result.stdout == "closed\n"
    assert f"config:application_protection.connectors.{alias}.guardrail.hook_fail_mode" in result.stderr


@pytest.mark.parametrize("alias", ["claude-code", "claude_code", "claudecode"])
def test_manual_connector_source_names_the_saved_connector_key(tmp_path, monkeypatch, alias):
    config = f"guardrail: {{connectors: {{{alias}: {{hook_fail_mode: closed}}}}}}\n"
    result = _run(
        tmp_path, monkeypatch, config, ["get", "guardrail.connectors.claudecode.hook_fail_mode", "--effective"]
    )
    assert result.stdout == "closed\n"
    assert f"config:guardrail.connectors.{alias}.hook_fail_mode" in result.stderr
