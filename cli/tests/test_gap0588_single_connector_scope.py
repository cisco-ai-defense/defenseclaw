"""Single-connector guardrail scope and config writer regressions."""

from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from defenseclaw import config as dcconfig
from defenseclaw import config_writer
from defenseclaw.commands import cmd_config, cmd_guardrail
from defenseclaw.context import AppContext
from defenseclaw.fail_mode import ConnectorFailModeState


def _app(tmp_path: Path, names: list[str]) -> AppContext:
    guardrail = dcconfig.GuardrailConfig()
    guardrail.enabled = True
    guardrail.connector = names[0]
    guardrail.hook_fail_mode = "open"
    guardrail.connectors = (
        {name: dcconfig.PerConnectorGuardrailConfig() for name in names}
        if len(names) > 1 else {}
    )
    data_dir = tmp_path / "home"
    (data_dir / "hooks").mkdir(parents=True)
    cfg = SimpleNamespace(
        data_dir=str(data_dir),
        guardrail=guardrail,
        gateway=SimpleNamespace(host="127.0.0.1", port=18789),
        deployment_mode="",
        active_connector=lambda: names[0],
        active_connectors=lambda: names,
        save=MagicMock(),
    )
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    return app


@pytest.mark.parametrize("mode", ["closed", "open"])
def test_single_openclaw_named_fail_mode_refreshes_shims(tmp_path: Path, mode: str) -> None:
    app = _app(tmp_path, ["openclaw"])
    app.cfg.guardrail.hook_fail_mode = "open" if mode == "closed" else "closed"
    with (
        patch.object(cmd_guardrail, "fail_mode_transaction_lock", return_value=nullcontext()),
        patch.object(cmd_guardrail, "snapshot_fail_mode_transaction", return_value=()),
        patch.object(cmd_guardrail, "_refresh_hook_outage_modes", return_value=True) as refresh,
        patch.object(cmd_guardrail, "_log_guardrail_action"),
    ):
        result = CliRunner().invoke(
            cmd_guardrail.fail_mode_cmd, [mode, "--connector", "openclaw", "--yes"], obj=app
        )
    assert result.exit_code == 0, result.output
    assert app.cfg.guardrail.hook_fail_mode == mode
    assert app.cfg.guardrail.effective_hook_fail_mode("openclaw") == mode
    assert app.cfg.guardrail.connectors == {}
    app.cfg.save.assert_called_once()
    refresh.assert_called_once_with(app)
    assert f"OpenClaw PATH shims now use fail={mode}" in result.output


def test_single_openclaw_wrong_name_names_installed_connector(tmp_path: Path) -> None:
    app = _app(tmp_path, ["openclaw"])
    result = CliRunner().invoke(
        cmd_guardrail.fail_mode_cmd, ["closed", "--connector", "kiro", "--yes"], obj=app
    )
    assert result.exit_code != 0
    assert "Installed connector: openclaw" in result.output
    app.cfg.save.assert_not_called()


def test_single_openclaw_shim_refresh_skip_reports_saved_mode(tmp_path: Path) -> None:
    app = _app(tmp_path, ["openclaw"])
    with (
        patch.object(cmd_guardrail, "fail_mode_transaction_lock", return_value=nullcontext()),
        patch.object(cmd_guardrail, "snapshot_fail_mode_transaction", return_value=()),
        patch.object(cmd_guardrail, "_refresh_hook_outage_modes", return_value=False),
        patch.object(cmd_guardrail, "_log_guardrail_action"),
    ):
        result = CliRunner().invoke(
            cmd_guardrail.fail_mode_cmd, ["closed", "--connector", "openclaw", "--yes"], obj=app
        )
    assert result.exit_code == 0, result.output
    assert "saved fail=closed applies when the PATH shims run" in result.output
    assert "PATH shims now use" not in result.output


def test_secure_client_single_connector_scope_stays_refused(tmp_path: Path) -> None:
    app = _app(tmp_path, ["openclaw"])
    app.cfg.guardrail._secure_client = True
    result = CliRunner().invoke(
        cmd_guardrail.fail_mode_cmd, ["closed", "--connector", "openclaw", "--yes"], obj=app
    )
    assert result.exit_code != 0
    app.cfg.save.assert_not_called()


@pytest.mark.parametrize("name", ["openclaw", "codex"])
@pytest.mark.parametrize(
    ("command", "args", "enabled"),
    [
        (cmd_guardrail.disable_cmd, ["--connector", "openclaw", "--yes"], False),
        (cmd_guardrail.enable_cmd, ["--connector", "openclaw", "--yes"], True),
        (cmd_guardrail.hilt_cmd, ["--connector", "openclaw"], True),
        (cmd_guardrail.block_message_cmd, ["--connector", "openclaw"], True),
    ],
)
def test_single_connector_named_scope_uses_global_command(
    tmp_path: Path, name: str, command, args: list[str], enabled: bool
) -> None:
    app = _app(tmp_path, [name])
    app.cfg.guardrail.enabled = enabled
    result = CliRunner().invoke(command, [name if arg == "openclaw" else arg for arg in args], obj=app)
    assert result.exit_code == 0, result.output
    app.cfg.save.assert_not_called()


def test_multi_connector_claudecode_scope_stays_available(tmp_path: Path) -> None:
    app = _app(tmp_path, ["claudecode", "codex"])
    state = ConnectorFailModeState(
        connector="claudecode", desired="open", configured="open", runtime="open", sources=(), drift=()
    )
    with patch.object(cmd_guardrail, "resolve_connector_fail_mode", return_value=state):
        result = CliRunner().invoke(
            cmd_guardrail.fail_mode_cmd, ["--connector", "claudecode"], obj=app
        )
    assert result.exit_code == 0, result.output
    assert "Claude Code (claudecode) hook_fail_mode" in result.output


def _set_in_file(
    tmp_path: Path, app: AppContext, roster: str, key: str, value: str, *, as_json: bool = False
) -> tuple[object, bytes, bytes]:
    path = tmp_path / "config.yaml"
    path.write_text(
        f"config_version: 9\ndata_dir: {tmp_path}\nguardrail:\n{roster}", encoding="utf-8"
    )
    before = path.read_bytes()

    with (
        patch.object(cmd_config.config_module, "config_path", return_value=path),
        patch.object(config_writer, "_use_go_validator", return_value=False),
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
        patch.object(cmd_config, "_refresh_stopped_gateway_hooks", return_value=[]),
    ):
        result = CliRunner().invoke(
            cmd_config.config_set, [key, value, *(["--json"] if as_json else [])], obj=app
        )
    return result, before, path.read_bytes()


def _unset_in_file(
    tmp_path: Path, app: AppContext, roster: str, *keys: str
) -> tuple[object, bytes, bytes]:
    path = tmp_path / "config.yaml"
    path.write_text(
        f"config_version: 9\ndata_dir: {tmp_path}\nguardrail:\n{roster}", encoding="utf-8"
    )
    before = path.read_bytes()

    with (
        patch.object(cmd_config.config_module, "config_path", return_value=path),
        patch.object(config_writer, "_use_go_validator", return_value=False),
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
        patch.object(cmd_config, "_refresh_stopped_gateway_hooks", return_value=[]),
    ):
        result = CliRunner().invoke(cmd_config.config_unset, list(keys), obj=app)
    return result, before, path.read_bytes()


@pytest.mark.parametrize("proxy", ["openclaw", "zeptoclaw"])
@pytest.mark.parametrize("loaded_app", [True, False])
def test_config_unset_refuses_enabled_proxy_in_final_multi_roster(
    tmp_path: Path, proxy: str, loaded_app: bool
) -> None:
    app = _app(tmp_path, ["kiro"])
    if not loaded_app:
        app.cfg = None
    roster = (
        "  connector: kiro\n  connectors:\n    kiro: {}\n"
        f"    {proxy}:\n      enabled: false\n"
    )
    result, before, after = _unset_in_file(
        tmp_path, app, roster, f"guardrail.connectors.{proxy}.enabled"
    )
    assert result.exit_code != 0
    assert f"{proxy} needs a proxy binding" in result.output
    assert after == before


@pytest.mark.parametrize("proxy", ["openclaw", "zeptoclaw"])
def test_config_unset_valid_roster_remains_allowed(tmp_path: Path, proxy: str) -> None:
    app = _app(tmp_path, ["kiro"])
    roster = (
        "  connector: kiro\n  connectors:\n    kiro: {}\n"
        f"    {proxy}:\n      enabled: false\n"
    )
    result, before, after = _unset_in_file(
        tmp_path, app, roster, f"guardrail.connectors.{proxy}"
    )
    assert result.exit_code == 0, result.output
    assert after != before


def test_config_unset_checks_final_roster_for_batch(tmp_path: Path) -> None:
    app = _app(tmp_path, ["kiro"])
    roster = (
        "  connector: kiro\n  hook_fail_mode: closed\n  connectors:\n"
        "    kiro: {}\n    openclaw:\n      enabled: false\n"
    )
    result, before, after = _unset_in_file(
        tmp_path, app, roster,
        "guardrail.hook_fail_mode", "guardrail.connectors.openclaw.enabled",
    )
    assert result.exit_code != 0
    assert "openclaw needs a proxy binding" in result.output
    assert after == before


@pytest.mark.parametrize(
    ("installed", "roster", "key", "value", "as_json"),
    [
        ("kiro", "  connector: kiro\n  connectors:\n    kiro: {}\n", "guardrail.connectors.openclaw.hook_fail_mode", "closed", False),
        ("openclaw", "  connector: openclaw\n  connectors:\n    openclaw: {}\n", "guardrail.connectors.kiro.hook_fail_mode", "closed", False),
        ("kiro", "  connector: kiro\n  connectors:\n    kiro: {}\n", "guardrail.connectors", '{"kiro": {}, "openclaw": {}}', True),
        ("kiro", "  connector: kiro\n  connectors:\n    kiro: {}\n", "guardrail", '{"connector": "kiro", "connectors": {"kiro": {}, "openclaw": {}}}', True),
        ("kiro", "  connector: kiro\n  connectors:\n    kiro: {}\n    openclaw:\n      enabled: false\n", "guardrail.connectors.openclaw.enabled", "true", False),
        # A single install and a first entry for another connector (GAP-0588).
        ("openclaw", "  connector: openclaw\n", "guardrail.connectors.kiro.hook_fail_mode", "closed", False),
        ("kiro", "  connector: kiro\n", "guardrail.connectors.openclaw.hook_fail_mode", "closed", False),
        ("openclaw", "  connector: openclaw\n", "guardrail.connectors", '{"kiro": {}}', True),
        ("openclaw", "  connector: openclaw\n", "guardrail", '{"connector": "openclaw", "connectors": {"kiro": {}}}', True),
    ],
)
def test_config_set_refuses_enabled_proxy_in_final_multi_roster(
    tmp_path: Path, installed: str, roster: str, key: str, value: str, as_json: bool
) -> None:
    app = _app(tmp_path, [installed])
    result, before, after = _set_in_file(tmp_path, app, roster, key, value, as_json=as_json)
    assert result.exit_code != 0
    assert "openclaw needs a proxy binding" in result.output
    assert "hook connectors (kiro)" in result.output
    assert after == before


@pytest.mark.parametrize(
    ("installed", "roster", "key", "value"),
    [
        ("kiro", "  connector: kiro\n  connectors:\n    kiro: {}\n", "guardrail.connectors.kiro.hook_fail_mode", "closed"),
        ("openclaw", "  connector: openclaw\n  connectors:\n    openclaw: {}\n", "guardrail.connectors.openclaw.hook_fail_mode", "closed"),
        # Hook connectors beside each other stay ordinary settings (ruling r7).
        ("kiro", "  connector: kiro\n", "guardrail.connectors.codex.hook_fail_mode", "closed"),
        ("claudecode", "  connector: claudecode\n", "guardrail.connectors.codex.hook_fail_mode", "open"),
        ("openclaw", "  connector: openclaw\n", "guardrail.connectors.openclaw.hook_fail_mode", "closed"),
        ("kiro", "  connector: kiro\n  connectors:\n    kiro: {}\n", "guardrail.connectors.openclaw.enabled", "false"),
        ("openclaw", "  connector: openclaw\n  connectors:\n    openclaw:\n      enabled: false\n", "guardrail.connectors.kiro.hook_fail_mode", "closed"),
    ],
)
def test_config_set_valid_roster_remains_allowed(
    tmp_path: Path, installed: str, roster: str, key: str, value: str
) -> None:
    app = _app(tmp_path, [installed])
    result, before, after = _set_in_file(tmp_path, app, roster, key, value)
    assert result.exit_code == 0, result.output
    assert after != before


def test_config_set_checks_roster_after_another_writer_changes_it(tmp_path: Path) -> None:
    app = _app(tmp_path, ["openclaw"])
    path = tmp_path / "config.yaml"
    path.write_text(
        f"config_version: 9\ndata_dir: {tmp_path}\nguardrail:\n"
        "  connector: openclaw\n  connectors:\n    openclaw: {}\n", encoding="utf-8"
    )
    latest = b""

    original_apply = config_writer.apply

    def write(changes, actor, reason, *args, **kwargs):
        nonlocal latest
        original_apply(
            [config_writer.Change("guardrail.connectors.kiro.hook_fail_mode", "closed")],
            "cli:test", "another writer", path=path,
        )
        latest = path.read_bytes()
        return original_apply(changes, actor, reason, *args, **kwargs)

    with (
        patch.object(cmd_config.config_module, "config_path", return_value=path),
        patch.object(config_writer, "apply", side_effect=write),
        patch.object(config_writer, "_use_go_validator", return_value=False),
    ):
        result = CliRunner().invoke(
            cmd_config.config_set,
            ["guardrail.connectors.openclaw.hook_fail_mode", "closed"], obj=app,
        )
    assert result.exit_code != 0
    assert "openclaw needs a proxy binding" in result.output
    assert path.read_bytes() == latest


def test_config_set_refuses_zeptoclaw_in_final_multi_roster(tmp_path: Path) -> None:
    app = _app(tmp_path, ["kiro"])
    result, before, after = _set_in_file(
        tmp_path, app, "  connector: kiro\n  connectors:\n    kiro: {}\n",
        "guardrail.connectors.zeptoclaw.hook_fail_mode", "closed",
    )
    assert result.exit_code != 0
    assert "zeptoclaw needs a proxy binding" in result.output
    assert after == before


def test_secure_client_roster_check_keeps_existing_scope(tmp_path: Path) -> None:
    candidate = (
        b"config_version: 9\ndeployment_mode: managed_enterprise\n"
        b"enterprise:\n  profile: secure_client\nguardrail:\n"
        b"  connectors:\n    kiro: {}\n    openclaw: {}\n"
    )
    cmd_config._check_guardrail_connector_roster(str(tmp_path / "config.yaml"), candidate)


def _set_with_claw_mode(tmp_path: Path, mode: str, key: str, value: str) -> tuple[object, bytes, bytes]:
    app = _app(tmp_path, [mode])
    path = tmp_path / "config.yaml"
    path.write_text(
        f"config_version: 9\ndata_dir: {tmp_path}\nclaw:\n  mode: {mode}\nguardrail: {{}}\n",
        encoding="utf-8",
    )
    before = path.read_bytes()
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=path),
        patch.object(config_writer, "_use_go_validator", return_value=False),
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
        patch.object(cmd_config, "_refresh_stopped_gateway_hooks", return_value=[]),
    ):
        result = CliRunner().invoke(cmd_config.config_set, [key, value], obj=app)
    return result, before, path.read_bytes()


def test_config_set_refuses_first_entry_beside_claw_mode_proxy(tmp_path: Path) -> None:
    result, before, after = _set_with_claw_mode(
        tmp_path, "openclaw", "guardrail.connectors.kiro.hook_fail_mode", "closed"
    )
    assert result.exit_code != 0
    assert "openclaw needs a proxy binding" in result.output
    assert after == before


def test_config_set_first_entry_beside_claw_mode_hook_connector_stays_allowed(tmp_path: Path) -> None:
    result, before, after = _set_with_claw_mode(
        tmp_path, "kiro", "guardrail.connectors.codex.hook_fail_mode", "closed"
    )
    assert result.exit_code == 0, result.output
    assert after != before


@pytest.mark.parametrize(
    ("installed", "roster", "key", "value", "message"),
    [
        # Implicit default OpenClaw (no guardrail.connector, no claw.mode in the file).
        ("openclaw", "  enabled: true\n", "guardrail.connectors.kiro.hook_fail_mode", "closed", "hook connectors (kiro)"),
        # A primary-selector edit is judged by the final file, like an entry edit.
        ("kiro", "  connector: kiro\n  connectors:\n    kiro: {}\n", "guardrail.connector", "openclaw", "hook connectors (kiro)"),
        ("openclaw", "  connector: openclaw\n  connectors:\n    openclaw: {}\n", "guardrail.connector", "kiro", "hook connectors (kiro)"),
    ],
)
def test_config_set_refuses_implicit_and_primary_selector_proxy_mix(
    tmp_path: Path, installed: str, roster: str, key: str, value: str, message: str
) -> None:
    app = AppContext()  # cfg is None, as under the root config command
    result, before, after = _set_in_file(tmp_path, app, roster, key, value)
    assert result.exit_code != 0
    assert "needs a proxy binding" in result.output
    assert message in result.output
    assert after == before


def test_config_set_claw_mode_switch_to_proxy_beside_hook_roster_is_refused(tmp_path: Path) -> None:
    app = _app(tmp_path, ["kiro"])
    path = tmp_path / "config.yaml"
    path.write_text(
        f"config_version: 9\ndata_dir: {tmp_path}\nclaw:\n  mode: kiro\nguardrail:\n  connectors:\n    kiro: {{}}\n",
        encoding="utf-8",
    )
    before = path.read_bytes()
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=path),
        patch.object(config_writer, "_use_go_validator", return_value=False),
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
        patch.object(cmd_config, "_refresh_stopped_gateway_hooks", return_value=[]),
    ):
        result = CliRunner().invoke(cmd_config.config_set, ["claw.mode", "openclaw"], obj=app)
    assert result.exit_code != 0
    assert "openclaw needs a proxy binding" in result.output
    assert path.read_bytes() == before


_DISABLED_KIRO = "  connector: openclaw\n  connectors:\n    kiro:\n      enabled: false\n"


@pytest.mark.parametrize(
    ("installed", "roster", "key", "value"),
    [
        # An explicitly disabled entry is not part of the process: its own settings stay editable.
        ("openclaw", _DISABLED_KIRO, "guardrail.connectors.kiro.hook_fail_mode", "closed"),
        ("openclaw", _DISABLED_KIRO, "guardrail.connectors.kiro.rule_pack", "default"),
        ("openclaw", _DISABLED_KIRO, "guardrail.connectors.kiro.enabled", "false"),
        # Hook beside hook and the proxy's own entry stay ordinary settings.
        ("kiro", "  connector: kiro\n  connectors:\n    kiro: {}\n", "guardrail.connector", "codex"),
        ("openclaw", "  connector: openclaw\n", "guardrail.connector", "openclaw"),
        ("kiro", "  connector: kiro\n  enabled: true\n", "guardrail.connectors.codex.hook_fail_mode", "closed"),
    ],
)
def test_config_set_disabled_entry_and_same_kind_selection_stay_allowed(
    tmp_path: Path, installed: str, roster: str, key: str, value: str
) -> None:
    app = _app(tmp_path, [installed])
    result, before, after = _set_in_file(tmp_path, app, roster, key, value)
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize("key", ["guardrail.connectors.kiro.hook_fail_mode", "guardrail.connectors.kiro"])
def test_config_unset_of_disabled_entry_setting_stays_allowed(tmp_path: Path, key: str) -> None:
    app = _app(tmp_path, ["openclaw"])
    roster = _DISABLED_KIRO + "      hook_fail_mode: closed\n"
    result, before, after = _unset_in_file(tmp_path, app, roster, key)
    assert result.exit_code == 0, result.output
    assert after != before


_IMPLICIT_OPENCLAW = "  enabled: true\n"


@pytest.mark.parametrize(
    ("key", "value", "as_json"),
    [
        ("guardrail.connectors.kiro.hook_fail_mode", "closed", False),
        ("guardrail.connectors.codex.rule_pack", "default", False),
        ("guardrail.connectors.kiro.enabled", "true", False),
        ("guardrail.connectors", "{\"kiro\": {}}", True),
        ("guardrail", "{\"enabled\": true, \"connectors\": {\"kiro\": {}}}", True),
    ],
)
def test_root_config_command_refuses_first_entry_beside_implicit_openclaw(
    tmp_path: Path, key: str, value: str, as_json: bool
) -> None:
    """The top-level config command loads no config (app.cfg is None); the file decides."""
    from defenseclaw.main import cli

    path = tmp_path / "config.yaml"
    path.write_text(
        f"config_version: 9\ndata_dir: {tmp_path}\nguardrail:\n{_IMPLICIT_OPENCLAW}", encoding="utf-8"
    )
    before = path.read_bytes()
    with (
        patch.object(dcconfig, "config_path", return_value=path),
        patch.object(config_writer, "_use_go_validator", return_value=False),
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
        patch.object(cmd_config, "_refresh_stopped_gateway_hooks", return_value=[]),
    ):
        result = CliRunner().invoke(cli, ["config", "set", key, value, *(["--json"] if as_json else [])])
    assert result.exit_code != 0
    assert "openclaw needs a proxy binding" in result.output
    assert path.read_bytes() == before


def test_root_config_command_hook_roster_without_primary_stays_editable(tmp_path: Path) -> None:
    """Benign twin: a hook-only roster that names no primary keeps its ordinary edits."""
    from defenseclaw.main import cli

    path = tmp_path / "config.yaml"
    path.write_text(
        f"config_version: 9\ndata_dir: {tmp_path}\nguardrail:\n  connectors:\n    kiro: {{}}\n    codex: {{}}\n",
        encoding="utf-8",
    )
    before = path.read_bytes()
    with (
        patch.object(dcconfig, "config_path", return_value=path),
        patch.object(config_writer, "_use_go_validator", return_value=False),
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
        patch.object(cmd_config, "_refresh_stopped_gateway_hooks", return_value=[]),
    ):
        result = CliRunner().invoke(cli, ["config", "set", "guardrail.connectors.codex.hook_fail_mode", "closed"])
    assert result.exit_code == 0, result.output
    assert path.read_bytes() != before


def _root_config(tmp_path: Path, guardrail: str, *args: str):
    from defenseclaw.main import cli

    path = tmp_path / "config.yaml"
    path.write_text(f"config_version: 9\ndata_dir: {tmp_path}\nguardrail:\n{guardrail}", encoding="utf-8")
    before = path.read_bytes()
    with (
        patch.object(dcconfig, "config_path", return_value=path),
        patch.object(config_writer, "_use_go_validator", return_value=False),
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
        patch.object(cmd_config, "_refresh_stopped_gateway_hooks", return_value=[]),
    ):
        result = CliRunner().invoke(cli, ["config", *args])
    return result, before, path.read_bytes()


@pytest.mark.parametrize(
    ("guardrail", "args"),
    [
        # A disabled hook entry beside a proxy still makes the gateway choose the shared boot (REVIEW-10).
        ("  enabled: true\n  connector: openclaw\n  connectors:\n    openclaw: {}\n",
         ["set", "guardrail.connectors.kiro.enabled", "false"]),
        ("  enabled: true\n  connector: zeptoclaw\n  connectors:\n    zeptoclaw: {}\n",
         ["set", "guardrail.connectors.codex.enabled", "false"]),
        ("  enabled: true\n  connector: openclaw\n  connectors:\n    kiro:\n      enabled: false\n",
         ["set", "guardrail.connectors.openclaw", "{}", "--json"]),
        ("  enabled: true\n  connector: openclaw\n  connectors:\n    openclaw: {}\n",
         ["set", "guardrail.connectors", '{"openclaw": {}, "kiro": {"enabled": false}}', "--json"]),
    ],
)
def test_root_config_command_refuses_disabled_hook_entry_beside_proxy(
    tmp_path: Path, guardrail: str, args: list[str]
) -> None:
    result, before, after = _root_config(tmp_path, guardrail, *args)
    assert result.exit_code != 0
    assert "needs a proxy binding" in result.output
    assert "A disabled entry under guardrail.connectors still counts" in result.output
    assert after == before


@pytest.mark.parametrize(
    "args",
    [
        ["set", "guardrail.connectors.kiro.hook_fail_mode", "closed"],
        ["set", "guardrail.connectors.openclaw.hook_fail_mode", "closed"],
        ["unset", "guardrail.connectors.openclaw"],
    ],
)
def test_root_config_command_hook_primary_with_disabled_proxy_entry_stays_editable(
    tmp_path: Path, args: list[str]
) -> None:
    """Benign twin: a hook primary beside a disabled proxy entry boots the hook connector alone."""
    result, before, after = _root_config(
        tmp_path,
        "  enabled: true\n  connector: kiro\n  connectors:\n    kiro: {}\n    openclaw:\n      enabled: false\n",
        *args,
    )
    assert result.exit_code == 0, result.output
    assert after != before
