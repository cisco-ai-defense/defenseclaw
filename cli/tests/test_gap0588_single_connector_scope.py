"""Single-connector guardrail scope and config writer regressions."""

from __future__ import annotations

import json
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import yaml
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
    tmp_path: Path, app: AppContext, roster: str, key: str, value: str, *, as_json: bool = False, head: str = ""
) -> tuple[object, bytes, bytes]:
    path = tmp_path / "config.yaml"
    path.write_text(
        f"config_version: 9\ndata_dir: {tmp_path}\n{head}guardrail:\n{roster}", encoding="utf-8"
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
        ("kiro", "  connector: kiro\n  connectors:\n    kiro: {}\n", "guardrail.connectors.openclaw.enabled", "false"),
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


@pytest.mark.parametrize(
    ("roster", "key", "value", "as_json"),
    [
        (
            "  connector: openclaw\n",
            "guardrail.connectors.kiro.hook_fail_mode", "open", False,
        ),
        (
            "  enabled: true\n",
            "guardrail.connectors.kiro.hook_fail_mode", "open", False,
        ),
        (
            "  connector: kiro\n  connectors:\n    kiro: {}\n    codex:\n      enabled: false\n",
            "guardrail.connectors.codex.enabled", "true", False,
        ),
        (
            "  connector: kiro\n  connectors:\n    kiro: {}\n    codex: {}\n",
            "guardrail.connectors.codex.enabled", "false", False,
        ),
        (
            "  connector: kiro\n  connectors:\n    kiro: {}\n    codex: {}\n",
            "guardrail.connectors", '{"kiro": {}}', True,
        ),
        (
            "  connector: kiro\n  connectors:\n    kiro: {}\n",
            "guardrail.connectors.codex.enabled", "true", False,
        ),
        (
            "  connector: kiro\n  connectors:\n    kiro: {}\n",
            "guardrail.connectors.codex", '{"enabled": true}', True,
        ),
        (
            "  connector: claudecode\n",
            "guardrail.connectors", '{"codex": {"enabled": false}}', True,
        ),
        (
            "  connector: claudecode\n",
            "guardrail.connectors.claudecode.enabled", "false", False,
        ),
        (
            "  connector: kiro\n  connectors:\n    kiro: {}\n",
            "guardrail.connectors", '{"kiro": {}, "codex": {}}', True,
        ),
        (
            "  connector: kiro\n  connectors:\n    kiro: {}\n",
            "guardrail", '{"connector": "kiro", "connectors": {"kiro": {}, "codex": {}}}', True,
        ),
        (
            "  connector: kiro\n  connectors:\n    kiro: {}\n    codex: {}\n",
            "guardrail.connector", "codex", False,
        ),
    ],
)
def test_config_set_does_not_change_active_connector_selection(
    tmp_path: Path, roster: str, key: str, value: str, as_json: bool
) -> None:
    app = _app(tmp_path, ["openclaw" if "openclaw" in roster else "kiro"])
    result, before, after = _set_in_file(tmp_path, app, roster, key, value, as_json=as_json)
    assert result.exit_code != 0
    assert "connector selection requires setup" in result.output
    assert after == before


_CLAUDE = "  enabled: true\n  connector: claudecode\n"
_CLAUDE_OFF_ROSTER = _CLAUDE + "  connectors:\n    codex: {}\n"


def _with_setting(document: dict, key: str, value: object) -> dict:
    node = document
    *parents, last = key.split(".")
    for part in parents:
        node = node.setdefault(part, {})
    node[last] = value
    return document


@pytest.mark.parametrize(
    ("head", "roster", "key", "value"),
    [
        # The gateway still boots the primary that guardrail.connector names, alone.
        ("", "  connector: claudecode\n", "guardrail.connectors.codex.hook_fail_mode", "closed"),
        ("", "  connector: claudecode\n", "guardrail.connectors.codex", {"hook_fail_mode": "closed"}),
        ("", "  enabled: true\n  connector: kiro\n", "guardrail.connectors.cursor.rules.enable", ["ALLOW"]),
        # GAP-0588 review 3: an agent-gateway route or an automatic source
        # keeps every enable signal the Go hook gate reads.
        (
            "connectors:\n  agent_gateway:\n    enabled: true\n", "  enabled: true\n  connector: kiro\n",
            "guardrail.connectors.agent-gateway.hook_fail_mode", "closed",
        ),
        (
            "application_protection:\n  enabled: true\n", "  enabled: true\n  connector: kiro\n",
            "guardrail.connectors.claudecode.hook_fail_mode", "closed",
        ),
    ],
)
def test_config_set_of_an_off_roster_setting_writes_only_that_key(
    tmp_path: Path, head: str, roster: str, key: str, value: object
) -> None:
    # GAP-0588 lead ruling r4: the set succeeds and writes that key alone. No
    # enabled field and no other roster entry is written, the primary stays,
    # and the Go hook gate reads the same enable signals as before.
    app = _app(tmp_path, ["kiro"])
    as_json = not isinstance(value, str)
    result, before, after = _set_in_file(
        tmp_path, app, roster, key, json.dumps(value) if as_json else value, as_json=as_json, head=head
    )
    assert result.exit_code == 0, result.output
    assert yaml.safe_load(after) == _with_setting(yaml.safe_load(before), key, value)


@pytest.mark.parametrize(
    ("head", "roster", "key"),
    [
        # The primary comes from roster order or claw.mode: the new entry would become it.
        ("", "  connectors:\n    kiro: {}\n", "guardrail.connectors.codex.hook_fail_mode"),
        ("claw:\n  mode: codex\n", "  enabled: true\n", "guardrail.connectors.kiro.hook_fail_mode"),
        ("claw:\n  mode: kiro\n", "  enabled: true\n", "guardrail.connectors.codex.hook_fail_mode"),
        # A proxy primary is guarded only from the roster; a disabled primary guards nothing.
        ("", "  connector: openclaw\n", "guardrail.connectors.kiro.hook_fail_mode"),
        (
            "", "  connector: openclaw\n  connectors:\n    openclaw:\n      enabled: false\n",
            "guardrail.connectors.kiro.hook_fail_mode",
        ),
        (
            "", "  connector: kiro\n  connectors:\n    kiro:\n      enabled: false\n",
            "guardrail.connectors.codex.hook_fail_mode",
        ),
        ("", "  connector: kiro\n", "guardrail.connectors.openclaw.hook_fail_mode"),
    ],
)
def test_config_set_of_an_off_roster_setting_that_would_select_it_is_refused(
    tmp_path: Path, head: str, roster: str, key: str
) -> None:
    # GAP-0588: writing that key alone would select the connector or leave the
    # primary unguarded, so the set is refused and config.yaml keeps its bytes.
    app = _app(tmp_path, ["kiro"])
    result, before, after = _set_in_file(tmp_path, app, roster, key, "closed", head=head)
    assert result.exit_code != 0
    assert "connector selection requires setup" in result.output
    assert after == before


@pytest.mark.parametrize(
    ("head", "roster", "key", "value"),
    [
        # GAP-0588 review 4: a second roster key selects the multi-connector
        # boot, which sets up only the roster and drops the named primary.
        ("", _CLAUDE_OFF_ROSTER, "guardrail.connectors.kiro.hook_fail_mode", "closed"),
        ("", _CLAUDE_OFF_ROSTER, "guardrail.connectors.kiro", {"hook_fail_mode": "closed"}),
        ("", _CLAUDE_OFF_ROSTER, "guardrail.connectors.cursor.rules.enable", ["ALLOW"]),
        ("", _CLAUDE_OFF_ROSTER, "guardrail.connectors.kiro.enabled", False),
        ("", _CLAUDE_OFF_ROSTER, "guardrail.connectors.claudecode.hook_fail_mode", "closed"),
        (
            "", "  enabled: true\n  connector: kiro\n  connectors:\n    codex: {}\n",
            "guardrail.connectors.claude_code.hook_fail_mode", "closed",
        ),
        # ... or sets up the new connector beside the primary.
        ("", "  connector: kiro\n  connectors:\n    kiro: {}\n", "guardrail.connectors.codex.hook_fail_mode", "closed"),
        ("", "  connector: kiro\n  connectors:\n    kiro: {}\n", "guardrail.connectors.codex", {"hook_fail_mode": "closed"}),
        (
            "", "  connector: claudecode\n  connectors:\n    claudecode: {}\n",
            "guardrail.connectors.codex.rules.enable", ["ALLOW"],
        ),
        (
            "application_protection:\n  enabled: true\n",
            "  enabled: true\n  connector: kiro\n  connectors:\n    kiro: {}\n",
            "guardrail.connectors.cursor", {"hook_fail_mode": "closed"},
        ),
    ],
)
def test_config_set_that_would_change_what_the_gateway_boots_is_refused(
    tmp_path: Path, head: str, roster: str, key: str, value: object
) -> None:
    # The gateway boots the same connectors after any config edit, so the
    # primary keeps its hooks and no other connector is set up.
    app = _app(tmp_path, ["kiro"])
    as_json = not isinstance(value, str)
    result, before, after = _set_in_file(
        tmp_path, app, roster, key, json.dumps(value) if as_json else value, as_json=as_json, head=head
    )
    assert result.exit_code != 0
    assert "connector selection requires setup" in result.output
    assert after == before


def _cli_in_file(path: Path, monkeypatch, verb: str, *args: str) -> object:
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(path))
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=path),
        patch.object(config_writer, "_use_go_validator", return_value=False),
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
        patch.object(cmd_config, "_refresh_stopped_gateway_hooks", return_value=[]),
    ):
        command = cmd_config.config_set if verb == "set" else cmd_config.config_unset
        return CliRunner().invoke(command, list(args))


def test_config_unset_removes_the_off_roster_entry_a_set_stored(tmp_path: Path, monkeypatch) -> None:
    # GAP-0588 review 4: set stores the entry and a whole-entry unset removes it.
    path = tmp_path / "config.yaml"
    path.write_text(f"config_version: 9\ndata_dir: {tmp_path}\nguardrail:\n{_CLAUDE}", encoding="utf-8")
    before = path.read_bytes()
    stored = _cli_in_file(path, monkeypatch, "set", "guardrail.connectors.codex.hook_fail_mode", "closed")
    assert stored.exit_code == 0, stored.output
    removed = _cli_in_file(path, monkeypatch, "unset", "guardrail.connectors.codex")
    assert removed.exit_code == 0, removed.output
    assert yaml.safe_load(path.read_bytes()) == yaml.safe_load(before)


def test_config_edits_keep_the_gateway_on_the_named_primary(tmp_path: Path, monkeypatch) -> None:
    # GAP-0588 review 4: CLI edits alone cannot reach a roster that boots
    # without the primary guardrail.connector names.
    path = tmp_path / "config.yaml"
    path.write_text(f"config_version: 9\ndata_dir: {tmp_path}\nguardrail:\n{_CLAUDE}", encoding="utf-8")
    before = yaml.safe_load(path.read_bytes())
    rule = "guardrail.connectors.codex.rules.enable"
    assert _cli_in_file(path, monkeypatch, "set", rule, '["ALLOW"]', "--json").exit_code == 0
    assert _cli_in_file(path, monkeypatch, "unset", rule).exit_code == 0
    staged = path.read_bytes()
    assert yaml.safe_load(staged)["guardrail"]["connectors"] == {"codex": {}}
    refused = _cli_in_file(path, monkeypatch, "set", "guardrail.connectors.kiro.hook_fail_mode", "closed")
    assert refused.exit_code != 0
    assert "connector selection requires setup" in refused.output
    assert path.read_bytes() == staged
    removed = _cli_in_file(path, monkeypatch, "unset", "guardrail.connectors.codex")
    assert removed.exit_code == 0, removed.output
    assert yaml.safe_load(path.read_bytes()) == before


@pytest.mark.parametrize(
    ("key", "value", "as_json"),
    [
        ("guardrail.connectors.codex.hook_fail_mode", "closed", False),
        ("guardrail.connectors.codex", '{"hook_fail_mode": "closed"}', True),
        ("guardrail.connector", "codex", False),
        ("guardrail.connectors", '{"codex": {"hook_fail_mode": "closed"}}', True),
    ],
)
def test_config_set_of_the_claw_mode_primary_itself_stays_available(
    tmp_path: Path, key: str, value: str, as_json: bool
) -> None:
    # Benign twin (GAP-1953): an edit that names the selected connector itself may give it its entry.
    app = _app(tmp_path, ["codex"])
    result, before, after = _set_in_file(
        tmp_path, app, "  enabled: true\n", key, value, as_json=as_json, head="claw:\n  mode: codex\n"
    )
    assert result.exit_code == 0, result.output
    assert after != before


def test_config_unset_of_a_stored_setting_keeps_the_roster_as_it_was(tmp_path: Path) -> None:
    app = _app(tmp_path, ["claudecode"])
    roster = (
        "  connector: claudecode\n  connectors:\n    claudecode: {}\n"
        "    codex:\n      hook_fail_mode: closed\n"
    )
    result, _before, after = _unset_in_file(tmp_path, app, roster, "guardrail.connectors.codex")
    assert result.exit_code == 0, result.output
    assert yaml.safe_load(after)["guardrail"]["connectors"] == {"claudecode": {}}


def test_config_set_existing_connector_setting_stays_available(tmp_path: Path) -> None:
    app = _app(tmp_path, ["kiro"])
    result, before, after = _set_in_file(
        tmp_path, app,
        "  connector: kiro\n  connectors:\n    kiro: {}\n",
        "guardrail.connectors.kiro.hook_fail_mode", "closed",
    )
    assert result.exit_code == 0, result.output
    assert after != before


def test_config_set_claw_mode_keeps_selected_connector(tmp_path: Path) -> None:
    app = _app(tmp_path, ["kiro"])
    path = tmp_path / "config.yaml"
    path.write_text(
        f"config_version: 9\ndata_dir: {tmp_path}\nclaw:\n  mode: kiro\nguardrail: {{}}\n",
        encoding="utf-8",
    )
    before = path.read_bytes()
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=path),
        patch.object(config_writer, "_use_go_validator", return_value=False),
    ):
        result = CliRunner().invoke(cmd_config.config_set, ["claw.mode", "codex"], obj=app)
    assert result.exit_code != 0
    assert "connector selection requires setup" in result.output
    assert path.read_bytes() == before


@pytest.mark.parametrize("batch", [False, True])
def test_config_unset_does_not_activate_disabled_hook_entry(tmp_path: Path, batch: bool) -> None:
    app = _app(tmp_path, ["kiro"])
    roster = (
        "  connector: kiro\n  hook_fail_mode: closed\n  connectors:\n"
        "    kiro: {}\n    codex:\n      enabled: false\n"
    )
    keys = ["guardrail.connectors.codex.enabled"]
    if batch:
        keys.insert(0, "guardrail.hook_fail_mode")
    result, before, after = _unset_in_file(tmp_path, app, roster, *keys)
    assert result.exit_code != 0
    assert "connector selection requires setup" in result.output
    assert after == before


def test_config_unset_keeps_primary_with_existing_roster(tmp_path: Path) -> None:
    app = _app(tmp_path, ["kiro", "codex"])
    roster = "  connector: kiro\n  connectors:\n    kiro: {}\n    codex: {}\n"
    result, before, after = _unset_in_file(tmp_path, app, roster, "guardrail.connector")
    assert result.exit_code != 0
    assert "connector selection requires setup" in result.output
    assert after == before


@pytest.mark.parametrize(
    ("roster", "keys"),
    [
        (
            "  connector: kiro\n  connectors:\n    kiro: {}\n    codex:\n      enabled: false\n",
            ("guardrail.connectors.kiro", "guardrail.connectors.codex.enabled"),
        ),
        (
            "  connector: kiro\n  connectors:\n    codex:\n      enabled: false\n",
            ("guardrail.connector",),
        ),
        (
            "  connector: codex\n  connectors:\n    codex:\n      enabled: false\n",
            ("guardrail.connectors.codex.enabled",),
        ),
    ],
)
def test_config_unset_rejects_selection_or_enable_change_without_retained_enabled_entry(
    tmp_path: Path, roster: str, keys: tuple[str, ...]
) -> None:
    app = _app(tmp_path, ["kiro"])
    result, before, after = _unset_in_file(tmp_path, app, roster, *keys)
    assert result.exit_code != 0
    assert "connector selection requires setup" in result.output
    assert after == before


@pytest.mark.parametrize(
    ("roster", "key", "value"),
    [
        (
            "  connectors:\n    kiro:\n      enabled: false\n",
            "guardrail.connectors.codex.hook_fail_mode", "closed",
        ),
        (
            "  connector: openclaw\n  connectors:\n    openclaw:\n      enabled: false\n",
            "guardrail.connectors.kiro.hook_fail_mode", "closed",
        ),
        (
            "  connector: claudecode\n  connectors:\n    claudecode: {}\n",
            "guardrail.connector", "claude",
        ),
        (
            "  connector: claudecode\n  connectors:\n    claudecode: {}\n",
            "guardrail.connectors.claude.hook_fail_mode", "closed",
        ),
    ],
)
def test_config_set_uses_runtime_connector_names_and_selection(
    tmp_path: Path, roster: str, key: str, value: str
) -> None:
    app = _app(tmp_path, ["kiro"])
    result, before, after = _set_in_file(tmp_path, app, roster, key, value)
    assert result.exit_code != 0
    assert "connector selection requires setup" in result.output
    assert after == before


def test_config_unset_removed_disabled_entry_keeps_selection(tmp_path: Path) -> None:
    app = _app(tmp_path, ["kiro"])
    roster = (
        "  connector: kiro\n  connectors:\n    kiro: {}\n"
        "    codex:\n      enabled: false\n"
    )
    result, before, after = _unset_in_file(tmp_path, app, roster, "guardrail.connectors.codex")
    assert result.exit_code == 0, result.output
    assert after != before


def test_config_unset_disabled_hook_setting_stays_available(tmp_path: Path) -> None:
    app = _app(tmp_path, ["kiro"])
    roster = (
        "  connector: kiro\n  connectors:\n    kiro: {}\n"
        "    codex:\n      enabled: false\n      hook_fail_mode: closed\n"
    )
    result, before, after = _unset_in_file(
        tmp_path, app, roster, "guardrail.connectors.codex.hook_fail_mode"
    )
    assert result.exit_code == 0, result.output
    assert after != before


def test_secure_client_roster_check_keeps_existing_scope(tmp_path: Path) -> None:
    candidate = (
        b"config_version: 9\ndeployment_mode: managed_enterprise\n"
        b"enterprise:\n  profile: secure_client\nguardrail:\n"
        b"  connectors:\n    kiro: {}\n    openclaw: {}\n"
    )
    cmd_config._check_guardrail_connector_roster(str(tmp_path / "config.yaml"), candidate)
