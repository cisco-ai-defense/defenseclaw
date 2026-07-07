from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from defenseclaw import config as dcconfig
from defenseclaw import fail_mode as fail_mode_runtime
from defenseclaw.commands import cmd_guardrail
from defenseclaw.context import AppContext
from defenseclaw.fail_mode import resolve_connector_fail_mode


@pytest.fixture(autouse=True)
def _clear_global_fail_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEFENSECLAW_FAIL_MODE", raising=False)
    monkeypatch.setattr("defenseclaw.fail_mode._windows_registration_freshness", lambda *_args: None)


def _runtime_cfg(tmp_path: Path, modes: dict[str, str]) -> tuple[SimpleNamespace, Path]:
    data_dir = tmp_path / "data"
    home = tmp_path / "home"
    (data_dir / "hooks").mkdir(parents=True)
    (home / ".claude").mkdir(parents=True)
    (home / ".codex").mkdir(parents=True)

    guardrail = dcconfig.GuardrailConfig()
    guardrail.enabled = True
    guardrail.hook_fail_mode = "open"
    guardrail.connectors = {}
    for name, mode in modes.items():
        guardrail.connectors[name] = dcconfig.PerConnectorGuardrailConfig(hook_fail_mode=mode)
    cfg = SimpleNamespace(
        data_dir=str(data_dir),
        guardrail=guardrail,
        gateway=SimpleNamespace(host="127.0.0.1", port=18789),
    )
    cfg.active_connector = lambda: sorted(modes)[0]
    cfg.active_connectors = lambda: sorted(modes)
    cfg.save = MagicMock()
    return cfg, home


def _write_current_runtime(cfg: SimpleNamespace, home: Path, modes: dict[str, str]) -> None:
    hook_dir = Path(cfg.data_dir) / "hooks"
    launcher_path = home / ".local" / "bin" / "defenseclaw-hook.exe"
    launcher_path.parent.mkdir(parents=True, exist_ok=True)
    launcher_body = b"MZfixture-launcher"
    launcher_path.write_bytes(launcher_body)
    (hook_dir / ".hookcfg").write_text(
        json.dumps({"version": 2, "gateway_addr": "127.0.0.1:18970", "fail_modes": modes}),
        encoding="utf-8",
    )
    (home / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {"PreToolUse": [{"command": "defenseclaw hook --connector claudecode"}]},
                "env": {"DEFENSECLAW_FAIL_MODE": modes.get("claudecode", "open")},
            }
        ),
        encoding="utf-8",
    )
    (home / ".codex" / "config.toml").write_text(
        '[hooks]\ndefenseclaw = "defenseclaw hook --connector codex"\n', encoding="utf-8"
    )
    entries = {}
    for name, mode in modes.items():
        script_name = "claude-code-hook.sh" if name == "claudecode" else f"{name}-hook.sh"
        script_path = hook_dir / script_name
        script_body = f'FAIL_MODE="${{DEFENSECLAW_FAIL_MODE:-{mode}}}"\n'.encode()
        script_path.write_bytes(script_body)
        config_path = home / (".claude/settings.json" if name == "claudecode" else ".codex/config.toml")
        entries[name] = {
            "connector": name,
            "contract_id": "claudecode-hooks-v1" if name == "claudecode" else "codex-hooks-v1",
            "compatibility_status": "known",
            "hook_script_version": "v6",
            "hook_script_digests": {
                script_name: "sha256:" + hashlib.sha256(script_body).hexdigest(),
                launcher_path.name: "sha256:" + hashlib.sha256(launcher_body).hexdigest(),
            },
            "locations": {
                "hook_config_paths": [str(config_path)],
                "hook_script_paths": [str(script_path), str(launcher_path)],
            },
            "hook_fail_mode": mode,
        }
    (Path(cfg.data_dir) / "hook_contract_lock.json").write_text(
        json.dumps(
            {
                "version": 1,
                "connectors": entries,
            }
        ),
        encoding="utf-8",
    )


def test_windows_resolver_reports_effective_mixed_modes(tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "closed", "codex": "open"})
    with patch("defenseclaw.fail_mode.os.name", "nt"), patch("defenseclaw.fail_mode.Path.home", return_value=home):
        claude = resolve_connector_fail_mode(cfg, "claudecode")
        codex = resolve_connector_fail_mode(cfg, "codex")
    assert claude.current and claude.runtime == "closed"
    assert codex.current and codex.runtime == "open"


def test_windows_resolver_initial_open_open_and_reverse_mixed_mode(tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(tmp_path, {"claudecode": "open", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "open", "codex": "open"})
    with patch("defenseclaw.fail_mode.os.name", "nt"), patch("defenseclaw.fail_mode.Path.home", return_value=home):
        assert resolve_connector_fail_mode(cfg, "claudecode").current
        assert resolve_connector_fail_mode(cfg, "codex").current

        cfg.guardrail.connectors["codex"].hook_fail_mode = "closed"
        _write_current_runtime(cfg, home, {"claudecode": "open", "codex": "closed"})
        claude = resolve_connector_fail_mode(cfg, "claudecode")
        codex = resolve_connector_fail_mode(cfg, "codex")
    assert claude.current and claude.runtime == "open"
    assert codex.current and codex.runtime == "closed"


def test_cli_status_reports_effective_mixed_modes_without_drift(tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "closed", "codex": "open"})
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    with patch("defenseclaw.fail_mode.os.name", "nt"), patch("defenseclaw.fail_mode.Path.home", return_value=home):
        result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
    assert result.exit_code == 0, result.output
    assert "Claude Code" in result.output and "closed" in result.output
    assert "Codex" in result.output and "open" in result.output
    assert "runtime fail-mode drift" not in result.output


def test_stale_persisted_closed_runtime_open_is_not_current(tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "open", "codex": "open"})
    with patch("defenseclaw.fail_mode.os.name", "nt"), patch("defenseclaw.fail_mode.Path.home", return_value=home):
        state = resolve_connector_fail_mode(cfg, "claudecode")
    assert not state.current
    assert state.desired == "closed"
    assert state.runtime == "open"
    assert "claude-env-open" in state.drift


def test_stale_closed_never_reports_already_closed(tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "open", "codex": "open"})
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    with (
        patch("defenseclaw.fail_mode.os.name", "nt"),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
        patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration") as reconcile,
    ):
        result = CliRunner().invoke(
            cmd_guardrail.fail_mode_cmd,
            ["closed", "--connector", "claudecode", "--yes"],
            obj=app,
        )
    assert result.exit_code == 0, result.output
    assert "already" not in result.output
    assert "Reconciling" in result.output
    reconcile.assert_called_once()


def test_raw_global_closed_observe_runtime_open_creates_scoped_override(tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(tmp_path, {"claudecode": "open", "codex": "open"})
    cfg.guardrail.hook_fail_mode = "closed"
    cfg.guardrail.connectors["claudecode"].hook_fail_mode = ""
    _write_current_runtime(cfg, home, {"claudecode": "open", "codex": "open"})
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    with (
        patch("defenseclaw.fail_mode.os.name", "nt"),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
        patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration") as reconcile,
    ):
        before = resolve_connector_fail_mode(cfg, "claudecode")
        result = CliRunner().invoke(
            cmd_guardrail.fail_mode_cmd,
            ["closed", "--connector", "claudecode", "--yes"],
            obj=app,
        )
    assert before.desired == "open" and before.current
    assert result.exit_code == 0, result.output
    assert "already" not in result.output
    assert cfg.guardrail.connectors["claudecode"].hook_fail_mode == "closed"
    assert cfg.guardrail.connectors["codex"].hook_fail_mode == "open"
    reconcile.assert_called_once_with(cfg, "claudecode")


def test_legacy_hookcfg_is_runtime_fallback_but_requires_migration(tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(tmp_path, {"codex": "open"})
    (Path(cfg.data_dir) / "hooks" / ".hookcfg").write_text(
        "DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:18970\nDEFENSECLAW_FAIL_MODE=open\n",
        encoding="utf-8",
    )
    (home / ".codex" / "config.toml").write_text(
        '[hooks]\ndefenseclaw = "defenseclaw hook --connector codex"\n', encoding="utf-8"
    )
    with patch("defenseclaw.fail_mode.os.name", "nt"), patch("defenseclaw.fail_mode.Path.home", return_value=home):
        state = resolve_connector_fail_mode(cfg, "codex")
    assert state.runtime == "open"
    assert not state.current
    assert any(reason.startswith("windows-sidecar-legacy") for reason in state.drift)


def test_scoped_reconcile_failure_rolls_back_config_and_registration(tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(tmp_path, {"claudecode": "open", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "open", "codex": "open"})
    original_settings = (home / ".claude" / "settings.json").read_bytes()
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()

    def fail_after_partial_write(_cfg: object, _connector: str) -> None:
        (home / ".claude" / "settings.json").write_text('{"partial":true}', encoding="utf-8")
        raise OSError("setup failed")

    with (
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
        patch(
            "defenseclaw.commands.cmd_guardrail.reconcile_connector_registration",
            side_effect=fail_after_partial_write,
        ),
    ):
        result = CliRunner().invoke(
            cmd_guardrail.fail_mode_cmd,
            ["closed", "--connector", "claudecode", "--yes"],
            obj=app,
        )
    assert result.exit_code != 0
    assert cfg.guardrail.connectors["claudecode"].hook_fail_mode == "open"
    assert (home / ".claude" / "settings.json").read_bytes() == original_settings
    assert "restored" in result.output


def test_truthful_noop_requires_current_runtime(tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "closed", "codex": "open"})
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    with (
        patch("defenseclaw.fail_mode.os.name", "nt"),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
        patch("defenseclaw.commands.cmd_guardrail.resolve_connector_fail_mode") as resolver,
        patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration") as reconcile,
    ):
        resolver.return_value = resolve_connector_fail_mode(cfg, "claudecode")
        result = CliRunner().invoke(
            cmd_guardrail.fail_mode_cmd,
            ["closed", "--connector", "claudecode", "--yes"],
            obj=app,
        )
    assert result.exit_code == 0
    assert "nothing to do" in result.output
    reconcile.assert_not_called()
    cfg.save.assert_not_called()


def test_stale_registered_script_digest_rejects_noop(tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "closed", "codex": "open"})
    (Path(cfg.data_dir) / "hooks" / "claude-code-hook.sh").write_text("stale launcher", encoding="utf-8")
    with patch("defenseclaw.fail_mode.os.name", "nt"), patch("defenseclaw.fail_mode.Path.home", return_value=home):
        state = resolve_connector_fail_mode(cfg, "claudecode")
    assert not state.current
    assert "registration-digest-stale" in state.drift


def test_stale_windows_launcher_digest_rejects_noop(tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "closed", "codex": "open"})
    (home / ".local" / "bin" / "defenseclaw-hook.exe").write_bytes(b"MZstale-launcher")
    with patch("defenseclaw.fail_mode.os.name", "nt"), patch(
        "defenseclaw.fail_mode.Path.home", return_value=home
    ):
        state = resolve_connector_fail_mode(cfg, "claudecode")
    assert not state.current
    assert "registration-digest-stale" in state.drift


def test_unix_registration_freshness_requires_current_script_path(tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(tmp_path, {"claudecode": "closed"})
    settings_path = home / ".claude" / "settings.json"
    settings_path.write_text(
        json.dumps({"hooks": {"PreToolUse": [{"command": "/stale/claude-code-hook.sh"}]}}),
        encoding="utf-8",
    )
    with patch("defenseclaw.fail_mode.Path.home", return_value=home):
        assert fail_mode_runtime._unix_registration_freshness(cfg, "claudecode") == "registration-command-stale"
        expected = str((Path(cfg.data_dir) / "hooks" / "claude-code-hook.sh").resolve())
        settings_path.write_text(
            json.dumps({"hooks": {"PreToolUse": [{"command": expected}]}}),
            encoding="utf-8",
        )
        assert fail_mode_runtime._unix_registration_freshness(cfg, "claudecode") is None
