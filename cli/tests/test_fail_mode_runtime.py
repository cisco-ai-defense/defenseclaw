from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner
from defenseclaw import config as dcconfig
from defenseclaw import fail_mode as fail_mode_runtime
from defenseclaw.commands import cmd_doctor, cmd_guardrail
from defenseclaw.context import AppContext
from defenseclaw.doctor_hooks import _HERMES_REQUIRED_HOOKS
from defenseclaw.fail_mode import (
    ConnectorFailModeState,
    connector_fail_mode_report,
    resolve_connector_fail_mode,
)

from tests.fail_mode_tier import policy_tier_follows_the_saved_fail_mode  # noqa: F401 - autouse fixture

_WINDOWS_REGISTRATION_FRESHNESS = fail_mode_runtime._windows_registration_freshness


def test_current_amp_bridge_reports_the_live_outage_tier(tmp_path: Path) -> None:
    """A stopped gateway can leave an earlier plugin render on disk."""
    plugin = tmp_path / "defenseclaw.ts"
    plugin.write_text(
        '// defenseclaw-call-time-outage-v1\nconst DC_FAIL_MODE: string = "closed"\n',
        encoding="utf-8",
    )
    selected = {"mode": "closed"}
    guardrail = SimpleNamespace(effective_hook_outage_fail_mode=lambda _name: selected["mode"])
    cfg = SimpleNamespace(guardrail=guardrail)

    assert fail_mode_runtime._read_amp_plugin_mode(plugin, cfg) == "closed"
    selected["mode"] = "open"
    assert fail_mode_runtime._read_amp_plugin_mode(plugin, cfg) == "open"


def test_current_opencode_bridge_reports_the_live_outage_tier(tmp_path: Path) -> None:
    plugin = tmp_path / "defenseclaw.js"
    plugin.write_text(
        '// defenseclaw-call-time-outage-v1\nconst DC_FAIL_MODE = "closed";\n',
        encoding="utf-8",
    )
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"connectors": {"opencode": {"locations": {"hook_config_paths": [str(plugin)]}}}}),
        encoding="utf-8",
    )
    selected = {"mode": "closed"}
    guardrail = SimpleNamespace(effective_hook_outage_fail_mode=lambda _name: selected["mode"])
    cfg = SimpleNamespace(data_dir=str(tmp_path), guardrail=guardrail)

    assert fail_mode_runtime._read_opencode_plugin_mode(cfg) == "closed"
    selected["mode"] = "open"
    assert fail_mode_runtime._read_opencode_plugin_mode(cfg) == "open"


def test_current_shell_helper_reports_the_live_outage_tier(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    (hooks / "codex-hook.sh").write_text('FAIL_MODE="closed"\n', encoding="utf-8")
    (hooks / "_hardening.sh").write_text("# defenseclaw-call-time-outage-v1\n", encoding="utf-8")
    selected = {"mode": "closed"}
    guardrail = SimpleNamespace(effective_hook_outage_fail_mode=lambda _name: selected["mode"])
    cfg = SimpleNamespace(data_dir=str(tmp_path), deployment_mode="", guardrail=guardrail)
    monkeypatch.setattr(fail_mode_runtime, "_is_windows", lambda: False)

    assert fail_mode_runtime._platform_runtime_source(cfg, "codex") == ("hook-script", "closed")
    selected["mode"] = "open"
    assert fail_mode_runtime._platform_runtime_source(cfg, "codex") == ("hook-script", "open")

# The fail-mode lines of real per-user Unix hook renders; the Go test
# TestUnixHookFailModeLinesMatchTheSharedGolden checks them against Setup.
_HOOK_FAIL_MODE_LINES = json.loads(
    (
        Path(__file__).resolve().parents[2] / "internal/gateway/connector/testdata/unix_hook_fail_mode_lines.json"
    ).read_text(encoding="utf-8")
)

# The hooks/.hookcfg bodies the Go test TestReadHookSidecarSharedVectors runs
# through the native hook's reader (readHookSidecar).
_WINDOWS_SIDECAR_VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "internal/cli/testdata/windows_hook_sidecar_vectors.json").read_text(
        encoding="utf-8"
    )
)["vectors"]


def _legacy_open_hook_lines(script: str) -> list[str]:
    """Model an older rendered hook that still contains an open mode."""
    return [
        line.replace('FAIL_MODE="closed"', 'FAIL_MODE="open"')
        if line.startswith('FAIL_MODE="closed"') else line
        for line in _HOOK_FAIL_MODE_LINES[f"{script}/closed"]
    ]

_SHARED_HOOK_SCRIPTS = (
    "inspect-tool.sh",
    "inspect-request.sh",
    "inspect-response.sh",
    "inspect-tool-response.sh",
    "_hardening.sh",
)


@pytest.fixture(autouse=True)
def _clear_global_fail_mode(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("DEFENSECLAW_FAIL_MODE", raising=False)
    monkeypatch.setattr("defenseclaw.fail_mode._windows_registration_freshness", lambda *_args: None)
    if sys.platform == "win32":
        # These fixtures model baked runtime mode and lock digests, not native
        # agent hook files. The real registration is checked in the Windows
        # doctor and hook-integrity suites.
        monkeypatch.setattr("defenseclaw.fail_mode.registration_integrity_drift", lambda *_args: [])
    yield


def _runtime_cfg(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    modes: dict[str, str],
) -> tuple[SimpleNamespace, Path]:
    data_dir = tmp_path / "data"
    home = tmp_path / "home"
    (data_dir / "hooks").mkdir(parents=True)
    (home / ".claude").mkdir(parents=True)
    (home / ".codex").mkdir(parents=True)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home / ".claude"))
    monkeypatch.setenv("CODEX_HOME", str(home / ".codex"))

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
    (home / ".codex" / "managed_config.toml").write_text(
        '[hooks]\ndefenseclaw = "defenseclaw hook --connector codex"\n', encoding="utf-8"
    )
    shared_digests = {}
    for script_name in _SHARED_HOOK_SCRIPTS:
        script_body = f"canonical shared hook: {script_name}\n".encode()
        (hook_dir / script_name).write_bytes(script_body)
        # Setup installs hook scripts 0700; a script the agent cannot run is drift (w20).
        (hook_dir / script_name).chmod(0o700)
        shared_digests[script_name] = "sha256:" + hashlib.sha256(script_body).hexdigest()
    entries = {}
    for name, mode in modes.items():
        script_name = "claude-code-hook.sh" if name == "claudecode" else f"{name}-hook.sh"
        script_path = hook_dir / script_name
        script_body = ("\n".join(_HOOK_FAIL_MODE_LINES[f"{script_name}/{mode}"]) + "\n").encode()
        script_path.write_bytes(script_body)
        script_path.chmod(0o700)
        config_path = home / (".claude/settings.json" if name == "claudecode" else ".codex/managed_config.toml")
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
                "version": 2,
                "shared_hook_script_digests": shared_digests,
                "connectors": entries,
            }
        ),
        encoding="utf-8",
    )


def _write_current_amp_runtime(
    cfg: SimpleNamespace,
    plugin_path: Path,
    mode: str,
) -> None:
    plugin_path.parent.mkdir(parents=True, exist_ok=True)
    plugin_body = (
        "// defenseclaw-managed-plugin v2\n"
        f'const DC_FAIL_MODE: string = "{mode}"\n'
        'const endpoint = "/api/v1/amp/hook"\n'
        'amp.on("session.start", () => {})\n'
        'amp.on("agent.start", () => {})\n'
        'amp.on("tool.call", () => {})\n'
        'amp.on("tool.result", () => {})\n'
        'amp.on("agent.end", () => {})\n'
    ).encode()
    plugin_path.write_bytes(plugin_body)
    entry = {
        "connector": "amp",
        "contract_id": "amp-plugin-v1",
        "compatibility_status": "known",
        "hook_script_version": "v2",
        "hook_script_digests": {
            "defenseclaw.ts": "sha256:" + hashlib.sha256(plugin_body).hexdigest(),
        },
        "locations": {
            "hook_config_paths": [str(plugin_path)],
            "hook_script_paths": [str(plugin_path)],
        },
        "hook_fail_mode": mode,
    }
    (Path(cfg.data_dir) / "hook_contract_lock.json").write_text(
        json.dumps({"version": 2, "connectors": {"amp": entry}}),
        encoding="utf-8",
    )


@pytest.mark.parametrize("windows", [False, True])
def test_amp_runtime_is_resolved_from_baked_plugin_on_every_platform(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    windows: bool,
) -> None:
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"amp": "closed"})
    plugin_path = tmp_path / "amp-home" / "plugins" / "defenseclaw.ts"
    _write_current_amp_runtime(cfg, plugin_path, "closed")
    monkeypatch.setattr("defenseclaw.fail_mode.amp_policy_plugin_path", lambda: str(plugin_path))
    monkeypatch.setattr("defenseclaw.fail_mode._is_windows", lambda: windows)

    state = resolve_connector_fail_mode(cfg, "amp")

    assert state.current
    assert state.runtime == "closed"
    assert state.provenance == "amp-plugin"
    assert dict(state.sources)["registration-lock"] == "closed"
    assert state.drift == ()


def test_amp_runtime_ignores_invoking_process_fail_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"amp": "closed"})
    plugin_path = tmp_path / "amp-home" / "plugins" / "defenseclaw.ts"
    _write_current_amp_runtime(cfg, plugin_path, "closed")
    monkeypatch.setattr("defenseclaw.fail_mode.amp_policy_plugin_path", lambda: str(plugin_path))
    monkeypatch.setenv("DEFENSECLAW_FAIL_MODE", "open")

    state = resolve_connector_fail_mode(cfg, "amp")

    assert state.current
    assert state.runtime == "closed"
    assert all(source != "process-env" for source, _mode in state.sources)


def test_amp_runtime_reports_plugin_and_digest_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"amp": "closed"})
    plugin_path = tmp_path / "amp-home" / "plugins" / "defenseclaw.ts"
    _write_current_amp_runtime(cfg, plugin_path, "closed")
    monkeypatch.setattr("defenseclaw.fail_mode.amp_policy_plugin_path", lambda: str(plugin_path))
    plugin_path.write_text(
        plugin_path.read_text(encoding="utf-8").replace(
            'const DC_FAIL_MODE: string = "closed"',
            'const DC_FAIL_MODE: string = "open"',
        ),
        encoding="utf-8",
    )

    state = resolve_connector_fail_mode(cfg, "amp")

    assert not state.current
    assert state.runtime == "open"
    assert "amp-plugin-open" in state.drift
    assert "registration-digest-stale" in state.drift


def test_amp_runtime_requires_exact_five_callback_registration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"amp": "closed"})
    plugin_path = tmp_path / "amp-home" / "plugins" / "defenseclaw.ts"
    _write_current_amp_runtime(cfg, plugin_path, "closed")
    monkeypatch.setattr("defenseclaw.fail_mode.amp_policy_plugin_path", lambda: str(plugin_path))
    plugin_path.write_text(
        plugin_path.read_text(encoding="utf-8").replace('amp.on("tool.result"', 'amp.on("tool.output"'),
        encoding="utf-8",
    )

    state = resolve_connector_fail_mode(cfg, "amp")

    assert not state.current
    assert "registration-command-stale" in state.drift
    assert "registration-digest-stale" in state.drift


def test_scoped_amp_fail_mode_refreshes_plugin_registration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # The strict tier (closed) with a plugin still rendered open.
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"amp": "closed", "codex": "closed"})
    plugin_path = tmp_path / "amp-home" / "plugins" / "defenseclaw.ts"
    _write_current_amp_runtime(cfg, plugin_path, "open")
    monkeypatch.setattr("defenseclaw.fail_mode.amp_policy_plugin_path", lambda: str(plugin_path))
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()

    with patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration") as reconcile:
        result = CliRunner().invoke(
            cmd_guardrail.fail_mode_cmd,
            ["closed", "--connector", "amp", "--yes"],
            obj=app,
        )

    assert result.exit_code == 0, result.output
    assert cfg.guardrail.connectors["amp"].hook_fail_mode == "closed"
    reconcile.assert_called_once_with(cfg, "amp")


def test_global_amp_fail_mode_refreshes_plugin_registration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # The strict tier (closed) with a plugin still rendered open.
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"amp": "closed"})
    cfg.guardrail.hook_fail_mode = "closed"
    plugin_path = tmp_path / "amp-home" / "plugins" / "defenseclaw.ts"
    _write_current_amp_runtime(cfg, plugin_path, "open")
    monkeypatch.setattr("defenseclaw.fail_mode.amp_policy_plugin_path", lambda: str(plugin_path))
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()

    with patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration") as reconcile:
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app)

    assert result.exit_code == 0, result.output
    assert cfg.guardrail.hook_fail_mode == "closed"
    assert cfg.guardrail.connectors["amp"].hook_fail_mode == "closed"
    reconcile.assert_called_once_with(cfg, "amp")


def _write_opencode_runtime(
    cfg: SimpleNamespace,
    tmp_path: Path,
    *,
    plugin_mode: str,
    lock_mode: str,
) -> Path:
    plugin_path = tmp_path / "opencode" / "plugins" / "defenseclaw.js"
    plugin_path.parent.mkdir(parents=True)
    plugin_path.write_text(
        f'const DC_FAIL_MODE = "{plugin_mode}";\n',
        encoding="utf-8",
    )
    Path(cfg.data_dir).mkdir(parents=True, exist_ok=True)
    (Path(cfg.data_dir) / "hook_contract_lock.json").write_text(
        json.dumps(
            {
                "version": 1,
                "connectors": {
                    "opencode": {
                        "connector": "opencode",
                        "contract_id": "opencode-hooks-v1",
                        "hook_fail_mode": lock_mode,
                        "locations": {"hook_config_paths": [str(plugin_path)]},
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return plugin_path


def test_fail_mode_state_reports_effective_provenance() -> None:
    state = ConnectorFailModeState(
        connector="codex",
        desired="open",
        configured="open",
        runtime="closed",
        sources=(
            ("config", "open"),
            ("windows-sidecar", "closed"),
            ("claude-env", "open"),
            ("registration-lock", "open"),
        ),
        drift=("windows-sidecar-closed",),
    )

    report = state.to_report()

    assert report["effective"] == "closed"
    # Claude Code's settings env is registration evidence, never the source
    # of the runtime mode: no hook reads a fail mode from its environment.
    assert report["provenance"] == "windows-sidecar"
    assert report["configured"] == "open"
    assert report["drift"] == ["windows-sidecar-closed"]
    assert report["note"] == ""
    assert "caller_env" not in report

    # The per-user default-tier outage mode can differ from the saved value.
    observe = ConnectorFailModeState(
        connector="claudecode",
        desired="open",
        configured="closed",
        runtime="open",
        sources=(("config", "closed"), ("hook-script", "open"), ("claude-env", "open")),
        drift=(),
        deployment="per-user",
        policy_tier="default",
    ).to_report()
    assert observe["effective"] == "open" and observe["drift"] == []
    assert (
        observe["note"] == "the default per-user policy tier keeps gateway outages fail-open; "
        "guardrail.hook_fail_mode=closed does not control hook failures here"
    )


def test_closed_per_user_hook_note_does_not_claim_observe_mode() -> None:
    # A saved open preference on a per-user action-mode host is overridden by
    # the closed hook rule. Status must name that rule, not observe mode.
    state = ConnectorFailModeState(
        connector="codex",
        desired="closed",
        configured="open",
        runtime="closed",
        sources=(("config", "open"), ("hook-script", "closed")),
        drift=(),
        deployment="per-user",
    )
    report = state.to_report()
    assert report["effective"] == "closed"
    assert report["note"] == (
        "this per-user deployment keeps hooks fail-closed; "
        "guardrail.hook_fail_mode=open does not control hook failures here"
    )


@pytest.mark.parametrize(
    ("deployment", "tier", "configured", "desired", "reason"),
    [
        ("per-user", "default", "closed", "open", "the default per-user policy tier keeps gateway outages fail-open"),
        ("per-user", "strict", "open", "closed", "the strict per-user policy tier keeps gateway outages fail-closed"),
        ("managed", "default", "open", "closed", "managed application protection selects hooks fail-closed"),
        ("secure-client", "default", "closed", "open", "Secure Client policy selects hooks fail-open"),
    ],
)
def test_fail_mode_note_names_deployment_and_tier_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    deployment: str,
    tier: str,
    configured: str,
    desired: str,
    reason: str,
) -> None:
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"cursor": ""})
    cfg.guardrail.hook_fail_mode = configured
    cfg.guardrail.effective_hook_fail_mode = lambda _name: desired
    cfg.guardrail.hook_policy_tier = lambda _name: tier
    cfg.managed_outside_secure_client = lambda: deployment == "managed"
    cfg.guardrail.secure_client_hook_fail_modes = lambda: deployment == "secure-client"
    monkeypatch.setattr(fail_mode_runtime, "_platform_runtime_source", lambda _cfg, _name: ("hook-script", desired))

    state = resolve_connector_fail_mode(cfg, "cursor")

    assert state.desired == desired
    assert state.effective == desired
    assert state.note == (
        f"{reason}; guardrail.hook_fail_mode={configured} does not control hook failures here"
    )


def test_opencode_fail_mode_uses_baked_plugin_and_ignores_process_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"opencode": "closed"})
    _write_opencode_runtime(cfg, tmp_path, plugin_mode="closed", lock_mode="closed")
    monkeypatch.setenv("DEFENSECLAW_FAIL_MODE", "open")

    state = resolve_connector_fail_mode(cfg, "opencode")

    assert state.current
    assert state.effective == "closed"
    assert state.provenance == "opencode-plugin"
    assert ("process-env", "open") not in state.sources


def test_opencode_fail_mode_reports_managed_plugin_drift(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"opencode": "closed"})
    _write_opencode_runtime(cfg, tmp_path, plugin_mode="open", lock_mode="closed")

    state = resolve_connector_fail_mode(cfg, "opencode")

    assert not state.current
    assert state.effective == "open"
    assert state.provenance == "opencode-plugin"
    assert "opencode-plugin-open" in state.drift


def test_connector_fail_mode_report_uses_disposable_windows_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"codex": "closed"})
    _write_current_runtime(cfg, home, {"codex": "closed"})

    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        report = connector_fail_mode_report(cfg, "codex")

    assert report["effective"] == "closed"
    assert report["provenance"] == "windows-sidecar"
    assert report["current"] is True


@pytest.mark.parametrize("connector", ["antigravity", "copilot", "hermes"])
def test_native_deny_connector_reports_the_mode_its_hook_renders(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    connector: str,
) -> None:
    # A per-user Copilot CLI, Antigravity or Hermes hook follows its fail
    # mode: closed blocks every failure DefenseClaw sees, and the report names
    # the vendor limit it keeps.
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {connector: "closed"})
    monkeypatch.setattr(fail_mode_runtime, "_is_windows", lambda: False)
    monkeypatch.setattr(fail_mode_runtime, "_native_deny_registration_freshness", lambda *_args: None, raising=False)
    _register_native_deny_hook(monkeypatch, cfg, home, connector)
    script = f"{connector}-hook.sh"
    hook = Path(cfg.data_dir) / "hooks" / script
    if connector != "hermes":
        # Hermes' read-back also seals and executes the registered script;
        # the fixture above already installed its closed, probed render.
        hook.write_text("\n".join(_HOOK_FAIL_MODE_LINES[f"{script}/closed"]) + "\n", encoding="utf-8")

    report = connector_fail_mode_report(cfg, connector)

    assert report["configured"] == "closed"
    assert report["effective"] == "closed"
    assert report["runtime"] == "closed"
    assert report["provenance"] == "hook-script"
    assert report["current"] is True
    label = {"antigravity": "Antigravity", "copilot": "Copilot", "hermes": "Hermes"}[connector]
    assert report["note"] == (
        f"DefenseClaw failures block; {label} itself lets a call run when the hook times out or cannot start"
    )

    # A hook rendered open while config says closed is drift, so doctor and
    # verify report it instead of passing.
    hook.write_text("\n".join(_legacy_open_hook_lines(script)) + "\n", encoding="utf-8")
    report = connector_fail_mode_report(cfg, connector)
    assert report["effective"] == "open"
    assert report["desired"] == "closed"
    assert report["current"] is False
    assert report["drift"] == (
        # Hermes seals its script in the contract lock: the open rewrite is
        # also an edit of the sealed hook (registration_integrity_drift). The
        # sealed-script runtime check (hook_runtime_problems) reads POSIX
        # scripts only, so a Windows host simulating this hook never runs it.
        ["registration-digest-stale", *(["hook-runtime-stale"] if os.name != "nt" else []), "hook-script-open"]
        if connector == "hermes"
        else ["hook-script-open"]
    )
    assert report["note"] == ""


@pytest.mark.parametrize("connector", ["antigravity", "copilot", "hermes"])
def test_native_deny_connector_reads_the_windows_hookcfg(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    connector: str,
) -> None:
    # r104 W3 G3-upg: the per-user hooks print the agent's native denial for
    # their own failures in fail mode closed, so they are no upstream
    # fail-open (Secure Client still is).
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {connector: "closed"})
    (Path(cfg.data_dir) / "hooks" / ".hookcfg").write_text(
        json.dumps({"version": 2, "gateway_addr": "127.0.0.1:18970", "fail_modes": {connector: "open"}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(fail_mode_runtime, "_is_windows", lambda: True)

    report = connector_fail_mode_report(cfg, connector)

    assert report["runtime"] == "open"
    assert "windows-sidecar-open" in report["drift"]


@pytest.mark.parametrize("connector", ["antigravity", "copilot", "hermes"])
def test_secure_client_native_deny_connector_stays_upstream_fail_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    connector: str,
) -> None:
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {connector: "closed"})
    cfg.deployment_mode = "managed_enterprise"
    cfg.managed_outside_secure_client = lambda: False

    report = connector_fail_mode_report(cfg, connector)

    assert report["configured"] == "closed"
    assert report["effective"] == "open"
    assert report["runtime"] == "open"
    assert report["provenance"] == f"{connector}-upstream-fail-open"
    assert report["current"] is True
    assert report["sources"][-1] == {"name": f"{connector}-upstream", "mode": "open"}


def test_windows_registration_freshness_uses_authenticated_packaged_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    data_dir = tmp_path / "data"
    install_root = tmp_path / "Programs" / "DefenseClaw"
    codex_home = tmp_path / "Configured Codex Home"
    observed: dict[str, str] = {}

    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    monkeypatch.setattr(
        "defenseclaw.doctor_hooks._packaged_windows_install_root",
        lambda value: str(install_root) if value == str(data_dir) else None,
    )

    def validate(**kwargs: str) -> SimpleNamespace:
        observed.update(kwargs)
        return SimpleNamespace(healthy=True, state="current")

    monkeypatch.setattr("defenseclaw.doctor_hooks.validate_windows_hook_registration", validate)
    cfg = SimpleNamespace(data_dir=str(data_dir))

    assert _WINDOWS_REGISTRATION_FRESHNESS(cfg, "codex") is None
    assert observed["install_root"] == str(install_root)
    # Current Codex ignores CODEX_HOME/managed_config.toml on Windows, so a
    # per-user install is checked at config.toml and a managed-layer
    # registration is reported stale.
    assert observed["config_path"] == str(codex_home / "config.toml")
    assert observed["codex_per_user"] is True


def test_windows_registration_freshness_surfaces_codex_effective_policy_block(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    data_dir = tmp_path / "data"
    observed: dict[str, str] = {}

    def validate(**kwargs: str) -> SimpleNamespace:
        observed.update(kwargs)
        return SimpleNamespace(healthy=False, state="policy-blocked")

    monkeypatch.setattr("defenseclaw.doctor_hooks.validate_windows_hook_registration", validate)
    cfg = SimpleNamespace(data_dir=str(data_dir))

    drift = _WINDOWS_REGISTRATION_FRESHNESS(cfg, "codex")

    assert drift == "registration-policy-blocked"
    assert observed["connector"] == "codex"


@pytest.mark.parametrize(
    ("states", "expected", "attempts"),
    [
        (["access-denied", "current"], None, 2),
        (["access-denied"] * 5, "registration-access-denied", 5),
        (["policy-blocked"], "registration-policy-blocked", 1),
    ],
)
def test_windows_registration_freshness_retries_access_denied_without_accepting_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, states: list[str], expected: str | None, attempts: int
) -> None:
    checks = iter(states)
    validate = MagicMock(
        side_effect=lambda **_kwargs: SimpleNamespace(healthy=(state := next(checks)) == "current", state=state)
    )
    waits: list[float] = []
    monkeypatch.setattr("defenseclaw.doctor_hooks.validate_windows_hook_registration", validate)
    monkeypatch.setattr("time.sleep", waits.append)

    assert _WINDOWS_REGISTRATION_FRESHNESS(SimpleNamespace(data_dir=str(tmp_path)), "claudecode") == expected
    assert validate.call_count == attempts
    assert len(waits) == attempts - 1 and sum(waits) <= 2
    if expected:
        monkeypatch.setattr("defenseclaw.fail_mode.shutil.which", lambda _name: str(tmp_path / "gateway.exe"))
        monkeypatch.setattr(
            "defenseclaw.fail_mode.subprocess.run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0)
        )
        monkeypatch.setattr(
            "defenseclaw.fail_mode.resolve_connector_fail_mode",
            lambda *_args: SimpleNamespace(current=False, connector="claudecode", drift=(expected,)),
        )
        with pytest.raises(OSError, match="defenseclaw doctor"):
            fail_mode_runtime.reconcile_connector_registration(SimpleNamespace(data_dir=str(tmp_path)), "claudecode")


def test_windows_codex_presence_uses_native_registration_validator(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"codex": "open"})
    _write_current_runtime(cfg, home, {"codex": "open"})
    (home / ".codex" / "managed_config.toml").write_text(
        '[[hooks.SessionStart]]\ncommand = "defenseclaw hook --connector codex"\n',
        encoding="utf-8",
    )

    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch(
            "defenseclaw.fail_mode._codex_registration_current",
            side_effect=AssertionError("legacy text probe must not own Windows managed registration"),
        ),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        state = resolve_connector_fail_mode(cfg, "codex")

    assert "registration-missing" not in state.drift


def test_windows_resolver_reports_effective_mixed_modes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "closed", "codex": "open"})
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        claude = resolve_connector_fail_mode(cfg, "claudecode")
        codex = resolve_connector_fail_mode(cfg, "codex")
    # Each connector runs its own tier's outage mode (oss-outage-open).
    assert claude.current and claude.runtime == "closed"
    assert codex.current and codex.desired == "open" and codex.runtime == "open"


def test_windows_resolver_accepts_sealed_claude_v2_contract(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed"})
    _write_current_runtime(cfg, home, {"claudecode": "closed"})
    lock_path = Path(cfg.data_dir) / "hook_contract_lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["connectors"]["claudecode"]["contract_id"] = "claudecode-hooks-v2"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        state = resolve_connector_fail_mode(cfg, "claudecode")

    assert state.current
    assert "registration-contract-stale" not in state.drift


def test_windows_resolver_initial_open_open_and_reverse_mixed_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "open", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "open", "codex": "open"})
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        # The default tier's open is current (oss-outage-open).
        assert resolve_connector_fail_mode(cfg, "claudecode").current
        assert resolve_connector_fail_mode(cfg, "codex").current

        cfg.guardrail.connectors["codex"].hook_fail_mode = "closed"
        _write_current_runtime(cfg, home, {"claudecode": "open", "codex": "closed"})
        claude = resolve_connector_fail_mode(cfg, "claudecode")
        codex = resolve_connector_fail_mode(cfg, "codex")
    assert claude.current and claude.runtime == "open" and claude.desired == "open"
    assert codex.current and codex.runtime == "closed"


def test_cli_status_reports_old_open_mode_as_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed", "codex": "open"})
    # Codex's tier gives open, but its installed hook still records closed.
    _write_current_runtime(cfg, home, {"claudecode": "closed", "codex": "closed"})
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
    assert result.exit_code == 0, result.output
    assert "Claude Code" in result.output and "closed" in result.output
    assert "Codex" in result.output and "open" in result.output
    assert "runtime fail-mode drift" in result.output


def test_stale_persisted_closed_runtime_open_is_not_current(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "open", "codex": "open"})
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        state = resolve_connector_fail_mode(cfg, "claudecode")
    assert not state.current
    assert state.desired == "closed"
    assert state.runtime == "open"
    # The sidecar is the stale carrier; the settings env is no input of the
    # native hook (round h), so it is not reported.
    assert "windows-sidecar-open" in state.drift
    assert "claude-env-open" not in state.drift


def test_stale_closed_never_reports_already_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "open", "codex": "open"})
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
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


@pytest.mark.parametrize("windows", [False, True])
def test_same_mode_command_repairs_malformed_shared_fail_map(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, windows: bool
) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed", "codex": "closed"})
    _write_current_runtime(cfg, home, {"claudecode": "closed", "codex": "closed"})
    sidecar = Path(cfg.data_dir) / "hooks" / ".hookcfg"
    body = json.loads(sidecar.read_text(encoding="utf-8"))
    body["fail_modes"] = None
    sidecar.write_text(json.dumps(body), encoding="utf-8")
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=windows),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
        patch("defenseclaw.fail_mode._codex_registration_current", return_value=True),
        patch("defenseclaw.fail_mode._unix_registration_freshness", return_value=None),
        patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration") as reconcile,
    ):
        state = resolve_connector_fail_mode(cfg, "codex")
        result = CliRunner().invoke(
            cmd_guardrail.fail_mode_cmd, ["closed", "--connector", "codex", "--yes"], obj=app
        )
    assert "shared-sidecar-malformed" in state.drift
    assert "nothing to do" not in result.output
    assert result.exit_code == 0, result.output
    reconcile.assert_called_once_with(cfg, "codex")


def test_secure_client_unset_global_runtime_open_creates_scoped_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "open", "codex": "open"})
    cfg.guardrail.hook_fail_mode = ""
    cfg.guardrail.connectors["claudecode"].hook_fail_mode = ""
    # Under Secure Client an unset fail mode is open (#1163).
    cfg.guardrail._secure_client = True
    _write_current_runtime(cfg, home, {"claudecode": "open", "codex": "open"})
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
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


def test_legacy_hookcfg_is_runtime_fallback_but_requires_migration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"codex": "open"})
    (Path(cfg.data_dir) / "hooks" / ".hookcfg").write_text(
        "DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:18970\nDEFENSECLAW_FAIL_MODE=open\n",
        encoding="utf-8",
    )
    (home / ".codex" / "config.toml").write_text(
        '[hooks]\ndefenseclaw = "defenseclaw hook --connector codex"\n', encoding="utf-8"
    )
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        state = resolve_connector_fail_mode(cfg, "codex")
    assert state.runtime == "open"
    assert not state.current
    assert any(reason.startswith("windows-sidecar-legacy") for reason in state.drift)


def test_scoped_reconcile_failure_rolls_back_config_and_registration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Claude Code in the strict tier with its hook still rendered open.
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "open", "codex": "open"})
    original_settings = (home / ".claude" / "settings.json").read_bytes()
    tracked_paths = [
        Path(cfg.data_dir) / "hook_contract_lock.json",
        Path(cfg.data_dir) / "hooks" / ".hookcfg",
        *(Path(cfg.data_dir) / "hooks" / name for name in _SHARED_HOOK_SCRIPTS),
    ]
    original_runtime = {path: path.read_bytes() for path in tracked_paths}
    config_yaml = dcconfig.config_path_for_data_dir(cfg.data_dir)
    config_yaml.write_text("config_version: 9\n", encoding="utf-8")
    concurrent = b"config_version: 9\nasset_policy: {}\n"
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()

    def fail_after_partial_write(_cfg: object, _connector: str) -> None:
        # Another writer commits config.yaml while the refresh runs.
        config_yaml.write_bytes(concurrent)
        (home / ".claude" / "settings.json").write_text('{"partial":true}', encoding="utf-8")
        for path in tracked_paths:
            path.write_text("partial reconciliation", encoding="utf-8")
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
    assert cfg.guardrail.connectors["claudecode"].hook_fail_mode == "closed"
    assert (home / ".claude" / "settings.json").read_bytes() == original_settings
    assert {path: path.read_bytes() for path in tracked_paths} == original_runtime
    assert "restored" in result.output
    # The rollback is a second save through the single writer, never a raw
    # copy of the snapshot over the other writer's commit (GAP-0303).
    assert cfg.save.call_count == 2
    assert config_yaml.read_bytes() == concurrent


def test_truthful_noop_requires_current_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "closed", "codex": "open"})
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
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


def test_stale_registered_script_digest_rejects_noop(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "closed", "codex": "open"})
    (Path(cfg.data_dir) / "hooks" / "claude-code-hook.sh").write_text("stale launcher", encoding="utf-8")
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        state = resolve_connector_fail_mode(cfg, "claudecode")
    assert not state.current
    assert "registration-digest-stale" in state.drift


def test_stale_windows_launcher_digest_rejects_noop(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "closed", "codex": "open"})
    (home / ".local" / "bin" / "defenseclaw-hook.exe").write_bytes(b"MZstale-launcher")
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        state = resolve_connector_fail_mode(cfg, "claudecode")
    assert not state.current
    assert "registration-digest-stale" in state.drift


def test_runtime_digest_hashes_raw_windows_binary_bytes(tmp_path: Path) -> None:
    artifact = tmp_path / "runtime.bin"
    body = b"MZ\r\nraw-before\x1araw-after\r\n"
    artifact.write_bytes(body)
    assert fail_mode_runtime._sha256_regular_file(artifact) == "sha256:" + hashlib.sha256(body).hexdigest()


def test_runtime_digest_hashes_a_launcher_larger_than_128_mib(tmp_path: Path) -> None:
    # GAP-1922: a source-built defenseclaw-hook.exe is about 148 MiB.
    artifact = tmp_path / "defenseclaw-hook.exe"
    size = 150 * 1024 * 1024
    with artifact.open("wb") as stream:
        stream.truncate(size)
    digest = hashlib.sha256()
    chunk = bytes(1024 * 1024)
    for _ in range(size // len(chunk)):
        digest.update(chunk)
    assert fail_mode_runtime._sha256_regular_file(artifact) == "sha256:" + digest.hexdigest()


def test_v2_shared_digest_is_authoritative_over_legacy_entry_duplicate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "closed", "codex": "open"})
    lock_path = Path(cfg.data_dir) / "hook_contract_lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["connectors"]["claudecode"]["hook_script_digests"]["inspect-tool.sh"] = "sha256:legacy-stale"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        state = resolve_connector_fail_mode(cfg, "claudecode")
    assert state.current


def test_divergent_v1_shared_digests_require_controlled_migration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "open", "codex": "open"})
    _write_current_runtime(cfg, home, {"claudecode": "open", "codex": "open"})
    lock_path = Path(cfg.data_dir) / "hook_contract_lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    shared = lock.pop("shared_hook_script_digests")
    lock["version"] = 1
    for name, entry in lock["connectors"].items():
        for script_name, digest in shared.items():
            entry["hook_script_digests"][script_name] = digest if name == "codex" else "sha256:divergent"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        claude = resolve_connector_fail_mode(cfg, "claudecode")
        codex = resolve_connector_fail_mode(cfg, "codex")
    assert "registration-shared-digest-divergent" in claude.drift
    assert "registration-shared-digest-divergent" in codex.drift


def test_single_connector_v1_shared_digests_remain_compatible(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed"})
    _write_current_runtime(cfg, home, {"claudecode": "closed"})
    lock_path = Path(cfg.data_dir) / "hook_contract_lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    shared = lock.pop("shared_hook_script_digests")
    lock["version"] = 1
    lock["connectors"]["claudecode"]["hook_script_digests"].update(shared)
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        state = resolve_connector_fail_mode(cfg, "claudecode")
    assert state.current


def test_single_connector_v1_missing_shared_digests_is_stale(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed"})
    _write_current_runtime(cfg, home, {"claudecode": "closed"})
    lock_path = Path(cfg.data_dir) / "hook_contract_lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock.pop("shared_hook_script_digests")
    lock["version"] = 1
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        state = resolve_connector_fail_mode(cfg, "claudecode")
    assert "registration-shared-digests-missing" in state.drift


@pytest.mark.parametrize("version", [True, 2.5, 3])
def test_unsupported_contract_lock_version_is_stale(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, version: object
) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed"})
    _write_current_runtime(cfg, home, {"claudecode": "closed"})
    lock_path = Path(cfg.data_dir) / "hook_contract_lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["version"] = version
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        state = resolve_connector_fail_mode(cfg, "claudecode")
    expected = "registration-lock-version-unsupported" if version == 3 else "registration-lock-malformed"
    assert expected in state.drift


def test_unix_registration_freshness_requires_current_script_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed"})
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


@pytest.mark.parametrize(
    ("connector", "script"),
    [("claudecode", "claude-code-hook.sh"), ("codex", "codex-hook.sh"), ("devin", "devin-hook.sh")],
)
def test_unix_registration_freshness_checks_each_connectors_own_script(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, connector: str, script: str
) -> None:
    # GAP-0027: a current Devin registration was reported stale because the
    # check looked for codex-hook.sh in it.
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {connector: "closed"})
    with (
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
        patch("defenseclaw.connector_paths.Path.home", return_value=home),
    ):
        registration = Path(fail_mode_runtime.connector_config_files(connector, workspace_dir="")[0])
        registration.parent.mkdir(parents=True, exist_ok=True)
        registration.write_text(json.dumps({"command": "/stale/" + script}), encoding="utf-8")
        assert fail_mode_runtime._unix_registration_freshness(cfg, connector) == "registration-command-stale"
        current = str((Path(cfg.data_dir) / "hooks" / script).resolve())
        registration.write_text(json.dumps({"command": current}), encoding="utf-8")
        assert fail_mode_runtime._unix_registration_freshness(cfg, connector) is None


def test_global_fail_mode_leaves_a_stopped_gateway_stopped_and_lists_effective_modes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # GAP-1370: under Secure Client connectors with an unset fail mode
    # already run fail-open (#1163), and a mixed roster (hermes has no
    # runtime registration) must not start a stopped gateway.
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "", "hermes": ""})
    cfg.guardrail.hook_fail_mode = ""
    cfg.guardrail._secure_client = True
    cfg.deployment_mode = "managed_enterprise"
    cfg.managed_outside_secure_client = lambda: False
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    with (
        patch("defenseclaw.commands.cmd_guardrail._gateway_running", return_value=False),
        patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration") as reconcile,
        patch("defenseclaw.commands.cmd_setup._restart_services") as restart,
    ):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["open", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    restart.assert_not_called()
    reconcile.assert_called_once_with(cfg, "claudecode")
    assert "closed → open" not in result.output
    # Neither connector is listed as a closed -> open change: both already
    # resolve open.
    assert "Hermes (hermes): " in result.output
    assert "left stopped" in result.output and "defenseclaw-gateway start" in result.output
    assert cfg.guardrail.connectors["hermes"].hook_fail_mode == "open"


def test_fail_mode_help_and_docs_describe_registration_refresh() -> None:
    result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["--help"])
    assert result.exit_code == 0, result.output
    help_text = " ".join(result.output.split())
    docs = " ".join(
        (Path(__file__).resolve().parents[2] / "docs-site/content/docs/reference/configuration/fail-modes.mdx")
        .read_text(encoding="utf-8").split()
    )
    persisted = docs.split("## Persisted fail mode", 1)[1].split("## ", 1)[0]
    for text in (help_text, persisted):
        assert "runtime registrations" in text and "refresh" in text
        assert "--restart" in text and "--no-restart" in text
        assert "stopped gateway" in text
        assert "restarts the gateway so" not in text
        assert "restarts the gateway by default" not in text


def test_fail_mode_change_list_matches_status_runtime_and_cursor_contract(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # GAP-1370: the change list shows the installed runtime value that
    # guardrail status shows. The guardrail mode no longer pins Cursor's fail
    # mode: it changes like every other connector.
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"codex": "", "cursor": ""})
    cfg.deployment_mode = "managed_enterprise"
    cfg.managed_outside_secure_client = lambda: True
    # The resolver reads the managed profile from the config that owns the
    # guardrail (sa-port-peer: only a managed config may keep an open).
    cfg.application_protection = SimpleNamespace(enabled=False)
    cfg.guardrail._owner = lambda: cfg
    cfg.guardrail.hook_fail_mode = "closed"
    cfg.guardrail.mode = "observe"
    cfg.guardrail.connectors["cursor"].mode = "action"
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    stale = SimpleNamespace(runtime="closed", desired="open", current=False, drift=("installed hook",))
    with (
        patch("defenseclaw.commands.cmd_guardrail._gateway_running", return_value=False),
        patch("defenseclaw.commands.cmd_guardrail.resolve_connector_fail_mode", return_value=stale),
        patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration"),
        patch("defenseclaw.commands.cmd_setup._restart_services") as restart,
    ):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["open", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    restart.assert_not_called()
    assert "(codex): closed → open" in result.output or "(codex): closed -> open" in result.output
    assert "(codex): already open" not in result.output
    assert "(cursor): stays closed" not in result.output
    assert "(cursor): closed → open" in result.output or "(cursor): closed -> open" in result.output


def test_rollback_skips_unchanged_immutable_config(tmp_path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("guardrail: {}")
    # Use the mode the filesystem reports: Windows has no 0o644 (it reports 0o666 or read-only 0o444).
    mode = stat.S_IMODE(path.stat().st_mode)
    snapshot = fail_mode_runtime.FileSnapshot(path=path, existed=True, data=path.read_bytes(), mode=mode)
    with patch.object(fail_mode_runtime.os, "replace", side_effect=PermissionError("immutable")) as replace:
        fail_mode_runtime.restore_fail_mode_transaction((snapshot,))
    replace.assert_not_called()


@pytest.mark.parametrize("windows", [False, True])
def test_hermes_reports_its_configured_fail_mode_on_every_os(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    windows: bool,
) -> None:
    # GAP-0150 (Linux, macOS) and GAP-0269 (the Windows native hook): the
    # Hermes hook blocks in fail mode closed, so it is not reported as
    # upstream fail-open.
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"hermes": "closed"})
    monkeypatch.setattr(fail_mode_runtime, "_is_windows", lambda: windows)

    report = connector_fail_mode_report(cfg, "hermes")

    assert report["configured"] == "closed"
    assert report["effective"] == "closed"
    # The native Windows hook fails closed on a missing sidecar, which status
    # names (g-hooks-upg); a missing Unix script falls back to the config.
    assert report["provenance"] == ("no-installed-mode" if windows else "config")
    assert ("windows-sidecar" if windows else "hook-script") + "-missing" in report["drift"]
    assert fail_mode_runtime.upstream_fail_open(cfg, "hermes") is False
    assert fail_mode_runtime.upstream_fail_open(cfg, "copilot") is False


# ── 1.0.4 review (GAP-0315): the environment only tightens ──────────────────


@pytest.mark.parametrize("key", sorted(_HOOK_FAIL_MODE_LINES))
def test_unix_resolver_reads_the_installed_mode_of_a_real_render(key: str, tmp_path: Path) -> None:
    # A 1.0.4 per-user render bakes closed even if an old option requests
    # open; reading it as missing made a refresh fail verification.
    script = tmp_path / "hook.sh"
    script.write_text("#!/bin/bash\n" + "\n".join(_HOOK_FAIL_MODE_LINES[key]) + "\n", encoding="utf-8")
    assert fail_mode_runtime._read_baked_hook_state(script) == ("closed", False)


@pytest.mark.parametrize("mode", ["open", "closed"])
def test_unix_resolver_still_reads_a_legacy_render(mode: str, tmp_path: Path) -> None:
    # 1.0.3 and older renders (and Secure Client renders) keep the override,
    # so the mode read is only their default.
    script = tmp_path / "hook.sh"
    script.write_text(f'#!/bin/bash\nFAIL_MODE="${{DEFENSECLAW_FAIL_MODE:-{mode}}}"\n', encoding="utf-8")
    assert fail_mode_runtime._read_baked_hook_state(script) == (mode, True)


@pytest.mark.parametrize("windows", [False, True])
def test_environment_open_does_not_reopen_a_closed_hook(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, windows: bool
) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed", "codex": "closed"})
    _write_current_runtime(cfg, home, {"claudecode": "closed", "codex": "closed"})
    monkeypatch.setenv("DEFENSECLAW_FAIL_MODE", "open")
    monkeypatch.setattr(fail_mode_runtime, "_codex_registration_current", lambda *_args: True)
    monkeypatch.setattr(fail_mode_runtime, "_unix_registration_freshness", lambda *_args: None)
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=windows),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        states = [resolve_connector_fail_mode(cfg, name) for name in ("claudecode", "codex")]
    for state in states:
        assert state.current, state.drift
        assert state.effective == "closed"
        assert state.provenance != "process-env"
        assert all(source != "process-env" for source, _mode in state.sources)


_DEPLOYMENTS = {
    "per-user": None,
    "managed-standalone": True,
    "secure-client": False,
}


@pytest.mark.parametrize("deployment", sorted(_DEPLOYMENTS))
@pytest.mark.parametrize("env_value", ["open", "closed", "Closed", " CLOSED "])
@pytest.mark.parametrize("installed", ["closed"])
@pytest.mark.parametrize("windows", [False, True])
def test_no_environment_changes_the_reported_fail_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    windows: bool,
    installed: str,
    env_value: str,
    deployment: str,
) -> None:
    # A current closed hook cannot be reopened by the caller's environment,
    # on any deployment or OS. Old open installs are covered as drift below.
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"codex": installed})
    _write_current_runtime(cfg, home, {"codex": installed})
    standalone = _DEPLOYMENTS[deployment]
    if standalone is not None:
        cfg.deployment_mode = "managed_enterprise"
        cfg.managed_outside_secure_client = lambda: standalone
    monkeypatch.setenv("DEFENSECLAW_FAIL_MODE", env_value)
    monkeypatch.setattr(fail_mode_runtime, "_codex_registration_current", lambda *_args: True)
    monkeypatch.setattr(fail_mode_runtime, "_unix_registration_freshness", lambda *_args: None)
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=windows),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        state = resolve_connector_fail_mode(cfg, "codex")
        report = connector_fail_mode_report(cfg, "codex")
    if windows and standalone is not None:
        # A managed native hook runs on the authenticated runtime generation,
        # which status cannot verify: the administrator's mode, unverified.
        assert state.runtime is None and state.effective == installed
        assert "windows-managed-runtime-unverified" in state.drift
        assert not state.runtime_verified and "guardian" in report["note"]
    else:
        assert state.runtime == installed and state.effective == installed
        assert state.provenance == ("windows-sidecar" if windows else "hook-script")
        assert state.current, state.drift
        assert report["note"] == ""
    assert report["effective"] == installed
    assert "caller_env" not in report
    assert not hasattr(fail_mode_runtime, "_inherited_fail_mode")


@pytest.mark.parametrize("windows", [False, True])
def test_the_callers_environment_does_not_hide_an_installed_open_hook(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, windows: bool
) -> None:
    # Config asks for closed, the installed hook is still open: doctor's Mode
    # row fails on effective != desired. A closed caller shell must not turn
    # the report closed and hide that.
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"codex": "closed"})
    _write_current_runtime(cfg, home, {"codex": "open"})
    if not windows:
        script = Path(cfg.data_dir) / "hooks" / "codex-hook.sh"
        script.write_text("\n".join(_legacy_open_hook_lines("codex-hook.sh")) + "\n", encoding="utf-8")
    monkeypatch.setenv("DEFENSECLAW_FAIL_MODE", "closed")
    monkeypatch.setattr(fail_mode_runtime, "_codex_registration_current", lambda *_args: True)
    monkeypatch.setattr(fail_mode_runtime, "_unix_registration_freshness", lambda *_args: None)
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=windows),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        report = connector_fail_mode_report(cfg, "codex")
    assert report["desired"] == "closed"
    assert report["runtime"] == "open" and report["effective"] == "open"
    assert not report["current"]


@pytest.mark.parametrize("installed", ["open", "closed"])
def test_a_missing_windows_sidecar_reports_closed_as_the_native_hook_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, installed: str
) -> None:
    # The native hook reads its mode from hooks/.hookcfg alone and fails
    # closed without it (readHookSidecar). Status reads the same file, so a
    # missing one reports closed, with the drift, whatever config.yaml asks.
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"codex": "open"})
    _write_current_runtime(cfg, home, {"codex": installed})
    (Path(cfg.data_dir) / "hooks" / ".hookcfg").unlink()
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        report = connector_fail_mode_report(cfg, "codex")
    assert report["runtime"] == "closed" and report["effective"] == "closed"
    assert report["provenance"] == "no-installed-mode"
    assert "windows-sidecar-missing" in report["drift"] and not report["current"]


@pytest.mark.parametrize(
    "text",
    [
        "{not json",
        "[]",
        '"open"',
        "true",
        '{"version": 1, "fail_modes": {"codex": "open"}, "legacy_fail_mode": "open"}',
        '{"version": "2", "fail_modes": {"codex": "open"}}',
        '{"version": 2.5, "fail_modes": {"codex": "open"}}',
        '{"version": true, "fail_modes": {"codex": "open"}}',
        '{"fail_modes": {"codex": "open"}}',
        '{"version": 2, "fail_modes": {"codex": "open"}\nDEFENSECLAW_FAIL_MODE=open\n',
        "  {\nDEFENSECLAW_FAIL_MODE=open\n",
    ],
)
def test_windows_sidecar_report_reads_malformed_json_closed_as_the_native_hook_does(
    tmp_path: Path, text: str
) -> None:
    # As readHookSidecar: JSON that does not parse or is not a v2 sidecar is
    # malformed state and closed, never read as KEY=value lines (where a
    # stray DEFENSECLAW_FAIL_MODE=open line would otherwise open it).
    path = tmp_path / ".hookcfg"
    path.write_text(text, encoding="utf-8")
    assert fail_mode_runtime._read_windows_hook_mode(path, "codex") == ("closed", False)


# The connector-scoped key of the 0.8.x KEY=value sidecar (a dynamic name).
_SCOPED_CODEX_KEY = "DEFENSECLAW_FAIL_MODE" + "_CODEX"


@pytest.mark.parametrize(
    "text,want",
    [
        ("DEFENSECLAW_FAIL_MODE=open\n", "open"),
        ("DEFENSECLAW_FAIL_MODE=open\n" + _SCOPED_CODEX_KEY + "=closed\n", "closed"),
        ("export " + _SCOPED_CODEX_KEY + '="open"\nDEFENSECLAW_FAIL_MODE=closed\n', "open"),
        ("DEFENSECLAW_FAIL_MODE=bogus\n", "closed"),
        ("DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:18970\n", None),
    ],
)
def test_windows_flat_sidecar_report_matches_the_native_hook(tmp_path: Path, text: str, want: str | None) -> None:
    # The 0.8.x KEY=value sidecar: the connector's own key comes first, as
    # readHookSidecar reads it. None (no mode) is reported closed by
    # resolve_connector_fail_mode.
    path = tmp_path / ".hookcfg"
    path.write_text(text, encoding="utf-8")
    assert fail_mode_runtime._read_windows_hook_mode(path, "codex") == (want, True)


@pytest.mark.parametrize(
    "text",
    [
        "DEFENSECLAW_FAIL_MODE=open\nDEFENSECLAW_FAIL_MODE=closed\n",
        "DEFENSECLAW_FAIL_MODE=closed\nDEFENSECLAW_FAIL_MODE=open\n",
        "\ufeff{broken\nDEFENSECLAW_FAIL_MODE=open\n",
        "# note\n{broken\nDEFENSECLAW_FAIL_MODE=open\n",
        "not a setting\nDEFENSECLAW_FAIL_MODE=open\n",
    ],
)
def test_windows_sidecar_that_is_not_the_legacy_shape_is_closed(tmp_path: Path, text: str) -> None:
    # 1.0.4 review (loop round 3 of G-hooks-upg): a byte-order mark or a
    # comment hid the opening brace of broken JSON, and a following
    # DEFENSECLAW_FAIL_MODE=open line then read open; a key given twice took
    # its last value. Only a document with the KEY=value shape throughout,
    # each key once, reads as one (connector.ParseLegacyHookSidecar).
    path = tmp_path / ".hookcfg"
    path.write_text(text, encoding="utf-8")
    assert fail_mode_runtime._read_windows_hook_mode(path, "codex") == ("closed", False)


@pytest.mark.parametrize("vector", _WINDOWS_SIDECAR_VECTORS, ids=lambda vector: vector["name"])
def test_windows_sidecar_report_matches_the_native_hook_contract(tmp_path: Path, vector: dict) -> None:
    # 1.0.4 review (loop round 2 of G-hooks-upg): a gateway_addr or peer entry
    # that is not a string made the native hook run closed while status
    # reported open, and a connector key in another case the other way round.
    # Status reads every vector the Go test runs through readHookSidecar to
    # the same mode.
    path = tmp_path / ".hookcfg"
    body = base64.b64decode(vector["body_b64"]) if "body_b64" in vector else vector.get("body", "").encode("utf-8")
    kind = vector.get("kind", "")
    if kind == "dir":
        path.mkdir()
    elif kind == "link":
        target = tmp_path / "target"
        target.write_bytes(body)
        try:
            path.symlink_to(target)
        except OSError as exc:
            pytest.skip(f"symlinks unavailable: {exc}")
    elif kind == "oversize":
        path.write_bytes(body + b" " * (70 * 1024))
    elif kind != "missing":
        path.write_bytes(body)
    mode, legacy = fail_mode_runtime._read_windows_hook_mode(path, vector["connector"])
    assert (mode or "closed") == vector["mode"]
    if "legacy" in vector:
        assert legacy is vector["legacy"]


@pytest.mark.parametrize("sidecar", ["missing", "closed", "malformed", "open"])
@pytest.mark.parametrize("desired", ["open", "closed"])
def test_managed_windows_status_does_not_report_the_sidecar_as_the_hook_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, desired: str, sidecar: str
) -> None:
    # 1.0.4 review (loop round 2 of G-hooks-upg): a managed native hook takes
    # its mode from the authenticated runtime generation, never from
    # hooks/.hookcfg, so a missing or stale sidecar made status and doctor
    # report closed while the hook ran the administrator's open. Status
    # cannot authenticate the generation: it reports the administrator's
    # mode and says the runtime is unverified, whatever the sidecar holds.
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"codex": desired})
    _write_current_runtime(cfg, home, {"codex": desired})
    cfg.deployment_mode = "managed_enterprise"
    cfg.managed_outside_secure_client = lambda: True
    # The resolver reads the managed profile from the config that owns the
    # guardrail (sa-port-peer: only a managed config may keep an open).
    cfg.application_protection = SimpleNamespace(enabled=False)
    cfg.guardrail._owner = lambda: cfg
    path = Path(cfg.data_dir) / "hooks" / ".hookcfg"
    if sidecar == "missing":
        path.unlink()
    elif sidecar == "malformed":
        path.write_text("{not json", encoding="utf-8")
    else:
        path.write_text(json.dumps({"version": 2, "fail_modes": {"codex": sidecar}}), encoding="utf-8")
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        report = connector_fail_mode_report(cfg, "codex")
    assert report["effective"] == desired and report["runtime"] is None
    assert report["provenance"] == "windows-managed-runtime-unverified"
    assert report["runtime_verified"] is False
    assert "windows-managed-runtime-unverified" in report["drift"] and not report["current"]
    assert {"name": "windows-managed-runtime", "mode": None} in report["sources"]
    assert not [reason for reason in report["drift"] if reason.startswith("windows-sidecar")]
    assert not [source for source in report["sources"] if source["name"].startswith("windows-sidecar")]


@pytest.mark.parametrize("secure_client", [False, True])
@pytest.mark.parametrize("sidecar", ["missing", "closed", "malformed", "open"])
@pytest.mark.parametrize(("configured", "deployed"), [("closed", "open"), ("open", "closed"), ("closed", "closed")])
def test_doctor_never_passes_an_unverified_managed_windows_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    configured: str,
    deployed: str,
    sidecar: str,
    secure_client: bool,
) -> None:
    # 1.0.4 review (loop round 2 of G-hooks-upg, post round 4): the
    # administrator changes the mode (open to closed, say) while the guardian's
    # authenticated runtime generation still runs the old one. Status cannot
    # read that generation, yet it reported the configured mode as verified
    # and doctor's Mode row passed. Every state of the sidecar the managed
    # hook does not read, every pair of modes: the runtime is unverified, the
    # report says why, and doctor warns (it can never verify it) instead of
    # passing.
    from defenseclaw.commands import cmd_doctor

    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"codex": configured})
    _write_current_runtime(cfg, home, {"codex": configured})
    cfg.deployment_mode = "managed_enterprise"
    cfg.managed_outside_secure_client = lambda: not secure_client
    cfg.guardrail.mode = "action"
    cfg.guardrail._secure_client = secure_client
    cfg.skill_dirs = lambda connector=None: []
    cfg.plugin_dirs = lambda connector=None: []
    cfg.mcp_servers = lambda connector=None, **_: []
    path = Path(cfg.data_dir) / "hooks" / ".hookcfg"
    if sidecar == "missing":
        path.unlink()
    elif sidecar == "malformed":
        path.write_text("{not json", encoding="utf-8")
    else:
        mode = deployed if sidecar == "open" else sidecar
        path.write_text(json.dumps({"version": 2, "fail_modes": {"codex": mode}}), encoding="utf-8")
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        state = resolve_connector_fail_mode(cfg, "codex")
        report = connector_fail_mode_report(cfg, "codex")
    assert not state.runtime_verified and not state.current
    assert report["runtime_verified"] is False and report["current"] is False
    assert report["provenance"] == "windows-managed-runtime-unverified"
    assert "defenseclaw enterprise windows verify" in report["note"]
    emitted: list[tuple[str, str, str, str]] = []
    with (
        patch("defenseclaw.fail_mode.connector_fail_mode_report", return_value=report),
        patch.object(cmd_doctor, "_workspace_dir", return_value=""),
        patch.object(
            cmd_doctor,
            "_emit",
            side_effect=lambda tag, label, detail="", **kw: emitted.append(
                (tag, label, detail, str(kw.get("remediation") or ""))
            ),
        ),
    ):
        cmd_doctor._check_connector_inventory(cfg, "codex", cmd_doctor._DoctorResult())
    rows = [row for row in emitted if row[1] == "Mode"]
    assert [row[0] for row in rows] == ["warn"], rows
    assert "unverified" in rows[0][2] and "enterprise windows verify" in rows[0][3]


@pytest.mark.parametrize(
    "body,want",
    [
        ({"version": 2, "fail_modes": None, "legacy_fail_mode": "open"}, ("closed", False)),
        ({"version": 2, "fail_modes": [], "legacy_fail_mode": "open"}, ("closed", False)),
        ({"version": 2, "fail_modes": "open", "legacy_fail_mode": "open"}, ("closed", False)),
        ({"version": 2, "fail_modes": {"codex": ""}, "legacy_fail_mode": "open"}, ("closed", False)),
        ({"version": 2, "fail_modes": {"codex": True}, "legacy_fail_mode": "open"}, ("closed", False)),
        # An entry no installer writes is no readable mode (doctor fails it),
        # never the legacy open (T4: hooks-upg loop 3 with w3-g3-hooks).
        ({"version": 2, "fail_modes": {"codex": "bogus"}, "legacy_fail_mode": "open"}, (None, False)),
        # Controls: an unrefreshed install keeps its legacy mode.
        ({"version": 2, "legacy_fail_mode": "open"}, ("open", True)),
        ({"version": 2, "fail_modes": {"claudecode": "closed"}, "legacy_fail_mode": "open"}, ("open", True)),
        ({"version": 2, "fail_modes": {"codex": "open"}, "legacy_fail_mode": "closed"}, ("open", False)),
    ],
)
def test_windows_sidecar_report_reads_a_malformed_map_as_the_native_hook_does(
    tmp_path: Path, body: dict, want: tuple[str, bool]
) -> None:
    # 1.0.4 review (loop round 3): the native hook resolves a present but
    # malformed connector map, or a blank or invalid entry, closed; status
    # must not report the legacy open mode for it.
    path = tmp_path / ".hookcfg"
    path.write_text(json.dumps(body), encoding="utf-8")
    assert fail_mode_runtime._read_windows_hook_mode(path, "codex") == want


@pytest.mark.parametrize("windows", [False, True])
@pytest.mark.parametrize("installed,settings_env", [("closed", "open")])
def test_claude_settings_env_is_never_the_effective_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, windows: bool, installed: str, settings_env: str
) -> None:
    # Claude Code passes its settings env to the hook, which reads no fail
    # mode from it: a closed installed mode stays closed. Setup takes back a
    # value DefenseClaw wrote and keeps one the user set, so a value left
    # there is not drift either (round h, GAP-1422).
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": installed})
    _write_current_runtime(cfg, home, {"claudecode": installed})
    settings = home / ".claude" / "settings.json"
    payload = json.loads(settings.read_text(encoding="utf-8"))
    payload["env"]["DEFENSECLAW_FAIL_MODE"] = settings_env
    settings.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(fail_mode_runtime, "_unix_registration_freshness", lambda *_args: None)
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=windows),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        state = resolve_connector_fail_mode(cfg, "claudecode")
    assert state.runtime == installed and state.effective == installed
    assert state.provenance == ("windows-sidecar" if windows else "hook-script")
    assert not [item for item in state.drift if item.startswith("claude-env")], state.drift


@pytest.mark.parametrize("env_value", ["open", "closed"])
@pytest.mark.parametrize("installed", ["open", "closed"])
def test_opencode_fail_mode_ignores_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, installed: str, env_value: str
) -> None:
    # The plugin reads no fail mode from its environment (GAP-0315), so the
    # baked plugin mode is the report, with no caller-environment note.
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"opencode": installed})
    _write_opencode_runtime(cfg, tmp_path, plugin_mode=installed, lock_mode=installed)
    monkeypatch.setenv("DEFENSECLAW_FAIL_MODE", env_value)
    report = connector_fail_mode_report(cfg, "opencode")
    assert report["effective"] == installed and report["provenance"] == "opencode-plugin"
    assert report["note"] == "" and "caller_env" not in report


def _stale_native_deny_app(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, connectors: list[str], *, multi: bool
) -> AppContext:
    # config.yaml says closed while each hook is still rendered open (an
    # older install, or a fail-mode change the hook never received).
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, dict.fromkeys(connectors, "closed") if multi else {})
    cfg.guardrail.hook_fail_mode = "closed"
    cfg.active_connector = lambda: connectors[0]
    cfg.active_connectors = lambda: list(connectors)
    for name in connectors:
        script = f"{name}-hook.sh"
        (Path(cfg.data_dir) / "hooks" / script).write_text(
            "\n".join(_HOOK_FAIL_MODE_LINES[f"{script}/open"]) + "\n", encoding="utf-8"
        )
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    return app


@pytest.mark.parametrize("connector", ["antigravity", "copilot"])
def test_closed_fail_mode_re_renders_a_single_native_deny_hook_still_rendered_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, connector: str
) -> None:
    app = _stale_native_deny_app(monkeypatch, tmp_path, [connector], multi=False)
    with (
        patch("defenseclaw.commands.cmd_guardrail._gateway_running", return_value=True),
        patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration") as reconcile,
        patch("defenseclaw.commands.cmd_setup._restart_services") as restart,
    ):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    assert "nothing to do" not in result.output
    assert "Re-applying hook fail mode" in result.output
    reconcile.assert_called_once_with(app.cfg, connector)
    restart.assert_not_called()


def test_closed_fail_mode_re_renders_native_deny_hooks_with_the_gateway_stopped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    app = _stale_native_deny_app(monkeypatch, tmp_path, ["antigravity", "copilot"], multi=True)
    with (
        patch("defenseclaw.commands.cmd_guardrail._gateway_running", return_value=False),
        patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration") as reconcile,
        patch("defenseclaw.commands.cmd_setup._restart_services") as restart,
    ):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    assert "nothing to do" not in result.output
    assert sorted(call.args[1] for call in reconcile.call_args_list) == ["antigravity", "copilot"]
    restart.assert_not_called()


def test_closed_fail_mode_closes_each_hook_before_a_mixed_gateway_restart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    app = _stale_native_deny_app(monkeypatch, tmp_path, ["copilot", "hermes"], multi=True)
    app.cfg.guardrail.connectors["kiro"] = dcconfig.PerConnectorGuardrailConfig(hook_fail_mode="closed")
    app.cfg.active_connectors = lambda: ["copilot", "hermes", "kiro"]
    closed: set[str] = set()

    def state(_cfg: object, name: str) -> SimpleNamespace:
        return SimpleNamespace(desired="closed", current=name in closed, runtime="closed" if name in closed else "open", drift=())

    def reconcile(_cfg: object, name: str) -> None:
        closed.add(name)

    def restart(*_args: object, **_kwargs: object) -> None:
        assert closed == {"copilot", "hermes"}, "gateway restart exposed an older open hook"

    with (
        patch("defenseclaw.commands.cmd_guardrail._gateway_running", return_value=True),
        patch("defenseclaw.commands.cmd_guardrail.resolve_connector_fail_mode", side_effect=state),
        patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration", side_effect=reconcile),
        patch("defenseclaw.commands.cmd_setup._restart_services", side_effect=restart),
    ):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    assert closed == {"copilot", "hermes"}


def test_closed_fail_mode_refuses_a_mixed_restart_when_a_hook_cannot_close(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    app = _stale_native_deny_app(monkeypatch, tmp_path, ["copilot", "hermes"], multi=True)
    app.cfg.guardrail.connectors["kiro"] = dcconfig.PerConnectorGuardrailConfig(hook_fail_mode="closed")
    app.cfg.active_connectors = lambda: ["copilot", "hermes", "kiro"]

    def reconcile(_cfg: object, name: str) -> None:
        if name == "hermes":
            raise OSError("hermes registration unavailable")

    with (
        patch("defenseclaw.commands.cmd_guardrail._gateway_running", return_value=True),
        patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration", side_effect=reconcile),
        patch("defenseclaw.commands.cmd_guardrail._rollback_fail_mode_transaction"),
        patch("defenseclaw.commands.cmd_setup._restart_services") as restart,
    ):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app)
    assert result.exit_code != 0
    assert "hermes registration unavailable" in result.output
    restart.assert_not_called()


def test_closed_fail_mode_no_restart_refuses_open_registered_hooks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    app = _stale_native_deny_app(monkeypatch, tmp_path, ["copilot", "hermes"], multi=True)
    result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--yes", "--no-restart"], obj=app)
    assert result.exit_code != 0
    assert "defenseclaw guardrail fail-mode closed --yes" in result.output
    app.cfg.save.assert_not_called()


def test_secure_client_native_deny_hooks_need_no_fail_mode_refresh(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Under Secure Client they stay open whatever is configured, so their open
    # hooks are no stale runtime.
    app = _stale_native_deny_app(monkeypatch, tmp_path, ["antigravity", "copilot"], multi=True)
    app.cfg.deployment_mode = "managed_enterprise"
    app.cfg.managed_outside_secure_client = lambda: False
    with patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration") as reconcile:
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    assert "nothing to do" in result.output
    reconcile.assert_not_called()


@pytest.mark.parametrize("windows", [False, True])
def test_doctor_fails_an_open_rendered_hook_whatever_its_own_environment_says(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, windows: bool
) -> None:
    # DEFENSECLAW_FAIL_MODE=closed in doctor's process changes nothing: no
    # hook reads it (GAP-0315), so the open-rendered hook stays open and
    # fails the Mode row.
    from defenseclaw.commands import cmd_doctor

    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {"copilot": "closed"})
    cfg.guardrail.hook_fail_mode = "closed"
    cfg.guardrail.mode = "action"
    cfg.skill_dirs = lambda connector=None: []
    cfg.plugin_dirs = lambda connector=None: []
    cfg.mcp_servers = lambda connector=None, **_: []
    hook_dir = Path(cfg.data_dir) / "hooks"
    # Each case picks the hook it renders, whatever OS runs the test.
    monkeypatch.setattr(fail_mode_runtime, "_is_windows", lambda: windows)
    if windows:
        (hook_dir / ".hookcfg").write_text(
            json.dumps({"version": 2, "gateway_addr": "127.0.0.1:18970", "fail_modes": {"copilot": "open"}}),
            encoding="utf-8",
        )
    else:
        (hook_dir / "copilot-hook.sh").write_text(
            "\n".join(_legacy_open_hook_lines("copilot-hook.sh")) + "\n", encoding="utf-8"
        )
    monkeypatch.setenv("DEFENSECLAW_FAIL_MODE", "closed")
    report = connector_fail_mode_report(cfg, "copilot")
    assert report["effective"] == "open"
    assert "caller_env" not in report
    emitted: list[tuple[str, str, str]] = []
    with (
        patch.object(cmd_doctor, "_workspace_dir", return_value=""),
        patch.object(
            cmd_doctor, "_emit", side_effect=lambda tag, label, detail="", **_: emitted.append((tag, label, detail))
        ),
    ):
        cmd_doctor._check_connector_inventory(cfg, "copilot", cmd_doctor._DoctorResult())
    mode_rows = [row for row in emitted if row[1] == "Mode"]
    assert len(mode_rows) == 1 and mode_rows[0][0] == "fail", mode_rows
    assert "fail-mode=open" in mode_rows[0][2] and "config wants fail-mode=closed" in mode_rows[0][2]


_COPILOT_BOUND_EVENTS = ("preToolUse", "permissionRequest", "postToolUse")
_ANTIGRAVITY_EVENTS = ("PreInvocation", "PreToolUse", "PostToolUse", "PostInvocation", "Stop")


def _register_native_deny_hook(
    monkeypatch: pytest.MonkeyPatch,
    cfg: SimpleNamespace,
    home: Path,
    connector: str,
    *,
    lock_mode: str = "closed",
    script: str = "",
    binding: dict[str, str] | None = None,
) -> Path:
    """Write the lock entry and the live registration a per-user Setup writes.

    binding maps an event to the registered command arguments that replace
    the exact ones (for a stale or lost binding).
    """
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("COPILOT_HOME", str(home / ".copilot"))
    monkeypatch.setenv("HERMES_HOME", str(home / ".hermes"))
    selected_script = script
    script = script or str(Path(cfg.data_dir) / "hooks" / f"{connector}-hook.sh")
    binding = binding or {}
    lock_path = Path(cfg.data_dir) / "hook_contract_lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8")) if lock_path.exists() else {"version": 2, "connectors": {}}
    lock["connectors"][connector] = {"hook_fail_mode": lock_mode}
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    if connector == "copilot":
        path = home / ".copilot" / "hooks" / "defenseclaw.json"
        hooks = {
            event: [
                {
                    "type": "command",
                    "bash": f"{script} {binding.get(event, '--event ' + event)}".strip(),
                    "timeoutSec": 30,
                }
            ]
            for event in _COPILOT_BOUND_EVENTS
        }
        document: object = {"version": 1, "hooks": hooks}
    elif connector == "antigravity":
        path = home / ".gemini" / "config" / "hooks.json"
        document = {}
        for event in _ANTIGRAVITY_EVENTS:
            handler = {"type": "command", "command": f"{script} {binding.get(event, event)}".strip(), "timeout": 30}
            entries = [{"matcher": "*", "hooks": [handler]}] if event.endswith("ToolUse") else [handler]
            document[f"defenseclaw-antigravity-{event.lower()}"] = {event: entries}
    else:
        path = home / ".hermes" / "config.yaml"
        current_script = Path(cfg.data_dir) / "hooks" / "hermes-hook.sh"
        if not selected_script:
            current_script.write_text(
                '#!/bin/sh\nFAIL_MODE="closed"\nprintf \'defenseclaw-execution-probe-ok\\n\'\n', encoding="utf-8"
            )
            current_script.chmod(0o700)
        command = "'" + script + "'"
        lock["connectors"][connector]["locations"] = {
            "hook_config_paths": [str(path)], "hook_script_paths": [str(current_script)]
        }
        lock["connectors"][connector]["hook_script_digests"] = {
            "hermes-hook.sh": "sha256:" + hashlib.sha256(current_script.read_bytes()).hexdigest()
        }
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        hooks = {
            event: [{"command": command, "timeout": 30, **({"matcher": matcher} if matcher else {})}]
            for event, matcher in _HERMES_REQUIRED_HOOKS.items()
        }
        path.write_text(yaml.safe_dump({"hooks": hooks, "hooks_auto_accept": False}), encoding="utf-8")
        path.with_name("shell-hooks-allowlist.json").write_text(json.dumps({"approvals": [
            {"event": event, "command": command, "defenseclaw_managed": True}
            for event in _HERMES_REQUIRED_HOOKS
        ]}), encoding="utf-8")
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


@pytest.mark.skipif(os.name == "nt", reason="the Linux and macOS hook script and registration")
@pytest.mark.parametrize("connector", ["antigravity", "copilot", "hermes"])
def test_native_deny_state_reports_a_stale_lock_or_registration_next_to_a_closed_script(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, connector: str
) -> None:
    # Review round 2: the hook script says closed, but the lock records open or
    # the live registration still runs an older copy of the hook (which may be
    # rendered open). Neither is current, so guardrail fail-mode closed
    # reconciles instead of saying there is nothing to do.
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {connector: "closed"})
    if connector == "hermes":
        # This test checks the lock and registered command. Its synthetic
        # hook is not a containment test, and CI hosts may forbid user PID
        # namespaces needed by Doctor's real execution probe.

        def registered_hook_probe(argv: list[str]) -> tuple[int, bytes]:
            assert argv[0] == str(Path(cfg.data_dir) / "hooks" / "hermes-hook.sh")
            return 0, cmd_doctor._HERMES_EXECUTION_PROBE_RESPONSE

        monkeypatch.setattr(cmd_doctor, "_run_hermes_execution_probe", registered_hook_probe)
    script = f"{connector}-hook.sh"
    (Path(cfg.data_dir) / "hooks" / script).write_text(
        "\n".join(_HOOK_FAIL_MODE_LINES[f"{script}/closed"]) + "\n", encoding="utf-8"
    )

    _register_native_deny_hook(monkeypatch, cfg, home, connector, lock_mode="open")
    state = resolve_connector_fail_mode(cfg, connector)
    assert state.runtime == "closed"
    assert not state.current
    assert {"registration-stale", "registration-lock-open"} <= set(state.drift)

    old = tmp_path / "old-data" / "hooks" / script
    old.parent.mkdir(parents=True)
    old.write_text("\n".join(_HOOK_FAIL_MODE_LINES[f"{script}/open"]) + "\n", encoding="utf-8")
    _register_native_deny_hook(monkeypatch, cfg, home, connector, script=str(old))
    state = resolve_connector_fail_mode(cfg, connector)
    assert not state.current
    assert state.drift == (("registration-command-stale",) if connector == "hermes" else ("registration-stale",))

    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    cfg.guardrail.hook_fail_mode = "closed"
    with (
        patch("defenseclaw.commands.cmd_guardrail._gateway_running", return_value=True),
        patch("defenseclaw.commands.cmd_guardrail.reconcile_connector_registration") as reconcile,
        patch("defenseclaw.commands.cmd_setup._restart_services"),
    ):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    assert "nothing to do" not in result.output
    reconcile.assert_called_once_with(cfg, connector)

    _register_native_deny_hook(monkeypatch, cfg, home, connector)
    assert resolve_connector_fail_mode(cfg, connector).current


@pytest.mark.skipif(os.name == "nt", reason="the Linux and macOS hook script and registration")
@pytest.mark.parametrize(
    ("connector", "event", "args"),
    [
        ("copilot", "preToolUse", ""),
        ("copilot", "preToolUse", "--event postToolUse"),
        ("copilot", "permissionRequest", "--event"),
        ("antigravity", "PreToolUse", ""),
        ("antigravity", "PreToolUse", "Stop"),
    ],
)
def test_a_registration_that_loses_its_event_binding_is_drift_and_fails_doctor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, connector: str, event: str, args: str
) -> None:
    # Review round 2: neither agent names the event in its hook input, so a
    # registered command that binds another event, or none, answers a tool
    # call as an event that cannot block. Status and doctor said current.
    from defenseclaw.commands import cmd_doctor

    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {connector: "closed"})
    script = f"{connector}-hook.sh"
    (Path(cfg.data_dir) / "hooks" / script).write_text(
        "\n".join(_HOOK_FAIL_MODE_LINES[f"{script}/closed"]) + "\n", encoding="utf-8"
    )
    path = _register_native_deny_hook(monkeypatch, cfg, home, connector, binding={event: args})

    state = resolve_connector_fail_mode(cfg, connector)
    assert not state.current
    assert "registration-stale" in state.drift

    cfg.connector_workspace_dir = lambda: ""
    emitted: list[tuple[str, str, str]] = []
    with (
        patch.object(cmd_doctor, "_workspace_dir", return_value=""),
        patch.object(cmd_doctor, "_edited_hook_problem", return_value=""),
        patch.object(
            cmd_doctor, "_emit", side_effect=lambda tag, label, detail="", **_: emitted.append((tag, label, detail))
        ),
    ):
        if connector == "copilot":
            cmd_doctor._check_copilot_hooks(cfg, cmd_doctor._DoctorResult(), platform_name="posix")
        else:
            cmd_doctor._check_antigravity_hooks(cfg, cmd_doctor._DoctorResult(), platform_name="posix")
    rows = [row for row in emitted if row[1].endswith("hooks")]
    assert rows and rows[0][0] == "fail", emitted
    assert "not bound to its registered event" in rows[0][2]

    _register_native_deny_hook(monkeypatch, cfg, home, connector)
    assert resolve_connector_fail_mode(cfg, connector).current
    emitted.clear()
    with (
        patch.object(cmd_doctor, "_workspace_dir", return_value=""),
        patch.object(cmd_doctor, "_edited_hook_problem", return_value=""),
        patch.object(
            cmd_doctor, "_emit", side_effect=lambda tag, label, detail="", **_: emitted.append((tag, label, detail))
        ),
    ):
        if connector == "copilot":
            cmd_doctor._check_copilot_hooks(cfg, cmd_doctor._DoctorResult(), platform_name="posix")
        else:
            cmd_doctor._check_antigravity_hooks(cfg, cmd_doctor._DoctorResult(), platform_name="posix")
    assert [row[0] for row in emitted if row[1].endswith("hooks")] == ["pass"], emitted
    assert path.exists()


def _antigravity_entry(document: dict, event: str) -> dict:
    return document[f"defenseclaw-antigravity-{event.lower()}"]


def _skip_antigravity_disabled(document: dict) -> None:
    _antigravity_entry(document, "PreToolUse")["enabled"] = False


def _skip_antigravity_matcher(document: dict) -> None:
    _antigravity_entry(document, "PreToolUse")["PreToolUse"][0]["matcher"] = "run_command"


def _skip_antigravity_type(document: dict) -> None:
    _antigravity_entry(document, "PreToolUse")["PreToolUse"][0]["hooks"][0]["type"] = "prompt"


def _skip_antigravity_timeout(document: dict) -> None:
    _antigravity_entry(document, "PreToolUse")["PreToolUse"][0]["hooks"][0]["timeout"] = 1


def _skip_antigravity_extra(document: dict) -> None:
    group = _antigravity_entry(document, "PreToolUse")["PreToolUse"]
    group.append({"matcher": "*", "hooks": [dict(group[0]["hooks"][0])]})


def _skip_copilot_type(document: dict) -> None:
    document["hooks"]["preToolUse"][0]["type"] = "prompt"


def _skip_copilot_timeout(document: dict) -> None:
    document["hooks"]["permissionRequest"][0]["timeoutSec"] = 1


def _skip_copilot_disabled(document: dict) -> None:
    document["disableAllHooks"] = True


def _skip_copilot_version(document: dict) -> None:
    del document["version"]


@pytest.mark.skipif(os.name == "nt", reason="the Linux and macOS hook script and registration")
@pytest.mark.parametrize(
    ("connector", "skip"),
    [
        ("antigravity", _skip_antigravity_disabled),
        ("antigravity", _skip_antigravity_matcher),
        ("antigravity", _skip_antigravity_type),
        ("antigravity", _skip_antigravity_timeout),
        ("antigravity", _skip_antigravity_extra),
        ("copilot", _skip_copilot_type),
        ("copilot", _skip_copilot_timeout),
        ("copilot", _skip_copilot_disabled),
        ("copilot", _skip_copilot_version),
    ],
    ids=lambda value: value.__name__.removeprefix("_skip_") if callable(value) else value,
)
def test_a_registration_the_agent_skips_is_drift_and_fails_doctor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, connector: str, skip
) -> None:
    # Review round 3: the registration keeps the exact command and event, but
    # the agent skips it (disabled, a narrowed matcher, not a command handler,
    # a timeout shorter than Setup's), so some tool calls never run the hook.
    # Status and doctor said current.
    from defenseclaw.commands import cmd_doctor

    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {connector: "closed"})
    script = f"{connector}-hook.sh"
    (Path(cfg.data_dir) / "hooks" / script).write_text(
        "\n".join(_HOOK_FAIL_MODE_LINES[f"{script}/closed"]) + "\n", encoding="utf-8"
    )
    path = _register_native_deny_hook(monkeypatch, cfg, home, connector)
    assert resolve_connector_fail_mode(cfg, connector).current
    document = json.loads(path.read_text(encoding="utf-8"))
    skip(document)
    path.write_text(json.dumps(document), encoding="utf-8")

    state = resolve_connector_fail_mode(cfg, connector)
    assert not state.current
    assert any(item.startswith("registration-") for item in state.drift), state.drift

    cfg.connector_workspace_dir = lambda: ""
    emitted: list[tuple[str, str, str]] = []
    with (
        patch.object(cmd_doctor, "_workspace_dir", return_value=""),
        patch.object(cmd_doctor, "_edited_hook_problem", return_value=""),
        patch.object(
            cmd_doctor, "_emit", side_effect=lambda tag, label, detail="", **_: emitted.append((tag, label, detail))
        ),
    ):
        if connector == "copilot":
            cmd_doctor._check_copilot_hooks(cfg, cmd_doctor._DoctorResult(), platform_name="posix")
        else:
            cmd_doctor._check_antigravity_hooks(cfg, cmd_doctor._DoctorResult(), platform_name="posix")
    rows = [row for row in emitted if row[1].endswith("hooks")]
    assert rows and rows[0][0] == "fail", emitted


@pytest.mark.parametrize(
    ("body", "mode", "legacy"),
    [
        ({"version": 2, "fail_modes": {"copilot": "OPEN"}}, "open", False),
        ({"version": 2, "fail_modes": {"copilot": " Closed "}}, "closed", False),
        # A top-level key that names a field in another case is malformed
        # (connector.HookSidecarJSONMalformed, the one contract of the hook,
        # status and the writers): closed.
        ({"Version": 2, "Fail_Modes": {"Copilot": "open"}}, "closed", False),
        ({"version": 2, "fail_modes": {"copilot": "bogus"}}, None, False),
        # Entries that normalize alike are open only when every one is.
        ({"version": 2, "fail_modes": {"copilot": "open", "COPILOT": "closed"}}, "closed", False),
        ({"version": 2, "fail_modes": {}, "legacy_fail_mode": "Open"}, "open", True),
        # JSON that Go cannot decode as a v2 sidecar is closed (readHookSidecar).
        ({"version": "2", "fail_modes": {"copilot": "open"}}, "closed", False),
        # A key given twice is malformed state (connector.ParseLegacyHookSidecar).
        ("DEFENSECLAW_FAIL_MODE=closed\nDEFENSECLAW_FAIL_MODE=open\n", "closed", False),
        (f"export {fail_mode_runtime._native_hook_sidecar_key('copilot')}='OPEN'\n", "open", True),
        ('DEFENSECLAW_FAIL_MODE="closed"\n', "closed", True),
    ],
)
def test_windows_hookcfg_is_read_as_the_native_hook_reads_it(
    tmp_path: Path, body: object, mode: str | None, legacy: bool
) -> None:
    # Review round 2: the native hook treats "open" in any case as open (and
    # reads Go's case-insensitive JSON fields, the last KEY=value line, and a
    # connector key); the reader rejected OPEN and reported no runtime mode.
    path = tmp_path / ".hookcfg"
    path.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")
    got_mode, got_legacy = fail_mode_runtime._read_windows_hook_mode(path, "copilot")
    assert got_mode == mode
    if mode is not None:
        assert got_legacy is legacy


@pytest.mark.parametrize(
    ("sidecar", "phrase"),
    [("OPEN", "fail-mode=open"), ("bogus", "no readable fail mode"), (None, "no readable fail mode")],
)
def test_doctor_mode_fails_a_windows_hook_rendered_open_or_without_a_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, sidecar: str | None, phrase: str
) -> None:
    from defenseclaw.commands import cmd_doctor

    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"copilot": "closed"})
    cfg.guardrail.hook_fail_mode = "closed"
    cfg.guardrail.mode = "action"
    cfg.skill_dirs = lambda connector=None: []
    cfg.plugin_dirs = lambda connector=None: []
    cfg.mcp_servers = lambda connector=None, **_: []
    monkeypatch.setattr(fail_mode_runtime, "_is_windows", lambda: True)
    monkeypatch.setattr(fail_mode_runtime, "_native_deny_registration_freshness", lambda *_args: None, raising=False)
    _register_native_deny_hook(monkeypatch, cfg, home, "copilot")
    if sidecar is not None:
        (Path(cfg.data_dir) / "hooks" / ".hookcfg").write_text(
            json.dumps({"version": 2, "gateway_addr": "127.0.0.1:18970", "fail_modes": {"copilot": sidecar}}),
            encoding="utf-8",
        )
    if sidecar == "OPEN":
        # Doctor's own environment is reported apart and does not mask it.
        monkeypatch.setenv("DEFENSECLAW_FAIL_MODE", "closed")
    emitted: list[tuple[str, str, str]] = []
    with (
        patch.object(cmd_doctor, "_workspace_dir", return_value=""),
        patch.object(
            cmd_doctor, "_emit", side_effect=lambda tag, label, detail="", **_: emitted.append((tag, label, detail))
        ),
    ):
        cmd_doctor._check_connector_inventory(cfg, "copilot", cmd_doctor._DoctorResult())
    mode_rows = [row for row in emitted if row[1] == "Mode"]
    assert len(mode_rows) == 1 and mode_rows[0][0] == "fail", mode_rows
    assert phrase in mode_rows[0][2]


# ── 1.0.4 review loop round 1 (G-hooks-upg): renders that read the agent env ─
#
# A 0.8.x or 1.0.3 render the upgrade's connector refresh has not replaced
# yet, and a Secure Client render (#1163), take DEFENSECLAW_FAIL_MODE from the
# agent's environment. Its default is not the mode it runs, so status and
# doctor never report it closed and current, whatever the status shell says.

_ENV_READING_RENDERS = {
    # 0.8.10 and 1.0.3 per-user renders, and Secure Client renders.
    "default": 'FAIL_MODE="${{DEFENSECLAW_FAIL_MODE:-{mode}}}"',
    "export": 'export FAIL_MODE="${{DEFENSECLAW_FAIL_MODE:-{mode}}}"',
    # A baked line the environment then overrides.
    "baked-then-env": 'FAIL_MODE="{mode}"\n  FAIL_MODE="${{DEFENSECLAW_FAIL_MODE:-{mode}}}"',
}


def _install_render(cfg: SimpleNamespace, name: str, body: str) -> None:
    """Write *name*'s hook render and keep the contract lock's digest of it current."""

    script_name = "claude-code-hook.sh" if name == "claudecode" else f"{name}-hook.sh"
    script_path = Path(cfg.data_dir) / "hooks" / script_name
    script_path.write_text("#!/bin/bash\n" + body + "\n", encoding="utf-8")
    lock_path = Path(cfg.data_dir) / "hook_contract_lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    entry = lock["connectors"][name]
    entry["contract_id"] = f"{name}-hooks-v1"
    entry["hook_script_digests"][script_name] = "sha256:" + hashlib.sha256(script_path.read_bytes()).hexdigest()
    lock_path.write_text(json.dumps(lock), encoding="utf-8")


def _set_claude_settings_env(home: Path, value: str | None) -> None:
    settings = home / ".claude" / "settings.json"
    payload = json.loads(settings.read_text(encoding="utf-8"))
    if value is None:
        payload.pop("env", None)
    else:
        payload["env"] = {"DEFENSECLAW_FAIL_MODE": value}
    settings.write_text(json.dumps(payload), encoding="utf-8")


def _unix_report(monkeypatch: pytest.MonkeyPatch, cfg: SimpleNamespace, home: Path, name: str) -> tuple:
    monkeypatch.setattr(fail_mode_runtime, "_codex_registration_current", lambda *_args: True)
    monkeypatch.setattr(fail_mode_runtime, "_unix_registration_freshness", lambda *_args: None)
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=False),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        return resolve_connector_fail_mode(cfg, name), connector_fail_mode_report(cfg, name)


@pytest.mark.parametrize("render", sorted(_ENV_READING_RENDERS))
@pytest.mark.parametrize("shell_env", [None, "open", "closed"])
@pytest.mark.parametrize(
    ("name", "mode"),
    # Claude Code with its settings env open is verified open (below). A
    # per-user open is no longer a mode: it resolves closed (sa-port-peer).
    [("claudecode", "closed"), ("codex", "closed"), ("devin", "closed")],
)
def test_a_render_that_reads_the_agent_env_is_never_reported_current(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str, mode: str, shell_env: str | None, render: str
) -> None:
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {name: mode})
    _write_current_runtime(cfg, home, {name: mode})
    if shell_env is None:
        monkeypatch.delenv("DEFENSECLAW_FAIL_MODE", raising=False)
    else:
        monkeypatch.setenv("DEFENSECLAW_FAIL_MODE", shell_env)

    # The same install with the 1.0.4 render is current: only the render differs.
    _install_render(cfg, name, "\n".join(_HOOK_FAIL_MODE_LINES[f"{_unix_script(name)}/{mode}"]))
    baked, _ = _unix_report(monkeypatch, cfg, home, name)
    assert baked.current and baked.runtime_verified, baked.drift

    _install_render(cfg, name, _ENV_READING_RENDERS[render].format(mode=mode))
    state, report = _unix_report(monkeypatch, cfg, home, name)
    assert not state.runtime_verified and not state.current
    assert "agent-env-unverified" in state.drift
    assert ("hook-script-reads-agent-env" in state.drift) is (name != "devin")
    assert state.provenance == "agent-env-unverified"
    assert "DEFENSECLAW_FAIL_MODE" in state.note
    assert report["current"] is False and report["runtime_verified"] is False
    assert report["provenance"] == "agent-env-unverified"
    # The status shell is not the agent: its value is never the runtime mode,
    # which stays the render's default (none read from an exported line).
    assert state.runtime == (None if render == "export" else mode)
    assert all(source != "process-env" for source, _mode in state.sources)


def _unix_script(name: str) -> str:
    return "claude-code-hook.sh" if name == "claudecode" else f"{name}-hook.sh"


@pytest.mark.parametrize("default", ["open", "closed"])
def test_claude_settings_env_open_is_the_mode_of_a_render_that_reads_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, default: str
) -> None:
    # Claude Code applies its settings env over the environment it started
    # in, so open there is what a 1.0.3 render runs: reported open, verified,
    # and stale until the refresh re-renders it.
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed"})
    _write_current_runtime(cfg, home, {"claudecode": "closed"})
    _set_claude_settings_env(home, "open")
    _install_render(cfg, "claudecode", _ENV_READING_RENDERS["default"].format(mode=default))
    state, report = _unix_report(monkeypatch, cfg, home, "claudecode")
    assert state.runtime_verified and state.runtime == "open" and state.effective == "open"
    assert state.provenance == "agent-env"
    assert not state.current and "hook-script-reads-agent-env" in state.drift
    assert report["effective"] == "open" and report["desired"] == "closed"


def test_claude_settings_env_closed_does_not_verify_a_render_that_reads_the_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A project's or managed settings env can still set open over the user
    # settings env, so closed there is no closed claim.
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed"})
    _write_current_runtime(cfg, home, {"claudecode": "closed"})
    _set_claude_settings_env(home, "closed")
    _install_render(cfg, "claudecode", _ENV_READING_RENDERS["default"].format(mode="closed"))
    state, report = _unix_report(monkeypatch, cfg, home, "claudecode")
    assert not state.runtime_verified and not state.current
    assert report["provenance"] == "agent-env-unverified"


@pytest.mark.parametrize(
    ("name", "desired", "secure_client", "want"),
    [
        ("codex", "closed", False, "fail"),
        ("devin", "closed", False, "fail"),
        ("devin", "closed", True, "warn"),
        # A per-user render no longer carries an open line (sa-port-peer pins it
        # closed), so the Secure Client open case has no per-user fixture here.
    ],
)
def test_doctor_never_passes_a_render_that_reads_the_agent_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str, desired: str, secure_client: bool, want: str
) -> None:
    from defenseclaw.commands import cmd_doctor

    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {name: desired})
    _write_current_runtime(cfg, home, {name: desired})
    cfg.guardrail.mode = "action"
    cfg.guardrail._secure_client = secure_client
    cfg.skill_dirs = lambda connector=None: []
    cfg.plugin_dirs = lambda connector=None: []
    cfg.mcp_servers = lambda connector=None, **_: []

    def mode_rows() -> list[tuple[str, str, str]]:
        _state, report = _unix_report(monkeypatch, cfg, home, name)
        emitted: list[tuple[str, str, str]] = []
        with (
            patch("defenseclaw.fail_mode.connector_fail_mode_report", return_value=report),
            patch.object(cmd_doctor, "_workspace_dir", return_value=""),
            patch.object(
                cmd_doctor,
                "_emit",
                side_effect=lambda tag, label, detail="", **_: emitted.append((tag, label, detail)),
            ),
        ):
            cmd_doctor._check_connector_inventory(cfg, name, cmd_doctor._DoctorResult())
        return [row for row in emitted if row[1] == "Mode"]

    _install_render(cfg, name, "\n".join(_HOOK_FAIL_MODE_LINES[f"{_unix_script(name)}/{desired}"]))
    assert [row[0] for row in mode_rows()] == ["pass"]
    _install_render(cfg, name, _ENV_READING_RENDERS["default"].format(mode=desired))
    rows = mode_rows()
    assert [row[0] for row in rows] == [want], rows
    assert "unverified" in rows[0][2]


def test_windows_codex_reconcile_waits_for_a_transient_registration_read(tmp_path: Path) -> None:
    # Windows can briefly deny a read of Codex's freshly reconciled hook
    # target while an existing app-server releases its handle. The final
    # verdict still has to come from a successful full registration check.
    unread = SimpleNamespace(current=False, connector="codex", drift=("registration-access-denied",))
    current = SimpleNamespace(current=True, connector="codex", drift=())
    cfg = SimpleNamespace(data_dir=str(tmp_path))
    with (
        patch.object(fail_mode_runtime, "_is_windows", return_value=True),
        patch.object(fail_mode_runtime.shutil, "which", return_value="C:/bin/defenseclaw-gateway.exe"),
        patch.object(fail_mode_runtime.subprocess, "run", return_value=SimpleNamespace(returncode=0)),
        patch.object(fail_mode_runtime, "resolve_connector_fail_mode", side_effect=(unread, current)) as check,
    ):
        assert fail_mode_runtime.reconcile_connector_registration(cfg, "codex") is current
    assert check.call_count == 2


def test_windows_codex_reconcile_refuses_persistent_registration_read_denial(tmp_path: Path) -> None:
    unread = SimpleNamespace(current=False, connector="codex", drift=("registration-access-denied",))
    cfg = SimpleNamespace(data_dir=str(tmp_path))
    with (
        patch.object(fail_mode_runtime, "_is_windows", return_value=True),
        patch.object(fail_mode_runtime.shutil, "which", return_value="C:/bin/defenseclaw-gateway.exe"),
        patch.object(fail_mode_runtime.subprocess, "run", return_value=SimpleNamespace(returncode=0)),
        patch.object(fail_mode_runtime, "resolve_connector_fail_mode", return_value=unread) as check,
    ):
        with pytest.raises(OSError, match="registration-access-denied"):
            fail_mode_runtime.reconcile_connector_registration(cfg, "codex")
    assert check.call_count == 3


@pytest.mark.parametrize("windows", [False, True])
@pytest.mark.parametrize("installed", ["open", "closed"])
def test_claude_settings_without_a_fail_mode_carrier_is_not_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, windows: bool, installed: str
) -> None:
    # oss-outage-open review (round g, loop round 2): a per-user setup no
    # longer writes DEFENSECLAW_FAIL_MODE into Claude Code's settings env
    # (no 1.0.4 render reads it). Status used to report the product-owned
    # closed it wrote as claude-env-closed next to an open outage, and would
    # report the carrier's absence as claude-env-missing.
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": installed})
    _write_current_runtime(cfg, home, {"claudecode": installed})
    settings = home / ".claude" / "settings.json"
    payload = json.loads(settings.read_text(encoding="utf-8"))
    del payload["env"]["DEFENSECLAW_FAIL_MODE"]
    settings.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(fail_mode_runtime, "_unix_registration_freshness", lambda *_args: None)
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=windows),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        state = resolve_connector_fail_mode(cfg, "claudecode")
    assert not [item for item in state.drift if item.startswith("claude-env")], state.drift


_RELEASED_CARRIERS = Path(__file__).resolve().parents[2] / "internal/gateway/connector/testdata/released-carriers"


@pytest.mark.parametrize("windows", [False, True])
@pytest.mark.parametrize(("release", "user_value"), [("1.0.2", "closed"), ("1.0.3", "open"), ("1.0.3", "closed")])
@pytest.mark.parametrize("installed", ["open", "closed"])
def test_a_claude_settings_carrier_the_user_kept_is_not_drift_for_a_render_that_ignores_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, windows: bool, release: str, user_value: str, installed: str
) -> None:
    # oss-outage-open round h (GAP-1422 class): the upgrade takes back the
    # DEFENSECLAW_FAIL_MODE that 1.0.2 or 1.0.3 wrote into Claude Code's
    # settings env, and keeps one the user changed. No 1.0.4 render (baked
    # shell hook, Windows sidecar) reads it, so status must not report that
    # kept value as drift; it made status non-current and rolled back the
    # fail-mode setter's verification. The env is the real released one.
    released = json.loads((_RELEASED_CARRIERS / release / "claude-settings.json").read_text(encoding="utf-8"))
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": installed})
    _write_current_runtime(cfg, home, {"claudecode": installed})
    settings = home / ".claude" / "settings.json"
    payload = json.loads(settings.read_text(encoding="utf-8"))
    del payload["env"]["DEFENSECLAW_FAIL_MODE"]
    settings.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(fail_mode_runtime, "_unix_registration_freshness", lambda *_args: None)

    def resolve():
        with (
            patch("defenseclaw.fail_mode._is_windows", return_value=windows),
            patch("defenseclaw.fail_mode.Path.home", return_value=home),
        ):
            return resolve_connector_fail_mode(cfg, "claudecode")

    without = resolve()
    payload["env"] = dict(released["env"], DEFENSECLAW_FAIL_MODE=user_value)
    settings.write_text(json.dumps(payload), encoding="utf-8")
    state = resolve()
    assert not [item for item in state.drift if item.startswith("claude-env")], state.drift
    assert (state.runtime, state.drift, state.current) == (without.runtime, without.drift, without.current)


@pytest.mark.parametrize("user_value", ["open", "closed"])
def test_a_claude_settings_carrier_is_still_an_input_of_a_render_that_reads_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, user_value: str
) -> None:
    # The other half: a 1.0.3 render the refresh has not replaced yet reads
    # the settings env (FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-closed}"), so a
    # value there is what it runs, and status still says so.
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "closed"})
    _write_current_runtime(cfg, home, {"claudecode": "closed"})
    _install_render(cfg, "claudecode", 'FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-closed}"')
    _set_claude_settings_env(home, user_value)
    state, _report = _unix_report(monkeypatch, cfg, home, "claudecode")
    assert not state.current
    assert "hook-script-reads-agent-env" in state.drift, state.drift
    if user_value == "open":
        assert state.runtime == "open"
        assert "claude-env-open" in state.drift, state.drift
    else:
        assert "agent-env-unverified" in state.drift, state.drift
