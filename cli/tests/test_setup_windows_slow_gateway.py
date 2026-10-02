"""GAP-1206/GAP-1396: setup must let `defenseclaw-gateway start|restart`
finish on a slow Windows host instead of killing it after 30 s."""

import os
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from defenseclaw.commands import cmd_setup

_REPO = Path(__file__).resolve().parents[2]


def _go_seconds(name: str) -> int:
    text = (_REPO / "internal" / "cli" / name).read_text(encoding="utf-8")
    match = re.search(r"platformStartReadinessTimeout = (\d+) \* time\.Second", text)
    assert match, name
    return int(match.group(1))


def test_windows_launcher_timeout_outlasts_the_gateway_readiness_wait():
    # The Go launcher stops the old gateway (10 s), waits for the port (10 s),
    # then waits for READY before it starts the watchdog.
    readiness = _go_seconds("daemon_readiness_windows.go")
    # 240 s still stopped a start that was admitting connectors (GAP-1206).
    assert readiness >= 600
    # GAP-1556: connector setup progress may extend that wait by this factor.
    text = (_REPO / "internal" / "cli" / "daemon_readiness_windows.go").read_text(encoding="utf-8")
    factor = int(re.search(r"startReadinessProgressFactor = (\d+)", text).group(1))
    assert cmd_setup._DEFENSE_GATEWAY_LAUNCHER_TIMEOUT_SECONDS_WINDOWS > readiness * factor + 20
    assert _go_seconds("daemon_readiness_other.go") == 60


def test_rollback_lock_identity_ignores_amp_release_age():
    # GAP-1206: the rollback restart wrote Amp's lock entry an hour bucket
    # later ("7h ago" -> "8h ago"); the identity check called that a change
    # and left the rollback incomplete.
    def identity(name, entry):
        return cmd_setup._setup_runtime_digest(cmd_setup._stable_lock_identity_entry(name, entry))

    before = {
        "connector": "amp",
        "raw_agent_version": "0.0.1790934954-gaac027 (released 2026-10-02T09:55:54.000Z, 7h ago)",
        "contract_id": "amp-plugin-v1",
        "updated_at": "2026-10-02T17:40:00Z",
    }
    after = dict(
        before,
        raw_agent_version="0.0.1790934954-gaac027 (released 2026-10-02T09:55:54.000Z, 8h ago)",
        updated_at="2026-10-02T18:08:31Z",
    )
    assert identity("amp", before) == identity("amp", after)
    assert before["raw_agent_version"].endswith("7h ago)"), "the stored entry must not be modified"
    upgraded = dict(before, raw_agent_version="0.0.1790999999-gbbbbbb (released 2026-10-03T01:00:00.000Z, 1h ago)")
    assert identity("amp", before) != identity("amp", upgraded)
    # Only Amp's presentation suffix is dropped.
    codex = {"connector": "codex", "raw_agent_version": "codex-cli 0.130.0 (released x, 7h ago)"}
    assert identity("codex", codex) != identity("codex", dict(codex, raw_agent_version="codex-cli 0.130.0 (released x, 8h ago)"))


def test_restart_passes_the_launcher_timeout(tmp_path):
    exe = tmp_path / "defenseclaw-gateway"
    exe.write_bytes(b"")
    exe.chmod(0o755)
    seen = {}

    def run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["timeout"] = kwargs.get("timeout")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch.object(cmd_setup, "_gateway_lifecycle_executable", return_value=str(exe)), patch.object(
        cmd_setup, "run_pinned_executable", side_effect=run
    ), patch.object(cmd_setup, "_wait_for_defense_gateway_api", return_value=True), patch.object(
        cmd_setup, "_gateway_runtime_generation_before_restart", return_value=None
    ), patch("defenseclaw.gateway.packaged_windows_install_root", return_value=None):
        assert cmd_setup._restart_defense_gateway(str(tmp_path)) is True

    assert seen["cmd"][-1] == "start"
    assert seen["timeout"] == cmd_setup._DEFENSE_GATEWAY_LAUNCHER_TIMEOUT_SECONDS
    if os.name == "nt":
        assert seen["timeout"] == cmd_setup._DEFENSE_GATEWAY_LAUNCHER_TIMEOUT_SECONDS_WINDOWS


def test_runtime_wait_budget_tolerates_a_loaded_windows_host():
    # GAP-1206: connectors took minutes to converge after a slow restart.
    if os.name == "nt":
        assert cmd_setup._CONNECTOR_RUNTIME_READY_TIMEOUT_SECONDS >= 180
        assert cmd_setup._CONNECTOR_RUNTIME_READY_ABSOLUTE_CAP_SECONDS >= 900
    else:
        assert cmd_setup._CONNECTOR_RUNTIME_READY_TIMEOUT_SECONDS == 60
        assert cmd_setup._CONNECTOR_RUNTIME_READY_ABSOLUTE_CAP_SECONDS == 300
