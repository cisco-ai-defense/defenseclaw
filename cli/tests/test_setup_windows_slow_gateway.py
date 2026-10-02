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
    assert readiness >= 180
    # GAP-1556: connector setup progress extends that wait by this factor.
    text = (_REPO / "internal" / "cli" / "daemon_readiness_windows.go").read_text(encoding="utf-8")
    factor = int(re.search(r"startReadinessProgressFactor = (\d+)", text).group(1))
    assert cmd_setup._DEFENSE_GATEWAY_LAUNCHER_TIMEOUT_SECONDS_WINDOWS > readiness * factor + 20
    assert _go_seconds("daemon_readiness_other.go") == 60


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
