"""The local policy digest runs the gateway against the install home, not the moved data_dir.

After ``defenseclaw config set data_dir <new>`` config.yaml stays in the install
home and names the moved store. The gateway reads config.yaml from
``DEFENSECLAW_HOME``, so the digest command must get the install home; it got the
moved store, found no config.yaml there, and doctor's Policy row warned that the
comparison was unavailable.
"""

from __future__ import annotations

import json
import os
import subprocess
from types import SimpleNamespace

import pytest
from defenseclaw import gateway
from defenseclaw.commands import cmd_doctor, cmd_setup, cmd_setup_cowork


class _Recorder:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.env: dict[str, str] = {}
        self._result = subprocess.CompletedProcess([], returncode, stdout, stderr)

    def __call__(self, *_args, **kwargs):
        self.env = kwargs["env"]
        return self._result


@pytest.fixture
def install_home(tmp_path, monkeypatch):
    home = tmp_path / "home" / ".defenseclaw"
    home.mkdir(parents=True)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setattr(gateway, "resolve_trusted_gateway_binary", lambda: "/trusted/defenseclaw-gateway")
    return home


def _digest_run(monkeypatch, cfg) -> tuple[dict | None, _Recorder, list[str]]:
    recorder = _Recorder(stdout=json.dumps({"effective_digest": "sha256:" + "a" * 64}))
    monkeypatch.setattr(gateway.subprocess, "run", recorder)
    failure: list[str] = []
    return gateway.local_policy_digest(cfg, failure=failure), recorder, failure


def test_moved_data_dir_digest_uses_install_home(install_home, tmp_path, monkeypatch) -> None:
    moved = tmp_path / "dc16n"
    moved.mkdir()
    (install_home / "config.yaml").write_text(f"data_dir: {moved}\n", encoding="utf-8")

    report, recorder, failure = _digest_run(monkeypatch, SimpleNamespace(data_dir=str(moved)))

    assert report == {"effective_digest": "sha256:" + "a" * 64}
    assert recorder.env["DEFENSECLAW_HOME"] == str(install_home)
    assert failure == []


def test_unmoved_data_dir_digest_keeps_its_home(install_home, monkeypatch) -> None:
    (install_home / "config.yaml").write_text(f"data_dir: {install_home}\n", encoding="utf-8")

    report, recorder, _ = _digest_run(monkeypatch, SimpleNamespace(data_dir=str(install_home)))

    assert report is not None
    assert recorder.env["DEFENSECLAW_HOME"] == str(install_home)


def test_store_the_config_does_not_name_keeps_its_own_home(install_home, tmp_path, monkeypatch) -> None:
    other = tmp_path / "other-store"
    other.mkdir()
    (install_home / "config.yaml").write_text(f"data_dir: {install_home}\n", encoding="utf-8")

    _, recorder, _ = _digest_run(monkeypatch, SimpleNamespace(data_dir=str(other)))

    assert recorder.env["DEFENSECLAW_HOME"] == str(other)


def test_digest_failure_reports_why(install_home, monkeypatch) -> None:
    recorder = _Recorder(returncode=1, stderr="policy digest: load config: open config.yaml: no such file\n")
    monkeypatch.setattr(gateway.subprocess, "run", recorder)
    failure: list[str] = []

    assert gateway.local_policy_digest(SimpleNamespace(data_dir=str(install_home)), failure=failure) is None
    assert len(failure) == 1
    assert "no such file" in failure[0]


def test_doctor_policy_row_names_the_cause_and_the_next_command(monkeypatch) -> None:
    applied = "sha256:" + "a" * 64

    def unavailable(_cfg, *, failure=None):
        failure.append("the gateway policy digest command failed: load config: no such file")

    monkeypatch.setattr(cmd_doctor, "_local_policy_digest", unavailable)
    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_policy_state(
        SimpleNamespace(),
        result,
        live_health={"policy": {"effective_digest": applied, "config_generation": 3}},
    )

    check = result.checks[0]
    assert check["status"] == "warn"
    assert "load config: no such file" in check["detail"]
    assert "defenseclaw-gateway policy digest --json" in check["remediation"]


def test_doctor_policy_row_passes_when_digests_match(monkeypatch) -> None:
    applied = "sha256:" + "a" * 64
    monkeypatch.setattr(cmd_doctor, "_local_policy_digest", lambda _cfg, *, failure=None: {"effective_digest": applied})
    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_policy_state(
        SimpleNamespace(),
        result,
        live_health={"policy": {"effective_digest": applied, "config_generation": 3, "config_generation_recorded": True}},
    )

    assert result.checks[0]["status"] == "pass"


def _policy_row(monkeypatch, cfg_failure: str | None):
    applied = "sha256:" + "a" * 64

    def unavailable(_cfg, *, failure=None):
        failure.append(cfg_failure)

    monkeypatch.setattr(cmd_doctor, "_local_policy_digest", unavailable)
    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_policy_state(
        SimpleNamespace(),
        result,
        live_health={"policy": {"effective_digest": applied, "config_generation": 3}},
    )
    return result.checks[0]


def test_missing_gateway_executable_names_a_command_that_can_run(install_home, monkeypatch) -> None:
    monkeypatch.setattr(gateway, "resolve_trusted_gateway_binary", lambda: None)
    failure: list[str] = []
    assert gateway.local_policy_digest(SimpleNamespace(data_dir=str(install_home)), failure=failure) is None

    check = _policy_row(monkeypatch, failure[0])

    assert check["status"] == "warn"
    assert "executable is installed" in check["detail"]
    assert "defenseclaw upgrade" in check["remediation"]
    assert "policy digest --json" not in check["remediation"]


def test_unverified_gateway_executable_names_a_command_that_can_run(install_home, monkeypatch) -> None:
    def refuse():
        raise OSError("refusing to run /x/defenseclaw-gateway: writable by another account")

    monkeypatch.setattr(gateway, "resolve_trusted_gateway_binary", refuse)
    failure: list[str] = []
    assert gateway.local_policy_digest(SimpleNamespace(data_dir=str(install_home)), failure=failure) is None

    check = _policy_row(monkeypatch, failure[0])

    assert "writable by another account" in check["detail"]
    assert "defenseclaw upgrade" in check["remediation"]
    assert "policy digest --json" not in check["remediation"]


def test_failing_gateway_command_keeps_the_diagnose_command(monkeypatch) -> None:
    check = _policy_row(monkeypatch, "the gateway policy digest command failed: load config")

    assert "policy digest --json" in check["remediation"]


@pytest.mark.parametrize("moved", [True, False])
def test_cowork_hooks_render_runs_the_gateway_in_the_install_home(install_home, tmp_path, monkeypatch, moved) -> None:
    store = tmp_path / "dc16n" if moved else install_home
    store.mkdir(exist_ok=True)
    (install_home / "config.yaml").write_text(f"data_dir: {store}\n", encoding="utf-8")
    seen: dict[str, str] = {}

    def run(_argv, **kwargs):
        seen.update(kwargs["env"])
        return subprocess.CompletedProcess([], 1, json.dumps({"error": "stop", "reason": "stop"}), "")

    monkeypatch.setattr(cmd_setup, "_gateway_lifecycle_resolution", lambda: ("/trusted/defenseclaw-gateway", ""))
    monkeypatch.setattr("defenseclaw.pinned_exec.run_pinned_executable", run)

    with pytest.raises(Exception, match="stop"):
        cmd_setup_cowork._render_hooks(SimpleNamespace(data_dir=str(store)))

    assert seen["DEFENSECLAW_HOME"] == str(install_home)
    assert os.path.exists(os.path.join(seen["DEFENSECLAW_HOME"], "config.yaml"))
