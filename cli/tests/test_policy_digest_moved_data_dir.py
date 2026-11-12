"""The local policy digest runs the gateway against the install home, not the moved data_dir.

After ``defenseclaw config set data_dir <new>`` config.yaml stays in the install
home and names the moved store. The gateway reads config.yaml from
``DEFENSECLAW_HOME``, so the digest command must get the install home; it got the
moved store, found no config.yaml there, and doctor's Policy row warned that the
comparison was unavailable.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
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


RESOLVER_COMMAND = "bash defenseclaw-upgrade.sh --yes"
WINDOWS_ROUTE = "running the install command again"


def _repair_route() -> str:
    """The per-user repair this platform's Policy row names."""
    return WINDOWS_ROUTE if os.name == "nt" else RESOLVER_COMMAND


class _NtOs:
    """The os module as a Windows host answers it for ``os.name``."""

    name = "nt"

    def __getattr__(self, attr):
        return getattr(os, attr)


@pytest.fixture
def as_windows(monkeypatch) -> None:
    monkeypatch.setattr(cmd_doctor, "os", _NtOs())


@pytest.fixture
def per_user_install(monkeypatch) -> None:
    from defenseclaw import upgrade_shim

    monkeypatch.setattr(upgrade_shim, "managed_deployment", lambda: None)


@pytest.fixture(autouse=True)
def _no_explicit_gateway(monkeypatch) -> None:
    monkeypatch.delenv("DEFENSECLAW_GATEWAY_BIN", raising=False)


def test_missing_gateway_executable_names_a_command_that_can_run(install_home, per_user_install, monkeypatch) -> None:
    monkeypatch.setattr(gateway, "resolve_trusted_gateway_binary", lambda: None)
    failure: list[str] = []
    assert gateway.local_policy_digest(SimpleNamespace(data_dir=str(install_home)), failure=failure) is None

    check = _policy_row(monkeypatch, failure[0])

    assert check["status"] == "warn"
    assert "executable is installed" in check["detail"]
    assert _repair_route() in check["remediation"]
    assert "defenseclaw upgrade" not in check["remediation"]
    assert "policy digest --json" not in check["remediation"]


def test_unverified_gateway_executable_names_the_permission_fix_and_the_repair(
    install_home, per_user_install, monkeypatch
) -> None:
    def refuse():
        raise OSError("refusing to run /x/defenseclaw-gateway: writable by another account")

    monkeypatch.setattr(gateway, "resolve_trusted_gateway_binary", refuse)
    failure: list[str] = []
    assert gateway.local_policy_digest(SimpleNamespace(data_dir=str(install_home)), failure=failure) is None

    check = _policy_row(monkeypatch, failure[0])

    assert "writable by another account" in check["detail"]
    assert "writable only by this account" in check["remediation"]
    assert _repair_route() in check["remediation"]
    assert "defenseclaw upgrade" not in check["remediation"]
    assert "policy digest --json" not in check["remediation"]


def test_explicit_gateway_path_that_is_absent_names_the_variable(
    install_home, per_user_install, tmp_path, monkeypatch
) -> None:
    absent = tmp_path / "gone" / "defenseclaw-gateway"
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", str(absent))
    monkeypatch.setattr(gateway, "resolve_trusted_gateway_binary", gateway.resolve_gateway_binary)
    failure: list[str] = []

    assert gateway.local_policy_digest(SimpleNamespace(data_dir=str(install_home)), failure=failure) is None

    check = _policy_row(monkeypatch, failure[0])
    assert str(absent) in check["detail"]
    assert "could not be started" in check["detail"]
    assert "DEFENSECLAW_GATEWAY_BIN" in check["remediation"]
    assert "policy digest --json" not in check["remediation"]
    assert "defenseclaw upgrade" not in check["remediation"]


def test_installed_gateway_that_cannot_start_names_the_repair(install_home, per_user_install, monkeypatch) -> None:
    def cannot_start(*_args, **_kwargs):
        raise OSError(8, "Exec format error")

    monkeypatch.setattr(gateway.subprocess, "run", cannot_start)
    failure: list[str] = []
    assert gateway.local_policy_digest(SimpleNamespace(data_dir=str(install_home)), failure=failure) is None

    check = _policy_row(monkeypatch, failure[0])

    assert "/trusted/defenseclaw-gateway" in check["detail"]
    assert _repair_route() in check["remediation"]
    assert "policy digest --json" not in check["remediation"]


def test_windows_hint_names_the_install_command_not_the_posix_resolver(
    install_home, per_user_install, as_windows, monkeypatch
) -> None:
    monkeypatch.setattr(gateway, "resolve_trusted_gateway_binary", lambda: None)
    failure: list[str] = []
    assert gateway.local_policy_digest(SimpleNamespace(data_dir=str(install_home)), failure=failure) is None

    remediation = _policy_row(monkeypatch, failure[0])["remediation"]

    assert WINDOWS_ROUTE in remediation
    assert RESOLVER_COMMAND not in remediation


def test_packaged_windows_install_ignores_the_override_so_the_row_names_the_install_command(
    install_home, tmp_path, as_windows, per_user_install, monkeypatch
) -> None:
    # The packaged runtime ignores DEFENSECLAW_GATEWAY_BIN and its sibling is
    # missing: setting or unsetting the variable changes nothing, so the row
    # must name the repair of the package.
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", str(tmp_path / "elsewhere" / "defenseclaw-gateway.exe"))
    monkeypatch.setattr(gateway, "packaged_windows_install_root", lambda: str(tmp_path / "install"))
    monkeypatch.setattr(gateway, "packaged_windows_gateway_path", lambda: None)
    monkeypatch.setattr(gateway, "resolve_trusted_gateway_binary", gateway.resolve_gateway_binary)
    assert gateway.resolve_gateway_binary() is None
    failure: list[str] = []
    assert gateway.local_policy_digest(SimpleNamespace(data_dir=str(install_home)), failure=failure) is None

    remediation = _policy_row(monkeypatch, failure[0])["remediation"]

    assert "DEFENSECLAW_GATEWAY_BIN" not in remediation
    assert WINDOWS_ROUTE in remediation


@pytest.mark.parametrize("kind", ["missing", "unverified"])
def test_managed_install_names_the_administrator_route_not_the_per_user_resolver(
    install_home, monkeypatch, kind
) -> None:
    # defenseclaw-upgrade.sh refuses a managed computer, so naming it clears nothing.
    from defenseclaw import upgrade_shim

    lifecycle = "/opt/defenseclaw/bin/defenseclaw-gateway enterprise linux"
    monkeypatch.setattr(upgrade_shim, "managed_deployment", lambda: "/etc/defenseclaw/managed-runtime.json")
    monkeypatch.setattr(upgrade_shim, "managed_lifecycle_command", lambda: lifecycle)
    if kind == "missing":
        monkeypatch.setattr(gateway, "resolve_trusted_gateway_binary", lambda: None)
    else:
        def refuse():
            raise OSError("refusing to run /x/defenseclaw-gateway: writable by another account")

        monkeypatch.setattr(gateway, "resolve_trusted_gateway_binary", refuse)
    failure: list[str] = []
    assert gateway.local_policy_digest(SimpleNamespace(data_dir=str(install_home)), failure=failure) is None

    remediation = _policy_row(monkeypatch, failure[0])["remediation"]

    assert "managed by your organization" in remediation
    assert "IT department" in remediation
    assert f"sudo {lifecycle} status" in remediation
    assert "defenseclaw-upgrade.sh" not in remediation
    assert "install command" not in remediation
    assert "policy digest --json" not in remediation


def test_managed_install_with_an_override_still_ends_in_a_step_that_clears_the_row(
    install_home, tmp_path, monkeypatch
) -> None:
    from defenseclaw import upgrade_shim

    monkeypatch.setattr(upgrade_shim, "managed_deployment", lambda: "/etc/defenseclaw/managed-runtime.json")
    monkeypatch.setattr(upgrade_shim, "managed_lifecycle_command", lambda: "")
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", str(tmp_path / "gone" / "defenseclaw-gateway"))
    monkeypatch.setattr(gateway, "resolve_trusted_gateway_binary", gateway.resolve_gateway_binary)
    failure: list[str] = []
    assert gateway.local_policy_digest(SimpleNamespace(data_dir=str(install_home)), failure=failure) is None

    remediation = _policy_row(monkeypatch, failure[0])["remediation"]

    assert "DEFENSECLAW_GATEWAY_BIN" in remediation
    assert "IT department" in remediation
    assert "defenseclaw-upgrade.sh" not in remediation


def test_gateway_command_that_times_out_keeps_the_diagnose_command(install_home, monkeypatch) -> None:
    def hang(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("defenseclaw-gateway", 60)

    monkeypatch.setattr(gateway.subprocess, "run", hang)
    failure: list[str] = []
    assert gateway.local_policy_digest(SimpleNamespace(data_dir=str(install_home)), failure=failure) is None

    check = _policy_row(monkeypatch, failure[0])

    assert "did not finish" in check["detail"]
    assert "policy digest --json" in check["remediation"]


@pytest.mark.skipif(os.name == "nt", reason="the release upgrade resolver is a POSIX shell script")
def test_named_repair_command_reinstalls_a_missing_gateway_at_the_current_version(
    install_home, tmp_path, monkeypatch
) -> None:
    # The command the Policy row names must change something when the gateway
    # is missing and the install is already at the latest release.
    monkeypatch.setattr(gateway, "resolve_trusted_gateway_binary", lambda: None)
    failure: list[str] = []
    assert gateway.local_policy_digest(SimpleNamespace(data_dir=str(install_home)), failure=failure) is None
    remediation = _policy_row(monkeypatch, failure[0])["remediation"]
    named = re.search(r"`bash defenseclaw-upgrade\.sh([^`]*)`", remediation)
    assert named, remediation

    version = "1.0.9"
    installer = tmp_path / "install.sh"
    ran = tmp_path / "installer-ran"
    installer.write_text(f"#!/bin/bash\nreadonly DC_VERSION=\"{version}\"\necho \"$@\" > {ran}\n", encoding="utf-8")
    checksum = hashlib.sha256(installer.read_bytes()).hexdigest()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "curl").write_text(
        "#!/bin/sh\n"
        "out=; prev=; url=\n"
        "for a in \"$@\"; do [ \"$prev\" = -o ] && out=$a; prev=$a; url=$a; done\n"
        "case \"$*\" in *-fsSI*)\n"
        f"  printf \"HTTP/2 302\\r\\nlocation: https://github.com/x/releases/tag/{version}\\r\\n\\r\\n\"; exit 0;;\n"
        "esac\n"
        "case \"$url\" in\n"
        f"  */install.sh) cp {installer} \"$out\";;\n"
        f"  */checksums.txt) printf \"%s  install.sh\\n\" {checksum} > \"$out\";;\n"
        "  *) exit 22;;\n"
        "esac\n",
        encoding="utf-8",
    )
    (bin_dir / "cosign").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    home = tmp_path / "home"
    (home / ".local" / "bin").mkdir(parents=True)
    # The install is current: the gateway that is still on disk reports the latest release.
    present = home / ".local" / "bin" / "defenseclaw-gateway"
    present.write_text(f"#!/bin/sh\necho defenseclaw-gateway {version}\n", encoding="utf-8")
    present.chmod(0o755)
    for tool in (bin_dir / "curl", bin_dir / "cosign"):
        tool.chmod(0o755)
    system_path = os.environ["PATH"]
    env = {**os.environ, "HOME": str(home), "PATH": f"{bin_dir}{os.pathsep}{system_path}"}
    env.pop("DEFENSECLAW_REPO", None)
    env.pop("DEFENSECLAW_UPGRADE_LOCAL_DIR", None)
    script = Path(__file__).resolve().parents[2] / "scripts" / "defenseclaw-upgrade.sh"

    result = subprocess.run(
        ["bash", str(script), *named.group(1).split()],
        capture_output=True, text=True, check=False, env=env, timeout=30,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "up to date" not in result.stdout
    assert ran.exists(), "the named repair command did not run the installer at the current version"


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
