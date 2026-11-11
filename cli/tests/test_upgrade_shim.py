# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the upgrade shim, the console entry point, and the update notice."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import types
import urllib.error
from pathlib import Path

import pytest
from click.testing import CliRunner
from defenseclaw import entry, update_notice, upgrade_shim
from defenseclaw.commands import cmd_upgrade

from tests.os_view import os_view

ROOT = Path(__file__).resolve().parents[2]
_FIND_COSIGN = upgrade_shim._cosign


@pytest.fixture(autouse=True)
def shim_os(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """The shim's own view of ``os``.

    Tests pretend a platform (``os.name``) and stub ``execv``/``chdir`` for
    the shim only. Patching the real module leaked the pretence into the
    config writer the shim calls: on a Windows runner a pretend POSIX host
    fsynced the config folder, which Windows refuses (GAP-0273).
    """
    view = types.ModuleType("os")
    view.__dict__.update(vars(os))
    monkeypatch.setattr(upgrade_shim, "os", view)
    return view


_REAL_WATCH_RECOVERY_COPY = upgrade_shim._watch_recovery_copy


@pytest.fixture(autouse=True)
def recovery_watchers(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, str]]:
    """Record the recovery watchers the shim starts instead of starting a PowerShell for each."""
    started: list[tuple[int, str]] = []

    def record(powershell: str, pid: int, recovery: tuple[str, str] | None, env: dict[str, str]) -> None:
        if recovery:
            started.append((pid, os.path.dirname(recovery[0])))

    monkeypatch.setattr(upgrade_shim, "_watch_recovery_copy", record)
    return started


def test_platform_pretence_stays_in_the_shim(monkeypatch: pytest.MonkeyPatch) -> None:
    # GAP-0273: a pretend platform reaches only the shim, never the config
    # writer and file helpers it calls; the environment stays shared.
    real = os.name
    monkeypatch.setattr(upgrade_shim.os, "name", "posix" if real == "nt" else "nt")
    assert os.name == real
    assert upgrade_shim.os.environ is os.environ


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    data = tmp_path / "home" / ".defenseclaw"
    data.mkdir(parents=True)
    (tmp_path / "tmp").mkdir()
    # The shim stages installers with tempfile.mkdtemp; keep them out of TMPDIR.
    monkeypatch.setattr(upgrade_shim.tempfile, "tempdir", str(tmp_path / "tmp"))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(data))
    monkeypatch.delenv(upgrade_shim.LOCAL_DIR_ENV, raising=False)
    monkeypatch.delenv(upgrade_shim.REPO_ENV, raising=False)
    monkeypatch.delenv(update_notice.NO_CHECK_ENV, raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    for name in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"):
        monkeypatch.delenv(name, raising=False)
    # A developer's own cosign must not take part; the signature tests add a fake one.
    monkeypatch.setattr(upgrade_shim, "_cosign", lambda: None)
    return data


@pytest.fixture()
def execs(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []
    monkeypatch.setattr(upgrade_shim.os, "execv", lambda path, argv: calls.append(list(argv)))
    # A downgrade waits for the older installer (rel-1-0-4:GAP-2503).
    monkeypatch.setattr(upgrade_shim, "_wait_for_installer", lambda argv: calls.append(list(argv)) or 0)
    monkeypatch.setattr(upgrade_shim.os, "chdir", lambda path: None)
    monkeypatch.setattr(upgrade_shim.os, "name", "posix")
    return calls


def _release_dir(tmp_path: Path, version: str, *, tamper: bool = False) -> Path:
    release = tmp_path / f"release-{version}"
    release.mkdir()
    installer = f'#!/bin/bash\nDC_VERSION="{version}"\necho installing\n'
    # Bytes, so Windows newline translation cannot change the digest.
    (release / "install.sh").write_bytes(installer.encode())
    digest = hashlib.sha256(installer.encode()).hexdigest()
    if tamper:
        digest = "0" * 64
    (release / "checksums.txt").write_text(f"{digest}  install.sh\n{'1' * 64}  other.tar.gz\n", encoding="utf-8")
    return release


def test_parse_accepts_the_permanent_flag_set() -> None:
    assert upgrade_shim._parse("upgrade", ["--version", "v1.2.3", "-y"]) == {"version": "1.2.3", "yes": True}
    assert upgrade_shim._parse("upgrade", ["--version=1.0.0"]) == {"version": "1.0.0", "yes": False}
    assert upgrade_shim._parse("rollback", ["--yes"]) == {"version": None, "yes": True}
    assert upgrade_shim._parse("upgrade", ["--help"]) is None
    # The console entry sends upgrade straight here, so the hidden 0.8.x flag must be accepted too.
    assert upgrade_shim._parse("upgrade", ["--recover-corrupt-audit", "--yes"]) == {"version": None, "yes": True}


@pytest.mark.parametrize("args", [["--version", "1.2"], ["--bogus"], ["--version"]])
def test_parse_rejects_bad_input(args: list[str]) -> None:
    with pytest.raises(upgrade_shim.ShimError):
        upgrade_shim._parse("upgrade", args)


@pytest.mark.parametrize("args", [["--version"], ["--version", "--yes"], ["-y", "--version"], ["--version="]])
def test_a_version_flag_without_a_value_says_it_needs_one(args: list[str]) -> None:
    # GAP-2258: the flag is valid, so the error must not call it unknown.
    with pytest.raises(upgrade_shim.ShimUsageError) as excinfo:
        upgrade_shim._parse("upgrade", args)
    assert "unknown option" not in str(excinfo.value)
    assert "--version needs a release number" in str(excinfo.value)
    assert excinfo.value.exit_code == 2


def test_rollback_does_not_take_a_version() -> None:
    with pytest.raises(upgrade_shim.ShimError):
        upgrade_shim._parse("rollback", ["--version", "1.0.0"])


class _Response:
    def __init__(self, location: str) -> None:
        self.headers = {"Location": location}

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def test_latest_version_reads_the_redirect_without_the_api(monkeypatch: pytest.MonkeyPatch) -> None:
    requested: list[str] = []

    class Opener:
        def open(self, request, timeout):
            requested.append(request.full_url)
            raise urllib.error.HTTPError(
                request.full_url,
                302,
                "Found",
                {"Location": "https://github.com/o/r/releases/tag/1.4.2"},
                None,
            )

    monkeypatch.setattr(upgrade_shim.urllib.request, "build_opener", lambda *_handlers: Opener())

    assert upgrade_shim.latest_version("o/r") == "1.4.2"
    assert requested == ["https://github.com/o/r/releases/latest"]


def test_latest_version_rejects_a_non_release_location(monkeypatch: pytest.MonkeyPatch) -> None:
    class Opener:
        def open(self, request, timeout):
            return _Response("https://github.com/o/r/releases")

    monkeypatch.setattr(upgrade_shim.urllib.request, "build_opener", lambda *_handlers: Opener())
    monkeypatch.setattr(upgrade_shim, "_latest_from_api", lambda repo, timeout: None)

    with pytest.raises(upgrade_shim.ShimError):
        upgrade_shim.latest_version("o/r")


def test_latest_version_retries_with_get_when_head_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    methods: list[str] = []

    class Opener:
        def open(self, request, timeout):
            methods.append(request.get_method())
            if request.get_method() == "HEAD":
                raise urllib.error.HTTPError(request.full_url, 405, "Method Not Allowed", {}, None)
            return _Response("https://github.com/o/r/releases/tag/v2.0.1")

    monkeypatch.setattr(upgrade_shim.urllib.request, "build_opener", lambda *_handlers: Opener())

    assert upgrade_shim.latest_version("o/r") == "2.0.1"
    assert methods == ["HEAD", "GET"]


def test_latest_version_falls_back_to_the_api(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upgrade_shim, "_latest_from_redirect", lambda repo, method, timeout: None)
    monkeypatch.setattr(upgrade_shim, "_latest_from_api", lambda repo, timeout: "3.1.4")

    assert upgrade_shim.latest_version("o/r") == "3.1.4"


def test_upgrade_is_a_no_op_when_current(
    home: Path, execs: list[list[str]], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.2.0")
    monkeypatch.setattr(upgrade_shim, "_latest_version", lambda repo: "1.2.0")

    assert upgrade_shim.run(["upgrade"]) == 0
    assert execs == []
    assert "up to date" in capsys.readouterr().out


def test_upgrade_never_targets_0x(home: Path, execs: list[list[str]], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.2.0")

    assert upgrade_shim.run(["upgrade", "--version", "0.8.10"]) == 1
    assert execs == []


def test_upgrade_runs_the_verified_release_installer(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    release = _release_dir(tmp_path, "1.0.1")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(release))

    assert upgrade_shim.run(["upgrade", "--yes"]) == 0

    assert len(execs) == 1
    bash, script, *args = execs[0]
    assert os.path.basename(script) == "install.sh"
    assert Path(script).read_text(encoding="utf-8") == (release / "install.sh").read_text(encoding="utf-8")
    assert args == ["--yes", "--local", str(release)]


@pytest.mark.parametrize("platform", ["posix", "nt"])
def test_installer_handoff_keeps_relative_retired_config_paths_bound_to_the_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shim_os: types.ModuleType, platform: str
) -> None:
    caller = tmp_path / "caller"
    caller.mkdir()
    staged = tmp_path / "staged"
    staged.mkdir()
    monkeypatch.chdir(caller)
    monkeypatch.setenv("OMNIGENT_CONFIG_HOME", "./policyhome")
    monkeypatch.setenv("OMNIGENT_CONFIG", "./config/agent.yaml")
    monkeypatch.setattr(upgrade_shim, "_configured_update_source", lambda: "")
    monkeypatch.setattr(shim_os, "name", platform)
    called: dict[str, object] = {}
    monkeypatch.setattr(shim_os, "chdir", lambda path: called.setdefault("chdir", path))
    monkeypatch.setattr(shim_os, "execv", lambda path, args: called.setdefault("env", dict(os.environ)))
    monkeypatch.setattr(upgrade_shim, "_windows_terminal_without_desktop", lambda: False)
    monkeypatch.setattr(
        upgrade_shim.subprocess,
        "Popen",
        lambda *args, **kwargs: called.update({"env": kwargs["env"], "cwd": kwargs["cwd"]})
        or _child(lambda: 0),
    )

    assert upgrade_shim._run_installer(str(staged / "install.sh"), [], str(staged), rerun="defenseclaw upgrade") == 0
    assert "chdir" not in called
    if platform == "nt":
        assert called["cwd"] == str(staged)
    inherited = called["env"]
    assert isinstance(inherited, dict)
    assert inherited["OMNIGENT_CONFIG_HOME"] == str(caller / "policyhome")
    assert inherited["OMNIGENT_CONFIG"] == str(caller / "config" / "agent.yaml")


def test_upgrade_refuses_an_installer_that_does_not_match_checksums(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.1", tamper=True)))

    assert upgrade_shim.run(["upgrade", "--yes"]) == 1
    assert execs == []


def _fake_cosign(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, verify_rc: int) -> Path:
    tools = tmp_path / "tools"
    tools.mkdir()
    log = tmp_path / "cosign.log"
    cosign = tools / "cosign"
    cosign.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{log}"\n'
        'if [ "$1" = version ]; then echo "GitVersion:    v2.6.3"; exit 0; fi\n'
        f"exit {verify_rc}\n"
    )
    cosign.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tools}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setattr(upgrade_shim, "_cosign", _FIND_COSIGN)
    return log


@pytest.mark.skipif(os.name == "nt", reason="the fake cosign is a shell script")
@pytest.mark.parametrize("verify_rc", [0, 1])
def test_installed_cosign_checks_the_release_signature_first(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verify_rc: int
) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    release = _release_dir(tmp_path, "1.0.1")
    (release / "checksums.txt.bundle").write_text("{}")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(release))
    log = _fake_cosign(tmp_path, monkeypatch, verify_rc=verify_rc)

    rc = upgrade_shim.run(["upgrade", "--yes"])

    calls = log.read_text().splitlines()
    assert any(call.startswith("verify-blob --bundle ") for call in calls)
    # Nothing but the installer and checksums.txt, so the installer can remove the dir.
    assert not list((tmp_path / "tmp").glob("*/checksums.txt.bundle"))
    assert any("--certificate-oidc-issuer https://token.actions.githubusercontent.com" in call for call in calls)
    if verify_rc == 0:
        assert rc == 0 and len(execs) == 1
    else:
        assert rc == 1 and execs == []


@pytest.mark.skipif(os.name == "nt", reason="the fake cosign is a shell script")
def test_a_local_build_without_a_bundle_skips_the_signature(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.1")))
    log = _fake_cosign(tmp_path, monkeypatch, verify_rc=1)

    assert upgrade_shim.run(["upgrade", "--yes"]) == 0
    assert len(execs) == 1
    assert "verify-blob" not in log.read_text()


def test_a_failed_fetch_leaves_no_temporary_directory(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.1", tamper=True)))

    assert upgrade_shim.run(["upgrade", "--yes"]) == 1
    assert list((tmp_path / "tmp").iterdir()) == []


def test_an_installer_stamped_with_another_release_is_refused(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A mirror can serve a genuinely signed older release under the requested version.
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.0")))

    assert upgrade_shim.run(["upgrade", "--version", "1.2.0"]) == 1
    assert execs == []


def test_a_downloaded_installer_without_a_version_stamp_is_refused(tmp_path: Path) -> None:
    # An older signed installer has no stamp in this format; only a local test build may lack one.
    unstamped = tmp_path / "install.sh"
    unstamped.write_text("#!/bin/bash\necho installing\n", encoding="utf-8")
    with pytest.raises(upgrade_shim.ShimError, match="release unknown"):
        upgrade_shim._check_installer_version(str(unstamped), "1.2.0")
    upgrade_shim._check_installer_version(str(unstamped), "1.2.0", test_build=True)


def test_explicit_version_may_reinstall_or_go_back(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.3.0")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.2.0")))

    assert upgrade_shim.run(["upgrade", "--version", "1.2.0"]) == 0
    assert len(execs) == 1


def test_windows_starts_the_installer_detached(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    release = tmp_path / "release"
    release.mkdir()
    script = '$DcVersion = "1.0.1"\n'
    (release / "install.ps1").write_bytes(script.encode())
    (release / "checksums.txt").write_text(
        f"{hashlib.sha256(script.encode()).hexdigest()}  install.ps1\n", encoding="utf-8"
    )
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(release))
    monkeypatch.setattr(upgrade_shim.os, "name", "nt")
    monkeypatch.setenv("PSModulePath", r"C:\Program Files\PowerShell\7\Modules")
    started: list[list[str]] = []
    envs: list[dict[str, str]] = []

    def popen(argv: list[str], **kwargs: object) -> types.SimpleNamespace:
        started.append(argv)
        envs.append(kwargs["env"])  # type: ignore[arg-type]
        _write_transcript(home)
        return _child(lambda: None)

    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", popen)
    monkeypatch.setattr(subprocess, "CREATE_NEW_CONSOLE", 16, raising=False)

    assert upgrade_shim.run(["upgrade", "--yes"]) == 0
    # Windows PowerShell 5.1 cannot load its modules from PowerShell 7 folders.
    assert not [key for key in envs[0] if key.upper() == "PSMODULEPATH"]
    assert envs[0]["PATH"] == os.environ["PATH"]

    assert started[0][1:6] == ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", started[0][5]]
    assert started[0][5].endswith("install.ps1")
    assert started[0][6:] == ["-Yes", "-Local", str(release)]


def test_windows_rollback_over_ssh_gives_the_command_for_this_terminal(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # GAP-1993: the new window never appears in an SSH session; rc 0 hid the result.
    from defenseclaw import __version__

    (home / "installer").mkdir()
    (home / "installer" / "install.ps1").write_text(f'$DcVersion = "{__version__}"\n', encoding="utf-8")
    _record(home, home / "installer" / "install.ps1")
    monkeypatch.setattr(upgrade_shim.os, "name", "nt")
    monkeypatch.setenv("SSH_CONNECTION", "10.0.0.1 50000 10.0.0.2 22")
    started: list[object] = []
    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: started.append(args))

    assert upgrade_shim.run(["rollback", "--yes"]) == 1

    assert started == []
    err = capsys.readouterr().err
    assert "no desktop (SSH session)" in err and "Nothing was changed." in err
    command = next(line.strip() for line in err.splitlines() if line.strip().startswith("powershell "))
    assert command.endswith("install.ps1\" -Rollback -Yes"), command
    staged = command.split('"')[1]
    assert os.path.isfile(staged) and staged != str(home / "installer" / "install.ps1")


_INSTALLER_PID = 4242
_LOG_NAME = "install-20261110T022503.log"


def _child(poll: object, pid: int = _INSTALLER_PID) -> types.SimpleNamespace:
    return types.SimpleNamespace(poll=poll, pid=pid)


def _write_transcript(home: Path, pid: int = _INSTALLER_PID, name: str = _LOG_NAME) -> None:
    """Append the header a PowerShell transcript of process *pid* starts with."""
    logs = home / "logs"
    logs.mkdir(exist_ok=True)
    header = f"**********************\nWindows PowerShell transcript start\nProcess ID: {pid}\nPSVersion: 5.1\n"
    with open(logs / name, "ab") as stream:
        stream.write(header.encode("utf-8"))


def _windows_rollback_with_desktop(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw import __version__

    (home / "installer").mkdir()
    (home / "installer" / "install.ps1").write_text(f'$DcVersion = "{__version__}"\n', encoding="utf-8")
    _record(home, home / "installer" / "install.ps1")
    monkeypatch.setattr(upgrade_shim.os, "name", "nt")
    monkeypatch.setattr(upgrade_shim, "_windows_terminal_without_desktop", lambda: False)
    monkeypatch.setattr(upgrade_shim.time, "sleep", lambda seconds: None)


def test_windows_rollback_whose_installer_ends_before_its_log_is_an_error_not_rc_0(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # GAP-1011: the installer window closed before the installer opened its
    # log; the shim had printed "continues in a new window" and returned 0.
    _windows_rollback_with_desktop(home, monkeypatch)
    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: _child(lambda: 1))

    assert upgrade_shim.run(["rollback", "--yes"]) == 1

    captured = capsys.readouterr()
    assert "exit code 1 before it opened its log" in captured.err, captured.err
    assert "defenseclaw doctor" in captured.err
    assert "continues in a new window" not in captured.out


def test_windows_rollback_whose_installer_holds_its_error_window_is_still_an_error(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A --yes installer that ends with an error keeps its console for 120
    # seconds (Wait-BeforeClose) before the process exits: the shim must still
    # be waiting then, not have reported a running install at 60 seconds.
    _windows_rollback_with_desktop(home, monkeypatch)
    clock = [0.0]
    monkeypatch.setattr(upgrade_shim.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(upgrade_shim.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(
        upgrade_shim.subprocess,
        "Popen",
        lambda *args, **kwargs: _child(lambda: 1 if clock[0] >= 120.0 else None),
    )

    assert upgrade_shim.run(["rollback", "--yes"]) == 1

    captured = capsys.readouterr()
    assert "exit code 1 before it opened its log" in captured.err, captured.err
    assert "continues in a new window" not in captured.out


def test_windows_rollback_whose_installer_opens_its_log_keeps_the_new_window_notice(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _windows_rollback_with_desktop(home, monkeypatch)
    polls: list[int] = []

    def poll() -> None:
        polls.append(1)
        if len(polls) == 3:
            _write_transcript(home)

    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: _child(poll))

    assert upgrade_shim.run(["rollback", "--yes"]) == 0

    captured = capsys.readouterr()
    assert "The installer continues in a new window" in captured.out
    assert "not confirmed" not in captured.out
    assert len(polls) == 3


def test_windows_installer_that_appends_to_a_same_second_log_has_opened_its_log(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The installer names a log to the second and opens it with -Append: a
    # name that was already there is not proof of nothing.
    _windows_rollback_with_desktop(home, monkeypatch)
    _write_transcript(home, pid=999)

    def poll() -> int:
        _write_transcript(home)
        return 1

    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: _child(poll))

    # The log is the proof the installer ran; its own window shows a failure.
    assert upgrade_shim.run(["rollback", "--yes"]) == 0
    assert "The installer continues in a new window" in capsys.readouterr().out


def test_windows_installer_whose_log_name_is_taken_by_another_run_is_not_confirmed_by_it(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Another install's log that grows while ours ends before opening one is
    # not ours: the transcript header names the process.
    _windows_rollback_with_desktop(home, monkeypatch)
    _write_transcript(home, pid=999)

    def poll() -> int:
        _write_transcript(home, pid=999)
        _write_transcript(home, pid=42420, name="install-20261110T022504.log")
        return 1

    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: _child(poll))

    assert upgrade_shim.run(["rollback", "--yes"]) == 1
    assert "exit code 1 before it opened its log" in capsys.readouterr().err


def test_windows_installer_that_fails_after_opening_its_log_is_not_a_shim_error(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _windows_rollback_with_desktop(home, monkeypatch)

    def poll() -> int:
        _write_transcript(home)
        return 1

    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: _child(poll))

    # The log is the proof the installer ran; its own window shows a failure.
    assert upgrade_shim.run(["rollback", "--yes"]) == 0
    assert "The installer continues in a new window" in capsys.readouterr().out


def test_windows_installer_still_running_without_a_log_is_an_unconfirmed_error_not_rc_0(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _windows_rollback_with_desktop(home, monkeypatch)
    clock = [0.0]
    monkeypatch.setattr(upgrade_shim.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(upgrade_shim.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: _child(lambda: None))

    assert upgrade_shim.run(["rollback", "--yes"]) == 1

    captured = capsys.readouterr()
    assert "still running and has not opened its log after 450 seconds, so the start is not confirmed" in captured.err
    assert "continues in a new window" not in captured.out
    assert clock[0] >= 450.0


def test_windows_installer_that_waits_out_the_uninstall_cleanup_and_fails_is_an_error_not_rc_0(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Before it has a log the installer waits up to 300 s for an earlier
    # uninstall's cleanup, then fails and keeps its console for 120 s: the
    # process ends at 420 s, which the shim still waits for.
    _windows_rollback_with_desktop(home, monkeypatch)
    clock = [0.0]
    monkeypatch.setattr(upgrade_shim.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(upgrade_shim.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(
        upgrade_shim.subprocess,
        "Popen",
        lambda *args, **kwargs: _child(lambda: 1 if clock[0] >= 420.0 else None),
    )

    assert upgrade_shim.run(["rollback", "--yes"]) == 1

    captured = capsys.readouterr()
    assert "exit code 1 before it opened its log" in captured.err, captured.err
    assert "still running" not in captured.err
    assert "continues in a new window" not in captured.out


def test_windows_installer_that_fails_without_a_log_does_not_claim_that_nothing_changed(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # install.ps1 goes on without a transcript when Start-Transcript fails, so
    # it can reach a changing step and then fail with no log: no log is not
    # proof of no change, and the staged installer stays for a recovery run.
    _windows_rollback_with_desktop(home, monkeypatch)
    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: _child(lambda: 1))

    assert upgrade_shim.run(["rollback", "--yes"]) == 1

    err = capsys.readouterr().err
    assert "result is not known" in err, err
    assert "no change" not in err.lower() and "nothing was changed" not in err.lower()
    assert "may have stopped before changing anything" in err
    assert "defenseclaw --version" in err and "run this command again" in err
    command = next(line.strip() for line in err.splitlines() if line.strip().startswith("powershell "))
    assert command.endswith("-Rollback -Yes"), command
    assert os.path.isfile(command.split('"')[1])


_INSTALLER_CLEANUP_LEAF = re.compile(r"^defenseclaw-(upgrade|rollback)-[a-z0-9_]+$")


def _installer_that_cleans_up_then_fails(created: list[str]) -> object:
    """A Popen stand-in whose child does what install.ps1 does in its finally block, then ends with exit 1."""

    def popen(argv: list[str], **kwargs: object) -> types.SimpleNamespace:
        script = argv[argv.index("-File") + 1]
        launch_dir = os.path.dirname(script)
        created.append(launch_dir)

        def poll() -> int:
            names = set(os.listdir(launch_dir)) if os.path.isdir(launch_dir) else set()
            if _INSTALLER_CLEANUP_LEAF.match(os.path.basename(launch_dir)) and names <= {
                "install.ps1",
                "checksums.txt",
                "checksums.txt.bundle",
            }:
                shutil.rmtree(launch_dir)
            return 1

        return _child(poll)

    return popen


def _recovery_dirs(home: Path) -> list[Path]:
    return list((home.parent.parent / "tmp").glob("defenseclaw-recovery-*"))


def _printed_target(err: str) -> str:
    command = next(line.strip() for line in err.splitlines() if line.strip().startswith("powershell "))
    return command.split('"')[1]


def test_windows_no_log_failure_names_a_verified_installer_that_outlives_the_installer_cleanup(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # install.ps1 deletes the temporary directory it runs from before it
    # exits; the command in the message must name a copy that survives that.
    _windows_rollback_with_desktop(home, monkeypatch)
    created: list[str] = []
    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", _installer_that_cleans_up_then_fails(created))

    assert upgrade_shim.run(["rollback", "--yes"]) == 1

    err = capsys.readouterr().err
    assert created and not os.path.exists(created[0]), "the fake child did not perform the installer cleanup"
    target = _printed_target(err)
    assert os.path.isfile(target), err
    assert not _INSTALLER_CLEANUP_LEAF.match(os.path.basename(os.path.dirname(target)))
    saved = (home / "installer" / "install.ps1").read_bytes()
    assert Path(target).read_bytes() == saved
    assert hashlib.sha256(saved).hexdigest() in err


@pytest.mark.parametrize("damage", ["missing", "changed"])
def test_windows_no_log_failure_prints_the_release_command_when_the_recovery_copy_does_not_verify(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], damage: str
) -> None:
    _windows_rollback_with_desktop(home, monkeypatch)
    created: list[str] = []
    cleanup = _installer_that_cleans_up_then_fails(created)

    def popen(argv: list[str], **kwargs: object) -> types.SimpleNamespace:
        child = cleanup(argv, **kwargs)
        recovery = _recovery_dirs(home)[0]
        if damage == "missing":
            shutil.rmtree(recovery)
        else:
            (recovery / "install.ps1").write_bytes(b"changed")
        return child

    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", popen)

    assert upgrade_shim.run(["rollback", "--yes"]) == 1

    err = capsys.readouterr().err
    assert "powershell -NoProfile" not in err, err
    # The command the user ran goes back through the shim; no release URL.
    assert "run this command again (the kept copy is not available)" in err, err
    assert err.rstrip().splitlines()[-2].strip() == "defenseclaw rollback --yes", err
    assert "releases/" not in err and "irm " not in err, err
    assert _recovery_dirs(home) == []


@pytest.mark.parametrize("damage", ["missing", "changed"])
def test_windows_downgrade_no_log_failure_with_a_damaged_recovery_copy_names_the_command_the_user_ran(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], damage: str
) -> None:
    # A downgrade stages the current saved installer, because an older one
    # cannot read the recovery receipts of this install. When the kept copy is
    # damaged, the fallback must not hand the user the older release installer.
    monkeypatch.setattr("defenseclaw.__version__", "1.0.9")
    _windows_rollback_with_desktop(home, monkeypatch)
    created: list[str] = []
    cleanup = _installer_that_cleans_up_then_fails(created)
    launched: list[list[str]] = []

    def popen(argv: list[str], **kwargs: object) -> types.SimpleNamespace:
        if "-File" not in argv:  # a hardware probe of the upgrade, not the installer
            raise FileNotFoundError(argv[0])
        launched.append(argv)
        child = cleanup(argv, **kwargs)
        recovery = _recovery_dirs(home)[0]
        if damage == "missing":
            shutil.rmtree(recovery)
        else:
            (recovery / "install.ps1").write_bytes(b"changed")
        return child

    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", popen)

    assert upgrade_shim.run(["upgrade", "--version", "v1.0.5", "--yes"]) == 1

    err = capsys.readouterr().err
    assert "-Version 1.0.5" in " ".join(launched[0]), launched
    assert "run this command again (the kept copy is not available)" in err, err
    assert err.rstrip().splitlines()[-2].strip() == "defenseclaw upgrade --version 1.0.5 --yes", err
    assert "releases/" not in err and "irm " not in err and "scriptblock" not in err, err
    assert _recovery_dirs(home) == []


def test_windows_recovery_copy_is_removed_when_the_installer_ended_with_exit_code_0(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _windows_rollback_with_desktop(home, monkeypatch)
    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: _child(lambda: 0))

    assert upgrade_shim.run(["rollback", "--yes"]) == 0
    assert _recovery_dirs(home) == []


def test_windows_recovery_copy_is_kept_when_the_installer_opened_its_log_and_then_failed(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An open log is a start, not a result: the installer may fail later and
    # delete the folder it runs from, so the verified copy is the way back.
    _windows_rollback_with_desktop(home, monkeypatch)

    def poll() -> int:
        _write_transcript(home)
        return 1

    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: _child(poll))

    assert upgrade_shim.run(["rollback", "--yes"]) == 0
    kept = _recovery_dirs(home)
    assert len(kept) == 1
    assert (kept[0] / "install.ps1").read_bytes() == (home / "installer" / "install.ps1").read_bytes()


def test_windows_recovery_copy_is_kept_when_the_installer_still_runs_without_a_log(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _windows_rollback_with_desktop(home, monkeypatch)
    clock = [0.0]
    monkeypatch.setattr(upgrade_shim.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(upgrade_shim.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: _child(lambda: None))

    assert upgrade_shim.run(["rollback", "--yes"]) == 1
    assert len(_recovery_dirs(home)) == 1


def test_windows_recovery_copy_is_removed_when_the_installer_opened_its_log_and_ended_with_exit_code_0(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _windows_rollback_with_desktop(home, monkeypatch)

    def poll() -> int:
        _write_transcript(home)
        return 0

    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: _child(poll))

    assert upgrade_shim.run(["rollback", "--yes"]) == 0
    assert _recovery_dirs(home) == []


def test_windows_rollback_that_returns_while_the_installer_runs_hands_its_recovery_copy_to_a_watcher(
    home: Path, monkeypatch: pytest.MonkeyPatch, recovery_watchers: list[tuple[int, str]]
) -> None:
    # The shim exits while the installer still runs, so it cannot see the exit
    # code: the copy stays for the watcher, which removes it after exit code 0.
    _windows_rollback_with_desktop(home, monkeypatch)

    def poll() -> None:
        _write_transcript(home)

    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: _child(poll))

    assert upgrade_shim.run(["rollback", "--yes"]) == 0
    kept = _recovery_dirs(home)
    assert len(kept) == 1
    assert recovery_watchers == [(_INSTALLER_PID, str(kept[0]))]


def test_recovery_watcher_takes_the_pid_and_folder_from_the_environment_and_never_stands_in_the_folder(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launches: list[tuple[list[str], dict[str, object]]] = []

    def popen(argv: list[str], **kwargs: object) -> object:
        launches.append((argv, kwargs))
        return object()

    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", popen)
    monkeypatch.setenv("SystemRoot", str(home.parent))
    staged = home.parent / "install.ps1"
    staged.write_text("x", encoding="utf-8")
    recovery = upgrade_shim._stage_recovery_copy(str(staged))
    assert recovery is not None

    assert _REAL_WATCH_RECOVERY_COPY("powershell.exe", 4242, None, {}) is None
    _REAL_WATCH_RECOVERY_COPY("powershell.exe", 4242, recovery, {"KEEP": "1"})

    assert len(launches) == 1
    argv, kwargs = launches[0]
    folder = os.path.dirname(recovery[0])
    assert argv[0] == "powershell.exe" and argv[-2] == "-Command"
    assert folder not in " ".join(argv)
    env = kwargs["env"]
    assert env["DC_WATCH_PID"] == "4242" and env["DC_WATCH_DIR"] == folder and env["KEEP"] == "1"
    assert kwargs["cwd"] == str(home.parent)
    assert not str(kwargs["cwd"]).startswith(folder)
    upgrade_shim._drop_recovery_copy(recovery)


@pytest.mark.skipif(sys.platform != "win32", reason="runs the Windows PowerShell watcher")
def test_recovery_watcher_removes_the_folder_after_exit_code_0_and_keeps_it_after_a_failure(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    powershell = os.path.join(
        os.environ["SystemRoot"], "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
    )
    staged = home.parent / "install.ps1"
    staged.write_text("x", encoding="utf-8")
    runs = []
    for code in (0, 7):
        recovery = upgrade_shim._stage_recovery_copy(str(staged))
        assert recovery is not None
        installer = subprocess.Popen(  # noqa: S603 - fixed interpreter, fixed script
            [powershell, "-NoProfile", "-Command", f"Start-Sleep -Seconds 2; exit {code}"]
        )
        env = {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
        watcher = _REAL_WATCH_RECOVERY_COPY(powershell, installer.pid, recovery, env)
        assert watcher is not None
        runs.append((code, installer, watcher, os.path.dirname(recovery[0])))

    for code, installer, watcher, folder in runs:
        assert installer.wait(timeout=60) == code
        # 0: the copy was removed; 4: the installer failed and the copy was kept.
        assert watcher.wait(timeout=60) == (0 if code == 0 else 4), f"installer exit code {code}"
        assert os.path.isdir(folder) == (code != 0), f"installer exit code {code}"
        shutil.rmtree(folder, ignore_errors=True)


def test_windows_installer_that_appends_beyond_the_first_chunk_of_a_same_second_log_has_opened_its_log(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Another run appends more than a read chunk to the same-second log before
    # this installer's header: the scan goes on through the later bytes.
    logs = home / "logs"
    _write_transcript(home, pid=999)
    known = upgrade_shim._install_logs(str(logs))
    with open(logs / _LOG_NAME, "ab") as stream:
        stream.write(b"x" * (upgrade_shim._INSTALLER_LOG_CHUNK * 2 + 17))
    _write_transcript(home)

    assert upgrade_shim._log_opened_by(str(logs), known, _INSTALLER_PID)
    assert not upgrade_shim._log_opened_by(str(logs), known, _INSTALLER_PID + 1)


def test_windows_installer_header_cut_by_a_chunk_edge_and_utf16_is_found(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(upgrade_shim, "_INSTALLER_LOG_CHUNK", 1024)
    logs = home / "logs"
    logs.mkdir()
    known = upgrade_shim._install_logs(str(logs))
    header = f"Windows PowerShell transcript start\r\nProcess ID: {_INSTALLER_PID}\r\n".encode("utf-16-le")
    for lead in range(1000, 1030):
        (logs / _LOG_NAME).write_bytes("\ufeff".encode("utf-16-le") + b"y" * lead + header)
        assert upgrade_shim._log_opened_by(str(logs), known, _INSTALLER_PID), lead
        assert not upgrade_shim._log_opened_by(str(logs), known, _INSTALLER_PID + 1), lead


def test_windows_installer_log_scan_reads_only_new_bytes_on_later_polls(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logs = home / "logs"
    _write_transcript(home, pid=999)
    known = upgrade_shim._install_logs(str(logs))
    scanned: dict[str, int] = {}
    assert not upgrade_shim._log_opened_by(str(logs), known, _INSTALLER_PID, scanned)
    with open(logs / _LOG_NAME, "ab") as stream:
        stream.write(b"z" * 5000)
    assert not upgrade_shim._log_opened_by(str(logs), known, _INSTALLER_PID, scanned)
    assert scanned[_LOG_NAME] == known[_LOG_NAME] + 5000
    _write_transcript(home)
    assert upgrade_shim._log_opened_by(str(logs), known, _INSTALLER_PID, scanned)


def test_windows_installer_that_ends_with_rc_0_and_no_log_says_so(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _windows_rollback_with_desktop(home, monkeypatch)
    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: _child(lambda: 0))

    assert upgrade_shim.run(["rollback", "--yes"]) == 0

    out = capsys.readouterr().out
    assert "ended with exit code 0 without opening an install log" in out
    assert "continues in a new window" not in out


def test_rollback_uses_the_saved_installer(home: Path, execs: list[list[str]]) -> None:
    saved = home / "installer" / "install.sh"
    saved.parent.mkdir()
    saved.write_text("#!/bin/bash\n", encoding="utf-8")
    _record(home, saved)

    assert upgrade_shim.run(["rollback", "--yes"]) == 0

    assert execs[0][2:] == ["--rollback", "--yes"]
    assert execs[0][1] != str(saved)


def test_windows_rollback_to_the_setup_package_refuses_in_this_terminal(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (home / "installer").mkdir()
    (home / "installer" / "install.ps1").write_text("", encoding="utf-8")
    (home / "previous" / "legacy-setup").mkdir(parents=True)
    (home / "previous" / "VERSION").write_text("0.8.10\n", encoding="utf-8")
    monkeypatch.setattr(upgrade_shim.os, "name", "nt")
    started: list[object] = []
    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: started.append(args))

    assert upgrade_shim.run(["rollback", "--yes"]) == 1

    assert started == []
    err = capsys.readouterr().err
    assert "DefenseClaw Setup 0.8.10, which cannot be restored automatically" in err
    assert "defenseclaw uninstall" in err
    assert "releases/tag/0.8.10" in err


def test_rollback_from_a_source_install_uses_the_installer_it_replaced(home: Path, execs: list[list[str]]) -> None:
    # GAP-2459: a 'make all' install has no installer/; the release it rolled
    # back from keeps one in previous/, and that rolls forward again.
    saved = home / "previous" / "installer" / "install.sh"
    saved.parent.mkdir(parents=True)
    saved.write_text("#!/bin/bash\n", encoding="utf-8")

    assert upgrade_shim.run(["rollback", "--yes"]) == 0

    assert execs[0][2:] == ["--rollback", "--yes"]
    assert execs[0][1] != str(saved)


def test_rollback_without_a_saved_installer_explains(
    home: Path, execs: list[list[str]], capsys: pytest.CaptureFixture[str]
) -> None:
    assert upgrade_shim.run(["rollback"]) == 1
    assert execs == []
    assert "previous" in capsys.readouterr().err


def test_entry_dispatches_upgrade_before_importing_the_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []
    monkeypatch.setattr(sys, "argv", ["defenseclaw", "upgrade", "--help"])
    monkeypatch.setattr(upgrade_shim, "run", lambda argv: seen.append(argv) or 0)
    monkeypatch.delitem(sys.modules, "defenseclaw.main", raising=False)

    with pytest.raises(SystemExit) as exc:
        entry.main()

    assert exc.value.code == 0
    assert seen == [["upgrade", "--help"]]
    assert "defenseclaw.main" not in sys.modules


def test_entry_version_matches_click_without_importing_the_cli(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    from click.testing import CliRunner
    from defenseclaw.main import cli

    expected = CliRunner().invoke(cli, ["--version"], prog_name="defenseclaw").output
    notices: list[list[str]] = []
    monkeypatch.setattr(sys, "argv", ["defenseclaw", "--version"])
    monkeypatch.setattr(entry, "_notice", lambda argv: notices.append(argv))
    monkeypatch.delitem(sys.modules, "defenseclaw.main", raising=False)

    with pytest.raises(SystemExit) as exc:
        entry.main()

    assert exc.value.code == 0
    assert "defenseclaw.main" not in sys.modules
    assert notices == [["--version"]]
    assert capsys.readouterr().out == expected


def test_entry_pin_names_match_config() -> None:
    from defenseclaw import config

    assert entry._DEPLOYMENT_PIN_ENVS == config._DEPLOYMENT_PIN_ENVS


def test_entry_skips_the_config_import_without_a_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in entry._DEPLOYMENT_PIN_ENVS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delitem(sys.modules, "defenseclaw.config", raising=False)

    entry.ignore_stray_deployment_pins()

    assert "defenseclaw.config" not in sys.modules


def test_entry_notice_survives_an_uninstall_that_removed_the_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    """uninstall --all --binaries finished, then the notice import raised ModuleNotFoundError."""
    monkeypatch.setitem(sys.modules, "defenseclaw.update_notice", None)

    entry._notice(["uninstall", "--all", "--binaries"])
    entry._notice(["status"])


def test_notice_is_silent_without_a_terminal(home: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setattr(update_notice, "available_message", lambda: "update!")
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)

    update_notice.maybe_print(["status"])

    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("argv", [[], ["upgrade"], ["status", "--json"], ["audit", "-o", "json"]])
def test_notice_skips_quiet_invocations(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_notice.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(update_notice.sys.stderr, "isatty", lambda: True, raising=False)

    assert update_notice._interactive(["status"])
    assert not update_notice._interactive(argv)


def test_notice_never_creates_the_data_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    missing = tmp_path / "not-initialized"
    monkeypatch.setenv("DEFENSECLAW_HOME", str(missing))
    monkeypatch.setattr(update_notice, "_lookup_latest", lambda: "9.9.9")

    assert update_notice._latest_cached() == "9.9.9"
    assert not missing.exists()


def test_notice_reads_update_check_from_defenseclaw_config(home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    external = tmp_path / "elsewhere.yaml"
    external.write_text("config_version: 9\nupdate:\n  check: false\n")
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(external))

    assert update_notice._disabled()


def test_notice_uses_the_daily_cache(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    (home / ".update-check.json").write_text(json.dumps({"checked_at": time.time(), "latest": "1.1.0"}))
    monkeypatch.setattr(upgrade_shim, "_latest_from_redirect", lambda *_args: pytest.fail("network used"))

    assert update_notice.available_message() == (
        "DefenseClaw 1.1.0 is available (you have 1.0.0) — run 'defenseclaw upgrade'"
    )


def test_notice_refreshes_a_stale_cache(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.1.0")
    (home / ".update-check.json").write_text(json.dumps({"checked_at": 0, "latest": "1.2.0"}))
    monkeypatch.setattr(upgrade_shim, "_latest_from_redirect", lambda repo, method, timeout: "1.1.0")

    assert update_notice.available_message() is None
    assert json.loads((home / ".update-check.json").read_text())["latest"] == "1.1.0"


@pytest.mark.parametrize("setting", ["env", "ci", "config"])
def test_notice_can_be_disabled(home: Path, monkeypatch: pytest.MonkeyPatch, setting: str) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    (home / ".update-check.json").write_text(json.dumps({"checked_at": time.time(), "latest": "9.0.0"}))
    if setting == "env":
        monkeypatch.setenv(update_notice.NO_CHECK_ENV, "1")
    elif setting == "ci":
        monkeypatch.setenv("CI", "true")
    else:
        (home / "config.yaml").write_text("config_version: 9\nupdate:\n  check: false\n")

    assert update_notice.available_message() is None


def test_notice_respects_the_windows_self_update_policy(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    (home / ".update-check.json").write_text(json.dumps({"checked_at": time.time(), "latest": "9.0.0"}))
    opened: list[str] = []

    class FakeKey:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    def open_key(_root, path, _reserved, _access):
        opened.append(path)
        if path == upgrade_shim.WINDOWS_MANAGED_MARKER_KEY:
            raise OSError("no managed deployment on this host")
        return FakeKey()

    fake_winreg = types.SimpleNamespace(
        HKEY_LOCAL_MACHINE=object(),
        KEY_READ=1,
        KEY_WOW64_64KEY=256,
        OpenKey=open_key,
        QueryValueEx=lambda _key, name: (1, 4) if name == "DisableSelfUpdate" else (0, 4),
    )
    monkeypatch.setitem(sys.modules, "winreg", fake_winreg)
    monkeypatch.setattr(update_notice, "os", os_view("nt"))
    monkeypatch.setattr(upgrade_shim.os, "name", "nt")

    assert update_notice.available_message() is None
    # The managed-deployment marker is checked first; without it the
    # DisableSelfUpdate policy still silences the notice.
    assert opened == [upgrade_shim.WINDOWS_MANAGED_MARKER_KEY, r"SOFTWARE\Policies\Cisco\DefenseClaw"]


def test_notice_gives_up_on_a_slow_network(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    monkeypatch.setattr(update_notice, "_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(upgrade_shim, "_latest_from_redirect", lambda *_args: time.sleep(5) or "9.9.9")

    started = time.monotonic()
    assert update_notice.available_message() is None
    assert time.monotonic() - started < 2


def test_notice_swallows_ctrl_c(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_notice, "_interactive", lambda argv: True)

    def interrupted():
        raise KeyboardInterrupt

    monkeypatch.setattr(update_notice, "available_message", interrupted)

    update_notice.maybe_print(["status"])


def test_shim_output_survives_a_console_that_cannot_encode_it(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import io

    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr("defenseclaw.__version__", "1.2.0")
    monkeypatch.setattr(upgrade_shim, "_latest_version", lambda repo: "1.2.0")

    assert upgrade_shim.run(["upgrade"]) == 0


def test_an_installer_that_cannot_start_is_an_error_not_a_traceback(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.1")))
    monkeypatch.setattr(upgrade_shim.os, "name", "posix")
    monkeypatch.setattr(upgrade_shim.os, "chdir", lambda path: None)

    def execv(path: str, argv: list[str]) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(upgrade_shim.os, "execv", execv)

    assert upgrade_shim.run(["upgrade", "--yes"]) == 1
    assert "could not run" in capsys.readouterr().err
    assert list((tmp_path / "tmp").iterdir()) == []


def test_a_release_mirror_changes_only_where_bytes_come_from(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """update.source (and DEFENSECLAW_REPO) move the downloads; the release
    signature is always checked against the compiled official identity, and a
    mirror is refused without cosign instead of trusting its checksums.txt."""
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    release = _release_dir(tmp_path, "1.0.1")
    (release / "checksums.txt.bundle").write_text("{}")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(release))
    monkeypatch.setenv(upgrade_shim.REPO_ENV, "acme+corp/defense.claw")
    config = tmp_path / "config.yaml"
    config.write_text("update:\n  source: https://mirror.example/defenseclaw\n")
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(config))
    assert upgrade_shim.release_source() == "https://mirror.example/defenseclaw"
    seen: list[list[str]] = []
    monkeypatch.setattr(upgrade_shim, "_cosign", lambda: "/usr/bin/cosign")

    def run(argv, **_kwargs):
        seen.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(upgrade_shim.subprocess, "run", run)

    assert upgrade_shim.run(["upgrade", "--yes"]) == 0
    pattern = seen[0][seen[0].index("--certificate-identity-regexp") + 1]
    assert pattern == upgrade_shim.RELEASE_SIGNER
    assert pattern.startswith("^https://github\\.com/cisco-ai-defense/defenseclaw/")

    monkeypatch.setattr(upgrade_shim, "_cosign", lambda: None)
    with pytest.raises(upgrade_shim.ShimError, match="install cosign"):
        upgrade_shim._verify_release_signature(upgrade_shim.release_source(), "1.0.1", None, str(tmp_path), "")


def test_the_update_notice_lookup_swallows_network_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    def broken(*_args, **_kwargs):
        raise RuntimeError("no network stack")

    uncaught: list[object] = []
    monkeypatch.setattr(upgrade_shim, "_latest_from_redirect", broken)
    # An exception escaping the thread would print a traceback through this hook.
    monkeypatch.setattr(threading, "excepthook", uncaught.append)

    assert update_notice._lookup_latest() == ""
    assert uncaught == []


def test_a_download_without_cosign_says_the_signature_was_not_checked(
    home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    upgrade_shim._verify_release_signature("cisco-ai-defense/defenseclaw", "1.0.1", None, str(tmp_path), "")

    assert "checked against checksums.txt only" in capsys.readouterr().out

# ---- managed hosts: per-user upgrades, installs and notices stay out of the way


class _FakeKey:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values

    def __enter__(self) -> _FakeKey:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def _fake_winreg(values: dict[str, str] | None) -> types.ModuleType:
    module = types.ModuleType("winreg")
    module.HKEY_LOCAL_MACHINE = object()
    module.KEY_READ = 1
    module.KEY_WOW64_64KEY = 2

    def open_key(_hive, path, _reserved, _access):
        assert path == r"SOFTWARE\Cisco\DefenseClaw\Enterprise"
        if values is None:
            raise FileNotFoundError(path)
        return _FakeKey(values)

    def query_value(key, name):
        if name not in key.values:
            raise FileNotFoundError(name)
        return key.values[name], 1

    module.OpenKey = open_key
    module.QueryValueEx = query_value
    return module


@pytest.mark.parametrize(
    ("values", "expected"),
    [(None, None), ({"Profile": "standalone"}, "standalone"), ({}, "managed")],
)
def test_marker_detection(monkeypatch: pytest.MonkeyPatch, values, expected) -> None:
    # One managed-host check serves the click commands and the console
    # entry point, which runs the upgrade shim directly.
    monkeypatch.setattr(upgrade_shim, "os", types.SimpleNamespace(name="nt", path=os.path))
    monkeypatch.setitem(sys.modules, "winreg", _fake_winreg(values))
    assert cmd_upgrade._managed_enterprise_profile() == expected
    assert upgrade_shim.managed_deployment() == expected


@pytest.mark.parametrize("command", [cmd_upgrade.upgrade, cmd_upgrade.rollback])
def test_commands_refuse_before_running_the_shim(monkeypatch: pytest.MonkeyPatch, command) -> None:
    monkeypatch.setattr(cmd_upgrade, "_managed_enterprise_profile", lambda: "standalone")
    shim = types.ModuleType("defenseclaw.upgrade_shim")

    def run(_argv):
        raise AssertionError("the upgrade shim must not run on a managed host")

    shim.run = run
    monkeypatch.setitem(sys.modules, "defenseclaw.upgrade_shim", shim)
    result = CliRunner().invoke(command, ["--yes"])
    assert result.exit_code == 1
    assert "managed DefenseClaw enterprise deployment (standalone)" in result.output


@pytest.fixture
def descriptor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "managed-runtime.json"
    monkeypatch.setattr(upgrade_shim, "MANAGED_DESCRIPTORS", (str(path),))
    return path


@pytest.mark.skipif(os.name == "nt", reason="POSIX managed hosts only")
def test_upgrade_and_rollback_refuse_on_a_managed_host(descriptor: Path, capsys: pytest.CaptureFixture[str]) -> None:
    descriptor.write_text("{}", encoding="utf-8")
    for command in (["upgrade", "--yes"], ["rollback", "--yes"]):
        assert upgrade_shim.run(command) == 1
        err = capsys.readouterr().err
        assert "managed by your organization" in err
        assert "Nothing was changed" in err


def test_update_notice_is_silent_on_any_managed_deployment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(update_notice.NO_CHECK_ENV, raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(tmp_path / "missing-config.yaml"))
    monkeypatch.setattr(update_notice, "_windows_self_update_policy", lambda: False)
    monkeypatch.setattr(update_notice, "_latest_cached", lambda: "999.0.0")
    monkeypatch.setattr(upgrade_shim, "managed_deployment", lambda: None)
    assert update_notice.available_message() is not None
    monkeypatch.setattr(upgrade_shim, "managed_deployment", lambda: "standalone")
    assert update_notice.available_message() is None


@pytest.mark.skipif(os.name == "nt", reason="install.sh is POSIX")
def test_install_sh_refuses_before_changing_anything(tmp_path: Path) -> None:
    descriptor = tmp_path / "managed-runtime.json"
    descriptor.write_text("{}", encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "DEFENSECLAW_INSTALL_MANAGED_DESCRIPTOR": str(descriptor),
    }
    completed = subprocess.run(
        ["bash", str(ROOT / "scripts" / "install.sh"), "--yes"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 1
    assert "managed by your organization" in completed.stdout + completed.stderr
    assert list(home.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="install.sh is POSIX")
def test_install_sh_environment_cannot_replace_the_platform_descriptor(tmp_path: Path) -> None:
    # The test hook may only add a descriptor. Pointing it elsewhere must not
    # skip the platform descriptor, or any user could bypass the refusal.
    text = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
    block = text[text.index("# ── Managed hosts") : text.index("# ── Which version")]
    platform = tmp_path / "managed-runtime.json"
    platform.write_text("{}", encoding="utf-8")
    assert "/etc/defenseclaw/managed-runtime.json" in block
    script = 'die() { echo "DIE: $*"; exit 1; }\nOS=linux\n' + block.replace(
        "/etc/defenseclaw/managed-runtime.json", str(platform)
    ) + "\necho proceeded\n"
    for override in (str(tmp_path / "missing.json"), ""):
        completed = subprocess.run(
            ["bash", "-c", script],
            env={"PATH": "/usr/bin:/bin", "DEFENSECLAW_INSTALL_MANAGED_DESCRIPTOR": override},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 1, (override, completed.stdout, completed.stderr)
        assert "managed by your organization" in completed.stdout
        assert "proceeded" not in completed.stdout


def test_upgrade_with_an_older_latest_release_is_up_to_date(
    home: Path, execs: list[list[str]], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # GAP-1801: 1.0.1 with 0.8.10 as the newest published release said
    # "cannot install 0.8.10" (rc 1), as if a downgrade had been asked for.
    monkeypatch.setattr("defenseclaw.__version__", "1.0.1")
    monkeypatch.setattr(upgrade_shim, "_latest_version", lambda repo: "0.8.10")

    assert upgrade_shim.run(["upgrade", "--yes"]) == 0
    assert execs == []
    out = capsys.readouterr()
    assert "DefenseClaw 1.0.1 is up to date (latest release: 0.8.10 is older). Nothing was changed." in out.out
    assert "defenseclaw upgrade --version X.Y.Z" in out.out
    assert "cannot install" not in out.out + out.err


def test_the_rollback_refusal_prints_a_normalized_path(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # GAP-1842: Windows printed C:\\Users\\x/.defenseclaw\\previous (expanduser
    # keeps the "/" of "~/.defenseclaw"); normpath gives one separator style.
    (home / "installer").mkdir()
    (home / "installer" / "install.ps1").write_text("", encoding="utf-8")
    (home / "previous" / "legacy-setup").mkdir(parents=True)
    monkeypatch.setenv("DEFENSECLAW_HOME", f"{home}/sub/..")
    monkeypatch.setattr(upgrade_shim.os, "name", "nt")
    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: None)

    assert upgrade_shim.run(["rollback", "--yes"]) == 1
    assert f"are in {home / 'previous'}\n" in capsys.readouterr().err


# GAP-0137: the installer of a release older than a config key refuses a
# config.yaml that sets it ("unknown field"), so a downgrade sets the key
# aside, and a release that has it puts it back (test_migrate).
_CA_CONFIG = "config_version: 9\nopenshell:\n  trusted_ca_bundle: ~/proxy-root-ca.pem\n"


def _set_aside(home: Path) -> Path:
    return home / upgrade_shim.SET_ASIDE_FILE


def test_downgrade_sets_aside_the_keys_the_older_release_lacks(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yaml

    monkeypatch.setattr("defenseclaw.__version__", "1.0.3")
    (home / "config.yaml").write_text(_CA_CONFIG, encoding="utf-8")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.2")))

    assert upgrade_shim.run(["upgrade", "--version", "1.0.2", "--yes"]) == 0

    assert len(execs) == 1
    config = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    assert "trusted_ca_bundle" not in (config.get("openshell") or {})
    record = json.loads(_set_aside(home).read_text(encoding="utf-8"))
    assert record == {"version": 1, "for": "1.0.2", "keys": {"openshell.trusted_ca_bundle": "~/proxy-root-ca.pem"}}
    # The execs fixture sets the shim's os.name to posix; the platform says what the file system is.
    if sys.platform != "win32":
        assert _set_aside(home).stat().st_mode & 0o777 == 0o600



# guardrail.chains (1.0.6, root-scope chains, issue #1391): 1.0.5 and 1.0.4
# refuse the block itself, so a downgrade sets it aside whole.
@pytest.mark.parametrize("target", ["1.0.5", "1.0.4"])
def test_downgrade_sets_aside_the_chains_block(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    import yaml

    monkeypatch.setattr("defenseclaw.__version__", "1.0.6")
    (home / "config.yaml").write_text(
        "config_version: 9\nguardrail:\n  mode: observe\n  chains:\n    root_scope: true\n", encoding="utf-8"
    )
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, target)))

    assert upgrade_shim.run(["upgrade", "--version", target, "--yes"]) == 0

    assert len(execs) == 1
    guardrail = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))["guardrail"]
    assert "chains" not in guardrail
    assert guardrail["mode"] == "observe"
    record = json.loads(_set_aside(home).read_text(encoding="utf-8"))
    assert record == {"version": 1, "for": target, "keys": {"guardrail.chains": {"root_scope": True}}}


# connectors (connectors.agent_gateway, 1.0.6): 1.0.5 and 1.0.4 refuse the
# top-level block, so a downgrade sets it aside with guardrail.chains.
@pytest.mark.parametrize("target", ["1.0.5", "1.0.4"])
def test_downgrade_sets_aside_the_connectors_block(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    import yaml

    monkeypatch.setattr("defenseclaw.__version__", "1.0.6")
    (home / "config.yaml").write_text(
        "config_version: 9\nconnectors:\n  agent_gateway:\n    enabled: true\n"
        "guardrail:\n  chains:\n    root_scope: true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, target)))

    assert upgrade_shim.run(["upgrade", "--version", target, "--yes"]) == 0

    config = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    assert "connectors" not in config
    assert "chains" not in (config.get("guardrail") or {})
    record = json.loads(_set_aside(home).read_text(encoding="utf-8"))
    assert record["keys"] == {
        "guardrail.chains": {"root_scope": True},
        "connectors": {"agent_gateway": {"enabled": True}},
    }



def test_a_downgrade_that_would_leave_opencode_v2_unguarded_is_refused_before_anything_changes(
    home: Path,
    execs: list[list[str]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """rel-1-0-6 GAP-0128: 'upgrade --version 1.0.5' runs the check 'defenseclaw rollback' runs."""
    from defenseclaw import migrations

    seen: list[tuple[str, str]] = []
    monkeypatch.setattr("defenseclaw.__version__", "1.0.6")
    monkeypatch.setattr(migrations, "_opencode_configured", lambda data_dir: seen.append(("configured", data_dir)) or True)
    monkeypatch.setattr(migrations, "_installed_opencode", lambda _data_dir: ("opencode v2.2.5", "/u/.npm/bin/opencode"))
    (home / "config.yaml").write_text(_DOMAINS_CONFIG, encoding="utf-8")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.5")))

    assert upgrade_shim.run(["upgrade", "--version", "1.0.5", "--yes"]) == 1

    assert execs == []
    assert seen == [("configured", str(home))]
    assert (home / "config.yaml").read_text(encoding="utf-8") == _DOMAINS_CONFIG
    assert not _set_aside(home).exists()
    err = capsys.readouterr().err
    assert "DefenseClaw 1.0.5 guards OpenCode V1 only and the OpenCode here is V2 (opencode v2.2.5)" in err
    assert "opencode-ai@1.18" in err and "Nothing was changed." in err
    assert "Installing DefenseClaw" not in err

    # The same OpenCode V2 and a release that guards it: no refusal.
    monkeypatch.setattr("defenseclaw.__version__", "1.0.7")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.6")))
    assert upgrade_shim.run(["upgrade", "--version", "1.0.6", "--yes"]) == 0
    assert len(execs) == 1


def test_a_downgrade_goes_on_when_the_check_cannot_load(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The way back from a broken install stays open (the shim runs before the rest of the CLI)."""
    monkeypatch.setattr("defenseclaw.__version__", "1.0.6")
    monkeypatch.setitem(sys.modules, "defenseclaw.migrations", None)
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.5")))

    assert upgrade_shim.run(["upgrade", "--version", "1.0.5", "--yes"]) == 0
    assert len(execs) == 1

@pytest.mark.parametrize(("installed", "target"), [("1.0.3", "1.0.4"), ("1.0.4", "1.0.3")])
def test_upgrade_keeps_keys_the_target_release_has(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, installed: str, target: str
) -> None:
    monkeypatch.setattr("defenseclaw.__version__", installed)
    (home / "config.yaml").write_text(_CA_CONFIG, encoding="utf-8")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, target)))

    assert upgrade_shim.run(["upgrade", "--version", target, "--yes"]) == 0

    assert len(execs) == 1
    assert (home / "config.yaml").read_text(encoding="utf-8") == _CA_CONFIG
    assert not _set_aside(home).exists()


# #1390: guardrail.internal_domains is new in 1.0.6; 1.0.5 and 1.0.4 refuse it.
_DOMAINS_CONFIG = "config_version: 9\nguardrail:\n  internal_domains:\n  - corp.example.com\n"


@pytest.mark.parametrize("target", ["1.0.5", "1.0.4"])
def test_downgrade_below_1_0_6_sets_aside_internal_domains(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    import yaml

    monkeypatch.setattr("defenseclaw.__version__", "1.0.6")
    (home / "config.yaml").write_text(_DOMAINS_CONFIG, encoding="utf-8")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, target)))

    assert upgrade_shim.run(["upgrade", "--version", target, "--yes"]) == 0

    assert len(execs) == 1
    config = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    assert "internal_domains" not in (config.get("guardrail") or {})
    record = json.loads(_set_aside(home).read_text(encoding="utf-8"))
    assert record == {"version": 1, "for": target, "keys": {"guardrail.internal_domains": ["corp.example.com"]}}


def test_upgrade_to_1_0_6_keeps_internal_domains(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.6")
    (home / "config.yaml").write_text(_DOMAINS_CONFIG, encoding="utf-8")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.6")))

    assert upgrade_shim.run(["upgrade", "--version", "1.0.6", "--yes"]) == 0

    assert (home / "config.yaml").read_text(encoding="utf-8") == _DOMAINS_CONFIG
    assert not _set_aside(home).exists()


def test_downgrade_stops_with_the_unset_command_when_the_key_cannot_be_set_aside(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    from defenseclaw import config_writer

    monkeypatch.setattr("defenseclaw.__version__", "1.0.3")
    (home / "config.yaml").write_text(_CA_CONFIG, encoding="utf-8")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.2")))

    def refuse(*_args, **_kwargs):
        raise config_writer.ConfigWriteError("config.yaml is locked")

    monkeypatch.setattr(config_writer, "apply", refuse)

    assert upgrade_shim.run(["upgrade", "--version", "1.0.2", "--yes"]) == 1

    assert execs == []
    assert (home / "config.yaml").read_text(encoding="utf-8") == _CA_CONFIG
    assert not _set_aside(home).exists()
    err = capsys.readouterr().err
    assert "defenseclaw config unset openshell.trusted_ca_bundle" in err
    assert "Nothing was changed." in err


@pytest.mark.parametrize("running", [True, False])
def test_a_downgrade_drops_the_hook_helper_this_release_left_and_restarts_the_gateway(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, running: bool
) -> None:
    # rel-1-0-4:GAP-2503: the 1.0.2 installer kept the 1.0.5 hooks/_hardening.sh
    # (a 1.0.2 gateway keeps a helper with a newer schema line), and its
    # native commands are not in the 1.0.2 binaries: every hook call was
    # refused until the helper was removed and the gateway restarted. The shim
    # waits for the older installer, then does that when the helper is the
    # one the replaced install (previous/) has.
    monkeypatch.setattr("defenseclaw.__version__", "1.0.5")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.2")))
    monkeypatch.setenv("HOME", str(home.parent))
    monkeypatch.setattr(upgrade_shim.os, "name", "posix")
    newer = b"#!/bin/bash\n# defenseclaw-managed-hook v10\n"
    calls: list[list[str]] = []

    def installer(argv: list[str]) -> int:
        calls.append(list(argv))
        for root in (home, home / "previous" / "data"):
            (root / "hooks").mkdir(parents=True, exist_ok=True)
            (root / "hooks" / "_hardening.sh").write_bytes(newer)
        (home / "previous" / "VERSION").write_text("1.0.5\n", encoding="utf-8")
        pid = os.getpid() if running else 2**22 + 7
        (home / "gateway.pid").write_text(json.dumps({"pid": pid}), encoding="utf-8")
        return 0

    def probe(pid: int, sig: int) -> None:
        # The liveness probe only: a real os.kill(pid, 0) on a Windows runner
        # is CTRL_C_EVENT and interrupts the test run itself.
        assert sig == 0
        if pid != os.getpid():
            raise ProcessLookupError(pid)

    monkeypatch.setattr(upgrade_shim.os, "kill", probe)
    restarts: list[list[str]] = []
    monkeypatch.setattr(upgrade_shim, "_wait_for_installer", installer)
    monkeypatch.setattr(upgrade_shim.subprocess, "call", lambda argv, **kw: restarts.append(list(argv)) or 0)
    monkeypatch.setattr(upgrade_shim.os, "execv", lambda path, argv: pytest.fail("a downgrade must wait for its installer"))

    assert upgrade_shim.run(["upgrade", "--version", "1.0.2", "--yes"]) == 0

    assert len(calls) == 1 and calls[0][-1] != "--rollback"
    assert not (home / "hooks" / "_hardening.sh").exists()
    assert (home / "previous" / "data" / "hooks" / "_hardening.sh").read_bytes() == newer
    gateway = str(home.parent / ".local" / "bin" / "defenseclaw-gateway")
    assert restarts == ([[gateway, "restart"]] if running else [])


def test_a_downgrade_to_1_0_5_or_later_keeps_the_hook_helper(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, execs: list[list[str]]
) -> None:
    # rel-1-0-6:GAP-0047: 1.0.5 and 1.0.6 ship the same hooks/_hardening.sh,
    # and a 1.0.5 gateway with only OpenCode set up never writes one: after
    # the shim dropped it, that gateway refused to start. The installer runs
    # as for an upgrade; nothing is dropped or restarted afterwards.
    monkeypatch.setattr("defenseclaw.__version__", "1.0.6")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.5")))
    monkeypatch.setattr(upgrade_shim, "_drop_newer_hook_helper", lambda newer: pytest.fail("helper dropped"))
    monkeypatch.setattr(upgrade_shim, "_wait_for_installer", lambda argv: pytest.fail("waited for the installer"))

    assert upgrade_shim.run(["upgrade", "--version", "1.0.5", "--yes"]) == 0

    assert len(execs) == 1 and execs[0][-1] != "--rollback"


@pytest.mark.parametrize("case", ["other-helper", "previous-not-newer", "installer-failed"])
def test_a_downgrade_keeps_a_hook_helper_it_did_not_leave(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.5")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.2")))
    monkeypatch.setattr(upgrade_shim.os, "name", "posix")
    live = b"#!/bin/bash\n# defenseclaw-managed-hook v8\n" if case == "other-helper" else b"v10\n"

    def installer(argv: list[str]) -> int:
        (home / "hooks").mkdir(parents=True, exist_ok=True)
        (home / "hooks" / "_hardening.sh").write_bytes(live)
        (home / "previous" / "data" / "hooks").mkdir(parents=True, exist_ok=True)
        (home / "previous" / "data" / "hooks" / "_hardening.sh").write_bytes(b"v10\n")
        (home / "previous" / "VERSION").write_text("1.0.4\n" if case == "previous-not-newer" else "1.0.5\n", encoding="utf-8")
        return 1 if case == "installer-failed" else 0

    monkeypatch.setattr(upgrade_shim, "_wait_for_installer", installer)
    monkeypatch.setattr(upgrade_shim.subprocess, "call", lambda argv, **kw: pytest.fail("nothing to restart"))

    assert upgrade_shim.run(["upgrade", "--version", "1.0.2", "--yes"]) == (1 if case == "installer-failed" else 0)

    assert (home / "hooks" / "_hardening.sh").read_bytes() == live


# ── GAP-1067: rollback runs only the saved installer the install recorded ───


def _record(data: Path, saved: Path, name: str | None = None, digest: str | None = None) -> Path:
    record = data / "receipts" / "installer.sha256"
    record.parent.mkdir(parents=True, exist_ok=True)
    digest = digest if digest is not None else hashlib.sha256(saved.read_bytes()).hexdigest()
    record.write_bytes(f"{digest}  {name or saved.name}\n".encode())
    return record


def _saved_installer(root: Path, name: str = "install.sh", body: str = "#!/bin/bash\n") -> Path:
    saved = root / "installer" / name
    saved.parent.mkdir(parents=True, exist_ok=True)
    saved.write_bytes(body.encode())
    return saved


@pytest.mark.parametrize("platform", ["posix", "nt"])
@pytest.mark.parametrize("change", ["appended", "missing-record", "wrong-name", "not-hex", "oversized", "empty"])
def test_rollback_refuses_a_saved_installer_the_install_did_not_save(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    platform: str,
    change: str,
) -> None:
    from defenseclaw import __version__

    name = "install.ps1" if platform == "nt" else "install.sh"
    body = f'$DcVersion = "{__version__}"\n' if platform == "nt" else "#!/bin/bash\n"
    saved = _saved_installer(home, name, body)
    record = _record(home, saved)
    if change == "appended":
        saved.write_bytes(saved.read_bytes() + b"# r28sa note\n")
    elif change == "missing-record":
        record.unlink()
    elif change == "wrong-name":
        _record(home, saved, name="other.sh")
    elif change == "not-hex":
        _record(home, saved, digest="z" * 64)
    elif change == "oversized":
        record.write_bytes(record.read_bytes() + b" " * 300)
    else:
        record.write_bytes(b"")
    execs: list[list[str]] = []
    started: list[object] = []
    monkeypatch.setattr(upgrade_shim.os, "execv", lambda path, argv: execs.append(list(argv)))
    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda *args, **kwargs: started.append(args))
    monkeypatch.setattr(upgrade_shim.os, "name", platform)

    assert upgrade_shim.run(["rollback", "--yes"]) == 1

    assert execs == [] and started == []
    err = capsys.readouterr().err
    assert f"defenseclaw upgrade --version {__version__} --yes" in err, err
    assert "nothing was changed" in err
    assert ("is missing" if change == "missing-record" else "is not the one DefenseClaw saved") in err or (
        change == "oversized" and "could not read the record" in err
    ), err
    # The staged copy is removed with the refusal.
    assert list((home.parent.parent / "tmp").iterdir()) == []


@pytest.mark.parametrize("platform", ["posix", "nt"])
def test_rollback_runs_the_recorded_saved_installer(
    home: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    from defenseclaw import __version__

    name = "install.ps1" if platform == "nt" else "install.sh"
    saved = _saved_installer(home, name, f'$DcVersion = "{__version__}"\n' if platform == "nt" else "#!/bin/bash\n")
    _record(home, saved)
    ran: list[tuple[str, list[str], bytes]] = []
    monkeypatch.setattr(
        upgrade_shim, "_run_installer", lambda path, args, workdir, *, rerun: ran.append((path, args, Path(path).read_bytes())) or 0
    )
    monkeypatch.setattr(upgrade_shim.os, "name", platform)

    assert upgrade_shim.run(["rollback", "--yes"]) == 0

    assert ran[0][0] != str(saved) and ran[0][1:] == (["--rollback", "--yes"], saved.read_bytes())


def test_rollback_checks_a_previous_installer_only_when_it_was_recorded(home: Path, execs: list[list[str]]) -> None:
    # until 1.1: an installer that 1.0.3 or older saved in previous/ has no
    # record (GAP-2459 roll forward from a source install keeps working).
    previous = home / "previous"
    saved = _saved_installer(previous)
    assert upgrade_shim.run(["rollback", "--yes"]) == 0
    assert len(execs) == 1
    _record(previous / "data", saved, digest="0" * 64)
    assert upgrade_shim.run(["rollback", "--yes"]) == 1
    assert len(execs) == 1
    _record(previous / "data", saved)
    assert upgrade_shim.run(["rollback", "--yes"]) == 0
    assert len(execs) == 2


@pytest.mark.parametrize(
    "value",
    ["http://127.0.0.1:8765/defenseclaw", "ftp://mirror.example/dc", "justaname", "a/b/c", "owner/na me", "file:///tmp/dc"],
)
def test_a_bad_defenseclaw_repo_is_refused_with_the_https_requirement(
    home: Path, execs: list[list[str]], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], value: str
) -> None:
    """GAP-1065: DEFENSECLAW_REPO is an owner/name or an https:// URL. Anything
    else used to be appended to github.com and ended in an HTTP 404; it is now
    refused before any download, without echoing the value."""
    monkeypatch.setenv(upgrade_shim.REPO_ENV, value)
    downloads: list[str] = []
    monkeypatch.setattr(upgrade_shim, "_download", lambda url, *_a, **_k: downloads.append(url))

    assert upgrade_shim.run(["upgrade", "--yes", "--version", "1.0.8200"]) == 2
    err = capsys.readouterr().err
    assert "DEFENSECLAW_REPO must be a GitHub owner/name or an https:// mirror URL" in err
    assert "Nothing was changed." in err
    assert value not in err
    assert downloads == [] and execs == []
    # The update notice stays quiet about it.
    assert update_notice._lookup_latest() == ""


@pytest.mark.parametrize(
    ("value", "base"),
    [
        ("fork/defense.claw", "https://github.com/fork/defense.claw"),
        ("https://mirror.example/dc/", "https://mirror.example/dc"),
    ],
)
def test_a_good_defenseclaw_repo_is_still_accepted(
    home: Path, monkeypatch: pytest.MonkeyPatch, value: str, base: str
) -> None:
    monkeypatch.setenv(upgrade_shim.REPO_ENV, value)
    assert upgrade_shim.release_source() == base
