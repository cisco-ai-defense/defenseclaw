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

ROOT = Path(__file__).resolve().parents[2]
_FIND_COSIGN = upgrade_shim._cosign


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
    # A developer's own cosign must not take part; the signature tests add a fake one.
    monkeypatch.setattr(upgrade_shim, "_cosign", lambda: None)
    return data


@pytest.fixture()
def execs(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []
    monkeypatch.setattr(upgrade_shim.os, "execv", lambda path, argv: calls.append(list(argv)))
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
    monkeypatch.setattr(
        upgrade_shim.subprocess,
        "Popen",
        lambda argv, **kwargs: (started.append(argv), envs.append(kwargs["env"])),
    )
    monkeypatch.setattr(subprocess, "CREATE_NEW_CONSOLE", 16, raising=False)

    assert upgrade_shim.run(["upgrade", "--yes"]) == 0
    # Windows PowerShell 5.1 cannot load its modules from PowerShell 7 folders.
    assert not [key for key in envs[0] if key.upper() == "PSMODULEPATH"]
    assert envs[0]["PATH"] == os.environ["PATH"]

    assert started[0][1:6] == ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", started[0][5]]
    assert started[0][5].endswith("install.ps1")
    assert started[0][6:] == ["-Yes", "-Local", str(release)]


def test_rollback_uses_the_saved_installer(home: Path, execs: list[list[str]]) -> None:
    saved = home / "installer" / "install.sh"
    saved.parent.mkdir()
    saved.write_text("#!/bin/bash\n", encoding="utf-8")

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


def test_rollback_without_a_saved_installer_explains(home: Path, execs: list[list[str]]) -> None:
    assert upgrade_shim.run(["rollback"]) == 1
    assert execs == []


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
    external.write_text("config_version: 8\nupdate_check: false\n")
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
        (home / "config.yaml").write_text("config_version: 8\nupdate_check: false\n")

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
    monkeypatch.setattr(update_notice.os, "name", "nt")

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


def test_the_signer_pattern_escapes_the_repository_name(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    release = _release_dir(tmp_path, "1.0.1")
    (release / "checksums.txt.bundle").write_text("{}")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(release))
    monkeypatch.setenv(upgrade_shim.REPO_ENV, "acme+corp/defense.claw")
    seen: list[list[str]] = []
    monkeypatch.setattr(upgrade_shim, "_cosign", lambda: "/usr/bin/cosign")

    def run(argv, **_kwargs):
        seen.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(upgrade_shim.subprocess, "run", run)

    assert upgrade_shim.run(["upgrade", "--yes"]) == 0
    pattern = seen[0][seen[0].index("--certificate-identity-regexp") + 1]
    assert pattern.startswith("^https://github\\.com/acme\\+corp/defense\\.claw/")


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

    def __enter__(self) -> "_FakeKey":
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
