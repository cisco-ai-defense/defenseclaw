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
import subprocess
import sys
import time
import types
import urllib.error
from pathlib import Path

import pytest
from defenseclaw import entry, update_notice, upgrade_shim


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
    (release / "install.sh").write_text(installer, encoding="utf-8")
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
    assert Path(script).name == "install.sh"
    assert Path(script).read_text(encoding="utf-8") == (release / "install.sh").read_text(encoding="utf-8")
    assert args == ["--yes", "--local", str(release)]


def test_upgrade_refuses_an_installer_that_does_not_match_checksums(
    home: Path, execs: list[list[str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("defenseclaw.__version__", "1.0.0")
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(_release_dir(tmp_path, "1.0.1", tamper=True)))

    assert upgrade_shim.run(["upgrade", "--yes"]) == 1
    assert execs == []


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
    (release / "install.ps1").write_text(script, encoding="utf-8")
    (release / "checksums.txt").write_text(
        f"{hashlib.sha256(script.encode()).hexdigest()}  install.ps1\n", encoding="utf-8"
    )
    monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, str(release))
    monkeypatch.setattr(upgrade_shim.os, "name", "nt")
    started: list[list[str]] = []
    monkeypatch.setattr(upgrade_shim.subprocess, "Popen", lambda argv, **_kwargs: started.append(argv))
    monkeypatch.setattr(subprocess, "CREATE_NEW_CONSOLE", 16, raising=False)

    assert upgrade_shim.run(["upgrade", "--yes"]) == 0

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


def test_notice_is_silent_without_a_terminal(home: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setattr(update_notice, "available_message", lambda: "update!")
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)

    update_notice.maybe_print(["status"])

    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("argv", [[], ["upgrade"], ["status", "--json"], ["audit", "-o", "json"]])
def test_notice_skips_quiet_invocations(argv: list[str]) -> None:
    assert not update_notice._interactive(argv) or argv == []


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
    assert opened == [r"SOFTWARE\Policies\Cisco\DefenseClaw"]


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
