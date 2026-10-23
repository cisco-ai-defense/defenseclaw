# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The install page shows what doctor prints right after a plain install."""

import os
import re
import subprocess
import sys
from pathlib import Path, PureWindowsPath

import pytest
from click.testing import CliRunner
from defenseclaw.main import cli

REPO = Path(__file__).resolve().parents[2]
PAGE = REPO / "docs-site" / "content" / "docs" / "get-started" / "install.mdx"


def _read_page(path: Path) -> str:
    """Read the page the same way on every OS: UTF-8, whatever the locale, and LF line ends."""
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n")


@pytest.mark.parametrize("flavor", ["native", "windows"])
def test_install_page_shows_doctor_before_init(tmp_path, monkeypatch: pytest.MonkeyPatch, flavor: str) -> None:
    """GAP-0562: before init, doctor prints only the Config file row; the page must say so.

    The page is for every OS, so the row must match with Windows paths too.
    """
    home = tmp_path / "home"
    data_dir = home / ".defenseclaw"
    data_dir.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(data_dir))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    shown_home = str(home)
    if flavor == "windows":
        shown_home = r"C:\Users\dev\home"
        monkeypatch.setattr(
            "defenseclaw.config.config_path_for_data_dir",
            lambda _data_dir=None: PureWindowsPath(shown_home, ".defenseclaw", "config.yaml"),
        )

    result = CliRunner().invoke(cli, ["doctor"])
    rows = [
        line.replace(shown_home, "~").replace("\\", "/")
        for line in result.output.splitlines()
        if re.match(r"\s*\[[A-Z]+\]", line)
    ]
    assert len(rows) == 1 and "[FAIL] Config file" in rows[0], result.output

    text = _read_page(PAGE)
    section = text.split("## Check it worked", 1)[1].split("\n## ", 1)[0]
    assert "After init" in section, "the page must say what doctor shows before and after init"
    before, after = section.split("After init", 1)
    assert "defenseclaw init --connector <agent>` before `defenseclaw doctor`" in before
    assert f"exits {result.exit_code}" in before
    shown = re.findall(r"```text\n(.*?)```", before.split("defenseclaw doctor", 1)[1], re.S)
    assert [line for line in shown[0].splitlines() if line.strip()] == rows
    assert "`defenseclaw doctor`" in after


def test_read_page_ignores_crlf_checkout(tmp_path) -> None:
    """A Windows checkout with core.autocrlf has CRLF line ends; the section split must still work."""
    crlf = tmp_path / "install.mdx"
    crlf.write_bytes(_read_page(PAGE).replace("\n", "\r\n").encode("utf-8"))
    assert _read_page(crlf) == _read_page(PAGE)
    assert "\n## Check it worked" in _read_page(crlf)


def test_install_page_check_passes_without_utf8_locale() -> None:
    """Windows CI runs without PYTHONUTF8, so the page must not be read with the locale codec.

    Runs on every OS: on Windows UTF-8 mode off means cp1252, elsewhere the C locale means ASCII.
    """
    env = {**os.environ, "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0", "LC_ALL": "C", "LANG": "C"}
    node = Path(__file__).resolve().relative_to(REPO).as_posix()
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            f"{node}::test_install_page_shows_doctor_before_init",
        ],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "2 passed" in proc.stdout, proc.stdout
