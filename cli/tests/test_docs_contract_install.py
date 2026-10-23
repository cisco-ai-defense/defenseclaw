# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The install page shows what doctor prints right after a plain install."""

import re
from pathlib import Path

import pytest
from click.testing import CliRunner
from defenseclaw.main import cli

PAGE = Path(__file__).resolve().parents[2] / "docs-site/content/docs/get-started/install.mdx"


def test_install_page_shows_doctor_before_init(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """GAP-0562: before init, doctor prints only the Config file row; the page must say so."""
    home = tmp_path / "home"
    data_dir = home / ".defenseclaw"
    data_dir.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(data_dir))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)

    result = CliRunner().invoke(cli, ["doctor"])
    rows = [line.replace(str(home), "~") for line in result.output.splitlines() if re.match(r"\s*\[[A-Z]+\]", line)]
    assert len(rows) == 1 and "[FAIL] Config file" in rows[0], result.output

    text = PAGE.read_text()
    section = text.split("## Check it worked", 1)[1].split("\n## ", 1)[0]
    assert "After init" in section, "the page must say what doctor shows before and after init"
    before, after = section.split("After init", 1)
    assert "defenseclaw init --connector <agent>` before `defenseclaw doctor`" in before
    assert f"exits {result.exit_code}" in before
    shown = re.findall(r"```text\n(.*?)```", before.split("defenseclaw doctor", 1)[1], re.S)
    assert [line for line in shown[0].splitlines() if line.strip()] == rows
    assert "`defenseclaw doctor`" in after
