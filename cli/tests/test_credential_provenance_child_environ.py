# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-1176: TUI children reload ~/.defenseclaw/.env instead of inheriting copies."""

from __future__ import annotations

import os
import sys

import pytest
from defenseclaw import config as config_module
from defenseclaw import credential_provenance
from defenseclaw.tui.executor import CommandExecutor

_KEY = "DCTEST_DOTENV_KEY"


@pytest.fixture
def dotenv_dir(tmp_path, monkeypatch):
    credential_provenance._reset_for_tests()
    monkeypatch.delenv(_KEY, raising=False)
    monkeypatch.setenv("DCTEST_SHELL_KEY", "from-shell")
    dotenv = tmp_path / ".env"
    dotenv.write_text(f"{_KEY}=from-dotenv\nDCTEST_SHELL_KEY=other\n")
    dotenv.chmod(0o600)
    config_module._load_dotenv_into_os(str(tmp_path))
    yield tmp_path
    os.environ.pop(_KEY, None)
    credential_provenance._reset_for_tests()


def test_child_environ_drops_dotenv_copies_and_keeps_shell_exports(dotenv_dir, monkeypatch):
    assert os.environ[_KEY] == "from-dotenv"
    child = credential_provenance.child_environ()
    assert _KEY not in child
    assert child["DCTEST_SHELL_KEY"] == "from-shell"

    # After 'keys remove' rewrote .env, the parent's stale copy still stays home.
    (dotenv_dir / ".env").write_text("DCTEST_SHELL_KEY=other\n")
    config_module._load_dotenv_into_os(str(dotenv_dir))
    assert _KEY not in credential_provenance.child_environ()

    # A value exported later is the user's own and is passed on.
    monkeypatch.setenv(_KEY, "re-exported")
    assert credential_provenance.child_environ()[_KEY] == "re-exported"


async def test_tui_executor_child_does_not_inherit_dotenv_copy(dotenv_dir):
    probe = f"import os; print('value=' + os.environ.get('{_KEY}', 'absent'))"
    output = []
    async for event in CommandExecutor(use_pty=False).run(sys.executable, ("-c", probe)):
        if event.kind == "output":
            output.append(event.text)
    assert "value=absent" in "".join(output)
