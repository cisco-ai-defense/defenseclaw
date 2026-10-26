# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""oss-outage-open round h: what `guardrail fail-mode open` says (GAP-1419, GAP-1434).

Open covers only a gateway outage, a call no gateway took. A reachable
gateway's block or error, a malformed or cut-off answer and an accepted call
without an answer in time block in every mode. The setter, global or per
connector, must say exactly that, never that "invalid or unavailable gateway
responses" will be allowed; on a managed computer it says the administrator's
open is honored (GAP-1319) and only for a gateway service the hook proves
stopped.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parent))

from defenseclaw.commands import cmd_guardrail  # noqa: E402
from test_cmd_guardrail import make_multi_ctx  # noqa: E402

_REQUIRED = (
    "A gateway outage will now ALLOW",
    "Open applies only when no gateway is reachable",
    "A reachable gateway's block or error",
    "a malformed or cut-off answer",
    "does not answer in time still block",
)
_FORBIDDEN = (
    "Invalid or unavailable gateway responses will now ALLOW",
    "invalid or unavailable gateway responses will ALLOW",
)


@pytest.fixture(autouse=True)
def _isolated_home():
    with tempfile.TemporaryDirectory() as home, patch.dict(os.environ, {"HOME": home, "USERPROFILE": home}), patch(
        "defenseclaw.commands.cmd_guardrail._gateway_running", return_value=True
    ):
        yield


@pytest.mark.parametrize("scope", [[], ["--connector", "codex"]], ids=["global", "per-connector"])
def test_per_user_open_setter_says_open_covers_only_an_outage(scope) -> None:
    app = make_multi_ctx({"codex": None, "claudecode": None})
    app.cfg.guardrail.hook_fail_mode = "closed"
    for name in ("codex", "claudecode"):
        app.cfg.guardrail.connectors[name].hook_fail_mode = "closed"
    state = SimpleNamespace(current=True, drift=(), desired="closed", runtime="closed")
    with patch("defenseclaw.commands.cmd_guardrail.resolve_connector_fail_mode", return_value=state):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["open", *scope, "--yes", "--no-restart"], obj=app)
    assert result.exit_code == 0, result.output
    output = " ".join(result.output.split())
    for phrase in _REQUIRED:
        assert phrase in output, (phrase, output)
    for phrase in _FORBIDDEN:
        assert phrase not in output, (phrase, output)
    assert "administrator" not in output, output


def test_managed_open_note_says_the_administrators_open_is_honored() -> None:
    for managed, expected in ((True, True), (False, False)):
        app = SimpleNamespace(cfg=SimpleNamespace(managed_outside_secure_client=lambda m=managed: m))
        note = cmd_guardrail._outage_open_note(app, "supported calls")
        for phrase in _REQUIRED:
            assert phrase in note
        assert ("administrator's open is honored, also under the strict policy" in note) is expected
        assert ("only while the hook proves the gateway service is stopped" in note) is expected


def test_fail_mode_help_says_open_covers_only_an_outage() -> None:
    result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["--help"])
    assert result.exit_code == 0, result.output
    output = " ".join(result.output.split())
    assert "while no gateway is reachable (an outage), allow the call" in output
    assert "A reachable gateway's block, a malformed answer or a timeout still blocks." in output
    assert "a managed administrator's open is honored (also under the strict policy)" in output
