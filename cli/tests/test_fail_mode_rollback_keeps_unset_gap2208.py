# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""An aborted global fail-mode change puts an unset hook fail mode back unset (GAP-2208)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from defenseclaw import config as dcconfig
from defenseclaw.commands import cmd_guardrail
from defenseclaw.context import AppContext


def _per_user_cfg(tmp_path: Path) -> SimpleNamespace:
    data_dir = tmp_path / "data"
    (data_dir / "hooks").mkdir(parents=True)
    guardrail = dcconfig.GuardrailConfig()
    guardrail.enabled = True
    guardrail.connectors = {
        "claudecode": dcconfig.PerConnectorGuardrailConfig(mode="observe"),
        "codex": dcconfig.PerConnectorGuardrailConfig(mode="observe"),
    }
    cfg = SimpleNamespace(
        data_dir=str(data_dir),
        guardrail=guardrail,
        gateway=SimpleNamespace(host="127.0.0.1", port=18789),
    )
    cfg.active_connector = lambda: "claudecode"
    cfg.active_connectors = lambda: ["claudecode", "codex"]
    return cfg


@pytest.mark.parametrize("failure", ["refresh", "save"])
def test_an_aborted_global_fail_mode_change_leaves_an_unset_mode_unset(tmp_path: Path, failure: str) -> None:
    # A per-user install that never chose a fail mode: the outage mode follows
    # the policy tier. `guardrail fail-mode open --yes` fails (a connector's
    # registration refresh, or the config write) and says the previous config
    # is restored. The rollback must not save the in-memory "closed"
    # placeholder of the unset value as the user's choice for every connector.
    cfg = _per_user_cfg(tmp_path)
    gc = cfg.guardrail
    assert gc._hook_fail_mode_saved is False
    saves: list[tuple[bool, str]] = []

    def save(*_args: object, **_kwargs: object) -> None:
        saves.append((gc._hook_fail_mode_saved, gc.hook_fail_mode))
        if failure == "save" and len(saves) == 1:
            raise OSError(13, "Permission denied")

    cfg.save = MagicMock(side_effect=save)
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    with (
        patch(
            "defenseclaw.commands.cmd_guardrail.reconcile_connector_registration",
            side_effect=OSError("connector runtime verification failed for codex"),
        ),
        patch("defenseclaw.commands.cmd_guardrail._gateway_running", return_value=True),
    ):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["open", "--yes"], obj=app)
    assert result.exit_code != 0, result.output
    assert saves[0] == (True, "open")
    # Every later save (the rollback) writes the unset value back unset.
    assert all(saved is False for saved, _ in saves[1:]), saves
    assert gc._hook_fail_mode_saved is False
    assert {name: entry.hook_fail_mode for name, entry in gc.connectors.items()} == {"claudecode": "", "codex": ""}
