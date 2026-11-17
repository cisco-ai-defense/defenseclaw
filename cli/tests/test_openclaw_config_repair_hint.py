# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-0110: name `openclaw doctor --fix` when OpenClaw refuses its own openclaw.json."""

from __future__ import annotations

import subprocess
from unittest import mock

from defenseclaw.commands import cmd_setup
from defenseclaw.inventory import claw_inventory

REFUSAL = (
    "openclaw.json:36 - gateway.tailscale: Unrecognized key: resetOnExit. "
    "Run openclaw doctor --fix to repair."
)


HINT = "run `openclaw doctor --fix` to repair it"


def test_hint_only_for_the_unrecognized_key_refusal() -> None:
    from defenseclaw.config import openclaw_config_repair_hint

    assert HINT in openclaw_config_repair_hint("", REFUSAL)
    assert openclaw_config_repair_hint("connection refused", None) == ""


def test_gateway_restart_failure_names_the_repair(capsys) -> None:
    proc = subprocess.CompletedProcess(["openclaw"], 1, stdout="", stderr=REFUSAL)
    with (
        mock.patch.object(cmd_setup.subprocess, "run", return_value=proc),
        mock.patch("defenseclaw.openclaw_plugin_config._openclaw_connector_block", return_value={}),
    ):
        assert cmd_setup._restart_openclaw_gateway() is False
    assert HINT in capsys.readouterr().out


def test_inventory_error_names_the_repair() -> None:
    proc = subprocess.CompletedProcess(["openclaw"], 1, stdout="", stderr=REFUSAL)
    with mock.patch.object(claw_inventory.subprocess, "run", return_value=proc):
        result = claw_inventory._run_openclaw("skills", "list")
    assert result.data is None
    assert result.error and HINT in result.error
