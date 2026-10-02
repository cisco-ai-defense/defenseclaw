# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-1345: name another account's port holder when tasklist is denied."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

from defenseclaw.commands import cmd_doctor


def test_windows_label_falls_back_to_a_process_snapshot_when_tasklist_is_denied() -> None:
    denied = subprocess.CompletedProcess(["tasklist"], 1, stdout="ERROR: Access denied\n", stderr="")
    with (
        patch.object(cmd_doctor.subprocess, "run", return_value=denied),
        patch("defenseclaw.process_liveness.process_image_name_windows", return_value="defenseclaw-gateway.exe"),
    ):
        label = cmd_doctor._windows_process_label(8220)
    assert label == "defenseclaw-gateway.exe, probably another account's DefenseClaw gateway"


def test_windows_label_keeps_the_tasklist_account_when_it_is_shown() -> None:
    row = '"pwsh.exe","14428","Console","1","80,000 K","Running","DC\\\\dcw-adm","0:00:01","N/A"\n'
    shown = subprocess.CompletedProcess(["tasklist"], 0, stdout=row, stderr="")
    with patch.object(cmd_doctor.subprocess, "run", return_value=shown):
        assert cmd_doctor._windows_process_label(14428).startswith("pwsh.exe, DC")
