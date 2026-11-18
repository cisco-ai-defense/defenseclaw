# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Doctor names a routing.admin group no spelling matches (rel-1-0-10:GAP-1124)."""

import os
from types import SimpleNamespace
from unittest.mock import patch

from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _DoctorResult

_WARNING = (
    'routing.admin budget b-grp-devs: group "dc-r102-devs@dclab.test" is not known to this host '
    "(renamed or deleted in the directory?), so it selects nobody (routing_admin_group_unmatched)"
)


def _run(tmp_path, warnings):
    (tmp_path / "config.yaml").write_text("config_version: 8\n", encoding="utf-8")
    result = _DoctorResult()
    with (
        patch("defenseclaw.commands.cmd_status._enterprise_profile", return_value=""),
        patch(
            "defenseclaw.config_inspect.inspect_v8_config",
            return_value=SimpleNamespace(valid=True, warnings=warnings),
        ),
    ):
        cmd_doctor._check_config(SimpleNamespace(data_dir=os.fspath(tmp_path)), result)
    return result.checks


def test_doctor_warns_for_a_routing_group_no_spelling_matches(tmp_path):
    checks = _run(tmp_path, ["some other validate warning", _WARNING])
    assert checks[0]["status"] == "pass"
    rows = [c for c in checks if c["label"] == "Routing policy"]
    assert len(rows) == 1
    row = rows[0]
    assert row["status"] == "warn"
    assert row["detail"].startswith("routing.admin budget b-grp-devs:")
    assert "routing_admin_group_unmatched" not in row["detail"]
    assert "DOMAIN\\name" in row["remediation"]


def test_doctor_adds_no_routing_row_without_the_warning(tmp_path):
    checks = _run(tmp_path, ["some other validate warning"])
    assert [c["status"] for c in checks] == ["pass"]
    assert _run(tmp_path, None)[-1]["status"] == "pass"
