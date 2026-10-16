# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The OTLP credential row names a rollback as a cause (1.0.2)."""

from __future__ import annotations

from datetime import datetime, timezone

from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _DoctorResult
from defenseclaw.observability.custody_status import ConnectorCustodyReport


def test_rejected_otlp_attempts_name_a_rollback_as_a_cause() -> None:
    # rel-1-0-1:GAP-0010: after a rollback an agent kept sending the token of
    # the install it was started with; the remediation did not name that case.
    now = datetime(2026, 10, 13, 6, 0, tzinfo=timezone.utc)
    report = ConnectorCustodyReport(
        state="available",
        reason="",
        observation_window_hours=24,
        unattributed_authentication_failures=3,
        last_unattributed_authentication_failure="2026-10-13T05:55:00Z",
    )
    r = _DoctorResult()
    cmd_doctor._emit_unattributed_otlp_credentials(report, r, now=now)
    (check,) = r.checks
    assert "changed (an upgrade, a rollback, 'defenseclaw setup' or 'setup rotate-token')" in check["remediation"]
