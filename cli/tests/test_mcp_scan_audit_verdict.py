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

"""The audit row of an MCP scan reads the admission verdict the command decides (GAP-0302).

Without a verdict the gateway records every scan with findings as "warn",
so one HIGH finding that ``mcp set`` refuses left a scan row saying warn
next to its install-rejected row.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands import cmd_mcp
from defenseclaw.enforce.admission import AdmissionDecision
from defenseclaw.logger import Logger
from defenseclaw.models import Finding, ScanResult

from tests.helpers import cleanup_app, make_app_context


def _result(*severities: str) -> ScanResult:
    return ScanResult(
        scanner="mcp-scanner",
        target="decoy",
        timestamp=datetime.now(timezone.utc),
        findings=[Finding(id=f"f{i}", severity=s, title="t", scanner="mcp-scanner") for i, s in enumerate(severities)],
        duration=timedelta(milliseconds=5),
    )


class _Recorder:
    def __init__(self) -> None:
        self.payloads: list[dict] = []

    def emit_cli_observability(self, payload) -> None:
        self.payloads.append(dict(payload))


def test_run_scan_records_the_audit_verdict_it_is_given() -> None:
    from defenseclaw.scanner.mcp import MCPScannerWrapper

    recorder = _Recorder()
    cfg = SimpleNamespace(
        scanners=SimpleNamespace(mcp_scanner=SimpleNamespace()),
        resolve_llm=lambda _scope: None,
        effective_inspect_llm=lambda: None,
        cisco_ai_defense=None,
    )
    app = SimpleNamespace(cfg=cfg, logger=Logger(recorder))
    with patch.object(MCPScannerWrapper, "__init__", return_value=None), patch.object(
        MCPScannerWrapper, "scan", return_value=_result("HIGH"),
    ), patch("defenseclaw.scanner.rulepack.maybe_wrap", side_effect=lambda scanner, *a, **k: scanner):
        cmd_mcp._run_scan(
            app, "decoy", "", False, False, False, quiet=True,
            audit_target="mcp://claudecode/decoy", audit_verdict=lambda r: "block",
        )
        cmd_mcp._run_scan(app, "decoy", "", False, False, False, quiet=True, audit_target="mcp://claudecode/decoy")

    assert [p["scan"].get("verdict") for p in recorder.payloads] == ["block", None]


@pytest.mark.parametrize(
    ("line", "severities", "want"),
    [("blocked", ("HIGH",), "block"), ("warn", ("HIGH",), "warn"), ("info", ("INFO",), "clean"), ("clean", (), "")],
)
def test_mcp_scan_audit_verdict_follows_the_scan_line(monkeypatch, line, severities, want) -> None:
    monkeypatch.setattr(cmd_mcp, "_mcp_scan_findings_verdict", lambda *a, **k: line)
    assert cmd_mcp._mcp_scan_audit_verdict(None, None, _result(*severities), name="decoy", connector="claudecode") == want


@pytest.mark.parametrize(
    ("verdicts", "severities", "want"),
    [
        (("rejected",), ("HIGH",), "block"),
        (("blocked", "rejected"), ("CRITICAL",), "block"),
        (("warning",), ("HIGH",), "warn"),
        (("allowed",), ("INFO",), "clean"),
        (("rejected", "warning"), ("HIGH",), ""),
        (("rejected",), (), ""),
    ],
)
def test_mcp_set_audit_verdict_agrees_with_every_connector_decision(verdicts, severities, want) -> None:
    decisions = [AdmissionDecision(v, "r") for v in verdicts]
    assert cmd_mcp._mcp_admission_audit_verdict(decisions, _result(*severities)) == want


@pytest.mark.parametrize(("post", "want"), [("rejected", "block"), ("warning", "warn")])
def test_mcp_set_scan_row_matches_the_admission_decision(post, want) -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.active_connectors = lambda: ["claudecode"]  # type: ignore[method-assign]

        def _decide(pe, *, scan_result=None, **kwargs):
            if scan_result is None:
                return AdmissionDecision("scan", "scan required", source="scan-required")
            return AdmissionDecision(post, "HIGH findings", source="scan-" + post)

        recorded: list[dict] = []
        with patch("defenseclaw.enforce.admission.evaluate_admission", side_effect=_decide), patch(
            "defenseclaw.scanner.mcp.MCPScannerWrapper.scan", return_value=_result("HIGH"),
        ), patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector"), patch(
            "defenseclaw.commands.cmd_mcp._record_scan",
            side_effect=lambda logger, result, **kwargs: recorded.append(kwargs),
        ):
            CliRunner().invoke(
                cmd_mcp.mcp, ["set", "decoy", "--command", "uvx", "--args", "decoy-mcp"],
                obj=app, catch_exceptions=False,
            )
        assert [kwargs.get("verdict") for kwargs in recorded] == [want]
    finally:
        cleanup_app(app, db_path, tmp_dir)
