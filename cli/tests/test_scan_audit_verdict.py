"""The audit row of a skill or plugin scan reads the verdict the CLI printed (GAP-0156)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from defenseclaw.commands import cmd_plugin, cmd_skill
from defenseclaw.logger import Logger
from defenseclaw.models import Finding, ScanResult


def _result(*severities: str) -> ScanResult:
    return ScanResult(
        scanner="skill-scanner",
        target="/tmp/sample",
        timestamp=datetime.now(timezone.utc),
        findings=[Finding(id=f"f{i}", severity=s, title="t", scanner="skill-scanner") for i, s in enumerate(severities)],
        duration=timedelta(milliseconds=5),
    )


class _Recorder:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    def emit_cli_observability(self, payload) -> None:
        self.sent.append(dict(payload))


def test_log_scan_puts_the_verdict_on_the_wire_only_when_given() -> None:
    recorder = _Recorder()
    logger = Logger(recorder)
    logger.log_scan(_result("CRITICAL"), verdict="block")
    logger.log_scan(_result("CRITICAL"))
    assert recorder.sent[0]["scan"]["verdict"] == "block"
    assert "verdict" not in recorder.sent[1]["scan"]


@pytest.mark.parametrize(
    ("label", "severities", "want"),
    [
        ("rejected", ("CRITICAL",), "block"),
        ("blocked", ("HIGH",), "block"),
        ("allowed", ("INFO",), "clean"),
        ("warning", ("MEDIUM",), "warn"),
        ("allowed", ("MEDIUM",), "warn"),
        ("-", ("LOW",), ""),
    ],
)
def test_skill_scan_audit_verdict_follows_the_policy_line(monkeypatch, label, severities, want) -> None:
    monkeypatch.setattr(cmd_skill, "_skill_policy_verdict", lambda *a, **k: (label, "", ""))
    pe = SimpleNamespace(is_blocked_for_connector=lambda *a, **k: False)
    assert cmd_skill._skill_scan_audit_verdict(None, pe, "s", "/tmp/s", _result(*severities)) == want


def test_skill_scan_audit_verdict_block_list_and_clean() -> None:
    pe = SimpleNamespace(is_blocked_for_connector=lambda *a, **k: True)
    assert cmd_skill._skill_scan_audit_verdict(None, pe, "s", "/tmp/s", _result("LOW")) == "block"
    assert cmd_skill._skill_scan_audit_verdict(None, pe, "s", "/tmp/s", _result()) == ""


@pytest.mark.parametrize(
    ("verdict", "rejects", "want"),
    [("warn", True, "block"), ("blocked", False, "block"), ("info", False, "clean"), ("warn", False, "warn")],
)
def test_plugin_scan_audit_verdict_follows_the_scan_line(monkeypatch, verdict, rejects, want) -> None:
    monkeypatch.setattr(cmd_plugin, "_plugin_scan_findings_verdict", lambda *a, **k: (verdict, rejects))
    assert cmd_plugin._plugin_scan_audit_verdict(None, _result("HIGH"), name="p", path="/tmp/p", connector="") == want
    assert cmd_plugin._plugin_scan_audit_verdict(None, _result(), name="p", path="/tmp/p", connector="") == ""
