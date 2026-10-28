# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0611: the "Check it worked" commands of ask-before-risky-calls.mdx run
against the audit rows the page's steps leave (deny, approve, or both, with
Claude Code's reply that quotes the URL after an approve, and a newer alert
from another connector) and print what the page shows."""

from __future__ import annotations

import os
import re
import shlex
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_alerts import alerts
from defenseclaw.models import Event

from tests.helpers import cleanup_app, make_app_context

PAGE = Path(__file__).resolve().parents[2] / "docs-site/content/docs/hitl.mdx"
RULE = {
    "defenseclaw.finding.rule_id": "C2-WEBHOOK-SITE",
    "defenseclaw.finding.title": "webhook.site (known exfil)",
    "defenseclaw.scan.scanner": "hook-rules",
}


def _section() -> str:
    text = PAGE.read_text(encoding="utf-8")
    return text.split("## Check it worked", 1)[1].split("\n## ", 1)[0]


def _commands() -> list[list[str]]:
    blocks = re.findall(r"```bash\n(.*?)```", _section(), re.S)
    commands = [shlex.split(line) for block in blocks for line in block.splitlines() if line.strip()]
    assert commands and all(c[:2] == ["defenseclaw", "alerts"] for c in commands), commands
    return [c[2:] for c in commands]


@pytest.fixture
def app():
    app, tmp_dir, db_path = make_app_context()
    columns = {row[1] for row in app.store.db.execute("PRAGMA table_info(audit_events)")}
    if "request_id" not in columns:
        app.store.db.execute("ALTER TABLE audit_events ADD COLUMN request_id TEXT")
    saved_columns = os.environ.get("COLUMNS")
    os.environ["COLUMNS"] = "240"
    yield app
    cleanup_app(app, db_path, tmp_dir)
    if saved_columns is None:
        os.environ.pop("COLUMNS", None)
    else:
        os.environ["COLUMNS"] = saved_columns


def _hook_finding(
    app, request_id: str, hook_event: str, action: str, at: datetime, connector: str = "claudecode"
) -> None:
    """The connector-hook row and the hook-rule finding the gateway writes for one hook call."""
    hook = Event(
        action="connector-hook",
        target=hook_event,
        severity="INFO",
        connector=connector,
        details=f"connector={connector} action={action} severity=HIGH",
        timestamp=at,
    )
    finding = Event(
        action="scan-finding",
        target="",
        severity="HIGH",
        connector=connector,
        details="finding.observed",
        timestamp=at,
        structured={**RULE, "defenseclaw.finding.target_ref": f"{connector}:{hook_event}"},
    )
    app.store.log_event(hook)
    app.store.log_event(finding)
    app.store.db.execute("UPDATE audit_events SET request_id=? WHERE id IN (?, ?)", (request_id, hook.id, finding.id))
    app.store.db.commit()


# Answers the reader may give in step 2. An approve run makes the command
# run, and Claude Code's reply quotes the URL (T6Z2-11).
RUNS = {
    "approve": ("approve",),
    "deny": ("deny",),
    "deny-then-approve": ("deny", "approve"),
}


def _run(app, answers: tuple[str, ...]) -> None:
    at = datetime.now(timezone.utc) - timedelta(minutes=5)
    for n, answer in enumerate(answers):
        _hook_finding(app, f"req-{n}", "PreToolUse", "confirm", at)
        at += timedelta(seconds=30)
        if answer == "approve":
            _hook_finding(app, f"req-{n}-reply", "MessageDisplay", "alert", at)
            at += timedelta(seconds=30)
    # Step 1 sets up Codex too; a newer Codex alert moves the global numbering.
    _hook_finding(app, "req-codex", "PreToolUse", "alert", at, connector="codex")


def _expected_lines() -> list[str]:
    blocks = re.findall(r"```text\n(.*?)```", _section(), re.S)
    assert len(blocks) == 1, blocks
    return [line.rstrip() for line in blocks[0].splitlines() if line.strip() and line.strip() != "…"]


def _same_line(page: str, shown: str) -> bool:
    # The ID and the timestamp differ per run.
    label = page.split(":", 1)[0].strip()
    if label in {"ID", "Timestamp"}:
        return shown.split(":", 1)[0].strip() == label
    return " ".join(page.split()) == " ".join(shown.split())


def _show_number(args: list[str]) -> int:
    return int(args[args.index("--show") + 1])


@pytest.mark.parametrize("run", sorted(RUNS))
def test_check_it_worked_shows_the_confirm_alert(app, run):
    _run(app, RUNS[run])
    runner = CliRunner()
    commands = _commands()
    list_args = [a for a in commands if "--show" not in a]
    show_args = [a for a in commands if "--show" in a]
    assert len(list_args) == 1 and len(show_args) == 1, commands
    list_args, show_args = list_args[0], show_args[0]

    listed = runner.invoke(alerts, list_args, obj=app, catch_exceptions=False)
    assert listed.exit_code == 0, (list_args, listed.output)
    targets = re.findall(r"claudecode:(PreToolUse|MessageDisplay)\s*[|│]\s*decision=(\w+)", listed.output)
    assert ("PreToolUse", "confirm") in targets, listed.output
    # The page's rule: the number of the newest PreToolUse confirm row of this list.
    newest_confirm = 1 + targets.index(("PreToolUse", "confirm"))

    # --show must number the same list the reader just read.
    def scope(args: list[str]) -> list[str]:
        return [args[i + 1] for i, a in enumerate(args) if a == "--connector"]

    assert scope(show_args) == scope(list_args), (list_args, show_args)

    # The page's example number holds for the approve run it describes.
    if run == "approve":
        assert _show_number(show_args) == newest_confirm, (show_args, listed.output)
    args = list(show_args)
    args[args.index("--show") + 1] = str(newest_confirm)
    result = runner.invoke(alerts, args, obj=app, catch_exceptions=False)
    assert result.exit_code == 0, (args, result.output)

    lines = result.output.splitlines()
    at = 0
    for expected in _expected_lines():
        if expected.startswith("Alert #"):
            expected = f"Alert #{newest_confirm}"
        while at < len(lines) and not _same_line(expected, lines[at]):
            at += 1
        assert at < len(lines), (args, expected, result.output)
        at += 1


def test_check_it_worked_names_the_later_reply_alert():
    text = " ".join(_section().split())
    assert "a newer `claudecode:MessageDisplay` row with `decision=alert`" in text
    assert "`claudecode:PreToolUse` row with `decision=confirm`" in text
