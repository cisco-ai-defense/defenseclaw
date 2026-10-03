# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""CLI help formatting (final-cert UX batch 14)."""

from __future__ import annotations

import click
from defenseclaw.main import _HelpContext, _HelpFormatter, cli


def _render(formatter_class) -> str:
    # Click's width for an 80-column terminal is 78.
    formatter = formatter_class(width=78)
    formatter.indent()
    formatter.write_dl(
        [
            ("findings", "Report distinct current scan findings (runs 'defenseclaw-gateway audit findings')."),
            ("log-activity", "x"),
        ]
    )
    formatter.dedent()
    formatter.write_text("Read the newest lines of ~/.defenseclaw/last-run.log and defenseclaw-gateway.log")
    return formatter.getvalue()


def _breaks_at_hyphen(text: str) -> bool:
    return any(line.rstrip().endswith("-") for line in text.splitlines())


def test_help_rows_never_wrap_at_a_hyphen() -> None:
    # GAP-2157: "(runs 'defenseclaw-" / "gateway audit findings')".
    assert _breaks_at_hyphen(_render(click.HelpFormatter))
    out = _render(_HelpFormatter)
    assert not _breaks_at_hyphen(out), out
    assert "'defenseclaw-gateway audit findings')" in out
    assert "defenseclaw-gateway.log" in out
    assert "\u2011" not in out


def test_audit_help_hides_the_internal_log_activity_helper() -> None:
    # GAP-2158: an internal helper with "Logger.log_activity" in its summary.
    audit = cli.commands["audit"]
    assert audit.context_class is _HelpContext
    text = audit.get_help(audit.context_class(audit, info_name="audit", terminal_width=80))
    assert "Commands:" in text and "findings" in text
    assert "log-activity" not in text
    assert "Logger" not in text
    assert "\u2011" not in text
    assert audit.commands["log-activity"].hidden
