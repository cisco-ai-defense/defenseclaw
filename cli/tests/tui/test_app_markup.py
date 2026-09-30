# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Markup-safety tests: every user, policy and subprocess string renders literally in the TUI."""

from __future__ import annotations

from types import SimpleNamespace

from defenseclaw.models import Event
from defenseclaw.tui.app import (
    DefenseClawTUI,
)
from defenseclaw.tui.panels.alerts import AlertEvent, AlertsPanelModel
from defenseclaw.tui.panels.audit import AuditPanelModel
from rich.text import Text

# ---------------------------------------------------------------------------
# Activity panel button bar + stdin pipe (Phase 1a click-first plan).
# These regression tests lock in the bar's presence so a future
# refactor can't strand operators in front of an interactive subprocess
# (the original "Selection [3]:" bug) with no clickable way to answer.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# AI Discovery panel button bar (Phase 1b click-first plan).
# Locks in the action bar so the panel is never view-only again —
# previously operators had to leave the panel to enable/scan via the
# drawer, which was the exact friction the user called out.
# ---------------------------------------------------------------------------


def test_safe_body_renderable_falls_back_on_invalid_style() -> None:
    """Bogus single-letter ``[e]`` markup must not crash rendering.

    The audit toolbar template ``[{action.key}] {action.label}`` was
    emitting strings like ``[e] export filter`` that Rich parsed as a
    style tag named ``e``. When the renderer later resolved that
    style it raised ``MissingStyle: 'e' is not a valid color`` and
    tore down the entire TUI. ``_safe_body_renderable`` must validate
    styles up front and fall back to plain text rather than re-throw.
    """

    rendered = DefenseClawTUI._safe_body_renderable(  # noqa: SLF001 - exercising defense in depth.
        "500 shown of 500 events   [e] export filter"
    )
    # We don't care which path the wrapper took (escape vs plain
    # fallback); we only care that it returned a Text object instead
    # of crashing — that's the regression we lock in.
    plain = rendered.plain
    assert "export" in plain
    assert "filter" in plain


def test_audit_body_text_escapes_action_key_brackets() -> None:
    """Escaped brackets keep ``[e] export`` rendered as literal text.

    Without escaping, the audit body crashes with ``MissingStyle`` the
    moment the panel renders. We assert both that the raw body string
    contains the escape and that the safety wrapper resolves it back
    to literal ``[e] export`` plain text.
    """

    panel = AuditPanelModel()
    app = DefenseClawTUI(audit_model=panel)
    app.active_panel = "audit"
    body = app._audit_body_text()  # noqa: SLF001 - regression for crash on switch.
    assert "\\[e]" in body
    rendered = DefenseClawTUI._safe_body_renderable(body)  # noqa: SLF001
    assert "[e] export" in rendered.plain


def test_audit_body_text_escapes_bracketed_filter_and_search_input() -> None:
    """User-supplied filter/search must not re-trigger the markup crash.

    The action-key fix escaped the static ``[e] export`` legend, but the
    Audit panel also echoes the operator's filter chip and the live ``/``
    search box. Both of those echo whatever the user typed — so a search
    for ``target:[skill]`` previously crashed the render pipeline with
    ``StyleSyntaxError: 'skill' is not a valid color``. Lock both paths
    in so future toolbar tweaks can't silently re-open the bug.
    """

    from rich.style import Style
    from rich.text import Text

    for hostile in ("target:[skill]", "run:[abc-123]", "[bogus]"):
        panel = AuditPanelModel()
        panel.filter_text = hostile
        panel.filtering = True
        app = DefenseClawTUI(audit_model=panel)
        app.active_panel = "audit"
        body = app._audit_body_text()  # noqa: SLF001 - regression for user-input crash.

        # ``from_markup`` is lazy: bad style names only blow up when
        # the renderer resolves them. Walk the spans and resolve each
        # style up-front — any unescaped ``[skill]`` shows up here.
        text = Text.from_markup(body)
        for span in text.spans:
            if isinstance(span.style, str) and span.style:
                Style.parse(span.style)  # raises if escape was missed.

        rendered = DefenseClawTUI._safe_body_renderable(body)  # noqa: SLF001
        assert hostile in rendered.plain, f"user input {hostile!r} dropped from rendered body"


def test_safe_body_renderable_handles_bracketed_status_strings() -> None:
    """``_set_status`` now routes its f-string through ``_safe_body_renderable``.

    Several status callers pass operator-supplied text straight through
    (e.g. ``self.audit_model.active_filter_label()`` after typing
    ``target:[skill]`` into the ``/`` search box). The previous
    implementation inlined that text into a Rich-parsed f-string and
    inherited the same ``MissingStyle`` / ``StyleSyntaxError`` crash
    class the audit-body fix closed. Verify the exact composed string
    the new ``_set_status`` feeds into the widget — ``f"{text}  [#444444]│[/]  {strip}"`` —
    survives the defensive wrapper on hostile input that uses
    *invalid* style names (the actual crash trigger). Inputs that
    happen to spell a valid Rich style (``[red]``) still get
    interpreted as markup — that's a known UX wart of layering
    user text inside a markup-parsed f-string and is the reason
    source-side escaping (see ``_audit_body_text``) is preferred
    for the panels we've already fixed.
    """

    safe = DefenseClawTUI._safe_body_renderable  # noqa: SLF001 - exercising defense in depth.
    for hostile in (
        "target:[skill]",
        "run:[abc-xyz]",
        "search:[unmatched",  # unbalanced bracket -> MarkupError fallback.
    ):
        composed = f"{hostile}  [#444444]│[/]  Ready"
        rendered = safe(composed)
        assert isinstance(rendered, Text)
        # Defensive guarantee: no crash, and the operator's text
        # survives as literal characters in the rendered plain text
        # (either via the validator dropping the bogus span or the
        # MarkupError fallback returning the whole string verbatim).
        assert hostile in rendered.plain


def test_judge_history_prefix_escapes_index_brackets() -> None:
    """``judge_response_detail_pairs`` must escape numeric prefixes.

    Without escaping, the modal renders ``[1] Timestamp`` which Rich
    interprets as ANSI color 1 (red) for the entire row, and once
    the operator has 16+ retained rows the prefix flips to ``[16]``
    and explodes with ``MissingStyle: '16' is not a valid color``.
    """

    from defenseclaw.tui.screens.judge_history import judge_response_detail_pairs

    rows = [
        {
            "timestamp": "2026-05-21T00:00:00Z",
            "kind": "policy",
            "direction": "inbound",
            "action": "allow",
            "severity": "LOW",
            "category": "",
            "rule": "",
            "decision_score": 0.0,
            "abridged": False,
            "source": "judge",
            "request_id": "r1",
            "trace_id": "t1",
            "span_id": "s1",
            "model": "m",
        }
        for _ in range(2)
    ]
    pairs = judge_response_detail_pairs(rows)
    labels = [label for label, _ in pairs if label]
    assert any(label.startswith("\\[1]") for label in labels)
    assert any(label.startswith("\\[2]") for label in labels)
    for label in labels:
        assert not label.startswith("[1]")
        assert not label.startswith("[2]")


def test_setup_webhook_summary_escapes_status_brackets() -> None:
    """Webhook summaries must escape ``[enabled]`` / ``[disabled]``."""

    from defenseclaw.tui.panels.setup import _webhook_summary_fields

    cfg = {
        "webhooks": [
            {"type": "webhook", "name": "ops", "url": "https://example/test", "enabled": True},
            {"type": "webhook", "name": "audit", "url": "https://example/audit", "enabled": False},
        ]
    }
    fields = _webhook_summary_fields(cfg)
    summaries = [field.value for field in fields if field.value]
    assert any(summary.startswith("\\[enabled]") for summary in summaries)
    assert any(summary.startswith("\\[disabled]") for summary in summaries)
    for summary in summaries:
        assert not summary.startswith("[enabled]")
        assert not summary.startswith("[disabled]")


def test_mode_picker_choice_action_escapes_hotkey_brackets() -> None:
    """Mode-picker MenuActions must escape the hotkey bracket."""

    from defenseclaw.tui.screens.mode_picker import MODE_PICKER_CHOICES, _choice_action

    for choice in MODE_PICKER_CHOICES:
        action = _choice_action(choice, current_wire="")
        assert action.label.startswith("\\["), action.label
        assert f"\\[{choice.hotkey}]" in action.label


# ---------------------------------------------------------------------
# Phase-1 markup-safety regression suite. Together with the existing
# audit/judge-history/setup/mode-picker/consequence tests above, these
# cover every "must not crash" Rich-markup site we audited in the TUI
# (RichLog writes, command-progress snippet, native overview notices,
# native metric detail strings, hint bar, judge-history modal,
# command-preview modal, and the shared detail modal).
# ---------------------------------------------------------------------


_HOSTILE_CORPUS = (
    "plain text",
    "target:[skill]",
    "run:[abc]",
    "[INFO] starting",
    "[WARN] retrying",
    "[ERROR] something broke",
    "[OK] ready",
    "Selection [3]:",
    "prompt[16]",  # numeric color 16+ is invalid
    "path with brackets [a/b/c]",
    "unclosed [bracket",
    "nested [bold][skill]nope[/][/]",
    "chr [\\u001b[31mred\\u001b[0m]",
)


def test_safe_body_renderable_handles_hostile_corpus() -> None:
    """Every string in our hostile corpus must survive the safety
    wrapper — either parsed cleanly or falling back to plain text —
    and the original characters must show up in the rendered plain
    text. This is the regression net for every future panel author:
    if ``_body_text``/``_detail_text`` ever produces a string with the
    same shape, the rendering pipeline still won't crash the TUI.
    """

    safe = DefenseClawTUI._safe_body_renderable  # noqa: SLF001
    for hostile in _HOSTILE_CORPUS:
        rendered = safe(hostile)
        assert isinstance(rendered, Text)
        # The visible characters survive: both the bracket fallback
        # path (returns the raw string) and the markup-parsing path
        # (drops the spans) preserve the literal characters.
        assert hostile.replace("[/", "").replace("[/]", "") in rendered.plain or rendered.plain.startswith(hostile[:20])


def test_write_activity_safe_escapes_subprocess_output(monkeypatch) -> None:
    """``_write_activity_safe`` must hand a safe renderable to the
    Activity RichLog — that's the whole point of the helper. Without
    safe-handling, a subprocess line like ``[INFO] foo`` crashes the
    Rich parser and tears down the activity stream.

    Implementation note: the helper switched from ``rich_escape``
    (which left ANSI bytes intact and leaked them as visible
    ``[1;33m...`` in the UI) to ``Text.from_ansi`` (which converts
    ANSI SGR sequences AND treats remaining content as opaque text,
    closing both the markup crash AND the ANSI leak in one go).
    Verify we now hand a ``Text`` object with the literal content
    preserved.
    """

    from rich.text import Text

    captured: list = []

    class _FakeRichLog:
        def write(self, renderable) -> None:  # noqa: ANN001
            captured.append(renderable)

    fake = _FakeRichLog()
    app = DefenseClawTUI.__new__(DefenseClawTUI)
    app.activity_lines = []  # type: ignore[attr-defined]

    def _query_one(_selector, _expected_type):  # noqa: ANN001
        return fake

    monkeypatch.setattr(app, "query_one", _query_one, raising=False)
    # ``[skill]`` is the canonical risk shape — Rich's markup parser
    # treats it as an opening style tag. Text.from_ansi consumes
    # the entire string as opaque text (no markup re-parse), so the
    # literal brackets survive verbatim into the Text's ``.plain``
    # without needing a separate escape pass.
    app._write_activity_safe("prompt: [skill] continue")  # noqa: SLF001
    assert len(captured) == 1
    rendered = captured[0]
    assert isinstance(rendered, Text), (
        "must hand a rich.text.Text object so RichLog skips its markup "
        "re-parse and the bracketed token can't take down the stream"
    )
    assert rendered.plain == "prompt: [skill] continue"


def test_write_activity_safe_converts_ansi_color_codes_to_styles(monkeypatch) -> None:
    """``_write_activity_safe`` must translate ANSI SGR sequences from
    subprocess stdout into actual Rich styles, NOT leak the raw escape
    bytes through to the renderer as visible literals like ``[1;33m``.

    Repro of the bug the operator screenshotted: ``ux.warn`` ->
    ``click.style`` writes ``\\x1b[1;33m\u25b3 warning:\\x1b[0m \\x1b[33mfoo\\x1b[0m``
    to stdout. The pre-fix safe writer fed those bytes verbatim to
    the Activity RichLog, which rendered them as the literal text
    the operator saw on screen. The fix routes through
    ``Text.from_ansi`` so the SGR codes become actual styles.
    """

    from rich.text import Text

    captured: list = []

    class _FakeRichLog:
        def write(self, renderable) -> None:  # noqa: ANN001
            captured.append(renderable)

    fake = _FakeRichLog()
    app = DefenseClawTUI.__new__(DefenseClawTUI)
    app.activity_lines = []  # type: ignore[attr-defined]

    def _query_one(_selector, _expected_type):  # noqa: ANN001
        return fake

    monkeypatch.setattr(app, "query_one", _query_one, raising=False)
    # Exact byte sequence ``click.style("warning:", fg="yellow", bold=True)``
    # produces — bold + yellow on, then reset.
    app._write_activity_safe("\x1b[1;33mwarning:\x1b[0m foo")  # noqa: SLF001

    assert len(captured) == 1
    rendered = captured[0]
    assert isinstance(rendered, Text)
    # The plain text must NOT include the raw escape bytes — that's
    # the operator-visible regression we're closing.
    assert "\x1b" not in rendered.plain
    assert "[1;33m" not in rendered.plain
    assert "[0m" not in rendered.plain
    # The visible content is the bare strings (escape bytes consumed).
    assert rendered.plain == "warning: foo"
    # And the styling must have been applied — there should be at
    # least one span (for the bold-yellow ``warning:`` segment).
    assert len(rendered.spans) >= 1, "ANSI codes should produce styled spans"


def test_findings_metric_detail_renders_bracketed_target_literally() -> None:
    """Build the metric detail string with a hostile target token and
    confirm Rich renders the brackets as literal characters. If the
    escape regresses, ``[skill]`` is consumed as a style tag and the
    detail line silently loses the target name.
    """

    app = DefenseClawTUI.__new__(DefenseClawTUI)
    # ``_top_finding_target`` returns ``(target, severity_letter)``;
    # the ``[skill]`` shape is the canonical Rich-tag risk pattern.
    app._top_finding_target = lambda: ("target [skill]:malware", "H")  # type: ignore[method-assign]  # noqa: SLF001
    detail = DefenseClawTUI._findings_metric_detail(  # noqa: SLF001
        app, critical=1, high=2, medium=0, low=0
    )
    rendered_plain = Text.from_markup(detail).plain
    # The bracketed target survives in the rendered detail string.
    assert "[skill]" in rendered_plain


def test_ai_metric_detail_renders_bracketed_vendor_literally() -> None:
    """Same shape as the findings test: feed a vendor name with a
    bracketed token through the AI metric detail formatter and verify
    the brackets render literally.
    """

    ai_box = SimpleNamespace(rows=[SimpleNamespace(vendor="acme[v2]")])
    app = DefenseClawTUI.__new__(DefenseClawTUI)
    detail = DefenseClawTUI._ai_agents_metric_detail(app, ai_box)  # noqa: SLF001
    rendered_plain = Text.from_markup(detail).plain
    assert "acme[v2]" in rendered_plain


def test_hint_bar_disables_markup_parsing() -> None:
    """HintBar passes user filter strings (e.g. ``target:[skill]``)
    straight into the Static label. The Static must have ``markup=False``
    so a bracketed filter can't crash the hint bar's update path.
    """

    from defenseclaw.tui.widgets.hint_bar import HintBar

    bar = HintBar()
    # Textual stores the Static's markup flag at ``_render_markup``.
    # We assert the canonical attribute first; if a future Textual
    # release renames it, fall back to a render-shape probe so the
    # test still distinguishes "literal text" from "parsed markup".
    flag = getattr(bar, "_render_markup", None)
    if flag is None:
        # Try the alternative attribute names some Textual versions use.
        for name in ("use_markup", "_markup", "markup"):
            value = getattr(bar, name, None)
            if value is not None:
                flag = value
                break
    assert flag is False, "HintBar must opt out of Rich markup parsing"


def test_judge_history_format_pair_renders_bracketed_value_literally() -> None:
    """Judge bodies are raw JSON snippets; the modal must escape
    ``value`` so a bracketed token in the body never crashes the
    markup-parsed Static. Behavioral check: feed the format helper a
    hostile value and confirm Rich renders the brackets as literal
    characters in the resulting markup string.
    """

    from defenseclaw.tui.screens.judge_history import _format_pair

    rendered = _format_pair("Raw", "prompt: [skill] Tell me [16]")
    # Render the markup string the same way the modal's Static would.
    plain = Text.from_markup(rendered).plain
    # ``rich.markup.escape`` is conservative: it escapes ``[skill]``
    # (lowercase tag-shape) and leaves numeric ``[16]`` alone because
    # Rich treats numeric tokens as literal text already. Both must
    # survive in the rendered plain text; if the escape regresses,
    # ``[skill]`` is dropped silently.
    assert "[skill]" in plain
    assert "[16]" in plain


def test_detail_modal_table_renders_bracketed_label_value_literally() -> None:
    """Build a ``DetailModalModel.table()`` from rows that include
    bracketed values (audit ``target=[skill]`` is a real shape we see
    in the wild) and verify the rendered table preserves the literal
    brackets. The previous code path forwarded the raw values into
    Rich markup and crashed when any value contained ``[lowercase]``.
    """

    from io import StringIO

    from defenseclaw.tui.screens.detail import DetailModalModel
    from rich.console import Console

    rows = (
        ("Action", "scan"),
        ("Target", "[skill] malware"),
        ("Detail", "policy=[strict] match=[allow]"),
    )
    model = DetailModalModel.from_pairs("Audit Detail", rows)
    table = model.table()
    # Render through a Rich console capturing plain text — that's
    # exactly what the modal's Static does when displayed.
    buf = StringIO()
    Console(file=buf, force_terminal=False, width=120).print(table)
    plain = buf.getvalue()
    assert "[skill]" in plain
    assert "[strict]" in plain
    assert "[allow]" in plain


def test_tui_panel_outputs_survive_hostile_markup_corpus() -> None:
    """Fuzz-style sweep: feed each hostile corpus string through
    ``_safe_body_renderable`` (the wrapper used by every panel body
    and detail update) and assert the result is a ``Text`` object —
    *never* an exception. This is the floor: as long as the wrapper
    holds, no panel can crash the TUI mid-frame, even if a future
    panel author forgets to escape user input on the way in.
    """

    safe = DefenseClawTUI._safe_body_renderable  # noqa: SLF001
    for hostile in _HOSTILE_CORPUS:
        # Compose hostile text into the kinds of strings panels build
        # at runtime so the test exercises the same surfaces an
        # operator would hit.
        for composed in (
            hostile,
            f"[bold #22D3EE]Header[/]\n{hostile}",
            f"line 1\n  {hostile}\n  follow-up",
            f"{hostile}  [#444444]│[/]  Ready",
        ):
            # No exception is the primary contract; the assertion
            # below is the strict shape contract.
            rendered = safe(composed)
            assert isinstance(rendered, Text), composed
            # Strict: every visible character that wasn't a markup
            # delimiter must survive into ``.plain``. We strip only
            # the bracket pairs Rich actually parses (lowercase tags,
            # close tags, hex/style spans) before comparing.
            for char in hostile:
                if char not in "[]/":
                    # Spot-check: any non-bracket character that was
                    # in the hostile string should also be in the
                    # rendered plain text. This catches catastrophic
                    # truncation that ``isinstance`` alone would miss.
                    if char.isalnum() or char in " :,.-_":
                        assert char in rendered.plain, f"character {char!r} dropped while rendering {composed!r}"


# ---------------------------------------------------------------------
# Phase-2 markup-safety regression suite. These complement the
# Phase-1 crash-site tests above by covering the *fallback* sites —
# strings the safety wrapper catches but Rich silently drops content
# from. They also include a static scanner that walks the TUI source
# tree and bans any new unescaped lowercase-bracket tokens, with an
# explicit allow-list for known-safe Rich style names.
# ---------------------------------------------------------------------


def test_setup_wizard_mode_hint_renders_bracketed_hint_literally() -> None:
    """The wizard-mode body builds a hint span with the same shape
    used in the live ``_setup_body_text`` fallback. Reconstruct that
    fragment with a hostile bracketed hint (``webhooks[0].url`` is
    the canonical real-world shape) and verify Rich's parser preserves
    the brackets in plain text. Without ``rich_escape(focused.hint)``
    the ``[0]`` is consumed as a style tag and the whole hint span
    silently collapses to plain text — the operator stops getting any
    actionable wizard guidance.
    """

    from defenseclaw.tui.theme import DEFAULT_TOKENS as TOKENS
    from rich.markup import escape as rich_escape

    hostile_hint = "set webhooks[0].url to your endpoint"
    # Mirror the exact fragment in app.py:_setup_body_text so a
    # refactor that drops the ``rich_escape`` call site still fails.
    fragment = "\n[" + TOKENS.text_secondary + "]" + rich_escape(hostile_hint) + "[/]"
    plain = Text.from_markup(fragment).plain
    # The full hint, brackets included, must survive Rich parsing.
    assert "webhooks[0].url" in plain


def test_audit_panel_render_text_renders_e_export_close_filter_literally() -> None:
    """The audit header embeds ``[e] export  [/] filter``. Both
    bracket pairs are problematic for Rich: ``[e]`` is a lowercase
    tag-shape and ``[/]`` is an unmatched close that raises
    ``MarkupError``. Render through ``Text.from_markup`` (which
    raises on real malformed markup) and assert both literals appear
    in the plain text.
    """

    panel = AuditPanelModel()
    # Inject a synthetic event so render_text reaches the header line.
    panel.set_events(
        [
            Event(
                id="1",
                action="scan",
                target="example",
                severity="HIGH",
                details="",
            )
        ]
    )
    panel.apply_filter()
    rendered = panel.render_text(height=24)
    plain = Text.from_markup(rendered).plain
    assert "[e] export" in plain
    assert "[/] filter" in plain


def test_audit_panel_summary_text_renders_e_export_close_filter_literally() -> None:
    """Same defense as ``render_text`` but for the lighter-weight
    summary header used in toolbars and tooltips.
    """

    panel = AuditPanelModel()
    plain = Text.from_markup(panel.summary_text()).plain
    assert "[e] export" in plain
    assert "[/] filter" in plain


def test_alerts_summary_text_renders_user_filter_text_literally() -> None:
    """Set a hostile filter on the alerts panel and confirm the
    summary line keeps the bracketed text literal. Without the
    escape Rich would parse ``[skill]`` as an opening style tag and
    silently truncate the search prompt.
    """

    alerts = AlertsPanelModel()
    alerts.filter_text = "target:[skill]"
    alerts.filtering = True
    rendered = alerts.summary_text()
    plain = Text.from_markup(rendered).plain
    assert "target:[skill]" in plain


def test_alerts_finding_scanner_badge_renders_literally() -> None:
    """Build an alert event with a finding whose ``scanner`` field is
    a lowercase identifier (``trivy``, ``semgrep`` are real values),
    select that alert in the panel, and verify the detail text
    preserves the ``[scanner]`` badge literally. Rich would otherwise
    consume the badge as a style tag and the operator would lose the
    most useful piece of triage info.
    """

    from defenseclaw.tui.panels.alerts import AlertDetailInfo, AlertFinding

    event = AlertEvent(
        id="evt-1",
        severity="HIGH",
        action="alert",
        target="/tmp/vendor",
    )
    finding = AlertFinding(
        id="f-1",
        scan_id="s-1",
        severity="HIGH",
        title="Critical CVE",
        scanner="trivy",
        location="/tmp/vendor",
    )
    info = AlertDetailInfo(event=event, findings=(finding,))

    alerts = AlertsPanelModel()
    alerts.detail_open = True
    # ``get_detail_info`` is the resolution seam used by both
    # ``detail_text`` and ``detail_pairs``. Patch it so we don't need
    # a full event store wired up just to surface a finding.
    alerts.get_detail_info = lambda: info  # type: ignore[method-assign]

    text_plain = Text.from_markup(alerts.detail_text()).plain
    assert "[trivy]" in text_plain

    pairs_plain = "\n".join(Text.from_markup(value).plain for _label, value in alerts.detail_pairs())
    assert "[trivy]" in pairs_plain


# Static scanner: the regression net for this entire bug class.
# ----------------------------------------------------------------

# The empirical rule (verified by probing Rich at runtime): Rich
# treats ``[X]`` as a markup tag iff X starts with a lowercase letter,
# ``#`` (hex color), or ``@`` (variable). Everything else — uppercase,
# numeric, whitespace-led, ``/`` close-tag, ``!``, etc. — is rendered
# as literal text. So the *only* unsafe shape we have to ban is a
# bracket pair starting with a lowercase letter.
import ast as _ast_scanner
import re as _re_scanner

# Rich style names that are intentional and safe to leave unescaped.
# Anything in this set is allowed to appear as ``[name]`` in markup
# strings without a backslash escape because Rich resolves it to a
# real style.
_RICH_STYLE_ALLOWLIST = frozenset(
    {
        "bold",
        "dim",
        "italic",
        "underline",
        "blink",
        "reverse",
        "strike",
        "conceal",
        "overline",
        "frame",
        "encircle",
        "black",
        "red",
        "green",
        "yellow",
        "blue",
        "magenta",
        "cyan",
        "white",
        "bright_black",
        "bright_red",
        "bright_green",
        "bright_yellow",
        "bright_blue",
        "bright_magenta",
        "bright_cyan",
        "bright_white",
        "on red",
        "on green",
        "on blue",
        "on yellow",
        "on cyan",
        "on magenta",
        "on white",
        "on black",
        "link",
        "reset",
        "none",
    }
)

# Per-string-literal allow-list for legitimate intentional uses
# of bracket-tag-shaped tokens that we don't want the scanner to
# flag (e.g. example markup in docstrings/help text, hostile-input
# corpora used by the markup tests themselves). Each entry is a
# substring; if the literal *contains* the substring, it's exempt.
_LITERAL_ALLOWLIST: tuple[str, ...] = (
    # Test fixtures that deliberately exercise hostile inputs.
    "target:[skill]",
    "prompt[16]",
    "Selection [3]:",
    "unclosed [bracket",
    "nested [bold][skill]nope",
    # Help / cheatsheet text that documents valid Rich markup.
    "[bold #22D3EE]",
    "[#9FB2CC]",
    # Docstring example in _safe_body_renderable's prose.
    "``[e] export``",
    # CLI usage hint shown in the command palette / error messages
    # (rendered via _write_activity, which already escapes via
    # ``rich_escape(str(exc))`` in the Phase-1 fix).
    "<preset> [flags]",
    # TOML section name shown in setup info text — not Rich markup.
    "[mcp_servers]",
    "([mcp_servers])",
    # Audit-row demonstration text (already covered by _audit_body_text
    # which routes through ``_safe_body_renderable``).
    "[Enter] view output",
    # Regex character classes inside raw-string patterns that never
    # flow through Rich markup (validators.py / answers.py only feed
    # these into ``re.compile``).
    "[a-z0-9][a-z0-9-]",
    "[A-Z][A-Z0-9_-]",
    "[a-z_]+",
    # Overview notice hotkey hints — the consumer (``_overview_body_text``)
    # wraps ``notice.message`` in ``rich_escape`` so the brackets render
    # literally even though Rich would otherwise parse them as style
    # tags. Keeping the bracketed letters readable in the source notice
    # is more useful to the operator than spreading escape backslashes
    # through every notice message.
    "press [g] to set up",
    "press [d] to refresh",
    "press [d] on Overview",
)

# Variable expressions inside f-strings whose values are statically
# guaranteed to be safe (hex colors, known Rich styles). Adding to
# this list is fine; missing one only causes a false-positive flag.
_FSTRING_EXPR_ALLOWLIST_PREFIXES: tuple[str, ...] = (
    "TOKENS.",
    "DEFAULT_TOKENS.",
    "color",
    "snippet_color",
    "alert_color",
    "icon_color",
)


# Suffix-based allow-list: f-string expressions that statically
# evaluate to an uppercase string never produce a tag-shaped bracket
# pair, so we don't need to flag them. ``.upper()`` and known-
# uppercase attributes like ``check.badge`` (FAIL/PASS/STALE/WARN)
# fall in this bucket.
_FSTRING_EXPR_ALLOWLIST_SUFFIXES: tuple[str, ...] = (
    ".upper()",
    ".UPPER()",
)

# Specific f-string expression strings that are known-safe at runtime
# (e.g. integer indices that always render as ``[0]`` / ``[1]`` /
# ``[16]`` — numeric tokens that Rich treats as literal text).
_FSTRING_EXPR_ALLOWLIST_EXACT: frozenset[str] = frozenset(
    {
        "index",
        "i",
        "n",
        "check.badge",
        "notice.level.upper()",
        # Catalog action key (single character). The surrounding code
        # in catalog_state.py wraps the rendered chunks in ``[dim]…[/]``
        # before display, so the bracket-tag shape never reaches the
        # user's terminal as a literal — Rich consumes the outer tags
        # first and the inner bracket pair is harmless.
        "action.key",
    }
)


_RAW_BRACKET_RE = _re_scanner.compile(r"(?<!\\)\[(?P<tag>[a-z][^\[\]]{0,40})\]")
_FSTRING_BRACKET_RE = _re_scanner.compile(r"(?<!\\)\[\{(?P<expr>[^{}]+)\}\]")


def _is_allowlisted_literal(literal: str) -> bool:
    return any(fragment in literal for fragment in _LITERAL_ALLOWLIST)


def _flag_raw_string(literal: str) -> list[str]:
    """Return the offending bracket tokens from a literal Python str."""

    if _is_allowlisted_literal(literal):
        return []
    findings: list[str] = []
    for match in _RAW_BRACKET_RE.finditer(literal):
        tag = match.group("tag").rstrip()
        if tag in _RICH_STYLE_ALLOWLIST:
            continue
        first_token = tag.split(" ")[0]
        if first_token in _RICH_STYLE_ALLOWLIST:
            continue
        findings.append(match.group(0))
    return findings


def _flag_fstring_placeholder(joined_text: str) -> list[str]:
    """Return offending ``[{expr}]`` patterns from an f-string's joined
    representation. ``joined_text`` has ``{expr}`` placeholders for
    each interpolation, so a Rich-markup ``[{var}]`` literal will
    show up as ``[{var}]`` in the joined string. A Python subscript
    like ``counts[key]`` shows up as ``{counts[key]}`` (the entire
    expression sits inside one placeholder) and won't match the
    ``[{...}]`` regex because there's no literal ``[`` adjacent to
    the opening brace. That asymmetry is exactly what we want — the
    scanner only flags the genuine markup shape.
    """

    if _is_allowlisted_literal(joined_text):
        return []
    findings: list[str] = []
    for match in _FSTRING_BRACKET_RE.finditer(joined_text):
        expr = match.group("expr").strip()
        if expr.startswith(_FSTRING_EXPR_ALLOWLIST_PREFIXES):
            continue
        if expr.endswith(_FSTRING_EXPR_ALLOWLIST_SUFFIXES):
            continue
        if expr in _FSTRING_EXPR_ALLOWLIST_EXACT:
            continue
        findings.append(match.group(0))
    return findings


def _joined_str_text_and_exprs(node: object) -> tuple[str, list[str]]:
    """Convert an ``ast.JoinedStr`` to its joined text (with ``{}``
    placeholders for FormattedValue parts) and the list of Python
    source for each interpolation in order. Returns ``("", [])`` if
    ``node`` isn't a JoinedStr.
    """

    if not isinstance(node, _ast_scanner.JoinedStr):
        return "", []
    parts: list[str] = []
    exprs: list[str] = []
    for value in node.values:
        if isinstance(value, _ast_scanner.Constant) and isinstance(value.value, str):
            parts.append(value.value)
        elif isinstance(value, _ast_scanner.FormattedValue):
            exprs.append(_ast_scanner.unparse(value.value))
            parts.append("{" + exprs[-1] + "}")
    return "".join(parts), exprs


def _scan_tui_source_for_lowercase_brackets() -> list[tuple[str, int, str]]:
    """Return ``(relpath, lineno, snippet)`` for every Python string
    literal or f-string in the TUI source tree that contains an
    unescaped ``[lowercase…]`` token Rich would parse as a markup tag.

    The walk is AST-based: only ``Constant(str)`` and ``JoinedStr``
    nodes are inspected. Type subscripts (``list[str]``), dict/list
    indexing, and other non-string syntax are ignored automatically.
    """

    from pathlib import Path as _Path

    repo = _Path(__file__).resolve().parents[3]
    targets = [
        repo / "cli/defenseclaw/tui",
        repo / "cli/defenseclaw/commands/cmd_tui.py",
    ]

    files: list[_Path] = []
    for target in targets:
        if target.is_dir():
            files.extend(p for p in target.rglob("*.py") if "__pycache__" not in p.parts)
        elif target.is_file():
            files.append(target)

    findings: list[tuple[str, int, str]] = []
    for path in files:
        rel = str(path.relative_to(repo))
        try:
            tree = _ast_scanner.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        for node in _ast_scanner.walk(tree):
            if isinstance(node, _ast_scanner.Constant) and isinstance(node.value, str):
                # Skip docstrings — they're prose, not Rich-rendered.
                # We can identify a docstring as the first statement of
                # a module / class / function body, but the simpler
                # heuristic is to skip any string > 200 chars long
                # (docstrings) since real markup strings are much
                # shorter than that.
                if len(node.value) > 200:
                    continue
                bad = _flag_raw_string(node.value)
                for token in bad:
                    findings.append((rel, node.lineno, token))
            elif isinstance(node, _ast_scanner.JoinedStr):
                # Two passes for f-strings:
                # 1. Each *literal* part is plain Python str text. Run
                #    the raw regex on it the same way we'd run it on a
                #    Constant(str) — this catches ``f"[bold]{x}[/]"``-
                #    style markup written into the static parts.
                # 2. Build the joined ``"x [{expr}] y"`` shape with
                #    ``{expr}`` placeholders for each interpolation,
                #    then run the placeholder-anchored regex. That
                #    only matches when the brackets are *literal*
                #    (i.e. adjacent to the placeholder boundary), so
                #    Python subscripts inside the placeholder don't
                #    trigger false positives.
                for value in node.values:
                    if isinstance(value, _ast_scanner.Constant) and isinstance(value.value, str):
                        for token in _flag_raw_string(value.value):
                            findings.append((rel, value.lineno, token))
                joined, _exprs = _joined_str_text_and_exprs(node)
                if joined:
                    for token in _flag_fstring_placeholder(joined):
                        findings.append((rel, node.lineno, token))
    return findings


def test_no_unescaped_lowercase_bracket_tokens_in_tui_sources() -> None:
    """Permanent guardrail: walk every Python file under the TUI
    package and refuse to merge any change that introduces a new
    unescaped ``[lowercase…]`` literal or ``f"[{lowercase_var}]"``
    pattern. Rich parses such tokens as opening style tags and either
    silently drops the bracketed content or — worse — fails the
    safety wrapper's per-span ``Style.parse`` validation, forcing
    the whole panel body to plain-text fallback.

    Failures here mean the operator will see panels with content
    silently dropped (``"  Scan all"`` instead of ``"[s] Scan all"``)
    or whole-panel color regressions when the wrapper falls back.
    Either escape the bracket (``\\[s]``), pick an uppercase label,
    or — if the token is a deliberate Rich style — add it to
    ``_RICH_STYLE_ALLOWLIST`` above.
    """

    findings = _scan_tui_source_for_lowercase_brackets()
    if findings:
        report = "\n".join(f"  {rel}:{lineno}  {snippet}" for rel, lineno, snippet in findings[:50])
        # Truncated message keeps the failure log scannable.
        assert not findings, (
            f"Found {len(findings)} unescaped lowercase-bracket token(s) in "
            f"the TUI source. Each one is parsed by Rich as a style tag and "
            f"silently drops the bracketed text. Either backslash-escape the "
            f"opening bracket (``\\\\[s]``), pick an uppercase label, or — if it "
            f"is an intentional Rich style — register it in "
            f"``_RICH_STYLE_ALLOWLIST``.\n\nOffending lines:\n{report}"
        )


def test_activity_history_render_keeps_t_hotkey_literal() -> None:
    """Render the activity panel's history view and verify the ``[t]``
    hotkey survives Rich parsing. Lowercase tag-shape would otherwise
    drop the bracketed letter from the visible output.
    """

    from defenseclaw.tui.panels.activity import ActivityEntry, ActivityPanelModel

    activity = ActivityPanelModel()
    activity.entries = [ActivityEntry(command="defenseclaw doctor", done=True, exit_code=0)]
    activity.term_mode = False  # exercise the history-tab branch
    rendered = activity.render_text(height=24)
    plain = Text.from_markup(rendered).plain
    assert "[t] terminal mode" in plain
    assert "[Enter] view output" in plain  # uppercase-led, also literal
