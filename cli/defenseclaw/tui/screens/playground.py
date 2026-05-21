# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 11: Playground modal screen.

Rich-renderer shell around ``PlaygroundModel``. The modal lays out:

* Left rail: 18-section navigation list (status badge + title +
  subtitle).
* Right pane: the active section's editor view (Rich text).
* Optional bottom: live test pane (toggled with ``p``) showing the
  bundled scenarios and a "press X to run" affordance.
* Optional collapsible: diff-vs-preset panel (toggled with ``d``).
* Footer: validation strip + key hints + save status.

Edits flow through ``PlaygroundModel.handle_key`` so every behavior
is unit-testable headlessly. The modal screen returns the saved
``Policy`` on Ctrl+S or ``None`` on Esc/Cancel - the same return
shape as ``QuickStartScreen`` so the calling Policy panel can use
one ``_save_wizard_policy`` for both flows.
"""

from __future__ import annotations

from rich.markup import escape as rich_escape
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

from defenseclaw.tui.creator.command_palette import Command
from defenseclaw.tui.creator.diff import render_diff_lines
from defenseclaw.tui.creator.emit import policy_to_gateway_yaml
from defenseclaw.tui.creator.emit_script import emit_install_script
from defenseclaw.tui.creator.playground_model import (
    SECTION_DEFS,
    PlaygroundModel,
    SectionStatus,
)
from defenseclaw.tui.creator.rego_lint import (
    has_blocking_errors,
    lint_rego,
    render_issues,
)
from defenseclaw.tui.creator.types import (
    SCANNER_TYPES,
    SEVERITIES,
    Policy,
)
from defenseclaw.tui.screens.command_palette import CommandPaletteScreen
from defenseclaw.tui.theme import DEFAULT_TOKENS

_STATUS_GLYPH: dict[SectionStatus, str] = {
    "untouched": ".",
    "customized": "*",
    "warning": "!",
}


class PlaygroundScreen(ModalScreen[Policy | None]):
    """Full-knob policy editor.

    Returns the live ``Policy`` on Ctrl+S, or ``None`` on Esc.
    """

    CSS = f"""
    PlaygroundScreen {{
        align: center middle;
    }}

    #playground-dialog {{
        width: 140;
        height: 42;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #playground-title {{
        height: 1;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #playground-body {{
        height: 1fr;
    }}

    #playground-nav {{
        width: 38;
        padding-right: 1;
        border-right: solid {DEFAULT_TOKENS.border_muted};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #playground-detail {{
        padding-left: 1;
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #playground-footer {{
        height: 3;
        margin-top: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
        Binding("ctrl+s", "save_policy", "Save", show=False),
        Binding("ctrl+k", "open_command_palette", "Command palette", show=False),
        Binding("ctrl+l", "run_rego_lint", "Lint custom-rego", show=False),
    ]

    def __init__(self, policy: Policy) -> None:
        super().__init__()
        # Operate directly on the passed policy so caller code can
        # observe the live edits if desired. ``ModalScreen.dismiss``
        # returns whatever ``handle_key`` produced through the screen
        # action handlers below.
        self._model = PlaygroundModel(policy=policy)

    # --- Textual lifecycle -------------------------------------------------

    def compose(self) -> ComposeResult:
        with Vertical(id="playground-dialog"):
            yield Static("Playground - full policy editor", id="playground-title")
            with Horizontal(id="playground-body"):
                yield Static(self._render_nav(), id="playground-nav")
                yield Static(self._render_detail(), id="playground-detail")
            yield Static(self._render_footer(), id="playground-footer")

    def on_key(self, event: events.Key) -> None:
        key = event.key
        # Modal-level shortcuts not delegated to the model:
        if key == "j" and self._is_section_nav_axis(event):
            self._model.next_section()
            event.stop()
            self._refresh_views()
            return
        if key == "k" and self._is_section_nav_axis(event):
            self._model.prev_section()
            event.stop()
            self._refresh_views()
            return

        # Pass alphanumerics + named keys through to the model. We
        # rebind the printable character so ``+`` / ``-`` / etc.
        # arrive verbatim (Textual surfaces those as ``"plus"`` /
        # ``"minus"`` otherwise, which would force every section to
        # carry a translation table).
        translated = key
        if event.character and len(event.character) == 1 and key not in {
            "enter",
            "tab",
            "escape",
        }:
            translated = event.character

        message = self._model.handle_key(translated)
        if message or translated in {"p", "d", "[", "]", "tab", "shift+tab"}:
            event.stop()
            self._refresh_views()

    # --- key-routing helpers ---------------------------------------------

    def _is_section_nav_axis(self, event: events.Key) -> bool:
        """Return True when j/k should step between sections rather
        than move within the active section's editor.

        On the severity-matrix section we want j/k to walk severity
        rows; on every other section, j/k walks the section list.
        Passing the keys through to the model when we're on
        severity-matrix lets ``_handle_severity_matrix`` consume them.
        """

        return self._model.section.id != "severity-matrix"

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_save_policy(self) -> None:
        if not self._model.is_savable():
            return
        self.dismiss(self._model.save_payload())

    def action_open_command_palette(self) -> None:
        """Push the Ctrl+K palette and route the resulting Command
        through ``_run_command``.

        We do not block the UI: the palette returns via callback
        which calls back into us once the operator picks something
        (or dismisses with Esc).
        """

        self.app.push_screen(CommandPaletteScreen(), self._on_palette_closed)

    def action_run_rego_lint(self) -> None:
        """Run the lint pass against ``policy.custom_rego`` snippets
        and pin the rendered findings into ``last_message`` so the
        footer surfaces them.
        """

        self._run_rego_lint()

    def _on_palette_closed(self, command: Command | None) -> None:
        if command is None:
            self._refresh_views()
            return
        self._run_command(command)

    def _run_command(self, command: Command) -> None:
        kind = command.kind
        if kind == "jump":
            if self._model.jump_to_section(command.target):
                self._model.last_message = f"jumped to {command.target}"
        elif kind == "toggle":
            if command.target == "test":
                self._model.test_pane_open = not self._model.test_pane_open
                self._model.last_message = (
                    f"live test {'on' if self._model.test_pane_open else 'off'}"
                )
            elif command.target == "diff":
                self._model.diff_open = not self._model.diff_open
                self._model.last_message = (
                    f"diff {'shown' if self._model.diff_open else 'hidden'}"
                )
        elif kind == "diff":
            self._model.diff_open = True
            self._model.last_message = "diff panel forced on"
        elif kind == "lint":
            self._run_rego_lint()
        elif kind == "emit-yaml":
            try:
                yaml_text = policy_to_gateway_yaml(self._model.policy)
            except Exception as exc:  # pragma: no cover - defensive
                self._model.last_message = f"emit failed: {exc}"
            else:
                first_line = yaml_text.splitlines()[0] if yaml_text else "(empty)"
                self._model.last_message = (
                    f"YAML emitted ({len(yaml_text)} chars) - first line: {first_line}"
                )
        elif kind == "emit-script":
            try:
                script = emit_install_script(self._model.policy)
            except Exception as exc:  # pragma: no cover - defensive
                self._model.last_message = f"emit-script failed: {exc}"
            else:
                self._model.last_message = (
                    f"install script emitted ({len(script)} chars)"
                )
        elif kind == "save":
            self.action_save_policy()
            return
        elif kind == "cancel":
            self.action_cancel()
            return
        self._refresh_views()

    def _run_rego_lint(self) -> str:
        """Run the rego linter and stash a one-line summary into
        ``last_message``. Returns the same summary string for callers
        that want to assert on it (tests, palette).
        """

        snippets = self._model.policy.custom_rego or []
        if not snippets:
            summary = "rego lint: no custom_rego snippets"
            self._model.last_message = summary
            self._refresh_views()
            return summary
        total_issues = 0
        blocking = 0
        for snippet in snippets:
            issues = lint_rego(snippet.source or "")
            total_issues += len(issues)
            if has_blocking_errors(issues):
                blocking += 1
        if blocking:
            summary = (
                f"rego lint: {blocking} snippet(s) with blocking error(s); "
                f"{total_issues} total finding(s)"
            )
        elif total_issues:
            summary = (
                f"rego lint: {total_issues} advisory finding(s) across "
                f"{len(snippets)} snippet(s)"
            )
        else:
            summary = f"rego lint: {len(snippets)} snippet(s) clean"
        self._model.last_message = summary
        self._refresh_views()
        return summary

    def _refresh_views(self) -> None:
        self.query_one("#playground-nav", Static).update(self._render_nav())
        self.query_one("#playground-detail", Static).update(self._render_detail())
        self.query_one("#playground-footer", Static).update(self._render_footer())

    # --- rendering ---------------------------------------------------------

    def _render_nav(self) -> Text:
        out = Text()
        for i, sec in enumerate(SECTION_DEFS):
            status = self._model.status_for(i)
            glyph = _STATUS_GLYPH[status]
            cursor = ">" if i == self._model.section_idx else " "
            line_style = "bold" if i == self._model.section_idx else ""
            badge_style = self._badge_style(status)
            out.append(f" {cursor} ", style=line_style)
            out.append(f"({glyph}) ", style=badge_style)
            out.append(f"{rich_escape(sec.title)}\n", style=line_style)
            subtitle = self._model.subtitle_for(i)
            out.append(f"     {rich_escape(subtitle)}\n", style="dim")
        return out

    def _badge_style(self, status: SectionStatus) -> str:
        if status == "warning":
            return DEFAULT_TOKENS.accent_amber
        if status == "customized":
            return DEFAULT_TOKENS.accent_cyan
        return "dim"

    def _render_detail(self) -> Text:
        section_id = self._model.section.id
        renderer = _SECTION_RENDERERS.get(section_id, _render_unknown)
        body = renderer(self._model)
        if self._model.diff_open:
            body.append("\n\n")
            body.append(self._render_diff_panel())
        if self._model.test_pane_open:
            body.append("\n\n")
            body.append(self._render_test_pane())
        return body

    def _render_diff_panel(self) -> Text:
        out = Text()
        entries = self._model.diff()
        out.append("Diff vs preset:\n", style="bold")
        if not entries:
            out.append("  (no overrides yet - everything matches the preset)\n", style="dim")
            return out
        for line in render_diff_lines(entries):
            out.append(f"  {rich_escape(line)}\n")
        return out

    def _render_test_pane(self) -> Text:
        out = Text()
        out.append("Live test pane:\n", style="bold")
        out.append(
            "  Press X to run the bundled scenarios against ``opa eval`` "
            "(requires the ``opa`` binary in PATH).\n",
            style="dim",
        )
        out.append(
            "  See cli/defenseclaw/tui/creator/scenarios.py for the "
            "scenario catalogue.\n",
            style="dim",
        )
        return out

    def _render_footer(self) -> Text:
        out = Text()
        section_id = self._model.section.id
        out.append(
            f"Section {self._model.section_idx + 1}/{len(SECTION_DEFS)} | "
            f"{rich_escape(section_id)}",
            style=f"bold {DEFAULT_TOKENS.accent_cyan}",
        )
        hints = ["[ / ] section", "p test", "d diff", "ctrl+k cmd", "ctrl+l lint"]
        if self._model.is_savable():
            hints.append("ctrl+s save")
        hints.append("esc cancel")
        out.append("   " + "   ".join(hints), style="dim")
        summary = self._model.summary()
        if summary.errors or summary.warnings:
            out.append("\nValidation: ", style="dim")
            if summary.errors:
                out.append(
                    f"{summary.errors} error(s) ",
                    style=f"bold {DEFAULT_TOKENS.accent_red}",
                )
            if summary.warnings:
                out.append(
                    f"{summary.warnings} warning(s) ",
                    style=DEFAULT_TOKENS.accent_amber,
                )
        if self._model.last_message:
            out.append("\n")
            out.append(rich_escape(self._model.last_message), style="dim")
        return out


# --- per-section detail renderers ------------------------------------------


def _render_basics(model: PlaygroundModel) -> Text:
    out = Text()
    p = model.policy
    out.append("Basics\n\n", style="bold")
    out.append("  name        ", style="dim")
    out.append(f"{rich_escape(p.name or '(unset)')}\n")
    out.append("  description ", style="dim")
    out.append(f"{rich_escape(p.description or '(none)')}\n")
    out.append("  basedOn     ", style="dim")
    out.append(f"{p.basedOn}\n", style="bold")
    out.append("\n  Press + to cycle preset (default / strict / permissive)\n", style="dim")
    return out


def _render_severity_matrix(model: PlaygroundModel) -> Text:
    out = Text()
    out.append("Severity matrix\n\n", style="bold")
    out.append("  axis: ", style="dim")
    if model.scanner_axis == 0:
        out.append("skill_actions ", style="bold")
    else:
        out.append(f"scanner_overrides.{SCANNER_TYPES[model.scanner_axis - 1]} ")
    out.append("(h/l to switch axis)\n\n", style="dim")
    out.append(f"  {'severity':<10}{'runtime':<12}{'file':<14}{'install':<10}\n", style="dim")
    for i, sev in enumerate(SEVERITIES):
        cursor = ">" if i == model.severity_cursor else " "
        triple = model._matrix_cell(sev)  # type: ignore[arg-type]
        line_style = "bold" if i == model.severity_cursor else ""
        out.append(f" {cursor} ", style=line_style)
        out.append(f"{sev:<10}", style=line_style)
        out.append(f"{triple.runtime:<12}", style=line_style)
        out.append(f"{triple.file:<14}", style=line_style)
        out.append(f"{triple.install:<10}\n", style=line_style)
    out.append(
        "\n  j/k row | h/l axis | space cycle runtime | f cycle file | i cycle install\n",
        style="dim",
    )
    return out


def _render_admission(model: PlaygroundModel) -> Text:
    out = Text()
    p = model.policy
    out.append("Admission\n\n", style="bold")
    out.append(f"  scan_on_install        {_bool_label(p.admission.scan_on_install)}\n")
    out.append(
        f"  allow_list_bypass_scan {_bool_label(p.admission.allow_list_bypass_scan)}\n"
    )
    out.append(f"\n  first_party_allow_list ({len(p.first_party_allow_list)}):\n", style="dim")
    if not p.first_party_allow_list:
        out.append("    (none)\n", style="dim")
    else:
        for i, entry in enumerate(p.first_party_allow_list):
            cursor = ">" if i == model.allowlist_cursor else " "
            line_style = "bold" if i == model.allowlist_cursor else ""
            out.append(f" {cursor} ", style=line_style)
            out.append(
                f"{entry.target_type}:{rich_escape(entry.target_name)}",
                style=line_style,
            )
            if entry.reason:
                out.append(f" - {rich_escape(entry.reason)}\n", style="dim")
            else:
                out.append("\n", style=line_style)
    out.append("\n  s toggle scan_on_install | b toggle bypass | x remove entry\n", style="dim")
    return out


def _render_guardrail(model: PlaygroundModel) -> Text:
    out = Text()
    g = model.policy.guardrail
    out.append("Guardrail\n\n", style="bold")
    out.append(f"  block_threshold     {g.block_threshold}/4   (+/- to adjust)\n")
    out.append(f"  alert_threshold     {g.alert_threshold}/4   (shift+up/down)\n")
    out.append(f"  hilt.enabled        {_bool_label(g.hilt.enabled)}   (h to toggle)\n")
    out.append(f"  hilt.min_severity   {g.hilt.min_severity}\n")
    out.append(f"  cisco_trust_level   {g.cisco_trust_level}   (t to cycle)\n")
    out.append(f"\n  patterns ({len(g.patterns)} categories):\n", style="dim")
    if not g.patterns:
        out.append("    (none - bundled defaults will load on save)\n", style="dim")
    else:
        for cat, patterns in list(g.patterns.items())[:6]:
            out.append(f"    {cat}: {len(patterns)} pattern(s)\n", style="dim")
        if len(g.patterns) > 6:
            out.append(
                f"    ... +{len(g.patterns) - 6} more\n", style="dim"
            )
    return out


def _render_rules(model: PlaygroundModel) -> Text:
    out = Text()
    rp = model.policy.rule_pack
    out.append("Rule pack\n\n", style="bold")
    out.append(f"  pack: {rich_escape(rp.name or '(unnamed)')}\n")
    out.append(f"  files: {len(rp.files)}\n")
    if rp.files:
        for f in rp.files[:8]:
            out.append(
                f"    {rich_escape(f.filename)}  category={rich_escape(f.category)}  "
                f"rules={len(f.rules)}\n",
                style="dim",
            )
        if len(rp.files) > 8:
            out.append(f"    ... +{len(rp.files) - 8} more\n", style="dim")
    out.append(
        "\n  Per-rule editing is read-only in this build; use "
        "``defenseclaw policy edit`` to author rule files via $EDITOR.\n",
        style="dim",
    )
    return out


def _render_suppressions(model: PlaygroundModel) -> Text:
    out = Text()
    s = model.policy.suppressions
    out.append("Suppressions\n\n", style="bold")
    out.append(f"  pre_judge_strips     {len(s.pre_judge_strips)}\n")
    out.append(f"  finding_suppressions {len(s.finding_suppressions)}\n")
    out.append(f"  tool_suppressions    {len(s.tool_suppressions)}\n")
    if s.pre_judge_strips:
        out.append("\n  Pre-judge strips (top 3):\n", style="dim")
        for strip in s.pre_judge_strips[:3]:
            out.append(
                f"    {rich_escape(strip.id)}: pattern={rich_escape(strip.pattern)}\n",
                style="dim",
            )
    if s.tool_suppressions:
        out.append("\n  Tool suppressions (top 3):\n", style="dim")
        for tsupp in s.tool_suppressions[:3]:
            out.append(
                f"    tool={rich_escape(tsupp.tool_pattern)}  "
                f"findings={len(tsupp.suppress_findings)}\n",
                style="dim",
            )
    out.append("\n  Edit suppressions via the bundled YAML for now.\n", style="dim")
    return out


def _render_sensitive_tools(model: PlaygroundModel) -> Text:
    out = Text()
    out.append("Sensitive tools\n\n", style="bold")
    if not model.policy.sensitive_tools:
        out.append("  (none)\n", style="dim")
    else:
        out.append(f"  {'tool':<28}{'inspect':<10}{'judge':<10}{'min entities':<12}\n", style="dim")
        for tool in model.policy.sensitive_tools:
            out.append(
                f"  {rich_escape(tool.name):<28}"
                f"{_bool_label(tool.result_inspection):<10}"
                f"{_bool_label(tool.judge_result):<10}"
                f"{tool.min_entities_for_alert if tool.min_entities_for_alert is not None else '-':<12}\n"
            )
    return out


def _render_judges(model: PlaygroundModel) -> Text:
    out = Text()
    out.append("LLM judges\n\n", style="bold")
    if not model.policy.judges:
        out.append("  (no judges configured)\n", style="dim")
        return out
    for judge in model.policy.judges:
        out.append(
            f"  {rich_escape(judge.name)}  enabled={_bool_label(judge.enabled)}  "
            f"categories={len(judge.categories)}\n"
        )
    return out


def _render_correlator(model: PlaygroundModel) -> Text:
    out = Text()
    out.append("Session correlator (Layer 5)\n\n", style="bold")
    if not model.policy.correlator:
        out.append("  (no patterns loaded - bundled defaults activate on save)\n", style="dim")
        return out
    for pattern in model.policy.correlator[:8]:
        marker = "*" if pattern.enabled else "."
        out.append(
            f"  ({marker}) {rich_escape(pattern.id):<28}  "
            f"window={pattern.window_events}  "
            f"sev={pattern.severity_on_match}\n"
        )
    if len(model.policy.correlator) > 8:
        out.append(f"  ... +{len(model.policy.correlator) - 8} more\n", style="dim")
    out.append("\n  space toggles the first pattern's ``enabled`` flag\n", style="dim")
    return out


def _render_firewall(model: PlaygroundModel) -> Text:
    out = Text()
    f = model.policy.firewall
    out.append("Firewall\n\n", style="bold")
    out.append(f"  default_action       {f.default_action}   (space to cycle)\n")
    out.append(f"  blocked_destinations {len(f.blocked_destinations)} entries\n")
    out.append(f"  allowed_domains      {len(f.allowed_domains)} entries\n")
    out.append(f"  allowed_ports        {len(f.allowed_ports)} entries\n")
    if f.blocked_destinations:
        out.append("\n  Blocked (top 3):\n", style="dim")
        for dest in f.blocked_destinations[:3]:
            out.append(f"    {rich_escape(dest)}\n", style="dim")
    if f.allowed_domains:
        out.append("\n  Allowed domains (top 3):\n", style="dim")
        for domain in f.allowed_domains[:3]:
            out.append(f"    {rich_escape(domain)}\n", style="dim")
    return out


def _render_webhooks(model: PlaygroundModel) -> Text:
    out = Text()
    out.append("Webhooks\n\n", style="bold")
    if not model.policy.webhooks:
        out.append("  (no destinations configured)\n", style="dim")
        out.append(
            "\n  Add via ``defenseclaw policy edit`` for now; live add "
            "lands in the next iteration.\n",
            style="dim",
        )
        return out
    out.append(f"  {'#':<3}{'type':<10}{'min sev':<10}{'url':<40}{'env':<14}\n", style="dim")
    for i, hook in enumerate(model.policy.webhooks):
        cursor = ">" if i == model.webhook_cursor else " "
        line_style = "bold" if i == model.webhook_cursor else ""
        out.append(f" {cursor}", style=line_style)
        out.append(f"{i:<3}", style=line_style)
        out.append(f"{hook.type:<10}", style=line_style)
        out.append(f"{hook.min_severity:<10}", style=line_style)
        out.append(f"{rich_escape(hook.url[:38]):<40}", style=line_style)
        out.append(f"{rich_escape(hook.secret_env):<14}\n", style=line_style)
    out.append("\n  j/k navigate | x remove\n", style="dim")
    return out


def _render_watch(model: PlaygroundModel) -> Text:
    out = Text()
    w = model.policy.watch
    out.append("Watch (rescan)\n\n", style="bold")
    out.append(f"  rescan_enabled       {_bool_label(w.rescan_enabled)}   (space toggle)\n")
    out.append(f"  rescan_interval_min  {w.rescan_interval_min}   (+/- adjust)\n")
    return out


def _render_enforcement(model: PlaygroundModel) -> Text:
    out = Text()
    e = model.policy.enforcement
    out.append("Enforcement\n\n", style="bold")
    out.append(
        f"  max_enforcement_delay_seconds  {e.max_enforcement_delay_seconds}   (+/- adjust)\n"
    )
    return out


def _render_audit(model: PlaygroundModel) -> Text:
    out = Text()
    a = model.policy.audit
    out.append("Audit\n\n", style="bold")
    out.append(f"  log_all_actions   {_bool_label(a.log_all_actions)}   (a toggle)\n")
    out.append(f"  log_scan_results  {_bool_label(a.log_scan_results)}  (s toggle)\n")
    out.append(f"  retention_days    {a.retention_days}   (+/- by 7)\n")
    return out


def _render_scanners(model: PlaygroundModel) -> Text:
    out = Text()
    s = model.policy.scanners
    out.append("Scanner profiles\n\n", style="bold")
    out.append(f"  codeguard       {rich_escape(s.codeguard or '(inherit)')}\n")
    out.append(f"  plugin-scanner  {rich_escape(s.plugin_scanner or '(inherit)')}\n")
    out.append(f"  skill-scanner   {rich_escape(s.skill_scanner or '(inherit)')}\n")
    out.append(
        "\n  Override profile names via ``defenseclaw policy edit`` for now.\n",
        style="dim",
    )
    return out


def _render_cisco_ai_defense(model: PlaygroundModel) -> Text:
    out = Text()
    aid = model.policy.cisco_ai_defense
    out.append("Cisco AI Defense (Optional)\n\n", style="bold")
    out.append(f"  enabled            {_bool_label(aid.enabled)}   (space toggle)\n")
    out.append(f"  endpoint           {rich_escape(aid.endpoint or '(unset)')}\n")
    out.append(f"  api_key_env        {rich_escape(aid.api_key_env or '(unset)')}\n")
    out.append(
        f"  scan_hook_surface  {_bool_label(aid.scan_hook_surface)}  (h toggle)\n"
    )
    if aid.enabled and not aid.api_key_env:
        out.append(
            "\n  WARNING: enabled without ``api_key_env`` - the lane will fail closed.\n",
            style=DEFAULT_TOKENS.accent_amber,
        )
    return out


def _render_custom_rego(model: PlaygroundModel) -> Text:
    out = Text()
    out.append("Custom Rego\n\n", style="bold")
    if not model.policy.custom_rego:
        out.append("  (no snippets)\n", style="dim")
        out.append(
            "\n  Drop a ``.rego`` file under "
            "~/.defenseclaw/policies/<pack>/rego/ or run ``defenseclaw "
            "policy edit`` to author one in $EDITOR. The Playground "
            "lints the bundle on demand via Ctrl+L.\n",
            style="dim",
        )
        return out
    for snippet in model.policy.custom_rego[:6]:
        issues = lint_rego(snippet.source or "")
        marker_style = (
            DEFAULT_TOKENS.accent_red
            if has_blocking_errors(issues)
            else (DEFAULT_TOKENS.accent_amber if issues else "dim")
        )
        marker = "!" if has_blocking_errors(issues) else ("?" if issues else "*")
        out.append(f"  ({marker}) ", style=marker_style)
        out.append(f"{rich_escape(snippet.name)}", style="bold")
        out.append(f"  package={rich_escape(snippet.package)}\n")
        if issues:
            for line in render_issues(issues)[:4]:
                out.append(f"      {rich_escape(line)}\n", style="dim")
            if len(issues) > 4:
                out.append(
                    f"      ... +{len(issues) - 4} more (Ctrl+L for full)\n",
                    style="dim",
                )
    if len(model.policy.custom_rego) > 6:
        out.append(
            f"  ... +{len(model.policy.custom_rego) - 6} more\n", style="dim"
        )
    out.append(
        "\n  Ctrl+L runs the full lint pass; legend: (*) clean (?) advisory (!) blocking\n",
        style="dim",
    )
    return out


def _render_review(model: PlaygroundModel) -> Text:
    out = Text()
    out.append("Review and save\n\n", style="bold")
    summary = model.summary()
    out.append(f"  validation: {summary.errors} error(s), {summary.warnings} warning(s)\n")
    if summary.errors:
        out.append("  Save is blocked until errors clear.\n", style=DEFAULT_TOKENS.accent_red)
    else:
        out.append("  Press Ctrl+S to save.\n", style=DEFAULT_TOKENS.accent_cyan)

    out.append("\n  Generated YAML preview (first 30 lines):\n", style="dim")
    try:
        yaml_text = policy_to_gateway_yaml(model.policy)
    except Exception as exc:  # pragma: no cover - defensive
        out.append(f"  emit failed: {exc}\n", style=DEFAULT_TOKENS.accent_red)
        return out
    for line in yaml_text.splitlines()[:30]:
        out.append(f"    {rich_escape(line)}\n", style="dim")
    return out


def _render_unknown(model: PlaygroundModel) -> Text:
    out = Text()
    out.append(
        f"unknown section: {rich_escape(model.section.id)}\n",
        style=DEFAULT_TOKENS.accent_red,
    )
    return out


def _bool_label(value: bool) -> str:
    return "true" if value else "false"


_SECTION_RENDERERS = {
    "basics": _render_basics,
    "severity-matrix": _render_severity_matrix,
    "admission": _render_admission,
    "guardrail": _render_guardrail,
    "rules": _render_rules,
    "suppressions": _render_suppressions,
    "sensitive-tools": _render_sensitive_tools,
    "judges": _render_judges,
    "correlator": _render_correlator,
    "firewall": _render_firewall,
    "webhooks": _render_webhooks,
    "watch": _render_watch,
    "enforcement": _render_enforcement,
    "audit": _render_audit,
    "scanners": _render_scanners,
    "cisco-ai-defense": _render_cisco_ai_defense,
    "custom-rego": _render_custom_rego,
    "review": _render_review,
}
