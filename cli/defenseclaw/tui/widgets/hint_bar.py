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

"""Contextual hint helpers for early Textual panels."""

from __future__ import annotations

from defenseclaw.tui.models import HintState, StatusModel

try:  # pragma: no cover - exercised when Textual is installed.
    from textual.widgets import Static as _Static
except ImportError:  # pragma: no cover - keeps the package importable pre-dependency.

    class _Static:  # type: ignore[no-redef]
        DEFAULT_CSS = ""

        def __init__(self, *args: object, **kwargs: object) -> None:
            self.content = ""

        def update(self, content: str) -> None:
            self.content = content


DEFAULT_HINTS: tuple[str, ...] = (
    "Press Ctrl+K to open the command palette from anywhere.",
    "Use scan aibom to generate a component inventory of the active connector.",
    "Press / on lists to filter. Esc clears the active filter.",
    "Press ? for the full keybinding reference.",
)


class HintEngine:
    """Pure hint selector used by the hint bar and unit tests."""

    def __init__(self, rotating_hints: tuple[str, ...] = DEFAULT_HINTS) -> None:
        self.rotating_hints = rotating_hints
        self.tip_index = 0

    def next_tip(self) -> str:
        tip = self.rotating_hints[self.tip_index % len(self.rotating_hints)]
        self.tip_index += 1
        return tip

    def hint_for(self, state: HintState, status: StatusModel | None = None) -> str:
        panel = state.active_panel.strip().lower().replace("_", "-").replace(" ", "-")
        if panel == "overview":
            return self._overview_hint(state, status)
        if panel == "alerts":
            return self._alerts_hint(state)
        if panel == "skills":
            return self._skills_hint(state)
        if panel in {"mcp", "mcps"}:
            return self._mcps_hint(state)
        if panel == "plugins":
            return self._plugins_hint(state)
        if panel == "inventory":
            return self._inventory_hint(state)
        if panel == "policy":
            return self._policy_hint(state)
        if panel == "logs":
            return self._logs_hint(state)
        if panel == "audit":
            return self._audit_hint(state)
        if panel == "activity":
            return self._activity_hint(state)
        if panel in {"tool", "tools"}:
            return self._tools_hint(state)
        if panel in {"ai", "ai-discovery"}:
            return self._ai_discovery_hint(state)
        if panel in {"registry", "registries"}:
            return self._registries_hint(state)
        if panel == "setup":
            return self._setup_hint(state, status)
        if panel in {"first-run", "firstrun"}:
            return self._first_run_hint(state, status)
        if state.filter_active:
            return f"Filtered to: {state.filter_active}. Esc clears the filter, / changes it."
        return "KEYS  j/k move | Enter detail | o actions | r refresh | / filter | Esc close | Ctrl+K commands."

    def _filter_hint(self, state: HintState) -> str:
        if not state.filter_active:
            return ""
        return f"Filtered to: {state.filter_active}. Esc clears the filter, / changes it."

    def _command_running(self, state: HintState, status: StatusModel | None) -> bool:
        return state.command_running or bool(status and status.command_running)

    def _missing_credentials_hint(self, status: StatusModel | None) -> str:
        if status is None:
            return ""
        segments = (status.gateway, status.watchdog, status.guardrail)
        for segment in segments:
            text = f"{segment.state} {segment.detail}".lower()
            has_missing = "missing" in text or "not configured" in text
            has_secret = any(token in text for token in ("credential", "api key", "key", "token", "secret"))
            if has_missing and has_secret:
                return (
                    "Required credentials are missing. Open Credentials setup, press f to fill missing, or r refresh."
                )
        return ""

    def _overview_hint(self, state: HintState, status: StatusModel | None) -> str:
        if status and status.gateway.state != "running":
            return 'Gateway is offline. Open the command palette and run "doctor" to diagnose.'
        if status and status.guardrail.state in {"disabled", "offline", "unknown"}:
            return 'LLM guardrail is not configured. Press "g" to set it up.'
        if state.critical_alerts > 0:
            return f"{state.critical_alerts} critical alert(s) need attention. Press 2 for Alerts."
        if state.unscanned_skills > 0:
            return f"{state.unscanned_skills} skills have not been scanned. Press s to scan all."
        return self.next_tip()

    def _alerts_hint(self, state: HintState) -> str:
        if state.total_alerts == 0:
            return "No active alerts. DefenseClaw is monitoring for scan findings."
        if state.filter_active:
            return f"Alerts filtered to {state.filter_active}. Click All or press Esc to clear; / changes search."
        if state.critical_alerts > 0:
            return (
                f"{state.critical_alerts} critical/high alert(s). Click severity chips, "
                "Enter opens details, Dismiss filtered clears the view."
            )
        return (
            "KEYS  j/k move | Enter detail | click severity chips | Space select | "
            "x ack | c dismiss | / search | Esc close."
        )

    def _audit_hint(self, state: HintState) -> str:
        if state.filter_active:
            return (
                f"Audit filtered to {state.filter_active}. Click All or press Esc to clear; "
                "Same target/run correlates rows."
            )
        return (
            "KEYS  j/k move | Enter detail | click common filters | / search field:value | "
            "t same target | u same run | e export | Esc close."
        )

    def _skills_hint(self, state: HintState) -> str:
        if hint := self._filter_hint(state):
            return hint
        if state.unscanned_skills > 0:
            return f'{state.unscanned_skills} skills unscanned. Press "s" on a skill, or : scan skill --all.'
        return (
            "KEYS  j/k move | Enter detail | o actions | s scan | b block | "
            "a allow | R registries | r refresh | / filter."
        )

    def _mcps_hint(self, state: HintState) -> str:
        if hint := self._filter_hint(state):
            return hint
        return "KEYS  j/k move | Enter detail | o actions | s scan | b block | a allow | n add server | R registries."

    def _plugins_hint(self, state: HintState) -> str:
        if hint := self._filter_hint(state):
            return hint
        return "KEYS  j/k move | Enter detail | o actions | s scan | r refresh | / filter | : plugin install <name>."

    def _inventory_hint(self, state: HintState) -> str:
        if hint := self._filter_hint(state):
            return hint
        return "h/l switch sub-tabs · 1-4 filter active list · j/k scroll · Enter detail · o fast scope · r scan."

    def _policy_hint(self, state: HintState) -> str:
        if hint := self._filter_hint(state):
            return hint
        return "Tab or [] switch policy tabs · j/k nav · Enter detail · v validate · r reload · n new policy."

    def _logs_hint(self, state: HintState) -> str:
        if state.logs_paused:
            return f"Paused. Space resumes. New lines since pause: +{state.new_lines_since_pause}."
        return "Streaming live. Space pauses, / searches, e filters errors, w filters warnings."

    def _activity_hint(self, state: HintState) -> str:
        if state.command_running:
            return "Command running. Press Ctrl+C to cancel. Output streams here in real time."
        if state.commands_run == 0:
            return 'No commands run yet. Press : or Ctrl+K. Try "doctor" or "status".'
        return f"{state.commands_run} command(s) run this session. Press ! to rerun the last one."

    def _tools_hint(self, state: HintState) -> str:
        if hint := self._filter_hint(state):
            return hint
        return (
            "KEYS  j/k move | Enter detail | o actions (block/allow/unblock) | "
            "r refresh | / filter | : tool block <name>."
        )

    def _ai_discovery_hint(self, state: HintState) -> str:
        if hint := self._filter_hint(state):
            return hint
        return "KEYS  j/k move | Enter detail | s scan | r refresh | / search vendor/product/component."

    def _registries_hint(self, state: HintState) -> str:
        if hint := self._filter_hint(state):
            return hint
        return "1 sources · 2 entries · 3 approved · s sync source · S sync all · a approve · x reject."

    def _setup_hint(self, state: HintState, status: StatusModel | None) -> str:
        if self._command_running(state, status):
            label = state.command_label or "Setup command"
            elapsed = state.command_elapsed_secs
            # Setup runs the connector wizard with --verify on by default,
            # which sits in a 30-60s OpenClaw gateway probe. Show the
            # argv plus elapsed seconds so operators know the TUI hasn't
            # frozen — and remind them they can re-run with verify=no
            # from the wizard form to skip the probe next time.
            elapsed_str = f"  ({elapsed}s)" if elapsed else ""
            tail = (
                " · setup with verify probes the gateway for up to 60s · "
                "Ctrl+C to cancel · A for live output"
            )
            return f"⟳ {label}{elapsed_str}{tail}"
        if hint := self._missing_credentials_hint(status):
            return hint
        return "j/k or [] choose wizard · Enter opens form · backtick config editor · r credentials · G restart."

    def _first_run_hint(self, state: HintState, status: StatusModel | None) -> str:
        if self._command_running(state, status):
            return "First-run setup is applying. Press Ctrl+C to cancel. Output streams in Activity."
        if hint := self._missing_credentials_hint(status):
            return hint
        return "First-run setup: j/k choose field · h/l change value · Ctrl+R apply."


class HintBar(_Static):
    """Small Textual-compatible widget for contextual operator hints."""

    DEFAULT_CSS = """
    HintBar {
        height: 2;
        color: #E6F1FF;
        text-style: bold;
        background: #203251;
    }
    """

    def __init__(self, engine: HintEngine | None = None, **kwargs: object) -> None:
        # ``markup=False`` is critical: the hint engine produces plain
        # text strings that freely interpolate user filter values such
        # as ``target:[skill]``. With Rich markup parsing on, the next
        # render after a user types ``/skill`` would crash the whole
        # frame with ``MissingStyle: 'skill' is not a valid color``.
        # We don't paint any intentional styles in the hint bar — colors
        # come from the widget's CSS instead — so disabling markup is
        # purely defensive and lossless.
        kwargs.setdefault("markup", False)
        super().__init__(classes="dc-hint-bar", **kwargs)
        self.engine = engine or HintEngine()
        self.refresh_hint(HintState())

    def refresh_hint(self, state: HintState, status: StatusModel | None = None) -> None:
        self.update(self.engine.hint_for(state, status))
