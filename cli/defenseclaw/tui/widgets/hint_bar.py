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
        if panel == "runtime":
            return self._runtime_hint(state)
        if panel == "sandboxes":
            from defenseclaw.tui.services.sandbox_state import sandbox_keys_hint

            return state.panel_keys or sandbox_keys_hint(
                state.panel_view or "sandboxes", has_rows=state.panel_has_rows
            )
        if panel == "policies":
            from defenseclaw.platform_support import openshell_sandboxes_supported
            from defenseclaw.tui.services.policy_state import policies_keys_hint

            return policies_keys_hint(
                state.panel_view or "policies",
                sandbox_supported=openshell_sandboxes_supported(),
            )
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
        # Prefer the explicit ``missing_keys`` field, set by
        # ``_hint_status_model`` from the live credential snapshot.
        # The previous fallback string-matched on Guardrail's detail
        # to detect missing creds, which (a) lit Guardrail red even
        # though the guardrail subsystem itself was running, and
        # (b) silently broke whenever Guardrail switched to the new
        # dedicated Keys pill. ``missing_keys`` is the source of
        # truth; the legacy string-match remains as a fallback for
        # callers that haven't been updated yet.
        if status.missing_keys:
            return (
                "Required API keys missing: select API keys & secrets, press f to fill missing."
            )
        segments = (status.gateway, status.watchdog, status.guardrail)
        for segment in segments:
            text = f"{segment.state} {segment.detail}".lower()
            has_missing = "missing" in text or "not configured" in text
            has_secret = any(token in text for token in ("credential", "api key", "key", "token", "secret"))
            if has_missing and has_secret:
                return (
                    "Required API keys missing: select API keys & secrets, press f to fill missing."
                )
        return ""

    def _overview_hint(self, state: HintState, status: StatusModel | None) -> str:
        if state.not_configured:
            return "DefenseClaw is not set up yet. Press 0 for Setup, or run: defenseclaw init"
        if status:
            gateway_state = status.gateway.state.strip().lower()
            if gateway_state in {"starting", "reconnecting"}:
                return "Gateway is starting. Health checks will retry automatically."
            if gateway_state in {"error", "failed"}:
                detail = status.gateway.detail.strip()
                if "authentication" in detail.lower() or "token" in detail.lower():
                    return "Gateway authentication error. Check the configured sidecar API token."
                if "config" in detail.lower() or "port" in detail.lower():
                    return "Gateway configuration error. Check the sidecar API bind, port, and token."
                return "Gateway health check failed. Open the command palette and run doctor to diagnose."
            if gateway_state in {"", "unknown"}:
                return "Gateway status is not available yet. Health checks will retry automatically."
            if gateway_state in {"offline", "stopped", "down"}:
                return 'Gateway is not running. Press : and run "start", or run "doctor" to diagnose.'
        if status and status.guardrail.state in {"disabled", "offline", "unknown"}:
            return 'LLM guardrail is not configured. Press "g" to set it up.'
        if state.critical_alerts > 0:
            noun = "event" if state.critical_alerts == 1 else "events"
            verb = "needs" if state.critical_alerts == 1 else "need"
            return (
                f"{state.critical_alerts} recent critical/high alert {noun} {verb} review. "
                "Press 2 for Alerts."
            )
        if state.hidden_critical_alerts > 0 and state.connector_filter:
            # Alerts would open empty under the filter; say how to see them.
            count = state.hidden_critical_alerts
            noun = "alert" if count == 1 else "alerts"
            return (
                f"{count} critical/high {noun} outside the {state.connector_filter} filter. "
                "Press m and pick All connectors, then 2 for Alerts."
            )
        if state.unscanned_skills > 0:
            return f"{state.unscanned_skills} skills have not been scanned. Press s to scan all."
        return self.next_tip()

    def _alerts_hint(self, state: HintState) -> str:
        if state.total_alerts == 0:
            return "No active alerts. DefenseClaw is monitoring for scan findings."
        if state.filter_active == "All severities":
            # All is not a filter; name the way back to the default queue (GAP-1875).
            return "Showing alerts of all severities. Press h or Esc for Actionable; / searches."
        if state.filter_active:
            return f"Alerts filtered to {state.filter_active}. Click All or press Esc to clear; / changes search."
        if state.critical_alerts > 0:
            scope = f" for {state.connector_filter}" if state.connector_filter else ""
            return (
                f"{state.critical_alerts} critical/high alert(s){scope}. Click severity chips or press h/l, "
                "Enter opens details, Dismiss filtered clears the view."
            )
        return (
            "KEYS  j/k move | Enter detail | h/l severity | Space select | x ack selected | "
            "d dismiss | c dismiss filtered | / search."
        )

    def _audit_hint(self, state: HintState) -> str:
        if state.filter_active:
            return (
                f"Audit filtered to {state.filter_active}. Click All or press Esc to clear; "
                "Same target/run correlates rows."
            )
        return (
            "KEYS  j/k move | Enter detail | h/l filter chips | / search field:value | "
            "t same target | u same run | e export | Esc close."
        )

    def _skills_hint(self, state: HintState) -> str:
        if hint := self._filter_hint(state):
            return hint
        if state.unscanned_skills > 0:
            return (
                f'{state.unscanned_skills} skills unscanned. Press "s" on a skill, '
                'or : scan skill --all. Press "u" to unblock a blocked skill.'
            )
        return (
            "KEYS  j/k move | Enter detail | o actions | s scan | b block | "
            "a allow | u unblock | R registries | r refresh | / filter."
        )

    def _mcps_hint(self, state: HintState) -> str:
        if hint := self._filter_hint(state):
            return hint
        return (
            "KEYS  j/k move | Enter detail | o actions | s scan | b block | "
            "a allow | u unblock | n add server | R registries."
        )

    def _plugins_hint(self, state: HintState) -> str:
        if hint := self._filter_hint(state):
            return hint
        return (
            "KEYS  j/k move | Enter detail | o actions | s scan | b block | a allow | u unblock | "
            "r refresh | / filter | : plugin install <name>."
        )

    def _inventory_hint(self, state: HintState) -> str:
        if hint := self._filter_hint(state):
            return hint
        return (
            "KEYS  h/l sub-tab | j/k move | Enter detail | 1-4 filter (Skills/Plugins only) | "
            "o fast scan scope | r scan."
        )

    def _logs_hint(self, state: HintState) -> str:
        if state.logs_paused:
            return f"Paused. Space resumes. New lines since pause: +{state.new_lines_since_pause}."
        return (
            "KEYS  h/l source | 1-8 filter | Space pause | / search | e errors | w warnings | "
            "Enter detail | g/G top/end."
        )

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
        return (
            "KEYS  j/k move | t switch table | a all models | Enter detail | s scan | r refresh | "
            "/ search vendor/product/component."
        )

    def _registries_hint(self, state: HintState) -> str:
        if hint := self._filter_hint(state):
            return hint
        return (
            "KEYS  h/l sources/entries/approved | j/k move | Enter detail | s sync | S sync all | "
            "a approve | x reject | e require approval | d remove source."
        )

    def _runtime_hint(self, state: HintState) -> str:
        return (
            "KEYS  j/k move | Enter finding | / filter | e enable | s poll now | r refresh | "
            "p planes detail."
        )

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
        from defenseclaw.tui.panels.setup_keys import SETUP_VIEWS, keys_hint

        view = state.panel_view if state.panel_view in SETUP_VIEWS else "wizards"
        # The missing-keys nudge belongs on the task list, not inside a form.
        if view == "wizards" and (hint := self._missing_credentials_hint(status)):
            return hint
        return keys_hint(view, state.panel_conditions)

    def _first_run_hint(self, state: HintState, status: StatusModel | None) -> str:
        if self._command_running(state, status):
            return "First-run setup is applying. Press Ctrl+C to cancel. Output streams in Activity."
        from defenseclaw.tui.panels.setup_keys import keys_hint

        return keys_hint("first-run")


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
        self._rendered_hint: str | None = None
        self.refresh_hint(HintState())

    def refresh_hint(self, state: HintState, status: StatusModel | None = None) -> None:
        hint = self.engine.hint_for(state, status)
        if hint == self._rendered_hint:
            return
        self._rendered_hint = hint
        self._paint()

    def on_resize(self, _event: object) -> None:
        self._paint()

    def _paint(self) -> None:
        try:  # 0 before the bar is laid out: paint the hint as is.
            width = int(self.content_size.width)
        except Exception:  # noqa: BLE001 - no app or layout yet.
            width = 0
        self.update(pack_hint_items(self._rendered_hint or "", width, max_lines=2))


def pack_hint_items(hint: str, width: int, *, max_lines: int = 2) -> str:
    """Break a ``key label · key label`` hint between items, never inside one.

    Word wrap split "r refresh keys" over two rows at 80 columns (GAP-1912).
    Items that don't fit in ``max_lines`` rows are dropped whole. Plain
    sentences, and any hint that fits, are left to the normal wrap.
    """

    from rich.cells import cell_len

    if width <= 0 or cell_len(hint) <= width or " · " not in hint:
        return hint
    lines: list[str] = []
    line = ""
    for item in hint.split(" · "):
        joined = f"{line} · {item}" if line else item
        if not line or cell_len(joined) <= width:
            line = joined
            continue
        lines.append(line)
        line = item
    lines.append(line)
    return "\n".join(lines[:max_lines])
