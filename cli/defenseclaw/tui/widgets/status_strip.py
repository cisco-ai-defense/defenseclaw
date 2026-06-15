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

"""Status strip helpers for the initial Textual shell."""

from __future__ import annotations

from dataclasses import dataclass

from defenseclaw.tui.models import ServiceStatus, StatusModel
from defenseclaw.tui.theme import DEFAULT_TOKENS, ThemeTokens, state_color, state_dot

try:  # pragma: no cover - exercised when Textual is installed.
    from textual.widgets import Static as _Static
except ImportError:  # pragma: no cover - keeps the package importable pre-dependency.

    class _Static:  # type: ignore[no-redef]
        DEFAULT_CSS = ""

        def __init__(self, *args: object, **kwargs: object) -> None:
            self.content = ""

        def update(self, content: str) -> None:
            self.content = content


@dataclass(frozen=True)
class StatusSegment:
    """One rendered status-strip segment."""

    label: str
    state: str
    detail: str = ""

    @classmethod
    def from_service(cls, service: ServiceStatus) -> StatusSegment:
        return cls(label=service.label, state=service.state, detail=service.detail)

    def render(self, tokens: ThemeTokens = DEFAULT_TOKENS) -> str:
        label = self.label if not self.detail else f"{self.label} ({self.detail})"
        color = state_color(self.state, tokens)
        return f"[{color}]{state_dot(self.state)} {label}[/]"


def status_segments(model: StatusModel) -> list[StatusSegment]:
    """Build the status-strip segments for shell state.

    Ordered for at-a-glance scanning: subsystem health first
    (Gateway / Watchdog / Guardrail), then anything that needs
    operator attention (missing keys, alerts), then ambient context
    (connector, redaction posture, command counters, version).
    """

    segments: list[StatusSegment] = [
        StatusSegment.from_service(model.gateway),
        StatusSegment.from_service(model.watchdog),
        # Guardrail pill mirrors the SERVICES box in Overview — it
        # reports the live subsystem state, NOT a hijacked overlay
        # for missing credentials. Surfacing missing keys on the
        # Guardrail tile contradicted the Services box (Guardrail
        # could be running yet show red) and pointed operators at
        # the wrong subsystem.
        StatusSegment.from_service(model.guardrail),
    ]

    # Dedicated Keys pill: surfaces missing required credentials as
    # its own segment so the Guardrail tile stays honest.
    if model.missing_keys:
        preview = ", ".join(model.missing_keys[:2])
        suffix = f" (+{len(model.missing_keys) - 2} more)" if len(model.missing_keys) > 2 else ""
        segments.append(
            StatusSegment("Keys", "error", f"missing {preview}{suffix}")
        )

    alert_state = "error" if model.active_alerts > 0 else "running"
    segments.append(StatusSegment(f"{model.active_alerts} alerts", alert_state))

    # Ambient context — connector + redaction + counters help
    # operators answer "what am I actually working on?" without
    # context-switching to Overview.
    if model.connector:
        segments.append(StatusSegment(model.connector, "active"))
    if model.redaction_label:
        # Redaction OFF is a privacy posture the operator should
        # see at all times; ON renders green, OFF/RAW renders
        # warning so it's visually distinct without conflicting
        # with the alerts / Keys error states.
        red_state = "running" if model.redaction_on else "warning"
        segments.append(StatusSegment(model.redaction_label, red_state))
    if model.policy_posture:
        segments.append(StatusSegment(model.policy_posture, "active"))
    if model.commands_run:
        plural = "" if model.commands_run == 1 else "s"
        segments.append(
            StatusSegment(f"{model.commands_run} cmd{plural}", "disabled")
        )
    if model.command_running:
        segments.append(StatusSegment("running", "starting"))
    if model.is_stale:
        segments.append(StatusSegment("stale", "warning"))
    if not model.focused:
        segments.append(StatusSegment("unfocused", "disabled"))
    if model.version:
        segments.append(StatusSegment(f"v{model.version}", "disabled"))
    return segments


def render_status_strip(model: StatusModel, tokens: ThemeTokens = DEFAULT_TOKENS) -> str:
    """Render status-strip markup suitable for a Textual Static widget."""

    return "  [#444444]│[/]  ".join(segment.render(tokens) for segment in status_segments(model))


class StatusStrip(_Static):
    """Small Textual-compatible widget for top-level service status."""

    DEFAULT_CSS = """
    StatusStrip {
        height: 1;
        background: #121A2B;
        color: #9FB2CC;
    }
    """

    def __init__(
        self,
        model: StatusModel | None = None,
        *,
        tokens: ThemeTokens = DEFAULT_TOKENS,
        **kwargs: object,
    ) -> None:
        super().__init__(classes="dc-status-strip", **kwargs)
        self.tokens = tokens
        self.model = model or StatusModel()
        self.refresh_model(self.model)

    def refresh_model(self, model: StatusModel) -> None:
        self.model = model
        self.update(render_status_strip(model, self.tokens))
