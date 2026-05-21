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
    """Build the parity status-strip segments for shell state."""

    alert_state = "error" if model.active_alerts > 0 else "running"
    segments = [
        StatusSegment.from_service(model.gateway),
        StatusSegment.from_service(model.watchdog),
        StatusSegment.from_service(model.guardrail),
        StatusSegment(f"{model.active_alerts} alerts", alert_state),
    ]
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
