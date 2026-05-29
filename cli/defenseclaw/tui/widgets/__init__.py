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

"""Reusable widgets for the Python Textual TUI migration."""

from defenseclaw.tui.widgets.hint_bar import DEFAULT_HINTS, HintBar, HintEngine
from defenseclaw.tui.widgets.status_strip import StatusSegment, StatusStrip, render_status_strip, status_segments

__all__ = [
    "DEFAULT_HINTS",
    "HintBar",
    "HintEngine",
    "StatusSegment",
    "StatusStrip",
    "render_status_strip",
    "status_segments",
]
