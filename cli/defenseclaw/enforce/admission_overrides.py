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

"""The admission-action override line shared by ``defenseclaw status`` and the TUI Overview.

It lives outside the TUI package so ``status`` does not import the TUI
(about 45 ms and 14 modules) for one line of text.
"""

from __future__ import annotations


def admission_action_overrides(
    config: object | None,
) -> tuple[tuple[str, str, str, str], ...]:
    """Effective explicit admission actions that differ from built-in policy.

    Per-type actions win over scanner-derived skill actions, which win over
    admission.defaults.actions. Only effective differences are shown to the
    Overview and status views.
    """

    admission = getattr(config, "admission", None)
    if admission is None:
        return ()
    try:
        from defenseclaw.enforce.admission import (  # noqa: PLC0415
            _builtin_admission,
            _compile_action_map,
            _derived_scanner_gate,
        )
    except Exception:  # noqa: BLE001 - the override summary is purely informational.
        return ()
    defaults = _compile_action_map(getattr(getattr(admission, "defaults", None), "actions", None))
    flat: list[tuple[str, str, str, str]] = []
    for target_type in ("skill", "mcp", "plugin"):
        own = _compile_action_map(getattr(getattr(admission, target_type, None), "actions", None))
        derived = {}
        if target_type == "skill":
            scanner = getattr(getattr(config, "scanners", None), "skill_scanner", None)
            derived = _derived_scanner_gate(
                getattr(scanner, "fail_on_severity", ""), getattr(scanner, "review_queue_min", "")
            )
        builtin = _builtin_admission(target_type).actions
        for severity in dict.fromkeys((*own, *defaults)):
            if severity in own:
                compiled = own[severity]
            elif severity in derived:
                continue
            else:
                compiled = defaults[severity]
            if compiled == builtin.get(severity):
                continue
            action, allowed = compiled
            for surface in ("install", "file", "runtime"):
                flat.append((target_type, severity, surface, str(getattr(action, surface))))
            if allowed:
                flat.append((target_type, severity, "verdict", "allow"))
    return tuple(flat)


def format_scanner_overrides_summary(
    overrides: tuple[tuple[str, str, str, str], ...],
) -> str:
    """One-line summary of active-policy scanner action overrides (N3).

    ``overrides`` is the flattened ``(asset_type, severity, surface, action)``
    view of :func:`admission_action_overrides`. Returns ``""`` when empty, so the
    Overview / ``defenseclaw status`` render nothing for the common default config.
    Groups by scanner then severity, e.g.::

        secrets: HIGH file=block, install=warn | pii: MEDIUM runtime=allow

    Malformed entries (not 4 fields, or missing scanner/surface) are skipped so
    a bad adapter payload degrades to a partial line rather than raising.
    """
    grouped: dict[str, dict[str, list[str]]] = {}
    for entry in overrides:
        if len(entry) != 4:
            continue
        scanner, severity, surface, action = (str(part).strip() for part in entry)
        if not scanner or not surface:
            continue
        grouped.setdefault(scanner, {}).setdefault(severity.upper(), []).append(f"{surface}={action}")
    parts: list[str] = []
    for scanner, sevs in grouped.items():
        sev_parts = [
            f"{severity + ' ' if severity else ''}{', '.join(surfaces)}" for severity, surfaces in sevs.items()
        ]
        parts.append(f"{scanner}: {'; '.join(sev_parts)}")
    return " | ".join(parts)
