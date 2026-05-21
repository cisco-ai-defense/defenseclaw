# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 9 patch: bundled live-test scenarios.

Loads the canned scenarios shipped at
``docs-site/data/policy-scenarios.json`` so the TUI's Live Test pane
runs the same fixtures the docs-site Creator does. Keeping a single
source of truth means the operator's mental model travels cleanly
between web and TUI: when "CRITICAL skill scan" produces ``rejected``
in the docs-site, it should produce the same verdict here.

The JSON file lives in ``docs-site/`` rather than ``cli/defenseclaw/``
because it's authored alongside the policy-creator UI; a small loader
here means we don't duplicate the data and don't grow another asset
path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

# Domains and verdict labels are taken verbatim from
# ``docs-site/data/policy-scenarios.json``; the file ships labels both
# in past tense (``allowed``/``blocked``) and present tense
# (``allow``/``block``/``deny``) to match the corresponding Rego
# entrypoint return values, so we accept the union and let the live
# test pane render whatever the engine produces.
ScenarioDomain = Literal[
    "admission", "audit", "firewall", "guardrail", "skill_actions", "sandbox"
]
ScenarioVerdict = Literal[
    "allowed",
    "blocked",
    "rejected",
    "warned",
    "alerted",
    "allow",
    "block",
    "deny",
    "alert",
    "true",
]


@dataclass(frozen=True, slots=True)
class Scenario:
    """One canned input for the OPA live-test pane.

    ``id`` mirrors the docs-site scenario ID so saved selections
    round-trip across UIs. ``domain`` picks the Rego entrypoint; the
    Live Test pane evaluates ``data.defenseclaw.<domain>.verdict`` on
    every refresh.
    """

    id: str
    title: str
    description: str
    domain: ScenarioDomain
    expected_verdict: ScenarioVerdict
    input: dict[str, Any] = field(default_factory=dict)


def _bundled_scenarios_path() -> Path:
    """Locate ``policy-scenarios.json`` shipped under
    ``docs-site/data/`` relative to the repo root.

    We climb out of ``cli/defenseclaw/tui/creator/scenarios.py``
    (5 ``parents``) to reach the repo root, then descend into
    ``docs-site/data/``. If the docs-site tree was excluded from the
    install (e.g. wheel-only deployments), we return a non-existent
    path and the caller falls back to an empty list.
    """

    here = Path(__file__).resolve()
    candidate = here.parents[4] / "docs-site" / "data" / "policy-scenarios.json"
    return candidate


def _coerce_scenario(raw: dict[str, Any]) -> Scenario | None:
    """Convert one JSON entry into a ``Scenario``.

    Returns ``None`` if the entry is missing required fields. The
    docs-site loader is more lenient (it logs and skips malformed
    entries); we mirror that behavior so a typo in the JSON doesn't
    crash the wizard.
    """

    sid = raw.get("id")
    title = raw.get("title")
    description = raw.get("description")
    domain = raw.get("domain")
    expected = raw.get("expectedVerdict")
    input_obj = raw.get("input", {})

    if not all(isinstance(v, str) and v for v in (sid, title, description, domain, expected)):
        return None
    if not isinstance(input_obj, dict):
        return None

    return Scenario(
        id=str(sid),
        title=str(title),
        description=str(description),
        domain=str(domain),  # type: ignore[arg-type]
        expected_verdict=str(expected),  # type: ignore[arg-type]
        input=dict(input_obj),
    )


@lru_cache(maxsize=1)
def load_bundled_scenarios() -> tuple[Scenario, ...]:
    """Return every scenario shipped with the repo.

    The JSON file is small (<10 KB) so we cache the parsed result for
    the lifetime of the process; unit tests that need a fresh load
    can call ``load_bundled_scenarios.cache_clear()``.
    """

    path = _bundled_scenarios_path()
    if not path.exists():
        return ()

    try:
        with path.open(encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return ()

    raw = payload.get("scenarios") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return ()

    out: list[Scenario] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        scenario = _coerce_scenario(entry)
        if scenario is not None:
            out.append(scenario)
    return tuple(out)


def scenarios_by_domain(domain: ScenarioDomain) -> tuple[Scenario, ...]:
    """Filter the bundled list to one OPA entrypoint.

    The Live Test pane offers a domain selector (admission /
    guardrail / firewall / etc.); this helper backs that filter
    without forcing every caller to repeat the comprehension.
    """

    return tuple(s for s in load_bundled_scenarios() if s.domain == domain)


def scenario_by_id(scenario_id: str) -> Scenario | None:
    """Return a scenario matching ``scenario_id`` or ``None``."""

    for scenario in load_bundled_scenarios():
        if scenario.id == scenario_id:
            return scenario
    return None
