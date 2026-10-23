# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Keep setup scope, failure behavior and inventory examples explicit."""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"


@pytest.mark.parametrize(
    ("page", "facts", "obsolete"),
    [
        (
            "reference/apis/capability-matrix.mdx",
            ("administrator explicitly selects `open`", "Hermes hooks block delivery failures"),
            ("every connector's hook fails closed, also in observe mode",),
        ),
        (
            "connectors/amp.mdx",
            ("workspace for the whole DefenseClaw install", "peer connectors", "without `--workspace`"),
            ("`--workspace` only adds",),
        ),
        (
            "reference/connectors/amp.mdx",
            ("workspace for the whole DefenseClaw install", "peer connectors"),
            (),
        ),
        (
            "reference/connectors/copilot.mdx",
            ("`ownership`, `owned_entries` and `foreign_entries`", "enterprise policy show --connector copilot"),
            ("The Copilot status row lists both settings", "status says why"),
        ),
        (
            "reference/scanning/ai-discovery.mdx",
            (
                "defenseclaw agent components show ai",
                "defenseclaw agent components history ai",
                "defenseclaw agent confidence explain openai",
                "Use the component ID from `agent components`",
            ),
            ("components show ai-sdk", "components history ai-sdk", "confidence explain claudecode"),
        ),
    ],
)
def test_connector_documented_limits(page, facts, obsolete):
    text = " ".join((DOCS / page).read_text(encoding="utf-8").split())
    for fact in facts:
        assert fact in text, (page, fact)
    for claim in obsolete:
        assert claim not in text, (page, claim)


def test_matrix_shows_delivery_failure_support_separately_from_agent_contract():
    matrix = json.loads((ROOT / "docs-site/data/capability-matrix.json").read_text())
    for row in matrix["connectors"]:
        if row["id"] in {"hermes", "copilot", "antigravity"}:
            assert row["hooks"]["blocksDeliveryFailures"] is True, row["id"]
            assert row["hooks"]["supportsFailClosed"] is False, row["id"]
    component = (ROOT / "docs-site/components/capability-matrix.tsx").read_text()
    assert "c.hooks.supportsFailClosed || c.hooks.blocksDeliveryFailures" in component
    assert "Timeout or spawn failure can allow" in component
