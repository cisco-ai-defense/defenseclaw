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


def test_connector_set_up_starts_with_init_on_a_new_install(monkeypatch):
    # `defenseclaw setup <agent>` refuses before init (GAP-0624): every
    # connector page's Set up names the init step and the refusal it replaces.
    from defenseclaw import config_writer
    from defenseclaw.commands.cmd_init import init_cmd
    from defenseclaw.config import not_initialized_error

    monkeypatch.setattr(config_writer, "machine_managed_standalone", lambda: False)
    refusal = str(not_initialized_error())
    choices = next(p for p in init_cmd.params if p.name == "connector").type.choices
    pages = sorted((DOCS / "connectors").glob("*.mdx"))
    checked = 0
    for page in pages:
        text = page.read_text(encoding="utf-8")
        if "## Set up\n" not in text:
            continue
        section = " ".join(text.split("## Set up\n", 1)[1].split("\n## ", 1)[0].split())
        name = section.split("defenseclaw setup ", 1)[1].split()[0].strip("`")
        assert name in choices, (page.name, name)
        assert section.index(f"`defenseclaw init --connector {name}`") < section.index(f"defenseclaw setup {name} "), page.name
        assert f"`{refusal}`" in section, page.name
        checked += 1
    assert checked >= 12
