"""Docs contracts for which destination receives which observability data.

GAP-2623: the bundled Grafana dashboards query the local-observability-v1
metric labels, which only the OTLP destination named ``local-observability``
receives. GAP-2634: Galileo's trace profile has no AI-discovery family.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from defenseclaw.observability.presets import resolve_preset
from defenseclaw.observability.v8_presets import destination_name

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"
PROFILES = ROOT / "schemas/telemetry/runtime/compatibility"


def _flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def test_shared_stack_docs_keep_the_dashboard_destination_name() -> None:
    preset = resolve_preset("local-otlp")
    assert destination_name(preset, None, {"endpoint": "stack.example.test:4317"}) == "local-observability"

    local = _flat(DOCS / "observability/local-observability.mdx")
    assert "defenseclaw setup observability add local-otlp --endpoint <stack-host>:4317" in local
    assert "selects the `local-observability-v1` metric projection" in local
    assert "if you renamed the destination" not in local
    assert "named `local-observability`" in _flat(DOCS / "observability/grafana-dashboards.mdx")
    # GAP-0058: the IDE gauge's board labels need that destination too.
    assert "plain `otlp` destination exports the canonical names `defenseclaw_ide_product`" in _flat(
        DOCS / "ai-discovery.mdx"
    )


def test_galileo_docs_list_the_profile_families_and_exclude_discovery() -> None:
    with gzip.open(PROFILES / "galileo-rich-v2.json.gz", "rt", encoding="utf-8") as handle:
        profile = json.load(handle)
    eligible = {family["family_id"] for family in profile["families"] if family.get("eligibility") == "eligible"}
    assert eligible == {
        "span.agent.invoke",
        "span.workflow.run",
        "span.model.chat",
        "span.tool.execute",
        "span.retrieval.search",
        "span.guardrail.judge",
    }
    assert not any("discovery" in family["family_id"] for family in profile["families"])

    galileo = _flat(DOCS / "observability/galileo.mdx")
    assert "The profile has six span families" in galileo
    assert "AI discovery, scanner, audit and other operational records are not in the profile" in galileo
    assert "discovery results never reach Galileo" in _flat(DOCS / "ai-discovery.mdx")
