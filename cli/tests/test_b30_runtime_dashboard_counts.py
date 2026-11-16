"""The shipped runtime charts count findings rather than repeated activity rows."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_grafana_no_hook_activity_counts_distinct_findings() -> None:
    dashboard = json.loads(
        (ROOT / "bundles/local_observability_stack/grafana/dashboards/defenseclaw-ai-runtime.json")
        .read_text(encoding="utf-8")
    )
    panels = {panel["title"]: panel for panel in dashboard["panels"]}
    no_hook = panels["Agent activity with no hook decision"]
    target = no_hook["targets"][0]
    expression = target["expr"]
    assert "body_defenseclaw_ai_runtime_finding_id" in expression
    assert "sum by (host_name, body_defenseclaw_ai_runtime_finding_id" in expression
    assert "[$__range]" in expression
    assert target["instant"] is True
    assert no_hook["type"] == "stat"


def test_grafana_would_block_by_control_counts_every_kernel_event() -> None:
    # GAP-0148: the per-tactic activity record keeps one control, so a second
    # control of the same tactic (ssh_authorized_keys_write beside
    # persistence_write) fell out of a bar built from those records. The bar
    # reads the kernel events counter instead, which counts each event under
    # its own control, so the bars add up to the Would-block tile.
    dashboard = json.loads(
        (ROOT / "bundles/local_observability_stack/grafana/dashboards/defenseclaw-ai-runtime.json")
        .read_text(encoding="utf-8")
    )
    panels = {panel["title"]: panel for panel in dashboard["panels"]}
    control = panels["Would-block in monitor mode, by control"]
    target = control["targets"][0]
    assert control["type"] == "bargauge"
    assert control["datasource"]["type"] == target["datasource"]["type"] == "prometheus"
    assert target["instant"] is True and target["legendFormat"] == "{{control}}"
    expression = target["expr"]
    # The counter is a delta sum made cumulative by the Collector, so a series
    # holds its first batch as its first sample and increase() skips it: the
    # bar is the last value in range minus the last value before the range, or
    # zero for a control first seen in the range. The Collector restarts the
    # cumulative after max_stale (24h) and on its own restart; the look-back is
    # that same 24h and a negative difference (a reset) counts the in-range
    # last value instead, so a reset cannot hide or lower another host's bar.
    assert "increase(" not in expression
    assert expression.startswith("sum by (control) (((last_over_time(defenseclaw_kernel_events_total{")
    assert expression.count("last_over_time(") == 4
    assert "[24h] offset $__range)" in expression and "[7d]" not in expression
    assert ") >= 0) or last_over_time(" in expression and " or (" in expression
    assert expression.endswith(") > 0")
    assert 'owner="defenseclaw"' in expression and 'outcome="would_block"' in expression
    assert 'host_name=~"$host"' in expression and "[$__range]" in expression
    assert "ai.runtime.activity" not in expression
    assert "first batch" in control["description"]
    assert "lower than the tile" in control["description"]


def test_splunk_timecharts_keep_first_sighting_bucket() -> None:
    view = ET.parse(
        ROOT
        / "bundles/splunk_local_bridge/splunk/apps/defenseclaw_local_mode/default/data/ui/views/ai_runtime_planes.xml"
    )
    panels = {panel.findtext("title"): panel for panel in view.iter("panel")}
    for title, distinct_fields in (
        ("Host-plane tactics by kill-chain stage", "host runtime_finding_id runtime_tactic"),
        # GAP-1400: one finding ID can carry several native hits (two
        # autostart files); its rows carry the count, repeats count once.
        ("Would-block by control (monitor mode)", "host runtime_finding_id runtime_kernel_control"),
    ):
        query = panels[title].findtext("chart/search/query")
        assert query is not None
        assert query.index("sort 0 + _time") < query.index(f"dedup {distinct_fields}")
        assert query.index(f"dedup {distinct_fields}") < query.index("timechart span=10m")


def test_would_block_bar_look_back_matches_the_collector_max_stale() -> None:
    # The bar's 24h look-back is the Collector's deltatocumulative max_stale:
    # a sample older than that belongs to a stream the Collector has already
    # restarted. Change both together.
    import yaml

    collector = yaml.safe_load(
        (ROOT / "bundles/local_observability_stack/otel-collector/config.yaml").read_text(encoding="utf-8")
    )
    assert collector["processors"]["deltatocumulative"]["max_stale"] == "24h"
