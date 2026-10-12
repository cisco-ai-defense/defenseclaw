"""Managed-sandbox views: the Grafana board rows and the Splunk saved searches.

Lean regression guards for the enterprise fleet views (lane L8b): every new
record family has a panel and a saved search, and no query groups by or shows a
person (user, principal or subject key), because users see only their own policy
and per-user values are never labels.
"""

from __future__ import annotations

import configparser
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOARD = ROOT / "bundles/local_observability_stack/grafana/dashboards/defenseclaw-sandboxes.json"
SAVED = ROOT / "bundles/splunk_local_bridge/splunk/apps/defenseclaw_local_mode/default/savedsearches.conf"

MANAGED_EVENTS = {
    "sandbox.policy.resolved",
    "sandbox.policy.rematched",
    "sandbox.policy.foreign_rule",
    "sandbox.ask.decided",
    "sandbox.host_run_refused",
    "sandbox.host_run_unavailable",
    "sandbox.access_refused",
    "sandbox.foreign_sandbox",
    "sandbox.foreign_container",
    "sandbox.settings_drift",
}
PERSON = re.compile(r"user|principal|subject", re.IGNORECASE)


def _board_queries() -> list[str]:
    board = json.loads(BOARD.read_text(encoding="utf-8"))
    return [
        target["expr"] for panel in board["panels"] if panel.get("id", 0) >= 101 for target in panel.get("targets", [])
    ]


def _board_event_names(queries: list[str]) -> set[str]:
    """Full event names the board filters on, with regex families like sandbox[.](a|b) expanded."""
    names: set[str] = set()
    for query in queries:
        for raw in re.findall(r'defenseclaw_event_name=~?"([^"]*)', query):
            value = raw.replace("[.]", ".")
            if "(" in value:
                prefix, rest = value.split("(", 1)
                names.update(prefix + alt for alt in rest.rstrip(")").split("|"))
            else:
                names.update(value.split("|"))
    return names


def _sandbox_searches() -> dict[str, str]:
    parser = configparser.RawConfigParser(strict=True)
    parser.optionxform = str  # keep key case (enableSched)
    parser.read(SAVED, encoding="utf-8")
    return {
        name: dict(parser.items(name))["search"]
        for name in parser.sections()
        if name.startswith("DefenseClaw Sandboxes - ")
        or re.match(r"DefenseClaw Alert - (Sandbox|Foreign|Required)", name)
    }


def test_board_covers_every_managed_record_and_names_no_person() -> None:
    queries = _board_queries()
    joined = "\n".join(queries)
    assert MANAGED_EVENTS <= _board_event_names(queries)
    assert not PERSON.search(joined)


def test_saved_searches_cover_every_managed_record_and_names_no_person() -> None:
    searches = _sandbox_searches()
    assert len(searches) >= 11
    joined = "\n".join(searches.values())
    for event in MANAGED_EVENTS:
        assert event in joined, event
    assert not PERSON.search(joined)


def test_saved_searches_use_only_real_scheduling_keys() -> None:
    text = SAVED.read_text(encoding="utf-8")
    for dead in ("is_scheduled", "alert_type", "alert_comparator", "alert_threshold"):
        assert not re.search(rf"^{dead}\s*=", text, re.MULTILINE), dead


def test_driver_variable_lists_only_drivers_defenseclaw_accepts() -> None:
    board = json.loads(BOARD.read_text(encoding="utf-8"))
    driver = next(v for v in board["templating"]["list"] if v["name"] == "driver")
    # internal/openshell/driver.go accepts docker and vm only; podman and kubernetes are refused.
    assert driver["query"] == "docker,vm"
    assert [o["value"] for o in driver["options"]] == ["$__all", "docker", "vm"]


def test_product_telemetry_summary_stays_unscheduled() -> None:
    parser = configparser.RawConfigParser(strict=True)
    parser.optionxform = str
    parser.read(SAVED, encoding="utf-8")
    stanza = dict(parser.items("DefenseClaw Internal - Daily Product Telemetry Usage Summary"))
    # The ansible phone-home toggle flips disabled=0; the job must still not run on a schedule
    # until the owner decides to activate it.
    assert stanza["enableSched"] == "0"


def test_fleet_search_names_what_it_counts() -> None:
    searches = _sandbox_searches()
    fleet = next(s for n, s in searches.items() if "Managed Fleet By Profile" in n)
    assert "dc(sandbox) as sandbox_names_seen" in fleet
