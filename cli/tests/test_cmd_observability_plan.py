# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import click
from click.testing import CliRunner
from defenseclaw.commands import cmd_observability
from defenseclaw.config_inspect import ConfigV8WireResult
from defenseclaw.observability.custody_status import (
    ConnectorCustodyReport,
    ConnectorCustodyStatus,
)


def _effective() -> dict:
    return {
        "buckets": [
            {
                "bucket": "security.finding",
                "collect": {"logs": True, "traces": True, "metrics": True},
                "redaction_profile": "none",
                "reload_applicability": "live_reloadable",
            },
            {
                "bucket": "model.io",
                "collect": {"logs": False, "traces": False, "metrics": False},
                "redaction_profile": "none",
                "reload_applicability": "live_reloadable",
            },
        ],
        "destinations": [
            {
                "name": "local-sqlite",
                "enabled": True,
                "selected_signals": ["logs"],
                "reload_applicability": {"policy": "live_reloadable", "transport": "restart_required"},
                "routes": [
                    {
                        "name": "all-collected-logs-and-mandatory-floor",
                        "signals": ["logs"],
                        "selector": {"buckets": ["security.finding", "model.io"]},
                        "action": "send",
                        "includes_mandatory_floor": True,
                        "redaction_profile_by_bucket": {
                            "security.finding": "none",
                            "model.io": "none",
                        },
                    }
                ],
            },
            {
                "name": "soc",
                "kind": "http_jsonl",
                "enabled": True,
                "selected_signals": ["logs"],
                "reload_applicability": {"policy": "live_reloadable", "transport": "live_reloadable"},
                "transport": {
                    "batch": {
                        "max_queue_size": 2048,
                        "max_queue_bytes": 67108864,
                        "max_export_batch_size": 512,
                        "max_export_batch_bytes": 8388608,
                        "scheduled_delay_ms": 5000,
                    }
                },
                "routes": [
                    {
                        "name": "ai-findings",
                        "signals": ["logs"],
                        "selector": {"buckets": ["security.finding"], "sources": ["ai_defense"]},
                        "action": "send",
                        "redaction_profile_by_bucket": {"security.finding": "sensitive"},
                    },
                    {
                        "name": "remaining",
                        "signals": ["logs"],
                        "selector": {"buckets": ["security.finding", "model.io"]},
                        "action": "send",
                        "redaction_profile_by_bucket": {
                            "security.finding": "strict",
                            "model.io": "strict",
                        },
                    },
                ],
            },
        ],
        "warnings": [],
    }


def _wire() -> ConfigV8WireResult:
    return ConfigV8WireResult(
        wire_version=1,
        kind="effective",
        config_version=8,
        source="/tmp/config.yaml",
        data_dir="/tmp/dc",
        plan_digest="plan-digest",
        network_validation="offline_syntax_and_literal_policy_only",
        effective=_effective(),
    )


def _effective_with_galileo() -> dict:
    effective = _effective()
    effective["buckets"][1]["collect"]["traces"] = True
    effective["destinations"].append(
        {
            "name": "galileo",
            "kind": "otlp",
            "enabled": True,
            "selected_signals": ["traces"],
            "reload_applicability": {"policy": "live_reloadable", "transport": "live_reloadable"},
            "compatibility_profiles": [
                {
                    "id": "galileo-rich-v2",
                    "availability": "pending",
                    "eligible_span_families": [
                        {
                            "event_name": "span.agent.invoke",
                            "bucket": "agent.lifecycle",
                            "availability": "pending",
                        },
                        {"event_name": "span.model.chat", "bucket": "model.io", "availability": "pending"},
                    ],
                }
            ],
            "routes": [
                {
                    "name": "model-spans",
                    "signals": ["traces"],
                    "selector": {
                        "buckets": ["model.io"],
                        "event_names": ["span.model.chat"],
                    },
                    "action": "send",
                    "redaction_profile_by_bucket": {"model.io": "none"},
                }
            ],
        }
    )
    return effective


def test_plan_labels_unknown_metadata_match_as_conditional() -> None:
    rows = cmd_observability._plan_rows(
        _effective(),
        selected_buckets={"security.finding"},
        selected_signals={"logs"},
        filters=cmd_observability._PlanFilters(),
    )
    remote = next(row for row in rows if row["destination"] == "soc")
    assert remote["decision"] == "conditional"
    assert remote["route"] == "ai-findings"
    assert remote["potential_action"] == "send"
    assert "compatibility_profile" not in remote
    assert remote["reload_applicability"] == {
        "collection": "live_reloadable",
        "routing": "live_reloadable",
        "transport": "live_reloadable",
    }


def test_plan_filters_resolve_first_match_without_recompiling_routes() -> None:
    rows = cmd_observability._plan_rows(
        _effective(),
        selected_buckets={"security.finding"},
        selected_signals={"logs"},
        filters=cmd_observability._PlanFilters(source="gateway"),
    )
    remote = next(row for row in rows if row["destination"] == "soc")
    assert remote["decision"] == "send"
    assert remote["route"] == "remaining"
    assert remote["redaction_profile"] == "strict"


def test_plan_labels_event_level_floor_as_conditional_and_remote_as_not_collected() -> None:
    rows = cmd_observability._plan_rows(
        _effective(),
        selected_buckets={"model.io"},
        selected_signals={"logs"},
        filters=cmd_observability._PlanFilters(),
    )
    by_destination = {row["destination"]: row for row in rows}
    assert by_destination["local-sqlite"]["decision"] == "conditional"
    assert by_destination["local-sqlite"]["potential_action"] == "floor_only"
    assert by_destination["local-sqlite"]["condition"] == "mandatory_floor_event_qualification"
    assert by_destination["local-sqlite"]["route"] == "all-collected-logs-and-mandatory-floor"
    assert by_destination["soc"]["decision"] == "not_collected"


def test_top_level_plan_skips_legacy_runtime_config_load(tmp_path: Path) -> None:
    from defenseclaw.main import cli

    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\nobservability: {}\n", encoding="utf-8")
    with (
        patch.object(cmd_observability.config_module, "config_path", return_value=config_path),
        patch.object(cmd_observability, "inspect_v8_config", return_value=_wire()),
        patch("defenseclaw.config.load", side_effect=AssertionError("legacy config loader must not run")),
    ):
        result = CliRunner().invoke(
            cli,
            ["observability", "plan", "--bucket", "security.finding", "--signal", "logs", "--format", "json"],
        )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["basis"] == "canonical_go_compiled_routes"
    assert payload["plan_digest"] == "plan-digest"
    assert payload["connector_export_custody"]["state"] == "unavailable"
    assert payload["delivery"] == [
        {
            "destination": "soc",
            "kind": "http_jsonl",
            "max_queue_size": 2048,
            "max_queue_bytes": 67108864,
            "max_export_batch_size": 512,
            "max_export_batch_bytes": 8388608,
            "scheduled_delay_ms": 5000,
        }
    ]
    assert len(payload["rows"]) == 2


def test_top_level_plan_json_reports_per_instance_export_custody(tmp_path: Path) -> None:
    from defenseclaw.main import cli

    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\nobservability: {}\n", encoding="utf-8")
    custody = ConnectorCustodyReport(
        state="available",
        reason="",
        observation_window_hours=24,
        instances=(
            ConnectorCustodyStatus(
                connector_instance_id="019b0000-0000-7000-8000-000000000001",
                connector="codex",
                custody="external",
                profile_version="codex-correlation-v1",
                default=True,
            ),
        ),
    )
    with (
        patch.object(cmd_observability.config_module, "config_path", return_value=config_path),
        patch.object(cmd_observability, "inspect_v8_config", return_value=_wire()),
        patch.object(cmd_observability, "inspect_connector_custody", return_value=custody),
    ):
        result = CliRunner().invoke(cli, ["observability", "plan", "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["connector_export_custody"] == custody.as_json()


def test_top_level_plan_json_reports_exact_go_compatibility_and_reload(tmp_path: Path) -> None:
    from defenseclaw.main import cli

    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\nobservability: {}\n", encoding="utf-8")
    wire = ConfigV8WireResult(
        wire_version=1,
        kind="effective",
        config_version=8,
        source=str(config_path),
        data_dir=str(tmp_path),
        plan_digest="compatibility-plan",
        network_validation="offline_syntax_and_literal_policy_only",
        effective=_effective_with_galileo(),
    )
    with (
        patch.object(cmd_observability.config_module, "config_path", return_value=config_path),
        patch.object(cmd_observability, "inspect_v8_config", return_value=wire),
    ):
        result = CliRunner().invoke(
            cli,
            [
                "observability",
                "plan",
                "--bucket",
                "model.io",
                "--signal",
                "traces",
                "--event-name",
                "span.model.chat",
                "--format",
                "json",
            ],
        )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    galileo = next(row for row in payload["rows"] if row["destination"] == "galileo")
    assert galileo == {
        "bucket": "model.io",
        "collected": True,
        "compatibility": [
            {
                "eligibility": "profile_pending",
                "event_name": "span.model.chat",
                "family_binding_availability": "pending",
                "family_eligible": False,
                "family_member": True,
                "family_shape_available": False,
                "profile": "galileo-rich-v2",
                "profile_availability": "pending",
            }
        ],
        "decision": "send",
        "destination": "galileo",
        "redaction_profile": "none",
        "reload_applicability": {
            "collection": "live_reloadable",
            "routing": "live_reloadable",
            "transport": "live_reloadable",
        },
        "route": "model-spans",
        "signal": "traces",
    }


def test_plan_table_renders_compiled_delivery_limits() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            click.Command(
                "render",
                callback=lambda: cmd_observability._render_plan_table(
                    [], "digest", cmd_observability._delivery_settings(_effective())
                ),
            )
        )

    assert result.exit_code == 0, result.output
    assert "Delivery limits (compiled defaults and source overrides):" in result.output
    assert "67108864" in result.output
    assert "8388608" in result.output


def test_plan_reports_only_go_published_exact_family_compatibility() -> None:
    effective = _effective_with_galileo()

    eligible = cmd_observability._plan_rows(
        effective,
        selected_buckets={"model.io"},
        selected_signals={"traces"},
        filters=cmd_observability._PlanFilters(event_name="span.model.chat"),
    )
    galileo = next(row for row in eligible if row["destination"] == "galileo")
    assert galileo["decision"] == "send"
    assert galileo["compatibility"] == [
        {
            "profile": "galileo-rich-v2",
            "profile_availability": "pending",
            "event_name": "span.model.chat",
            "family_member": True,
            "family_binding_availability": "pending",
            "family_shape_available": False,
            "family_eligible": False,
            "eligibility": "profile_pending",
        }
    ]

    available = _effective_with_galileo()
    available_profile = available["destinations"][-1]["compatibility_profiles"][0]
    available_profile["availability"] = "available"
    available_profile["eligible_span_families"][1]["availability"] = "available"
    available_rows = cmd_observability._plan_rows(
        available,
        selected_buckets={"model.io"},
        selected_signals={"traces"},
        filters=cmd_observability._PlanFilters(event_name="span.model.chat"),
    )
    available_galileo = next(row for row in available_rows if row["destination"] == "galileo")
    assert available_galileo["compatibility"][0]["family_shape_available"] is True
    assert available_galileo["compatibility"][0]["family_eligible"] is True
    assert available_galileo["compatibility"][0]["eligibility"] == "eligible"

    ineligible = cmd_observability._plan_rows(
        effective,
        selected_buckets={"model.io"},
        selected_signals={"traces"},
        filters=cmd_observability._PlanFilters(event_name="span.agent.invoke"),
    )
    galileo = next(row for row in ineligible if row["destination"] == "galileo")
    assert galileo["decision"] == "unmatched"
    assert galileo["compatibility"][0] == {
        "profile": "galileo-rich-v2",
        "profile_availability": "pending",
        "event_name": "span.agent.invoke",
        "family_member": False,
        "family_binding_availability": None,
        "family_shape_available": False,
        "family_eligible": False,
        "eligibility": "family_not_in_profile",
    }

    unfiltered = cmd_observability._plan_rows(
        effective,
        selected_buckets={"model.io"},
        selected_signals={"traces"},
        filters=cmd_observability._PlanFilters(),
    )
    galileo = next(row for row in unfiltered if row["destination"] == "galileo")
    assert "compatibility" not in galileo


def test_family_eligibility_requires_an_exact_send_decision() -> None:
    base = _effective_with_galileo()["destinations"][-1]
    base["compatibility_profiles"][0]["availability"] = "available"
    base["compatibility_profiles"][0]["eligible_span_families"][1]["availability"] = "available"
    filters = cmd_observability._PlanFilters(event_name="span.model.chat")

    cases: list[tuple[str, dict, bool, str, str]] = []

    disabled = deepcopy(base)
    disabled["enabled"] = False
    cases.append(("disabled", disabled, True, "destination_disabled", "not_routed"))

    unselected = deepcopy(base)
    unselected["selected_signals"] = []
    cases.append(("unselected", unselected, True, "signal_not_selected", "not_routed"))

    cases.append(("not-collected", deepcopy(base), False, "not_collected", "not_routed"))

    dropped = deepcopy(base)
    dropped["routes"][0]["action"] = "drop"
    cases.append(("drop", dropped, True, "drop", "not_routed"))

    unmatched = deepcopy(base)
    unmatched["routes"][0]["selector"]["event_names"] = ["span.agent.invoke"]
    cases.append(("unmatched", unmatched, True, "unmatched", "not_routed"))

    conditional = deepcopy(base)
    conditional["routes"][0]["selector"]["sources"] = ["gateway"]
    cases.append(("conditional", conditional, True, "conditional", "conditional_route"))

    for name, destination, collected, expected_decision, expected_eligibility in cases:
        row = cmd_observability._destination_row(
            "model.io", "traces", collected, "live_reloadable", destination, filters
        )
        compatibility = row["compatibility"][0]
        assert row["decision"] == expected_decision, name
        assert compatibility["family_member"] is True, name
        assert compatibility["family_shape_available"] is True, name
        assert compatibility["family_eligible"] is False, name
        assert compatibility["eligibility"] == expected_eligibility, name


def test_plan_table_renders_compatibility_and_reload_from_effective_plan() -> None:
    row = {
        "bucket": "model.io",
        "signal": "traces",
        "collected": True,
        "destination": "galileo",
        "decision": "send",
        "route": "model-spans",
        "redaction_profile": "none",
        "compatibility": [
            {
                "profile": "galileo-rich-v2",
                "profile_availability": "pending",
                "event_name": "span.model.chat",
                "family_member": True,
                "family_binding_availability": "pending",
                "family_shape_available": False,
                "family_eligible": False,
                "eligibility": "profile_pending",
            }
        ],
        "reload_applicability": {
            "collection": "live_reloadable",
            "routing": "live_reloadable",
            "transport": "restart_required",
        },
    }
    runner = CliRunner()
    result = runner.invoke(
        click.Command("render", callback=lambda: cmd_observability._render_plan_table([row], "digest", []))
    )

    assert result.exit_code == 0, result.output
    assert "galileo-rich-v2:profile_pending" in result.output
    assert "collect=live_reloadable,route=live_reloadable,transport=restart_required" in result.output
