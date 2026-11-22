# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""doctor and routing rules list price routing aliases as the gateway does (rel-1-0-10 GAP-1108)."""

from __future__ import annotations

from defenseclaw.commands import cmd_routing

PRICING = {
    "version": "t-1",
    "unknown_model": "omit",
    "models": [{"provider": "bedrock", "model": "claude-haiku-4-5*", "input_per_mtok": 1, "output_per_mtok": 5}],
}
NO_PRICE = "model fast has no price in observability.pricing: its calls do not count toward budgets"


def _doc(model: str, pricing: dict | None) -> dict:
    budget = {"id": "b1", "scope": "user", "subject": "*", "period": "day", "limit_usd": 5, "on_exceed": "warn"}
    doc = {
        "config_version": 9,
        "routing": {
            "enabled": True,
            "models": [{"name": "fast", "provider": "bedrock", "model": model}],
            "admin": {"budgets": [budget]},
        },
        "observability": {"tokenomics": {"enabled": True, "local_store": {"enabled": True}}},
    }
    if pricing is not None:
        doc["observability"]["pricing"] = pricing
    return doc


def test_doctor_does_not_warn_for_a_bedrock_region_profile_the_table_prices() -> None:
    for model in (
        "us.anthropic.claude-haiku-4-5-20251001-v1:0",
        "eu.anthropic.claude-haiku-4-5-20251001-v1:0",
        "global.anthropic.claude-haiku-4-5-20251001-v1:0",
    ):
        notes = cmd_routing._lint(_doc(model, PRICING))
        assert NO_PRICE not in notes, (model, notes)


def test_doctor_still_warns_for_an_unpriced_model() -> None:
    assert NO_PRICE in cmd_routing._lint(_doc("us.meta.llama4-maverick-17b-instruct-v1:0", PRICING))
    assert NO_PRICE in cmd_routing._lint(_doc("us.anthropic.claude-haiku-4-5-20251001-v1:0", None))


def test_budget_feed_note_follows_the_gateway_not_the_local_store() -> None:
    doc = _doc("us.anthropic.claude-haiku-4-5-20251001-v1:0", PRICING)
    doc["observability"]["tokenomics"] = {"enabled": True}  # local store off: budgets still count
    assert not [n for n in cmd_routing._lint(doc) if "cannot count spend" in n]
    doc["observability"]["tokenomics"] = {"enabled": True, "cost": {"compute": False}}
    assert [n for n in cmd_routing._lint(doc) if "cannot count spend" in n and "cost.compute" in n]
