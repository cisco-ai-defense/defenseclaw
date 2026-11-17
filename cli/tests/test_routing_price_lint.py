# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""doctor and routing rules list price routing aliases as the gateway does (rel-1-0-10 GAP-1108)."""

from __future__ import annotations

from defenseclaw.commands import cmd_routing
from defenseclaw.tokenomics_seed import load_default_pricing


def _doc(model: str, pricing: dict | None) -> dict:
    doc = {
        "config_version": 9,
        "routing": {
            "enabled": True,
            "models": [{"name": "fast", "provider": "bedrock", "model": model}],
            "admin": {"budgets": [{"id": "b1", "scope": "user", "subject": "*", "period": "day", "limit_usd": 5, "on_exceed": "warn"}]},
        },
        "observability": {"tokenomics": {"enabled": True, "local_store": {"enabled": True}}},
    }
    if pricing is not None:
        doc["observability"]["pricing"] = pricing
    return doc


def test_doctor_does_not_warn_for_a_bedrock_region_profile_the_seed_prices() -> None:
    notes = cmd_routing._lint(_doc("us.anthropic.claude-haiku-4-5-20251001-v1:0", load_default_pricing()))
    assert not [n for n in notes if "has no price" in n], notes


def test_doctor_still_warns_for_an_unpriced_model() -> None:
    notes = cmd_routing._lint(_doc("us.meta.llama4-maverick-17b-instruct-v1:0", load_default_pricing()))
    assert "model fast has no price in observability.pricing: its calls do not count toward budgets" in notes
    assert [n for n in cmd_routing._lint(_doc("us.anthropic.claude-haiku-4-5-20251001-v1:0", None)) if "has no price" in n]
