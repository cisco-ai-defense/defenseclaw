# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""observability.tokenomics and observability.pricing: parse, defaults, validation (mirrors internal/config/tokenomics.go)."""

from __future__ import annotations

import pytest
from defenseclaw.config import (
    TOKENOMICS_METRIC_LABELS,
    PricingConfig,
    TokenomicsConfig,
    _merge_observability,
)
from defenseclaw.observability.v8_config import V8ConfigError, load_validate_v8

VALID = """\
config_version: 9
observability:
  tokenomics:
    enabled: true
    roles: [agent, judge]
    cost: {compute: true, currency: USD, keep_reported: false}
    local_store: {enabled: true, retention_days: 14}
    metrics: {labels: [connector, model]}
  pricing:
    version: "2026-11-12.1"
    unknown_model: fallback
    fallback: {input_per_mtok: 3.0, output_per_mtok: 15.0}
    ai_defense: {per_call_usd: 0.002}
    models:
      - {provider: anthropic, model: "claude-haiku-4-5*", input_per_mtok: 1.0, output_per_mtok: 5.0, cache_read_per_mtok: 0.1}
"""


def _doc(body: str) -> str:
    return "config_version: 9\nobservability:\n" + "".join("  " + line + "\n" for line in body.strip().splitlines())


def test_absent_blocks_are_old_behaviour() -> None:
    obs = _merge_observability({})
    assert obs.tokenomics == TokenomicsConfig()
    assert obs.tokenomics.enabled is False
    assert obs.tokenomics.local_store_enabled is False
    assert obs.pricing == PricingConfig()
    assert obs.pricing.models == []
    assert list(obs.tokenomics.metric_labels) == list(TOKENOMICS_METRIC_LABELS)


def test_valid_blocks_load_and_parse() -> None:
    validated = load_validate_v8(VALID)
    raw = validated.source["observability"]
    obs = _merge_observability(raw)
    assert obs.tokenomics.enabled and obs.tokenomics.roles == ["agent", "judge"]
    assert obs.tokenomics.cost_keep_reported is False
    assert obs.tokenomics.local_store_retention_days == 14
    assert obs.tokenomics.metric_labels == ["connector", "model"]
    assert obs.pricing.version == "2026-11-12.1"
    entry = obs.pricing.models[0]
    assert entry.model == "claude-haiku-4-5*" and entry.input_per_mtok == 1.0 and entry.cache_read_per_mtok == 0.1
    # An unset price stays absent, never 0.
    assert entry.cache_write_per_mtok is None and entry.reasoning_per_mtok is None
    assert obs.pricing.ai_defense_per_call_usd == 0.002


@pytest.mark.parametrize(
    "body",
    [
        # identity labels are never allowed on a metric
        "tokenomics: {metrics: {labels: [user]}}",
        "tokenomics: {metrics: {labels: [connector, connector]}}",
        "tokenomics: {roles: [intruder]}",
        "tokenomics: {cost: {currency: EUR}}",
        "tokenomics: {local_store: {retention_days: 0}}",
        "tokenomics: {local_store: {retention_days: 4000}}",
        "tokenomics: {local_store: {granularity: day}}",
        "tokenomics: {surprise: true}",
        "pricing: {models: [{provider: a, model: b, input_per_mtok: 1, output_per_mtok: 1}]}",  # no version
        "pricing: {version: v, models: [{provider: a, model: b, input_per_mtok: -1, output_per_mtok: 1}]}",
        "pricing: {version: v, models: [{provider: a, model: b, input_per_mtok: 1}]}",
        "pricing: {version: v, models: [{provider: a, model: b*c, input_per_mtok: 1, output_per_mtok: 1}]}",
        "pricing: {version: v, models: [{provider: a, model: b, input_per_mtok: 1, output_per_mtok: 1}, {provider: A, model: B, input_per_mtok: 1, output_per_mtok: 1}]}",
        "pricing: {unknown_model: fallback}",
        "pricing: {unknown_model: guess}",
        "pricing: {version: v, ai_defense: {per_call_usd: -0.1}}",
    ],
)
def test_invalid_blocks_are_refused(body: str) -> None:
    with pytest.raises(V8ConfigError):
        load_validate_v8(_doc(body))
