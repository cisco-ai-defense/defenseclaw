# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The CLI price lookup answers as the gateway does (rel-1-0-10 GAP-1108)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from defenseclaw import price_lookup

ROOT = Path(__file__).resolve().parents[2]
CASES = json.loads((ROOT / "internal" / "modelusage" / "testdata" / "price_lookup_cases.json").read_text())
FLAT = [
    pytest.param(table["pricing"], case, id=f"{table['name']}:{case['provider']}/{case['model']}")
    for table in CASES["tables"]
    for case in table["cases"]
]


@pytest.mark.parametrize(("pricing", "case"), FLAT)
def test_same_entry_as_the_gateway(pricing: dict, case: dict) -> None:
    # internal/modelusage/price_lookup_cases_test.go runs the same cases on PriceTable.Compute.
    assert price_lookup.price_entry(pricing, case["provider"], case["model"]) == case["entry"]


def test_cases_load() -> None:
    assert len(FLAT) >= 20
