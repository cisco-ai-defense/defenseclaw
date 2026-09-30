# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Judge response history modal tests."""

from __future__ import annotations

from defenseclaw.tui.screens.judge_history import (
    judge_response_detail_pairs,
)


def _confidence_values(rows) -> list[str]:
    return [value for key, value in judge_response_detail_pairs(rows) if key.endswith("Confidence")]


def test_zero_confidence_is_rendered_not_dropped() -> None:
    # 0.0 is a meaningful verdict -> it must render as 0.000, not vanish.
    assert _confidence_values([{"confidence": 0.0}]) == ["0.000"]
    assert _confidence_values([{"confidence": 0}]) == ["0.000"]


def test_absent_confidence_is_omitted() -> None:
    assert _confidence_values([{"confidence": None}]) == []
    assert _confidence_values([{"confidence": ""}]) == []
    assert _confidence_values([{}]) == []
