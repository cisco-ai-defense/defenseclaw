# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Searchable model picker modal tests."""

from __future__ import annotations

from defenseclaw.tui.screens.model_picker import (
    filter_models,
    picker_rows,
)

_MODELS = ("gpt-4o", "gpt-4o-mini", "o3")


def test_filter_and_picker_rows_freeform() -> None:
    assert filter_models("", _MODELS) == list(_MODELS)
    assert filter_models("mini", _MODELS) == ["gpt-4o-mini"]
    # An id the catalog doesn't contain is prepended as a free-form row.
    assert picker_rows("gpt[4", _MODELS)[0] == "gpt[4"
    # An exact catalog match is not duplicated as a free-form row.
    assert picker_rows("o3", _MODELS) == ["o3"]
