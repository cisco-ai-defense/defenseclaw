# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from defenseclaw.observability.v8_config import V8ConfigError, load_validate_v8

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "testdata" / "observability_v8" / "config_validation_cases.yaml"


def test_python_matches_shared_go_validation_corpus() -> None:
    corpus = yaml.safe_load(CORPUS.read_text(encoding="utf-8"))
    assert corpus["schema_version"] == 1
    assert len(corpus["cases"]) >= 15
    names = [case["name"] for case in corpus["cases"]]
    assert len(names) == len(set(names))

    disagreements: list[str] = []
    for case in corpus["cases"]:
        try:
            load_validate_v8(case["source"], source_name=f"shared:{case['name']}")
            accepted = True
        except V8ConfigError:
            accepted = False
        if accepted != case["valid"]:
            disagreements.append(f"{case['name']}: expected valid={case['valid']}, accepted={accepted}")

    if disagreements:
        pytest.fail("Python disagrees with the shared Go/Python corpus:\n" + "\n".join(disagreements))
