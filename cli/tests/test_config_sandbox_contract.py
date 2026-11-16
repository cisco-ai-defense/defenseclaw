# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Contract mirror of the managed sandbox floor keys (Go config structs)."""

from __future__ import annotations

import dataclasses

import yaml
from defenseclaw import config as cfgmod


def test_floor_fields_mirror_go():
    fields = {f.name: f.default for f in dataclasses.fields(cfgmod.OpenShellAdminConfig)}
    for name in cfgmod._OPENSHELL_ADMIN_FLOOR_KEYS:
        assert name in fields, name
        assert fields[name] in (None, ""), name
    profile = {f.name: f.default for f in dataclasses.fields(cfgmod.GuardrailProfile)}
    assert profile["sandbox"] is None
    ent = {f.name for f in dataclasses.fields(cfgmod.EnterpriseOpenShellConfig)}
    # Python reads only the driver; the rest of enterprise.openshell is Go's.
    # None of it is a per-user openshell.* key (GAP-0094).
    assert ent == {"driver"}
    assert "gateway_port" not in {f.name for f in dataclasses.fields(cfgmod.OpenShellConfig)}


def test_unset_floor_keys_are_never_written(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    cfg = cfgmod.load()
    cfg.openshell.admin.request_access = "it-help@example.com"
    cfg.guardrail.profiles["p1"] = cfgmod.GuardrailProfile(description="contract")
    cfg.save()
    doc = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    admin = doc["openshell"]["admin"]
    assert admin["request_access"] == "it-help@example.com"
    for name in cfgmod._OPENSHELL_ADMIN_FLOOR_KEYS:
        if name != "request_access":
            assert name not in admin, name
    assert doc["guardrail"]["profiles"]["p1"] == {"description": "contract"}
