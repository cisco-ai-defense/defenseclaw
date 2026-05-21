# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Shared TUI test fixtures.

Phase 1 of the Policy tab overhaul wires bundled-preset surfacing into
``PolicyPanelModel.load_policies``. By default, every test in this
package gets an isolated, *empty* bundled dir so existing tests that
write a known set of policies don't suddenly see ``default.yaml`` /
``strict.yaml`` / ``permissive.yaml`` materialize in their assertions.

Tests that exercise the bundled-merge path explicitly override these
fixtures via ``monkeypatch.setattr(policy_state, "bundled_policies_dir",
lambda: real_path)`` from inside the test body.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_bundled_assets(tmp_path_factory, monkeypatch):
    """Point ``policy_state``'s bundled-asset resolvers at empty tmp dirs.

    The model imports these names at module level, so we patch the
    ``policy_state`` module's bound references rather than
    ``defenseclaw.paths`` itself.
    """
    bundled_root = tmp_path_factory.mktemp("bundled_assets")
    bundled_policies = bundled_root / "policies"
    bundled_rego = bundled_root / "policies" / "rego"
    bundled_guardrail = bundled_root / "policies" / "guardrail"
    for directory in (bundled_policies, bundled_rego, bundled_guardrail):
        directory.mkdir(parents=True, exist_ok=True)

    from defenseclaw.tui.services import policy_state

    monkeypatch.setattr(
        policy_state,
        "bundled_policies_dir",
        lambda: bundled_policies,
        raising=True,
    )
    monkeypatch.setattr(
        policy_state,
        "bundled_rego_dir",
        lambda: bundled_rego,
        raising=True,
    )
    monkeypatch.setattr(
        policy_state,
        "bundled_guardrail_profiles_dir",
        lambda: bundled_guardrail,
        raising=True,
    )

    yield bundled_root


@pytest.fixture
def bundled_assets(_isolated_bundled_assets) -> Path:
    """Re-export ``_isolated_bundled_assets`` under a non-private name.

    Tests that want to seed bundled assets (e.g. assert the merge happens
    in ``load_policies``) request this fixture and write into the
    returned root.
    """
    return _isolated_bundled_assets
