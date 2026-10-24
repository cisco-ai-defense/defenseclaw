# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Model policy tier labels in fail-mode CLI mechanics tests."""

from __future__ import annotations

import pytest
from defenseclaw import config as dcconfig


@pytest.fixture(autouse=True)
def policy_tier_follows_the_saved_fail_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """A connector saved ``closed`` is in the strict tier, one saved ``open`` in the default tier.

    Per-user outages remain closed in every tier. The modules importing this
    fixture use the tier labels for registration and message scenarios without
    building a rule pack on disk. test_managed_fail_mode tests the resolver.
    """

    def tier(self: dcconfig.GuardrailConfig, connector: str = "") -> str:
        override = self._connector_override(connector)
        raw = override.hook_fail_mode if override is not None and override.hook_fail_mode.strip() else self.hook_fail_mode
        return "default" if str(raw or "").strip().lower() == "open" else "strict"

    monkeypatch.setattr(dcconfig.GuardrailConfig, "hook_policy_tier", tier)
