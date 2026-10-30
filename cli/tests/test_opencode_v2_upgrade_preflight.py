# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Upgrade and rollback refuse before anything changes when OpenCode's major does not fit (rel-1-0-6 GAP-0021, GAP-0028)."""

import pytest

from defenseclaw import migrations
from defenseclaw.migrations import MigrationError


@pytest.fixture
def opencode(monkeypatch):
    found = {}
    monkeypatch.setattr(migrations, "_opencode_configured", lambda _data_dir: True)
    monkeypatch.setattr(migrations, "_installed_opencode", lambda _data_dir: found.get("value"))
    return found


def test_upgrade_check_refuses_a_guarded_opencode_v1(opencode, tmp_path):
    opencode["value"] = ("1.18.34", "/opt/agents/bin/opencode")
    with pytest.raises(MigrationError, match=r"OpenCode V1.*nothing was changed.*@opencode/cli@2"):
        migrations._check_opencode_v2(str(tmp_path), "1.0.6")
    opencode["value"] = ("opencode v2.2.3", "/home/u/.npm/bin/opencode")
    migrations._check_opencode_v2(str(tmp_path), "1.0.6")
    opencode["value"] = None
    migrations._check_opencode_v2(str(tmp_path), "1.0.6")


def test_rollback_check_refuses_an_earlier_release_with_opencode_v2(opencode, tmp_path):
    opencode["value"] = ("opencode v2.2.3", "/home/u/.npm/bin/opencode")
    with pytest.raises(MigrationError, match=r"1\.0\.5 guards OpenCode V1 only.*nothing was changed.*setup remove opencode"):
        migrations.check_opencode_rollback(str(tmp_path), "1.0.5")
    migrations.check_opencode_rollback(str(tmp_path), "1.0.6")
    opencode["value"] = ("1.18.34", "/opt/agents/bin/opencode")
    migrations.check_opencode_rollback(str(tmp_path), "1.0.5")
