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
    with pytest.raises(MigrationError, match=r"1\.0\.5 guards OpenCode V1 only.*nothing was changed.*opencode-ai@1\.18"):
        migrations.check_opencode_rollback(str(tmp_path), "1.0.5")
    migrations.check_opencode_rollback(str(tmp_path), "1.0.6")
    opencode["value"] = ("1.18.34", "/opt/agents/bin/opencode")
    migrations.check_opencode_rollback(str(tmp_path), "1.0.5")


def test_installed_opencode_uses_the_discovery_probe_outside_trusted_prefixes(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from defenseclaw.inventory import agent_discovery

    calls = {}

    def discover(connectors, **kwargs):
        calls.update(kwargs, connectors=connectors)
        signal = SimpleNamespace(installed=True, version="1.18.34", binary_path="/opt/agents/bin/opencode")
        return SimpleNamespace(agents={"opencode": signal})

    monkeypatch.setattr(agent_discovery, "discover_with_probes", discover)
    assert migrations._installed_opencode(str(tmp_path)) == ("1.18.34", "/opt/agents/bin/opencode")
    assert calls["connectors"] == ["opencode"] and calls["persist_cache"] is False and calls["use_cache"] is False
