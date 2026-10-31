# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Upgrade, rollback and downgrade refuse before anything changes when OpenCode's major does not fit
(rel-1-0-6 GAP-0021, GAP-0028, GAP-0128)."""

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



def test_downgrade_check_gives_the_downgrade_next_step(opencode, tmp_path):
    """GAP-0128: a downgrade keeps this install's configuration, so removing OpenCode first is a way through."""
    opencode["value"] = ("opencode v2.2.5", "/home/u/.npm/bin/opencode")
    with pytest.raises(MigrationError) as raised:
        migrations.check_opencode_rollback(str(tmp_path), "1.0.5", downgrade=True)
    text = str(raised.value)
    assert text.startswith("DefenseClaw 1.0.5 guards OpenCode V1 only and the OpenCode here is V2 (opencode v2.2.5)")
    assert "To downgrade, put OpenCode V1 back first" in text and "setup remove opencode" in text
    assert "rollback restores" not in text
    migrations.check_opencode_rollback(str(tmp_path), "1.0.6", downgrade=True)


def test_migrate_check_downgrade_to_exits_1_with_the_reason(opencode, tmp_path):
    from click.testing import CliRunner
    from defenseclaw.commands.cmd_migrate import migrate_cmd

    opencode["value"] = ("opencode v2.2.5", "/home/u/.npm/bin/opencode")
    result = CliRunner().invoke(migrate_cmd, ["--check-downgrade-to", "1.0.5", "--data-dir", str(tmp_path)])
    assert result.exit_code == 1, result.output
    assert "guards OpenCode V1 only" in result.output and "To downgrade" in result.output
    result = CliRunner().invoke(migrate_cmd, ["--check-rollback-to", "1.0.5", "--data-dir", str(tmp_path)])
    assert result.exit_code == 1 and "to roll back" in result.output
    opencode["value"] = ("1.18.34", "/opt/agents/bin/opencode")
    assert CliRunner().invoke(migrate_cmd, ["--check-downgrade-to", "1.0.5", "--data-dir", str(tmp_path)]).exit_code == 0

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


def _v2_package(prefix, version="2.2.4"):
    import json

    package = prefix / "lib" / "node_modules" / "@opencode" / "cli"
    package.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": "@opencode/cli", "version": version}))


def test_rollback_check_finds_a_v2_outside_the_callers_path(opencode, monkeypatch, tmp_path):
    """GAP-0067: the shell's PATH has only V1 (or nothing), the account's V2 sits in another prefix."""
    import json

    home = tmp_path / "home"
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("APPDATA", raising=False)
    opencode["value"] = ("1.18.34", "/opt/dc-agents/bin/opencode")  # the PATH of this shell: V1
    migrations.check_opencode_rollback(str(data), "1.0.5")  # nothing else known: no refusal

    # 1. setup recorded the V2 binary in a prefix this shell does not have on PATH
    binary = tmp_path / "custom-prefix" / "bin" / "opencode"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\n")
    record = {"agents": {"opencode": {"installed": True, "version": "2.2.4", "binary_path": str(binary)}}}
    (data / "agent_discovery.json").write_text(json.dumps(record))
    with pytest.raises(MigrationError, match=r"1\.0\.5 guards OpenCode V1 only.*V2 \(2\.2\.4\).*nothing was changed"):
        migrations.check_opencode_rollback(str(data), "1.0.5")
    binary.unlink()  # V2 uninstalled since: the record no longer counts
    migrations.check_opencode_rollback(str(data), "1.0.5")

    # 2. package metadata under a usual prefix
    _v2_package(home / ".npm-global")
    with pytest.raises(MigrationError, match=r"V2 \(2\.2\.4\)"):
        migrations.check_opencode_rollback(str(data), "1.0.5")
    # a V1 package there is not V2
    (home / ".npm-global" / "lib" / "node_modules" / "@opencode" / "cli" / "package.json").write_text(
        json.dumps({"version": "1.18.34"})
    )
    migrations.check_opencode_rollback(str(data), "1.0.5")
    # and a rollback to 1.0.6 or later never looks
    _v2_package(home / ".local", "2.2.4")
    migrations.check_opencode_rollback(str(data), "1.0.6")
