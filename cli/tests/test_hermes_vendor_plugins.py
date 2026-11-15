# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""rel-1-0-10:GAP-0765: the gateway recognizes the shipped plugins of every
Hermes release a hook contract covers, and doctor and status say plainly when
the installed Hermes is newer than all of them."""

from __future__ import annotations

from types import SimpleNamespace

from defenseclaw.commands import cmd_doctor, cmd_status
from defenseclaw.commands.cmd_doctor import _DoctorResult
from defenseclaw.connector_contracts import normalize_agent_version, resolve_connector_contract
from defenseclaw.hermes_vendor_plugin_releases import NEWEST_PLUGIN_COUNT, RELEASES
from defenseclaw.hermes_vendor_plugins import COVERED, NEWER, OTHER, shipped_plugin_coverage


def test_digest_sets_cover_each_contract_release_from_its_tag():
    versions = [version for version, _tag, _commit in RELEASES]
    # The update that raised the gap: 0.21.5 (v2026.9.24) to 0.23.1.
    assert {"0.21.5", "0.23.1"} <= set(versions)
    assert versions == sorted(versions, key=lambda v: tuple(int(p) for p in v.split(".")))
    assert NEWEST_PLUGIN_COUNT > 0
    for version, tag, commit in RELEASES:
        assert resolve_connector_contract("hermes", version).status == "known", version
        assert len(commit) == 40 and int(commit, 16) >= 0
        # A semver tag names the version; a date tag carries its own date.
        assert tag[1:] == version or normalize_agent_version(tag).startswith("20")


def test_installed_release_is_covered():
    for raw in (
        "Hermes Agent v0.23.1 (2026.9.24)",
        "Hermes Agent v0.20.3 (2026.8.16.2)",
        "Hermes Agent vunknown (2026.9.24)",
    ):
        coverage = shipped_plugin_coverage(raw)
        assert coverage.state == COVERED, raw
        assert "not scanned" in coverage.detail and "an edited one is scanned" in coverage.detail


def test_hermes_newer_than_every_release_says_what_happens_and_what_to_do():
    newest = RELEASES[-1][0]
    major, minor, _patch = (int(p) for p in newest.split("."))
    newer = f"{major}.{minor + 1}.0"
    coverage = shipped_plugin_coverage(f"Hermes Agent v{newer} (2026.9.24)")
    assert coverage.state == NEWER
    assert f"Hermes {newer} is newer than every Hermes release" in coverage.detail
    assert f"newest {newest}" in coverage.detail
    assert "scans each one as an unknown plugin" in coverage.detail
    assert "HIGH finding" in coverage.detail
    assert f"covers Hermes {newer}" in coverage.step and "defenseclaw upgrade" in coverage.step


def test_release_outside_the_digest_sets_is_named():
    assert shipped_plugin_coverage("Hermes Agent v0.18.2 (2026.7.7.2)").state == OTHER
    assert shipped_plugin_coverage("").state == ""


def test_doctor_warns_for_a_hermes_newer_than_every_digest_set(monkeypatch):
    monkeypatch.setattr(cmd_doctor, "_gateway_store_unknown", lambda cfg: False)
    monkeypatch.setattr(cmd_doctor, "_gateway_store_dir", lambda cfg: "/nonexistent")
    rows = {}
    for raw in ("Hermes Agent v99.0.0 (2026.9.24)", "Hermes Agent v0.23.1 (2026.9.24)"):
        monkeypatch.setattr(cmd_doctor, "_agent_version_now", lambda data_dir, connector, raw=raw: (raw, True))
        result = _DoctorResult(passive=True, quiet=True)
        cmd_doctor._check_hermes_shipped_plugins(SimpleNamespace(), result)
        rows[raw] = next(row for row in result.checks if row["label"] == "Hermes shipped plugins")
    newer = rows["Hermes Agent v99.0.0 (2026.9.24)"]
    assert newer["status"] == "warn"
    assert "newer than every Hermes release" in newer["detail"]
    assert "unknown plugin" in newer["detail"] and "defenseclaw upgrade" in newer["remediation"]
    assert rows["Hermes Agent v0.23.1 (2026.9.24)"]["status"] == "pass"


def test_status_note_only_when_hermes_is_not_covered(monkeypatch):
    from defenseclaw.inventory import agent_discovery

    def cache(version):
        hermes = SimpleNamespace(installed=True, version=version)
        return lambda data_dir=None: SimpleNamespace(agents={"hermes": hermes})

    monkeypatch.setattr(agent_discovery, "_read_cache", cache("Hermes Agent v99.0.0 (2026.9.24)"))
    note = cmd_status._hermes_shipped_plugins_note(SimpleNamespace(data_dir="/nonexistent"))
    assert note.startswith("Hermes shipped plugins: Hermes 99.0.0 is newer than every Hermes release")
    assert "defenseclaw upgrade" in note
    monkeypatch.setattr(agent_discovery, "_read_cache", cache("Hermes Agent v0.23.1 (2026.9.24)"))
    assert cmd_status._hermes_shipped_plugins_note(SimpleNamespace(data_dir="/nonexistent")) == ""
