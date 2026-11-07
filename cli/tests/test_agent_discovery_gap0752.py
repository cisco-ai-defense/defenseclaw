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

"""GAP-0752: discovery reads the version of a configured connector whose cached
record is missing (the scan ran before setup) or older than its executable."""

from __future__ import annotations

import os
import time
from datetime import timedelta
from pathlib import Path

import pytest
from defenseclaw.inventory import agent_discovery as ad

_CONFIG = "guardrail:\n  enabled: true\n  connector: codex\n  connectors:\n    codex:\n      enabled: true\n"


def _signal(name: str, *, binary: str = "", version: str = "", error: str = "") -> ad.AgentSignal:
    return ad.AgentSignal(
        name=name,
        installed=bool(binary),
        config_path="",
        binary_path=binary,
        version=version,
        error=error,
    )


def _seed(tmp_path: Path, codex: ad.AgentSignal, *, age: timedelta = timedelta(hours=1), config: str = _CONFIG) -> None:
    (tmp_path / "config.yaml").write_text(config, encoding="utf-8")
    agents = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    agents["codex"] = codex
    scanned = ad._format_rfc3339(ad._now_utc() - age)
    assert ad._write_cache(ad.AgentDiscovery(scanned_at=scanned, agents=agents, cache_hit=False), data_dir=tmp_path)


def _scan_returning(version: str, calls: list[str]):
    def scan(name, **kwargs):
        calls.append(name)
        if name == "codex":
            return _signal(name, binary="/opt/codex/bin/codex", version=version)
        return _signal(name)

    return scan


@pytest.fixture(autouse=True)
def _posix_trust(monkeypatch):
    monkeypatch.setattr(ad, "_is_windows_host", lambda: False)


def _launch_order(monkeypatch, *candidates: Path) -> None:
    monkeypatch.setattr(ad, "_binary_candidates_for_agent", lambda name, spec: tuple(str(c) for c in candidates))


def test_a_configured_connector_never_probed_is_probed_by_the_next_discovery(monkeypatch, tmp_path):
    # Fresh account: the scan init ran cached codex before config.yaml named it.
    _seed(tmp_path, _signal("codex", binary="/opt/codex/bin/codex", error=ad.VERSION_NOT_PROBED))
    calls: list[str] = []
    monkeypatch.setattr(ad, "_scan_agent", _scan_returning("codex-cli 0.160.0", calls))

    disc = ad.discover_agents(data_dir=tmp_path)

    assert disc.agents["codex"].version == "codex-cli 0.160.0"
    assert ad._read_cache(data_dir=tmp_path).agents["codex"].version == "codex-cli 0.160.0"


def test_an_updated_executable_is_probed_again(monkeypatch, tmp_path):
    binary = tmp_path / "codex"
    binary.write_text("#!/bin/sh\n")
    # The scan is an hour old; the executable was replaced after it.
    _launch_order(monkeypatch, binary)
    _seed(tmp_path, _signal("codex", binary=str(binary), version="codex-cli 0.160.0"))
    calls: list[str] = []
    monkeypatch.setattr(ad, "_scan_agent", _scan_returning("codex-cli 0.167.0", calls))

    disc = ad.discover_agents(data_dir=tmp_path)

    assert disc.agents["codex"].version == "codex-cli 0.167.0"


def test_an_unchanged_executable_keeps_the_cached_version_without_a_probe(monkeypatch, tmp_path):
    binary = tmp_path / "codex"
    binary.write_text("#!/bin/sh\n")
    # Benign twin: the scan is newer than the executable.
    _seed(
        tmp_path,
        _signal("codex", binary=str(binary), version="codex-cli 0.160.0"),
        age=-timedelta(minutes=5),
    )
    _launch_order(monkeypatch, binary)
    monkeypatch.setattr(ad, "_scan_agent", lambda name, **_k: (_ for _ in ()).throw(AssertionError(name)))

    disc = ad.discover_agents(data_dir=tmp_path)

    assert disc.cache_hit is True
    assert disc.agents["codex"].version == "codex-cli 0.160.0"


def test_a_connector_nobody_set_up_is_never_probed(monkeypatch, tmp_path):
    # Balanced cost: an installed agent that is not enrolled stays unprobed (GAP-0901).
    _seed(
        tmp_path,
        _signal("codex", binary="/opt/codex/bin/codex", error=ad.VERSION_NOT_PROBED),
        config="guardrail:\n  enabled: true\n  connector: claude-code\n",
    )
    monkeypatch.setattr(ad, "_scan_agent", lambda name, **_k: (_ for _ in ()).throw(AssertionError(name)))

    disc = ad.discover_agents(data_dir=tmp_path)

    assert disc.cache_hit is True
    assert disc.agents["codex"].version == ""


def test_a_probe_that_already_failed_is_not_repeated_on_every_call(monkeypatch, tmp_path):
    _seed(tmp_path, _signal("codex", binary="/opt/codex/bin/codex", error=ad.VERSION_PROBE_TIMED_OUT))
    monkeypatch.setattr(ad, "_scan_agent", lambda name, **_k: (_ for _ in ()).throw(AssertionError(name)))

    assert ad.discover_agents(data_dir=tmp_path).cache_hit is True


def test_an_unprobed_connector_with_no_install_is_left_alone(monkeypatch, tmp_path):
    _seed(tmp_path, _signal("codex"))
    monkeypatch.setattr(ad, "_scan_agent", lambda name, **_k: (_ for _ in ()).throw(AssertionError(name)))

    assert ad.discover_agents(data_dir=tmp_path).cache_hit is True


def test_a_link_switched_to_another_installed_version_is_probed_again(monkeypatch, tmp_path):
    # The link moves to a file that was installed (and last written) long
    # before the scan, so the file itself looks unchanged.
    old, new = tmp_path / "codex-0.160", tmp_path / "codex-0.167"
    old.write_text("#!/bin/sh\n")
    new.write_text("#!/bin/sh\n")
    link = tmp_path / "codex"
    link.symlink_to(old)
    time.sleep(1.2)
    _launch_order(monkeypatch, link)
    _seed(tmp_path, _signal("codex", binary=str(link), version="codex-cli 0.160.0"), age=timedelta(0))
    switched = tmp_path / "switched"
    switched.symlink_to(new)
    os.replace(switched, link)
    calls: list[str] = []
    monkeypatch.setattr(ad, "_scan_agent", _scan_returning("codex-cli 0.167.0", calls))

    disc = ad.discover_agents(data_dir=tmp_path)

    assert disc.agents["codex"].version == "codex-cli 0.167.0"
    assert "codex" in calls


def test_a_link_that_did_not_move_keeps_the_cached_version(monkeypatch, tmp_path):
    old = tmp_path / "codex-0.160"
    old.write_text("#!/bin/sh\n")
    link = tmp_path / "codex"
    link.symlink_to(old)
    _launch_order(monkeypatch, link)
    _seed(tmp_path, _signal("codex", binary=str(link), version="codex-cli 0.160.0"), age=-timedelta(minutes=5))
    monkeypatch.setattr(ad, "_scan_agent", lambda name, **_k: (_ for _ in ()).throw(AssertionError(name)))

    disc = ad.discover_agents(data_dir=tmp_path)

    assert disc.cache_hit is True
    assert disc.agents["codex"].version == "codex-cli 0.160.0"


def test_a_new_executable_ahead_in_launch_order_is_probed(monkeypatch, tmp_path):
    old, new = tmp_path / "codex-old", tmp_path / "codex-new"
    old.write_text("#!/bin/sh\n")
    _seed(tmp_path, _signal("codex", binary=str(old), version="codex-cli 0.160.0"), age=-timedelta(minutes=5))
    new.write_text("#!/bin/sh\n")
    _launch_order(monkeypatch, new, old)
    calls: list[str] = []
    monkeypatch.setattr(ad, "_scan_agent", _scan_returning("codex-cli 0.167.0", calls))

    disc = ad.discover_agents(data_dir=tmp_path)

    assert disc.agents["codex"].version == "codex-cli 0.167.0"
    assert "codex" in calls


def test_an_executable_that_left_the_launch_order_is_probed(monkeypatch, tmp_path):
    old = tmp_path / "codex-old"
    old.write_text("#!/bin/sh\n")
    _seed(tmp_path, _signal("codex", binary=str(old), version="codex-cli 0.160.0"), age=-timedelta(minutes=5))
    _launch_order(monkeypatch)
    calls: list[str] = []
    monkeypatch.setattr(ad, "_scan_agent", _scan_returning("", calls))

    ad.discover_agents(data_dir=tmp_path)

    assert "codex" in calls


def test_publishing_one_agent_keeps_every_peer_entry(tmp_path):
    peers = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    peers["cursor"] = _signal("cursor", binary="/opt/cursor/bin/cursor", version="3.19.13")
    peers["codex"] = _signal("codex", binary="/opt/codex/bin/codex", error=ad.VERSION_NOT_PROBED)
    scanned = ad._format_rfc3339(ad._now_utc() - timedelta(minutes=5))
    assert ad._write_cache(ad.AgentDiscovery(scanned_at=scanned, agents=peers, cache_hit=False), data_dir=tmp_path)
    # The fresh scan versioned codex but missed cursor.
    fresh = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    fresh["codex"] = _signal("codex", binary="/opt/codex/bin/codex", version="codex-cli 0.160.0")

    assert ad._publish_agent_signal(
        ad.AgentDiscovery(scanned_at=ad._format_rfc3339(ad._now_utc()), agents=fresh, cache_hit=False),
        "codex",
        data_dir=tmp_path,
    )

    cache = ad._read_cache(data_dir=tmp_path)
    assert cache.agents["codex"].version == "codex-cli 0.160.0"
    assert cache.agents["cursor"].version == "3.19.13"
    assert cache.scanned_at == scanned


def test_publishing_with_no_cache_takes_the_scan(tmp_path):
    fresh = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    fresh["codex"] = _signal("codex", binary="/opt/codex/bin/codex", version="codex-cli 0.160.0")

    assert ad._publish_agent_signal(
        ad.AgentDiscovery(scanned_at=ad._format_rfc3339(ad._now_utc()), agents=fresh, cache_hit=False),
        "codex",
        data_dir=tmp_path,
    )

    assert ad._read_cache(data_dir=tmp_path).agents["codex"].version == "codex-cli 0.160.0"
