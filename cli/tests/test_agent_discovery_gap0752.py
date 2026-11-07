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
import threading
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


def _skipped_link_cache(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    """Cache whose selected codex sits behind a skipped (failed) earlier link."""
    ahead, picked, data = tmp_path / "ahead", tmp_path / "picked", tmp_path / "data"
    for folder in (ahead, picked, data):
        folder.mkdir()
    failed, working, selected = ahead / "codex-0.150", ahead / "codex-0.167", picked / "codex"
    for path in (failed, working, selected):
        path.write_text("#!/bin/sh\n")
    link = ahead / "codex"
    link.symlink_to(failed)
    time.sleep(1.2)
    codex = _signal("codex", binary=str(selected), version="codex-cli 0.160.0")
    codex.skipped_binaries = (str(link),)
    _seed(data, codex, age=timedelta(0))
    time.sleep(1.2)
    return link, working, selected, data


def test_a_skipped_link_switched_to_another_installed_version_is_probed_again(monkeypatch, tmp_path):
    # The earlier launch candidate failed its version probe at scan time. The
    # link now points at a codex installed long before the scan, so neither
    # the target file nor the selected binary look changed.
    link, working, selected, data = _skipped_link_cache(tmp_path)
    _launch_order(monkeypatch, link, selected)
    switched = link.parent / "switched"
    switched.symlink_to(working)
    os.replace(switched, link)
    calls: list[str] = []
    monkeypatch.setattr(ad, "_scan_agent", _scan_returning("codex-cli 0.167.0", calls))

    disc = ad.discover_agents(data_dir=data)

    assert disc.cache_hit is False
    assert disc.agents["codex"].version == "codex-cli 0.167.0"
    assert "codex" in calls


def test_a_skipped_link_that_did_not_move_keeps_the_cached_version(monkeypatch, tmp_path):
    link, _working, selected, data = _skipped_link_cache(tmp_path)
    _launch_order(monkeypatch, link, selected)
    monkeypatch.setattr(ad, "_scan_agent", lambda name, **_k: (_ for _ in ()).throw(AssertionError(name)))

    disc = ad.discover_agents(data_dir=data)

    assert disc.cache_hit is True
    assert disc.agents["codex"].version == "codex-cli 0.160.0"


def test_publishing_one_agent_replaces_a_peer_the_scan_read_at_another_version(tmp_path):
    # Both directions: a successfully read peer is the newer fact, so the
    # gateway admits the version the machine runs now, not the old record.
    for before, after in (("3.19.13", "cursor 2.3.99"), ("cursor 2.3.99", "3.19.13")):
        data = tmp_path / after.replace(" ", "-")
        data.mkdir()
        peers = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
        peers["cursor"] = _signal("cursor", binary="/opt/cursor/bin/cursor", version=before)
        scanned = ad._format_rfc3339(ad._now_utc() - timedelta(minutes=5))
        assert ad._write_cache(ad.AgentDiscovery(scanned_at=scanned, agents=peers, cache_hit=False), data_dir=data)
        fresh = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
        fresh["codex"] = _signal("codex", binary="/opt/codex/bin/codex", version="codex-cli 0.160.0")
        fresh["cursor"] = _signal("cursor", binary="/opt/cursor/bin/cursor", version=after)

        assert ad._publish_agent_signal(
            ad.AgentDiscovery(scanned_at=ad._format_rfc3339(ad._now_utc()), agents=fresh, cache_hit=False),
            "codex",
            data_dir=data,
        )

        cache = ad._read_cache(data_dir=data)
        assert cache.agents["cursor"].version == after
        assert cache.agents["codex"].version == "codex-cli 0.160.0"
        assert cache.scanned_at == scanned


def test_publishing_one_agent_keeps_a_peer_the_scan_found_but_did_not_version(tmp_path):
    peers = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    peers["cursor"] = _signal("cursor", binary="/opt/cursor/bin/cursor", version="3.19.13")
    scanned = ad._format_rfc3339(ad._now_utc() - timedelta(minutes=5))
    assert ad._write_cache(ad.AgentDiscovery(scanned_at=scanned, agents=peers, cache_hit=False), data_dir=tmp_path)
    fresh = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    fresh["codex"] = _signal("codex", binary="/opt/codex/bin/codex", version="codex-cli 0.160.0")
    fresh["cursor"] = _signal("cursor", binary="/opt/cursor/bin/cursor", error=ad.VERSION_NOT_PROBED)

    assert ad._publish_agent_signal(
        ad.AgentDiscovery(scanned_at=ad._format_rfc3339(ad._now_utc()), agents=fresh, cache_hit=False),
        "codex",
        data_dir=tmp_path,
    )

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == "3.19.13"


def _cursor_cache(data: Path, version: str, *, seconds_old: int) -> str:
    peers = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    peers["cursor"] = _signal("cursor", binary="/opt/cursor/bin/cursor", version=version)
    scanned = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=seconds_old))
    assert ad._write_cache(ad.AgentDiscovery(scanned_at=scanned, agents=peers, cache_hit=False), data_dir=data)
    return scanned


def _scan(*, seconds_old: int, cursor: str, codex: str = "codex-cli 0.160.0") -> ad.AgentDiscovery:
    agents = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    agents["codex"] = _signal("codex", binary="/opt/codex/bin/codex", version=codex)
    agents["cursor"] = _signal("cursor", binary="/opt/cursor/bin/cursor", version=cursor)
    scanned = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=seconds_old))
    return ad.AgentDiscovery(scanned_at=scanned, agents=agents, cache_hit=False)


def test_publishing_an_older_scan_keeps_a_peer_a_newer_scan_cached(tmp_path):
    # Setup A scanned three seconds ago; discovery B wrote the cache one second
    # ago. A ends last and must not put its older reading back, whichever way
    # the version moved: one direction would admit a changed agent, the other
    # would block a good one.
    for newer, older in (("3.19.13", "cursor 2.3.99"), ("cursor 2.3.99", "3.19.13")):
        data = tmp_path / older.replace(" ", "-")
        data.mkdir()
        _cursor_cache(data, newer, seconds_old=1)

        assert ad._publish_agent_signal(_scan(seconds_old=3, cursor=older), "codex", data_dir=data)

        cache = ad._read_cache(data_dir=data)
        assert cache.agents["cursor"].version == newer
        assert cache.agents["codex"].version == "codex-cli 0.160.0"


def test_a_peer_published_by_a_newer_scan_is_not_replaced_by_an_older_publish(tmp_path):
    # The file time stays at the first scan, so the order of each entry is its own.
    _cursor_cache(tmp_path, "3.19.0", seconds_old=300)
    assert ad._publish_agent_signal(_scan(seconds_old=1, cursor="3.19.13"), "codex", data_dir=tmp_path)

    assert ad._publish_agent_signal(_scan(seconds_old=3, cursor="cursor 2.3.99"), "codex", data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == "3.19.13"


def test_a_complete_older_scan_keeps_what_a_newer_scan_read(tmp_path):
    _cursor_cache(tmp_path, "3.19.0", seconds_old=300)
    assert ad._publish_agent_signal(_scan(seconds_old=1, cursor="3.19.13"), "codex", data_dir=tmp_path)

    assert ad._write_cache(_scan(seconds_old=3, cursor="cursor 2.3.99", codex="codex-cli 0.150.0"), data_dir=tmp_path)

    cache = ad._read_cache(data_dir=tmp_path)
    assert cache.agents["cursor"].version == "3.19.13"
    assert cache.agents["codex"].version == "codex-cli 0.160.0"


def test_a_complete_newer_scan_replaces_the_cache(tmp_path):
    _cursor_cache(tmp_path, "3.19.0", seconds_old=300)

    assert ad._write_cache(_scan(seconds_old=0, cursor="3.19.13", codex="codex-cli 0.167.0"), data_dir=tmp_path)

    cache = ad._read_cache(data_dir=tmp_path)
    assert cache.agents["cursor"].version == "3.19.13"
    assert cache.agents["codex"].version == "codex-cli 0.167.0"


def test_scans_ending_in_any_order_leave_the_newest_reading(tmp_path):
    _cursor_cache(tmp_path, "3.19.0", seconds_old=300)
    ages = (9, 2, 7, 4, 1, 8, 3, 6)
    barrier = threading.Barrier(len(ages))

    def publish(age: int) -> None:
        scan = _scan(seconds_old=age, cursor=f"cursor-{age}")
        barrier.wait()
        assert ad._publish_agent_signal(scan, "codex", data_dir=tmp_path)

    threads = [threading.Thread(target=publish, args=(age,)) for age in ages]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == "cursor-1"


def test_a_busy_cache_lock_means_no_unserialized_write(monkeypatch, tmp_path):
    from defenseclaw.file_lock import locked_file_update

    _cursor_cache(tmp_path, "3.19.0", seconds_old=300)
    monkeypatch.setattr(ad, "_CACHE_LOCK_SECONDS", 0.2)

    with locked_file_update(str(tmp_path / ad.CACHE_FILENAME)):
        assert ad._publish_agent_signal(_scan(seconds_old=0, cursor="3.19.13"), "codex", data_dir=tmp_path) is False

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == "3.19.0"


def _skipped_candidate_in_folder_cache(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    """Cache whose selected codex sits behind a skipped (failed) candidate that
    is two folders below a folder an installer can replace as a whole."""
    active, spare, picked, data = (tmp_path / name for name in ("active", "spare", "picked", "data"))
    candidate = active / "nested" / "bin" / "codex"
    ready = spare / "nested" / "bin" / "codex"
    selected = picked / "codex"
    for path in (candidate, ready, selected):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n")
    data.mkdir()
    time.sleep(1.2)
    codex = _signal("codex", binary=str(selected), version="codex-cli 0.160.0")
    codex.skipped_binaries = (str(candidate),)
    _seed(data, codex, age=timedelta(0))
    time.sleep(1.2)
    return candidate, active, spare, data


def test_a_skipped_candidate_behind_a_replaced_higher_folder_is_probed_again(monkeypatch, tmp_path):
    # The file and the folder holding it keep their old times when the folder
    # above them is swapped for a ready-made one.
    candidate, active, spare, data = _skipped_candidate_in_folder_cache(tmp_path)
    _launch_order(monkeypatch, candidate, tmp_path / "picked" / "codex")
    os.rename(active, tmp_path / "parked")
    os.rename(spare, active)
    calls: list[str] = []
    monkeypatch.setattr(ad, "_scan_agent", _scan_returning("codex-cli 0.167.0", calls))

    disc = ad.discover_agents(data_dir=data)

    assert disc.cache_hit is False
    assert disc.agents["codex"].version == "codex-cli 0.167.0"
    assert "codex" in calls


def test_a_skipped_candidate_behind_an_untouched_higher_folder_keeps_the_cached_version(monkeypatch, tmp_path):
    # A folder above the data folder changes whenever anything is saved in it
    # and is not part of the install: saving a file there is not a change.
    candidate, _active, _spare, data = _skipped_candidate_in_folder_cache(tmp_path)
    _launch_order(monkeypatch, candidate, tmp_path / "picked" / "codex")
    (tmp_path / "unrelated.txt").write_text("saved\n")
    monkeypatch.setattr(ad, "_scan_agent", lambda name, **_k: (_ for _ in ()).throw(AssertionError(name)))

    disc = ad.discover_agents(data_dir=data)

    assert disc.cache_hit is True
    assert disc.agents["codex"].version == "codex-cli 0.160.0"


def test_an_installed_executable_behind_a_replaced_higher_folder_is_probed_again(monkeypatch, tmp_path):
    # The same rule for the selected executable, not only a skipped one.
    candidate, active, spare, data = _skipped_candidate_in_folder_cache(tmp_path)
    selected = active / "nested" / "bin" / "codex"
    codex = _signal("codex", binary=str(selected), version="codex-cli 0.160.0")
    time.sleep(1.2)
    _seed(data, codex, age=timedelta(0))
    time.sleep(1.2)
    _launch_order(monkeypatch, selected)
    os.rename(active, tmp_path / "parked")
    os.rename(spare, active)
    calls: list[str] = []
    monkeypatch.setattr(ad, "_scan_agent", _scan_returning("codex-cli 0.167.0", calls))

    disc = ad.discover_agents(data_dir=data)

    assert disc.cache_hit is False
    assert disc.agents["codex"].version == "codex-cli 0.167.0"


# Round 5: entries are ordered by when each version was read.


def _read_scan(*, started_ago: float, read_ago: float, cursor: str, codex: str = "codex-cli 0.160.0") -> ad.AgentDiscovery:
    """A scan that began *started_ago* seconds ago and read the Cursor version
    *read_ago* seconds ago (a scan reads its connectors one after another)."""
    disc = _scan(seconds_old=0, cursor=cursor, codex=codex)
    now = ad._now_utc()
    disc.scanned_at = ad._format_rfc3339(now - timedelta(seconds=started_ago))
    for signal in disc.agents.values():
        signal.observed_at = ad._format_rfc3339(now - timedelta(seconds=read_ago))
    return disc


def _slug(version: str) -> str:
    return version.replace(chr(32), chr(45))


_VERSION_PAIRS = (("3.19.13", "cursor 2.3.99"), ("cursor 2.3.99", "3.19.13"))


def test_a_scan_that_started_first_but_read_later_keeps_its_reading(tmp_path):
    # Scan A started three seconds ago and read Cursor half a second ago; scan B
    # started one second ago and read it two seconds ago. B publishes first and
    # A last. A holds the later reading, whichever way the version moved.
    for later, earlier in _VERSION_PAIRS:
        for writer in ("publish", "write"):
            data = tmp_path / f"{writer}-{_slug(later)}"
            data.mkdir()
            scan_b = _read_scan(started_ago=1, read_ago=2, cursor=earlier)
            scan_a = _read_scan(started_ago=3, read_ago=0.5, cursor=later)
            assert ad._write_cache(scan_b, data_dir=data)

            if writer == "publish":
                assert ad._publish_agent_signal(scan_a, "codex", data_dir=data)
            else:
                assert ad._write_cache(scan_a, data_dir=data)

            assert ad._read_cache(data_dir=data).agents["cursor"].version == later


def test_a_scan_that_started_later_but_read_earlier_does_not_replace_a_later_reading(tmp_path):
    for later, earlier in _VERSION_PAIRS:
        for writer in ("publish", "write"):
            data = tmp_path / f"{writer}-{_slug(later)}"
            data.mkdir()
            assert ad._write_cache(_read_scan(started_ago=3, read_ago=0.5, cursor=later), data_dir=data)
            late_start = _read_scan(started_ago=1, read_ago=2, cursor=earlier)

            if writer == "publish":
                assert ad._publish_agent_signal(late_start, "codex", data_dir=data)
            else:
                assert ad._write_cache(late_start, data_dir=data)

            assert ad._read_cache(data_dir=data).agents["cursor"].version == later


def test_scans_started_in_one_second_are_ordered_by_their_readings(tmp_path):
    # Benign twin of the order tests: nothing is held back when the later
    # reading arrives last; and the same second is no longer a tie.
    for later, earlier in _VERSION_PAIRS:
        for first, second in (("later", "earlier"), ("earlier", "later")):
            data = tmp_path / f"{first}-{_slug(later)}"
            data.mkdir()
            start = ad._now_utc().replace(microsecond=0)
            scans = {
                "earlier": _read_scan(started_ago=0, read_ago=0, cursor=earlier),
                "later": _read_scan(started_ago=0, read_ago=0, cursor=later),
            }
            for scan, offset in ((scans["earlier"], 100), (scans["later"], 900)):
                stamp = ad._format_rfc3339(start + timedelta(milliseconds=offset))
                scan.scanned_at = stamp
                for signal in scan.agents.values():
                    signal.observed_at = stamp
            assert ad._write_cache(scans[first], data_dir=data)
            assert ad._publish_agent_signal(scans[second], "codex", data_dir=data)

            assert ad._read_cache(data_dir=data).agents["cursor"].version == later


def test_first_writers_on_a_fresh_account_are_serialized_and_ordered(monkeypatch, tmp_path):
    # Two scans both see no data folder. The one holding the earlier reading
    # reaches the write second; it must not put its reading over the later one.
    for later, earlier in _VERSION_PAIRS:
        data = tmp_path / f"fresh-{_slug(later)}" / "data"
        scans = {
            "later": _read_scan(started_ago=3, read_ago=0.5, cursor=later),
            "earlier": _read_scan(started_ago=1, read_ago=2, cursor=earlier),
        }
        writing = {"now": 0, "most": 0}
        guard = threading.Lock()
        real_write = ad.atomic_write_private_bytes
        newer_has_begun = threading.Event()

        def slow_write(path, body, _real=real_write, _writing=writing, _guard=guard, _begun=newer_has_begun):
            with _guard:
                _writing["now"] += 1
                _writing["most"] = max(_writing["most"], _writing["now"])
            _begun.set()
            time.sleep(0.2)
            try:
                _real(path, body)
            finally:
                with _guard:
                    _writing["now"] -= 1

        monkeypatch.setattr(ad, "atomic_write_private_bytes", slow_write)
        results: dict[str, bool] = {}

        def run(label: str) -> None:
            results[label] = ad._write_cache(scans[label], data_dir=data)

        first = threading.Thread(target=run, args=("later",))
        second = threading.Thread(target=run, args=("earlier",))
        first.start()
        assert newer_has_begun.wait(timeout=5)
        second.start()
        first.join(timeout=20)
        second.join(timeout=20)

        assert results == {"later": True, "earlier": True}
        assert writing["most"] == 1
        assert ad._read_cache(data_dir=data).agents["cursor"].version == later
        if os.name != "nt":
            assert (data.stat().st_mode & 0o077) == 0
        monkeypatch.setattr(ad, "atomic_write_private_bytes", real_write)


def test_a_probe_stamps_when_the_version_was_read(monkeypatch, tmp_path):
    binary = tmp_path / "codex"
    binary.write_text("#!/bin/sh\n")
    monkeypatch.setattr(ad, "_binary_candidates_for_agent", lambda name, spec: (str(binary),))
    monkeypatch.setattr(ad, "_version_for_binary", lambda *_a, **_k: ("codex-cli 0.167.0", ""))
    before = ad._now_utc()

    signal = ad._scan_agent("codex", data_dir=tmp_path, require_trusted_binary_paths=False)

    read_at = ad._parse_rfc3339(signal.observed_at)
    assert signal.version == "codex-cli 0.167.0"
    assert read_at is not None and before <= read_at <= ad._now_utc()


def test_a_kept_version_keeps_the_time_it_was_read(monkeypatch, tmp_path):
    binary = tmp_path / "codex"
    binary.write_text("#!/bin/sh\n")
    cached = _signal("codex", binary=str(binary), version="codex-cli 0.160.0")
    cached.observed_at = ad._format_rfc3339(ad._now_utc() - timedelta(minutes=3))
    # The scan that read it is newer than the executable.
    _seed(tmp_path, cached, age=-timedelta(minutes=5))
    agents = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    agents["codex"] = _signal("codex", binary=str(binary), error=ad.VERSION_NOT_PROBED)

    ad._keep_versions_of_slow_unchanged_agents(agents, data_dir=tmp_path)

    assert agents["codex"].version == "codex-cli 0.160.0"
    assert agents["codex"].observed_at == cached.observed_at


def test_two_overlapping_discoveries_leave_the_version_read_last(monkeypatch, tmp_path):
    # End to end through the real scan: discovery A starts first and is held at
    # its Cursor probe; discovery B starts, reads Cursor and publishes; A then
    # reads Cursor and publishes last. A holds the later reading in either
    # direction of the version change.
    binary = tmp_path / "cursor"
    binary.write_text("#!/bin/sh\n")
    for later, earlier in _VERSION_PAIRS:
        data = tmp_path / f"overlap-{_slug(later)}"
        data.mkdir()
        monkeypatch.setattr(ad, "_ai_discovery_trust_config", lambda _d: (False, []))
        monkeypatch.setattr(ad, "_configured_probe_names", lambda _d: frozenset({"cursor"}))
        monkeypatch.setattr(
            ad,
            "_binary_candidates_for_agent",
            lambda name, spec: (str(binary),) if name == "cursor" else (),
        )
        calls: list[str] = []
        lock = threading.Lock()
        a_in_probe, b_done = threading.Event(), threading.Event()

        def version_for_binary(*_args, _calls=calls, _lock=lock, _in=a_in_probe, _done=b_done, **_kw):
            with _lock:
                _calls.append("probe")
                mine = len(_calls)
            if mine == 1:  # discovery A
                _in.set()
                assert _done.wait(timeout=10)
                return later, ""
            return earlier, ""

        monkeypatch.setattr(ad, "_version_for_agent_binary", version_for_binary)
        a = threading.Thread(target=lambda: ad.discover_agents(use_cache=False, refresh=True, data_dir=data))
        a.start()
        assert a_in_probe.wait(timeout=10)
        time.sleep(1.1)  # B starts in a later second than A
        ad.discover_agents(use_cache=False, refresh=True, data_dir=data)
        b_done.set()
        a.join(timeout=20)
        assert not a.is_alive()

        assert ad._read_cache(data_dir=data).agents["cursor"].version == later


# Round 6: the time is taken when the probe answers, and a later unread
# result is a reading too.


def _discover_with_a_held_scan(monkeypatch, tmp_path, data, answers, *, change_binary=None):
    """Discovery A reads Cursor first and is then held in the probe-state
    bookkeeping that follows the probes; discovery B (started a second later)
    reads and publishes; A is then released and publishes last. *answers* are
    the probe replies in order: A, then B."""
    binary = tmp_path / "cursor"
    binary.write_text("old executable")
    held, released = threading.Event(), threading.Event()
    guard = threading.Lock()
    count = {"probes": 0, "bookkeeping": 0}
    errors: list[str] = []

    def probe(*_args, **_kwargs):
        with guard:
            count["probes"] += 1
            return answers[count["probes"] - 1]

    def record_state(*_args, **_kwargs):
        with guard:
            count["bookkeeping"] += 1
            mine = count["bookkeeping"]
        if mine == 1:
            held.set()
            assert released.wait(timeout=10)

    def first_discovery():
        try:
            ad.discover_agents(use_cache=False, refresh=True, data_dir=data)
        except BaseException as exc:  # reported below, never lost in the thread
            errors.append(repr(exc))

    monkeypatch.setattr(ad, "_ai_discovery_trust_config", lambda _d: (False, []))
    monkeypatch.setattr(ad, "_configured_probe_names", lambda _d: frozenset({"cursor"}))
    monkeypatch.setattr(
        ad, "_binary_candidates_for_agent", lambda name, spec: (str(binary),) if name == "cursor" else ()
    )
    monkeypatch.setattr(ad, "_version_for_agent_binary", probe)
    monkeypatch.setattr(
        ad,
        "_missing_probe_state",
        lambda name: ([str(tmp_path / "created-by-probe")], []) if name == "cursor" else ([], []),
    )
    monkeypatch.setattr(ad, "_record_probe_state", record_state)
    first = threading.Thread(target=first_discovery)
    first.start()
    assert held.wait(timeout=10)
    if change_binary:
        binary.write_text("updated executable")
    time.sleep(1.1)  # B starts in a later second than A
    later = ad.discover_agents(use_cache=False, refresh=True, data_dir=data)
    released.set()
    first.join(timeout=20)
    assert not first.is_alive() and not errors, errors
    return later


def test_a_version_read_before_a_delayed_publish_does_not_replace_a_later_reading(monkeypatch, tmp_path):
    # A reads its Cursor version, then waits on bookkeeping; B reads and
    # writes meanwhile. The stamp is the time of the read, so A, writing last,
    # still loses to B in either direction of the version change.
    for earlier, later_version in _VERSION_PAIRS:
        data = tmp_path / f"post-{_slug(later_version)}"
        data.mkdir()
        later = _discover_with_a_held_scan(
            monkeypatch, tmp_path, data, [(earlier, ""), (later_version, "")]
        )

        assert later.agents["cursor"].version == later_version
        assert ad._read_cache(data_dir=data).agents["cursor"].version == later_version


def test_the_stamp_is_the_time_the_selected_binary_answered_not_the_end_of_the_scan(monkeypatch, tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("#!/bin/sh\n")
    monkeypatch.setattr(ad, "_binary_candidates_for_agent", lambda name, spec: (str(binary),))
    answered: list[object] = []

    def probe(*_args, **_kwargs):
        answered.append(ad._now_utc())
        return "3.19.13", ""

    monkeypatch.setattr(ad, "_version_for_agent_binary", probe)
    monkeypatch.setattr(ad, "_missing_probe_state", lambda name: ([str(tmp_path / "made")], []))
    monkeypatch.setattr(ad, "_record_probe_state", lambda *_a, **_k: time.sleep(0.3))

    signal = ad._scan_agent("cursor", data_dir=tmp_path)

    stamp = ad._parse_rfc3339(signal.observed_at)
    assert stamp is not None and answered[0] <= stamp < answered[0] + timedelta(seconds=0.2)


def _unread_scan(*, read_ago: float, version: str, error: str, binary: str = "/opt/cursor/bin/cursor") -> ad.AgentDiscovery:
    disc = _scan(seconds_old=0, cursor=version)
    disc.agents["cursor"] = _signal("cursor", binary=binary, version=version, error=error)
    stamp = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=read_ago))
    disc.scanned_at = stamp
    for signal in disc.agents.values():
        signal.observed_at = stamp
    return disc


def test_a_later_unread_result_is_not_replaced_by_an_older_known_version(tmp_path):
    for writer in ("publish", "write"):
        data = tmp_path / writer
        data.mkdir()
        old = _unread_scan(read_ago=2, version="3.19.13", error="")
        updated = _unread_scan(read_ago=1, version="", error=ad.VERSION_PROBE_TIMED_OUT)
        assert ad._write_cache(updated, data_dir=data)

        if writer == "publish":
            assert ad._publish_agent_signal(old, "codex", data_dir=data)
        else:
            assert ad._write_cache(old, data_dir=data)

        cursor = ad._read_cache(data_dir=data).agents["cursor"]
        assert (cursor.version, cursor.error) == ("", ad.VERSION_PROBE_TIMED_OUT)


def test_a_later_known_version_replaces_an_earlier_unread_result_in_any_order(tmp_path):
    for writer in ("publish", "write"):
        data = tmp_path / writer
        data.mkdir()
        unread = _unread_scan(read_ago=2, version="", error=ad.VERSION_PROBE_TIMED_OUT)
        known = _unread_scan(read_ago=1, version="3.19.13", error="")
        assert ad._write_cache(unread, data_dir=data)

        if writer == "publish":
            assert ad._publish_agent_signal(known, "codex", data_dir=data)
        else:
            assert ad._write_cache(known, data_dir=data)

        assert ad._read_cache(data_dir=data).agents["cursor"].version == "3.19.13"


def test_an_entry_never_probed_does_not_hold_back_an_older_known_version(tmp_path):
    data = tmp_path
    unprobed = _unread_scan(read_ago=1, version="", error=ad.VERSION_NOT_PROBED)
    known = _unread_scan(read_ago=2, version="3.19.13", error="")
    assert ad._write_cache(unprobed, data_dir=data)

    assert ad._write_cache(known, data_dir=data)

    assert ad._read_cache(data_dir=data).agents["cursor"].version == "3.19.13"


def test_an_executable_replaced_between_two_discoveries_leaves_the_later_unread_result(monkeypatch, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    later = _discover_with_a_held_scan(
        monkeypatch,
        tmp_path,
        data,
        # A timed-out probe is asked once more before it is called slow.
        [("3.19.13", ""), ("", ad.VERSION_PROBE_TIMED_OUT), ("", ad.VERSION_PROBE_TIMED_OUT)],
        change_binary=True,
    )

    final = ad._read_cache(data_dir=data).agents["cursor"]
    assert later.agents["cursor"].installed and later.agents["cursor"].version == ""
    assert (final.installed, final.version) == (True, "")
    assert final.error.endswith(ad.VERSION_PROBE_TIMED_OUT)
