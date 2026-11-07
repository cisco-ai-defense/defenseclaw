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

import atexit
import ctypes
import json
import os
import shutil
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

import pytest
from defenseclaw.inventory import agent_discovery as ad

#: A file system stamps a write with its coarse clock (about 16 ms on NTFS), so
#: two writes closer together than one tick can carry the same change time.
_FILE_CLOCK_TICK = 0.05

_CONFIG = "guardrail:\n  enabled: true\n  connector: codex\n  connectors:\n    codex:\n      enabled: true\n"


#: The cursor executable of the cache-ordering cases is a real file: a cached
#: version belongs to an executable that is there, so a recorded path that is
#: not a file keeps nothing.
_PEERS = Path(tempfile.mkdtemp(prefix="g752-peers-"))
atexit.register(shutil.rmtree, _PEERS, ignore_errors=True)
_CURSOR = str(_PEERS / "cursor")
Path(_CURSOR).write_text("cursor", encoding="utf-8")


def _cursor_signal(*, version: str = "", error: str = "") -> ad.AgentSignal:
    signal = _signal("cursor", binary=_CURSOR, version=version, error=error)
    signal.identity = ad._executable_identity(_CURSOR)
    return signal


_CODEX = str(_PEERS / "codex")
Path(_CODEX).write_text("codex", encoding="utf-8")


def _codex_signal(*, version: str) -> ad.AgentSignal:
    signal = _signal("codex", binary=_CODEX, version=version)
    signal.identity = ad._executable_identity(_CODEX)
    return signal


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
    if codex.version and not codex.identity and Path(codex.binary_path).is_file():
        # A cache written by this release names the file the version came from.
        codex.identity = ad._executable_identity(codex.binary_path)
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
    binary.write_text("#!/bin/sh\necho updated\n")
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
    peers["cursor"] = _cursor_signal(version="3.19.13")
    peers["codex"] = _signal("codex", binary="/opt/codex/bin/codex", error=ad.VERSION_NOT_PROBED)
    scanned = ad._format_rfc3339(ad._now_utc() - timedelta(minutes=5))
    assert ad._write_cache(ad.AgentDiscovery(scanned_at=scanned, agents=peers, cache_hit=False), data_dir=tmp_path)
    # The fresh scan versioned codex but missed cursor.
    fresh = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    fresh["codex"] = _codex_signal(version="codex-cli 0.160.0")

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
    fresh["codex"] = _codex_signal(version="codex-cli 0.160.0")

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
        peers["cursor"] = _cursor_signal(version=before)
        scanned = ad._format_rfc3339(ad._now_utc() - timedelta(minutes=5))
        assert ad._write_cache(ad.AgentDiscovery(scanned_at=scanned, agents=peers, cache_hit=False), data_dir=data)
        fresh = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
        fresh["codex"] = _codex_signal(version="codex-cli 0.160.0")
        fresh["cursor"] = _cursor_signal(version=after)

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
    peers["cursor"] = _cursor_signal(version="3.19.13")
    scanned = ad._format_rfc3339(ad._now_utc() - timedelta(minutes=5))
    assert ad._write_cache(ad.AgentDiscovery(scanned_at=scanned, agents=peers, cache_hit=False), data_dir=tmp_path)
    fresh = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    fresh["codex"] = _codex_signal(version="codex-cli 0.160.0")
    fresh["cursor"] = _cursor_signal(error=ad.VERSION_NOT_PROBED)

    assert ad._publish_agent_signal(
        ad.AgentDiscovery(scanned_at=ad._format_rfc3339(ad._now_utc()), agents=fresh, cache_hit=False),
        "codex",
        data_dir=tmp_path,
    )

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == "3.19.13"


def _cursor_cache(data: Path, version: str, *, seconds_old: int) -> str:
    peers = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    peers["cursor"] = _cursor_signal(version=version)
    scanned = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=seconds_old))
    assert ad._write_cache(ad.AgentDiscovery(scanned_at=scanned, agents=peers, cache_hit=False), data_dir=data)
    return scanned


def _scan(*, seconds_old: int, cursor: str, codex: str = "codex-cli 0.160.0") -> ad.AgentDiscovery:
    agents = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    agents["codex"] = _codex_signal(version=codex)
    agents["cursor"] = _cursor_signal(version=cursor)
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


def _file_times_of_this_system(monkeypatch) -> None:
    """The lookup rules of the system the tests run on: on Windows the change time of a
    folder (not its creation time) says that it was swapped."""
    monkeypatch.setattr(ad, "_is_windows_host", lambda: os.name == "nt")
    monkeypatch.setattr(ad, "_windows_configured_package_manager_bin_prefixes", lambda: ())


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
    _file_times_of_this_system(monkeypatch)
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
    _file_times_of_this_system(monkeypatch)
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
    cached.observed_at = ad._format_rfc3339(ad._now_utc() + timedelta(minutes=3))
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


def _unread_scan(*, read_ago: float, version: str, error: str, binary: str = _CURSOR) -> ad.AgentDiscovery:
    disc = _scan(seconds_old=0, cursor=version)
    disc.agents["cursor"] = _signal("cursor", binary=binary, version=version, error=error)
    disc.agents["cursor"].identity = ad._executable_identity(binary)
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


# --- GAP-0752 review 6: a version belongs to the executable that answered ----


def _one_cursor(monkeypatch, binary: Path, probe=None) -> None:
    monkeypatch.setattr(ad, "_ai_discovery_trust_config", lambda *_a, **_k: (False, []))
    monkeypatch.setattr(ad, "_configured_probe_names", lambda *_a, **_k: frozenset({"cursor"}))
    monkeypatch.setattr(
        ad, "_binary_candidates_for_agent", lambda name, _spec: (str(binary),) if name == "cursor" else ()
    )
    monkeypatch.setattr(ad, "_missing_probe_state", lambda *_a, **_k: ([], []))
    if probe is not None:
        monkeypatch.setattr(ad, "_version_for_agent_binary", probe)


def _replace(binary: Path, text: str) -> None:
    staged = binary.with_name(binary.name + ".new")
    staged.write_text(text, encoding="utf-8")
    staged.replace(binary)


@pytest.mark.skipif(os.name == "nt", reason="the probe is a shell script")
def test_an_executable_replaced_while_it_answers_is_read_again_and_cached_at_the_new_version(monkeypatch, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    binary = tmp_path / "cursor"
    started, release = tmp_path / "started", tmp_path / "release"
    binary.write_text(
        f"#!/bin/sh\nprintf x > '{started}'\nwhile [ ! -e '{release}' ]; do sleep 0.01; done\nprintf '3.19.13\\n'\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)
    _one_cursor(monkeypatch, binary)
    result: dict[str, ad.AgentDiscovery] = {}
    worker = threading.Thread(
        target=lambda: result.update(scan=ad.discover_agents(use_cache=False, refresh=True, data_dir=data))
    )
    worker.start()
    deadline = time.monotonic() + 10
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert started.exists()
    _replace(binary, "#!/bin/sh\nprintf 'cursor 2.3.99\\n'\n")
    binary.chmod(0o700)
    release.touch()
    worker.join(timeout=20)
    assert not worker.is_alive()

    assert result["scan"].agents["cursor"].version == "cursor 2.3.99"
    assert ad._read_cache(data_dir=data).agents["cursor"].version == "cursor 2.3.99"


@pytest.mark.skipif(os.name == "nt", reason="links need privileges on Windows")
def test_a_link_switched_while_the_probe_ran_is_read_again(monkeypatch, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    old, new, link = tmp_path / "old", tmp_path / "new", tmp_path / "cursor"
    old.write_text("3.19.13", encoding="utf-8")
    new.write_text("cursor 2.3.99", encoding="utf-8")
    link.symlink_to(old)
    calls: list[str] = []

    def probe(name, path, *_a, **_k):
        calls.append(path)
        answer = Path(path).read_text(encoding="utf-8")
        if len(calls) == 1:
            link.unlink()
            link.symlink_to(new)
        return answer, ""

    _one_cursor(monkeypatch, link, probe)
    scan = ad.discover_agents(use_cache=False, refresh=True, data_dir=data)

    assert len(calls) == 2
    assert scan.agents["cursor"].version == "cursor 2.3.99"
    assert ad._read_cache(data_dir=data).agents["cursor"].version == "cursor 2.3.99"


@pytest.mark.parametrize("prior,replacement", [("3.19.13", "cursor 2.3.99"), ("cursor 2.3.99", "3.19.13")])
def test_an_executable_that_changes_at_every_probe_is_unread_never_recorded_at_either_version(
    monkeypatch, tmp_path, prior, replacement
):
    data = tmp_path / "data"
    data.mkdir()
    binary = tmp_path / "cursor"
    binary.write_text(prior, encoding="utf-8")

    def probe(name, path, *_a, **_k):
        answer = Path(path).read_text(encoding="utf-8")
        _replace(binary, replacement + "\n" * (len(answer) % 7 + 1))
        return answer, ""

    _one_cursor(monkeypatch, binary, probe)
    scan = ad.discover_agents(use_cache=False, refresh=True, data_dir=data)

    assert scan.agents["cursor"].version == ""
    assert ad.VERSION_EXECUTABLE_CHANGED in scan.agents["cursor"].error
    assert ad._read_cache(data_dir=data).agents["cursor"].version == ""


def test_an_executable_that_updates_itself_on_its_first_answer_is_read_at_the_version_it_settles_on(
    monkeypatch, tmp_path
):
    data = tmp_path / "data"
    data.mkdir()
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    calls: list[str] = []

    def probe(name, path, *_a, **_k):
        calls.append(path)
        answer = Path(path).read_text(encoding="utf-8")
        if len(calls) == 1:
            _replace(binary, "3.20.0")
        return answer, ""

    _one_cursor(monkeypatch, binary, probe)
    scan = ad.discover_agents(use_cache=False, refresh=True, data_dir=data)

    assert scan.agents["cursor"].version == "3.20.0"
    assert ad._read_cache(data_dir=data).agents["cursor"].version == "3.20.0"


def test_an_executable_that_does_not_change_is_probed_once_and_keeps_its_version(monkeypatch, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    calls: list[str] = []

    def probe(name, path, *_a, **_k):
        calls.append(path)
        return Path(path).read_text(encoding="utf-8"), ""

    _one_cursor(monkeypatch, binary, probe)
    scan = ad.discover_agents(use_cache=False, refresh=True, data_dir=data)

    assert calls == [str(binary)]
    assert scan.agents["cursor"].version == "3.19.13"
    assert ad._read_cache(data_dir=data).agents["cursor"].identity == ad._executable_identity(str(binary))


def _identified_scan(binary: Path, version: str) -> ad.AgentDiscovery:
    agents = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    agents["cursor"] = ad.AgentSignal(
        name="cursor",
        installed=True,
        config_path="",
        binary_path=str(binary),
        version=version,
        error="",
        identity=ad._executable_identity(str(binary)),
        observed_at=ad._format_rfc3339(ad._now_utc()),
    )
    return ad.AgentDiscovery(scanned_at=ad._format_rfc3339(ad._now_utc()), agents=agents, cache_hit=False)


def test_a_version_is_not_written_for_an_executable_replaced_after_the_scan(tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    scan = _identified_scan(binary, "3.19.13")
    _replace(binary, "cursor 2.3.99")

    assert ad._write_cache(scan, data_dir=tmp_path)

    cached = ad._read_cache(data_dir=tmp_path).agents["cursor"]
    assert cached.version == ""
    assert cached.installed and cached.error == ad.VERSION_NOT_PROBED


def test_a_version_is_written_for_an_executable_that_is_still_the_one_that_answered(tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    scan = _identified_scan(binary, "3.19.13")

    assert ad._write_cache(scan, data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == "3.19.13"


def test_a_published_version_is_not_written_for_an_executable_replaced_after_the_scan(tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    scan = _identified_scan(binary, "3.19.13")
    assert ad._write_cache(scan, data_dir=tmp_path)
    _replace(binary, "cursor 2.3.99")

    assert ad._publish_agent_signal(scan, "cursor", data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == ""


def _peer_cache(tmp_path: Path, binary: Path, version: str) -> ad.AgentDiscovery:
    scan = _identified_scan(binary, version)
    scan.agents["cursor"].observed_at = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=30))
    assert ad._write_cache(scan, data_dir=tmp_path)
    return scan


def _later_scan_of_the_peer(binary: Path, *, error: str) -> ad.AgentDiscovery:
    scan = _identified_scan(binary, "")
    scan.agents["cursor"].error = error
    codex = _codex_signal(version="codex-cli 0.160.0")
    codex.observed_at = scan.agents["cursor"].observed_at
    scan.agents["codex"] = codex
    return scan


def test_a_later_unread_result_of_a_replaced_peer_executable_supersedes_its_cached_version(tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    _peer_cache(tmp_path, binary, "3.19.13")
    _replace(binary, "cursor 2.3.99")
    fresh = _later_scan_of_the_peer(binary, error=f"{binary}: {ad.VERSION_PROBE_TIMED_OUT}")

    assert ad._publish_agent_signal(fresh, "codex", data_dir=tmp_path)

    cached = ad._read_cache(data_dir=tmp_path).agents
    assert cached["cursor"].version == ""
    assert cached["codex"].version == "codex-cli 0.160.0"


def test_a_slow_answer_from_the_same_peer_executable_keeps_its_cached_version(tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    _peer_cache(tmp_path, binary, "3.19.13")
    fresh = _later_scan_of_the_peer(binary, error=f"{binary}: {ad.VERSION_PROBE_TIMED_OUT}")

    assert ad._publish_agent_signal(fresh, "codex", data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == "3.19.13"


def test_a_peer_missing_from_the_scan_keeps_its_cached_version(tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    _peer_cache(tmp_path, binary, "3.19.13")
    fresh = _later_scan_of_the_peer(binary, error="")
    fresh.agents["cursor"] = _signal("cursor")

    assert ad._publish_agent_signal(fresh, "codex", data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == "3.19.13"


# --- GAP-0752 review 7: the cache write, the returned scan and the peer check
# --- judge the executable at the moment they act, not before ----


@pytest.mark.parametrize(("prior", "current"), [("3.19.13", "cursor 2.3.99"), ("cursor 2.3.99", "3.19.13")])
def test_a_writer_that_waited_for_the_cache_lock_does_not_write_what_was_true_before_the_wait(
    monkeypatch, tmp_path, prior, current
):
    binary = tmp_path / "cursor"
    binary.write_text(prior, encoding="utf-8")
    scan = _identified_scan(binary, prior)
    locked = ad._cache_update

    @contextmanager
    def replaced_while_waiting(path):
        _replace(binary, current)
        with locked(path):
            yield

    monkeypatch.setattr(ad, "_cache_update", replaced_while_waiting)

    assert ad._write_cache(scan, data_dir=tmp_path)

    cached = ad._read_cache(data_dir=tmp_path).agents["cursor"]
    assert cached.version == ""
    assert cached.installed and cached.error == ad.VERSION_NOT_PROBED


def test_a_writer_that_waited_for_the_cache_lock_writes_an_executable_that_did_not_change(monkeypatch, tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    scan = _identified_scan(binary, "3.19.13")
    locked = ad._cache_update

    @contextmanager
    def waiting(path):
        time.sleep(0.05)
        with locked(path):
            yield

    monkeypatch.setattr(ad, "_cache_update", waiting)

    assert ad._write_cache(scan, data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == "3.19.13"


@pytest.mark.parametrize(("prior", "current"), [("3.19.13", "cursor 2.3.99"), ("cursor 2.3.99", "3.19.13")])
def test_a_discovery_does_not_hand_back_a_version_of_an_executable_replaced_before_its_cache_write(
    monkeypatch, tmp_path, prior, current
):
    data = tmp_path / "data"
    data.mkdir()
    binary = tmp_path / "cursor"
    binary.write_text(prior, encoding="utf-8")
    _one_cursor(monkeypatch, binary, lambda _n, path, *_a, **_k: (Path(path).read_text(encoding="utf-8"), ""))
    written = ad._write_cache

    def replaced_before_the_write(disc, *, data_dir=None):
        _replace(binary, current)
        return written(disc, data_dir=data_dir)

    monkeypatch.setattr(ad, "_write_cache", replaced_before_the_write)

    result = ad.discover_agents(use_cache=False, refresh=True, data_dir=data)

    returned = result.agents["cursor"]
    assert returned.version == "" and returned.installed and returned.error == ad.VERSION_NOT_PROBED
    assert ad._read_cache(data_dir=data).agents["cursor"].version == ""


def test_a_discovery_hands_back_the_version_of_an_executable_that_stayed_the_same(monkeypatch, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    _one_cursor(monkeypatch, binary, lambda _n, path, *_a, **_k: (Path(path).read_text(encoding="utf-8"), ""))

    result = ad.discover_agents(use_cache=False, refresh=True, data_dir=data)

    assert result.agents["cursor"].version == "3.19.13"
    assert ad._read_cache(data_dir=data).agents["cursor"].version == "3.19.13"


def _strip_identities(tmp_path: Path) -> None:
    cache = tmp_path / ad.CACHE_FILENAME
    payload = json.loads(cache.read_text(encoding="utf-8"))
    for entry in payload["agents"].values():
        entry.pop("identity", None)
    cache.write_text(json.dumps(payload), encoding="utf-8")


def test_a_peer_cached_before_identities_existed_loses_its_version_when_its_executable_changed_unreadable(tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    _peer_cache(tmp_path, binary, "3.19.13")
    _strip_identities(tmp_path)
    _replace(binary, "timeout")
    fresh = _later_scan_of_the_peer(binary, error=f"{binary}: {ad.VERSION_PROBE_TIMED_OUT}")
    fresh.agents["cursor"].identity = []

    assert ad._publish_agent_signal(fresh, "codex", data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == ""


def test_a_peer_cached_before_identities_existed_keeps_no_version_even_when_its_executable_did_not_change(tmp_path):
    (tmp_path / "bin").mkdir()
    binary = tmp_path / "bin" / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    scan = _identified_scan(binary, "3.19.13")
    scan.agents["cursor"].observed_at = ad._format_rfc3339(ad._now_utc())
    assert ad._write_cache(scan, data_dir=tmp_path)
    _strip_identities(tmp_path)
    fresh = _later_scan_of_the_peer(binary, error=f"{binary}: {ad.VERSION_PROBE_TIMED_OUT}")
    fresh.agents["cursor"].identity = []
    for signal in fresh.agents.values():
        signal.observed_at = ad._format_rfc3339(ad._now_utc() + timedelta(seconds=5))

    assert ad._publish_agent_signal(fresh, "codex", data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == ""


def test_a_peer_whose_replaced_executable_kept_changing_loses_its_cached_version(tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    _peer_cache(tmp_path, binary, "3.19.13")
    _replace(binary, "2.3.99-0")
    fresh = _later_scan_of_the_peer(binary, error="")
    # Nothing was selected: not installed, no path, no version, no identity.
    fresh.agents["cursor"] = _signal("cursor", error=f"{binary}: {ad.VERSION_EXECUTABLE_CHANGED}")
    fresh.agents["cursor"].observed_at = fresh.agents["codex"].observed_at

    assert ad._publish_agent_signal(fresh, "codex", data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == ""


def test_a_peer_the_scan_did_not_select_keeps_its_cached_version_while_its_executable_is_unchanged(tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    _peer_cache(tmp_path, binary, "3.19.13")
    fresh = _later_scan_of_the_peer(binary, error="")
    fresh.agents["cursor"] = _signal("cursor", error=f"{binary}: {ad.VERSION_EXECUTABLE_CHANGED}")
    fresh.agents["cursor"].observed_at = fresh.agents["codex"].observed_at

    assert ad._publish_agent_signal(fresh, "codex", data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == "3.19.13"


def test_a_same_size_rewrite_that_restores_the_modification_time_changes_the_identity(monkeypatch, tmp_path):
    # The file rules of the system the test runs on: on Windows the identity carries the
    # NTFS change time (``st_ctime`` there is the creation time, which a rewrite leaves alone).
    _file_times_of_this_system(monkeypatch)
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    first = binary.stat()
    before = ad._executable_identity(str(binary))
    assert ad._executable_identity(str(binary)) == before

    time.sleep(_FILE_CLOCK_TICK)
    binary.write_text("2.3.999", encoding="utf-8")
    os.utime(binary, ns=(first.st_atime_ns, first.st_mtime_ns))

    after = ad._executable_identity(str(binary))
    assert after != before


def test_an_executable_rewritten_in_place_with_its_time_restored_while_it_answers_is_read_again(monkeypatch, tmp_path):
    _file_times_of_this_system(monkeypatch)
    data = tmp_path / "data"
    data.mkdir()
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    initial = binary.stat()
    calls = [0]

    def probe(_name, path, *_args, **_kwargs):
        calls[0] += 1
        answer = Path(path).read_text(encoding="utf-8")
        if calls[0] == 1:
            binary.write_text("2.3.999", encoding="utf-8")
            os.utime(binary, ns=(initial.st_atime_ns, initial.st_mtime_ns))
        return answer, ""

    _one_cursor(monkeypatch, binary, probe)

    result = ad.discover_agents(use_cache=False, refresh=True, data_dir=data)

    assert calls[0] == 2
    assert result.agents["cursor"].version == "2.3.999"
    assert ad._read_cache(data_dir=data).agents["cursor"].version == "2.3.999"


# --- GAP-0752 review 8: a peer's new selection, a kept entry and a Windows
# --- in-place update are each judged against the executable itself ----


def _selection_moved(tmp_path: Path, *, error: str) -> tuple[Path, Path, ad.AgentDiscovery]:
    """Cursor cached at a version of one executable; the launch order has since
    moved to another one (the first stays on disk, unchanged)."""
    old = tmp_path / "old-cursor"
    new = tmp_path / "new-cursor"
    old.write_text("3.19.13", encoding="utf-8")
    new.write_text("cursor 2.3.99", encoding="utf-8")
    _peer_cache(tmp_path, old, "3.19.13")
    fresh = _later_scan_of_the_peer(new, error=error)
    return old, new, fresh


def test_a_peer_whose_launch_selection_moved_to_another_executable_loses_the_old_version_when_unread(tmp_path):
    _old, new, fresh = _selection_moved(tmp_path, error=f"x: {ad.VERSION_PROBE_TIMED_OUT}")

    assert ad._publish_agent_signal(fresh, "codex", data_dir=tmp_path)

    cached = ad._read_cache(data_dir=tmp_path).agents["cursor"]
    assert cached.version == ""
    assert cached.binary_path == str(new)


def test_a_peer_selected_elsewhere_by_a_scan_with_no_identity_loses_the_old_version_too(tmp_path):
    _old, new, fresh = _selection_moved(tmp_path, error=f"x: {ad.VERSION_PROBE_TIMED_OUT}")
    fresh.agents["cursor"].identity = []

    assert ad._publish_agent_signal(fresh, "codex", data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == ""


def test_a_peer_selected_elsewhere_that_the_scan_read_is_cached_at_the_version_it_read(tmp_path):
    _old, new, fresh = _selection_moved(tmp_path, error="")
    fresh.agents["cursor"].version = "cursor 2.3.99"

    assert ad._publish_agent_signal(fresh, "codex", data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == "cursor 2.3.99"


def test_a_peer_the_scan_selected_through_another_link_to_the_same_file_keeps_its_cached_version(tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    link = tmp_path / "cursor-link"
    link.symlink_to(binary)
    _peer_cache(tmp_path, binary, "3.19.13")
    fresh = _later_scan_of_the_peer(link, error=f"x: {ad.VERSION_PROBE_TIMED_OUT}")

    assert ad._publish_agent_signal(fresh, "codex", data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == "3.19.13"


def test_a_real_scan_that_selected_another_executable_and_timed_out_does_not_leave_the_old_version(monkeypatch, tmp_path):
    old = tmp_path / "old-cursor"
    new = tmp_path / "new-cursor"
    old.write_text("3.19.13", encoding="utf-8")
    new.write_text("cursor 2.3.99", encoding="utf-8")
    _peer_cache(tmp_path, old, "3.19.13")
    candidates = {"cursor": str(new), "codex": str(tmp_path / "codex")}
    (tmp_path / "codex").write_text("codex-cli 0.160.0", encoding="utf-8")

    def probe(name, *_args, **_kwargs):
        return ("", ad.VERSION_PROBE_TIMED_OUT) if name == "cursor" else ("codex-cli 0.160.0", "")

    monkeypatch.setattr(ad, "_ai_discovery_trust_config", lambda *_a, **_k: (False, []))
    monkeypatch.setattr(ad, "_configured_probe_names", lambda *_a, **_k: frozenset({"codex", "cursor"}))
    monkeypatch.setattr(ad, "_binary_candidates_for_agent", lambda name, _spec: (candidates[name],) if name in candidates else ())
    monkeypatch.setattr(ad, "_version_for_agent_binary", probe)
    monkeypatch.setattr(ad, "_missing_probe_state", lambda *_a, **_k: ([], []))
    scan = ad.discover_with_probes(["codex"], use_cache=False, refresh=True, data_dir=tmp_path, persist_cache=False)
    assert scan.agents["cursor"].binary_path == str(new)

    assert ad._publish_agent_signal(scan, "codex", data_dir=tmp_path)

    cached = ad._read_cache(data_dir=tmp_path).agents["cursor"]
    assert cached.version == ""
    assert cached.binary_path == str(new)


def _newer_cached_reading_then_replacement(tmp_path: Path) -> tuple[Path, ad.AgentDiscovery]:
    """A reading taken after the scan being written is in the cache; the
    executable is replaced after that reading."""
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    older = _identified_scan(binary, "3.19.13")
    older.agents["cursor"].observed_at = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=30))
    newer = _identified_scan(binary, "3.19.13")
    newer.agents["cursor"].observed_at = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=5))
    assert ad._write_cache(newer, data_dir=tmp_path)
    _replace(binary, "cursor 2.3.99")
    return binary, older


def test_a_full_write_does_not_keep_a_newer_cached_version_of_an_executable_replaced_since(tmp_path):
    binary, older = _newer_cached_reading_then_replacement(tmp_path)

    assert ad._write_cache(older, data_dir=tmp_path)

    cached = ad._read_cache(data_dir=tmp_path).agents["cursor"]
    assert cached.version == ""
    assert cached.error == ad.VERSION_NOT_PROBED


def test_a_publish_does_not_keep_a_newer_cached_version_of_an_executable_replaced_since(tmp_path):
    binary, older = _newer_cached_reading_then_replacement(tmp_path)

    assert ad._publish_agent_signal(older, "cursor", data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == ""


def test_a_write_keeps_a_newer_cached_version_of_an_executable_that_did_not_change(tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    older = _identified_scan(binary, "3.19.13")
    older.agents["cursor"].observed_at = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=30))
    newer = _identified_scan(binary, "3.19.13")
    newer.agents["cursor"].observed_at = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=5))
    assert ad._write_cache(newer, data_dir=tmp_path)

    assert ad._write_cache(older, data_dir=tmp_path)

    cached = ad._read_cache(data_dir=tmp_path).agents["cursor"]
    assert cached.version == "3.19.13"
    assert cached.observed_at == newer.agents["cursor"].observed_at


def _filetime(unix_ns: int) -> int:
    """A Unix time in nanoseconds as the 100 ns ticks since 1601 Windows keeps."""
    return unix_ns // 100 + ad._WINDOWS_TICKS_AT_UNIX_EPOCH


def _on_windows(monkeypatch, original: os.stat_result, binary: Path) -> None:
    """Windows semantics for one file: ``st_ctime`` is the creation time (it
    stays what the file was created with), and the NTFS change time moves with
    every write (here the change time this system keeps). On Windows itself the
    file system already behaves so and its own change time is read."""
    monkeypatch.setattr(ad, "_is_windows_host", lambda: True)
    if os.name == "nt":
        return
    real_stat = os.stat

    class WindowsStat:
        def __init__(self, wrapped):
            self.wrapped = wrapped
            self.st_ctime_ns = original.st_ctime_ns

        def __getattr__(self, name):
            return getattr(self.wrapped, name)

    monkeypatch.setattr(ad.os, "stat", lambda path, *a, **k: WindowsStat(real_stat(path, *a, **k)))
    monkeypatch.setattr(ad, "_windows_change_time", lambda path: _filetime(real_stat(path).st_ctime_ns))
    real_lstat = os.lstat
    monkeypatch.setattr(ad.os, "lstat", lambda path, *a, **k: WindowsStat(real_lstat(path, *a, **k)))


def test_a_same_size_rewrite_with_the_modification_time_restored_changes_the_identity_on_windows(monkeypatch, tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    original = binary.stat()
    _on_windows(monkeypatch, original, binary)
    before = ad._executable_identity(str(binary))
    assert ad._executable_identity(str(binary)) == before

    time.sleep(_FILE_CLOCK_TICK)
    binary.write_text("2.3.999", encoding="utf-8")
    os.utime(binary, ns=(original.st_atime_ns, original.st_mtime_ns))

    assert ad._executable_identity(str(binary)) != before


def _folder_changed_at(monkeypatch, tmp_path: Path, changed_ns: dict[str, int | None]) -> tuple[Path, float]:
    """A Windows host whose folder times are the creation time in ``st_ctime`` and the
    change time given per path (None: Windows gives none for that path). Returns the
    executable and a scan time after every file time ``st_*`` reports."""
    folder = tmp_path / "bin"
    folder.mkdir()
    binary = folder / "codex"
    binary.write_text("codex", encoding="utf-8")
    since = time.time() + 10
    monkeypatch.setattr(ad, "_is_windows_host", lambda: True)
    def change_time(path: str) -> int | None:
        changed = changed_ns.get(path, int((since - 600) * 1e9))
        return None if changed is None else _filetime(changed)

    monkeypatch.setattr(ad, "_windows_change_time", change_time)
    return binary, since


def test_a_folder_renamed_on_windows_is_changed_though_its_creation_time_is_old(monkeypatch, tmp_path):
    folder = str(tmp_path / "bin")
    binary, since = _folder_changed_at(monkeypatch, tmp_path, {folder: int((time.time() + 11) * 1e9)})

    assert not ad._resolves_unchanged_since(str(binary), since, tmp_path / "data")


def test_a_folder_not_changed_since_the_scan_on_windows_keeps_the_version(monkeypatch, tmp_path):
    binary, since = _folder_changed_at(monkeypatch, tmp_path, {})

    assert ad._resolves_unchanged_since(str(binary), since, tmp_path / "data")


def test_a_windows_executable_that_was_not_written_to_keeps_its_identity_and_its_version(monkeypatch, tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    _on_windows(monkeypatch, binary.stat(), binary)
    scan = _identified_scan(binary, "3.19.13")

    assert ad._write_cache(scan, data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == "3.19.13"


def test_a_windows_in_place_rewrite_after_the_scan_is_not_cached_at_the_old_version(monkeypatch, tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    original = binary.stat()
    _on_windows(monkeypatch, original, binary)
    scan = _identified_scan(binary, "3.19.13")
    time.sleep(_FILE_CLOCK_TICK)
    binary.write_text("2.3.999", encoding="utf-8")
    os.utime(binary, ns=(original.st_atime_ns, original.st_mtime_ns))

    assert ad._write_cache(scan, data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == ""


def test_a_folder_whose_windows_change_time_cannot_be_read_is_not_proven_unchanged(monkeypatch, tmp_path):
    folder = str(tmp_path / "bin")
    binary, since = _folder_changed_at(monkeypatch, tmp_path, {folder: None})

    assert not ad._resolves_unchanged_since(str(binary), since, tmp_path / "data")


def test_an_executable_whose_windows_change_time_cannot_be_read_is_not_proven_unchanged(monkeypatch, tmp_path):
    binary, since = _folder_changed_at(monkeypatch, tmp_path, {})
    unreadable = {str(binary): None}
    monkeypatch.setattr(
        ad,
        "_windows_change_time",
        lambda path: None if path in unreadable else _filetime(int((since - 600) * 1e9)),
    )

    assert not ad._resolves_unchanged_since(str(binary), since, tmp_path / "data")


def test_a_cached_version_is_dropped_when_windows_cannot_give_the_change_time_of_the_executable(monkeypatch, tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    _on_windows(monkeypatch, binary.stat(), binary)
    recorded = ad._executable_identity(str(binary))
    assert recorded
    assert not ad._executable_replaced_since_read(str(binary), recorded)
    monkeypatch.setattr(ad, "_windows_change_time", lambda path: None)

    assert ad._executable_identity(str(binary)) == []
    assert ad._executable_replaced_since_read(str(binary), recorded)


def test_the_identity_of_an_executable_is_the_stat_change_time_off_windows(monkeypatch, tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    monkeypatch.setattr(ad, "_is_windows_host", lambda: False)
    monkeypatch.setattr(ad, "_windows_change_time", lambda path: None)

    assert ad._executable_identity(str(binary))[5] == binary.stat().st_ctime_ns


class _Foreign:
    """A foreign function: callable, with the prototype attributes ctypes sets."""

    argtypes = None
    restype = None

    def __init__(self, call):
        self._call = call

    def __call__(self, *args):
        return self._call(*args)


class _FakeKernel32:
    """CreateFileW / GetFileInformationByHandleEx / CloseHandle, as far as the
    change-time read uses them."""

    def __init__(self, *, change_time: int, handle: int | None = 7, query_ok: bool = True):
        self.change_time = change_time
        self.handle = handle
        self.query_ok = query_ok
        self.closed: list[int] = []
        self.opened: list[tuple] = []
        self.CreateFileW = _Foreign(self._create)
        self.GetFileInformationByHandleEx = _Foreign(self._query)
        self.CloseHandle = _Foreign(self._close)

    def _create(self, path, access, share, security, disposition, flags, template):
        self.opened.append((path, access, share, disposition, flags))
        return self.handle

    def _query(self, handle, info_class, buffer, size):
        assert info_class == 0 and size == ctypes.sizeof(ad._WindowsFileBasicInfo) == 40
        buffer._obj.change_time = self.change_time
        return 1 if self.query_ok else 0

    def _close(self, handle):
        self.closed.append(handle)
        return 1


def _fake_windows_api(monkeypatch, kernel32: _FakeKernel32) -> None:
    monkeypatch.setattr(ad.ctypes, "WinDLL", lambda *_a, **_k: kernel32, raising=False)


def test_the_windows_change_time_is_read_through_a_read_attributes_handle_that_is_closed(monkeypatch):
    kernel32 = _FakeKernel32(change_time=133_000_000_000_000_000)
    _fake_windows_api(monkeypatch, kernel32)

    assert ad._windows_change_time("C:\\tools\\cursor.exe") == 133_000_000_000_000_000

    assert kernel32.closed == [7]
    path, access, share, disposition, _flags = kernel32.opened[0]
    assert access == 0x80 and share == 7 and disposition == 3  # read attributes only, never exclusive


@pytest.mark.parametrize(
    "kernel32",
    [
        _FakeKernel32(change_time=1, handle=ctypes.c_void_p(-1).value),
        _FakeKernel32(change_time=1, handle=None),
        _FakeKernel32(change_time=1, query_ok=False),
        _FakeKernel32(change_time=0),
    ],
)
def test_the_windows_change_time_is_none_when_windows_does_not_give_one(monkeypatch, kernel32):
    _fake_windows_api(monkeypatch, kernel32)

    assert ad._windows_change_time("C:\\tools\\cursor.exe") is None
    assert kernel32.closed == ([7] if kernel32.handle == 7 else [])


# --- GAP-0752 review 9: a version is judged against the executable by every reader ----


def test_the_windows_change_time_is_in_the_unit_of_the_modification_time(monkeypatch, tmp_path):
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    written = 1_800_000_000_123_456_700
    monkeypatch.setattr(ad, "_is_windows_host", lambda: True)
    monkeypatch.setattr(ad, "_windows_change_time", lambda path: _filetime(written))

    assert ad._executable_identity(str(binary))[5] == written


def _cursor_discovery_setup(monkeypatch, tmp_path: Path, scan_version: str):
    """A Windows account with Cursor configured, a cached read of the file, and a
    scan that would answer *scan_version*. Returns (data, binary, original, rescans)."""
    data, bindir = tmp_path / "data", tmp_path / "bin"
    data.mkdir()
    bindir.mkdir()
    (data / "config.yaml").write_text(
        "guardrail:\n  enabled: true\n  connector: cursor\n  connectors:\n    cursor:\n      enabled: true\n",
        encoding="utf-8",
    )
    binary = bindir / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    original = binary.stat()
    _on_windows(monkeypatch, original, binary)
    rescans: list[str] = []

    def scan(name, **_kwargs):
        rescans.append(name)
        if name == "cursor":
            return _signal(name, binary=str(binary), version=scan_version)
        return _signal(name)

    monkeypatch.setattr(ad, "_configured_probe_names", lambda *_a, **_k: frozenset({"cursor"}))
    monkeypatch.setattr(ad, "_unchanged_candidates_ahead", lambda *_a, **_k: ())
    monkeypatch.setattr(ad, "_scan_agent", scan)
    time.sleep(_FILE_CLOCK_TICK)
    assert ad._write_cache(_identified_scan(binary, "3.19.13"), data_dir=data)
    return data, binary, original, rescans


def test_a_windows_cached_discovery_reads_again_an_executable_rewritten_in_place(monkeypatch, tmp_path):
    data, binary, original, rescans = _cursor_discovery_setup(monkeypatch, tmp_path, "cursor 2.3.99")
    time.sleep(_FILE_CLOCK_TICK)
    binary.write_text("2.3.999", encoding="utf-8")
    os.utime(binary, ns=(original.st_atime_ns, original.st_mtime_ns))

    disc = ad.discover_agents(data_dir=data)

    assert rescans and disc.cache_hit is False
    assert disc.agents["cursor"].version == "cursor 2.3.99"


def test_a_windows_cached_discovery_keeps_the_version_of_an_executable_not_written_to(monkeypatch, tmp_path):
    data, _binary, _original, rescans = _cursor_discovery_setup(monkeypatch, tmp_path, "cursor 2.3.99")

    disc = ad.discover_agents(data_dir=data)

    assert not rescans and disc.cache_hit is True
    assert disc.agents["cursor"].version == "3.19.13"


def _legacy_scan(binary: Path, version: str, *, read_ago: float = 0.0) -> ad.AgentDiscovery:
    """A scan as a release before executable identities wrote it."""
    scan = _identified_scan(binary, version)
    stamp = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=read_ago))
    scan.scanned_at = scan.agents["cursor"].observed_at = stamp
    scan.agents["cursor"].identity = []
    return scan


@pytest.mark.parametrize("rewritten", (False, True))
def test_a_legacy_entry_is_never_trusted_whether_or_not_its_file_was_written_to(tmp_path, rewritten):
    (tmp_path / "bin").mkdir()
    binary = tmp_path / "bin" / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    original = binary.stat()
    os.utime(binary, ns=(original.st_atime_ns, original.st_mtime_ns - 60_000_000_000))
    time.sleep(_FILE_CLOCK_TICK)
    assert ad._write_cache(_legacy_scan(binary, "3.19.13"), data_dir=tmp_path)
    if rewritten:
        time.sleep(_FILE_CLOCK_TICK)
        binary.write_text("2.3.999", encoding="utf-8")
        os.utime(binary, ns=(original.st_atime_ns, original.st_mtime_ns - 60_000_000_000))
    payload = ad._read_cache_payload(ad._cache_path(data_dir=tmp_path))
    assert not payload["agents"]["cursor"].get("identity")

    assert ad._entry_executable_changed(payload["agents"]["cursor"]) is True
    older = _identified_scan(binary, "3.19.13")
    older.agents["cursor"].observed_at = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=30))
    assert ad._write_cache(older, data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].identity == ad._executable_identity(str(binary))


def _link_cache(tmp_path: Path):
    (tmp_path / "bin").mkdir()
    old, new, link = tmp_path / "bin" / "cursor-old", tmp_path / "bin" / "cursor-new", tmp_path / "bin" / "cursor"
    old.write_text("3.19.13", encoding="utf-8")
    new.write_text("cursor 2.3.99", encoding="utf-8")
    link.symlink_to(old)
    time.sleep(_FILE_CLOCK_TICK)
    assert ad._write_cache(_legacy_scan(link, "3.19.13"), data_dir=tmp_path)
    return old, new, link


def _peer_scan_that_timed_out_on(link: Path) -> ad.AgentDiscovery:
    scan = _identified_scan(link, "")
    scan.agents["cursor"].error = ad.VERSION_PROBE_TIMED_OUT
    scan.agents["codex"] = _codex_signal(version="codex-cli 0.160.0")
    return scan


@pytest.mark.skipif(os.name == "nt", reason="needs symbolic links")
@pytest.mark.parametrize("moved", (True, False))
def test_a_legacy_entry_is_not_kept_whether_or_not_its_launch_link_moved(tmp_path, moved):
    _old, new, link = _link_cache(tmp_path)
    if moved:
        time.sleep(_FILE_CLOCK_TICK)
        staged = link.parent / "moved"
        staged.symlink_to(new)
        os.replace(staged, link)
    payload = ad._read_cache_payload(ad._cache_path(data_dir=tmp_path))
    assert ad._entry_executable_changed(payload["agents"]["cursor"]) is True

    assert ad._publish_agent_signal(_peer_scan_that_timed_out_on(link), "codex", data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == ""


def _removed_then_older_scan(tmp_path: Path, writer: str) -> Path:
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    older = _identified_scan(binary, "3.19.13")
    older.agents["cursor"].observed_at = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=30))
    newer = _identified_scan(binary, "3.19.13")
    newer.agents["cursor"].observed_at = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=5))
    assert ad._write_cache(newer, data_dir=tmp_path)
    binary.unlink()
    if writer == "publish":
        assert ad._publish_agent_signal(older, "cursor", data_dir=tmp_path)
    else:
        assert ad._write_cache(older, data_dir=tmp_path)
    return binary


@pytest.mark.parametrize("writer", ("publish", "write"))
def test_a_removed_executable_does_not_keep_a_newer_cached_version_for_what_is_installed_there_next(tmp_path, writer):
    binary = _removed_then_older_scan(tmp_path, writer)
    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == ""

    binary.write_text("cursor 2.3.99", encoding="utf-8")

    cached = ad._read_cache(data_dir=tmp_path).agents["cursor"]
    assert cached.version == ""
    assert cached.identity != ad._executable_identity(str(binary))


def _legacy_cursor_cache(tmp_path: Path) -> Path:
    """A schema-7 cache from before identities, as an upgrade leaves it: Cursor
    3.19.13 read from a file that has not been written to since."""
    (tmp_path / "bin").mkdir()
    binary = tmp_path / "bin" / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    original = binary.stat()
    os.utime(binary, ns=(original.st_atime_ns, original.st_mtime_ns - 120_000_000_000))
    time.sleep(_FILE_CLOCK_TICK)
    assert ad._write_cache(_legacy_scan(binary, "3.19.13"), data_dir=tmp_path)
    return binary


def _slow_cursor_agents(binary: Path) -> dict[str, ad.AgentSignal]:
    agents = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    agents["cursor"] = _signal("cursor", binary=str(binary), error=ad.VERSION_PROBE_TIMED_OUT)
    return agents


@pytest.mark.parametrize("rewritten", (False, True))
def test_a_slow_probe_keeps_no_version_from_a_cache_before_identities(tmp_path, rewritten):
    binary = _legacy_cursor_cache(tmp_path)
    kept = binary.stat()
    if rewritten:
        time.sleep(_FILE_CLOCK_TICK)
        binary.write_text("2.3.999", encoding="utf-8")
        os.utime(binary, ns=(kept.st_atime_ns, kept.st_mtime_ns))
    agents = _slow_cursor_agents(binary)

    ad._keep_versions_of_slow_unchanged_agents(agents, data_dir=tmp_path)

    assert agents["cursor"].version == ""
    assert agents["cursor"].error == ad.VERSION_PROBE_TIMED_OUT


def _swap_parent_folder(tmp_path: Path, *, restore_times: bool) -> Path:
    """A cache from before identities for Cursor in ``bin``; ``bin`` is then
    swapped for a ready-made folder holding another version. With
    *restore_times* every folder time is set back to what it was, as the
    creation-time semantics of ``st_ctime`` on Windows leave it."""
    launch, ready = tmp_path / "bin", tmp_path / "ready"
    launch.mkdir()
    ready.mkdir()
    (launch / "cursor").write_text("3.19.13", encoding="utf-8")
    (ready / "cursor").write_text("2.3.999", encoding="utf-8")
    old = (launch.stat().st_atime_ns, launch.stat().st_mtime_ns - 120_000_000_000)
    for folder in (launch, ready, tmp_path):
        os.utime(folder, ns=old)
    time.sleep(_FILE_CLOCK_TICK)
    assert ad._write_cache(_legacy_scan(launch / "cursor", "3.19.13"), data_dir=tmp_path)
    time.sleep(_FILE_CLOCK_TICK)
    os.rename(launch, tmp_path / "retired")
    os.rename(ready, launch)
    if restore_times:
        for folder in (launch, tmp_path):
            os.utime(folder, ns=old)
    return launch / "cursor"


@pytest.mark.parametrize("restore_times", (False, True))
def test_a_replaced_parent_folder_keeps_no_version_from_a_cache_before_identities(tmp_path, restore_times):
    swapped = _swap_parent_folder(tmp_path, restore_times=restore_times)
    payload = ad._read_cache_payload(ad._cache_path(data_dir=tmp_path))
    assert ad._entry_executable_changed(payload["agents"]["cursor"]) is True

    assert ad._publish_agent_signal(_peer_scan_that_timed_out_on(swapped), "codex", data_dir=tmp_path)
    agents = _slow_cursor_agents(swapped)
    ad._keep_versions_of_slow_unchanged_agents(agents, data_dir=tmp_path)

    assert ad._read_cache(data_dir=tmp_path).agents["cursor"].version == ""
    assert agents["cursor"].version == ""


@pytest.mark.parametrize("swap", (False, True))
def test_a_cache_before_identities_is_read_again_and_rewritten_with_the_identity(monkeypatch, tmp_path, swap):
    data = tmp_path / "data"
    data.mkdir()
    if swap:
        binary = _swap_parent_folder(tmp_path, restore_times=True)
        payload = ad._read_cache_payload(ad._cache_path(data_dir=tmp_path))
        ad._cache_path(data_dir=data).write_text(json.dumps(payload), encoding="utf-8")
    else:
        (tmp_path / "bin").mkdir()
        binary = tmp_path / "bin" / "cursor"
        binary.write_text("3.19.13", encoding="utf-8")
        assert ad._write_cache(_legacy_scan(binary, "3.19.13"), data_dir=data)
    probed: list[str] = []

    def probe(_name, path, *_a, **_k):
        probed.append(path)
        return Path(path).read_text(encoding="utf-8"), ""

    _one_cursor(monkeypatch, binary, probe)

    disc = ad.discover_agents(data_dir=data)

    expected = "2.3.999" if swap else "3.19.13"
    assert probed and disc.cache_hit is False
    assert disc.agents["cursor"].version == expected
    cached = ad._read_cache(data_dir=data).agents["cursor"]
    assert cached.version == expected
    assert cached.identity == ad._executable_identity(str(binary))


def _kiro_signal(binary: Path, version: str, *, identified: bool) -> ad.AgentSignal:
    banner = f"kiro-cli {version}"
    return ad.AgentSignal(
        name="kiro",
        installed=True,
        config_path="",
        binary_path=str(binary),
        version=banner,
        error="",
        kiro_cli_version=banner,
        kiro_forms=[{"kind": "cli", "version": banner, "unread": "", "path": str(binary)}],
        identity=ad._executable_identity(str(binary)) if identified else [],
    )


def _kiro_cached(monkeypatch, tmp_path: Path, *, identified: bool, configured: bool = True):
    """A Kiro CLI at its hook floor, read into the cache; returns (data, binary, rescans)."""
    data, bindir = tmp_path / "data", tmp_path / "bin"
    data.mkdir()
    bindir.mkdir()
    binary = bindir / "kiro-cli"
    binary.write_text("2.27.1", encoding="utf-8")
    rescans: list[str] = []

    def scan(name, **_kwargs):
        rescans.append(name)
        if name != "kiro":
            return _signal(name)
        return _kiro_signal(binary, binary.read_text(encoding="utf-8"), identified=True)

    monkeypatch.setattr(ad, "_configured_probe_names", lambda *_a, **_k: frozenset({"kiro"} if configured else ()))
    monkeypatch.setattr(ad, "_scan_agent", scan)
    agents = {name: _signal(name) for name in ad.DISCOVERABLE_CONNECTORS}
    agents["kiro"] = _kiro_signal(binary, "2.27.1", identified=identified)
    time.sleep(_FILE_CLOCK_TICK)
    assert ad._write_cache(
        ad.AgentDiscovery(scanned_at=ad._format_rfc3339(ad._now_utc()), agents=agents, cache_hit=False),
        data_dir=data,
    )
    return data, binary, rescans


def _kiro_protected(disc: ad.AgentDiscovery) -> bool:
    from defenseclaw.connector_contracts import assess_kiro_signal

    return assess_kiro_signal(disc.agents["kiro"]).selected is not None


def test_a_kiro_cached_before_identities_is_read_again_and_not_judged_at_its_old_version(monkeypatch, tmp_path):
    data, binary, rescans = _kiro_cached(monkeypatch, tmp_path, identified=False)
    assert not ad._read_cache_payload(ad._cache_path(data_dir=data))["agents"]["kiro"].get("identity")
    binary.write_text("2.26.1", encoding="utf-8")

    disc = ad.discover_agents(data_dir=data)

    assert "kiro" in rescans and disc.cache_hit is False
    assert disc.agents["kiro"].version == "kiro-cli 2.26.1"
    assert _kiro_protected(disc) is False
    cached = ad._read_cache(data_dir=data).agents["kiro"]
    assert cached.version == "kiro-cli 2.26.1" and cached.identity == ad._executable_identity(str(binary))


def test_a_kiro_cached_before_identities_at_a_protected_version_is_read_again_and_stays_protected(monkeypatch, tmp_path):
    data, _binary, rescans = _kiro_cached(monkeypatch, tmp_path, identified=False)

    disc = ad.discover_agents(data_dir=data)

    assert "kiro" in rescans
    assert _kiro_protected(disc) is True
    assert ad._read_cache(data_dir=data).agents["kiro"].identity


def test_an_identified_kiro_replaced_after_the_scan_is_read_again(monkeypatch, tmp_path):
    data, binary, rescans = _kiro_cached(monkeypatch, tmp_path, identified=True)
    time.sleep(_FILE_CLOCK_TICK)
    _replace(binary, "2.26.1")

    disc = ad.discover_agents(data_dir=data)

    assert "kiro" in rescans
    assert _kiro_protected(disc) is False


def test_an_identified_kiro_that_did_not_change_is_served_from_the_cache(monkeypatch, tmp_path):
    data, _binary, rescans = _kiro_cached(monkeypatch, tmp_path, identified=True)

    disc = ad.discover_agents(data_dir=data)

    assert not rescans and disc.cache_hit is True
    assert _kiro_protected(disc) is True


def test_a_kiro_nobody_set_up_is_never_run_for_a_cache_before_identities(monkeypatch, tmp_path):
    data, binary, rescans = _kiro_cached(monkeypatch, tmp_path, identified=False, configured=False)
    binary.write_text("2.26.1", encoding="utf-8")

    disc = ad.discover_agents(data_dir=data)

    assert not rescans and disc.cache_hit is True


def _rewrite_during_first_version_probe(monkeypatch, tmp_path, *, change_time_readable: bool):
    """A Windows scan of a versioned Cursor whose executable is rewritten, to a
    lower version of the same size with the modification time restored, while
    the first version probe runs."""
    data = tmp_path / "data"
    data.mkdir()
    binary = tmp_path / "cursor"
    binary.write_text("3.19.13", encoding="utf-8")
    original = binary.stat()
    answers: list[str] = []

    def probe(_name, path, *_args, **_kwargs):
        answer = Path(path).read_text(encoding="utf-8")
        answers.append(answer)
        if len(answers) == 1:
            time.sleep(_FILE_CLOCK_TICK)
            binary.write_text("2.3.999", encoding="utf-8")
            os.utime(binary, ns=(original.st_atime_ns, original.st_mtime_ns))
        return answer, ""

    _one_cursor(monkeypatch, binary, probe)
    _on_windows(monkeypatch, original, binary)
    if not change_time_readable:
        monkeypatch.setattr(ad, "_windows_change_time", lambda path: None)
    result = ad.discover_agents(use_cache=False, refresh=True, data_dir=data)
    return result.agents["cursor"], ad._read_cache(data_dir=data).agents["cursor"], answers


def test_a_rewrite_during_the_version_probe_is_read_again_when_windows_gives_the_change_time(monkeypatch, tmp_path):
    scanned, cached, answers = _rewrite_during_first_version_probe(monkeypatch, tmp_path, change_time_readable=True)

    assert (scanned.version, cached.version) == ("2.3.999", "2.3.999"), answers


def test_a_version_read_while_windows_gives_no_change_time_is_not_returned_or_cached(monkeypatch, tmp_path):
    scanned, cached, answers = _rewrite_during_first_version_probe(monkeypatch, tmp_path, change_time_readable=False)

    assert (scanned.version, cached.version) == ("", ""), answers
    assert ad.VERSION_EXECUTABLE_CHANGED in scanned.error
    assert "3.19.13" not in scanned.error


def test_a_version_probe_of_a_path_with_no_file_is_not_dropped_for_want_of_an_identity(monkeypatch, tmp_path):
    binary = tmp_path / "cursor"
    _one_cursor(monkeypatch, binary, lambda *_a, **_k: ("3.19.13", ""))

    scanned = ad.discover_agents(use_cache=False, refresh=True, data_dir=tmp_path).agents["cursor"]

    assert scanned.version == "3.19.13"
