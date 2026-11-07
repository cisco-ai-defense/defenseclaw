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

"""GAP-0752: setup publishes the Codex version it accepted on every OS."""

from __future__ import annotations

import atexit
import shutil
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest import mock

import pytest
from defenseclaw.commands import cmd_setup
from defenseclaw.inventory import agent_discovery as ad

#: A cached peer version belongs to an executable that is there: a real file.
_PEERS = Path(tempfile.mkdtemp(prefix="g752-setup-peers-"))
atexit.register(shutil.rmtree, _PEERS, ignore_errors=True)
_CURSOR = str(_PEERS / "cursor")
Path(_CURSOR).write_text("cursor", encoding="utf-8")


def _cursor(version: str) -> ad.AgentSignal:
    return ad.AgentSignal(
        name="cursor",
        installed=True,
        config_path="",
        binary_path=_CURSOR,
        version=version,
        error="",
        identity=ad._executable_identity(_CURSOR),
    )


def _disc() -> ad.AgentDiscovery:
    agents = {
        name: ad.AgentSignal(name=name, installed=False, config_path="", binary_path="", version="", error="")
        for name in ad.DISCOVERABLE_CONNECTORS
    }
    agents["codex"] = ad.AgentSignal(
        name="codex",
        installed=True,
        config_path="",
        binary_path="/opt/codex/bin/codex",
        version="codex-cli 0.160.0",
        error="",
    )
    return ad.AgentDiscovery(scanned_at="2026-11-06T00:00:00Z", agents=agents, cache_hit=False)


def _check(host: str, write_ok: bool, tmp_path) -> tuple[bool, mock.Mock]:
    write = mock.Mock(return_value=write_ok)
    with (
        mock.patch.object(cmd_setup.platform_support, "host_os", return_value=host),
        mock.patch.object(cmd_setup.agent_discovery, "discover_with_probes", return_value=_disc()),
        mock.patch.object(cmd_setup.agent_discovery, "_write_cache", write),
        mock.patch.object(cmd_setup.agent_discovery, "_publish_agent_signal", write),
    ):
        ok = cmd_setup._check_connector_version_supported_for_setup(
            "codex", mode="action", emit=False, data_dir=str(tmp_path), _allow_prompt=False
        )
    return ok, write


@pytest.mark.parametrize("host", ("windows", "linux", "darwin"))
def test_setup_publishes_the_codex_version_it_accepted(host, tmp_path) -> None:
    ok, write = _check(host, True, tmp_path)
    assert ok is True
    write.assert_called_once()
    assert write.call_args.args[0].agents["codex"].version == "codex-cli 0.160.0"
    if host == "windows":
        assert write.call_args.args[1] == "codex"


def test_a_failed_write_on_windows_does_not_refuse_setup(tmp_path) -> None:
    # The Windows gateway never takes Codex authority from this cache.
    ok, write = _check("windows", False, tmp_path)
    assert ok is True
    write.assert_called_once()


def test_a_failed_write_elsewhere_still_refuses_setup(tmp_path) -> None:
    # Unchanged: the gateway restart reads the cache on these hosts.
    ok, _ = _check("linux", False, tmp_path)
    assert ok is False


def test_windows_setup_keeps_a_peer_version_the_fresh_scan_missed(tmp_path) -> None:
    peers = {
        name: ad.AgentSignal(name=name, installed=False, config_path="", binary_path="", version="", error="")
        for name in ad.DISCOVERABLE_CONNECTORS
    }
    peers["cursor"] = _cursor("3.19.13")
    scanned = ad._format_rfc3339(ad._now_utc())
    assert ad._write_cache(ad.AgentDiscovery(scanned_at=scanned, agents=peers, cache_hit=False), data_dir=tmp_path)

    with (
        mock.patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
        mock.patch.object(cmd_setup.agent_discovery, "discover_with_probes", return_value=_disc()),
    ):
        ok = cmd_setup._check_connector_version_supported_for_setup(
            "codex", mode="action", emit=False, data_dir=str(tmp_path), _allow_prompt=False
        )

    cache = ad._read_cache(data_dir=tmp_path)
    assert ok is True
    assert cache.agents["codex"].version == "codex-cli 0.160.0"
    assert cache.agents["cursor"].version == "3.19.13"


def test_windows_setup_replaces_a_peer_version_the_fresh_scan_read(tmp_path) -> None:
    # The cache is older than the setup scan, which read the peer again.
    scanned = ad._format_rfc3339(ad._now_utc() - timedelta(minutes=5))
    for previous, fresh_version in (("3.19.13", "cursor 2.3.99"), ("cursor 2.3.99", "3.19.13")):
        data = tmp_path / fresh_version.replace(" ", "-")
        data.mkdir()
        agents = {
            name: ad.AgentSignal(name=name, installed=False, config_path="", binary_path="", version="", error="")
            for name in ad.DISCOVERABLE_CONNECTORS
        }
        agents["cursor"] = _cursor(previous)
        assert ad._write_cache(ad.AgentDiscovery(scanned_at=scanned, agents=agents, cache_hit=False), data_dir=data)
        disc = _disc()
        disc.scanned_at = ad._format_rfc3339(ad._now_utc())
        disc.agents["cursor"] = _cursor(fresh_version)

        with (
            mock.patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
            mock.patch.object(cmd_setup.agent_discovery, "discover_with_probes", return_value=disc),
        ):
            ok = cmd_setup._check_connector_version_supported_for_setup(
                "codex", mode="action", emit=False, data_dir=str(data), _allow_prompt=False
            )

        assert ok is True
        assert ad._read_cache(data_dir=data).agents["cursor"].version == fresh_version


def test_windows_setup_keeps_a_peer_version_a_newer_scan_cached(tmp_path) -> None:
    # Setup scanned three seconds ago; discovery cached the peer one second ago.
    # Setup ends last and must not put its older reading back, either way.
    for newer, older in (("3.19.13", "cursor 2.3.99"), ("cursor 2.3.99", "3.19.13")):
        data = tmp_path / older.replace(" ", "-")
        data.mkdir()
        agents = {
            name: ad.AgentSignal(name=name, installed=False, config_path="", binary_path="", version="", error="")
            for name in ad.DISCOVERABLE_CONNECTORS
        }
        agents["cursor"] = _cursor(newer)
        cached_at = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=1))
        assert ad._write_cache(ad.AgentDiscovery(scanned_at=cached_at, agents=agents, cache_hit=False), data_dir=data)
        disc = _disc()
        disc.scanned_at = ad._format_rfc3339(ad._now_utc() - timedelta(seconds=3))
        disc.agents["cursor"] = _cursor(older)

        with (
            mock.patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
            mock.patch.object(cmd_setup.agent_discovery, "discover_with_probes", return_value=disc),
        ):
            ok = cmd_setup._check_connector_version_supported_for_setup(
                "codex", mode="action", emit=False, data_dir=str(data), _allow_prompt=False
            )

        cache = ad._read_cache(data_dir=data)
        assert ok is True
        assert cache.agents["cursor"].version == newer
        assert cache.agents["codex"].version == "codex-cli 0.160.0"
