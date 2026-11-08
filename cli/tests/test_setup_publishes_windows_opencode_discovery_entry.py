# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Native Windows OpenCode/Amp setup records the executable it verified.

The setup scan of these two connectors does not rewrite the whole discovery
cache (that would erase the reviewed version of another connector), so setup
used to leave no entry at all and doctor failed a healthy fresh setup as
"installation unavailable" until ``defenseclaw agent discover --refresh``.
Setup now publishes its own connector entry and leaves every other as it was.
"""

from __future__ import annotations

import atexit
import shutil
import tempfile
from pathlib import Path
from unittest import mock

import pytest
from defenseclaw.commands import cmd_setup
from defenseclaw.inventory import agent_discovery as ad

_EXES = Path(tempfile.mkdtemp(prefix="setup-discovery-exes-"))
atexit.register(shutil.rmtree, _EXES, ignore_errors=True)
_CURSOR = str(_EXES / "cursor")
Path(_CURSOR).write_text("cursor", encoding="utf-8")
_AGENT = str(_EXES / "agent")
Path(_AGENT).write_text("agent", encoding="utf-8")


def _empty() -> dict[str, ad.AgentSignal]:
    return {
        name: ad.AgentSignal(name=name, installed=False, config_path="", binary_path="", version="", error="")
        for name in ad.DISCOVERABLE_CONNECTORS
    }


def _scan(connector: str, *, installed: bool = True) -> ad.AgentDiscovery:
    agents = _empty()
    agents[connector] = ad.AgentSignal(
        name=connector,
        installed=installed,
        config_path="",
        binary_path=_AGENT if installed else "",
        version="2.2.6" if installed else "",
        error="",
        identity=ad._executable_identity(_AGENT) if installed else "",
    )
    return ad.AgentDiscovery(scanned_at=ad._format_rfc3339(ad._now_utc()), agents=agents, cache_hit=False)


def _cache_with_cursor(data_dir: Path) -> None:
    agents = _empty()
    agents["cursor"] = ad.AgentSignal(
        name="cursor",
        installed=True,
        config_path="",
        binary_path=_CURSOR,
        version="3.19.13",
        error="",
        identity=ad._executable_identity(_CURSOR),
    )
    scanned = ad._format_rfc3339(ad._now_utc())
    assert ad._write_cache(ad.AgentDiscovery(scanned_at=scanned, agents=agents, cache_hit=False), data_dir=data_dir)


def _setup_check(host: str, connector: str, scan: ad.AgentDiscovery, data_dir: Path) -> None:
    with (
        mock.patch.object(cmd_setup.platform_support, "host_os", return_value=host),
        mock.patch.object(cmd_setup.agent_discovery, "discover_with_probes", return_value=scan),
    ):
        cmd_setup._check_connector_version_supported_for_setup(
            connector, mode="action", emit=False, data_dir=str(data_dir), _allow_prompt=False
        )


@pytest.mark.parametrize("connector", ("opencode", "amp"))
def test_windows_setup_leaves_the_verified_entry_where_doctor_reads_it(connector, tmp_path) -> None:
    _cache_with_cursor(tmp_path)
    _setup_check("windows", connector, _scan(connector), tmp_path)

    cache = ad._read_cache(data_dir=tmp_path)
    assert cache is not None
    assert cache.agents[connector].installed is True
    assert cache.agents[connector].version == "2.2.6"
    assert cache.agents["cursor"].version == "3.19.13"


def test_windows_setup_with_no_cache_yet_leaves_the_entry(tmp_path) -> None:
    _setup_check("windows", "opencode", _scan("opencode"), tmp_path)
    cache = ad._read_cache(data_dir=tmp_path)
    assert cache is not None and cache.agents["opencode"].installed is True


def test_windows_setup_of_an_agent_that_is_not_installed_publishes_nothing(tmp_path) -> None:
    _cache_with_cursor(tmp_path)
    _setup_check("windows", "opencode", _scan("opencode", installed=False), tmp_path)
    cache = ad._read_cache(data_dir=tmp_path)
    assert cache is not None and cache.agents["opencode"].installed is False
    assert cache.agents["cursor"].version == "3.19.13"


def test_a_scan_handed_in_by_the_caller_is_not_republished(tmp_path) -> None:
    publish = mock.Mock(return_value=True)
    with (
        mock.patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
        mock.patch.object(cmd_setup.agent_discovery, "_publish_agent_signal", publish),
    ):
        cmd_setup._check_connector_version_supported_for_setup(
            "opencode",
            mode="action",
            emit=False,
            data_dir=str(tmp_path),
            _allow_prompt=False,
            _discovery=_scan("opencode"),
        )
    publish.assert_not_called()


@pytest.mark.parametrize("host", ("linux", "darwin"))
def test_other_hosts_keep_the_scan_writing_the_cache_itself(host, tmp_path) -> None:
    # The benign twin: the scan persists on these hosts, so setup adds no second write.
    publish = mock.Mock(return_value=True)
    with mock.patch.object(cmd_setup.agent_discovery, "_publish_agent_signal", publish):
        _setup_check(host, "opencode", _scan("opencode"), tmp_path)
    publish.assert_not_called()
