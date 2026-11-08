# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Native Windows OpenCode/Amp setup records the executable it verified.

The setup scan of these two connectors does not rewrite the whole discovery
cache (that would erase the reviewed version of another connector), so setup
used to leave no entry at all and doctor failed a healthy fresh setup as
"installation unavailable" until ``defenseclaw agent discover --refresh``.
Setup now publishes its own connector entry and leaves every other as it was.

Native-Windows OpenCode takes no generic version check at all: its executable
comes from the protected selection, so the entry is published from that
selection, on the real `setup` command. A cache that is missing or past its
time limit is replaced by a scan, never merged, so no expired entry returns.
"""

from __future__ import annotations

import atexit
import json
import shutil
import tempfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
from defenseclaw import agent_selection
from defenseclaw.commands import cmd_setup
from defenseclaw.doctor_health import assess_connector_health
from defenseclaw.file_permissions import atomic_write_private_bytes
from defenseclaw.inventory import agent_discovery as ad

from tests.helpers import cleanup_app, make_app_context

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


# --- the real native-Windows OpenCode route, and a cache past its time limit ---------------------


def _age(data_dir: Path, *, days: int) -> None:
    path = ad._cache_path(data_dir=data_dir)
    payload = json.loads(path.read_text())
    payload["scanned_at"] = ad._format_rfc3339(ad._now_utc() - timedelta(days=days))
    path.write_text(json.dumps(payload))


def _doctor_status(data_dir: Path, connector: str = "opencode") -> str:
    cache = ad._read_cache(data_dir=data_dir)
    return assess_connector_health([connector], cache)[0].status.value if cache is not None else "no cache"


def _drive_windows_setup(connector: str, data_dir: Path, *, verified_exe: str, version: str = "2.2.6"):
    """Run the real `setup <connector>` command as native Windows with a verified executable."""
    from click.testing import CliRunner
    from defenseclaw.agent_selection import SetupAgentSelection

    def select(target_dir, connectors):
        records = {
            name: SetupAgentSelection(
                connector=name, executable=verified_exe, raw_version=version,
                normalized_version=version, sha256="0" * 64,
            )
            for name in connectors
        }
        agent_selection.publish_setup_agent_selections(target_dir, records)
        return records, {}

    app, temp_dir, db_path = make_app_context()
    try:
        app.cfg.data_dir = str(data_dir)
        app.cfg.save = lambda: atomic_write_private_bytes(str(Path(temp_dir) / "config.yaml"), b"x\n")
        with (
            mock.patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
            mock.patch.object(cmd_setup, "_preflight_opencode_plugin_folder"),
            mock.patch("defenseclaw.agent_selection.record_setup_agent_selections", side_effect=select),
            mock.patch.object(cmd_setup, "_maybe_bring_up_local_stack", return_value=None),
        ):
            return CliRunner().invoke(
                cmd_setup.setup, [connector, "--yes", "--no-restart", "--mode", "action"],
                obj=app, catch_exceptions=True,
            )
    finally:
        cleanup_app(app, db_path, temp_dir)


@pytest.fixture
def opencode_exe(tmp_path) -> str:
    exe = tmp_path / "npm" / "opencode.exe"
    exe.parent.mkdir()
    exe.write_text("opencode", encoding="utf-8")
    return str(exe)


def test_the_real_windows_opencode_setup_leaves_doctor_a_passing_entry(tmp_path, opencode_exe) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    # What init left: a current cache that has not seen OpenCode, and a peer reviewed at a version.
    _cache_with_cursor(data_dir)
    assert _doctor_status(data_dir) == "unavailable"

    result = _drive_windows_setup("opencode", data_dir, verified_exe=opencode_exe)

    assert result.exit_code == 0, result.output
    cache = ad._read_cache(data_dir=data_dir)
    assert cache is not None
    assert cache.agents["opencode"].installed and cache.agents["opencode"].binary_path == opencode_exe
    assert cache.agents["opencode"].version == "2.2.6"
    assert cache.agents["cursor"].version == "3.19.13"  # the peer keeps what it was reviewed at
    assert _doctor_status(data_dir) == "supported"


def test_the_real_windows_opencode_setup_makes_an_expired_cache_readable(tmp_path, opencode_exe) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    _cache_with_cursor(data_dir)
    _age(data_dir, days=2)
    assert ad._read_cache(data_dir=data_dir) is None

    result = _drive_windows_setup("opencode", data_dir, verified_exe=opencode_exe)

    assert result.exit_code == 0, result.output
    assert _doctor_status(data_dir) == "supported"


def test_the_real_windows_opencode_setup_with_no_cache_leaves_a_readable_one(tmp_path, opencode_exe) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    result = _drive_windows_setup("opencode", data_dir, verified_exe=opencode_exe)
    assert result.exit_code == 0, result.output
    assert _doctor_status(data_dir) == "supported"


@pytest.mark.parametrize("cache", ["missing", "expired"])
def test_a_failing_host_scan_does_not_refuse_a_verified_windows_opencode_setup(tmp_path, opencode_exe, cache) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    if cache == "expired":
        _cache_with_cursor(data_dir)
        _age(data_dir, days=2)
    with mock.patch.object(ad, "discover_with_probes", side_effect=RuntimeError("scan failed")):
        result = _drive_windows_setup("opencode", data_dir, verified_exe=opencode_exe)

    # Admission comes from the protected selection; the cache is doctor evidence only.
    assert result.exit_code == 0, result.output
    assert "defenseclaw agent discover --refresh" in result.output
    assert ad._read_cache(data_dir=data_dir) is None


def test_a_verified_publish_reports_any_failure_as_false(tmp_path, opencode_exe) -> None:
    with mock.patch.object(ad, "discover_with_probes", side_effect=OSError("probe denied")):
        assert ad.publish_verified_agent(
            "opencode", binary_path=opencode_exe, version="2.2.6", data_dir=tmp_path
        ) is False


def test_an_expired_cache_is_replaced_by_a_windows_amp_publish(tmp_path) -> None:
    # The helper route (Amp) had the same hole: a cache past its limit stayed unreadable.
    _cache_with_cursor(tmp_path)
    _age(tmp_path, days=2)
    _setup_check("windows", "amp", _scan("amp"), tmp_path)
    cache = ad._read_cache(data_dir=tmp_path)
    assert cache is not None and cache.agents["amp"].installed is True


def test_a_publish_never_writes_a_cache_that_lacks_a_catalog_entry(tmp_path) -> None:
    partial = ad.AgentDiscovery(
        scanned_at=ad._format_rfc3339(ad._now_utc()),
        agents={"opencode": _scan("opencode").agents["opencode"]},
        cache_hit=False,
    )
    assert ad._publish_agent_signal(partial, "opencode", data_dir=tmp_path) is False
    assert not ad._cache_path(data_dir=tmp_path).exists()


def test_a_failed_verified_publish_is_named_with_the_refresh_step(tmp_path, opencode_exe) -> None:
    with (
        mock.patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
        mock.patch.object(cmd_setup.agent_discovery, "publish_verified_agent", return_value=False),
        mock.patch.object(cmd_setup.ux, "warn") as warn,
    ):
        cmd_setup._publish_verified_selection_discovery(
            tmp_path,
            {"opencode": SimpleNamespace(executable=opencode_exe, raw_version="2.2.6")},
        )
    assert "defenseclaw agent discover --refresh" in warn.call_args.args[0]


def test_a_peer_with_its_own_check_is_not_published_twice(tmp_path, opencode_exe) -> None:
    # The benign twin: Codex and Amp are published by the version check, not by the selection step.
    with (
        mock.patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
        mock.patch.object(cmd_setup.agent_discovery, "publish_verified_agent") as publish,
    ):
        cmd_setup._publish_verified_selection_discovery(
            tmp_path, {"codex": SimpleNamespace(executable=opencode_exe, raw_version="1.0.0")}
        )
    publish.assert_not_called()
