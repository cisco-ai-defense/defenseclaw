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

from __future__ import annotations

import json
import os
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from defenseclaw.connector_paths import KNOWN_CONNECTORS
from defenseclaw.inventory import agent_discovery as ad


def _signal(name: str, installed: bool = False) -> ad.AgentSignal:
    return ad.AgentSignal(
        name=name,
        installed=installed,
        config_path=f"/tmp/{name}.config" if installed else "",
        binary_path="",
        version="",
        error="",
    )


def _discovery(*installed: str, cache_hit: bool = False) -> ad.AgentDiscovery:
    return ad.AgentDiscovery(
        scanned_at="2026-05-04T18:21:00Z",
        agents={name: _signal(name, name in installed) for name in KNOWN_CONNECTORS},
        cache_hit=cache_hit,
    )


def _pin_home(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / ".defenseclaw"))
    monkeypatch.setenv("HOME", str(tmp_path))


def test_cache_miss_hit_and_ttl_expiry(monkeypatch, tmp_path):
    _pin_home(monkeypatch, tmp_path)
    now = datetime(2026, 5, 4, 18, 21, tzinfo=timezone.utc)
    calls: list[str] = []

    def fake_scan(name: str) -> ad.AgentSignal:
        calls.append(name)
        return _signal(name, name == "codex")

    monkeypatch.setattr(ad, "_now_utc", lambda: now)
    monkeypatch.setattr(ad, "_scan_agent", fake_scan)

    first = ad.discover_agents()
    assert first.cache_hit is False
    assert first.agents["codex"].installed is True
    assert len(calls) == len(KNOWN_CONNECTORS)

    cache_file = Path(os.environ["DEFENSECLAW_HOME"]) / ad.CACHE_FILENAME
    assert cache_file.is_file()
    assert stat.S_IMODE(cache_file.stat().st_mode) == 0o600

    calls.clear()
    monkeypatch.setattr(ad, "_scan_agent", lambda name: (_ for _ in ()).throw(AssertionError(name)))
    cached = ad.discover_agents()
    assert cached.cache_hit is True
    assert cached.agents["codex"].installed is True
    assert calls == []

    expired = now + timedelta(seconds=ad.CACHE_TTL_SECONDS + 1)
    monkeypatch.setattr(ad, "_now_utc", lambda: expired)
    monkeypatch.setattr(ad, "_scan_agent", lambda name: _signal(name, name == "claudecode"))
    refreshed = ad.discover_agents()
    assert refreshed.cache_hit is False
    assert refreshed.agents["codex"].installed is False
    assert refreshed.agents["claudecode"].installed is True


def test_schema_version_mismatch_rescans(monkeypatch, tmp_path):
    _pin_home(monkeypatch, tmp_path)
    data_dir = Path(os.environ["DEFENSECLAW_HOME"])
    data_dir.mkdir(parents=True)
    (data_dir / ad.CACHE_FILENAME).write_text(
        json.dumps({
            "version": 999,
            "scanned_at": "2026-05-04T18:21:00Z",
            "ttl_seconds": ad.CACHE_TTL_SECONDS,
            "agents": {},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(ad, "_now_utc", lambda: datetime(2026, 5, 4, 18, 22, tzinfo=timezone.utc))
    monkeypatch.setattr(ad, "_scan_agent", lambda name: _signal(name, name == "openclaw"))

    disc = ad.discover_agents()

    assert disc.cache_hit is False
    assert disc.agents["openclaw"].installed is True


def test_timeout_sets_error_and_does_not_mark_binary_only_install(monkeypatch, tmp_path):
    _pin_home(monkeypatch, tmp_path)
    monkeypatch.setattr(ad.shutil, "which", lambda name: "/usr/local/bin/codex")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"])

    monkeypatch.setattr(ad.subprocess, "run", timeout)

    signal = ad._scan_agent("codex")

    assert signal.binary_path == "/usr/local/bin/codex"
    assert signal.config_path == ""
    assert signal.installed is False
    assert "timed out" in signal.error


def test_version_probe_uses_no_shell_and_list_args(monkeypatch, tmp_path):
    _pin_home(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(ad.shutil, "which", lambda name: "/opt/bin/codex")

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="codex 1.2.3\n", stderr="")

    monkeypatch.setattr(ad.subprocess, "run", fake_run)

    signal = ad._scan_agent("codex")

    assert signal.installed is True
    assert signal.version == "codex 1.2.3"
    args, kwargs = calls[0]
    assert args == ["/opt/bin/codex", "--version"]
    assert kwargs["shell"] is False
    assert kwargs["timeout"] == 2.0
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True


def test_first_installed_precedence():
    assert ad.first_installed(_discovery("claudecode"), "claudecode") == "claudecode"
    assert ad.first_installed(_discovery(*KNOWN_CONNECTORS), "codex") == "codex"
    assert ad.first_installed(_discovery(), "codex") == "codex"
    assert ad.first_installed(_discovery("openclaw"), "not-real") == "openclaw"


def test_render_discovery_table_includes_connectors_and_cache_state():
    rendered = ad.render_discovery_table(_discovery("codex", cache_hit=True))

    assert "Agent discovery" in rendered
    assert "cached" in rendered
    assert "codex" in rendered
    assert "yes" in rendered
