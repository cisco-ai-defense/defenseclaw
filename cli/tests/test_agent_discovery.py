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
    # M-4: bypass the trusted-prefix file-existence check so we can
    # exercise the timeout branch with a path the test doesn't have to
    # actually create on disk.
    monkeypatch.setattr(ad, "_is_trusted_binary_path", lambda path: True)

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
    # M-4: this fake binary lives in /opt/bin (not a default trusted
    # prefix); waive the trust check so the test focuses on subprocess
    # invocation contract.
    monkeypatch.setattr(ad, "_is_trusted_binary_path", lambda path: True)

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


# M-4 regression coverage: the version probe MUST refuse to exec a
# binary that lives outside the canonical install prefixes (an attacker
# who can prepend a hostile directory to PATH could otherwise have us
# run their binary as part of a passive discovery scan).
def test_version_probe_refuses_binary_outside_trusted_prefix(monkeypatch, tmp_path):
    hostile = tmp_path / "hostile_bin" / "codex"
    hostile.parent.mkdir(parents=True, exist_ok=True)
    hostile.write_text("#!/bin/sh\nexit 0\n")
    hostile.chmod(0o755)
    monkeypatch.setattr(ad.shutil, "which", lambda name: str(hostile))

    called = []

    def fake_run(*args, **kwargs):
        called.append((args, kwargs))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="pwned 0.0\n", stderr="")

    monkeypatch.setattr(ad.subprocess, "run", fake_run)
    monkeypatch.delenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", raising=False)

    signal = ad._scan_agent("codex")

    assert called == [], "version probe exec'd a binary outside the trusted prefix"
    assert signal.binary_path == str(hostile)
    assert signal.version == ""
    assert "trusted install prefix" in signal.error.lower()


def test_trust_check_accepts_canonical_prefix(monkeypatch, tmp_path):
    # Add tmp_path as a trusted prefix and place a real, non-world-writable
    # binary inside it.
    binary = tmp_path / "bin" / "codex"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    binary.parent.chmod(0o755)
    monkeypatch.setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", str(tmp_path))
    assert ad._is_trusted_binary_path(str(binary)) is True


def test_trust_check_rejects_world_writable_parent(monkeypatch, tmp_path):
    binary = tmp_path / "bin" / "codex"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    # World-writable parent → an attacker who can write here could swap
    # the binary out from under us at any time.
    binary.parent.chmod(0o757)
    monkeypatch.setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", str(tmp_path))
    assert ad._is_trusted_binary_path(str(binary)) is False


def test_trust_check_follows_symlinks(monkeypatch, tmp_path):
    real = tmp_path / "untrusted" / "real-bin"
    real.parent.mkdir(parents=True, exist_ok=True)
    real.write_text("#!/bin/sh\nexit 0\n")
    real.chmod(0o755)
    real.parent.chmod(0o755)
    trusted_dir = tmp_path / "trusted"
    trusted_dir.mkdir()
    link = trusted_dir / "codex"
    link.symlink_to(real)
    monkeypatch.setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", str(trusted_dir))
    # Symlink is in a trusted prefix, but its target is not — must reject.
    assert ad._is_trusted_binary_path(str(link)) is False


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
