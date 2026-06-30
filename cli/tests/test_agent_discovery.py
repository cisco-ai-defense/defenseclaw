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

import pytest
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
    monkeypatch.setenv("USERPROFILE", str(tmp_path))


def test_discovery_trust_config_honors_config_override(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    config_path = tmp_path / "managed" / "config.yaml"
    config_path.parent.mkdir()
    config_path.write_text(
        "ai_discovery:\n  require_trusted_binary_paths: true\n  trusted_binary_prefixes: [/opt/enterprise/bin]\n"
    )
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(config_path))

    required, prefixes = ad._ai_discovery_trust_config(data_dir)

    assert required is True
    assert prefixes == ("/opt/enterprise/bin",)


def test_cache_miss_hit_and_ttl_expiry(monkeypatch, tmp_path):
    _pin_home(monkeypatch, tmp_path)
    now = datetime(2026, 5, 4, 18, 21, tzinfo=timezone.utc)
    calls: list[str] = []

    def fake_scan(name: str, **_kwargs) -> ad.AgentSignal:
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
    if os.name == "nt":
        assert ad._windows_acl_write_error(str(cache_file)) is None
    else:
        assert stat.S_IMODE(cache_file.stat().st_mode) == 0o600

    calls.clear()
    monkeypatch.setattr(ad, "_scan_agent", lambda name, **_kwargs: (_ for _ in ()).throw(AssertionError(name)))
    cached = ad.discover_agents()
    assert cached.cache_hit is True
    assert cached.agents["codex"].installed is True
    assert calls == []

    expired = now + timedelta(seconds=ad.CACHE_TTL_SECONDS + 1)
    monkeypatch.setattr(ad, "_now_utc", lambda: expired)
    monkeypatch.setattr(ad, "_scan_agent", lambda name, **_kwargs: _signal(name, name == "claudecode"))
    refreshed = ad.discover_agents()
    assert refreshed.cache_hit is False
    assert refreshed.agents["codex"].installed is False
    assert refreshed.agents["claudecode"].installed is True


def test_schema_version_mismatch_rescans(monkeypatch, tmp_path):
    _pin_home(monkeypatch, tmp_path)
    data_dir = Path(os.environ["DEFENSECLAW_HOME"])
    data_dir.mkdir(parents=True)
    (data_dir / ad.CACHE_FILENAME).write_text(
        json.dumps(
            {
                "version": 999,
                "scanned_at": "2026-05-04T18:21:00Z",
                "ttl_seconds": ad.CACHE_TTL_SECONDS,
                "agents": {},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(ad, "_now_utc", lambda: datetime(2026, 5, 4, 18, 22, tzinfo=timezone.utc))
    monkeypatch.setattr(ad, "_scan_agent", lambda name, **_kwargs: _signal(name, name == "openclaw"))

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

    assert signal.binary_path == os.path.abspath("/usr/local/bin/codex")
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
    assert args == [os.path.abspath("/opt/bin/codex"), "--version"]
    assert kwargs["shell"] is False
    assert kwargs["timeout"] == 2.0
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True


def test_openhands_version_probe_prefers_cli_line_after_banner(monkeypatch, tmp_path):
    _pin_home(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(ad.shutil, "which", lambda name: "/opt/bin/openhands")
    monkeypatch.setattr(ad, "_is_trusted_binary_path", lambda path: True)

    banner = """+----------------------------------------------------------------------+
|  OpenHands SDK v1.21.0                                               |
+----------------------------------------------------------------------+

OpenHands CLI 1.16.0
"""

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=banner, stderr="")

    monkeypatch.setattr(ad.subprocess, "run", fake_run)

    signal = ad._scan_agent("openhands")

    assert signal.installed is True
    assert signal.version == "OpenHands CLI 1.16.0"
    args, kwargs = calls[0]
    assert args == [os.path.abspath("/opt/bin/openhands"), "--version"]
    assert kwargs["timeout"] == 8.0
    assert kwargs["env"]["OPENHANDS_SUPPRESS_BANNER"] == "1"


def test_hermes_version_probe_gets_longer_timeout(monkeypatch, tmp_path):
    _pin_home(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(ad.shutil, "which", lambda name: "/opt/bin/hermes")
    monkeypatch.setattr(ad, "_is_trusted_binary_path", lambda path: True)

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="Hermes Agent v0.13.0\n", stderr="")

    monkeypatch.setattr(ad.subprocess, "run", fake_run)

    signal = ad._scan_agent("hermes")

    assert signal.installed is True
    assert signal.version == "Hermes Agent v0.13.0"
    _, kwargs = calls[0]
    assert kwargs["timeout"] == 8.0


def test_windows_executable_suffixes_preserve_agent_specific_probe_rules(monkeypatch):
    calls = []
    monkeypatch.setattr(ad, "_is_trusted_binary_path", lambda _path: True)

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout="SDK banner\nOpenHands CLI 1.16.0\n",
            stderr="",
        )

    monkeypatch.setattr(ad.subprocess, "run", fake_run)

    version, error = ad._version_for_binary(r"C:\Tools\openhands.EXE", ("--version",))

    assert error == ""
    assert version == "OpenHands CLI 1.16.0"
    assert calls[0][1]["timeout"] == 8.0
    assert calls[0][1]["env"]["OPENHANDS_SUPPRESS_BANNER"] == "1"


def test_claude_version_probe_gets_longer_timeout_with_exe_suffix(monkeypatch):
    calls = []
    monkeypatch.setattr(ad, "_is_trusted_binary_path", lambda _path: True)

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="2.1.196 (Claude Code)\n", stderr="")

    monkeypatch.setattr(ad.subprocess, "run", fake_run)

    version, error = ad._version_for_binary(r"C:\Tools\claude.EXE", ("--version",))

    assert error == ""
    assert version == "2.1.196 (Claude Code)"
    assert calls[0][1]["timeout"] == 8.0


@pytest.mark.skipif(os.name != "nt", reason="Windows PATHEXT regression")
def test_which_discovers_cmd_wrapper(monkeypatch, tmp_path):
    wrapper = tmp_path / "cursor.CMD"
    wrapper.write_text("@echo 3.9.16\r\n", encoding="utf-8")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")

    assert ad._path_key(ad._which("cursor")) == ad._path_key(str(wrapper))


def test_omnigent_discovery_honors_config_home(monkeypatch, tmp_path):
    _pin_home(monkeypatch, tmp_path)
    config_home = tmp_path / "omnigent-config-home"
    config_home.mkdir()
    config_path = config_home / "config.yaml"
    config_path.write_text("policies: {}\n", encoding="utf-8")
    monkeypatch.setenv("OMNIGENT_CONFIG_HOME", str(config_home))
    monkeypatch.setattr(ad.shutil, "which", lambda _name: None)

    signal = ad._scan_agent("omnigent")

    assert signal.installed is True
    assert signal.config_path == str(config_path)


def test_omnigent_discovery_does_not_fall_back_when_config_home_is_set(monkeypatch, tmp_path):
    _pin_home(monkeypatch, tmp_path)
    default_home = tmp_path / ".omnigent"
    default_home.mkdir()
    (default_home / "config.yaml").write_text("policies: {}\n", encoding="utf-8")
    monkeypatch.setenv("OMNIGENT_CONFIG_HOME", str(tmp_path / "missing-custom-home"))
    monkeypatch.setattr(ad.shutil, "which", lambda _name: None)

    signal = ad._scan_agent("omnigent")

    assert signal.installed is False
    assert signal.config_path == ""


# M-4 regression coverage: the version probe MUST refuse to exec a
# binary that lives outside the canonical install prefixes (an attacker
# who can prepend a hostile directory to PATH could otherwise have us
# run their binary as part of a passive discovery scan).
def test_version_probe_probes_untrusted_prefix_by_default(monkeypatch, tmp_path):
    hostile = tmp_path / "hostile_bin" / "codex"
    hostile.parent.mkdir(parents=True, exist_ok=True)
    hostile.write_text("#!/bin/sh\nexit 0\n")
    hostile.chmod(0o755)
    monkeypatch.setattr(ad.shutil, "which", lambda name: str(hostile))

    called = []

    def fake_run(*args, **kwargs):
        called.append((args, kwargs))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="codex 0.0\n", stderr="")

    monkeypatch.setattr(ad.subprocess, "run", fake_run)
    monkeypatch.delenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", raising=False)

    signal = ad._scan_agent("codex")

    assert called, "default discovery should probe without trusted-prefix enforcement"
    assert signal.binary_path == str(hostile)
    assert signal.version == "codex 0.0"
    assert signal.error == ""


def test_version_probe_refuses_binary_outside_trusted_prefix_when_enabled(monkeypatch, tmp_path):
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

    signal = ad._scan_agent("codex", require_trusted_binary_paths=True)

    assert called == [], "version probe exec'd a binary outside the trusted prefix"
    assert signal.binary_path == str(hostile)
    assert signal.version == ""
    assert "trusted install prefix" in signal.error.lower()


def test_trust_check_accepts_canonical_prefix(monkeypatch, tmp_path):
    # Add tmp_path as a trusted prefix and place a real, non-world-writable
    # binary inside it.
    binary = tmp_path / "bin" / ("codex.exe" if os.name == "nt" else "codex")
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    binary.parent.chmod(0o755)
    monkeypatch.setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", str(tmp_path))
    assert ad._is_trusted_binary_path(str(binary)) is True


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL regression")
def test_windows_acl_distinguishes_owner_control_from_everyone_write(tmp_path):
    safe = tmp_path / "safe"
    unsafe = tmp_path / "everyone-write"
    safe.mkdir()
    unsafe.mkdir()
    subprocess.run(
        ["icacls", str(unsafe), "/grant", "*S-1-1-0:(OI)(CI)F"],
        check=True,
        capture_output=True,
        text=True,
    )

    _safe_path, safe_error = ad.validate_trusted_prefix(str(safe))
    _unsafe_path, unsafe_error = ad.validate_trusted_prefix(str(unsafe))

    assert safe_error is None
    assert unsafe_error is not None
    assert "Everyone" in unsafe_error


@pytest.mark.skipif(os.name != "nt", reason="Windows path comparison regression")
def test_windows_trust_check_is_case_insensitive(monkeypatch, tmp_path):
    binary = tmp_path / "bin" / "codex.EXE"
    binary.parent.mkdir()
    binary.write_bytes(b"MZ")
    monkeypatch.setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", str(tmp_path).swapcase())

    assert ad._is_trusted_binary_path(str(binary)) is True


@pytest.mark.skipif(os.name != "nt", reason="Windows prefix policy")
def test_windows_defaults_are_narrow_and_reject_drive_root():
    local_app_data = os.environ["LOCALAPPDATA"]
    expected = os.path.join(local_app_data, "Programs", "OpenAI", "Codex", "bin")
    default_keys = {ad._path_key(path) for path in ad._TRUSTED_BIN_PREFIXES_DEFAULT}

    assert ad._path_key(expected) in default_keys
    assert ad._path_key(local_app_data) not in default_keys
    assert ad._expand_bin_prefixes((Path(local_app_data).anchor,)) == []


@pytest.mark.skipif(os.name == "nt", reason="requires unprivileged POSIX symlinks")
def test_trust_check_canonicalises_operator_prefix_symlink(monkeypatch, tmp_path):
    real_root = tmp_path / "real-tools"
    binary = real_root / "bin" / "omnigent"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    binary.parent.chmod(0o755)
    alias = tmp_path / "tools-alias"
    alias.symlink_to(real_root, target_is_directory=True)

    monkeypatch.setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", str(alias))

    assert ad._is_trusted_binary_path(str(alias / "bin" / "omnigent")) is True


def test_trust_check_accepts_config_prefix_when_required(monkeypatch, tmp_path):
    data_dir = tmp_path / ".defenseclaw"
    data_dir.mkdir()
    binary = tmp_path / "tools" / "codex"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    binary.parent.chmod(0o755)
    (data_dir / "config.yaml").write_text(
        f"ai_discovery:\n  require_trusted_binary_paths: true\n  trusted_binary_prefixes:\n    - {binary.parent}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(ad.shutil, "which", lambda name: str(binary))

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="codex 1.2.3\n", stderr="")

    monkeypatch.setattr(ad.subprocess, "run", fake_run)
    signal = ad._scan_agent(
        "codex",
        data_dir=data_dir,
        require_trusted_binary_paths=True,
    )

    assert signal.installed is True
    assert signal.version == "codex 1.2.3"


@pytest.mark.skipif(os.name == "nt", reason="POSIX Homebrew layout")
def test_trust_check_accepts_homebrew_symlink_targets(monkeypatch, tmp_path):
    homebrew = tmp_path / "homebrew"
    real = homebrew / "lib" / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
    real.parent.mkdir(parents=True, exist_ok=True)
    real.write_text("#!/usr/bin/env node\n")
    real.chmod(0o755)
    real.parent.chmod(0o755)
    link_dir = homebrew / "bin"
    link_dir.mkdir(parents=True, exist_ok=True)
    link = link_dir / "codex"
    link.symlink_to(real)

    # F-0421: built-in default prefixes now require root ownership, and the
    # fixture dirs are owned by the (non-root) test user. The symlink-target
    # containment behaviour this test exercises is unchanged — it just has
    # to be reached via an operator opt-in trusted prefix (which keeps the
    # looser per-file/parent permission checks).
    monkeypatch.delenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", raising=False)
    monkeypatch.setenv(
        "DEFENSECLAW_TRUSTED_BIN_PREFIXES",
        ":".join((str(link_dir), str(homebrew / "lib" / "node_modules"))),
    )

    assert ad._is_trusted_binary_path(str(link)) is True


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership semantics")
def test_operator_prefix_still_applies_after_default_prefix_ownership_failure(
    monkeypatch,
    tmp_path,
):
    """A default prefix match must not mask a later operator-added prefix."""
    default_prefix = tmp_path / "homebrew"
    operator_prefix = default_prefix / "lib" / "node_modules" / "@openai" / "codex" / "bin"
    binary = operator_prefix / "codex.js"
    operator_prefix.mkdir(parents=True)
    binary.write_text("#!/usr/bin/env node\n")
    binary.chmod(0o755)
    operator_prefix.chmod(0o755)

    monkeypatch.setattr(
        ad,
        "_trusted_bin_prefixes",
        lambda *_args: (str(default_prefix), str(operator_prefix)),
    )
    monkeypatch.setattr(
        ad,
        "_default_trusted_bin_prefixes",
        lambda: frozenset({str(default_prefix)}),
    )
    monkeypatch.setattr(ad, "_bin_chain_is_system_owned", lambda _resolved, _prefix: False)

    assert ad._is_trusted_binary_path(str(binary)) is True


def test_trust_check_operator_prefix_wins_over_failed_default_ownership(monkeypatch, tmp_path):
    # Regression: Homebrew npm globals live under a default prefix
    # (/opt/homebrew/lib/node_modules) that fails F-0421 root-ownership on
    # user-owned installs. Setup's "trust this directory?" prompt adds only
    # the package bin dir; _is_trusted_binary_path must not return False
    # when that narrower operator prefix matches after the default fails.
    homebrew = tmp_path / "homebrew"
    real = homebrew / "lib" / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
    real.parent.mkdir(parents=True, exist_ok=True)
    real.write_text("#!/usr/bin/env node\n")
    real.chmod(0o755)
    real.parent.chmod(0o755)
    link_dir = homebrew / "bin"
    link_dir.mkdir(parents=True, exist_ok=True)
    link = link_dir / "codex"
    link.symlink_to(real)

    monkeypatch.delenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", raising=False)
    monkeypatch.setenv(
        "DEFENSECLAW_TRUSTED_BIN_PREFIXES",
        str(homebrew / "lib" / "node_modules" / "@openai" / "codex" / "bin"),
    )

    assert ad._is_trusted_binary_path(str(link)) is True


@pytest.mark.skipif(os.name == "nt", reason="requires unprivileged POSIX symlinks")
def test_trust_check_accepts_claude_local_share_target(monkeypatch, tmp_path):
    real = tmp_path / ".local" / "share" / "claude" / "versions" / "2.1.139"
    real.parent.mkdir(parents=True, exist_ok=True)
    real.write_text("#!/bin/sh\nexit 0\n")
    real.chmod(0o755)
    real.parent.chmod(0o755)
    link_dir = tmp_path / ".local" / "bin"
    link_dir.mkdir(parents=True, exist_ok=True)
    link = link_dir / "claude"
    link.symlink_to(real)

    # F-0421: see homebrew test above — user-owned trees are trusted only
    # via explicit operator opt-in now; defaults require root ownership.
    monkeypatch.delenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", raising=False)
    monkeypatch.setenv(
        "DEFENSECLAW_TRUSTED_BIN_PREFIXES",
        ":".join((str(link_dir), str(tmp_path / ".local" / "share" / "claude"))),
    )

    assert ad._is_trusted_binary_path(str(link)) is True


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode-bit policy")
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


@pytest.mark.skipif(os.name == "nt", reason="requires unprivileged POSIX symlinks")
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


@pytest.mark.skipif(os.name == "nt", reason="POSIX default-prefix policy")
def test_default_trusted_prefixes_excludes_user_writable_roots():
    # Regression guard for the secure default: user-writable tool roots
    # are intentionally NOT auto-trusted. A local agent running as the
    # operator can plant a binary (e.g. `codex`) under any of these and
    # the passive discovery scan would otherwise exec it. The modern
    # Codex CLI symlinks ~/.local/bin/codex to a real binary under
    # ~/.codex/packages/standalone/...; operators who want that path
    # discovered must opt in explicitly via
    # DEFENSECLAW_TRUSTED_BIN_PREFIXES (see the opt-in test below).
    for writable in (
        "~/.codex/packages",
        "~/.codex",
        "~/.local/bin",
        "~/.cargo/bin",
    ):
        assert writable not in ad._TRUSTED_BIN_PREFIXES_DEFAULT
    # System-managed prefixes (root / package-manager write only) stay
    # trusted out of the box.
    assert "/usr/bin" in ad._TRUSTED_BIN_PREFIXES_DEFAULT
    assert "/usr/local/bin" in ad._TRUSTED_BIN_PREFIXES_DEFAULT


@pytest.mark.skipif(os.name == "nt", reason="POSIX standalone symlink layout")
def test_trust_check_codex_standalone_symlink_requires_opt_in(monkeypatch, tmp_path):
    # Reproduce the Codex standalone layout under a fake HOME and assert
    # the secure-default behavior plus the documented opt-in escape
    # hatch. Prefixes and binaries are both canonicalised before comparison,
    # including macOS's /var -> /private/var indirection.
    home = Path(os.path.realpath(str(tmp_path)))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", raising=False)

    real = home / ".codex" / "packages" / "standalone" / "releases" / "0.136.0-aarch64-apple-darwin" / "bin" / "codex"
    real.parent.mkdir(parents=True, exist_ok=True)
    real.write_text("#!/bin/sh\nexit 0\n")
    real.chmod(0o755)
    real.parent.chmod(0o755)

    link_dir = home / ".local" / "bin"
    link_dir.mkdir(parents=True, exist_ok=True)
    link = link_dir / "codex"
    link.symlink_to(real)

    # Default (no env override): the user-writable ~/.codex/packages root
    # is NOT trusted, so discovery refuses to exec the resolved binary.
    assert ad._is_trusted_binary_path(str(link)) is False

    # Opt-in: an operator who deliberately trusts the Codex standalone
    # root via DEFENSECLAW_TRUSTED_BIN_PREFIXES makes the same symlink
    # resolve as trusted (the per-file / parent permission checks still
    # apply on top — the fixture's 0o755 binary + parent satisfy them).
    monkeypatch.setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", str(home / ".codex" / "packages"))
    assert ad._is_trusted_binary_path(str(link)) is True


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
