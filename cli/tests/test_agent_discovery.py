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

from defenseclaw.connector_paths import KNOWN_AGENT_KINDS, KNOWN_CONNECTORS
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
    assert len(calls) == len(KNOWN_AGENT_KINDS)

    cache_file = Path(os.environ["DEFENSECLAW_HOME"]) / ad.CACHE_FILENAME
    assert cache_file.is_file()
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
    # Retargeted from codex → openclaw: codex now uses the metadata-only
    # collector (_collect_codex_versions) rather than shutil.which +
    # --version exec, so the "timeout on exec" branch is only reachable
    # from connectors that stayed on the legacy path (openclaw, hermes,
    # zeptoclaw, geminicli, etc.). Everything the assertion cares about
    # — timeout produces an error, binary_only-install stays false —
    # applies identically to any legacy-path connector.
    _pin_home(monkeypatch, tmp_path)
    monkeypatch.setattr(ad.shutil, "which", lambda name: "/usr/local/bin/openclaw")
    # M-4: bypass the trusted-prefix file-existence check so we can
    # exercise the timeout branch with a path the test doesn't have to
    # actually create on disk.
    monkeypatch.setattr(ad, "_is_trusted_binary_path", lambda path: True)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"])

    monkeypatch.setattr(ad.subprocess, "run", timeout)

    signal = ad._scan_agent("openclaw")

    assert signal.binary_path == "/usr/local/bin/openclaw"
    assert signal.config_path == ""
    assert signal.installed is False
    assert "timed out" in signal.error


def test_version_probe_uses_no_shell_and_list_args(monkeypatch, tmp_path):
    # Retargeted from codex → openclaw (same reason as
    # test_timeout_sets_error_and_does_not_mark_binary_only_install:
    # codex no longer takes the exec path).
    _pin_home(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(ad.shutil, "which", lambda name: "/opt/bin/openclaw")
    # M-4: this fake binary lives in /opt/bin (not a default trusted
    # prefix); waive the trust check so the test focuses on subprocess
    # invocation contract.
    monkeypatch.setattr(ad, "_is_trusted_binary_path", lambda path: True)

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="openclaw 1.2.3\n", stderr="")

    monkeypatch.setattr(ad.subprocess, "run", fake_run)

    signal = ad._scan_agent("openclaw")

    assert signal.installed is True
    assert signal.version == "openclaw 1.2.3"
    args, kwargs = calls[0]
    assert args == ["/opt/bin/openclaw", "--version"]
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
    assert args == ["/opt/bin/openhands", "--version"]
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
#
# NOTE (2026-07): retargeted from codex → openclaw. codex now uses the
# metadata-only collector (_collect_codex_versions) which never
# shutil.which's the binary, so the trust-prefix gate isn't reachable
# from that connector. The gate still applies identically to every
# legacy-path connector (openclaw, hermes, zeptoclaw, geminicli,
# copilot, opencode) — these tests cover it via openclaw.
def test_version_probe_probes_untrusted_prefix_by_default(monkeypatch, tmp_path):
    hostile = tmp_path / "hostile_bin" / "openclaw"
    hostile.parent.mkdir(parents=True, exist_ok=True)
    hostile.write_text("#!/bin/sh\nexit 0\n")
    hostile.chmod(0o755)
    monkeypatch.setattr(ad.shutil, "which", lambda name: str(hostile))

    called = []

    def fake_run(*args, **kwargs):
        called.append((args, kwargs))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="openclaw 0.0\n", stderr="")

    monkeypatch.setattr(ad.subprocess, "run", fake_run)
    monkeypatch.delenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", raising=False)

    signal = ad._scan_agent("openclaw")

    assert called, "default discovery should probe without trusted-prefix enforcement"
    assert signal.binary_path == str(hostile)
    assert signal.version == "openclaw 0.0"
    assert signal.error == ""


def test_version_probe_refuses_binary_outside_trusted_prefix_when_enabled(monkeypatch, tmp_path):
    hostile = tmp_path / "hostile_bin" / "openclaw"
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

    signal = ad._scan_agent("openclaw", require_trusted_binary_paths=True)

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
    # Retargeted from codex → openclaw: same reason as
    # test_version_probe_probes_untrusted_prefix_by_default.
    data_dir = tmp_path / ".defenseclaw"
    data_dir.mkdir()
    binary = tmp_path / "tools" / "openclaw"
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
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="openclaw 1.2.3\n", stderr="")

    monkeypatch.setattr(ad.subprocess, "run", fake_run)
    signal = ad._scan_agent(
        "openclaw",
        data_dir=data_dir,
        require_trusted_binary_paths=True,
    )

    assert signal.installed is True
    assert signal.version == "openclaw 1.2.3"


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


def test_semver_regex_matches_across_files():
    """Drift guard for the two _VERSION_RE definitions.

    ``defenseclaw/inventory/_semver.py`` and
    ``scripts/connector-version-radar.py`` intentionally keep separate
    copies of the semver regex (the radar is a standalone lab script
    outside the CLI import path), but the two compiled patterns MUST
    stay identical — a drift means one side accepts a version shape
    the other rejects, which produces hard-to-reproduce ``ValueError``s
    on the radar path or the reverse.

    Uses ``ast`` to find the ``_VERSION_RE = re.compile(...)`` node in
    each file and concatenates every string argument literal. A prior
    version of this test scanned for the first `)` byte after the
    marker, which stopped inside the lookbehind ``(?<![0-9A-Za-z])``
    and only compared the prefix — CodeRabbit caught that during PR
    review. AST parsing is the robust way to grab the full pattern
    argument regardless of formatting.
    """
    import ast

    repo_root = Path(__file__).resolve().parents[2]
    semver_py = (repo_root / "cli" / "defenseclaw" / "inventory" / "_semver.py").read_text()
    radar_py = (repo_root / "scripts" / "connector-version-radar.py").read_text()

    def _extract(source: str, source_path: str) -> str:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not (len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == "_VERSION_RE"):
                continue
            value = node.value
            if not (isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Attribute)
                    and value.func.attr == "compile"):
                continue
            # `re.compile(...)` accepts (pattern, flags). We care only
            # about the pattern arg. Concatenate every string literal
            # in it so multi-line
            #     re.compile("a" "b")
            # style splits still compare correctly.
            pattern_parts: list[str] = []
            pattern_arg = value.args[0]
            if isinstance(pattern_arg, ast.Constant) and isinstance(pattern_arg.value, str):
                pattern_parts.append(pattern_arg.value)
            elif isinstance(pattern_arg, ast.BinOp):
                # Not expected today, but be resilient to a future
                # concatenation refactor.
                pattern_parts.append(ast.unparse(pattern_arg))
            else:
                raise AssertionError(
                    f"{source_path}: unsupported _VERSION_RE literal shape "
                    f"{ast.dump(pattern_arg)}"
                )
            return "".join(pattern_parts)
        raise AssertionError(f"{source_path}: _VERSION_RE = re.compile(...) not found")

    semver_pat = _extract(semver_py, "_semver.py")
    radar_pat = _extract(radar_py, "connector-version-radar.py")
    assert semver_pat == radar_pat, (
        "_VERSION_RE in _semver.py has drifted from "
        "scripts/connector-version-radar.py:\n"
        f"  _semver.py:      {semver_pat!r}\n"
        f"  version-radar:   {radar_pat!r}\n"
        "Keep the two byte-for-byte identical or route both through a "
        "shared import."
    )


def test_known_agent_kinds_matches_go_promoted_agent_kinds():
    """Drift guard for the KNOWN_AGENT_KINDS ↔ promotedAgentKinds contract.

    The Python-side ``KNOWN_AGENT_KINDS`` (this file's neighbour
    ``defenseclaw/connector_paths.py``) lists discovery-only agents that
    the CLI treats as first-class for inventory / TUI purposes but that
    have no DefenseClaw enforcement path. The Go side promotes the same
    set via ``promotedAgentKinds`` in
    ``internal/inventory/ai_catalog.go``; the connector-slug VALUES on
    both sides must agree, otherwise dashboards that join on
    ``agent_kind`` will silently miss surfaces on one side.

    The Go map keys are signature IDs (``claude-desktop``) whose
    Python analogue in ``KNOWN_AGENT_KINDS`` is the *normalised* slug
    (``claudedesktop``); this test compares the two sides after
    stripping the documented `-` → `` normalisation. Any drift —
    add/remove/rename on either side — trips the assertion.
    """
    import re

    repo_root = Path(__file__).resolve().parents[2]
    catalog_go = (repo_root / "internal" / "inventory" / "ai_catalog.go").read_text()

    # Extract the map body between the opening `{` and matching `}` on
    # promotedAgentKinds. `\A(?:.|\n)*?` skips ahead lazily; keeping
    # this pattern tight avoids matching later map blocks.
    match = re.search(
        r"promotedAgentKinds\s*=\s*map\[string\]string\{([^}]+)\}",
        catalog_go,
    )
    assert match, "promotedAgentKinds map not found in ai_catalog.go"
    entries = re.findall(r'"([^"]+)"\s*:\s*"([^"]+)"', match.group(1))
    assert entries, "promotedAgentKinds body parsed to zero entries — regex drift?"

    # Every Go-side connector-slug value must appear in KNOWN_AGENT_KINDS.
    go_slugs = {slug for _, slug in entries}
    python_promoted = set(KNOWN_AGENT_KINDS) - set(KNOWN_CONNECTORS)
    assert go_slugs == python_promoted, (
        f"KNOWN_AGENT_KINDS ↔ promotedAgentKinds drift: "
        f"Go-only={sorted(go_slugs - python_promoted)}, "
        f"Python-only={sorted(python_promoted - go_slugs)}"
    )
