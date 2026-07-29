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

"""Coverage for the multi-install hook-discovery fix.

Pins the two QA regressions we shipped this PR against:

1. Claude Code installed via Anthropic's native installer produces a
   real version (not blank) so managed_enterprise action-mode reaches
   the hook installer.
2. Two Claude Code installs (a stale Homebrew npm-global at 1.9.0 and a
   supported NVM install at 2.5.0) resolve to the NVM version — the
   first-hit-wins loop would previously have stopped at Homebrew.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from defenseclaw.inventory import agent_discovery as ad
from defenseclaw.inventory._semver import parse_version, pick_highest_supported


def _write_pkg_json(path: Path, version: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": version}))


def _native_layout(base: Path, active: str, others: tuple[str, ...] = ()) -> None:
    """Simulate the Anthropic native-installer layout under ``base``."""
    versions = base / "versions"
    (versions / active).mkdir(parents=True, exist_ok=True)
    for other in others:
        (versions / other).mkdir(parents=True, exist_ok=True)
    current = base / "current"
    if current.exists() or current.is_symlink():
        current.unlink()
    current.symlink_to(versions / active)


# ---- semver helpers -------------------------------------------------------


def test_semver_prerelease_ordering() -> None:
    assert parse_version("2.5.0-alpha.1").compare(parse_version("2.5.0")) < 0
    assert parse_version("2.5.0-rc.2").compare(parse_version("2.5.0-rc.1")) > 0
    assert parse_version("2.5.0-1").compare(parse_version("2.5.0-alpha")) < 0
    # Numeric identifiers sort numerically, not lexically.
    assert parse_version("2.5.0-10").compare(parse_version("2.5.0-2")) > 0


def test_pick_highest_supported_prefers_meeting_the_minimum() -> None:
    # Even when 1.9.0 was seen "first", 2.5.0 wins because it clears MIN.
    assert pick_highest_supported(
        [("homebrew", "1.9.0"), ("nvm", "2.5.0")],
        "2.1.144",
    ) == ("nvm", "2.5.0")


def test_pick_highest_supported_falls_back_to_highest_overall() -> None:
    # Both below the minimum → still emit the highest so the Go gate
    # reports "unsupported" rather than "unversioned".
    assert pick_highest_supported(
        [("a", "1.0.0"), ("b", "1.5.0")],
        "2.0.0",
    ) == ("b", "1.5.0")


def test_pick_highest_supported_stable_ties_prefer_first_source() -> None:
    assert pick_highest_supported(
        [("native", "2.5.0"), ("nvm", "2.5.0")],
        "2.0.0",
    ) == ("native", "2.5.0")


def test_pick_highest_supported_ignores_garbage_versions() -> None:
    assert pick_highest_supported(
        [("bad", "not-a-version"), ("good", "2.1.144")],
        "2.1.144",
    ) == ("good", "2.1.144")


def test_pick_highest_supported_empty_returns_none() -> None:
    assert pick_highest_supported([], "1.0.0") is None
    assert pick_highest_supported([("only-garbage", "n/a")], "1.0.0") is None


# ---- multi-install claudecode --------------------------------------------


def test_claudecode_nvm_wins_over_stale_homebrew(monkeypatch, tmp_path: Path) -> None:
    """QA regression #2: two installs, Homebrew is old, NVM is supported."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(home)) if p.startswith("~") else p)

    homebrew_pkg = Path("/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/package.json")
    nvm_pkg = home / ".nvm/versions/node/v22.21.0/lib/node_modules/@anthropic-ai/claude-code/package.json"
    # We can't write to /opt/homebrew inside the test sandbox, so intercept
    # _read_pkg_version instead — this keeps the assertion pinned to the
    # real collector's glob logic while making the fixture hermetic.
    _write_pkg_json(nvm_pkg, "2.5.0")

    original = ad._read_pkg_version
    fake_pkg_versions = {str(homebrew_pkg): "1.9.0"}

    def fake_read_pkg_version(path: str) -> str:
        if path in fake_pkg_versions:
            return fake_pkg_versions[path]
        return original(path)

    monkeypatch.setattr(ad, "_read_pkg_version", fake_read_pkg_version)
    # os.path.isfile is used by _emit-style helpers elsewhere; make the
    # fake homebrew path look present.
    original_isfile = os.path.isfile
    monkeypatch.setattr(
        os.path,
        "isfile",
        lambda p: True if p == str(homebrew_pkg) else original_isfile(p),
    )

    signal = ad._scan_agent("claudecode")
    assert signal.installed is True
    assert signal.version == "2.5.0"
    assert "nvm" in signal.source
    assert signal.error == ""


def test_claudecode_native_installer_yields_real_version(monkeypatch, tmp_path: Path) -> None:
    """QA regression #1: Anthropic native installer → non-blank version."""
    home = tmp_path / "home"
    home.mkdir()
    _native_layout(home / ".local" / "share" / "claude", active="2.5.0")

    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(home)) if p.startswith("~") else p)

    signal = ad._scan_agent("claudecode")
    assert signal.installed is True
    assert signal.version == "2.5.0"
    assert signal.source.endswith("current -> 2.5.0")
    # The trust-prefix gate is deliberately dodged in the metadata path;
    # binary_path stays empty. This is intentional — see _scan_agent
    # comment above.
    assert signal.binary_path == ""
    assert signal.error == ""


def test_claudecode_native_symlink_beats_older_versions_dir(monkeypatch, tmp_path: Path) -> None:
    """The `current` symlink is authoritative even when a higher versions/*/ exists.

    A user who ran ``claude version rollback`` has `current` pointing at
    an older version; the sidecar must report that version so hooks stay
    aligned with what the user is actually running.
    """
    home = tmp_path / "home"
    home.mkdir()
    _native_layout(
        home / ".local" / "share" / "claude",
        active="2.1.144",
        others=("2.5.0",),
    )
    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(home)) if p.startswith("~") else p)

    signal = ad._scan_agent("claudecode")
    assert signal.installed is True
    assert signal.version == "2.1.144"


def test_claudecode_no_installs_falls_back_to_config_presence(monkeypatch, tmp_path: Path) -> None:
    """No enumerable installs → still installed=True when ~/.claude exists."""
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(home)) if p.startswith("~") else p)

    signal = ad._scan_agent("claudecode")
    assert signal.installed is True
    assert signal.version == ""
    assert signal.source == ""


# ---- codex ----------------------------------------------------------------


def test_codex_caskroom_and_npm_yield_highest_supported(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    _write_pkg_json(
        home / ".npm-global/lib/node_modules/@openai/codex/package.json",
        "0.150.0",
    )
    # Simulate a stale Caskroom entry at 0.100.0 below the min.
    caskroom_versions = {"/opt/homebrew/Caskroom/codex": ["0.100.0"]}
    original_listdir = os.listdir
    original_isdir = os.path.isdir

    def fake_listdir(p):
        if p in caskroom_versions:
            return list(caskroom_versions[p])
        return original_listdir(p)

    def fake_isdir(p):
        if p in caskroom_versions:
            return True
        return original_isdir(p)

    monkeypatch.setattr(os, "listdir", fake_listdir)
    monkeypatch.setattr(os.path, "isdir", fake_isdir)
    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(home)) if p.startswith("~") else p)

    signal = ad._scan_agent("codex")
    assert signal.installed is True
    assert signal.version == "0.150.0"
    assert signal.source.endswith("/@openai/codex/package.json")


# ---- min-version alignment -----------------------------------------------


def test_min_versions_match_hook_contracts_json() -> None:
    """Drift guard: the shell installer, this module, and hook_contracts.json
    must agree on MinAgentVersion for the three hookable connectors."""
    hook_contracts_path = (
        Path(__file__).resolve().parent.parent / "defenseclaw" / "inventory" / "hook_contracts.json"
    )
    doc = json.loads(hook_contracts_path.read_text())
    for name, expected in ad._MIN_SUPPORTED_VERSIONS.items():
        contracts = doc["connectors"][name]["contracts"]
        # The default contract is the one flagged for unversioned installs.
        default = next(c for c in contracts if c.get("default_for_unversioned"))
        assert default["agent_version"]["min_inclusive"] == expected, (
            f"{name}: agent_discovery._MIN_SUPPORTED_VERSIONS={expected!r} "
            f"differs from hook_contracts.json {default['agent_version']['min_inclusive']!r}"
        )
