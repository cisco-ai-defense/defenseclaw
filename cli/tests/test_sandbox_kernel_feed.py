# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The sandbox kernel feed in the per-user install's lifecycle.

The feed is a root service (``sudo defenseclaw-gateway sandbox kernel-feed
install``) with its own copy of ``defenseclaw-sensor-helper``. The per-user
install ships the helper beside the gateway (Linux), ``defenseclaw
uninstall`` removes that copy and names the command that removes the root
service, and ``install.sh`` says when an upgrade left the feed on an older
release.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from defenseclaw.commands import cmd_uninstall

REPO_ROOT = Path(__file__).resolve().parents[2]


def _plan(**fields: object) -> cmd_uninstall.UninstallPlan:
    return cmd_uninstall.UninstallPlan(**fields)


def test_uninstall_names_the_feed_removal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    unit = tmp_path / "defenseclaw-sandbox-feed.service"
    monkeypatch.setattr(cmd_uninstall.sys, "platform", "linux")
    assert cmd_uninstall._sandbox_kernel_feed_hint(_plan(), str(unit)) == ""
    unit.write_text("[Unit]\n", encoding="utf-8")
    gateway = "/home/dev/.local/bin/defenseclaw-gateway"
    kept = cmd_uninstall._sandbox_kernel_feed_hint(_plan(gateway_path=gateway), str(unit))
    assert kept == f"remove it with `sudo {gateway} sandbox kernel-feed uninstall`"
    # Once the gateway goes, the feed's own root copy removes it.
    gone = cmd_uninstall._sandbox_kernel_feed_hint(_plan(gateway_path=gateway, remove_binaries=True), str(unit))
    assert gone == f"remove it with `sudo {cmd_uninstall._SANDBOX_FEED_HELPER} --sandbox-feed --uninstall`"
    monkeypatch.setattr(cmd_uninstall.sys, "platform", "darwin")
    assert cmd_uninstall._sandbox_kernel_feed_hint(_plan(gateway_path=gateway), str(unit)) == ""


def test_the_feed_paths_match_the_go_lifecycle() -> None:
    lifecycle = (REPO_ROOT / "internal/sensor/sandboxfeed/lifecycle.go").read_text(encoding="utf-8")
    assert 'UnitPath        = "/etc/systemd/system/" + UnitName' in lifecycle
    assert 'UnitName        = "defenseclaw-sandbox-feed.service"' in lifecycle
    assert 'InstallDir      = "/usr/local/libexec/defenseclaw"' in lifecycle
    assert cmd_uninstall._SANDBOX_FEED_UNIT == "/etc/systemd/system/defenseclaw-sandbox-feed.service"
    assert cmd_uninstall._SANDBOX_FEED_HELPER == "/usr/local/libexec/defenseclaw/defenseclaw-sensor-helper"
    installer = (REPO_ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    assert f'SANDBOX_FEED_UNIT="{cmd_uninstall._SANDBOX_FEED_UNIT}"' in installer
    assert f'SANDBOX_FEED_HELPER="{cmd_uninstall._SANDBOX_FEED_HELPER}"' in installer


def test_the_helper_ships_and_is_removed_with_the_per_user_install() -> None:
    release = yaml.safe_load((REPO_ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    default = next(archive for archive in release["archives"] if archive["id"] == "default")
    assert "defenseclaw-sensor-helper-posix" in default["ids"]
    installer = (REPO_ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    managed = re.search(r'^readonly MANAGED_BINARIES="([^"]*)"', installer, re.MULTILINE)
    assert managed and "defenseclaw-sensor-helper" in managed.group(1).split()
    # A Mac install does not keep it: the feed is Linux only.
    assert '[[ "${OS}" == linux ]] || rm -f "${STAGING}/bin/defenseclaw-sensor-helper"' in installer
    _root, targets = cmd_uninstall._owned_binary_targets("linux")
    assert any(target.endswith("/defenseclaw-sensor-helper") for target in targets)
