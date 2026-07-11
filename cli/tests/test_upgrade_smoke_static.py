# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UPGRADE_SMOKE_BASELINES = (
    "0.8.3",
    "0.8.2",
    "0.8.1",
    "0.8.0",
    "0.7.2",
    "0.7.1",
    "0.6.6",
    "0.6.5",
    "0.6.4",
    "0.6.3",
    "0.6.2",
    "0.6.1",
    "0.6.0",
    "0.5.0",
    "0.4.0",
)


def test_makefile_upgrade_smoke_matrix_tracks_supported_baselines() -> None:
    text = (ROOT / "Makefile").read_text()
    match = re.search(r"^UPGRADE_SMOKE_FROM \?= (.+)$", text, re.MULTILINE)
    assert match is not None
    assert tuple(match.group(1).split()) == UPGRADE_SMOKE_BASELINES

    policy = json.loads((ROOT / "release" / "upgrade-baselines.json").read_text())
    assert tuple(policy["published_baselines"]) == UPGRADE_SMOKE_BASELINES


def test_upgrade_smoke_docs_cover_default_matrix() -> None:
    text = (ROOT / "docs" / "TESTING.md").read_text()
    default_line = next(
        line for line in text.splitlines() if line.startswith("The default matrix covers")
    )
    for version in UPGRADE_SMOKE_BASELINES:
        assert f"`{version}`" in default_line


def test_upgrade_smoke_help_example_includes_latest_0_8_releases() -> None:
    text = (ROOT / "scripts" / "test-upgrade-release.sh").read_text()
    assert "0.8.3,0.8.2,0.8.1,0.8.0" in text


def test_posix_resolver_bootstraps_recovery_under_fixed_mutator_lease() -> None:
    text = (ROOT / "scripts" / "upgrade.sh").read_text()
    header = text.index("# ── Platform Detection")
    recovery_call = text.rfind("recover_interrupted_phase_two", 0, header)
    version_detection = text.index('CURRENT_VERSION="unknown"')

    assert recovery_call != -1
    assert recovery_call < version_detection
    assert "phase-two-mutator.lease" in text
    assert "fcntl.flock(descriptor, fcntl.LOCK_EX)" in text
    assert '"--reinstall", str(wheel)' in text
    assert "_recover_interrupted_hard_cut" in text
