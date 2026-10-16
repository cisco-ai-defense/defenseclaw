# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""#1249: every enterprise build stamps the source commit and the build time."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_the_windows_enterprise_builds_stamp_the_commit_and_its_time() -> None:
    # `defenseclaw-gateway --version` showed an unknown build time on Windows.
    bundle = (ROOT / "packaging" / "scripts" / "build-managed-windows-bundle.sh").read_text(encoding="utf-8")
    stamp = 'STAMP="-X main.version=${VERSION} -X main.commit=${SOURCE_COMMIT} -X main.date=${SOURCE_DATE}"'
    assert stamp in bundle
    assert (
        'SOURCE_DATE="$(TZ=UTC git -C "${REPO_ROOT}" show -s --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ HEAD)"'
        in bundle
    )
    for name in ("GATEWAY", "HOOK", "BROKER", "SENSOR_HELPER", "ACP"):
        line = re.search(rf'^LDFLAGS_{name}="([^"]*)"$', bundle, re.M)
        assert line is not None and line.group(1).endswith("${STAMP}"), name
    setup = (ROOT / "packaging" / "windows" / "standalone" / "build-setup.sh").read_text(encoding="utf-8")
    assert '-X main.commit=${SOURCE_COMMIT} -X main.date=$(TZ=UTC git -C "${REPO_ROOT}" show -s --format=%cd' in setup


def test_the_macos_bundle_stamps_the_commit_and_build_time() -> None:
    # The generic macOS bundle stamped only the version: unknown commit.
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "BUNDLE_LDFLAGS := -X main.version=$(VERSION) $(BUILD_INFO_LDFLAGS)" in makefile
    assert "BUILD_INFO_LDFLAGS := -X main.commit=$(GIT_COMMIT) -X main.date=$(BUILD_DATE)" in makefile
    pkg = (ROOT / "scripts" / "build-macos-enterprise-pkg.sh").read_text(encoding="utf-8")
    assert "-X main.commit=${COMMIT} -X main.date=${DATE}" in pkg
