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

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALL_DEV = ROOT / "scripts" / "install-dev.sh"


def test_dev_install_syncs_openclaw_embed_before_go_build() -> None:
    text = INSTALL_DEV.read_text(encoding="utf-8")
    sync = 'make -C "${REPO_ROOT}" sync-openclaw-extension'
    build = 'GOOS="${OS}" GOARCH="${ARCH_NORMALIZED}" go build'
    assert sync in text
    assert build in text
    assert text.index(sync) < text.index(build)
