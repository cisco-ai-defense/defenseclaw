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
INSTALL_SH = ROOT / "scripts" / "install.sh"


def test_sandbox_installer_fallback_uses_selected_release() -> None:
    text = INSTALL_SH.read_text()
    assert "raw.githubusercontent.com/${REPO}/main/scripts/install-openshell-sandbox.sh" not in text
    assert (
        "raw.githubusercontent.com/${REPO}/${RELEASE_VERSION}/scripts/install-openshell-sandbox.sh"
        in text
    )
