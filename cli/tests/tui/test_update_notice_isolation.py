# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""TUI tests must not depend on the host's release-update cache."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from defenseclaw.update_notice import available_message


def test_a_cached_newer_release_does_not_reach_tui_tests(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The app shows this notice as its first toast, so a host with a newer
    # release cached made toast assertions fail (GAP-0375). The TUI conftest
    # turns the check off for every test in this folder.
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    (tmp_path / ".update-check.json").write_text(
        json.dumps({"checked_at": time.time(), "latest": "99.0.0"}), encoding="utf-8"
    )

    assert available_message() is None
