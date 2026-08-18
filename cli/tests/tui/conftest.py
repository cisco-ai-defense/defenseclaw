# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Shared TUI test fixtures."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def current_windows_gateway(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build one current-source gateway before per-test HOME isolation.

    The suite intentionally assigns every Windows test a fresh USERPROFILE.
    Go derives its module cache from that profile, so compiling inside an
    individual test redownloads the complete dependency graph and can exceed
    the shard timeout. A session-scoped build both preserves isolation and
    shares the already authenticated runner cache across the two native TUI
    lifecycle contracts.
    """

    if os.name != "nt":
        pytest.skip("native Windows gateway fixture")
    output_dir = tmp_path_factory.mktemp("current-windows-gateway")
    binary = output_dir / "defenseclaw-gateway.exe"
    build_log = output_dir / "go-build.log"
    repo_root = Path(__file__).resolve().parents[3]
    with build_log.open("wb") as output:
        completed = subprocess.run(
            ["go", "build", "-trimpath", "-o", str(binary), "./cmd/defenseclaw"],
            cwd=repo_root,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=300,
        )
    assert completed.returncode == 0, build_log.read_text(encoding="utf-8", errors="replace")
    return binary
