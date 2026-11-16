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

"""Native stand-in programs for tests that need a program at a given path.

A test that must run "a program named opencode" cannot copy or link a system
binary: a distribution may ship sleep(1) or echo(1) as one entry of a
multi-call binary that refuses to run under another name (Ubuntu 26.04). The
sources are the ones the Go tests build (internal/testenv/native).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SOURCES = Path(__file__).resolve().parents[2] / "internal" / "testenv" / "native"


def native_program(destination: Path, kind: str) -> Path:
    """Build the native stand-in ``kind`` ("sleep" or "echo") at ``destination``."""
    compiler = shutil.which(os.environ.get("CC") or "cc")
    if compiler is None:
        pytest.fail("this test builds a stand-in program and needs a C compiler (cc)")
    destination.parent.mkdir(parents=True, exist_ok=True)
    built = subprocess.run(
        [compiler, "-o", os.fspath(destination), os.fspath(SOURCES / f"{kind}.c")],
        capture_output=True, text=True, check=False,
    )
    if built.returncode != 0:
        pytest.fail(f"building the {kind} stand-in failed: {built.stderr}")
    destination.chmod(0o755)
    return destination
