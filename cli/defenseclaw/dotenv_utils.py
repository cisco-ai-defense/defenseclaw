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

"""Shared dotenv file helpers for CLI commands."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def persist_env_var(env_path: Path, key: str, value: str) -> None:
    """Append or update a KEY=VALUE line in a dotenv file."""
    if "\n" in value or "\r" in value:
        raise ValueError(f"{key} must be a single line")
    env_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    found = False
    if env_path.exists():
        lines = env_path.read_text().splitlines()
        new_lines: list[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(f"{key}=") or stripped.startswith(f"export {key}="):
                new_lines.append(f"{key}={value}")
                found = True
            else:
                new_lines.append(line)
        lines = new_lines

    if not found:
        lines.append(f"{key}={value}")

    content = "\n".join(lines) + "\n"

    # A private same-directory temporary file keeps the previous credentials
    # intact if the write fails before replacement.
    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(prefix=f".{env_path.name}.", dir=env_path.parent)
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, env_path)
        temp_path = None
    finally:
        if temp_path is not None:
            Path(temp_path).unlink(missing_ok=True)
