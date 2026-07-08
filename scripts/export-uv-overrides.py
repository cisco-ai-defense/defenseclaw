#!/usr/bin/env python3
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

"""Export pyproject.toml's uv override-dependencies as a requirements file."""

from __future__ import annotations

import sys
from pathlib import Path

import tomllib


def main() -> int:
    source = Path(sys.argv[1] if len(sys.argv) > 1 else "pyproject.toml")
    try:
        payload = tomllib.loads(source.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"failed to read {source}: {exc}", file=sys.stderr)
        return 1
    overrides = payload.get("tool", {}).get("uv", {}).get("override-dependencies", [])
    if not isinstance(overrides, list) or not overrides:
        print(f"no [tool.uv].override-dependencies in {source}", file=sys.stderr)
        return 1
    for value in overrides:
        if not isinstance(value, str) or not value.strip():
            print(f"invalid override-dependencies entry in {source}", file=sys.stderr)
            return 1
        print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
