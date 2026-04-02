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

import json
import os
import platform
from pathlib import Path


def normalize_arch(machine: str) -> str:
    value = machine.strip().lower()
    if value in {"x86_64", "amd64"}:
        return "amd64"
    if value in {"aarch64", "arm64"}:
        return "arm64"
    return value or "unknown"


def parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def main() -> int:
    root = repo_root()
    build_dir = root / "splunk" / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    output_path = build_dir / "defenseclaw_product_telemetry_context.json"

    payload = {
        "platform_arch": f"{platform.system().lower()}/{normalize_arch(platform.machine())}",
        "splunk_image": os.environ.get("SPLUNK_IMAGE", "unknown") or "unknown",
        "phone_home_enabled": parse_bool(os.environ.get("PHONE_HOME_ENABLED", "true")),
        "defenseclaw_integration_enabled": parse_bool(os.environ.get("DEFENSECLAW_INTEGRATION_ENABLED", "false")),
        "nemoclaw_ref": os.environ.get("NEMOCLAW_REF", "unknown") or "unknown",
        "defenseclaw_ref": os.environ.get("DEFENSECLAW_REF", "unknown") or "unknown",
    }
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(str(output_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
