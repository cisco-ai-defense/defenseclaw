#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Emit Local Splunk lifecycle telemetry without an in-container shell."""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import uuid
from pathlib import Path

from product_telemetry_sender import emit_event, emit_result

INSTANCE_ID_PATH = Path(
    "/opt/splunk/etc/apps/defenseclaw_local_mode/local/.product_telemetry_instance_id"
)
SPLUNK_VERSION_COMMAND = ["/opt/splunk/bin/splunk", "version"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--event-type",
        required=True,
        choices=("startup", "integration_configured", "shutdown"),
    )
    return parser.parse_args()


def ensure_instance_id(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    instance_id = str(uuid.uuid4())
    path.write_text(instance_id + "\n", encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return instance_id


def read_splunk_version() -> str:
    try:
        result = subprocess.run(
            SPLUNK_VERSION_COMMAND,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    match = re.search(r"^Splunk ([^ ]+)", result.stdout, flags=re.MULTILINE)
    return match.group(1) if match else "unknown"


def main() -> int:
    args = parse_args()
    enabled = os.environ.get("DEFENSECLAW_INTEGRATION_ENABLED", "false")
    sender_args = argparse.Namespace(
        event_type=args.event_type,
        instance_id=ensure_instance_id(INSTANCE_ID_PATH),
        splunk_version=read_splunk_version(),
        defenseclaw_integration_enabled=(
            "true" if enabled.strip().lower() in {"1", "true", "yes", "on"} else "false"
        ),
        event_details_json=None,
        output="json",
        hec_url=os.environ.get("PHONE_HOME_HEC_URL", ""),
        hec_token=os.environ.get("PHONE_HOME_HEC_TOKEN", ""),
        enabled=os.environ.get("PHONE_HOME_ENABLED", "true"),
        timeout=10,
    )
    payload, result = emit_event(sender_args)
    return emit_result(payload, result, sender_args.output)


if __name__ == "__main__":
    raise SystemExit(main())
