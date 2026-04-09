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

"""Audit logger — convenience wrapper over Store for scan/action logging.

Mirrors internal/audit/logger.go.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

from defenseclaw.db import Store
from defenseclaw.models import Event, ScanResult


class Logger:
    def __init__(self, store: Store, splunk_cfg: Any | None = None) -> None:
        self.store = store
        self._splunk = _SplunkForwarder(splunk_cfg)

    def log_scan(self, result: ScanResult) -> None:
        scan_id = str(uuid.uuid4())
        raw = result.to_json()
        duration_ms = int(result.duration.total_seconds() * 1000)
        max_sev = result.max_severity()

        self.store.insert_scan_result(
            scan_id, result.scanner, result.target, result.timestamp,
            duration_ms, len(result.findings), max_sev, raw,
        )

        for f in result.findings:
            tags_json = json.dumps(f.tags) if f.tags else "[]"
            self.store.insert_finding(
                str(uuid.uuid4()), scan_id, f.severity, f.title,
                f.description, f.location, f.remediation, f.scanner, tags_json,
            )

        event = Event(
            timestamp=datetime.now(timezone.utc),
            action="scan",
            target=result.target,
            details=(
                f"scanner={result.scanner} findings={len(result.findings)} "
                f"max_severity={max_sev} duration={result.duration}"
            ),
            severity=max_sev,
            run_id=_current_run_id(),
        )
        self.store.log_event(event)
        self._splunk.forward_event(event)

    def log_action(self, action: str, target: str, details: str) -> None:
        event = Event(
            timestamp=datetime.now(timezone.utc),
            action=action,
            target=target,
            details=details,
            severity="INFO",
            run_id=_current_run_id(),
        )
        self.store.log_event(event)
        self._splunk.forward_event(event)

    def close(self) -> None:
        self._splunk.close()


def _current_run_id() -> str:
    return os.environ.get("DEFENSECLAW_RUN_ID", "").strip()


class _SplunkForwarder:
    def __init__(self, splunk_cfg: Any | None) -> None:
        self.cfg = splunk_cfg

    def close(self) -> None:
        return

    def forward_event(self, event: Event) -> None:
        if not self.cfg or not getattr(self.cfg, "enabled", False):
            return

        endpoint = _normalize_hec_endpoint(getattr(self.cfg, "hec_endpoint", ""))
        token = self.cfg.resolved_hec_token() if hasattr(self.cfg, "resolved_hec_token") else ""
        if not endpoint or not token:
            return

        payload = {
            "time": event.timestamp.timestamp(),
            "source": getattr(self.cfg, "source", "defenseclaw"),
            "sourcetype": getattr(self.cfg, "sourcetype", "_json"),
            "index": getattr(self.cfg, "index", "defenseclaw"),
            "event": {
                "id": event.id,
                "timestamp": event.timestamp.isoformat(),
                "action": event.action,
                "target": event.target,
                "actor": event.actor,
                "details": event.details,
                "severity": event.severity,
                "run_id": event.run_id,
                "source": "defenseclaw",
            },
        }

        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                method="POST",
                headers={
                    "Authorization": f"Splunk {token}",
                    "Content-Type": "application/json",
                },
            )
            ctx = None
            if not getattr(self.cfg, "verify_tls", False):
                import ssl

                ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                if getattr(resp, "status", 200) >= 400:
                    raise urllib.error.HTTPError(
                        endpoint,
                        resp.status,
                        resp.read().decode("utf-8", errors="replace"),
                        hdrs=resp.headers,
                        fp=None,
                    )
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            print(f"warning: splunk forward: {exc}", file=sys.stderr)


def _normalize_hec_endpoint(endpoint: str) -> str:
    endpoint = endpoint.strip().rstrip("/")
    if not endpoint:
        return ""
    suffix = "/services/collector/event"
    if endpoint.endswith(suffix):
        return endpoint
    return endpoint + suffix
