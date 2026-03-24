"""Audit logger — convenience wrapper over Store for scan/action logging.

Mirrors internal/audit/logger.go.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from defenseclaw.db import Store
from defenseclaw.models import Event, ScanResult


class Logger:
    def __init__(self, store: Store) -> None:
        self.store = store

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
        )
        self.store.log_event(event)

    def log_action(self, action: str, target: str, details: str) -> None:
        event = Event(
            timestamp=datetime.now(timezone.utc),
            action=action,
            target=target,
            details=details,
            severity="INFO",
        )
        self.store.log_event(event)

    def close(self) -> None:
        pass
