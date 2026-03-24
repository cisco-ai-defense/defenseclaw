"""AIBOM scanner — stub subprocess wrapper.

Shells out to cisco-aibom CLI (same as Go implementation).
Full implementation deferred.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from defenseclaw.models import Finding, ScanResult


class AIBOMScannerWrapper:
    def __init__(self, binary: str = "cisco-aibom") -> None:
        self.binary = binary

    def name(self) -> str:
        return "aibom"

    def scan(self, target: str) -> ScanResult:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            subprocess.run(
                [self.binary, "analyze", target,
                 "--output-format", "json", "--output-file", tmp_path],
                capture_output=True, text=True, timeout=300,
            )
        except FileNotFoundError:
            print(
                f"error: {self.binary} not found.\n"
                f"  Install with: uv tool install cisco-aibom",
                file=sys.stderr,
            )
            raise SystemExit(1)

        findings: list[Finding] = []
        try:
            data = json.loads(Path(tmp_path).read_text())
            findings.append(Finding(
                id="aibom-inventory",
                severity="INFO",
                title="AIBOM Inventory",
                description=json.dumps(data, indent=2)[:500],
                scanner="aibom",
            ))
        except (json.JSONDecodeError, OSError):
            pass
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        return ScanResult(
            scanner="aibom",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
        )
