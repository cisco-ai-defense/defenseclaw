"""MCP scanner — stub subprocess wrapper.

Shells out to mcp-scanner CLI (same as Go implementation).
Full implementation deferred.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone

from defenseclaw.models import Finding, ScanResult


class MCPScannerWrapper:
    def __init__(self, binary: str = "mcp-scanner") -> None:
        self.binary = binary

    def name(self) -> str:
        return "mcp-scanner"

    def scan(self, target: str) -> ScanResult:
        try:
            proc = subprocess.run(
                [self.binary, "scan", "--format", "json", target],
                capture_output=True, text=True, timeout=300,
            )
        except FileNotFoundError:
            print(
                f"error: {self.binary} not found.\n"
                f"  Install with: uv tool install cisco-ai-mcp-scanner",
                file=sys.stderr,
            )
            raise SystemExit(1)

        findings: list[Finding] = []
        if proc.stdout.strip():
            try:
                data = json.loads(proc.stdout)
                for f in data.get("findings", []):
                    findings.append(Finding(
                        id=f.get("id", ""),
                        severity=f.get("severity", "INFO"),
                        title=f.get("title", ""),
                        description=f.get("description", ""),
                        location=f.get("location", ""),
                        remediation=f.get("remediation", ""),
                        scanner="mcp-scanner",
                    ))
            except json.JSONDecodeError:
                pass

        return ScanResult(
            scanner="mcp-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
        )
