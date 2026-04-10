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

"""MCP scanner — native SDK integration.

Uses the cisco-ai-mcp-scanner Python SDK directly instead of shelling out
to the mcp-scanner CLI.  Maps SDK ToolScanResult/SecurityFinding →
DefenseClaw models.

Supports both remote (URL) and local (stdio) MCP servers:
  - Remote: uses ``scan_remote_server_tools`` with the URL directly.
  - Local:  creates a temporary MCP config file and uses
    ``scan_mcp_config_file`` which spawns the server process.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from defenseclaw.config import CiscoAIDefenseConfig, InspectLLMConfig, MCPScannerConfig, MCPServerEntry
from defenseclaw.models import Finding, ScanResult

if TYPE_CHECKING:
    pass

_PROVIDER_BASE_URLS: dict[str, str] = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
}

_PROVIDER_ENV_VARS: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}


class MCPScannerWrapper:
    """Wraps the cisco-ai-mcp-scanner SDK."""

    def __init__(
        self,
        config: MCPScannerConfig,
        inspect_llm: InspectLLMConfig | None = None,
        cisco_ai_defense: CiscoAIDefenseConfig | None = None,
    ) -> None:
        self.config = config
        self.inspect_llm = inspect_llm or InspectLLMConfig()
        self.cisco_ai_defense = cisco_ai_defense or CiscoAIDefenseConfig()

    def name(self) -> str:
        return "mcp-scanner"

    def _resolve_llm_base_url(self) -> str:
        """Resolve the LLM base URL from explicit config or provider name."""
        llm = self.inspect_llm
        if llm.base_url:
            return llm.base_url
        provider = llm.provider.lower().strip()
        return _PROVIDER_BASE_URLS.get(provider, "")

    def _inject_env(self) -> None:
        """Inject LLM API key into provider-specific env var if not set."""
        llm = self.inspect_llm
        api_key = llm.resolved_api_key()
        if not api_key:
            return
        provider = llm.provider.lower().strip()
        env_var = _PROVIDER_ENV_VARS.get(provider)
        if env_var and env_var not in os.environ:
            os.environ[env_var] = api_key

    def scan(self, target: str, server_entry: MCPServerEntry | None = None) -> ScanResult:
        import time
        import warnings

        warnings.filterwarnings("ignore", message="Pydantic serializer warnings")

        try:
            from mcpscanner import Config as MCPConfig
            from mcpscanner import Scanner as MCPSDKScanner
            from mcpscanner.core.models import AnalyzerEnum
        except ImportError:
            print(
                "error: cisco-ai-mcp-scanner not installed.\n"
                "  Install with: pip install cisco-ai-mcp-scanner\n"
                "\n"
                "  Or install DefenseClaw with the mcp-scan extra:\n"
                "  pip install defenseclaw[mcp-scan]",
                file=sys.stderr,
            )
            raise SystemExit(1)

        llm = self.inspect_llm
        aid = self.cisco_ai_defense
        self._inject_env()

        llm_model = llm.model
        if llm_model and llm.provider and "/" not in llm_model:
            llm_model = f"{llm.provider}/{llm_model}"
        sdk_config = MCPConfig(
            api_key=aid.resolved_api_key(),
            endpoint_url=aid.endpoint,
            llm_provider_api_key=llm.resolved_api_key(),
            llm_model=llm_model,
            llm_base_url=self._resolve_llm_base_url(),
            llm_timeout=llm.timeout,
            llm_max_retries=llm.max_retries,
        )

        scanner = MCPSDKScanner(sdk_config)
        analyzers = self._parse_analyzers(AnalyzerEnum)

        is_local = server_entry is not None and server_entry.command and not server_entry.url

        start = time.monotonic()

        if is_local:
            all_findings = self._scan_local(scanner, server_entry, analyzers)
        else:
            all_findings = self._scan_remote(scanner, target, analyzers)

        elapsed = time.monotonic() - start
        return self._convert(all_findings, target, elapsed)

    def _parse_analyzers(self, analyzer_enum_cls: type) -> list | None:
        """Parse configured analyzer names into SDK enum values."""
        cfg = self.config
        if not cfg.analyzers:
            return None
        analyzer_map = {e.value: e for e in analyzer_enum_cls}
        valid_names = sorted(analyzer_map.keys())
        analyzers = []
        for name in cfg.analyzers.split(","):
            name = name.strip().lower()
            if not name:
                continue
            if name in analyzer_map:
                analyzers.append(analyzer_map[name])
            else:
                print(
                    f"warning: unknown analyzer {name!r}, valid options: {', '.join(valid_names)}",
                    file=sys.stderr,
                )
        if not analyzers:
            print(
                f"warning: no valid analyzers after parsing "
                f"{cfg.analyzers!r}, falling back to all analyzers",
                file=sys.stderr,
            )
            return None
        return analyzers

    def _scan_local(self, scanner: object, entry: MCPServerEntry,
                    analyzers: list | None) -> list[object]:
        """Scan a local stdio MCP server via a temporary config file."""

        server_def: dict = {"command": entry.command}
        if entry.args:
            server_def["args"] = entry.args
        if entry.env:
            server_def["env"] = entry.env

        config_data = {"mcpServers": {entry.name: server_def}}

        fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="defenseclaw-mcp-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(config_data, f)

            scan_kwargs: dict = {"config_path": tmp_path}
            if analyzers is not None:
                scan_kwargs["analyzers"] = analyzers

            errors: list[str] = []
            handler = _ErrorCapture(errors)
            loggers = _attach_error_handler(handler)
            try:
                results = asyncio.run(scanner.scan_mcp_config_file(**scan_kwargs))
            finally:
                for lgr in loggers:
                    lgr.removeHandler(handler)

            connection_errors = [e for e in errors if "connect" in e.lower() or "connection" in e.lower()]
            if connection_errors:
                raise RuntimeError(
                    f"failed to connect to local server {entry.name!r} "
                    f"({entry.command}): {connection_errors[0]}"
                )
            if not results and errors:
                raise RuntimeError(
                    f"scan failed for local server {entry.name!r} "
                    f"({entry.command}): {errors[0]}"
                )

            all_findings: list[object] = []
            for tr in results:
                entity_name = getattr(tr, "tool_name", "")
                for finding in _extract_findings(tr):
                    finding._entity_name = entity_name
                    finding._entity_type = "tool"
                    all_findings.append(finding)
            return all_findings
        finally:
            os.unlink(tmp_path)

    def _scan_remote(self, scanner: object, target: str,
                     analyzers: list | None) -> list[object]:
        """Scan a remote MCP server by URL."""
        cfg = self.config
        all_findings: list[object] = []

        tool_results = asyncio.run(
            scanner.scan_remote_server_tools(target, analyzers=analyzers)
        )
        for tr in tool_results:
            entity_name = getattr(tr, "tool_name", "")
            for finding in _extract_findings(tr):
                finding._entity_name = entity_name
                finding._entity_type = "tool"
                all_findings.append(finding)

        if cfg.scan_prompts:
            prompt_results = asyncio.run(
                scanner.scan_remote_server_prompts(target, analyzers=analyzers)
            )
            for pr in prompt_results:
                entity_name = getattr(pr, "prompt_name", "")
                for finding in _extract_findings(pr):
                    finding._entity_name = entity_name
                    finding._entity_type = "prompt"
                    all_findings.append(finding)

        if cfg.scan_resources:
            resource_results = asyncio.run(
                scanner.scan_remote_server_resources(target, analyzers=analyzers)
            )
            for rr in resource_results:
                entity_name = getattr(rr, "resource_name", "") or getattr(rr, "resource_uri", "")
                for finding in _extract_findings(rr):
                    finding._entity_name = entity_name
                    finding._entity_type = "resource"
                    all_findings.append(finding)

        if cfg.scan_instructions:
            try:
                instr_results = asyncio.run(
                    scanner.scan_remote_server_instructions(target, analyzers=analyzers)
                )
                items = instr_results if isinstance(instr_results, list) else [instr_results]
                for ir in items:
                    for finding in _extract_findings(ir):
                        finding._entity_name = "server-instructions"
                        finding._entity_type = "instructions"
                        all_findings.append(finding)
            except Exception as exc:
                print(f"warning: scan_remote_server_instructions failed: {exc}", file=sys.stderr)

        return all_findings

    def _convert(self, sdk_findings: list[object], target: str, elapsed: float) -> ScanResult:
        """Convert SDK SecurityFinding list → DefenseClaw ScanResult."""
        findings: list[Finding] = []
        for sf in sdk_findings:
            severity = getattr(sf, "severity", "UNKNOWN")
            if hasattr(severity, "name"):
                severity = severity.name
            severity = str(severity).upper()

            entity_name = getattr(sf, "_entity_name", "")
            entity_type = getattr(sf, "_entity_type", "")
            location = f"{entity_type}:{entity_name}" if entity_type and entity_name else entity_name

            tags: list[str] = []
            threat_cat = getattr(sf, "threat_category", None)
            if threat_cat:
                cat_str = threat_cat.name if hasattr(threat_cat, "name") else str(threat_cat)
                tags.append(cat_str)

            taxonomy = getattr(sf, "mcp_taxonomy", None) or {}
            if isinstance(taxonomy, dict):
                aisubtech = taxonomy.get("aisubtech_name", "")
                if aisubtech:
                    tags.append(aisubtech)

            description = ""
            if taxonomy and isinstance(taxonomy, dict):
                description = taxonomy.get("description", "")
            if not description:
                details = getattr(sf, "details", None)
                if isinstance(details, dict):
                    description = details.get("evidence", "") or details.get("reason", "")

            analyzer = getattr(sf, "analyzer", "")
            scanner_name = f"mcp-scanner/{analyzer}" if analyzer else "mcp-scanner"

            findings.append(Finding(
                id=f"mcp-{analyzer}-{len(findings)}" if analyzer else f"mcp-{len(findings)}",
                severity=severity,
                title=getattr(sf, "summary", ""),
                description=description,
                location=location,
                remediation="",
                scanner=scanner_name,
                tags=tags,
            ))

        return ScanResult(
            scanner="mcp-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            duration=timedelta(seconds=elapsed),
        )


def _extract_findings(tool_result: object) -> list[object]:
    """Extract flat list of SecurityFinding from a ToolScanResult.

    ToolScanResult stores findings in a dict keyed by analyzer name,
    or sometimes as a flat list.
    """
    findings_by_analyzer = getattr(tool_result, "findings_by_analyzer", None)
    if isinstance(findings_by_analyzer, dict):
        flat: list[object] = []
        for finding_list in findings_by_analyzer.values():
            if isinstance(finding_list, list):
                flat.extend(finding_list)
            else:
                findings = getattr(finding_list, "findings", [])
                flat.extend(findings)
        return flat

    direct = getattr(tool_result, "findings", None)
    if isinstance(direct, dict):
        flat = []
        for finding_list in direct.values():
            if isinstance(finding_list, list):
                flat.extend(finding_list)
            else:
                findings = getattr(finding_list, "findings", [])
                flat.extend(findings)
        return flat
    if isinstance(direct, list):
        return direct

    return []


class _ErrorCapture(logging.Handler):
    """Captures ERROR-level log messages from the SDK."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__(level=logging.ERROR)
        self._errors = errors

    def emit(self, record: logging.LogRecord) -> None:
        self._errors.append(self.format(record))


def _attach_error_handler(handler: logging.Handler) -> list[logging.Logger]:
    """Attach *handler* to mcpscanner loggers at every level.

    Some SDK versions set ``propagate=False`` on child loggers, so
    attaching only to the parent ``mcpscanner`` logger misses errors.
    Returns the list of loggers so the caller can remove the handler.
    """
    names = ["mcpscanner", "mcpscanner.core", "mcpscanner.core.scanner"]
    loggers = [logging.getLogger(n) for n in names]
    for lgr in loggers:
        lgr.addHandler(handler)
    return loggers
