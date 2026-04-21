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

"""Plugin scanner."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from defenseclaw.config import LLMConfig
from defenseclaw.models import Finding, ScanResult
from defenseclaw.scanner.plugin_scanner import scan_plugin
from defenseclaw.scanner.plugin_scanner.types import (
    PluginScanOptions,
)
from defenseclaw.scanner.plugin_scanner.types import (
    ScanResult as PluginScanResult,
)

SCANNER_NAME = "defenseclaw-plugin-scanner"


def _llm_to_override(llm: LLMConfig | None) -> dict | None:
    """Translate a resolved :class:`LLMConfig` into the dict shape
    :class:`defenseclaw.scanner.plugin_scanner.policy.LLMPolicy`
    consumes.

    Returns ``None`` when the config is effectively empty (no model,
    no key) so the scanner falls back to whatever the YAML policy
    already had — this avoids accidentally wiping a policy-authored
    ``model`` just because nobody set ``DEFENSECLAW_LLM_MODEL``.
    """
    if llm is None:
        return None
    model = llm.model
    if model and llm.provider and "/" not in model:
        model = f"{llm.provider}/{model}"
    api_key = llm.resolved_api_key()
    if not model and not api_key and not llm.base_url:
        return None
    override: dict = {}
    if model:
        override["model"] = model
    if api_key:
        override["api_key"] = api_key
    if llm.base_url:
        override["api_base"] = llm.base_url
    if llm.provider:
        override["provider"] = llm.provider
    return override or None


class PluginScannerWrapper:
    def __init__(
        self,
        binary: str = SCANNER_NAME,
        *,
        llm: LLMConfig | None = None,
    ) -> None:
        # binary param kept for backward-compat but no longer used
        self._binary = binary
        # Resolved unified LLM config for this wrapper. Threaded into
        # ``PluginScanOptions.llm_override`` at scan time so the
        # top-level ``llm:`` config (with ``scanners.plugin.llm:``
        # overrides applied) reaches the plugin scanner without
        # requiring callers to hand-author a YAML policy.
        self._llm: LLMConfig | None = llm

    def name(self) -> str:
        return "plugin-scanner"

    def scan(
        self,
        target: str,
        *,
        policy: str = "",
        profile: str = "",
        use_llm: bool = False,
        llm_model: str = "",
        llm_api_key: str = "",
        llm_provider: str = "",
        llm_consensus_runs: int = 0,
        disable_meta: bool = False,
        lenient: bool = False,
    ) -> ScanResult:
        start = time.monotonic()

        # Map CLI flags to PluginScanOptions
        options = PluginScanOptions()
        if policy:
            options.policy = policy
        elif lenient:
            options.policy = "permissive"
        if profile:
            options.profile = profile

        # Build the LLM override:
        #   1. Start from the resolved unified LLM config (top-level
        #      llm + scanners.plugin.llm overrides).
        #   2. Layer the direct CLI kwargs on top — these are the
        #      highest-precedence source because the operator is
        #      pointing a specific flag at this one run.
        override = _llm_to_override(self._llm) or {}
        if use_llm:
            override["enabled"] = True
        if llm_model:
            override["model"] = llm_model
        if llm_api_key:
            override["api_key"] = llm_api_key
        if llm_provider:
            override["provider"] = llm_provider
        if llm_consensus_runs > 0:
            override["consensus_runs"] = llm_consensus_runs
        if override:
            options.llm_override = override

        # Run the scanner
        result: PluginScanResult = scan_plugin(target, options)

        elapsed = time.monotonic() - start

        # Convert rich plugin_scanner.Finding -> models.Finding
        findings: list[Finding] = []
        for f in result.findings:
            if getattr(f, "suppressed", False):
                continue
            findings.append(Finding(
                id=f.id,
                severity=f.severity,
                title=f.title,
                description=f.description,
                location=f.location or "",
                remediation=f.remediation or "",
                scanner="plugin-scanner",
                tags=list(f.tags) if f.tags else [],
            ))

        return ScanResult(
            scanner="plugin-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            duration=timedelta(seconds=elapsed),
        )
