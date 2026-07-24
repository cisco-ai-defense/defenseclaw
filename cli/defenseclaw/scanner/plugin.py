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

import sys
import time
from datetime import datetime, timedelta, timezone

from defenseclaw.config import LLMConfig
from defenseclaw.models import Finding, ScanResult
from defenseclaw.scanner._llm_env import litellm_model, llm_analyzer_ready
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
        use_llm: bool | None = None,
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
        # Thread the --no-meta request through so the MetaAnalyzer is
        # actually skipped by the scanner pipeline (F-0302).
        options.disable_meta = disable_meta

        # Build the LLM override:
        #   1. Start from the resolved unified LLM config (top-level
        #      llm + scanners.plugin.llm overrides).
        #   2. Layer the direct CLI kwargs on top — these are the
        #      highest-precedence source because the operator is
        #      pointing a specific flag at this one run.
        override = _llm_to_override(self._llm) or {}
        if llm_model:
            override["model"] = llm_model
        if llm_api_key:
            override["api_key"] = llm_api_key
        if llm_provider:
            override["provider"] = llm_provider
        if llm_consensus_runs > 0:
            override["consensus_runs"] = llm_consensus_runs

        # P-F: the LLM lane is default-ON whenever a usable model is configured.
        #   use_llm is None  → auto: enable iff a model resolves and can auth.
        #   use_llm is True  → force-request it; loud-degrade to static
        #                      (YARA/heuristic) when the model or required
        #                      credential is unavailable.
        #   use_llm is False → force off (local analyzers only; --no-llm).
        # The plugin_scanner orchestrator additionally surfaces a runtime LLM
        # failure (backend unreachable) as an LLM-SCAN-ERROR finding rather than
        # swallowing it — see tests/test_plugin_llm_degrade.py.
        model_configured = bool(override.get("model")) or bool(
            self._llm and litellm_model(self._llm)
        )
        readiness_llm = LLMConfig(
            model=str(override.get("model") or ""),
            provider=str(override.get("provider") or ""),
            api_key=str(override.get("api_key") or ""),
            base_url=str(override.get("api_base") or ""),
        )
        llm_ready = model_configured and llm_analyzer_ready(readiness_llm)
        if use_llm is None:
            if llm_ready:
                override["enabled"] = True
            elif model_configured:
                key_name = (
                    self._llm.api_key_env
                    if self._llm and self._llm.api_key_env
                    else "DEFENSECLAW_LLM_KEY"
                )
                print(
                    "warning: LLM analyzer skipped: "
                    f"{key_name} is not configured; continuing with local analyzers",
                    file=sys.stderr,
                )
        elif use_llm:
            if llm_ready:
                override["enabled"] = True
            elif not model_configured:
                print(
                    "warning: --use-llm requested but no model is configured for "
                    "scanners.plugin — running static (YARA/heuristic) analysis "
                    "only. Set llm.model or scanners.plugin.llm to enable the "
                    "semantic LLM lane.",
                    file=sys.stderr,
                )
            else:
                key_name = (
                    self._llm.api_key_env
                    if self._llm and self._llm.api_key_env
                    else "DEFENSECLAW_LLM_KEY"
                )
                print(
                    "warning: --use-llm requested but "
                    f"{key_name} is not configured — running static "
                    "(YARA/heuristic) analysis only.",
                    file=sys.stderr,
                )
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
            rid = getattr(f, "rule_id", None) or ""
            line = getattr(f, "line", None) or getattr(f, "line_number", None)
            ln: int | None = int(line) if line is not None else None
            findings.append(Finding(
                id=f.id,
                severity=f.severity,
                title=f.title,
                description=f.description,
                location=f.location or "",
                remediation=f.remediation or "",
                scanner="plugin-scanner",
                tags=list(f.tags) if f.tags else [],
                rule_id=rid,
                line_number=ln,
            ))

        return ScanResult(
            scanner="plugin-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            duration=timedelta(seconds=elapsed),
        )
