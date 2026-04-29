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

"""Skill scanner — native SDK integration.

Uses the cisco-ai-skill-scanner Python SDK directly instead of shelling out
to the skill-scanner CLI.  Maps SDK ScanResult/Finding → DefenseClaw models.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from defenseclaw.config import (
    CiscoAIDefenseConfig,
    InspectLLMConfig,
    LLMConfig,
    SkillScannerConfig,
)
from defenseclaw.models import Finding, ScanResult
from defenseclaw.scanner._llm_env import inject_llm_env, litellm_model

if TYPE_CHECKING:
    pass

_SKILL_SCANNER_LLM_PROVIDERS = frozenset({"", "anthropic", "openai"})


def _inspect_to_llm(il: InspectLLMConfig) -> LLMConfig:
    """Back-compat shim — mirrors the one in ``mcp.py``. Kept local so
    each scanner can be deleted independently when we fully retire the
    legacy ``InspectLLMConfig`` shape."""
    return LLMConfig(
        model=il.model,
        provider=il.provider,
        api_key=il.api_key,
        api_key_env=il.api_key_env,
        base_url=il.base_url,
        timeout=il.timeout,
        max_retries=il.max_retries,
    )


class SkillScannerWrapper:
    """Wraps the cisco-ai-skill-scanner SDK.

    Mirrors :class:`MCPScannerWrapper` — accepts either a legacy
    ``InspectLLMConfig`` or a unified ``LLMConfig`` via ``llm=``.
    Internally everything is driven through :class:`LLMConfig` and the
    shared :mod:`defenseclaw.scanner._llm_env` helpers.
    """

    def __init__(
        self,
        config: SkillScannerConfig,
        inspect_llm: InspectLLMConfig | None = None,
        cisco_ai_defense: CiscoAIDefenseConfig | None = None,
        *,
        llm: LLMConfig | None = None,
    ) -> None:
        self.config = config
        self.inspect_llm = inspect_llm or InspectLLMConfig()
        self.cisco_ai_defense = cisco_ai_defense or CiscoAIDefenseConfig()
        self._llm: LLMConfig = llm if llm is not None else _inspect_to_llm(self.inspect_llm)

    def name(self) -> str:
        return "skill-scanner"

    def scan(self, target: str) -> ScanResult:
        import time

        try:
            from skill_scanner import SkillScanner
            from skill_scanner.core.analyzer_factory import build_analyzers
            from skill_scanner.core.scan_policy import ScanPolicy
        except ImportError:
            print(
                "error: cisco-ai-skill-scanner not installed.\n"
                "  Install with: pip install cisco-ai-skill-scanner",
                file=sys.stderr,
            )
            raise SystemExit(1)

        cfg = self.config
        llm = self._llm
        self._inject_env()

        policy = ScanPolicy.default()
        if cfg.policy:
            try:
                policy = ScanPolicy.from_file(cfg.policy)
            except Exception:
                presets = {"strict", "balanced", "permissive"}
                if cfg.policy in presets:
                    policy = ScanPolicy.from_preset(cfg.policy)

        build_kwargs: dict = {"policy": policy}
        if cfg.use_behavioral:
            build_kwargs["use_behavioral"] = True
        if cfg.use_llm and _skill_scanner_provider_supported(llm.provider_prefix()):
            build_kwargs["use_llm"] = True
            # skill-scanner accepts the LiteLLM-style ``provider/model``
            # string via llm_model; we still pass ``llm_provider``
            # separately because skill-scanner uses it for routing
            # decisions (e.g. local vs remote handling).
            model = litellm_model(llm)
            if model:
                build_kwargs["llm_model"] = model
            if llm.provider:
                build_kwargs["llm_provider"] = llm.provider
            api_key = llm.resolved_api_key()
            if api_key:
                build_kwargs["llm_api_key"] = api_key
            elif os.environ.get("SKILL_SCANNER_LLM_API_KEY"):
                build_kwargs["llm_api_key"] = os.environ["SKILL_SCANNER_LLM_API_KEY"]
            if cfg.llm_consensus_runs > 0:
                build_kwargs["llm_consensus_runs"] = cfg.llm_consensus_runs
        if cfg.use_trigger:
            build_kwargs["use_trigger"] = True
        if cfg.use_virustotal:
            build_kwargs["use_virustotal"] = True
        if cfg.use_aidefense:
            build_kwargs["use_aidefense"] = True

        analyzers = build_analyzers(**build_kwargs)
        scanner = SkillScanner(analyzers=analyzers, policy=policy)

        start = time.monotonic()
        sdk_result = scanner.scan_skill(str(target), lenient=cfg.lenient)
        elapsed = time.monotonic() - start

        return self._convert(sdk_result, target, elapsed)

    def _inject_env(self) -> None:
        """Inject API keys and the skill-scanner-specific env vars.

        Two layers:

        1. Provider-specific env vars for LiteLLM (via the shared
           helper). This is how the analyzer eventually reaches the
           model regardless of provider.
        2. skill-scanner's bespoke env vars (``SKILL_SCANNER_LLM_*``,
           ``VIRUSTOTAL_API_KEY``, ``AI_DEFENSE_API_KEY``) that the SDK
           reads directly. Kept here until skill-scanner switches to the
           provider-native env vars.
        """
        cfg = self.config
        llm = self._llm
        aid = self.cisco_ai_defense
        inject_llm_env(llm)

        mappings = [
            ("SKILL_SCANNER_LLM_API_KEY", llm.resolved_api_key()),
            ("SKILL_SCANNER_LLM_MODEL", litellm_model(llm)),
            ("VIRUSTOTAL_API_KEY", cfg.resolved_virustotal_api_key()),
            ("AI_DEFENSE_API_KEY", aid.resolved_api_key()),
        ]
        for env_var, value in mappings:
            if value and env_var not in os.environ:
                os.environ[env_var] = value

    def _convert(self, sdk_result: object, target: str, elapsed: float) -> ScanResult:
        """Convert SDK ScanResult → DefenseClaw ScanResult."""
        findings: list[Finding] = []
        for sf in getattr(sdk_result, "findings", []):
            location = getattr(sf, "file_path", "") or ""
            line = getattr(sf, "line_number", None)
            if line and location:
                location = f"{location}:{line}"

            tags: list[str] = []
            category = getattr(sf, "category", None)
            if category:
                cat_name = category.name if hasattr(category, "name") else str(category)
                tags.append(cat_name)

            severity = getattr(sf, "severity", None)
            sev_str = severity.name if hasattr(severity, "name") else str(severity)

            findings.append(Finding(
                id=getattr(sf, "id", "") or getattr(sf, "rule_id", ""),
                severity=sev_str.upper(),
                title=getattr(sf, "title", ""),
                description=getattr(sf, "description", ""),
                location=location,
                remediation=getattr(sf, "remediation", "") or "",
                scanner=getattr(sf, "analyzer", "") or "skill-scanner",
                tags=tags,
            ))

        return ScanResult(
            scanner="skill-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            duration=timedelta(seconds=elapsed),
        )


def _skill_scanner_provider_supported(provider: str) -> bool:
    """Return whether cisco-ai-skill-scanner accepts ``llm_provider``.

    The upstream scanner currently restricts providers to Anthropic and
    OpenAI. When DefenseClaw's unified LLM is Bedrock (or another
    provider), forcing ``--llm-provider bedrock`` makes every scan fail
    before static/behavioral analyzers can run. In that case we keep the
    scan alive by omitting the optional LLM analyzer.
    """
    return provider.strip().lower() in _SKILL_SCANNER_LLM_PROVIDERS
