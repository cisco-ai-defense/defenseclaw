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

import functools
import logging
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
from defenseclaw.scanner._llm_env import (
    inject_llm_env,
    litellm_model,
    llm_analyzer_ready,
)

if TYPE_CHECKING:
    pass

_log = logging.getLogger(__name__)


def _frontmatter_yara_analyzers(analyzers: list) -> list:
    """YARA-scan the SKILL.md frontmatter description too (GAP-1376).

    The SDK's static analyzer runs YARA on the SKILL.md body only, but the
    description is the text an agent always loads, so an instruction-override
    phrase there must be found like the same phrase in the body.
    """
    try:
        from skill_scanner.core.analyzers.base import BaseAnalyzer
        from skill_scanner.core.analyzers.static import StaticAnalyzer
    except ImportError:
        return []
    static = next(
        (
            a for a in analyzers
            if isinstance(a, StaticAnalyzer) and getattr(a, "yara_scanner", None) is not None
        ),
        None,
    )
    if static is None:
        return []

    class _FrontmatterYaraAnalyzer(BaseAnalyzer):
        def __init__(self) -> None:
            super().__init__("static_frontmatter", policy=static.policy)

        def analyze(self, skill):  # type: ignore[no-untyped-def]
            text = getattr(skill, "description", "") or ""
            if not text.strip():
                return []
            findings = []
            for match in static.yara_scanner.scan_content(text, "SKILL.md"):
                if not static._is_rule_enabled(match.get("rule_name", "")):
                    continue
                findings.extend(static._create_findings_from_yara_match(match, skill))
            return findings

    return [_FrontmatterYaraAnalyzer()]


# Skip warnings already printed in this process, so `skill scan --all` says
# once why the LLM analyzer is off instead of once per skill (GAP-2628).
_warned_llm_skips: set[str] = set()


def _warn_llm_skipped_once(reason: str) -> None:
    if reason in _warned_llm_skips:
        return
    _warned_llm_skips.add(reason)
    print(
        f"warning: LLM analyzer skipped: {reason}; continuing with local analyzers",
        file=sys.stderr,
    )


@functools.lru_cache(maxsize=1)
def _aws_credentials_found() -> bool:
    """Whether the AWS credential chain LiteLLM signs Bedrock calls with
    resolves (environment, profile, SSO, container or instance role).

    Without credentials every LLM call failed with "Unable to locate
    credentials" while the scan still reported success (GAP-2628). Checked
    once per process; a missing boto3 is left to LiteLLM to report.
    """
    try:
        import boto3
    except ImportError:
        return True
    try:
        return boto3.Session().get_credentials() is not None
    except Exception as exc:  # noqa: BLE001 - any chain error means no usable credentials
        _log.debug("skill-scanner: AWS credential lookup failed: %s", exc)
        return False


def _bedrock_region(llm: LLMConfig) -> str:
    region = llm.bedrock.region if llm.bedrock is not None else ""
    return (region or llm.region or "").strip()


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

    def batch_workers(self, **_scan_options) -> int:
        """Items ``skill scan --all`` may scan at once (GAP-2643).

        The LLM analyzer waits on the network for each skill, so those scans
        overlap; the local analyzers alone stay one at a time.
        """
        from defenseclaw.commands._scan_ui import LLM_SCAN_WORKERS

        return LLM_SCAN_WORKERS if self.config.use_llm else 1

    def scan(self, target: str) -> ScanResult:
        import time

        try:
            from skill_scanner import SkillScanner
            from skill_scanner.core.analyzer_factory import build_analyzers
            from skill_scanner.core.scan_policy import ScanPolicy
        except ImportError:
            print(
                "error: cisco-ai-skill-scanner not installed.\n"
                "  Repair the managed DefenseClaw installation.\n"
                "  Source checkouts: uv sync",
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
        if cfg.use_llm:
            # The upstream skill-scanner SDK auto-detects the provider
            # from a LiteLLM-shaped ``provider/model`` string via its
            # ``ProviderConfig`` (Bedrock, Gemini, Vertex, Azure,
            # Ollama, OpenRouter, …). We deliberately do NOT pass
            # ``llm_provider`` here because:
            #   1. The factory ignores it whenever ``llm_model`` is
            #      set (skill_scanner/core/analyzer_factory.py).
            #   2. Our internal short names ("bedrock", "vertex_ai")
            #      don't match the upstream ``LLMProvider`` enum
            #      ("aws-bedrock", "gcp-vertex"), so passing them
            #      would only matter on the model-less path and
            #      would error out there.
            # Letting the model string carry the provider keeps every
            # LiteLLM-supported provider working end-to-end.
            #
            # Guard ``use_llm`` on a resolved model: without it, the
            # upstream factory falls back to a hard-coded Anthropic
            # default (``claude-3-5-sonnet-20241022``) and then crashes
            # on operators whose unified key isn't an Anthropic key.
            # Skipping the LLM analyzer with a clear log line is
            # strictly better than emitting an upstream warning that
            # operators can't action.
            model = litellm_model(llm)
            env_model = os.environ.get("SKILL_SCANNER_LLM_MODEL", "")
            effective_model = model or env_model
            api_key = llm.resolved_api_key() or os.environ.get(
                "SKILL_SCANNER_LLM_API_KEY", ""
            )
            ready = bool(effective_model) and llm_analyzer_ready(
                llm,
                model=effective_model,
                api_key=api_key,
            )
            if (
                ready
                and "bedrock/" in effective_model.lower()
                and not api_key
                and not os.environ.get("AWS_BEARER_TOKEN_BEDROCK")
                and not _aws_credentials_found()
            ):
                # Keyless Bedrock signs with the AWS credential chain; say
                # once why the LLM lane is off instead of failing every call.
                mode = llm.keyless_auth_mode() or "aws credentials"
                _warn_llm_skipped_once(
                    f"no AWS credentials found for Bedrock (auth_mode={mode}); "
                    "check the instance profile or the AWS credential chain"
                )
            elif ready:
                build_kwargs["use_llm"] = True
                if model:
                    build_kwargs["llm_model"] = model
                elif env_model:
                    build_kwargs["llm_model"] = env_model
                if api_key:
                    build_kwargs["llm_api_key"] = api_key
                if llm.base_url:
                    build_kwargs["llm_base_url"] = llm.base_url
                if cfg.llm_consensus_runs > 0:
                    build_kwargs["llm_consensus_runs"] = cfg.llm_consensus_runs
            elif effective_model:
                key_name = llm.api_key_env or "DEFENSECLAW_LLM_KEY"
                print(
                    "warning: LLM analyzer skipped: "
                    f"{key_name} is not configured; continuing with local analyzers",
                    file=sys.stderr,
                )
            else:
                _log.info(
                    "skill-scanner: use_llm requested but no model resolved "
                    "from llm.model / SKILL_SCANNER_LLM_MODEL — skipping LLM "
                    "analyzer to avoid upstream's Anthropic fallback default. "
                    "Set llm.model (e.g. 'bedrock/anthropic.claude-3-5-haiku') "
                    "or SKILL_SCANNER_LLM_MODEL to enable.",
                )
        if cfg.use_trigger:
            build_kwargs["use_trigger"] = True
        if cfg.use_virustotal:
            build_kwargs["use_virustotal"] = True
        if cfg.use_aidefense:
            build_kwargs["use_aidefense"] = True

        analyzers = build_analyzers(**build_kwargs)
        analyzers.extend(_frontmatter_yara_analyzers(analyzers))
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

        if litellm_model(llm).lower().startswith("bedrock/"):
            # The SDK reads the Bedrock region from AWS_REGION only (default
            # us-east-1), so pass the configured one on. botocore tries the
            # instance-metadata credentials once with a 1 s timeout; retry a
            # slow answer like the gateway's Go SDK does (GAP-2628).
            region = _bedrock_region(llm)
            if region and not os.environ.get("AWS_REGION"):
                os.environ["AWS_REGION"] = region
            if llm.keyless_auth_mode() == "instance_role":
                os.environ.setdefault("AWS_METADATA_SERVICE_NUM_ATTEMPTS", "3")

    def _convert(self, sdk_result: object, target: str, elapsed: float) -> ScanResult:
        """Convert SDK ScanResult → DefenseClaw ScanResult."""
        scanner_name = self.name()
        findings: list[Finding] = []
        for sf in getattr(sdk_result, "findings", []):
            location = getattr(sf, "file_path", "") or ""
            line = getattr(sf, "line_number", None)
            if line and location:
                line = _snippet_file_line(target, location, line, getattr(sf, "snippet", ""))
                location = f"{location}:{line}"

            tags: list[str] = []
            category = getattr(sf, "category", None)
            if category:
                cat_name = category.name if hasattr(category, "name") else str(category)
                tags.append(cat_name)
            analyzer = str(getattr(sf, "analyzer", "") or "")
            if analyzer:
                tags.append(f"analyzer:{analyzer}")

            severity = getattr(sf, "severity", None)
            sev_str = severity.name if hasattr(severity, "name") else str(severity)

            findings.append(Finding(
                id=getattr(sf, "id", "") or getattr(sf, "rule_id", ""),
                severity=sev_str.upper(),
                title=getattr(sf, "title", ""),
                description=getattr(sf, "description", ""),
                location=location,
                remediation=getattr(sf, "remediation", "") or "",
                # The scanner's own rule id (COMMAND_INJECTION_EVAL, ...), the
                # same one the watcher files; without it the gateway made up
                # a title slug for path scans (GAP-1683).
                rule_id=str(getattr(sf, "rule_id", "") or ""),
                # Canonical finding identity names the producer, not the
                # upstream SDK's internal analyzer, which remains in tags.
                scanner=scanner_name,
                tags=tags,
            ))

        return ScanResult(
            scanner=scanner_name,
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            duration=timedelta(seconds=elapsed),
        )


def _snippet_file_line(target: str, file_path: str, line: int, snippet: object) -> int:
    """The file line that holds *snippet*, when the SDK's line is off.

    GAP-1599: the SDK counts SKILL.md lines from the end of the front
    matter, so a match on line 6 of the file read "SKILL.md:1". Keep the
    SDK's line when it already holds the snippet or the snippet is not found.
    """
    first = next((ln.strip() for ln in str(snippet or "").splitlines() if ln.strip()), "")
    if not first:
        return line
    path = file_path if os.path.isabs(file_path) else os.path.join(target, file_path)
    try:
        if os.path.getsize(path) > 2_000_000:
            return line
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except (OSError, ValueError):
        return line
    if 0 < line <= len(lines) and first in lines[line - 1]:
        return line
    for idx, text in enumerate(lines, start=1):
        if first in text:
            return idx
    return line
