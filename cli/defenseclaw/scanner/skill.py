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

import contextlib
import functools
import logging
import os
import sys
import tempfile
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

from defenseclaw.config import (
    CiscoAIDefenseConfig,
    InspectLLMConfig,
    LLMConfig,
    SkillScannerConfig,
)
from defenseclaw.models import Finding, ScanResult
from defenseclaw.scanner import settings, skill_metadata
from defenseclaw.scanner._llm_env import (
    drop_unsupported_litellm_params,
    inject_llm_env,
    litellm_model,
    llm_analyzer_ready,
)

_log = logging.getLogger(__name__)


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


# Bounds on the copy _skill_scan_copy makes (Go stageSkill).
_SCAN_STAGE_MAX_BYTES = 64 << 20
_SCAN_STAGE_MAX_FILES = 2000


class _StageError(RuntimeError):
    pass


def _plan_scan_copy(target: str) -> tuple[list[tuple[str, str]], set[str]]:
    """The OS metadata files to leave out and the files to re-encode (one bounded walk)."""
    metadata: list[tuple[str, str]] = []
    transcode: set[str] = set()
    total = files = 0
    for root, dirs, names in os.walk(target):
        for name in dirs + names:
            if os.path.islink(os.path.join(root, name)):
                raise _StageError("the skill holds a link")
        for name in names:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, target)
            if not os.path.isfile(path):
                raise _StageError(f"{rel} is not a regular file")
            size = os.path.getsize(path)
            files += 1
            total += size
            if files > _SCAN_STAGE_MAX_FILES or total > _SCAN_STAGE_MAX_BYTES:
                raise _StageError("the skill is too large to re-encode")
            kind, recode = skill_metadata.classify(target, rel, size)
            if kind:
                metadata.append((rel.replace(os.sep, "/"), kind))
            elif recode:
                transcode.add(rel)
    return metadata, transcode


@contextlib.contextmanager
def _skill_scan_copy(target: str) -> Iterator[tuple[str, list[tuple[str, str]]]]:
    """Yield the folder to scan for the skill and the OS metadata files left out.

    That folder is the skill itself unless it needs a scan copy: a SKILL.md
    saved as UTF-16 is re-encoded as UTF-8, since skill-scanner refuses one
    with NUL bytes, which is how Windows editors save "Unicode" text
    (GAP-0417); OS metadata files (skill_metadata) are left out and a UTF-16
    desktop.ini is re-encoded, since the scanner scored them as opaque
    binaries and the watcher quarantined a plain-text skill (GAP-0106). The
    install watcher scans the same copy (internal/scanner stageSkill). A
    UTF-16 SKILL.md that cannot be copied fails the scan; any other skill is
    then scanned in place, metadata files included. The skill's own files
    are never changed.
    """
    manifest = ""
    for name in ("SKILL.md", "skill.md"):
        candidate = os.path.join(target, name)
        if os.path.isfile(candidate) and not os.path.islink(candidate):
            manifest = name
            break
    utf16_manifest = False
    if manifest:
        with open(os.path.join(target, manifest), "rb") as fh:
            utf16_manifest = fh.read(2) in (b"\xff\xfe", b"\xfe\xff")
    try:
        metadata, transcode = _plan_scan_copy(target)
    except (_StageError, OSError) as exc:
        if utf16_manifest:
            raise RuntimeError(f"{manifest} is saved as UTF-16 and {exc}; save it as UTF-8") from exc
        yield target, []
        return
    if not utf16_manifest and not metadata and not transcode:
        yield target, []
        return
    from defenseclaw.skill_discovery import decode_skill_text

    skip = {rel for rel, _ in metadata}
    with tempfile.TemporaryDirectory(prefix="dc-skill-scan-") as tmp:
        stage = os.path.join(tmp, os.path.basename(os.path.normpath(target)))
        for root, _dirs, names in os.walk(target):
            rel_root = os.path.relpath(root, target)
            os.makedirs(os.path.join(stage, rel_root), exist_ok=True)
            for name in names:
                rel = os.path.normpath(os.path.join(rel_root, name))
                if rel.replace(os.sep, "/") in skip:
                    continue
                with open(os.path.join(root, name), "rb") as fh:
                    data = fh.read()
                if (utf16_manifest and rel == manifest) or rel in transcode:
                    data = decode_skill_text(data).encode("utf-8")
                with open(os.path.join(stage, rel), "wb") as fh:
                    fh.write(data)
        yield stage, metadata


# The INFO finding skill-scanner reports when its LLM judge started but did
# not answer; the scan then ran the deterministic analyzers only.
LLM_ANALYSIS_FAILED = "LLM_ANALYSIS_FAILED"


def _scanner_llm_configured() -> bool:
    """Whether skill-scanner can make an LLM call in this scan.

    Its LLM analyzer, behavioral alignment client and adjudicator take their
    model and provider only from ``SKILL_SCANNER_*`` variables, which
    :func:`settings.scanner_env` sets from the resolved judge and otherwise
    removes. With none set, no scanner component reaches LiteLLM.
    """
    return any(
        value.strip() and name.upper().startswith("SKILL_SCANNER_") and "LLM" in name.upper()
        for name, value in os.environ.items()
    )


class JudgeUnavailableError(RuntimeError):
    """The LLM judge did not run, so the scan is incomplete (GAP-0376)."""


def _raise_on_judge_failure(result: ScanResult) -> None:
    """Fail a scan whose judge did not run, as skill-scanner.mdx promises.

    The scanner reports the outage as an INFO finding and exits 0, so the
    scan read as clean or MEDIUM while every judge-only detection was lost.
    The install watcher blocks such a skill; the CLI exits non-zero.
    """
    for finding in result.findings:
        if finding.rule_id != LLM_ANALYSIS_FAILED:
            continue
        detail = " ".join(str(finding.description or "").split())
        if len(detail) > 240:
            detail = detail[:240] + "..."
        raise JudgeUnavailableError(
            "the LLM judge did not run, so the scan is incomplete (static analysis only)"
            + (f": {detail}" if detail else "")
            + ". Check the judge model, its key and the network, or pass --no-use-llm "
            "to scan with the static rules alone."
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
        secure_client: bool = False,
        decision_model: tuple[dict, dict[str, str]] | None = None,
    ) -> None:
        self.config = config
        self.secure_client = secure_client
        # (build_analyzers kwargs, env) for the scanner's advisory System One
        # tier, from defenseclaw.decision_model.skill_scanner_options.
        self.decision_model = decision_model or ({}, {})
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

        from defenseclaw.scanner._skill_judge_compat import install as install_judge_compat

        # Accept a well-formed answer from any judge model (GAP-2609).
        install_judge_compat()
        cfg = self.config
        policy = _scan_policy(ScanPolicy, cfg)

        build_kwargs: dict = {"policy": policy}
        env: dict[str, str] = {}
        judge: dict = {}
        if cfg.use_behavioral:
            build_kwargs["use_behavioral"] = True
        if cfg.use_llm:
            judge = self._judge()
            if judge:
                build_kwargs.update(judge)
                build_kwargs["use_llm"] = True
                if cfg.llm_consensus_runs > 0:
                    build_kwargs["llm_consensus_runs"] = cfg.llm_consensus_runs
                env.update({
                    "SKILL_SCANNER_LLM_MODEL": judge["llm_model"],
                    "SKILL_SCANNER_LLM_API_KEY": judge.get("llm_api_key", ""),
                    "SKILL_SCANNER_LLM_BASE_URL": judge.get("llm_base_url", ""),
                    "SKILL_SCANNER_LLM_PROVIDER": judge.get("llm_provider", ""),
                })
        if cfg.use_trigger:
            build_kwargs["use_trigger"] = True
        if settings.virustotal_enabled(cfg):
            build_kwargs["use_virustotal"] = True
            build_kwargs["vt_upload_files"] = bool(cfg.analyzers.virustotal.upload_files)
            env["VIRUSTOTAL_API_KEY"] = cfg.resolved_virustotal_api_key()
        if settings.aidefense_enabled(cfg):
            build_kwargs["use_aidefense"] = True
            env["AI_DEFENSE_API_KEY"] = self.cisco_ai_defense.resolved_api_key()
            env["AI_DEFENSE_API_URL"] = self.cisco_ai_defense.endpoint or ""
        if settings.osv_enabled(cfg):
            build_kwargs["use_osv"] = True
        dm_kwargs, dm_env = self.decision_model
        if dm_kwargs and _supports_system_one(build_analyzers):
            build_kwargs.update(dm_kwargs)
            env.update(dm_env)
        elif dm_kwargs:
            print(
                "warning: the installed skill scanner has no System One tier; decision model not used",
                file=sys.stderr,
            )
            dm_kwargs = {}

        with settings.scanner_env(env, secure_client=self.secure_client):
            self._inject_env()
            if _scanner_llm_configured():
                # Importing LiteLLM costs about 2 s; a scan with no judge
                # model makes no LLM call, so it skips the import.
                drop_unsupported_litellm_params()
            analyzers = build_analyzers(**build_kwargs)
            scanner = SkillScanner(analyzers=analyzers, policy=policy)

            start = time.monotonic()
            with _skill_scan_copy(str(target)) as (scan_target, metadata):
                sdk_result = scanner.scan_skill(scan_target, lenient=cfg.lenient)
                if cfg.enable_meta and judge and len(analyzers) > 1:
                    _apply_meta_analysis(scanner, sdk_result, scan_target, cfg.lenient, judge, policy)
                elapsed = time.monotonic() - start
                result = self._convert(sdk_result, scan_target, elapsed)
                result.findings.extend(skill_metadata.metadata_findings(metadata, self.name()))
        result.target = target
        if judge:
            _raise_on_judge_failure(result)
        # The scan says which policy and judge model it ran with (GAP-0047).
        result.settings = {"policy": settings.effective_policy(cfg), "judge": judge.get("llm_model") or "off"}
        if dm_kwargs:
            result.settings["decision_model"] = _system_one_record(analyzers, dm_kwargs["system_one_model"])
        return result

    def _judge(self) -> dict:
        """The judge's ``build_analyzers`` arguments, or ``{}`` when none can run.

        The judge is the resolved ``llm:`` block. A model is required, and so
        is a key unless the provider is keyless (local servers, Bedrock with
        its AWS credential chain). Without the guard the upstream factory
        falls back to its own default model, or refuses to start.
        """
        llm = self._llm
        model = litellm_model(llm)
        if self.secure_client and not model:
            model = os.environ.get("SKILL_SCANNER_LLM_MODEL", "")
        if not model:
            _log.info("skill-scanner: no judge model resolved from llm.model; running the static rules")
            return {}
        api_key = llm.resolved_api_key()
        if self.secure_client and not api_key:
            api_key = os.environ.get("SKILL_SCANNER_LLM_API_KEY", "")
        if not llm_analyzer_ready(llm, model=model, api_key=api_key):
            key_name = llm.api_key_env or "DEFENSECLAW_LLM_KEY"
            _warn_llm_skipped_once(f"{key_name} is not configured")
            return {}
        if (
            "bedrock/" in model.lower()
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
            return {}
        provider, model = settings.judge_route(llm, model)
        if not api_key and llm.is_local_provider():
            # The openai-compatible route needs a key; local servers ignore it.
            api_key = "local-no-key"
        judge = {"llm_model": model}
        if provider:
            judge["llm_provider"] = provider
        if api_key:
            judge["llm_api_key"] = api_key
        if llm.base_url:
            judge["llm_base_url"] = llm.request_base_url()
        return judge

    def _inject_env(self) -> None:
        """Provider-native LiteLLM variables and the Bedrock region.

        The ``SKILL_SCANNER_*`` / VirusTotal / AI Defense variables are set
        by :func:`settings.scanner_env` from config, never from the shell.
        """
        llm = self._llm
        inject_llm_env(llm)

        if litellm_model(llm).lower().startswith("bedrock/"):
            # The SDK reads the Bedrock region from AWS_REGION only (default
            # us-east-1), so pass the configured one on. botocore tries the
            # instance-metadata credentials once with a 1 s timeout; retry a
            # slow answer like the gateway's Go SDK does (GAP-2628).
            region = _bedrock_region(llm)
            # Config wins over the shell, as in the gateway scanner env.
            if region:
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


def _supports_system_one(build_analyzers: object) -> bool:
    """Whether the installed skill scanner has the System One tier (2.3+)."""
    import inspect

    try:
        return "system_one_endpoint" in inspect.signature(build_analyzers).parameters
    except (TypeError, ValueError):
        return False


def _system_one_record(analyzers: list, model: str) -> dict:
    """The decision model's advisory answer for this scan.

    The skill scanner's System One tier records a calibrated probability and
    never emits a finding, so the decision model cannot change the verdict
    here; the record is for triage and observability only.
    """
    for analyzer in analyzers:
        if getattr(analyzer, "get_name", lambda: "")() == "system_one":
            last = dict(getattr(analyzer, "last_result", None) or {})
            if not last:
                last = {"status": "error", "reason": getattr(analyzer, "last_error", None) or "no answer"}
            last.setdefault("model", model)
            last["advisory_only"] = True
            if isinstance(last.get("probability"), float):
                last["probability"] = round(last["probability"], 4)
            return last
    return {"status": "off", "model": model, "advisory_only": True}


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


def _scan_policy(policy_cls: type, cfg: SkillScannerConfig) -> object:
    """The scan policy from config: a preset, or a custom file by digest.

    A custom policy loads only from bytes that match ``policy_file.digest``;
    a mismatch fails the scan. A v8 config may still hold a policy file path
    in ``policy`` (migration input); any other unknown name fails the scan,
    as it does on the gateway.
    """
    name = settings.effective_policy(cfg)
    if name in settings.POLICY_PRESETS:
        return policy_cls.from_preset(name)
    if name == settings.POLICY_CUSTOM:
        ref = cfg.policy_file
        data = settings.verified_asset_bytes(ref.path, ref.digest)
        import tempfile

        with tempfile.TemporaryDirectory(prefix="dc-skill-policy-") as tmp:
            path = os.path.join(tmp, "policy.yaml")
            with open(path, "wb") as fh:
                fh.write(data)
            return policy_cls.from_yaml(path)
    if os.path.isfile(name):
        return policy_cls.from_yaml(name)
    presets = ", ".join(settings.POLICY_PRESETS)
    raise ValueError(f"unknown skill-scanner policy {name!r}; use one of {presets} or custom")


def _apply_meta_analysis(
    scanner: object, result: object, target: str, lenient: bool, judge: dict, policy: object
) -> None:
    """Filter *result* with the meta-analyzer (scanners.skill_scanner.enable_meta).

    Mirrors the upstream CLI's --enable-meta. The meta-analyzer only removes
    likely false positives, so when it cannot run the findings stay as they are.
    """
    if not getattr(result, "findings", None):
        return
    try:
        import asyncio

        from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer, apply_meta_analysis_to_results

        meta = MetaAnalyzer(
            model=judge["llm_model"],
            api_key=judge.get("llm_api_key"),
            base_url=judge.get("llm_base_url"),
            provider=judge.get("llm_provider"),
            policy=policy,
        )
        skill = scanner.loader.load_skill(target, lenient=lenient)
        meta_result = asyncio.run(
            meta.analyze_with_findings(skill=skill, findings=result.findings, analyzers_used=result.analyzers_used)
        )
        result.findings = apply_meta_analysis_to_results(
            original_findings=result.findings, meta_result=meta_result, skill=skill
        )
    except Exception as exc:  # noqa: BLE001 - meta-analysis is a filter, never a gate
        print(f"warning: meta-analysis skipped: {exc}; keeping every finding", file=sys.stderr)
