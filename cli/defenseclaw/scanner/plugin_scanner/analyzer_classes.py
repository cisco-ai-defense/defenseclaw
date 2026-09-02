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

"""Analyzer class implementations.

Each wraps an existing analysis function from analyzers.py behind the
Analyzer interface.
"""

from __future__ import annotations

import math
import os

from defenseclaw.scanner.plugin_scanner.analyzer import ScanContext
from defenseclaw.scanner.plugin_scanner.analyzers import (
    check_dependencies,
    check_install_scripts,
    check_permissions,
    check_tool,
    scan_bundle_size,
    scan_claw_manifest,
    scan_directory_structure,
    scan_json_configs,
    scan_source_files,
)
from defenseclaw.scanner.plugin_scanner.helpers import (
    check_lockfile_presence,
    dir_exists,
    make_finding,
    resolve_entrypoint_files,
)
from defenseclaw.scanner.plugin_scanner.types import Finding, compare_severity, max_severity

# ---------------------------------------------------------------------------
# Manifest analyzers
# ---------------------------------------------------------------------------


class PermissionsAnalyzer:
    name = "permissions"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.manifest:
            return []
        findings: list[Finding] = []
        check_permissions(ctx.manifest, findings, ctx.plugin_dir)
        return findings


class DependencyAnalyzer:
    name = "dependencies"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.manifest:
            return []
        findings: list[Finding] = []
        check_dependencies(ctx.manifest, findings, ctx.plugin_dir)
        return findings


class InstallScriptAnalyzer:
    name = "install-scripts"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.manifest:
            return []
        findings: list[Finding] = []
        check_install_scripts(ctx.manifest, findings, ctx.plugin_dir)
        return findings


class ToolAnalyzer:
    name = "tools"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.manifest or not ctx.manifest.tools:
            return []
        findings: list[Finding] = []
        for tool in ctx.manifest.tools:
            check_tool(tool, findings, ctx.plugin_dir)
        return findings


# ---------------------------------------------------------------------------
# Source code analyzer
# ---------------------------------------------------------------------------


class SourceAnalyzer:
    name = "source"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        # Force-include manifest-declared entrypoints (package.json
        # bin/main values, connector-manifest entrypoints) so an
        # extensionless launcher or an entrypoint under a skipped dir
        # (e.g. node_modules) is still source- and LLM-scanned
        # (F-0383 / F-0809 / F-0384).
        force_include: list[str] = []
        if ctx.manifest is not None:
            force_include = resolve_entrypoint_files(ctx.plugin_dir, ctx.manifest.entrypoints)
        # Mutate ctx.source_files in place so the LLM analyzer (and the
        # meta LLM analyzer) can see the actual plugin source. Before
        # this change ``ctx.source_files`` stayed empty for the entire
        # pipeline and the LLM path silently degraded to manifest-only
        # analysis (finding "LLM plugin analysis receives no
        # source files" / other-scanner-coverage-gap).
        file_count, total_bytes = scan_source_files(
            ctx.plugin_dir,
            findings,
            ctx.capabilities,
            ctx.profile,
            source_files_out=ctx.source_files,
            force_include=force_include,
        )
        ctx.metadata["file_count"] = file_count
        ctx.metadata["total_size_bytes"] = total_bytes
        return findings


# ---------------------------------------------------------------------------
# Structure analyzers
# ---------------------------------------------------------------------------


class DirectoryStructureAnalyzer:
    name = "directory-structure"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        scan_directory_structure(ctx.plugin_dir, findings)
        return findings


class ClawManifestAnalyzer:
    name = "claw-manifest"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        scan_claw_manifest(ctx.plugin_dir, findings)
        return findings


class BundleSizeAnalyzer:
    name = "bundle-size"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        scan_bundle_size(ctx.plugin_dir, findings)
        return findings


class JsonConfigAnalyzer:
    name = "json-configs"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        scan_json_configs(ctx.plugin_dir, findings)
        return findings


class LockfileAnalyzer:
    name = "lockfile"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        has_lockfile = check_lockfile_presence(ctx.plugin_dir)
        ctx.metadata["has_lockfile"] = has_lockfile

        if not has_lockfile and ctx.manifest and ctx.manifest.dependencies and len(ctx.manifest.dependencies) > 0:
            is_distributed = not dir_exists(os.path.join(ctx.plugin_dir, "node_modules"))
            if not is_distributed:
                return [
                    make_finding(
                        ctx.finding_counter[0],
                        rule_id="STRUCT-NO-LOCKFILE",
                        severity="MEDIUM",
                        confidence=1.0,
                        title="No lockfile found",
                        description=(
                            "Plugin has dependencies but no package-lock.json, yarn.lock, or pnpm-lock.yaml. "
                            "Without a lockfile, builds are non-deterministic and vulnerable to dependency confusion."
                        ),
                        location=ctx.plugin_dir,
                        remediation="Run npm install to generate a package-lock.json and commit it.",
                        tags=["supply-chain"],
                    )
                ]

        return []


# ---------------------------------------------------------------------------
# Meta analyzer -- cross-references findings from other analyzers
# ---------------------------------------------------------------------------


_META_MIN_INPUT_CONFIDENCE = 0.65
_META_EXCLUDED_PATH_COMPONENTS = frozenset(
    {
        "benchmark",
        "benchmarks",
        "doc",
        "docs",
        "documentation",
        "example",
        "examples",
        "fixture",
        "fixtures",
        "test",
        "tests",
        "__tests__",
    }
)
_META_DOCUMENT_EXTENSIONS = (".md", ".mdx", ".rst")
_META_TEST_FILE_MARKERS = (".test.", ".spec.")
_META_DIRECT_ACTION_RULES = frozenset(
    {
        "CLAW-HOOK-DANGEROUS",
        "COG-TAMPER",
        "DYN-IMPORT",
        "DYN-REQUIRE",
        "DYN-SPAWN-VAR",
        "EXFIL-DNS",
        "GW-ENV-WRITE",
        "GW-GLOBAL-MOD",
        "GW-MODULE-LOAD",
        "GW-PROCESS-EXIT",
        "GW-PROTO-ACCESS",
        "GW-PROTO-DEFINE",
        "SCRIPT-INSTALL-HOOK",
        "SRC-BUN-SPAWN",
        "SRC-DENO-RUN",
        "SRC-EVAL",
        "SRC-EXEC",
        "SRC-HTTP-SERVER",
        "SRC-NET-SERVER",
        "SRC-NEW-FUNC",
    }
)


def _meta_location_is_documentation_or_test(location: str | None) -> bool:
    if not location:
        return False
    path = location.split(" → ", 1)[0].replace("\\", "/").strip()
    head, separator, tail = path.rpartition(":")
    if separator and tail.isdigit():
        path = head
    folded = path.casefold()
    if folded.endswith(_META_DOCUMENT_EXTENSIONS):
        return True
    if any(marker in os.path.basename(folded) for marker in _META_TEST_FILE_MARKERS):
        return True
    components = {part for part in folded.split("/") if part not in ("", ".", "..")}
    return bool(components & _META_EXCLUDED_PATH_COMPONENTS)


def _eligible_meta_input(finding: Finding) -> bool:
    if finding.suppressed or (finding.rule_id or "").startswith("META-"):
        return False
    confidence = finding.confidence
    if (
        confidence is None
        or not math.isfinite(confidence)
        or confidence < _META_MIN_INPUT_CONFIDENCE
        or confidence > 1.0
    ):
        return False
    return not _meta_location_is_documentation_or_test(finding.location)


def _meta_candidates(
    findings: list[Finding],
    *,
    rule_ids: frozenset[str] = frozenset(),
    tags: frozenset[str] = frozenset(),
) -> list[Finding]:
    matches = [
        finding for finding in findings if (finding.rule_id or "") in rule_ids or bool(set(finding.tags or []) & tags)
    ]
    return sorted(matches, key=lambda finding: finding.confidence or 0.0, reverse=True)


def _choose_distinct_meta_inputs(groups: list[list[Finding]]) -> list[Finding] | None:
    """Choose one distinct finding for every correlation leg."""

    def choose(index: int, selected: list[Finding], used: set[int]) -> list[Finding] | None:
        if index == len(groups):
            return selected
        for candidate in groups[index]:
            identity = id(candidate)
            if identity in used:
                continue
            result = choose(index + 1, [*selected, candidate], {*used, identity})
            if result is not None:
                return result
        return None

    return choose(0, [], set())


class MetaAnalyzer:
    name = "meta"

    def __init__(self, llm_policy: dict | None = None) -> None:
        self._llm_policy = llm_policy

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        # Documentation, examples, benchmarks, tests, low-confidence matches,
        # and already-suppressed findings remain visible as atomic findings but
        # cannot serve as correlation legs. This prevents prose/test fixtures
        # from being amplified into a synthetic CRITICAL alert.
        prev = [finding for finding in ctx.previous_findings if _eligible_meta_input(finding)]
        if not prev:
            return []

        findings: list[Finding] = []

        def leg(*, rules: tuple[str, ...] = (), tags: tuple[str, ...] = ()) -> list[Finding]:
            return _meta_candidates(prev, rule_ids=frozenset(rules), tags=frozenset(tags))

        def correlate(
            *,
            rule_id: str,
            requested_severity: str,
            confidence_cap: float,
            title: str,
            description: str,
            remediation: str,
            tags: list[str],
            legs: list[list[Finding]],
        ) -> None:
            selected = _choose_distinct_meta_inputs(legs)
            if selected is None:
                return

            confidence = min(confidence_cap, *(finding.confidence or 0.0 for finding in selected))
            if confidence < _META_MIN_INPUT_CONFIDENCE:
                return

            severity = requested_severity
            evidence_ceiling = max_severity([finding.severity for finding in selected])
            if compare_severity(severity, evidence_ceiling) > 0:
                severity = evidence_ceiling
            if requested_severity == "CRITICAL":
                high_signal_count = sum(finding.severity in ("HIGH", "CRITICAL") for finding in selected)
                has_direct_action = any((finding.rule_id or "") in _META_DIRECT_ACTION_RULES for finding in selected)
                if severity == "CRITICAL" and (
                    confidence < 0.9 or high_signal_count < 2 or not has_direct_action
                ):
                    severity = "HIGH"

            evidence_parts = [
                f"{finding.rule_id}@{finding.location or '(manifest)'} (confidence={finding.confidence:.2f})"
                for finding in selected
            ]
            evidence = "; ".join(evidence_parts)
            findings.append(
                make_finding(
                    ctx.finding_counter[0],
                    rule_id=rule_id,
                    severity=severity,
                    confidence=round(confidence, 3),
                    title=f"{title} (correlated, {len(selected)} signals)",
                    description=(
                        f"{description} This is a static correlation, not proof that execution occurred. "
                        f"Evidence chain: {evidence}."
                    ),
                    evidence=evidence,
                    location=selected[0].location,
                    remediation=remediation,
                    tags=[*tags, "correlation", "static-analysis"],
                )
            )
            ctx.finding_counter[0] += 1

        code_exec = leg(rules=("SRC-EVAL", "SRC-NEW-FUNC", "SRC-CHILD-PROC", "SRC-EXEC"))
        network = leg(
            rules=("SRC-FETCH", "EXFIL-C2-DOMAIN", "EXFIL-DNS"),
            tags=("exfiltration", "network-access"),
        )
        credentials = leg(
            rules=(
                "CRED-OPENCLAW-DIR",
                "CRED-OPENCLAW-ENV",
                "CRED-OPENCLAW-AGENTS",
                "CRED-CODEX-AUTH",
                "CRED-CODEX-CONFIG",
                "CRED-CLAUDE-JSON",
                "CRED-CLAUDE-SETTINGS",
                "CRED-CLAUDE-CONFIG",
                "CRED-READFILE-SECRETS",
            )
        )

        correlate(
            rule_id="META-EXFIL-CHAIN",
            requested_severity="CRITICAL",
            confidence_cap=0.95,
            title="Credential-exfiltration pattern",
            description="Plugin source combines code execution, network access, and credential-file access.",
            remediation="Investigate the referenced source locations and confirm data flow before blocking.",
            tags=["exfiltration", "credential-theft"],
            legs=[code_exec, network, credentials],
        )
        correlate(
            rule_id="META-EVASIVE-ATTACK",
            requested_severity="CRITICAL",
            confidence_cap=0.9,
            title="Evasive gateway-manipulation pattern",
            description="Plugin source combines obfuscation with gateway manipulation.",
            remediation="Inspect the referenced transformations and gateway mutations.",
            tags=["obfuscation", "gateway-manipulation"],
            legs=[leg(tags=("obfuscation",)), leg(tags=("gateway-manipulation",))],
        )
        correlate(
            rule_id="META-SUPPLY-CHAIN",
            requested_severity="HIGH",
            confidence_cap=0.85,
            title="Supply-chain execution pattern",
            description="The manifest combines install-time execution, a risky dependency, and no lockfile.",
            remediation="Remove install scripts, pin dependencies, and add a reviewed lockfile.",
            tags=["supply-chain"],
            legs=[
                leg(rules=("SCRIPT-INSTALL-HOOK",)),
                leg(rules=("DEP-RISKY",)),
                leg(rules=("STRUCT-NO-LOCKFILE",)),
            ],
        )
        correlate(
            rule_id="META-PERSISTENT-COMPROMISE",
            requested_severity="CRITICAL",
            confidence_cap=0.9,
            title="Persistent agent-compromise pattern",
            description="Plugin source combines cognitive-file writes with code obfuscation.",
            remediation="Inspect the referenced writes and restore affected cognitive files if unauthorized.",
            tags=["cognitive-tampering", "obfuscation"],
            legs=[leg(rules=("COG-TAMPER",)), leg(tags=("obfuscation",))],
        )
        correlate(
            rule_id="META-CLOUD-CRED-THEFT",
            requested_severity="CRITICAL",
            confidence_cap=0.9,
            title="Cloud credential-theft pattern",
            description="Plugin source combines a cloud metadata endpoint with credential-file access.",
            remediation="Confirm the referenced request and credential read, then rotate exposed credentials.",
            tags=["exfiltration", "credential-theft"],
            legs=[leg(rules=("SSRF-AWS-META", "SSRF-GCP-META", "SSRF-AZURE-META")), credentials],
        )
        correlate(
            rule_id="META-REVERSE-SHELL",
            requested_severity="CRITICAL",
            confidence_cap=0.95,
            title="Reverse-shell/backdoor pattern",
            description="Plugin source combines process spawning, a listening server, and obfuscation.",
            remediation="Trace the referenced server and process arguments before enabling the plugin.",
            tags=["code-execution", "network-access", "obfuscation"],
            legs=[
                leg(rules=("SRC-CHILD-PROC", "SRC-EXEC", "SRC-DENO-RUN", "SRC-BUN-SPAWN", "DYN-SPAWN-VAR")),
                leg(rules=("SRC-NET-SERVER", "SRC-HTTP-SERVER")),
                leg(tags=("obfuscation",)),
            ],
        )
        correlate(
            rule_id="META-ENV-EXFIL",
            requested_severity="CRITICAL",
            confidence_cap=0.9,
            title="Environment-secret exfiltration pattern",
            description="Plugin source combines environment access with a specific exfiltration channel.",
            remediation="Trace the referenced data flow and rotate any secrets shown to leave the process.",
            tags=["exfiltration", "credential-theft"],
            legs=[leg(rules=("SRC-ENV-READ", "GW-ENV-WRITE")), leg(rules=("EXFIL-C2-DOMAIN", "EXFIL-DNS"))],
        )
        correlate(
            rule_id="META-REMOTE-CODE-EXEC",
            requested_severity="CRITICAL",
            confidence_cap=0.9,
            title="Remote-code-loading pattern",
            description="Plugin source combines a non-literal module/process target with network access.",
            remediation="Constrain the dynamic target to a reviewed allowlist and trace its network source.",
            tags=["code-execution", "supply-chain"],
            legs=[leg(rules=("DYN-IMPORT", "DYN-REQUIRE", "DYN-SPAWN-VAR")), network],
        )
        correlate(
            rule_id="META-DROP-AND-EXEC",
            requested_severity="CRITICAL",
            confidence_cap=0.95,
            title="Binary auto-execution pattern",
            description="The package combines a native executable with an automatic install hook.",
            remediation="Remove automatic execution and independently verify the native payload.",
            tags=["supply-chain", "code-execution"],
            legs=[leg(rules=("STRUCT-BINARY",)), leg(rules=("SCRIPT-INSTALL-HOOK",))],
        )
        correlate(
            rule_id="META-AGENT-TAKEOVER",
            requested_severity="CRITICAL",
            confidence_cap=0.95,
            title="Agent-takeover pattern",
            description="Plugin source combines cognitive-file modification with credential-file access.",
            remediation="Review both referenced operations and restore cognitive files if unauthorized.",
            tags=["cognitive-tampering", "credential-theft"],
            legs=[leg(rules=("COG-TAMPER",)), credentials],
        )
        correlate(
            rule_id="META-PROTO-RCE",
            requested_severity="CRITICAL",
            confidence_cap=0.9,
            title="Prototype-pollution/code-execution pattern",
            description="Plugin source combines prototype mutation with dynamic code execution.",
            remediation="Remove prototype mutation and constrain the referenced execution primitive.",
            tags=["gateway-manipulation", "code-execution"],
            legs=[leg(rules=("GW-PROTO-DEFINE", "GW-PROTO-ACCESS")), code_exec],
        )

        # LLM-powered meta analysis (when configured).
        #
        # Hardening notes:
        #   * The model's false-positive verdicts are ADVISORY ONLY. We
        #     never mutate ``f.suppressed`` based on LLM output -- a
        #     prompt-injected plugin could otherwise hide its own static
        #     findings ("Meta LLM can be prompt-injected into
        #     suppressing static findings"). Suggestions are surfaced as
        #     INFO findings so analysts can review them.
        #   * If the LLM ran without source files we explicitly emit a
        #     SCAN-LLM-NO-SOURCE finding instead of silently degrading
        #     to manifest-only meta-analysis ("LLM plugin
        #     analysis receives no source files").
        if self._llm_policy and self._llm_policy.get("enabled"):
            try:
                from defenseclaw.scanner.plugin_scanner.llm_analyzer import run_meta_llm  # noqa: PLC0415

                llm_config = {
                    "model": self._llm_policy.get("model", ""),
                    "api_key": self._llm_policy.get("api_key") or None,
                    "api_base": self._llm_policy.get("api_base") or None,
                    "provider": self._llm_policy.get("provider") or None,
                    "max_tokens": self._llm_policy.get("max_output_tokens"),
                    "python_binary": self._llm_policy.get("python_binary") or None,
                }

                # The LLM correlator receives the same confidence/provenance
                # gated inputs as the deterministic correlator. Source prose
                # in documentation/test paths is also excluded from its
                # correlation context.
                original_previous = ctx.previous_findings
                original_source_files = ctx.source_files
                ctx.previous_findings = prev
                eligible_source_files = [
                    source_file
                    for source_file in original_source_files
                    if not _meta_location_is_documentation_or_test(source_file.rel_path)
                ]
                # An intentionally excluded docs/tests-only tree is not the
                # scanner coverage failure represented by SCAN-LLM-NO-SOURCE.
                # Skip LLM correlation in that case; retain the warning only
                # when the source analyzer genuinely collected nothing.
                if original_source_files and not eligible_source_files:
                    ctx.previous_findings = original_previous
                    return findings
                ctx.source_files = eligible_source_files
                try:
                    result = run_meta_llm(llm_config, ctx)
                finally:
                    ctx.previous_findings = original_previous
                    ctx.source_files = original_source_files
                if result.get("no_source_files_warning") is not None:
                    findings.append(result["no_source_files_warning"])
                findings.extend(result["new_findings"])
                # NOTE: ``result["false_positive_advisories"]`` is intentionally
                # not consumed here -- the advisory findings are already in
                # ``new_findings``.
            except Exception:
                # LLM meta not available -- pattern-based findings are still returned
                pass

        return findings
