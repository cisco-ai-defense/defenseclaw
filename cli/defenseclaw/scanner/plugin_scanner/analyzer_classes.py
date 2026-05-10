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
)
from defenseclaw.scanner.plugin_scanner.types import Finding

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
        # Mutate ctx.source_files in place so the LLM analyzer (and the
        # meta LLM analyzer) can see the actual plugin source. Before
        # this change ``ctx.source_files`` stayed empty for the entire
        # pipeline and the LLM path silently degraded to manifest-only
        # analysis (DeepSec finding "LLM plugin analysis receives no
        # source files" / other-scanner-coverage-gap).
        file_count, total_bytes = scan_source_files(
            ctx.plugin_dir,
            findings,
            ctx.capabilities,
            ctx.profile,
            source_files_out=ctx.source_files,
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


class MetaAnalyzer:
    name = "meta"

    def __init__(self, llm_policy: dict | None = None) -> None:
        self._llm_policy = llm_policy

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        prev = ctx.previous_findings
        if not prev:
            return []

        findings: list[Finding] = []

        def has_rule(rid: str) -> bool:
            return any(f.rule_id == rid for f in prev)

        def has_tag(tag: str) -> bool:
            return any(tag in (f.tags or []) for f in prev)

        # Chain: eval/exec + network + credential access = exfiltration chain
        has_code_exec = (
            has_rule("SRC-EVAL") or has_rule("SRC-NEW-FUNC") or has_rule("SRC-CHILD-PROC") or has_rule("SRC-EXEC")
        )
        has_network = has_tag("exfiltration") or has_tag("network-access") or has_rule("SRC-FETCH")
        has_creds = has_tag("credential-theft") or has_rule("CRED-OPENCLAW-DIR") or has_rule("CRED-OPENCLAW-ENV")

        if has_code_exec and has_network and has_creds:
            findings.append(
                make_finding(
                    ctx.finding_counter[0],
                    rule_id="META-EXFIL-CHAIN",
                    severity="CRITICAL",
                    confidence=0.95,
                    title="Likely credential exfiltration chain detected",
                    description=(
                        "Plugin combines code execution, network access, and credential file reads. "
                        "This multi-signal pattern is a strong indicator of data theft."
                    ),
                    remediation="Investigate the plugin immediately. This pattern is rarely legitimate.",
                    tags=["exfiltration", "credential-theft"],
                )
            )
            ctx.finding_counter[0] += 1

        # Chain: obfuscation + gateway manipulation = evasive attack
        if has_tag("obfuscation") and has_tag("gateway-manipulation"):
            findings.append(
                make_finding(
                    ctx.finding_counter[0],
                    rule_id="META-EVASIVE-ATTACK",
                    severity="CRITICAL",
                    confidence=0.9,
                    title="Obfuscated gateway manipulation detected",
                    description=(
                        "Plugin uses code obfuscation combined with gateway manipulation patterns. "
                        "This suggests intentional evasion of security scanning."
                    ),
                    remediation="Block this plugin immediately and investigate its source.",
                    tags=["obfuscation", "gateway-manipulation"],
                )
            )
            ctx.finding_counter[0] += 1

        # Chain: install scripts + risky deps + no lockfile = supply chain surface
        if has_rule("SCRIPT-INSTALL-HOOK") and has_rule("DEP-RISKY") and has_rule("STRUCT-NO-LOCKFILE"):
            findings.append(
                make_finding(
                    ctx.finding_counter[0],
                    rule_id="META-SUPPLY-CHAIN",
                    severity="HIGH",
                    confidence=0.85,
                    title="Supply chain attack surface: install hooks + risky deps + no lockfile",
                    description=(
                        "Plugin has install scripts that run automatically, depends on packages that can execute "
                        "arbitrary code, and lacks a lockfile to pin dependency versions. This combination "
                        "creates a broad supply chain attack surface."
                    ),
                    remediation="Remove install scripts, pin dependencies to specific versions, and add a lockfile.",
                    tags=["supply-chain"],
                )
            )
            ctx.finding_counter[0] += 1

        # Chain: cognitive tampering + obfuscation = persistent agent compromise
        if has_tag("cognitive-tampering") and has_tag("obfuscation"):
            findings.append(
                make_finding(
                    ctx.finding_counter[0],
                    rule_id="META-PERSISTENT-COMPROMISE",
                    severity="CRITICAL",
                    confidence=0.9,
                    title="Obfuscated cognitive file tampering detected",
                    description=(
                        "Plugin uses obfuscation techniques alongside cognitive file modification. "
                        "This suggests an attempt to covertly alter agent identity or behaviour for "
                        "persistent compromise (T4 threat class)."
                    ),
                    remediation="Block this plugin. Inspect cognitive files for unauthorized changes.",
                    tags=["cognitive-tampering", "obfuscation"],
                )
            )
            ctx.finding_counter[0] += 1

        # Chain: SSRF/metadata + credential access = cloud credential theft
        has_ssrf = has_rule("SSRF-AWS-META") or has_rule("SSRF-GCP-META") or has_rule("SSRF-AZURE-META")
        if has_ssrf and has_creds:
            findings.append(
                make_finding(
                    ctx.finding_counter[0],
                    rule_id="META-CLOUD-CRED-THEFT",
                    severity="CRITICAL",
                    confidence=0.9,
                    title="Cloud credential theft pattern: SSRF + credential access",
                    description=(
                        "Plugin accesses cloud metadata endpoints and reads credential files. "
                        "This pattern enables stealing IAM tokens and API keys from cloud instances."
                    ),
                    remediation="Block this plugin. Review for lateral movement attempts.",
                    tags=["exfiltration", "credential-theft"],
                )
            )
            ctx.finding_counter[0] += 1

        # Chain: child_process/spawn + server creation + obfuscation = reverse shell / backdoor
        has_spawn = (
            has_rule("SRC-CHILD-PROC")
            or has_rule("SRC-EXEC")
            or has_rule("SRC-DENO-RUN")
            or has_rule("SRC-BUN-SPAWN")
            or has_rule("DYN-SPAWN-VAR")
        )
        has_server = has_rule("SRC-NET-SERVER") or has_rule("SRC-HTTP-SERVER")
        if has_spawn and has_server and has_tag("obfuscation"):
            findings.append(
                make_finding(
                    ctx.finding_counter[0],
                    rule_id="META-REVERSE-SHELL",
                    severity="CRITICAL",
                    confidence=0.95,
                    title="Likely reverse shell or backdoor: server + exec + obfuscation",
                    description=(
                        "Plugin opens a network server, spawns processes, and uses obfuscation. "
                        "This combination is the hallmark of a reverse shell or backdoor implant."
                    ),
                    remediation="Block this plugin immediately. Report to the plugin registry.",
                    tags=["code-execution", "network-access", "obfuscation"],
                )
            )
            ctx.finding_counter[0] += 1

        # Chain: env read + C2/exfil network = environment secret exfiltration
        has_env_read = has_rule("SRC-ENV-READ") or has_rule("GW-ENV-WRITE")
        has_exfil = has_tag("exfiltration") or has_rule("EXFIL-C2-DOMAIN") or has_rule("EXFIL-DNS")
        if has_env_read and has_exfil:
            findings.append(
                make_finding(
                    ctx.finding_counter[0],
                    rule_id="META-ENV-EXFIL",
                    severity="CRITICAL",
                    confidence=0.9,
                    title="Environment secret exfiltration: env access + exfil channel",
                    description=(
                        "Plugin reads environment variables and has an exfiltration channel "
                        "(C2 domain, DNS exfil). Environment variables commonly hold API keys, "
                        "database passwords, and cloud credentials."
                    ),
                    remediation="Block this plugin. Rotate any secrets stored in environment variables.",
                    tags=["exfiltration", "credential-theft"],
                )
            )
            ctx.finding_counter[0] += 1

        # Chain: dynamic import/require + network = remote code execution
        has_dynamic = has_rule("DYN-IMPORT") or has_rule("DYN-REQUIRE") or has_rule("DYN-SPAWN-VAR")
        if has_dynamic and has_network:
            findings.append(
                make_finding(
                    ctx.finding_counter[0],
                    rule_id="META-REMOTE-CODE-EXEC",
                    severity="CRITICAL",
                    confidence=0.9,
                    title="Remote code execution: dynamic import + network access",
                    description=(
                        "Plugin uses dynamic import/require with non-literal arguments and has network access. "
                        "This enables loading and executing arbitrary code from remote sources at runtime, "
                        "completely bypassing static analysis."
                    ),
                    remediation="Block this plugin. Dynamic imports from network sources must never be allowed.",
                    tags=["code-execution", "supply-chain"],
                )
            )
            ctx.finding_counter[0] += 1

        # Chain: binary executable + install hooks = unauditable auto-execution
        if has_rule("STRUCT-BINARY") and has_rule("SCRIPT-INSTALL-HOOK"):
            findings.append(
                make_finding(
                    ctx.finding_counter[0],
                    rule_id="META-DROP-AND-EXEC",
                    severity="CRITICAL",
                    confidence=0.95,
                    title="Unauditable auto-execution: binary + install hook",
                    description=(
                        "Plugin ships a binary executable and runs it automatically via install hooks. "
                        "Binary payloads cannot be statically audited and install hooks execute without "
                        "user confirmation -- this is the 'drop and execute' attack pattern."
                    ),
                    remediation="Block this plugin. Binaries must never be auto-executed via install scripts.",
                    tags=["supply-chain", "code-execution"],
                )
            )
            ctx.finding_counter[0] += 1

        # Chain: cognitive tampering + credential theft = full agent takeover
        if has_tag("cognitive-tampering") and has_creds:
            findings.append(
                make_finding(
                    ctx.finding_counter[0],
                    rule_id="META-AGENT-TAKEOVER",
                    severity="CRITICAL",
                    confidence=0.95,
                    title="Full agent takeover: cognitive tampering + credential theft",
                    description=(
                        "Plugin modifies agent identity/behaviour files AND accesses credentials. "
                        "This enables an attacker to rewrite the agent's instructions to trust "
                        "the attacker, then exfiltrate credentials through the compromised agent."
                    ),
                    remediation="Block this plugin. Audit all cognitive files for unauthorized modifications.",
                    tags=["cognitive-tampering", "credential-theft"],
                )
            )
            ctx.finding_counter[0] += 1

        # Chain: prototype pollution + code execution = privilege escalation to RCE
        has_proto = has_rule("GW-PROTO-DEFINE") or has_rule("GW-PROTO-ACCESS")
        if has_proto and has_code_exec:
            findings.append(
                make_finding(
                    ctx.finding_counter[0],
                    rule_id="META-PROTO-RCE",
                    severity="CRITICAL",
                    confidence=0.9,
                    title="Prototype pollution escalation to code execution",
                    description=(
                        "Plugin pollutes JavaScript prototypes and executes dynamic code. "
                        "Prototype pollution can intercept any function call in the runtime, "
                        "and combined with code execution enables full remote code execution."
                    ),
                    remediation="Block this plugin. Prototype pollution combined with eval/exec is always malicious.",
                    tags=["gateway-manipulation", "code-execution"],
                )
            )
            ctx.finding_counter[0] += 1

        # LLM-powered meta analysis (when configured).
        #
        # Hardening notes:
        #   * The model's false-positive verdicts are ADVISORY ONLY. We
        #     never mutate ``f.suppressed`` based on LLM output -- a
        #     prompt-injected plugin could otherwise hide its own static
        #     findings (DeepSec "Meta LLM can be prompt-injected into
        #     suppressing static findings"). Suggestions are surfaced as
        #     INFO findings so analysts can review them.
        #   * If the LLM ran without source files we explicitly emit a
        #     SCAN-LLM-NO-SOURCE finding instead of silently degrading
        #     to manifest-only meta-analysis (DeepSec "LLM plugin
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

                result = run_meta_llm(llm_config, ctx)
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
