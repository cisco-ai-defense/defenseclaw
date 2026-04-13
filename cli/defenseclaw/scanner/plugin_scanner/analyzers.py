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

"""Scan-phase functions for the plugin scanner.

Each exported function analyses one aspect of a plugin (manifest checks,
source-code patterns, directory structure) and pushes findings into the
shared findings array.
"""

from __future__ import annotations

import json
import os
import re

from defenseclaw.scanner.plugin_scanner.helpers import (
    collect_files,
    downgrade,
    is_comment_line,
    is_test_path,
    make_finding,
    sanitise_evidence,
    strip_comment,
)
from defenseclaw.scanner.plugin_scanner.rules import (
    BINARY_EXTENSIONS,
    BUNDLE_DIRS,
    BUNDLE_SIZE_THRESHOLD_BYTES,
    C2_DOMAINS,
    CLOUD_METADATA_PATTERNS,
    COGNITIVE_FILES,
    CREDENTIAL_PATH_PATTERNS,
    DANGEROUS_INSTALL_SCRIPTS,
    DANGEROUS_PERMISSIONS,
    DYNAMIC_IMPORT_PATTERNS,
    GATEWAY_PATTERNS,
    INTERNAL_HOSTNAME_PATTERNS,
    JSON_SECRET_PATTERNS,
    JSON_URL_PATTERNS,
    PRIVATE_IP_PATTERN,
    RISKY_DEPENDENCIES,
    SAFE_DOTFILES,
    SCRIPT_EXTENSIONS,
    SECRET_PATTERNS,
    SHELL_COMMANDS_IN_SCRIPTS,
    SOURCE_PATTERN_RULES,
    WRITE_FUNCTIONS,
)
from defenseclaw.scanner.plugin_scanner.types import Finding, PluginManifest

# ---------------------------------------------------------------------------
# Manifest checks
# ---------------------------------------------------------------------------


def check_permissions(
    manifest: PluginManifest,
    findings: list[Finding],
    target: str,
) -> None:
    if not manifest.permissions or len(manifest.permissions) == 0:
        findings.append(
            make_finding(
                len(findings) + 1,
                rule_id="PERM-NONE",
                severity="LOW",
                confidence=1.0,
                title="Plugin declares no permissions",
                description=(
                    "No permissions declared in manifest. The plugin may operate without "
                    "restrictions, or permissions may not be documented."
                ),
                location=f"{target}/{manifest.source or 'package.json'}",
                remediation=("Declare required permissions explicitly in the manifest to enable policy enforcement."),
            )
        )
        return

    for perm in manifest.permissions:
        if perm in DANGEROUS_PERMISSIONS:
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="PERM-DANGEROUS",
                    severity="HIGH",
                    confidence=0.95,
                    title=f"Dangerous permission: {perm}",
                    evidence=f'"permissions": ["{perm}"]',
                    description=(
                        f'Plugin requests "{perm}" which grants broad {perm.split(":")[0]} access. '
                        "This permission should be scoped more narrowly."
                    ),
                    location=f"{target}/{manifest.source or 'package.json'}",
                    remediation=f'Replace "{perm}" with specific, scoped permissions (e.g., "fs:read:/specific/path").',
                )
            )
        elif perm.endswith(":*"):
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="PERM-WILDCARD",
                    severity="MEDIUM",
                    confidence=0.8,
                    title=f"Wildcard permission: {perm}",
                    evidence=f'"permissions": ["{perm}"]',
                    description=(
                        f'Plugin uses wildcard permission "{perm}". '
                        "Wildcard permissions bypass fine-grained policy enforcement."
                    ),
                    location=f"{target}/{manifest.source or 'package.json'}",
                    remediation="Use specific, scoped permissions instead of wildcards.",
                )
            )


def check_dependencies(
    manifest: PluginManifest,
    findings: list[Finding],
    target: str,
) -> None:
    if not manifest.dependencies:
        return

    for dep in manifest.dependencies:
        if dep in RISKY_DEPENDENCIES:
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="DEP-RISKY",
                    severity="MEDIUM",
                    confidence=0.75,
                    title=f"Risky dependency: {dep}",
                    evidence=f'"{dep}": "{manifest.dependencies[dep]}"',
                    description=f'Plugin depends on "{dep}" which can execute arbitrary commands or code.',
                    location=f"{target}/{manifest.source or 'package.json'}",
                    remediation=f'Review usage of "{dep}" and ensure it does not process untrusted input.',
                    tags=["supply-chain"],
                )
            )

    for dep, version in manifest.dependencies.items():
        if not isinstance(version, str):
            continue

        if version in ("*", "latest", ""):
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="DEP-UNPINNED",
                    severity="MEDIUM",
                    confidence=0.9,
                    title=f"Unpinned dependency: {dep}@{version or '(empty)'}",
                    evidence=f'"{dep}": "{version}"',
                    description=(
                        f'Dependency "{dep}" uses unpinned version "{version or "(empty)"}". '
                        "Unpinned versions are vulnerable to dependency confusion attacks."
                    ),
                    location=f"{target}/{manifest.source or 'package.json'}",
                    remediation=f'Pin "{dep}" to a specific version or range (e.g., "^1.2.3").',
                    tags=["supply-chain"],
                )
            )

        if version.startswith("http://"):
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="DEP-HTTP",
                    severity="HIGH",
                    confidence=0.95,
                    title=f'Dependency "{dep}" fetched over HTTP',
                    evidence=f'"{dep}": "{version}"',
                    description=(
                        f'Dependency "{dep}" uses an unencrypted HTTP URL, '
                        "allowing man-in-the-middle package substitution."
                    ),
                    location=f"{target}/{manifest.source or 'package.json'}",
                    remediation="Use HTTPS or a registry reference instead.",
                    tags=["supply-chain"],
                )
            )

        if version.startswith("file:"):
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="DEP-LOCAL-FILE",
                    severity="MEDIUM",
                    confidence=0.7,
                    title=f'Dependency "{dep}" uses local file path',
                    evidence=f'"{dep}": "{version}"',
                    description=(
                        f'Dependency "{dep}" references a local file path ("{version}"). '
                        "This may be a path-traversal vector."
                    ),
                    location=f"{target}/{manifest.source or 'package.json'}",
                    remediation="Use a registry-published package instead of a local file reference.",
                    tags=["supply-chain"],
                )
            )

        if version.startswith("git") or version.startswith("github:"):
            if not re.search(r"#[a-f0-9]{7,}", version):
                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id="DEP-GIT-UNPIN",
                        severity="MEDIUM",
                        confidence=0.85,
                        title=f'Git dependency "{dep}" without commit pin',
                        evidence=f'"{dep}": "{version}"',
                        description=(
                            f'Dependency "{dep}" references a git source without a commit hash. '
                            "The content can change silently."
                        ),
                        location=f"{target}/{manifest.source or 'package.json'}",
                        remediation=f'Pin "{dep}" to a specific commit hash (e.g., "github:user/repo#abc1234").',
                        tags=["supply-chain"],
                    )
                )


def check_install_scripts(
    manifest: PluginManifest,
    findings: list[Finding],
    target: str,
) -> None:
    if not manifest.scripts:
        return

    for name, value in manifest.scripts.items():
        if not isinstance(value, str):
            continue

        if name in DANGEROUS_INSTALL_SCRIPTS:
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="SCRIPT-INSTALL-HOOK",
                    severity="HIGH",
                    confidence=0.9,
                    title=f"Dangerous install script: {name}",
                    evidence=f'"{name}": "{value[:120]}"',
                    description=(
                        f'Plugin defines a "{name}" script that runs automatically during npm install. '
                        "Install scripts are a primary npm supply-chain attack vector."
                    ),
                    location=f"{target}/{manifest.source or 'package.json'} \u2192 scripts.{name}",
                    remediation=(
                        f'Remove the "{name}" script or replace with explicit build steps that users run manually.'
                    ),
                    tags=["supply-chain"],
                )
            )

        if SHELL_COMMANDS_IN_SCRIPTS.search(value):
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="SCRIPT-SHELL-CMD",
                    severity="MEDIUM",
                    confidence=0.8,
                    title=f'Script "{name}" invokes shell commands',
                    evidence=f'"{name}": "{value[:120]}"',
                    description=(
                        f'The "{name}" script contains shell command invocations ({value[:80]}). '
                        "Scripts that download or execute external code introduce supply-chain risk."
                    ),
                    location=f"{target}/{manifest.source or 'package.json'} \u2192 scripts.{name}",
                    remediation="Review the script and remove unnecessary shell invocations.",
                    tags=["supply-chain"],
                )
            )


def has_install_scripts(manifest: PluginManifest) -> bool:
    if not manifest.scripts:
        return False
    return any(k in DANGEROUS_INSTALL_SCRIPTS for k in manifest.scripts)


def check_tool(
    tool: dict[str, object],
    findings: list[Finding],
    target: str,
) -> None:
    tool_name = tool.get("name", "")
    if not tool.get("description"):
        findings.append(
            make_finding(
                len(findings) + 1,
                rule_id="TOOL-NO-DESC",
                severity="LOW",
                confidence=1.0,
                title=f'Tool "{tool_name}" lacks description',
                description=("Tools without descriptions cannot be reviewed for safety by users or automated systems."),
                location=f"{target} \u2192 tool:{tool_name}",
                remediation="Add a clear description explaining what this tool does.",
            )
        )

    tool_perms = tool.get("permissions")
    if isinstance(tool_perms, list):
        for perm in tool_perms:
            if perm in DANGEROUS_PERMISSIONS:
                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id="TOOL-PERM-DANGEROUS",
                        severity="HIGH",
                        confidence=0.95,
                        title=f'Tool "{tool_name}" requests dangerous permission: {perm}',
                        evidence=f'tool "{tool_name}" \u2192 permissions: ["{perm}"]',
                        description=f'Tool "{tool_name}" requests "{perm}" which grants broad system access.',
                        location=f"{target} \u2192 tool:{tool_name}",
                        remediation=f'Scope the permission for tool "{tool_name}" more narrowly.',
                    )
                )


# ---------------------------------------------------------------------------
# Source file scanning
# ---------------------------------------------------------------------------


def _emit_collection_findings(
    findings: list[Finding],
    symlink_escapes: list[str],
    depth_truncations: list[str],
    directory: str,
    scan_label: str,
    oversized_files: list[str] | None = None,
) -> None:
    """Emit findings for anomalies detected during file collection.

    Centralises the symlink-escape, depth-truncation, and oversized-file
    finding blocks that would otherwise be duplicated in every scan function
    that calls collect_files.
    """
    label_suffix = f" ({scan_label})" if scan_label else ""

    for esc in symlink_escapes:
        rel = esc.replace(directory + os.sep, "")
        findings.append(make_finding(
            0,
            rule_id="STRUCT-SYMLINK-ESCAPE",
            severity="HIGH",
            confidence=0.95,
            title=f"Symlink escapes plugin directory{label_suffix}",
            description=(
                f"Symlink at '{rel}' points outside the plugin root. "
                "This could allow the plugin to read host files."
            ),
            location=rel,
            remediation="Remove symlinks that reference paths outside the plugin directory.",
            tags=["supply-chain"],
        ))

    for trunc in depth_truncations:
        rel = trunc.replace(directory + os.sep, "")
        findings.append(make_finding(
            0,
            rule_id="SCAN-DEPTH-LIMIT",
            severity="MEDIUM",
            confidence=0.9,
            title=f"Directory depth limit reached{label_suffix}",
            description=(
                f"Directory '{rel}' was not scanned because it exceeds the depth limit. "
                "A plugin may hide malicious code in deeply nested directories."
            ),
            location=rel,
            remediation="Inspect deeply nested directories manually.",
            tags=["supply-chain"],
        ))

    for path in (oversized_files or []):
        rel = path.replace(directory + os.sep, "")
        findings.append(make_finding(
            0,
            rule_id="SCAN-OVERSIZED-FILE",
            severity="LOW",
            confidence=0.9,
            title=f"File skipped: exceeds size limit{label_suffix}",
            description=(
                f"File '{rel}' exceeds the per-file size limit and was not scanned. "
                "Oversized files may be used to evade static analysis."
            ),
            location=rel,
            remediation="Investigate oversized files and remove them if unnecessary.",
            tags=["supply-chain"],
        ))


def scan_source_files(
    directory: str,
    findings: list[Finding],
    capabilities: set[str],
    profile: str,
) -> tuple[int, int]:
    """Returns (file_count, total_bytes)."""
    symlink_escapes: list[str] = []
    depth_truncations: list[str] = []
    oversized_files: list[str] = []
    ts_files = collect_files(
        directory,
        [".ts", ".js", ".mjs"],
        max_file_bytes=2 * 1024 * 1024,
        _symlink_escapes=symlink_escapes,
        _depth_truncations=depth_truncations,
        _oversized_files=oversized_files,
    )
    _emit_collection_findings(findings, symlink_escapes, depth_truncations, directory, "source", oversized_files)

    total_bytes = 0

    for file_path in ts_files:
        try:
            with open(file_path, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue

        total_bytes += len(content)

        # Normalise path separators for consistent matching
        rel_path = file_path.replace(directory + os.sep, "").replace(os.sep, "/")
        if not rel_path.startswith("/"):
            rel_path_slash = file_path.replace(directory + "/", "")
            if rel_path_slash != file_path:
                rel_path = rel_path_slash

        in_test = is_test_path(rel_path)
        lines = content.split("\n")
        code_lines = [strip_comment(line) for line in lines]

        _scan_suspicious_patterns(code_lines, rel_path, findings, capabilities, profile, in_test)
        _check_for_hardcoded_secrets(lines, rel_path, findings, in_test)
        _check_for_credential_access(code_lines, rel_path, findings, capabilities, in_test)
        _check_for_exfiltration(lines, content, rel_path, findings, capabilities, in_test)
        _check_for_ssrf(code_lines, rel_path, findings, in_test)
        _check_for_dynamic_imports(code_lines, rel_path, findings, in_test)
        _check_for_cognitive_file_tampering(code_lines, content, rel_path, findings)
        _check_for_obfuscation(code_lines, content, rel_path, findings, in_test)
        _check_for_gateway_manipulation(code_lines, lines, rel_path, findings, in_test)
        _check_for_cost_runaway(code_lines, rel_path, findings)

    return len(ts_files), total_bytes


def _scan_suspicious_patterns(
    code_lines: list[str],
    rel_path: str,
    findings: list[Finding],
    capabilities: set[str],
    profile: str,
    in_test_path: bool,
) -> None:
    for rule in SOURCE_PATTERN_RULES:
        if profile not in rule.profiles:
            continue

        for i, line in enumerate(code_lines):
            if rule.pattern.search(line):
                if rule.capability:
                    capabilities.add(rule.capability)
                if in_test_path and rule.severity == "INFO":
                    break

                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id=rule.id,
                        severity=downgrade(rule.severity) if in_test_path else rule.severity,
                        confidence=rule.confidence * 0.5 if in_test_path else rule.confidence,
                        title=rule.title,
                        evidence=sanitise_evidence(line),
                        description="Detected in source file. Review for secure usage.",
                        location=f"{rel_path}:{i + 1}",
                        remediation="Ensure this pattern is used safely and does not process untrusted input.",
                        tags=list(rule.tags),
                    )
                )
                break


def _check_for_hardcoded_secrets(
    lines: list[str],
    rel_path: str,
    findings: list[Finding],
    in_test_path: bool,
) -> None:
    for sp in SECRET_PATTERNS:
        for line_idx, line in enumerate(lines):
            if sp.pattern.search(line):
                effective_severity = "MEDIUM" if in_test_path else "CRITICAL"
                effective_confidence = sp.confidence * 0.4 if in_test_path else sp.confidence

                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id=sp.id,
                        severity=effective_severity,
                        confidence=effective_confidence,
                        title=f"{sp.title} (in test file)" if in_test_path else sp.title,
                        evidence=sanitise_evidence(line, True),
                        description=(
                            "Possible credential detected in a test file. "
                            "Verify it is a placeholder and not a live secret."
                            if in_test_path
                            else "Hardcoded credential detected in plugin source code. "
                            "Credentials in source should be rotated immediately."
                        ),
                        location=f"{rel_path}:{line_idx + 1}",
                        remediation=(
                            "Remove the credential from source code. "
                            "Use environment variables or a secrets manager."
                        ),
                        tags=["credential-theft"],
                    )
                )
                break  # only first match per pattern


def _check_for_credential_access(
    code_lines: list[str],
    rel_path: str,
    findings: list[Finding],
    capabilities: set[str],
    in_test_path: bool,
) -> None:
    for cp in CREDENTIAL_PATH_PATTERNS:
        for i, line in enumerate(code_lines):
            if cp.pattern.search(line):
                capabilities.add("credential-access")
                if in_test_path:
                    break

                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id=cp.id,
                        severity="HIGH",
                        confidence=0.9,
                        title=cp.title,
                        evidence=sanitise_evidence(line),
                        description=(
                            "Plugin accesses sensitive credential paths. A compromised plugin "
                            "with credential access can exfiltrate API keys and tokens."
                        ),
                        location=f"{rel_path}:{i + 1}",
                        remediation=(
                            "Plugins should not access credential files directly. "
                            "Use the PluginContext API for authorised access."
                        ),
                        tags=["credential-theft"],
                    )
                )
                break


def _check_for_exfiltration(
    lines: list[str],
    content: str,
    rel_path: str,
    findings: list[Finding],
    capabilities: set[str],
    in_test_path: bool,
) -> None:
    for domain in C2_DOMAINS:
        for idx, line in enumerate(lines):
            if domain in line:
                capabilities.add("network")
                in_comment = is_comment_line(line)
                effective_severity = "MEDIUM" if (in_test_path or in_comment) else "CRITICAL"
                effective_confidence = 0.4 if (in_test_path or in_comment) else 0.95

                if in_test_path or in_comment:
                    desc = (
                        f'Reference to "{domain}" found in '
                        f"{'test file' if in_test_path else 'comment'}. "
                        "Verify this is documentation or a test fixture, not active exfiltration code."
                    )
                else:
                    desc = (
                        f'Plugin references "{domain}", a known data-exfiltration/C2 service. '
                        "This is a strong indicator of data exfiltration."
                    )

                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id="EXFIL-C2-DOMAIN",
                        severity=effective_severity,
                        confidence=effective_confidence,
                        title=f"Known exfiltration domain: {domain}",
                        evidence=sanitise_evidence(line),
                        description=desc,
                        location=f"{rel_path}:{idx + 1}",
                        remediation="Remove the reference and investigate the plugin's provenance.",
                        tags=["exfiltration"],
                    )
                )
                break  # first match per domain

    if re.search(r"\bdns\.resolve\b|\bdns\.lookup\b", content) and re.search(
        r"process\.env|readFile|credentials", content
    ):
        findings.append(
            make_finding(
                len(findings) + 1,
                rule_id="EXFIL-DNS",
                severity="MEDIUM" if in_test_path else "HIGH",
                confidence=0.4 if in_test_path else 0.85,
                title="Possible DNS exfiltration pattern",
                evidence="dns.resolve/dns.lookup combined with credential/env access",
                description=(
                    "Plugin uses DNS resolution combined with credential/env access. "
                    "DNS queries can encode data in subdomains for exfiltration."
                ),
                location=rel_path,
                remediation="Review DNS usage and ensure it is not used for data exfiltration.",
                tags=["exfiltration"],
            )
        )


def _check_for_cognitive_file_tampering(
    code_lines: list[str],
    content: str,
    rel_path: str,
    findings: list[Finding],
) -> None:
    for cog_file in COGNITIVE_FILES:
        if cog_file not in content:
            continue
        if not WRITE_FUNCTIONS.search(content):
            continue

        for line_idx, line in enumerate(code_lines):
            if cog_file in line:
                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id="COG-TAMPER",
                        severity="HIGH",
                        confidence=0.9,
                        title=f"Possible cognitive file tampering: {cog_file}",
                        evidence=sanitise_evidence(line),
                        description=(
                            f'Plugin references "{cog_file}" and contains file-write operations. '
                            "Modifying OpenClaw cognitive files persists behavioral changes across all sessions, "
                            "enabling long-term agent compromise (T4 threat class)."
                        ),
                        location=f"{rel_path}:{line_idx + 1}",
                        remediation=(
                            f'Plugins must not write to "{cog_file}". '
                            "Agent identity and behaviour files should only be modified by the operator."
                        ),
                        tags=["cognitive-tampering"],
                    )
                )
                break


def _check_for_obfuscation(
    code_lines: list[str],
    _content: str,
    rel_path: str,
    findings: list[Finding],
    in_test_path: bool,
) -> None:
    code_content = "\n".join(code_lines)

    # Base64 payloads
    base64_re = re.compile(r"""Buffer\.from\s*\(\s*["'][A-Za-z0-9+/=]{50,}["']""")
    atob_re = re.compile(r"""\batob\s*\(\s*["'][A-Za-z0-9+/=]{50,}["']""")
    for i, line in enumerate(code_lines):
        if base64_re.search(line) or atob_re.search(line):
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="OBF-BASE64",
                    severity="LOW" if in_test_path else "MEDIUM",
                    confidence=0.3 if in_test_path else 0.7,
                    title="Base64-encoded payload detected",
                    evidence=sanitise_evidence(line),
                    description=(
                        "Plugin decodes a large base64 string at runtime. "
                        "Base64 encoding is commonly used to hide URLs, shell commands, or credentials."
                    ),
                    location=f"{rel_path}:{i + 1}",
                    remediation="Decode and review the base64 payload. Remove if it contains suspicious content.",
                    tags=["obfuscation"],
                )
            )
            break

    # String.fromCharCode
    charcode_re = re.compile(r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){4,}")
    if charcode_re.search(code_content):
        idx = next(
            (i for i, ln in enumerate(code_lines) if re.search(r"String\.fromCharCode", ln)),
            -1,
        )
        findings.append(
            make_finding(
                len(findings) + 1,
                rule_id="OBF-CHARCODE",
                severity="MEDIUM",
                confidence=0.8,
                title="String.fromCharCode obfuscation detected",
                evidence=sanitise_evidence(code_lines[idx]) if idx >= 0 else None,
                description=(
                    "Plugin constructs strings from character codes, "
                    "a technique used to evade static analysis."
                ),
                location=f"{rel_path}:{idx + 1 if idx >= 0 else 0}",
                remediation="Evaluate the constructed string and replace with a readable literal if safe.",
                tags=["obfuscation"],
            )
        )

    # Hex escape sequences
    hex_re = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
    if hex_re.search(code_content):
        idx = next(
            (i for i, ln in enumerate(code_lines) if hex_re.search(ln)), -1
        )
        findings.append(
            make_finding(
                len(findings) + 1,
                rule_id="OBF-HEX",
                severity="MEDIUM",
                confidence=0.75,
                title="Hex escape sequence obfuscation detected",
                evidence=sanitise_evidence(code_lines[idx]) if idx >= 0 else None,
                description=(
                    "Plugin uses hex escape sequences to build strings, "
                    "a common technique for hiding commands."
                ),
                location=f"{rel_path}:{idx + 1 if idx >= 0 else 0}",
                remediation="Decode the hex sequence and review the resulting string.",
                tags=["obfuscation"],
            )
        )

    # String concatenation evasion
    concat_re = re.compile(r"""['"](?:ev|cu|ch|ex|sp)['"]\s*\+\s*['"](?:al|rl|ild|ec|awn)""")
    if concat_re.search(code_content):
        idx = next(
            (i for i, ln in enumerate(code_lines) if concat_re.search(ln)), -1
        )
        findings.append(
            make_finding(
                len(findings) + 1,
                rule_id="OBF-CONCAT",
                severity="HIGH",
                confidence=0.9,
                title="String concatenation evasion detected",
                evidence=sanitise_evidence(code_lines[idx]) if idx >= 0 else None,
                description=(
                    "Plugin splits a dangerous function name across string concatenation to evade static analysis. "
                    "This is a strong indicator of intentional evasion."
                ),
                location=f"{rel_path}:{idx + 1 if idx >= 0 else 0}",
                remediation="Investigate the plugin immediately \u2014 this pattern is rarely legitimate.",
                tags=["obfuscation"],
            )
        )

    # Minified/bundled code
    if 0 < len(code_lines) < 20:
        total_len = sum(len(ln) for ln in code_lines)
        avg_len = total_len / len(code_lines)
        if avg_len > 500 and total_len > 10_000:
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="OBF-MINIFIED",
                    severity="INFO",
                    confidence=0.6,
                    title="Minified or bundled code detected",
                    description=(
                        "Source file appears to be minified or bundled (very long lines, few line breaks). "
                        "Minified code is difficult to audit for security issues."
                    ),
                    location=rel_path,
                    remediation="Request unminified source for security review, or use a deobfuscation tool.",
                    tags=["obfuscation"],
                )
            )


def _check_for_gateway_manipulation(
    code_lines: list[str],
    raw_lines: list[str],
    rel_path: str,
    findings: list[Finding],
    in_test_path: bool,
) -> None:
    for gp in GATEWAY_PATTERNS:
        for i, line in enumerate(code_lines):
            if gp.pattern.search(line):
                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id=gp.id,
                        severity=downgrade(gp.severity) if in_test_path else gp.severity,
                        confidence=gp.confidence * 0.5 if in_test_path else gp.confidence,
                        title=gp.title,
                        evidence=sanitise_evidence(raw_lines[i]) if i < len(raw_lines) else None,
                        description=(
                            "Plugin interacts with gateway internals or modifies the runtime environment. "
                            "This can crash the gateway, hijack the module system, "
                            "or pollute prototypes (T5 threat class)."
                        ),
                        location=f"{rel_path}:{i + 1}",
                        remediation=(
                            "Plugins should not modify the runtime environment. "
                            "Use the PluginContext API for authorised interactions."
                        ),
                        tags=["gateway-manipulation"],
                    )
                )
                break


def _check_for_cost_runaway(
    code_lines: list[str],
    rel_path: str,
    findings: list[Finding],
) -> None:
    interval_re = re.compile(r"setInterval\s*\([^,]+,\s*(\d+)\s*\)")
    api_re = re.compile(r"\b(?:fetch|http|https|request|openai|anthropic|api)\b", re.IGNORECASE)

    for i, line in enumerate(code_lines):
        m = interval_re.search(line)
        if m:
            interval = int(m.group(1))
            if interval < 1000:
                start = max(0, i - 5)
                end = min(len(code_lines), i + 10)
                nearby = "\n".join(code_lines[start:end])
                if api_re.search(nearby):
                    findings.append(
                        make_finding(
                            len(findings) + 1,
                            rule_id="COST-RUNAWAY",
                            severity="MEDIUM",
                            confidence=0.75,
                            title="Possible cost runaway: rapid API polling",
                            evidence=sanitise_evidence(line),
                            description=(
                                f"Plugin uses setInterval with {interval}ms delay near API/network calls. "
                                "This pattern can cause runaway API costs or rate-limit exhaustion (T7 threat class)."
                            ),
                            location=f"{rel_path}:{i + 1}",
                            remediation="Use reasonable polling intervals (\u2265 1 second) and implement backoff.",
                            tags=["cost-runaway"],
                        )
                    )


# ---------------------------------------------------------------------------
# Directory structure scanning
# ---------------------------------------------------------------------------


def scan_directory_structure(
    directory: str,
    findings: list[Finding],
) -> None:
    try:
        entries = os.listdir(directory)
    except OSError:
        return

    for entry in entries:
        if entry in ("node_modules", "dist"):
            continue

        dot_idx = entry.rfind(".")
        ext = entry[dot_idx:] if dot_idx >= 0 else ""

        if entry in (".env", ".env.local", ".env.production"):
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="STRUCT-ENV-FILE",
                    severity="CRITICAL",
                    confidence=0.95,
                    title=f"Environment file found: {entry}",
                    evidence=f"File: {entry}",
                    description=(
                        "Plugin directory contains an environment file that likely holds secrets. "
                        "Secrets in a plugin directory risk being published or accessed by other plugins."
                    ),
                    location=f"{directory}/{entry}",
                    remediation="Remove the .env file and use a secrets manager or environment variables instead.",
                    tags=["credential-theft"],
                )
            )
        elif ext in BINARY_EXTENSIONS:
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="STRUCT-BINARY",
                    severity="HIGH",
                    confidence=0.9,
                    title=f"Binary executable found: {entry}",
                    evidence=f"File: {entry}",
                    description=(
                        f'Plugin contains a binary file "{entry}". Binary executables cannot be audited '
                        "for security and may contain malware."
                    ),
                    location=f"{directory}/{entry}",
                    remediation="Remove binary files. Plugins should contain only auditable source code.",
                    tags=["supply-chain"],
                )
            )
        elif ext in SCRIPT_EXTENSIONS:
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="STRUCT-SCRIPT",
                    severity="LOW",
                    confidence=0.6,
                    title=f"Script file found: {entry}",
                    evidence=f"File: {entry}",
                    description=(
                        f'Plugin contains a script file "{entry}". While auditable, script files '
                        "can execute arbitrary commands if invoked during install or build."
                    ),
                    location=f"{directory}/{entry}",
                    remediation="Review the script contents. Ensure it is not invoked by install hooks.",
                    tags=["supply-chain"],
                )
            )
        elif entry.startswith(".") and entry not in SAFE_DOTFILES:
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="STRUCT-HIDDEN",
                    severity="LOW",
                    confidence=0.5,
                    title=f"Hidden file found: {entry}",
                    evidence=f"File: {entry}",
                    description=f'Plugin contains hidden file "{entry}" which may conceal configuration or data.',
                    location=f"{directory}/{entry}",
                    remediation="Review the hidden file and remove if unnecessary.",
                )
            )


# ---------------------------------------------------------------------------
# SSRF / Cloud metadata detection
# ---------------------------------------------------------------------------


def _check_for_ssrf(
    code_lines: list[str],
    rel_path: str,
    findings: list[Finding],
    in_test_path: bool,
) -> None:
    # Cloud metadata endpoints
    for cmp in CLOUD_METADATA_PATTERNS:
        for i, line in enumerate(code_lines):
            if cmp.pattern.search(line):
                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id=cmp.id,
                        severity="MEDIUM" if in_test_path else "HIGH",
                        confidence=cmp.confidence * 0.5 if in_test_path else cmp.confidence,
                        title=cmp.title,
                        evidence=sanitise_evidence(line),
                        description=(
                            "Plugin references a cloud metadata endpoint. "
                            "SSRF attacks use metadata endpoints to steal IAM credentials, "
                            "tokens, and instance configuration."
                        ),
                        location=f"{rel_path}:{i + 1}",
                        remediation=(
                            "Remove the metadata endpoint reference. "
                            "Plugins should not access cloud instance metadata."
                        ),
                        tags=["exfiltration"],
                    )
                )
                break

    # Private IP addresses in network contexts
    net_keyword_re = re.compile(r"\b(?:fetch|http|request|get|post|url|endpoint|host)\b", re.IGNORECASE)
    for i, line in enumerate(code_lines):
        if PRIVATE_IP_PATTERN.search(line) and net_keyword_re.search(line):
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="SSRF-PRIVATE-IP",
                    severity="LOW" if in_test_path else "MEDIUM",
                    confidence=0.3 if in_test_path else 0.65,
                    title="Private IP address in network context",
                    evidence=sanitise_evidence(line),
                    description=(
                        "Plugin references a private/internal IP address alongside network operations. "
                        "This may indicate SSRF or lateral movement attempts."
                    ),
                    location=f"{rel_path}:{i + 1}",
                    remediation="Remove hardcoded internal IPs. Use configuration or service discovery instead.",
                    tags=["exfiltration"],
                )
            )
            break

    # Internal hostnames in network calls
    for i, line in enumerate(code_lines):
        if INTERNAL_HOSTNAME_PATTERNS.search(line):
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="SSRF-INTERNAL-HOST",
                    severity="LOW" if in_test_path else "MEDIUM",
                    confidence=0.25 if in_test_path else 0.55,
                    title="Internal hostname in network context",
                    evidence=sanitise_evidence(line),
                    description=(
                        "Plugin references an internal hostname "
                        "(localhost, corp, internal, etc.) in a network call."
                    ),
                    location=f"{rel_path}:{i + 1}",
                    remediation="Verify the hostname is intentional and not an SSRF target.",
                    tags=["exfiltration"],
                )
            )
            break


# ---------------------------------------------------------------------------
# Dynamic import / require / spawn detection
# ---------------------------------------------------------------------------


def _check_for_dynamic_imports(
    code_lines: list[str],
    rel_path: str,
    findings: list[Finding],
    in_test_path: bool,
) -> None:
    for dp in DYNAMIC_IMPORT_PATTERNS:
        for i, line in enumerate(code_lines):
            if dp.pattern.search(line):
                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id=dp.id,
                        severity=downgrade(dp.severity) if in_test_path else dp.severity,
                        confidence=dp.confidence * 0.5 if in_test_path else dp.confidence,
                        title=dp.title,
                        evidence=sanitise_evidence(line),
                        description=(
                            "Plugin uses a dynamic import, require, or process spawn with a non-literal argument. "
                            "This can load arbitrary code at runtime, bypassing static analysis."
                        ),
                        location=f"{rel_path}:{i + 1}",
                        remediation=(
                            "Use string-literal module specifiers. "
                            "If dynamic loading is needed, validate the argument against an allowlist."
                        ),
                        tags=["code-execution"],
                    )
                )
                break


# ---------------------------------------------------------------------------
# OpenClaw plugin manifest scanning
# ---------------------------------------------------------------------------


def scan_claw_manifest(
    directory: str,
    findings: list[Finding],
) -> None:
    manifest_path = os.path.join(directory, "openclaw.plugin.json")
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return  # no openclaw manifest -- not an error

    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError:
        findings.append(
            make_finding(
                len(findings) + 1,
                rule_id="CLAW-MANIFEST-MISSING",
                severity="MEDIUM",
                confidence=1.0,
                title="Malformed openclaw.plugin.json",
                evidence="File exists but is not valid JSON",
                description="The openclaw.plugin.json file exists but could not be parsed as JSON.",
                location=f"{directory}/openclaw.plugin.json",
                remediation="Fix the JSON syntax in openclaw.plugin.json.",
                tags=["supply-chain"],
            )
        )
        return

    # Check for dangerous hooks
    hooks = manifest.get("hooks")
    if isinstance(hooks, dict):
        dangerous_hooks = ["onInstall", "onLoad", "onEnable"]
        for hook_name in dangerous_hooks:
            hook_value = hooks.get(hook_name)
            if isinstance(hook_value, str) and len(hook_value) > 0:
                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id="CLAW-HOOK-DANGEROUS",
                        severity="MEDIUM",
                        confidence=0.8,
                        title=f"Plugin declares lifecycle hook: {hook_name}",
                        evidence=f'"{hook_name}": "{str(hook_value)[:120]}"',
                        description=(
                            f'Plugin registers a "{hook_name}" lifecycle hook that executes automatically. '
                            "Lifecycle hooks can run arbitrary code during plugin installation or loading."
                        ),
                        location=f"{directory}/openclaw.plugin.json \u2192 hooks.{hook_name}",
                        remediation=f'Review the "{hook_name}" hook. Ensure it does not execute untrusted code.',
                        tags=["supply-chain"],
                    )
                )

    # Check tools declared in openclaw.plugin.json
    tools = manifest.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if isinstance(tool, dict) and not tool.get("description") and tool.get("name"):
                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id="CLAW-TOOL-NO-DESC",
                        severity="LOW",
                        confidence=1.0,
                        title=f'OpenClaw tool "{tool["name"]}" lacks description',
                        description=(
                            "Tools declared in openclaw.plugin.json without descriptions "
                            "cannot be reviewed by users or admission gates."
                        ),
                        location=f"{directory}/openclaw.plugin.json \u2192 tools",
                        remediation="Add a description to every tool declared in the plugin manifest.",
                    )
                )


# ---------------------------------------------------------------------------
# Bundle / dist size detection
# ---------------------------------------------------------------------------


def scan_bundle_size(
    directory: str,
    findings: list[Finding],
) -> None:
    try:
        entries = os.listdir(directory)
    except OSError:
        return

    for entry in entries:
        if entry not in BUNDLE_DIRS:
            continue

        bundle_path = os.path.join(directory, entry)
        try:
            if os.path.islink(bundle_path):
                continue
            if not os.path.isdir(bundle_path):
                continue
        except OSError:
            continue

        total_size = _measure_dir_size(bundle_path)
        if total_size > BUNDLE_SIZE_THRESHOLD_BYTES:
            size_mb = f"{total_size / (1024 * 1024):.1f}"
            threshold_mb = f"{BUNDLE_SIZE_THRESHOLD_BYTES / (1024 * 1024):.0f}"
            findings.append(
                make_finding(
                    len(findings) + 1,
                    rule_id="STRUCT-LARGE-BUNDLE",
                    severity="MEDIUM",
                    confidence=0.7,
                    title=f"Large bundle directory: {entry}/ ({size_mb} MB)",
                    evidence=f"{entry}/ \u2014 {size_mb} MB (threshold: {threshold_mb} MB)",
                    description=(
                        f'Plugin contains a {size_mb} MB "{entry}" directory. Large bundled/compiled artifacts '
                        "cannot be effectively audited for security and may hide malicious code."
                    ),
                    location=f"{directory}/{entry}",
                    remediation=(
                        "Ship source code instead of bundles, "
                        "or provide source maps and unminified source for review."
                    ),
                    tags=["obfuscation"],
                )
            )


def _measure_dir_size(
    directory: str,
    max_depth: int = 3,
    depth: int = 0,
    _root: str | None = None,
) -> int:
    if depth >= max_depth:
        return 0
    if _root is None:
        _root = os.path.realpath(directory)
    total = 0
    try:
        entries = os.listdir(directory)
    except OSError:
        return 0
    for entry in entries:
        full_path = os.path.join(directory, entry)
        try:
            if os.path.islink(full_path):
                continue
            real = os.path.realpath(full_path)
            if not real.startswith(_root + os.sep) and real != _root:
                continue
            if os.path.isdir(full_path):
                total += _measure_dir_size(full_path, max_depth, depth + 1, _root)
            else:
                total += os.path.getsize(full_path)
        except OSError:
            continue
    return total


# ---------------------------------------------------------------------------
# JSON config artifact scanning
# ---------------------------------------------------------------------------


def scan_json_configs(
    directory: str,
    findings: list[Finding],
) -> None:
    symlink_escapes: list[str] = []
    depth_truncations: list[str] = []
    oversized_files: list[str] = []
    json_files = collect_files(
        directory,
        [".json"],
        max_file_bytes=256 * 1024,
        _symlink_escapes=symlink_escapes,
        _depth_truncations=depth_truncations,
        _oversized_files=oversized_files,
    )
    _emit_collection_findings(findings, symlink_escapes, depth_truncations, directory, "JSON", oversized_files)

    for file_path in json_files:
        basename = os.path.basename(file_path)
        # Skip package.json (already handled), lockfiles, and tsconfig
        if basename in ("package.json", "package-lock.json", "tsconfig.json"):
            continue

        try:
            with open(file_path, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue

        rel_path = file_path.replace(directory + os.sep, "").replace(os.sep, "/")
        if not rel_path.startswith("/"):
            rel_path_slash = file_path.replace(directory + "/", "")
            if rel_path_slash != file_path:
                rel_path = rel_path_slash

        # Check for secrets in JSON values
        for jsp in JSON_SECRET_PATTERNS:
            m = jsp.pattern.search(content)
            if m:
                line_idx = content[: m.start()].count("\n") + 1
                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id=jsp.id,
                        severity="HIGH",
                        confidence=jsp.confidence,
                        title=f"{jsp.title}: {rel_path}",
                        evidence=sanitise_evidence(m.group(0), True),
                        description=(
                            "JSON configuration file contains a possible secret or credential. "
                            "Secrets in config files risk being committed to version control or published."
                        ),
                        location=f"{rel_path}:{line_idx}",
                        remediation=(
                            "Move secrets to environment variables or a secrets manager. "
                            "Do not store them in JSON config files."
                        ),
                        tags=["credential-theft"],
                    )
                )

        # Check for suspicious URLs
        for jup in JSON_URL_PATTERNS:
            m = jup.pattern.search(content)
            if m:
                line_idx = content[: m.start()].count("\n") + 1
                is_c2 = jup.id == "JSON-URL-C2"
                findings.append(
                    make_finding(
                        len(findings) + 1,
                        rule_id=jup.id,
                        severity="CRITICAL" if is_c2 else "HIGH",
                        confidence=jup.confidence,
                        title=f"{jup.title}: {rel_path}",
                        evidence=sanitise_evidence(m.group(0)),
                        description=(
                            "JSON config file contains a URL pointing to a known C2/exfiltration service."
                            if is_c2
                            else "JSON config file contains a URL pointing to a cloud metadata endpoint or localhost."
                        ),
                        location=f"{rel_path}:{line_idx}",
                        remediation="Remove the suspicious URL from the config file.",
                        tags=["exfiltration"],
                    )
                )
