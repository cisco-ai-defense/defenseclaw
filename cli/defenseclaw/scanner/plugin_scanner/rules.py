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

"""Plugin scanner rule definitions, constants, and Cisco AITech taxonomy map.

All pattern sets, severity defaults, and taxonomy references live here
so security reviewers can audit them without reading scan logic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from defenseclaw.scanner.plugin_scanner.types import TaxonomyRef

# ---------------------------------------------------------------------------
# Scan profile type
# ---------------------------------------------------------------------------

RuleProfile = str  # "default" | "strict"

# ---------------------------------------------------------------------------
# Permission rules
# ---------------------------------------------------------------------------

DANGEROUS_PERMISSIONS: set[str] = {
    "fs:write",
    "fs:*",
    "net:*",
    "shell:exec",
    "shell:*",
    "system:*",
    "crypto:*",
}

# ---------------------------------------------------------------------------
# Dependency rules
# ---------------------------------------------------------------------------

RISKY_DEPENDENCIES: set[str] = {
    "child_process",
    "shelljs",
    "execa",
    "node-pty",
    "vm2",
    "isolated-vm",
    "node-serialize",
    "decompress",
    "adm-zip",
    "cross-spawn",
}

# ---------------------------------------------------------------------------
# Install script rules
# ---------------------------------------------------------------------------

DANGEROUS_INSTALL_SCRIPTS: set[str] = {"preinstall", "postinstall", "install"}

SHELL_COMMANDS_IN_SCRIPTS: re.Pattern[str] = re.compile(
    r"\b(?:curl|wget|bash|sh|powershell|nc|ncat|netcat|chmod|sudo|rm\s+-rf|dd\s+if=)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Exfiltration domains (C2)
# ---------------------------------------------------------------------------

C2_DOMAINS: set[str] = {
    "webhook.site",
    "ngrok.io",
    "ngrok-free.app",
    "pipedream.net",
    "requestbin.com",
    "hookbin.com",
    "burpcollaborator.net",
    "interact.sh",
    "oast.fun",
    "canarytokens.com",
}

# ---------------------------------------------------------------------------
# Cognitive files (agent identity / behaviour)
# ---------------------------------------------------------------------------

COGNITIVE_FILES: set[str] = {
    "SOUL.md",
    "IDENTITY.md",
    "TOOLS.md",
    "AGENTS.md",
    "MEMORY.md",
    "openclaw.json",
    "gateway.json",
    "config.yaml",
}

# ---------------------------------------------------------------------------
# Structural rules
# ---------------------------------------------------------------------------

BINARY_EXTENSIONS: set[str] = {".exe", ".so", ".dylib", ".wasm", ".dll", ".node"}
SCRIPT_EXTENSIONS: set[str] = {".sh", ".bat", ".cmd"}

SAFE_DOTFILES: set[str] = {
    ".gitignore",
    ".eslintrc",
    ".eslintrc.js",
    ".eslintrc.json",
    ".eslintrc.cjs",
    ".prettierrc",
    ".prettierrc.json",
    ".prettierignore",
    ".npmrc",
    ".npmignore",
    ".editorconfig",
    ".nvmrc",
    ".tsconfig.json",
}

# ---------------------------------------------------------------------------
# Path de-prioritisation (test / fixture / build output)
# ---------------------------------------------------------------------------

DEPRIORITIZED_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/__tests__/"),
    re.compile(r"/test/"),
    re.compile(r"/tests/"),
    re.compile(r"/fixtures?/"),
    re.compile(r"/dist/"),
    re.compile(r"/build/"),
    re.compile(r"\.test\.[jt]sx?$"),
    re.compile(r"\.spec\.[jt]sx?$"),
]

# ---------------------------------------------------------------------------
# Source-level pattern rules
# ---------------------------------------------------------------------------


@dataclass
class SourcePatternRule:
    id: str
    pattern: re.Pattern[str]
    title: str
    severity: str  # Severity
    confidence: float
    profiles: list[str]  # list of RuleProfile
    tags: list[str] = field(default_factory=list)
    capability: str | None = None


SOURCE_PATTERN_RULES: list[SourcePatternRule] = [
    # --- code-execution: always reported ---
    SourcePatternRule(
        id="SRC-EVAL",
        pattern=re.compile(r"\beval\s*\("),
        title="Uses eval()",
        severity="MEDIUM",
        confidence=0.85,
        profiles=["default", "strict"],
        tags=["code-execution"],
        capability="eval",
    ),
    SourcePatternRule(
        id="SRC-NEW-FUNC",
        pattern=re.compile(r"\bnew\s+Function\s*\("),
        title="Uses dynamic Function constructor",
        severity="MEDIUM",
        confidence=0.85,
        profiles=["default", "strict"],
        tags=["code-execution"],
        capability="eval",
    ),
    # SRC-CHILD-PROC was INFO and SRC-EXEC was INFO
    # AND only enabled in strict. compute_assessment downgrades a
    # finding set with only LOW/INFO severities to "benign", so a
    # plugin that imported node:child_process and called
    # exec("sh -c whoami") was classified benign even under strict.
    # Direct command execution is the textbook RCE primitive — raise
    # SRC-CHILD-PROC to MEDIUM and SRC-EXEC to HIGH and enable both
    # in the default profile.
    SourcePatternRule(
        id="SRC-CHILD-PROC",
        pattern=re.compile(r"\bchild_process\b"),
        title="Imports child_process",
        severity="MEDIUM",
        confidence=0.7,
        profiles=["default", "strict"],
        tags=["code-execution"],
        capability="child-process",
    ),
    SourcePatternRule(
        id="SRC-EXEC",
        pattern=re.compile(r"\bexec\s*\("),
        title="Calls exec()",
        severity="HIGH",
        confidence=0.85,
        profiles=["default", "strict"],
        tags=["code-execution"],
        capability="child-process",
    ),
    SourcePatternRule(
        id="SRC-DENO-RUN",
        pattern=re.compile(r"\bDeno\.run\b"),
        title="Uses Deno.run",
        severity="MEDIUM",
        confidence=0.85,
        profiles=["default", "strict"],
        tags=["code-execution"],
        capability="child-process",
    ),
    SourcePatternRule(
        id="SRC-BUN-SPAWN",
        pattern=re.compile(r"\bBun\.spawn\b"),
        title="Uses Bun.spawn",
        severity="MEDIUM",
        confidence=0.85,
        profiles=["default", "strict"],
        tags=["code-execution"],
        capability="child-process",
    ),
    # --- network: default profile suppresses low-signal ---
    SourcePatternRule(
        id="SRC-FETCH",
        pattern=re.compile(r"\b(?:fetch|https?\.request|undici\.request)\s*\("),
        title="Makes network requests",
        severity="INFO",
        confidence=0.3,
        profiles=["strict"],
        tags=["network-access"],
        capability="network",
    ),
    SourcePatternRule(
        id="SRC-NET-SERVER",
        pattern=re.compile(r"\bnet\.createServer\b"),
        title="Creates a network server",
        severity="MEDIUM",
        confidence=0.8,
        profiles=["default", "strict"],
        tags=["network-access"],
        capability="network",
    ),
    SourcePatternRule(
        id="SRC-HTTP-SERVER",
        pattern=re.compile(r"\bhttp\.createServer\b"),
        title="Creates an HTTP server",
        severity="MEDIUM",
        confidence=0.8,
        profiles=["default", "strict"],
        tags=["network-access"],
        capability="network",
    ),
    SourcePatternRule(
        id="SRC-WS",
        pattern=re.compile(r"\bnew\s+WebSocket\b"),
        title="Uses WebSocket connections",
        severity="INFO",
        confidence=0.5,
        profiles=["strict"],
        tags=["network-access"],
        capability="network",
    ),
    # --- env access ---
    SourcePatternRule(
        id="SRC-ENV-READ",
        pattern=re.compile(r"\bprocess\.env\b"),
        title="Reads environment variables",
        severity="INFO",
        confidence=0.3,
        profiles=["strict"],
        tags=["env-access"],
        capability="env-access",
    ),
    # --- filesystem ---
    SourcePatternRule(
        id="SRC-FS-WRITE",
        pattern=re.compile(r"\bfs\.write"),
        title="Performs filesystem writes",
        severity="INFO",
        confidence=0.6,
        profiles=["default", "strict"],
        tags=["filesystem"],
        capability="filesystem-write",
    ),
]

# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------


@dataclass
class SecretPattern:
    id: str
    pattern: re.Pattern[str]
    title: str
    confidence: float


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        id="SEC-AWS",
        pattern=re.compile(r"(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}"),
        title="Possible AWS access key",
        confidence=0.95,
    ),
    SecretPattern(
        id="SEC-STRIPE",
        pattern=re.compile(r"(?:sk_live_|pk_live_|sk_test_|pk_test_)[a-zA-Z0-9]{20,}"),
        title="Possible Stripe key",
        confidence=0.95,
    ),
    SecretPattern(
        id="SEC-GITHUB",
        pattern=re.compile(r"(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}"),
        title="Possible GitHub token",
        confidence=0.95,
    ),
    SecretPattern(
        id="SEC-PRIVKEY",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"),
        title="Private key embedded in source",
        confidence=0.98,
    ),
    SecretPattern(
        id="SEC-GOOGLE", pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"), title="Possible Google API key", confidence=0.9
    ),
    SecretPattern(
        id="SEC-SLACK",
        pattern=re.compile(r"xox[bpors]-[0-9a-zA-Z\-]{10,}"),
        title="Possible Slack token",
        confidence=0.9,
    ),
    SecretPattern(
        id="SEC-JWT",
        pattern=re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*"),
        title="Possible JWT token",
        confidence=0.7,
    ),
    SecretPattern(
        id="SEC-CONNSTR",
        pattern=re.compile(r"(?:mongodb|postgres|mysql|redis)://[^:]+:[^@]+@"),
        title="Connection string with embedded credentials",
        confidence=0.9,
    ),
]

# ---------------------------------------------------------------------------
# Credential path patterns
# ---------------------------------------------------------------------------


@dataclass
class CredentialPathPattern:
    id: str
    pattern: re.Pattern[str]
    title: str


CREDENTIAL_PATH_PATTERNS: list[CredentialPathPattern] = [
    CredentialPathPattern(
        id="CRED-OPENCLAW-DIR",
        pattern=re.compile(r"\.openclaw/credentials", re.IGNORECASE),
        title="Accesses OpenClaw credentials directory",
    ),
    CredentialPathPattern(
        id="CRED-OPENCLAW-ENV",
        pattern=re.compile(r"\.openclaw/\.env", re.IGNORECASE),
        title="Accesses OpenClaw .env file",
    ),
    CredentialPathPattern(
        id="CRED-OPENCLAW-AGENTS",
        pattern=re.compile(r"\.openclaw/agents/", re.IGNORECASE),
        title="Accesses OpenClaw agents directory",
    ),
    CredentialPathPattern(
        id="CRED-READFILE-SECRETS",
        pattern=re.compile(r"readFile\w*\s*\([^)]*(?:\.env|credentials|secrets)", re.IGNORECASE),
        title="Reads credential or secrets files",
    ),
]

# ---------------------------------------------------------------------------
# Gateway manipulation patterns
# ---------------------------------------------------------------------------


@dataclass
class GatewayPattern:
    id: str
    pattern: re.Pattern[str]
    title: str
    severity: str
    confidence: float


GATEWAY_PATTERNS: list[GatewayPattern] = [
    GatewayPattern(
        id="GW-PROCESS-EXIT",
        pattern=re.compile(r"\bprocess\.exit\s*\("),
        title="Calls process.exit()",
        severity="HIGH",
        confidence=0.9,
    ),
    GatewayPattern(
        id="GW-MODULE-IMPORT",
        pattern=re.compile(r"""\b(?:require|import)\s*\(\s*['"]module['"]\s*\)"""),
        title="Imports Node module system",
        severity="HIGH",
        confidence=0.9,
    ),
    GatewayPattern(
        id="GW-MODULE-LOAD",
        pattern=re.compile(r"\bModule\._load\b"),
        title="Manipulates Module._load",
        severity="HIGH",
        confidence=0.95,
    ),
    GatewayPattern(
        id="GW-GLOBAL-MOD",
        pattern=re.compile(r"\bglobalThis\s*[.[=]|\bglobal\s*\.\s*\w+\s*="),
        title="Modifies global state",
        severity="MEDIUM",
        confidence=0.7,
    ),
    GatewayPattern(
        id="GW-PROTO-DEFINE",
        pattern=re.compile(r"Object\.defineProperty\s*\(\s*Object\.prototype"),
        title="Prototype pollution via Object.defineProperty",
        severity="CRITICAL",
        confidence=0.98,
    ),
    GatewayPattern(
        id="GW-PROTO-ACCESS",
        pattern=re.compile(r"__proto__\s*[=\[]"),
        title="Accesses __proto__ (prototype pollution risk)",
        severity="HIGH",
        confidence=0.85,
    ),
    GatewayPattern(
        id="GW-ENV-WRITE",
        pattern=re.compile(r"\bprocess\.env\s*\.\s*\w+\s*="),
        title="Modifies environment variables at runtime",
        severity="MEDIUM",
        confidence=0.8,
    ),
]

# ---------------------------------------------------------------------------
# Write-function detection (cognitive tampering)
# ---------------------------------------------------------------------------

WRITE_FUNCTIONS: re.Pattern[str] = re.compile(
    r"(?:writeFile|appendFile|writeFileSync|appendFileSync|createWriteStream)\s*\("
)

# ---------------------------------------------------------------------------
# SSRF / Cloud metadata patterns
# ---------------------------------------------------------------------------


@dataclass
class CloudMetadataPattern:
    id: str
    pattern: re.Pattern[str]
    title: str
    confidence: float


CLOUD_METADATA_PATTERNS: list[CloudMetadataPattern] = [
    CloudMetadataPattern(
        id="SSRF-AWS-META",
        pattern=re.compile(r"169\.254\.169\.254"),
        title="AWS EC2 metadata endpoint reference",
        confidence=0.95,
    ),
    CloudMetadataPattern(
        id="SSRF-GCP-META",
        pattern=re.compile(r"metadata\.google\.internal"),
        title="GCP metadata endpoint reference",
        confidence=0.95,
    ),
    CloudMetadataPattern(
        id="SSRF-AZURE-META",
        pattern=re.compile(r"169\.254\.169\.254.*metadata/instance|metadata/instance.*169\.254\.169\.254"),
        title="Azure metadata endpoint reference",
        confidence=0.9,
    ),
    CloudMetadataPattern(
        id="SSRF-ALIBABA-META",
        pattern=re.compile(r"100\.100\.100\.200"),
        title="Alibaba Cloud metadata endpoint reference",
        confidence=0.9,
    ),
    CloudMetadataPattern(
        id="SSRF-LINK-LOCAL",
        pattern=re.compile(r"169\.254\.\d{1,3}\.\d{1,3}"),
        title="Link-local IP address reference",
        confidence=0.7,
    ),
]

PRIVATE_IP_PATTERN: re.Pattern[str] = re.compile(
    r"(?:^|\b)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\b|$)"
)

INTERNAL_HOSTNAME_PATTERNS: re.Pattern[str] = re.compile(
    r"\b(?:localhost|internal|corp|local|intranet|private)\b.*\b(?:fetch|http|request|get|post)\b|\b(?:fetch|http|request|get|post)\b.*\b(?:localhost|internal|corp|local|intranet|private)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Dynamic import / require patterns
# ---------------------------------------------------------------------------


@dataclass
class DynamicImportPattern:
    id: str
    pattern: re.Pattern[str]
    title: str
    severity: str
    confidence: float


DYNAMIC_IMPORT_PATTERNS: list[DynamicImportPattern] = [
    DynamicImportPattern(
        id="DYN-IMPORT",
        pattern=re.compile(r"""\bimport\s*\(\s*(?!['"][^'"]+['"]\s*\))"""),
        title="Dynamic import() with non-literal argument",
        severity="MEDIUM",
        confidence=0.8,
    ),
    DynamicImportPattern(
        id="DYN-REQUIRE",
        pattern=re.compile(r"""\brequire\s*\(\s*(?!['"][^'"]+['"]\s*\))"""),
        title="Dynamic require() with non-literal argument",
        severity="MEDIUM",
        confidence=0.75,
    ),
    DynamicImportPattern(
        id="DYN-SPAWN-VAR",
        pattern=re.compile(r"""\b(?:spawn|execFile|fork)\s*\(\s*(?!['"][^'"]+['"]\s*[,)])"""),
        title="Process spawn with non-literal command",
        severity="HIGH",
        confidence=0.85,
    ),
]

# ---------------------------------------------------------------------------
# Bundle size threshold
# ---------------------------------------------------------------------------

BUNDLE_SIZE_THRESHOLD_BYTES: int = 500 * 1024  # 500 KB
BUNDLE_DIRS: set[str] = {"dist", "build", "out", "bundle"}

# ---------------------------------------------------------------------------
# JSON config scanning patterns
# ---------------------------------------------------------------------------


@dataclass
class JsonPattern:
    id: str
    pattern: re.Pattern[str]
    title: str
    confidence: float


JSON_SECRET_PATTERNS: list[JsonPattern] = [
    JsonPattern(
        id="JSON-SEC-AWS",
        pattern=re.compile(r"(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}"),
        title="AWS key in config file",
        confidence=0.95,
    ),
    JsonPattern(
        id="JSON-SEC-PRIVKEY",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"),
        title="Private key in config file",
        confidence=0.98,
    ),
    JsonPattern(
        id="JSON-SEC-CONNSTR",
        pattern=re.compile(r"(?:mongodb|postgres|mysql|redis)://[^:]+:[^@]+@"),
        title="Connection string in config file",
        confidence=0.9,
    ),
    JsonPattern(
        id="JSON-SEC-GENERIC",
        pattern=re.compile(
            r"""["'](?:password|secret|api[_-]?key|access[_-]?token|auth[_-]?token)["']\s*:\s*["'][^"']{8,}["']""",
            re.IGNORECASE,
        ),
        title="Possible secret in config key-value pair",
        confidence=0.7,
    ),
]

JSON_URL_PATTERNS: list[JsonPattern] = [
    JsonPattern(
        id="JSON-URL-HTTP",
        pattern=re.compile(
            r"""["']https?://(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|localhost|127\.0\.0\.1)"""
        ),
        title="Metadata/localhost URL in config",
        confidence=0.9,
    ),
    JsonPattern(
        id="JSON-URL-C2",
        pattern=re.compile(
            r"""["']https?://[^"']*(?:webhook\.site|ngrok\.io|pipedream\.net|requestbin\.com|interact\.sh|oast\.fun|burpcollaborator\.net)"""
        ),
        title="Known C2 domain in config",
        confidence=0.95,
    ),
]

# ---------------------------------------------------------------------------
# Cisco AITech Taxonomy mapping -- rule_id -> taxonomy reference
# ---------------------------------------------------------------------------

TAXONOMY_MAP: dict[str, TaxonomyRef] = {
    # OB-009: Supply Chain Compromise
    "SCRIPT-INSTALL-HOOK": TaxonomyRef(objective="OB-009", technique="AITech-9.3", sub_technique="AISubtech-9.3.1"),
    "SCRIPT-SHELL-CMD": TaxonomyRef(objective="OB-009", technique="AITech-9.3", sub_technique="AISubtech-9.3.1"),
    "DEP-RISKY": TaxonomyRef(objective="OB-009", technique="AITech-9.3", sub_technique="AISubtech-9.3.1"),
    "DEP-UNPINNED": TaxonomyRef(objective="OB-009", technique="AITech-9.3", sub_technique="AISubtech-9.3.3"),
    "DEP-HTTP": TaxonomyRef(objective="OB-009", technique="AITech-9.3", sub_technique="AISubtech-9.3.3"),
    "DEP-LOCAL-FILE": TaxonomyRef(objective="OB-009", technique="AITech-9.3", sub_technique="AISubtech-9.3.1"),
    "DEP-GIT-UNPIN": TaxonomyRef(objective="OB-009", technique="AITech-9.3", sub_technique="AISubtech-9.3.3"),
    "STRUCT-NO-LOCKFILE": TaxonomyRef(objective="OB-009", technique="AITech-9.3", sub_technique="AISubtech-9.3.3"),
    "MANIFEST-MISSING": TaxonomyRef(objective="OB-009", technique="AITech-9.3"),
    "STRUCT-BINARY": TaxonomyRef(objective="OB-009", technique="AITech-9.2", sub_technique="AISubtech-9.2.2"),
    "STRUCT-SCRIPT": TaxonomyRef(objective="OB-009", technique="AITech-9.3", sub_technique="AISubtech-9.3.1"),
    # OB-009 / Detection Evasion
    "OBF-BASE64": TaxonomyRef(objective="OB-009", technique="AITech-9.2", sub_technique="AISubtech-9.2.1"),
    "OBF-CHARCODE": TaxonomyRef(objective="OB-009", technique="AITech-9.2", sub_technique="AISubtech-9.2.1"),
    "OBF-HEX": TaxonomyRef(objective="OB-009", technique="AITech-9.2", sub_technique="AISubtech-9.2.1"),
    "OBF-CONCAT": TaxonomyRef(objective="OB-009", technique="AITech-9.2", sub_technique="AISubtech-9.2.1"),
    "OBF-MINIFIED": TaxonomyRef(objective="OB-009", technique="AITech-9.2", sub_technique="AISubtech-9.2.1"),
    # OB-014: Privilege Compromise
    "PERM-DANGEROUS": TaxonomyRef(objective="OB-014", technique="AITech-14.2", sub_technique="AISubtech-14.2.1"),
    "PERM-WILDCARD": TaxonomyRef(objective="OB-014", technique="AITech-14.2", sub_technique="AISubtech-14.2.1"),
    "PERM-NONE": TaxonomyRef(objective="OB-014", technique="AITech-14.1", sub_technique="AISubtech-14.1.2"),
    "TOOL-NO-DESC": TaxonomyRef(objective="OB-014", technique="AITech-14.1", sub_technique="AISubtech-14.1.2"),
    "TOOL-PERM-DANGEROUS": TaxonomyRef(objective="OB-014", technique="AITech-14.2", sub_technique="AISubtech-14.2.1"),
    # OB-008: Data Privacy / Credential Theft
    "SEC-AWS": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "SEC-STRIPE": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "SEC-GITHUB": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "SEC-PRIVKEY": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "SEC-GOOGLE": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "SEC-SLACK": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "SEC-JWT": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "SEC-CONNSTR": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "CRED-OPENCLAW-DIR": TaxonomyRef(objective="OB-014", technique="AITech-14.1", sub_technique="AISubtech-14.1.1"),
    "CRED-OPENCLAW-ENV": TaxonomyRef(objective="OB-014", technique="AITech-14.1", sub_technique="AISubtech-14.1.1"),
    "CRED-OPENCLAW-AGENTS": TaxonomyRef(objective="OB-014", technique="AITech-14.1", sub_technique="AISubtech-14.1.1"),
    "CRED-READFILE-SECRETS": TaxonomyRef(objective="OB-014", technique="AITech-14.1", sub_technique="AISubtech-14.1.1"),
    "STRUCT-ENV-FILE": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    # OB-008: Exfiltration
    "EXFIL-C2-DOMAIN": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "EXFIL-DNS": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    # OB-012: Action-Space Abuse / Code Execution
    "SRC-EVAL": TaxonomyRef(objective="OB-012", technique="AITech-12.1", sub_technique="AISubtech-12.1.3"),
    "SRC-NEW-FUNC": TaxonomyRef(objective="OB-012", technique="AITech-12.1", sub_technique="AISubtech-12.1.3"),
    "SRC-CHILD-PROC": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.1"),
    "SRC-EXEC": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.1"),
    "SRC-DENO-RUN": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.1"),
    "SRC-BUN-SPAWN": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.1"),
    "SRC-FETCH": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.3"),
    "SRC-NET-SERVER": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.3"),
    "SRC-HTTP-SERVER": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.3"),
    "SRC-WS": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.3"),
    "SRC-ENV-READ": TaxonomyRef(objective="OB-008", technique="AITech-8.3", sub_technique="AISubtech-8.3.2"),
    "SRC-FS-WRITE": TaxonomyRef(objective="OB-012", technique="AITech-12.1", sub_technique="AISubtech-12.1.3"),
    # OB-005: Persistence / Cognitive Tampering
    "COG-TAMPER": TaxonomyRef(objective="OB-005", technique="AITech-5.2", sub_technique="AISubtech-5.2.1"),
    # OB-012 / OB-013: Gateway Manipulation
    "GW-PROCESS-EXIT": TaxonomyRef(objective="OB-013", technique="AITech-13.1", sub_technique="AISubtech-13.1.4"),
    "GW-MODULE-IMPORT": TaxonomyRef(objective="OB-012", technique="AITech-12.1", sub_technique="AISubtech-12.1.3"),
    "GW-MODULE-LOAD": TaxonomyRef(objective="OB-012", technique="AITech-12.1", sub_technique="AISubtech-12.1.3"),
    "GW-GLOBAL-MOD": TaxonomyRef(objective="OB-012", technique="AITech-12.1", sub_technique="AISubtech-12.1.2"),
    "GW-PROTO-DEFINE": TaxonomyRef(objective="OB-012", technique="AITech-12.1", sub_technique="AISubtech-12.1.2"),
    "GW-PROTO-ACCESS": TaxonomyRef(objective="OB-012", technique="AITech-12.1", sub_technique="AISubtech-12.1.2"),
    "GW-ENV-WRITE": TaxonomyRef(objective="OB-012", technique="AITech-12.1", sub_technique="AISubtech-12.1.3"),
    # OB-013: Availability / Cost Abuse
    "COST-RUNAWAY": TaxonomyRef(objective="OB-013", technique="AITech-13.2", sub_technique="AISubtech-13.2.1"),
    # Structural
    "STRUCT-HIDDEN": TaxonomyRef(objective="OB-009", technique="AITech-9.2", sub_technique="AISubtech-9.2.2"),
    # SSRF / Cloud metadata
    "SSRF-AWS-META": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.3"),
    "SSRF-GCP-META": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.3"),
    "SSRF-AZURE-META": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.3"),
    "SSRF-ALIBABA-META": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.3"),
    "SSRF-LINK-LOCAL": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.3"),
    "SSRF-PRIVATE-IP": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.3"),
    "SSRF-INTERNAL-HOST": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.3"),
    # OpenClaw plugin manifest
    "CLAW-MANIFEST-MISSING": TaxonomyRef(objective="OB-014", technique="AITech-14.1", sub_technique="AISubtech-14.1.2"),
    "CLAW-HOOK-DANGEROUS": TaxonomyRef(objective="OB-012", technique="AITech-12.1", sub_technique="AISubtech-12.1.2"),
    "CLAW-TOOL-NO-DESC": TaxonomyRef(objective="OB-014", technique="AITech-14.1", sub_technique="AISubtech-14.1.2"),
    # Bundle size
    "STRUCT-LARGE-BUNDLE": TaxonomyRef(objective="OB-009", technique="AITech-9.2", sub_technique="AISubtech-9.2.1"),
    # Dynamic imports
    "DYN-IMPORT": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.1"),
    "DYN-REQUIRE": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.1"),
    "DYN-SPAWN-VAR": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.1"),
    # JSON config secrets
    "JSON-SEC-AWS": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "JSON-SEC-PRIVKEY": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "JSON-SEC-CONNSTR": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "JSON-SEC-GENERIC": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "JSON-URL-HTTP": TaxonomyRef(objective="OB-009", technique="AITech-9.1", sub_technique="AISubtech-9.1.3"),
    "JSON-URL-C2": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    # Meta-analyzer cross-reference rules
    "META-EXFIL-CHAIN": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "META-EVASIVE-ATTACK": TaxonomyRef(objective="OB-009", technique="AITech-9.2", sub_technique="AISubtech-9.2.1"),
    "META-SUPPLY-CHAIN": TaxonomyRef(objective="OB-009", technique="AITech-9.3", sub_technique="AISubtech-9.3.1"),
    "META-PERSISTENT-COMPROMISE": TaxonomyRef(
        objective="OB-005", technique="AITech-5.2", sub_technique="AISubtech-5.2.1"
    ),
    "META-CLOUD-CRED-THEFT": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "META-REVERSE-SHELL": TaxonomyRef(objective="OB-012", technique="AITech-12.1", sub_technique="AISubtech-12.1.3"),
    "META-ENV-EXFIL": TaxonomyRef(objective="OB-008", technique="AITech-8.2", sub_technique="AISubtech-8.2.3"),
    "META-REMOTE-CODE-EXEC": TaxonomyRef(objective="OB-012", technique="AITech-12.1", sub_technique="AISubtech-12.1.3"),
    "META-DROP-AND-EXEC": TaxonomyRef(objective="OB-009", technique="AITech-9.3", sub_technique="AISubtech-9.3.1"),
    "META-AGENT-TAKEOVER": TaxonomyRef(objective="OB-005", technique="AITech-5.2", sub_technique="AISubtech-5.2.1"),
    "META-PROTO-RCE": TaxonomyRef(objective="OB-012", technique="AITech-12.1", sub_technique="AISubtech-12.1.2"),
}
