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

"""Plugin scan policy."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Policy types
# ---------------------------------------------------------------------------


@dataclass
class AnalyzersPolicy:
    permissions: bool = True
    dependencies: bool = True
    install_scripts: bool = True
    tools: bool = True
    source: bool = True
    directory_structure: bool = True
    claw_manifest: bool = True
    bundle_size: bool = True
    json_configs: bool = True
    lockfile: bool = True
    meta: bool = True


@dataclass
class SeverityOverride:
    rule_id: str
    severity: str


@dataclass
class LLMPolicy:
    enabled: bool = False
    model: str = "claude-sonnet-4-20250514"
    api_key: str = ""
    api_base: str = ""
    provider: str = ""
    max_output_tokens: int = 8192
    meta_multiplier: int = 3
    consensus_runs: int = 1
    python_binary: str = "python3"

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "model": self.model,
            "api_key": self.api_key,
            "api_base": self.api_base,
            "provider": self.provider,
            "max_output_tokens": self.max_output_tokens,
            "meta_multiplier": self.meta_multiplier,
            "consensus_runs": self.consensus_runs,
            "python_binary": self.python_binary,
        }


@dataclass
class PluginScanPolicy:
    policy_name: str = "default"
    policy_version: str = "1.0"
    profile: str = "default"  # ScanProfile
    analyzers: AnalyzersPolicy = field(default_factory=AnalyzersPolicy)
    severity_overrides: list[SeverityOverride] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    min_confidence: float = 0.0
    safe_dotfiles: list[str] = field(default_factory=list)
    max_findings_per_rule: int = 10
    llm: LLMPolicy = field(default_factory=LLMPolicy)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_SAFE_DOTFILES = [
    ".gitignore",
    ".gitattributes",
    ".gitmodules",
    ".gitkeep",
    ".editorconfig",
    ".prettierrc",
    ".prettierrc.json",
    ".prettierignore",
    ".eslintrc",
    ".eslintrc.js",
    ".eslintrc.json",
    ".eslintrc.cjs",
    ".eslintrc.yml",
    ".stylelintrc",
    ".stylelintignore",
    ".npmrc",
    ".npmignore",
    ".nvmrc",
    ".node-version",
    ".python-version",
    ".ruby-version",
    ".tool-versions",
    ".flake8",
    ".pylintrc",
    ".isort.cfg",
    ".mypy.ini",
    ".babelrc",
    ".browserslistrc",
    ".postcssrc",
    ".dockerignore",
    ".env.example",
    ".env.sample",
    ".env.template",
    ".markdownlint.json",
    ".markdownlintignore",
    ".yamllint",
    ".yamllint.yml",
    ".cursorrules",
    ".cursorignore",
    ".clang-format",
    ".clang-tidy",
    ".rubocop.yml",
    ".solhint.json",
    ".mcp.json",
    ".envrc",
    ".tsconfig.json",
]


def default_policy() -> PluginScanPolicy:
    return PluginScanPolicy(
        policy_name="default",
        policy_version="1.0",
        profile="default",
        analyzers=AnalyzersPolicy(),
        severity_overrides=[],
        disabled_rules=[],
        min_confidence=0.0,
        safe_dotfiles=list(_DEFAULT_SAFE_DOTFILES),
        max_findings_per_rule=10,
        llm=LLMPolicy(),
    )


# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------


def _strict_policy() -> PluginScanPolicy:
    return PluginScanPolicy(
        policy_name="strict",
        policy_version="1.0",
        profile="strict",
        analyzers=AnalyzersPolicy(),
        severity_overrides=[
            SeverityOverride(rule_id="PERM-WILDCARD", severity="HIGH"),
            SeverityOverride(rule_id="SRC-EVAL", severity="HIGH"),
            SeverityOverride(rule_id="SRC-NEW-FUNC", severity="HIGH"),
            SeverityOverride(rule_id="DEP-UNPINNED", severity="HIGH"),
        ],
        disabled_rules=[],
        min_confidence=0.0,
        safe_dotfiles=[
            ".gitignore",
            ".gitattributes",
            ".gitmodules",
            ".gitkeep",
            ".editorconfig",
            ".dockerignore",
        ],
        max_findings_per_rule=20,
        llm=LLMPolicy(),
    )


def _permissive_policy() -> PluginScanPolicy:
    return PluginScanPolicy(
        policy_name="permissive",
        policy_version="1.0",
        profile="default",
        analyzers=AnalyzersPolicy(
            bundle_size=False,
            lockfile=False,
            meta=False,
        ),
        severity_overrides=[],
        disabled_rules=[
            "PERM-NONE",
            "TOOL-NO-DESC",
            "CLAW-TOOL-NO-DESC",
            "STRUCT-HIDDEN",
            "STRUCT-SCRIPT",
            "OBF-MINIFIED",
        ],
        min_confidence=0.5,
        safe_dotfiles=list(_DEFAULT_SAFE_DOTFILES),
        max_findings_per_rule=5,
        llm=LLMPolicy(),
    )


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def from_preset(name: str) -> PluginScanPolicy:
    if name == "strict":
        return _strict_policy()
    if name == "permissive":
        return _permissive_policy()
    if name == "default":
        return default_policy()
    raise ValueError(f'Unknown policy preset: "{name}". Use "default", "strict", or "permissive".')


def from_yaml(path: str) -> PluginScanPolicy:
    """Load a policy from a YAML file and merge on top of defaults."""
    import yaml  # pyyaml

    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        return default_policy()

    return _merge_policy(default_policy(), data)


def _merge_policy(
    base: PluginScanPolicy,
    override: dict[str, Any],
) -> PluginScanPolicy:
    result = deepcopy(base)

    if isinstance(override.get("policy_name"), str):
        result.policy_name = override["policy_name"]
    if isinstance(override.get("policy_version"), str):
        result.policy_version = override["policy_version"]
    if override.get("profile") in ("strict", "default"):
        result.profile = override["profile"]
    if isinstance(override.get("min_confidence"), int | float):
        result.min_confidence = float(override["min_confidence"])
    if isinstance(override.get("max_findings_per_rule"), int):
        result.max_findings_per_rule = override["max_findings_per_rule"]

    # Merge analyzers (only override specified keys)
    a = override.get("analyzers")
    if isinstance(a, dict):
        # Map YAML keys (snake_case) to AnalyzersPolicy fields
        key_map = {
            "permissions": "permissions",
            "dependencies": "dependencies",
            "installScripts": "install_scripts",
            "install_scripts": "install_scripts",
            "tools": "tools",
            "source": "source",
            "directoryStructure": "directory_structure",
            "directory_structure": "directory_structure",
            "clawManifest": "claw_manifest",
            "claw_manifest": "claw_manifest",
            "bundleSize": "bundle_size",
            "bundle_size": "bundle_size",
            "jsonConfigs": "json_configs",
            "json_configs": "json_configs",
            "lockfile": "lockfile",
            "meta": "meta",
        }
        for yaml_key, attr_name in key_map.items():
            if yaml_key in a and isinstance(a[yaml_key], bool):
                setattr(result.analyzers, attr_name, a[yaml_key])

    # Severity overrides (replace, not merge)
    so = override.get("severity_overrides")
    if isinstance(so, list):
        result.severity_overrides = [
            SeverityOverride(rule_id=o["rule_id"], severity=o["severity"])
            for o in so
            if isinstance(o, dict) and o.get("rule_id") and o.get("severity")
        ]

    # Disabled rules (replace)
    dr = override.get("disabled_rules")
    if isinstance(dr, list):
        result.disabled_rules = [r for r in dr if isinstance(r, str)]

    # Safe dotfiles (replace)
    sd = override.get("safe_dotfiles")
    if isinstance(sd, list):
        result.safe_dotfiles = [s for s in sd if isinstance(s, str)]

    # LLM config (merge)
    lc = override.get("llm")
    if isinstance(lc, dict):
        if isinstance(lc.get("enabled"), bool):
            result.llm.enabled = lc["enabled"]
        if isinstance(lc.get("model"), str):
            result.llm.model = lc["model"]
        if isinstance(lc.get("api_key"), str):
            result.llm.api_key = lc["api_key"]
        if isinstance(lc.get("api_base"), str):
            result.llm.api_base = lc["api_base"]
        if isinstance(lc.get("provider"), str):
            result.llm.provider = lc["provider"]
        if isinstance(lc.get("max_output_tokens"), int):
            result.llm.max_output_tokens = lc["max_output_tokens"]
        if isinstance(lc.get("meta_multiplier"), int):
            result.llm.meta_multiplier = lc["meta_multiplier"]
        if isinstance(lc.get("consensus_runs"), int):
            result.llm.consensus_runs = lc["consensus_runs"]
        if isinstance(lc.get("python_binary"), str):
            result.llm.python_binary = lc["python_binary"]

    return result


# ---------------------------------------------------------------------------
# Policy application helpers
# ---------------------------------------------------------------------------

# Map AnalyzersPolicy field names to analyzer names
_ANALYZER_NAME_MAP: dict[str, str] = {
    "permissions": "permissions",
    "dependencies": "dependencies",
    "install_scripts": "install-scripts",
    "tools": "tools",
    "source": "source",
    "directory_structure": "directory-structure",
    "claw_manifest": "claw-manifest",
    "bundle_size": "bundle-size",
    "json_configs": "json-configs",
    "lockfile": "lockfile",
    "meta": "meta",
}


def disabled_analyzer_names(policy: PluginScanPolicy) -> list[str]:
    """Get the list of disabled analyzer names from the policy."""
    disabled: list[str] = []
    for field_name, analyzer_name in _ANALYZER_NAME_MAP.items():
        if not getattr(policy.analyzers, field_name, True):
            disabled.append(analyzer_name)
    return disabled


def apply_severity_override(
    finding: Any,
    overrides: list[SeverityOverride],
) -> None:
    """Apply severity overrides to a finding."""
    if not getattr(finding, "rule_id", None):
        return
    for override in overrides:
        if override.rule_id == finding.rule_id:
            finding.severity = override.severity
            return


def is_suppressed(
    finding: Any,
    policy: PluginScanPolicy,
) -> bool:
    """Check if a finding should be suppressed by policy or meta-analysis."""
    if getattr(finding, "suppressed", False):
        return True
    rule_id = getattr(finding, "rule_id", None)
    if rule_id and rule_id in policy.disabled_rules:
        return True
    confidence = getattr(finding, "confidence", None)
    if confidence is not None and confidence < policy.min_confidence:
        return True
    return False
