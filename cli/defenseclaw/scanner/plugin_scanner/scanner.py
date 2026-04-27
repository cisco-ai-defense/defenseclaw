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

"""DefenseClaw Plugin Scanner -- orchestrator.

Public entry point. Loads the manifest, builds the analyzer pipeline via
the factory, runs each analyzer, deduplicates findings, and computes the
assessment.
"""

from __future__ import annotations

import json
import os
import time

from defenseclaw.scanner.plugin_scanner.analyzer import ScanContext
from defenseclaw.scanner.plugin_scanner.analyzer_factory import build_analyzers
from defenseclaw.scanner.plugin_scanner.analyzers import has_install_scripts
from defenseclaw.scanner.plugin_scanner.helpers import (
    build_result,
    deduplicate_findings,
    make_finding,
)
from defenseclaw.scanner.plugin_scanner.policy import (
    PluginScanPolicy,
    apply_severity_override,
    default_policy,
    disabled_analyzer_names,
    from_preset,
    from_yaml,
    is_suppressed,
)
from defenseclaw.scanner.plugin_scanner.types import (
    Finding,
    PluginManifest,
    PluginScanOptions,
    ScanMetadata,
    ScanResult,
)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_plugin(
    plugin_dir: str,
    options: PluginScanOptions | None = None,
) -> ScanResult:
    start_ms = time.time() * 1000
    target = os.path.abspath(plugin_dir)

    # --- Load policy ---
    policy: PluginScanPolicy
    if options and options.policy:
        if options.policy in ("default", "strict", "permissive"):
            policy = from_preset(options.policy)
        else:
            policy = from_yaml(options.policy)
    else:
        policy = default_policy()

    # Apply the unified LLM override on top of the loaded policy. This
    # is the hook that lets the top-level ``llm:`` config (resolved for
    # ``scanners.plugin``) flow in without forcing every caller to
    # author a YAML policy file. Precedence ends up being:
    #     CLI flag  >  scanners.plugin.llm  >  top-level llm  >  YAML policy.llm
    # The first three are collapsed by ``Config.resolve_llm`` before
    # reaching us; the YAML policy is what ``policy.llm`` already is,
    # so we only need to override fields the resolver actually set.
    if options and options.llm_override:
        for key, value in options.llm_override.items():
            if hasattr(policy.llm, key) and value not in (None, ""):
                setattr(policy.llm, key, value)

    # Profile from options overrides policy profile
    profile = (options.profile if options and options.profile else None) or policy.profile

    # --- Load manifest ---
    manifest = _load_manifest(target)
    manifest_missing_finding: Finding | None = None
    if manifest is None:
        manifest_missing_finding = make_finding(
            1,
            rule_id="MANIFEST-MISSING",
            severity="HIGH",
            confidence=1.0,
            title="No plugin manifest found",
            description=(
                "Plugin directory lacks a recognised manifest "
                "(package.json, manifest.json, plugin.json, "
                "openclaw.plugin.json, .codex-plugin/plugin.json, "
                "or .claude-plugin/plugin.json). Cannot verify plugin "
                "identity, version, or declared permissions. Source "
                "scanning will still run."
            ),
            location=target,
            remediation="Add a package.json with name, version, and permissions fields.",
            tags=["supply-chain"],
        )
        # Synthetic manifest so the analyzer pipeline still runs
        manifest = PluginManifest(name="unknown", source="none")

    # --- Build analyzer pipeline (respecting policy toggles + LLM config) ---
    analyzers = build_analyzers(
        profile=profile,
        disabled_analyzers=disabled_analyzer_names(policy),
        llm=policy.llm.to_dict() if policy.llm else None,
    )

    # --- Build scan context ---
    ctx = ScanContext(
        plugin_dir=target,
        manifest=manifest,
        source_files=[],
        profile=profile,
        capabilities=set(),
        finding_counter=[1],
        previous_findings=[],
        metadata={},
    )

    # --- Run analyzers sequentially ---
    all_findings: list[Finding] = []
    if manifest_missing_finding is not None:
        all_findings.append(manifest_missing_finding)

    for analyzer in analyzers:
        # Feed accumulated findings to meta analyzer
        if analyzer.name == "meta":
            ctx.previous_findings = list(all_findings)

        findings = analyzer.analyze(ctx)

        # Assign stable IDs
        for f in findings:
            if f.id.startswith("plugin-0") or not f.id.startswith("plugin-"):
                f.id = f"plugin-{ctx.finding_counter[0]}"
                ctx.finding_counter[0] += 1

        all_findings.extend(findings)

    # --- Apply policy: severity overrides + suppression ---
    for f in all_findings:
        apply_severity_override(f, policy.severity_overrides)

    policy_filtered = [f for f in all_findings if not is_suppressed(f, policy)]

    # --- Build metadata ---
    metadata = ScanMetadata(
        manifest_name=manifest.name,
        manifest_version=manifest.version,
        file_count=int(ctx.metadata.get("file_count", 0)),
        total_size_bytes=int(ctx.metadata.get("total_size_bytes", 0)),
        has_lockfile=bool(ctx.metadata.get("has_lockfile", False)),
        has_install_scripts=has_install_scripts(manifest),
        detected_capabilities=sorted(ctx.capabilities),
    )

    return build_result(target, deduplicate_findings(policy_filtered), start_ms, metadata)


# ---------------------------------------------------------------------------
# Manifest loading
# ---------------------------------------------------------------------------


# Manifest candidates checked in order. The first hit wins. Each entry
# is (relative_path, source_label):
#
#   * relative_path is the path relative to the plugin directory the
#     scanner is targeting (e.g. ".codex-plugin/plugin.json" for the
#     Codex per-plugin manifest convention).
#   * source_label is what gets recorded in PluginManifest.source so
#     downstream analyzers can reason about which schema produced
#     the data.
#
# Order is "generic-first": package.json wins when both it and a
# connector-specific manifest are present, because most plugins
# bundle their node deps via npm and the npm schema has more useful
# fields for security analysis (dependencies, scripts, etc.).
# Connector-specific manifests are fallbacks that only kick in when
# no generic packaging is present — that's how OpenClaw-only plugins
# got rescued before this change, and Codex/Claude plugins follow
# the same precedence so a future Codex plugin that ships a
# package.json doesn't suddenly get scanned under a different
# schema. See S2.3 / F8 and `test_package_json_still_takes_precedence`.
_MANIFEST_CANDIDATES: tuple[tuple[str, str], ...] = (
    # Generic packaging — preferred when present.
    ("package.json", "package.json"),
    ("manifest.json", "manifest.json"),
    ("plugin.json", "plugin.json"),
    # Connector-specific fallbacks. Order within this group is alpha
    # for stability; none takes precedence over another in practice
    # because each lives in a distinct plugin layout.
    ("openclaw.plugin.json", "openclaw.plugin.json"),
    (os.path.join(".claude-plugin", "plugin.json"), "claude.plugin.json"),
    (os.path.join(".codex-plugin", "plugin.json"), "codex.plugin.json"),
)


def _load_manifest(directory: str) -> PluginManifest | None:
    for rel_path, source_label in _MANIFEST_CANDIDATES:
        candidate = os.path.join(directory, rel_path)
        try:
            with open(candidate, encoding="utf-8") as fh:
                raw = json.loads(fh.read())
            return _normalize_manifest(raw, source_label)
        except (OSError, json.JSONDecodeError):
            continue
    return None


def _normalize_manifest(
    raw: dict,
    filename: str,
) -> PluginManifest:
    # openclaw.plugin.json uses "id" instead of "name"
    name = raw.get("name") or raw.get("id") or os.path.basename(filename)
    manifest = PluginManifest(
        name=str(name),
        version=raw.get("version") if isinstance(raw.get("version"), str) else None,
        description=raw.get("description") if isinstance(raw.get("description"), str) else None,
        source=filename,
    )

    if isinstance(raw.get("permissions"), list):
        manifest.permissions = raw["permissions"]

    defenseclaw = raw.get("defenseclaw")
    if isinstance(defenseclaw, dict) and isinstance(defenseclaw.get("permissions"), list):
        manifest.permissions = defenseclaw["permissions"]

    if isinstance(raw.get("tools"), list):
        manifest.tools = raw["tools"]

    if isinstance(raw.get("commands"), list):
        manifest.commands = raw["commands"]

    if isinstance(raw.get("dependencies"), dict):
        manifest.dependencies = raw["dependencies"]
    if isinstance(raw.get("devDependencies"), dict):
        manifest.dependencies = {
            **(manifest.dependencies or {}),
            **raw["devDependencies"],
        }

    if isinstance(raw.get("scripts"), dict):
        manifest.scripts = raw["scripts"]

    return manifest
