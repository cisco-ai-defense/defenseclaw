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
import stat
import time

from defenseclaw.scanner.plugin_scanner.analyzer import ScanContext
from defenseclaw.scanner.plugin_scanner.analyzer_factory import build_analyzers
from defenseclaw.scanner.plugin_scanner.analyzers import has_install_scripts
from defenseclaw.scanner.plugin_scanner.helpers import (
    audit_skipped_dirs_for_native,
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
    disabled_analyzers = disabled_analyzer_names(policy)
    # Honour an explicit request to disable meta analysis (CLI --no-meta
    # threaded through PluginScanOptions). Previously the flag was accepted
    # by the wrapper but never reached the pipeline (F-0302).
    if options and options.disable_meta and "meta" not in disabled_analyzers:
        disabled_analyzers = [*disabled_analyzers, "meta"]
    analyzers = build_analyzers(
        profile=profile,
        disabled_analyzers=disabled_analyzers,
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
        manifest_missing_finding.id = f"plugin-{ctx.finding_counter[0]}"
        ctx.finding_counter[0] += 1
        all_findings.append(manifest_missing_finding)

    # F-1907: surface native/binary payloads hidden under normally-skipped
    # dirs (node_modules/.git/etc.). The directory-structure analyzer skips
    # those trees, so this audit is the only thing that catches a native
    # addon stashed there to dodge both source and binary scanning. Run it
    # before the analyzer loop so the meta analyzer can fold the signal into
    # its cross-reference chains.
    for f in audit_skipped_dirs_for_native(target):
        f.id = f"plugin-{ctx.finding_counter[0]}"
        ctx.finding_counter[0] += 1
        all_findings.append(f)

    for analyzer in analyzers:
        # Feed accumulated findings to meta analyzer
        if analyzer.name == "meta":
            ctx.previous_findings = list(all_findings)

        findings = analyzer.analyze(ctx)

        # Assign globally-unique IDs. Each analyzer's ``make_finding``
        # helper numbers findings from ``plugin-1`` against its own local
        # list, so without renumbering here multiple analyzers collide on
        # the same ``plugin-N`` id (F-0364). Renumber every finding from
        # the shared monotonic counter so ids are unique across the merged
        # result set.
        for f in findings:
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


def _safe_read_manifest(candidate: str, scan_root: str) -> dict | None:
    """Read and JSON-parse a manifest candidate without following symlinks.

    A third-party plugin can ship a manifest-named path (``package.json``,
    ``.codex-plugin/plugin.json`` …) that is actually a symlink to an
    arbitrary host file. A plain ``open()`` follows it and copies outside
    file contents into manifest metadata (and downstream finding
    evidence) — arbitrary file read (F-0361). We:

      * require the realpath of the candidate to stay inside the plugin
        root (blocks ``..``/symlink escapes via intermediate components);
      * reject a symlinked final component outright (``lstat``);
      * open with ``O_NOFOLLOW`` so a final-component symlink that races
        in between the checks and the open also fails.

    Returns the parsed dict, or ``None`` if the candidate is missing,
    unsafe, unreadable, or not a JSON object.
    """
    try:
        real = os.path.realpath(candidate)
    except OSError:
        return None
    if real != scan_root and not real.startswith(scan_root + os.sep):
        return None
    try:
        st = os.lstat(candidate)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        # Symlinks (S_ISLNK), directories, fifos, devices, etc. are not
        # acceptable manifests.
        return None

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open(candidate, flags)
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            return None
        with os.fdopen(fd, encoding="utf-8") as fh:
            fd = -1  # ownership transferred to the file object
            raw_text = fh.read()
    except OSError:
        return None
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass

    try:
        data = json.loads(raw_text)
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _manifest_permissions(raw: dict) -> list[str]:
    """Union of declared permissions from a single manifest dict.

    Includes both the top-level ``permissions`` list and a nested
    ``defenseclaw.permissions`` list so the strictest declared set is
    considered (F-0241) and when merging across manifests. Order is
    first-seen; duplicates are dropped so the returned list is stable and
    free of redundant entries for downstream consumers.
    """
    perms: list[str] = []
    seen: set[str] = set()

    def _add(values: object) -> None:
        if not isinstance(values, list):
            return
        for p in values:
            if isinstance(p, str) and p not in seen:
                seen.add(p)
                perms.append(p)

    _add(raw.get("permissions"))
    dc = raw.get("defenseclaw")
    if isinstance(dc, dict):
        _add(dc.get("permissions"))
    return perms


def _manifest_entrypoints(raw: dict) -> list[str]:
    """Declared runtime entrypoints from a single manifest dict.

    Covers npm ``main`` and ``bin`` (string or name->path map) plus
    connector-manifest ``entrypoint``/``entry`` fields. These are the
    files that actually execute, so they must be force-scanned even when
    extensionless or under a normally-skipped directory.
    """
    eps: list[str] = []
    main = raw.get("main")
    if isinstance(main, str) and main.strip():
        eps.append(main)
    bin_field = raw.get("bin")
    if isinstance(bin_field, str) and bin_field.strip():
        eps.append(bin_field)
    elif isinstance(bin_field, dict):
        for value in bin_field.values():
            if isinstance(value, str) and value.strip():
                eps.append(value)
    for key in ("entrypoint", "entry"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            eps.append(value)
    return eps


def _load_manifest(directory: str) -> PluginManifest | None:
    scan_root = os.path.realpath(directory)

    parsed: list[tuple[dict, str]] = []
    for rel_path, source_label in _MANIFEST_CANDIDATES:
        candidate = os.path.join(directory, rel_path)
        raw = _safe_read_manifest(candidate, scan_root)
        if raw is None:
            continue
        parsed.append((raw, source_label))

    if not parsed:
        return None

    primary_raw, primary_label = parsed[0]
    manifest = _normalize_manifest(primary_raw, primary_label)

    # When multiple candidate manifests are present, the primary (per
    # _MANIFEST_CANDIDATES ordering, normally package.json) still defines
    # identity/metadata, but a benign primary must NOT shadow the
    # security-relevant declarations of a connector-specific manifest
    # (F-0362). Union the declared permissions, tools, and entrypoints
    # across ALL present manifests so the stricter set is always checked.
    if len(parsed) > 1:
        _merge_declared_capabilities(manifest, parsed)

    return manifest


def _merge_declared_capabilities(
    manifest: PluginManifest,
    parsed: list[tuple[dict, str]],
) -> None:
    merged_perms: list[str] = []
    seen_perms: set[str] = set()
    merged_tools: list[dict] = []
    merged_entrypoints: list[str] = []
    seen_entrypoints: set[str] = set()

    for raw, _label in parsed:
        for perm in _manifest_permissions(raw):
            if perm not in seen_perms:
                seen_perms.add(perm)
                merged_perms.append(perm)
        tools = raw.get("tools")
        if isinstance(tools, list):
            merged_tools.extend(t for t in tools if isinstance(t, dict))
        for ep in _manifest_entrypoints(raw):
            if ep not in seen_entrypoints:
                seen_entrypoints.add(ep)
                merged_entrypoints.append(ep)

    if merged_perms:
        manifest.permissions = merged_perms
    if merged_tools:
        manifest.tools = merged_tools
    if merged_entrypoints:
        manifest.entrypoints = merged_entrypoints


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

    # F-0241: UNION the top-level ``permissions`` list with any nested
    # ``defenseclaw.permissions`` list rather than letting the nested block
    # REPLACE the top-level one. A malicious manifest could otherwise hide a
    # dangerous top-level permission (e.g. ``fs:*``) behind an empty/benign
    # nested ``defenseclaw.permissions`` and dodge the permission checks.
    # ``_manifest_permissions`` already unions both sources and de-dups while
    # preserving first-seen ordering, which is what downstream consumers
    # (check_permissions, _merge_declared_capabilities) expect.
    merged_perms = _manifest_permissions(raw)
    if merged_perms:
        manifest.permissions = merged_perms

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

    entrypoints = _manifest_entrypoints(raw)
    if entrypoints:
        manifest.entrypoints = entrypoints

    return manifest
