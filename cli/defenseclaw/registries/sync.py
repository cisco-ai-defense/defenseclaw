# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Registry sync pipeline.

The sync command stitches three concerns together:

1. **Ingest** — call the appropriate adapter to fetch + parse the
   manifest, with SSRF / size guards already applied.
2. **Cache** — persist the parsed manifest + per-entry placeholders to
   ``~/.defenseclaw/registries/<id>/index.json`` so the TUI and
   ``registry entries`` can render fast without re-fetching.
3. **Promote** — for each entry that passes scanning (or that the
   operator has manually approved), append a matching
   :class:`AssetPolicyRule` to ``asset_policy.{skill,mcp}.registry``
   with ``Reason="registry:<id>"`` so admission can attribute the rule
   back to its source. Manual operator overrides
   (``approved`` / ``rejected``) win over scanner verdict.

The scanning step is **optional and pluggable**. The default
implementation (in this module) only runs scanners when
``scan_callback`` is provided, leaving status=``pending`` otherwise.
This keeps unit tests fast and lets the CLI inject a real scanner
factory without coupling the package to the heavy SDK dependencies.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from defenseclaw.config import (
    AssetPolicyRule,
    Config,
    RegistrySource,
)
from defenseclaw.registries.adapters import IngestError, fetch_manifest
from defenseclaw.registries.cache import (
    EntryVerdict,
    SourceIndex,
    load_index,
    merge_manifest_into_index,
    save_index,
    save_manifest,
)
from defenseclaw.registries.manifest import (
    Manifest,
    ManifestEntry,
    ManifestError,
)

if TYPE_CHECKING:
    from defenseclaw.models import ScanResult


# Severity rank — entries with HIGH or worse are blocked, MEDIUM is
# treated as a warning that the operator must explicitly approve, LOW
# / INFO findings are treated as clean. This matches the existing
# scanner default policy in ``cli/defenseclaw/scanner/skill.py``.
_BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}
_WARNING_SEVERITIES = {"MEDIUM"}


ScanCallback = Callable[[RegistrySource, ManifestEntry], "ScanResult | None"]
"""Callable that runs the appropriate scanner on a single manifest entry.

Returns ``None`` to mark the entry as ``status="pending"`` (e.g. when
the scanner can't run because the operator hasn't installed the heavy
SDKs yet, or when the source is metadata-only). Otherwise returns a
:class:`defenseclaw.models.ScanResult` whose findings drive the
verdict transition.

Tests can pass in a stub callback to exercise the full pipeline
without spawning a scanner subprocess.
"""


@dataclass
class SyncReport:
    """Result of a single ``registry sync`` run."""

    source_id: str = ""
    fetched: int = 0
    scanned: int = 0
    promoted_skills: int = 0
    promoted_mcps: int = 0
    blocked: int = 0
    warnings: int = 0
    errors: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "fetched": self.fetched,
            "scanned": self.scanned,
            "promoted_skills": self.promoted_skills,
            "promoted_mcps": self.promoted_mcps,
            "blocked": self.blocked,
            "warnings": self.warnings,
            "errors": list(self.errors),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "ok": self.ok(),
        }


def sync_source(
    cfg: Config,
    data_dir: str,
    source: RegistrySource,
    *,
    scan_callback: ScanCallback | None = None,
    allow_private: bool = False,
    auto_promote: bool = True,
    save: bool = True,
) -> SyncReport:
    """Sync a single :class:`RegistrySource`.

    Args:
        cfg: live :class:`Config`. Mutated in-place — promoted entries
            are appended to ``cfg.asset_policy.{skill,mcp}.registry``
            and ``source.last_sync`` / ``source.last_status`` are
            updated. The caller is responsible for persisting the
            mutated config (or pass ``save=True`` for the standard
            atomic-write flow).
        data_dir: ``cfg.data_dir`` — kept as a separate argument so
            unit tests can point at a tmp dir without copying the
            entire config.
        source: the source to sync. Must already exist in
            ``cfg.registries.sources``.
        scan_callback: optional callback that runs the appropriate
            scanner on each :class:`ManifestEntry`. See
            :data:`ScanCallback`.
        allow_private: when True, the SSRF guard accepts RFC1918 / ULA
            destinations. Operators opt in explicitly via
            ``--allow-private``.
        auto_promote: when True, clean entries are appended to
            ``asset_policy.{skill,mcp}.registry``. Set to False for a
            preview ("scan only, don't touch policy") flow.
        save: when True, :func:`defenseclaw.config.save_config` is
            called at the end. Tests can disable this and inspect the
            mutated config object directly.

    Returns:
        :class:`SyncReport` — never raises. Errors are collected on
        ``report.errors`` so a flaky source doesn't break a multi-source
        ``sync --all`` run.
    """
    report = SyncReport(source_id=source.id, started_at=_now_iso())

    if not source.id:
        report.errors.append("source has no id")
        report.finished_at = _now_iso()
        return report

    try:
        manifest, raw = fetch_manifest(source, allow_private=allow_private)
    except (IngestError, ManifestError) as exc:
        report.errors.append(f"fetch failed: {exc}")
        source.last_status = f"error: {exc}"[:240]
        source.last_sync = report.started_at
        report.finished_at = _now_iso()
        if save:
            cfg.save()
        return report

    save_manifest(data_dir, source.id, raw)

    # Honour the operator's declared content type before anything else
    # touches the manifest. Adapters that publish a single type
    # (clawhub / smithery / skills_sh) ignore the field by convention,
    # but for mixed manifests (http_*, git, file) declaring
    # ``content: skill`` MUST prevent MCP entries from being scanned,
    # cached, or promoted into ``asset_policy.mcp.registry``. Filtering
    # at this single point keeps the rest of the pipeline content-
    # agnostic and avoids parallel filter logic in scan / promote.
    filtered = manifest.filter_by_content(source.content)
    manifest = Manifest(
        schema_version=manifest.schema_version,
        generated_at=manifest.generated_at,
        publisher=manifest.publisher,
        default_connector=manifest.default_connector,
        entries=filtered,
    )
    report.fetched = len(manifest.entries)

    idx = load_index(data_dir, source.id)
    idx.fetched_at = report.started_at
    idx = merge_manifest_into_index(idx, manifest)

    if scan_callback is not None:
        _run_scans(source, manifest, idx, scan_callback, report)
    save_index(data_dir, source.id, idx)

    if auto_promote:
        promoted_skills, promoted_mcps = _promote_to_asset_policy(
            cfg, source, manifest, idx,
        )
        report.promoted_skills = promoted_skills
        report.promoted_mcps = promoted_mcps

    source.last_sync = report.started_at
    source.last_status = "ok" if not report.errors else f"error: {report.errors[0]}"[:240]

    report.blocked = sum(1 for v in idx.verdicts if v.status == "blocked")
    report.warnings = sum(1 for v in idx.verdicts if v.status == "warning")
    report.finished_at = _now_iso()

    if save:
        cfg.save()
    return report


def sync_all(
    cfg: Config,
    data_dir: str,
    *,
    scan_callback: ScanCallback | None = None,
    allow_private: bool = False,
    auto_promote: bool = True,
    only: Iterable[str] | None = None,
    include_disabled: bool = False,
) -> list[SyncReport]:
    """Sync every enabled :class:`RegistrySource`.

    Args:
        only: optional iterable of source ids to restrict the run to.
            Useful for the TUI's "sync this source" action.
        include_disabled: when True, disabled sources are synced too
            (matches ``--all-including-disabled`` on the CLI).

    Returns:
        One :class:`SyncReport` per source, in config order.
    """
    only_set = set(only) if only is not None else None
    reports: list[SyncReport] = []
    for source in cfg.registries.sources:
        if only_set is not None and source.id not in only_set:
            continue
        if not source.enabled and not include_disabled:
            continue
        report = sync_source(
            cfg,
            data_dir,
            source,
            scan_callback=scan_callback,
            allow_private=allow_private,
            auto_promote=auto_promote,
            save=False,  # save once at the end of the loop
        )
        reports.append(report)
    cfg.save()
    return reports


# ---------------------------------------------------------------------------
# Scan + promotion helpers
# ---------------------------------------------------------------------------

def _run_scans(
    source: RegistrySource,
    manifest: Manifest,
    idx: SourceIndex,
    scan_callback: ScanCallback,
    report: SyncReport,
) -> None:
    for entry in manifest.entries:
        verdict = idx.find(entry.type, entry.name)
        if verdict is None:
            continue
        if verdict.rejected:
            verdict.status = "blocked"
            continue
        try:
            scan_result = scan_callback(source, entry)
        except Exception as exc:  # noqa: BLE001 - keep the loop alive
            verdict.status = "error"
            verdict.error = str(exc)[:240]
            report.errors.append(f"scan({entry.type}:{entry.name}): {exc}")
            continue
        report.scanned += 1
        if scan_result is None:
            verdict.status = "pending"
            continue
        verdict.scan_id = getattr(scan_result, "scan_id", "") or ""
        verdict.target = scan_result.target
        verdict.findings = len(scan_result.findings)
        verdict.last_scanned_at = _now_iso()
        verdict.severity = scan_result.max_severity()
        verdict.error = ""
        if scan_result.is_clean():
            verdict.status = "clean"
        elif verdict.severity in _BLOCKING_SEVERITIES:
            verdict.status = "blocked"
        elif verdict.severity in _WARNING_SEVERITIES:
            verdict.status = "warning"
        else:
            verdict.status = "clean"


def _promote_to_asset_policy(
    cfg: Config,
    source: RegistrySource,
    manifest: Manifest,
    idx: SourceIndex,
) -> tuple[int, int]:
    """Append rules for clean / approved entries to asset_policy.

    Returns ``(promoted_skill_count, promoted_mcp_count)``.

    Behaviour:

    * Existing rules with the same ``Reason="registry:<id>"`` for this
      source are wiped first so a remove-from-manifest cleanly removes
      the rule.
    * Skills are matched by ``name``; MCPs by ``(name, command,
      args_prefix, transport)`` so two servers that differ only in
      args produce distinct rules.
    * Operator-rejected entries are NEVER promoted, even if the scanner
      reports clean.
    * Operator-approved entries ARE promoted, even if the scanner
      hasn't run yet.
    """
    reason = f"registry:{source.id}"

    # Wipe stale rules whose Reason matches this source so we re-emit a
    # fresh set in lockstep with the current manifest. Rules from other
    # sources / manual rules are preserved.
    cfg.asset_policy.skill.registry = [
        r for r in cfg.asset_policy.skill.registry if r.reason != reason
    ]
    cfg.asset_policy.mcp.registry = [
        r for r in cfg.asset_policy.mcp.registry if r.reason != reason
    ]

    promoted_skills = 0
    promoted_mcps = 0

    for entry in manifest.entries:
        verdict = idx.find(entry.type, entry.name)
        if verdict is None:
            continue
        # Operator overrides. ``approved`` always wins over the scanner;
        # ``rejected`` always loses.
        if verdict.rejected:
            continue
        if not verdict.approved:
            if verdict.status not in ("clean",):
                continue
        if entry.is_skill():
            cfg.asset_policy.skill.registry.append(AssetPolicyRule(
                name=entry.name,
                connector=entry.connector,
                reason=reason,
                url=entry.source_url,
            ))
            promoted_skills += 1
        elif entry.is_mcp():
            cfg.asset_policy.mcp.registry.append(AssetPolicyRule(
                name=entry.name,
                connector=entry.connector,
                reason=reason,
                url=entry.url,
                command=entry.command,
                args_prefix=list(entry.args),
                transport=entry.transport,
            ))
            promoted_mcps += 1
    return promoted_skills, promoted_mcps


def manual_set_verdict(
    data_dir: str,
    source_id: str,
    entry_type: str,
    name: str,
    *,
    approved: bool | None = None,
    rejected: bool | None = None,
) -> EntryVerdict | None:
    """Apply an operator approve/reject decision to a cached verdict.

    Returns the updated :class:`EntryVerdict` (or ``None`` if the
    entry is not in the cache yet). The caller is responsible for
    re-running :func:`promote_from_cache` (or :func:`sync_source`)
    so the decision is reflected in ``asset_policy``; this helper
    only persists the bit on disk.
    """
    idx = load_index(data_dir, source_id)
    verdict = idx.find(entry_type, name)
    if verdict is None:
        return None
    if approved is not None:
        verdict.approved = approved
        if approved:
            verdict.rejected = False
    if rejected is not None:
        verdict.rejected = rejected
        if rejected:
            verdict.approved = False
    save_index(data_dir, source_id, idx)
    return verdict


def promote_from_cache(
    cfg: Config,
    data_dir: str,
    source: RegistrySource,
    *,
    save: bool = True,
) -> tuple[int, int] | None:
    """Re-run promotion against the cached manifest.

    Used by ``registry approve`` / ``registry reject`` so an operator
    flipping a bit doesn't pay a network round-trip and — more
    importantly — doesn't silently lose the promotion when the
    publisher is offline. The on-disk ``index.json`` already reflects
    the freshly-toggled approved/rejected flag (from
    :func:`manual_set_verdict`), so we just re-load the cached
    manifest and run :func:`_promote_to_asset_policy` against it.

    Returns ``(promoted_skills, promoted_mcps)`` on success, or
    ``None`` when there's no cached manifest yet (the caller should
    fall back to a full :func:`sync_source` in that case).
    """
    # Local import keeps cache.py free of a sync import cycle.
    from defenseclaw.registries.cache import load_cached_manifest

    manifest = load_cached_manifest(data_dir, source.id)
    if manifest is None:
        return None
    # Honour the same content filter sync_source applies so an
    # approve doesn't accidentally promote an MCP entry the operator
    # never wanted by setting content="skill".
    filtered = manifest.filter_by_content(source.content)
    manifest = Manifest(
        schema_version=manifest.schema_version,
        generated_at=manifest.generated_at,
        publisher=manifest.publisher,
        default_connector=manifest.default_connector,
        entries=filtered,
    )
    idx = load_index(data_dir, source.id)
    promoted_skills, promoted_mcps = _promote_to_asset_policy(
        cfg, source, manifest, idx,
    )
    if save:
        cfg.save()
    return promoted_skills, promoted_mcps


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
