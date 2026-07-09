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

"""Refresh user-seeded bundle copies from the wheel/repo source.

Both the local Splunk bridge (``~/.defenseclaw/splunk-bridge/``) and the
local observability stack (``~/.defenseclaw/observability-stack/``) are
seeded by ``defenseclaw init`` and *never* refreshed by it on a re-run
(``init`` preserves the seeded copy so operator edits survive). That
historically meant new bundle code shipped in the wheel — the v0.130
``s3_exporter/`` sidecar, a fix to ``compose/docker-compose.local.yml``,
a new dashboard — sat unused on disk forever.

This module is the explicit, opt-out path for picking those up:

* :func:`refresh_splunk_bridge` does an rsync-style overwrite of the
  whole bridge, preserving only operator-secret files (``env/.env``)
  and regenerated artefacts (``splunk/build/``). The Splunk bundle is
  overwhelmingly maintainer-owned (compose, bin, app source,
  ``s3_exporter/``); the only operator-overrideable Splunk runtime
  state lives inside the persistent ``splunk_etc`` Docker volume,
  which we never touch.

* :func:`refresh_local_observability_stack` refreshes maintainer-owned
  files (``bin/``, ``run.sh``, ``docker-compose.yml``) by default and
  preserves operator-editable surfaces (Grafana dashboards, Prometheus
  rules, Loki/Tempo/OTel-Collector configs). Pass
  ``refresh_config=True`` for a wholesale refresh — that's destructive
  to operator dashboard edits and so is opt-in.

* :func:`is_compose_project_running` uses ``docker ps`` labels to spot
  a running stack so callers can stop → refresh → restart in one
  motion.

All refresh writes go through a tmp dir + ``os.replace`` so a crash
midway through a copy can't leave the seeded copy half-overwritten.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import yaml

from defenseclaw.paths import (
    bundled_local_observability_dir,
    bundled_splunk_bridge_dir,
)

# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------


@dataclass
class RefreshResult:
    """Outcome of a single refresh + (optional) restart cycle.

    All paths are stored as the relative-to-bundle-root strings the
    caller passed in (e.g. ``"compose/docker-compose.local.yml"``) so
    they render cleanly in CLI status output.
    """

    bundle_kind: str
    seeded_dest: str
    bundle_source: str
    refreshed: bool = False
    refreshed_paths: list[str] = field(default_factory=list)
    preserved_paths: list[str] = field(default_factory=list)
    skipped_reason: str | None = None
    was_running: bool = False
    stopped: bool = False
    restarted: bool = False
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class LocalObservabilityUpgradeResult:
    """Serializable result of the fail-closed upgrade refresh transaction."""

    installed: bool
    refreshed: bool = False
    was_running: bool = False
    stopped: bool = False
    restart_required: bool = False
    restarted: bool = False
    managed_paths: tuple[str, ...] = ()
    changed_paths: tuple[str, ...] = ()
    conflict_paths: tuple[str, ...] = ()
    preserved_custom_paths: tuple[str, ...] = ()
    named_volumes: tuple[str, ...] = ()
    manifest_sha256: str | None = None
    degraded_errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "installed": self.installed,
            "refreshed": self.refreshed,
            "was_running": self.was_running,
            "stopped": self.stopped,
            "restart_required": self.restart_required,
            "restarted": self.restarted,
            "managed_paths": list(self.managed_paths),
            "changed_paths": list(self.changed_paths),
            "conflict_paths": list(self.conflict_paths),
            "preserved_custom_paths": list(self.preserved_custom_paths),
            "named_volumes": list(self.named_volumes),
            "manifest_sha256": self.manifest_sha256,
            "degraded_errors": list(self.degraded_errors),
        }


class LocalObservabilityUpgradeError(RuntimeError):
    """Value-safe failure raised before the upgraded services may restart."""

    def __init__(self, code: str, phase: str) -> None:
        self.code = code
        self.phase = phase
        super().__init__(f"local observability bundle upgrade failed ({code}, {phase})")


class _WindowsSecuritySnapshot(Protocol):
    owner: bytes
    dacl: bytes
    dacl_protected: bool
    mandatory_label: bytes | None
    sacl_protected: bool


# ---------------------------------------------------------------------------
# Splunk bridge refresh
# ---------------------------------------------------------------------------


# Files inside ``~/.defenseclaw/splunk-bridge/`` that the refresh must
# never overwrite. ``env/.env`` carries the operator's SPLUNK_PASSWORD
# (and any AWS creds for the s3_exporter sidecar), and ``splunk/build/``
# is the generated tarball that ``package_local_mode_app.sh`` rebuilds
# every ``up`` so there is no point in ferrying it across.
_SPLUNK_BRIDGE_PRESERVE: tuple[str, ...] = (
    "env/.env",
    "splunk/build",
)

_SPLUNK_BRIDGE_DEST_REL: str = "splunk-bridge"


def refresh_splunk_bridge(data_dir: str) -> RefreshResult:
    """Refresh ``~/.defenseclaw/splunk-bridge/`` from the bundled source.

    Returns a :class:`RefreshResult` describing what changed. Never
    raises for missing source / missing dest — the result captures
    those as a ``skipped_reason`` so the CLI can render a soft
    warning instead of crashing the setup flow.
    """
    bundle = bundled_splunk_bridge_dir()
    dest = os.path.join(data_dir, _SPLUNK_BRIDGE_DEST_REL)
    result = RefreshResult(
        bundle_kind="splunk-bridge",
        seeded_dest=dest,
        bundle_source=str(bundle),
    )

    if not bundle.is_dir():
        result.skipped_reason = f"bundled source missing ({bundle})"
        return result

    if not os.path.isdir(dest):
        # No prior seed — fall back to a plain copytree. Keeps the
        # refresh path safe to call before ``init`` has run.
        try:
            shutil.copytree(str(bundle), dest)
        except OSError as exc:
            result.errors.append(f"initial seed: {exc}")
            return result
        bridge_bin = os.path.join(dest, "bin", "splunk-claw-bridge")
        if os.path.isfile(bridge_bin):
            try:
                os.chmod(bridge_bin, 0o755)
            except OSError as exc:
                result.errors.append(f"chmod splunk-claw-bridge: {exc}")
        result.refreshed = True
        result.refreshed_paths.append("(initial seed)")
        return result

    refreshed, preserved, errors = _rsync_overwrite(
        src=Path(bundle),
        dest=Path(dest),
        preserve=_SPLUNK_BRIDGE_PRESERVE,
    )
    result.refreshed_paths = refreshed
    result.preserved_paths = preserved
    result.errors = errors
    result.refreshed = bool(refreshed)

    bridge_bin = os.path.join(dest, "bin", "splunk-claw-bridge")
    if os.path.isfile(bridge_bin):
        try:
            os.chmod(bridge_bin, 0o755)
        except OSError as exc:
            result.errors.append(f"chmod splunk-claw-bridge: {exc}")

    return result


# ---------------------------------------------------------------------------
# Local observability stack refresh
# ---------------------------------------------------------------------------


# Operator-editable surfaces — preserved unless the caller passes
# ``refresh_config=True``. Each entry is a relative path inside
# ``~/.defenseclaw/observability-stack/`` and may be a file or a
# directory; ``_rsync_overwrite`` treats both correctly.
_LOCAL_OBSERVABILITY_OPERATOR_PATHS: tuple[str, ...] = (
    "grafana",
    "prometheus",
    "loki",
    "tempo",
    "otel-collector",
)

# Maintainer-owned files removed from newer bundles.  The rsync-style refresh
# intentionally preserves arbitrary destination-only files so operator-created
# dashboards survive upgrades; explicit tombstones let us remove only retired
# DefenseClaw assets without turning refresh into a destructive directory
# mirror.
_LOCAL_OBSERVABILITY_RETIRED_PATHS: tuple[str, ...] = ("grafana/dashboards/defenseclaw-reliability.json",)
_LOCAL_OBSERVABILITY_RETIRED_SHA256: dict[str, frozenset[str]] = {
    "grafana/dashboards/defenseclaw-reliability.json": frozenset(
        {
            "4993c6ca65313823a410df84778531c377eec217b2947f2e78d083b18437aae5",
            "ba845c3ced38a69b6a6d175a88227c4887556731ba7c77fa4f3efa880cbe5443",
            "c39b8d1e45726c2016e6622bdc4234ff3d5bbfbc683f0283106f026eab245d26",
        }
    ),
}

_LOCAL_OBSERVABILITY_DEST_REL: str = "observability-stack"
_LOCAL_OBSERVABILITY_MANIFEST = ".defenseclaw-bundle-manifest.json"
_LOCAL_OBSERVABILITY_RESTART_INTENT = "restart-intent.json"
_LOCAL_OBSERVABILITY_MANIFEST_SCHEMA = 1
_MAX_BUNDLE_ROLLBACK_METADATA_BYTES = 4 * 1024 * 1024
_LOCAL_OBSERVABILITY_REQUIRED_FILES: tuple[str, ...] = (
    "bin/openclaw-observability-bridge",
    "docker-compose.yml",
    "grafana/provisioning/dashboards/dashboards.yml",
    "grafana/provisioning/datasources/datasources.yml",
    "loki/loki.yaml",
    "otel-collector/config.yaml",
    "prometheus/prometheus.yml",
    "prometheus/rules/alerts.yml",
    "prometheus/rules/recording.yml",
    "run.sh",
    "tempo/tempo.yaml",
)
_LOCAL_OBSERVABILITY_SERVICES: tuple[str, ...] = (
    "otel-collector",
    "prometheus",
    "loki",
    "tempo",
    "grafana",
)
_LOCAL_OBSERVABILITY_NAMED_VOLUMES: tuple[str, ...] = (
    "grafana-data",
    "loki-data",
    "prometheus-data",
    "tempo-data",
)
_LOCAL_OBSERVABILITY_DASHBOARD_UIDS: tuple[str, ...] = (
    "defenseclaw-activity",
    "defenseclaw-agent-360",
    "defenseclaw-agent-identity",
    "defenseclaw-ai-discovery",
    "defenseclaw-connector-detail",
    "defenseclaw-connectors",
    "defenseclaw-findings",
    "defenseclaw-hitl",
    "defenseclaw-overview",
    "defenseclaw-policy-decisions",
    "defenseclaw-runtime",
    "defenseclaw-scanners",
    "defenseclaw-security",
    "defenseclaw-traffic",
)


@dataclass(frozen=True)
class _BundleFile:
    path: str
    sha256: str
    size: int
    mode: int


@dataclass(frozen=True)
class _BundleManifest:
    bundle_version: str
    files: tuple[_BundleFile, ...]
    dashboard_uids: tuple[str, ...]
    named_volumes: tuple[str, ...]
    raw: bytes
    sha256: str


def refresh_local_observability_stack(
    data_dir: str,
    *,
    refresh_config: bool = False,
) -> RefreshResult:
    """Refresh ``~/.defenseclaw/observability-stack/`` from the bundle.

    By default we refresh maintainer-owned files (``bin/``, ``run.sh``,
    ``docker-compose.yml``) and preserve every operator-editable
    surface listed in :data:`_LOCAL_OBSERVABILITY_OPERATOR_PATHS`. Set
    ``refresh_config=True`` to also overwrite those — destructive to
    Grafana dashboard / Prometheus rule edits, hence opt-in.
    """
    bundle = bundled_local_observability_dir()
    dest = os.path.join(data_dir, _LOCAL_OBSERVABILITY_DEST_REL)
    result = RefreshResult(
        bundle_kind="observability-stack",
        seeded_dest=dest,
        bundle_source=str(bundle),
    )

    try:
        _assert_safe_bundle_destination(Path(data_dir), Path(dest))
    except OSError as exc:
        result.errors.append(f"unsafe observability destination: {exc}")
        return result

    if not bundle.is_dir():
        result.skipped_reason = f"bundled source missing ({bundle})"
        return result

    if not os.path.isdir(dest):
        try:
            Path(dest).mkdir(parents=False)
        except OSError as exc:
            result.errors.append(f"initial seed: {exc}")
            return result
        refreshed, _preserved, errors = _rsync_overwrite(
            src=Path(bundle),
            dest=Path(dest),
            preserve=(),
        )
        result.errors.extend(errors)
        if errors:
            return result
        result.errors.extend(
            _ensure_local_observability_container_access(
                Path(dest), Path(bundle), include_operator_custom=True,
            )
        )
        result.refreshed = True
        result.refreshed_paths.extend(refreshed or ["(initial seed)"])
        return result

    preserve: tuple[str, ...] = ()
    if not refresh_config:
        preserve = _LOCAL_OBSERVABILITY_OPERATOR_PATHS

    refreshed, preserved, errors = _rsync_overwrite(
        src=Path(bundle),
        dest=Path(dest),
        preserve=preserve,
    )
    result.refreshed_paths = refreshed
    result.preserved_paths = preserved
    result.errors = errors
    result.refreshed = bool(refreshed)

    if refresh_config:
        removed, removal_errors = _remove_retired_paths(
            Path(dest),
            _LOCAL_OBSERVABILITY_RETIRED_PATHS,
        )
        result.refreshed_paths.extend(f"{path} (removed)" for path in removed)
        result.errors.extend(removal_errors)
        result.refreshed = bool(result.refreshed_paths)

    result.errors.extend(
        _ensure_local_observability_container_access(
            Path(dest), Path(bundle), include_operator_custom=True,
        )
    )
    return result


def upgrade_local_observability_stack(
    data_dir: str,
    backup_dir: str,
    *,
    bundle_version: str,
    fault_injector: Callable[[str, str | None], None] | None = None,
) -> LocalObservabilityUpgradeResult:
    """Safely refresh an installed local-observability stack during upgrade.

    Unlike the interactive setup refresher, this path is an all-or-rollback
    transaction over the complete DefenseClaw-owned file set. Destination-only
    files are never removed, and Docker named volumes are never copied, reset,
    or passed to ``compose down -v``.
    """

    data_root = Path(data_dir).expanduser().absolute()
    destination = data_root / _LOCAL_OBSERVABILITY_DEST_REL
    if not destination.exists() and not destination.is_symlink():
        return LocalObservabilityUpgradeResult(installed=False)
    if destination.is_symlink() or not destination.is_dir():
        raise LocalObservabilityUpgradeError("unsafe_install_root", "preflight")

    source = bundled_local_observability_dir().absolute()
    target = _build_local_observability_manifest(source, bundle_version)
    prior = _read_installed_bundle_manifest(destination)
    managed_retired = _managed_retired_paths(destination)
    _preflight_upgrade_destination(destination, target, managed_retired)

    was_running = _strict_compose_project_running(LOCAL_OBSERVABILITY_COMPOSE_PROJECT)
    bridge = destination / "bin" / "openclaw-observability-bridge"
    if was_running:
        _require_regular_file(destination, bridge, "bridge")
    backup_root = _prepare_local_observability_backup_custody(
        Path(backup_dir).expanduser().absolute(),
        target_manifest_sha256=target.sha256,
        restart_required=was_running,
    )
    if fault_injector:
        try:
            fault_injector("after_restart_intent", None)
        except Exception as exc:
            raise LocalObservabilityUpgradeError("backup_failed", "backup") from exc

    stopped = False
    if was_running:
        try:
            completed = subprocess.run(
                [str(bridge), "down"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise LocalObservabilityUpgradeError("stack_stop_failed", "stop") from exc
        if completed.returncode != 0:
            raise LocalObservabilityUpgradeError("stack_stop_failed", "stop")
        if _strict_compose_project_running(LOCAL_OBSERVABILITY_COMPOSE_PROJECT):
            raise LocalObservabilityUpgradeError("stack_still_running", "stop")
        stopped = True
    if fault_injector:
        try:
            fault_injector("after_stop", None)
        except Exception as exc:
            raise LocalObservabilityUpgradeError("backup_failed", "backup") from exc

    return _activate_local_observability_manifest(
        source,
        destination,
        backup_root,
        target,
        prior,
        managed_retired,
        was_running=was_running,
        stopped=stopped,
        fault_injector=fault_injector,
    )


def _prepare_local_observability_backup_custody(
    backup_dir: Path,
    *,
    target_manifest_sha256: str,
    restart_required: bool,
) -> Path:
    """Commit exact restart intent before the stack can be stopped.

    Constructing the complete managed-file rollback descriptor is fallible:
    every retained member must be copied and authenticated. This smaller
    record gives the bridge durable authority to restore only the source
    running state if the child fails before publishing that descriptor. No
    bundle path may be mutated while only this intent exists.
    """

    backup_root = backup_dir / "local-observability-stack"
    try:
        if backup_dir.is_symlink() or (backup_dir.exists() and not backup_dir.is_dir()):
            raise LocalObservabilityUpgradeError("unsafe_backup_root", "backup")
        if not backup_dir.exists():
            _mkdir_private(backup_dir)
            _fsync_directory(backup_dir.parent)
        if backup_root.exists() or backup_root.is_symlink():
            raise LocalObservabilityUpgradeError("backup_collision", "backup")
        _mkdir_private(backup_root)
        _fsync_directory(backup_dir)
        intent = {
            "schema_version": 1,
            "target_manifest_sha256": target_manifest_sha256,
            "restart_required": restart_required,
        }
        _atomic_write_bytes(
            backup_root / _LOCAL_OBSERVABILITY_RESTART_INTENT,
            (json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            mode=0o600,
        )
    except (OSError, LocalObservabilityUpgradeError) as exc:
        if isinstance(exc, LocalObservabilityUpgradeError):
            raise
        raise LocalObservabilityUpgradeError("backup_failed", "backup") from exc
    return backup_root


def restart_upgraded_local_observability_stack(
    data_dir: str,
    *,
    timeout: int = 180,
) -> LocalObservabilityUpgradeResult:
    """Restart and smoke-check a stack stopped by the upgrade transaction.

    Restart/readiness failures are returned as degraded status because the
    bundle bytes have already been safely activated. They never trigger a
    config/gateway rollback and never reset named volumes.
    """

    destination = Path(data_dir).expanduser().absolute() / _LOCAL_OBSERVABILITY_DEST_REL
    if not destination.is_dir() or destination.is_symlink():
        return LocalObservabilityUpgradeResult(
            installed=False,
            degraded_errors=("installed_bundle_missing",),
        )
    bridge = destination / "bin" / "openclaw-observability-bridge"
    try:
        _require_regular_file(destination, bridge, "bridge")
        completed = subprocess.run(
            [str(bridge), "up", "--output", "json", "--timeout", str(timeout)],
            capture_output=True,
            text=True,
            timeout=max(timeout + 30, 60),
            check=False,
        )
    except (LocalObservabilityUpgradeError, OSError, subprocess.TimeoutExpired):
        return LocalObservabilityUpgradeResult(
            installed=True,
            restart_required=True,
            degraded_errors=("stack_restart_failed",),
        )
    if completed.returncode != 0 or not _bridge_contract_valid(completed.stdout):
        return LocalObservabilityUpgradeResult(
            installed=True,
            restart_required=True,
            degraded_errors=("stack_restart_failed",),
        )

    errors = _live_local_observability_smoke(timeout=min(max(timeout, 1), 30))
    return LocalObservabilityUpgradeResult(
        installed=True,
        restart_required=True,
        restarted=not errors,
        named_volumes=_LOCAL_OBSERVABILITY_NAMED_VOLUMES,
        degraded_errors=tuple(errors),
    )


def _build_local_observability_manifest(source: Path, bundle_version: str) -> _BundleManifest:
    if source.is_symlink() or not source.is_dir():
        raise LocalObservabilityUpgradeError("target_bundle_missing", "manifest")
    entries: list[_BundleFile] = []
    for root, dirs, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        for name in dirs:
            if (root_path / name).is_symlink():
                raise LocalObservabilityUpgradeError("target_bundle_unsafe", "manifest")
        for name in files:
            path = root_path / name
            _require_regular_file(source, path, "target")
            relative = _safe_relative_path(path.relative_to(source).as_posix())
            metadata = path.stat()
            entries.append(
                _BundleFile(
                    path=relative,
                    sha256=_sha256_file(path),
                    size=metadata.st_size,
                    # Python package installers honor the invoking umask, so
                    # resource files can arrive as 0600/0711 even though the
                    # non-root containers must read/execute them. The bundle
                    # contract owns stable deployment modes independently of
                    # how the wheel happened to be extracted.
                    mode=_canonical_local_observability_file_mode(relative),
                )
            )
    entries.sort(key=lambda item: item.path.encode("utf-8"))
    paths = {entry.path for entry in entries}
    if not set(_LOCAL_OBSERVABILITY_REQUIRED_FILES).issubset(paths):
        raise LocalObservabilityUpgradeError("target_bundle_incomplete", "manifest")

    dashboards = _validate_dashboard_inventory(source, paths)
    named_volumes = _validate_compose_inventory(source / "docker-compose.yml")
    document = {
        "schema_version": _LOCAL_OBSERVABILITY_MANIFEST_SCHEMA,
        "bundle_version": bundle_version,
        "dashboard_uids": list(dashboards),
        "named_volumes": list(named_volumes),
        "files": [
            {
                "path": entry.path,
                "sha256": entry.sha256,
                "size": entry.size,
                "mode": entry.mode,
            }
            for entry in entries
        ],
    }
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return _BundleManifest(
        bundle_version=bundle_version,
        files=tuple(entries),
        dashboard_uids=dashboards,
        named_volumes=named_volumes,
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _validate_dashboard_inventory(source: Path, paths: set[str]) -> tuple[str, ...]:
    prefix = "grafana/dashboards/"
    dashboard_paths = sorted(path for path in paths if path.startswith(prefix) and path.endswith(".json"))
    uids: list[str] = []
    for relative in dashboard_paths:
        try:
            document = json.loads((source / relative).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            raise LocalObservabilityUpgradeError("target_dashboard_invalid", "manifest") from exc
        uid = document.get("uid") if isinstance(document, dict) else None
        if not isinstance(uid, str) or not uid:
            raise LocalObservabilityUpgradeError("target_dashboard_invalid", "manifest")
        uids.append(uid)
    observed = tuple(sorted(uids))
    if observed != _LOCAL_OBSERVABILITY_DASHBOARD_UIDS:
        raise LocalObservabilityUpgradeError("target_dashboard_inventory_mismatch", "manifest")
    return observed


def _validate_compose_inventory(compose_path: Path) -> tuple[str, ...]:
    try:
        document = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise LocalObservabilityUpgradeError("target_compose_invalid", "manifest") from exc
    if not isinstance(document, dict) or document.get("name") != LOCAL_OBSERVABILITY_COMPOSE_PROJECT:
        raise LocalObservabilityUpgradeError("target_compose_invalid", "manifest")
    services = document.get("services")
    volumes = document.get("volumes")
    if not isinstance(services, dict) or not set(_LOCAL_OBSERVABILITY_SERVICES).issubset(services):
        raise LocalObservabilityUpgradeError("target_service_inventory_mismatch", "manifest")
    if not isinstance(volumes, dict):
        raise LocalObservabilityUpgradeError("target_volume_inventory_mismatch", "manifest")
    observed = tuple(sorted(str(name) for name in volumes))
    if observed != _LOCAL_OBSERVABILITY_NAMED_VOLUMES:
        raise LocalObservabilityUpgradeError("target_volume_inventory_mismatch", "manifest")
    return observed


def _read_installed_bundle_manifest(destination: Path) -> _BundleManifest | None:
    path = destination / _LOCAL_OBSERVABILITY_MANIFEST
    if not path.exists() and not path.is_symlink():
        return None
    _require_regular_file(destination, path, "installed_manifest")
    try:
        if path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("manifest is too large")
        raw = path.read_bytes()
        document = json.loads(raw)
        if not isinstance(document, dict):
            raise ValueError("manifest is not an object")
        if document.get("schema_version") != _LOCAL_OBSERVABILITY_MANIFEST_SCHEMA:
            raise ValueError("unsupported schema")
        bundle_version = document["bundle_version"]
        files_raw = document["files"]
        dashboards_raw = document["dashboard_uids"]
        volumes_raw = document["named_volumes"]
        if not isinstance(bundle_version, str) or not isinstance(files_raw, list) or len(files_raw) > 4096:
            raise ValueError("invalid manifest fields")
        files: list[_BundleFile] = []
        seen: set[str] = set()
        for item in files_raw:
            if not isinstance(item, dict) or set(item) != {"path", "sha256", "size", "mode"}:
                raise ValueError("invalid file row")
            relative = _safe_relative_path(item["path"])
            digest = item["sha256"]
            size = item["size"]
            mode = item["mode"]
            if (
                relative in seen
                or not isinstance(digest, str)
                or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
                or not isinstance(mode, int)
                or isinstance(mode, bool)
                or mode < 0
                or mode > 0o7777
            ):
                raise ValueError("invalid file row")
            seen.add(relative)
            files.append(_BundleFile(relative, digest, size, mode))
        if (
            not isinstance(dashboards_raw, list)
            or len(dashboards_raw) > 256
            or not all(isinstance(v, str) for v in dashboards_raw)
        ):
            raise ValueError("invalid dashboard inventory")
        if (
            not isinstance(volumes_raw, list)
            or len(volumes_raw) > 256
            or not all(isinstance(v, str) for v in volumes_raw)
        ):
            raise ValueError("invalid volume inventory")
        return _BundleManifest(
            bundle_version=bundle_version,
            files=tuple(files),
            dashboard_uids=tuple(dashboards_raw),
            named_volumes=tuple(volumes_raw),
            raw=raw,
            sha256=hashlib.sha256(raw).hexdigest(),
        )
    except (KeyError, OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise LocalObservabilityUpgradeError("installed_manifest_invalid", "preflight") from exc


def _managed_retired_paths(destination: Path) -> set[str]:
    """Return only retired files whose bytes match a reviewed shipped asset.

    A destination-only file at a retired DefenseClaw filename is still an
    operator file unless its digest is one of the historical bundle digests.
    This prevents a tombstone from deleting an unrelated custom dashboard.
    """

    managed: set[str] = set()
    for relative, historical_digests in _LOCAL_OBSERVABILITY_RETIRED_SHA256.items():
        path = destination / relative
        if not path.exists() or path.is_symlink():
            continue
        try:
            if stat.S_ISREG(path.lstat().st_mode) and _sha256_file(path) in historical_digests:
                managed.add(relative)
        except OSError as exc:
            raise LocalObservabilityUpgradeError("retired_path_unreadable", "preflight") from exc
    return managed


def _preflight_upgrade_destination(
    destination: Path,
    target: _BundleManifest,
    managed_retired: set[str],
) -> None:
    managed = {entry.path for entry in target.files}
    managed.update(managed_retired)
    managed.add(_LOCAL_OBSERVABILITY_MANIFEST)
    for relative in sorted(managed):
        path = destination / relative
        _validate_destination_ancestors(destination, path)
        if path.exists() or path.is_symlink():
            _require_regular_file(destination, path, "destination")


def _stage_local_observability_manifest(
    source: Path,
    destination: Path,
    target: _BundleManifest,
) -> Path:
    """Materialize every target byte before rollback authority is published."""

    stage = Path(tempfile.mkdtemp(prefix=".local-observability-stage-", dir=destination.parent))
    os.chmod(stage, 0o700)
    try:
        for entry in target.files:
            stage_path = stage / entry.path
            stage_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / entry.path, stage_path, follow_symlinks=False)
            os.chmod(stage_path, entry.mode)
            if _sha256_file(stage_path) != entry.sha256:
                raise LocalObservabilityUpgradeError("staged_digest_mismatch", "stage")
        _atomic_write_bytes(
            stage / _LOCAL_OBSERVABILITY_MANIFEST,
            target.raw,
            mode=0o600,
        )
        return stage
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _remove_local_observability_stage(stage: Path) -> None:
    shutil.rmtree(stage, ignore_errors=True)


def _serialize_windows_security(security: _WindowsSecuritySnapshot) -> dict[str, object]:
    return {
        "owner": base64.b64encode(security.owner).decode("ascii"),
        "dacl": base64.b64encode(security.dacl).decode("ascii"),
        "dacl_protected": security.dacl_protected,
        "mandatory_label": (
            base64.b64encode(security.mandatory_label).decode("ascii") if security.mandatory_label is not None else None
        ),
        "sacl_protected": security.sacl_protected,
    }


def _remove_managed_bundle_file(path: Path) -> None:
    info = _rollback_file_info(path, missing_ok=False)
    if info is None:
        raise OSError("managed bundle file disappeared before removal")
    path.unlink()
    _fsync_directory(path.parent)


def _activate_local_observability_manifest(
    source: Path,
    destination: Path,
    backup_root: Path,
    target: _BundleManifest,
    prior: _BundleManifest | None,
    managed_retired: set[str],
    *,
    was_running: bool,
    stopped: bool,
    fault_injector: Callable[[str, str | None], None] | None,
) -> LocalObservabilityUpgradeResult:
    target_by_path = {entry.path: entry for entry in target.files}
    prior_by_path = {entry.path: entry for entry in prior.files} if prior else {}
    # Never treat an installed manifest's arbitrary extra rows as deletion
    # authority. Only current target entries and reviewed tombstones are
    # DefenseClaw-managed; destination-only paths remain operator-owned.
    target_paths = set(target_by_path) | {_LOCAL_OBSERVABILITY_MANIFEST}
    candidate_managed_paths = target_paths | managed_retired
    existing_paths = {
        relative
        for relative in candidate_managed_paths
        if (destination / relative).exists()
    }
    created_paths = candidate_managed_paths - existing_paths
    managed_paths = existing_paths | created_paths
    if created_paths - target_paths:
        raise LocalObservabilityUpgradeError("retired_inventory_inconsistent", "preflight")
    backup_managed = backup_root / "managed"
    backup_created = backup_root / "created"
    backup_retired = backup_root / "retired"
    if backup_root.is_symlink() or not backup_root.is_dir():
        raise LocalObservabilityUpgradeError("unsafe_backup_root", "backup")

    changed: list[str] = []
    conflicts: list[str] = []
    custom = _destination_only_files(destination, managed_paths)
    old_sha256: dict[str, str] = {}
    old_modes: dict[str, int] = {}
    created_sha256: dict[str, str] = {}
    old_windows_security: dict[str, dict[str, object]] = {}
    old_windows_security_native: dict[str, object] = {}
    stage = _stage_local_observability_manifest(source, destination, target)
    try:
        _mkdir_private(backup_managed)
        _mkdir_private(backup_created)
        _mkdir_private(backup_retired)
        _fsync_directory_chain(backup_managed, stop=backup_root)
        _fsync_directory_chain(backup_created, stop=backup_root)
        _fsync_directory_chain(backup_retired, stop=backup_root)
        if fault_injector:
            fault_injector("before_backup", None)
        for relative in sorted(existing_paths):
            path = destination / relative
            source_before = path.lstat()
            native_security = None
            if os.name == "nt":
                from defenseclaw import windows_acl

                native_security = windows_acl.capture_path(str(path))
            backup_path = backup_managed / relative
            _mkdir_private(backup_path.parent)
            shutil.copy2(path, backup_path, follow_symlinks=False)
            os.chmod(backup_path, 0o600)
            _fsync_file(backup_path)
            _fsync_directory_chain(backup_path.parent, stop=backup_root)
            old_sha256[relative] = _sha256_file(backup_path)
            old_modes[relative] = stat.S_IMODE(source_before.st_mode)
            source_after = path.lstat()
            if (
                not _rollback_source_snapshot_unchanged(source_before, source_after)
                or _sha256_file(path) != old_sha256[relative]
            ):
                raise LocalObservabilityUpgradeError("backup_source_changed", "backup")
            if os.name == "nt":
                if native_security != windows_acl.capture_path(str(path)):
                    raise LocalObservabilityUpgradeError("backup_source_changed", "backup")
                assert native_security is not None
                old_windows_security_native[relative] = native_security
                old_windows_security[relative] = _serialize_windows_security(native_security)

            target_entry = target_by_path.get(relative)
            prior_entry = prior_by_path.get(relative)
            if target_entry is None:
                continue
            if old_sha256[relative] == target_entry.sha256:
                continue
            if prior_entry is None or old_sha256[relative] != prior_entry.sha256:
                conflicts.append(relative)

        for relative in sorted(created_paths):
            created_claim = backup_created / relative
            _mkdir_private(created_claim.parent)
            _atomic_copy_file(str(stage / relative), str(created_claim))
            _fsync_file(created_claim)
            _fsync_directory_chain(created_claim.parent, stop=backup_root)
            created_sha256[relative] = _sha256_file(created_claim)

        backup_metadata = {
            "schema_version": 2,
            "managed_paths": sorted(managed_paths),
            "existing_paths": sorted(existing_paths),
            "old_sha256": old_sha256,
            "old_modes": old_modes,
            "created_sha256": created_sha256,
            "old_windows_security": old_windows_security,
            "restart_required": was_running,
        }
        serialized_metadata = json.dumps(backup_metadata, sort_keys=True).encode("utf-8")
        if not 0 < len(serialized_metadata) <= _MAX_BUNDLE_ROLLBACK_METADATA_BYTES:
            raise LocalObservabilityUpgradeError("backup_metadata_too_large", "backup")
        _atomic_write_bytes(
            backup_root / "refresh-backup.json",
            serialized_metadata,
            mode=0o600,
        )
        if fault_injector:
            fault_injector("after_backup", None)
    except (OSError, LocalObservabilityUpgradeError) as exc:
        _remove_local_observability_stage(stage)
        if isinstance(exc, LocalObservabilityUpgradeError):
            raise
        raise LocalObservabilityUpgradeError("backup_failed", "backup") from exc

    mutation_started = False
    try:
        if fault_injector:
            fault_injector("after_stage", None)
        mutation_started = True

        for relative in sorted(existing_paths & target_paths):
            destination_path = destination / relative
            target_entry = target_by_path.get(relative)
            expected_digest = target.sha256 if target_entry is None else target_entry.sha256
            expected_mode = 0o600 if target_entry is None else target_entry.mode
            if old_sha256[relative] != expected_digest or (
                os.name == "posix" and old_modes[relative] != expected_mode
            ):
                changed.append(relative)
            if fault_injector:
                fault_injector("before_activate", relative)
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_copy_file(str(stage / relative), str(destination_path))
            if fault_injector:
                fault_injector("after_activate", relative)

        for relative in sorted(created_paths):
            created_claim = backup_created / relative
            destination_path = destination / relative
            if fault_injector:
                fault_injector("before_activate", relative)
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            os.link(created_claim, destination_path)
            _fsync_directory(destination_path.parent)
            changed.append(relative)
            if fault_injector:
                fault_injector("after_activate", relative)

        for relative in sorted(existing_paths & managed_retired):
            path = destination / relative
            if fault_injector:
                fault_injector("before_remove", relative)
            _remove_managed_bundle_file(path)
            changed.append(relative)

        access_errors = _ensure_local_observability_container_access(
            destination,
            source,
            include_operator_custom=False,
        )
        if access_errors:
            raise LocalObservabilityUpgradeError("container_access_failed", "activate")
        _verify_activated_bundle(destination, target)
        if fault_injector:
            fault_injector("after_verify", None)
    except Exception as exc:
        try:
            if mutation_started:
                _restore_local_observability_backup(
                    destination,
                    backup_managed,
                    backup_created,
                    backup_retired,
                    managed_paths,
                    existing_paths,
                    old_sha256,
                    old_modes,
                    created_sha256,
                    old_windows_security_native,
                )
        except Exception as rollback_exc:
            raise LocalObservabilityUpgradeError("rollback_failed", "rollback") from rollback_exc
        if isinstance(exc, LocalObservabilityUpgradeError):
            raise
        raise LocalObservabilityUpgradeError("activation_failed", "activate") from exc
    finally:
        _remove_local_observability_stage(stage)

    return LocalObservabilityUpgradeResult(
        installed=True,
        refreshed=bool(changed),
        was_running=was_running,
        stopped=stopped,
        restart_required=was_running,
        managed_paths=tuple(sorted(target_by_path)),
        changed_paths=tuple(changed),
        conflict_paths=tuple(sorted(conflicts)),
        preserved_custom_paths=custom,
        named_volumes=target.named_volumes,
        manifest_sha256=target.sha256,
    )


def _restore_local_observability_activation_backup(
    destination: Path,
    backup_managed: Path,
    managed_paths: set[str],
    existing_paths: set[str],
    old_digests: dict[str, str],
    old_modes: dict[str, int],
) -> None:
    """Restore the transaction's exact managed-file inventory."""

    if os.name != "posix":
        _restore_local_observability_activation_backup_by_path(
            destination,
            backup_managed,
            managed_paths,
            existing_paths,
            old_digests,
            old_modes,
        )
        return

    root_descriptor = _open_rollback_root_descriptor(destination)
    try:
        backup_root_descriptor = _open_rollback_root_descriptor(backup_managed)
        try:
            for relative in sorted(managed_paths):
                parts = _rollback_path_parts(relative)
                parent_descriptor = _open_rollback_parent(
                    root_descriptor,
                    parts[:-1],
                    create=relative in existing_paths,
                )
                if parent_descriptor is None:
                    continue
                try:
                    if relative in existing_paths:
                        backup_parent_descriptor = _open_rollback_parent(
                            backup_root_descriptor,
                            parts[:-1],
                            create=False,
                        )
                        if backup_parent_descriptor is None:
                            raise OSError("backup member missing")
                        try:
                            _restore_rollback_file_at(
                                backup_parent_descriptor,
                                parts[-1],
                                parent_descriptor,
                                parts[-1],
                                old_modes[relative],
                                old_digests[relative],
                            )
                        finally:
                            os.close(backup_parent_descriptor)
                    else:
                        _remove_rollback_file_at(parent_descriptor, parts[-1])
                finally:
                    os.close(parent_descriptor)
        finally:
            os.close(backup_root_descriptor)
    finally:
        os.close(root_descriptor)


def _restore_local_observability_activation_backup_by_path(
    destination: Path,
    backup_managed: Path,
    managed_paths: set[str],
    existing_paths: set[str],
    old_digests: dict[str, str],
    old_modes: dict[str, int],
) -> None:
    """Fail closed around symlinks and reparse points without POSIX dirfds."""

    root_chain = [(destination, _rollback_directory_info(destination))]
    backup_root_chain = [(backup_managed, _rollback_directory_info(backup_managed))]
    for relative in sorted(managed_paths):
        parts = _rollback_path_parts(relative)
        parent_chain = _open_rollback_parent_by_path(
            root_chain,
            parts[:-1],
            create=relative in existing_paths,
        )
        if parent_chain is None:
            continue
        destination_path = parent_chain[-1][0] / parts[-1]
        if relative in existing_paths:
            backup_parent_chain = _open_rollback_parent_by_path(
                backup_root_chain,
                parts[:-1],
                create=False,
            )
            if backup_parent_chain is None:
                raise OSError("backup member missing")
            _restore_rollback_file_by_path(
                backup_parent_chain[-1][0] / parts[-1],
                backup_parent_chain,
                destination_path,
                parent_chain,
                old_modes[relative],
                old_digests[relative],
            )
        else:
            destination_info = _rollback_file_info(destination_path, missing_ok=True)
            if destination_info is None:
                continue
            _revalidate_rollback_directory_chain(parent_chain)
            _revalidate_rollback_file(destination_path, destination_info)
            destination_path.unlink()
            _revalidate_rollback_directory_chain(parent_chain)
            if _rollback_file_info(destination_path, missing_ok=True) is not None:
                raise OSError("local observability rollback managed file reappeared")


_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WINDOWS_ROLLBACK_MEMBER_MAX_BYTES = 256 * 1024 * 1024


def _is_rollback_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _rollback_directory_info(path: Path) -> os.stat_result:
    """Inspect one fallback-path directory without following a reparse point."""

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise OSError("could not inspect local observability rollback destination") from exc
    if _is_rollback_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise OSError("unsafe local observability rollback destination ancestor")
    return info


def _rollback_file_info(path: Path, *, missing_ok: bool) -> os.stat_result | None:
    """Inspect one fallback-path managed file without following it."""

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise OSError("restored member is missing") from None
    except OSError as exc:
        raise OSError("could not inspect local observability rollback member") from exc
    if _is_rollback_link_or_reparse(info):
        raise OSError("unsafe local observability rollback managed file")
    if stat.S_ISDIR(info.st_mode):
        raise OSError("unexpected directory at managed file path")
    if not stat.S_ISREG(info.st_mode):
        raise OSError("unsafe local observability rollback managed file")
    return info


def _revalidate_rollback_directory_chain(
    chain: list[tuple[Path, os.stat_result]],
) -> None:
    """Ensure every fallback ancestor is still the same real directory."""

    for path, expected in chain:
        current = _rollback_directory_info(path)
        if not os.path.samestat(expected, current):
            raise OSError("local observability rollback destination ancestor changed")


def _revalidate_rollback_file(path: Path, expected: os.stat_result) -> None:
    current = _rollback_file_info(path, missing_ok=False)
    if current is None or not os.path.samestat(expected, current):
        raise OSError("local observability rollback managed file changed")


def _open_rollback_parent_by_path(
    root_chain: list[tuple[Path, os.stat_result]],
    parts: tuple[str, ...],
    *,
    create: bool,
) -> list[tuple[Path, os.stat_result]] | None:
    """Validate or create a fallback parent chain without accepting links."""

    chain = list(root_chain)
    _revalidate_rollback_directory_chain(chain)
    current = chain[-1][0]
    for part in parts:
        candidate = current / part
        try:
            info = _rollback_directory_info(candidate)
        except FileNotFoundError:
            if not create:
                return None
            _revalidate_rollback_directory_chain(chain)
            try:
                os.mkdir(candidate, 0o700)
            except FileExistsError:
                # A competing creator must still pass the no-link inspection.
                pass
            info = _rollback_directory_info(candidate)
            _revalidate_rollback_directory_chain(chain)
        chain.append((candidate, info))
        _revalidate_rollback_directory_chain(chain)
        current = candidate
    return chain


def _rollback_path_parts(relative: str) -> tuple[str, ...]:
    """Return a normalized managed path that cannot escape its dirfd root."""

    parts = tuple(relative.replace("\\", "/").split("/"))
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise OSError("local observability rollback contains an unsafe path")
    return parts


def _open_rollback_root_descriptor(path: Path) -> int:
    """Open and bind a real rollback root without accepting a swapped leaf."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OSError("unsafe local observability rollback root") from exc
    try:
        opened = os.fstat(descriptor)
        named = os.lstat(path)
        if (
            _is_rollback_link_or_reparse(named)
            or not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or not os.path.samestat(opened, named)
        ):
            raise OSError("unsafe local observability rollback root")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_rollback_parent(
    root_descriptor: int,
    parts: tuple[str, ...],
    *,
    create: bool,
) -> int | None:
    """Open one managed file's parent without following any path component."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    current = os.dup(root_descriptor)
    try:
        for part in parts:
            try:
                child = os.open(part, flags, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    os.close(current)
                    return None
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                except FileExistsError:
                    # A competing creator still has to pass the no-follow open.
                    pass
                else:
                    os.fsync(current)
                try:
                    child = os.open(part, flags, dir_fd=current)
                except OSError as exc:
                    raise OSError("unsafe local observability rollback destination ancestor") from exc
            except OSError as exc:
                raise OSError("unsafe local observability rollback destination ancestor") from exc
            try:
                child_info = os.fstat(child)
            except BaseException:
                os.close(child)
                raise
            if not stat.S_ISDIR(child_info.st_mode):
                os.close(child)
                raise OSError("unsafe local observability rollback destination ancestor")
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _restore_rollback_file_at(
    backup_parent_descriptor: int,
    backup_name: str,
    parent_descriptor: int,
    destination_name: str,
    mode: int,
    expected_digest: str,
) -> None:
    """Atomically restore, flush, and verify one file below a trusted dirfd."""

    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        source_descriptor = os.open(
            backup_name,
            source_flags,
            dir_fd=backup_parent_descriptor,
        )
    except OSError as exc:
        raise OSError("backup member missing") from exc
    temporary_name = ""
    temporary_descriptor = -1
    try:
        source_before = os.fstat(source_descriptor)
        source_named_before = os.stat(
            backup_name,
            dir_fd=backup_parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(source_before.st_mode)
            or not stat.S_ISREG(source_named_before.st_mode)
            or not os.path.samestat(source_before, source_named_before)
        ):
            raise OSError("backup member missing")
        destination_before = _rollback_file_info_at(
            parent_descriptor,
            destination_name,
            missing_ok=True,
        )
        create_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for _ in range(128):
            temporary_name = f".rollback-{secrets.token_hex(8)}"
            try:
                temporary_descriptor = os.open(
                    temporary_name,
                    create_flags,
                    0o600,
                    dir_fd=parent_descriptor,
                )
                break
            except FileExistsError:
                continue
        else:
            raise OSError("could not allocate rollback temporary file")

        while True:
            block = os.read(source_descriptor, 1024 * 1024)
            if not block:
                break
            view = memoryview(block)
            while view:
                written = os.write(temporary_descriptor, view)
                if written == 0:
                    raise OSError("short write while restoring rollback member")
                view = view[written:]
        source_after = os.fstat(source_descriptor)
        try:
            source_named_after = os.stat(
                backup_name,
                dir_fd=backup_parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise OSError("backup member changed during restore") from exc
        if (
            not _rollback_source_snapshot_unchanged(source_before, source_after)
            or not os.path.samestat(source_before, source_named_after)
        ):
            raise OSError("backup member changed during restore")
        if _sha256_descriptor(temporary_descriptor) != expected_digest:
            raise OSError("backup member digest mismatch")
        os.fchmod(temporary_descriptor, mode)
        os.fsync(temporary_descriptor)
        _revalidate_rollback_file_at(
            parent_descriptor,
            destination_name,
            destination_before,
        )
        os.replace(
            temporary_name,
            destination_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary_name = ""
        published = os.stat(
            destination_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if not os.path.samestat(os.fstat(temporary_descriptor), published):
            raise OSError("restored member identity changed during publish")
        os.fsync(parent_descriptor)
    finally:
        os.close(source_descriptor)
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
            except OSError:
                pass



def _rollback_file_info_at(
    parent_descriptor: int,
    name: str,
    *,
    missing_ok: bool,
) -> os.stat_result | None:
    try:
        info = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise OSError("restored member is missing") from None
    if not stat.S_ISREG(info.st_mode):
        raise OSError("unsafe local observability rollback managed file")
    return info


def _revalidate_rollback_file_at(
    parent_descriptor: int,
    name: str,
    expected: os.stat_result | None,
) -> None:
    current = _rollback_file_info_at(parent_descriptor, name, missing_ok=True)
    if expected is None:
        if current is not None:
            raise OSError("local observability rollback managed file changed")
        return
    if current is None or not os.path.samestat(expected, current):
        raise OSError("local observability rollback managed file changed")


def _rollback_source_snapshot_unchanged(
    before: os.stat_result,
    after: os.stat_result,
) -> bool:
    """Reject in-place writes while a retained rollback member is copied."""

    return (
        os.path.samestat(before, after)
        and before.st_mode == after.st_mode
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


def _rollback_named_snapshot_unchanged(
    opened: os.stat_result,
    named: os.stat_result,
) -> bool:
    """Compare descriptor/path views while tolerating Windows ctime skew."""

    return (
        os.path.samestat(opened, named)
        and opened.st_mode == named.st_mode
        and opened.st_size == named.st_size
        and opened.st_mtime_ns == named.st_mtime_ns
        and (os.name == "nt" or opened.st_ctime_ns == named.st_ctime_ns)
        and getattr(opened, "st_uid", None) == getattr(named, "st_uid", None)
    )


def _restore_rollback_file_by_path(
    backup_path: Path,
    backup_parent_chain: list[tuple[Path, os.stat_result]],
    destination_path: Path,
    destination_parent_chain: list[tuple[Path, os.stat_result]],
    mode: int,
    expected_digest: str,
) -> None:
    """Stage and authenticate fallback rollback bytes before publication."""

    _revalidate_rollback_directory_chain(backup_parent_chain)
    _revalidate_rollback_directory_chain(destination_parent_chain)
    source_named_before = _rollback_file_info(backup_path, missing_ok=False)
    if source_named_before is None:
        raise OSError("backup member missing")
    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        source_descriptor = os.open(backup_path, source_flags)
    except OSError as exc:
        raise OSError("backup member missing") from exc
    temporary_path: Path | None = None
    temporary_descriptor = -1
    try:
        source_before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(source_before.st_mode)
            or not os.path.samestat(source_before, source_named_before)
        ):
            raise OSError("backup member missing")
        destination_before = _rollback_file_info(destination_path, missing_ok=True)
        if os.name == "nt":
            _restore_windows_rollback_file_by_path(
                source_descriptor,
                source_before,
                backup_path,
                backup_parent_chain,
                destination_path,
                destination_parent_chain,
                destination_before,
                mode,
                expected_digest,
            )
            return
        create_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for _ in range(128):
            candidate = destination_path.parent / f".rollback-{secrets.token_hex(8)}"
            try:
                temporary_descriptor = os.open(candidate, create_flags, 0o600)
                temporary_path = candidate
                break
            except FileExistsError:
                continue
        else:
            raise OSError("could not allocate rollback temporary file")

        while True:
            block = os.read(source_descriptor, 1024 * 1024)
            if not block:
                break
            view = memoryview(block)
            while view:
                written = os.write(temporary_descriptor, view)
                if written == 0:
                    raise OSError("short write while restoring rollback member")
                view = view[written:]

        source_after = os.fstat(source_descriptor)
        _revalidate_rollback_directory_chain(backup_parent_chain)
        source_named_after = _rollback_file_info(backup_path, missing_ok=False)
        if (
            source_named_after is None
            or not _rollback_source_snapshot_unchanged(source_before, source_after)
            or not os.path.samestat(source_before, source_named_after)
        ):
            raise OSError("backup member changed during restore")
        if _sha256_descriptor(temporary_descriptor) != expected_digest:
            raise OSError("backup member digest mismatch")

        descriptor_chmod = getattr(os, "fchmod", None)
        if descriptor_chmod is not None:
            descriptor_chmod(temporary_descriptor, mode)
        else:
            os.chmod(temporary_path, mode)
        os.fsync(temporary_descriptor)
        staged_info = os.fstat(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = -1
        staged_named = _rollback_file_info(temporary_path, missing_ok=False)
        if staged_named is None or not os.path.samestat(staged_info, staged_named):
            raise OSError("rollback temporary identity changed")

        _revalidate_rollback_directory_chain(backup_parent_chain)
        source_named_final = _rollback_file_info(backup_path, missing_ok=False)
        if source_named_final is None or not os.path.samestat(source_before, source_named_final):
            raise OSError("backup member changed during restore")
        _revalidate_rollback_directory_chain(destination_parent_chain)
        destination_current = _rollback_file_info(destination_path, missing_ok=True)
        if destination_before is None:
            if destination_current is not None:
                raise OSError("local observability rollback managed file changed")
        elif destination_current is None or not os.path.samestat(
            destination_before,
            destination_current,
        ):
            raise OSError("local observability rollback managed file changed")

        os.replace(temporary_path, destination_path)
        temporary_path = None
        _fsync_directory(destination_path.parent)
        _revalidate_rollback_directory_chain(destination_parent_chain)
        restored_info = _rollback_file_info(destination_path, missing_ok=False)
        if restored_info is None or not os.path.samestat(staged_info, restored_info):
            raise OSError("restored member identity changed during publish")
    finally:
        os.close(source_descriptor)
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if temporary_path is not None:
            try:
                _revalidate_rollback_directory_chain(destination_parent_chain)
                temporary_path.unlink()
                _fsync_directory(temporary_path.parent)
            except OSError:
                pass


def _restore_windows_rollback_file_by_path(
    source_descriptor: int,
    source_before: os.stat_result,
    backup_path: Path,
    backup_parent_chain: list[tuple[Path, os.stat_result]],
    destination_path: Path,
    destination_parent_chain: list[tuple[Path, os.stat_result]],
    destination_before: os.stat_result | None,
    mode: int,
    expected_digest: str,
) -> None:
    """Use a protected Windows DACL before staging the first rollback byte."""

    payload = bytearray()
    while True:
        block = os.read(source_descriptor, 1024 * 1024)
        if not block:
            break
        payload.extend(block)
        if len(payload) > _WINDOWS_ROLLBACK_MEMBER_MAX_BYTES:
            raise OSError("backup member exceeds rollback size bound")
    source_after = os.fstat(source_descriptor)
    _revalidate_rollback_directory_chain(backup_parent_chain)
    source_named_after = _rollback_file_info(backup_path, missing_ok=False)
    if (
        source_named_after is None
        or not _rollback_source_snapshot_unchanged(source_before, source_after)
        or not os.path.samestat(source_before, source_named_after)
    ):
        raise OSError("backup member changed during restore")
    if hashlib.sha256(payload).hexdigest() != expected_digest:
        raise OSError("backup member digest mismatch")

    from defenseclaw import windows_acl

    temporary_path = destination_path.parent / f".rollback-{secrets.token_hex(16)}"
    if os.path.lexists(temporary_path):
        raise OSError("rollback temporary path collision")
    created = False
    try:
        security = windows_acl.private_security_for_directory(str(destination_path.parent))
        windows_acl.write_new_file(str(temporary_path), bytes(payload), security)
        created = True
        os.chmod(temporary_path, mode)
        temporary_flags = (
            os.O_RDWR
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        temporary_descriptor = os.open(temporary_path, temporary_flags)
        try:
            staged_info = os.fstat(temporary_descriptor)
            staged_named = _rollback_file_info(temporary_path, missing_ok=False)
            if staged_named is None or not os.path.samestat(staged_info, staged_named):
                raise OSError("rollback temporary identity changed")
            if _sha256_descriptor(temporary_descriptor) != expected_digest:
                raise OSError("rollback temporary digest changed")
            os.fsync(temporary_descriptor)
        finally:
            os.close(temporary_descriptor)

        _revalidate_rollback_directory_chain(backup_parent_chain)
        source_named_final = _rollback_file_info(backup_path, missing_ok=False)
        if source_named_final is None or not os.path.samestat(source_before, source_named_final):
            raise OSError("backup member changed during restore")
        _revalidate_rollback_directory_chain(destination_parent_chain)
        destination_current = _rollback_file_info(destination_path, missing_ok=True)
        if destination_before is None:
            if destination_current is not None:
                raise OSError("local observability rollback managed file changed")
        elif destination_current is None or not os.path.samestat(
            destination_before,
            destination_current,
        ):
            raise OSError("local observability rollback managed file changed")

        os.replace(temporary_path, destination_path)
        created = False
        _fsync_directory(destination_path.parent)
        _revalidate_rollback_directory_chain(destination_parent_chain)
        restored_info = _rollback_file_info(destination_path, missing_ok=False)
        if restored_info is None or not os.path.samestat(staged_info, restored_info):
            raise OSError("restored member identity changed during publish")
    finally:
        if created:
            try:
                _revalidate_rollback_directory_chain(destination_parent_chain)
                temporary_path.unlink()
                _fsync_directory(temporary_path.parent)
            except OSError:
                pass


def _remove_rollback_file_at(parent_descriptor: int, destination_name: str) -> None:
    """Durably unlink one target-created managed entry without following it."""

    try:
        info = os.stat(destination_name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode):
        raise OSError("unexpected directory at managed file path")
    os.unlink(destination_name, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _verify_activated_bundle(destination: Path, target: _BundleManifest) -> None:
    for entry in target.files:
        path = destination / entry.path
        _require_regular_file(destination, path, "activated")
        metadata = path.stat()
        if (
            metadata.st_size != entry.size
            or _sha256_file(path) != entry.sha256
            or stat.S_IMODE(metadata.st_mode) != entry.mode
        ):
            raise LocalObservabilityUpgradeError("activated_digest_mismatch", "verify")
    manifest_path = destination / _LOCAL_OBSERVABILITY_MANIFEST
    _require_regular_file(destination, manifest_path, "activated_manifest")
    if manifest_path.read_bytes() != target.raw:
        raise LocalObservabilityUpgradeError("activated_manifest_mismatch", "verify")


def _destination_only_files(destination: Path, managed_paths: set[str]) -> tuple[str, ...]:
    custom: list[str] = []
    for root, dirs, files in os.walk(destination, followlinks=False):
        root_path = Path(root)
        dirs[:] = [name for name in dirs if not (root_path / name).is_symlink()]
        for name in files:
            path = root_path / name
            relative = path.relative_to(destination).as_posix()
            if relative not in managed_paths:
                custom.append(relative)
    return tuple(sorted(custom))


def _strict_compose_project_running(project_name: str, *, timeout: float = 10.0) -> bool:
    docker = shutil.which("docker")
    if not docker:
        if _local_observability_ports_active():
            raise LocalObservabilityUpgradeError("docker_state_unknown", "stack_state")
        return False
    try:
        completed = subprocess.run(
            [
                docker,
                "ps",
                "--filter",
                f"label=com.docker.compose.project={project_name}",
                "--filter",
                "status=running",
                "--format",
                "{{.ID}}",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        if _local_observability_ports_active():
            raise LocalObservabilityUpgradeError("docker_state_unknown", "stack_state") from exc
        return False
    if completed.returncode != 0:
        if _local_observability_ports_active():
            raise LocalObservabilityUpgradeError("docker_state_unknown", "stack_state")
        return False
    return bool((completed.stdout or "").strip())


def _local_observability_ports_active() -> bool:
    for port in (3000, 3100, 3200, 4317, 4318, 9090):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                return True
        except OSError:
            continue
    return False


def _bridge_contract_valid(stdout: str | None) -> bool:
    for line in (stdout or "").splitlines():
        if not line.lstrip().startswith("{"):
            continue
        try:
            document = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            isinstance(document, dict)
            and document.get("otlp_endpoint")
            and document.get("grafana_url")
            and document.get("prometheus_url")
            and document.get("tempo_url")
            and document.get("loki_url")
        ):
            return True
    return False


def _live_local_observability_smoke(timeout: int) -> list[str]:
    deadline = time.monotonic() + max(timeout, 1)
    readiness = (
        ("collector", "http://127.0.0.1:13133/"),
        ("prometheus", "http://127.0.0.1:9090/-/ready"),
        ("loki", "http://127.0.0.1:3100/ready"),
        ("tempo", "http://127.0.0.1:3200/ready"),
        ("grafana", "http://127.0.0.1:3000/api/health"),
    )
    pending = dict(readiness)
    while pending and time.monotonic() < deadline:
        for name, url in tuple(pending.items()):
            if _http_ready(url):
                pending.pop(name, None)
        if pending:
            time.sleep(min(0.25, max(deadline - time.monotonic(), 0)))
    errors = [f"{name}_not_ready" for name in pending]
    if errors:
        return errors
    inventory_error = "grafana_inventory_unavailable"
    while time.monotonic() < deadline:
        try:
            search = _http_get_json("http://127.0.0.1:3000/api/search?type=dash-db")
        except (OSError, ValueError, urllib.error.URLError):
            inventory_error = "grafana_inventory_unavailable"
        else:
            if not isinstance(search, list):
                inventory_error = "grafana_inventory_invalid"
            else:
                observed = {
                    item.get("uid") for item in search if isinstance(item, dict) and isinstance(item.get("uid"), str)
                }
                if not set(_LOCAL_OBSERVABILITY_DASHBOARD_UIDS) - observed:
                    return []
                inventory_error = "grafana_dashboard_inventory_incomplete"
        time.sleep(min(0.25, max(deadline - time.monotonic(), 0)))
    return [inventory_error]


def _http_ready(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310 - fixed loopback URL
            return 200 <= response.status < 400
    except (OSError, urllib.error.URLError):
        return False


def _http_get_json(url: str) -> object:
    with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310 - fixed loopback URL
        if not 200 <= response.status < 300:
            raise OSError("unexpected HTTP status")
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("response too large")
        return json.loads(raw)


def _validate_destination_ancestors(root: Path, path: Path) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise LocalObservabilityUpgradeError("managed_path_escape", "preflight") from exc
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise LocalObservabilityUpgradeError("managed_parent_symlink", "preflight")
        if current.exists() and not current.is_dir():
            raise LocalObservabilityUpgradeError("managed_parent_not_directory", "preflight")


def _require_regular_file(root: Path, path: Path, phase: str) -> None:
    _validate_destination_ancestors(root, path)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LocalObservabilityUpgradeError("managed_file_unreadable", phase) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise LocalObservabilityUpgradeError("managed_file_not_regular", phase)


def _safe_relative_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("invalid relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ValueError("invalid relative path")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def _atomic_write_bytes(path: Path, raw: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".bundle-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            descriptor_chmod = getattr(os, "fchmod", None)
            if descriptor_chmod is not None:
                descriptor_chmod(handle.fileno(), mode)
            else:
                os.chmod(temporary, mode)
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _remove_retired_paths(
    dest: Path,
    retired_paths: tuple[str, ...],
) -> tuple[list[str], list[str]]:
    """Remove explicit bundle tombstones while preserving custom files."""
    removed: list[str] = []
    errors: list[str] = []
    try:
        _assert_safe_bundle_destination(dest, dest)
    except OSError as exc:
        return removed, [f"unsafe retired-path root: {exc}"]
    root = dest.resolve()
    for rel in retired_paths:
        rel_path = Path(rel)
        if rel_path.is_absolute() or not rel_path.parts or ".." in rel_path.parts:
            errors.append(f"refused invalid retired path: {rel}")
            continue
        candidate = dest.joinpath(*rel_path.parts)
        try:
            candidate.resolve().relative_to(root)
        except ValueError:
            errors.append(f"refused retired path outside bundle root: {rel}")
            continue
        if not candidate.exists() and not candidate.is_symlink():
            continue
        reviewed_digests = _LOCAL_OBSERVABILITY_RETIRED_SHA256.get(rel)
        if not reviewed_digests:
            errors.append(f"refused unreviewed retired path: {rel}")
            continue
        if _is_reparse_or_symlink(candidate) or not candidate.is_file():
            errors.append(f"refused non-regular retired path: {rel}")
            continue
        try:
            if _sha256_file(candidate) not in reviewed_digests:
                # A local file reusing a retired DefenseClaw filename is
                # operator-owned unless its bytes match a shipped asset.
                continue
        except OSError as exc:
            errors.append(f"inspect retired {rel}: {exc}")
            continue
        try:
            candidate.unlink()
        except OSError as exc:
            errors.append(f"remove retired {rel}: {exc}")
            continue
        removed.append(rel)
    return removed, errors


def _canonical_local_observability_file_mode(relative: str) -> int:
    """Return the stable deployment mode for one shipped stack file."""

    if os.name == "nt":
        # Windows exposes only the read-only bit through os.chmod; regular
        # extracted resource files consequently report 0666 regardless of the
        # POSIX executable vocabulary used by the Linux/macOS stack.
        return 0o666
    if relative == "run.sh" or relative.startswith("bin/"):
        return 0o755
    return 0o644


def _ensure_local_observability_container_access(
    destination: Path,
    source: Path,
    *,
    include_operator_custom: bool,
) -> list[str]:
    """Normalize non-secret bind-mounted assets for non-root containers.

    The enclosing DefenseClaw data directory remains 0700. Inside that trust
    boundary, shipped stack files are public configuration (0644), entry points
    are executable (0755), and their directory chain is traversable (0755).
    Package-manager extraction modes and the caller's umask therefore cannot
    make a Linux deployment unreadable. Interactive refresh also repairs custom
    files below the five operator-mounted surfaces; the upgrade transaction
    limits mode changes to managed files so rollback remains exact.
    """

    errors: list[str] = []
    if destination.is_symlink() or not destination.is_dir():
        return ["container access: destination is not a regular directory"]

    managed_files: set[str] = set()
    managed_directories: set[Path] = {destination}
    try:
        for root, dirs, files in os.walk(source, followlinks=False):
            root_path = Path(root)
            relative_root = root_path.relative_to(source)
            managed_directories.add(destination / relative_root)
            for name in dirs:
                source_dir = root_path / name
                if source_dir.is_symlink():
                    continue
                managed_directories.add(destination / relative_root / name)
            for name in files:
                source_file = root_path / name
                if source_file.is_symlink() or not source_file.is_file():
                    continue
                managed_files.add((relative_root / name).as_posix())
    except (OSError, ValueError) as exc:
        return [f"container access inventory: {exc}"]

    for directory in sorted(managed_directories, key=lambda path: len(path.parts)):
        try:
            if directory.is_symlink() or not directory.is_dir():
                continue
            os.chmod(directory, 0o755)
        except OSError as exc:
            errors.append(f"container access directory {directory}: {exc}")

    for relative in sorted(managed_files):
        path = destination / relative
        try:
            if path.is_symlink() or not path.is_file():
                continue
            os.chmod(path, _canonical_local_observability_file_mode(relative))
        except OSError as exc:
            errors.append(f"container access file {relative}: {exc}")

    if not include_operator_custom:
        return errors

    # The compose bundle bind-mounts these trees into non-root containers.
    # Destination-only dashboards/rules/configs must be readable too, while
    # unrelated operator files elsewhere under observability-stack retain
    # their original modes.
    for relative_root in _LOCAL_OBSERVABILITY_OPERATOR_PATHS:
        operator_root = destination / relative_root
        if operator_root.is_symlink() or not operator_root.is_dir():
            continue
        for root, dirs, files in os.walk(operator_root, followlinks=False):
            root_path = Path(root)
            try:
                os.chmod(root_path, 0o755)
            except OSError as exc:
                errors.append(f"container access directory {root_path}: {exc}")
            dirs[:] = [name for name in dirs if not (root_path / name).is_symlink()]
            for name in files:
                path = root_path / name
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    os.chmod(path, 0o644)
                except OSError as exc:
                    errors.append(f"container access file {path}: {exc}")
    return errors


# ---------------------------------------------------------------------------
# Compose-project running detection
# ---------------------------------------------------------------------------


# Compose project label values used by each bundle — kept in lockstep
# with bundles/splunk_local_bridge/compose/docker-compose.local.yml
# (``name:`` field) and bundles/local_observability_stack/docker-compose.yml.
SPLUNK_COMPOSE_PROJECT: str = "defenseclaw-splunk-local"
LOCAL_OBSERVABILITY_COMPOSE_PROJECT: str = "defenseclaw-observability"


def is_compose_project_running(project_name: str, *, timeout: float = 5.0) -> bool:
    """Return True if a docker-compose project has at least one running container.

    Best-effort: returns False if Docker is missing/unreachable rather
    than raising. Callers use this to decide whether to stop the stack
    before refreshing the bundle on disk; a False here is correctly
    interpreted as "nothing to stop".
    """
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            [
                "docker",
                "ps",
                "--filter",
                f"label=com.docker.compose.project={project_name}",
                "--filter",
                "status=running",
                "--format",
                "{{.ID}}",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    return bool((result.stdout or "").strip())


# ---------------------------------------------------------------------------
# rsync-style overwrite primitive
# ---------------------------------------------------------------------------


def _rsync_overwrite(
    *,
    src: Path,
    dest: Path,
    preserve: tuple[str, ...],
) -> tuple[list[str], list[str], list[str]]:
    """Copy every file from ``src`` over ``dest``, except ``preserve`` paths.

    Returns ``(refreshed_paths, preserved_paths, errors)`` where each
    list contains the source-relative paths actually touched / kept /
    failed. ``preserve`` entries may be either files or directories;
    a directory in ``preserve`` shields its entire subtree.

    The copy goes through ``shutil.copy2 → tmp → os.replace`` per file
    so a crash during the loop leaves each file either fully old or
    fully new (never half-written). We do NOT prune dest-only files —
    the seeded copy can have generated artefacts (e.g.
    ``splunk/build/defenseclaw_local_mode.tgz``) that should outlive
    the refresh.
    """
    refreshed: list[str] = []
    preserved: list[str] = []
    errors: list[str] = []

    preserve_norm = tuple(p.replace("\\", "/").strip("/") for p in preserve if p)

    try:
        _assert_safe_bundle_destination(dest, dest)
    except OSError as exc:
        return refreshed, preserved, [f"unsafe destination root: {exc}"]

    for root, dirs, files in os.walk(src):
        rel_root = os.path.relpath(root, src)
        if rel_root == ".":
            rel_root = ""

        # Prune directories that match a preserve entry so we don't
        # descend into them at all. Track each as preserved so the
        # caller can show what survived.
        kept_dirs: list[str] = []
        for d in dirs:
            source_dir = Path(root) / d
            if _is_reparse_or_symlink(source_dir):
                errors.append(f"refused reparse/symlink source directory: {source_dir}")
                continue
            rel_dir = Path(os.path.join(rel_root, d) if rel_root else d).as_posix()
            if _path_is_preserved(rel_dir, preserve_norm):
                preserved.append(rel_dir)
                continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs

        for fname in files:
            rel_file = Path(os.path.join(rel_root, fname) if rel_root else fname).as_posix()
            if _path_is_preserved(rel_file, preserve_norm):
                preserved.append(rel_file)
                continue

            src_path = os.path.join(root, fname)
            dest_path = os.path.join(str(dest), rel_file)
            try:
                if _is_reparse_or_symlink(Path(src_path)):
                    raise OSError(f"refused reparse/symlink source file: {src_path}")
                _assert_safe_bundle_destination(dest, Path(dest_path))
                os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
                _assert_safe_bundle_destination(dest, Path(dest_path))
                _atomic_copy_file(src_path, dest_path, root=dest)
            except OSError as exc:
                errors.append(f"{rel_file}: {exc}")
                continue
            refreshed.append(rel_file)

    return refreshed, preserved, errors


def _path_is_preserved(rel: str, preserve: tuple[str, ...]) -> bool:
    """Return True if ``rel`` exactly matches or is nested under any preserve entry."""
    rel_norm = rel.replace("\\", "/").strip("/")
    for p in preserve:
        if rel_norm == p:
            return True
        if rel_norm.startswith(p + "/"):
            return True
    return False


def _atomic_copy_file(
    src_path: str,
    dest_path: str,
    *,
    root: Path | None = None,
) -> None:
    """``shutil.copy2`` to a same-directory tmp file, then ``os.replace``.

    Preserves mode bits via ``copy2``. Same-directory tmp file is
    required because ``os.replace`` is only atomic on the same
    filesystem — a tmp in ``/tmp`` could land on a different mount
    on Linux when ``data_dir`` is on an external volume.
    """
    dest_dir = os.path.dirname(dest_path) or "."
    if root is not None:
        _assert_safe_bundle_destination(root, Path(dest_path))
    fd, tmp_path = tempfile.mkstemp(
        prefix=".refresh-",
        dir=dest_dir,
    )
    try:
        try:
            shutil.copy2(src_path, tmp_path)
            # Keep the writable mkstemp descriptor across copy2. On Windows
            # the copied metadata may set FILE_ATTRIBUTE_READONLY, which would
            # prevent acquiring a new writable FlushFileBuffers handle.
            _fsync_claimed_file(fd, Path(tmp_path))
        finally:
            os.close(fd)
        if root is not None:
            _assert_safe_bundle_destination(root, Path(dest_path))
        os.replace(tmp_path, dest_path)
        _fsync_directory(Path(dest_dir))
    except OSError:
        # Best-effort cleanup of the orphan tmp; re-raise so the
        # caller logs the original failure.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _is_reparse_or_symlink(path: Path) -> bool:
    """Recognize POSIX links and Windows junction/reparse points via lstat."""

    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _assert_safe_bundle_destination(root: Path, candidate: Path) -> None:
    """Reject lexical escapes and existing reparse ancestors below ``root``."""

    root_abs = Path(os.path.abspath(root))
    candidate_abs = Path(os.path.abspath(candidate))
    try:
        relative = candidate_abs.relative_to(root_abs)
    except ValueError as exc:
        raise OSError(f"path escapes bundle root: {candidate_abs}") from exc

    try:
        resolved_root = root_abs.resolve(strict=True)
    except OSError as exc:
        raise OSError(f"bundle root cannot be resolved: {root_abs}") from exc
    resolved_candidate = candidate_abs.resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise OSError(
            f"resolved path escapes canonical bundle root: {resolved_candidate}"
        ) from exc

    current = root_abs
    if _is_reparse_or_symlink(current):
        raise OSError(f"bundle root is a reparse/symlink: {current}")
    for part in relative.parts:
        current = current / part
        if _is_reparse_or_symlink(current):
            raise OSError(f"destination contains a reparse/symlink: {current}")


def _restore_local_observability_backup(
    destination: Path,
    backup_managed: Path,
    backup_created: Path,
    backup_retired: Path,
    managed_paths: set[str],
    existing_paths: set[str],
    old_digests: dict[str, str],
    old_modes: dict[str, int],
    created_digests: dict[str, str],
    old_windows_security: dict[str, object],
) -> None:
    """Restore the transaction's exact managed-file inventory."""

    if os.name != "posix":
        _restore_local_observability_backup_by_path(
            destination,
            backup_managed,
            backup_created,
            backup_retired,
            managed_paths,
            existing_paths,
            old_digests,
            old_modes,
            created_digests,
            old_windows_security,
        )
        return

    root_descriptor = _open_rollback_root_descriptor(destination)
    try:
        backup_root_descriptor = _open_rollback_root_descriptor(backup_managed)
        try:
            created_root_descriptor = -1
            retired_root_descriptor = -1
            created_claims: dict[str, int] = {}
            try:
                if created_digests:
                    created_root_descriptor = _open_rollback_root_descriptor(backup_created)
                    retired_root_descriptor = _open_rollback_root_descriptor(backup_retired)
                    created_claims = _open_created_rollback_claims_at(
                        created_root_descriptor,
                        created_digests,
                    )
                try:
                    for relative in sorted(managed_paths):
                        parts = _rollback_path_parts(relative)
                        parent_descriptor = _open_rollback_parent(
                            root_descriptor,
                            parts[:-1],
                            create=relative in existing_paths,
                        )
                        if parent_descriptor is None:
                            continue
                        try:
                            if relative in existing_paths:
                                backup_parent_descriptor = _open_rollback_parent(
                                    backup_root_descriptor,
                                    parts[:-1],
                                    create=False,
                                )
                                if backup_parent_descriptor is None:
                                    raise OSError("backup member missing")
                                try:
                                    _restore_rollback_file_at(
                                        backup_parent_descriptor,
                                        parts[-1],
                                        parent_descriptor,
                                        parts[-1],
                                        old_modes[relative],
                                        old_digests[relative],
                                    )
                                finally:
                                    os.close(backup_parent_descriptor)
                            else:
                                retired_parent_descriptor = _open_rollback_parent(
                                    retired_root_descriptor,
                                    parts[:-1],
                                    create=True,
                                )
                                assert retired_parent_descriptor is not None
                                try:
                                    _retire_rollback_file_at(
                                        parent_descriptor,
                                        parts[-1],
                                        retired_parent_descriptor,
                                        parts[-1],
                                        created_claims[relative],
                                        created_digests[relative],
                                    )
                                finally:
                                    os.close(retired_parent_descriptor)
                        finally:
                            os.close(parent_descriptor)
                finally:
                    for descriptor in created_claims.values():
                        os.close(descriptor)
            finally:
                if created_root_descriptor >= 0:
                    os.close(created_root_descriptor)
                if retired_root_descriptor >= 0:
                    os.close(retired_root_descriptor)
        finally:
            os.close(backup_root_descriptor)
    finally:
        os.close(root_descriptor)


def _restore_local_observability_backup_by_path(
    destination: Path,
    backup_managed: Path,
    backup_created: Path,
    backup_retired: Path,
    managed_paths: set[str],
    existing_paths: set[str],
    old_digests: dict[str, str],
    old_modes: dict[str, int],
    created_digests: dict[str, str],
    old_windows_security: dict[str, object],
) -> None:
    """Fail closed around symlinks and reparse points without POSIX dirfds."""

    if os.name == "nt":
        _restore_local_observability_backup_windows(
            destination,
            backup_managed,
            backup_created,
            backup_retired,
            managed_paths,
            existing_paths,
            old_digests,
            old_modes,
            created_digests,
            old_windows_security,
        )
        return

    root_chain = [(destination, _rollback_directory_info(destination))]
    backup_root_chain = [(backup_managed, _rollback_directory_info(backup_managed))]
    created_root_chain: list[tuple[Path, os.stat_result]] = []
    retired_root_chain: list[tuple[Path, os.stat_result]] = []
    if created_digests:
        created_root_chain = [(backup_created, _rollback_directory_info(backup_created))]
        retired_root_chain = [(backup_retired, _rollback_directory_info(backup_retired))]
        _validate_created_rollback_claims_by_path(
            backup_created,
            created_root_chain,
            created_digests,
        )
    for relative in sorted(managed_paths):
        parts = _rollback_path_parts(relative)
        parent_chain = _open_rollback_parent_by_path(
            root_chain,
            parts[:-1],
            create=relative in existing_paths,
        )
        if parent_chain is None:
            continue
        destination_path = parent_chain[-1][0] / parts[-1]
        if relative in existing_paths:
            backup_parent_chain = _open_rollback_parent_by_path(
                backup_root_chain,
                parts[:-1],
                create=False,
            )
            if backup_parent_chain is None:
                raise OSError("backup member missing")
            _restore_rollback_file_by_path(
                backup_parent_chain[-1][0] / parts[-1],
                backup_parent_chain,
                destination_path,
                parent_chain,
                old_modes[relative],
                old_digests[relative],
            )
        else:
            claim_parent_chain = _open_rollback_parent_by_path(
                created_root_chain,
                parts[:-1],
                create=False,
            )
            if claim_parent_chain is None:
                raise OSError("target-created rollback claim is missing")
            retired_parent_chain = _open_rollback_parent_by_path(
                retired_root_chain,
                parts[:-1],
                create=True,
            )
            assert retired_parent_chain is not None
            _retire_rollback_file_by_path(
                destination_path,
                parent_chain,
                claim_parent_chain[-1][0] / parts[-1],
                claim_parent_chain,
                retired_parent_chain[-1][0] / parts[-1],
                retired_parent_chain,
                created_digests[relative],
            )


def _restore_local_observability_backup_windows(
    destination: Path,
    backup_managed: Path,
    backup_created: Path,
    backup_retired: Path,
    managed_paths: set[str],
    existing_paths: set[str],
    old_digests: dict[str, str],
    old_modes: dict[str, int],
    created_digests: dict[str, str],
    old_windows_security: dict[str, object],
) -> None:
    """Restore below native, non-delete-sharing Windows directory leases."""

    _ = backup_retired

    created_root_chain: list[tuple[Path, os.stat_result]] = []
    if created_digests:
        created_root_chain = [(backup_created, _rollback_directory_info(backup_created))]
        _validate_created_rollback_claims_by_path(
            backup_created,
            created_root_chain,
            created_digests,
        )
    for relative in sorted(managed_paths):
        parts = _rollback_path_parts(relative)
        with ExitStack() as leases:
            parent_chain = _open_windows_rollback_parent(
                destination,
                parts[:-1],
                create=relative in existing_paths,
                leases=leases,
            )
            if parent_chain is None:
                continue
            destination_path = parent_chain[-1][0] / parts[-1]
            if relative in existing_paths:
                backup_parent_chain = _open_windows_rollback_parent(
                    backup_managed,
                    parts[:-1],
                    create=False,
                    leases=leases,
                )
                if backup_parent_chain is None:
                    raise OSError("backup member missing")
                _restore_rollback_file_by_path(
                    backup_parent_chain[-1][0] / parts[-1],
                    backup_parent_chain,
                    destination_path,
                    parent_chain,
                    old_modes[relative],
                    old_digests[relative],
                    old_windows_security[relative],
                )
                continue

            claim_parent_chain = _open_windows_rollback_parent(
                backup_created,
                parts[:-1],
                create=False,
                leases=leases,
            )
            if claim_parent_chain is None:
                raise OSError("target-created rollback claim is missing")
            _remove_windows_rollback_file_by_path(
                destination_path,
                parent_chain,
                claim_parent_chain[-1][0] / parts[-1],
                claim_parent_chain,
                created_digests[relative],
            )


def _open_windows_rollback_parent(
    root: Path,
    parts: tuple[str, ...],
    *,
    create: bool,
    leases: ExitStack,
) -> list[tuple[Path, os.stat_result]] | None:
    """Bind a no-reparse parent chain before any Windows mutation."""

    from defenseclaw import windows_acl

    leases.enter_context(windows_acl.hold_directory_chain(str(root)))
    chain = [(root, _rollback_directory_info(root))]
    current = root
    for part in parts:
        candidate = current / part
        try:
            _rollback_directory_info(candidate)
        except FileNotFoundError:
            if not create:
                return None
            try:
                os.mkdir(candidate, 0o700)
            except FileExistsError:
                pass
        # The parent is already bound. Opening the child without delete sharing
        # either binds the current real directory or rejects a raced reparse.
        leases.enter_context(windows_acl.hold_directory(str(candidate)))
        chain.append((candidate, _rollback_directory_info(candidate)))
        current = candidate
    return chain


_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WINDOWS_ROLLBACK_MEMBER_MAX_BYTES = 256 * 1024 * 1024


def _is_rollback_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _rollback_directory_info(path: Path) -> os.stat_result:
    """Inspect one fallback-path directory without following a reparse point."""

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise OSError("could not inspect local observability rollback destination") from exc
    if _is_rollback_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise OSError("unsafe local observability rollback destination ancestor")
    return info


def _rollback_file_info(path: Path, *, missing_ok: bool) -> os.stat_result | None:
    """Inspect one fallback-path managed file without following it."""

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise OSError("restored member is missing") from None
    except OSError as exc:
        raise OSError("could not inspect local observability rollback member") from exc
    if _is_rollback_link_or_reparse(info):
        raise OSError("unsafe local observability rollback managed file")
    if stat.S_ISDIR(info.st_mode):
        raise OSError("unexpected directory at managed file path")
    if not stat.S_ISREG(info.st_mode):
        raise OSError("unsafe local observability rollback managed file")
    return info


def _revalidate_rollback_directory_chain(
    chain: list[tuple[Path, os.stat_result]],
) -> None:
    """Ensure every fallback ancestor is still the same real directory."""

    for path, expected in chain:
        current = _rollback_directory_info(path)
        if not os.path.samestat(expected, current):
            raise OSError("local observability rollback destination ancestor changed")


def _revalidate_rollback_file(path: Path, expected: os.stat_result) -> None:
    current = _rollback_file_info(path, missing_ok=False)
    if current is None or not os.path.samestat(expected, current):
        raise OSError("local observability rollback managed file changed")


def _open_rollback_parent_by_path(
    root_chain: list[tuple[Path, os.stat_result]],
    parts: tuple[str, ...],
    *,
    create: bool,
) -> list[tuple[Path, os.stat_result]] | None:
    """Validate or create a fallback parent chain without accepting links."""

    chain = list(root_chain)
    _revalidate_rollback_directory_chain(chain)
    current = chain[-1][0]
    for part in parts:
        candidate = current / part
        try:
            info = _rollback_directory_info(candidate)
        except FileNotFoundError:
            if not create:
                return None
            _revalidate_rollback_directory_chain(chain)
            try:
                os.mkdir(candidate, 0o700)
            except FileExistsError:
                # A competing creator must still pass the no-link inspection.
                pass
            info = _rollback_directory_info(candidate)
            _revalidate_rollback_directory_chain(chain)
        chain.append((candidate, info))
        _revalidate_rollback_directory_chain(chain)
        current = candidate
    return chain


def _rollback_path_parts(relative: str) -> tuple[str, ...]:
    """Return a normalized managed path that cannot escape its dirfd root."""

    parts = tuple(relative.replace("\\", "/").split("/"))
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise OSError("local observability rollback contains an unsafe path")
    return parts


def _open_rollback_root_descriptor(path: Path) -> int:
    """Open and bind a real rollback root without accepting a swapped leaf."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OSError("unsafe local observability rollback root") from exc
    try:
        opened = os.fstat(descriptor)
        named = os.lstat(path)
        if (
            _is_rollback_link_or_reparse(named)
            or not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or not os.path.samestat(opened, named)
        ):
            raise OSError("unsafe local observability rollback root")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_rollback_parent(
    root_descriptor: int,
    parts: tuple[str, ...],
    *,
    create: bool,
) -> int | None:
    """Open one managed file's parent without following any path component."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    current = os.dup(root_descriptor)
    try:
        for part in parts:
            try:
                child = os.open(part, flags, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    os.close(current)
                    return None
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                except FileExistsError:
                    # A competing creator still has to pass the no-follow open.
                    pass
                else:
                    os.fsync(current)
                try:
                    child = os.open(part, flags, dir_fd=current)
                except OSError as exc:
                    raise OSError("unsafe local observability rollback destination ancestor") from exc
            except OSError as exc:
                raise OSError("unsafe local observability rollback destination ancestor") from exc
            try:
                child_info = os.fstat(child)
            except BaseException:
                os.close(child)
                raise
            if not stat.S_ISDIR(child_info.st_mode):
                os.close(child)
                raise OSError("unsafe local observability rollback destination ancestor")
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _restore_rollback_file_at(
    backup_parent_descriptor: int,
    backup_name: str,
    parent_descriptor: int,
    destination_name: str,
    mode: int,
    expected_digest: str,
) -> None:
    """Atomically restore, flush, and verify one file below a trusted dirfd."""

    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        source_descriptor = os.open(
            backup_name,
            source_flags,
            dir_fd=backup_parent_descriptor,
        )
    except OSError as exc:
        raise OSError("backup member missing") from exc
    temporary_name = ""
    temporary_descriptor = -1
    try:
        source_before = os.fstat(source_descriptor)
        source_named_before = os.stat(
            backup_name,
            dir_fd=backup_parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(source_before.st_mode)
            or not stat.S_ISREG(source_named_before.st_mode)
            or not os.path.samestat(source_before, source_named_before)
        ):
            raise OSError("backup member missing")
        destination_before = _rollback_file_info_at(
            parent_descriptor,
            destination_name,
            missing_ok=True,
        )
        create_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for _ in range(128):
            temporary_name = f".rollback-{secrets.token_hex(8)}"
            try:
                temporary_descriptor = os.open(
                    temporary_name,
                    create_flags,
                    0o600,
                    dir_fd=parent_descriptor,
                )
                break
            except FileExistsError:
                continue
        else:
            raise OSError("could not allocate rollback temporary file")

        while True:
            block = os.read(source_descriptor, 1024 * 1024)
            if not block:
                break
            view = memoryview(block)
            while view:
                written = os.write(temporary_descriptor, view)
                if written == 0:
                    raise OSError("short write while restoring rollback member")
                view = view[written:]
        source_after = os.fstat(source_descriptor)
        try:
            source_named_after = os.stat(
                backup_name,
                dir_fd=backup_parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise OSError("backup member changed during restore") from exc
        if (
            not _rollback_source_snapshot_unchanged(source_before, source_after)
            or not os.path.samestat(source_before, source_named_after)
        ):
            raise OSError("backup member changed during restore")
        if _sha256_descriptor(temporary_descriptor) != expected_digest:
            raise OSError("backup member digest mismatch")
        os.fchmod(temporary_descriptor, mode)
        os.fsync(temporary_descriptor)
        _revalidate_rollback_file_at(
            parent_descriptor,
            destination_name,
            destination_before,
        )
        os.replace(
            temporary_name,
            destination_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary_name = ""
        published = os.stat(
            destination_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if not os.path.samestat(os.fstat(temporary_descriptor), published):
            raise OSError("restored member identity changed during publish")
        os.fsync(parent_descriptor)
    finally:
        os.close(source_descriptor)
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
            except OSError:
                pass



def _rollback_file_info_at(
    parent_descriptor: int,
    name: str,
    *,
    missing_ok: bool,
) -> os.stat_result | None:
    try:
        info = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise OSError("restored member is missing") from None
    if not stat.S_ISREG(info.st_mode):
        raise OSError("unsafe local observability rollback managed file")
    return info


def _revalidate_rollback_file_at(
    parent_descriptor: int,
    name: str,
    expected: os.stat_result | None,
) -> None:
    current = _rollback_file_info_at(parent_descriptor, name, missing_ok=True)
    if expected is None:
        if current is not None:
            raise OSError("local observability rollback managed file changed")
        return
    if current is None or not os.path.samestat(expected, current):
        raise OSError("local observability rollback managed file changed")


def _rollback_source_snapshot_unchanged(
    before: os.stat_result,
    after: os.stat_result,
) -> bool:
    """Reject in-place writes while a retained rollback member is copied."""

    return (
        os.path.samestat(before, after)
        and before.st_mode == after.st_mode
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


def _restore_rollback_file_by_path(
    backup_path: Path,
    backup_parent_chain: list[tuple[Path, os.stat_result]],
    destination_path: Path,
    destination_parent_chain: list[tuple[Path, os.stat_result]],
    mode: int,
    expected_digest: str,
    windows_security: object | None = None,
) -> None:
    """Stage and authenticate fallback rollback bytes before publication."""

    _revalidate_rollback_directory_chain(backup_parent_chain)
    _revalidate_rollback_directory_chain(destination_parent_chain)
    source_named_before = _rollback_file_info(backup_path, missing_ok=False)
    if source_named_before is None:
        raise OSError("backup member missing")
    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        source_descriptor = os.open(backup_path, source_flags)
    except OSError as exc:
        raise OSError("backup member missing") from exc
    temporary_path: Path | None = None
    temporary_descriptor = -1
    try:
        source_before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(source_before.st_mode)
            or not os.path.samestat(source_before, source_named_before)
        ):
            raise OSError("backup member missing")
        destination_before = _rollback_file_info(destination_path, missing_ok=True)
        if os.name == "nt":
            _restore_windows_rollback_file_by_path(
                source_descriptor,
                source_before,
                backup_path,
                backup_parent_chain,
                destination_path,
                destination_parent_chain,
                destination_before,
                mode,
                expected_digest,
                windows_security,
            )
            return
        create_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for _ in range(128):
            candidate = destination_path.parent / f".rollback-{secrets.token_hex(8)}"
            try:
                temporary_descriptor = os.open(candidate, create_flags, 0o600)
                temporary_path = candidate
                break
            except FileExistsError:
                continue
        else:
            raise OSError("could not allocate rollback temporary file")

        while True:
            block = os.read(source_descriptor, 1024 * 1024)
            if not block:
                break
            view = memoryview(block)
            while view:
                written = os.write(temporary_descriptor, view)
                if written == 0:
                    raise OSError("short write while restoring rollback member")
                view = view[written:]

        source_after = os.fstat(source_descriptor)
        _revalidate_rollback_directory_chain(backup_parent_chain)
        source_named_after = _rollback_file_info(backup_path, missing_ok=False)
        if (
            source_named_after is None
            or not _rollback_source_snapshot_unchanged(source_before, source_after)
            or not os.path.samestat(source_before, source_named_after)
        ):
            raise OSError("backup member changed during restore")
        if _sha256_descriptor(temporary_descriptor) != expected_digest:
            raise OSError("backup member digest mismatch")

        descriptor_chmod = getattr(os, "fchmod", None)
        if descriptor_chmod is not None:
            descriptor_chmod(temporary_descriptor, mode)
        else:
            os.chmod(temporary_path, mode)
        os.fsync(temporary_descriptor)
        staged_info = os.fstat(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = -1
        staged_named = _rollback_file_info(temporary_path, missing_ok=False)
        if staged_named is None or not os.path.samestat(staged_info, staged_named):
            raise OSError("rollback temporary identity changed")

        _revalidate_rollback_directory_chain(backup_parent_chain)
        source_named_final = _rollback_file_info(backup_path, missing_ok=False)
        if source_named_final is None or not os.path.samestat(source_before, source_named_final):
            raise OSError("backup member changed during restore")
        _revalidate_rollback_directory_chain(destination_parent_chain)
        destination_current = _rollback_file_info(destination_path, missing_ok=True)
        if destination_before is None:
            if destination_current is not None:
                raise OSError("local observability rollback managed file changed")
        elif destination_current is None or not os.path.samestat(
            destination_before,
            destination_current,
        ):
            raise OSError("local observability rollback managed file changed")

        os.replace(temporary_path, destination_path)
        temporary_path = None
        _fsync_directory(destination_path.parent)
        _revalidate_rollback_directory_chain(destination_parent_chain)
        restored_info = _rollback_file_info(destination_path, missing_ok=False)
        if restored_info is None or not os.path.samestat(staged_info, restored_info):
            raise OSError("restored member identity changed during publish")
    finally:
        os.close(source_descriptor)
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if temporary_path is not None:
            try:
                _revalidate_rollback_directory_chain(destination_parent_chain)
                temporary_path.unlink()
                _fsync_directory(temporary_path.parent)
            except OSError:
                pass


def _restore_windows_rollback_file_by_path(
    source_descriptor: int,
    source_before: os.stat_result,
    backup_path: Path,
    backup_parent_chain: list[tuple[Path, os.stat_result]],
    destination_path: Path,
    destination_parent_chain: list[tuple[Path, os.stat_result]],
    destination_before: os.stat_result | None,
    mode: int,
    expected_digest: str,
    expected_security: object | None,
) -> None:
    """Use a protected Windows DACL before staging the first rollback byte."""

    payload = bytearray()
    while True:
        block = os.read(source_descriptor, 1024 * 1024)
        if not block:
            break
        payload.extend(block)
        if len(payload) > _WINDOWS_ROLLBACK_MEMBER_MAX_BYTES:
            raise OSError("backup member exceeds rollback size bound")
    source_after = os.fstat(source_descriptor)
    _revalidate_rollback_directory_chain(backup_parent_chain)
    source_named_after = _rollback_file_info(backup_path, missing_ok=False)
    if (
        source_named_after is None
        or not _rollback_source_snapshot_unchanged(source_before, source_after)
        or not os.path.samestat(source_before, source_named_after)
    ):
        raise OSError("backup member changed during restore")
    if hashlib.sha256(payload).hexdigest() != expected_digest:
        raise OSError("backup member digest mismatch")
    if expected_security is None:
        raise OSError("backup member lacks exact Windows security metadata")

    from defenseclaw import windows_acl

    temporary_path = destination_path.parent / f".rollback-{secrets.token_hex(16)}"
    if os.path.lexists(temporary_path):
        raise OSError("rollback temporary path collision")
    created = False
    try:
        created = True
        # write_new_file protects the disposable staging object before its
        # first payload byte. Reapply the exact retained owner, DACL, and
        # protection state while it is still unpublished, then verify those
        # native bytes through the same descriptor that authenticates the
        # staged payload.
        windows_acl.write_new_file(
            str(temporary_path),
            bytes(payload),
            expected_security,
        )
        windows_acl.apply_path(str(temporary_path), expected_security)
        if windows_acl.capture_path(str(temporary_path)) != expected_security:
            raise OSError("rollback temporary owner/DACL mismatch")
        # A POSIX mode cannot encode Windows ACE order or inheritance state.
        _ = mode
        temporary_flags = (
            os.O_RDWR
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        temporary_descriptor = os.open(temporary_path, temporary_flags)
        try:
            staged_info = os.fstat(temporary_descriptor)
            staged_named = _rollback_file_info(temporary_path, missing_ok=False)
            if staged_named is None or not os.path.samestat(staged_info, staged_named):
                raise OSError("rollback temporary identity changed")
            if _sha256_descriptor(temporary_descriptor) != expected_digest:
                raise OSError("rollback temporary digest changed")
            if windows_acl.capture_fd(temporary_descriptor) != expected_security:
                raise OSError("rollback temporary owner/DACL changed")
            os.fsync(temporary_descriptor)
            if windows_acl.capture_fd(temporary_descriptor) != expected_security:
                raise OSError("rollback temporary owner/DACL changed")
            staged_after = os.fstat(temporary_descriptor)
            if not _rollback_source_snapshot_unchanged(staged_info, staged_after):
                raise OSError("rollback temporary changed before publish")
        finally:
            os.close(temporary_descriptor)

        _revalidate_rollback_directory_chain(backup_parent_chain)
        source_named_final = _rollback_file_info(backup_path, missing_ok=False)
        if source_named_final is None or not os.path.samestat(source_before, source_named_final):
            raise OSError("backup member changed during restore")
        _revalidate_rollback_directory_chain(destination_parent_chain)
        destination_current = _rollback_file_info(destination_path, missing_ok=True)
        if destination_before is None:
            if destination_current is not None:
                raise OSError("local observability rollback managed file changed")
        elif destination_current is None or not os.path.samestat(
            destination_before,
            destination_current,
        ):
            raise OSError("local observability rollback managed file changed")

        windows_acl.replace_regular_file_by_handle(
            str(temporary_path),
            str(destination_path),
        )
        created = False
        _fsync_directory(destination_path.parent)
        _revalidate_rollback_directory_chain(destination_parent_chain)
        restored_info = _rollback_file_info(destination_path, missing_ok=False)
        if restored_info is None or not os.path.samestat(staged_info, restored_info):
            raise OSError("restored member identity changed during publish")
        restored_flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        restored_descriptor = os.open(destination_path, restored_flags)
        try:
            restored_before = os.fstat(restored_descriptor)
            restored_security_before = windows_acl.capture_fd(restored_descriptor)
            if (
                not os.path.samestat(staged_info, restored_before)
                or _sha256_descriptor(restored_descriptor) != expected_digest
                or restored_security_before != expected_security
                or windows_acl.capture_fd(restored_descriptor) != expected_security
            ):
                raise OSError("restored member bytes or owner/DACL mismatch")
            restored_after = os.fstat(restored_descriptor)
            if not _rollback_source_snapshot_unchanged(restored_before, restored_after):
                raise OSError("restored member changed during final verification")
            restored_named_final = _rollback_file_info(
                destination_path,
                missing_ok=False,
            )
            if restored_named_final is None or not _rollback_named_snapshot_unchanged(
                restored_after,
                restored_named_final,
            ):
                raise OSError("restored member identity changed after verification")
        finally:
            os.close(restored_descriptor)
    finally:
        if created:
            try:
                windows_acl.delete_regular_file_by_handle(
                    str(temporary_path),
                    missing_ok=True,
                )
                _fsync_directory(temporary_path.parent)
            except OSError:
                pass


def _open_created_rollback_claim_at(
    root_descriptor: int,
    relative: str,
    expected_digest: str,
) -> int:
    """Open one private retained hardlink that proves target ownership."""

    parts = _rollback_path_parts(relative)
    parent_descriptor = _open_rollback_parent(
        root_descriptor,
        parts[:-1],
        create=False,
    )
    if parent_descriptor is None:
        raise OSError("target-created rollback claim is missing")
    descriptor = -1
    try:
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        before = os.fstat(descriptor)
        named = os.stat(
            parts[-1],
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or not os.path.samestat(before, named)
        ):
            raise OSError("target-created rollback claim is unsafe")
        if _sha256_descriptor(descriptor) != expected_digest:
            raise OSError("target-created rollback claim digest mismatch")
        after = os.fstat(descriptor)
        if not _rollback_source_snapshot_unchanged(before, after):
            raise OSError("target-created rollback claim changed during verification")
        return descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    finally:
        os.close(parent_descriptor)


def _open_created_rollback_claims_at(
    root_descriptor: int,
    created_digests: dict[str, str],
) -> dict[str, int]:
    claims: dict[str, int] = {}
    try:
        for relative, expected_digest in sorted(created_digests.items()):
            claims[relative] = _open_created_rollback_claim_at(
                root_descriptor,
                relative,
                expected_digest,
            )
        return claims
    except BaseException:
        for descriptor in claims.values():
            os.close(descriptor)
        raise


def _rename_no_replace_at(
    source_parent_descriptor: int,
    source_name: str,
    destination_parent_descriptor: int,
    destination_name: str,
) -> None:
    """Atomically rename across bound directories without replacing a leaf."""

    import ctypes
    import errno
    import sys

    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function = library.renameatx_np
        flag = 0x4  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        function = library.renameat2
        flag = 0x1  # RENAME_NOREPLACE
    else:
        raise OSError("target-created retirement is unsupported on this platform")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if function(
        source_parent_descriptor,
        os.fsencode(source_name),
        destination_parent_descriptor,
        os.fsencode(destination_name),
        flag,
    ) == 0:
        return
    code = ctypes.get_errno()
    if code == errno.EEXIST:
        raise FileExistsError(code, "retirement destination already exists")
    if code == errno.ENOENT:
        raise FileNotFoundError(code, "retirement source disappeared")
    raise OSError(code, "atomic target-created retirement failed")


def _open_retirement_member_at(parent_descriptor: int, name: str) -> int | None:
    try:
        named_before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(named_before.st_mode):
        raise OSError("unsafe target-created retirement member was preserved")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise OSError("unsafe target-created retirement member was preserved") from exc
    try:
        opened = os.fstat(descriptor)
        named_after = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(named_after.st_mode)
            or not os.path.samestat(opened, named_before)
            or not os.path.samestat(opened, named_after)
        ):
            raise OSError("target-created retirement member changed while opening")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _opened_retirement_matches_claim(
    descriptor: int,
    claim_descriptor: int,
    expected_digest: str,
) -> bool:
    member_before = os.fstat(descriptor)
    claim_before = os.fstat(claim_descriptor)
    if not os.path.samestat(member_before, claim_before):
        return False
    if _sha256_descriptor(descriptor) != expected_digest:
        raise OSError("target-created retirement claim digest changed")
    member_after = os.fstat(descriptor)
    claim_after = os.fstat(claim_descriptor)
    if (
        not _rollback_source_snapshot_unchanged(member_before, member_after)
        or not _rollback_source_snapshot_unchanged(claim_before, claim_after)
        or not os.path.samestat(member_after, claim_after)
    ):
        raise OSError("target-created retirement claim changed during verification")
    return True


def _restore_raced_retirement_at(
    source_parent_descriptor: int,
    source_name: str,
    retired_parent_descriptor: int,
    retired_name: str,
    retired_descriptor: int,
    claim_descriptor: int,
    expected_digest: str,
) -> bool:
    """Put a raced foreign leaf back at its public name without clobbering."""

    expected = os.fstat(retired_descriptor)
    try:
        _rename_no_replace_at(
            retired_parent_descriptor,
            retired_name,
            source_parent_descriptor,
            source_name,
        )
    except FileExistsError as exc:
        raise OSError("raced target-created replacement and canonical path were preserved") from exc
    except FileNotFoundError:
        _commit_completed_retirement_at(
            source_parent_descriptor,
            source_name,
            retired_parent_descriptor,
            retired_name,
            claim_descriptor,
            expected_digest,
            expect_retired_claim=False,
        )
        return True
    restored_descriptor = _open_retirement_member_at(source_parent_descriptor, source_name)
    remaining_retired = _open_retirement_member_at(retired_parent_descriptor, retired_name)
    try:
        if restored_descriptor is None or remaining_retired is not None:
            raise OSError("raced target-created replacement restore could not be verified")
        restored_before = os.fstat(restored_descriptor)
        if not os.path.samestat(expected, restored_before):
            raise OSError("raced target-created replacement restore could not be verified")
        # Persist the foreign object itself before either directory entry is
        # reported durable. A writer racing this fsync must not let rollback
        # claim that the exact restored snapshot was preserved.
        os.fsync(restored_descriptor)
        restored_after = os.fstat(restored_descriptor)
        restored_named = _rollback_file_info_at(
            source_parent_descriptor,
            source_name,
            missing_ok=False,
        )
        if (
            restored_named is None
            or not _rollback_source_snapshot_unchanged(restored_before, restored_after)
            or not _rollback_named_snapshot_unchanged(restored_after, restored_named)
        ):
            raise OSError("raced target-created replacement changed during restore")
        os.fsync(retired_parent_descriptor)
        os.fsync(source_parent_descriptor)
    finally:
        if restored_descriptor is not None:
            os.close(restored_descriptor)
        if remaining_retired is not None:
            os.close(remaining_retired)
    raise OSError("raced target-created replacement was restored and preserved")


def _assert_completed_retirement_at(
    source_parent_descriptor: int,
    source_name: str,
    retired_parent_descriptor: int,
    retired_name: str,
    claim_descriptor: int,
    expected_digest: str,
    *,
    expect_retired_claim: bool,
) -> None:
    source_descriptor = _open_retirement_member_at(source_parent_descriptor, source_name)
    retired_descriptor = _open_retirement_member_at(retired_parent_descriptor, retired_name)
    try:
        if source_descriptor is not None:
            raise OSError("canonical target-created path reappeared during retirement")
        if expect_retired_claim:
            if retired_descriptor is None or not _opened_retirement_matches_claim(
                retired_descriptor,
                claim_descriptor,
                expected_digest,
            ):
                raise OSError("retired target-created claim changed before durability")
        elif retired_descriptor is not None:
            raise OSError("target-created retirement path appeared concurrently")
        elif os.fstat(claim_descriptor).st_nlink != 1:
            # With both deterministic public/retired names absent, the
            # retained private claim must be the inode's sole remaining link.
            # A larger count proves the canonical object escaped under an
            # untracked name; zero proves even retained custody was unlinked.
            raise OSError("target-created rollback claim escaped deterministic custody")
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
        if retired_descriptor is not None:
            os.close(retired_descriptor)


def _commit_completed_retirement_at(
    source_parent_descriptor: int,
    source_name: str,
    retired_parent_descriptor: int,
    retired_name: str,
    claim_descriptor: int,
    expected_digest: str,
    *,
    expect_retired_claim: bool,
) -> None:
    _assert_completed_retirement_at(
        source_parent_descriptor,
        source_name,
        retired_parent_descriptor,
        retired_name,
        claim_descriptor,
        expected_digest,
        expect_retired_claim=expect_retired_claim,
    )
    os.fsync(retired_parent_descriptor)
    os.fsync(source_parent_descriptor)
    _assert_completed_retirement_at(
        source_parent_descriptor,
        source_name,
        retired_parent_descriptor,
        retired_name,
        claim_descriptor,
        expected_digest,
        expect_retired_claim=expect_retired_claim,
    )


def _finish_rollback_retirement_at(
    source_parent_descriptor: int,
    source_name: str,
    retired_parent_descriptor: int,
    retired_name: str,
    claim_descriptor: int,
    expected_digest: str,
) -> bool:
    """Classify a deterministic retirement after a first attempt or crash."""

    source_descriptor = _open_retirement_member_at(source_parent_descriptor, source_name)
    retired_descriptor = _open_retirement_member_at(retired_parent_descriptor, retired_name)
    try:
        if retired_descriptor is None:
            if source_descriptor is None:
                _commit_completed_retirement_at(
                    source_parent_descriptor,
                    source_name,
                    retired_parent_descriptor,
                    retired_name,
                    claim_descriptor,
                    expected_digest,
                    expect_retired_claim=False,
                )
                return True
            return False
        retired_is_claim = _opened_retirement_matches_claim(
            retired_descriptor,
            claim_descriptor,
            expected_digest,
        )
        if retired_is_claim:
            if source_descriptor is None:
                _commit_completed_retirement_at(
                    source_parent_descriptor,
                    source_name,
                    retired_parent_descriptor,
                    retired_name,
                    claim_descriptor,
                    expected_digest,
                    expect_retired_claim=True,
                )
                return True
            raise OSError("retired target-created claim is complete but canonical path reappeared")
        if source_descriptor is None:
            if _restore_raced_retirement_at(
                source_parent_descriptor,
                source_name,
                retired_parent_descriptor,
                retired_name,
                retired_descriptor,
                claim_descriptor,
                expected_digest,
            ):
                return True
        raise OSError("target-created retirement collision was preserved")
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
        if retired_descriptor is not None:
            os.close(retired_descriptor)


def _retire_rollback_file_at(
    source_parent_descriptor: int,
    source_name: str,
    retired_parent_descriptor: int,
    retired_name: str,
    claim_descriptor: int,
    expected_digest: str,
) -> None:
    """Durably retire only the exact target-created claim; never unlink it."""

    if _finish_rollback_retirement_at(
        source_parent_descriptor,
        source_name,
        retired_parent_descriptor,
        retired_name,
        claim_descriptor,
        expected_digest,
    ):
        return
    source_descriptor = _open_retirement_member_at(source_parent_descriptor, source_name)
    try:
        if source_descriptor is None or not _opened_retirement_matches_claim(
            source_descriptor,
            claim_descriptor,
            expected_digest,
        ):
            raise OSError("target-created managed file changed and was preserved")
        try:
            _rename_no_replace_at(
                source_parent_descriptor,
                source_name,
                retired_parent_descriptor,
                retired_name,
            )
        except (FileExistsError, FileNotFoundError):
            # Re-read both deterministic names. This covers a concurrent move
            # as well as a retry after the rename reached disk but its caller
            # was killed before observing the return value.
            pass
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
    if not _finish_rollback_retirement_at(
        source_parent_descriptor,
        source_name,
        retired_parent_descriptor,
        retired_name,
        claim_descriptor,
        expected_digest,
    ):
        raise OSError("target-created retirement did not reach a durable terminal state")


def _open_created_rollback_claim_by_path(
    claim_path: Path,
    claim_parent_chain: list[tuple[Path, os.stat_result]],
    expected_digest: str,
) -> int:
    _revalidate_rollback_directory_chain(claim_parent_chain)
    named_before = _rollback_file_info(claim_path, missing_ok=False)
    try:
        if os.name == "nt":
            from defenseclaw import windows_acl

            descriptor = windows_acl.open_regular_read_fd_shared_delete(
                str(claim_path),
            )
        else:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(claim_path, flags)
    except OSError as exc:
        raise OSError("target-created rollback claim is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if named_before is None or not os.path.samestat(before, named_before):
            raise OSError("target-created rollback claim changed while opening")
        if _sha256_descriptor(descriptor) != expected_digest:
            raise OSError("target-created rollback claim digest mismatch")
        after = os.fstat(descriptor)
        _revalidate_rollback_directory_chain(claim_parent_chain)
        named_after = _rollback_file_info(claim_path, missing_ok=False)
        if (
            named_after is None
            or not _rollback_source_snapshot_unchanged(before, after)
            or not os.path.samestat(before, named_after)
        ):
            raise OSError("target-created rollback claim changed during verification")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_created_rollback_claims_by_path(
    backup_created: Path,
    root_chain: list[tuple[Path, os.stat_result]],
    created_digests: dict[str, str],
) -> None:
    for relative, expected_digest in sorted(created_digests.items()):
        parts = _rollback_path_parts(relative)
        parent_chain = _open_rollback_parent_by_path(
            root_chain,
            parts[:-1],
            create=False,
        )
        if parent_chain is None:
            raise OSError("target-created rollback claim is missing")
        descriptor = _open_created_rollback_claim_by_path(
            backup_created.joinpath(*parts),
            parent_chain,
            expected_digest,
        )
        os.close(descriptor)


def _retire_rollback_file_by_path(
    destination_path: Path,
    destination_parent_chain: list[tuple[Path, os.stat_result]],
    claim_path: Path,
    claim_parent_chain: list[tuple[Path, os.stat_result]],
    retired_path: Path,
    retired_parent_chain: list[tuple[Path, os.stat_result]],
    expected_digest: str,
) -> None:
    claim_descriptor = _open_created_rollback_claim_by_path(
        claim_path,
        claim_parent_chain,
        expected_digest,
    )
    destination_parent_descriptor = -1
    retired_parent_descriptor = -1
    try:
        _revalidate_rollback_directory_chain(destination_parent_chain)
        _revalidate_rollback_directory_chain(retired_parent_chain)
        _rollback_file_info(destination_path, missing_ok=True)
        _rollback_file_info(retired_path, missing_ok=True)
        destination_parent_descriptor = _open_rollback_root_descriptor(destination_path.parent)
        retired_parent_descriptor = _open_rollback_root_descriptor(retired_path.parent)
        _retire_rollback_file_at(
            destination_parent_descriptor,
            destination_path.name,
            retired_parent_descriptor,
            retired_path.name,
            claim_descriptor,
            expected_digest,
        )
        _revalidate_rollback_directory_chain(destination_parent_chain)
        _revalidate_rollback_directory_chain(retired_parent_chain)
    finally:
        if destination_parent_descriptor >= 0:
            os.close(destination_parent_descriptor)
        if retired_parent_descriptor >= 0:
            os.close(retired_parent_descriptor)
        os.close(claim_descriptor)


def _mark_windows_handle_for_delete(api, handle: int) -> None:
    """Apply delete disposition to the same native handle we authenticated."""

    import ctypes

    from defenseclaw import windows_acl

    delete = ctypes.c_ubyte(1)
    if not api._set_file_information(  # noqa: SLF001 - bridge for the 0.8.4 API
        handle,
        windows_acl._FILE_DISPOSITION_INFO_CLASS,  # noqa: SLF001
        ctypes.byref(delete),
        ctypes.sizeof(delete),
    ):
        error = ctypes.get_last_error()
        raise windows_acl.WindowsAclError(error, "FileDispositionInfo failed")


def _remove_windows_rollback_file_by_path(
    destination_path: Path,
    destination_parent_chain: list[tuple[Path, os.stat_result]],
    claim_path: Path,
    claim_parent_chain: list[tuple[Path, os.stat_result]],
    expected_digest: str,
) -> None:
    """Bind, authenticate, and delete one exact Windows target-created file."""

    from defenseclaw import windows_acl

    claim_descriptor = _open_created_rollback_claim_by_path(
        claim_path,
        claim_parent_chain,
        expected_digest,
    )
    api = windows_acl._get_api()  # noqa: SLF001 - 0.8.4 compatibility bridge
    handle = None
    try:
        if _rollback_file_info(destination_path, missing_ok=True) is None:
            return
        try:
            handle = api._open_regular_mutator(str(destination_path))  # noqa: SLF001
        except OSError as exc:
            raise OSError("target-created managed file is unsafe and was preserved") from exc
        # _open_regular_mutator deliberately omits FILE_SHARE_DELETE. Once it
        # returns, the canonical leaf cannot be renamed or replaced before the
        # disposition is applied to this same handle.
        _revalidate_rollback_directory_chain(destination_parent_chain)
        current = _rollback_file_info(destination_path, missing_ok=False)
        claim_info = os.fstat(claim_descriptor)
        if current is None or not os.path.samestat(current, claim_info):
            raise OSError("target-created managed file changed and was preserved")
        _mark_windows_handle_for_delete(api, handle)
    finally:
        if handle is not None:
            api.close_handle(handle)
        os.close(claim_descriptor)
    _fsync_directory(destination_path.parent)
    if _rollback_file_info(destination_path, missing_ok=True) is not None:
        raise OSError("local observability rollback managed file reappeared")


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _fsync_file(path: Path) -> None:
    windows_exclusive_lease = False
    if os.name == "nt":
        from defenseclaw import windows_acl

        descriptor = windows_acl.open_regular_flush_fd(str(path))
        windows_exclusive_lease = True
    else:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    try:
        _fsync_claimed_file(
            descriptor,
            path,
            windows_exclusive_lease=windows_exclusive_lease,
        )
    finally:
        os.close(descriptor)


def _fsync_claimed_file(
    descriptor: int,
    path: Path,
    *,
    windows_exclusive_lease: bool = False,
) -> None:
    """Flush and revalidate one already-open exact regular-file claim."""

    before = os.fstat(descriptor)
    named_before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or not stat.S_ISREG(named_before.st_mode)
        or getattr(named_before, "st_file_attributes", 0) & 0x00000400
        or not os.path.samestat(before, named_before)
    ):
        raise OSError("rollback custody member changed while syncing")
    before_security = None
    if windows_exclusive_lease:
        if os.name != "nt":
            raise OSError("exclusive Windows rollback lease requires Windows")
        from defenseclaw import windows_acl

        before_security = windows_acl.capture_fd(descriptor)
    os.fsync(descriptor)
    after = os.fstat(descriptor)
    named_after = os.lstat(path)
    after_security = None
    if windows_exclusive_lease:
        after_security = windows_acl.capture_fd(descriptor)
    if (
        not stat.S_ISREG(after.st_mode)
        or not stat.S_ISREG(named_after.st_mode)
        or getattr(named_after, "st_file_attributes", 0) & 0x00000400
        or not os.path.samestat(before, after)
        or not os.path.samestat(after, named_after)
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_mode != after.st_mode
        or getattr(before, "st_file_attributes", 0) != getattr(after, "st_file_attributes", 0)
        or getattr(named_before, "st_file_attributes", 0) != getattr(named_after, "st_file_attributes", 0)
        # FlushFileBuffers may commit a pending NTFS ctime update. Exempt only
        # the share-none data handle, and compensate for Windows security and
        # attribute writes that do not require compatible data sharing.
        or (not windows_exclusive_lease and before.st_ctime_ns != after.st_ctime_ns)
        or (windows_exclusive_lease and before_security != after_security)
    ):
        raise OSError("rollback custody member changed while syncing")


def _fsync_directory_chain(path: Path, *, stop: Path) -> None:
    current = path
    while True:
        _fsync_directory(current)
        if current == stop:
            break
        parent = current.parent
        if parent == current:
            raise OSError("backup root is not an ancestor of rollback custody")
        current = parent


def _fsync_directory(path: Path) -> None:
    """Durably publish a same-directory rename where the platform supports it."""

    directory_flag = getattr(os, "O_DIRECTORY", None)
    if directory_flag is None:
        return
    fd = os.open(path, os.O_RDONLY | directory_flag)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


__all__ = [
    "LOCAL_OBSERVABILITY_COMPOSE_PROJECT",
    "LocalObservabilityUpgradeError",
    "LocalObservabilityUpgradeResult",
    "RefreshResult",
    "SPLUNK_COMPOSE_PROJECT",
    "is_compose_project_running",
    "refresh_local_observability_stack",
    "refresh_splunk_bridge",
    "restart_upgraded_local_observability_stack",
    "upgrade_local_observability_stack",
]
