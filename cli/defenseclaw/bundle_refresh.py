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

import hashlib
import os
import secrets
import shutil
import stat
import subprocess
import tempfile
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path

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
_LOCAL_OBSERVABILITY_RETIRED_PATHS: tuple[str, ...] = (
    "grafana/dashboards/defenseclaw-reliability.json",
)

_LOCAL_OBSERVABILITY_DEST_REL: str = "observability-stack"


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

    if not bundle.is_dir():
        result.skipped_reason = f"bundled source missing ({bundle})"
        return result

    if not os.path.isdir(dest):
        try:
            shutil.copytree(str(bundle), dest)
        except OSError as exc:
            result.errors.append(f"initial seed: {exc}")
            return result
        _ensure_observability_executables(dest)
        result.refreshed = True
        result.refreshed_paths.append("(initial seed)")
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
            Path(dest), _LOCAL_OBSERVABILITY_RETIRED_PATHS,
        )
        result.refreshed_paths.extend(f"{path} (removed)" for path in removed)
        result.errors.extend(removal_errors)
        result.refreshed = bool(result.refreshed_paths)

    _ensure_observability_executables(dest)
    return result


def _remove_retired_paths(
    dest: Path,
    retired_paths: tuple[str, ...],
) -> tuple[list[str], list[str]]:
    """Remove explicit bundle tombstones while preserving custom files."""
    removed: list[str] = []
    errors: list[str] = []
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
        try:
            if candidate.is_dir() and not candidate.is_symlink():
                shutil.rmtree(candidate)
            else:
                candidate.unlink()
        except OSError as exc:
            errors.append(f"remove retired {rel}: {exc}")
            continue
        removed.append(rel)
    return removed, errors


def _ensure_observability_executables(dest: str) -> None:
    """Make the bridge entry points executable after a refresh.

    Keeps parity with ``cmd_init._ensure_observability_stack_executables``
    — re-implemented here so the refresh module has zero dependencies on
    the (much larger) ``cmd_init`` import chain at import time.
    """
    for rel in (
        os.path.join("bin", "openclaw-observability-bridge"),
        "run.sh",
    ):
        path = os.path.join(dest, rel)
        if os.path.isfile(path):
            try:
                os.chmod(path, 0o755)
            except OSError:
                # Non-fatal — the bridge will fail loudly on first
                # invocation if it really lacks the +x bit, and we
                # don't want refresh() to abort over a chmod hiccup.
                pass


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

    preserve_norm = tuple(p.strip("/") for p in preserve if p)

    for root, dirs, files in os.walk(src):
        rel_root = os.path.relpath(root, src)
        if rel_root == ".":
            rel_root = ""

        # Prune directories that match a preserve entry so we don't
        # descend into them at all. Track each as preserved so the
        # caller can show what survived.
        kept_dirs: list[str] = []
        for d in dirs:
            rel_dir = os.path.join(rel_root, d) if rel_root else d
            if _path_is_preserved(rel_dir, preserve_norm):
                preserved.append(rel_dir)
                continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs

        for fname in files:
            rel_file = os.path.join(rel_root, fname) if rel_root else fname
            if _path_is_preserved(rel_file, preserve_norm):
                preserved.append(rel_file)
                continue

            src_path = os.path.join(root, fname)
            dest_path = os.path.join(str(dest), rel_file)
            try:
                os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
                _atomic_copy_file(src_path, dest_path)
            except OSError as exc:
                errors.append(f"{rel_file}: {exc}")
                continue
            refreshed.append(rel_file)

    return refreshed, preserved, errors


def _path_is_preserved(rel: str, preserve: tuple[str, ...]) -> bool:
    """Return True if ``rel`` exactly matches or is nested under any preserve entry."""
    rel_norm = rel.strip("/")
    for p in preserve:
        if rel_norm == p:
            return True
        if rel_norm.startswith(p + "/"):
            return True
    return False


def _atomic_copy_file(src_path: str, dest_path: str) -> None:
    """``shutil.copy2`` to a same-directory tmp file, then ``os.replace``.

    Preserves mode bits via ``copy2``. Same-directory tmp file is
    required because ``os.replace`` is only atomic on the same
    filesystem — a tmp in ``/tmp`` could land on a different mount
    on Linux when ``data_dir`` is on an external volume.
    """
    dest_dir = os.path.dirname(dest_path) or "."
    fd, tmp_path = tempfile.mkstemp(
        prefix=".refresh-", dir=dest_dir,
    )
    os.close(fd)
    try:
        shutil.copy2(src_path, tmp_path)
        os.replace(tmp_path, dest_path)
    except OSError:
        # Best-effort cleanup of the orphan tmp; re-raise so the
        # caller logs the original failure.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


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

    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
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
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
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
        temporary_flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
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
            if restored_named_final is None or not _rollback_source_snapshot_unchanged(
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
            or not _rollback_source_snapshot_unchanged(restored_after, restored_named)
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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "LOCAL_OBSERVABILITY_COMPOSE_PROJECT",
    "RefreshResult",
    "SPLUNK_COMPOSE_PROJECT",
    "is_compose_project_running",
    "refresh_local_observability_stack",
    "refresh_splunk_bridge",
]
