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
    managed_paths: set[str],
    existing_paths: set[str],
    old_digests: dict[str, str],
    old_modes: dict[str, int],
) -> None:
    """Restore the transaction's exact managed-file inventory."""

    if os.name != "posix":
        _restore_local_observability_backup_by_path(
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


def _restore_local_observability_backup_by_path(
    destination: Path,
    backup_managed: Path,
    managed_paths: set[str],
    existing_paths: set[str],
    old_digests: dict[str, str],
    old_modes: dict[str, int],
) -> None:
    """Fail closed around symlinks and reparse points without POSIX dirfds."""

    if os.name == "nt":
        _restore_local_observability_backup_windows(
            destination,
            backup_managed,
            managed_paths,
            existing_paths,
            old_digests,
            old_modes,
        )
        return

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


def _restore_local_observability_backup_windows(
    destination: Path,
    backup_managed: Path,
    managed_paths: set[str],
    existing_paths: set[str],
    old_digests: dict[str, str],
    old_modes: dict[str, int],
) -> None:
    """Restore below native, non-delete-sharing Windows directory leases."""

    from defenseclaw import windows_acl

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
                )
                continue

            destination_info = _rollback_file_info(destination_path, missing_ok=True)
            if destination_info is None:
                continue
            # The exact-leaf delete is safe without another path-chain stat:
            # every ancestor lease remains held until this ExitStack unwinds.
            windows_acl.delete_regular_file_by_handle(str(destination_path))
            if _rollback_file_info(destination_path, missing_ok=True) is not None:
                raise OSError("local observability rollback managed file reappeared")


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
        # Windows authorization is restored as a native protected DACL. Do
        # not translate the retained POSIX mode through a path-based chmod:
        # that both loses ACE semantics and would reopen a leaf-race window.
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
