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

import os
import shutil
import stat
import subprocess
import tempfile
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
            src=Path(bundle), dest=Path(dest), preserve=()
        )
        result.errors.extend(errors)
        if errors:
            return result
        _ensure_observability_executables(dest)
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
        if _is_reparse_or_symlink(candidate):
            errors.append(f"refused retired reparse/symlink path: {rel}")
            continue
        try:
            if candidate.is_dir():
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


def _atomic_copy_file(src_path: str, dest_path: str, *, root: Path) -> None:
    """``shutil.copy2`` to a same-directory tmp file, then ``os.replace``.

    Preserves mode bits via ``copy2``. Same-directory tmp file is
    required because ``os.replace`` is only atomic on the same
    filesystem — a tmp in ``/tmp`` could land on a different mount
    on Linux when ``data_dir`` is on an external volume.
    """
    dest_dir = os.path.dirname(dest_path) or "."
    _assert_safe_bundle_destination(root, Path(dest_path))
    fd, tmp_path = tempfile.mkstemp(
        prefix=".refresh-", dir=dest_dir,
    )
    os.close(fd)
    try:
        _assert_safe_bundle_destination(root, Path(dest_path))
        shutil.copy2(src_path, tmp_path)
        _assert_safe_bundle_destination(root, Path(dest_path))
        os.replace(tmp_path, dest_path)
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
        mode = path.lstat()
    except OSError:
        return False
    return stat.S_ISLNK(mode.st_mode) or bool(
        getattr(mode, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _assert_safe_bundle_destination(root: Path, candidate: Path) -> None:
    """Reject lexical escapes and every existing reparse ancestor under root."""
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
    if current.exists() and _is_reparse_or_symlink(current):
        raise OSError(f"bundle root is a reparse/symlink: {current}")
    for part in relative.parts:
        current = current / part
        if current.exists() and _is_reparse_or_symlink(current):
            raise OSError(f"destination contains a reparse/symlink: {current}")


__all__ = [
    "LOCAL_OBSERVABILITY_COMPOSE_PROJECT",
    "RefreshResult",
    "SPLUNK_COMPOSE_PROJECT",
    "is_compose_project_running",
    "refresh_local_observability_stack",
    "refresh_splunk_bridge",
]
