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

"""Persistent migration cursor for ``defenseclaw upgrade``.

Decouples "which migration version we shipped with this build" (the
package's ``__version__``) from "which migrations have actually run on
this host" (the cursor file). Without this split we hit four bug
classes documented in the per-function docstrings:

* author forgets to bump ``__version__`` -> migrations re-fire forever
* migration partially fails -> cursor unchanged -> retried automatically
* operator restores from backup -> ``__version__`` perception drifts but
  the cursor on disk is the truth
* operator skips the upgrade flow entirely -> any code path that calls
  ``run_migrations`` with the cursor stays consistent

Schema-evolution contract:

* The on-disk schema is versioned by ``CURRENT_SCHEMA_VERSION``.
* A cursor written by a newer DefenseClaw build than the one currently
  installed must be treated as opaque: read what we can, never silently
  rewrite fields we don't understand. ``load`` returns ``None`` for
  unknown schemas to force the operator into ``defenseclaw doctor
  migration-state --reset`` rather than letting us downgrade their
  state silently.
* Atomic writes: every save goes through ``tempfile.NamedTemporaryFile``
  + ``os.replace`` so a crash mid-write leaves the previous good copy.
* Mode 0o600: the file logs upgrade timestamps. Not strictly secret,
  but tightening permissions matches the rest of ``~/.defenseclaw/``
  and stops accidental world-readable installs.

This module is intentionally framework-free: it has no Click, no
``ux``, no logger, no config dependency. ``run_migrations`` and
``defenseclaw doctor`` are the only callers; they own the user-facing
output. Keeping this module pure lets tests construct cursors without
spinning up an ``AppContext``.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone

# Bumped whenever the on-disk schema gains a non-additive change.
# Additive (new optional fields) bumps stay at the same number; the
# loader tolerates unknown additive fields. A bump signals that the
# meaning of an existing field changed and old readers MUST refuse to
# parse rather than misinterpret.
CURRENT_SCHEMA_VERSION = 1

STATE_FILE_NAME = ".migration_state.json"

# Sentinel value written into ``applied_at`` when a migration record
# was inferred from the operator's package version on first upgrade
# rather than observed by ``run_migrations``. ``defenseclaw doctor
# migration-state`` surfaces this so an operator can tell which
# entries are cryptographic-truth versus "we assumed this had run".
BOOTSTRAP_SENTINEL = "bootstrap"


@dataclass
class MigrationState:
    """In-memory view of the cursor file.

    Field naming mirrors the on-disk JSON shape so a future migration
    of THIS file (the meta-cursor) is just renaming a single key.
    """

    # ``schema`` is REQUIRED on disk; the dataclass default lets tests
    # construct fresh state without a redundant ``schema=1`` everywhere.
    schema: int = CURRENT_SCHEMA_VERSION
    # The package version that *wrote* the cursor on its last
    # successful save. Useful as a tie-breaker for "did we bootstrap
    # at this version or later?". NEVER used by run_migrations to
    # decide whether a migration applies — that role belongs to
    # ``applied`` exclusively.
    package_version: str = ""
    # Versions whose migration callable ran to completion (or was
    # bootstrap-marked). Order is ascending semver, maintained by
    # ``mark_applied`` so that doctor output reads top-to-bottom in
    # release order.
    applied: list[str] = field(default_factory=list)
    # Per-version ISO 8601 UTC timestamp, OR ``BOOTSTRAP_SENTINEL``
    # for entries that were inferred at first-upgrade time. Keeping
    # this as a flat dict (instead of nested objects) keeps the JSON
    # under 1 KB even after 50 releases — small enough to ``cat``.
    applied_at: dict[str, str] = field(default_factory=dict)


def state_path(data_dir: str) -> str:
    """Return the absolute path to the cursor file inside ``data_dir``.

    Centralised so tests and ``defenseclaw doctor`` agree on the path.
    """
    return os.path.join(data_dir, STATE_FILE_NAME)


def load(data_dir: str) -> MigrationState | None:
    """Load the cursor, or ``None`` if it doesn't exist or is unusable.

    The caller treats ``None`` as "first upgrade on this host" and
    bootstraps appropriately. We deliberately conflate four cases
    under ``None`` because they all need the same recovery path:

    * file does not exist (clean install or pre-cursor build)
    * file is empty (crashed mid-write)
    * file is not valid JSON (operator hand-edited and broke it)
    * file's schema version is newer than this build (downgrade case)

    The loader logs nothing — that's the caller's job. We return a
    plain ``None`` so the caller can decide whether to warn, prompt,
    or silently bootstrap.
    """
    path = state_path(data_dir)
    try:
        with open(path) as f:
            raw = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None

    if not isinstance(raw, dict):
        return None

    schema = raw.get("schema")
    # Newer schemas are intentionally rejected. Old code reading new
    # data would have to GUESS at field semantics; we'd rather force
    # an explicit ``defenseclaw doctor migration-state --reset``.
    if not isinstance(schema, int) or schema > CURRENT_SCHEMA_VERSION:
        return None
    # Older schemas are tolerated by reading what we can; future
    # bumps that need a migration of the cursor itself add a branch
    # here. For schema 1 there is no migration to perform.
    applied_raw = raw.get("applied", [])
    if not isinstance(applied_raw, list):
        return None
    applied = [str(v) for v in applied_raw if isinstance(v, str)]

    applied_at_raw = raw.get("applied_at", {})
    if not isinstance(applied_at_raw, dict):
        applied_at_raw = {}
    applied_at = {
        str(k): str(v)
        for k, v in applied_at_raw.items()
        if isinstance(k, str) and isinstance(v, str)
    }

    package_version_raw = raw.get("package_version", "")
    package_version = str(package_version_raw) if isinstance(package_version_raw, str) else ""

    return MigrationState(
        schema=schema,
        package_version=package_version,
        applied=applied,
        applied_at=applied_at,
    )


def save(data_dir: str, state: MigrationState) -> None:
    """Atomically persist the cursor to disk.

    Atomicity contract:
    1. Write to a sibling temp file in the same directory (so
       ``os.replace`` is a same-filesystem rename).
    2. ``os.replace`` is atomic on POSIX and Windows; a crash either
       leaves the old file or the new one, never half-written.
    3. ``os.fsync`` on the temp file flushes data before the rename
       so a power loss after rename still has the bytes on disk.

    Permission contract:
    * ``data_dir`` itself is created with 0o700 (the rest of
       ``~/.defenseclaw/`` already does this) by the caller; we don't
       redundantly chmod the parent.
    * The cursor file is mode 0o600. Operators with a multi-user
       host see only their own state.

    This function raises ``OSError`` on filesystem failures so the
    caller can decide whether to warn-and-continue or abort. Failure
    to persist a cursor is recoverable: the next ``run_migrations``
    will just bootstrap again from ``from_version``, which usually
    re-applies idempotent migrations harmlessly.
    """
    os.makedirs(data_dir, exist_ok=True)
    target = state_path(data_dir)

    payload = {
        "schema": state.schema,
        "package_version": state.package_version,
        "applied": state.applied,
        "applied_at": state.applied_at,
    }

    # NamedTemporaryFile in delete=False mode so we control the rename
    # explicitly. dir=data_dir keeps the rename on the same filesystem
    # as the target — required for os.replace to be atomic.
    fd, tmp_path = tempfile.mkstemp(
        prefix=".migration_state.", suffix=".tmp", dir=data_dir,
    )
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        # Tighten perms BEFORE the rename so the file appears at its
        # final path with the intended mode (and never spends a
        # microsecond at the default 0o600/0o644 from mkstemp).
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, target)
    except OSError:
        # Clean up the temp file if the rename never happened.
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def is_applied(state: MigrationState | None, version: str) -> bool:
    """True iff ``state`` exists AND records ``version`` as applied.

    Centralised so callers don't repeat the ``state is not None``
    null-check at every call site. Returning False for a nil state
    is the safe default: with no cursor we don't know what's applied,
    so we treat everything as unapplied and let the bootstrap path
    in ``run_migrations`` decide which entries should be pre-marked.
    """
    if state is None:
        return False
    return version in state.applied


def mark_applied(
    state: MigrationState,
    version: str,
    *,
    package_version: str,
    bootstrap: bool = False,
    now: datetime | None = None,
) -> None:
    """Record ``version`` as applied and update bookkeeping in place.

    Idempotent: marking the same version twice is a no-op for
    ``applied`` (no duplicate entries) but DOES update ``applied_at``
    to the new timestamp. That lets a manual ``defenseclaw doctor
    migration-state --reapply`` flow record when each replay
    happened. The ``applied`` list is kept sorted ascending by semver
    so doctor output reads release-by-release.

    ``now`` is injectable purely for tests. In production the call
    site uses ``datetime.now(timezone.utc)``.
    """
    if version not in state.applied:
        state.applied.append(version)
        # Defer the import to keep this module standalone — see the
        # module docstring's "framework-free" contract. The
        # _ver_tuple helper lives in migrations.py to avoid copying
        # the parser; runtime cost of the import is negligible.
        from defenseclaw.migrations import _ver_tuple

        state.applied.sort(key=_ver_tuple)

    if bootstrap:
        state.applied_at[version] = BOOTSTRAP_SENTINEL
    else:
        ts = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
        state.applied_at[version] = ts

    state.package_version = package_version


def bootstrap(
    state: MigrationState | None,
    *,
    from_version: str,
    package_version: str,
    registry_versions: list[str],
) -> MigrationState:
    """Build a fresh cursor for a host that doesn't have one yet.

    First-upgrade rule: every registry entry whose version is at or
    below the operator's reported ``from_version`` is treated as
    already-applied. Without this, the first upgrade after rolling
    out the cursor would re-run every historical migration on hosts
    that were already in steady state at, say, ``0.4.0``.

    Why we trust ``from_version`` for bootstrap only:
    * It's the operator's most recent reading of ``__version__``,
      which (combined with their previous successful upgrades)
      strongly implies the matching migrations ran.
    * Migrations are required to be idempotent, so a wrong bootstrap
      that re-runs a migration is a noisy no-op rather than a
      destructive event.
    * After bootstrap we never trust ``from_version`` again: the
      cursor becomes authoritative.

    Returns a NEW ``MigrationState`` so callers can save unconditionally.
    Pre-existing ``state`` (e.g. partially populated by an older code
    path) is honored: any version already in ``state.applied`` is
    preserved with its current ``applied_at`` value, and bootstrap
    only fills in the gaps.
    """
    from defenseclaw.migrations import _ver_tuple

    out = state if state is not None else MigrationState()
    out.schema = CURRENT_SCHEMA_VERSION
    out.package_version = package_version

    if not from_version:
        # Operator reported no version (clean install, or older code
        # path that didn't pass --version). Don't pre-mark anything;
        # let run_migrations apply the full registry.
        return out

    cutoff = _ver_tuple(from_version)
    for ver in registry_versions:
        if ver in out.applied:
            continue
        if _ver_tuple(ver) <= cutoff:
            out.applied.append(ver)
            out.applied_at.setdefault(ver, BOOTSTRAP_SENTINEL)
    out.applied.sort(key=_ver_tuple)
    return out


def unmark(state: MigrationState, version: str) -> bool:
    """Remove ``version`` from the applied set.

    Used by ``defenseclaw doctor migration-state --unmark X.Y.Z`` so
    an operator who suspects a migration didn't actually finish can
    force a re-run without nuking the entire cursor. Returns True if
    something was removed, False if the version was never present.
    """
    if version not in state.applied:
        return False
    state.applied.remove(version)
    state.applied_at.pop(version, None)
    return True


def reset(data_dir: str) -> bool:
    """Delete the cursor entirely.

    Used by ``defenseclaw doctor migration-state --reset`` for the
    "operator wants a clean slate" case. Returns True if a file was
    removed, False if there was nothing to remove. Failures (e.g.
    permission denied) raise so the caller can show a useful
    diagnostic instead of pretending success.
    """
    path = state_path(data_dir)
    if not os.path.exists(path):
        return False
    os.remove(path)
    return True
