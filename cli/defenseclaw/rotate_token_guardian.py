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

"""Coordinate the Linux/macOS guardian participant during token rotation.

Issue #735 binds service-side rotate-token to the #734 prepare/commit/rollback
commands. Public state carries only identities, opaque operation/generation
IDs, and canonical non-secret fingerprints.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import click
import yaml

GUARDIAN_MANIFEST_ENV = "DEFENSECLAW_HOOK_GUARDIAN_MANIFEST"
GUARDIAN_AUTH_DIR_ENV = "DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR"
_LINUX_DEFAULT_MANIFEST = "/etc/defenseclaw/hook-guardian/targets.yaml"
_DARWIN_DEFAULT_MANIFEST = "/opt/cisco/secureclient/defenseclaw/hook-guardian/targets.yaml"
_JOURNAL_FILE = "rotation-transaction.json"
_AUTHORIZATION_FILE = "protected_targets.json"
_LOCK_BASE_NAME = "rotation-transaction"
_MANIFEST_MAX_BYTES = 4 << 20
_STATE_MAX_BYTES = 1 << 20
_PHASE_PREPARING = "preparing"
_PHASE_PREPARED = "prepared"
_PHASE_COMMITTED = "committed"
_PHASE_ROLLED_BACK = "rolled_back"
_ACTIVE_PHASES = {_PHASE_PREPARING, _PHASE_PREPARED}
_TERMINAL_PHASES = {_PHASE_COMMITTED, _PHASE_ROLLED_BACK}
_EXPECTED_PHASES = {
    "prepare": _PHASE_PREPARED,
    "commit": _PHASE_COMMITTED,
    "rollback": _PHASE_ROLLED_BACK,
}


@dataclass(frozen=True)
class GuardianRotationTarget:
    user: str
    user_home: str
    sid: str
    connector: str
    data_dir: str

    def key(self) -> str:
        connector = self.connector.strip().lower()
        if not connector:
            return ""
        sid = self.sid.strip().upper()
        if sid:
            return f"{connector}\x00sid\x00{sid}"
        user = self.user.strip()
        if user:
            return f"{connector}\x00user\x00{user}"
        home = self.user_home.strip()
        if not home:
            return ""
        return f"{connector}\x00home\x00{os.path.normpath(home)}"

    def public_dict(self) -> dict[str, str]:
        payload = {"connector": self.connector}
        if self.user:
            payload["user"] = self.user
        if self.user_home:
            payload["user_home"] = self.user_home
        if self.sid:
            payload["sid"] = self.sid
        if self.data_dir:
            payload["data_dir"] = self.data_dir
        return payload


@dataclass(frozen=True)
class GuardianRotationPlan:
    operation_id: str
    generation: str
    manifest: str
    targets: tuple[GuardianRotationTarget, ...]


def guardian_lock_base(data_dir: str) -> str:
    return os.path.join(guardian_authorization_dir(data_dir), _LOCK_BASE_NAME)


def guardian_authorization_dir(data_dir: str) -> str:
    configured = str(os.environ.get(GUARDIAN_AUTH_DIR_ENV, "") or "").strip()
    if configured:
        return os.path.abspath(configured)
    return os.path.abspath(str(data_dir).rstrip(os.sep)) + "-hook-guardian"


def default_guardian_manifest_path(platform: str | None = None) -> str:
    resolved = (platform or sys.platform).strip().lower()
    if resolved == "darwin":
        return _DARWIN_DEFAULT_MANIFEST
    return _LINUX_DEFAULT_MANIFEST


def guardian_manifest_path() -> str:
    configured = str(os.environ.get(GUARDIAN_MANIFEST_ENV, "") or "").strip()
    if configured:
        return os.path.abspath(configured)
    return default_guardian_manifest_path()


def is_managed_enterprise(cfg: Any) -> bool:
    return str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise"


def require_guardian_participant(cfg: Any) -> bool:
    """Windows managed targets join only through the native adapter (#736)."""

    if not is_managed_enterprise(cfg):
        return False
    if os.name == "nt":
        raise click.ClickException(
            "Managed-enterprise token rotation on Windows requires the native "
            "guardian adapter; the general Linux/macOS guardian cannot join."
        )
    return True


def load_enabled_guardian_targets(manifest_path: str) -> tuple[GuardianRotationTarget, ...]:
    path = _require_regular_file(manifest_path, "guardian manifest", _MANIFEST_MAX_BYTES)
    with open(path, "rb") as handle:
        raw = yaml.safe_load(handle) or {}
    if not isinstance(raw, dict):
        raise click.ClickException("Guardian manifest is malformed; token rotation did not start.")
    rows = raw.get("targets")
    if rows is None:
        rows = []
    if not isinstance(rows, list):
        raise click.ClickException("Guardian manifest target roster is malformed; token rotation did not start.")
    targets: list[GuardianRotationTarget] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise click.ClickException("Guardian manifest contains a malformed target; token rotation did not start.")
        enabled = row.get("enabled")
        if enabled is False:
            continue
        target = GuardianRotationTarget(
            user=str(row.get("user") or "").strip(),
            user_home=str(row.get("user_home") or "").strip(),
            sid=str(row.get("sid") or "").strip(),
            connector=str(row.get("connector") or "").strip().lower(),
            data_dir=str(row.get("data_dir") or "").strip(),
        )
        key = target.key()
        if not key:
            raise click.ClickException("Guardian manifest contains an incomplete target; token rotation did not start.")
        if key in seen:
            raise click.ClickException("Guardian manifest contains a duplicate target; token rotation did not start.")
        seen.add(key)
        targets.append(target)
    targets.sort(key=lambda item: item.key())
    return tuple(targets)


def bind_guardian_roster(
    *,
    manifest_path: str,
    requested_scopes: set[str],
    operation_id: str,
    generation: str,
) -> GuardianRotationPlan | None:
    targets = load_enabled_guardian_targets(manifest_path)
    if not targets:
        return None
    missing = sorted({target.connector for target in targets} - set(requested_scopes))
    if missing:
        raise click.ClickException(
            "Guardian manifest includes a connector that is not in the service rotation roster; "
            "no credentials were modified."
        )
    if not _valid_rotation_hex(operation_id) or not _valid_rotation_hex(generation):
        raise click.ClickException("Guardian rotation identity is invalid; no credentials were modified.")
    return GuardianRotationPlan(
        operation_id=operation_id,
        generation=generation,
        manifest=os.path.abspath(manifest_path),
        targets=targets,
    )


def assert_guardian_idle(data_dir: str) -> None:
    journal_path = os.path.join(guardian_authorization_dir(data_dir), _JOURNAL_FILE)
    if not os.path.lexists(journal_path):
        return
    payload = _load_bounded_json(journal_path, "guardian rotation journal")
    phase = str(payload.get("phase") or "").strip()
    if phase in _ACTIVE_PHASES:
        raise click.ClickException(
            "A guardian rotation transaction is already in progress; no credentials were modified."
        )
    if phase not in _TERMINAL_PHASES:
        raise click.ClickException(
            "Guardian rotation journal is in an unexpected phase; no credentials were modified."
        )
    try:
        os.unlink(journal_path)
    except OSError as exc:
        raise click.ClickException(
            "A completed guardian rotation journal could not be retired; no credentials were modified."
        ) from exc


def assert_current_attestations(
    data_dir: str,
    plan: GuardianRotationPlan,
    fingerprints: Mapping[str, str],
    *,
    generation: str | None = None,
) -> None:
    """Prove every selected target is current for the expected fingerprints.

    Connector-name presence, aggregate counts, timestamps, and file existence
    are not sufficient on their own.
    """

    current = _load_current_readiness(data_dir)
    if generation is not None and str(current.get("generation") or "").strip() != generation:
        raise click.ClickException(
            "Guardian current attestations are bound to a different generation; rotation did not commit."
        )
    if str(current.get("manifest_sha256") or "").strip() == "":
        raise click.ClickException(
            "Guardian current attestations omit the manifest digest; rotation did not commit."
        )
    rows = current.get("attestations")
    if not isinstance(rows, list):
        raise click.ClickException("Guardian current attestations are malformed; rotation did not commit.")
    by_key: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise click.ClickException("Guardian current attestations are malformed; rotation did not commit.")
        target = GuardianRotationTarget(
            user=str(row.get("user") or "").strip(),
            user_home=str(row.get("user_home") or "").strip(),
            sid=str(row.get("sid") or "").strip(),
            connector=str(row.get("connector") or "").strip().lower(),
            data_dir="",
        )
        key = target.key()
        if not key or key in by_key:
            raise click.ClickException("Guardian current attestations are incomplete or duplicated.")
        by_key[key] = row
    if len(by_key) != len(plan.targets):
        raise click.ClickException(
            "Guardian current attestations do not cover the exact selected target roster."
        )
    for target in plan.targets:
        row = by_key.get(target.key())
        if row is None:
            raise click.ClickException(
                "Guardian current attestations omit a selected target; rotation did not commit."
            )
        if row.get("ok") is not True:
            raise click.ClickException(
                "A selected guardian target is not currently attested; rotation did not commit."
            )
        expected = fingerprints.get(target.connector)
        actual = str(row.get("token_fingerprint") or "").strip()
        if not expected or actual != expected:
            raise click.ClickException(
                "A selected guardian target is not on the expected credential generation."
            )
        if generation is not None and str(row.get("generation") or "").strip() != generation:
            raise click.ClickException(
                "A selected guardian target attested a different generation; rotation did not commit."
            )


def expected_fingerprints_payload(
    plan: GuardianRotationPlan,
    fingerprints: Mapping[str, str],
) -> dict[str, list[dict[str, str]]]:
    rows: list[dict[str, str]] = []
    for target in plan.targets:
        fingerprint = fingerprints.get(target.connector)
        if not fingerprint:
            raise click.ClickException(
                "Guardian expected fingerprints omit a selected connector; no credentials were modified."
            )
        row = target.public_dict()
        row["token_fingerprint"] = fingerprint
        rows.append(row)
    return {"targets": rows}


def parse_guardian_rotate_response(
    raw: str,
    *,
    action: str,
    plan: GuardianRotationPlan,
) -> None:
    if len(raw.encode("utf-8")) > _STATE_MAX_BYTES:
        raise click.ClickException("Guardian rotation response exceeded the trusted size bound.")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise click.ClickException("Guardian rotation returned a malformed response.") from exc
    if not isinstance(payload, dict):
        raise click.ClickException("Guardian rotation returned a malformed response.")
    if payload.get("ok") is not True:
        raise click.ClickException(f"Guardian rotation {action} failed.")
    if str(payload.get("action") or "").strip() != action:
        raise click.ClickException("Guardian rotation response action did not match the requested phase.")
    if action == "rollback" and _is_idle_rollback_response(payload):
        return
    if str(payload.get("operation_id") or "").strip() != plan.operation_id:
        raise click.ClickException("Guardian rotation response named a different operation.")
    if str(payload.get("generation") or "").strip() != plan.generation:
        raise click.ClickException("Guardian rotation response named a different generation.")
    if str(payload.get("phase") or "").strip() != _EXPECTED_PHASES[action]:
        raise click.ClickException("Guardian rotation response named an unexpected phase.")
    raw_targets = payload.get("targets")
    if type(raw_targets) is not int:
        raise click.ClickException("Guardian rotation response omitted the target count.")
    if raw_targets != len(plan.targets):
        raise click.ClickException("Guardian rotation response did not cover the exact selected roster.")


def _is_idle_rollback_response(payload: Mapping[str, Any]) -> bool:
    """Accept rollback of a prepare that never published a journal."""

    return (
        str(payload.get("operation_id") or "").strip() == ""
        and str(payload.get("generation") or "").strip() == ""
        and str(payload.get("phase") or "").strip() == ""
        and type(payload.get("targets")) is int
        and payload.get("targets") == 0
    )


def _load_current_readiness(data_dir: str) -> dict[str, Any]:
    path = os.path.join(guardian_authorization_dir(data_dir), _AUTHORIZATION_FILE)
    payload = _load_bounded_json(path, "guardian authorization")
    current = payload.get("current")
    if not isinstance(current, dict) or current.get("ok") is not True:
        raise click.ClickException(
            "Guardian current attestations are unavailable or unready; no credentials were modified."
        )
    try:
        target_count = int(current.get("target_count"))
        success_count = int(current.get("success_count"))
    except (TypeError, ValueError) as exc:
        raise click.ClickException("Guardian current attestations are malformed.") from exc
    rows = current.get("attestations")
    if not isinstance(rows, list) or success_count != target_count or success_count != len(rows):
        raise click.ClickException(
            "Guardian current attestations do not prove per-target readiness."
        )
    return current


def _load_bounded_json(path: str, label: str) -> dict[str, Any]:
    regular = _require_regular_file(path, label, _STATE_MAX_BYTES)
    with open(regular, "rb") as handle:
        raw = handle.read(_STATE_MAX_BYTES + 1)
    if len(raw) > _STATE_MAX_BYTES:
        raise click.ClickException(f"{label} exceeded the trusted size bound.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise click.ClickException(f"{label} is malformed.") from exc
    if not isinstance(payload, dict):
        raise click.ClickException(f"{label} is malformed.")
    return payload


def _require_regular_file(path: str, label: str, max_bytes: int) -> str:
    if not path or not os.path.isabs(path):
        raise click.ClickException(f"{label} path is not an absolute regular file.")
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise click.ClickException(f"{label} is unavailable; no credentials were modified.") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
        raise click.ClickException(f"{label} is not a trusted regular file.")
    return path


def _valid_rotation_hex(value: str) -> bool:
    return len(value) == 32 and all(character in "0123456789abcdef" for character in value)
