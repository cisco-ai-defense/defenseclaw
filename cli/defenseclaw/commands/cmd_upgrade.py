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

"""defenseclaw upgrade — Upgrade DefenseClaw to the latest version.

Downloads pre-built release artifacts (gateway binary and Python CLI wheel)
from the GitHub release, runs version-specific migrations, and restarts
services. No source checkout or build toolchain required.

This matches the upgrade path used by scripts/upgrade.sh.
"""

from __future__ import annotations

import ast
import base64
import datetime
import email.parser
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn
from urllib.parse import urlsplit

import click
import requests

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.upgrade_receipt import (
    begin_upgrade_receipt,
    complete_upgrade_receipt,
    finalize_interrupted_upgrade_receipts,
    load_upgrade_receipt,
    record_upgrade_migrations,
)

if TYPE_CHECKING:
    from defenseclaw.windows_acl import WindowsFileSecurity

GITHUB_REPO = "cisco-ai-defense/defenseclaw"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}"
GITHUB_DL = f"https://github.com/{GITHUB_REPO}/releases/download"
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_CANONICAL_VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_DOTENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SHA256_HEX = set("0123456789abcdefABCDEF")
# Controller capability, not the minimum protocol required by a particular
# release.  The 0.8.4 bridge is intentionally reachable by protocol-1 clients
# while installing this protocol-2 controller for the 0.8.5 hard cut.
_UPGRADE_PROTOCOL_VERSION = 2
_UPGRADE_MANIFEST_FILENAME = "upgrade-manifest.json"
_OBSERVABILITY_V8_MIGRATION_VERSION = "0.8.5"
_UPGRADE_HANDOFF_ENV = "DEFENSECLAW_UPGRADE_FRESH_PROCESS"
_STAGED_UPGRADE_ENV = "DEFENSECLAW_STAGED_UPGRADE"
_STAGED_BRIDGE_VERSION_ENV = "DEFENSECLAW_STAGED_BRIDGE_VERSION"
_STAGED_BRIDGE_ARTIFACT_DIR_ENV = "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR"
_UPGRADE_TEST_MODE_ENV = "DEFENSECLAW_UPGRADE_TEST_MODE"
_UPGRADE_TEST_RELEASE_BASE_URL_ENV = "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL"
_UPGRADE_RECOVERY_DIRECTORY = ".upgrade-recovery"
_HARD_CUT_RECOVERY_FILENAME = "phase-two-active.json"
_PHASE_TWO_MUTATOR_LEASE_FILENAME = "phase-two-mutator.lease"
_HARD_CUT_RECOVERY_SCHEMA_VERSION = 1
_MAX_HARD_CUT_RECOVERY_BYTES = 64 * 1024
_PHASE_TWO_MUTATOR_LEASE_TIMEOUT_SECONDS = 600
_MAX_PHASE_TWO_MUTATOR_OUTPUT_BYTES = 1024 * 1024
_STRICT_SIGSTORE_RELEASE_VERSION = "0.8.4"
_RELEASE_WORKFLOW_IDENTITY = (
    f"https://github.com/{GITHUB_REPO}/.github/workflows/release.yaml@refs/heads/main"
)
_TARGET_CONFIG_VERSION = 8
_MAX_WHEEL_MIGRATIONS_BYTES = 8 * 1024 * 1024
_MAX_WHEEL_METADATA_BYTES = 256 * 1024
_MAX_WHEEL_MUTATOR_WRAPPER_BYTES = 256 * 1024
_HELD_PHASE_TWO_MUTATOR_LEASE: object | None = None


@dataclass(frozen=True)
class _TargetMigrationCapabilities:
    package_version: str
    run_migrations_parameters: frozenset[str]
    migration_versions: frozenset[str]
    supported_config_versions: frozenset[int]


@dataclass(frozen=True)
class _RollbackFileSnapshot:
    active_path: str
    backup_path: str | None
    existed: bool
    sha256: str | None
    mode: int | None
    windows_security: WindowsFileSecurity | None = None


@dataclass(frozen=True)
class _HardCutRollbackPlan:
    source_version: str
    data_dir: str
    backup_dir: str
    rollback_wheel_path: str
    rollback_wheel_sha256: str
    rollback_gateway_path: str
    rollback_gateway_sha256: str
    active_gateway_path: str
    gateway_snapshot: _RollbackFileSnapshot
    state_files: tuple[_RollbackFileSnapshot, ...]
    os_name: str
    environment_snapshot: dict[str, str] = field(repr=False, compare=False)
    source_dotenv_values: dict[str, str] = field(repr=False, compare=False)


_INSTALLED_MIGRATION_SCRIPT = """
import inspect
import json
import sys

from defenseclaw.migrations import run_migrations

kwargs = {}
bundle_parameter = inspect.signature(run_migrations).parameters.get(
    "upgrade_handles_local_bundle"
)
if bundle_parameter is not None and bundle_parameter.kind in (
    inspect.Parameter.POSITIONAL_OR_KEYWORD,
    inspect.Parameter.KEYWORD_ONLY,
):
    kwargs["upgrade_handles_local_bundle"] = True
count = run_migrations(
    sys.argv[1],
    sys.argv[2],
    sys.argv[3],
    sys.argv[4],
    **kwargs,
)
with open(sys.argv[5], "w", encoding="utf-8") as fh:
    json.dump({"count": count}, fh)
"""


_INSTALLED_HEALTH_SCRIPT = """
import sys

from defenseclaw import config as config_module
from defenseclaw.commands.cmd_upgrade import _poll_health

config_module._load_dotenv_into_os(sys.argv[1])
cfg = config_module.load()
_poll_health(cfg, int(sys.argv[2]), expected_version=sys.argv[3])
"""


class _LocalBundleUpgradeInvocationError(RuntimeError):
    """Value-safe target-wheel local bundle failure."""

    def __init__(self, code: str, phase: str) -> None:
        self.code = code
        self.phase = phase
        super().__init__(f"local observability bundle refresh failed ({code}, {phase})")


@click.command("upgrade")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
@click.option("--version", "target_version", default=None, help="Upgrade to a specific release version (e.g. 0.3.1)")
@click.option("--health-timeout", default=60, type=int, help="Seconds to wait for gateway health after restart")
@click.option(
    "--allow-unverified",
    is_flag=True,
    default=False,
    help=(
        "Proceed even when release artifacts cannot be cryptographically "
        "verified (missing/unsigned checksums.txt, invalid signature, or "
        "missing upgrade-manifest.json). UNSAFE: only use when you knowingly "
        "accept the supply-chain risk."
    ),
)
@pass_ctx
def upgrade(
    app: AppContext,
    yes: bool,
    target_version: str | None,
    health_timeout: int,
    allow_unverified: bool,
) -> None:
    """Upgrade DefenseClaw to the latest version.

    Downloads pre-built release artifacts (gateway binary, Python CLI wheel)
    from GitHub Releases, runs version-specific migrations, and restarts
    services. Your existing configuration is preserved.

    The upgrade is non-destructive: artifacts are downloaded and verified
    before the gateway is stopped, so a failed download never disrupts a
    running gateway.
    """
    from defenseclaw import __version__ as current_version

    ux.banner("DefenseClaw Upgrade")

    # ── Resolve target version ───────────────────────────────────────────────

    target_was_explicit = target_version is not None
    if target_version is None:
        click.echo(f"  {ux.dim('→')} Fetching latest release from GitHub ...")
        target_version = _fetch_latest_version()
        if target_version is None:
            ux.err("Could not determine latest release. Use --version to specify.", indent="  ")
            raise SystemExit(1)

    target_version = _normalize_target_version(target_version)
    requires_hard_cut_contract = _version_key(target_version) >= _version_key(
        _OBSERVABILITY_V8_MIGRATION_VERSION
    )
    requires_strict_provenance = _version_key(target_version) >= _version_key(
        _STRICT_SIGSTORE_RELEASE_VERSION
    )
    effective_allow_unverified = allow_unverified and not requires_strict_provenance
    if requires_strict_provenance and allow_unverified:
        ux.warn(
            "--allow-unverified cannot bypass mandatory 0.8.4+ manifest or artifact provenance checks; "
            "continuing with fail-closed verification.",
            indent="  ",
        )
    ux.kv("Installed version", current_version, indent="  ", key_width=22)
    ux.kv("Target version", target_version, indent="  ", key_width=22)

    # ── Same-version repair ──────────────────────────────────────────────────

    if target_version == current_version:
        click.echo()
        ux.subhead(
            f"Already at version {current_version}; continuing to re-apply "
            "release artifacts and same-version migrations.",
        )

    # ── Platform detection ───────────────────────────────────────────────────

    os_name, arch = _detect_platform()
    ux.kv("Platform", f"{os_name}/{arch}", indent="  ", key_width=22)

    # ── Pre-flight: verify artifacts exist ───────────────────────────────────

    ux.banner("Pre-flight Check")

    _preflight_check(target_version, os_name, arch)

    # ── Download artifacts to temp (gateway still running) ───────────────────

    ux.banner("Downloading Release Artifacts")

    staging_dir = tempfile.mkdtemp(prefix="defenseclaw-upgrade-")
    restart_services = True
    local_bundle_upgrade: dict[str, object] | None = None
    rollback_plan: _HardCutRollbackPlan | None = None
    hard_cut_recovery_journal: Path | None = None
    hard_cut_rollback_attempted = False
    hard_cut_rollback_succeeded = False
    staged_bridge_artifact_dir: str | None = None
    try:
        # Resolve checksums.txt FIRST so any download we accept is verified
        # against a published manifest. Returns None for old releases that
        # predate goreleaser's checksum publication; in that case we proceed
        # with a clear warning rather than hard-failing operators on a
        # version they could otherwise install.
        artifact_names = [
            _gateway_archive_name(target_version, os_name, arch),
            f"defenseclaw-{target_version}-py3-none-any.whl",
            _UPGRADE_MANIFEST_FILENAME,
        ]
        checksums = _download_checksums(
            target_version,
            staging_dir,
            allow_unverified=effective_allow_unverified,
        )
        if checksums is None:
            # F-0581 (BREAKING CHANGE): the only signed integrity manifest is
            # checksums.txt when it is either Sigstore-verified or accepted
            # with an explicit missing-cosign warning. GitHub's per-asset `digest`
            # values come from the same (untrusted, remote) release service and
            # are UNSIGNED metadata — a compromised/spoofed release endpoint can
            # serve matching bytes + digest, so they are NOT a substitute for a
            # signed manifest. We therefore fail closed whenever checksums is
            # None, regardless of whether unsigned asset digests are available.
            #
            # This is a user-visible behavior change: upgrades that previously
            # succeeded on unsigned GitHub asset digests now require an explicit
            # --allow-unverified opt-in. Operators who knowingly accept the
            # supply-chain risk can still proceed, but only WITHOUT integrity
            # verification (we do not pretend unsigned digests are trusted).
            if not effective_allow_unverified:
                if requires_strict_provenance:
                    ux.err(
                        f"DefenseClaw {target_version} requires a trusted checksums.txt; "
                        "--allow-unverified cannot override this gate.",
                        indent="  ",
                    )
                    ux.subhead(
                        "No changes were made: no services were stopped and no installed artifacts were changed.",
                        indent="    ",
                    )
                else:
                    ux.err(
                        "No trusted checksums.txt is available for this "
                        "release — refusing to install release artifacts that "
                        "cannot be cryptographically integrity-verified. GitHub "
                        "per-asset digests are unsigned metadata and are NOT "
                        "accepted as a substitute for the signed manifest.",
                        indent="  ",
                    )
                    ux.subhead(
                        "Re-run with --allow-unverified to override (UNSAFE).",
                        indent="    ",
                    )
                raise SystemExit(1)
            # Operator opted in: proceed WITHOUT integrity verification. We do
            # not seed `checksums` from unsigned GitHub digests — passing None
            # downstream makes it explicit that nothing was verified.
            ux.warn(
                "No verified checksums.txt — release artifacts will be "
                "downloaded WITHOUT integrity verification (--allow-unverified). "
                "Unsigned GitHub asset digests are intentionally not used.",
                indent="  ",
            )
        else:
            ux.ok("Checksum manifest accepted (checksums.txt)")
            # F-0582 (BREAKING CHANGE): do NOT silently fill missing artifact
            # entries from unsigned GitHub asset digests. Doing so would
            # downgrade those artifacts from signed to unsigned authentication
            # behind the operator's back. Missing entries are only filled when
            # --allow-unverified is set (with a per-artifact warning); otherwise
            # the gap is left in place and _verify_sha256 fails closed on the
            # unrecognized artifact.
            _fill_missing_checksums_from_release_assets(
                target_version,
                checksums,
                artifact_names,
                allow_unverified=effective_allow_unverified,
            )

        upgrade_manifest = _download_upgrade_manifest(
            target_version,
            staging_dir,
            checksums,
            allow_unverified=effective_allow_unverified,
        )
        _require_hard_cut_manifest_contract(
            upgrade_manifest,
            target_version=target_version,
            required=requires_hard_cut_contract,
        )
        _enforce_upgrade_source_contract(
            upgrade_manifest,
            source_version=current_version,
            target_version=target_version,
            explicit_target=target_was_explicit,
        )
        if _is_bridge_to_hard_cut_phase(upgrade_manifest, current_version, target_version):
            staged_bridge_artifact_dir = _acquire_bridge_rollback_artifacts(
                current_version,
                os_name,
                arch,
                staging_dir,
            )
        gw_binary_path, _gw_tarball_name = _download_gateway(
            target_version,
            os_name,
            arch,
            staging_dir,
            checksums,
        )
        whl_path, _whl_name = _download_wheel(
            target_version,
            staging_dir,
            checksums,
        )
        _preflight_wheel_install(
            whl_path,
            os_name,
            target_version=target_version,
            upgrade_manifest=upgrade_manifest,
        )
    except BaseException:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise

    # ── Confirm ──────────────────────────────────────────────────────────────

    if not yes:
        click.echo()
        click.echo(f"  {ux.bold('This will:')}")
        click.echo(f"    {ux.dim('1.')} Back up ~/.defenseclaw/ and ~/.openclaw/openclaw.json")
        click.echo(f"    {ux.dim('2.')} Stop the gateway, replace binaries from downloaded artifacts")
        click.echo(
            f"    {ux.dim('3.')} Run version-specific migrations and refresh any installed local observability bundle"
        )
        click.echo(f"    {ux.dim('4.')} Restart services and verify health")
        click.echo()
        if not click.confirm("  Proceed?", default=False):
            ux.subhead("Aborted.")
            shutil.rmtree(staging_dir, ignore_errors=True)
            return

    # ── Create backup ────────────────────────────────────────────────────────

    ux.banner("Creating Backup")

    backup_dir = _create_backup(app.cfg)
    ux.ok(f"Backup saved to: {backup_dir}")

    if _is_bridge_to_hard_cut_phase(upgrade_manifest, current_version, target_version):
        try:
            rollback_plan = _prepare_hard_cut_rollback_plan(
                app.cfg,
                backup_dir,
                source_version=current_version,
                os_name=os_name,
                arch=arch,
                staged_artifact_dir=staged_bridge_artifact_dir,
            )
        except BaseException:
            ux.err(
                "Hard-cut rollback preflight failed; refusing to change installed state.",
                indent="  ",
            )
            ux.subhead(
                "No services were stopped and no installed artifacts were changed.",
                indent="    ",
            )
            shutil.rmtree(staging_dir, ignore_errors=True)
            raise
        ux.ok(f"Retained authenticated {current_version} rollback artifacts")

    data_dir = app.cfg.data_dir if app.cfg and app.cfg.data_dir else os.path.expanduser("~/.defenseclaw")
    try:
        interrupted = finalize_interrupted_upgrade_receipts(data_dir, current_version=current_version)
        receipt_path = begin_upgrade_receipt(
            data_dir,
            from_version=current_version,
            target_version=target_version,
            artifacts_verified=checksums is not None and not effective_allow_unverified,
        )
    except (OSError, ValueError):
        ux.err("Could not create the durable upgrade compliance receipt; installed state was not changed.")
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise SystemExit(1) from None
    if interrupted:
        ux.warn(f"Recovered {interrupted} interrupted upgrade receipt(s) for canonical audit on startup.")
    if rollback_plan is not None:
        try:
            hard_cut_recovery_journal = _write_hard_cut_recovery_journal(
                rollback_plan,
                receipt_path,
                target_version=target_version,
            )
        except (OSError, ValueError):
            _record_failed_upgrade_receipt(receipt_path, "install_failed")
            shutil.rmtree(staging_dir, ignore_errors=True)
            ux.err(
                "Could not persist the hard-cut recovery journal; installed state was not changed."
            )
            raise SystemExit(1) from None
        _hold_phase_two_lease_for_command_lifetime()
        ux.ok("Durable hard-cut recovery journal committed before mutation")

    # ── Stop gateway, install, migrate, restart ──────────────────────────────

    ux.banner("Stopping Services")

    gateway_stop_ok = _run_silent(
        ["defenseclaw-gateway", "stop"],
        "Gateway stopped",
        "Could not stop gateway",
    )
    try:
        if not gateway_stop_ok:
            raise OSError("gateway stop command failed")
        _assert_gateway_quiesced(data_dir)
    except OSError as exc:
        if hard_cut_recovery_journal is not None:
            _remove_hard_cut_recovery_journal(hard_cut_recovery_journal)
        _record_failed_upgrade_receipt(receipt_path, "install_failed")
        shutil.rmtree(staging_dir, ignore_errors=True)
        ux.err("Gateway shutdown could not be verified; refusing to replace installed artifacts.")
        ux.subhead(str(exc), indent="    ")
        ux.subhead(
            "No installed artifacts or configuration files were changed.",
            indent="    ",
        )
        raise SystemExit(1) from None

    upgrade_phase = "install"
    upgrade_body_failed = False
    migration_failed = False
    try:
        ux.banner("Installing Artifacts")

        # Pass backup_dir so the previous gateway binary is snapshotted
        # before being overwritten — turns a failed health check into a
        # documented `cp` rollback instead of a "rebuild from source"
        # incident.
        installed_gateway_path = _install_gateway(gw_binary_path, os_name, backup_dir=backup_dir)
        _verify_installed_gateway_version(installed_gateway_path, target_version)
        _install_wheel(whl_path, os_name)

        ux.banner("Running Migrations")

        openclaw_home = os.path.expanduser(app.cfg.claw.home_dir if app.cfg else "~/.openclaw")
        # Thread the operator's data_dir through so migrations that
        # touch ``<data_dir>/.env`` / ``<data_dir>/active_connector.json``
        # / etc. (introduced in the connector-v3 wave, PR #194) hit the
        # right path even when the operator runs with a non-default
        # ``DEFENSECLAW_HOME``. Falls back to the upgrade module's
        # default expansion when the config could not be loaded.
        upgrade_phase = "migration"
        try:
            count = _run_installed_migrations(
                current_version,
                target_version,
                openclaw_home,
                data_dir,
                os_name=os_name,
            )
        except subprocess.CalledProcessError:
            migration_failed = True
            count = 0
            if rollback_plan is not None:
                record_upgrade_migrations(
                    receipt_path,
                    migration_count=0,
                    degraded=True,
                )
                ux.err(
                    "Hard-cut migration runner failed; refusing partial target activation."
                )
                raise
        click.echo()
        if migration_failed:
            ux.warn("Migration runner failed; upgrade will continue. Run: defenseclaw doctor --fix")
        elif count == 0:
            ux.ok("No migrations needed")
        else:
            ux.ok(f"Applied {count} migration(s)")
        record_upgrade_migrations(
            receipt_path,
            migration_count=count,
            degraded=migration_failed,
        )

        # Surface the migration cursor so a partial-failure host (where
        # the cursor differs from what the registry says we just ran)
        # is visible in the upgrade log, not buried in
        # ``<data_dir>/.migration_state.json``. Best-effort: a missing
        # cursor module simply skips the summary.
        _print_migration_cursor_summary(data_dir)
        upgrade_phase = "required_migration"
        try:
            _assert_required_cli_migrations(upgrade_manifest, data_dir)
        except SystemExit:
            # A release-owned required migration is part of the target
            # runtime contract.  Starting the newly installed gateway after
            # that migration failed can pair target binaries with an
            # incompatible source configuration (observability v8 is the
            # first such migration).  Preserve the ordinary retry/cursor
            # flow, but leave services stopped until the operator retries or
            # deliberately restores the recovery backup.
            restart_services = False
            ux.err("Required migration failed; target services remain stopped.")
            ux.subhead(f"Recovery backup: {backup_dir}", indent="    ")
            raise

        upgrade_phase = "local_observability"
        if rollback_plan is not None:
            try:
                local_bundle_upgrade = _run_installed_local_observability_bundle_upgrade(
                    data_dir,
                    backup_dir,
                    target_version,
                    os_name=os_name,
                )
            except _LocalBundleUpgradeInvocationError as exc:
                restart_services = False
                ux.err("Local observability bundle refresh failed; target services remain stopped.")
                ux.subhead(
                    f"failure={exc.code} phase={exc.phase}",
                    indent="    ",
                )
                ux.subhead(f"Recovery backup: {backup_dir}", indent="    ")
                raise SystemExit(1) from None

        if local_bundle_upgrade and local_bundle_upgrade.get("installed"):
            changed = local_bundle_upgrade.get("changed_paths", [])
            conflicts = local_bundle_upgrade.get("conflict_paths", [])
            changed_count = len(changed) if isinstance(changed, list) else 0
            ux.ok(
                "Local observability bundle verified"
                + (f" ({changed_count} managed files refreshed)" if changed_count else " (already current)")
            )
            if isinstance(conflicts, list) and conflicts:
                ux.warn(
                    "Overwritten local modifications were retained in the upgrade backup:",
                    indent="  ",
                )
                for path in conflicts[:10]:
                    if isinstance(path, str):
                        ux.subhead(path, indent="    ")

    except BaseException:
        upgrade_body_failed = True
        failure_code = _upgrade_failure_code(upgrade_phase)
        if rollback_plan is not None:
            restart_services = False
            hard_cut_rollback_attempted = True
            hard_cut_rollback_succeeded = _execute_hard_cut_rollback(
                rollback_plan,
                app,
                receipt_path,
                failure_code=failure_code,
                health_timeout=health_timeout,
                local_bundle_upgrade=local_bundle_upgrade,
                retain_pending_on_failure=hard_cut_recovery_journal is not None,
                recovery_journal_path=hard_cut_recovery_journal,
            )
        else:
            _record_failed_upgrade_receipt(receipt_path, failure_code)
        raise
    finally:
        # Always clean up staging dir first, even if restart fails.
        shutil.rmtree(staging_dir, ignore_errors=True)

        if hard_cut_rollback_attempted:
            _print_hard_cut_rollback_outcome(
                succeeded=hard_cut_rollback_succeeded,
                backup_dir=backup_dir,
            )
        elif not restart_services:
            ux.banner("Services Remain Stopped")
            ux.subhead(
                "Fix the reported upgrade error and re-run `defenseclaw upgrade`; "
                "required work will be retried from the recovery backup state.",
                indent="  ",
            )
        else:
            try:
                _start_and_verify_services(
                    app,
                    health_timeout,
                    data_dir=data_dir,
                    local_bundle_upgrade=local_bundle_upgrade,
                    os_name=os_name,
                    expected_version=target_version,
                    rollback_plan=rollback_plan,
                )
            except BaseException:
                if rollback_plan is not None and not upgrade_body_failed:
                    hard_cut_rollback_attempted = True
                    hard_cut_rollback_succeeded = _execute_hard_cut_rollback(
                        rollback_plan,
                        app,
                        receipt_path,
                        failure_code="health_check_failed",
                        health_timeout=health_timeout,
                        local_bundle_upgrade=local_bundle_upgrade,
                        retain_pending_on_failure=hard_cut_recovery_journal is not None,
                        recovery_journal_path=hard_cut_recovery_journal,
                    )
                    _print_hard_cut_rollback_outcome(
                        succeeded=hard_cut_rollback_succeeded,
                        backup_dir=backup_dir,
                    )
                    raise
                if upgrade_body_failed:
                    # This restart is recovery after an earlier install or
                    # migration exception.  A second failure here must not
                    # replace the original diagnostic (the receipt already
                    # contains its phase-specific failure code).  Leaving this
                    # handler without raising lets Python resume propagation of
                    # the exception that entered the ``finally`` block.
                    ux.warn(
                        "Service restart verification also failed; "
                        "preserving the original upgrade error.",
                        indent="  ",
                    )
                else:
                    _record_failed_upgrade_receipt(receipt_path, "health_check_failed")
                    raise
            else:
                if not upgrade_body_failed:
                    if hard_cut_recovery_journal is not None:
                        _remove_hard_cut_recovery_journal(hard_cut_recovery_journal)
                    complete_upgrade_receipt(
                        receipt_path,
                        status="partial" if migration_failed else "succeeded",
                    )

    # ── Done ─────────────────────────────────────────────────────────────────

    ux.banner("Upgrade Complete")
    ux.ok(f"DefenseClaw upgraded: {current_version} → {target_version}")
    click.echo(f"  {ux.bold('Backup:')} {backup_dir}")
    # Surface component drift now (rather than waiting for the operator to
    # discover it next time they run `defenseclaw version`). The plugin
    # ships separately from `defenseclaw upgrade` — when guardrail flows
    # through OpenClaw, a stale plugin against a fresh gateway is the #1
    # source of "guardrail not enforcing" reports.
    _check_post_upgrade_drift(target_version)
    click.echo()


def _print_hard_cut_rollback_outcome(*, succeeded: bool, backup_dir: str) -> None:
    """Emit one truthful summary for either rollback entry point."""

    if succeeded:
        ux.banner("Upgrade Rolled Back")
        ux.subhead(
            "The hard-cut target was not activated; the command is returning the original failure.",
            indent="  ",
        )
        return
    ux.banner("Rollback Incomplete")
    ux.subhead(
        "The hard-cut target was not reported successful; services remain fail-closed.",
        indent="  ",
    )
    ux.subhead(f"Recovery backup: {backup_dir}", indent="    ")


def _start_and_verify_services(
    app: AppContext,
    health_timeout: int,
    *,
    data_dir: str,
    local_bundle_upgrade: dict[str, object] | None = None,
    os_name: str | None = None,
    expected_version: str | None = None,
    rollback_plan: _HardCutRollbackPlan | None = None,
) -> None:
    """Restart and verify services after every required migration succeeds."""

    ux.banner("Starting Services")

    # A genuine 0.8.4 bridge is intentionally config-v7-only and must not
    # import the target v8 loader into this already-running process.  Refresh
    # only dotenv values that came from the source file, start the target
    # gateway with that environment, then let the freshly installed target
    # interpreter load and probe its own schema below.
    if rollback_plan is None:
        post_migration_cfg = _reload_post_upgrade_config(app, data_dir)
    else:
        _refresh_target_dotenv_environment(rollback_plan)
        post_migration_cfg = None

    if not _run_silent(
        ["defenseclaw-gateway", "start"],
        "Gateway started",
        "Could not start gateway",
    ):
        ux.err("Gateway failed to start; the upgrade cannot be marked successful.")
        raise SystemExit(1)

    # Reuse _run_silent so the restart degrades gracefully when the
    # `openclaw` CLI isn't installed. A bare subprocess.run() raises
    # FileNotFoundError before check=False can take effect, which used
    # to crash the upgrade command after services had already restarted.
    if not _run_silent(
        ["openclaw", "gateway", "restart"],
        "OpenClaw gateway restarted — DefenseClaw plugin loaded",
        "Could not restart OpenClaw gateway automatically",
    ):
        ux.subhead("Run manually: openclaw gateway restart")

    # Health verification
    ux.banner("Verifying Gateway Health")
    if rollback_plan is None:
        _poll_health(
            post_migration_cfg,
            health_timeout,
            expected_version=expected_version,
        )
    elif expected_version is None:
        raise OSError("hard-cut health verification requires an expected version")
    else:
        _poll_installed_health(
            data_dir,
            health_timeout,
            expected_version,
            os_name=rollback_plan.os_name,
        )

    if local_bundle_upgrade and local_bundle_upgrade.get("restart_required") is True:
        ux.banner("Restarting Local Observability")
        try:
            restart = _run_installed_local_observability_bundle_restart(
                data_dir,
                health_timeout=max(health_timeout, 1),
                os_name=os_name,
            )
        except _LocalBundleUpgradeInvocationError as exc:
            ux.warn(
                "Local observability restart/readiness is degraded; the gateway upgrade remains healthy.",
                indent="  ",
            )
            ux.subhead(f"failure={exc.code} phase={exc.phase}", indent="    ")
            ux.subhead(
                "Recover with: defenseclaw setup local-observability up",
                indent="    ",
            )
        else:
            errors = restart.get("degraded_errors", [])
            if restart.get("restarted") is True and not errors:
                ux.ok("Local observability restarted; services and dashboard inventory verified")
            else:
                ux.warn(
                    "Local observability restart/readiness is degraded; the gateway upgrade remains healthy.",
                    indent="  ",
                )
                if isinstance(errors, list):
                    for error in errors[:5]:
                        if isinstance(error, str):
                            ux.subhead(error, indent="    ")
                ux.subhead(
                    "Recover with: defenseclaw setup local-observability up",
                    indent="    ",
                )


def _reload_post_upgrade_config(app: AppContext, data_dir: str):
    """Reload migrated config and newly written dotenv values before restart."""

    from defenseclaw import config as config_module

    try:
        # ``config.load`` sources the default home before it discovers a
        # custom ``data_dir`` in config.yaml.  Source the upgrade's explicit
        # data directory first so custom-home installations also see secrets
        # created or promoted by migrations.  Ambient operator overrides keep
        # precedence because the loader never overwrites existing variables.
        config_module._load_dotenv_into_os(data_dir)
        fresh_cfg = config_module.load()
    except Exception as exc:
        ux.err(
            "Could not load the post-migration configuration; "
            "the gateway was not started.",
        )
        ux.subhead(type(exc).__name__, indent="    ")
        raise SystemExit(1) from None

    app.cfg = fresh_cfg
    return fresh_cfg


def _upgrade_failure_code(phase: str) -> str:
    return {
        "install": "install_failed",
        "migration": "migration_failed",
        "required_migration": "required_migration_failed",
        "local_observability": "local_observability_failed",
    }.get(phase, "interrupted")


def _record_failed_upgrade_receipt(path, failure_code: str) -> None:
    """Preserve the original upgrade error when failure-receipt I/O also fails."""

    try:
        complete_upgrade_receipt(path, status="failed", failure_code=failure_code)
    except (OSError, ValueError):
        ux.warn(
            "Could not finalize the upgrade compliance failure receipt; "
            "the pending receipt remains and will be classified on retry.",
            indent="  ",
        )


# ---------------------------------------------------------------------------
# GitHub release helpers
# ---------------------------------------------------------------------------


def _normalize_target_version(version: str) -> str:
    """Return a canonical release version or abort on unsafe input."""
    normalized = version.strip()
    if normalized.startswith("v"):
        normalized = normalized[1:]
    if _VERSION_RE.fullmatch(normalized):
        return normalized

    ux.err(
        f"Invalid release version: {version!r}. Expected MAJOR.MINOR.PATCH.",
        indent="  ",
    )
    raise SystemExit(1)


def _fetch_latest_version() -> str | None:
    """Fetch the latest release version from GitHub.

    Uses GITHUB_TOKEN / GH_TOKEN for authentication when available to
    avoid hitting the unauthenticated rate limit (60 req/h).
    """
    try:
        resp = requests.get(f"{GITHUB_API}/releases/latest", headers=_github_headers(), timeout=15)
        resp.raise_for_status()
        tag = resp.json().get("tag_name", "")
        if not isinstance(tag, str) or not tag:
            return None
        return tag[1:] if tag.startswith("v") else tag
    except (requests.RequestException, KeyError, ValueError):
        return None


def _github_headers() -> dict[str, str]:
    """Headers for GitHub API calls, with optional token auth."""
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _release_download_base() -> str:
    """Return GitHub's asset base or a deliberately gated local test base.

    Candidate release tests need the freshly installed bridge controller to
    fetch an unpublished target from the same local fixture server after the
    resolver handoff.  The override is intentionally unsuitable for normal
    operation: both environment variables are required, the scheme must be
    plain HTTP, and the authority must be a numeric loopback address with an
    explicit port.  This prevents a production environment typo from silently
    redirecting signed-release lookups to an arbitrary host.
    """

    raw = os.environ.get(_UPGRADE_TEST_RELEASE_BASE_URL_ENV, "").strip()
    if not raw:
        return GITHUB_DL
    if os.environ.get(_UPGRADE_TEST_MODE_ENV) != "1":
        _reject_test_release_base(
            f"{_UPGRADE_TEST_RELEASE_BASE_URL_ENV} requires {_UPGRADE_TEST_MODE_ENV}=1"
        )

    try:
        parsed = urlsplit(raw)
        port = parsed.port
        address = ipaddress.ip_address(parsed.hostname or "")
    except (ValueError, TypeError):
        _reject_test_release_base("test release base URL is malformed")
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port is None
        or not address.is_loopback
    ):
        _reject_test_release_base(
            "test release base URL must be http://<numeric-loopback>:<port>[/path]"
        )
    return raw.rstrip("/")


def _release_asset_redirects_allowed() -> bool:
    """GitHub assets redirect to its CDN; loopback test assets must not.

    Disabling redirects for the test override preserves the numeric-loopback
    network boundary after the initial request instead of allowing a local
    fixture endpoint to redirect the fresh controller to a remote host.
    """

    return not bool(os.environ.get(_UPGRADE_TEST_RELEASE_BASE_URL_ENV, "").strip())


def _reject_test_release_base(message: str) -> NoReturn:
    ux.err(f"Unsafe upgrade test endpoint: {message}.", indent="  ")
    ux.subhead(
        "No services were stopped and no installed artifacts were changed.",
        indent="    ",
    )
    raise SystemExit(1)


def _detect_platform() -> tuple[str, str]:
    """Return (os_name, arch) matching goreleaser naming convention."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        ux.err(f"Unsupported architecture: {machine}", indent="  ")
        raise SystemExit(1)

    if system not in ("darwin", "linux", "windows"):
        ux.err(f"Unsupported OS: {system}", indent="  ")
        raise SystemExit(1)

    return system, arch


def _gateway_archive_name(version: str, os_name: str, arch: str) -> str:
    """Release archive filename for the gateway, matching .goreleaser.yaml.

    Windows ships a .zip (format_overrides); linux/darwin ship .tar.gz.
    """
    ext = "zip" if os_name == "windows" else "tar.gz"
    return f"defenseclaw_{version}_{os_name}_{arch}.{ext}"


def _gateway_binary_filename(os_name: str) -> str:
    """Name of the gateway binary inside the release archive.

    GoReleaser appends .exe on Windows; everywhere else it is bare.
    """
    return "defenseclaw.exe" if os_name == "windows" else "defenseclaw"


def _installed_gateway_filename(os_name: str) -> str:
    """Name the gateway is installed as on PATH.

    shutil.which("defenseclaw-gateway") resolves the .exe via PATHEXT on
    Windows, so the CLI finds it regardless of the suffix.
    """
    return "defenseclaw-gateway.exe" if os_name == "windows" else "defenseclaw-gateway"


def _preflight_check(version: str, os_name: str, arch: str) -> None:
    """Verify release artifacts exist on GitHub before touching anything."""
    archive = _gateway_archive_name(version, os_name, arch)
    whl_name = f"defenseclaw-{version}-py3-none-any.whl"
    download_base = _release_download_base()
    urls = [
        f"{download_base}/{version}/{archive}",
        f"{download_base}/{version}/{whl_name}",
    ]
    allow_redirects = _release_asset_redirects_allowed()
    for url in urls:
        try:
            resp = requests.head(url, timeout=15, allow_redirects=allow_redirects)
            if resp.status_code >= 400 or (not allow_redirects and resp.status_code >= 300):
                ux.err(f"Artifact not found ({resp.status_code}): {url}", indent="  ")
                ux.err(
                    f"Version {version} may not exist or is missing platform artifacts.",
                    indent="    ",
                )
                raise SystemExit(1)
        except requests.RequestException as exc:
            ux.err(f"Could not reach GitHub: {exc}", indent="  ")
            raise SystemExit(1)
    ux.ok("Release artifacts verified")


def _download_gateway(
    version: str,
    os_name: str,
    arch: str,
    staging_dir: str,
    checksums: dict[str, str] | None = None,
) -> tuple[str, str]:
    """Download the gateway tarball, verify its checksum, and extract.

    Returns ``(binary_path, archive_name)``. The archive name is returned
    so the caller can correlate this artifact with the published
    ``checksums.txt`` entry; we keep the binary path stable so existing
    callers don't break when checksum verification is opted into.

    The archive is a .zip on Windows (containing defenseclaw.exe) and a
    .tar.gz elsewhere (containing defenseclaw), matching .goreleaser.yaml.
    """
    archive = _gateway_archive_name(version, os_name, arch)
    url = f"{_release_download_base()}/{version}/{archive}"

    click.echo(f"  {ux.dim('→')} Downloading gateway binary ({os_name}/{arch}) ...")
    dest = os.path.join(staging_dir, archive)
    _download_file(url, dest)
    if checksums is not None:
        _verify_sha256(dest, archive, checksums)
    if os_name == "windows":
        _extract_gateway_zip(dest, staging_dir)
    else:
        _extract_gateway_tarball(dest, staging_dir)
    binary_name = _gateway_binary_filename(os_name)
    binary = os.path.join(staging_dir, binary_name)
    if not os.path.isfile(binary):
        ux.err(
            f"Gateway archive did not contain the expected {binary_name} binary.",
            indent="  ",
        )
        raise SystemExit(1)
    ux.ok("Gateway binary downloaded")
    return binary, archive


def _download_wheel(
    version: str,
    staging_dir: str,
    checksums: dict[str, str] | None = None,
) -> tuple[str, str]:
    """Download the Python CLI wheel and verify its checksum."""
    whl_name = f"defenseclaw-{version}-py3-none-any.whl"
    url = f"{_release_download_base()}/{version}/{whl_name}"

    click.echo(f"  {ux.dim('→')} Downloading Python CLI wheel ...")
    dest = os.path.join(staging_dir, whl_name)
    _download_file(url, dest)
    if checksums is not None:
        _verify_sha256(dest, whl_name, checksums)
    ux.ok("Python CLI wheel downloaded")
    return dest, whl_name


# Filename the GitHub release exposes for the SHA-256 manifest. Mirrors
# .goreleaser.yaml ``checksum.name_template``.
_CHECKSUMS_FILENAME = "checksums.txt"


def _download_checksums(
    version: str,
    staging_dir: str,
    allow_unverified: bool = False,
) -> dict[str, str] | None:
    """Download ``checksums.txt`` for the target release and parse it.

    Returns a mapping of ``filename → lowercase_sha256_hex`` or ``None``
    when the manifest is unavailable. Old releases predate goreleaser's
    checksum publication, so a missing file must not block the upgrade
    — the caller decides whether to warn or hard-fail. We deliberately
    parse, not just download, because a 200 with garbage body would
    otherwise look "verified" to the caller.

    Releases before 0.8.4 retain the historical missing-cosign compatibility
    warning.  Protocol-2-capable releases (0.8.4+) require local Sigstore
    verification against the exact protected release workflow identity;
    ``--allow-unverified`` cannot weaken that modern provenance boundary.
    """
    dest = _download_optional_release_asset(version, _CHECKSUMS_FILENAME, staging_dir)
    if not dest:
        return None

    _verify_checksums_sigstore(
        version,
        staging_dir,
        dest,
        allow_unverified=allow_unverified,
    )

    out: dict[str, str] = {}
    try:
        with open(dest, encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                # goreleaser emits "<sha256>  <filename>" (two spaces).
                # We split on whitespace to tolerate single-space variants
                # from sha256sum / shasum output styles.
                parts = line.split()
                if len(parts) != 2:
                    continue
                sha, name = parts
                # Defense in depth: only accept hex strings of expected length.
                if not _is_sha256_hex(sha):
                    continue
                name = name.removeprefix("./")
                out[name] = sha.lower()
    except OSError as exc:
        ux.warn(f"Could not parse checksums.txt: {exc}", indent="  ")
        return None

    if out:
        return out

    ux.err("checksums.txt did not contain any valid SHA-256 entries.", indent="  ")
    raise SystemExit(1)


def _fail_unsigned_checksums(
    message: str,
    allow_unverified: bool,
    *,
    override_allowed: bool = True,
) -> None:
    """Fail closed on an unsigned/unverifiable checksum manifest.

    When ``allow_unverified`` is set the operator has knowingly opted into
    the supply-chain risk, so we warn and let the caller proceed; otherwise
    we abort the upgrade.
    """
    if allow_unverified:
        ux.warn(f"{message} Continuing because --allow-unverified is set.", indent="  ")
        return
    ux.err(message, indent="  ")
    if override_allowed:
        ux.subhead("Re-run with --allow-unverified to override (UNSAFE).", indent="    ")
    else:
        ux.subhead(
            "Modern release provenance is mandatory; --allow-unverified cannot override it.",
            indent="    ",
        )
    raise SystemExit(1)


def _verify_checksums_sigstore(
    version: str,
    staging_dir: str,
    checksums_path: str,
    allow_unverified: bool = False,
) -> None:
    """Verify checksums.txt with its Sigstore cert/signature.

    Fails closed (``SystemExit``) when the manifest cannot be trusted.  Legacy
    releases may still honor ``allow_unverified``; 0.8.4+ never do:

    * F-0202: an unsigned manifest (no ``.sig``/``.pem`` assets, or only
      one of them) is untrusted — a checksum match against an unsigned
      manifest proves nothing about provenance.
    * Bad Sigstore signatures or identities are untrusted.
    * Missing local ``cosign`` is fatal for 0.8.4+, while older releases keep
      their compatibility warning.
    """
    strict_provenance = _version_key(version) >= _version_key(
        _STRICT_SIGSTORE_RELEASE_VERSION
    )
    legacy_allow_unverified = allow_unverified and not strict_provenance
    sig_path = _download_optional_release_asset(version, f"{_CHECKSUMS_FILENAME}.sig", staging_dir)
    cert_path = _download_optional_release_asset(version, f"{_CHECKSUMS_FILENAME}.pem", staging_dir)

    if not sig_path and not cert_path:
        _fail_unsigned_checksums(
            "checksums.txt is not signed (no Sigstore signature/certificate "
            "assets were published) — refusing to trust an unsigned checksum "
            "manifest.",
            legacy_allow_unverified,
            override_allowed=not strict_provenance,
        )
        return
    if not sig_path or not cert_path:
        _fail_unsigned_checksums(
            "checksums.txt Sigstore signature assets are incomplete — "
            "refusing to trust a checksum manifest that cannot be verified.",
            legacy_allow_unverified,
            override_allowed=not strict_provenance,
        )
        return

    cosign = shutil.which("cosign")
    if not cosign:
        if strict_provenance:
            ux.err(
                f"DefenseClaw {version} requires cosign to authenticate release provenance.",
                indent="  ",
            )
            ux.subhead(
                "Install cosign and retry; no release artifacts were accepted.",
                indent="    ",
            )
            raise SystemExit(1)
        ux.warn(
            "checksums.txt Sigstore signature is present, but cosign was "
            "not found on PATH; continuing with checksum verification only. "
            "Install cosign to verify release provenance.",
            indent="  ",
        )
        return

    identity_args = (
        ["--certificate-identity", _RELEASE_WORKFLOW_IDENTITY]
        if strict_provenance
        else [
            "--certificate-identity-regexp",
            f"^https://github.com/{GITHUB_REPO}/.+",
        ]
    )
    cmd = [
        cosign,
        "verify-blob",
        "--certificate",
        cert_path,
        "--signature",
        sig_path,
        *identity_args,
        "--certificate-oidc-issuer",
        "https://token.actions.githubusercontent.com",
        checksums_path,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        ux.err(f"Could not verify checksums.txt Sigstore signature: {exc}", indent="  ")
        raise SystemExit(1) from exc

    if result.returncode != 0:
        ux.err("checksums.txt Sigstore signature verification failed.", indent="  ")
        detail = (result.stderr or result.stdout or "").strip()
        for line in detail.splitlines()[:5]:
            ux.subhead(line[:200], indent="    ")
        raise SystemExit(1)

    ux.ok("Checksum signature verified (Sigstore)")


def _download_optional_release_asset(
    version: str,
    filename: str,
    staging_dir: str,
) -> str | None:
    """Download an optional release-side file, returning its path if present."""
    url = f"{_release_download_base()}/{version}/{filename}"
    dest = os.path.join(staging_dir, filename)
    resp = None
    for attempt in range(1, 4):
        try:
            resp = requests.get(
                url,
                timeout=15,
                allow_redirects=_release_asset_redirects_allowed(),
            )
        except requests.RequestException:
            if attempt < 3:
                time.sleep(2 ** (attempt - 1))
                continue
            return None
        if resp.status_code == 200:
            break
        if attempt < 3 and resp.status_code in {429, 500, 502, 503, 504}:
            time.sleep(2 ** (attempt - 1))
            continue
        return None
    if resp is None or resp.status_code != 200:
        return None
    try:
        with open(dest, "wb") as f:
            f.write(resp.content)
    except OSError as exc:
        ux.warn(f"Could not save optional release asset {filename}: {exc}", indent="  ")
        return None
    return dest


def _fail_missing_upgrade_manifest(message: str, allow_unverified: bool) -> None:
    """Fail closed when the release upgrade manifest cannot be fetched.

    Honors ``allow_unverified`` so an operator can deliberately upgrade a
    release that ships no ``upgrade-manifest.json`` (e.g. a legacy build).
    """
    if allow_unverified:
        ux.warn(
            f"{message}; continuing without release-specific upgrade policy (--allow-unverified).",
            indent="  ",
        )
        return
    ux.err(
        f"{message} — refusing to upgrade without the release's mandatory upgrade policy.",
        indent="  ",
    )
    ux.subhead("Re-run with --allow-unverified to override (UNSAFE).", indent="    ")
    raise SystemExit(1)


def _download_upgrade_manifest(
    version: str,
    staging_dir: str,
    checksums: dict[str, str] | None = None,
    allow_unverified: bool = False,
) -> dict[str, object] | None:
    """Download and validate the release's upgrade contract.

    ``defenseclaw upgrade`` itself is installed on the operator's machine,
    so future releases cannot assume the local upgrader learned new rules.
    The release-owned manifest is the forward-compatibility handoff: it can
    require a newer upgrade protocol, name migrations that must be recorded
    in the cursor, and make breaking releases fail before old code guesses.

    F-0203: the manifest carries mandatory upgrade policy. Silently
    skipping it when it cannot be fetched (404, request error, non-200)
    lets a hostile or partially-unavailable release endpoint suppress that
    policy. We fail closed by default; operators can opt out of the policy
    requirement with ``allow_unverified``.
    """
    url = f"{_release_download_base()}/{version}/{_UPGRADE_MANIFEST_FILENAME}"
    dest = os.path.join(staging_dir, _UPGRADE_MANIFEST_FILENAME)
    try:
        resp = requests.get(
            url,
            timeout=15,
            allow_redirects=_release_asset_redirects_allowed(),
        )
    except requests.RequestException as exc:
        _fail_missing_upgrade_manifest(
            f"Could not reach {_UPGRADE_MANIFEST_FILENAME}: {exc}",
            allow_unverified,
        )
        return None
    if resp.status_code == 404:
        _fail_missing_upgrade_manifest(
            f"{_UPGRADE_MANIFEST_FILENAME} not found for release {version}",
            allow_unverified,
        )
        return None
    if resp.status_code != 200:
        _fail_missing_upgrade_manifest(
            f"Could not fetch {_UPGRADE_MANIFEST_FILENAME} ({resp.status_code})",
            allow_unverified,
        )
        return None

    try:
        with open(dest, "wb") as f:
            f.write(resp.content)
    except OSError as exc:
        ux.err(f"Could not save {_UPGRADE_MANIFEST_FILENAME}: {exc}", indent="  ")
        raise SystemExit(1) from exc

    if checksums is not None:
        _verify_sha256(dest, _UPGRADE_MANIFEST_FILENAME, checksums)

    try:
        payload = json.loads(resp.content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        ux.err(f"Invalid {_UPGRADE_MANIFEST_FILENAME}: {exc}", indent="  ")
        raise SystemExit(1) from exc

    manifest = _validate_upgrade_manifest(payload, version)
    required = manifest["required_cli_migrations"]
    if required:
        ux.ok(f"Upgrade manifest loaded (required migrations: {', '.join(required)})")
    else:
        ux.ok("Upgrade manifest loaded")
    return manifest


def _validate_upgrade_manifest(payload: object, version: str) -> dict[str, object]:
    """Validate a parsed ``upgrade-manifest.json`` payload."""
    if not isinstance(payload, dict):
        ux.err(f"{_UPGRADE_MANIFEST_FILENAME} must be a JSON object.", indent="  ")
        raise SystemExit(1)

    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool):
        ux.err(f"{_UPGRADE_MANIFEST_FILENAME} missing integer schema_version.", indent="  ")
        raise SystemExit(1)
    if schema_version > 1:
        ux.err(
            f"Release {version} uses upgrade manifest schema {schema_version}, "
            "which this upgrader does not understand.",
            indent="  ",
        )
        _print_new_upgrade_script_hint(version)
        raise SystemExit(1)

    release_version = payload.get("release_version")
    if release_version != version:
        ux.err(
            f"{_UPGRADE_MANIFEST_FILENAME} release_version mismatch: expected {version}, got {release_version!r}.",
            indent="  ",
        )
        raise SystemExit(1)

    min_protocol = payload.get("min_upgrade_protocol", 1)
    if not isinstance(min_protocol, int) or isinstance(min_protocol, bool) or min_protocol < 1:
        ux.err(f"{_UPGRADE_MANIFEST_FILENAME} has invalid min_upgrade_protocol.", indent="  ")
        raise SystemExit(1)
    if min_protocol > _UPGRADE_PROTOCOL_VERSION:
        ux.err(
            f"Release {version} requires upgrade protocol {min_protocol}, "
            f"but this upgrader supports {_UPGRADE_PROTOCOL_VERSION}.",
            indent="  ",
        )
        _print_new_upgrade_script_hint(version)
        raise SystemExit(1)

    controller_protocol = payload.get("controller_upgrade_protocol", min_protocol)
    if (
        not isinstance(controller_protocol, int)
        or isinstance(controller_protocol, bool)
        or controller_protocol < min_protocol
    ):
        ux.err(
            f"{_UPGRADE_MANIFEST_FILENAME} has invalid controller_upgrade_protocol.",
            indent="  ",
        )
        raise SystemExit(1)

    policy = payload.get("migration_failure_policy", "warn")
    if policy not in ("warn", "fail"):
        ux.err(
            f"{_UPGRADE_MANIFEST_FILENAME} has invalid migration_failure_policy: {policy!r}.",
            indent="  ",
        )
        raise SystemExit(1)

    required_raw = payload.get("required_cli_migrations", [])
    if not isinstance(required_raw, list) or not all(isinstance(v, str) for v in required_raw):
        ux.err(
            f"{_UPGRADE_MANIFEST_FILENAME} required_cli_migrations must be a list of version strings.",
            indent="  ",
        )
        raise SystemExit(1)
    required = []
    seen: set[str] = set()
    for migration_version in required_raw:
        if not _VERSION_RE.fullmatch(migration_version):
            ux.err(
                f"{_UPGRADE_MANIFEST_FILENAME} contains invalid migration version {migration_version!r}.",
                indent="  ",
            )
            raise SystemExit(1)
        if migration_version not in seen:
            required.append(migration_version)
            seen.add(migration_version)

    bridge_keys = (
        "minimum_source_version",
        "required_bridge_version",
        "auto_bridge_from",
    )
    bridge_fields_present = [key in payload for key in bridge_keys]
    if any(bridge_fields_present) and not all(bridge_fields_present):
        ux.err(
            f"{_UPGRADE_MANIFEST_FILENAME} must declare the complete bridge contract: "
            + ", ".join(bridge_keys)
            + ".",
            indent="  ",
        )
        raise SystemExit(1)

    minimum_source = payload.get("minimum_source_version")
    required_bridge = payload.get("required_bridge_version")
    auto_bridge_from = payload.get("auto_bridge_from", [])
    if all(bridge_fields_present):
        for key, value in (
            ("minimum_source_version", minimum_source),
            ("required_bridge_version", required_bridge),
        ):
            if not isinstance(value, str) or _CANONICAL_VERSION_RE.fullmatch(value) is None:
                ux.err(
                    f"{_UPGRADE_MANIFEST_FILENAME} has invalid {key}; expected canonical X.Y.Z.",
                    indent="  ",
                )
                raise SystemExit(1)
        if not isinstance(auto_bridge_from, list) or not all(
            isinstance(item, str) and _CANONICAL_VERSION_RE.fullmatch(item) is not None
            for item in auto_bridge_from
        ):
            ux.err(
                f"{_UPGRADE_MANIFEST_FILENAME} auto_bridge_from must be a list of canonical X.Y.Z versions.",
                indent="  ",
            )
            raise SystemExit(1)
        if len(auto_bridge_from) != len(set(auto_bridge_from)):
            ux.err(
                f"{_UPGRADE_MANIFEST_FILENAME} auto_bridge_from contains duplicate versions.",
                indent="  ",
            )
            raise SystemExit(1)

        target_key = _version_key(version)
        minimum_key = _version_key(minimum_source)
        bridge_key = _version_key(required_bridge)
        if minimum_key > target_key:
            ux.err(
                f"{_UPGRADE_MANIFEST_FILENAME} minimum_source_version cannot exceed release_version.",
                indent="  ",
            )
            raise SystemExit(1)
        if bridge_key < minimum_key or bridge_key > target_key:
            ux.err(
                f"{_UPGRADE_MANIFEST_FILENAME} required_bridge_version must be between "
                "minimum_source_version and release_version.",
                indent="  ",
            )
            raise SystemExit(1)
        if any(_version_key(item) >= minimum_key for item in auto_bridge_from):
            ux.err(
                f"{_UPGRADE_MANIFEST_FILENAME} auto_bridge_from must contain only pre-bridge versions.",
                indent="  ",
            )
            raise SystemExit(1)

    manifest = {
        "schema_version": schema_version,
        "release_version": release_version,
        "min_upgrade_protocol": min_protocol,
        "controller_upgrade_protocol": controller_protocol,
        "migration_failure_policy": policy,
        "required_cli_migrations": required,
    }
    if all(bridge_fields_present):
        manifest.update(
            {
                "minimum_source_version": minimum_source,
                "required_bridge_version": required_bridge,
                "auto_bridge_from": list(auto_bridge_from),
            }
        )
    return manifest


def _version_key(version: str) -> tuple[int, int, int]:
    """Return the numeric ordering key for an already-validated X.Y.Z."""

    major, minor, patch = version.split(".")
    return int(major), int(minor), int(patch)


def _is_bridge_to_hard_cut_phase(
    manifest: dict[str, object] | None,
    source_version: str,
    target_version: str,
) -> bool:
    if not manifest:
        return False
    required_bridge = manifest.get("required_bridge_version")
    minimum_source = manifest.get("minimum_source_version")
    return (
        isinstance(required_bridge, str)
        and isinstance(minimum_source, str)
        and source_version == required_bridge
        and _version_key(source_version) < _version_key(target_version)
    )


def _require_hard_cut_manifest_contract(
    manifest: dict[str, object] | None,
    *,
    target_version: str,
    required: bool,
) -> None:
    """Make the 0.8.5+ release policy non-bypassable, including unsafe mode."""

    if not required:
        return
    required_migrations = manifest.get("required_cli_migrations") if manifest else None
    valid = (
        manifest is not None
        and manifest.get("min_upgrade_protocol") == 2
        and manifest.get("migration_failure_policy") == "fail"
        and isinstance(manifest.get("minimum_source_version"), str)
        and isinstance(manifest.get("required_bridge_version"), str)
        and isinstance(manifest.get("auto_bridge_from"), list)
        and isinstance(required_migrations, list)
        and _OBSERVABILITY_V8_MIGRATION_VERSION in required_migrations
    )
    if valid:
        return
    ux.err(
        f"Release {target_version} is missing the mandatory hard-cut upgrade contract; "
        "refusing to download or install target artifacts.",
        indent="  ",
    )
    ux.subhead(
        "No changes were made: no services were stopped and no installed artifacts were changed.",
        indent="    ",
    )
    raise SystemExit(1)


def _enforce_upgrade_source_contract(
    manifest: dict[str, object] | None,
    *,
    source_version: str,
    target_version: str,
    explicit_target: bool,
) -> None:
    """Reject an unsafe hard-cut edge before backup, stop, or installation.

    This gate is intentionally non-recursive.  The immutable 0.8.3 built-in
    controller only understands protocol 1, so it refuses a protocol-2
    manifest before reaching this function.  A one-command 0.8.3-to-latest
    transition therefore belongs to the release-owned shell/PowerShell
    resolver, which installs the bridge and then executes its fresh controller.
    """

    if not manifest or "minimum_source_version" not in manifest:
        return
    minimum_source = manifest.get("minimum_source_version")
    required_bridge = manifest.get("required_bridge_version")
    auto_bridge_raw = manifest.get("auto_bridge_from")
    if (
        not isinstance(minimum_source, str)
        or not isinstance(required_bridge, str)
        or not isinstance(auto_bridge_raw, list)
    ):
        # Validated manifests cannot reach this branch.  Keep the enforcement
        # boundary fail-closed for direct/internal callers as well.
        ux.err("Upgrade manifest bridge contract is incomplete; refusing to change installed state.", indent="  ")
        ux.subhead(
            "No changes were made: no services were stopped and no installed artifacts were changed.",
            indent="    ",
        )
        raise SystemExit(1)

    try:
        if _CANONICAL_VERSION_RE.fullmatch(source_version) is None:
            raise ValueError("source version is not canonical")
        source_key = _version_key(source_version)
        minimum_key = _version_key(minimum_source)
    except (AttributeError, TypeError, ValueError):
        source_key = None
        minimum_key = _version_key(minimum_source)
    if source_key is not None and source_key >= minimum_key:
        return

    auto_bridge_from = [item for item in auto_bridge_raw if isinstance(item, str)]
    if source_version in auto_bridge_from:
        ux.err(
            f"Release {target_version} requires DefenseClaw {minimum_source} or newer as its source; "
            f"installed version is {source_version}.",
            indent="  ",
        )
        if explicit_target:
            ux.subhead(
                f"The explicit --version {target_version} request cannot skip the required bridge.",
                indent="    ",
            )
        else:
            ux.subhead("The built-in latest-version path cannot install the bridge recursively.", indent="    ")
        ux.subhead(f"Bridge first: defenseclaw upgrade --version {required_bridge}", indent="    ")
        ux.subhead(f"Then retry:  defenseclaw upgrade --version {target_version}", indent="    ")
        ux.subhead(
            "For a one-command old-to-latest upgrade, use the release-owned shell or PowerShell resolver.",
            indent="    ",
        )
    else:
        supported = ", ".join(auto_bridge_from) if auto_bridge_from else "none declared"
        ux.err(
            f"Installed version {source_version!r} is not a supported source for the "
            f"{required_bridge} bridge to {target_version}.",
            indent="  ",
        )
        ux.subhead(f"Supported automatic bridge sources: {supported}", indent="    ")
        ux.subhead(
            f"Supported path (shell): scripts/upgrade.sh --version {required_bridge}",
            indent="    ",
        )
        ux.subhead(
            f"Supported path (PowerShell): .\\scripts\\upgrade.ps1 -Version {required_bridge}",
            indent="    ",
        )
        ux.subhead(
            f"Then run the release-owned upgrade resolver for latest, or explicitly request {target_version}.",
            indent="    ",
        )
    ux.subhead(
        "No changes were made: no services were stopped and no installed artifacts were changed.",
        indent="    ",
    )
    raise SystemExit(1)


def _print_new_upgrade_script_hint(version: str) -> None:
    release_url = f"https://github.com/{GITHUB_REPO}/releases/tag/{version}"
    ux.subhead(
        "Use the release-owned shell or PowerShell upgrade resolver; "
        "the installed controller made no changes:",
        indent="    ",
    )
    ux.subhead(
        release_url,
        indent="    ",
    )


def _assert_required_cli_migrations(
    manifest: dict[str, object] | None,
    data_dir: str,
) -> None:
    """Warn or fail if the release manifest named migrations that did not apply."""
    if not manifest:
        return
    required = manifest.get("required_cli_migrations", [])
    policy = manifest.get("migration_failure_policy", "warn")
    if not isinstance(required, list) or not required:
        return

    from defenseclaw import migration_state

    state = migration_state.load(data_dir)
    missing = [
        version for version in required if isinstance(version, str) and not migration_state.is_applied(state, version)
    ]
    if not missing:
        return

    label = "Required" if policy == "fail" else "Expected"
    ux.warn(
        f"{label} migration(s) were not recorded in the migration cursor: " + ", ".join(missing),
        indent="  ",
    )
    if policy == "fail":
        ux.subhead(
            "The release manifest marks these migrations as mandatory. "
            "Re-run the upgrade after fixing the migration error, or run "
            "`defenseclaw migrations status` for cursor details.",
            indent="    ",
        )
        raise SystemExit(1)


def _fetch_release_asset_digests(version: str) -> dict[str, str] | None:
    """Read GitHub's per-asset SHA-256 digests for ``version``.

    GitHub release assets expose a ``digest`` field (`sha256:<hex>`).
    We use it as a fallback for releases where ``checksums.txt`` was
    generated by GoReleaser before the Python wheel/plugin assets were
    attached. A missing API digest does not make the release unverifiable
    by itself; callers decide whether to warn or fail for required files.
    """
    try:
        resp = requests.get(
            f"{GITHUB_API}/releases/tags/{version}",
            headers=_github_headers(),
            timeout=15,
        )
        resp.raise_for_status()
        payload = resp.json()
    except (requests.RequestException, ValueError) as exc:
        ux.warn(f"Could not fetch GitHub asset digests: {exc}", indent="  ")
        return None

    assets = payload.get("assets", []) if isinstance(payload, dict) else []
    if not isinstance(assets, list):
        return None

    out: dict[str, str] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name")
        digest = asset.get("digest")
        if not isinstance(name, str) or not isinstance(digest, str):
            continue
        prefix = "sha256:"
        if not digest.startswith(prefix):
            continue
        sha = digest[len(prefix) :]
        if _is_sha256_hex(sha):
            out[name] = sha.lower()
    return out if out else None


def _fill_missing_checksums_from_release_assets(
    version: str,
    checksums: dict[str, str],
    artifact_names: list[str],
    allow_unverified: bool = False,
) -> None:
    """Fill required checksum gaps from GitHub release asset metadata.

    F-0582 (BREAKING CHANGE): GitHub per-asset ``digest`` values are UNSIGNED
    metadata from the (untrusted) release service. Filling a gap in the
    Sigstore-verified ``checksums.txt`` from them silently downgrades that
    artifact from signed to unsigned authentication. We therefore refuse to do
    this unless the operator explicitly accepted the risk with
    ``--allow-unverified`` — and even then we warn, naming each downgraded
    artifact. Without the flag the gap is left untouched so ``_verify_sha256``
    fails closed on the missing (unsigned) artifact rather than trusting it.
    """
    missing = [name for name in artifact_names if name not in checksums]
    if not missing:
        return

    if not allow_unverified:
        # Leave the gap: the signed manifest does not cover these artifacts.
        # _verify_sha256 will refuse to install them ("No checksum entry"),
        # which is the intended fail-closed behavior. Surface why up front so
        # the operator gets an actionable message before the hard failure.
        ux.warn(
            "Signed checksums.txt is missing entries for: "
            + ", ".join(missing)
            + ". Refusing to fill them from unsigned GitHub asset digests.",
            indent="  ",
        )
        ux.subhead(
            "Re-run with --allow-unverified to install these artifacts using unsigned GitHub asset digests (UNSAFE).",
            indent="    ",
        )
        return

    asset_digests = _fetch_release_asset_digests(version)
    if not asset_digests:
        return

    filled: list[str] = []
    for name in missing:
        digest = asset_digests.get(name)
        if digest:
            checksums[name] = digest
            filled.append(name)

    for name in filled:
        ux.warn(
            f"checksums.txt missing {name}; using UNSIGNED GitHub release "
            "asset digest (--allow-unverified). This artifact is NOT covered "
            "by the signed manifest.",
            indent="  ",
        )


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(c in _SHA256_HEX for c in value)


def _extract_gateway_tarball(tarball_path: str, staging_dir: str) -> None:
    """Safely extract the gateway tarball into ``staging_dir``.

    The release artifact is expected to be trusted once its checksum
    matches, but validating members is still cheap defense in depth: an
    archive that tries path traversal, absolute paths, or symlink/hardlink
    tricks is never allowed to write outside the staging directory.
    """
    root = os.path.realpath(staging_dir)
    try:
        with tarfile.open(tarball_path, mode="r:gz") as tar:
            members = tar.getmembers()
            for member in members:
                target = os.path.realpath(os.path.join(staging_dir, member.name))
                if not member.name or os.path.isabs(member.name):
                    ux.err(f"Unsafe tarball entry: {member.name!r}", indent="  ")
                    raise SystemExit(1)
                if target != root and not target.startswith(root + os.sep):
                    ux.err(f"Unsafe tarball entry escapes staging dir: {member.name}", indent="  ")
                    raise SystemExit(1)
                if member.issym() or member.islnk():
                    ux.err(f"Unsafe tarball link entry: {member.name}", indent="  ")
                    raise SystemExit(1)
                if not (member.isfile() or member.isdir()):
                    ux.err(f"Unsupported tarball entry type: {member.name}", indent="  ")
                    raise SystemExit(1)
            try:
                tar.extractall(staging_dir, members=members, filter="data")
            except TypeError:
                # Python < 3.12 does not support extraction filters; the
                # explicit member validation above covers the same hazards.
                tar.extractall(staging_dir, members=members)
    except tarfile.TarError as exc:
        ux.err(f"Could not extract gateway tarball: {exc}", indent="  ")
        raise SystemExit(1) from exc
    except OSError as exc:
        ux.err(f"Could not write gateway files from tarball: {exc}", indent="  ")
        raise SystemExit(1) from exc


def _extract_gateway_zip(zip_path: str, staging_dir: str) -> None:
    """Safely extract the Windows gateway .zip into ``staging_dir``.

    Mirrors the defense-in-depth of ``_extract_gateway_tarball``: even a
    checksum-verified archive is validated entry-by-entry so a malicious or
    corrupted zip can never write outside the staging directory via absolute
    paths or ``..`` traversal. ZIP has no symlink member type the stdlib will
    materialize here, so the path checks are the relevant guard.
    """
    root = os.path.realpath(staging_dir)
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for name in zf.namelist():
                # Normalize Windows separators so a "..\\" entry is caught the
                # same as "../" on a POSIX extractor.
                normalized = name.replace("\\", "/")
                if not normalized or normalized.startswith("/") or os.path.isabs(normalized):
                    ux.err(f"Unsafe zip entry: {name!r}", indent="  ")
                    raise SystemExit(1)
                target = os.path.realpath(os.path.join(staging_dir, normalized))
                if target != root and not target.startswith(root + os.sep):
                    ux.err(f"Unsafe zip entry escapes staging dir: {name}", indent="  ")
                    raise SystemExit(1)
            zf.extractall(staging_dir)
    except zipfile.BadZipFile as exc:
        ux.err(f"Could not extract gateway zip: {exc}", indent="  ")
        raise SystemExit(1) from exc
    except OSError as exc:
        ux.err(f"Could not write gateway files from zip: {exc}", indent="  ")
        raise SystemExit(1) from exc


def _verify_sha256(
    path: str,
    filename: str,
    checksums: dict[str, str],
) -> None:
    """Verify ``path``'s SHA-256 against ``checksums[filename]``.

    Raises ``SystemExit(1)`` on mismatch — a tampered or corrupted
    artifact must never reach ``_install_gateway`` / ``_install_wheel``.
    A missing entry in the manifest is also fatal: it would otherwise
    let an attacker who can drop a file with a novel name into the
    release tree slip past verification.
    """
    expected = checksums.get(filename)
    if not expected:
        ux.err(
            f"No checksum entry for {filename} in checksums.txt or GitHub asset metadata — "
            "refusing to install an unrecognized artifact.",
            indent="  ",
        )
        raise SystemExit(1)

    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError as exc:
        ux.err(f"Could not hash {path}: {exc}", indent="  ")
        raise SystemExit(1) from exc
    actual = h.hexdigest().lower()
    if actual != expected.lower():
        ux.err(
            f"Checksum mismatch for {filename}: expected {expected}, got {actual}",
            indent="  ",
        )
        ux.err(
            "Refusing to install — possible tampering or corrupted download.",
            indent="    ",
        )
        raise SystemExit(1)


def _install_gateway(
    binary_path: str,
    os_name: str,
    backup_dir: str | None = None,
) -> str:
    """Install a pre-downloaded gateway binary.

    When ``backup_dir`` is supplied AND a previous gateway binary exists,
    it's snapshotted to ``<backup_dir>/defenseclaw-gateway.previous``
    before being overwritten. Operators can roll back manually with::

        cp <backup_dir>/defenseclaw-gateway.previous ~/.local/bin/defenseclaw-gateway
        defenseclaw-gateway restart

    The snapshot is best-effort — a failure to copy the previous binary
    must not block a fresh install where there's nothing to snapshot.
    """
    install_dir = os.path.expanduser("~/.local/bin")
    os.makedirs(install_dir, exist_ok=True)
    target = os.path.join(install_dir, _installed_gateway_filename(os_name))

    if backup_dir and os.path.isfile(target):
        snapshot = os.path.join(backup_dir, _installed_gateway_filename(os_name) + ".previous")
        try:
            shutil.copy2(target, snapshot)
            if os_name != "windows":
                os.chmod(snapshot, 0o755)
            ux.ok(f"Snapshotted previous gateway → {snapshot}")
        except OSError as exc:
            ux.warn(
                f"Could not snapshot previous gateway: {exc}",
                indent="  ",
            )

    # Publish from a fully copied, flushed same-directory file. A power loss or
    # SIGKILL before os.replace leaves the old gateway intact; after os.replace
    # the target names complete candidate bytes, never a truncated in-place
    # copy. On macOS, ad-hoc signing is also completed before publication.
    descriptor, temporary = tempfile.mkstemp(prefix=".defenseclaw-gateway-", dir=install_dir)
    os.close(descriptor)
    try:
        shutil.copy2(binary_path, temporary)
        if os_name != "windows":
            os.chmod(temporary, 0o755)
            if os_name == "darwin":
                _run_phase_two_mutator(
                    ["codesign", "-f", "-s", "-", temporary],
                    capture_output=True,
                    check=False,
                )
        descriptor = os.open(temporary, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, target)
        if os.name == "posix":
            directory_fd = os.open(install_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    ux.ok("Gateway binary installed")
    return target


def _verify_installed_gateway_version(binary_path: str, expected: str) -> None:
    """Confirm the freshly-installed gateway reports ``expected``.

    A version mismatch indicates either a corrupted tarball that
    extracted but produced an unexpected binary, or a failed copy into
    ``~/.local/bin/defenseclaw-gateway``. We invoke the exact installed
    path returned by ``_install_gateway`` so PATH ordering cannot turn
    this check into a false positive or false negative.

    This is a soft check — we warn but don't abort. A binary that fails
    to report ``--version`` may still start cleanly under the right
    flags, and the subsequent health probe will catch a genuinely broken
    install. The point is to surface the discrepancy, not to gate the
    rest of the upgrade.
    """
    if not os.path.isfile(binary_path):
        ux.warn(
            f"Installed gateway binary is missing: {binary_path}",
            indent="  ",
        )
        return
    try:
        result = subprocess.run(
            [binary_path, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        ux.warn(f"Could not invoke {binary_path} --version: {exc}", indent="  ")
        return

    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if expected in output:
        ux.ok(f"Gateway binary verified ({expected})")
        return

    ux.warn(
        f"Gateway version verification failed: expected {expected}",
        indent="  ",
    )
    if output:
        first_line = output.splitlines()[0][:200]
        ux.subhead(f"binary reported: {first_line}", indent="    ")
    ux.subhead(
        "Continuing — health probe below will catch a genuinely broken install.",
        indent="    ",
    )


def _print_migration_cursor_summary(data_dir: str) -> None:
    """Print a one-line summary of which migrations the cursor recorded.

    The cursor at ``<data_dir>/.migration_state.json`` is the source of
    truth for "which migrations have observably executed on this host."
    Printing it after every upgrade gives operators a stable artifact
    to grep when triaging "did the 0.4.0 token bootstrap actually run?"
    questions. Falls silent on missing/corrupt cursors — the surrounding
    upgrade flow already surfaces those via ``defenseclaw doctor``.
    """
    try:
        from defenseclaw import migration_state
    except ImportError:
        return
    state = migration_state.load(data_dir)
    if state is None:
        return
    if state.applied:
        applied_repr = ", ".join(state.applied)
        ux.subhead(f"cursor: applied=[{applied_repr}]", indent="    ")
    else:
        ux.subhead("cursor: applied=[] (no migrations recorded)", indent="    ")


def _check_post_upgrade_drift(target_version: str) -> None:
    """Surface component drift at the end of the upgrade flow.

    The upgrade only refreshes the CLI and gateway. The OpenClaw plugin
    ships separately (via the release tarball, installed by install.sh),
    so a successful upgrade can still leave the operator running a
    target-version gateway against a stale-version plugin — silently
    breaking guardrail enforcement until the operator notices via
    ``defenseclaw version``. Surfacing drift here gives them an
    actionable warning at the moment the upgrade completes, not days
    later when a runtime error fires.

    Imports are deferred so this module's import time is unaffected
    when ``defenseclaw.commands.cmd_version`` is unavailable (e.g.,
    inside test rigs that patch the upgrade module's dependencies).
    """
    try:
        from defenseclaw.commands.cmd_version import (
            _cli_component,
            _compute_drift,
            _gateway_component,
            _plugin_component,
        )
    except ImportError as exc:
        ux.warn(f"Could not run drift check: {exc}", indent="  ")
        return

    try:
        components = [_cli_component(), _gateway_component(), _plugin_component()]
        drift = _compute_drift(components)
    except Exception as exc:
        ux.warn(f"Could not run drift check: {exc}", indent="  ")
        return
    if not drift:
        return

    click.echo()
    ux.warn("Component drift detected after upgrade:", indent="  ")
    for issue in drift:
        ux.subhead(issue, indent="    ")
    ux.subhead(
        "Run `defenseclaw version` for the full report. "
        "If the plugin is out of sync, reinstall it from the "
        f"{target_version} release tarball.",
        indent="    ",
    )


def _install_wheel(whl_path: str, os_name: str | None = None) -> None:
    """Install a pre-downloaded Python CLI wheel.

    ``os_name`` defaults to the running platform; the upgrade flow passes the
    detected OS explicitly. Windows venvs put executables under ``Scripts`` (not
    ``bin``), and we expose the CLI via a ``defenseclaw.cmd`` shim because
    ``os.symlink`` needs elevated/Developer-Mode privileges there.
    """
    if os_name is None:
        os_name = platform.system().lower()

    uv = shutil.which("uv")
    if not uv:
        ux.err("uv not found on PATH — cannot update Python CLI", indent="  ")
        raise SystemExit(1)

    venv = os.path.expanduser("~/.defenseclaw/.venv")
    scripts_subdir = "Scripts" if os_name == "windows" else "bin"
    python_exe = "python.exe" if os_name == "windows" else "python"
    venv_python = os.path.join(venv, scripts_subdir, python_exe)

    if not os.path.isfile(venv_python):
        click.echo(f"  {ux.dim('→')} Creating venv ...")
        _run_phase_two_mutator(
            [uv, "--no-config", "venv", venv, "--python", "3.12"],
            check=True,
        )

    _run_phase_two_mutator(
        [uv, "--no-config", "pip", "install", "--python", venv_python, "--quiet", whl_path],
        check=True,
    )

    install_dir = os.path.expanduser("~/.local/bin")
    os.makedirs(install_dir, exist_ok=True)

    if os_name == "windows":
        cli_exe = os.path.join(venv, "Scripts", "defenseclaw.exe")
        shim = os.path.join(install_dir, "defenseclaw.cmd")
        if os.path.isfile(cli_exe):
            # PATHEXT includes .CMD, so `defenseclaw` and
            # shutil.which("defenseclaw") both resolve to this shim.
            with open(shim, "w", encoding="ascii", newline="\r\n") as f:
                f.write(f'@echo off\r\n"{cli_exe}" %*\r\n')
    else:
        symlink = os.path.join(install_dir, "defenseclaw")
        venv_bin = os.path.join(venv, "bin", "defenseclaw")
        if os.path.isfile(venv_bin):
            if os.path.islink(symlink) or os.path.exists(symlink):
                os.remove(symlink)
            os.symlink(venv_bin, symlink)
    ux.ok("Python CLI installed")


def _run_installed_migrations(
    from_version: str,
    to_version: str,
    openclaw_home: str,
    data_dir: str,
    *,
    os_name: str | None = None,
) -> int:
    """Run migrations in the freshly installed managed venv.

    ``defenseclaw upgrade`` replaces the wheel while this command is already
    running. Importing ``defenseclaw.migrations`` in-process can therefore mix
    old modules cached in ``sys.modules`` with new files on disk. A child
    interpreter starts with a clean import graph from the just-installed wheel.
    """
    if os_name is None:
        os_name = platform.system().lower()

    venv = os.path.expanduser("~/.defenseclaw/.venv")
    venv_python = _venv_python_path(venv, os_name)
    if not os.path.isfile(venv_python):
        raise subprocess.CalledProcessError(1, [venv_python, "-c", "<missing managed venv>"])

    fd, result_path = tempfile.mkstemp(prefix="defenseclaw-migrations-", suffix=".json")
    os.close(fd)
    try:
        _run_phase_two_mutator(
            [
                venv_python,
                "-I",
                "-c",
                _INSTALLED_MIGRATION_SCRIPT,
                from_version,
                to_version,
                openclaw_home,
                data_dir,
                result_path,
            ],
            check=True,
        )
        with open(result_path, encoding="utf-8") as f:
            payload = json.load(f)
        count = payload.get("count")
        if not isinstance(count, int):
            raise subprocess.CalledProcessError(1, [venv_python, "-c", "<invalid migration count>"])
        return count
    finally:
        try:
            os.remove(result_path)
        except OSError:
            pass


def _run_installed_local_observability_bundle_upgrade(
    data_dir: str,
    backup_dir: str,
    target_version: str,
    *,
    os_name: str | None = None,
) -> dict[str, object]:
    """Run the target wheel's fail-closed bundle transaction when installed."""

    destination = os.path.join(data_dir, "observability-stack")
    if not os.path.lexists(destination):
        return {"installed": False}
    return _run_installed_local_observability_operation(
        "refresh",
        data_dir,
        backup_dir,
        target_version,
        os_name=os_name,
    )


def _run_installed_local_observability_bundle_restart(
    data_dir: str,
    *,
    health_timeout: int,
    os_name: str | None = None,
) -> dict[str, object]:
    """Run target-wheel restart/readiness checks after a safe refresh."""

    return _run_installed_local_observability_operation(
        "restart",
        data_dir,
        "",
        str(health_timeout),
        os_name=os_name,
    )


def _run_installed_local_observability_operation(
    operation: str,
    data_dir: str,
    backup_dir: str,
    value: str,
    *,
    os_name: str | None,
) -> dict[str, object]:
    if os_name is None:
        os_name = platform.system().lower()
    venv = os.path.expanduser("~/.defenseclaw/.venv")
    venv_python = _venv_python_path(venv, os_name)
    if not os.path.isfile(venv_python):
        raise _LocalBundleUpgradeInvocationError("target_cli_missing", "invoke")

    child_timeout = 300
    if operation == "restart":
        try:
            child_timeout = max(child_timeout, int(value) + 60)
        except ValueError as exc:
            raise _LocalBundleUpgradeInvocationError("invalid_timeout", "invoke") from exc

    fd, result_path = tempfile.mkstemp(prefix="defenseclaw-local-bundle-", suffix=".json")
    os.close(fd)
    script = """
import json
import sys

from defenseclaw.bundle_refresh import (
    LocalObservabilityUpgradeError,
    restart_upgraded_local_observability_stack,
    upgrade_local_observability_stack,
)

try:
    if sys.argv[1] == "refresh":
        result = upgrade_local_observability_stack(
            sys.argv[2],
            sys.argv[3],
            bundle_version=sys.argv[4],
        )
    elif sys.argv[1] == "restart":
        result = restart_upgraded_local_observability_stack(
            sys.argv[2],
            timeout=int(sys.argv[4]),
        )
    else:
        raise LocalObservabilityUpgradeError("invalid_operation", "invoke")
    payload = {"ok": True, "result": result.to_dict()}
except LocalObservabilityUpgradeError as exc:
    payload = {"ok": False, "code": exc.code, "phase": exc.phase}
except Exception:
    payload = {"ok": False, "code": "unexpected_failure", "phase": "invoke"}

with open(sys.argv[5], "w", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True)
sys.exit(0 if payload["ok"] else 1)
"""
    try:
        completed = _run_phase_two_mutator(
            [
                venv_python,
                "-c",
                script,
                operation,
                data_dir,
                backup_dir,
                value,
                result_path,
            ],
            capture_output=True,
            text=True,
            timeout=child_timeout,
            check=False,
        )
        try:
            with open(result_path, encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise _LocalBundleUpgradeInvocationError("result_unavailable", "invoke") from exc
        if not isinstance(payload, dict):
            raise _LocalBundleUpgradeInvocationError("result_invalid", "invoke")
        if completed.returncode != 0 or payload.get("ok") is not True:
            code = payload.get("code")
            phase = payload.get("phase")
            raise _LocalBundleUpgradeInvocationError(
                code if isinstance(code, str) and re.fullmatch(r"[a-z0-9_]+", code) else "child_failed",
                phase if isinstance(phase, str) and re.fullmatch(r"[a-z0-9_]+", phase) else "invoke",
            )
        result = payload.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("installed"), bool):
            raise _LocalBundleUpgradeInvocationError("result_invalid", "invoke")
        return result
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _LocalBundleUpgradeInvocationError("child_failed", "invoke") from exc
    finally:
        try:
            os.remove(result_path)
        except OSError:
            pass


def _venv_python_path(venv: str, os_name: str) -> str:
    scripts_subdir = "Scripts" if os_name == "windows" else "bin"
    python_exe = "python.exe" if os_name == "windows" else "python"
    return os.path.join(venv, scripts_subdir, python_exe)


def _handoff_to_installed_upgrade(
    target_version: str,
    *,
    health_timeout: int,
    allow_unverified: bool = False,
    os_name: str | None = None,
) -> NoReturn:
    """Terminate through a fresh installed-CLI upgrade process.

    A release-owned resolver may install the bridge as one phase and then use
    this primitive for the hard-cut phase.  The child runs the managed venv's
    interpreter in isolated mode, so it imports the newly installed wheel
    rather than modules cached by the pre-bridge process.  This helper never
    installs a bridge and never returns, including when the child succeeds.
    """

    if os.environ.get(_UPGRADE_HANDOFF_ENV):
        ux.err("Refusing a recursive upgrade handoff; installed state was not changed.", indent="  ")
        raise SystemExit(1)

    normalized_target = _normalize_target_version(target_version)
    if os_name is None:
        os_name = platform.system().lower()
    managed_venv = os.path.expanduser("~/.defenseclaw/.venv")
    venv_python = _venv_python_path(managed_venv, os_name)
    if not os.path.isfile(venv_python):
        ux.err("Fresh-process upgrade handoff could not find the managed CLI interpreter.", indent="  ")
        raise SystemExit(1)

    argv = [
        venv_python,
        "-I",
        "-m",
        "defenseclaw.main",
        "upgrade",
        "--yes",
        "--version",
        normalized_target,
        "--health-timeout",
        str(health_timeout),
    ]
    if allow_unverified:
        argv.append("--allow-unverified")

    child_env = os.environ.copy()
    # Isolated mode already ignores Python environment injection.  Removing
    # these variables as well makes that boundary explicit to wrappers and to
    # platforms whose launcher performs work before Python processes ``-I``.
    child_env.pop("PYTHONHOME", None)
    child_env.pop("PYTHONPATH", None)
    child_env[_UPGRADE_HANDOFF_ENV] = "1"
    try:
        completed = subprocess.run(argv, check=False, env=child_env)
    except OSError as exc:
        ux.err(f"Fresh-process upgrade handoff failed: {type(exc).__name__}", indent="  ")
        raise SystemExit(1) from None
    raise SystemExit(completed.returncode)


def _fail_wheel_preflight(message: str, exc: subprocess.CalledProcessError | None = None) -> None:
    ux.err(message, indent="  ")
    if exc is not None:
        output = "\n".join(part for part in (exc.stderr, exc.stdout) if part).strip()
        if output:
            tail = "\n".join(output.splitlines()[-20:])
            ux.subhead(tail, indent="    ")
    ux.subhead("No services were stopped and no installed artifacts were changed.", indent="    ")
    raise SystemExit(1)


def _assigned_module_value(module: ast.Module, name: str) -> ast.expr:
    values: list[ast.expr] = []
    for statement in module.body:
        if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            if statement.target.id == name and statement.value is not None:
                values.append(statement.value)
        elif isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in statement.targets
        ):
            values.append(statement.value)
    if len(values) != 1:
        raise ValueError(f"target wheel must define {name} exactly once")
    return values[0]


def _has_module_assignment(module: ast.Module, name: str) -> bool:
    for statement in module.body:
        if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            if statement.target.id == name:
                return True
        elif isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in statement.targets
        ):
            return True
    return False


def _literal_int_versions(module: ast.Module, name: str) -> frozenset[int]:
    try:
        value = ast.literal_eval(_assigned_module_value(module, name))
    except (ValueError, TypeError, SyntaxError) as exc:
        raise ValueError(f"target wheel {name} is not a literal sequence") from exc
    if (
        not isinstance(value, (list, tuple))
        or not value
        or any(not isinstance(item, int) or isinstance(item, bool) or item <= 0 for item in value)
    ):
        raise ValueError(f"target wheel {name} is invalid")
    if len(value) != len(set(value)):
        raise ValueError(f"target wheel {name} contains duplicates")
    return frozenset(value)


def _literal_migration_versions(module: ast.Module) -> frozenset[str]:
    value = _assigned_module_value(module, "MIGRATIONS")
    if not isinstance(value, (ast.List, ast.Tuple)):
        raise ValueError("target wheel MIGRATIONS is not a literal sequence")
    function_names = {statement.name for statement in module.body if isinstance(statement, ast.FunctionDef)}
    versions: list[str] = []
    for item in value.elts:
        if not isinstance(item, (ast.List, ast.Tuple)) or len(item.elts) != 3:
            raise ValueError("target wheel MIGRATIONS contains an invalid row")
        version, description, migration = item.elts
        if not isinstance(version, ast.Constant) or not isinstance(version.value, str):
            raise ValueError("target wheel MIGRATIONS contains a dynamic version")
        if _VERSION_RE.fullmatch(version.value) is None:
            raise ValueError("target wheel MIGRATIONS contains an invalid version")
        if not isinstance(description, ast.Constant) or not isinstance(description.value, str) or not description.value:
            raise ValueError("target wheel MIGRATIONS contains an invalid description")
        if not isinstance(migration, ast.Name) or migration.id not in function_names:
            raise ValueError("target wheel MIGRATIONS contains an invalid callable")
        versions.append(version.value)
    if len(versions) != len(set(versions)):
        raise ValueError("target wheel MIGRATIONS contains duplicate versions")
    if versions != sorted(versions, key=lambda version: tuple(int(part) for part in version.split("."))):
        raise ValueError("target wheel MIGRATIONS is not sorted")
    return frozenset(versions)


def _validate_run_migrations_contract(function: ast.FunctionDef) -> None:
    """Require the positional API used by the installed-target runner."""

    positional = (*function.args.posonlyargs, *function.args.args)
    expected = ("from_version", "to_version", "openclaw_home", "data_dir")
    if tuple(argument.arg for argument in positional) != expected:
        raise ValueError(
            "target wheel run_migrations must declare positional parameters "
            "(from_version, to_version, openclaw_home, data_dir)"
        )
    required_keyword_only = [
        argument.arg
        for argument, default in zip(
            function.args.kwonlyargs,
            function.args.kw_defaults,
            strict=True,
        )
        if default is None
    ]
    if required_keyword_only:
        raise ValueError(
            "target wheel run_migrations has unsupported required keyword-only parameter(s): "
            + ", ".join(required_keyword_only)
        )


def _target_migration_capabilities(whl_path: str) -> _TargetMigrationCapabilities:
    """Inspect a target wheel without importing or executing target code."""

    try:
        with zipfile.ZipFile(whl_path) as archive:
            migration_members = [item for item in archive.infolist() if item.filename == "defenseclaw/migrations.py"]
            if len(migration_members) != 1:
                raise ValueError("target wheel must contain one defenseclaw/migrations.py")
            migration_member = migration_members[0]
            if migration_member.file_size > _MAX_WHEEL_MIGRATIONS_BYTES:
                raise ValueError("target wheel migrations.py exceeds its size limit")
            migration_source = archive.read(migration_member).decode("utf-8")

            metadata_messages = []
            for item in archive.infolist():
                if not item.filename.endswith(".dist-info/METADATA"):
                    continue
                if item.file_size > _MAX_WHEEL_METADATA_BYTES:
                    raise ValueError("target wheel metadata exceeds its size limit")
                message = email.parser.Parser().parsestr(archive.read(item).decode("utf-8"))
                normalized_name = (message.get("Name") or "").lower().replace("_", "-")
                if normalized_name == "defenseclaw":
                    metadata_messages.append(message)
            if len(metadata_messages) != 1:
                raise ValueError("target wheel must contain one DefenseClaw metadata record")
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ValueError("target wheel migration contract is unreadable") from exc

    try:
        module = ast.parse(migration_source, filename="defenseclaw/migrations.py")
    except (RecursionError, SyntaxError, ValueError) as exc:
        raise ValueError("target wheel migrations.py is invalid Python") from exc
    functions = [
        node
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run_migrations"
    ]
    if len(functions) != 1 or isinstance(functions[0], ast.AsyncFunctionDef):
        raise ValueError("target wheel must define one synchronous run_migrations")
    function = functions[0]
    _validate_run_migrations_contract(function)
    parameters = {
        argument.arg
        for argument in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
    }
    package_version = metadata_messages[0].get("Version") or ""
    if _VERSION_RE.fullmatch(package_version) is None:
        raise ValueError("target wheel metadata has an invalid version")

    if _has_module_assignment(module, "SUPPORTED_CONFIG_VERSIONS"):
        supported_config_versions = _literal_int_versions(module, "SUPPORTED_CONFIG_VERSIONS")
    else:
        # Wheels before the v8 hard cut have no explicit config capability.
        supported_config_versions = frozenset()
    return _TargetMigrationCapabilities(
        package_version=package_version,
        run_migrations_parameters=frozenset(parameters),
        migration_versions=_literal_migration_versions(module),
        supported_config_versions=supported_config_versions,
    )


def _require_target_phase_two_mutator_wrapper(whl_path: str) -> None:
    """Require the crash-surviving child wrapper before a hard-cut install."""

    try:
        with zipfile.ZipFile(whl_path) as archive:
            members = [
                item
                for item in archive.infolist()
                if item.filename == "defenseclaw/phase_two_mutator.py"
            ]
            if len(members) != 1 or not 0 < members[0].file_size <= _MAX_WHEEL_MUTATOR_WRAPPER_BYTES:
                raise ValueError("target wheel lacks its bounded phase-two mutator wrapper")
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ValueError("target wheel phase-two mutator wrapper is unreadable") from exc


def _validate_target_migration_capabilities(
    capabilities: _TargetMigrationCapabilities,
    *,
    target_version: str,
    source_version: int | None,
    upgrade_manifest: dict[str, object] | None,
) -> None:
    if capabilities.package_version != target_version:
        raise ValueError(
            f"target wheel version is {capabilities.package_version}, expected {target_version}; "
            "use release-stamped artifacts"
        )
    required = upgrade_manifest.get("required_cli_migrations", []) if upgrade_manifest else []
    required_versions = {item for item in required if isinstance(item, str)}
    missing_required = sorted(required_versions - capabilities.migration_versions)
    if missing_required:
        raise ValueError("target wheel does not contain release-required migration(s): " + ", ".join(missing_required))
    target_key = tuple(int(part) for part in target_version.split("."))
    unreachable_required = sorted(
        version for version in required_versions if tuple(int(part) for part in version.split(".")) > target_key
    )
    if unreachable_required:
        raise ValueError(
            f"target {target_version} cannot run release-required migration(s): " + ", ".join(unreachable_required)
        )

    # The protocol-1-reachable 0.8.4 bridge intentionally has no v8 config
    # capability and no v8 migration.  Its job is to install this newer
    # controller, restart healthy on the existing v7 configuration, and hand
    # off from a fresh process.  Enforce v8 capability only for the actual
    # 0.8.5+ hard cut; bridge and legacy releases still receive the generic
    # package-version and manifest-required-migration checks above.
    cutover_key = _version_key(_OBSERVABILITY_V8_MIGRATION_VERSION)
    if _version_key(target_version) < cutover_key:
        return
    if _TARGET_CONFIG_VERSION not in capabilities.supported_config_versions:
        raise ValueError(f"target {target_version} does not support config_version: {_TARGET_CONFIG_VERSION}")
    if source_version is None:
        return
    if source_version > _TARGET_CONFIG_VERSION:
        raise ValueError(
            f"source config_version {source_version} is newer than target capability {_TARGET_CONFIG_VERSION}"
        )
    if source_version != _TARGET_CONFIG_VERSION:
        if _OBSERVABILITY_V8_MIGRATION_VERSION not in capabilities.migration_versions:
            raise ValueError(
                f"target {target_version} cannot migrate the existing configuration to config_version: "
                f"{_TARGET_CONFIG_VERSION}; use a release stamped "
                f"{_OBSERVABILITY_V8_MIGRATION_VERSION} or later"
            )


def _preflight_target_wheel_migrations(
    whl_path: str,
    target_version: str,
    upgrade_manifest: dict[str, object] | None,
) -> _TargetMigrationCapabilities:
    from defenseclaw.config import ConfigVersionError, source_config_version

    try:
        capabilities = _target_migration_capabilities(whl_path)
        if _version_key(target_version) >= _version_key(_OBSERVABILITY_V8_MIGRATION_VERSION):
            _require_target_phase_two_mutator_wrapper(whl_path)
        version = source_config_version()
        _validate_target_migration_capabilities(
            capabilities,
            target_version=target_version,
            source_version=version,
            upgrade_manifest=upgrade_manifest,
        )
    except (ConfigVersionError, ValueError) as exc:
        _fail_wheel_preflight(f"Target wheel cannot safely upgrade this installation: {exc}")
        raise AssertionError("unreachable") from exc
    ux.ok("Target wheel migration capabilities verified")
    return capabilities


def _preflight_wheel_install(
    whl_path: str,
    os_name: str | None = None,
    *,
    target_version: str | None = None,
    upgrade_manifest: dict[str, object] | None = None,
) -> None:
    """Resolve the downloaded wheel before the upgrade mutates services.

    A release wheel can be checksum-valid but dependency-unsatisfiable. Running
    uv's dry-run resolver before backup/stop/install keeps that failure mode
    from leaving the operator with a fresh gateway and the old Python CLI.
    """
    if target_version is not None:
        _preflight_target_wheel_migrations(whl_path, target_version, upgrade_manifest)
    if os_name is None:
        os_name = platform.system().lower()

    uv = shutil.which("uv")
    if not uv:
        ux.err("uv not found on PATH — cannot update Python CLI", indent="  ")
        raise SystemExit(1)

    click.echo(f"  {ux.dim('→')} Resolving Python CLI dependencies ...")

    managed_venv = os.path.expanduser("~/.defenseclaw/.venv")
    venv_python = _venv_python_path(managed_venv, os_name)
    cleanup_dir: str | None = None

    if not os.path.isfile(venv_python):
        cleanup_dir = tempfile.mkdtemp(prefix="defenseclaw-wheel-preflight-")
        preflight_venv = os.path.join(cleanup_dir, "venv")
        try:
            subprocess.run(
                [uv, "--no-config", "venv", preflight_venv, "--python", "3.12", "--quiet"],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            shutil.rmtree(cleanup_dir, ignore_errors=True)
            _fail_wheel_preflight("Could not create Python CLI preflight environment.", exc)
        venv_python = _venv_python_path(preflight_venv, os_name)

    try:
        subprocess.run(
            [uv, "--no-config", "pip", "install", "--python", venv_python, "--dry-run", "--quiet", whl_path],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        _fail_wheel_preflight("Python CLI wheel dependencies are unsatisfiable.", exc)
    finally:
        if cleanup_dir is not None:
            shutil.rmtree(cleanup_dir, ignore_errors=True)

    ux.ok("Python CLI dependency preflight passed")


def _poll_health(
    cfg,
    timeout_seconds: int = 60,
    *,
    expected_version: str | None = None,
) -> None:
    """Poll until the expected gateway process reports healthy.

    ``gateway.state=running`` alone is insufficient during a replacement or
    rollback: a target process that failed to stop can keep answering on the
    old socket and make the transaction look successful.  Release gateways
    expose their binary version in the health provenance quartet, so callers
    that know the expected release require an exact match before accepting the
    response.
    """
    from defenseclaw.gateway import OrchestratorClient

    bind = _api_bind_host(cfg)
    api_port = 18970
    token = ""
    if cfg:
        api_port = cfg.gateway.api_port
        token = cfg.gateway.resolved_token()

    # F-0701: the gateway bearer token authenticates to the local sidecar.
    # ``api_bind`` is operator config and may have been tampered to point at
    # an attacker-controlled host; never send the sidecar token anywhere but
    # loopback. For a non-loopback bind we probe health without the token
    # rather than leak the credential to that host.
    if token and not _is_loopback_host(bind):
        ux.warn(
            f"Gateway health probe host {bind!r} is not loopback; omitting the "
            "gateway bearer token from the health request.",
            indent="  ",
        )
        token = ""

    client = OrchestratorClient(host=bind, port=api_port, token=token)

    deadline = time.monotonic() + timeout_seconds
    # Treat the pre-first-probe window the same way the gateway does so the
    # first successful "starting" reply is recognized as a state change and
    # printed. A missing/unreachable endpoint is surfaced as "unreachable" on
    # the first transient failure instead of being silently swallowed, which
    # was the #96 gotcha — operators saw no output for the full 60s timeout
    # when the sidecar crashed mid-upgrade.
    last_state = ""
    last_err = ""
    last_reported_version = ""
    click.echo(f"  {ux.dim('→')} Waiting for gateway to become healthy (timeout {timeout_seconds}s) ...")

    while time.monotonic() < deadline:
        try:
            snap = client.health()
            if snap and isinstance(snap, dict):
                last_err = ""
                gw_state = snap.get("gateway", {}).get("state", "unknown")
                if gw_state != last_state:
                    click.echo(f"    {ux.dim('gateway:')} {gw_state}")
                    last_state = gw_state
                if gw_state == "running":
                    if expected_version is not None:
                        provenance = snap.get("provenance")
                        reported_version = (
                            provenance.get("binary_version")
                            if isinstance(provenance, dict)
                            else None
                        )
                        version_label = (
                            reported_version
                            if isinstance(reported_version, str) and reported_version
                            else "missing"
                        )
                        if reported_version != expected_version:
                            if version_label != last_reported_version:
                                click.echo(
                                    f"    {ux.dim('gateway version:')} {version_label} "
                                    f"(expected {expected_version})"
                                )
                                last_reported_version = version_label
                            time.sleep(2)
                            continue
                    ux.ok("Gateway is healthy")
                    return
            else:
                # 2xx with an empty/non-dict body — treat like unreachable so
                # the operator still sees a progress line instead of silence.
                err_label = "health endpoint returned no payload"
                if err_label != last_err:
                    click.echo(f"    {ux.dim('gateway:')} unreachable ({err_label})")
                    last_err = err_label
                    last_state = ""
        except (OSError, ValueError) as exc:
            # Print the first unreachable reason and any distinct follow-up
            # so the operator can correlate with gateway.log. We deliberately
            # don't flood on every retry — only on transitions.
            err_label = type(exc).__name__
            detail = str(exc).splitlines()[0] if str(exc) else ""
            if detail:
                err_label = f"{err_label}: {detail}"
            if err_label != last_err:
                click.echo(f"    {ux.dim('gateway:')} unreachable ({err_label})")
                last_err = err_label
                last_state = ""
        time.sleep(2)

    if expected_version is None:
        ux.warn(f"Gateway did not become healthy within {timeout_seconds}s")
    else:
        ux.warn(
            f"Gateway did not become healthy as version {expected_version} "
            f"within {timeout_seconds}s"
        )
    ux.subhead("Check telemetry: defenseclaw tui (canonical SQLite event history and destination status)")
    ux.subhead("Run:  defenseclaw-gateway status")
    raise SystemExit(1)


def _assert_gateway_quiesced(data_dir: str) -> None:
    """Fail closed when ``gateway.pid`` still identifies a live process.

    The daemon's stop command waits for its recorded process to exit.  This
    second, independent read closes the race between a nominally successful
    stop and replacing the gateway binary, and is required on Windows where a
    live executable cannot be atomically replaced.  A malformed or planted PID
    file is also not accepted as proof that shutdown completed.
    """

    from defenseclaw.process_liveness import pid_alive, process_is_gateway, read_pid_file

    pid_path = os.path.join(data_dir, "gateway.pid")
    try:
        info = os.lstat(pid_path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise OSError("gateway PID file could not be inspected after stop") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OSError("gateway PID file is not a real regular file after stop")

    pid = read_pid_file(pid_path)
    if pid is None:
        raise OSError("gateway PID file is malformed after stop")
    if not pid_alive(pid):
        return
    if process_is_gateway(pid):
        raise OSError(f"gateway process {pid} is still running after stop")
    raise OSError(f"gateway PID file points to an unverified live process {pid}")


def _is_loopback_host(host: str) -> bool:
    """Return True when ``host`` resolves to the local loopback interface.

    Used to decide whether it is safe to attach the gateway bearer token to
    an outbound health probe. We treat ``localhost`` and any loopback IP
    literal (IPv4 ``127.0.0.0/8`` or IPv6 ``::1``) as loopback. Anything
    else — including unspecified addresses like ``0.0.0.0`` and DNS names —
    is treated as non-loopback so the token is not leaked.
    """
    candidate = (host or "").strip().lower()
    if not candidate:
        # An empty bind resolves to 127.0.0.1 in _api_bind_host.
        return True
    if candidate == "localhost":
        return True
    candidate = candidate.strip("[]")
    if candidate == "localhost":
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def _api_bind_host(cfg) -> str:
    """Resolve the API bind address, mirroring sidecar.runAPI in Go."""
    if not cfg:
        return "127.0.0.1"
    api_bind = getattr(cfg.gateway, "api_bind", "")
    if api_bind:
        return api_bind
    if cfg.openshell.is_standalone() and cfg.guardrail.host not in ("", "localhost", "127.0.0.1"):
        return cfg.guardrail.host
    return "127.0.0.1"


def _download_file(url: str, dest: str) -> None:
    """Download a file from url to dest, raising on failure."""
    last_exc: requests.RequestException | None = None
    for attempt in range(1, 4):
        try:
            resp = requests.get(
                url,
                stream=True,
                timeout=60,
                allow_redirects=_release_asset_redirects_allowed(),
            )
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < 3:
                time.sleep(2 ** (attempt - 1))
                continue
            ux.err(f"Download failed: {exc}", indent="  ")
            raise SystemExit(1) from exc

        if resp.status_code != 200:
            if attempt < 3 and resp.status_code in {429, 500, 502, 503, 504}:
                time.sleep(2 ** (attempt - 1))
                continue
            ux.err(f"Download failed ({resp.status_code}): {url}", indent="  ")
            raise SystemExit(1)

        try:
            with open(dest, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            return
        except OSError as exc:
            ux.err(f"Could not save download to {dest}: {exc}", indent="  ")
            raise SystemExit(1) from exc

    if last_exc is not None:
        raise SystemExit(1) from last_exc


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _create_backup(cfg) -> str:
    """Back up ~/.defenseclaw/ config files and ~/.openclaw/openclaw.json."""
    data_dir = cfg.data_dir if cfg else os.path.expanduser("~/.defenseclaw")
    backup_root = os.path.join(data_dir, "backups")
    timestamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    backup_dir = _create_private_backup_directory(backup_root, timestamp)

    # Back up every file the connector-v3 migration may touch. Listing
    # them explicitly (rather than copying the whole data_dir) keeps
    # the backup small and predictable: an operator restoring the
    # backup gets exactly the credentials + state files they had
    # pre-upgrade, not a snapshot of unrelated cache directories.
    for fname in (
        "config.yaml",
        ".env",
        "guardrail_runtime.json",
        "device.key",
        "active_connector.json",
        "codex_backup.json",
        "claudecode_backup.json",
        "zeptoclaw_backup.json",
        "codex_config_backup.json",
    ):
        src = os.path.join(data_dir, fname)
        if os.path.isfile(src):
            shutil.copy2(src, backup_dir)
            ux.ok(f"Backed up: {fname}")

    policies_dir = os.path.join(data_dir, "policies")
    if os.path.isdir(policies_dir):
        shutil.copytree(policies_dir, os.path.join(backup_dir, "policies"))
        ux.ok("Backed up: policies/")

    connector_backups_dir = os.path.join(data_dir, "connector_backups")
    if os.path.isdir(connector_backups_dir):
        shutil.copytree(
            connector_backups_dir,
            os.path.join(backup_dir, "connector_backups"),
        )
        ux.ok("Backed up: connector_backups/")

    openclaw_home = os.path.expanduser(cfg.claw.home_dir) if cfg else os.path.expanduser("~/.openclaw")
    oc_json = os.path.join(openclaw_home, "openclaw.json")
    if os.path.isfile(oc_json):
        shutil.copy2(oc_json, os.path.join(backup_dir, "openclaw.json"))
        ux.ok("Backed up: openclaw.json")

    return backup_dir


def _acquire_bridge_rollback_artifacts(
    source_version: str,
    os_name: str,
    arch: str,
    staging_dir: str,
) -> str:
    """Prefer resolver staging, otherwise securely fetch the installed bridge."""

    supplied = any(
        os.environ.get(name)
        for name in (
            _STAGED_UPGRADE_ENV,
            _STAGED_BRIDGE_VERSION_ENV,
            _STAGED_BRIDGE_ARTIFACT_DIR_ENV,
        )
    )
    if supplied:
        if os.environ.get(_STAGED_UPGRADE_ENV) != "1":
            raise OSError(f"{_STAGED_UPGRADE_ENV}=1 is required for staged handoff")
        if os.environ.get(_STAGED_BRIDGE_VERSION_ENV) != source_version:
            raise OSError(f"{_STAGED_BRIDGE_VERSION_ENV} does not match the installed bridge")
        staged = os.environ.get(_STAGED_BRIDGE_ARTIFACT_DIR_ENV, "")
        if not staged:
            raise OSError(f"{_STAGED_BRIDGE_ARTIFACT_DIR_ENV} is required for staged handoff")
        staged = os.path.abspath(os.path.expanduser(staged))
        _validate_staged_bridge_artifact_set(staged, source_version, os_name, arch)
        return staged

    staged = os.path.join(staging_dir, "bridge-rollback-artifacts")
    os.mkdir(staged, 0o700)
    checksums = _download_checksums(source_version, staged, allow_unverified=False)
    if checksums is None:
        raise OSError("installed bridge release has no trusted checksum manifest")
    _download_upgrade_manifest(
        source_version,
        staged,
        checksums,
        allow_unverified=False,
    )
    _download_wheel(source_version, staged, checksums)
    _download_gateway(source_version, os_name, arch, staged, checksums)
    if os.name == "posix":
        os.chmod(staged, 0o700)
        for name in os.listdir(staged):
            path = os.path.join(staged, name)
            if os.path.isfile(path) and not os.path.islink(path):
                os.chmod(path, 0o600)
    _validate_staged_bridge_artifact_set(staged, source_version, os_name, arch)
    return staged


def _validate_staged_bridge_artifact_set(
    staged: str,
    source_version: str,
    os_name: str,
    arch: str,
) -> tuple[dict[str, str], str, str]:
    """Validate one resolver/fallback bridge artifact set without mutation."""

    _assert_private_staged_bridge_directory(staged)
    checksums_path = os.path.join(staged, _CHECKSUMS_FILENAME)
    signature_path = checksums_path + ".sig"
    certificate_path = checksums_path + ".pem"
    manifest_path = os.path.join(staged, _UPGRADE_MANIFEST_FILENAME)
    wheel_name = f"defenseclaw-{source_version}-py3-none-any.whl"
    archive_name = _gateway_archive_name(source_version, os_name, arch)
    wheel_path = os.path.join(staged, wheel_name)
    archive_path = os.path.join(staged, archive_name)
    for path in (
        checksums_path,
        signature_path,
        certificate_path,
        manifest_path,
        wheel_path,
        archive_path,
    ):
        _assert_private_staged_bridge_file(path)

    _verify_staged_checksums_signature(
        source_version,
        checksums_path,
        signature_path,
        certificate_path,
    )
    checksums = _parse_staged_checksums(checksums_path)
    for path, filename in (
        (manifest_path, _UPGRADE_MANIFEST_FILENAME),
        (wheel_path, wheel_name),
        (archive_path, archive_name),
    ):
        _verify_sha256(path, filename, checksums)
    try:
        with open(manifest_path, encoding="utf-8") as stream:
            source_manifest = _validate_upgrade_manifest(json.load(stream), source_version)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OSError("staged bridge manifest is invalid") from exc
    if source_manifest.get("min_upgrade_protocol") != 1:
        raise OSError("staged bridge manifest is not protocol-1 reachable")
    return checksums, wheel_path, archive_path


def _prepare_hard_cut_rollback_plan(
    cfg,
    backup_dir: str,
    *,
    source_version: str,
    os_name: str,
    arch: str,
    staged_artifact_dir: str | None = None,
) -> _HardCutRollbackPlan:
    """Retain authenticated bridge artifacts and exact mutable state.

    The release-owned resolver supplies a private staged directory containing
    these release filenames:

    * ``checksums.txt``, ``checksums.txt.sig``, ``checksums.txt.pem``;
    * ``upgrade-manifest.json`` for ``source_version``;
    * ``defenseclaw-<source_version>-py3-none-any.whl``;
    * the platform gateway archive from :func:`_gateway_archive_name`.

    The resolver has already verified the set, but this process verifies the
    signature/checksums again before any service or installed artifact changes.
    """

    staged = os.path.abspath(
        os.path.expanduser(
            staged_artifact_dir
            if staged_artifact_dir is not None
            else os.environ.get(_STAGED_BRIDGE_ARTIFACT_DIR_ENV, "")
        )
    )
    if not staged_artifact_dir and not os.environ.get(_STAGED_BRIDGE_ARTIFACT_DIR_ENV):
        raise OSError(f"{_STAGED_BRIDGE_ARTIFACT_DIR_ENV} is required for hard-cut rollback")
    wheel_name = f"defenseclaw-{source_version}-py3-none-any.whl"
    archive_name = _gateway_archive_name(source_version, os_name, arch)
    checksums, wheel_path, archive_path = _validate_staged_bridge_artifact_set(
        staged,
        source_version,
        os_name,
        arch,
    )

    rollback_root = os.path.join(backup_dir, "hard-cut-rollback")
    os.mkdir(rollback_root, 0o700)
    _protect_windows_rollback_directory(rollback_root)
    retained_wheel = os.path.join(rollback_root, wheel_name)
    retained_archive = os.path.join(rollback_root, archive_name)
    if os.name == "nt":
        from defenseclaw import windows_acl

        retained_security = windows_acl.private_security_for_directory(rollback_root)
        with open(wheel_path, "rb") as stream:
            windows_acl.write_new_file(retained_wheel, stream.read(), retained_security)
        with open(archive_path, "rb") as stream:
            windows_acl.write_new_file(retained_archive, stream.read(), retained_security)
    else:
        shutil.copy2(wheel_path, retained_wheel, follow_symlinks=False)
        shutil.copy2(archive_path, retained_archive, follow_symlinks=False)
        os.chmod(retained_wheel, 0o600)
        os.chmod(retained_archive, 0o600)
    if _sha256_file(retained_wheel) != checksums[wheel_name]:
        raise OSError("retained bridge wheel digest mismatch")
    if _sha256_file(retained_archive) != checksums[archive_name]:
        raise OSError("retained bridge gateway archive digest mismatch")

    extraction_root = os.path.join(rollback_root, "gateway")
    os.mkdir(extraction_root, 0o700)
    _protect_windows_rollback_directory(extraction_root)
    if os_name == "windows":
        _extract_gateway_zip(retained_archive, extraction_root)
    else:
        _extract_gateway_tarball(retained_archive, extraction_root)
    rollback_gateway = os.path.join(extraction_root, _gateway_binary_filename(os_name))
    if not os.path.isfile(rollback_gateway) or os.path.islink(rollback_gateway):
        raise OSError("retained bridge gateway binary is missing")
    if os.name == "nt":
        from defenseclaw import windows_acl

        private_gateway_security = windows_acl.private_security_for_directory(extraction_root)
        windows_acl.apply_path(rollback_gateway, private_gateway_security)
    signed_gateway_sha256 = _sha256_file(rollback_gateway)

    # Preserve the exact bridge executable that is active on this host, not
    # merely another copy reconstructed from the release archive.  Requiring
    # its bytes to match the authenticated source release catches drift or a
    # mismatched installed component before the target is allowed to mutate
    # anything, while the snapshot preserves native metadata for rollback.
    active_gateway = os.path.join(
        os.path.expanduser("~/.local/bin"),
        _installed_gateway_filename(os_name),
    )
    gateway_snapshot = _capture_rollback_file(
        active_gateway,
        os.path.join(rollback_root, "active-gateway"),
        required=True,
    )
    if gateway_snapshot.sha256 != signed_gateway_sha256:
        raise OSError(
            "installed bridge gateway does not match its authenticated rollback artifact"
        )

    data_dir = cfg.data_dir if cfg and cfg.data_dir else os.path.expanduser("~/.defenseclaw")
    from defenseclaw.config import config_path_for_data_dir

    state_root = os.path.join(rollback_root, "state")
    os.mkdir(state_root, 0o700)
    _protect_windows_rollback_directory(state_root)
    state_files = tuple(
        _capture_rollback_file(active, os.path.join(state_root, label), required=required)
        for label, active, required in (
            ("config.yaml", str(config_path_for_data_dir(data_dir)), True),
            ("environment", os.path.join(data_dir, ".env"), False),
            ("migration-state.json", os.path.join(data_dir, ".migration_state.json"), False),
        )
    )
    if gateway_snapshot.backup_path is None or gateway_snapshot.sha256 is None:
        raise OSError("exact bridge gateway snapshot is unavailable")
    return _HardCutRollbackPlan(
        source_version=source_version,
        data_dir=data_dir,
        backup_dir=backup_dir,
        rollback_wheel_path=retained_wheel,
        rollback_wheel_sha256=checksums[wheel_name],
        rollback_gateway_path=gateway_snapshot.backup_path,
        rollback_gateway_sha256=gateway_snapshot.sha256,
        active_gateway_path=active_gateway,
        gateway_snapshot=gateway_snapshot,
        state_files=state_files,
        os_name=os_name,
        environment_snapshot=dict(os.environ),
        source_dotenv_values=_read_dotenv_values(data_dir),
    )


def _upgrade_recovery_home() -> str:
    return os.path.abspath(
        os.path.expanduser(os.environ.get("DEFENSECLAW_HOME") or "~/.defenseclaw")
    )


def _hard_cut_recovery_path(recovery_home: str) -> Path:
    root = Path(os.path.abspath(os.path.expanduser(recovery_home)))
    return root / _UPGRADE_RECOVERY_DIRECTORY / _HARD_CUT_RECOVERY_FILENAME


def _phase_two_mutator_lease_path(recovery_home: str) -> Path:
    return _hard_cut_recovery_path(recovery_home).with_name(
        _PHASE_TWO_MUTATOR_LEASE_FILENAME
    )


def _open_phase_two_mutator_lease(recovery_home: str, *, create: bool) -> int:
    """Open and exclusively lock the fixed private phase-two lease."""

    if os.name != "posix":
        raise OSError("native phase-two mutator lease is unavailable on this platform")
    import fcntl

    path = _phase_two_mutator_lease_path(recovery_home)
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if create:
        flags |= os.O_CREAT
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise OSError("phase-two mutator lease could not be opened safely") from exc
    try:
        if create:
            os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        path_info = os.lstat(path)
        if (
            stat.S_ISLNK(path_info.st_mode)
            or not stat.S_ISREG(path_info.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or not os.path.samestat(path_info, opened)
            or path_info.st_uid != os.getuid()
            or stat.S_IMODE(path_info.st_mode) != 0o600
        ):
            raise OSError("phase-two mutator lease is not an owner-only regular file")
        deadline = time.monotonic() + _PHASE_TWO_MUTATOR_LEASE_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise OSError(
                        "timed out waiting for the active phase-two mutator lease"
                    ) from None
                time.sleep(0.05)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _ensure_phase_two_mutator_lease(recovery_home: str) -> Path:
    path = _phase_two_mutator_lease_path(recovery_home)
    if os.name == "nt":
        from defenseclaw import windows_acl

        windows_acl.ensure_phase_two_mutator_lease(str(path))
        return path
    descriptor = _open_phase_two_mutator_lease(recovery_home, create=True)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if os.name == "posix":
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    return path


@contextmanager
def _hold_phase_two_recovery_lease(recovery_home: str):
    """Wait for every orphan mutator, then serialize the whole restore."""

    global _HELD_PHASE_TWO_MUTATOR_LEASE
    if _HELD_PHASE_TWO_MUTATOR_LEASE is not None:
        raise OSError("phase-two recovery lease is already held")
    if os.name == "nt":
        from defenseclaw import windows_acl

        with windows_acl.hold_phase_two_mutator_lease(
            str(_phase_two_mutator_lease_path(recovery_home))
        ) as held:
            _HELD_PHASE_TWO_MUTATOR_LEASE = held
            try:
                yield
            finally:
                _HELD_PHASE_TWO_MUTATOR_LEASE = None
        return
    descriptor = _open_phase_two_mutator_lease(recovery_home, create=False)
    _HELD_PHASE_TWO_MUTATOR_LEASE = descriptor
    try:
        yield
    finally:
        _HELD_PHASE_TWO_MUTATOR_LEASE = None
        os.close(descriptor)


def _active_phase_two_mutator_lease() -> tuple[str, str] | None:
    recovery_home = _upgrade_recovery_home()
    journal = _hard_cut_recovery_path(recovery_home)
    if not journal.exists() and not journal.is_symlink():
        return None
    return recovery_home, str(_phase_two_mutator_lease_path(recovery_home))


def _hold_phase_two_lease_for_command_lifetime() -> None:
    """Cover direct controller mutations and every child until Click exits."""

    manager = _hold_phase_two_recovery_lease(_upgrade_recovery_home())
    manager.__enter__()
    context = click.get_current_context(silent=True)
    if context is None:
        manager.__exit__(None, None, None)
        raise OSError("phase-two lifetime lease requires an active command context")

    released = False

    def release() -> None:
        nonlocal released
        if released:
            return
        released = True
        manager.__exit__(None, None, None)

    context.call_on_close(release)


def _run_phase_two_mutator(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a mutating child with a lease that survives controller death."""

    active = _active_phase_two_mutator_lease()
    if active is None:
        return subprocess.run(command, **kwargs)
    recovery_home, lease_path = active
    if os.name != "posix":
        # The Windows resolver supplies the equivalent exclusive native-handle
        # wrapper; Python-side Windows support is implemented in windows_acl.
        from defenseclaw import windows_acl

        return windows_acl.run_phase_two_mutator(
            command,
            lease_path=lease_path,
            held_lease=_HELD_PHASE_TWO_MUTATOR_LEASE,
            **kwargs,
        )

    inherited = _HELD_PHASE_TWO_MUTATOR_LEASE
    if inherited is not None and not isinstance(inherited, int):
        raise OSError("phase-two POSIX lease token is invalid")
    descriptor = (
        inherited
        if inherited is not None
        else _open_phase_two_mutator_lease(recovery_home, create=False)
    )
    wrapper = [
        sys.executable,
        "-I",
        str(Path(__file__).parent.parent / "phase_two_mutator.py"),
        "--defenseclaw-phase-two-mutator",
        lease_path,
        str(descriptor),
        "--",
        *command,
    ]
    allowed = {"check", "capture_output", "text", "timeout", "env"}
    unexpected = set(kwargs) - allowed
    if unexpected:
        if inherited is None:
            os.close(descriptor)
        raise TypeError(f"unsupported phase-two mutator subprocess options: {sorted(unexpected)}")
    check = bool(kwargs.get("check", False))
    capture_output = bool(kwargs.get("capture_output", False))
    text = bool(kwargs.get("text", False))
    timeout = kwargs.get("timeout")
    environment = kwargs.get("env")
    spool: list[tuple[int, str]] = []
    if capture_output:
        spool_root = _hard_cut_recovery_path(recovery_home).parent
        stdout_fd, stdout_path = tempfile.mkstemp(prefix=".mutator-stdout-", dir=spool_root)
        stderr_fd, stderr_path = tempfile.mkstemp(prefix=".mutator-stderr-", dir=spool_root)
        os.fchmod(stdout_fd, 0o600)
        os.fchmod(stderr_fd, 0o600)
        spool = [(stdout_fd, stdout_path), (stderr_fd, stderr_path)]
        stdout_target: int | None = stdout_fd
        stderr_target: int | None = stderr_fd
    else:
        stdout_target = None
        stderr_target = None

    def cleanup_spool(*, read: bool) -> tuple[bytes | str | None, bytes | str | None]:
        output: list[bytes | str | None] = []
        try:
            for descriptor_value, _path in spool:
                if not read:
                    output.append(None)
                    continue
                size = os.fstat(descriptor_value).st_size
                if size > _MAX_PHASE_TWO_MUTATOR_OUTPUT_BYTES:
                    raise OSError("phase-two mutator output exceeded its size bound")
                os.lseek(descriptor_value, 0, os.SEEK_SET)
                payload = os.read(descriptor_value, _MAX_PHASE_TWO_MUTATOR_OUTPUT_BYTES + 1)
                output.append(payload.decode("utf-8", errors="replace") if text else payload)
            while len(output) < 2:
                output.append(None)
            return output[0], output[1]
        finally:
            for descriptor_value, spool_path in spool:
                try:
                    os.close(descriptor_value)
                except OSError:
                    pass
                try:
                    os.unlink(spool_path)
                except OSError:
                    pass
    try:
        process = subprocess.Popen(
            wrapper,
            pass_fds=(descriptor,),
            stdout=stdout_target,
            stderr=stderr_target,
            env=environment,
        )
    except BaseException:
        if inherited is None:
            os.close(descriptor)
        cleanup_spool(read=False)
        raise
    if inherited is None:
        os.close(descriptor)
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        # Never kill the wrapper on controller timeout: it and the real child
        # keep the lease until mutation actually ends. The rollback path's
        # next lease acquisition therefore waits instead of racing an orphan.
        threading.Thread(target=process.wait, daemon=True).start()
        cleanup_spool(read=False)
        raise subprocess.TimeoutExpired(
            command,
            timeout,
            output=exc.output,
            stderr=exc.stderr,
        ) from None
    stdout, stderr = cleanup_spool(read=capture_output)
    completed = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    if check:
        completed.check_returncode()
    return completed


def _snapshot_to_recovery_json(snapshot: _RollbackFileSnapshot) -> dict[str, object]:
    security: dict[str, object] | None = None
    if snapshot.windows_security is not None:
        security = {
            "owner": base64.b64encode(snapshot.windows_security.owner).decode("ascii"),
            "dacl": base64.b64encode(snapshot.windows_security.dacl).decode("ascii"),
            "dacl_protected": snapshot.windows_security.dacl_protected,
        }
    return {
        "active_path": snapshot.active_path,
        "backup_path": snapshot.backup_path,
        "existed": snapshot.existed,
        "sha256": snapshot.sha256,
        "mode": snapshot.mode,
        "windows_security": security,
    }


def _snapshot_from_recovery_json(raw: object) -> _RollbackFileSnapshot:
    fields = {
        "active_path",
        "backup_path",
        "existed",
        "sha256",
        "mode",
        "windows_security",
    }
    if not isinstance(raw, dict) or set(raw) != fields:
        raise OSError("hard-cut recovery snapshot has invalid fields")
    active_path = raw["active_path"]
    backup_path = raw["backup_path"]
    existed = raw["existed"]
    digest = raw["sha256"]
    mode = raw["mode"]
    security_raw = raw["windows_security"]
    if (
        not isinstance(active_path, str)
        or not active_path
        or not os.path.isabs(active_path)
        or not isinstance(existed, bool)
    ):
        raise OSError("hard-cut recovery snapshot has invalid path state")
    if backup_path is not None and (
        not isinstance(backup_path, str)
        or not backup_path
        or not os.path.isabs(backup_path)
    ):
        raise OSError("hard-cut recovery snapshot has invalid backup path")
    if digest is not None and (not isinstance(digest, str) or not _is_sha256_hex(digest)):
        raise OSError("hard-cut recovery snapshot has invalid digest")
    if mode is not None and (
        not isinstance(mode, int)
        or isinstance(mode, bool)
        or not 0 <= mode <= 0o7777
    ):
        raise OSError("hard-cut recovery snapshot has invalid mode")
    if existed and (backup_path is None or digest is None or mode is None):
        raise OSError("hard-cut recovery snapshot is incomplete")
    if not existed and any(value is not None for value in (backup_path, digest, mode, security_raw)):
        raise OSError("hard-cut recovery absent snapshot carries restore data")

    security = None
    if security_raw is not None:
        if not isinstance(security_raw, dict) or set(security_raw) != {
            "owner",
            "dacl",
            "dacl_protected",
        }:
            raise OSError("hard-cut recovery Windows security is invalid")
        owner = security_raw["owner"]
        dacl = security_raw["dacl"]
        protected = security_raw["dacl_protected"]
        if not isinstance(owner, str) or not isinstance(dacl, str) or not isinstance(protected, bool):
            raise OSError("hard-cut recovery Windows security is invalid")
        try:
            owner_bytes = base64.b64decode(owner, validate=True)
            dacl_bytes = base64.b64decode(dacl, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise OSError("hard-cut recovery Windows security is invalid") from exc
        if not owner_bytes or not dacl_bytes:
            raise OSError("hard-cut recovery Windows security is empty")
        from defenseclaw.windows_acl import WindowsFileSecurity

        security = WindowsFileSecurity(owner_bytes, dacl_bytes, protected)
    return _RollbackFileSnapshot(
        active_path=active_path,
        backup_path=backup_path,
        existed=existed,
        sha256=digest,
        mode=mode,
        windows_security=security,
    )


def _hard_cut_recovery_payload(
    plan: _HardCutRollbackPlan,
    receipt_path: Path,
    *,
    target_version: str,
) -> dict[str, object]:
    return {
        "schema_version": _HARD_CUT_RECOVERY_SCHEMA_VERSION,
        "source_version": plan.source_version,
        "target_version": target_version,
        "os_name": plan.os_name,
        "data_dir": plan.data_dir,
        "backup_dir": plan.backup_dir,
        "receipt_path": str(receipt_path),
        "rollback_wheel_path": plan.rollback_wheel_path,
        "rollback_wheel_sha256": plan.rollback_wheel_sha256,
        "rollback_gateway_path": plan.rollback_gateway_path,
        "rollback_gateway_sha256": plan.rollback_gateway_sha256,
        "active_gateway_path": plan.active_gateway_path,
        "gateway_snapshot": _snapshot_to_recovery_json(plan.gateway_snapshot),
        "state_files": [_snapshot_to_recovery_json(snapshot) for snapshot in plan.state_files],
    }


def _fsync_hard_cut_recovery_custody(plan: _HardCutRollbackPlan) -> None:
    """Make every rollback input durable before publishing the journal."""

    files = {
        plan.rollback_wheel_path,
        plan.rollback_gateway_path,
        *(snapshot.backup_path for snapshot in plan.state_files if snapshot.backup_path),
    }
    directories: set[str] = set()
    for path in files:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise OSError("hard-cut recovery custody contains a non-regular file")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directories.add(os.path.dirname(path) or ".")
    if os.name == "posix":
        for directory in directories:
            descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


def _ensure_private_upgrade_recovery_directory(recovery_home: str) -> Path:
    path = _hard_cut_recovery_path(recovery_home).parent
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700)
        if os.name == "nt":
            _protect_windows_rollback_directory(str(path))
        info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise OSError("upgrade recovery root must be a real directory")
    if os.name == "posix":
        if info.st_uid != os.getuid():
            raise OSError("upgrade recovery root has an untrusted owner")
        os.chmod(path, 0o700)
    elif os.name == "nt":
        from defenseclaw import windows_acl

        security = windows_acl.capture_path(str(path), directory=True)
        windows_acl.assert_trusted_owner(security)
        windows_acl.assert_not_broadly_writable(security)
        if not security.dacl_protected:
            raise OSError("upgrade recovery root DACL must be protected")
    return path


def _write_hard_cut_recovery_journal(
    plan: _HardCutRollbackPlan,
    receipt_path: Path,
    *,
    target_version: str,
) -> Path:
    """Durably publish a secret-free rollback plan before target mutation."""

    _fsync_hard_cut_recovery_custody(plan)
    recovery_home = _upgrade_recovery_home()
    directory = _ensure_private_upgrade_recovery_directory(recovery_home)
    _ensure_phase_two_mutator_lease(recovery_home)
    path = directory / _HARD_CUT_RECOVERY_FILENAME
    if path.exists() or path.is_symlink():
        raise OSError("another hard-cut recovery journal is already active")
    payload = _hard_cut_recovery_payload(plan, receipt_path, target_version=target_version)
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(encoded) > _MAX_HARD_CUT_RECOVERY_BYTES:
        raise OSError("hard-cut recovery journal exceeds its size bound")
    if os.name == "nt":
        from defenseclaw import windows_acl

        security = windows_acl.private_security_for_directory(str(directory))
        windows_acl.write_new_file(str(path), encoded, security)
    else:
        descriptor, temporary = tempfile.mkstemp(prefix=".phase-two-", dir=directory)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            os.chmod(path, 0o600)
            directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    # Read through the same strict parser before crossing the stop boundary.
    try:
        _load_hard_cut_recovery_journal(recovery_home)
    except BaseException:
        try:
            _remove_hard_cut_recovery_journal(path)
        except OSError:
            pass
        raise
    return path


def _read_bounded_private_json(path: Path) -> object:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OSError("hard-cut recovery journal must be a regular file")
    if info.st_size <= 0 or info.st_size > _MAX_HARD_CUT_RECOVERY_BYTES:
        raise OSError("hard-cut recovery journal has invalid size")
    if os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
        raise OSError("hard-cut recovery journal must be owner-only")
    if os.name == "nt":
        from defenseclaw import windows_acl

        security = windows_acl.capture_path(str(path))
        windows_acl.assert_trusted_owner(security)
        windows_acl.assert_not_broadly_writable(security)
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(info, opened):
            raise OSError("hard-cut recovery journal changed while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(_MAX_HARD_CUT_RECOVERY_BYTES + 1)
    finally:
        os.close(descriptor)
    if not raw or len(raw) > _MAX_HARD_CUT_RECOVERY_BYTES:
        raise OSError("hard-cut recovery journal has invalid size")
    try:
        return json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OSError("hard-cut recovery journal is invalid JSON") from exc


def _path_is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath((os.path.abspath(path), os.path.abspath(root))) == os.path.abspath(root)
    except ValueError:
        return False


def _assert_private_hard_cut_directory(path: str, *, label: str) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise OSError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise OSError(f"{label} must be a real directory")
    if os.name == "posix":
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise OSError(f"{label} must be owner-only")
    elif os.name == "nt":
        from defenseclaw import windows_acl

        security = windows_acl.capture_path(path, directory=True)
        windows_acl.assert_trusted_owner(security)
        windows_acl.assert_not_broadly_writable(security)
        if not security.dacl_protected:
            raise OSError(f"{label} DACL must be protected")


def _assert_private_hard_cut_file(
    path: str,
    *,
    expected_sha256: str,
    label: str,
) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise OSError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OSError(f"{label} must be a regular file")
    if os.name == "posix":
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise OSError(f"{label} must be owner-only")
    elif os.name == "nt":
        from defenseclaw import windows_acl

        security = windows_acl.capture_path(path)
        windows_acl.assert_trusted_owner(security)
        windows_acl.assert_not_broadly_writable(security)
    if _sha256_file(path) != expected_sha256:
        raise OSError(f"{label} digest changed")


def _load_hard_cut_recovery_journal(
    recovery_home: str,
) -> tuple[Path, _HardCutRollbackPlan, Path, str] | None:
    path = _hard_cut_recovery_path(recovery_home)
    if not path.exists() and not path.is_symlink():
        return None
    _ensure_private_upgrade_recovery_directory(recovery_home)
    raw = _read_bounded_private_json(path)
    fields = {
        "schema_version",
        "source_version",
        "target_version",
        "os_name",
        "data_dir",
        "backup_dir",
        "receipt_path",
        "rollback_wheel_path",
        "rollback_wheel_sha256",
        "rollback_gateway_path",
        "rollback_gateway_sha256",
        "active_gateway_path",
        "gateway_snapshot",
        "state_files",
    }
    if not isinstance(raw, dict) or set(raw) != fields:
        raise OSError("hard-cut recovery journal has invalid fields")
    if raw["schema_version"] != _HARD_CUT_RECOVERY_SCHEMA_VERSION:
        raise OSError("hard-cut recovery journal has an unsupported schema")
    source_version = raw["source_version"]
    target_version = raw["target_version"]
    os_name = raw["os_name"]
    recorded_data_dir = raw["data_dir"]
    backup_dir = raw["backup_dir"]
    receipt_path_raw = raw["receipt_path"]
    wheel_path = raw["rollback_wheel_path"]
    wheel_digest = raw["rollback_wheel_sha256"]
    gateway_path = raw["rollback_gateway_path"]
    gateway_digest = raw["rollback_gateway_sha256"]
    active_gateway = raw["active_gateway_path"]
    if (
        not isinstance(source_version, str)
        or not _CANONICAL_VERSION_RE.fullmatch(source_version)
        or not isinstance(target_version, str)
        or not _CANONICAL_VERSION_RE.fullmatch(target_version)
        or _version_key(source_version) >= _version_key(target_version)
        or os_name not in {"darwin", "linux", "windows"}
    ):
        raise OSError("hard-cut recovery journal has invalid release identity")
    path_values = (
        recorded_data_dir,
        backup_dir,
        receipt_path_raw,
        wheel_path,
        gateway_path,
        active_gateway,
    )
    if any(not isinstance(value, str) or not value or not os.path.isabs(value) for value in path_values):
        raise OSError("hard-cut recovery journal has invalid paths")
    expected_data_dir = os.path.abspath(os.path.expanduser(recorded_data_dir))
    backup_root = os.path.join(expected_data_dir, "backups")
    if os.path.dirname(os.path.abspath(backup_dir)) != os.path.abspath(backup_root):
        raise OSError("hard-cut recovery backup is outside the managed backup root")
    rollback_root = os.path.join(os.path.abspath(backup_dir), "hard-cut-rollback")
    if not _path_is_within(wheel_path, rollback_root) or not _path_is_within(gateway_path, rollback_root):
        raise OSError("hard-cut recovery artifacts are outside retained custody")
    receipt_root = os.path.join(expected_data_dir, ".upgrade-receipts")
    if os.path.dirname(os.path.abspath(receipt_path_raw)) != os.path.abspath(receipt_root):
        raise OSError("hard-cut recovery receipt is outside the private receipt queue")
    if (
        not isinstance(wheel_digest, str)
        or not _is_sha256_hex(wheel_digest)
        or not isinstance(gateway_digest, str)
        or not _is_sha256_hex(gateway_digest)
    ):
        raise OSError("hard-cut recovery journal has invalid artifact digests")
    gateway_snapshot = _snapshot_from_recovery_json(raw["gateway_snapshot"])
    state_raw = raw["state_files"]
    if not isinstance(state_raw, list) or len(state_raw) != 3:
        raise OSError("hard-cut recovery journal has invalid state inventory")
    state_files = tuple(_snapshot_from_recovery_json(item) for item in state_raw)
    retained_backups = [
        snapshot.backup_path
        for snapshot in (gateway_snapshot, *state_files)
        if snapshot.backup_path is not None
    ]
    if any(not _path_is_within(item, rollback_root) for item in retained_backups):
        raise OSError("hard-cut recovery snapshots are outside retained custody")
    if (
        gateway_snapshot.active_path != active_gateway
        or gateway_snapshot.backup_path != gateway_path
        or gateway_snapshot.sha256 != gateway_digest
    ):
        raise OSError("hard-cut recovery gateway snapshot is inconsistent")

    expected_gateway = os.path.join(
        os.path.expanduser("~/.local/bin"),
        _installed_gateway_filename(os_name),
    )
    if os.path.abspath(active_gateway) != os.path.abspath(expected_gateway):
        raise OSError("hard-cut recovery journal targets a different gateway")
    from defenseclaw.config import config_path_for_data_dir

    expected_state_paths = (
        os.path.abspath(str(config_path_for_data_dir(expected_data_dir))),
        os.path.abspath(os.path.join(expected_data_dir, ".env")),
        os.path.abspath(os.path.join(expected_data_dir, ".migration_state.json")),
    )
    if tuple(os.path.abspath(item.active_path) for item in state_files) != expected_state_paths:
        raise OSError("hard-cut recovery state inventory is inconsistent")

    _assert_private_hard_cut_directory(os.path.abspath(backup_dir), label="recovery backup")
    _assert_private_hard_cut_directory(rollback_root, label="recovery custody")
    _assert_private_hard_cut_file(
        os.path.abspath(wheel_path),
        expected_sha256=wheel_digest.lower(),
        label="retained bridge wheel",
    )
    _assert_private_hard_cut_file(
        os.path.abspath(gateway_path),
        expected_sha256=gateway_digest.lower(),
        label="retained bridge gateway",
    )
    for snapshot in state_files:
        if snapshot.existed:
            assert snapshot.backup_path is not None
            assert snapshot.sha256 is not None
            _assert_private_hard_cut_file(
                snapshot.backup_path,
                expected_sha256=snapshot.sha256,
                label="retained bridge state",
            )
    if os_name == "windows":
        if any(
            snapshot.existed and snapshot.windows_security is None
            for snapshot in (gateway_snapshot, *state_files)
        ):
            raise OSError("hard-cut recovery lacks Windows security metadata")
    elif any(snapshot.windows_security is not None for snapshot in (gateway_snapshot, *state_files)):
        raise OSError("hard-cut recovery carries unexpected Windows security metadata")
    plan = _HardCutRollbackPlan(
        source_version=source_version,
        data_dir=expected_data_dir,
        backup_dir=os.path.abspath(backup_dir),
        rollback_wheel_path=os.path.abspath(wheel_path),
        rollback_wheel_sha256=wheel_digest.lower(),
        rollback_gateway_path=os.path.abspath(gateway_path),
        rollback_gateway_sha256=gateway_digest.lower(),
        active_gateway_path=os.path.abspath(active_gateway),
        gateway_snapshot=gateway_snapshot,
        state_files=state_files,
        os_name=os_name,
        environment_snapshot=dict(os.environ),
        source_dotenv_values={},
    )
    return path, plan, Path(receipt_path_raw), target_version


def _remove_hard_cut_recovery_journal(path: Path) -> None:
    path.unlink()
    if os.name == "posix":
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _crash_bundle_rollback_result(backup_dir: str) -> dict[str, object] | None:
    metadata_path = Path(backup_dir) / "local-observability-stack" / "refresh-backup.json"
    if not metadata_path.exists() and not metadata_path.is_symlink():
        return None
    raw = _read_bounded_private_json(metadata_path)
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise OSError("local observability crash rollback metadata is invalid")
    managed = raw.get("managed_paths")
    if not isinstance(managed, list):
        raise OSError("local observability crash rollback lacks its managed path inventory")
    return {
        "installed": True,
        "managed_paths": managed,
        "changed_paths": [],
    }


def _recover_interrupted_hard_cut(data_dir: str | None = None) -> bool:
    """Rollback a journaled phase-two attempt before either schema is loaded."""

    if data_dir is None:
        data_dir = _upgrade_recovery_home()
    if _load_hard_cut_recovery_journal(data_dir) is None:
        return False
    with _hold_phase_two_recovery_lease(data_dir):
        # The wait above may outlive an orphaned wheel/migration/bundle child.
        # Re-read every durable fact only after exclusive ownership begins.
        loaded = _load_hard_cut_recovery_journal(data_dir)
        if loaded is None:
            return False
        journal_path, plan, receipt_path, target_version = loaded
        receipt = load_upgrade_receipt(receipt_path)
        if receipt.from_version != plan.source_version or receipt.target_version != target_version:
            raise OSError("hard-cut recovery receipt does not match the journal")
        if receipt.status in {"succeeded", "rolled_back"}:
            _remove_hard_cut_recovery_journal(journal_path)
            return False
        if receipt.status != "pending":
            raise OSError("hard-cut recovery receipt is terminal without a recoverable outcome")

        ux.banner("Recovering Interrupted Hard-Cut Upgrade")
        local_bundle_upgrade = _crash_bundle_rollback_result(plan.backup_dir)
        recovered = _execute_hard_cut_rollback(
            plan,
            AppContext(),
            receipt_path,
            failure_code="interrupted",
            health_timeout=60,
            local_bundle_upgrade=local_bundle_upgrade,
            retain_pending_on_failure=True,
            recovery_journal_path=journal_path,
        )
        if not recovered:
            raise OSError("interrupted hard-cut rollback remains incomplete")
        ux.ok(f"Recovered DefenseClaw {plan.source_version}; restarting the requested upgrade")
        return True


def _assert_private_staged_bridge_directory(path: str) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise OSError("staged bridge artifact directory is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise OSError("staged bridge artifact root must be a real directory")
    if os.name == "posix":
        if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise OSError("staged bridge artifact root must be owner-only")
    elif os.name == "nt":
        from defenseclaw import windows_acl

        security = windows_acl.capture_path(path, directory=True)
        windows_acl.assert_trusted_owner(security)
        windows_acl.assert_not_broadly_writable(security)
        if not security.dacl_protected:
            raise OSError("staged bridge artifact root DACL must be protected")


def _assert_private_staged_bridge_file(path: str) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise OSError("staged bridge artifact is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OSError("staged bridge artifact must be a regular file")
    if os.name == "posix" and (stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid()):
        raise OSError("staged bridge artifact must be owner-only")
    if os.name == "nt":
        from defenseclaw import windows_acl

        security = windows_acl.capture_path(path)
        windows_acl.assert_trusted_owner(security)
        windows_acl.assert_not_broadly_writable(security)


def _protect_windows_rollback_directory(path: str) -> None:
    if os.name != "nt":
        return
    from defenseclaw import windows_acl

    security = windows_acl.private_security_for_directory(
        os.path.dirname(path) or path,
        inherit_children=True,
    )
    windows_acl.apply_path(path, security, directory=True)
    if windows_acl.capture_path(path, directory=True) != security:
        raise OSError("Windows rollback directory owner/DACL did not remain private")


def _parse_staged_checksums(path: str) -> dict[str, str]:
    checksums: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as stream:
            for raw in stream:
                parts = raw.strip().split()
                if len(parts) != 2 or not _is_sha256_hex(parts[0]):
                    continue
                filename = parts[1].removeprefix("./")
                if not filename or os.path.basename(filename) != filename or filename in checksums:
                    raise OSError("staged checksums contain an invalid artifact name")
                checksums[filename] = parts[0].lower()
    except (OSError, UnicodeError) as exc:
        raise OSError("staged checksums are unreadable") from exc
    if not checksums:
        raise OSError("staged checksums contain no valid entries")
    return checksums


def _verify_staged_checksums_signature(
    version: str,
    checksums_path: str,
    signature_path: str,
    certificate_path: str,
) -> None:
    strict_provenance = _version_key(version) >= _version_key(
        _STRICT_SIGSTORE_RELEASE_VERSION
    )
    cosign = shutil.which("cosign")
    if not cosign:
        if strict_provenance:
            raise OSError(
                f"staged bridge {version} requires cosign provenance verification"
            )
        ux.warn(
            "Staged bridge signature assets are present, but cosign is unavailable; "
            "continuing with the resolver-verified private handoff and local SHA-256 checks.",
            indent="  ",
        )
        return
    identity_args = (
        ["--certificate-identity", _RELEASE_WORKFLOW_IDENTITY]
        if strict_provenance
        else [
            "--certificate-identity-regexp",
            f"^https://github.com/{GITHUB_REPO}/.+",
        ]
    )
    try:
        completed = subprocess.run(
            [
            cosign,
            "verify-blob",
            "--certificate",
            certificate_path,
            "--signature",
            signature_path,
            *identity_args,
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            checksums_path,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OSError("staged bridge checksum signature verification failed") from exc
    if completed.returncode != 0:
        raise OSError("staged bridge checksum signature verification failed")


def _capture_rollback_file(active_path: str, backup_path: str, *, required: bool) -> _RollbackFileSnapshot:
    try:
        info = os.lstat(active_path)
    except FileNotFoundError:
        if required:
            raise OSError(f"required rollback source is missing: {active_path}") from None
        return _RollbackFileSnapshot(active_path, None, False, None, None)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OSError(f"rollback source must be a regular file: {active_path}")
    windows_security = None
    if os.name == "nt":
        from defenseclaw import windows_acl

        if getattr(info, "st_file_attributes", 0) & 0x00000400:
            raise OSError(f"rollback source must not be a reparse point: {active_path}")
        descriptor = os.open(active_path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise OSError(f"rollback source changed while opening: {active_path}")
            windows_security = windows_acl.capture_fd(descriptor)
            with os.fdopen(os.dup(descriptor), "rb") as stream:
                payload = stream.read()
        finally:
            os.close(descriptor)
        private_security = windows_acl.private_security_for_directory(os.path.dirname(backup_path))
        windows_acl.write_new_file(backup_path, payload, private_security)
    else:
        shutil.copy2(active_path, backup_path, follow_symlinks=False)
        os.chmod(backup_path, 0o600)
    digest = _sha256_file(backup_path)
    return _RollbackFileSnapshot(
        active_path=active_path,
        backup_path=backup_path,
        existed=True,
        sha256=digest,
        mode=stat.S_IMODE(info.st_mode),
        windows_security=windows_security,
    )


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_dotenv_values(data_dir: str) -> dict[str, str]:
    """Read the bounded dotenv subset used to refresh an upgrade child."""

    path = os.path.join(data_dir, ".env")
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return {}
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
        raise OSError("upgrade dotenv must be a bounded regular file")
    values: dict[str, str] = {}
    with open(path, encoding="utf-8") as stream:
        for raw in stream:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if not separator or not key:
                continue
            if not _DOTENV_KEY_RE.fullmatch(key) or "\x00" in value:
                raise OSError("upgrade dotenv contains an invalid environment entry")
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            values[key] = value
    return values


def _refresh_target_dotenv_environment(plan: _HardCutRollbackPlan) -> None:
    """Replace source-file values while preserving ambient operator overrides."""

    target_values = _read_dotenv_values(plan.data_dir)
    for name, source_value in plan.source_dotenv_values.items():
        if os.environ.get(name) == source_value:
            os.environ.pop(name, None)
    for name, value in target_values.items():
        if name not in os.environ:
            os.environ[name] = value


def _poll_installed_health(
    data_dir: str,
    timeout_seconds: int,
    expected_version: str,
    *,
    os_name: str,
) -> None:
    """Load configuration and verify health in the freshly installed wheel."""

    managed_venv = os.path.expanduser("~/.defenseclaw/.venv")
    venv_python = _venv_python_path(managed_venv, os_name)
    if not os.path.isfile(venv_python):
        raise OSError("fresh-process health check cannot find the managed CLI interpreter")
    child_env = os.environ.copy()
    child_env.pop("PYTHONHOME", None)
    child_env.pop("PYTHONPATH", None)
    try:
        completed = subprocess.run(
            [
                venv_python,
                "-I",
                "-c",
                _INSTALLED_HEALTH_SCRIPT,
                data_dir,
                str(timeout_seconds),
                expected_version,
            ],
            check=False,
            env=child_env,
            timeout=max(timeout_seconds, 1) + 15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OSError("fresh-process gateway health verification failed") from exc
    if completed.returncode != 0:
        raise SystemExit(completed.returncode or 1)


def _restore_rollback_environment(snapshot: dict[str, str]) -> None:
    """Restore the process environment captured before target activation.

    The normal dotenv loader intentionally preserves existing environment
    variables.  That precedence is correct for operator overrides, but during
    rollback it would also preserve target-era values loaded just before the
    failed health check.  Restore the in-memory environment first, then source
    the restored bridge dotenv so disk and the restarted process agree.
    """

    for name in set(os.environ) - set(snapshot):
        os.environ.pop(name, None)
    for name, value in snapshot.items():
        os.environ[name] = value


def _execute_hard_cut_rollback(
    plan: _HardCutRollbackPlan,
    app: AppContext,
    receipt_path,
    *,
    failure_code: str,
    health_timeout: int,
    local_bundle_upgrade: dict[str, object] | None = None,
    retain_pending_on_failure: bool = False,
    recovery_journal_path: Path | None = None,
) -> bool:
    """Restore the retained bridge state and prove its gateway is healthy.

    The receipt must still be pending when this function is called.  A
    successful rollback records ``status=rolled_back`` while retaining the
    original upgrade ``failure_code``.  Any incomplete restore records the
    original failed outcome and returns ``False``.
    """

    ux.banner("Rolling Back Hard-Cut Upgrade")
    try:
        if not _run_silent(
            ["defenseclaw-gateway", "stop"],
            "Target gateway stopped",
            "Could not stop target gateway",
        ):
            raise OSError("target gateway stop command failed during rollback")
        _assert_gateway_quiesced(plan.data_dir)
        _restore_rollback_environment(plan.environment_snapshot)
        for snapshot in plan.state_files:
            _restore_rollback_file(snapshot)
        _restore_local_observability_upgrade_backup(
            plan.data_dir,
            plan.backup_dir,
            local_bundle_upgrade,
        )
        _restore_rollback_gateway(plan)
        if _sha256_file(plan.rollback_wheel_path) != plan.rollback_wheel_sha256:
            raise OSError("retained bridge wheel changed before rollback")
        _install_wheel(plan.rollback_wheel_path, plan.os_name)
        _verify_restored_bridge_artifacts(plan)

        if not _run_silent(
            ["defenseclaw-gateway", "start"],
            "Restored bridge gateway started",
            "Could not start restored bridge gateway",
        ):
            raise OSError("restored bridge gateway failed to start")
        _poll_installed_health(
            plan.data_dir,
            health_timeout,
            plan.source_version,
            os_name=plan.os_name,
        )

        if local_bundle_upgrade and local_bundle_upgrade.get("restart_required") is True:
            restored_bundle = _run_installed_local_observability_bundle_restart(
                plan.data_dir,
                health_timeout=max(health_timeout, 1),
                os_name=plan.os_name,
            )
            errors = restored_bundle.get("degraded_errors", [])
            if restored_bundle.get("restarted") is not True or errors:
                raise OSError("restored local observability stack failed readiness")
    except BaseException:
        if not retain_pending_on_failure:
            _record_failed_upgrade_receipt(receipt_path, failure_code)
        ux.err(
            "Automatic rollback was incomplete; the failed upgrade remains non-successful.",
            indent="  ",
        )
        ux.subhead(f"Recovery backup: {plan.backup_dir}", indent="    ")
        return False

    try:
        # Health is now proven and no target mutator remains. Remove recovery
        # authority before publishing a terminal receipt, so the v8 consumer
        # can never acknowledge/delete the receipt while a stale journal still
        # tells native resolvers that rollback is pending.
        if recovery_journal_path is not None:
            _remove_hard_cut_recovery_journal(recovery_journal_path)
        complete_upgrade_receipt(
            receipt_path,
            status="rolled_back",
            failure_code=failure_code,
        )
    except (OSError, ValueError):
        if recovery_journal_path is None or recovery_journal_path.exists():
            if not retain_pending_on_failure:
                _record_failed_upgrade_receipt(receipt_path, failure_code)
        else:
            # Rollback itself is healthy and recovery authority is gone. A
            # terminal failed receipt is safer than leaving an unprovable
            # pending record with no journal to replay.
            _record_failed_upgrade_receipt(receipt_path, failure_code)
        ux.err("Rollback succeeded, but its durable receipt could not be finalized.", indent="  ")
        return False
    ux.ok(f"Restored DefenseClaw {plan.source_version}; gateway health verified")
    return True


def _restore_rollback_file(snapshot: _RollbackFileSnapshot) -> None:
    if os.name == "nt":
        _restore_windows_rollback_file(snapshot)
        return
    if not snapshot.existed:
        try:
            info = os.lstat(snapshot.active_path)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise OSError("rollback-created path is not a regular file")
        os.unlink(snapshot.active_path)
        return
    if (
        snapshot.backup_path is None
        or snapshot.sha256 is None
        or snapshot.mode is None
        or _sha256_file(snapshot.backup_path) != snapshot.sha256
    ):
        raise OSError("rollback state backup is missing or changed")
    parent = os.path.dirname(snapshot.active_path) or "."
    fd, temporary = tempfile.mkstemp(prefix=".defenseclaw-rollback-", dir=parent)
    os.close(fd)
    try:
        shutil.copy2(snapshot.backup_path, temporary, follow_symlinks=False)
        os.chmod(temporary, snapshot.mode)
        if _sha256_file(temporary) != snapshot.sha256:
            raise OSError("staged rollback state digest mismatch")
        os.replace(temporary, snapshot.active_path)
        if _sha256_file(snapshot.active_path) != snapshot.sha256:
            raise OSError("restored rollback state digest mismatch")
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _restore_windows_rollback_file(snapshot: _RollbackFileSnapshot) -> None:
    """Restore bytes plus the exact owner/DACL using retained file objects.

    The target gateway is stopped before this runs.  A changed target is moved
    aside before the verified replacement is published, so a failure never
    destroys the only copy of either the rollback source or the failed target.
    """

    from defenseclaw import windows_acl

    parent = os.path.dirname(snapshot.active_path) or "."
    basename = os.path.basename(snapshot.active_path)
    displaced = os.path.join(parent, f".{basename}.hard-cut-displaced-{secrets.token_hex(16)}")
    if not snapshot.existed:
        try:
            info = os.lstat(snapshot.active_path)
        except FileNotFoundError:
            return
        if (
            stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x00000400
            or not stat.S_ISREG(info.st_mode)
        ):
            raise OSError("rollback-created path is not a real regular file")
        windows_acl.move_file_no_replace(snapshot.active_path, displaced)
        try:
            os.unlink(displaced)
        except BaseException:
            if not os.path.lexists(snapshot.active_path) and os.path.lexists(displaced):
                windows_acl.move_file_no_replace(displaced, snapshot.active_path)
            raise
        return

    if (
        snapshot.backup_path is None
        or snapshot.sha256 is None
        or snapshot.windows_security is None
        or _sha256_file(snapshot.backup_path) != snapshot.sha256
    ):
        raise OSError("Windows rollback state backup or owner/DACL is missing or changed")
    with open(snapshot.backup_path, "rb") as stream:
        payload = stream.read()
    temporary = os.path.join(parent, f".{basename}.hard-cut-restore-{secrets.token_hex(16)}")
    failed_publish = os.path.join(parent, f".{basename}.hard-cut-failed-{secrets.token_hex(16)}")
    _stage_windows_rollback_file(temporary, payload, snapshot.windows_security)
    displaced_exists = False
    try:
        try:
            info = os.lstat(snapshot.active_path)
        except FileNotFoundError:
            info = None
        if info is not None:
            if (
                stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x00000400
                or not stat.S_ISREG(info.st_mode)
            ):
                raise OSError("rollback target is not a real regular file")
            windows_acl.move_file_no_replace(snapshot.active_path, displaced)
            displaced_exists = True
        try:
            windows_acl.move_file_no_replace(temporary, snapshot.active_path)
            temporary = ""
        except BaseException:
            if displaced_exists and not os.path.lexists(snapshot.active_path) and os.path.lexists(displaced):
                windows_acl.move_file_no_replace(displaced, snapshot.active_path)
                displaced_exists = False
            raise
        try:
            _assert_windows_rollback_file(snapshot)
        except BaseException:
            # The verified staged object was changed during/after publish.
            # Keep the failed target object, recreate the rollback candidate
            # from the authenticated backup, and make one exact recovery
            # attempt before reporting rollback incomplete.
            windows_acl.move_file_no_replace(snapshot.active_path, failed_publish)
            recovery = os.path.join(parent, f".{basename}.hard-cut-recovery-{secrets.token_hex(16)}")
            try:
                _stage_windows_rollback_file(recovery, payload, snapshot.windows_security)
                windows_acl.move_file_no_replace(recovery, snapshot.active_path)
                recovery = ""
                _assert_windows_rollback_file(snapshot)
            except BaseException:
                if not os.path.lexists(snapshot.active_path) and os.path.lexists(failed_publish):
                    windows_acl.move_file_no_replace(failed_publish, snapshot.active_path)
                raise
            finally:
                if recovery and os.path.lexists(recovery):
                    os.unlink(recovery)
        if displaced_exists and os.path.lexists(displaced):
            os.unlink(displaced)
            displaced_exists = False
        if os.path.lexists(failed_publish):
            os.unlink(failed_publish)
    finally:
        if temporary and os.path.lexists(temporary):
            os.unlink(temporary)


def _stage_windows_rollback_file(
    path: str,
    payload: bytes,
    security: WindowsFileSecurity,
) -> None:
    from defenseclaw import windows_acl

    # write_new_file applies a protected copy before its first payload byte.
    # Reapply the original protection state only while the object is still
    # disposable, then demand an exact native descriptor readback.
    windows_acl.write_new_file(path, payload, security)
    windows_acl.apply_path(path, security)
    if _sha256_file(path) != hashlib.sha256(payload).hexdigest():
        raise OSError("staged Windows rollback state digest mismatch")
    if windows_acl.capture_path(path) != security:
        raise OSError("staged Windows rollback owner/DACL mismatch")


def _assert_windows_rollback_file(snapshot: _RollbackFileSnapshot) -> None:
    from defenseclaw import windows_acl

    if snapshot.sha256 is None or snapshot.windows_security is None:
        raise OSError("Windows rollback verification metadata is unavailable")
    try:
        info = os.lstat(snapshot.active_path)
    except FileNotFoundError as exc:
        raise OSError("restored Windows rollback file is missing") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & 0x00000400
        or not stat.S_ISREG(info.st_mode)
        or _sha256_file(snapshot.active_path) != snapshot.sha256
        or windows_acl.capture_path(snapshot.active_path) != snapshot.windows_security
    ):
        raise OSError("restored Windows rollback bytes or owner/DACL mismatch")


def _restore_rollback_gateway(plan: _HardCutRollbackPlan) -> None:
    snapshot = plan.gateway_snapshot
    if (
        snapshot.active_path != plan.active_gateway_path
        or snapshot.backup_path != plan.rollback_gateway_path
        or snapshot.sha256 != plan.rollback_gateway_sha256
        or snapshot.backup_path is None
        or snapshot.sha256 is None
        or _sha256_file(snapshot.backup_path) != snapshot.sha256
    ):
        raise OSError("retained bridge gateway changed before rollback")
    _restore_rollback_file(snapshot)
    if _sha256_file(plan.active_gateway_path) != plan.rollback_gateway_sha256:
        raise OSError("restored bridge gateway digest mismatch")


def _verify_restored_bridge_artifacts(plan: _HardCutRollbackPlan) -> None:
    gateway = subprocess.run(
        [plan.active_gateway_path, "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    gateway_output = ((gateway.stdout or "") + (gateway.stderr or "")).strip()
    if gateway.returncode != 0 or plan.source_version not in gateway_output:
        raise OSError("restored gateway version verification failed")

    managed_venv = os.path.expanduser("~/.defenseclaw/.venv")
    venv_python = _venv_python_path(managed_venv, plan.os_name)
    cli = subprocess.run(
        [venv_python, "-I", "-c", "from defenseclaw import __version__; print(__version__)"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if cli.returncode != 0 or (cli.stdout or "").strip() != plan.source_version:
        raise OSError("restored CLI version verification failed")


def _restore_local_observability_upgrade_backup(
    data_dir: str,
    backup_dir: str,
    local_bundle_upgrade: dict[str, object] | None,
) -> None:
    if not local_bundle_upgrade or local_bundle_upgrade.get("installed") is not True:
        return
    backup_root = os.path.join(backup_dir, "local-observability-stack")
    metadata_path = os.path.join(backup_root, "refresh-backup.json")
    managed_backup = os.path.join(backup_root, "managed")
    try:
        if os.path.getsize(metadata_path) > 4 * 1024 * 1024:
            raise ValueError("bundle rollback metadata is too large")
        with open(metadata_path, encoding="utf-8") as stream:
            metadata = json.load(stream)
    except (OSError, UnicodeError, ValueError) as exc:
        raise OSError("local observability rollback metadata is unavailable") from exc
    if not isinstance(metadata, dict) or metadata.get("schema_version") != 1:
        raise OSError("local observability rollback metadata is invalid")
    existing_raw = metadata.get("existing_paths")
    digests_raw = metadata.get("old_sha256")
    modes_raw = metadata.get("old_modes")
    managed_raw = local_bundle_upgrade.get("managed_paths")
    changed_raw = local_bundle_upgrade.get("changed_paths")
    if not all(isinstance(value, list) for value in (existing_raw, managed_raw, changed_raw)):
        raise OSError("local observability rollback path inventory is invalid")
    if not isinstance(digests_raw, dict) or not isinstance(modes_raw, dict):
        raise OSError("local observability rollback metadata maps are invalid")

    def _safe_paths(values) -> set[str]:
        paths = set()
        for value in values:
            if (
                not isinstance(value, str)
                or not value
                or os.path.isabs(value)
                or ".." in value.replace("\\", "/").split("/")
            ):
                raise OSError("local observability rollback contains an unsafe path")
            paths.add(value)
        return paths

    existing = _safe_paths(existing_raw)
    managed = _safe_paths(managed_raw) | _safe_paths(changed_raw) | {".defenseclaw-bundle-manifest.json"}
    old_digests = {
        key: value
        for key, value in digests_raw.items()
        if isinstance(key, str) and isinstance(value, str) and _is_sha256_hex(value)
    }
    old_modes = {
        key: value
        for key, value in modes_raw.items()
        if (
            isinstance(key, str)
            and isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value <= 0o7777
        )
    }
    if set(digests_raw) != set(old_digests) or set(modes_raw) != set(old_modes):
        raise OSError("local observability rollback metadata contains invalid values")
    if (
        not existing.issubset(managed)
        or set(old_digests) != existing
        or set(old_modes) != existing
    ):
        raise OSError("local observability rollback inventory is inconsistent")
    from defenseclaw.bundle_refresh import _restore_local_observability_backup

    _restore_local_observability_backup(
        Path(data_dir) / "observability-stack",
        Path(managed_backup),
        managed,
        existing,
        old_digests,
        old_modes,
    )


def _create_private_backup_directory(backup_root: str, timestamp: str) -> str:
    """Create a unique upgrade backup below a private, non-symlink root.

    Observability-v8 activation stores recovery copies in the same ``backups``
    root and intentionally rejects roots readable by group or other users.
    Older upgrade releases created this root using the process umask (normally
    0755), so an upgrade to v8 must securely tighten an operator-owned root
    before the target migration starts.  Descriptor-relative creation keeps a
    same-second retry unique and prevents a swapped root from redirecting the
    new backup directory.
    """

    try:
        os.mkdir(backup_root, 0o700)
    except FileExistsError:
        pass

    if os.name == "nt":
        return _create_private_windows_backup_directory(backup_root, timestamp)

    if os.name != "posix":
        root_info = os.lstat(backup_root)
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            raise OSError("backup root is not a real directory")
        os.chmod(backup_root, 0o700)
        return tempfile.mkdtemp(prefix=f"upgrade-{timestamp}-", dir=backup_root)

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_descriptor = os.open(backup_root, flags)
    directory_descriptor = -1
    directory_name = ""
    try:
        root_info = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_info.st_mode):
            raise OSError("backup root is not a directory")
        os.fchmod(root_descriptor, 0o700)
        root_info = os.fstat(root_descriptor)
        if stat.S_IMODE(root_info.st_mode) != 0o700:
            raise OSError("backup root permissions are not private")

        for _ in range(128):
            directory_name = f"upgrade-{timestamp}-{secrets.token_hex(8)}"
            try:
                os.mkdir(directory_name, 0o700, dir_fd=root_descriptor)
                break
            except FileExistsError:
                continue
        else:
            raise OSError("unable to allocate a unique upgrade backup")

        directory_descriptor = os.open(directory_name, flags, dir_fd=root_descriptor)
        os.fchmod(directory_descriptor, 0o700)
        directory_info = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(directory_info.st_mode) or stat.S_IMODE(directory_info.st_mode) != 0o700:
            raise OSError("backup directory permissions are not private")

        public_root = os.lstat(backup_root)
        if stat.S_ISLNK(public_root.st_mode) or (public_root.st_dev, public_root.st_ino) != (
            root_info.st_dev,
            root_info.st_ino,
        ):
            raise OSError("backup root changed during creation")
        backup_dir = os.path.join(backup_root, directory_name)
        public_directory = os.lstat(backup_dir)
        if stat.S_ISLNK(public_directory.st_mode) or (public_directory.st_dev, public_directory.st_ino) != (
            directory_info.st_dev,
            directory_info.st_ino,
        ):
            raise OSError("backup directory changed during creation")
        os.fsync(directory_descriptor)
        os.fsync(root_descriptor)
        return backup_dir
    except BaseException:
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
            directory_descriptor = -1
        if directory_name:
            try:
                os.rmdir(directory_name, dir_fd=root_descriptor)
            except OSError:
                pass
        raise
    finally:
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
        os.close(root_descriptor)


def _create_private_windows_backup_directory(backup_root: str, timestamp: str) -> str:
    """Narrow a real backup root and its new child before any secret copy."""

    from defenseclaw import windows_acl

    initial = os.lstat(backup_root)
    if (
        stat.S_ISLNK(initial.st_mode)
        or getattr(initial, "st_file_attributes", 0) & 0x00000400
        or not stat.S_ISDIR(initial.st_mode)
    ):
        raise OSError("backup root is not a real directory")
    security = windows_acl.private_security_for_directory(
        backup_root,
        inherit_children=True,
    )
    windows_acl.apply_path(backup_root, security, directory=True)
    narrowed = os.lstat(backup_root)
    if (
        (narrowed.st_dev, narrowed.st_ino) != (initial.st_dev, initial.st_ino)
        or windows_acl.capture_path(backup_root, directory=True) != security
    ):
        raise OSError("backup root changed while its owner/DACL was narrowed")

    for _ in range(128):
        directory = os.path.join(backup_root, f"upgrade-{timestamp}-{secrets.token_hex(8)}")
        try:
            os.mkdir(directory)
        except FileExistsError:
            continue
        created = os.lstat(directory)
        try:
            windows_acl.apply_path(directory, security, directory=True)
            secured = os.lstat(directory)
            if (
                stat.S_ISLNK(secured.st_mode)
                or getattr(secured, "st_file_attributes", 0) & 0x00000400
                or not stat.S_ISDIR(secured.st_mode)
                or (secured.st_dev, secured.st_ino) != (created.st_dev, created.st_ino)
                or windows_acl.capture_path(directory, directory=True) != security
            ):
                raise OSError("backup directory changed while its owner/DACL was narrowed")
        except BaseException:
            try:
                os.rmdir(directory)
            except OSError:
                pass
            raise
        return directory
    raise OSError("unable to allocate a unique Windows upgrade backup")


def _run_silent(cmd: list[str], ok_msg: str, fail_msg: str) -> bool:
    """Run a command, printing ok_msg on success and fail_msg on failure.

    On non-zero exit, surface the first few stderr/stdout lines so an
    operator can correlate with logs immediately instead of needing a
    second debug pass with the same command. Exceptions (missing
    binary, timeout) are caught and reported similarly so the upgrade
    flow never raises mid-restart.
    """
    try:
        result = _run_phase_two_mutator(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode == 0:
            ux.ok(ok_msg)
            return True
        ux.warn(fail_msg)
        err = (result.stderr or result.stdout or "").strip()
        if err:
            for line in err.splitlines()[:5]:
                ux.subhead(line, indent="    ")
        return False
    except (OSError, subprocess.SubprocessError) as exc:
        ux.warn(fail_msg)
        ux.subhead(str(exc), indent="    ")
        return False
