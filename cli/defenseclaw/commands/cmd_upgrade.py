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

import datetime
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import zipfile

import click
import requests

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx

GITHUB_REPO = "cisco-ai-defense/defenseclaw"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}"
GITHUB_DL = f"https://github.com/{GITHUB_REPO}/releases/download"
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SHA256_HEX = set("0123456789abcdefABCDEF")
_UPGRADE_PROTOCOL_VERSION = 1
_UPGRADE_MANIFEST_FILENAME = "upgrade-manifest.json"
_TUI_SMOKE_CODE = """
import asyncio
import tempfile
from defenseclaw.tui.app import DefenseClawTUI

async def smoke():
    with tempfile.TemporaryDirectory(prefix="defenseclaw-tui-smoke-") as data_dir:
        app = DefenseClawTUI(data_dir=data_dir)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()

asyncio.run(smoke())
"""


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

    if target_version is None:
        click.echo(f"  {ux.dim('→')} Fetching latest release from GitHub ...")
        target_version = _fetch_latest_version()
        if target_version is None:
            ux.err("Could not determine latest release. Use --version to specify.", indent="  ")
            raise SystemExit(1)

    target_version = _normalize_target_version(target_version)
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
            target_version, staging_dir, allow_unverified=allow_unverified,
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
            if not allow_unverified:
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
                target_version, checksums, artifact_names,
                allow_unverified=allow_unverified,
            )

        upgrade_manifest = _download_upgrade_manifest(
            target_version, staging_dir, checksums, allow_unverified=allow_unverified,
        )
        gw_binary_path, _gw_tarball_name = _download_gateway(
            target_version, os_name, arch, staging_dir, checksums,
        )
        whl_path, _whl_name = _download_wheel(
            target_version, staging_dir, checksums,
        )
        _preflight_wheel_install(whl_path, os_name)
    except SystemExit:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise

    # ── Confirm ──────────────────────────────────────────────────────────────

    if not yes:
        click.echo()
        click.echo(f"  {ux.bold('This will:')}")
        click.echo(
            f"    {ux.dim('1.')} Back up ~/.defenseclaw/ and ~/.openclaw/openclaw.json"
        )
        click.echo(
            f"    {ux.dim('2.')} Stop the gateway, replace binaries from downloaded artifacts"
        )
        click.echo(f"    {ux.dim('3.')} Run version-specific migrations")
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

    # ── Stop gateway, install, migrate, restart ──────────────────────────────

    ux.banner("Stopping Services")

    _run_silent(["defenseclaw-gateway", "stop"], "Gateway stopped", "Gateway was not running")

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

        openclaw_home = os.path.expanduser(
            app.cfg.claw.home_dir if app.cfg else "~/.openclaw"
        )
        # Thread the operator's data_dir through so migrations that
        # touch ``<data_dir>/.env`` / ``<data_dir>/active_connector.json``
        # / etc. (introduced in the connector-v3 wave, PR #194) hit the
        # right path even when the operator runs with a non-default
        # ``DEFENSECLAW_HOME``. Falls back to the upgrade module's
        # default expansion when the config could not be loaded.
        data_dir = (
            app.cfg.data_dir if app.cfg and app.cfg.data_dir
            else os.path.expanduser("~/.defenseclaw")
        )

        migration_failed = False
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
        click.echo()
        if migration_failed:
            ux.warn("Migration runner failed; upgrade will continue. Run: defenseclaw doctor --fix")
        elif count == 0:
            ux.ok("No migrations needed")
        else:
            ux.ok(f"Applied {count} migration(s)")

        # Surface the migration cursor so a partial-failure host (where
        # the cursor differs from what the registry says we just ran)
        # is visible in the upgrade log, not buried in
        # ``<data_dir>/.migration_state.json``. Best-effort: a missing
        # cursor module simply skips the summary.
        _print_migration_cursor_summary(data_dir)
        _assert_required_cli_migrations(upgrade_manifest, data_dir)

    finally:
        # Always clean up staging dir first, even if restart fails.
        shutil.rmtree(staging_dir, ignore_errors=True)

        ux.banner("Starting Services")

        _run_silent(["defenseclaw-gateway", "start"], "Gateway started", "Could not start gateway")

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
        _poll_health(app.cfg, health_timeout)

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

    if app.logger:
        app.logger.log_action(
            "upgrade", "defenseclaw",
            f"from={current_version} to={target_version} backup={backup_dir}",
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

    if system == "windows" and arch != "amd64":
        ux.err(
            "Windows ARM64 is not certified for this release; use certified Windows x64 (amd64).",
            indent="  ",
        )
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


def _hook_binary_filename(os_name: str) -> str | None:
    """Return the Windows no-console hook artifact name, when applicable."""
    return "defenseclaw-hook.exe" if os_name == "windows" else None


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
    urls = [
        f"{GITHUB_DL}/{version}/{archive}",
        f"{GITHUB_DL}/{version}/{whl_name}",
    ]
    for url in urls:
        try:
            resp = requests.head(url, timeout=15, allow_redirects=True)
            if resp.status_code >= 400:
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

    The archive is a .zip on Windows (containing defenseclaw.exe and the
    no-console defenseclaw-hook.exe) and a .tar.gz elsewhere (containing
    defenseclaw), matching .goreleaser.yaml.
    """
    archive = _gateway_archive_name(version, os_name, arch)
    url = f"{GITHUB_DL}/{version}/{archive}"

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
    hook_name = _hook_binary_filename(os_name)
    if hook_name and not os.path.isfile(os.path.join(staging_dir, hook_name)):
        ux.err(
            f"Gateway archive did not contain the expected {hook_name} launcher.",
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
    url = f"{GITHUB_DL}/{version}/{whl_name}"

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

    F-0202: a downloaded ``checksums.txt`` is trusted when either its
    Sigstore signature verifies or the release shipped signature assets but
    the local host cannot run cosign. The latter is a deliberate operator-UX
    compromise: checksum validation still protects against a corrupt or
    swapped payload, and the command prints a warning naming the missing
    verifier. Other unsigned/unverifiable states still fail closed unless the
    operator passed ``allow_unverified``.
    """
    dest = _download_optional_release_asset(version, _CHECKSUMS_FILENAME, staging_dir)
    if not dest:
        return None

    _verify_checksums_sigstore(
        version, staging_dir, dest, allow_unverified=allow_unverified,
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


def _fail_unsigned_checksums(message: str, allow_unverified: bool) -> None:
    """Fail closed on an unsigned/unverifiable checksum manifest.

    When ``allow_unverified`` is set the operator has knowingly opted into
    the supply-chain risk, so we warn and let the caller proceed; otherwise
    we abort the upgrade.
    """
    if allow_unverified:
        ux.warn(f"{message} Continuing because --allow-unverified is set.", indent="  ")
        return
    ux.err(message, indent="  ")
    ux.subhead("Re-run with --allow-unverified to override (UNSAFE).", indent="    ")
    raise SystemExit(1)


def _verify_checksums_sigstore(
    version: str,
    staging_dir: str,
    checksums_path: str,
    allow_unverified: bool = False,
) -> None:
    """Verify checksums.txt with its Sigstore cert/signature.

    Fails closed (``SystemExit``) when the manifest cannot be trusted, unless
    ``allow_unverified`` is set:

    * F-0202: an unsigned manifest (no ``.sig``/``.pem`` assets, or only
      one of them) is untrusted — a checksum match against an unsigned
      manifest proves nothing about provenance.
    * Bad Sigstore signatures are untrusted.
    * Missing local ``cosign`` is a warning, not a hard stop, when both
      Sigstore assets are present. The operator still gets SHA-256 checksum
      validation and an explicit reminder to install cosign for provenance
      verification.
    """
    sig_path = _download_optional_release_asset(version, f"{_CHECKSUMS_FILENAME}.sig", staging_dir)
    cert_path = _download_optional_release_asset(version, f"{_CHECKSUMS_FILENAME}.pem", staging_dir)

    if not sig_path and not cert_path:
        _fail_unsigned_checksums(
            "checksums.txt is not signed (no Sigstore signature/certificate "
            "assets were published) — refusing to trust an unsigned checksum "
            "manifest.",
            allow_unverified,
        )
        return
    if not sig_path or not cert_path:
        _fail_unsigned_checksums(
            "checksums.txt Sigstore signature assets are incomplete — "
            "refusing to trust a checksum manifest that cannot be verified.",
            allow_unverified,
        )
        return

    cosign = shutil.which("cosign")
    if not cosign:
        ux.warn(
            "checksums.txt Sigstore signature is present, but cosign was "
            "not found on PATH; continuing with checksum verification only. "
            "Install cosign to verify release provenance.",
            indent="  ",
        )
        return

    cmd = [
        cosign,
        "verify-blob",
        "--certificate",
        cert_path,
        "--signature",
        sig_path,
        "--certificate-identity-regexp",
        f"^https://github.com/{GITHUB_REPO}/.+",
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
    url = f"{GITHUB_DL}/{version}/{filename}"
    dest = os.path.join(staging_dir, filename)
    resp = None
    for attempt in range(1, 4):
        try:
            resp = requests.get(url, timeout=15, allow_redirects=True)
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
            f"{message}; continuing without release-specific upgrade policy "
            "(--allow-unverified).",
            indent="  ",
        )
        return
    ux.err(
        f"{message} — refusing to upgrade without the release's mandatory "
        "upgrade policy.",
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
    url = f"{GITHUB_DL}/{version}/{_UPGRADE_MANIFEST_FILENAME}"
    dest = os.path.join(staging_dir, _UPGRADE_MANIFEST_FILENAME)
    try:
        resp = requests.get(url, timeout=15, allow_redirects=True)
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
        ux.ok(
            "Upgrade manifest loaded "
            f"(required migrations: {', '.join(required)})"
        )
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
            f"{_UPGRADE_MANIFEST_FILENAME} release_version mismatch: "
            f"expected {version}, got {release_version!r}.",
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

    policy = payload.get("migration_failure_policy", "warn")
    if policy not in ("warn", "fail"):
        ux.err(
            f"{_UPGRADE_MANIFEST_FILENAME} has invalid migration_failure_policy: "
            f"{policy!r}.",
            indent="  ",
        )
        raise SystemExit(1)

    required_raw = payload.get("required_cli_migrations", [])
    if not isinstance(required_raw, list) or not all(isinstance(v, str) for v in required_raw):
        ux.err(
            f"{_UPGRADE_MANIFEST_FILENAME} required_cli_migrations must be "
            "a list of version strings.",
            indent="  ",
        )
        raise SystemExit(1)
    required = []
    seen: set[str] = set()
    for migration_version in required_raw:
        if not _VERSION_RE.fullmatch(migration_version):
            ux.err(
                f"{_UPGRADE_MANIFEST_FILENAME} contains invalid migration "
                f"version {migration_version!r}.",
                indent="  ",
            )
            raise SystemExit(1)
        if migration_version not in seen:
            required.append(migration_version)
            seen.add(migration_version)

    return {
        "schema_version": schema_version,
        "release_version": release_version,
        "min_upgrade_protocol": min_protocol,
        "migration_failure_policy": policy,
        "required_cli_migrations": required,
    }


def _print_new_upgrade_script_hint(version: str) -> None:
    url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{version}/scripts/upgrade.sh"
    ux.subhead(
        "Use the upgrade script shipped with that release:",
        indent="    ",
    )
    ux.subhead(
        f"curl -fsSL {url} | bash -s -- --version {version}",
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
        version
        for version in required
        if isinstance(version, str) and not migration_state.is_applied(state, version)
    ]
    if not missing:
        return

    label = "Required" if policy == "fail" else "Expected"
    ux.warn(
        f"{label} migration(s) were not recorded in the migration cursor: "
        + ", ".join(missing),
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
        sha = digest[len(prefix):]
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
            "Re-run with --allow-unverified to install these artifacts using "
            "unsigned GitHub asset digests (UNSAFE).",
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
            f"Checksum mismatch for {filename}: "
            f"expected {expected}, got {actual}",
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
        snapshot = os.path.join(
            backup_dir, _installed_gateway_filename(os_name) + ".previous"
        )
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

    hook_source = None
    hook_target = None
    if os_name == "windows":
        hook_name = _hook_binary_filename(os_name)
        assert hook_name is not None
        hook_source = os.path.join(os.path.dirname(binary_path), hook_name)
        hook_target = os.path.join(install_dir, hook_name)
        if not os.path.isfile(hook_source):
            ux.err(f"Windows hook launcher is missing: {hook_source}", indent="  ")
            raise SystemExit(1)

        if backup_dir and os.path.isfile(hook_target):
            try:
                snapshot = os.path.join(backup_dir, hook_name + ".previous")
                shutil.copy2(hook_target, snapshot)
            except OSError as exc:
                ux.warn(
                    f"Could not snapshot previous hook launcher: {exc}",
                    indent="  ",
                )

    shutil.copy2(binary_path, target)
    if hook_source and hook_target:
        shutil.copy2(hook_source, hook_target)
    # chmod's executable bits are meaningless on Windows (and os.chmod there only
    # toggles the read-only flag); the gateway was already stopped above, so the
    # copy can overwrite the prior .exe.
    if os_name != "windows":
        os.chmod(target, 0o755)
        if os_name == "darwin":
            subprocess.run(["codesign", "-f", "-s", "-", target], capture_output=True, check=False)
    ux.ok("Gateway binary installed")
    if hook_target:
        ux.ok("No-console hook launcher installed")
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
            capture_output=True, text=True, timeout=10, check=False,
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
        subprocess.run([uv, "--no-config", "venv", venv, "--python", "3.12"], check=True)

    managed_env = os.environ.copy()
    managed_env.pop("PYTHONHOME", None)
    managed_env.pop("PYTHONPATH", None)
    subprocess.run(
        [
            uv,
            "--no-config",
            "pip",
            "install",
            "--python",
            venv_python,
            "--quiet",
            "--reinstall",
            "--no-cache",
            "--strict",
            whl_path,
        ],
        check=True,
        env=managed_env,
    )
    try:
        subprocess.run(
            [uv, "--no-config", "pip", "check", "--python", venv_python],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            env=managed_env,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        output = ""
        if isinstance(exc, subprocess.CalledProcessError):
            output = "\n".join((exc.stdout or "", exc.stderr or ""))
        detail = " | ".join(line.strip() for line in output.splitlines()[:5] if line.strip())
        suffix = f": {detail[:1000]}" if detail else ""
        ux.err(f"Managed CLI dependency validation failed{suffix}", indent="  ")
        raise SystemExit(1) from exc

    try:
        subprocess.run(
            [venv_python, "-I", "-c", _TUI_SMOKE_CODE],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            env=managed_env,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        output = ""
        if isinstance(exc, subprocess.CalledProcessError):
            output = "\n".join((exc.stdout or "", exc.stderr or ""))
        detail = " | ".join(line.strip() for line in output.splitlines()[:5] if line.strip())
        suffix = f": {detail[:1000]}" if detail else ""
        ux.err(f"Managed TUI launch validation failed{suffix}", indent="  ")
        raise SystemExit(1) from exc

    install_dir = os.path.expanduser("~/.local/bin")
    os.makedirs(install_dir, exist_ok=True)

    if os_name == "windows":
        cli_exe = os.path.join(venv, "Scripts", "defenseclaw.exe")
        _publish_windows_cli_launcher(cli_exe, install_dir)
    else:
        symlink = os.path.join(install_dir, "defenseclaw")
        venv_bin = os.path.join(venv, "bin", "defenseclaw")
        if os.path.isfile(venv_bin):
            if os.path.islink(symlink) or os.path.exists(symlink):
                os.remove(symlink)
            os.symlink(venv_bin, symlink)
    ux.ok("Python CLI installed")


def _publish_windows_cli_launcher(cli_exe: str, install_dir: str) -> None:
    """Atomically publish the Windows CLI shim after removing an exact .exe shadow."""
    if not os.path.isfile(cli_exe):
        ux.err(f"Managed CLI executable not found: {cli_exe}", indent="  ")
        raise SystemExit(1)

    shim = os.path.join(install_dir, "defenseclaw.cmd")
    shadow = os.path.join(install_dir, "defenseclaw.exe")
    fd, temporary_shim = tempfile.mkstemp(
        prefix=".defenseclaw.cmd.", suffix=".tmp", dir=install_dir
    )
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="") as stream:
            fd = -1
            stream.write(f'@echo off\r\n"{cli_exe}" %*\r\n')

        if os.path.lexists(shadow):
            try:
                # unlink removes the exact directory entry and never follows a
                # symlink or launches/inspects the untrusted executable.
                os.unlink(shadow)
            except OSError as exc:
                ux.err(f"Cannot remove shadowing CLI launcher '{shadow}': {exc}", indent="  ")
                raise SystemExit(1) from exc
            if os.path.lexists(shadow):
                ux.err(f"Cannot remove shadowing CLI launcher '{shadow}': entry still exists", indent="  ")
                raise SystemExit(1)

        os.replace(temporary_shim, shim)
        temporary_shim = ""
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary_shim and os.path.lexists(temporary_shim):
            os.unlink(temporary_shim)


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
    script = """
import json
import sys

from defenseclaw.migrations import run_migrations

count = run_migrations(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
with open(sys.argv[5], "w", encoding="utf-8") as fh:
    json.dump({"count": count}, fh)
"""
    try:
        subprocess.run(
            [
                venv_python,
                "-c",
                script,
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


def _venv_python_path(venv: str, os_name: str) -> str:
    scripts_subdir = "Scripts" if os_name == "windows" else "bin"
    python_exe = "python.exe" if os_name == "windows" else "python"
    return os.path.join(venv, scripts_subdir, python_exe)


def _fail_wheel_preflight(message: str, exc: subprocess.CalledProcessError | None = None) -> None:
    ux.err(message, indent="  ")
    if exc is not None:
        output = "\n".join(part for part in (exc.stderr, exc.stdout) if part).strip()
        if output:
            tail = "\n".join(output.splitlines()[-20:])
            ux.subhead(tail, indent="    ")
    ux.subhead("No services were stopped and no installed artifacts were changed.", indent="    ")
    raise SystemExit(1)


def _preflight_wheel_install(whl_path: str, os_name: str | None = None) -> None:
    """Resolve the downloaded wheel before the upgrade mutates services.

    A release wheel can be checksum-valid but dependency-unsatisfiable. Running
    uv's dry-run resolver before backup/stop/install keeps that failure mode
    from leaving the operator with a fresh gateway and the old Python CLI.
    """
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


def _poll_health(cfg, timeout_seconds: int = 60) -> None:
    """Poll the sidecar health endpoint until healthy or timeout."""
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
    click.echo(
        f"  {ux.dim('→')} Waiting for gateway to become healthy "
        f"(timeout {timeout_seconds}s) ..."
    )

    while time.monotonic() < deadline:
        try:
            snap = client.health()
            if snap and isinstance(snap, dict):
                last_err = ""
                gw_state = snap.get("gateway", {}).get("state", "unknown")
                if gw_state != last_state:
                    click.echo(
                        f"    {ux.dim('gateway:')} {gw_state}"
                    )
                    last_state = gw_state
                if gw_state == "running":
                    ux.ok("Gateway is healthy")
                    return
            else:
                # 2xx with an empty/non-dict body — treat like unreachable so
                # the operator still sees a progress line instead of silence.
                err_label = "health endpoint returned no payload"
                if err_label != last_err:
                    click.echo(
                        f"    {ux.dim('gateway:')} unreachable ({err_label})"
                    )
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
                click.echo(
                    f"    {ux.dim('gateway:')} unreachable ({err_label})"
                )
                last_err = err_label
                last_state = ""
        time.sleep(2)

    ux.warn(f"Gateway did not become healthy within {timeout_seconds}s")
    ux.subhead(
        "Check logs: ~/.defenseclaw/gateway.log (pretty) / "
        "~/.defenseclaw/gateway.jsonl (structured)"
    )
    ux.subhead("Run:  defenseclaw-gateway status")


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
            resp = requests.get(url, stream=True, timeout=60, allow_redirects=True)
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
    backup_dir = os.path.join(backup_root, f"upgrade-{timestamp}")
    os.makedirs(backup_dir, exist_ok=True)

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


def _run_silent(cmd: list[str], ok_msg: str, fail_msg: str) -> bool:
    """Run a command, printing ok_msg on success and fail_msg on failure.

    On non-zero exit, surface the first few stderr/stdout lines so an
    operator can correlate with logs immediately instead of needing a
    second debug pass with the same command. Exceptions (missing
    binary, timeout) are caught and reported similarly so the upgrade
    flow never raises mid-restart.
    """
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode == 0:
            ux.ok(ok_msg)
            return True
        ux.warn(fail_msg)
        err = (result.stderr or result.stdout or "").strip()
        if err:
            for line in err.splitlines()[:5]:
                ux.subhead(line, indent="    ")
        return False
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        ux.warn(fail_msg)
        ux.subhead(str(exc), indent="    ")
        return False
