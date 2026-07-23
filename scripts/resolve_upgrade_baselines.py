#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Materialize the effective upgrade-baseline policy for one candidate.

The checked-in policy is the reviewed historical floor. Newer stable releases
are admitted without a source edit only after GitHub reports them immutable and
their release-owned manifest is authenticated by the signed checksums produced
by ``release.yaml``. The resulting schema-2 document is candidate input and
must be sealed with the candidate/certification evidence that consumed it.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "release" / "upgrade-baselines.json"
DEFAULT_REPOSITORY = "cisco-ai-defense/defenseclaw"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ASSET = re.compile(r"^[A-Za-z0-9._-]+$")
MAX_RELEASE_INVENTORY_BYTES = 8 * 1024 * 1024
MAX_CHECKSUMS_BYTES = 8 * 1024 * 1024
MAX_CERTIFICATE_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_RELEASE_PAGES = 20
MAX_DOWNLOAD_ATTEMPTS = 4
INITIAL_DOWNLOAD_RETRY_DELAY_SECONDS = 1.0
TRANSIENT_HTTP_STATUSES = frozenset({408, 425, 429})


class BaselineResolutionError(RuntimeError):
    """An effective baseline could not be authenticated or materialized."""


def _version_key(version: str) -> tuple[int, int, int]:
    if not isinstance(version, str) or SEMVER.fullmatch(version) is None:
        raise BaselineResolutionError(f"invalid canonical version: {version!r}")
    return tuple(map(int, version.split(".")))


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _checked_policy(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BaselineResolutionError(f"could not read baseline floor {path}: {exc}") from exc
    expected = {
        "schema_version",
        "published_baselines",
        "published_baseline_config_versions",
        "platform_published_baselines",
    }
    if not isinstance(document, dict) or set(document) != expected:
        raise BaselineResolutionError("checked baseline floor has unexpected fields")
    if document.get("schema_version") != 2:
        raise BaselineResolutionError("checked baseline floor must use schema_version 2")
    versions = document.get("published_baselines")
    configs = document.get("published_baseline_config_versions")
    platforms = document.get("platform_published_baselines")
    if not isinstance(versions, list) or not versions:
        raise BaselineResolutionError("checked baseline floor is empty")
    if any(not isinstance(item, str) or SEMVER.fullmatch(item) is None for item in versions):
        raise BaselineResolutionError("checked baseline floor contains a non-canonical version")
    if len(versions) != len(set(versions)) or versions != sorted(versions, key=_version_key, reverse=True):
        raise BaselineResolutionError("checked baseline floor must be unique descending semver")
    if not isinstance(configs, dict) or set(configs) != set(versions):
        raise BaselineResolutionError("checked baseline config map does not match its versions")
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in configs.values()):
        raise BaselineResolutionError("checked baseline config versions must be positive")
    if not isinstance(platforms, dict) or set(platforms) != {"windows"}:
        raise BaselineResolutionError("checked baseline platforms must contain exactly windows")
    windows = platforms["windows"]
    if (
        not isinstance(windows, list)
        or not windows
        or len(windows) != len(set(windows))
        or windows != [item for item in versions if item in set(windows)]
    ):
        raise BaselineResolutionError(
            "checked Windows baselines must be a non-empty ordered subset of the global floor"
        )
    return document


def _parse_checksums(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise BaselineResolutionError("published checksums are not UTF-8") from exc
    checksums: dict[str, str] = {}
    for number, line in enumerate(lines, start=1):
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([0-9A-Fa-f]{64})[ \t]+([A-Za-z0-9._-]+)", line)
        if match is None:
            raise BaselineResolutionError(f"invalid published checksum line {number}")
        digest, name = match.groups()
        if SAFE_ASSET.fullmatch(name) is None or name in checksums:
            raise BaselineResolutionError(f"unsafe or duplicate published checksum name: {name!r}")
        checksums[name] = digest.lower()
    if not checksums:
        raise BaselineResolutionError("published checksum manifest is empty")
    return checksums


def _asset_map(release: dict[str, Any]) -> dict[str, dict[str, Any]]:
    assets = release.get("assets")
    if not isinstance(assets, list) or not assets:
        raise BaselineResolutionError("immutable release has no asset inventory")
    result: dict[str, dict[str, Any]] = {}
    for item in assets:
        if not isinstance(item, dict):
            raise BaselineResolutionError("release asset inventory contains a non-object")
        name = item.get("name")
        digest = item.get("digest")
        url = item.get("url") or item.get("browser_download_url")
        if (
            not isinstance(name, str)
            or SAFE_ASSET.fullmatch(name) is None
            or name in result
            or not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or SHA256.fullmatch(digest.removeprefix("sha256:")) is None
            or not isinstance(url, str)
            or not url.startswith("https://")
        ):
            raise BaselineResolutionError(f"release has invalid asset metadata: {name!r}")
        normalized = dict(item)
        normalized["_download_url"] = url
        result[name] = normalized
    return result


def _required_windows_assets(version: str) -> set[str]:
    names = {
        "DefenseClawSetup-x64.exe",
        "DefenseClawSetup-x64.exe.sha256",
        "DefenseClawSetup-x64.exe.provenance.json",
        "DefenseClawSetup-x64.exe.sbom.json",
    }
    for arch in ("amd64", "arm64"):
        protected = f"defenseclaw_{version}_protocol2_windows_{arch}.dcgateway"
        names.update((protected, f"{protected}.sbom.json"))
    return names


def _required_posix_assets(version: str) -> set[str]:
    names = {f"defenseclaw-{version}-2-py3-none-any.dcwheel"}
    for os_name in ("darwin", "linux"):
        for arch in ("amd64", "arm64"):
            names.add(f"defenseclaw_{version}_protocol2_{os_name}_{arch}.dcgateway")
    return names


def _write_private(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _download(
    url: str,
    max_bytes: int,
    *,
    token: str | None = None,
    accept: str = "application/octet-stream",
    sleeper: Callable[[float], None] = time.sleep,
) -> bytes:
    headers = {
        "Accept": accept,
        "User-Agent": "defenseclaw-release-baseline-resolver",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    for attempt in range(1, MAX_DOWNLOAD_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                length = response.headers.get("Content-Length")
                if length is not None and int(length) > max_bytes:
                    raise BaselineResolutionError(f"download exceeds bound: {url}")
                payload = response.read(max_bytes + 1)
            break
        except urllib.error.HTTPError as exc:
            transient = exc.code in TRANSIENT_HTTP_STATUSES or 500 <= exc.code < 600
            if not transient:
                raise BaselineResolutionError(f"could not download {url}: {exc}") from exc
            failure: Exception = exc
        except (http.client.HTTPException, OSError, urllib.error.URLError) as exc:
            failure = exc
        except ValueError as exc:
            raise BaselineResolutionError(f"could not download {url}: {exc}") from exc

        if attempt == MAX_DOWNLOAD_ATTEMPTS:
            raise BaselineResolutionError(
                f"could not download {url} after {MAX_DOWNLOAD_ATTEMPTS} attempts: {failure}"
            ) from failure
        delay = INITIAL_DOWNLOAD_RETRY_DELAY_SECONDS * (2 ** (attempt - 1))
        print(
            f"transient download failure for {url}; "
            f"retrying attempt {attempt + 1}/{MAX_DOWNLOAD_ATTEMPTS} in {delay:g}s",
            file=sys.stderr,
        )
        sleeper(delay)
    if len(payload) == 0 or len(payload) > max_bytes:
        raise BaselineResolutionError(f"download is empty or exceeds bound: {url}")
    return payload


def _verify_sigstore(
    checksums: Path,
    certificate: Path,
    signature: Path,
    *,
    repository: str,
    cosign: str,
) -> None:
    command = [
        sys.executable,
        str(ROOT / "scripts" / "verify-sigstore-blob.py"),
        "--cosign",
        cosign,
        "--certificate",
        str(certificate),
        "--signature",
        str(signature),
        "--certificate-identity",
        f"https://github.com/{repository}/.github/workflows/release.yaml@refs/heads/main",
        "--certificate-oidc-issuer",
        OIDC_ISSUER,
        str(checksums),
    ]
    try:
        completed = subprocess.run(command, check=False, timeout=400)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BaselineResolutionError("could not execute bounded Sigstore verification") from exc
    if completed.returncode != 0:
        raise BaselineResolutionError("published baseline Sigstore verification failed")


Download = Callable[[str, int], bytes]
Verifier = Callable[[Path, Path, Path], None]


def _authenticate_release(
    release: dict[str, Any],
    *,
    version: str,
    candidate_runtime_config_version: int,
    download: Download,
    verify: Verifier,
) -> tuple[int, bool]:
    assets = _asset_map(release)
    required_metadata = {
        "checksums.txt": MAX_CHECKSUMS_BYTES,
        "checksums.txt.pem": MAX_CERTIFICATE_BYTES,
        "checksums.txt.sig": MAX_SIGNATURE_BYTES,
        "upgrade-manifest.json": MAX_MANIFEST_BYTES,
    }
    missing = sorted(set(required_metadata) - set(assets))
    if missing:
        raise BaselineResolutionError(f"immutable release {version} lacks authentication assets: {missing}")
    fetched: dict[str, bytes] = {}
    for name, maximum in required_metadata.items():
        item = assets[name]
        payload = download(item["_download_url"], maximum)
        expected = item["digest"].removeprefix("sha256:")
        if _sha256(payload) != expected:
            raise BaselineResolutionError(f"GitHub asset digest mismatch for {version}/{name}")
        fetched[name] = payload

    with tempfile.TemporaryDirectory(prefix="defenseclaw-baseline-auth-") as temporary:
        custody = Path(temporary)
        custody.chmod(0o700)
        paths: dict[str, Path] = {}
        for name, payload in fetched.items():
            path = custody / name
            _write_private(path, payload)
            paths[name] = path
        verify(paths["checksums.txt"], paths["checksums.txt.pem"], paths["checksums.txt.sig"])

    checksums = _parse_checksums(fetched["checksums.txt"])
    manifest_digest = checksums.get("upgrade-manifest.json")
    if manifest_digest is None or manifest_digest != _sha256(fetched["upgrade-manifest.json"]):
        raise BaselineResolutionError(f"upgrade manifest for {version} is not covered by authenticated checksums")
    # Every actually published payload must be covered by the signed checksum
    # manifest and GitHub's immutable digest. The sealed candidate may contain
    # platform payloads intentionally omitted at publication (0.8.4's Windows
    # bytes are the precedent), so signed-but-unpublished entries do not widen
    # platform support and are not themselves an error.
    authentication_assets = {"checksums.txt", "checksums.txt.pem", "checksums.txt.sig"}
    for name, item in assets.items():
        if name in authentication_assets:
            continue
        digest = checksums.get(name)
        if digest is None or item["digest"].removeprefix("sha256:") != digest:
            raise BaselineResolutionError(f"signed checksum and immutable GitHub asset disagree for {version}/{name}")
    try:
        manifest = json.loads(fetched["upgrade-manifest.json"].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BaselineResolutionError(f"published upgrade manifest for {version} is invalid") from exc
    runtime_config = manifest.get("runtime_config_version") if isinstance(manifest, dict) else None
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != 2
        or manifest.get("release_version") != version
        or not isinstance(runtime_config, int)
        or isinstance(runtime_config, bool)
        or runtime_config < 1
        or runtime_config > candidate_runtime_config_version
    ):
        raise BaselineResolutionError(f"published upgrade manifest for {version} has invalid release/config identity")
    posix = _required_posix_assets(version)
    if not posix.issubset(checksums) or not posix.issubset(assets):
        raise BaselineResolutionError(f"published release {version} lacks its complete POSIX runtime")
    windows = _required_windows_assets(version)
    published_windows = windows & set(assets)
    if published_windows and published_windows != windows:
        raise BaselineResolutionError(f"published release {version} has a partial Windows runtime capability")
    return runtime_config, published_windows == windows


def resolve_effective_policy(
    *,
    target_version: str,
    candidate_runtime_config_version: int,
    releases: Sequence[dict[str, Any]],
    checked_policy_path: Path = DEFAULT_POLICY,
    download: Download,
    verify: Verifier,
) -> dict[str, Any]:
    target_key = _version_key(target_version)
    if (
        not isinstance(candidate_runtime_config_version, int)
        or isinstance(candidate_runtime_config_version, bool)
        or candidate_runtime_config_version < 1
    ):
        raise BaselineResolutionError("candidate runtime config version must be positive")
    checked = _checked_policy(checked_policy_path)
    checked_versions = list(checked["published_baselines"])
    eligible_checked_versions = [version for version in checked_versions if _version_key(version) < target_key]
    dynamic_floor_key = max(
        (_version_key(version) for version in eligible_checked_versions),
        default=None,
    )
    if any(
        checked["published_baseline_config_versions"][version] > candidate_runtime_config_version
        for version in eligible_checked_versions
    ):
        raise BaselineResolutionError("eligible checked baseline config version is newer than the candidate runtime")
    candidates: dict[str, dict[str, Any]] = {}
    for release in releases:
        if not isinstance(release, dict):
            raise BaselineResolutionError("release inventory contains a non-object")
        tag = release.get("tag_name")
        if not isinstance(tag, str) or SEMVER.fullmatch(tag) is None:
            continue
        key = _version_key(tag)
        if dynamic_floor_key is None or not dynamic_floor_key < key < target_key:
            continue
        if release.get("draft") is not False or release.get("prerelease") is not False:
            continue
        if release.get("immutable") is not True:
            raise BaselineResolutionError(f"published stable release {tag} is not immutable")
        if tag in candidates:
            raise BaselineResolutionError(f"release inventory contains duplicate tag {tag}")
        candidates[tag] = release

    dynamic_versions = sorted(candidates, key=_version_key, reverse=True)
    configs = {version: checked["published_baseline_config_versions"][version] for version in eligible_checked_versions}
    windows = [
        version
        for version in checked["platform_published_baselines"]["windows"]
        if version in eligible_checked_versions
    ]
    dynamic_windows: list[str] = []
    for version in dynamic_versions:
        runtime_config, has_windows = _authenticate_release(
            candidates[version],
            version=version,
            candidate_runtime_config_version=candidate_runtime_config_version,
            download=download,
            verify=verify,
        )
        configs[version] = runtime_config
        if has_windows:
            dynamic_windows.append(version)

    versions = [*dynamic_versions, *eligible_checked_versions]
    if not versions:
        raise BaselineResolutionError(f"no supported published baseline predates candidate {target_version}")
    ordered_configs = {version: configs[version] for version in versions}
    return {
        "schema_version": 2,
        "published_baselines": versions,
        "published_baseline_config_versions": ordered_configs,
        "platform_published_baselines": {"windows": [*dynamic_windows, *windows]},
    }


def _release_inventory(repository: str, token: str | None) -> list[dict[str, Any]]:
    releases: list[dict[str, Any]] = []
    for page in range(1, MAX_RELEASE_PAGES + 1):
        url = f"https://api.github.com/repos/{repository}/releases?per_page=100&page={page}"
        payload = _download(
            url,
            MAX_RELEASE_INVENTORY_BYTES,
            token=token,
            accept="application/vnd.github+json",
        )
        try:
            rows = json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise BaselineResolutionError("GitHub release inventory is invalid") from exc
        if not isinstance(rows, list) or any(not isinstance(item, dict) for item in rows):
            raise BaselineResolutionError("GitHub release inventory must be an object array")
        releases.extend(rows)
        if len(rows) < 100:
            return releases
    raise BaselineResolutionError("GitHub release inventory exceeded the pagination bound")


def _source_runtime_config_version(target_version: str) -> int:
    target = _version_key(target_version)
    if target >= (0, 8, 5):
        path = ROOT / "internal" / "config" / "observability_v8_types.go"
        pattern = r"^\s*ObservabilityV8ConfigVersion\s*=\s*([1-9][0-9]*)\s*$"
    else:
        path = ROOT / "internal" / "config" / "config.go"
        pattern = r"^\s*const\s+CurrentConfigVersion\s*=\s*([1-9][0-9]*)\s*$"
    match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
    if match is None:
        raise BaselineResolutionError(f"could not resolve candidate runtime config from {path}")
    return int(match.group(1))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument("--candidate-runtime-config-version", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        runtime_config = (
            args.candidate_runtime_config_version
            if args.candidate_runtime_config_version is not None
            else _source_runtime_config_version(args.target_version)
        )
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        releases = _release_inventory(args.repository, token)

        def download(url: str, maximum: int) -> bytes:
            return _download(url, maximum, token=token)

        def verify(checksums: Path, certificate: Path, signature: Path) -> None:
            _verify_sigstore(
                checksums,
                certificate,
                signature,
                repository=args.repository,
                cosign=args.cosign,
            )

        policy = resolve_effective_policy(
            target_version=args.target_version,
            candidate_runtime_config_version=runtime_config,
            releases=releases,
            checked_policy_path=args.policy,
            download=download,
            verify=verify,
        )
        if args.output.exists() or args.output.is_symlink():
            raise BaselineResolutionError(f"output already exists: {args.output}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        _write_private(args.output, (json.dumps(policy, indent=2) + "\n").encode())
    except (BaselineResolutionError, OSError, UnicodeError) as exc:
        print(f"effective upgrade-baseline resolution failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
