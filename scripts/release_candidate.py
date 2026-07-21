#!/usr/bin/env python3
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

"""Build and verify the immutable release-candidate custody bundle.

The release workflow builds platform artifacts once, seals their exact bytes in
this bundle, and gives the same GitHub Actions artifact to every upgrade gate
and the final publisher.  ``checksums.txt`` is the public release manifest;
``release-candidate.json`` additionally covers that manifest and its Sigstore
proof so a later job cannot silently substitute any file.
"""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import hashlib
import io
import json
import os
import re
import shutil
import ssl
import stat
import struct
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from scripts.source_release_identity import (
        SourceIdentityError,
        release_identity_for_version,
    )
except ModuleNotFoundError:  # Direct ``python scripts/release_candidate.py`` execution.
    from source_release_identity import SourceIdentityError, release_identity_for_version

try:
    from scripts.telemetry_runtime_assets import RuntimeAssetError, read_logical_asset
except ModuleNotFoundError:  # Direct ``python scripts/release_candidate.py`` execution.
    from telemetry_runtime_assets import RuntimeAssetError, read_logical_asset

SCHEMA_VERSION = 2
RUNTIME_ATTESTATION_FILENAME = "runtime-candidate-checksums.txt"
RELEASE_SOURCE_MAP_FILENAME = "release-source-map.json"
RELEASE_SOURCE_MAP_SCHEMA_VERSION = 1
RELEASE_PROVENANCE_FILENAME = "release-provenance.json"
RELEASE_PROVENANCE_SCHEMA_VERSION = 1
VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_GATEWAY_BINARY_BYTES = 512 * 1024 * 1024
PROTECTED_ARTIFACT_MAGIC = b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n"
PROTECTED_ARTIFACT_XOR_BYTE = 0xA5
PROTECTED_ARTIFACT_TRANSLATION = bytes(
    value ^ PROTECTED_ARTIFACT_XOR_BYTE for value in range(256)
)
MAX_PROTECTED_ARTIFACT_BYTES = MAX_GATEWAY_BINARY_BYTES + len(PROTECTED_ARTIFACT_MAGIC)
ROOT = Path(__file__).resolve().parents[1]
V8_CONFIG_WHEEL_RESOURCES = (
    (
        "defenseclaw/_data/config/v8/defenseclaw-config.schema.json",
        "schemas/config/v8/defenseclaw-config.schema.json",
    ),
    (
        "defenseclaw/_data/config/v8/observability.yaml",
        "schemas/config/v8/reference/observability.yaml",
    ),
    (
        "defenseclaw/_data/config/v8/observability.md",
        "schemas/config/v8/reference/observability.md",
    ),
)
V8_TELEMETRY_WHEEL_RESOURCES = (
    (
        "defenseclaw/_data/telemetry/v8/telemetry.schema.json",
        "schemas/telemetry/generated/telemetry.schema.json",
    ),
    (
        "defenseclaw/_data/telemetry/v8/catalog.json",
        "schemas/telemetry/generated/catalog.json",
    ),
    (
        "defenseclaw/_data/telemetry/v8/v7-exporter-selection.json",
        "schemas/telemetry/generated/compatibility/v7-exporter-selection.json",
    ),
    (
        "defenseclaw/_data/telemetry/v8/galileo-rich-v2.json",
        "schemas/telemetry/generated/compatibility/galileo-rich-v2.json",
    ),
    (
        "defenseclaw/_data/telemetry/v8/local-observability-v1.json",
        "schemas/telemetry/generated/compatibility/local-observability-v1.json",
    ),
    (
        "defenseclaw/_data/telemetry/v8/openinference-v1.json",
        "schemas/telemetry/generated/compatibility/openinference-v1.json",
    ),
)
UPGRADE_BASELINES_PATH = Path(
    os.environ.get(
        "UPGRADE_BASELINE_POLICY",
        str(ROOT / "release" / "upgrade-baselines.json"),
    )
)
HISTORICAL_ARTIFACT_DIGESTS_PATH = ROOT / "release" / "historical-artifact-digests.json"
RUNTIME_CONFIG_PATH = ROOT / "internal" / "config" / "config.go"
RESOLVER_COMPLETENESS_MARKER = b"# DefenseClaw upgrade resolver complete v1"
RESOLVER_ASSET_SOURCES = {
    "defenseclaw-upgrade.sh": ROOT / "scripts" / "upgrade.sh",
    "defenseclaw-upgrade.ps1": ROOT / "scripts" / "upgrade.ps1",
}
MAX_RESOLVER_BYTES = 4 * 1024 * 1024
MAX_RELEASE_CERTIFICATE_BYTES = 64 * 1024
MAX_EFFECTIVE_UPGRADE_BASELINES_BYTES = 1024 * 1024
EFFECTIVE_UPGRADE_BASELINES_FILENAME = "effective-upgrade-baselines.json"
STRICT_BASE64_RE = re.compile(
    rb"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
)
MACOS_VERIFICATION_STATUSES = ("notarized", "unverified")
WINDOWS_SETUP_START_VERSION = (0, 8, 6)
WINDOWS_SETUP_ASSET = "DefenseClawSetup-x64.exe"
WINDOWS_SETUP_PUBLISHER = "Cisco Systems, Inc."
WINDOWS_SETUP_CLIENTS = {
    "codex": "0.144.3",
    "claudecode": "2.1.208",
}
WINDOWS_SETUP_CERTIFICATION_REQUIREMENTS = (
    "automatic-codex-trust",
    "lifecycle",
    "tool-allow",
    "tool-block",
    "gateway-jsonl",
    "audit-correlation",
    "connector-otlp",
    "repair",
    "upgrade",
    "uninstall",
)
CHECKSUMS_BUNDLE_FILENAME = "checksums.txt.bundle"
MAX_WINDOWS_SETUP_BYTES = 2 * 1024 * 1024 * 1024
MAX_WINDOWS_SETUP_METADATA_BYTES = 128 * 1024 * 1024
MAX_LEGACY_COSIGN_BUNDLE_BYTES = 16 * 1024 * 1024
WINDOWS_PYTHON_EMBED_NAME = "python-3.13.14-embed-amd64.zip"
WINDOWS_PYTHON_EMBED_URL = (
    "https://www.python.org/ftp/python/3.13.14/python-3.13.14-embed-amd64.zip"
)
WINDOWS_PYTHON_EMBED_SHA256 = "90b4e5b9898b72d744650524bff92377c367f44bd5fbd09e3148656c080ad907"
WINDOWS_PYTHON_RUNTIME_REVIEW_DEADLINE = "2026-09-10T00:00:00.0000000+00:00"
WINDOWS_YARA_COMPAT_WHEEL = "yara_python-4.5.4.post1-py3-none-any.whl"
WINDOWS_WIN_UNICODE_SOURCE_URL = (
    "https://files.pythonhosted.org/packages/89/8d/7aad74930380c8972ab282304a2ff45f3d4927108bb6693cabcc9fc6a099/"
    "win_unicode_console-0.5.zip"
)
WINDOWS_WIN_UNICODE_SOURCE_SHA256 = "d4142d4d56d46f449d6f00536a73625a871cba040f0bc1a2e305a04578f07d1e"
WINDOWS_COSIGN_VERSION = "2.6.2"
WINDOWS_COSIGN_URL = "https://github.com/sigstore/cosign/releases/download/v2.6.2/cosign-windows-amd64.exe"
WINDOWS_COSIGN_SHA256 = "dd6c61e510da627bcaed4cd9db844ec11cacd09826d814d89f7f68d40feb07be"
WINDOWS_RESOURCE_POLICY = "internal/windowsresources"
WINDOWS_RESOURCE_ICON = (
    "macos/DefenseClawMac/DefenseClawMac/Assets.xcassets/AppIcon.appiconset/icon_256.png"
)
WINDOWS_RESOURCE_ICON_SHA256 = "4425858688397762266ceb5304dcbca7afe330ec1c262dd2addcb7539b14b2bf"


class CandidateError(RuntimeError):
    """A release candidate is incomplete, inconsistent, or mutated."""


def _reviewed_source_install_identity(version: str) -> dict[str, int | str]:
    """Bind candidate custody to reviewed compatibility plus the dispatch version."""

    try:
        return release_identity_for_version(version, ROOT)
    except SourceIdentityError as exc:
        raise CandidateError(f"reviewed source-install identity is invalid: {exc}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_bounded_regular_file(path: Path, *, label: str, max_bytes: int) -> bytes:
    """Read one stable bounded regular file without following a leaf symlink."""

    try:
        named_before = path.lstat()
    except OSError as exc:
        raise CandidateError(f"{label} is unavailable: {path}") from exc
    if not stat.S_ISREG(named_before.st_mode) or not 0 < named_before.st_size <= max_bytes:
        raise CandidateError(f"{label} must be a non-empty bounded regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CandidateError(f"{label} is unavailable: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        bytes_read = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - bytes_read))
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            if bytes_read > max_bytes:
                raise CandidateError(f"{label} exceeds its size bound: {path}")
        opened_after = os.fstat(descriptor)
        try:
            named_after = path.lstat()
        except OSError as exc:
            raise CandidateError(f"{label} disappeared while being read: {path}") from exc
        if (
            _file_state(named_before) != _file_state(named_after)
            or _file_state(opened) != _file_state(opened_after)
            or _file_identity(named_after) != _file_identity(opened_after)
            or bytes_read != opened_after.st_size
        ):
            raise CandidateError(f"{label} changed while being read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_size,
        info.st_mtime_ns,
    )


def _file_state(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (*_file_identity(info), info.st_ctime_ns)


def _directory_identity(info: os.stat_result) -> tuple[int, int, int]:
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


def _read_release_certificate(path: Path) -> tuple[bytes, os.stat_result, os.stat_result]:
    """Read one bounded regular certificate file without following a symlink."""

    try:
        parent_info = path.parent.lstat()
    except OSError as exc:
        raise CandidateError(f"release certificate parent is unavailable: {path.parent}") from exc
    if not stat.S_ISDIR(parent_info.st_mode):
        raise CandidateError(f"release certificate parent must be a real directory: {path.parent}")
    try:
        named_before = path.lstat()
    except OSError as exc:
        raise CandidateError(f"release certificate is unavailable: {path}") from exc
    if not stat.S_ISREG(named_before.st_mode):
        raise CandidateError(f"release certificate must be a regular file: {path}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CandidateError(f"release certificate is unavailable: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise CandidateError(f"release certificate must be a regular file: {path}")
        if not 0 < opened.st_size <= MAX_RELEASE_CERTIFICATE_BYTES:
            raise CandidateError(f"release certificate has an invalid size: {path}")
        chunks: list[bytes] = []
        bytes_read = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_RELEASE_CERTIFICATE_BYTES + 1 - bytes_read),
            )
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            if bytes_read > MAX_RELEASE_CERTIFICATE_BYTES:
                raise CandidateError(f"release certificate has an invalid size: {path}")
        opened_after = os.fstat(descriptor)
        try:
            named_after = path.lstat()
        except OSError as exc:
            raise CandidateError(f"release certificate disappeared while being read: {path}") from exc
        if (
            # CPython on Windows exposes creation time as pathname st_ctime,
            # but NTFS change time as descriptor st_ctime. Bind the pathname
            # to the descriptor without comparing those incompatible fields,
            # then retain ctime in each same-API mutation check.
            _file_identity(named_before) != _file_identity(opened)
            or _file_identity(named_after) != _file_identity(opened_after)
            or _file_state(named_before) != _file_state(named_after)
            or _file_state(opened) != _file_state(opened_after)
            or bytes_read != opened_after.st_size
        ):
            raise CandidateError(f"release certificate changed while being read: {path}")
        return b"".join(chunks), named_after, parent_info
    finally:
        os.close(descriptor)


def _canonical_pem_certificate(raw: bytes) -> bytes:
    try:
        text = raw.decode("ascii")
        der = ssl.PEM_cert_to_DER_cert(text)
        canonical = ssl.DER_cert_to_PEM_cert(der).encode("ascii")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise CandidateError("release certificate is not exactly one PEM certificate") from exc
    if not der or raw != canonical:
        raise CandidateError("release certificate is not canonical raw PEM")
    return canonical


def _release_certificate_payload(raw: bytes, *, allow_base64_wrapper: bool) -> bytes:
    if not 0 < len(raw) <= MAX_RELEASE_CERTIFICATE_BYTES:
        raise CandidateError("release certificate has an invalid size")
    if raw.startswith(b"-----BEGIN CERTIFICATE-----\n"):
        return _canonical_pem_certificate(raw)
    if not allow_base64_wrapper:
        raise CandidateError("sealed release certificate must be canonical raw PEM")
    if STRICT_BASE64_RE.fullmatch(raw) is None:
        raise CandidateError("post-cosign release certificate is not strict base64 or raw PEM")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CandidateError("post-cosign release certificate has invalid base64") from exc
    if base64.b64encode(decoded) != raw:
        raise CandidateError("post-cosign release certificate base64 is noncanonical")
    canonical = _canonical_pem_certificate(decoded)
    if decoded != canonical:
        raise CandidateError("post-cosign release certificate does not wrap canonical PEM")
    return canonical


def _atomic_replace_release_certificate(
    path: Path,
    payload: bytes,
    *,
    expected_file: os.stat_result,
    expected_parent: os.stat_result,
) -> None:
    descriptor = -1
    temporary_name = ""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.canonical-",
            dir=path.parent,
        )
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, stat.S_IMODE(expected_file.st_mode))
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write while canonicalizing release certificate")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1

        current_file = path.lstat()
        current_parent = path.parent.lstat()
        if (
            _file_state(current_file) != _file_state(expected_file)
            or _directory_identity(current_parent) != _directory_identity(expected_parent)
        ):
            raise CandidateError("release certificate path changed before atomic publication")
        os.replace(temporary_name, path)
        temporary_name = ""
        if os.name == "posix":
            parent_descriptor = os.open(
                path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
    except CandidateError:
        raise
    except OSError as exc:
        raise CandidateError(f"could not atomically publish canonical release certificate: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass


def canonicalize_release_certificate(path: Path) -> None:
    """Canonicalize trusted Cosign output before candidate bytes are sealed."""

    raw, file_info, parent_info = _read_release_certificate(path)
    canonical = _release_certificate_payload(raw, allow_base64_wrapper=True)
    _atomic_replace_release_certificate(
        path,
        canonical,
        expected_file=file_info,
        expected_parent=parent_info,
    )
    published, _, _ = _read_release_certificate(path)
    if published != canonical:
        raise CandidateError("canonical release certificate changed after atomic publication")


def _require_canonical_release_certificate(path: Path) -> None:
    raw, _, _ = _read_release_certificate(path)
    _release_certificate_payload(raw, allow_base64_wrapper=False)


def _protected_payload(path: Path) -> bytes:
    try:
        size = path.stat().st_size
        if size <= len(PROTECTED_ARTIFACT_MAGIC) or size > MAX_PROTECTED_ARTIFACT_BYTES:
            raise CandidateError(f"protected artifact size is invalid: {path.name}")
        with path.open("rb") as handle:
            magic = handle.read(len(PROTECTED_ARTIFACT_MAGIC))
            if magic != PROTECTED_ARTIFACT_MAGIC:
                raise CandidateError(f"protected artifact envelope is invalid: {path.name}")
            payload = handle.read(MAX_GATEWAY_BINARY_BYTES + 1)
    except OSError as exc:
        raise CandidateError(f"could not read protected artifact {path}: {exc}") from exc
    if not payload or len(payload) > MAX_GATEWAY_BINARY_BYTES:
        raise CandidateError(f"protected artifact payload size is invalid: {path.name}")
    return payload.translate(PROTECTED_ARTIFACT_TRANSLATION)


def _write_protected_artifact(source: Path, destination: Path) -> None:
    try:
        with source.open("rb") as input_handle, destination.open("xb") as output_handle:
            output_handle.write(PROTECTED_ARTIFACT_MAGIC)
            for chunk in iter(lambda: input_handle.read(1024 * 1024), b""):
                output_handle.write(chunk.translate(PROTECTED_ARTIFACT_TRANSLATION))
            output_handle.flush()
            os.fsync(output_handle.fileno())
        source.unlink()
    except OSError as exc:
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
        raise CandidateError(
            f"could not create protected runtime artifact {destination.name}: {exc}"
        ) from exc


def _validate_version(version: str) -> None:
    if not VERSION_RE.fullmatch(version):
        raise CandidateError(f"version must be X.Y.Z, got {version!r}")


def _validate_commit(commit: str) -> None:
    if not COMMIT_RE.fullmatch(commit):
        raise CandidateError(f"commit must be a full lowercase SHA-1, got {commit!r}")


def runtime_asset_names(version: str) -> tuple[str, ...]:
    _validate_version(version)
    canonical_archives = (
        f"defenseclaw_{version}_darwin_amd64.tar.gz",
        f"defenseclaw_{version}_darwin_arm64.tar.gz",
        f"defenseclaw_{version}_linux_amd64.tar.gz",
        f"defenseclaw_{version}_linux_arm64.tar.gz",
        f"defenseclaw_{version}_windows_amd64.zip",
        f"defenseclaw_{version}_windows_arm64.zip",
    )
    if tuple(map(int, version.split("."))) < (0, 8, 4):
        archives = canonical_archives
        wheel = f"defenseclaw-{version}-py3-none-any.whl"
        refusal_assets: tuple[str, ...] = ()
    else:
        protected = _expected_release_artifacts(version)
        archives = tuple(
            protected["gateways"][os_name][arch]
            for os_name in ("darwin", "linux", "windows")
            for arch in ("amd64", "arm64")
        )
        wheel = protected["wheel"]
        refusal_assets = (*canonical_archives, f"defenseclaw-{version}-py3-none-any.whl")
    return tuple(
        sorted(
            (
                *archives,
                *(f"{name}.sbom.json" for name in archives),
                *refusal_assets,
                wheel,
                f"defenseclaw-plugin-{version}.tar.gz",
                "upgrade-manifest.json",
            )
        )
    )


def _validate_macos_verification_status(status: object) -> str:
    if not isinstance(status, str) or status not in MACOS_VERIFICATION_STATUSES:
        raise CandidateError(
            "macOS verification status must be exactly one of "
            f"{MACOS_VERIFICATION_STATUSES!r}, got {status!r}"
        )
    return status


def macos_asset_names(
    version: str,
    macos_verification_status: str,
) -> tuple[str, ...]:
    _validate_version(version)
    status = _validate_macos_verification_status(macos_verification_status)
    suffix = "" if status == "notarized" else "-unverified"
    return (
        f"DefenseClawMac-{version}-macos-arm64{suffix}.dmg",
        f"DefenseClawMac-{version}-macos-arm64{suffix}.zip",
    )


def resolver_asset_names(version: str) -> tuple[str, ...]:
    _validate_version(version)
    if tuple(map(int, version.split("."))) < (0, 8, 4):
        return ()
    return tuple(sorted(RESOLVER_ASSET_SOURCES))


def release_identity_asset_names(version: str) -> tuple[str, ...]:
    _validate_version(version)
    if tuple(map(int, version.split("."))) < (0, 8, 5):
        return ()
    return (RELEASE_PROVENANCE_FILENAME, RELEASE_SOURCE_MAP_FILENAME)


def windows_installer_asset_names(version: str) -> tuple[str, ...]:
    """Return the exact signed native-Setup custody set for 0.8.6+."""

    _validate_version(version)
    if tuple(map(int, version.split("."))) < WINDOWS_SETUP_START_VERSION:
        return ()
    return (
        WINDOWS_SETUP_ASSET,
        f"{WINDOWS_SETUP_ASSET}.certification.json",
        f"{WINDOWS_SETUP_ASSET}.provenance.json",
        f"{WINDOWS_SETUP_ASSET}.sbom.json",
        f"{WINDOWS_SETUP_ASSET}.sha256",
    )


def release_proof_asset_names(version: str) -> tuple[str, ...]:
    """Return checksum-signature proof files published outside checksums.txt."""

    _validate_version(version)
    names = ["checksums.txt.pem", "checksums.txt.sig"]
    if tuple(map(int, version.split("."))) >= WINDOWS_SETUP_START_VERSION:
        names.append(CHECKSUMS_BUNDLE_FILENAME)
    return tuple(sorted(names))


def payload_asset_names(
    version: str,
    macos_verification_status: str,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            (
                *runtime_asset_names(version),
                *macos_asset_names(version, macos_verification_status),
                *resolver_asset_names(version),
                *release_identity_asset_names(version),
                *windows_installer_asset_names(version),
            )
        )
    )


def published_asset_names(
    version: str,
    macos_verification_status: str,
    *,
    omit_windows_binaries: bool = False,
) -> tuple[str, ...]:
    names = tuple(
        sorted(
            (
                *payload_asset_names(version, macos_verification_status),
                "checksums.txt",
                *release_proof_asset_names(version),
            )
        )
    )
    if omit_windows_binaries:
        omitted = set(windows_release_binary_names(version))
        names = tuple(name for name in names if name not in omitted)
    return names


def windows_release_binary_names(version: str) -> tuple[str, ...]:
    """Return Windows runtime binaries and SBOMs, excluding the refusal resolver."""

    _validate_version(version)
    canonical = tuple(
        f"defenseclaw_{version}_windows_{arch}.zip" for arch in ("amd64", "arm64")
    )
    if tuple(map(int, version.split("."))) < (0, 8, 4):
        archives = canonical
        sboms = tuple(f"{name}.sbom.json" for name in archives)
    else:
        protected = _expected_release_artifacts(version)["gateways"]["windows"]
        archives = tuple(protected[arch] for arch in ("amd64", "arm64"))
        sboms = tuple(f"{name}.sbom.json" for name in archives)
        archives = (*archives, *canonical)
    return tuple(sorted((*archives, *sboms)))


def _require_regular_files(directory: Path, names: tuple[str, ...], label: str) -> None:
    if not directory.is_dir():
        raise CandidateError(f"{label} directory not found: {directory}")
    for name in names:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise CandidateError(f"{label} is missing regular file {name}")


def _strict_file_names(directory: Path, label: str) -> tuple[str, ...]:
    if not directory.is_dir() or directory.is_symlink():
        raise CandidateError(f"{label} must be a regular directory: {directory}")
    entries = list(directory.iterdir())
    invalid = [path.name for path in entries if path.is_symlink() or not path.is_file()]
    if invalid:
        raise CandidateError(f"{label} contains non-file entries: {sorted(invalid)!r}")
    return tuple(sorted(path.name for path in entries))


def _validated_resolver_source(name: str) -> Path:
    source = RESOLVER_ASSET_SOURCES[name]
    try:
        info = source.lstat()
        payload = source.read_bytes()
    except OSError as exc:
        raise CandidateError(f"could not read reviewed resolver source {source}: {exc}") from exc
    if source.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise CandidateError(f"reviewed resolver source is not a regular file: {source}")
    if not payload or len(payload) > MAX_RESOLVER_BYTES or b"\0" in payload:
        raise CandidateError(f"reviewed resolver source has invalid content: {source}")
    if payload.splitlines()[-1] != RESOLVER_COMPLETENESS_MARKER:
        raise CandidateError(f"reviewed resolver source lacks its completeness marker: {source}")
    # Windows does not preserve Git's POSIX executable bit in os.stat().
    # Enforce the reviewed mode where the host exposes POSIX permissions;
    # Windows release gates still validate the exact resolver bytes below.
    if os.name == "posix" and name.endswith(".sh") and not info.st_mode & stat.S_IXUSR:
        raise CandidateError(f"reviewed POSIX resolver is not executable: {source}")
    return source


def _copy_resolver_assets(destination: Path, version: str) -> None:
    for name in resolver_asset_names(version):
        source = _validated_resolver_source(name)
        target = destination / name
        if target.exists() or target.is_symlink():
            raise CandidateError(f"resolver asset destination already exists: {name}")
        shutil.copy2(source, target)


def _validate_resolver_assets(directory: Path, version: str) -> None:
    for name in resolver_asset_names(version):
        source = _validated_resolver_source(name)
        candidate = directory / name
        if candidate.is_symlink() or not candidate.is_file():
            raise CandidateError(f"release candidate is missing resolver asset {name}")
        if candidate.read_bytes() != source.read_bytes():
            raise CandidateError(f"release resolver differs from reviewed source: {name}")


def stage_resolvers(directory: Path, version: str) -> None:
    """Stage the exact reviewed resolver assets for a local release harness."""

    _validate_version(version)
    if directory.is_symlink() or not directory.is_dir():
        raise CandidateError(f"resolver staging destination is not a regular directory: {directory}")
    _copy_resolver_assets(directory, version)
    _validate_resolver_assets(directory, version)


def _load_upgrade_baseline_policy(
    candidate_version: str | None = None,
    policy_path: Path | None = None,
) -> tuple[list[str], dict[str, list[str]]]:
    if candidate_version is None:
        try:
            source_identity = json.loads(
                (ROOT / "release" / "source-install-identity.json").read_text(
                    encoding="utf-8"
                )
            )
            candidate_version = source_identity["source_release"]
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise CandidateError("could not resolve source release for baseline validation") from exc
        if not isinstance(candidate_version, str) or not VERSION_RE.fullmatch(candidate_version):
            raise CandidateError("source release for baseline validation is invalid")
    policy_path = policy_path or UPGRADE_BASELINES_PATH
    try:
        document = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"could not load tested upgrade baselines: {exc}") from exc
    configured = document.get("published_baselines")
    config_versions = document.get("published_baseline_config_versions")
    platforms = document.get("platform_published_baselines")
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "schema_version",
            "published_baselines",
            "published_baseline_config_versions",
            "platform_published_baselines",
        }
        or document.get("schema_version") != 2
        or not isinstance(configured, list)
        or not configured
        or any(not isinstance(item, str) or not VERSION_RE.fullmatch(item) for item in configured)
        or len(configured) != len(set(configured))
        or configured != sorted(configured, key=lambda item: tuple(map(int, item.split("."))), reverse=True)
        or not isinstance(config_versions, dict)
        or set(config_versions) != set(configured)
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 1
            or value > _runtime_config_version_from_source(candidate_version)
            for value in config_versions.values()
        )
        or (
            "0.8.4" in config_versions
            and config_versions.get("0.8.4") != 7
        )
        or not isinstance(platforms, dict)
        or set(platforms) != {"windows"}
    ):
        raise CandidateError("tested upgrade baseline policy is invalid")
    windows = platforms["windows"]
    if (
        not isinstance(windows, list)
        or not windows
        or any(not isinstance(item, str) or not VERSION_RE.fullmatch(item) for item in windows)
        or len(windows) != len(set(windows))
        or windows != sorted(windows, key=lambda item: tuple(map(int, item.split("."))), reverse=True)
        or any(item not in configured for item in windows)
    ):
        raise CandidateError("tested Windows upgrade baseline policy is invalid")
    _validate_historical_artifact_digest_policy(configured)
    return configured, {"windows": windows}


def _validate_historical_artifact_digest_policy(configured: list[str]) -> None:
    try:
        document = json.loads(
            HISTORICAL_ARTIFACT_DIGESTS_PATH.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"could not load historical artifact digest policy: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "signed_wheel_coverage_starts_at",
        "signed_checksum_exceptions",
    }:
        raise CandidateError("historical artifact digest policy is invalid")
    coverage_start = document.get("signed_wheel_coverage_starts_at")
    exceptions = document.get("signed_checksum_exceptions")
    if (
        document.get("schema_version") != 1
        or not isinstance(coverage_start, str)
        or not VERSION_RE.fullmatch(coverage_start)
        or not isinstance(exceptions, dict)
    ):
        raise CandidateError("historical artifact digest policy is invalid")
    def version_key(value: str) -> tuple[int, int, int]:
        return tuple(map(int, value.split(".")))

    expected_versions = {
        version for version in configured if version_key(version) < version_key(coverage_start)
    }
    if set(exceptions) != expected_versions:
        raise CandidateError(
            "historical artifact digest exceptions must exactly match tested baselines "
            "below signed-wheel coverage"
        )
    for version, artifacts in exceptions.items():
        expected_name = f"defenseclaw-{version}-py3-none-any.whl"
        if (
            not isinstance(artifacts, dict)
            or set(artifacts) != {expected_name}
            or not isinstance(artifacts.get(expected_name), str)
            or not SHA256_RE.fullmatch(artifacts[expected_name])
        ):
            raise CandidateError(
                f"historical digest exception for {version} must be one canonical wheel digest"
            )


def validate_release_progression(target: str, releases_json: Path) -> tuple[str, str]:
    """Require a release target newer than reviewed and published stable state."""

    _validate_version(target)
    configured, _platforms = _load_upgrade_baseline_policy(target)
    try:
        document = json.loads(releases_json.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"could not load published release inventory: {exc}") from exc

    if not isinstance(document, list):
        raise CandidateError("published release inventory must be a JSON array")
    if document and all(isinstance(page, list) for page in document):
        rows = [row for page in document for row in page]
    else:
        rows = document
    if any(not isinstance(row, dict) for row in rows):
        raise CandidateError("published release inventory contains a non-object row")

    stable_versions: list[str] = []
    for row in rows:
        draft = row.get("draft")
        prerelease = row.get("prerelease")
        if not isinstance(draft, bool) or not isinstance(prerelease, bool):
            raise CandidateError("published release inventory lacks boolean draft/prerelease state")
        if draft or prerelease:
            continue
        tag = row.get("tag_name")
        if not isinstance(tag, str) or not VERSION_RE.fullmatch(tag):
            raise CandidateError(
                f"published stable release has a non-canonical tag: {tag!r}"
            )
        stable_versions.append(tag)

    def version_key(value: str) -> tuple[int, int, int]:
        return tuple(map(int, value.split(".")))

    reviewed_max = max(configured, key=version_key)
    published_max = max(stable_versions, key=version_key) if stable_versions else reviewed_max
    current_max = max((reviewed_max, published_max), key=version_key)
    if version_key(target) <= version_key(current_max):
        raise CandidateError(
            f"release target {target} must be strictly newer than current stable {current_max} "
            f"(reviewed max {reviewed_max}, published max {published_max})"
        )
    return reviewed_max, published_max


def _go_config_version_literal(path: Path, name: str) -> int:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise CandidateError(f"could not read gateway {name}: {exc}") from exc
    matches = re.findall(
        rf"^\s*(?:const[ \t]+)?{re.escape(name)}[ \t]*=[ \t]*([0-9]+)[ \t]*$",
        text,
        re.MULTILINE,
    )
    if len(matches) != 1:
        raise CandidateError(f"gateway source must declare exactly one literal {name}")
    value = int(matches[0])
    if value < 1:
        raise CandidateError(f"gateway {name} must be positive")
    return value


def _compatibility_config_version_from_source() -> int:
    return _go_config_version_literal(RUNTIME_CONFIG_PATH, "CurrentConfigVersion")


def _runtime_config_version_from_source(version: str) -> int:
    if tuple(map(int, version.split("."))) >= (0, 8, 5):
        return _go_config_version_literal(
            ROOT / "internal" / "config" / "observability_v8_types.go",
            "ObservabilityV8ConfigVersion",
        )
    return _compatibility_config_version_from_source()


def _expected_runtime_config_version(version: str) -> int:
    version_key = tuple(map(int, version.split(".")))
    if version_key == (0, 8, 4):
        return 7
    if version_key >= (0, 8, 5):
        return 8
    raise CandidateError(f"release {version} does not use schema-2 runtime attestation")


def _expected_release_artifacts(version: str) -> dict[str, Any]:
    _validate_version(version)
    gateways: dict[str, dict[str, str]] = {}
    for os_name in ("darwin", "linux", "windows"):
        gateways[os_name] = {
            arch: f"defenseclaw_{version}_protocol2_{os_name}_{arch}.dcgateway"
            for arch in ("amd64", "arm64")
        }
    return {
        "wheel": f"defenseclaw-{version}-2-py3-none-any.dcwheel",
        "gateways": gateways,
    }


def _validate_upgrade_manifest(
    path: Path,
    version: str,
    *,
    baseline_policy_path: Path | None = None,
) -> None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"invalid upgrade manifest {path}: {exc}") from exc
    if document.get("release_version") != version:
        raise CandidateError(
            f"upgrade manifest release_version={document.get('release_version')!r}; want {version!r}"
        )
    version_key = tuple(map(int, version.split(".")))
    expected_schema = 2 if version_key >= (0, 8, 4) else 1
    if document.get("schema_version") != expected_schema:
        raise CandidateError(
            f"upgrade manifest schema_version must be {expected_schema} for release {version}"
        )
    if document.get("migration_failure_policy") != "fail":
        raise CandidateError("release upgrade manifest must fail closed on required migration errors")
    min_protocol = document.get("min_upgrade_protocol", 1)
    controller_protocol = document.get("controller_upgrade_protocol", 1)
    for label, value in (
        ("min_upgrade_protocol", min_protocol),
        ("controller_upgrade_protocol", controller_protocol),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise CandidateError(f"upgrade manifest {label} must be a positive integer")
    if controller_protocol < min_protocol:
        raise CandidateError("candidate controller cannot drive its own minimum upgrade protocol")

    configured, platform_configured = _load_upgrade_baseline_policy(
        version,
        baseline_policy_path,
    )
    tested = document.get("tested_source_versions")
    platform_tested = document.get("platform_tested_source_versions")
    runtime_config = document.get("runtime_config_version")
    release_artifacts = document.get("release_artifacts")
    if expected_schema == 2:
        if not isinstance(tested, list) or not isinstance(platform_tested, dict):
            raise CandidateError("schema-2 manifest lacks its complete tested-source policy")
        if set(platform_tested) != {"windows"} or not isinstance(platform_tested["windows"], list):
            raise CandidateError(
                "platform_tested_source_versions must contain exactly the Windows source list"
            )
        expected_tested = [
            item for item in configured if tuple(map(int, item.split("."))) < version_key
        ]
        expected_windows = [
            item
            for item in platform_configured["windows"]
            if tuple(map(int, item.split("."))) < version_key
        ]
        manifest_bridge = document.get("required_bridge_version")
        if manifest_bridge and manifest_bridge not in expected_windows:
            # An unpublished platform bridge makes the entire hard-cut path
            # from older sources unsupported on that platform. Retain only
            # actually published post-hard-cut runtimes, which can drive a
            # direct protocol-2 transition without the bridge.
            expected_windows = [
                item
                for item in expected_windows
                if tuple(map(int, item.split("."))) >= (0, 8, 5)
            ]
        if tested != expected_tested:
            raise CandidateError(
                "tested_source_versions must exactly match every reviewed baseline older than the candidate"
            )
        if platform_tested["windows"] != expected_windows:
            raise CandidateError(
                "platform_tested_source_versions.windows must exactly match the reviewed Windows matrix"
            )
        expected_runtime = _expected_runtime_config_version(version)
        compatibility_runtime = _compatibility_config_version_from_source()
        if compatibility_runtime != 7:
            raise CandidateError(
                "schema-2 source must retain gateway CurrentConfigVersion=7 as its "
                f"compatibility ceiling, got {compatibility_runtime}"
            )
        source_runtime = _runtime_config_version_from_source(version)
        if source_runtime != expected_runtime:
            literal = (
                "ObservabilityV8ConfigVersion"
                if version_key >= (0, 8, 5)
                else "CurrentConfigVersion"
            )
            raise CandidateError(
                f"release {version} requires gateway {literal}={expected_runtime}, "
                f"got {source_runtime}"
            )
        if (
            not isinstance(runtime_config, int)
            or isinstance(runtime_config, bool)
            or runtime_config != source_runtime
        ):
            raise CandidateError(
                "runtime_config_version must match the release-selected gateway config literal"
            )
        if release_artifacts != _expected_release_artifacts(version):
            raise CandidateError(
                "release_artifacts must explicitly name the exact protected wheel and platform gateways"
            )
        flattened = [release_artifacts["wheel"]] + [
            release_artifacts["gateways"][os_name][arch]
            for os_name in ("darwin", "linux", "windows")
            for arch in ("amd64", "arm64")
        ]
        if len(flattened) != len(set(flattened)) or any(
            Path(name).name != name for name in flattened
        ):
            raise CandidateError("release_artifacts names must be unique basenames")
    elif (
        tested is not None
        or platform_tested is not None
        or runtime_config is not None
        or release_artifacts is not None
    ):
        raise CandidateError("schema-1 candidate must not declare schema-2 policy")

    bridge_keys = ("minimum_source_version", "required_bridge_version", "auto_bridge_from")
    bridge_presence = [key in document for key in bridge_keys]
    if version_key >= (0, 8, 5) and (
        min_protocol != 2 or not all(bridge_presence)
    ):
        raise CandidateError(
            "0.8.5+ hard-cut release requires upgrade protocol 2 and a complete bridge contract"
        )
    if any(bridge_presence) and not all(bridge_presence):
        raise CandidateError("upgrade manifest bridge contract is incomplete")
    if min_protocol > 1 and not all(bridge_presence):
        raise CandidateError("non-legacy upgrade protocol requires a complete signed bridge contract")
    if not any(bridge_presence):
        return

    minimum = document["minimum_source_version"]
    bridge = document["required_bridge_version"]
    automatic = document["auto_bridge_from"]
    if not isinstance(minimum, str) or not VERSION_RE.fullmatch(minimum):
        raise CandidateError("upgrade manifest minimum_source_version must be X.Y.Z")
    if not isinstance(bridge, str) or not VERSION_RE.fullmatch(bridge):
        raise CandidateError("upgrade manifest required_bridge_version must be X.Y.Z")
    if bridge != minimum:
        raise CandidateError("required_bridge_version must equal minimum_source_version")
    if tuple(map(int, minimum.split("."))) > tuple(map(int, version.split("."))):
        raise CandidateError("minimum_source_version cannot exceed the candidate version")
    if not isinstance(automatic, list) or any(
        not isinstance(item, str) or not VERSION_RE.fullmatch(item) for item in automatic
    ):
        raise CandidateError("upgrade manifest auto_bridge_from must contain unique X.Y.Z versions")
    if len(automatic) != len(set(automatic)):
        raise CandidateError("upgrade manifest auto_bridge_from must contain unique X.Y.Z versions")

    if tested is None or platform_tested is None:
        raise CandidateError(
            "upgrade manifest bridge contract requires the schema-2 tested-source policy"
        )
    if bridge not in configured:
        raise CandidateError(f"required bridge {bridge} is absent from the tested baseline matrix")
    if bridge not in tested:
        raise CandidateError(
            f"required bridge {bridge} is absent from the signed global tested-source matrix"
        )
    if bridge in platform_configured["windows"]:
        if bridge not in platform_tested["windows"]:
            raise CandidateError(
                f"required bridge {bridge} is absent from the tested Windows baseline matrix"
            )
    elif platform_tested["windows"]:
        raise CandidateError(
            f"Windows bridge {bridge} is unpublished; the tested Windows baseline matrix "
            "must be empty"
        )
    bridge_key = tuple(map(int, bridge.split(".")))
    expected_automatic = [
        item for item in configured if tuple(map(int, item.split("."))) < bridge_key
    ]
    if automatic != expected_automatic:
        raise CandidateError(
            "auto_bridge_from must exactly match every published baseline older than "
            f"required_bridge_version {bridge}"
        )


def _wheel_migration_versions(source: str) -> list[str]:
    try:
        tree = ast.parse(source, filename="defenseclaw/migrations.py")
    except (SyntaxError, ValueError) as exc:
        raise CandidateError("candidate wheel migration registry is invalid") from exc

    registries: list[ast.AST] = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "MIGRATIONS" for target in node.targets
        ):
            registries.append(node.value)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "MIGRATIONS"
            and node.value is not None
        ):
            registries.append(node.value)
    if len(registries) != 1 or not isinstance(registries[0], ast.List):
        raise CandidateError("candidate wheel must contain one literal MIGRATIONS registry")

    versions: list[str] = []
    for item in registries[0].elts:
        if (
            not isinstance(item, ast.Tuple)
            or len(item.elts) != 3
            or not isinstance(item.elts[0], ast.Constant)
            or not isinstance(item.elts[0].value, str)
            or not VERSION_RE.fullmatch(item.elts[0].value)
        ):
            raise CandidateError("candidate wheel contains an invalid MIGRATIONS entry")
        versions.append(item.elts[0].value)
    return versions


def _upgrade_controller_calls(
    entrypoint: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[str, int, bool]]:
    """Collect direct entrypoint calls and whether the hard-cut guard encloses them."""

    calls: list[tuple[str, int, bool]] = []

    class CallVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.hard_cut_guard_depth = 0

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            # Do not allow a dead nested helper to satisfy the entrypoint invariant.
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_If(self, node: ast.If) -> None:
            self.visit(node.test)
            guarded = (
                isinstance(node.test, ast.Call)
                and isinstance(node.test.func, ast.Name)
                and node.test.func.id == "_is_bridge_to_hard_cut_phase"
            )
            if guarded:
                self.hard_cut_guard_depth += 1
            for statement in node.body:
                self.visit(statement)
            if guarded:
                self.hard_cut_guard_depth -= 1
            for statement in node.orelse:
                self.visit(statement)

        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Name):
                calls.append(
                    (node.func.id, node.lineno, self.hard_cut_guard_depth > 0)
                )
            self.generic_visit(node)

    visitor = CallVisitor()
    for statement in entrypoint.body:
        visitor.visit(statement)
    return calls


def _direct_hard_cut_guard_first_calls(
    entrypoint: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[tuple[str, int]]:
    """Return calls that are first in a reachable, positive hard-cut guard."""

    candidates: list[ast.stmt] = list(entrypoint.body)
    for statement in entrypoint.body:
        if isinstance(statement, ast.Try):
            # The controller performs authenticated downloads in one top-level
            # try block. Exception/else/finally branches cannot satisfy the gate.
            candidates.extend(statement.body)

    calls: set[tuple[str, int]] = set()
    for statement in candidates:
        if (
            not isinstance(statement, ast.If)
            or not isinstance(statement.test, ast.Call)
            or not isinstance(statement.test.func, ast.Name)
            or statement.test.func.id != "_is_bridge_to_hard_cut_phase"
            or not statement.body
        ):
            continue
        first = statement.body[0]
        value: ast.AST | None = None
        if isinstance(first, ast.Expr):
            value = first.value
        elif isinstance(first, ast.Assign):
            value = first.value
        elif isinstance(first, ast.AnnAssign):
            value = first.value
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            calls.add((value.func.id, value.lineno))
    return calls


def _ast_call_name(node: ast.Call) -> str | None:
    parts: list[str] = []
    current: ast.AST = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def _validate_phase_two_mutator_wrapper(source: str) -> None:
    """Require a lease-owning supervisor with a closed child-exec boundary."""

    try:
        tree = ast.parse(source, filename="defenseclaw/phase_two_mutator.py")
    except (SyntaxError, ValueError) as exc:
        raise CandidateError("0.8.4+ candidate wheel mutator wrapper is invalid") from exc
    markers = [
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "_MARKER" for target in node.targets)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    if markers != ["--defenseclaw-phase-two-mutator"]:
        raise CandidateError("0.8.4+ mutator wrapper lacks its exact private marker")
    entrypoints = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "main"
    ]
    if len(entrypoints) != 1:
        raise CandidateError("0.8.4+ mutator wrapper must define one main entrypoint")
    main = entrypoints[0]
    calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)]
    call_names = {_ast_call_name(node) for node in calls}
    for required in (
        "os.path.abspath",
        "os.lstat",
        "os.fstat",
        "os.path.samestat",
        "os.set_inheritable",
        "stat.S_ISLNK",
        "stat.S_ISREG",
        "subprocess.run",
    ):
        if required not in call_names:
            raise CandidateError(
                f"0.8.4+ mutator wrapper lacks lease/child contract call {required}"
            )
    if len([node for node in calls if _ast_call_name(node) == "subprocess.run"]) != 1 or any(
        _ast_call_name(node) in {"subprocess.Popen", "os.system", "os.popen"}
        for node in calls
    ):
        raise CandidateError("0.8.4+ mutator wrapper has an unbound child launch")
    inheritable_calls = [
        node for node in calls if _ast_call_name(node) == "os.set_inheritable"
    ]
    if not (
        len(inheritable_calls) == 1
        and len(inheritable_calls[0].args) == 2
        and isinstance(inheritable_calls[0].args[0], ast.Name)
        and inheritable_calls[0].args[0].id == "lease_fd"
        and isinstance(inheritable_calls[0].args[1], ast.Constant)
        and inheritable_calls[0].args[1].value is False
    ):
        raise CandidateError("0.8.4+ mutator wrapper does not mark the exact lease close-on-exec")

    child_launches: list[tuple[ast.Assign, ast.Call]] = []
    for node in ast.walk(main):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "completed"
            and isinstance(node.value, ast.Call)
            and _ast_call_name(node.value) == "subprocess.run"
        ):
            child_launches.append((node, node.value))
    if len(child_launches) != 1:
        raise CandidateError("0.8.4+ mutator wrapper must synchronously launch one real child")
    _assignment, child_launch = child_launches[0]
    if (
        len(child_launch.args) != 1
        or not isinstance(child_launch.args[0], ast.Name)
        or child_launch.args[0].id != "command"
    ):
        raise CandidateError("0.8.4+ mutator wrapper child command is not argument-bound")
    keywords = {keyword.arg: keyword.value for keyword in child_launch.keywords if keyword.arg}
    if not (
        isinstance(keywords.get("check"), ast.Constant)
        and keywords["check"].value is False
    ):
        raise CandidateError("0.8.4+ mutator wrapper child launch must return its status")
    close_fds = keywords.get("close_fds")
    pass_fds = keywords.get("pass_fds")
    if not (
        isinstance(close_fds, ast.Constant)
        and close_fds.value is True
        and isinstance(pass_fds, ast.Tuple)
        and not pass_fds.elts
    ):
        raise CandidateError("0.8.4+ mutator wrapper does not close the lease at child exec")
    if not any(
        isinstance(node, ast.Return)
        and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "completed"
        and node.value.attr == "returncode"
        for node in ast.walk(main)
    ):
        raise CandidateError("0.8.4+ mutator wrapper does not wait for the child lifetime")

    module_guards = [
        node
        for node in tree.body
        if isinstance(node, ast.If)
        and any(
            isinstance(candidate, ast.Name) and candidate.id == "__name__"
            for candidate in ast.walk(node.test)
        )
        and any(
            isinstance(candidate, ast.Call) and _ast_call_name(candidate) == "main"
            for candidate in ast.walk(node)
        )
    ]
    if len(module_guards) != 1:
        raise CandidateError("0.8.4+ mutator wrapper is not executable as a private child")


def _validate_fixture_hard_cut_bundle_transaction(source: str) -> None:
    """Validate the compact contract fixture used by mutation tests."""

    try:
        tree = ast.parse(source, filename="defenseclaw/bundle_refresh.py")
    except (SyntaxError, ValueError) as exc:
        raise CandidateError("0.8.5+ candidate wheel bundle transaction is invalid") from exc

    def references_name(node: ast.AST, name: str) -> bool:
        return any(
            isinstance(candidate, ast.Name) and candidate.id == name
            for candidate in ast.walk(node)
        )

    def static_int(node: ast.AST | None) -> int | None:
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, int)
            and not isinstance(node.value, bool)
        ):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            left = static_int(node.left)
            right = static_int(node.right)
            if left is not None and right is not None:
                return left * right
        return None

    metadata_bounds: list[int] = []
    for node in tree.body:
        value: ast.AST | None = None
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name)
            and target.id == "_MAX_BUNDLE_ROLLBACK_METADATA_BYTES"
            for target in node.targets
        ):
            value = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "_MAX_BUNDLE_ROLLBACK_METADATA_BYTES"
        ):
            value = node.value
        static_value = static_int(value)
        if static_value is not None:
            metadata_bounds.append(static_value)
    if metadata_bounds != [4 * 1024 * 1024]:
        raise CandidateError(
            "0.8.5+ bundle transaction lacks the bridge metadata size bound"
        )

    serializers = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_serialize_windows_security"
    ]
    if len(serializers) != 1:
        raise CandidateError(
            "0.8.5+ bundle transaction lacks one exact Windows security serializer"
        )
    serializer = serializers[0]
    serializer_arguments = [argument.arg for argument in serializer.args.args]
    serializer_returns = [
        node.value
        for node in ast.walk(serializer)
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)
    ]
    if (
        serializer.args.posonlyargs
        or serializer_arguments != ["security"]
        or serializer.args.kwonlyargs
        or serializer.args.vararg is not None
        or serializer.args.kwarg is not None
        or serializer.args.defaults
        or serializer.args.kw_defaults
        or len(serializer_returns) != 1
    ):
        raise CandidateError(
            "0.8.5+ bundle Windows security serializer has an invalid signature"
        )
    serialized_security = serializer_returns[0]
    serialized_values = {
        key.value: value
        for key, value in zip(
            serialized_security.keys,
            serialized_security.values,
            strict=True,
        )
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    if (
        len(serialized_security.keys) != 3
        or len(serialized_values) != 3
        or set(serialized_values) != {"owner", "dacl", "dacl_protected"}
    ):
        raise CandidateError(
            "0.8.5+ bundle Windows security serializer lacks exact owner/DACL fields"
        )

    def is_canonical_security_bytes(value: ast.AST, field: str) -> bool:
        if not (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "decode"
            and len(value.args) == 1
            and not value.keywords
            and isinstance(value.args[0], ast.Constant)
            and value.args[0].value == "ascii"
            and isinstance(value.func.value, ast.Call)
        ):
            return False
        encoder = value.func.value
        return (
            _ast_call_name(encoder) == "base64.b64encode"
            and len(encoder.args) == 1
            and not encoder.keywords
            and isinstance(encoder.args[0], ast.Attribute)
            and encoder.args[0].attr == field
            and isinstance(encoder.args[0].value, ast.Name)
            and encoder.args[0].value.id == "security"
        )

    for field in ("owner", "dacl"):
        if not is_canonical_security_bytes(serialized_values[field], field):
            raise CandidateError(
                "0.8.5+ bundle Windows owner/DACL bytes are not canonically serialized"
            )
    protected_value = serialized_values["dacl_protected"]
    if not (
        isinstance(protected_value, ast.Attribute)
        and protected_value.attr == "dacl_protected"
        and isinstance(protected_value.value, ast.Name)
        and protected_value.value.id == "security"
    ):
        raise CandidateError(
            "0.8.5+ bundle Windows DACL protection state is not serialized exactly"
        )
    directory_chain_helpers = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_fsync_directory_chain"
    ]
    if len(directory_chain_helpers) != 1:
        raise CandidateError("0.8.5+ bundle transaction lacks one directory fsync-chain helper")
    directory_chain_helper = directory_chain_helpers[0]
    helper_arguments = {
        argument.arg
        for argument in (
            *directory_chain_helper.args.args,
            *directory_chain_helper.args.kwonlyargs,
        )
    }
    helper_calls = [
        node
        for node in ast.walk(directory_chain_helper)
        if isinstance(node, ast.Call)
    ]
    if (
        helper_arguments != {"path", "stop"}
        or not any(isinstance(node, ast.While) for node in ast.walk(directory_chain_helper))
        or not any(_ast_call_name(node) == "_fsync_directory" for node in helper_calls)
        or not any(
            isinstance(node, ast.Compare)
            and any(
                isinstance(candidate, ast.Name) and candidate.id == "stop"
                for candidate in ast.walk(node)
            )
            for node in ast.walk(directory_chain_helper)
        )
        or not any(isinstance(node, ast.Break) for node in ast.walk(directory_chain_helper))
        or not any(
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and any(
                isinstance(candidate, ast.Attribute) and candidate.attr == "parent"
                for candidate in ast.walk(node)
            )
            for node in ast.walk(directory_chain_helper)
        )
    ):
        raise CandidateError(
            "0.8.5+ bundle directory fsync-chain helper does not walk to its stop root"
        )
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_activate_local_observability_manifest"
    ]
    if len(functions) != 1:
        raise CandidateError("0.8.5+ candidate wheel lacks one bundle activation transaction")
    transaction = functions[0]
    was_running_args = [
        argument
        for argument in (*transaction.args.args, *transaction.args.kwonlyargs)
        if argument.arg == "was_running"
    ]
    if not (
        len(was_running_args) == 1
        and isinstance(was_running_args[0].annotation, ast.Name)
        and was_running_args[0].annotation.id == "bool"
    ):
        raise CandidateError("0.8.5+ bundle transaction restart state is not boolean-bound")

    metadata_dicts: list[ast.Dict] = []
    for node in ast.walk(transaction):
        if not isinstance(node, ast.Dict):
            continue
        keys = {
            key.value
            for key in node.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        if "managed_paths" in keys or "restart_required" in keys:
            metadata_dicts.append(node)
    if len(metadata_dicts) != 1:
        raise CandidateError("0.8.5+ bundle transaction must define one rollback metadata object")
    metadata = metadata_dicts[0]
    metadata_values = {
        key.value: value
        for key, value in zip(metadata.keys, metadata.values, strict=True)
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    expected_metadata_fields = {
        "schema_version",
        "managed_paths",
        "existing_paths",
        "old_sha256",
        "old_modes",
        "created_sha256",
        "old_windows_security",
        "restart_required",
    }
    if (
        len(metadata.keys) != len(expected_metadata_fields)
        or len(metadata_values) != len(expected_metadata_fields)
        or set(metadata_values) != expected_metadata_fields
    ):
        missing = sorted(expected_metadata_fields - set(metadata_values))
        extra = sorted(set(metadata_values) - expected_metadata_fields)
        raise CandidateError(
            "0.8.5+ bundle rollback metadata lacks the exact schema-2 inventory "
            f"(missing={missing!r}, extra={extra!r})"
        )
    schema_value = metadata_values["schema_version"]
    if not (
        isinstance(schema_value, ast.Constant)
        and isinstance(schema_value.value, int)
        and not isinstance(schema_value.value, bool)
        and schema_value.value == 2
    ):
        raise CandidateError("0.8.5+ bundle rollback metadata is not schema version 2")
    for field in ("managed_paths", "existing_paths"):
        value = metadata_values[field]
        binding = field
        if not (
            isinstance(value, ast.Call)
            and _ast_call_name(value) == "sorted"
            and len(value.args) == 1
            and not value.keywords
            and isinstance(value.args[0], ast.Name)
            and value.args[0].id == binding
        ):
            raise CandidateError(
                f"0.8.5+ bundle rollback metadata {field} is not bound to its exact inventory"
            )
    for field in ("old_sha256", "old_modes", "created_sha256", "old_windows_security"):
        value = metadata_values[field]
        if not (isinstance(value, ast.Name) and value.id == field):
            raise CandidateError(
                f"0.8.5+ bundle rollback metadata {field} is not bound to its exact inventory"
            )
    restart_value = metadata_values.get("restart_required")
    if not (
        isinstance(restart_value, ast.Name) and restart_value.id == "was_running"
    ):
        raise CandidateError(
            "0.8.5+ bundle rollback metadata lacks boolean restart_required"
        )

    calls = [node for node in ast.walk(transaction) if isinstance(node, ast.Call)]
    metadata_writes = [
        node
        for node in calls
        if _ast_call_name(node) == "_atomic_write_bytes"
        and any(
            isinstance(candidate, ast.Constant)
            and candidate.value == "refresh-backup.json"
            for candidate in ast.walk(node)
        )
    ]
    if len(metadata_writes) != 1:
        raise CandidateError("0.8.5+ bundle transaction must durably publish one backup manifest")
    metadata_write = metadata_writes[0]
    all_atomic_writes = [
        node for node in calls if _ast_call_name(node) == "_atomic_write_bytes"
    ]
    if len(all_atomic_writes) != 1 or all_atomic_writes[0] is not metadata_write:
        raise CandidateError(
            "0.8.5+ bundle transaction has an ambiguous direct file write"
        )
    metadata_write_line = metadata_write.lineno
    if metadata.lineno >= metadata_write_line:
        raise CandidateError("0.8.5+ bundle rollback authority is not built before publication")
    metadata_assignments = [
        node
        for node in ast.walk(transaction)
        if (
            isinstance(node, ast.Assign)
            and node.value is metadata
            and any(
                isinstance(target, ast.Name) and target.id == "backup_metadata"
                for target in node.targets
            )
        )
        or (
            isinstance(node, ast.AnnAssign)
            and node.value is metadata
            and isinstance(node.target, ast.Name)
            and node.target.id == "backup_metadata"
        )
    ]
    metadata_payload = metadata_write.args[1] if len(metadata_write.args) >= 2 else None
    serialized_assignments = [
        node
        for node in ast.walk(transaction)
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "serialized_metadata"
                for target in node.targets
            )
        )
        or (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "serialized_metadata"
        )
    ]
    serialized_value = (
        serialized_assignments[0].value if len(serialized_assignments) == 1 else None
    )
    serialized_json_call = (
        serialized_value.func.value
        if isinstance(serialized_value, ast.Call)
        and isinstance(serialized_value.func, ast.Attribute)
        and isinstance(serialized_value.func.value, ast.Call)
        else None
    )
    serialized_keywords = (
        {keyword.arg: keyword.value for keyword in serialized_json_call.keywords}
        if isinstance(serialized_json_call, ast.Call)
        and all(keyword.arg is not None for keyword in serialized_json_call.keywords)
        else {}
    )
    if not (
        len(metadata_assignments) == 1
        and len(serialized_assignments) == 1
        and serialized_assignments[0].lineno < metadata_write_line
        and serialized_value is not None
        and isinstance(metadata_payload, ast.Name)
        and metadata_payload.id == "serialized_metadata"
        and isinstance(serialized_value, ast.Call)
        and isinstance(serialized_value.func, ast.Attribute)
        and serialized_value.func.attr == "encode"
        and len(serialized_value.args) == 1
        and not serialized_value.keywords
        and isinstance(serialized_value.args[0], ast.Constant)
        and serialized_value.args[0].value == "utf-8"
        and isinstance(serialized_json_call, ast.Call)
        and _ast_call_name(serialized_json_call) == "json.dumps"
        and len(serialized_json_call.args) == 1
        and isinstance(serialized_json_call.args[0], ast.Name)
        and serialized_json_call.args[0].id == "backup_metadata"
        and set(serialized_keywords) == {"sort_keys"}
        and isinstance(serialized_keywords["sort_keys"], ast.Constant)
        and serialized_keywords["sort_keys"].value is True
    ):
        raise CandidateError(
            "0.8.5+ bundle transaction does not publish its exact schema-2 metadata object"
        )
    metadata_bound_guards = [
        node
        for node in ast.walk(transaction)
        if isinstance(node, ast.If)
        and node.lineno < metadata_write_line
        and references_name(node.test, "serialized_metadata")
        and references_name(node.test, "_MAX_BUNDLE_ROLLBACK_METADATA_BYTES")
        and any(
            isinstance(candidate, ast.Call)
            and _ast_call_name(candidate) == "len"
            and candidate.args
            and references_name(candidate.args[0], "serialized_metadata")
            for candidate in ast.walk(node.test)
        )
        and any(isinstance(candidate, ast.Raise) for candidate in ast.walk(node))
    ]
    if len(metadata_bound_guards) != 1:
        raise CandidateError(
            "0.8.5+ bundle serialized metadata is not bounded before publication"
        )
    bound_test = metadata_bound_guards[0].test
    bound_comparison = bound_test.operand if isinstance(bound_test, ast.UnaryOp) else None
    if not (
        isinstance(bound_test, ast.UnaryOp)
        and isinstance(bound_test.op, ast.Not)
        and isinstance(bound_comparison, ast.Compare)
        and isinstance(bound_comparison.left, ast.Constant)
        and bound_comparison.left.value == 0
        and len(bound_comparison.ops) == 2
        and isinstance(bound_comparison.ops[0], ast.Lt)
        and isinstance(bound_comparison.ops[1], ast.LtE)
        and len(bound_comparison.comparators) == 2
        and isinstance(bound_comparison.comparators[0], ast.Call)
        and _ast_call_name(bound_comparison.comparators[0]) == "len"
        and len(bound_comparison.comparators[0].args) == 1
        and isinstance(bound_comparison.comparators[0].args[0], ast.Name)
        and bound_comparison.comparators[0].args[0].id == "serialized_metadata"
        and isinstance(bound_comparison.comparators[1], ast.Name)
        and bound_comparison.comparators[1].id == "_MAX_BUNDLE_ROLLBACK_METADATA_BYTES"
    ):
        raise CandidateError(
            "0.8.5+ bundle serialized metadata uses an invalid size bound"
        )

    parent: dict[ast.AST, ast.AST] = {}
    for ancestor in ast.walk(transaction):
        for child in ast.iter_child_nodes(ancestor):
            parent[child] = ancestor

    def condition_between(node: ast.AST, boundary: ast.AST) -> bool:
        current = node
        while current in parent and current is not boundary:
            current = parent[current]
            if current is boundary:
                break
            if isinstance(
                current,
                (ast.If, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda),
            ):
                return True
        return False

    if (
        condition_between(metadata_assignments[0], transaction)
        or condition_between(serialized_assignments[0], transaction)
        or condition_between(metadata_write, transaction)
    ):
        raise CandidateError(
            "0.8.5+ bundle rollback metadata construction or publication is conditional"
        )

    def assignment_value(node: ast.AST, name: str) -> ast.AST | None:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            return node.value
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            return node.value
        return None

    def child_path(value: ast.AST, root: str, leaf: str) -> bool:
        return (
            isinstance(value, ast.BinOp)
            and isinstance(value.op, ast.Div)
            and isinstance(value.left, ast.Name)
            and value.left.id == root
            and isinstance(value.right, ast.Constant)
            and value.right.value == leaf
        ) or (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "joinpath"
            and isinstance(value.func.value, ast.Name)
            and value.func.value.id == root
            and len(value.args) == 1
            and isinstance(value.args[0], ast.Constant)
            and value.args[0].value == leaf
        )

    def exact_root_call(name: str, argument: str) -> list[ast.Call]:
        return [
            node
            for node in calls
            if _ast_call_name(node) == name
            and node.lineno < metadata_write_line
            and len(node.args) >= 1
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == argument
        ]

    custody_roots = {
        "backup_managed": "managed",
        "backup_created": "created",
        "backup_retired": "retired",
    }
    for binding, leaf in custody_roots.items():
        assignments = [
            value
            for node in ast.walk(transaction)
            if getattr(node, "lineno", metadata_write_line) < metadata_write_line
            and (value := assignment_value(node, binding)) is not None
        ]
        if len(assignments) != 1 or not child_path(assignments[0], "backup_root", leaf):
            raise CandidateError(
                f"0.8.5+ bundle transaction lacks exact {leaf} rollback custody"
            )
        mkdir_calls = exact_root_call("_mkdir_private", binding)
        fsync_calls = exact_root_call("_fsync_directory_chain", binding)
        if len(mkdir_calls) != 1 or len(fsync_calls) != 1:
            raise CandidateError(
                f"0.8.5+ bundle {leaf} rollback custody is not durably created"
            )
        stop_values = [
            keyword.value
            for keyword in fsync_calls[0].keywords
            if keyword.arg == "stop"
        ]
        if not (
            len(mkdir_calls[0].args) == 1
            and not mkdir_calls[0].keywords
            and len(fsync_calls[0].args) == 1
            and len(fsync_calls[0].keywords) == 1
            and not condition_between(mkdir_calls[0], transaction)
            and not condition_between(fsync_calls[0], transaction)
            and mkdir_calls[0].lineno < fsync_calls[0].lineno < metadata_write_line
            and len(stop_values) == 1
            and isinstance(stop_values[0], ast.Name)
            and stop_values[0].id == "backup_root"
        ):
            raise CandidateError(
                f"0.8.5+ bundle {leaf} rollback custody is not fsynced to its root"
            )

    for binding in ("old_sha256", "old_modes", "created_sha256", "old_windows_security"):
        initializers = [
            value
            for node in ast.walk(transaction)
            if getattr(node, "lineno", metadata_write_line) < metadata_write_line
            and (value := assignment_value(node, binding)) is not None
            and isinstance(value, ast.Dict)
        ]
        if len(initializers) != 1 or initializers[0].keys:
            raise CandidateError(
                f"0.8.5+ bundle transaction lacks one empty {binding} inventory"
            )

    managed_inventory_values = [
        value
        for node in ast.walk(transaction)
        if getattr(node, "lineno", metadata_write_line) < metadata_write_line
        and (value := assignment_value(node, "managed_paths")) is not None
    ]
    if not (
        len(managed_inventory_values) == 1
        and isinstance(managed_inventory_values[0], ast.BinOp)
        and isinstance(managed_inventory_values[0].op, ast.BitOr)
        and isinstance(managed_inventory_values[0].left, ast.Name)
        and isinstance(managed_inventory_values[0].right, ast.Name)
        and {
            managed_inventory_values[0].left.id,
            managed_inventory_values[0].right.id,
        }
        == {"existing_paths", "created_paths"}
    ):
        raise CandidateError(
            "0.8.5+ bundle managed inventory is not the exact existing/created union"
        )

    backup_copies = [
        node
        for node in calls
        if _ast_call_name(node) == "shutil.copy2"
        and node.lineno < metadata_write_line
        and len(node.args) == 2
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "path"
        and isinstance(node.args[1], ast.Name)
        and node.args[1].id == "backup_path"
    ]
    if len(backup_copies) != 1:
        raise CandidateError("0.8.5+ bundle transaction lacks one bounded backup copy loop")
    copy_call = backup_copies[0]
    copy_loop: ast.For | None = None
    current: ast.AST | None = copy_call
    while current in parent:
        current = parent[current]
        if isinstance(current, ast.For):
            copy_loop = current
            break
    if copy_loop is None:
        raise CandidateError("0.8.5+ bundle backup copy is outside its managed inventory loop")
    if condition_between(copy_call, copy_loop) or not (
        isinstance(copy_loop.iter, ast.Name)
        and copy_loop.iter.id == "existing_paths"
    ):
        raise CandidateError(
            "0.8.5+ bundle backup copy does not exactly cover existing paths"
        )
    backup_path_values = [
        value
        for node in ast.walk(copy_loop)
        if (value := assignment_value(node, "backup_path")) is not None
    ]
    backup_path_value = backup_path_values[0] if len(backup_path_values) == 1 else None
    if not (
        isinstance(backup_path_value, ast.BinOp)
        and isinstance(backup_path_value.op, ast.Div)
        and isinstance(backup_path_value.left, ast.Name)
        and backup_path_value.left.id == "backup_managed"
        and isinstance(backup_path_value.right, ast.Name)
        and backup_path_value.right.id == "path"
    ):
        raise CandidateError(
            "0.8.5+ bundle existing backup is outside managed rollback custody"
        )

    def inventory_writes(scope: ast.AST, binding: str) -> list[ast.Assign | ast.AnnAssign]:
        writes: list[ast.Assign | ast.AnnAssign] = []
        for node in ast.walk(scope):
            targets: tuple[ast.AST, ...] = ()
            if isinstance(node, ast.Assign):
                targets = tuple(node.targets)
            elif isinstance(node, ast.AnnAssign):
                targets = (node.target,)
            else:
                continue
            if any(
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id == binding
                for target in targets
            ):
                writes.append(node)
        return writes

    def exact_inventory_key(
        write: ast.Assign | ast.AnnAssign,
        binding: str,
    ) -> bool:
        targets = write.targets if isinstance(write, ast.Assign) else [write.target]
        return (
            len(targets) == 1
            and isinstance(targets[0], ast.Subscript)
            and isinstance(targets[0].value, ast.Name)
            and targets[0].value.id == binding
            and isinstance(targets[0].slice, ast.Name)
            and targets[0].slice.id == "path"
        )

    old_digest_writes = inventory_writes(copy_loop, "old_sha256")
    old_mode_writes = inventory_writes(copy_loop, "old_modes")
    old_digest_value = old_digest_writes[0].value if len(old_digest_writes) == 1 else None
    old_mode_value = old_mode_writes[0].value if len(old_mode_writes) == 1 else None
    if (
        len(old_digest_writes) != 1
        or len(old_mode_writes) != 1
        or old_digest_value is None
        or old_mode_value is None
        or not exact_inventory_key(old_digest_writes[0], "old_sha256")
        or not exact_inventory_key(old_mode_writes[0], "old_modes")
        or condition_between(old_digest_writes[0], copy_loop)
        or condition_between(old_mode_writes[0], copy_loop)
        or old_digest_writes[0].lineno <= copy_call.lineno
        or old_mode_writes[0].lineno <= copy_call.lineno
        or not isinstance(old_digest_value, ast.Call)
        or _ast_call_name(old_digest_value) != "_sha256_file"
        or len(old_digest_value.args) != 1
        or old_digest_value.keywords
        or not isinstance(old_digest_value.args[0], ast.Name)
        or old_digest_value.args[0].id != "backup_path"
        or not isinstance(old_mode_value, ast.Call)
        or _ast_call_name(old_mode_value) != "stat.S_IMODE"
        or len(old_mode_value.args) != 1
        or old_mode_value.keywords
        or not isinstance(old_mode_value.args[0], ast.Attribute)
        or old_mode_value.args[0].attr != "st_mode"
        or not isinstance(old_mode_value.args[0].value, ast.Call)
        or _ast_call_name(old_mode_value.args[0].value) != "path.stat"
        or old_mode_value.args[0].value.args
        or old_mode_value.args[0].value.keywords
    ):
        raise CandidateError(
            "0.8.5+ bundle backup loop lacks exact digest and mode inventory"
        )

    windows_writes = inventory_writes(copy_loop, "old_windows_security")
    if len(windows_writes) != 1:
        raise CandidateError(
            "0.8.5+ bundle backup loop lacks exact per-path Windows security inventory"
        )
    windows_write = windows_writes[0]
    if not exact_inventory_key(windows_write, "old_windows_security"):
        raise CandidateError(
            "0.8.5+ bundle Windows security inventory is not keyed by its exact path"
        )
    windows_value = windows_write.value
    if windows_value is None:
        raise CandidateError(
            "0.8.5+ bundle Windows security inventory has no serialized value"
        )
    captured_security = (
        windows_value.args[0]
        if isinstance(windows_value, ast.Call) and len(windows_value.args) == 1
        else None
    )
    if (
        not isinstance(windows_value, ast.Call)
        or _ast_call_name(windows_value) != "_serialize_windows_security"
        or windows_value.keywords
        or not isinstance(captured_security, ast.Call)
        or _ast_call_name(captured_security) != "windows_acl.capture_path"
        or len(captured_security.args) != 1
        or captured_security.keywords
        or not isinstance(captured_security.args[0], ast.Name)
        or captured_security.args[0].id != "path"
    ):
        raise CandidateError(
            "0.8.5+ bundle Windows security inventory is not captured and serialized exactly"
        )
    current = windows_write
    windows_guard: ast.If | None = None
    while current in parent and current is not copy_loop:
        current = parent[current]
        if isinstance(current, ast.If):
            windows_guard = current
            break
    windows_test = windows_guard.test if windows_guard is not None else None
    if not (
        isinstance(windows_test, ast.Compare)
        and len(windows_test.ops) == 1
        and isinstance(windows_test.ops[0], ast.Eq)
        and len(windows_test.comparators) == 1
        and (
            (
                isinstance(windows_test.left, ast.Attribute)
                and windows_test.left.attr == "name"
                and isinstance(windows_test.left.value, ast.Name)
                and windows_test.left.value.id == "os"
                and isinstance(windows_test.comparators[0], ast.Constant)
                and windows_test.comparators[0].value == "nt"
            )
            or (
                isinstance(windows_test.left, ast.Constant)
                and windows_test.left.value == "nt"
                and isinstance(windows_test.comparators[0], ast.Attribute)
                and windows_test.comparators[0].attr == "name"
                and isinstance(windows_test.comparators[0].value, ast.Name)
                and windows_test.comparators[0].value.id == "os"
            )
        )
    ):
        raise CandidateError(
            "0.8.5+ bundle Windows security inventory is not platform-exact"
        )
    durable_backup_calls = [
        node
        for node in ast.walk(copy_loop)
        if isinstance(node, ast.Call)
        and node.lineno > copy_call.lineno
        and node.lineno < metadata_write_line
        and _ast_call_name(node) == "_fsync_file"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "backup_path"
    ]
    if not durable_backup_calls:
        raise CandidateError(
            "0.8.5+ bundle backup files are not fsynced before metadata publication"
        )
    if any(condition_between(node, copy_loop) for node in durable_backup_calls):
        raise CandidateError(
            "0.8.5+ bundle backup file durability is conditional"
        )
    durable_directory_calls = [
        node
        for node in ast.walk(copy_loop)
        if isinstance(node, ast.Call)
        and node.lineno > copy_call.lineno
        and node.lineno < metadata_write_line
        and _ast_call_name(node) == "_fsync_directory_chain"
        and len(node.args) == 1
        and len(node.keywords) == 1
        and isinstance(node.args[0], ast.Attribute)
        and node.args[0].attr == "parent"
        and isinstance(node.args[0].value, ast.Name)
        and node.args[0].value.id == "backup_path"
    ]
    if len(durable_directory_calls) != 1:
        raise CandidateError(
            "0.8.5+ bundle backup directory entries are not fsynced before metadata publication"
        )
    if condition_between(durable_directory_calls[0], copy_loop):
        raise CandidateError(
            "0.8.5+ bundle backup directory durability is conditional"
        )
    directory_call = durable_directory_calls[0]
    stop_values = [
        keyword.value for keyword in directory_call.keywords if keyword.arg == "stop"
    ]
    if not (
        len(stop_values) == 1
        and isinstance(stop_values[0], ast.Name)
        and stop_values[0].id == "backup_root"
    ):
        raise CandidateError(
            "0.8.5+ bundle directory fsync chain must include the backup root"
        )
    if not any(node.lineno < directory_call.lineno for node in durable_backup_calls):
        raise CandidateError(
            "0.8.5+ bundle backup files must be fsynced before directory entries"
        )

    claim_copies = [
        node
        for node in calls
        if _ast_call_name(node) == "_atomic_copy_file"
        and node.lineno < metadata_write_line
        and len(node.args) == 2
        and not node.keywords
        and isinstance(node.args[1], ast.Name)
        and node.args[1].id == "created_claim"
    ]
    if len(claim_copies) != 1:
        raise CandidateError(
            "0.8.5+ bundle transaction lacks one retained target-created claim loop"
        )
    claim_copy = claim_copies[0]
    claim_loop: ast.For | None = None
    current = claim_copy
    while current in parent:
        current = parent[current]
        if isinstance(current, ast.For):
            claim_loop = current
            break
    if claim_loop is None or condition_between(claim_copy, claim_loop) or not (
        isinstance(claim_loop.iter, ast.Name)
        and claim_loop.iter.id == "created_paths"
    ):
        raise CandidateError(
            "0.8.5+ bundle target-created claims do not exactly cover created paths"
        )
    claim_bindings = [
        value
        for node in ast.walk(claim_loop)
        if (value := assignment_value(node, "created_claim")) is not None
    ]
    claim_binding = claim_bindings[0] if len(claim_bindings) == 1 else None
    if not (
        isinstance(claim_binding, ast.BinOp)
        and isinstance(claim_binding.op, ast.Div)
        and isinstance(claim_binding.left, ast.Name)
        and claim_binding.left.id == "backup_created"
        and isinstance(claim_binding.right, ast.Name)
        and claim_binding.right.id == "path"
    ):
        raise CandidateError(
            "0.8.5+ bundle target-created claims are outside retained custody"
        )
    claim_file_fsyncs = [
        node
        for node in ast.walk(claim_loop)
        if isinstance(node, ast.Call)
        and _ast_call_name(node) == "_fsync_file"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "created_claim"
    ]
    claim_directory_fsyncs = [
        node
        for node in ast.walk(claim_loop)
        if isinstance(node, ast.Call)
        and _ast_call_name(node) == "_fsync_directory_chain"
        and len(node.args) == 1
        and len(node.keywords) == 1
        and isinstance(node.args[0], ast.Attribute)
        and node.args[0].attr == "parent"
        and isinstance(node.args[0].value, ast.Name)
        and node.args[0].value.id == "created_claim"
    ]
    if len(claim_file_fsyncs) != 1 or len(claim_directory_fsyncs) != 1:
        raise CandidateError(
            "0.8.5+ bundle target-created claims are not durably retained"
        )
    if condition_between(claim_file_fsyncs[0], claim_loop) or condition_between(
        claim_directory_fsyncs[0],
        claim_loop,
    ):
        raise CandidateError(
            "0.8.5+ bundle target-created claim durability is conditional"
        )
    claim_stop_values = [
        keyword.value
        for keyword in claim_directory_fsyncs[0].keywords
        if keyword.arg == "stop"
    ]
    if not (
        claim_copy.lineno
        < claim_file_fsyncs[0].lineno
        < claim_directory_fsyncs[0].lineno
        < metadata_write_line
        and len(claim_stop_values) == 1
        and isinstance(claim_stop_values[0], ast.Name)
        and claim_stop_values[0].id == "backup_root"
    ):
        raise CandidateError(
            "0.8.5+ bundle target-created claims are not fsynced to the backup root"
        )
    created_digest_writes = inventory_writes(claim_loop, "created_sha256")
    created_digest_value = (
        created_digest_writes[0].value if len(created_digest_writes) == 1 else None
    )
    if not (
        len(created_digest_writes) == 1
        and created_digest_value is not None
        and exact_inventory_key(created_digest_writes[0], "created_sha256")
        and not condition_between(created_digest_writes[0], claim_loop)
        and created_digest_writes[0].lineno > claim_copy.lineno
        and isinstance(created_digest_value, ast.Call)
        and _ast_call_name(created_digest_value) == "_sha256_file"
        and len(created_digest_value.args) == 1
        and not created_digest_value.keywords
        and isinstance(created_digest_value.args[0], ast.Name)
        and created_digest_value.args[0].id == "created_claim"
    ):
        raise CandidateError(
            "0.8.5+ bundle target-created claim digest inventory is incomplete"
        )

    claim_publications = [
        node
        for node in calls
        if _ast_call_name(node) == "os.link"
        and node.lineno > metadata_write_line
        and len(node.args) == 2
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "created_claim"
        and isinstance(node.args[1], ast.Name)
        and node.args[1].id == "destination"
    ]
    if len(claim_publications) != 1:
        raise CandidateError(
            "0.8.5+ bundle target-created claims lack one no-replace publication"
        )
    claim_publication = claim_publications[0]
    publication_loop: ast.For | None = None
    current = claim_publication
    while current in parent:
        current = parent[current]
        if isinstance(current, ast.For):
            publication_loop = current
            break
    if publication_loop is None or condition_between(
        claim_publication,
        publication_loop,
    ) or not (
        isinstance(publication_loop.iter, ast.Name)
        and publication_loop.iter.id == "created_paths"
    ):
        raise CandidateError(
            "0.8.5+ bundle target-created publication does not cover its exact inventory"
        )
    publication_claim_values = [
        value
        for node in ast.walk(publication_loop)
        if (value := assignment_value(node, "created_claim")) is not None
    ]
    publication_destination_values = [
        value
        for node in ast.walk(publication_loop)
        if (value := assignment_value(node, "destination")) is not None
    ]
    published_claim = (
        publication_claim_values[0] if len(publication_claim_values) == 1 else None
    )
    published_destination = (
        publication_destination_values[0]
        if len(publication_destination_values) == 1
        else None
    )
    if not (
        isinstance(published_claim, ast.BinOp)
        and isinstance(published_claim.op, ast.Div)
        and isinstance(published_claim.left, ast.Name)
        and published_claim.left.id == "backup_created"
        and isinstance(published_claim.right, ast.Name)
        and published_claim.right.id == "path"
        and isinstance(published_destination, ast.Name)
        and published_destination.id == "path"
    ):
        raise CandidateError(
            "0.8.5+ bundle target-created publication is not claim-bound"
        )

    mutation_nodes = [
        node
        for node in ast.walk(transaction)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and (
            (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "mutation_started"
                    for target in node.targets
                )
            )
            or (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == "mutation_started"
            )
        )
        and isinstance(node.value, ast.Constant)
        and node.value.value is True
    ]
    mutation_lines = [node.lineno for node in mutation_nodes]
    if (
        len(mutation_lines) != 1
        or mutation_lines[0] <= metadata_write_line
        or mutation_lines[0] >= claim_publication.lineno
        or condition_between(mutation_nodes[0], transaction)
    ):
        raise CandidateError(
            "0.8.5+ bundle rollback metadata is not durable before first mutation"
        )
    mutation_line = mutation_lines[0]
    all_link_calls = [node for node in calls if _ast_call_name(node) == "os.link"]
    if len(all_link_calls) != 1:
        raise CandidateError(
            "0.8.5+ bundle transaction has ambiguous target-created publication"
        )
    managed_publications = [
        node
        for node in calls
        if _ast_call_name(node) == "_atomic_copy_file"
        and node.lineno > metadata_write_line
        and len(node.args) == 2
        and not node.keywords
        and isinstance(node.args[1], ast.Name)
        and node.args[1].id == "destination"
    ]
    if len(managed_publications) != 1:
        raise CandidateError(
            "0.8.5+ bundle transaction lacks one authenticated managed-file publication"
        )
    all_atomic_copies = [
        node for node in calls if _ast_call_name(node) == "_atomic_copy_file"
    ]
    all_legacy_copies = [
        node for node in calls if _ast_call_name(node) == "shutil.copy2"
    ]
    if set(all_atomic_copies) != {claim_copy, managed_publications[0]} or all_legacy_copies != [
        copy_call
    ]:
        raise CandidateError(
            "0.8.5+ bundle transaction has an ambiguous copy mutation"
        )
    managed_publication = managed_publications[0]
    managed_publication_loop: ast.For | None = None
    current = managed_publication
    while current in parent:
        current = parent[current]
        if isinstance(current, ast.For):
            managed_publication_loop = current
            break
    if managed_publication_loop is None or condition_between(
        managed_publication,
        managed_publication_loop,
    ) or not (
        isinstance(managed_publication_loop.iter, ast.Name)
        and managed_publication_loop.iter.id == "existing_paths"
    ):
        raise CandidateError(
            "0.8.5+ bundle managed-file publication does not cover existing paths"
        )
    managed_destination_values = [
        value
        for node in ast.walk(managed_publication_loop)
        if (value := assignment_value(node, "destination")) is not None
    ]
    if not (
        len(managed_destination_values) == 1
        and isinstance(managed_destination_values[0], ast.Name)
        and managed_destination_values[0].id == "path"
    ):
        raise CandidateError(
            "0.8.5+ bundle managed-file publication is not destination-bound"
        )
    canonical_mutations = [*all_link_calls, *managed_publications]
    if any(node.lineno <= mutation_line for node in canonical_mutations):
        raise CandidateError(
            "0.8.5+ bundle mutation begins before durable rollback authority"
        )
    transaction_returns = [
        node for node in ast.walk(transaction) if isinstance(node, ast.Return)
    ]
    if not (
        len(transaction_returns) == 1
        and transaction_returns[0].lineno > max(
            node.lineno for node in canonical_mutations
        )
        and isinstance(transaction_returns[0].value, ast.Name)
        and transaction_returns[0].value.id == "mutation_started"
        and not condition_between(transaction_returns[0], transaction)
    ):
        raise CandidateError(
            "0.8.5+ bundle transaction has an ambiguous completion path"
        )
    forbidden_direct_mutators = {
        "open",
        "os.open",
        "os.write",
        "os.pwrite",
        "os.replace",
        "os.rename",
        "os.unlink",
        "os.remove",
        "os.symlink",
        "os.truncate",
        "shutil.copy",
        "shutil.copyfile",
        "shutil.move",
        "shutil.rmtree",
    }
    forbidden_mutator_suffixes = (
        ".open",
        ".write_bytes",
        ".write_text",
        ".touch",
        ".unlink",
        ".replace",
        ".rename",
        ".rmdir",
    )
    if any(
        (name := _ast_call_name(node)) is not None
        and (
            name in forbidden_direct_mutators
            or name.endswith(forbidden_mutator_suffixes)
        )
        for node in calls
    ):
        raise CandidateError(
            "0.8.5+ bundle transaction bypasses its reviewed publication primitives"
        )
    forbidden_before_metadata = {
        "os.link",
        "os.replace",
        "os.rename",
        "os.unlink",
        "os.remove",
        "shutil.rmtree",
    }
    if any(
        (_ast_call_name(node) in forbidden_before_metadata)
        and node.lineno < metadata_write_line
        for node in calls
    ):
        raise CandidateError(
            "0.8.5+ bundle transaction mutates canonical paths before rollback metadata"
        )


def _validate_runtime_hard_cut_bundle_transaction(source: str) -> None:
    """Validate the real path-safe schema-2 transaction shipped in 0.8.5+.

    The older compact fixture uses relative placeholder paths and returns a
    boolean. The runtime transaction must instead bind each relative inventory
    member to the installed and custody roots explicitly, retain target-created
    inodes with a private hardlink, and return its structured result. Keep this
    validator exact so a future shape change requires an intentional review.
    """

    try:
        tree = ast.parse(source, filename="defenseclaw/bundle_refresh.py")
    except (SyntaxError, ValueError) as exc:
        raise CandidateError("0.8.5+ candidate wheel bundle transaction is invalid") from exc

    def one_function(name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
        matches = [
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
        ]
        if len(matches) != 1:
            raise CandidateError(f"0.8.5+ bundle transaction lacks one {name} helper")
        return matches[0]

    def calls(scope: ast.AST, name: str) -> list[ast.Call]:
        return [
            node
            for node in ast.walk(scope)
            if isinstance(node, ast.Call) and _ast_call_name(node) == name
        ]

    def references(node: ast.AST, name: str) -> bool:
        return any(isinstance(item, ast.Name) and item.id == name for item in ast.walk(node))

    def assignment(scope: ast.AST, name: str) -> list[ast.AST]:
        values: list[ast.AST] = []
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == name for target in node.targets
            ):
                values.append(node.value)
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == name
                and node.value is not None
            ):
                values.append(node.value)
        return values

    def child_path(value: ast.AST, root: str, child: str | None = None) -> bool:
        return (
            isinstance(value, ast.BinOp)
            and isinstance(value.op, ast.Div)
            and isinstance(value.left, ast.Name)
            and value.left.id == root
            and (
                (child is None and isinstance(value.right, ast.Name))
                or (
                    child is not None
                    and isinstance(value.right, ast.Constant)
                    and value.right.value == child
                )
            )
        )

    parent: dict[ast.AST, ast.AST] = {}
    for ancestor in ast.walk(tree):
        for child in ast.iter_child_nodes(ancestor):
            parent[child] = ancestor

    def enclosing_loop(node: ast.AST) -> ast.For | None:
        current = node
        while current in parent:
            current = parent[current]
            if isinstance(current, ast.For):
                return current
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return None
        return None

    def loop_iterates(loop: ast.For | None, inventory: str) -> bool:
        if loop is None:
            return False
        iterator = loop.iter
        if isinstance(iterator, ast.Call) and _ast_call_name(iterator) == "sorted":
            if len(iterator.args) != 1 or iterator.keywords:
                return False
            iterator = iterator.args[0]
        return references(iterator, inventory)

    # The bridge reader has a hard 4 MiB cap; the target must share it.
    bounds = assignment(tree, "_MAX_BUNDLE_ROLLBACK_METADATA_BYTES")
    if len(bounds) != 1 or ast.unparse(bounds[0]) not in {"4 * 1024 * 1024", "4194304"}:
        raise CandidateError("0.8.5+ bundle transaction lacks the bridge metadata size bound")

    serializer = one_function("_serialize_windows_security")
    serializer_source = ast.unparse(serializer)
    for fragment in (
        "base64.b64encode(security.owner).decode('ascii')",
        "base64.b64encode(security.dacl).decode('ascii')",
        "security.dacl_protected",
    ):
        if fragment not in serializer_source:
            raise CandidateError(
                "0.8.5+ bundle Windows owner/DACL bytes are not canonically serialized"
            )

    fsync_chain = one_function("_fsync_directory_chain")
    if not (
        calls(fsync_chain, "_fsync_directory")
        and any(isinstance(node, ast.While) for node in ast.walk(fsync_chain))
        and references(fsync_chain, "stop")
    ):
        raise CandidateError("0.8.5+ bundle directory fsync custody is incomplete")

    # Restart authority must reach durable private storage before `down`.
    prepare = one_function("_prepare_local_observability_backup_custody")
    intent_dicts = [
        node
        for node in ast.walk(prepare)
        if isinstance(node, ast.Dict)
        and {
            key.value for key in node.keys if isinstance(key, ast.Constant)
        }
        == {"schema_version", "target_manifest_sha256", "restart_required"}
    ]
    intent_writes = calls(prepare, "_atomic_write_bytes")
    if len(intent_dicts) != 1 or len(intent_writes) != 1:
        raise CandidateError("0.8.5+ bundle restart intent is not durably published")
    intent_values = {
        key.value: value
        for key, value in zip(intent_dicts[0].keys, intent_dicts[0].values, strict=True)
        if isinstance(key, ast.Constant)
    }
    intent_write = intent_writes[0]
    if not (
        isinstance(intent_values.get("schema_version"), ast.Constant)
        and intent_values["schema_version"].value == 1
        and references(intent_values["target_manifest_sha256"], "target_manifest_sha256")
        and references(intent_values["restart_required"], "restart_required")
        and references(intent_write.args[0], "_LOCAL_OBSERVABILITY_RESTART_INTENT")
        and any(keyword.arg == "mode" and ast.unparse(keyword.value) == "384" for keyword in intent_write.keywords)
    ):
        raise CandidateError("0.8.5+ bundle restart intent lacks exact private authority")

    upgrade = one_function("upgrade_local_observability_stack")
    prepare_calls = calls(upgrade, "_prepare_local_observability_backup_custody")
    stop_calls = calls(upgrade, "subprocess.run")
    activation_calls = calls(upgrade, "_activate_local_observability_manifest")
    if not (
        len(prepare_calls) == len(stop_calls) == len(activation_calls) == 1
        and prepare_calls[0].lineno < stop_calls[0].lineno < activation_calls[0].lineno
        and any(
            keyword.arg == "restart_required" and references(keyword.value, "was_running")
            for keyword in prepare_calls[0].keywords
        )
        and references(activation_calls[0], "backup_root")
    ):
        raise CandidateError("0.8.5+ bundle restart intent is not committed before stop")

    transaction = one_function("_activate_local_observability_manifest")
    was_running = [
        argument
        for argument in (*transaction.args.args, *transaction.args.kwonlyargs)
        if argument.arg == "was_running"
    ]
    if not (
        len(was_running) == 1
        and isinstance(was_running[0].annotation, ast.Name)
        and was_running[0].annotation.id == "bool"
    ):
        raise CandidateError("0.8.5+ bundle transaction restart state is not boolean-bound")

    metadata_dicts = []
    expected_fields = {
        "schema_version",
        "managed_paths",
        "existing_paths",
        "old_sha256",
        "old_modes",
        "created_sha256",
        "old_windows_security",
        "restart_required",
    }
    for node in ast.walk(transaction):
        if not isinstance(node, ast.Dict):
            continue
        keys = {
            key.value for key in node.keys if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        if keys & {"managed_paths", "restart_required"}:
            metadata_dicts.append(node)
    if len(metadata_dicts) != 1:
        raise CandidateError("0.8.5+ bundle transaction must define one rollback metadata object")
    metadata = metadata_dicts[0]
    values = {
        key.value: value
        for key, value in zip(metadata.keys, metadata.values, strict=True)
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    if set(values) != expected_fields or len(metadata.keys) != len(expected_fields):
        raise CandidateError("0.8.5+ bundle rollback metadata lacks exact schema-2 custody")
    if not isinstance(values["schema_version"], ast.Constant) or values["schema_version"].value != 2:
        raise CandidateError("0.8.5+ bundle rollback metadata is not schema version 2")
    for field in ("managed_paths", "existing_paths"):
        value = values[field]
        if not (
            isinstance(value, ast.Call)
            and _ast_call_name(value) == "sorted"
            and len(value.args) == 1
            and references(value.args[0], field)
        ):
            raise CandidateError(f"0.8.5+ bundle {field} is not exact")
    for field in ("old_sha256", "old_modes", "created_sha256", "old_windows_security"):
        if not isinstance(values[field], ast.Name) or values[field].id != field:
            raise CandidateError(f"0.8.5+ bundle {field} is not bound to exact custody")
    if not isinstance(values["restart_required"], ast.Name) or values["restart_required"].id != "was_running":
        raise CandidateError("0.8.5+ bundle rollback metadata lacks boolean restart_required")

    metadata_writes = [
        call
        for call in calls(transaction, "_atomic_write_bytes")
        if any(
            isinstance(node, ast.Constant) and node.value == "refresh-backup.json"
            for node in ast.walk(call)
        )
    ]
    if len(metadata_writes) != 1 or len(calls(transaction, "_atomic_write_bytes")) != 1:
        raise CandidateError("0.8.5+ bundle transaction has ambiguous metadata publication")
    metadata_write = metadata_writes[0]
    metadata_line = metadata_write.lineno
    serialized = assignment(transaction, "serialized_metadata")
    if not (
        len(serialized) == 1
        and _ast_call_name(serialized[0].func.value) == "json.dumps"
        if isinstance(serialized[0], ast.Call)
        and isinstance(serialized[0].func, ast.Attribute)
        and isinstance(serialized[0].func.value, ast.Call)
        else False
    ):
        raise CandidateError("0.8.5+ bundle transaction does not serialize exact metadata")
    serialized_source = ast.unparse(serialized[0])
    if not (
        "json.dumps(backup_metadata, sort_keys=True)" in serialized_source
        and ".encode('utf-8')" in serialized_source
        and references(metadata_write, "serialized_metadata")
    ):
        raise CandidateError("0.8.5+ bundle transaction does not publish exact schema-2 metadata")
    size_guards = [
        node
        for node in ast.walk(transaction)
        if isinstance(node, ast.If)
        and node.lineno < metadata_line
        and references(node.test, "serialized_metadata")
        and references(node.test, "_MAX_BUNDLE_ROLLBACK_METADATA_BYTES")
        and any(isinstance(child, ast.Raise) for child in ast.walk(node))
    ]
    expected_bound = "0 < len(serialized_metadata) <= _MAX_BUNDLE_ROLLBACK_METADATA_BYTES"
    if len(size_guards) != 1 or expected_bound not in ast.unparse(size_guards[0].test):
        raise CandidateError("0.8.5+ bundle serialized metadata is not bounded")

    for binding, leaf in {
        "backup_managed": "managed",
        "backup_created": "created",
        "backup_retired": "retired",
    }.items():
        values_for_binding = assignment(transaction, binding)
        mkdirs = [call for call in calls(transaction, "_mkdir_private") if references(call, binding)]
        syncs = [
            call
            for call in calls(transaction, "_fsync_directory_chain")
            if references(call, binding) and references(call, "backup_root")
        ]
        if not (
            len(values_for_binding) == 1
            and child_path(values_for_binding[0], "backup_root", leaf)
            and len(mkdirs) == 1
            and len(syncs) == 1
            and mkdirs[0].lineno < syncs[0].lineno < metadata_line
        ):
            raise CandidateError(f"0.8.5+ bundle {leaf} rollback custody is incomplete")

    backup_copies = calls(transaction, "shutil.copy2")
    if len(backup_copies) != 1:
        raise CandidateError("0.8.5+ bundle transaction lacks one bounded backup copy loop")
    backup_copy = backup_copies[0]
    backup_loop = enclosing_loop(backup_copy)
    if not (
        loop_iterates(backup_loop, "existing_paths")
        and len(backup_copy.args) == 2
        and references(backup_copy.args[0], "path")
        and references(backup_copy.args[1], "backup_path")
        and len(backup_copy.keywords) == 1
        and backup_copy.keywords[0].arg == "follow_symlinks"
        and isinstance(backup_copy.keywords[0].value, ast.Constant)
        and backup_copy.keywords[0].value.value is False
    ):
        raise CandidateError("0.8.5+ bundle backup copy is not path-safe or exact")
    backup_loop_source = ast.unparse(backup_loop)
    for fragment in (
        "path = destination / relative",
        "backup_path = backup_managed / relative",
        "_fsync_file(backup_path)",
        "_fsync_directory_chain(backup_path.parent, stop=backup_root)",
        "old_sha256[relative] = _sha256_file(backup_path)",
        "old_modes[relative] = stat.S_IMODE(source_before.st_mode)",
        "_rollback_source_snapshot_unchanged(source_before, source_after)",
        "_sha256_file(path) != old_sha256[relative]",
        "old_windows_security[relative] = _serialize_windows_security(native_security)",
    ):
        if fragment not in backup_loop_source:
            raise CandidateError("0.8.5+ bundle existing backup custody is incomplete")
    windows_capture = calls(backup_loop, "windows_acl.capture_path")
    if len(windows_capture) != 2 or not all(references(call, "path") for call in windows_capture):
        raise CandidateError("0.8.5+ bundle Windows security is not captured exactly")
    windows_guard = parent.get(windows_capture[0])
    while windows_guard is not None and windows_guard is not backup_loop and not isinstance(windows_guard, ast.If):
        windows_guard = parent.get(windows_guard)
    if not isinstance(windows_guard, ast.If) or ast.unparse(windows_guard.test) != "os.name == 'nt'":
        raise CandidateError("0.8.5+ bundle Windows security is not platform-exact")

    atomic_copies = calls(transaction, "_atomic_copy_file")
    if len(atomic_copies) != 2:
        raise CandidateError("0.8.5+ bundle transaction has ambiguous copy mutation")
    claim_copy = next((call for call in atomic_copies if call.lineno < metadata_line), None)
    publish_copy = next((call for call in atomic_copies if call.lineno > metadata_line), None)
    claim_loop = enclosing_loop(claim_copy) if claim_copy is not None else None
    publish_loop = enclosing_loop(publish_copy) if publish_copy is not None else None
    if not (
        claim_copy is not None
        and loop_iterates(claim_loop, "created_paths")
        and references(claim_copy, "stage")
        and references(claim_copy, "created_claim")
        and "created_claim = backup_created / relative" in ast.unparse(claim_loop)
        and "_fsync_file(created_claim)" in ast.unparse(claim_loop)
        and "_fsync_directory_chain(created_claim.parent, stop=backup_root)" in ast.unparse(claim_loop)
        and "created_sha256[relative] = _sha256_file(created_claim)" in ast.unparse(claim_loop)
    ):
        raise CandidateError("0.8.5+ bundle target-created claims lack exact durable custody")
    if not (
        publish_copy is not None
        and loop_iterates(publish_loop, "existing_paths")
        and references(publish_loop.iter, "target_paths")
        and references(publish_copy, "stage")
        and references(publish_copy, "destination_path")
    ):
        raise CandidateError("0.8.5+ bundle existing publication is not exact")

    links = calls(transaction, "os.link")
    if len(links) != 1 or links[0].lineno < metadata_line:
        raise CandidateError("0.8.5+ bundle target-created claims lack one no-replace publication")
    link_loop = enclosing_loop(links[0])
    if not (
        loop_iterates(link_loop, "created_paths")
        and references(links[0].args[0], "created_claim")
        and references(links[0].args[1], "destination_path")
        and "created_claim = backup_created / relative" in ast.unparse(link_loop)
        and "destination_path = destination / relative" in ast.unparse(link_loop)
        and "_fsync_directory(destination_path.parent)" in ast.unparse(link_loop)
    ):
        raise CandidateError("0.8.5+ bundle target-created publication is not claim-bound")

    removals = calls(transaction, "_remove_managed_bundle_file")
    if len(removals) != 1 or removals[0].lineno < metadata_line:
        raise CandidateError("0.8.5+ bundle retired-file mutation lacks rollback authority")
    first_publication = min(publish_copy.lineno, links[0].lineno, removals[0].lineno)
    mutation_starts = [
        node
        for node in ast.walk(transaction)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "mutation_started" for target in node.targets)
        and isinstance(node.value, ast.Constant)
        and node.value.value is True
    ]
    if len(mutation_starts) != 1 or not metadata_line < mutation_starts[0].lineno < first_publication:
        raise CandidateError("0.8.5+ bundle rollback metadata is not durable before first mutation")

    rollback_calls = calls(transaction, "_restore_local_observability_backup")
    if len(rollback_calls) != 1 or not all(
        references(rollback_calls[0], name)
        for name in (
            "backup_managed",
            "backup_created",
            "backup_retired",
            "managed_paths",
            "existing_paths",
            "old_sha256",
            "old_modes",
            "created_sha256",
            "old_windows_security_native",
        )
    ):
        raise CandidateError("0.8.5+ bundle activation failure lacks exact schema-2 replay")
    cleanup = calls(transaction, "_remove_local_observability_stage")
    if len(cleanup) != 2:
        raise CandidateError("0.8.5+ bundle stage cleanup is not total")

    forbidden = {
        "os.replace",
        "os.rename",
        "os.unlink",
        "os.remove",
        "shutil.rmtree",
    }
    if any(_ast_call_name(call) in forbidden for call in ast.walk(transaction) if isinstance(call, ast.Call)):
        raise CandidateError("0.8.5+ bundle transaction bypasses reviewed publication primitives")


def _validate_hard_cut_bundle_transaction(source: str) -> None:
    """Require durable rollback authority before every 0.8.5+ mutation."""

    # Retain strict mutation coverage for the compact release-test fixture,
    # while validating the path-safe production implementation with its own
    # equally closed contract.
    if "def _stage_local_observability_manifest(" in source:
        _validate_runtime_hard_cut_bundle_transaction(source)
    else:
        _validate_fixture_hard_cut_bundle_transaction(source)


def _canonical_v8_wheel_resources() -> dict[str, bytes]:
    """Load the exact reviewed v8 payloads required in 0.8.5+ wheels."""

    resources: dict[str, bytes] = {}
    try:
        for member_name, source_name in V8_CONFIG_WHEEL_RESOURCES:
            resources[member_name] = (ROOT / source_name).read_bytes()
        for member_name, logical_name in V8_TELEMETRY_WHEEL_RESOURCES:
            resources[member_name] = read_logical_asset(ROOT, logical_name)
    except (OSError, RuntimeAssetError) as exc:
        raise CandidateError("canonical v8 wheel resources are unavailable or malformed") from exc

    for member_name, payload in resources.items():
        if not payload:
            raise CandidateError(f"canonical v8 wheel resource is empty: {member_name}")
        if member_name.endswith(".json"):
            try:
                document = json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CandidateError(
                    f"canonical v8 wheel resource is malformed JSON: {member_name}"
                ) from exc
            if not isinstance(document, dict):
                raise CandidateError(
                    f"canonical v8 wheel resource must be a JSON object: {member_name}"
                )
    return resources


def _is_v8_package_data_member(member_name: str) -> bool:
    parts = PurePosixPath(member_name).parts
    return (
        len(parts) > 2
        and parts[:2] == ("defenseclaw", "_data")
        and any(part == "v8" or part.startswith(("v8_", "v8.")) for part in parts[2:])
    )


def _validate_v8_wheel_resources(
    archive: zipfile.ZipFile,
    member_names: list[str],
) -> None:
    expected = _canonical_v8_wheel_resources()
    observed = {name for name in member_names if _is_v8_package_data_member(name)}
    missing = sorted(set(expected) - observed)
    unexpected = sorted(observed - set(expected))
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing={missing!r}")
        if unexpected:
            details.append(f"unexpected={unexpected!r}")
        raise CandidateError(
            "0.8.5+ candidate wheel v8 runtime resource inventory is invalid: "
            + "; ".join(details)
        )

    for member_name, canonical_payload in expected.items():
        info = archive.getinfo(member_name)
        if info.file_size != len(canonical_payload):
            raise CandidateError(
                f"0.8.5+ candidate wheel v8 runtime resource is altered: {member_name}"
            )
        try:
            candidate_payload = archive.read(member_name)
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise CandidateError(
                f"0.8.5+ candidate wheel v8 runtime resource is unreadable: {member_name}"
            ) from exc
        if candidate_payload != canonical_payload:
            raise CandidateError(
                f"0.8.5+ candidate wheel v8 runtime resource is altered: {member_name}"
            )


def _validate_wheel(path: Path, version: str) -> None:
    metadata_name = f"defenseclaw-{version}.dist-info/METADATA"
    try:
        wheel_source: Path | io.BytesIO
        wheel_source = io.BytesIO(_protected_payload(path)) if path.suffix == ".dcwheel" else path
        with zipfile.ZipFile(wheel_source) as archive:
            member_names = archive.namelist()
            names = set(member_names)
            if len(names) != len(member_names):
                raise CandidateError("candidate wheel contains duplicate member names")
            bytecode = [
                name
                for name in names
                if "/__pycache__/" in name or name.endswith((".pyc", ".pyo"))
            ]
            if bytecode:
                raise CandidateError(f"candidate wheel contains Python bytecode: {bytecode[:3]!r}")
            if metadata_name not in names:
                raise CandidateError(f"candidate wheel is missing {metadata_name}")
            metadata = archive.read(metadata_name).decode("utf-8", errors="strict")
            controller_source = archive.read("defenseclaw/commands/cmd_upgrade.py").decode(
                "utf-8", errors="strict"
            )
            migrations_source = archive.read("defenseclaw/migrations.py").decode(
                "utf-8", errors="strict"
            )
            mutator_source = ""
            bundle_transaction_source = ""
            install_publish_source = b""
            if tuple(map(int, version.split("."))) >= (0, 8, 4):
                mutator_source = archive.read("defenseclaw/phase_two_mutator.py").decode(
                    "utf-8", errors="strict"
                )
                install_publish_source = archive.read(
                    "defenseclaw/install_publish.py"
                )
            if tuple(map(int, version.split("."))) >= (0, 8, 5):
                _validate_v8_wheel_resources(archive, member_names)
                bundle_transaction_source = archive.read(
                    "defenseclaw/bundle_refresh.py"
                ).decode("utf-8", errors="strict")
    except (KeyError, OSError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
        raise CandidateError(f"invalid candidate wheel {path}: {exc}") from exc
    if f"\nVersion: {version}\n" not in f"\n{metadata}":
        raise CandidateError(f"candidate wheel metadata does not report version {version}")
    try:
        tree = ast.parse(controller_source, filename="defenseclaw/commands/cmd_upgrade.py")
    except (SyntaxError, ValueError) as exc:
        raise CandidateError("candidate wheel upgrade controller is invalid") from exc
    protocol_values: list[int] = []
    for node in tree.body:
        value: ast.AST | None = None
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "_UPGRADE_PROTOCOL_VERSION"
            for target in node.targets
        ):
            value = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "_UPGRADE_PROTOCOL_VERSION"
        ):
            value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, int) and not isinstance(
            value.value, bool
        ):
            protocol_values.append(value.value)
    if len(protocol_values) != 1 or protocol_values[0] < 1:
        raise CandidateError("candidate wheel must declare one positive upgrade protocol")
    manifest = _read_json_object(path.parent / "upgrade-manifest.json", "upgrade manifest")
    migration_versions = _wheel_migration_versions(migrations_source)
    if version == "0.8.4":
        v8_members = sorted(
            name
            for name in names
            if any(
                part == "v8" or part.startswith(("v8_", "v8."))
                for part in PurePosixPath(name).parts
            )
        )
        if v8_members:
            raise CandidateError(
                f"0.8.4 bridge wheel contains v8 runtime resources: {v8_members[:3]!r}"
            )
        if any(tuple(map(int, item.split("."))) > (0, 8, 4) for item in migration_versions):
            raise CandidateError("0.8.4 bridge wheel contains a post-bridge migration")
    candidate_key = tuple(map(int, version.split(".")))
    required_migration_versions = [
        item for item in migration_versions if tuple(map(int, item.split("."))) <= candidate_key
    ]
    if required_migration_versions != manifest.get("required_cli_migrations"):
        raise CandidateError("candidate wheel migration registry does not match its manifest")
    if manifest.get("controller_upgrade_protocol", 1) != protocol_values[0]:
        raise CandidateError("sealed wheel controller protocol does not match its upgrade manifest")
    if tuple(map(int, version.split("."))) >= (0, 8, 4) and protocol_values[0] < 2:
        raise CandidateError("0.8.4+ candidate wheel must ship the protocol-2 bridge controller")
    if tuple(map(int, version.split("."))) >= (0, 8, 4):
        expected_install_publish_source = (
            ROOT / "cli" / "defenseclaw" / "install_publish.py"
        ).read_bytes()
        if install_publish_source != expected_install_publish_source:
            raise CandidateError(
                "0.8.4+ candidate wheel does not contain the exact reviewed install publisher"
            )
        _validate_phase_two_mutator_wrapper(mutator_source)
        if tuple(map(int, version.split("."))) >= (0, 8, 5):
            _validate_hard_cut_bundle_transaction(bundle_transaction_source)
        functions = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for name in (
            "_require_release_owned_hard_cut_handoff",
            "_acquire_bridge_rollback_artifacts",
            "_prepare_hard_cut_rollback_plan",
            "_write_hard_cut_recovery_journal",
            "_recover_interrupted_hard_cut",
            "_run_phase_two_mutator",
            "_execute_hard_cut_rollback",
            "_poll_health",
        ):
            if name not in functions:
                raise CandidateError(f"0.8.4+ controller lacks required bridge capability {name}")
        entrypoints = [
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "upgrade"
        ]
        if len(entrypoints) != 1:
            raise CandidateError("0.8.4+ controller must define one upgrade entrypoint")
        controller_calls = _upgrade_controller_calls(entrypoints[0])
        direct_guard_first_calls = _direct_hard_cut_guard_first_calls(entrypoints[0])
        handoff_calls = [
            (line, guarded)
            for name, line, guarded in controller_calls
            if name == "_require_release_owned_hard_cut_handoff"
        ]
        acquisition_calls = [
            (line, guarded)
            for name, line, guarded in controller_calls
            if name == "_acquire_bridge_rollback_artifacts"
        ]
        if (
            len(handoff_calls) != 1
            or not handoff_calls[0][1]
            or (
                "_require_release_owned_hard_cut_handoff",
                handoff_calls[0][0],
            )
            not in direct_guard_first_calls
        ):
            raise CandidateError(
                "0.8.4+ controller must invoke the release-owned handoff gate once "
                "inside the bridge-to-hard-cut path"
            )
        if (
            len(acquisition_calls) != 1
            or not acquisition_calls[0][1]
            or (
                "_acquire_bridge_rollback_artifacts",
                acquisition_calls[0][0],
            )
            not in direct_guard_first_calls
        ):
            raise CandidateError(
                "0.8.4+ controller must acquire bridge rollback artifacts once "
                "inside the bridge-to-hard-cut path"
            )
        protected_calls = [
            (name, line)
            for name, line, _guarded in controller_calls
            if name
            in {
                "_acquire_bridge_rollback_artifacts",
                "_create_backup",
                "_prepare_hard_cut_rollback_plan",
            }
        ]
        if {name for name, _line in protected_calls} != {
            "_acquire_bridge_rollback_artifacts",
            "_create_backup",
            "_prepare_hard_cut_rollback_plan",
        }:
            raise CandidateError(
                "0.8.4+ controller lacks required bridge acquisition or backup calls"
            )
        handoff_line = handoff_calls[0][0]
        if any(line <= handoff_line for _name, line in protected_calls):
            raise CandidateError(
                "0.8.4+ controller must enforce the release-owned handoff before "
                "bridge artifact acquisition or backup"
            )
        assignments = {
            target.id: node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        if assignments.get("_STAGED_BRIDGE_ARTIFACT_DIR_ENV") != (
            "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR"
        ):
            raise CandidateError("0.8.4+ controller lacks the authenticated bridge handoff contract")
        if candidate_key >= (0, 8, 5) and assignments.get(
            "_STAGED_TARGET_CONTROLLER_VERSION_ENV"
        ) != "DEFENSECLAW_STAGED_TARGET_CONTROLLER_VERSION":
            raise CandidateError(
                "0.8.5+ controller lacks the authenticated target-controller handoff contract"
            )


def _safe_archive_member_path(name: str, archive_name: str) -> PurePosixPath:
    if not name or "\\" in name:
        raise CandidateError(f"unsafe member in gateway archive {archive_name}: {name!r}")
    member_path = PurePosixPath(name)
    if (
        member_path.is_absolute()
        or str(member_path) != name
        or any(part in {"", ".", ".."} or ":" in part for part in member_path.parts)
    ):
        raise CandidateError(f"unsafe member in gateway archive {archive_name}: {name!r}")
    return member_path


def _validate_gateway_binary(
    payload: bytes,
    *,
    os_name: str,
    arch: str,
    version: str,
    commit: str | None,
    archive_name: str,
) -> None:
    if not payload or len(payload) > MAX_GATEWAY_BINARY_BYTES:
        raise CandidateError(f"gateway binary size is invalid in {archive_name}")

    expected_machine: int
    observed_machine: int
    if os_name == "linux":
        if len(payload) < 64 or payload[:4] != b"\x7fELF" or payload[4:6] != b"\x02\x01":
            raise CandidateError(f"gateway in {archive_name} is not a 64-bit little-endian ELF")
        observed_machine = struct.unpack_from("<H", payload, 18)[0]
        expected_machine = {"amd64": 62, "arm64": 183}[arch]
    elif os_name == "darwin":
        if len(payload) < 32 or payload[:4] != b"\xcf\xfa\xed\xfe":
            raise CandidateError(f"gateway in {archive_name} is not a 64-bit Mach-O")
        observed_machine = struct.unpack_from("<I", payload, 4)[0]
        expected_machine = {"amd64": 0x01000007, "arm64": 0x0100000C}[arch]
    elif os_name == "windows":
        if len(payload) < 64 or payload[:2] != b"MZ":
            raise CandidateError(f"gateway in {archive_name} is not a PE executable")
        pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
        if pe_offset > len(payload) - 6 or payload[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise CandidateError(f"gateway in {archive_name} has an invalid PE header")
        observed_machine = struct.unpack_from("<H", payload, pe_offset + 4)[0]
        expected_machine = {"amd64": 0x8664, "arm64": 0xAA64}[arch]
    else:  # pragma: no cover - every caller iterates the fixed platform map
        raise CandidateError(f"unsupported gateway operating system: {os_name}")

    if observed_machine != expected_machine:
        raise CandidateError(
            f"gateway architecture mismatch in {archive_name}: "
            f"got 0x{observed_machine:x}, want {os_name}/{arch}"
        )

    version_pattern = (
        rb"(?<![0-9.])" + re.escape(version.encode("ascii")) + rb"(?![0-9.])"
    )
    if re.search(version_pattern, payload) is None:
        raise CandidateError(f"gateway in {archive_name} does not embed release version {version}")
    if commit is not None and commit.encode("ascii") not in payload:
        raise CandidateError(f"gateway in {archive_name} does not embed release commit {commit}")


def _validate_windows_gateway_zip_payload(
    payload: bytes,
    *,
    version: str,
    arch: str,
    commit: str | None,
    archive_name: str,
) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            seen: set[PurePosixPath] = set()
            gateway_payloads: list[bytes] = []
            for member in archive.infolist():
                raw_name = member.filename[:-1] if member.is_dir() else member.filename
                member_path = _safe_archive_member_path(raw_name, archive_name)
                if member_path in seen:
                    raise CandidateError(f"duplicate member in gateway archive {archive_name}: {member.filename}")
                seen.add(member_path)
                unix_mode = (member.external_attr >> 16) & 0xFFFF
                file_kind = stat.S_IFMT(unix_mode)
                if file_kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise CandidateError(f"non-regular member in gateway archive {archive_name}: {member.filename}")
                if member.is_dir():
                    continue
                if member.flag_bits & 0x1:
                    raise CandidateError(f"encrypted member in gateway archive {archive_name}: {member.filename}")
                if member_path != PurePosixPath("defenseclaw.exe"):
                    continue
                if member.file_size <= 0 or member.file_size > MAX_GATEWAY_BINARY_BYTES:
                    raise CandidateError(f"gateway binary size is invalid in {archive_name}")
                gateway_payloads.append(archive.read(member))
    except CandidateError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise CandidateError(f"invalid gateway archive {archive_name}: {exc}") from exc
    if len(gateway_payloads) != 1:
        raise CandidateError(f"gateway archive {archive_name} must contain exactly one root defenseclaw.exe binary")
    _validate_gateway_binary(
        gateway_payloads[0],
        os_name="windows",
        arch=arch,
        version=version,
        commit=commit,
        archive_name=archive_name,
    )


def _validate_gateway_archives(
    directory: Path,
    version: str,
    *,
    commit: str | None = None,
) -> None:
    artifacts = _expected_release_artifacts(version)
    for os_name in ("darwin", "linux"):
        for arch in ("amd64", "arm64"):
            path = directory / artifacts["gateways"][os_name][arch]
            try:
                with tarfile.open(fileobj=io.BytesIO(_protected_payload(path)), mode="r:gz") as archive:
                    seen: set[PurePosixPath] = set()
                    gateway_payloads: list[bytes] = []
                    for member in archive.getmembers():
                        raw_name = (
                            member.name[:-1]
                            if member.isdir() and member.name.endswith("/")
                            else member.name
                        )
                        member_path = _safe_archive_member_path(raw_name, path.name)
                        if member_path in seen:
                            raise CandidateError(
                                f"duplicate member in gateway archive {path.name}: {member.name}"
                            )
                        seen.add(member_path)
                        if member.isdir():
                            continue
                        if not member.isfile():
                            raise CandidateError(
                                f"non-regular member in gateway archive {path.name}: {member.name}"
                            )
                        if member_path != PurePosixPath("defenseclaw"):
                            continue
                        if member.size <= 0 or member.size > MAX_GATEWAY_BINARY_BYTES:
                            raise CandidateError(f"gateway binary size is invalid in {path.name}")
                        stream = archive.extractfile(member)
                        if stream is None:
                            raise CandidateError(f"gateway binary could not be read from {path.name}")
                        gateway_payloads.append(stream.read(MAX_GATEWAY_BINARY_BYTES + 1))
            except CandidateError:
                raise
            except (OSError, tarfile.TarError) as exc:
                raise CandidateError(f"invalid gateway archive {path}: {exc}") from exc
            if len(gateway_payloads) != 1:
                raise CandidateError(
                    f"gateway archive {path.name} must contain exactly one root defenseclaw binary"
                )
            _validate_gateway_binary(
                gateway_payloads[0],
                os_name=os_name,
                arch=arch,
                version=version,
                commit=commit,
                archive_name=path.name,
            )

    for arch in ("amd64", "arm64"):
        path = directory / artifacts["gateways"]["windows"][arch]
        _validate_windows_gateway_zip_payload(
            _protected_payload(path),
            version=version,
            arch=arch,
            commit=commit,
            archive_name=path.name,
        )


def _refusal_envelope_payload(version: str) -> bytes:
    if version == "0.8.4":
        boundary = (
            "DefenseClaw 0.8.4 must be installed by the release-owned staged upgrade resolver.\n"
        )
    else:
        boundary = f"DefenseClaw {version} requires the 0.8.4 upgrade bridge.\n"
    return (
        boundary
        + "No changes were made. Run the release-owned upgrade resolver without a version.\n"
    ).encode("utf-8")


def _validate_legacy_refusal_envelopes(directory: Path, version: str) -> None:
    expected_plain = _refusal_envelope_payload(version)
    for os_name in ("darwin", "linux"):
        for arch in ("amd64", "arm64"):
            path = directory / f"defenseclaw_{version}_{os_name}_{arch}.tar.gz"
            if path.read_bytes() != expected_plain:
                raise CandidateError(f"legacy gateway refusal envelope changed: {path.name}")
            try:
                with tarfile.open(path, mode="r:gz"):
                    pass
            except tarfile.TarError:
                pass
            else:
                raise CandidateError(f"legacy gateway refusal envelope became installable: {path.name}")
    for arch in ("amd64", "arm64"):
        path = directory / f"defenseclaw_{version}_windows_{arch}.zip"
        if path.read_bytes() != expected_plain or zipfile.is_zipfile(path):
            raise CandidateError(f"legacy Windows gateway refusal envelope is installable: {path.name}")
    wheel = directory / f"defenseclaw-{version}-py3-none-any.whl"
    if wheel.read_bytes() != expected_plain or zipfile.is_zipfile(wheel):
        raise CandidateError("legacy wheel refusal envelope is installable")


def prepare_runtime(directory: Path, version: str) -> None:
    """Replace canonical modern artifacts with deterministic refusal envelopes."""

    _validate_version(version)
    if tuple(map(int, version.split("."))) < (0, 8, 4):
        raise CandidateError("protected runtime preparation requires a schema-2 release")
    _validate_upgrade_manifest(directory / "upgrade-manifest.json", version)
    protected = _expected_release_artifacts(version)

    payload_moves: list[tuple[Path, Path]] = []
    metadata_moves: list[tuple[Path, Path]] = []
    for os_name in ("darwin", "linux", "windows"):
        extension = "zip" if os_name == "windows" else "tar.gz"
        for arch in ("amd64", "arm64"):
            canonical = directory / f"defenseclaw_{version}_{os_name}_{arch}.{extension}"
            destination = directory / protected["gateways"][os_name][arch]
            payload_moves.append((canonical, destination))
            metadata_moves.append(
                (
                    directory / f"{canonical.name}.sbom.json",
                    directory / f"{destination.name}.sbom.json",
                )
            )
    canonical_wheel = directory / f"defenseclaw-{version}-py3-none-any.whl"
    protected_wheel = directory / protected["wheel"]
    payload_moves.append((canonical_wheel, protected_wheel))

    for source, destination in (*payload_moves, *metadata_moves):
        if source.is_symlink() or not source.is_file():
            raise CandidateError(f"runtime preparation source is missing: {source.name}")
        if destination.exists() or destination.is_symlink():
            raise CandidateError(f"protected runtime artifact already exists: {destination.name}")
    for source, destination in payload_moves:
        _write_protected_artifact(source, destination)
    for source, destination in metadata_moves:
        source.replace(destination)

    plain_payload = _refusal_envelope_payload(version)
    for os_name in ("darwin", "linux"):
        for arch in ("amd64", "arm64"):
            (directory / f"defenseclaw_{version}_{os_name}_{arch}.tar.gz").write_bytes(
                plain_payload
            )
    for arch in ("amd64", "arm64"):
        (directory / f"defenseclaw_{version}_windows_{arch}.zip").write_bytes(
            plain_payload
        )
    canonical_wheel.write_bytes(plain_payload)
    _validate_legacy_refusal_envelopes(directory, version)
    checksum_lines = [
        f"{_sha256(directory / name)}  {name}" for name in runtime_asset_names(version)
    ]
    (directory / RUNTIME_ATTESTATION_FILENAME).write_text(
        "\n".join(checksum_lines) + "\n",
        encoding="utf-8",
    )


def verify_runtime(directory: Path, version: str) -> None:
    names = runtime_asset_names(version)
    _require_regular_files(directory, names, "runtime artifact")
    _validate_upgrade_manifest(directory / "upgrade-manifest.json", version)
    artifacts = _expected_release_artifacts(version)
    _validate_wheel(directory / artifacts["wheel"], version)
    _validate_gateway_archives(directory, version)
    if tuple(map(int, version.split("."))) >= (0, 8, 4):
        _validate_legacy_refusal_envelopes(directory, version)
        runtime_checksums = _parse_checksums(directory / RUNTIME_ATTESTATION_FILENAME)
        expected_runtime_checksums = {
            name: _sha256(directory / name) for name in runtime_asset_names(version)
        }
        if runtime_checksums != expected_runtime_checksums:
            raise CandidateError("runtime checksums do not cover the exact protected candidate")
    for name in names:
        if not name.endswith(".sbom.json"):
            continue
        try:
            document = json.loads((directory / name).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CandidateError(f"invalid SBOM {name}: {exc}") from exc
        if not isinstance(document, dict):
            raise CandidateError(f"SBOM {name} must contain a JSON object")


def stage_runtime(release_dir: Path, output_dir: Path, version: str) -> None:
    """Copy only publishable runtime inputs out of GoReleaser's work directory."""

    verify_runtime(release_dir, version)
    if output_dir.exists():
        raise CandidateError(f"runtime staging output already exists: {output_dir}")
    output_dir.mkdir(parents=True)
    _copy_exact(release_dir, output_dir, runtime_asset_names(version))
    notes = release_dir / "CHANGELOG.md"
    if notes.is_file() and not notes.is_symlink():
        shutil.copy2(notes, output_dir / "CHANGELOG.md")
    if tuple(map(int, version.split("."))) >= (0, 8, 4):
        shutil.copy2(
            release_dir / RUNTIME_ATTESTATION_FILENAME,
            output_dir / RUNTIME_ATTESTATION_FILENAME,
        )


def extract_gateway(release_dir: Path, output: Path, version: str, os_name: str, arch: str) -> None:
    """Safely extract one POSIX gateway from a verified candidate archive."""

    if os_name not in {"darwin", "linux"} or arch not in {"amd64", "arm64"}:
        raise CandidateError("gateway extraction supports darwin/linux and amd64/arm64")
    verify_runtime(release_dir, version)
    archive_path = release_dir / _expected_release_artifacts(version)["gateways"][os_name][arch]
    try:
        with tarfile.open(
            fileobj=io.BytesIO(_protected_payload(archive_path)), mode="r:gz"
        ) as archive:
            matches = []
            for member in archive.getmembers():
                member_path = PurePosixPath(member.name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise CandidateError(f"unsafe gateway archive member: {member.name}")
                if member_path.name == "defenseclaw" and member.isfile():
                    matches.append(member)
            if len(matches) != 1:
                raise CandidateError(f"gateway archive must contain exactly one gateway, got {len(matches)}")
            stream = archive.extractfile(matches[0])
            if stream is None:
                raise CandidateError("gateway archive member could not be read")
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.exists() or output.is_symlink():
                raise CandidateError(f"gateway extraction output already exists: {output}")
            with output.open("xb") as handle:
                shutil.copyfileobj(stream, handle)
    except CandidateError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise CandidateError(f"could not extract candidate gateway: {exc}") from exc
    output.chmod(0o755)


def _write_exclusive_file(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    owned = False
    try:
        with path.open("xb") as handle:
            owned = True
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(mode)
    except OSError as exc:
        if owned:
            try:
                path.unlink()
            except OSError:
                pass
        raise CandidateError(f"could not publish extracted installer input {path.name}: {exc}") from exc


def extract_windows_installer_inputs(
    release_dir: Path,
    output_dir: Path,
    version: str,
) -> None:
    """Decode only authenticated Windows x64 Setup inputs into a new private dir."""

    _validate_version(version)
    if tuple(map(int, version.split("."))) < WINDOWS_SETUP_START_VERSION:
        raise CandidateError("native Windows Setup input extraction starts with release 0.8.6")
    if output_dir.exists() or output_dir.is_symlink():
        raise CandidateError(f"Windows installer input output already exists: {output_dir}")

    verify_runtime(release_dir, version)
    attestation = _parse_checksums(release_dir / RUNTIME_ATTESTATION_FILENAME)
    artifacts = _expected_release_artifacts(version)
    protected_gateway_name = artifacts["gateways"]["windows"]["amd64"]
    protected_wheel_name = artifacts["wheel"]

    def protected_payload(name: str) -> bytes:
        source = release_dir / name
        expected = attestation.get(name)
        before = _sha256(source)
        if expected != before:
            raise CandidateError(f"runtime attestation changed before extracting {name}")
        payload = _protected_payload(source)
        if _sha256(source) != before:
            raise CandidateError(f"protected runtime input changed while extracting {name}")
        return payload

    manifest_source = release_dir / "upgrade-manifest.json"
    manifest_expected = attestation.get(manifest_source.name)
    manifest_before = _sha256(manifest_source)
    if manifest_expected != manifest_before:
        raise CandidateError("runtime attestation changed before extracting upgrade-manifest.json")
    try:
        manifest_payload = manifest_source.read_bytes()
    except OSError as exc:
        raise CandidateError(f"could not read verified upgrade manifest: {exc}") from exc
    if _sha256(manifest_source) != manifest_before:
        raise CandidateError("upgrade-manifest.json changed while being extracted")

    gateway_payload = protected_payload(protected_gateway_name)
    wheel_payload = protected_payload(protected_wheel_name)
    gateway_name = f"defenseclaw_{version}_windows_amd64.zip"
    wheel_name = f"defenseclaw-{version}-py3-none-any.whl"
    created: list[Path] = []
    try:
        try:
            output_dir.mkdir(parents=True, mode=0o700)
            output_dir.chmod(0o700)
        except OSError as exc:
            raise CandidateError(
                f"could not create private Windows installer input directory: {exc}"
            ) from exc
        for name, payload in (
            (gateway_name, gateway_payload),
            (wheel_name, wheel_payload),
            ("upgrade-manifest.json", manifest_payload),
        ):
            destination = output_dir / name
            _write_exclusive_file(destination, payload)
            created.append(destination)
        if _strict_file_names(output_dir, "Windows installer input") != tuple(
            sorted((gateway_name, wheel_name, "upgrade-manifest.json"))
        ):
            raise CandidateError("Windows installer input contains an unexpected file set")
        _validate_upgrade_manifest(output_dir / "upgrade-manifest.json", version)
        _validate_windows_gateway_zip_payload(
            gateway_payload,
            version=version,
            arch="amd64",
            commit=None,
            archive_name=gateway_name,
        )
        _validate_wheel(output_dir / wheel_name, version)
    except Exception:
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        try:
            output_dir.rmdir()
        except OSError:
            pass
        raise


def _copy_exact(source: Path, destination: Path, names: tuple[str, ...]) -> None:
    for name in names:
        shutil.copy2(source / name, destination / name)


def _canonical_json(document: Any) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _release_identity_documents(
    version: str,
    commit: str,
    *,
    source_tree: str | None,
    bridge_commit: str | None,
    bridge_tree: str | None,
    bridge_checksums_sha256: str | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    fields = {
        "source_tree": source_tree,
        "bridge_commit": bridge_commit,
        "bridge_tree": bridge_tree,
        "bridge_checksums_sha256": bridge_checksums_sha256,
    }
    if tuple(map(int, version.split("."))) < (0, 8, 5):
        supplied = sorted(name for name, value in fields.items() if value is not None)
        if supplied:
            raise CandidateError(
                f"release {version} forbids hard-cut provenance fields: {supplied!r}"
            )
        return None, None

    missing = sorted(name for name, value in fields.items() if value is None)
    if missing:
        raise CandidateError(
            f"release {version} requires hard-cut provenance fields: {missing!r}"
        )
    for name in ("source_tree", "bridge_commit", "bridge_tree"):
        value = fields[name]
        if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
            raise CandidateError(f"{name} must be a full lowercase SHA-1, got {value!r}")
    if not isinstance(bridge_checksums_sha256, str) or not SHA256_RE.fullmatch(
        bridge_checksums_sha256
    ):
        raise CandidateError(
            "bridge_checksums_sha256 must be a full lowercase SHA-256, "
            f"got {bridge_checksums_sha256!r}"
        )

    identity = _reviewed_source_install_identity(version)
    bridge = {
        "version": "0.8.4",
        "commit": bridge_commit,
        "tree": bridge_tree,
        "checksums_sha256": bridge_checksums_sha256,
    }
    source_map = {
        "schema_version": RELEASE_SOURCE_MAP_SCHEMA_VERSION,
        "release_version": version,
        "source_commit": commit,
        "source_tree": source_tree,
        "policy_mode": "same_as_release_source",
        "policy_commit": commit,
        "policy_tree": source_tree,
        "source_install_identity": identity,
        "bridge": bridge,
    }
    source_map_sha256 = hashlib.sha256(
        _canonical_json(source_map).encode("utf-8")
    ).hexdigest()
    provenance = {
        "schema_version": RELEASE_PROVENANCE_SCHEMA_VERSION,
        "release_version": version,
        "source_commit": commit,
        "source_tree": source_tree,
        "policy_commit": commit,
        "policy_tree": source_tree,
        "release_source_map_sha256": source_map_sha256,
        "source_install_identity": identity,
        "bridge": bridge,
    }
    return source_map, provenance


def _validate_release_identity(
    dist: Path,
    version: str,
    commit: str,
) -> dict[str, Any] | None:
    source_map_path = dist / RELEASE_SOURCE_MAP_FILENAME
    provenance_path = dist / RELEASE_PROVENANCE_FILENAME
    if tuple(map(int, version.split("."))) < (0, 8, 5):
        for path in (source_map_path, provenance_path):
            if path.exists() or path.is_symlink():
                raise CandidateError(f"release {version} must not contain {path.name}")
        return None

    source_map = _read_json_object(source_map_path, "release source map")
    provenance = _read_json_object(provenance_path, "release provenance")
    expected_map_keys = {
        "schema_version",
        "release_version",
        "source_commit",
        "source_tree",
        "policy_mode",
        "policy_commit",
        "policy_tree",
        "source_install_identity",
        "bridge",
    }
    expected_provenance_keys = {
        "schema_version",
        "release_version",
        "source_commit",
        "source_tree",
        "policy_commit",
        "policy_tree",
        "release_source_map_sha256",
        "source_install_identity",
        "bridge",
    }
    identity_keys = {
        "schema_version",
        "source_release",
        "source_install_compatibility_epoch",
        "runtime_config_version",
    }
    bridge_keys = {"version", "commit", "tree", "checksums_sha256"}
    if set(source_map) != expected_map_keys:
        raise CandidateError("release source map does not use the closed schema-1 field set")
    if set(provenance) != expected_provenance_keys:
        raise CandidateError("release provenance does not use the closed schema-1 field set")
    if source_map.get("schema_version") != RELEASE_SOURCE_MAP_SCHEMA_VERSION:
        raise CandidateError("release source map schema_version mismatch")
    if provenance.get("schema_version") != RELEASE_PROVENANCE_SCHEMA_VERSION:
        raise CandidateError("release provenance schema_version mismatch")
    if source_map.get("release_version") != version or provenance.get("release_version") != version:
        raise CandidateError("release identity version mismatch")
    if source_map.get("source_commit") != commit or provenance.get("source_commit") != commit:
        raise CandidateError("release identity source_commit mismatch")
    if source_map.get("policy_mode") != "same_as_release_source":
        raise CandidateError("release source map policy_mode mismatch")

    for document, label in ((source_map, "release source map"), (provenance, "release provenance")):
        identity = document.get("source_install_identity")
        bridge = document.get("bridge")
        if not isinstance(identity, dict) or set(identity) != identity_keys:
            raise CandidateError(f"{label} source identity is not closed")
        if not isinstance(bridge, dict) or set(bridge) != bridge_keys:
            raise CandidateError(f"{label} bridge identity is not closed")
        if identity != _reviewed_source_install_identity(version):
            raise CandidateError(f"{label} source-install identity mismatch")
        if bridge.get("version") != "0.8.4":
            raise CandidateError(f"{label} bridge version mismatch")
        for name in ("source_commit", "source_tree", "policy_commit", "policy_tree"):
            value = document.get(name)
            if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
                raise CandidateError(f"{label} {name} is not a canonical lowercase SHA-1")
        for name in ("commit", "tree"):
            value = bridge.get(name)
            if not isinstance(value, str) or not COMMIT_RE.fullmatch(value):
                raise CandidateError(f"{label} bridge {name} is not a canonical lowercase SHA-1")
        digest = bridge.get("checksums_sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise CandidateError(f"{label} bridge checksums digest is not canonical")
        if document.get("policy_commit") != document.get("source_commit"):
            raise CandidateError(f"{label} policy commit must equal its release source")
        if document.get("policy_tree") != document.get("source_tree"):
            raise CandidateError(f"{label} policy tree must equal its release source")

    shared = (
        "release_version",
        "source_commit",
        "source_tree",
        "policy_commit",
        "policy_tree",
        "source_install_identity",
        "bridge",
    )
    if any(source_map.get(name) != provenance.get(name) for name in shared):
        raise CandidateError("release source map and provenance identities differ")

    try:
        source_map_bytes = source_map_path.read_bytes()
        provenance_text = provenance_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise CandidateError(f"could not read release identity assets: {exc}") from exc
    if source_map_bytes != _canonical_json(source_map).encode("utf-8"):
        raise CandidateError("release source map JSON is not canonical or changed")
    if provenance_text != _canonical_json(provenance):
        raise CandidateError("release provenance JSON is not canonical or changed")
    if provenance.get("release_source_map_sha256") != hashlib.sha256(
        source_map_bytes
    ).hexdigest():
        raise CandidateError("release provenance does not authenticate its source map")
    return provenance


def _validate_windows_setup_pe(path: Path) -> str:
    try:
        size = path.stat().st_size
        if not 0 < size <= MAX_WINDOWS_SETUP_BYTES:
            raise CandidateError("Windows Setup executable size is invalid")
        payload = path.read_bytes()
    except OSError as exc:
        raise CandidateError(f"could not read Windows Setup executable: {exc}") from exc
    if len(payload) != size or len(payload) < 0x100 or payload[:2] != b"MZ":
        raise CandidateError("Windows Setup is not a complete PE executable")
    pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
    if pe_offset > len(payload) - 24 or payload[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise CandidateError("Windows Setup has an invalid PE header")
    machine = struct.unpack_from("<H", payload, pe_offset + 4)[0]
    optional_size = struct.unpack_from("<H", payload, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    if machine != 0x8664:
        raise CandidateError("Windows Setup is not an x64 PE executable")
    if optional_size < 152 or optional_offset + optional_size > len(payload):
        raise CandidateError("Windows Setup has a truncated PE32+ optional header")
    if struct.unpack_from("<H", payload, optional_offset)[0] != 0x20B:
        raise CandidateError("Windows Setup is not a PE32+ executable")
    if struct.unpack_from("<H", payload, optional_offset + 68)[0] != 2:
        raise CandidateError("Windows Setup is not a Windows GUI executable")
    directory_count = struct.unpack_from("<I", payload, optional_offset + 108)[0]
    if directory_count < 5:
        raise CandidateError("Windows Setup lacks an Authenticode certificate directory")
    certificate_offset, certificate_size = struct.unpack_from("<II", payload, optional_offset + 112 + 4 * 8)
    if certificate_offset <= 0 or certificate_size < 8 or certificate_offset > len(payload) - certificate_size:
        raise CandidateError("Windows Setup lacks a complete embedded Authenticode signature")
    return hashlib.sha256(payload).hexdigest()


def _require_object_fields(
    value: object,
    expected: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise CandidateError(f"{label} does not use its closed field set")
    return value


def _read_windows_setup_json(path: Path, label: str) -> dict[str, Any]:
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or not 0 < info.st_size <= MAX_WINDOWS_SETUP_METADATA_BYTES
        ):
            raise CandidateError(f"{label} has an invalid file type or size")
        payload = path.read_bytes()
        if len(payload) != info.st_size:
            raise CandidateError(f"{label} changed while being read")
        document = json.loads(payload.decode("utf-8", errors="strict"))
    except CandidateError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"invalid {label} {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise CandidateError(f"{label} must contain a JSON object")
    return document


def _require_sha256_fields(
    document: dict[str, Any],
    fields: tuple[str, ...],
    label: str,
) -> None:
    for field in fields:
        value = document.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise CandidateError(f"{label} {field} is not a lowercase SHA-256 digest")


def _validate_windows_setup_provenance(
    path: Path,
    *,
    version: str,
    commit: str,
    setup_sha256: str,
) -> dict[str, Any]:
    document = _read_windows_setup_json(path, "Windows Setup provenance")
    _require_object_fields(
        document,
        {
            "schema_version",
            "artifact",
            "artifact_sha256",
            "version",
            "source_commit",
            "distribution_flavor",
            "built_at_utc",
            "unsigned",
            "authenticode",
            "inputs",
            "toolchain",
        },
        "Windows Setup provenance",
    )
    if (
        document.get("schema_version") != 1
        or document.get("artifact") != WINDOWS_SETUP_ASSET
        or document.get("artifact_sha256") != setup_sha256
        or document.get("version") != version
        or document.get("source_commit") != commit
        or document.get("distribution_flavor") != "oss"
        or document.get("unsigned") is not False
    ):
        raise CandidateError("Windows Setup provenance release identity mismatch")
    built_at = document.get("built_at_utc")
    if not isinstance(built_at, str) or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", built_at) is None:
        raise CandidateError("Windows Setup provenance build timestamp is invalid")
    inputs = _require_object_fields(
        document.get("inputs"),
        {
            "gateway_archive",
            "gateway_archive_sha256",
            "embedded_gateway_archive_sha256",
            "embedded_payload_sha256",
            "product_executables_authenticode_signed",
            "wheel",
            "wheel_sha256",
            "python_embed",
            "python_embed_sha256",
            "site_packages_sha256",
            "yara_compat_wheel",
            "yara_compat_wheel_sha256",
            "cosign_sha256",
            "payload_manifest_sha256",
            "go_component_inventory_sha256",
            "payload_files",
            "windows_resource_policy",
            "windows_resource_icon",
            "windows_resource_icon_sha256",
        },
        "Windows Setup provenance inputs",
    )
    _require_sha256_fields(
        inputs,
        (
            "gateway_archive_sha256",
            "embedded_gateway_archive_sha256",
            "embedded_payload_sha256",
            "wheel_sha256",
            "python_embed_sha256",
            "site_packages_sha256",
            "yara_compat_wheel_sha256",
            "cosign_sha256",
            "payload_manifest_sha256",
            "go_component_inventory_sha256",
            "windows_resource_icon_sha256",
        ),
        "Windows Setup provenance input",
    )
    gateway_archive = f"defenseclaw_{version}_windows_amd64.zip"
    wheel = f"defenseclaw-{version}-py3-none-any.whl"
    if (
        inputs.get("gateway_archive") != gateway_archive
        or inputs.get("wheel") != wheel
        or inputs.get("python_embed") != WINDOWS_PYTHON_EMBED_NAME
        or inputs.get("python_embed_sha256") != WINDOWS_PYTHON_EMBED_SHA256
        or inputs.get("yara_compat_wheel") != WINDOWS_YARA_COMPAT_WHEEL
        or inputs.get("cosign_sha256") != WINDOWS_COSIGN_SHA256
        or inputs.get("product_executables_authenticode_signed") is not True
        or inputs.get("windows_resource_policy") != WINDOWS_RESOURCE_POLICY
        or inputs.get("windows_resource_icon") != WINDOWS_RESOURCE_ICON
        or inputs.get("windows_resource_icon_sha256") != WINDOWS_RESOURCE_ICON_SHA256
    ):
        raise CandidateError("Windows Setup provenance input identity or reviewed pin mismatch")
    payload_files = _require_object_fields(
        inputs.get("payload_files"),
        {
            gateway_archive,
            wheel,
            WINDOWS_PYTHON_EMBED_NAME,
            WINDOWS_YARA_COMPAT_WHEEL,
            "site-packages.zip",
            "defenseclaw-launcher.exe",
            "defenseclaw-startup.exe",
            "cosign.exe",
            "requirements-release.txt",
            "upgrade-manifest.json",
        },
        "Windows Setup provenance payload files",
    )
    _require_sha256_fields(
        payload_files,
        tuple(sorted(payload_files)),
        "Windows Setup provenance payload file",
    )
    payload_bindings = {
        gateway_archive: "embedded_gateway_archive_sha256",
        wheel: "wheel_sha256",
        WINDOWS_PYTHON_EMBED_NAME: "python_embed_sha256",
        WINDOWS_YARA_COMPAT_WHEEL: "yara_compat_wheel_sha256",
        "site-packages.zip": "site_packages_sha256",
        "cosign.exe": "cosign_sha256",
    }
    if any(payload_files[name] != inputs[field] for name, field in payload_bindings.items()):
        raise CandidateError("Windows Setup provenance payload digests are inconsistent")

    toolchain = _require_object_fields(
        document.get("toolchain"),
        {
            "go",
            "uv",
            "python_embed_url",
            "python_embed_sha256",
            "python_runtime_review_deadline_utc",
            "yara_compat_sha256",
            "win_unicode_console_source_url",
            "win_unicode_console_source_sha256",
            "cosign_version",
            "cosign_url",
            "cosign_sha256",
        },
        "Windows Setup provenance toolchain",
    )
    if (
        not isinstance(toolchain.get("go"), str)
        or re.fullmatch(r"go version go[0-9]+\.[0-9]+(?:\.[0-9]+)? windows/amd64", toolchain["go"])
        is None
        or not isinstance(toolchain.get("uv"), str)
        or re.fullmatch(r"uv [0-9]+\.[0-9]+\.[0-9]+(?: .*)?", toolchain["uv"]) is None
        or toolchain.get("python_embed_url") != WINDOWS_PYTHON_EMBED_URL
        or toolchain.get("python_embed_sha256") != WINDOWS_PYTHON_EMBED_SHA256
        or toolchain.get("python_embed_sha256") != inputs.get("python_embed_sha256")
        or toolchain.get("python_runtime_review_deadline_utc")
        != WINDOWS_PYTHON_RUNTIME_REVIEW_DEADLINE
        or toolchain.get("yara_compat_sha256") != inputs.get("yara_compat_wheel_sha256")
        or toolchain.get("win_unicode_console_source_url") != WINDOWS_WIN_UNICODE_SOURCE_URL
        or toolchain.get("win_unicode_console_source_sha256") != WINDOWS_WIN_UNICODE_SOURCE_SHA256
        or toolchain.get("cosign_version") != WINDOWS_COSIGN_VERSION
        or toolchain.get("cosign_url") != WINDOWS_COSIGN_URL
        or toolchain.get("cosign_sha256") != WINDOWS_COSIGN_SHA256
        or toolchain.get("cosign_sha256") != inputs.get("cosign_sha256")
    ):
        raise CandidateError("Windows Setup provenance toolchain identity or reviewed pin mismatch")

    authenticode = _require_object_fields(
        document.get("authenticode"),
        {"schema_version", "files"},
        "Windows Setup Authenticode inventory",
    )
    files = authenticode.get("files")
    if authenticode.get("schema_version") != 1 or not isinstance(files, dict):
        raise CandidateError("Windows Setup Authenticode inventory is invalid")
    evidence = _require_object_fields(
        files.get(WINDOWS_SETUP_ASSET),
        {
            "schema_version",
            "installed_path",
            "sbom_file_name",
            "sha256",
            "expected",
            "observed",
        },
        "Windows Setup Authenticode evidence",
    )
    if (
        evidence.get("schema_version") != 1
        or evidence.get("installed_path") != WINDOWS_SETUP_ASSET
        or evidence.get("sbom_file_name") != f"./{WINDOWS_SETUP_ASSET}"
        or evidence.get("sha256") != setup_sha256
    ):
        raise CandidateError("Windows Setup Authenticode evidence digest mismatch")
    expected = _require_object_fields(
        evidence.get("expected"),
        {
            "policy",
            "status",
            "publisher",
            "signature_type",
            "platform_identity_required",
            "timestamp_required",
            "signer_thumbprint_sha256",
            "timestamp_signer_thumbprint_sha256",
            "timestamp_token_sha256",
        },
        "Windows Setup expected Authenticode policy",
    )
    if (
        expected.get("policy") != "defenseclaw-product-publisher"
        or expected.get("status") != "Valid"
        or expected.get("publisher") != WINDOWS_SETUP_PUBLISHER
        or expected.get("signature_type") != "Authenticode"
        or expected.get("platform_identity_required") is not True
        or expected.get("timestamp_required") is not True
    ):
        raise CandidateError("Windows Setup does not require Cisco Authenticode and RFC3161")
    for field in (
        "signer_thumbprint_sha256",
        "timestamp_signer_thumbprint_sha256",
        "timestamp_token_sha256",
    ):
        if not isinstance(expected.get(field), str) or SHA256_RE.fullmatch(expected[field]) is None:
            raise CandidateError(f"Windows Setup Authenticode {field} is invalid")

    observed = _require_object_fields(
        evidence.get("observed"),
        {
            "status",
            "publisher",
            "signature_type",
            "signer",
            "chain",
            "timestamp",
            "embedded_signatures",
        },
        "Windows Setup observed Authenticode evidence",
    )
    if (
        observed.get("status") != "Valid"
        or observed.get("publisher") != WINDOWS_SETUP_PUBLISHER
        or observed.get("signature_type") != "Authenticode"
    ):
        raise CandidateError("Windows Setup observed Authenticode identity is invalid")
    signer = observed.get("signer")
    timestamp = observed.get("timestamp")
    if not isinstance(signer, dict) or signer.get("thumbprint_sha256") != expected.get("signer_thumbprint_sha256"):
        raise CandidateError("Windows Setup Authenticode signer identity is inconsistent")
    if (
        not isinstance(timestamp, dict)
        or timestamp.get("present") is not True
        or timestamp.get("format") != "rfc3161"
        or timestamp.get("token_sha256") != expected.get("timestamp_token_sha256")
        or not isinstance(timestamp.get("signing_time_utc"), str)
        or not timestamp.get("signing_time_utc")
    ):
        raise CandidateError("Windows Setup RFC3161 timestamp evidence is invalid")
    timestamp_certificate = timestamp.get("certificate")
    if not isinstance(timestamp_certificate, dict) or timestamp_certificate.get("thumbprint_sha256") != expected.get(
        "timestamp_signer_thumbprint_sha256"
    ):
        raise CandidateError("Windows Setup RFC3161 signer identity is inconsistent")
    embedded = observed.get("embedded_signatures")
    if not isinstance(embedded, list) or len(embedded) != 1:
        raise CandidateError("Windows Setup must contain exactly one embedded Authenticode signature")
    embedded_signature = embedded[0]
    if not isinstance(embedded_signature, dict) or embedded_signature.get("publisher") != WINDOWS_SETUP_PUBLISHER:
        raise CandidateError("Windows Setup embedded Authenticode publisher is invalid")
    embedded_signer = embedded_signature.get("signer")
    embedded_timestamp = embedded_signature.get("timestamp")
    if (
        not isinstance(embedded_signer, dict)
        or embedded_signer.get("thumbprint_sha256") != expected.get("signer_thumbprint_sha256")
        or not isinstance(embedded_timestamp, dict)
        or embedded_timestamp.get("present") is not True
        or embedded_timestamp.get("format") != "rfc3161"
        or embedded_timestamp.get("token_sha256") != expected.get("timestamp_token_sha256")
    ):
        raise CandidateError("Windows Setup embedded Authenticode timestamp identity is invalid")
    return document


def _validate_windows_setup_runtime_inputs(
    provenance: dict[str, Any],
    runtime_directory: Path,
    version: str,
) -> None:
    """Bind installer provenance to the exact protected runtime candidate bytes."""

    artifacts = _expected_release_artifacts(version)
    gateway_path = runtime_directory / artifacts["gateways"]["windows"]["amd64"]
    wheel_path = runtime_directory / artifacts["wheel"]
    manifest_path = runtime_directory / "upgrade-manifest.json"
    inputs = provenance["inputs"]
    try:
        gateway_sha256 = hashlib.sha256(_protected_payload(gateway_path)).hexdigest()
        wheel_sha256 = hashlib.sha256(_protected_payload(wheel_path)).hexdigest()
        manifest_sha256 = _sha256(manifest_path)
    except (KeyError, OSError) as exc:
        raise CandidateError(f"could not bind Windows Setup to runtime inputs: {exc}") from exc
    if (
        gateway_sha256 != inputs["gateway_archive_sha256"]
        or wheel_sha256 != inputs["wheel_sha256"]
        or manifest_sha256 != inputs["payload_files"]["upgrade-manifest.json"]
    ):
        raise CandidateError("Windows Setup provenance does not bind the exact runtime candidate")


def _spdx_sha256(element: dict[str, Any], label: str) -> str:
    checksums = element.get("checksums")
    matches = (
        [
            row.get("checksumValue")
            for row in checksums
            if isinstance(row, dict) and row.get("algorithm") == "SHA256"
        ]
        if isinstance(checksums, list)
        else []
    )
    if (
        len(matches) != 1
        or not isinstance(matches[0], str)
        or SHA256_RE.fullmatch(matches[0]) is None
    ):
        raise CandidateError(f"{label} does not contain exactly one lowercase SHA-256 digest")
    return matches[0]


def _validate_windows_setup_sbom(
    path: Path,
    *,
    version: str,
    commit: str,
    setup_sha256: str,
    provenance: dict[str, Any],
) -> None:
    document = _read_windows_setup_json(path, "Windows Setup SBOM")
    _require_object_fields(
        document,
        {
            "spdxVersion",
            "dataLicense",
            "SPDXID",
            "name",
            "documentNamespace",
            "comment",
            "creationInfo",
            "documentDescribes",
            "packages",
            "files",
            "relationships",
        },
        "Windows Setup SBOM",
    )
    expected_namespace = f"https://github.com/cisco-ai-defense/defenseclaw/spdx/windows/{version}/{setup_sha256}"
    if (
        document.get("spdxVersion") != "SPDX-2.3"
        or document.get("dataLicense") != "CC0-1.0"
        or document.get("SPDXID") != "SPDXRef-DOCUMENT"
        or document.get("name") != f"{WINDOWS_SETUP_ASSET}-{version}"
        or document.get("documentNamespace") != expected_namespace
        or document.get("comment") != f"DefenseClaw source commit: {commit}"
    ):
        raise CandidateError("Windows Setup SBOM document identity is invalid")
    creation_info = _require_object_fields(
        document.get("creationInfo"),
        {"created", "creators", "licenseListVersion"},
        "Windows Setup SBOM creationInfo",
    )
    created = creation_info.get("created")
    if (
        not isinstance(created, str)
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", created) is None
        or creation_info.get("creators")
        != [
            "Organization: Cisco Systems, Inc.",
            "Tool: DefenseClaw Windows installer SBOM generator",
        ]
        or creation_info.get("licenseListVersion") != "3.25"
    ):
        raise CandidateError("Windows Setup SBOM creation identity is invalid")
    packages = document.get("packages")
    files = document.get("files")
    relationships = document.get("relationships")
    if not all(isinstance(value, list) for value in (packages, files, relationships)):
        raise CandidateError("Windows Setup SBOM inventory is invalid")

    identifiers: set[str] = {"SPDXRef-DOCUMENT"}
    for element in [*packages, *files]:
        if not isinstance(element, dict):
            raise CandidateError("Windows Setup SBOM contains a non-object element")
        identifier = element.get("SPDXID")
        if (
            not isinstance(identifier, str)
            or not identifier.startswith("SPDXRef-")
            or identifier in identifiers
        ):
            raise CandidateError("Windows Setup SBOM contains a duplicate or invalid SPDXID")
        identifiers.add(identifier)

    relationship_rows: set[tuple[str, str, str]] = set()
    for relationship in relationships:
        if not isinstance(relationship, dict) or set(relationship) != {
            "spdxElementId",
            "relationshipType",
            "relatedSpdxElement",
        }:
            raise CandidateError("Windows Setup SBOM contains an invalid relationship row")
        row = (
            relationship.get("spdxElementId"),
            relationship.get("relationshipType"),
            relationship.get("relatedSpdxElement"),
        )
        if (
            not all(isinstance(item, str) and item for item in row)
            or row[0] not in identifiers
            or row[2] not in identifiers
            or row in relationship_rows
        ):
            raise CandidateError("Windows Setup SBOM relationships are invalid")
        relationship_rows.add(row)
    setup_packages = [
        item for item in packages if isinstance(item, dict) and item.get("name") == "DefenseClaw Windows Setup"
    ]
    if len(setup_packages) != 1:
        raise CandidateError("Windows Setup SBOM must contain exactly one Setup package")
    package = setup_packages[0]
    package_id = package.get("SPDXID")
    if (
        not isinstance(package_id, str)
        or package.get("versionInfo") != version
        or package.get("packageFileName") != WINDOWS_SETUP_ASSET
    ):
        raise CandidateError("Windows Setup SBOM package identity is invalid")
    if _spdx_sha256(package, "Windows Setup SBOM package") != setup_sha256:
        raise CandidateError("Windows Setup SBOM package digest is invalid")
    expected_purl = f"pkg:github/cisco-ai-defense/defenseclaw@{version}"
    refs = package.get("externalRefs")
    if (
        not isinstance(refs, list)
        or sum(
            isinstance(item, dict)
            and item.get("referenceCategory") == "PACKAGE-MANAGER"
            and item.get("referenceType") == "purl"
            and item.get("referenceLocator") == expected_purl
            for item in refs
        )
        != 1
    ):
        raise CandidateError("Windows Setup SBOM source package identity is invalid")
    setup_files = [
        item for item in files if isinstance(item, dict) and item.get("fileName") == f"./{WINDOWS_SETUP_ASSET}"
    ]
    if len(setup_files) != 1:
        raise CandidateError("Windows Setup SBOM must contain exactly one Setup file")
    setup_file = setup_files[0]
    file_id = setup_file.get("SPDXID")
    if not isinstance(file_id, str) or _spdx_sha256(setup_file, "Windows Setup SBOM file") != setup_sha256:
        raise CandidateError("Windows Setup SBOM file digest is invalid")
    if document.get("documentDescribes") != [package_id]:
        raise CandidateError("Windows Setup SBOM documentDescribes is invalid")
    required_relationships: set[tuple[str, str, str]] = {
        ("SPDXRef-DOCUMENT", "DESCRIBES", package_id),
        (package_id, "CONTAINS", file_id),
    }

    embedded_packages = [
        item
        for item in packages
        if isinstance(item, dict) and item.get("name") == "DefenseClaw embedded installer payload"
    ]
    if len(embedded_packages) != 1:
        raise CandidateError("Windows Setup SBOM must contain exactly one embedded payload package")
    embedded_package = embedded_packages[0]
    embedded_package_id = embedded_package.get("SPDXID")
    embedded_sha256 = provenance["inputs"]["embedded_payload_sha256"]
    if (
        not isinstance(embedded_package_id, str)
        or embedded_package.get("versionInfo") != version
        or embedded_package.get("packageFileName") != "installer-payload.zip"
        or _spdx_sha256(embedded_package, "Windows Setup embedded payload package") != embedded_sha256
    ):
        raise CandidateError("Windows Setup SBOM embedded payload package is invalid")
    embedded_files = [
        item
        for item in files
        if isinstance(item, dict) and item.get("fileName") == "./embedded/installer-payload.zip"
    ]
    if len(embedded_files) != 1:
        raise CandidateError("Windows Setup SBOM must contain exactly one embedded payload file")
    embedded_file = embedded_files[0]
    embedded_file_id = embedded_file.get("SPDXID")
    if (
        not isinstance(embedded_file_id, str)
        or _spdx_sha256(embedded_file, "Windows Setup embedded payload file") != embedded_sha256
    ):
        raise CandidateError("Windows Setup SBOM embedded payload file is invalid")
    required_relationships.update(
        {
            (embedded_package_id, "CONTAINS", embedded_file_id),
            (package_id, "CONTAINS", embedded_package_id),
        }
    )

    expected_payload = dict(provenance["inputs"]["payload_files"])
    expected_payload["manifest.json"] = provenance["inputs"]["payload_manifest_sha256"]
    for name, digest in expected_payload.items():
        component_packages = [
            item for item in packages if isinstance(item, dict) and item.get("packageFileName") == name
        ]
        component_files = [
            item for item in files if isinstance(item, dict) and item.get("fileName") == f"./payload/{name}"
        ]
        if len(component_packages) != 1 or len(component_files) != 1:
            raise CandidateError(f"Windows Setup SBOM payload inventory is incomplete for {name}")
        component_package = component_packages[0]
        component_file = component_files[0]
        component_package_id = component_package.get("SPDXID")
        component_file_id = component_file.get("SPDXID")
        if (
            not isinstance(component_package_id, str)
            or not isinstance(component_file_id, str)
            or _spdx_sha256(component_package, f"Windows Setup SBOM package {name}") != digest
            or _spdx_sha256(component_file, f"Windows Setup SBOM file {name}") != digest
        ):
            raise CandidateError(f"Windows Setup SBOM payload digest is invalid for {name}")
        required_relationships.update(
            {
                (component_package_id, "CONTAINS", component_file_id),
                (embedded_package_id, "CONTAINS", component_package_id),
            }
        )
    if not required_relationships.issubset(relationship_rows):
        raise CandidateError("Windows Setup SBOM custody relationships are incomplete")


def _validate_windows_setup_certification(
    path: Path,
    *,
    version: str,
    commit: str,
    setup_sha256: str,
) -> None:
    document = _read_windows_setup_json(path, "Windows Setup certification")
    _require_object_fields(
        document,
        {
            "schema_version",
            "status",
            "platform",
            "setup",
            "clients",
            "connectors",
            "requirements",
            "source_commit",
            "release_version",
            "staging_artifact_digest",
            "run_url",
        },
        "Windows Setup certification",
    )
    setup = document.get("setup")
    if (
        document.get("schema_version") != 1
        or document.get("status") != "passed"
        or document.get("platform") != "windows-x64"
        or setup
        != {
            "name": WINDOWS_SETUP_ASSET,
            "sha256": setup_sha256,
            "publisher": WINDOWS_SETUP_PUBLISHER,
        }
        or document.get("clients") != WINDOWS_SETUP_CLIENTS
        or document.get("connectors") != ["codex", "claudecode"]
        or document.get("requirements") != list(WINDOWS_SETUP_CERTIFICATION_REQUIREMENTS)
        or document.get("source_commit") != commit
        or document.get("release_version") != version
    ):
        raise CandidateError("Windows Setup certification identity or required evidence mismatch")
    staging_digest = document.get("staging_artifact_digest")
    if not isinstance(staging_digest, str) or re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", staging_digest) is None:
        raise CandidateError("Windows Setup certification staging digest is invalid")
    run_url = document.get("run_url")
    if (
        not isinstance(run_url, str)
        or re.fullmatch(
            r"https://github\.com/cisco-ai-defense/defenseclaw/actions/runs/[1-9][0-9]*",
            run_url,
        )
        is None
    ):
        raise CandidateError("Windows Setup certification run URL is invalid")


def _validate_windows_installer_assets(
    directory: Path,
    version: str,
    commit: str,
    *,
    exact_file_set: bool = False,
    runtime_directory: Path | None = None,
) -> None:
    names = windows_installer_asset_names(version)
    if not names:
        return
    _require_regular_files(directory, names, "Windows installer artifact")
    if exact_file_set and _strict_file_names(directory, "Windows installer artifact") != names:
        raise CandidateError("Windows installer artifact directory must contain exactly five files")
    setup_path = directory / WINDOWS_SETUP_ASSET
    setup_sha256 = _validate_windows_setup_pe(setup_path)
    sidecar = directory / f"{WINDOWS_SETUP_ASSET}.sha256"
    try:
        sidecar_payload = sidecar.read_bytes()
    except OSError as exc:
        raise CandidateError(f"could not read Windows Setup SHA-256 sidecar: {exc}") from exc
    match = re.fullmatch(
        rb"([0-9a-f]{64})  DefenseClawSetup-x64\.exe(?:\r\n|\n)",
        sidecar_payload,
    )
    if match is None or match.group(1).decode("ascii") != setup_sha256:
        raise CandidateError("Windows Setup SHA-256 sidecar does not bind the exact executable")
    provenance = _validate_windows_setup_provenance(
        directory / f"{WINDOWS_SETUP_ASSET}.provenance.json",
        version=version,
        commit=commit,
        setup_sha256=setup_sha256,
    )
    if runtime_directory is not None:
        _validate_windows_setup_runtime_inputs(provenance, runtime_directory, version)
    _validate_windows_setup_sbom(
        directory / f"{WINDOWS_SETUP_ASSET}.sbom.json",
        version=version,
        commit=commit,
        setup_sha256=setup_sha256,
        provenance=provenance,
    )
    _validate_windows_setup_certification(
        directory / f"{WINDOWS_SETUP_ASSET}.certification.json",
        version=version,
        commit=commit,
        setup_sha256=setup_sha256,
    )
def _validated_effective_upgrade_baselines(root: Path, version: str) -> str:
    path = root / EFFECTIVE_UPGRADE_BASELINES_FILENAME
    before = _read_bounded_regular_file(
        path,
        label="effective upgrade-baseline policy",
        max_bytes=MAX_EFFECTIVE_UPGRADE_BASELINES_BYTES,
    )
    _load_upgrade_baseline_policy(version, path)
    after = _read_bounded_regular_file(
        path,
        label="effective upgrade-baseline policy",
        max_bytes=MAX_EFFECTIVE_UPGRADE_BASELINES_BYTES,
    )
    if before != after:
        raise CandidateError("effective upgrade-baseline policy changed during validation")
    return hashlib.sha256(after).hexdigest()


def assemble(
    runtime_dir: Path,
    macos_dir: Path,
    root: Path,
    version: str,
    commit: str,
    macos_verification_status: str,
    *,
    windows_dir: Path | None = None,
    source_tree: str | None = None,
    bridge_commit: str | None = None,
    bridge_tree: str | None = None,
    bridge_checksums_sha256: str | None = None,
    baseline_policy_path: Path | None = None,
) -> None:
    _validate_version(version)
    _validate_commit(commit)
    macos_verification_status = _validate_macos_verification_status(
        macos_verification_status
    )
    source_map, provenance = _release_identity_documents(
        version,
        commit,
        source_tree=source_tree,
        bridge_commit=bridge_commit,
        bridge_tree=bridge_tree,
        bridge_checksums_sha256=bridge_checksums_sha256,
    )
    if root.exists():
        raise CandidateError(f"candidate output already exists: {root}")

    windows_names = windows_installer_asset_names(version)
    if windows_names:
        if windows_dir is None:
            raise CandidateError(f"release {version} requires --windows-dir")
        _validate_windows_installer_assets(
            windows_dir,
            version,
            commit,
            exact_file_set=True,
        )
    elif windows_dir is not None:
        raise CandidateError(f"release {version} forbids native Windows Setup artifacts")

    verify_runtime(runtime_dir, version)
    _validate_gateway_archives(runtime_dir, version, commit=commit)
    macos_names = macos_asset_names(version, macos_verification_status)
    _require_regular_files(macos_dir, macos_names, "macOS artifact")
    actual_macos_names = _strict_file_names(macos_dir, "macOS artifact")
    if actual_macos_names != tuple(sorted(macos_names)):
        raise CandidateError(
            "macOS artifact directory does not match its verification status: "
            f"got {actual_macos_names!r}, want {tuple(sorted(macos_names))!r}"
        )

    dist = root / "dist"
    dist.mkdir(parents=True)
    policy_source = baseline_policy_path or UPGRADE_BASELINES_PATH
    policy_payload = _read_bounded_regular_file(
        policy_source,
        label="effective upgrade-baseline policy",
        max_bytes=MAX_EFFECTIVE_UPGRADE_BASELINES_BYTES,
    )
    effective_policy = root / EFFECTIVE_UPGRADE_BASELINES_FILENAME
    effective_policy.write_bytes(policy_payload)
    effective_policy_sha256 = _validated_effective_upgrade_baselines(root, version)
    _copy_exact(runtime_dir, dist, runtime_asset_names(version))
    _copy_exact(macos_dir, dist, macos_names)
    if windows_dir is not None:
        _copy_exact(windows_dir, dist, windows_names)
        _validate_windows_installer_assets(
            dist,
            version,
            commit,
            runtime_directory=dist,
        )
    _copy_resolver_assets(dist, version)
    _validate_resolver_assets(dist, version)
    if source_map is not None and provenance is not None:
        (dist / RELEASE_SOURCE_MAP_FILENAME).write_bytes(
            _canonical_json(source_map).encode("utf-8"),
        )
        (dist / RELEASE_PROVENANCE_FILENAME).write_bytes(
            _canonical_json(provenance).encode("utf-8"),
        )

    notes = runtime_dir / "CHANGELOG.md"
    if notes.is_file() and not notes.is_symlink():
        shutil.copy2(notes, root / "RELEASE_NOTES.md")

    checksum_lines = [
        f"{_sha256(dist / name)}  {name}"
        for name in payload_asset_names(version, macos_verification_status)
    ]
    (dist / "checksums.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    metadata = {
        "schema_version": SCHEMA_VERSION,
        "release_version": version,
        "commit": commit,
        "macos_verification_status": macos_verification_status,
        "source_install_identity": _reviewed_source_install_identity(version),
        "effective_upgrade_baselines_sha256": effective_policy_sha256,
    }
    (root / "candidate-metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _parse_checksums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise CandidateError(f"could not read {path}: {exc}") from exc
    for line_number, line in enumerate(lines, start=1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if not match:
            raise CandidateError(f"invalid checksums.txt line {line_number}: {line!r}")
        digest, name = match.groups()
        if name in entries:
            raise CandidateError(f"duplicate checksums.txt entry: {name}")
        entries[name] = digest
    return entries


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"invalid {label} {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise CandidateError(f"{label} must contain a JSON object")
    return document


def _legacy_bundle_base64(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise CandidateError(f"legacy Cosign bundle {label} must be non-empty base64")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise CandidateError(f"legacy Cosign bundle {label} is invalid base64") from exc
    if not decoded or base64.b64encode(decoded) != encoded:
        raise CandidateError(f"legacy Cosign bundle {label} is noncanonical base64")
    return decoded


def _validate_legacy_cosign_bundle(path: Path) -> None:
    """Validate Cosign 2.6.2 bundle framing; workflow Cosign verifies its cryptography."""

    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or not 0 < info.st_size <= MAX_LEGACY_COSIGN_BUNDLE_BYTES
        ):
            raise CandidateError("legacy Cosign bundle has an invalid file type or size")
        payload = path.read_bytes()
        if len(payload) != info.st_size:
            raise CandidateError("legacy Cosign bundle changed while being read")
        document = json.loads(payload.decode("utf-8", errors="strict"))
    except CandidateError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"invalid legacy Cosign bundle {path}: {exc}") from exc
    bundle = _require_object_fields(
        document,
        {"base64Signature", "cert", "rekorBundle"},
        "legacy Cosign bundle",
    )
    _legacy_bundle_base64(bundle.get("base64Signature"), "base64Signature")
    certificate = bundle.get("cert")
    if not isinstance(certificate, str):
        raise CandidateError("legacy Cosign bundle cert must be a certificate string")
    try:
        _release_certificate_payload(certificate.encode("ascii"), allow_base64_wrapper=True)
    except (UnicodeEncodeError, CandidateError) as exc:
        raise CandidateError("legacy Cosign bundle cert is not a canonical certificate") from exc

    rekor = _require_object_fields(
        bundle.get("rekorBundle"),
        {"SignedEntryTimestamp", "Payload"},
        "legacy Cosign Rekor bundle",
    )
    _legacy_bundle_base64(rekor.get("SignedEntryTimestamp"), "SignedEntryTimestamp")
    rekor_payload = _require_object_fields(
        rekor.get("Payload"),
        {"body", "integratedTime", "logIndex", "logID"},
        "legacy Cosign Rekor payload",
    )
    _legacy_bundle_base64(rekor_payload.get("body"), "Rekor body")
    for field in ("integratedTime", "logIndex"):
        value = rekor_payload.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise CandidateError(f"legacy Cosign Rekor {field} must be a nonnegative integer")
    log_id = rekor_payload.get("logID")
    if not isinstance(log_id, str) or SHA256_RE.fullmatch(log_id) is None:
        raise CandidateError("legacy Cosign Rekor logID must be a lowercase SHA-256 digest")


def seal(root: Path, version: str, commit: str) -> None:
    _validate_version(version)
    _validate_commit(commit)
    metadata = _read_json_object(root / "candidate-metadata.json", "candidate metadata")
    macos_verification_status = _validate_macos_verification_status(
        metadata.get("macos_verification_status")
    )
    effective_policy_sha256 = _validated_effective_upgrade_baselines(root, version)
    expected_metadata = {
        "schema_version": SCHEMA_VERSION,
        "release_version": version,
        "commit": commit,
        "macos_verification_status": macos_verification_status,
        "source_install_identity": _reviewed_source_install_identity(version),
        "effective_upgrade_baselines_sha256": effective_policy_sha256,
    }
    if metadata != expected_metadata:
        raise CandidateError(f"candidate metadata mismatch: got {metadata!r}")

    dist = root / "dist"
    _validate_release_identity(dist, version, commit)
    _validate_windows_installer_assets(
        dist,
        version,
        commit,
        runtime_directory=dist,
    )
    names = published_asset_names(version, macos_verification_status)
    _require_regular_files(dist, names, "release candidate")
    actual_names = _strict_file_names(dist, "release candidate")
    if actual_names != names:
        raise CandidateError(
            "release candidate contains an unexpected file set: "
            f"got {actual_names!r}, want {names!r}"
        )
    _require_canonical_release_certificate(dist / "checksums.txt.pem")
    if tuple(map(int, version.split("."))) >= WINDOWS_SETUP_START_VERSION:
        _validate_legacy_cosign_bundle(dist / CHECKSUMS_BUNDLE_FILENAME)

    checksums = _parse_checksums(dist / "checksums.txt")
    payload_names = payload_asset_names(version, macos_verification_status)
    if tuple(sorted(checksums)) != payload_names:
        raise CandidateError("checksums.txt does not cover the exact publish payload")
    for name, expected in checksums.items():
        actual = _sha256(dist / name)
        if actual != expected:
            raise CandidateError(f"checksum mismatch for {name}: got {actual}, want {expected}")
    _validate_resolver_assets(dist, version)

    assets = [{"name": name, "sha256": _sha256(dist / name)} for name in names]
    manifest: dict[str, Any] = {
        **expected_metadata,
        "assets": assets,
        "checksums_sha256": _sha256(dist / "checksums.txt"),
    }
    notes = root / "RELEASE_NOTES.md"
    if notes.is_file() and not notes.is_symlink():
        manifest["release_notes_sha256"] = _sha256(notes)
    (root / "release-candidate.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def verify(root: Path, version: str, commit: str) -> None:
    _validate_version(version)
    _validate_commit(commit)
    manifest = _read_json_object(root / "release-candidate.json", "release candidate manifest")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise CandidateError("release candidate schema_version mismatch")
    if manifest.get("release_version") != version:
        raise CandidateError("release candidate version mismatch")
    if manifest.get("commit") != commit:
        raise CandidateError("release candidate commit mismatch")
    macos_verification_status = _validate_macos_verification_status(
        manifest.get("macos_verification_status")
    )
    if manifest.get("source_install_identity") != _reviewed_source_install_identity(version):
        raise CandidateError("release candidate source-install identity mismatch")
    effective_policy_sha256 = _validated_effective_upgrade_baselines(root, version)
    if manifest.get("effective_upgrade_baselines_sha256") != effective_policy_sha256:
        raise CandidateError("effective upgrade-baseline policy digest mismatch")

    dist = root / "dist"
    _validate_release_identity(dist, version, commit)
    _validate_windows_installer_assets(
        dist,
        version,
        commit,
        runtime_directory=dist,
    )
    expected_names = published_asset_names(version, macos_verification_status)
    _require_regular_files(dist, expected_names, "release candidate")
    actual_names = _strict_file_names(dist, "release candidate")
    if actual_names != expected_names:
        raise CandidateError("release candidate file set changed after sealing")
    _require_canonical_release_certificate(dist / "checksums.txt.pem")
    if tuple(map(int, version.split("."))) >= WINDOWS_SETUP_START_VERSION:
        _validate_legacy_cosign_bundle(dist / CHECKSUMS_BUNDLE_FILENAME)

    assets = manifest.get("assets")
    if not isinstance(assets, list):
        raise CandidateError("release candidate assets must be a list")
    expected_assets = {name: _sha256(dist / name) for name in expected_names}
    recorded_assets: dict[str, str] = {}
    for item in assets:
        if not isinstance(item, dict) or set(item) != {"name", "sha256"}:
            raise CandidateError(f"invalid release candidate asset row: {item!r}")
        name = item.get("name")
        digest = item.get("sha256")
        if not isinstance(name, str) or name in recorded_assets:
            raise CandidateError(f"invalid or duplicate asset name: {name!r}")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise CandidateError(f"invalid asset digest for {name!r}")
        recorded_assets[name] = digest
    if recorded_assets != expected_assets:
        raise CandidateError("release candidate asset digests changed after sealing")
    if manifest.get("checksums_sha256") != expected_assets["checksums.txt"]:
        raise CandidateError("release candidate checksums digest mismatch")

    notes = root / "RELEASE_NOTES.md"
    recorded_notes = manifest.get("release_notes_sha256")
    if notes.exists():
        if notes.is_symlink() or not notes.is_file():
            raise CandidateError("release notes must be a regular file")
        if recorded_notes != _sha256(notes):
            raise CandidateError("release notes changed after sealing")
    elif recorded_notes is not None:
        raise CandidateError("sealed release notes are missing")

    checksums = _parse_checksums(dist / "checksums.txt")
    if tuple(sorted(checksums)) != payload_asset_names(
        version, macos_verification_status
    ):
        raise CandidateError("checksums.txt coverage changed after sealing")
    for name, expected in checksums.items():
        if _sha256(dist / name) != expected:
            raise CandidateError(f"published checksum mismatch for {name}")
    _validate_resolver_assets(dist, version)

    _validate_upgrade_manifest(
        dist / "upgrade-manifest.json",
        version,
        baseline_policy_path=root / EFFECTIVE_UPGRADE_BASELINES_FILENAME,
    )
    if tuple(map(int, version.split("."))) >= (0, 8, 4):
        artifacts = _expected_release_artifacts(version)
        _validate_wheel(dist / artifacts["wheel"], version)
        _validate_gateway_archives(dist, version, commit=commit)
        _validate_legacy_refusal_envelopes(dist, version)
    else:
        _validate_wheel(dist / f"defenseclaw-{version}-py3-none-any.whl", version)


def verify_published_release(
    root: Path,
    release_json: Path,
    version: str,
    commit: str,
    *,
    omit_windows_binaries: bool = False,
) -> None:
    """Confirm GitHub exposes the exact sealed bytes after publication."""

    verify(root, version, commit)
    release = _read_json_object(release_json, "published release metadata")
    if release.get("tagName") != version or release.get("isDraft") is not False:
        raise CandidateError("GitHub release tag or draft status does not match the sealed candidate")
    if release.get("isImmutable") is not True:
        raise CandidateError("published GitHub release is not immutable")
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise CandidateError("published release assets must be a list")
    published: dict[str, str] = {}
    for item in assets:
        if not isinstance(item, dict):
            raise CandidateError(f"invalid published asset row: {item!r}")
        name = item.get("name")
        digest = item.get("digest")
        if not isinstance(name, str) or name in published:
            raise CandidateError(f"invalid or duplicate published asset name: {name!r}")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise CandidateError(f"GitHub did not report a SHA-256 digest for {name!r}")
        published[name] = digest.removeprefix("sha256:")

    dist = root / "dist"
    names = _strict_file_names(dist, "release candidate")
    if omit_windows_binaries:
        omitted = set(windows_release_binary_names(version))
        names = tuple(name for name in names if name not in omitted)
    expected = {name: _sha256(dist / name) for name in names}
    if published != expected:
        raise CandidateError("published GitHub asset names or digests differ from the sealed candidate")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_version_parser = subparsers.add_parser("validate-version")
    validate_version_parser.add_argument("--target", required=True)
    validate_version_parser.add_argument("--releases-json", type=Path, required=True)

    verify_runtime_parser = subparsers.add_parser("verify-runtime")
    verify_runtime_parser.add_argument("--release-dir", type=Path, required=True)
    verify_runtime_parser.add_argument("--version", required=True)

    prepare_runtime_parser = subparsers.add_parser("prepare-runtime")
    prepare_runtime_parser.add_argument("--release-dir", type=Path, required=True)
    prepare_runtime_parser.add_argument("--version", required=True)

    stage_runtime_parser = subparsers.add_parser("stage-runtime")
    stage_runtime_parser.add_argument("--release-dir", type=Path, required=True)
    stage_runtime_parser.add_argument("--output-dir", type=Path, required=True)
    stage_runtime_parser.add_argument("--version", required=True)

    stage_resolvers_parser = subparsers.add_parser("stage-resolvers")
    stage_resolvers_parser.add_argument("--release-dir", type=Path, required=True)
    stage_resolvers_parser.add_argument("--version", required=True)

    extract_parser = subparsers.add_parser("extract-gateway")
    extract_parser.add_argument("--release-dir", type=Path, required=True)
    extract_parser.add_argument("--output", type=Path, required=True)
    extract_parser.add_argument("--version", required=True)
    extract_parser.add_argument("--os", choices=("darwin", "linux"), required=True)
    extract_parser.add_argument("--arch", choices=("amd64", "arm64"), required=True)

    extract_windows_parser = subparsers.add_parser("extract-windows-installer-inputs")
    extract_windows_parser.add_argument("--release-dir", type=Path, required=True)
    extract_windows_parser.add_argument("--output-dir", type=Path, required=True)
    extract_windows_parser.add_argument("--version", required=True)

    assemble_parser = subparsers.add_parser("assemble")
    assemble_parser.add_argument("--runtime-dir", type=Path, required=True)
    assemble_parser.add_argument("--macos-dir", type=Path, required=True)
    assemble_parser.add_argument("--windows-dir", type=Path)
    assemble_parser.add_argument("--root", type=Path, required=True)
    assemble_parser.add_argument("--version", required=True)
    assemble_parser.add_argument("--commit", required=True)
    assemble_parser.add_argument("--macos-verification-status", required=True)
    assemble_parser.add_argument("--source-tree")
    assemble_parser.add_argument("--bridge-commit")
    assemble_parser.add_argument("--bridge-tree")
    assemble_parser.add_argument("--bridge-checksums-sha256")
    assemble_parser.add_argument("--baseline-policy", type=Path)

    canonicalize_certificate_parser = subparsers.add_parser("canonicalize-certificate")
    canonicalize_certificate_parser.add_argument("--certificate", type=Path, required=True)

    seal_parser = subparsers.add_parser("seal")
    seal_parser.add_argument("--root", type=Path, required=True)
    seal_parser.add_argument("--version", required=True)
    seal_parser.add_argument("--commit", required=True)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", type=Path, required=True)
    verify_parser.add_argument("--version", required=True)
    verify_parser.add_argument("--commit", required=True)

    list_parser = subparsers.add_parser("list-assets")
    list_parser.add_argument("--root", type=Path, required=True)
    list_parser.add_argument("--version", required=True)
    list_parser.add_argument("--commit", required=True)
    list_parser.add_argument("--omit-windows-binaries", action="store_true")

    published_parser = subparsers.add_parser("verify-published")
    published_parser.add_argument("--root", type=Path, required=True)
    published_parser.add_argument("--release-json", type=Path, required=True)
    published_parser.add_argument("--version", required=True)
    published_parser.add_argument("--commit", required=True)
    published_parser.add_argument("--omit-windows-binaries", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate-version":
            reviewed, published = validate_release_progression(
                args.target,
                args.releases_json,
            )
            print(
                "release progression verified: "
                f"target={args.target} reviewed_max={reviewed} published_max={published}"
            )
        elif args.command == "verify-runtime":
            verify_runtime(args.release_dir, args.version)
            print(f"runtime candidate verified: {args.version}")
        elif args.command == "prepare-runtime":
            prepare_runtime(args.release_dir, args.version)
            print(f"protected runtime artifacts prepared: {args.version}")
        elif args.command == "stage-runtime":
            stage_runtime(args.release_dir, args.output_dir, args.version)
            print(f"runtime candidate staged: {args.output_dir}")
        elif args.command == "stage-resolvers":
            stage_resolvers(args.release_dir, args.version)
            print(f"release resolvers staged: {args.version}")
        elif args.command == "extract-gateway":
            extract_gateway(args.release_dir, args.output, args.version, args.os, args.arch)
            print(f"candidate gateway extracted: {args.output}")
        elif args.command == "extract-windows-installer-inputs":
            extract_windows_installer_inputs(args.release_dir, args.output_dir, args.version)
            print(f"Windows installer inputs extracted: {args.output_dir}")
        elif args.command == "assemble":
            assemble(
                args.runtime_dir,
                args.macos_dir,
                args.root,
                args.version,
                args.commit,
                args.macos_verification_status,
                windows_dir=args.windows_dir,
                source_tree=args.source_tree,
                bridge_commit=args.bridge_commit,
                bridge_tree=args.bridge_tree,
                bridge_checksums_sha256=args.bridge_checksums_sha256,
                baseline_policy_path=args.baseline_policy,
            )
            print(f"release candidate assembled: {args.root}")
        elif args.command == "canonicalize-certificate":
            canonicalize_release_certificate(args.certificate)
            print(f"release certificate canonicalized: {args.certificate}")
        elif args.command == "seal":
            seal(args.root, args.version, args.commit)
            print(f"release candidate sealed: {args.version} at {args.commit}")
        elif args.command == "verify":
            verify(args.root, args.version, args.commit)
            print(f"release candidate verified: {args.version} at {args.commit}")
        elif args.command == "list-assets":
            verify(args.root, args.version, args.commit)
            names = _strict_file_names(args.root / "dist", "release candidate")
            if args.omit_windows_binaries:
                omitted = set(windows_release_binary_names(args.version))
                names = tuple(name for name in names if name not in omitted)
            for name in names:
                print(name)
        elif args.command == "verify-published":
            verify_published_release(
                args.root,
                args.release_json,
                args.version,
                args.commit,
                omit_windows_binaries=args.omit_windows_binaries,
            )
            print(f"published release verified: {args.version} at {args.commit}")
        else:  # pragma: no cover - argparse enforces the subcommand set
            raise AssertionError(args.command)
    except CandidateError as exc:
        print(f"release candidate verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
