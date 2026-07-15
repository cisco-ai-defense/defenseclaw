#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Authenticate published baseline artifacts before an upgrade test uses them."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PIN_POLICY = ROOT / "release" / "historical-artifact-digests.json"
REPOSITORY = "cisco-ai-defense/defenseclaw"
CERTIFICATE_IDENTITY = (
    f"https://github.com/{REPOSITORY}/.github/workflows/release.yaml@refs/heads/main"
)
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
ASSET_RE = re.compile(r"^[A-Za-z0-9._-]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_CERTIFICATE_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_CHECKSUM_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_PIN_POLICY_BYTES = 1024 * 1024
MAX_HISTORICAL_ASSET_BYTES = 512 * 1024 * 1024


class HistoricalReleaseAuthError(RuntimeError):
    """A historical artifact could not be tied to reviewed release provenance."""


def _version_key(version: str) -> tuple[int, int, int]:
    return tuple(map(int, version.split(".")))


def _opened_file_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _opened_file_state(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (*_opened_file_identity(metadata), metadata.st_ctime_ns)


def _open_bounded_regular_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
) -> tuple[int, os.stat_result]:
    """Open one bounded regular-file identity without following a leaf symlink."""

    try:
        path_before = path.lstat()
    except OSError as exc:
        raise HistoricalReleaseAuthError(f"{label} could not be opened: {path}") from exc
    if not stat.S_ISREG(path_before.st_mode):
        raise HistoricalReleaseAuthError(f"{label} must be a regular file: {path}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise HistoricalReleaseAuthError(f"{label} could not be opened: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        try:
            path_after = path.lstat()
        except OSError as exc:
            raise HistoricalReleaseAuthError(f"{label} changed while being opened: {path}") from exc
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(path_after.st_mode)
            # CPython on Windows exposes creation time as pathname st_ctime,
            # but NTFS change time as descriptor st_ctime. Bind the pathname
            # to the descriptor without comparing those incompatible fields,
            # then retain ctime in each same-API mutation check.
            or _opened_file_identity(path_before) != _opened_file_identity(opened)
            or _opened_file_identity(path_after) != _opened_file_identity(opened)
            or _opened_file_state(path_before) != _opened_file_state(path_after)
        ):
            raise HistoricalReleaseAuthError(f"{label} changed while being opened: {path}")
        if opened.st_size <= 0 or opened.st_size > max_bytes:
            raise HistoricalReleaseAuthError(f"{label} has an invalid size: {path}")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _assert_open_file_unchanged(
    descriptor: int,
    *,
    expected_metadata: os.stat_result,
    bytes_read: int,
    label: str,
    path: Path,
) -> None:
    metadata = os.fstat(descriptor)
    if (
        _opened_file_state(metadata) != _opened_file_state(expected_metadata)
        or bytes_read != expected_metadata.st_size
    ):
        raise HistoricalReleaseAuthError(f"{label} changed while being read: {path}")


def _read_bounded_regular_file(path: Path, label: str, *, max_bytes: int) -> bytes:
    descriptor, expected_metadata = _open_bounded_regular_file(path, label, max_bytes=max_bytes)
    try:
        chunks: list[bytes] = []
        bytes_read = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - bytes_read))
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            if bytes_read > max_bytes:
                raise HistoricalReleaseAuthError(f"{label} has an invalid size: {path}")
        _assert_open_file_unchanged(
            descriptor,
            expected_metadata=expected_metadata,
            bytes_read=bytes_read,
            label=label,
            path=path,
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_private_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _normalize_certificate_bytes(raw: bytes) -> bytes:
    raw = raw.strip()
    if raw.startswith(b"-----BEGIN CERTIFICATE-----"):
        certificate = raw + b"\n"
    else:
        try:
            certificate = base64.b64decode(b"".join(raw.split()), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HistoricalReleaseAuthError(
                "historical checksums certificate is neither PEM nor base64-encoded PEM"
            ) from exc
        certificate = certificate.strip() + b"\n"
    if len(certificate) > MAX_CERTIFICATE_BYTES:
        raise HistoricalReleaseAuthError("historical checksums certificate is oversized")
    if (
        not certificate.startswith(b"-----BEGIN CERTIFICATE-----\n")
        or not certificate.endswith(b"-----END CERTIFICATE-----\n")
        or certificate.count(b"-----BEGIN CERTIFICATE-----") != 1
        or certificate.count(b"-----END CERTIFICATE-----") != 1
    ):
        raise HistoricalReleaseAuthError("historical checksums certificate is not one PEM certificate")
    return certificate


def normalized_certificate_bytes(path: Path) -> bytes:
    """Return a PEM certificate, decoding the legacy base64-of-PEM format."""

    raw = _read_bounded_regular_file(
        path,
        "Sigstore certificate",
        max_bytes=MAX_CERTIFICATE_BYTES,
    )
    return _normalize_certificate_bytes(raw)


def _parse_signed_checksums(raw: bytes) -> dict[str, str]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise HistoricalReleaseAuthError("historical checksums are not UTF-8") from exc
    checksums: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([0-9A-Fa-f]{64})[ \t]+(.+)", line)
        if match is None:
            raise HistoricalReleaseAuthError(
                f"invalid historical checksums line {line_number}: {line!r}"
            )
        digest, name = match.groups()
        if not name or "\x00" in name or name in checksums:
            raise HistoricalReleaseAuthError(
                f"empty, unsafe, or duplicate historical checksum name: {name!r}"
            )
        checksums[name] = digest.lower()
    if not checksums:
        raise HistoricalReleaseAuthError("historical checksums manifest is empty")
    return checksums


def _load_reviewed_pins(path: Path) -> dict[str, dict[str, str]]:
    raw = _read_bounded_regular_file(
        path,
        "reviewed historical digest policy",
        max_bytes=MAX_PIN_POLICY_BYTES,
    )
    try:
        document: Any = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HistoricalReleaseAuthError("reviewed historical digest policy is invalid") from exc
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "signed_wheel_coverage_starts_at",
        "signed_checksum_exceptions",
    }:
        raise HistoricalReleaseAuthError("reviewed historical digest policy has unexpected fields")
    exceptions = document.get("signed_checksum_exceptions")
    coverage_start = document.get("signed_wheel_coverage_starts_at")
    if (
        document.get("schema_version") != 1
        or not isinstance(coverage_start, str)
        or VERSION_RE.fullmatch(coverage_start) is None
        or not isinstance(exceptions, dict)
    ):
        raise HistoricalReleaseAuthError("reviewed historical digest policy schema is invalid")
    normalized: dict[str, dict[str, str]] = {}
    for version, artifacts in exceptions.items():
        if not isinstance(version, str) or VERSION_RE.fullmatch(version) is None:
            raise HistoricalReleaseAuthError("reviewed historical digest policy has an invalid version")
        if _version_key(version) >= _version_key(coverage_start):
            raise HistoricalReleaseAuthError(
                "reviewed digest exceptions must be older than the signed-wheel "
                f"coverage boundary {coverage_start}"
            )
        if not isinstance(artifacts, dict) or not artifacts:
            raise HistoricalReleaseAuthError(
                f"reviewed historical digest policy has no artifacts for {version}"
            )
        normalized[version] = {}
        expected_name = f"defenseclaw-{version}-py3-none-any.whl"
        if set(artifacts) != {expected_name}:
            raise HistoricalReleaseAuthError(
                f"reviewed digest exception for {version} must cover only {expected_name}"
            )
        for name, digest in artifacts.items():
            if (
                not isinstance(name, str)
                or ASSET_RE.fullmatch(name) is None
                or not isinstance(digest, str)
                or SHA256_RE.fullmatch(digest) is None
            ):
                raise HistoricalReleaseAuthError(
                    f"reviewed historical digest policy has an invalid artifact for {version}"
                )
            normalized[version][name] = digest
    return normalized


def _sha256_bounded_regular_file(path: Path, label: str, *, max_bytes: int) -> str:
    descriptor, expected_metadata = _open_bounded_regular_file(path, label, max_bytes=max_bytes)
    digest = hashlib.sha256()
    bytes_read = 0
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            bytes_read += len(chunk)
            if bytes_read > max_bytes:
                raise HistoricalReleaseAuthError(f"{label} has an invalid size: {path}")
        _assert_open_file_unchanged(
            descriptor,
            expected_metadata=expected_metadata,
            bytes_read=bytes_read,
            label=label,
            path=path,
        )
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def authenticate_release_assets(
    *,
    version: str,
    release_dir: Path,
    assets: list[str],
    cosign: Path,
    pin_policy: Path = DEFAULT_PIN_POLICY,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, str]:
    """Verify the signed checksum manifest, then authenticate every requested asset."""

    if VERSION_RE.fullmatch(version) is None:
        raise HistoricalReleaseAuthError(f"historical version is not canonical: {version!r}")
    if release_dir.is_symlink() or not release_dir.is_dir():
        raise HistoricalReleaseAuthError(f"historical release directory is invalid: {release_dir}")
    if cosign.is_symlink() or not cosign.is_file():
        raise HistoricalReleaseAuthError(f"cosign executable is not a regular file: {cosign}")
    if not assets or len(assets) != len(set(assets)):
        raise HistoricalReleaseAuthError("historical asset request must be non-empty and unique")
    for name in assets:
        if ASSET_RE.fullmatch(name) is None:
            raise HistoricalReleaseAuthError(f"historical asset name is unsafe: {name!r}")

    checksums_path = release_dir / "checksums.txt"
    signature_path = release_dir / "checksums.txt.sig"
    certificate_path = release_dir / "checksums.txt.pem"
    checksums = _read_bounded_regular_file(
        checksums_path,
        "historical checksums",
        max_bytes=MAX_CHECKSUM_MANIFEST_BYTES,
    )
    signature = _read_bounded_regular_file(
        signature_path,
        "historical checksums signature",
        max_bytes=MAX_SIGNATURE_BYTES,
    )
    certificate = normalized_certificate_bytes(certificate_path)
    with tempfile.TemporaryDirectory(prefix="defenseclaw-historical-auth-") as temporary:
        custody = Path(temporary)
        custody.chmod(0o700)
        staged_checksums = custody / "checksums.txt"
        staged_signature = custody / "checksums.txt.sig"
        staged_certificate = custody / "checksums.txt.pem"
        _write_private_file(staged_checksums, checksums)
        _write_private_file(staged_signature, signature)
        _write_private_file(staged_certificate, certificate)
        try:
            completed = runner(
                [
                    str(cosign),
                    "verify-blob",
                    "--certificate",
                    str(staged_certificate),
                    "--signature",
                    str(staged_signature),
                    "--certificate-identity",
                    CERTIFICATE_IDENTITY,
                    "--certificate-oidc-issuer",
                    OIDC_ISSUER,
                    str(staged_checksums),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HistoricalReleaseAuthError(
                f"could not verify historical release {version} with cosign"
            ) from exc
        if completed.returncode != 0:
            raise HistoricalReleaseAuthError(
                f"Sigstore verification failed for historical release {version}"
            )

        signed = _parse_signed_checksums(checksums)
    reviewed_pins = _load_reviewed_pins(pin_policy)
    authenticated: dict[str, str] = {}
    for name in assets:
        path = release_dir / name
        label = f"historical release asset {name}"
        actual = _sha256_bounded_regular_file(
            path,
            label,
            max_bytes=MAX_HISTORICAL_ASSET_BYTES,
        )
        signed_digest = signed.get(name)
        if signed_digest is not None:
            if actual != signed_digest:
                raise HistoricalReleaseAuthError(
                    f"signed checksum mismatch for historical release asset {version}/{name}"
                )
            authenticated[name] = "signed-checksums"
            continue
        pinned_digest = reviewed_pins.get(version, {}).get(name)
        if pinned_digest is None:
            raise HistoricalReleaseAuthError(
                f"historical release asset {version}/{name} is absent from its signed "
                "checksums and has no reviewed digest exception"
            )
        if actual != pinned_digest:
            raise HistoricalReleaseAuthError(
                f"reviewed digest mismatch for historical release asset {version}/{name}"
            )
        authenticated[name] = "reviewed-digest-exception"
    return authenticated


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--release-dir", type=Path, required=True)
    parser.add_argument("--asset", action="append", required=True)
    parser.add_argument("--cosign", type=Path, required=True)
    parser.add_argument("--pin-policy", type=Path, default=DEFAULT_PIN_POLICY)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        authenticated = authenticate_release_assets(
            version=args.version,
            release_dir=args.release_dir,
            assets=args.asset,
            cosign=args.cosign,
            pin_policy=args.pin_policy,
        )
    except HistoricalReleaseAuthError as exc:
        print(f"historical release authentication failed: {exc}", file=sys.stderr)
        return 1
    for name, provenance in authenticated.items():
        print(f"authenticated {args.version}/{name} via {provenance}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
