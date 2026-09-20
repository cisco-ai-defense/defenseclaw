#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Stage and verify the immutable OpenClaw extension runtime reference."""

from __future__ import annotations

import argparse
import json
import os
import stat
import struct
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cli"))

from defenseclaw.extension_fingerprint import (  # noqa: E402
    REFERENCE_PACKAGE_PATH,
    ExtensionFingerprintError,
    canonical_reference_bytes,
    fingerprint_deployed_runtime,
    fingerprint_repository_runtime,
    load_reference,
    validate_reference,
)

_MAX_PLUGIN_ARCHIVE_ENTRIES = 4096
_MAX_PLUGIN_ARCHIVE_COMPRESSED_BYTES = 128 * 1024 * 1024
_MAX_PLUGIN_ARCHIVE_EXPANDED_BYTES = 64 * 1024 * 1024
_MAX_PLUGIN_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_WHEEL_ENTRIES = 4096
_MAX_WHEEL_ARCHIVE_BYTES = 256 * 1024 * 1024
_MAX_WHEEL_CENTRAL_DIRECTORY_BYTES = 16 * 1024 * 1024
_MAX_WHEEL_COMPRESSED_BYTES = 128 * 1024 * 1024
_MAX_WHEEL_EXPANDED_BYTES = 256 * 1024 * 1024
_MAX_WHEEL_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_WHEEL_REFERENCE_BYTES = 256 * 1024
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_EOCD_STRUCT = struct.Struct("<4s4H2LH")
_ZIP_EOCD_MAX_BYTES = 22 + 65_535
_ZIP_CENTRAL_SIGNATURE = b"PK\x01\x02"
_ZIP_CENTRAL_FIXED_BYTES = 46


def _same_reference(left: dict[str, object], right: dict[str, object], *, label: str) -> None:
    if left != right:
        raise ExtensionFingerprintError(f"{label} does not match the canonical extension runtime")


def _write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    published = False
    created = False
    try:
        with temporary.open("xb") as handle:
            created = True
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        published = True
    finally:
        if created and not published:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def stage(source: Path, output: Path) -> dict[str, object]:
    document = fingerprint_repository_runtime(source)
    _write_atomic(output, canonical_reference_bytes(document))
    _same_reference(load_reference(output), document, label="staged extension fingerprint")
    return document


def _safe_archive_relative(name: str) -> PurePosixPath:
    if not name or "\\" in name or any(ord(character) < 32 for character in name):
        raise ExtensionFingerprintError(f"plugin archive has a non-canonical member path: {name!r}")
    relative = PurePosixPath(name)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ExtensionFingerprintError(f"plugin archive has a non-canonical member path: {name!r}")
    return relative


def _fingerprint_archive(archive_path: Path) -> dict[str, object]:
    """Materialize only regular canonical members, then use runtime validation."""

    if not archive_path.is_file() or archive_path.is_symlink():
        raise ExtensionFingerprintError("plugin archive is not a plain file")
    try:
        compressed_bytes = archive_path.stat().st_size
    except OSError as exc:
        raise ExtensionFingerprintError("plugin archive is not a readable gzip tar") from exc
    # Tar does not expose compressed sizes per member. Bounding the complete
    # gzip stream also bounds every individual member's compressed bytes.
    if compressed_bytes > _MAX_PLUGIN_ARCHIVE_COMPRESSED_BYTES:
        raise ExtensionFingerprintError("plugin archive exceeds the compressed size limit")
    with tempfile.TemporaryDirectory(prefix="dc-extension-contract-") as temporary_name:
        destination = Path(temporary_name)
        seen: set[str] = set()
        try:
            # Streaming mode avoids materializing an attacker-controlled member
            # table before the entry-count bound can be enforced.
            archive = tarfile.open(archive_path, mode="r|gz")
        except (OSError, tarfile.TarError) as exc:
            raise ExtensionFingerprintError("plugin archive is not a readable gzip tar") from exc
        with archive:
            entry_count = 0
            expanded_bytes = 0
            for member in archive:
                entry_count += 1
                if entry_count > _MAX_PLUGIN_ARCHIVE_ENTRIES:
                    raise ExtensionFingerprintError("plugin archive exceeds the entry count limit")
                if member.size < 0 or member.size > _MAX_PLUGIN_ARCHIVE_MEMBER_BYTES:
                    raise ExtensionFingerprintError("plugin archive member exceeds the expanded size limit")
                expanded_bytes += member.size
                if expanded_bytes > _MAX_PLUGIN_ARCHIVE_EXPANDED_BYTES:
                    raise ExtensionFingerprintError("plugin archive exceeds the expanded size limit")
                relative = _safe_archive_relative(member.name)
                normalized = relative.as_posix().casefold()
                if normalized in seen:
                    raise ExtensionFingerprintError("plugin archive contains duplicate or colliding members")
                seen.add(normalized)
                target = destination.joinpath(*relative.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise ExtensionFingerprintError("plugin archive contains a link or special member")
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ExtensionFingerprintError("plugin archive regular member is unreadable")
                with extracted, target.open("xb") as output:
                    remaining = member.size
                    while remaining:
                        chunk = extracted.read(min(128 * 1024, remaining))
                        if not chunk:
                            raise ExtensionFingerprintError("plugin archive regular member is truncated")
                        output.write(chunk)
                        remaining -= len(chunk)
                os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
        return fingerprint_deployed_runtime(destination)


def _preflight_wheel_directory(wheel: Path, archive_bytes: int) -> int:
    """Bound ZIP metadata before ``ZipFile`` materializes its entry table."""

    try:
        with wheel.open("rb") as handle:
            tail_bytes = min(archive_bytes, _ZIP_EOCD_MAX_BYTES)
            handle.seek(archive_bytes - tail_bytes)
            tail = handle.read(tail_bytes)
    except OSError as exc:
        raise ExtensionFingerprintError("DefenseClaw wheel is not a readable ZIP archive") from exc

    cursor = len(tail)
    record: tuple[bytes, int, int, int, int, int, int, int] | None = None
    record_offset = -1
    while cursor:
        candidate = tail.rfind(_ZIP_EOCD_SIGNATURE, 0, cursor)
        if candidate < 0:
            break
        if candidate + _ZIP_EOCD_STRUCT.size <= len(tail):
            parsed = _ZIP_EOCD_STRUCT.unpack_from(tail, candidate)
            if candidate + _ZIP_EOCD_STRUCT.size + parsed[-1] == len(tail):
                record = parsed
                record_offset = archive_bytes - len(tail) + candidate
                break
        cursor = candidate
    if record is None:
        raise ExtensionFingerprintError("DefenseClaw wheel is not a readable ZIP archive")

    (
        _signature,
        disk_number,
        directory_disk,
        disk_entries,
        total_entries,
        directory_size,
        directory_offset,
        _comment,
    ) = record
    if disk_number != 0 or directory_disk != 0 or disk_entries != total_entries:
        raise ExtensionFingerprintError("DefenseClaw wheel uses an unsupported multi-disk ZIP")
    if total_entries == 0xFFFF or directory_size == 0xFFFFFFFF or directory_offset == 0xFFFFFFFF:
        raise ExtensionFingerprintError("DefenseClaw wheel uses unsupported ZIP64 metadata")
    if total_entries > _MAX_WHEEL_ENTRIES:
        raise ExtensionFingerprintError("DefenseClaw wheel exceeds the entry count limit")
    if directory_size > _MAX_WHEEL_CENTRAL_DIRECTORY_BYTES:
        raise ExtensionFingerprintError("DefenseClaw wheel central directory exceeds the size limit")
    if directory_offset + directory_size != record_offset:
        raise ExtensionFingerprintError("DefenseClaw wheel has invalid central directory bounds")

    try:
        with wheel.open("rb") as handle:
            handle.seek(directory_offset)
            directory = handle.read(directory_size)
    except OSError as exc:
        raise ExtensionFingerprintError("DefenseClaw wheel is not a readable ZIP archive") from exc
    if len(directory) != directory_size:
        raise ExtensionFingerprintError("DefenseClaw wheel has a truncated central directory")

    position = 0
    parsed_entries = 0
    while position < len(directory):
        if (
            len(directory) - position < _ZIP_CENTRAL_FIXED_BYTES
            or directory[position : position + 4] != _ZIP_CENTRAL_SIGNATURE
        ):
            raise ExtensionFingerprintError("DefenseClaw wheel has invalid central directory entries")
        name_bytes, extra_bytes, comment_bytes = struct.unpack_from("<3H", directory, position + 28)
        position += _ZIP_CENTRAL_FIXED_BYTES + name_bytes + extra_bytes + comment_bytes
        if position > len(directory):
            raise ExtensionFingerprintError("DefenseClaw wheel has invalid central directory entries")
        parsed_entries += 1
        if parsed_entries > _MAX_WHEEL_ENTRIES or parsed_entries > total_entries:
            raise ExtensionFingerprintError("DefenseClaw wheel exceeds the entry count limit")
    if parsed_entries != total_entries:
        raise ExtensionFingerprintError("DefenseClaw wheel entry count does not match its directory")
    return total_entries


def _wheel_reference(wheel: Path) -> dict[str, object]:
    if not wheel.is_file() or wheel.is_symlink():
        raise ExtensionFingerprintError("DefenseClaw wheel is not a plain file")
    try:
        archive_bytes = wheel.stat().st_size
    except OSError as exc:
        raise ExtensionFingerprintError("DefenseClaw wheel is not a readable ZIP archive") from exc
    if archive_bytes > _MAX_WHEEL_ARCHIVE_BYTES:
        raise ExtensionFingerprintError("DefenseClaw wheel exceeds the compressed size limit")
    expected_entries = _preflight_wheel_directory(wheel, archive_bytes)
    member_name = f"defenseclaw/{REFERENCE_PACKAGE_PATH}"
    try:
        with zipfile.ZipFile(wheel) as archive:
            members = archive.infolist()
            if len(members) != expected_entries:
                raise ExtensionFingerprintError("DefenseClaw wheel entry count does not match its directory")
            compressed_total = 0
            expanded_total = 0
            for info in members:
                if (
                    info.compress_size < 0
                    or info.file_size < 0
                    or info.compress_size > _MAX_WHEEL_MEMBER_BYTES
                    or info.file_size > _MAX_WHEEL_MEMBER_BYTES
                ):
                    raise ExtensionFingerprintError("DefenseClaw wheel member exceeds the size limit")
                compressed_total += info.compress_size
                expanded_total += info.file_size
                if compressed_total > _MAX_WHEEL_COMPRESSED_BYTES:
                    raise ExtensionFingerprintError("DefenseClaw wheel exceeds the compressed size limit")
                if expanded_total > _MAX_WHEEL_EXPANDED_BYTES:
                    raise ExtensionFingerprintError("DefenseClaw wheel exceeds the expanded size limit")
            matches = [info for info in members if info.filename == member_name]
            if len(matches) != 1:
                raise ExtensionFingerprintError(
                    "DefenseClaw wheel must contain exactly one extension fingerprint reference"
                )
            info = matches[0]
            if info.is_dir() or ((info.external_attr >> 16) & 0o170000) == 0o120000:
                raise ExtensionFingerprintError("DefenseClaw wheel extension reference is not a regular file")
            if info.compress_size > _MAX_WHEEL_REFERENCE_BYTES or info.file_size > _MAX_WHEEL_REFERENCE_BYTES:
                raise ExtensionFingerprintError("DefenseClaw wheel extension reference exceeds the size limit")
            payload = archive.read(info)
    except (OSError, RuntimeError, zipfile.BadZipFile, KeyError) as exc:
        raise ExtensionFingerprintError("DefenseClaw wheel is not a readable ZIP archive") from exc
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ExtensionFingerprintError("wheel extension reference is not valid UTF-8 JSON") from exc
    if canonical_reference_bytes(validate_reference(document)) != payload:
        raise ExtensionFingerprintError("wheel extension reference is not canonically serialized")
    return validate_reference(document)


def verify_archive(source: Path, reference: Path, archive: Path) -> None:
    expected = fingerprint_repository_runtime(source)
    _same_reference(load_reference(reference), expected, label="staged extension fingerprint")
    _same_reference(_fingerprint_archive(archive), expected, label="plugin archive")


def verify_contract(source: Path, reference: Path, archive: Path, wheel: Path) -> None:
    expected = fingerprint_repository_runtime(source)
    _same_reference(load_reference(reference), expected, label="staged extension fingerprint")
    _same_reference(_fingerprint_archive(archive), expected, label="plugin archive")
    _same_reference(_wheel_reference(wheel), expected, label="wheel extension fingerprint")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    stage_parser = subparsers.add_parser("stage")
    stage_parser.add_argument("--source", type=Path, required=True)
    stage_parser.add_argument("--output", type=Path, required=True)

    archive_parser = subparsers.add_parser("verify-archive")
    archive_parser.add_argument("--source", type=Path, required=True)
    archive_parser.add_argument("--reference", type=Path, required=True)
    archive_parser.add_argument("--archive", type=Path, required=True)

    contract_parser = subparsers.add_parser("verify-contract")
    contract_parser.add_argument("--source", type=Path, required=True)
    contract_parser.add_argument("--reference", type=Path, required=True)
    contract_parser.add_argument("--archive", type=Path, required=True)
    contract_parser.add_argument("--wheel", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "stage":
            document = stage(args.source, args.output)
            print(document["sha256"])
        elif args.command == "verify-archive":
            verify_archive(args.source, args.reference, args.archive)
            print("validated plugin archive against immutable extension fingerprint")
        else:
            verify_contract(args.source, args.reference, args.archive, args.wheel)
            print("validated wheel and plugin archive extension fingerprint contract")
    except ExtensionFingerprintError as exc:
        print(f"extension fingerprint validation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
