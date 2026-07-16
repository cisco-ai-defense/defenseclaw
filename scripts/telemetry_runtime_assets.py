#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Deterministic storage for generated telemetry runtime JSON.

The compiler and release interfaces continue to use ordinary JSON bytes. Git
stores the six large, reproducible runtime artifacts as canonical gzip members
so generated data does not dominate code review. Wheel staging expands the
members back to their exact logical filenames.
"""

from __future__ import annotations

import argparse
import gzip
import io
import struct
import zlib
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Final

RUNTIME_ASSET_ROOT: Final = Path("schemas/telemetry/runtime")
MAX_RUNTIME_ASSET_BYTES: Final = 16 * 1024 * 1024

LOGICAL_TO_ENCODED: Final[Mapping[str, str]] = MappingProxyType(
    {
        "schemas/telemetry/generated/telemetry.schema.json": (
            "schemas/telemetry/runtime/telemetry.schema.json.gz"
        ),
        "schemas/telemetry/generated/catalog.json": (
            "schemas/telemetry/runtime/catalog.json.gz"
        ),
        "schemas/telemetry/generated/compatibility/galileo-rich-v2.json": (
            "schemas/telemetry/runtime/compatibility/galileo-rich-v2.json.gz"
        ),
        "schemas/telemetry/generated/compatibility/local-observability-v1.json": (
            "schemas/telemetry/runtime/compatibility/local-observability-v1.json.gz"
        ),
        "schemas/telemetry/generated/compatibility/openinference-v1.json": (
            "schemas/telemetry/runtime/compatibility/openinference-v1.json.gz"
        ),
        "schemas/telemetry/generated/compatibility/v7-exporter-selection.json": (
            "schemas/telemetry/runtime/compatibility/v7-exporter-selection.json.gz"
        ),
    }
)


class RuntimeAssetError(ValueError):
    """A generated runtime asset is missing, malformed, or noncanonical."""


def canonical_gzip(payload: bytes) -> bytes:
    """Return one reproducible RFC 1952 member with no ambient metadata."""
    output = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=output,
        mtime=0,
    ) as writer:
        writer.write(payload)
    encoded = output.getvalue()
    # ID1, ID2, deflate, no flags, zero mtime, XFL=maximum, OS=unknown.
    if encoded[:10] != b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff":
        raise RuntimeAssetError("canonical gzip encoder produced an unexpected header")
    return encoded


def decode_canonical_gzip(
    encoded: bytes,
    *,
    maximum: int = MAX_RUNTIME_ASSET_BYTES,
) -> bytes:
    """Decode one portable canonical member and reject bombs or trailers.

    Deflate output is not byte-stable across every supported zlib build, so
    canonicality is defined by the metadata-free RFC 1952 envelope, one raw
    deflate stream, and its exact CRC/size trailer. Recompressing during read
    would reject valid release inputs on hosts with a different zlib build.
    """

    header = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
    if maximum < 0 or len(encoded) < 18 or encoded[:10] != header:
        raise RuntimeAssetError("telemetry runtime asset is malformed")
    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
    try:
        payload = decoder.decompress(encoded[10:], maximum + 1)
    except zlib.error as exc:
        raise RuntimeAssetError("telemetry runtime asset is malformed") from exc
    if len(payload) > maximum:
        raise RuntimeAssetError("telemetry runtime asset exceeds its decoded size limit")
    if not decoder.eof or decoder.unconsumed_tail or len(decoder.unused_data) != 8:
        raise RuntimeAssetError("telemetry runtime asset is not canonical gzip")
    expected_crc, expected_size = struct.unpack("<II", decoder.unused_data)
    if expected_crc != zlib.crc32(payload) or expected_size != (len(payload) & 0xFFFFFFFF):
        raise RuntimeAssetError("telemetry runtime asset is malformed")
    return payload


def encoded_path(logical_path: str) -> str:
    try:
        return LOGICAL_TO_ENCODED[logical_path]
    except KeyError as exc:
        raise RuntimeAssetError(f"unknown telemetry runtime artifact: {logical_path}") from exc


def read_logical_asset(root: Path, logical_path: str) -> bytes:
    physical = root / encoded_path(logical_path)
    try:
        encoded = physical.read_bytes()
    except OSError as exc:
        raise RuntimeAssetError(f"telemetry runtime asset is unavailable: {logical_path}") from exc
    return decode_canonical_gzip(encoded)


def stage_wheel_assets(root: Path, destination: Path) -> None:
    """Expand every tracked asset to the wheel's stable raw JSON names."""
    destination.mkdir(parents=True, exist_ok=True)
    expected = {Path(logical).name for logical in LOGICAL_TO_ENCODED}
    for existing in destination.glob("*.json"):
        if existing.name not in expected:
            existing.unlink()
    for logical in LOGICAL_TO_ENCODED:
        target = destination / Path(logical).name
        target.write_bytes(read_logical_asset(root, logical))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--stage", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        stage_wheel_assets(args.root.resolve(), args.stage.resolve())
    except RuntimeAssetError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
