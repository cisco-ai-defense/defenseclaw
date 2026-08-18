#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Validate the installed DefenseClaw v8 resource contract."""

from __future__ import annotations

import argparse
import json
import sys
from importlib import resources
from pathlib import Path
from typing import Final

EXPECTED_V8_RESOURCES: Final[dict[str, frozenset[str]]] = {
    "_data/config/v8": frozenset(
        {
            "defenseclaw-config.schema.json",
            "observability.yaml",
            "observability.md",
        }
    ),
    "_data/telemetry/v8": frozenset(
        {
            "telemetry.schema.json",
            "catalog.json",
            "v7-exporter-selection.json",
            "galileo-rich-v2.json",
            "local-observability-v1.json",
            "openinference-v1.json",
        }
    ),
}


class PackagedV8ResourceError(RuntimeError):
    """Raised when installed v8 resources violate the release contract."""


def _validate_inventory(package_root: Path, runtime_root: Path, *, label: str) -> None:
    fallback_root = runtime_root / "Lib" / "schemas"
    if fallback_root.exists() or fallback_root.is_symlink():
        raise PackagedV8ResourceError(f"{label} runtime unexpectedly contains a Lib/schemas fallback tree")

    for relative, expected_names in EXPECTED_V8_RESOURCES.items():
        directory = package_root.joinpath(relative)
        if directory.is_symlink() or not directory.is_dir():
            raise PackagedV8ResourceError(
                f"{label} DefenseClaw v8 resource directory is not a regular directory: {relative}"
            )

        entries = tuple(directory.iterdir())
        non_files = sorted(entry.name for entry in entries if entry.is_symlink() or not entry.is_file())
        actual_names = {entry.name for entry in entries}
        if non_files or actual_names != expected_names:
            raise PackagedV8ResourceError(
                f"{label} DefenseClaw v8 resource inventory mismatch in {relative}: "
                f"actual={sorted(actual_names)!r} expected={sorted(expected_names)!r} "
                f"non_files={non_files!r}"
            )


def validate_packaged_v8_resources(
    site_packages: Path,
    runtime_root: Path,
    *,
    label: str,
) -> None:
    """Validate exact package-local inventory and exercise every resource loader."""

    site_packages = site_packages.resolve(strict=True)
    runtime_root = runtime_root.resolve(strict=True)
    package_root = Path(str(resources.files("defenseclaw"))).resolve(strict=True)
    canonical_package_path = site_packages / "defenseclaw"
    is_junction = getattr(canonical_package_path, "is_junction", None)
    if canonical_package_path.is_symlink() or (is_junction is not None and is_junction()):
        raise PackagedV8ResourceError(
            f"{label} DefenseClaw package root uses symlink or junction indirection: {canonical_package_path}"
        )
    canonical_package_root = canonical_package_path.resolve(strict=True)
    if not canonical_package_root.is_dir():
        raise PackagedV8ResourceError(f"{label} DefenseClaw package root is not a directory: {canonical_package_root}")
    if package_root != canonical_package_root:
        raise PackagedV8ResourceError(
            f"DefenseClaw resources did not resolve to the canonical {label} package root: "
            f"actual={package_root} expected={canonical_package_root}"
        )

    _validate_inventory(package_root, runtime_root, label=label)

    from defenseclaw.observability.schema_resources import (
        telemetry_v8_catalog_bytes,
        telemetry_v8_compatibility_profile_bytes,
        telemetry_v8_schema_bytes,
        v7_exporter_selection_bytes,
    )
    from defenseclaw.observability.v8_config import _schema_validator

    _schema_validator()
    for reference in ("observability.yaml", "observability.md"):
        if not package_root.joinpath("_data/config/v8", reference).read_bytes():
            raise PackagedV8ResourceError(f"{label} DefenseClaw v8 reference is empty: {reference}")

    telemetry_payloads = {
        "telemetry.schema.json": telemetry_v8_schema_bytes(),
        "catalog.json": telemetry_v8_catalog_bytes(),
        "v7-exporter-selection.json": v7_exporter_selection_bytes(),
        "galileo-rich-v2.json": telemetry_v8_compatibility_profile_bytes("galileo-rich-v2"),
        "local-observability-v1.json": telemetry_v8_compatibility_profile_bytes("local-observability-v1"),
        "openinference-v1.json": telemetry_v8_compatibility_profile_bytes("openinference-v1"),
    }
    for name, payload in telemetry_payloads.items():
        try:
            json.loads(payload)
        except (TypeError, ValueError) as exc:
            raise PackagedV8ResourceError(f"{label} DefenseClaw v8 resource is not valid JSON: {name}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-packages", required=True, type=Path)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--label", required=True, choices=("staged", "packaged"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        validate_packaged_v8_resources(
            args.site_packages,
            args.runtime_root,
            label=args.label,
        )
    except (ImportError, OSError, PackagedV8ResourceError) as exc:
        print(f"packaged v8 resource validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"validated nine package-local DefenseClaw v8 resources in {args.label} runtime")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
