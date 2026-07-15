#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Validate the reviewed source-release and source-install identity.

Release assets are built from a reviewed commit and the published Git tag points
to that same commit.  Consequently the checked-in version sources must already
match the requested release; an ephemeral workflow-only version stamp is not a
valid source-distribution identity.

The source-install marker is deliberately separate from release-managed upgrade
state.  It permits rebuilds only while the checkout remains in the same reviewed
release/compatibility epoch.  A source-owned installation has no resolver-owned
venv layout or rollback journal, so crossing an epoch must fail before a build or
dependency install mutates it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
IDENTITY_RELATIVE_PATH = Path("release/source-install-identity.json")
COMPATIBILITY_CONFIG_RELATIVE_PATH = Path("internal/config/config.go")
OBSERVABILITY_V8_CONFIG_RELATIVE_PATH = Path(
    "internal/config/observability_v8_types.go"
)
IDENTITY_SCHEMA_VERSION = 1
MARKER_SCHEMA_VERSION = 2
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_MARKER_BYTES = 16 * 1024
IDENTITY_KEYS = {
    "schema_version",
    "source_release",
    "source_install_compatibility_epoch",
    "runtime_config_version",
}
MARKER_KEYS = {
    "schema_version",
    "checkout_root",
    "source_release",
    "source_install_compatibility_epoch",
    "runtime_config_version",
    "gateway_sha256",
}


class SourceIdentityError(RuntimeError):
    """The reviewed source identity is missing, ambiguous, or inconsistent."""


class LegacySourceMarkerError(SourceIdentityError):
    """A pre-v2 marker cannot prove which release/epoch owns live state."""


def _version_tuple(value: str) -> tuple[int, int, int]:
    if not SEMVER_RE.fullmatch(value):
        raise SourceIdentityError(f"source release must be canonical X.Y.Z, got {value!r}")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def _read_text(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SourceIdentityError(f"could not read {label} {path}: {exc}") from exc


def _single_regex(path: Path, pattern: str, label: str) -> str:
    matches = re.findall(pattern, _read_text(path, label), re.MULTILINE)
    if len(matches) != 1:
        raise SourceIdentityError(f"{label} must contain exactly one canonical version")
    value = matches[0]
    _version_tuple(value)
    return value


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(_read_text(path, label))
    except json.JSONDecodeError as exc:
        raise SourceIdentityError(f"invalid {label} JSON {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SourceIdentityError(f"{label} must contain a JSON object")
    return payload


def checked_in_version_sources(root: Path = ROOT) -> dict[str, str]:
    """Read every checked-in source that reports the release version."""

    versions = {
        "pyproject.toml": _single_regex(
            root / "pyproject.toml",
            r'^version\s*=\s*"([^"]+)"\s*$',
            "pyproject.toml",
        ),
        "cli/defenseclaw/__init__.py": _single_regex(
            root / "cli/defenseclaw/__init__.py",
            r'^__version__\s*=\s*"([^"]+)"\s*$',
            "cli __version__",
        ),
        "Makefile": _single_regex(
            root / "Makefile",
            r"^VERSION\s*:=\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$",
            "Makefile",
        ),
    }

    package = _read_json_object(root / "extensions/defenseclaw/package.json", "package.json")
    package_version = package.get("version")
    if not isinstance(package_version, str):
        raise SourceIdentityError("package.json lacks a string version")
    _version_tuple(package_version)
    versions["extensions/defenseclaw/package.json"] = package_version

    package_lock = _read_json_object(root / "extensions/defenseclaw/package-lock.json", "package-lock.json")
    lock_root = package_lock.get("packages")
    root_package = lock_root.get("") if isinstance(lock_root, dict) else None
    lock_root_version = root_package.get("version") if isinstance(root_package, dict) else None
    for label, value in (
        ("package-lock.json top level", package_lock.get("version")),
        ("package-lock.json root package", lock_root_version),
    ):
        if not isinstance(value, str):
            raise SourceIdentityError(f"{label} lacks a string version")
        _version_tuple(value)
        versions[f"extensions/defenseclaw/{label}"] = value

    uv_matches = re.findall(
        r'^\[\[package\]\]\nname = "defenseclaw"\nversion = "([^"]+)"\nsource = \{ editable = "\." \}$',
        _read_text(root / "uv.lock", "uv.lock"),
        re.MULTILINE,
    )
    if len(uv_matches) != 1:
        raise SourceIdentityError("uv.lock must contain one editable defenseclaw package version")
    _version_tuple(uv_matches[0])
    versions["uv.lock editable defenseclaw package"] = uv_matches[0]

    xcode_matches = re.findall(
        r"^\s*MARKETING_VERSION\s*=\s*([0-9]+\.[0-9]+\.[0-9]+);\s*$",
        _read_text(
            root / "macos/DefenseClawMac/DefenseClawMac.xcodeproj/project.pbxproj",
            "macOS Xcode project",
        ),
        re.MULTILINE,
    )
    if len(xcode_matches) != 2 or len(set(xcode_matches)) != 1:
        raise SourceIdentityError("macOS Xcode project must contain exactly two matching MARKETING_VERSION values")
    versions["macOS MARKETING_VERSION"] = xcode_matches[0]
    return versions


def _go_config_version_literal(root: Path, relative_path: Path, name: str) -> int:
    matches = re.findall(
        rf"^\s*(?:const[ \t]+)?{re.escape(name)}[ \t]*=[ \t]*([0-9]+)[ \t]*$",
        _read_text(root / relative_path, f"gateway {name} source"),
        re.MULTILINE,
    )
    if len(matches) != 1:
        raise SourceIdentityError(
            f"gateway source must declare exactly one literal {name}"
        )
    value = int(matches[0])
    if value < 1:
        raise SourceIdentityError(f"gateway {name} must be positive")
    return value


def compatibility_config_version(root: Path = ROOT) -> int:
    """Read the legacy compatibility-decoder ceiling."""

    return _go_config_version_literal(
        root,
        COMPATIBILITY_CONFIG_RELATIVE_PATH,
        "CurrentConfigVersion",
    )


def observability_v8_config_version(root: Path = ROOT) -> int:
    """Read the strict observability-v8 runtime schema literal."""

    return _go_config_version_literal(
        root,
        OBSERVABILITY_V8_CONFIG_RELATIVE_PATH,
        "ObservabilityV8ConfigVersion",
    )


def runtime_config_version(
    root: Path = ROOT,
    *,
    source_release: str | None = None,
) -> int:
    """Select the release-owned runtime attestation literal."""

    if source_release is None:
        payload = _read_json_object(
            root / IDENTITY_RELATIVE_PATH,
            "source-install identity",
        )
        candidate = payload.get("source_release")
        if not isinstance(candidate, str):
            raise SourceIdentityError(
                "source-install identity source_release must be a string"
            )
        source_release = candidate
    release_key = _version_tuple(source_release)
    if release_key >= (0, 8, 5):
        return observability_v8_config_version(root)
    return compatibility_config_version(root)


def _validate_identity_payload(payload: dict[str, Any]) -> dict[str, int | str]:
    if set(payload) != IDENTITY_KEYS:
        raise SourceIdentityError(
            f"source-install identity keys changed: got {sorted(payload)}, want {sorted(IDENTITY_KEYS)}"
        )
    schema = payload.get("schema_version")
    release = payload.get("source_release")
    epoch = payload.get("source_install_compatibility_epoch")
    runtime = payload.get("runtime_config_version")
    if schema != IDENTITY_SCHEMA_VERSION:
        raise SourceIdentityError(f"source-install identity schema must be {IDENTITY_SCHEMA_VERSION}")
    if not isinstance(release, str):
        raise SourceIdentityError("source-install identity source_release must be a string")
    release_key = _version_tuple(release)
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
        raise SourceIdentityError("source-install identity compatibility epoch must be a positive integer")
    if not isinstance(runtime, int) or isinstance(runtime, bool) or runtime < 1:
        raise SourceIdentityError("source-install identity runtime_config_version must be a positive integer")
    if release_key == (0, 8, 4) and (epoch != 1 or runtime != 7):
        raise SourceIdentityError("release 0.8.4 must use source-install compatibility epoch 1 and runtime config 7")
    if release_key == (0, 8, 5) and (epoch != 2 or runtime != 8):
        raise SourceIdentityError(
            "release 0.8.5 must use source-install compatibility epoch 2 and runtime config 8"
        )
    if release_key > (0, 8, 5) and (epoch < 2 or runtime < 8):
        raise SourceIdentityError("release 0.8.5+ cannot reuse the 0.8.4 bridge source-install identity")
    return {
        "schema_version": IDENTITY_SCHEMA_VERSION,
        "source_release": release,
        "source_install_compatibility_epoch": epoch,
        "runtime_config_version": runtime,
    }


def validate_source_tree(
    root: Path = ROOT,
    *,
    expected_release: str | None = None,
) -> dict[str, int | str]:
    """Validate source versions, reviewed identity, and gateway runtime schema."""

    root = root.resolve()
    identity = _validate_identity_payload(_read_json_object(root / IDENTITY_RELATIVE_PATH, "source-install identity"))
    release = str(identity["source_release"])
    versions = checked_in_version_sources(root)
    drift = {label: value for label, value in versions.items() if value != release}
    if drift:
        details = ", ".join(f"{label}={value}" for label, value in sorted(drift.items()))
        raise SourceIdentityError(f"checked-in version sources do not match source_release {release}: {details}")
    if expected_release is not None:
        _version_tuple(expected_release)
        if release != expected_release:
            raise SourceIdentityError(
                f"requested release {expected_release} does not match reviewed source_release {release}"
            )
    compatibility_runtime = compatibility_config_version(root)
    if _version_tuple(release) >= (0, 8, 5) and compatibility_runtime != 7:
        raise SourceIdentityError(
            "hard-cut source must retain CurrentConfigVersion=7 as its compatibility ceiling: "
            f"got {compatibility_runtime}"
        )
    source_runtime = runtime_config_version(root, source_release=release)
    if identity["runtime_config_version"] != source_runtime:
        raise SourceIdentityError(
            "source-install identity runtime_config_version does not match gateway source: "
            f"identity={identity['runtime_config_version']}, source={source_runtime}"
        )
    return identity


def _read_opened_marker(path: Path) -> tuple[bytes, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SourceIdentityError(f"could not open source-install marker {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_MARKER_BYTES:
            raise SourceIdentityError("source-install marker must be a bounded regular file")
        chunks: list[bytes] = []
        remaining = MAX_MARKER_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or len(payload) > MAX_MARKER_BYTES
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise SourceIdentityError("source-install marker changed while it was opened")
        return payload, hashlib.sha256(payload).hexdigest()
    finally:
        os.close(descriptor)


def _looks_like_legacy_marker(raw: bytes) -> bool:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return False
    return (
        len(lines) == 2
        and os.path.isabs(lines[0])
        and lines[1].startswith("gateway_sha256=")
        and SHA256_RE.fullmatch(lines[1].removeprefix("gateway_sha256=")) is not None
    )


def validate_marker(
    path: Path,
    *,
    checkout_root: Path,
    source_release: str,
    compatibility_epoch: int,
    runtime_version: int,
    allow_source_transition: bool = False,
) -> tuple[str, str]:
    """Return exact marker and gateway digests after v2 identity checks."""

    raw, digest = _read_opened_marker(path)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        if _looks_like_legacy_marker(raw):
            raise LegacySourceMarkerError("legacy source-install marker has no release-bound identity") from exc
        raise SourceIdentityError("source-install marker is not valid v2 JSON") from exc
    if not isinstance(payload, dict) or set(payload) != MARKER_KEYS:
        raise SourceIdentityError(f"source-install marker must contain exactly the v2 fields {sorted(MARKER_KEYS)}")
    if payload.get("schema_version") != MARKER_SCHEMA_VERSION:
        raise SourceIdentityError(f"source-install marker schema must be {MARKER_SCHEMA_VERSION}")
    marker_release = payload.get("source_release")
    marker_epoch = payload.get("source_install_compatibility_epoch")
    marker_runtime = payload.get("runtime_config_version")
    if not isinstance(marker_release, str):
        raise SourceIdentityError("source-install marker source_release must be a string")
    _version_tuple(marker_release)
    for label, value in (
        ("source_install_compatibility_epoch", marker_epoch),
        ("runtime_config_version", marker_runtime),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise SourceIdentityError(f"source-install marker {label} must be a positive integer")
    expected_root = str(checkout_root.resolve())
    marker_root = payload.get("checkout_root")
    if (
        not isinstance(marker_root, str)
        or not os.path.isabs(marker_root)
        or any(character in marker_root for character in ("\n", "\r", "\t"))
        or marker_root != expected_root
    ):
        raise SourceIdentityError(f"source-install marker belongs to a different checkout ({marker_root!r})")
    if not allow_source_transition:
        expected_scalars = {
            "source_release": source_release,
            "source_install_compatibility_epoch": compatibility_epoch,
            "runtime_config_version": runtime_version,
        }
        for key, expected in expected_scalars.items():
            if payload.get(key) != expected:
                raise SourceIdentityError(
                    f"source-install marker {key}={payload.get(key)!r} does not match checkout {expected!r}"
                )
    gateway_digest = payload.get("gateway_sha256")
    if not isinstance(gateway_digest, str) or SHA256_RE.fullmatch(gateway_digest) is None:
        raise SourceIdentityError("source-install marker gateway_sha256 is invalid")
    return digest, gateway_digest


def render_marker(
    *,
    checkout_root: Path,
    source_release: str,
    compatibility_epoch: int,
    runtime_version: int,
    gateway_sha256: str,
) -> bytes:
    _version_tuple(source_release)
    if (
        not isinstance(compatibility_epoch, int)
        or isinstance(compatibility_epoch, bool)
        or compatibility_epoch < 1
        or not isinstance(runtime_version, int)
        or isinstance(runtime_version, bool)
        or runtime_version < 1
    ):
        raise SourceIdentityError("source-install marker identity values must be positive")
    if SHA256_RE.fullmatch(gateway_sha256) is None:
        raise SourceIdentityError("source-install marker gateway digest is invalid")
    root = str(checkout_root.resolve())
    if any(character in root for character in ("\n", "\r", "\t")):
        raise SourceIdentityError("source-install checkout root contains a control character")
    payload = {
        "schema_version": MARKER_SCHEMA_VERSION,
        "checkout_root": root,
        "source_release": source_release,
        "source_install_compatibility_epoch": compatibility_epoch,
        "runtime_config_version": runtime_version,
        "gateway_sha256": gateway_sha256,
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check")
    check.add_argument("--root", type=Path, default=ROOT)
    check.add_argument("--expected-release")
    check.add_argument("--machine", action="store_true")

    marker = subparsers.add_parser("validate-marker")
    marker.add_argument("--path", type=Path, required=True)
    marker.add_argument("--checkout-root", type=Path, required=True)
    marker.add_argument("--source-release", required=True)
    marker.add_argument("--compatibility-epoch", type=int, required=True)
    marker.add_argument("--runtime-config-version", type=int, required=True)
    marker.add_argument("--allow-source-transition", action="store_true")

    render = subparsers.add_parser("render-marker")
    render.add_argument("--checkout-root", type=Path, required=True)
    render.add_argument("--source-release", required=True)
    render.add_argument("--compatibility-epoch", type=int, required=True)
    render.add_argument("--runtime-config-version", type=int, required=True)
    render.add_argument("--gateway-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "check":
            identity = validate_source_tree(args.root, expected_release=args.expected_release)
            if args.machine:
                print(
                    f"{identity['source_release']}\t"
                    f"{identity['source_install_compatibility_epoch']}\t"
                    f"{identity['runtime_config_version']}"
                )
            else:
                print(
                    "version sync OK: "
                    f"{identity['source_release']} "
                    f"(source epoch {identity['source_install_compatibility_epoch']}, "
                    f"runtime {identity['runtime_config_version']})"
                )
        elif args.command == "validate-marker":
            marker_digest, gateway_digest = validate_marker(
                args.path,
                checkout_root=args.checkout_root,
                source_release=args.source_release,
                compatibility_epoch=args.compatibility_epoch,
                runtime_version=args.runtime_config_version,
                allow_source_transition=args.allow_source_transition,
            )
            print(f"{marker_digest}\t{gateway_digest}")
        elif args.command == "render-marker":
            sys.stdout.buffer.write(
                render_marker(
                    checkout_root=args.checkout_root,
                    source_release=args.source_release,
                    compatibility_epoch=args.compatibility_epoch,
                    runtime_version=args.runtime_config_version,
                    gateway_sha256=args.gateway_sha256,
                )
            )
        else:  # pragma: no cover - argparse owns the command set
            raise SourceIdentityError(f"unsupported command {args.command!r}")
    except SourceIdentityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
