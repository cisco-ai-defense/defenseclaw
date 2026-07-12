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
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import struct
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from scripts.source_release_identity import SourceIdentityError, validate_source_tree
except ModuleNotFoundError:  # Direct ``python scripts/release_candidate.py`` execution.
    from source_release_identity import SourceIdentityError, validate_source_tree

SCHEMA_VERSION = 2
RUNTIME_ATTESTATION_FILENAME = "runtime-candidate-checksums.txt"
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
UPGRADE_BASELINES_PATH = ROOT / "release" / "upgrade-baselines.json"
HISTORICAL_ARTIFACT_DIGESTS_PATH = ROOT / "release" / "historical-artifact-digests.json"
RUNTIME_CONFIG_PATH = ROOT / "internal" / "config" / "config.go"
RESOLVER_COMPLETENESS_MARKER = b"# DefenseClaw upgrade resolver complete v1"
RESOLVER_ASSET_SOURCES = {
    "defenseclaw-upgrade.sh": ROOT / "scripts" / "upgrade.sh",
    "defenseclaw-upgrade.ps1": ROOT / "scripts" / "upgrade.ps1",
}
MAX_RESOLVER_BYTES = 4 * 1024 * 1024


class CandidateError(RuntimeError):
    """A release candidate is incomplete, inconsistent, or mutated."""


def _reviewed_source_install_identity(version: str) -> dict[str, int | str]:
    """Bind candidate custody to the reviewed source/tag compatibility identity."""

    try:
        return validate_source_tree(ROOT, expected_release=version)
    except SourceIdentityError as exc:
        raise CandidateError(f"reviewed source-install identity is invalid: {exc}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def macos_asset_names(version: str) -> tuple[str, ...]:
    _validate_version(version)
    return (
        f"DefenseClawMac-{version}-macos-arm64.dmg",
        f"DefenseClawMac-{version}-macos-arm64.zip",
    )


def resolver_asset_names(version: str) -> tuple[str, ...]:
    _validate_version(version)
    if tuple(map(int, version.split("."))) < (0, 8, 4):
        return ()
    return tuple(sorted(RESOLVER_ASSET_SOURCES))


def payload_asset_names(version: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            (
                *runtime_asset_names(version),
                *macos_asset_names(version),
                *resolver_asset_names(version),
            )
        )
    )


def published_asset_names(version: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            (
                *payload_asset_names(version),
                "checksums.txt",
                "checksums.txt.pem",
                "checksums.txt.sig",
            )
        )
    )


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


def _load_upgrade_baseline_policy() -> tuple[list[str], dict[str, list[str]]]:
    try:
        document = json.loads(UPGRADE_BASELINES_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"could not load tested upgrade baselines: {exc}") from exc
    configured = document.get("published_baselines")
    platforms = document.get("platform_published_baselines")
    if (
        document.get("schema_version") != 1
        or not isinstance(configured, list)
        or not configured
        or any(not isinstance(item, str) or not VERSION_RE.fullmatch(item) for item in configured)
        or len(configured) != len(set(configured))
        or configured != sorted(configured, key=lambda item: tuple(map(int, item.split("."))), reverse=True)
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
    configured, _platforms = _load_upgrade_baseline_policy()
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


def _runtime_config_version_from_source() -> int:
    try:
        text = RUNTIME_CONFIG_PATH.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise CandidateError(f"could not read gateway runtime config version: {exc}") from exc
    matches = re.findall(
        r"^const[ \t]+CurrentConfigVersion[ \t]*=[ \t]*([0-9]+)[ \t]*$",
        text,
        re.MULTILINE,
    )
    if len(matches) != 1:
        raise CandidateError(
            "gateway source must declare exactly one literal CurrentConfigVersion"
        )
    value = int(matches[0])
    if value < 1:
        raise CandidateError("gateway CurrentConfigVersion must be positive")
    return value


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


def _validate_upgrade_manifest(path: Path, version: str) -> None:
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

    configured, platform_configured = _load_upgrade_baseline_policy()
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
        if tested != expected_tested:
            raise CandidateError(
                "tested_source_versions must exactly match every reviewed baseline older than the candidate"
            )
        if platform_tested["windows"] != expected_windows:
            raise CandidateError(
                "platform_tested_source_versions.windows must exactly match the reviewed Windows matrix"
            )
        expected_runtime = _expected_runtime_config_version(version)
        source_runtime = _runtime_config_version_from_source()
        if source_runtime != expected_runtime:
            raise CandidateError(
                f"release {version} requires gateway CurrentConfigVersion={expected_runtime}, "
                f"got {source_runtime}"
            )
        if (
            not isinstance(runtime_config, int)
            or isinstance(runtime_config, bool)
            or runtime_config != source_runtime
        ):
            raise CandidateError(
                "runtime_config_version must match the gateway CurrentConfigVersion literal"
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
    if bridge not in platform_tested["windows"]:
        raise CandidateError(
            f"required bridge {bridge} is absent from the tested Windows baseline matrix"
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
    """Require the target wrapper to retain the lease for its real child lifetime."""

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
    pass_fds = keywords.get("pass_fds")
    if not (
        isinstance(pass_fds, ast.IfExp)
        and isinstance(pass_fds.test, ast.Compare)
        and isinstance(pass_fds.test.left, ast.Attribute)
        and isinstance(pass_fds.test.left.value, ast.Name)
        and pass_fds.test.left.value.id == "os"
        and pass_fds.test.left.attr == "name"
        and len(pass_fds.test.ops) == 1
        and isinstance(pass_fds.test.ops[0], ast.Eq)
        and len(pass_fds.test.comparators) == 1
        and isinstance(pass_fds.test.comparators[0], ast.Constant)
        and pass_fds.test.comparators[0].value == "posix"
        and isinstance(pass_fds.body, ast.Tuple)
        and len(pass_fds.body.elts) == 1
        and isinstance(pass_fds.body.elts[0], ast.Name)
        and pass_fds.body.elts[0].id == "lease_fd"
        and isinstance(pass_fds.orelse, ast.Tuple)
        and not pass_fds.orelse.elts
    ):
        raise CandidateError("0.8.4+ mutator wrapper does not hand the lease to its child")
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


def _validate_hard_cut_bundle_transaction(source: str) -> None:
    """Require durable rollback authority before a 0.8.5+ bundle mutation."""

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
        try:
            with zipfile.ZipFile(io.BytesIO(_protected_payload(path))) as archive:
                seen = set()
                gateway_payloads = []
                for member in archive.infolist():
                    raw_name = member.filename[:-1] if member.is_dir() else member.filename
                    member_path = _safe_archive_member_path(raw_name, path.name)
                    if member_path in seen:
                        raise CandidateError(
                            f"duplicate member in gateway archive {path.name}: {member.filename}"
                        )
                    seen.add(member_path)
                    unix_mode = (member.external_attr >> 16) & 0xFFFF
                    file_kind = stat.S_IFMT(unix_mode)
                    if file_kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
                        raise CandidateError(
                            f"non-regular member in gateway archive {path.name}: {member.filename}"
                        )
                    if member.is_dir():
                        continue
                    if member.flag_bits & 0x1:
                        raise CandidateError(
                            f"encrypted member in gateway archive {path.name}: {member.filename}"
                        )
                    if member_path != PurePosixPath("defenseclaw.exe"):
                        continue
                    if member.file_size <= 0 or member.file_size > MAX_GATEWAY_BINARY_BYTES:
                        raise CandidateError(f"gateway binary size is invalid in {path.name}")
                    gateway_payloads.append(archive.read(member))
        except CandidateError:
            raise
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise CandidateError(f"invalid gateway archive {path}: {exc}") from exc
        if len(gateway_payloads) != 1:
            raise CandidateError(
                f"gateway archive {path.name} must contain exactly one root defenseclaw.exe binary"
            )
        _validate_gateway_binary(
            gateway_payloads[0],
            os_name="windows",
            arch=arch,
            version=version,
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


def _posix_refusal_envelope(version: str) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0) as stream:
        stream.write(_refusal_envelope_payload(version))
    return buffer.getvalue()


def _validate_legacy_refusal_envelopes(directory: Path, version: str) -> None:
    expected_gzip = _posix_refusal_envelope(version)
    expected_plain = _refusal_envelope_payload(version)
    for os_name in ("darwin", "linux"):
        for arch in ("amd64", "arm64"):
            path = directory / f"defenseclaw_{version}_{os_name}_{arch}.tar.gz"
            if path.read_bytes() != expected_gzip:
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

    gzip_payload = _posix_refusal_envelope(version)
    plain_payload = _refusal_envelope_payload(version)
    for os_name in ("darwin", "linux"):
        for arch in ("amd64", "arm64"):
            (directory / f"defenseclaw_{version}_{os_name}_{arch}.tar.gz").write_bytes(
                gzip_payload
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


def _copy_exact(source: Path, destination: Path, names: tuple[str, ...]) -> None:
    for name in names:
        shutil.copy2(source / name, destination / name)


def assemble(
    runtime_dir: Path,
    macos_dir: Path,
    root: Path,
    version: str,
    commit: str,
    macos_verification_status: str,
) -> None:
    _validate_version(version)
    _validate_commit(commit)
    if macos_verification_status != "notarized":
        raise CandidateError(
            "production release candidate requires a notarized macOS app; "
            f"got {macos_verification_status!r}"
        )
    if root.exists():
        raise CandidateError(f"candidate output already exists: {root}")

    verify_runtime(runtime_dir, version)
    _validate_gateway_archives(runtime_dir, version, commit=commit)
    _require_regular_files(macos_dir, macos_asset_names(version), "macOS artifact")

    dist = root / "dist"
    dist.mkdir(parents=True)
    _copy_exact(runtime_dir, dist, runtime_asset_names(version))
    _copy_exact(macos_dir, dist, macos_asset_names(version))
    _copy_resolver_assets(dist, version)
    _validate_resolver_assets(dist, version)

    notes = runtime_dir / "CHANGELOG.md"
    if notes.is_file() and not notes.is_symlink():
        shutil.copy2(notes, root / "RELEASE_NOTES.md")

    checksum_lines = [f"{_sha256(dist / name)}  {name}" for name in payload_asset_names(version)]
    (dist / "checksums.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    metadata = {
        "schema_version": SCHEMA_VERSION,
        "release_version": version,
        "commit": commit,
        "macos_verification_status": macos_verification_status,
        "source_install_identity": _reviewed_source_install_identity(version),
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


def seal(root: Path, version: str, commit: str) -> None:
    _validate_version(version)
    _validate_commit(commit)
    metadata = _read_json_object(root / "candidate-metadata.json", "candidate metadata")
    expected_metadata = {
        "schema_version": SCHEMA_VERSION,
        "release_version": version,
        "commit": commit,
        "macos_verification_status": "notarized",
        "source_install_identity": _reviewed_source_install_identity(version),
    }
    if metadata != expected_metadata:
        raise CandidateError(f"candidate metadata mismatch: got {metadata!r}")

    dist = root / "dist"
    names = published_asset_names(version)
    _require_regular_files(dist, names, "release candidate")
    actual_names = _strict_file_names(dist, "release candidate")
    if actual_names != names:
        raise CandidateError(
            "release candidate contains an unexpected file set: "
            f"got {actual_names!r}, want {names!r}"
        )

    checksums = _parse_checksums(dist / "checksums.txt")
    payload_names = payload_asset_names(version)
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
    if manifest.get("macos_verification_status") != "notarized":
        raise CandidateError("release candidate macOS app is not notarized")
    if manifest.get("source_install_identity") != _reviewed_source_install_identity(version):
        raise CandidateError("release candidate source-install identity mismatch")

    dist = root / "dist"
    expected_names = published_asset_names(version)
    _require_regular_files(dist, expected_names, "release candidate")
    actual_names = _strict_file_names(dist, "release candidate")
    if actual_names != expected_names:
        raise CandidateError("release candidate file set changed after sealing")

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
    if tuple(sorted(checksums)) != payload_asset_names(version):
        raise CandidateError("checksums.txt coverage changed after sealing")
    for name, expected in checksums.items():
        if _sha256(dist / name) != expected:
            raise CandidateError(f"published checksum mismatch for {name}")
    _validate_resolver_assets(dist, version)

    _validate_upgrade_manifest(dist / "upgrade-manifest.json", version)
    if tuple(map(int, version.split("."))) >= (0, 8, 4):
        artifacts = _expected_release_artifacts(version)
        _validate_wheel(dist / artifacts["wheel"], version)
        _validate_gateway_archives(dist, version, commit=commit)
        _validate_legacy_refusal_envelopes(dist, version)
    else:
        _validate_wheel(dist / f"defenseclaw-{version}-py3-none-any.whl", version)


def verify_published_release(root: Path, release_json: Path, version: str, commit: str) -> None:
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

    assemble_parser = subparsers.add_parser("assemble")
    assemble_parser.add_argument("--runtime-dir", type=Path, required=True)
    assemble_parser.add_argument("--macos-dir", type=Path, required=True)
    assemble_parser.add_argument("--root", type=Path, required=True)
    assemble_parser.add_argument("--version", required=True)
    assemble_parser.add_argument("--commit", required=True)
    assemble_parser.add_argument("--macos-verification-status", required=True)

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

    published_parser = subparsers.add_parser("verify-published")
    published_parser.add_argument("--root", type=Path, required=True)
    published_parser.add_argument("--release-json", type=Path, required=True)
    published_parser.add_argument("--version", required=True)
    published_parser.add_argument("--commit", required=True)
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
        elif args.command == "assemble":
            assemble(
                args.runtime_dir,
                args.macos_dir,
                args.root,
                args.version,
                args.commit,
                args.macos_verification_status,
            )
            print(f"release candidate assembled: {args.root}")
        elif args.command == "seal":
            seal(args.root, args.version, args.commit)
            print(f"release candidate sealed: {args.version} at {args.commit}")
        elif args.command == "verify":
            verify(args.root, args.version, args.commit)
            print(f"release candidate verified: {args.version} at {args.commit}")
        elif args.command == "list-assets":
            verify(args.root, args.version, args.commit)
            for name in published_asset_names(args.version):
                print(name)
        elif args.command == "verify-published":
            verify_published_release(args.root, args.release_json, args.version, args.commit)
            print(f"published release verified: {args.version} at {args.commit}")
        else:  # pragma: no cover - argparse enforces the subcommand set
            raise AssertionError(args.command)
    except CandidateError as exc:
        print(f"release candidate verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
