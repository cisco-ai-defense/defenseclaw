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
import hashlib
import json
import re
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = 1
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ROOT = Path(__file__).resolve().parents[1]
UPGRADE_BASELINES_PATH = ROOT / "release" / "upgrade-baselines.json"


class CandidateError(RuntimeError):
    """A release candidate is incomplete, inconsistent, or mutated."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_version(version: str) -> None:
    if not VERSION_RE.fullmatch(version):
        raise CandidateError(f"version must be X.Y.Z, got {version!r}")


def _validate_commit(commit: str) -> None:
    if not COMMIT_RE.fullmatch(commit):
        raise CandidateError(f"commit must be a full lowercase SHA-1, got {commit!r}")


def runtime_asset_names(version: str) -> tuple[str, ...]:
    _validate_version(version)
    archives = (
        f"defenseclaw_{version}_darwin_amd64.tar.gz",
        f"defenseclaw_{version}_darwin_arm64.tar.gz",
        f"defenseclaw_{version}_linux_amd64.tar.gz",
        f"defenseclaw_{version}_linux_arm64.tar.gz",
        f"defenseclaw_{version}_windows_amd64.zip",
        f"defenseclaw_{version}_windows_arm64.zip",
    )
    return tuple(
        sorted(
            (
                *archives,
                *(f"{name}.sbom.json" for name in archives),
                f"defenseclaw-{version}-py3-none-any.whl",
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


def payload_asset_names(version: str) -> tuple[str, ...]:
    return tuple(sorted((*runtime_asset_names(version), *macos_asset_names(version))))


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


def _validate_upgrade_manifest(path: Path, version: str) -> None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"invalid upgrade manifest {path}: {exc}") from exc
    if document.get("release_version") != version:
        raise CandidateError(
            f"upgrade manifest release_version={document.get('release_version')!r}; want {version!r}"
        )
    if document.get("schema_version") != 1:
        raise CandidateError("upgrade manifest schema_version must be 1")
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

    try:
        baseline_document = json.loads(UPGRADE_BASELINES_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"could not load tested upgrade baselines: {exc}") from exc
    configured = baseline_document.get("published_baselines")
    if (
        baseline_document.get("schema_version") != 1
        or not isinstance(configured, list)
        or any(not isinstance(item, str) or not VERSION_RE.fullmatch(item) for item in configured)
        or len(configured) != len(set(configured))
    ):
        raise CandidateError("tested upgrade baseline policy is invalid")
    if bridge not in configured:
        raise CandidateError(f"required bridge {bridge} is absent from the tested baseline matrix")
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


def _validate_wheel(path: Path, version: str) -> None:
    metadata_name = f"defenseclaw-{version}.dist-info/METADATA"
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
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
            if tuple(map(int, version.split("."))) >= (0, 8, 4):
                mutator_source = archive.read("defenseclaw/phase_two_mutator.py").decode(
                    "utf-8", errors="strict"
                )
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
        try:
            ast.parse(mutator_source, filename="defenseclaw/phase_two_mutator.py")
        except (SyntaxError, ValueError) as exc:
            raise CandidateError("0.8.4+ candidate wheel mutator wrapper is invalid") from exc
        functions = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for name in (
            "_prepare_hard_cut_rollback_plan",
            "_write_hard_cut_recovery_journal",
            "_recover_interrupted_hard_cut",
            "_run_phase_two_mutator",
            "_execute_hard_cut_rollback",
            "_poll_health",
        ):
            if name not in functions:
                raise CandidateError(f"0.8.4+ controller lacks required bridge capability {name}")
        if not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_prepare_hard_cut_rollback_plan"
            for node in ast.walk(tree)
        ):
            raise CandidateError("0.8.4+ controller never prepares hard-cut rollback")
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


def _validate_gateway_archives(directory: Path, version: str) -> None:
    for os_name in ("darwin", "linux"):
        for arch in ("amd64", "arm64"):
            path = directory / f"defenseclaw_{version}_{os_name}_{arch}.tar.gz"
            try:
                with tarfile.open(path, mode="r:gz") as archive:
                    members = [member for member in archive.getmembers() if member.isfile()]
            except (OSError, tarfile.TarError) as exc:
                raise CandidateError(f"invalid gateway archive {path}: {exc}") from exc
            if not any(Path(member.name).name == "defenseclaw" for member in members):
                raise CandidateError(f"gateway archive {path.name} does not contain defenseclaw")

    for arch in ("amd64", "arm64"):
        path = directory / f"defenseclaw_{version}_windows_{arch}.zip"
        try:
            with zipfile.ZipFile(path) as archive:
                names = [Path(name).name.lower() for name in archive.namelist() if not name.endswith("/")]
        except (OSError, zipfile.BadZipFile) as exc:
            raise CandidateError(f"invalid gateway archive {path}: {exc}") from exc
        if "defenseclaw.exe" not in names:
            raise CandidateError(f"gateway archive {path.name} does not contain defenseclaw.exe")


def verify_runtime(directory: Path, version: str) -> None:
    names = runtime_asset_names(version)
    _require_regular_files(directory, names, "runtime artifact")
    _validate_upgrade_manifest(directory / "upgrade-manifest.json", version)
    _validate_wheel(directory / f"defenseclaw-{version}-py3-none-any.whl", version)
    _validate_gateway_archives(directory, version)
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


def extract_gateway(release_dir: Path, output: Path, version: str, os_name: str, arch: str) -> None:
    """Safely extract one POSIX gateway from a verified candidate archive."""

    if os_name not in {"darwin", "linux"} or arch not in {"amd64", "arm64"}:
        raise CandidateError("gateway extraction supports darwin/linux and amd64/arm64")
    verify_runtime(release_dir, version)
    archive_path = release_dir / f"defenseclaw_{version}_{os_name}_{arch}.tar.gz"
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
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
    _require_regular_files(macos_dir, macos_asset_names(version), "macOS artifact")

    dist = root / "dist"
    dist.mkdir(parents=True)
    _copy_exact(runtime_dir, dist, runtime_asset_names(version))
    _copy_exact(macos_dir, dist, macos_asset_names(version))

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

    _validate_upgrade_manifest(dist / "upgrade-manifest.json", version)
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

    verify_runtime_parser = subparsers.add_parser("verify-runtime")
    verify_runtime_parser.add_argument("--release-dir", type=Path, required=True)
    verify_runtime_parser.add_argument("--version", required=True)

    stage_runtime_parser = subparsers.add_parser("stage-runtime")
    stage_runtime_parser.add_argument("--release-dir", type=Path, required=True)
    stage_runtime_parser.add_argument("--output-dir", type=Path, required=True)
    stage_runtime_parser.add_argument("--version", required=True)

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
        if args.command == "verify-runtime":
            verify_runtime(args.release_dir, args.version)
            print(f"runtime candidate verified: {args.version}")
        elif args.command == "stage-runtime":
            stage_runtime(args.release_dir, args.output_dir, args.version)
            print(f"runtime candidate staged: {args.output_dir}")
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
