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

"""Deterministic ZIP and merged SPDX support for the Windows installer.

This helper intentionally uses only the Python standard library.  The Windows
release builder executes it with the pinned embeddable CPython runtime, so ZIP
layout and SPDX generation do not depend on whichever Python happens to be on
the runner PATH.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.parse
import zipfile
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import BinaryIO

ZIP_EPOCH = 315532800  # 1980-01-01, the earliest timestamp ZIP can encode.
BUFFER_SIZE = 1024 * 1024


class ArtifactError(RuntimeError):
    """Raised when an installer artifact violates the release contract."""


def _normalized_epoch(epoch: int) -> tuple[int, int, int, int, int, int]:
    value = max(epoch, ZIP_EPOCH)
    parts = list(time.gmtime(value)[:6])
    # ZIP stores seconds at two-second resolution.  Normalize rather than let
    # individual ZIP implementations round differently.
    parts[5] -= parts[5] % 2
    return tuple(parts)  # type: ignore[return-value]


def deterministic_zip(source: Path, output: Path, epoch: int, include_root: bool) -> None:
    source = source.resolve(strict=True)
    output = output.resolve()
    if not source.is_dir():
        raise ArtifactError(f"ZIP source is not a directory: {source}")
    try:
        output.relative_to(source)
    except ValueError:
        pass
    else:
        raise ArtifactError("ZIP output must not be inside its source directory")

    entries: list[tuple[str, Path]] = []
    for candidate in source.rglob("*"):
        if candidate.is_symlink():
            raise ArtifactError(f"Refusing to archive symbolic link: {candidate}")
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(source).as_posix()
        archive_name = f"{source.name}/{relative}" if include_root else relative
        entries.append((archive_name, candidate))
    entries.sort(key=lambda item: item[0].encode("utf-8"))
    if not entries:
        raise ArtifactError(f"Cannot create an archive from an empty directory: {source}")

    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        timestamp = _normalized_epoch(epoch)
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for archive_name, candidate in entries:
                info = zipfile.ZipInfo(archive_name, date_time=timestamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.flag_bits |= 0x800  # UTF-8 names, independent of locale.
                with candidate.open("rb") as source_stream, archive.open(info, "w") as target_stream:
                    shutil.copyfileobj(source_stream, target_stream, BUFFER_SIZE)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def normalize_site_packages(root: Path) -> dict[str, int]:
    """Remove installer/cache provenance that would make a payload host-specific."""

    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ArtifactError(f"site-packages root is not a directory: {root}")
    removed_paths: set[str] = set()
    removed_bytecode = 0
    removed_local_origins = 0
    removed_uv_cache = 0

    for cache_dir in sorted(
        (path for path in root.rglob("__pycache__") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        for child in cache_dir.rglob("*"):
            if child.is_file():
                removed_paths.add(child.relative_to(root).as_posix())
                if child.suffix.lower() == ".pyc":
                    removed_bytecode += 1
        shutil.rmtree(cache_dir)
    for bytecode in sorted(root.rglob("*.pyc")):
        if not bytecode.is_file():
            continue
        removed_paths.add(bytecode.relative_to(root).as_posix())
        bytecode.unlink()
        removed_bytecode += 1

    for origin in sorted(root.glob("*.dist-info/direct_url.json")):
        try:
            direct_url = json.loads(origin.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            raise ArtifactError(f"Invalid Python direct_url metadata: {origin}") from exc
        url = direct_url.get("url")
        if not isinstance(url, str):
            raise ArtifactError(f"Python direct_url metadata has no URL: {origin}")
        if urllib.parse.urlsplit(url).scheme.lower() != "file":
            continue
        removed_paths.add(origin.relative_to(root).as_posix())
        origin.unlink()
        removed_local_origins += 1

    # uv records the installation wall clock in this non-standard cache hint.
    # It is not runtime metadata and is not part of the input wheel.
    for cache_metadata in sorted(root.glob("*.dist-info/uv_cache.json")):
        removed_paths.add(cache_metadata.relative_to(root).as_posix())
        cache_metadata.unlink()
        removed_uv_cache += 1

    rewritten_records = 0
    for record in sorted(root.glob("*.dist-info/RECORD")):
        rows = list(csv.reader(io.StringIO(record.read_text(encoding="utf-8-sig"))))
        retained = []
        changed = False
        for row in rows:
            if row and row[0].replace("\\", "/") in removed_paths:
                changed = True
                continue
            retained.append(row)
        if not changed:
            continue
        output = io.StringIO(newline="")
        csv.writer(output, lineterminator="\n").writerows(retained)
        record.write_text(output.getvalue(), encoding="utf-8", newline="\n")
        rewritten_records += 1

    leftovers = [path for path in root.rglob("*") if path.is_file() and path.suffix.lower() == ".pyc"]
    if leftovers:
        raise ArtifactError(f"Python bytecode remained after normalization: {leftovers[0]}")
    for origin in root.glob("*.dist-info/direct_url.json"):
        direct_url = json.loads(origin.read_text(encoding="utf-8-sig"))
        if urllib.parse.urlsplit(str(direct_url.get("url", ""))).scheme.lower() == "file":
            raise ArtifactError(f"Local build path remained in Python direct_url metadata: {origin}")

    return {
        "removed_bytecode": removed_bytecode,
        "removed_local_origins": removed_local_origins,
        "removed_uv_cache": removed_uv_cache,
        "rewritten_records": rewritten_records,
    }


def _parse_go_build_info(output: str) -> dict:
    lines = output.splitlines()
    if not lines:
        raise ArtifactError("go version -m returned no build information")
    runtime_match = re.search(r":\s+(go\d+(?:\.\d+)+(?:[^\s]*)?)\s*$", lines[0])
    if not runtime_match:
        raise ArtifactError(f"go version -m did not report a Go runtime: {lines[0]!r}")
    module_path = None
    module_version = None
    dependencies = []
    for line in lines[1:]:
        fields = line.strip().split("\t")
        if not fields:
            continue
        if fields[0] == "mod" and len(fields) >= 3:
            module_path, module_version = fields[1], fields[2]
        elif fields[0] == "dep" and len(fields) >= 3:
            dependencies.append(
                {
                    "path": fields[1],
                    "version": fields[2],
                    "sum": fields[3] if len(fields) >= 4 else None,
                }
            )
    if not module_path:
        raise ArtifactError("go version -m did not report the main module")
    dependencies.sort(key=lambda item: (item["path"], item["version"], item["sum"] or ""))
    return {
        "runtime": runtime_match.group(1),
        "module": {"path": module_path, "version": module_version},
        "dependencies": dependencies,
    }


def create_go_inventory(go_executable: Path, output: Path, components: list[str]) -> dict:
    go_executable = go_executable.resolve(strict=True)
    parsed_components: dict[str, Path] = {}
    for value in components:
        if "=" not in value:
            raise ArtifactError(f"Go component must be LABEL=PATH: {value!r}")
        label, raw_path = value.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9-]*", label) or label in parsed_components:
            raise ArtifactError(f"Invalid or duplicate Go component label: {label!r}")
        parsed_components[label] = Path(raw_path).resolve(strict=True)
    if not parsed_components:
        raise ArtifactError("Go module inventory requires at least one component")

    inventory = {"schema_version": 1, "components": {}}
    for label, path in sorted(parsed_components.items()):
        result = subprocess.run(
            [str(go_executable), "version", "-m", str(path)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
        )
        if result.returncode != 0:
            raise ArtifactError(f"go version -m failed for {label}: {result.stderr.strip()}")
        build_info = _parse_go_build_info(result.stdout)
        build_info["sha256"] = _file_digests(path)[0]
        inventory["components"][label] = build_info

    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return {"output": str(output), "components": len(parsed_components)}


def _digests(stream: BinaryIO) -> tuple[str, str]:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()  # noqa: S324 - mandated by SPDX package verification code.
    while chunk := stream.read(BUFFER_SIZE):
        sha256.update(chunk)
        sha1.update(chunk)
    return sha256.hexdigest(), sha1.hexdigest()


def _file_digests(path: Path) -> tuple[str, str]:
    with path.open("rb") as stream:
        return _digests(stream)


def _safe_archive_name(raw_name: str) -> str:
    name = raw_name.replace("\\", "/")
    if not name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise ArtifactError(f"Unsafe absolute archive member: {raw_name!r}")
    path = PurePosixPath(name)
    if any(part in ("", ".", "..") for part in path.parts):
        raise ArtifactError(f"Unsafe archive member: {raw_name!r}")
    return path.as_posix()


def _canonical_distribution(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _spdx_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-.")
    return slug[:64] or "item"


def _spdx_id(kind: str, identity: str) -> str:
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    return f"SPDXRef-{kind}-{_spdx_slug(identity)}-{digest}"


def _file_type(name: str) -> str:
    lower = name.lower()
    if lower.endswith((".exe", ".dll", ".pyd")):
        return "BINARY"
    if lower.endswith((".zip", ".whl")):
        return "ARCHIVE"
    if lower.endswith((".py", ".go", ".ps1", ".sh", ".c", ".h")):
        return "SOURCE"
    return "TEXT"


LICENSE_MAP = {
    "apache software license": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "bsd license": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "isc license": "ISC",
    "mit": "MIT",
    "mit license": "MIT",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "mpl-2.0": "MPL-2.0",
    "python software foundation license": "PSF-2.0",
    "the unlicense (unlicense)": "Unlicense",
}


CLASSIFIER_LICENSE_MAP = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
}


def _declared_license(metadata) -> tuple[str, str | None]:
    expression = (metadata.get("License-Expression") or "").strip()
    if expression and re.fullmatch(r"[A-Za-z0-9.+()\- ]+(?:\s(?:AND|OR|WITH)\s[A-Za-z0-9.+()\- ]+)*", expression):
        return expression, None
    license_text = (metadata.get("License") or "").strip()
    mapped = LICENSE_MAP.get(license_text.lower())
    if mapped:
        return mapped, None
    for classifier in metadata.get_all("Classifier", []):
        if classifier in CLASSIFIER_LICENSE_MAP:
            return CLASSIFIER_LICENSE_MAP[classifier], None
    return "NOASSERTION", license_text or None


class SpdxDocument:
    def __init__(self, name: str, namespace: str, created: str, source_commit: str):
        self.name = name
        self.namespace = namespace
        self.created = created
        self.source_commit = source_commit
        self.files: dict[str, dict] = {}
        self.file_sha1: dict[str, str] = {}
        self.packages: dict[str, dict] = {}
        self.package_files: dict[str, set[str]] = defaultdict(set)
        self.relationships: set[tuple[str, str, str]] = set()
        self.described: list[str] = []

    def add_file(self, logical_name: str, sha256: str, sha1: str) -> str:
        if not logical_name.startswith("./"):
            raise ArtifactError(f"SPDX file name must be relative: {logical_name}")
        file_id = _spdx_id("File", logical_name)
        existing = self.files.get(file_id)
        record = {
            "SPDXID": file_id,
            "fileName": logical_name,
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": sha1},
                {"algorithm": "SHA256", "checksumValue": sha256},
            ],
            "fileTypes": [_file_type(logical_name)],
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        if existing is not None and existing != record:
            raise ArtifactError(f"Conflicting SPDX file identity: {logical_name}")
        self.files[file_id] = record
        self.file_sha1[file_id] = sha1
        return file_id

    def add_path_file(self, logical_name: str, path: Path) -> str:
        sha256, sha1 = _file_digests(path)
        return self.add_file(logical_name, sha256, sha1)

    def add_package(
        self,
        identity: str,
        name: str,
        version: str | None,
        purpose: str,
        checksum: str | None = None,
        package_file_name: str | None = None,
        license_declared: str = "NOASSERTION",
        license_comment: str | None = None,
        purl: str | None = None,
        files_analyzed: bool = True,
    ) -> str:
        package_id = _spdx_id("Package", identity)
        record = {
            "SPDXID": package_id,
            "name": name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": files_analyzed,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": license_declared,
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": purpose,
        }
        if version:
            record["versionInfo"] = version
        if checksum:
            record["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
        if package_file_name:
            record["packageFileName"] = package_file_name
        if license_comment:
            record["licenseComments"] = f"Python metadata license field: {license_comment}"
        if purl:
            record["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                }
            ]
        existing = self.packages.get(package_id)
        if existing is not None and existing != record:
            raise ArtifactError(f"Conflicting SPDX package identity: {identity}")
        self.packages[package_id] = record
        return package_id

    def relate(self, source: str, relationship: str, target: str) -> None:
        self.relationships.add((source, relationship, target))

    def contains_file(self, package_id: str, file_id: str) -> None:
        self.package_files[package_id].add(file_id)
        self.relate(package_id, "CONTAINS", file_id)

    def render(self) -> dict:
        for package_id, package in self.packages.items():
            hashes = sorted(self.file_sha1[file_id] for file_id in self.package_files[package_id])
            if not hashes and package["filesAnalyzed"]:
                raise ArtifactError(f"SPDX package has no analyzed files: {package['name']}")
            if hashes:
                verification = hashlib.sha1("".join(hashes).encode("ascii")).hexdigest()  # noqa: S324
                package["packageVerificationCode"] = {"packageVerificationCodeValue": verification}

        document = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self.name,
            "documentNamespace": self.namespace,
            "comment": f"DefenseClaw source commit: {self.source_commit}",
            "creationInfo": {
                "created": self.created,
                "creators": [
                    "Organization: Cisco Systems, Inc.",
                    "Tool: DefenseClaw Windows installer SBOM generator",
                ],
                "licenseListVersion": "3.25",
            },
            "documentDescribes": sorted(self.described),
            "packages": sorted(self.packages.values(), key=lambda item: item["SPDXID"]),
            "files": sorted(self.files.values(), key=lambda item: item["fileName"].encode("utf-8")),
            "relationships": [
                {
                    "spdxElementId": source,
                    "relationshipType": relationship,
                    "relatedSpdxElement": target,
                }
                for source, relationship, target in sorted(self.relationships)
            ],
        }
        self.validate(document)
        return document

    @staticmethod
    def validate(document: dict) -> None:
        if document.get("spdxVersion") != "SPDX-2.3" or document.get("dataLicense") != "CC0-1.0":
            raise ArtifactError("Generated document is not SPDX 2.3 JSON")
        packages = document.get("packages") or []
        files = document.get("files") or []
        identifiers = {"SPDXRef-DOCUMENT"}
        for element in [*packages, *files]:
            identifier = element.get("SPDXID")
            if not isinstance(identifier, str) or identifier in identifiers:
                raise ArtifactError(f"Duplicate or invalid SPDX identifier: {identifier!r}")
            identifiers.add(identifier)
        for relationship in document.get("relationships") or []:
            if relationship.get("spdxElementId") not in identifiers:
                raise ArtifactError("SPDX relationship has an unknown source")
            if relationship.get("relatedSpdxElement") not in identifiers:
                raise ArtifactError("SPDX relationship has an unknown target")
        described = document.get("documentDescribes") or []
        if len(described) != 1 or described[0] not in identifiers:
            raise ArtifactError("SPDX document must describe exactly one setup package")


def _attach_authenticode_evidence(document: SpdxDocument, inventory_path: Path, payload_manifest: dict) -> int:
    inventory = json.loads(inventory_path.resolve(strict=True).read_text(encoding="utf-8-sig"))
    files = inventory.get("files")
    if inventory.get("schema_version") != 1 or not isinstance(files, dict) or not files:
        raise ArtifactError("Authenticode inventory is missing or unsupported")
    payload_inventory = payload_manifest.get("authenticode")
    payload_files = payload_inventory.get("files") if isinstance(payload_inventory, dict) else None
    payload_inventory_schema = payload_inventory.get("schema_version") if isinstance(payload_inventory, dict) else None
    if (
        payload_manifest.get("schema_version") != 2
        or payload_inventory_schema != 1
        or not isinstance(payload_files, dict)
        or not payload_files
    ):
        raise ArtifactError("Payload manifest lacks the required Authenticode inventory")
    expected_release_paths = {"DefenseClawSetup-x64.exe", *payload_files}
    if set(files) != expected_release_paths:
        raise ArtifactError("Release and payload Authenticode inventory paths differ")
    if any(files[name] != evidence for name, evidence in payload_files.items()):
        raise ArtifactError("Release and payload Authenticode evidence differ")

    grouped: dict[str, list[dict]] = defaultdict(list)
    for installed_path, evidence in sorted(files.items()):
        installed_identity = PurePosixPath(installed_path) if isinstance(installed_path, str) else None
        if (
            installed_identity is None
            or not installed_path
            or not installed_path.isascii()
            or "\\" in installed_path
            or ":" in installed_path
            or installed_identity.is_absolute()
            or installed_identity.as_posix() != installed_path
            or any(part in {"", ".", ".."} for part in installed_identity.parts)
        ):
            raise ArtifactError(f"Invalid Authenticode installed path {installed_path!r}")
        if not isinstance(evidence, dict) or evidence.get("schema_version") != 1:
            raise ArtifactError(f"Invalid Authenticode evidence for {installed_path!r}")
        if evidence.get("installed_path") != installed_path:
            raise ArtifactError(f"Authenticode installed path mismatch for {installed_path!r}")
        sbom_name = evidence.get("sbom_file_name")
        if (
            not isinstance(sbom_name, str)
            or not sbom_name.startswith("./")
            or not sbom_name[2:]
            or not sbom_name.isascii()
            or "\\" in sbom_name
            or ":" in sbom_name
            or PurePosixPath(sbom_name[2:]).as_posix() != sbom_name[2:]
            or any(part in {"", ".", ".."} for part in PurePosixPath(sbom_name[2:]).parts)
        ):
            raise ArtifactError(f"Invalid Authenticode SPDX file identity for {installed_path!r}")
        digest = evidence.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ArtifactError(f"Invalid Authenticode SHA-256 for {installed_path!r}")
        if not isinstance(evidence.get("expected"), dict) or not isinstance(evidence.get("observed"), dict):
            raise ArtifactError(f"Incomplete Authenticode policy evidence for {installed_path!r}")
        grouped[sbom_name].append(evidence)

    if "./DefenseClawSetup-x64.exe" not in grouped:
        raise ArtifactError("Authenticode inventory omits the outer Setup executable")
    by_name = {record["fileName"]: record for record in document.files.values()}
    for sbom_name, evidence_list in sorted(grouped.items()):
        record = by_name.get(sbom_name)
        if record is None:
            raise ArtifactError(f"Authenticode evidence names an absent SPDX file: {sbom_name}")
        spdx_sha256 = next(
            (item["checksumValue"] for item in record["checksums"] if item.get("algorithm") == "SHA256"),
            None,
        )
        if any(item["sha256"] != spdx_sha256 for item in evidence_list):
            raise ArtifactError(f"Authenticode evidence digest does not match SPDX file: {sbom_name}")
        record["comment"] = "DefenseClaw Authenticode evidence: " + json.dumps(
            evidence_list, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    return len(files)


def _archive_entries(
    document: SpdxDocument,
    archive_path: Path,
    logical_prefix: str,
    package_id: str,
    required: Iterable[str] = (),
) -> dict[str, tuple[str, str, str]]:
    with zipfile.ZipFile(archive_path, "r") as archive:
        return _zip_entries(document, archive, logical_prefix, package_id, required)


def _zip_entries(
    document: SpdxDocument,
    archive: zipfile.ZipFile,
    logical_prefix: str,
    package_id: str,
    required: Iterable[str] = (),
) -> dict[str, tuple[str, str, str]]:
    indexed: dict[str, zipfile.ZipInfo] = {}
    casefolded: set[str] = set()
    for info in archive.infolist():
        if info.is_dir():
            continue
        name = _safe_archive_name(info.filename)
        folded = name.casefold()
        if folded in casefolded:
            raise ArtifactError(f"Archive has duplicate Windows path: {name}")
        casefolded.add(folded)
        indexed[name] = info
    missing = sorted(set(required) - set(indexed))
    if missing:
        raise ArtifactError(f"Archive {archive.filename!s} is missing: {', '.join(missing)}")

    result: dict[str, tuple[str, str, str]] = {}
    for name in sorted(indexed, key=lambda value: value.encode("utf-8")):
        with archive.open(indexed[name], "r") as stream:
            sha256, sha1 = _digests(stream)
        logical_name = f"{logical_prefix.rstrip('/')}/{name}"
        file_id = document.add_file(logical_name, sha256, sha1)
        document.contains_file(package_id, file_id)
        result[name] = (file_id, sha256, sha1)
    return result


def _read_archive_member(path: Path, member: str) -> bytes:
    with zipfile.ZipFile(path, "r") as archive:
        return archive.read(member)


def _payload_contract(
    payload_root: Path, embedded_payload: Path, manifest: dict
) -> tuple[dict[str, Path], dict[str, str]]:
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ArtifactError("Payload manifest has no digest map")
    children = list(payload_root.iterdir())
    unexpected = sorted(path.name for path in children if not path.is_file())
    if unexpected:
        raise ArtifactError(f"Payload root contains non-file entries: {unexpected}")
    actual = {path.name: path for path in children if path.name != "manifest.json"}
    if set(actual) != set(files):
        missing = sorted(set(files) - set(actual))
        extra = sorted(set(actual) - set(files))
        raise ArtifactError(f"Payload digest coverage mismatch; missing={missing}, extra={extra}")

    digests: dict[str, str] = {}
    for name, path in sorted(actual.items()):
        digest, _ = _file_digests(path)
        expected = str(files[name]).lower()
        if digest != expected:
            raise ArtifactError(f"Payload digest mismatch for {name}: {digest} != {expected}")
        digests[name] = digest

    expected_embedded = {f"payload/{name}": path for name, path in actual.items()}
    expected_embedded["payload/manifest.json"] = payload_root / "manifest.json"
    with zipfile.ZipFile(embedded_payload, "r") as archive:
        members = {}
        casefolded = set()
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = _safe_archive_name(info.filename)
            if name.casefold() in casefolded:
                raise ArtifactError(f"Embedded payload has a duplicate Windows path: {name}")
            casefolded.add(name.casefold())
            members[name] = info
        if set(members) != set(expected_embedded):
            raise ArtifactError("Embedded payload archive does not exactly match the staged payload")
        for name, source in expected_embedded.items():
            with archive.open(members[name], "r") as embedded_stream:
                embedded_sha256, _ = _digests(embedded_stream)
            source_sha256, _ = _file_digests(source)
            if embedded_sha256 != source_sha256:
                raise ArtifactError(f"Embedded payload content differs for {name}")
    return actual, digests


def _required_payload_names(manifest: dict) -> dict[str, str]:
    properties = (
        "gateway_archive",
        "wheel",
        "python_embed",
        "yara_compat_wheel",
        "upgrade_manifest",
        "site_packages",
        "launcher",
        "startup_launcher",
        "cosign_verifier",
    )
    result: dict[str, str] = {}
    for prop in properties:
        value = manifest.get(prop)
        if not isinstance(value, str) or not value or Path(value).name != value:
            raise ArtifactError(f"Payload manifest has invalid {prop}")
        result[prop] = value
    return result


def _python_distributions(
    document: SpdxDocument,
    site_archive: Path,
    site_package_id: str,
    entries: dict[str, tuple[str, str, str]],
) -> dict[str, str]:
    roots: dict[str, list[str]] = defaultdict(list)
    for name in entries:
        first = name.split("/", 1)[0]
        if re.search(r"\.(?:dist-info|egg-info)$", first, flags=re.IGNORECASE):
            roots[first].append(name)
    if not roots:
        raise ArtifactError("Embedded site-packages has no Python distribution metadata")

    distributions: dict[str, str] = {}
    with zipfile.ZipFile(site_archive, "r") as archive:
        names = {_safe_archive_name(info.filename): info for info in archive.infolist() if not info.is_dir()}
        for root in sorted(roots, key=lambda value: value.encode("utf-8")):
            candidates = [name for name in (f"{root}/METADATA", f"{root}/PKG-INFO") if name in names]
            if len(candidates) != 1:
                raise ArtifactError(f"Python distribution {root} must contain exactly one metadata file")
            metadata_name = candidates[0]
            metadata = BytesParser(policy=policy.default).parsebytes(archive.read(names[metadata_name]))
            name = (metadata.get("Name") or "").strip()
            version = (metadata.get("Version") or "").strip()
            if not name or not version:
                raise ArtifactError(f"Python distribution metadata is missing Name/Version: {metadata_name}")
            canonical = _canonical_distribution(name)
            if canonical in distributions:
                raise ArtifactError(f"Duplicate embedded Python distribution: {name}")
            license_declared, license_comment = _declared_license(metadata)
            purl_name = urllib.parse.quote(canonical, safe="-._~")
            purl_version = urllib.parse.quote(version, safe="-._~+!")
            package_id = document.add_package(
                f"python-distribution:{canonical}@{version}",
                name,
                version,
                "LIBRARY",
                license_declared=license_declared,
                license_comment=license_comment,
                purl=f"pkg:pypi/{purl_name}@{purl_version}",
            )
            document.relate(package_id, "EXPANDED_FROM_ARCHIVE", site_package_id)
            distributions[canonical] = package_id

            owned_names = set(roots[root])
            record_name = f"{root}/RECORD"
            if record_name in names:
                record_text = archive.read(names[record_name]).decode("utf-8-sig")
                for row in csv.reader(io.StringIO(record_text)):
                    if not row:
                        continue
                    try:
                        record_path = _safe_archive_name(row[0])
                    except ArtifactError:
                        # Console scripts may be installed outside the target
                        # site-packages root; the archive-level package still
                        # covers every file actually embedded.
                        continue
                    if record_path in entries:
                        owned_names.add(record_path)
            for owned_name in sorted(owned_names):
                document.contains_file(package_id, entries[owned_name][0])

        # Parse dependency headers again now that all installed names are known.
        for root in sorted(roots):
            metadata_name = next(name for name in (f"{root}/METADATA", f"{root}/PKG-INFO") if name in names)
            metadata = BytesParser(policy=policy.default).parsebytes(archive.read(names[metadata_name]))
            source = distributions[_canonical_distribution(str(metadata["Name"]))]
            for requirement in metadata.get_all("Requires-Dist", []):
                match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
                if not match:
                    continue
                target = distributions.get(_canonical_distribution(match.group(1)))
                if target and target != source:
                    document.relate(source, "DEPENDS_ON", target)

    for required in ("defenseclaw", "yara-python"):
        if required not in distributions:
            raise ArtifactError(f"Required embedded Python distribution is missing: {required}")
    return distributions


def _go_sum_sha256(value: str | None) -> str | None:
    if not value or not value.startswith("h1:"):
        return None
    try:
        digest = base64.b64decode(value[3:], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ArtifactError(f"Invalid Go module sum: {value}") from exc
    if len(digest) != 32:
        raise ArtifactError(f"Go module sum is not SHA-256: {value}")
    return digest.hex()


def _add_go_inventory(
    document: SpdxDocument,
    inventory_path: Path,
    component_packages: dict[str, str],
) -> int:
    inventory = json.loads(inventory_path.read_text(encoding="utf-8-sig"))
    if inventory.get("schema_version") != 1 or not isinstance(inventory.get("components"), dict):
        raise ArtifactError("Go component inventory has an invalid schema")
    components = inventory["components"]
    if set(components) != set(component_packages):
        raise ArtifactError(
            f"Go component inventory coverage mismatch; expected={sorted(component_packages)}, "
            f"actual={sorted(components)}"
        )

    module_ids: set[str] = set()
    for label, package_id in sorted(component_packages.items()):
        component = components[label]
        expected_hashes = {
            checksum["checksumValue"]
            for checksum in document.packages[package_id].get("checksums", [])
            if checksum.get("algorithm") == "SHA256"
        }
        if component.get("sha256") not in expected_hashes:
            raise ArtifactError(f"Go inventory binary digest does not match the SPDX component: {label}")
        runtime = component.get("runtime")
        if not isinstance(runtime, str) or not re.fullmatch(r"go\d+(?:\.\d+)+(?:[^\s]*)?", runtime):
            raise ArtifactError(f"Go inventory runtime is invalid for {label}")
        runtime_version = runtime.removeprefix("go")
        runtime_id = document.add_package(
            f"go-runtime:{runtime_version}",
            "Go standard library",
            runtime_version,
            "LIBRARY",
            purl=f"pkg:golang/stdlib@{urllib.parse.quote(runtime_version, safe='-._~')}",
            files_analyzed=False,
        )
        module_ids.add(runtime_id)
        document.relate(package_id, "DEPENDS_ON", runtime_id)

        dependencies = component.get("dependencies")
        if not isinstance(dependencies, list):
            raise ArtifactError(f"Go inventory dependencies are invalid for {label}")
        for dependency in dependencies:
            path = dependency.get("path")
            version = dependency.get("version")
            if not isinstance(path, str) or not path or not isinstance(version, str) or not version:
                raise ArtifactError(f"Go inventory dependency is invalid for {label}")
            purl_path = urllib.parse.quote(path, safe="/-._~")
            purl_version = urllib.parse.quote(version, safe="-._~+")
            module_id = document.add_package(
                f"go-module:{path}@{version}",
                path,
                version,
                "LIBRARY",
                checksum=_go_sum_sha256(dependency.get("sum")),
                purl=f"pkg:golang/{purl_path}@{purl_version}",
                files_analyzed=False,
            )
            module_ids.add(module_id)
            document.relate(package_id, "DEPENDS_ON", module_id)
    return len(module_ids)


def build_sbom(args: argparse.Namespace) -> dict:
    setup = args.setup.resolve(strict=True)
    payload_root = args.payload_root.resolve(strict=True)
    embedded_payload = args.embedded_payload.resolve(strict=True)
    output = args.output.resolve()
    if not payload_root.is_dir():
        raise ArtifactError(f"Payload root is not a directory: {payload_root}")
    manifest_path = payload_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if manifest.get("version") != args.version:
        raise ArtifactError("Payload manifest version does not match the SBOM version")
    if manifest.get("source_commit") != args.source_commit:
        raise ArtifactError("Payload manifest source commit does not match the SBOM source commit")
    if manifest.get("python_version") != args.python_version:
        raise ArtifactError("Payload manifest CPython version does not match the SBOM version")

    payload_files, payload_digests = _payload_contract(payload_root, embedded_payload, manifest)
    required = _required_payload_names(manifest)
    for prop, name in required.items():
        if name not in payload_files:
            raise ArtifactError(f"Required payload component is absent ({prop}): {name}")
    if "requirements-release.txt" not in payload_files:
        raise ArtifactError("Required locked Python requirements are absent")

    setup_sha256, setup_sha1 = _file_digests(setup)
    embedded_sha256, embedded_sha1 = _file_digests(embedded_payload)
    created = (
        datetime.fromtimestamp(args.source_epoch, timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    namespace = (
        "https://github.com/cisco-ai-defense/defenseclaw/"
        f"spdx/windows/{urllib.parse.quote(args.version, safe='-._~')}/{setup_sha256}"
    )
    document = SpdxDocument(
        f"DefenseClawSetup-x64.exe-{args.version}", namespace, created, args.source_commit
    )

    setup_id = document.add_package(
        "windows-setup",
        "DefenseClaw Windows Setup",
        args.version,
        "INSTALL",
        checksum=setup_sha256,
        package_file_name=setup.name,
        license_declared="Apache-2.0",
        purl=f"pkg:github/cisco-ai-defense/defenseclaw@{urllib.parse.quote(args.version, safe='-._~')}",
    )
    setup_file_id = document.add_file(f"./{setup.name}", setup_sha256, setup_sha1)
    document.contains_file(setup_id, setup_file_id)
    document.described.append(setup_id)
    document.relate("SPDXRef-DOCUMENT", "DESCRIBES", setup_id)

    embedded_id = document.add_package(
        "embedded-installer-payload",
        "DefenseClaw embedded installer payload",
        args.version,
        "ARCHIVE",
        checksum=embedded_sha256,
        package_file_name=embedded_payload.name,
        license_declared="Apache-2.0",
    )
    embedded_file_id = document.add_file("./embedded/installer-payload.zip", embedded_sha256, embedded_sha1)
    document.contains_file(embedded_id, embedded_file_id)
    document.relate(setup_id, "CONTAINS", embedded_id)

    specialized = {
        required["gateway_archive"]: ("DefenseClaw signed gateway archive", "ARCHIVE", args.version),
        required["wheel"]: ("DefenseClaw Python wheel", "LIBRARY", args.version),
        required["python_embed"]: ("CPython embeddable runtime", "APPLICATION", args.python_version),
        required["yara_compat_wheel"]: ("DefenseClaw YARA Python compatibility wheel", "LIBRARY", None),
        required["site_packages"]: ("DefenseClaw embedded Python site-packages", "LIBRARY", args.version),
        required["launcher"]: ("DefenseClaw native CLI launcher", "APPLICATION", args.version),
        required["startup_launcher"]: ("DefenseClaw native startup launcher", "APPLICATION", args.version),
        required["cosign_verifier"]: ("Sigstore Cosign verifier", "APPLICATION", args.cosign_version),
        required["upgrade_manifest"]: ("DefenseClaw upgrade manifest", "FILE", args.version),
        "requirements-release.txt": ("DefenseClaw locked Python requirements", "FILE", args.version),
        "manifest.json": ("DefenseClaw installer payload manifest", "FILE", args.version),
    }
    component_paths = dict(payload_files)
    component_paths["manifest.json"] = manifest_path
    defenseclaw_purl = f"pkg:github/cisco-ai-defense/defenseclaw@{urllib.parse.quote(args.version, safe='-._~')}"
    component_purls = {
        required["gateway_archive"]: defenseclaw_purl,
        required["wheel"]: f"pkg:pypi/defenseclaw@{urllib.parse.quote(args.version, safe='-._~')}",
        required["python_embed"]: f"pkg:generic/cpython@{urllib.parse.quote(args.python_version, safe='-._~')}",
        required["yara_compat_wheel"]: "pkg:pypi/yara-python@4.5.4.post1",
        required["site_packages"]: defenseclaw_purl,
        required["launcher"]: defenseclaw_purl,
        required["startup_launcher"]: defenseclaw_purl,
        required["cosign_verifier"]: (
            f"pkg:github/sigstore/cosign@v{urllib.parse.quote(args.cosign_version, safe='-._~')}"
        ),
    }
    component_licenses = {name: "Apache-2.0" for name in component_paths}
    component_licenses[required["python_embed"]] = "PSF-2.0"
    component_packages: dict[str, str] = {}
    for name, path in sorted(component_paths.items()):
        sha256, sha1 = _file_digests(path)
        component_name, purpose, component_version = specialized.get(
            name, (f"DefenseClaw payload component {name}", "FILE", args.version)
        )
        package_id = document.add_package(
            f"payload:{name}",
            component_name,
            component_version,
            purpose,
            checksum=sha256,
            package_file_name=name,
            license_declared=component_licenses[name],
            purl=component_purls.get(name),
        )
        file_id = document.add_file(f"./payload/{name}", sha256, sha1)
        document.contains_file(package_id, file_id)
        document.relate(embedded_id, "CONTAINS", package_id)
        component_packages[name] = package_id

    go_component_packages = {
        "setup": setup_id,
        "launcher": component_packages[required["launcher"]],
        "startup-launcher": component_packages[required["startup_launcher"]],
        "cosign": component_packages[required["cosign_verifier"]],
    }

    python_archive = payload_files[required["python_embed"]]
    python_entries = _archive_entries(
        document,
        python_archive,
        "./expanded/python",
        component_packages[required["python_embed"]],
        required=("python.exe",),
    )
    stdlib_archives = [name for name in python_entries if re.fullmatch(r"python\d+\.zip", name, re.IGNORECASE)]
    if len(stdlib_archives) != 1:
        raise ArtifactError("CPython embeddable archive must contain exactly one standard-library ZIP")
    with zipfile.ZipFile(python_archive, "r") as archive:
        stdlib_bytes = archive.read(stdlib_archives[0])
    with zipfile.ZipFile(io.BytesIO(stdlib_bytes), "r") as stdlib:
        _zip_entries(
            document,
            stdlib,
            "./expanded/python/stdlib",
            component_packages[required["python_embed"]],
        )

    gateway_entries = _archive_entries(
        document,
        payload_files[required["gateway_archive"]],
        "./expanded/gateway",
        component_packages[required["gateway_archive"]],
        required=("defenseclaw.exe", "defenseclaw-hook.exe"),
    )
    for member, display_name in (
        ("defenseclaw.exe", "DefenseClaw gateway executable"),
        ("defenseclaw-hook.exe", "DefenseClaw hook executable"),
    ):
        file_id, sha256, _ = gateway_entries[member]
        package_id = document.add_package(
            f"gateway-member:{member}",
            display_name,
            args.version,
            "APPLICATION",
            checksum=sha256,
            package_file_name=member,
            license_declared="Apache-2.0",
            purl=defenseclaw_purl,
        )
        document.contains_file(package_id, file_id)
        document.relate(package_id, "EXPANDED_FROM_ARCHIVE", component_packages[required["gateway_archive"]])
        go_component_packages["hook" if member == "defenseclaw-hook.exe" else "gateway"] = package_id

    for prop, prefix in (
        ("wheel", "./expanded/wheels/defenseclaw"),
        ("yara_compat_wheel", "./expanded/wheels/yara-compat"),
    ):
        name = required[prop]
        _archive_entries(document, payload_files[name], prefix, component_packages[name], required=())

    site_name = required["site_packages"]
    site_entries = _archive_entries(
        document,
        payload_files[site_name],
        "./expanded/site-packages",
        component_packages[site_name],
    )
    distributions = _python_distributions(
        document,
        payload_files[site_name],
        component_packages[site_name],
        site_entries,
    )
    go_modules = _add_go_inventory(document, args.go_inventory.resolve(strict=True), go_component_packages)

    # Fail closed if any exact payload digest is absent from the generated
    # package inventory.  This is the binding between expanded components and
    # the bytes actually embedded in the signed outer executable.
    package_checksums = {
        checksum["checksumValue"]
        for package in document.packages.values()
        for checksum in package.get("checksums", [])
        if checksum.get("algorithm") == "SHA256"
    }
    missing_digests = sorted(set(payload_digests.values()) - package_checksums)
    if missing_digests:
        raise ArtifactError(f"SPDX document omitted payload digests: {missing_digests}")

    authenticode_files = _attach_authenticode_evidence(document, args.authenticode_inventory, manifest)
    rendered = document.render()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(rendered, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "output": str(output),
        "setup_sha256": setup_sha256,
        "embedded_payload_sha256": embedded_sha256,
        "packages": len(rendered["packages"]),
        "files": len(rendered["files"]),
        "python_distributions": len(distributions),
        "go_modules": go_modules,
        "payload_digests": len(payload_digests),
        "authenticode_files": authenticode_files,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    zip_parser = subparsers.add_parser("zip", help="create a deterministic ZIP archive")
    zip_parser.add_argument("--source", type=Path, required=True)
    zip_parser.add_argument("--output", type=Path, required=True)
    zip_parser.add_argument("--epoch", type=int, required=True)
    zip_parser.add_argument("--include-root", action="store_true")

    normalize_parser = subparsers.add_parser(
        "normalize-site", help="remove host-specific cache/provenance from site-packages"
    )
    normalize_parser.add_argument("--root", type=Path, required=True)

    go_parser = subparsers.add_parser("go-inventory", help="inventory Go modules in exact payload binaries")
    go_parser.add_argument("--go", type=Path, required=True)
    go_parser.add_argument("--output", type=Path, required=True)
    go_parser.add_argument("--component", action="append", required=True)

    sbom_parser = subparsers.add_parser("sbom", help="generate and validate the merged installer SPDX document")
    sbom_parser.add_argument("--setup", type=Path, required=True)
    sbom_parser.add_argument("--payload-root", type=Path, required=True)
    sbom_parser.add_argument("--embedded-payload", type=Path, required=True)
    sbom_parser.add_argument("--output", type=Path, required=True)
    sbom_parser.add_argument("--version", required=True)
    sbom_parser.add_argument("--source-commit", required=True)
    sbom_parser.add_argument("--source-epoch", type=int, required=True)
    sbom_parser.add_argument("--python-version", required=True)
    sbom_parser.add_argument("--cosign-version", required=True)
    sbom_parser.add_argument("--go-inventory", type=Path, required=True)
    sbom_parser.add_argument("--authenticode-inventory", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "zip":
            deterministic_zip(args.source, args.output, args.epoch, args.include_root)
            result = {"output": str(args.output.resolve()), "sha256": _file_digests(args.output)[0]}
        elif args.command == "normalize-site":
            result = normalize_site_packages(args.root)
        elif args.command == "go-inventory":
            result = create_go_inventory(args.go, args.output, args.component)
        else:
            if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
                raise ArtifactError("Source commit must be a lowercase 40-character Git object ID")
            result = build_sbom(args)
    except (ArtifactError, OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        raise SystemExit(f"windows installer artifact error: {exc}") from exc
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
