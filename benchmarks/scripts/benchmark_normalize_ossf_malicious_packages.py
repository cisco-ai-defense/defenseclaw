#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize the exact pinned OpenSSF malicious-package report index.

The source owns a package-level malicious label, not proof that an arbitrary
install command is malicious.  Active reports are therefore emitted as
development-only, contextual plugin facts.  Narrative details, references,
contacts, indicators, package contents, and version strings are excluded.
Withdrawn and unmergable reports are counted but never emitted as positives.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

SCHEMA_VERSION = "1"
ADAPTER = "ossf-malicious-package-reports-v1"
DATASET_ID = "ossf-malicious-packages"
SOURCE_URL = "https://github.com/ossf/malicious-packages.git"
SOURCE_REVISION = "de3a859ea74ab1a4701902937140ae4f496c6a28"
SOURCE_LICENSE = "Apache-2.0"
SOURCE_REDISTRIBUTION = "download-only"
SOURCE_OSV_TREE = "64df065c0aeed6a82e21226cd65956d59872e071"
SOURCE_INDEX_SHA256 = "69ab731a43d7ab85ff1fa63426bff7fbffe77321b4ef4aaf418584b13b059d0d"
LICENSE_SHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
README_SHA256 = "da23130403a5e2efec9e9a27b4c6e6cdc68fc697b0a527c1c6e824cdb48042c3"
INCLUDE_PATHS = ("LICENSE", "README.md", "osv")
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_AFFECTED = 64
MAX_VERSIONS = 65_536
MAX_RANGES = 4_096
MAX_RANGE_EVENTS = 65_536
SAFE_REPORT_ID = re.compile(r"^MAL-[0-9]{4}-[0-9]+$")
SAFE_ECOSYSTEM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+/-]{0,79}$")
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"


class ProjectionError(ValueError):
    """A source record cannot be projected into bounded facts."""


def fail(message: str) -> NoReturn:
    raise ProjectionError(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--revision", default=SOURCE_REVISION)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate_json_key")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    fail(f"non_finite_json:{value}")


def required_text(value: object, code: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(code)
    result = value.strip()
    if len(result.encode("utf-8")) > maximum:
        fail(code)
    return result


def _git(root: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(f"unable to verify pinned source with git: {' '.join(arguments)}") from exc
    return completed.stdout


def verify_source(root: Path, revision: str) -> tuple[Path, list[str]]:
    if revision != SOURCE_REVISION:
        raise ValueError(f"revision must equal pinned revision {SOURCE_REVISION}")
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("input must be the pinned source checkout")
    head = _git(resolved, "rev-parse", "HEAD").decode("ascii").strip()
    if head != SOURCE_REVISION:
        raise ValueError("source checkout HEAD does not match pinned revision")
    osv_tree = _git(resolved, "rev-parse", "HEAD:osv").decode("ascii").strip()
    if osv_tree != SOURCE_OSV_TREE:
        raise ValueError("source OSV tree does not match pinned revision")
    dirty = _git(
        resolved,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        *INCLUDE_PATHS,
    )
    if dirty:
        raise ValueError("pinned source include paths must be clean")

    index = _git(
        resolved,
        "-c",
        "core.quotePath=false",
        "ls-tree",
        "-rz",
        "HEAD",
        "--",
        *INCLUDE_PATHS,
    )
    if hashlib.sha256(index).hexdigest() != SOURCE_INDEX_SHA256:
        raise ValueError("source index fingerprint does not match pinned revision")
    entries: list[str] = []
    for raw_entry in index.rstrip(b"\0").split(b"\0"):
        metadata_bytes, separator, relative_bytes = raw_entry.partition(b"\t")
        try:
            metadata = metadata_bytes.decode("ascii")
            relative = relative_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("source index contains a non-UTF-8 path") from exc
        fields = metadata.split()
        if not separator or len(fields) != 3 or fields[0] != "100644" or fields[1] != "blob":
            raise ValueError("source index contains an unsupported entry")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts:
            raise ValueError("source index path escapes checkout")
        entries.append(relative)
    if not entries or len(entries) != len(set(entries)):
        raise ValueError("source index is empty or contains duplicate paths")

    for relative, expected in (("LICENSE", LICENSE_SHA256), ("README.md", README_SHA256)):
        path = (resolved / relative).resolve(strict=True)
        try:
            path.relative_to(resolved)
        except ValueError as exc:
            raise ValueError(f"source path escapes checkout: {relative}") from exc
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"source fingerprint mismatch: {relative}")

    return resolved, entries


def version_shape(affected: Mapping[str, Any]) -> dict[str, int | bool]:
    versions = affected.get("versions", [])
    ranges = affected.get("ranges", [])
    if not isinstance(versions, list) or len(versions) > MAX_VERSIONS:
        fail("invalid_versions")
    if any(not isinstance(version, str) or not version for version in versions):
        fail("invalid_version")
    if not isinstance(ranges, list) or len(ranges) > MAX_RANGES:
        fail("invalid_ranges")
    event_count = 0
    for item in ranges:
        if not isinstance(item, dict):
            fail("invalid_range")
        events = item.get("events", [])
        if not isinstance(events, list):
            fail("invalid_range_events")
        event_count += len(events)
        if event_count > MAX_RANGE_EVENTS:
            fail("too_many_range_events")
    return {
        "explicit_version_count": len(versions),
        "range_count": len(ranges),
        "range_event_count": event_count,
        "has_explicit_versions": bool(versions),
        "has_ranges": bool(ranges),
    }


def project_report(record: object, relative: str) -> list[dict[str, Any]]:
    if not isinstance(record, dict):
        fail("report_not_object")
    report_id = required_text(record.get("id"), "invalid_report_id", 80)
    if not SAFE_REPORT_ID.fullmatch(report_id) or PurePosixPath(relative).stem != report_id:
        fail("report_id_path_mismatch")
    if "withdrawn" in record:
        fail("active_report_marked_withdrawn")
    affected = record.get("affected")
    if not isinstance(affected, list) or not affected or len(affected) > MAX_AFFECTED:
        fail("invalid_affected")

    projections: list[dict[str, Any]] = []
    path_parts = PurePosixPath(relative).parts
    for index, item in enumerate(affected):
        if not isinstance(item, dict):
            fail("affected_not_object")
        package = item.get("package")
        if isinstance(package, dict):
            ecosystem = required_text(package.get("ecosystem"), "invalid_ecosystem", 80)
            package_name = required_text(package.get("name"), "invalid_package_name", 512)
        elif (
            package is None
            and len(affected) == 1
            and len(path_parts) >= 5
            and path_parts[:3] == ("osv", "malicious", "git")
        ):
            # OSV permits GIT ranges without a package object.  The pinned
            # source's hierarchy is the source-owned repository identity.
            ecosystem = "Git"
            package_name = required_text("/".join(path_parts[3:-1]), "invalid_package_name", 512)
        else:
            fail("package_not_object")
        if not SAFE_ECOSYSTEM.fullmatch(ecosystem):
            fail("invalid_ecosystem")
        projections.append(
            {
                "report_id": report_id,
                "affected_index": index,
                "action": "reported_malicious",
                "ecosystem": ecosystem,
                "package_name": package_name,
                **version_shape(item),
            }
        )
    return projections


def truth() -> dict[str, Any]:
    return {
        "source_truth": "malicious",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "high",
        "label_source": "source:ossf_active_malicious_package_report",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "exclusion_reason": (
            "The active source report establishes package-level evidence only; it does not prove "
            "that an atomic install or execution command is malicious or completed."
        ),
        "categories": [
            "software_supply_chain",
            "malicious_package_source_label",
            "package_level_only",
            "no_atomic_command_authority",
        ],
    }


def make_case(revision: str, facts: Mapping[str, Any]) -> dict[str, Any]:
    identity = digest(revision, str(facts["report_id"]), str(facts["affected_index"]))
    ecosystem = str(facts["ecosystem"])
    return {
        "schema_version": SCHEMA_VERSION,
        "id": f"ossf-malicious-packages/{identity[:32]}",
        "source": {
            "dataset": DATASET_ID,
            "revision": revision,
            "original_id": f"{facts['report_id']}#affected-{facts['affected_index']}",
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
        },
        "split": "development",
        "surface": "plugin",
        "payload": {
            "direction": "artifact",
            "tool_name": "package.registry.report",
            "args": dict(facts),
        },
        "truth": truth(),
        "strata": {
            "platform": "package_registry",
            "ecosystem": ecosystem,
            "domain": "software_supply_chain",
            "document_type": "osv_malicious_package_report",
            "hard_negative": False,
            "split_group": digest(revision, ecosystem, str(facts["package_name"]))[:24],
        },
    }


def normalize_directory(root: Path, revision: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    resolved, entries = verify_source(root, revision)
    active_paths = [path for path in entries if path.startswith("osv/malicious/") and path.endswith(".json")]
    withdrawn_paths = [path for path in entries if path.startswith("osv/withdrawn/") and path.endswith(".json")]
    unmergable_paths = [path for path in entries if path.startswith("osv/unmergable/") and path.endswith(".json")]
    active_set = set(active_paths)
    source_bytes = 0
    for relative in entries:
        if relative in active_set:
            continue
        path = (resolved / relative).resolve(strict=True)
        try:
            path.relative_to(resolved)
        except ValueError as exc:
            raise ValueError(f"source path escapes checkout: {relative}") from exc
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"source entry is not a regular file: {relative}")
        source_bytes += path.stat().st_size
    cases: list[dict[str, Any]] = []
    ecosystems: Counter[str] = Counter()
    counts: Counter[str] = Counter()
    seen: set[tuple[str, int]] = set()
    for relative in active_paths:
        path = (resolved / relative).resolve(strict=True)
        try:
            path.relative_to(resolved)
        except ValueError as exc:
            raise ValueError(f"source path escapes checkout: {relative}") from exc
        if path.is_symlink():
            raise ValueError(f"source report must not be a symlink: {relative}")
        data = path.read_bytes()
        source_bytes += len(data)
        if not data or len(data) > MAX_REPORT_BYTES:
            raise ValueError(f"source report size is invalid: {relative}")
        try:
            record = json.loads(
                data.decode("utf-8"),
                object_pairs_hook=strict_object,
                parse_constant=reject_nonfinite,
            )
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ProjectionError) as exc:
            raise ValueError(f"invalid active report: {relative}: {exc}") from exc
        try:
            projections = project_report(record, relative)
        except ProjectionError as exc:
            raise ValueError(f"unsafe active report: {relative}: {exc}") from exc
        counts["active_reports"] += 1
        for facts in projections:
            identity = (str(facts["report_id"]), int(facts["affected_index"]))
            if identity in seen:
                raise ValueError(f"duplicate report projection: {identity[0]}#{identity[1]}")
            seen.add(identity)
            cases.append(make_case(revision, facts))
            ecosystems[str(facts["ecosystem"])] += 1
            counts["package_cases"] += 1
            counts["explicit_versions"] += int(facts["explicit_version_count"])
            counts["ranges"] += int(facts["range_count"])
            counts["range_events"] += int(facts["range_event_count"])

    cases.sort(key=lambda case: str(case["id"]))
    counts["withdrawn_reports_excluded"] = len(withdrawn_paths)
    counts["unmergable_reports_excluded"] = len(unmergable_paths)
    counts["cases"] = len(cases)
    statistics = {key: int(value) for key, value in sorted(counts.items())}
    statistics["ecosystems"] = {key: int(value) for key, value in sorted(ecosystems.items())}
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET_ID],
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {ADAPTER: statistics},
        "source": {
            "dataset": DATASET_ID,
            "revision": revision,
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
            "include_paths": list(INCLUDE_PATHS),
            "bytes": source_bytes,
            "files": len(entries),
            "git_osv_tree": SOURCE_OSV_TREE,
            "index_sha256": SOURCE_INDEX_SHA256,
            "source_url": SOURCE_URL,
        },
        "authority": {
            "package_label": "source-owned active report",
            "atomic_command": "none",
            "enforcement": "contextual detect-only development mining",
            "excluded_fields": [
                "affected version strings",
                "contacts",
                "credits",
                "details",
                "indicators",
                "package contents",
                "references",
                "summary",
            ],
        },
    }
    return cases, manifest


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path) -> None:
    import jsonschema

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for row in rows:
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"{row.get('id', '<unknown>')}:{location}: {errors[0].message}")


def write_outputs(cases: Sequence[dict[str, Any]], manifest: dict[str, Any], output: Path, manifest_path: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = "".join(canonical_json(case) + "\n" for case in cases)
    manifest["output_sha256"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    for path, content in (
        (output, serialized),
        (manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n"),
    ):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            handle.write(content)
            temporary = Path(handle.name)
        os.replace(temporary, path)


def main() -> int:
    args = parse_args()
    cases, manifest = normalize_directory(args.input_dir, args.revision)
    validate_cases(cases, args.schema)
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    write_outputs(cases, manifest, args.output, manifest_path)
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
