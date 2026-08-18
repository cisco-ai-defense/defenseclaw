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

"""Select release validation and bind reusable certification evidence."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "release" / "certification-policy.json"
DEFAULT_BASELINES = ROOT / "release" / "upgrade-baselines.json"
DEFAULT_DIGEST_POLICY = ROOT / "release" / "historical-artifact-digests.json"

SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PLATFORM_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+$")

SELECTION_SCHEMA = 1
CERTIFICATION_SCHEMA = 1
CERTIFICATION_RESULT = "passed"
BEHAVIOR_CLASSES = {
    "latest_stable",
    "previous_stable",
    "bridge_boundary",
    "explicit_skip_refusal",
    "pre_v8_hard_cut_source",
    "oldest_supported",
    "protocol_installer_boundaries",
}


class CertificationError(RuntimeError):
    """A release selection or certification receipt is invalid."""


def _read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CertificationError(f"could not read {label} {path}: {exc}") from exc


def _read_object(path: Path, label: str) -> dict[str, Any]:
    value = _read_json(path, label)
    if not isinstance(value, dict):
        raise CertificationError(f"{label} must contain a JSON object")
    return value


def _strict_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise CertificationError(f"{label} has unexpected keys: got {sorted(value)}, want {sorted(expected)}")


def _version_tuple(value: object, label: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not SEMVER_RE.fullmatch(value):
        raise CertificationError(f"{label} must be canonical X.Y.Z")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _normalize_digest(value: object, label: str) -> str:
    match = DIGEST_RE.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise CertificationError(f"{label} must be a lowercase SHA-256 digest")
    return f"sha256:{match.group(1)}"


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CertificationError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CertificationError(f"{label} is not a valid timestamp") from exc


def load_policy(path: Path = DEFAULT_POLICY) -> dict[str, Any]:
    policy = _read_object(path, "certification policy")
    _strict_keys(
        policy,
        {
            "schema_version",
            "max_age_hours",
            "bridge_boundary_version",
            "profiles",
            "profile_platform_sets",
            "release_sensitive_paths",
            "protocol_installer_boundaries",
        },
        "certification policy",
    )
    if policy["schema_version"] != 1:
        raise CertificationError("certification policy schema_version must be 1")
    max_age = policy["max_age_hours"]
    if not isinstance(max_age, int) or isinstance(max_age, bool) or not 1 <= max_age <= 168:
        raise CertificationError("max_age_hours must be in [1, 168]")
    _version_tuple(policy["bridge_boundary_version"], "bridge_boundary_version")

    profiles = policy["profiles"]
    if not isinstance(profiles, dict) or set(profiles) != {"pr", "medium", "full"}:
        raise CertificationError("profiles must contain exactly pr, medium, and full")
    for name, classes in profiles.items():
        if (
            not isinstance(classes, list)
            or not classes
            or any(not isinstance(item, str) or item not in BEHAVIOR_CLASSES for item in classes)
            or len(classes) != len(set(classes))
        ):
            raise CertificationError(f"profile {name} has invalid behavior classes")
    required_pr = {
        "latest_stable",
        "previous_stable",
        "bridge_boundary",
        "explicit_skip_refusal",
        "oldest_supported",
    }
    if set(profiles["pr"]) != required_pr:
        raise CertificationError("PR profile must contain exactly the five selective behaviors")
    required_full = required_pr | {
        "pre_v8_hard_cut_source",
        "protocol_installer_boundaries",
    }
    if not required_full.issubset(profiles["full"]):
        raise CertificationError("full profile omits a required behavior class")

    platforms = policy["profile_platform_sets"]
    if not isinstance(platforms, dict) or set(platforms) != set(profiles):
        raise CertificationError("profile_platform_sets must exactly cover profiles")
    for name, values in platforms.items():
        if (
            not isinstance(values, list)
            or not values
            or len(values) != len(set(values))
            or any(not isinstance(item, str) or not PLATFORM_RE.fullmatch(item) for item in values)
        ):
            raise CertificationError(f"platform set {name} is invalid")
    full_platforms = platforms["full"]
    if any(item.startswith("windows-") and item != "windows-resolver-refusal" for item in full_platforms):
        raise CertificationError("Windows certification must remain resolver-refusal-only")
    if "windows-resolver-refusal" not in full_platforms:
        raise CertificationError("full certification must prove Windows resolver refusal")

    patterns = policy["release_sensitive_paths"]
    if (
        not isinstance(patterns, list)
        or not patterns
        or any(not isinstance(item, str) or not item for item in patterns)
    ):
        raise CertificationError("release_sensitive_paths must be non-empty strings")
    boundaries = policy["protocol_installer_boundaries"]
    if not isinstance(boundaries, dict):
        raise CertificationError("protocol_installer_boundaries must be an object")
    _strict_keys(
        boundaries,
        {
            "explicit_versions",
            "include_config_transitions",
            "include_historical_auth_transition",
        },
        "protocol_installer_boundaries",
    )
    explicit = boundaries["explicit_versions"]
    if not isinstance(explicit, list) or len(explicit) != len(set(explicit)):
        raise CertificationError("explicit boundary versions must be unique")
    for version in explicit:
        _version_tuple(version, "explicit boundary version")
    for name in ("include_config_transitions", "include_historical_auth_transition"):
        if not isinstance(boundaries[name], bool):
            raise CertificationError(f"{name} must be boolean")
    return policy


def load_baseline_policy(path: Path = DEFAULT_BASELINES) -> dict[str, Any]:
    value = _read_object(path, "upgrade baseline policy")
    _strict_keys(
        value,
        {
            "schema_version",
            "published_baselines",
            "published_baseline_config_versions",
            "platform_published_baselines",
        },
        "upgrade baseline policy",
    )
    if value["schema_version"] != 2:
        raise CertificationError("upgrade baseline policy schema_version must be 2")
    versions = value["published_baselines"]
    if not isinstance(versions, list) or not versions:
        raise CertificationError("published_baselines must be non-empty")
    tuples = [_version_tuple(item, "published baseline") for item in versions]
    if len(versions) != len(set(versions)) or tuples != sorted(tuples, reverse=True):
        raise CertificationError("published baselines must be unique descending semver")
    configs = value["published_baseline_config_versions"]
    if not isinstance(configs, dict) or set(configs) != set(versions):
        raise CertificationError("config-version map must exactly cover published baselines")
    if any(not isinstance(item, int) or isinstance(item, bool) or item < 1 for item in configs.values()):
        raise CertificationError("baseline config versions must be positive integers")
    platforms = value["platform_published_baselines"]
    if not isinstance(platforms, dict) or set(platforms) != {"windows"}:
        raise CertificationError("platform baselines must contain exactly the Windows exception")
    windows = platforms["windows"]
    if not isinstance(windows, list) or any(item not in versions for item in windows):
        raise CertificationError("Windows baselines must be a published subset")
    if "0.8.4" in windows:
        raise CertificationError("the immutable POSIX-only 0.8.4 bridge cannot claim Windows")
    return value


def _historical_auth_boundary(path: Path) -> str:
    value = _read_object(path, "historical artifact digest policy")
    _strict_keys(
        value,
        {
            "schema_version",
            "signed_wheel_coverage_starts_at",
            "signed_checksum_exceptions",
        },
        "historical artifact digest policy",
    )
    if value["schema_version"] != 1:
        raise CertificationError("historical artifact digest policy schema_version must be 1")
    boundary = value["signed_wheel_coverage_starts_at"]
    _version_tuple(boundary, "signed wheel coverage boundary")
    return boundary


def workflow_version(
    *,
    policy_path: Path = DEFAULT_POLICY,
    baseline_path: Path = DEFAULT_BASELINES,
    digest_policy_path: Path = DEFAULT_DIGEST_POLICY,
) -> str:
    """Digest the selector implementation and every reviewed selection input."""

    hasher = hashlib.sha256()
    for label, path in (
        ("helper", Path(__file__).resolve()),
        ("policy", policy_path),
        ("baselines", baseline_path),
        ("historical-auth", digest_policy_path),
    ):
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise CertificationError(f"could not read workflow-version input {path}: {exc}") from exc
        hasher.update(label.encode() + b"\0" + content + b"\0")
    return f"sha256:{hasher.hexdigest()}"


def _published_versions(value: Any) -> list[str]:
    if isinstance(value, list) and value and all(isinstance(item, list) for item in value):
        value = [item for page in value for item in page]
    if not isinstance(value, list):
        raise CertificationError("published releases JSON must be a list")
    versions: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or item.get("draft") is not False or item.get("prerelease") is not False:
            continue
        tag = item.get("tag_name")
        if isinstance(tag, str):
            if SEMVER_RE.fullmatch(tag):
                versions.add(tag)
    if not versions:
        raise CertificationError("published releases contain no canonical stable version")
    return sorted(versions, key=lambda item: _version_tuple(item, "published version"), reverse=True)


def resolve_version(
    *,
    requested: str | None,
    source_version: str,
    published_releases: Any,
) -> tuple[str, str]:
    """Resolve a dispatch version, or the next patch after live GitHub stable."""

    source_tuple = _version_tuple(source_version, "source version")
    published = _published_versions(published_releases)
    latest = published[0]
    if requested:
        _version_tuple(requested, "requested version")
        return requested, latest
    latest_tuple = _version_tuple(latest, "latest stable")
    next_patch = (latest_tuple[0], latest_tuple[1], latest_tuple[2] + 1)
    resolved_tuple = max(source_tuple, next_patch)
    return ".".join(str(part) for part in resolved_tuple), latest


def _ordered_sources(
    candidate_version: str,
    baseline_policy: dict[str, Any],
    latest_stable: str | None,
) -> list[str]:
    candidate = _version_tuple(candidate_version, "candidate version")
    values = list(baseline_policy["published_baselines"])
    if latest_stable:
        latest_tuple = _version_tuple(latest_stable, "latest stable")
        if latest_tuple >= candidate:
            raise CertificationError("latest stable must precede the candidate version")
        values.append(latest_stable)
    sources = sorted(
        {item for item in values if _version_tuple(item, "source version") < candidate},
        key=lambda item: _version_tuple(item, "source version"),
        reverse=True,
    )
    if latest_stable and sources[0] != latest_stable:
        raise CertificationError("latest stable does not match the newest eligible source")
    return sources


def _protocol_boundaries(
    sources: list[str],
    baseline_policy: dict[str, Any],
    policy: dict[str, Any],
    digest_policy_path: Path,
) -> list[str]:
    settings = policy["protocol_installer_boundaries"]
    selected = {item for item in settings["explicit_versions"] if item in sources}
    configs = baseline_policy["published_baseline_config_versions"]
    known_sources = [item for item in sources if item in configs]
    if settings["include_config_transitions"]:
        for newer, older in zip(known_sources, known_sources[1:]):
            if configs[newer] != configs[older]:
                selected.update((newer, older))
    if settings["include_historical_auth_transition"]:
        boundary = _historical_auth_boundary(digest_policy_path)
        if boundary in sources:
            selected.add(boundary)
            index = sources.index(boundary)
            if index + 1 < len(sources):
                selected.add(sources[index + 1])
    return [item for item in sources if item in selected]


def select_cases(
    candidate_version: str,
    scope: str,
    *,
    latest_stable: str | None = None,
    policy_path: Path = DEFAULT_POLICY,
    baseline_path: Path = DEFAULT_BASELINES,
    digest_policy_path: Path = DEFAULT_DIGEST_POLICY,
) -> dict[str, Any]:
    """Select representative sources by behavior class, not arbitrary count."""

    policy = load_policy(policy_path)
    baseline_policy = load_baseline_policy(baseline_path)
    if scope not in policy["profiles"]:
        raise CertificationError(f"unknown validation scope {scope!r}")
    sources = _ordered_sources(candidate_version, baseline_policy, latest_stable)
    if len(sources) < 2:
        raise CertificationError("selection needs at least two published source releases")
    bridge = policy["bridge_boundary_version"]
    bridge_tuple = _version_tuple(bridge, "bridge boundary")
    bridge_applies = _version_tuple(candidate_version, "candidate version") > bridge_tuple
    pre_bridge = [item for item in sources if _version_tuple(item, "source") < bridge_tuple]
    class_versions: dict[str, list[str]] = {
        "latest_stable": sources[:1],
        "previous_stable": sources[1:2],
        "bridge_boundary": [bridge] if bridge_applies and bridge in sources else [],
        "explicit_skip_refusal": pre_bridge[:1] if bridge_applies else [],
        "pre_v8_hard_cut_source": pre_bridge[:1] if bridge_applies else [],
        "oldest_supported": sources[-1:],
        "protocol_installer_boundaries": _protocol_boundaries(sources, baseline_policy, policy, digest_policy_path),
    }
    requested = policy["profiles"][scope]
    selected = {version for name in requested for version in class_versions[name]}
    baselines = [
        {
            "version": version,
            "classes": [name for name in requested if version in class_versions[name]],
        }
        for version in sources
        if version in selected
    ]
    if scope == "pr":
        cases = []
        case_by_behavior: dict[tuple[str, str, str, bool], dict[str, Any]] = {}
        for name in requested:
            versions = class_versions[name]
            if not versions:
                raise CertificationError(f"PR behavior class {name} has no eligible baseline")
            mode = "staged-upgrade"
            expected = "success"
            if name == "explicit_skip_refusal":
                mode = "explicit-direct-target"
                expected = "refusal-before-mutation"
            elif name == "oldest_supported":
                mode = "oldest-smoke-and-refusal"
                expected = "success-and-refusal"
            start_source_gateway = name == "oldest_supported"
            behavior = (versions[0], mode, expected, start_source_gateway)
            existing = case_by_behavior.get(behavior)
            if existing is not None:
                existing["classes"].append(name)
                continue
            case = {
                "class": name,
                "classes": [name],
                "baseline": versions[0],
                "mode": mode,
                "expected": expected,
                "start_source_gateway": start_source_gateway,
            }
            case_by_behavior[behavior] = case
            cases.append(case)
    else:
        cases = [
            {
                "class": item["classes"][0],
                "classes": item["classes"],
                "baseline": item["version"],
                "mode": "full" if scope == "full" else "staged-upgrade",
                "expected": "success-and-refusal" if scope == "full" else "success",
                "start_source_gateway": item["version"] in {sources[0], pre_bridge[0] if pre_bridge else ""},
            }
            for item in baselines
        ]
    if not baselines or not cases:
        raise CertificationError(f"scope {scope} selected no validation cases")
    return {
        "schema_version": SELECTION_SCHEMA,
        "workflow_version": workflow_version(
            policy_path=policy_path,
            baseline_path=baseline_path,
            digest_policy_path=digest_policy_path,
        ),
        "scope": scope,
        "candidate_version": candidate_version,
        "latest_stable": latest_stable or sources[0],
        "platform_set": policy["profile_platform_sets"][scope],
        "baselines": baselines,
        "cases": cases,
    }


def _changed_paths(base: str, head: str) -> list[str]:
    process = subprocess.run(
        [
            "git",
            "diff",
            "--name-status",
            "-z",
            "--find-renames",
            "--diff-filter=ACDMRTUXB",
            f"{base}...{head}",
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    fields = process.stdout.split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    paths: list[str] = []
    index = 0
    while index < len(fields):
        status = fields[index]
        index += 1
        path_count = 2 if status[:1] in {"R", "C"} else 1
        if index + path_count > len(fields):
            raise CertificationError("git diff returned a truncated name-status record")
        paths.extend(fields[index : index + path_count])
        index += path_count
    return paths


def _is_sensitive(paths: list[str], patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for path in paths for pattern in patterns)


def _candidate_seal_digest(root: Path) -> str:
    path = root / "release-candidate.json"
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise CertificationError(f"candidate seal is missing or unreadable: {path}: {exc}") from exc
    return _sha256_bytes(content)


def _workflow_file_digest(path: Path) -> str:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise CertificationError(f"could not read certification workflow {path}: {exc}") from exc


def create_metadata(
    *,
    selection: dict[str, Any],
    repository: str,
    commit: str,
    candidate_root: Path,
    artifact_id: str,
    artifact_name: str,
    artifact_digest: str,
    run_id: str,
    run_attempt: int,
    workflow_file: Path,
    tested_baselines: Sequence[str],
    completed_at: datetime,
    policy_path: Path = DEFAULT_POLICY,
) -> dict[str, Any]:
    """Create a receipt only after the exact selected baseline list passed."""

    policy = load_policy(policy_path)
    if not REPOSITORY_RE.fullmatch(repository):
        raise CertificationError("repository must be owner/name")
    if not COMMIT_RE.fullmatch(commit):
        raise CertificationError("commit must be a lowercase 40-character Git SHA")
    expected = [item["version"] for item in selection["baselines"]]
    if list(tested_baselines) != expected:
        raise CertificationError("tested baselines must exactly match the ordered selection")
    if not artifact_id.isdigit() or int(artifact_id) < 1:
        raise CertificationError("candidate artifact id must be a positive decimal identifier")
    if not SAFE_NAME_RE.fullmatch(artifact_name):
        raise CertificationError("candidate artifact name is invalid")
    if not run_id.isdigit() or int(run_id) < 1:
        raise CertificationError("run id must be a positive decimal identifier")
    if not isinstance(run_attempt, int) or isinstance(run_attempt, bool) or run_attempt < 1:
        raise CertificationError("run attempt must be a positive integer")
    if completed_at.tzinfo is None:
        raise CertificationError("completed_at must be timezone-aware")
    completed_at = completed_at.astimezone(timezone.utc).replace(microsecond=0)
    valid_until = completed_at + timedelta(hours=policy["max_age_hours"])
    document: dict[str, Any] = {
        "schema_version": CERTIFICATION_SCHEMA,
        "result": CERTIFICATION_RESULT,
        "workflow_version": selection["workflow_version"],
        "workflow_file_sha256": _workflow_file_digest(workflow_file),
        "repository": repository,
        "commit_sha": commit,
        "candidate_version": selection["candidate_version"],
        "platform_set": selection["platform_set"],
        "tested_baselines": selection["baselines"],
        "tested_cases": selection["cases"],
        "candidate_artifact": {
            "id": artifact_id,
            "name": artifact_name,
            "digest": _normalize_digest(artifact_digest, "candidate artifact digest"),
            "seal_sha256": _candidate_seal_digest(candidate_root),
        },
        "run": {"id": run_id, "attempt": run_attempt},
        "completed_at": _format_time(completed_at),
        "valid_until": _format_time(valid_until),
    }
    document["certification_key"] = _sha256_bytes(_canonical_bytes(document))
    return document


def verify_metadata(
    document: dict[str, Any],
    *,
    selection: dict[str, Any],
    repository: str,
    commit: str,
    candidate_root: Path,
    workflow_file: Path,
    now: datetime,
    policy_path: Path = DEFAULT_POLICY,
) -> dict[str, str]:
    """Verify exact candidate custody and freshness; reject means run full certification."""

    _strict_keys(
        document,
        {
            "schema_version",
            "result",
            "workflow_version",
            "workflow_file_sha256",
            "repository",
            "commit_sha",
            "candidate_version",
            "platform_set",
            "tested_baselines",
            "tested_cases",
            "candidate_artifact",
            "run",
            "completed_at",
            "valid_until",
            "certification_key",
        },
        "certification metadata",
    )
    if document["schema_version"] != CERTIFICATION_SCHEMA or document["result"] != CERTIFICATION_RESULT:
        raise CertificationError("certification metadata is not a passed supported receipt")
    if document["repository"] != repository:
        raise CertificationError("certification repository mismatch")
    if document["commit_sha"] != commit or not COMMIT_RE.fullmatch(commit):
        raise CertificationError("certification commit mismatch")
    if document["candidate_version"] != selection["candidate_version"]:
        raise CertificationError("certification candidate version mismatch")
    key_input = dict(document)
    stored_key = key_input.pop("certification_key")
    if stored_key != _sha256_bytes(_canonical_bytes(key_input)):
        raise CertificationError("certification metadata content digest mismatch")
    for key in ("workflow_version", "platform_set"):
        if document[key] != selection[key]:
            raise CertificationError(f"certification {key} mismatch")
    if document["workflow_file_sha256"] != _workflow_file_digest(workflow_file):
        raise CertificationError("certification workflow file digest mismatch")
    if document["tested_baselines"] != selection["baselines"]:
        raise CertificationError("certified baseline classes do not match current selection")
    if document["tested_cases"] != selection["cases"]:
        raise CertificationError("certified cases do not match current selection")

    policy = load_policy(policy_path)
    completed = _parse_time(document["completed_at"], "completed_at")
    valid_until = _parse_time(document["valid_until"], "valid_until")
    if valid_until != completed + timedelta(hours=policy["max_age_hours"]):
        raise CertificationError("certification validity window does not match current policy")
    if now.tzinfo is None:
        raise CertificationError("verification time must be timezone-aware")
    now = now.astimezone(timezone.utc)
    if completed > now + timedelta(minutes=5):
        raise CertificationError("certification timestamp is in the future")
    if now > valid_until:
        raise CertificationError("certification is stale; full certification is required")

    artifact = document["candidate_artifact"]
    if not isinstance(artifact, dict) or set(artifact) != {"id", "name", "digest", "seal_sha256"}:
        raise CertificationError("candidate artifact metadata is invalid")
    if not isinstance(artifact["id"], str) or not artifact["id"].isdigit() or int(artifact["id"]) < 1:
        raise CertificationError("candidate artifact id is invalid")
    if not isinstance(artifact["name"], str) or not SAFE_NAME_RE.fullmatch(artifact["name"]):
        raise CertificationError("candidate artifact name is invalid")
    if artifact["digest"] != _normalize_digest(artifact["digest"], "candidate artifact digest"):
        raise CertificationError("candidate artifact digest is invalid")
    if artifact["seal_sha256"] != _candidate_seal_digest(candidate_root):
        raise CertificationError("candidate artifact seal digest mismatch")
    run = document["run"]
    if not isinstance(run, dict) or set(run) != {"id", "attempt"}:
        raise CertificationError("certification run metadata is invalid")
    if not isinstance(run["id"], str) or not run["id"].isdigit() or int(run["id"]) < 1:
        raise CertificationError("certification run id is invalid")
    if not isinstance(run["attempt"], int) or isinstance(run["attempt"], bool) or run["attempt"] < 1:
        raise CertificationError("certification run attempt is invalid")
    return {
        "artifact_id": artifact["id"],
        "artifact_name": artifact["name"],
        "artifact_digest": artifact["digest"],
        "certification_run_id": run["id"],
        "certification_run_attempt": str(run["attempt"]),
        "workflow_version": document["workflow_version"],
        "completed_at": document["completed_at"],
        "valid_until": document["valid_until"],
        "tested_baselines": json.dumps(
            [item["version"] for item in document["tested_baselines"]], separators=(",", ":")
        ),
    }


def _write_json(path: Path | None, value: object) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if path is None:
        sys.stdout.write(rendered)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")


def _github_output(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as output:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                raise CertificationError(f"GitHub output {key} must be one line")
            output.write(f"{key}={value}\n")


def _add_selection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scope", choices=("pr", "medium", "full"), required=True)
    parser.add_argument("--candidate-version", required=True)
    parser.add_argument("--latest-stable")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--baselines", type=Path, default=DEFAULT_BASELINES)
    parser.add_argument("--digest-policy", type=Path, default=DEFAULT_DIGEST_POLICY)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--policy", type=Path, default=argparse.SUPPRESS)
    common.add_argument("--baselines", type=Path, default=argparse.SUPPRESS)
    common.add_argument("--digest-policy", type=Path, default=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(dest="command", required=True)

    resolve = subparsers.add_parser("resolve-version", parents=[common])
    resolve.add_argument("--requested")
    resolve.add_argument("--source-version", required=True)
    resolve.add_argument("--published-releases", type=Path, required=True)
    resolve.add_argument("--github-output", type=Path)

    select = subparsers.add_parser("select-baselines", parents=[common])
    _add_selection_args(select)
    select.add_argument("--format", choices=("matrix", "versions", "document"), default="matrix")
    select.add_argument("--output", type=Path)
    select.add_argument("--github-output", type=Path)

    paths = subparsers.add_parser("paths", parents=[common])
    paths.add_argument("--base", required=True)
    paths.add_argument("--head", required=True)
    paths.add_argument("--candidate-version")
    paths.add_argument("--latest-stable")
    paths.add_argument("--github-output", type=Path)

    info = subparsers.add_parser("policy-info", parents=[common])
    info.add_argument("--github-output", type=Path)

    write = subparsers.add_parser("write-metadata", parents=[common])
    _add_selection_args(write)
    write.add_argument("--repository", required=True)
    write.add_argument("--commit", required=True)
    write.add_argument("--candidate-root", type=Path, required=True)
    write.add_argument("--artifact-id", required=True)
    write.add_argument("--artifact-name", required=True)
    write.add_argument("--artifact-digest", required=True)
    write.add_argument("--run-id", required=True)
    write.add_argument("--run-attempt", type=int, required=True)
    write.add_argument("--workflow-file", type=Path, required=True)
    write.add_argument("--tested-baseline", action="append", default=[])
    write.add_argument("--completed-at")
    write.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify-metadata", parents=[common])
    _add_selection_args(verify)
    verify.add_argument("--repository", required=True)
    verify.add_argument("--commit", required=True)
    verify.add_argument("--candidate-root", type=Path, required=True)
    verify.add_argument("--workflow-file", type=Path, required=True)
    verify.add_argument("--metadata", type=Path, required=True)
    verify.add_argument("--now")
    verify.add_argument("--github-output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "resolve-version":
            resolved, latest = resolve_version(
                requested=args.requested,
                source_version=args.source_version,
                published_releases=_read_json(args.published_releases, "published releases"),
            )
            result = {"candidate_version": resolved, "latest_stable": latest}
            if args.github_output:
                _github_output(args.github_output, result)
            _write_json(None, result)
            return 0
        if args.command == "policy-info":
            policy = load_policy(args.policy)
            result = {
                "workflow_version": workflow_version(
                    policy_path=args.policy,
                    baseline_path=args.baselines,
                    digest_policy_path=args.digest_policy,
                ),
                "max_age_hours": str(policy["max_age_hours"]),
            }
            if args.github_output:
                _github_output(args.github_output, result)
            _write_json(None, result)
            return 0
        if args.command in {"select-baselines", "write-metadata", "verify-metadata"}:
            selection = select_cases(
                args.candidate_version,
                args.scope,
                latest_stable=args.latest_stable,
                policy_path=args.policy,
                baseline_path=args.baselines,
                digest_policy_path=args.digest_policy,
            )
        if args.command == "select-baselines":
            value: object = {"include": selection["cases"]}
            if args.format == "versions":
                value = [item["version"] for item in selection["baselines"]]
            elif args.format == "document":
                value = selection
            _write_json(args.output, value)
            if args.github_output:
                _github_output(
                    args.github_output,
                    {
                        "matrix": json.dumps({"include": selection["cases"]}, separators=(",", ":")),
                        "versions": json.dumps(
                            [item["version"] for item in selection["baselines"]],
                            separators=(",", ":"),
                        ),
                        "platform_set": json.dumps(selection["platform_set"], separators=(",", ":")),
                        "workflow_version": selection["workflow_version"],
                    },
                )
            return 0
        if args.command == "paths":
            changed = _changed_paths(args.base, args.head)
            sensitive = _is_sensitive(changed, load_policy(args.policy)["release_sensitive_paths"])
            result = {"sensitive": sensitive, "paths": changed}
            outputs = {"sensitive": "true" if sensitive else "false"}
            if args.candidate_version:
                selection = select_cases(
                    args.candidate_version,
                    "pr",
                    latest_stable=args.latest_stable,
                    policy_path=args.policy,
                    baseline_path=args.baselines,
                    digest_policy_path=args.digest_policy,
                )
                outputs.update(
                    {
                        "matrix": json.dumps({"include": selection["cases"]}, separators=(",", ":")),
                        "versions": json.dumps(
                            [item["version"] for item in selection["baselines"]],
                            separators=(",", ":"),
                        ),
                        "workflow_version": selection["workflow_version"],
                    }
                )
            else:
                outputs.update({"matrix": '{"include":[]}', "versions": "[]"})
            if args.github_output:
                _github_output(args.github_output, outputs)
            _write_json(None, result)
            return 0
        if args.command == "write-metadata":
            completed = (
                _parse_time(args.completed_at, "completed_at") if args.completed_at else datetime.now(timezone.utc)
            )
            document = create_metadata(
                selection=selection,
                repository=args.repository,
                commit=args.commit,
                candidate_root=args.candidate_root,
                artifact_id=args.artifact_id,
                artifact_name=args.artifact_name,
                artifact_digest=args.artifact_digest,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                workflow_file=args.workflow_file,
                tested_baselines=args.tested_baseline,
                completed_at=completed,
                policy_path=args.policy,
            )
            _write_json(args.output, document)
            return 0
        if args.command == "verify-metadata":
            outputs = verify_metadata(
                _read_object(args.metadata, "certification metadata"),
                selection=selection,
                repository=args.repository,
                commit=args.commit,
                candidate_root=args.candidate_root,
                workflow_file=args.workflow_file,
                now=_parse_time(args.now, "now") if args.now else datetime.now(timezone.utc),
                policy_path=args.policy,
            )
            if args.github_output:
                _github_output(args.github_output, outputs)
            _write_json(None, outputs)
            return 0
        raise AssertionError(args.command)
    except (CertificationError, subprocess.CalledProcessError) as exc:
        print(f"release certification error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
