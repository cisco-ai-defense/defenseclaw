#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Select a release-smoke lane from authenticated candidate policy."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
EXPECTED_POLICY_FIELDS = {
    "schema_version",
    "published_baselines",
    "published_baseline_config_versions",
    "platform_published_baselines",
}


class ValidationLaneError(RuntimeError):
    """The authenticated release-validation plan is inconsistent."""


def _version_key(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str) or SEMVER.fullmatch(value) is None:
        raise ValidationLaneError(f"non-canonical version {value!r}")
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationLaneError(f"could not read {label}: {exc}") from exc
    if not isinstance(document, dict):
        raise ValidationLaneError(f"{label} is not an object")
    return document


def select_lane(
    *,
    policy: dict[str, Any],
    manifest: dict[str, Any],
    selected: object,
    baseline: str,
) -> str:
    versions = policy.get("published_baselines")
    configs = policy.get("published_baseline_config_versions")
    platforms = policy.get("platform_published_baselines")
    if (
        set(policy) != EXPECTED_POLICY_FIELDS
        or policy.get("schema_version") != 2
        or not isinstance(versions, list)
        or not versions
        or any(not isinstance(version, str) for version in versions)
        or len(versions) != len(set(versions))
        or not isinstance(configs, dict)
        or set(configs) != set(versions)
    ):
        raise ValidationLaneError("effective baseline policy is malformed")
    keys = [_version_key(version) for version in versions]
    if keys != sorted(keys, reverse=True):
        raise ValidationLaneError("effective baselines are not descending")
    if any(
        not isinstance(configs[version], int) or isinstance(configs[version], bool) or configs[version] < 1
        for version in versions
    ):
        raise ValidationLaneError("effective baseline config map is malformed")
    if not isinstance(platforms, dict) or set(platforms) != {"windows"}:
        raise ValidationLaneError("effective platform baseline policy must contain exactly windows")
    windows_versions = platforms["windows"]
    if (
        not isinstance(windows_versions, list)
        or any(not isinstance(version, str) or version not in versions for version in windows_versions)
        or len(windows_versions) != len(set(windows_versions))
        or windows_versions != [version for version in versions if version in set(windows_versions)]
    ):
        raise ValidationLaneError("effective Windows baselines must be an ordered subset of the global policy")

    release_version = manifest.get("release_version")
    release_key = _version_key(release_version)
    if any(key >= release_key for key in keys):
        raise ValidationLaneError("effective baselines must all predate the candidate release")

    bridge_anchor = manifest.get("required_bridge_version")
    if bridge_anchor not in versions:
        raise ValidationLaneError("required bridge is absent from the effective baseline policy")
    bridge_key = _version_key(bridge_anchor)
    bridge_config = configs[bridge_anchor]
    post_bridge = sorted(
        (version for version in versions if _version_key(version) > bridge_key and configs[version] > bridge_config),
        key=_version_key,
    )
    if not post_bridge:
        raise ValidationLaneError("no authenticated post-bridge config boundary exists")
    hard_cut_anchor = post_bridge[0]
    if hard_cut_anchor != "0.8.5":
        raise ValidationLaneError("hard-cut boundary must remain bound to exact published 0.8.5")
    native_config = configs[hard_cut_anchor]
    native_versions = [
        version
        for version in post_bridge
        if configs[version] == native_config and _version_key(version) > _version_key(hard_cut_anchor)
    ]
    if not native_versions:
        raise ValidationLaneError("clean missing-cursor recovery anchor is unavailable")
    field_recovery_anchor = native_versions[0]
    if field_recovery_anchor != "0.8.6":
        raise ValidationLaneError("clean missing-cursor recovery must remain bound to exact published 0.8.6")

    # POSIX release smoke is governed by one complete authenticated seven-lane
    # matrix.  Windows has a separately authenticated publication map and must
    # never narrow Linux/macOS merely because its first-release map is empty.
    family_anchors: list[str] = []
    for family in ((0, 7), (0, 6), (0, 5)):
        family_versions = [version for version in versions if _version_key(version)[:2] == family]
        if not family_versions:
            raise ValidationLaneError(f"authenticated {family[0]}.{family[1]}.x family baseline is unavailable")
        family_anchors.append(max(family_versions, key=_version_key))
    required_matrix = [versions[0], field_recovery_anchor, hard_cut_anchor, bridge_anchor, *family_anchors]
    matrix_label = "seven-lane"
    if release_version == "0.8.7" and versions[0] == field_recovery_anchor == "0.8.6":
        # 0.8.7 is the one historical publication where the newest published
        # baseline and the clean field-recovery anchor are the same release.
        # Collapse that duplicate only for this authenticated target identity.
        required_matrix = [versions[0], hard_cut_anchor, bridge_anchor, *family_anchors]
        matrix_label = "historical six-lane"
        if len(required_matrix) != 6 or len(set(required_matrix)) != 6:
            raise ValidationLaneError("authenticated historical six-lane baseline matrix is unavailable")
    elif len(required_matrix) != 7 or len(set(required_matrix)) != 7:
        raise ValidationLaneError("authenticated seven-lane baseline matrix is unavailable")
    if (
        not isinstance(selected, list)
        or len(selected) != len(required_matrix)
        or any(not isinstance(item, str) for item in selected)
        or len(set(selected)) != len(selected)
    ):
        raise ValidationLaneError(
            f"selected {matrix_label} baseline matrix must contain exactly {len(required_matrix)} distinct releases"
        )
    if selected != required_matrix:
        raise ValidationLaneError(
            f"selected baseline matrix does not exactly match the authenticated {matrix_label} policy"
        )
    if baseline not in required_matrix:
        raise ValidationLaneError(f"baseline is absent from the authenticated {matrix_label} matrix")

    if baseline == bridge_anchor:
        return "bridge-dependency-drift"
    if baseline == field_recovery_anchor:
        return "field-recovery"
    return "published"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--selected-json", required=True)
    parser.add_argument("--baseline", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        selected = json.loads(args.selected_json)
        lane = select_lane(
            policy=_load_object(args.policy, "effective baseline policy"),
            manifest=_load_object(args.manifest, "upgrade manifest"),
            selected=selected,
            baseline=args.baseline,
        )
    except (json.JSONDecodeError, TypeError, ValueError, ValidationLaneError) as exc:
        print(f"invalid authenticated release validation plan: {exc}", file=sys.stderr)
        return 2
    print(lane)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
