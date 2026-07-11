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

"""Generate the release-owned upgrade manifest.

The installed upgrade script is intentionally stable: it may be months older
than the release it is installing. This manifest gives each release a small,
validated contract that old upgraders can read before they make changes.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
LEGACY_UPGRADE_PROTOCOL_VERSION = 1
HARD_CUT_UPGRADE_PROTOCOL_VERSION = 2
OBSERVABILITY_V8_BRIDGE_VERSION = "0.8.4"
OBSERVABILITY_V8_HARD_CUT_VERSION = "0.8.5"
UPGRADE_BASELINES_PATH = ROOT / "release" / "upgrade-baselines.json"


def _ver_tuple(value: str) -> tuple[int, int, int]:
    if not SEMVER_RE.fullmatch(value):
        raise ValueError(f"invalid semver {value!r}; expected X.Y.Z")
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)


def _regex_version(path: Path, pattern: str, label: str) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise RuntimeError(f"could not find {label} version in {path}")
    version = match.group(1)
    _ver_tuple(version)
    return version


def current_version() -> str:
    versions = {
        "pyproject.toml": _regex_version(
            ROOT / "pyproject.toml",
            r'^version\s*=\s*"([^"]+)"',
            "pyproject",
        ),
        "cli/defenseclaw/__init__.py": _regex_version(
            ROOT / "cli" / "defenseclaw" / "__init__.py",
            r'^__version__\s*=\s*"([^"]+)"',
            "__version__",
        ),
        "Makefile": _regex_version(
            ROOT / "Makefile",
            r"^VERSION\s*:=\s*([0-9]+\.[0-9]+\.[0-9]+)",
            "Makefile",
        ),
        "extensions/defenseclaw/package.json": _regex_version(
            ROOT / "extensions" / "defenseclaw" / "package.json",
            r'^\s*"version":\s*"([^"]+)"',
            "package.json",
        ),
    }
    unique = set(versions.values())
    if len(unique) != 1:
        details = "\n".join(f"  {path}: {version}" for path, version in versions.items())
        raise RuntimeError(f"version drift detected:\n{details}")
    return unique.pop()


def migration_versions() -> list[str]:
    path = ROOT / "cli" / "defenseclaw" / "migrations.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    function_names = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    for node in tree.body:
        value: ast.AST | None = None
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "MIGRATIONS" for target in node.targets
        ):
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == "MIGRATIONS":
                value = node.value
        if value is None:
            continue
        if not isinstance(value, ast.List):
            raise RuntimeError("MIGRATIONS must be a list literal")
        versions: list[str] = []
        for item in value.elts:
            if not isinstance(item, ast.Tuple) or len(item.elts) != 3:
                raise RuntimeError("each MIGRATIONS entry must be a three-field tuple")
            version_node, description_node, callable_node = item.elts
            if not isinstance(version_node, ast.Constant) or not isinstance(version_node.value, str):
                raise RuntimeError("each MIGRATIONS entry must start with a string version")
            if (
                not isinstance(description_node, ast.Constant)
                or not isinstance(description_node.value, str)
                or not description_node.value
            ):
                raise RuntimeError("each MIGRATIONS entry must contain a non-empty string description")
            if not isinstance(callable_node, ast.Name) or callable_node.id not in function_names:
                raise RuntimeError("each MIGRATIONS entry must reference a module-level migration function")
            _ver_tuple(version_node.value)
            versions.append(version_node.value)
        expected = sorted(versions, key=_ver_tuple)
        if versions != expected:
            raise RuntimeError(f"MIGRATIONS must be sorted ascending: got {versions}, want {expected}")
        if len(versions) != len(set(versions)):
            raise RuntimeError(f"MIGRATIONS contains duplicates: {versions}")
        return versions
    raise RuntimeError("MIGRATIONS registry not found")


def controller_upgrade_protocol() -> int:
    """Read the protocol supported by the controller shipped in the wheel.

    This is deliberately separate from ``min_upgrade_protocol``.  The 0.8.4
    bridge must be reachable by protocol-1 controllers while installing a
    protocol-2 controller capable of driving the 0.8.5 hard cut.
    """
    path = ROOT / "cli" / "defenseclaw" / "commands" / "cmd_upgrade.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
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
        if value is None:
            continue
        if (
            not isinstance(value, ast.Constant)
            or not isinstance(value.value, int)
            or isinstance(value.value, bool)
            or value.value < 1
        ):
            raise RuntimeError("_UPGRADE_PROTOCOL_VERSION must be a positive integer literal")
        return value.value
    raise RuntimeError("_UPGRADE_PROTOCOL_VERSION not found")


def published_upgrade_baselines() -> list[str]:
    """Load the single release-gate/source-support matrix."""
    try:
        payload = json.loads(UPGRADE_BASELINES_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"could not load {UPGRADE_BASELINES_PATH}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise RuntimeError("upgrade baseline policy must be a schema_version 1 object")
    baselines = payload.get("published_baselines")
    if not isinstance(baselines, list) or not baselines:
        raise RuntimeError("published_baselines must be a non-empty list")
    if not all(isinstance(value, str) and SEMVER_RE.fullmatch(value) for value in baselines):
        raise RuntimeError("published_baselines must contain canonical X.Y.Z versions")
    expected = sorted(baselines, key=_ver_tuple, reverse=True)
    if baselines != expected:
        raise RuntimeError(
            f"published_baselines must be strictly descending: got {baselines}, want {expected}"
        )
    if len(baselines) != len(set(baselines)):
        raise RuntimeError(f"published_baselines contains duplicates: {baselines}")
    return baselines


def release_upgrade_policy(version: str) -> dict[str, Any]:
    """Return transition policy independently of controller capability."""
    if _ver_tuple(version) < _ver_tuple(OBSERVABILITY_V8_HARD_CUT_VERSION):
        return {"min_upgrade_protocol": LEGACY_UPGRADE_PROTOCOL_VERSION}

    bridge_t = _ver_tuple(OBSERVABILITY_V8_BRIDGE_VERSION)
    auto_bridge_from = [
        baseline
        for baseline in published_upgrade_baselines()
        if _ver_tuple(baseline) < bridge_t
    ]
    if not auto_bridge_from:
        raise RuntimeError("hard-cut policy has no tested pre-bridge source versions")
    return {
        "min_upgrade_protocol": HARD_CUT_UPGRADE_PROTOCOL_VERSION,
        "minimum_source_version": OBSERVABILITY_V8_BRIDGE_VERSION,
        "required_bridge_version": OBSERVABILITY_V8_BRIDGE_VERSION,
        "auto_bridge_from": auto_bridge_from,
    }


def build_manifest() -> dict[str, Any]:
    version = current_version()
    migrations = migration_versions()
    current_t = _ver_tuple(version)
    # Migration rows may be forward-keyed before a release is cut. This lets a
    # migration land and pass source CI without pretending that the unstamped
    # checkout is already the future release. The release workflow stamps all
    # package version sources from the tag before invoking this generator, so a
    # row becomes mandatory in the manifest precisely when the release version
    # reaches that row.
    required = [migration for migration in migrations if _ver_tuple(migration) <= current_t]
    manifest = {
        "schema_version": 1,
        "release_version": version,
        "controller_upgrade_protocol": controller_upgrade_protocol(),
        "migration_failure_policy": "fail" if required else "warn",
        "required_cli_migrations": required,
        "generated_by": "scripts/generate-upgrade-manifest.py",
    }
    manifest.update(release_upgrade_policy(version))
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="write manifest JSON to this path")
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the manifest contract without writing an artifact",
    )
    args = parser.parse_args(argv)

    try:
        manifest = build_manifest()
    except Exception as exc:  # noqa: BLE001 - print concise CI diagnostics
        print(f"upgrade manifest check failed: {exc}", file=sys.stderr)
        return 1

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    elif not args.check:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(
            "upgrade manifest OK: "
            f"{manifest['release_version']} "
            f"({len(manifest['required_cli_migrations'])} required migration(s))"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
