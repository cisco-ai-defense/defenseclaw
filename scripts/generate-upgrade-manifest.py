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

try:
    from scripts.source_release_identity import SourceIdentityError, validate_source_tree
except ModuleNotFoundError:  # Direct ``python scripts/generate-upgrade-manifest.py`` execution.
    from source_release_identity import SourceIdentityError, validate_source_tree

ROOT = Path(__file__).resolve().parents[1]
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
LEGACY_UPGRADE_PROTOCOL_VERSION = 1
HARD_CUT_UPGRADE_PROTOCOL_VERSION = 2
OBSERVABILITY_V8_BRIDGE_VERSION = "0.8.4"
OBSERVABILITY_V8_HARD_CUT_VERSION = "0.8.5"
UPGRADE_BASELINES_PATH = ROOT / "release" / "upgrade-baselines.json"
RUNTIME_CONFIG_PATH = ROOT / "internal" / "config" / "config.go"
OBSERVABILITY_V8_CONFIG_PATH = (
    ROOT / "internal" / "config" / "observability_v8_types.go"
)


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
    version = unique.pop()
    try:
        identity = validate_source_tree(ROOT, expected_release=version)
    except SourceIdentityError as exc:
        raise RuntimeError(f"reviewed source-release identity is invalid: {exc}") from exc
    if identity["source_release"] != version:  # Defensive; expected_release already checks this.
        raise RuntimeError("reviewed source-release identity does not match package version")
    return version


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


def _go_config_version_literal(path: Path, name: str) -> int:
    """Read one positive Go configuration-version literal."""

    text = path.read_text(encoding="utf-8")
    matches = re.findall(
        rf"^\s*(?:const[ \t]+)?{re.escape(name)}[ \t]*=[ \t]*([0-9]+)[ \t]*$",
        text,
        re.MULTILINE,
    )
    if len(matches) != 1:
        raise RuntimeError(f"{path} must declare exactly one literal {name}")
    value = int(matches[0])
    if value < 1:
        raise RuntimeError(f"{name} must be a positive integer literal")
    return value


def compatibility_config_version() -> int:
    """Read the legacy compatibility-decoder ceiling."""

    return _go_config_version_literal(RUNTIME_CONFIG_PATH, "CurrentConfigVersion")


def observability_v8_config_version() -> int:
    """Read the strict observability-v8 runtime schema."""

    return _go_config_version_literal(
        OBSERVABILITY_V8_CONFIG_PATH,
        "ObservabilityV8ConfigVersion",
    )


def runtime_config_version(version: str | None = None) -> int:
    """Select the literal that attests the requested release runtime."""

    if version is None:
        version = current_version()
    if _ver_tuple(version) >= _ver_tuple(OBSERVABILITY_V8_HARD_CUT_VERSION):
        return observability_v8_config_version()
    return compatibility_config_version()


def expected_runtime_config_version(version: str) -> int:
    version_t = _ver_tuple(version)
    if version_t == _ver_tuple(OBSERVABILITY_V8_BRIDGE_VERSION):
        return 7
    if version_t >= _ver_tuple(OBSERVABILITY_V8_HARD_CUT_VERSION):
        return 8
    raise RuntimeError(f"release {version} does not use schema-2 runtime attestation")


def protected_release_artifacts(version: str) -> dict[str, Any]:
    """Name every protocol-2 runtime artifact explicitly in signed policy."""

    _ver_tuple(version)
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


def published_upgrade_baselines() -> list[str]:
    """Load the single release-gate/source-support matrix."""
    try:
        payload = json.loads(UPGRADE_BASELINES_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"could not load {UPGRADE_BASELINES_PATH}: {exc}") from exc
    expected_keys = {
        "schema_version",
        "published_baselines",
        "published_baseline_config_versions",
        "platform_published_baselines",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected_keys
        or payload.get("schema_version") != 2
    ):
        raise RuntimeError("upgrade baseline policy must be a schema_version 2 object")
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
    config_versions = payload.get("published_baseline_config_versions")
    if not isinstance(config_versions, dict) or set(config_versions) != set(baselines):
        raise RuntimeError(
            "published_baseline_config_versions keys must exactly match published_baselines"
        )
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value not in {5, 6, 7}
        for value in config_versions.values()
    ):
        raise RuntimeError("published baseline config versions must be integers in {5, 6, 7}")
    if (
        OBSERVABILITY_V8_BRIDGE_VERSION in config_versions
        and config_versions.get(OBSERVABILITY_V8_BRIDGE_VERSION) != 7
    ):
        raise RuntimeError("the observability-v8 bridge baseline must use config version 7")
    return baselines


def platform_published_upgrade_baselines() -> dict[str, list[str]]:
    """Load reviewed platform subsets without widening the global matrix."""

    try:
        payload = json.loads(UPGRADE_BASELINES_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"could not load {UPGRADE_BASELINES_PATH}: {exc}") from exc
    platforms = payload.get("platform_published_baselines")
    if not isinstance(platforms, dict) or set(platforms) != {"windows"}:
        raise RuntimeError("platform_published_baselines must contain exactly the windows matrix")
    global_baselines = published_upgrade_baselines()
    windows = platforms["windows"]
    if not isinstance(windows, list) or not windows:
        raise RuntimeError("platform_published_baselines.windows must be a non-empty list")
    if not all(isinstance(value, str) and SEMVER_RE.fullmatch(value) for value in windows):
        raise RuntimeError("platform_published_baselines.windows must contain canonical X.Y.Z versions")
    expected = sorted(windows, key=_ver_tuple, reverse=True)
    if windows != expected:
        raise RuntimeError(
            "platform_published_baselines.windows must be strictly descending: "
            f"got {windows}, want {expected}"
        )
    if len(windows) != len(set(windows)):
        raise RuntimeError(f"platform_published_baselines.windows contains duplicates: {windows}")
    if any(value not in global_baselines for value in windows):
        raise RuntimeError("platform_published_baselines.windows must be a subset of published_baselines")
    return {"windows": windows}


def release_upgrade_policy(version: str) -> dict[str, Any]:
    """Return transition policy independently of controller capability."""
    version_t = _ver_tuple(version)
    bridge_t = _ver_tuple(OBSERVABILITY_V8_BRIDGE_VERSION)
    if version_t < bridge_t:
        return {"min_upgrade_protocol": LEGACY_UPGRADE_PROTOCOL_VERSION}

    tested_sources = [
        baseline for baseline in published_upgrade_baselines() if _ver_tuple(baseline) < version_t
    ]
    platform_tested_sources = {
        platform: [baseline for baseline in baselines if _ver_tuple(baseline) < version_t]
        for platform, baselines in platform_published_upgrade_baselines().items()
    }
    if not tested_sources:
        raise RuntimeError(f"release {version} has an empty tested-source matrix")
    policy: dict[str, Any] = {
        "min_upgrade_protocol": LEGACY_UPGRADE_PROTOCOL_VERSION,
        "tested_source_versions": tested_sources,
        "platform_tested_source_versions": platform_tested_sources,
    }
    if version_t < _ver_tuple(OBSERVABILITY_V8_HARD_CUT_VERSION):
        if any(not values for values in platform_tested_sources.values()):
            raise RuntimeError(f"release {version} has an empty tested-source matrix")
        return policy

    auto_bridge_from = [
        baseline
        for baseline in published_upgrade_baselines()
        if _ver_tuple(baseline) < bridge_t
    ]
    if not auto_bridge_from:
        raise RuntimeError("hard-cut policy has no tested pre-bridge source versions")
    if OBSERVABILITY_V8_BRIDGE_VERSION not in tested_sources:
        raise RuntimeError(
            f"required bridge {OBSERVABILITY_V8_BRIDGE_VERSION} is absent from the "
            "global tested-source matrix"
        )
    for platform, sources in tuple(platform_tested_sources.items()):
        if OBSERVABILITY_V8_BRIDGE_VERSION not in sources:
            # A platform cannot traverse the hard cut when the immutable
            # bridge was not published for it. Encode that platform as
            # unsupported instead of claiming its older releases were tested
            # through a bridge that users cannot install.
            platform_tested_sources[platform] = []
    policy.update(
        {
            "min_upgrade_protocol": HARD_CUT_UPGRADE_PROTOCOL_VERSION,
            "minimum_source_version": OBSERVABILITY_V8_BRIDGE_VERSION,
            "required_bridge_version": OBSERVABILITY_V8_BRIDGE_VERSION,
            "auto_bridge_from": auto_bridge_from,
        }
    )
    return policy


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
        "schema_version": (
            2 if current_t >= _ver_tuple(OBSERVABILITY_V8_BRIDGE_VERSION) else 1
        ),
        "release_version": version,
        "controller_upgrade_protocol": controller_upgrade_protocol(),
        "migration_failure_policy": "fail" if required else "warn",
        "required_cli_migrations": required,
        "windows_installer": {
            "asset": "DefenseClawSetup-x64.exe",
            "architectures": ["amd64"],
            "handoff_args": [
                "/upgrade",
                "/quiet",
                "/norestart",
                "INSTALLSCOPE=user",
            ],
            "authenticode": {
                "required": True,
                "publisher": "Cisco Systems, Inc.",
            },
            "managed_policy": "respect",
        },
        "generated_by": "scripts/generate-upgrade-manifest.py",
    }
    manifest.update(release_upgrade_policy(version))
    if manifest["schema_version"] == 2:
        compatibility_version = compatibility_config_version()
        if compatibility_version != 7:
            raise RuntimeError(
                "schema-2 source must retain CurrentConfigVersion=7 as its "
                f"compatibility ceiling, got {compatibility_version}"
            )
        runtime_version = runtime_config_version(version)
        expected_runtime_version = expected_runtime_config_version(version)
        if runtime_version != expected_runtime_version:
            literal = (
                "ObservabilityV8ConfigVersion"
                if current_t >= _ver_tuple(OBSERVABILITY_V8_HARD_CUT_VERSION)
                else "CurrentConfigVersion"
            )
            raise RuntimeError(
                f"release {version} requires {literal}={expected_runtime_version}, "
                f"got {runtime_version}"
            )
        manifest["runtime_config_version"] = runtime_version
        manifest["release_artifacts"] = protected_release_artifacts(version)
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
