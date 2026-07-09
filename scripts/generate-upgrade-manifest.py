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
UPGRADE_PROTOCOL_VERSION = 1


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
            if not isinstance(item, ast.Tuple) or not item.elts:
                raise RuntimeError("each MIGRATIONS entry must be a tuple")
            version_node = item.elts[0]
            if not isinstance(version_node, ast.Constant) or not isinstance(version_node.value, str):
                raise RuntimeError("each MIGRATIONS entry must start with a string version")
            _ver_tuple(version_node.value)
            versions.append(version_node.value)
        expected = sorted(versions, key=_ver_tuple)
        if versions != expected:
            raise RuntimeError(f"MIGRATIONS must be sorted ascending: got {versions}, want {expected}")
        if len(versions) != len(set(versions)):
            raise RuntimeError(f"MIGRATIONS contains duplicates: {versions}")
        return versions
    raise RuntimeError("MIGRATIONS registry not found")


def build_manifest() -> dict[str, Any]:
    version = current_version()
    migrations = migration_versions()
    current_t = _ver_tuple(version)
    future = [migration for migration in migrations if _ver_tuple(migration) > current_t]
    if future:
        raise RuntimeError(
            "migration registry contains versions newer than the package version "
            f"{version}: {', '.join(future)}. Bump the release version first."
        )

    required = [migration for migration in migrations if _ver_tuple(migration) <= current_t]
    return {
        "schema_version": 1,
        "release_version": version,
        "min_upgrade_protocol": UPGRADE_PROTOCOL_VERSION,
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
