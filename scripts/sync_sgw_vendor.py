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

"""Synchronize and verify the pinned public s-gw source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MODULE_MANIFEST = ROOT / "release" / "s-gw-module.json"
ALLOWED_GIT_MODES = {"100644": 0o644, "100755": 0o755}


class VendorError(RuntimeError):
    pass


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VendorError(f"could not read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise VendorError(f"{path} must contain one JSON object")
    return value


def module_manifest(path: Path = MODULE_MANIFEST) -> dict[str, Any]:
    data = read_json_object(path)
    required = {
        "schema_version",
        "module_name",
        "package_name",
        "package_version",
        "upstream_package_version",
        "upstream_repository",
        "upstream_revision",
        "upstream_tree",
        "source_path",
        "source_inventory",
        "source_selection",
        "minimum_node_version",
        "entrypoints",
        "install",
        "runner_manifest",
    }
    missing = sorted(required.difference(data))
    if missing:
        raise VendorError(f"{path} is missing fields: {', '.join(missing)}")
    if data["schema_version"] != 1:
        raise VendorError(f"unsupported s-gw module schema: {data['schema_version']!r}")
    for field in ("upstream_revision", "upstream_tree"):
        value = data[field]
        if not isinstance(value, str) or len(value) != 40 or any(c not in "0123456789abcdef" for c in value):
            raise VendorError(f"{field} must be a lowercase 40-character Git object ID")
    return data


def selected_source_path(path: str, manifest: dict[str, Any]) -> bool:
    selection = manifest["source_selection"]
    if not isinstance(selection, dict):
        raise VendorError("source_selection must be an object")
    files = selection.get("files")
    directories = selection.get("directories")
    excluded = selection.get("exclude_directories")
    if not isinstance(files, list) or not all(isinstance(item, str) for item in files):
        raise VendorError("source_selection.files must contain strings")
    if not isinstance(directories, list) or not all(isinstance(item, str) for item in directories):
        raise VendorError("source_selection.directories must contain strings")
    if not isinstance(excluded, list) or not all(isinstance(item, str) for item in excluded):
        raise VendorError("source_selection.exclude_directories must contain strings")
    for item in [*files, *directories, *excluded]:
        safe_member_path(item)

    if path in set(files):
        return True
    for prefix in excluded:
        if path == prefix or path.startswith(f"{prefix}/"):
            return False
    return any(path.startswith(f"{prefix}/") for prefix in directories)


def checked_repo_path(relative: object, *, label: str) -> Path:
    if not isinstance(relative, str):
        raise VendorError(f"{label} must be a repository-relative string")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise VendorError(f"unsafe {label}: {relative!r}")
    path = ROOT.joinpath(*pure.parts)
    try:
        path.resolve().relative_to(ROOT.resolve())
    except (OSError, ValueError) as exc:
        raise VendorError(f"{label} escapes the repository: {relative!r}") from exc
    return path


def safe_member_path(value: str) -> PurePosixPath:
    if "\\" in value or "\x00" in value:
        raise VendorError(f"unsafe upstream path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise VendorError(f"unsafe upstream path: {value!r}")
    return path


def run_git(source: Path, *args: str, text: bool = True) -> str | bytes:
    command = ["git", "-C", os.fspath(source), *args]
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=text)
    except OSError as exc:
        raise VendorError(f"could not execute git: {exc}") from exc
    if result.returncode != 0:
        stderr = result.stderr.strip() if text else result.stderr.decode("utf-8", "replace").strip()
        raise VendorError(stderr or f"git command failed: {' '.join(args)}")
    return result.stdout


def clean_source_identity(source: Path, expected_commit: str, expected_tree: str) -> None:
    if not source.is_dir():
        raise VendorError(f"s-gw source is not a directory: {source}")
    commit = str(run_git(source, "rev-parse", "HEAD")).strip()
    if commit != expected_commit:
        raise VendorError(f"s-gw source is at {commit}, expected {expected_commit}")
    tree = str(run_git(source, "rev-parse", f"{expected_commit}^{{tree}}")).strip()
    if tree != expected_tree:
        raise VendorError(f"s-gw source tree is {tree}, expected {expected_tree}")
    dirty = str(run_git(source, "status", "--porcelain", "--untracked-files=all")).strip()
    if dirty:
        raise VendorError("s-gw source checkout must be clean before synchronization")


def git_tree_records(source: Path, revision: str) -> list[tuple[str, str, str]]:
    raw = run_git(source, "ls-tree", "-rz", "--full-tree", revision, text=False)
    assert isinstance(raw, bytes)
    records: list[tuple[str, str, str]] = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            metadata, encoded_path = item.split(b"\t", 1)
            mode, kind, object_id = metadata.decode("ascii").split(" ")
            path = encoded_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise VendorError("upstream Git tree contains an invalid entry") from exc
        if kind != "blob" or mode not in ALLOWED_GIT_MODES:
            raise VendorError(f"unsupported upstream Git entry {mode} {kind} {path}")
        safe_member_path(path)
        records.append((path, mode, object_id))
    if not records:
        raise VendorError("upstream Git tree is empty")
    records.sort(key=lambda item: item[0].encode("utf-8"))
    return records


def blob(source: Path, object_id: str) -> bytes:
    value = run_git(source, "cat-file", "blob", object_id, text=False)
    assert isinstance(value, bytes)
    return value


def git_blob_oid(value: bytes) -> str:
    payload = b"blob " + str(len(value)).encode("ascii") + b"\0" + value
    return hashlib.sha1(payload, usedforsecurity=False).hexdigest()  # noqa: S324 - Git object identity is SHA-1.


def checkout_mode(path: Path, *, platform_name: str | None = None) -> int | None:
    """Return a meaningful POSIX checkout mode when the host exposes one."""
    if (platform_name or os.name) == "nt":
        return None
    return path.stat().st_mode & 0o777


def source_record(path: str, mode: str, object_id: str, value: bytes) -> dict[str, object]:
    return {
        "git_blob": object_id,
        "path": path,
        "mode": mode,
        "size": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
    }


def validate_package_contract(root: Path, manifest: dict[str, Any]) -> None:
    package_path = root / "package.json"
    package = read_json_object(package_path)
    if package.get("name") != manifest["package_name"]:
        raise VendorError(f"vendored package name is not {manifest['package_name']!r}")
    if package.get("version") != manifest["upstream_package_version"]:
        raise VendorError(f"vendored upstream package version is not {manifest['upstream_package_version']!r}")
    engines = package.get("engines")
    expected_engine = f">={manifest['minimum_node_version'].split('.', 1)[0]}"
    if not isinstance(engines, dict) or engines.get("node") != expected_engine:
        raise VendorError(f"vendored package must declare Node {expected_engine}")
    for leaf in ("LICENSE", "NOTICE"):
        item = root / leaf
        if not item.is_file() or item.is_symlink() or item.stat().st_size == 0:
            raise VendorError(f"vendored source lacks a regular non-empty {leaf}")
    entrypoints = manifest["entrypoints"]
    if not isinstance(entrypoints, dict) or set(entrypoints) != {"cli", "mcp"}:
        raise VendorError("s-gw entrypoints must define exactly cli and mcp")
    bins = package.get("bin")
    if not isinstance(bins, dict):
        raise VendorError("vendored package lacks executable entrypoints")
    expected_bins = {
        "s-gw": f"./{entrypoints['cli']}",
        "s-gw-mcp": f"./{entrypoints['mcp']}",
    }
    for name, target in expected_bins.items():
        if bins.get(name) != target:
            raise VendorError(f"vendored package entrypoint {name!r} is not {target!r}")


def synchronize(source: Path) -> int:
    manifest = module_manifest()
    revision = manifest["upstream_revision"]
    tree = manifest["upstream_tree"]
    clean_source_identity(source, revision, tree)
    target = checked_repo_path(manifest["source_path"], label="source_path")
    inventory_path = checked_repo_path(manifest["source_inventory"], label="source_inventory")
    target.parent.mkdir(parents=True, exist_ok=True)

    staging = Path(tempfile.mkdtemp(prefix=".s-gw-upstream-", dir=target.parent))
    backup: Path | None = None
    records: list[dict[str, object]] = []
    try:
        selected = [
            record for record in git_tree_records(source, revision) if selected_source_path(record[0], manifest)
        ]
        if not selected:
            raise VendorError("s-gw source selection is empty")
        for relative, mode, object_id in selected:
            value = blob(source, object_id)
            destination = staging.joinpath(*safe_member_path(relative).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(value)
            destination.chmod(ALLOWED_GIT_MODES[mode])
            if git_blob_oid(value) != object_id:
                raise VendorError(f"upstream Git returned the wrong blob object for {relative}")
            records.append(source_record(relative, mode, object_id, value))
        validate_package_contract(staging, manifest)

        if target.exists() or target.is_symlink():
            if target.is_symlink() or not target.is_dir():
                raise VendorError(f"refusing to replace non-directory vendored source: {target}")
            backup = target.parent / f".s-gw-upstream-backup-{os.getpid()}"
            if backup.exists() or backup.is_symlink():
                raise VendorError(f"refusing to replace existing sync backup: {backup}")
            os.replace(target, backup)
        os.replace(staging, target)
        staging = Path()

        inventory = {
            "schema_version": 2,
            "repository": manifest["upstream_repository"],
            "revision": revision,
            "tree": tree,
            "files": records,
        }
        payload = (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode("utf-8")
        tmp_inventory = inventory_path.with_name(f".{inventory_path.name}.{os.getpid()}.tmp")
        tmp_inventory.write_bytes(payload)
        tmp_inventory.chmod(0o644)
        os.replace(tmp_inventory, inventory_path)
        if backup is not None:
            shutil.rmtree(backup)
    except Exception:
        if staging and staging.exists():
            shutil.rmtree(staging)
        if backup is not None and backup.exists() and not target.exists():
            os.replace(backup, target)
        raise

    verify()
    print(f"s-gw vendor synchronized at {revision} ({len(records)} files)")
    return 0


def inventory_records(data: dict[str, Any]) -> dict[str, dict[str, object]]:
    raw = data.get("files")
    if not isinstance(raw, list) or not raw:
        raise VendorError("s-gw source inventory has no files")
    result: dict[str, dict[str, object]] = {}
    for record in raw:
        if not isinstance(record, dict):
            raise VendorError("s-gw source inventory contains a non-object record")
        if set(record) != {"git_blob", "mode", "path", "sha256", "size"}:
            raise VendorError("s-gw source inventory record has unexpected fields")
        path = record.get("path")
        if not isinstance(path, str):
            raise VendorError("s-gw source inventory contains an invalid path")
        safe_member_path(path)
        if path in result:
            raise VendorError(f"duplicate s-gw source inventory path: {path}")
        mode = record.get("mode")
        digest = record.get("sha256")
        git_blob = record.get("git_blob")
        size = record.get("size")
        if mode not in ALLOWED_GIT_MODES:
            raise VendorError(f"invalid mode for {path}: {mode!r}")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise VendorError(f"invalid SHA-256 for {path}")
        if not isinstance(git_blob, str) or len(git_blob) != 40 or any(c not in "0123456789abcdef" for c in git_blob):
            raise VendorError(f"invalid Git blob object ID for {path}")
        if not isinstance(size, int) or size < 0:
            raise VendorError(f"invalid size for {path}")
        result[path] = record
    return result


def verify() -> int:
    manifest = module_manifest()
    root = checked_repo_path(manifest["source_path"], label="source_path")
    inventory_path = checked_repo_path(manifest["source_inventory"], label="source_inventory")
    inventory = read_json_object(inventory_path)
    if inventory.get("schema_version") != 2:
        raise VendorError("unsupported s-gw source inventory schema")
    for field, expected in (
        ("repository", manifest["upstream_repository"]),
        ("revision", manifest["upstream_revision"]),
        ("tree", manifest["upstream_tree"]),
    ):
        if inventory.get(field) != expected:
            raise VendorError(f"s-gw source inventory {field} does not match the module manifest")
    expected = inventory_records(inventory)
    if not root.is_dir() or root.is_symlink():
        raise VendorError(f"vendored s-gw source is not a regular directory: {root}")

    found: set[str] = set()
    for item in root.rglob("*"):
        if item.is_dir() and not item.is_symlink():
            continue
        relative = item.relative_to(root).as_posix()
        if item.is_symlink() or not item.is_file():
            raise VendorError(f"vendored s-gw contains a non-regular entry: {relative}")
        record = expected.get(relative)
        if record is None:
            raise VendorError(f"vendored s-gw contains an untracked file: {relative}")
        value = item.read_bytes()
        if len(value) != record["size"]:
            raise VendorError(f"vendored s-gw size mismatch: {relative}")
        if hashlib.sha256(value).hexdigest() != record["sha256"]:
            raise VendorError(f"vendored s-gw digest mismatch: {relative}")
        if git_blob_oid(value) != record["git_blob"]:
            raise VendorError(f"vendored s-gw Git blob identity mismatch: {relative}")
        actual_mode = checkout_mode(item)
        expected_mode = ALLOWED_GIT_MODES[str(record["mode"])]
        if actual_mode is not None and actual_mode != expected_mode:
            raise VendorError(f"vendored s-gw mode mismatch: {relative} is {actual_mode:o}, expected {expected_mode:o}")
        found.add(relative)
    missing = sorted(set(expected).difference(found))
    if missing:
        raise VendorError(f"vendored s-gw is missing files: {', '.join(missing[:5])}")
    validate_package_contract(root, manifest)
    print(f"s-gw vendor verified at {manifest['upstream_revision']} ({len(found)} files)")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify", help="verify the checked-in source mirror")
    sync = subparsers.add_parser("sync", help="replace the mirror from a clean pinned checkout")
    sync.add_argument("--source", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "sync":
            return synchronize(args.source.resolve())
        return verify()
    except VendorError as exc:
        print(f"s-gw vendor validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
