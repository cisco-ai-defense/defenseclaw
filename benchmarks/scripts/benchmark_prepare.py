#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Safely materialize pinned benchmark sources without running source code.

Git sources are fetched into a blobless bare object database. Only blobs below
locked include paths are hydrated and streamed through ``git cat-file``. The
exporter rejects links, submodules, absolute paths, and traversal entries and
strips executable bits. Git checkout, hooks, archive attributes, and content
filters are never invoked. Hugging Face Git-LFS pointers are resolved directly
and verified against their declared SHA-256 and size.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

LFS_POINTER = re.compile(
    rb"\Aversion https://git-lfs\.github\.com/spec/v1\n"
    rb"oid sha256:([0-9a-f]{64})\nsize ([0-9]+)\n?\Z"
)
GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", default="benchmarks/datasets.lock.json")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument(
        "--datasets",
        required=True,
        help="comma-separated dataset IDs; explicit selection prevents accidental bulk downloads",
    )
    parser.add_argument(
        "--allow-unapproved",
        action="store_true",
        help="allow license_status other than approved (for authorized review only)",
    )
    parser.add_argument(
        "--max-git-bytes",
        type=int,
        default=10 * 1024 * 1024 * 1024,
        help="maximum aggregate selected Git blob bytes per dataset",
    )
    parser.add_argument(
        "--max-lfs-bytes",
        type=int,
        default=10 * 1024 * 1024 * 1024,
        help="maximum aggregate Git-LFS bytes per dataset",
    )
    return parser.parse_args()


def run_checked(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, check=True, **kwargs)  # noqa: S603 -- argv is fixed and never shell-parsed.


def load_lock(path: Path) -> dict[str, dict[str, object]]:
    with path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if raw.get("schema_version") != "1":
        raise ValueError("unsupported dataset lock schema")
    datasets: dict[str, dict[str, object]] = {}
    for item in raw.get("datasets", []):
        dataset_id = item.get("id")
        if not isinstance(dataset_id, str) or not dataset_id:
            raise ValueError("dataset lock contains an invalid ID")
        if dataset_id in datasets:
            raise ValueError(f"duplicate dataset ID {dataset_id!r}")
        datasets[dataset_id] = item
    return datasets


def ensure_below(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve()
    resolved = candidate.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError(f"path escapes data directory: {candidate}")
    return resolved


def archive_member_path(root: Path, name: str) -> Path:
    pure = PurePosixPath(name)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"unsafe archive path {name!r}")
    return ensure_below(root, root.joinpath(*pure.parts))


def validate_include_paths(raw: object, dataset_id: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"{dataset_id}: include_paths must be a non-empty list")
    out: list[str] = []
    for value in raw:
        if not isinstance(value, str):
            raise ValueError(f"{dataset_id}: include_paths entries must be strings")
        pure = PurePosixPath(value)
        if (
            pure.is_absolute()
            or not pure.parts
            or any(part in {"", ".", ".."} for part in pure.parts)
            or any(character in value for character in "*?[\\")
        ):
            raise ValueError(f"{dataset_id}: unsafe include path {value!r}")
        normalized = pure.as_posix()
        if normalized in out:
            raise ValueError(f"{dataset_id}: duplicate include path {value!r}")
        out.append(normalized)
    return out


def parse_git_tree_entry(raw: bytes) -> tuple[str, str, int]:
    try:
        metadata, raw_path = raw.split(b"\t", 1)
        fields = metadata.split(b" ")
        if len(fields) not in {3, 4}:
            raise ValueError
        mode, object_type, object_id = fields[:3]
        size = int(fields[3]) if len(fields) == 4 else -1
        path = raw_path.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Git tree contains an invalid entry") from exc
    if mode not in {b"100644", b"100755"} or object_type != b"blob":
        raise ValueError(f"Git tree contains unsupported entry type: {path!r}")
    if not re.fullmatch(rb"[0-9a-f]{40,64}", object_id) or size < -1:
        raise ValueError(f"Git tree contains invalid object metadata: {path!r}")
    return path, object_id.decode("ascii"), size


def selected_git_entries(git_dir: Path, revision: str, include_paths: list[str]) -> list[tuple[str, str, int]]:
    # Do not request ``ls-tree -l`` here. On a blobless promisor clone Git
    # resolves each missing blob separately just to discover its size, which
    # turns a source with thousands of small files into thousands of network
    # round trips. Hydrate the selected object IDs in bounded batches first,
    # then obtain sizes locally below.
    command = ["git", f"--git-dir={git_dir}", "ls-tree", "-rz", "-r", "--full-tree", revision]
    if include_paths:
        command.extend(["--", *include_paths])
    raw = run_checked(command, stdout=subprocess.PIPE).stdout
    entries = [parse_git_tree_entry(item) for item in raw.split(b"\0") if item]
    if not entries:
        raise ValueError("locked Git include paths selected no files")
    return entries


def hydrate_git_blobs(
    git_dir: Path,
    entries: list[tuple[str, str, int]],
) -> list[tuple[str, str, int]]:
    object_ids = sorted({object_id for _, object_id, _ in entries})
    check_input = ("\n".join(object_ids) + "\n").encode("ascii")
    environment = dict(os.environ)
    environment["GIT_NO_LAZY_FETCH"] = "1"
    checked = run_checked(
        ["git", f"--git-dir={git_dir}", "cat-file", "--batch-check"],
        input=check_input,
        stdout=subprocess.PIPE,
        env=environment,
    ).stdout.decode("ascii")
    missing = [line.split(" ", 1)[0] for line in checked.splitlines() if line.endswith(" missing")]
    for offset in range(0, len(missing), 128):
        run_checked(
            [
                "git",
                f"--git-dir={git_dir}",
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                "origin",
                *missing[offset : offset + 128],
            ],
            stdout=subprocess.DEVNULL,
        )
    sized = run_checked(
        ["git", f"--git-dir={git_dir}", "cat-file", "--batch-check"],
        input=check_input,
        stdout=subprocess.PIPE,
        env=environment,
    ).stdout.decode("ascii")
    sizes: dict[str, int] = {}
    for line in sized.splitlines():
        fields = line.split(" ")
        if len(fields) != 3 or fields[1] != "blob":
            raise ValueError("selected Git object did not resolve to a blob")
        size = int(fields[2])
        if size < 0:
            raise ValueError("selected Git blob has an invalid size")
        sizes[fields[0]] = size
    return [(path, object_id, sizes[object_id]) for path, object_id, _ in entries]


def export_git_blobs(
    git_dir: Path,
    destination: Path,
    entries: list[tuple[str, str, int]],
) -> None:
    if any(size < 0 for _, _, size in entries):
        entries = hydrate_git_blobs(git_dir, entries)
    # Keep request batches small so writing object IDs cannot fill the pipe
    # before we start draining potentially large blob responses.
    for offset in range(0, len(entries), 128):
        batch = entries[offset : offset + 128]
        process = subprocess.Popen(  # noqa: S603 -- fixed git argv; object IDs are validated hashes.
            ["git", f"--git-dir={git_dir}", "cat-file", "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
        )
        assert process.stdin is not None
        assert process.stdout is not None
        try:
            process.stdin.write(("\n".join(object_id for _, object_id, _ in batch) + "\n").encode("ascii"))
            process.stdin.close()
            for path, expected_id, expected_size in batch:
                header = process.stdout.readline().decode("ascii", "strict").strip().split(" ")
                if len(header) != 3 or header[0] != expected_id or header[1] != "blob":
                    raise ValueError(f"unexpected Git object response for {path!r}")
                size = int(header[2])
                if size != expected_size:
                    raise ValueError(f"Git object size changed for {path!r}")
                target = archive_member_path(destination, path)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                remaining = size
                with target.open("xb") as output:
                    while remaining:
                        chunk = process.stdout.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ValueError(f"truncated Git object for {path!r}")
                        output.write(chunk)
                        remaining -= len(chunk)
                if process.stdout.read(1) != b"\n":
                    raise ValueError(f"invalid Git object delimiter for {path!r}")
                target.chmod(0o644)
        except Exception:
            process.kill()
            process.wait()
            if not process.stdin.closed:
                process.stdin.close()
            process.stdout.close()
            if process.stderr:
                process.stderr.close()
            raise
        stderr = process.stderr.read().decode("utf-8", "replace") if process.stderr else ""
        exit_code = process.wait()
        process.stdout.close()
        if process.stderr:
            process.stderr.close()
        if exit_code != 0:
            raise RuntimeError(f"git cat-file failed: {stderr.strip()}")


def lfs_pointer(path: Path) -> tuple[str, int] | None:
    if path.stat().st_size > 512:
        return None
    match = LFS_POINTER.fullmatch(path.read_bytes())
    if not match:
        return None
    return match.group(1).decode("ascii"), int(match.group(2))


def resolve_huggingface_lfs(source_url: str, revision: str, root: Path, max_bytes: int) -> int:
    parsed = urllib.parse.urlsplit(source_url)
    if parsed.netloc != "huggingface.co":
        return 0
    total = 0
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        pointer = lfs_pointer(path)
        if pointer is None:
            continue
        expected_digest, expected_size = pointer
        total += expected_size
        if total > max_bytes:
            raise ValueError(f"Git-LFS content exceeds --max-lfs-bytes ({max_bytes})")
        relative = path.relative_to(root).as_posix()
        quoted = urllib.parse.quote(relative, safe="/")
        url = f"{source_url.rstrip('/')}/resolve/{revision}/{quoted}?download=true"
        request = urllib.request.Request(url, headers={"User-Agent": "DefenseClaw-benchmark/1"})
        temporary = path.with_name(path.name + ".download")
        digest = hashlib.sha256()
        size = 0
        try:
            with urllib.request.urlopen(request, timeout=120) as response, temporary.open("xb") as output:  # noqa: S310 -- host is lock-pinned and checked above.
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > expected_size:
                        raise ValueError(f"Git-LFS object exceeded declared size for {relative}")
                    digest.update(chunk)
                    output.write(chunk)
            if size != expected_size or digest.hexdigest() != expected_digest:
                raise ValueError(f"Git-LFS verification failed for {relative}")
            temporary.chmod(0o644)
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return total


def prepare_git(dataset: dict[str, object], data_root: Path, max_git_bytes: int, max_lfs_bytes: int) -> None:
    dataset_id = str(dataset["id"])
    source_url = str(dataset["source_url"])
    revision = str(dataset["revision"])
    if not GIT_REVISION.fullmatch(revision):
        raise ValueError(f"{dataset_id}: Git source is not pinned to a full revision")
    include_paths = validate_include_paths(dataset.get("include_paths"), dataset_id)

    sources_root = ensure_below(data_root, data_root / "sources")
    cache_root = ensure_below(data_root, data_root / ".git-cache")
    sources_root.mkdir(parents=True, exist_ok=True)
    cache_root.mkdir(parents=True, exist_ok=True)
    destination = ensure_below(sources_root, sources_root / dataset_id)
    metadata_path = destination / ".defenseclaw-source.json"
    if destination.exists():
        if metadata_path.is_file():
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if (
                metadata.get("source_url") == source_url
                and metadata.get("revision") == revision
                and metadata.get("include_paths", []) == include_paths
            ):
                print(f"{dataset_id}: already prepared at {destination}")
                return
        raise ValueError(f"{dataset_id}: destination exists with different or missing provenance: {destination}")

    git_dir = ensure_below(cache_root, cache_root / f"{dataset_id}.git")
    if not git_dir.exists():
        run_checked(["git", "init", "--bare", str(git_dir)], stdout=subprocess.DEVNULL)
        run_checked(["git", f"--git-dir={git_dir}", "config", "core.hooksPath", os.devnull])
        run_checked(["git", f"--git-dir={git_dir}", "remote", "add", "origin", source_url])
    else:
        remote = (
            run_checked(
                ["git", f"--git-dir={git_dir}", "remote", "get-url", "origin"],
                stdout=subprocess.PIPE,
            )
            .stdout.decode()
            .strip()
        )
        if remote != source_url:
            raise ValueError(f"{dataset_id}: cached remote differs from lock")
    # A pinned repository can still contain many gigabytes of unrelated
    # package blobs. Make the bare cache a promisor remote and fetch trees and
    # commits only; the selected exporter hydrates just the locked include paths.
    run_checked(["git", f"--git-dir={git_dir}", "config", "remote.origin.promisor", "true"])
    run_checked(["git", f"--git-dir={git_dir}", "config", "remote.origin.partialclonefilter", "blob:none"])
    run_checked(
        [
            "git",
            f"--git-dir={git_dir}",
            "fetch",
            "--depth=1",
            "--filter=blob:none",
            "--no-tags",
            "origin",
            revision,
        ],
        stdout=subprocess.DEVNULL,
    )
    fetched = (
        run_checked(
            ["git", f"--git-dir={git_dir}", "rev-parse", "FETCH_HEAD^{commit}"],
            stdout=subprocess.PIPE,
        )
        .stdout.decode()
        .strip()
    )
    if fetched != revision:
        raise ValueError(f"{dataset_id}: fetched {fetched}, expected {revision}")

    entries = selected_git_entries(git_dir, revision, include_paths)
    entries = hydrate_git_blobs(git_dir, entries)
    selected_bytes = sum(size for _, _, size in entries)
    if selected_bytes > max_git_bytes:
        raise ValueError(f"selected Git content exceeds --max-git-bytes ({max_git_bytes})")

    with tempfile.TemporaryDirectory(prefix=f".{dataset_id}-", dir=sources_root) as temporary_name:
        temporary = ensure_below(sources_root, Path(temporary_name))
        export_git_blobs(git_dir, temporary, entries)
        lfs_bytes = resolve_huggingface_lfs(source_url, revision, temporary, max_lfs_bytes)
        metadata = {
            "schema_version": "1",
            "id": dataset_id,
            "source_url": source_url,
            "revision": revision,
            "license": dataset["license"],
            "license_status": dataset["license_status"],
            "include_paths": include_paths,
            "git_bytes": selected_bytes,
            "lfs_bytes": lfs_bytes,
        }
        (temporary / ".defenseclaw-source.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, destination)
    print(f"{dataset_id}: prepared at {destination}")


def main() -> int:
    args = parse_args()
    data_root = Path(args.data_dir).expanduser().resolve()
    data_root.mkdir(parents=True, exist_ok=True)
    datasets = load_lock(Path(args.lock))
    selected = [item.strip() for item in args.datasets.split(",") if item.strip()]
    if not selected:
        raise ValueError("--datasets must select at least one dataset")
    unknown = sorted(set(selected) - set(datasets))
    if unknown:
        raise ValueError(f"unknown dataset IDs: {', '.join(unknown)}")

    for dataset_id in selected:
        dataset = datasets[dataset_id]
        license_status = dataset.get("license_status")
        if license_status != "approved" and not args.allow_unapproved:
            raise ValueError(
                f"{dataset_id}: license_status={license_status}; legal approval or --allow-unapproved is required"
            )
        fetch = dataset.get("fetch")
        if fetch == "vendored":
            source = Path(str(dataset["source_url"]))
            if not source.is_file():
                raise ValueError(f"{dataset_id}: vendored source is missing: {source}")
            print(f"{dataset_id}: vendored at {source}")
        elif fetch == "git":
            prepare_git(dataset, data_root, args.max_git_bytes, args.max_lfs_bytes)
        else:
            raise ValueError(f"{dataset_id}: fetch={fetch} requires manual preparation")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"benchmark-prepare: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
