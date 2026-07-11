#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Descriptor-bound, no-clobber publication for authenticated installers."""

from __future__ import annotations

import argparse
import base64
import ctypes
import errno
import hashlib
import json
import os
import stat
import sys
import uuid
from pathlib import Path


class PublishError(RuntimeError):
    pass


def _identity(fd: int) -> tuple[int, int]:
    value = os.fstat(fd)
    return value.st_dev, value.st_ino


def _entry_identity(parent_fd: int, leaf: str) -> tuple[int, int] | None:
    try:
        value = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return value.st_dev, value.st_ino


def _entry_stat(parent_fd: int, leaf: str) -> os.stat_result | None:
    try:
        return os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _open_directory(path: Path, *, create: bool) -> int:
    if not path.is_absolute():
        raise PublishError(f"managed path must be absolute: {path}")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            if not component or component in {".", ".."}:
                raise PublishError(f"managed path has an unsafe component: {path}")
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not create:
                    raise PublishError(f"managed directory is missing: {path}") from None
                staged = f".{component}.install-directory-{uuid.uuid4().hex}"
                staged_descriptor = -1
                mkdir_succeeded = False
                created_identity: tuple[int, int] | None = None
                staged_identity: tuple[int, int] | None = None
                try:
                    os.mkdir(staged, mode=0o700, dir_fd=descriptor)
                    mkdir_succeeded = True
                    created_identity = _entry_identity(descriptor, staged)
                    if created_identity is None:
                        raise PublishError("attempt-created directory disappeared before binding")
                    staged_descriptor = os.open(
                        staged,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=descriptor,
                    )
                    staged_identity = _identity(staged_descriptor)
                    if staged_identity != created_identity:
                        raise PublishError("attempt-created directory changed before binding")
                    os.fsync(staged_descriptor)
                    _rename_no_replace(descriptor, staged, component)
                    os.fsync(descriptor)
                except (OSError, PublishError):
                    if staged_descriptor >= 0:
                        os.close(staged_descriptor)
                    if (
                        mkdir_succeeded
                        and created_identity is not None
                        and _entry_identity(descriptor, staged) == created_identity
                    ):
                        try:
                            os.rmdir(staged, dir_fd=descriptor)
                        except OSError:
                            pass
                    raise PublishError(f"managed directory appeared concurrently and was preserved: {path}") from None
                if _entry_identity(descriptor, component) != staged_identity:
                    os.close(staged_descriptor)
                    raise PublishError(f"managed directory activation identity mismatch: {path}")
                child = staged_descriptor
            except OSError as exc:
                raise PublishError(f"managed directory is not a real directory: {path}") from exc
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _sha256_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def _validate_sha256(value: str | None, *, label: str) -> None:
    if value is not None and (len(value) != 64 or not all(character in "0123456789abcdef" for character in value)):
        raise PublishError(f"expected {label} digest is invalid")


def _open_path_regular(path: Path, *, require_executable: bool = False) -> int:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise PublishError(f"managed entry is not a regular file: {path}")
    if require_executable and not metadata.st_mode & 0o111:
        os.close(descriptor)
        raise PublishError(f"managed entry is not executable: {path}")
    return descriptor


def regular_sha256(path: Path, *, require_executable: bool = False) -> str:
    """Hash one exact, no-follow regular-file descriptor."""

    descriptor = _open_path_regular(path, require_executable=require_executable)
    try:
        return _sha256_fd(descriptor)
    finally:
        os.close(descriptor)


def matching_regular_sha256(
    first: Path,
    second: Path,
    *,
    require_executable: bool = False,
) -> str:
    """Return the digest only when two simultaneously opened files match."""

    first_fd = _open_path_regular(first, require_executable=require_executable)
    try:
        # Open both names before reading either descriptor.  A rename after
        # this point cannot redirect either comparison read to a new inode.
        second_fd = _open_path_regular(second, require_executable=require_executable)
        try:
            first_digest = _sha256_fd(first_fd)
            if _sha256_fd(second_fd) != first_digest:
                raise PublishError(f"regular-file bytes do not match: {first} and {second}")
            return first_digest
        finally:
            os.close(second_fd)
    finally:
        os.close(first_fd)


def _open_regular(parent_fd: int, leaf: str) -> int:
    descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise PublishError(f"managed entry is not a regular file: {leaf}")
    return descriptor


def _exchange(parent_fd: int, first: str, second: str) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function = library.renameatx_np
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    elif sys.platform.startswith("linux"):
        function = library.renameat2
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    else:
        raise PublishError("safe same-checkout replacement is unsupported on this platform")
    function.restype = ctypes.c_int
    result = function(parent_fd, os.fsencode(first), parent_fd, os.fsencode(second), 0x2)
    if result != 0:
        code = ctypes.get_errno()
        raise PublishError(f"atomic source-install exchange failed: errno {code}")


def _rename_no_replace(parent_fd: int, source: str, destination: str) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function = library.renameatx_np
        flag = 0x4  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        function = library.renameat2
        flag = 0x1  # RENAME_NOREPLACE
    else:
        raise PublishError("safe no-replace rename is unsupported on this platform")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(parent_fd, os.fsencode(source), parent_fd, os.fsencode(destination), flag) != 0:
        code = ctypes.get_errno()
        raise PublishError(f"atomic no-replace rename failed: errno {code}")


def ensure_directory(path: Path) -> None:
    descriptor = _open_directory(path, create=True)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fresh_directory(path: Path) -> tuple[int, int]:
    """Atomically reserve a previously absent real directory."""

    if not path.is_absolute() or not path.name or path.name in {".", ".."}:
        raise PublishError(f"fresh-install directory path is unsafe: {path}")
    parent_fd = _open_directory(path.parent, create=False)
    staged = f".{path.name}.install-directory-{uuid.uuid4().hex}"
    staged_fd = -1
    staged_identity: tuple[int, int] | None = None
    activated = False
    try:
        if _entry_identity(parent_fd, path.name) is not None:
            raise PublishError(f"fresh-install directory already exists and was preserved: {path}")
        os.mkdir(staged, mode=0o700, dir_fd=parent_fd)
        staged_fd = os.open(
            staged,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        staged_identity = _identity(staged_fd)
        os.fsync(staged_fd)
        try:
            _rename_no_replace(parent_fd, staged, path.name)
        except PublishError as exc:
            raise PublishError(f"fresh-install directory appeared concurrently and was preserved: {path}") from exc
        activated = True
        if _entry_identity(parent_fd, path.name) != staged_identity:
            raise PublishError(f"fresh-install directory identity mismatch: {path}")
        os.fsync(parent_fd)
        return staged_identity
    finally:
        if staged_fd >= 0:
            os.close(staged_fd)
        if not activated and staged_identity is not None and _entry_identity(parent_fd, staged) == staged_identity:
            try:
                os.rmdir(staged, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError:
                pass
        os.close(parent_fd)


def _rmdir_exact_at(parent_fd: int, leaf: str, expected: tuple[int, int]) -> bool:
    current = _entry_stat(parent_fd, leaf)
    if current is None:
        return True
    if (current.st_dev, current.st_ino) != expected or not stat.S_ISDIR(current.st_mode):
        return False
    displaced = f".{leaf}.rollback-directory-{uuid.uuid4().hex}"
    os.mkdir(displaced, mode=0o700, dir_fd=parent_fd)
    placeholder_fd = os.open(
        displaced,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent_fd,
    )
    placeholder_identity = _identity(placeholder_fd)
    os.close(placeholder_fd)
    try:
        _exchange(parent_fd, displaced, leaf)
    except Exception:
        if _entry_identity(parent_fd, displaced) == placeholder_identity:
            os.rmdir(displaced, dir_fd=parent_fd)
        raise
    displaced_info = _entry_stat(parent_fd, displaced)
    if (
        displaced_info is None
        or (displaced_info.st_dev, displaced_info.st_ino) != expected
        or not stat.S_ISDIR(displaced_info.st_mode)
    ):
        try:
            _exchange(parent_fd, displaced, leaf)
        finally:
            if _entry_identity(parent_fd, displaced) == placeholder_identity:
                os.rmdir(displaced, dir_fd=parent_fd)
                os.fsync(parent_fd)
        return False
    try:
        os.rmdir(displaced, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno not in {errno.ENOTEMPTY, errno.EEXIST}:
            raise
        # Contents appeared (or were already present). Atomically restore
        # the exact directory to its canonical name and preserve them.
        _exchange(parent_fd, displaced, leaf)
        if _entry_identity(parent_fd, displaced) == placeholder_identity:
            os.rmdir(displaced, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return False

    cleanup = ""
    for _attempt in range(16):
        cleanup = f".{leaf}.rollback-placeholder-{uuid.uuid4().hex}"
        try:
            _rename_no_replace(parent_fd, leaf, cleanup)
            break
        except PublishError:
            continue
    else:
        raise PublishError(f"could not retire directory rollback placeholder: {leaf}")
    if _entry_identity(parent_fd, cleanup) != placeholder_identity:
        raise PublishError(f"directory rollback placeholder changed: {leaf}")
    os.rmdir(cleanup, dir_fd=parent_fd)
    os.fsync(parent_fd)
    return True


def rmdir_exact(path: Path, expected: tuple[int, int]) -> bool:
    """Remove only an exact empty directory, preserving races and contents."""

    if not path.is_absolute() or not path.name or path.name in {".", ".."}:
        raise PublishError(f"fresh-install directory path is unsafe: {path}")
    parent_fd = _open_directory(path.parent, create=False)
    try:
        return _rmdir_exact_at(parent_fd, path.name, expected)
    finally:
        os.close(parent_fd)


MAX_REMOVE_TREE_NODES = 500_000
MAX_REMOVE_TREE_BYTES = 16 * 1024 * 1024 * 1024
MAX_REMOVE_TREE_DEPTH = 64


def _account_tree_entry(
    metadata: os.stat_result,
    *,
    root_device: int,
    depth: int,
    budget: dict[str, int],
) -> None:
    if metadata.st_dev != root_device:
        raise PublishError("attempt-owned tree crosses a filesystem boundary")
    if depth > MAX_REMOVE_TREE_DEPTH:
        raise PublishError("attempt-owned tree exceeds the removal depth bound")
    budget["nodes"] += 1
    budget["bytes"] += max(int(metadata.st_size), int(metadata.st_blocks) * 512, 0)
    if budget["nodes"] > MAX_REMOVE_TREE_NODES:
        raise PublishError("attempt-owned tree exceeds the removal node bound")
    if budget["bytes"] > MAX_REMOVE_TREE_BYTES:
        raise PublishError("attempt-owned tree exceeds the removal byte bound")


def _walk_owned_tree(
    directory_fd: int,
    *,
    root_device: int,
    depth: int,
    budget: dict[str, int],
    remove: bool,
) -> None:
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            name = entry.name
            if not name or name in {".", ".."} or "/" in name:
                raise PublishError("attempt-owned tree contains an unsafe entry name")
            try:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            _account_tree_entry(
                metadata,
                root_device=root_device,
                depth=depth,
                budget=budget,
            )
            identity = (metadata.st_dev, metadata.st_ino)
            if stat.S_ISDIR(metadata.st_mode):
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory_fd,
                )
                try:
                    if _identity(child_fd) != identity:
                        raise PublishError("attempt-owned tree directory changed while opening")
                    _walk_owned_tree(
                        child_fd,
                        root_device=root_device,
                        depth=depth + 1,
                        budget=budget,
                        remove=remove,
                    )
                finally:
                    os.close(child_fd)
                if remove and not _rmdir_exact_at(directory_fd, name, identity):
                    raise PublishError("attempt-owned tree directory changed or became nonempty and was preserved")
            elif remove and not _unlink_exact_at(directory_fd, name, identity):
                raise PublishError("attempt-owned tree entry changed and was preserved")


def remove_tree_exact(path: Path, expected: tuple[int, int]) -> bool:
    """Quarantine and boundedly remove only an exact directory tree."""

    if not path.is_absolute() or not path.name or path.name in {".", ".."}:
        raise PublishError(f"fresh-install directory path is unsafe: {path}")
    parent_fd = _open_directory(path.parent, create=False)
    quarantine = f".{path.name}.rollback-tree-{uuid.uuid4().hex}"
    try:
        current = _entry_stat(parent_fd, path.name)
        if current is None:
            return True
        if (current.st_dev, current.st_ino) != expected or not stat.S_ISDIR(current.st_mode):
            return False

        os.mkdir(quarantine, mode=0o700, dir_fd=parent_fd)
        placeholder_fd = os.open(
            quarantine,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        placeholder_identity = _identity(placeholder_fd)
        os.close(placeholder_fd)
        try:
            _exchange(parent_fd, quarantine, path.name)
        except Exception:
            if _entry_identity(parent_fd, quarantine) == placeholder_identity:
                os.rmdir(quarantine, dir_fd=parent_fd)
            raise
        quarantined = _entry_stat(parent_fd, quarantine)
        if (
            quarantined is None
            or (quarantined.st_dev, quarantined.st_ino) != expected
            or not stat.S_ISDIR(quarantined.st_mode)
        ):
            try:
                _exchange(parent_fd, quarantine, path.name)
            finally:
                if _entry_identity(parent_fd, quarantine) == placeholder_identity:
                    os.rmdir(quarantine, dir_fd=parent_fd)
                    os.fsync(parent_fd)
            return False

        retired = f".{path.name}.rollback-placeholder-{uuid.uuid4().hex}"
        _rename_no_replace(parent_fd, path.name, retired)
        if _entry_identity(parent_fd, retired) != placeholder_identity:
            raise PublishError("tree rollback placeholder changed during quarantine")
        os.rmdir(retired, dir_fd=parent_fd)
        os.fsync(parent_fd)

        tree_fd = os.open(
            quarantine,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        try:
            if _identity(tree_fd) != expected:
                raise PublishError("attempt-owned tree changed after quarantine")
            scan_budget = {"nodes": 1, "bytes": 0}
            _walk_owned_tree(
                tree_fd,
                root_device=expected[0],
                depth=1,
                budget=scan_budget,
                remove=False,
            )
        except Exception:
            os.close(tree_fd)
            try:
                _rename_no_replace(parent_fd, quarantine, path.name)
                os.fsync(parent_fd)
            except PublishError:
                # A concurrent canonical path is preserved; the exact tree
                # remains in its private quarantine for explicit recovery.
                pass
            raise

        try:
            remove_budget = {"nodes": 1, "bytes": 0}
            _walk_owned_tree(
                tree_fd,
                root_device=expected[0],
                depth=1,
                budget=remove_budget,
                remove=True,
            )
        finally:
            os.close(tree_fd)
        if not _rmdir_exact_at(parent_fd, quarantine, expected):
            raise PublishError("attempt-owned tree root changed or became nonempty")
        os.fsync(parent_fd)
        return True
    finally:
        os.close(parent_fd)


def publish_symlink(
    target: str,
    destination: Path,
    *,
    fresh_only: bool = False,
) -> tuple[int, int] | None:
    parent_fd = _open_directory(destination.parent, create=False)
    try:
        try:
            current = os.readlink(destination.name, dir_fd=parent_fd)
        except FileNotFoundError:
            current = None
        except OSError as exc:
            if exc.errno == errno.EINVAL:
                raise PublishError(
                    f"source-install destination belongs to another installation: {destination}"
                ) from None
            raise
        if current is not None:
            if fresh_only:
                raise PublishError(f"fresh-install destination already exists and was preserved: {destination}")
            if current != target:
                raise PublishError(f"source-install destination points to another installation: {destination}")
            return None
        try:
            os.symlink(target, destination.name, dir_fd=parent_fd)
        except FileExistsError:
            raise PublishError(
                f"source-install destination appeared concurrently and was preserved: {destination}"
            ) from None
        owned_identity = _entry_identity(parent_fd, destination.name)
        if (
            owned_identity is None
            or os.readlink(destination.name, dir_fd=parent_fd) != target
            or _entry_identity(parent_fd, destination.name) != owned_identity
        ):
            raise PublishError(f"source-install symlink changed during publication: {destination}")
        os.fsync(parent_fd)
        return owned_identity
    finally:
        os.close(parent_fd)


def _encode_rollback_token(destination: Path, stage: Path, identity: tuple[int, int]) -> str:
    payload = json.dumps(
        {
            "destination": str(destination),
            "device": identity[0],
            "inode": identity[1],
            "stage": str(stage),
            "version": 1,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def _decode_rollback_token(value: str) -> tuple[Path, Path, tuple[int, int]]:
    try:
        padding = "=" * (-len(value) % 4)
        document = json.loads(base64.b64decode(value + padding, altchars=b"-_", validate=True))
        if set(document) != {"destination", "device", "inode", "stage", "version"}:
            raise ValueError
        destination = Path(document["destination"])
        stage = Path(document["stage"])
        identity = (int(document["device"]), int(document["inode"]))
        if (
            document["version"] != 1
            or not destination.is_absolute()
            or not stage.is_absolute()
            or stage.parent != destination.parent
            or not stage.name.startswith(f".{destination.name}.source-install-")
            or identity[0] <= 0
            or identity[1] <= 0
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PublishError("fresh-install rollback token is invalid") from exc
    return destination, stage, identity


def _unlink_exact_at(parent_fd: int, leaf: str, expected: tuple[int, int]) -> bool:
    if _entry_identity(parent_fd, leaf) is None:
        return True
    displaced = f".{leaf}.rollback-displaced-{uuid.uuid4().hex}"
    placeholder_fd = os.open(
        displaced,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=parent_fd,
    )
    placeholder_identity = _identity(placeholder_fd)
    os.close(placeholder_fd)
    try:
        _exchange(parent_fd, displaced, leaf)
    except Exception:
        if _entry_identity(parent_fd, displaced) == placeholder_identity:
            os.unlink(displaced, dir_fd=parent_fd)
        raise

    if _entry_identity(parent_fd, displaced) != expected:
        try:
            _exchange(parent_fd, displaced, leaf)
        finally:
            if _entry_identity(parent_fd, displaced) == placeholder_identity:
                os.unlink(displaced, dir_fd=parent_fd)
                os.fsync(parent_fd)
        return False

    cleanup = f".{leaf}.rollback-placeholder-{uuid.uuid4().hex}"
    try:
        _rename_no_replace(parent_fd, leaf, cleanup)
    except Exception:
        # The expected object is still private and the placeholder still
        # occupies the public name, so an exchange restores the original.
        try:
            _exchange(parent_fd, displaced, leaf)
        finally:
            if _entry_identity(parent_fd, displaced) == placeholder_identity:
                os.unlink(displaced, dir_fd=parent_fd)
        raise
    if _entry_identity(parent_fd, displaced) != expected or _entry_identity(parent_fd, cleanup) != placeholder_identity:
        raise PublishError(f"rollback identities changed and private state was preserved: {leaf}")
    os.unlink(displaced, dir_fd=parent_fd)
    os.unlink(cleanup, dir_fd=parent_fd)
    os.fsync(parent_fd)
    return True


def unlink_exact(destination: Path, expected: tuple[int, int]) -> bool:
    """Remove only the exact dev/inode while preserving any replacement."""

    parent_fd = _open_directory(destination.parent, create=False)
    try:
        return _unlink_exact_at(parent_fd, destination.name, expected)
    finally:
        os.close(parent_fd)


def publish_regular(
    source: Path,
    destination: Path,
    expected_current: str | None,
    *,
    expected_source: str | None = None,
    retain_token: bool = False,
) -> str | None:
    _validate_sha256(expected_current, label="current destination")
    _validate_sha256(expected_source, label="source")
    source_fd = _open_path_regular(source)
    try:
        source_stat = os.fstat(source_fd)
        parent_fd = _open_directory(destination.parent, create=False)
        try:
            stage = f".{destination.name}.source-install-{uuid.uuid4().hex}"
            stage_fd = os.open(
                stage,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o700,
                dir_fd=parent_fd,
            )
            stage_identity = _identity(stage_fd)
            safe_stage_identities = {stage_identity}
            retain_stage = False
            linked_fresh = False
            succeeded = False
            try:
                copied_digest = hashlib.sha256()
                try:
                    while True:
                        chunk = os.read(source_fd, 1024 * 1024)
                        if not chunk:
                            break
                        copied_digest.update(chunk)
                        view = memoryview(chunk)
                        while view:
                            written = os.write(stage_fd, view)
                            view = view[written:]
                    os.fchmod(stage_fd, source_stat.st_mode & 0o777)
                    os.fsync(stage_fd)
                finally:
                    os.close(stage_fd)
                    stage_fd = -1
                if expected_source is not None and copied_digest.hexdigest() != expected_source:
                    raise PublishError(f"source-install candidate changed before publication: {source}")

                current_identity: tuple[int, int] | None = None
                current_identity = _entry_identity(parent_fd, destination.name)
                if current_identity is not None:
                    safe_stage_identities.add(current_identity)
                if retain_token and current_identity is not None:
                    raise PublishError(f"fresh-install destination already exists and was preserved: {destination}")
                if current_identity is None:
                    try:
                        os.link(
                            stage,
                            destination.name,
                            src_dir_fd=parent_fd,
                            dst_dir_fd=parent_fd,
                            follow_symlinks=False,
                        )
                        linked_fresh = True
                    except FileExistsError:
                        raise PublishError(
                            f"source-install destination appeared concurrently and was preserved: {destination}"
                        ) from None
                    if _entry_identity(parent_fd, destination.name) != stage_identity:
                        raise PublishError(f"source-install publication identity mismatch: {destination}")
                else:
                    if expected_current is None:
                        raise PublishError(f"source-install destination belongs to another installation: {destination}")
                    current_fd = _open_regular(parent_fd, destination.name)
                    try:
                        expected_identity = _identity(current_fd)
                        if _sha256_fd(current_fd) != expected_current:
                            raise PublishError(f"source-install destination changed before publication: {destination}")
                    finally:
                        os.close(current_fd)
                    if _entry_identity(parent_fd, stage) != stage_identity:
                        raise PublishError(f"source-install staging changed before publication: {destination}")
                    _exchange(parent_fd, stage, destination.name)
                    displaced_fd = _open_regular(parent_fd, stage)
                    try:
                        displaced_is_expected = (
                            _identity(displaced_fd) == expected_identity
                            and _sha256_fd(displaced_fd) == expected_current
                        )
                    finally:
                        os.close(displaced_fd)
                    if not displaced_is_expected or _entry_identity(parent_fd, destination.name) != stage_identity:
                        try:
                            _exchange(parent_fd, stage, destination.name)
                        except PublishError:
                            pass
                        raise PublishError(
                            f"source-install destination changed during publication and was preserved: {destination}"
                        )
                os.fsync(parent_fd)
                token = None
                if retain_token:
                    retain_stage = True
                    token = _encode_rollback_token(
                        destination,
                        destination.parent / stage,
                        stage_identity,
                    )
                succeeded = True
                return token
            finally:
                if stage_fd >= 0:
                    os.close(stage_fd)
                if not succeeded and linked_fresh:
                    try:
                        unlink_exact(destination, stage_identity)
                    except (OSError, PublishError):
                        pass
                if not retain_stage and _entry_identity(parent_fd, stage) in safe_stage_identities:
                    os.unlink(stage, dir_fd=parent_fd)
                    os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        os.close(source_fd)


def commit_rollback_token(value: str) -> None:
    _destination, stage, identity = _decode_rollback_token(value)
    if not unlink_exact(stage, identity):
        raise PublishError("fresh-install rollback token changed and was preserved")


def rollback_token(value: str) -> None:
    destination, stage, identity = _decode_rollback_token(value)
    if not unlink_exact(destination, identity):
        raise PublishError(f"fresh-install destination changed and was preserved: {destination}")
    if not unlink_exact(stage, identity):
        raise PublishError("fresh-install rollback token changed and was preserved")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    directory = subparsers.add_parser("ensure-directory")
    directory.add_argument("path", type=Path)
    real_directory = subparsers.add_parser("ensure-real-directory")
    real_directory.add_argument("path", type=Path)
    fresh_dir = subparsers.add_parser("fresh-directory")
    fresh_dir.add_argument("path", type=Path)
    remove_dir = subparsers.add_parser("rmdir-exact")
    remove_dir.add_argument("path", type=Path)
    remove_dir.add_argument("device", type=int)
    remove_dir.add_argument("inode", type=int)
    remove_tree = subparsers.add_parser("remove-tree-exact")
    remove_tree.add_argument("path", type=Path)
    remove_tree.add_argument("device", type=int)
    remove_tree.add_argument("inode", type=int)
    symlink = subparsers.add_parser("symlink")
    symlink.add_argument("target")
    symlink.add_argument("destination", type=Path)
    fresh_symlink = subparsers.add_parser("fresh-symlink")
    fresh_symlink.add_argument("target")
    fresh_symlink.add_argument("destination", type=Path)
    regular = subparsers.add_parser("regular")
    regular.add_argument("source", type=Path)
    regular.add_argument("destination", type=Path)
    regular.add_argument("--expected-current-sha256")
    regular.add_argument("--expected-source-sha256")
    fresh_regular = subparsers.add_parser("fresh-regular")
    fresh_regular.add_argument("source", type=Path)
    fresh_regular.add_argument("destination", type=Path)
    fresh_regular.add_argument("--retain-token", action="store_true")
    unlink = subparsers.add_parser("unlink-exact")
    unlink.add_argument("path", type=Path)
    unlink.add_argument("device", type=int)
    unlink.add_argument("inode", type=int)
    commit = subparsers.add_parser("commit-token")
    commit.add_argument("token")
    rollback = subparsers.add_parser("rollback-token")
    rollback.add_argument("token")
    digest_regular = subparsers.add_parser("sha256-regular")
    digest_regular.add_argument("path", type=Path)
    digest_regular.add_argument("--require-executable", action="store_true")
    compare_regular = subparsers.add_parser("compare-regular")
    compare_regular.add_argument("first", type=Path)
    compare_regular.add_argument("second", type=Path)
    compare_regular.add_argument("--require-executable", action="store_true")
    args = parser.parse_args()
    try:
        if args.command in {"ensure-directory", "ensure-real-directory"}:
            ensure_directory(args.path)
        elif args.command == "fresh-directory":
            identity = fresh_directory(args.path)
            print(f"{identity[0]}:{identity[1]}")
        elif args.command == "rmdir-exact":
            if args.device <= 0 or args.inode <= 0:
                raise PublishError("expected directory identity is invalid")
            if not rmdir_exact(args.path, (args.device, args.inode)):
                raise PublishError(f"directory changed or became nonempty and was preserved: {args.path}")
        elif args.command == "remove-tree-exact":
            if args.device <= 0 or args.inode <= 0:
                raise PublishError("expected tree identity is invalid")
            if not remove_tree_exact(args.path, (args.device, args.inode)):
                raise PublishError(f"directory tree changed and was preserved: {args.path}")
        elif args.command == "symlink":
            publish_symlink(args.target, args.destination)
        elif args.command == "fresh-symlink":
            identity = publish_symlink(args.target, args.destination, fresh_only=True)
            if identity is None:
                raise PublishError("fresh-install symlink identity is unavailable")
            print(f"{identity[0]}:{identity[1]}")
        elif args.command == "regular":
            publish_regular(
                args.source,
                args.destination,
                args.expected_current_sha256,
                expected_source=args.expected_source_sha256,
            )
        elif args.command == "fresh-regular":
            token = publish_regular(
                args.source,
                args.destination,
                None,
                retain_token=args.retain_token,
            )
            if token is not None:
                print(token)
        elif args.command == "unlink-exact":
            if args.device <= 0 or args.inode <= 0:
                raise PublishError("expected path identity is invalid")
            if not unlink_exact(args.path, (args.device, args.inode)):
                raise PublishError(f"destination changed and was preserved: {args.path}")
        elif args.command == "commit-token":
            commit_rollback_token(args.token)
        elif args.command == "rollback-token":
            rollback_token(args.token)
        elif args.command == "sha256-regular":
            print(
                regular_sha256(
                    args.path,
                    require_executable=args.require_executable,
                )
            )
        else:
            print(
                matching_regular_sha256(
                    args.first,
                    args.second,
                    require_executable=args.require_executable,
                )
            )
    except (OSError, PublishError) as exc:
        print(f"source-install publication refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
