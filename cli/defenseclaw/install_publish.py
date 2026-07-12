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
import struct
import sys
import uuid
from pathlib import Path


class PublishError(RuntimeError):
    pass


BasicIdentity = tuple[int, int]
StrongIdentity = tuple[int, int, int, int]
ObjectIdentity = tuple[int, ...]
MAX_CUSTODY_ENTRIES = 128
CUSTODY_MARKER = b"DefenseClaw deterministic retirement custody v1\n"


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


class _DarwinAttrList(ctypes.Structure):
    _fields_ = [
        ("bitmapcount", ctypes.c_ushort),
        ("reserved", ctypes.c_ushort),
        ("commonattr", ctypes.c_uint),
        ("volattr", ctypes.c_uint),
        ("dirattr", ctypes.c_uint),
        ("fileattr", ctypes.c_uint),
        ("forkattr", ctypes.c_uint),
    ]


def _macos_birth(fd: int) -> tuple[int, int]:
    """Return Darwin's exact kernel creation timespec for one open object."""

    attributes = _DarwinAttrList(5, 0, 0x00000200, 0, 0, 0, 0)  # ATTR_CMN_CRTIME
    buffer = ctypes.create_string_buffer(32)
    library = ctypes.CDLL(None, use_errno=True)
    function = library.fgetattrlist
    function.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(_DarwinAttrList),
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if function(fd, ctypes.byref(attributes), buffer, len(buffer), 0) != 0:
        code = ctypes.get_errno()
        raise PublishError(f"could not read durable Darwin object identity: errno {code}")
    returned_length = struct.unpack_from("=I", buffer.raw, 0)[0]
    seconds, nanoseconds = struct.unpack_from("=qq", buffer.raw, 4)
    if returned_length < 20 or seconds <= 0 or not 0 <= nanoseconds < 1_000_000_000:
        raise PublishError("filesystem does not expose a durable object birth identity")
    return seconds, nanoseconds


def _linux_statx(directory_fd: int, path: bytes, flags: int) -> tuple[StrongIdentity, int]:
    """Read identity and mount ID in one statx(2) snapshot."""

    # Linux's statx structure is a fixed 256-byte ABI.  These offsets are the
    # stable fields from struct statx: mask, inode, birth timestamp, and device.
    # Reading all identity fields from the same syscall avoids an lstat/statx
    # split where an immediately reused inode could straddle the two calls.
    statx_buffer = ctypes.create_string_buffer(256)
    library = ctypes.CDLL(None, use_errno=True)
    function = getattr(library, "statx", None)
    if function is None:
        raise PublishError("filesystem object identity requires statx support")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.c_void_p,
    ]
    function.restype = ctypes.c_int
    statx_ino = 0x00000100
    statx_btime = 0x00000800
    statx_mnt_id = 0x00001000
    statx_basic_stats = 0x000007FF
    requested = statx_basic_stats | statx_btime | statx_mnt_id
    if function(directory_fd, path, flags, requested, statx_buffer) != 0:
        code = ctypes.get_errno()
        if code == errno.ENOENT:
            raise FileNotFoundError(code, os.strerror(code))
        raise PublishError(f"could not read durable filesystem object identity: errno {code}")

    raw = statx_buffer.raw
    returned_mask = struct.unpack_from("=I", raw, 0)[0]
    inode = struct.unpack_from("=Q", raw, 32)[0]
    birth_seconds, birth_nanoseconds = struct.unpack_from("=qI", raw, 80)
    device_major, device_minor = struct.unpack_from("=II", raw, 136)
    mount_id = struct.unpack_from("=Q", raw, 144)[0]
    if (
        returned_mask & (statx_ino | statx_btime | statx_mnt_id) != (statx_ino | statx_btime | statx_mnt_id)
        or inode <= 0
        or birth_seconds <= 0
        or birth_nanoseconds >= 1_000_000_000
        or mount_id <= 0
    ):
        raise PublishError("filesystem does not expose a durable object birth identity")
    return (
        (
            os.makedev(device_major, device_minor),
            inode,
            birth_seconds,
            birth_nanoseconds,
        ),
        mount_id,
    )


def _strong_identity(fd: int) -> StrongIdentity:
    if sys.platform.startswith("linux"):
        # AT_EMPTY_PATH asks statx to identify the already-open object, not a
        # pathname that could be exchanged between lookup and measurement.
        return _linux_statx(fd, b"", 0x1000)[0]
    if sys.platform == "darwin":
        metadata = os.fstat(fd)
        return metadata.st_dev, metadata.st_ino, *_macos_birth(fd)
    raise PublishError("durable filesystem object identity is unsupported on this platform")


def _entry_strong_identity(parent_fd: int, leaf: str) -> StrongIdentity | None:
    if sys.platform.startswith("linux"):
        try:
            # AT_SYMLINK_NOFOLLOW makes symlinks themselves claimable.
            return _linux_statx(parent_fd, os.fsencode(leaf), 0x100)[0]
        except FileNotFoundError:
            return None
    if sys.platform == "darwin":
        try:
            metadata = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        flags = os.O_RDONLY | os.O_CLOEXEC
        if stat.S_ISDIR(metadata.st_mode):
            flags |= os.O_DIRECTORY | os.O_NOFOLLOW
        elif stat.S_ISLNK(metadata.st_mode):
            # Apple system Python 3.9 omits the binding even though the flag is
            # part of the stable Darwin ABI.  Use the SDK value so symlinks get
            # the same exact fgetattrlist timespec as every other object.
            flags |= getattr(os, "O_SYMLINK", 0x00200000)
        elif stat.S_ISFIFO(metadata.st_mode):
            flags |= os.O_NONBLOCK | os.O_NOFOLLOW
        elif not stat.S_ISREG(metadata.st_mode):
            raise PublishError("managed entry type cannot be durably identified")
        else:
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(leaf, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            return None
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise PublishError("managed entry changed while opening its identity")
            return _strong_identity(descriptor)
        finally:
            os.close(descriptor)
    raise PublishError("durable filesystem object identity is unsupported on this platform")


def _mount_identity(fd: int) -> tuple[int, int]:
    if sys.platform.startswith("linux"):
        identity, mount_id = _linux_statx(fd, b"", 0x1000)
        return identity[0], mount_id
    if sys.platform == "darwin":
        metadata = os.fstat(fd)
        filesystem = os.fstatvfs(fd)
        return metadata.st_dev, int(filesystem.f_fsid)
    raise PublishError("filesystem mount identity is unsupported on this platform")


def _entry_claim_matches(parent_fd: int, leaf: str, expected: ObjectIdentity) -> bool:
    """Match a durable claim, or a caller-retained inode claim.

    Two-field identities are accepted only for in-process callers that retain
    another hardlink to the object for the whole operation.  That retained
    claim makes inode recycling impossible.  All serialized/public identities
    use the four-field birth identity.
    """

    if len(expected) == 2:
        return _entry_identity(parent_fd, leaf) == expected
    return _entry_strong_identity(parent_fd, leaf) == expected


def path_identity(path: Path) -> StrongIdentity:
    """Return a durable, no-follow identity suitable for later rollback."""

    if not path.is_absolute() or not path.name or path.name in {".", ".."}:
        raise PublishError(f"managed path is unsafe: {path}")
    parent_fd = _open_directory(path.parent, create=False)
    try:
        identity = _entry_strong_identity(parent_fd, path.name)
        if identity is None:
            raise PublishError(f"managed path is missing: {path}")
        return identity
    finally:
        os.close(parent_fd)


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
                created_identity: StrongIdentity | None = None
                staged_identity: StrongIdentity | None = None
                try:
                    os.mkdir(staged, mode=0o700, dir_fd=descriptor)
                    mkdir_succeeded = True
                    created_identity = _entry_strong_identity(descriptor, staged)
                    if created_identity is None:
                        raise PublishError("attempt-created directory disappeared before binding")
                    staged_descriptor = os.open(
                        staged,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=descriptor,
                    )
                    staged_identity = _strong_identity(staged_descriptor)
                    if staged_identity != created_identity:
                        raise PublishError("attempt-created directory changed before binding")
                    os.fsync(staged_descriptor)
                    _rename_no_replace(descriptor, staged, component)
                    os.fsync(descriptor)
                except (OSError, PublishError):
                    if staged_descriptor >= 0:
                        os.close(staged_descriptor)
                    if mkdir_succeeded and created_identity is not None:
                        try:
                            _rmdir_exact_at(descriptor, staged, created_identity)
                        except (OSError, PublishError):
                            pass
                    raise PublishError(f"managed directory appeared concurrently and was preserved: {path}") from None
                if _entry_strong_identity(descriptor, component) != staged_identity:
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
    try:
        _rename_no_replace_between(parent_fd, source, parent_fd, destination)
    except OSError as exc:
        raise PublishError(f"atomic no-replace rename failed: errno {exc.errno}") from exc


def _rename_no_replace_between(
    source_parent_fd: int,
    source: str,
    destination_parent_fd: int,
    destination: str,
) -> None:
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
    if (
        function(
            source_parent_fd,
            os.fsencode(source),
            destination_parent_fd,
            os.fsencode(destination),
            flag,
        )
        != 0
    ):
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError(code, os.strerror(code), destination)
        if code == errno.ENOENT:
            raise FileNotFoundError(code, os.strerror(code), source)
        raise PublishError(f"atomic no-replace rename failed: errno {code}")


def ensure_directory(path: Path) -> None:
    descriptor = _open_directory(path, create=True)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fresh_directory(path: Path) -> StrongIdentity:
    """Atomically reserve a previously absent real directory."""

    if not path.is_absolute() or not path.name or path.name in {".", ".."}:
        raise PublishError(f"fresh-install directory path is unsafe: {path}")
    parent_fd = _open_directory(path.parent, create=False)
    staged = f".{path.name}.install-directory-{uuid.uuid4().hex}"
    staged_fd = -1
    staged_claim: StrongIdentity | None = None
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
        staged_claim = _strong_identity(staged_fd)
        os.fsync(staged_fd)
        try:
            _rename_no_replace(parent_fd, staged, path.name)
        except PublishError as exc:
            raise PublishError(f"fresh-install directory appeared concurrently and was preserved: {path}") from exc
        activated = True
        if _entry_strong_identity(parent_fd, path.name) != staged_claim:
            raise PublishError(f"fresh-install directory birth identity mismatch: {path}")
        os.fsync(parent_fd)
        return staged_claim
    finally:
        if staged_fd >= 0:
            os.close(staged_fd)
        if not activated and staged_claim is not None:
            try:
                _rmdir_exact_at(parent_fd, staged, staged_claim)
            except (OSError, PublishError):
                pass
        os.close(parent_fd)


def _retirement_document(
    canonical: str,
    expected: ObjectIdentity,
    kind: str,
) -> bytes:
    return (
        json.dumps(
            {
                "canonical": canonical,
                "identity": list(expected),
                "kind": kind,
                "schema_version": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _retirement_names(canonical: str, expected: ObjectIdentity, kind: str) -> tuple[str, str]:
    digest = hashlib.sha256(_retirement_document(canonical, expected, kind)).hexdigest()
    return f"intent-{digest}.json", f"retired-{digest}"


def _read_regular_at(parent_fd: int, leaf: str, *, missing_ok: bool) -> bytes | None:
    try:
        descriptor = os.open(
            leaf,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        if missing_ok:
            return None
        raise
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 64 * 1024:
            raise PublishError("retirement intent is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                raise PublishError("retirement intent changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _ensure_retirement_intent(
    custody_fd: int,
    intent: str,
    document: bytes,
    *,
    allow_create: bool,
) -> bool:
    existing = _read_regular_at(custody_fd, intent, missing_ok=True)
    if existing is not None:
        if existing != document:
            raise PublishError("deterministic retirement intent collided and was preserved")
        return False
    if not allow_create:
        return False
    with os.scandir(custody_fd) as entries:
        # A completed claim owns one durable intent and one retired name.
        # Reserve both slots before creating either so the advertised bound is
        # never exceeded by the normal second (rename) phase.
        if sum(1 for _entry in entries) + 2 > MAX_CUSTODY_ENTRIES:
            raise PublishError("retirement custody reached its bounded entry limit")
    try:
        descriptor = os.open(
            intent,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=custody_fd,
        )
    except FileExistsError:
        existing = _read_regular_at(custody_fd, intent, missing_ok=False)
        if existing != document:
            raise PublishError("deterministic retirement intent collided and was preserved")
        return False
    try:
        view = memoryview(document)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(custody_fd)
    return True


def _bind_custody_fd(descriptor: int, *, create: bool, label: str) -> None:
    metadata = os.fstat(descriptor)
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise PublishError(f"retirement custody is not private and caller-owned: {label}")
    marker = ".defenseclaw-custody-v1"
    existing = _read_regular_at(descriptor, marker, missing_ok=True)
    if existing is None:
        if not create:
            raise PublishError("retirement custody has no durable binding marker")
        with os.scandir(descriptor) as entries:
            if next(entries, None) is not None:
                raise PublishError("pre-existing retirement custody was not empty and was preserved")
        marker_fd = os.open(
            marker,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=descriptor,
        )
        try:
            remaining = memoryview(CUSTODY_MARKER)
            while remaining:
                written = os.write(marker_fd, remaining)
                if written <= 0:
                    raise PublishError("retirement custody marker write did not progress")
                remaining = remaining[written:]
            os.fsync(marker_fd)
        finally:
            os.close(marker_fd)
        os.fsync(descriptor)
    elif existing != CUSTODY_MARKER:
        raise PublishError("retirement custody binding marker is invalid")


def _open_custody_root(path: Path, *, create: bool) -> int:
    descriptor = _open_directory(path, create=create)
    try:
        _bind_custody_fd(descriptor, create=create, label=str(path))
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _default_custody_root(path: Path) -> Path:
    return path.parent / ".defenseclaw-install-custody"


def prepare_custody(custody_root: Path, managed_parent: Path) -> None:
    """Bind private custody to the exact mount that will hold managed names."""

    managed_fd = _open_directory(managed_parent, create=False)
    try:
        custody_fd = _open_custody_root(custody_root, create=True)
        try:
            if _mount_identity(custody_fd) != _mount_identity(managed_fd):
                raise PublishError("retirement custody must share the managed object's mount before publication")
        finally:
            os.close(custody_fd)
    finally:
        os.close(managed_fd)


def _directory_is_empty_at(parent_fd: int, leaf: str, expected: ObjectIdentity) -> bool:
    descriptor = os.open(
        leaf,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent_fd,
    )
    try:
        if not _entry_claim_matches(parent_fd, leaf, expected):
            return False
        with os.scandir(descriptor) as entries:
            return next(entries, None) is None
    finally:
        os.close(descriptor)


def _kind_matches(metadata: os.stat_result, kind: str) -> bool:
    if kind in {"directory", "tree"}:
        return stat.S_ISDIR(metadata.st_mode)
    if kind == "entry":
        return not stat.S_ISDIR(metadata.st_mode)
    raise PublishError("retirement kind is invalid")


def _retire_exact_at(
    parent_fd: int,
    leaf: str,
    expected: ObjectIdentity,
    custody_fd: int,
    canonical: str,
    kind: str,
    *,
    validator=None,
    recover_only: bool = False,
) -> bool:
    if os.fstat(parent_fd).st_dev != os.fstat(custody_fd).st_dev:
        raise PublishError("retirement custody must be on the managed object's filesystem")
    intent, retired = _retirement_names(canonical, expected, kind)
    document = _retirement_document(canonical, expected, kind)

    for _attempt in range(8):
        intent_exists = _read_regular_at(custody_fd, intent, missing_ok=True) is not None
        retired_info = _entry_stat(custody_fd, retired)
        current = _entry_stat(parent_fd, leaf)

        if not intent_exists:
            if recover_only:
                # Recovery is successful only when the deterministic retired
                # name proves the claimed object reached durable custody.  A
                # missing journal entry and missing canonical name prove
                # nothing about where that object went.
                return False
            if retired_info is not None:
                return False
            _ensure_retirement_intent(custody_fd, intent, document, allow_create=True)
            continue
        _ensure_retirement_intent(custody_fd, intent, document, allow_create=False)

        if retired_info is not None:
            retired_matches = _kind_matches(retired_info, kind) and _entry_claim_matches(custody_fd, retired, expected)
            if not retired_matches:
                # A substitution moved after a durable intent is restored only
                # when its canonical name remains absent.  A concurrently
                # occupied canonical name and the private substitution are both
                # preserved for explicit recovery.
                if current is None:
                    try:
                        _rename_no_replace_between(custody_fd, retired, parent_fd, leaf)
                    except (FileExistsError, FileNotFoundError):
                        continue
                    os.fsync(custody_fd)
                    os.fsync(parent_fd)
                return False

            if validator is not None and not validator(custody_fd, retired, expected):
                if current is None:
                    try:
                        _rename_no_replace_between(custody_fd, retired, parent_fd, leaf)
                    except (FileExistsError, FileNotFoundError):
                        continue
                    os.fsync(custody_fd)
                    os.fsync(parent_fd)
                return False

            if current is None:
                os.fsync(custody_fd)
                os.fsync(parent_fd)
                return True
            if _entry_claim_matches(parent_fd, leaf, expected):
                return False
            # The exact object is durably retired and a foreign canonical
            # replacement is preserved in place.
            return True

        if current is None:
            # A durable intent records only the plan.  The claimed object may
            # have been moved elsewhere between snapshots or immediately
            # before rename.  Without its exact deterministic retired entry,
            # completion is unproven and must fail closed.
            return False
        if not _kind_matches(current, kind) or not _entry_claim_matches(parent_fd, leaf, expected):
            return False
        if validator is not None and not validator(parent_fd, leaf, expected):
            return False
        if recover_only or intent_exists:
            try:
                _rename_no_replace_between(parent_fd, leaf, custody_fd, retired)
            except (FileExistsError, FileNotFoundError):
                continue
            os.fsync(parent_fd)
            os.fsync(custody_fd)
            continue
    raise PublishError("deterministic retirement did not reach a stable state")


def _rmdir_exact_at(
    parent_fd: int,
    leaf: str,
    expected: ObjectIdentity,
    *,
    custody_fd: int | None = None,
    canonical: str | None = None,
) -> bool:
    owned_custody = -1
    if custody_fd is None:
        custody_name = ".defenseclaw-install-custody"
        try:
            os.mkdir(custody_name, mode=0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
        owned_custody = os.open(
            custody_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        try:
            _bind_custody_fd(owned_custody, create=True, label=custody_name)
        except Exception:
            os.close(owned_custody)
            owned_custody = -1
            raise
        custody_fd = owned_custody
    try:
        key = canonical or leaf
        return _retire_exact_at(
            parent_fd,
            leaf,
            expected,
            custody_fd,
            key,
            "directory",
            validator=_directory_is_empty_at,
        )
    finally:
        if owned_custody >= 0:
            os.close(owned_custody)


def rmdir_exact(
    path: Path,
    expected: ObjectIdentity,
    *,
    custody_root: Path | None = None,
) -> bool:
    """Retire only an exact empty directory, preserving races and contents."""

    if not path.is_absolute() or not path.name or path.name in {".", ".."}:
        raise PublishError(f"fresh-install directory path is unsafe: {path}")
    parent_fd = _open_directory(path.parent, create=False)
    custody_fd = _open_custody_root(custody_root or _default_custody_root(path), create=True)
    try:
        return _rmdir_exact_at(
            parent_fd,
            path.name,
            expected,
            custody_fd=custody_fd,
            canonical=str(path),
        )
    finally:
        os.close(custody_fd)
        os.close(parent_fd)


MAX_REMOVE_TREE_NODES = 500_000
MAX_REMOVE_TREE_BYTES = 2 * 1024 * 1024 * 1024
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


def _validate_tree_mounts_fd(
    directory_fd: int,
    *,
    root_device: int,
    root_mount: tuple[int, int],
    depth: int,
    budget: dict[str, int],
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
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if stat.S_ISDIR(metadata.st_mode):
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            elif stat.S_ISREG(metadata.st_mode) or stat.S_ISFIFO(metadata.st_mode):
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            else:
                raise PublishError("attempt-owned tree contains an unsafe special entry")
            child_fd = os.open(name, flags, dir_fd=directory_fd)
            try:
                if _identity(child_fd) != (metadata.st_dev, metadata.st_ino):
                    raise PublishError("attempt-owned tree entry changed while opening")
                if _mount_identity(child_fd) != root_mount:
                    raise PublishError("attempt-owned tree crosses a mount boundary")
                if stat.S_ISDIR(metadata.st_mode):
                    _validate_tree_mounts_fd(
                        child_fd,
                        root_device=root_device,
                        root_mount=root_mount,
                        depth=depth + 1,
                        budget=budget,
                    )
            finally:
                os.close(child_fd)


def _tree_has_safe_mounts_at(
    parent_fd: int,
    leaf: str,
    expected: ObjectIdentity,
) -> bool:
    descriptor = os.open(
        leaf,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent_fd,
    )
    try:
        if not _entry_claim_matches(parent_fd, leaf, expected):
            return False
        root_mount = _mount_identity(descriptor)
        if root_mount != _mount_identity(parent_fd):
            return False
        budget = {"nodes": 1, "bytes": 0}
        _validate_tree_mounts_fd(
            descriptor,
            root_device=expected[0],
            root_mount=root_mount,
            depth=1,
            budget=budget,
        )
        return True
    finally:
        os.close(descriptor)


def remove_tree_exact(
    path: Path,
    expected: ObjectIdentity,
    *,
    custody_root: Path | None = None,
) -> bool:
    """Durably retire an exact tree without recursively deleting its contents."""

    if not path.is_absolute() or not path.name or path.name in {".", ".."}:
        raise PublishError(f"fresh-install directory path is unsafe: {path}")
    parent_fd = _open_directory(path.parent, create=False)
    custody_fd = _open_custody_root(custody_root or _default_custody_root(path), create=True)
    try:
        return _retire_exact_at(
            parent_fd,
            path.name,
            expected,
            custody_fd,
            str(path),
            "tree",
            validator=_tree_has_safe_mounts_at,
        )
    finally:
        os.close(custody_fd)
        os.close(parent_fd)


def publish_symlink(
    target: str,
    destination: Path,
    *,
    fresh_only: bool = False,
    custody_root: Path | None = None,
) -> StrongIdentity | None:
    parent_fd = _open_directory(destination.parent, create=False)
    stage_digest = hashlib.sha256((str(destination) + "\0" + target).encode()).hexdigest()[:32]
    stage = f".{destination.name}.source-symlink-{stage_digest}"
    stage_claim: StrongIdentity | None = None
    activated = False
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
            os.symlink(target, stage, dir_fd=parent_fd)
        except FileExistsError:
            raise PublishError(
                f"source-install symlink staging is unresolved and was preserved: {destination}"
            ) from None
        stage_claim = _entry_strong_identity(parent_fd, stage)
        if stage_claim is None or os.readlink(stage, dir_fd=parent_fd) != target:
            raise PublishError(f"source-install symlink staging changed: {destination}")
        try:
            _rename_no_replace_between(parent_fd, stage, parent_fd, destination.name)
        except FileExistsError:
            raise PublishError(
                f"source-install destination appeared concurrently and was preserved: {destination}"
            ) from None
        activated = True
        if _entry_strong_identity(parent_fd, destination.name) != stage_claim:
            raise PublishError(f"source-install symlink activation identity changed: {destination}")
        os.fsync(parent_fd)
        return stage_claim
    finally:
        if not activated and stage_claim is not None:
            try:
                unlink_exact(
                    destination.parent / stage,
                    stage_claim,
                    custody_root=custody_root or _default_custody_root(destination),
                )
            except (OSError, PublishError):
                pass
        os.close(parent_fd)


def _encode_rollback_token(
    destination: Path,
    stage: Path,
    identity: StrongIdentity,
    custody_root: Path,
) -> str:
    payload = json.dumps(
        {
            "birth_nanoseconds": identity[3],
            "birth_seconds": identity[2],
            "custody_root": str(custody_root),
            "destination": str(destination),
            "device": identity[0],
            "inode": identity[1],
            "stage": str(stage),
            "version": 3,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def _decode_rollback_token(value: str) -> tuple[Path, Path, StrongIdentity, Path]:
    try:
        padding = "=" * (-len(value) % 4)
        document = json.loads(base64.b64decode(value + padding, altchars=b"-_", validate=True))
        if set(document) != {
            "birth_nanoseconds",
            "birth_seconds",
            "custody_root",
            "destination",
            "device",
            "inode",
            "stage",
            "version",
        }:
            raise ValueError
        destination = Path(document["destination"])
        stage = Path(document["stage"])
        custody_root = Path(document["custody_root"])
        identity = (
            int(document["device"]),
            int(document["inode"]),
            int(document["birth_seconds"]),
            int(document["birth_nanoseconds"]),
        )
        if (
            document["version"] != 3
            or not destination.is_absolute()
            or not stage.is_absolute()
            or stage.parent != destination.parent
            or not custody_root.is_absolute()
            or not stage.name.startswith(f".{destination.name}.source-install-")
            or identity[0] <= 0
            or identity[1] <= 0
            or identity[2] <= 0
            or not 0 <= identity[3] < 1_000_000_000
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PublishError("fresh-install rollback token is invalid") from exc
    return destination, stage, identity, custody_root


def _unlink_exact_at(
    parent_fd: int,
    leaf: str,
    expected: ObjectIdentity,
    *,
    custody_fd: int | None = None,
    canonical: str | None = None,
) -> bool:
    owned_custody = -1
    if custody_fd is None:
        custody_name = ".defenseclaw-install-custody"
        try:
            os.mkdir(custody_name, mode=0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
        owned_custody = os.open(
            custody_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        try:
            _bind_custody_fd(owned_custody, create=True, label=custody_name)
        except Exception:
            os.close(owned_custody)
            owned_custody = -1
            raise
        custody_fd = owned_custody
    try:
        return _retire_exact_at(
            parent_fd,
            leaf,
            expected,
            custody_fd,
            canonical or leaf,
            "entry",
        )
    finally:
        if owned_custody >= 0:
            os.close(owned_custody)


def unlink_exact(
    destination: Path,
    expected: ObjectIdentity,
    *,
    custody_root: Path | None = None,
) -> bool:
    """Durably retire only the exact claimed object and preserve replacements."""

    parent_fd = _open_directory(destination.parent, create=False)
    custody_fd = _open_custody_root(custody_root or _default_custody_root(destination), create=True)
    try:
        return _unlink_exact_at(
            parent_fd,
            destination.name,
            expected,
            custody_fd=custody_fd,
            canonical=str(destination),
        )
    finally:
        os.close(custody_fd)
        os.close(parent_fd)


def publish_regular(
    source: Path,
    destination: Path,
    expected_current: str | None,
    *,
    expected_source: str | None = None,
    retain_token: bool = False,
    custody_root: Path | None = None,
) -> str | None:
    _validate_sha256(expected_current, label="current destination")
    _validate_sha256(expected_source, label="source")
    source_fd = _open_path_regular(source)
    retirement_root = custody_root or _default_custody_root(destination)
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
            stage_claim = _strong_identity(stage_fd)
            safe_stage_identities = {stage_claim}
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

                current_identity = _entry_strong_identity(parent_fd, destination.name)
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
                    if _entry_strong_identity(parent_fd, destination.name) != stage_claim:
                        raise PublishError(f"source-install publication identity mismatch: {destination}")
                else:
                    if expected_current is None:
                        raise PublishError(f"source-install destination belongs to another installation: {destination}")
                    current_fd = _open_regular(parent_fd, destination.name)
                    try:
                        expected_identity = _strong_identity(current_fd)
                        if _sha256_fd(current_fd) != expected_current:
                            raise PublishError(f"source-install destination changed before publication: {destination}")
                    finally:
                        os.close(current_fd)
                    if _entry_strong_identity(parent_fd, stage) != stage_claim:
                        raise PublishError(f"source-install staging changed before publication: {destination}")
                    _exchange(parent_fd, stage, destination.name)
                    displaced_fd = _open_regular(parent_fd, stage)
                    try:
                        displaced_is_expected = (
                            _strong_identity(displaced_fd) == expected_identity
                            and _sha256_fd(displaced_fd) == expected_current
                        )
                    finally:
                        os.close(displaced_fd)
                    if not displaced_is_expected or _entry_strong_identity(parent_fd, destination.name) != stage_claim:
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
                        stage_claim,
                        retirement_root,
                    )
                succeeded = True
                return token
            finally:
                if stage_fd >= 0:
                    os.close(stage_fd)
                if not succeeded and linked_fresh:
                    try:
                        unlink_exact(destination, stage_claim, custody_root=retirement_root)
                    except (OSError, PublishError):
                        pass
                if not retain_stage:
                    current_stage = _entry_strong_identity(parent_fd, stage)
                    if current_stage is not None:
                        if current_stage not in safe_stage_identities:
                            raise PublishError(f"source-install staging changed and was preserved: {destination}")
                        if not unlink_exact(
                            destination.parent / stage,
                            current_stage,
                            custody_root=retirement_root,
                        ):
                            raise PublishError(f"source-install staging changed and was preserved: {destination}")
        finally:
            os.close(parent_fd)
    finally:
        os.close(source_fd)


def commit_rollback_token(value: str) -> None:
    _destination, stage, identity, custody_root = _decode_rollback_token(value)
    if not unlink_exact(stage, identity, custody_root=custody_root):
        raise PublishError("fresh-install rollback token changed and was preserved")


def rollback_token(value: str) -> None:
    destination, stage, identity, custody_root = _decode_rollback_token(value)
    if not unlink_exact(destination, identity, custody_root=custody_root):
        raise PublishError(f"fresh-install destination changed and was preserved: {destination}")
    if not unlink_exact(stage, identity, custody_root=custody_root):
        raise PublishError("fresh-install rollback token changed and was preserved")


def recover_custody(custody_root: Path) -> None:
    """Converge durable retirement intents from an interrupted installer."""

    if not custody_root.is_absolute():
        raise PublishError("retirement custody path must be absolute")
    try:
        custody_fd = _open_custody_root(custody_root, create=False)
    except PublishError as exc:
        if "managed directory is missing" in str(exc):
            return
        raise
    try:
        documents: list[tuple[Path, ObjectIdentity, str, str]] = []
        with os.scandir(custody_fd) as entries:
            names = sorted(entry.name for entry in entries if entry.name.startswith("intent-"))
        for name in names:
            raw = _read_regular_at(custody_fd, name, missing_ok=False)
            assert raw is not None
            try:
                document = json.loads(raw)
                if set(document) != {"canonical", "identity", "kind", "schema_version"}:
                    raise ValueError
                canonical = Path(document["canonical"])
                identity = tuple(document["identity"])
                kind = document["kind"]
                if (
                    document["schema_version"] != 1
                    or not canonical.is_absolute()
                    or len(identity) not in {2, 4}
                    or any(not isinstance(value, int) or value <= 0 for value in identity[:3])
                    or (len(identity) == 4 and not 0 <= identity[3] < 1_000_000_000)
                    or kind not in {"entry", "directory", "tree"}
                    or _retirement_names(str(canonical), identity, kind)[0] != name
                ):
                    raise ValueError
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise PublishError("retirement custody contains an invalid intent") from exc
            documents.append((canonical, identity, kind, name))

        for canonical, identity, kind, _name in sorted(
            documents,
            key=lambda item: len(item[0].parts),
            reverse=True,
        ):
            try:
                parent_fd = _open_directory(canonical.parent, create=False)
            except PublishError as exc:
                if "managed directory is missing" in str(exc):
                    continue
                raise
            try:
                validator = None
                if kind == "directory":
                    validator = _directory_is_empty_at
                elif kind == "tree":
                    validator = _tree_has_safe_mounts_at
                if not _retire_exact_at(
                    parent_fd,
                    canonical.name,
                    identity,
                    custody_fd,
                    str(canonical),
                    kind,
                    validator=validator,
                    recover_only=True,
                ):
                    raise PublishError(f"retirement recovery preserved unresolved state: {canonical}")
            finally:
                os.close(parent_fd)
    finally:
        os.close(custody_fd)


def _parse_strong_identity(value: str) -> StrongIdentity:
    try:
        parts = tuple(int(part) for part in value.split(":"))
    except ValueError as exc:
        raise PublishError("expected durable object identity is invalid") from exc
    if len(parts) != 4 or parts[0] <= 0 or parts[1] <= 0 or parts[2] <= 0 or not 0 <= parts[3] < 1_000_000_000:
        raise PublishError("expected durable object identity is invalid")
    return parts


def _format_strong_identity(identity: StrongIdentity) -> str:
    return ":".join(str(part) for part in identity)


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
    remove_dir.add_argument("identity")
    remove_dir.add_argument("--custody-root", type=Path)
    remove_tree = subparsers.add_parser("remove-tree-exact")
    remove_tree.add_argument("path", type=Path)
    remove_tree.add_argument("identity")
    remove_tree.add_argument("--custody-root", type=Path)
    symlink = subparsers.add_parser("symlink")
    symlink.add_argument("target")
    symlink.add_argument("destination", type=Path)
    symlink.add_argument("--custody-root", type=Path)
    fresh_symlink = subparsers.add_parser("fresh-symlink")
    fresh_symlink.add_argument("target")
    fresh_symlink.add_argument("destination", type=Path)
    fresh_symlink.add_argument("--custody-root", type=Path)
    regular = subparsers.add_parser("regular")
    regular.add_argument("source", type=Path)
    regular.add_argument("destination", type=Path)
    regular.add_argument("--expected-current-sha256")
    regular.add_argument("--expected-source-sha256")
    regular.add_argument("--custody-root", type=Path)
    fresh_regular = subparsers.add_parser("fresh-regular")
    fresh_regular.add_argument("source", type=Path)
    fresh_regular.add_argument("destination", type=Path)
    fresh_regular.add_argument("--retain-token", action="store_true")
    fresh_regular.add_argument("--custody-root", type=Path)
    unlink = subparsers.add_parser("unlink-exact")
    unlink.add_argument("path", type=Path)
    unlink.add_argument("identity")
    unlink.add_argument("--custody-root", type=Path)
    identify = subparsers.add_parser("path-identity")
    identify.add_argument("path", type=Path)
    recover = subparsers.add_parser("recover-custody")
    recover.add_argument("path", type=Path)
    prepare = subparsers.add_parser("prepare-custody")
    prepare.add_argument("path", type=Path)
    prepare.add_argument("managed_parent", type=Path)
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
            print(_format_strong_identity(identity))
        elif args.command == "rmdir-exact":
            if not rmdir_exact(
                args.path,
                _parse_strong_identity(args.identity),
                custody_root=args.custody_root,
            ):
                raise PublishError(f"directory changed or became nonempty and was preserved: {args.path}")
        elif args.command == "remove-tree-exact":
            if not remove_tree_exact(
                args.path,
                _parse_strong_identity(args.identity),
                custody_root=args.custody_root,
            ):
                raise PublishError(f"directory tree changed and was preserved: {args.path}")
        elif args.command == "symlink":
            publish_symlink(args.target, args.destination, custody_root=args.custody_root)
        elif args.command == "fresh-symlink":
            identity = publish_symlink(
                args.target,
                args.destination,
                fresh_only=True,
                custody_root=args.custody_root,
            )
            if identity is None:
                raise PublishError("fresh-install symlink identity is unavailable")
            print(_format_strong_identity(identity))
        elif args.command == "regular":
            publish_regular(
                args.source,
                args.destination,
                args.expected_current_sha256,
                expected_source=args.expected_source_sha256,
                custody_root=args.custody_root,
            )
        elif args.command == "fresh-regular":
            token = publish_regular(
                args.source,
                args.destination,
                None,
                retain_token=args.retain_token,
                custody_root=args.custody_root,
            )
            if token is not None:
                print(token)
        elif args.command == "unlink-exact":
            if not unlink_exact(
                args.path,
                _parse_strong_identity(args.identity),
                custody_root=args.custody_root,
            ):
                raise PublishError(f"destination changed and was preserved: {args.path}")
        elif args.command == "path-identity":
            print(_format_strong_identity(path_identity(args.path)))
        elif args.command == "recover-custody":
            recover_custody(args.path)
        elif args.command == "prepare-custody":
            prepare_custody(args.path, args.managed_parent)
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
