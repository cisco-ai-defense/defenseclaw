# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Comment-preserving, validated writes for ordinary v8 policy mutations."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from defenseclaw.config import _assert_config_write_allowed, locked_config_yaml
from defenseclaw.config_inspect import inspect_v8_config
from defenseclaw.file_permissions import set_file_mode
from defenseclaw.observability.v8_config import load_validate_v8
from defenseclaw.observability.v8_yaml import V8YAMLMutation, prepare_v8_yaml_write


@dataclass(frozen=True)
class V8PolicyWriteResult:
    """Digest-only result; source bytes and values never enter diagnostics."""

    changed: bool
    before_sha256: str
    after_sha256: str


V8CandidateValidator = Callable[[str, str | None], None]
_StatIdentity = tuple[int, int, int, int, int, int]
_CandidateIdentity = tuple[_StatIdentity, object | None]


def mutate_v8_config(
    config_path: str | Path,
    mutations: Iterable[V8YAMLMutation],
    *,
    data_dir: str | None = None,
    validator: V8CandidateValidator | None = None,
    dry_run: bool = False,
) -> V8PolicyWriteResult:
    """Prepare, validate, and atomically install one ordinary v8 edit.

    The shared sibling lock covers the full read/prepare/validate/replace cycle.
    Validation runs first in the strict Python parser and then in the canonical
    Go compiler against a private sibling candidate.  The original file is
    unchanged on every failure.  This is the ordinary setup/TUI mutation path;
    full-version upgrade activation continues to use ``v8_activation``.
    """

    path = os.path.abspath(os.fspath(config_path))
    validate = validator or _validate_candidate
    with locked_config_yaml(path):
        _assert_safe_target(path)
        _assert_config_write_allowed(path)
        original = Path(path).read_bytes()
        prepared = prepare_v8_yaml_write(original, tuple(mutations), source_name=path)
        load_validate_v8(prepared.candidate, source_name=path)
        candidate_path = _stage_candidate(path, prepared.candidate)
        try:
            candidate_identity, candidate_sha256 = _candidate_snapshot(candidate_path)
            if candidate_sha256 != prepared.candidate_sha256:
                raise RuntimeError("staged observability candidate differs from prepared policy bytes")
            validate(candidate_path, data_dir)
            validated_identity, validated_sha256 = _candidate_snapshot(candidate_path)
            if validated_identity != candidate_identity or validated_sha256 != prepared.candidate_sha256:
                raise RuntimeError("staged observability candidate changed while the canonical validator was running")
            if not prepared.changed:
                return V8PolicyWriteResult(
                    False,
                    prepared.expected_sha256,
                    prepared.candidate_sha256,
                )
            if dry_run:
                return V8PolicyWriteResult(True, prepared.expected_sha256, prepared.candidate_sha256)
            current = Path(path).read_bytes()
            if hashlib.sha256(current).hexdigest() != prepared.expected_sha256:
                raise RuntimeError("config.yaml changed while the observability policy edit was being validated")
            os.replace(candidate_path, path)
            candidate_path = ""
            _fsync_directory(os.path.dirname(path) or ".")
        finally:
            if candidate_path:
                try:
                    os.unlink(candidate_path)
                except FileNotFoundError:
                    pass
        return V8PolicyWriteResult(True, prepared.expected_sha256, prepared.candidate_sha256)


def _validate_candidate(path: str, data_dir: str | None) -> None:
    result = inspect_v8_config("validate", config_path=path, data_dir=data_dir)
    if result.valid is not True:
        raise RuntimeError("canonical v8 configuration validator rejected the candidate")


def _assert_safe_target(path: str) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as exc:
        raise FileNotFoundError("config.yaml does not exist; initialize DefenseClaw before editing v8 policy") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise OSError("refusing to edit config.yaml through a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError("config.yaml must be a regular file")


def _stage_candidate(path: str, candidate: bytes) -> str:
    directory = os.path.dirname(path) or "."
    target_mode = 0o600
    if os.name != "nt":
        existing_mode = stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode)
        target_mode = existing_mode & 0o640
        if target_mode not in {0o600, 0o640}:
            target_mode = 0o600
    descriptor, staged = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.observability-v8-",
        suffix=".tmp",
        dir=directory,
    )
    try:
        # POSIX applies the retained 0600/0640 mode through the descriptor.
        # Windows has no os.fchmod, so the shared helper installs a protected
        # owner/SYSTEM DACL before any policy (and possible secret) bytes are
        # written to the sibling candidate.
        set_file_mode(descriptor, staged, target_mode, set_owner=True)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(candidate)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(staged)
        except OSError:
            pass
        raise
    return staged


def _candidate_snapshot(path: str) -> tuple[_CandidateIdentity, str]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened_before = os.fstat(descriptor)
        path_before = os.lstat(path)
        if not stat.S_ISREG(opened_before.st_mode) or not stat.S_ISREG(path_before.st_mode):
            raise RuntimeError("staged observability candidate is not a regular file")
        opened_stat_identity = _stat_identity(opened_before)
        if _stat_identity(path_before) != opened_stat_identity:
            raise RuntimeError("staged observability candidate changed while being opened")
        windows_security = None
        if os.name == "nt":
            from defenseclaw import windows_acl

            windows_security = windows_acl.capture_fd(descriptor)

        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)

        opened_after = os.fstat(descriptor)
        path_after = os.lstat(path)
        if _stat_identity(opened_after) != opened_stat_identity or _stat_identity(path_after) != opened_stat_identity:
            raise RuntimeError("staged observability candidate changed while being verified")
        if os.name == "nt":
            from defenseclaw import windows_acl

            if windows_acl.capture_fd(descriptor) != windows_security:
                raise RuntimeError("staged observability candidate security changed while being verified")
        return (opened_stat_identity, windows_security), digest.hexdigest()
    except OSError as exc:
        raise RuntimeError("staged observability candidate could not be verified safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _stat_identity(metadata: os.stat_result) -> _StatIdentity:
    # Windows' CRT handle and path stat calls can report different ctime values
    # for the same NTFS file after a DACL update. Device/inode still bind the
    # file identity, while mode/size/mtime plus the content digest bind its
    # bytes. The exact Windows security descriptor is captured separately.
    ctime_ns = 0 if os.name == "nt" else metadata.st_ctime_ns
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        ctime_ns,
    )


def _fsync_directory(path: str) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        try:
            os.fsync(descriptor)
        except OSError:
            pass
    finally:
        os.close(descriptor)


__all__ = ["V8PolicyWriteResult", "mutate_v8_config"]
