# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The single config.yaml writer (Python side).

It follows the same protocol as the Go package
``internal/config/configwrite`` and takes the same ``config.yaml.lock``, so
the two interoperate:

1. Lock ``config.yaml.lock`` (``flock`` on POSIX, ``msvcrt.locking`` on byte 0
   on Windows) with a 10 s default timeout; on timeout raise
   :class:`ConfigLockBusyError`.
2. Read the current bytes and their sha256; when ``expect_sha256`` is given
   and differs, raise :class:`ConfigConflictError`.
3. Apply the changes as a comment-preserving YAML patch
   (``observability.v8_writer.mutate_v8_config``).
4. Validate the candidate with the Go canonical validator
   (``defenseclaw-gateway config-v8 validate``), falling back to
   ``load_validate_v8`` with a warning when the binary is missing.
5. Write atomically (temp file, fsync, rename, directory fsync; a failed
   directory fsync is an error).
6. Write ``config.generation.json`` with the generation incremented.
7. Release the lock and audit ``config.change.applied``.

On a managed (standalone enterprise) host both writers refuse unless the
actor is :data:`ACTOR_LIFECYCLE` or :data:`ACTOR_MIGRATION`
(:class:`ManagedConfigWriteError`, exit code 3 in the CLI).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LOCK_SUFFIX = ".lock"
GENERATION_FILE_NAME = "config.generation.json"
DEFAULT_LOCK_TIMEOUT_S = 10.0

ACTOR_MIGRATION = "migration"
ACTOR_LIFECYCLE = "lifecycle"
ACTOR_PREFIX_CLI = "cli:"
ACTOR_PREFIX_TUI = "tui:"
ACTOR_PREFIX_API = "api:"
ACTOR_PREFIX_SANDBOX = "sandbox:"
ACTOR_PREFIX_HAND_EDIT = "hand-edit:"


class ConfigWriteError(RuntimeError):
    """Base class for writer failures."""


class ConfigConflictError(ConfigWriteError):
    """config.yaml changed after the caller read it (``expect_sha256``)."""


class ConfigLockBusyError(ConfigWriteError):
    """Another DefenseClaw process is changing config.yaml."""


class ManagedConfigWriteError(ConfigWriteError):
    """This device is managed; policy changes come from the management plane."""


@dataclass(frozen=True)
class Change:
    """One edit. ``path`` is dotted with ``[i]`` list indexes, for example
    ``asset_policy.skill.denied[0].name``. ``unset`` removes the key."""

    path: str
    value: Any = None
    unset: bool = False


@dataclass(frozen=True)
class WriteResult:
    """A committed write: the new generation and the written sha256."""

    generation: int
    sha256: str
    changed: list[str] = field(default_factory=list)
    restart_required: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class GenerationState:
    """``config.generation.json``."""

    generation: int
    config_sha256: str
    actor: str
    written_at: str
    reason: str = ""
    generation_reset: bool = False


def lock_path(config_path: str | os.PathLike[str]) -> str:
    return os.fspath(config_path) + LOCK_SUFFIX


def generation_path(config_path: str | os.PathLike[str]) -> str:
    return str(Path(os.fspath(config_path)).parent / GENERATION_FILE_NAME)


def read_generation_state(config_path: str | os.PathLike[str]) -> GenerationState:
    """Read ``config.generation.json`` next to ``config_path``.

    Raises ``FileNotFoundError`` when it is missing and ``ValueError`` when it
    is not a JSON object.
    """
    with open(generation_path(config_path), encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        raise ValueError(f"{GENERATION_FILE_NAME} is not a JSON object")
    return GenerationState(
        generation=int(raw.get("generation", 0)),
        config_sha256=str(raw.get("config_sha256", "")),
        actor=str(raw.get("actor", "")),
        written_at=str(raw.get("written_at", "")),
        reason=str(raw.get("reason", "")),
        generation_reset=raw.get("generation_reset") is True,
    )


def apply(
    changes: list[Change],
    actor: str,
    reason: str,
    expect_sha256: str | None = None,
    *,
    path: str | os.PathLike[str] | None = None,
    timeout_s: float = DEFAULT_LOCK_TIMEOUT_S,
) -> WriteResult:
    """Apply ``changes`` to config.yaml (``path`` defaults to the active
    config) under the writer lock and return the new generation."""
    raise NotImplementedError("config_writer.apply lands with the single-writer change")


def replace_document(
    raw: bytes,
    actor: str,
    reason: str,
    expect_sha256: str | None = None,
    *,
    path: str | os.PathLike[str] | None = None,
    timeout_s: float = DEFAULT_LOCK_TIMEOUT_S,
) -> WriteResult:
    """Write ``raw`` as the whole config.yaml after the same validation.
    Migrations and restores use it."""
    raise NotImplementedError("config_writer.replace_document lands with the single-writer change")
