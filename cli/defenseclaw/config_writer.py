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
7. Release the lock. Callers that own an audit logger record the change
   (``defenseclaw config set`` does) from the returned :class:`WriteResult`.

The lock is reentrant within one thread (:func:`hold_lock`), so a
``Config.save`` inside ``locked_config_yaml`` joins the held lock.

On a managed (standalone enterprise) host both writers refuse unless the
actor is :data:`ACTOR_LIFECYCLE` or :data:`ACTOR_MIGRATION`
(:class:`ManagedConfigWriteError`, exit code 3 in the CLI).
"""

from __future__ import annotations

import getpass
import hashlib
import json
import logging
import os
import re
import stat
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from defenseclaw import file_permissions
from defenseclaw.file_lock import FileLockTimeoutError, locked_file_update

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

#: The runtime descriptor the enterprise lifecycle writes next to the managed
#: config.yaml. The folder that holds it is the lifecycle's, not the writer's.
MANAGED_RUNTIME_DESCRIPTOR = "managed-runtime.json"

#: Shown when a local writer is refused on a managed (standalone) device.
MANAGED_REFUSAL = (
    "This device is managed: change config.yaml in the admin config "
    "(MDM or management plane), not on the device"
)

#: Shown instead of "run defenseclaw init" on a managed (standalone) device.
MANAGED_NOT_INITIALIZED = (
    "This device is managed: DefenseClaw is configured by your administrator (MDM or management "
    "plane), so there is no per-user config to create and 'defenseclaw init' does not apply. "
    "Nothing was changed."
)

# Keys a running gateway applies only after a restart: the process-level
# keys, plus what its reload still treats as restart-required (claw, agent
# and routing, read once at start; the guardrail listener and enablement;
# the hook self-heal settings). "*" matches one segment. Everything
# else is hot. Mirrors internal/config/configwrite restartKeys.
RESTART_KEYS = (
    "data_dir",
    "observability.local.path",
    "observability.local.judge_bodies_path",
    "gateway",
    "guardrail.host",
    "guardrail.port",
    "guardrail.enabled",
    "guardrail.connector",
    "guardrail.scanner_mode",
    "guardrail.retain_judge_bodies",
    "guardrail.hook_self_heal",
    "guardrail.hook_self_heal_debounce_ms",
    "guardrail.connectors.*.enabled",
    "claw",
    "agent",
    "routing",
    "deployment_mode",
    "enterprise.profile",
    "enterprise.network",
    "environment",
    "tenant_id",
    "workspace_id",
    "discovery_source",
)

_log = logging.getLogger(__name__)


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


def current_actor(prefix: str = ACTOR_PREFIX_CLI) -> str:
    """Return ``prefix`` + the OS user (``cli:alice``)."""
    try:
        name = getpass.getuser()
    except Exception:  # noqa: BLE001 - no user database entry
        name = ""
    return prefix + (name or "unknown")


def _connector_enabled(raw: bytes, name: str) -> bool:
    """Whether config bytes enable the guardrail connector ``name`` (unset is enabled)."""
    try:
        document = yaml.safe_load(raw.decode("utf-8")) if raw.strip() else {}
        connectors = document["guardrail"]["connectors"]
        return connectors[name]["enabled"] is not False
    except (UnicodeDecodeError, yaml.YAMLError, KeyError, TypeError):
        return True


def restart_required(changed: list[str], before: bytes | None = None, after: bytes | None = None) -> list[str]:
    """Return the paths in ``changed`` that need a gateway restart. With the
    document bytes before and after, a connector ``enabled`` that resolves to
    the same value (``true`` against unset) is not a change."""
    out = []
    for path in changed:
        try:
            segs = [str(p) for p in parse_path(path) if not isinstance(p, int)]
        except ValueError:
            segs = path.split(".")
        hot_reload_key = segs[:2] == ["gateway", "config_reload"] and segs[2:3] not in ([], ["mode"])
        if segs[:2] == ["gateway", "watcher"] or hot_reload_key:
            continue
        for key in RESTART_KEYS:
            parts = key.split(".")
            if all(k in ("*", p) for k, p in zip(parts, segs)):
                if (
                    before is not None
                    and after is not None
                    and len(segs) == 4
                    and segs[:2] == ["guardrail", "connectors"]
                    and segs[3] == "enabled"
                    and _connector_enabled(before, segs[2]) == _connector_enabled(after, segs[2])
                ):
                    break
                out.append(path)
                break
    return out


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
    config) under the writer lock and return the new generation. Comments
    and key order are kept. When nothing changes, nothing is written."""

    def mutate(current: bytes, source_name: str) -> tuple[bytes, list[str]]:
        return _patch(current, changes, source_name)

    return write_with(mutate, actor, reason, expect_sha256, path=path, timeout_s=timeout_s)


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
    candidate = bytes(raw)

    def mutate(current: bytes, _source_name: str) -> tuple[bytes, list[str]]:
        return candidate, diff_documents(current, candidate)

    return write_with(mutate, actor, reason, expect_sha256, path=path, timeout_s=timeout_s)


Mutator = Callable[[bytes, str], "tuple[bytes, list[str]]"]


def write_with(
    mutate: Mutator,
    actor: str,
    reason: str,
    expect_sha256: str | None = None,
    *,
    path: str | os.PathLike[str] | None = None,
    timeout_s: float = DEFAULT_LOCK_TIMEOUT_S,
    verify: Callable[[str], None] | None = None,
) -> WriteResult:
    """Run one writer transaction: ``mutate(current_bytes, path)`` returns
    the candidate bytes and the changed paths. ``Config.save`` uses it to
    merge its modeled values inside the lock. ``verify(path)`` runs after the
    commit, still under the lock; when it raises, the previous bytes are
    restored (as a new generation) and the error re-raised."""

    if not str(actor or "").strip():
        raise ConfigWriteError("a config writer actor is required")
    target = _resolve(path)
    refuse_when_managed(target, actor)
    with hold_lock(target, timeout_s=timeout_s):
        return _transact(target, mutate, actor, reason, expect_sha256, verify)


_held = threading.local()


@contextmanager
def hold_lock(path: str | os.PathLike[str], *, timeout_s: float | None = DEFAULT_LOCK_TIMEOUT_S) -> Iterator[None]:
    """Hold ``config.yaml.lock``; reentrant in the thread that holds it.

    ``timeout_s=None`` waits without a bound (the legacy
    ``locked_config_yaml`` contract). A timeout raises
    :class:`ConfigLockBusyError`.
    """
    target = os.path.abspath(os.fspath(path))
    held: dict[str, int] = getattr(_held, "paths", None) or {}
    _held.paths = held
    if held.get(target):
        held[target] += 1
        try:
            yield
        finally:
            held[target] -= 1
        return
    directory = os.path.dirname(target) or "."
    # The managed config folder is root-owned 0755 on purpose (every user's
    # hook reads it); a refused or lifecycle write must not tighten it.
    if not os.path.isfile(os.path.join(directory, MANAGED_RUNTIME_DESCRIPTOR)):
        file_permissions.make_private_directory(directory)
    stack = ExitStack()
    try:
        stack.enter_context(locked_file_update(target, timeout_seconds=timeout_s))
    except FileLockTimeoutError as exc:
        raise ConfigLockBusyError("another DefenseClaw process is changing config.yaml") from exc
    with stack:
        held[target] = 1
        try:
            yield
        finally:
            held.pop(target, None)


def _transact(
    target: str,
    mutate: Mutator,
    actor: str,
    reason: str,
    expect_sha256: str | None,
    verify: Callable[[str], None] | None,
) -> WriteResult:
    current, mode, exists = _read_current(target)
    digest = hashlib.sha256(current).hexdigest()
    if expect_sha256 and expect_sha256.lower() != digest:
        raise ConfigConflictError("config.yaml changed since it was read")
    if managed_refuses(current, actor):
        raise ManagedConfigWriteError(MANAGED_REFUSAL)
    candidate, changed = mutate(current, target)
    if exists and candidate == current:
        return WriteResult(_current_generation(target), digest, [], [])
    validate_candidate(target, candidate)
    try:
        _write_durable(target, candidate, mode)
        state = record_generation(target, hashlib.sha256(candidate).hexdigest(), actor, reason)
    except Exception:
        _undo_failed_commit(target, candidate, current, mode, exists)
        raise
    if verify is not None:
        try:
            verify(target)
        except Exception:
            if exists:
                _write_durable(target, current, mode)
                record_generation(target, digest, actor, f"rollback: {reason}")
            else:
                os.unlink(target)
            raise
    _refresh_derived_files(target, candidate)
    return WriteResult(state.generation, state.config_sha256, changed, restart_required(changed, current, candidate))


def _undo_failed_commit(target: str, candidate: bytes, previous: bytes, mode: int, existed: bool) -> None:
    """Put the previous config.yaml back when the new bytes reached disk but
    the commit then failed (a directory fsync, a full disk before the
    generation file), so the error means nothing changed."""
    try:
        if Path(target).read_bytes() != candidate:
            return
        if existed:
            _write_durable(target, previous, mode)
        else:
            os.unlink(target)
    except OSError as exc:
        _log.warning(
            "config writer: config.yaml holds the new bytes after a failed write and could not be restored: %s", exc
        )


def _refresh_derived_files(target: str, candidate: bytes) -> None:
    """Post-commit: re-render custom-providers.json from ``llm_providers``.

    The commit already happened, so a failure here only leaves the derived
    file stale, which doctor reports (and ``doctor --fix`` re-renders).
    """
    try:
        from types import SimpleNamespace

        from defenseclaw import derived_providers
        from defenseclaw.config import _merge_llm_providers

        document = yaml.safe_load(candidate.decode("utf-8")) or {}
        if not isinstance(document, dict):
            return
        data_dir = os.path.expanduser(_data_dir_for(target, candidate))
        shim = SimpleNamespace(data_dir=data_dir, llm_providers=_merge_llm_providers(document.get("llm_providers")))
        derived_providers.refresh(shim)
    except Exception as exc:  # noqa: BLE001 - the config commit stands
        _log.warning("config writer: custom-providers.json was not re-rendered: %s", exc)


def _resolve(path: str | os.PathLike[str] | None) -> str:
    if path is None:
        from defenseclaw.config import config_path

        path = config_path()
    return os.path.abspath(os.fspath(path))


def _read_current(target: str) -> tuple[bytes, int, bool]:
    try:
        info = os.lstat(target)
    except FileNotFoundError:
        return b"", 0o600, False
    if stat.S_ISLNK(info.st_mode):
        raise ConfigWriteError("refusing to edit config.yaml through a symbolic link")
    if not stat.S_ISREG(info.st_mode):
        raise ConfigWriteError("config.yaml must be a regular file")
    with open(target, "rb") as handle:
        return handle.read(), stat.S_IMODE(info.st_mode), True


def _current_generation(target: str) -> int:
    try:
        return read_generation_state(target).generation
    except (OSError, ValueError):
        return 0


_GENERATION_COUNTER = re.compile(rb'"generation"\s*:\s*([0-9]{1,20})')


def _salvage_generation(target: str) -> int:
    """Return the counter a corrupt ``config.generation.json`` still holds, or 0."""
    try:
        with open(generation_path(target), "rb") as handle:
            match = _GENERATION_COUNTER.search(handle.read())
    except OSError:
        return 0
    return int(match.group(1)) if match else 0


def record_generation(target: str, sha256: str, actor: str, reason: str) -> GenerationState:
    """Advance ``config.generation.json`` for bytes already at ``target``.

    For writers that install config.yaml under their own transaction while
    holding ``config.yaml.lock`` (the v8 activation, the upgrade import).
    """
    previous = 0
    reset = False
    try:
        previous = read_generation_state(target).generation
    except (OSError, ValueError):
        reset = True
        # A truncated or hand-broken file may still carry its counter; never
        # go backwards from it (the Go writer salvages it the same way).
        previous = _salvage_generation(target)
    state = GenerationState(
        generation=previous + 1,
        config_sha256=sha256,
        actor=actor,
        written_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        reason=reason,
        generation_reset=reset,
    )
    payload: dict[str, Any] = {
        "generation": state.generation,
        "config_sha256": state.config_sha256,
        "actor": state.actor,
    }
    if reason:
        payload["reason"] = reason
    payload["written_at"] = state.written_at
    if reset:
        payload["generation_reset"] = True
    _write_durable(generation_path(target), (json.dumps(payload, indent=2) + "\n").encode("utf-8"), 0o600)
    return state


def _write_durable(target: str, data: bytes, mode: int) -> None:
    """Temp file in the same directory (mode kept, protected before the
    bytes land), fsync, rename (MoveFileExW write-through on Windows), then
    an fsync of the directory on POSIX. Every failure is an error."""

    directory = os.path.dirname(target) or "."
    # Narrow-only mirror of the existing mode (0600, or 0640 for a
    # group-readable file; a stricter 0400 stays 0400).
    target_mode = mode & 0o600 or 0o600
    if target_mode == 0o600 and mode & 0o077 == 0o040:
        target_mode = 0o640
    fd, staged = tempfile.mkstemp(prefix=f".{os.path.basename(target)}.", suffix=".tmp", dir=directory)
    try:
        file_permissions.set_file_mode(fd, staged, target_mode, set_owner=True)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        file_permissions.replace_file_durable(staged, target)
        staged = ""
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        if staged:
            try:
                os.unlink(staged)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Managed gate


def _standalone_profile(document: dict[str, Any]) -> bool:
    pinned = os.environ.get("DEFENSECLAW_ENTERPRISE_PROFILE", "").strip().lower()
    enterprise = document.get("enterprise") if isinstance(document, dict) else None
    configured = ""
    if isinstance(enterprise, dict):
        configured = str(enterprise.get("profile") or "").strip().lower()
    # As Go (managed.ResolveEnterpriseProfile / StandaloneManagedSource): a
    # pin that contradicts the document's declared profile does not
    # reclassify the host; the document decides.
    if pinned and configured and pinned != configured:
        pinned = ""
    profile = pinned or configured or ("standalone" if sys.platform.startswith("linux") else "secure_client")
    return profile == "standalone"


def machine_managed_standalone() -> bool:
    """Whether this computer is a managed standalone host: the enterprise
    lifecycle published its runtime descriptor (Linux, macOS) or the Windows
    marker with the standalone profile. Any account's CLI sees it, so a
    standard user's per-user config cannot opt out of the managed gate.
    Secure Client hosts publish neither, so their path is unchanged."""
    from defenseclaw.upgrade_shim import managed_deployment

    deployment = managed_deployment()
    return bool(deployment) and (os.name != "nt" or str(deployment).strip().lower() == "standalone")


def _managed_document(current: bytes) -> tuple[bool, dict[str, Any]]:
    """Whether config bytes (or ``DEFENSECLAW_DEPLOYMENT_MODE``) say managed
    enterprise, with the parsed document."""
    from defenseclaw.config import DEPLOYMENT_MODE_ENV, _is_managed_enterprise_mode

    try:
        document = yaml.safe_load(current.decode("utf-8")) if current.strip() else {}
    except (UnicodeDecodeError, yaml.YAMLError):
        document = {}
    if not isinstance(document, dict):
        document = {}
    managed = _is_managed_enterprise_mode(os.environ.get(DEPLOYMENT_MODE_ENV)) or _is_managed_enterprise_mode(
        str(document.get("deployment_mode") or "")
    )
    return managed, document


def standalone_managed(current: bytes) -> bool:
    """Whether this computer, config bytes or ``DEFENSECLAW_DEPLOYMENT_MODE``
    describe a managed deployment on the standalone profile. Secure Client
    hosts are not standalone, so their path is unchanged."""
    if machine_managed_standalone():
        return True
    managed, document = _managed_document(current)
    return managed and _standalone_profile(document)


def secure_client_managed(current: bytes) -> bool:
    """Whether config bytes (or ``DEFENSECLAW_DEPLOYMENT_MODE``) describe a
    managed device on the Secure Client profile."""
    if machine_managed_standalone():
        return False
    managed, document = _managed_document(current)
    return managed and not _standalone_profile(document)


def managed_refuses(current: bytes, actor: str) -> bool:
    """The writer's managed gate: a standalone managed host refuses every
    actor but the lifecycle and migrations."""
    if actor in (ACTOR_LIFECYCLE, ACTOR_MIGRATION):
        return False
    return standalone_managed(current)


def refuse_when_managed(path: str | os.PathLike[str], actor: str | None = None) -> None:
    """Raise :class:`ManagedConfigWriteError` when the managed gate would refuse
    this writer, before it takes ``config.yaml.lock`` or touches the folder: a
    refused writer leaves nothing behind (an empty lock file in a service-owned
    folder). The locked transaction checks the same gate again."""
    try:
        current, _mode, _exists = _read_current(_resolve(path))
    except (ConfigWriteError, OSError):
        return  # the locked transaction reports it
    if managed_refuses(current, actor or current_actor(ACTOR_PREFIX_CLI)):
        raise ManagedConfigWriteError(MANAGED_REFUSAL)


# ---------------------------------------------------------------------------
# Validation


_warned_python_only = False


def _use_go_validator() -> bool:
    """Whether the canonical Go validator is available (tests stub this)."""
    try:
        from defenseclaw.gateway import resolve_trusted_gateway_binary

        return bool(resolve_trusted_gateway_binary())
    except Exception:  # noqa: BLE001 - an unsafe or missing binary falls back below
        return False


def validate_candidate(target: str, candidate: bytes) -> None:
    """Validate candidate bytes before any write: the Go canonical validator
    (``defenseclaw-gateway config-v8 validate``) on a private sibling copy,
    or ``load_validate_v8`` with a warning when the binary is missing."""
    from defenseclaw.observability.v8_config import load_validate_v8

    load_validate_v8(candidate, source_name=target)
    if not _use_go_validator():
        global _warned_python_only
        if not _warned_python_only:
            _warned_python_only = True
            _log.warning("defenseclaw-gateway is not installed; config.yaml is validated by the Python checks only")
        return
    from defenseclaw.config_inspect import ConfigInspectError, inspect_v8_config

    directory = os.path.dirname(target) or "."
    fd, staged = tempfile.mkstemp(prefix=f".{os.path.basename(target)}.candidate-", suffix=".yaml", dir=directory)
    try:
        file_permissions.set_file_mode(fd, staged, 0o600, set_owner=True)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(candidate)
        try:
            inspect_v8_config("validate", config_path=staged, data_dir=_data_dir_for(target, candidate))
        except ConfigInspectError as exc:
            raise ConfigWriteError(f"config.yaml change rejected: {exc}") from exc
    finally:
        if fd != -1:
            os.close(fd)
        try:
            os.unlink(staged)
        except OSError:
            pass


_REASON_CODE = re.compile(r"^\[(?P<code>[A-Za-z0-9_-]+)\]\s*(?P<text>.*)$", re.S)
_RULE_PACK_PREFIX = re.compile(r'^config rule pack (?:"[^"]*"|\S+): ')
_SCHEMA_WORDS = (
    ("correct the field using the configuration schema and reference", "check the value and its documented format"),
    ("use the value type documented by the configuration schema", "use the value type the reference documents"),
)


def plain_error(exc: BaseException) -> str:
    """A refused change in plain words: the key and what to do about it.

    The validators report a JSON path, a bracketed error code and pointers to
    "the canonical v8 schema"; none of that helps someone who typed
    ``config set``. The Go decision stands; this only says it plainly (the
    same wording ``config validate`` uses for the schema errors).
    """
    from defenseclaw.config_inspect import ConfigInspectError
    from defenseclaw.observability.v8_config import V8ConfigError

    cause = exc.__cause__ if isinstance(exc.__cause__, (ConfigInspectError, V8ConfigError)) else exc
    if isinstance(cause, ConfigInspectError) and cause.field_path and cause.reason:
        path, reason = cause.field_path, cause.reason
    elif isinstance(cause, V8ConfigError):
        path, reason = cause.path, f"[{cause.keyword}] {cause.corrective_action}"
    else:
        return str(exc)
    for internal, plain in _SCHEMA_WORDS:
        reason = reason.replace(internal, plain)
    name = path.split(" (line", 1)[0].strip()
    name = name[2:] if name.startswith("$.") else ("config.yaml" if name == "$" else name)
    match = _REASON_CODE.match(reason.strip())
    code, text = (match.group("code"), match.group("text")) if match else ("", reason.strip())
    parts = [part.strip() for part in text.split("; ") if part.strip()]
    if code == "config_semantic_invalid" and parts:
        detail = _RULE_PACK_PREFIX.sub("", parts[0])
        sentence = detail if detail.startswith(name) else f"{name}: {detail}"
        actions = [part for part in parts[1:] if not part.startswith("expected ")]
        return sentence + "." + "".join(f" {part[:1].upper()}{part[1:]}." for part in actions)
    if code == "pattern":
        hint = " (sha256: followed by 64 hex digits)" if name.endswith("digest") else ""
        # A pattern of plain words (block_at) names them in the corrective action.
        allowed = text if text.startswith("use one of ") else ""
        sentence = f"{name} is not in the expected format{hint}."
        return sentence + (f" {allowed[:1].upper()}{allowed[1:]}." if allowed else "")
    from defenseclaw.commands.cmd_config import _plain_v8_issue

    return _plain_v8_issue(None, path, reason)


def _data_dir_for(target: str, candidate: bytes) -> str:
    try:
        document = yaml.safe_load(candidate.decode("utf-8")) or {}
    except (UnicodeDecodeError, yaml.YAMLError):
        document = {}
    value = document.get("data_dir") if isinstance(document, dict) else None
    if isinstance(value, str) and value.strip():
        return value.strip()
    return os.path.dirname(target)


# ---------------------------------------------------------------------------
# Paths and patches

_SEGMENT = re.compile(r'\["((?:[^"\\]|\\.)*)"\]|\[(\d+)\]|([^.\[\]]+)')


def parse_path(path: str) -> tuple[str | int, ...]:
    """Split ``a.b[0]["c.d"]`` into ``("a", "b", 0, "c.d")``."""
    parts: list[str | int] = []
    position = 0
    expect_key = True
    while position < len(path):
        if path[position] == ".":
            if expect_key:
                raise ValueError(f"empty segment in config path {path!r}")
            expect_key = True
            position += 1
            continue
        match = _SEGMENT.match(path, position)
        if match is None:
            raise ValueError(f"invalid config path {path!r}")
        quoted, index, key = match.groups()
        if key is not None:
            if not expect_key:
                raise ValueError(f"missing '.' before {key!r} in config path {path!r}")
            parts.append(key)
        elif index is not None:
            parts.append(int(index))
        else:
            parts.append(json.loads(f'"{quoted}"'))
        expect_key = False
        position = match.end()
    if not parts or expect_key or not isinstance(parts[0], str):
        raise ValueError(f"invalid config path {path!r}")
    return tuple(parts)


def format_path(parts: tuple[str | int, ...]) -> str:
    out = ""
    for part in parts:
        if isinstance(part, int):
            out += f"[{part}]"
        elif re.fullmatch(r"[A-Za-z0-9_-]+", part):
            out += ("." if out else "") + part
        else:
            out += "[" + json.dumps(part) + "]"
    return out


_MISSING = object()


def _lookup(document: Any, parts: tuple[str | int, ...]) -> Any:
    current = document
    for part in parts:
        if isinstance(part, int):
            if not isinstance(current, list) or part >= len(current):
                return _MISSING
            current = current[part]
        else:
            if not isinstance(current, dict) or part not in current:
                return _MISSING
            current = current[part]
    return current


def _check_destination_index(document: Any, path: str, parts: tuple[str | int, ...]) -> None:
    """Refuse a field of a destination config.yaml does not list.

    Writing it would append a half-written entry that the schema then rejects
    with a oneOf message, so say what config get says: the index is out of
    range (GAP-0154). A whole new destination is written at index len().
    """
    if len(parts) < 4 or parts[:2] != ("observability", "destinations") or not isinstance(parts[2], int):
        return
    listed = _lookup(document, parts[:2])
    count = len(listed) if isinstance(listed, list) else 0
    if parts[2] >= count:
        noun = "destination" if count == 1 else "destinations"
        raise ConfigWriteError(
            f"{path}: the index is out of range (config.yaml lists {count} {noun}); "
            "add a destination with 'defenseclaw setup observability add'"
        )


def _patch(current: bytes, changes: list[Change], source_name: str) -> tuple[bytes, list[str]]:
    from defenseclaw.observability.v8_yaml import V8YAMLMutation, prepare_v8_yaml_write

    document = yaml.safe_load(current.decode("utf-8")) if current.strip() else {}
    mutations = []
    changed: list[str] = []
    for change in changes:
        parts = parse_path(change.path)
        before = _lookup(document, parts)
        if change.unset:
            if before is _MISSING:
                continue
            mutations.append(V8YAMLMutation.delete(parts))
        else:
            if before is not _MISSING and before == change.value:
                continue
            _check_destination_index(document, change.path, parts)
            mutations.append(V8YAMLMutation.set(parts, change.value))
        changed.append(change.path)
    if not mutations:
        return current, []
    if not current.strip():
        from defenseclaw.config import CURRENT_CONFIG_VERSION

        current = f"config_version: {CURRENT_CONFIG_VERSION}\n".encode()
    prepared = prepare_v8_yaml_write(current, mutations, source_name=source_name, any_path=True)
    return prepared.candidate, changed


def render_document(current: bytes, document: dict[str, Any], source_name: str) -> bytes:
    """Return ``current`` edited to equal ``document``, keeping comments and
    order where the comment-preserving patcher can; anything it can not
    express is rendered whole."""
    from defenseclaw.observability.v8_yaml import V8YAMLMutation, V8YAMLMutationError, prepare_v8_yaml_write

    try:
        before = yaml.safe_load(current.decode("utf-8")) if current.strip() else None
    except (UnicodeDecodeError, yaml.YAMLError):
        before = None
    if isinstance(before, dict) and before:
        mutations = [
            V8YAMLMutation.set(parts, value) if value is not _MISSING else V8YAMLMutation.delete(parts)
            for parts, value in _document_changes((), before, document)
        ]
        if not mutations:
            return current
        try:
            candidate = prepare_v8_yaml_write(current, mutations, source_name=source_name, any_path=True).candidate
            if yaml.safe_load(candidate.decode("utf-8")) == document:
                return candidate
        except V8YAMLMutationError:
            pass
    return yaml.safe_dump(document, default_flow_style=False, sort_keys=False).encode("utf-8")


_Changes = list[tuple[tuple[str | int, ...], Any]]


def _document_changes(prefix: tuple[str | int, ...], before: Any, after: Any) -> _Changes:
    if isinstance(before, dict) and isinstance(after, dict):
        out: _Changes = []
        for key in before:
            if key not in after:
                out.append(((*prefix, key), _MISSING))
        for key, value in after.items():
            if key not in before:
                out.append(((*prefix, key), value))
            elif before[key] != value:
                out.extend(_document_changes((*prefix, key), before[key], value))
        return out
    if before == after:
        return []
    return [(prefix, after)]


def diff_documents(before_raw: bytes, after_raw: bytes) -> list[str]:
    try:
        before = yaml.safe_load(before_raw.decode("utf-8")) if before_raw.strip() else {}
    except (UnicodeDecodeError, yaml.YAMLError):
        before = {}
    after = yaml.safe_load(after_raw.decode("utf-8")) if after_raw.strip() else {}
    out = []
    for parts, _value in _document_changes((), before if isinstance(before, dict) else {}, after or {}):
        out.append(format_path(parts) or "$")
    return sorted(out)
