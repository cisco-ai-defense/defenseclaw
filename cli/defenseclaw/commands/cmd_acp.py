# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Configure the DefenseClaw ACP guard and supported editor clients."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import ipaddress
import json
import ntpath
import os
import secrets
import shlex
import shutil
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import click

from defenseclaw import ux
from defenseclaw.acp_catalog import ACP_AGENT_ENTRY_POINTS, ACP_CLIENT_IDS, ACP_REGISTRY
from defenseclaw.config import ACPBinding, ACPProfile
from defenseclaw.connector_paths import _normalize_jsonc
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.file_permissions import (
    atomic_write_private_bytes,
    atomic_write_text_secure,
    make_private_directory,
    protect_private_file,
    windows_private_file_protection_error,
)

_SCHEMA_VERSION = ACP_REGISTRY["protocol"]["release"]
_SCHEMA_SHA256 = ACP_REGISTRY["protocol"]["sha256"]
# Go strings.TrimSpace excludes U+001C-U+001F, which Python str.strip removes.
_GO_WHITESPACE = (
    " \t\n\v\f\r\x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)
_REGISTRY = ACP_REGISTRY
_CLIENTS = set(ACP_CLIENT_IDS)
_AGENTS = {agent_id: (command, list(args)) for agent_id, (command, args) in ACP_AGENT_ENTRY_POINTS.items()}


def _client_path(client: str) -> Path:
    if client == "jetbrains":
        return Path.home() / ".jetbrains" / "acp.json"
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise click.ClickException("APPDATA is required to configure Zed on Windows")
        return Path(appdata) / "Zed" / "settings.json"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "zed" / "settings.json"


def _resolve_executable(value: str, label: str) -> str:
    candidate = shutil.which(value)
    if candidate:
        return str(Path(candidate).resolve())
    path = Path(value).expanduser()
    if path.is_absolute() and path.is_file():
        return str(path.resolve())
    raise click.ClickException(f"{label} executable was not found: {value}")


def _read_json_object(path: Path) -> dict[str, Any]:
    # A broken symlink reports exists() == False; reject it before that check.
    if path.is_symlink():
        raise click.ClickException(f"refusing unsafe client configuration path: {path}")
    if not path.exists():
        return {}
    if not path.is_file():
        raise click.ClickException(f"refusing unsafe client configuration path: {path}")
    if path.stat().st_size > 4 << 20:
        raise click.ClickException(f"client configuration is too large: {path}")
    try:
        raw = path.read_text(encoding="utf-8-sig")
        value = json.loads(_normalize_jsonc(raw))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise click.ClickException(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise click.ClickException(f"client configuration must contain a JSON object: {path}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    prefix = ""
    if path.is_file() and not path.is_symlink():
        raw = path.read_text(encoding="utf-8-sig")
        for index, character in enumerate(raw):
            if character != "{":
                continue
            candidate = raw[:index]
            try:
                if not _normalize_jsonc(candidate).strip():
                    prefix = candidate
                    break
            except ValueError:
                continue

    def write(stream) -> None:
        stream.write(prefix)
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")

    atomic_write_text_secure(str(path), write, prefix=".defenseclaw-acp-")


def _write_token(data_dir: str) -> Path:
    path = Path(data_dir) / "acp" / ".token"
    make_private_directory(path.parent)
    if path.is_symlink():
        raise click.ClickException(f"refusing unsafe ACP token path: {path}")
    if path.exists() and (not path.is_file() or path.stat().st_size > 16 << 10):
        raise click.ClickException(f"refusing unsafe ACP token path: {path}")
    if not path.exists():
        token = secrets.token_urlsafe(48)
        atomic_write_text_secure(str(path), lambda stream: stream.write(token + "\n"), prefix=".token-")
    return path.resolve()


def _managed_token(path_value: str, data_dir: str, client: str, agent: str) -> Path:
    """Validate an administrator-provisioned per-binding token sidecar."""
    expected = (Path(data_dir) / "acp" / f"{client}-{agent}.token").resolve()
    path = Path(path_value).expanduser().resolve() if path_value else expected
    if path != expected:
        raise click.ClickException(f"managed ACP token must use the enrolled binding path: {expected}")
    if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0 or path.stat().st_size > 16 << 10:
        raise click.ClickException(f"managed ACP token is missing or unsafe: {path}")
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise click.ClickException(f"managed ACP token permissions are too broad: {path}")
    try:
        protect_private_file(path)
    except OSError as exc:
        raise click.ClickException(f"managed ACP token custody is unsafe: {path}: {exc}") from exc
    return path


def _snapshot(path: Path) -> tuple[bool, bytes]:
    # Keep broken symlinks out of both mutation and rollback paths.
    if path.is_symlink():
        raise click.ClickException(f"refusing unsafe managed path: {path}")
    if not path.exists():
        return False, b""
    if not path.is_file():
        raise click.ClickException(f"refusing unsafe managed path: {path}")
    return True, path.read_bytes()


def _restore(path: Path, snapshot: tuple[bool, bytes]) -> None:
    existed, body = snapshot
    if existed:
        atomic_write_private_bytes(path, body)
    elif path.exists():
        if path.is_symlink() or not path.is_file():
            raise click.ClickException(f"cannot safely roll back managed path: {path}")
        path.unlink()


def _client_digest(path: Path) -> str:
    """The editor file's digest, or "" when it cannot be read (never matches a pin)."""
    try:
        return _sha256_file(str(path))
    except OSError:
        return ""


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _agent_version(_executable: str) -> str:
    # Setup must not execute an arbitrary operator-selected binary merely to
    # decorate the lock. Runtime identity is pinned by absolute path + SHA-256;
    # certification captures version output in a separate, explicit test flow.
    return "not-probed"


def _contract_lock_path(data_dir: str, client: str, agent: str) -> Path:
    return Path(data_dir) / "acp" / f"{client}-{agent}.contract-lock.json"


def _write_contract_lock(
    *,
    data_dir: str,
    client: str,
    agent: str,
    profile: str,
    mode: str,
    guard: str,
    agent_executable: str,
    client_path: Path,
    managed: bool,
    adopted_entries: list[str] | None = None,
) -> Path:
    path = _contract_lock_path(data_dir, client, agent)
    document: dict[str, Any] = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "protocol": {"schema_version": _SCHEMA_VERSION, "schema_sha256": _SCHEMA_SHA256},
        "client": {"id": client, "config_path": str(client_path), "config_sha256": _sha256_file(str(client_path))},
        "agent": {
            "id": agent,
            "path": agent_executable,
            "sha256": _sha256_file(agent_executable),
            "version": _agent_version(agent_executable),
        },
        "guard": {"path": guard, "sha256": _sha256_file(guard), "managed_custody": managed},
        "profile": profile,
        "mode": mode,
    }
    if adopted_entries:
        # The operator's own picker entries this binding routes through the
        # guard. Verify reports one that stops launching the guard, and the
        # next setup routes it back, so pointing it at the agent again is not
        # a silent bypass. Omitted when only the reserved entry is written.
        document["client"]["adopted_entries"] = sorted(adopted_entries)
    atomic_write_private_bytes(path, (json.dumps(document, indent=2, sort_keys=True) + "\n").encode())
    return path.resolve()


def _lock_document(path: Path, client: str, agent: str) -> dict[str, Any] | None:
    """The pair's contract lock when it is a safe, readable lock for this pair."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 << 10:
            return None
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(document, dict):
        return None
    lock_client, lock_agent = document.get("client"), document.get("agent")
    if (
        not isinstance(lock_client, dict)
        or not isinstance(lock_agent, dict)
        or lock_client.get("id") != client
        or lock_agent.get("id") != agent
    ):
        return None
    return document


def _adopted_entries(document: dict[str, Any] | None) -> list[str]:
    names = document["client"].get("adopted_entries") if document else None
    return [name for name in names if isinstance(name, str)] if isinstance(names, list) else []


def _client_contract_snapshots(data_dir: str, client: str, agent: str) -> list[tuple[Path, tuple[bool, bytes]]]:
    paths = {_contract_lock_path(data_dir, client, agent)}
    paths.update(
        _contract_lock_path(data_dir, pair_client, pair_agent)
        for pair_client, pair_agent in _managed_pairs(data_dir)
        if pair_client == client
    )
    return [(path, _snapshot(path)) for path in sorted(paths)]


def _refresh_client_contract_digests(data_dir: str, client: str, client_path: Path) -> None:
    """Atomically re-pin every DefenseClaw entry sharing one editor file."""
    if not client_path.is_file():
        return
    digest = _sha256_file(str(client_path))
    for pair_client, pair_agent in sorted(_managed_pairs(data_dir)):
        if pair_client != client:
            continue
        path = _contract_lock_path(data_dir, pair_client, pair_agent)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 << 10:
            raise click.ClickException(f"managed ACP contract lock is missing or unsafe: {path}")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise click.ClickException(f"managed ACP contract lock is unreadable: {path}: {exc}") from exc
        lock_client = document.get("client") if isinstance(document, dict) else None
        lock_agent = document.get("agent") if isinstance(document, dict) else None
        if (
            not isinstance(lock_client, dict)
            or not isinstance(lock_agent, dict)
            or lock_client.get("id") != pair_client
            or lock_agent.get("id") != pair_agent
        ):
            raise click.ClickException(f"managed ACP contract lock identity does not match: {path}")
        lock_client["config_path"] = str(client_path.resolve())
        lock_client["config_sha256"] = digest
        atomic_write_private_bytes(path, (json.dumps(document, indent=2, sort_keys=True) + "\n").encode())


def _managed_name(agent: str) -> str:
    return f"DefenseClaw · {agent.capitalize()}"


def _guard_options(entry: dict[str, Any]) -> dict[str, str]:
    args = entry.get("args")
    if not isinstance(args, list) or "--" not in args:
        return {}
    prefix = args[:args.index("--")]
    if len(prefix) % 2 or not all(isinstance(value, str) for value in prefix):
        return {}
    options = dict(zip(prefix[::2], prefix[1::2]))
    return options if len(options) * 2 == len(prefix) else {}


def _lock_is_private(path: Path) -> bool:
    """Whether a contract lock is still in this account's custody.

    Setup writes locks owner-only. On POSIX a lock another account owns, or
    one others can read or rewrite, proves nothing about who wrote the entry,
    and the guard refuses a lock with any group or other permission bit.
    (Root may own one: enterprise re-pinning rewrites managed locks.) Windows
    locks sit in the account's own profile with an owner-only ACL.
    """
    if os.name == "nt":
        return True
    try:
        info = path.lstat()
    except OSError:
        return False
    return info.st_uid in {os.geteuid(), 0} and not stat.S_IMODE(info.st_mode) & 0o077


# Every field the guard's lock decoder knows, per object (RuntimeContractLock
# in internal/acp/contract.go). The guard refuses a lock with any other field
# at any level (DisallowUnknownFields). Every DefenseClaw release since 1.0.0
# has written only these fields, so this also covers locks from upgrades.
_LOCK_FIELDS: dict[str, frozenset[str]] = {
    "": frozenset({"version", "generated_at", "protocol", "client", "agent", "guard", "profile", "mode"}),
    "protocol": frozenset({"schema_version", "schema_sha256"}),
    "client": frozenset({"id", "config_path", "config_sha256", "adopted_entries"}),
    "agent": frozenset({"id", "path", "sha256", "version"}),
    "guard": frozenset({"path", "sha256", "managed_custody"}),
}


def _unique_lock_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Do not let a later JSON field hide one the guard's decoder refuses."""
    fields: dict[str, Any] = {}
    for name, value in pairs:
        if name in fields:
            raise ValueError(f"duplicate contract lock field {name!r}")
        fields[name] = value
    return fields


def _lock_is_complete(document: dict[str, Any]) -> bool:
    """Whether a lock is one the guard can start from (version 1).

    The guard refuses a lock that lacks its protocol pin, the editor file
    digest, or the guard and agent pins, or that carries a field its decoder
    does not know, so such a lock proves nothing about an entry. Values are
    not compared with the current schema here: after a DefenseClaw upgrade a
    lock keeps its old protocol pin until acp refresh, and it is still this
    runtime's lock.
    """

    def strings(item: Any, *keys: str) -> bool:
        return isinstance(item, dict) and all(isinstance(item.get(key), str) and item[key].strip() for key in keys)

    def optional_string(item: Any, key: str) -> bool:
        return key not in item or isinstance(item[key], str)

    client, agent, guard = document.get("client"), document.get("agent"), document.get("guard")
    adopted = client.get("adopted_entries", []) if isinstance(client, dict) else None
    known = set(document) <= _LOCK_FIELDS[""] and all(
        isinstance(document.get(key), dict) and set(document[key]) <= fields
        for key, fields in _LOCK_FIELDS.items()
        if key
    )
    return (
        known
        and type(document.get("version")) is int
        and document["version"] == 1
        and optional_string(document, "generated_at")
        and strings(document.get("protocol"), "schema_version", "schema_sha256")
        and strings(client, "id", "config_path", "config_sha256")
        and isinstance(adopted, list)
        and all(isinstance(name, str) for name in adopted)
        and strings(agent, "id", "path", "sha256")
        and optional_string(agent, "version")
        and strings(guard, "path", "sha256")
        and isinstance(guard.get("managed_custody", False), bool)
        and strings(document, "profile", "mode")
    )


def _proven_lock(path: Path, client: str, agent: str) -> dict[str, Any] | None:
    """The pair's lock when it can prove ownership: safe, complete and private."""
    document = _lock_document(path, client, agent)
    if document is None or not _lock_is_complete(document) or not _lock_is_private(path):
        return None
    return document


# The guard options setup writes, in every release since 1.0.0 and in the
# managed Go setup. The guard refuses a flag it does not know.
_GUARD_ENTRY_OPTIONS = frozenset(
    {"--agent", "--client", "--profile", "--mode", "--token-file", "--gateway", "--contract-lock"}
)


def _launches_locked_agent(entry: dict[str, Any], options: dict[str, str], lock: dict[str, Any], agent: str) -> bool:
    """Whether an entry's argv is the launch setup writes for this lock.

    The guard starts only the executable the lock pins, under the lock's
    profile and mode. Setup writes exactly its guard options, then -- and
    the pinned executable with the catalog arguments. An entry that launches
    anything else after -- (another binary, the same file by another path,
    added or missing arguments, or none, which makes the guard fall back to
    the catalog command) is not the entry setup wrote.
    """
    args = entry.get("args")
    lock_agent = lock.get("agent")
    if not isinstance(args, list) or "--" not in args or not isinstance(lock_agent, dict):
        return False
    return (
        set(options) == _GUARD_ENTRY_OPTIONS
        and options["--profile"] == lock.get("profile")
        and options["--mode"] == lock.get("mode")
        and args[args.index("--") + 1:] == [lock_agent.get("path"), *_AGENTS[agent][1]]
    )


def _is_exact_path(value: str, expected: Path) -> bool:
    """Whether an argv path is exactly the canonical path setup writes.

    Setup writes resolved paths, and verify compares them as strings. A path
    that only resolves to the same file (a symlink in another directory, or
    one with .. in it) is not what setup wrote.
    """
    if not value or not Path(value).is_absolute():
        return False
    if os.name == "nt":
        return os.path.normcase(value) == os.path.normcase(str(expected))
    return value == str(expected)


def _lock_names_entry(
    entry: dict[str, Any], options: dict[str, str], client: str, agent: str, data_dir: str | None
) -> bool:
    """Whether this runtime's contract lock proves that setup wrote the entry.

    Only setup writes the lock, in the private ACP runtime directory. The
    entry must name this runtime's lock for the pair (a valid lock in another
    runtime directory belongs to that runtime, not this one) and this
    runtime's token for the lock's custody, both by the exact canonical path
    setup writes: a symlink elsewhere that resolves to this lock is another
    runtime's entry, and the guard will not open a symlinked lock. The lock
    must be a regular file, complete (the guard can start from it), private,
    bind this editor file and pin the guard the entry starts, and the entry
    must launch exactly the agent command the lock pins, under its profile
    and mode.
    A guard-like filename proves nothing on its own: an operator's wrapper
    may also be called defenseclaw-acp. With no runtime (data_dir None) no
    alias is proven.
    """
    if not data_dir:
        return False
    lock_value, token_value = options.get("--contract-lock", ""), options.get("--token-file", "")
    try:
        runtime_lock = _contract_lock_path(str(Path(data_dir).expanduser()), client, agent)
        runtime = runtime_lock.parent.resolve()
        expected_lock = runtime / runtime_lock.name
        if not _is_exact_path(lock_value, expected_lock):
            return False
        lock = _proven_lock(expected_lock, client, agent)
        if (
            lock is None
            or lock["guard"]["path"] != entry.get("command")
            or not _launches_locked_agent(entry, options, lock, agent)
        ):
            return False
        token_name = f"{client}-{agent}.token" if lock["guard"].get("managed_custody") else ".token"
        if not _is_exact_path(token_value, runtime / token_name):
            return False
        return Path(lock["client"]["config_path"]).resolve() == _client_path(client).resolve()
    except (OSError, ValueError, click.ClickException):
        return False


def _guarded_pair(entry: dict[str, Any], name: str, data_dir: str | None) -> tuple[str, str] | None:
    """The pair a DefenseClaw-written editor entry guards, or None.

    data_dir is the ACP runtime directory whose locks can prove an alias.
    """
    options = _guard_options(entry)
    client, agent = options.get("--client", ""), options.get("--agent", "")
    if client not in _CLIENTS or agent not in _AGENTS:
        return None
    if name == _managed_name(agent) and _entry_is_guarded(entry):
        # The reserved entry name launching the guard is what setup has
        # always written for this pair.
        return client, agent
    # Any other entry (an adopted picker entry, a copy, or a guard with
    # another filename) belongs to DefenseClaw only when this runtime's lock
    # says so. Without that proof it is the operator's (or another
    # runtime's), and setup and remove leave it.
    return (client, agent) if _lock_names_entry(entry, options, client, agent, data_dir) else None


def _pair_entry_names(servers: dict[str, Any], client: str, agent: str, data_dir: str | None) -> list[str]:
    return [
        name for name, entry in servers.items()
        if name == _managed_name(agent)
        or isinstance(entry, dict) and _guarded_pair(entry, name, data_dir) == (client, agent)
    ]


def _check_reserved_entry(client: str, agent: str, data_dir: str, adopting: str | None = None) -> None:
    path = _client_path(client)
    servers = _read_json_object(path).get("agent_servers")
    name = _managed_name(agent)
    if not isinstance(servers, dict) or name not in servers or name == adopting:
        return
    entry = servers[name]
    if not isinstance(entry, dict) or _guarded_pair(entry, name, data_dir) != (client, agent):
        # Ask for the same command again, not a shortened one: a bare
        # `acp setup` would rebind the pair in observe mode.
        raise click.ClickException(
            f"cannot identify editor entry {name!r} as DefenseClaw-owned; "
            f"rename that entry in {path}, then run the same command again"
        )


def _set_client_entry(
    client: str,
    agent: str,
    data_dir: str,
    command: str,
    args: list[str],
    entry_name: str | None = None,
    retained: list[str] | None = None,
) -> tuple[Path, list[str]]:
    """Write the pair's guard entries; return the file and the entry names written."""
    path = _client_path(client)
    document = _read_json_object(path)
    servers = document.setdefault("agent_servers", {})
    if not isinstance(servers, dict):
        raise click.ClickException(f"agent_servers must be an object in {path}")
    names = _pair_entry_names(servers, client, agent, data_dir)
    taken_over: set[str] = set()
    if entry_name is not None:
        adopted = servers.get(entry_name)
        if not isinstance(adopted, dict) or _agent_for_entry(adopted) != agent:
            raise click.ClickException(f"ACP entry {entry_name!r} changed before adoption; run the same command again")
        taken_over.add(entry_name)
    # An entry this binding adopted earlier (its lock names it) that now
    # launches the agent directly is a bypass; route it back through the guard.
    for name in retained or []:
        candidate = servers.get(name)
        if name not in names and isinstance(candidate, dict) and _agent_for_entry(candidate) == agent:
            taken_over.add(name)
    names.extend(sorted(taken_over - set(names)))
    for name in names:
        if name in taken_over:
            continue
        existing = servers[name]
        if not isinstance(existing, dict) or _guarded_pair(existing, name, data_dir) != (client, agent):
            raise click.ClickException(
                f"cannot identify editor entry {name!r} as DefenseClaw-owned; "
                f"rename that entry in {path}, then run the same command again"
            )
    aliases = [name for name in names if name != _managed_name(agent)]
    if aliases and _managed_name(agent) in servers:
        canonical = servers[_managed_name(agent)]
        if not isinstance(canonical, dict) or _guarded_pair(canonical, _managed_name(agent), data_dir) != (
            client, agent
        ):
            raise click.ClickException("the duplicate ACP entry cannot be identified; run defenseclaw acp verify")
        del servers[_managed_name(agent)]
    written = aliases or names or [_managed_name(agent)]
    for name in written:
        entry = dict(servers.get(name) or {})
        entry.update(command=command, args=args)
        entry.setdefault("env", {})
        if client == "zed":
            entry["type"] = "custom"
        servers[name] = entry
    _write_json(path, document)
    return path, written


def _has_client_entry(client: str, agent: str, data_dir: str) -> bool:
    servers = _read_json_object(_client_path(client)).get("agent_servers")
    return isinstance(servers, dict) and bool(_pair_entry_names(servers, client, agent, data_dir))


def _unproven_pair_entries(client: str, agent: str, data_dir: str) -> list[str]:
    """Entries that start a guard for this pair but that this runtime cannot prove it wrote.

    Removal leaves them (the operator's, or another runtime's) and warns.
    """
    servers = _read_json_object(_client_path(client)).get("agent_servers")
    if not isinstance(servers, dict):
        return []
    proven = set(_pair_entry_names(servers, client, agent, data_dir))
    return sorted(
        name for name, entry in servers.items()
        if name not in proven
        and isinstance(entry, dict)
        and (options := _guard_options(entry)).get("--client") == client
        and options.get("--agent") == agent
    )


def _warn_unproven_entries(names: list[str], path: Path, client: str, agent: str) -> None:
    for name in names:
        ux.warn(
            f"Left editor entry {name!r} in {path}: it starts a guard for {client}/{agent}, but this "
            "runtime cannot prove DefenseClaw wrote it. Delete it there if you no longer use it.",
            indent="",
        )


def _remove_client_entry(client: str, agent: str, data_dir: str) -> Path:
    path = _client_path(client)
    document = _read_json_object(path)
    servers = document.get("agent_servers")
    if not isinstance(servers, dict):
        return path
    names = _pair_entry_names(servers, client, agent, data_dir)
    if not names:
        # Nothing here is this runtime's: leave the operator's file byte for byte.
        return path
    for name in names:
        entry = servers[name]
        if not isinstance(entry, dict) or _guarded_pair(entry, name, data_dir) != (client, agent):
            raise click.ClickException(
                f"cannot identify editor entry {name!r} as DefenseClaw-owned; "
                f"rename that entry in {path}, then run the same command again"
            )
    for name in names:
        servers.pop(name)
    if not servers:
        # Don't leave an empty agent_servers object (or a file that setup
        # created only for DefenseClaw) behind once the last entry is gone.
        document.pop("agent_servers")
    if document:
        _write_json(path, document)
    elif path.is_file() and not path.is_symlink():
        path.unlink()
    return path


def _managed_pairs(data_dir: str | None) -> set[tuple[str, str]]:
    """Pairs with an editor entry this runtime (data_dir) can prove it wrote."""
    pairs: set[tuple[str, str]] = set()
    for client in sorted(_CLIENTS):
        document = _read_json_object(_client_path(client))
        servers = document.get("agent_servers")
        if not isinstance(servers, dict):
            continue
        for agent in _AGENTS:
            if _pair_entry_names(servers, client, agent, data_dir):
                pairs.add((client, agent))
    return pairs


def _binding_pairs(cfg: Any, data_dir: str) -> set[tuple[str, str]]:
    """Every pair bound here: editor entries, contract locks and configured bindings.

    An adopted entry pointed back at the agent no longer looks like a guard
    entry, so reading the editor files alone dropped the binding from status
    and verify exactly when it was bypassed. Its lock and its configured
    binding remain. A managed host's central bindings name pairs for every
    user, so only this user's locks count there.
    """
    pairs = _managed_pairs(data_dir)
    for client in _CLIENTS:
        for agent in _AGENTS:
            lock = _contract_lock_path(data_dir, client, agent)
            if lock.is_symlink() or lock.exists():
                pairs.add((client, agent))
    if cfg.deployment_mode != "managed_enterprise":
        for key, binding in cfg.acp.bindings.items():
            client, _, agent = str(key).partition("/")
            if getattr(binding, "enabled", False) and client in _CLIENTS and agent in _AGENTS:
                pairs.add((client, agent))
    return pairs


def _managed_guard_custody_is_trusted(path_value: str) -> bool:
    """Conservatively preflight the runtime's admin-owned managed-path signal."""

    try:
        path = Path(path_value).expanduser().absolute()
        if os.name == "nt":
            from defenseclaw.file_permissions import (
                reject_reparse_path,
                windows_acl_custody_write_error,
            )

            reject_reparse_path(path)
            if not path.is_file():
                return False
            for index, element in enumerate((path, *path.parents)):
                if (
                    windows_acl_custody_write_error(
                        element,
                        allow_current_user=False,
                        ancestor_replace_only=index > 0,
                    )
                    is not None
                ):
                    return False
            return True
        for index, element in enumerate((path, *path.parents)):
            info = element.lstat()
            if stat.S_ISLNK(info.st_mode):
                return False
            if index == 0 and not stat.S_ISREG(info.st_mode):
                return False
            if index > 0 and not stat.S_ISDIR(info.st_mode):
                return False
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                return False
        return True
    except (OSError, ValueError):
        return False


# The guard's flags and their defaults (run in cmd/defenseclaw-acp/main.go).
_GUARD_FLAG_DEFAULTS = {
    "agent": "",
    "client": "custom",
    "profile": "default",
    "mode": "observe",
    "gateway": "http://127.0.0.1:18970/api/v1/acp/evaluate",
    "token-file": "",
    "contract-lock": "",
}

# samePath in internal/acp/contract.go ignores case on Windows.
_GUARD_PATHS_FOLD_CASE = os.name == "nt"


def _same_guard_path(left: str, right: str) -> bool:
    """The guard's path comparison: filepath.Abs, then samePath."""
    left, right = os.path.abspath(left), os.path.abspath(right)
    if _GUARD_PATHS_FOLD_CASE:
        return ntpath.normcase(ntpath.normpath(left)) == ntpath.normcase(ntpath.normpath(right))
    return left == right


def _guard_argv(args: Any) -> tuple[dict[str, str], list[str]] | None:
    """The guard's flags and agent command line for an entry's args.

    Parses like Go's flag package: -name or --name, with =value or the next
    argument, up to -- or the first argument that is not a flag. None when
    the guard does not start an agent from them (an unknown flag, a missing
    value, --catalog or --version).
    """
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        return None
    values = dict(_GUARD_FLAG_DEFAULTS)
    index = 0
    while index < len(args):
        arg = args[index]
        if len(arg) < 2 or arg[0] != "-":
            break
        index += 1
        if arg == "--":
            break
        name = arg[2:] if arg.startswith("--") else arg[1:]
        if not name or name[0] in "-=":
            return None
        name, has_value, value = name.partition("=")
        if name not in values:
            return None
        if not has_value:
            if index == len(args):
                return None
            value = args[index]
            index += 1
        values[name] = value
    return values, args[index:]


def _names_file(value: str, path: Path) -> bool:
    """Whether an argv path is this file by any path (symlinked directory, case)."""
    if not value:
        return False
    try:
        return os.path.samefile(value, path)
    except OSError:
        return _same_guard_path(value, str(path))


def _guard_token_problem(value: str) -> str | None:
    """The guard's checks of --token-file (run in cmd/defenseclaw-acp/main.go)."""
    if not value:
        return "it has no --token-file"
    path = Path(os.path.normpath(value))
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            return f"its --token-file {path} is not a regular file"
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            return f"its --token-file {path} permissions are too broad"
        if os.name == "nt":
            protection = windows_private_file_protection_error(path)
            if protection:
                return f"its --token-file {path} protection is unsafe: {protection}"
        if info.st_size > 16 << 10:
            return f"its --token-file {path} is unexpectedly large"
        if not path.read_bytes().decode("utf-8", errors="surrogateescape").strip(_GO_WHITESPACE):
            return f"its --token-file {path} is empty"
    except OSError:
        return f"its --token-file {path} cannot be read"
    return None


def _guard_contract_lock_problem(path: Path) -> str | None:
    """Check the lock's file type, size and protection before the guard reads it."""
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 64 << 10:
            return "is missing or unsafe"
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            return "permissions are too broad"
        if os.name == "nt":
            protection = windows_private_file_protection_error(path)
            if protection:
                return f"protection is unsafe: {protection}"
    except OSError:
        return "is missing or unsafe"
    return None


def _guard_gateway_problem(value: str) -> str | None:
    """Match NewHTTPEvaluator: only a literal HTTP loopback endpoint starts."""
    endpoint = value.strip(_GO_WHITESPACE)
    if any(ord(character) < 32 or ord(character) == 127 for character in endpoint):
        return "its --gateway is not an HTTP literal loopback URL"
    for index, character in enumerate(endpoint):
        if character == "%" and (
            index + 2 >= len(endpoint)
            or any(digit not in "0123456789abcdefABCDEF" for digit in endpoint[index + 1:index + 3])
        ):
            return "its --gateway is not an HTTP literal loopback URL"
    try:
        parsed = urlsplit(endpoint)
        host = parsed.hostname
        if parsed.scheme != "http" or not host or parsed.username is not None or parsed.query or parsed.fragment:
            return "its --gateway is not an HTTP literal loopback URL"
        if "%" in host:  # net.ParseIP rejects IPv6 zone identifiers.
            return "its --gateway is not an HTTP literal loopback URL"
        # Go's URL parser accepts an empty or decimal port, without applying
        # the socket layer's range check during evaluator construction.
        authority = parsed.netloc
        port = authority[authority.find("]") + 1:] if authority.startswith("[") else authority[len(host):]
        if port and (not port.startswith(":") or (port[1:] and (not port[1:].isascii() or not port[1:].isdigit()))):
            return "its --gateway is not an HTTP literal loopback URL"
        address = ipaddress.ip_address(host)
        loopback = address.is_loopback or (
            isinstance(address, ipaddress.IPv6Address)
            and address.ipv4_mapped is not None
            and address.ipv4_mapped.is_loopback
        )
    except ValueError:
        return "its --gateway is not an HTTP literal loopback URL"
    return None if loopback else "its --gateway is not an HTTP literal loopback URL"


def _copy_refusal(entry: dict[str, Any], lock: dict[str, Any], lock_path: Path) -> str | None:
    """Why the guard refuses a copied entry that names this lock, or None.

    None also for an entry that names another lock, which is not this
    binding's. Follows run in cmd/defenseclaw-acp/main.go and
    ValidateRuntimeContract: flags take the guard's defaults, paths compare
    as the guard compares them, the guard falls back to the catalog command
    without a command after --, and --token-file and --gateway are checked.
    The lock itself (its digests and pins) is checked once for the binding.
    """
    args = entry.get("args")
    parsed = _guard_argv(args)
    if parsed is None:
        named = isinstance(args, list) and any(isinstance(arg, str) and _names_file(arg, lock_path) for arg in args)
        return "the guard does not accept its arguments" if named else None
    values, launch = parsed
    if not _names_file(values["contract-lock"], lock_path):
        return None
    lock_problem = _guard_contract_lock_problem(Path(values["contract-lock"]))
    if lock_problem:
        return f"its --contract-lock {lock_problem}"
    if launch:
        command = launch[0]
    elif values["agent"] in _AGENTS:
        command = _AGENTS[values["agent"]][0]
    else:
        return "it names no agent command"
    lock_client, lock_agent, lock_guard = lock.get("client"), lock.get("agent"), lock.get("guard")
    if (
        not isinstance(lock_client, dict)
        or not isinstance(lock_agent, dict)
        or not isinstance(lock_guard, dict)
        or [lock_client.get("id"), lock_agent.get("id"), lock.get("profile"), lock.get("mode")]
        != [values["client"], values["agent"], values["profile"], values["mode"]]
    ):
        return "its --client, --agent, --profile or --mode does not match the lock"
    if not isinstance(lock_agent.get("path"), str) or not _same_guard_path(command, lock_agent["path"]):
        return "it launches another agent executable than the lock"
    guard = entry.get("command")
    guard = guard if isinstance(guard, str) and os.path.isabs(guard) else shutil.which(str(guard or ""))
    if guard is None:
        # The editor cannot start it at all; the guard never runs.
        return None
    if os.name == "nt" and not os.path.splitext(guard)[1]:
        # Windows starts <path>.exe, which os.Executable then reports.
        guard += ".exe"
    if sys.platform.startswith("linux"):
        # os.Executable resolves symlinks on Linux.
        guard = os.path.realpath(guard)
    if not isinstance(lock_guard.get("path"), str) or not _same_guard_path(guard, lock_guard["path"]):
        return "it starts another guard executable than the lock"
    return _guard_token_problem(values["token-file"]) or _guard_gateway_problem(values["gateway"])


def _verify_binding(
    data_dir: str,
    client: str,
    agent: str,
    acp_config: Any | None = None,
) -> list[str]:
    """Check one binding's editor entry, contract lock and pinned policy.

    acp_config is optional so callers without configuration loaded keep the
    previous file-only checks.
    """

    problems: list[str] = []
    client_path = _client_path(client)
    # The lock and the configured binding keep a pair listed after its
    # editor file is gone, so report the file instead of hashing it.
    settings_usable = False
    document: dict[str, Any] = {}
    if not client_path.is_symlink() and not client_path.exists():
        problems.append(f"editor settings file is missing: {client_path}")
    else:
        try:
            document = _read_json_object(client_path)
            settings_usable = True
        except click.ClickException as exc:
            problems.append(f"editor settings file cannot be used: {exc.message}")
    servers = document.get("agent_servers")
    names = _pair_entry_names(servers, client, agent, data_dir) if isinstance(servers, dict) else []
    if not names:
        problems.append("managed editor entry is missing")
    lock_path = _contract_lock_path(data_dir, client, agent)
    lock_problem = _guard_contract_lock_problem(lock_path)
    if lock_problem:
        problems.append(f"contract lock {lock_problem}")
        return problems
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_lock_fields)
    except (OSError, UnicodeError, ValueError):
        problems.append("contract lock is unreadable")
        return problems
    if not isinstance(lock, dict):
        problems.append("contract lock is not an object")
        return problems
    lock_client = lock.get("client")
    lock_agent = lock.get("agent")
    lock_guard = lock.get("guard")
    if (
        not isinstance(lock_client, dict)
        or not isinstance(lock_agent, dict)
        or lock_client.get("id") != client
        or lock_agent.get("id") != agent
    ):
        problems.append("contract lock identity does not match")
    # Ownership only establishes which entry setup wrote. The guard also
    # decodes the whole lock with a closed field set and requires the current
    # version and protocol pins before it will start the agent. In particular,
    # a stale, nonempty protocol digest still proves ownership of an alias.
    if not _lock_is_complete(lock):
        problems.append("contract lock malformed or incomplete")
        return problems
    if lock["protocol"]["schema_version"] != _SCHEMA_VERSION or lock["protocol"]["schema_sha256"] != _SCHEMA_SHA256:
        problems.append("contract lock protocol pins do not match this guard")
        return problems
    problems.extend(
        f"adopted editor entry {name!r} no longer launches the DefenseClaw guard"
        for name in lock_client.get("adopted_entries", [])
        if name not in names
    )
    locked_client_path = lock_client["config_path"]
    if Path(locked_client_path).resolve() != client_path.resolve():
        problems.append("client configuration path does not match")
    elif settings_usable and lock_client["config_sha256"] != _client_digest(client_path):
        problems.append("client configuration digest has drifted")
    for key in ("agent", "guard"):
        item = lock.get(key)
        path_value = item["path"]
        if not Path(path_value).is_file():
            problems.append(f"{key} executable is missing")
        elif item["sha256"] != _sha256_file(path_value) and not (
            key == "guard"
            and lock_guard.get("managed_custody") is True
            and _managed_guard_custody_is_trusted(path_value)
        ):
            problems.append(
                f"{key} executable digest has drifted"
                + ("; after a DefenseClaw upgrade run: defenseclaw acp refresh" if key == "guard" else "")
            )
    # Policy drift. The guard carries its profile and mode in argv, pinned
    # here at setup, and the gateway refuses a request whose profile the
    # configuration no longer assigns to this pair. Editing
    # acp.bindings["<client>/<agent>"].profile by hand therefore breaks the
    # next session, and without this check `verify` and `status` would keep
    # reporting the binding healthy until the operator hit a dead editor.
    if acp_config is not None:
        expected_profile = acp_config.profile_for_pair(client, agent)
        locked_profile = lock.get("profile")
        if isinstance(locked_profile, str) and locked_profile != expected_profile:
            problems.append(
                f"contract lock profile {locked_profile!r} no longer matches the configured "
                f"{expected_profile!r} for {client}/{agent}; re-run acp setup"
            )
        else:
            resolved = acp_config.profiles.get(expected_profile)
            expected_mode = (resolved.mode if resolved else "") or acp_config.mode
            locked_mode = lock.get("mode")
            if isinstance(locked_mode, str) and expected_mode and locked_mode != expected_mode:
                problems.append(
                    f"contract lock mode {locked_mode!r} no longer matches profile "
                    f"{expected_profile!r} mode {expected_mode!r}; re-run acp setup"
                )
    for name in names:
        entry = servers[name]
        if not isinstance(entry, dict):
            problems.append(f"editor entry {name!r} is not an object")
            continue
        args = entry.get("args")
        options = _guard_options(entry)
        if (
            entry.get("command") != lock_guard["path"]
            or not isinstance(args, list)
            or not options
            or not _launches_locked_agent(entry, options, lock, agent)
            or any(options.get(flag) != expected for flag, expected in {
                "--client": client, "--agent": agent,
                "--contract-lock": str(lock_path.resolve()),
                "--token-file": str(Path(data_dir).expanduser().resolve() / "acp" / (
                    f"{client}-{agent}.token" if lock_guard.get("managed_custody")
                    else ".token"
                )),
            }.items())
        ):
            problems.append(f"editor launch command does not match the lock: {name}")
    # A copied entry with an edited gateway can look like an adopted alias to
    # the ownership check. Check those flags on owned entries too; the other
    # launch fields are checked in the names loop above.
    for name, entry in servers.items() if isinstance(servers, dict) else ():
        if not isinstance(entry, dict) or not _entry_is_guarded(entry):
            continue
        if name in names:
            options = _guard_options(entry)
            reason = _guard_token_problem(options.get("--token-file", "")) or _guard_gateway_problem(
                options.get("--gateway", "")
            )
        else:
            reason = _copy_refusal(entry, lock, lock_path)
        if reason:
            origin = "" if name in names else "setup did not write it and "
            remedy = f"re-run acp setup for {client}/{agent}" if name in names else f"delete it from {client_path}"
            problems.append(
                f"editor entry {name!r} cannot start: {origin}{reason} "
                f"({remedy})"
            )
    return problems


@click.group("acp")
def acp_cmd() -> None:
    """Inspect and configure the local Agent Client Protocol guard."""


@acp_cmd.command("catalog")
def catalog_cmd() -> None:
    """Print protocol and built-in integration inventory."""
    click.echo(json.dumps(_REGISTRY, indent=2, sort_keys=True))


def _progress(enabled: bool, message: str) -> None:
    """Print one step of a slow ACP change, so it does not look hung (GAP-1835).

    Setup and remove hash executables, rewrite editor files and config.yaml
    and wait for the gateway's audit acknowledgement; on a busy Windows host
    that took about two minutes with no output at all. The lines go to
    stderr, so --json output stays one document.
    """
    if enabled:
        click.echo(f"  {message}", err=True)


@acp_cmd.command("setup")
@click.option("--client", type=click.Choice(sorted(_CLIENTS)), required=True, help="Editor that runs the agent.")
@click.option("--agent", type=click.Choice(sorted(_AGENTS)), required=True, help="ACP agent to guard.")
@click.option(
    "--profile", default="default", show_default=True, help="ACP policy profile (acp.profiles) the guard enforces."
)
@click.option(
    "--guard-binary",
    default="defenseclaw-acp",
    show_default=True,
    help="DefenseClaw ACP guard executable the editor entry starts.",
)
@click.option("--agent-binary", default="", help="Override the catalog agent executable.")
@click.option("--activate", is_flag=True, help="Enable action mode; setup otherwise observes only.")
@click.option(
    "--managed",
    is_flag=True,
    help="Enroll user-side files only; enterprise policy and credential stay administrator-owned.",
)
@click.option(
    "--runtime-data-dir",
    default=None,
    type=click.Path(file_okay=False, path_type=Path),
    help="Per-user ACP runtime directory (required when it differs from central enterprise data_dir).",
)
@click.option(
    "--token-file",
    default=None,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Administrator-provisioned managed token; must equal <runtime-data-dir>/acp/<client>-<agent>.token.",
)
@click.option("--json-output", "--json", "json_output", is_flag=True, help="Print the result as JSON.")
@pass_ctx
def setup_cmd(
    app: AppContext,
    client: str,
    agent: str,
    profile: str,
    guard_binary: str,
    agent_binary: str,
    activate: bool,
    managed: bool,
    runtime_data_dir: Path | None,
    token_file: Path | None,
    json_output: bool,
    entry_name: str | None = None,
) -> None:
    """Install a guarded agent entry into Zed or JetBrains."""
    if not app.cfg:
        raise click.ClickException("configuration is unavailable")
    show = not json_output
    _progress(show, f"Setting up {client}/{agent}: checking the guard and agent executables...")
    guard = _resolve_executable(guard_binary, "DefenseClaw ACP guard")
    catalog_command, catalog_args = _AGENTS[agent]
    agent_executable = _resolve_executable(agent_binary or catalog_command, agent)
    mode = "action" if activate else "observe"
    data_dir = str((runtime_data_dir or Path(app.cfg.data_dir)).expanduser().resolve())
    if managed and app.cfg.deployment_mode != "managed_enterprise":
        raise click.ClickException("--managed requires deployment_mode: managed_enterprise")
    if not managed and (runtime_data_dir or token_file):
        raise click.ClickException("--runtime-data-dir and --token-file are managed-enrollment options")
    # Policy is per pair. A client or agent pin may still be shared by other
    # pairs, so this pair records its own binding and never rewrites a pin
    # another pair depends on.
    pair_key = app.cfg.acp.binding_key(client, agent)
    existing_profile = app.cfg.acp.profiles.get(profile)
    # Refuse only when the requested mode would change a profile that another
    # pair is already using -- that pair did not ask to be promoted or demoted.
    # Resolve every already-configured pair, not just the ones with an
    # explicit binding. A pair that inherits this profile through its client
    # or agent pin is affected by a mode change just as much, and looking only
    # at `bindings` would silently promote or demote it.
    other_pairs_using_profile = sorted(
        f"{other_client}/{other_agent}"
        for other_client, other_agent in _binding_pairs(app.cfg, data_dir)
        if app.cfg.acp.binding_key(other_client, other_agent) != pair_key
        and app.cfg.acp.profile_for_pair(other_client, other_agent) == profile
    )
    if (
        existing_profile is not None
        and other_pairs_using_profile
        and existing_profile.mode
        and existing_profile.mode != mode
    ):
        raise click.ClickException(
            f"profile {profile} is {existing_profile.mode} mode for {', '.join(other_pairs_using_profile)}; "
            f"pass --profile <name> to give {pair_key} its own profile instead of changing theirs"
        )
    if managed:
        client_binding = app.cfg.acp.clients.get(client)
        agent_binding = app.cfg.acp.agents.get(agent)
        selected_profile = app.cfg.acp.profiles.get(profile)
        selected_mode = (selected_profile.mode if selected_profile else "") or app.cfg.acp.mode or "observe"
        if (
            not app.cfg.acp.enabled
            or client_binding is None
            or not client_binding.enabled
            or client_binding.profile != profile
            or agent_binding is None
            or not agent_binding.enabled
            or agent_binding.profile != profile
            or selected_profile is None
            or client not in selected_profile.allowed_clients
            or agent not in selected_profile.allowed_agents
            or selected_mode != mode
        ):
            raise click.ClickException(
                f"central enterprise ACP policy does not authorize {client}/{agent} in {profile} {mode} mode"
            )
    client_path = _client_path(client)
    _check_reserved_entry(client, agent, data_dir, entry_name)
    token_candidate = (
        Path(data_dir) / "acp" / f"{client}-{agent}.token" if managed else Path(data_dir) / "acp" / ".token"
    )
    lock_candidate = _contract_lock_path(data_dir, client, agent)
    retained = _adopted_entries(_proven_lock(lock_candidate, client, agent))
    client_snapshot = _snapshot(client_path)
    token_snapshot = _snapshot(token_candidate)
    lock_snapshots = _client_contract_snapshots(data_dir, client, agent)
    acp_snapshot = copy.deepcopy(app.cfg.acp)
    token_path = _managed_token(str(token_file or ""), data_dir, client, agent) if managed else _write_token(data_dir)
    args = [
        "--agent",
        agent,
        "--client",
        client,
        "--profile",
        profile,
        "--mode",
        mode,
        "--token-file",
        str(token_path),
        "--gateway",
        f"http://127.0.0.1:{app.cfg.gateway.api_port}/api/v1/acp/evaluate",
        "--contract-lock",
        str(lock_candidate.resolve()),
        "--",
        agent_executable,
        *catalog_args,
    ]
    try:
        _progress(show, f"Writing the DefenseClaw {agent} entry to {client_path}...")
        path, written = _set_client_entry(client, agent, data_dir, guard, args, entry_name, retained)
        _progress(show, "Pinning the guard and agent executable digests...")
        lock_path = _write_contract_lock(
            data_dir=data_dir,
            client=client,
            agent=agent,
            profile=profile,
            mode=mode,
            guard=guard,
            agent_executable=agent_executable,
            client_path=path,
            managed=managed,
            adopted_entries=[name for name in written if name != _managed_name(agent)],
        )
        _refresh_client_contract_digests(data_dir, client, path)
        if not managed:
            app.cfg.acp.enabled = True
            # These two are global fallbacks, not this pair's policy. Writing
            # them on every setup made a second pair in observe mode flip the
            # default for pairs that inherit it, and left `acp.mode`
            # describing whichever pair was configured last. Seed them from
            # the first binding and leave them alone afterwards; this pair's
            # own mode lives on its profile.
            existing_pairs = {
                app.cfg.acp.binding_key(other_client, other_agent)
                for other_client, other_agent in _binding_pairs(app.cfg, data_dir)
            } - {pair_key}
            if not existing_pairs:
                # The first binding seeds both fallbacks; leaving
                # default_profile at its dataclass default would point the
                # last-resort lookup at a profile setup never created.
                app.cfg.acp.mode = mode
                app.cfg.acp.default_profile = profile
            # The pair is the authority. The client and agent pins record
            # only that each half is enabled; leaving their profile blank
            # keeps them from dragging other pairs onto this profile.
            app.cfg.acp.bindings[pair_key] = ACPBinding(enabled=True, profile=profile)
            app.cfg.acp.clients.setdefault(client, ACPBinding(enabled=True, profile=""))
            app.cfg.acp.agents.setdefault(agent, ACPBinding(enabled=True, profile=""))
            app.cfg.acp.clients[client].enabled = True
            app.cfg.acp.agents[agent].enabled = True
            profile_value = existing_profile or ACPProfile()
            profile_value.mode = mode
            profile_value.fail_mode = "closed" if activate else "open"
            profile_value.allowed_clients = sorted(set(profile_value.allowed_clients) | {client})
            profile_value.allowed_agents = sorted(set(profile_value.allowed_agents) | {agent})
            app.cfg.acp.profiles[profile] = profile_value
            _progress(show, "Saving the ACP policy to the DefenseClaw config...")
            app.cfg.save()
    except Exception as exc:
        app.cfg.acp = acp_snapshot
        rollback_errors: list[str] = []
        for managed_path, snapshot in [
            (client_path, client_snapshot),
            (token_candidate, token_snapshot),
            *lock_snapshots,
        ]:
            try:
                _restore(managed_path, snapshot)
            except Exception as rollback_exc:  # pragma: no cover - catastrophic platform failure
                rollback_errors.append(f"{managed_path}: {type(rollback_exc).__name__}")
        suffix = f"; rollback problems: {', '.join(rollback_errors)}" if rollback_errors else ""
        raise click.ClickException(f"ACP setup was rolled back: {exc}{suffix}") from exc
    result = {
        "client": client,
        "agent": agent,
        "mode": mode,
        "profile": profile,
        "path": str(path),
        "contract_lock": str(lock_path),
        "managed": managed,
    }
    prior = acp_snapshot.bindings.get(pair_key)
    prior_profile = acp_snapshot.profiles.get(prior.profile) if prior is not None else None
    _progress(show, "Recording the change with the gateway...")
    _log_acp_change(
        app,
        "acp-setup",
        f"scope={client}/{agent} mode={mode} previous={getattr(prior_profile, 'mode', '') or ''}",
    )
    if not managed:
        _wait_for_gateway_acp(app, profile, mode, show)
    click.echo(
        json.dumps(result, sort_keys=True)
        if json_output
        else f"Configured {agent} through DefenseClaw in {client} ({mode}) at {path}"
    )


def _log_acp_change(app: AppContext, operation: str, details: str) -> None:
    """Record an ACP entry change as an Activity mutation that names it (GAP-1511).

    The change is saved first; a stopped gateway only skips the audit event.
    """
    if not getattr(app, "logger", None):
        return
    from defenseclaw.logger import CanonicalObservabilityError, CanonicalObservabilityUnavailableError

    try:
        app.logger.log_config_change(operation, details)
    except CanonicalObservabilityUnavailableError:
        ux.echo("  ⚠ Change saved. The gateway isn't running, so the audit event was not recorded.", err=True)
    except CanonicalObservabilityError as exc:
        ux.echo(f"  ⚠ Change saved, but the gateway did not confirm the audit event ({exc}).", err=True)


# The gateway reloads config.yaml about half a second after it changes.
_GATEWAY_ACP_APPLY_SECONDS = 10.0


def _wait_for_gateway_acp(app: AppContext, profile: str, mode: str, show: bool) -> None:
    """Return once the running gateway has loaded this setup (GAP-2135).

    An editor session started before the reload was refused with HTTP 503
    ("ACP guard is not enabled") right after setup said Configured. A gateway
    that is stopped, or does not answer this request, is not waited for.
    """
    from defenseclaw.gateway import OrchestratorClient, gateway_api_client_host

    try:
        client = OrchestratorClient(
            host=gateway_api_client_host(app.cfg),
            port=app.cfg.gateway.api_port,
            token=app.cfg.gateway.resolved_token(),
            timeout=2,
        )
    except Exception:  # noqa: BLE001 - the wait is best effort
        return
    deadline = time.monotonic() + _GATEWAY_ACP_APPLY_SECONDS
    announced = False
    try:
        while True:
            try:
                loaded = client.acp_profiles()
            except Exception:  # noqa: BLE001 - stopped or older gateway: nothing to wait for
                return
            profiles = loaded.get("profiles")
            entry = profiles.get(profile) if isinstance(profiles, dict) else None
            if loaded.get("enabled") is True and isinstance(entry, dict) and entry.get("mode") == mode:
                return
            if time.monotonic() >= deadline:
                ux.echo(
                    "  ⚠ Change saved, but the gateway has not loaded it yet; an editor session started "
                    "in the next few seconds may be refused. Wait a moment before you start it.",
                    err=True,
                )
                return
            if not announced:
                _progress(show, "Waiting for the gateway to load the ACP policy...")
                announced = True
            time.sleep(0.25)
    finally:
        client.close()


@acp_cmd.command("remove")
@click.option("--client", type=click.Choice(sorted(_CLIENTS)), required=True, help="Editor that runs the agent.")
@click.option("--agent", type=click.Choice(sorted(_AGENTS)), required=True, help="ACP agent to guard.")
@click.option("--managed", is_flag=True, help="Remove only user-side enterprise enrollment files.")
@click.option(
    "--runtime-data-dir",
    default=None,
    type=click.Path(file_okay=False, path_type=Path),
    help="Per-user ACP runtime directory of a managed enrollment.",
)
@pass_ctx
def remove_cmd(app: AppContext, client: str, agent: str, managed: bool, runtime_data_dir: Path | None) -> None:
    """Remove one DefenseClaw-owned editor entry without touching foreign agents."""
    if not app.cfg:
        raise click.ClickException("configuration is unavailable")
    path = _client_path(client)
    data_dir = str((runtime_data_dir or Path(app.cfg.data_dir)).expanduser().resolve())
    _check_reserved_entry(client, agent, data_dir)
    unproven = _unproven_pair_entries(client, agent, data_dir)
    path_snapshot = _snapshot(path)
    if managed and app.cfg.deployment_mode != "managed_enterprise":
        raise click.ClickException("--managed requires deployment_mode: managed_enterprise")
    if not managed and runtime_data_dir:
        raise click.ClickException("--runtime-data-dir is a managed-enrollment option")
    lock_path = _contract_lock_path(data_dir, client, agent)
    lock_snapshots = _client_contract_snapshots(data_dir, client, agent)
    had_entry = _has_client_entry(client, agent, data_dir)
    had_policy = not managed and app.cfg.acp.binding_key(client, agent) in app.cfg.acp.bindings
    if not (had_entry or had_policy or lock_path.exists()):
        click.echo(f"Nothing to remove: no DefenseClaw {agent} entry is configured for {client} ({path})")
        _warn_unproven_entries(unproven, path, client, agent)
        return
    acp_snapshot = copy.deepcopy(app.cfg.acp)
    try:
        _progress(True, f"Removing the DefenseClaw {agent} entry from {path}...")
        path = _remove_client_entry(client, agent, data_dir)
        remaining = _binding_pairs(app.cfg, data_dir) - {(client, agent)}
        if not managed:
            # The pair's own policy goes with the pair. The client and agent
            # pins survive while any other pair still uses that half.
            app.cfg.acp.bindings.pop(app.cfg.acp.binding_key(client, agent), None)
            if not any(pair_client == client for pair_client, _ in remaining):
                app.cfg.acp.clients.pop(client, None)
            if not any(pair_agent == agent for _, pair_agent in remaining):
                app.cfg.acp.agents.pop(agent, None)
        if lock_path.exists():
            lock_path.unlink()
        _refresh_client_contract_digests(data_dir, client, path)
        if not managed:
            active_clients = set(app.cfg.acp.clients)
            active_agents = set(app.cfg.acp.agents)
            for profile_name, profile_value in app.cfg.acp.profiles.items():
                profile_value.allowed_clients = [
                    value for value in profile_value.allowed_clients if value in active_clients
                ]
                profile_value.allowed_agents = [
                    value for value in profile_value.allowed_agents if value in active_agents
                ]
            app.cfg.acp.enabled = bool(active_clients and active_agents)
            _progress(True, "Saving the ACP policy to the DefenseClaw config...")
            app.cfg.save()
    except Exception as exc:
        app.cfg.acp = acp_snapshot
        rollback_errors: list[str] = []
        for managed_path, snapshot in [(path, path_snapshot), *lock_snapshots]:
            try:
                _restore(managed_path, snapshot)
            except Exception as rollback_exc:  # pragma: no cover - catastrophic platform failure
                rollback_errors.append(f"{managed_path}: {type(rollback_exc).__name__}")
        suffix = f"; rollback problems: {', '.join(rollback_errors)}" if rollback_errors else ""
        raise click.ClickException(f"ACP removal was rolled back: {exc}{suffix}") from exc
    _progress(True, "Recording the change with the gateway...")
    _log_acp_change(app, "acp-remove", f"scope={client}/{agent} entry=removed previous=configured")
    _warn_unproven_entries(unproven, path, client, agent)
    if had_entry:
        click.echo(f"Removed the DefenseClaw {agent} entry from {path}")
    else:
        click.echo(f"Removed leftover DefenseClaw {client}/{agent} state; {path} had no {agent} entry")


@acp_cmd.command("status")
@click.option(
    "--runtime-data-dir",
    default=None,
    type=click.Path(file_okay=False, path_type=Path),
    help="Per-user ACP runtime directory of a managed enrollment.",
)
@click.option("--json-output", "--json", "json_output", is_flag=True, help="Print the result as JSON.")
@pass_ctx
def status_cmd(app: AppContext, runtime_data_dir: Path | None, json_output: bool = False) -> None:
    """Show configured ACP posture and editor paths."""
    if not app.cfg:
        raise click.ClickException("configuration is unavailable")
    data_dir = str((runtime_data_dir or Path(app.cfg.data_dir)).expanduser().resolve())
    bindings = {}
    for client, agent in sorted(_binding_pairs(app.cfg, data_dir)):
        problems = _verify_binding(data_dir, client, agent, app.cfg.acp)
        profile = app.cfg.acp.profile_for_pair(client, agent)
        resolved = app.cfg.acp.profiles.get(profile)
        bindings[f"{client}/{agent}"] = {
            "healthy": not problems,
            "problems": problems,
            # Policy is per pair, so the resolved profile and its mode belong
            # on the binding rather than only at the top level.
            "profile": profile,
            "mode": (resolved.mode if resolved else "") or app.cfg.acp.mode,
            "profile_source": (
                "binding"
                if app.cfg.acp.bindings.get(app.cfg.acp.binding_key(client, agent), None) is not None
                and app.cfg.acp.bindings[app.cfg.acp.binding_key(client, agent)].profile.strip()
                else "inherited"
            ),
        }
    payload = {
        "enabled": app.cfg.acp.enabled,
        "mode": app.cfg.acp.mode,
        "default_profile": app.cfg.acp.default_profile,
        "clients": {name: str(_client_path(name)) for name in sorted(_CLIENTS)},
        "configured_clients": sorted(app.cfg.acp.clients),
        "configured_agents": sorted(app.cfg.acp.agents),
        "bindings": bindings,
    }
    if json_output:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    _print_acp_status(payload)


def _print_acp_status(payload: dict) -> None:
    """Readable ACP posture for 'acp status' (GAP-1501); --json keeps the document."""
    state = "on" if payload["enabled"] else "off"
    bindings = payload["bindings"]
    # Mode and profile are per binding (rows below). The top-level acp.mode /
    # default_profile only seed the first setup, so showing them here
    # described a past setup call rather than the guard (GAP-1732).
    count = len(bindings)
    click.echo(f"ACP guard: {state} ({count} binding{'' if count == 1 else 's'})")
    if not bindings:
        click.echo("  No guarded editor/agent pairs yet.")
        ux.subhead("Add one with: defenseclaw acp setup --client <editor> --agent <agent>", indent="  ")
        return
    click.echo("  Bindings:")
    for pair, info in sorted(bindings.items()):
        health = "healthy" if info["healthy"] else "NEEDS ATTENTION"
        source = "" if info["profile_source"] == "binding" else ", inherited"
        click.echo(f"    {pair:<20} {health:<16} profile {info['profile']} ({info['mode']}{source})")
        for problem in info["problems"]:
            ux.warn(str(problem), indent="      ")
    if any(not info["healthy"] for info in bindings.values()):
        ux.subhead("Fix with: defenseclaw acp verify, then re-run defenseclaw acp setup for that pair", indent="  ")
    clients = payload["configured_clients"]
    for name in clients:
        click.echo(f"  {name} config: {payload['clients'].get(name, '')}")
    ux.subhead("Machine-readable output: defenseclaw acp status --json", indent="  ")


@acp_cmd.command("verify")
@click.option(
    "--client",
    type=click.Choice(sorted(_CLIENTS)),
    default=None,
    help="Editor that runs the agent (default: every configured binding).",
)
@click.option(
    "--agent",
    type=click.Choice(sorted(_AGENTS)),
    default=None,
    help="ACP agent to guard (default: every configured binding).",
)
@click.option(
    "--runtime-data-dir",
    default=None,
    type=click.Path(file_okay=False, path_type=Path),
    help="Per-user ACP runtime directory of a managed enrollment.",
)
@pass_ctx
def verify_cmd(app: AppContext, client: str | None, agent: str | None, runtime_data_dir: Path | None) -> None:
    """Fail if a managed editor entry or executable digest has drifted.

    With no --client/--agent, every configured binding is verified.
    """
    if not app.cfg:
        raise click.ClickException("configuration is unavailable")
    data_dir = str((runtime_data_dir or Path(app.cfg.data_dir)).expanduser().resolve())
    if client and agent:
        pairs = [(client, agent)]
    else:
        pairs = sorted(
            (pair_client, pair_agent)
            for pair_client, pair_agent in _binding_pairs(app.cfg, data_dir)
            if (client is None or pair_client == client) and (agent is None or pair_agent == agent)
        )
        if not pairs:
            raise click.ClickException(
                "No DefenseClaw ACP bindings are configured"
                + (f" for {client or agent}" if client or agent else "")
                + "; run 'defenseclaw acp setup --client <editor> --agent <agent>' first"
            )
    failures: list[str] = []
    for pair_client, pair_agent in pairs:
        problems = _verify_binding(data_dir, pair_client, pair_agent, app.cfg.acp)
        if problems:
            command = setup_repair_command(app.cfg, pair_client, pair_agent, data_dir)
            failures.append(f"{pair_client}/{pair_agent}: " + "; ".join(problems) + f"; run {command}")
        else:
            click.echo(f"Verified {pair_client}/{pair_agent}: editor entry and executable digests match")
    if failures:
        raise click.ClickException("ACP binding verification failed: " + " | ".join(failures))


def setup_repair_command(cfg: Any, client: str, agent: str, data_dir: str) -> str:
    """The `acp setup` command that restores this binding as configured.

    It keeps the binding's profile and mode. Setup without --activate writes
    observe mode and fail-open, so a repair hint without it turned an action
    binding into an unenforced one. The lock's guard and agent executables are
    named when the lock still identifies them, so the repair rebinds the same
    files rather than whatever is first on PATH.
    """
    profile = cfg.acp.profile_for_pair(client, agent)
    resolved = cfg.acp.profiles.get(profile)
    mode = (resolved.mode if resolved else "") or cfg.acp.mode or "observe"
    command = ["defenseclaw", "acp", "setup", "--client", client, "--agent", agent, "--profile", profile]
    if mode != "observe":
        # Every mode but observe enforces; never print a command that demotes it.
        command.append("--activate")
    lock = _lock_document(_contract_lock_path(data_dir, client, agent), client, agent)
    for flag, key in (("--guard-binary", "guard"), ("--agent-binary", "agent")):
        item = lock.get(key) if lock else None
        executable = item.get("path") if isinstance(item, dict) else None
        if isinstance(executable, str) and Path(executable).is_absolute() and Path(executable).is_file():
            command.extend([flag, executable])
    if cfg.deployment_mode == "managed_enterprise":
        command.extend(["--managed", "--runtime-data-dir", data_dir])
    if os.name == "nt":
        return "defenseclaw " + " ".join("'" + value.replace("'", "''") + "'" for value in command[1:])
    return shlex.join(command)


def refresh_guard_pins(
    data_dir: str,
    *,
    from_sha256: str = "",
    guard_path: str = "",
    apply: bool = True,
) -> list[str]:
    """Re-pin DefenseClaw's own ACP guard in its contract locks.

    Touches only the editor entries DefenseClaw wrote (``_managed_pairs``),
    never a managed-custody lock, and only the guard digest and protocol
    schema: a changed agent binary still needs ``acp setup``. ``from_sha256``
    limits it to locks that pinned that guard digest; ``guard_path`` to
    locks whose guard is that file. With ``apply=False`` nothing is written.
    Returns the ``client/agent`` pairs re-pinned (or that would be).
    """
    protocol = {"schema_version": _SCHEMA_VERSION, "schema_sha256": _SCHEMA_SHA256}
    only_path = os.path.normcase(str(Path(guard_path).expanduser().resolve())) if guard_path else ""
    repinned: list[str] = []
    for client, agent in sorted(_managed_pairs(data_dir)):
        lock_path = _contract_lock_path(data_dir, client, agent)
        try:
            if lock_path.is_symlink() or not lock_path.is_file() or lock_path.stat().st_size > 64 << 10:
                continue
            document = json.loads(lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        guard = document.get("guard") if isinstance(document, dict) else None
        pinned_path = guard.get("path") if isinstance(guard, dict) else None
        if (
            not isinstance(pinned_path, str)
            or guard.get("managed_custody") is True
            or Path(pinned_path).name.lower() not in _GUARD_BASENAMES
            or not Path(pinned_path).is_file()
        ):
            continue
        if only_path and os.path.normcase(str(Path(pinned_path).resolve())) != only_path:
            continue
        if from_sha256 and str(guard.get("sha256", "")).lower() != from_sha256.strip().lower():
            continue
        digest = _sha256_file(pinned_path)
        if guard.get("sha256") == digest and document.get("protocol") == protocol:
            continue
        if apply:
            guard["sha256"] = digest
            document["protocol"] = protocol
            atomic_write_private_bytes(lock_path, (json.dumps(document, indent=2, sort_keys=True) + "\n").encode())
        repinned.append(f"{client}/{agent}")
    return repinned


@acp_cmd.command("refresh")
@click.option(
    "--from-sha256",
    "from_sha256",
    default="",
    help="Re-pin only locks that pinned this guard digest (the installer passes the guard it replaced).",
)
@click.option(
    "--guard-path",
    "guard_path",
    default="",
    help="Re-pin only locks whose guard is this file (a source install passes the guard it just published).",
)
@pass_ctx
def refresh_cmd(app: AppContext, from_sha256: str, guard_path: str) -> None:
    """Re-pin the DefenseClaw ACP guard in every editor entry after an upgrade.

    An upgrade replaces defenseclaw-acp, so each contract lock still names the
    old guard digest and the editor entry fails closed. This re-pins only
    DefenseClaw's own guard and the protocol schema; a changed agent binary or
    editor entry still needs 'defenseclaw acp setup'. The installers and
    'make all' run it, and 'defenseclaw doctor --fix' does too.
    """
    if not app.cfg:
        raise click.ClickException("configuration is unavailable")
    data_dir = str(Path(app.cfg.data_dir).expanduser().resolve())
    for pair in refresh_guard_pins(data_dir, from_sha256=from_sha256, guard_path=guard_path):
        click.echo(f"Re-pinned the DefenseClaw ACP guard for {pair}")


# --- ACP discovery and takeover -------------------------------------------
#
# `acp setup` requires the operator to already know which client and which
# agent they want guarded. That is the wrong starting point for someone who
# just installed DefenseClaw: the editor may already be launching an ACP agent
# directly, which is exactly the traffic the guard exists to mediate, and
# nothing surfaced it. These helpers read the clients DefenseClaw knows, say
# what is guarded and what is not, and can route an existing direct entry
# through the guard without the operator naming anything.

_GUARD_BASENAMES = {"defenseclaw-acp", "defenseclaw-acp.exe"}


def _entry_basename(command: str) -> str:
    name = Path(str(command or "")).name.lower()
    return name[:-4] if name.endswith(".exe") else name


def _entry_is_guarded(entry: dict[str, Any]) -> bool:
    return _entry_basename(str(entry.get("command", ""))) in {
        base.removesuffix(".exe") for base in _GUARD_BASENAMES
    }


def _agent_for_entry(entry: dict[str, Any]) -> str:
    """Return the catalog agent a direct client entry launches, if any.

    Matching is by executable basename plus a catalog-argument prefix, so an
    operator who added their own flags after the ACP subcommand is still
    recognised. An unrecognised entry is never rewritten -- a foreign agent
    server stays exactly as the operator left it.
    """

    command = _entry_basename(str(entry.get("command", "")))
    if not command:
        return ""
    raw_args = entry.get("args")
    args = [str(value) for value in raw_args] if isinstance(raw_args, list) else []
    for agent, (catalog_command, catalog_args) in sorted(_AGENTS.items()):
        if command != _entry_basename(catalog_command):
            continue
        if list(catalog_args) == args[: len(catalog_args)]:
            return agent
    return ""


def _registry_entry_agent(entry_name: str) -> str:
    """Best-effort agent id for a client-registry entry name.

    Client registries name their entries themselves ("cursor", "claude-acp"),
    so this is a name match rather than an argv match. It is used only to say
    whether DefenseClaw has a native entry point that could replace it.
    """

    candidate = entry_name.strip().lower().removesuffix("-acp")
    return candidate if candidate in _AGENTS else ""


def _detect_acp_clients(data_dir: str | None = None) -> list[dict[str, Any]]:
    """Report every known client's ACP posture without changing anything.

    data_dir is the ACP runtime whose locks prove an alias; without it only
    the reserved entry is attributed to its pair. Any other entry launching
    the guard is still reported as guarded and is never offered for adoption.
    """

    findings: list[dict[str, Any]] = []
    for client in sorted(_CLIENTS):
        try:
            path = _client_path(client)
        except click.ClickException:
            continue
        record: dict[str, Any] = {
            "client": client,
            "config_path": str(path),
            "config_present": path.exists(),
            "guarded": [],
            "adoptable": [],
            "client_registry": [],
            "foreign": [],
        }
        if path.exists():
            try:
                document = _read_json_object(path)
            except click.ClickException as exc:
                record["error"] = str(exc)
                findings.append(record)
                continue
            servers = document.get("agent_servers")
            if isinstance(servers, dict):
                for name, entry in sorted(servers.items()):
                    if not isinstance(entry, dict):
                        continue
                    pair = _guarded_pair(entry, name, data_dir)
                    if pair is not None or _entry_is_guarded(entry):
                        record["guarded"].append({"entry": name, "agent": pair[1] if pair else ""})
                        continue
                    if agent := _agent_for_entry(entry):
                        record["adoptable"].append(
                            {"entry": name, "agent": agent, "command": str(entry.get("command", ""))}
                        )
                    elif str(entry.get("type", "")) == "registry" and not entry.get("command"):
                        # The client resolves and launches this agent from its
                        # own registry, so there is no argv for the guard to
                        # wrap. It is still an unmediated ACP path, and saying
                        # "foreign, left untouched" would understate that.
                        record["client_registry"].append(
                            {"entry": name, "agent": _registry_entry_agent(name)}
                        )
                    else:
                        record["foreign"].append({"entry": name})
        # Native agents installed on this host with no entry in this client.
        accounted = {item.get("agent") for item in (*record["adoptable"], *record["guarded"])}
        accounted |= {item.get("agent") for item in record["client_registry"]}
        record["installable"] = sorted(
            agent
            for agent, (command, _args) in _AGENTS.items()
            if agent not in accounted and shutil.which(command)
        )
        findings.append(record)
    return findings


@acp_cmd.command("detect")
@click.option("--json-output", "--json", "json_output", is_flag=True, help="Print the result as JSON.")
def detect_cmd(json_output: bool) -> None:
    """Report which ACP clients are guarded, unguarded, or unconfigured."""
    findings = _detect_acp_clients()
    if json_output:
        click.echo(json.dumps({"clients": findings}, indent=2, sort_keys=True))
        return
    for record in findings:
        ux.subhead(f"{record['client']} — {record['config_path']}")
        if error := record.get("error"):
            ux.warn(f"  unreadable: {error}")
            continue
        if not record["config_present"]:
            click.echo("  no client configuration yet")
        for item in record["guarded"]:
            click.echo(f"  guarded    {item['entry']}")
        for item in record["adoptable"]:
            ux.warn(f"  UNGUARDED  {item['entry']} → launches {item['agent']} directly")
        for item in record["client_registry"]:
            detail = f"  UNGUARDED  {item['entry']} → launched from the client's own registry"
            if item.get("agent"):
                detail += f"; replace with a guarded {item['agent']} entry"
            else:
                detail += "; DefenseClaw has no native entry point for it"
            ux.warn(detail)
        for item in record["foreign"]:
            click.echo(f"  foreign    {item['entry']} (left untouched)")
        if record["installable"]:
            click.echo(f"  installed but not configured here: {', '.join(record['installable'])}")
    if any(record["adoptable"] for record in findings):
        ux.subhead("Route the unguarded entries through DefenseClaw with: defenseclaw setup acp")


@acp_cmd.command("adopt")
@click.option("--client", type=click.Choice(sorted(_CLIENTS)), default=None, help="Limit to one client.")
@click.option(
    "--profile", default="default", show_default=True, help="ACP policy profile (acp.profiles) the guard enforces."
)
@click.option(
    "--guard-binary",
    default="defenseclaw-acp",
    show_default=True,
    help="DefenseClaw ACP guard executable the editor entry starts.",
)
@click.option("--activate", is_flag=True, help="Enable action mode; adoption otherwise observes only.")
@click.option(
    "--yes",
    "--non-interactive",
    "--accept-defaults",
    "assume_yes",
    is_flag=True,
    help="Adopt without the confirmation prompt (--non-interactive and --accept-defaults are aliases).",
)
@click.option("--json-output", "--json", "json_output", is_flag=True, help="Print the result as JSON.")
@click.pass_context
def adopt_cmd(
    ctx: click.Context,
    client: str | None,
    profile: str,
    guard_binary: str,
    activate: bool,
    assume_yes: bool,
    json_output: bool,
) -> None:
    """Find unguarded ACP agents and route them through DefenseClaw.

    Adoption reuses `acp setup` for every pair it finds, so the transactional
    write, executable resolution, digest pinning and contract lock are
    identical to configuring the pair by hand. It then points the entry the
    operator already had at the guard, keeping that entry's key and `env`, so
    the familiar picker entry stops reaching the agent unmediated instead of
    sitting beside a guarded duplicate as a silent bypass.
    """

    app = ctx.find_object(AppContext)
    data_dir = str(Path(app.cfg.data_dir).expanduser().resolve()) if app and app.cfg else None
    findings = [record for record in _detect_acp_clients(data_dir) if client is None or record["client"] == client]
    planned = [
        (record["client"], item["entry"], item["agent"], item["command"])
        for record in findings
        for item in record["adoptable"]
    ]
    # A client-registry entry has no argv to wrap, so the most adoption can do
    # is install a guarded entry beside it and report the remaining bypass.
    registry_pairs = [
        (record["client"], item["entry"], item["agent"])
        for record in findings
        for item in record["client_registry"]
        if item.get("agent")
    ]

    if not planned and not registry_pairs:
        if json_output:
            click.echo(json.dumps({"adopted": [], "guarded_beside_registry": []}, indent=2, sort_keys=True))
        else:
            ux.subhead("No unguarded ACP agents found. Nothing to adopt.")
        return

    if not json_output:
        for target_client, entry, agent, _command in planned:
            ux.echo(f"  take over  {target_client}: {entry} → guarded {agent}")
        for target_client, entry, agent in registry_pairs:
            click.echo(f"  add guard  {target_client}: guarded {agent} beside registry entry {entry}")
        mode = "action" if activate else "observe"
        ux.subhead(f"Mode: {mode}. Profile: {profile}.")
    if not assume_yes and not json_output and not click.confirm("Proceed?", default=True):
        raise click.Abort()

    def _invoke_setup(target_client: str, agent: str, agent_binary: str = "", entry_name: str | None = None) -> None:
        """Run `acp setup` for one pair without its output.

        Adoption owns the operator-facing summary, and with --json-output it
        must emit exactly one document; letting each reused setup call print
        its own would make the result unparseable.
        """

        with contextlib.redirect_stdout(io.StringIO()):
            ctx.invoke(
                setup_cmd,
                client=target_client,
                agent=agent,
                profile=profile,
                guard_binary=guard_binary,
                agent_binary=agent_binary,
                activate=activate,
                managed=False,
                runtime_data_dir=None,
                token_file=None,
                json_output=True,
                entry_name=entry_name,
            )

    adopted: list[dict[str, str]] = []
    for target_client, entry, agent, agent_binary in planned:
        _invoke_setup(target_client, agent, agent_binary, entry)
        adopted.append({"client": target_client, "entry": entry, "agent": agent})

    beside: list[dict[str, str]] = []
    for target_client, entry, agent in registry_pairs:
        _invoke_setup(target_client, agent)
        beside.append({"client": target_client, "registry_entry": entry, "agent": agent})

    if json_output:
        click.echo(json.dumps({"adopted": adopted, "guarded_beside_registry": beside}, indent=2, sort_keys=True))
        return
    for item in adopted:
        ux.ok(f"{item['client']}: {item['entry']} now launches DefenseClaw · {item['agent']}")
    for item in beside:
        ux.ok(f"{item['client']}: guarded {item['agent']} entry installed")
        ux.warn(
            f"  {item['client']} still has registry entry {item['registry_entry']}, which launches "
            f"{item['agent']} without the guard. Remove it in the client to close that bypass."
        )
