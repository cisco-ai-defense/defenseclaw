# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Configure the DefenseClaw ACP guard and supported editor clients."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click

from defenseclaw import ux
from defenseclaw.acp_catalog import ACP_AGENT_ENTRY_POINTS, ACP_CLIENT_IDS, ACP_REGISTRY
from defenseclaw.config import ACPBinding, ACPProfile
from defenseclaw.connector_paths import _normalize_jsonc
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.enforce.asset_lists import is_secure_client
from defenseclaw.file_permissions import (
    atomic_write_private_bytes,
    atomic_write_text_secure,
    make_private_directory,
    protect_private_file,
    read_regular_file_no_follow,
    windows_guard_private_file_error,
)

_SCHEMA_VERSION = "schema-v1.21.0"
_SCHEMA_SHA256 = "caf62ff962ada396878372ced11efb2c6764e59d90919a38583c319948931a42"
# A contract lock whose client pin starts with this prefix pins the guarded
# entry, not the whole editor file (acp.EntryDigestPrefix; enterprise setup).
_ENTRY_DIGEST_PREFIX = "entry-sha256:"
_REGISTRY = ACP_REGISTRY
_CLIENTS = set(ACP_CLIENT_IDS)
_AGENTS = {agent_id: (command, list(args)) for agent_id, (command, args) in ACP_AGENT_ENTRY_POINTS.items()}


# The home of the account whose managed runtime an administrator checks
# (_runtime_owner_view), or None for this account's own home.
_RUNTIME_OWNER_HOME: Path | None = None


def _client_path(client: str) -> Path:
    owner_home = _RUNTIME_OWNER_HOME
    if client == "jetbrains":
        return (owner_home or Path.home()) / ".jetbrains" / "acp.json"
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise click.ClickException("APPDATA is required to configure Zed on Windows")
        return Path(appdata) / "Zed" / "settings.json"
    if owner_home is not None:
        return owner_home / ".config" / "zed" / "settings.json"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "zed" / "settings.json"


def _runtime_owner_uid(data_dir: str) -> int | None:
    """The account that owns <data_dir>/acp, when root checks another account's runtime (POSIX), else None."""
    if os.name == "nt" or os.geteuid() != 0:
        return None
    try:
        owner = (Path(data_dir).expanduser() / "acp").lstat().st_uid
    except OSError:
        return None
    return owner if owner != 0 else None


@contextlib.contextmanager
def _runtime_owner_view(data_dir: str):
    """Read a managed enrollment as the account it belongs to (GAP-2111).

    The administrator checks a user's managed enrollment with
    --runtime-data-dir. The editor settings file is that user's, under the
    home of the account that owns the runtime directory, not root's.
    """
    global _RUNTIME_OWNER_HOME
    owner = _runtime_owner_uid(data_dir)
    previous = _RUNTIME_OWNER_HOME
    if owner is not None:
        import pwd

        try:
            _RUNTIME_OWNER_HOME = Path(pwd.getpwuid(owner).pw_dir)
        except KeyError:
            pass
    try:
        yield
    finally:
        _RUNTIME_OWNER_HOME = previous


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


def _acp_dir_is_redirected(data_dir: str) -> bool:
    """Whether <data_dir>/acp exists but is a link, a reparse point or not a directory.

    Setup creates that directory itself, private to this account. A symlink
    or a Windows junction there sends the entry record, every lock and the
    token to another runtime's directory: that record proves nothing about
    this runtime's entries, and those files are not this runtime's to change
    or remove.
    """
    path = Path(data_dir).expanduser() / "acp"
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    reparse = getattr(info, "st_file_attributes", 0) & 0x400  # FILE_ATTRIBUTE_REPARSE_POINT
    return stat.S_ISLNK(info.st_mode) or bool(reparse) or not stat.S_ISDIR(info.st_mode)


def _acp_runtime_dir(data_dir: str) -> Path | None:
    """This runtime's own ACP directory (canonical), or None when there is none to trust.

    The data directory is resolved (it holds this runtime's config, so where
    it points is this runtime), but the acp directory under it must be a
    real directory, not a link to someone else's: the record of the entries
    DefenseClaw wrote, and the locks and tokens, are read only from there.
    """
    if not data_dir or _acp_dir_is_redirected(data_dir):
        return None
    path = Path(data_dir).expanduser().resolve() / "acp"
    return path if path.is_dir() else None


def _refuse_redirected_acp_dir(data_dir: str) -> None:
    if _acp_dir_is_redirected(data_dir):
        raise click.ClickException(
            f"ACP runtime directory {Path(data_dir) / 'acp'} is a link or not a directory; "
            "DefenseClaw will not write or remove ACP state through it. Move it aside and run the command again"
        )


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
    pin_entry: bool = False,
) -> Path:
    """Write the pair's contract lock.

    pin_entry: pin the pair's guarded entries (acp.EntryDigestPrefix): the
    entries that start the guard with this lock, under the reserved name, an
    adopted name or a numbered one, instead of the whole editor file, so a
    theme or agent-panel edit elsewhere in the file keeps the guard starting
    (GAP-0504).
    """
    path = _contract_lock_path(data_dir, client, agent)
    client_pin = _sha256_file(str(client_path))
    if pin_entry:
        entry_digest = _guard_entry_sha256(
            _read_json_object(client_path).get("agent_servers"), client, agent, path.resolve()
        )
        if entry_digest:
            client_pin = _ENTRY_DIGEST_PREFIX + entry_digest
    document: dict[str, Any] = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "protocol": {"schema_version": _SCHEMA_VERSION, "schema_sha256": _SCHEMA_SHA256},
        "client": {"id": client, "config_path": str(client_path), "config_sha256": client_pin},
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


def _lock_binds_editor(lock: dict[str, Any], client: str) -> bool:
    """Whether a lock was written for the editor settings file this client uses now.

    The editor file moves with XDG_CONFIG_HOME, APPDATA or HOME. A lock
    written for the old file names entries in that file, not in this one.
    """
    try:
        return Path(lock["client"]["config_path"]).resolve() == _client_path(client).resolve()
    except (KeyError, TypeError, OSError, ValueError, click.ClickException):
        return False


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
        pinned = lock_client.get("config_sha256")
        if isinstance(pinned, str) and pinned.startswith(_ENTRY_DIGEST_PREFIX) and _lock_binds_editor(document, client):
            # It pins only its own entry, which this change did not write:
            # re-pinning it here would seal another binding's edit (GAP-0513).
            continue
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


# --- DefenseClaw's record of the editor entries it wrote --------------------
#
# An editor entry is DefenseClaw's only when it carries the DefenseClaw marker
# (it starts the guard for its pair: --client and --agent before --) and its
# digest equals the digest DefenseClaw recorded when it wrote that entry,
# under that name and in that editor file, in this runtime's own record: a
# file in this runtime's acp directory that this account owns, no one else
# can read or change, and that is read without following links. Contract
# locks pin what the guard launches; they never prove who wrote an entry. Any
# change to an entry (its --gateway, profile, env, or the agent it starts)
# breaks the digest, and an entry DefenseClaw cannot prove is foreign: setup
# writes DefenseClaw's own entry next to it, removal leaves it exactly as it
# is, and verify reports it with the manual step. That includes an entry under
# the reserved name "DefenseClaw · <Agent>": releases through 1.0.3 wrote it
# without a record, so it can be anyone's.

_ENTRY_RECORD = "owned-entries.json"
_ENTRY_RECORD_LIMIT = 256 << 10
_ENTRY_RECORD_FIELDS = ("client", "agent", "config_path", "name", "sha256")

# (client, agent, editor file key, entry name) -> digest of the entry as written.
EntryRecords = dict[tuple[str, str, str, str], str]


# Keys an editor stores in an agent entry for choices made in its own UI, the
# same list as editorOwnedEntryKeys in internal/acp/contract.go. Zed keeps the
# mode or model picked in its agent panel there. That choice does not change
# what the entry launches, so it does not make DefenseClaw's own entry foreign.
_EDITOR_OWNED_ENTRY_KEYS = {
    "zed": frozenset({
        "default_mode", "default_model", "favorite_models", "default_config_options",
        "favorite_config_option_values",
    }),
}


def _entry_digest(entry: dict[str, Any], client: str) -> str:
    """The digest of an entry's JSON value, whatever the file's formatting or key order.

    The keys the editor owns for client are left out.
    """
    editor_owned = _EDITOR_OWNED_ENTRY_KEYS.get(client, frozenset())
    pinned = {key: value for key, value in entry.items() if key not in editor_owned}
    canonical = json.dumps(pinned, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# Characters Go's json.Marshal escapes inside strings and Python's json.dumps does not.
_GO_JSON_ESCAPES = (
    ("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"),
    ("\u2028", "\\u2028"), ("\u2029", "\\u2029"),
)


def _entry_starts_lock(entry: Any, lock_path: str | Path) -> bool:
    """Whether an editor entry starts the guard with the contract lock at lock_path (acp entryStartsLock)."""
    value = _guard_options(entry).get("--contract-lock") if isinstance(entry, dict) else None
    if not value:
        return False
    return os.path.normcase(os.path.abspath(value)) == os.path.normcase(os.path.abspath(str(lock_path)))


def _guard_entry_sha256(servers: Any, client: str, agent: str, lock_path: str | Path | None = None) -> str:
    """The digest the guard computes for the pair's entries (acp.ClientEntrySHA256), or "".

    The entries are those that start the guard with the lock at lock_path
    (an adopted or numbered entry too, GAP-0504); with none, the entry under
    the reserved name. One entry is pinned alone, several as one object by
    name. Go's json.Marshal: sorted keys, no spaces, and <, >, &, U+2028 and
    U+2029 escaped. The keys the editor owns for client are left out, as there.
    """
    if not isinstance(servers, dict):
        return ""
    editor_owned = _EDITOR_OWNED_ENTRY_KEYS.get(client, frozenset())

    def pinned(entry: Any) -> Any:
        if not isinstance(entry, dict):
            return entry
        return {key: value for key, value in entry.items() if key not in editor_owned}

    guarded = {
        name: pinned(entry)
        for name, entry in servers.items()
        if lock_path is not None and _entry_starts_lock(entry, lock_path)
    }
    if len(guarded) == 1:
        value: Any = next(iter(guarded.values()))
    elif guarded:
        value = guarded
    else:
        value = servers.get(_managed_name(agent))
        if value is None:
            return ""
        value = pinned(value)
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    for raw, escaped in _GO_JSON_ESCAPES:
        canonical = canonical.replace(raw, escaped)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _is_regular_no_follow(path_value: str) -> bool:
    """Whether path_value is itself a regular file: the guard lstats the pinned agent and refuses a link."""
    try:
        return stat.S_ISREG(os.lstat(path_value).st_mode)
    except OSError:
        return False


def _path_key(value: str | Path) -> str:
    return os.path.normcase(str(Path(value).expanduser().resolve()))


def _editor_key(client: str) -> str:
    """The key of the editor settings file this client uses now ("" when it has none)."""
    try:
        return _path_key(_client_path(client))
    except (OSError, ValueError, RuntimeError, click.ClickException):
        return ""


def _entry_record_path(data_dir: str) -> Path:
    return Path(data_dir) / "acp" / _ENTRY_RECORD


def _record_is_private(path: Path, info: os.stat_result) -> bool:
    """Whether the record is this account's own file, private to it.

    On POSIX it must be a regular file this account owns with no group or
    other permission bit. Root checking another account's managed runtime
    (--runtime-data-dir) accepts that account's own record in its own acp
    directory, where its enterprise setup writes it (GAP-2111). On Windows the check is the guard's private-file
    rule: no reparse point on the path, owned by this account, and a DACL
    that grants only this account, OWNER RIGHTS and SYSTEM.
    """
    if os.name == "nt":
        return windows_guard_private_file_error(path) is None
    owner = os.geteuid()
    if owner == 0:
        try:
            owner = path.parent.lstat().st_uid
        except OSError:
            return False
    return stat.S_ISREG(info.st_mode) and info.st_uid == owner and not stat.S_IMODE(info.st_mode) & 0o077


def _owned_entry_records(data_dir: str | None) -> EntryRecords:
    """The entries this runtime recorded writing, or nothing when the record proves nothing.

    A missing, linked, unreadable or malformed record, one that is not this
    account's private file, one written for another runtime directory, or a
    record behind a linked acp directory proves no entry.
    """
    runtime = _acp_runtime_dir(data_dir or "")
    if runtime is None:
        return {}
    path = runtime / _ENTRY_RECORD
    try:
        info = path.lstat()
        if not _record_is_private(path, info):
            return {}
        document = json.loads(read_regular_file_no_follow(path, max_bytes=_ENTRY_RECORD_LIMIT, expected_stat=info))
        if (
            not isinstance(document, dict)
            or type(document.get("version")) is not int
            or document["version"] != 1
            or not isinstance(document.get("runtime"), str)
            or _path_key(document["runtime"]) != _path_key(runtime.parent)
            or not isinstance(document.get("entries"), list)
        ):
            return {}
        records: EntryRecords = {}
        for item in document["entries"]:
            values = [item.get(key) if isinstance(item, dict) else None for key in _ENTRY_RECORD_FIELDS]
            if all(isinstance(value, str) and value for value in values):
                client, agent, config_path, name, digest = values
                records[(client, agent, _path_key(config_path), name)] = digest
        return records
    except (OSError, ValueError, RuntimeError):
        return {}


def _write_entry_records(data_dir: str, records: EntryRecords) -> None:
    """Replace this runtime's record of the entries it wrote; delete it when none are left."""
    path = _entry_record_path(data_dir)
    if not records:
        if path.is_file() and not path.is_symlink():
            path.unlink()
        return
    make_private_directory(path.parent)
    document = {
        "version": 1,
        "runtime": str(Path(data_dir).expanduser().resolve()),
        "entries": [dict(zip(_ENTRY_RECORD_FIELDS, (*key, digest))) for key, digest in sorted(records.items())],
    }
    atomic_write_private_bytes(path, (json.dumps(document, indent=2, sort_keys=True) + "\n").encode())


# The guard options setup writes, in every release since 1.0.0 and in the
# managed Go setup. The guard refuses a flag it does not know.
_GUARD_ENTRY_OPTIONS = frozenset(
    {"--agent", "--client", "--profile", "--mode", "--token-file", "--gateway", "--contract-lock"}
)


def _launches_locked_agent(entry: dict[str, Any], options: dict[str, str], lock: dict[str, Any], agent: str) -> bool:
    """Whether an entry's argv is the launch setup writes for this lock (verify only, never ownership).

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


def _carries_marker(entry: dict[str, Any], client: str, agent: str) -> bool:
    """The DefenseClaw marker: the entry starts the guard for this pair (--client and --agent before --)."""
    options = _guard_options(entry)
    return options.get("--client") == client and options.get("--agent") == agent


def _guarded_pair(entry: dict[str, Any], name: str, records: EntryRecords) -> tuple[str, str] | None:
    """The pair a DefenseClaw-written editor entry guards, or None.

    records is this runtime's record of the entries it wrote (_owned_entry_records).
    """
    options = _guard_options(entry)
    client, agent = options.get("--client", ""), options.get("--agent", "")
    if client not in _CLIENTS or agent not in _AGENTS:
        return None
    # Every entry, the reserved name included, is DefenseClaw's only while it
    # is exactly what this runtime recorded writing under that name in this
    # editor file. A reserved entry from 1.0.0-1.0.3 has no record: it is
    # foreign, and setup writes DefenseClaw's own entry next to it.
    digest = records.get((client, agent, _editor_key(client), name))
    return (client, agent) if digest is not None and digest == _entry_digest(entry, client) else None


def _pair_entry_names(servers: dict[str, Any], client: str, agent: str, records: EntryRecords) -> list[str]:
    """The pair's entries this runtime can prove it wrote, as they are now."""
    return [
        name for name, entry in servers.items()
        if isinstance(entry, dict) and _guarded_pair(entry, name, records) == (client, agent)
    ]


def _free_entry_name(servers: dict[str, Any], agent: str) -> str:
    """The reserved name for agent, or its first numbered variant no entry uses.

    An entry DefenseClaw cannot prove it wrote may hold the reserved name.
    DefenseClaw's own entry then goes next to it instead of replacing it.
    """
    name = _managed_name(agent)
    number = 2
    while name in servers:
        name = f"{_managed_name(agent)} ({number})"
        number += 1
    return name


# Why an entry of the pair is foreign (_left_pair_entries).
_CHANGED, _DIRECT, _UNRECORDED_GUARD, _RESERVED_NAME = "changed", "direct", "guard", "name"


def _pinned_agent_path(data_dir: str, client: str, agent: str) -> str:
    """The agent executable the pair's contract lock pins ("" without a usable lock)."""
    lock = _lock_document(_contract_lock_path(data_dir, client, agent), client, agent)
    path_value = lock["agent"].get("path") if lock else None
    return path_value if isinstance(path_value, str) else ""


# A Windows command shim (npm, pnpm and Volta write one per PATH name) starts
# the last file it quotes after %dp0% or %~dp0: npm's opencode.cmd ends in
# "%dp0%\node_modules\opencode-ai\bin\opencode.exe" %*. A shim for a node
# package first quotes the node.exe beside it (an IF EXIST check and the
# interpreter), then the package script it runs.
_SHIM_SUFFIXES = (".cmd", ".bat")
_SHIM_TARGET = re.compile(r'"%~?dp0%?[\\/]([^"\r\n]+)"', re.IGNORECASE)


def _shim_targets(path_value: str) -> list[str]:
    """The agent file a Windows command shim at path_value starts ([] for any other file).

    Only the last quoted file counts. An earlier one is the shared interpreter
    (node.exe beside npm's global shims on nvm-windows and fnm), and counting
    it would make every other node-based agent in that folder start the
    pinned agent.
    """
    if os.path.splitext(path_value)[1].lower() not in _SHIM_SUFFIXES:
        return []
    try:
        with open(path_value, "rb") as stream:
            text = stream.read(64 << 10).decode("utf-8", "replace")
    except OSError:
        return []
    base = os.path.dirname(os.path.abspath(path_value))
    quoted = _SHIM_TARGET.findall(text)
    if not quoted:
        return []
    candidate = os.path.normpath(os.path.join(base, quoted[-1].replace("\\", os.sep).replace("/", os.sep)))
    return [candidate] if os.path.isfile(candidate) else []


def _same_agent_file(candidate: str, pinned: str) -> bool:
    """Whether candidate is the pinned agent file or a byte-identical copy of it.

    A copy or a renamed copy of the agent executable starts the same agent. A
    shim is matched only as the same file: its bytes name a path relative to
    where it sits, so a copied shim starts something else.
    """
    try:
        if os.path.samefile(candidate, pinned):
            return True
        if os.path.splitext(pinned)[1].lower() in _SHIM_SUFFIXES or not os.path.isfile(candidate):
            return False
        size = os.path.getsize(pinned)
        if size == 0 or os.path.getsize(candidate) != size:
            return False
        return _sha256_file(candidate) == _sha256_file(pinned)
    except (OSError, ValueError):
        return False


def _entry_path_arguments(entry: dict[str, Any]) -> list[str]:
    """The arguments of an editor entry that name an existing file by an absolute or ~ path.

    An interpreter or a wrapper entry (node, node.exe, env) starts the file
    it is given: node <agent package script> runs the agent as its shim
    would. A relative argument depends on the editor's working folder and a
    bare name is not looked up on PATH by an interpreter, so neither counts.
    """
    args = entry.get("args")
    if not isinstance(args, list):
        return []
    paths: list[str] = []
    for arg in args:
        if not isinstance(arg, str) or not arg.strip():
            continue
        value = os.path.expanduser(arg)
        if os.path.isabs(value) and os.path.isfile(value):
            paths.append(value)
    return paths


def _launches_file(entry: dict[str, Any], path_value: str) -> bool:
    """Whether an editor entry's command starts the agent file at path_value.

    The editor resolves a bare command on PATH, so a PATH name, another
    spelling of the path, a link to the file or a copy of it all start it.
    When either side is a Windows command shim, the file the shim starts
    counts too: the lock pins npm's opencode.cmd on Windows, and an entry
    that starts the opencode.exe it wraps runs the same agent (GAP-0496).
    An argument that names the agent file, or the package script a pinned
    shim runs, starts it too: node <agent script> is the same launch as the
    agent's own shim or link (GAP-2487).
    """
    command = entry.get("command")
    if not path_value or not isinstance(command, str) or not command.strip():
        return False
    found = os.path.expanduser(command) if os.path.dirname(command) else shutil.which(command)
    launched = [found, *_shim_targets(found)] if found else []
    launched += _entry_path_arguments(entry)
    if not launched:
        return False
    pinned = [path_value, *_shim_targets(path_value)]
    return any(_same_agent_file(candidate, target) for candidate in launched for target in pinned)


def _left_pair_entries(
    servers: dict[str, Any], client: str, agent: str, records: EntryRecords, agent_path: str = ""
) -> list[tuple[str, str, bool]]:
    """The pair's foreign entries: entries DefenseClaw cannot prove it wrote as they are now.

    Each is (name, why, adoptable). why is _CHANGED (DefenseClaw recorded an
    entry with this name in this editor file and it has changed since:
    pointed back at the agent, edited, or a new file with an entry of that
    name), _DIRECT (it launches the agent without the guard), _UNRECORDED_GUARD
    (it starts a guard for the pair with no matching record, as releases
    through 1.0.3 wrote the reserved entry) or _RESERVED_NAME (it has the
    pair's reserved name and nothing else of DefenseClaw's). agent_path is the
    agent executable the pair's lock pins: an entry that starts that file
    without the guard is _DIRECT whatever its name, arguments or spelling of
    the path (GAP-0496). adoptable: it launches the catalog command, so acp
    adopt can route it through the guard.
    Setup writes DefenseClaw's own entry next to them, adoption and removal
    leave them, and verify reports them.
    """
    owned = set(_pair_entry_names(servers, client, agent, records))
    editor = _editor_key(client)
    recorded = {name for pair_client, pair_agent, key, name in records if (pair_client, pair_agent, key) == (
        client, agent, editor
    )}
    left: list[tuple[str, str, bool]] = []
    for name, value in sorted(servers.items()):
        if name in owned:
            continue
        entry = value if isinstance(value, dict) else {}
        unguarded = bool(entry) and not _entry_is_guarded(entry)
        adoptable = unguarded and _agent_for_entry(entry) == agent
        if name in recorded:
            why = _CHANGED
        elif adoptable or (unguarded and _launches_file(entry, agent_path)):
            why = _DIRECT
        elif _carries_marker(entry, client, agent):
            why = _UNRECORDED_GUARD
        elif name == _managed_name(agent):
            why = _RESERVED_NAME
        else:
            continue
        left.append((name, why, adoptable))
    return left


def _set_client_entry(
    client: str,
    agent: str,
    data_dir: str,
    command: str,
    args: list[str],
    entry_name: str | None = None,
) -> tuple[Path, dict[str, dict[str, Any]]]:
    """Write the pair's guard entries; return the file and each entry written, by name.

    Only entries DefenseClaw can prove it wrote are rewritten, plus the one
    entry an explicit adoption names. Any other entry, including one this
    pair adopted earlier that has changed since and a recordless one under
    the reserved name, is left as it is, and the pair's entry goes next to it.
    """
    path = _client_path(client)
    document = _read_json_object(path)
    servers = document.setdefault("agent_servers", {})
    if not isinstance(servers, dict):
        raise click.ClickException(f"agent_servers must be an object in {path}")
    names = _pair_entry_names(servers, client, agent, _owned_entry_records(data_dir))
    if entry_name is not None:
        adopted = servers.get(entry_name)
        if not isinstance(adopted, dict) or _agent_for_entry(adopted) != agent:
            raise click.ClickException(f"ACP entry {entry_name!r} changed before adoption; run the same command again")
        names.append(entry_name)
    aliases = [name for name in names if name != _managed_name(agent)]
    if aliases and _managed_name(agent) in names:
        # DefenseClaw's own reserved entry gives way to the alias that replaces it.
        del servers[_managed_name(agent)]
    written = aliases or names or [_free_entry_name(servers, agent)]
    for name in written:
        entry = dict(servers.get(name) or {})
        entry.update(command=command, args=args)
        entry.setdefault("env", {})
        if client == "zed":
            entry["type"] = "custom"
        servers[name] = entry
    _write_json(path, document)
    return path, {name: servers[name] for name in written}


def _has_client_entry(client: str, agent: str, data_dir: str) -> bool:
    servers = _read_json_object(_client_path(client)).get("agent_servers")
    return isinstance(servers, dict) and bool(
        _pair_entry_names(servers, client, agent, _owned_entry_records(data_dir))
    )


def _left_entries(client: str, agent: str, data_dir: str) -> list[tuple[str, bool, bool]]:
    """_left_pair_entries for the pair's current editor file."""
    servers = _read_json_object(_client_path(client)).get("agent_servers")
    if not isinstance(servers, dict):
        return []
    return _left_pair_entries(
        servers, client, agent, _owned_entry_records(data_dir), _pinned_agent_path(data_dir, client, agent)
    )


def _warn_redirected_acp_dir(redirected: bool, data_dir: str) -> None:
    if redirected:
        ux.warn(
            f"Left {Path(data_dir) / 'acp'}: it is a link or not a directory, so the contract locks "
            "and tokens it reaches are not this runtime's to remove.",
            indent="",
        )


def _left_reason(why: str, client: str, agent: str) -> str:
    return {
        _CHANGED: "DefenseClaw wrote an entry with this name, but it has changed since",
        _DIRECT: f"it launches {agent} without the DefenseClaw guard",
        _UNRECORDED_GUARD: (
            f"it starts a guard for {client}/{agent}, but DefenseClaw has no record that it wrote it as it is"
        ),
        _RESERVED_NAME: f"it has DefenseClaw's name for {agent}, but DefenseClaw has no record that it wrote it",
    }[why]


def _warn_left_entries(
    left: list[tuple[str, str, bool]], path: Path, client: str, agent: str, *, own: list[str] | None
) -> None:
    """Name each foreign entry DefenseClaw left unchanged, and the manual step for it.

    own is the pair's entries setup or adoption just wrote, or None on removal.
    Setup and adoption warn on stderr, so --json output stays one document.
    """
    removing = own is None
    for name, why, adoptable in left:
        reason = _left_reason(why, client, agent)
        if removing:
            step = "Delete it there if you no longer use it."
        elif adoptable:
            step = f"To route it through the guard, run: defenseclaw acp adopt --client {client}"
        else:
            step = f"Delete it there if you no longer use it; DefenseClaw's own entry is {', '.join(map(repr, own))}."
        message = f"Left editor entry {name!r} in {path}: {reason}, so DefenseClaw did not change it. {step}"
        if removing:
            ux.warn(message, indent="")
        else:
            ux.echo(f"  ⚠ {message}", err=True)


def _remove_client_entry(client: str, agent: str, records: EntryRecords) -> Path:
    path = _client_path(client)
    document = _read_json_object(path)
    servers = document.get("agent_servers")
    if not isinstance(servers, dict):
        return path
    names = _pair_entry_names(servers, client, agent, records)
    if not names:
        # Nothing here is this runtime's: leave the operator's file byte for byte.
        return path
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
    records = _owned_entry_records(data_dir)
    for client in sorted(_CLIENTS):
        document = _read_json_object(_client_path(client))
        servers = document.get("agent_servers")
        if not isinstance(servers, dict):
            continue
        for agent in _AGENTS:
            if _pair_entry_names(servers, client, agent, records):
                pairs.add((client, agent))
    return pairs


def _lock_pairs(data_dir: str) -> set[tuple[str, str]]:
    """Pairs with a contract lock in this runtime's own acp directory.

    Locks reached through a linked acp directory are another runtime's.
    """
    if _acp_dir_is_redirected(data_dir):
        return set()
    return {
        (client, agent)
        for client in _CLIENTS
        for agent in _AGENTS
        if (lock := _contract_lock_path(data_dir, client, agent)).is_symlink() or lock.exists()
    }


def _binding_pairs(cfg: Any, data_dir: str) -> set[tuple[str, str]]:
    """Every pair bound here: editor entries, contract locks and configured bindings.

    An adopted entry pointed back at the agent no longer looks like a guard
    entry, so reading the editor files alone dropped the binding from status
    and verify exactly when it was bypassed. Its lock and its configured
    binding remain. A managed host's central bindings name pairs for every
    user, so only this user's locks count there.
    """
    pairs = _managed_pairs(data_dir) | _lock_pairs(data_dir)
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


# The contract lock as the guard decodes it (acp.RuntimeContractLock, with
# DisallowUnknownFields): each section's keys and the type each value must have.
_LOCK_SCHEMA: dict[str, Any] = {
    "version": int, "generated_at": str, "profile": str, "mode": str,
    "protocol": {"schema_version": str, "schema_sha256": str},
    "client": {"id": str, "config_path": str, "config_sha256": str},
    "agent": {"id": str, "path": str, "sha256": str, "version": str},
    "guard": {"path": str, "sha256": str, "managed_custody": bool},
}


def _lock_shape_problem(value: Any, schema: dict[str, Any], where: str) -> str:
    """The first key or type the guard's decoder refuses, or ""."""
    if not isinstance(value, dict):
        return f"{where or 'the lock'} is not an object"
    for key, item in value.items():
        expected = schema.get(key)
        name = f"{where}.{key}" if where else key
        if expected is None:
            return f"unknown key {name!r}"
        if isinstance(expected, dict):
            problem = _lock_shape_problem(item, expected, name)
            if problem:
                return problem
        elif item is not None and (type(item) is not expected):
            return f"{name!r} is not a {expected.__name__}"
    return ""


def _lock_file_problems(lock: dict[str, Any], info: os.stat_result) -> list[str]:
    """What the guard refuses in the lock file itself before it checks any pin (GAP-2071).

    The guard starts only a private lock (no group or other access on POSIX)
    of at most 64 KiB that decodes into its lock type with no unknown key and
    no value of another type, and it compares the running guard's resolved
    path with the pinned one, so a pinned guard path that is a link never
    starts. A user who copied ~/.defenseclaw with cp -r under umask 022 got
    "Verified" while the editor could not start the agent.
    """
    problems: list[str] = []
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        problems.append("contract lock permissions are too broad (the guard starts only a private lock)")
    if info.st_size > 64 << 10:
        problems.append("contract lock is larger than the guard reads")
    shape = _lock_shape_problem(lock, _LOCK_SCHEMA, "")
    if shape:
        problems.append(f"contract lock is malformed for the guard: {shape}")
    guard = lock.get("guard")
    guard_path = guard.get("path") if isinstance(guard, dict) else None
    if (
        os.name != "nt"
        and isinstance(guard_path, str)
        and guard.get("managed_custody") is not True
        and os.path.realpath(guard_path) != os.path.abspath(guard_path)
    ):
        problems.append("guard executable path is a link; the guard starts only from the path setup pinned")
    return problems


def _verify_binding(
    data_dir: str,
    client: str,
    agent: str,
    acp_config: Any | None = None,
    gateway_url: str | None = None,
) -> list[str]:
    """Check one binding's editor entry, contract lock and pinned policy.

    acp_config is optional so callers without configuration loaded keep the
    previous file-only checks. gateway_url is the evaluation endpoint setup
    writes (_expected_gateway); each entry must send verdicts there.
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
    records = _owned_entry_records(data_dir)
    editor = _editor_key(client)
    names = _pair_entry_names(servers, client, agent, records) if isinstance(servers, dict) else []
    if not names:
        problems.append("managed editor entry is missing")
    if settings_usable:
        # A foreign entry of the pair never makes the binding healthy: one that
        # DefenseClaw wrote and that changed since, one that launches the agent
        # without the guard, or a recordless guard entry under any name. Each
        # problem names its manual step.
        left = _left_pair_entries(
            servers, client, agent, records, _pinned_agent_path(data_dir, client, agent)
        ) if isinstance(servers, dict) else []
        problems.extend(_foreign_entry_problem(item, client, agent, client_path) for item in left)
        # An entry this pair adopted that is gone from the file.
        problems.extend(
            f"adopted editor entry {name!r} no longer launches the DefenseClaw guard as DefenseClaw set it up"
            for pair_client, pair_agent, key, name in sorted(records)
            if (pair_client, pair_agent, key) == (client, agent, editor)
            and name != _managed_name(agent)
            and name not in names
            and name not in {item[0] for item in left}
        )
    lock_path = _contract_lock_path(data_dir, client, agent)
    if lock_path.is_symlink() or not lock_path.is_file() or _acp_runtime_dir(data_dir) is None:
        problems.append("contract lock is missing or unsafe")
        return problems
    try:
        lock_info = lock_path.stat()
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        problems.append("contract lock is unreadable")
        return problems
    if not isinstance(lock, dict):
        problems.append("contract lock is not an object")
        return problems
    problems.extend(_lock_file_problems(lock, lock_info))
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
    # The guard starts only a version 1 lock for this protocol schema (GAP-0879).
    version = lock.get("version")
    if (
        type(version) is not int
        or version != 1
        or lock.get("protocol") != {"schema_version": _SCHEMA_VERSION, "schema_sha256": _SCHEMA_SHA256}
    ):
        problems.append("contract lock version or protocol pins are not the ones the guard starts with")
    same_editor = isinstance(lock_client, dict) and _lock_binds_editor(lock, client)
    if isinstance(lock_client, dict):
        client_digest = lock_client.get("config_sha256")
        if not same_editor:
            problems.append("client configuration path does not match")
        elif settings_usable and isinstance(client_digest, str) and client_digest.startswith(_ENTRY_DIGEST_PREFIX):
            # The lock pins the guarded entries, checked as the guard checks them (GAP-0912, GAP-0504).
            pinned_digest = client_digest[len(_ENTRY_DIGEST_PREFIX):].lower()
            if pinned_digest != _guard_entry_sha256(servers, client, agent, lock_path.resolve()):
                problems.append(
                    _pinned_entry_problem(servers, names, client, agent, lock_path.resolve(), pinned_digest)
                )
        elif settings_usable and (not isinstance(client_digest, str) or client_digest != _client_digest(client_path)):
            problems.append("client configuration digest has drifted")
    for key in ("agent", "guard"):
        item = lock.get(key)
        path_value = item.get("path") if isinstance(item, dict) else None
        digest = item.get("sha256") if isinstance(item, dict) else None
        if not isinstance(path_value, str) or not Path(path_value).is_file():
            problems.append(f"{key} executable is missing")
        elif key == "agent" and not _is_regular_no_follow(path_value):
            # The guard lstats the pinned agent and refuses a link (GAP-0911).
            problems.append("agent executable is a link or not a regular file; the guard starts only the pinned file")
        elif digest != _sha256_file(path_value) and not (
            key == "guard"
            and isinstance(lock_guard, dict)
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
            entry.get("command") != (lock_guard.get("path") if isinstance(lock_guard, dict) else None)
            or not isinstance(args, list)
            or not options
            or not isinstance(lock_agent, dict)
            or not _launches_locked_agent(entry, options, lock, agent)
            or any(options.get(flag) != expected for flag, expected in {
                "--client": client, "--agent": agent,
                "--contract-lock": str(lock_path.resolve()),
                "--token-file": str(Path(data_dir).expanduser().resolve() / "acp" / (
                    f"{client}-{agent}.token" if isinstance(lock_guard, dict) and lock_guard.get("managed_custody")
                    else ".token"
                )),
            }.items())
        ):
            problems.append(f"editor launch command does not match the lock: {name}")
        if gateway_url is not None and options.get("--gateway") != gateway_url:
            problems.append(
                f"editor entry {name!r} does not send verdicts to this gateway ({gateway_url}); re-run acp setup"
            )
    return problems


def _pinned_entry_problem(
    servers: dict[str, Any], names: list[str], client: str, agent: str, lock_path: Path, pinned_digest: str
) -> str:
    """Why the entries the contract lock pins no longer match it, naming the entries themselves (GAP-0043).

    The guard pins the entries that start it with this lock (an adopted or
    numbered entry has its own name), so the message names those, not the
    reserved name. When the entries setup wrote are unchanged and only an
    entry it did not write starts the guard with the lock, it says so.
    """
    guarded = [name for name, entry in sorted(servers.items()) if _entry_starts_lock(entry, lock_path)]
    added = [name for name in guarded if name not in names]
    if added and len(added) < len(guarded) and _guard_entry_sha256(
        {name: entry for name, entry in servers.items() if name not in added}, client, agent, lock_path
    ) == pinned_digest:
        listed = ", ".join(repr(name) for name in added)
        return (
            f"editor {'entry' if len(added) == 1 else 'entries'} {listed} "
            f"{'starts' if len(added) == 1 else 'start'} the guard with this pair's contract lock, "
            "which pins only the entries setup wrote, so the guard refuses to start"
        )
    changed = [name for name in guarded if name in names] or guarded or [_managed_name(agent)]
    listed = ", ".join(repr(name) for name in changed)
    return (
        f"the {listed} {'entry' if len(changed) == 1 else 'entries'} changed after setup "
        f"(the contract lock pins {'it' if len(changed) == 1 else 'them'})"
    )


def _foreign_entry_problem(item: tuple[str, str, bool], client: str, agent: str, path: Path) -> str:
    """The verify problem for one foreign entry of the pair (_left_pair_entries), with its manual step."""
    name, why, adoptable = item
    if adoptable:
        step = f"route it through the guard with: defenseclaw acp adopt --client {client}, or delete it in {path}"
    else:
        step = f"DefenseClaw leaves it as it is; delete it in {path} if you no longer use it"
    if why == _CHANGED and name != _managed_name(agent):
        return (
            f"adopted editor entry {name!r} no longer launches the DefenseClaw guard as DefenseClaw set it up; {step}"
        )
    if why == _CHANGED:
        return f"editor entry {name!r} changed after DefenseClaw wrote it; {step}"
    return f"editor entry {name!r} is not DefenseClaw's: {_left_reason(why, client, agent)}; {step}"


def _gateway_url(cfg: Any) -> str:
    """The loopback evaluation endpoint setup writes into every entry."""
    return f"http://127.0.0.1:{cfg.gateway.api_port}/api/v1/acp/evaluate"


def _expected_gateway(cfg: Any) -> str | None:
    """The endpoint verify expects in each entry, or None when it cannot know it.

    A managed host's enrollment names the enterprise gateway, which this
    configuration may not describe, so only standalone entries are compared.
    """
    if str(getattr(cfg, "deployment_mode", "") or "") == "managed_enterprise":
        return None
    port = getattr(getattr(cfg, "gateway", None), "api_port", None)
    return _gateway_url(cfg) if port else None


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
    _refuse_redirected_acp_dir(data_dir)
    # Read before setup replaces the pair's record: an adopted entry that
    # changed since is named as such. An explicit adoption takes its entry.
    left = [item for item in _left_entries(client, agent, data_dir) if item[0] != entry_name]
    token_candidate = (
        Path(data_dir) / "acp" / f"{client}-{agent}.token" if managed else Path(data_dir) / "acp" / ".token"
    )
    lock_candidate = _contract_lock_path(data_dir, client, agent)
    record_path = _entry_record_path(data_dir)
    client_snapshot = _snapshot(client_path)
    token_snapshot = _snapshot(token_candidate)
    record_snapshot = _snapshot(record_path)
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
        _gateway_url(app.cfg),
        "--contract-lock",
        str(lock_candidate.resolve()),
        "--",
        agent_executable,
        *catalog_args,
    ]
    try:
        _progress(show, f"Writing the DefenseClaw {agent} entry to {client_path}...")
        path, written = _set_client_entry(client, agent, data_dir, guard, args, entry_name)
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
            pin_entry=not is_secure_client(app.cfg),
        )
        _refresh_client_contract_digests(data_dir, client, path)
        # Record what was written, so this runtime can later prove these
        # entries are its own. The pair's earlier records are replaced.
        records = {key: digest for key, digest in _owned_entry_records(data_dir).items() if key[:2] != (client, agent)}
        editor = _path_key(path)
        records.update(
            {(client, agent, editor, name): _entry_digest(entry, client) for name, entry in written.items()}
        )
        _write_entry_records(data_dir, records)
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
            (record_path, record_snapshot),
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
    _warn_left_entries(left, path, client, agent, own=sorted(written))
    # A profile setup created is named, so a typo in --profile shows (GAP-1589).
    created = f", new profile {profile}" if existing_profile is None and not managed else ""
    click.echo(
        json.dumps(result, sort_keys=True)
        if json_output
        else f"Configured {agent} through DefenseClaw in {client} ({mode}{created}) at {path}"
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
    left = _left_entries(client, agent, data_dir)
    path_snapshot = _snapshot(path)
    if managed and app.cfg.deployment_mode != "managed_enterprise":
        raise click.ClickException("--managed requires deployment_mode: managed_enterprise")
    if not managed and runtime_data_dir:
        raise click.ClickException("--runtime-data-dir is a managed-enrollment option")
    lock_path = _contract_lock_path(data_dir, client, agent)
    # A linked acp directory holds another runtime's locks: remove neither
    # reads, rewrites nor deletes them, and says so.
    redirected = _acp_dir_is_redirected(data_dir)
    records = _owned_entry_records(data_dir)
    record_path = _entry_record_path(data_dir)
    lock_snapshots = [] if redirected else [
        *_client_contract_snapshots(data_dir, client, agent),
        (record_path, _snapshot(record_path)),
    ]
    remaining_records = {key: digest for key, digest in records.items() if key[:2] != (client, agent)}
    had_lock = not redirected and lock_path.exists()
    had_entry = _has_client_entry(client, agent, data_dir)
    had_policy = not managed and app.cfg.acp.binding_key(client, agent) in app.cfg.acp.bindings
    if not (had_entry or had_policy or had_lock or remaining_records != records):
        click.echo(f"Nothing to remove: no DefenseClaw {agent} entry is configured for {client} ({path})")
        _warn_left_entries(left, path, client, agent, own=None)
        _warn_redirected_acp_dir(redirected, data_dir)
        return
    acp_snapshot = copy.deepcopy(app.cfg.acp)
    try:
        _progress(True, f"Removing the DefenseClaw {agent} entry from {path}...")
        path = _remove_client_entry(client, agent, records)
        remaining = _binding_pairs(app.cfg, data_dir) - {(client, agent)}
        if not managed:
            # The pair's own policy goes with the pair. The client and agent
            # pins survive while any other pair still uses that half.
            app.cfg.acp.bindings.pop(app.cfg.acp.binding_key(client, agent), None)
            if not any(pair_client == client for pair_client, _ in remaining):
                app.cfg.acp.clients.pop(client, None)
            if not any(pair_agent == agent for _, pair_agent in remaining):
                app.cfg.acp.agents.pop(agent, None)
        if had_lock and lock_path.exists():
            lock_path.unlink()
        if not redirected:
            _refresh_client_contract_digests(data_dir, client, path)
            if remaining_records != records:
                _write_entry_records(data_dir, remaining_records)
        if not managed:
            active_clients = set(app.cfg.acp.clients)
            active_agents = set(app.cfg.acp.agents)
            served = {
                name for name, value in app.cfg.acp.profiles.items() if value.allowed_clients or value.allowed_agents
            }
            for profile_name, profile_value in app.cfg.acp.profiles.items():
                profile_value.allowed_clients = [
                    value for value in profile_value.allowed_clients if value in active_clients
                ]
                profile_value.allowed_agents = [
                    value for value in profile_value.allowed_agents if value in active_agents
                ]
            app.cfg.acp.enabled = bool(active_clients and active_agents)
            # Remove takes out the profiles setup wrote for the pairs it
            # removed (GAP-1589): one that allowed a pair, now allows none,
            # names no denied method and no remaining pair uses. While ACP
            # stays on, the default profile stays (default_profile names it).
            in_use = {app.cfg.acp.profile_for_pair(pair_client, pair_agent) for pair_client, pair_agent in remaining}
            for profile_name in sorted(served):
                profile_value = app.cfg.acp.profiles[profile_name]
                if (
                    profile_value.allowed_clients
                    or profile_value.allowed_agents
                    or profile_value.denied_methods
                    or profile_name in in_use
                    or (app.cfg.acp.enabled and profile_name == app.cfg.acp.default_profile)
                ):
                    continue
                del app.cfg.acp.profiles[profile_name]
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
    _warn_left_entries(left, path, client, agent, own=None)
    _warn_redirected_acp_dir(redirected, data_dir)
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
    with _runtime_owner_view(data_dir) if runtime_data_dir else contextlib.nullcontext():
        _status(app, data_dir, json_output)


def _status(app: AppContext, data_dir: str, json_output: bool) -> None:
    bindings = {}
    for client, agent in sorted(_binding_pairs(app.cfg, data_dir)):
        problems = _verify_binding(data_dir, client, agent, app.cfg.acp, _expected_gateway(app.cfg))
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
    with _runtime_owner_view(data_dir) if runtime_data_dir else contextlib.nullcontext():
        _verify(app, client, agent, data_dir)


def _verify(app: AppContext, client: str | None, agent: str | None, data_dir: str) -> None:
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
        problems = _verify_binding(data_dir, pair_client, pair_agent, app.cfg.acp, _expected_gateway(app.cfg))
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
    if cfg.deployment_mode == "managed_enterprise" and not is_secure_client(cfg):
        return _enterprise_setup_command(cfg, client, agent, profile, mode != "observe", data_dir, lock)
    if cfg.deployment_mode == "managed_enterprise":
        command.extend(["--managed", "--runtime-data-dir", data_dir])
    if os.name == "nt":
        return "defenseclaw " + " ".join("'" + value.replace("'", "''") + "'" for value in command[1:])
    return shlex.join(command)


def _enterprise_setup_command(
    cfg: Any, client: str, agent: str, profile: str, activate: bool, data_dir: str, lock: dict[str, Any] | None
) -> str:
    """The user's setup step on a managed standalone host: the gateway's own `enterprise acp setup`.

    That host has no per-user `defenseclaw acp setup` (the per-user CLI
    refuses to run there), so verify named a command the user cannot run.
    This is the command the enrollment reports and the guard prints. The
    installed guard sits next to the gateway.
    """
    item = lock.get("guard") if lock else None
    guard = item.get("path") if isinstance(item, dict) else None
    if isinstance(guard, str) and Path(guard).is_absolute():
        gateway = str(Path(guard).with_name("defenseclaw-gateway" + Path(guard).suffix))
    else:
        guard, gateway = "defenseclaw-acp", "defenseclaw-gateway"
    command = [gateway, "enterprise", "acp", "setup", "--client", client, "--agent", agent, "--profile", profile]
    if activate:
        command.append("--activate")
    port = getattr(getattr(cfg, "gateway", None), "api_port", None) or 18970
    command.extend(["--data-dir", data_dir, "--api-port", str(port), "--guard-binary", guard])
    if os.name == "nt":
        return "& " + " ".join("'" + value.replace("'", "''") + "'" for value in command)
    return shlex.join(command)


def refresh_guard_pins(
    data_dir: str,
    *,
    from_sha256: str = "",
    guard_path: str = "",
    apply: bool = True,
) -> list[str]:
    """Re-pin DefenseClaw's own ACP guard in its contract locks.

    Touches only this runtime's own locks (``_lock_pairs``), never an editor
    entry and never a managed-custody lock, and only the guard digest and
    protocol schema: a changed agent binary still needs ``acp setup``. A lock
    is not proof of who wrote an entry, but it is this runtime's file, and
    re-pinning it keeps an entry from 1.0.0-1.0.3 starting after an upgrade
    (fail closed until then). Verify still reports that recordless entry
    until setup writes DefenseClaw's own. ``from_sha256``
    limits it to locks that pinned that guard digest; ``guard_path`` to
    locks whose guard is that file. With ``apply=False`` nothing is written.
    Returns the ``client/agent`` pairs re-pinned (or that would be).
    """
    if _acp_dir_is_redirected(data_dir):
        # Locks behind a linked acp directory are another runtime's.
        return []
    protocol = {"schema_version": _SCHEMA_VERSION, "schema_sha256": _SCHEMA_SHA256}
    only_path = os.path.normcase(str(Path(guard_path).expanduser().resolve())) if guard_path else ""
    repinned: list[str] = []
    for client, agent in sorted(_lock_pairs(data_dir)):
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

    data_dir is the ACP runtime whose record proves an entry; without it no
    entry is attributed to its pair. Any other entry launching the guard is
    still reported as guarded and is never offered for adoption.
    """

    records = _owned_entry_records(data_dir)
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
                    pair = _guarded_pair(entry, name, records)
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
