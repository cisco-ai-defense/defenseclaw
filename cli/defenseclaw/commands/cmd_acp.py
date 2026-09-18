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
import secrets
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
)

_SCHEMA_VERSION = "schema-v1.21.0"
_SCHEMA_SHA256 = "caf62ff962ada396878372ced11efb2c6764e59d90919a38583c319948931a42"
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
) -> Path:
    path = _contract_lock_path(data_dir, client, agent)
    document = {
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
    atomic_write_private_bytes(path, (json.dumps(document, indent=2, sort_keys=True) + "\n").encode())
    return path.resolve()


def _client_contract_snapshots(data_dir: str, client: str, agent: str) -> list[tuple[Path, tuple[bool, bytes]]]:
    paths = {_contract_lock_path(data_dir, client, agent)}
    paths.update(
        _contract_lock_path(data_dir, pair_client, pair_agent)
        for pair_client, pair_agent in _managed_pairs()
        if pair_client == client
    )
    return [(path, _snapshot(path)) for path in sorted(paths)]


def _refresh_client_contract_digests(data_dir: str, client: str, client_path: Path) -> None:
    """Atomically re-pin every DefenseClaw entry sharing one editor file."""
    digest = _sha256_file(str(client_path))
    for pair_client, pair_agent in sorted(_managed_pairs()):
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


def _set_client_entry(client: str, agent: str, command: str, args: list[str]) -> Path:
    path = _client_path(client)
    document = _read_json_object(path)
    servers = document.setdefault("agent_servers", {})
    if not isinstance(servers, dict):
        raise click.ClickException(f"agent_servers must be an object in {path}")
    entry: dict[str, Any] = {"command": command, "args": args, "env": {}}
    if client == "zed":
        entry["type"] = "custom"
    servers[_managed_name(agent)] = entry
    _write_json(path, document)
    return path


def _remove_client_entry(client: str, agent: str) -> Path:
    path = _client_path(client)
    document = _read_json_object(path)
    servers = document.get("agent_servers")
    if isinstance(servers, dict):
        servers.pop(_managed_name(agent), None)
    _write_json(path, document)
    return path


def _managed_pairs() -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for client in sorted(_CLIENTS):
        document = _read_json_object(_client_path(client))
        servers = document.get("agent_servers")
        if not isinstance(servers, dict):
            continue
        for agent in _AGENTS:
            if _managed_name(agent) in servers:
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
    document = _read_json_object(client_path)
    servers = document.get("agent_servers")
    entry = servers.get(_managed_name(agent)) if isinstance(servers, dict) else None
    if not isinstance(entry, dict):
        problems.append("managed editor entry is missing")
    lock_path = _contract_lock_path(data_dir, client, agent)
    if lock_path.is_symlink() or not lock_path.is_file():
        problems.append("contract lock is missing or unsafe")
        return problems
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
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
    if isinstance(lock_client, dict):
        locked_client_path = lock_client.get("config_path")
        client_digest = lock_client.get("config_sha256")
        if not isinstance(locked_client_path, str) or Path(locked_client_path).resolve() != client_path.resolve():
            problems.append("client configuration path does not match")
        elif not isinstance(client_digest, str) or client_digest != _sha256_file(str(client_path)):
            problems.append("client configuration digest has drifted")
    for key in ("agent", "guard"):
        item = lock.get(key)
        path_value = item.get("path") if isinstance(item, dict) else None
        digest = item.get("sha256") if isinstance(item, dict) else None
        if not isinstance(path_value, str) or not Path(path_value).is_file():
            problems.append(f"{key} executable is missing")
        elif digest != _sha256_file(path_value) and not (
            key == "guard"
            and isinstance(lock_guard, dict)
            and lock_guard.get("managed_custody") is True
            and _managed_guard_custody_is_trusted(path_value)
        ):
            problems.append(f"{key} executable digest has drifted")
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
    if isinstance(entry, dict):
        args = entry.get("args")
        if (
            entry.get("command") != (lock_guard.get("path") if isinstance(lock_guard, dict) else None)
            or not isinstance(args, list)
            or str(lock_path.resolve()) not in args
        ):
            problems.append("editor launch command does not match the lock")
    return problems


@click.group("acp")
def acp_cmd() -> None:
    """Inspect and configure the local Agent Client Protocol guard."""


@acp_cmd.command("catalog")
def catalog_cmd() -> None:
    """Print protocol and built-in integration inventory."""
    click.echo(json.dumps(_REGISTRY, indent=2, sort_keys=True))


@acp_cmd.command("setup")
@click.option("--client", type=click.Choice(sorted(_CLIENTS)), required=True)
@click.option("--agent", type=click.Choice(sorted(_AGENTS)), required=True)
@click.option("--profile", default="default", show_default=True)
@click.option("--guard-binary", default="defenseclaw-acp", show_default=True)
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
@click.option("--json-output", "json_output", is_flag=True)
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
) -> None:
    """Install a guarded agent entry into Zed or JetBrains."""
    if not app.cfg:
        raise click.ClickException("configuration is unavailable")
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
        for other_client, other_agent in _managed_pairs()
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
    token_candidate = (
        Path(data_dir) / "acp" / f"{client}-{agent}.token" if managed else Path(data_dir) / "acp" / ".token"
    )
    lock_candidate = _contract_lock_path(data_dir, client, agent)
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
        path = _set_client_entry(client, agent, guard, args)
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
                for other_client, other_agent in _managed_pairs()
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
    click.echo(
        json.dumps(result, sort_keys=True)
        if json_output
        else f"Configured {agent} through DefenseClaw in {client} ({mode}) at {path}"
    )


@acp_cmd.command("remove")
@click.option("--client", type=click.Choice(sorted(_CLIENTS)), required=True)
@click.option("--agent", type=click.Choice(sorted(_AGENTS)), required=True)
@click.option("--managed", is_flag=True, help="Remove only user-side enterprise enrollment files.")
@click.option("--runtime-data-dir", default=None, type=click.Path(file_okay=False, path_type=Path))
@pass_ctx
def remove_cmd(app: AppContext, client: str, agent: str, managed: bool, runtime_data_dir: Path | None) -> None:
    """Remove one DefenseClaw-owned editor entry without touching foreign agents."""
    if not app.cfg:
        raise click.ClickException("configuration is unavailable")
    path = _client_path(client)
    path_snapshot = _snapshot(path)
    data_dir = str((runtime_data_dir or Path(app.cfg.data_dir)).expanduser().resolve())
    if managed and app.cfg.deployment_mode != "managed_enterprise":
        raise click.ClickException("--managed requires deployment_mode: managed_enterprise")
    if not managed and runtime_data_dir:
        raise click.ClickException("--runtime-data-dir is a managed-enrollment option")
    lock_path = _contract_lock_path(data_dir, client, agent)
    lock_snapshots = _client_contract_snapshots(data_dir, client, agent)
    acp_snapshot = copy.deepcopy(app.cfg.acp)
    try:
        path = _remove_client_entry(client, agent)
        remaining = _managed_pairs()
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
    click.echo(f"Removed the DefenseClaw {agent} entry from {path}")


@acp_cmd.command("status")
@click.option("--runtime-data-dir", default=None, type=click.Path(file_okay=False, path_type=Path))
@pass_ctx
def status_cmd(app: AppContext, runtime_data_dir: Path | None) -> None:
    """Show configured ACP posture and editor paths."""
    if not app.cfg:
        raise click.ClickException("configuration is unavailable")
    data_dir = str((runtime_data_dir or Path(app.cfg.data_dir)).expanduser().resolve())
    bindings = {}
    for client, agent in sorted(_managed_pairs()):
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
    click.echo(
        json.dumps(
            {
                "enabled": app.cfg.acp.enabled,
                "mode": app.cfg.acp.mode,
                "default_profile": app.cfg.acp.default_profile,
                "clients": {name: str(_client_path(name)) for name in sorted(_CLIENTS)},
                "configured_clients": sorted(app.cfg.acp.clients),
                "configured_agents": sorted(app.cfg.acp.agents),
                "bindings": bindings,
            },
            indent=2,
            sort_keys=True,
        )
    )


@acp_cmd.command("verify")
@click.option("--client", type=click.Choice(sorted(_CLIENTS)), required=True)
@click.option("--agent", type=click.Choice(sorted(_AGENTS)), required=True)
@click.option("--runtime-data-dir", default=None, type=click.Path(file_okay=False, path_type=Path))
@pass_ctx
def verify_cmd(app: AppContext, client: str, agent: str, runtime_data_dir: Path | None) -> None:
    """Fail if a managed editor entry or executable digest has drifted."""
    if not app.cfg:
        raise click.ClickException("configuration is unavailable")
    data_dir = str((runtime_data_dir or Path(app.cfg.data_dir)).expanduser().resolve())
    problems = _verify_binding(data_dir, client, agent, app.cfg.acp)
    if problems:
        raise click.ClickException("ACP binding verification failed: " + "; ".join(problems))
    click.echo(f"Verified {client}/{agent}: editor entry and executable digests match")


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


def _guarded_entry_agent(entry_name: str) -> str:
    """Recover the agent id from a DefenseClaw-managed entry name."""

    for agent in sorted(_AGENTS):
        if entry_name == _managed_name(agent):
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


def _detect_acp_clients() -> list[dict[str, Any]]:
    """Report every known client's ACP posture without changing anything."""

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
                    if _entry_is_guarded(entry):
                        record["guarded"].append({"entry": name, "agent": _guarded_entry_agent(name)})
                        continue
                    if agent := _agent_for_entry(entry):
                        record["adoptable"].append({"entry": name, "agent": agent})
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


def _point_entry_at_guard(client: str, entry_name: str, guard: str, args: list[str]) -> None:
    """Route an existing client entry through the guard, in place.

    The entry keeps its key and its `env`, so the operator's own picker entry
    keeps working and simply stops reaching the agent unmediated. Leaving the
    direct entry behind instead would preserve a bypass that the guard cannot
    see, which is the opposite of taking over.
    """

    path = _client_path(client)
    document = _read_json_object(path)
    servers = document.get("agent_servers")
    if not isinstance(servers, dict):
        return
    entry = servers.get(entry_name)
    if not isinstance(entry, dict):
        return
    entry["command"] = guard
    entry["args"] = args
    if client == "zed":
        entry["type"] = "custom"
    servers[entry_name] = entry
    _write_json(path, document)


@acp_cmd.command("detect")
@click.option("--json-output", "json_output", is_flag=True)
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
@click.option("--profile", default="default", show_default=True)
@click.option("--guard-binary", default="defenseclaw-acp", show_default=True)
@click.option("--activate", is_flag=True, help="Enable action mode; adoption otherwise observes only.")
@click.option("--yes", "assume_yes", is_flag=True, help="Adopt without the confirmation prompt.")
@click.option("--json-output", "json_output", is_flag=True)
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

    findings = [record for record in _detect_acp_clients() if client is None or record["client"] == client]
    planned = [
        (record["client"], item["entry"], item["agent"])
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
        for target_client, entry, agent in planned:
            click.echo(f"  take over  {target_client}: {entry} → guarded {agent}")
        for target_client, entry, agent in registry_pairs:
            click.echo(f"  add guard  {target_client}: guarded {agent} beside registry entry {entry}")
        mode = "action" if activate else "observe"
        ux.subhead(f"Mode: {mode}. Profile: {profile}.")
    if not assume_yes and not json_output and not click.confirm("Proceed?", default=True):
        raise click.Abort()

    guard = _resolve_executable(guard_binary, "DefenseClaw ACP guard")

    def _invoke_setup(target_client: str, agent: str) -> None:
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
                agent_binary="",
                activate=activate,
                managed=False,
                runtime_data_dir=None,
                token_file=None,
                json_output=True,
            )

    adopted: list[dict[str, str]] = []
    for target_client, entry, agent in planned:
        _invoke_setup(target_client, agent)
        # Reuse the exact argv setup just wrote for the managed entry so the
        # adopted entry cannot drift from it.
        managed = _read_json_object(_client_path(target_client)).get("agent_servers", {})
        written = managed.get(_managed_name(agent)) if isinstance(managed, dict) else None
        if isinstance(written, dict) and entry != _managed_name(agent):
            args = [str(value) for value in written.get("args", [])]
            _point_entry_at_guard(target_client, entry, guard, args)
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
