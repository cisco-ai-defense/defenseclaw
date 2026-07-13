"""Connector-scoped fail-mode resolution and transactional runtime refresh."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defenseclaw import config as config_module
from defenseclaw.connector_paths import connector_config_files, normalize

_VALID_MODES = frozenset({"open", "closed"})
_MAX_RUNTIME_FILE = 2 * 1024 * 1024
_MAX_DIGEST_FILE = 128 * 1024 * 1024
_FAIL_MODE_PATTERN = re.compile(r"FAIL_MODE=\"\$\{DEFENSECLAW_FAIL_MODE:-(open|closed)\}\"")
_EXPECTED_CONTRACT = {
    "claudecode": "claudecode-hooks-v1",
    "codex": "codex-hooks-v1",
}
_SHARED_HOOK_SCRIPTS = frozenset(
    {
        "inspect-tool.sh",
        "inspect-request.sh",
        "inspect-response.sh",
        "inspect-tool-response.sh",
        "_hardening.sh",
    }
)
_LEGACY_SHARED_HOOK_SCRIPTS = _SHARED_HOOK_SCRIPTS - {"_hardening.sh"}


def _is_windows() -> bool:
    return os.name == "nt"


def normalize_fail_mode(value: object, *, default: str = "closed") -> str:
    raw = str(value or "").strip().lower()
    return raw if raw in _VALID_MODES else default


@dataclass(frozen=True)
class ConnectorFailModeState:
    connector: str
    desired: str
    configured: str
    runtime: str | None
    sources: tuple[tuple[str, str | None], ...]
    drift: tuple[str, ...]

    @property
    def current(self) -> bool:
        return not self.drift and self.runtime == self.desired


def resolve_connector_fail_mode(cfg: Any, connector: str) -> ConnectorFailModeState:
    """Resolve desired, installed, and effective runtime fail mode for one connector."""

    name = normalize(connector)
    guardrail = cfg.guardrail
    entry = guardrail._connector_override(name) if hasattr(guardrail, "_connector_override") else None
    if entry is None:
        configured_entries = getattr(guardrail, "connectors", {}) or {}
        entry = configured_entries.get(name)
    raw = getattr(entry, "hook_fail_mode", "") if entry is not None else ""
    configured = normalize_fail_mode(raw or getattr(guardrail, "hook_fail_mode", ""))
    resolver = getattr(guardrail, "effective_hook_fail_mode", None)
    desired = normalize_fail_mode(resolver(name) if callable(resolver) else configured)
    sources: list[tuple[str, str | None]] = [("config", configured)]
    drift: list[str] = []

    runtime_source = _platform_runtime_source(cfg, name)
    sources.append(runtime_source)
    runtime = runtime_source[1]
    if runtime_source[0].endswith("-legacy"):
        drift.append("windows-sidecar-legacy")
    process_env = str(os.environ.get("DEFENSECLAW_FAIL_MODE", "")).strip().lower()
    if process_env in _VALID_MODES:
        sources.append(("process-env", process_env))
        runtime = process_env

    if name == "claudecode":
        claude_env, registered = _claude_registration_state()
        sources.append(("claude-env", claude_env))
        if claude_env is not None:
            runtime = claude_env
        if not registered:
            drift.append("registration-missing")
    elif name == "codex" and not _codex_registration_current():
        drift.append("registration-missing")

    lock_mode, lock_drift = _registration_lock_state(cfg, name)
    sources.append(("registration-lock", lock_mode))
    if lock_mode != desired:
        drift.append("registration-stale")
    if lock_drift:
        drift.append(lock_drift)
    if _is_windows() and name in _EXPECTED_CONTRACT:
        windows_registration = _windows_registration_freshness(cfg, name)
        if windows_registration:
            drift.append(windows_registration)
    elif name in _EXPECTED_CONTRACT:
        unix_registration = _unix_registration_freshness(cfg, name)
        if unix_registration:
            drift.append(unix_registration)

    for source, mode in sources:
        if source == "config":
            continue
        if mode is None:
            if source not in {"claude-env"} or name == "claudecode":
                drift.append(f"{source}-missing")
        elif mode != desired:
            drift.append(f"{source}-{mode}")

    return ConnectorFailModeState(
        connector=name,
        desired=desired,
        configured=configured,
        runtime=runtime,
        sources=tuple(sources),
        drift=tuple(dict.fromkeys(drift)),
    )


def _platform_runtime_source(cfg: Any, connector: str) -> tuple[str, str | None]:
    if _is_windows():
        mode, legacy = _read_windows_hook_mode(Path(cfg.data_dir) / "hooks" / ".hookcfg", connector)
        if legacy:
            return "windows-sidecar-legacy", mode
        return "windows-sidecar", mode
    script_name = "claude-code-hook.sh" if connector == "claudecode" else f"{connector}-hook.sh"
    return "hook-script", _read_baked_hook_mode(Path(cfg.data_dir) / "hooks" / script_name)


def _read_windows_hook_mode(path: Path, connector: str) -> tuple[str | None, bool]:
    data = _read_small_file(path)
    if data is None:
        return None, False
    try:
        payload = json.loads(data)
    except (TypeError, ValueError):
        payload = None
    if isinstance(payload, dict) and int(payload.get("version", 0) or 0) >= 2:
        modes = payload.get("fail_modes")
        if isinstance(modes, dict):
            value = modes.get(normalize(connector))
            if str(value or "").strip() in _VALID_MODES:
                return normalize_fail_mode(value), False
        legacy_value = str(payload.get("legacy_fail_mode") or "").strip().lower()
        if legacy_value in _VALID_MODES:
            return legacy_value, True
        return None, False
    for line in data.splitlines():
        key, separator, value = line.strip().partition("=")
        if separator and key.removeprefix("export ").strip() == "DEFENSECLAW_FAIL_MODE":
            value = value.strip().strip("\"'").lower()
            return (value if value in _VALID_MODES else None), True
    return None, True


def _read_baked_hook_mode(path: Path) -> str | None:
    data = _read_small_file(path)
    if data is None:
        return None
    match = _FAIL_MODE_PATTERN.search(data)
    return match.group(1) if match else None


def _claude_registration_state() -> tuple[str | None, bool]:
    data = _read_small_file(Path(connector_config_files("claudecode")[0]))
    if data is None:
        return None, False
    try:
        settings = json.loads(data)
    except (TypeError, ValueError):
        return None, False
    if not isinstance(settings, dict):
        return None, False
    env = settings.get("env")
    value = env.get("DEFENSECLAW_FAIL_MODE") if isinstance(env, dict) else None
    mode = str(value or "").strip().lower()
    hooks = settings.get("hooks")
    try:
        hook_registration = json.dumps(hooks, separators=(",", ":")).lower()
    except (TypeError, ValueError):
        hook_registration = ""
    registered = "defenseclaw" in hook_registration and (
        "claudecode" in hook_registration or "claude-code-hook" in hook_registration
    )
    return (mode if mode in _VALID_MODES else None), registered


def _codex_registration_current() -> bool:
    data = _read_small_file(Path(connector_config_files("codex")[0]))
    if data is None:
        return False
    return "[hooks]" in data and "defenseclaw" in data.lower()


def _registration_lock_state(cfg: Any, connector: str) -> tuple[str | None, str | None]:
    data = _read_small_file(Path(cfg.data_dir) / "hook_contract_lock.json")
    if data is None:
        return None, "registration-lock-missing"
    try:
        payload = json.loads(data)
    except (TypeError, ValueError):
        return None, "registration-lock-malformed"
    connectors = payload.get("connectors") if isinstance(payload, dict) else None
    entry = connectors.get(connector) if isinstance(connectors, dict) else None
    if not isinstance(entry, dict):
        return None, "registration-lock-missing"
    value = entry.get("hook_fail_mode") if isinstance(entry, dict) else None
    raw = str(value or "").strip().lower()
    mode = raw if raw in _VALID_MODES else None
    expected_contract = _EXPECTED_CONTRACT.get(connector)
    if expected_contract and str(entry.get("contract_id") or "") != expected_contract:
        return mode, "registration-contract-stale"
    if expected_contract and not str(entry.get("hook_script_version") or "").strip():
        return mode, "registration-version-stale"
    digests = entry.get("hook_script_digests")
    if expected_contract and not isinstance(digests, dict):
        return mode, "registration-digests-missing"
    locations = entry.get("locations")
    configured_paths = locations.get("hook_script_paths") if isinstance(locations, dict) else None
    path_by_name = {
        Path(str(item)).name: Path(str(item))
        for item in (configured_paths if isinstance(configured_paths, list) else [])
        if str(item or "").strip()
    }
    if expected_contract and not digests:
        return mode, "registration-digests-missing"

    raw_lock_version = payload.get("version", 1)
    if type(raw_lock_version) is not int or raw_lock_version < 1:
        return mode, "registration-lock-malformed"
    lock_version = raw_lock_version
    if lock_version > 2:
        return mode, "registration-lock-version-unsupported"
    shared_digests: dict[str, object] = {}
    if lock_version >= 2:
        raw_shared = payload.get("shared_hook_script_digests")
        if not isinstance(raw_shared, dict) or not _SHARED_HOOK_SCRIPTS.issubset(raw_shared):
            return mode, "registration-shared-digests-missing"
        shared_digests = raw_shared
    else:
        # A v1 lock duplicated shared-file expectations in every connector
        # entry.  Divergent values cannot be reconciled by choosing whichever
        # connector happens to match disk; require controlled setup to render
        # canonical bytes and atomically migrate the whole lock to v2.
        legacy_shared = False
        if expected_contract and not _LEGACY_SHARED_HOOK_SCRIPTS.issubset(digests):
            return mode, "registration-shared-digests-missing"
        for filename in _SHARED_HOOK_SCRIPTS:
            expected_values = {
                str(candidate_digests.get(filename) or "")
                for candidate in (connectors or {}).values()
                if isinstance(candidate, dict)
                for candidate_digests in [candidate.get("hook_script_digests")]
                if isinstance(candidate_digests, dict) and filename in candidate_digests
            }
            legacy_shared = legacy_shared or bool(expected_values)
            if len(expected_values) > 1:
                return mode, "registration-shared-digest-divergent"
        if legacy_shared and len(connectors or {}) > 1:
            return mode, "registration-shared-lock-legacy"
    if _is_windows() and expected_contract:
        digest_names = {str(filename).casefold() for filename in digests}
        if "defenseclaw-hook.exe" not in digest_names:
            return mode, "registration-launcher-digest-missing"
    digest_sets = [digests or {}]
    if lock_version >= 2:
        digest_sets.append(shared_digests)
    for digest_set in digest_sets:
        for filename, expected in digest_set.items():
            if lock_version >= 2 and digest_set is digests and str(filename) in _SHARED_HOOK_SCRIPTS:
                # Root shared evidence is authoritative in v2.  Ignore a
                # lingering legacy duplicate until the next locked save strips
                # it; never let the duplicate override the root digest.
                continue
            if expected_contract and Path(str(filename)).name != str(filename):
                return mode, "registration-digest-path-stale"
            if expected_contract:
                # Prefer the exact setup-time location recorded by the lock.
                # The Windows launcher can live outside the current process's
                # notion of HOME (service accounts and isolated installs are
                # common); hashing a guessed home path creates false drift.
                path = path_by_name.get(str(filename))
                if path is None:
                    path = (
                        Path.home() / ".local" / "bin" / "defenseclaw-hook.exe"
                        if str(filename).casefold() == "defenseclaw-hook.exe"
                        else Path(cfg.data_dir) / "hooks" / str(filename)
                    )
            else:
                path = path_by_name.get(str(filename), Path(cfg.data_dir) / "hooks" / str(filename))
            actual = _sha256_regular_file(path)
            if actual != str(expected or ""):
                return mode, "registration-digest-stale"
    return mode, None


def _windows_registration_freshness(cfg: Any, connector: str) -> str | None:
    """Return drift when the live Windows command/launcher is not current."""

    from defenseclaw.doctor_hooks import validate_windows_hook_registration

    workspace = ""
    workspace_resolver = getattr(cfg, "connector_workspace_dir", None)
    if callable(workspace_resolver):
        workspace = str(workspace_resolver() or "")
    paths = connector_config_files(connector, workspace_dir=workspace)
    config_path = (
        paths[0]
        if paths
        else str(Path.home() / (".codex/config.toml" if connector == "codex" else ".claude/settings.json"))
    )
    check = validate_windows_hook_registration(
        connector=connector,
        config_path=config_path,
        data_dir=str(cfg.data_dir),
        install_root=str(Path.home() / ".local" / "bin"),
        search_path=os.environ.get("PATH", ""),
        pathext=os.environ.get("PATHEXT", ""),
    )
    return None if check.healthy else f"registration-{check.state}"


def _unix_registration_freshness(cfg: Any, connector: str) -> str | None:
    """Verify the live Unix agent registration points at this data dir's hook."""

    if connector == "claudecode":
        registration_path = Path(connector_config_files("claudecode")[0])
        script_name = "claude-code-hook.sh"
    else:
        registration_path = Path(connector_config_files("codex")[0])
        script_name = "codex-hook.sh"
    registration = _read_small_file(registration_path)
    if registration is None:
        return "registration-missing"
    expected = str((Path(cfg.data_dir) / "hooks" / script_name).resolve())
    # JSON/TOML string literals escape a backslash when this helper is unit
    # tested from Windows; Unix paths use '/' and are unchanged.
    expected_forms = {expected, expected.replace("\\", "\\\\")}
    if not any(candidate in registration for candidate in expected_forms):
        return "registration-command-stale"
    return None


def _read_small_file(path: Path) -> str | None:
    body = _read_small_bytes(path)
    if body is None:
        return None
    try:
        return body.decode("utf-8")
    except UnicodeError:
        return None


def _read_small_bytes(path: Path) -> bytes | None:
    descriptor: int | None = None
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_RUNTIME_FILE:
            return None
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > _MAX_RUNTIME_FILE:
            return None
        if not os.path.samestat(info, opened):
            return None
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            body = handle.read(_MAX_RUNTIME_FILE + 1)
            return body if len(body) <= _MAX_RUNTIME_FILE else None
    except OSError:
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _sha256_regular_file(path: Path) -> str:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_DIGEST_FILE:
            return ""
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > _MAX_DIGEST_FILE
            or not os.path.samestat(before, opened)
        ):
            return ""
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity_before = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after:
            return ""
        return "sha256:" + digest.hexdigest()
    except OSError:
        return ""
    finally:
        if descriptor is not None:
            os.close(descriptor)


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    existed: bool
    data: bytes = b""
    mode: int = 0o600


@contextmanager
def fail_mode_transaction_lock(cfg: Any) -> Iterator[None]:
    """Serialize config + registration reconciliation across CLI/TUI callers."""

    config_path = str(config_module.config_path_for_data_dir(cfg.data_dir))
    lock_path = config_path + ".fail-mode-transaction.lock"
    Path(lock_path).parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        lock = os.fdopen(descriptor, "r+")
    except BaseException:
        os.close(descriptor)
        raise
    try:
        config_module._lock_file_exclusive(lock)
        try:
            yield
        finally:
            config_module._unlock_file(lock)
    finally:
        lock.close()


def snapshot_fail_mode_transaction(cfg: Any, connectors: list[str]) -> tuple[FileSnapshot, ...]:
    paths = {config_module.config_path_for_data_dir(cfg.data_dir)}
    hook_dir = Path(cfg.data_dir) / "hooks"
    paths.update(
        {
            hook_dir / ".hookcfg",
            hook_dir / ".hookcfg.legacy",
            Path(cfg.data_dir) / "hook_contract_lock.json",
            hook_dir / "inspect-tool.sh",
            hook_dir / "inspect-request.sh",
            hook_dir / "inspect-response.sh",
            hook_dir / "inspect-tool-response.sh",
            hook_dir / "_hardening.sh",
        }
    )
    workspace = ""
    workspace_resolver = getattr(cfg, "connector_workspace_dir", None)
    if callable(workspace_resolver):
        workspace = str(workspace_resolver() or "")
    for raw_name in connectors:
        name = normalize(raw_name)
        paths.add(hook_dir / f".hook-{name}.token")
        paths.add(hook_dir / f".hookcfg.{name}")
        for config_path in connector_config_files(name, workspace_dir=workspace):
            paths.add(Path(config_path))
        paths.add(hook_dir / f"{name}-hook.sh")
        paths.add(Path(cfg.data_dir) / f"{name}_backup.json")
        backup_dir = Path(cfg.data_dir) / "connector_backups" / name
        for logical_name in ("config", "settings.json", "config.toml", "module", "pth", "openclaw.json"):
            paths.add(backup_dir / f"{logical_name}.json")
        if backup_dir.is_dir():
            paths.update(path for path in backup_dir.rglob("*") if path.is_file())
        if name == "claudecode":
            paths.update(
                {
                    Path(connector_config_files("claudecode")[0]),
                    hook_dir / "claude-code-hook.sh",
                    Path(cfg.data_dir) / "claudecode_backup.json",
                    Path(cfg.data_dir) / "connector_backups" / "claudecode" / "settings.json.json",
                }
            )
        elif name == "codex":
            paths.update(
                {
                    Path(connector_config_files("codex")[0]),
                    hook_dir / "codex-hook.sh",
                    Path(cfg.data_dir) / "codex_config_backup.json",
                    Path(cfg.data_dir) / "codex_backup.json",
                    Path(cfg.data_dir) / "connector_backups" / "codex" / "config.toml.json",
                    Path(cfg.data_dir) / "notify-bridge.sh",
                }
            )
    snapshots: list[FileSnapshot] = []
    for path in sorted(paths, key=str):
        try:
            data, mode = _snapshot_regular_file(path)
            snapshots.append(
                FileSnapshot(
                    path=path,
                    existed=True,
                    data=data,
                    mode=mode,
                )
            )
        except FileNotFoundError:
            snapshots.append(FileSnapshot(path=path, existed=False))
    return tuple(snapshots)


def _snapshot_regular_file(path: Path) -> tuple[bytes, int]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_RUNTIME_FILE:
        raise OSError(f"unsafe transaction path: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > _MAX_RUNTIME_FILE:
            raise OSError(f"unsafe opened transaction path: {path}")
        if not os.path.samestat(info, opened):
            raise OSError(f"transaction path changed while opening: {path}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            body = handle.read(_MAX_RUNTIME_FILE + 1)
            if len(body) > _MAX_RUNTIME_FILE:
                raise OSError(f"transaction path grew beyond size limit: {path}")
            return body, stat.S_IMODE(opened.st_mode)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def restore_fail_mode_transaction(snapshots: tuple[FileSnapshot, ...]) -> None:
    errors: list[str] = []
    for snapshot in reversed(snapshots):
        try:
            if snapshot.existed:
                snapshot.path.parent.mkdir(parents=True, exist_ok=True)
                fd, temporary = tempfile.mkstemp(prefix=f".{snapshot.path.name}.", dir=snapshot.path.parent)
                try:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(snapshot.data)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.chmod(temporary, snapshot.mode)
                    os.replace(temporary, snapshot.path)
                finally:
                    try:
                        os.unlink(temporary)
                    except FileNotFoundError:
                        pass
            else:
                snapshot.path.unlink(missing_ok=True)
        except OSError:
            errors.append(str(snapshot.path))
    if errors:
        raise OSError("rollback failed for runtime files: " + ", ".join(errors))


def reconcile_connector_registration(cfg: Any, connector: str) -> ConnectorFailModeState:
    executable = shutil.which("defenseclaw-gateway")
    if not executable or (_is_windows() and Path(executable).suffix.lower() != ".exe"):
        raise OSError("native defenseclaw-gateway executable not found")
    environment = os.environ.copy()
    environment[config_module.CONFIG_PATH_ENV] = str(config_module.config_path_for_data_dir(cfg.data_dir))
    try:
        result = subprocess.run(
            [
                executable,
                "connector",
                "reconcile",
                "--connector",
                normalize(connector),
                "--data-dir",
                str(cfg.data_dir),
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OSError(f"connector reconcile failed: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "connector reconcile failed").splitlines()[0]
        raise OSError(detail[:240])
    state = resolve_connector_fail_mode(cfg, connector)
    if not state.current:
        raise OSError(f"connector runtime verification failed for {state.connector}: " + ", ".join(state.drift))
    return state
