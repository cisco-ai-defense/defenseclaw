"""Secure native artifact publication and sidecar activation."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import digest_bytes


class PublicationError(RuntimeError):
    pass


class ActivationError(RuntimeError):
    pass


class RollbackDivergenceError(ActivationError):
    pass


@dataclass(frozen=True)
class PublishedArtifact:
    path: Path
    digest: str | None
    previous: bytes | None
    previous_existed: bool


class ManagedPublisher:
    def __init__(
        self,
        *,
        data_dir: str,
        policy_dir: str,
        managed_dir: str = "",
        opa_enabled: bool = True,
    ) -> None:
        raw_data_dir = _absolute_path(data_dir)
        raw_policy_dir = _absolute_path(policy_dir)
        self.data_dir = raw_data_dir.resolve()
        self.policy_dir = raw_policy_dir.resolve()
        if managed_dir:
            raw_managed_dir = _absolute_path(managed_dir)
            _reject_descendant_symlinks(raw_managed_dir, raw_data_dir)
            self.managed_dir = raw_managed_dir.resolve()
        else:
            self.managed_dir = self.data_dir / "agent-control"
        if self.managed_dir != self.data_dir / "agent-control" and self.data_dir not in self.managed_dir.parents:
            raise PublicationError("managed_dir must be inside data_dir")
        self.state_path = self.managed_dir / "state.json"
        self.lock_path = self.managed_dir / "lock"
        self.opa_enabled = opa_enabled
        self.opa_active_path = self.policy_dir / "rego" / "data-agent-control.json"
        self.rule_pack_root = self.managed_dir / "rule-pack" / "current"
        self.rule_pack_active_path = self.rule_pack_root / "rules" / "agent-control.yaml"

    def prepare(self) -> None:
        for directory in (
            self.managed_dir,
            self.managed_dir / "opa" / "versions",
            self.managed_dir / "rule-pack" / "versions",
            self.rule_pack_active_path.parent,
        ):
            _ensure_real_directory(directory)
        # policy_dir/rego is shared with the gateway's local Rego modules.
        # Require it to be writable and symlink-free, but do not take
        # ownership of it or silently tighten an administrator-selected mode.
        if self.opa_enabled:
            _ensure_publish_directory(self.opa_active_path.parent)

    def publish_opa(self, content: bytes) -> PublishedArtifact:
        if not self.opa_enabled:
            raise PublicationError("OPA publication is disabled for this synchronizer")
        self.prepare()
        digest = digest_bytes(content)
        self._store_version("opa", digest, "data-agent-control.json", content)
        return self._replace_active(self.opa_active_path, content, digest)

    def stage_opa(self, content: bytes) -> Path:
        """Persist an immutable candidate without changing the active file."""
        if not self.opa_enabled:
            raise PublicationError("OPA publication is disabled for this synchronizer")
        self.prepare()
        digest = digest_bytes(content)
        self._store_version("opa", digest, "data-agent-control.json", content)
        return self.managed_dir / "opa" / "versions" / digest.removeprefix("sha256:") / "data-agent-control.json"

    def publish_rule_pack(self, content: bytes | None) -> PublishedArtifact:
        self.prepare()
        digest = digest_bytes(content) if content is not None else None
        if content is not None and digest is not None:
            self._store_version("rule-pack", digest, "rules/agent-control.yaml", content)
        return self._replace_active(self.rule_pack_active_path, content, digest)

    def stage_rule_pack(self, content: bytes) -> Path:
        """Persist an immutable rule candidate and return its overlay root."""
        self.prepare()
        digest = digest_bytes(content)
        self._store_version("rule-pack", digest, "rules/agent-control.yaml", content)
        return self.managed_dir / "rule-pack" / "versions" / digest.removeprefix("sha256:")

    @staticmethod
    def active_digest(path: Path) -> str | None:
        try:
            return digest_bytes(_read_regular(path))
        except FileNotFoundError:
            return None

    def rollback(self, publication: PublishedArtifact) -> None:
        current_digest = self.active_digest(publication.path)
        if current_digest != publication.digest:
            raise RollbackDivergenceError(
                f"refusing rollback for {publication.path}: "
                f"expected active digest {publication.digest}, got {current_digest}"
            )
        if publication.previous_existed and publication.previous is not None:
            _atomic_write(
                publication.path,
                publication.previous,
                shared_parent=publication.path == self.opa_active_path,
            )
        else:
            try:
                _validate_existing_file(publication.path)
                publication.path.unlink()
                _fsync_dir(publication.path.parent)
            except FileNotFoundError:
                pass

    def _replace_active(self, path: Path, content: bytes | None, digest: str | None) -> PublishedArtifact:
        try:
            previous = _read_regular(path)
            previous_existed = True
        except FileNotFoundError:
            previous = None
            previous_existed = False
        if content is None:
            try:
                _validate_existing_file(path)
                path.unlink()
                _fsync_dir(path.parent)
            except FileNotFoundError:
                pass
        else:
            _atomic_write(path, content, shared_parent=path == self.opa_active_path)
        return PublishedArtifact(path=path, digest=digest, previous=previous, previous_existed=previous_existed)

    def _store_version(self, lane: str, digest: str, relative: str, content: bytes) -> None:
        version_dir = self.managed_dir / lane / "versions" / digest.removeprefix("sha256:")
        destination = version_dir / relative
        try:
            _validate_existing_file(destination)
            destination_exists = True
        except FileNotFoundError:
            destination_exists = False
        protected = {version_dir.name}
        active_path = self.opa_active_path if lane == "opa" else self.rule_pack_active_path
        active_digest = self.active_digest(active_path)
        if active_digest:
            protected.add(active_digest.removeprefix("sha256:"))
        if destination_exists:
            if _read_regular(destination) != content:
                raise PublicationError(f"immutable version collision at {destination}")
            self._prune_versions(version_dir.parent, keep=8, protected=protected)
            return
        _ensure_real_directory(destination.parent)
        _atomic_write(destination, content)
        self._prune_versions(version_dir.parent, keep=8, protected=protected)

    @staticmethod
    def _prune_versions(parent: Path, keep: int, protected: set[str]) -> None:
        entries = list(parent.iterdir())
        for entry in entries:
            if entry.is_symlink() or not entry.is_dir():
                raise PublicationError(f"unexpected managed version entry: {entry}")
        versions = sorted(
            entries,
            key=lambda entry: entry.stat().st_mtime_ns,
            reverse=True,
        )
        retained = {entry.name for entry in versions[:keep]} | protected
        for old in versions:
            if old.name in retained:
                continue
            shutil.rmtree(old)


class SingleWriterLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._file: Any = None

    def __enter__(self) -> SingleWriterLock:
        _ensure_real_directory(self.path.parent)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        info = os.fstat(fd)
        geteuid = getattr(os, "geteuid", None)
        if info.st_nlink != 1 or (geteuid is not None and info.st_uid != geteuid()):
            os.close(fd)
            raise PublicationError("writer lock has unexpected owner or link count")
        self._file = os.fdopen(fd, "r+")
        try:
            import fcntl

            fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (ImportError, BlockingIOError) as exc:
            self._file.close()
            self._file = None
            raise PublicationError("another Agent Control synchronizer owns the writer lock") from exc
        self._file.seek(0)
        self._file.truncate()
        self._file.write(str(os.getpid()) + "\n")
        self._file.flush()
        os.fsync(self._file.fileno())
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._file is not None:
            try:
                import fcntl

                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            finally:
                self._file.close()
                self._file = None


class NativeValidator:
    def __init__(self, binary: str = "defenseclaw-gateway") -> None:
        self.binary = binary

    def validate_opa(self, *, rego_dir: Path, candidate: Path) -> None:
        binary = shutil.which(self.binary)
        if binary is None:
            raise PublicationError(f"{self.binary} is required for native OPA candidate validation")
        try:
            result = subprocess.run(
                [
                    binary,
                    "policy",
                    "validate",
                    "--rego-dir",
                    str(rego_dir),
                    "--candidate-agent-control",
                    str(candidate),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise PublicationError(f"native OPA validation could not run ({type(exc).__name__})") from exc
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "native validation failed").strip()
            raise PublicationError(message[-1000:])

    def validate_rule_pack(self, *, base_dirs: list[Path], overlay_dir: Path) -> None:
        binary = shutil.which(self.binary)
        if binary is None:
            raise PublicationError(f"{self.binary} is required for native rule-pack validation")
        # An empty base list means "use the embedded/default base". Preserve
        # that as an empty CLI flag instead of converting Path("") to ".",
        # which would make validation depend on the synchronizer's cwd.
        for base_dir in [*base_dirs] or [None]:
            base_arg = "" if base_dir is None else str(base_dir)
            try:
                result = subprocess.run(
                    [
                        binary,
                        "policy",
                        "validate-rule-pack",
                        "--base-dir",
                        base_arg,
                        "--overlay-dir",
                        str(overlay_dir),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise PublicationError(f"native rule-pack validation could not run ({type(exc).__name__})") from exc
            if result.returncode != 0:
                raise PublicationError("native rule-pack validation failed; candidate was not published")


class GatewayClient:
    def __init__(self, *, bind: str, port: int, token: str, timeout: float = 10.0) -> None:
        host = (bind or "127.0.0.1").strip()
        if host in {"0.0.0.0", "::", "[::]", "localhost"}:
            host = "127.0.0.1"
        elif ":" in host and not host.startswith("["):
            host = f"[{host}]"
        self.base_url = f"http://{host}:{port}"
        self.token = token
        self.timeout = timeout

    def reload_opa(self, expected_digest: str | None) -> dict[str, Any]:
        response = self._request("POST", "/policy/reload")
        actual = _status_artifact_digest(response, "agent_control")
        if actual != expected_digest:
            raise ActivationError(f"OPA active digest mismatch: expected {expected_digest}, got {actual}")
        return response

    def status(self) -> dict[str, Any]:
        return self._request("GET", "/policy/status")

    def verify_rule_pack(self, expected_digest: str | None) -> dict[str, Any]:
        response = self.status()
        actual = _status_artifact_digest(response, "rule_pack")
        if actual != expected_digest:
            raise ActivationError(f"rule-pack active digest mismatch: expected {expected_digest}, got {actual}")
        return response

    def ensure_restart_supported(self) -> None:
        response = self.status()
        if response.get("restart_supported") is not True:
            raise ActivationError(
                "automatic rule-pack activation requires a supervised gateway; "
                "use manual activation or run the gateway under a packaged supervisor"
            )

    def restart_and_verify_rule_pack(self, expected_digest: str | None, timeout: float = 60.0) -> dict[str, Any]:
        self._request("POST", "/policy/restart")
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                return self.verify_rule_pack(expected_digest)
            except (ActivationError, OSError, urllib.error.URLError) as exc:
                last_error = exc
                time.sleep(0.5)
        raise ActivationError(f"gateway did not activate rule-pack before timeout: {last_error}")

    def _request(self, method: str, path: str) -> dict[str, Any]:
        headers = {"Content-Type": "application/json", "X-DefenseClaw-Client": "agent-control-sync"}
        if not self.token:
            raise ActivationError("no DefenseClaw gateway token is configured")
        headers["Authorization"] = f"Bearer {self.token}"
        headers["X-DefenseClaw-Token"] = self.token
        request = urllib.request.Request(
            self.base_url + path,
            data=b"" if method == "POST" else None,
            method=method,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw_bytes = response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise ActivationError(f"gateway {path} failed with HTTP {exc.code}: {body[-500:]}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ActivationError(f"gateway {path} is unavailable ({type(exc).__name__})") from exc
        try:
            payload = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ActivationError(f"gateway {path} returned malformed JSON") from exc
        if not isinstance(payload, dict):
            raise ActivationError(f"gateway {path} returned a non-object response")
        return payload


def _ensure_real_directory(path: Path) -> None:
    _reject_symlink_components(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if path.is_symlink() or not path.is_dir():
        raise PublicationError(f"managed path must be a real directory: {path}")
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and info.st_uid != geteuid():
        raise PublicationError(f"managed directory has unexpected owner: {path}")
    try:
        path.chmod(0o700)
    except OSError as exc:
        raise PublicationError(f"cannot restrict managed directory permissions: {path}") from exc
    if path.lstat().st_mode & 0o777 != 0o700:
        raise PublicationError(f"managed directory permissions are not 0700: {path}")


def _ensure_publish_directory(path: Path) -> None:
    """Prepare a shared policy directory without changing its ownership/mode."""
    _reject_symlink_components(path)
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise PublicationError(f"policy publication directory must already exist: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise PublicationError(f"policy publication path must be a real directory: {path}")
    if not os.access(path, os.W_OK | os.X_OK):
        raise PublicationError(f"policy publication directory is not writable: {path}")


def _atomic_write(path: Path, content: bytes, *, shared_parent: bool = False) -> None:
    if shared_parent:
        _ensure_publish_directory(path.parent)
    else:
        _ensure_real_directory(path.parent)
    try:
        _validate_existing_file(path)
    except FileNotFoundError:
        pass
    tmp = path.parent / f".{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        # Windows does not allow opening a directory with os.open().
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _absolute_path(value: str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(value)))


def _reject_symlink_components(path: Path) -> None:
    absolute = _absolute_path(str(path))
    for component in reversed((absolute, *absolute.parents)):
        try:
            if component.is_symlink():
                raise PublicationError(f"managed path cannot traverse a symlink: {component}")
        except OSError as exc:
            raise PublicationError(f"cannot inspect managed path component {component}: {exc}") from exc


def _reject_descendant_symlinks(path: Path, root: Path) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise PublicationError(f"managed path cannot traverse a symlink: {current}")


def _validate_existing_file(path: Path) -> os.stat_result:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PublicationError(f"managed file must be regular: {path}")
    if info.st_nlink != 1:
        raise PublicationError(f"managed file must not be hard-linked: {path}")
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and info.st_uid not in {0, geteuid()}:
        raise PublicationError(f"managed file owner is neither root nor the current user: {path}")
    return info


def _read_regular(path: Path) -> bytes:
    """Read one managed file through an identity-checked descriptor."""
    before = _validate_existing_file(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise PublicationError(f"managed file changed while opening: {path}")
        if opened.st_nlink != 1:
            raise PublicationError(f"managed file must not be hard-linked: {path}")
        geteuid = getattr(os, "geteuid", None)
        if geteuid is not None and opened.st_uid not in {0, geteuid()}:
            raise PublicationError(f"managed file owner is neither root nor the current user: {path}")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            content = handle.read()
        after = path.lstat()
        if stat.S_ISLNK(after.st_mode) or (after.st_dev, after.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise PublicationError(f"managed file changed while reading: {path}")
        return content
    finally:
        os.close(fd)


def _status_artifact_digest(response: dict[str, Any], field: str) -> str | None:
    status = response.get(field)
    if not isinstance(status, dict) or not isinstance(status.get("present"), bool):
        raise ActivationError(f"gateway status has malformed {field} metadata")
    digest = status.get("artifact_digest")
    if status["present"]:
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise ActivationError(f"gateway status has malformed {field} artifact digest")
        return digest
    if digest not in (None, ""):
        raise ActivationError(f"gateway status reports a digest for absent {field} policy")
    return None
