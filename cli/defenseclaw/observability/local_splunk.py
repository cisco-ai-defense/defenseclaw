# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Native, transactional lifecycle for bundled Local Splunk.

This controller is the Windows x64 implementation behind ``setup splunk
--logs``.  Every host process is launched through :class:`CommandRunner` with
an argument vector.  Bash, WSL, command-script shims, and shell parsing are not
part of this lifecycle.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import stat
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from defenseclaw.file_permissions import (
    atomic_write_private_bytes,
    make_private_directory,
    protect_private_file,
    reject_reparse_path,
)
from defenseclaw.observability.local_stack import (
    CommandResult,
    CommandRunner,
    LocalStackError,
    resolve_native_docker_executable,
    validate_native_docker_preflight,
)
from defenseclaw.paths import bundled_splunk_bridge_dir
from defenseclaw.platform_support import host_os
from defenseclaw.safety import sanitize_dotenv_value

COMPOSE_PROJECT = "defenseclaw-splunk-local"
COMPOSE_FILE_REL = Path("compose") / "docker-compose.local.yml"
ENV_FILE_REL = Path("env") / ".env"
ENV_EXAMPLE_REL = Path("env") / ".env.example"
APP_SOURCE_REL = Path("splunk") / "apps" / "defenseclaw_local_mode"
APP_PACKAGE_REL = Path("splunk") / "build" / "defenseclaw_local_mode.tgz"
DEFAULTS_REL = Path("splunk") / "default.yml"
LOCAL_TOKEN_ENV = "DEFENSECLAW_LOCAL_SPLUNK_HEC_TOKEN"
WEB_URL = "http://127.0.0.1:8000"
DEFAULT_HEC_URL = "https://127.0.0.1:8088/services/collector/event"
SERVICE_NAMES = frozenset({"splunk", "splunk-s3-exporter"})
MANAGED_VOLUME_NAMES = frozenset(
    {
        "defenseclaw_splunk_local_etc",
        "defenseclaw_splunk_local_var",
        "defenseclaw_splunk_s3_exporter_state",
    }
)
MANAGED_VOLUMES = {
    "defenseclaw_splunk_local_etc": "splunk_etc",
    "defenseclaw_splunk_local_var": "splunk_var",
    "defenseclaw_splunk_s3_exporter_state": "splunk_s3_exporter_state",
}
_REQUIRED_ASSETS = (
    COMPOSE_FILE_REL,
    ENV_EXAMPLE_REL,
    DEFAULTS_REL,
    APP_SOURCE_REL / "default" / "app.conf",
    APP_SOURCE_REL / "default" / "savedsearches.conf",
    APP_SOURCE_REL / "default" / "data" / "ui" / "nav" / "default.xml",
    APP_SOURCE_REL / "lookups" / "dcso_risk_state_labels.csv",
    APP_SOURCE_REL / "lookups" / "dcso_severity_labels.csv",
    APP_SOURCE_REL / "bin" / "emit_product_telemetry_lifecycle.py",
    APP_SOURCE_REL / "bin" / "product_telemetry_sender.py",
    Path("splunk") / "ansible" / "configure_product_telemetry.yml",
    Path("splunk") / "ansible" / "sync_security_ops_support_layer.yml",
)
_S3_REQUIRED_ASSETS = (
    Path("s3_exporter") / "Dockerfile",
    Path("s3_exporter") / "export_splunk_to_s3.py",
    Path("s3_exporter") / "requirements.txt",
)
_S3_ENV_OVERRIDES = frozenset(
    {
        "S3_EXPORT_ENABLED",
        "S3_EXPORT_ONCE",
        "S3_BUCKET",
        "S3_PREFIX",
        "AWS_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "S3_ENDPOINT_URL",
        "S3_SSE",
        "S3_EXPORT_INTERVAL_SECONDS",
        "S3_EXPORT_WINDOW_SECONDS",
        "S3_EXPORT_LOOKBACK_SECONDS",
        "TENANT_ID",
        "WORKSPACE_ID",
        "DEPLOYMENT_ENVIRONMENT",
    }
)
_S3_COMPOSE_ENVIRONMENT = {
    "S3_EXPORT_ENABLED": "${S3_EXPORT_ENABLED:-false}",
    "S3_EXPORT_ONCE": "${S3_EXPORT_ONCE:-false}",
    "S3_BUCKET": "${S3_BUCKET:-}",
    "S3_PREFIX": "${S3_PREFIX:-agentwatch/defenseclaw}",
    "AWS_REGION": "${AWS_REGION:-us-west-2}",
    "AWS_ACCESS_KEY_ID": "${AWS_ACCESS_KEY_ID:-}",
    "AWS_SECRET_ACCESS_KEY": "${AWS_SECRET_ACCESS_KEY:-}",
    "AWS_SESSION_TOKEN": "${AWS_SESSION_TOKEN:-}",
    "S3_ENDPOINT_URL": "${S3_ENDPOINT_URL:-}",
    "S3_SSE": "${S3_SSE:-AES256}",
    "SPLUNK_BASE_URL": "https://splunk:8089",
    "SPLUNK_VERIFY_TLS": "false",
    "TENANT_ID": "${TENANT_ID:-c3-demo-tenant}",
    "WORKSPACE_ID": "${WORKSPACE_ID:-workspace-demo}",
    "DEPLOYMENT_ENVIRONMENT": "${DEPLOYMENT_ENVIRONMENT:-local}",
    "S3_EXPORT_INTERVAL_SECONDS": "${S3_EXPORT_INTERVAL_SECONDS:-60}",
    "S3_EXPORT_WINDOW_SECONDS": "${S3_EXPORT_WINDOW_SECONDS:-300}",
    "S3_EXPORT_LOOKBACK_SECONDS": "${S3_EXPORT_LOOKBACK_SECONDS:-30}",
    "S3_EXPORT_CHECKPOINT_FILE": "/state/checkpoint.json",
}
_PORTS = ((8000, "8000/tcp", "Splunk Web"), (8088, "8088/tcp", "HEC"))
_PACKAGE_MTIME = 1767225600  # 2026-01-01T00:00:00Z


@dataclass(frozen=True)
class NativeSplunkContract:
    """Verified local connection values.  ``hec_token`` is never rendered."""

    splunk_web_url: str
    hec_url: str
    hec_token: str = field(repr=False)
    token_env: str
    index: str
    source: str
    sourcetype: str
    license_group: str = "Free"
    web_login_required: bool = False

    def as_dict(self) -> dict[str, str | bool]:
        return {
            "splunk_web_url": self.splunk_web_url,
            "hec_url": self.hec_url,
            "token_env": self.token_env,
            "index": self.index,
            "source": self.source,
            "sourcetype": self.sourcetype,
            "license_group": self.license_group,
            "web_login_required": self.web_login_required,
        }


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _require_safe_tree(root: Path, *, description: str) -> Path:
    """Resolve *root* and reject links/reparse points anywhere below it."""

    raw = Path(os.path.abspath(root))
    reject_reparse_path(raw)
    try:
        canonical = raw.resolve(strict=True)
    except OSError as exc:
        raise LocalStackError(f"invalid {description}: {exc}") from exc
    if not canonical.is_dir() or _is_reparse_or_symlink(raw):
        raise LocalStackError(f"invalid {description}: {raw}")
    for current, dirs, files in os.walk(canonical, followlinks=False):
        current_path = Path(current)
        reject_reparse_path(current_path)
        for name in (*dirs, *files):
            candidate = current_path / name
            reject_reparse_path(candidate)
            if _is_reparse_or_symlink(candidate):
                raise LocalStackError(f"refusing reparse/symlink in {description}: {candidate}")
            try:
                candidate.resolve(strict=True).relative_to(canonical)
            except (OSError, ValueError) as exc:
                raise LocalStackError(f"path escapes {description}: {candidate}") from exc
    return canonical


def _load_yaml_mapping(path: Path, *, description: str) -> dict[str, object]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise LocalStackError(f"invalid {description}: {exc}") from exc
    if not isinstance(value, dict):
        raise LocalStackError(f"invalid {description}: expected a YAML mapping")
    return value


def validate_bundle_assets(root: str | os.PathLike[str], *, require_s3: bool = False) -> Path:
    """Validate every host-mounted asset before any lifecycle mutation."""

    canonical = _require_safe_tree(Path(root), description="Local Splunk bundle")
    required = _REQUIRED_ASSETS + (_S3_REQUIRED_ASSETS if require_s3 else ())
    missing = [str(rel) for rel in required if not (canonical / rel).is_file()]
    if missing:
        raise LocalStackError("Local Splunk bundle is incomplete; missing: " + ", ".join(missing))

    compose = _load_yaml_mapping(canonical / COMPOSE_FILE_REL, description="Local Splunk Compose file")
    if set(compose) != {"name", "services", "volumes"}:
        raise LocalStackError("Local Splunk Compose file contains an unexpected top-level key")
    if compose.get("name") != COMPOSE_PROJECT:
        raise LocalStackError(f"Local Splunk Compose project must be exactly {COMPOSE_PROJECT}")
    services = compose.get("services")
    if not isinstance(services, dict) or "splunk" not in services:
        raise LocalStackError("Local Splunk Compose file is missing the splunk service")
    if set(services) != SERVICE_NAMES:
        raise LocalStackError("Local Splunk Compose file contains an unexpected service")
    splunk = services["splunk"]
    if not isinstance(splunk, dict):
        raise LocalStackError("Local Splunk Compose service is invalid")
    if set(splunk) != {"image", "env_file", "ports", "extra_hosts", "volumes", "restart"}:
        raise LocalStackError("Local Splunk Compose service contains an unexpected key")
    ports = {str(item) for item in splunk.get("ports", [])}
    expected_ports = {"127.0.0.1:8000:8000", "127.0.0.1:8088:8088"}
    if ports != expected_ports:
        raise LocalStackError("Local Splunk Web and HEC must be bound to 127.0.0.1")
    expected_mounts = {
        "splunk_etc:/opt/splunk/etc",
        "splunk_var:/opt/splunk/var",
        "../splunk/default.yml:/tmp/defaults/default.yml:ro",
        "../splunk:/opt/splunk-claw-bridge/splunk:ro",
    }
    if splunk.get("image") != "${SPLUNK_IMAGE}" or {str(item) for item in splunk.get("volumes", [])} != expected_mounts:
        raise LocalStackError("Local Splunk Compose image or mount contract is invalid")
    if splunk.get("env_file") != ["${SPLUNK_ENV_FILE:-../env/.env.example}"]:
        raise LocalStackError("Local Splunk Compose env-file contract is invalid")
    if splunk.get("extra_hosts") != ["host.docker.internal:host-gateway"] or splunk.get("restart") != "unless-stopped":
        raise LocalStackError("Local Splunk Compose host/restart contract is invalid")
    exporter = services["splunk-s3-exporter"]
    if not isinstance(exporter, dict) or exporter.get("profiles") != ["s3-export"]:
        raise LocalStackError("Local Splunk S3 exporter profile is invalid")
    if set(exporter) != {"profiles", "build", "depends_on", "environment", "volumes"}:
        raise LocalStackError("Local Splunk S3 exporter contains an unexpected key")
    build = exporter.get("build")
    if not isinstance(build, dict) or build != {"context": "../s3_exporter"}:
        raise LocalStackError("Local Splunk S3 exporter build context is invalid")
    exporter_environment = exporter.get("environment")
    if (
        exporter.get("depends_on") != ["splunk"]
        or not isinstance(exporter_environment, dict)
        or exporter_environment != _S3_COMPOSE_ENVIRONMENT
        or exporter.get("volumes") != ["splunk_s3_exporter_state:/state"]
    ):
        raise LocalStackError("Local Splunk S3 exporter runtime contract is invalid")
    volumes = compose.get("volumes")
    if not isinstance(volumes, dict):
        raise LocalStackError("Local Splunk Compose volumes are missing")
    physical = {str(value.get("name")) for value in volumes.values() if isinstance(value, dict) and value.get("name")}
    if not MANAGED_VOLUME_NAMES.issubset(physical):
        raise LocalStackError("Local Splunk Compose volume identities are invalid")
    if set(volumes) != set(MANAGED_VOLUMES.values()):
        raise LocalStackError("Local Splunk Compose file contains an unexpected volume")
    defaults = _load_yaml_mapping(canonical / DEFAULTS_REL, description="Local Splunk defaults file")
    splunk_defaults = defaults.get("splunk")
    if not isinstance(splunk_defaults, dict):
        raise LocalStackError("Local Splunk defaults are missing the splunk mapping")
    hec = splunk_defaults.get("hec")
    if (
        not isinstance(hec, dict)
        or hec.get("enable") is not True
        or hec.get("ssl") is not True
        or hec.get("port") != 8088
    ):
        raise LocalStackError("Local Splunk defaults do not enable TLS HEC on port 8088")
    if splunk_defaults.get("apps_location") != [
        "file:///opt/splunk-claw-bridge/splunk/build/defenseclaw_local_mode.tgz"
    ]:
        raise LocalStackError("Local Splunk app package location is invalid")
    return canonical


def _parse_dotenv(path: Path, *, require_private: bool = False) -> dict[str, str]:
    reject_reparse_path(path)
    try:
        info = path.stat()
    except FileNotFoundError:
        return {}
    if not stat.S_ISREG(info.st_mode):
        raise LocalStackError(f"credential path is not a regular file: {path}")
    if require_private:
        try:
            protect_private_file(path)
        except OSError as exc:
            raise LocalStackError(f"could not protect Local Splunk credentials: {exc}") from exc
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise LocalStackError(f"could not read Local Splunk credentials: {exc}") from exc
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            values[key] = value.strip()
    return values


def _dotenv_bytes(values: Mapping[str, str]) -> bytes:
    lines = [f"{key}={sanitize_dotenv_value(str(value), key=key)}\n" for key, value in sorted(values.items())]
    return "".join(lines).encode("utf-8")


def _credential_values(
    template: Mapping[str, str],
    previous: Mapping[str, str],
    *,
    index: str,
    source: str,
    sourcetype: str,
) -> dict[str, str]:
    values = dict(template)
    values.update(previous)
    previous_token = previous.get("SPLUNK_HEC_TOKEN", "")
    hec_token = (
        previous_token
        if _valid_existing_secret(previous_token)
        else str(uuid.UUID(bytes=secrets.token_bytes(16), version=4))
    )
    previous_password = previous.get("SPLUNK_PASSWORD", "")
    password = previous_password if _valid_existing_secret(previous_password) else f"Dc9!{secrets.token_urlsafe(32)}"
    values.update(
        {
            "SPLUNK_START_ARGS": "--accept-license",
            "SPLUNK_LICENSE_URI": "Free",
            "SPLUNK_GENERAL_TERMS": "--accept-sgt-current-at-splunk-com",
            "SPLUNK_PASSWORD": password,
            "SPLUNK_HEC_TOKEN": hec_token,
            "DEFENSECLAW_HEC_URL": DEFAULT_HEC_URL,
            "DEFENSECLAW_HEC_TOKEN": hec_token,
            LOCAL_TOKEN_ENV: hec_token,
            "DEFENSECLAW_INDEX": index,
            "DEFENSECLAW_SOURCE": source,
            "DEFENSECLAW_SOURCETYPE": sourcetype,
            "DEFENSECLAW_INTEGRATION_ENABLED": "true",
        }
    )
    if not values.get("SPLUNK_IMAGE"):
        raise LocalStackError("Local Splunk environment template is missing SPLUNK_IMAGE")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,79}", index):
        raise LocalStackError("Local Splunk index must contain only letters, digits, underscores, or hyphens")
    return values


def _valid_existing_secret(value: str) -> bool:
    normalized = value.strip().lower()
    return (
        len(value) >= 24
        and normalized not in {"00000000-0000-0000-0000-000000000001", "replace-me-in-named-environments"}
        and not normalized.startswith("defenseclawlocalmode1")
    )


def package_splunk_app(stack_dir: str | os.PathLike[str]) -> Path:
    """Create the bundled Splunk app without invoking tar or a shell."""

    root = _require_safe_tree(Path(stack_dir), description="Local Splunk stack")
    app_root = root / APP_SOURCE_REL
    if not app_root.is_dir():
        raise LocalStackError(f"Local Splunk app source is missing: {app_root}")
    build_dir = root / APP_PACKAGE_REL.parent
    reject_reparse_path(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    reject_reparse_path(build_dir)
    package_path = root / APP_PACKAGE_REL
    descriptor, temp_name = tempfile.mkstemp(prefix=".defenseclaw_local_mode-", suffix=".tgz", dir=build_dir)
    os.close(descriptor)
    temp_path = Path(temp_name)
    try:
        with temp_path.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=_PACKAGE_MTIME) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    paths = [app_root, *sorted(app_root.rglob("*"))]
                    for candidate in paths:
                        reject_reparse_path(candidate)
                        if _is_reparse_or_symlink(candidate):
                            raise LocalStackError(f"refusing reparse/symlink in Splunk app: {candidate}")
                        relative = candidate.relative_to(app_root.parent).as_posix()
                        if "__pycache__" in candidate.parts or candidate.suffix == ".pyc":
                            continue
                        info = archive.gettarinfo(str(candidate), arcname=relative)
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        info.mtime = _PACKAGE_MTIME
                        if candidate.is_dir():
                            info.mode = 0o755
                            archive.addfile(info)
                        elif candidate.is_file():
                            info.mode = (
                                0o755
                                if "bin" in candidate.relative_to(app_root).parts and candidate.suffix == ".py"
                                else 0o644
                            )
                            with candidate.open("rb") as stream:
                                archive.addfile(info, stream)
                        else:
                            raise LocalStackError(f"unsupported Splunk app asset: {candidate}")
        reject_reparse_path(package_path)
        os.replace(temp_path, package_path)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
    return package_path


def _copy_bundle(source: Path, destination: Path) -> None:
    """Copy a validated bundle into a private, same-volume staging tree."""

    if destination.exists():
        raise LocalStackError(f"staging directory already exists: {destination}")
    make_private_directory(destination)
    for current, dirs, files in os.walk(source, followlinks=False):
        current_path = Path(current)
        rel = current_path.relative_to(source)
        target_dir = destination / rel
        reject_reparse_path(target_dir)
        if os.name == "nt":
            make_private_directory(target_dir)
        else:
            target_dir.mkdir(exist_ok=True)
        dirs[:] = [name for name in dirs if name != "__pycache__"]
        for name in dirs:
            candidate = current_path / name
            if _is_reparse_or_symlink(candidate):
                raise LocalStackError(f"refusing linked bundle directory: {candidate}")
        for name in files:
            if name.endswith(".pyc"):
                continue
            candidate = current_path / name
            if _is_reparse_or_symlink(candidate):
                raise LocalStackError(f"refusing linked bundle file: {candidate}")
            target = target_dir / name
            reject_reparse_path(target)
            shutil.copy2(candidate, target)


def _remove_safe_tree(path: Path) -> None:
    if not path.exists():
        return
    reject_reparse_path(path)
    if _is_reparse_or_symlink(path):
        raise LocalStackError(f"refusing to remove reparse/symlink tree: {path}")
    shutil.rmtree(path)


class NativeLocalSplunkController:
    """One exact Compose project rooted at an already-validated stack tree."""

    def __init__(
        self,
        stack_dir: str | os.PathLike[str],
        *,
        docker_path: str | os.PathLike[str] | None = None,
        runner: CommandRunner | None = None,
        os_name: str | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self.stack_dir = validate_bundle_assets(stack_dir)
        self.compose_file = (self.stack_dir / COMPOSE_FILE_REL).resolve(strict=True)
        self.env_file = self.stack_dir / ENV_FILE_REL
        self.os_name = host_os() if os_name is None else os_name.lower()
        self.docker_path = resolve_native_docker_executable(docker_path, os_name=self.os_name)
        self.runner = runner or CommandRunner()
        self.environment = dict(os.environ if environment is None else environment)

    def preflight(self) -> dict[str, object]:
        return validate_native_docker_preflight(
            self.docker_path,
            self.runner,
            self.environment,
            os_name=self.os_name,
            feature_name="Local Splunk",
        )

    def _compose_environment(self, overrides: Mapping[str, str] | None = None) -> dict[str, str]:
        values = _parse_dotenv(self.env_file, require_private=True)
        if not values:
            raise LocalStackError("Local Splunk credential contract is missing")
        environment = dict(self.environment)
        environment.update(values)
        # Match the POSIX bridge contract: explicit operator S3/AWS process
        # values win over the private env file's disabled/empty defaults.
        for key in _S3_ENV_OVERRIDES:
            if key in self.environment:
                environment[key] = self.environment[key]
        if overrides:
            environment.update({key: str(value) for key, value in overrides.items()})
        environment["SPLUNK_ENV_FILE"] = str(self.env_file)
        environment.pop("HOST_BIND", None)
        return environment

    def compose_argv(self, *args: str, s3_export: bool = False) -> list[str]:
        if not self.docker_path:
            raise LocalStackError("Docker CLI was not found on PATH. Install Docker Desktop and retry.")
        argv = [
            self.docker_path,
            "compose",
            "--env-file",
            str(self.env_file),
            "--project-directory",
            str(self.stack_dir),
            "--file",
            str(self.compose_file),
            "--project-name",
            COMPOSE_PROJECT,
        ]
        if s3_export:
            argv.extend(["--profile", "s3-export"])
        argv.extend(args)
        return argv

    def _run_compose(
        self,
        *args: str,
        timeout: float,
        s3_export: bool = False,
        overrides: Mapping[str, str] | None = None,
    ) -> CommandResult:
        return self.runner.run(
            self.compose_argv(*args, s3_export=s3_export),
            timeout=timeout,
            env=self._compose_environment(overrides),
        )

    def _redacted_detail(self, result: CommandResult) -> str:
        detail = (result.stderr or result.stdout).strip()
        if not detail:
            return ""
        line = detail.splitlines()[0]
        for value in _parse_dotenv(self.env_file, require_private=True).values():
            if value and len(value) >= 8:
                line = line.replace(value, "[REDACTED]")
        return line

    def _checked(self, result: CommandResult, description: str) -> CommandResult:
        if result.returncode == 0:
            return result
        detail = self._redacted_detail(result)
        suffix = f": {detail}" if detail else ""
        raise LocalStackError(f"{description} failed with exit code {result.returncode}{suffix}")

    def _project_container_ids(self, *, running_only: bool = False) -> set[str]:
        argv = [
            self.docker_path,
            "ps",
            "--all",
            "--filter",
            f"label=com.docker.compose.project={COMPOSE_PROJECT}",
        ]
        if running_only:
            argv.extend(["--filter", "status=running"])
        argv.extend(["--format", "{{.ID}}"])
        result = self.runner.run(argv, timeout=10, env=self.environment)
        if result.returncode != 0:
            raise LocalStackError("could not enumerate Local Splunk containers")
        return {line.strip() for line in result.stdout.splitlines() if line.strip()}

    def _container_labels(self, container_id: str) -> dict[str, object]:
        result = self.runner.run(
            [
                self.docker_path,
                "inspect",
                "--format",
                "{{json .Config.Labels}}",
                container_id,
            ],
            timeout=8,
            env=self.environment,
        )
        if result.returncode != 0:
            raise LocalStackError("could not inspect a Local Splunk container; ownership is unproven")
        try:
            labels = json.loads(result.stdout.strip())
        except ValueError as exc:
            raise LocalStackError("Docker returned invalid container labels JSON") from exc
        if not isinstance(labels, dict):
            raise LocalStackError("Docker returned invalid container labels JSON")
        return labels

    @staticmethod
    def _paths_equal(value: str, expected: Path) -> bool:
        if not value:
            return False
        return os.path.normcase(os.path.abspath(value)) == os.path.normcase(os.path.abspath(expected))

    def verify_container_ownership(self) -> dict[str, str]:
        """Prove every project-labelled container belongs to this exact tree."""

        owned: dict[str, str] = {}
        for container_id in self._project_container_ids():
            labels = self._container_labels(container_id)
            service = str(labels.get("com.docker.compose.service", ""))
            config_files = str(labels.get("com.docker.compose.project.config_files", ""))
            working_dir = str(labels.get("com.docker.compose.project.working_dir", ""))
            config_matches = any(
                self._paths_equal(item.strip(), self.compose_file) for item in config_files.split(",") if item.strip()
            )
            if (
                labels.get("com.docker.compose.project") != COMPOSE_PROJECT
                or service not in SERVICE_NAMES
                or not config_matches
                or not self._paths_equal(working_dir, self.stack_dir)
            ):
                raise LocalStackError(
                    "Compose project identity collision: a container using "
                    f"{COMPOSE_PROJECT} is not owned by this Local Splunk stack"
                )
            owned[container_id] = service
        return owned

    def verify_volume_ownership(self) -> None:
        """Reject same-name volumes not labelled for this exact project."""

        listed = self.runner.run(
            [self.docker_path, "volume", "ls", "--format", "{{.Name}}"],
            timeout=8,
            env=self.environment,
        )
        if listed.returncode != 0:
            raise LocalStackError("could not enumerate Local Splunk volumes")
        existing = {line.strip() for line in listed.stdout.splitlines() if line.strip()}
        for physical_name, logical_name in MANAGED_VOLUMES.items():
            if physical_name not in existing:
                continue
            inspected = self.runner.run(
                [
                    self.docker_path,
                    "volume",
                    "inspect",
                    "--format",
                    "{{json .Labels}}",
                    physical_name,
                ],
                timeout=8,
                env=self.environment,
            )
            if inspected.returncode != 0:
                raise LocalStackError(f"could not inspect Local Splunk volume {physical_name}")
            try:
                labels = json.loads(inspected.stdout.strip())
            except ValueError as exc:
                raise LocalStackError("Docker returned invalid volume labels JSON") from exc
            if not isinstance(labels, dict) or (
                labels.get("com.docker.compose.project") != COMPOSE_PROJECT
                or labels.get("com.docker.compose.volume") != logical_name
            ):
                raise LocalStackError(f"volume ownership is unproven for {physical_name}; refusing to adopt it")

    def _container_ports(self, container_id: str) -> dict[str, object]:
        result = self.runner.run(
            [
                self.docker_path,
                "inspect",
                "--format",
                "{{json .NetworkSettings.Ports}}",
                container_id,
            ],
            timeout=8,
            env=self.environment,
        )
        if result.returncode != 0:
            raise LocalStackError("could not verify Local Splunk port ownership")
        try:
            value = json.loads(result.stdout.strip())
        except ValueError as exc:
            raise LocalStackError("Docker returned invalid published-port JSON") from exc
        if not isinstance(value, dict):
            raise LocalStackError("Docker returned invalid published-port JSON")
        return value

    @staticmethod
    def _port_in_use(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
            stream.settimeout(0.5)
            return stream.connect_ex(("127.0.0.1", port)) == 0

    def verify_port_ownership(self) -> None:
        """Allow listeners only when exact owned Splunk mappings explain them."""

        owned = self.verify_container_ownership()
        splunk_ids = [cid for cid, service in owned.items() if service == "splunk"]
        published = [self._container_ports(cid) for cid in splunk_ids]
        for port, container_port, label in _PORTS:
            if not self._port_in_use(port):
                continue
            matches = False
            for mapping in published:
                bindings = mapping.get(container_port)
                if not isinstance(bindings, list):
                    continue
                if any(
                    isinstance(binding, dict)
                    and binding.get("HostIp") == "127.0.0.1"
                    and str(binding.get("HostPort")) == str(port)
                    for binding in bindings
                ):
                    matches = True
                    break
            if not matches:
                raise LocalStackError(f"port {port} ({label}) is held by a foreign process or container")

    def is_running(self) -> bool:
        return bool(self._project_container_ids(running_only=True))

    def s3_runtime_state(self) -> tuple[bool, dict[str, str]]:
        """Capture the owned exporter profile and its non-Compose runtime inputs."""

        owned = self.verify_container_ownership()
        exporter_ids = [container_id for container_id, service in owned.items() if service == "splunk-s3-exporter"]
        if not exporter_ids:
            return False, {}
        result = self.runner.run(
            [self.docker_path, "inspect", "--format", "{{json .Config.Env}}", exporter_ids[0]],
            timeout=20,
            env=self.environment,
        )
        if result.returncode != 0:
            raise LocalStackError("could not capture the owned Local Splunk S3 exporter state")
        try:
            raw_values = json.loads(result.stdout.strip())
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise LocalStackError("Docker returned invalid Local Splunk S3 exporter state") from exc
        if not isinstance(raw_values, list) or not all(isinstance(item, str) for item in raw_values):
            raise LocalStackError("Docker returned invalid Local Splunk S3 exporter state")
        values: dict[str, str] = {}
        for item in raw_values:
            key, separator, value = item.partition("=")
            if separator and key in _S3_ENV_OVERRIDES:
                values[key] = value
        values["S3_EXPORT_ENABLED"] = "true"
        return True, values

    def up(
        self,
        *,
        timeout: int = 300,
        s3_export: bool = False,
        overrides: Mapping[str, str] | None = None,
        emit_startup_telemetry: bool = True,
    ) -> tuple[NativeSplunkContract, set[str]]:
        before = self._project_container_ids()
        try:
            self._checked(
                self._run_compose(
                    "up",
                    "--detach",
                    "--remove-orphans",
                    timeout=max(120, timeout),
                    s3_export=s3_export,
                    overrides=overrides,
                ),
                "docker compose up",
            )
            created = self._project_container_ids() - before
            self.wait_for_readiness(timeout)
            if emit_startup_telemetry:
                self.emit_product_telemetry("startup")
            return self.contract(), created
        except BaseException:
            created = self._project_container_ids() - before
            self.remove_created_containers(created)
            raise

    def down(self, *, emit_shutdown_telemetry: bool = True) -> None:
        self.verify_container_ownership()
        if emit_shutdown_telemetry and self.is_running():
            self.emit_product_telemetry("shutdown")
        self._checked(
            self._run_compose("down", "--remove-orphans", timeout=120),
            "docker compose down",
        )

    def remove_created_containers(self, container_ids: set[str]) -> None:
        for container_id in sorted(container_ids):
            try:
                labels = self._container_labels(container_id)
            except LocalStackError:
                continue
            service = str(labels.get("com.docker.compose.service", ""))
            config_files = str(labels.get("com.docker.compose.project.config_files", ""))
            working_dir = str(labels.get("com.docker.compose.project.working_dir", ""))
            if (
                labels.get("com.docker.compose.project") != COMPOSE_PROJECT
                or service not in SERVICE_NAMES
                or not any(
                    self._paths_equal(item.strip(), self.compose_file)
                    for item in config_files.split(",")
                    if item.strip()
                )
                or not self._paths_equal(working_dir, self.stack_dir)
            ):
                raise LocalStackError("refusing cleanup because a failed-attempt container's exact ownership changed")
            result = self.runner.run(
                [self.docker_path, "rm", "--force", container_id],
                timeout=30,
                env=self.environment,
            )
            if result.returncode != 0:
                raise LocalStackError("could not clean up a container created by the failed Local Splunk attempt")

    def wait_for_readiness(self, timeout: int) -> None:
        if timeout <= 0:
            raise LocalStackError("Local Splunk readiness timeout must be positive")
        deadline = time.monotonic() + timeout
        web_ready = False
        hec_ready = False
        while time.monotonic() < deadline:
            remaining = max(0.05, deadline - time.monotonic())
            web_ready = self._web_ready(min(1.5, remaining))
            hec_ready = self._hec_ready(min(1.5, remaining))
            if web_ready and hec_ready:
                return
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        raise LocalStackError(
            "Local Splunk readiness timeout after "
            f"{timeout}s: web={'ready' if web_ready else 'fail'} "
            f"hec={'ready' if hec_ready else 'fail'}"
        )

    @staticmethod
    def _web_ready(timeout: float) -> bool:
        request = urllib.request.Request(WEB_URL, method="GET")
        opener = urllib.request.build_opener(_NoRedirectHandler())
        try:
            with opener.open(request, timeout=timeout) as response:
                return 200 <= response.status < 400
        except (OSError, urllib.error.URLError, ValueError):
            return False

    def _hec_ready(self, timeout: float) -> bool:
        values = _parse_dotenv(self.env_file, require_private=True)
        event_url = values.get("DEFENSECLAW_HEC_URL", DEFAULT_HEC_URL)
        parsed = urllib.parse.urlparse(event_url)
        if parsed.scheme != "https" or parsed.hostname != "127.0.0.1" or parsed.port != 8088:
            raise LocalStackError("Local Splunk HEC readiness URL must be loopback HTTPS")
        health_url = urllib.parse.urlunparse(parsed._replace(path="/services/collector/health", query=""))
        token = values.get("DEFENSECLAW_HEC_TOKEN", "")
        request = urllib.request.Request(
            health_url,
            headers={"Authorization": f"Splunk {token}"},
            method="GET",
        )
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirectHandler())
        try:
            with opener.open(request, timeout=timeout) as response:
                return 200 <= response.status < 300
        except (OSError, urllib.error.URLError, ValueError):
            return False

    def contract(self) -> NativeSplunkContract:
        values = _parse_dotenv(self.env_file, require_private=True)
        token = values.get("DEFENSECLAW_HEC_TOKEN", "")
        if not token:
            raise LocalStackError("Local Splunk HEC token is missing")
        return NativeSplunkContract(
            splunk_web_url=WEB_URL,
            hec_url=values.get("DEFENSECLAW_HEC_URL", DEFAULT_HEC_URL),
            hec_token=token,
            token_env=LOCAL_TOKEN_ENV,
            index=values.get("DEFENSECLAW_INDEX", "defenseclaw_local"),
            source=values.get("DEFENSECLAW_SOURCE", "defenseclaw"),
            sourcetype=values.get("DEFENSECLAW_SOURCETYPE", "defenseclaw:json"),
        )

    def emit_product_telemetry(self, event_type: str) -> None:
        if event_type not in {"startup", "integration_configured", "shutdown"}:
            raise ValueError("unsupported Local Splunk telemetry event")
        try:
            result = self._run_compose(
                "exec",
                "--no-TTY",
                "--user",
                "splunk",
                "splunk",
                "/opt/splunk/bin/splunk",
                "cmd",
                "python",
                "/opt/splunk-claw-bridge/splunk/apps/defenseclaw_local_mode/bin/emit_product_telemetry_lifecycle.py",
                "--event-type",
                event_type,
                timeout=45,
            )
        except LocalStackError:
            return
        # Product telemetry is deliberately best effort and never weakens the
        # primary local audit pipeline.  Captured output is not rendered.
        _ = result.returncode


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


class NativeSplunkSetupTransaction:
    """Own staged assets until configuration and gateway reload commit."""

    def __init__(
        self,
        *,
        controller: NativeLocalSplunkController,
        contract: NativeSplunkContract,
        stable_dir: Path,
        backup_dir: Path | None,
        previous_running: bool,
        previous_s3_export: bool,
        previous_s3_overrides: Mapping[str, str],
        created_ids: set[str],
    ) -> None:
        self.controller = controller
        self.contract = contract
        self.stable_dir = stable_dir
        self.backup_dir = backup_dir
        self.previous_running = previous_running
        self.previous_s3_export = previous_s3_export
        self.previous_s3_overrides = dict(previous_s3_overrides)
        self.created_ids = set(created_ids)
        self._finished = False

    def commit(self) -> None:
        if self._finished:
            return
        self._finished = True
        if self.backup_dir is not None:
            try:
                _remove_safe_tree(self.backup_dir)
            except (LocalStackError, OSError):
                # The new runtime/config generation is already committed.
                # A locked private backup is safer to retain for operator
                # cleanup than attempting an impossible rollback after a
                # partially completed deletion.
                pass

    def rollback(self) -> None:
        if self._finished:
            return
        errors: list[str] = []
        try:
            self.controller.remove_created_containers(self.created_ids)
        except LocalStackError as exc:
            errors.append(str(exc))
        if self.backup_dir is not None:
            failed_dir: Path | None = None
            restored = False
            try:
                if self.stable_dir.exists():
                    failed_dir = self.stable_dir.with_name(f".splunk-failed-{uuid.uuid4().hex[:8]}")
                    os.replace(self.stable_dir, failed_dir)
                os.replace(self.backup_dir, self.stable_dir)
                restored = True
            except (LocalStackError, OSError) as exc:
                errors.append(str(exc))
            if restored and self.previous_running:
                try:
                    previous = NativeLocalSplunkController(
                        self.stable_dir,
                        docker_path=self.controller.docker_path,
                        runner=self.controller.runner,
                        os_name=self.controller.os_name,
                        environment=self.controller.environment,
                    )
                    previous.verify_container_ownership()
                    previous.up(
                        s3_export=self.previous_s3_export,
                        overrides=self.previous_s3_overrides,
                        emit_startup_telemetry=False,
                    )
                except LocalStackError as exc:
                    errors.append(str(exc))
            if failed_dir is not None:
                try:
                    _remove_safe_tree(failed_dir)
                except (LocalStackError, OSError) as exc:
                    errors.append(str(exc))
        elif not errors:
            try:
                _remove_safe_tree(self.stable_dir)
            except (LocalStackError, OSError) as exc:
                errors.append(str(exc))
        self._finished = True
        if errors:
            raise LocalStackError("; ".join(errors))


def start_native_local_splunk(
    data_dir: str,
    *,
    license_accepted: bool = False,
    index: str,
    source: str,
    sourcetype: str,
    s3_export: bool = False,
    s3_bucket: str | None = None,
    s3_prefix: str | None = None,
    aws_region: str | None = None,
    refresh_bundle: bool = True,
    timeout: int = 300,
    docker_path: str | os.PathLike[str] | None = None,
    runner: CommandRunner | None = None,
    os_name: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> NativeSplunkSetupTransaction:
    """Preflight, stage, start, and verify Local Splunk without config writes."""

    if not license_accepted:
        raise LocalStackError("explicit Splunk General Terms acceptance is required")
    source_dir = validate_bundle_assets(bundled_splunk_bridge_dir(), require_s3=s3_export)
    resolved_os = host_os() if os_name is None else os_name.lower()
    resolved_runner = runner or CommandRunner()
    base_environment = dict(os.environ if environment is None else environment)
    resolved_docker = resolve_native_docker_executable(docker_path, os_name=resolved_os)
    validate_native_docker_preflight(
        resolved_docker,
        resolved_runner,
        base_environment,
        os_name=resolved_os,
        feature_name="Local Splunk",
    )

    state_root = Path(os.path.abspath(data_dir))
    make_private_directory(state_root)
    stable_dir = state_root / "splunk-bridge"
    reject_reparse_path(stable_dir)
    if os.path.lexists(stable_dir) and not stable_dir.is_dir():
        raise LocalStackError(f"managed Local Splunk path is not a directory: {stable_dir}")
    previous: NativeLocalSplunkController | None = None
    previous_running = False
    previous_s3_export = False
    previous_s3_overrides: dict[str, str] = {}
    if stable_dir.is_dir():
        previous = NativeLocalSplunkController(
            stable_dir,
            docker_path=resolved_docker,
            runner=resolved_runner,
            os_name=resolved_os,
            environment=base_environment,
        )
        previous.verify_container_ownership()
        previous.verify_volume_ownership()
        previous.verify_port_ownership()
        previous_running = previous.is_running()
        previous_s3_export, previous_s3_overrides = previous.s3_runtime_state()
    else:
        # A same-name project with no exact managed tree cannot be proven ours.
        provisional = NativeLocalSplunkController(
            source_dir,
            docker_path=resolved_docker,
            runner=resolved_runner,
            os_name=resolved_os,
            environment=base_environment,
        )
        if provisional._project_container_ids():
            raise LocalStackError(f"Compose project {COMPOSE_PROJECT} exists without its managed stack assets")
        provisional.verify_volume_ownership()
        provisional.verify_port_ownership()

    stage_dir: Path | None = None
    backup_dir: Path | None = None
    stage_dir = state_root / f".splunk-stage-{uuid.uuid4().hex[:8]}"
    stage_source = source_dir if refresh_bundle or previous is None else stable_dir
    controller: NativeLocalSplunkController | None = None
    try:
        _copy_bundle(stage_source, stage_dir)
        prior_values = _parse_dotenv(stable_dir / ENV_FILE_REL, require_private=True) if previous else {}
        template = _parse_dotenv(stage_dir / ENV_EXAMPLE_REL)
        credentials = _credential_values(
            template,
            prior_values,
            index=index,
            source=source,
            sourcetype=sourcetype,
        )
        env_path = stage_dir / ENV_FILE_REL
        atomic_write_private_bytes(env_path, _dotenv_bytes(credentials))
        protect_private_file(env_path)
        package_splunk_app(stage_dir)
    except BaseException:
        _remove_safe_tree(stage_dir)
        raise

    overrides: dict[str, str] = {}
    if s3_export:
        overrides["S3_EXPORT_ENABLED"] = "true"
        if s3_bucket:
            overrides["S3_BUCKET"] = s3_bucket
        if s3_prefix:
            overrides["S3_PREFIX"] = s3_prefix
        if aws_region:
            overrides["AWS_REGION"] = aws_region

    try:
        if stage_dir is not None:
            if previous_running and previous is not None:
                previous.down()
            if stable_dir.exists():
                backup_candidate = state_root / f".splunk-backup-{uuid.uuid4().hex[:8]}"
                os.replace(stable_dir, backup_candidate)
                backup_dir = backup_candidate
            os.replace(stage_dir, stable_dir)
            stage_dir = None
        controller = NativeLocalSplunkController(
            stable_dir,
            docker_path=resolved_docker,
            runner=resolved_runner,
            os_name=resolved_os,
            environment=base_environment,
        )
        controller.verify_container_ownership()
        contract, created_ids = controller.up(
            timeout=timeout,
            s3_export=s3_export,
            overrides=overrides,
        )
        return NativeSplunkSetupTransaction(
            controller=controller,
            contract=contract,
            stable_dir=stable_dir,
            backup_dir=backup_dir,
            previous_running=previous_running,
            previous_s3_export=previous_s3_export,
            previous_s3_overrides=previous_s3_overrides,
            created_ids=created_ids,
        )
    except BaseException as exc:
        recovery_errors: list[str] = []
        if stage_dir is not None:
            try:
                _remove_safe_tree(stage_dir)
            except (LocalStackError, OSError) as cleanup_exc:
                recovery_errors.append(str(cleanup_exc))
        if backup_dir is not None:
            failed_dir: Path | None = None
            restored_assets = False
            try:
                if stable_dir.exists():
                    failed_dir = state_root / f".splunk-failed-{uuid.uuid4().hex[:8]}"
                    os.replace(stable_dir, failed_dir)
                os.replace(backup_dir, stable_dir)
                restored_assets = True
            except OSError as restore_exc:
                recovery_errors.append(str(restore_exc))
            if restored_assets and previous_running:
                try:
                    restored = NativeLocalSplunkController(
                        stable_dir,
                        docker_path=resolved_docker,
                        runner=resolved_runner,
                        os_name=resolved_os,
                        environment=base_environment,
                    )
                    restored.up(
                        s3_export=previous_s3_export,
                        overrides=previous_s3_overrides,
                        emit_startup_telemetry=False,
                    )
                except LocalStackError as restart_exc:
                    recovery_errors.append(str(restart_exc))
            if failed_dir is not None:
                try:
                    _remove_safe_tree(failed_dir)
                except (LocalStackError, OSError) as cleanup_exc:
                    recovery_errors.append(str(cleanup_exc))
        elif previous_running and previous is not None and stable_dir.is_dir():
            try:
                # A failed ``compose down`` commonly leaves the original
                # primary container untouched. Avoid bouncing and re-waiting
                # an already-running generation; only recreate it when the
                # failed command actually stopped the project.
                if not previous.is_running():
                    previous.up(
                        s3_export=previous_s3_export,
                        overrides=previous_s3_overrides,
                        emit_startup_telemetry=False,
                    )
            except LocalStackError as restart_exc:
                recovery_errors.append(str(restart_exc))
        elif previous is None and stable_dir.is_dir() and controller is not None:
            try:
                remaining = controller._project_container_ids()
            except LocalStackError:
                remaining = {"ownership-unavailable"}
            if not remaining:
                try:
                    _remove_safe_tree(stable_dir)
                except (LocalStackError, OSError) as cleanup_exc:
                    recovery_errors.append(str(cleanup_exc))
        if recovery_errors:
            raise LocalStackError(
                "Local Splunk startup failed and rollback was incomplete: " + "; ".join(recovery_errors)
            ) from exc
        raise


def preflight_native_local_splunk_setup(
    data_dir: str,
    *,
    license_accepted: bool = False,
    require_s3: bool = False,
    docker_path: str | os.PathLike[str] | None = None,
    runner: CommandRunner | None = None,
    os_name: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> None:
    """Validate a native setup without changing assets, containers, or config."""

    if not license_accepted:
        raise LocalStackError("explicit Splunk General Terms acceptance is required")
    source_dir = validate_bundle_assets(bundled_splunk_bridge_dir(), require_s3=require_s3)
    resolved_os = host_os() if os_name is None else os_name.lower()
    resolved_runner = runner or CommandRunner()
    base_environment = dict(os.environ if environment is None else environment)
    resolved_docker = resolve_native_docker_executable(docker_path, os_name=resolved_os)
    validate_native_docker_preflight(
        resolved_docker,
        resolved_runner,
        base_environment,
        os_name=resolved_os,
        feature_name="Local Splunk",
    )
    stable_dir = Path(os.path.abspath(data_dir)) / "splunk-bridge"
    reject_reparse_path(stable_dir)
    if os.path.lexists(stable_dir) and not stable_dir.is_dir():
        raise LocalStackError(f"managed Local Splunk path is not a directory: {stable_dir}")
    stack_dir = stable_dir if stable_dir.is_dir() else source_dir
    controller = NativeLocalSplunkController(
        stack_dir,
        docker_path=resolved_docker,
        runner=resolved_runner,
        os_name=resolved_os,
        environment=base_environment,
    )
    owned = controller.verify_container_ownership()
    if not stable_dir.is_dir() and owned:
        raise LocalStackError(f"Compose project {COMPOSE_PROJECT} exists without its managed stack assets")
    controller.verify_volume_ownership()
    controller.verify_port_ownership()


def prepare_native_local_splunk_stop(
    data_dir: str,
    *,
    docker_path: str | os.PathLike[str] | None = None,
    runner: CommandRunner | None = None,
    os_name: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> tuple[NativeLocalSplunkController | None, bool]:
    """Validate exact ownership and return a controller without mutating runtime."""

    stable_dir = Path(os.path.abspath(data_dir)) / "splunk-bridge"
    reject_reparse_path(stable_dir)
    if os.path.lexists(stable_dir) and not stable_dir.is_dir():
        raise LocalStackError(f"managed Local Splunk path is not a directory: {stable_dir}")
    if not stable_dir.is_dir():
        source_dir = validate_bundle_assets(bundled_splunk_bridge_dir())
        provisional = NativeLocalSplunkController(
            source_dir,
            docker_path=docker_path,
            runner=runner,
            os_name=os_name,
            environment=environment,
        )
        provisional.preflight()
        if provisional._project_container_ids():
            raise LocalStackError(
                f"Compose project {COMPOSE_PROJECT} is running without its managed stack assets; stop refused"
            )
        provisional.verify_volume_ownership()
        provisional.verify_port_ownership()
        return None, False
    controller = NativeLocalSplunkController(
        stable_dir,
        docker_path=docker_path,
        runner=runner,
        os_name=os_name,
        environment=environment,
    )
    controller.preflight()
    controller.verify_container_ownership()
    controller.verify_volume_ownership()
    controller.verify_port_ownership()
    return controller, controller.is_running()


def stop_native_local_splunk(
    data_dir: str,
    *,
    docker_path: str | os.PathLike[str] | None = None,
    runner: CommandRunner | None = None,
    os_name: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Stop only the exact owned project and preserve all named volumes."""

    controller, was_running = prepare_native_local_splunk_stop(
        data_dir,
        docker_path=docker_path,
        runner=runner,
        os_name=os_name,
        environment=environment,
    )
    if controller is None or not was_running:
        return False
    controller.down()
    return True


def load_native_local_splunk_credentials(data_dir: str) -> dict[str, str]:
    """Read the protected runtime contract for explicit credential display."""

    stable_dir = Path(os.path.abspath(data_dir)) / "splunk-bridge"
    validate_bundle_assets(stable_dir)
    env_file = stable_dir / ENV_FILE_REL
    protect_private_file(env_file)
    return _parse_dotenv(env_file, require_private=True)


__all__ = [
    "COMPOSE_PROJECT",
    "LOCAL_TOKEN_ENV",
    "NativeLocalSplunkController",
    "NativeSplunkContract",
    "NativeSplunkSetupTransaction",
    "load_native_local_splunk_credentials",
    "package_splunk_app",
    "preflight_native_local_splunk_setup",
    "prepare_native_local_splunk_stop",
    "start_native_local_splunk",
    "stop_native_local_splunk",
    "validate_bundle_assets",
]
