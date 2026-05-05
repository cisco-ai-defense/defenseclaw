# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Shared AI signature catalog helpers for CLI rendering/tests."""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

CATALOG_VERSION = 1
MANAGED_PACK_DIRNAME = "signature-packs"
WORKSPACE_PACK_PATH = Path(".defenseclaw") / "ai-signatures.json"
MAX_SIGNATURE_PACKS = 64
MAX_SIGNATURE_BYTES = 1024 * 1024

ALLOWED_CATEGORIES = {
    "supported_connector",
    "ai_cli",
    "active_process",
    "editor_extension",
    "mcp_server",
    "skill",
    "rule",
    "plugin",
    "package_dependency",
    "env_var_name",
    "shell_history_match",
    "provider_domain",
    "workspace_artifact",
    "desktop_app",
    "local_ai_endpoint",
}


class SignaturePackError(ValueError):
    """Raised when an AI signature catalog or pack is malformed."""


@dataclass(frozen=True)
class AISignature:
    id: str
    name: str
    vendor: str
    category: str
    confidence: float
    source: str = "builtin"
    supported_connector: str = ""
    binary_names: tuple[str, ...] = ()
    process_names: tuple[str, ...] = ()
    application_names: tuple[str, ...] = ()
    config_paths: tuple[str, ...] = ()
    extension_ids: tuple[str, ...] = ()
    mcp_paths: tuple[str, ...] = ()
    package_names: tuple[str, ...] = ()
    env_var_names: tuple[str, ...] = ()
    domain_patterns: tuple[str, ...] = ()
    history_patterns: tuple[str, ...] = ()
    local_endpoints: tuple[str, ...] = ()


def load_ai_signatures(
    *,
    data_dir: str | Path | None = None,
    signature_packs: list[str] | tuple[str, ...] = (),
    allow_workspace_signatures: bool = False,
    scan_roots: list[str] | tuple[str, ...] = (),
    disabled_signature_ids: list[str] | tuple[str, ...] = (),
) -> list[AISignature]:
    """Load the built-in catalog plus configured operator signature packs."""
    builtins = _parse_catalog_text(_catalog_text(), source="builtin")
    disabled = {_normalize_id(s) for s in disabled_signature_ids if _normalize_id(s)}
    merged: list[AISignature] = []
    seen: dict[str, str] = {}
    for sig in builtins:
        if sig.id in disabled:
            continue
        merged.append(sig)
        seen[sig.id] = sig.source

    pack_paths = _signature_pack_paths(
        data_dir=data_dir,
        signature_packs=signature_packs,
        allow_workspace_signatures=allow_workspace_signatures,
        scan_roots=scan_roots,
    )
    if len(pack_paths) > MAX_SIGNATURE_PACKS:
        raise SignaturePackError(f"too many signature packs ({len(pack_paths)} > {MAX_SIGNATURE_PACKS})")
    for pack_path in pack_paths:
        for sig in validate_signature_pack(pack_path):
            if sig.id in disabled:
                continue
            if sig.id in seen:
                raise SignaturePackError(
                    f"duplicate signature id {sig.id!r} in {pack_path} (already defined in {seen[sig.id]})"
                )
            merged.append(sig)
            seen[sig.id] = sig.source
    return merged


def validate_signature_pack(path: str | Path) -> list[AISignature]:
    """Validate and return signatures from a user-supplied pack."""
    pack = Path(path).expanduser()
    try:
        stat = pack.stat()
    except OSError as exc:
        raise SignaturePackError(f"cannot stat {pack}: {exc}") from exc
    if pack.is_dir():
        raise SignaturePackError(f"{pack} is a directory")
    if stat.st_size > MAX_SIGNATURE_BYTES:
        raise SignaturePackError(f"{pack} exceeds {MAX_SIGNATURE_BYTES} bytes")
    try:
        text = pack.read_text(encoding="utf-8")
    except OSError as exc:
        raise SignaturePackError(f"cannot read {pack}: {exc}") from exc
    return _parse_catalog_text(text, source=str(pack))


def install_signature_pack(
    source: str | Path,
    *,
    data_dir: str | Path,
    replace: bool = False,
) -> Path:
    """Install *source* into the managed pack directory after validation."""
    src = Path(source).expanduser()
    pack = _load_pack_payload(src)
    pack_id = _normalize_id(str(pack.get("id") or src.stem))
    if not pack_id:
        raise SignaturePackError("signature pack id or filename must normalize to a non-empty id")
    signatures = validate_signature_pack(src)

    dest_dir = Path(data_dir).expanduser() / MANAGED_PACK_DIRNAME
    dest = dest_dir / f"{pack_id}.json"
    if dest.exists() and not replace:
        raise SignaturePackError(f"signature pack already installed: {dest}")

    dest_resolved = dest.resolve() if dest.exists() else dest.absolute()
    existing = load_ai_signatures(data_dir=data_dir, signature_packs=())
    existing_ids = {sig.id: sig.source for sig in existing if Path(sig.source) != dest_resolved}
    conflicts = sorted(sig.id for sig in signatures if sig.id in existing_ids)
    if conflicts:
        joined = ", ".join(conflicts)
        raise SignaturePackError(f"signature id conflict with existing catalog: {joined}")

    dest_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{pack_id}.", suffix=".tmp", dir=str(dest_dir))
    try:
        with os.fdopen(fd, "wb") as tmp:
            with src.open("rb") as inp:
                shutil.copyfileobj(inp, tmp)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, dest)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return dest


def signature_pack_dir(data_dir: str | Path) -> Path:
    return Path(data_dir).expanduser() / MANAGED_PACK_DIRNAME


def _parse_catalog_text(text: str, *, source: str) -> list[AISignature]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SignaturePackError(f"{source}: invalid JSON: {exc}") from exc
    if payload.get("version") != CATALOG_VERSION:
        raise SignaturePackError(f"{source}: unsupported AI signature catalog version")
    raw_sigs = payload.get("signatures", [])
    if not isinstance(raw_sigs, list) or not raw_sigs:
        raise SignaturePackError(f"{source}: signatures must be a non-empty list")
    out: list[AISignature] = []
    seen: set[str] = set()
    for raw in raw_sigs:
        sig = _signature_from_raw(raw, source=source)
        if sig.id in seen:
            raise SignaturePackError(f"{source}: duplicate signature id {sig.id!r}")
        seen.add(sig.id)
        out.append(sig)
    return out


def _signature_from_raw(raw: Any, *, source: str) -> AISignature:
    if not isinstance(raw, dict):
        raise SignaturePackError(f"{source}: each signature must be an object")
    sig = AISignature(
        id=_normalize_id(str(raw.get("id", ""))),
        name=str(raw.get("name", "")).strip(),
        vendor=str(raw.get("vendor", "")).strip(),
        category=_normalize_category(str(raw.get("category", ""))),
        confidence=float(raw.get("confidence", 0.5) or 0.5),
        source=source,
        supported_connector=_normalize_id(str(raw.get("supported_connector", ""))),
        binary_names=_tuple(raw.get("binary_names", [])),
        process_names=_tuple(raw.get("process_names", [])),
        application_names=_tuple(raw.get("application_names", [])),
        config_paths=_tuple(raw.get("config_paths", [])),
        extension_ids=_tuple(raw.get("extension_ids", [])),
        mcp_paths=_tuple(raw.get("mcp_paths", [])),
        package_names=_tuple(raw.get("package_names", [])),
        env_var_names=_tuple(raw.get("env_var_names", [])),
        domain_patterns=_tuple(raw.get("domain_patterns", [])),
        history_patterns=_tuple(raw.get("history_patterns", [])),
        local_endpoints=_tuple(raw.get("local_endpoints", [])),
    )
    _validate_signature(sig)
    return sig


def _validate_signature(sig: AISignature) -> None:
    if not sig.id:
        raise SignaturePackError("signature id is required")
    if len(sig.id) > 96:
        raise SignaturePackError(f"{sig.id}: id is too long")
    if not sig.name:
        raise SignaturePackError(f"{sig.id}: name is required")
    if not sig.vendor:
        raise SignaturePackError(f"{sig.id}: vendor is required")
    if sig.category not in ALLOWED_CATEGORIES:
        raise SignaturePackError(f"{sig.id}: unsupported category {sig.category!r}")
    if sig.confidence <= 0:
        raise SignaturePackError(f"{sig.id}: confidence must be positive")
    if sig.confidence > 1:
        raise SignaturePackError(f"{sig.id}: confidence must be <= 1")
    for field in (
        "binary_names",
        "process_names",
        "application_names",
        "config_paths",
        "extension_ids",
        "mcp_paths",
        "package_names",
        "env_var_names",
        "domain_patterns",
        "history_patterns",
        "local_endpoints",
    ):
        values = getattr(sig, field)
        if len(values) > 256:
            raise SignaturePackError(f"{sig.id}: {field} has too many entries")
        for value in values:
            if len(value) > 1024:
                raise SignaturePackError(f"{sig.id}: {field} entry is too long")
            if "\x00" in value:
                raise SignaturePackError(f"{sig.id}: {field} entry contains NUL")


def _signature_pack_paths(
    *,
    data_dir: str | Path | None,
    signature_packs: list[str] | tuple[str, ...],
    allow_workspace_signatures: bool,
    scan_roots: list[str] | tuple[str, ...],
) -> list[Path]:
    candidates: list[tuple[str, bool]] = []
    if data_dir:
        candidates.append((str(signature_pack_dir(data_dir) / "*.json"), False))
    for pack in signature_packs:
        candidates.append((str(pack), True))
    if allow_workspace_signatures:
        for root in [*scan_roots, os.getcwd()]:
            if root:
                candidates.append((str(Path(root).expanduser() / WORKSPACE_PACK_PATH), False))

    out: list[Path] = []
    seen: set[Path] = set()
    for pattern, required in candidates:
        matches = _expand_pack_candidate(pattern)
        if not matches and required:
            raise SignaturePackError(f"signature pack path matched nothing: {pattern}")
        for path in matches:
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                out.append(resolved)
    return sorted(out)


def _expand_pack_candidate(pattern: str) -> list[Path]:
    path = Path(pattern).expanduser()
    if path.exists() and path.is_dir():
        return sorted(p for p in path.glob("*.json") if p.is_file())
    if any(ch in str(path) for ch in "*?["):
        return sorted(Path(p).resolve() for p in glob.glob(str(path)) if Path(p).is_file())
    return [path] if path.exists() and path.is_file() else []


def _load_pack_payload(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SignaturePackError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SignaturePackError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SignaturePackError(f"{path}: pack must be a JSON object")
    return payload


def _tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise SignaturePackError("signature list fields must be arrays")
    return tuple(str(item) for item in value)


def _normalize_id(value: str) -> str:
    value = value.strip().lower().replace("_", "-")
    return re.sub(r"[^a-z0-9.-]+", "-", value).strip("-")


def _normalize_category(value: str) -> str:
    value = value.strip().lower().replace("-", "_")
    return re.sub(r"[^a-z0-9_]+", "_", value).strip("_")


def normalize_signature_id(value: str) -> str:
    return _normalize_id(value)


def _catalog_text() -> str:
    source_tree_catalog = Path(__file__).resolve().parents[3] / "internal" / "inventory" / "ai_signatures.json"
    if source_tree_catalog.exists():
        return source_tree_catalog.read_text(encoding="utf-8")
    return resources.files("defenseclaw").joinpath("inventory/ai_signatures.json").read_text(encoding="utf-8")
