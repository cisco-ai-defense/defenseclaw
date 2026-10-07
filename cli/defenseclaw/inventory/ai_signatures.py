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
import hashlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Mapping
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
    "local_model",
}


class SignaturePackError(ValueError):
    """Raised when an AI signature catalog or pack is malformed."""


@dataclass(frozen=True)
class AISignatureComponent:
    """High-fidelity sub-identity attached to a signature.

    Mirrors the Go ``AISignatureComponent``: when a manifest match
    resolves to one of these, the resulting signal carries the
    ``framework``/``vendor`` here instead of the catch-all signature
    name. ``ecosystem`` and ``name`` are required; ``framework`` and
    ``vendor`` are optional overrides.
    """

    ecosystem: str
    name: str
    framework: str = ""
    vendor: str = ""


@dataclass(frozen=True)
class AISignature:
    id: str
    name: str
    vendor: str
    category: str
    # `confidence` is the legacy seed; new catalogs may instead
    # populate `curator_confidence` (operator-meaningful base prior on
    # identity) and `specificity` (how unique the matched value is, in
    # (0, 1]). When a catalog ships only `confidence`, the loader
    # mirrors it into `curator_confidence` and defaults `specificity`
    # to 0.7. The two-axis confidence engine on the Go side reads
    # `curator_confidence` and `specificity`; the Python catalog
    # carries them so renderers and tests agree on the surface.
    confidence: float
    curator_confidence: float = 0.0
    specificity: float = 0.0
    source: str = "builtin"
    supported_connector: str = ""
    binary_names: tuple[str, ...] = ()
    process_names: tuple[str, ...] = ()
    application_names: tuple[str, ...] = ()
    config_paths: tuple[str, ...] = ()
    extension_ids: tuple[str, ...] = ()
    # IDE inventory AI flags (JetBrains plugin.xml ids, Zed extension ids,
    # Vim/Neovim plugin folder names). Mirrors ai_catalog.go.
    jetbrains_plugin_ids: tuple[str, ...] = ()
    zed_extension_ids: tuple[str, ...] = ()
    vim_plugins: tuple[str, ...] = ()
    mcp_paths: tuple[str, ...] = ()
    # SkillPaths / RulePaths / PluginPaths are directory globs whose
    # per-user existence + non-emptiness produce SignalSkill / SignalRule /
    # SignalPlugin signals. Semantics mirror mcp_paths (path-based
    # detection, no content scan). Kept in sync with the Go dataclass
    # in internal/inventory/ai_catalog.go — the packaged JSON on both
    # sides is byte-identical per test_packaged_catalog_matches_go_catalog.
    skill_paths: tuple[str, ...] = ()
    rule_paths: tuple[str, ...] = ()
    plugin_paths: tuple[str, ...] = ()
    package_names: tuple[str, ...] = ()
    env_var_names: tuple[str, ...] = ()
    domain_patterns: tuple[str, ...] = ()
    history_patterns: tuple[str, ...] = ()
    local_endpoints: tuple[str, ...] = ()
    components: tuple[AISignatureComponent, ...] = ()


@dataclass(frozen=True)
class RefusedPack:
    """A configured pack the gateway does not load: its digest is not the
    one ``ai_discovery.signature_pack_digests`` pins for it, or a managed
    device has no pin for it (internal/inventory/ai_catalog.go pinRefusal)."""

    path: str
    reason: str
    digest: str = ""
    pinned: str = ""


def load_ai_signatures(
    *,
    signature_packs: list[str] | tuple[str, ...] = (),
    allow_workspace_signatures: bool = False,
    scan_roots: list[str] | tuple[str, ...] = (),
    disabled_signature_ids: list[str] | tuple[str, ...] = (),
) -> list[AISignature]:
    """Load the built-in catalog plus the configured operator signature packs
    (``ai_discovery.signature_packs``, the only operator source since
    config_version 9; the managed folder is not globbed)."""
    return load_ai_signature_catalog(
        signature_packs=signature_packs,
        allow_workspace_signatures=allow_workspace_signatures,
        scan_roots=scan_roots,
        disabled_signature_ids=disabled_signature_ids,
    )[0]


def load_ai_signature_catalog(
    *,
    signature_packs: list[str] | tuple[str, ...] = (),
    allow_workspace_signatures: bool = False,
    scan_roots: list[str] | tuple[str, ...] = (),
    disabled_signature_ids: list[str] | tuple[str, ...] = (),
    pack_digests: Mapping[str, str] | None = None,
    require_digests: bool = False,
) -> tuple[list[AISignature], list[RefusedPack]]:
    """:func:`load_ai_signatures` as the gateway loads it: a pack that fails
    its pin is left out and returned as refused, the rest of the catalog
    still loads."""
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
        signature_packs=signature_packs,
        allow_workspace_signatures=allow_workspace_signatures,
        scan_roots=scan_roots,
    )
    if len(pack_paths) > MAX_SIGNATURE_PACKS:
        raise SignaturePackError(f"too many signature packs ({len(pack_paths)} > {MAX_SIGNATURE_PACKS})")
    pins = _pinned_digests(pack_digests)
    refused: list[RefusedPack] = []
    for pack_path in pack_paths:
        pack, raw = _read_pack(pack_path)
        if (refusal := _pin_refusal(pack, raw, pins, require_digests)) is not None:
            refused.append(refusal)
            continue
        for sig in _parse_catalog_text(raw.decode("utf-8"), source=str(pack)):
            if sig.id in disabled:
                continue
            if sig.id in seen:
                raise SignaturePackError(
                    f"duplicate signature id {sig.id!r} in {pack_path} (already defined in {seen[sig.id]})"
                )
            merged.append(sig)
            seen[sig.id] = sig.source
    return merged, refused


def pack_pins(cfg: Any) -> tuple[dict[str, str], bool]:
    """The pins and whether a pack needs one: ``ai_discovery.signature_pack_digests``,
    and a managed standalone computer, which loads only pinned packs."""
    from defenseclaw import config_writer
    from defenseclaw.config import config_path_for_data_dir

    pins = dict(getattr(cfg.ai_discovery, "signature_pack_digests", None) or {})
    try:
        current = Path(config_path_for_data_dir(cfg.data_dir)).read_bytes()
    except OSError:
        current = b""
    return pins, config_writer.standalone_managed(current)


def refused_packs(cfg: Any) -> tuple[int, list[RefusedPack]]:
    """How many packs ``ai_discovery`` configures and which of them the gateway
    refuses to load (pin mismatch). A pack that cannot be read is not counted
    as refused: the loader reports it."""
    discovery = cfg.ai_discovery
    pins, require = pack_pins(cfg)
    try:
        paths = _signature_pack_paths(
            signature_packs=discovery.signature_packs,
            allow_workspace_signatures=discovery.allow_workspace_signatures,
            scan_roots=discovery.scan_roots,
        )
    except SignaturePackError:
        return 0, []
    pinned, refused = _pinned_digests(pins), []
    for path in paths:
        try:
            pack, raw = _read_pack(path)
        except SignaturePackError:
            continue
        if (refusal := _pin_refusal(pack, raw, pinned, require)) is not None:
            refused.append(refusal)
    return len(paths), refused


def _pinned_digests(pins: Mapping[str, str] | None) -> dict[str, str]:
    """``signature_pack_digests`` keyed by resolved, home-expanded path, as
    the loader looks them up."""
    return {
        str(Path(str(path).strip()).expanduser().resolve()): str(digest).strip().lower()
        for path, digest in (pins or {}).items()
    }


def _pin_refusal(pack: Path, raw: bytes, pins: Mapping[str, str], required: bool) -> RefusedPack | None:
    want = pins.get(str(pack.resolve()), "")
    if not want:
        if required:
            return RefusedPack(
                str(pack), "a managed device loads only packs pinned in ai_discovery.signature_pack_digests"
            )
        return None
    got = "sha256:" + hashlib.sha256(raw).hexdigest()
    if got == want:
        return None
    return RefusedPack(str(pack), f"its digest {got} does not match the pinned {want}", digest=got, pinned=want)


def validate_signature_pack(path: str | Path) -> list[AISignature]:
    """Validate and return signatures from a user-supplied pack."""
    pack, raw = _read_pack(path)
    return _parse_catalog_text(raw.decode("utf-8"), source=str(pack))


def _read_pack(path: str | Path) -> tuple[Path, bytes]:
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
        return pack, pack.read_bytes()
    except OSError as exc:
        raise SignaturePackError(f"cannot read {pack}: {exc}") from exc


def install_signature_pack(
    source: str | Path,
    *,
    data_dir: str | Path,
    signature_packs: list[str] | tuple[str, ...] = (),
    replace: bool = False,
) -> Path:
    """Install *source* into the managed pack directory after validation.

    The caller adds the returned path to ``ai_discovery.signature_packs``;
    *signature_packs* are the packs already configured, checked for id
    conflicts."""
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
    existing = load_ai_signatures(signature_packs=[p for p in signature_packs if Path(p).expanduser() != dest])
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
    confidence = float(raw.get("confidence", 0.5) or 0.5)
    curator_confidence = float(raw.get("curator_confidence", 0.0) or 0.0)
    if curator_confidence <= 0:
        # Back-compat: legacy catalogs only ship `confidence`. Mirror
        # it into `curator_confidence` so the Python view always
        # exposes the same two-axis fields the Go engine consumes.
        curator_confidence = confidence
    if curator_confidence > 1:
        curator_confidence = 1.0
    specificity = float(raw.get("specificity", 0.0) or 0.0)
    if specificity <= 0:
        specificity = 0.7  # neutral default
    if specificity > 1:
        specificity = 1.0
    sig = AISignature(
        id=_normalize_id(str(raw.get("id", ""))),
        name=str(raw.get("name", "")).strip(),
        vendor=str(raw.get("vendor", "")).strip(),
        category=_normalize_category(str(raw.get("category", ""))),
        confidence=confidence,
        curator_confidence=curator_confidence,
        specificity=specificity,
        source=source,
        supported_connector=_normalize_id(str(raw.get("supported_connector", ""))),
        binary_names=_tuple(raw.get("binary_names", [])),
        process_names=_tuple(raw.get("process_names", [])),
        application_names=_tuple(raw.get("application_names", [])),
        config_paths=_tuple(raw.get("config_paths", [])),
        extension_ids=_tuple(raw.get("extension_ids", [])),
        jetbrains_plugin_ids=_tuple(raw.get("jetbrains_plugin_ids", [])),
        zed_extension_ids=_tuple(raw.get("zed_extension_ids", [])),
        vim_plugins=_tuple(raw.get("vim_plugins", [])),
        mcp_paths=_tuple(raw.get("mcp_paths", [])),
        skill_paths=_tuple(raw.get("skill_paths", [])),
        rule_paths=_tuple(raw.get("rule_paths", [])),
        plugin_paths=_tuple(raw.get("plugin_paths", [])),
        package_names=_tuple(raw.get("package_names", [])),
        env_var_names=_tuple(raw.get("env_var_names", [])),
        domain_patterns=_tuple(raw.get("domain_patterns", [])),
        history_patterns=_tuple(raw.get("history_patterns", [])),
        local_endpoints=_tuple(raw.get("local_endpoints", [])),
        components=_components_tuple(raw.get("components", [])),
    )
    _validate_signature(sig)
    return sig


def _components_tuple(value: Any) -> tuple[AISignatureComponent, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise SignaturePackError("components must be an array")
    out: list[AISignatureComponent] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise SignaturePackError("each component must be an object")
        out.append(
            AISignatureComponent(
                ecosystem=str(entry.get("ecosystem", "")).strip(),
                name=str(entry.get("name", "")).strip(),
                framework=str(entry.get("framework", "")).strip(),
                vendor=str(entry.get("vendor", "")).strip(),
            )
        )
    return tuple(out)


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
    if sig.curator_confidence <= 0 or sig.curator_confidence > 1:
        raise SignaturePackError(f"{sig.id}: curator_confidence must be in (0, 1]")
    if sig.specificity <= 0 or sig.specificity > 1:
        raise SignaturePackError(f"{sig.id}: specificity must be in (0, 1]")
    for field in (
        "binary_names",
        "process_names",
        "application_names",
        "config_paths",
        "extension_ids",
        "jetbrains_plugin_ids",
        "zed_extension_ids",
        "vim_plugins",
        "mcp_paths",
        "skill_paths",
        "rule_paths",
        "plugin_paths",
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
    if len(sig.components) > 1024:
        raise SignaturePackError(f"{sig.id}: components has too many entries")
    for idx, comp in enumerate(sig.components):
        if not comp.ecosystem:
            raise SignaturePackError(f"{sig.id}: components[{idx}].ecosystem is required")
        if not comp.name:
            raise SignaturePackError(f"{sig.id}: components[{idx}].name is required")
        if (
            len(comp.ecosystem) > 64
            or len(comp.name) > 256
            or len(comp.framework) > 256
            or len(comp.vendor) > 128
        ):
            raise SignaturePackError(f"{sig.id}: components[{idx}] field too long")
        for value in (comp.ecosystem, comp.name, comp.framework, comp.vendor):
            if "\x00" in value:
                raise SignaturePackError(f"{sig.id}: components[{idx}] entry contains NUL")


def _signature_pack_paths(
    *,
    signature_packs: list[str] | tuple[str, ...],
    allow_workspace_signatures: bool,
    scan_roots: list[str] | tuple[str, ...],
) -> list[Path]:
    candidates: list[tuple[str, bool]] = []
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
