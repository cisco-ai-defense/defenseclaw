# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Registry manifest dataclasses + schema validation.

A manifest is the vendor-neutral document published by an external
catalog source (corporate HTTPS YAML/JSON, smithery.ai, a git repo with
``defenseclaw-registry.yaml`` at the root, etc.). Its schema is pinned
in :mod:`schemas/registry-manifest.schema.json`. This module owns:

* the in-memory representation (:class:`Manifest`,
  :class:`ManifestEntry`) used throughout the ingest pipeline;
* loose-tolerant parsing from YAML or JSON byte strings, with strict
  validation against the JSON Schema (when available — the dependency
  is optional so that ``defenseclaw registry list`` doesn't fail in
  reduced-deps installs);
* a hand-written fallback validator that enforces the same set of
  invariants the JSON Schema declares — name/command character class,
  enum membership, length caps — so the security-relevant guards are
  always on.

The character-class constraints intentionally match those in
``cli/defenseclaw/registry.py::_CLAWHUB_NAME_RE`` and the existing
``_safe_tar_extract`` helper so the same untrusted-input rules apply
uniformly to every fetch path.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Shared regexes — kept as module-level compiled patterns so adapters and
# tests can reuse them without re-importing this module's internals.
# ---------------------------------------------------------------------------

NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,127}$")
"""Stable identifier for skills / MCP servers in a manifest.

Matches the schema's ``pattern`` and the existing CLAWHUB regex in
``cli/defenseclaw/registry.py``. Restrictive on purpose — the value is
pasted into tar prefixes, scanner subprocess argv, and audit-store
queries so anything outside ``[A-Za-z0-9._-]`` is rejected.
"""

COMMAND_RE = re.compile(r"^[A-Za-z0-9_./@-]*$")
"""Allowed character class for an MCP entry's ``command`` field.

Conservative on purpose — anything outside this class can smuggle
shell metacharacters into the scanner subprocess.
"""

ENV_VAR_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
SOURCE_URL_RE = re.compile(r"^(clawhub://|https?://)")
HTTP_URL_RE = re.compile(r"^https?://")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

KNOWN_TRANSPORTS = {"stdio", "http", "sse", "streamable-http", "websocket"}
KNOWN_CONNECTORS = {
    "openclaw",
    "claudecode",
    "codex",
    "zeptoclaw",
    "hermes",
    "cursor",
    "windsurf",
    "geminicli",
    "copilot",
    "openhands",
    "antigravity",
    "opencode",
    "omnigent",
}
KNOWN_TYPES = {"skill", "mcp"}

MAX_ENTRIES = 10000
MAX_ARGS = 64
MAX_ENV_VARS = 32
MAX_TAGS = 64
MAX_STRING = 2048


class ManifestError(ValueError):
    """Raised when a manifest fails to load or validate."""


@dataclass
class ManifestEntry:
    """One skill / MCP entry in a registry manifest.

    Field semantics mirror the JSON Schema. Empty strings stand in for
    missing optional fields so callers can use ``if entry.url`` cheaply
    without juggling :data:`None`.
    """

    name: str
    type: str
    source_url: str = ""
    sha256: str = ""
    version: str = ""
    license: str = ""
    publisher: str = ""
    description: str = ""
    homepage: str = ""
    connector: str = ""
    tags: list[str] = field(default_factory=list)

    transport: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    env_required: list[str] = field(default_factory=list)
    url: str = ""

    def is_skill(self) -> bool:
        return self.type == "skill"

    def is_mcp(self) -> bool:
        return self.type == "mcp"

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "type": self.type}
        for key in (
            "source_url",
            "sha256",
            "version",
            "license",
            "publisher",
            "description",
            "homepage",
            "connector",
            "transport",
            "command",
            "url",
        ):
            value = getattr(self, key)
            if value:
                out[key] = value
        if self.args:
            out["args"] = list(self.args)
        if self.env_required:
            out["env_required"] = list(self.env_required)
        if self.tags:
            out["tags"] = list(self.tags)
        return out


@dataclass
class Manifest:
    """Parsed + validated catalog manifest."""

    schema_version: int = 1
    generated_at: str = ""
    publisher: str = ""
    default_connector: str = ""
    entries: list[ManifestEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"schema_version": self.schema_version}
        if self.generated_at:
            out["generated_at"] = self.generated_at
        if self.publisher:
            out["publisher"] = self.publisher
        if self.default_connector:
            out["default_connector"] = self.default_connector
        out["entries"] = [e.to_dict() for e in self.entries]
        return out

    def filter_by_content(self, content: str) -> list[ManifestEntry]:
        """Return entries matching the source's declared content type.

        ``content`` is one of ``skill``, ``mcp``, ``both``. ``both``
        returns everything; the others filter on :attr:`ManifestEntry.type`.
        """
        c = content.strip().lower()
        if c == "both":
            return list(self.entries)
        if c == "skill":
            return [e for e in self.entries if e.is_skill()]
        if c == "mcp":
            return [e for e in self.entries if e.is_mcp()]
        return list(self.entries)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_manifest(raw: str | bytes) -> Manifest:
    """Parse *raw* as JSON or YAML and return a validated :class:`Manifest`.

    YAML parsing uses :func:`yaml.safe_load` (no arbitrary-type
    deserialization) and JSON parsing uses :func:`json.loads`. Either
    representation is accepted because publishers may serve YAML for
    humans and JSON for machines from the same endpoint.

    Raises :class:`ManifestError` on parse / schema / invariant failures.
    """
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ManifestError("manifest is not valid UTF-8") from exc

    text = raw.strip()
    if not text:
        raise ManifestError("manifest is empty")

    data: Any
    if text[0] in "{[":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ManifestError(f"invalid JSON manifest: {exc}") from exc
    else:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ManifestError(f"invalid YAML manifest: {exc}") from exc

    return _build_manifest(data)


def load_manifest_file(path: str | Path) -> Manifest:
    """Read *path* from disk and return a validated :class:`Manifest`."""
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise ManifestError(f"could not read manifest {p}: {exc}") from exc
    return parse_manifest(raw)


# ---------------------------------------------------------------------------
# Validation — hand-written so the security guards stay on even when the
# optional jsonschema package is missing. When jsonschema IS available we
# also run it for full schema fidelity (extra errors / better messages).
# ---------------------------------------------------------------------------


def _build_manifest(data: Any) -> Manifest:
    if not isinstance(data, dict):
        raise ManifestError("manifest must be a mapping at the top level")

    schema_version = data.get("schema_version")
    if schema_version != 1:
        raise ManifestError(f"unsupported schema_version {schema_version!r} (expected 1)")

    publisher = _opt_str(data.get("publisher"), "publisher", max_len=256)
    generated_at = _opt_str(data.get("generated_at"), "generated_at", max_len=64)
    default_connector = _opt_str(
        data.get("default_connector"),
        "default_connector",
        max_len=64,
    )
    if default_connector and default_connector not in KNOWN_CONNECTORS:
        raise ManifestError(f"default_connector {default_connector!r} is not one of {sorted(KNOWN_CONNECTORS)}")

    raw_entries = data.get("entries")
    if not isinstance(raw_entries, list):
        raise ManifestError("entries must be a list")
    if len(raw_entries) > MAX_ENTRIES:
        raise ManifestError(f"manifest has {len(raw_entries)} entries (max {MAX_ENTRIES})")

    seen: set[tuple[str, str]] = set()
    entries: list[ManifestEntry] = []
    for idx, raw_entry in enumerate(raw_entries):
        try:
            entry = _build_entry(raw_entry, default_connector)
        except ManifestError as exc:
            raise ManifestError(f"entries[{idx}]: {exc}") from exc
        key = (entry.type, entry.name)
        if key in seen:
            raise ManifestError(f"entries[{idx}]: duplicate {entry.type} entry {entry.name!r}")
        seen.add(key)
        entries.append(entry)

    manifest = Manifest(
        schema_version=schema_version,
        generated_at=generated_at,
        publisher=publisher,
        default_connector=default_connector,
        entries=entries,
    )

    # Optional belt-and-suspenders pass via jsonschema when available.
    # Failures here surface to callers but the hand-written checks above
    # already covered the security-relevant invariants.
    _maybe_jsonschema_validate(manifest.to_dict())

    return manifest


def validate_entry(raw: dict[str, Any], default_connector: str = "") -> ManifestEntry:
    """Validate *raw* (a dict) and return a clean :class:`ManifestEntry`.

    Public wrapper around the same checks :func:`_build_manifest`
    applies per-entry. Adapters that synthesize entries from a
    third-party API response (smithery.ai, clawhub, etc.) should run
    every candidate through this function before appending it to the
    manifest so the same character-class / enum / length / required-
    field invariants apply uniformly to every ingest path.

    Raises :class:`ManifestError` on any policy violation.
    """
    return _build_entry(raw, default_connector)


def _build_entry(raw: Any, default_connector: str) -> ManifestEntry:
    if not isinstance(raw, dict):
        raise ManifestError("entry must be a mapping")
    type_ = raw.get("type")
    if type_ not in KNOWN_TYPES:
        raise ManifestError(f"type must be one of {sorted(KNOWN_TYPES)} (got {type_!r})")
    name = raw.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise ManifestError(f"name must match {NAME_RE.pattern!r} (got {name!r})")

    connector = _opt_str(raw.get("connector"), "connector", max_len=64)
    if not connector:
        connector = default_connector
    if connector and connector not in KNOWN_CONNECTORS:
        raise ManifestError(f"connector {connector!r} is not one of {sorted(KNOWN_CONNECTORS)}")

    publisher = _opt_str(raw.get("publisher"), "publisher", max_len=256)
    license_ = _opt_str(raw.get("license"), "license", max_len=128)
    description = _opt_str(raw.get("description"), "description", max_len=MAX_STRING)
    homepage = _opt_str(raw.get("homepage"), "homepage", max_len=MAX_STRING)
    if homepage and not HTTP_URL_RE.match(homepage):
        raise ManifestError(f"homepage must be http(s) URL (got {homepage!r})")
    version = _opt_str(raw.get("version"), "version", max_len=64)
    tags = _opt_str_list(raw.get("tags"), "tags", max_items=MAX_TAGS, max_len=64)

    if type_ == "skill":
        source_url = _req_str(raw.get("source_url"), "source_url", max_len=MAX_STRING)
        if not SOURCE_URL_RE.match(source_url):
            raise ManifestError(f"source_url must start with clawhub://, https://, or http:// (got {source_url!r})")
        sha256 = _opt_str(raw.get("sha256"), "sha256", max_len=64)
        if sha256 and not SHA256_RE.match(sha256):
            raise ManifestError(f"sha256 must be 64 hex chars (got {sha256!r})")
        return ManifestEntry(
            name=name,
            type="skill",
            source_url=source_url,
            sha256=sha256,
            version=version,
            license=license_,
            publisher=publisher,
            description=description,
            homepage=homepage,
            connector=connector,
            tags=tags,
        )

    transport = _opt_str(raw.get("transport"), "transport", max_len=32) or "stdio"
    if transport not in KNOWN_TRANSPORTS:
        raise ManifestError(f"transport {transport!r} is not one of {sorted(KNOWN_TRANSPORTS)}")

    command = _opt_str(raw.get("command"), "command", max_len=256)
    if command and not COMMAND_RE.match(command):
        raise ManifestError(f"command {command!r} contains characters outside the allow-list ({COMMAND_RE.pattern})")
    args = _opt_str_list(raw.get("args"), "args", max_items=MAX_ARGS, max_len=1024)
    env_required = _opt_str_list(
        raw.get("env_required"),
        "env_required",
        max_items=MAX_ENV_VARS,
        max_len=128,
    )
    for env in env_required:
        if not ENV_VAR_RE.match(env):
            raise ManifestError(f"env_required entry {env!r} must match {ENV_VAR_RE.pattern!r}")
    url = _opt_str(raw.get("url"), "url", max_len=MAX_STRING)

    if transport == "stdio" and not command:
        raise ManifestError("stdio transport requires a non-empty command")
    if transport != "stdio" and not url:
        raise ManifestError(f"transport {transport!r} requires a non-empty url")

    return ManifestEntry(
        name=name,
        type="mcp",
        transport=transport,
        command=command,
        args=args,
        env_required=env_required,
        url=url,
        version=version,
        license=license_,
        publisher=publisher,
        description=description,
        homepage=homepage,
        connector=connector,
        tags=tags,
    )


# ---------------------------------------------------------------------------
# Tiny string helpers — keep length / type validation tight and uniform.
# ---------------------------------------------------------------------------


def _coerce_yaml_scalar(value: Any, label: str) -> str:
    """Coerce a YAML-auto-typed scalar to its string surface form.

    PyYAML's safe_load resolves common patterns even when the publisher
    didn't quote them: ``2026-05-07T20:00:00Z`` becomes ``datetime``,
    ``1.0`` becomes ``float``, ``42`` becomes ``int``. The manifest
    schema declares every text field as a string, so without coercion
    a publisher who emits perfectly valid YAML hits a hard parse
    failure on first sync. We accept the lossless scalar types and
    render them with the syntax YAML used (``isoformat``-style for
    timestamps; ``repr``-equivalent for ints/floats); structured
    values (mapping / sequence / bytes) and ``bool`` (which would
    silently coerce ``True`` to a misleading ``"True"`` token in fields
    like ``version``) remain hard errors so manifest poisoning still
    fails closed.
    """
    if isinstance(value, _dt.datetime):
        # datetime.isoformat keeps offset / microseconds; we strip
        # microseconds so the surface matches the typical
        # publisher-written ``YYYY-MM-DDTHH:MM:SSZ`` form. Naive
        # datetimes (no tzinfo) are emitted without a 'Z' since
        # tagging them as UTC would be a lie.
        if value.microsecond:
            value = value.replace(microsecond=0)
        s = value.isoformat()
        if value.tzinfo is None:
            return s
        return s.replace("+00:00", "Z")
    if isinstance(value, _dt.date):
        return value.isoformat()
    # Reject bool BEFORE int (bool is a subclass of int) so
    # ``version: yes`` doesn't silently become "True".
    if isinstance(value, bool):
        raise ManifestError(f'{label} must be a string (got bool — quote the value, e.g. "true")')
    if isinstance(value, int | float):
        # repr() avoids YAML's int(1) → "1" + float(1.0) → "1.0"
        # both rendering identically; preserves the operator's intent.
        return repr(value) if isinstance(value, float) else str(value)
    raise ManifestError(f"{label} must be a string (got {type(value).__name__})")


def _opt_str(value: Any, label: str, *, max_len: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = _coerce_yaml_scalar(value, label)
    if len(value) > max_len:
        raise ManifestError(f"{label} exceeds {max_len} chars")
    return value


def _req_str(value: Any, label: str, *, max_len: int) -> str:
    out = _opt_str(value, label, max_len=max_len)
    if not out:
        raise ManifestError(f"{label} is required")
    return out


def _opt_str_list(value: Any, label: str, *, max_items: int, max_len: int) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ManifestError(f"{label} must be a list (got {type(value).__name__})")
    if len(value) > max_items:
        raise ManifestError(f"{label} has {len(value)} items (max {max_items})")
    out: list[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str):
            item = _coerce_yaml_scalar(item, f"{label}[{i}]")
        if len(item) > max_len:
            raise ManifestError(f"{label}[{i}] exceeds {max_len} chars")
        out.append(item)
    return out


def _maybe_jsonschema_validate(payload: dict[str, Any]) -> None:
    """Run optional jsonschema validation when the package is installed.

    The package is **not** a runtime requirement — every security
    invariant is also enforced by the hand-written validator above. We
    use jsonschema only when present, and surface its richer error
    messages to the operator.
    """
    try:
        import jsonschema
    except ImportError:
        return
    schema_path = Path(__file__).resolve().parents[3] / "schemas" / "registry-manifest.schema.json"
    if not schema_path.exists():
        return
    try:
        schema = json.loads(schema_path.read_text())
    except (OSError, json.JSONDecodeError):
        return
    try:
        jsonschema.validate(payload, schema)
    except jsonschema.ValidationError as exc:
        path = ".".join(str(p) for p in exc.absolute_path)
        loc = f" at {path}" if path else ""
        raise ManifestError(f"manifest schema violation{loc}: {exc.message}") from exc
