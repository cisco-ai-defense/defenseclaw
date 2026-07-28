"""DefenseClaw environment-variable registry (Python side).

This module loads ``internal/envvars/registry.json`` — the single source of
truth for every ``DEFENSECLAW_*`` env var consumed by the codebase — and
exposes a small typed API used by:

* ``defenseclaw doctor`` (surfaces active security-opt-out vars)
* the docs-generation script (``scripts/gen_envvars_docs.py``)
* the CI gate that fails the build if any callsite references a
  ``DEFENSECLAW_*`` var not declared in the registry
  (``cli/tests/test_envvars_codebase_coverage.py``)

The Go side (``internal/envvars/registry.go``) loads the same JSON via
``//go:embed`` and ``internal/envvars/registry_test.go`` asserts that the
two language readers agree.

Why a registry?
---------------
The codebase historically accumulated ~70 ``DEFENSECLAW_*`` vars across
Go, Python, shell, TypeScript, and Docker compose files. Operators had no
way to know which were security-impacting, which were debug-only, and
which were internal. The registry centralises the metadata so that:

1. Operators see exactly which security overrides are active via
   ``defenseclaw doctor``.
2. Docs are generated from one source and never drift.
3. CI fails if a new env var is added without a registry entry.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "Consumer",
    "EnvVar",
    "Registry",
    "load_registry",
    "load_registry_file",
    "active_security_overrides",
    "CATEGORY_SECURITY_OPT_OUT",
    "CATEGORY_DEBUG",
    "CATEGORY_TELEMETRY",
    "CATEGORY_RUNTIME_PATH",
    "CATEGORY_HOOK_INTERNAL",
    "CATEGORY_UPGRADE_INTERNAL",
    "CATEGORY_CREDENTIAL",
    "CATEGORY_DISCOVERY",
    "CATEGORY_SPLUNK_BRIDGE",
    "CATEGORY_TEST_FIXTURE",
    "ALLOWED_CATEGORIES",
    "ALLOWED_SECURITY_IMPACT",
]


# Category identifiers must match the keys of ``$categories`` in registry.json.
CATEGORY_SECURITY_OPT_OUT = "security_opt_out"
CATEGORY_DEBUG = "debug"
CATEGORY_TELEMETRY = "telemetry"
CATEGORY_RUNTIME_PATH = "runtime_path"
CATEGORY_HOOK_INTERNAL = "hook_internal"
CATEGORY_UPGRADE_INTERNAL = "upgrade_internal"
CATEGORY_CREDENTIAL = "credential"
CATEGORY_DISCOVERY = "discovery"
CATEGORY_SPLUNK_BRIDGE = "splunk_bridge"
CATEGORY_TEST_FIXTURE = "test_fixture"

ALLOWED_CATEGORIES = frozenset(
    {
        CATEGORY_SECURITY_OPT_OUT,
        CATEGORY_DEBUG,
        CATEGORY_TELEMETRY,
        CATEGORY_RUNTIME_PATH,
        CATEGORY_HOOK_INTERNAL,
        CATEGORY_UPGRADE_INTERNAL,
        CATEGORY_CREDENTIAL,
        CATEGORY_DISCOVERY,
        CATEGORY_SPLUNK_BRIDGE,
        CATEGORY_TEST_FIXTURE,
    }
)

ALLOWED_SECURITY_IMPACT = frozenset({"none", "low", "medium", "high"})

# Truthy values that activate an opt-out toggle. Mirrors the Go side
# (internal/envvars/registry.go: isTruthy) so doctor and tests agree.
_TRUTHY = frozenset({"1", "true", "yes", "on"})

_ACTIVE_WHEN_NONEMPTY = frozenset({"DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS"})

@dataclass(frozen=True)
class Consumer:
    """A single ``file:line`` location that reads or references the var."""

    location: str
    description: str


@dataclass(frozen=True)
class EnvVar:
    """One entry in the registry."""

    name: str
    category: str
    purpose: str
    default: str
    accepted_values: tuple[str, ...]
    security_impact: str
    surface_in_doctor: bool
    consumers: tuple[Consumer, ...]
    since: str
    security_note: str = ""
    replacement_hint: str = ""
    deprecated: bool = False
    migration_only: bool = False

    def is_active(self, env: dict[str, str] | None = None) -> bool:
        """Return True when this var is set to a value that activates the
        feature it controls.

        For opt-outs this means a documented truthy value
        (``1``/``true``/...). Empty, unset, and unrecognized values are
        inactive.
        """
        environ = env if env is not None else os.environ
        raw = environ.get(self.name, "")
        v = raw.strip().lower()
        if not v:
            return False
        if self.name in _ACTIVE_WHEN_NONEMPTY:
            return True
        return v in _TRUTHY


@dataclass(frozen=True)
class Registry:
    """The full registry, indexed by name."""

    schema_version: str
    description: str
    categories: dict[str, str]
    entries: tuple[EnvVar, ...]
    _by_name: dict[str, EnvVar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Frozen dataclass: bypass the freeze for the cache.
        object.__setattr__(self, "_by_name", {e.name: e for e in self.entries})

    def get(self, name: str) -> EnvVar | None:
        return self._by_name.get(name)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._by_name

    def names(self) -> frozenset[str]:
        return frozenset(self._by_name)

    def by_category(self, category: str) -> tuple[EnvVar, ...]:
        if category not in ALLOWED_CATEGORIES:
            raise ValueError(
                f"unknown category {category!r}; expected one of "
                f"{sorted(ALLOWED_CATEGORIES)}"
            )
        return tuple(e for e in self.entries if e.category == category)


# ---------------------------------------------------------------------------
# Loading

_REGISTRY_RELATIVE_PATH = Path("internal") / "envvars" / "registry.json"
_BUNDLED_REGISTRY_PATH = Path("_data") / "envvars" / "registry.json"
_cached: Registry | None = None


def _registry_path() -> Path:
    """Locate the registry.json relative to the repo root.

    A module imported from ``<repo>/cli/defenseclaw`` uses the authoritative
    source registry. An installed package uses only its adjacent package-data
    mirror, even when its virtualenv happens to live below a source checkout.
    DEFENSECLAW_REPO_ROOT remains an explicit override for CI sandboxes.
    """
    env_root = os.environ.get("DEFENSECLAW_REPO_ROOT", "").strip()
    if env_root:
        p = Path(env_root) / _REGISTRY_RELATIVE_PATH
        if p.is_file():
            return p
    here = Path(__file__).resolve()
    if len(here.parents) >= 3 and here.parents[1].name == "cli":
        source = here.parents[2] / _REGISTRY_RELATIVE_PATH
        if source.is_file():
            return source
    bundled = here.parent / _BUNDLED_REGISTRY_PATH
    if bundled.is_file():
        return bundled
    raise FileNotFoundError(
        f"could not locate {_REGISTRY_RELATIVE_PATH} starting from {here}"
    )


def _validate_entry(raw: dict[str, Any], path: Path) -> EnvVar:
    required = (
        "name",
        "category",
        "purpose",
        "default",
        "accepted_values",
        "security_impact",
        "surface_in_doctor",
        "consumers",
        "since",
    )
    for field_name in required:
        if field_name not in raw:
            raise ValueError(
                f"{path}: entry is missing required field {field_name!r}: {raw!r}"
            )

    name = raw["name"]
    if not isinstance(name, str) or not name.startswith("DEFENSECLAW_") and name != "MIGRATION_DEFENSECLAW_HOME":
        raise ValueError(
            f"{path}: entry name {name!r} must start with 'DEFENSECLAW_' "
            "(or be the legacy MIGRATION_DEFENSECLAW_HOME)"
        )

    category = raw["category"]
    if category not in ALLOWED_CATEGORIES:
        raise ValueError(
            f"{path}: entry {name}: unknown category {category!r}; "
            f"expected one of {sorted(ALLOWED_CATEGORIES)}"
        )

    impact = raw["security_impact"]
    if impact not in ALLOWED_SECURITY_IMPACT:
        raise ValueError(
            f"{path}: entry {name}: unknown security_impact {impact!r}; "
            f"expected one of {sorted(ALLOWED_SECURITY_IMPACT)}"
        )

    consumers_raw = raw["consumers"]
    if not isinstance(consumers_raw, list):
        raise ValueError(
            f"{path}: entry {name}: 'consumers' must be a list, got {type(consumers_raw).__name__}"
        )
    consumers = tuple(
        Consumer(location=str(c["location"]), description=str(c["description"]))
        for c in consumers_raw
    )

    accepted = raw["accepted_values"]
    if not isinstance(accepted, list):
        raise ValueError(
            f"{path}: entry {name}: 'accepted_values' must be a list"
        )

    boolean_fields = {
        "deprecated": raw.get("deprecated", False),
        "migration_only": raw.get("migration_only", False),
        "surface_in_doctor": raw["surface_in_doctor"],
    }
    for field_name, value in boolean_fields.items():
        if not isinstance(value, bool):
            raise ValueError(
                f"{path}: entry {name}: {field_name} must be a boolean"
            )
    deprecated = boolean_fields["deprecated"]
    migration_only = boolean_fields["migration_only"]
    surface_in_doctor = boolean_fields["surface_in_doctor"]
    if migration_only and not deprecated:
        raise ValueError(
            f"{path}: entry {name}: migration_only requires deprecated=true"
        )
    if migration_only and surface_in_doctor:
        raise ValueError(
            f"{path}: entry {name}: migration-only inputs cannot surface in doctor"
        )
    if (
        deprecated
        and category == CATEGORY_SECURITY_OPT_OUT
        and impact == "high"
        and not surface_in_doctor
        and not migration_only
    ):
        raise ValueError(
            f"{path}: entry {name}: deprecated high-impact opt-out must "
            "surface in doctor or be migration_only"
        )

    return EnvVar(
        name=name,
        category=category,
        purpose=str(raw["purpose"]),
        default=str(raw["default"]),
        accepted_values=tuple(str(v) for v in accepted),
        security_impact=impact,
        surface_in_doctor=surface_in_doctor,
        consumers=consumers,
        since=str(raw["since"]),
        security_note=str(raw.get("security_note", "")),
        replacement_hint=str(raw.get("replacement_hint", "")),
        deprecated=deprecated,
        migration_only=migration_only,
    )


def load_registry_file(path: str | Path) -> Registry:
    """Load and validate one explicit registry file without using the cache.

    Generators use this entry point so their input cannot change based on an
    ambient, potentially stale package-data mirror.
    """
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)

    if not isinstance(raw, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")

    schema_version = str(raw.get("$schema_version", "0"))
    description = str(raw.get("$description", ""))
    categories_raw = raw.get("$categories", {})
    if not isinstance(categories_raw, dict):
        raise ValueError(f"{path}: $categories must be an object")
    categories = {str(k): str(v) for k, v in categories_raw.items()}

    declared_categories = set(categories.keys())
    if declared_categories != ALLOWED_CATEGORIES:
        missing = ALLOWED_CATEGORIES - declared_categories
        extra = declared_categories - ALLOWED_CATEGORIES
        raise ValueError(
            f"{path}: $categories does not match ALLOWED_CATEGORIES; "
            f"missing={sorted(missing)} extra={sorted(extra)}"
        )

    entries_raw = raw.get("entries", [])
    if not isinstance(entries_raw, list):
        raise ValueError(f"{path}: 'entries' must be a list")

    entries = tuple(_validate_entry(e, path) for e in entries_raw)

    # Duplicate-name check.
    seen: set[str] = set()
    for e in entries:
        if e.name in seen:
            raise ValueError(f"{path}: duplicate entry for {e.name!r}")
        seen.add(e.name)

    return Registry(
        schema_version=schema_version,
        description=description,
        categories=categories,
        entries=entries,
    )


def load_registry(force_reload: bool = False) -> Registry:
    """Load and validate the discovered registry. Cached after first call."""
    global _cached
    if _cached is not None and not force_reload:
        return _cached

    _cached = load_registry_file(_registry_path())
    return _cached


def active_security_overrides(
    env: dict[str, str] | None = None,
    *,
    include_low_impact: bool = True,
) -> list[EnvVar]:
    """Return registry entries that are currently active AND flagged
    ``surface_in_doctor: true``.

    Used by ``defenseclaw doctor`` to render the "Security overrides"
    section. Operators with no overrides set see an empty section.
    """
    reg = load_registry()
    out: list[EnvVar] = []
    for entry in reg.entries:
        if not entry.surface_in_doctor:
            continue
        if entry.security_impact == "none":
            continue
        if not include_low_impact and entry.security_impact == "low":
            continue
        if entry.is_active(env):
            out.append(entry)
    return out


def iter_entries() -> Iterable[EnvVar]:
    """Convenience iterator over every entry."""
    return iter(load_registry().entries)
