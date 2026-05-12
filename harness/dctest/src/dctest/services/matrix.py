"""Matrix expansion and selection.

The matrix is the cross-product of six dimensions defined under
``src/dctest/matrix/*.yaml``:

- providers (vendor + model + endpoint + auth_env)
- roles (guardrail / judge / both)
- connectors
- profiles (OPA × pack, with ``permissive`` / ``default`` / ``strict`` each)
- fail_modes (open / closed)
- scan_types (skill / mcp / plugin / code / aibom)

A MatrixCell is one combination. The full cross-product is enormous; the
default ``required-only`` selector trims the matrix to a per-PR practical
size. Selectors are expressed as simple ``key=value1,value2`` filters,
optionally combined with ``--required-only`` and ``--full-profiles``.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable
from pathlib import Path

import yaml

from dctest.exceptions import MatrixSelectionError
from dctest.models import MatrixCell, MatrixDimension, ProviderSpec, Role
from dctest.models.matrix import Tier
from dctest.prompt_loader import matrix_path


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        raise MatrixSelectionError(f"Missing matrix file: {path}")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load_providers() -> list[ProviderSpec]:
    data = _load_yaml(matrix_path("providers.yaml"))
    return [ProviderSpec(**p) for p in data.get("providers", [])]


def load_roles() -> list[Role]:
    data = _load_yaml(matrix_path("roles.yaml"))
    return list(data.get("roles", []))


def load_connectors() -> list[dict]:
    data = _load_yaml(matrix_path("connectors.yaml"))
    return list(data.get("connectors", []))


def load_profiles() -> dict[str, list[str]]:
    data = _load_yaml(matrix_path("profiles.yaml"))
    return {
        "opa": list(data.get("opa", ["permissive", "default", "strict"])),
        "pack": list(data.get("pack", ["permissive", "default", "strict"])),
    }


def load_fail_modes() -> list[str]:
    data = _load_yaml(matrix_path("fail_modes.yaml"))
    return list(data.get("fail_modes", ["fail-open", "fail-closed"]))


def load_scan_types() -> list[str]:
    data = _load_yaml(matrix_path("scan_types.yaml"))
    return list(data.get("scan_types", ["skill", "mcp", "plugin", "code", "aibom"]))


def load_dimensions() -> list[MatrixDimension]:
    """Return a list of MatrixDimension records describing the available axes."""
    return [
        MatrixDimension(
            name="provider",
            description="LLM provider + model.",
            values=[p.id for p in load_providers()],
        ),
        MatrixDimension(
            name="role",
            description="Which DefenseClaw component uses the provider.",
            values=load_roles(),
        ),
        MatrixDimension(
            name="connector",
            description="Agent runtime under test.",
            values=[c["id"] for c in load_connectors()],
        ),
        MatrixDimension(
            name="opa_profile",
            description="OPA bundle profile.",
            values=load_profiles()["opa"],
        ),
        MatrixDimension(
            name="pack_profile",
            description="Guardrail rule pack profile.",
            values=load_profiles()["pack"],
        ),
        MatrixDimension(name="fail_mode", description="Fail-open vs fail-closed.", values=load_fail_modes()),
        MatrixDimension(
            name="scan_type",
            description="Which DefenseClaw scanner the case exercises.",
            values=load_scan_types(),
        ),
    ]


def _parse_filter(s: str) -> tuple[str, list[str]]:
    if "=" not in s:
        raise MatrixSelectionError(f"Bad filter syntax (expected key=v[,v2]): {s!r}")
    key, vals = s.split("=", 1)
    return key.strip(), [v.strip() for v in vals.split(",") if v.strip()]


def expand_matrix(
    *,
    filters: Iterable[str] | None = None,
    required_only: bool = True,
    full_profiles: bool = False,
    sample_profiles: tuple[tuple[str, str], ...] = (
        ("default", "default"),
        ("strict", "permissive"),
        ("permissive", "strict"),
    ),
) -> list[MatrixCell]:
    """Expand the matrix into MatrixCell records, respecting the supplied filters.

    ``required_only`` keeps only connectors whose YAML tier is ``required``.
    ``full_profiles`` enables the full 3×3 cross-product of OPA × pack
    profiles; otherwise ``sample_profiles`` is used (3 cells by default).
    """
    providers = load_providers()
    providers_by_id = {p.id: p for p in providers}
    roles = load_roles()
    connectors = load_connectors()
    if required_only:
        connectors = [c for c in connectors if c.get("tier", "required") == "required"]
    profiles = load_profiles()
    fail_modes = load_fail_modes()
    scan_types = load_scan_types()

    if full_profiles:
        profile_combos = list(itertools.product(profiles["opa"], profiles["pack"]))
    else:
        profile_combos = list(sample_profiles)

    parsed_filters: dict[str, list[str]] = {}
    for f in filters or []:
        k, v = _parse_filter(f)
        parsed_filters.setdefault(k, []).extend(v)

    out: list[MatrixCell] = []
    for connector in connectors:
        if "connector" in parsed_filters and connector["id"] not in parsed_filters["connector"]:
            continue
        if "tier" in parsed_filters and connector.get("tier", "required") not in parsed_filters["tier"]:
            continue
        for provider in providers:
            if "provider" in parsed_filters and provider.id not in parsed_filters["provider"]:
                continue
            for role in roles:
                if "role" in parsed_filters and role not in parsed_filters["role"]:
                    continue
                judge_provider = None
                if role == "guardrail+judge-mixed":
                    # Pair with the next provider by id ordering, else self.
                    ordered = sorted(p.id for p in providers)
                    idx = ordered.index(provider.id)
                    other = ordered[(idx + 1) % len(ordered)]
                    judge_provider = providers_by_id[other]
                elif role == "guardrail+judge-same" or role == "judge-only":
                    judge_provider = provider
                for opa_p, pack_p in profile_combos:
                    if "opa_profile" in parsed_filters and opa_p not in parsed_filters["opa_profile"]:
                        continue
                    if "pack_profile" in parsed_filters and pack_p not in parsed_filters["pack_profile"]:
                        continue
                    for fm in fail_modes:
                        if "fail_mode" in parsed_filters and fm not in parsed_filters["fail_mode"]:
                            continue
                        for st in scan_types:
                            if "scan_type" in parsed_filters and st not in parsed_filters["scan_type"]:
                                continue
                            cell_id = "--".join(
                                [
                                    connector["id"],
                                    provider.id,
                                    role,
                                    f"opa.{opa_p}",
                                    f"pack.{pack_p}",
                                    fm,
                                    st,
                                ]
                            )
                            out.append(
                                MatrixCell(
                                    id=cell_id,
                                    connector=connector["id"],
                                    provider=provider,
                                    role=role,
                                    judge_provider=judge_provider,
                                    opa_profile=opa_p,  # type: ignore[arg-type]
                                    pack_profile=pack_p,  # type: ignore[arg-type]
                                    fail_mode=fm,  # type: ignore[arg-type]
                                    scan_type=st,  # type: ignore[arg-type]
                                    tier=Tier(connector.get("tier", "required")),
                                )
                            )
    return out


def serialize_selection(cells: list[MatrixCell], path: Path) -> None:
    """Write a selection YAML the user (or `dctest run --selection`) can consume."""
    payload = {"cells": [c.model_dump(mode="json") for c in cells]}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def load_selection(path: Path) -> list[MatrixCell]:
    if not path.exists():
        raise MatrixSelectionError(f"Selection file not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cells_data = data.get("cells", [])
    return [MatrixCell.model_validate(c) for c in cells_data]


# Cheapest, lowest-latency providers go first so the early-finishing cells
# surface verdicts (and any harness regressions) sooner. Used by
# walk_priority(); cheap to update when the provider mix changes.
_PROVIDER_PREFERENCE = (
    "anthropic-claude-sonnet",
    "anthropic-claude-haiku",
    "openai-4o",
    "openai-4o-mini",
    "openai-gpt-5",
    "vllm-qwen",
    "vllm-llama",
    "ollama-llama",
    "ollama-qwen",
    "bifrost-clawshield",
)

_ROLE_PREFERENCE = (
    "guardrail-only",
    "judge-only",
    "guardrail+judge-same",
    "guardrail+judge-mixed",
)


def walk_priority(cells: list[MatrixCell]) -> list[MatrixCell]:
    """Return ``cells`` re-ordered by execution priority.

    Order, ascending (= run first):
      1. Tier ``required`` before ``optional``.
      2. Providers in ``_PROVIDER_PREFERENCE`` order; unknown providers last.
      3. Roles in ``_ROLE_PREFERENCE`` order; unknown roles last.
      4. Cell id as a stable tie-breaker so reruns are deterministic.
    """

    def provider_rank(cell: MatrixCell) -> int:
        try:
            return _PROVIDER_PREFERENCE.index(cell.provider.id)
        except ValueError:
            return len(_PROVIDER_PREFERENCE)

    def role_rank(cell: MatrixCell) -> int:
        try:
            return _ROLE_PREFERENCE.index(cell.role)
        except ValueError:
            return len(_ROLE_PREFERENCE)

    def tier_rank(cell: MatrixCell) -> int:
        return 0 if cell.tier == Tier.REQUIRED else 1

    return sorted(
        cells, key=lambda c: (tier_rank(c), provider_rank(c), role_rank(c), c.id)
    )
