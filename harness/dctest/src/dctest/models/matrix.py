"""Matrix models: dimensions, providers, and the cross-product cells."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

Role = Literal[
    "guardrail-only",
    "judge-only",
    "guardrail+judge-same",
    "guardrail+judge-mixed",
]


class ProviderSpec(BaseModel):
    """A concrete LLM provider configuration used by a matrix cell."""

    id: str = Field(description="Stable provider id used in cell ids and selection files.")
    vendor: Literal["anthropic", "openai", "vllm", "ollama", "bifrost"]
    model: str
    endpoint: str | None = Field(
        default=None,
        description="Base URL for OpenAI-compatible providers (vLLM, Ollama, Bifrost).",
    )
    auth_env: str | None = Field(
        default=None,
        description="Environment variable name holding the API key (None for local providers).",
    )
    notes: str = ""

    def display_name(self) -> str:
        return f"{self.vendor}/{self.model}"


class MatrixDimension(BaseModel):
    """A single matrix dimension with a list of allowed values."""

    name: str
    description: str
    values: list[str]


class Tier(str, Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"


class MatrixCell(BaseModel):
    """One concrete combination of dimension values to test.

    Persisted as ``runs/<run-id>/cells/<cell-id>/cell.json``.
    """

    id: str = Field(description="Stable, hyphen-delimited cell id.")
    connector: str
    provider: ProviderSpec
    role: Role
    judge_provider: ProviderSpec | None = None
    opa_profile: Literal["permissive", "default", "strict"] = "default"
    pack_profile: Literal["permissive", "default", "strict"] = "default"
    fail_mode: Literal["fail-open", "fail-closed"] = "fail-open"
    scan_type: Literal["skill", "mcp", "plugin", "code", "aibom"] = "skill"
    tier: Tier = Tier.REQUIRED
    cases: list[str] = Field(
        default_factory=list,
        description="Case ids drawn from cases/* that should run inside this cell.",
    )
    notes: str = ""

    def short_label(self) -> str:
        return (
            f"{self.connector} | {self.provider.id} | {self.role} | "
            f"opa:{self.opa_profile} pack:{self.pack_profile} | "
            f"{self.fail_mode} | {self.scan_type}"
        )
