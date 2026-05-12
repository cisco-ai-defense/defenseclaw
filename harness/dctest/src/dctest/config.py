"""dctest settings.

Pydantic-settings-backed configuration, env-prefixed with ``DCTEST_``.
An optional ``.env`` file at the harness root is honored.

This mirrors avarice's ``config.py`` shape but with knobs sized for a
manual-testing matrix rather than a security pipeline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_runs_root() -> Path:
    """Locate the default runs root next to this package."""
    return _find_harness_root() / "runs"


def _find_harness_root() -> Path:
    """Walk up from this file to find the harness/dctest/ root."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").exists() and parent.name == "dctest":
            return parent
    return here.parents[2]


class Settings(BaseSettings):
    """Global dctest settings.

    All fields can be overridden via ``DCTEST_<UPPER>`` environment variables
    or a ``.env`` file at the harness root.
    """

    model_config = SettingsConfigDict(
        env_prefix="DCTEST_",
        env_file=str(_find_harness_root() / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    runs_root: Path = Field(
        default_factory=_default_runs_root,
        description="Directory under which per-run artifacts are written.",
    )
    default_backend: Literal["claude", "codex", "manual"] = Field(
        default="claude",
        description="Which agent backend stage_runner uses by default.",
    )
    claude_bin: str = Field(default="claude", description="Path or name of the Claude CLI.")
    codex_bin: str = Field(default="codex", description="Path or name of the Codex CLI.")
    claude_model: str = Field(default="claude-sonnet-4-5", description="Default Claude model.")
    codex_model: str = Field(default="gpt-5-codex", description="Default Codex model.")
    agent_timeout_s: int = Field(default=900, description="Timeout per agent invocation.")
    command_timeout_s: int = Field(
        default=300, description="Timeout per defenseclaw command under test."
    )
    default_jobs: int = Field(default=1, description="Default parallelism for cell execution.")

    defenseclaw_bin: str = Field(default="defenseclaw", description="DefenseClaw Python CLI.")
    defenseclaw_gateway_bin: str = Field(
        default="defenseclaw-gateway", description="DefenseClaw Go gateway binary."
    )

    redact_logs: bool = Field(
        default=True,
        description=(
            "If True, scrub known token/key patterns from stored transcripts before write."
        ),
    )

    snapshot_paths: list[str] = Field(
        default_factory=lambda: [
            "~/.defenseclaw",
            "~/.openclaw",
            "~/.codex/config.toml",
            "~/.claude/settings.json",
            "~/.local/bin/defenseclaw",
            "~/.local/bin/defenseclaw-gateway",
        ],
        description="Host paths captured by `dctest snapshot create`.",
    )

    vllm_endpoint: str = Field(
        default="http://127.0.0.1:8000/v1",
        description="Default vLLM OpenAI-compatible endpoint for matrix cells.",
    )
    ollama_endpoint: str = Field(
        default="http://127.0.0.1:11434/v1",
        description="Default Ollama OpenAI-compatible endpoint for matrix cells.",
    )

    python_shim_dir: Path | None = Field(
        default=None,
        description=(
            "Optional override for the directory that holds the python->python3 "
            "shim injected into each case subshell. Defaults to "
            "<harness_root>/runtime/bin when None."
        ),
    )

    gateway_health_url: str = Field(
        default="http://127.0.0.1:8765/healthz",
        description="URL the prereq probe hits to confirm the DefenseClaw gateway is up.",
    )
    observability_health_url: str = Field(
        default="http://127.0.0.1:8765/metrics",
        description=(
            "URL the prereq probe hits to confirm observability "
            "(prom metrics endpoint on the gateway) is up."
        ),
    )
    webhook_target_url: str = Field(
        default="http://127.0.0.1:9999/webhook",
        description=(
            "URL the prereq probe hits to confirm a webhook sink is reachable for "
            "cases that send notifications."
        ),
    )

    def harness_root(self) -> Path:
        """Return the harness/dctest/ root directory."""
        return _find_harness_root()

    def effective_python_shim_dir(self) -> Path:
        """Return ``python_shim_dir`` if set, otherwise ``<harness_root>/runtime/bin``."""
        if self.python_shim_dir is not None:
            return self.python_shim_dir
        return self.harness_root() / "runtime" / "bin"


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return a cached Settings instance, constructing it on first call."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings_for_tests() -> None:
    """Drop the cached Settings instance (tests only)."""
    global _settings
    _settings = None
