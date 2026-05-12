"""Provider switching for matrix cells.

The actual DefenseClaw configuration edits happen via ``defenseclaw setup llm``
and ``defenseclaw keys``. This module's job is to emit a sequence of shell
commands that the **AI agent** then executes (recorded in the case
transcript). We do NOT mutate the user's config directly from Python:
that keeps the harness honest about what it tested and lets a human read
the executed shell history.
"""

from __future__ import annotations

from dataclasses import dataclass

from dctest.config import get_settings
from dctest.models import ProviderSpec


@dataclass
class ProviderSwitchPlan:
    """A plain-data description of how to flip DefenseClaw to ``provider``.

    The list of shell lines below is what gets fed to the AI agent. The
    agent's job is to actually run them, capture output, and decide if
    the switch succeeded.
    """

    role: str  # "guardrail" | "judge" | "both"
    provider: ProviderSpec
    judge_provider: ProviderSpec | None
    shell_lines: list[str]
    required_env: list[str]
    notes: str


def plan_provider_switch(
    *,
    role: str,
    provider: ProviderSpec,
    judge_provider: ProviderSpec | None = None,
) -> ProviderSwitchPlan:
    """Build the (non-executed) plan for switching DefenseClaw to a provider."""
    settings = get_settings()
    lines: list[str] = []
    required_env: list[str] = []
    notes: list[str] = []
    bin_name = settings.defenseclaw_bin

    if provider.auth_env:
        required_env.append(provider.auth_env)
        notes.append(
            f"Set {provider.auth_env} before invocation; harness env-check verifies presence."
        )

    if provider.vendor == "vllm":
        lines.append(
            f"{bin_name} setup llm --provider openai-compatible "
            f"--endpoint {provider.endpoint} --model {provider.model} --no-interactive"
        )
        notes.append("vLLM endpoint must be reachable at the configured URL.")
    elif provider.vendor == "ollama":
        lines.append(
            f"{bin_name} setup llm --provider openai-compatible "
            f"--endpoint {provider.endpoint} --model {provider.model} --no-interactive"
        )
        notes.append("Ollama daemon must be running at the configured URL.")
    elif provider.vendor == "bifrost":
        lines.append(
            f"{bin_name} setup llm --provider bifrost "
            f"--endpoint {provider.endpoint} --model {provider.model} --no-interactive"
        )
    else:
        # anthropic / openai
        lines.append(
            f"{bin_name} setup llm --provider {provider.vendor} --model {provider.model} --no-interactive"
        )

    if role in ("guardrail", "guardrail-only", "guardrail+judge-same", "guardrail+judge-mixed"):
        lines.append(f"{bin_name} guardrail enable")
    if role in ("judge", "judge-only", "guardrail+judge-same", "guardrail+judge-mixed"):
        lines.append(f"{bin_name} setup guardrail --judge-enabled --no-interactive")

    if judge_provider and judge_provider.id != provider.id:
        if judge_provider.auth_env:
            required_env.append(judge_provider.auth_env)
        if judge_provider.vendor in ("vllm", "ollama", "bifrost"):
            lines.append(
                f"{bin_name} setup guardrail --judge-provider openai-compatible "
                f"--judge-endpoint {judge_provider.endpoint} "
                f"--judge-model {judge_provider.model} --no-interactive"
            )
        else:
            lines.append(
                f"{bin_name} setup guardrail "
                f"--judge-provider {judge_provider.vendor} "
                f"--judge-model {judge_provider.model} --no-interactive"
            )
        notes.append(
            "Mixed role: separate provider for guardrail vs LLM-as-judge "
            "(exercises per-component key overrides)."
        )

    lines.append(f"{bin_name} status")

    return ProviderSwitchPlan(
        role=role,
        provider=provider,
        judge_provider=judge_provider,
        shell_lines=lines,
        required_env=list(dict.fromkeys(required_env)),  # de-dupe while preserving order
        notes="\n".join(notes),
    )
