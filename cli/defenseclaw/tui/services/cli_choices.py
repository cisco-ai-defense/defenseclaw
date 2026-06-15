# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Shared CLI choice lists for the Textual TUI wizards.

Each tuple here mirrors a list defined in the CLI command modules.
Centralizing them in one place removes the drift that previously
caused the skill/MCP scanner wizards to lag behind ``_configure_llm``'s
provider catalogue. The TUI and the cmd_* modules are still distinct
import roots; ``test_cli_choices_module_matches_cli_source_of_truth``
in ``cli/tests/tui/test_setup_panel.py`` asserts exact parity between
the constants here and ``cmd_setup._WIZARD_LLM_PROVIDERS`` /
``cmd_agent._AI_DISCOVERY_MODES`` so drift fails CI.

If you add a value to a CLI choice, mirror it here in the same pull
request. Treating these as build-time constants keeps the wizards
snappy (no Click group imports during TUI startup) without giving up
the parity guarantee.
"""

from __future__ import annotations

from defenseclaw.platform_support import supported_connectors

# Connectors the TUI knows how to set up. The order here drives the
# wizard's connector picker, so put first-class proxies (openclaw,
# zeptoclaw) first and hook-based connectors after.
CONNECTORS: tuple[str, ...] = (
    "openclaw",
    "zeptoclaw",
    "codex",
    "claudecode",
    "hermes",
    "cursor",
    "windsurf",
    "geminicli",
    "copilot",
    "openhands",
    "antigravity",
    "opencode",
)

# Connectors that participate in the gateway proxy / guardrail stack.
# Used to decide whether the connector wizard should surface
# ``--scanner-mode`` and ``--with-local-stack``; the other connectors
# are hook-based and only take ``--mode``.
GUARDRAIL_CONNECTORS: frozenset[str] = frozenset({"openclaw", "zeptoclaw"})


def supported_connector_choices(os_name: str | None = None) -> tuple[str, ...]:
    """``CONNECTORS`` filtered to those supported on *os_name*.

    DefenseClaw is hook-only on Windows, so the proxy connectors
    (openclaw/zeptoclaw) are dropped there; a no-op on macOS/Linux. Use this
    wherever the connector list is presented to or chosen by the operator.
    """
    return tuple(supported_connectors(CONNECTORS, os_name))

# Full provider catalogue accepted by ``_configure_llm`` in
# ``cmd_setup.py``. Cloud providers first, then local runtimes. Tests
# assert these stay in sync.
WIZARD_LLM_PROVIDERS: tuple[str, ...] = (
    "anthropic",
    "openai",
    "openrouter",
    "azure",
    "gemini",
    "gemini-openai",
    "groq",
    "mistral",
    "cohere",
    "deepseek",
    "xai",
    "bedrock",
    "vertex_ai",
    "fireworks_ai",
    "perplexity",
    "huggingface",
    "replicate",
    "together_ai",
    "cerebras",
    "ollama",
    "vllm",
    "lm_studio",
)

# Subset used by the LLM provider override field (``setup llm``). The
# leading empty string keeps "no override" pickable from the choice
# widget without a separate code path.
LLM_PROVIDERS: tuple[str, ...] = (
    "anthropic",
    "openai",
    "openrouter",
    "azure",
    "gemini",
    "gemini-openai",
    "groq",
    "mistral",
    "cohere",
    "deepseek",
    "xai",
    "bedrock",
    "vertex_ai",
    "ollama",
    "vllm",
    "lm_studio",
)
LLM_OVERRIDE_PROVIDERS: tuple[str, ...] = ("", *LLM_PROVIDERS)

# AI Discovery cadence modes as defined by ``cmd_agent._AI_DISCOVERY_MODES``.
AI_DISCOVERY_MODES: tuple[str, ...] = ("passive", "enhanced")

# ---------------------------------------------------------------------------
# Connector-aware LLM roles, inherit paths, and regional auth modes.
#
# These mirror the ``click.Choice`` lists declared inline on
# ``cmd_setup.setup_llm`` and ``cmd_setup.setup_guardrail``. The TUI emits
# them as ``--role`` / ``--llm-role`` / ``--inherit-from`` /
# ``--*-auth-mode`` values, so drift here would silently produce argv the
# CLI rejects. ``test_cli_choices_module_matches_cli_source_of_truth``
# extracts the live choices off the Click commands and asserts equality.
# ---------------------------------------------------------------------------

# ``defenseclaw setup llm --role``: where the unified/agent/judge LLM
# settings are written.
LLM_ROLES: tuple[str, ...] = ("unified", "agent", "judge")

# ``defenseclaw setup llm --inherit-from``: sibling blocks the unified LLM
# can copy resolved settings from before flags are applied.
LLM_INHERIT_PATHS: tuple[str, ...] = (
    "guardrail",
    "guardrail.judge",
    "scanners.skill",
    "scanners.mcp",
    "scanners.plugin",
)

# ``defenseclaw setup guardrail --llm-role``: how a connector uses the LLM.
# ``judge_only`` configures just the guardrail judge (hook connectors);
# ``judge_and_agent`` also configures the agent's upstream LLM (proxies).
GUARDRAIL_JUDGE_LLM_ROLES: tuple[str, ...] = ("judge_only", "judge_and_agent")

# ``defenseclaw setup guardrail --inherit-from``: judge inherit sources.
# The leading empty string keeps "no inherit" pickable from a choice
# widget without a separate code path.
GUARDRAIL_JUDGE_INHERIT_PATHS: tuple[str, ...] = (
    "",
    "guardrail",
    "scanners.skill",
    "scanners.mcp",
    "scanners.plugin",
)

# Providers that expose regional / auth-mode / TLS field groups in the
# wizard. Canonical catalog names — note Vertex is ``vertex_ai`` (the
# ``vertex`` spelling is only an --auth-mode delegation alias in the CLI).
REGIONAL_PROVIDERS: frozenset[str] = frozenset({"bedrock", "vertex_ai", "azure"})

# Per-family auth-mode choices, mirroring --bedrock-auth-mode /
# --vertex-auth-mode / --azure-auth-mode (and their --judge-* twins).
BEDROCK_AUTH_MODES: tuple[str, ...] = ("api_key", "iam_credentials", "profile", "instance_role")
VERTEX_AUTH_MODES: tuple[str, ...] = ("service_account", "adc", "workload_identity")
AZURE_AUTH_MODES: tuple[str, ...] = ("api_key", "managed_identity")

# ``defenseclaw setup provider add --base-provider-type``: the upstream
# provider family a custom-providers.json instance speaks. Mirrors
# ``cmd_setup_provider._ALLOWED_BASE_PROVIDER_TYPES``. The leading empty
# string keeps "infer from model prefix" pickable from a choice widget.
CUSTOM_PROVIDER_BASE_TYPES: tuple[str, ...] = (
    "",
    "openai",
    "anthropic",
    "bedrock",
    "azure",
    "vertex_ai",
    "gemini",
    "gemini-openai",
    "groq",
    "mistral",
    "cohere",
    "deepseek",
    "xai",
    "fireworks_ai",
    "perplexity",
    "huggingface",
    "replicate",
    "openrouter",
    "together_ai",
    "cerebras",
    "ollama",
    "vllm",
    "lm_studio",
)

# ``defenseclaw setup provider add --allowed-request`` request types.
# Mirrors ``cmd_setup_provider._ALLOWED_REQUEST_TYPES``.
CUSTOM_PROVIDER_REQUEST_TYPES: tuple[str, ...] = (
    "chat",
    "completion",
    "embedding",
    "rerank",
    "image",
    "audio",
    "responses",
)
