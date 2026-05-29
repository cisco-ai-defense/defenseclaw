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
)

# Connectors that participate in the gateway proxy / guardrail stack.
# Used to decide whether the connector wizard should surface
# ``--scanner-mode`` and ``--with-local-stack``; the other connectors
# are hook-based and only take ``--mode``.
GUARDRAIL_CONNECTORS: frozenset[str] = frozenset({"openclaw", "zeptoclaw"})

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
