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

"""Shared LLM environment injector for Python scanners.

DefenseClaw exposes a single canonical LLM key via
``DEFENSECLAW_LLM_KEY`` (see :mod:`defenseclaw.config.LLMConfig`). The
Python scanners (skill, MCP, plugin) all use LiteLLM under the hood,
and LiteLLM expects provider-specific env vars (``OPENAI_API_KEY``,
``ANTHROPIC_API_KEY``, etc.) to be set. This helper derives the right
env var from the resolved ``LLMConfig.provider_prefix()`` and writes it
into ``os.environ`` before the scanner boots LiteLLM.

Keeping this mapping in one place avoids the provider drift we saw
when each scanner maintained its own two-entry dict (mcp.py had only
openai+anthropic — silently ignored everyone else). The full provider
list is kept in lockstep with:

* ``internal/gateway/bifrost_provider.go`` — Bifrost's routing table
* ``internal/configs/providers.json``       — OpenClaw fetch interceptor

Add new providers here first, then propagate to those two files in the
same PR. Local providers (ollama/vllm/lm_studio) deliberately have no
entry: they don't take an API key — only ``base_url`` — and the
scanner flips to that mode in :func:`inject_llm_env` below.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from defenseclaw.config import LLMConfig

_log = logging.getLogger(__name__)


# Provider prefix → canonical env var that LiteLLM (and most direct
# SDKs) read to pick up the API key. When a provider has multiple
# accepted env vars, we pick the one LiteLLM prefers; the fallbacks are
# listed in the trailing tuple so callers that want to back-fill all of
# them (e.g. legacy OpenClaw flows) can iterate.
#
# Keep in lockstep with internal/configs/providers.json::env_keys and
# with the Python CLI's guardrail.detect_api_key_env() heuristic.
_PROVIDER_ENV_VARS: dict[str, tuple[str, ...]] = {
    "openai": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"),
    "azure": ("AZURE_OPENAI_API_KEY", "AZURE_API_KEY"),
    "gemini": ("GOOGLE_API_KEY", "GEMINI_API_KEY"),
    "vertex_ai": ("GOOGLE_APPLICATION_CREDENTIALS",),
    # Bedrock has two auth modes. LiteLLM prefers the short-term API
    # bearer token (prefix ``ABSK...``, env var ``AWS_BEARER_TOKEN_BEDROCK``,
    # sent as ``Authorization: Bearer ...``) when set. Long-term AWS SigV4
    # credentials (``AWS_ACCESS_KEY_ID``/``AWS_SECRET_ACCESS_KEY``/
    # ``AWS_SESSION_TOKEN``) are a separate path handled by boto3 and
    # must NOT be populated from a single opaque ``DEFENSECLAW_LLM_KEY``
    # — doing so would break signing. We therefore write only the bearer
    # env var here; operators using SigV4 keep their AWS creds in the
    # shell env or ``~/.aws/credentials`` untouched.
    "bedrock": ("AWS_BEARER_TOKEN_BEDROCK",),
    "groq": ("GROQ_API_KEY",),
    "mistral": ("MISTRAL_API_KEY",),
    "cohere": ("COHERE_API_KEY",),
    "deepseek": ("DEEPSEEK_API_KEY",),
    "xai": ("XAI_API_KEY",),
    "fireworks_ai": ("FIREWORKS_AI_API_KEY", "FIREWORKS_API_KEY"),
    "perplexity": ("PERPLEXITY_API_KEY", "PERPLEXITYAI_API_KEY"),
    "huggingface": ("HUGGINGFACE_API_KEY", "HF_TOKEN"),
    "replicate": ("REPLICATE_API_KEY",),
    "openrouter": ("OPENROUTER_API_KEY",),
    "together_ai": ("TOGETHERAI_API_KEY", "TOGETHER_API_KEY"),
    "cerebras": ("CEREBRAS_API_KEY",),
}

# Providers that don't take an API key. These run on-box; the resolved
# ``LLMConfig.base_url`` is what matters instead. Duplicated (with care)
# from ``defenseclaw.config._LOCAL_LLM_PROVIDERS`` to avoid a circular
# import at module load.
_LOCAL_PROVIDERS = frozenset({"ollama", "vllm", "lm_studio", "lmstudio", "local"})


def provider_env_vars(provider: str) -> tuple[str, ...]:
    """Return the env var(s) LiteLLM reads for *provider*.

    Unknown providers get an empty tuple — the caller should fall back
    to whatever the upstream library does on its own (which, for
    LiteLLM, is usually "error out with a clear message").
    """
    return _PROVIDER_ENV_VARS.get(provider.strip().lower(), ())


def is_local_provider(provider: str) -> bool:
    """Mirror of :meth:`LLMConfig.is_local_provider` for the subset of
    checks the injector needs without importing Config."""
    return provider.strip().lower() in _LOCAL_PROVIDERS


def inject_llm_env(llm: LLMConfig, *, overwrite: bool = False) -> list[str]:
    """Inject the resolved LLM key into the provider-specific env var.

    Reads ``llm.resolved_api_key()`` (which already walks the
    ``api_key_env → api_key`` ladder and falls back to
    ``DEFENSECLAW_LLM_KEY``) and copies the value into every env var
    LiteLLM would inspect for the resolved provider prefix.

    * When the provider is local (ollama/vllm/lm_studio/…), the key is
      skipped; only ``OPENAI_API_BASE`` / ``base_url`` matter for these.
    * ``overwrite=False`` (default) preserves operator-set env vars,
      matching the pre-v5 scanner behavior. Callers driving a scan from
      within DefenseClaw's own process can set it to True to force the
      resolved key through.

    Returns the list of env var names that were touched (useful for
    debug logging). Silent no-op when the resolved key is empty —
    scanners that need an explicit failure should check the return
    value or call :func:`resolved_api_key` themselves.
    """
    prefix = llm.provider_prefix()
    if not prefix:
        return []
    if is_local_provider(prefix):
        # Local providers don't consume API keys; LiteLLM routes by
        # base_url alone. Intentionally do nothing.
        return []
    api_key = llm.resolved_api_key()
    if not api_key:
        return []
    touched: list[str] = []
    for env_var in provider_env_vars(prefix):
        if not overwrite and os.environ.get(env_var):
            continue
        os.environ[env_var] = api_key
        touched.append(env_var)
    if not touched and not overwrite:
        # Every provider env var was already populated by the operator
        # — respect that, don't clobber.
        _log.debug(
            "llm env: provider %s already has env vars set; not overwriting",
            prefix,
        )
    return touched


def litellm_model(llm: LLMConfig) -> str:
    """Return the model string shaped for LiteLLM.

    LiteLLM accepts ``"provider/model-id"`` directly — the same shape
    DefenseClaw uses in config. A bare ``llm.model`` with a separate
    ``llm.provider`` gets stitched together into
    ``"<provider>/<model>"`` so LiteLLM can route it. Empty models are
    passed through unchanged (the caller should handle that).
    """
    model = llm.model or ""
    if model and llm.provider and "/" not in model:
        return f"{llm.provider}/{model}"
    return model


def litellm_completion_kwargs(llm: LLMConfig) -> dict:
    """Build kwargs for ``litellm.completion`` from a resolved LLMConfig.

    Callers typically spread this into their own call:

    .. code-block:: python

        from defenseclaw.scanner._llm_env import (
            inject_llm_env,
            litellm_completion_kwargs,
        )

        inject_llm_env(llm)
        litellm.completion(
            messages=...,
            **litellm_completion_kwargs(llm),
        )

    Only the fields LiteLLM understands are emitted — :meth:`resolve_llm`
    guarantees sensible defaults for ``timeout`` and ``max_retries``,
    so we pass those through unconditionally.
    """
    kwargs: dict = {
        "model": litellm_model(llm),
        "timeout": llm.effective_timeout(),
        "num_retries": llm.effective_max_retries(),
    }
    api_key = llm.resolved_api_key()
    if api_key:
        kwargs["api_key"] = api_key
    if llm.base_url:
        kwargs["api_base"] = llm.base_url
    return kwargs
