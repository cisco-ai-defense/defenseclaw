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

"""Connector-agnostic LLM key + model helpers.

This module is the home for the small set of helpers that map a
``provider/model`` string (``"anthropic/claude-3-5-sonnet"``,
``"bedrock/us.anthropic.claude-3-haiku"``, ``"gpt-4o"``, …) to:

* the environment variable holding the matching API key
* a short alias used as a per-provider proxy name
* a deterministic master-key derivation rooted at ``device.key``

These primitives are used by ``defenseclaw setup``, ``defenseclaw
doctor``, the LiteLLM bridge, and the per-connector guardrail
modules. They contain *no* OpenClaw-specific behavior — splitting
them out from the historical ``guardrail.py`` (S4.4) is what lets
Codex / Claude Code / ZeptoClaw guardrail flows reuse them without
inheriting the OpenClaw config-patch logic.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path


def detect_api_key_env(model: str) -> str:
    """Guess the API key env var from the model string.

    Routing is prefix-first: a model written as
    ``"bedrock/us.anthropic.claude-…"`` must yield the *Bedrock*
    bearer env var, not ``ANTHROPIC_API_KEY``, because that's the
    provider LiteLLM will actually call. Earlier revisions
    substring-matched ``"claude"`` and got this wrong, so every
    Bedrock Claude model silently wrote the key into the Anthropic
    env var while the scanner read from ``AWS_BEARER_TOKEN_BEDROCK``
    — i.e. an empty key. The prefix check runs before any substring
    matching to prevent that regression.
    """
    lower = model.lower()
    # Prefix routing (strongest signal). Order matters only within
    # this block: bedrock before anthropic because bedrock/claude-* is
    # a *Bedrock* call, not an Anthropic call.
    if "/" in lower:
        prefix = lower.split("/", 1)[0]
        if prefix == "bedrock":
            # LiteLLM reads the Bedrock short-term bearer token
            # (ABSK…) from AWS_BEARER_TOKEN_BEDROCK; AWS_ACCESS_KEY_ID
            # is the SigV4 key-id pair, which is a different auth
            # flow. Suggesting the bearer env var keeps setup,
            # doctor, and the Python scanner bridge (_llm_env.py) in
            # lockstep — otherwise `setup llm` writes one env var and
            # the scanners read another. Operators using long-term
            # SigV4 creds should override api_key_env by hand.
            return "AWS_BEARER_TOKEN_BEDROCK"
        if prefix == "anthropic":
            return "ANTHROPIC_API_KEY"
        if prefix == "azure":
            return "AZURE_OPENAI_API_KEY"
        if prefix == "openrouter":
            return "OPENROUTER_API_KEY"
        if prefix == "openai":
            return "OPENAI_API_KEY"
        if prefix in ("gemini", "google", "vertex_ai"):
            return "GOOGLE_API_KEY"
    # Substring fallback for bare model names (``claude-3``, ``gpt-4o``)
    # — same behavior as before so existing configs without provider
    # prefixes still resolve.
    if "anthropic" in lower or "claude" in lower:
        return "ANTHROPIC_API_KEY"
    if "azure" in lower:
        return "AZURE_OPENAI_API_KEY"
    if "openrouter" in lower:
        return "OPENROUTER_API_KEY"
    if "openai" in lower or "gpt" in lower or "o1" in lower:
        return "OPENAI_API_KEY"
    if "gemini" in lower or "google" in lower:
        return "GOOGLE_API_KEY"
    if "bedrock" in lower:
        return "AWS_BEARER_TOKEN_BEDROCK"
    return "LLM_API_KEY"


def model_to_proxy_name(model: str) -> str:
    """Derive a short model alias from a full model string like
    ``'anthropic/claude-opus-4-5'``."""
    name = model.split("/")[-1] if "/" in model else model
    for prefix in (
        "anthropic-",
        "openai-",
        "google-",
        "azure-",
        "openrouter-",
        "gemini-",
        "gemini-openai-",
    ):
        name = name.removeprefix(prefix)
    return name


def derive_master_key(device_key_file: str) -> str:
    """Derive a deterministic master key from the device key file.

    Tries the given path first, then the default
    ``~/.defenseclaw/device.key``. Raises
    :class:`RuntimeError` if neither exists — we no longer fall back
    to a static key because that produces predictable proxy
    credentials (a credential-stuffing oracle).

    Implementation note: ``hmac.new`` over the raw key bytes with a
    fixed string label is intentional — we want determinism across
    sidecar restarts so the gateway can re-issue the same proxy
    bearer without forcing every scanner to re-fetch a new value.
    """
    candidates = [device_key_file]
    default_path = os.path.join(str(Path.home()), ".defenseclaw", "device.key")
    if _expand(device_key_file) != default_path:
        candidates.append(default_path)

    for candidate in candidates:
        path = _expand(candidate)
        try:
            with open(path, "rb") as f:
                data = f.read()
            digest = hmac.new(
                b"defenseclaw-proxy-master-key", data, hashlib.sha256
            ).hexdigest()[:32]
            return f"sk-dc-{digest}"
        except OSError:
            continue
    raise RuntimeError(
        f"Device key not found: {device_key_file}\n"
        f"  Run 'defenseclaw init' to generate a device key."
    )


# ---------------------------------------------------------------------------
# Internal helper — kept private to avoid divergence from the path
# expansion contract used elsewhere in the CLI (``connector_paths._expand``).
# ---------------------------------------------------------------------------

def _expand(p: str) -> str:
    if p.startswith("~/"):
        return str(Path.home() / p[2:])
    return p
