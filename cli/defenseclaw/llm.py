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

"""defenseclaw-llm — thin CLI bridge to LLM provider SDKs.

Called by the TypeScript plugin scanner (and anything else) via subprocess.
Routes to Anthropic or OpenAI based on the model name.

Usage:
  echo '{"model":"claude-sonnet-4-20250514","messages":[...]}' | python -m defenseclaw.llm
  python -m defenseclaw.llm --model claude-sonnet-4-20250514 --prompt "Analyze this code..."

Input (stdin JSON):
  {
    "model": "claude-sonnet-4-20250514",
    "messages": [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}],
    "max_tokens": 8192,
    "temperature": 0.0,
    "api_key": "...",           // optional, falls back to env
    "api_base": "...",          // optional
    "provider": "anthropic"     // optional, auto-detected from model name
  }

Output (stdout JSON):
  {
    "content": "...",           // assistant response text
    "model": "...",             // actual model used
    "usage": {"prompt_tokens": N, "completion_tokens": N, "total_tokens": N},
    "error": null               // or error message string
  }
"""

from __future__ import annotations

import json
import sys


def _resolve_provider(model: str, provider_hint: str = "") -> tuple[str, str]:
    """Determine the provider and bare model name.

    Returns (provider, bare_model).  Handles prefixed names like
    ``anthropic/claude-sonnet-4-20250514`` and bare names like ``claude-sonnet-4-20250514``.
    """
    if provider_hint:
        bare = model.split("/", 1)[-1] if "/" in model else model
        return provider_hint.lower(), bare

    if "/" in model:
        prefix, bare = model.split("/", 1)
        return prefix.lower(), bare

    lower = model.lower()
    if lower.startswith("claude"):
        return "anthropic", model
    if lower.startswith(("gpt", "o1", "o3", "o4")):
        return "openai", model
    if lower.startswith("gemini"):
        return "google", model

    return "openai", model


def _call_anthropic(
    model: str,
    messages: list[dict],
    max_tokens: int,
    temperature: float,
    api_key: str | None,
    api_base: str | None,
) -> dict:
    try:
        import anthropic
    except ImportError:
        return {
            "content": "",
            "model": model,
            "usage": {},
            "error": "anthropic SDK not installed. Install with: pip install anthropic",
        }

    kwargs: dict = {}
    if api_key:
        kwargs["api_key"] = api_key
    if api_base:
        kwargs["base_url"] = api_base

    client = anthropic.Anthropic(**kwargs)

    system_text = ""
    api_messages = []
    for msg in messages:
        if msg.get("role") == "system":
            system_text = msg.get("content", "")
        else:
            api_messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})

    create_kwargs: dict = {
        "model": model,
        "messages": api_messages,
        "max_tokens": max_tokens,
    }
    if temperature > 0:
        create_kwargs["temperature"] = temperature
    if system_text:
        create_kwargs["system"] = system_text

    response = client.messages.create(**create_kwargs)

    content = ""
    for block in response.content:
        if hasattr(block, "text"):
            content += block.text

    usage = {}
    if response.usage:
        usage = {
            "prompt_tokens": response.usage.input_tokens,
            "completion_tokens": response.usage.output_tokens,
            "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
        }

    return {
        "content": content,
        "model": response.model,
        "usage": usage,
        "error": None,
    }


def _call_openai(
    model: str,
    messages: list[dict],
    max_tokens: int,
    temperature: float,
    api_key: str | None,
    api_base: str | None,
) -> dict:
    try:
        import openai
    except ImportError:
        return {
            "content": "",
            "model": model,
            "usage": {},
            "error": "openai SDK not installed. Install with: pip install openai",
        }

    kwargs: dict = {}
    if api_key:
        kwargs["api_key"] = api_key
    if api_base:
        kwargs["base_url"] = api_base

    client = openai.OpenAI(**kwargs)

    response = client.chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=max_tokens,
        temperature=temperature,
    )

    content = ""
    if response.choices and len(response.choices) > 0:
        content = response.choices[0].message.content or ""

    usage = {}
    if response.usage:
        usage = {
            "prompt_tokens": response.usage.prompt_tokens or 0,
            "completion_tokens": response.usage.completion_tokens or 0,
            "total_tokens": response.usage.total_tokens or 0,
        }

    return {
        "content": content,
        "model": response.model or model,
        "usage": usage,
        "error": None,
    }


def call_llm(request: dict) -> dict:
    model = request.get("model", "")
    messages = request.get("messages", [])
    max_tokens = request.get("max_tokens", 8192)
    temperature = request.get("temperature", 0.0)
    api_key = request.get("api_key")
    api_base = request.get("api_base")
    provider_hint = request.get("provider", "")

    provider, bare_model = _resolve_provider(model, provider_hint)

    try:
        if provider == "anthropic":
            return _call_anthropic(bare_model, messages, max_tokens, temperature, api_key, api_base)
        else:
            return _call_openai(bare_model, messages, max_tokens, temperature, api_key, api_base)
    except Exception as exc:
        return {
            "content": "",
            "model": model,
            "usage": {},
            "error": str(exc),
        }


# Backward-compatible alias.
call_litellm = call_llm


def main() -> None:
    raw = sys.stdin.read().strip()
    if not raw:
        json.dump({"content": "", "model": "", "usage": {}, "error": "empty input"}, sys.stdout)
        return

    try:
        request = json.loads(raw)
    except json.JSONDecodeError as exc:
        json.dump({"content": "", "model": "", "usage": {}, "error": f"invalid JSON: {exc}"}, sys.stdout)
        return

    result = call_llm(request)
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
