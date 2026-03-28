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

"""LLM client -- calls the defenseclaw LLM bridge."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LLMConfig:
    model: str = ""
    api_key: str | None = None
    api_base: str | None = None
    provider: str | None = None
    max_tokens: int | None = None
    python_binary: str | None = None


@dataclass
class LLMMessage:
    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class LLMResponse:
    content: str = ""
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    error: str | None = None


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

_ALLOWED_PYTHON_NAMES = {"python3", "python", "python3.11", "python3.12", "python3.13"}


def validate_python_binary(raw: str) -> str:
    if raw in _ALLOWED_PYTHON_NAMES:
        return raw

    resolved = os.path.abspath(raw)
    if not os.path.isabs(resolved) or ".." in resolved or not os.path.exists(resolved):
        allowed = ", ".join(sorted(_ALLOWED_PYTHON_NAMES))
        raise ValueError(
            f'Refusing untrusted python_binary: "{raw}". '
            f"Use an absolute path to an existing executable or one of: {allowed}"
        )
    return resolved


def call_llm(
    config: LLMConfig | dict[str, Any],
    messages: list[LLMMessage] | list[dict[str, str]],
) -> LLMResponse:
    # Normalise config
    if isinstance(config, dict):
        model = config.get("model", "")
        api_key = config.get("api_key")
        api_base = config.get("api_base")
        provider = config.get("provider")
        max_tokens = config.get("max_tokens", 8192)
        python_binary = config.get("python_binary", "python3")
    else:
        model = config.model
        api_key = config.api_key
        api_base = config.api_base
        provider = config.provider
        max_tokens = config.max_tokens or 8192
        python_binary = config.python_binary or "python3"

    python = validate_python_binary(python_binary or "python3")

    # Normalise messages
    msg_dicts = []
    for m in messages:
        if isinstance(m, dict):
            msg_dicts.append(m)
        else:
            msg_dicts.append({"role": m.role, "content": m.content})

    request: dict[str, Any] = {
        "model": model,
        "messages": msg_dicts,
        "max_tokens": max_tokens,
        "temperature": 0.0,
    }
    if api_key:
        request["api_key"] = api_key
    if api_base:
        request["api_base"] = api_base
    if provider:
        request["provider"] = provider

    input_json = json.dumps(request)

    try:
        proc = subprocess.run(
            [python, "-m", "defenseclaw.llm"],
            input=input_json,
            capture_output=True,
            text=True,
            timeout=120,
        )
        response = json.loads(proc.stdout)
        return LLMResponse(
            content=response.get("content", ""),
            model=response.get("model", model),
            usage=response.get("usage", {}),
            error=response.get("error"),
        )
    except Exception as e:
        return LLMResponse(content="", model=model, usage={}, error=str(e))
