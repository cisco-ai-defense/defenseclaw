# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""LLM provider matrix → MDX AUTOGEN block.

Source:
  * internal/configs/providers.json — canonical provider list
  * internal/gateway/adapter_*.go — format adapters (OpenAI-chat,
    OpenAI-responses, Anthropic, Gemini, Bedrock-converse, Ollama)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

from . import mdx, splice


PAGE = Path("docs-site/guardrail/providers.mdx")
PROVIDERS_JSON = Path("internal/configs/providers.json")
ADAPTER_DIR = Path("internal/gateway")


def _discover_adapters() -> List[str]:
    names = []
    for f in sorted(ADAPTER_DIR.glob("adapter_*.go")):
        stem = f.stem  # adapter_openai_chat
        names.append(stem.removeprefix("adapter_"))
    return names


def _render_block(data: dict) -> str:
    providers = data.get("providers") or []
    body: List[str] = []
    body.append(f"_{len(providers)} providers mapped; adapters auto-select the right "
                f"request/response format per route._")
    body.append("")
    body.append(mdx.render_table(
        ["Provider", "Domains", "Profile ID", "Env vars"],
        [[
            mdx.md_code(p["name"]),
            ", ".join(mdx.md_code(d) for d in p.get("domains", [])) or "—",
            mdx.md_code(p.get("profile_id") or "") if p.get("profile_id") else "—",
            ", ".join(mdx.md_code(e) for e in p.get("env_keys", [])) or "—",
        ] for p in providers],
    ))
    body.append("")
    body.append("**Format adapters**")
    body.append("")
    body.append("These adapters shape requests and parse streaming responses. "
                "`internal/gateway/adapter_*.go`.")
    body.append("")
    adapters = _discover_adapters()
    body.append(mdx.render_table(
        ["Adapter", "Source"],
        [[mdx.md_code(a), mdx.md_code(f"internal/gateway/adapter_{a}.go")]
         for a in adapters],
    ))
    return "\n".join(body).rstrip() + "\n"


def _template() -> str:
    return """---
title: "Providers"
description: "LLM provider catalog and format adapter matrix for the DefenseClaw guardrail."
order: 12
---

## Overview

The guardrail proxy is a LiteLLM-compatible endpoint on `localhost:4000`.
It fans out to upstream LLM providers using format adapters that shape
the request body and parse the streaming response. The matrix below
is sourced from [`internal/configs/providers.json`](https://github.com/cisco-ai-defense/defenseclaw/blob/main/internal/configs/providers.json)
and the adapter files under `internal/gateway/`.

<Callout type="info">
  Credentials are never stored in config.yaml — they are loaded from the
  environment (see [Environment variables](/docs-site/reference/env-vars))
  or `~/.defenseclaw/.env` which the sidecar daemon reads during
  `PersistentPreRunE`.
</Callout>

## Reference

<!-- BEGIN AUTOGEN:providers:matrix -->
<!-- END AUTOGEN:providers:matrix -->

## Adding a new provider

See [Developer › Architecture](/docs-site/developer/architecture#provider-pipeline)
for the end-to-end flow, and [Developer › Plugin protocol](/docs-site/developer/plugin-protocol)
if you need a custom injection point.

## Related

- [Guardrail overview](/docs-site/guardrail/index)
- [Streaming](/docs-site/guardrail/streaming)
- [Environment variables](/docs-site/reference/env-vars)

---

<!-- generated-from: internal/configs/providers.json, internal/gateway/adapter_anthropic.go, internal/gateway/adapter_gemini.go, internal/gateway/adapter_openai_chat.go, internal/gateway/adapter_openai_responses.go, internal/gateway/adapter_bedrock_converse.go, internal/gateway/adapter_ollama.go -->
"""


def run() -> List[Tuple[str, bool]]:
    data = json.loads(PROVIDERS_JSON.read_text())
    splice.ensure_scaffold(PAGE, _template())
    ch = splice.splice(PAGE, "providers", "matrix", _render_block(data))
    return [(str(PAGE), ch)]


if __name__ == "__main__":
    for p, ch in run():
        print(("CHANGED " if ch else "ok      ") + p)
