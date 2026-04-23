# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Environment variable inventory → MDX AUTOGEN block."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple

from . import mdx, splice


PAGE = Path("docs-site/reference/env-vars.mdx")

# Regexes — keep narrow to avoid capturing string literals or user data.
PY_GETENV = re.compile(r'os\.(?:getenv|environ\.get)\(\s*[\'"]([A-Z][A-Z0-9_]{1,80})[\'"]')
PY_ENVIRON = re.compile(r'os\.environ\[\s*[\'"]([A-Z][A-Z0-9_]{1,80})[\'"]\s*\]')
PY_CLICK_ENVVAR = re.compile(r'envvar\s*=\s*[\'"]([A-Z][A-Z0-9_]{1,80})[\'"]')
GO_GETENV = re.compile(r'os\.Getenv\(\s*"([A-Z][A-Z0-9_]{1,80})"')
GO_LOOKUP = re.compile(r'os\.LookupEnv\(\s*"([A-Z][A-Z0-9_]{1,80})"')

EXCLUDE = {"PATH", "HOME", "USER", "SHELL", "LANG", "TERM", "PWD", "TMPDIR", "TMP",
           "DISPLAY", "EDITOR", "PAGER", "LOGNAME", "HOSTNAME",
           # Third-party OTel SDK env vars surface noisily and are documented upstream.
           "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_HEADERS",
           "OTEL_EXPORTER_OTLP_PROTOCOL", "OTEL_SERVICE_NAME",
           "OTEL_RESOURCE_ATTRIBUTES", "OTEL_TRACES_SAMPLER",
           "OTEL_SDK_DISABLED", "GOPATH", "GOMAXPROCS", "GOFLAGS", "GOROOT",
           "CI", "GITHUB_ACTIONS", "CODESPACES", "TRAVIS"}


SEARCH_ROOTS = [Path("cli"), Path("internal"), Path("cmd"), Path("extensions"),
                Path("scripts"), Path("observability")]


def _scan() -> Dict[str, Set[str]]:
    """Return {ENV_VAR: {relpath1, relpath2, ...}}."""
    found: Dict[str, Set[str]] = defaultdict(set)
    for root in SEARCH_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in {".py", ".go", ".ts", ".tsx", ".js"}:
                continue
            if any(part in {"node_modules", ".venv", "venv", "dist", "build", "__pycache__"}
                   for part in path.parts):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            patterns = (PY_GETENV, PY_ENVIRON, PY_CLICK_ENVVAR, GO_GETENV, GO_LOOKUP)
            for pat in patterns:
                for m in pat.finditer(text):
                    name = m.group(1)
                    if name in EXCLUDE:
                        continue
                    found[name].add(str(path))
    return found


# Prefix-based grouping for rendering
PREFIX_ORDER = [
    ("DEFENSECLAW_", "DefenseClaw"),
    ("OPENCLAW_", "OpenClaw"),
    ("OTEL_", "OpenTelemetry"),
    ("SPLUNK_", "Splunk"),
    ("OPENAI_", "OpenAI provider"),
    ("ANTHROPIC_", "Anthropic provider"),
    ("OPENROUTER_", "OpenRouter provider"),
    ("GROQ_", "Groq provider"),
    ("GEMINI_", "Gemini provider"),
    ("GOOGLE_", "Google provider"),
    ("MISTRAL_", "Mistral provider"),
    ("COHERE_", "Cohere provider"),
    ("AZURE_", "Azure provider"),
    ("AWS_", "AWS / Bedrock provider"),
    ("XAI_", "xAI provider"),
    ("PERPLEXITY_", "Perplexity provider"),
    ("DATABRICKS_", "Databricks provider"),
    ("FIREWORKS_", "Fireworks provider"),
    ("DEEPSEEK_", "DeepSeek provider"),
    ("TOGETHER_", "Together provider"),
    ("HF_", "Hugging Face provider"),
    ("HUGGINGFACE_", "Hugging Face provider"),
    ("NVIDIA_", "NVIDIA provider"),
    ("LM_", "LM Studio provider"),
    ("OLLAMA_", "Ollama provider"),
    ("LLM_", "LLM provider — generic"),
    ("LITELLM_", "LiteLLM"),
]


def _group(name: str) -> str:
    for prefix, label in PREFIX_ORDER:
        if name.startswith(prefix):
            return label
    return "Miscellaneous"


def _render_block(found: Dict[str, Set[str]]) -> str:
    groups: Dict[str, List[Tuple[str, Set[str]]]] = defaultdict(list)
    for name, paths in sorted(found.items()):
        groups[_group(name)].append((name, paths))

    body: List[str] = []
    body.append(f"_Auto-discovered across `cli/`, `internal/`, `cmd/`, `extensions/`, `scripts/`, and `observability/`. "
                f"Total variables: **{len(found)}**._")
    body.append("")
    # Preserve prefix order; then append Miscellaneous at the end.
    labels_in_order = [label for _, label in PREFIX_ORDER]
    seen = set()
    for label in labels_in_order:
        if label in groups and label not in seen:
            seen.add(label)
            _emit(body, label, groups[label])
    if "Miscellaneous" in groups:
        _emit(body, "Miscellaneous", groups["Miscellaneous"])
    return "\n".join(body).rstrip() + "\n"


def _emit(body: List[str], label: str, items: List[Tuple[str, Set[str]]]) -> None:
    body.append(f"### {label}")
    body.append("")
    rows = []
    for name, paths in sorted(items):
        files = ", ".join(sorted({p.split("/", 1)[-1] if "/" in p else p
                                  for p in paths})[:3])
        if len(paths) > 3:
            files += f" (+{len(paths) - 3} more)"
        rows.append([mdx.md_code(name), mdx.escape_pipe(files)])
    body.append(mdx.render_table(["Variable", "Referenced in"], rows))
    body.append("")


def _template() -> str:
    return """---
title: "Environment variables"
description: "All environment variables read by the DefenseClaw Python CLI, Go gateway, and plugins."
order: 2
---

## Overview

DefenseClaw reads a long tail of environment variables:

- Runtime knobs (`DEFENSECLAW_HOME`, `DEFENSECLAW_ENV`, …).
- Provider credentials proxied by the guardrail (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, …).
- Sink auth tokens (`SPLUNK_HEC_TOKEN`, `OTEL_EXPORTER_OTLP_HEADERS`, …).
- Feature flags toggled for local dev and CI.

This page is auto-generated by walking Python `os.getenv`, Click
`envvar=`, and Go `os.Getenv` / `os.LookupEnv` call-sites under
`cli/`, `internal/`, `cmd/`, `extensions/`, `scripts/`, and
`observability/`.

<Callout type="warning" title="Not authoritative for provider URLs">
  Only the variable *names* are inventoried here. See each provider's
  page under [Guardrail › Providers](/docs-site/guardrail/providers)
  for canonical base URLs, auth headers, and streaming support.
</Callout>

## Reference

<!-- BEGIN AUTOGEN:env_vars:all -->
<!-- END AUTOGEN:env_vars:all -->

## Related

- [Config files](/docs-site/reference/config-files)
- [Exit codes](/docs-site/reference/exit-codes)
- [Guardrail providers](/docs-site/guardrail/providers)

---

<!-- generated-from: cli/, internal/, cmd/, extensions/, scripts/ -->
"""


def run() -> List[Tuple[str, bool]]:
    splice.ensure_scaffold(PAGE, _template())
    found = _scan()
    ch = splice.splice(PAGE, "env_vars", "all", _render_block(found))
    return [(str(PAGE), ch)]


if __name__ == "__main__":
    for p, ch in run():
        print(("CHANGED " if ch else "ok      ") + p)
