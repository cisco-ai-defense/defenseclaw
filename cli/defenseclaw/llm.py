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

"""defenseclaw-llm — LiteLLM-backed subprocess bridge.

Called by the TypeScript plugin scanner (``@defenseclaw/plugin-scanner``)
and any other out-of-process component that needs to talk to an LLM
without pulling in the full DefenseClaw Python dependency tree on its
own. Uses LiteLLM's :func:`litellm.completion` so every provider
LiteLLM supports — OpenAI, Anthropic, Google, Azure, Bedrock, Groq,
Mistral, DeepSeek, Fireworks, Ollama, vLLM, LM Studio, OpenRouter,
Together.ai, etc. — works through the same bridge with no SDK-specific
branching here.

Routing precedence (high → low) for each field:

1. Explicit JSON request field (``model``, ``api_key``, ``api_base``,
   ``provider``, ``temperature``, ``max_tokens``).
2. The unified :class:`defenseclaw.config.LLMConfig` resolved at
   ``scanners.plugin`` — top-level ``llm:`` merged with
   ``scanners.plugin.llm:`` overrides. This is where
   ``DEFENSECLAW_LLM_KEY`` / ``DEFENSECLAW_LLM_MODEL`` land.
3. Provider-specific env vars (``OPENAI_API_KEY``, ``ANTHROPIC_API_KEY``,
   …) that LiteLLM reads on its own as a last resort.

Guardrail bypass:
    By design, the plugin scanner does NOT route through Bifrost.
    Running DefenseClaw's own guardrails against third-party plugin
    source code would double-bill operators and add latency for no
    security benefit — the scanner IS the guardrail layer. If you want
    guardrails on this path, stand Bifrost up separately and point
    ``api_base`` at it.

Usage::

    echo '{"model":"anthropic/claude-sonnet-4-20250514","messages":[...]}' \\
        | python -m defenseclaw.llm

Input (stdin JSON) — every field is optional except ``messages``::

    {
        "model": "anthropic/claude-sonnet-4-20250514",
        "messages": [{"role": "system", "content": "..."},
                     {"role": "user",   "content": "..."}],
        "max_tokens": 8192,
        "temperature": 0.0,
        "api_key": "...",
        "api_base": "...",
        "provider": "anthropic",
        "timeout": 60,
        "max_retries": 2
    }

Output (stdout JSON)::

    {
        "content": "...",
        "model":   "anthropic/claude-sonnet-4-20250514",
        "usage":   {"prompt_tokens": N,
                    "completion_tokens": N,
                    "total_tokens": N},
        "error":   null
    }
"""

from __future__ import annotations

import json
import os
import sys
import time
from contextlib import contextmanager
from typing import Any

try:
    from opentelemetry import trace as otel_trace
except ImportError:
    otel_trace = None  # type: ignore[assignment]

try:
    from opentelemetry import metrics as otel_metrics
except ImportError:
    otel_metrics = None  # type: ignore[assignment]

from defenseclaw.gateway_error_codes import ERR_LLM_BRIDGE_ERROR

# Opt-in debug flag. Default off so the plugin scanner stays quiet on
# stderr (the TS plugin pipes stderr through to the Cursor/OpenClaw
# log panel, and a noisy bridge pollutes that view). When the operator
# is debugging "why is my LLM analyzer silent?" they can set
# ``DEFENSECLAW_LLM_DEBUG=1`` and get one ``[llm-bridge]`` line per
# fallback so they can tell which stage is failing — import vs config
# load vs resolve vs env injection. We intentionally avoid ``logging``
# here because this module is executed as a short-lived subprocess
# without any log configuration, and configuring a root logger per
# invocation is worse than a plain stderr line.
_DEBUG = os.environ.get("DEFENSECLAW_LLM_DEBUG", "").strip() not in ("", "0", "false", "False")


def _debug(msg: str) -> None:
    if _DEBUG:
        sys.stderr.write(f"[llm-bridge] {msg}\n")


_bridge_hist = None


def _llm_bridge_histogram():
    global _bridge_hist
    if otel_metrics is None:
        return None
    if _bridge_hist is None:
        meter = otel_metrics.get_meter("defenseclaw")
        _bridge_hist = meter.create_histogram(
            name="defenseclaw.llm_bridge.latency",
            unit="ms",
            description="LiteLLM bridge call latency",
        )
    return _bridge_hist


def _record_llm_bridge_latency(model: str, status: str, duration_ms: float) -> None:
    h = _llm_bridge_histogram()
    if h is None:
        return
    attrs = {"status": status}
    if model:
        attrs["gen_ai.request.model"] = model
    h.record(duration_ms, attributes=attrs)


@contextmanager
def _genai_span(model: str, provider_hint: str):
    if otel_trace is None:
        yield
        return
    tracer = otel_trace.get_tracer("defenseclaw.llm")
    with tracer.start_as_current_span("gen_ai.chat.completions") as span:
        span.set_attribute("gen_ai.operation.name", "chat")
        if model:
            span.set_attribute("gen_ai.request.model", model)
        if provider_hint:
            span.set_attribute("gen_ai.provider.name", provider_hint)
        yield


def _log_bridge_error_json(status: str, message: str) -> None:
    rec = {
        "defenseclaw": "llm-bridge",
        "error_code": ERR_LLM_BRIDGE_ERROR,
        "status": status,
        "message": message[:2000],
    }
    sys.stderr.write(json.dumps(rec) + "\n")


def _classify_llm_exception(exc: BaseException) -> str:
    name = type(exc).__name__
    mod = type(exc).__module__
    if isinstance(exc, TimeoutError):
        return "timeout"
    if mod.startswith("httpx") or mod.startswith("http"):
        pass
    try:
        import requests  # noqa: PLC0415 — optional, same as litellm

        if isinstance(exc, requests.Timeout | requests.ConnectTimeout | requests.ReadTimeout):
            return "timeout"
        if isinstance(exc, requests.ConnectionError):
            return "network_error"
    except Exception:
        pass
    try:
        import litellm  # noqa: PLC0415

        if isinstance(exc, getattr(litellm, "RateLimitError", ())):
            return "rate_limited"
        if isinstance(exc, getattr(litellm, "AuthenticationError", ())):
            return "auth_failed"
        if isinstance(exc, getattr(litellm, "Timeout", ())):
            return "timeout"
    except Exception:
        pass
    low = f"{name} {exc}".lower()
    if "429" in low or "rate limit" in low:
        return "rate_limited"
    if "401" in low or "403" in low or "authentication" in low:
        return "auth_failed"
    if "timeout" in low:
        return "timeout"
    if "connection" in low or "connect" in low:
        return "network_error"
    return "internal"


def _load_plugin_llm_config() -> dict[str, Any]:
    """Best-effort load of the plugin-scoped unified LLM config.

    We isolate the import/load inside a try/except because this module
    is designed to run even when DefenseClaw isn't fully installed on
    the host (e.g. a user running the plugin scanner stand-alone from
    the OpenClaw plugin). Missing config → empty dict, callers treat
    it as "no defaults available" and fall back to env vars.

    Each stage swallows its own exceptions and logs to stderr only
    when ``DEFENSECLAW_LLM_DEBUG=1`` — see module-level ``_debug``.
    Silently ignoring errors here was the M6 concern: before the debug
    hook, a config typo left the scanner running with *no* resolved
    defaults and the only symptom was "LLM analyzer shows no findings",
    which is indistinguishable from a clean scan.

    Returned keys map 1:1 to the LiteLLM ``completion`` kwargs so the
    caller can spread them straight in.
    """
    try:
        # ``defenseclaw.config`` exposes ``load()`` as a module-level
        # function, not ``Config.load()``. Using the module entry point
        # also keeps the import surface minimal for plugin scanner
        # subprocesses that don't need the whole ``Config`` class.
        from defenseclaw.config import load as _load_config
        from defenseclaw.scanner._llm_env import (
            inject_llm_env,
            litellm_completion_kwargs,
        )
    except Exception as exc:
        _debug(f"import failed; falling back to env-only routing: {exc!r}")
        return {}

    try:
        cfg = _load_config()
    except Exception as exc:
        _debug(f"config.load() failed; check ~/.defenseclaw/config.yaml: {exc!r}")
        return {}

    try:
        resolved = cfg.resolve_llm("scanners.plugin")
    except Exception as exc:
        _debug(f"cfg.resolve_llm('scanners.plugin') failed: {exc!r}")
        return {}

    _debug(
        "resolved plugin LLM: "
        f"provider={resolved.provider!r} "
        f"model={resolved.model!r} "
        f"api_key_env={resolved.api_key_env!r} "
        f"has_key={bool(resolved.resolved_api_key())} "
        f"base_url={resolved.base_url!r}"
    )

    # Inject the resolved key into provider env vars so LiteLLM picks
    # it up even on code paths that bypass ``api_key=`` (e.g. Bedrock's
    # AWS credential chain, Vertex AI's application-default creds).
    try:
        touched = inject_llm_env(resolved)
        if touched:
            _debug(f"injected env vars: {touched}")
    except Exception as exc:
        _debug(f"inject_llm_env failed (non-fatal): {exc!r}")

    try:
        return litellm_completion_kwargs(resolved)
    except Exception as exc:
        _debug(f"litellm_completion_kwargs failed: {exc!r}")
        return {}


def _merge_defaults(request: dict, defaults: dict) -> dict:
    """Layer defaults under explicit request fields.

    Anything the caller set wins; anything they left empty comes from
    the resolved DefenseClaw config. Kept dead simple because LiteLLM's
    ``completion`` is forgiving about missing optional kwargs.
    """
    merged: dict = dict(defaults)
    # Map request field names → LiteLLM kwarg names. Most are 1:1
    # except ``api_base`` which LiteLLM also accepts as ``api_base``
    # (alias for base_url).
    aliases = {
        "model": "model",
        "api_key": "api_key",
        "api_base": "api_base",
        "timeout": "timeout",
        "max_retries": "num_retries",
    }
    for req_name, litellm_name in aliases.items():
        value = request.get(req_name)
        if value:
            merged[litellm_name] = value
    return merged


def call_llm(request: dict) -> dict:
    """Dispatch a single LLM completion via LiteLLM.

    Returns the canonical bridge response shape regardless of which
    provider actually served the request. Any exception — import,
    network, rate-limit, schema — is surfaced as ``error`` rather than
    raised so the caller (typically a TS subprocess) gets a clean JSON
    error document instead of a crash stack.
    """
    messages = request.get("messages", [])
    if not messages:
        return {
            "content": "",
            "model": request.get("model", ""),
            "usage": {},
            "error": "messages is required and must be a non-empty list",
            "error_code": None,
        }

    try:
        import litellm
    except ImportError:
        return {
            "content": "",
            "model": request.get("model", ""),
            "usage": {},
            "error": (
                "litellm not installed. Install with: pip install litellm "
                "(bundled automatically with `defenseclaw` ≥ 0.5)"
            ),
            "error_code": None,
        }

    defaults = _load_plugin_llm_config()
    kwargs = _merge_defaults(request, defaults)

    # ``provider`` in the request is a hint for LiteLLM's routing when
    # the model is ambiguous (e.g. ``gpt-4o`` could be OpenAI or Azure).
    # LiteLLM expects this stitched into the model string as
    # ``provider/model``, which matches our config convention — only
    # prepend when the caller hasn't already.
    model = kwargs.get("model") or request.get("model") or ""
    provider_hint = request.get("provider", "").strip()
    if model and provider_hint and "/" not in model:
        model = f"{provider_hint}/{model}"
    kwargs["model"] = model

    if not kwargs.get("model"):
        return {
            "content": "",
            "model": "",
            "usage": {},
            "error": (
                "model is required — pass ``model`` in the request or set "
                "``llm.model`` / ``DEFENSECLAW_LLM_MODEL`` in the DefenseClaw "
                "config"
            ),
            "error_code": None,
        }

    # Per-request knobs that LiteLLM expects verbatim.
    kwargs["messages"] = messages
    kwargs["max_tokens"] = request.get("max_tokens", 8192)
    kwargs["temperature"] = request.get("temperature", 0.0)

    t0 = time.perf_counter()
    with _genai_span(model, provider_hint):
        try:
            response = litellm.completion(**kwargs)
        except Exception as exc:
            ms = (time.perf_counter() - t0) * 1000.0
            st = _classify_llm_exception(exc)
            _record_llm_bridge_latency(model, st, ms)
            _log_bridge_error_json(st, f"{type(exc).__name__}: {exc}")
            return {
                "content": "",
                "model": model,
                "usage": {},
                "error": f"{type(exc).__name__}: {exc}",
                "error_code": ERR_LLM_BRIDGE_ERROR,
            }

    # LiteLLM normalizes responses to the OpenAI ChatCompletion shape
    # regardless of provider, so a single extraction path works for
    # every supported backend.
    content = ""
    try:
        choices = response.choices or []
        if choices:
            msg = choices[0].message
            content = getattr(msg, "content", "") or ""
    except Exception as exc:
        ms_bad = (time.perf_counter() - t0) * 1000.0
        _record_llm_bridge_latency(model, "internal", ms_bad)
        _log_bridge_error_json("internal", f"malformed LiteLLM response: {exc}")
        return {
            "content": "",
            "model": model,
            "usage": {},
            "error": f"malformed LiteLLM response: {exc}",
            "error_code": ERR_LLM_BRIDGE_ERROR,
        }

    usage: dict = {}
    response_usage = getattr(response, "usage", None)
    if response_usage is not None:
        prompt_tokens = getattr(response_usage, "prompt_tokens", 0) or 0
        completion_tokens = getattr(response_usage, "completion_tokens", 0) or 0
        total_tokens = getattr(response_usage, "total_tokens", 0) or (
            prompt_tokens + completion_tokens
        )
        usage = {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        }

    _record_llm_bridge_latency(model, "success", (time.perf_counter() - t0) * 1000.0)

    return {
        "content": content,
        "model": getattr(response, "model", "") or model,
        "usage": usage,
        "error": None,
        "error_code": None,
    }


# Backward-compatible alias — older call sites (and the OpenClaw plugin
# bridge) imported ``call_litellm`` before this module was renamed
# ``call_llm``. Keep the name live so upgrading DefenseClaw doesn't
# break a pinned plugin version.
call_litellm = call_llm


def main() -> None:
    """Entry point for ``python -m defenseclaw.llm``.

    Reads one JSON request from stdin, writes one JSON response to
    stdout. Non-zero exit codes are deliberately avoided — errors are
    reported in the response body so the caller can distinguish
    transport failures (subprocess died) from model failures (rate
    limit, auth, bad model id).
    """
    raw = sys.stdin.read().strip()
    if not raw:
        json.dump(
            {"content": "", "model": "", "usage": {}, "error": "empty input"},
            sys.stdout,
        )
        return

    try:
        request = json.loads(raw)
    except json.JSONDecodeError as exc:
        json.dump(
            {
                "content": "",
                "model": "",
                "usage": {},
                "error": f"invalid JSON: {exc}",
            },
            sys.stdout,
        )
        return

    result = call_llm(request)
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
