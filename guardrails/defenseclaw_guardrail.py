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

"""DefenseClaw LiteLLM Guardrail — LLM traffic inspection for agentic AI.

Intercepts all prompts and completions flowing through the LiteLLM proxy.
Operates in two modes (set via DEFENSECLAW_GUARDRAIL_MODE env var):

  observe  — log findings, never block (default)
  action   — block prompts/responses that match security policies

Scanner mode (set via DEFENSECLAW_SCANNER_MODE env var):

  local    — only local pattern matching (default)
  remote   — only Cisco AI Defense cloud API
  both     — local first; if clean, run remote as second layer
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

try:
    from litellm.integrations.custom_guardrail import CustomGuardrail
except ModuleNotFoundError:
    CustomGuardrail = object  # type: ignore[misc,assignment]

if TYPE_CHECKING:
    from litellm.caching.caching import DualCache
    from litellm.proxy._types import UserAPIKeyAuth

BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

INJECTION_PATTERNS = [
    "ignore previous", "ignore all instructions", "ignore above",
    "disregard previous", "disregard all", "you are now",
    "act as", "pretend you are", "bypass", "jailbreak",
    "do anything now", "dan mode",
]

SECRET_PATTERNS = [
    "sk-", "sk-ant-", "sk-proj-", "api_key=", "apikey=",
    "-----begin rsa", "-----begin private", "-----begin openssh",
    "aws_access_key", "aws_secret_access", "password=",
    "token:", "bearer ", "ghp_", "gho_", "github_pat_",
]

EXFIL_PATTERNS = [
    "/etc/passwd", "/etc/shadow", "base64 -d", "base64 --decode",
    "exfiltrate", "send to my server", "curl http",
]

_SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ---------------------------------------------------------------------------
# Cross-instance verdict cache
#
# LiteLLM creates a *separate* guardrail instance per mode (pre_call,
# during_call, post_call).  To pass the pre_call verdict to during_call's
# moderation hook we use a module-level cache keyed by the data dict id.
# Entries expire after _VERDICT_TTL seconds to prevent leaks.
# ---------------------------------------------------------------------------

_verdict_cache: dict[int, tuple[dict[str, Any], float]] = {}
_verdict_lock = threading.Lock()
_VERDICT_TTL = 30.0
_VERDICT_CLEANUP_INTERVAL = 60.0
_last_verdict_cleanup: float = 0.0

_SECRET_REDACT_RE = re.compile(
    r"(?:sk-ant-|sk-proj-|sk-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_"
    r"|xox[bpors]-|AIza|eyJ)[A-Za-z0-9\-_+/=.]{6,}"
    r"|AKIA[A-Z0-9]{12,}",
    re.IGNORECASE,
)
_KV_REDACT_RE = re.compile(
    r"((?:password|secret|token|api_key|apikey|aws_secret_access)[=:\s]+)\S{6,}",
    re.IGNORECASE,
)


def _redact_secrets(text: str) -> str:
    text = _SECRET_REDACT_RE.sub(lambda m: m.group()[:4] + "***REDACTED***", text)
    text = _KV_REDACT_RE.sub(r"\1***REDACTED***", text)
    return text


def _cache_verdict(data_id: int, verdict: dict[str, Any]) -> None:
    global _last_verdict_cleanup
    with _verdict_lock:
        _verdict_cache[data_id] = (verdict, time.monotonic())
        now = time.monotonic()
        if now - _last_verdict_cleanup > _VERDICT_CLEANUP_INTERVAL:
            _last_verdict_cleanup = now
            cutoff = now - _VERDICT_TTL
            stale = [k for k, (_, ts) in _verdict_cache.items() if ts < cutoff]
            for k in stale:
                _verdict_cache.pop(k, None)


def _pop_verdict(data_id: int) -> dict[str, Any] | None:
    with _verdict_lock:
        entry = _verdict_cache.pop(data_id, None)
    if entry is None:
        return None
    verdict, ts = entry
    if time.monotonic() - ts > _VERDICT_TTL:
        return None
    return verdict


# ---------------------------------------------------------------------------
# Cisco AI Defense Inspect API client
# ---------------------------------------------------------------------------

_DEFAULT_ENABLED_RULES: list[dict[str, str]] = [
    {"rule_name": "Prompt Injection"},
    {"rule_name": "Harassment"},
    {"rule_name": "Hate Speech"},
    {"rule_name": "Profanity"},
    {"rule_name": "Sexual Content & Exploitation"},
    {"rule_name": "Social Division & Polarization"},
    {"rule_name": "Violence & Public Safety Threats"},
    {"rule_name": "Code Detection"},
]


class CiscoAIDefenseClient:
    """Calls the Cisco AI Defense Chat Inspection API (/api/v1/inspect/chat).

    API key is read from env var (never hardcoded).  Endpoint is configurable
    via CISCO_AI_DEFENSE_ENDPOINT (default: US region).
    """

    def __init__(self) -> None:
        self.api_key: str = os.environ.get(
            os.environ.get("CISCO_AI_DEFENSE_API_KEY_ENV", "CISCO_AI_DEFENSE_API_KEY"),
            "",
        )
        self.endpoint: str = os.environ.get(
            "CISCO_AI_DEFENSE_ENDPOINT",
            "https://us.api.inspect.aidefense.security.cisco.com",
        ).rstrip("/")
        try:
            self.timeout_s: float = int(os.environ.get("CISCO_AI_DEFENSE_TIMEOUT_MS", "3000")) / 1000.0
        except (ValueError, TypeError):
            self.timeout_s = 3.0
        rules_env = os.environ.get("CISCO_AI_DEFENSE_ENABLED_RULES", "")
        self.enabled_rules: list[dict[str, str]] = (
            [{"rule_name": r.strip()} for r in rules_env.split(",") if r.strip()]
            if rules_env
            else list(_DEFAULT_ENABLED_RULES)
        )

    def inspect(self, messages: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Send messages to Cisco AI Defense and return a normalized verdict.

        Returns None on any error (network, auth, timeout) so the caller can
        fall back to local-only scanning.
        """
        if not self.api_key:
            return None

        chat_messages = []
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, list):
                content = " ".join(
                    b.get("text", "") for b in content
                    if isinstance(b, dict) and b.get("type") == "text"
                )
            chat_messages.append({"role": msg.get("role", "user"), "content": content})

        payload: dict[str, Any] = {"messages": chat_messages}
        if self.enabled_rules:
            payload["config"] = {"enabled_rules": self.enabled_rules}

        url = f"{self.endpoint}/api/v1/inspect/chat"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Cisco-AI-Defense-API-Key": self.api_key,
        }

        tried_without_rules = False
        for _attempt in range(2):
            try:
                body = json.dumps(payload).encode()
                req = urllib.request.Request(url, data=body, headers=headers, method="POST")
                resp = urllib.request.urlopen(req, timeout=self.timeout_s)
                data = json.loads(resp.read().decode())
                return self._normalize(data)
            except urllib.error.HTTPError as exc:
                if exc.code == 400 and not tried_without_rules and "config" in payload:
                    err_body = exc.read().decode("utf-8", errors="replace").lower()
                    if "already has rules configured" in err_body or "pre-configured" in err_body:
                        payload.pop("config", None)
                        tried_without_rules = True
                        print(f"  {DIM}[cisco-ai-defense] key has pre-configured rules, retrying without config{RESET}", file=sys.stderr)
                        continue
                print(f"  {DIM}[cisco-ai-defense] error: {exc}{RESET}", file=sys.stderr)
                return None
            except Exception as exc:
                print(f"  {DIM}[cisco-ai-defense] error: {exc}{RESET}", file=sys.stderr)
                return None
        return None

    @staticmethod
    def _normalize(data: dict[str, Any]) -> dict[str, Any]:
        """Map Cisco InspectResponse to DefenseClaw verdict format.

        The API returns: is_safe (bool), action (str e.g. "Block"),
        classifications (list[str]), rules (list[{rule_name, classification}]).
        """
        is_safe = data.get("is_safe", True)
        api_action = data.get("action", "").lower()

        classifications = [
            c for c in data.get("classifications", [])
            if c and c != "NONE_VIOLATION"
        ]
        rules_list = data.get("rules", [])
        rule_names = [
            r.get("rule_name", "")
            for r in rules_list
            if r.get("rule_name") and r.get("classification", "") != "NONE_VIOLATION"
        ]
        findings = classifications + rule_names

        if is_safe and api_action != "block":
            return {
                "action": "allow",
                "severity": "NONE",
                "reason": "",
                "findings": [],
                "scanner": "ai-defense",
            }

        severity = "HIGH" if api_action == "block" else "MEDIUM"
        action = "block" if api_action == "block" else "alert"
        reason = f"cisco: {', '.join(findings[:5])}" if findings else "cisco: content flagged"
        return {
            "action": action,
            "severity": severity,
            "reason": reason,
            "findings": findings,
            "scanner": "ai-defense",
        }


# ---------------------------------------------------------------------------
# Verdict merging
# ---------------------------------------------------------------------------

def _merge_verdicts(
    local_result: dict[str, Any] | None,
    cisco_result: dict[str, Any] | None,
) -> dict[str, Any]:
    """Merge local and Cisco verdicts, taking the higher severity."""
    if local_result is None and cisco_result is None:
        return {"action": "allow", "severity": "NONE", "reason": "", "findings": [], "scanner_sources": []}

    if local_result is None:
        cisco_result.setdefault("scanner_sources", ["ai-defense"])
        return cisco_result
    if cisco_result is None:
        local_result.setdefault("scanner_sources", ["local-pattern"])
        return local_result

    local_sev = _SEVERITY_RANK.get(local_result.get("severity", "NONE"), 0)
    cisco_sev = _SEVERITY_RANK.get(cisco_result.get("severity", "NONE"), 0)

    if cisco_sev > local_sev:
        winner = cisco_result
    else:
        winner = local_result

    combined_findings = list(local_result.get("findings", [])) + list(cisco_result.get("findings", []))
    reasons = []
    if local_result.get("reason"):
        reasons.append(local_result["reason"])
    if cisco_result.get("reason"):
        reasons.append(cisco_result["reason"])

    return {
        "action": winner["action"],
        "severity": winner["severity"],
        "reason": "; ".join(reasons),
        "findings": combined_findings,
        "scanner_sources": ["local-pattern", "ai-defense"],
    }


# ---------------------------------------------------------------------------
# Hot-reload: TTL-cached runtime config from sidecar file
# ---------------------------------------------------------------------------

_runtime_cache: dict[str, Any] | None = None
_runtime_cache_ts: float = 0.0
_RUNTIME_CACHE_TTL = 5.0


def _read_runtime_config() -> dict[str, str]:
    """Read guardrail_runtime.json with a 5-second TTL cache."""
    global _runtime_cache, _runtime_cache_ts
    now = time.monotonic()
    if now - _runtime_cache_ts < _RUNTIME_CACHE_TTL and _runtime_cache is not None:
        return _runtime_cache

    data_dir = os.environ.get("DEFENSECLAW_DATA_DIR", os.path.expanduser("~/.defenseclaw"))
    runtime_file = os.path.join(data_dir, "guardrail_runtime.json")
    try:
        with open(runtime_file) as f:
            _runtime_cache = json.load(f)
    except (OSError, json.JSONDecodeError):
        _runtime_cache = {}
    _runtime_cache_ts = now
    return _runtime_cache


class DefenseClawGuardrail(CustomGuardrail):
    """LiteLLM custom guardrail for DefenseClaw."""

    def __init__(self, **kwargs: Any) -> None:
        self.mode: str = os.getenv("DEFENSECLAW_GUARDRAIL_MODE", "observe")
        self.scanner_mode: str = os.getenv("DEFENSECLAW_SCANNER_MODE", "local")
        self.block_message: str = ""
        self._cisco_client: CiscoAIDefenseClient | None = None
        if self.scanner_mode in ("remote", "both"):
            self._cisco_client = CiscoAIDefenseClient()
        super().__init__(**kwargs)

    # ------------------------------------------------------------------
    # Local pattern scanning
    # ------------------------------------------------------------------

    @staticmethod
    def _scan_patterns(text: str, patterns: list[str]) -> list[str]:
        lower = text.lower()
        return [p for p in patterns if p in lower]

    def _scan_local(self, direction: str, content: str) -> dict[str, Any]:
        """Run local pattern-based scanning."""
        flags: list[str] = []
        if direction == "prompt":
            flags.extend(self._scan_patterns(content, INJECTION_PATTERNS))
            flags.extend(self._scan_patterns(content, EXFIL_PATTERNS))
        flags.extend(self._scan_patterns(content, SECRET_PATTERNS))

        if not flags:
            return {"action": "allow", "severity": "NONE", "reason": "", "findings": [], "scanner": "local-pattern"}

        severity = "HIGH" if any(
            p in flags for p in INJECTION_PATTERNS + EXFIL_PATTERNS
        ) else "MEDIUM"

        return {
            "action": "block" if severity in ("HIGH", "CRITICAL") else "alert",
            "severity": severity,
            "reason": f"matched: {', '.join(flags[:5])}",
            "findings": flags,
            "scanner": "local-pattern",
        }

    # ------------------------------------------------------------------
    # Multi-scanner orchestrator
    # ------------------------------------------------------------------

    def _inspect(
        self,
        direction: str,
        content: str,
        messages: list[dict[str, Any]] | None = None,
        model: str = "",
    ) -> dict[str, Any]:
        """Run scanners according to scanner_mode config.

        local:  only local patterns
        remote: only Cisco AI Defense
        both:   local first, skip remote if local already flags
        """
        runtime = _read_runtime_config()
        if runtime.get("scanner_mode"):
            new_sm = runtime["scanner_mode"]
            if new_sm != self.scanner_mode:
                self.scanner_mode = new_sm
                if new_sm in ("remote", "both") and self._cisco_client is None:
                    self._cisco_client = CiscoAIDefenseClient()
                elif new_sm == "local":
                    self._cisco_client = None
        if "block_message" in runtime:
            self.block_message = runtime["block_message"]

        local_result: dict[str, Any] | None = None
        cisco_result: dict[str, Any] | None = None

        if self.scanner_mode in ("local", "both"):
            local_result = self._scan_local(direction, content)

        if self.scanner_mode == "both" and local_result and local_result.get("severity") != "NONE":
            local_result.setdefault("scanner_sources", ["local-pattern"])
            return local_result

        cisco_elapsed_ms: float = 0.0
        if self.scanner_mode in ("remote", "both") and self._cisco_client and messages:
            _t0 = time.monotonic()
            cisco_result = self._cisco_client.inspect(messages)
            cisco_elapsed_ms = (time.monotonic() - _t0) * 1000

        merged = _merge_verdicts(local_result, cisco_result)
        merged["cisco_elapsed_ms"] = cisco_elapsed_ms

        opa_verdict = self._evaluate_via_sidecar(
            direction=direction,
            model=model,
            local_result=local_result,
            cisco_result=cisco_result,
            content_length=len(content),
        )
        if opa_verdict:
            return opa_verdict

        return merged

    # ------------------------------------------------------------------
    # OPA sidecar evaluation (synchronous)
    # ------------------------------------------------------------------

    def _evaluate_via_sidecar(
        self,
        direction: str,
        model: str,
        local_result: dict[str, Any] | None,
        cisco_result: dict[str, Any] | None,
        content_length: int,
    ) -> dict[str, Any] | None:
        """POST to Go sidecar's OPA guardrail evaluate endpoint.

        Returns the OPA verdict or None if the sidecar is unreachable
        (falls back to _merge_verdicts).
        """
        port = os.environ.get("DEFENSECLAW_API_PORT")
        if not port:
            return None

        def _strip_scanner(d: dict[str, Any] | None) -> dict[str, Any] | None:
            if d is None:
                return None
            return {k: v for k, v in d.items() if k != "scanner" and k != "scanner_sources"}

        payload: dict[str, Any] = {
            "direction": direction,
            "model": model,
            "mode": self.mode,
            "scanner_mode": self.scanner_mode,
            "local_result": _strip_scanner(local_result),
            "cisco_result": _strip_scanner(cisco_result),
            "content_length": content_length,
        }

        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{int(port)}/v1/guardrail/evaluate",
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "X-DefenseClaw-Client": "litellm-guardrail",
                },
                method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=2)
            result = json.loads(resp.read().decode())
            if "action" in result and "severity" in result:
                return result
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # PRE-CALL: inspect prompt before it reaches the LLM
    # ------------------------------------------------------------------

    # Defense-in-depth: strip OpenAI-only parameters that Anthropic rejects.
    _STRIP_OPENAI_PARAMS = frozenset({
        "store", "metadata", "frequency_penalty", "presence_penalty",
        "logit_bias", "logprobs", "top_logprobs", "n", "seed",
        "service_tier", "suffix",
    })

    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict[str, Any],
        call_type: Any | None = None,
    ) -> Exception | str | dict[str, Any] | None:
        for p in self._STRIP_OPENAI_PARAMS:
            data.pop(p, None)

        messages = data.get("messages", [])
        text = self._last_user_text(messages)
        if not text:
            return data

        model = data.get("model", "?")
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        t0 = time.monotonic()

        verdict = self._inspect("prompt", text, messages, model=model)
        elapsed_ms = (time.monotonic() - t0) * 1000

        severity = verdict.get("severity", "NONE")
        action = verdict.get("action", "allow")
        reason = verdict.get("reason", "")

        self._log_pre_call(ts, model, messages, severity, action, reason, elapsed_ms)
        self._report_to_sidecar("prompt", model, verdict, elapsed_ms)

        _cache_verdict(id(data), verdict)

        if action == "block" and self.mode == "action":
            user_msg = self._block_message("prompt", reason)
            data["_defenseclaw_prompt_blocked"] = True
            # Plain string (not ModelResponse): LiteLLM streams it in small deltas
            # then emits a final finish_reason chunk — matches OpenAI shape OpenClaw expects.
            data["mock_response"] = user_msg
            return data

        return data

    # ------------------------------------------------------------------
    # MODERATION: runs in parallel with LLM call
    #
    # Safety-net for blocked prompts.  Pre-call sets ``mock_response`` so the
    # router returns a synthetic completion (HTTP 200) and never calls the LLM.
    # Skip this hook in that case — otherwise it would race route_request and
    # can raise HTTP 400 while the mock completion is already being returned.
    # ------------------------------------------------------------------

    async def async_moderation_hook(
        self,
        data: dict[str, Any],
        user_api_key_dict: UserAPIKeyAuth,
        call_type: Any | None = None,
    ) -> None:
        if data.get("_defenseclaw_prompt_blocked"):
            _pop_verdict(id(data))
            return

        cached = _pop_verdict(id(data))
        if cached:
            action = cached.get("action", "allow")
            reason = cached.get("reason", "")
        else:
            messages = data.get("messages", [])
            text = self._last_user_text(messages)
            if not text:
                return
            model = data.get("model", "?")
            verdict = self._inspect("prompt", text, messages, model=model)
            action = verdict.get("action", "allow")
            reason = verdict.get("reason", "")

        if action == "block" and self.mode == "action":
            from fastapi import HTTPException
            raise HTTPException(
                status_code=400,
                detail={"error": {"message": self._block_message("prompt", reason),
                                  "type": "content_filter", "code": "content_filter"}},
            )

    # ------------------------------------------------------------------
    # POST-CALL: inspect completion after LLM responds
    # ------------------------------------------------------------------

    async def async_post_call_success_hook(
        self,
        data: dict[str, Any],
        user_api_key_dict: UserAPIKeyAuth,
        response: Any,
    ) -> None:
        import litellm

        if data.get("_defenseclaw_prompt_blocked"):
            return

        content = ""
        tool_calls: list[dict[str, str]] = []
        if isinstance(response, litellm.ModelResponse):
            for choice in response.choices:
                if hasattr(choice, "message"):
                    if choice.message.content:
                        content += choice.message.content
                    if (
                        hasattr(choice.message, "tool_calls")
                        and choice.message.tool_calls
                    ):
                        for tc in choice.message.tool_calls:
                            tool_calls.append({
                                "name": tc.function.name if tc.function else "?",
                                "args": (tc.function.arguments or "")[:200]
                                if tc.function else "",
                            })

        if not content and not tool_calls:
            return

        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        model = getattr(response, "model", "?")
        usage = getattr(response, "usage", None)
        t0 = time.monotonic()

        response_messages = [{"role": "assistant", "content": content}]
        verdict = self._inspect("completion", content, response_messages, model=model)
        elapsed_ms = (time.monotonic() - t0) * 1000

        severity = verdict.get("severity", "NONE")
        action = verdict.get("action", "allow")
        reason = verdict.get("reason", "")

        self._log_post_call(
            ts, model, content, tool_calls, severity, action, reason,
            usage, elapsed_ms,
        )

        t_in = getattr(usage, "prompt_tokens", None) if usage else None
        t_out = getattr(usage, "completion_tokens", None) if usage else None
        self._report_to_sidecar(
            "completion", model, verdict, elapsed_ms,
            tokens_in=t_in, tokens_out=t_out,
        )

        if action == "block" and self.mode == "action":
            from fastapi import HTTPException
            raise HTTPException(
                status_code=400,
                detail={"error": {"message": self._block_message("completion", reason),
                                  "type": "content_filter", "code": "content_filter"}},
            )

    # ------------------------------------------------------------------
    # STREAMING POST-CALL: inspect streaming response chunks
    # ------------------------------------------------------------------

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        response: Any,
        request_data: dict[str, Any] | None = None,
    ):
        """Inspect streaming responses by buffering chunks and scanning periodically.

        Yields each chunk through unchanged but accumulates text for scanning.
        Once the stream finishes, runs a final inspection on the full response.
        """
        if request_data and request_data.get("_defenseclaw_prompt_blocked"):
            async for chunk in response:
                yield chunk
            return

        accumulated = ""
        model = "?"
        usage = None
        last_scan_len = 0
        scan_interval = 500

        async for chunk in response:
            content_delta = ""
            if hasattr(chunk, "choices"):
                for choice in chunk.choices:
                    delta = getattr(choice, "delta", None)
                    if delta and getattr(delta, "content", None):
                        content_delta = delta.content

            if hasattr(chunk, "model") and chunk.model:
                model = chunk.model
            if hasattr(chunk, "usage") and chunk.usage:
                usage = chunk.usage

            accumulated += content_delta

            if len(accumulated) - last_scan_len >= scan_interval:
                if self.scanner_mode in ("remote", "both"):
                    response_messages = [{"role": "assistant", "content": accumulated}]
                    mid_verdict = self._inspect(
                        "completion", accumulated, response_messages, model=model,
                    )
                else:
                    mid_verdict = self._scan_local("completion", accumulated)
                if mid_verdict.get("severity") not in ("NONE", None) and self.mode == "action":
                    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                    print(
                        f"\n{RED}[{ts}] STREAM-BLOCK{RESET} "
                        f"severity={mid_verdict['severity']} {mid_verdict.get('reason', '')}",
                        file=sys.stderr,
                    )
                    self._report_to_sidecar("completion", model, mid_verdict, 0)
                    return
                last_scan_len = len(accumulated)

            yield chunk

        if accumulated:
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            t0 = time.monotonic()
            response_messages = [{"role": "assistant", "content": accumulated}]
            verdict = self._inspect("completion", accumulated, response_messages, model=model)
            elapsed_ms = (time.monotonic() - t0) * 1000

            severity = verdict.get("severity", "NONE")
            action = verdict.get("action", "allow")
            reason = verdict.get("reason", "")

            sev_color = GREEN if severity == "NONE" else YELLOW if severity == "MEDIUM" else RED
            tokens_str = ""
            if usage:
                tokens_str = f"  in={getattr(usage, 'prompt_tokens', '?')} out={getattr(usage, 'completion_tokens', '?')}"
            print(
                f"\n{BOLD}{GREEN}{'─'*60}{RESET}\n"
                f"{GREEN}[{ts}]{RESET} {BOLD}STREAM-COMPLETE{RESET}  "
                f"model={model}{tokens_str}  chars={len(accumulated)}  "
                f"{DIM}{elapsed_ms:.0f}ms{RESET}",
                file=sys.stderr,
            )
            print(f"  verdict: {sev_color}{severity}{RESET}", file=sys.stderr)
            if severity != "NONE":
                print(f"  action={action}  {reason}", file=sys.stderr)
            print(f"{GREEN}{'─'*60}{RESET}", file=sys.stderr)

            t_in = getattr(usage, "prompt_tokens", None) if usage else None
            t_out = getattr(usage, "completion_tokens", None) if usage else None
            self._report_to_sidecar(
                "completion", model, verdict, elapsed_ms,
                tokens_in=t_in, tokens_out=t_out,
            )

    # ------------------------------------------------------------------
    # Sidecar telemetry reporter
    # ------------------------------------------------------------------

    def _report_to_sidecar(
        self,
        direction: str,
        model: str,
        verdict: dict[str, Any],
        elapsed_ms: float,
        *,
        tokens_in: int | None = None,
        tokens_out: int | None = None,
    ) -> None:
        """Fire-and-forget POST to the Go sidecar's guardrail event endpoint."""
        port = os.environ.get("DEFENSECLAW_API_PORT")
        if not port:
            return
        try:
            payload: dict[str, Any] = {
                "direction": direction,
                "model": model,
                "action": verdict.get("action", "allow"),
                "severity": verdict.get("severity", "NONE"),
                "reason": verdict.get("reason", ""),
                "findings": verdict.get("findings", []),
                "elapsed_ms": elapsed_ms,
                "cisco_elapsed_ms": verdict.get("cisco_elapsed_ms", 0),
            }
            if tokens_in is not None:
                payload["tokens_in"] = tokens_in
            if tokens_out is not None:
                payload["tokens_out"] = tokens_out
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{int(port)}/v1/guardrail/event",
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "X-DefenseClaw-Client": "litellm-guardrail",
                },
                method="POST",
            )
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _log_pre_call(
        self, ts: str, model: str, messages: list[dict[str, Any]],
        severity: str, action: str, reason: str, elapsed_ms: float,
    ) -> None:
        sev_color = GREEN if severity == "NONE" else YELLOW if severity == "MEDIUM" else RED
        print(f"\n{BOLD}{BLUE}{'─'*60}{RESET}", file=sys.stderr)
        print(
            f"{BLUE}[{ts}]{RESET} {BOLD}PRE-CALL{RESET}  "
            f"model={model}  messages={len(messages)}  "
            f"{DIM}{elapsed_ms:.0f}ms{RESET}",
            file=sys.stderr,
        )

        for i, msg in enumerate(messages):
            role = msg.get("role", "?")
            text = self._extract_content(msg)
            rc = YELLOW if role == "user" else GREEN if role == "assistant" else DIM
            print(f"  {DIM}[{i}]{RESET} {rc}{role}{RESET}: ({len(text)} chars)", file=sys.stderr)

        verdict_label = f"{sev_color}{severity}{RESET}"
        if severity == "NONE":
            print(f"  verdict: {verdict_label}", file=sys.stderr)
        else:
            print(f"  verdict: {verdict_label}  action={action}  {reason}", file=sys.stderr)
        print(f"{BLUE}{'─'*60}{RESET}", file=sys.stderr)

    def _log_post_call(
        self, ts: str, model: str, content: str,
        tool_calls: list[dict[str, str]], severity: str, action: str,
        reason: str, usage: Any, elapsed_ms: float,
    ) -> None:
        sev_color = GREEN if severity == "NONE" else YELLOW if severity == "MEDIUM" else RED
        print(f"\n{BOLD}{GREEN}{'─'*60}{RESET}", file=sys.stderr)
        tokens_str = ""
        if usage:
            tokens_str = f"  in={getattr(usage, 'prompt_tokens', '?')} out={getattr(usage, 'completion_tokens', '?')}"
        print(
            f"{GREEN}[{ts}]{RESET} {BOLD}POST-CALL{RESET}  "
            f"model={model}{tokens_str}  "
            f"{DIM}{elapsed_ms:.0f}ms{RESET}",
            file=sys.stderr,
        )

        if content:
            print(f"  content: ({len(content)} chars)", file=sys.stderr)

        if tool_calls:
            for tc in tool_calls:
                print(f"  tool: {YELLOW}{tc['name']}{RESET} (args: {len(tc.get('args', ''))} chars)", file=sys.stderr)

        verdict_label = f"{sev_color}{severity}{RESET}"
        if severity == "NONE":
            print(f"  verdict: {verdict_label}", file=sys.stderr)
        else:
            print(f"  verdict: {verdict_label}  action={action}  {reason}", file=sys.stderr)
        print(f"{GREEN}{'─'*60}{RESET}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Blocking helpers
    # ------------------------------------------------------------------

    def _block_message(self, direction: str, reason: str) -> str:
        if self.block_message:
            return self.block_message
        if direction == "prompt":
            return (
                "I'm unable to process this request. DefenseClaw detected a "
                f"potential security concern in the prompt ({reason}). "
                "If you believe this is a false positive, contact your "
                "administrator or adjust the guardrail policy."
            )
        return (
            "The model's response was blocked by DefenseClaw due to a "
            f"potential security concern ({reason}). "
            "If you believe this is a false positive, contact your "
            "administrator or adjust the guardrail policy."
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _last_user_text(messages: list[dict[str, Any]]) -> str:
        """Extract text from only the most recent user message.

        Scanning the full conversation history causes false positives:
        once a flagged message enters the history (even if already
        blocked), every subsequent turn would be blocked because the
        old patterns are still in the concatenated text.
        """
        for msg in reversed(messages):
            if msg.get("role") != "user":
                continue
            c = msg.get("content", "")
            if isinstance(c, str):
                return c
            if isinstance(c, list):
                return " ".join(
                    b.get("text", "") for b in c
                    if isinstance(b, dict) and b.get("type") == "text"
                )
        return ""

    @staticmethod
    def _extract_content(msg: dict[str, Any]) -> str:
        c = msg.get("content", "")
        if isinstance(c, str):
            return c
        if isinstance(c, list):
            return " ".join(
                b.get("text", "") for b in c
                if isinstance(b, dict) and b.get("type") == "text"
            )
        return str(c)
