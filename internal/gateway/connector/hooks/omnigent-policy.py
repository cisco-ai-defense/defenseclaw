# defenseclaw-managed-policy v1
"""OmniGent custom policy bridge installed by DefenseClaw.

The enforcement path uses only the Python standard library so it works inside
OmniGent's isolated uv/pip environment without adding dependencies. When
OmniGent's OpenTelemetry packages are available, the bridge also forwards the
active W3C trace context. Encoded configuration constants are rendered by the
DefenseClaw connector.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from typing import Any


def _decoded(value: str) -> str:
    # Keep the checked-in template importable for validation tooling. A raw
    # template token is deliberately treated as unset; rendered installs always
    # contain valid base64.
    if value.startswith("{{") and value.endswith("}}"):
        return ""
    try:
        return base64.b64decode(value.encode("ascii"), validate=True).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return ""


_API_ADDR = _decoded("{{API_ADDR_B64}}")
_API_TOKEN = _decoded("{{API_TOKEN_B64}}")
_FAIL_MODE = _decoded("{{FAIL_MODE_B64}}")
_ENDPOINT = f"http://{_API_ADDR}/api/v1/omnigent/hook"
_TIMEOUT_SECONDS = 10

_EVENT_NAMES = {
    "request": "UserPromptSubmit",
    "tool_call": "PreToolUse",
    "tool_result": "PostToolUse",
    "response": "AfterAgentResponse",
    "llm_request": "BeforeModel",
    "llm_response": "AfterModel",
}


def _safe(value: Any) -> Any:
    """Return a JSON-compatible copy without leaking Python objects."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError, RecursionError):
        return str(value)


def _payload(event: dict[str, Any]) -> dict[str, Any]:
    event_type = str(event.get("type") or "")
    data = event.get("data")
    context = event.get("context")
    if not isinstance(context, dict):
        context = {}

    tool_name = str(event.get("target") or "")
    tool_input: Any = {}
    prompt = ""
    tool_response: Any = None

    if event_type == "tool_call" and isinstance(data, dict):
        tool_name = str(data.get("name") or tool_name)
        tool_input = data.get("arguments", {})
    elif event_type == "tool_result":
        tool_response = data.get("result") if isinstance(data, dict) else data
        request_data = event.get("request_data")
        if isinstance(request_data, dict):
            tool_name = str(request_data.get("name") or tool_name)
            tool_input = request_data.get("arguments", {})
    elif event_type in {"request", "response"}:
        if event_type == "request":
            prompt = str(data or "")
        else:
            tool_response = data
    elif isinstance(data, dict):
        if event_type == "llm_request":
            prompt = str(data.get("last_user_message") or data.get("system_prompt_preview") or "")
        elif event_type == "llm_response":
            tool_response = data.get("text_preview", data)

    actor = context.get("actor")
    if not isinstance(actor, dict):
        actor = {}

    payload: dict[str, Any] = {
        "hook_event_name": _EVENT_NAMES.get(event_type, event_type or "PolicyEvaluation"),
        "omnigent_event_type": event_type,
        "agent_name": "OmniGent",
        "agent_type": "omnigent",
        "agent_id": str(actor.get("client_id") or actor.get("run_as") or ""),
        "model": str(context.get("model") or ""),
        "tool_name": tool_name,
        "tool_input": _safe(tool_input),
    }
    if prompt:
        payload["prompt"] = prompt
    if tool_response is not None:
        payload["tool_response"] = _safe(tool_response)
    return payload


def _failure(reason: str) -> dict[str, str]:
    if _FAIL_MODE == "closed":
        return {"result": "DENY", "reason": f"DefenseClaw policy failed closed: {reason}"}
    return {"result": "ALLOW"}


def _trace_headers() -> dict[str, str]:
    """Best-effort propagation from OmniGent's active OpenTelemetry span."""
    try:
        from opentelemetry.propagate import inject

        carrier: dict[str, str] = {}
        inject(carrier)
        return {str(key): str(value) for key, value in carrier.items()}
    except (ImportError, RuntimeError, TypeError, ValueError):
        return {}


def defenseclaw_policy(event: dict[str, Any]) -> dict[str, str]:
    """Evaluate one OmniGent policy event through DefenseClaw."""
    body = json.dumps(_payload(event), separators=(",", ":")).encode("utf-8")
    headers = _trace_headers()
    headers.update({
        "Content-Type": "application/json",
        "X-DefenseClaw-Client": "omnigent-policy/1.0",
    })
    if _API_TOKEN:
        headers["Authorization"] = f"Bearer {_API_TOKEN}"
    try:
        if not _API_ADDR:
            return _failure("bridge is not configured")
        request = urllib.request.Request(_ENDPOINT, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            if response.status < 200 or response.status >= 300:
                return _failure(f"HTTP {response.status}")
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return _failure(f"HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return _failure(str(exc))

    action = str(result.get("action") or "allow").lower() if isinstance(result, dict) else "allow"
    reason = str(result.get("reason") or "") if isinstance(result, dict) else ""
    if action == "block":
        return {"result": "DENY", "reason": reason or "DefenseClaw blocked this action."}
    if action == "confirm":
        return {"result": "ASK", "reason": reason or "DefenseClaw requires approval."}
    return {"result": "ALLOW"}


# OmniGent's module registry allowlists this callable. The server-wide
# ``policies.defenseclaw_guardrail`` config entry attaches it once; declaring
# it here does not itself execute or attach the policy.
POLICY_REGISTRY = [
    {
        "handler": "defenseclaw_omnigent_policy.defenseclaw_policy",
        "kind": "callable",
        "name": "DefenseClaw Guardrail",
        "description": "Evaluate OmniGent requests and tool activity through DefenseClaw.",
    }
]
