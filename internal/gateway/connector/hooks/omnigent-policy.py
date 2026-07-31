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
_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_PROMPT_CHARS = 64 * 1024
_MAX_ATTACHMENTS = 16
_MAX_ATTACHMENT_TEXT_CHARS = 32 * 1024
_MAX_ATTACHMENT_TOTAL_TEXT_CHARS = 128 * 1024
_MAX_ATTACHMENT_METADATA_CHARS = 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep policy credentials and content on the configured gateway origin."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


# The policy endpoint is an explicitly configured local gateway. Never inherit
# HTTP(S)_PROXY or the Windows proxy registry, and never forward the scoped
# credential or inspected content through a redirect.
_DIRECT_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _NoRedirect(),
)

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
        json.dumps(value, allow_nan=False)
        return value
    except (TypeError, ValueError, RecursionError):
        return str(value)


def _request_user_text(data: Any) -> tuple[str, bool]:
    """Mirror OmniGent v0.7.0 request_user_text with an outbound size bound."""
    text = ""
    if isinstance(data, dict):
        candidate = data.get("user_content")
        text = candidate if isinstance(candidate, str) else ""
    elif isinstance(data, str):
        text = data
    elif isinstance(data, list):
        parts = [
            block.get("text", "")
            for block in data
            if isinstance(block, dict) and isinstance(block.get("text"), str)
        ]
        text = "\n".join(part for part in parts if part)
    return text[:_MAX_PROMPT_CHARS], len(text) > _MAX_PROMPT_CHARS


def _request_attachments(data: Any) -> tuple[list[dict[str, Any]], bool]:
    """Normalize the official attachment shape without unbounded forwarding."""
    if not isinstance(data, dict) or not isinstance(data.get("attachments"), list):
        return [], False
    truncated = len(data["attachments"]) > _MAX_ATTACHMENTS
    remaining_text = _MAX_ATTACHMENT_TOTAL_TEXT_CHARS
    normalized: list[dict[str, Any]] = []
    for attachment in data["attachments"][:_MAX_ATTACHMENTS]:
        if not isinstance(attachment, dict):
            continue
        filename = attachment.get("filename")
        content_type = attachment.get("content_type")
        text = attachment.get("text")
        text_value = text if isinstance(text, str) else ""
        text_limit = min(_MAX_ATTACHMENT_TEXT_CHARS, remaining_text)
        bounded_text = text_value[:text_limit]
        remaining_text -= len(bounded_text)
        filename_value = filename if isinstance(filename, str) else ""
        content_type_value = content_type if isinstance(content_type, str) else ""
        attachment_truncated = (
            len(text_value) > len(bounded_text)
            or len(filename_value) > _MAX_ATTACHMENT_METADATA_CHARS
            or len(content_type_value) > _MAX_ATTACHMENT_METADATA_CHARS
        )
        truncated = truncated or attachment_truncated
        normalized.append(
            {
                "filename": filename_value[:_MAX_ATTACHMENT_METADATA_CHARS],
                "content_type": content_type_value[:_MAX_ATTACHMENT_METADATA_CHARS],
                "text": bounded_text,
                "truncated": attachment_truncated,
            }
        )
    return normalized, truncated


def _request_inspection_text(
    user_content: str,
    attachments: list[dict[str, Any]],
) -> str:
    parts = [user_content] if user_content else []
    for attachment in attachments:
        metadata = json.dumps(
            {
                "filename": attachment["filename"],
                "content_type": attachment["content_type"],
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
        parts.append(f"[OmniGent attachment {metadata}]\n{attachment['text']}")
    return "\n\n".join(parts)


def _payload(event: dict[str, Any]) -> dict[str, Any]:
    event_type = str(event.get("type") or "")
    data = event.get("data")
    context = event.get("context")
    if not isinstance(context, dict):
        context = {}

    tool_name = str(event.get("target") or "")
    tool_input: Any = {}
    prompt = ""
    attachments: list[dict[str, Any]] = []
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
            user_content, prompt_truncated = _request_user_text(data)
            attachments, attachments_truncated = _request_attachments(data)
            prompt = _request_inspection_text(user_content, attachments)
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
        # OmniGent documents this as the calling actor/client identity, not as
        # an agent identity. Keep the exact meaning for audit without letting
        # the generic correlation decoder reinterpret it as ``agent_id``.
        "omnigent_actor_client_id": str(actor.get("client_id") or ""),
        "model": str(context.get("model") or ""),
        "tool_name": tool_name,
        "tool_input": _safe(tool_input),
    }
    if prompt:
        payload["prompt"] = prompt
    if attachments:
        payload["omnigent_attachments"] = attachments
    if event_type == "request" and (prompt_truncated or attachments_truncated):
        payload["omnigent_content_truncated"] = True
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
    except ImportError:
        return {}


def defenseclaw_policy(event: dict[str, Any]) -> dict[str, str]:
    """Evaluate one OmniGent policy event through DefenseClaw."""
    try:
        if not _API_ADDR:
            return _failure("bridge is not configured")
        payload = _payload(event)
        if payload.get("omnigent_content_truncated"):
            return _failure("request content exceeds bridge limit")
        body = json.dumps(
            payload,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        headers = _trace_headers()
        headers.update({
            "Content-Type": "application/json",
            "X-DefenseClaw-Client": "omnigent-policy/1.0",
        })
        if _API_TOKEN:
            headers["Authorization"] = f"Bearer {_API_TOKEN}"
        request = urllib.request.Request(_ENDPOINT, data=body, headers=headers, method="POST")
        with _DIRECT_OPENER.open(request, timeout=_TIMEOUT_SECONDS) as response:
            if response.status < 200 or response.status >= 300:
                return _failure(f"HTTP {response.status}")
            response_body = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(response_body) > _MAX_RESPONSE_BYTES:
                return _failure("gateway response exceeded 1 MiB")
            result = json.loads(response_body.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return _failure(f"HTTP {exc.code}")
    except Exception as exc:
        # Preserve KeyboardInterrupt/SystemExit while routing every ordinary
        # normalization, propagation, serialization, transport, read, and
        # response-parse failure through the configured bridge fail mode.
        return _failure(f"bridge error ({type(exc).__name__})")

    try:
        if not isinstance(result, dict):
            return _failure("gateway response was not an object")
        action = str(result.get("action") or "").lower()
        if action not in {"allow", "alert", "block", "confirm"}:
            return _failure("gateway response had no valid action")
        reason = str(result.get("reason") or "")
        if action == "alert":
            # DefenseClaw already recorded the finding and uses ``alert`` when a
            # post-action confirm cannot pause safely. Continuing is intentional;
            # treating this authenticated fallback as invalid would turn it into a
            # DENY under fail-closed and contradict the post-phase contract.
            return {"result": "ALLOW"}
        if action == "block":
            return {"result": "DENY", "reason": reason or "DefenseClaw blocked this action."}
        if action == "confirm":
            return {"result": "ASK", "reason": reason or "DefenseClaw requires approval."}
        return {"result": "ALLOW"}
    except Exception as exc:
        return _failure(f"bridge error ({type(exc).__name__})")


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
