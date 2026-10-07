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
import http.client
import json
import math
import os
import re
import socket
import stat
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any

try:
    import pwd
except ImportError:  # pragma: no cover - absent on Windows
    pwd = None  # type: ignore[assignment]

_SAFE_ACCOUNT_NAME = re.compile(r"[A-Za-z0-9._-]+")


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
_TOKEN_FILE = _decoded("{{TOKEN_FILE_B64}}")
_FAIL_MODE = _decoded("{{FAIL_MODE_B64}}")
# A standalone enterprise install names the gateway's peer-authorized unix
# hook socket and the gateway service uid trusted beside root as its owner.
# Empty keeps the loopback TCP transport with the scoped credential.
_HOOK_SOCKET = _decoded("{{HOOK_SOCKET_B64}}")
try:
    _SERVICE_UID = int(_decoded("{{SERVICE_UID_B64}}") or "0")
except ValueError:
    _SERVICE_UID = 0
# The administrator-owned hook binary of a standalone managed install, which
# reads the user's Kerberos credential cache (see _full_session_facts). Empty
# for a per-user install, which uses its own gateway binary.
_SESSION_FACTS_BIN = _decoded("{{SESSION_FACTS_BIN_B64}}")
_HOOK_PATH = "/api/v1/omnigent/hook"
_ENDPOINT = f"http://{_API_ADDR}{_HOOK_PATH}"
_TIMEOUT_SECONDS = 10
_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_PROMPT_CHARS = 64 * 1024
_MAX_ATTACHMENTS = 16
_MAX_ATTACHMENT_TEXT_CHARS = 32 * 1024
_MAX_ATTACHMENT_TOTAL_TEXT_CHARS = 128 * 1024
_MAX_ATTACHMENT_METADATA_CHARS = 1024
_MAX_LLM_PREVIEW_CHARS = 30 * 1024
_MAX_CONTEXT_TEXT_CHARS = 1024
_MAX_LABELS = 32
_MAX_LABEL_KEY_CHARS = 128
_MAX_LABEL_VALUE_CHARS = 1024
_MAX_USAGE_VALUE = 10**15


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


def _trusted_socket_owner(uid: int) -> bool:
    return uid == 0 or (_SERVICE_UID > 0 and uid == _SERVICE_UID)


def _hook_socket_trusted() -> bool:
    """Accept the hook socket only where no standard user can have made it.

    The socket must be a socket (not a link), and it and its resolved
    directory must belong to root or the gateway account, with the directory
    writable by no one else. Another local user can then never be listening
    on this path, whoever holds the loopback TCP port.
    """
    try:
        directory = os.lstat(os.path.realpath(os.path.dirname(_HOOK_SOCKET)))
        entry = os.lstat(_HOOK_SOCKET)
    except (OSError, ValueError):
        return False
    return (
        stat.S_ISDIR(directory.st_mode)
        and not directory.st_mode & 0o022
        and _trusted_socket_owner(directory.st_uid)
        and stat.S_ISSOCK(entry.st_mode)
        and _trusted_socket_owner(entry.st_uid)
    )


class _HookSocketConnection(http.client.HTTPConnection):
    """HTTP to the gateway over its unix hook socket."""

    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = path

    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(self.timeout)
            connection.connect(self._socket_path)
        except BaseException:
            connection.close()
            raise
        self.sock = connection


def _post_hook_socket(body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
    connection = _HookSocketConnection(_HOOK_SOCKET, _TIMEOUT_SECONDS)
    try:
        connection.request("POST", _HOOK_PATH, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read(_MAX_RESPONSE_BYTES + 1)
    finally:
        connection.close()

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


def _llm_request_inspection_text(data: Any) -> tuple[str, bool]:
    """Keep both official v0.7 LLM-request previews visible and bounded."""
    if not isinstance(data, dict):
        return "", False
    parts: list[str] = []
    truncated = False
    for field in ("system_prompt_preview", "last_user_message"):
        value = data.get(field)
        if not isinstance(value, str) or not value:
            continue
        bounded = value[:_MAX_LLM_PREVIEW_CHARS]
        truncated = truncated or len(value) > len(bounded)
        parts.append(f"[OmniGent {field}]\n{bounded}")
    return "\n\n".join(parts), truncated


def _bounded_text(value: Any) -> tuple[str, bool]:
    if value is None:
        return "", False
    text = value if isinstance(value, str) else str(value)
    return text[:_MAX_CONTEXT_TEXT_CHARS], len(text) > _MAX_CONTEXT_TEXT_CHARS


def _bounded_usage(value: Any) -> tuple[dict[str, int | float], bool]:
    """Project only the documented cumulative v0.7 usage counters."""
    if value is None:
        return {}, False
    if not isinstance(value, dict):
        return {}, True
    result: dict[str, int | float] = {}
    partial = False
    for key in ("input_tokens", "output_tokens", "total_tokens", "total_cost_usd"):
        candidate = value.get(key)
        if candidate is None:
            continue
        if (
            isinstance(candidate, bool)
            or not isinstance(candidate, (int, float))
            or not math.isfinite(float(candidate))
            or float(candidate) < 0
            or float(candidate) > _MAX_USAGE_VALUE
        ):
            partial = True
            continue
        result[key] = candidate
    return result, partial


def _bounded_labels(value: Any) -> tuple[dict[str, str], bool]:
    """Bound OmniGent labels before forwarding operator-controlled metadata."""
    if value is None:
        return {}, False
    if not isinstance(value, dict):
        return {}, True
    result: dict[str, str] = {}
    partial = len(value) > _MAX_LABELS
    for index, (key, item) in enumerate(value.items()):
        if index >= _MAX_LABELS:
            break
        if not isinstance(key, str) or not isinstance(item, str):
            partial = True
            continue
        bounded_key = key[:_MAX_LABEL_KEY_CHARS]
        bounded_value = item[:_MAX_LABEL_VALUE_CHARS]
        if not bounded_key or bounded_key in result:
            partial = True
            continue
        partial = partial or bounded_key != key or bounded_value != item
        result[bounded_key] = bounded_value
    return result, partial


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
    content_truncated = False

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
            content_truncated = prompt_truncated or attachments_truncated
        else:
            tool_response = data
    elif isinstance(data, dict):
        if event_type == "llm_request":
            prompt, content_truncated = _llm_request_inspection_text(data)
        elif event_type == "llm_response":
            tool_response = data.get("text_preview", data)

    actor = context.get("actor")
    if not isinstance(actor, dict):
        actor = {}
    actor_client_id, actor_partial = _bounded_text(actor.get("client_id"))
    model, model_partial = _bounded_text(context.get("model"))
    harness, harness_partial = _bounded_text(context.get("harness"))
    usage, usage_partial = _bounded_usage(context.get("usage"))
    labels, labels_partial = _bounded_labels(context.get("labels"))

    payload: dict[str, Any] = {
        "hook_event_name": _EVENT_NAMES.get(event_type, event_type or "PolicyEvaluation"),
        "omnigent_event_type": event_type,
        "agent_name": "OmniGent",
        "agent_type": "omnigent",
        # OmniGent documents this as the calling actor/client identity, not as
        # an agent identity. Keep the exact meaning for audit without letting
        # the generic correlation decoder reinterpret it as ``agent_id``.
        "omnigent_actor_client_id": actor_client_id,
        "model": model,
        "omnigent_session_id_status": "unavailable_in_v0.7_policy_event",
        "tool_name": tool_name,
        "tool_input": _safe(tool_input),
    }
    if harness:
        payload["omnigent_harness"] = harness
    if usage:
        payload["usage"] = usage
    if labels:
        payload["omnigent_labels"] = labels
    if labels_partial:
        payload["omnigent_label_projection_partial"] = True
    if actor_partial or model_partial or harness_partial or usage_partial:
        payload["omnigent_metadata_projection_partial"] = True
    if prompt:
        payload["prompt"] = prompt
    if attachments:
        payload["omnigent_attachments"] = attachments
    if content_truncated:
        payload["omnigent_content_truncated"] = True
    if tool_response is not None:
        payload["tool_response"] = _safe(tool_response)
    return payload


def _failure(reason: str) -> dict[str, str]:
    if _FAIL_MODE == "closed":
        return {"result": "DENY", "reason": f"DefenseClaw policy failed closed: {reason}"}
    return {"result": "ALLOW"}


def _credential_failure() -> dict[str, str]:
    return {"result": "DENY", "reason": "DefenseClaw policy credential is unavailable."}


def _hook_socket_failure() -> dict[str, str]:
    return {"result": "DENY", "reason": "DefenseClaw hook socket is not owned by root or the gateway account."}


def _trace_headers() -> dict[str, str]:
    """Best-effort propagation from OmniGent's active OpenTelemetry span."""
    try:
        from opentelemetry.propagate import inject

        carrier: dict[str, str] = {}
        inject(carrier)
        return {str(key): str(value) for key, value in carrier.items()}
    except ImportError:
        return {}


def _identity_headers() -> dict[str, str]:
    """Report which end user this policy module runs as.

    Under a managed install the gateway runs as a service account, so it cannot
    see whose session a request belongs to; this module is in-session and can.
    A value that is not a safe header field is dropped rather than sanitized,
    so a hostile account name cannot smuggle a second header into every call.
    """
    headers: dict[str, str] = {}
    facts = _session_facts_header()
    if facts:
        headers["X-DefenseClaw-Session-Facts"] = facts
    try:
        # os.getuid is absent on Windows, where no POSIX uid exists.
        uid = os.getuid()  # type: ignore[attr-defined]
    except AttributeError:
        uid = -1
    if uid >= 0:
        headers["X-DefenseClaw-User-Id"] = str(uid)
    try:
        name = pwd.getpwuid(uid).pw_name if pwd is not None and uid >= 0 else ""
    except (KeyError, OSError):
        # No identity is a supported outcome: the record is emitted
        # unattributed rather than wrongly attributed.
        return headers
    # Mirrors the account-name allowlist the POSIX hooks apply in their
    # shared hardening helper.
    if name and len(name) <= 256 and _SAFE_ACCOUNT_NAME.fullmatch(name):
        headers["X-DefenseClaw-User-Name"] = name
    return headers


_SAFE_SESSION_FACT = re.compile(r"[A-Za-z0-9._@/:-]{1,256}")


_FULL_SESSION_FACTS = re.compile(r"v1;[A-Za-z0-9._@/:;=-]{1,1020}")
_session_facts_cache: dict[str, Any] = {"key": None, "value": "", "until": 0.0}


def _full_session_facts() -> str:
    """Ask a DefenseClaw binary for this login's whole session facts.

    The Kerberos principal sits in a credential cache this module cannot read
    (a KCM cache is a socket protocol), so `hook session-facts` reads it and
    prints the whole X-DefenseClaw-Session-Facts value, the principal included.
    The binary keeps its own five-minute cache in ~/.defenseclaw and this
    module keeps the answer for the same time. No answer is a supported
    outcome: the SSH and logind variables alone follow.
    """
    env = os.environ
    key = "|".join(env.get(name, "") for name in ("KRB5CCNAME", "XDG_SESSION_ID", "SSH_CONNECTION", "SSH_TTY"))
    now = time.monotonic()
    if _session_facts_cache["key"] == key and now < _session_facts_cache["until"]:
        return str(_session_facts_cache["value"])
    value = ""
    binary = _SESSION_FACTS_BIN or os.path.join(
        os.path.expanduser("~"), ".local", "bin", "defenseclaw-gateway.exe" if os.name == "nt" else "defenseclaw-gateway"
    )
    try:
        completed = subprocess.run(
            [binary, "hook", "session-facts"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=3, check=False,
        )
        answer = completed.stdout.strip()
        if completed.returncode == 0 and _FULL_SESSION_FACTS.fullmatch(answer):
            value = answer
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    _session_facts_cache.update(key=key, value=value, until=now + (300.0 if value else 30.0))
    return value


def _session_facts_header() -> str:
    """Render the claimed SSH and logind session facts.

    The value is the X-DefenseClaw-Session-Facts header the hook runner also
    sends. Each value is dropped unless it matches the header's allowlisted
    charset; everything here is claimed attribution, never authority.
    """
    full = _full_session_facts()
    if full:
        return full
    connection = os.environ.get("SSH_CONNECTION", "").split()
    address = connection[0] if connection else ""
    tty = os.environ.get("SSH_TTY", "")
    if tty.startswith("/dev/"):
        tty = tty[len("/dev/"):]
    session = os.environ.get("XDG_SESSION_ID", "")
    kind = "ssh" if address or tty else ("local" if session else "")
    parts = ["v1"]
    for key, value in (("k", kind), ("tty", tty), ("ls", session), ("ca", address)):
        if value and _SAFE_SESSION_FACT.fullmatch(value):
            parts.append(f"{key}={value}")
    return ";".join(parts) if len(parts) > 1 else ""


def _scoped_hook_token() -> str:
    """Load one strict credential without exposing path, bytes, or read errors."""
    with open(_TOKEN_FILE, "rb") as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise ValueError("oversized scoped hook credential")
    token = raw.decode("ascii").strip()
    if len(token) != 64 or any(character not in "0123456789abcdef" for character in token):
        raise ValueError("malformed scoped hook credential")
    return token


def defenseclaw_policy(event: dict[str, Any]) -> dict[str, str]:
    """Evaluate one OmniGent policy event through DefenseClaw."""
    token = ""
    if _HOOK_SOCKET:
        # The gateway identifies a hook-socket caller by its kernel-verified
        # uid, so no credential is read or sent. An unverified socket is as
        # unsafe as a missing credential, whatever the transport fail mode.
        if not _hook_socket_trusted():
            return _hook_socket_failure()
    elif not _TOKEN_FILE:
        return _credential_failure()
    else:
        try:
            token = _scoped_hook_token()
        except (OSError, UnicodeDecodeError, ValueError):
            # Credential failures are categorically unsafe at a policy boundary,
            # regardless of the operator's transport fail mode.
            return _credential_failure()
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
        headers.update(_identity_headers())
        headers.update({
            "Content-Type": "application/json",
            "X-DefenseClaw-Client": "omnigent-policy/1.0",
        })
        if _HOOK_SOCKET:
            status, response_body = _post_hook_socket(body, headers)
            if status < 200 or status >= 300:
                return _failure(f"HTTP {status}")
            if len(response_body) > _MAX_RESPONSE_BYTES:
                return _failure("gateway response exceeded 1 MiB")
            result = json.loads(response_body.decode("utf-8"))
        else:
            headers["Authorization"] = f"Bearer {token}"
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
