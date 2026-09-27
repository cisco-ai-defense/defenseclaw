

# ---------------------------------------------------------------------------
# OpenShell sandbox transport. Rendered only into DefenseClaw's OpenShell
# overlay images, appended to the bridge above, which the image renders with
# the baked hook ingress, no token file and fail mode "closed". It replaces
# defenseclaw_policy (the registry resolves the handler by name at call time)
# with the sandbox contract every DefenseClaw sandbox hook follows:
#
#   - the only credential is the per-sandbox binding token, an OpenShell
#     provider placeholder read from DEFENSECLAW_SANDBOX_TOKEN at call time
#     (the supervisor substitutes the real value only on the ingress);
#   - every failure (no token, transport, status, body, action) is a DENY:
#     the workload can make the ingress, or the relay in front of it, answer
#     anything, so no failed or unparseable reply may become an ALLOW;
#   - a transport failure or relay 502/503/504 is retried exactly once with
#     the same random X-DefenseClaw-Hook-Idempotency-Key (the relay
#     occasionally drops a request; the ingress dedupes retries by key).
# ---------------------------------------------------------------------------

import secrets as _dc_sandbox_secrets

_SANDBOX_TOKEN_ENV = "DEFENSECLAW_SANDBOX_TOKEN"
# OmniGent's local host daemon, which starts the server this policy runs in,
# keeps only provider and OMNIGENT_* variables; the DefenseClaw launcher
# copies the binding token placeholder under this name so it survives.
_SANDBOX_TOKEN_ENV_OMNIGENT = "OMNIGENT_DEFENSECLAW_SANDBOX_TOKEN"
_SANDBOX_ATTEMPT_TIMEOUTS = (9, 12)
_SANDBOX_RETRY_STATUSES = frozenset({502, 503, 504})


def _sandbox_deny(reason: str) -> dict[str, str]:
    return {"result": "DENY", "reason": f"DefenseClaw policy failed closed: {reason}"}


def _sandbox_token() -> str:
    token = os.environ.get(_SANDBOX_TOKEN_ENV, "") or os.environ.get(_SANDBOX_TOKEN_ENV_OMNIGENT, "")
    if not token or len(token) > 4096 or any(ch in token for ch in "\r\n\x00"):
        raise ValueError("sandbox binding token unavailable")
    return token


def _sandbox_post(body: bytes, headers: dict[str, str]) -> Any:
    """POST body to the ingress; return the parsed reply or raise."""
    headers = dict(headers)
    headers["X-DefenseClaw-Hook-Idempotency-Key"] = _dc_sandbox_secrets.token_hex(16)
    for attempt, timeout in enumerate(_SANDBOX_ATTEMPT_TIMEOUTS):
        last = attempt == len(_SANDBOX_ATTEMPT_TIMEOUTS) - 1
        request = urllib.request.Request(_ENDPOINT, data=body, headers=headers, method="POST")
        try:
            with _DIRECT_OPENER.open(request, timeout=timeout) as response:
                if response.status < 200 or response.status >= 300:
                    raise ValueError(f"HTTP {response.status}")
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(raw) > _MAX_RESPONSE_BYTES:
                    raise ValueError("gateway response exceeded 1 MiB")
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in _SANDBOX_RETRY_STATUSES and not last:
                continue
            raise ValueError(f"HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError):
            if not last:
                continue
            raise
    raise ValueError("sandbox ingress unreachable")


def defenseclaw_policy(event: dict[str, Any]) -> dict[str, str]:  # noqa: F811
    """Evaluate one OmniGent policy event through the sandbox ingress."""
    try:
        token = _sandbox_token()
    except ValueError:
        return {"result": "DENY", "reason": "DefenseClaw sandbox binding token is unavailable."}
    try:
        if not _API_ADDR:
            return _sandbox_deny("bridge is not configured")
        payload = _payload(event)
        if payload.get("omnigent_content_truncated"):
            return _sandbox_deny("request content exceeds bridge limit")
        body = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
        headers = _trace_headers()
        headers.update(_identity_headers())
        headers.update({
            "Content-Type": "application/json",
            "X-DefenseClaw-Client": "omnigent-policy/1.0",
            "Authorization": f"Bearer {token}",
        })
        result = _sandbox_post(body, headers)
    except Exception as exc:
        return _sandbox_deny(f"bridge error ({type(exc).__name__}: {exc})" if isinstance(exc, ValueError) else f"bridge error ({type(exc).__name__})")

    try:
        if not isinstance(result, dict):
            return _sandbox_deny("gateway response was not an object")
        action = str(result.get("action") or "").lower()
        reason = str(result.get("reason") or "")
        if action == "allow" or action == "alert":
            return {"result": "ALLOW"}
        if action == "block":
            return {"result": "DENY", "reason": reason or "DefenseClaw blocked this action."}
        if action == "confirm":
            return {"result": "ASK", "reason": reason or "DefenseClaw requires approval."}
        return _sandbox_deny("gateway response had no valid action")
    except Exception as exc:
        return _sandbox_deny(f"bridge error ({type(exc).__name__})")
