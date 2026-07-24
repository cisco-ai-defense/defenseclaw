# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Secret-isolated client for the gateway-owned runtime trace canary.

This path never asks Python configuration for the gateway bearer. The installed
Go helper resolves it from canonical v8 configuration and the owner-only dotenv,
authenticates to the loopback API, and never returns it in argv, stdout, stderr,
or this module's small closed result envelope. The surrounding Python process
may already have loaded installation dotenv values for other CLI operations.
"""

from __future__ import annotations

import json
import math
import re
import subprocess
from dataclasses import dataclass

from defenseclaw.gateway import resolve_gateway_binary

_STABLE_DESTINATION = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_MAX_RESULT_BYTES = 1024
_FAILURE_MESSAGES = {
    "invalid_request": "the runtime canary request is invalid",
    "configuration_unavailable": "the canonical v8 gateway configuration is unavailable",
    "authentication_unavailable": "gateway authentication is unavailable; run defenseclaw setup gateway",
    "gateway_unavailable": "the running gateway API is unavailable",
    "gateway_rejected": "the running gateway did not acknowledge the destination canary",
    "invalid_response": "the gateway returned an invalid canary acknowledgement",
}


class TraceCanaryError(RuntimeError):
    """One bounded, display-safe runtime-canary failure."""

    def __init__(self, failure_class: str) -> None:
        if failure_class not in _FAILURE_MESSAGES:
            failure_class = "invalid_response"
        self.failure_class = failure_class
        self.message = _FAILURE_MESSAGES[failure_class]
        super().__init__(self.message)


@dataclass(frozen=True)
class TraceCanaryResult:
    destination: str
    trace_id: str
    generation: int
    acknowledged: bool


def run_trace_canary(
    *,
    destination: str,
    config_path: str,
    data_dir: str,
    timeout: float,
) -> TraceCanaryResult:
    """Emit and exactly acknowledge one real canary through ``destination``."""

    if (
        not _STABLE_DESTINATION.fullmatch(destination)
        or not isinstance(config_path, str)
        or not config_path
        or not isinstance(data_dir, str)
        or not data_dir
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or timeout < 0.1
        or timeout > 60
    ):
        raise TraceCanaryError("invalid_request")
    binary = resolve_gateway_binary()
    if not binary:
        raise TraceCanaryError("gateway_unavailable")
    argv = [
        binary,
        "observability-v8",
        "--config",
        config_path,
        "--data-dir",
        data_dir,
        "emit-trace-canary",
        destination,
        "--timeout",
        f"{float(timeout):g}s",
    ]
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=float(timeout) + 2.0,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TraceCanaryError("gateway_unavailable") from exc
    except OSError as exc:
        raise TraceCanaryError("gateway_unavailable") from exc

    payload = _decode_helper_result(completed.stdout, destination)
    failure_class = payload.get("failure_class")
    if failure_class:
        raise TraceCanaryError(failure_class)
    if completed.returncode != 0:
        raise TraceCanaryError("invalid_response")
    trace_id = payload.get("trace_id")
    generation = payload.get("generation")
    acknowledged = payload.get("acknowledged")
    if (
        set(payload) != {"destination", "trace_id", "generation", "acknowledged"}
        or not isinstance(trace_id, str)
        or not _TRACE_ID.fullmatch(trace_id)
        or trace_id == "0" * 32
        or type(generation) is not int
        or generation < 1
        or acknowledged is not True
    ):
        raise TraceCanaryError("invalid_response")
    return TraceCanaryResult(
        destination=destination,
        trace_id=trace_id,
        generation=generation,
        acknowledged=True,
    )


def _decode_helper_result(raw: str, destination: str) -> dict:
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8", errors="replace")) > _MAX_RESULT_BYTES:
        raise TraceCanaryError("invalid_response")
    try:
        payload = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise TraceCanaryError("invalid_response") from exc
    if not isinstance(payload, dict) or payload.get("destination") != destination:
        raise TraceCanaryError("invalid_response")
    failure_class = payload.get("failure_class")
    if failure_class is not None:
        if (
            set(payload) != {"destination", "acknowledged", "failure_class"}
            or payload.get("acknowledged") is not False
            or not isinstance(failure_class, str)
            or failure_class not in _FAILURE_MESSAGES
        ):
            raise TraceCanaryError("invalid_response")
    return payload
