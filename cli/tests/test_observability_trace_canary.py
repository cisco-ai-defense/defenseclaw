# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest
from defenseclaw.observability.trace_canary import (
    TraceCanaryError,
    run_trace_canary,
)


def _run(*, stdout: str, returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess(
        args=[],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def test_trace_canary_uses_go_helper_and_accepts_only_bounded_acknowledgement() -> None:
    trace_id = "0123456789abcdef0123456789abcdef"
    completed = _run(
        stdout=json.dumps(
            {
                "destination": "galileo",
                "trace_id": trace_id,
                "generation": 9,
                "acknowledged": True,
            }
        ),
        stderr="gateway-token-must-never-render",
    )
    with (
        patch(
            "defenseclaw.observability.trace_canary.resolve_gateway_binary",
            return_value="/opt/defenseclaw-gateway",
        ),
        patch(
            "defenseclaw.observability.trace_canary.subprocess.run",
            return_value=completed,
        ) as run,
    ):
        result = run_trace_canary(
            destination="galileo",
            config_path="/data/config.yaml",
            data_dir="/data",
            timeout=7.0,
        )

    assert result.trace_id == trace_id
    assert result.generation == 9
    assert result.acknowledged is True
    argv = run.call_args.args[0]
    assert argv == [
        "/opt/defenseclaw-gateway",
        "observability-v8",
        "--config",
        "/data/config.yaml",
        "--data-dir",
        "/data",
        "emit-trace-canary",
        "galileo",
        "--timeout",
        "7s",
    ]
    assert "token" not in " ".join(argv).lower()
    assert "shell" not in run.call_args.kwargs
    assert run.call_args.kwargs["stdout"] is subprocess.PIPE
    assert run.call_args.kwargs["stderr"] is subprocess.DEVNULL
    assert run.call_args.kwargs["timeout"] == 9.0


def test_trace_canary_failure_uses_closed_class_and_never_helper_stderr() -> None:
    secret = "remote-response-and-gateway-token-secret"
    completed = _run(
        returncode=1,
        stdout='{"destination":"galileo","acknowledged":false,"failure_class":"gateway_rejected"}\n',
        stderr=secret,
    )
    with (
        patch(
            "defenseclaw.observability.trace_canary.resolve_gateway_binary",
            return_value="gateway",
        ),
        patch(
            "defenseclaw.observability.trace_canary.subprocess.run",
            return_value=completed,
        ),
        pytest.raises(TraceCanaryError) as caught,
    ):
        run_trace_canary(
            destination="galileo",
            config_path="/data/config.yaml",
            data_dir="/data",
            timeout=15,
        )

    assert caught.value.failure_class == "gateway_rejected"
    assert secret not in str(caught.value)


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        "not-json",
        '{"destination":"other","acknowledged":false,"failure_class":"gateway_rejected"}',
        '{"destination":"galileo","trace_id":"bad","generation":1,"acknowledged":true}',
        '{"destination":"galileo","trace_id":"0123456789abcdef0123456789abcdef","generation":1,"acknowledged":true,"private":"x"}',
        "x" * 1025,
    ],
)
def test_trace_canary_rejects_malformed_or_unbounded_helper_output(stdout: str) -> None:
    with (
        patch(
            "defenseclaw.observability.trace_canary.resolve_gateway_binary",
            return_value="gateway",
        ),
        patch(
            "defenseclaw.observability.trace_canary.subprocess.run",
            return_value=_run(stdout=stdout),
        ),
        pytest.raises(TraceCanaryError) as caught,
    ):
        run_trace_canary(
            destination="galileo",
            config_path="/data/config.yaml",
            data_dir="/data",
            timeout=15,
        )
    assert caught.value.failure_class == "invalid_response"


def test_trace_canary_rejects_invalid_destination_before_spawning_helper() -> None:
    with (
        patch("defenseclaw.observability.trace_canary.subprocess.run") as run,
        pytest.raises(TraceCanaryError) as caught,
    ):
        run_trace_canary(
            destination="Galileo/../../private",
            config_path="/data/config.yaml",
            data_dir="/data",
            timeout=15,
        )
    assert caught.value.failure_class == "invalid_request"
    run.assert_not_called()


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), float("-inf"), 0.09, 61, True])
def test_trace_canary_rejects_invalid_timeout_before_spawning_helper(timeout) -> None:
    with (
        patch("defenseclaw.observability.trace_canary.subprocess.run") as run,
        pytest.raises(TraceCanaryError) as caught,
    ):
        run_trace_canary(
            destination="galileo",
            config_path="/data/config.yaml",
            data_dir="/data",
            timeout=timeout,
        )
    assert caught.value.failure_class == "invalid_request"
    run.assert_not_called()
