# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest
from defenseclaw import config_inspect


def _completed(*, stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


def test_effective_bridge_uses_versioned_go_helper_without_shell() -> None:
    payload = {
        "wire_version": 2,
        "kind": "effective",
        "config_version": 8,
        "source": "/tmp/config.yaml",
        "data_dir": "/tmp/dc",
        "gateway_api_port": 29071,
        "plan_digest": "abc123",
        "network_validation": "offline_syntax_and_literal_policy_only",
        "effective": {"buckets": [], "destinations": []},
    }
    with (
        patch.object(config_inspect, "resolve_gateway_binary", return_value="/opt/bin/defenseclaw-gateway"),
        patch.object(config_inspect.subprocess, "run", return_value=_completed(stdout=json.dumps(payload))) as run,
    ):
        result = config_inspect.inspect_v8_config(
            "effective",
            config_path="/tmp/config.yaml",
            data_dir="/tmp/dc",
        )

    assert result.effective == {"buckets": [], "destinations": []}
    assert result.gateway_api_port == 29071
    run.assert_called_once_with(
        [
            "/opt/bin/defenseclaw-gateway",
            "config-v8",
            "effective",
            "--config",
            "/tmp/config.yaml",
            "--data-dir",
            "/tmp/dc",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def test_explicit_target_gateway_bypasses_installed_binary_resolution() -> None:
    payload = {
        "wire_version": 2,
        "kind": "validation",
        "config_version": 8,
        "source": "/tmp/candidate.yaml",
        "data_dir": "/tmp/dc",
        "gateway_api_port": 18970,
        "plan_digest": "target-proof",
        "network_validation": "offline_syntax_and_literal_policy_only",
        "valid": True,
    }
    with (
        patch.object(config_inspect, "resolve_gateway_binary") as resolve,
        patch.object(
            config_inspect.subprocess,
            "run",
            return_value=_completed(stdout=json.dumps(payload)),
        ) as run,
    ):
        result = config_inspect.inspect_v8_config(
            "validate",
            config_path="/tmp/candidate.yaml",
            data_dir="/tmp/dc",
            gateway_binary="/tmp/downloaded-0.8.5/defenseclaw-gateway",
        )

    assert result.valid is True
    resolve.assert_not_called()
    assert run.call_args.args[0][0] == "/tmp/downloaded-0.8.5/defenseclaw-gateway"


def test_bridge_rejects_protocol_drift_and_never_echoes_helper_stdout() -> None:
    hidden = "DO-NOT-ECHO-SECRET"
    with (
        patch.object(config_inspect, "resolve_gateway_binary", return_value="gateway"),
        patch.object(config_inspect.subprocess, "run", return_value=_completed(stdout=hidden)),
        pytest.raises(config_inspect.ConfigInspectError) as caught,
    ):
        config_inspect.inspect_v8_config("validate", config_path="config.yaml")
    assert hidden not in str(caught.value)

    incompatible = {
        "wire_version": 99,
        "kind": "validation",
        "config_version": 8,
    }
    with (
        patch.object(config_inspect, "resolve_gateway_binary", return_value="gateway"),
        patch.object(config_inspect.subprocess, "run", return_value=_completed(stdout=json.dumps(incompatible))),
        pytest.raises(config_inspect.ConfigInspectError, match="protocol is incompatible"),
    ):
        config_inspect.inspect_v8_config("validate", config_path="config.yaml")


def test_validation_refusal_preserves_exact_safe_field_and_reason() -> None:
    secret = "must-not-appear-in-diagnostic"
    failure = {
        "wire_version": 2,
        "kind": "validation_error",
        "config_version": 8,
        "path": "$.observability.destinations[0].protocol",
        "reason": "[config_schema_invalid] configuration violates the enum constraint; expected one of [grpc,http/protobuf]",
    }
    with (
        patch.object(config_inspect, "resolve_gateway_binary", return_value="gateway"),
        patch.object(
            config_inspect.subprocess,
            "run",
            return_value=_completed(stdout=json.dumps(failure), stderr=secret, returncode=1),
        ),
        pytest.raises(config_inspect.ConfigInspectError) as caught,
    ):
        config_inspect.inspect_v8_config("validate", config_path="config.yaml")

    assert caught.value.field_path == failure["path"]
    assert caught.value.reason == failure["reason"]
    assert f"field={failure['path']}" in str(caught.value)
    assert f"reason={failure['reason']}" in str(caught.value)
    assert secret not in str(caught.value)


def test_validation_refusal_rejects_multiline_structured_diagnostic() -> None:
    failure = {
        "wire_version": 2,
        "kind": "validation_error",
        "config_version": 8,
        "path": "$.observability\n.secret",
        "reason": "unsafe\nsecond line",
    }
    with (
        patch.object(config_inspect, "resolve_gateway_binary", return_value="gateway"),
        patch.object(
            config_inspect.subprocess,
            "run",
            return_value=_completed(stdout=json.dumps(failure), stderr="", returncode=1),
        ),
        pytest.raises(config_inspect.ConfigInspectError) as caught,
    ):
        config_inspect.inspect_v8_config("validate", config_path="config.yaml")

    assert caught.value.field_path is None
    assert caught.value.reason is None


def test_bridge_missing_binary_and_timeout_are_actionable() -> None:
    with (
        patch.object(config_inspect, "resolve_gateway_binary", return_value=None),
        pytest.raises(config_inspect.ConfigInspectError, match="defenseclaw upgrade"),
    ):
        config_inspect.inspect_v8_config("validate", config_path="config.yaml")

    with (
        patch.object(config_inspect, "resolve_gateway_binary", return_value="gateway"),
        patch.object(
            config_inspect.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["gateway"], timeout=15),
        ),
        pytest.raises(config_inspect.ConfigInspectError, match="timed out"),
    ):
        config_inspect.inspect_v8_config("validate", config_path="config.yaml")


def test_validation_environment_overrides_are_process_only_and_value_safe() -> None:
    payload = {
        "wire_version": 2,
        "kind": "validation",
        "config_version": 8,
        "source": "/tmp/config.yaml",
        "data_dir": "/tmp/dc",
        "gateway_api_port": 18970,
        "plan_digest": "abc123",
        "network_validation": "offline_syntax_and_literal_policy_only",
        "valid": True,
    }
    secret = "must-never-enter-argv"
    with (
        patch.object(config_inspect, "resolve_gateway_binary", return_value="gateway"),
        patch.dict(config_inspect.os.environ, {"PRESERVED": "ambient"}, clear=True),
        patch.object(
            config_inspect.subprocess,
            "run",
            return_value=_completed(stdout=json.dumps(payload)),
        ) as run,
    ):
        result = config_inspect.inspect_v8_config(
            "validate",
            config_path="/tmp/config.yaml",
            environment_overrides={"PROMOTED_SECRET": secret},
        )

    assert result.valid is True
    argv = run.call_args.args[0]
    assert secret not in argv
    assert run.call_args.kwargs["env"] == {
        "PRESERVED": "ambient",
        "PROMOTED_SECRET": secret,
    }


def test_validation_environment_drops_execution_control_from_ambient_and_overrides() -> None:
    payload = {
        "wire_version": 2,
        "kind": "validation",
        "config_version": 8,
        "source": "/tmp/config.yaml",
        "data_dir": "/tmp/dc",
        "gateway_api_port": 18970,
        "plan_digest": "abc123",
        "network_validation": "offline_syntax_and_literal_policy_only",
        "valid": True,
    }
    with (
        patch.object(config_inspect, "resolve_gateway_binary", return_value="/safe/gateway"),
        patch.dict(
            config_inspect.os.environ,
            {
                "PRESERVED": "ambient",
                "PATH": "/ambient/attacker-path",
                "LD_PRELOAD": "/ambient/attacker.so",
                "DYLD_INSERT_LIBRARIES": "/ambient/attacker.dylib",
            },
            clear=True,
        ),
        patch.object(
            config_inspect.subprocess,
            "run",
            return_value=_completed(stdout=json.dumps(payload)),
        ) as run,
    ):
        result = config_inspect.inspect_v8_config(
            "validate",
            config_path="/tmp/config.yaml",
            environment_overrides={
                "SAFE_TOKEN": "protected",
                "LD_LIBRARY_PATH": "/override/attacker",
                "PYTHONPATH": "/override/python",
            },
        )

    assert result.valid is True
    assert run.call_args.args[0][0] == "/safe/gateway"
    assert run.call_args.kwargs["env"] == {
        "PRESERVED": "ambient",
        "SAFE_TOKEN": "protected",
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"INVALID-NAME": "hidden"},
        {"VALID_NAME": "hidden\x00tail"},
    ],
)
def test_invalid_validation_environment_never_starts_helper_or_echoes_value(
    overrides: dict[str, str],
) -> None:
    with (
        patch.object(config_inspect, "resolve_gateway_binary", return_value="gateway"),
        patch.object(config_inspect.subprocess, "run") as run,
        pytest.raises(config_inspect.ConfigInspectError) as caught,
    ):
        config_inspect.inspect_v8_config(
            "validate",
            config_path="config.yaml",
            environment_overrides=overrides,
        )
    run.assert_not_called()
    assert "hidden" not in str(caught.value)


def test_reference_and_schema_use_embedded_go_artifacts() -> None:
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "$defs": {"observability": {}}}
    with (
        patch.object(config_inspect, "resolve_gateway_binary", return_value="gateway"),
        patch.object(config_inspect.subprocess, "run", return_value=_completed(stdout=json.dumps(schema))) as run,
    ):
        rendered = config_inspect.config_v8_schema()
    assert json.loads(rendered) == schema
    assert run.call_args.args[0] == ["gateway", "config-v8", "schema"]

    with (
        patch.object(config_inspect, "resolve_gateway_binary", return_value="gateway"),
        patch.object(config_inspect.subprocess, "run", return_value=_completed(stdout="# reference\n")) as run,
    ):
        assert config_inspect.config_v8_reference("yaml") == "# reference\n"
    assert run.call_args.args[0] == [
        "gateway",
        "config-v8",
        "reference",
        "--section",
        "observability",
        "--format",
        "yaml",
    ]
