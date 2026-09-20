# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw import rulepack_validation
from defenseclaw.commands import cmd_guardrail


def _summary(**overrides: int | str) -> dict[str, int | str]:
    result: dict[str, int | str] = {
        "judge_count": 2,
        "judge_category_count": 2,
        "rule_file_count": 4,
        "rule_count": 12,
        "enabled_rule_count": 11,
        "local_pattern_count": 6,
        "suppression_count": 3,
        "sensitive_tool_count": 5,
        "digest": "a" * 64,
    }
    result.update(overrides)
    return result


def _completed(
    payload: object,
    *,
    returncode: int = 0,
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        [],
        returncode,
        stdout=json.dumps(payload),
        stderr=stderr,
    )


def test_valid_protocol_invokes_offline_gateway_command() -> None:
    payload = {
        "wire_version": 1,
        "kind": "validation",
        "valid": True,
        "summary": _summary(),
    }
    with (
        patch.object(
            rulepack_validation,
            "resolve_gateway_binary",
            return_value="/opt/defenseclaw-gateway",
        ),
        patch.object(
            rulepack_validation.subprocess,
            "run",
            return_value=_completed(payload),
        ) as run,
    ):
        result = rulepack_validation.validate_rule_pack("/tmp/my pack")

    assert result.valid is True
    assert result.summary == _summary()
    run.assert_called_once_with(
        [
            "/opt/defenseclaw-gateway",
            "rulepack",
            "validate",
            "--dir",
            "/tmp/my pack",
            "--json",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=15,
        check=False,
    )


def test_invalid_protocol_is_a_typed_nonzero_result() -> None:
    payload = {
        "wire_version": 1,
        "kind": "validation_error",
        "valid": False,
        "error": {
            "path": "rules/commands.yaml.rules[2].pattern",
            "code": "invalid_pattern",
            "reason": "pattern does not compile",
        },
    }
    hidden_stderr = "must-not-reach-operator"
    with (
        patch.object(
            rulepack_validation,
            "resolve_gateway_binary",
            return_value="gateway",
        ),
        patch.object(
            rulepack_validation.subprocess,
            "run",
            return_value=_completed(
                payload,
                returncode=1,
                stderr=hidden_stderr,
            ),
        ),
    ):
        result = rulepack_validation.validate_rule_pack("/tmp/invalid")

    assert result.valid is False
    assert result.error is not None
    assert result.error.code == "invalid_pattern"
    assert hidden_stderr not in json.dumps(result.to_wire_dict())


def test_zero_returncode_with_invalid_result_is_a_protocol_error() -> None:
    payload = {
        "wire_version": 1,
        "kind": "validation_error",
        "valid": False,
        "error": {
            "path": "$",
            "code": "invalid_pack",
            "reason": "pack is invalid",
        },
    }
    with (
        patch.object(
            rulepack_validation,
            "resolve_gateway_binary",
            return_value="gateway",
        ),
        patch.object(
            rulepack_validation.subprocess,
            "run",
            return_value=_completed(payload, returncode=0),
        ),
        pytest.raises(
            rulepack_validation.RulePackValidationBridgeError,
            match="incompatible success response",
        ) as caught,
    ):
        rulepack_validation.validate_rule_pack("/tmp/pack")

    assert caught.value.code == "protocol_error"


def test_nonzero_returncode_with_valid_result_is_a_protocol_error() -> None:
    payload = {
        "wire_version": 1,
        "kind": "validation",
        "valid": True,
        "summary": _summary(),
    }
    with (
        patch.object(
            rulepack_validation,
            "resolve_gateway_binary",
            return_value="gateway",
        ),
        patch.object(
            rulepack_validation.subprocess,
            "run",
            return_value=_completed(payload, returncode=1),
        ),
        pytest.raises(
            rulepack_validation.RulePackValidationBridgeError,
            match="incompatible failure response",
        ) as caught,
    ):
        rulepack_validation.validate_rule_pack("/tmp/pack")

    assert caught.value.code == "protocol_error"


def test_helper_invalid_text_is_a_safe_protocol_error() -> None:
    decode_error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
    with (
        patch.object(
            rulepack_validation,
            "resolve_gateway_binary",
            return_value="gateway",
        ),
        patch.object(
            rulepack_validation.subprocess,
            "run",
            side_effect=decode_error,
        ),
        pytest.raises(
            rulepack_validation.RulePackValidationBridgeError,
            match="malformed text",
        ) as caught,
    ):
        rulepack_validation.validate_rule_pack("/tmp/pack")
    assert caught.value.code == "protocol_error"
    assert "\\xff" not in str(caught.value)


def test_helper_oversized_stdout_is_a_safe_protocol_error() -> None:
    secret = "DO-NOT-ECHO"
    oversized = secret + ("x" * rulepack_validation._MAX_HELPER_OUTPUT_CHARS)
    completed = subprocess.CompletedProcess(
        [],
        0,
        stdout=oversized,
        stderr="",
    )
    with (
        patch.object(
            rulepack_validation,
            "resolve_gateway_binary",
            return_value="gateway",
        ),
        patch.object(
            rulepack_validation.subprocess,
            "run",
            return_value=completed,
        ),
        pytest.raises(
            rulepack_validation.RulePackValidationBridgeError,
            match="invalid response",
        ) as caught,
    ):
        rulepack_validation.validate_rule_pack("/tmp/pack")

    assert caught.value.code == "protocol_error"
    assert secret not in str(caught.value)


@pytest.mark.parametrize(
    "payload",
    [
        {
            "wire_version": 2,
            "kind": "validation",
            "valid": True,
            "summary": _summary(),
        },
        {
            "wire_version": 1,
            "kind": "validation",
            "valid": True,
            "summary": _summary(rule_count=-1),
        },
        {
            "wire_version": 1,
            "kind": "validation_error",
            "valid": False,
            "error": {
                "path": "$",
                "code": "invalid_pack",
                "reason": "unsafe\nsecond line",
            },
        },
    ],
    ids=("wire-version", "negative-summary-count", "control-character"),
)
def test_incompatible_protocol_is_rejected(
    payload: dict[str, object],
) -> None:
    with (
        patch.object(
            rulepack_validation,
            "resolve_gateway_binary",
            return_value="gateway",
        ),
        patch.object(
            rulepack_validation.subprocess,
            "run",
            return_value=_completed(payload),
        ),
        pytest.raises(
            rulepack_validation.RulePackValidationBridgeError,
            match="protocol is incompatible",
        ) as caught,
    ):
        rulepack_validation.validate_rule_pack("/tmp/pack")
    assert caught.value.code == "protocol_error"


def test_incompatible_protocol_extra_key_is_rejected_without_echoing_payload() -> None:
    secret = "DO-NOT-ECHO"
    payload = {
        "wire_version": 1,
        "kind": "validation",
        "valid": True,
        "summary": _summary(),
        "secret": secret,
    }
    with (
        patch.object(
            rulepack_validation,
            "resolve_gateway_binary",
            return_value="gateway",
        ),
        patch.object(
            rulepack_validation.subprocess,
            "run",
            return_value=_completed(payload),
        ),
        pytest.raises(
            rulepack_validation.RulePackValidationBridgeError,
            match="protocol is incompatible",
        ) as caught,
    ):
        rulepack_validation.validate_rule_pack("/tmp/pack")
    assert caught.value.code == "protocol_error"
    assert secret not in str(caught.value)


def test_validate_pack_command_invalid_exits_one_with_safe_json() -> None:
    result_value = rulepack_validation.RulePackValidationResult(
        wire_version=1,
        kind="validation_error",
        valid=False,
        error=rulepack_validation.RulePackValidationIssue(
            path="rules/custom.yaml.rules[0]",
            code="missing_field",
            reason="id is required",
        ),
    )
    with patch.object(
        rulepack_validation,
        "validate_rule_pack",
        return_value=result_value,
    ):
        result = CliRunner().invoke(
            cmd_guardrail.validate_pack_cmd,
            ["/tmp/pack", "--json"],
        )

    assert result.exit_code == 1
    assert json.loads(result.output) == result_value.to_wire_dict()


def test_validate_pack_command_rejects_whitespace_only_path() -> None:
    with patch.object(rulepack_validation, "validate_rule_pack") as validate:
        result = CliRunner().invoke(
            cmd_guardrail.validate_pack_cmd,
            ["   "],
        )

    assert result.exit_code == 2
    assert "Error: PATH must not be empty." in result.output
    validate.assert_not_called()


def test_validate_pack_command_missing_helper_exits_two_and_never_passes() -> None:
    error = rulepack_validation.RulePackValidationBridgeError(
        "defenseclaw-gateway is required for authoritative rule-pack validation; "
        "run defenseclaw upgrade",
        code="gateway_unavailable",
    )
    with patch.object(
        rulepack_validation,
        "validate_rule_pack",
        side_effect=error,
    ):
        human = CliRunner().invoke(
            cmd_guardrail.validate_pack_cmd,
            ["/tmp/pack"],
        )
        machine = CliRunner().invoke(
            cmd_guardrail.validate_pack_cmd,
            ["/tmp/pack", "--json"],
        )

    assert human.exit_code == 2
    assert "validation unavailable" in human.output.lower()
    assert "valid:" not in human.output.lower()
    assert machine.exit_code == 2
    payload = json.loads(machine.output)
    assert payload["valid"] is False
    assert payload["error"]["code"] == "gateway_unavailable"


def test_root_command_bypasses_config_and_db_for_offline_validation() -> None:
    from defenseclaw.main import cli

    result_value = rulepack_validation.RulePackValidationResult(
        wire_version=1,
        kind="validation",
        valid=True,
        summary=_summary(),
    )
    with (
        patch(
            "sys.argv",
            [
                "defenseclaw",
                "guardrail",
                "validate-pack",
                "/tmp/pack",
                "--json",
            ],
        ),
        patch.object(
            rulepack_validation,
            "validate_rule_pack",
            return_value=result_value,
        ),
        patch("defenseclaw.config.require_v8_config") as require_config,
        patch("defenseclaw.config.load") as load_config,
    ):
        result = CliRunner().invoke(
            cli,
            ["guardrail", "validate-pack", "/tmp/pack", "--json"],
        )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["valid"] is True
    require_config.assert_not_called()
    load_config.assert_not_called()


@pytest.mark.parametrize(
    ("invoked_subcommand", "argv", "expected"),
    [
        (
            "guardrail",
            ["defenseclaw", "guardrail", "validate-pack", "/tmp/pack"],
            True,
        ),
        (
            "guardrail",
            [
                "defenseclaw",
                "--root-option",
                "guardrail",
                "validate-pack",
                "/tmp/pack",
            ],
            True,
        ),
        (
            "guardrail",
            ["defenseclaw", "--", "guardrail", "validate-pack", "/tmp/pack"],
            True,
        ),
        (
            "guardrail",
            ["defenseclaw", "guardrail", "--json", "validate-pack", "/tmp/pack"],
            False,
        ),
        (
            "guardrail",
            ["defenseclaw", "guardrail", "list-packs", "validate-pack"],
            False,
        ),
        (
            "skill",
            ["defenseclaw", "skill", "scan", "guardrail", "validate-pack"],
            False,
        ),
    ],
    ids=(
        "exact",
        "root-option-prefix",
        "option-terminator-prefix",
        "intervening-flag",
        "different-guardrail-subcommand",
        "unrelated-top-level-command",
    ),
)
def test_offline_validation_preflight_matches_only_exact_command_sequence(
    invoked_subcommand: str,
    argv: list[str],
    expected: bool,
) -> None:
    from defenseclaw import main

    ctx = SimpleNamespace(invoked_subcommand=invoked_subcommand)
    with patch("sys.argv", argv):
        assert main._is_offline_rulepack_validation(ctx) is expected
