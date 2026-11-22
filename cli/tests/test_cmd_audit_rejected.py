# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""`defenseclaw audit rejected` runs `defenseclaw-gateway audit rejected` (#1442)."""

from __future__ import annotations

import sys

import pytest
from click.testing import CliRunner
from defenseclaw import main as main_module
from defenseclaw.commands import cmd_audit
from defenseclaw.gateway_error_codes import ALL_ERROR_CODES
from defenseclaw.observability.v8_config import observability_v8_parity_contract
from defenseclaw.observability.v8_yaml import _supported_path

from tests.os_view import os_view

GATEWAY = "/opt/dc/defenseclaw-gateway"


@pytest.fixture
def exec_capture(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []
    monkeypatch.setenv("DEFENSECLAW_DELEGATED_FROM", "")
    monkeypatch.setattr(cmd_audit, "_execv", lambda path, argv: calls.append([path, *argv]))
    monkeypatch.setattr("defenseclaw.gateway.resolve_trusted_gateway_binary", lambda: GATEWAY)
    monkeypatch.setattr(cmd_audit, "os", os_view("posix"))

    def no_config(*_args, **_kwargs):
        raise AssertionError("audit rejected loaded the CLI config or audit store")

    monkeypatch.setattr("defenseclaw.config.require_v8_config", no_config)
    monkeypatch.setattr("defenseclaw.config.load", no_config)
    return calls


@pytest.mark.parametrize("args", [["--since", "1h", "--limit", "5"], ["--help"]])
def test_rejected_alias_execs_the_gateway_without_loading_config(
    exec_capture: list[list[str]], monkeypatch: pytest.MonkeyPatch, args: list[str]
) -> None:
    argv = ["audit", "rejected", *args]
    monkeypatch.setattr(sys, "argv", ["defenseclaw", *argv])
    result = CliRunner().invoke(main_module.cli, argv, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert exec_capture == [[GATEWAY, GATEWAY, *argv]]


def test_audit_help_names_rejected() -> None:
    result = CliRunner().invoke(cmd_audit.audit, ["--help"])
    assert result.exit_code == 0
    assert "defenseclaw audit rejected" in result.output


def test_rejected_record_keys_are_settable_and_off_by_default() -> None:
    for key in ("keep_rejected_records", "rejected_records_max_rows"):
        assert _supported_path(("observability", "local", key))
    defaults = observability_v8_parity_contract()["catalog_defaults"]
    assert defaults["local_keep_rejected_records"] is False
    assert defaults["local_rejected_records_max_rows"] == 10000


def test_rejected_record_error_codes_are_registered() -> None:
    assert "REJECTED_RECORD_STORE_FAILED" in ALL_ERROR_CODES
    assert "REJECTED_RECORD_DROPPED" in ALL_ERROR_CODES
