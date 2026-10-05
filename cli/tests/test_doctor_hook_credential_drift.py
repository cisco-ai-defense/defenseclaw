"""GAP-1244: Doctor finds a connector hook credential the gateway refuses."""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest import mock

import click
import pytest
from defenseclaw.commands import cmd_doctor, cmd_setup


def _cfg(data_dir: str) -> SimpleNamespace:
    return SimpleNamespace(data_dir=data_dir, active_connectors=lambda: ["claudecode"])


def _write_token(data_dir: str, body: bytes) -> None:
    hooks = os.path.join(data_dir, "hooks")
    os.makedirs(hooks, exist_ok=True)
    with open(os.path.join(hooks, ".hook-claudecode.token"), "wb") as stream:
        stream.write(body)


def test_malformed_hook_credential_is_reported_without_sending_it(tmp_path) -> None:
    _write_token(str(tmp_path), b"not-a-token\n")
    with mock.patch.object(cmd_doctor, "_http_probe", side_effect=AssertionError("sent")):
        problems = cmd_doctor._connector_hook_credential_problems(_cfg(str(tmp_path)), SimpleNamespace(trusted=True))
    assert problems == ["claudecode"]


@pytest.mark.parametrize(("status", "expected"), [(401, ["claudecode"]), (405, [])])
def test_well_formed_hook_credential_is_checked_against_the_verified_gateway(tmp_path, status, expected) -> None:
    _write_token(str(tmp_path), b"a" * 64 + b"\n")
    trust = SimpleNamespace(trusted=True)
    with (
        mock.patch.object(cmd_doctor, "_gateway_api_url", return_value="http://127.0.0.1:1/api/v1/inspect/tool"),
        mock.patch.object(cmd_doctor, "_http_probe", return_value=(status, "")) as probe,
    ):
        problems = cmd_doctor._connector_hook_credential_problems(_cfg(str(tmp_path)), trust)
    assert problems == expected
    kwargs = probe.call_args.kwargs
    assert kwargs["bound_peer"] is trust
    assert kwargs["headers"]["X-DefenseClaw-Connector"] == "claudecode"


def test_untrusted_listener_gets_no_hook_credential(tmp_path) -> None:
    _write_token(str(tmp_path), b"a" * 64 + b"\n")
    with mock.patch.object(cmd_doctor, "_http_probe", side_effect=AssertionError("sent")):
        problems = cmd_doctor._connector_hook_credential_problems(_cfg(str(tmp_path)), SimpleNamespace(trusted=False))
    assert problems == []


def test_rotate_token_names_the_connector_and_the_way_out() -> None:
    with pytest.raises(click.ClickException) as raised:
        cmd_setup._rotate_token_hook_value(b"not-a-token", "claudecode")
    assert "claudecode" in raised.value.message
    assert "defenseclaw-gateway restart" in raised.value.message
