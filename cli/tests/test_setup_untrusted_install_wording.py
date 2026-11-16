# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""rel-1-0-4 GAP-2479: setup passes on discovery's untrusted-path reason in both modes."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw.commands import cmd_setup

FOLDER = "C:/Users/Public/r107-vs9e/wwbin"


def _run(mode: str, *, error: str, binary: str = FOLDER + "/codex.exe"):
    signal = SimpleNamespace(version="", installed=False, error=error, binary_path=binary)
    disc = SimpleNamespace(agents={"codex": signal})
    contract = SimpleNamespace(status=cmd_setup.STATUS_UNVERSIONED, contract=None, reason="")
    said: list[tuple[str, str]] = []
    with (
        patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc),
        patch.object(cmd_setup, "resolve_connector_contract", return_value=contract),
        patch.object(cmd_setup.ux, "err", side_effect=lambda m: said.append(("err", m))),
        patch.object(cmd_setup.ux, "warn", side_effect=lambda m: said.append(("warn", m))),
        patch.object(cmd_setup.ux, "subhead", side_effect=lambda m: said.append(("sub", m))),
    ):
        ok = cmd_setup._check_connector_version_supported_for_setup("codex", mode=mode)
    return ok, " ".join(text for _, text in said), said


@pytest.mark.parametrize("mode", ["action", "observe"])
def test_an_agent_in_an_untrusted_folder_is_named_with_its_step(mode: str) -> None:
    ok, text, said = _run(mode, error=cmd_setup.agent_discovery.UNTRUSTED_PREFIX_ERROR)
    assert ok is (mode == "observe")
    assert "the agent was found at" in text and "codex.exe" in text
    assert "not a built-in or operator-approved trusted install prefix" in text
    assert "defenseclaw setup trusted-paths add" in text and "wwbin" in text
    assert "not installed" not in text and "not detected locally" not in text
    assert "Install the connector locally" not in text
    kinds = [kind for kind, _ in said]
    assert kinds[0] == ("err" if mode == "action" else "warn")
    if mode == "action":
        assert "refusing action-mode hook setup" in text
        assert "Or install the agent where only administrators or this account can write" in text


@pytest.mark.parametrize("mode", ["action", "observe"])
def test_discovery_error_with_the_binary_in_front_is_the_same_cause(mode: str) -> None:
    error = f"{FOLDER}/codex.exe: {cmd_setup.agent_discovery.UNTRUSTED_PREFIX_ERROR}"
    _, text, _ = _run(mode, error=error)
    assert "the agent was found at" in text and "trusted-paths add" in text
    assert "not detected locally" not in text


@pytest.mark.parametrize("mode", ["action", "observe"])
def test_an_agent_that_is_not_found_keeps_the_not_detected_wording(mode: str) -> None:
    ok, text, _ = _run(mode, error="", binary="")
    assert ok is (mode == "observe")
    assert "not detected locally" in text
    assert "trusted-paths add" not in text
    # An untrusted error with no binary to name is not worded as a found agent.
    _, text, _ = _run(mode, error=cmd_setup.agent_discovery.UNTRUSTED_PREFIX_ERROR, binary="")
    assert "the agent was found at" not in text
