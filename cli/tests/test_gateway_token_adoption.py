# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0847: an adopted gateway token copy never shadows the token the operator saved."""

from __future__ import annotations

import os

import pytest
from defenseclaw import config as config_module
from defenseclaw import credential_provenance, gateway_token_adoption
from defenseclaw.commands.cmd_setup import _record_adopted_gateway_token

# The line the Go gateway writes for the token "adopted"
# (internal/envvars/gateway_token_adoption_test.go asserts the same text).
GO_MARKER = "# defenseclaw: adopted gateway token sha256=5d4686f6ad6a5e224c3961e4d3ed3c65f192697ec734fa02b244e42df5900a84"
NAMES = ("DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    credential_provenance._reset_for_tests()
    for name in NAMES:
        monkeypatch.delenv(name, raising=False)
    yield
    for name in NAMES:
        os.environ.pop(name, None)
    credential_provenance._reset_for_tests()


def _resolve(tmp_path, body: str) -> str:
    (tmp_path / ".env").write_text(body)
    (tmp_path / ".env").chmod(0o600)
    config_module._load_dotenv_into_os(str(tmp_path))
    return config_module.GatewayConfig().resolved_token()


def test_marker_matches_the_go_gateway():
    assert gateway_token_adoption.marker_line("adopted") == GO_MARKER.encode()


@pytest.mark.parametrize(
    ("body", "want"),
    [
        (f"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=edited\n{GO_MARKER}\n", "edited"),
        (f"DEFENSECLAW_GATEWAY_TOKEN=\"edited\"\nOPENCLAW_GATEWAY_TOKEN=adopted\n{GO_MARKER}\n", "edited"),
        # Unedited adopted copies, no marker, or a marker for another value: the earlier spelling wins as before.
        (f"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=adopted\n{GO_MARKER}\n", "adopted"),
        ("DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=edited\n", "adopted"),
        (f"DEFENSECLAW_GATEWAY_TOKEN=one\nOPENCLAW_GATEWAY_TOKEN=two\n{GO_MARKER}\n", "one"),
        (f"OPENCLAW_GATEWAY_TOKEN=adopted\n{GO_MARKER}\n", "adopted"),
    ],
)
def test_resolved_token_prefers_the_value_the_operator_saved(tmp_path, body, want):
    assert _resolve(tmp_path, body) == want


def test_a_reload_drops_the_adopted_copy_an_earlier_load_injected(tmp_path):
    # The TUI loads .env once, then the operator edits one spelling and it loads again.
    assert _resolve(tmp_path, f"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=adopted\n{GO_MARKER}\n") == "adopted"
    assert _resolve(tmp_path, f"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=edited\n{GO_MARKER}\n") == "edited"
    assert "DEFENSECLAW_GATEWAY_TOKEN" not in os.environ


def test_a_shell_export_still_beats_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_TOKEN", "from-shell")
    body = f"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=edited\n{GO_MARKER}\n"
    assert _resolve(tmp_path, body) == "from-shell"


def test_setup_records_the_token_it_copied_and_a_later_edit_wins(tmp_path):
    (tmp_path / ".env").write_text("DEFENSECLAW_LLM_KEY=keep\nDEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=adopted\n")
    (tmp_path / ".env").chmod(0o600)
    _record_adopted_gateway_token("adopted", str(tmp_path))
    _record_adopted_gateway_token("adopted", str(tmp_path))
    body = (tmp_path / ".env").read_text()
    assert body.count(GO_MARKER) == 1
    assert "DEFENSECLAW_LLM_KEY=keep" in body
    edited = body.replace("OPENCLAW_GATEWAY_TOKEN=adopted", "OPENCLAW_GATEWAY_TOKEN=edited")
    assert _resolve(tmp_path, edited) == "edited"
