# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
from unittest.mock import patch

import requests
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup import setup
from defenseclaw.logger import Logger

from tests.helpers import cleanup_app, make_app_context


def test_disable_completes_when_restart_replaces_gateway_token(tmp_path) -> None:
    app, tmp_dir, db_path = make_app_context(str(tmp_path))
    app.cfg.guardrail.enabled = True
    app.cfg.gateway.token_env = "DEFENSECLAW_GATEWAY_TOKEN"
    app.logger = Logger.from_config(app.cfg)
    dotenv_path = tmp_path / ".env"
    dotenv_path.write_text(
        "DEFENSECLAW_GATEWAY_TOKEN=stale-pre-restart-token\n",
        encoding="utf-8",
    )

    def restart_services(*_args, **_kwargs) -> None:
        dotenv_path.write_text(
            "DEFENSECLAW_GATEWAY_TOKEN=fresh-post-restart-token\n",
            encoding="utf-8",
        )

    class Client:
        def __init__(self, token: str) -> None:
            self.token = token
            self.payloads: list[dict] = []

        def emit_cli_observability(self, payload) -> None:
            if self.token == "stale-pre-restart-token":
                response = requests.Response()
                response.status_code = 401
                raise requests.HTTPError(
                    "private authentication response",
                    response=response,
                )
            self.payloads.append(dict(payload))

        def close(self) -> None:
            return

    clients: list[Client] = []

    def client_factory(**kwargs):
        client = Client(kwargs["token"])
        clients.append(client)
        return client

    try:
        with (
            patch.dict(
                os.environ,
                {"DEFENSECLAW_GATEWAY_TOKEN": "stale-pre-restart-token"},
                clear=False,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._restart_services",
                side_effect=restart_services,
            ),
            patch(
                "defenseclaw.logger.OrchestratorClient",
                side_effect=client_factory,
            ),
        ):
            result = CliRunner().invoke(
                setup,
                ["guardrail", "--disable"],
                obj=app,
            )
    finally:
        cleanup_app(app, db_path, tmp_dir)

    assert result.exit_code == 0, result.output
    assert "teardown complete" in result.output.lower()
    assert not app.cfg.guardrail.enabled
    assert [client.token for client in clients] == [
        "stale-pre-restart-token",
        "fresh-post-restart-token",
    ]
    assert clients[-1].payloads[0]["action"]["details"] == "disabled connector=openclaw"
