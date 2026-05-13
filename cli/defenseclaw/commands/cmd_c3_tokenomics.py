# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path

import click

from defenseclaw.c3_agent_tokenomics.cli import build_payload_from_files
from defenseclaw.c3_agent_tokenomics.galileo_config import (
    GalileoAPIError,
    galileo_config_from_env,
    resolve_galileo_project,
)
from defenseclaw.c3_agent_tokenomics.mock_api import make_server


@click.group(name="c3-tokenomics")
def c3_tokenomics() -> None:
    """Generate or serve the Cisco Cloud Control Agent Tokenomics demo response."""


@c3_tokenomics.command("generate")
@click.option("--input", "o11y_input", default=None, help="O11y token metric rows JSON fixture.")
@click.option("--galileo-input", default=None, help="Galileo runtime controls JSON fixture.")
@click.option("--output", default="artifacts/generated_agent_tokenomics_summary.json", help="Output JSON path.")
@click.option("--tenant-id", default="c3-demo-tenant", show_default=True)
@click.option("--workspace-id", default="wayne-demo", show_default=True)
@click.option("--realm", default=None, help="Splunk O11y realm for deep links.")
@click.option("--include-galileo", is_flag=True, help="Attach Galileo runtime control and eval evidence.")
def generate_cmd(
    o11y_input: str | None,
    galileo_input: str | None,
    output: str,
    tenant_id: str,
    workspace_id: str,
    realm: str | None,
    include_galileo: bool,
) -> None:
    payload = build_payload_from_files(
        o11y_input=o11y_input,
        galileo_input=galileo_input,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        include_galileo=include_galileo,
        realm=realm,
    )
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    click.echo(f"wrote {out}")


@c3_tokenomics.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8787, show_default=True, type=int)
@click.option("--input", "o11y_input", default=None, help="O11y token metric rows JSON fixture.")
@click.option("--galileo-input", default=None, help="Galileo runtime controls JSON fixture.")
@click.option("--realm", default=None, help="Splunk O11y realm for deep links.")
def serve_cmd(host: str, port: int, o11y_input: str | None, galileo_input: str | None, realm: str | None) -> None:
    server = make_server(host, port, o11y_fixture_path=o11y_input, galileo_fixture_path=galileo_input, realm=realm)
    click.echo(f"serving http://{host}:{port}")
    server.serve_forever()


@c3_tokenomics.command("galileo-check")
@click.option("--live", is_flag=True, help="Call Galileo and resolve the configured project.")
@click.option("--api-base", default=None, help="Override GALILEO_API_BASE.")
@click.option("--project", default=None, help="Override GALILEO_PROJECT.")
@click.option("--project-id", default=None, help="Override GALILEO_PROJECT_ID.")
@click.option("--log-stream", default=None, help="Override GALILEO_LOG_STREAM.")
@click.option("--log-stream-id", default=None, help="Override GALILEO_LOG_STREAM_ID.")
def galileo_check_cmd(
    live: bool,
    api_base: str | None,
    project: str | None,
    project_id: str | None,
    log_stream: str | None,
    log_stream_id: str | None,
) -> None:
    """Show safe Galileo config status and optionally validate API access."""
    cfg = galileo_config_from_env(
        api_base=api_base,
        project=project,
        project_id=project_id,
        log_stream=log_stream,
        log_stream_id=log_stream_id,
    )
    payload: dict[str, object] = {"configured": cfg.public_status()}
    if live:
        try:
            result = resolve_galileo_project(cfg)
        except (GalileoAPIError, ValueError) as exc:
            raise click.ClickException(str(exc)) from exc
        payload["galileo"] = result
        if not result.get("ok"):
            click.echo(json.dumps(payload, indent=2, sort_keys=True))
            raise click.ClickException(str(result.get("message") or "Galileo project check failed."))
    click.echo(json.dumps(payload, indent=2, sort_keys=True))
