# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Proxy and outbound-call regressions (GAP-1466, GAP-1655)."""

from __future__ import annotations

import urllib.request
from types import SimpleNamespace

import pytest
from defenseclaw.entry import exempt_instance_metadata_from_proxy

IMDS = "169.254.169.254,169.254.170.2,fd00:ec2::254"


@pytest.mark.parametrize(
    ("env", "want"),
    [
        ({"NO_PROXY": "corp.example"}, {"NO_PROXY": "corp.example"}),
        (
            {"HTTPS_PROXY": "http://127.0.0.1:3128"},
            {"HTTPS_PROXY": "http://127.0.0.1:3128", "NO_PROXY": IMDS, "no_proxy": IMDS},
        ),
        (
            {"http_proxy": "http://p:1", "no_proxy": "corp.example,169.254.169.254"},
            {
                "http_proxy": "http://p:1",
                "NO_PROXY": "corp.example,169.254.169.254,169.254.170.2,fd00:ec2::254",
                "no_proxy": "corp.example,169.254.169.254,169.254.170.2,fd00:ec2::254",
            },
        ),
        ({"HTTPS_PROXY": "http://p:1", "NO_PROXY": "*"}, {"HTTPS_PROXY": "http://p:1", "NO_PROXY": "*"}),
    ],
)
def test_instance_metadata_bypasses_the_proxy(env, want):
    # GAP-1655: botocore's IMDS lookup honors the proxy variables, so the
    # metadata endpoints must be in NO_PROXY whenever a proxy is set.
    exempt_instance_metadata_from_proxy(env)
    assert {k: v for k, v in env.items() if v} == want
    if "no_proxy" in env and env["no_proxy"] != "*":
        assert urllib.request.proxy_bypass_environment("169.254.169.254", proxies={"no": env["no_proxy"]})
        assert not urllib.request.proxy_bypass_environment(
            "bedrock-runtime.us-east-1.amazonaws.com", proxies={"no": env["no_proxy"]}
        )


def test_status_reads_fail_mode_without_starting_the_codex_app_server(monkeypatch):
    # GAP-1466: the effective-policy check starts the Codex app-server, which
    # calls chatgpt.com and the model provider; status must stay local.
    from defenseclaw import fail_mode
    from defenseclaw.commands import cmd_status

    calls = []

    def report(cfg, connector, *, inspect_effective_policy=True):
        calls.append((connector, inspect_effective_policy))
        return {"effective": "closed", "provenance": "config"}

    monkeypatch.setattr(fail_mode, "connector_fail_mode_report", report)
    result = cmd_status._effective_status_fail_mode(SimpleNamespace(), "codex")
    assert result["effective"] == "closed"
    assert calls == [("codex", False)]


def test_docs_say_gateway_start_runs_the_codex_check_on_windows():
    # GAP-1942: gateway start/restart sets up the Codex connector, which on
    # Windows starts the Codex app-server (OpenAI and the model provider);
    # the CLI reference said only doctor reaches out.
    from pathlib import Path

    docs = Path(__file__).resolve().parents[2] / "docs-site" / "content" / "docs"
    cli = " ".join((docs / "reference" / "cli.mdx").read_text(encoding="utf-8").split())
    assert "so `defenseclaw-gateway start` and `restart`, Codex setup, and the installers" in cli
    codex = " ".join((docs / "connectors" / "codex.mdx").read_text(encoding="utf-8").split())
    assert "Each gateway start or restart with the Codex connector enabled runs Codex's app-server once" in codex
