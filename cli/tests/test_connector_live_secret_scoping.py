# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Least-privilege contracts for live connector provider credentials."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "connector-live-e2e.yml"

PROVIDER_SECRETS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AMP_API_KEY",
    "GOOGLE_API_KEY",
    "CURSOR_API_KEY",
    "COPILOT_GITHUB_TOKEN",
    "LLM_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
)


def _jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def _step(job: dict, name: str) -> dict:
    return next(step for step in job["steps"] if step.get("name") == name)


def _secret_expression(secret: str, *connectors: str) -> str:
    comparisons = [f"matrix.connector == '{connector}'" for connector in connectors]
    condition = comparisons[0] if len(comparisons) == 1 else f"({' || '.join(comparisons)})"
    return f"${{{{ {condition} && secrets.{secret} || '' }}}}"


def _provider_references(value: object) -> set[str]:
    rendered = str(value)
    return {secret for secret in PROVIDER_SECRETS if f"secrets.{secret}" in rendered}


def _case_writes(script: str, label: str) -> set[str]:
    match = re.search(
        rf"(?ms)^\s*{re.escape(label)}\)\s*$\n(?P<body>.*?)^\s*;;\s*$",
        script,
    )
    assert match is not None, label
    return set(re.findall(r"(?m)^\s*write_key\s+([A-Z0-9_]+)\b", match.group("body")))


def test_unix_live_secrets_are_connector_scoped_and_not_job_wide() -> None:
    live = _jobs()["live-matrix"]
    assert _provider_references(live.get("env", {})) == set()

    seed = _step(live, "Seed DefenseClaw env")
    assert seed["env"] == {
        "MATRIX_CONNECTOR": "${{ matrix.connector }}",
        "OPENAI_API_KEY": _secret_expression("OPENAI_API_KEY", "codex", "opencode", "openhands"),
        "ANTHROPIC_API_KEY": _secret_expression("ANTHROPIC_API_KEY", "claudecode"),
        "AMP_API_KEY": _secret_expression("AMP_API_KEY", "amp"),
        "CURSOR_API_KEY": _secret_expression("CURSOR_API_KEY", "cursor"),
        "LLM_API_KEY": _secret_expression("LLM_API_KEY", "openhands"),
    }

    driver = _step(live, "Live driver")
    assert driver["env"] == {
        "OPENAI_API_KEY": _secret_expression("OPENAI_API_KEY", "codex", "opencode", "openhands"),
        "ANTHROPIC_API_KEY": _secret_expression("ANTHROPIC_API_KEY", "claudecode"),
        "AMP_API_KEY": _secret_expression("AMP_API_KEY", "amp"),
        "CURSOR_API_KEY": _secret_expression("CURSOR_API_KEY", "cursor"),
        "COPILOT_GITHUB_TOKEN": _secret_expression("COPILOT_GITHUB_TOKEN", "copilot"),
        "LLM_API_KEY": _secret_expression("LLM_API_KEY", "openhands"),
        "AZURE_OPENAI_API_KEY": _secret_expression("AZURE_OPENAI_API_KEY", "codex", "openhands"),
        "AWS_BEARER_TOKEN_BEDROCK": _secret_expression("AWS_BEARER_TOKEN_BEDROCK", "claudecode", "openhands"),
        "AWS_ACCESS_KEY_ID": _secret_expression("AWS_ACCESS_KEY_ID", "claudecode", "openhands"),
        "AWS_SECRET_ACCESS_KEY": _secret_expression("AWS_SECRET_ACCESS_KEY", "claudecode", "openhands"),
        "AWS_SESSION_TOKEN": _secret_expression("AWS_SESSION_TOKEN", "claudecode", "openhands"),
    }

    cursor = _step(live, "Validate Cursor headless hooks")
    assert cursor["env"] == {"CURSOR_API_KEY": _secret_expression("CURSOR_API_KEY", "cursor")}
    assert _step(live, "Initialize DefenseClaw without provider credentials").get("env") is None

    allowed = {"Seed DefenseClaw env", "Validate Cursor headless hooks", "Live driver"}
    for step in live["steps"]:
        if step.get("name") not in allowed:
            assert _provider_references(step) == set(), step.get("name", step.get("uses"))


def test_seeded_env_contains_only_the_current_connector_keys() -> None:
    seed_script = _step(_jobs()["live-matrix"], "Seed DefenseClaw env")["run"]
    assert 'case "${MATRIX_CONNECTOR}" in' in seed_script
    assert _case_writes(seed_script, "codex|opencode") == {"OPENAI_API_KEY"}
    assert _case_writes(seed_script, "claudecode") == {"ANTHROPIC_API_KEY"}
    assert _case_writes(seed_script, "amp") == {"AMP_API_KEY"}
    assert _case_writes(seed_script, "cursor") == {"CURSOR_API_KEY"}
    assert _case_writes(seed_script, "openhands") == {"OPENAI_API_KEY", "LLM_API_KEY"}
    assert _case_writes(seed_script, "copilot|hermes|devin|antigravity") == set()
    for alternative_secret in (
        "AZURE_OPENAI_API_KEY",
        "AWS_BEARER_TOKEN_BEDROCK",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ):
        assert f"write_key {alternative_secret}" not in seed_script


def test_windows_live_provider_secrets_are_harness_and_connector_scoped() -> None:
    windows = _jobs()["windows-live"]
    assert _provider_references(windows.get("env", {})) == set()

    harness = _step(windows, "Native Windows live harness")
    assert harness["env"] == {
        "OPENAI_API_KEY": _secret_expression("OPENAI_API_KEY", "codex", "opencode"),
        "ANTHROPIC_API_KEY": _secret_expression("ANTHROPIC_API_KEY", "claudecode"),
        "AMP_API_KEY": _secret_expression("AMP_API_KEY", "amp"),
        "CURSOR_API_KEY": _secret_expression("CURSOR_API_KEY", "cursor"),
    }

    for step in windows["steps"]:
        if step.get("name") != "Native Windows live harness":
            assert _provider_references(step) == set(), step.get("name", step.get("uses"))
