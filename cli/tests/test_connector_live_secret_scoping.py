# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Least-privilege contracts for live connector provider credentials."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
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


def _bash_executable() -> str:
    """Select Git Bash on Windows instead of the WSL app alias."""

    if os.name != "nt":
        return shutil.which("bash") or "bash"

    candidates: list[Path] = []
    if git := shutil.which("git"):
        candidates.append(Path(git).resolve().parent.parent / "bin" / "bash.exe")
    for variable in ("ProgramFiles", "ProgramFiles(x86)", "LocalAppData"):
        if root := os.environ.get(variable):
            candidates.append(Path(root) / "Git" / "bin" / "bash.exe")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    pytest.skip("Git Bash is required for the POSIX connector secret-scoping contract on Windows")


def _jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def _step(job: dict, name: str) -> dict:
    return next(step for step in job["steps"] if step.get("name") == name)


def _secret_expression(secret: str, *connectors: str) -> str:
    comparisons = [f"matrix.connector == '{connector}'" for connector in connectors]
    condition = comparisons[0] if len(comparisons) == 1 else f"({' || '.join(comparisons)})"
    return f"${{{{ {condition} && secrets.{secret} || '' }}}}"


def _gated_secret_expression(secret: str, condition: str) -> str:
    return f"${{{{ {condition} && secrets.{secret} || '' }}}}"


def _provider_references(value: object) -> set[str]:
    rendered = str(value)
    return {secret for secret in PROVIDER_SECRETS if f"secrets.{secret}" in rendered}


def test_unix_live_secrets_are_connector_scoped_and_not_job_wide() -> None:
    live = _jobs()["live-matrix"]
    assert _provider_references(live.get("env", {})) == set()
    assert {
        "connector": "opencode",
        "os": "macos-latest",
        "dcos": "macos",
    } in live["strategy"]["matrix"]["include"]
    assert not any(
        cell.get("connector") == "opencode" and cell.get("dcos") != "macos"
        for cell in live["strategy"]["matrix"]["include"]
    )

    direct_openai = (
        "(matrix.connector == 'opencode' || "
        "(matrix.connector == 'codex' && env.DC_USE_AZURE != '1') || "
        "(matrix.connector == 'openhands' && env.DC_USE_BEDROCK != '1' && env.DC_USE_AZURE != '1'))"
    )
    direct_anthropic = "(matrix.connector == 'claudecode' && env.DC_USE_BEDROCK != '1')"
    direct_openhands = (
        "(matrix.connector == 'openhands' && env.DC_USE_BEDROCK != '1' && env.DC_USE_AZURE != '1')"
    )
    azure = (
        "((matrix.connector == 'codex' && env.DC_USE_AZURE == '1') || "
        "(matrix.connector == 'openhands' && env.DC_USE_BEDROCK != '1' && env.DC_USE_AZURE == '1'))"
    )
    bedrock = "((matrix.connector == 'claudecode' || matrix.connector == 'openhands') && env.DC_USE_BEDROCK == '1')"

    assert all(step.get("name") != "Seed DefenseClaw env" for step in live["steps"])

    driver = _step(live, "Live driver")
    assert driver["env"] == {
        "OPENAI_API_KEY": _gated_secret_expression("OPENAI_API_KEY", direct_openai),
        "ANTHROPIC_API_KEY": _gated_secret_expression("ANTHROPIC_API_KEY", direct_anthropic),
        "AMP_API_KEY": _secret_expression("AMP_API_KEY", "amp"),
        "CURSOR_API_KEY": _secret_expression("CURSOR_API_KEY", "cursor"),
        "COPILOT_GITHUB_TOKEN": _secret_expression("COPILOT_GITHUB_TOKEN", "copilot"),
        "LLM_API_KEY": _gated_secret_expression("LLM_API_KEY", direct_openhands),
        "AZURE_OPENAI_API_KEY": _gated_secret_expression("AZURE_OPENAI_API_KEY", azure),
        "AWS_BEARER_TOKEN_BEDROCK": _gated_secret_expression("AWS_BEARER_TOKEN_BEDROCK", bedrock),
        "AWS_ACCESS_KEY_ID": _gated_secret_expression("AWS_ACCESS_KEY_ID", bedrock),
        "AWS_SECRET_ACCESS_KEY": _gated_secret_expression("AWS_SECRET_ACCESS_KEY", bedrock),
        "AWS_SESSION_TOKEN": _gated_secret_expression("AWS_SESSION_TOKEN", bedrock),
    }

    cursor = _step(live, "Validate Cursor headless hooks")
    assert cursor["env"] == {"CURSOR_API_KEY": _secret_expression("CURSOR_API_KEY", "cursor")}
    assert _step(live, "Initialize DefenseClaw without provider credentials").get("env") is None

    allowed = {"Validate Cursor headless hooks", "Live driver"}
    for step in live["steps"]:
        if step.get("name") not in allowed:
            assert _provider_references(step) == set(), step.get("name", step.get("uses"))


def test_live_installers_do_not_receive_or_persist_provider_credentials_early() -> None:
    common = (ROOT / "scripts/live-connector-e2e/lib/common.sh").read_text(encoding="utf-8")
    helper = common.split("dc_without_provider_credentials() (", 1)[1].split("\n)", 1)[0]
    for secret in PROVIDER_SECRETS:
        assert secret in helper
    assert 'raw="$(dc_without_provider_credentials "$@"' in common

    drivers = ROOT / "scripts" / "live-connector-e2e" / "drivers"
    codex = (drivers / "codex.sh").read_text(encoding="utf-8")
    assert "npm install -g --ignore-scripts" in codex
    assert codex.index("dc_without_provider_credentials npm install") < codex.index(
        "dc_write_env_key OPENAI_API_KEY"
    )
    assert "codex --version" not in codex

    opencode = (drivers / "opencode.sh").read_text(encoding="utf-8")
    assert "dc_without_provider_credentials npm install" in opencode
    assert opencode.index("dc_without_provider_credentials npm install") < opencode.index(
        "dc_write_env_key OPENAI_API_KEY"
    )

    openhands = (drivers / "openhands.sh").read_text(encoding="utf-8")
    assert "dc_without_provider_credentials uv tool install" in openhands
    assert openhands.index("dc_without_provider_credentials uv tool install") < openhands.index(
        "dc_write_env_key LLM_API_KEY"
    )
    assert "dc_write_env_key AWS_" not in openhands
    assert "dc_write_env_key AZURE_OPENAI_API_KEY" not in openhands

    claude = (drivers / "claudecode.sh").read_text(encoding="utf-8")
    assert 'dc_without_provider_credentials _claude_install_release "${requested}"' in claude
    assert claude.index("dc_without_provider_credentials _claude_install_release") < claude.index(
        'DC_E2E_AGENT_VERSION="${version}"'
    )
    assert claude.index('DC_E2E_AGENT_VERSION="${version}"') < claude.index(
        "dc_write_env_key ANTHROPIC_API_KEY"
    )
    assert "dc_write_env_key AWS_" not in claude


def test_contract_macos_fixtures_are_pinned_discoverable_and_credential_free() -> None:
    contract = _jobs()["contract-matrix"]
    codex = _step(contract, "Install authenticated Codex lifecycle fixture")
    assert codex["env"] == {
        "CODEX_VERSION": "0.146.0",
        "DC_E2E_CLIENT_PROVISION_ONLY": "1",
    }
    assert _provider_references(codex) == set()
    assert ". scripts/live-connector-e2e/drivers/codex.sh" in codex["run"]
    assert 'export npm_config_prefix="${HOME}/.npm-global"' in codex["run"]
    assert "${HOME}/.npm-global/lib/node_modules/@openai/codex" in codex["run"]
    assert "${RUNNER_TEMP}" not in codex["run"]
    selection = (ROOT / "cli/defenseclaw/agent_selection.py").read_text(encoding="utf-8")
    assert 'home / ".npm-global" / "lib" / "node_modules"' in selection

    fixture = _step(contract, "Install authenticated Claude Code lifecycle fixture")

    assert fixture["if"] == (
        "steps.select.outputs.run == 'true' && "
        "matrix.connector == 'claudecode' && runner.os == 'macOS'"
    )
    assert fixture["env"] == {
        "CLAUDE_VERSION": "2.1.219",
        "DC_E2E_CLIENT_PROVISION_ONLY": "1",
    }
    assert _provider_references(fixture) == set()
    assert ". scripts/live-connector-e2e/drivers/claudecode.sh" in fixture["run"]
    assert "agent_install" in fixture["run"]


def test_claude_provision_only_scrubs_every_installer_child(tmp_path: Path) -> None:
    driver = (ROOT / "scripts/live-connector-e2e/drivers/claudecode.sh").as_posix()
    child_environment = (tmp_path / "child.env").as_posix()
    script = f"""
set -euo pipefail
. "$1"
secret_scope_child_environment="$2"
_claude_install_release() {{
  env > "$secret_scope_child_environment"
  printf '2.1.219'
}}
export DC_E2E_CLIENT_PROVISION_ONLY=1
agent_install
for name in {' '.join(PROVIDER_SECRETS)}; do
  test "${{!name}}" = sentinel
done
"""
    environment = os.environ.copy()
    environment.update({name: "sentinel" for name in PROVIDER_SECRETS})
    subprocess.run(
        [_bash_executable(), "-c", script, "secret-scope-test", driver, child_environment],
        check=True,
        env=environment,
    )

    child = (tmp_path / "child.env").read_text(encoding="utf-8")
    for name in PROVIDER_SECRETS:
        assert f"{name}=" not in child

    # Sourcing a provision-only driver must not dispatch its authenticated
    # live harness. The source guard is part of the reusable installer API.
    claude = (ROOT / "scripts/live-connector-e2e/drivers/claudecode.sh").read_text(encoding="utf-8")
    assert 'if [ "${BASH_SOURCE[0]}" = "$0" ]; then' in claude


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
