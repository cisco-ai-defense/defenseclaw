# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Contracts for the operator claims reported in the 1.0.4 W4 docs audit."""

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

DOCS = Path(__file__).resolve().parents[2] / "docs-site/content/docs"


def page(path):
    return (DOCS / path).read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform == "win32", reason="Linux package deployment recipe")
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("statuses, expected", [("0", 0), ("1", 1), ("2", 2), ("75 0", 0), ("75 75 75 75 75", 75)])
def test_plain_package_recipe_propagates_ensure_exit(statuses, expected):
    text = page("enterprise/mdm/linux-config-management.mdx")
    recipe = text.split("rc=75\n", 1)[1].split("```", 1)[0]
    recipe = "rc=75\n" + recipe.replace("/opt/defenseclaw/bin/defenseclaw-gateway", "ensure_stub")
    stub = f"""statuses=({statuses})
calls=0
ensure_stub() {{
  result=${{statuses[$calls]}}
  calls=$((calls + 1))
  return "$result"
}}
sleep() {{ :; }}
"""
    result = subprocess.run(["bash", "-c", stub + recipe], capture_output=True, text=True)
    assert result.returncode == expected, result.stdout + result.stderr


def test_tetragon_detection_names_the_mode_argument():
    text = page("enterprise/mdm/index.mdx")
    assert "--require-tetragon consume|observe|enforce" in text
    assert not re.search(r"`[^`]*detect\.sh --require-tetragon`", text)


@pytest.mark.parametrize("path", [
    "observability/webhooks.mdx",
    "policies/cel/engine.mdx",
    "policies/cel/authoring.mdx",
    "policies/creator.mdx",
])
def test_bash_examples_disclose_the_shell_before_commands(path):
    text = page(path)
    before_first_shell = text.split("```bash", 1)[0]
    assert "Bash" in before_first_shell and "Windows" in before_first_shell


@pytest.mark.parametrize("path, required, forbidden", [
    ("connectors/hermes.mdx", "whitespace can change", "keeping every byte outside"),
    ("connectors/devin.mdx", "comments and formatting are removed", "Foreign hook groups and JSONC content are kept"),
    ("policies/deterministic-detection.mdx", "Go 1.26.4", "go test -timeout 30m ./internal/actionfacts ./internal/guardrail ./internal/gateway"),
    ("guardrail/user-and-group-policies.mdx", "`invalid_arguments`", "forbidden key fails with `config_invalid`"),
    ("connectors/kiro.mdx", "setup kiro --workspace", "set `claw.workspace_dir` to the project root before setup"),
    ("stories/cursor-secret-exfil.mdx", "tilde", "recorded as CRITICAL but not blocked"),
    ("enterprise/identity-sources.mdx", "TCP", "It never contacts an identity provider, a domain controller"),
    ("enterprise/troubleshooting.mdx", "`doctor` is unavailable", "Where the `defenseclaw` CLI is present, doctor shows"),
    ("enterprise/configuration.mdx", "outage", "does not override fail-closed gateway peer verification when the gateway is down"),
    ("enterprise/configuration.mdx", "enterprise macos verify", "`enterprise verify`"),
    ("segmentation.mdx", "effective hook fail mode", "Open: the call runs and the failure is recorded"),
    ("guardrail/index.mdx", "defenseclaw-hook.exe", ""),
    ("connectors/devin.mdx", "comments and formatting are removed", "JSONC content in those files are kept"),
    ("connectors/antigravity.mdx", "`~/.defenseclaw/hooks/antigravity-hook.sh` stays after `guardrail disable` and `setup remove antigravity` as an inert stub that exits successfully", None),
    ("connectors/devin.mdx", "If setup cannot edit the project file in place, for example when it has a duplicate top-level key, it writes it back as JSON too, so its comments, formatting and BOM are removed", None),
])
def test_corrected_operator_claims(path, required, forbidden):
    text = " ".join(page(path).split())
    assert required in text
    if forbidden:
        assert forbidden not in text


def test_env_pipe_lists_only_the_shipped_exfil_rule():
    text = page("stories/cursor-secret-exfil.mdx")
    row = next(line for line in text.splitlines() if "`cat .env \\|" in line)
    assert "exfil.secret_read_and_egress_oneliner" in row
    assert "CMD-ENV-DUMP" not in row


def test_effective_connector_example_matches_its_yaml():
    text = page("policies/thresholds.mdx")
    configs = re.findall(r"```yaml[^\n]*\n(.*?)```", text, re.S)
    config = next(yaml.safe_load(c) for c in configs if "contractors:" in c)
    output = re.search(r"\$ defenseclaw config get guardrail\.connectors\.codex\.block_at --effective[^\n]*\n\(source: [^\n]+\)\n(\w+)", text)
    assert output and output.group(1) == config["guardrail"]["connectors"]["codex"]["block_at"]
