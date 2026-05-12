"""Snapshot-aware connector install / teardown wrapper.

Like :mod:`provider_setup`, this module emits a plan of shell commands
the AI agent then runs, rather than mutating local config from Python.
Each plan includes a pre-snapshot label and an explicit teardown
counterpart so lifecycle bookkeeping is symmetric.
"""

from __future__ import annotations

from dataclasses import dataclass

from dctest.config import get_settings


@dataclass
class ConnectorPlan:
    connector: str
    setup_lines: list[str]
    verify_lines: list[str]
    teardown_lines: list[str]
    notes: str


_SETUP_ALIASES = {
    # The Python CLI exposes a `setup <alias>` for each first-party connector.
    "codex": "setup codex",
    "claudecode": "setup claude-code",
    "openclaw": "setup openclaw",
    "zeptoclaw": "setup zeptoclaw",
    "cursor": "setup cursor",
    "copilot": "setup copilot",
    "geminicli": "setup gemini-cli",
    "windsurf": "setup windsurf",
    "hermes": "setup hermes",
}


_VERIFY_HINTS = {
    "codex": [
        "test -f $HOME/.codex/config.toml",
        "grep -q '\\[hooks\\]' $HOME/.codex/config.toml",
        "grep -q 'model_providers' $HOME/.codex/config.toml",
    ],
    "claudecode": [
        "test -f $HOME/.claude/settings.json",
        "grep -q 'ANTHROPIC_BASE_URL' $HOME/.claude/settings.json || true",
    ],
    "openclaw": [
        "test -d $HOME/.openclaw/extensions/defenseclaw",
        "test -f $HOME/.openclaw/extensions/defenseclaw/openclaw.plugin.json",
    ],
    "zeptoclaw": [
        "test -f $HOME/.zeptoclaw/config.json",
    ],
    "cursor": [
        "find . -name hooks.json -path '*cursor*' -maxdepth 4 -print -quit 2>/dev/null || true",
    ],
    "copilot": [
        "ls $HOME/.config/github-copilot 2>/dev/null || true",
    ],
    "geminicli": [
        "test -d $HOME/.gemini",
    ],
    "windsurf": [
        "ls $HOME/.codeium 2>/dev/null || true",
    ],
    "hermes": [
        "test -f $HOME/.hermes/config.yaml",
    ],
}


def plan_connector_setup(connector: str) -> ConnectorPlan:
    settings = get_settings()
    bin_name = settings.defenseclaw_bin
    if connector not in _SETUP_ALIASES:
        raise ValueError(f"Unknown connector: {connector!r}")
    alias = _SETUP_ALIASES[connector]
    setup_lines = [f"{bin_name} {alias} --no-interactive"]
    verify_lines = list(_VERIFY_HINTS.get(connector, []))
    verify_lines.append(f"{settings.defenseclaw_gateway_bin} connector verify --connector {connector} --json")
    teardown_lines = [
        f"{settings.defenseclaw_gateway_bin} connector teardown --connector {connector} --json"
    ]
    notes = (
        f"Connector {connector!r}: setup is snapshot-aware in the prompt; "
        "agent must capture before/after diffs of the verify_lines output."
    )
    return ConnectorPlan(
        connector=connector,
        setup_lines=setup_lines,
        verify_lines=verify_lines,
        teardown_lines=teardown_lines,
        notes=notes,
    )
