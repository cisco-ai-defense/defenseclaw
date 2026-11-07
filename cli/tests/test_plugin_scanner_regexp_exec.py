# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""SRC-EXEC reports command execution, not RegExp.prototype.exec (GAP-0610)."""

from __future__ import annotations

import json

import pytest
from defenseclaw.scanner.plugin_scanner.scanner import scan_plugin
from defenseclaw.scanner.plugin_scanner.types import PluginScanOptions

from tests.environment import requires_symlink_privilege

PROFILES = ("default", "permissive", "strict")

# The matching code of the OpenClaw Amazon Bedrock provider, as published.
PROVIDER_SOURCE = """\
const BEDROCK_REGION_RE = /bedrock-runtime\\.([a-z0-9-]+)\\.amazonaws\\.com/;
const bedrockRegionRe = new RegExp("^[a-z]{2}-[a-z]+-\\\\d$");
export function family(normalized) {
  return /(?:opus-(?:5|4-6))(?:$|-)/.exec(normalized)?.[0];
}
export function arnId(profile) {
  return /foundation-model\\/(.+)$/.exec(profile.models?.[0]?.modelArn ?? "")?.[1];
}
export function region(url) {
  bedrockRegionRe.lastIndex = 0;
  return url?.trim() ? BEDROCK_REGION_RE.exec(url)?.[1] : bedrockRegionRe.exec(url)?.[0];
}
"""


def _plugin(root, source: str, version: str = "2026.11.2") -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({
        "name": "@openclaw/amazon-bedrock-provider", "version": version,
        "type": "module", "main": "index.js",
    }), encoding="utf-8")
    (root / "index.js").write_text(source, encoding="utf-8")


def _high(root, profile: str) -> set[str]:
    return {
        f.rule_id for f in scan_plugin(str(root), PluginScanOptions(policy=profile)).findings
        if f.severity in ("HIGH", "CRITICAL")
    }


@pytest.mark.parametrize("profile", PROFILES)
def test_r109_g610_pattern_matching_is_not_command_execution(tmp_path, profile) -> None:
    """Benign twin: a provider release no local pin lists is admitted by its own code."""

    _plugin(tmp_path / "provider", PROVIDER_SOURCE)
    assert _high(tmp_path / "provider", profile) == set()


@requires_symlink_privilege
@pytest.mark.parametrize("profile", PROFILES)
def test_r109_g610_provider_with_peer_link_is_admitted_for_any_release(tmp_path, profile) -> None:
    """The installer layout (hoisted dependencies, linked host package) is not a finding."""

    peer = tmp_path / "host" / "node_modules" / "openclaw"
    peer.mkdir(parents=True)
    (peer / "package.json").write_text(json.dumps({"name": "openclaw"}), encoding="utf-8")
    for version in ("2026.10.9", "2026.10.10", "2026.11.1", "2026.11.2", "2027.1.1"):
        root = tmp_path / version
        _plugin(root, PROVIDER_SOURCE, version)
        (root / "node_modules" / "dep").mkdir(parents=True)
        (root / "node_modules" / "dep" / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        (root / "node_modules" / "openclaw").symlink_to(peer, target_is_directory=True)
        assert _high(root, profile) == set(), version


HOSTILE = {
    "bare-call": "exec(command);\n",
    "shell-receiver": "const shell = require(`node:child_process`);\nshell.exec(command);\n",
    "module-call": "require(`child_process`).exec(command);\n",
    "unknown-property-receiver": "options.pattern.exec(command);\n",
    "call-result-receiver": "load().exec(command);\n",
    "literal-and-real-call-on-one-line": "const m = /a/.exec(x); exec(command);\n",
    "regexp-name-rebound": "let RE = /a/;\nRE = require(`child_process`);\nRE.exec(command);\n",
    "regexp-name-shadowed-by-parameter": (
        "const RE = /a/;\nfunction run(RE) { RE.exec(command); }\n"
        "run(require(`child_process`));\n"
    ),
    "regexp-name-declared-twice": (
        "const RE = /a/;\n{ const RE = require(`child_process`); RE.exec(command); }\n"
    ),
    "regexp-name-passed-on": "const RE = /a/;\nuse(RE);\nRE.exec(command);\n",
    "division-not-a-literal": "const q = total /count/g.exec(command);\n",
    "name-without-regexp-binding": "const RE = load();\nRE.exec(command);\n",
}


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("case", sorted(HOSTILE))
def test_r109_g610_command_execution_stays_reported(tmp_path, profile, case) -> None:
    _plugin(tmp_path / "provider", PROVIDER_SOURCE + HOSTILE[case])
    assert "SRC-EXEC" in _high(tmp_path / "provider", profile), case


@pytest.mark.parametrize("profile", PROFILES)
def test_r109_g610_a_regexp_name_is_judged_per_file(tmp_path, profile) -> None:
    _plugin(tmp_path / "provider", PROVIDER_SOURCE)
    (tmp_path / "provider" / "other.js").write_text("BEDROCK_REGION_RE.exec(command);\n", encoding="utf-8")
    assert "SRC-EXEC" in _high(tmp_path / "provider", profile)
