# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""A version with no hook contract: the same cause everywhere, and next steps that work.

Setup, init and quickstart refuse an agent version with no hook contract in
observe and action mode (GAP-0554). Their refusals name the gateway's cause,
and every next step they or doctor name is a command that works then
(GAP-0550 class): quickstart's refusal named `defenseclaw init` and "rerun
setup", and doctor named `setup --mode action` and `--mode observe`, which
both exit 1 for a version that cannot be read.
"""

import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.connector_paths import KNOWN_CONNECTORS
from defenseclaw.inventory.agent_discovery import AgentDiscovery, AgentSignal

REPO = Path(__file__).resolve().parents[2]
NO_DRIFT = {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": ""}
# The gateway's admission refusal (runGuardrail and setupOneConnector).
GATEWAY_CAUSE = "is not covered by a known hook contract"


def _disc(versions: dict[str, str]) -> AgentDiscovery:
    return AgentDiscovery(
        scanned_at="2026-10-22T00:00:00Z",
        cache_hit=False,
        agents={
            name: AgentSignal(
                name=name,
                installed=name in versions,
                config_path=f"/tmp/{name}.cfg" if name in versions else "",
                binary_path=f"/usr/local/bin/{name}" if name in versions else "",
                version=versions.get(name, ""),
                error="",
            )
            for name in KNOWN_CONNECTORS
        },
    )


def test_the_gateway_names_the_cause_setup_and_first_run_name():
    sidecar = (REPO / "internal/gateway/sidecar.go").read_text(encoding="utf-8")
    assert sidecar.count(f"agent version %q {GATEWAY_CAUSE}: %s") >= 2


def test_setup_names_the_gateway_cause_and_a_setup_command():
    from defenseclaw.commands.cmd_setup import _check_connector_version_supported_for_setup

    for mode in ("observe", "action"):
        with (
            patch.dict(os.environ, NO_DRIFT),
            patch("defenseclaw.commands.cmd_setup.ux.err") as err,
            patch("defenseclaw.commands.cmd_setup.ux.subhead") as subhead,
        ):
            ok = _check_connector_version_supported_for_setup(
                "claudecode", mode=mode, _discovery=_disc({"claudecode": "2.1.100 (Claude Code)"})
            )
        assert not ok
        assert GATEWAY_CAUSE in err.call_args.args[0]
        guidance = " ".join(call.args[0] for call in subhead.call_args_list)
        assert "rerun setup" not in guidance
        assert "Then run: defenseclaw setup claude-code." in guidance


def test_old_claude_code_refusal_names_the_whole_supported_range():
    # GAP-0049: for Claude Code 2.1.121 the refusal named only
    # claudecode-hooks-v1 ("requires >=2.1.154 and <2.1.219"), as if current
    # releases were unsupported, though claudecode-hooks-v2 covers >=2.1.219.
    from defenseclaw.commands.cmd_setup import _connector_contract_upgrade_guidance

    text = _connector_contract_upgrade_guidance("claudecode", "Claude Code", "2.1.121")
    assert "installed version 2.1.121 is older than the validated minimum" in text
    assert "DefenseClaw supports Claude Code >=2.1.154;" in text
    assert "claudecode-hooks-v1 covers >=2.1.154 and <2.1.219" in text
    assert "requires >=2.1.154 and <2.1.219" not in text
    assert text.endswith("Then run: defenseclaw setup claude-code.")


def test_contract_range_messages_name_the_connector_span():
    # GAP-0049 class: every range message names the connector's whole span,
    # as setup and doctor render it, and the latest uncapped contract is never
    # read as a capped one ("newer than" a range that has no upper bound).
    from defenseclaw.commands.cmd_setup import _connector_contract_upgrade_guidance
    from defenseclaw.doctor_health import _supported_ranges, supported_range_text

    assert supported_range_text(_supported_ranges("hermes")) == ">=0.19.0 and <0.22.0"
    old = _connector_contract_upgrade_guidance("hermes", "Hermes", "0.17.0")
    assert "DefenseClaw supports Hermes >=0.19.0 and <0.22.0; hermes-hooks-v1 covers >=0.19.0 and <0.21.0." in old
    new = _connector_contract_upgrade_guidance("hermes", "Hermes", "0.23.0")
    assert "newer than DefenseClaw's validated range (>=0.19.0 and <0.22.0)" in new
    for version in ("2.1.219", "2.1.300"):
        text = _connector_contract_upgrade_guidance("claudecode", "Claude Code", version)
        assert "newer than" not in text and "<2.1.219" not in text, text
    codex = _connector_contract_upgrade_guidance("codex", "Codex", "0.100.0")
    assert "DefenseClaw supports Codex >=0.124.0;" in codex


def test_no_upgrade_guidance_says_rerun_setup():
    # Every branch of the guidance names a command, not "rerun setup".
    source = (REPO / "cli/defenseclaw/commands/cmd_setup.py").read_text(encoding="utf-8")
    start = source.index("def _connector_contract_upgrade_guidance(")
    body = source[start : source.index("\ndef ", start + 1)]
    assert "rerun setup" not in body
    assert body.count("{rerun}") >= 5
    assert not re.search(r'^\s+"[^"]*\{rerun\}', body, re.M), "an f-prefix is missing"


class QuickstartNoContractRefusalTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = os.path.realpath(tempfile.mkdtemp(prefix="dclaw-qs-no-contract-"))
        self.addCleanup(shutil.rmtree, self.tmp_dir, ignore_errors=True)
        self.home = os.path.join(self.tmp_dir, "home")
        os.makedirs(self.home)
        selection = patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            return_value=({"claudecode": object()}, {}),
        )
        selection.start()
        self.addCleanup(selection.stop)
        gate = patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=True)
        gate.start()
        self.addCleanup(gate.stop)

    def _quickstart(self, *args):
        from defenseclaw.commands.cmd_quickstart import quickstart_cmd

        env = {"DEFENSECLAW_HOME": self.tmp_dir, "HOME": self.home, "USERPROFILE": self.home, **NO_DRIFT}
        with (
            patch.dict(os.environ, env),
            patch(
                "defenseclaw.inventory.agent_discovery.discover_agents",
                return_value=_disc({"claudecode": "2.1.100 (Claude Code)"}),
            ),
            patch("defenseclaw.commands.cmd_quickstart._refuse_roster_narrowing"),
        ):
            return CliRunner().invoke(
                quickstart_cmd, ["--connector", "claudecode", *args, "--skip-gateway", "--json-summary"], env=env
            )

    def test_quickstart_refusal_names_quickstart_after_the_upgrade(self):
        for mode in ("observe", "action"):
            with self.subTest(mode=mode):
                result = self._quickstart("--mode", mode)
                self.assertEqual(result.exit_code, 1, result.output)
                summary = json.loads(result.output)
                step = next(s for s in summary["setup"] if s["name"] == "Hook contract")
                rerun = "defenseclaw quickstart --connector claudecode"
                self.assertEqual(step["status"], "fail")
                self.assertIn(GATEWAY_CAUSE, step["detail"])
                self.assertIn("Upgrade Claude Code", step["detail"])
                self.assertIn(f"Then run: {rerun}.", step["detail"])
                self.assertNotIn("rerun setup", step["detail"])
                self.assertEqual(step["next_command"], rerun)
                self.assertEqual(summary["next_commands"], [rerun])
                self.assertFalse(os.path.exists(os.path.join(self.tmp_dir, "config.yaml")))


def test_doctor_does_not_name_setup_for_a_version_it_cannot_read():
    # Setup refuses a version it cannot read (no contract) in both modes, so
    # `setup <c> --mode action|observe` exits 1.
    from defenseclaw import doctor_health
    from defenseclaw.commands import cmd_doctor
    from defenseclaw.commands.cmd_setup import _check_connector_version_supported_for_setup

    unreadable = _disc({"claudecode": "Claude Code (beta)"})
    for mode in ("observe", "action"):
        with patch.dict(os.environ, NO_DRIFT), patch("defenseclaw.commands.cmd_setup.ux"):
            assert not _check_connector_version_supported_for_setup("claudecode", mode=mode, _discovery=unreadable)

    (finding,) = doctor_health.assess_connector_health(["claudecode"], unreadable)
    assert finding.reason_code == "connector-version-unparseable"
    assert all(choice.argv[:2] != ("defenseclaw", "setup") for choice in finding.remediations)
    report = SimpleNamespace(components=(), connectors=(finding,))
    r = cmd_doctor._DoctorResult()
    with (
        patch("defenseclaw.doctor_health.read_cached_discovery", return_value=None),
        patch("defenseclaw.doctor_health.build_health_report", return_value=report),
        patch.object(cmd_doctor, "_doctor_component_evidence", return_value=()),
        patch.object(cmd_doctor, "_connector_enabled", return_value=True),
    ):
        cmd_doctor._check_component_connector_compatibility(SimpleNamespace(data_dir=""), ["claudecode"], r)
    remediation = next(c for c in r.checks if c["label"] == "Connector compatibility: claudecode")["remediation"]
    assert "--mode" not in remediation
    assert remediation.startswith("run 'defenseclaw agent discover --refresh --no-emit-otel'")
    assert "install claudecode >=2.1.154 from its trusted vendor distribution" in remediation
    assert remediation.endswith("then run 'defenseclaw setup claude-code'")
