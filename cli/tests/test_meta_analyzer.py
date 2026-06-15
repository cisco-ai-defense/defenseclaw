# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for MetaAnalyzer attack chain detection.

Tests all 11 cross-reference chains (5 original + 6 new) and verifies
consensus removal from LLM client.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.scanner.plugin_scanner.analyzer import ScanContext
from defenseclaw.scanner.plugin_scanner.analyzer_classes import MetaAnalyzer
from defenseclaw.scanner.plugin_scanner.types import Finding


def _make_finding(rule_id: str, severity: str = "HIGH", tags: list[str] | None = None) -> Finding:
    return Finding(
        id=f"F-{rule_id}",
        severity=severity,
        title=f"Test finding {rule_id}",
        rule_id=rule_id,
        tags=tags or [],
    )


def _ctx_with_findings(findings: list[Finding]) -> ScanContext:
    ctx = ScanContext(plugin_dir="/tmp/test-plugin", manifest=None)
    ctx.previous_findings = findings
    return ctx


class TestMetaAnalyzerOriginalChains(unittest.TestCase):
    """Tests for the 5 original attack chains."""

    def test_exfil_chain_fires(self):
        """code exec + network + creds = META-EXFIL-CHAIN"""
        findings = [
            _make_finding("SRC-EVAL", tags=["code-execution"]),
            _make_finding("SRC-FETCH", tags=["network-access"]),
            _make_finding("CRED-OPENCLAW-DIR", tags=["credential-theft"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-EXFIL-CHAIN", rule_ids)

    def test_exfil_chain_does_not_fire_without_creds(self):
        findings = [
            _make_finding("SRC-EVAL", tags=["code-execution"]),
            _make_finding("SRC-FETCH", tags=["network-access"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertNotIn("META-EXFIL-CHAIN", rule_ids)

    def test_evasive_attack_fires(self):
        """obfuscation + gateway manipulation = META-EVASIVE-ATTACK"""
        findings = [
            _make_finding("OBF-BASE64", tags=["obfuscation"]),
            _make_finding("GW-PROCESS-EXIT", tags=["gateway-manipulation"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-EVASIVE-ATTACK", rule_ids)

    def test_supply_chain_fires(self):
        """install hook + risky dep + no lockfile = META-SUPPLY-CHAIN"""
        findings = [
            _make_finding("SCRIPT-INSTALL-HOOK", tags=["supply-chain"]),
            _make_finding("DEP-RISKY", tags=["supply-chain"]),
            _make_finding("STRUCT-NO-LOCKFILE", tags=["supply-chain"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-SUPPLY-CHAIN", rule_ids)

    def test_persistent_compromise_fires(self):
        """cognitive tampering + obfuscation = META-PERSISTENT-COMPROMISE"""
        findings = [
            _make_finding("COG-TAMPER", tags=["cognitive-tampering"]),
            _make_finding("OBF-CONCAT", tags=["obfuscation"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-PERSISTENT-COMPROMISE", rule_ids)

    def test_cloud_cred_theft_fires(self):
        """SSRF + creds = META-CLOUD-CRED-THEFT"""
        findings = [
            _make_finding("SSRF-AWS-META", tags=["exfiltration"]),
            _make_finding("CRED-OPENCLAW-ENV", tags=["credential-theft"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-CLOUD-CRED-THEFT", rule_ids)


class TestMetaAnalyzerNewChains(unittest.TestCase):
    """Tests for the 6 new attack chains."""

    def test_reverse_shell_fires(self):
        """spawn + server + obfuscation = META-REVERSE-SHELL"""
        findings = [
            _make_finding("SRC-CHILD-PROC", tags=["code-execution"]),
            _make_finding("SRC-NET-SERVER", tags=["network-access"]),
            _make_finding("OBF-HEX", tags=["obfuscation"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-REVERSE-SHELL", rule_ids)

    def test_reverse_shell_needs_all_three(self):
        """Missing obfuscation should not trigger reverse shell chain."""
        findings = [
            _make_finding("SRC-CHILD-PROC", tags=["code-execution"]),
            _make_finding("SRC-NET-SERVER", tags=["network-access"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertNotIn("META-REVERSE-SHELL", rule_ids)

    def test_reverse_shell_with_http_server(self):
        """HTTP server variant should also trigger."""
        findings = [
            _make_finding("SRC-EXEC", tags=["code-execution"]),
            _make_finding("SRC-HTTP-SERVER", tags=["network-access"]),
            _make_finding("OBF-BASE64", tags=["obfuscation"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-REVERSE-SHELL", rule_ids)

    def test_reverse_shell_with_dyn_spawn(self):
        """DYN-SPAWN-VAR should count as spawn capability."""
        findings = [
            _make_finding("DYN-SPAWN-VAR", tags=["code-execution"]),
            _make_finding("SRC-NET-SERVER", tags=["network-access"]),
            _make_finding("OBF-CONCAT", tags=["obfuscation"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-REVERSE-SHELL", rule_ids)

    def test_env_exfil_fires(self):
        """env read + exfil = META-ENV-EXFIL"""
        findings = [
            _make_finding("SRC-ENV-READ", tags=["env-access"]),
            _make_finding("EXFIL-C2-DOMAIN", tags=["exfiltration"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-ENV-EXFIL", rule_ids)

    def test_env_exfil_with_dns(self):
        """DNS exfil variant should also trigger."""
        findings = [
            _make_finding("SRC-ENV-READ", tags=["env-access"]),
            _make_finding("EXFIL-DNS", tags=["exfiltration"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-ENV-EXFIL", rule_ids)

    def test_env_exfil_with_env_write(self):
        """GW-ENV-WRITE should also count as env access."""
        findings = [
            _make_finding("GW-ENV-WRITE", tags=["gateway-manipulation"]),
            _make_finding("EXFIL-C2-DOMAIN", tags=["exfiltration"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-ENV-EXFIL", rule_ids)

    def test_env_exfil_does_not_fire_without_exfil(self):
        findings = [
            _make_finding("SRC-ENV-READ", tags=["env-access"]),
            _make_finding("SRC-FETCH", tags=["network-access"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertNotIn("META-ENV-EXFIL", rule_ids)

    def test_remote_code_exec_fires(self):
        """dynamic import + network = META-REMOTE-CODE-EXEC"""
        findings = [
            _make_finding("DYN-IMPORT", tags=["code-execution"]),
            _make_finding("SRC-FETCH", tags=["network-access"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-REMOTE-CODE-EXEC", rule_ids)

    def test_remote_code_exec_with_require(self):
        """DYN-REQUIRE variant."""
        findings = [
            _make_finding("DYN-REQUIRE", tags=["code-execution"]),
            _make_finding("EXFIL-C2-DOMAIN", tags=["exfiltration"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-REMOTE-CODE-EXEC", rule_ids)

    def test_remote_code_exec_does_not_fire_without_network(self):
        findings = [
            _make_finding("DYN-IMPORT", tags=["code-execution"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertNotIn("META-REMOTE-CODE-EXEC", rule_ids)

    def test_drop_and_exec_fires(self):
        """binary + install hook = META-DROP-AND-EXEC"""
        findings = [
            _make_finding("STRUCT-BINARY", tags=["supply-chain"]),
            _make_finding("SCRIPT-INSTALL-HOOK", tags=["supply-chain"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-DROP-AND-EXEC", rule_ids)

    def test_drop_and_exec_does_not_fire_without_hook(self):
        findings = [
            _make_finding("STRUCT-BINARY", tags=["supply-chain"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertNotIn("META-DROP-AND-EXEC", rule_ids)

    def test_agent_takeover_fires(self):
        """cognitive tampering + creds = META-AGENT-TAKEOVER"""
        findings = [
            _make_finding("COG-TAMPER", tags=["cognitive-tampering"]),
            _make_finding("CRED-OPENCLAW-DIR", tags=["credential-theft"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-AGENT-TAKEOVER", rule_ids)

    def test_agent_takeover_does_not_fire_without_creds(self):
        findings = [
            _make_finding("COG-TAMPER", tags=["cognitive-tampering"]),
            _make_finding("OBF-BASE64", tags=["obfuscation"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertNotIn("META-AGENT-TAKEOVER", rule_ids)

    def test_proto_rce_fires(self):
        """prototype pollution + code exec = META-PROTO-RCE"""
        findings = [
            _make_finding("GW-PROTO-DEFINE", tags=["gateway-manipulation"]),
            _make_finding("SRC-EVAL", tags=["code-execution"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-PROTO-RCE", rule_ids)

    def test_proto_rce_with_proto_access(self):
        """GW-PROTO-ACCESS variant."""
        findings = [
            _make_finding("GW-PROTO-ACCESS", tags=["gateway-manipulation"]),
            _make_finding("SRC-NEW-FUNC", tags=["code-execution"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertIn("META-PROTO-RCE", rule_ids)

    def test_proto_rce_does_not_fire_without_exec(self):
        findings = [
            _make_finding("GW-PROTO-DEFINE", tags=["gateway-manipulation"]),
            _make_finding("SRC-FETCH", tags=["network-access"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in result]
        self.assertNotIn("META-PROTO-RCE", rule_ids)


class TestMetaAnalyzerEdgeCases(unittest.TestCase):

    def test_no_findings_returns_empty(self):
        ctx = _ctx_with_findings([])
        result = MetaAnalyzer().analyze(ctx)
        self.assertEqual(result, [])

    def test_all_chains_fire_high_or_critical(self):
        """Every META chain should be at least HIGH."""
        findings = [
            # exfil chain
            _make_finding("SRC-EVAL", tags=["code-execution"]),
            _make_finding("SRC-FETCH", tags=["network-access"]),
            _make_finding("CRED-OPENCLAW-DIR", tags=["credential-theft"]),
            # evasive
            _make_finding("OBF-CONCAT", tags=["obfuscation"]),
            _make_finding("GW-MODULE-LOAD", tags=["gateway-manipulation"]),
            # supply chain
            _make_finding("SCRIPT-INSTALL-HOOK", tags=["supply-chain"]),
            _make_finding("DEP-RISKY", tags=["supply-chain"]),
            _make_finding("STRUCT-NO-LOCKFILE", tags=["supply-chain"]),
            # persistent
            _make_finding("COG-TAMPER", tags=["cognitive-tampering"]),
            # cloud cred
            _make_finding("SSRF-AWS-META", tags=["exfiltration"]),
            # reverse shell
            _make_finding("SRC-NET-SERVER", tags=["network-access"]),
            # env exfil
            _make_finding("SRC-ENV-READ", tags=["env-access"]),
            _make_finding("EXFIL-C2-DOMAIN", tags=["exfiltration"]),
            # remote code exec
            _make_finding("DYN-IMPORT", tags=["code-execution"]),
            # drop and exec
            _make_finding("STRUCT-BINARY", tags=["supply-chain"]),
            # proto rce
            _make_finding("GW-PROTO-DEFINE", tags=["gateway-manipulation"]),
        ]
        ctx = _ctx_with_findings(findings)
        result = MetaAnalyzer().analyze(ctx)

        for f in result:
            self.assertIn(f.severity, ("CRITICAL", "HIGH"),
                          f"{f.rule_id} should be HIGH or CRITICAL, got {f.severity}")

    def test_finding_counter_increments(self):
        """Each chain should bump the counter so IDs are unique."""
        findings = [
            _make_finding("SRC-EVAL", tags=["code-execution"]),
            _make_finding("SRC-FETCH", tags=["network-access"]),
            _make_finding("CRED-OPENCLAW-DIR", tags=["credential-theft"]),
            _make_finding("OBF-CONCAT", tags=["obfuscation"]),
            _make_finding("GW-PROCESS-EXIT", tags=["gateway-manipulation"]),
        ]
        ctx = _ctx_with_findings(findings)
        ctx.finding_counter = [100]
        result = MetaAnalyzer().analyze(ctx)

        self.assertGreater(ctx.finding_counter[0], 100)
        ids = [f.id for f in result]
        self.assertEqual(len(ids), len(set(ids)), "Finding IDs must be unique")


class TestConsensusRemoved(unittest.TestCase):
    """Verify consensus logic was fully removed."""

    def test_no_consensus_function_exported(self):
        import defenseclaw.scanner.plugin_scanner.llm_client as mod
        self.assertFalse(hasattr(mod, "call_llm_with_consensus"))

    def test_no_consensus_runs_in_config(self):
        from defenseclaw.scanner.plugin_scanner.llm_client import LLMConfig
        cfg = LLMConfig()
        self.assertFalse(hasattr(cfg, "consensus_runs"))

    def test_llm_analyzer_does_not_import_consensus(self):
        import inspect

        import defenseclaw.scanner.plugin_scanner.llm_analyzer as mod
        source = inspect.getsource(mod)
        self.assertNotIn("consensus", source)


class TestTaxonomyMappings(unittest.TestCase):
    """Every META rule must have a taxonomy entry."""

    def test_all_meta_rules_have_taxonomy(self):
        from defenseclaw.scanner.plugin_scanner.rules import TAXONOMY_MAP
        meta_rules = [
            "META-EXFIL-CHAIN",
            "META-EVASIVE-ATTACK",
            "META-SUPPLY-CHAIN",
            "META-PERSISTENT-COMPROMISE",
            "META-CLOUD-CRED-THEFT",
            "META-REVERSE-SHELL",
            "META-ENV-EXFIL",
            "META-REMOTE-CODE-EXEC",
            "META-DROP-AND-EXEC",
            "META-AGENT-TAKEOVER",
            "META-PROTO-RCE",
        ]
        for rule_id in meta_rules:
            self.assertIn(rule_id, TAXONOMY_MAP,
                          f"{rule_id} missing from TAXONOMY_MAP")
            ref = TAXONOMY_MAP[rule_id]
            self.assertTrue(ref.objective.startswith("OB-"),
                            f"{rule_id} taxonomy objective invalid: {ref.objective}")


if __name__ == "__main__":
    unittest.main()
