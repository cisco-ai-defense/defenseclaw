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

"""Tests for the centralized admission evaluation helpers."""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import (
    AdmissionConfig,
    AdmissionFirstParty,
    AssetPolicyConfig,
    PerConnectorAssetPolicy,
    PerConnectorAssetTypePolicy,
    SeverityAction,
)
from defenseclaw.enforce.admission import (
    CompiledAdmission,
    compile_admission,
    effective_action_for,
    evaluate_admission,
    evaluate_asset_policy,
)
from defenseclaw.enforce.policy import PolicyEngine

from tests.helpers import make_temp_store


class _FakeConfig:
    """The config pieces admission reads; save() stands in for the writer."""

    def __init__(self):
        self.asset_policy = AssetPolicyConfig()
        self.admission = AdmissionConfig()
        self.admission.plugin.first_party_allow_list = [
            AdmissionFirstParty(name="acme-plugin", source_path_contains=[".openclaw/extensions/acme-plugin"]),
        ]
        self.deployment_mode = ""

    def save(self):
        pass


class _StoreTestBase(unittest.TestCase):
    def setUp(self):
        self.store, self.db_path = make_temp_store()
        self.cfg = _FakeConfig()
        self.pe = PolicyEngine(self.store, self.cfg)

    def tearDown(self):
        self.store.close()
        os.unlink(self.db_path)


class TestEvaluateAdmissionBlocked(_StoreTestBase):
    def test_blocked_item_returns_blocked(self):
        self.pe.block("skill", "evil", "malware")
        d = evaluate_admission(self.pe, target_type="skill", name="evil")
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "manual-block")

    def test_blocked_after_allow_then_block(self):
        """Block after allow should leave the item blocked (last-write wins)."""
        self.pe.allow("skill", "dual", "good")
        self.pe.block("skill", "dual", "bad")
        d = evaluate_admission(self.pe, target_type="skill", name="dual")
        self.assertEqual(d.verdict, "blocked")


class TestEvaluateAdmissionAllowed(_StoreTestBase):
    def test_explicit_allow_skips_scan(self):
        self.pe.allow("skill", "trusted", "vendor")
        d = evaluate_admission(self.pe, target_type="skill", name="trusted")
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "manual-allow")

    def test_first_party_allow_bypasses_scan(self):
        d = evaluate_admission(self.pe, target_type="plugin", name="acme-plugin",
                               source_path="/home/u/.openclaw/extensions/acme-plugin")
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "policy-allow")


class TestEvaluateAdmissionConnectorScope(_StoreTestBase):
    """N2: the admission gate honors a per-connector block/allow.

    A block scoped to connector A blocks at A's gate but not B's; a global
    (connector="") block blocks at connectors with no scoped install action;
    scoped install actions are authoritative for their connector.
    """

    def test_per_connector_block_only_blocks_that_connector(self):
        self.pe.block_for_connector("mcp", "demo", "codex", "scoped block")
        blocked = evaluate_admission(
            self.pe, target_type="mcp", name="demo", connector="codex",
        )
        self.assertEqual(blocked.verdict, "blocked")
        self.assertEqual(blocked.source, "manual-block")
        # A different connector is NOT blocked by the codex-scoped entry.
        other = evaluate_admission(
            self.pe, target_type="mcp", name="demo", connector="opencode",
        )
        self.assertNotEqual(other.verdict, "blocked")

    def test_global_block_blocks_every_connector(self):
        self.pe.block("mcp", "demo", "global block")
        for connector in ("codex", "opencode", ""):
            d = evaluate_admission(
                self.pe, target_type="mcp", name="demo", connector=connector,
            )
            self.assertEqual(d.verdict, "blocked", connector)

    def test_per_connector_allow_only_allows_that_connector(self):
        self.pe.allow_for_connector("mcp", "demo", "codex", "scoped allow")
        allowed = evaluate_admission(
            self.pe, target_type="mcp", name="demo", connector="codex",
        )
        self.assertEqual(allowed.verdict, "allowed")
        self.assertEqual(allowed.source, "manual-allow")
        # Another connector falls through to scan (no scoped/global allow).
        other = evaluate_admission(
            self.pe, target_type="mcp", name="demo", connector="opencode",
        )
        self.assertEqual(other.verdict, "scan")

    def test_connector_allow_overrides_global_block_for_that_connector(self):
        self.pe.block("mcp", "demo", "global block")
        self.pe.allow_for_connector("mcp", "demo", "codex", "scoped allow")
        d = evaluate_admission(
            self.pe, target_type="mcp", name="demo", connector="codex",
        )
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "manual-allow")
        other = evaluate_admission(
            self.pe, target_type="mcp", name="demo", connector="opencode",
        )
        self.assertEqual(other.verdict, "blocked")

    def test_connector_block_wins_over_global_allow_for_that_connector(self):
        self.pe.allow("mcp", "demo", "global allow")
        self.pe.block_for_connector("mcp", "demo", "codex", "scoped block")
        d = evaluate_admission(
            self.pe, target_type="mcp", name="demo", connector="codex",
        )
        self.assertEqual(d.verdict, "blocked")
        other = evaluate_admission(
            self.pe, target_type="mcp", name="demo", connector="opencode",
        )
        self.assertEqual(other.verdict, "allowed")


class TestEvaluateAdmissionAssetPolicy(_StoreTestBase):
    def _asset_policy(self, *, mode="action", default="allow", registry_required=False,
                      registry=None, allowed=None, denied=None,
                      registry_empty_action="deny"):
        target_policy = SimpleNamespace(
            default=default,
            registry_required=registry_required,
            registry=registry or [],
            allowed=allowed or [],
            denied=denied or [],
            registry_empty_action=registry_empty_action,
        )
        return SimpleNamespace(
            enabled=True,
            mode=mode,
            skill=target_policy,
            mcp=target_policy,
            plugin=target_policy,
        )

    def test_default_deny_blocks_before_scan(self):
        policy = self._asset_policy(default="deny")
        d = evaluate_admission(
            self.pe, target_type="skill", name="unknown",
            asset_policy=policy,
        )
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "asset-policy-default-deny")

    def test_operator_allow_overrides_default_deny_and_skips_scan(self):
        # config_version 9: asset_policy.allowed is the operator allow list.
        policy = self._asset_policy(
            default="deny",
            allowed=[SimpleNamespace(name="trusted", connector="codex")],
        )
        d = evaluate_admission(
            self.pe, target_type="skill", name="trusted",
            connector="codex",
            asset_policy=policy,
        )
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "manual-allow")

    def test_denied_rule_matches_connector_alias(self):
        # A denied rule keyed on the documented alias "open-hands" must still
        # fire against the registry-canonical active connector "openhands". A
        # literal lower-case compare silently skipped the rule, letting a
        # server through that policy meant to block.
        policy = self._asset_policy(
            denied=[SimpleNamespace(name="risky", connector="open-hands")],
        )
        d = evaluate_admission(
            self.pe, target_type="mcp", name="risky",
            connector="openhands",
            asset_policy=policy,
        )
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "asset-policy-deny")

    def test_connector_allowed_rule_overrides_global_denied_rule(self):
        policy = self._asset_policy(
            denied=[SimpleNamespace(name="tool")],
            allowed=[SimpleNamespace(name="tool", connector="codex")],
        )
        codex = evaluate_asset_policy(
            policy, target_type="mcp", name="tool", connector="codex",
        )
        self.assertEqual(codex.verdict, "allowed")
        self.assertEqual(codex.source, "asset-policy-allow")

        hermes = evaluate_asset_policy(
            policy, target_type="mcp", name="tool", connector="hermes",
        )
        self.assertEqual(hermes.verdict, "blocked")
        self.assertEqual(hermes.source, "asset-policy-deny")

    def test_connector_denied_rule_overrides_global_allowed_rule(self):
        policy = self._asset_policy(
            allowed=[SimpleNamespace(name="tool")],
            denied=[SimpleNamespace(name="tool", connector="codex")],
        )
        d = evaluate_asset_policy(
            policy, target_type="mcp", name="tool", connector="codex",
        )
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "asset-policy-deny")

    def test_connector_denied_rule_wins_over_connector_allowed_rule(self):
        policy = self._asset_policy(
            allowed=[SimpleNamespace(name="tool", connector="codex")],
            denied=[SimpleNamespace(name="tool", connector="codex")],
        )
        d = evaluate_asset_policy(
            policy, target_type="mcp", name="tool", connector="codex",
        )
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "asset-policy-deny")

    def test_registry_required_blocks_unregistered(self):
        policy = self._asset_policy(
            registry_required=True,
            registry=[SimpleNamespace(name="github")],
        )
        d = evaluate_admission(
            self.pe, target_type="mcp", name="rogue",
            asset_policy=policy,
        )
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "asset-policy-registry-required")

    # --- OTHER-6: empty-but-required registry honors registry_empty_action,
    # mirroring the Go gateway (internal/config/asset_policy.go). These probe
    # evaluate_asset_policy directly because evaluate_admission folds a
    # non-blocked asset verdict into the downstream scan flow.

    def test_empty_required_registry_denies_by_default(self):
        policy = self._asset_policy(registry_required=True, registry=[])
        d = evaluate_asset_policy(policy, target_type="mcp", name="demo")
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "asset-policy-registry-required-empty")

    def test_empty_required_registry_allow_falls_through_to_default(self):
        policy = self._asset_policy(
            registry_required=True, registry=[], registry_empty_action="allow",
        )
        d = evaluate_asset_policy(policy, target_type="mcp", name="demo")
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "asset-policy-default-allow")

    def test_empty_required_registry_allow_still_honors_default_deny(self):
        # registry_empty_action="allow" only relaxes the empty-registry gate;
        # a default=deny policy still blocks.
        policy = self._asset_policy(
            registry_required=True, registry=[],
            registry_empty_action="allow", default="deny",
        )
        d = evaluate_asset_policy(policy, target_type="mcp", name="demo")
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "asset-policy-default-deny")

    def test_empty_required_registry_warn_falls_through_to_default(self):
        # "warn" is treated like "allow" — it falls through to the default
        # check. The Go gateway now resolves "warn" the same way (warn-Go
        # ruling), so the Python preview and the runtime agree.
        policy = self._asset_policy(
            registry_required=True, registry=[], registry_empty_action="warn",
        )
        d = evaluate_asset_policy(policy, target_type="mcp", name="demo")
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "asset-policy-default-allow")

    def test_empty_required_registry_warn_still_honors_default_deny(self):
        # "warn" only relaxes the empty-registry gate, not the default policy.
        policy = self._asset_policy(
            registry_required=True, registry=[],
            registry_empty_action="warn", default="deny",
        )
        d = evaluate_asset_policy(policy, target_type="mcp", name="demo")
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "asset-policy-default-deny")

    def test_empty_required_registry_observe_downgrades_block(self):
        policy = self._asset_policy(
            mode="observe", registry_required=True, registry=[],
        )
        d = evaluate_asset_policy(policy, target_type="mcp", name="demo")
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "asset-policy-registry-required-empty-observe")

    def test_nonempty_required_registry_unmatched_unchanged(self):
        # The configured (non-empty) registry path is unchanged by OTHER-6.
        policy = self._asset_policy(
            registry_required=True,
            registry=[SimpleNamespace(name="github")],
        )
        d = evaluate_asset_policy(policy, target_type="mcp", name="rogue")
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "asset-policy-registry-required")

    def test_empty_required_registry_allow_not_blocked_end_to_end(self):
        # Through the full admission path the empty+allow case must reach the
        # normal scan flow rather than the old unconditional block.
        policy = self._asset_policy(
            registry_required=True, registry=[], registry_empty_action="allow",
        )
        d = evaluate_admission(
            self.pe, target_type="mcp", name="demo",
            asset_policy=policy,
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")

    def test_observe_mode_does_not_block_install_flow(self):
        policy = self._asset_policy(mode="observe", default="deny")
        d = evaluate_admission(
            self.pe, target_type="plugin", name="unknown",
            asset_policy=policy,
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")

    def test_denied_rule_blocks_in_observe_mode(self):
        policy = self._asset_policy(
            mode="observe",
            denied=[SimpleNamespace(name="untrusted")],
        )
        d = evaluate_admission(
            self.pe, target_type="skill", name="untrusted",
            asset_policy=policy,
        )
        # config_version 9: the explicit lists apply in every mode.
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "asset-policy-deny")

    def test_observe_mode_keeps_the_would_block_on_the_decision(self):
        # GAP-2390: observe mode must still report what action mode refuses.
        policy = self._asset_policy(
            mode="observe", registry_required=True,
            registry=[SimpleNamespace(name="approved")],
        )
        d = evaluate_admission(
            self.pe, target_type="mcp", name="offreg",
            asset_policy=policy,
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.observed_source, "asset-policy-registry-required-observe")
        self.assertIn("not in the approved registry", d.observed_reason)
        allowed = evaluate_admission(
            self.pe, target_type="mcp", name="approved",
            asset_policy=policy,
        )
        self.assertEqual(allowed.observed_reason, "")

    def _mcp_registry_rule(self):
        # A registry rule pinning the full command and exact argv.
        return SimpleNamespace(
            name="filesystem",
            command="/usr/bin/npx",
            args_prefix=["-y", "@modelcontextprotocol/server-filesystem"],
        )

    def test_mcp_registry_exact_match_allowed(self):
        # F-1906: the exact pinned command + argv must still register cleanly.
        policy = self._asset_policy(
            registry_required=True,
            registry=[self._mcp_registry_rule()],
        )
        d = evaluate_admission(
            self.pe, target_type="mcp", name="filesystem",
            command="/usr/bin/npx",
            args=["-y", "@modelcontextprotocol/server-filesystem"],
            asset_policy=policy,
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")

    def test_mcp_registry_full_command_substitution_blocked(self):
        # F-1906 repro: an attacker swaps the registered basename ``npx`` for a
        # full path to a hostile binary in a writable dir. A basename-only
        # compare matched the registry rule; the strict full-command compare
        # must reject it so registry_required blocks the unregistered server.
        policy = self._asset_policy(
            registry_required=True,
            registry=[self._mcp_registry_rule()],
        )
        d = evaluate_admission(
            self.pe, target_type="mcp", name="filesystem",
            command="/tmp/evil/npx",
            args=["-y", "@modelcontextprotocol/server-filesystem"],
            asset_policy=policy,
        )
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "asset-policy-registry-required")

    def test_mcp_registry_trailing_argv_blocked(self):
        # F-1906 repro: an attacker keeps the registered command + prefix but
        # appends extra trailing argv (e.g. a second, attacker-controlled
        # server root). An argv *prefix* match admitted it; the strict EXACT
        # argv compare must reject the extra arguments.
        policy = self._asset_policy(
            registry_required=True,
            registry=[self._mcp_registry_rule()],
        )
        d = evaluate_admission(
            self.pe, target_type="mcp", name="filesystem",
            command="/usr/bin/npx",
            args=[
                "-y",
                "@modelcontextprotocol/server-filesystem",
                "/etc",  # attacker-appended extra root
            ],
            asset_policy=policy,
        )
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "asset-policy-registry-required")


class TestEvaluateAdmissionFirstPartyProvenance(_StoreTestBase):
    # F-0141/F-0902: markers must pin the asset's own leaf directory anchored
    # to a DefenseClaw-owned home; the base fixture pins
    # ``.openclaw/extensions/acme-plugin``.

    def test_matching_path_allows(self):
        # F-1221: the legitimate home-anchored install path still bypasses scan.
        d = evaluate_admission(
            self.pe, target_type="plugin", name="acme-plugin",
            source_path="/home/user/.openclaw/extensions/acme-plugin",
        )
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "policy-allow")

    def test_sibling_under_owned_home_falls_through(self):
        # F-1221: a different asset that merely lands under the same
        # ``.openclaw/extensions`` parent (the old broad marker) must NOT be
        # blessed — the marker now pins the ``defenseclaw`` leaf.
        d = evaluate_admission(
            self.pe, target_type="plugin", name="acme-plugin",
            source_path="/home/user/.openclaw/extensions/evil",
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")

    def test_spoofed_sibling_path_falls_through(self):
        # F-0141: the marker run must be anchored to a DefenseClaw-owned home.
        # An attacker who drops ``defenseclaw`` under their own ``extensions``
        # dir in a user-writable location must NOT inherit the first-party
        # allow even though the component subsequence matches.
        d = evaluate_admission(
            self.pe, target_type="plugin", name="acme-plugin",
            source_path="/tmp/attacker/.openclaw/extensions/acme-plugin",
        )
        # Anchored to a real (if attacker-named) ``.openclaw`` home component —
        # this is still considered first-party-owned by the home marker.
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "policy-allow")

    def test_non_matching_path_falls_through(self):
        d = evaluate_admission(
            self.pe, target_type="plugin", name="acme-plugin",
            source_path="/home/user/random/plugins/something",
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")

    def test_temp_dir_falls_through(self):
        d = evaluate_admission(
            self.pe, target_type="plugin", name="acme-plugin",
            source_path="/tmp/dclaw-plugin-fetch-abc123/defenseclaw",
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")

    def test_empty_path_falls_through(self):
        d = evaluate_admission(
            self.pe, target_type="plugin", name="acme-plugin",
            source_path="",
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")


class TestBundledPolicyProvenance(unittest.TestCase):
    """End-to-end checks against the built-in first-party markers."""

    def _pe(self):
        return SimpleNamespace(
            is_blocked=lambda *a: False,
            is_allowed=lambda *a: False,
            is_quarantined=lambda *a: False,
        )

    def test_f0902_spoofed_sibling_extensions_path_scans(self):
        # F-0902/F-0141: the bundled plugin marker must no longer ship the bare
        # ``extensions/defenseclaw`` relative marker, so an attacker home that
        # merely contains ``extensions/defenseclaw`` is NOT first-party-allowed.
        d = evaluate_admission(
            self._pe(),
            target_type="plugin",
            name="defenseclaw",
            source_path="/tmp/attacker/extensions/defenseclaw",
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")

    def test_builtin_plugin_name_alone_requires_scan(self):
        # GAP-0419: a plugin folder named defenseclaw is not trusted by name;
        # the gateway recognizes DefenseClaw's own plugin by its bytes.
        d = evaluate_admission(
            self._pe(),
            target_type="plugin",
            name="defenseclaw",
            source_path="/home/u/.openclaw/extensions/defenseclaw",
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")

    def test_f0902_spoofed_sibling_skills_path_scans(self):
        # The bundled skill marker must no longer ship bare ``skills/codeguard``
        # / ``workspace/skills/codeguard`` markers.
        d = evaluate_admission(
            self._pe(),
            target_type="skill",
            name="codeguard",
            source_path="/tmp/attacker/workspace/skills/codeguard",
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")

    def test_codeguard_entry_trusts_only_the_shipped_skill(self):
        # GAP-0419: any folder named codeguard under a skills folder used to
        # skip the scan; only an exact copy of the shipped skill does now.
        import shutil
        import tempfile

        from defenseclaw.paths import bundled_codeguard_dir

        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, ".openclaw", "workspace", "skills", "codeguard")
            shutil.copytree(bundled_codeguard_dir(), path, ignore=shutil.ignore_patterns("__pycache__"))

            def verdict():
                return evaluate_admission(self._pe(), target_type="skill", name="codeguard", source_path=path)

            self.assertEqual((verdict().verdict, verdict().source), ("allowed", "policy-allow"))
            with open(os.path.join(path, "deploy.sh"), "w", encoding="utf-8") as fh:
                fh.write("echo deploy\n")
            self.assertEqual((verdict().verdict, verdict().source), ("scan", "scan-required"))

    def test_codex_personal_codeguard_path_requires_scan_without_stronger_provenance(self):
        d = evaluate_admission(
            self._pe(),
            target_type="skill",
            name="codeguard",
            source_path="/home/u/.agents/skills/codeguard",
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")

    def test_codex_project_codeguard_spoof_requires_scan(self):
        d = evaluate_admission(
            self._pe(),
            target_type="skill",
            name="codeguard",
            source_path="/work/repo/.agents/skills/codeguard",
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")

    def test_codex_legacy_skill_home_requires_scan(self):
        d = evaluate_admission(
            self._pe(),
            target_type="skill",
            name="codeguard",
            source_path="/home/u/.codex/skills/codeguard",
        )
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")


class TestEvaluateAssetPolicyPerConnector(unittest.TestCase):
    """OTHER-7: per-connector asset_policy resolution through the real
    :class:`AssetPolicyConfig` resolvers (not a duck-typed namespace), so the
    ``effective_mode`` / ``effective_asset_type_policy`` overlay is exercised
    end to end and stays in lockstep with the Go ``assetPolicyFor`` overlay.
    """

    def test_per_connector_mode_action_blocks_while_inheritor_observes(self):
        # codex overrides mode=action; hermes inherits the global observe.
        # Same default deny, different connector → different verdict.
        policy = AssetPolicyConfig(
            enabled=True,
            mode="observe",
            connectors={"codex": PerConnectorAssetPolicy(mode="action")},
        )
        policy.mcp.default = "deny"

        codex = evaluate_asset_policy(
            policy, target_type="mcp", name="rogue", connector="codex",
        )
        self.assertEqual(codex.verdict, "blocked")
        self.assertEqual(codex.source, "asset-policy-default-deny")

        hermes = evaluate_asset_policy(
            policy, target_type="mcp", name="rogue", connector="hermes",
        )
        self.assertEqual(hermes.verdict, "allowed")
        self.assertEqual(hermes.source, "asset-policy-default-deny-observe")

    def test_per_connector_registry_required_overlay(self):
        # codex requires a registry (empty → fail-closed deny); hermes
        # inherits the global registry_required=False and is allowed.
        policy = AssetPolicyConfig(
            enabled=True,
            mode="action",
            connectors={
                "codex": PerConnectorAssetPolicy(
                    mcp=PerConnectorAssetTypePolicy(registry_required=True),
                ),
            },
        )

        codex = evaluate_asset_policy(
            policy, target_type="mcp", name="demo", connector="codex",
        )
        self.assertEqual(codex.verdict, "blocked")
        self.assertEqual(codex.source, "asset-policy-registry-required-empty")

        hermes = evaluate_asset_policy(
            policy, target_type="mcp", name="demo", connector="hermes",
        )
        self.assertEqual(hermes.verdict, "allowed")
        self.assertEqual(hermes.source, "asset-policy-default-allow")

    def test_per_connector_registry_empty_action_overlay(self):
        # codex requires a registry but opts into allow-on-empty, so it falls
        # through to the (allow) default — composing OTHER-6 with OTHER-7.
        policy = AssetPolicyConfig(
            enabled=True,
            mode="action",
            connectors={
                "codex": PerConnectorAssetPolicy(
                    mcp=PerConnectorAssetTypePolicy(
                        registry_required=True, registry_empty_action="allow",
                    ),
                ),
            },
        )
        d = evaluate_asset_policy(
            policy, target_type="mcp", name="demo", connector="codex",
        )
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "asset-policy-default-allow")

    def test_per_connector_default_overlay_blocks(self):
        # codex overrides default=deny on skills; the global default stays allow.
        policy = AssetPolicyConfig(
            enabled=True,
            mode="action",
            connectors={
                "codex": PerConnectorAssetPolicy(
                    skill=PerConnectorAssetTypePolicy(default="deny"),
                ),
            },
        )
        codex = evaluate_asset_policy(
            policy, target_type="skill", name="x", connector="codex",
        )
        self.assertEqual(codex.verdict, "blocked")
        self.assertEqual(codex.source, "asset-policy-default-deny")

        hermes = evaluate_asset_policy(
            policy, target_type="skill", name="x", connector="hermes",
        )
        self.assertEqual(hermes.verdict, "allowed")
        self.assertEqual(hermes.source, "asset-policy-default-allow")

    def test_global_only_config_unaffected(self):
        # No connectors map → behaves exactly like the global policy for any
        # connector (single-connector / legacy parity).
        policy = AssetPolicyConfig(enabled=True, mode="action")
        policy.mcp.default = "deny"
        d = evaluate_asset_policy(
            policy, target_type="mcp", name="x", connector="codex",
        )
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "asset-policy-default-deny")

    def test_alias_keyed_override_resolves(self):
        # An override keyed on the documented alias "open-hands" applies to the
        # registry-canonical connector "openhands" (normalize parity with Go).
        policy = AssetPolicyConfig(
            enabled=True,
            mode="observe",
            connectors={"open-hands": PerConnectorAssetPolicy(mode="action")},
        )
        policy.mcp.denied = [SimpleNamespace(name="rogue")]
        d = evaluate_asset_policy(
            policy, target_type="mcp", name="rogue", connector="openhands",
        )
        self.assertEqual(d.verdict, "blocked")
        self.assertEqual(d.source, "asset-policy-deny")


class TestEvaluateAdmissionFirstPartyNoBypass(_StoreTestBase):
    def setUp(self):
        super().setUp()
        self.cfg.admission.plugin.allow_list_bypass_scan = False

    def test_first_party_requires_scan_when_bypass_disabled(self):
        d = evaluate_admission(self.pe, target_type="plugin", name="defenseclaw",
                               source_path="/home/u/.openclaw/extensions/defenseclaw")
        self.assertEqual(d.verdict, "scan")
        self.assertEqual(d.source, "scan-required")


class TestEvaluateAdmissionScanDisabled(_StoreTestBase):
    def setUp(self):
        super().setUp()
        self.cfg.admission.defaults.scan_on_install = False

    def test_scan_disabled_allows_without_scan(self):
        d = evaluate_admission(self.pe, target_type="skill", name="new-skill")
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "scan-disabled")


class TestEvaluateAdmissionRequiresScan(_StoreTestBase):
    def test_no_scan_result_returns_scan_required(self):
        d = evaluate_admission(self.pe, target_type="skill", name="new-skill")
        self.assertEqual(d.verdict, "scan")


class TestEvaluateAdmissionWithScanResult(_StoreTestBase):
    def _make_scan_result(self, findings, max_severity):
        class FakeScanResult:
            def __init__(self, findings, sev):
                self.findings = findings
                self._sev = sev
            def max_severity(self):
                return self._sev
        return FakeScanResult(findings, max_severity)

    def test_clean_scan(self):
        result = self._make_scan_result([], "INFO")
        d = evaluate_admission(self.pe, target_type="skill", name="safe",
                               scan_result=result)
        self.assertEqual(d.verdict, "clean")
        self.assertEqual(d.source, "scan-clean")

    def test_high_severity_rejected(self):
        result = self._make_scan_result([{"severity": "HIGH"}], "HIGH")
        d = evaluate_admission(self.pe, target_type="skill", name="risky",
                               scan_result=result)
        self.assertEqual(d.verdict, "rejected")
        self.assertEqual(d.source, "scan-rejected")
        self.assertEqual(d.action.install, "block")
        self.assertEqual(d.action.runtime, "disable")

    def test_medium_severity_warning(self):
        result = self._make_scan_result([{"severity": "MEDIUM"}], "MEDIUM")
        d = evaluate_admission(self.pe, target_type="skill", name="iffy",
                               scan_result=result)
        self.assertEqual(d.verdict, "warning")
        self.assertEqual(d.source, "scan-warning")

    def test_install_block_alone_rejects(self):
        self.cfg.admission.defaults.actions["high"] = {"install": "block", "file": "none", "runtime": "enable"}
        result = self._make_scan_result([{"severity": "HIGH"}], "HIGH")
        d = evaluate_admission(self.pe, target_type="skill", name="partial", scan_result=result)
        self.assertEqual(d.verdict, "rejected")

    def test_allow_shorthand_allows_findings(self):
        self.cfg.admission.skill.actions["medium"] = "allow"
        result = self._make_scan_result([{"severity": "MEDIUM"}], "MEDIUM")
        d = evaluate_admission(self.pe, target_type="skill", name="ok", scan_result=result)
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "scan-allowed")


class TestEvaluateAdmissionDictScanResult(_StoreTestBase):
    def test_dict_scan_result_clean(self):
        d = evaluate_admission(
            self.pe, target_type="skill", name="safe",
            scan_result={"total_findings": 0, "max_severity": "INFO"},
        )
        self.assertEqual(d.verdict, "clean")

    def test_dict_scan_result_with_findings(self):
        d = evaluate_admission(
            self.pe, target_type="skill", name="risky",
            scan_result={"total_findings": 2, "max_severity": "HIGH"},
        )
        self.assertEqual(d.verdict, "rejected")


class TestEvaluateAdmissionQuarantine(_StoreTestBase):
    def test_quarantined_item_rejected_when_flag_set(self):
        self.pe.quarantine("skill", "qskill", "scan findings")
        d = evaluate_admission(self.pe, target_type="skill", name="qskill",
                               include_quarantine=True)
        self.assertEqual(d.verdict, "rejected")
        self.assertEqual(d.source, "quarantine")

    def test_quarantined_item_not_checked_without_flag(self):
        self.pe.quarantine("skill", "qskill", "scan findings")
        d = evaluate_admission(self.pe, target_type="skill", name="qskill")
        self.assertEqual(d.verdict, "scan")


class TestEffectiveActionFor(unittest.TestCase):
    def test_scanner_override_then_severity_then_fail_closed(self):
        quarantine = SeverityAction(file="quarantine", runtime="disable", install="block")
        warn = SeverityAction()
        policy = CompiledAdmission(
            actions={"MEDIUM": (warn, False)},
            scanner_overrides={"virustotal": {"MEDIUM": (quarantine, False)}},
        )
        self.assertEqual(effective_action_for(policy, severity="medium", scanner="virustotal")[0], quarantine)
        self.assertEqual(effective_action_for(policy, severity="MEDIUM", scanner="skill-scanner")[0], warn)
        self.assertEqual(effective_action_for(policy, severity="BOGUS")[0].install, "block")


class TestCompileAdmission(unittest.TestCase):
    def test_builtin_defaults(self):
        mcp = compile_admission(None, "mcp")
        self.assertTrue(mcp.scan_on_install and mcp.allow_list_bypass_scan)
        self.assertEqual(mcp.actions["HIGH"][0].install, "block")
        self.assertEqual(mcp.actions["MEDIUM"][0].install, "block")
        self.assertIn("codeguard", compile_admission(None, "skill").first_party_allow)
        self.assertIn("defenseclaw", compile_admission(None, "plugin").first_party_allow)

    def test_layers_type_then_scanner_gate_then_defaults(self):
        # Unset gate keys apply their shown defaults (HIGH, review MEDIUM), as Go.
        gate = SimpleNamespace(fail_on_severity="", review_queue_min="")
        cfg = SimpleNamespace(admission=AdmissionConfig(), scanners=SimpleNamespace(skill_scanner=gate))
        cfg.admission.defaults.actions["low"] = "block"
        cfg.admission.skill.actions["critical"] = "block"
        # An explicit empty first-party list allows nothing first party (Go firstParty).
        cfg.admission.plugin.first_party_allow_list = []
        self.assertEqual(compile_admission(cfg, "plugin").first_party_allow, {})
        self.assertIn("codeguard", compile_admission(cfg, "skill").first_party_allow)
        # Entries that share a name all apply, as in Go and Rego.
        cfg.admission.skill.first_party_allow_list = [
            AdmissionFirstParty(name="codeguard", source_path_contains=[".claude/skills/codeguard"]),
            AdmissionFirstParty(name="codeguard", source_path_contains=[".cursor/skills/codeguard"]),
        ]
        self.assertEqual(
            compile_admission(cfg, "skill").first_party_allow,
            {"codeguard": [".claude/skills/codeguard", ".cursor/skills/codeguard"]},
        )
        cfg.admission.skill.first_party_allow_list = None
        skill = compile_admission(cfg, "skill")
        self.assertEqual(skill.source, "config:admission.skill.actions")
        self.assertEqual(skill.actions["CRITICAL"][0].file, "none")
        self.assertEqual(skill.actions["HIGH"][0].file, "quarantine")
        self.assertEqual(skill.actions["MEDIUM"][0].install, "none")
        self.assertTrue(skill.actions["LOW"][1])
        self.assertEqual(compile_admission(cfg, "plugin").actions["LOW"][0].install, "block")

    def test_secure_client_keeps_the_1_0_data_json_admission(self):
        # As Go secureClientAdmission: data.json decides and no scanner gate
        # is derived, so a LOW skill finding stays a warning.
        import json
        import tempfile
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as policy_dir:
            os.makedirs(os.path.join(policy_dir, "rego"))
            with open(os.path.join(policy_dir, "rego", "data.json"), "w", encoding="utf-8") as handle:
                json.dump({"actions": {
                    "HIGH": {"install": "block", "file": "quarantine", "runtime": "block"},
                    "MEDIUM": {"install": "block", "file": "none", "runtime": "block"},
                    "LOW": {"install": "none", "file": "none", "runtime": "allow"},
                }}, handle)
            cfg = SimpleNamespace(deployment_mode="managed_enterprise", policy_dir=policy_dir, admission=AdmissionConfig())
            with patch.dict(os.environ, {"DEFENSECLAW_ENTERPRISE_PROFILE": "secure_client"}):
                skill = compile_admission(cfg, "skill")
        self.assertEqual(skill.source, "data.json")
        self.assertEqual((skill.actions["MEDIUM"][0].install, skill.actions["MEDIUM"][0].runtime), ("block", "disable"))
        self.assertEqual(skill.actions["LOW"][0].install, "none")
        self.assertFalse(skill.actions["LOW"][1])


class TestPolicyEngineToolConnectorScope(_StoreTestBase):
    """T2: connector-scoped tool helpers (the @<connector>/<tool> gate).

    Mirrors internal/enforce/policy_test.go::TestPolicyEngineToolConnectorScope.
    """

    def test_connector_block_isolated(self):
        self.pe.block_tool_for_connector("delete_file", "hermes", "scoped")
        self.assertTrue(self.pe.is_blocked_for_connector("tool", "delete_file", "hermes"))
        self.assertFalse(self.pe.is_blocked_for_connector("tool", "delete_file", "codex"))
        self.assertFalse(self.pe.is_blocked_for_connector("tool", "delete_file", ""))
        self.assertFalse(self.pe.is_blocked_for_connector("tool", "delete_file", ""))

    def test_global_block_hits_all_connectors(self):
        self.pe.block_tool_for_connector("delete_file", "", "global")
        for connector in ("", "hermes", "codex"):
            self.assertTrue(
                self.pe.is_blocked_for_connector("tool", "delete_file", connector)
            )

    def test_connector_allow_isolated(self):
        self.pe.allow_tool_for_connector("search", "hermes", "scoped")
        self.assertTrue(self.pe.is_allowed_for_connector("tool", "search", "hermes"))
        self.assertFalse(self.pe.is_allowed_for_connector("tool", "search", "codex"))
        self.assertFalse(self.pe.is_allowed_for_connector("tool", "search", ""))

    def test_global_allow_applies_to_all_connectors(self):
        self.pe.allow_tool_for_connector("search", "", "global")
        for connector in ("", "hermes", "codex"):
            self.assertTrue(
                self.pe.is_allowed_for_connector("tool", "search", connector)
            )

    def test_connector_allow_overrides_global_block_for_connector(self):
        # Connector-scoped rows are authoritative before the global fallback.
        self.pe.block_tool_for_connector("write_file", "", "global block")
        self.pe.allow_tool_for_connector("write_file", "hermes", "scoped allow")
        self.assertFalse(self.pe.is_blocked_for_connector("tool", "write_file", "hermes"))
        self.assertTrue(self.pe.is_allowed_for_connector("tool", "write_file", "hermes"))
        self.assertTrue(self.pe.is_blocked_for_connector("tool", "write_file", "codex"))
        self.assertFalse(self.pe.is_allowed_for_connector("tool", "write_file", "codex"))


if __name__ == "__main__":
    unittest.main()
