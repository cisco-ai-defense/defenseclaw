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

"""Regression tests for security remediations.

One focused test (or pair) per finding; each fails against the
pre-remediation behaviour and passes after the fix.

  F-0241  cmd_policy runtime vocabulary mapping (block stays block)
  F-0543  admission.rego provenance matches by path component, not substring
  F-0541  bundled data.json first-party plugin provenance is tightened
  F-0401  path-pinned allow fails closed on an empty presented path
  F-0282  skill scan honours path-pinned allows (shared admission)
  F-0283  skill install rejects quarantined skills
  F-0422  inventory source path prefers the live item path
  F-0423  prior scans match by full resolved path, not basename
  F-0424  skill marker files are not read through symlinks
  F-0742  user-sourced inventory rows are not first-party-allowed
  F-0544  openshell hostless allowed_ips requires host membership
  F-0546  openshell messaging egress is not granted to every binary
  F-0641  Codex TOML parsing falls back to tomli when tomllib is absent
"""

from __future__ import annotations

import builtins
import os
import shutil
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import defenseclaw
from click.testing import CliRunner
from defenseclaw.commands.cmd_policy import _opa_runtime_action
from defenseclaw.commands.cmd_skill import skill
from defenseclaw.config import SkillActionsConfig
from defenseclaw.enforce.admission import (
    _matches_provenance,
    evaluate_admission,
    load_admission_policy,
)
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.inventory import agent_discovery as ad
from defenseclaw.inventory.claw_inventory import (
    _inventory_source_path,
    _read_skill_description,
    _scan_entry_matches_path,
    _tools_from_codex_config,
    enrich_with_policy,
)
from defenseclaw.models import ScanResult

from tests.helpers import cleanup_app, make_app_context, make_temp_store


def _bundled_rego_dir() -> str:
    return os.path.join(os.path.dirname(defenseclaw.__file__), "_data", "policies", "rego")


# ---------------------------------------------------------------------------
# F-0241 — runtime vocabulary mapping
# ---------------------------------------------------------------------------


class TestF0241RuntimeVocabulary(unittest.TestCase):
    def test_block_runtime_stays_block(self):
        # The bug mapped only "disable" -> "block"; an explicit
        # ``runtime: block`` override silently became "allow".
        self.assertEqual(_opa_runtime_action("block"), "block")

    def test_disable_maps_to_block(self):
        self.assertEqual(_opa_runtime_action("disable"), "block")

    def test_enable_and_allow_map_to_allow(self):
        self.assertEqual(_opa_runtime_action("enable"), "allow")
        self.assertEqual(_opa_runtime_action("allow"), "allow")

    def test_case_and_whitespace_insensitive(self):
        self.assertEqual(_opa_runtime_action("  BLOCK "), "block")

    def test_unknown_defaults_to_allow(self):
        self.assertEqual(_opa_runtime_action("something-else"), "allow")


# ---------------------------------------------------------------------------
# F-0543 — admission.rego provenance is component-based, not substring
# ---------------------------------------------------------------------------


class TestF0543ProvenanceComponentMatch(unittest.TestCase):
    def test_evil_sibling_component_does_not_match(self):
        # `.defenseclaw-evil` must NOT satisfy a `.defenseclaw` allow.
        self.assertFalse(
            _matches_provenance([".defenseclaw"], "/tmp/.defenseclaw-evil/x")
        )

    def test_exact_component_matches(self):
        self.assertTrue(
            _matches_provenance([".defenseclaw"], "/home/u/.defenseclaw/plugin")
        )

    def test_rego_uses_component_matcher_not_substring(self):
        rego = os.path.join(_bundled_rego_dir(), "admission.rego")
        with open(rego, encoding="utf-8") as f:
            text = f.read()
        # The substring form was the vulnerability; the active matcher must
        # now compare whole path components (a contiguous component slice),
        # not a bare ``contains`` substring test.
        self.assertIn("_provenance_prefix_matches(input.path, prefix)", text)
        self.assertIn("array.slice(path_comps", text)


# ---------------------------------------------------------------------------
# F-0541 — bundled data.json first-party plugin provenance is tightened
# ---------------------------------------------------------------------------


class TestF0541TightenedFirstPartyProvenance(unittest.TestCase):
    def setUp(self):
        self.policy = load_admission_policy(_bundled_rego_dir())
        _, self.constraints = self.policy.first_party_allow[("plugin", "defenseclaw")]

    def test_broad_extensions_dir_entry_removed(self):
        # `.openclaw/extensions` matched ANY plugin in the extensions dir.
        self.assertNotIn(".openclaw/extensions", self.constraints)
        self.assertNotIn(".defenseclaw", self.constraints)
        # `.codex-plugin/defenseclaw` is an attacker-placeable Codex plugin
        # location (codex plugins live in `~/.codex/plugins`, NOT here), so
        # it must not be a first-party provenance marker.
        self.assertNotIn(".codex-plugin/defenseclaw", self.constraints)

    def test_bare_relative_marker_removed(self):
        # F-0902: the bare, home-UNANCHORED ``extensions/defenseclaw`` marker
        # matched the same component sequence under ANY parent (including an
        # attacker-writable one), so it must no longer ship. Only home-anchored
        # markers remain.
        self.assertNotIn("extensions/defenseclaw", self.constraints)

    def test_precise_home_anchored_entry_present(self):
        # The replacement is the home-anchored leaf path.
        self.assertIn(".openclaw/extensions/defenseclaw", self.constraints)

    def test_spoofed_codex_plugin_path_no_longer_bypasses(self):
        # F-0541 repro path: a hostile plugin named "defenseclaw" dropped
        # under a `.codex-plugin` marker dir must NOT inherit the first-party
        # allow (it used to match the broad `.codex-plugin/defenseclaw`
        # entry and skip scanning).
        self.assertFalse(
            _matches_provenance(
                self.constraints, "/tmp/attacker/.codex-plugin/defenseclaw"
            )
        )

    def test_f0141_spoofed_extensions_sibling_no_longer_bypasses(self):
        # F-0141 repro: a hostile plugin dropped at
        # ``<attacker-writable>/extensions/defenseclaw`` used to match the bare
        # ``extensions/defenseclaw`` marker anywhere in the tree. With the bare
        # marker removed and the matcher anchored to a DefenseClaw-owned home,
        # this attacker path must fall through to a scan.
        self.assertFalse(
            _matches_provenance(
                self.constraints, "/tmp/attacker/extensions/defenseclaw"
            )
        )

    def test_evaluate_admission_scans_spoofed_codex_plugin(self):
        # End-to-end through the bundled policy: the spoofed path must come
        # back as a scan-required decision, not a first-party allow bypass.
        pe = SimpleNamespace(
            is_blocked=lambda *a: False,
            is_allowed=lambda *a: False,
            is_quarantined=lambda *a: False,
        )
        bundled_policies = os.path.join(
            os.path.dirname(defenseclaw.__file__), "_data", "policies"
        )
        decision = evaluate_admission(
            pe,
            policy_dir=bundled_policies,
            target_type="plugin",
            name="defenseclaw",
            source_path="/tmp/attacker/.codex-plugin/defenseclaw",
        )
        self.assertEqual(decision.verdict, "scan")
        self.assertEqual(decision.source, "scan-required")

    def test_evaluate_admission_scans_spoofed_extensions_sibling(self):
        # F-0141 end-to-end: the bare-marker bypass path is scan-required.
        pe = SimpleNamespace(
            is_blocked=lambda *a: False,
            is_allowed=lambda *a: False,
            is_quarantined=lambda *a: False,
        )
        bundled_policies = os.path.join(
            os.path.dirname(defenseclaw.__file__), "_data", "policies"
        )
        decision = evaluate_admission(
            pe,
            policy_dir=bundled_policies,
            target_type="plugin",
            name="defenseclaw",
            source_path="/tmp/attacker/extensions/defenseclaw",
        )
        self.assertEqual(decision.verdict, "scan")
        self.assertEqual(decision.source, "scan-required")

    def test_spoofed_install_path_no_longer_bypasses(self):
        # A hostile plugin named "defenseclaw" dropped elsewhere under the
        # extensions dir must not match the tightened provenance.
        self.assertFalse(
            _matches_provenance(self.constraints, "/home/u/.openclaw/extensions/evil")
        )

    def test_legitimate_install_still_allowed(self):
        self.assertTrue(
            _matches_provenance(
                self.constraints, "/home/u/.openclaw/extensions/defenseclaw"
            )
        )


# ---------------------------------------------------------------------------
# F-0401 — path-pinned allow fails closed on empty presented path
# ---------------------------------------------------------------------------


class TestF0401PathPinFailsClosed(unittest.TestCase):
    def setUp(self):
        self.store, self.db_path = make_temp_store()
        self.pe = PolicyEngine(self.store)
        self.policy_dir = tempfile.mkdtemp(prefix="dclaw-f0401-")

    def tearDown(self):
        self.store.close()
        os.unlink(self.db_path)
        shutil.rmtree(self.policy_dir, ignore_errors=True)

    def _pin(self):
        self.pe.allow("skill", "trusted", "vetted at a path")
        self.pe.set_source_path("skill", "trusted", "/opt/trusted/trusted")

    def test_empty_presented_path_is_rejected(self):
        self._pin()
        d = evaluate_admission(
            self.pe, policy_dir=self.policy_dir,
            target_type="skill", name="trusted", source_path="",
        )
        self.assertEqual(d.verdict, "rejected")
        self.assertEqual(d.source, "manual-allow-path-mismatch")

    def test_matching_path_still_allows(self):
        self._pin()
        d = evaluate_admission(
            self.pe, policy_dir=self.policy_dir,
            target_type="skill", name="trusted",
            source_path="/opt/trusted/trusted",
        )
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.source, "manual-allow")


# ---------------------------------------------------------------------------
# F-0422 — inventory source path prefers the live item path
# ---------------------------------------------------------------------------


class TestF0422LiveSourcePathPreferred(unittest.TestCase):
    def test_live_path_wins_over_stale_stored_path(self):
        action_entry = SimpleNamespace(
            source_path="/stale/stored/location", target_name="demo"
        )
        item = {"id": "demo", "path": "/live/on-disk/demo"}
        resolved = _inventory_source_path(
            item, "skill", ["demo"], None, action_entry, None,
        )
        self.assertEqual(resolved, "/live/on-disk/demo")

    def test_stored_path_used_only_when_no_live_path(self):
        action_entry = SimpleNamespace(
            source_path="/stored/location", target_name="demo"
        )
        item = {"id": "demo"}
        resolved = _inventory_source_path(
            item, "skill", ["demo"], None, action_entry, None,
        )
        self.assertEqual(resolved, "/stored/location")


# ---------------------------------------------------------------------------
# F-0423 — prior scans match by full resolved path, not basename
# ---------------------------------------------------------------------------


class TestF0423FullPathScanMatch(unittest.TestCase):
    def setUp(self):
        self.store, self.db_path = make_temp_store()

    def tearDown(self):
        self.store.close()
        os.unlink(self.db_path)

    def test_helper_rejects_basename_collision(self):
        self.assertFalse(
            _scan_entry_matches_path({"target": "/a/codeguard"}, "/b/codeguard")
        )
        self.assertTrue(
            _scan_entry_matches_path({"target": "/a/codeguard"}, "/a/codeguard")
        )
        # No independent path → keep the (name) match for legacy rows.
        self.assertTrue(_scan_entry_matches_path({"target": "/a/codeguard"}, ""))

    def test_same_basename_different_path_is_unscanned(self):
        now = datetime.now(timezone.utc)
        self.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", "/tmp/elsewhere/foo",
            now, 100, 0, "INFO", "{}",
        )
        inv = {
            "skills": [{"id": "foo", "source": "user", "path": "/opt/real/foo"}],
            "summary": {"skills": {"count": 1}},
        }
        enrich_with_policy(inv, self.store, SkillActionsConfig())
        # The clean scan belongs to a *different* on-disk asset that merely
        # shares the basename — it must not be credited here.
        self.assertEqual(inv["skills"][0]["policy_verdict"], "unscanned")
        self.assertNotIn("scan_findings", inv["skills"][0])

    def test_same_path_is_credited(self):
        now = datetime.now(timezone.utc)
        self.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", "/tmp/elsewhere/foo",
            now, 100, 0, "INFO", "{}",
        )
        inv = {
            "skills": [{"id": "foo", "source": "user", "path": "/tmp/elsewhere/foo"}],
            "summary": {"skills": {"count": 1}},
        }
        enrich_with_policy(inv, self.store, SkillActionsConfig())
        self.assertEqual(inv["skills"][0]["policy_verdict"], "clean")


# ---------------------------------------------------------------------------
# F-0742 — user-sourced inventory rows are not first-party-allowed
# ---------------------------------------------------------------------------


class TestF0742UserSourceNotFirstParty(unittest.TestCase):
    def setUp(self):
        self.store, self.db_path = make_temp_store()

    def tearDown(self):
        self.store.close()
        os.unlink(self.db_path)

    def test_user_sourced_codeguard_is_not_first_party_allowed(self):
        inv = {
            "skills": [
                {
                    "id": "codeguard",
                    "source": "user",
                    "path": "/home/u/.openclaw/skills/codeguard",
                }
            ],
            "summary": {"skills": {"count": 1}},
        }
        enrich_with_policy(inv, self.store, SkillActionsConfig())
        self.assertNotEqual(inv["skills"][0]["policy_verdict"], "allowed")

    def test_bundled_codeguard_still_first_party_allowed(self):
        inv = {
            "skills": [
                {
                    "id": "codeguard",
                    "source": "bundled",
                    "path": "/home/u/.openclaw/skills/codeguard",
                }
            ],
            "summary": {"skills": {"count": 1}},
        }
        enrich_with_policy(inv, self.store, SkillActionsConfig())
        self.assertEqual(inv["skills"][0]["policy_verdict"], "allowed")


# ---------------------------------------------------------------------------
# F-0424 — skill marker files are not read through symlinks
# ---------------------------------------------------------------------------


class TestF0424NoSymlinkMarkerRead(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-f0424-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_symlinked_marker_is_not_followed(self):
        secret = os.path.join(self.tmp, "secret.txt")
        with open(secret, "w", encoding="utf-8") as f:
            f.write("TOP-SECRET-API-TOKEN-CONTENTS\n")
        skill_dir = os.path.join(self.tmp, "evil-skill")
        os.makedirs(skill_dir)
        marker = os.path.join(skill_dir, "SKILL.md")
        try:
            os.symlink(secret, marker)
        except OSError:
            self.skipTest("filesystem does not support symlinks")
        # The symlinked marker must not leak the secret's contents.
        self.assertEqual(_read_skill_description(skill_dir), "")

    def test_regular_marker_is_read(self):
        skill_dir = os.path.join(self.tmp, "good-skill")
        os.makedirs(skill_dir)
        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write("# A helpful skill\n")
        self.assertEqual(_read_skill_description(skill_dir), "A helpful skill")


# ---------------------------------------------------------------------------
# F-0282 — skill scan honours path-pinned allows
# ---------------------------------------------------------------------------


class _SkillCommandBase(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()
        self._orig_columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "200"

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)
        if self._orig_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._orig_columns

    def invoke(self, args):
        return self.runner.invoke(skill, args, obj=self.app, catch_exceptions=False)


class TestF0282SkillScanPathPinnedAllow(_SkillCommandBase):
    def _clean_result(self, skill_dir):
        return ScanResult(
            scanner="skill-scanner",
            target=skill_dir,
            timestamp=datetime.now(timezone.utc),
            findings=[],
            duration=timedelta(seconds=0.1),
        )

    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_path_pinned_allow_mismatch_does_not_skip(self, mock_scanner_cls):
        skill_dir = os.path.join(self.tmp_dir, "demo")
        os.makedirs(skill_dir)
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = self._clean_result(skill_dir)
        mock_scanner_cls.return_value = mock_scanner

        pe = PolicyEngine(self.app.store)
        pe.allow("skill", "demo", "vetted at a specific path")
        # Pinned to a DIFFERENT path than the one being scanned.
        pe.set_source_path("skill", "demo", "/opt/trusted/demo")

        result = self.invoke(["scan", "demo", "--path", skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("ALLOWED (skip scan)", result.output)
        mock_scanner.scan.assert_called_once_with(skill_dir)

    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_path_pinned_allow_match_skips_scan(self, mock_scanner_cls):
        skill_dir = os.path.join(self.tmp_dir, "demo")
        os.makedirs(skill_dir)
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = self._clean_result(skill_dir)
        mock_scanner_cls.return_value = mock_scanner

        pe = PolicyEngine(self.app.store)
        pe.allow("skill", "demo", "vetted")
        pe.set_source_path("skill", "demo", skill_dir)

        result = self.invoke(["scan", "demo", "--path", skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("ALLOWED", result.output)
        mock_scanner.scan.assert_not_called()


# ---------------------------------------------------------------------------
# F-0283 — skill install rejects quarantined skills
# ---------------------------------------------------------------------------


class TestF0283InstallRejectsQuarantined(_SkillCommandBase):
    @patch("defenseclaw.commands.cmd_skill._run_clawhub_install")
    def test_quarantined_skill_is_not_installed(self, mock_install):
        pe = PolicyEngine(self.app.store)
        pe.quarantine("skill", "qskill", "prior scan findings")

        result = self.invoke(["install", "qskill"])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("quarantined", result.output.lower())
        mock_install.assert_not_called()


# ---------------------------------------------------------------------------
# F-0421 — owner-writable binaries under default prefixes are untrusted
# ---------------------------------------------------------------------------


class TestF0421OwnerWritableTrustedBinary(unittest.TestCase):
    def setUp(self):
        # realpath() up front so macOS's /var -> /private/var symlink does
        # not desync the resolved binary path from the abspath'd prefix.
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="dclaw-f0421-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_user_owned_binary(self):
        bin_dir = os.path.join(self.tmp, "bin")
        os.makedirs(bin_dir)
        binary = os.path.join(bin_dir, "codex")
        with open(binary, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(binary, 0o755)
        os.chmod(bin_dir, 0o755)
        return bin_dir, binary

    def test_default_prefix_owner_writable_binary_rejected(self):
        bin_dir, binary = self._make_user_owned_binary()
        if os.stat(binary).st_uid == 0:
            self.skipTest("test runner is root; owner-write ownership check is moot")
        with patch.object(ad, "_TRUSTED_BIN_PREFIXES_DEFAULT", (bin_dir,)):
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("DEFENSECLAW_TRUSTED_BIN_PREFIXES", None)
                # A user-owned, owner-writable binary under a *default*
                # trusted prefix is swappable by a non-root principal.
                self.assertFalse(ad._is_trusted_binary_path(binary))

    @unittest.skipIf(
        os.name == "nt", "POSIX owner-writable executable trust; Windows DACL admission has dedicated coverage"
    )
    def test_operator_opt_in_prefix_still_trusts_binary(self):
        bin_dir, binary = self._make_user_owned_binary()
        with patch.object(ad, "_builtin_trusted_bin_prefixes", return_value=()):
            with patch.dict(
                os.environ,
                {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": bin_dir},
                clear=False,
            ):
                # Explicit operator opt-in keeps the looser checks.
                self.assertTrue(ad._is_trusted_binary_path(binary))


# ---------------------------------------------------------------------------
# F-0544 / F-0546 — openshell sandbox policy hardening
# ---------------------------------------------------------------------------


class TestOpenShellPolicyHardening(unittest.TestCase):
    def _openshell_dir(self):
        return os.path.join(
            os.path.dirname(defenseclaw.__file__), "_data", "policies", "openshell"
        )

    def test_f0544_hostless_allowed_ips_requires_host_membership(self):
        rego = os.path.join(self._openshell_dir(), "default.rego")
        with open(rego, encoding="utf-8") as f:
            text = f.read()
        # The fixed hostless branch must consult the connection host against
        # allowed_ips rather than matching on the port alone.
        self.assertIn("_host_in_allowed_ips", text)
        self.assertIn("_host_in_allowed_ips(allowed, network.host)", text)

    def test_f0546_messaging_egress_not_wildcard(self):
        import yaml

        data_path = os.path.join(self._openshell_dir(), "default-data.yaml")
        with open(data_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        channels = data["network_policies"]["allow_channels"]
        bin_paths = [b["path"] for b in channels["binaries"]]
        # The universal `/**` grant is the vulnerability and must be gone.
        self.assertNotIn("/**", bin_paths)
        self.assertTrue(bin_paths, "allow_channels must still scope some binaries")
        # All remaining grants must be specific runtime binaries, not a
        # bare match-everything wildcard.
        for path in bin_paths:
            self.assertTrue(path.endswith(("/node", "/openclaw", "/claude", "/codex")))


# ---------------------------------------------------------------------------
# F-0641 — Codex TOML parsing degrades gracefully without stdlib tomllib
# ---------------------------------------------------------------------------


class TestF0641TomllibFallback(unittest.TestCase):
    _CONFIG = (
        '[tools.audit]\n'
        'name = "Audit Tool"\n'
        'description = "scans things"\n'
    )

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="f0641-")
        self.addCleanup(shutil.rmtree, self._dir, ignore_errors=True)
        self.path = os.path.join(self._dir, "config.toml")
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(self._CONFIG)

    def test_parses_with_stdlib_tomllib(self):
        rows = _tools_from_codex_config(self.path)
        self.assertEqual([r["id"] for r in rows], ["audit"])
        self.assertEqual(rows[0]["name"], "Audit Tool")

    def test_falls_back_to_tomli_when_tomllib_missing(self):
        # On Python 3.10 ``tomllib`` is absent. The pre-fix code only tried
        # ``import tomllib`` and silently dropped every Codex tool definition.
        # Simulate the 3.10 environment by forcing that import to fail and
        # confirm the tomli backport still yields the parsed tools.
        try:
            import tomllib as fallback_parser
        except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
            import tomli as fallback_parser

        real_import = builtins.__import__

        def _no_tomllib(name, *args, **kwargs):
            if name == "tomllib":
                raise ModuleNotFoundError("No module named 'tomllib'")
            return real_import(name, *args, **kwargs)

        with (
            patch.dict(sys.modules, {"tomli": fallback_parser}),
            patch("builtins.__import__", side_effect=_no_tomllib),
        ):
            rows = _tools_from_codex_config(self.path)
        self.assertEqual([r["id"] for r in rows], ["audit"])
        self.assertEqual(rows[0]["name"], "Audit Tool")


if __name__ == "__main__":
    unittest.main()
