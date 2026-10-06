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

from click.testing import CliRunner
from defenseclaw.commands.cmd_policy import _admission_triple
from defenseclaw.commands.cmd_skill import skill
from defenseclaw.enforce.admission import (
    _matches_provenance,
    compile_admission,
    evaluate_admission,
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

# ---------------------------------------------------------------------------
# F-0241 — runtime vocabulary mapping
# ---------------------------------------------------------------------------


class TestF0241RuntimeVocabulary(unittest.TestCase):
    def test_block_and_disable_runtime_stay_blocking(self):
        # A policy may spell a runtime block either way; both must activate
        # as runtime disable, never as an allow.
        for runtime in ("block", "disable", "  BLOCK "):
            self.assertEqual(_admission_triple({"runtime": runtime})["runtime"], "disable")
        for runtime in ("enable", "allow", "something-else"):
            self.assertEqual(_admission_triple({"runtime": runtime})["runtime"], "enable")


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


# ---------------------------------------------------------------------------
# F-0541 — built-in first-party plugin provenance is tightened
# ---------------------------------------------------------------------------


class TestF0541TightenedFirstPartyProvenance(unittest.TestCase):
    def setUp(self):
        self.constraints = compile_admission(None, "plugin").first_party_allow["defenseclaw"]

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
        decision = evaluate_admission(
            pe,
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
        decision = evaluate_admission(
            pe,
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

    def test_amp_policy_plugin_marker_is_exact_and_home_anchored(self):
        marker = ".config/amp/plugins/defenseclaw.ts"
        self.assertIn(marker, self.constraints)
        with tempfile.TemporaryDirectory(prefix="dclaw-amp-home-") as home:
            with patch.dict(
                os.environ,
                {"HOME": home, "USERPROFILE": home},
            ):
                self.assertTrue(
                    _matches_provenance(
                        self.constraints,
                        os.path.join(home, *marker.split("/")),
                    )
                )
                self.assertFalse(
                    _matches_provenance(
                        self.constraints,
                        os.path.join(
                            home,
                            "attacker",
                            *marker.split("/"),
                        ),
                    )
                )
                self.assertFalse(
                    _matches_provenance(
                        self.constraints,
                        os.path.join(
                            os.path.dirname(home),
                            "attacker",
                            *marker.split("/"),
                        ),
                    )
                )
        self.assertFalse(
            _matches_provenance(
                self.constraints,
                "/home/u/.config/amp/plugins/untrusted.ts",
            )
        )

    def test_evaluate_admission_scans_amp_marker_outside_resolved_home(self):
        pe = SimpleNamespace(
            is_blocked=lambda *a: False,
            is_allowed=lambda *a: False,
            is_quarantined=lambda *a: False,
        )
        with tempfile.TemporaryDirectory(prefix="dclaw-amp-home-") as home:
            with patch.dict(
                os.environ,
                {"HOME": home, "USERPROFILE": home},
            ):
                decision = evaluate_admission(
                    pe,
                    target_type="plugin",
                    name="defenseclaw",
                    source_path=os.path.join(
                        os.path.dirname(home),
                        "attacker",
                        ".config",
                        "amp",
                        "plugins",
                        "defenseclaw.ts",
                    ),
                )
        self.assertEqual(decision.verdict, "scan")
        self.assertEqual(decision.source, "scan-required")


# ---------------------------------------------------------------------------
# F-0401 — path-pinned allow fails closed on empty presented path
# ---------------------------------------------------------------------------


class TestF0401PathPinFailsClosed(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.pe = PolicyEngine(self.app.store, self.app.cfg)

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _pin(self):
        self.pe.allow("skill", "trusted", "vetted at a path", source_path="/opt/trusted/trusted")

    def test_empty_presented_path_does_not_skip_scan(self):
        # An empty presented path cannot prove it is the pinned asset.
        self._pin()
        d = evaluate_admission(self.pe, target_type="skill", name="trusted", source_path="")
        self.assertEqual(d.verdict, "scan")

    def test_lookalike_sibling_path_does_not_skip_scan(self):
        self._pin()
        d = evaluate_admission(self.pe, target_type="skill", name="trusted", source_path="/opt/trusted/trusted-evil")
        self.assertEqual(d.verdict, "scan")

    def test_matching_path_still_allows(self):
        self._pin()
        d = evaluate_admission(
            self.pe,
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
        enrich_with_policy(inv, self.store)
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
        enrich_with_policy(inv, self.store)
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
        enrich_with_policy(inv, self.store)
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
        enrich_with_policy(inv, self.store)
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

        pe = PolicyEngine(self.app.store, self.app.cfg)
        # Pinned to a DIFFERENT path than the one being scanned.
        pe.allow("skill", "demo", "vetted at a specific path", source_path="/opt/trusted/demo")

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

        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.allow("skill", "demo", "vetted", source_path=skill_dir)

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
        pe = PolicyEngine(self.app.store, self.app.cfg)
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
