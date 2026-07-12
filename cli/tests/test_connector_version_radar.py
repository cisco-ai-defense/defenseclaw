#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Hermetic tests for the connector release radar."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "connector-version-radar.py"
SPEC = importlib.util.spec_from_file_location("connector_version_radar", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
radar = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = radar
SPEC.loader.exec_module(radar)


class FakeCommandRunner:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, command, timeout):
        key = tuple(command)
        self.calls.append((key, timeout))
        if key not in self.responses:
            raise AssertionError(f"unexpected command: {key}")
        return self.responses[key]


class ConnectorVersionRadarTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.state = self.root / "machine-state.json"

    @staticmethod
    def _success(value):
        return radar.ExternalResult(True, stdout=value)

    def _runner(self, *, codex_installed="codex-cli 0.142.5", codex_latest='"0.144.1"'):
        return FakeCommandRunner(
            {
                ("codex", "--version"): self._success(codex_installed),
                ("npm", "view", "@openai/codex", "dist-tags.latest", "--json"): self._success(
                    codex_latest
                ),
                ("claude", "--version"): self._success("2.1.207 (Claude Code)"),
                (
                    "npm",
                    "view",
                    "@anthropic-ai/claude-code",
                    "dist-tags.latest",
                    "--json",
                ): self._success('"2.1.207"'),
                ("agy", "--version"): self._success("Antigravity CLI v1.1.1"),
            }
        )

    @staticmethod
    def _manifest_fetcher(url, timeout):
        if not url.endswith("/darwin_arm64.json"):
            raise AssertionError(f"unexpected release URL: {url}")
        if timeout <= 0:
            raise AssertionError("timeout must be positive")
        return radar.ExternalResult(True, stdout='{"version":"1.1.1","url":"ignored"}')

    def test_version_normalization_and_semver_ordering(self):
        self.assertEqual(radar.parse_version("codex-cli 0.144.1").normalized, "0.144.1")
        self.assertEqual(radar.parse_version("Claude Code v2.1.207+build.9").normalized, "2.1.207")
        prerelease = radar.parse_version("agy 1.2.0-rc.2")
        self.assertEqual(prerelease.normalized, "1.2.0-rc.2")
        self.assertLess(prerelease.compare(radar.parse_version("1.2.0")), 0)
        self.assertLess(
            radar.parse_version("1.2.0-rc.2").compare(radar.parse_version("1.2.0-rc.10")),
            0,
        )
        with self.assertRaisesRegex(ValueError, "stable channel returned prerelease"):
            radar.parse_version("1.2.0-beta.1", require_stable=True)

    def test_empty_state_seeds_installed_versions_but_requires_initial_tests(self):
        runner = self._runner()
        payload = radar.check_radar(
            state_path=self.state,
            command_runner=runner,
            url_fetcher=self._manifest_fetcher,
            antigravity_platform_name="darwin_arm64",
            now="2026-07-11T12:00:00Z",
        )

        self.assertEqual(payload["status"], "ok")
        self.assertEqual(
            [(item["connector"], item["candidate_version"]) for item in payload["candidates"]],
            [("codex", "0.144.1"), ("claudecode", "2.1.207"), ("antigravity", "1.1.1")],
        )
        self.assertTrue(payload["any_new"])
        self.assertEqual(payload["connectors"]["codex"]["status"], "update_available")
        self.assertEqual(payload["candidates"][0]["baseline_version"], "0.142.5")
        self.assertEqual(payload["connectors"]["claudecode"]["status"], "initial_test_required")
        self.assertEqual(payload["connectors"]["antigravity"]["status"], "initial_test_required")

        persisted = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(persisted["connectors"]["codex"]["installed_seed_version"], "0.142.5")
        self.assertNotIn("last_attempted_version", persisted["connectors"]["codex"])
        self.assertNotIn("last_passed_version", persisted["connectors"]["codex"])
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)

        commands = [call[0] for call in runner.calls]
        self.assertIn(("codex", "--version"), commands)
        self.assertIn(("npm", "view", "@openai/codex", "dist-tags.latest", "--json"), commands)
        self.assertFalse(any("install" in command for call in commands for command in call))

    def test_attempted_and_passed_releases_are_persisted_and_not_retested(self):
        runner = self._runner()
        radar.check_radar(
            state_path=self.state,
            connector_names=("codex",),
            command_runner=runner,
            antigravity_platform_name="darwin_arm64",
            now="2026-07-11T12:00:00Z",
        )
        radar.mark_state(
            state_path=self.state,
            connector="codex",
            version="v0.144.1",
            result="attempted",
            now="2026-07-11T12:05:00Z",
        )
        attempted = radar.check_radar(
            state_path=self.state,
            connector_names=("codex",),
            command_runner=runner,
            now="2026-07-12T12:00:00Z",
        )
        self.assertFalse(attempted["has_candidates"])
        self.assertEqual(attempted["connectors"]["codex"]["status"], "already_attempted")
        self.assertIsNone(attempted["connectors"]["codex"]["state"]["last_passed_version"])

        radar.mark_state(
            state_path=self.state,
            connector="codex",
            version="0.144.1",
            result="passed",
            now="2026-07-12T12:05:00Z",
        )
        passed = radar.check_radar(
            state_path=self.state,
            connector_names=("codex",),
            command_runner=runner,
            now="2026-07-13T12:00:00Z",
        )
        self.assertFalse(passed["has_candidates"])
        self.assertEqual(passed["connectors"]["codex"]["status"], "tested_passed")
        self.assertEqual(passed["connectors"]["codex"]["state"]["last_passed_version"], "0.144.1")

        forced = radar.check_radar(
            state_path=self.state,
            connector_names=("codex",),
            command_runner=runner,
            force=True,
            now="2026-07-14T12:00:00Z",
        )
        self.assertTrue(forced["any_new"])
        self.assertEqual(forced["connectors"]["codex"]["status"], "forced_test_required")
        self.assertEqual(
            forced["candidates"],
            [
                {
                    "connector": "codex",
                    "baseline_version": "0.144.1",
                    "installed_version": "0.142.5",
                    "candidate_version": "0.144.1",
                }
            ],
        )

    def test_last_passed_release_remains_baseline_after_global_cli_updates(self):
        initial_runner = self._runner()
        radar.check_radar(
            state_path=self.state,
            connector_names=("codex",),
            command_runner=initial_runner,
            now="2026-07-11T12:00:00Z",
        )
        radar.mark_state(
            state_path=self.state,
            connector="codex",
            version="0.142.5",
            result="passed",
            now="2026-07-11T12:05:00Z",
        )
        radar.mark_state(
            state_path=self.state,
            connector="codex",
            version="0.144.1",
            result="attempted",
            now="2026-07-11T12:06:00Z",
        )

        upgraded_runner = self._runner(
            codex_installed="codex-cli 0.144.1",
            codex_latest='"0.145.0"',
        )
        payload = radar.check_radar(
            state_path=self.state,
            connector_names=("codex",),
            command_runner=upgraded_runner,
            now="2026-07-12T12:00:00Z",
        )

        self.assertEqual(
            payload["candidates"],
            [
                {
                    "connector": "codex",
                    "baseline_version": "0.142.5",
                    "installed_version": "0.144.1",
                    "candidate_version": "0.145.0",
                }
            ],
        )

    def test_query_failures_are_infrastructure_errors_not_candidates(self):
        runner = FakeCommandRunner(
            {
                ("codex", "--version"): self._success("codex 0.144.0"),
                ("npm", "view", "@openai/codex", "dist-tags.latest", "--json"): self._success(
                    '"0.145.0-beta.1"'
                ),
                ("claude", "--version"): radar.ExternalResult(False, error="executable not found: claude"),
                (
                    "npm",
                    "view",
                    "@anthropic-ai/claude-code",
                    "dist-tags.latest",
                    "--json",
                ): self._success('"2.1.208"'),
                ("agy", "--version"): self._success("1.1.1"),
            }
        )

        payload = radar.check_radar(
            state_path=self.state,
            command_runner=runner,
            url_fetcher=lambda _url, _timeout: radar.ExternalResult(False, error="simulated timeout"),
            antigravity_platform_name="darwin_arm64",
            now="2026-07-11T12:00:00Z",
        )

        self.assertEqual(payload["status"], "infrastructure_error")
        self.assertFalse(payload["has_candidates"])
        self.assertEqual(
            {(item["connector"], item["stage"]) for item in payload["infrastructure_errors"]},
            {
                ("codex", "latest_query"),
                ("claudecode", "installed_probe"),
                ("antigravity", "latest_query"),
            },
        )
        self.assertTrue(all(item["status"] == "infrastructure_error" for item in payload["connectors"].values()))

    def test_structured_npm_output_cannot_select_an_unrelated_version(self):
        payload = radar.check_radar(
            state_path=self.state,
            connector_names=("codex",),
            command_runner=self._runner(codex_latest='{"npm":"10.9.2"}'),
            now="2026-07-11T12:00:00Z",
        )
        self.assertEqual(payload["status"], "infrastructure_error")
        self.assertFalse(payload["any_new"])
        self.assertIn(
            "dist-tags.latest did not return a JSON string",
            payload["infrastructure_errors"][0]["error"],
        )

    def test_fixture_mode_never_falls_through_to_commands_or_network(self):
        def unexpected_command(_command, _timeout):
            raise AssertionError("fixture mode executed a command")

        def unexpected_fetch(_url, _timeout):
            raise AssertionError("fixture mode used the network")

        payload = radar.check_radar(
            state_path=self.state,
            connector_names=("codex",),
            command_runner=unexpected_command,
            url_fetcher=unexpected_fetch,
            fixtures={"codex": {"installed": "0.143.0"}},
            now="2026-07-11T12:00:00Z",
        )

        self.assertEqual(payload["status"], "infrastructure_error")
        self.assertFalse(payload["has_candidates"])
        self.assertIn("fixture missing codex.latest", payload["infrastructure_errors"][0]["error"])

    def test_installed_version_ahead_of_stable_channel_is_not_downgraded(self):
        payload = radar.check_radar(
            state_path=self.state,
            connector_names=("codex",),
            command_runner=self._runner(codex_installed="0.145.0", codex_latest='"0.144.1"'),
            now="2026-07-11T12:00:00Z",
        )
        self.assertFalse(payload["has_candidates"])
        self.assertEqual(payload["connectors"]["codex"]["status"], "installed_ahead")

    def test_cli_fixture_emits_json_file_and_github_outputs(self):
        fixture = self.root / "fixture.json"
        output = self.root / "radar.json"
        github_output = self.root / "github-output.txt"
        fixture.write_text(
            json.dumps(
                {
                    "codex": {"installed": "codex-cli 0.142.5", "latest": '"0.144.1"'},
                    "claudecode": {"installed": "2.1.207", "latest": '"2.1.208"'},
                    "antigravity": {"installed": "1.1.1", "latest": '{"version":"1.1.2"}'},
                }
            ),
            encoding="utf-8",
        )
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = radar.main(
                [
                    "check",
                    "--state",
                    str(self.state),
                    "--fixture",
                    str(fixture),
                    "--output",
                    str(output),
                    "--github-output",
                    str(github_output),
                    "--antigravity-platform",
                    "darwin_arm64",
                ]
            )

        self.assertEqual(exit_code, radar.EXIT_OK)
        stdout_payload = json.loads(stdout.getvalue())
        self.assertEqual(stdout_payload, json.loads(output.read_text(encoding="utf-8")))
        github_values = dict(
            line.split("=", 1)
            for line in github_output.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(github_values["status"], "ok")
        self.assertEqual(github_values["any_new"], "true")
        self.assertEqual(github_values["has_candidates"], "true")
        self.assertEqual(
            json.loads(github_values["candidate_connectors"]),
            ["codex", "claudecode", "antigravity"],
        )
        self.assertEqual(len(json.loads(github_values["candidate_matrix"])["include"]), 3)
        self.assertEqual(json.loads(github_values["matrix"]), json.loads(github_values["candidate_matrix"]))
        self.assertEqual(
            set(json.loads(github_values["matrix"])["include"][0]),
            {"connector", "baseline_version", "installed_version", "candidate_version"},
        )
        self.assertEqual(json.loads(github_values["radar_json"]), stdout_payload)

    def test_cli_partial_infrastructure_error_preserves_candidate_outputs(self):
        fixture = self.root / "fixture.json"
        github_output = self.root / "github-output.txt"
        fixture.write_text(
            json.dumps(
                {
                    "codex": {"installed": "codex-cli 0.142.5", "latest": '"0.144.1"'},
                    "claudecode": {"installed": "2.1.207", "latest": {"error": "simulated timeout"}},
                }
            ),
            encoding="utf-8",
        )
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = radar.main(
                [
                    "check",
                    "--state",
                    str(self.state),
                    "--fixture",
                    str(fixture),
                    "--github-output",
                    str(github_output),
                    "--connector",
                    "codex",
                    "--connector",
                    "claudecode",
                ]
            )

        self.assertEqual(exit_code, radar.EXIT_OK)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "infrastructure_error")
        self.assertTrue(payload["has_candidates"])
        self.assertEqual(payload["candidates"][0]["connector"], "codex")
        self.assertEqual(payload["infrastructure_errors"][0]["connector"], "claudecode")

        github_values = dict(
            line.split("=", 1)
            for line in github_output.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(github_values["status"], "infrastructure_error")
        self.assertEqual(github_values["any_new"], "true")
        self.assertEqual(json.loads(github_values["matrix"])["include"][0]["connector"], "codex")

    def test_corrupt_state_returns_distinct_infrastructure_exit(self):
        self.state.write_text("not-json", encoding="utf-8")
        fixture = self.root / "fixture.json"
        fixture.write_text(json.dumps({"codex": {"installed": "0.1.0", "latest": "0.1.1"}}), encoding="utf-8")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = radar.main(
                [
                    "check",
                    "--state",
                    str(self.state),
                    "--fixture",
                    str(fixture),
                    "--connector",
                    "codex",
                ]
            )
        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, radar.EXIT_INFRASTRUCTURE_ERROR)
        self.assertEqual(payload["status"], "infrastructure_error")
        self.assertFalse(payload["has_candidates"])
        self.assertIn("not valid JSON", payload["infrastructure_errors"][0]["error"])


if __name__ == "__main__":
    unittest.main()
