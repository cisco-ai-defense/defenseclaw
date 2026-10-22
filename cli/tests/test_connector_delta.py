# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Offline regression cases for the small CI script; no clients or credentials."""

import copy
import io
import json
import os
import ssl
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts import connector_delta_monitor as m

SCHEMA = "codex-rs/hooks/schema/generated/pre-tool-use.command.input.schema.json"
PARENT = "a" * 40


def pr(number=1):
    return {
        "number": number,
        "merged_at": f"2026-10-18T12:00:{number:02}Z",
        "updated_at": "2026-10-19T00:00:00Z",
        "merge_commit_sha": format(number, "040x"),
        "base": {"ref": "main"},
    }


def schema(kind="string"):
    return json.dumps({"type": "object", "properties": {"tool_use_id": {"type": kind}}})


class Fake:
    def __init__(self, path=SCHEMA, before=None, after=None):
        self.before, self.after = before or schema(), after or schema("integer")
        self.rows = [{"filename": path, "status": "modified", "patch": "+hook contract changed"}]
        self.prs, self.issues, self.calls = [pr()], [], []

    def __call__(self, url, payload=None, **kwargs):
        self.calls.append((url, payload, kwargs))
        if "api.anthropic.com" in url:
            packet = json.loads(payload["messages"][0]["content"])
            item = packet["changes"][0]
            local = next(iter(packet["local"]))
            result = {
                "risk": "review",
                "summary": "Review applicability; no runtime break established.",
                "comparisons": [
                    {
                        "invariant": "payload",
                        "upstream_file": item["path"],
                        "upstream_quote": item["diff"][:100],
                        "local_file": local,
                        "local_quote": packet["local"][local][:100],
                        "assessment": "Review this consumer.",
                    }
                ],
            }
            return {"content": [{"type": "text", "text": json.dumps(result)}]}
        if "raw.githubusercontent.com" in url:
            return self.before if PARENT in url else self.after
        if "/commits/" in url:
            return {"parents": [{"sha": PARENT}]}
        if "/files?" in url:
            return self.rows
        if "/pulls?" in url:
            return self.prs
        if "/pulls/" in url:
            return next(row for row in self.prs if url.endswith("/" + str(row["number"])))
        if "/issues" in url:
            if payload is not None:
                self.issues.append({**payload, "user": {"login": "github-actions[bot]"}})
                return self.issues[-1]
            return copy.deepcopy(self.issues)
        raise AssertionError(url)


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.config = m.load(m.CONFIG)
        self.empty = {"schema_version": 1, "cursors": {}}

    def run_fake(self, fake, connector="codex", state=None, ai=False):
        config = {**self.config, "connectors": {connector: self.config["connectors"][connector]}}
        return m.analyze(config, m.ROOT, state or self.empty, fake, ai)

    def test_only_merged_main_prs_and_incremental_cursor(self):
        fake = Fake()
        fake.prs = [pr(2), pr(1), {**pr(3), "merged_at": None}, {**pr(4), "base": {"ref": "dev"}}]
        self.assertEqual([row["number"] for row in m.merged_prs(m.REPOS["codex"], fetch=fake)], [1, 2])
        bundle, report = self.run_fake(fake)
        self.assertEqual(len(report), 2)
        self.assertEqual(bundle["state"]["cursors"]["codex"]["number"], 2)
        again, report = self.run_fake(fake, state=bundle["state"])
        self.assertFalse(report)
        self.assertFalse(again["notices"])
        self.assertEqual(self.empty["cursors"], {})

    def test_initial_window_is_bounded_and_later_runs_drain_oldest_first(self):
        fake = Fake()
        fake.prs = [pr(i) for i in range(1, 45)]
        self.assertEqual([r["number"] for r in m.merged_prs(m.REPOS["codex"], fetch=fake)], list(range(25, 45)))
        self.assertEqual([r["number"] for r in m.merged_prs(m.REPOS["codex"], pr(2), fake)], list(range(3, 23)))

    def test_cursor_outside_inventory_window_fails_visibly(self):
        with self.assertRaises(ValueError):
            m.merged_prs(m.REPOS["codex"], pr(1), lambda _: [pr(2)] * 100)

    def test_payload_type_change_and_optional_field_control(self):
        for kind, expected in (
            ("integer", "static_conflict"),
            ("object", "static_conflict"),
            ("string", "review_required"),
        ):
            with self.subTest(kind=kind):
                fake = Fake(after=schema(kind))
                bundle, report = self.run_fake(fake)
                self.assertFalse(bundle["gaps"])
                self.assertEqual(report[0]["decision"], expected)
                urls = [row[0] for row in fake.calls]
                self.assertTrue(any(PARENT in url for url in urls))
                self.assertTrue(any(pr()["merge_commit_sha"] in url and "raw." in url for url in urls))

    def test_unknown_schema_ref_and_changed_local_type_are_not_proven(self):
        fake = Fake(after='{"properties":{"tool_use_id":{"$ref":"#/missing"}}}')
        self.assertEqual(self.run_fake(fake)[1][0]["decision"], "review_required")
        fake = Fake(after='{"type":"string","properties":{"tool_use_id":{"type":"integer"}}}')
        self.assertEqual(self.run_fake(fake)[1][0]["decision"], "review_required")
        spec = {**self.config["connectors"]["codex"], "name": "codex"}
        contract, context = m.local_context(spec, m.ROOT)
        context[spec["local_files"][0]] = 'ToolUseID int `json:"tool_use_id"`'
        self.assertEqual(
            m.conflicts([{"path": SCHEMA, "before": schema(), "after": schema("integer")}], contract, context, spec), []
        )

    def test_additions_deletions_and_renames_are_not_silently_safe(self):
        for status in ("added", "removed", "renamed"):
            fake = Fake(path="renamed.data")
            fake.rows[0].update(status=status, previous_filename="hooks/old.rs")
            bundle, report = self.run_fake(fake)
            with self.subTest(status=status):
                self.assertFalse(bundle["gaps"])
                self.assertEqual(report[0]["decision"], "review_required")
                raw_calls = [url for url, _, _ in fake.calls if "raw." in url]
                self.assertEqual(len(raw_calls), 1 if status != "renamed" else 2)

    def test_event_removal_is_review_not_a_compatibility_verdict(self):
        fake = Fake(
            "codex-rs/hooks/src/events.rs", "enum Event { PreToolUse, PostToolUse }", "enum Event { PostToolUse }"
        )
        self.assertEqual(self.run_fake(fake)[1][0]["decision"], "review_required")

    def test_edited_hook_references_outside_paths_but_not_unchanged_context(self):
        spec = self.config["connectors"]["codex"]
        row = {"filename": "core/unwatched.rs", "patch": " hook unchanged\n+unrelated"}
        self.assertFalse(m.relevant(row, spec))
        for patch_text in ("+run_hooks()", "-hook_state", "+register hook"):
            self.assertTrue(m.relevant({**row, "patch": patch_text}, spec))
        fake = Fake(path="README.md")
        fake.rows[0]["patch"] = "+spelling fix"
        self.assertEqual(self.run_fake(fake)[1][0]["decision"], "informational")

    def test_claude_exact_path_retirement_and_scoped_controls(self):
        line = "- Hooks are no longer read from `~/.claude/settings.json`."
        for statement, expected in (
            (line, "static_conflict"),
            ("- On Windows, managed " + line, "review_required"),
            ("- Fixed " + line, "review_required"),
        ):
            fake = Fake("CHANGELOG.md", "# Changelog\n", "# Changelog\n\n" + statement)
            with self.subTest(statement=statement):
                self.assertEqual(self.run_fake(fake, "claudecode")[1][0]["decision"], expected)
        fake = Fake("CHANGELOG.md", line, line + "\n- Hook documentation fix.")
        self.assertEqual(self.run_fake(fake, "claudecode")[1][0]["decision"], "review_required")

    def test_collection_failure_holds_failed_pr_but_retains_earlier_progress(self):
        fake = Fake()
        fake.prs = [pr(1), pr(2)]

        def fetch(url, *args, **kwargs):
            if "/commits/" + pr(2)["merge_commit_sha"] in url:
                raise ValueError("offline")
            return fake(url, *args, **kwargs)

        bundle, _ = self.run_fake(fetch)
        self.assertEqual(bundle["gaps"], ["codex"])
        self.assertEqual(bundle["state"]["cursors"]["codex"]["number"], 1)

    def test_file_inventory_truncation_is_a_gap(self):
        fake = Fake()
        fake.rows *= 100
        bundle, _ = self.run_fake(fake)
        self.assertEqual(bundle["gaps"], ["codex"])
        self.assertFalse(bundle["state"]["cursors"])

    def test_ai_quotes_are_checked_and_cannot_promote_a_break(self):
        fake = Fake(after=json.dumps({**json.loads(schema()), "additionalProperties": False}))
        with patch.dict(os.environ, {"CONNECTOR_DELTA_MODEL": "test-model"}):
            bundle, report = self.run_fake(fake, ai=True)
        self.assertFalse(bundle["gaps"])
        self.assertIn("ai_review", report[0])
        self.assertEqual(report[0]["decision"], "review_required")

        def forged(url, *args, **kwargs):
            result = fake(url, *args, **kwargs)
            if kwargs.get("ai"):
                review = json.loads(result["content"][0]["text"])
                review["comparisons"][0]["local_quote"] = "invented source"
                result["content"][0]["text"] = json.dumps(review)
            return result

        with patch.dict(os.environ, {"CONNECTOR_DELTA_MODEL": "test-model"}):
            bundle, _ = self.run_fake(forged, ai=True)
        self.assertTrue(bundle["gaps"])
        self.assertFalse(bundle["state"]["cursors"])

    def test_rejecting_emitted_deny_vs_retaining_it(self):
        path = self.config["connectors"]["codex"]["output_schemas"][0]

        def output(values):
            return json.dumps(
                {
                    "properties": {
                        "hookSpecificOutput": {"properties": {"permissionDecision": {"type": "string", "enum": values}}}
                    }
                }
            )

        for values, expected in ((["allow"], "static_conflict"), (["allow", "deny"], "review_required")):
            with self.subTest(values=values):
                fake = Fake(path, output(["allow", "deny"]), output(values))
                self.assertEqual(self.run_fake(fake)[1][0]["decision"], expected)

    def test_fenced_and_os_heading_retirements_remain_review(self):
        line = "- Hooks are no longer read from `~/.claude/settings.json`."
        for text in ("```\n" + line + "\n```", "~~~text\n" + line + "\n~~~", "## Windows\n" + line):
            with self.subTest(text=text):
                self.assertEqual(
                    self.run_fake(Fake("CHANGELOG.md", "# Changelog", text), "claudecode")[1][0]["decision"],
                    "review_required",
                )

    def test_disabled_unrelated_notices_and_failed_delivery_checkpoint(self):
        fake = Fake(path="README.md")
        fake.rows[0]["patch"] = "+spelling fix"
        bundle, _ = self.run_fake(fake)
        m.publish(bundle, self.config, "owner/repo", fake, enabled=True)
        self.assertFalse(fake.issues)
        bundle, _ = self.run_fake(Fake())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            m.save(root / "public/bundle.json", bundle)
            with (
                patch.dict(os.environ, {"CONNECTOR_DELTA_NOTIFICATIONS_ENABLED": "true"}),
                patch.object(m, "publish", side_effect=ValueError("offline")),
            ):
                self.assertEqual(m.main(["publish", "--output", directory]), 2)
            self.assertFalse((root / "checkpoint/state.json").exists())

    def test_public_notice_omits_conflict_evidence_and_model_output(self):
        bundle, report = self.run_fake(Fake())
        self.assertEqual(report[0]["decision"], "static_conflict")
        self.assertTrue(report[0]["conflicts"])
        text = json.dumps(bundle)
        for private in ("static_conflict", "suspected_conflict", "ai_review", "conflicts", "tool_use_id"):
            self.assertNotIn(private, text)
        self.assertEqual(bundle["notices"][0]["kind"], "upstream_change")
        self.assertEqual(bundle["notices"][0]["number"], 1)
        self.assertEqual(bundle["notices"][0]["files"], [SCHEMA])

    def test_public_bundle_and_issue_do_not_depend_on_private_risk(self):
        bundles, issues = [], []
        for decision in ("review_required", "static_conflict", "suspected_conflict"):
            fake = Fake()
            proven = [{"reason": "PRIVATE-SENTINEL"}] if decision == "static_conflict" else []
            with (
                patch.object(m, "conflicts", return_value=proven),
                patch.object(m, "ai_review", return_value={"risk": decision, "summary": "PRIVATE-SENTINEL"}),
            ):
                bundle, report = self.run_fake(fake, ai=decision == "suspected_conflict")
            self.assertEqual(report[0]["decision"], decision)
            m.publish(bundle, self.config, "owner/repo", fake, enabled=True)
            bundles.append(bundle)
            issues.append(fake.issues)
            self.assertNotIn("PRIVATE-SENTINEL", json.dumps([bundle, fake.issues]))
        self.assertEqual(bundles[0], bundles[1])
        self.assertEqual(bundles[1], bundles[2])
        self.assertEqual(issues[0], issues[1])
        self.assertEqual(issues[1], issues[2])

    def test_cli_keeps_private_findings_local_and_owner_readable(self):
        bundle, report = self.run_fake(Fake())
        report[0]["evidence"] = "PRIVATE-SENTINEL"
        with tempfile.TemporaryDirectory() as directory:
            root, stdout = Path(directory), io.StringIO()
            with patch.object(m, "analyze", return_value=(bundle, report)), redirect_stdout(stdout):
                self.assertEqual(m.main(["analyze", "--output", directory]), 0)
            with patch.dict(os.environ, {"CONNECTOR_DELTA_NOTIFICATIONS_ENABLED": "false"}), redirect_stdout(stdout):
                self.assertEqual(m.main(["publish", "--output", directory]), 0)
            private = root / "private-report.json"
            self.assertIn("PRIVATE-SENTINEL", private.read_text())
            if os.name == "posix":
                self.assertEqual(private.stat().st_mode & 0o777, 0o600)
            public = stdout.getvalue() + "".join(path.read_text() for path in root.glob("public/*"))
            public += (root / "checkpoint/state.json").read_text()
            for value in ("PRIVATE-SENTINEL", "static_conflict", "conflicts"):
                self.assertNotIn(value, public)

    def test_publisher_rejects_legacy_and_private_fields_even_when_disabled(self):
        bundle, _ = self.run_fake(Fake())
        bad = []
        for location, key in (
            ((), "ai_review"),
            (("notices", 0), "decision"),
            (("state",), "findings"),
            (("state", "cursors", "codex"), "assessment"),
        ):
            item = copy.deepcopy(bundle)
            target = item
            for part in location:
                target = target[part]
            target[key] = "PRIVATE-SENTINEL"
            bad.append(item)
        bad.append({key: value for key, value in bundle.items() if key != "schema_version"})
        for item in bad:
            for enabled in (False, True):
                fake = Fake()
                with self.subTest(item=item, enabled=enabled), self.assertRaises(ValueError):
                    m.publish(item, self.config, "owner/repo", fake, enabled=enabled)
                self.assertFalse(fake.calls)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(m, "analyze", return_value=(bad[0], [])):
                self.assertEqual(m.main(["analyze", "--output", directory]), 2)
            self.assertFalse((Path(directory) / "public/bundle.json").exists())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            m.save(root / "public/bundle.json", bad[0])
            m.save(root / "checkpoint/state.json", self.empty)
            with patch.dict(os.environ, {"CONNECTOR_DELTA_NOTIFICATIONS_ENABLED": "false"}):
                self.assertEqual(m.main(["publish", "--output", directory]), 2)
            self.assertEqual(m.load(root / "checkpoint/state.json"), self.empty)

    def test_ai_suspicion_is_private_and_not_a_static_proof(self):
        fake = Fake(after=json.dumps({**json.loads(schema()), "additionalProperties": False}))

        def suspicious(url, *args, **kwargs):
            result = fake(url, *args, **kwargs)
            if kwargs.get("ai"):
                review = json.loads(result["content"][0]["text"])
                review["risk"] = "suspected_conflict"
                result["content"][0]["text"] = json.dumps(review)
            return result

        with patch.dict(os.environ, {"CONNECTOR_DELTA_MODEL": "test-model"}):
            bundle, report = self.run_fake(suspicious, ai=True)
        self.assertEqual(report[0]["decision"], "suspected_conflict")
        self.assertFalse(report[0]["conflicts"])
        self.assertNotIn("suspected_conflict", json.dumps(bundle))
        self.assertNotIn("ai_review", json.dumps(bundle))
        self.assertEqual(bundle["notices"][0]["kind"], "upstream_change")

    def test_optional_delivery_deduplicates_and_mentions_configured_contributors(self):
        fake = Fake(after=schema())
        bundle, _ = self.run_fake(fake)
        fake.calls.clear()
        m.publish(bundle, self.config, "owner/repo", fake)
        self.assertFalse(fake.calls)
        m.publish(bundle, self.config, "owner/repo", fake, enabled=True)
        m.publish(bundle, self.config, "owner/repo", fake, enabled=True)
        self.assertEqual(len(fake.issues), 1)
        for user in self.config["recipients"]:
            self.assertIn("@" + user, fake.issues[0]["body"])

    def test_replay_cannot_publish_and_corrupt_state_cannot_reset(self):
        bundle, _ = self.run_fake(Fake())
        with self.assertRaises(ValueError):
            m.publish({**bundle, "replay": True}, self.config, "owner/repo")
        for bad in ({}, {"schema_version": 0, "cursors": {}}, {"schema_version": 1, "cursors": []}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                m.analyze(self.config, m.ROOT, bad, Fake())
        state = copy.deepcopy(bundle["state"])
        state["cursors"]["codex"]["assessment"] = "PRIVATE-SENTINEL"
        fake = Fake()
        with self.assertRaises(ValueError):
            m.analyze(self.config, m.ROOT, state, fake)
        self.assertFalse(fake.calls)

    def test_strict_json_path_validation_and_redirect_refusal(self):
        for text in ('{"x":1,"x":2}', '{"x":NaN}'):
            with self.assertRaises(ValueError):
                m.decode(text)
        for path in ("../secret", "/etc/passwd", "hooks/../../secret"):
            self.assertFalse(m.path_ok(path))
        with self.assertRaises(ValueError):
            m.NoRedirect().redirect_request(None)
        with self.assertRaises(ValueError):
            m.request("https://attacker.example/secret")

    def test_tls13_and_github_token_never_sent_to_raw_host(self):
        context = ssl.create_default_context()
        with (
            patch.dict(
                os.environ,
                {
                    "GH_TOKEN": "test-only-placeholder",
                    "CONNECTOR_DELTA_ANTHROPIC_API_KEY": "test-only-ai-placeholder",
                },
            ),
            patch.object(m.ssl, "create_default_context", return_value=context),
            patch.object(m.urllib.request, "build_opener") as build,
        ):
            response = build.return_value.open.return_value.__enter__.return_value
            response.read.return_value = b"{}"
            m.request("https://api.github.com/repos/openai/codex")
            self.assertIn("Authorization", build.return_value.open.call_args.args[0].headers)
            m.request("https://raw.githubusercontent.com/openai/codex/" + PARENT + "/hooks.rs")
            self.assertNotIn("Authorization", build.return_value.open.call_args.args[0].headers)
            self.assertNotIn("X-api-key", build.return_value.open.call_args.args[0].headers)
            m.request("https://api.anthropic.com/v1/messages", {"messages": []}, ai=True)
            self.assertNotIn("Authorization", build.return_value.open.call_args.args[0].headers)
            self.assertIn("X-api-key", build.return_value.open.call_args.args[0].headers)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_cli_disabled_publisher_commits_only_public_checkpoint(self):
        bundle, _ = self.run_fake(Fake())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            m.save(root / "public/bundle.json", bundle)
            with (
                patch.dict(os.environ, {"CONNECTOR_DELTA_NOTIFICATIONS_ENABLED": "false"}),
                patch.object(m, "request", side_effect=AssertionError("network")),
            ):
                self.assertEqual(m.main(["publish", "--output", directory]), 0)
            self.assertEqual(m.load(root / "checkpoint/state.json"), bundle["state"])

    def test_workflow_is_main_only_and_never_uploads_private_report(self):
        workflow = (m.ROOT / ".github/workflows/connector-delta-monitor.yml").read_text()
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("ref: main", workflow)
        self.assertIn("path: monitor/public/bundle.json", workflow)
        self.assertNotIn("path: monitor/private-report.json", workflow)
        self.assertNotIn("issues: write", workflow.split("  publish:")[0])
        self.assertEqual(set(self.config["connectors"]), {"codex", "claudecode"})


if __name__ == "__main__":
    unittest.main()
