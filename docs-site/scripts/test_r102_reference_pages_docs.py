"""Regression checks for the 1.0.2 reference and sandbox pages."""

import re
import unittest
from pathlib import Path


DOCS = Path(__file__).resolve().parents[1] / "content/docs"


def page(name: str) -> str:
    return (DOCS / name).read_text()


def deprecated_harness_rows(text: str) -> None:
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        if not re.search(r"OpenHands|OmniGent", line, re.IGNORECASE):
            continue
        if re.search(r"verified|supported", line, re.IGNORECASE):
            assert "deprecated" in line.lower(), line


class R102ReferencePagesDocsTest(unittest.TestCase):
    def test_gap_0038_write_proof_names_child_program_limit_without_recipes(self):
        text = page("guardrail/index.mdx")
        self.assertIn("### Protected-file write proof", text)
        section = text.split("### Protected-file write proof", 1)[1].split(
            "## Common follow-ups", 1
        )[0]
        self.assertIn("child programs write", section)
        normalized = " ".join(section.split())
        self.assertIn(
            "A write inside a script, interpreter or shell built-in that the command only names "
            "cannot be fully checked from the command text", normalized
        )
        self.assertIn(
            "A rule that needs the complete action cannot block that inner write; "
            "an eligible rule about the complete outer argument list can still block the call "
            "in action mode", normalized
        )
        self.assertNotIn("reported as partly checked", normalized)
        self.assertIn("use a sandbox or file permissions", section)
        for forbidden in (
            "xargs", "find -exec", "make", "git", "source", "ln -s",
            "symlink", "authorized_keys",
        ):
            self.assertNotIn(forbidden, section.lower())

    def test_gap_0296_manifest_is_in_pinned_digest(self):
        text = page("policies/rulepack-validation.mdx")
        self.assertIn("pinned digest also covers the", text)
        self.assertNotIn("pinned digest does not cover the", text)

    def test_gap_0346_allow_rule_marks_example_values(self):
        text = page("policies/admission.mdx")
        self.assertIn("Replace the skill name and path with your reviewed asset", text)
        self.assertIn("use your own account paths", text)

    def test_gap_0297_managed_windows_tool_names_are_exact(self):
        text = " ".join(page("policies/admission.mdx").split())
        self.assertIn("Claude Code reports `Bash` for shell calls, `Read` for file reads, and `Skill` for skill calls", text)
        self.assertIn("Codex reports `Bash` for shell commands and `apply_patch` for file edits", text)
        self.assertIn("Codex has no `Read` or `Skill` tool name", text)
        self.assertIn("Write these exact names, including capitals", text)
        self.assertNotIn("the Claude Code and Codex hooks receive the native tool names", text)

    def test_gap_0300_mcp_scan_verdict_survives_runtime_toggle(self):
        text = page("policies/admission.mdx")
        self.assertIn("scan verdict still refuses MCP calls", text)
        self.assertIn("runtime_detection.enabled` is `false`", text)

    def test_gap_0301_claude_skill_call_checks_each_copy_path(self):
        text = " ".join(page("policies/admission.mdx").split())
        self.assertIn("judges each copy at its own path", text)
        self.assertIn("a matching deny on any copy blocks the call", text)
        self.assertIn("a pin to a copy the caller does not have matches nothing", text)
        for false_claim in (
            "carries no skill path",
            "cannot match that call",
            "Deny the skill by name without a path pin",
        ):
            self.assertNotIn(false_claim, text)

    def test_gap_0352_high_rule_alerts_and_requires_complete_argv(self):
        text = page("policies/rules.mdx")
        self.assertIn("this `HIGH` rule alerts; `CRITICAL` is the", text)
        self.assertIn("enforcement needs the complete argument list", text)

    def test_gap_0314_equal_custom_policy_can_fold_to_preset(self):
        text = page("reference/migrate-v9.mdx")
        self.assertIn("does not retain an activated custom policy's name", text)
        self.assertIn("`policy list` can show the preset as active", text)

    def test_gap_0309_failed_group_lookup_can_match_verified_identity(self):
        text = page("guardrail/user-and-group-policies.mdx")
        self.assertIn("A verified UID, SID or agent", text)
        self.assertNotIn("a failed lookup always lands on the default profile", text)

    def test_gap_0311_latest_v8_source_refreshes_backup(self):
        text = page("get-started/upgrade.mdx")
        self.assertIn("refreshed with that run's latest v8 source", text)
        self.assertNotIn("`config.yaml.v8.bak` is written once", text)

    def test_gap_0312_unreadable_scanner_policy_stops_migration(self):
        text = page("reference/migrate-v9.mdx")
        self.assertIn("If the file cannot be read, migration stops", text)
        self.assertNotIn("A file that cannot be read becomes `quiet`", text)

    def test_gap_0299_legacy_install_requires_vacant_data_home(self):
        text = page("reference/migrate-v9.mdx")
        self.assertIn("0.8.x installer refuses a data home that is still there", text)
        self.assertIn("Move the kept data home out of the install location", text)

    def test_gap_0349_ide_inventory_counts_four_ai_plugins(self):
        text = page("ai-discovery.mdx")
        self.assertIn("7 plugin(s) shown; 7 in total, 4 AI", text)
        self.assertNotIn("7 plugin(s) shown; 7 in total, 3 AI", text)

    def test_row_37_deprecated_harnesses_have_no_resume_recipe(self):
        reference = page("reference/sandbox-cli.mdx")
        guide = page("sandboxes/guide.mdx")
        self.assertIn("OpenHands and OmniGent are deprecated", reference)
        self.assertNotIn("| OpenHands | `defenseclaw sandbox connect", reference)
        self.assertNotIn("OmniGent | `defenseclaw sandbox connect", reference)
        deprecated_harness_rows(reference)
        deprecated_harness_rows(guide)

    def test_gap_0064_guide_marks_both_harnesses_deprecated(self):
        guide = page("sandboxes/guide.mdx")
        reference = page("reference/sandbox-cli.mdx")
        self.assertRegex(guide, r"\| OpenHands \| `openhands` \| user \| Deprecated\. \|")
        self.assertRegex(guide, r"\| OmniGent \| `omnigent` \| managed \| Deprecated\. \|")
        deprecated_harness_rows(guide)
        deprecated_harness_rows(reference)

    def test_gap_0320_opencode_does_not_offer_user_removal_of_managed_hook(self):
        text = page("connectors/opencode.mdx")
        self.assertIn("hook-removal silence check is unavailable", text)
        self.assertIn("positive check is untested", text)
        self.assertNotIn("<name> -- rm <file>", text)

    def test_gap_0318_claude_fresh_home_notice_is_expected(self):
        text = page("sandboxes/guide.mdx")
        self.assertIn("fresh sandbox home may", text)
        self.assertIn("model-launch notice again", text)

    def test_gap_0350_current_kernel_feed_line_has_text_fallback(self):
        text = page("reference/sandbox-cli.mdx")
        section = text.split("### `sandbox kernel-feed install`", 1)[1].split(
            "### `sandbox kernel-feed status`", 1
        )[0]
        self.assertIn("Current install output also says", section)
        self.assertIn("own hook calls in full until you stop and start it", section)


if __name__ == "__main__":
    unittest.main()
