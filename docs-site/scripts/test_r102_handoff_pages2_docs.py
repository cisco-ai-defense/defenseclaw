"""Regression checks for round 1.0.2 handoff text on lane D pages."""

import unittest
from pathlib import Path


DOCS = Path(__file__).resolve().parents[1] / "content/docs"


def page(path):
    return (DOCS / path).read_text()


class R102HandoffPages2DocsTest(unittest.TestCase):
    def test_fg05_managed_agent_destination_notes(self):
        text = page("enterprise/sandboxes.mdx")
        self.assertIn("destinations refused, awaiting approval or declined", text)
        self.assertIn("only while the\norganization allows unblocks", text)

    def test_fg05_repository_refusal_names_policy(self):
        text = page("sandboxes/guide.mdx")
        self.assertIn("A refusal from the repository's\n`.defenseclaw/sandbox.yaml` names that policy", text)

    def test_fg05_activity_omits_deleted_by_default(self):
        guide = page("sandboxes/guide.mdx")
        reference = page("reference/sandbox-cli.mdx")
        self.assertIn("listing leaves out sandboxes deleted since the daemon", guide)
        self.assertIn("listing leaves out events\nof sandboxes deleted since the daemon started", reference)

    def test_fg05_policy_explain_default_new_run(self):
        enterprise = page("enterprise/sandboxes.mdx")
        reference = page("reference/sandbox-cli.mdx")
        self.assertIn("it explains a new\nrun of the default agent", enterprise)
        self.assertIn("describes a\nnew run of the default agent", reference)

    def test_fg05_approval_always_refused_under_floor(self):
        enterprise = page("enterprise/sandboxes.mdx")
        reference = page("reference/sandbox-cli.mdx")
        self.assertIn("With `allow_unblock: false`, the person can approve", enterprise)
        self.assertIn("`approve --always` is refused, even when `user_approvals` is\nunset", reference)

    def test_fg05_driver_switch_notice(self):
        text = page("enterprise/sandboxes.mdx")
        self.assertIn("your organization changed how sandboxes run on this computer", text)
        self.assertIn("This notice carries no exception\ncontact", text)

    def test_fg05_active_gauge_refresh(self):
        text = page("enterprise/sandboxes.mdx")
        self.assertIn("`defenseclaw.sandbox.active` is exported again every minute", text)
        self.assertIn("exports `0` for a connector whose sandboxes stopped", text)

    def test_fg05_session_unblock_expires_on_stop(self):
        guide = page("sandboxes/guide.mdx")
        reference = page("reference/sandbox-cli.mdx")
        self.assertIn("After a stop and start, or a connect of\na stopped sandbox", guide)
        self.assertIn("at the hook and egress proxy", reference)

    def test_fg05_upstream_telemetry_profile_floor(self):
        text = page("enterprise/sandboxes.mdx")
        self.assertIn("`allow_upstream_telemetry: false` has OpenShell's\nown telemetry off", text)
        self.assertIn("host's rendered `gateway.env`", text)

    def test_fg05_managed_policy_next_hook_call(self):
        text = page("enterprise/sandboxes.mdx")
        # DELTA-21 (GAP-0172) replaced "takes the changed policy on its next
        # relayed hook call": a running sandbox takes the change before its
        # next connection (test_r102_delta15_docs checks the full paragraph).
        self.assertIn("A running managed sandbox takes a changed live field before its next\nconnection", text)
        self.assertNotIn("changed policy on its next relayed hook\ncall", text)

    def test_lfuninst_running_sandbox_refuses_uninstall(self):
        text = page("sandboxes/guide.mdx")
        self.assertIn("A running sandbox stops\n`defenseclaw uninstall` before any change", text)
        self.assertIn("`--stop-sandboxes`\ninstead stops and deletes running sandboxes", text)

    def test_lfuninst_signed_out_gateway_files_restore(self):
        text = page("sandboxes/guide.mdx")
        self.assertIn("without a systemd user manager restores these files and finishes", text)
        self.assertIn("service loads them when it next starts", text)

    def test_fg01_failed_uninstall_teardown_keeps_receipt(self):
        text = page("sandboxes/guide.mdx")
        self.assertIn("without either flag so the data\ndirectory and gateway binary stay", text)
        self.assertIn("`defenseclaw-gateway sandbox teardown`, then uninstall again", text)

    def test_fg06_guide_uses_private_home_probe_directory(self):
        text = page("sandboxes/guide.mdx")
        self.assertIn("`~/Library/Caches/defenseclaw/hookfire` directory under your home", text)
        self.assertIn("Colima and OrbStack also\nrun containers in VMs", text)
        self.assertNotIn("Docker Desktop shares your temp directory", text)

    def test_fg06_image_build_reference_names_probe_directory(self):
        section = page("reference/sandbox-cli.mdx").split("### `sandbox image build`", 1)[1]
        self.assertIn("`~/Library/Caches/defenseclaw/hookfire`", section)
        self.assertIn("`sandbox image build <harness> --force` recheck command", section)

    def test_fg07_workload_python_shims(self):
        text = page("sandboxes/guide.mdx")
        self.assertIn("`python3`, `python` and `pip` using `/sandbox/.venv`", text)
        self.assertIn("hooks keep the system `/usr/bin/python3`", text)

    def test_fg07_full_disk_stop_keeps_copy(self):
        guide = page("sandboxes/guide.mdx")
        reference = page("reference/sandbox-cli.mdx")
        self.assertIn("even with `--yes` (exit `5`)", guide)
        self.assertIn("full disk keeps running if its copy holds work not\nyet pulled", reference)
        self.assertIn("If its disk does not answer\nwithin 15 seconds", reference)

    def test_fg07_connect_replays_known_option_values(self):
        guide = " ".join(page("sandboxes/guide.mdx").split())
        self.assertIn("known options with their values for Claude Code, Codex, OpenCode, Copilot CLI and Hermes", guide)
        self.assertIn("For other harnesses, or an option whose value is optional, attach the value", guide)
        self.assertIn("OpenCode `--prompt`, Codex `-i`/`--image`", guide)
        self.assertIn("Copilot CLI `-i`/`--interactive` and `--attachment`", guide)
        self.assertIn("Hermes `-z`/`--oneshot` and `--image`", guide)
        self.assertIn("apply to the run only", guide)
        self.assertIn("passes `--append-system-prompt` with `be brief` and `--model` with `sonnet`", guide)
        self.assertNotIn("with a space ends the record", guide)
        self.assertNotIn("passes that option without the word", guide)

    def test_pr886_remote_scanner_empty_rules_use_connection_policy(self):
        text = page("guardrail/index.mdx")
        self.assertIn("an unset or empty\n`cisco_ai_defense.enabled_rules` sends no", text)
        self.assertIn("A nonempty operator list is sent in\nthe order configured", text)
        self.assertIn("former implicit 12-rule list", text)

    def test_fg02_relative_scanner_policy_path(self):
        row = next(line for line in page("reference/migrate-v9.mdx").splitlines()
                   if line.startswith("| `policy: <path to a file>` |"))
        self.assertIn("including a file named `custom`", row)
        self.assertIn("pinned by its absolute path", row)
        self.assertNotIn("becomes `quiet`", row)

    def test_fg02_duplicate_custom_providers_merge(self):
        section = page("reference/migrate-v9.mdx").split("### Custom providers", 1)[1]
        self.assertIn("lists are unioned and the overlay's\nvalues win", section)
        self.assertIn("`migration-v9.json` notes each merged provider", section)

    def test_fg01_rollback_restores_data_and_prunes_hooks(self):
        text = page("get-started/upgrade.mdx")
        self.assertIn("comes back when you run `defenseclaw rollback`\nagain", text)
        self.assertIn("on every `defenseclaw upgrade`, DefenseClaw removes only\nits own hook entries", text)

    def test_macos_protected_folder_skip_is_partial(self):
        discovery = " ".join(page("ai-discovery.mdx").split())
        macos = " ".join(page("enterprise/macos.mdx").split())
        self.assertNotIn("a root reached through a link into a protected folder is skipped", discovery)
        self.assertNotIn("a package scan root reached through a link into one of them is skipped too", discovery)
        self.assertNotIn("A package scan root reached through a link into one of these folders is skipped too", macos)
        self.assertIn("`detector_errors.macos_privacy`", macos)
        self.assertIn("protected folders were not scanned", macos)
        self.assertNotIn("`detector_errors.macos_privacy` naming the skipped protected folders", macos)
        self.assertNotIn("the scan stays complete", macos)

    def test_fg04a_windows_plugin_refusal_is_structured(self):
        section = page("enterprise/windows.mdx").split("- Claude Code runs a plugin", 1)[1].split("- MCP servers", 1)[0]
        self.assertIn("ASSET-POLICY reason_code=admin-deny", section)
        self.assertNotIn("reason_code=install-block", section)
        self.assertNotIn("the refusal\n  says `plugin", section)

    def test_fg04a_sandbox_image_action_mode_cross_link(self):
        text = page("sandboxes/guide.mdx")
        self.assertIn("For action mode on a host without the agent installed", text)
        self.assertIn("[connector compatibility guide](/docs/connectors/compatibility)", text)

    def test_lfwin_guardian_first_reconcile_wait(self):
        text = page("enterprise/troubleshooting.mdx")
        self.assertIn("Setup waits up to 10 minutes for the guardian's first reconcile", text)
        self.assertIn("hook_guardian_startup.json", text)
        self.assertIn("no longer running during its first reconcile", text)

    def test_fg12_uninstall_incomplete_code(self):
        text = page("enterprise/troubleshooting.mdx")
        self.assertIn("| `uninstall_incomplete` |", text)
        self.assertIn("started the services again", text)

    def test_fg12_linux_package_removal_keeps_files(self):
        text = page("enterprise/linux.mdx")
        self.assertIn("apt or dnf fails and keeps the package files", text)
        self.assertIn("`uninstall_incomplete`", text)

    def test_fg12_doctor_prints_pinned_driver_digest(self):
        section = page("enterprise/sandboxes.mdx").split("### Recipe: prerequisite mode", 1)[1]
        self.assertIn("install command with the SHA-256 digest this DefenseClaw build pins", section)
        self.assertNotIn("and its `.sha256` file", section)

    def test_fg11_machine_policy_summary_missing(self):
        self.assertIn("| `machine_policy_summary_missing` | Windows |", page("enterprise/troubleshooting.mdx"))

    def test_fg11_stopped_service_verify_is_not_ready(self):
        row = next(line for line in page("enterprise/troubleshooting.mdx").splitlines()
                   if line.startswith("| `not_ready` | Windows |"))
        self.assertIn("`verify` also reports it", row)

    def test_fg11_rule_pack_preflight_grant(self):
        row = next(line for line in page("enterprise/troubleshooting.mdx").splitlines()
                   if line.startswith("| `rule_pack_unreadable` | Windows |"))
        self.assertIn("Setup's config preflight", row)
        self.assertIn("service's derived SID", row)

    def test_fg11_scanner_trust_and_judge(self):
        text = page("enterprise/troubleshooting.mdx")
        self.assertIn("folder or executable is writable by a non-administrator", text)
        self.assertIn("| `scanner_judge_missing` | Windows |", text)
        self.assertIn("`Scanners:` shows `judge none`", text)

    def test_fg11_secret_remove_requires_readable_config(self):
        text = page("enterprise/configuration.mdx")
        self.assertIn("refuses when it cannot read the installed config", text)

    def test_fg11_setup_upgrade_file_held(self):
        text = page("enterprise/troubleshooting.mdx")
        self.assertIn("Setup upgrade says another program holds a file open", text)

    def test_fg08_update_keeps_running_sessions_enforced(self):
        section = page("enterprise/tetragon.mdx").split(
            "5. **Restart agent sessions after enforce starts.**", 1
        )[1].split("The controls compile", 1)[0]
        self.assertIn("old controls policy\n   stays loaded and enforcing", section)
        self.assertNotIn("A planned follow-up", section)

    def test_fg08_predate_troubleshooting_excludes_self_update(self):
        tetragon = page("enterprise/tetragon.mdx")
        table = page("enterprise/troubleshooting.mdx")
        self.assertIn("enforce turned on or Tetragon restarted", tetragon)
        row = next(line for line in table.splitlines() if line.startswith("| `kernel_sessions_predate_controls`"))
        self.assertIn("old controls policy enforcing", row)
        self.assertNotIn("after an agent's own update", row)

    def test_fg08_limit_keeps_old_controls(self):
        section = page("enterprise/tetragon.mdx").split("## Reference", 1)[1]
        self.assertIn("old controls policy enforcing", section)
        self.assertNotIn("A planned follow-up", section)

    def test_fg08_lifecycle_retains_old_policy(self):
        row = next(line for line in page("enterprise/tetragon.mdx").splitlines()
                   if line.startswith("| An agent updates itself |"))
        self.assertIn("removed when the last one exits", row)
        self.assertNotIn("A planned follow-up", row)

    def test_fg13_entra_planning_and_local_group_guards(self):
        text = page("enterprise/identity-entra-id.mdx")
        self.assertIn("A Microsoft Graph read failure stops the plan", text)
        self.assertIn("planned groups without regard to letter case", text)
        self.assertIn("refuses existing\ndynamic or mail-enabled groups", text)
        self.assertIn("whose SID differs from the local\ngroup with the same short name", text)
        self.assertNotIn("leaves the others alone", text)


if __name__ == "__main__":
    unittest.main()
