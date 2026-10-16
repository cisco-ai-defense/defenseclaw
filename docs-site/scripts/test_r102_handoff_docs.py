"""Regression checks for 1.0.2 documentation handoffs."""

import unittest
from pathlib import Path


DOCS = Path(__file__).resolve().parents[1] / "content/docs"


def page(name: str) -> str:
    return (DOCS / name).read_text()


class R102HandoffDocsTest(unittest.TestCase):
    def test_fg01_absent_connector_cleanup(self):
        text = page("reference/cli.mdx")
        self.assertIn("the command removes DefenseClaw hook entries it left", text)
        self.assertNotIn("Remove one connector from the active roster; the gateway restart tears down its hooks. Removing", text)

    def test_fg01_doctor_orphaned_hooks_and_otlp(self):
        text = page("reference/cli.mdx")
        self.assertIn("| Orphaned hook entries [connector] | FAIL or WARN |", text)
        self.assertIn("| Native OTLP credentials | WARN | An agent can keep an old credential after an upgrade, rollback", text)

    def test_fg01_uninstall_teardown_receipt(self):
        text = page("get-started/install.mdx")
        self.assertIn("to keep the data needed for later teardown", text)
        self.assertNotIn("When Docker or OpenShell is gone\nor broken, add", text)

    def test_fg01_installer_local_requires_directory(self):
        text = page("get-started/install.mdx")
        self.assertIn("require a nonempty directory argument", text)
        self.assertIn("usage error (exit `2`)", text)

    def test_fg01_legacy_sigstore_cache(self):
        text = page("get-started/install.mdx")
        self.assertIn("`~/.sigstore` only when the 0.8.x installer's cache is still untouched", text)

    def test_fg04b_creator_first_party_pin(self):
        text = page("policies/creator.mdx")
        self.assertIn("with an exact asset name and at least one `source_path_contains`", text)
        self.assertNotIn("Two cards: first-party plugins", text)

    def test_fg04b_creator_mode_aware_live_test(self):
        text = page("policies/creator.mdx")
        self.assertIn("Observe mode reports\n`alert` for the bundled CRITICAL", text)
        self.assertIn("`input.thresholds` and `input.mode`", text)

    def test_fg04b_creator_keep_host_mode(self):
        text = page("policies/creator.mdx")
        self.assertIn("Playground's **keep host mode** choice omits `guardrail.mode`", text)
        self.assertNotIn("Activation copies the mode, levels, and trust level", text)

    def test_fg05_active_metric_refresh(self):
        text = page("observability/sandbox-telemetry.mdx")
        self.assertIn("Exported every minute, including `0`", text)
        self.assertIn("a running sandbox counts again within a minute", text)

    def test_fg06_macos_probe_file_sharing(self):
        text = page("sandboxes/macos.mdx")
        self.assertIn("/Users/alice/Library/Caches/defenseclaw/hookfire is shared", text)
        self.assertIn("which those engines share with their container VM by default", text)
        self.assertNotIn("/var/folders/…/T is shared", text)

    def test_fg07_macos_overlay_warning(self):
        text = page("sandboxes/macos.mdx")
        self.assertIn("warns once when its overlay disk reaches\n90% use", text)

    def test_fg07_macos_app_stop_full_disk(self):
        text = page("macos-app.mdx")
        self.assertIn("full-disk MicroVM with work not yet\n    pulled keeps running", text)

    def test_fg09_splunk_distinct_activity(self):
        text = page("observability/splunk.mdx")
        self.assertIn("each host, finding ID and tactic\nonce", text)
        self.assertIn("Records with no finding ID are counted\nseparately", text)
        self.assertNotIn("They show the same things as the Grafana", text)

    def test_fg11_windows_secret_remove_checks_config(self):
        text = page("enterprise/ai-defense-key.mdx")
        self.assertIn("If it cannot read that config, it refuses", text)
        self.assertIn("leaves the credential in place", text)

    def test_fg12_package_uninstall_refusal(self):
        text = page("enterprise/lifecycle.mdx")
        self.assertIn("`uninstall_incomplete` keeps the package files", text)

    def test_fg12_duplicate_rpm_repair(self):
        text = page("enterprise/lifecycle.mdx")
        self.assertIn("`sudo dnf remove --duplicates defenseclaw-enterprise`", text)
        self.assertIn("does not\n  repair the package database", text)

    def test_fg12_infopipe_upn_expiry(self):
        text = page("enterprise/identity-sources.mdx")
        self.assertIn("kept for at most 24 hours (`upn_source: infopipe_kept`)", text)

    def test_fg12_local_groups_follow_nsswitch(self):
        text = page("enterprise/identity-sources.mdx")
        self.assertIn("only when `nsswitch.conf` lists `files` or `compat`", text)

    def test_fg13_intune_rollback_assignment(self):
        text = page("enterprise/lifecycle.mdx")
        self.assertIn("remove the superseding **Required** assignment", text)

    def test_fg13_mdm_config_and_result_codes(self):
        text = page("enterprise/mdm/index.mdx")
        self.assertIn("Intune Win32 packager requires a supplied `config_version: 9`", text)
        self.assertIn("| `mdm_staging_full` |", text)
        self.assertIn("| `mdm_cancelled` |", text)

    def test_fg13_other_windows_packagers_require_v9(self):
        self.assertIn("Your administrator `config_version: 9` config", page("enterprise/mdm/configmgr.mdx"))
        self.assertIn("requires a supplied\n`config_version: 9` config", page("enterprise/mdm/workspace-one.mdx"))
        self.assertIn("The next run sees a failed result", page("enterprise/mdm/workspace-one.mdx"))

    def test_fg13_intune_unix_wrapper_failures(self):
        linux = page("enterprise/mdm/intune-linux.mdx")
        mac = page("enterprise/mdm/intune-macos.mdx")
        self.assertIn("older `.deb` is refused before `dpkg -i`", linux)
        self.assertIn("`mdm_staging_full`", linux)
        self.assertIn("`mdm_cancelled`", mac)
        self.assertIn("**MDM inline\nconfig**", mac)

    def test_fg13_jamf_kandji_wrapper_failures(self):
        self.assertIn("if Jamf\ncancels the run", page("enterprise/mdm/jamf.mdx"))
        self.assertIn("A cancelled run stops its lifecycle child", page("enterprise/mdm/kandji.mdx"))

    def test_fg13_okta_range_source_and_repair(self):
        text = page("enterprise/identity-okta.mdx")
        self.assertIn("both `assign-posix` and `install-sssd-okta.sh`", text)
        self.assertIn("SSSD NSS source\nexplicitly", text)
        self.assertIn("it retries the reload even when the\ndrop-in is unchanged", text)

    def test_lfmac_desktop_homebrew_and_probe(self):
        text = page("sandboxes/macos.mdx")
        self.assertIn("Log in to the Mac's desktop as this account", text)
        self.assertIn("Each account would also need\nits own Docker Desktop", text)
        self.assertIn("Setup can upgrade\nthe `nvidia/openshell` formula", text)
        self.assertIn("including `~/Library/Caches/defenseclaw/hookfire`", text)

    def test_lfmac_second_account_without_openshell(self):
        for name in ("sandboxes/macos.mdx", "sandboxes/linux.mdx"):
            text = page(name)
            self.assertIn("Setup installs and starts nothing there", text)
            self.assertIn("`--install-openshell` if OpenShell is not installed there", text)

    def test_lfuninst_cli_running_sandbox_option(self):
        text = page("reference/cli.mdx")
        self.assertIn("| `defenseclaw uninstall --stop-sandboxes` |", text)
        self.assertIn("`reset` takes this option too", text)

    def test_lfuninst_install_running_sandbox_refusal(self):
        text = page("get-started/install.mdx")
        self.assertIn("A running sandbox stops uninstall before any change", text)
        self.assertNotIn("A live-mounted sandbox is stopped\nand deleted", text)

    def test_pr886_api_key_rule_list(self):
        text = page("reference/configuration.mdx")
        self.assertIn("an unset, null or\nempty `cisco_ai_defense.enabled_rules` sends no `config`", text)
        self.assertIn("in the configured order", text)


if __name__ == "__main__":
    unittest.main()
