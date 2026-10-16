"""Regression checks for round 1.0.2 enterprise guide corrections."""

import unittest
from pathlib import Path


DOCS = Path(__file__).resolve().parents[1] / "content/docs/enterprise"


def page(name):
    return (DOCS / name).read_text()


class R102EnterprisePagesDocsTest(unittest.TestCase):
    def test_gap_0285_linux_units_name_paths_dropin(self):
        text = page("linux.mdx")
        self.assertIn("`50-defenseclaw-paths.conf` for both guardian units", text)
        self.assertNotIn("The one drop-in the lifecycle writes itself", text)

    def test_gap_0287_windows_uninstall_leaves_disconnected_sessions_pending(self):
        text = page("windows.mdx")
        self.assertIn("Disconnected or signed-out\nsessions remain pending", text)
        self.assertNotIn("agent configuration of every signed-in user", text)

    def test_gap_0289_invalid_machine_policy_is_config_invalid(self):
        text = page("troubleshooting.mdx")
        self.assertIn("Invalid `enterprise.machine_policy` settings fail validation as `config_invalid`", text)
        self.assertNotIn("The `enterprise.machine_policy` settings are invalid, or a vendor policy", text)

    def test_gap_0290_rpm_architecture_reports_install_failure(self):
        text = page("troubleshooting.mdx")
        self.assertIn("an RPM for another CPU architecture instead reaches `rpm -U`", text)

    def test_gap_0292_linux_fips_support(self):
        text = page("linux.mdx")
        self.assertIn("| FIPS mode | RHEL 9 in FIPS mode is supported", text)

    def test_gap_0293_legacy_macos_installer(self):
        text = page("macos.mdx")
        self.assertIn("0.8.10 `install.sh`\npredates the managed-host check", text)

    def test_gap_0344_custom_pack_folder_mode(self):
        text = " ".join(page("configuration.mdx").split())
        self.assertIn("umask 022 && mkdir -p /opt/cisco/defenseclaw/etc/policies/guardrail && cp -R", text)
        self.assertIn("umask 022 && mkdir -p /etc/defenseclaw/policies/guardrail && cp -R", text)
        self.assertIn("sudo chmod 0755 /opt/cisco/defenseclaw/etc/policies /opt/cisco/defenseclaw/etc/policies/guardrail", text)
        self.assertIn("sudo chmod 0755 /etc/defenseclaw/policies /etc/defenseclaw/policies/guardrail", text)
        self.assertIn("sudo chmod -R u=rwX,go=rX /opt/cisco/defenseclaw/etc/policies/guardrail/my-pack", text)
        self.assertIn("sudo chmod -R u=rwX,go=rX /etc/defenseclaw/policies/guardrail/my-pack", text)
        self.assertNotIn("sudo chmod -R u=rwX,go=rX /etc/defenseclaw/policies`", text)
        self.assertNotIn("After `mkdir -p`, run", text)
        self.assertNotIn("a root shell with umask `077` otherwise creates it as `0700`", text)

    def test_gap_0447_windows_scan_examples_avoid_user_profiles(self):
        text = " ".join(page("windows.mdx").split())
        self.assertNotIn("C:\\Users\\Public", text)
        self.assertIn("scan skill 'C:\\DefenseClawReview\\my-skill'", text)
        self.assertIn("scan plugin 'C:\\DefenseClawReview\\my-plugin'", text)
        self.assertIn("refuses any folder inside a user profile", text)
        self.assertIn("administrator-created folder outside the profiles", text)
        self.assertIn("LocalSystem can read", text)

    def test_gap_0294_purge_removes_lifecycle_lock(self):
        text = page("windows.mdx")
        self.assertIn("Setup with `PURGE=1` removes that lock", text)
        self.assertNotIn("the uninstall keeps it in place. To leave nothing", text)

    def test_gap_0295_block_message_limit(self):
        text = page("configuration.mdx")
        self.assertIn("at\nmost 4096 characters. `ensure` refuses", text)

    def test_gap_0298_setup_recovers_committed_uninstall(self):
        text = page("windows.mdx")
        self.assertIn("Setup carries its own verified gateway", text)
        self.assertNotIn("run the same\n`defenseclaw.exe` uninstall", text)

    def test_gap_0310_disabled_connector_excluded(self):
        text = page("troubleshooting.mdx")
        self.assertIn("Disabled connectors are excluded from managed machine policy", text)
        self.assertNotIn("get machine policy whenever they are named", text)

    def test_gap_0288_machine_policy_only_enrollment(self):
        rollout = page("rollout.mdx")
        operations = page("operations.mdx")
        self.assertIn("machine-policy-only deployment can have an empty", rollout)
        self.assertIn("Enrollment section can be absent while eligible users remain protected", operations)
        self.assertNotIn("Confirm that the users you expect appear for each\n   agent", rollout)

    def test_gap_0291_unreadable_data_directory_is_repaired(self):
        text = page("operations.mdx")
        self.assertIn("The guardian repairs the mode of a user-owned `~/.defenseclaw`", text)
        self.assertNotIn("by making `~/.defenseclaw` unreadable", text)

    def test_gap_0063_user_path_warning_excludes_repaired_directory(self):
        text = page("operations.mdx")
        self.assertIn("another\nfolder the worker cannot read", text)
        self.assertNotIn("or a folder\nthe user made unreadable", text)

    def test_gap_0303_jsonl_collection_requires_read_access(self):
        text = page("operations.mdx")
        self.assertIn("only if it runs as root or the `defenseclaw` service account", text)
        self.assertIn("file is `0600` inside a service-owned `0750` folder", text)

    def test_gap_0304_managed_audit_pipe_has_consistent_ownership(self):
        text = page("identity-and-authentication.mdx")
        self.assertIn("audit export --since 10m \\\n  | jq -c", text)
        self.assertNotIn("audit_file=$(mktemp)", text)

    def test_gap_0345_projected_principal_values(self):
        text = page("identity-and-authentication.mdx")
        self.assertIn("and `kerberos_principal` values are `null`", text)
        self.assertNotIn("and `kerberos_principal` keys are absent", text)

    def test_gap_0305_machine_policy_directory_holds_session_facts(self):
        text = page("operations.mdx")
        self.assertIn("`~/.defenseclaw` holds session facts", text)
        self.assertIn("managed hook policy is not stored\nthere", text)

    def test_gap_0306_never_signed_in_lookup_is_host_specific(self):
        text = page("identity-entra-id.mdx")
        self.assertIn("may resolve an\n  Entra name or UPN to a SID before first sign-in", text)
        self.assertNotIn("has no account there yet, so there is no SID", text)

    def test_gap_0307_per_user_sssd_does_not_promise_upn(self):
        text = page("identity-entra-id.mdx")
        self.assertIn("A per-user install uses source `sssd` and may have only", text)
        self.assertNotIn("the UPN, the domain | The synced Entra groups", text)

    def test_gap_0314_macos_detached_child_plane_c_limit(self):
        text = page("macos.mdx")
        self.assertIn("detached child of a terminal-launched\nagent unattributed", text)

    def test_docs_sameuser_sandbox_registration_limit(self):
        text = page("sandboxes.mdx")
        self.assertIn("inside the trust boundary of that user's sandbox registration", text)
        self.assertIn("Additional isolation is planned for 1.0.3", text)

    def test_deprecated_enterprise_example_omits_omnigent_image(self):
        text = page("sandboxes.mdx")
        section = text.split("### Hook silence", 1)[1].split("## Require sandboxes", 1)[0]
        self.assertIn("Claude Code, Codex, Copilot and Cursor images", section)
        self.assertNotIn("OmniGent images own their hooks", section)

    def test_gap_0319_host_refusal_reason_is_required_for(self):
        text = page("sandboxes.mdx")
        self.assertIn("| `required_for` | Not a failure.", text)
        self.assertNotIn("| `required_group` |", text)

    def test_gap_0351_required_for_is_managed_only(self):
        text = page("sandboxes.mdx")
        self.assertIn("enforced only by standalone managed gateways", text)

    def test_gap_0353_openshell_umask_home_effect(self):
        text = page("sandboxes.mdx")
        self.assertIn("DefenseClaw's Linux user unit uses `UMask=0022`", text)
        self.assertIn("New files and folders the gateway creates under\nthe user's home", text)
        self.assertIn("https://github.com/NVIDIA/OpenShell/blob/main/deploy/deb/openshell-gateway.service", text)

    def test_gap_0317_tetragon_lineage_and_matching_limits(self):
        text = page("tetragon.mdx")
        self.assertIn("may\nno longer carry its original `parent_exec_id`", text)
        self.assertIn("keeps at most four older exec-ID aliases", text)
        self.assertIn("DNS names used alongside\nthese events come from DefenseClaw's `dnscapture`", text)
        self.assertIn("File matching is inode-scoped", text)
        self.assertIn("reparented before its first observed exec", text)

    def test_gap_0316_windows_project_mcp_files_are_read_as_the_enrolled_user(self):
        text = page("windows.mdx")
        self.assertIn("under the\n  enrolled user's own token", text)
        self.assertIn("A project the user cannot access contributes\n  neither its local-scope servers nor its `.mcp.json` servers", text)


if __name__ == "__main__":
    unittest.main()
