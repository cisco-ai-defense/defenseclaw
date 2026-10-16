"""Pin the final rel-1-0-2 documentation hand-offs."""

import re
import unittest
from pathlib import Path


DOCS = Path(__file__).resolve().parents[1] / "content/docs"


def page(name):
    return " ".join((DOCS / name).read_text().split())


def section(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]


class R102DocsFinal4DocsTest(unittest.TestCase):
    def assert_public(self, *sections):
        for section_text in sections:
            lower = section_text.lower()
            for forbidden in ("dc-", "okta", "dcad", "vm-", ".corp"):
                self.assertNotIn(forbidden, lower)
            self.assertIsNone(re.search(r"\b[^\s@]+@[^\s@]+\b", section_text))

    def test_gap_0575_copy_complete_audit_archive_before_recovery(self):
        text = page("get-started/upgrade.mdx")
        recovery = section(text, "For any `audit.db.corrupt-<time>` archive", "- On a host")
        for phrase in (
            "whether from a 0.x upgrade or a later gateway start",
            "copy the main file with its `-wal` and `-shm` files and any `-journal` file to a new folder before opening it with SQLite tools",
            "SQLite can change files it opens, so work on the copy",
            'If the first bytes of the main file are zeroed and SQLite says "file is not a database", repair the header on the copy, never on the original archive',
            "A hot rollback journal is rolled back when the gateway starts and is not archived",
            "if the store is still corrupt afterward, the start warning says the pre-existing `-journal` was not preserved",
        ):
            self.assertIn(phrase, recovery)
        self.assert_public(recovery)

    def test_gap_0610_empty_per_user_sandbox_state_skips_list_and_teardown(self):
        install = page("get-started/install.mdx")
        guide = page("sandboxes/guide.mdx")
        install_block = section(install, "A per-user uninstall for an account", "A running sandbox")
        guide_block = section(guide, "A per-user uninstall for an account", "`defenseclaw uninstall` runs teardown")
        for block in (install_block, guide_block):
            for phrase in (
                "never set up sandboxes completes without a teardown override",
                "Its sandbox directory is absent or holds only empty lock files and empty folders",
                "no OpenShell state or user gateway config sits beside them, and no OpenShell sandbox setting or wrapper is enabled",
                "Neither `uninstall` nor `reset` reads the sandbox list or runs teardown then",
                "records, snapshots, non-empty files, links or unreadable entries",
                "enabled OpenShell settings",
                "empty lock file alongside OpenShell state or a user gateway config",
            ):
                self.assertIn(phrase.lower(), block.lower())
        self.assertIn("When sandbox state is present, uninstall also removes DefenseClaw's OpenShell sandboxes and images", install)
        self.assertIn("This list check applies only when sandbox teardown is planned. If the sandbox list cannot be read", install)
        self.assertIn("This preflight runs only when sandbox teardown is planned. If DefenseClaw cannot read the sandbox list", guide)
        self.assertIn("`defenseclaw uninstall` runs teardown when sandbox state is present", guide)
        self.assertNotIn("Uninstall also removes DefenseClaw's OpenShell sandboxes and images", install)
        self.assertNotIn("`defenseclaw uninstall` runs teardown too", guide)
        self.assert_public(install_block, guide_block)

    def test_gap_0556_to_0591_windows_restart_discovery_and_owner_reporting(self):
        windows = page("enterprise/windows.mdx")
        enrollment = page("enterprise/enrollment.mdx")
        troubleshooting = page("enterprise/troubleshooting.mdx")
        restart = section(windows, "If the hook guardian's restore record cannot be read", "Windows `status`, `verify`, `ensure`")
        reports = section(windows, "`status` and `verify` also report agents", "Cursor's machine hooks file")
        enrolled = section(enrollment, "When a running agent has no account name", "An agent CLI installed")
        unprotected = section(troubleshooting, "| `agent_unprotected` |", "| `agent_settings_not_restored` |")
        sessions = section(troubleshooting, "| `agent_sessions_restart_required` |", "| `no_connectors_enabled` |")
        for phrase in (
            '`agent_sessions_restart_required` with "restart status unknown" and set `security_complete` to `false`, even when no session was listed',
            "a running agent with no account name is checked by its owner SID when available",
            "with neither an account name nor a SID, its restart status is unknown",
        ):
            self.assertIn(phrase.lower(), restart.lower())
        for phrase in (
            "accounts it could not finish scanning",
            "Each warning applies to one account",
            "a running enabled agent whose account SID cannot be resolved",
            "the warning names the account when known and otherwise says the owner is unknown",
            'reaches its entry limit or deadline is reported as "not fully scanned"',
        ):
            self.assertIn(phrase, reports)
        self.assertIn('If a per-user WinGet Packages listing reaches its entry limit or deadline, the account is reported as "not fully scanned" and is scanned again on the next enumeration', enrollment)
        self.assertIn("the enumerator uses its owner SID to check enrollment", enrolled)
        self.assertIn("if neither is available, an enabled agent is reported as not protected with its owner unknown", enrolled)
        for phrase in (
            "could not finish the Windows per-user WinGet package listing",
            "a process with no account name is checked by its owner SID",
            'reaches the entry limit or deadline is reported as "not fully scanned"',
        ):
            self.assertIn(phrase, unprotected)
        for phrase in (
            "This usually names a user running an agent CLI",
            "For a known restart time, the warning clears once the sessions are restarted",
            "when those times can be read",
            'an unreadable guardian restore record reports "restart status unknown" and sets `security_complete` to `false`, even when no session was listed',
            "with neither name nor SID, its restart status is unknown",
            "if the restore record is unreadable, resolve that read failure and recheck",
        ):
            self.assertIn(phrase, sessions)
        self.assertNotIn("Each is one account's agent", windows)
        self.assertNotIn("The enumerator found an agent installed for a user but could not enroll it; the message gives the reason", troubleshooting)
        self.assertNotIn("The warning clears once the sessions are restarted.", sessions)
        self.assertNotIn("It names sessions older than the activation or than a guardian restore.", sessions)
        self.assert_public(restart, reports, enrolled, unprotected, sessions)

    def test_gap_0564_0579_0588_settings_warning_and_docker_namespace(self):
        windows = page("enterprise/windows.mdx")
        troubleshooting = page("enterprise/troubleshooting.mdx")
        guide = page("sandboxes/guide.mdx")
        lifecycle = section(windows, "Windows `status`, `verify`, `ensure` and `repair` also report", "With `JSON=1`")
        warning = section(troubleshooting, "| `agent_settings_not_restored` |", "| `guardian_target_failed` |")
        namespace = section(guide, "On Linux, setup gives each per-user Docker gateway", "On a Mac, setup asks instead")
        for phrase in (
            "`agent_settings_not_restored` when the hook guardian puts back a missing Hermes `config.yaml` or Devin `config.json`",
            "last known good copy or the pristine backup",
            "recreates the file with hooks only when no copy is available",
            "review settings that may not have been restored",
            "it does not by itself change `security_complete`, the exit code or MDM detection",
        ):
            self.assertIn(phrase, lifecycle)
        for phrase in (
            "Linux, macOS, Windows",
            "the last known good copy or the pristine backup",
            "recreated it with DefenseClaw's hooks only when no copy was available",
            "settings need to be entered again if no copy held them",
            "This warning alone does not fail `verify`, set `security_complete` to `false`, change the exit code or fail MDM detection",
        ):
            self.assertIn(phrase, warning)
        for phrase in (
            "its own sandbox namespace, `defenseclaw-u<uid>`",
            "when that account has no sandbox in OpenShell's `default` namespace",
            "If the gateway still has sandboxes there, setup leaves its namespace in place",
            "`defenseclaw sandbox doctor` warns `docker-namespace` until those sandboxes are gone",
        ):
            self.assertIn(phrase, namespace)
        self.assert_public(lifecycle, warning, namespace)

    def test_gap_0598_mdm_uninstall_pages_name_the_kept_sandbox_store_and_key(self):
        linux = ("`/var/lib/defenseclaw/sandbox`", "`/var/lib/defenseclaw/redaction-correlation.key`")
        mac = ("`/opt/cisco/defenseclaw/runtime/sandbox`", "`/opt/cisco/defenseclaw/runtime/redaction-correlation.key`")
        pages = {
            "enterprise/mdm/linux-config-management.mdx": linux,
            "enterprise/mdm/intune-linux.mdx": linux,
            "enterprise/mdm/kandji.mdx": mac,
            "enterprise/mdm/jamf.mdx": mac,
            "enterprise/mdm/intune-macos.mdx": mac,
        }
        for name, paths in pages.items():
            text = page(name)
            for path in paths:
                self.assertIn(path, text, name)
            self.assertIn("If an account keeps sandboxes, the gateway's sandbox registration store", text, name)
            self.assertIn("stay, root-owned, until the next `ensure` adopts them", text, name)
            if not name.endswith("linux-config-management.mdx"):
                self.assertIn("the kept sandbox store and key", text, name)
        self.assertIn("use `--purge` for a clean image", page("enterprise/mdm/linux-config-management.mdx"))
        self.assertNotIn("removes the machine state (config, credentials, state and logs)",
                         page("enterprise/mdm/linux-config-management.mdx"))
        self.assertNotIn("removes the machine state (config, policies, key, state and logs)",
                         page("enterprise/mdm/intune-linux.mdx"))
        self.assertNotIn("The uninstall always removes the config, credentials, state and logs", page("enterprise/mdm/jamf.mdx"))


if __name__ == "__main__":
    unittest.main()
