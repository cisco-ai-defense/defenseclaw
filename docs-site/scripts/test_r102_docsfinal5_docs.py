"""Pin the rc.5 managed uninstall and agent-settings documentation."""

import os
import re
import unittest
from pathlib import Path


DOCS = Path(
    os.environ.get(
        "R102_DOCSFINAL5_DOCS_ROOT", Path(__file__).resolve().parents[1] / "content/docs"
    )
)


def page(name):
    return " ".join((DOCS / name).read_text().split())


def section(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]


class R102DocsFinal5DocsTest(unittest.TestCase):
    def assert_public(self, text):
        lower = text.lower()
        for forbidden in ("dc-", "okta", "dcad", "vm-", ".corp"):
            self.assertNotIn(forbidden, lower)
        self.assertIsNone(re.search(r"\b[^\s@]+@[^\s@]+\b", text))

    def assert_pins(self, name, start, end, phrases, forbidden=()):
        full = page(name)
        block = section(full, start, end)
        for phrase in phrases:
            with self.subTest(page=name, phrase=phrase):
                self.assertIn(phrase, block)
        for phrase in (
            "setup record",
            "applied setup",
            "without it uninstall removes all of it",
            *forbidden,
        ):
            with self.subTest(page=name, forbidden=phrase):
                self.assertNotIn(phrase.lower(), full.lower())
        self.assert_public(block)

    def test_operations_image_needs_purge(self):
        self.assert_pins(
            "enterprise/operations.mdx",
            "Prefer an image without that state:",
            "For clones that already run it,",
            (
                "`enterprise linux uninstall --purge --json`",
                "`enterprise macos uninstall --purge --json`",
                "A plain uninstall removes most machine state, but if an account keeps sandboxes",
                "`/var/lib/defenseclaw/sandbox`",
                "`/opt/cisco/defenseclaw/runtime/sandbox`",
                "`/var/lib/defenseclaw/redaction-correlation.key`",
                "`/opt/cisco/defenseclaw/runtime/redaction-correlation.key`",
                "root-owned while the service account is gone; the next `ensure` adopts them",
                "The key is per-machine; a clone must not share it",
                "Use `--purge` for a clean image",
            ),
            ("The plain uninstall removes the machine state",),
        )

    def test_lifecycle_kept_store_and_package_channel(self):
        self.assert_pins(
            "enterprise/lifecycle.mdx",
            "## Uninstall",
            "## Decommission checklist",
            (
                "On a standalone deployment it also removes the config, credentials, most machine state and logs",
                "most gateway and guardian state, most lifecycle state",
                "`/var/lib/defenseclaw/sandbox`",
                "`/opt/cisco/defenseclaw/runtime/sandbox`",
                "stays if it contains a file",
                "`/var/lib/defenseclaw/redaction-correlation.key`",
                "`/opt/cisco/defenseclaw/runtime/redaction-correlation.key`",
                "stays if it is a regular file",
                "They are root-owned while the service account is gone; the next `ensure` adopts them",
                "Use `--purge` for a clean image or to remove the retained sandbox store and key",
                "Remove the deployment and keep each user's data (Linux/macOS may keep sandbox state)",
                "the kept sandbox store and key above stay when an account keeps sandboxes",
                "`/var/lib/defenseclaw` (including a kept sandbox store and key)",
            ),
            (
                "It also removes the machine state: the config, credentials, state and logs",
                "Remove the deployment and machine state, keep each user's data",
            ),
        )

    def test_lifecycle_registration_warning_and_error(self):
        self.assert_pins(
            "enterprise/lifecycle.mdx",
            "- **Registrations left",
            "- **Manifest rows",
            (
                "warning (Linux and macOS)",
                "the user's home is unavailable",
                "the directory gives a removed account no home while its recorded home remains",
                "re-homed account's current home was cleaned but its old home cannot be trusted",
                "uninstall warns with `per_user_hooks_remaining` and goes on",
                "current-home and old-home clearing paths in [Warnings](/docs/enterprise/troubleshooting#warnings)",
                "error (Linux and macOS)",
                "Other registration removal failures report `per_user_hooks_remaining`",
                "stop uninstall before removing the binaries those registrations run",
                "The deployment record and state stay",
                "rerun the same uninstall; `ensure` restores the deployment instead",
            ),
            ("- **Registrations left (Linux and macOS).**",),
        )

    def test_linux_removal_and_package_scripts(self):
        self.assert_pins(
            "enterprise/linux.mdx",
            "## Remove",
            "## Upgrades and changes",
            (
                "most of its data and lifecycle state, and the `defenseclaw` account",
                "When an account keeps sandboxes, `/var/lib/defenseclaw/sandbox` and `/var/lib/defenseclaw/redaction-correlation.key` stay",
                "They are root-owned while the service account is gone; the next `ensure` adopts them",
                "store and `redaction-correlation.key` are root-owned while the service account is gone; the next `ensure` adopts them",
                "Use `--purge` for a clean image",
                "`apt remove defenseclaw-enterprise` | Runs plain `uninstall`",
                "`apt purge defenseclaw-enterprise` | Runs the same plain lifecycle uninstall, then deletes",
                "`/var/lib/defenseclaw` (including `sandbox` and `redaction-correlation.key`)",
                "It does not purge each enrolled account's home; run lifecycle `--purge` before package removal",
                "`dnf remove defenseclaw-enterprise` | Runs plain `uninstall`",
            ),
            ("and the sandbox setup record stay",),
        )

    def test_macos_removal(self):
        self.assert_pins(
            "enterprise/macos.mdx",
            "## Remove",
            "## Upgrades and changes",
            (
                "most of its data and lifecycle state, and the `_defenseclaw` account",
                "When an account keeps sandboxes, `/opt/cisco/defenseclaw/runtime/sandbox` and `/opt/cisco/defenseclaw/runtime/redaction-correlation.key` stay",
                "They are root-owned while the service account is gone; the next `ensure` adopts them",
                "Use `--purge` for a clean image",
            ),
            ("and the root-owned sandbox setup record stay",),
        )

    def test_mdm_removal_rows_and_followup(self):
        self.assert_pins(
            "enterprise/mdm/index.mdx",
            "## Uninstall",
            "## Simulate your MDM",
            (
                "Without `--purge`, if an account keeps sandboxes, `/var/lib/defenseclaw/sandbox` and `/var/lib/defenseclaw/redaction-correlation.key` can stay",
                "Without `--purge`, if an account keeps sandboxes, `/opt/cisco/defenseclaw/runtime/sandbox` and `/opt/cisco/defenseclaw/runtime/redaction-correlation.key` can stay",
                "`--purge` removes them and each enrolled account's `~/.defenseclaw` and per-user binaries",
                "the kept `sandbox` store and `redaction-correlation.key` are root-owned while the service account is gone; the next `ensure` adopts them",
                "Use `--purge` for a clean image",
                "To keep the other machine state for a later reinstall",
            ),
            ("the machine state (config, credentials, state and logs)",),
        )

    def test_cli_uninstall_flags(self):
        self.assert_pins(
            "reference/cli.mdx",
            "| `uninstall` | Stop and remove the deployment",
            "| `--keep-service-account` | uninstall",
            (
                "`/var/lib/defenseclaw/sandbox`",
                "`/opt/cisco/defenseclaw/runtime/sandbox`",
                "`/var/lib/defenseclaw/redaction-correlation.key`",
                "`/opt/cisco/defenseclaw/runtime/redaction-correlation.key`",
                "stay root-owned while the service account is gone; the next `ensure` adopts them",
                "`--purge` removes them and each enrolled account's data and binaries for a clean image",
                "It removes the sandbox registration store and key for a clean image",
                "may keep `sandbox` registrations and `redaction-correlation.key` when an account keeps sandboxes",
                "gateway and guardian state (the sandbox registrations and key included), logs, lifecycle state and the service account",
                "Cannot combine with `--purge`",
            ),
            (
                "Without `--purge`, uninstall already removes the config, credentials, state",
                "A plain uninstall can still keep sandbox registrations and their key",
            ),
        )

    def test_jamf_second_uninstall_description(self):
        self.assert_pins(
            "enterprise/mdm/jamf.mdx",
            "## Uninstall",
            "## Logs",
            (
                "the binaries and most machine state",
                "`/opt/cisco/defenseclaw/runtime/sandbox`",
                "`/opt/cisco/defenseclaw/runtime/redaction-correlation.key`",
                "stay root-owned while the service account is gone; the next `ensure` adopts them",
                "Use `--purge` for a clean image",
            ),
            ("the binaries and the machine state",),
        )

    def assert_agent_settings_notice(self, name, start, end):
        self.assert_pins(
            name,
            start,
            end,
            (
                "`status` and `verify` warn with `agent_settings_not_restored`",
                "missing Hermes `config.yaml` or Devin `config.json`",
                "last known good copy or the pristine backup",
                "recreates it with DefenseClaw's hooks only when no copy is available",
                "settings changed after the copy may be missing; with no copy, the user may need to re-enter their settings",
                "does not make `security_complete` false or `verify` fail, change the exit code, or fail MDM detection",
                "review their settings and restore missing values from a backup",
                "[Warnings](/docs/enterprise/troubleshooting#warnings)",
            ),
        )

    def test_linux_agent_settings_warning(self):
        self.assert_agent_settings_notice(
            "enterprise/linux.mdx", "guardian reconciles.", "The guardian is always running"
        )

    def test_macos_agent_settings_warning(self):
        self.assert_agent_settings_notice(
            "enterprise/macos.mdx", "enterprise macos reconcile --json`.", "A `guardrail.profile_assignments`"
        )


if __name__ == "__main__":
    unittest.main()
