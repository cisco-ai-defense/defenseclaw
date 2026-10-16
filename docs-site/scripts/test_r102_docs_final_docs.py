"""Regression checks for rel-1-0-2 docs hand-offs and GAP-0554."""

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOCS = Path(__file__).resolve().parents[1] / "content/docs"


def page(name):
    return " ".join((DOCS / name).read_text().split())


class R102DocsFinalDocsTest(unittest.TestCase):
    def test_gap_0012_windows_profile_scan_limit(self):
        text = page("enterprise/windows.mdx")
        self.assertIn("health.watcher.details.profile_roots_skipped: true", text)
        self.assertIn("enterprise `status` and `verify` results do not report that field separately", text)
        self.assertIn("set `asset_policy.skill.runtime_detection.enabled: true` and "
                      "`asset_policy.plugin.runtime_detection.enabled: true`", text)
        self.assertIn("Set `asset_policy.enabled: true` as well", text)
        self.assertIn("A brokered scan as the enrolled user is planned for a later release", text)
        self.assertNotIn("gateway service watches the skill and plugin folders of every user", text)

    def test_gap_0012_admission_profile_roots(self):
        text = page("policies/admission.mdx")
        self.assertIn("assets there do not receive its install-admission scan", text)
        self.assertIn("keep shared skills outside profiles", text)
        self.assertIn("On managed Linux and macOS, only projects inside the caller's real home count, "
                      "after links are resolved", text)
        self.assertIn("Explicit `gateway.watcher.skill.dirs` prevent project folders from being added "
                      "on every platform", text)

    def test_gap_0957_managed_windows_profile_runtime_rules(self):
        text = page("policies/admission.mdx")
        self.assertIn("set `runtime_detection.enabled: true` so hooks apply default, registry and "
                      "approval rules to profile assets", text)
        self.assertIn("Set `asset_policy.enabled: true` as well", text)
        self.assertIn("On managed Windows, profile assets have no install-watcher decision", text)
        self.assertIn("MCP runtime detection defaults to true", text)
        self.assertIn("Windows `status` and `verify` do not emit `asset_policy_not_enforced`", text)
        self.assertIn("gateway log is the only warning on Windows", text)
        windows = page("enterprise/windows.mdx")
        self.assertIn("Windows `status` and `verify` do not warn when a default or registry rule goes "
                      "unenforced; the gateway log is the only signal", windows)

    def test_gap_0012_windows_scan_examples_exclude_profiles(self):
        text = page("enterprise/windows.mdx")
        self.assertIn("no per-user attribution", text)
        self.assertIn("A profile asset is never admission-blocked in 1.0.2", text)
        self.assertIn("C:\\\\ApprovedSkills\\\\<account>\\\\reviewed-skill", text)
        self.assertIn("This example assumes the folder `C:\\ApprovedSkills\\<account>` is listed in "
                      "`gateway.watcher.skill.dirs`", text)
        for phrase in ("copied into the profile", "elsewhere in the profile",
                       "whose profile holds the asset", "asset_removal_deferred",
                       "source_path_contains: [\"C:\\\\Users", "reason_code=install-block"):
            self.assertNotIn(phrase, text)

    def test_gap_1188_link_refusal_only_in_watched_roots(self):
        text = page("scanning/skill-scanner.mdx")
        self.assertIn("For a per-user install, a link outside that account's watched skill folders", text)
        self.assertIn('reason=link-outside-own-folders user=this account target="<path>"', text)
        self.assertIn("Managed computers do not watch users' connector skill folders in 1.0.2", text)
        self.assertNotIn("on Windows the hook guardian removes it as that user", text)

    def test_gap_0012_denied_config_rechecks_watched_roots_only(self):
        text = page("policies/admission.mdx")
        self.assertIn("For watched roots (per-user installs and managed Windows roots outside profiles)", text)
        self.assertIn("Managed Windows profile assets and managed Linux/macOS connector assets are "
                      "refused only by the hooks", text)
        self.assertNotIn("(per-user installs and managed Windows), a config change", text)

    def test_gap_0012_skill_watcher_profile_roots(self):
        text = page("scanning/skill-scanner.mdx")
        self.assertIn("skills there receive no watcher scan", text)
        self.assertIn("scan a copy outside profiles", text)

    def test_gap_0012_mcp_watcher_profile_roots(self):
        text = page("scanning/mcp-scanner.mdx")
        self.assertIn("those servers receive no install-watcher scan", text)
        self.assertIn("watcher.details.profile_roots_skipped: true", text)

    def test_gap_0461_kiro_prompt_scope(self):
        text = page("connectors/capability-matrix.mdx")
        self.assertIn("Kiro blocks a matching prompt only in Kiro IDE; `kiro-cli` sends it to the model.", text)
        self.assertNotIn("and Kiro have a prompt hook that can block", text)

    def test_gap_0440_windows_guardian_restore_restart(self):
        text = page("enterprise/windows.mdx")
        self.assertIn("the hook guardian restored hooks that the user changed or removed", text)
        self.assertIn("`security_complete` stays `false` until that session restarts", text)
        self.assertIn("Claude Code, Codex and Cursor use machine policy hooks", text)

    def test_gap_0499_unix_guardian_restore_restart(self):
        text = page("enterprise/troubleshooting.mdx")
        row = text.split("| `agent_sessions_restart_required` |", 1)[1].split("| Ask the user named", 1)[0]
        self.assertIn("hook guardian put back hooks the user changed or removed", row)
        self.assertIn("On Linux and macOS this restore case excludes Codex", row)
        self.assertIn("`security_complete` stays `false` until it restarts", row)
        self.assertNotIn("It names only sessions older than the activation", row)

    def test_gap_0483_rollback_carries_sandbox_setup(self):
        text = page("get-started/upgrade.mdx")
        self.assertIn("Between releases from 1.0.1 on, rollback carries the sandbox setup", text)
        self.assertIn("each sandbox record and hook binding, harness image records, and undo point", text)
        self.assertIn("A release before 1.0.1 cannot take over that setup", text)
        self.assertIn("After a return to 1.0.0, run `defenseclaw rollback` again", text)
        self.assertIn("After a return to 0.8.x, which has no rollback command, run "
                      "`bash ~/.defenseclaw/previous/installer/install.sh --rollback`", text)
        self.assertIn("names only sandboxes in the `ready` phase, and only while the gateway runs", text)
        self.assertNotIn("tool calls are refused until you run `defenseclaw rollback` again", text)

    def test_gap_0554_enterprise_sandbox_docker_limit(self):
        text = page("enterprise/sandboxes.mdx")
        bullet = text.split("**Docker is root-equivalent.**", 1)[1].split("- **A registration", 1)[0]
        self.assertIn("container outside DefenseClaw, bypassing `sandbox.required_for` too", bullet)
        self.assertIn("must not give them Docker access", bullet)
        self.assertIn("A root-owned image and lifecycle service", bullet)

    def test_gap_0554_enterprise_linux_docker_limit(self):
        text = page("enterprise/linux.mdx")
        self.assertIn("outside DefenseClaw, bypassing `sandbox.required_for`", text)
        self.assertIn("must not give them Docker access", text)
        self.assertIn("root-owned image and lifecycle service", text)

    def test_gap_0445_cli_unreadable_sandbox_list(self):
        text = page("reference/cli.mdx")
        self.assertIn("`uninstall` and `reset` also stop before any change if DefenseClaw cannot read the sandbox list", text)
        self.assertIn("`error`, `stopping`, `creating` and `deleting` phases count as running", text)
        self.assertIn("Only `stopped`, `completed`, `deleted` and `missing` do not", text)

    def test_gap_0445_guide_unreadable_sandbox_list(self):
        text = page("sandboxes/guide.mdx")
        self.assertIn("`uninstall` and `reset` stop before any change: teardown could otherwise delete a sandbox that still runs", text)
        self.assertIn("Check with `defenseclaw sandbox list`", text)
        self.assertIn("A sandbox in `error`, `stopping`, `creating` or `deleting` counts as running", text)

    def test_gap_0445_install_unreadable_sandbox_list(self):
        text = page("get-started/install.mdx")
        self.assertIn("If the sandbox list cannot be read, `uninstall` and `reset` also stop before any change", text)
        self.assertIn("`error`, `stopping`, `creating` and `deleting` phases count as running", text)

    def test_gap_0226_windows_install_discovery(self):
        text = page("enterprise/enrollment.mdx")
        self.assertIn("official Codex `install.ps1` layout", text)
        self.assertIn("per-user WinGet packages for signed-in users", text)
        self.assertIn("A signed-out user's per-user WinGet package is read at the next sign-in", text)
        self.assertIn("enabled agent running for an account with no enrollment target", text)
        self.assertIn("`security_complete` stays `false`", text)
        self.assertNotIn("is not found, so it is neither enrolled nor reported", text)

    def test_gap_0226_managed_codex_install_locations(self):
        text = page("connectors/codex.mdx")
        self.assertIn("On managed Windows, the enumerator enrolls Codex installed with npm", text)
        self.assertIn("official `install.ps1` at its default location, or WinGet", text)
        self.assertIn("under a relocated `CODEX_HOME`", text)

    def test_gap_0255_profile_explain_account_ids(self):
        text = page("guardrail/user-and-group-policies.mdx")
        self.assertIn("Group assignments follow the OS-verified account ID", text)
        self.assertIn("use each uid or SID with `guardrail profile explain --user`", text)

    def test_gap_0438_guardian_hook_binary_reread(self):
        text = page("enterprise/troubleshooting.mdx")
        self.assertIn("The guardian re-reads the hook binary when it changes and at least every 10 minutes", text)

    def test_gap_0085_grafana_history_and_current_state(self):
        text = page("observability/grafana-dashboards.mdx")
        self.assertIn("The **DefenseClaw kernel policies** table counts policy-change events", text)
        self.assertIn("The stat and **Kernel controls per host (last 10 minutes)** show current host state", text)

    def test_gap_0528_macos_bare_group_name_selects_local_and_domain_group(self):
        text = page("guardrail/user-and-group-policies.mdx")
        self.assertIn("selects the members of that local group", text)
        self.assertIn("A bare name also selects, by its name part,", text)
        self.assertIn("the members of the `DOMAIN\\name` Active Directory group the user is already listed in", text)
        self.assertIn("Open Directory's search order only decides which group the extra nested-membership "
                      "check resolves (the local one when both exist)", text)
        self.assertIn("Write `DOMAIN\\name` to target only the Active Directory group", text)
        self.assertNotIn("the local group is " "the one checked", text)

    def test_gap_0595_matched_group_source_lists_every_value(self):
        text = page("guardrail/user-and-group-policies.mdx")
        self.assertIn("`matched_group_source` (`local`, `directory` or `local and directory`)", text)
        self.assertIn("`local and directory` means that the bare name matched both a local group "
                      "and a `DOMAIN\\name` group in the user's group list", text)
        self.assertIn("If the source cannot be determined, `matched_group_source` is left out", text)

    def test_guide_no_sandbox_bullet_names_both_host_run_exceptions(self):
        text = page("sandboxes/guide.mdx")
        self.assertIn("the host run is refused by the agent's machine-owned hook unless your account is in "
                      "`enterprise.enrollment.exempt_users`, or sandboxes are unavailable to your account and "
                      "the effective `when_unavailable` setting is `alert`", text)

    def test_enterprise_non_exempt_host_refusal_names_unavailable_alert_exception(self):
        text = page("enterprise/sandboxes.mdx")
        self.assertIn("For a non-exempt account, a host run is refused even when it claims to be "
                      "nested in a sandbox, unless sandboxes are unavailable to the account and "
                      "the effective `when_unavailable` setting is `alert`", text)
        self.assertIn("an agent that has no machine-owned hook is not stopped by it", text)

    def test_guide_host_refusal_applies_while_sandboxes_are_available(self):
        text = page("sandboxes/guide.mdx")
        self.assertIn("the host run is refused while sandboxes are available to the account, "
                      "whether the effective `when_unavailable` setting is `refuse` or `alert`", text)
        self.assertIn("An effective `alert` setting when sandboxes are unavailable to the account "
                      "lifts that refusal", text)
        self.assertIn("[the registration limit](/docs/enterprise/sandboxes#require-sandboxes)", text)
        self.assertNotIn("that host refusal applies when the effective `when_unavailable` setting "
                         "is `refuse`", text)

    def test_no_sandbox_registry_names_both_host_run_exceptions(self):
        registry = json.loads((ROOT / "internal/envvars/registry.json").read_text())
        entry = next(item for item in registry["entries"]
                     if item["name"] == "DEFENSECLAW_NO_SANDBOX")
        self.assertIn("host run is still refused unless the account is in "
                      "`enterprise.enrollment.exempt_users`, or sandboxes are unavailable to the account "
                      "and the effective `when_unavailable` setting is `alert`", entry["purpose"])

    def test_no_sandbox_generated_env_vars_row_names_both_exceptions(self):
        text = page("reference/env-vars.mdx")
        row = text.split("`DEFENSECLAW_NO_SANDBOX`", 1)[1].split(" | ", 1)[1]
        self.assertIn("host run is still refused unless the account is in "
                      "`enterprise.enrollment.exempt_users`, or sandboxes are unavailable to the account "
                      "and the effective `when_unavailable` setting is `alert`", row)

    def test_no_sandbox_changelog_bullet_names_both_exceptions(self):
        changelog = (ROOT / "CHANGELOG.md").read_text()
        release = changelog.split("## [1.0.2]", 1)[1].split("\n## [", 1)[0]
        bullet = release.split("- `DEFENSECLAW_NO_SANDBOX=1`", 1)[1].split("\n- ", 1)[0]
        bullet = " ".join(bullet.split())
        self.assertIn("It is not an exemption", bullet)
        self.assertIn("host run is refused unless the account is in "
                      "`enterprise.enrollment.exempt_users`, or sandboxes are unavailable to the account "
                      "and the effective `when_unavailable` setting is `alert`", bullet)

    def test_sandbox_gate_doc_names_exempt_and_alert_outcomes(self):
        text = " ".join((ROOT / "docs/SANDBOX.md").read_text().split())
        gate = text.split("The require-sandbox gate", 1)[1].split("### OpenShell under management", 1)[0]
        self.assertIn("An account in `enterprise.enrollment.exempt_users` is not refused", gate)
        self.assertIn("When sandboxes are unavailable to the account and the effective "
                      "`when_unavailable` setting is `alert`, the gate alerts instead of refusing", gate)
        self.assertIn("rebuilt from a live registration skips the host-run gate", gate)

    def test_enterprise_uninstall_keeps_sandboxes_until_purge(self):
        text = page("enterprise/sandboxes.mdx")
        bullet = text.split("- **Uninstall and purge.**", 1)[1].split("## Troubleshooting", 1)[0]
        self.assertIn("Without `--purge`, uninstall stops running sandboxes through the sandbox daemon, "
                      "which syncs a MicroVM disk before stopping it", bullet)
        self.assertIn("It then stops the daemon and the OpenShell gateway. Every sandbox stays with "
                      "its records, disks and any copy-mode work not pulled yet for the next "
                      "activation of the deployment", bullet)
        self.assertIn("Only `--purge` runs each user's teardown as that user and removes the daemon state, "
                      "MicroVM disks, images, both stores and the rendered `gateway.toml`", bullet)
        self.assertNotIn("Root runs each user's teardown as that user", bullet)

    def test_enterprise_lifecycle_row_does_not_say_every_uninstall_tears_down(self):
        text = page("enterprise/sandboxes.mdx")
        row = text.split("| Lifecycle (`ensure`, `verify`, `repair`, `uninstall`) | root |", 1)[1].split("\n", 1)[0]
        self.assertIn("`uninstall --purge` tears down per user; `uninstall` alone stops running "
                      "sandboxes and keeps them", row)
        self.assertNotIn("checks group membership, tears down per user", row)

    def test_enterprise_uninstall_names_the_kept_sandbox_store(self):
        # rel-1-0-2:GAP-0598 (lead decision option a): a non-purge uninstall
        # that keeps sandboxes keeps the registrations, decisions and key.
        text = page("enterprise/sandboxes.mdx")
        bullet = text.split("- **Uninstall and purge.**", 1)[1].split("## Troubleshooting", 1)[0]
        self.assertIn("also keeps the gateway's sandbox registrations and decisions "
                      "(`sandbox/registrations` and `sandbox/decisions`) and their key "
                      "(`redaction-correlation.key`); the rest of the machine state goes", bullet)
        self.assertIn("which adopts them and gives them to the service account, also after a package "
                      "reinstall (`rpm -e` or `apt remove`, then an install)", bullet)
        self.assertIn("it also removes the kept registrations, decisions and key", bullet)
        row = text.split("| Lifecycle (`ensure`, `verify`, `repair`, `uninstall`) | root |", 1)[1].split("\n", 1)[0]
        self.assertIn("with the gateway's sandbox registrations, decisions and `redaction-correlation.key` "
                      "(`--purge` removes those too)", row)

    def test_gap_0534_macos_users_entry_names_the_upn(self):
        text = page("guardrail/user-and-group-policies.mdx")
        self.assertIn("and by its UPN, which the hook guardian reads from the account's domain record "
                      "(a mobile account's included)", text)

    def test_gap_1356_windows_project_skill_roots_skipped(self):
        text = page("enterprise/windows.mdx")
        self.assertIn("project skill folders inside profiles are skipped before verification or registration", text)
        self.assertIn("no install scan, no \"is not scanned yet\" refusal and no "
                      "`project_skill_root_unverified` warning", text)
        self.assertNotIn("skills are refused: `enterprise windows status` and `verify` warn with "
                         "`project_skill_root_unverified`", text)


if __name__ == "__main__":
    unittest.main()
